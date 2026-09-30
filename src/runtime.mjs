import { randomUUID } from 'node:crypto';
import { digest, clone } from './canonical.mjs';
import { signed, verifySigned } from './crypto.mjs';
import { fields, identifier, text, integer, oneOf, uniqueStrings } from './schema.mjs';
import { requireThat } from './errors.mjs';

export class RuntimeGate {
  constructor(fabric) { this.f = fabric; }
  issue(principal, input) {
    fields(input, ['device_id', 'resource', 'destination', 'action', 'purpose', 'columns', 'row_ids', 'classification', 'jurisdiction', 'max_cost', 'ttl_ms']);
    identifier(input.device_id); identifier(input.resource); text(input.destination, 'destination'); oneOf(input.action, ['data.read', 'service.connect'], 'runtime action');
    for (const k of ['purpose', 'classification', 'jurisdiction']) text(input[k], k);
    uniqueStrings(input.columns, 'columns', 64); uniqueStrings(input.row_ids, 'rows', 256); integer(input.max_cost, 'cost ceiling', 1, 1e9); integer(input.ttl_ms, 'TTL', 1000, 300000);
    return this.f.transaction(principal, now => {
      const t = principal.tenant_id, policy = this.f.policy(t), r = policy.runtime, identity = this.f.identity(principal);
      this.f.assertHealthy(t, principal.subject_id, input.device_id, now);
      requireThat(identity.device_id === input.device_id && identity.grants.resources.includes(input.resource) && identity.grants.actions.includes(input.action), 'INV-403-SCOPE', 'Capability scope denied', 403);
      requireThat(r.destinations.includes(input.destination) && identity.grants.destinations.includes(input.destination) && r.purposes.includes(input.purpose) && r.classifications.includes(input.classification) && r.jurisdictions.includes(input.jurisdiction), 'INV-403-SCOPE', 'Capability context denied', 403);
      requireThat(input.columns.every(c => identity.grants.columns.includes(c) && !r.forbidden_columns.includes(c)) && input.row_ids.every(id => identity.grants.row_ids.includes(id)), 'INV-403-SCOPE', 'Dataset selection denied', 403);
      if (input.action === 'data.read') requireThat(input.columns.length && input.row_ids.length, 'INV-400-SCHEMA', 'Data capabilities require explicit rows and columns');
      if (input.action === 'service.connect') requireThat(r.services.includes(input.resource) && input.destination === input.resource && !input.columns.length && !input.row_ids.length, 'INV-403-SCOPE', 'Network service scope denied', 403);
      requireThat(input.max_cost <= r.max_cost && input.ttl_ms <= policy.capability_ttl_ms && policy.expires_at > now && policy.not_before <= now, 'INV-403-SCOPE', 'Capability limit denied', 403);
      const payload = { ...clone(input), capability_id: randomUUID(), tenant_id: t, subject_id: principal.subject_id, policy_digest: digest(policy), policy_version: policy.version, issued_at: now, expires_at: Math.min(now + input.ttl_ms, policy.expires_at), gate_id: this.f.config.gate_id, runtime_policy: clone(r) };
      const envelope = signed(payload, this.f.keys(t).execution, 'capability');
      this.f.store.insert(t, 'capability', payload.capability_id, envelope, now);
      this.f.store.audit(t, 'CAPABILITY_ISSUED', principal.subject_id, payload.capability_id, { digest: digest(envelope), resource: input.resource }, now);
      return envelope;
    });
  }
  consume(principal, input) {
    fields(input, ['capability', 'device_id', 'resource', 'destination', 'action', 'purpose', 'columns', 'row_ids', 'request_id', 'protocol', 'port']);
    identifier(input.request_id); identifier(input.device_id); identifier(input.resource); text(input.destination, 'destination');
    uniqueStrings(input.columns, 'columns', 64); uniqueStrings(input.row_ids, 'row ids', 256);
    oneOf(input.protocol, ['https'], 'protocol'); integer(input.port, 'port', 443, 443);
    return this.f.transaction(principal, now => {
      const t = principal.tenant_id, cap = verifySigned(input.capability, this.f.executionPublic(t), 'capability');
      requireThat(cap.tenant_id === t && cap.subject_id === principal.subject_id && cap.gate_id === this.f.config.gate_id, 'INV-403-SCOPE', 'Capability scope denied', 403);
      this.f.assertHealthy(t, principal.subject_id, input.device_id, now);
      requireThat(cap.expires_at > now && cap.issued_at <= now && !this.f.revoked(t, 'capability', cap.capability_id) && !this.f.revoked(t, 'key', input.capability.protected.key_id), 'INV-401-CAPABILITY', 'Capability is expired or revoked', 401);
      requireThat(this.f.store.get(t, 'capability', cap.capability_id) && cap.policy_digest === digest(this.f.policy(t)), 'INV-401-CAPABILITY', 'Capability policy is no longer active', 401);
      for (const key of ['device_id', 'resource', 'destination', 'action', 'purpose']) requireThat(input[key] === cap[key], 'INV-403-SCOPE', 'Capability binding mismatch', 403);
      requireThat(input.columns.every(c => cap.columns.includes(c)) && input.row_ids.every(id => cap.row_ids.includes(id)), 'INV-403-SCOPE', 'Data scope denied', 403);
      requireThat(input.action !== 'data.read' || (input.columns.length > 0 && input.row_ids.length > 0), 'INV-400-SCHEMA', 'Data request requires explicit selection');
      const exists = this.f.store.db.prepare('SELECT 1 FROM usage WHERE tenant=? AND capability=? AND request=?').get(t, cap.capability_id, input.request_id);
      requireThat(!exists, 'INV-409-REPLAY', 'Runtime request already consumed', 409);
      const r = cap.runtime_policy, cost = cap.action === 'data.read' ? input.row_ids.length * input.columns.length * r.sensitivity_weights[cap.classification] : 1;
      const used = this.f.store.db.prepare('SELECT coalesce(sum(cost),0) AS n FROM usage WHERE tenant=? AND capability=?').get(t, cap.capability_id).n;
      requireThat(used + cost <= cap.max_cost, 'INV-429-BUDGET', 'Capability volume exhausted', 429);
      // No caller-provided byte counts: charge observed requested information units.
      for (const window of r.windows) {
        const total = this.f.store.db.prepare('SELECT coalesce(sum(cost),0) AS n FROM usage WHERE tenant=? AND subject=? AND resource=? AND at>?').get(t, cap.subject_id, cap.resource, now - window.duration_ms).n;
        requireThat(total + cost <= window.limit, 'INV-429-BUDGET', 'Rolling information budget exhausted', 429);
      }
      const rate = this.f.store.db.prepare('SELECT count(*) AS n FROM usage WHERE tenant=? AND subject=? AND at>?').get(t, cap.subject_id, now - 1000).n;
      requireThat(rate < r.rate_per_second, 'INV-429-RATE', 'Subject request rate exceeded', 429);
      const resources = this.f.store.db.prepare('SELECT DISTINCT resource FROM usage WHERE tenant=? AND subject=? AND at>?').all(t, cap.subject_id, now - 1000).map(x => x.resource);
      requireThat(resources.includes(cap.resource) || resources.length < r.max_fanout, 'INV-429-FANOUT', 'Service fan-out exceeded', 429);
      let rows = null;
      if (cap.action === 'data.read') {
        const dataset = this.f.target.state(t, cap.resource).material_fields;
        requireThat(dataset.classification === cap.classification && dataset.jurisdiction === cap.jurisdiction, 'INV-409-STATE', 'Dataset classification or jurisdiction changed', 409);
        rows = this.f.target.readDataset(t, cap.resource, input.columns, input.row_ids, input.row_ids.length);
      }
      this.f.store.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?)').run(t, cap.subject_id, cap.resource, now, cost, cap.capability_id, input.request_id);
      this.f.store.audit(t, 'RUNTIME_ALLOWED', principal.subject_id, cap.capability_id, { cost, resource: cap.resource, selection_digest: digest({ columns: input.columns, rows: input.row_ids }), request_id: input.request_id }, now);
      return { decision: 'ALLOW', cost, remaining_capability_cost: cap.max_cost - used - cost, rows, attribution: { tenant_id: t, subject_id: principal.subject_id, request_id: input.request_id }, simulation: true, limitation: cap.action === 'service.connect' ? 'Software decision only; no packet or socket enforcement is provided.' : 'Reads the isolated synthetic dataset only.' };
    });
  }
}

import { randomUUID } from 'node:crypto';
import { digest, clone } from './canonical.mjs';
import { verifySigned } from './crypto.mjs';
import { fields, identifier, text, integer, oneOf, uniqueStrings } from './schema.mjs';
import { watermark, applyTransforms, reconstructionCheck } from './datagate.mjs';
import { requireThat, InvariantError } from './errors.mjs';

export class RuntimeGate {
  constructor(fabric) { this.f = fabric; }
  issue(principal, input) {
    // Role binding at issue (runtime-audit F-11): capabilities exist only
    // for the workload plane — custodian/auditor identities cannot mint them.
    this.f.authorize(principal, ['operator', 'workload']);
    fields(input, ['device_id', 'resource', 'destination', 'action', 'purpose', 'columns', 'row_ids', 'classification', 'jurisdiction', 'max_cost', 'ttl_ms'], ['transforms']);
    identifier(input.device_id); identifier(input.resource); text(input.destination, 'destination'); oneOf(input.action, ['data.read', 'service.connect'], 'runtime action');
    for (const k of ['purpose', 'classification', 'jurisdiction']) text(input[k], k);
    uniqueStrings(input.columns, 'columns', 64); uniqueStrings(input.row_ids, 'rows', 256); integer(input.max_cost, 'cost ceiling', 1, 1e9); integer(input.ttl_ms, 'TTL', 1000, 300000);
    if (input.transforms !== undefined) { requireThat(input.transforms !== null && typeof input.transforms === 'object' && !Array.isArray(input.transforms), 'INV-400-SCHEMA', 'Transforms must be an object keyed by column'); for (const [col, tr] of Object.entries(input.transforms)) { requireThat(tr !== null && typeof tr === 'object' && !Array.isArray(tr), 'INV-400-SCHEMA', 'Transform must be an object'); oneOf(tr.op, ['mask', 'tokenise', 'drop', 'constant', 'aggregate'], 'transform op'); } }
    return this.f.transaction(principal, now => {
      const t = principal.tenant_id, policy = this.f.policy(t), r = policy.runtime, identity = this.f.identity(principal);
      this.f.assertHealthy(t, principal.subject_id, input.device_id, now);
      // Effective grants = static grants ∪ active JIT action-grants (IDN).
      const grants = this.f.grantsFor(t, principal.subject_id, now);
      // NET-001/002: workstation-class peers are never reachable through a
      // service capability; east-west is default-deny by constitution. This
      // precedes grant-scope checks so a peer-named destination reports the
      // segmentation denial, not a generic scope one.
      if (input.action === 'service.connect') {
        requireThat(!(r.network?.deny_workstation_peers && /^ws-|^workstation-|^endpoint-/.test(input.resource)), 'INV-451-POLICY', 'Workstation peers are not a service destination', 451);
      }
      requireThat(identity.device_id === input.device_id && grants.resources.includes(input.resource) && grants.actions.includes(input.action), 'INV-403-SCOPE', 'Capability scope denied', 403);
      requireThat(r.destinations.includes(input.destination) && grants.destinations.includes(input.destination) && r.purposes.includes(input.purpose) && r.classifications.includes(input.classification) && r.jurisdictions.includes(input.jurisdiction), 'INV-403-SCOPE', 'Capability context denied', 403);
      requireThat(input.columns.every(c => grants.columns.includes(c) && !r.forbidden_columns.includes(c) && r.allowed_columns.includes(c)) && input.row_ids.every(id => grants.row_ids.includes(id)), 'INV-403-SCOPE', 'Dataset selection denied', 403);
      if (input.action === 'data.read') {
        requireThat(input.columns.length && input.row_ids.length, 'INV-400-SCHEMA', 'Data capabilities require explicit rows and columns');
        // Catalog ceilings (policy-audit F7): only policy-declared datasets.
        requireThat(r.datasets.includes(input.resource), 'INV-403-SCOPE', 'Dataset is not policy-declared', 403);
      }
      // Transformation policy (runtime-audit F-8): declared ops only, and
      // the row key itself can never be transformed — that would silently
      // defeat the reconstruction ledger.
      for (const [col, tr] of Object.entries(input.transforms ?? {})) {
        requireThat(r.allowed_transforms.includes(tr.op), 'INV-403-SCOPE', `Transform ${tr.op} is not policy-declared`, 403);
        requireThat(col !== 'id', 'INV-403-SCOPE', 'The row key column cannot be transformed', 403);
      }
      if (input.action === 'service.connect') {
        requireThat(r.services.includes(input.resource) && input.destination === input.resource && !input.columns.length && !input.row_ids.length, 'INV-403-SCOPE', 'Network service scope denied', 403);
      }
      requireThat(input.max_cost <= r.max_cost && input.ttl_ms <= policy.capability_ttl_ms && policy.expires_at > now && policy.not_before <= now, 'INV-403-SCOPE', 'Capability limit denied', 403);
      const payload = { ...clone(input), capability_id: randomUUID(), tenant_id: t, subject_id: principal.subject_id, policy_digest: digest(policy), policy_version: policy.version, issued_at: now, expires_at: Math.min(now + input.ttl_ms, policy.expires_at), gate_id: this.f.config.gate_id, runtime_policy: clone(r) };
      const envelope = this.f.signExecution(t, payload, 'capability');
      this.f.store.insert(t, 'capability', payload.capability_id, envelope, now);
      this.f.store.audit(t, 'CAPABILITY_ISSUED', principal.subject_id, payload.capability_id, { digest: digest(envelope), resource: input.resource }, now);
      return envelope;
    });
  }
  consume(principal, input) {
    fields(input, ['capability', 'device_id', 'resource', 'destination', 'action', 'purpose', 'columns', 'row_ids', 'request_id', 'protocol', 'port']);
    identifier(input.request_id); identifier(input.device_id); identifier(input.resource); text(input.destination, 'destination');
    uniqueStrings(input.columns, 'columns', 64); uniqueStrings(input.row_ids, 'row ids', 256);
    try {
      return this.f.transaction(principal, now => {
      const t = principal.tenant_id, policy = this.f.policy(t);
      // Role binding at consume too — a leaked envelope cannot be spent by
      // an identity outside the workload plane (runtime-audit F-11).
      this.f.authorize(principal, ['operator', 'workload']);
      const cap = verifySigned(input.capability, this.f.executionPublic(t), 'capability');
      // NET-003: the wire channel is bound by the capability's SIGNED
      // runtime_policy snapshot, not whatever the live policy now allows —
      // a later widening cannot retro-extend an outstanding capability to
      // adjacent ports or weaker protocols (w9-network F3).
      const netAllow = cap.runtime_policy?.network ?? policy.runtime.network ?? {};
      oneOf(input.protocol, netAllow.allowed_protocols ?? ['https'], 'protocol');
      oneOf(input.port, netAllow.allowed_ports ?? [443], 'port');
      requireThat(cap.tenant_id === t && cap.subject_id === principal.subject_id && cap.gate_id === this.f.config.gate_id, 'INV-403-SCOPE', 'Capability scope denied', 403);
      this.f.assertHealthy(t, principal.subject_id, input.device_id, now);
      requireThat(cap.expires_at > now && cap.issued_at <= now && !this.f.revoked(t, 'capability', cap.capability_id) && !this.f.revoked(t, 'key', input.capability.protected.key_id), 'INV-401-CAPABILITY', 'Capability is expired or revoked', 401);
      // JIT/static grant validity is re-evaluated AT CONSUMPTION — a grant
      // revoked since issuance cannot ride a signed envelope past policy
      // (runtime-audit F-4).
      const live = this.f.grantsFor(t, cap.subject_id, now);
      requireThat(live.resources.includes(cap.resource) && live.actions.includes(cap.action) && live.destinations.includes(cap.destination) && cap.columns.every(c => live.columns.includes(c)) && cap.row_ids.every(id => live.row_ids.includes(id)), 'INV-403-SCOPE', 'Underlying grant is revoked, expired, or narrowed', 403);
      // RUN-005 / fail-mode matrix: a capability minted under a superseded
      // policy is honoured only for classes configured cached-allow, and only
      // inside max_stale_ms; everything else fails closed.
      let constrained = false;
      if (cap.policy_digest !== digest(policy)) {
        const mode = policy.fail_modes?.[cap.action] ?? policy.fail_modes?.default ?? 'closed';
        // Per-class staleness ceiling (NFR-AVL-004): stale_ms[class] tightens
        // the global max_stale_ms window for that class only.
        const staleWindow = policy.stale_ms?.[cap.action] ?? policy.stale_ms?.default ?? policy.max_stale_ms;
        if (mode === 'constrained') {
          // 'Constrained' (RUN-005): stale access is read-only at half the
          // capability budget — never writes, never full cost.
          requireThat(cap.action === 'data.read' && now - cap.issued_at <= staleWindow, 'INV-503-GATE', `Policy changed; fail mode for ${cap.action} is constrained`, 503);
          constrained = true;
        } else {
          requireThat(mode === 'cached-allow' && now - cap.issued_at <= staleWindow, 'INV-503-GATE', `Policy changed; fail mode for ${cap.action} is ${mode}`, 503);
        }
      }
      requireThat(this.f.store.get(t, 'capability', cap.capability_id), 'INV-401-CAPABILITY', 'Unknown capability', 401);
      for (const key of ['device_id', 'resource', 'destination', 'action', 'purpose']) requireThat(input[key] === cap[key], 'INV-403-SCOPE', 'Capability binding mismatch', 403);
      requireThat(input.columns.every(c => cap.columns.includes(c)) && input.row_ids.every(id => cap.row_ids.includes(id)), 'INV-403-SCOPE', 'Data scope denied', 403);
      requireThat(input.action !== 'data.read' || (input.columns.length > 0 && input.row_ids.length > 0), 'INV-400-SCHEMA', 'Data request requires explicit selection');
      // Replay/budget/rate/fanout authority is the signed chain, not the
      // mutable usage table — an insider who can DELETE or INSERT usage rows
      // can otherwise replay a request, refill a budget, or clear the
      // fan-out set (w13-fixverify M1). The usage INSERT below stays as an
      // observability mirror only.
      const idx = this.f._auditIndex(t);
      // The fold keeps per-capability and per-subject indexes — scanning
      // the whole runtime history per request was a quadratic sink
      // (w17-idx F8). Fall back to the flat list only on a stale index
      // built before the maps existed.
      const byCap = idx.runtimeUseByCap?.get(cap.capability_id) ?? idx.runtimeUse.filter(u => u.capability === cap.capability_id);
      const bySubject = idx.runtimeUseBySubject?.get(cap.subject_id) ?? idx.runtimeUse.filter(u => u.subject === cap.subject_id);
      const exists = byCap.some(u => u.request_id === input.request_id);
      requireThat(!exists, 'INV-409-REPLAY', 'Runtime request already consumed', 409);
      const r = cap.runtime_policy, cost = cap.action === 'data.read' ? input.row_ids.length * input.columns.length * r.sensitivity_weights[cap.classification] : 1;
      const used = byCap.reduce((n, u) => n + (u.cost ?? 0), 0);
      requireThat(used + cost <= (constrained ? Math.floor(cap.max_cost / 2) : cap.max_cost), 'INV-429-BUDGET', 'Capability volume exhausted', 429);
      // No caller-provided byte counts: charge observed requested information units.
      for (const window of r.windows) {
        // The rolling budget is deliberately per (subject, resource): a
        // per-dataset anti-enumeration bound, not a subject-wide quota —
        // the subject-wide spend ceiling is carried by cap.max_cost /
        // rate / fanout separately (w20-datagate F7, documented semantic).
        const total = bySubject.filter(u => u.resource === cap.resource && u.at > now - window.duration_ms).reduce((n, u) => n + (u.cost ?? 0), 0);
        requireThat(total + cost <= window.limit, 'INV-429-BUDGET', 'Rolling information budget exhausted', 429);
      }
      const rate = bySubject.filter(u => u.at > now - 1000).length;
      requireThat(rate < r.rate_per_second, 'INV-429-RATE', 'Subject request rate exceeded', 429);
      const resources = [...new Set(bySubject.filter(u => u.at > now - 1000).map(u => u.resource))];
      requireThat(resources.includes(cap.resource) || resources.length < r.max_fanout, 'INV-429-FANOUT', 'Service fan-out exceeded', 429);
      let rows = null, recon = null, watermarks = null;
      if (cap.action === 'data.read') {
        const dataset = this.f.target.state(t, cap.resource).material_fields;
        requireThat(dataset.classification === cap.classification && dataset.jurisdiction === cap.jurisdiction, 'INV-409-STATE', 'Dataset classification or jurisdiction changed', 409);
        // DAT-009: cumulative overlap/reconstruction check BEFORE release.
        recon = reconstructionCheck(this.f.store.db, this.f.target.db, { tenant: t, subject: cap.subject_id, dataset: cap.resource, rows: input.row_ids, columns: input.columns, now, policy: r.reconstruction, access: this.f._auditIndex(t).dataAccess });
        requireThat(recon.allowed, 'INV-429-BUDGET', `Reconstruction limit reached (${recon.coverage_percent}% of dataset rows touched)`, 429, { row_count: recon.row_count, column_count: recon.column_count, coverage_percent: recon.coverage_percent });
        // The plan rebinds to the authorising capability — the request's
        // own fields are not the grant (w20-datagate F8).
        rows = this.f.target.readDataset(t, cap.resource, input.columns, input.row_ids, input.row_ids.length, { dataset: cap.resource, columns: cap.columns, row_ids: cap.row_ids, max_rows: cap.row_ids.length });
        if (cap.transforms) {
          // Pseudonyms get their own primitive: tokenise never shares the
          // row-encryption key — the same fusion the watermark path
          // refuses (w20-datagate F5).
          const tokeniseKey = this.f.dataKey(t, 'tokenise');
          requireThat(tokeniseKey, 'INV-503-CONFIG', `Tenant ${t} has no tokenise data key`, 503);
          rows = applyTransforms(rows, cap.transforms, { tenant: t, dataset: cap.resource, tenantKey: tokeniseKey });
        }
        // DAT-011: attribution watermark on released rows — returned as
        // separate marks, never injected into the authorised columns.
        // Attribution marks require the dedicated watermark key — the
        // row-encryption key is a different primitive, not a fallback
        // (w10-datagate F10).
        const watermarkKey = this.f.dataKey(t, 'watermark');
        requireThat(watermarkKey, 'INV-503-CONFIG', `Tenant ${t} has no watermark data key`, 503);
        watermarks = watermark(rows, { tenant: t, dataset: cap.resource, subject: cap.subject_id, capabilityId: cap.capability_id, requestId: input.request_id, tenantWatermarkKey: watermarkKey }).watermarks;
      }
      this.f.store.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?)').run(t, cap.subject_id, cap.resource, now, cost, cap.capability_id, input.request_id);
      // The disclosure is attested on the signed chain — the data_access
      // table is only a mirror of this event (w11-redteam R9).
      // The disclosure event binds the authorising capability and request
      // — a consume-path attestation is traceable to its authority, same
      // as the export path's certificate_id binding (w20-datagate F6).
      if (cap.action === 'data.read') this.f.store.audit(t, 'DATA_ACCESSED', cap.subject_id, cap.subject_id, { dataset: cap.resource, row_ids: input.row_ids, columns: input.columns, at: now, capability_id: cap.capability_id, request_id: input.request_id }, now);
      this.f.store.audit(t, 'RUNTIME_ALLOWED', principal.subject_id, cap.capability_id, { cost, resource: cap.resource, selection_digest: digest({ columns: input.columns, rows: input.row_ids }), request_id: input.request_id, watermarked: cap.action === 'data.read' }, now);
      return { decision: 'ALLOW', cost, remaining_capability_cost: cap.max_cost - used - cost, rows, watermarks, reconstruction: recon && { row_count: recon.row_count, coverage_percent: recon.coverage_percent }, attribution: { tenant_id: t, subject_id: principal.subject_id, request_id: input.request_id }, simulation: true, limitation: cap.action === 'service.connect' ? 'Software decision only; no packet or socket enforcement is provided.' : 'Reads the isolated synthetic dataset only.' };
      });
    } catch (e) {
      if (e instanceof InvariantError) this.recordContainment(principal, input, e);
      throw e;
    }
  }
  // NET-010: every denied consume lands in the containment ledger — the
  // incident report reconstructs the containment sequence from these records
  // plus subject/device revocations (see fabric.containmentReport).
  recordContainment(principal, input, e) {
    try {
      const t = principal.tenant_id, now = this.f.clock();
      // A denied consume must not mint unbounded ledger rows — identical
      // (subject, code, capability) denials re-record at most once per
      // 60s, the same bound _rejectionAudit applies to gate denials
      // (w17-idx F7). The ledger still proves the denial happened, just
      // not at request frequency.
      this.f._containMemo ??= new Map();
      // The dedup key must not carry unverified request fields: the
      // envelope failed verification, so its capability_id is an
      // attacker-chosen salt that un-budgets the signed-ledger write
      // (w18-fixverify F4). And the window is consumed only by a write
      // that lands — a failed insert must not suppress the next denial's
      // evidence (w18-fixverify F14).
      const memoKey = `${t} ${principal.subject_id} ${e.code}`;
      const last = this.f._containMemo.get(memoKey);
      if (last !== undefined && now - last < 60_000) return;
      this.f.store.tx(() => { this.f.store.put(t, 'containment', `deny:${randomUUID()}:${e.code}`, {
        contained_at: now, subject_id: principal.subject_id, device_id: input.device_id ?? null,
        capability_id: input.capability?.payload?.capability_id ?? null, resource: input.resource ?? null,
        destination: input.destination ?? null, action: input.action ?? null, code: e.code,
        request_id: input.request_id, dropped_requests: 1,
      }, now);
      // The denial anchors on the signed chain too — the containment report
      // cross-checks each mutable row against RUNTIME_DENIED events instead
      // of trusting store contents (w13-fixverify L7).
      this.f.store.audit(t, 'RUNTIME_DENIED', principal.subject_id, input.request_id ?? 'unknown', { code: e.code, capability_id: input.capability?.payload?.capability_id ?? null }, now); });
      this.f._containMemo.set(memoKey, now);
    } catch { /* containment logging never masks the original denial */ }
  }
}

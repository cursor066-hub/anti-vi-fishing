import { randomUUID } from 'node:crypto';
import { Store } from './store.mjs';
import { SimulatedTarget } from './target.mjs';
import { RuntimeGate } from './runtime.mjs';
import { digest, clone, canonical } from './canonical.mjs';
import { signed, verifySigned } from './crypto.mjs';
import { fields, text, identifier, integer, uniqueStrings, validateProposal } from './schema.mjs';
import { evaluatePolicy, validatePolicy, policyDiff } from './policy.mjs';
import { declarePath, coverageManifest } from './coverage.mjs';
import { requireThat, InvariantError } from './errors.mjs';
import { join } from 'node:path';

export class Fabric {
  constructor(config, directory, clock = Date.now) {
    requireThat(config.profile === 'engineering', 'INV-503-RELEASE', 'Production mode is blocked: external acceptance evidence is missing', 503);
    this.config = config; this.directory = directory; this.clock = clock;
    const encryption = {}, audit = {};
    for (const [tenant, t] of Object.entries(config.tenants)) { encryption[tenant] = t.encryption_key; audit[tenant] = t.keys.audit; }
    this.store = new Store(join(directory, 'fabric.db'), encryption, audit);
    this.target = new SimulatedTarget(join(directory, 'target.db'), encryption); this.runtime = new RuntimeGate(this);
    try { for (const [tenant, t] of Object.entries(config.tenants)) {
      validatePolicy(t.genesis_policy);
      requireThat(t.genesis_policy.tenant_id === tenant, 'INV-503-CONFIG', 'Genesis tenant mismatch', 503);
      const roots = new Set(), domains = new Set();
      for (const sig of t.genesis_signatures) {
        const p = verifySigned(sig, t.identities, 'root-policy'), who = t.identities[sig.protected.key_id];
        requireThat(who.roles.includes('custodian') && digest(p) === digest(t.genesis_policy), 'INV-503-CONFIG', 'Invalid genesis governance', 503);
        roots.add(sig.protected.key_id); domains.add(who.failure_domain);
      }
      requireThat(roots.size >= 3 && domains.size >= 3, 'INV-503-CONFIG', 'Genesis requires independent 3-of-5 software signatures', 503);
      this.store.tx(() => {
        if (!this.store.get(tenant, 'policy', 'active')) {
          this.store.put(tenant, 'policy', 'active', t.genesis_policy, this.clock());
          this.store.audit(tenant, 'POLICY_GENESIS', 'customer-bootstrap', t.genesis_policy.policy_id, { policy_digest: digest(t.genesis_policy), software_quorum: roots.size }, this.clock());
        }
      });
    } } catch (error) { this.close(); throw error; }
  }
  close() { this.target.close(); this.store.close(); }
  tenant(t) { const row = this.config.tenants[t]; requireThat(row, 'INV-404-NOT-FOUND', 'Resource not found', 404); return row; }
  keys(t) { return this.tenant(t).keys; }
  executionPublic(t) { const key = this.keys(t).execution; return { [key.key_id]: { public_key: key.public_key } }; }
  identity(p) {
    const identity = Object.values(this.tenant(p.tenant_id).identities).find(x => x.subject_id === p.subject_id);
    requireThat(identity && !identity.revoked, 'INV-401-AUTH', 'Authentication required', 401); return identity;
  }
  authorize(p, roles) {
    requireThat(p && this.config.tenants[p.tenant_id], 'INV-401-AUTH', 'Authentication required', 401);
    const identity = this.identity(p);
    requireThat(identity.roles.some(r => roles.includes(r)), 'INV-403-ROLE', 'Permission denied', 403);
    requireThat(!this.revoked(p.tenant_id, 'subject', p.subject_id), 'INV-403-QUARANTINE', 'Identity unavailable', 403);
    return identity;
  }
  transaction(principal, fn) {
    this.authorize(principal, ['operator', 'approver', 'custodian', 'security', 'auditor', 'policy_admin', 'workload']);
    try { return this.store.tx(() => { const now = this.clock(); this.store.clock(now); return fn(now); }); }
    catch (error) {
      if (error instanceof InvariantError && error.code !== 'INV-503-TIME') {
        this.store.tx(() => { const now = this.clock(); this.store.clock(now); this.store.audit(principal.tenant_id, 'SECURITY_OPERATION_REJECTED', principal.subject_id, 'local-gate', { code: error.code }, now); });
      }
      throw error;
    }
  }
  revoked(tenant, kind, id) { return Boolean(this.store.get(tenant, 'revocation', `${kind}:${id}`)); }
  policy(t) { return this.store.must(t, 'policy', 'active'); }
  identities(t) { return Object.fromEntries(Object.entries(this.tenant(t).identities).map(([id, v]) => [id, { ...v, revoked: v.revoked || this.revoked(t, 'key', id) || this.revoked(t, 'subject', v.subject_id) }])); }
  assertHealthy(t, subject, device, now) {
    requireThat(!this.revoked(t, 'subject', subject) && !this.revoked(t, 'device', device), 'INV-403-QUARANTINE', 'Subject or device quarantined', 403);
    const identity = Object.values(this.tenant(t).identities).find(x => x.subject_id === subject);
    requireThat(identity && identity.device_id === device && identity.health_expires_at > now, 'INV-403-HEALTH', 'Configured device health evidence expired or mismatched', 403);
  }
  getCapsule(p, id) { this.authorize(p, ['operator', 'approver', 'custodian', 'security', 'policy_admin']); return this.store.must(p.tenant_id, 'capsule', identifier(id)); }
  propose(p, input, idempotencyKey) {
    this.authorize(p, ['operator', 'workload', 'policy_admin']); validateProposal(input);
    requireThat(input.actor.subject_id === p.subject_id && input.actor.identity_class === this.identity(p).identity_class, 'INV-403-ACTOR', 'Actor must match authenticated identity', 403);
    return this.transaction(p, now => this.store.idempotent(p.tenant_id, 'propose', idempotencyKey, digest(input), () => {
      const policy = this.policy(p.tenant_id); this.assertHealthy(p.tenant_id, p.subject_id, input.actor.device_id, now);
      requireThat(input.created_at <= now + 5000 && input.created_at >= now - 300000 && input.expires_at > now && input.expires_at - input.created_at <= policy.max_capsule_ttl_ms, 'INV-400-SCHEMA', 'Capsule timing invalid');
      const prior = this.store.db.prepare('SELECT capsule FROM nonces WHERE tenant=? AND nonce=?').get(p.tenant_id, input.nonce);
      requireThat(!prior, 'INV-409-REPLAY', 'Nonce is already bound to another action', 409);
      const capsule = { ...clone(input), capsule_id: randomUUID(), tenant_id: p.tenant_id };
      const record = { capsule, capsule_digest: digest(capsule), status: 'CANONICALISED', evidence: [], approvals: [], decision: null, certificate_id: null, created_at: now };
      this.store.db.prepare('INSERT INTO nonces VALUES(?,?,?)').run(p.tenant_id, input.nonce, capsule.capsule_id);
      this.store.insert(p.tenant_id, 'capsule', capsule.capsule_id, record, now);
      this.store.audit(p.tenant_id, 'CAPSULE_PROPOSED', p.subject_id, capsule.capsule_id, { capsule_digest: record.capsule_digest, action_type: capsule.action.type }, now);
      return record;
    }));
  }
  ensureMutable(record) { requireThat(!['DENY', 'CANCELLED', 'CERTIFIED', 'EXECUTING', 'VERIFIED', 'UNCERTAIN', 'FAILED'].includes(record.status), 'INV-409-STATE', 'Action is immutable in its current state', 409); }
  graph(t, record) {
    const items = record.evidence.map(id => {
      const e = this.store.get(t, 'evidence', id);
      if (!e) {
        const tombstone = this.store.must(t, 'evidence-tombstone', id);
        return { payload: { evidence_id: id, expires_at: 0 }, envelope: { retained_digest: tombstone.original_digest }, revoked: true, issuer: { failure_domain: 'deleted' } };
      }
      return { ...e, revoked: this.revoked(t, 'evidence', id) || this.revoked(t, 'issuer', e.envelope.protected.key_id) || this.revoked(t, 'key', e.envelope.protected.key_id), issuer: this.tenant(t).issuers[e.envelope.protected.key_id] };
    });
    const graph_digest = digest(items.map(e => ({ envelope_digest: digest(e.envelope), issuer_digest: digest(e.issuer), revoked: e.revoked })).sort((a, b) => a.envelope_digest < b.envelope_digest ? -1 : 1));
    return { items, digest: graph_digest };
  }
  attachEvidence(p, id, envelope) {
    this.authorize(p, ['operator', 'security', 'policy_admin']);
    return this.transaction(p, now => {
      const t = p.tenant_id, record = this.store.must(t, 'capsule', id); this.ensureMutable(record);
      const payload = verifySigned(envelope, this.tenant(t).issuers, 'evidence');
      fields(payload, ['evidence_id', 'tenant_id', 'capsule_digest', 'kind', 'content_digest', 'acquired_at', 'expires_at', 'confidence', 'advisory', 'claim', 'dependencies', 'provenance', 'retention_until']);
      identifier(payload.evidence_id); text(payload.kind, 'evidence kind'); text(payload.provenance, 'provenance', 2048); uniqueStrings(payload.dependencies, 'dependencies', 32);
      requireThat(payload.tenant_id === t && payload.capsule_digest === record.capsule_digest, 'INV-403-SCOPE', 'Evidence scope mismatch', 403);
      integer(payload.confidence, 'confidence', 0, 100); integer(payload.acquired_at, 'acquisition time', 1, now); integer(payload.expires_at, 'evidence expiry', now + 1); integer(payload.retention_until, 'retention', payload.expires_at);
      requireThat(typeof payload.advisory === 'boolean' && ['supports', 'conflict'].includes(payload.claim) && /^[a-f0-9]{64}$/.test(payload.content_digest), 'INV-400-SCHEMA', 'Invalid evidence claim');
      requireThat(!this.revoked(t, 'issuer', envelope.protected.key_id) && !this.revoked(t, 'key', envelope.protected.key_id) && !this.revoked(t, 'evidence', payload.evidence_id), 'INV-401-EVIDENCE', 'Evidence source revoked', 401);
      requireThat(payload.dependencies.every(dep => record.evidence.includes(dep)), 'INV-400-SCHEMA', 'Dependencies must already belong to this action');
      requireThat(record.evidence.length < 32, 'INV-429-CAPACITY', 'Evidence set limit reached', 429);
      const issuer = this.tenant(t).issuers[envelope.protected.key_id];
      requireThat(issuer.kinds.includes(payload.kind), 'INV-403-SCOPE', 'Issuer is not trusted for this evidence kind', 403);
      this.store.insert(t, 'evidence', payload.evidence_id, { payload: clone(payload), envelope: clone(envelope), legal_hold: false }, now);
      record.evidence.push(payload.evidence_id); record.status = 'EVIDENCED'; record.approvals = []; record.decision = null;
      this.store.put(t, 'capsule', id, record, now); this.store.audit(t, 'EVIDENCE_ATTACHED', p.subject_id, id, { evidence_id: payload.evidence_id, evidence_digest: digest(envelope) }, now);
      return { evidence_id: payload.evidence_id, evidence_graph_digest: this.graph(t, record).digest };
    });
  }
  approvalChallenge(p, id) {
    this.authorize(p, ['approver', 'custodian']); const r = this.store.must(p.tenant_id, 'capsule', id); this.ensureMutable(r);
    const now = this.clock(), key = Object.entries(this.identities(p.tenant_id)).find(([, v]) => v.subject_id === p.subject_id);
    return { tenant_id: p.tenant_id, capsule_id: id, capsule_digest: r.capsule_digest, evidence_graph_digest: this.graph(p.tenant_id, r).digest, policy_digest: digest(this.policy(p.tenant_id)), signer_id: key[0], approved_at: now, expires_at: Math.min(now + 300000, r.capsule.expires_at) };
  }
  approve(p, envelope) {
    this.authorize(p, ['approver', 'custodian']);
    return this.transaction(p, now => {
      const t = p.tenant_id, payload = verifySigned(envelope, this.identities(t), 'action-approval');
      fields(payload, ['tenant_id', 'capsule_id', 'capsule_digest', 'evidence_graph_digest', 'policy_digest', 'signer_id', 'approved_at', 'expires_at']);
      requireThat(payload.tenant_id === t && payload.signer_id === envelope.protected.key_id, 'INV-403-SCOPE', 'Approval scope mismatch', 403);
      const identity = this.identities(t)[payload.signer_id]; requireThat(identity.subject_id === p.subject_id, 'INV-403-SCOPE', 'Approval signer does not match authenticated identity', 403);
      const record = this.store.must(t, 'capsule', payload.capsule_id); this.ensureMutable(record);
      requireThat(identity.subject_id !== record.capsule.actor.subject_id, 'INV-403-SEPARATION', 'An initiator cannot approve their own action', 403);
      requireThat(payload.capsule_digest === record.capsule_digest && payload.evidence_graph_digest === this.graph(t, record).digest && payload.policy_digest === digest(this.policy(t)), 'INV-409-STATE', 'Approval no longer matches action, evidence or policy', 409);
      integer(payload.approved_at, 'approval time', now - 300000, now + 5000); integer(payload.expires_at, 'approval expiry', now + 1, Math.min(record.capsule.expires_at, payload.approved_at + 300000));
      requireThat(!record.approvals.some(a => a.payload.signer_id === payload.signer_id), 'INV-409-REPLAY', 'Signer already approved this action', 409);
      record.approvals.push(clone(envelope)); this.store.put(t, 'capsule', payload.capsule_id, record, now);
      this.store.audit(t, 'EXACT_ACTION_APPROVED', p.subject_id, payload.capsule_id, { approval_digest: digest(envelope), signer_id: payload.signer_id }, now);
      return { accepted: true, software_key: !identity.hardware_backed, approvals: record.approvals.length };
    });
  }
  evaluation(t, record, now, policy = this.policy(t)) {
    const graph = this.graph(t, record), identities = this.identities(t);
    if (record.capsule.action.type === 'policy.change') {
      const candidateDigest = digest(record.capsule.requested_state.policy);
      const reviewed = this.store.list(t, 'simulation', 500).some(s => s.candidate_digest === candidateDigest && s.baseline_digest === digest(this.policy(t)));
      if (!reviewed) return { decision: 'ESCROW', reasons: [{ code: 'SIMULATION_REQUIRED', message: 'Simulate the exact candidate policy against the active baseline before activation.' }], explanation: 'Exact policy simulation is required.', owner: record.capsule.actor.subject_id, expires_at: record.capsule.expires_at, evaluated_at: now, policy_version: policy.version, policy_digest: digest(policy) };
    }
    const approvals = record.approvals.filter(a => a.payload.policy_digest === digest(policy) && a.payload.evidence_graph_digest === graph.digest).map(a => {
      try { return verifySigned(a, identities, 'action-approval'); } catch { return null; }
    }).filter(Boolean);
    return evaluatePolicy({ capsule: record.capsule, policy, evidence: graph.items, approvals, identities, quarantined: this.revoked(t, 'subject', record.capsule.actor.subject_id) || this.revoked(t, 'device', record.capsule.actor.device_id), now });
  }
  evaluate(p, id) {
    this.authorize(p, ['operator', 'policy_admin', 'approver', 'custodian']);
    return this.transaction(p, now => {
      const record = this.store.must(p.tenant_id, 'capsule', id); this.ensureMutable(record);
      record.decision = this.evaluation(p.tenant_id, record, now); record.status = record.decision.decision;
      this.store.put(p.tenant_id, 'capsule', id, record, now); this.store.audit(p.tenant_id, 'POLICY_EVALUATED', p.subject_id, id, { decision: record.status, decision_digest: digest(record.decision) }, now);
      return record.decision;
    });
  }
  certificate(p, id) {
    this.authorize(p, ['operator', 'policy_admin']);
    return this.transaction(p, now => {
      const t = p.tenant_id, r = this.store.must(t, 'capsule', id); this.ensureMutable(r);
      requireThat(!r.certificate_id, 'INV-409-REPLAY', 'Action already has a certificate', 409);
      const decision = this.evaluation(t, r, now), policy = this.policy(t);
      requireThat(decision.decision === 'ALLOW', 'INV-412-EVIDENCE', 'Only ALLOW may receive an execution certificate', 412, decision);
      this.assertHealthy(t, r.capsule.actor.subject_id, r.capsule.actor.device_id, now);
      const graph = this.graph(t, r), expiry = Math.min(now + policy.certificate_ttl_ms, r.capsule.expires_at, policy.expires_at, ...graph.items.map(e => e.payload.expires_at), ...r.approvals.map(a => a.payload.expires_at));
      const payload = { certificate_id: randomUUID(), tenant_id: t, capsule_id: id, capsule_digest: r.capsule_digest, evidence_graph_digest: graph.digest, policy_id: policy.policy_id, policy_version: policy.version, policy_digest: digest(policy), decision: 'ALLOW', constraints: { destination: r.capsule.destination, quantity: r.capsule.quantity, requested_digest: digest(r.capsule.requested_state), current_state: r.capsule.current_state, exclusions: r.capsule.exclusions }, target_gate_id: this.config.gate_id, signer_set: decision.eligible_signers, nonce: r.capsule.nonce, issued_at: now, expires_at: expiry, single_use: true, revocation_ref: `certificate:${id}` };
      requireThat(!this.revoked(t, 'key', this.keys(t).execution.key_id), 'INV-401-SIGNATURE', 'Execution key revoked', 401);
      const envelope = signed(payload, this.keys(t).execution, 'action-certificate');
      this.store.insert(t, 'certificate', payload.certificate_id, { envelope, consumed: false, status: 'CERTIFIED' }, now);
      r.certificate_id = payload.certificate_id; r.status = 'CERTIFIED'; r.decision = decision; this.store.put(t, 'capsule', id, r, now);
      this.store.audit(t, 'CERTIFICATE_ISSUED', p.subject_id, id, { certificate_id: payload.certificate_id, certificate_digest: digest(envelope) }, now); return envelope;
    });
  }
  execute(p, envelope, { dryRun = false, fault = null } = {}) {
    this.authorize(p, ['operator', 'policy_admin']);
    // Reservation commits before target dispatch. An ambiguous result is never re-dispatched.
    const reservation = this.transaction(p, now => {
      const t = p.tenant_id, cert = verifySigned(envelope, this.executionPublic(t), 'action-certificate');
      requireThat(cert.tenant_id === t && cert.target_gate_id === this.config.gate_id, 'INV-403-SCOPE', 'Certificate scope mismatch', 403);
      requireThat(!this.revoked(t, 'key', envelope.protected.key_id) && !this.revoked(t, 'certificate', cert.certificate_id) && cert.issued_at <= now && cert.expires_at > now, 'INV-401-CERTIFICATE', 'Certificate expired or revoked', 401);
      const stored = this.store.must(t, 'certificate', cert.certificate_id), record = this.store.must(t, 'capsule', cert.capsule_id);
      requireThat(digest(stored.envelope) === digest(envelope), 'INV-401-CERTIFICATE', 'Certificate does not match issued authority', 401);
      requireThat(!stored.consumed && record.status === 'CERTIFIED', 'INV-409-REPLAY', 'Certificate already consumed or action cancelled', 409);
      requireThat(record.capsule_digest === cert.capsule_digest && this.graph(t, record).digest === cert.evidence_graph_digest && digest(this.policy(t)) === cert.policy_digest, 'INV-409-STATE', 'Action, evidence or policy changed', 409);
      requireThat(this.evaluation(t, record, now).decision === 'ALLOW', 'INV-412-EVIDENCE', 'Execution predicates no longer hold', 412);
      this.assertHealthy(t, record.capsule.actor.subject_id, record.capsule.actor.device_id, now);
      const state = this.target.state(t, record.capsule.action.target_resource);
      requireThat(state.version === record.capsule.current_state.version && state.digest === record.capsule.current_state.digest, 'INV-409-STATE', 'Target state changed', 409);
      if (dryRun || this.policy(t).mode === 'shadow') {
        this.store.audit(t, 'EXECUTION_DRY_RUN', p.subject_id, cert.certificate_id, { no_mutation: true }, now);
        return { dry_run: true, no_mutation: true, certificate_id: cert.certificate_id };
      }
      stored.consumed = true; stored.status = 'EXECUTING'; stored.transaction_id = cert.certificate_id;
      record.status = 'EXECUTING'; this.store.put(t, 'certificate', cert.certificate_id, stored, now); this.store.put(t, 'capsule', cert.capsule_id, record, now);
      this.store.audit(t, 'EXECUTION_RESERVED', p.subject_id, cert.certificate_id, { capsule_digest: cert.capsule_digest }, now);
      return { cert, capsule: record.capsule, now };
    });
    if (reservation.dry_run) return reservation;
    const { cert, capsule, now } = reservation;
    if (fault === 'process-crash') throw new Error('Simulated process death after durable reservation');
    let raw;
    try { raw = this.target.execute(capsule, cert.certificate_id, now, fault); }
    catch (e) {
      if (e instanceof InvariantError && e.code === 'INV-409-STATE') return this.finish(p, cert, null, 'FAILED', 'TARGET_STATE_REJECTED');
      return this.finish(p, cert, null, 'UNCERTAIN', 'TARGET_RESULT_UNCONFIRMED');
    }
    return this.finish(p, cert, raw, 'VERIFIED', 'TARGET_RECONCILED');
  }
  finish(p, cert, raw, status, reason) {
    return this.transaction(p, now => {
      const t = p.tenant_id, r = this.store.must(t, 'capsule', cert.capsule_id), stored = this.store.must(t, 'certificate', cert.certificate_id);
      const responseKeys = ['target_transaction_id', 'capsule_digest', 'authorised_requested_digest', 'observed_state_digest', 'observed_state', 'output', 'status', 'execution_time', 'simulation'];
      let responseShape = raw && typeof raw === 'object' && !Array.isArray(raw) && Object.keys(raw).length === responseKeys.length && responseKeys.every(key => Object.hasOwn(raw, key)) && raw.observed_state && typeof raw.observed_state === 'object' && !Array.isArray(raw.observed_state) && (raw.output === null || Array.isArray(raw.output));
      if (responseShape) {
        try { canonical(raw); } catch (error) { if (error instanceof InvariantError) responseShape = false; else throw error; }
      }
      let expected = null;
      if (responseShape && Number.isSafeInteger(raw.execution_time)) {
        const c = r.capsule;
        expected = { ...c.current_state.material_fields, ...c.requested_state };
        if (c.action.type === 'finance.bank.change') expected = { ...expected, first_payment_done: false, payment_eligible_at: raw.execution_time + 60000 };
        if (c.action.type === 'finance.payment.first') expected = { ...c.current_state.material_fields, first_payment_done: true, payment: c.requested_state, payment_transaction: cert.certificate_id };
        if (c.action.type === 'data.export') expected = c.current_state.material_fields;
      }
      let outputValid = r.capsule.action.type !== 'data.export' && raw?.output === null;
      if (responseShape && Array.isArray(raw.output) && r.capsule.action.type === 'data.export') {
        const requested = r.capsule.requested_state;
        const sourceRows = r.capsule.current_state.material_fields.rows;
        if (Array.isArray(sourceRows)) {
          const exactOutput = sourceRows.filter(row => requested.row_ids.includes(row.id)).map(row => Object.fromEntries(requested.columns.map(column => [column, row[column] ?? null])));
          outputValid = exactOutput.length === requested.row_ids.length && digest(raw.output) === digest(exactOutput);
        }
      }
      const valid = responseShape && expected && outputValid && raw.execution_time >= cert.issued_at && raw.execution_time <= now && raw.execution_time < cert.expires_at && digest(expected) === raw.observed_state_digest && raw.status === 'VERIFIED' && raw.target_transaction_id === cert.certificate_id && raw.capsule_digest === cert.capsule_digest && raw.authorised_requested_digest === digest(r.capsule.requested_state) && raw.observed_state_digest === digest(raw.observed_state) && raw.simulation === true;
      if (status === 'VERIFIED' && !valid) { status = 'UNCERTAIN'; reason = 'TARGET_RESPONSE_INVALID'; }
      if (valid && r.capsule.action.type === 'policy.change') {
        const next = r.capsule.requested_state.policy;
        requireThat(next.version === this.policy(t).version + 1, 'INV-409-STATE', 'Policy activation sequence changed', 409);
        this.store.put(t, 'policy', 'active', next, now);
      }
      const payload = { certificate_id: cert.certificate_id, capsule_digest: cert.capsule_digest, target_transaction_id: cert.certificate_id, observed_state_digest: valid ? raw.observed_state_digest : null, status, reason, execution_time: valid ? raw.execution_time : now, reconciliation_evidence: valid ? digest(raw) : null, simulation: true, output: valid ? raw.output : null };
      const envelope = signed(payload, this.keys(t).audit, 'outcome');
      this.store.put(t, 'outcome', cert.certificate_id, envelope, now); stored.status = status; r.status = status;
      this.store.put(t, 'certificate', cert.certificate_id, stored, now); this.store.put(t, 'capsule', cert.capsule_id, r, now);
      this.store.audit(t, 'EXECUTION_OUTCOME', p.subject_id, cert.certificate_id, { status, reason, outcome_digest: digest(envelope) }, now);
      return envelope;
    });
  }
  reconcile(p, id) {
    this.authorize(p, ['operator', 'security', 'policy_admin']); const t = p.tenant_id, stored = this.store.must(t, 'certificate', id);
    const current = this.store.get(t, 'outcome', id);
    if (current && ['VERIFIED', 'FAILED'].includes(current.payload.status)) return current;
    requireThat(stored.consumed, 'INV-409-STATE', 'Execution has not started', 409);
    const cert = stored.envelope.payload, raw = this.target.outcome(t, id);
    return this.finish(p, cert, raw, raw ? 'VERIFIED' : 'UNCERTAIN', raw ? 'RECONCILED_FROM_TARGET_JOURNAL' : 'NO_TARGET_CONFIRMATION_DO_NOT_RETRY');
  }
  cancel(p, id) {
    this.authorize(p, ['operator', 'security', 'policy_admin']);
    return this.transaction(p, now => {
      const r = this.store.must(p.tenant_id, 'capsule', id); requireThat(!['EXECUTING', 'VERIFIED', 'UNCERTAIN', 'FAILED'].includes(r.status), 'INV-409-STATE', 'Dispatched action cannot be cancelled; reconcile first', 409);
      r.status = 'CANCELLED'; this.store.put(p.tenant_id, 'capsule', id, r, now);
      this.store.audit(p.tenant_id, 'ACTION_CANCELLED', p.subject_id, id, { certificate_id: r.certificate_id }, now); return { status: r.status };
    });
  }
  revoke(p, input) {
    this.authorize(p, ['security']); fields(input, ['kind', 'id', 'reason']); text(input.reason, 'revocation reason'); identifier(input.id);
    requireThat(['certificate', 'evidence', 'issuer', 'key', 'subject', 'device', 'capability'].includes(input.kind), 'INV-400-SCHEMA', 'Unsupported revocation type');
    return this.transaction(p, now => {
      const payload = { ...clone(input), tenant_id: p.tenant_id, revoked_at: now, actor: p.subject_id, propagation: 'local-synchronous', remote_propagation: 'NOT_IMPLEMENTED' };
      this.store.put(p.tenant_id, 'revocation', `${input.kind}:${input.id}`, payload, now);
      this.store.audit(p.tenant_id, 'AUTHORITY_REVOKED', p.subject_id, `${input.kind}:${input.id}`, { reason_digest: digest(input.reason) }, now);
      return signed(payload, this.keys(p.tenant_id).audit, 'revocation');
    });
  }
  simulate(p, candidate) {
    this.authorize(p, ['policy_admin', 'security']); validatePolicy(candidate); requireThat(candidate.tenant_id === p.tenant_id, 'INV-403-SCOPE', 'Policy scope mismatch', 403);
    return this.transaction(p, now => {
      const active = this.policy(p.tenant_id), records = this.store.list(p.tenant_id, 'capsule', 500);
      const results = records.map(r => ({ capsule_id: r.capsule.capsule_id, observed_status: r.status, projected: this.evaluation(p.tenant_id, { ...r, capsule: { ...r.capsule, policy_version: candidate.version } }, now, candidate).decision }));
      const result = { simulation_id: randomUUID(), candidate_digest: digest(candidate), baseline_digest: digest(active), activation: false, approvals_invalidated_by_policy_change: true, time_basis: now, diff: policyDiff(active, candidate), results, counts: Object.fromEntries(['ALLOW', 'SHIELD', 'ESCROW', 'DEFER', 'DENY'].map(d => [d, results.filter(r => r.projected === d).length])), truncated: records.length === 500 };
      this.store.insert(p.tenant_id, 'simulation', result.simulation_id, result, now); this.store.audit(p.tenant_id, 'POLICY_SIMULATED', p.subject_id, result.simulation_id, { candidate_digest: digest(candidate), result_digest: digest(result) }, now); return result;
    });
  }
  coverage(p) { this.authorize(p, ['operator', 'approver', 'custodian', 'security', 'auditor', 'policy_admin']); return coverageManifest(p.tenant_id, this.store.list(p.tenant_id, 'coverage'), this.clock(), this.keys(p.tenant_id).audit); }
  declareCoverage(p, input) {
    this.authorize(p, ['security']); return this.transaction(p, now => {
      const path = declarePath(input, now); this.store.put(p.tenant_id, 'coverage', path.path_id, path, now);
      this.store.audit(p.tenant_id, 'COVERAGE_DECLARED', p.subject_id, path.path_id, { digest: digest(path), status: path.status }, now); return path;
    });
  }
  exportAudit(p, purpose) {
    this.authorize(p, ['auditor', 'security']); text(purpose, 'audit export purpose', 256);
    return this.transaction(p, now => { this.store.audit(p.tenant_id, 'AUDIT_ACCESSED', p.subject_id, 'tenant-log', { purpose_digest: digest(purpose) }, now); return this.store.auditExport(p.tenant_id); });
  }
  retention(p, input) {
    this.authorize(p, ['security']); fields(input, ['evidence_id', 'legal_hold']); identifier(input.evidence_id); requireThat(typeof input.legal_hold === 'boolean', 'INV-400-SCHEMA', 'Legal hold must be boolean');
    return this.transaction(p, now => { const e = this.store.must(p.tenant_id, 'evidence', input.evidence_id); e.legal_hold = input.legal_hold; this.store.put(p.tenant_id, 'evidence', input.evidence_id, e, now); this.store.audit(p.tenant_id, 'RETENTION_HOLD_CHANGED', p.subject_id, input.evidence_id, { legal_hold: input.legal_hold }, now); return { evidence_id: input.evidence_id, legal_hold: input.legal_hold }; });
  }
  retentionSweep(p) {
    this.authorize(p, ['security']); return this.transaction(p, now => {
      const items = this.store.list(p.tenant_id, 'evidence', 10000), records = this.store.list(p.tenant_id, 'capsule', 10000); let deleted = 0, held = 0;
      // Conservative batch boundary: do not erase if a reference could be outside this scan.
      if (records.length === 10000) return { deleted: 0, held: items.length, reason: 'Reference scan limit reached; no deletion performed', complete_payload_erasure: false };
      for (const e of items) {
        if (e.payload.retention_until > now) continue;
        const activeReference = records.some(r => r.evidence.includes(e.payload.evidence_id) && !['VERIFIED', 'FAILED', 'DENY', 'CANCELLED'].includes(r.status));
        if (e.legal_hold || activeReference) { held++; continue; }
        const original_digest = digest(e.envelope);
        this.store.insert(p.tenant_id, 'evidence-tombstone', e.payload.evidence_id, { evidence_id: e.payload.evidence_id, original_digest, deleted_at: now }, now);
        this.store.remove(p.tenant_id, 'evidence', e.payload.evidence_id); deleted++;
        this.store.audit(p.tenant_id, 'RETENTION_DELETED', p.subject_id, e.payload.evidence_id, { original_digest, logical_deletion_only: true }, now);
      }
      return { deleted, held, complete_payload_erasure: false, limitation: 'Logical deletion does not remove old ciphertext from backups or SQLite free pages; per-record key destruction is not implemented.' };
    });
  }
}

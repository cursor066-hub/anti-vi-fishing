import { randomUUID, randomBytes } from 'node:crypto';
import { Store } from './store.mjs';
import { SimulatedTarget } from './target.mjs';
import { RuntimeGate } from './runtime.mjs';
import { digest, clone, canonical } from './canonical.mjs';
import { verifySigned } from './crypto.mjs';
import { KeyVault } from './keystore.mjs';
import { merkleRoot, inclusionProof, consistencyProof, verifyInclusion } from './merkle.mjs';
import { httpJson, driftCheck } from './connectors.mjs';
import { createCeremony, acknowledge, commitShares, splitSecret, reconstructSecret, ceremonyReport } from './ceremony.mjs';
import { decodeShare, encodeShare } from './shamir.mjs';
import { openSession, releaseFields, workspaceFallback } from './secureview.mjs';
import { extract, explain, classifyIntent } from './advisory.mjs';
import { fields, text, identifier, integer, uniqueStrings, validateProposal } from './schema.mjs';
import { evaluatePolicy, validatePolicy, policyDiff } from './policy.mjs';
import { declarePath, coverageManifest } from './coverage.mjs';
import { requireThat, InvariantError } from './errors.mjs';
import { join } from 'node:path';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';

export class Fabric {
  constructor(config, directory, clock = Date.now, { vault = null } = {}) {
    requireThat(config.profile === 'engineering', 'INV-503-RELEASE', 'Production mode is blocked: external acceptance evidence is missing', 503);
    this.config = config; this.directory = directory; this.clock = clock;
    const encryption = {}, auditSigners = {};
    this.vault = vault ?? this._openVault();
    for (const [tenant, t] of Object.entries(config.tenants)) {
      encryption[tenant] = t.encryption_key;
      for (const klass of ['execution', 'audit']) {
        const key = t.keys[klass];
        if (key.private_key && !this.vault.has(key.key_id)) this.vault.importKey({ key_id: key.key_id, public_key: key.public_key, private_key: key.private_key }, 'any', { exportable: true });
        requireThat(this.vault.has(key.key_id), 'INV-503-CONFIG', `Tenant ${klass} key is not in the keystore`, 503);
      }
      auditSigners[tenant] = { key_id: t.keys.audit.key_id, public_key: t.keys.audit.public_key, keys: () => this.auditPublicKeys(tenant), sign: (payload, purpose = 'audit') => this.vault.envelope(this.keys(tenant).audit.key_id, purpose, payload) };
    }
    this.store = new Store(join(directory, 'fabric.db'), encryption, auditSigners);
    this.target = new SimulatedTarget(join(directory, 'target.db'), encryption); this.runtime = new RuntimeGate(this);
    this.perceptionComponents = {};
    for (const [tenant, t] of Object.entries(config.tenants)) this.perceptionComponents[tenant] = t.components ?? {};
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
      // Signed configuration snapshot (NFR-OPS integrity): drift vs the
      // genesis-signed digest is surfaced, never silently accepted.
      const configDigest = digest({ tenant, identities: t.identities, issuers: t.issuers, genesis_policy: t.genesis_policy, gate_id: config.gate_id });
      const existing = this.store.get(tenant, 'config-snapshot', 'current');
      if (!existing) this.store.tx(() => { this.store.put(tenant, 'config-snapshot', 'current', { digest: configDigest, taken_at: this.clock() }, this.clock()); this.store.audit(tenant, 'CONFIG_SNAPSHOT', 'system', 'config', { config_digest: configDigest }, this.clock()); });
      else if (existing.digest !== configDigest) this.store.tx(() => this.store.audit(tenant, 'CONFIG_DRIFT', 'system', 'config', { expected: existing.digest, observed: configDigest }, this.clock()));
    } } catch (error) { this.close(); throw error; }
  }
  _openVault() {
    const storePath = join(this.directory, 'keystore.json'), masterPath = join(this.directory, 'master.key');
    if (existsSync(storePath)) return KeyVault.load(storePath, JSON.parse(readFileSync(masterPath, 'utf8')).master_key);
    return new KeyVault(randomBytes(32).toString('base64url'));
  }
  persistVault() {
    mkdirSync(this.directory, { recursive: true, mode: 0o700 });
    if (!existsSync(join(this.directory, 'master.key'))) {
      writeFileSync(join(this.directory, 'master.key'), canonical({ format: 'IF-MASTERKEY-1', warning: 'software vault master key; custody is the operator\'s responsibility', master_key: this.vault.masterKey.toString('base64url') }) + '\n', { mode: 0o600 });
    }
    this.vault.save(join(this.directory, 'keystore.json'));
  }
  close() { this.target.close(); this.store.close(); }
  tenant(t) { const row = this.config.tenants[t]; requireThat(row, 'INV-404-NOT-FOUND', 'Resource not found', 404); return row; }
  keys(t) { return this.tenant(t).keys; }
  // Verification keys for execution signatures: current plus retired keys so
  // certificates issued before rotation still verify within their TTL.
  executionPublic(t) {
    const out = { [this.keys(t).execution.key_id]: { public_key: this.keys(t).execution.public_key } };
    for (const e of this.keys(t).retired ?? []) out[e.key_id] = { public_key: e.public_key };
    return out;
  }
  auditPublicKeys(t) {
    const out = { [this.keys(t).audit.key_id]: { public_key: this.keys(t).audit.public_key } };
    for (const e of this.keys(t).retired ?? []) out[e.key_id] = { public_key: e.public_key };
    return out;
  }
  signExecution(t, payload, purpose) { return this.vault.envelope(this.keys(t).execution.key_id, purpose, payload); }
  signAudit(t, payload, purpose = 'audit') { return this.vault.envelope(this.keys(t).audit.key_id, purpose, payload); }
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
  // IDN: JIT grants merge with static identity grants. A grant only ever adds
  // scope already permitted by the runtime policy; it cannot exceed it.
  grantsFor(tenant, subject_id, now) {
    const identity = Object.values(this.tenant(tenant).identities).find(x => x.subject_id === subject_id);
    const base = identity?.grants ?? { resources: [], actions: [], destinations: [], columns: [], row_ids: [] };
    const merged = { resources: [...base.resources], actions: [...base.actions], destinations: [...base.destinations], columns: [...base.columns], row_ids: [...base.row_ids] };
    for (const g of this.target.grants(tenant, subject_id, now)) {
      for (const k of Object.keys(merged)) for (const v of g[k] ?? []) if (!merged[k].includes(v)) merged[k].push(v);
    }
    return merged;
  }
  activateDuePolicies(t, now) {
    // Staged deployment (POL-008/013): a verified policy.change with a staged
    // clause stores the next constitution as 'staged'; it promotes exactly one
    // version at activate_at. Versions can never regress.
    const staged = this.store.get(t, 'policy', 'staged');
    if (!staged) return null;
    const active = this.store.must(t, 'policy', 'active');
    if (staged.activate_at <= now) {
      requireThat(staged.policy.version === active.version + 1 && staged.policy.version > active.version, 'INV-409-STATE', 'Staged policy sequence violated', 409);
      this.store.put(t, 'policy', 'active', staged.policy, now);
      this.store.remove(t, 'policy', 'staged');
      this.store.put(t, 'policy-history', `v${staged.policy.version}`, { activated_at: now, digest: digest(staged.policy), staged: true, emergency: staged.policy.emergency_of !== undefined }, now);
      this.store.audit(t, staged.policy.emergency_of !== undefined ? 'EMERGENCY_POLICY_ACTIVATED' : 'POLICY_ACTIVATED', 'system', staged.policy.policy_id, { version: staged.policy.version, staged_from: staged.staged_at }, now);
      return staged.policy;
    }
    return null;
  }
  transaction(principal, fn) {
    this.authorize(principal, ['operator', 'approver', 'custodian', 'security', 'auditor', 'policy_admin', 'workload']);
    try { return this.store.tx(() => { const now = this.clock(); this.store.clock(now); this.activateDuePolicies(principal.tenant_id, now); return fn(now); }); }
    catch (error) {
      if (error instanceof InvariantError && error.code !== 'INV-503-TIME') {
        this.store.tx(() => { const now = this.clock(); this.store.clock(now); this.store.audit(principal.tenant_id, 'SECURITY_OPERATION_REJECTED', principal.subject_id, 'local-gate', { code: error.code }, now); });
      }
      throw error;
    }
  }
  revoked(tenant, kind, id) { return Boolean(this.store.get(tenant, 'revocation', `${kind}:${id}`)); }
  policy(t) {
    const staged = this.store.get(t, 'policy', 'staged'), active = this.store.must(t, 'policy', 'active');
    if (staged && staged.activate_at <= this.clock() && staged.policy.version === active.version + 1) return staged.policy;
    return active;
  }
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
  ensureMutable(record) { requireThat(!['DENY', 'CANCELLED', 'CERTIFIED', 'EXECUTING', 'VERIFIED', 'UNCERTAIN', 'FAILED', 'COMPENSATED'].includes(record.status), 'INV-409-STATE', 'Action is immutable in its current state', 409); }
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
      const payload = this.verifyEvidenceEnvelope(t, envelope);
      requireThat(!this.revoked(t, 'issuer', envelope.protected.key_id) && !this.revoked(t, 'key', envelope.protected.key_id) && !this.revoked(t, 'evidence', payload.evidence_id), 'INV-401-EVIDENCE', 'Evidence source revoked', 401);
      requireThat(payload.tenant_id === t && payload.capsule_digest === record.capsule_digest, 'INV-403-SCOPE', 'Evidence scope mismatch', 403);
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
  verifyEvidenceEnvelope(t, envelope) {
    const payload = verifySigned(envelope, this.tenant(t).issuers, 'evidence');
    fields(payload, ['evidence_id', 'tenant_id', 'capsule_digest', 'kind', 'content_digest', 'acquired_at', 'expires_at', 'confidence', 'advisory', 'claim', 'dependencies', 'provenance', 'retention_until'], ['claims', 'issuer_version']);
    identifier(payload.evidence_id); text(payload.kind, 'evidence kind'); text(payload.provenance, 'provenance', 2048); uniqueStrings(payload.dependencies, 'dependencies', 32);
    const now = this.clock();
    integer(payload.confidence, 'confidence', 0, 100); integer(payload.acquired_at, 'acquisition time', 1, now + 5000); integer(payload.expires_at, 'evidence expiry', now + 1); integer(payload.retention_until, 'retention', payload.expires_at);
    requireThat(typeof payload.advisory === 'boolean' && ['supports', 'conflict'].includes(payload.claim) && /^[a-f0-9]{64}$/.test(payload.content_digest), 'INV-400-SCHEMA', 'Invalid evidence claim');
    return payload;
  }
  // Real evidence acquisition: the issuer is a separate service holding the
  // authoritative record store; the fabric pulls a signed envelope over HTTP
  // and binds it to the capsule (EVD-001..010).
  async acquireEvidence(p, capsule_id, input) {
    this.authorize(p, ['operator', 'security', 'policy_admin']);
    fields(input, ['issuer', 'kind', 'claims'], ['subject_id', 'dependencies']);
    identifier(input.issuer, 'issuer'); text(input.kind, 'evidence kind');
    const t = p.tenant_id, record = this.store.must(t, 'capsule', capsule_id);
    const entry = Object.entries(this.tenant(t).issuers).find(([, v]) => v.name === input.issuer || v.endpoint?.includes(`/${input.issuer}`) || input.issuer === v.issuer_id);
    requireThat(entry, 'INV-404-NOT-FOUND', 'Issuer not found', 404);
    const [key_id, issuer] = entry;
    requireThat(issuer.endpoint, 'INV-412-EVIDENCE', 'Issuer has no live endpoint; attach a pre-signed envelope instead', 412);
    requireThat(!this.revoked(t, 'issuer', key_id) && !this.revoked(t, 'key', key_id), 'INV-401-EVIDENCE', 'Evidence source revoked', 401);
    let envelope;
    try {
      const res = await httpJson(`${issuer.endpoint}/v1/issuers/${issuer.name ?? input.issuer}/issue`, { method: 'POST', body: { tenant_id: t, capsule_digest: record.capsule_digest, kind: input.kind, subject_id: input.subject_id ?? p.subject_id, claims: input.claims, dependencies: input.dependencies ?? [] }, timeout_ms: 10000 });
      requireThat(res.status === 201, 'INV-503-EVIDENCE-SOURCE', `Issuer refused (${res.status})`, 503);
      envelope = res.data;
    } catch (e) {
      const err = new InvariantError('INV-503-EVIDENCE-SOURCE', `Evidence source unavailable or refused: ${e.code ?? 'transport'}`, 503);
      this.store.tx(() => this.store.audit(t, 'EVIDENCE_ACQUISITION_FAILED', p.subject_id, capsule_id, { issuer: input.issuer, kind: input.kind, code: e.code ?? 'transport' }, this.clock()));
      throw err;
    }
    return this.attachEvidence(p, capsule_id, envelope);
  }
  connectorStatus(p) {
    this.authorize(p, ['operator', 'security', 'policy_admin', 'auditor']);
    const issuers = Object.entries(this.tenant(p.tenant_id).issuers).map(([key_id, v]) => ({ key_id, name: v.name ?? null, channel: v.channel, failure_domain: v.failure_domain, endpoint: v.endpoint ?? null, revoked: this.revoked(p.tenant_id, 'issuer', key_id) || this.revoked(p.tenant_id, 'key', key_id) }));
    return { gate: this.config.gate_id, target: this.target.manifest(), issuers, profile: 'engineering' };
  }
  async checkIssuerDrift(p, key_id) {
    this.authorize(p, ['security', 'policy_admin']);
    const issuer = this.tenant(p.tenant_id).issuers[key_id];
    requireThat(issuer?.endpoint, 'INV-404-NOT-FOUND', 'Issuer endpoint not found', 404);
    let observed;
    try { const res = await httpJson(`${issuer.endpoint}/v1/issuers/${issuer.name}/manifest?tenant=${p.tenant_id}`, { method: 'GET', timeout_ms: 10000 }); requireThat(res.status === 200, 'INV-503-CONNECTOR', `Manifest fetch refused (${res.status})`, 503); observed = res.data; } catch (e) {
      return this.transaction(p, now => { this.store.audit(p.tenant_id, 'CONNECTOR_DRIFT', p.subject_id, key_id, { drifted: 'unreachable', code: e.code ?? 'transport' }, now); return { drifted: true, changes: [{ field: 'endpoint', detail: 'unreachable' }], checked_at: now }; });
    }
    const observedPayload = verifySigned(observed, { [key_id]: issuer }, 'connector-manifest');
    const registered = { connector_id: `issuer:${issuer.name}`, version: issuer.version ?? '1.0.0', actions: issuer.kinds, channel: issuer.channel, key_id };
    const result = driftCheck(registered, { connector_id: observedPayload.connector_id, version: observedPayload.version, actions: observedPayload.actions, channel: observedPayload.domain, key_id: observed.protected.key_id }, this.clock());
    return this.transaction(p, now => { if (result.drifted) this.store.audit(p.tenant_id, 'CONNECTOR_DRIFT', p.subject_id, key_id, { changes: result.changes, configuration_digest: result.configuration_digest }, now); return result; });
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
    if (record.capsule.action.type === 'action.composite') {
      // ACT-012: a composite may only wrap children that themselves reached
      // CERTIFIED with ALLOW under the current policy — composition cannot
      // acquire authority a child did not independently hold.
      const children = record.capsule.requested_state.children;
      const problems = [];
      const certs = [];
      for (const childId of children) {
        const child = this.store.get(t, 'capsule', childId);
        if (!child) { problems.push({ code: 'CHILD_MISSING', child: childId }); continue; }
        if (child.capsule.actor.subject_id !== record.capsule.actor.subject_id) problems.push({ code: 'CHILD_ACTOR', child: childId });
        if (child.status !== 'CERTIFIED') problems.push({ code: 'CHILD_STATE', child: childId, status: child.status });
        const cert = child.certificate_id ? this.store.get(t, 'certificate', child.certificate_id) : null;
        if (!cert || cert.consumed) problems.push({ code: 'CHILD_CERT', child: childId });
        else certs.push(cert);
      }
      if (problems.length) return { decision: 'ESCROW', reasons: problems.map(x => ({ code: x.code, message: `Composite child ${x.child}: ${x.code.toLowerCase().replace(/_/g, ' ')}${x.status ? ` (${x.status})` : ''}` })), explanation: 'Every child of a composite must be independently certified.', owner: record.capsule.actor.subject_id, expires_at: record.capsule.expires_at, evaluated_at: now, policy_version: policy.version, policy_digest: digest(policy), eligible_signers: [] };
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
      const suite = this.vault.entry(this.keys(t).execution.key_id).suite ?? 'Ed25519';
      requireThat(policy.algorithms.allowed_suites.includes(suite), 'INV-451-POLICY', 'Certificate suite is no longer approved by policy', 451);
      const graph = this.graph(t, r), expiry = Math.min(now + policy.certificate_ttl_ms, r.capsule.expires_at, policy.expires_at, ...graph.items.map(e => e.payload.expires_at), ...r.approvals.map(a => a.payload.expires_at));
      const payload = { certificate_id: randomUUID(), tenant_id: t, capsule_id: id, capsule_digest: r.capsule_digest, evidence_graph_digest: graph.digest, policy_id: policy.policy_id, policy_version: policy.version, policy_digest: digest(policy), decision: 'ALLOW', constraints: { destination: r.capsule.destination, quantity: r.capsule.quantity, requested_digest: digest(r.capsule.requested_state), current_state: r.capsule.current_state, exclusions: r.capsule.exclusions }, target_gate_id: this.config.gate_id, signer_set: decision.eligible_signers, nonce: r.capsule.nonce, issued_at: now, expires_at: expiry, single_use: true, suite, revocation_ref: `certificate:${id}` };
      requireThat(!this.revoked(t, 'key', this.keys(t).execution.key_id) && this.vault.has(this.keys(t).execution.key_id), 'INV-401-SIGNATURE', 'Execution key revoked', 401);
      const envelope = this.signExecution(t, payload, 'action-certificate');
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
    if (capsule.action.type === 'action.composite') return this.executeComposite(p, cert, capsule, now, fault);
    let raw;
    try { raw = this.target.execute(capsule, cert.certificate_id, now, fault); }
    catch (e) {
      if (e instanceof InvariantError && e.code === 'INV-409-STATE') return this.finish(p, cert, null, 'FAILED', 'TARGET_STATE_REJECTED');
      return this.finish(p, cert, null, 'UNCERTAIN', 'TARGET_RESULT_UNCONFIRMED');
    }
    return this.finish(p, cert, raw, 'VERIFIED', 'TARGET_RECONCILED');
  }
  executeComposite(p, cert, capsule, now, fault) {
    // Children execute in order. On failure the already-executed children are
    // compensated via their recorded prior state — documented compensation,
    // never a pretend rollback of irreversible effects.
    const children = capsule.requested_state.children;
    const executed = [];
    for (const childId of children) {
      const child = this.store.must(p.tenant_id, 'capsule', childId);
      const childCert = this.store.must(p.tenant_id, 'certificate', child.certificate_id);
      try {
        const raw = this.target.execute(child.capsule, childCert.envelope.payload.certificate_id, now, fault);
        executed.push({ child, raw, prior: child.capsule.current_state.material_fields });
      } catch (e) {
        const compensations = [];
        for (const done of executed.reverse()) compensations.push({ capsule_id: done.child.capsule.capsule_id, ...this.target.compensate(done.child.capsule, done.prior, now) });
        return this.finishComposite(p, cert, capsule, executed, 'COMPENSATED', 'CHILD_EXECUTION_FAILED', compensations, now);
      }
    }
    return this.finishComposite(p, cert, capsule, executed, 'VERIFIED', 'CHILDREN_VERIFIED', [], now);
  }
  finishComposite(p, cert, capsule, executed, status, reason, compensations, execNow) {
    return this.transaction(p, now => {
      const t = p.tenant_id, r = this.store.must(t, 'capsule', cert.capsule_id), stored = this.store.must(t, 'certificate', cert.certificate_id);
      for (const done of executed) {
        const childRecord = this.store.must(t, 'capsule', done.child.capsule.capsule_id), childStored = this.store.must(t, 'certificate', done.child.certificate_id);
        const childValid = status === 'VERIFIED' || status === 'COMPENSATED';
        childRecord.status = status === 'VERIFIED' ? 'VERIFIED' : 'COMPENSATED';
        childStored.consumed = true; childStored.status = childRecord.status;
        this.store.put(t, 'capsule', childRecord.capsule.capsule_id, childRecord, now);
        this.store.put(t, 'certificate', childStored.envelope.payload.certificate_id, childStored, now);
      }
      const payload = { certificate_id: cert.certificate_id, capsule_digest: cert.capsule_digest, target_transaction_id: cert.certificate_id, observed_state_digest: digest({ children: executed.map(e => e.child.capsule.capsule_id), compensations }), status, reason, execution_time: execNow, reconciliation_evidence: digest(executed.map(e => e.raw)), simulation: true, output: null, composite: true, children: executed.map(e => e.child.capsule.capsule_id), compensations };
      const envelope = this.signAudit(t, payload, 'outcome');
      this.store.put(t, 'outcome', cert.certificate_id, envelope, now); stored.status = status; r.status = status;
      this.store.put(t, 'certificate', cert.certificate_id, stored, now); this.store.put(t, 'capsule', cert.capsule_id, r, now);
      this.store.audit(t, 'EXECUTION_OUTCOME', p.subject_id, cert.certificate_id, { status, reason, outcome_digest: digest(envelope), composite: true }, now);
      return envelope;
    });
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
        if (['identity.mfa.reset', 'identity.authenticator.enroll', 'identity.account.recover'].includes(c.action.type)) expected = { ...expected, last_identity_operation: { type: c.action.type, at: raw.execution_time, transaction: cert.certificate_id } };
        if (c.action.type === 'key.rotate') expected = { ...expected, rotated_at: raw.execution_time, rotation_transaction: cert.certificate_id };
        if (c.action.type === 'secret.use') expected = { ...c.current_state.material_fields, last_use: { secret_id: c.requested_state.secret_id, operation: c.requested_state.operation, workload_id: c.requested_state.workload_id, at: raw.execution_time, transaction: cert.certificate_id } };
        if (c.action.type === 'backup.delete') expected = { ...c.current_state.material_fields, deleted_backups: [...(c.current_state.material_fields.deleted_backups ?? []), { backup_id: c.requested_state.backup_id, at: raw.execution_time, transaction: cert.certificate_id }] };
        if (c.action.type === 'identity.jit.grant') expected = { ...expected };
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
        const next = r.capsule.requested_state.policy, active = this.policy(t);
        requireThat(next.version === active.version + 1, 'INV-409-STATE', 'Policy activation sequence changed', 409);
        // POL-013: a successor policy whose not_before lies in the future is
        // stored as 'staged' and promoted by activateDuePolicies() when the
        // trusted clock reaches it — never by a write to 'active'.
        if (next.not_before > now) {
          requireThat(next.not_before >= now + (active.staged_policy?.min_delay_ms ?? 0), 'INV-400-SCHEMA', 'Staged activation violates min delay');
          this.store.put(t, 'policy', 'staged', { policy: next, activate_at: next.not_before, staged_at: now, capsule_id: r.capsule.capsule_id }, now);
          this.store.audit(t, 'POLICY_STAGED', p.subject_id, next.policy_id, { activate_at: next.not_before, version: next.version }, now);
        } else {
          this.store.put(t, 'policy', 'active', next, now);
          this.store.put(t, 'policy-history', `v${next.version}`, { activated_at: now, digest: digest(next), staged: false, emergency: next.emergency_of !== undefined }, now);
          if (next.emergency_of !== undefined) this.store.audit(t, 'EMERGENCY_POLICY_ACTIVATED', p.subject_id, next.policy_id, { version: next.version, base: next.emergency_of }, now);
        }
      }
      if (valid && r.capsule.action.type === 'key.rotate') {
        // The pending vault key is activated only after the rotation capsule is
        // VERIFIED; the retiring key stays verifiable but can no longer sign.
        const req = r.capsule.requested_state;
        this.vault.activate(req.new_key_id);
        const klass = req.key_class, previous = this.keys(t)[klass];
        this.tenant(t).keys[klass] = { key_id: req.new_key_id, public_key: req.new_public_key };
        this.tenant(t).keys.retired = [...(this.tenant(t).keys.retired ?? []), { key_class: klass, key_id: previous.key_id, public_key: previous.public_key, retired_at: now }];
        if (req.revoke_old) this.vault.revoke(previous.key_id);
        this.persistVault();
        this.store.audit(t, 'KEY_ROTATED', p.subject_id, req.new_key_id, { key_class: klass, previous_key_id: previous.key_id, ceremony_id: req.ceremony_id }, now);
      }
      if (valid && r.capsule.action.type === 'identity.jit.grant') {
        const req = r.capsule.requested_state;
        this.target.grant(t, `jit-${cert.certificate_id}`, { grant_id: `jit-${cert.certificate_id}`, subject_id: req.subject_id, resources: req.resources, actions: req.actions, destinations: req.destinations, columns: req.columns, row_ids: req.row_ids, expires_at: now + req.ttl_ms, issued_at: now, issued_by: `action:${r.capsule.capsule_id}`, reason: req.reason, revoked: false });
        this.store.audit(t, 'JIT_GRANT_ISSUED', p.subject_id, req.subject_id, { grant_digest: digest(req), expires_at: now + req.ttl_ms }, now);
      }
      const payload = { certificate_id: cert.certificate_id, capsule_digest: cert.capsule_digest, target_transaction_id: cert.certificate_id, observed_state_digest: valid ? raw.observed_state_digest : null, status, reason, execution_time: valid ? raw.execution_time : now, reconciliation_evidence: valid ? digest(raw) : null, simulation: true, output: valid ? raw.output : null };
      const envelope = this.signAudit(t, payload, 'outcome');
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
      const r = this.store.must(p.tenant_id, 'capsule', id); requireThat(!['EXECUTING', 'VERIFIED', 'UNCERTAIN', 'FAILED', 'COMPENSATED'].includes(r.status), 'INV-409-STATE', 'Dispatched action cannot be cancelled; reconcile first', 409);
      r.status = 'CANCELLED'; this.store.put(p.tenant_id, 'capsule', id, r, now);
      this.store.audit(p.tenant_id, 'ACTION_CANCELLED', p.subject_id, id, { certificate_id: r.certificate_id }, now); return { status: r.status };
    });
  }
  revoke(p, input) {
    this.authorize(p, ['security']); fields(input, ['kind', 'id', 'reason']); text(input.reason, 'revocation reason'); identifier(input.id);
    requireThat(['certificate', 'evidence', 'issuer', 'key', 'subject', 'device', 'capability', 'grant'].includes(input.kind), 'INV-400-SCHEMA', 'Unsupported revocation type');
    return this.transaction(p, now => {
      if (input.kind === 'grant') this.target.revokeGrant(p.tenant_id, input.id);
      const payload = { ...clone(input), tenant_id: p.tenant_id, revoked_at: now, actor: p.subject_id, propagation: 'local-synchronous', remote_propagation: 'NOT_IMPLEMENTED' };
      this.store.put(p.tenant_id, 'revocation', `${input.kind}:${input.id}`, payload, now);
      this.store.audit(p.tenant_id, 'AUTHORITY_REVOKED', p.subject_id, `${input.kind}:${input.id}`, { reason_digest: digest(input.reason) }, now);
      return this.signAudit(p.tenant_id, payload, 'revocation');
    });
  }
  revocations(p, kind = null) {
    this.authorize(p, ['operator', 'security', 'auditor', 'policy_admin']);
    const items = this.store.list(p.tenant_id, 'revocation', 10000);
    return { quarantine: items.filter(i => ['subject', 'device'].includes(i.kind)).filter(i => !kind || i.kind === kind), items: kind ? items.filter(i => i.kind === kind) : items };
  }
  listGrants(p, subject = null) {
    this.authorize(p, ['operator', 'security', 'auditor']);
    const now = this.clock();
    const items = this.target.allGrants(p.tenant_id).filter(g => !subject || g.subject_id === subject);
    return { now, items };
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
  coverage(p) { this.authorize(p, ['operator', 'approver', 'custodian', 'security', 'auditor', 'policy_admin']); return coverageManifest(p.tenant_id, this.store.list(p.tenant_id, 'coverage'), this.clock(), payload => this.signAudit(p.tenant_id, payload, 'coverage')); }
  declareCoverage(p, input) {
    this.authorize(p, ['security']); return this.transaction(p, now => {
      const path = declarePath(input, now); this.store.put(p.tenant_id, 'coverage', path.path_id, path, now);
      this.store.audit(p.tenant_id, 'COVERAGE_DECLARED', p.subject_id, path.path_id, { digest: digest(path), status: path.status }, now); return path;
    });
  }
  // AUD-003/005/010 + transparency: the audit log is a hash-chained signed log
  // whose heads also commit to a Merkle tree, so inclusion and consistency
  // proofs can be checked offline by anyone holding the export.
  auditProof(p, sequence) {
    this.authorize(p, ['auditor', 'security', 'operator']);
    integer(sequence, 'sequence', 1);
    const hashes = this.store.auditHashes(p.tenant_id);
    requireThat(sequence <= hashes.length, 'INV-404-NOT-FOUND', 'Sequence beyond log head', 404);
    return { format: 'IF-MERKLE-1', tenant_id: p.tenant_id, sequence, size: hashes.length, leaf_hash: hashes[sequence - 1], path: inclusionProof(hashes, sequence - 1), root: merkleRoot(hashes), verify: 'leaf = sha256(0x00||entry_hash); node = sha256(0x01||left||right); subtree partition = maximal aligned power-of-two split' };
  }
  auditConsistency(p, first) {
    this.authorize(p, ['auditor', 'security', 'operator']);
    integer(first, 'first size', 1);
    const hashes = this.store.auditHashes(p.tenant_id);
    requireThat(first <= hashes.length, 'INV-404-NOT-FOUND', 'First size beyond log head', 404);
    const proof = consistencyProof(hashes, first);
    return { format: 'IF-MERKLE-1', tenant_id: p.tenant_id, first, second: hashes.length, first_root: merkleRoot(hashes.slice(0, first)), second_root: merkleRoot(hashes), proof };
  }
  verifyAuditProof(tenant, proof) {
    // Stateless helper for the offline verifier and tests.
    return verifyInclusion(proof.leaf_hash, proof.sequence - 1, proof.size, proof.path, proof.root);
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
    this.authorize(p, ['security']);
    const result = this.transaction(p, now => {
      const items = this.store.list(p.tenant_id, 'evidence', 10000), records = this.store.list(p.tenant_id, 'capsule', 10000); let deleted = 0, held = 0;
      // Conservative batch boundary: do not erase if a reference could be outside this scan.
      if (records.length === 10000) return { deleted: 0, held: items.length, reason: 'Reference scan limit reached; no deletion performed', complete_payload_erasure: false };
      for (const e of items) {
        if (e.payload.retention_until > now) continue;
        const activeReference = records.some(r => r.evidence.includes(e.payload.evidence_id) && !['VERIFIED', 'FAILED', 'DENY', 'CANCELLED', 'COMPENSATED'].includes(r.status));
        if (e.legal_hold || activeReference) { held++; continue; }
        const original_digest = digest(e.envelope);
        this.store.insert(p.tenant_id, 'evidence-tombstone', e.payload.evidence_id, { evidence_id: e.payload.evidence_id, original_digest, deleted_at: now }, now);
        this.store.shred(p.tenant_id, 'evidence', e.payload.evidence_id); deleted++;
        this.store.audit(p.tenant_id, 'RETENTION_DELETED', p.subject_id, e.payload.evidence_id, { original_digest, crypto_shred: true }, now);
      }
      return { deleted, held, complete_payload_erasure: false, limitation: 'Record DEKs are destroyed and the WAL truncated; ciphertext remaining in pre-erasure backups or external copies is not reachable by this operation.' };
    });
    if (result.deleted) this.store.checkpoint();
    return result;
  }
  // KEY-004/005: threshold ceremonies manage exportable material (backup roots)
  // and pre-stage vault-resident rotation keys. Private material stays inside
  // the vault; shares are the only portable form.
  createCeremony(p, input) {
    this.authorize(p, ['security', 'custodian']);
    return this.transaction(p, now => {
      const ceremony = createCeremony({ ...input, tenant_id: p.tenant_id });
      this.store.insert(p.tenant_id, 'ceremony', ceremony.ceremony_id, ceremony, now);
      this.store.audit(p.tenant_id, 'CEREMONY_PLANNED', p.subject_id, ceremony.ceremony_id, { digest: ceremony.artifact_digest, threshold: ceremony.threshold }, now);
      return ceremony;
    });
  }
  acknowledgeCeremony(p, envelope) {
    this.authorize(p, ['custodian']);
    return this.transaction(p, now => {
      const t = p.tenant_id, payload = verifySigned(envelope, this.identities(t), 'ceremony-acknowledgement');
      fields(payload, ['ceremony_id', 'artifact_digest', 'custodian', 'acknowledged_at']);
      const ceremony = this.store.must(t, 'ceremony', identifier(payload.ceremony_id));
      requireThat(payload.custodian === p.subject_id && payload.artifact_digest === ceremony.artifact_digest, 'INV-403-SCOPE', 'Acknowledgement scope mismatch', 403);
      requireThat(Math.abs(payload.acknowledged_at - now) <= 300000, 'INV-409-STATE', 'Acknowledgement timestamp outside window', 409);
      acknowledge(ceremony, p.subject_id, envelope, now);
      this.store.put(t, 'ceremony', ceremony.ceremony_id, ceremony, now);
      this.store.audit(t, 'CEREMONY_ACKNOWLEDGED', p.subject_id, ceremony.ceremony_id, { custodian: p.subject_id }, now);
      return ceremonyReport(ceremony);
    });
  }
  commitCeremonyShares(p, ceremony_id, shares) {
    this.authorize(p, ['security', 'custodian']);
    return this.transaction(p, now => {
      const ceremony = this.store.must(p.tenant_id, 'ceremony', identifier(ceremony_id));
      commitShares(ceremony, shares, null, now);
      this.store.put(p.tenant_id, 'ceremony', ceremony.ceremony_id, ceremony, now);
      this.store.audit(p.tenant_id, 'CEREMONY_SHARES_COMMITTED', p.subject_id, ceremony.ceremony_id, { count: ceremony.share_commitments.length }, now);
      return ceremonyReport(ceremony);
    });
  }
  reconstructCeremony(p, ceremony_id, encodedShares) {
    this.authorize(p, ['security', 'custodian']);
    return this.transaction(p, now => {
      const ceremony = this.store.must(p.tenant_id, 'ceremony', identifier(ceremony_id));
      requireThat(ceremony.acknowledgements.length >= ceremony.threshold, 'INV-409-STATE', 'Ceremony lacks custodian acknowledgements', 409);
      const shares = encodedShares.map(s => decodeShare(s));
      const { secret, artifact } = reconstructSecret(ceremony, shares, now);
      this.store.put(p.tenant_id, 'ceremony', ceremony.ceremony_id, ceremony, now);
      this.store.audit(p.tenant_id, 'CEREMONY_RECONSTRUCTED', p.subject_id, ceremony.ceremony_id, { quorum: artifact.quorum, purpose: ceremony.purpose }, now);
      return { artifact, reconstructed: true, secret_digest: digest({ secret: Buffer.from(secret).toString('base64url') }), note: 'Secret reconstructed under ceremony quorum; raw material is not returned by this endpoint.' };
    });
  }
  splitCeremonySecret(p, ceremony_id, secretB64) {
    this.authorize(p, ['security', 'custodian']);
    return this.transaction(p, now => {
      const ceremony = this.store.must(p.tenant_id, 'ceremony', identifier(ceremony_id));
      requireThat(ceremony.status === 'planned' || ceremony.status === 'committed', 'INV-409-STATE', 'Ceremony already completed', 409);
      const secret = Buffer.from(secretB64, 'base64url');
      requireThat(secret.length >= 16 && secret.length <= 512, 'INV-400-SCHEMA', 'Secret size out of bounds');
      const shares = splitSecret(secret, ceremony);
      commitShares(ceremony, shares, null, now);
      this.store.put(p.tenant_id, 'ceremony', ceremony.ceremony_id, ceremony, now);
      this.store.audit(p.tenant_id, 'CEREMONY_SHARES_COMMITTED', p.subject_id, ceremony.ceremony_id, { count: ceremony.share_commitments.length }, now);
      return { shares: ceremony.custodians.map((custodian, i) => ({ custodian, share: encodeShare(shares[i]) })), commitments: ceremony.share_commitments };
    });
  }
  prepareRotation(p, key_class) {
    this.authorize(p, ['security', 'custodian']);
    requireThat(['execution', 'audit'].includes(key_class), 'INV-400-SCHEMA', 'key_class must be execution or audit');
    return this.transaction(p, now => {
      const pending = this.vault.generate('any', { pending: true });
      this.persistVault();
      this.store.audit(p.tenant_id, 'ROTATION_PREPARED', p.subject_id, pending.key_id, { key_class, ceremony_bound: true }, now);
      return { key_id: pending.key_id, public_key: pending.public_key, key_class, status: 'pending', note: 'Key generated inside the vault; it cannot sign until a verified key.rotate action activates it.' };
    });
  }
  // Secure Perception (PER-*): dev-attested profile.
  perceptionSession(p, attestation) {
    this.authorize(p, ['operator', 'approver', 'custodian', 'security']);
    return this.transaction(p, now => {
      const t = p.tenant_id;
      const component = this.perceptionComponents[t]?.[attestation?.payload?.component];
      requireThat(component, 'INV-401-ATTESTATION', 'Unknown perception component', 401);
      const session = openSession(component, attestation, this.policy(t), now);
      const stored = { ...session, _server_private: session._server_private.export({ type: 'pkcs8', format: 'pem' }) };
      this.store.insert(t, 'perception-session', session.session_id, stored, now);
      this.store.audit(t, 'PERCEPTION_SESSION', p.subject_id, session.session_id, { component: session.component, assurance: session.assurance, firmware: session.firmware_version }, now);
      return { session_id: session.session_id, assurance: session.assurance, production: false, component: session.component, expires_at: session.expires_at, ephemeral_public: session.server_ephemeral };
    });
  }
  perceptionRelease(p, session_id, release) {
    this.authorize(p, ['operator', 'approver', 'custodian', 'security']);
    return this.transaction(p, now => {
      const t = p.tenant_id, session = this.store.must(t, 'perception-session', identifier(session_id));
      const result = releaseFields(session, release, this.policy(t), now);
      this.store.audit(t, 'PERCEPTION_RELEASE', p.subject_id, session_id, { fields: result.binding.fields, assurance: result.assurance, capsule_id: release.capsule_id ?? null }, now);
      return result;
    });
  }
  perceptionFallback(p, release) {
    this.authorize(p, ['operator', 'approver', 'custodian', 'security']);
    return this.transaction(p, now => {
      const result = workspaceFallback(release, this.policy(p.tenant_id), now);
      this.store.audit(p.tenant_id, 'PERCEPTION_FALLBACK', p.subject_id, 'workspace', { fields: result.binding.fields, assurance: result.assurance }, now);
      return result;
    });
  }
  // AIG-*: deterministic advisory plane — extraction, explanation, intent.
  // Every call is audited with model identity; outputs are advisory:true and
  // cannot create evidence or authority by themselves.
  advise(p, input) {
    this.authorize(p, ['operator', 'security', 'policy_admin', 'approver', 'custodian']);
    fields(input, ['operation'], ['document', 'decision', 'kind_hint']);
    return this.transaction(p, now => {
      requireThat(this.policy(p.tenant_id).mode !== 'disabled', 'INV-451-POLICY', 'Advisory plane disabled', 451);
      let out;
      if (input.operation === 'extract') out = extract(text(input.document, 'document', 1000000));
      else if (input.operation === 'explain') out = explain(input.decision ?? {});
      else if (input.operation === 'intent') out = classifyIntent(text(input.document, 'request text', 100000));
      else throw new InvariantError('INV-400-SCHEMA', 'Unsupported advisory operation');
      this.store.audit(p.tenant_id, 'AI_ADVISORY', p.subject_id, out.model, { operation: input.operation, model: out.model, output_digest: digest(out), advisory: true }, now);
      return out;
    });
  }
}

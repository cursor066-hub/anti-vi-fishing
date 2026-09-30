import { randomUUID, randomBytes } from 'node:crypto';
import { Store } from './store.mjs';
import { SimulatedTarget } from './target.mjs';
import { RuntimeGate } from './runtime.mjs';
import { digest, clone, canonical } from './canonical.mjs';
import { verifySigned, decrypt } from './crypto.mjs';
import { KeyVault } from './keystore.mjs';
import { merkleRoot, inclusionProof, consistencyProof, verifyInclusion } from './merkle.mjs';
import { httpJson, postOnce, readWithRetry, driftCheck } from './connectors.mjs';
import { createCeremony, acknowledge, commitShares, splitSecret, reconstructSecret, ceremonyReport } from './ceremony.mjs';
import { decodeShare, encodeShare } from './shamir.mjs';
import { SUITES } from './crypto.mjs';
import { openSession, releaseFields, workspaceFallback } from './secureview.mjs';
import { extract, explain, classifyIntent } from './advisory.mjs';
import { fields, text, identifier, integer, uniqueStrings, validateProposal } from './schema.mjs';
import { evaluatePolicy, validatePolicy, policyDiff } from './policy.mjs';
import { declarePath, coverageManifest, applyDriftToPaths, coverageAt, effectiveStatus } from './coverage.mjs';
import { watermark, reconstructionCheck } from './datagate.mjs';
import { requireThat, InvariantError } from './errors.mjs';
import { join } from 'node:path';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';

export class Fabric {
  constructor(config, directory, clock = Date.now, { vault = null } = {}) {
    requireThat(config.profile === 'engineering', 'INV-503-RELEASE', 'Production mode is blocked: external acceptance evidence is missing', 503);
    this.config = config; this.directory = directory; this.clock = clock;
    this._configDrift = new Set();
    const encryption = {}, auditSigners = {};
    this.vault = vault ?? this._openVault();
    for (const [tenant, t] of Object.entries(config.tenants)) {
      encryption[tenant] = this.dataKey(tenant, 'encryption');
      for (const klass of ['execution', 'audit']) {
        const key = t.keys[klass];
        // Embedded-custody keys are imported purpose-bound and non-exportable
        // — never 'any'/exportable, so no future code path can coerce them
        // into signing outside their class or exfiltrating private material.
        const purposes = { execution: ['action-certificate', 'capability'], audit: ['audit', 'outcome', 'revocation', 'coverage', 'checkpoint', 'backup-manifest'] };
        this._keyPurposes = purposes;
        if (key.private_key && !this.vault.has(key.key_id)) this.vault.importKey({ key_id: key.key_id, public_key: key.public_key, private_key: key.private_key }, purposes[klass], { exportable: false, tenant_id: tenant });
        requireThat(this.vault.has(key.key_id), 'INV-503-CONFIG', `Tenant ${klass} key is not in the keystore`, 503);
      }
      auditSigners[tenant] = { key_id: t.keys.audit.key_id, public_key: t.keys.audit.public_key, keys: () => this.auditPublicKeys(tenant), sign: (payload, purpose = 'audit') => this.vault.envelope(this.keys(tenant).audit.key_id, purpose, payload) };
    }
    this.store = new Store(join(directory, 'fabric.db'), encryption, auditSigners);
    this.target = new SimulatedTarget(join(directory, 'target.db'), encryption); this.runtime = new RuntimeGate(this);
    this._reconcileLedger();
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
      // Per-section digests let a later drift report name WHAT changed, not
      // just that the combined digest differs.
      const sections = { identities: digest(t.identities), issuers: digest(t.issuers), genesis_policy: digest(t.genesis_policy), gate_id: digest(config.gate_id) };
      const configDigest = digest({ tenant, sections });
      const existing = this.store.get(tenant, 'config-snapshot', 'current');
      if (!existing) this.store.tx(() => { this.store.put(tenant, 'config-snapshot', 'current', { digest: configDigest, taken_at: this.clock(), sections }, this.clock()); this.store.audit(tenant, 'CONFIG_SNAPSHOT', 'system', 'config', { config_digest: configDigest }, this.clock()); });
      else if (existing.digest !== configDigest) {
        const changed = existing.sections ? Object.keys(sections).filter(k => existing.sections[k] !== sections[k]) : ['unknown'];
        this._configDrift.add(tenant);
        this.store.tx(() => { this.store.put(tenant, 'config-flag', 'drift', { detected_at: this.clock(), expected: existing.digest, observed: configDigest }, this.clock()); this.store.audit(tenant, 'CONFIG_DRIFT', 'system', 'config', { expected: existing.digest, observed: configDigest, changed_sections: changed, consequence: 'gate-privileges-withdrawn' }, this.clock()); });
      }
    } } catch (error) { this.close(); throw error; }
  }
  // Converge non-transactional side effects to the committed ledger. The
  // outcome tx writes key-rotation / jit-grant records; their vault and
  // target mutations run post-commit, so a crash between commit and apply is
  // healed here on the next open rather than leaving a permanent divergence
  // (store-audit MED-6). The ledger is the source of truth; vault and target
  // grant tables are derived state.
  _reconcileLedger() {
    let dirty = false;
    for (const tenant of Object.keys(this.config.tenants)) {
      // Rotation history is newest-first; only the newest record per class
      // may restore a key pointer. Applying every record converged the class
      // to the OLDEST rotation — and resurrected revoked keys (w6 F1).
      const latestByClass = new Map();
      for (const rot of this.store.list(tenant, 'key-rotation', 1000)) if (!latestByClass.has(rot.key_class)) latestByClass.set(rot.key_class, rot);
      for (const rot of latestByClass.values()) {
        if (this.tenant(tenant).keys[rot.key_class]?.key_id === rot.new_key_id) continue;
        const entry = this.vault.keys.get(rot.new_key_id);
        if (entry && !entry.revoked && entry.public_key === rot.new_public_key) {
          if (entry.pending) this.vault.activate(rot.new_key_id);
          const previous = this.tenant(tenant).keys[rot.key_class];
          this.tenant(tenant).keys[rot.key_class] = { key_id: rot.new_key_id, public_key: rot.new_public_key };
          if (previous && !(this.tenant(tenant).keys.retired ?? []).some(x => x.key_id === previous.key_id)) {
            this.tenant(tenant).keys.retired = [...(this.tenant(tenant).keys.retired ?? []), { key_class: rot.key_class, key_id: previous.key_id, public_key: previous.public_key, retired_at: rot.rotated_at }];
          }
          dirty = true;
        }
      }
      const grants = this.target.allGrants(tenant);
      for (const jg of this.store.list(tenant, 'jit-grant', 1000)) {
        if (!grants.some(g => g.grant_id === jg.grant.grant_id)) this.target.grant(tenant, jg.grant.grant_id, jg.grant);
      }
    }
    if (dirty) this.persistVault();
  }
  _openVault() {
    const storePath = join(this.directory, 'keystore.json'), masterPath = join(this.directory, 'master.key');
    // master.key is the commit marker written last: a keystore without it
    // means a crash mid-persist — refuse rather than silently regenerate.
    if (existsSync(storePath) && !existsSync(masterPath)) throw new InvariantError('INV-503-CONFIG', 'Keystore exists but master key is missing — refusing to silently regenerate', 503);
    if (existsSync(storePath)) return KeyVault.load(storePath, JSON.parse(readFileSync(masterPath, 'utf8')).master_key);
    return new KeyVault(randomBytes(32).toString('base64url'));
  }
  persistVault() {
    mkdirSync(this.directory, { recursive: true, mode: 0o700 });
    // Write order: keystore first, master.key last — the master file is the
    // commit marker, so a crash mid-write can never pair a stale master key
    // with a keystore it did not wrap (w6-ceremony F12).
    this.vault.save(join(this.directory, 'keystore.json'));
    if (!existsSync(join(this.directory, 'master.key'))) {
      writeFileSync(join(this.directory, 'master.key'), canonical({ format: 'IF-MASTERKEY-1', warning: 'software vault master key; custody is the operator\'s responsibility', master_key: this.vault.masterKey.toString('base64url') }) + '\n', { mode: 0o600 });
    }
  }
  // Live, failure-domain-deduplicated custodian consent for a ceremony:
  // acknowledgements from revoked identities or from the same failure
  // domain do not count toward quorum (w6 F7/F9).
  custodianQuorum(t, ceremony) {
    const bySubject = new Map(Object.values(this.identities(t)).map(i => [i.subject_id, i]));
    const domains = new Set(), live = new Set();
    for (const a of ceremony.acknowledgements) {
      // Only consent to the CURRENT artifact counts: an acknowledgement
      // bound to a superseded digest attested different terms (w7-seam F4).
      if (a.payload.artifact_digest !== ceremony.artifact_digest) continue;
      const identity = bySubject.get(a.payload.custodian);
      if (!identity || identity.revoked) continue;
      live.add(a.payload.custodian);
      domains.add(identity.failure_domain ?? a.payload.custodian);
    }
    return { count: ceremony.acknowledgements.length, live: domains.size, custodians: live };
  }
  close() { this.target.close(); this.store.close(); }
  tenant(t) { const row = this.config.tenants[t]; requireThat(row, 'INV-404-NOT-FOUND', 'Resource not found', 404); return row; }
  // Tenant data keys are stored wrapped under the vault master key in real
  // deployments (encryption_key_wrapped / watermark_key_wrapped); the
  // embedded-custody dev profile falls back to the plaintext fields
  // (DEK-audit F2).
  dataKey(t, kind) {
    const row = this.tenant(t), wrapped = row[`${kind}_key_wrapped`], plain = row[`${kind}_key`];
    // Ambiguous custody is refused, not silently resolved: a config carrying
    // both a wrapped and a plaintext twin for the same key is a defect an
    // operator must fix (w8-fixverify F6).
    requireThat(!(wrapped && plain), 'INV-503-CONFIG', `Tenant ${t} has both wrapped and plaintext ${kind} key material`, 503);
    if (wrapped) try { return decrypt(wrapped, this.vault.masterKey, `data-key/${t}/${kind}`); } catch { throw new InvariantError('INV-503-CONFIG', `Wrapped ${kind} data key for ${t} is malformed`, 503); }
    return plain;
  }
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
  signExecution(t, payload, purpose) {
    const key_id = this.keys(t).execution.key_id;
    // The ledger, not the vault flag, is authoritative for revocation — a
    // revoked key keeps verifying old artifacts but must never sign new
    // envelopes (w6-fix F4).
    requireThat(!this.revoked(t, 'key', key_id), 'INV-401-SIGNATURE', 'Signing key revoked', 401);
    this.assertSuiteAllowed(t, this.vault.entry(key_id).suite ?? 'Ed25519');
    return this.vault.envelope(key_id, purpose, payload);
  }
  signAudit(t, payload, purpose = 'audit', key_id = null) {
    const kid = key_id ?? this.keys(t).audit.key_id;
    requireThat(!this.revoked(t, 'key', kid), 'INV-401-SIGNATURE', 'Signing key revoked', 401);
    this.assertSuiteAllowed(t, this.vault.entry(kid).suite ?? 'Ed25519');
    return this.vault.envelope(kid, purpose, payload);
  }
  assertSuiteAllowed(t, suite) {
    requireThat((this.policy(t).algorithms?.allowed_suites ?? ['Ed25519']).includes(suite), 'INV-451-POLICY', 'Signature suite retired by constitution', 451);
  }
  // Current drift status with a field-level preview of what changed — a
  // security actor must be able to see the diff before re-attesting.
  configDriftStatus(p) {
    this.authorize(p, ['security', 'policy_admin']);
    const t = p.tenant_id, tenant = this.tenant(t);
    const sections = { identities: digest(tenant.identities), issuers: digest(tenant.issuers), genesis_policy: digest(tenant.genesis_policy), gate_id: digest(this.config.gate_id) };
    const observed = digest({ tenant: t, sections }), existing = this.store.get(t, 'config-snapshot', 'current');
    const changed = existing?.sections ? Object.keys(sections).filter(k => existing.sections[k] !== sections[k]) : [];
    return { drifted: this._configDrift.has(t) || (existing && existing.digest !== observed), expected: existing?.digest ?? null, observed, changed_sections: changed };
  }
  // RUN-010: security re-attests a drifted configuration snapshot, restoring
  // privileges. This is the only operation allowed through during drift.
  reassertConfig(p) {
    this.authorize(p, ['security']);
    return this.transaction(p, now => {
      const t = p.tenant_id, tenant = this.tenant(t);
      const sections = { identities: digest(tenant.identities), issuers: digest(tenant.issuers), genesis_policy: digest(tenant.genesis_policy), gate_id: digest(this.config.gate_id) };
      const digestNow = digest({ tenant: t, sections }), existing = this.store.get(t, 'config-snapshot', 'current');
      const changed = existing?.sections ? Object.keys(sections).filter(k => existing.sections[k] !== sections[k]) : [];
      this.store.put(t, 'config-snapshot', 'current', { digest: digestNow, taken_at: now, sections }, now);
      this._configDrift.delete(t);
      if (this.store.get(t, 'config-flag', 'drift')) this.store.remove(t, 'config-flag', 'drift');
      this.store.audit(t, 'CONFIG_REASSERTED', p.subject_id, 'config', { config_digest: digestNow, changed_sections: changed }, now);
      return { reasserted: true, config_digest: digestNow, changed_sections: changed };
    }, { allowDuringDrift: true });
  }
  // Clock recovery (concurrency-audit L6): the ledger clock is monotone and a
  // forward host-clock jump would otherwise wedge every tenant permanently —
  // transaction() itself throws INV-503-TIME before it can run recovery. This
  // deliberately bypasses transaction() and requires a security actor; the
  // recovery is audited. It can only move the clock forward to the host's
  // current time, never back.
  recoverClock(p) {
    this.authorize(p, ['security', 'policy_admin']);
    return this.store.tx(() => {
      const now = this.clock();
      const prior = this.store.db.prepare('SELECT last FROM clock WHERE id=1').get()?.last ?? null;
      // Recovery records the discontinuity explicitly: prior_last is what
      // the ledger believed, recovered_at is the operator-asserted honest
      // host time. An external verifier sees the jump on the signed chain
      // — time discontinuity is evidence, not silent rewriting (w7-clock F1).
      this.store.clock(now, { recovery: true });
      this.store.audit(p.tenant_id, 'CLOCK_RECOVERED', p.subject_id, 'local-gate', { prior_last: prior, recovered_at: now, regression_ms: prior !== null ? prior - now : 0 }, now);
      return { recovered_at: now, prior_last: prior };
    });
  }
  identity(p) {
    const identity = Object.values(this.tenant(p.tenant_id).identities).find(x => x.subject_id === p.subject_id);
    requireThat(identity && !identity.revoked, 'INV-401-AUTH', 'Authentication required', 401); return identity;
  }
  authorize(p, roles) {
    requireThat(p && this.config.tenants[p.tenant_id], 'INV-401-AUTH', 'Authentication required', 401);
    const identity = this.identity(p);
    const effective = this.grantsFor(p.tenant_id, p.subject_id, this.clock()).roles ?? identity.roles;
    requireThat(effective.some(r => roles.includes(r)), 'INV-403-ROLE', 'Permission denied', 403);
    requireThat(!this.revoked(p.tenant_id, 'subject', p.subject_id), 'INV-403-QUARANTINE', 'Identity unavailable', 403);
    return identity;
  }
  // IDN: JIT grants merge with static identity grants. A grant only ever adds
  // scope already permitted by the runtime policy; it cannot exceed it.
  grantsFor(tenant, subject_id, now) {
    const identity = Object.values(this.tenant(tenant).identities).find(x => x.subject_id === subject_id);
    const base = identity?.grants ?? { resources: [], actions: [], destinations: [], columns: [], row_ids: [] };
    // CON-008: grant-carried roles merge too — support access confers its
    // operational role ONLY for the grant window; no standing access remains
    // after expiry or revocation.
    const merged = { roles: [...(identity?.roles ?? [])], resources: [...base.resources], actions: [...base.actions], destinations: [...base.destinations], columns: [...base.columns], row_ids: [...base.row_ids] };
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
      // A due-but-stale row (superseded version race, or expired before its
      // slot) must never wedge every transaction — retire it honestly and
      // move on (policy-audit F1/F3).
      if (staged.policy.version !== active.version + 1 || staged.policy.expires_at <= now) {
        this.store.remove(t, 'policy', 'staged');
        this.store.audit(t, 'POLICY_SUPERSEDED', 'system', staged.policy.policy_id, { version: staged.policy.version, reason: staged.policy.expires_at <= now ? 'expired-before-activation' : 'version-superseded' }, now);
        return null;
      }
      this.store.put(t, 'policy', 'active', staged.policy, now);
      this.store.remove(t, 'policy', 'staged');
      this.store.put(t, 'policy-history', `v${staged.policy.version}`, { activated_at: now, digest: digest(staged.policy), staged: true, emergency: staged.policy.emergency_of !== undefined }, now);
      this.store.audit(t, staged.policy.emergency_of !== undefined ? 'EMERGENCY_POLICY_ACTIVATED' : 'POLICY_ACTIVATED', 'system', staged.policy.policy_id, { version: staged.policy.version, staged_from: staged.staged_at }, now);
      return staged.policy;
    }
    return null;
  }
  transaction(principal, fn, { allowDuringDrift = false } = {}) {
    try {
      this.authorize(principal, ['operator', 'approver', 'custodian', 'security', 'auditor', 'policy_admin', 'workload']);
      // RUN-010: a drifting gate configuration withdraws privileges until a
      // security actor re-attests the observed config snapshot.
      // Drift quarantine is durable (a 'config-flag' record), not just the
      // in-memory set — a second Fabric instance on the same deployment
      // cannot transact through a drift it never noticed (concurrency-audit M4).
      requireThat(allowDuringDrift || (!this._configDrift.has(principal.tenant_id) && !this.store.get(principal.tenant_id, 'config-flag', 'drift')), 'INV-403-QUARANTINE', 'Configuration drift withdrew gate privileges pending security re-attestation', 403);
      return this.store.tx(() => { const now = this.clock(); this.store.clock(now); this.activateDuePolicies(principal.tenant_id, now); return fn(now); });
    }
    catch (error) {
      if (error instanceof InvariantError && error.code !== 'INV-503-TIME') {
        // A failing rejection-audit tx must not mask the original error (L1).
        try { this.store.tx(() => { const now = this.clock(); this.store.clock(now); this.store.audit(principal.tenant_id, 'SECURITY_OPERATION_REJECTED', principal.subject_id, 'local-gate', { code: error.code }, now); }); } catch { /* ledger unavailable — surface the real rejection */ }
        throw error;
      }
      if (error instanceof InvariantError) throw error;
      // RUN-009: infrastructure failures get a stable documented code instead
      // of leaking driver internals (e.g. node:sqlite ERR_INVALID_STATE).
      throw new InvariantError('INV-503-GATE', 'Internal gate failure', 503);
    }
  }
  revoked(tenant, kind, id) { return Boolean(this.store.get(tenant, 'revocation', `${kind}:${id}`)); }
  policy(t) {
    const staged = this.store.get(t, 'policy', 'staged'), active = this.store.must(t, 'policy', 'active');
    if (staged && staged.activate_at <= this.clock() && staged.policy.version === active.version + 1 && staged.policy.expires_at > this.clock()) return staged.policy;
    return active;
  }
  identities(t) { return Object.fromEntries(Object.entries(this.tenant(t).identities).map(([id, v]) => [id, { ...v, revoked: v.revoked || this.revoked(t, 'key', id) || this.revoked(t, 'subject', v.subject_id) }])); }
  assertHealthy(t, subject, device, now) {
    requireThat(!this.revoked(t, 'subject', subject) && !this.revoked(t, 'device', device), 'INV-403-QUARANTINE', 'Subject or device quarantined', 403);
    const identity = Object.values(this.tenant(t).identities).find(x => x.subject_id === subject);
    requireThat(identity && identity.device_id === device && identity.health_expires_at > now, 'INV-403-HEALTH', 'Configured device health evidence expired or mismatched', 403);
  }
  getCapsule(p, id) { this.authorize(p, ['operator', 'approver', 'custodian', 'security', 'policy_admin', 'auditor']); return this.capsuleView(this.store.must(p.tenant_id, 'capsule', identifier(id))); }
  // A capsule read never returns raw dataset rows: current_state snapshots
  // are needed internally for predicates and target equality checks, but the
  // read surface exposes only their digest (w6-tenancy F1).
  capsuleView(record) {
    const view = clone(record);
    const redact = material_fields => {
      if (Array.isArray(material_fields?.rows)) return { ...material_fields, rows: undefined, row_count: material_fields.rows.length, rows_digest: digest(material_fields.rows) };
      return material_fields;
    };
    if (view.capsule?.current_state?.material_fields) view.capsule.current_state = { ...view.capsule.current_state, material_fields: redact(view.capsule.current_state.material_fields) };
    // The signed intent envelope carries the proposal input verbatim — an
    // unredacted payload would re-expose every row (w6-fix F1). The served
    // copy is a projection; verification happens at attach time.
    const intent = view.capsule?.request_intent?.payload;
    if (intent?.current_state?.material_fields) intent.current_state = { ...intent.current_state, material_fields: redact(intent.current_state.material_fields) };
    if (intent?.requested_state?.material_fields) intent.requested_state = { ...intent.requested_state, material_fields: redact(intent.requested_state.material_fields) };
    return view;
  }
  // A stored outcome is the signed forensic artifact — its served projection
  // never re-ships exported rows to readers: a second subject cannot drain
  // row material from the outcome store without a data_access charge
  // (w6-fix F3).
  outcomeView(outcome) {
    const view = clone(outcome), output = view?.payload?.output;
    if (Array.isArray(output)) view.payload.output = { row_count: output.length, rows_digest: digest(output), redacted: true };
    return view;
  }
  // Tenant ownership of a vault key: entries tagged at mint match directly;
  // a legacy untagged entry (a keystore file carried over the tenant-binding
  // upgrade) resolves through the tenant's own key bindings — anything else
  // is an unreachable orphan on every surface (w6-fix F5).
  ownsVaultKey(t, key_id) {
    const entry = this.vault.keys.get(key_id);
    if (!entry) return false;
    if (entry.tenant_id != null) return entry.tenant_id === t;
    const bound = this.keys(t);
    return Object.values(bound).some(v => v?.key_id === key_id) || (bound.retired ?? []).some(r => r.key_id === key_id);
  }
  // The state reference carried by signed artifacts binds the snapshot by
  // digest — material rows never travel inside a certificate (w6-tenancy F1).
  stateRef(current_state) {
    const ref = { version: current_state.version, digest: current_state.digest };
    if (current_state.material_fields !== undefined) ref.material_fields_digest = digest(current_state.material_fields);
    return ref;
  }
  // The snapshot a proposer embeds must still describe live target state at
  // decision time — a fabricated or stale current_state cannot earn an
  // evaluation or a certificate (w6-tenancy F1).
  assertFreshSnapshot(t, capsule) {
    const ref = capsule.current_state;
    if (!ref || ref.version === undefined || ref.digest === undefined) return;
    // The decisive record differs by action class — secret.use binds the
    // secrets-registry row, everything else binds the resources row
    // (w6-fix F2). Untracked ids synthesize an empty state, so a fabricated
    // snapshot (claimed version or fields) fails the comparison instead of
    // skipping the check.
    const live = capsule.action.type === 'secret.use' ? this.target.secretState(t, capsule.requested_state?.secret_id) : this.target.state(t, capsule.action.target_resource);
    requireThat(live.version === ref.version && live.digest === ref.digest, 'INV-409-STATE', 'Proposed state snapshot is stale or does not match live target state', 409);
  }
  propose(p, input, idempotencyKey, requestIntent = null) {
    this.authorize(p, ['operator', 'workload', 'policy_admin']); validateProposal(input);
    requireThat(input.actor.subject_id === p.subject_id && input.actor.identity_class === this.identity(p).identity_class, 'INV-403-ACTOR', 'Actor must match authenticated identity', 403);
    // ACT-005: request intent is its own signed object, distinct from the
    // authorised action (certificate) and the observed outcome. It must be a
    // 'capsule-intent' envelope over the exact proposal input, signed by the
    // actor's registered identity key — a bearer token alone never mints a
    // request record someone could disown.
    requireThat(requestIntent, 'INV-401-SIGNATURE', 'A signed request-intent envelope over the proposal input is required', 401);
    const identityEntry = Object.entries(this.tenant(p.tenant_id).identities).find(([, v]) => v.subject_id === p.subject_id);
    const intentPayload = verifySigned(requestIntent, { [identityEntry[0]]: { public_key: identityEntry[1].public_key } }, 'capsule-intent');
    requireThat(digest(intentPayload) === digest(input), 'INV-401-SIGNATURE', 'Request intent does not cover the proposed capsule exactly', 401);
    return this.transaction(p, now => this.store.idempotent(p.tenant_id, 'propose', idempotencyKey, digest(input), () => {
      const policy = this.policy(p.tenant_id); this.assertHealthy(p.tenant_id, p.subject_id, input.actor.device_id, now);
      requireThat(input.created_at <= now + 5000 && input.created_at >= now - 300000 && input.expires_at > now && input.expires_at - input.created_at <= policy.max_capsule_ttl_ms, 'INV-400-SCHEMA', 'Capsule timing invalid');
      const prior = this.store.db.prepare('SELECT capsule FROM nonces WHERE tenant=? AND nonce=?').get(p.tenant_id, input.nonce);
      requireThat(!prior, 'INV-409-REPLAY', 'Nonce is already bound to another action', 409);
      const capsule = { ...clone(input), request_intent: clone(requestIntent), capsule_id: randomUUID(), tenant_id: p.tenant_id, received_at: now };
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
      const iss = this.tenant(t).issuers[e.envelope.protected.key_id];
      // Only the issuer's semantic identity is digest-bound — credential
      // fields (tokens, expiry, endpoint) rotate by design and must never
      // invalidate a minted certificate or pending approval (w5 F-3).
      const semantic = iss ? { public_key: iss.public_key, name: iss.name, issuer_id: iss.issuer_id, failure_domain: iss.failure_domain, channel: iss.channel, kinds: iss.kinds, version: iss.version } : iss;
      return { ...e, revoked: this.revoked(t, 'evidence', id) || this.revoked(t, 'issuer', e.envelope.protected.key_id) || this.revoked(t, 'key', e.envelope.protected.key_id), drifted: !!this.store.get(t, 'issuer-drift', e.envelope.protected.key_id), issuer: semantic };
    });
    const graph_digest = digest(items.map(e => ({ envelope_digest: digest(e.envelope), issuer_digest: digest(e.issuer), revoked: e.revoked })).sort((a, b) => a.envelope_digest < b.envelope_digest ? -1 : 1));
    return { items, digest: graph_digest };
  }
  attachEvidence(p, id, envelope) {
    this.authorize(p, ['operator', 'security', 'policy_admin']);
    return this.transaction(p, now => {
      const t = p.tenant_id, record = this.store.must(t, 'capsule', id); this.ensureMutable(record);
      // Attaching wipes collected approvals by design (new evidence invalidates
      // the evaluation), so only the proposing actor may do it — a third party
      // must not grief another actor's capsule (HTTP-audit finding).
      requireThat(record.capsule.actor.subject_id === p.subject_id, 'INV-403-SCOPE', 'Only the proposing actor may attach evidence', 403);
      this.assertHealthy(t, record.capsule.actor.subject_id, record.capsule.actor.device_id, now);
      const payload = this.verifyEvidenceEnvelope(t, envelope);
      requireThat(payload.acquired_at > now - 7 * 86400000, 'INV-400-SCHEMA', 'Evidence too old to attach', 400);
      requireThat(!this.revoked(t, 'issuer', envelope.protected.key_id) && !this.revoked(t, 'key', envelope.protected.key_id) && !this.revoked(t, 'evidence', payload.evidence_id), 'INV-401-EVIDENCE', 'Evidence source revoked', 401);
      // A connector whose observed manifest drifted from registration stops
      // being trusted for new evidence until a clean re-check clears the flag
      // (CON-006; issuerd-audit MED-2).
      requireThat(!this.store.get(t, 'issuer-drift', envelope.protected.key_id), 'INV-403-QUARANTINE', 'Issuer connector drifted — evidence suspended pending revalidation', 403);
      requireThat(payload.tenant_id === t && payload.capsule_digest === record.capsule_digest, 'INV-403-SCOPE', 'Evidence scope mismatch', 403);
      // HIGH-2: supporting evidence must describe THIS action's content, not
      // merely be a true statement of the right kind. Policy-declared
      // bindings map claim fields to capsule paths (requested_state/
      // target_resource/actor). Only 'supports' envelopes are bound — a
      // 'conflict' answer deliberately carries minimal claims and can never
      // satisfy a requirement, so it stays attachable as denial evidence.
      if (payload.claim === 'supports') {
        const bindings = (this.policy(t).rules[record.capsule.action.type]?.evidence_bindings ?? {})[payload.kind] ?? {};
        for (const [claimField, path] of Object.entries(bindings)) {
          const expected = path.split('.').reduce((o, k) => o?.[k], record.capsule);
          requireThat(expected !== undefined && String(payload.claims?.[claimField]) === String(expected), 'INV-403-SCOPE', `Evidence claims do not describe this action (claims.${claimField} must equal ${path})`, 403);
        }
      }
      requireThat(payload.dependencies.every(dep => record.evidence.includes(dep)), 'INV-400-SCHEMA', 'Dependencies must already belong to this action');
      requireThat(record.evidence.length < 32, 'INV-429-CAPACITY', 'Evidence set limit reached', 429);
      const issuer = this.tenant(t).issuers[envelope.protected.key_id];
      requireThat(issuer.kinds.includes(payload.kind), 'INV-403-SCOPE', 'Issuer is not trusted for this evidence kind', 403);
      requireThat(!payload.issuer_version || payload.issuer_version === issuer.version, 'INV-403-SCOPE', 'Issuer version drifted from registration', 403);
      this.store.insert(t, 'evidence', payload.evidence_id, { payload: clone(payload), envelope: clone(envelope), legal_hold: false }, now);
      record.evidence.push(payload.evidence_id); record.status = 'EVIDENCED'; record.approvals = []; record.decision = null;
      this.store.put(t, 'capsule', id, record, now); this.store.audit(t, 'EVIDENCE_ATTACHED', p.subject_id, id, { evidence_id: payload.evidence_id, evidence_digest: digest(envelope) }, now);
      return { evidence_id: payload.evidence_id, evidence_graph_digest: this.graph(t, record).digest };
    });
  }
  verifyEvidenceEnvelope(t, envelope) {
    const payload = verifySigned(envelope, this.tenant(t).issuers, 'evidence');
    this.assertSuiteAllowed(t, envelope.protected.suite);
    fields(payload, ['evidence_id', 'tenant_id', 'capsule_digest', 'kind', 'content_digest', 'acquired_at', 'expires_at', 'confidence', 'advisory', 'claim', 'dependencies', 'provenance', 'retention_until'], ['claims', 'issuer_version']);
    identifier(payload.evidence_id); text(payload.kind, 'evidence kind'); text(payload.provenance, 'provenance', 2048); uniqueStrings(payload.dependencies, 'dependencies', 32);
    const now = this.clock();
    integer(payload.confidence, 'confidence', 0, 100); integer(payload.acquired_at, 'acquisition time', 1, now + 5000); integer(payload.expires_at, 'evidence expiry', now + 1); integer(payload.retention_until, 'retention', payload.expires_at);
    // AUD-006: the envelope cannot claim a retention window past the policy
    // ceiling for its evidence class.
    const retention = this.policy(t).retention;
    if (retention) { const ceiling = payload.acquired_at + (retention.per_kind?.[payload.kind] ?? retention.default_ms); requireThat(payload.retention_until <= ceiling, 'INV-400-SCHEMA', `Retention exceeds the policy ceiling for kind ${payload.kind}`, 400); }
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
    requireThat(record.capsule.actor.subject_id === p.subject_id, 'INV-403-SCOPE', 'Only the proposing actor may acquire evidence', 403);
    const entry = Object.entries(this.tenant(t).issuers).find(([, v]) => v.name === input.issuer || input.issuer === v.issuer_id);
    requireThat(entry, 'INV-404-NOT-FOUND', 'Issuer not found', 404);
    const [key_id, issuer] = entry;
    requireThat(issuer.endpoint, 'INV-412-EVIDENCE', 'Issuer has no live endpoint; attach a pre-signed envelope instead', 412);
    requireThat(!this.revoked(t, 'issuer', key_id) && !this.revoked(t, 'key', key_id), 'INV-401-EVIDENCE', 'Evidence source revoked', 401);
    requireThat(!this.store.get(t, 'issuer-drift', key_id), 'INV-403-QUARANTINE', 'Issuer connector drifted — acquisition suspended pending revalidation', 403);
    // The fabric — not the caller — derives the claims that bind the evidence
    // to this action's declared content, so a caller cannot query the issuer
    // about an unrelated entity and attach the answer (HIGH-2).
    const bindings = (this.policy(t).rules[record.capsule.action.type]?.evidence_bindings ?? {})[input.kind] ?? {};
    const claims = { ...(input.claims ?? {}) };
    for (const [claimField, path] of Object.entries(bindings)) {
      const expected = path.split('.').reduce((o, k) => o?.[k], record.capsule);
      requireThat(expected !== undefined, 'INV-400-SCHEMA', `Action lacks the field the evidence binding requires (${path})`, 400);
      claims[claimField] = expected;
    }
    let envelope;
    const callStarted = Date.now();
    try {
      const res = await postOnce(`${issuer.endpoint}/v1/issuers/${issuer.name ?? input.issuer}/issue`, { tenant_id: t, capsule_digest: record.capsule_digest, kind: input.kind, subject_id: input.subject_id ?? p.subject_id, claims, dependencies: input.dependencies ?? [] }, { headers: issuer.issue_token ? { Authorization: `Bearer ${issuer.issue_token}` } : undefined, timeout_ms: 10000 });
      requireThat(res.status === 201, 'INV-503-EVIDENCE-SOURCE', `Issuer refused (${res.status})`, 503);
      envelope = res.data;
      this.recordIssuerCall(key_id, Date.now() - callStarted, false);
    } catch (e) {
      this.recordIssuerCall(key_id, Date.now() - callStarted, true);
      const err = new InvariantError('INV-503-EVIDENCE-SOURCE', `Evidence source unavailable or refused: ${e instanceof InvariantError ? e.code : 'transport'}`, 503);
      this.store.tx(() => this.store.audit(t, 'EVIDENCE_ACQUISITION_FAILED', p.subject_id, capsule_id, { issuer: input.issuer, kind: input.kind, code: e.code ?? 'transport' }, this.clock()));
      throw err;
    }
    return this.attachEvidence(p, capsule_id, envelope);
  }
  // CON-009: live issuer call telemetry — latency and error counts are
  // process-local, honest in-memory counters surfaced via connectorStatus.
  recordIssuerCall(key_id, latency_ms, failed) {
    const map = this.issuerMetrics ??= {};
    const m = map[key_id] ??= { calls: 0, errors: 0, total_latency_ms: 0, last_error_at: null };
    m.calls++; m.total_latency_ms += latency_ms;
    if (failed) { m.errors++; m.last_error_at = this.clock(); }
  }
  connectorStatus(p) {
    this.authorize(p, ['operator', 'security', 'policy_admin', 'auditor']);
    const issuers = Object.entries(this.tenant(p.tenant_id).issuers).map(([key_id, v]) => { const m = this.issuerMetrics?.[key_id] ?? { calls: 0, errors: 0, total_latency_ms: 0, last_error_at: null }; return { key_id, name: v.name ?? null, channel: v.channel, failure_domain: v.failure_domain, endpoint: v.endpoint ?? null, revoked: this.revoked(p.tenant_id, 'issuer', key_id) || this.revoked(p.tenant_id, 'key', key_id), metrics: { calls: m.calls, errors: m.errors, mean_latency_ms: m.calls ? Math.round(m.total_latency_ms / m.calls) : null, last_error_at: m.last_error_at } }; });
    return { gate: this.config.gate_id, target: this.target.manifest(), issuers, profile: 'engineering' };
  }
  async checkIssuerDrift(p, key_id) {
    this.authorize(p, ['security', 'policy_admin']);
    const issuer = this.tenant(p.tenant_id).issuers[key_id];
    requireThat(issuer?.endpoint, 'INV-404-NOT-FOUND', 'Issuer endpoint not found', 404);
    let observed;
    const callStarted = Date.now();
    try { const res = await readWithRetry(`${issuer.endpoint}/v1/issuers/${issuer.name}/manifest?tenant=${p.tenant_id}`, { timeout_ms: 10000, retries: 2, headers: (issuer.read_token ?? issuer.issue_token) ? { Authorization: `Bearer ${issuer.read_token ?? issuer.issue_token}` } : undefined }); observed = res.data; this.recordIssuerCall(key_id, Date.now() - callStarted, false); } catch (e) {
      this.recordIssuerCall(key_id, Date.now() - callStarted, true);
      return this.transaction(p, now => { this.store.put(p.tenant_id, 'issuer-drift', key_id, { drifted_at: now, changes: [{ field: 'endpoint', detail: 'unreachable' }] }, now); this.store.audit(p.tenant_id, 'CONNECTOR_DRIFT', p.subject_id, key_id, { drifted: 'unreachable', code: e.code ?? 'transport' }, now); return { drifted: true, changes: [{ field: 'endpoint', detail: 'unreachable' }], checked_at: now }; });
    }
    let observedPayload;
    try {
      observedPayload = verifySigned(observed, { [key_id]: issuer }, 'connector-manifest');
      this.assertSuiteAllowed(p.tenant_id, observed.protected.suite);
      fields(observedPayload, ['connector_id', 'version', 'domain', 'actions', 'permissions', 'limitations', 'idempotency', 'coverage_implications', 'issued_at', 'expires_at']);
      requireThat(observedPayload.expires_at > this.clock(), 'INV-401-CONNECTOR', 'Connector manifest expired', 401);
      requireThat(Number.isSafeInteger(observedPayload.issued_at) && observedPayload.issued_at <= this.clock() + 300000, 'INV-401-CONNECTOR', 'Connector manifest issued-at is implausible', 401);
    } catch (e) {
      // A tampered or mis-signed manifest is drift, not just an error: the
      // issuer is quarantined exactly as if unreachable — forged manifests
      // are a stronger signal than downtime (w5 F-5).
      if (e instanceof InvariantError) {
        try { this.store.tx(() => { this.store.put(p.tenant_id, 'issuer-drift', key_id, { drifted_at: this.clock(), changes: [{ field: 'manifest', detail: 'invalid' }] }, this.clock()); this.store.audit(p.tenant_id, 'CONNECTOR_DRIFT', p.subject_id, key_id, { drifted: 'manifest_invalid', code: e.code }, this.clock()); }); } catch { /* ledger unavailable */ }
      }
      throw e;
    }
    const registered = { connector_id: `issuer:${issuer.name}`, version: issuer.version ?? '1.0.0', actions: issuer.kinds, channel: issuer.channel, key_id };
    const result = driftCheck(registered, { connector_id: observedPayload.connector_id, version: observedPayload.version, actions: observedPayload.actions, channel: observedPayload.domain, key_id: observed.protected.key_id }, this.clock());
    return this.transaction(p, now => {
      // A clean re-check clears the suspension; a drifted one records it and
      // stops the issuer's evidence until then (MED-2).
      this.store.remove(p.tenant_id, 'issuer-drift', key_id);
      if (!result.drifted) return result;
      this.store.put(p.tenant_id, 'issuer-drift', key_id, { drifted_at: now, changes: result.changes }, now);
      // COV-004/CON-006 consequence: paths depending on the drifted connector
      // lose their observation evidence and fall to UNKNOWN until revalidated.
      // Each transition emits a coverage event and an owner task (COV-005/009).
      const paths = this.store.list(p.tenant_id, 'coverage', 10000);
      const transitioned = applyDriftToPaths(paths, path => path.target === issuer.name || path.connector_id === `issuer:${issuer.name}`);
      for (const path of transitioned) this.coverageTransition(p.tenant_id, path, 'UNKNOWN', `connector-drift:${key_id}`, now);
      this.store.audit(p.tenant_id, 'CONNECTOR_DRIFT', p.subject_id, key_id, { changes: result.changes, configuration_digest: result.configuration_digest, coverage_paths_staled: transitioned.length }, now);
      if (transitioned.length) this.store.audit(p.tenant_id, 'COVERAGE_STALED', p.subject_id, key_id, { paths: transitioned.map(x => x.path_id) }, now);
      return { ...result, coverage_paths_staled: transitioned.length };
    });
  }
  approvalChallenge(p, id) {
    this.authorize(p, ['approver', 'custodian']); const r = this.store.must(p.tenant_id, 'capsule', id); this.ensureMutable(r);
    const now = this.clock(), key = Object.entries(this.identities(p.tenant_id)).find(([, v]) => v.subject_id === p.subject_id);
    // Device quarantine applies on the approval plane too (runtime-audit F-10).
    this.assertHealthy(p.tenant_id, p.subject_id, this.identity(p).device_id, now);
    return { tenant_id: p.tenant_id, capsule_id: id, capsule_digest: r.capsule_digest, evidence_graph_digest: this.graph(p.tenant_id, r).digest, policy_digest: digest(this.policy(p.tenant_id)), signer_id: key[0], approved_at: now, expires_at: Math.min(now + 300000, r.capsule.expires_at) };
  }
  approve(p, envelope) {
    this.authorize(p, ['approver', 'custodian']);
    return this.transaction(p, now => {
      const identity = this.identity(p), capsuleId = verifySigned(envelope, this.identities(p.tenant_id), 'action-approval').capsule_id, accepted = this.approveInner(p, capsuleId, envelope, now);
      return { accepted: true, software_key: !identity.hardware_backed, approvals: accepted.approvals };
    });
  }
  evaluation(t, record, now, policy = this.policy(t)) {
    const graph = this.graph(t, record), identities = this.identities(t);
    if (record.capsule.action.type === 'policy.change') {
      const candidateDigest = digest(record.capsule.requested_state.policy);
      // Simulation freshness (policy-audit F11): 'reviewed' means reviewed
      // RECENTLY — a simulation older than an hour cannot authorise a
      // constitution change.
      const reviewed = this.store.list(t, 'simulation', 500).some(s => s.candidate_digest === candidateDigest && s.baseline_digest === digest(this.policy(t)) && s.time_basis > now - 3600000);
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
        // A composite may only wrap leaf actions — a nested composite would
        // dispatch as a generic mutation and leave live, re-spendable
        // grandchild certificates behind (w7-seam F6).
        if (child.capsule.action.type === 'action.composite') { problems.push({ code: 'CHILD_TYPE', child: childId }); continue; }
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
      this.assertHealthy(p.tenant_id, record.capsule.actor.subject_id, record.capsule.actor.device_id, now);
      this.assertFreshSnapshot(p.tenant_id, record.capsule);
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
      this.assertFreshSnapshot(t, r.capsule);
      const decision = this.evaluation(t, r, now), policy = this.policy(t);
      requireThat(decision.decision === 'ALLOW', 'INV-412-EVIDENCE', 'Only ALLOW may receive an execution certificate', 412, decision);
      this.assertHealthy(t, r.capsule.actor.subject_id, r.capsule.actor.device_id, now);
      const suite = this.vault.entry(this.keys(t).execution.key_id).suite ?? 'Ed25519';
      requireThat(policy.algorithms.allowed_suites.includes(suite), 'INV-451-POLICY', 'Certificate suite is no longer approved by policy', 451);
      // The floor runs over still-valid approvals only — a lapsed approval
      // must not mint an already-dead certificate that wedges the capsule in
      // CERTIFIED (policy-audit F12).
      // A policy.change capsule binds the NEXT constitution, not the expiry
      // of the dead one — an expired constitution must still permit its own
      // succession or the tenant wedges permanently (w7-clock F2).
      const graph = this.graph(t, r), expiry = Math.min(now + policy.certificate_ttl_ms, r.capsule.expires_at, r.capsule.action.type === 'policy.change' ? Infinity : policy.expires_at, ...graph.items.map(e => e.payload.expires_at), ...r.approvals.filter(a => a.payload.expires_at > now).map(a => a.payload.expires_at));
      requireThat(expiry > now, 'INV-409-STATE', 'Certificate would be stillborn; re-approve the action', 409);
      const certificate_id = randomUUID();
      const payload = { certificate_id, tenant_id: t, capsule_id: id, capsule_digest: r.capsule_digest, evidence_graph_digest: graph.digest, policy_id: policy.policy_id, policy_version: policy.version, policy_digest: digest(policy), decision: 'ALLOW', constraints: { destination: r.capsule.destination, quantity: r.capsule.quantity, requested_digest: digest(r.capsule.requested_state), current_state: this.stateRef(r.capsule.current_state), exclusions: r.capsule.exclusions }, target_gate_id: this.config.gate_id, signer_set: decision.eligible_signers, nonce: r.capsule.nonce, issued_at: now, expires_at: expiry, single_use: true, suite, revocation_ref: `certificate:${certificate_id}` };
      requireThat(!this.revoked(t, 'key', this.keys(t).execution.key_id) && this.vault.has(this.keys(t).execution.key_id), 'INV-401-SIGNATURE', 'Execution key revoked', 401);
      const envelope = this.signExecution(t, payload, 'action-certificate');
      this.store.insert(t, 'certificate', payload.certificate_id, { envelope, consumed: false, status: 'CERTIFIED', issued_at: now }, now);
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
      const state = record.capsule.action.type === 'secret.use' ? this.target.secretState(t, record.capsule.requested_state.secret_id) : this.target.state(t, record.capsule.action.target_resource);
      requireThat(state.version === record.capsule.current_state.version && state.digest === record.capsule.current_state.digest, 'INV-409-STATE', 'Target state changed', 409);
      if (dryRun || this.policy(t).mode === 'shadow') {
        this.store.audit(t, 'EXECUTION_DRY_RUN', p.subject_id, cert.certificate_id, { no_mutation: true }, now);
        return { dry_run: true, no_mutation: true, certificate_id: cert.certificate_id };
      }
      // Rotation pre-flight runs at RESERVATION — before the certificate is
      // consumed and before the target journal writes. A certified rotation
      // that fails here keeps its cert live and the capsule CERTIFIED instead
      // of wedging EXECUTING after a committed journal (w7-seam F5).
      if (record.capsule.action.type === 'key.rotate') {
        const req = record.capsule.requested_state, entry = this.vault.keys.get(req.new_key_id);
        requireThat(entry && entry.pending && !entry.revoked && !this.revoked(t, 'key', req.new_key_id), 'INV-409-STATE', 'Rotation target is not a pending vault key', 409);
        requireThat(this.ownsVaultKey(t, req.new_key_id), 'INV-403-SCOPE', 'Vault key is not owned by this tenant', 403);
        requireThat(req.new_public_key === entry.public_key, 'INV-400-SCHEMA', 'new_public_key does not match the pending vault key');
        const offered = Array.isArray(entry.purpose) ? entry.purpose : [entry.purpose];
        requireThat(entry.purpose === 'any' || (this._keyPurposes[req.key_class] ?? []).every(x => offered.includes(x)), 'INV-403-SCOPE', 'Rotation key purpose does not cover the target class', 403);
        if (req.ceremony_id) {
          const ceremony = this.store.get(t, 'ceremony', req.ceremony_id);
          requireThat(ceremony && ceremony.status !== 'completed' && ceremony.valid_until > now && ceremony.purpose === 'key.rotate' && !ceremony.rotation_consumed, 'INV-409-STATE', 'key.rotate requires a live, unconsumed key.rotate ceremony', 409);
          requireThat(ceremony.rotation?.key_class === req.key_class && ceremony.rotation?.new_key_id === req.new_key_id, 'INV-403-SCOPE', 'Ceremony is not bound to this rotation', 403);
          requireThat(this.custodianQuorum(t, ceremony).live >= ceremony.threshold, 'INV-409-STATE', 'Ceremony lacks a live custodian quorum across failure domains', 409);
          // The ceremony is spent atomically with the reservation — a second
          // certified rotation cannot race past it into the journal.
          ceremony.rotation_consumed = record.capsule.capsule_id;
          this.store.put(t, 'ceremony', ceremony.ceremony_id, ceremony, now);
        }
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
      // A deterministic refusal is a FAILED outcome, honestly recorded — only
      // genuinely ambiguous failures (transport/unknown) are UNCERTAIN
      // (runtime-audit F-9).
      if (e instanceof InvariantError) return this.finish(p, cert, null, /^INV-5/.test(e.code ?? '') ? 'UNCERTAIN' : 'FAILED', e.code);
      return this.finish(p, cert, null, 'UNCERTAIN', 'TARGET_RESULT_UNCONFIRMED');
    }
    return this.finish(p, cert, raw, 'VERIFIED', 'TARGET_RECONCILED', { postRead: true });
  }
  executeComposite(p, cert, capsule, now, fault) {
    // Children execute in order under the SAME dispatch-time authority checks
    // as a standalone execute(): revocation, expiry, evidence/policy digests,
    // a live ALLOW re-evaluation, actor health and target-state freshness are
    // all re-verified per child (runtime-audit F-1). On failure the
    // already-executed children are compensated via their recorded prior
    // state — documented compensation, never a pretend rollback of
    // irreversible effects.
    const t = p.tenant_id;
    const children = capsule.requested_state.children;
    const executed = [], wedged = [];
    const bail = (reason) => {
      const compensations = [];
      // Compensation runs in reverse EXECUTION order; the executed array
      // itself must keep dispatch order for the signed ledger (M2).
      for (const done of [...executed].reverse()) compensations.push({ capsule_id: done.child.capsule.capsule_id, ...this.target.compensate(done.child.capsule, done.prior, this.clock()) });
      return this.finishComposite(p, cert, capsule, executed, 'COMPENSATED', reason, compensations, this.clock(), wedged);
    };
    for (const childId of children) {
      let child, childCert, childNow;
      try {
        this.store.tx(() => {
          // Per-child authority is evaluated against a FRESH clock reading,
          // not the parent reservation time — wall clock may have advanced
          // across earlier child dispatches (concurrency-audit M1).
          childNow = this.clock(); this.store.clock(childNow);
          child = this.store.must(t, 'capsule', childId);
          const childStored = this.store.must(t, 'certificate', child.certificate_id);
          childCert = childStored.envelope.payload;
          requireThat(!this.revoked(t, 'key', childStored.envelope.protected.key_id) && !this.revoked(t, 'certificate', childCert.certificate_id) && childCert.issued_at <= childNow && childCert.expires_at > childNow, 'INV-401-CERTIFICATE', 'Child certificate expired or revoked', 401);
          requireThat(!childStored.consumed && child.status === 'CERTIFIED', 'INV-409-REPLAY', 'Child certificate consumed or action cancelled', 409);
          requireThat(child.capsule_digest === childCert.capsule_digest && this.graph(t, child).digest === childCert.evidence_graph_digest && digest(this.policy(t)) === childCert.policy_digest, 'INV-409-STATE', 'Child action, evidence or policy changed', 409);
          requireThat(this.evaluation(t, child, childNow).decision === 'ALLOW', 'INV-412-EVIDENCE', 'Child execution predicates no longer hold', 412);
          this.assertHealthy(t, child.capsule.actor.subject_id, child.capsule.actor.device_id, childNow);
          const state = child.capsule.action.type === 'secret.use' ? this.target.secretState(t, child.capsule.requested_state.secret_id) : this.target.state(t, child.capsule.action.target_resource);
          requireThat(state.version === child.capsule.current_state.version && state.digest === child.capsule.current_state.digest, 'INV-409-STATE', 'Child target state changed', 409);
          childStored.consumed = true; childStored.status = 'EXECUTING'; childStored.transaction_id = childCert.certificate_id;
          child.status = 'EXECUTING';
          this.store.put(t, 'certificate', childCert.certificate_id, childStored, childNow); this.store.put(t, 'capsule', childId, child, childNow);
          this.store.audit(t, 'EXECUTION_RESERVED', p.subject_id, childCert.certificate_id, { capsule_digest: childCert.capsule_digest, composite_child_of: cert.certificate_id }, childNow);
        });
      } catch (e) { return bail(`CHILD_REVALIDATION_FAILED:${e.code ?? 'UNKNOWN'}`); }
      let raw, dispatchError = null;
      try { raw = this.target.execute(child.capsule, childCert.certificate_id, childNow, fault); }
      catch (e) { dispatchError = e; }
      if (dispatchError instanceof InvariantError) {
        // A deterministic refusal is a FAILED child outcome, honestly
        // recorded — same rule as a standalone execution (runtime-audit F-9).
        try { this.finish(p, childCert, null, 'FAILED', dispatchError.code ?? 'INV-500'); } catch { /* bail must proceed regardless */ }
        return bail(`CHILD_EXECUTION_FAILED:${dispatchError.code ?? 'UNKNOWN'}`);
      }
      if (dispatchError) {
        // The reservation committed but the dispatch did not conclude: the
        // child is honestly wedged (EXECUTING, reconcilable later) and the
        // parent outcome must name it rather than understate the loss (M2).
        wedged.push(childId);
        return bail(`CHILD_EXECUTION_FAILED:${dispatchError.code ?? 'UNKNOWN'}`);
      }
      // A child's reply earns VERIFIED only under the same response rules as
      // a standalone execution (runtime-audit F-2).
      if (!this._validateTargetResponse(child, childCert, raw, this.clock(), { postRead: true }).valid) {
        wedged.push(childId);
        return bail('CHILD_EXECUTION_FAILED:TARGET_RESPONSE_INVALID');
      }
      executed.push({ child, raw, prior: child.capsule.current_state.material_fields });
    }
    return this.finishComposite(p, cert, capsule, executed, 'VERIFIED', 'CHILDREN_VERIFIED', [], this.clock());
  }
  finishComposite(p, cert, capsule, executed, status, reason, compensations, execNow, wedged = []) {
    const post = [];
    const envelope = this.transaction(p, now => {
      const t = p.tenant_id, r = this.store.must(t, 'capsule', cert.capsule_id), stored = this.store.must(t, 'certificate', cert.certificate_id);
      const existing = this.store.get(t, 'outcome', cert.certificate_id);
      requireThat(!existing || !['VERIFIED', 'FAILED', 'COMPENSATED'].includes(existing.payload.status), 'INV-409-STATE', 'A terminal execution outcome cannot be overwritten', 409);
      for (const done of executed) {
        const childRecord = this.store.must(t, 'capsule', done.child.capsule.capsule_id), childStored = this.store.must(t, 'certificate', done.child.certificate_id);
        childRecord.status = status === 'VERIFIED' ? 'VERIFIED' : status === 'UNCERTAIN' ? 'UNCERTAIN' : 'COMPENSATED';
        childStored.consumed = true; childStored.status = childRecord.status;
        this.store.put(t, 'capsule', childRecord.capsule.capsule_id, childRecord, now);
        this.store.put(t, 'certificate', childStored.envelope.payload.certificate_id, childStored, now);
        // VERIFIED children take their declared post-effects — a composite
        // may not attest an effect that never happened (runtime-audit F-2).
        // An effect that refuses (budget denial, lapsed rotation
        // precondition) demotes the parent outcome too — the ledger must not
        // attest VERIFIED over a child that failed (w7-seam F6).
        if (status === 'VERIFIED') {
          const childExtras = this._applyVerifiedEffects(p, t, childRecord, childStored.envelope.payload, done.raw, now, post);
          if (childExtras?.gate_denied || childExtras?.rotation_precondition_lapsed) {
            status = 'FAILED'; reason = childExtras?.gate_denied?.code ?? 'ROTATION_PRECONDITION_LAPSED';
            childRecord.status = 'FAILED'; childStored.status = 'FAILED';
            this.store.put(t, 'capsule', childRecord.capsule.capsule_id, childRecord, now);
            this.store.put(t, 'certificate', childStored.envelope.payload.certificate_id, childStored, now);
          }
        }
      }
      const payload = { certificate_id: cert.certificate_id, capsule_digest: cert.capsule_digest, target_transaction_id: cert.certificate_id, observed_state_digest: digest({ children: executed.map(e => e.child.capsule.capsule_id), compensations }), status, reason, execution_time: execNow, reconciliation_evidence: digest(executed.map(e => e.raw)), simulation: true, output: null, composite: true, children: executed.map(e => e.child.capsule.capsule_id), wedged_children: wedged.length ? wedged : null, compensations, supersedes: existing ? digest(existing) : null };
      const envelope = this.signAudit(t, payload, 'outcome');
      this.store.put(t, 'outcome', cert.certificate_id, envelope, now); stored.status = status; r.status = status;
      this.store.put(t, 'certificate', cert.certificate_id, stored, now); this.store.put(t, 'capsule', cert.capsule_id, r, now);
      this.store.audit(t, 'EXECUTION_OUTCOME', p.subject_id, cert.certificate_id, { status, reason, outcome_digest: digest(envelope), composite: true, wedged_children: wedged.length ? wedged : null, supersedes: existing ? digest(existing) : null }, now);
      return envelope;
    });
    for (const fn of post) fn();
    return envelope;
  }
  // A target reply earns VERIFIED only if it is exactly the authorised
  // request applied to the prior state — shape, digests, timing and the
  // simulation flag all checked. Shared by finish() and composite children.
  _validateTargetResponse(r, cert, raw, now, { postRead = false } = {}) {
    const responseKeys = ['target_transaction_id', 'capsule_digest', 'authorised_requested_digest', 'observed_state_digest', 'observed_state', 'output', 'status', 'execution_time', 'simulation'];
    let responseShape = raw && typeof raw === 'object' && !Array.isArray(raw) && Object.keys(raw).length === responseKeys.length && responseKeys.every(key => Object.hasOwn(raw, key)) && raw.observed_state && typeof raw.observed_state === 'object' && !Array.isArray(raw.observed_state) && (raw.output === null || Array.isArray(raw.output));
    if (responseShape) {
      try { canonical(raw); } catch (error) { if (error instanceof InvariantError) responseShape = false; else throw error; }
    }
    let expected = null;
    if (responseShape && Number.isSafeInteger(raw.execution_time)) {
      const c = r.capsule;
      expected = { ...c.current_state.material_fields, ...c.requested_state };
      if (c.action.type === 'finance.bank.change') expected = { ...expected, first_payment_done: false, payment_eligible_at: now + 60000 };
      if (c.action.type === 'finance.payment.first') expected = { ...c.current_state.material_fields, first_payment_done: true, payment: c.requested_state, payment_transaction: cert.certificate_id };
      if (c.action.type === 'data.export') expected = c.current_state.material_fields;
      if (['identity.mfa.reset', 'identity.authenticator.enroll', 'identity.account.recover'].includes(c.action.type)) expected = { ...expected, last_identity_operation: { type: c.action.type, at: now, transaction: cert.certificate_id } };
      if (c.action.type === 'key.rotate') expected = { ...expected, rotated_at: now, rotation_transaction: cert.certificate_id };
      if (c.action.type === 'secret.use') expected = { ...c.current_state.material_fields, last_use: { secret_id: c.requested_state.secret_id, operation: c.requested_state.operation, workload_id: c.requested_state.workload_id, at: now, transaction: cert.certificate_id } };
      if (c.action.type === 'backup.delete') expected = { ...c.current_state.material_fields, deleted_backups: [...(c.current_state.material_fields.deleted_backups ?? []), { backup_id: c.requested_state.backup_id, at: now, transaction: cert.certificate_id }] };
      if (c.action.type === 'identity.jit.grant') expected = { ...expected };
    }
    let outputValid = r.capsule.action.type !== 'data.export' && raw?.output === null;
    let exportRows = null;
    if (responseShape && Array.isArray(raw.output) && r.capsule.action.type === 'data.export') {
      const requested = r.capsule.requested_state;
      const sourceRows = r.capsule.current_state.material_fields.rows;
      if (Array.isArray(sourceRows)) {
        const exactOutput = sourceRows.filter(row => requested.row_ids.includes(row.id)).map(row => Object.fromEntries(requested.columns.map(column => [column, row[column] ?? null])));
        outputValid = exactOutput.length === requested.row_ids.length && digest(raw.output) === digest(exactOutput);
        if (outputValid) exportRows = raw.output;
      }
    }
    // Post-execution re-read: a connector can claim the authorised state
    // without ever writing it — only a fresh read of the decisive record
    // distinguishes "applied" from "reported" (w5 F-6). Reconcile replays
    // historical outcomes where the state has since moved on, so this check
    // runs only on the live dispatch path.
    let postStateOk = true;
    if (postRead && responseShape && expected) {
      const ref = r.capsule.action.type === 'secret.use' ? this.target.secretState(r.capsule.tenant_id, r.capsule.requested_state.secret_id) : this.target.state(r.capsule.tenant_id, r.capsule.action.target_resource);
      postStateOk = Boolean(ref && digest(ref.material_fields) === raw.observed_state_digest && (r.capsule.action.type === 'data.export' ? ref.version === r.capsule.current_state.version : ref.version === r.capsule.current_state.version + 1));
    }
    const valid = Boolean(responseShape && expected && outputValid && postStateOk && raw.execution_time >= cert.issued_at && raw.execution_time <= now && raw.execution_time < cert.expires_at && digest(expected) === raw.observed_state_digest && raw.status === 'VERIFIED' && raw.target_transaction_id === cert.certificate_id && raw.capsule_digest === cert.capsule_digest && raw.authorised_requested_digest === digest(r.capsule.requested_state) && raw.observed_state_digest === digest(raw.observed_state) && raw.simulation === true);
    return { valid, expected, exportRows };
  }
  // Post-effects a VERIFIED outcome declares. Store writes happen in the
  // outcome tx; non-transactional side effects (vault key state, target grant
  // table) are deferred into `post` and run after commit, with ledger records
  // ('key-rotation' / 'jit-grant') written in-tx so _reconcileLedger heals a
  // crash between commit and apply (store-audit MED-6).
  _applyVerifiedEffects(p, t, r, cert, raw, now, post) {
    const type = r.capsule.action.type;
    if (type === 'policy.change') {
      const next = r.capsule.requested_state.policy, active = this.policy(t);
      requireThat(next.version === active.version + 1, 'INV-409-STATE', 'Policy activation sequence changed', 409);
      // Expiry and staged min-delay are admission-time checks in evaluation();
      // a candidate that cannot legally activate never reaches CERTIFIED.
      if (next.not_before > now) {
        requireThat(!this.store.get(t, 'policy', 'staged'), 'INV-409-CONFLICT', 'A staged policy is already pending', 409);
        this.store.put(t, 'policy', 'staged', { policy: next, activate_at: next.not_before, staged_at: now, capsule_id: r.capsule.capsule_id }, now);
        this.store.audit(t, 'POLICY_STAGED', p.subject_id, next.policy_id, { activate_at: next.not_before, version: next.version }, now);
      } else {
        this.store.put(t, 'policy', 'active', next, now);
        this.store.put(t, 'policy-history', `v${next.version}`, { activated_at: now, digest: digest(next), staged: false, emergency: next.emergency_of !== undefined }, now);
        if (next.emergency_of !== undefined) this.store.audit(t, 'EMERGENCY_POLICY_ACTIVATED', p.subject_id, next.policy_id, { version: next.version, base: next.emergency_of }, now);
      }
    }
    if (type === 'key.rotate') {
      // The pending vault key is activated only after the rotation capsule is
      // VERIFIED; the retiring key stays verifiable but can no longer sign.
      const req = r.capsule.requested_state;
      // Rotation activates only a genuinely pending, unrevoked vault key
      // whose purpose covers the class it will serve — everything is checked
      // inside the transaction so the vault can never diverge from a
      // committed VERIFIED outcome (w6 F2/F4).
      const entry = this.vault.keys.get(req.new_key_id);
      // Activation preconditions are re-verified here — a lapse between
      // reservation and outcome (e.g. a revocation landing mid-flight) must
      // become an honest FAILED outcome, not a thrown wedge after the target
      // journal already committed (w7-seam F5).
      const needed = this._keyPurposes[req.key_class] ?? [];
      const offered = entry && (Array.isArray(entry.purpose) ? entry.purpose : [entry.purpose]);
      let preconditions = entry && entry.pending && !entry.revoked && !this.revoked(t, 'key', req.new_key_id)
        && this.ownsVaultKey(t, req.new_key_id)
        && req.new_public_key === entry.public_key
        && (entry.purpose === 'any' || needed.every(x => offered.includes(x)));
      if (req.ceremony_id) {
        const ceremony = this.store.get(t, 'ceremony', req.ceremony_id);
        // The ceremony was consumed atomically at reservation — this may
        // only be consumed by THIS capsule and stay bound to this rotation.
        preconditions = preconditions && ceremony && ceremony.purpose === 'key.rotate' && ceremony.rotation_consumed === r.capsule.capsule_id
          && ceremony.rotation?.key_class === req.key_class && ceremony.rotation?.new_key_id === req.new_key_id;
      }
      if (!preconditions) return { rotation_precondition_lapsed: true };
      const klass = req.key_class, previous = this.keys(t)[klass];
      // Activation, repointing and retiring run inside the transaction; only
      // the vault file write stays post-commit. The rotation's own outcome is
      // signed by the retiring key — it was the authoritative signer when the
      // action verified — then its private half is revoked post-commit (w6
      // F2/F11).
      this.vault.activate(req.new_key_id);
      this.tenant(t).keys[klass] = { key_id: req.new_key_id, public_key: req.new_public_key };
      this.tenant(t).keys.retired = [...(this.tenant(t).keys.retired ?? []), { key_class: klass, key_id: previous.key_id, public_key: previous.public_key, retired_at: now }];
      // revoke_old is the operator's declared choice — the ledger attests
      // what was actually done, never a hardcoded true (w7-seam F7).
      const revokeOld = req.revoke_old !== false;
      this.store.put(t, 'key-rotation', req.new_key_id, { new_key_id: req.new_key_id, new_public_key: req.new_public_key, key_class: klass, previous_key_id: previous.key_id, previous_public_key: previous.public_key, revoke_old: revokeOld, rotated_at: now, capsule_id: r.capsule.capsule_id }, now);
      this.store.audit(t, 'KEY_ROTATED', p.subject_id, req.new_key_id, { key_class: klass, previous_key_id: previous.key_id, ceremony_id: req.ceremony_id, revoke_old: revokeOld }, now);
      post.push(() => { if (revokeOld) this.vault.revoke(previous.key_id); this.persistVault(); });
      // Only an audit-class rotation changes the outcome signer; other
      // classes leave the audit key untouched.
      if (klass === 'audit') return { outcome_key_id: previous.key_id };
      return null;
    }
    if (type === 'identity.jit.grant') {
      const req = r.capsule.requested_state;
      const grant = { grant_id: `jit-${cert.certificate_id}`, subject_id: req.subject_id, resources: req.resources, actions: req.actions, destinations: req.destinations, columns: req.columns, row_ids: req.row_ids, roles: req.roles ?? [], expires_at: now + req.ttl_ms, issued_at: now, issued_by: `action:${r.capsule.capsule_id}`, reason: req.reason, revoked: false };
      this.store.put(t, 'jit-grant', grant.grant_id, { grant }, now);
      this.store.audit(t, 'JIT_GRANT_ISSUED', p.subject_id, req.subject_id, { grant_id: grant.grant_id, grant_digest: digest(req), expires_at: grant.expires_at }, now);
      post.push(() => this.target.grant(t, grant.grant_id, grant));
    }
    if (type === 'data.export') {
      // DAT-009/011: a certified export is a first-class data access — it
      // writes the same touch rows, budget charge and attribution watermarks
      // as a capability read, so the reconstruction ledger sees every egress
      // channel (runtime-audit F-7).
      const requested = r.capsule.requested_state, subject = r.capsule.actor.subject_id;
      const dataset = this.target.state(t, requested.dataset).material_fields;
      // The export channel is gated by the same cumulative reconstruction
      // budget as capability reads — an export may not sail past a coverage
      // denial (w6-tenancy F5). Touch rows stay committed for the attempt.
      const recon = reconstructionCheck(this.store.db, this.target.db, { tenant: t, subject, dataset: requested.dataset, rows: requested.row_ids, columns: requested.columns, now, policy: this.policy(t).runtime.reconstruction });
      if (!recon.allowed) return { gate_denied: { code: 'INV-429-BUDGET', detail: { row_count: recon.row_count, column_count: recon.column_count, coverage_percent: recon.coverage_percent } } };
      const weight = this.policy(t).runtime.sensitivity_weights[dataset.classification] ?? 1;
      const cost = requested.row_ids.length * requested.columns.length * weight;
      this.store.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?)').run(t, subject, requested.dataset, now, cost, `cert:${cert.certificate_id}`, cert.certificate_id);
      let tenantWatermarkKey;
      try { tenantWatermarkKey = this.dataKey(t, 'watermark'); } catch { tenantWatermarkKey = null; }
      return { watermarks: watermark(raw.output ?? [], { tenant: t, dataset: requested.dataset, subject, requestId: cert.certificate_id, tenantWatermarkKey: tenantWatermarkKey ?? this.dataKey(t, 'encryption') }).watermarks };
    }
    return null;
  }
  finish(p, cert, raw, status, reason, { postRead = false } = {}) {
    const post = [];
    const envelope = this.transaction(p, now => {
      const t = p.tenant_id, r = this.store.must(t, 'capsule', cert.capsule_id), stored = this.store.must(t, 'certificate', cert.certificate_id);
      // Terminal outcomes are immutable — a VERIFIED/FAILED result can never
      // be overwritten by a second finish (only UNCERTAIN may resolve later).
      const existing = this.store.get(t, 'outcome', cert.certificate_id);
      requireThat(!existing || !['VERIFIED', 'FAILED', 'COMPENSATED'].includes(existing.payload.status), 'INV-409-STATE', 'A terminal execution outcome cannot be overwritten', 409);
      const { valid } = this._validateTargetResponse(r, cert, raw, now, { postRead });
      if (status === 'VERIFIED' && !valid) { status = 'UNCERTAIN'; reason = 'TARGET_RESPONSE_INVALID'; }
      const extras = valid ? this._applyVerifiedEffects(p, t, r, cert, raw, now, post) : null;
      if (extras?.gate_denied) { status = 'FAILED'; reason = extras.gate_denied.code; }
      if (extras?.rotation_precondition_lapsed) { status = 'FAILED'; reason = 'ROTATION_PRECONDITION_LAPSED'; }
      // H1: revocation cannot abort a committed reservation — it stops NEW
      // reservations. A revocation that landed between reservation and this
      // finish is recorded and flagged rather than hidden, so the ledger
      // shows the race instead of pretending it never happened.
      const revokedMidFlight = this.revoked(t, 'certificate', cert.certificate_id) || this.revoked(t, 'key', stored.envelope.protected.key_id);
      const payload = { certificate_id: cert.certificate_id, capsule_digest: cert.capsule_digest, target_transaction_id: cert.certificate_id, observed_state_digest: valid ? raw.observed_state_digest : null, status, reason, execution_time: valid ? raw.execution_time : now, reconciliation_evidence: valid ? digest(raw) : null, simulation: true, output: valid && !extras?.gate_denied ? raw.output : null, watermarks: extras?.watermarks ?? null, gate_denied: extras?.gate_denied?.detail ?? null, revoked_post_reservation: revokedMidFlight || null, supersedes: existing ? digest(existing) : null };
      const envelope = this.signAudit(t, payload, 'outcome', extras?.outcome_key_id ?? null);
      this.store.put(t, 'outcome', cert.certificate_id, envelope, now); stored.status = status; r.status = status;
      this.store.put(t, 'certificate', cert.certificate_id, stored, now); this.store.put(t, 'capsule', cert.capsule_id, r, now);
      this.store.audit(t, 'EXECUTION_OUTCOME', p.subject_id, cert.certificate_id, { status, reason, outcome_digest: digest(envelope), supersedes: existing ? digest(existing) : null, revoked_post_reservation: revokedMidFlight || null }, now);
      if (revokedMidFlight) this.store.audit(t, 'EXECUTION_COMPLETED_POST_REVOCATION', p.subject_id, cert.certificate_id, { status, outcome_digest: digest(envelope) }, now);
      return envelope;
    });
    for (const fn of post) fn();
    return envelope;
  }
  reconcile(p, id) {
    this.authorize(p, ['operator', 'security', 'policy_admin']); const t = p.tenant_id, stored = this.store.must(t, 'certificate', id);
    const current = this.store.get(t, 'outcome', id);
    // COMPENSATED is terminal too — reconcile returns any settled outcome
    // instead of throwing where VERIFIED/FAILED simply answer (w7-seam F8).
    if (current && ['VERIFIED', 'FAILED', 'COMPENSATED'].includes(current.payload.status)) return current;
    requireThat(stored.consumed, 'INV-409-STATE', 'Execution has not started', 409);
    const cert = stored.envelope.payload, raw = this.target.outcome(t, id);
    const record = this.store.must(t, 'capsule', cert.capsule_id);
    if (record.capsule.action.type === 'action.composite') {
      // A wedged composite reconciles per-child, never as a fake standalone:
      // children whose target journal wrote are recorded executed, the rest
      // are wedged — and they keep their own live certificates so a fresh
      // composite can still spend them (w7-seam F9).
      const executed = [], wedged = [];
      for (const childId of record.capsule.requested_state.children ?? []) {
        const childCapsule = this.store.get(t, 'capsule', childId);
        const childCert = childCapsule?.certificate_id ? this.store.get(t, 'certificate', childCapsule.certificate_id) : null;
        const childRaw = childCert ? this.target.outcome(t, childCert.envelope.payload.certificate_id) : null;
        if (childCapsule && childCert && childRaw) executed.push({ child: { ...childCapsule, certificate_id: childCert.envelope.payload.certificate_id }, raw: childRaw, prior: childCapsule.capsule.current_state.material_fields });
        else wedged.push(childId);
      }
      if (raw) return this.finishComposite(p, cert, record.capsule, executed, 'VERIFIED', 'RECONCILED_FROM_TARGET_JOURNAL', [], this.clock(), wedged);
      return this.finishComposite(p, cert, record.capsule, executed, 'UNCERTAIN', 'COMPOSITE_INTERRUPTED_CHILDREN_ATTEMPTED', [], this.clock(), wedged);
    }
    return this.finish(p, cert, raw, raw ? 'VERIFIED' : 'UNCERTAIN', raw ? 'RECONCILED_FROM_TARGET_JOURNAL' : 'NO_TARGET_CONFIRMATION_DO_NOT_RETRY');
  }
  cancel(p, id) {
    this.authorize(p, ['operator', 'security', 'policy_admin']);
    return this.transaction(p, now => {
      const r = this.store.must(p.tenant_id, 'capsule', id); requireThat(!['EXECUTING', 'VERIFIED', 'UNCERTAIN', 'FAILED', 'COMPENSATED'].includes(r.status), 'INV-409-STATE', 'Dispatched action cannot be cancelled; reconcile first', 409);
      this.assertHealthy(p.tenant_id, p.subject_id, this.identity(p).device_id, now);
      r.status = 'CANCELLED'; this.store.put(p.tenant_id, 'capsule', id, r, now);
      this.store.audit(p.tenant_id, 'ACTION_CANCELLED', p.subject_id, id, { certificate_id: r.certificate_id }, now); return { status: r.status };
    });
  }
  revoke(p, input) {
    this.authorize(p, ['security']); fields(input, ['kind', 'id', 'reason'], ['remediation_service']); text(input.reason, 'revocation reason'); identifier(input.id);
    // NET-005/006: quarantine remediation may only invoke services named in
    // the policy allowlist — the dispatch itself stays an external system,
    // the contract enforced here is that arbitrary services cannot be asked.
    if (input.remediation_service !== undefined) {
      text(input.remediation_service, 'remediation service');
      requireThat(this.policy(p.tenant_id).runtime.remediation_services.includes(input.remediation_service), 'INV-403-SCOPE', 'Remediation service is not in the policy allowlist', 403);
    }
    requireThat(['certificate', 'evidence', 'issuer', 'key', 'subject', 'device', 'capability', 'grant', 'token'].includes(input.kind), 'INV-400-SCHEMA', 'Unsupported revocation type');
    return this.transaction(p, now => {
      // Revocation must name a live authority — revoking a nonexistent id
      // would be silent record pollution.
      const t = p.tenant_id;
      const exists = {
        certificate: () => this.store.get(t, 'certificate', input.id),
        evidence: () => this.store.get(t, 'evidence', input.id),
        issuer: () => this.tenant(t).issuers[input.id],
        // A revocable key is a vault entry, an identity, an issuer — or a
        // perception component signing key, which must also be revocable
        // (w6-perception P-2). vault.entry throws on unknown ids; probe the
        // map directly instead.
        // A vault entry resolves only when it belongs to this tenant —
        // probing another tenant's key id is not an existence oracle.
        // Legacy untagged entries resolve through the tenant's bindings
        // (w6-fix F5).
        // (w6-tenancy F4).
        key: () => (this.ownsVaultKey(t, input.id) ? this.vault.keys.get(input.id) : null) || this.identities(t)[input.id] || this.tenant(t).issuers[input.id] || Object.values(this.perceptionComponents[t] ?? {}).find(c => c.signing.key_id === input.id),
        subject: () => Object.values(this.tenant(t).identities).some(i => i.subject_id === input.id),
        device: () => Object.values(this.tenant(t).identities).some(i => i.device_id === input.id),
        capability: () => this.store.get(t, 'capability', input.id),
        grant: () => this.target.allGrants(t).some(g => g.grant_id === input.id),
        token: () => this.tenant(t).auth[input.id],
      }[input.kind];
      requireThat(exists?.(), 'INV-404-NOT-FOUND', `No live ${input.kind} authority with that id`, 404);
      if (input.kind === 'grant') this.target.revokeGrant(t, input.id);
      const payload = { ...clone(input), tenant_id: t, revoked_at: now, actor: p.subject_id, propagation: 'local-synchronous', remote_propagation: 'NOT_IMPLEMENTED' };
      // Sign the revocation envelope BEFORE the record lands — the signing
      // key is still valid at signature time, and revoking the audit key
      // itself would otherwise deadlock inside its own record write
      // (w6-fix F4).
      const envelope = this.signAudit(p.tenant_id, payload, 'revocation');
      this.store.put(t, 'revocation', `${input.kind}:${input.id}`, payload, now);
      if (input.remediation_service) this.store.audit(t, 'REMEDIATION_REQUESTED', p.subject_id, `${input.kind}:${input.id}`, { service: input.remediation_service, dispatched: false, channel: 'external-system-not-integrated' }, now);
      this.store.audit(t, 'AUTHORITY_REVOKED', p.subject_id, `${input.kind}:${input.id}`, { reason_digest: digest(input.reason) }, now);
      return envelope;
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
  // Every coverage state change passes through here so the coverage-event
  // history and owner tasks can never disagree with the stored path.
  coverageTransition(tenant, path, to, cause, now) {
    path.status = to; if (to === 'UNKNOWN') path.evidence_at = null;
    this.store.put(tenant, 'coverage', path.path_id, path, now);
    this.store.insert(tenant, 'coverage-event', `${path.path_id}:${now}:${cause}`, { type: 'transitioned', path_id: path.path_id, to, evidence_at: path.evidence_at, at: now, cause }, now);
    // Owner tasks exist only for degraded/unprotected states — a promotion
    // is a resolution, not a new obligation. UNCOVERED means the path is
    // declared unprotected: the owner must close it or enforce it.
    if (to === 'UNKNOWN') this.store.insert(tenant, 'coverage-task', `${cause}:${path.path_id}`, { path_id: path.path_id, owner: path.owner, cause, opened_at: now, status: 'open', required_action: 'attach independently executed technical validation evidence' }, now);
    if (to === 'UNCOVERED') this.store.insert(tenant, 'coverage-task', `${cause}:${path.path_id}`, { path_id: path.path_id, owner: path.owner, cause, opened_at: now, status: 'open', required_action: 'close this declared-unprotected path or bring it under enforced coverage' }, now);
  }
  coverage(p) {
    this.authorize(p, ['operator', 'approver', 'custodian', 'security', 'auditor', 'policy_admin']);
    return this.transaction(p, now => {
      // Evidence-expiry is a real transition, not a computed convenience: a
      // MONITORED path that ages out is recorded UNKNOWN with its coverage
      // event and owner task, exactly like a drift-driven drop (w8-ledger
      // COV-005). Idempotent — stored UNKNOWN paths never re-fire.
      for (const path of this.store.list(p.tenant_id, 'coverage', 10000))
        if ((path.status === 'MONITORED' || path.status === 'ENFORCED') && effectiveStatus(path, now) === 'UNKNOWN')
          this.coverageTransition(p.tenant_id, path, 'UNKNOWN', 'evidence-expired', now);
      return coverageManifest(p.tenant_id, this.store.list(p.tenant_id, 'coverage'), now, payload => this.signAudit(p.tenant_id, payload, 'coverage'));
    });
  }
  // COV-009: what the coverage record showed at an arbitrary past instant —
  // answered from the coverage-event log, not the current mutable state.
  coverageAt(p, at) {
    this.authorize(p, ['operator', 'approver', 'custodian', 'security', 'auditor', 'policy_admin']);
    const atTime = integer(Number(at), 'at', 1, 1e14);
    return { at: atTime, paths: coverageAt(this.store.list(p.tenant_id, 'coverage-event', 100000), atTime) };
  }
  declareCoverage(p, input) {
    this.authorize(p, ['security']); return this.transaction(p, now => {
      const path = declarePath(input, now); this.store.put(p.tenant_id, 'coverage', path.path_id, path, now);
      this.store.insert(p.tenant_id, 'coverage-event', `${path.path_id}:${now}:declared`, { type: 'declared', path_id: path.path_id, path, at: now }, now);
      if (path.status === 'UNKNOWN') this.store.insert(p.tenant_id, 'coverage-task', `declared-unknown:${path.path_id}`, { path_id: path.path_id, owner: path.owner, cause: 'declared-unknown', opened_at: now, status: 'open', required_action: 'attach independently executed technical validation evidence' }, now);
      if (path.status === 'UNCOVERED') this.store.insert(p.tenant_id, 'coverage-task', `declared-uncovered:${path.path_id}`, { path_id: path.path_id, owner: path.owner, cause: 'declared-uncovered', opened_at: now, status: 'open', required_action: 'close this declared-unprotected path or bring it under enforced coverage' }, now);
      this.store.audit(p.tenant_id, 'COVERAGE_DECLARED', p.subject_id, path.path_id, { digest: digest(path), status: path.status }, now); return path;
    });
  }
  // COV-010: technical validation attaches an independently executed bypass
  // test result to a path — the only way a path can claim stronger than
  // MONITORED is a verified evidence envelope, never a checkbox.
  technicalValidation(p, path_id, envelope) {
    this.authorize(p, ['security']); return this.transaction(p, now => {
      const path = this.store.must(p.tenant_id, 'coverage', identifier(path_id));
      // The evidence schema is reused; its capsule_digest field binds the
      // validation to this path (digest(path)) rather than to an action.
      const payload = this.verifyEvidenceEnvelope(p.tenant_id, envelope);
      // Same trust bar as attachEvidence: revoked signer, drifted connector,
      // out-of-kind envelope or a non-supporting outcome cannot promote a
      // coverage path (w5 F-6).
      requireThat(!this.revoked(p.tenant_id, 'issuer', envelope.protected.key_id) && !this.revoked(p.tenant_id, 'key', envelope.protected.key_id) && !this.revoked(p.tenant_id, 'evidence', payload.evidence_id), 'INV-401-EVIDENCE', 'Validation source revoked', 401);
      requireThat(!this.store.get(p.tenant_id, 'issuer-drift', envelope.protected.key_id), 'INV-403-QUARANTINE', 'Issuer connector drifted — validation suspended pending revalidation', 403);
      const issuer = this.tenant(p.tenant_id).issuers[envelope.protected.key_id];
      requireThat(issuer.kinds.includes(payload.kind), 'INV-403-SCOPE', 'Issuer is not trusted for this evidence kind', 403);
      requireThat(!payload.issuer_version || payload.issuer_version === issuer.version, 'INV-403-SCOPE', 'Issuer version drifted from registration', 403);
      // The same trust floor evaluatePolicy applies to action evidence:
      // advisory opinions, sub-threshold confidence and communication-channel
      // issuers can never promote a coverage path — and the kind is pinned so
      // a generic attestation cannot masquerade as a bypass test (w7-seam F1).
      requireThat(payload.kind === 'technical_validation', 'INV-403-SCOPE', 'Validation evidence must be technical_validation kind', 403);
      requireThat(!payload.advisory && (payload.confidence ?? 0) >= 90, 'INV-400-SCHEMA', 'Advisory or low-confidence evidence cannot validate a path', 400);
      requireThat(issuer.channel !== 'communication', 'INV-403-SCOPE', 'Communication-channel issuers cannot technically validate a path', 403);
      requireThat(payload.claim === 'supports', 'INV-400-SCHEMA', 'Technical validation requires a supporting outcome', 400);
      requireThat(payload.capsule_digest === digest(path), 'INV-400-SCHEMA', 'Validation evidence must bind this path');
      // The cited evidence_id must resolve on the ledger — a validation can
      // never reference an envelope that exists nowhere (w7-seam F1).
      const priorEvidence = this.store.get(p.tenant_id, 'evidence', payload.evidence_id);
      if (priorEvidence) requireThat(digest(priorEvidence.envelope) === digest(envelope), 'INV-409-CONFLICT', 'Evidence id already bound to different material', 409);
      else this.store.insert(p.tenant_id, 'evidence', payload.evidence_id, { payload: clone(payload), envelope: clone(envelope), legal_hold: false }, now);
      path.technical_validation = { evidence_id: payload.evidence_id, issuer: envelope.protected.key_id, at: now, outcome: payload.claim };
      // Re-validation refreshes the evidence window — the documented way to
      // keep a path MONITORED must actually extend coverage (w7-seam F10).
      path.evidence_at = now;
      if (path.status === 'UNKNOWN') this.coverageTransition(p.tenant_id, path, 'MONITORED', 'technical-validation', now);
      else this.store.put(p.tenant_id, 'coverage', path.path_id, path, now);
      this.store.insert(p.tenant_id, 'coverage-event', `${path.path_id}:${now}:validation`, { type: 'technical_validation', path_id: path.path_id, validation: path.technical_validation, at: now }, now);
      this.store.remove(p.tenant_id, 'coverage-task', `declared-unknown:${path.path_id}`);
      this.store.remove(p.tenant_id, 'coverage-task', `declared-uncovered:${path.path_id}`);
      this.store.audit(p.tenant_id, 'COVERAGE_TECHNICAL_VALIDATION', p.subject_id, path.path_id, { issuer: envelope.protected.key_id }, now);
      return path;
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
  verifyAuditProof(tenant, proof, pinned = null) {
    // Stateless helper for the offline verifier and tests. When `pinned`
    // ({root, size} from a previously trusted checkpoint) is supplied, the
    // claimed tree is bound to it — an RFC-6962 inclusion proof is only
    // meaningful relative to a pinned (root, size).
    requireThat(proof && typeof proof === 'object' && !Array.isArray(proof), 'INV-400-SCHEMA', 'Invalid proof', 400);
    if (pinned) requireThat(pinned.root === proof.root && pinned.size === proof.size, 'INV-409-FORK', 'Proof does not match the pinned checkpoint', 409);
    return verifyInclusion(proof.leaf_hash, proof.sequence - 1, proof.size, proof.path, proof.root);
  }
  exportAudit(p, purpose) {
    this.authorize(p, ['auditor', 'security']); text(purpose, 'audit export purpose', 256);
    return this.transaction(p, now => {
      this.store.audit(p.tenant_id, 'AUDIT_ACCESSED', p.subject_id, 'tenant-log', { purpose_digest: digest(purpose) }, now);
      return this.store.auditExport(p.tenant_id, now);
    });
  }
  // AUD-010: least-privilege audit views. An operational principal (operator
  // without an assessor role) receives only the digest level of every entry —
  // sequence, chain hash, action type, actor, timestamp — not the signed
  // payload body. Auditors and security receive the full signed envelope:
  // independent verification IS the auditor's necessary information. Merkle
  // integrity checks still work on the scoped view — the hash column is the
  // payload digest.
  auditDigestOnly(p) {
    const identity = this.identity(p);
    const roles = this.grantsFor(p.tenant_id, p.subject_id, this.clock()).roles ?? identity.roles;
    return !roles.some(r => ['auditor', 'security', 'policy_admin'].includes(r));
  }
  auditEntryScoped(entry) {
    const payload = entry.envelope?.payload ?? {};
    return { sequence: entry.sequence, hash: entry.hash, payload_digest: entry.hash, type: payload.type ?? null, actor: payload.actor ?? null, reference: payload.reference ?? null, at: payload.time ?? null, digest_only: true };
  }
  auditPageScoped(p, options = {}) {
    this.authorize(p, ['operator', 'security', 'auditor', 'policy_admin']);
    const page = this.store.auditPage(p.tenant_id, options);
    // AUD-010: named domain projections filter the verified page. Integrity
    // verification runs on the unfiltered page before projection.
    if (options.view !== undefined) {
      const PROJECTIONS = {
        finance: ['CAPSULE_PROPOSED', 'EVIDENCE_ATTACHED', 'EXACT_ACTION_APPROVED', 'BATCH_APPROVED', 'CERTIFICATE_ISSUED', 'EXECUTION_RESERVED', 'EXECUTION_OUTCOME', 'EXECUTION_DRY_RUN', 'ACTION_CANCELLED', 'EXECUTION_COMPLETED_POST_REVOCATION', 'POLICY_EVALUATED'],
        privacy: ['RETENTION_DELETED', 'RETENTION_HOLD_CHANGED', 'CAPABILITY_ISSUED', 'RUNTIME_ALLOWED', 'PERCEPTION_SESSION', 'PERCEPTION_RELEASE', 'PERCEPTION_FALLBACK', 'AUDIT_ACCESSED'],
        technical: ['CONFIG_DRIFT', 'CONFIG_REASSERTED', 'CONFIG_SNAPSHOT', 'CONNECTOR_DRIFT', 'COVERAGE_DECLARED', 'COVERAGE_STALED', 'COVERAGE_TECHNICAL_VALIDATION', 'CLOCK_RECOVERED', 'KEY_ROTATED', 'ROTATION_PREPARED', 'CEREMONY_PLANNED', 'CEREMONY_ACKNOWLEDGED', 'CEREMONY_SHARES_COMMITTED', 'CEREMONY_RECONSTRUCTED', 'EVIDENCE_ACQUISITION_FAILED', 'REMEDIATION_REQUESTED', 'JIT_GRANT_ISSUED', 'RECOVERY_NOTICE_ISSUED', 'POLICY_GENESIS', 'POLICY_STAGED', 'POLICY_SIMULATED', 'POLICY_SUPERSEDED', 'EMERGENCY_POLICY_ACTIVATED', 'AI_ADVISORY', 'SECURITY_OPERATION_REJECTED', 'AUTHORITY_REVOKED'],
      };
      requireThat(Object.hasOwn(PROJECTIONS, options.view), 'INV-400-SCHEMA', `Unknown audit projection ${options.view}`);
      const types = new Set(PROJECTIONS[options.view]);
      page.entries = page.entries.filter(e => types.has(e.envelope.payload.type));
    }
    if (this.auditDigestOnly(p)) page.entries = page.entries.map(e => this.auditEntryScoped(e));
    return page;
  }
  // UX-006: batch approval. Every capsule in the batch is individually
  // bound — each envelope must carry that capsule's own digests; a count or
  // set mismatch (hidden addition or omission) rejects the whole batch
  // atomically, and any single invalid approval aborts it.
  batchApprove(p, input) {
    this.authorize(p, ['approver', 'custodian']);
    fields(input, ['capsule_ids', 'signatures']);
    requireThat(Array.isArray(input.capsule_ids) && input.capsule_ids.length >= 2 && input.capsule_ids.length <= 32, 'INV-400-SCHEMA', 'Batch must contain 2-32 actions');
    requireThat(Array.isArray(input.signatures) && input.signatures.length === input.capsule_ids.length, 'INV-400-SCHEMA', 'Signature count must equal the declared action set');
    requireThat(new Set(input.capsule_ids).size === input.capsule_ids.length, 'INV-400-SCHEMA', 'Duplicate capsule in batch');
    for (const id of input.capsule_ids) identifier(id, 'capsule id');
    return this.transaction(p, now => {
      const accepted = [], constraints = [];
      for (const capsuleId of input.capsule_ids) {
        const record = this.store.must(p.tenant_id, 'capsule', capsuleId);
        const matched = input.signatures.filter(sig => sig?.payload?.capsule_id === capsuleId);
        requireThat(matched.length === 1, 'INV-400-SCHEMA', `Batch must carry exactly one approval per declared action: ${capsuleId}`, 400);
        accepted.push(this.approveInner(p, capsuleId, matched[0], now));
        constraints.push(this.policy(p.tenant_id).rules[record.capsule.action.type]?.approval_threshold ?? null);
      }
      this.store.audit(p.tenant_id, 'BATCH_APPROVED', p.subject_id, 'batch', { capsule_ids: input.capsule_ids, count: accepted.length }, now);
      return { accepted: accepted.length, capsule_ids: input.capsule_ids, aggregate_constraints: constraints };
    });
  }
  // The shared per-capsule approval check used by approve() and batchApprove.
  approveInner(p, capsuleId, envelope, now) {
    const t = p.tenant_id, payload = verifySigned(envelope, this.identities(t), 'action-approval');
    requireThat(payload.capsule_id === capsuleId, 'INV-403-SCOPE', 'Approval payload does not bind the declared action', 403);
    this.assertHealthy(t, p.subject_id, this.identity(p).device_id, now);
    this.assertSuiteAllowed(t, envelope.protected.suite);
    fields(payload, ['tenant_id', 'capsule_id', 'capsule_digest', 'evidence_graph_digest', 'policy_digest', 'signer_id', 'approved_at', 'expires_at']);
    requireThat(payload.tenant_id === t && payload.signer_id === envelope.protected.key_id, 'INV-403-SCOPE', 'Approval scope mismatch', 403);
    const identity = this.identities(t)[payload.signer_id]; requireThat(identity.subject_id === p.subject_id, 'INV-403-SCOPE', 'Approval signer does not match authenticated identity', 403);
    const record = this.store.must(t, 'capsule', capsuleId); this.ensureMutable(record);
    requireThat(identity.subject_id !== record.capsule.actor.subject_id, 'INV-403-SEPARATION', 'An initiator cannot approve their own action', 403);
    requireThat(payload.capsule_digest === record.capsule_digest && payload.evidence_graph_digest === this.graph(t, record).digest && payload.policy_digest === digest(this.policy(t)), 'INV-409-STATE', 'Approval no longer matches action, evidence or policy', 409);
    integer(payload.approved_at, 'approval time', now - 300000, now + 5000); integer(payload.expires_at, 'approval expiry', now + 1, Math.min(record.capsule.expires_at, payload.approved_at + 300000));
    requireThat(!record.approvals.some(a => a.payload.signer_id === payload.signer_id), 'INV-409-REPLAY', 'Signer already approved this action', 409);
    record.approvals.push(clone(envelope)); this.store.put(t, 'capsule', capsuleId, record, now);
    this.store.audit(t, 'EXACT_ACTION_APPROVED', p.subject_id, capsuleId, { approval_digest: digest(envelope), signer_id: payload.signer_id }, now);
    return { capsule_id: capsuleId, signer_id: payload.signer_id, approvals: record.approvals.length };
  }
  // NET-010: reconstruct the containment sequence for incident analysis —
  // denied consumes (rate/budget/quarantine/scope) interleaved with
  // subject/device revocations, ordered by time.
  containmentReport(p) {
    this.authorize(p, ['operator', 'security', 'auditor', 'policy_admin']);
    const t = p.tenant_id;
    const denials = this.store.list(t, 'containment', 10000).map(c => ({ kind: 'denied_consume', at: c.contained_at, code: c.code, subject_id: c.subject_id, capability_id: c.capability_id, resource: c.resource, request_id: c.request_id }));
    const quarantines = this.store.list(t, 'revocation', 10000).filter(r => ['subject', 'device'].includes(r.kind)).map(r => ({ kind: 'revocation', at: r.revoked_at, revoked: `${r.kind}:${r.id}`, by: r.actor }));
    const sequence = [...denials, ...quarantines].sort((a, b) => a.at - b.at);
    return { sequence, dropped_requests: denials.length, affected_capabilities: [...new Set(denials.map(d => d.capability_id).filter(Boolean))], quarantined: quarantines.map(q => q.revoked), limitation: 'Software dataplane telemetry only; packet-level counters require a real network path.' };
  }
  retention(p, input) {
    this.authorize(p, ['security']); fields(input, ['evidence_id', 'legal_hold']); identifier(input.evidence_id); requireThat(typeof input.legal_hold === 'boolean', 'INV-400-SCHEMA', 'Legal hold must be boolean');
    return this.transaction(p, now => { const e = this.store.must(p.tenant_id, 'evidence', input.evidence_id); e.legal_hold = input.legal_hold; this.store.put(p.tenant_id, 'evidence', input.evidence_id, e, now); this.store.audit(p.tenant_id, 'RETENTION_HOLD_CHANGED', p.subject_id, input.evidence_id, { legal_hold: input.legal_hold }, now); return { evidence_id: input.evidence_id, legal_hold: input.legal_hold }; });
  }
  retentionSweep(p) {
    this.authorize(p, ['security']);
    const result = this.transaction(p, now => {
      // Enumerate by id and load each record individually: a single
      // undecryptable evidence/capsule row is reported, not a sweep-wedging
      // exception (store-audit MED-3). Any residue is honestly flagged.
      const evidenceIds = this.store.ids(p.tenant_id, 'evidence', 20000), capsuleIds = this.store.ids(p.tenant_id, 'capsule', 20000), coverageIdsList = this.store.ids(p.tenant_id, 'coverage', 10000);
      const items = [], records = [], corrupt = [], citedEvidence = new Set();
      for (const id of evidenceIds) { try { items.push(this.store.must(p.tenant_id, 'evidence', id)); } catch { corrupt.push(['evidence', id]); } }
      for (const id of capsuleIds) { try { records.push(this.store.must(p.tenant_id, 'capsule', id)); } catch { corrupt.push(['capsule', id]); } }
      // Coverage rows join the reference scan per-id: one corrupt coverage
      // record must not wedge the whole sweep (w8-fixverify F5).
      for (const id of coverageIdsList) { try { const c = this.store.must(p.tenant_id, 'coverage', id); if (c.technical_validation?.evidence_id) citedEvidence.add(c.technical_validation.evidence_id); } catch { corrupt.push(['coverage', id]); } }
      // Undecryptable residue is itself erased — a corrupt row can never
      // become readable again, so keeping it only leaks ciphertext
      // indefinitely (DEK-audit F5).
      for (const [kind, id] of corrupt) this.store.shred(p.tenant_id, kind, id);
      const truncated = evidenceIds.length === 20000 || capsuleIds.length === 20000 || coverageIdsList.length === 10000;
      let deleted = 0, held = 0;
      // Conservative batch boundary: do not erase if a reference could be outside this scan.
      if (truncated) return { deleted: 0, held: items.length, corrupt: corrupt.length, reason: 'Reference scan limit reached; no deletion performed', complete_payload_erasure: false, truncated: true };
      for (const e of items) {
        if (e.payload.retention_until > now) continue;
        const activeReference = records.some(r => Array.isArray(r.evidence) && r.evidence.includes(e.payload.evidence_id) && !['VERIFIED', 'FAILED', 'DENY', 'CANCELLED', 'COMPENSATED'].includes(r.status)) || citedEvidence.has(e.payload.evidence_id);
        if (e.legal_hold || activeReference) { held++; continue; }
        const original_digest = digest(e.envelope);
        // put(), not insert(): an issuer may legitimately re-mint a shredded
        // evidence_id — a stale tombstone must then be overwritten, or the
        // sweep wedges permanently on INV-409-CONFLICT (DEK-audit F1).
        // Re-minted evidence ids overwrite the tombstone but never erase the
        // receipt history — earlier erasures stay provable (w8-fixverify F7).
        const priorTomb = this.store.get(p.tenant_id, 'evidence-tombstone', e.payload.evidence_id);
        const superseded = priorTomb ? [...(priorTomb.superseded ?? []), { original_digest: priorTomb.original_digest, deleted_at: priorTomb.deleted_at }] : [];
        this.store.put(p.tenant_id, 'evidence-tombstone', e.payload.evidence_id, { evidence_id: e.payload.evidence_id, original_digest, deleted_at: now, superseded }, now);
        this.store.shred(p.tenant_id, 'evidence', e.payload.evidence_id); deleted++;
        this.store.audit(p.tenant_id, 'RETENTION_DELETED', p.subject_id, e.payload.evidence_id, { original_digest, crypto_shred: true }, now);
      }
      return { deleted, held, corrupt: corrupt.length, corrupt_ids: corrupt.slice(0, 64).map(([k, i]) => `${k}:${i}`), corrupt_shredded: corrupt.length, complete_payload_erasure: false, truncated: false, limitation: 'Record DEKs are destroyed and the WAL truncated; ciphertext remaining in pre-erasure backups or external copies is not reachable by this operation.' };
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
      const t = p.tenant_id;
      this.assertHealthy(t, p.subject_id, this.identity(p).device_id, now);
      // The key.ceremony rule's cooldown is the floor for the recovery delay
      // — ceremonies are never instant-reconstructible (w6-ceremony F13).
      const floor = this.policy(t).rules['key.ceremony']?.cooldown_ms ?? 0;
      requireThat((input.min_delay_ms ?? 0) >= floor, 'INV-400-SCHEMA', `Ceremony min_delay_ms must be at least ${floor}`, 400);
      const ceremony = createCeremony({ ...input, tenant_id: t });
      this.store.insert(t, 'ceremony', ceremony.ceremony_id, ceremony, now);
      this.store.audit(t, 'CEREMONY_PLANNED', p.subject_id, ceremony.ceremony_id, { digest: ceremony.artifact_digest, threshold: ceremony.threshold }, now);
      return ceremony;
    });
  }
  acknowledgeCeremony(p, envelope) {
    this.authorize(p, ['custodian']);
    return this.transaction(p, now => {
      const t = p.tenant_id, payload = verifySigned(envelope, this.identities(t), 'ceremony-acknowledgement');
      this.assertHealthy(t, p.subject_id, this.identity(p).device_id, now);
      this.assertSuiteAllowed(t, envelope.protected.suite);
      fields(payload, ['ceremony_id', 'artifact_digest', 'custodian', 'acknowledged_at']);
      const ceremony = this.store.must(t, 'ceremony', identifier(payload.ceremony_id));
      requireThat(payload.custodian === p.subject_id && payload.artifact_digest === ceremony.artifact_digest, 'INV-403-SCOPE', 'Acknowledgement scope mismatch', 403);
      // The signing key must belong to the claimed custodian identity — the
      // same binding rule approvals enforce (HTTP-audit finding).
      const ackIdentity = this.identities(t)[envelope.protected.key_id];
      requireThat(ackIdentity?.subject_id === p.subject_id, 'INV-403-SCOPE', 'Acknowledgement signer does not match the custodian identity', 403);
      // Ceremony-bound device pinning: when the ceremony declared which
      // device a custodian acknowledges from, the live identity must match
      // (w6 F7).
      if (ceremony.devices?.[p.subject_id]) requireThat(ackIdentity.device_id === ceremony.devices[p.subject_id], 'INV-403-SCOPE', 'Acknowledgement device does not match the ceremony binding', 403);
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
      this.assertHealthy(p.tenant_id, p.subject_id, this.identity(p).device_id, now);
      const ceremony = this.store.must(p.tenant_id, 'ceremony', identifier(ceremony_id));
      commitShares(ceremony, shares, now);
      this.store.put(p.tenant_id, 'ceremony', ceremony.ceremony_id, ceremony, now);
      this.store.audit(p.tenant_id, 'CEREMONY_SHARES_COMMITTED', p.subject_id, ceremony.ceremony_id, { count: ceremony.share_commitments.length }, now);
      for (const n of ceremony.notices) this.store.audit(p.tenant_id, 'RECOVERY_NOTICE_ISSUED', p.subject_id, ceremony.ceremony_id, { custodian: n.custodian, channel: n.channel, issued_at: n.issued_at, delay_ms: ceremony.min_delay_ms }, now);
      return ceremonyReport(ceremony);
    });
  }
  reconstructCeremony(p, ceremony_id, encodedShares) {
    this.authorize(p, ['security', 'custodian']);
    return this.transaction(p, now => {
      const t = p.tenant_id, ceremony = this.store.must(t, 'ceremony', identifier(ceremony_id));
      this.assertHealthy(t, p.subject_id, this.identity(p).device_id, now);
      // The consent quorum and the share quorum are one set: every presented
      // share must belong to a custodian who acknowledged the committed
      // artifact, and the acknowledgements themselves must span distinct
      // failure domains with all custodians still live (w6 F5/F7/F9).
      requireThat(this.custodianQuorum(t, ceremony).live >= ceremony.threshold, 'INV-409-STATE', 'Ceremony lacks a live custodian quorum across failure domains', 409);
      const acked = new Set(ceremony.acknowledgements.filter(a => a.payload.artifact_digest === ceremony.artifact_digest).map(a => a.payload.custodian));
      const shares = encodedShares.map(s => decodeShare(s));
      for (const s of shares) requireThat(acked.has(ceremony.custodians[s.x - 1]), 'INV-403-ROLE', 'Share presented for a custodian who did not acknowledge', 403);
      const { secret, artifact } = reconstructSecret(ceremony, shares, now);
      this.store.put(t, 'ceremony', ceremony.ceremony_id, ceremony, now);
      // The reconstructed secret's digest goes on the audit record so the
      // ledger can prove WHICH secret the quorum reconstructed (w6 F6).
      const secret_digest = digest({ secret: Buffer.from(secret).toString('base64url') });
      this.store.audit(t, 'CEREMONY_RECONSTRUCTED', p.subject_id, ceremony.ceremony_id, { quorum: artifact.quorum, purpose: ceremony.purpose, secret_digest }, now);
      return { artifact, reconstructed: true, secret_digest, note: 'Secret reconstructed under ceremony quorum; raw material is not returned by this endpoint.' };
    });
  }
  splitCeremonySecret(p, ceremony_id, secretB64) {
    this.authorize(p, ['security', 'custodian']);
    return this.transaction(p, now => {
      const ceremony = this.store.must(p.tenant_id, 'ceremony', identifier(ceremony_id));
      requireThat(ceremony.status === 'planned', 'INV-409-STATE', 'Shares were already committed for this ceremony', 409);
      const secret = Buffer.from(secretB64, 'base64url');
      requireThat(secret.length >= 16 && secret.length <= 512, 'INV-400-SCHEMA', 'Secret size out of bounds');
      const shares = splitSecret(secret, ceremony);
      commitShares(ceremony, shares, now);
      this.store.put(p.tenant_id, 'ceremony', ceremony.ceremony_id, ceremony, now);
      this.store.audit(p.tenant_id, 'CEREMONY_SHARES_COMMITTED', p.subject_id, ceremony.ceremony_id, { count: ceremony.share_commitments.length }, now);
      for (const n of ceremony.notices) this.store.audit(p.tenant_id, 'RECOVERY_NOTICE_ISSUED', p.subject_id, ceremony.ceremony_id, { custodian: n.custodian, channel: n.channel, issued_at: n.issued_at, delay_ms: ceremony.min_delay_ms }, now);
      return { shares: ceremony.custodians.map((custodian, i) => ({ custodian, share: encodeShare(shares[i]) })), commitments: ceremony.share_commitments };
    });
  }
  prepareRotation(p, key_class, suite = 'Ed25519') {
    this.authorize(p, ['security', 'custodian']);
    requireThat(['execution', 'audit'].includes(key_class), 'INV-400-SCHEMA', 'key_class must be execution or audit');
    requireThat(SUITES[suite], 'INV-400-SCHEMA', 'Unknown signature suite');
    return this.transaction(p, now => {
      // KEY-007: a rotated key keeps the class's purpose binding — 'any' would
      // destroy the separation genesis established (w5 F-4).
      const pending = this.vault.generate(this._keyPurposes?.[key_class] ?? 'any', { pending: true, suite, tenant_id: p.tenant_id });
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
      // Prototype-safe lookup: a caller-controlled component name must not
      // resolve built-in object members (w6-perception P-1).
      const components = this.perceptionComponents[t] ?? {}, componentName = attestation?.payload?.component;
      requireThat(typeof componentName === 'string' && Object.hasOwn(components, componentName), 'INV-401-ATTESTATION', 'Unknown perception component', 401);
      const component = components[componentName];
      // A component whose signing credential was revoked cannot attest —
      // revocation of component key_ids is honoured here, not only in the
      // class-key machinery (w6-perception P-2).
      requireThat(!this.revoked(t, 'key', component.signing.key_id), 'INV-401-ATTESTATION', 'Component signing key revoked', 401);
      const session = openSession(component, attestation, this.policy(t), now);
      this.assertHealthy(t, p.subject_id, this.identity(p).device_id, now);
      // Replay guard: an attestation nonce may mint exactly one session.
      const seen = this.store.db.prepare('SELECT capsule FROM nonces WHERE tenant=? AND nonce=?').get(t, attestation.payload.nonce);
      requireThat(!seen, 'INV-409-REPLAY', 'Attestation nonce already consumed', 409);
      this.store.db.prepare('INSERT INTO nonces VALUES(?,?,?)').run(t, attestation.payload.nonce, `perception:${session.session_id}`);
      const stored = { ...session, _server_private: session._server_private.export({ type: 'pkcs8', format: 'pem' }), creator: p.subject_id };
      this.store.insert(t, 'perception-session', session.session_id, stored, now);
      this.store.audit(t, 'PERCEPTION_SESSION', p.subject_id, session.session_id, { component: session.component, assurance: session.assurance, firmware: session.firmware_version }, now);
      return { session_id: session.session_id, assurance: session.assurance, production: false, component: session.component, expires_at: session.expires_at, ephemeral_public: session.server_ephemeral };
    });
  }
  perceptionRelease(p, session_id, release) {
    this.authorize(p, ['operator', 'approver', 'custodian', 'security']);
    return this.transaction(p, now => {
      const t = p.tenant_id, session = this.store.must(t, 'perception-session', identifier(session_id));
      this.assertHealthy(t, p.subject_id, this.identity(p).device_id, now);
      // A session is bound to its creator — another identity cannot release
      // into someone else's sealed channel (runtime-audit F-12).
      requireThat(session.creator === p.subject_id, 'INV-403-SCOPE', 'Perception session belongs to another identity', 403);
      // Release provenance must be real: a cited capsule or evidence record
      // that does not exist would write forged authority into the signed
      // audit trail (runtime-audit F-6).
      requireThat(release && typeof release === 'object' && !Array.isArray(release) && release.fields && typeof release.fields === 'object' && !Array.isArray(release.fields), 'INV-400-SCHEMA', 'Invalid release', 400);
      text(release.purpose, 'purpose', 512);
      this._releaseCitation(t, release, p, now);
      const result = releaseFields(session, release, this.policy(t), now);
      this.store.audit(t, 'PERCEPTION_RELEASE', p.subject_id, session_id, { fields: result.binding.fields, assurance: result.assurance, capsule_id: release.capsule_id ?? null, evidence_ref: release.evidence_ref ?? null }, now);
      return result;
    });
  }
  // A cited capsule or evidence record must exist, be live, belong to the
  // releasing actor, and bind to each other — existence alone would let any
  // real object launder the provenance of sealed fields (w6 P-3). Shared by
  // the sealed release and the labeled fallback so neither path can mint a
  // free-floating citation (w6-perception P-8).
  _releaseCitation(t, release, p, now) {
    // A citation means "this release draws on provenance that already passed
    // evaluation" — an undecided, expired, advisory or foreign capsule/
    // evidence can never launder sealed fields (w8-fixverify F4).
    const checkCapsule = record => {
      requireThat(record && record.capsule.expires_at > now, 'INV-404-NOT-FOUND', 'Release cites no live capsule', 404);
      requireThat(record.capsule.actor.subject_id === p.subject_id, 'INV-403-SCOPE', 'Release cites a capsule belonging to another actor', 403);
      requireThat(record.decision, 'INV-409-STATE', 'Release cites an undecided capsule', 409);
      return record;
    };
    let cited = null;
    if (release.capsule_id !== undefined)
      cited = checkCapsule(this.store.get(t, 'capsule', identifier(release.capsule_id, 'capsule')));
    if (release.evidence_ref !== undefined) {
      const ev = this.store.get(t, 'evidence', identifier(release.evidence_ref, 'evidence'));
      const payload = ev?.envelope?.payload;
      requireThat(payload, 'INV-404-NOT-FOUND', 'Release cites nonexistent evidence', 404);
      requireThat(payload.expires_at > now, 'INV-412-EVIDENCE', 'Release cites expired evidence', 412);
      requireThat(payload.advisory !== true, 'INV-412-EVIDENCE', 'Advisory evidence cannot be cited as authority', 412);
      // An evidence-only citation still binds the capsule it supports — the
      // citation can never float free of its evaluated context.
      const backing = cited ?? checkCapsule(this.store.list(t, 'capsule', 10000).find(r => r.capsule_digest === payload.capsule_digest));
      if (cited) requireThat(payload.capsule_digest === cited.capsule_digest, 'INV-403-SCOPE', 'Evidence does not support the cited capsule', 403);
      else cited = backing;
    }
    return cited;
  }
  perceptionFallback(p, release) {
    this.authorize(p, ['operator', 'approver', 'custodian', 'security']);
    requireThat(release && typeof release === 'object' && !Array.isArray(release), 'INV-400-SCHEMA', 'Invalid release', 400);
    requireThat(release.fields && typeof release.fields === 'object' && !Array.isArray(release.fields), 'INV-400-SCHEMA', 'fields must be an object', 400);
    text(release.purpose, 'purpose');
    return this.transaction(p, now => {
      this.assertHealthy(p.tenant_id, p.subject_id, this.identity(p).device_id, now);
      this._releaseCitation(p.tenant_id, release, p, now);
      const result = workspaceFallback(release, this.policy(p.tenant_id), now);
      this.store.audit(p.tenant_id, 'PERCEPTION_FALLBACK', p.subject_id, 'workspace', { fields: result.binding.fields, assurance: result.assurance, capsule_id: release.capsule_id ?? null, evidence_ref: release.evidence_ref ?? null }, now);
      return result;
    });
  }
  // AIG-*: deterministic advisory plane — extraction, explanation, intent.
  // Every call is audited with model identity; outputs are advisory:true and
  // cannot create evidence or authority by themselves.
  advise(p, input) {
    this.authorize(p, ['operator', 'security', 'policy_admin', 'approver', 'custodian', 'auditor']);
    fields(input, ['operation'], ['document', 'capsule_id']);
    return this.transaction(p, now => {
      this.assertHealthy(p.tenant_id, p.subject_id, this.identity(p).device_id, now);
      requireThat(this.policy(p.tenant_id).mode !== 'disabled', 'INV-451-POLICY', 'Advisory plane disabled', 451);
      let out;
      // Documents are capped at the canonical ceiling (64 KiB) — a value the
      // audit digest can always cover, so advertised limits never exceed the
      // envelope that records them (w6-perception A-1).
      if (input.operation === 'extract') out = extract(text(input.document, 'document', 65536));
      // explain narrates a STORED decision only — a caller cannot mint an
      // official-looking explanation for a verdict that never happened
      // (runtime-audit F-13).
      else if (input.operation === 'explain') {
        const record = this.store.must(p.tenant_id, 'capsule', identifier(input.capsule_id ?? ''));
        requireThat(record.decision, 'INV-409-STATE', 'Action has no recorded decision to explain', 409);
        out = explain(record.decision);
        // The audit digest commits to the stored decision that was actually
        // explained — never to a caller-supplied one (w6-perception A-2).
        this.store.audit(p.tenant_id, 'AI_ADVISORY', p.subject_id, out.model, { operation: input.operation, model: out.model, model_version: out.model_version ?? out.model, provider: out.provider ?? 'local-deterministic', prompt_digest: digest({ operation: input.operation, capsule_id: input.capsule_id, decision: record.decision }), tool_context_digest: digest(input), output_digest: digest(out), advisory: true }, now);
        return out;
      }
      else if (input.operation === 'intent') out = classifyIntent(text(input.document, 'request text', 65536));
      else throw new InvariantError('INV-400-SCHEMA', 'Unsupported advisory operation');
      this.store.audit(p.tenant_id, 'AI_ADVISORY', p.subject_id, out.model, { operation: input.operation, model: out.model, model_version: out.model_version ?? out.model, provider: out.provider ?? 'local-deterministic', prompt_digest: digest({ operation: input.operation, document: input.document ?? null }), tool_context_digest: digest(input), output_digest: digest(out), advisory: true }, now);
      return out;
    });
  }
}

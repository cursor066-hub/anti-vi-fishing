import { randomUUID, randomBytes, createHmac } from 'node:crypto';
import { Store } from './store.mjs';
import { SimulatedTarget } from './target.mjs';
import { RuntimeGate } from './runtime.mjs';
import { digest, clone, canonical } from './canonical.mjs';
import { verifySigned, decrypt, ctEqual } from './crypto.mjs';
import { KeyVault, derivePublic } from './keystore.mjs';
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

// Issuer fields that legitimately rotate at runtime; everything else on the
// issuer record is a trust anchor and stays frozen (w11-redteam R12).
const ISSUER_MUTABLE = new Set(['issue_token', 'read_token', 'token_expires_at']);

export class Fabric {
  // The authoritative tenant map lives behind a private field: an
  // in-process insider can mutate or replace this.config.tenants but cannot
  // reach #tenants — phantom tenants and unguarded _setTenant swaps mint
  // nothing (w12-provenance F13/F14). config.tenants stays populated as a
  // frozen diagnostic mirror.
  #tenants = {};
  // In-memory projections derived from the signed audit chain. They live in
  // private fields because every in-process object mutation is in threat
  // scope — a reachable cache is a forged cache (w13-store F9/F11).
  #auditIdx = new Map();
  #denyAudit = new Map();
  #verifyMemo = new Map();
  #rejectMemo = new Map();
  #declaredRetired = {};
  constructor(config, directory, clock = Date.now, { vault = null } = {}) {
    requireThat(config.profile === 'engineering', 'INV-503-RELEASE', 'Production mode is blocked: external acceptance evidence is missing', 503);
    this.config = config; this.directory = directory; this.clock = clock;
    this.#tenants = clone(config.tenants ?? {});
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
        // Presence, not signing-eligibility: a revoked configured key must
        // still load (it verifies every artifact it signed in the past) —
        // gating on has() would try to re-import it and wedge cold start on
        // a key-id conflict (w13 fixverify).
        if (key.private_key && !this.vault.keys.has(key.key_id)) this.vault.importKey({ key_id: key.key_id, public_key: key.public_key, private_key: key.private_key }, purposes[klass], { exportable: false, tenant_id: tenant });
        requireThat(this.vault.keys.has(key.key_id), 'INV-503-CONFIG', `Tenant ${klass} key is not in the keystore`, 503);
      }
      auditSigners[tenant] = { key_id: t.keys.audit.key_id, public_key: t.keys.audit.public_key, keys: () => this.auditPublicKeys(tenant), sign: (payload, purpose = 'audit') => { const sel = this._signingKeyId(tenant, 'audit'); return this.vault.envelope(sel.key_id, purpose, this._recoveryBody(sel, payload), { allowPending: sel.recovery }); } };
    }
    this.store = new Store(join(directory, 'fabric.db'), encryption, auditSigners);
    this.target = new SimulatedTarget(join(directory, 'target.db'), encryption); this.runtime = new RuntimeGate(this);
    // Retired-key declarations are authentic only from the signed config —
    // _reconcileLedger appends store-derived entries (attacker-writable) to
    // the same list, so verification trusts the declared set by key_id plus
    // whatever the vault itself can attest (w13 fixverify).
    this.#declaredRetired = Object.fromEntries(Object.entries(config.tenants ?? {}).map(([tn, row]) => [tn, new Map((row.keys?.retired ?? []).filter(r => !r.derived).map(r => [r.key_id, r.public_key]))]));
    this._reconcileLedger();
    this.perceptionComponents = {};
    for (const [tenant, t] of Object.entries(config.tenants)) this.perceptionComponents[tenant] = this._deepFreeze(clone(t.components ?? {}));
    // The map mirrors declared config — it must be as immutable as the
    // digested sections: an in-process slot/entry swap would otherwise
    // register an unlisted perception component and mint sealed ECDH
    // releases under attacker-chosen keys (w17-redteam A4).
    Object.freeze(this.perceptionComponents);
    Object.defineProperty(this, 'perceptionComponents', { value: this.perceptionComponents, writable: false, enumerable: true, configurable: false });
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
      const sections = this._configSections(t);
      const configDigest = digest({ tenant, sections });
      const existing = this.store.get(tenant, 'config-snapshot', 'current');
      // The drift baseline is the LAST SIGNED snapshot event, falling back
      // to the record only when the chain has none — a forged or deleted
      // 'config-snapshot' row cannot launder a tampered config through
      // re-baselining (w13-fixverify M4).
      const anchored = this._anchoredConfigSnapshot(tenant);
      const expected = anchored ?? existing?.digest;
      if (expected !== undefined && expected !== configDigest) {
        const changed = existing?.sections ? Object.keys(sections).filter(k => existing.sections[k] !== sections[k]) : ['unknown'];
        this._configDrift.add(tenant);
        this.store.tx(() => { this.store.put(tenant, 'config-flag', 'drift', { detected_at: this.clock(), expected, observed: configDigest }, this.clock()); this.store.audit(tenant, 'CONFIG_DRIFT', 'system', 'config', { expected, observed: configDigest, changed_sections: changed, consequence: 'gate-privileges-withdrawn' }, this.clock()); });
      } else {
        if (!existing) this.store.tx(() => { this.store.put(tenant, 'config-snapshot', 'current', { digest: configDigest, taken_at: this.clock(), sections }, this.clock()); });
        if (anchored === null) this.store.tx(() => { this.store.audit(tenant, 'CONFIG_SNAPSHOT', 'system', 'config', { config_digest: configDigest }, this.clock()); });
      }
    } } catch (error) { this.close(); throw error; }
    // Freeze tenant configuration last (post-reconcile): a mid-session edit
    // of identities/issuers/keys must trip drift detection like a file-level
    // change, and immutability is the only honest in-process answer
    // (w11-redteam R12).
    for (const t of Object.keys(this.#tenants)) this.#setTenant(t, this.#tenants[t]);
  }
  // Converge non-transactional side effects to the committed ledger. The
  // outcome tx writes key-rotation / jit-grant records; their vault and
  // target mutations run post-commit, so a crash between commit and apply is
  // healed here on the next open rather than leaving a permanent divergence
  // (store-audit MED-6). The ledger is the source of truth; vault and target
  // grant tables are derived state.
  // A store record can only repoint the signing binding if the chain itself
  // attests the transition: find a consumed-consistent, vault-verified
  // audit row of `type` matching `match`. auditPage re-proves hash/seq/
  // previous continuity across the whole prefix, so a replayed envelope
  // dies at the seq check and a forged envelope dies at verifySigned
  // (w13-store F5 / w13-fixverify H1).
  _anchoredEvent(t, type, match) {
    let after = 0;
    try {
      for (;;) {
        const page = this.store.auditPage(t, { after, limit: 5000 });
        for (const row of page.entries) {
          const e = row.envelope;
          if (!e || e.payload?.type !== type) continue;
          try { verifySigned(e, this.auditPublicKeys(t), 'audit'); } catch { continue; }
          if (match(e.payload)) return e.payload;
        }
        if (page.next_cursor === null) return null;
        after = page.next_cursor;
      }
    } catch {
      // A tampered page fails closed: no event is anchored, so the caller's
      // state transition never fires — and sealAuditChain can still open.
      return null;
    }
  }
  // The last signature-verified CONFIG_SNAPSHOT/CONFIG_REASSERTED digest on
  // the chain — the drift baseline the mutable 'config-snapshot' record can
  // never launder (w13-fixverify M4).
  _anchoredConfigSnapshot(t) {
    let latest = null, after = 0;
    try {
      for (;;) {
        const page = this.store.auditPage(t, { after, limit: 5000 });
        for (const row of page.entries) {
          const e = row.envelope, pl = e?.payload;
          if (pl?.type === 'CONFIG_SNAPSHOT' || pl?.type === 'CONFIG_REASSERTED') {
            try { verifySigned(e, this.auditPublicKeys(t), 'audit'); if (pl.metadata?.config_digest) latest = pl.metadata.config_digest; } catch { /* forged row: ignore */ }
          }
        }
        if (page.next_cursor === null) break;
        after = page.next_cursor;
      }
    } catch { /* poisoned chain: no baseline — drift gates stay up */ }
    return latest;
  }
  _reconcileLedger() {
    let dirty = false;
    for (const tenant of Object.keys(this.#tenants)) {
      // A wedged chain must not block construction — sealAuditChain is a
      // Fabric method and stays reachable; every replay below then fails
      // closed (nothing replays until the chain verifies).
      let idx = null;
      try { idx = this._auditIndex(tenant); } catch { /* poisoned ledger: skip replays */ }
      // The repoint target is the newest ANCHORED rotation per class, not
      // the newest 'key-rotation' record — records are forgeable and
      // deletable, so picking the repoint from them lets a store writer
      // rewind the binding to an older (possibly dead) key and launder a
      // concurrent config tamper into the drift baseline (w16-fixverify
      // F3). Only the signed event speaks; the vault entry must still be a
      // live, tenant-owned key that the chain has not already killed.
      if (idx) for (const [klass, rot] of idx.rotations) {
        if (this.tenant(tenant).keys[klass]?.key_id === rot.new_key_id) continue;
        const entry = this.vault.keys.get(rot.new_key_id);
        if (entry && !entry.revoked && entry.generated_inside !== false && !idx.keyDeadAt.has(rot.new_key_id)) {
          const preSections = this._configSections(this.tenant(tenant));
          if (entry.pending) this.vault.activate(rot.new_key_id);
          const tn = clone(this.tenant(tenant));
          const previous = tn.keys[klass];
          tn.keys[klass] = { key_id: rot.new_key_id, public_key: entry.public_key };
          if (previous && !(tn.keys.retired ?? []).some(x => x.key_id === previous.key_id)) {
            // `derived` marks store-sourced lineage: only unmarked (config-
            // declared) retired entries join the declared-verification set,
            // so a forged rotation record cannot launder an attacker key
            // into a later cold-open's trust set (w13 fixverify).
            tn.keys.retired = [...(tn.keys.retired ?? []), { key_class: klass, key_id: previous.key_id, public_key: previous.public_key, retired_at: rot.at, derived: true }];
          }
          // The repoint is a clone+freeze swap, never an in-place write — a
          // shared config object may already be frozen by another Fabric
          // instance in this process (w13-fixverify L8).
          this.#setTenant(tenant, tn);
          // Re-anchor the config snapshot ONLY when the pre-repoint
          // configuration still matched the chain's last attested
          // baseline — the repoint itself is then the only sanctioned
          // delta. A dirty baseline (file tamper riding the repoint, an
          // injected token, a rewritten section) must stay drift, not be
          // minted into the new baseline (w16-fixverify F3).
          const postSections = this._configSections(this.tenant(tenant));
          const anchoredBaseline = this._anchoredConfigSnapshot(tenant);
          if (anchoredBaseline === null || digest({ tenant, sections: preSections }) === anchoredBaseline) {
            try { this.store.audit(tenant, 'CONFIG_SNAPSHOT', 'system', 'config', { config_digest: digest({ tenant, sections: postSections }) }, this.clock()); } catch { /* poisoned chain: drift flag will handle */ }
            // The display record tracks the same sanctioned state — a stale
            // baseline record would otherwise make every honest repoint
            // read as drift in configDriftStatus forever (w17-fixverify).
            this.store.put(tenant, 'config-snapshot', 'current', { digest: digest({ tenant, sections: postSections }), taken_at: this.clock(), sections: postSections }, this.clock());
          }
          dirty = true;
        }
      }
      const grants = this.target.allGrants(tenant);
      // Enumerate by id and load per-row: one undecryptable jit-grant row
      // skips its replay instead of wedging cold-start — anchoring remains
      // the authority, a corrupt row can only lose a grant, never mint one
      // (w17-fixverify).
      for (const id of this.store.ids(tenant, 'jit-grant', 1000)) {
        let jg; try { jg = this.store.must(tenant, 'jit-grant', id); } catch { continue; }
        // Forged grant rows replay into the dataplane — only rows the chain
        // anchors (new scope_digest, or the legacy grant_digest scheme with
        // every row field proven against the issuing request) may replay
        // (w13-fixverify L10, w16-fixverify F4/F7).
        if (jg.grant?.grant_id && !grants.some(g => g.grant_id === jg.grant.grant_id) && idx && this._grantAnchored(tenant, idx, jg.grant.grant_id, jg.grant)) this.target.grant(tenant, jg.grant.grant_id, jg.grant);
      }
      // Revoke direction too: a grant revoked in the ledger whose dataplane
      // write never landed (crash between commit and apply) is still dead
      // (w9-network F5).
      for (const g of grants) if (!g.revoked && this.revoked(tenant, 'grant', g.grant_id)) this.target.revokeGrant(tenant, g.grant_id);
    }
    if (dirty) this.persistVault();
  }
  // Is this grants-table row anchored by the ledger? Returns true only for
  // the two honest anchoring schemes: the current scope_digest over the
  // row's own scope fields, or the legacy grant_digest scheme — where the
  // anchor commits to the issuing capsule's requested_state, so every field
  // the row declares must equal that request and its timing must match the
  // anchored event (w16-fixverify F4). Anything else mints nothing.
  _grantAnchored(tenant, idx, grant_id, g) {
    const anchored = idx.grants.get(grant_id);
    if (anchored === undefined) return false;
    const scope = digest({ subject_id: g.subject_id, resources: g.resources ?? [], actions: g.actions ?? [], destinations: g.destinations ?? [], columns: g.columns ?? [], row_ids: g.row_ids ?? [], roles: g.roles ?? [], expires_at: g.expires_at });
    if (anchored === scope) return true;
    const capsuleId = typeof g.issued_by === 'string' && g.issued_by.startsWith('action:') ? g.issued_by.slice(7) : null;
    const req = capsuleId ? this.store.get(tenant, 'capsule', capsuleId)?.capsule?.requested_state : null;
    if (!req || anchored !== digest(req)) return false;
    const eq = (a, b) => digest(a ?? []) === digest(b ?? []);
    const gm = idx.grantMeta.get(grant_id);
    return g.subject_id === req.subject_id
      && eq(g.resources, req.resources) && eq(g.actions, req.actions) && eq(g.destinations, req.destinations)
      && eq(g.columns, req.columns) && eq(g.row_ids, req.row_ids) && eq(g.roles, req.roles)
      && (gm?.expires_at !== undefined ? g.expires_at === gm.expires_at : gm !== undefined && g.expires_at === gm.at + (req.ttl_ms ?? 0))
      && (gm === undefined || g.issued_at === gm.at);
  }
  _openVault() {
    const storePath = join(this.directory, 'keystore.json'), masterPath = join(this.directory, 'master.key');
    // master.key is the commit marker written last: a keystore without it
    // means a crash mid-persist — refuse rather than silently regenerate.
    if (existsSync(storePath) && !existsSync(masterPath)) throw new InvariantError('INV-503-CONFIG', 'Keystore exists but master key is missing — refusing to silently regenerate', 503);
    // The mirror image is equally suspect: a stale master.key without a
    // keystore means a prior wrapped store is gone — silently re-keying
    // under a fresh master strands every stored DEK and wedges the NEXT
    // persist on MAC mismatch, far from the cause (w9-schema F-4).
    if (!existsSync(storePath) && existsSync(masterPath)) throw new InvariantError('INV-503-CONFIG', 'Master key exists but keystore is missing — refusing to silently re-key and strand existing wrapped records', 503);
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
    // The ceremony row must descend from an anchored plan: its governance
    // fields (threshold, custodians, validity, rotation) must recompute to
    // the digest the signed CEREMONY_PLANNED event attested. The artifact
    // digest itself legitimately mutates at share-commit (it folds the
    // commitments in), so the plan digest is recomputed from the plan
    // terms instead (w17-redteam A2).
    const planned = this._auditIndex(t).ceremonyPlanned?.get(ceremony.ceremony_id);
    let planDigest = null;
    try { planDigest = digest({ ceremony_id: ceremony.ceremony_id, tenant_id: ceremony.tenant_id, purpose: ceremony.purpose, threshold: ceremony.threshold, custodians: [...(ceremony.custodians ?? [])].sort(), valid_until: ceremony.valid_until, min_delay_ms: ceremony.min_delay_ms, rotation: ceremony.rotation ?? null }); }
    catch { /* forged rows with non-canonical fields fail closed, never crash the gate */ }
    if (planned === undefined || planDigest === null || !ctEqual(planDigest, planned))
      return { count: ceremony.acknowledgements?.length ?? 0, live: 0, custodians: new Set() };
    const ids = this.identities(t);
    const domains = new Set(), live = new Set();
    for (const a of ceremony.acknowledgements) {
      // Only consent to the CURRENT artifact counts: an acknowledgement
      // bound to a superseded digest attested different terms (w7-seam F4).
      if (a.payload?.artifact_digest !== ceremony.artifact_digest) continue;
      // Consent is attributed to the failure domain of the exact identity
      // whose key signed the ack — a subject carrying several identities
      // cannot smuggle a second domain into the quorum count
      // (w11-approval F4).
      const identity = ids[a.protected?.key_id];
      if (!identity || identity.revoked || identity.subject_id !== a.payload.custodian) continue;
      // The ack envelope must still verify against the custodian's
      // registered key AND the chain must record that custodian's
      // acknowledgement for THIS ceremony — a store writer planting
      // unsigned acks, or transplanting real acks from a ceremony the
      // ledger never acknowledged, mints no quorum (w17-fixverify H1).
      try { verifySigned(a, { [a.protected.key_id]: { public_key: identity.public_key } }, 'ceremony-acknowledgement'); } catch { continue; }
      if (!(this._auditIndex(t).ceremonyAcks.get(ceremony.ceremony_id) ?? new Set()).has(a.payload.custodian)) continue;
      live.add(a.payload.custodian);
      domains.add(identity.failure_domain ?? a.payload.custodian);
    }
    return { count: ceremony.acknowledgements.length, live: domains.size, custodians: live };
  }
  close() { this.target.close(); this.store.close(); }
  // Own-property only: an inherited member must never resolve into a
  // phantom tenant (w10-fixverify F-12 — loadConfiguration also refuses
  // proto-named tenants at boot, defence in depth).
  tenant(t) { const row = Object.hasOwn(this.#tenants, t) ? this.#tenants[t] : undefined; requireThat(row, 'INV-404-NOT-FOUND', 'Resource not found', 404); return row; }
  // The authoritative tenant set for readers outside the class — a shallow
  // copy so a caller cannot write into #tenants itself (values are already
  // deep-frozen by #setTenant). server.mjs authenticateToken MUST use this,
  // not config.tenants — the mirror is writable in-process (w12-supply
  // W12-02 / w13-supply amplifier).
  tenantMap() { return { ...this.#tenants }; }

  // Test/ops hook: drop the derived index projections for tenant t (or all
  // tenants) so the next access rebuilds from the chain. The cache itself
  // stays private; nothing outside the class can forge a projection.
  invalidateAuditIndex(t) { t === undefined ? this.#auditIdx.clear() : this.#auditIdx.delete(t); this.#verifyMemo?.clear(); }
  // the drift snapshot is computed once at boot, so a live in-process edit
  // of identities/issuers/keys would take effect with no drift flag
  // (w11-redteam R12). Legitimate changes (key rotation) replace the record
  // through _setTenant with a fresh deep-frozen clone — section digests then
  // reflect the change on the next computation.
  _deepFreeze(o) { if (o && typeof o === 'object') { Object.freeze(o); for (const v of Object.values(o)) this._deepFreeze(v); } return o; }
  // Freeze every enumerable member except named fields — used for issuer
  // records whose credential fields (endpoint, tokens, expiry) legitimately
  // rotate at runtime while their trust anchors (public_key, kinds, name,
  // failure_domain) must not (w11-redteam R12).
  _freezeExcept(o, mutableKeys) {
    if (!o || typeof o !== 'object') return o;
    // Mutable keys that do not exist yet must still be assignable — create
    // them non-enumerable so canonicalization/digests never see undefined.
    for (const k of mutableKeys)
      if (!Object.hasOwn(o, k)) Object.defineProperty(o, k, { value: undefined, writable: true, enumerable: false, configurable: true });
    for (const [k, v] of Object.entries(o)) {
      if (mutableKeys.has(k)) { o[k] = this._deepFreeze(v); continue; }
      Object.defineProperty(o, k, { value: this._deepFreeze(v), writable: false, enumerable: true, configurable: false });
    }
    return Object.preventExtensions(o);
  }
  #setTenant(t, next) {
    const c = clone(next);
    // Issuer credential fields rotate at runtime — freeze each issuer record
    // EXCEPT the rotation surface before sealing the tenant object. The
    // endpoint itself is NOT mutable: a live-swap would redirect the
    // evidence POST (and its Bearer token) to an attacker host — endpoint
    // changes go through config reload + drift detection (w12-prov F15).
    if (c.issuers) for (const k of Object.keys(c.issuers)) c.issuers[k] = this._freezeExcept(c.issuers[k], ISSUER_MUTABLE);
    for (const k of Object.keys(c)) if (k !== 'issuers') c[k] = this._deepFreeze(c[k]);
    if (c.issuers) Object.freeze(c.issuers);
    const frozen = Object.freeze(c);
    this.#tenants[t] = frozen;
    // Diagnostic mirror only — authority is #tenants; mutating the mirror
    // shifts nothing (w12-provenance F13).
    if (this.config?.tenants) this.config.tenants[t] = frozen;
  }
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
  // Verification keys for a signing class. Sources, in order of trust:
  // the configured key (frozen config or a vault-gated reconcile pointer);
  // every tenant-owned VAULT key covering the class — vault residency is
  // authenticated because a fake entry cannot unwrap at load, and rotated
  // or revoked keys stay resident, so the whole rotation lineage verifies
  // on a cold start; retired declarations that are either config-declared
  // or corroborated by a matching vault entry. key-rotation RECORDS are
  // deliberately NOT a key source: they are mutable store rows, and a
  // forged record could otherwise enroll an attacker public key into the
  // verification set (w13 fixverify regression catch).
  // Runtime membership is not proof of vault residency: an entry injected
  // into the live map must re-derive its public half from wrapped material
  // under the master key — impossible without that key, the same guarantee
  // the vault's load-time check gives (w13 fixverify).
  _vaultAttested(kid, public_key) {
    const e = this.vault.keys.get(kid);
    if (!e || e.public_key !== public_key) return false;
    try { return derivePublic(decrypt(e.wrapped, this.vault.masterKey, `vault/${kid}`)) === public_key; } catch { return false; }
  }
  _verifyKeys(t, klass) {
    const out = {};
    const cur = this.keys(t)[klass];
    if (cur) out[cur.key_id] = { public_key: cur.public_key };
    const needed = this._keyPurposes[klass] ?? [];
    for (const [kid, e] of this.vault.keys) if (this.ownsVaultKey(t, kid)
      && (e.purpose === 'any' || needed.every(x => (Array.isArray(e.purpose) ? e.purpose : [e.purpose]).includes(x)))
      // Externally imported keys (generated_inside === false) never join
      // the verification set by vault membership: importKey is a dev/ceremony
      // path with no provenance, so admitting its keys would make it an
      // unauthenticated enrollment oracle for attested signers (w13-store
      // F4). Config-declared keys still verify through `cur`/retired above.
      && e.generated_inside !== false
      && this._vaultAttested(kid, e.public_key)) out[kid] = { public_key: e.public_key };
    for (const e of this.keys(t).retired ?? []) {
      if (e.key_class && e.key_class !== klass) continue;
      if (this.#declaredRetired[t]?.get(e.key_id) === e.public_key || this._vaultAttested(e.key_id, e.public_key)) out[e.key_id] = { public_key: e.public_key };
    }
    return out;
  }
  executionPublic(t) { return this._verifyKeys(t, 'execution'); }
  auditPublicKeys(t) { return this._verifyKeys(t, 'audit'); }
  // Resolves the key allowed to mint class envelopes right now: the bound
  // key when live, else the pending, tenant-owned successor minted before
  // the revoke — the designed escape that keeps a compromise-response from
  // bricking the tenant (w11-lifecycle F1/F2). Recovery envelopes carry a
  // `recovery_signing` marker naming the superseded key, so the ledger tells
  // the truth about which authority signed.
  _signingKeyId(t, klass) {
    const configured = this.keys(t)[klass]?.key_id;
    // A committed-but-not-yet-activated rotation also supersedes the
    // configured key: activation is post-commit by design (ledger-first),
    // so rows written later in the SAME transaction must already attest
    // under the successor — otherwise the signing window would see the
    // retiring key signing past its own KEY_ROTATED row (w14 W13-01).
    if (configured && !this.revoked(t, 'key', configured) && this.vault.has(configured)) {
      // Succession steering must see this transaction's own uncommitted
      // rotation rows, so records stay the lookup — but a 'key-rotation'
      // record is only a hint: a signed KEY_ROTATED event attesting the
      // exact succession must corroborate it before signing moves to the
      // pending successor. A forged record mints a signature-valid lie
      // (recovery_signing attribution under an attacker-chosen key)
      // (w16-fixverify F13).
      // The fold already indexes every anchored KEY_ROTATED keyed by
      // predecessor — an O(1) lookup replaces the records scan and removes
      // the forged 'key-rotation' record amplifier (w17-redteam C3,
      // w17-idx F6). Uncommitted same-transaction rotations are visible to
      // the fold, so W13-01 steering is preserved.
      const steered = this._auditIndex(t).rotationsByPrev?.get(`${klass}:${configured}`);
      if (steered) {
        const e = this.vault.keys.get(steered);
        if (e?.pending && !e?.revoked && e?.generated_inside !== false) return { key_id: steered, recovery: true, superseded: configured };
      }
      return { key_id: configured, recovery: false };
    }
    // A vault entry flagged revoked with no chain AUTHORITY_REVOKED is
    // unattributable in-process tamper — report the divergence honestly
    // instead of looking like a mere missing rotation (w17-redteam C4).
    const cfgEntry = configured ? this.vault.keys.get(configured) : null;
    if (cfgEntry?.revoked && !this._auditIndex(t).revoked.has(`key:${configured}`))
      throw new InvariantError('INV-503-INTEGRITY', `${klass} signing key was revoked without a ledger revocation event`, 503);
    const needed = this._keyPurposes[klass] ?? [];
    const successor = [...this.vault.keys.entries()].find(([kid, e]) => e.pending && !e.revoked && this.chainOwnsVaultKey(t, kid)
      && e.generated_inside !== false
      && (e.purpose === 'any' || needed.every(x => (Array.isArray(e.purpose) ? e.purpose : [e.purpose]).includes(x))));
    requireThat(successor, 'INV-401-SIGNATURE', `${klass} signing key unavailable and no pending successor exists — rotate first`, 401);
    return { key_id: successor[0], recovery: true, superseded: configured ?? null };
  }
  _recoveryBody(sel, payload) {
    return sel.recovery ? { ...payload, recovery_signing: { superseded_key: sel.superseded } } : payload;
  }
  // Signature results are pure functions of (keyset, envelope, purpose) —
  // the evaluate/graph path re-verifies the same fixed envelopes on every
  // call. Memoize the verified payload by key fingerprint + envelope
  // digest; the cache is evidence of nothing beyond crypto cost (w14 perf).
  _verifyCached(envelope, keys, purpose) {
    this.#verifyMemo ??= new Map();
    // The memo key must carry each key's material fingerprint and revoked
    // flag — a flipped revocation or swapped public key must never let a
    // stale hit keep verifying (w17-idx F10).
    const ck = `${Object.entries(keys).map(([k, v]) => `${k}:${String(v?.public_key ?? '').slice(0, 8)}:${v?.revoked ? 1 : 0}`).sort().join(',')}|${purpose}|${digest(envelope)}`;
    if (this.#verifyMemo.has(ck)) return this.#verifyMemo.get(ck);
    const pl = verifySigned(envelope, keys, purpose);
    if (this.#verifyMemo.size >= 16384) this.#verifyMemo.clear();
    this.#verifyMemo.set(ck, pl);
    return pl;
  }
  signExecution(t, payload, purpose) {
    const sel = this._signingKeyId(t, 'execution');
    // The ledger, not the vault flag, is authoritative for revocation — a
    // revoked key keeps verifying old artifacts but must never sign new
    // envelopes (w6-fix F4). Recovery signing uses the pending successor via
    // the scoped allowPending path.
    const e = this.vault.keys.get(sel.key_id);
    this.assertSuiteAllowed(t, e?.suite ?? 'Ed25519');
    return this.vault.envelope(sel.key_id, purpose, this._recoveryBody(sel, payload), { allowPending: sel.recovery });
  }
  // The explicit key_id path is internal-only (the rotation-succession
  // outcome signer) — it still enforces tenant ownership and ledger
  // revocation; the purpose pin lives at the vault sign call (w13 L10).
  signAudit(t, payload, purpose = 'audit', key_id = null, { allowPending = false } = {}) {
    const sel = key_id ? { key_id, recovery: false } : this._signingKeyId(t, 'audit');
    if (key_id) requireThat(this.ownsVaultKey(t, key_id) && !this.revoked(t, 'key', key_id), 'INV-401-SIGNATURE', 'Signing key revoked or foreign', 401);
    const e = this.vault.keys.get(sel.key_id);
    this.assertSuiteAllowed(t, e?.suite ?? 'Ed25519');
    return this.vault.envelope(sel.key_id, purpose, this._recoveryBody(sel, payload), { allowPending: allowPending || sel.recovery });
  }
  assertSuiteAllowed(t, suite) {
    requireThat((this.policy(t).algorithms?.allowed_suites ?? ['Ed25519']).includes(suite), 'INV-451-POLICY', 'Signature suite retired by constitution', 451);
  }
  // Current drift status with a field-level preview of what changed — a
  // security actor must be able to see the diff before re-attesting.
  configDriftStatus(p) {
    this.authorize(p, ['security', 'policy_admin']);
    const t = p.tenant_id, tenant = this.tenant(t);
    const sections = this._configSections(tenant);
    const observed = digest({ tenant: t, sections }), existing = this.store.get(t, 'config-snapshot', 'current');
    const changed = existing?.sections ? Object.keys(sections).filter(k => existing.sections[k] !== sections[k]) : [];
    return { drifted: this._configDrift.has(t) || this._auditIndex(t).tenantDrifted || (existing && existing.digest !== observed), expected: existing?.digest ?? null, observed, changed_sections: changed };
  }
  // RUN-010: security re-attests a drifted configuration snapshot, restoring
  // privileges. This is the only operation allowed through during drift.
  reassertConfig(p) {
    this.authorize(p, ['security']);
    return this.transaction(p, now => {
      const t = p.tenant_id, tenant = this.tenant(t);
      const sections = this._configSections(tenant);
      const digestNow = digest({ tenant: t, sections }), existing = this.store.get(t, 'config-snapshot', 'current');
      const changed = existing?.sections ? Object.keys(sections).filter(k => existing.sections[k] !== sections[k]) : [];
      this.store.put(t, 'config-snapshot', 'current', { digest: digestNow, taken_at: now, sections }, now);
      this._configDrift.delete(t);
      if (this.store.get(t, 'config-flag', 'drift')) this.store.remove(t, 'config-flag', 'drift');
      this.store.audit(t, 'CONFIG_REASSERTED', p.subject_id, 'config', { config_digest: digestNow, changed_sections: changed, previous_sections: existing?.sections ?? null }, now);
      return { reasserted: true, config_digest: digestNow, changed_sections: changed };
    }, { allowDuringDrift: true });
  }
  // Clock recovery (concurrency-audit L6): the ledger clock is monotone and a
  // forward host-clock jump would otherwise wedge every tenant permanently —
  // transaction() itself throws INV-503-TIME before it can run recovery. This
  // deliberately bypasses transaction() and requires a security actor; the
  // recovery is audited. It moves the clock forward only — a backward step
  // would resurrect expired certificates (w9-network F4) and is refused.
  // Remediation for a poisoned tail: an unverifiable audit row wedges the
  // index by design, but the wedge must not be permanent. A security
  // operator seals the chain at the last verifiable row — every row after
  // it is removed under a signed AUDIT_SEALED event that records what was
  // dropped, so the tamper stays on the ledger's own evidence trail
  // (w13-timing NEW-MED-1). The append-only triggers are suspended only
  // inside this transaction: mid-chain corruption (a rewritten row below
  // the tail) cannot be sealed this way — that case fails loudly and
  // requires restore-check remediation instead.
  sealAuditChain(p) {
    const t = p.tenant_id;
    // Break-glass authorization: the usual chain-derived checks are exactly
    // what the seal repairs — a poisoned row wedges _auditIndex and would
    // take authorize() down with it. Gate on the frozen tenant identity
    // set instead (role asserted, revocation unknowable until the seal
    // lands — the seal itself is signed and records who ran it).
    const identity = Object.values(this.tenant(t).identities).find(v => v.subject_id === p.subject_id);
    requireThat(identity?.roles?.includes('security'), 'INV-403-ROLE', 'Role denied for security', 403);
    const keys = this.auditPublicKeys(t);
    const rows = this.store.db.prepare('SELECT seq,hash,envelope FROM audit WHERE tenant=? ORDER BY seq').all(t);
    // The seal scan enforces the same signing window the index does — a row
    // signed by a key the chain already killed (revoke or audit-class
    // rotation) is poison, not a verifiable leaf: otherwise a dead-key row
    // would verify, the seal would find nothing to cut, and the index
    // would stay wedged forever (w16-fixverify F3). Revocations seen on the
    // consumed prefix are also collected: an operator whose own revocation
    // is already on-chain cannot truncate the ledger that attests it
    // (w16-fixverify F10).
    const keyDeadAt = new Map(), revokedSeen = new Set(), auditSuccessions = new Map();
    // The scan must enforce the same acceptance rules as the fold — a row
    // that verifies here but violates the fold's future-time bound would be
    // reported "already verifies" while _auditIndex wedges: signed poison
    // the seal could never cut (w17-fixverify).
    const consumeNow = this.clock();
    let previous = '0'.repeat(64), firstBad = null, prevPlTime = 0;
    for (const r of rows) {
      let ok = false, env = null;
      try {
        env = JSON.parse(r.envelope);
        const kid = env?.protected?.key_id, deadAt = kid !== undefined ? keyDeadAt.get(kid) : undefined;
        ok = ctEqual(digest(env.payload), r.hash) && env.payload.sequence === r.seq && ctEqual(env.payload.previous, previous)
          && !(deadAt !== undefined && deadAt < r.seq)
          && (typeof env.payload.time !== 'number' || env.payload.time <= Math.max(consumeNow, prevPlTime) + 60_000)
          && verifySigned(env, keys, 'audit').tenant_id === t;
      } catch { ok = false; }
      if (!ok) { firstBad = r.seq; break; }
      previous = r.hash;
      prevPlTime = Math.max(prevPlTime, typeof env.payload.time === 'number' ? env.payload.time : prevPlTime);
      const meta = env.payload.metadata ?? {};
      if (env.payload.type === 'AUTHORITY_REVOKED') {
        revokedSeen.add(env.payload.reference);
        if (typeof env.payload.reference === 'string' && env.payload.reference.startsWith('key:')) keyDeadAt.set(env.payload.reference.slice(4), r.seq);
      }
      if (env.payload.type === 'KEY_ROTATED' && meta.key_class === 'audit' && meta.previous_key_id) {
        keyDeadAt.set(meta.previous_key_id, r.seq);
        auditSuccessions.set(env.payload.reference, meta.previous_key_id); // newest last, keyed by new key
      }
    }
    if (firstBad === null) return { sealed: false, reason: 'chain already verifies' };
    const [iid, ident] = Object.entries(this.tenant(t).identities).find(([, v]) => v.subject_id === p.subject_id) ?? [];
    const callerRefs = [`subject:${p.subject_id}`, `key:${iid}`, ...(ident?.device_id ? [`device:${ident.device_id}`] : [])];
    requireThat(!callerRefs.some(ref => revokedSeen.has(ref)), 'INV-403-QUARANTINE', 'A revoked identity cannot seal the audit chain', 403);
    let repointUndo = null;
    return this.store.tx(() => {
      const now = this.clock();
      // Suspend and restore the guards inside one transaction — if the
      // recreate fails the delete rolls back with it.
      for (const tr of this.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all()) this.store.db.exec(`DROP TRIGGER ${tr.name}`);
      // Attest what the DELETE actually removes, computed INSIDE the
      // transaction — rows appended between the pre-scan and the cut are
      // destroyed too and must be named in the signed record
      // (w17-redteam B1).
      const removed = this.store.db.prepare('SELECT hash FROM audit WHERE tenant=? AND seq>=? ORDER BY seq').all(t, firstBad).map(r => r.hash);
      this.store.db.prepare('DELETE FROM audit WHERE tenant=? AND seq>=?').run(t, firstBad);
      this.store.db.exec(`
        CREATE TRIGGER no_audit_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
        CREATE TRIGGER no_audit_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
        CREATE TRIGGER audit_seq_guard BEFORE INSERT ON audit
          WHEN NEW.seq <> (SELECT COALESCE(MAX(seq),0)+1 FROM audit WHERE tenant=NEW.tenant)
          BEGIN SELECT RAISE(ABORT, 'audit sequence must extend the head'); END;`);
      // The seal row itself must survive the signing window it just
      // enforced: when the consumed prefix killed the configured audit key,
      // repoint onto the newest chain-attested successor before sealing —
      // otherwise AUDIT_SEALED would be the next dead-key row it should
      // have cut (w16-fixverify F3).
      const tenant = this.tenant(t), configuredAudit = tenant.keys?.audit?.key_id;
      if (configuredAudit === undefined || keyDeadAt.has(configuredAudit)) {
        const needed = this._keyPurposes?.audit ?? [];
        let successor = [...auditSuccessions.keys()].reverse().find(k => {
          const e = this.vault.keys.get(k);
          return e && !e.revoked && e.generated_inside !== false && !keyDeadAt.has(k);
        });
        // No chain-attested succession (the key was revoked without a
        // rotation event): fall back to the newest live pending tenant-owned
        // vault key that covers the audit purposes — a revoke-without-rotate
        // must not leave the chain unsealable while a valid signer waits in
        // the vault (w17-fixverify).
        if (!successor)
          successor = [...this.vault.keys.entries()].reverse().find(([kid, e]) => e.pending && !e.revoked
            && e.generated_inside !== false && !keyDeadAt.has(kid) && this.ownsVaultKey(t, kid)
            && (e.purpose === 'any' || needed.every(x => (Array.isArray(e.purpose) ? e.purpose : [e.purpose]).includes(x))))?.[0];
        requireThat(successor, 'INV-503-CONFIG', 'No live audit signing key can attest the seal', 503);
        const entry = this.vault.keys.get(successor);
        const wasPending = entry.pending, savedTenant = this.tenant(t);
        if (entry.pending) this.vault.activate(successor);
        // In-memory repoint + activation happen inside the store tx but
        // cannot roll back with it — if the seal write aborts, restore the
        // binding so memory never claims a repoint the ledger rejected
        // (w17-redteam L1).
        repointUndo = () => { this.#tenants[t] = savedTenant; if (this.config?.tenants) this.config.tenants[t] = savedTenant; const e2 = this.vault.keys.get(successor); if (e2 && wasPending) e2.pending = true; };
        // Baseline BEFORE the repoint — the snapshot re-anchor below is
        // legitimate only when the pre-repoint config still matched the
        // chain's last attested baseline (a dirty baseline must stay drift).
        const preSections = this._configSections(this.tenant(t));
        const tn = clone(this.tenant(t));
        const previous = tn.keys.audit;
        tn.keys.audit = { key_id: successor, public_key: entry.public_key };
        // The outgoing key must stay advertised or the pre-rotation rows it
        // signed stop verifying — same retired bookkeeping the repoint in
        // _reconcileLedger performs.
        if (previous && !(tn.keys.retired ?? []).some(x => x.key_id === previous.key_id))
          tn.keys.retired = [...(tn.keys.retired ?? []), { key_class: 'audit', key_id: previous.key_id, public_key: previous.public_key, retired_at: now, derived: true }];
        this.#setTenant(t, tn);
        // The repoint is itself a sanctioned config delta — re-anchor it
        // like _reconcileLedger does or the tenant drift-quarantines
        // forever for the repair it just performed (w17-fixverify).
        const anchoredBaseline = this._anchoredConfigSnapshot(t);
        if (anchoredBaseline === null || digest({ tenant: t, sections: preSections }) === anchoredBaseline) {
          const postSections = this._configSections(this.tenant(t));
          this.store.audit(t, 'CONFIG_SNAPSHOT', p.subject_id, 'config', { config_digest: digest({ tenant: t, sections: postSections }) }, now);
          this.store.put(t, 'config-snapshot', 'current', { digest: digest({ tenant: t, sections: postSections }), taken_at: now, sections: postSections }, now);
        }
      }
      try { this.store.audit(t, 'AUDIT_SEALED', p.subject_id, 'audit', { sealed_at_seq: firstBad, removed_count: removed.length, removed_head: removed[0] ?? null, removed_tail: removed.at(-1) ?? null }, now); }
      catch (sealErr) { repointUndo?.(); throw sealErr; }
      this.#auditIdx?.delete(t);
      return { sealed: true, sealed_at_seq: firstBad, removed_count: removed.length };
    });
  }
  recoverClock(p) {
    this.authorize(p, ['security', 'policy_admin']);
    return this.store.tx(() => {
      const now = this.clock();
      const prior = this.store.db.prepare('SELECT last FROM clock WHERE id=1').get()?.last ?? null;
      // A backward step (snapshot restore) is survivable, but never silently:
      // it must not re-open the validity window of any authority that the
      // ledger watched lapse. Any certificate or live-status capsule whose
      // expiry falls inside the rewound span would resurrect — refuse
      // (w9-network F4). Forward steps need no such check.
      if (prior !== null && now < prior) {
        for (const tenant of Object.keys(this.#tenants)) {
          const idx = this._auditIndex(tenant);
          // Enumeration must not cap at a fixed page — a flooded table
          // would push a real certificate past the limit and let a rewind
          // resurrect it (w17-redteam E2). Rows are tolerated per-record
          // and only chain-anchored state may veto: a planted certificate
          // envelope fails verification, and a planted or rewritten capsule
          // never matches its anchored proposed digest (w17-fixverify L3).
          for (let off = 0;; off += 5000) {
            const ids = this.store.ids(tenant, 'certificate', 5000, off);
            if (!ids.length) break;
            for (const id of ids) {
              let c; try { c = this.store.get(tenant, 'certificate', id); } catch { continue; }
              if (!c || !(idx.issuedCerts ?? new Set()).has(id)) continue;
              if (c.consumed || idx.reserved.has(id)) continue;
              let envOk = false; try { envOk = !!verifySigned(c.envelope, this.executionPublic(tenant), 'action-certificate'); } catch { envOk = false; }
              if (!envOk) continue;
              const exp = c.envelope.payload.expires_at;
              requireThat(exp <= now || exp > prior, 'INV-503-TIME', 'Clock recovery would resurrect an expired certificate', 503);
            }
          }
          for (let off = 0;; off += 5000) {
            const ids = this.store.ids(tenant, 'capsule', 5000, off);
            if (!ids.length) break;
            for (const id of ids) {
              let r; try { r = this.store.get(tenant, 'capsule', id); } catch { continue; }
              if (!r) continue;
              const anchoredCapsuleDigest = idx.proposedDigest?.get(id);
              if (anchoredCapsuleDigest === undefined || digest(r.capsule) !== anchoredCapsuleDigest) continue;
              if (['VERIFIED', 'UNCERTAIN', 'FAILED', 'COMPENSATED', 'CANCELLED', 'EXECUTING'].includes(r.status)) continue;
              requireThat(r.capsule.expires_at <= now || r.capsule.expires_at > prior, 'INV-503-TIME', 'Clock recovery would resurrect an expired action', 503);
            }
          }
        }
      }
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
  authorize(p, roles, { auditDeny = true } = {}) {
    // Authentication denials are security events too — an unknown tenant or
    // an unmapped subject must leave a signed ledger trace before the gate
    // ever throws (w11-redteam R13).
    if (!(p && Object.hasOwn(this.#tenants, p.tenant_id))) {
      if (auditDeny && !this.store.db.isTransaction) this._rejectionAudit(p?.tenant_id ?? 'unknown', p?.subject_id ?? 'anonymous', 'INV-401-AUTH', 'Authentication required');
      requireThat(false, 'INV-401-AUTH', 'Authentication required', 401);
    }
    let identity;
    try { identity = this.identity(p); } catch (error) { if (error instanceof InvariantError && auditDeny && !this.store.db.isTransaction) this._rejectionAudit(p.tenant_id, p.subject_id, error.code, error.message); throw error; }
    const effective = this.grantsFor(p.tenant_id, p.subject_id, this.clock()).roles ?? identity.roles;
    const denied = !effective.some(r => roles.includes(r));
    // A rejection raised outside a transaction would otherwise leave no
    // trace — hostile role probing must land in the ledger too (w11 F7).
    if (denied && auditDeny && !this.store.db.isTransaction) this._rejectionAudit(p.tenant_id, p.subject_id, 'INV-403-ROLE', `Role denied for ${roles.join('/')}`);
    requireThat(!denied, 'INV-403-ROLE', 'Permission denied', 403);
    requireThat(!this.revoked(p.tenant_id, 'subject', p.subject_id), 'INV-403-QUARANTINE', 'Identity unavailable', 403);
    return identity;
  }
  // Denials raised before the store transaction opens never reached the
  // audit chain — every reject path that can fire pre-transaction reports
  // itself (w11 F7). Audit failure must never mask the original denial.
  _rejectionAudit(t, subject_id, code, message, details = null) {
    const now = this.clock();
    // A denied request costs one signed ledger write — without a bound a low
    // role could grow the chain at its request rate limit indefinitely.
    // Identical denials re-record at most once per 60s: the ledger still
    // proves the denial happened, just not at request frequency
    // (w11-timing NEW-LOW-1). Best-effort, in-memory across restarts.
    this.#denyAudit ??= new Map();
    // The dedup key excludes the free-text message — an attacker varying
    // the string cannot un-budget the ledger (w13-timing M-1).
    const key = `${t}${subject_id}${code}`, last = this.#denyAudit.get(key);
    if (last !== undefined && now - last < 60_000) return;
    this.#denyAudit.set(key, now);
    try { this.store.audit(t, 'AUTHORIZATION_DENIED', subject_id ?? 'anonymous', null, { code, message: String(message).slice(0, 200) }, now); } catch { /* ledger write failure does not change the verdict */ }
    // Quarantine denials land in the containment ledger too — a quarantined
    // device hammering proposals must be reconstructible, not invisible
    // (w11-lifecycle F5; NET-010 coverage of pre-transaction denials).
    if (details?.quarantine_denial) {
      try { this.store.put(t, 'containment', `deny:${randomUUID()}`, { contained_at: now, subject_id: subject_id ?? null, device_id: details.device ?? null, capability_id: null, resource: null, destination: null, action: null, code, request_id: 'gate-deny', dropped_requests: 1 }, now); } catch { /* containment logging never masks the verdict */ }
    }
  }
  // Stored-record integrity anchored in the actor's own signature: the
  // request_intent envelope covers the capsule's proposal fields, so a
  // store-level tamper that forgets (or cannot) re-sign is detected — the
  // stored capsule_digest field is not trusted as the anchor (w11 F1/F2).
  _capsuleIntegrity(t, record) {
    const intent = record?.capsule?.request_intent;
    requireThat(intent && typeof intent === 'object', 'INV-409-INTEGRITY', 'Capsule carries no signed request intent', 409);
    const kid = intent?.protected?.key_id, signer = kid ? this.identities(t)[kid] : null;
    requireThat(signer, 'INV-409-INTEGRITY', 'Request intent signed by an unknown identity', 409);
    let payload = null;
    try { payload = verifySigned(intent, { [kid]: { public_key: signer.public_key } }, 'capsule-intent'); } catch { payload = null; }
    requireThat(payload, 'INV-409-INTEGRITY', 'Request intent signature no longer verifies', 409);
    const { request_intent, capsule_id, tenant_id, received_at, ...signedInput } = record.capsule;
    requireThat(digest(payload) === digest(signedInput), 'INV-409-INTEGRITY', 'Stored capsule diverged from the signed request intent', 409);
    requireThat(record.capsule_digest === digest(record.capsule), 'INV-409-INTEGRITY', 'Stored capsule digest does not match its contents', 409);
    // The chain-attested proposal digest is the unforgeable binding: an
    // in-place rewrite of the stored capsule (e.g. a composite's children
    // list) recomputes away from the anchored value no matter which of
    // the two fields the writer edits (w13-timing M-3).
    requireThat(record.capsule_digest === this._auditIndex(t).proposedDigest.get(record.capsule.capsule_id), 'INV-409-INTEGRITY', 'Capsule diverges from its ledger-anchored proposal', 409);
    return payload;
  }
  // A stored outcome is only trustworthy as a vault-signed envelope — a
  // planted row (store-level write without vault access) fails the
  // signature, never just shape (w11 F5).
  _outcomeIntegrity(t, envelope, expectId = null) {
    // The payload's certificate_id must equal the row key it is served
    // under: a real signed outcome transplanted onto a sibling key returns
    // the wrong certificate's verdict (w12-provenance F18).
    if (expectId !== null) requireThat(envelope?.payload?.certificate_id === expectId, 'INV-409-INTEGRITY', 'Outcome does not belong to this certificate', 409);
    // keys.get, not entry(): a pending key must still verify the recovery
    // envelopes it legitimately signed (w11-lifecycle F2) — only its
    // signature path is gated, never its verification. The revoked flag is
    // likewise NOT consulted here: revocation is not retroactive erasure —
    // a retired key's authentic signatures remain verifiable history, so
    // routine rotation must not invalidate pre-rotation outcomes
    // (w11-timing NEW-MED-1).
    // Verification runs against the ATTESTED audit keyset, not a bare
    // vault lookup: an injected keys.set entry (bogus wrapped) or an
    // imported key (generated_inside === false) must never verify an
    // outcome row — only gate-provenanced signers may (w13-store F10).
    // An unverifiable or non-outcome envelope is tamper evidence — it must
    // surface as INTEGRITY, not as a signer/auth failure (w11 F5).
    try { verifySigned(envelope, this.auditPublicKeys(t), 'outcome'); } catch (e) { throw new InvariantError('INV-409-INTEGRITY', 'Outcome envelope fails ledger signature verification', 409); }
    // A VERIFIED verdict must correspond to a real dispatch: the outcome
    // commits the journal digest, and the journal row must still match —
    // a planted (even validly-signed) outcome cannot impersonate an
    // execution the target never journaled (w11-redteam R14).
    const pl = envelope.payload;
    if (pl?.status === 'VERIFIED' && !pl?.composite && pl?.journal_digest) {
      const journal = this.target.outcome(t, pl.certificate_id);
      requireThat(journal && digest(journal) === pl.journal_digest, 'INV-409-INTEGRITY', 'Outcome journal digest does not match the durable dispatch journal', 409);
    }
    return envelope;
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
    const idx = this._auditIndex(tenant);
    for (const g of this.target.grants(tenant, subject_id, now)) {
      // A grants-table row is derived state, never authority: it is honored
      // only when a ledger JIT_GRANT_ISSUED event anchors it — either by
      // scope_digest or, for pre-upgrade grants, by the issuing request's
      // digest with every row field proven equal (w11-redteam R2/R11,
      // w16-fixverify F4).
      // A ledger-revoked grant is dead no matter what the mutable row says
      // — the dataplane flag is a cache; idx.revoked is the authority
      // (w17-idx F2).
      if (idx.revoked.has(`grant:${g.grant_id}`)) continue;
      if (!this._grantAnchored(tenant, idx, g.grant_id, g)) continue;
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
      // The version ladder may only consume ANCHORED content: the mutable
      // 'active' row supplies the baseline version solely when it matches
      // its last non-staged ledger anchor — otherwise a planted row
      // regresses the constitution and the signed POLICY_ACTIVATED
      // launders the regression (w17-idx F1).
      const activeAnchor = [...this._auditIndex(t).policyAnchors].reverse().find(a => !a.staged);
      // A due-but-stale row (superseded version race, or expired before its
      // slot) must never wedge every transaction — retire it honestly and
      // move on (policy-audit F1/F3).
      if (!activeAnchor || digest(active) !== activeAnchor.digest || staged.policy.version !== active.version + 1 || staged.policy.expires_at <= now) {
        this.store.remove(t, 'policy', 'staged');
        this.store.audit(t, 'POLICY_SUPERSEDED', 'system', staged.policy.policy_id, { version: staged.policy.version, reason: !activeAnchor || digest(active) !== activeAnchor.digest ? 'divergent-active-row' : (staged.policy.expires_at <= now ? 'expired-before-activation' : 'version-superseded') }, now);
        return null;
      }
      // The promoter must demand the same ledger anchor the getter does —
      // a store-level 'staged' write can never launder into an anchored
      // active constitution by being promoted (w12-lifecycle F2). An
      // unanchored staged row is tamper evidence: retire it loudly instead
      // of letting a mutable row mint a signed POLICY_ACTIVATED.
      const stagedAnchored = this._auditIndex(t).policyAnchors.some(a => a.staged && a.digest === digest(staged.policy));
      if (!stagedAnchored) {
        this.store.remove(t, 'policy', 'staged');
        this.store.audit(t, 'POLICY_SUPERSEDED', 'system', staged.policy.policy_id, { version: staged.policy.version, reason: 'unanchored-staged-row', policy_digest: digest(staged.policy) }, now);
        return null;
      }
      this.store.put(t, 'policy', 'active', staged.policy, now);
      this.store.remove(t, 'policy', 'staged');
      this.store.put(t, 'policy-history', `v${staged.policy.version}`, { activated_at: now, digest: digest(staged.policy), staged: true, emergency: staged.policy.emergency_of !== undefined }, now);
      this.store.audit(t, staged.policy.emergency_of !== undefined ? 'EMERGENCY_POLICY_ACTIVATED' : 'POLICY_ACTIVATED', 'system', staged.policy.policy_id, { version: staged.policy.version, staged_from: staged.staged_at, policy_digest: digest(staged.policy) }, now);
      return staged.policy;
    }
    return null;
  }
  transaction(principal, fn, { allowDuringDrift = false } = {}) {
    try {
      this.authorize(principal, ['operator', 'approver', 'custodian', 'security', 'auditor', 'policy_admin', 'workload'], { auditDeny: false });
      // RUN-010: a drifting gate configuration withdraws privileges until a
      // security actor re-attests the observed config snapshot.
      // Drift quarantine is durable (a 'config-flag' record), not just the
      // in-memory set — a second Fabric instance on the same deployment
      // cannot transact through a drift it never noticed (concurrency-audit M4).
      requireThat(allowDuringDrift || (!this._configDrift.has(principal.tenant_id) && !this._auditIndex(principal.tenant_id).tenantDrifted), 'INV-403-QUARANTINE', 'Configuration drift withdrew gate privileges pending security re-attestation', 403);
      return this.store.tx(() => { const now = this.clock(); this.store.clock(now); this.activateDuePolicies(principal.tenant_id, now); return fn(now); });
    }
    catch (error) {
      // A rolled-back transaction may have let a reader project chain rows
      // that never committed — the cached index would retain a phantom
      // anchor forever (w12-provenance F11). But routine denials (bad id,
      // schema, health) throw just the same: dropping the whole index on
      // every error lets a low-priv principal force a full-chain re-verify
      // per request (w15-timing F8). Delete only when the fold could have
      // seen uncommitted rows — i.e. its head is ahead of the committed
      // head after rollback.
      const cachedIdx = this.#auditIdx?.get(principal?.tenant_id);
      if (cachedIdx && principal?.tenant_id && cachedIdx.maxSeq > this.store.auditHeadSeq(principal.tenant_id)) this.#auditIdx.delete(principal.tenant_id);
      // Every gate-level refusal — schema, actor, intent, health, role —
      // lands in the ledger even when it fired before the transaction could
      // commit (w11-redteam R13). The 60s identical-denial bound inside
      // _rejectionAudit keeps flood cost capped.
      if (error instanceof InvariantError) this._rejectionAudit(principal?.tenant_id ?? 'unknown', principal?.subject_id ?? 'anonymous', error.code, error.message, error.details);
      if (error instanceof InvariantError && error.code !== 'INV-503-TIME') {
        // A failing rejection-audit tx must not mask the original error (L1).
        // Identical (subject, code) rejections re-record at most once per
        // 60s — the same bound _rejectionAudit enforces on gate denials;
        // an unbounded chain row per crafted request is a write amplifier
        // (w17-idx F7).
        const rNow = this.clock(), rKey = `${principal?.tenant_id ?? 'unknown'} ${principal?.subject_id ?? 'anonymous'} ${error.code}`;
        if (rNow - (this.#rejectMemo.get(rKey) ?? -Infinity) >= 60_000) {
          this.#rejectMemo.set(rKey, rNow);
          try { this.store.tx(() => { const now = this.clock(); this.store.clock(now); this.store.audit(principal.tenant_id, 'SECURITY_OPERATION_REJECTED', principal.subject_id, 'local-gate', { code: error.code }, now); }); } catch { /* ledger unavailable — surface the real rejection */ }
        }
        // Quarantine denials land in the containment ledger too — NET-010
        // reconstruction must see denied executes/proposes, not only denied
        // consume calls (w9-network F7). Best-effort like the audit row.
        if (error.code === 'INV-403-QUARANTINE' && error.details?.quarantine_denial) {
          try { const n0 = this.clock(); this.store.tx(() => this.store.put(principal.tenant_id, 'containment', `deny:${randomUUID()}`, { contained_at: n0, subject_id: principal.subject_id, device_id: error.details.device ?? null, capability_id: null, resource: null, destination: null, action: null, code: error.code, request_id: `gate-deny`, dropped_requests: 1 }, n0)); } catch { /* containment logging never masks the original denial */ }
        }
        throw error;
      }
      if (error instanceof InvariantError) throw error;
      // RUN-009: infrastructure failures get a stable documented code instead
      // of leaking driver internals (e.g. node:sqlite ERR_INVALID_STATE).
      throw new InvariantError('INV-503-GATE', 'Internal gate failure', 503);
    }
  }
  // RUN-010: the snapshot watches every security-bearing config section —
  // identities, issuers, policy, the bearer-token map, key bindings and
  // custody flags, perception trust anchors, and the data-key material
  // itself (private halves stay out of the digest; the vault/embedded
  // custody flag still pins them) — a forged credential or swapped anchor
  // must trip drift exactly like an edited identity set (w9-network F1).
  _configSections(tenant) {
    const keys = Object.fromEntries(Object.entries(tenant.keys ?? {}).map(([klass, v]) => [klass, klass === 'retired' ? (v ?? []).map(r => ({ key_class: r.key_class, key_id: r.key_id, public_key: r.public_key, retired_at: r.retired_at })) : { key_id: v.key_id, public_key: v.public_key, custody: v.custody ?? null }]));
    return {
      identities: digest(tenant.identities), issuers: digest(tenant.issuers), genesis_policy: digest(tenant.genesis_policy), gate_id: digest(this.config.gate_id),
      auth: digest(tenant.auth ?? {}), keys: digest(keys), components: digest(tenant.components ?? {}),
      data_keys: digest({ encryption_key_wrapped: tenant.encryption_key_wrapped ?? null, encryption_key: tenant.encryption_key ? digest(tenant.encryption_key) : null, watermark_key_wrapped: tenant.watermark_key_wrapped ?? null, watermark_key: tenant.watermark_key ? digest(tenant.watermark_key) : null })
    };
  }
  // Record-provenance layer (w11-redteam R1-R16): every security-significant
  // store row is a trusted mutable input only in the naive model. The
  // authoritative state of a revocation, a certificate issuance, an evidence
  // attachment, a policy activation, a JIT grant, a consumed nonce or a data
  // egress is derived from the chained, vault-signed audit events — a forged
  // or deleted records row cannot mint authority without forging a signed,
  // hash-chained ledger entry. The index is incremental over audit sequence:
  // rows deleted mid-table cannot un-anchor what the chain already attested.
  _auditIndex(t) {
    const maxSeq = this.store.db.prepare('SELECT COALESCE(MAX(seq),0) m FROM audit WHERE tenant=?').get(t).m;
    let idx = this.#auditIdx.get(t);
    if (!idx) { idx = { maxSeq: 0, building: false, revoked: new Set(), attached: new Map(), proposedNonce: new Set(), proposedAt: new Map(), proposedDigest: new Map(), issued: new Set(), issuedCert: new Map(), issuedCerts: new Set(), grants: new Map(), grantMeta: new Map(), rotations: new Map(), rotationsByPrev: new Map(), rotationKeys: new Set(), policyAnchors: [], dataAccess: [], perceptionNonce: new Set(), reserved: new Set(), dispatched: new Map(), outcomes: new Map(), keyDeadAt: new Map(), parentChildren: new Map(), simulated: [], issuerDrift: new Set(), tenantDrifted: false, configSnapshot: null, decisions: new Map(), runtimeUse: [], runtimeUseByCap: new Map(), runtimeUseBySubject: new Map(), revocationDigests: new Map(), denials: [], denialsByReq: new Map(), ceremonyAcks: new Map(), ceremonyPlanned: new Map(), ceremonyCommitted: new Map(), coverageAnchors: new Map() }; this.#auditIdx.set(t, idx); }
    // Re-entrancy must fail closed: a nested caller handed the mid-fold
    // partial projection could observe anchors that the committed chain
    // never attested (w17-idx F9). Nothing inside the fold recurses
    // today — if a future path does, it wedges loudly, never silently.
    requireThat(!idx.building, 'INV-503-INTEGRITY', 'Re-entrant audit index fold', 503);
    // Same-seq head replacement cannot resync silently: the stored head row
    // must still carry the hash the index last consumed — otherwise a
    // tail rewrite slipped under the MAX(seq) watermark (w12-provenance F10).
    if (idx.maxSeq > 0 && idx.headHash !== undefined) {
      const head = this.store.db.prepare('SELECT hash FROM audit WHERE tenant=? AND seq=?').get(t, idx.maxSeq);
      requireThat(head && ctEqual(head.hash, idx.headHash), 'INV-409-AUDIT-TAMPER', 'Audit head diverged from the consumed index', 409);
    }
    if (idx.maxSeq === maxSeq) return idx;
    // Signature-trust boundary: the seq trigger lets an in-process writer
    // append a self-consistent row whose hash and `previous` link are forged
    // but whose envelope cannot be vault-signed. Every consumed event must
    // verify against the tenant's audit keys (retired ones stay verifiable —
    // w12 red-team) and carry this tenant's id. Replay needs no separate
    // check: a re-inserted envelope can never satisfy the stored-row binding
    // (payload.sequence/previous) that auditPage already enforces, and
    // chain time may legitimately regress across racing writers.
    idx.building = true;
    const keys = this.auditPublicKeys(t);
    idx.keyDeadAt ??= new Map();
    idx.proposedDigest ??= new Map();
    idx.revocationDigests ??= new Map();
    idx.denials ??= [];
    idx.issuedCert ??= new Map();
    idx.grantMeta ??= new Map();
    idx.rotations ??= new Map();
    idx.ceremonyAcks ??= new Map();
    idx.issuedCerts ??= new Set();
    idx.rotationsByPrev ??= new Map();
    idx.rotationKeys ??= new Set();
    idx.ceremonyPlanned ??= new Map();
    idx.ceremonyCommitted ??= new Map();
    idx.coverageAnchors ??= new Map();
    idx.runtimeUseByCap ??= new Map();
    idx.runtimeUseBySubject ??= new Map();
    idx.denialsByReq ??= new Map();
    const consumeNow = this.clock();
    let prevPlTime = idx.prevPlTime ?? 0;
    try {
      for (const e of this.store.auditPage(t, { after: idx.maxSeq, limit: 2_000_000 }).entries) {
      // Signing-window enforcement (w13-supply W13-01): a revoked or
      // rotated-out key keeps verifying entries signed during its
      // authority but can never mint an entry appended AFTER its on-chain
      // death — the verification set is still every legitimate key, the
      // window binds which seqs it may cover.
      const kid = e.envelope?.protected?.key_id, deadAt = kid !== undefined ? idx.keyDeadAt.get(kid) : undefined;
      let pl; try { pl = e.envelope && !(deadAt !== undefined && deadAt < e.sequence) ? verifySigned(e.envelope, keys, 'audit') : null; } catch { pl = null; }
      requireThat(pl && pl.tenant_id === t, 'INV-409-INTEGRITY', 'Audit row fails ledger signature verification', 409);
      // Time-sanity bound (w13-supply W13-04): a forged row claiming a
      // far-future timestamp can never be consumed silently — chain time
      // may exceed the operator clock only by the previous entry's own
      // stamp (legitimate rewinds) plus a read-race allowance. Rows that
      // fail wedge the index; remediation is the seal runbook.
      requireThat(typeof pl.time !== 'number' || pl.time <= Math.max(consumeNow, prevPlTime) + 60_000, 'INV-409-INTEGRITY', 'Audit row claims an impossible future timestamp', 409);
      prevPlTime = Math.max(prevPlTime, typeof pl.time === 'number' ? pl.time : prevPlTime);
      const meta = pl.metadata ?? {};
      switch (pl.type) {
        case 'AUTHORITY_REVOKED': idx.revoked.add(pl.reference);
          if (meta.record_digest) idx.revocationDigests.set(pl.reference, meta.record_digest);
          // The revocation row itself may still be signed by the dying
          // key — the window closes only for LATER seqs.
          if (typeof pl.reference === 'string' && pl.reference.startsWith('key:')) idx.keyDeadAt.set(pl.reference.slice(4), e.sequence);
          break;
        case 'KEY_ROTATED':
          if (meta.key_class === 'audit' && meta.previous_key_id) idx.keyDeadAt.set(meta.previous_key_id, e.sequence);
          // The newest anchored succession per class is the only authority
          // a key-binding repoint may follow — 'key-rotation' records are
          // forgeable hints, never the selector (w16-fixverify F3/F13).
          if (typeof meta.key_class === 'string' && typeof pl.reference === 'string') idx.rotations.set(meta.key_class, { new_key_id: pl.reference, previous_key_id: meta.previous_key_id ?? null, at: pl.time });
          // Every anchored key is chain-bound to this tenant (ownership
          // for ledger-significant ops), and each predecessor maps to its
          // successor for O(1) steering — no records scan, no full-chain
          // re-verify per signing call (w17-redteam C3, w17-idx F6).
          if (typeof pl.reference === 'string') idx.rotationKeys.add(pl.reference);
          if (typeof meta.previous_key_id === 'string') idx.rotationKeys.add(meta.previous_key_id);
          if (typeof meta.key_class === 'string' && typeof meta.previous_key_id === 'string' && typeof pl.reference === 'string') idx.rotationsByPrev.set(`${meta.key_class}:${meta.previous_key_id}`, pl.reference);
          break;
        case 'ROTATION_PREPARED': if (typeof pl.reference === 'string') idx.rotationKeys.add(pl.reference); break;
        case 'EVIDENCE_ATTACHED': { const l = idx.attached.get(pl.reference) ?? []; l.push(meta.evidence_id); idx.attached.set(pl.reference, l); break; }
        case 'CAPSULE_PROPOSED': idx.proposedAt.set(pl.reference, pl.time); if (meta.nonce) idx.proposedNonce.add(meta.nonce); if (meta.capsule_digest) idx.proposedDigest.set(pl.reference, meta.capsule_digest); break;
        case 'CERTIFICATE_ISSUED': idx.issued.add(pl.reference); if (meta.certificate_id) { idx.issuedCert.set(pl.reference, meta.certificate_id); idx.issuedCerts.add(meta.certificate_id); } if (Array.isArray(meta.children)) idx.parentChildren.set(pl.reference, meta.children); break;
        case 'JIT_GRANT_ISSUED': idx.grants.set(meta.grant_id, meta.scope_digest ?? meta.grant_digest); if (meta.grant_id) idx.grantMeta.set(meta.grant_id, { expires_at: meta.expires_at, at: pl.time }); break;
        case 'POLICY_GENESIS': case 'POLICY_ACTIVATED': case 'EMERGENCY_POLICY_ACTIVATED': if (meta.policy_digest) idx.policyAnchors.push({ staged: false, digest: meta.policy_digest }); break;
        case 'POLICY_STAGED': if (meta.policy_digest) idx.policyAnchors.push({ staged: true, digest: meta.policy_digest }); break;
        case 'POLICY_SIMULATED': if (meta.candidate_digest) idx.simulated.push({ candidate_digest: meta.candidate_digest, baseline_digest: meta.baseline_digest ?? null, at: pl.time }); break;
        case 'CONNECTOR_DRIFT': idx.issuerDrift.add(pl.reference); break;
        case 'CONNECTOR_REVALIDATED': idx.issuerDrift.delete(pl.reference); break;
        case 'CONFIG_DRIFT': case 'CONFIG_REASSERTED': if (meta.config_digest) idx.configSnapshot = meta.config_digest; break;
        case 'CONFIG_SNAPSHOT': if (meta.config_digest) idx.configSnapshot = meta.config_digest; break;
        case 'POLICY_EVALUATED': if (meta.decision_digest) idx.decisions.set(pl.reference, meta.decision_digest); break;
        // Per-capability and per-subject indexes keep consume() checks
        // bounded — a linear pass over the whole runtime history per
        // request was a quadratic wall-clock sink (w17-idx F8).
        case 'RUNTIME_ALLOWED': { const u = { capability: pl.reference, subject: pl.actor, resource: meta.resource ?? null, request_id: meta.request_id ?? null, cost: typeof meta.cost === 'number' ? meta.cost : 0, at: pl.time }; idx.runtimeUse.push(u); const cl = idx.runtimeUseByCap.get(u.capability) ?? []; cl.push(u); idx.runtimeUseByCap.set(u.capability, cl); const sl = idx.runtimeUseBySubject.get(u.subject) ?? []; sl.push(u); idx.runtimeUseBySubject.set(u.subject, sl); break; }
        case 'PERCEPTION_SESSION': if (meta.nonce) idx.perceptionNonce.add(meta.nonce); break;
        case 'DATA_ACCESSED': idx.dataAccess.push({ subject: pl.reference, dataset: meta.dataset, row_ids: meta.row_ids ?? [], columns: meta.columns ?? [], at: meta.at ?? pl.time, certificate_id: meta.certificate_id ?? null }); break;
        case 'EXECUTION_RESERVED': idx.reserved.add(pl.reference); break;
        case 'EXECUTION_DISPATCHED': if (meta.journal_digest) idx.dispatched.set(pl.reference, meta.journal_digest); break;
        case 'EXECUTION_OUTCOME': idx.outcomes.set(pl.reference, meta.status); break;
        case 'ACTION_CANCELLED': if (meta.certificate_id) idx.outcomes.set(meta.certificate_id, 'CANCELLED'); break;
        case 'RUNTIME_DENIED': { const d = { request_id: pl.reference, actor: pl.actor, code: meta.code ?? null, capability_id: meta.capability_id ?? null, at: pl.time }; idx.denials.push(d); const rl = idx.denialsByReq.get(d.request_id) ?? []; rl.push(d); idx.denialsByReq.set(d.request_id, rl); break; }
        case 'COVERAGE_DECLARED': if (meta.digest) idx.coverageAnchors.set(pl.reference, meta.digest); break;
        case 'CEREMONY_PLANNED': if (meta.digest) idx.ceremonyPlanned.set(pl.reference, meta.digest); break;
        case 'CEREMONY_SHARES_COMMITTED': idx.ceremonyCommitted.set(pl.reference, pl.time); break;
        // Only a chain-recorded acknowledgement attests that the consent
        // flow ran — the mutable ceremony row's ack list is a cache, never
        // the quorum's authority (w17-fixverify H1).
        case 'CEREMONY_ACKNOWLEDGED': if (meta.custodian === pl.actor) { const s = idx.ceremonyAcks.get(pl.reference) ?? new Set(); s.add(pl.actor); idx.ceremonyAcks.set(pl.reference, s); } break;
      }
        idx.maxSeq = Math.max(idx.maxSeq, e.sequence ?? 0);
      }
      // Stamp the LAST CONSUMED seq, not the page head — a tenant over the
      // page limit must not claim full coverage while mid-table rows went
      // unread (w12-supply W12-04). The head pin tracks the consumed tip.
      const tip = this.store.db.prepare('SELECT hash FROM audit WHERE tenant=? AND seq=?').get(t, idx.maxSeq);
      idx.headHash = tip?.hash;
      idx.prevPlTime = prevPlTime;
      // Unanchored floor = tamper: every 'revocation' record row must trace
      // to a consumed AUTHORITY_REVOKED event. Deleting the event before
      // the index consumes it can no longer silently un-revoke — the
      // surviving floor row indicts the gap and closes the gate
      // (w12-provenance F9). Checked inside the build, not per revoked()
      // call: during the revoke transaction itself the floor row lands a
      // beat after its event, so a per-call check would deadlock the
      // writer.
      for (const row of this.store.db.prepare("SELECT id FROM records WHERE tenant=? AND kind='revocation'").all(t))
        requireThat(idx.revoked.has(row.id), 'INV-409-INTEGRITY', 'Revocation state diverges from the ledger', 409);
      // Anchored config-drift: the last SIGNED snapshot is the baseline,
      // not a mutable record — a forged/deleted 'config-flag' or
      // 'config-snapshot' row can no longer withdraw or restore gate
      // privileges (w13-fixverify M4). The flag is CURRENT divergence:
      // a tampered-then-reverted config is honestly clean, while a
      // CONFIG_DRIFT event trail keeps the history. A tenant whose chain
      // never anchored a snapshot skips the check (pre-upgrade ledgers).
      if (idx.configSnapshot !== null) {
        const current = digest({ tenant: t, sections: this._configSections(this.tenant(t)) });
        idx.tenantDrifted = idx.configSnapshot !== current;
      }
    } catch (err) {
      // A fold that throws after stamping consumed seqs must not leave its
      // watermark committed — the next call would early-return over the
      // very row it rejected, turning a clean wedge into a flapping one
      // (w17-redteam C2). Evict so every call re-verifies from scratch.
      this.#auditIdx.delete(t);
      throw err;
    } finally { idx.building = false; }
    return idx;
  }
  revoked(tenant, kind, id) { return this._auditIndex(tenant).revoked.has(`${kind}:${id}`); }
  // Break-glass anchor repair (w13-fixverify H3): a pre-upgrade ledger can
  // hold an active policy whose activation event never carried a digest —
  // the anchor check inside policy() then throws INV-409 on every call and
  // no in-band path exists to recover. A security actor re-anchors the
  // CURRENT stored policy under a signed POLICY_ACTIVATED event marked as
  // remediation; refused while the anchor is already healthy so this can
  // never launder a forged 'active' row into trust.
  reanchorPolicy(p) {
    this.authorize(p, ['security']);
    return this.transaction(p, now => {
      const t = p.tenant_id, active = this.store.get(t, 'policy', 'active');
      const anchors = this._auditIndex(t).policyAnchors, anchor = [...anchors].reverse().find(a => !a.staged);
      // Bootstrapping is the documented purpose: a pre-upgrade ledger has
      // no digest anchor at all, and `anchor &&` made the first anchor
      // unreachable. The break-glass may fire whenever the anchor is
      // missing OR divergent — never when it already attests the row
      // (w16-fixverify F6).
      requireThat(!anchor || !active || digest(active) !== anchor.digest, 'INV-409-STATE', 'Active policy already matches its ledger anchor', 409);
      // The anchored content is the only provable legitimacy: with NO
      // anchor at all the only in-band truth is the custodian-signed
      // genesis constitution, and a divergent active row may only be
      // RESTORED from a retrievable copy matching the anchor — signing an
      // anchor over attacker-supplied row content would launder a forged
      // constitution into a permanent indistinguishable truth
      // (w17-redteam A1). If no retrievable copy of the anchored
      // constitution exists, the ledger stays honest and wedge-loud.
      const genesis = this.tenant(t).genesis_policy;
      let restored;
      if (!anchor) {
        restored = genesis;
        requireThat(!active || digest(active) === digest(genesis), 'INV-409-INTEGRITY', 'First anchor may only attest the custodian-signed genesis policy — delete the divergent row out-of-band first', 409);
      } else {
        const candidates = [active, this.store.get(t, 'policy', 'staged')?.policy, genesis].filter(x => x && digest(x) === anchor.digest);
        requireThat(candidates.length > 0, 'INV-409-INTEGRITY', 'Active policy diverges from its anchor and no retrievable copy of the anchored constitution exists', 409);
        restored = candidates[0];
      }
      if (!active || digest(active) !== digest(restored)) this.store.put(t, 'policy', 'active', restored, now);
      const sealMeta = { version: restored.version, policy_digest: digest(restored), reanchored: true, previous_anchor_digest: anchor?.digest ?? null };
      if (anchor) sealMeta.restored_from_divergence = true;
      this.store.audit(t, 'POLICY_ACTIVATED', p.subject_id, restored.policy_id, sealMeta, now);
      return { reanchored: true, policy_id: restored.policy_id, version: restored.version, policy_digest: digest(restored), limitation: 'Anchors the observed stored policy — verify it matches the intended constitution before resuming traffic (RUNBOOKS).' };
    });
  }
  policy(t) {
    const staged = this.store.get(t, 'policy', 'staged'), active = this.store.must(t, 'policy', 'active');
    const anchors = this._auditIndex(t).policyAnchors;
    const anchor = [...anchors].reverse().find(a => !a.staged);
    // An empty anchor must NOT vacuously pass: on the pre-upgrade ledgers
    // this exists for, ANY rewritten 'active' row would verify. Fail
    // closed — reanchorPolicy is the break-glass that establishes the
    // first anchor under a signed remediation event (w16-fixverify F6).
    requireThat(anchor && digest(active) === anchor.digest, 'INV-409-INTEGRITY', 'Active policy diverges from its ledger-anchored activation', 409);
    if (staged && staged.activate_at <= this.clock() && staged.policy.version === active.version + 1 && staged.policy.expires_at > this.clock()) {
      requireThat([...anchors].reverse().find(a => a.staged && a.digest === digest(staged.policy)), 'INV-409-INTEGRITY', 'Staged policy has no ledger-anchored staging event', 409);
      return staged.policy;
    }
    return active;
  }
  identities(t) { return Object.fromEntries(Object.entries(this.tenant(t).identities).map(([id, v]) => [id, { ...v, revoked: v.revoked || this.revoked(t, 'key', id) || this.revoked(t, 'subject', v.subject_id) || this.revoked(t, 'device', v.device_id) }])); }
  assertHealthy(t, subject, device, now) {
    try {
      this._assertHealthy(t, subject, device, now);
    } catch (error) {
      // Pre-transaction quarantine denials audit themselves (w11 F7) — and
      // land the same containment row the in-transaction path would write,
      // so a quarantined actor hammering proposals is reconstructible from
      // the containment ledger too (w11-lifecycle F5).
      if (error instanceof InvariantError && !this.store.db.isTransaction) {
        this._rejectionAudit(t, subject, error.code, error.message, error.details);
        if (error.code === 'INV-403-QUARANTINE' && error.details?.quarantine_denial) {
          try { const n0 = this.clock(); this.store.tx(() => this.store.put(t, 'containment', `deny:${randomUUID()}`, { contained_at: n0, subject_id: subject, device_id: error.details.device ?? null, capability_id: null, resource: null, destination: null, action: null, code: error.code, request_id: 'gate-deny', dropped_requests: 1 }, n0)); } catch { /* containment logging never masks the original denial */ }
        }
      }
      throw error;
    }
  }
  _assertHealthy(t, subject, device, now) {
    requireThat(!this.revoked(t, 'subject', subject) && !this.revoked(t, 'device', device), 'INV-403-QUARANTINE', 'Subject or device quarantined', 403, { quarantine_denial: true, subject, device });
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
      // Key names an operator may plausibly store secret bytes under — the
      // matcher over-redacts rather than leaks: a suppressed display field
      // costs a reader, a verbatim secret costs the secret (w15-timing F1).
      const secretKey = k => /secret|private|password|passwd|passphrase|token|share|credential|seed|entropy|otp|pin|bearer|recovery|ssn|cvv|api.?key|key.?material|_key$|^key$|^auth$|_auth$|^value$/i.test(k);
      // Arrays recurse element-wise — a registry row carrying recovery
      // codes or nested items must not sail through verbatim (w15-timing F1).
      const scrub = v => (v && typeof v === 'object') ? (Array.isArray(v) ? v.map(scrub) : Object.fromEntries(Object.entries(v).map(([k, x]) => [k, secretKey(k) ? '«redacted»' : scrub(x)]))) : v;
      if (Array.isArray(material_fields?.rows)) {
        // The rows branch must still scrub its OTHER keys — a dataset row
        // set beside a credential field cannot launder it past redaction.
        const { rows, ...rest } = material_fields;
        return { ...scrub(rest), row_count: rows.length, rows_digest: digest(rows) };
      }
      // Object-shaped material fields (e.g. a secret.use registry row) may
      // carry secret VALUES that the capsule binds only by digest — readers
      // get the binding proof, never the bytes (w11-timing LOW-7).
      if (material_fields && typeof material_fields === 'object') return scrub(material_fields);
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
  outcomeView(t, outcome, expectId = null) {
    if (outcome) this._outcomeIntegrity(t, outcome, expectId);
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
  // Chain-bound ownership for ledger-significant operations (key
  // revocation, recovery signing): a vault entry's tenant_id is a mutable
  // flag — a flipped entry must not let one tenant kill another's bound
  // key under its own signature (w17-redteam D1). A key belongs to this
  // tenant only when its declared binding or its own signed chain attests
  // the custody (rotation lineage, prepared rotations).
  chainOwnsVaultKey(t, key_id) {
    const bound = this.keys(t);
    if (Object.values(bound).some(v => v?.key_id === key_id) || (bound.retired ?? []).some(r => r.key_id === key_id)) return true;
    return this._auditIndex(t).rotationKeys?.has(key_id) ?? false;
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
    // Quarantine precedes the idempotency store: a replayed proposal must
    // not return the cached record to a now-quarantined device
    // (w9-network F10).
    this.assertHealthy(p.tenant_id, p.subject_id, input.actor.device_id, this.clock());
    const identityEntry = Object.entries(this.tenant(p.tenant_id).identities).find(([, v]) => v.subject_id === p.subject_id);
    const intentPayload = verifySigned(requestIntent, { [identityEntry[0]]: { public_key: identityEntry[1].public_key } }, 'capsule-intent');
    requireThat(digest(intentPayload) === digest(input), 'INV-401-SIGNATURE', 'Request intent does not cover the proposed capsule exactly', 401);
    return this.transaction(p, now => this.store.idempotent(p.tenant_id, 'propose', idempotencyKey, digest(input), () => {
      const policy = this.policy(p.tenant_id); this.assertHealthy(p.tenant_id, p.subject_id, input.actor.device_id, now);
      requireThat(input.created_at <= now + 5000 && input.created_at >= now - 300000 && input.expires_at > now && input.expires_at - input.created_at <= policy.max_capsule_ttl_ms, 'INV-400-SCHEMA', 'Capsule timing invalid');
      // Nonce namespaces are per-surface: a capsule must not squat on an
      // attestation nonce (or vice versa) to block a legitimate session
      // open (w8-canonical F12).
      // The bare-key lookup also covers nonce rows written before the
      // 'capsule:'/'perception:' namespacing shipped — a legacy row must
      // still block the replay (w9-fixverify NB-5).
      const prior = this.store.db.prepare('SELECT capsule FROM nonces WHERE tenant=? AND nonce IN (?, ?)').get(p.tenant_id, 'capsule:' + input.nonce, input.nonce);
      // The nonce table is a fast index, not the authority — deleting the
      // row cannot replay a nonce whose CAPSULE_PROPOSED already sits on the
      // signed chain (w11-redteam R10).
      requireThat(!prior && !this._auditIndex(p.tenant_id).proposedNonce.has(input.nonce), 'INV-409-REPLAY', 'Nonce is already bound to another action', 409);
      const capsule = { ...clone(input), request_intent: clone(requestIntent), capsule_id: randomUUID(), tenant_id: p.tenant_id, received_at: now };
      const record = { capsule, capsule_digest: digest(capsule), status: 'CANONICALISED', evidence: [], approvals: [], decision: null, certificate_id: null, created_at: now };
      this.store.db.prepare('INSERT INTO nonces VALUES(?,?,?)').run(p.tenant_id, 'capsule:' + input.nonce, capsule.capsule_id);
      this.store.insert(p.tenant_id, 'capsule', capsule.capsule_id, record, now);
      this.store.audit(p.tenant_id, 'CAPSULE_PROPOSED', p.subject_id, capsule.capsule_id, { capsule_digest: record.capsule_digest, action_type: capsule.action.type, nonce: input.nonce }, now);
      return record;
    }));
  }
  ensureMutable(record) { requireThat(!['DENY', 'CANCELLED', 'CERTIFIED', 'EXECUTING', 'VERIFIED', 'UNCERTAIN', 'FAILED', 'COMPENSATED'].includes(record.status), 'INV-409-STATE', 'Action is immutable in its current state', 409); }
  graph(t, record) {
    // Set membership is ledger-derived, not read off the mutable capsule
    // record: only envelopes whose EVIDENCE_ATTACHED event sits on the
    // signed chain count — deleting an id from record.evidence or planting
    // one changes nothing (w11-redteam R3/R15).
    const attachedIds = this._auditIndex(t).attached.get(record.capsule.capsule_id) ?? [];
    const rows = attachedIds.map(id => this.store.get(t, 'evidence', id) ? { id, e: this.store.get(t, 'evidence', id) } : { id, e: null });
    // Supersession is derived from attach ORDER on the chain — the stored
    // superseded_by flag is only a cache; a later same-issuer+kind envelope
    // retires a non-conflict predecessor (mirrors attachEvidence semantics).
    const claimOf = x => x?.envelope?.payload?.claim;
    const kindOf = x => x?.envelope?.payload?.kind, kidOf = x => x?.envelope?.protected?.key_id;
    const superseded = new Map();
    // The issuer's LATEST signed statement wins for its own kind — including
    // a supports envelope that retracts an earlier conflict. A veto only
    // stays sticky against a DIFFERENT issuer (w11-lifecycle F4).
    rows.forEach((x, i) => { if (x.e) { const j = rows.findLastIndex(y => y.e && kindOf(y.e) === kindOf(x.e) && kidOf(y.e) === kidOf(x.e)); if (j > i) superseded.set(x.id, rows[j].id); } });
    const items = rows.map(({ id, e }) => {
      if (!e) {
        // A deleted member whose tombstone row is also gone still counts as
        // revoked — anchored membership must never wedge the whole capsule
        // into INV-404 forever (delete-as-DoS, w12-lifecycle F6).
        const tombstone = this.store.get(t, 'evidence-tombstone', id);
        return { payload: { evidence_id: id, expires_at: 0 }, envelope: { retained_digest: tombstone?.original_digest ?? null }, revoked: true, superseded_by: superseded.get(id) ?? null, issuer: { failure_domain: 'deleted' } };
      }
      const iss = this.tenant(t).issuers[e.envelope.protected.key_id];
      // The stored payload is a clone of the SIGNED envelope — divergence
      // means store-level tampering, and evaluation must die on it, not
      // silently reason over the edited clone (w11 F6). The issuer-trust
      // ceiling is re-proven here too: attach-time checks do not cover
      // post-attach mutation of payload.kind (w11 F6).
      requireThat(digest(e.payload) === digest(e.envelope.payload), 'INV-409-INTEGRITY', 'Stored evidence diverged from its signed envelope', 409);
      requireThat(iss?.kinds?.includes(e.envelope.payload.kind), 'INV-403-SCOPE', 'Evidence kind exceeds issuer trust', 403);
      // The envelope itself must verify under the declared issuer's key —
      // planted rows with forged signatures die here regardless of how the
      // id entered the attach ledger (w11-redteam R3).
      requireThat(typeof iss?.public_key === 'string', 'INV-401-EVIDENCE', 'Unknown evidence issuer', 401);
      this._verifyCached(e.envelope, { [e.envelope.protected.key_id]: { public_key: iss.public_key, suite: iss.suite } }, 'evidence');
      // Evaluation re-derives the attach-time scope: a real envelope
      // transplanted under this action's chain-attested id still dies —
      // its signed capsule_digest names the action it was issued for
      // (w12-provenance F2 / EXP-02).
      requireThat(e.envelope.payload.tenant_id === t && e.envelope.payload.capsule_digest === record.capsule_digest, 'INV-409-INTEGRITY', 'Attached evidence names a different action', 409);
      // Supports claims must still bind to this capsule's fields under the
      // ACTIVE policy — a binding tightened since attach cannot be
      // satisfied by claims signed for the old one. A failed item stays in
      // the graph/digest trail but cannot satisfy requirements.
      let binding_failed = false;
      if (e.envelope.payload.claim === 'supports') {
        const bindings = (this.policy(t).rules[record.capsule.action.type]?.evidence_bindings ?? {})[e.envelope.payload.kind] ?? {};
        const scalar = v => v === null || typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean';
        for (const [cf, path] of Object.entries(bindings)) {
          const expected = path.split('.').reduce((o, k) => (o !== null && typeof o === 'object' && Object.hasOwn(o, k)) ? o[k] : undefined, record.capsule);
          const actual = e.envelope.payload.claims?.[cf];
          if (!(scalar(expected) && scalar(actual) && canonical(actual) === canonical(expected))) { binding_failed = true; break; }
        }
      }
      // Only the issuer's semantic identity is digest-bound — credential
      // fields (tokens, expiry, endpoint) rotate by design and must never
      // invalidate a minted certificate or pending approval (w5 F-3).
      const semantic = iss ? { public_key: iss.public_key, name: iss.name, issuer_id: iss.issuer_id, failure_domain: iss.failure_domain, channel: iss.channel, kinds: iss.kinds, version: iss.version } : iss;
      return { ...e, binding_failed, superseded_by: superseded.get(id) ?? null, revoked: this.revoked(t, 'evidence', id) || this.revoked(t, 'issuer', e.envelope.protected.key_id) || this.revoked(t, 'key', e.envelope.protected.key_id), drifted: this._auditIndex(t).issuerDrift.has(e.envelope.protected.key_id), issuer: semantic };
    });
    const graph_digest = digest(items.map(e => ({ envelope_digest: digest(e.envelope), issuer_digest: digest(e.issuer), revoked: e.revoked })).sort((a, b) => a.envelope_digest < b.envelope_digest ? -1 : 1));
    return { items, digest: graph_digest };
  }
  attachEvidence(p, id, envelope) {
    this.authorize(p, ['operator', 'security', 'policy_admin']);
    return this.transaction(p, now => {
      const t = p.tenant_id, record = this.store.must(t, 'capsule', id); this.ensureMutable(record);
      this._capsuleIntegrity(t, record);
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
      // Drift quarantine is chain-anchored: deleting the mutable record
      // cannot un-quarantine a connector (w13-fixverify M3).
      requireThat(!this._auditIndex(t).issuerDrift.has(envelope.protected.key_id), 'INV-403-QUARANTINE', 'Issuer connector drifted — evidence suspended pending revalidation', 403);
      requireThat(payload.tenant_id === t && payload.capsule_digest === record.capsule_digest, 'INV-403-SCOPE', 'Evidence scope mismatch', 403);
      // HIGH-2: supporting evidence must describe THIS action's content, not
      // merely be a true statement of the right kind. Policy-declared
      // bindings map claim fields to capsule paths (requested_state/
      // target_resource/actor). Only 'supports' envelopes are bound — a
      // 'conflict' answer deliberately carries minimal claims and can never
      // satisfy a requirement, so it stays attachable as denial evidence.
      if (payload.claim === 'supports') {
        const bindings = (this.policy(t).rules[record.capsule.action.type]?.evidence_bindings ?? {})[payload.kind] ?? {};
        // A binding only holds on an own-property scalar leaf:
        // '[object Object]' is equal for every object pair and inherited
        // members resolve to attacker-known values, so object-valued or
        // inherited paths must never satisfy a binding (w8-canonical F2).
        const scalar = v => v === null || typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean';
        for (const [claimField, path] of Object.entries(bindings)) {
          const expected = path.split('.').reduce((o, k) => (o !== null && typeof o === 'object' && Object.hasOwn(o, k)) ? o[k] : undefined, record.capsule);
          const actual = payload.claims?.[claimField];
          requireThat(scalar(expected) && scalar(actual) && canonical(actual) === canonical(expected), 'INV-403-SCOPE', `Evidence claims do not describe this action (claims.${claimField} must equal ${path})`, 403);
        }
      }
      const attached = this._auditIndex(t).attached.get(id) ?? [];
      requireThat(payload.dependencies.every(dep => attached.includes(dep)), 'INV-400-SCHEMA', 'Dependencies must already belong to this action');
      requireThat(attached.length < 32, 'INV-429-CAPACITY', 'Evidence set limit reached', 429);
      const issuer = this.tenant(t).issuers[envelope.protected.key_id];
      requireThat(issuer.kinds.includes(payload.kind), 'INV-403-SCOPE', 'Issuer is not trusted for this evidence kind', 403);
      // Evidence supersession (w11-lifecycle F4): a fresh envelope from the
      // same issuer+kind retires its predecessors, so one expired/stale
      // envelope cannot wedge the capsule forever — and the issuer's own
      // signed retraction may retire an earlier conflict the same way.
      // Envelopes whose issuer/key was since revoked still cannot be
      // superseded (a revocation is an authority statement, not staleness).
      // The superseded rows stay in record.evidence — the trail is never
      // erased, only evaluated out.
      for (const eid of attached) {
        const e = this.store.get(t, 'evidence', eid);
        if (e && !e.superseded_by && e.envelope?.protected?.key_id === envelope.protected.key_id && e.envelope?.payload?.kind === payload.kind && !this.revoked(t, 'issuer', e.envelope.protected.key_id) && !this.revoked(t, 'key', e.envelope.protected.key_id)) {
          e.superseded_by = payload.evidence_id;
          this.store.put(t, 'evidence', eid, e, now);
        }
      }
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
    // claims is a flat scalar map — anything else is unbound junk carried
    // under an issuer signature into the evidence graph (w8-canonical F10).
    if (payload.claims !== undefined) {
      requireThat(typeof payload.claims === 'object' && payload.claims !== null && !Array.isArray(payload.claims), 'INV-400-SCHEMA', 'Evidence claims must be an object');
      for (const v of Object.values(payload.claims)) requireThat(v === null || typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean', 'INV-400-SCHEMA', 'Evidence claims values must be scalar');
    }
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
    requireThat(!this._auditIndex(t).issuerDrift.has(key_id), 'INV-403-QUARANTINE', 'Issuer connector drifted — acquisition suspended pending revalidation', 403);
    // The fabric — not the caller — derives the claims that bind the evidence
    // to this action's declared content, so a caller cannot query the issuer
    // about an unrelated entity and attach the answer (HIGH-2).
    const bindings = (this.policy(t).rules[record.capsule.action.type]?.evidence_bindings ?? {})[input.kind] ?? {};
    const claims = { ...(input.claims ?? {}) };
    for (const [claimField, path] of Object.entries(bindings)) {
      // Own-property walk + scalar leaf — matching the attach-side binding
      // contract so acquisition can never mint unattachable claims
      // (w8-canonical F2).
      const expected = path.split('.').reduce((o, k) => (o !== null && typeof o === 'object' && Object.hasOwn(o, k)) ? o[k] : undefined, record.capsule);
      requireThat(expected !== undefined, 'INV-400-SCHEMA', `Action lacks the field the evidence binding requires (${path})`, 400);
      requireThat(expected === null || typeof expected === 'string' || typeof expected === 'number' || typeof expected === 'boolean', 'INV-400-SCHEMA', `Evidence binding path ${path} must resolve to a scalar claim`, 400);
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
      return this.transaction(p, now => {
        this.store.put(p.tenant_id, 'issuer-drift', key_id, { drifted_at: now, changes: [{ field: 'endpoint', detail: 'unreachable' }] }, now);
        // An unreachable issuer stales its dependent paths exactly like a
        // drifted manifest — quarantined evidence cannot keep paths
        // MONITORED (w8-composite F14).
        const paths = this.store.list(p.tenant_id, 'coverage', 10000);
        const transitioned = applyDriftToPaths(paths, path => path.target === issuer.name);
        for (const path of transitioned) this.coverageTransition(p.tenant_id, path, 'UNKNOWN', `connector-unreachable:${key_id}`, now);
        this.store.audit(p.tenant_id, 'CONNECTOR_DRIFT', p.subject_id, key_id, { drifted: 'unreachable', code: e.code ?? 'transport', coverage_paths_staled: transitioned.length }, now);
        if (transitioned.length) this.store.audit(p.tenant_id, 'COVERAGE_STALED', p.subject_id, key_id, { paths: transitioned.map(x => x.path_id) }, now);
        return { drifted: true, changes: [{ field: 'endpoint', detail: 'unreachable' }], checked_at: now, coverage_paths_staled: transitioned.length };
      });
    }
    let observedPayload;
    try {
      observedPayload = verifySigned(observed, { [key_id]: issuer }, 'connector-manifest');
      this.assertSuiteAllowed(p.tenant_id, observed.protected.suite);
      fields(observedPayload, ['connector_id', 'version', 'domain', 'actions', 'permissions', 'limitations', 'idempotency', 'coverage_implications', 'issued_at', 'expires_at']);
      requireThat(observedPayload.expires_at > this.clock(), 'INV-401-CONNECTOR', 'Connector manifest expired', 401);
      requireThat(Number.isSafeInteger(observedPayload.issued_at) && observedPayload.issued_at <= this.clock() + 300000, 'INV-401-CONNECTOR', 'Connector manifest issued-at is implausible', 401);
      // Freshness floor: a manifest minted before the window replays stale
      // issuer state as "no drift" (w9-network F8). The signed horizon is
      // capped too — an issuer cannot extend its own replay window.
      requireThat(observedPayload.issued_at >= this.clock() - 300000, 'INV-401-CONNECTOR', 'Connector manifest is stale', 401);
      requireThat(observedPayload.expires_at <= this.clock() + 900000, 'INV-401-CONNECTOR', 'Connector manifest horizon too long', 401);
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
      if (!result.drifted) { this.store.audit(p.tenant_id, 'CONNECTOR_REVALIDATED', p.subject_id, key_id, { configuration_digest: result.configuration_digest }, now); return result; }
      this.store.put(p.tenant_id, 'issuer-drift', key_id, { drifted_at: now, changes: result.changes }, now);
      // COV-004/CON-006 consequence: paths depending on the drifted connector
      // lose their observation evidence and fall to UNKNOWN until revalidated.
      // Each transition emits a coverage event and an owner task (COV-005/009).
      const paths = this.store.list(p.tenant_id, 'coverage', 10000);
      const transitioned = applyDriftToPaths(paths, path => path.target === issuer.name);
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
      // 'reviewed' is chain-anchored, not a mutable simulation row — a
      // planted record can never satisfy the gate (w13-fixverify M2).
      const reviewed = this._auditIndex(t).simulated.some(s => s.candidate_digest === candidateDigest && s.baseline_digest === digest(this.policy(t)) && s.at > now - 3600000);
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
        // A composite over an already-dead child certificate mints a parent
        // that can only bail — the dead child is an admission problem, not a
        // dispatch-time surprise (w8-composite F9).
        const cp = cert?.envelope?.payload;
        if (!cert || cert.consumed || !cp || cp.issued_at > now || cp.expires_at <= now || this.revoked(t, 'certificate', cp.certificate_id)) problems.push({ code: 'CHILD_CERT', child: childId });
        else certs.push(cert);
      }
      if (problems.length) return { decision: 'ESCROW', reasons: problems.map(x => ({ code: x.code, message: `Composite child ${x.child}: ${x.code.toLowerCase().replace(/_/g, ' ')}${x.status ? ` (${x.status})` : ''}` })), explanation: 'Every child of a composite must be independently certified.', owner: record.capsule.actor.subject_id, expires_at: record.capsule.expires_at, evaluated_at: now, policy_version: policy.version, policy_digest: digest(policy), eligible_signers: [] };
    }
    // The approval's signed challenge binds the RECOMPUTED capsule digest —
    // an approval granted over a capsule that has since been rewritten
    // (with a synced stored digest) must silently drop out (w11 F2).
    const capsuleDigest = digest(record.capsule);
    const approvals = record.approvals.filter(a => a.payload.policy_digest === digest(policy) && a.payload.evidence_graph_digest === graph.digest && a.payload.capsule_digest === capsuleDigest).map(a => {
      try { return this._verifyCached(a, identities, 'action-approval'); } catch { return null; }
    }).filter(Boolean);
    // Superseded evidence keeps its seat in the graph/digest (the signed
    // trail is never rewritten) but is retired from evaluation — only the
    // live set speaks (w11-lifecycle F4).
    // Cooldowns anchor on the ledger-attested proposal instant, not the
    // mutable capsule field — a backdated received_at cannot age a capsule
    // past its cooldown window (w11-redteam R7).
    const anchored = this._auditIndex(t).proposedAt.get(record.capsule.capsule_id);
    const capsuleForEval = anchored !== undefined ? { ...record.capsule, received_at: anchored } : record.capsule;
    return evaluatePolicy({ capsule: capsuleForEval, policy, evidence: graph.items.filter(e => !e.superseded_by && !e.binding_failed), approvals, identities, quarantined: this.revoked(t, 'subject', record.capsule.actor.subject_id) || this.revoked(t, 'device', record.capsule.actor.device_id), now });
  }
  evaluate(p, id) {
    this.authorize(p, ['operator', 'policy_admin', 'approver', 'custodian']);
    return this.transaction(p, now => {
      const record = this.store.must(p.tenant_id, 'capsule', id); this.ensureMutable(record); this._capsuleIntegrity(p.tenant_id, record);
      this.assertHealthy(p.tenant_id, record.capsule.actor.subject_id, record.capsule.actor.device_id, now);
      // The decisioning principal's own device must be live too — the gate
      // revokes a device everywhere or nowhere (w11-approval F6).
      if (p.subject_id !== record.capsule.actor.subject_id) this.assertHealthy(p.tenant_id, p.subject_id, this.identity(p).device_id, now);
      this.assertFreshSnapshot(p.tenant_id, record.capsule);
      record.decision = this.evaluation(p.tenant_id, record, now); record.status = record.decision.decision;
      this.store.put(p.tenant_id, 'capsule', id, record, now); this.store.audit(p.tenant_id, 'POLICY_EVALUATED', p.subject_id, id, { decision: record.status, decision_digest: digest(record.decision) }, now);
      return record.decision;
    });
  }
  certificate(p, id) {
    this.authorize(p, ['operator', 'policy_admin']);
    return this.transaction(p, now => {
      const t = p.tenant_id, r = this.store.must(t, 'capsule', id); this.ensureMutable(r); this._capsuleIntegrity(t, r);
      // Mint-state is ledger-derived: clearing the record field cannot
      // resurrect a second certificate — CERTIFICATE_ISSUED on the signed
      // chain is the authority (w11-redteam R8).
      requireThat(!r.certificate_id && !this._auditIndex(t).issued.has(id), 'INV-409-REPLAY', 'Action already has a certificate', 409);
      this.assertFreshSnapshot(t, r.capsule);
      const decision = this.evaluation(t, r, now), policy = this.policy(t);
      requireThat(decision.decision === 'ALLOW', 'INV-412-EVIDENCE', 'Only ALLOW may receive an execution certificate', 412, decision);
      this.assertHealthy(t, r.capsule.actor.subject_id, r.capsule.actor.device_id, now);
      // Minting on behalf of another actor still requires the minting
      // principal's device to be healthy (w11-approval F6).
      if (p.subject_id !== r.capsule.actor.subject_id) this.assertHealthy(t, p.subject_id, this.identity(p).device_id, now);
      // Resolve the signing key BEFORE any further work — a revoked
      // execution key must not dead-end certificate minting while a pending
      // successor exists (w11-lifecycle F1).
      const execSel = this._signingKeyId(t, 'execution');
      const suite = this.vault.keys.get(execSel.key_id)?.suite ?? 'Ed25519';
      requireThat(policy.algorithms.allowed_suites.includes(suite), 'INV-451-POLICY', 'Certificate suite is no longer approved by policy', 451);
      // The floor runs over still-valid approvals only — a lapsed approval
      // must not mint an already-dead certificate that wedges the capsule in
      // CERTIFIED (policy-audit F12).
      // A policy.change capsule binds the NEXT constitution, not the expiry
      // of the dead one — an expired constitution must still permit its own
      // succession or the tenant wedges permanently (w7-clock F2).
      const graph = this.graph(t, r), expiry = Math.min(now + policy.certificate_ttl_ms, r.capsule.expires_at, r.capsule.action.type === 'policy.change' ? Infinity : policy.expires_at, ...graph.items.filter(e => !e.superseded_by).map(e => e.payload.expires_at), ...r.approvals.filter(a => a.payload.expires_at > now).map(a => a.payload.expires_at));
      requireThat(expiry > now, 'INV-409-STATE', 'Certificate would be stillborn; re-approve the action', 409);
      const certificate_id = randomUUID();
      const payload = { certificate_id, tenant_id: t, capsule_id: id, capsule_digest: r.capsule_digest, evidence_graph_digest: graph.digest, policy_id: policy.policy_id, policy_version: policy.version, policy_digest: digest(policy), decision: 'ALLOW', constraints: { destination: r.capsule.destination, quantity: r.capsule.quantity, requested_digest: digest(r.capsule.requested_state), current_state: this.stateRef(r.capsule.current_state), exclusions: r.capsule.exclusions }, target_gate_id: this.config.gate_id, signer_set: decision.eligible_signers, nonce: r.capsule.nonce, issued_at: now, expires_at: expiry, single_use: true, suite, revocation_ref: `certificate:${certificate_id}` };
      const envelope = this.signExecution(t, payload, 'action-certificate');
      this.store.insert(t, 'certificate', payload.certificate_id, { envelope, consumed: false, status: 'CERTIFIED', issued_at: now }, now);
      r.certificate_id = payload.certificate_id; r.status = 'CERTIFIED'; r.decision = decision; this.store.put(t, 'capsule', id, r, now);
      // The certify path mutates the stored decision without evaluate() —
      // anchor it on the chain too or decision-digest consumers wedge an
      // honest capsule forever (w16-fixverify F5).
      this.store.audit(t, 'POLICY_EVALUATED', p.subject_id, id, { decision: r.status, decision_digest: digest(decision) }, now);
      // A certified composite binds each child to itself by an indexed
      // marker — the execute() guard resolves the parent by key, never by
      // scanning (w10-cert F4).
      if (r.capsule.action.type === 'action.composite') for (const childId of r.capsule.requested_state.children ?? []) { const child = this.store.must(t, 'capsule', childId); child.composite_parents = [...new Set([...(child.composite_parents ?? []), id])]; this.store.put(t, 'capsule', childId, child, now); }
      // Composite parentage is chain-anchored too: the children list lands
      // in the signed event, so editing the stored capsule's children (or
      // deleting the parent row) can never unbind a certified child
      // (w13-fixverify M5).
      this.store.audit(t, 'CERTIFICATE_ISSUED', p.subject_id, id, { certificate_id: payload.certificate_id, certificate_digest: digest(envelope), children: r.capsule.action.type === 'action.composite' ? (r.capsule.requested_state.children ?? []) : null }, now); return envelope;
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
      this._capsuleIntegrity(t, record);
      requireThat(record.capsule.tenant_id === t, 'INV-403-SCOPE', 'Capsule tenant does not match the certificate tenant', 403);
      requireThat(digest(stored.envelope) === digest(envelope), 'INV-401-CERTIFICATE', 'Certificate does not match issued authority', 401);
      requireThat(!stored.consumed && record.status === 'CERTIFIED', 'INV-409-REPLAY', 'Certificate already consumed or action cancelled', 409);
      // A composite child's certificate is spendable only through its parent
      // — a solo spend verifies the child, then the parent's reservation
      // bricks on the consumed cert (w8-composite F8). Once the parent is
      // terminal the child is unbound again. The binding is an indexed
      // marker written at parent certification — a capped capsule scan
      // would silently expire as a guard (w10-cert F4).
      // Composite parentage is ledger-derived: a parent counts iff the chain
      // attests a CERTIFICATE_ISSUED for it AND it names this capsule among
      // its children — clearing the mutable composite_parents marker cannot
      // unbind a certified child (w11-redteam R17).
      const idx = this._auditIndex(t);
      // Consumption and cancellation are chain verdicts, not row state: a
      // flipped `consumed`/`status` pair can never un-spend or un-cancel
      // what the signed ledger already attested (w12-lifecycle F3).
      requireThat(!idx.outcomes.has(cert.certificate_id) && !idx.reserved.has(cert.certificate_id), 'INV-409-REPLAY', 'Certificate already consumed or cancelled on the ledger', 409);
      // Candidate parents come from the anchored membership map itself —
      // enumerating capsule rows would let a store writer delete the parent
      // row and unbind the child even though CERTIFICATE_ISSUED still
      // attests the binding (w16-fixverify F2). Terminal-ness resolves from
      // the anchored outcome of the anchored parent certificate — the
      // mutable parent row is never consulted.
      const certifiedParents = [...idx.parentChildren.keys()].filter(pid => {
        if (pid === record.capsule.capsule_id || !(idx.parentChildren.get(pid) ?? []).includes(record.capsule.capsule_id)) return false;
        // Resolved = an outcome or cancellation exists on the chain for the
        // parent certificate — its one dispatch slot is spent and it can
        // never fire again, so wedged children return to free authority
        // (w7-seam F9). Any other state — issued, reserved, revoked — keeps
        // children bound: the parent may still legitimately dispatch or is
        // under a security hold.
        const parentCertId = idx.issuedCert.get(pid);
        return !(parentCertId !== undefined && idx.outcomes.has(parentCertId));
      });
      requireThat(certifiedParents.length === 0, 'INV-409-STATE', 'Composite child certificates execute only through their parent', 409);
      // A quarantined actor or dispatcher is refused before evidence work —
      // the containment denial must land as INV-403, not as an evidence
      // miss (w9-network F6/F7).
      this.assertHealthy(t, record.capsule.actor.subject_id, record.capsule.actor.device_id, now);
      // The dispatching endpoint must be healthy too — a quarantined-device
      // principal cannot relay another actor's certificate (w9-network F6).
      if (p.subject_id !== record.capsule.actor.subject_id) this.assertHealthy(t, p.subject_id, this.identity(p).device_id, now);
      requireThat(record.capsule_digest === cert.capsule_digest && this.graph(t, record).digest === cert.evidence_graph_digest && digest(this.policy(t)) === cert.policy_digest, 'INV-409-STATE', 'Action, evidence or policy changed', 409);
      requireThat(this.evaluation(t, record, now).decision === 'ALLOW', 'INV-412-EVIDENCE', 'Execution predicates no longer hold', 412);
      const state = record.capsule.action.type === 'secret.use' ? this.target.secretState(t, record.capsule.requested_state.secret_id) : this.target.state(t, record.capsule.action.target_resource);
      requireThat(state.version === record.capsule.current_state.version && state.digest === record.capsule.current_state.digest, 'INV-409-STATE', 'Target state changed', 409);
      // Export rows release only to the identity the disclosure ledger
      // authorized — a relay receiving plaintext egress while usage,
      // watermarks and data_access all bill the approved actor would break
      // attribution entirely (w10-datagate F1). A composite containing an
      // export child releases those rows to its spender — same rule.
      const releasesExport = record.capsule.action.type === 'data.export'
        || (record.capsule.action.type === 'action.composite' && (record.capsule.requested_state.children ?? []).some(cid => this.store.get(t, 'capsule', cid)?.capsule.action.type === 'data.export'));
      requireThat(!releasesExport || p.subject_id === record.capsule.actor.subject_id, 'INV-403-SCOPE', 'Data export rows release only to the approved actor', 403);
      // A reconstruction denial refuses the export at reservation — before
      // the certificate is consumed and before the journal writes — so a
      // denied export egresses nothing and bills nothing (w10-datagate F3).
      // The check is read-only; the touch rows land at finish with egress.
      if (record.capsule.action.type === 'data.export') {
        const req = record.capsule.requested_state;
        const recon = reconstructionCheck(this.store.db, this.target.db, { tenant: t, subject: record.capsule.actor.subject_id, dataset: req.dataset, rows: req.row_ids, columns: req.columns, now, policy: this.policy(t).runtime.reconstruction, record: false, access: this._auditIndex(t).dataAccess });
        requireThat(recon.allowed, 'INV-429-BUDGET', 'Reconstruction limit reached', 429, { coverage_percent: recon.coverage_percent, dataset_coverage_percent: recon.dataset_coverage_percent });
      }
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
    let raw, dispatchError = null;
    try { raw = this.target.execute(capsule, cert.certificate_id, now, fault); }
    catch (e) { dispatchError = e; }
    // Dispatch is anchored on the signed chain the moment the durable
    // journal exists — including an after-commit fault whose journal
    // survived while its response was lost, so reconcile can honestly
    // confirm VERIFIED against the anchor. A planted journal without the
    // anchored event can never mint VERIFIED (w12-provenance F16).
    const journal = this.target.outcome(p.tenant_id, cert.certificate_id);
    if (journal) this.store.tx(() => this.store.audit(p.tenant_id, 'EXECUTION_DISPATCHED', p.subject_id, cert.certificate_id, { journal_digest: digest(journal) }, now));
    if (dispatchError) {
      // A deterministic refusal is a FAILED outcome, honestly recorded — only
      // genuinely ambiguous failures (transport/unknown) are UNCERTAIN
      // (runtime-audit F-9).
      if (dispatchError instanceof InvariantError) return this.finish(p, cert, null, /^INV-5/.test(dispatchError.code ?? '') ? 'UNCERTAIN' : 'FAILED', dispatchError.code);
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
          // Each child's stored capsule must still equal its chain-attested
          // proposal — a graft onto the child record (current_state or
          // action rewrite) fails before it can be dispatched under the
          // parent's composite authority (w13-timing M-3).
          this._capsuleIntegrity(t, child);
          const childStored = this.store.must(t, 'certificate', child.certificate_id);
          childCert = childStored.envelope.payload;
          requireThat(!this.revoked(t, 'key', childStored.envelope.protected.key_id) && !this.revoked(t, 'certificate', childCert.certificate_id) && childCert.issued_at <= childNow && childCert.expires_at > childNow, 'INV-401-CERTIFICATE', 'Child certificate expired or revoked', 401);
          requireThat(!childStored.consumed && child.status === 'CERTIFIED', 'INV-409-REPLAY', 'Child certificate consumed or action cancelled', 409);
          requireThat(child.capsule_digest === childCert.capsule_digest && this.graph(t, child).digest === childCert.evidence_graph_digest && digest(this.policy(t)) === childCert.policy_digest, 'INV-409-STATE', 'Child action, evidence or policy changed', 409);
          requireThat(this.evaluation(t, child, childNow).decision === 'ALLOW', 'INV-412-EVIDENCE', 'Child execution predicates no longer hold', 412);
          this.assertHealthy(t, child.capsule.actor.subject_id, child.capsule.actor.device_id, childNow);
          const state = child.capsule.action.type === 'secret.use' ? this.target.secretState(t, child.capsule.requested_state.secret_id) : this.target.state(t, child.capsule.action.target_resource);
          requireThat(state.version === child.capsule.current_state.version && state.digest === child.capsule.current_state.digest, 'INV-409-STATE', 'Child target state changed', 409);
          // A denied export child refuses before its cert is consumed —
          // same reservation-time rule as a standalone export (w10-datagate F3).
          if (child.capsule.action.type === 'data.export') {
            const req = child.capsule.requested_state;
            const recon = reconstructionCheck(this.store.db, this.target.db, { tenant: t, subject: child.capsule.actor.subject_id, dataset: req.dataset, rows: req.row_ids, columns: req.columns, now: childNow, policy: this.policy(t).runtime.reconstruction, record: false, access: this._auditIndex(t).dataAccess });
            requireThat(recon.allowed, 'INV-429-BUDGET', 'Reconstruction limit reached', 429, { coverage_percent: recon.coverage_percent, dataset_coverage_percent: recon.dataset_coverage_percent });
          }
          childStored.consumed = true; childStored.status = 'EXECUTING'; childStored.transaction_id = childCert.certificate_id;
          child.status = 'EXECUTING';
          this.store.put(t, 'certificate', childCert.certificate_id, childStored, childNow); this.store.put(t, 'capsule', childId, child, childNow);
          this.store.audit(t, 'EXECUTION_RESERVED', p.subject_id, childCert.certificate_id, { capsule_digest: childCert.capsule_digest, composite_child_of: cert.certificate_id }, childNow);
        });
      } catch (e) { return bail(`CHILD_REVALIDATION_FAILED:${e.code ?? 'UNKNOWN'}`); }
      let raw, dispatchError = null;
      try { raw = this.target.execute(child.capsule, childCert.certificate_id, childNow, fault); }
      catch (e) { dispatchError = e; }
      // Same dispatch anchor as a standalone: any durable journal is
      // attested on the chain, so a wedged child can be honestly settled
      // later while a planted journal can never mint VERIFIED
      // (w12-provenance F16).
      const childJournal = this.target.outcome(t, childCert.certificate_id);
      if (childJournal) this.store.tx(() => this.store.audit(t, 'EXECUTION_DISPATCHED', p.subject_id, childCert.certificate_id, { journal_digest: digest(childJournal), composite_child_of: cert.certificate_id }, childNow));
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
      requireThat(stored.consumed && this._auditIndex(t).reserved.has(cert.certificate_id), 'INV-409-STATE', 'Certificate was never reserved for execution', 409);
      this._capsuleIntegrity(t, r);
      // The composite parent certificate re-proves itself like any other:
      // signed under an attested execution key, chain-anchored at issuance,
      // and the caller-presented payload equal to the issued payload
      // (w13-store F1).
      const issuedParent = verifySigned(stored.envelope, this.executionPublic(t), 'action-certificate');
      requireThat(this._auditIndex(t).issued.has(cert.capsule_id) && digest(cert) === digest(issuedParent), 'INV-401-CERTIFICATE', 'Presented certificate does not match the issued authority', 401);
      const existing = this.store.get(t, 'outcome', cert.certificate_id);
      // A planted terminal outcome must scream INTEGRITY, not wedge the cert
      // behind a state check (w13-fixverify L6).
      if (existing) this._outcomeIntegrity(t, existing, cert.certificate_id);
      requireThat(!existing || !['VERIFIED', 'FAILED', 'COMPENSATED'].includes(existing.payload.status), 'INV-409-STATE', 'A terminal execution outcome cannot be overwritten', 409);
      // Compensation is claimed only where it actually ran — a refused or
      // never-attempted unwind makes the outcome honestly FAILED, not
      // COMPENSATED (w8-composite F1).
      const compensatedIds = new Set((compensations ?? []).filter(c => c.compensated === true).map(c => c.capsule_id));
      // COMPENSATED attests that every journaled child was actually unwound:
      // an executed child without a positive compensation entry, a refused
      // compensation, or a wedged child each falsify the verdict — it then
      // lands as FAILED (w10-cert F1).
      if (status === 'COMPENSATED' && (wedged.length || compensations?.some(c => c.compensated === false) || executed.some(d => !compensatedIds.has(d.child.capsule.capsule_id)))) {
        status = 'FAILED'; reason = `COMPENSATION_INCOMPLETE:${reason}`;
        wedged = [...new Set([...wedged, ...compensations.filter(c => c.compensated === false).map(c => c.capsule_id)])];
      }
      const childOutcomes = {};
      for (const done of executed) {
        const childCapsuleId = done.child.capsule.capsule_id;
        const childRecord = this.store.must(t, 'capsule', childCapsuleId), childStored = this.store.must(t, 'certificate', done.child.certificate_id);
        const childCertId = childStored.envelope.payload.certificate_id;
        const priorOutcome = this.store.get(t, 'outcome', childCertId);
        // A planted child outcome must scream INTEGRITY, not silently skip
        // post-effects while the parent attests success (w13-fixverify H2).
        if (priorOutcome) this._outcomeIntegrity(t, priorOutcome, childCertId);
        const settledTerminal = priorOutcome && ['VERIFIED', 'FAILED', 'COMPENSATED'].includes(priorOutcome.payload.status);
        let childStatus = status === 'VERIFIED' ? 'VERIFIED' : status === 'UNCERTAIN' ? 'UNCERTAIN' : compensatedIds.has(childCapsuleId) ? 'COMPENSATED' : 'FAILED';
        let extras = null;
        // VERIFIED children take their declared post-effects — a composite
        // may not attest an effect that never happened (runtime-audit F-2).
        // An effect that refuses (budget denial, lapsed rotation
        // precondition) demotes the parent outcome too — the ledger must not
        // attest VERIFIED over a child that failed (w7-seam F6). Effects
        // never re-fire for an already-settled child (w8-composite F6).
        if (status === 'VERIFIED' && childStatus === 'VERIFIED' && !settledTerminal) {
          // A child's VERIFIED rides on the same anchored dispatch proof as
          // a standalone: the chain must attest this journal for this cert.
          const childJournal = this.target.outcome(t, childCertId);
          requireThat(childJournal && digest(childJournal) === digest(done.raw) && this._auditIndex(t).dispatched.get(childCertId) === digest(childJournal), 'INV-409-INTEGRITY', 'Child outcome lacks a ledger-anchored dispatch', 409);
          extras = this._applyVerifiedEffects(p, t, childRecord, childStored.envelope.payload, done.raw, now, post);
          if (extras?.gate_denied || extras?.rotation_precondition_lapsed || extras?.activation_superseded) {
            status = 'FAILED'; reason = extras?.gate_denied?.code ?? extras?.activation_superseded?.detail ?? 'ROTATION_PRECONDITION_LAPSED';
            childStatus = 'FAILED';
          }
        }
        // An export that egressed rows is charged and watermarked even when
        // the parent did not finish VERIFIED — egress is irrevocable
        // (w8-composite F2).
        if (done.child.capsule.action.type === 'data.export' && childStatus !== 'VERIFIED' && !settledTerminal) extras = this._recordExportEgress(p, t, childRecord, childStored.envelope.payload, done.raw, now);
        // A child whose outcome already settled keeps its recorded verdict —
        // the parent's status never overrides a terminal child row.
        if (settledTerminal) childStatus = priorOutcome.payload.status;
        childRecord.status = childStatus; childStored.consumed = true; childStored.status = childStatus;
        this.store.put(t, 'capsule', childCapsuleId, childRecord, now);
        this.store.put(t, 'certificate', childCertId, childStored, now);
        childOutcomes[childCapsuleId] = settledTerminal ? priorOutcome.payload.status : childStatus;
        // Every executed child gets its own outcome row — reconcile(child)
        // must answer the recorded verdict, never resurrect or re-fire
        // effects (w8-composite F3/F4/F6). UNCERTAIN rows may supersede.
        if (!settledTerminal) {
          const childPayload = { certificate_id: childCertId, capsule_digest: childStored.envelope.payload.capsule_digest, target_transaction_id: childCertId, observed_state_digest: done.raw?.observed_state_digest ?? null, status: childStatus, reason: childStatus === status ? reason : `PARENT_${status}:${reason}`, execution_time: done.raw?.execution_time ?? execNow, reconciliation_evidence: done.raw ? digest(done.raw) : null, simulation: true, output: null, watermarks: extras?.watermarks ?? null, gate_denied: extras?.gate_denied?.detail ?? null, composite_child_of: cert.certificate_id, supersedes: priorOutcome ? digest(priorOutcome) : null };
          this.store.put(t, 'outcome', childCertId, this.signAudit(t, childPayload, 'outcome'), now);
        }
      }
      // The terminal record names every child's fate — wedged and
      // never-attempted children are accounted, not hidden (w8-composite F7).
      for (const childId of capsule.requested_state.children ?? []) childOutcomes[childId] ??= wedged.includes(childId) ? 'WEDGED' : 'NOT_ATTEMPTED';
      const payload = { certificate_id: cert.certificate_id, capsule_digest: cert.capsule_digest, target_transaction_id: cert.certificate_id, observed_state_digest: digest({ children: executed.map(e => e.child.capsule.capsule_id), compensations }), status, reason, execution_time: execNow, reconciliation_evidence: digest(executed.map(e => e.raw)), simulation: true, output: null, composite: true, children: executed.map(e => e.child.capsule.capsule_id), child_outcomes: childOutcomes, wedged_children: wedged.length ? wedged : null, compensations, supersedes: existing ? digest(existing) : null };
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
    // The response can only ever describe a capsule of this tenant — a
    // cross-tenant journal row must invalidate, never validate (w11 F3).
    if (r.capsule.tenant_id !== cert.tenant_id) return { valid: false, detail: 'capsule-tenant-mismatch' };
    const responseKeys = ['target_transaction_id', 'capsule_digest', 'authorised_requested_digest', 'observed_state_digest', 'observed_state', 'output', 'status', 'execution_time', 'simulation'];
    let responseShape = raw && typeof raw === 'object' && !Array.isArray(raw) && Object.keys(raw).length === responseKeys.length && responseKeys.every(key => Object.hasOwn(raw, key)) && (r.capsule.action.type === 'data.export' ? raw.observed_state === null : (raw.observed_state && typeof raw.observed_state === 'object' && !Array.isArray(raw.observed_state))) && (raw.output === null || Array.isArray(raw.output));
    if (responseShape) {
      try { canonical(raw); } catch (error) { if (error instanceof InvariantError) responseShape = false; else throw error; }
    }
    let expected = null;
    if (responseShape && Number.isSafeInteger(raw.execution_time)) {
      // Expected state embeds the EXECUTION instant, not the validation
      // instant — recomputing with validate-now falsifies every replayed
      // journal entry whose time fields moved on (w8-composite F5).
      const et = raw.execution_time;
      const c = r.capsule;
      expected = { ...c.current_state.material_fields, ...c.requested_state };
      if (c.action.type === 'finance.bank.change') expected = { ...expected, first_payment_done: false, payment_eligible_at: et + 60000 };
      if (c.action.type === 'finance.payment.first') expected = { ...c.current_state.material_fields, first_payment_done: true, payment: c.requested_state, payment_transaction: cert.certificate_id };
      if (c.action.type === 'data.export') expected = c.current_state.material_fields;
      if (['identity.mfa.reset', 'identity.authenticator.enroll', 'identity.account.recover'].includes(c.action.type)) expected = { ...expected, last_identity_operation: { type: c.action.type, at: et, transaction: cert.certificate_id } };
      if (c.action.type === 'key.rotate') expected = { ...expected, rotated_at: et, rotation_transaction: cert.certificate_id };
      if (c.action.type === 'secret.use') expected = { ...c.current_state.material_fields, last_use: { secret_id: c.requested_state.secret_id, operation: c.requested_state.operation, workload_id: c.requested_state.workload_id, at: et, transaction: cert.certificate_id } };
      if (c.action.type === 'backup.delete') expected = { ...c.current_state.material_fields, deleted_backups: [...(c.current_state.material_fields.deleted_backups ?? []), { backup_id: c.requested_state.backup_id, at: et, transaction: cert.certificate_id }] };
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
    // The journal's observed_state binds observed_state_digest exactly —
    // except where residency rules journal only the digest-bearing
    // projection (secret.use keeps material_digest; export keeps none —
    // w15-timing F9, w10-datagate F5).
    const journalBound = raw === null ? false
      : r.capsule.action.type === 'data.export' ? true
      : r.capsule.action.type === 'secret.use' ? raw.observed_state?.withheld === true && raw.observed_state?.material_digest === raw.observed_state_digest
      : raw.observed_state_digest === digest(raw.observed_state);
    const valid = Boolean(responseShape && expected && outputValid && postStateOk && raw.execution_time >= cert.issued_at && raw.execution_time <= now && raw.execution_time < cert.expires_at && digest(expected) === raw.observed_state_digest && raw.status === 'VERIFIED' && raw.target_transaction_id === cert.certificate_id && raw.capsule_digest === cert.capsule_digest && raw.authorised_requested_digest === digest(r.capsule.requested_state) && journalBound && raw.simulation === true);
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
      // A lapsed activation — a sibling took the version, or a staged
      // candidate already pends — must never throw inside the outcome
      // transaction: the journal committed, so the honest verdict is FAILED
      // (w10-cert F2).
      if (next.version !== active.version + 1) return { activation_superseded: { detail: 'POLICY_SEQUENCE_LAPSED' } };
      // A staged candidate pending activation conflicts with ANY second
      // activation — immediate or staged alike (w10-cert F2).
      if (this.store.get(t, 'policy', 'staged')) return { activation_superseded: { detail: 'POLICY_STAGED_CONFLICT' } };
      // Expiry and staged min-delay are admission-time checks in evaluation();
      // a candidate that cannot legally activate never reaches CERTIFIED.
      if (next.not_before > now) {
        this.store.put(t, 'policy', 'staged', { policy: next, activate_at: next.not_before, staged_at: now, capsule_id: r.capsule.capsule_id }, now);
        this.store.audit(t, 'POLICY_STAGED', p.subject_id, next.policy_id, { activate_at: next.not_before, version: next.version, policy_digest: digest(next) }, now);
      } else {
        this.store.put(t, 'policy', 'active', next, now);
        this.store.put(t, 'policy-history', `v${next.version}`, { activated_at: now, digest: digest(next), staged: false, emergency: next.emergency_of !== undefined }, now);
        if (next.emergency_of !== undefined) this.store.audit(t, 'EMERGENCY_POLICY_ACTIVATED', p.subject_id, next.policy_id, { version: next.version, base: next.emergency_of, policy_digest: digest(next) }, now);
        else this.store.audit(t, 'POLICY_ACTIVATED', p.subject_id, next.policy_id, { version: next.version, policy_digest: digest(next) }, now);
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
      // The rotating-in key must be gate-provenanced: a vault-resident,
      // pending, tenant-owned entry that attests its wrapped material AND
      // was generated inside — an injected keys.set (bogus wrapped) or an
      // importKey oracle entry can never become a signer (w13-store F2/F4).
      let preconditions = entry && entry.pending && !entry.revoked && !this.revoked(t, 'key', req.new_key_id)
        && this.ownsVaultKey(t, req.new_key_id)
        && req.new_public_key === entry.public_key
        && entry.generated_inside !== false
        && this._vaultAttested(req.new_key_id, req.new_public_key)
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
      // The ledger is authoritative: the key-rotation record commits in-tx,
      // while every in-memory mutation (activation, repoint, retire,
      // revoke) runs post-commit — a failed outcome write can never leave
      // the vault/config repointed against a ledger that shows no rotation
      // (w11-lifecycle F2c). _reconcileLedger heals crash-between windows.
      // revoke_old is the operator's declared choice — the ledger attests
      // what was actually done, never a hardcoded true (w7-seam F7).
      const revokeOld = req.revoke_old !== false;
      this.store.put(t, 'key-rotation', req.new_key_id, { new_key_id: req.new_key_id, new_public_key: req.new_public_key, key_class: klass, previous_key_id: previous.key_id, previous_public_key: previous.public_key, revoke_old: revokeOld, rotated_at: now, capsule_id: r.capsule.capsule_id }, now);
      this.store.audit(t, 'KEY_ROTATED', p.subject_id, req.new_key_id, { key_class: klass, previous_key_id: previous.key_id, ceremony_id: req.ceremony_id, revoke_old: revokeOld }, now);
      post.push(() => {
        this.vault.activate(req.new_key_id);
        const tn = clone(this.tenant(t));
        tn.keys[klass] = { key_id: req.new_key_id, public_key: req.new_public_key };
        tn.keys.retired = [...(tn.keys.retired ?? []), { key_class: klass, key_id: previous.key_id, public_key: previous.public_key, retired_at: now, derived: true }];
        this.#setTenant(t, tn);
        if (revokeOld) this.vault.revoke(previous.key_id);
        this.persistVault();
        // The repoint changes the keys section — re-anchor the signed
        // snapshot so drift detection tracks the post-rotation state
        // instead of flagging a legitimate rotation as drift
        // (w13-fixverify M4).
        try { this.store.audit(t, 'CONFIG_SNAPSHOT', 'system', 'config', { config_digest: digest({ tenant: t, sections: this._configSections(this.tenant(t)) }) }, this.clock()); } catch { /* ledger write failure does not undo the rotation */ }
      });
      // Only an audit-class rotation changes the outcome signer. The
      // incoming (still-pending) successor always attests the succession —
      // via the scoped allowPending path — so the retiring key never signs
      // past its own KEY_ROTATED row; the signing window closes exactly at
      // the event, with no grace seq a dead key could exploit (w13 W13-01).
      if (klass === 'audit') return { outcome_key_id: req.new_key_id, outcome_allow_pending: true };
      return null;
    }
    if (type === 'identity.jit.grant') {
      const req = r.capsule.requested_state;
      const grant = { grant_id: `jit-${cert.certificate_id}`, subject_id: req.subject_id, resources: req.resources, actions: req.actions, destinations: req.destinations, columns: req.columns, row_ids: req.row_ids, roles: req.roles ?? [], expires_at: now + req.ttl_ms, issued_at: now, issued_by: `action:${r.capsule.capsule_id}`, reason: req.reason, revoked: false };
      this.store.put(t, 'jit-grant', grant.grant_id, { grant }, now);
      this.store.audit(t, 'JIT_GRANT_ISSUED', p.subject_id, req.subject_id, { grant_id: grant.grant_id, grant_digest: digest(req), scope_digest: digest({ subject_id: grant.subject_id, resources: grant.resources ?? [], actions: grant.actions ?? [], destinations: grant.destinations ?? [], columns: grant.columns ?? [], row_ids: grant.row_ids ?? [], roles: grant.roles ?? [], expires_at: grant.expires_at }), expires_at: grant.expires_at }, now);
      post.push(() => this.target.grant(t, grant.grant_id, grant));
    }
    if (type === 'data.export') return this._recordExportEgress(p, t, r, cert, raw, now);
    return null;
  }
  // DAT-009/011: an executed export is a first-class data access — touch
  // rows, budget charge and attribution watermarks. This runs whenever rows
  // left the gate, including under a bail or demotion that can never
  // un-egress them; a late budget denial is recorded, not silently skipped
  // (w8-composite F2).
  _recordExportEgress(p, t, r, cert, raw, now) {
    const requested = r.capsule.requested_state, subject = r.capsule.actor.subject_id;
    const dataset = this.target.state(t, requested.dataset).material_fields;
    // The egress is billed and touched exactly once per certificate — a
    // reconcile re-firing the finish path after the crash window re-runs the
    // budget check read-only but must not double-charge or double-touch the
    // same disclosure (w10-cert F3).
    const requestKey = `cert:${cert.certificate_id}`;
    // The charge decision is chain-anchored: a squatted usage row can no
    // longer suppress billing, coverage or the DATA_ACCESSED attestation —
    // only a real signed disclosure event for THIS certificate counts
    // (w12-provenance F17). The usage row stays as the billing mirror.
    const alreadyCharged = this._auditIndex(t).dataAccess.some(a => a.certificate_id === cert.certificate_id);
    const recon = reconstructionCheck(this.store.db, this.target.db, { tenant: t, subject, dataset: requested.dataset, rows: requested.row_ids, columns: requested.columns, now, policy: this.policy(t).runtime.reconstruction, record: !alreadyCharged, access: this._auditIndex(t).dataAccess });
    const weight = this.policy(t).runtime.sensitivity_weights[dataset.classification] ?? 1;
    const cost = requested.row_ids.length * requested.columns.length * weight;
    // A squatted mirror row cannot even fail the insert — upsert folds the
    // honest charge into whatever the insider pre-planted (w12-provenance
    // F17): the row is a billing projection, the chain decides.
    if (!alreadyCharged)
      this.store.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?) ON CONFLICT(tenant,capability,request) DO UPDATE SET cost=cost+excluded.cost,at=excluded.at').run(t, subject, requested.dataset, now, cost, requestKey, cert.certificate_id);
    if (!recon.allowed) return { gate_denied: { code: 'INV-429-BUDGET', detail: { row_count: recon.row_count, column_count: recon.column_count, coverage_percent: recon.coverage_percent } } };
    // Egress disclosure is attested on the signed chain — the touch table
    // is a mirror; wiping it can never reset coverage (w11-redteam R9).
    if (!alreadyCharged)
      this.store.audit(t, 'DATA_ACCESSED', subject, subject, { dataset: requested.dataset, row_ids: requested.row_ids, columns: requested.columns, at: now, certificate_id: cert.certificate_id }, now);
    // Watermarking requires the dedicated key — falling back to the
    // row-encryption key would fuse two distinct primitives (w10-datagate F10).
    const tenantWatermarkKey = this.dataKey(t, 'watermark');
    requireThat(tenantWatermarkKey, 'INV-503-CONFIG', `Tenant ${t} has no watermark data key`, 503);
    return { watermarks: watermark(raw.output ?? [], { tenant: t, dataset: requested.dataset, subject, requestId: cert.certificate_id, capabilityId: `cert:${cert.certificate_id}`, tenantWatermarkKey }).watermarks };
  }
  finish(p, cert, raw, status, reason, { postRead = false } = {}) {
    const post = [];
    const envelope = this.transaction(p, now => {
      const t = p.tenant_id, r = this.store.must(t, 'capsule', cert.capsule_id), stored = this.store.must(t, 'certificate', cert.certificate_id);
      // finish is reachable only after the reservation consumed the
      // certificate — an outcome row cannot be forged ahead of dispatch
      // (w11 F4). Record integrity is re-proven before effects fire (w11 F1).
      // The reservation anchor, not the mutable consumed flag, proves the
      // certificate entered execution — a flipped flag without a signed
      // EXECUTION_RESERVED fails here (w12-provenance F16).
      requireThat(stored.consumed && this._auditIndex(t).reserved.has(cert.certificate_id), 'INV-409-STATE', 'Certificate was never reserved for execution', 409);
      this._capsuleIntegrity(t, r);
      // finish() is a confused deputy unless the certificate re-proves
      // itself: (a) the stored row is a genuine gate-issued envelope —
      // verifySigned under an attested execution key rejects a store.put
      // forgery; (b) the chain attests this capsule's issuance — a
      // hand-made cert row never saw CERTIFICATE_ISSUED; (c) the
      // caller-presented payload equals the issued payload byte-for-byte,
      // binding certificate_id/capsule_id/capsule_digest so a valid cert
      // for another action cannot launder a forged finish. Anchored
      // issuance IS the ALLOW proof — re-running evaluatePolicy at finish
      // would falsify legitimate executions once policy moved on
      // (w13-store F1).
      const issuedPayload = verifySigned(stored.envelope, this.executionPublic(t), 'action-certificate');
      requireThat(this._auditIndex(t).issued.has(cert.capsule_id) && digest(cert) === digest(issuedPayload), 'INV-401-CERTIFICATE', 'Presented certificate does not match the issued authority', 401);
      // Terminal outcomes are immutable — a VERIFIED/FAILED result can never
      // be overwritten by a second finish (only UNCERTAIN may resolve later).
      const existing = this.store.get(t, 'outcome', cert.certificate_id);
      // A planted terminal outcome must scream INTEGRITY, not wedge the
      // cert behind a state ordering (w13-fixverify L6).
      if (existing) this._outcomeIntegrity(t, existing, cert.certificate_id);
      requireThat(!existing || !['VERIFIED', 'FAILED', 'COMPENSATED'].includes(existing.payload.status), 'INV-409-STATE', 'A terminal execution outcome cannot be overwritten', 409);
      requireThat(!existing || existing.payload.certificate_id === cert.certificate_id, 'INV-409-INTEGRITY', 'Stored outcome belongs to another certificate', 409);
      // A VERIFIED verdict requires the durable dispatch journal — not the
      // caller's word. Reservation != dispatch: the journal row exists only
      // when the target transaction actually committed (w11-redteam R4).
      const journal = this.target.outcome(t, cert.certificate_id);
      if (status === 'VERIFIED') {
        requireThat(journal && raw && digest(raw) === digest(journal), 'INV-409-INTEGRITY', 'Claimed VERIFIED execution does not match the durable dispatch journal', 409);
        // Dispatch itself is chain-anchored: flipping certificate.consumed
        // and planting a journal row cannot mint VERIFIED — the ledger must
        // attest this exact journal at dispatch time (w12-provenance F16).
        requireThat(this._auditIndex(t).dispatched.get(cert.certificate_id) === digest(journal), 'INV-409-INTEGRITY', 'No ledger-anchored dispatch for this journal', 409);
      }
      const { valid } = this._validateTargetResponse(r, cert, raw, now, { postRead });
      if (status === 'VERIFIED' && !valid) { status = 'UNCERTAIN'; reason = 'TARGET_RESPONSE_INVALID'; }
      const extras = valid ? this._applyVerifiedEffects(p, t, r, cert, raw, now, post) : null;
      if (extras?.gate_denied) { status = 'FAILED'; reason = extras.gate_denied.code; }
      if (extras?.rotation_precondition_lapsed) { status = 'FAILED'; reason = 'ROTATION_PRECONDITION_LAPSED'; }
      if (extras?.activation_superseded) { status = 'FAILED'; reason = extras.activation_superseded.detail; }
      // H1: revocation cannot abort a committed reservation — it stops NEW
      // reservations. A revocation that landed between reservation and this
      // finish is recorded and flagged rather than hidden, so the ledger
      // shows the race instead of pretending it never happened.
      const revokedMidFlight = this.revoked(t, 'certificate', cert.certificate_id) || this.revoked(t, 'key', stored.envelope.protected.key_id);
      const payload = { certificate_id: cert.certificate_id, capsule_digest: cert.capsule_digest, target_transaction_id: cert.certificate_id, observed_state_digest: valid ? raw.observed_state_digest : null, status, reason, execution_time: valid ? raw.execution_time : now, reconciliation_evidence: valid ? digest(raw) : null, journal_digest: status === 'VERIFIED' ? digest(journal) : null, simulation: true, output: valid && !extras?.gate_denied ? raw.output : null, watermarks: extras?.watermarks ?? null, gate_denied: extras?.gate_denied?.detail ?? null, revoked_post_reservation: revokedMidFlight || null, composite_child_of: (r.composite_parents ?? []).map(pid => this.store.get(t, 'capsule', pid)?.certificate_id).find(Boolean) ?? null, supersedes: existing ? digest(existing) : null };
      const envelope = this.signAudit(t, payload, 'outcome', extras?.outcome_key_id ?? null, { allowPending: extras?.outcome_allow_pending === true });
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
    // A recorded outcome without a consumed reservation is always forged
    // (w11 F4) — the consumed check precedes every stored-row read, and the
    // row itself must re-verify as a vault-signed envelope before it is
    // served (w11 F5).
    // A stored outcome row is integrity-proven before the state checks —
    // tamper evidence outranks 'not started' (a planted row must scream
    // INTEGRITY, never hide behind state ordering).
    const current = this.store.get(t, 'outcome', id);
    if (current) this._outcomeIntegrity(t, current, id);
    requireThat(stored.consumed && this._auditIndex(t).reserved.has(id), 'INV-409-STATE', 'Execution has not started', 409);
    // COMPENSATED is terminal too — reconcile returns any settled outcome
    // instead of throwing where VERIFIED/FAILED simply answer (w7-seam F8).
    if (current && ['VERIFIED', 'FAILED', 'COMPENSATED'].includes(current.payload.status)) return this._outcomeIntegrity(t, current, id);
    const cert = stored.envelope.payload, raw = this.target.outcome(t, id);
    const record = this.store.must(t, 'capsule', cert.capsule_id);
    if (record.capsule.action.type === 'action.composite') {
      // A wedged composite reconciles per-child, never as a fake standalone:
      // children whose target journal wrote are recorded executed, the rest
      // are wedged — and they keep their own live certificates so a fresh
      // composite can still spend them (w7-seam F9). Parent capsules never
      // write a target journal row — the outcome aggregates the child
      // outcome rows each child settle wrote (w8-composite F16).
      const executed = [], wedged = [];
      let allSettledVerified = true, anyFailed = false, anyCompensated = false;
      for (const childId of record.capsule.requested_state.children ?? []) {
        const childCapsule = this.store.get(t, 'capsule', childId);
        const childCert = childCapsule?.certificate_id ? this.store.get(t, 'certificate', childCapsule.certificate_id) : null;
        const certId = childCert?.envelope?.payload?.certificate_id;
        const childOutcome = certId ? this.store.get(t, 'outcome', certId) : null;
        // A planted child outcome can never mint a parent verdict: the row
        // re-proves itself as a gate-signed envelope bound to this cert
        // before its status counts (w13-fixverify H2).
        if (childOutcome) this._outcomeIntegrity(t, childOutcome, certId);
        if (childCapsule) this._capsuleIntegrity(t, childCapsule);
        const childRaw = childCert ? this.target.outcome(t, certId) : null;
        const settled = childOutcome && ['VERIFIED', 'FAILED', 'COMPENSATED'].includes(childOutcome.payload.status) ? childOutcome.payload.status : null;
        if (settled === 'FAILED') anyFailed = true;
        if (settled === 'COMPENSATED') anyCompensated = true;
        if (settled !== 'VERIFIED') allSettledVerified = false;
        if (childCapsule && childCert && (childRaw || settled)) executed.push({ child: { ...childCapsule, certificate_id: certId }, raw: childRaw, prior: childCapsule.capsule.current_state.material_fields });
        else wedged.push(childId);
      }
      // All children settled VERIFIED → the parent is VERIFIED; a failed or
      // compensated child resolves the parent FAILED (a COMPENSATED child
      // row can only be written alongside a terminal parent outcome, so
      // reaching one here names an orphaned compensation — never a clean
      // parent verdict — w10-cert F7); anything incomplete stays honestly
      // UNCERTAIN.
      const settled = wedged.length === 0 && allSettledVerified ? 'VERIFIED' : (anyFailed || anyCompensated) ? 'FAILED' : 'UNCERTAIN';
      const reasonMap = { VERIFIED: 'RECONCILED_FROM_CHILD_OUTCOMES', FAILED: anyCompensated && !anyFailed ? 'RECONCILED_CHILD_COMPENSATED_ORPHANED' : 'RECONCILED_CHILD_FAILED', UNCERTAIN: 'COMPOSITE_INTERRUPTED_CHILDREN_ATTEMPTED' };
      return this.finishComposite(p, cert, record.capsule, executed, settled, reasonMap[settled], [], this.clock(), wedged);
    }
    return this.finish(p, cert, raw, raw ? 'VERIFIED' : 'UNCERTAIN', raw ? 'RECONCILED_FROM_TARGET_JOURNAL' : 'NO_TARGET_CONFIRMATION_DO_NOT_RETRY');
  }
  cancel(p, id) {
    this.authorize(p, ['operator', 'security', 'policy_admin']);
    return this.transaction(p, now => {
      // CANCELLED and DENY are terminal too — re-cancelling rewrites the
      // forensic record (a second ACTION_CANCELLED, a DENY verdict silently
      // overwritten to CANCELLED) (w11-lifecycle F6/F7).
      const r = this.store.must(p.tenant_id, 'capsule', id); requireThat(!['EXECUTING', 'VERIFIED', 'UNCERTAIN', 'FAILED', 'COMPENSATED', 'CANCELLED', 'DENY'].includes(r.status), 'INV-409-STATE', 'Dispatched or terminal action cannot be cancelled; reconcile first', 409);
      this.assertHealthy(p.tenant_id, p.subject_id, this.identity(p).device_id, now);
      // Same anti-grief rule attachEvidence already carries: only the
      // proposing actor — or a privileged role — may cancel (w9-network F9).
      const callerRoles = this.grantsFor(p.tenant_id, p.subject_id, now).roles ?? this.identity(p).roles;
      requireThat(r.capsule.actor.subject_id === p.subject_id || callerRoles.some(x => ['security', 'policy_admin'].includes(x)), 'INV-403-SCOPE', 'Only the proposing actor or a privileged role may cancel', 403);
      r.status = 'CANCELLED'; this.store.put(p.tenant_id, 'capsule', id, r, now);
      // The certificate row must not keep reading as a live CERTIFIED
      // authority after its action is cancelled (w10-cert F8).
      const cert = r.certificate_id ? this.store.get(p.tenant_id, 'certificate', r.certificate_id) : null;
      if (cert && cert.status === 'CERTIFIED') { cert.status = 'CANCELLED'; this.store.put(p.tenant_id, 'certificate', r.certificate_id, cert, now); }
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
    const env = this.transaction(p, now => {
      // Revocation must name a live authority — revoking a nonexistent id
      // would be silent record pollution.
      const t = p.tenant_id;
      const exists = {
        certificate: () => this.store.get(t, 'certificate', input.id),
        evidence: () => this.store.get(t, 'evidence', input.id),
        // Existence must be own-property — inherited Object.prototype
        // members ('constructor', 'toString', ...) are not live authorities
        // and must never mint revocation records (w8-canonical F1).
        issuer: () => Object.hasOwn(this.tenant(t).issuers, input.id) ? this.tenant(t).issuers[input.id] : null,
        // A revocable key is a vault entry, an identity, an issuer — or a
        // perception component signing key, which must also be revocable
        // (w6-perception P-2). vault.entry throws on unknown ids; probe the
        // map directly instead.
        // A vault entry resolves only when it belongs to this tenant —
        // probing another tenant's key id is not an existence oracle.
        // Legacy untagged entries resolve through the tenant's bindings
        // (w6-fix F5).
        // (w6-tenancy F4).
        key: () => (this.chainOwnsVaultKey(t, input.id) ? this.vault.keys.get(input.id) : null) || (Object.hasOwn(this.identities(t), input.id) ? this.identities(t)[input.id] : null) || (Object.hasOwn(this.tenant(t).issuers, input.id) ? this.tenant(t).issuers[input.id] : null) || Object.values(this.perceptionComponents[t] ?? {}).find(c => c.signing.key_id === input.id),
        subject: () => Object.values(this.tenant(t).identities).some(i => i.subject_id === input.id),
        device: () => Object.values(this.tenant(t).identities).some(i => i.device_id === input.id),
        capability: () => this.store.get(t, 'capability', input.id),
        grant: () => this.target.allGrants(t).some(g => g.grant_id === input.id),
        token: () => Object.hasOwn(this.tenant(t).auth, input.id) ? this.tenant(t).auth[input.id] : null,
        // `exists` itself is a table lookup — the prototype chain must not
        // shadow a kind either.
      }[Object.hasOwn({ certificate:1, evidence:1, issuer:1, key:1, subject:1, device:1, capability:1, grant:1, token:1 }, input.kind) ? input.kind : ''];
      requireThat(exists?.(), 'INV-404-NOT-FOUND', `No live ${input.kind} authority with that id`, 404);
      // Re-revocation is refused: the first revocation's `revoked_at` is the
      // forensically important fact and must never be rewritten (w11 F6).
      requireThat(!this.revoked(t, input.kind, input.id), 'INV-409-STATE', 'Authority already revoked', 409);
      // The bound execution or audit signer cannot be revoked without a
      // pending, tenant-owned successor covering its purposes — the recovery
      // rotation needs certificates and outcome signatures to keep flowing,
      // and only the successor supplies them (w10-cert F5, w11-lifecycle
      // F1/F2: an unguarded execution-key revoke bricked the whole tenant).
      for (const klass of ['execution', 'audit']) if (input.kind === 'key' && input.id === this.keys(t)[klass]?.key_id) {
        const needed = this._keyPurposes[klass] ?? [];
        const successor = [...this.vault.keys.entries()].some(([kid, e]) => e.pending && !e.revoked && this.chainOwnsVaultKey(t, kid)
          && (e.purpose === 'any' || needed.every(x => (Array.isArray(e.purpose) ? e.purpose : [e.purpose]).includes(x))));
        requireThat(successor, 'INV-409-STATE', `Revoking the active ${klass} signer requires a pending successor key covering the ${klass} purposes — rotate first`, 409);
      }
      const payload = { ...clone(input), tenant_id: t, revoked_at: now, actor: p.subject_id, propagation: 'local-synchronous', remote_propagation: 'NOT_IMPLEMENTED' };
      // Sign the revocation envelope BEFORE the record lands — the signing
      // key is still valid at signature time, and revoking the audit key
      // itself would otherwise deadlock inside its own record write
      // (w6-fix F4).
      const envelope = this.signAudit(p.tenant_id, payload, 'revocation');
      // The chain event lands BEFORE the floor row: the divergence check
      // (floor ⊆ anchored revocations, inside _auditIndex) must never see a
      // floor row whose event is still unwritten — that ordering would
      // deadlock the revoking write itself (w12-provenance F9).
      if (input.remediation_service) this.store.audit(t, 'REMEDIATION_REQUESTED', p.subject_id, `${input.kind}:${input.id}`, { service: input.remediation_service, dispatched: false, channel: 'external-system-not-integrated' }, now);
      // record_digest pins the stored revocation row to its signed event —
      // the incident report can then cross-check each mutable record
      // against the chain instead of trusting store contents
      // (w13-fixverify L7).
      // Operator free-text digests are keyed under the vault master key —
      // a bare digest over bounded operator vocabulary ("custodian device
      // compromised", "contract ended") is an offline dictionary oracle to
      // every envelope holder (w15-timing F3). Verification then needs
      // vault custody — the same authority the audit signer already needs.
      const metaMac = v => createHmac('sha256', this.vault.masterKey).update(canonical(v)).digest('base64url');
      this.store.audit(t, 'AUTHORITY_REVOKED', p.subject_id, `${input.kind}:${input.id}`, { reason_digest: metaMac(input.reason), record_digest: metaMac(payload) }, now);
      this.store.put(t, 'revocation', `${input.kind}:${input.id}`, payload, now);
      return envelope;
    });
    // The dataplane write lands AFTER the ledger commit: a revocation that
    // fails its ledger write must never silently kill the grant anyway, and
    // a ledger-confirmed revoke that can't reach the dataplane is healed by
    // _reconcileLedger on the next open (w9-network F5).
    if (input.kind === 'grant') this.target.revokeGrant(p.tenant_id, input.id);
    // A ledger revocation on a vault key also flips the vault flag — the
    // ledger stays authoritative (post-commit), and vault-level APIs that
    // consult only their own entry map cannot sign under a revoked key
    // (w11-fix F4).
    if (input.kind === 'key' && this.chainOwnsVaultKey(p.tenant_id, input.id)) { this.vault.revoke(input.id); this.persistVault(); }
    return env;
  }
  revocations(p, kind = null) {
    this.authorize(p, ['operator', 'security', 'auditor', 'policy_admin']);
    const idx = this._auditIndex(p.tenant_id);
    // Every returned record is cross-checked against the signed chain:
    // anchored when its AUTHORITY_REVOKED event carries this row's digest
    // (post-upgrade) or at least its kind:id (legacy events). A record
    // with no anchor at all is a store-level plant and is excluded — the
    // floor check inside the index already wedges on it, but the report
    // must never present a fabricated revocation as real (w13-fixverify
    // L7).
    // record_digest is keyed under the vault master key (w15-timing F3) —
    // the cross-check recomputes with the same key, so an external reader
    // cannot and an insider with row-write but no vault still fails it.
    const metaMac = v => createHmac('sha256', this.vault.masterKey).update(canonical(v)).digest('base64url');
    const items = this.store.list(p.tenant_id, 'revocation', 10000).filter(i => idx.revoked.has(`${i.kind}:${i.id}`)).map(i => ({ ...i, anchored: (idx.revocationDigests.get(`${i.kind}:${i.id}`) ?? null) === metaMac(i) ? true : 'identity-only' }));
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
      this.store.insert(p.tenant_id, 'simulation', result.simulation_id, result, now); this.store.audit(p.tenant_id, 'POLICY_SIMULATED', p.subject_id, result.simulation_id, { candidate_digest: digest(candidate), baseline_digest: digest(active), result_digest: digest(result) }, now); return result;
    });
  }
  // Every coverage state change passes through here so the coverage-event
  // history and owner tasks can never disagree with the stored path.
  coverageTransition(tenant, path, to, cause, now) {
    path.status = to; if (to === 'UNKNOWN') path.evidence_at = null;
    this.store.put(tenant, 'coverage', path.path_id, path, now);
    // Events and tasks are upserts: a same-millisecond re-transition must
    // never throw INV-409 inside the caller's transaction and roll back the
    // drift record itself (w8-composite F12).
    this.store.put(tenant, 'coverage-event', `${path.path_id}:${now}:${cause}`, { type: 'transitioned', path_id: path.path_id, to, evidence_at: path.evidence_at, at: now, cause }, now);
    // Owner tasks exist only for degraded/unprotected states — a promotion
    // is a resolution, not a new obligation. UNCOVERED means the path is
    // declared unprotected: the owner must close it or enforce it.
    if (to === 'UNKNOWN' || to === 'UNCOVERED') {
      const taskId = `${cause}:${path.path_id}`, prev = this.store.get(tenant, 'coverage-task', taskId);
      this.store.put(tenant, 'coverage-task', taskId, prev?.status === 'open' ? { ...prev, refreshed_at: now } : { path_id: path.path_id, owner: path.owner, cause, opened_at: now, status: 'open', required_action: to === 'UNKNOWN' ? 'attach independently executed technical validation evidence' : 'close this declared-unprotected path or bring it under enforced coverage' }, now);
    } else {
      // A promotion closes every open task for this path — drift tasks must
      // not linger after revalidation (w8-composite F12).
      for (const id of this.store.ids(tenant, 'coverage-task', 10000)) {
        const task = this.store.get(tenant, 'coverage-task', id);
        if (task && task.path_id === path.path_id && task.status === 'open') this.store.put(tenant, 'coverage-task', id, { ...task, status: 'closed', closed_at: now }, now);
      }
    }
  }
  coverage(p) {
    this.authorize(p, ['operator', 'approver', 'custodian', 'security', 'auditor', 'policy_admin']);
    return this.transaction(p, now => {
      // Evidence-expiry is a real transition, not a computed convenience: a
      // MONITORED path that ages out is recorded UNKNOWN with its coverage
      // event and owner task, exactly like a drift-driven drop (w8-ledger
      // COV-005). Idempotent — stored UNKNOWN paths never re-fire.
      const idx = this._auditIndex(p.tenant_id);
      const rows = this.store.list(p.tenant_id, 'coverage', 10000);
      for (const path of rows)
        if ((path.status === 'MONITORED' || path.status === 'ENFORCED') && effectiveStatus(path, now) === 'UNKNOWN')
          this.coverageTransition(p.tenant_id, path, 'UNKNOWN', 'evidence-expired', now);
      // Only chain-declared paths may appear in a vault-signed manifest —
      // a forged coverage row cannot claim ENFORCED under the gate's
      // signature; planted rows are reported separately, never attested
      // (w17-redteam A3).
      const anchoredRows = rows.filter(path => (idx.coverageAnchors ?? new Map()).has(path.path_id));
      const unanchored = rows.filter(path => !(idx.coverageAnchors ?? new Map()).has(path.path_id)).map(path => path.path_id);
      return coverageManifest(p.tenant_id, anchoredRows, now, payload => this.signAudit(p.tenant_id, payload, 'coverage'), { unanchored });
    });
  }
  // COV-009: what the coverage record showed at an arbitrary past instant —
  // answered from the coverage-event log, not the current mutable state.
  coverageAt(p, at) {
    this.authorize(p, ['operator', 'approver', 'custodian', 'security', 'auditor', 'policy_admin']);
    const atTime = integer(Number(at), 'at', 1, 1e14);
    // Events replay in write order — store.list is newest-first and id
    // ordering is lexical, so neither can be trusted for same-ms ties
    // (w8-composite F10). rowid is the durable insertion sequence.
    const events = this.store.db.prepare("SELECT id,value FROM records WHERE tenant=? AND kind='coverage-event' ORDER BY rowid").all(p.tenant_id).map(row => this.store.readValue(p.tenant_id, 'coverage-event', row.id, row.value));
    return { at: atTime, paths: coverageAt(events, atTime) };
  }
  declareCoverage(p, input) {
    this.authorize(p, ['security']); return this.transaction(p, now => {
      const path = declarePath(input, now);
      // Re-declaring an identical path carries its evidence forward — only a
      // real configuration change resets the observation window; a bare
      // re-declare can never mint MONITORED over nothing (w8-composite F11).
      const prior = this.store.get(p.tenant_id, 'coverage', path.path_id);
      if (prior && prior.configuration_digest === path.configuration_digest && prior.target === path.target && prior.action_type === path.action_type) {
        path.evidence_at = prior.evidence_at; path.evidence_digest = prior.evidence_digest; path.technical_validation = prior.technical_validation;
      }
      if (path.status === 'MONITORED' && path.evidence_at === null) path.status = 'UNKNOWN';
      this.store.put(p.tenant_id, 'coverage', path.path_id, path, now);
      this.store.put(p.tenant_id, 'coverage-event', `${path.path_id}:${now}:declared`, { type: 'declared', path_id: path.path_id, path, at: now }, now);
      if (path.status === 'UNKNOWN') this.store.put(p.tenant_id, 'coverage-task', `declared-unknown:${path.path_id}`, { path_id: path.path_id, owner: path.owner, cause: 'declared-unknown', opened_at: now, status: 'open', required_action: 'attach independently executed technical validation evidence' }, now);
      if (path.status === 'UNCOVERED') this.store.put(p.tenant_id, 'coverage-task', `declared-uncovered:${path.path_id}`, { path_id: path.path_id, owner: path.owner, cause: 'declared-uncovered', opened_at: now, status: 'open', required_action: 'close this declared-unprotected path or bring it under enforced coverage' }, now);
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
      requireThat(!this._auditIndex(p.tenant_id).issuerDrift.has(envelope.protected.key_id), 'INV-403-QUARANTINE', 'Issuer connector drifted — validation suspended pending revalidation', 403);
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
      // keep a path covered must actually extend coverage (w7-seam F10).
      // A passed independent bypass test is the ENFORCED criterion: it
      // promotes UNKNOWN, UNCOVERED and MONITORED alike (w8-composite F13).
      path.evidence_at = now;
      if (path.status === 'ENFORCED') this.store.put(p.tenant_id, 'coverage', path.path_id, path, now);
      else this.coverageTransition(p.tenant_id, path, 'ENFORCED', 'technical-validation', now);
      this.store.put(p.tenant_id, 'coverage-event', `${path.path_id}:${now}:validation`, { type: 'technical_validation', path_id: path.path_id, validation: path.technical_validation, at: now }, now);
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
    // The proof attests a SIGNED leaf: the envelope at this sequence must
    // verify under an attested audit key and bind to its stored hash —
    // otherwise a forged row would ride a valid merkle path out the door
    // (w13-fixverify L4). auditPage re-checks hash/sequence/continuity.
    const leaf = this.store.auditPage(p.tenant_id, { after: sequence - 1, limit: 1 }).entries[0];
    requireThat(leaf?.sequence === sequence && leaf.envelope, 'INV-404-NOT-FOUND', 'Leaf not found', 404);
    const leafPl = verifySigned(leaf.envelope, this.auditPublicKeys(p.tenant_id), 'audit');
    // The proof claims a ledger-valid leaf — apply the same signing window
    // and tenant binding the index does: a row the index rejects (dead
    // key, foreign tenant) cannot be served as verified (w16-fixverify F12).
    const idx = this._auditIndex(p.tenant_id);
    const leafDeadAt = leaf.envelope.protected?.key_id !== undefined ? idx?.keyDeadAt.get(leaf.envelope.protected.key_id) : undefined;
    requireThat(leafPl.tenant_id === p.tenant_id && !(leafDeadAt !== undefined && leafDeadAt < leaf.sequence), 'INV-409-INTEGRITY', 'Leaf fails ledger signature verification', 409);
    return { format: 'IF-MERKLE-1', tenant_id: p.tenant_id, sequence, size: hashes.length, leaf_hash: hashes[sequence - 1], leaf_signature_verified: true, path: inclusionProof(hashes, sequence - 1), root: merkleRoot(hashes), verify: 'leaf = sha256(0x00||entry_hash); node = sha256(0x01||left||right); subtree partition = maximal aligned power-of-two split' };
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
      // Same keyed-digest treatment as revocation reasons — an exported
      // log must not hand an offline oracle for enumerable export purposes
      // like "quarterly PCI audit" (w15-timing F4).
      this.store.audit(p.tenant_id, 'AUDIT_ACCESSED', p.subject_id, 'tenant-log', { purpose_digest: createHmac('sha256', this.vault.masterKey).update(canonical({ purpose })).digest('base64url') }, now);
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
    // The audit READ surface is evidence: every served row must be a real
    // vault-signed entry, not an in-process forgery appended under the seq
    // trigger (w12 red-team). A row that fails signature verification flags
    // loudly rather than blending into history.
    const keys = this.auditPublicKeys(p.tenant_id), deadAt = this._auditIndex(p.tenant_id).keyDeadAt;
    for (const e of page.entries) {
      let ok = false; try {
        const kid = e.envelope?.protected?.key_id, dead = kid !== undefined ? deadAt.get(kid) : undefined;
        ok = e.envelope && !(dead !== undefined && dead < e.sequence) ? verifySigned(e.envelope, keys, 'audit').tenant_id === p.tenant_id : false;
      } catch { ok = false; }
      requireThat(ok, 'INV-409-INTEGRITY', 'Audit page contains a row whose ledger signature does not verify', 409);
    }
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
    const t = p.tenant_id;
    // Quarantine speaks before signature verification so the caller gets the
    // specific INV-403-QUARANTINE, not the generic signer-unavailable that a
    // device-folded identities() view would surface (w11-approval F1).
    this.assertHealthy(t, p.subject_id, this.identity(p).device_id, now);
    const payload = verifySigned(envelope, this.identities(t), 'action-approval');
    requireThat(payload.capsule_id === capsuleId, 'INV-403-SCOPE', 'Approval payload does not bind the declared action', 403);
    this.assertSuiteAllowed(t, envelope.protected.suite);
    fields(payload, ['tenant_id', 'capsule_id', 'capsule_digest', 'evidence_graph_digest', 'policy_digest', 'signer_id', 'approved_at', 'expires_at']);
    requireThat(payload.tenant_id === t && payload.signer_id === envelope.protected.key_id, 'INV-403-SCOPE', 'Approval scope mismatch', 403);
    const identity = this.identities(t)[payload.signer_id]; requireThat(identity.subject_id === p.subject_id, 'INV-403-SCOPE', 'Approval signer does not match authenticated identity', 403);
    const record = this.store.must(t, 'capsule', capsuleId); this.ensureMutable(record); this._capsuleIntegrity(t, record);
    requireThat(identity.subject_id !== record.capsule.actor.subject_id, 'INV-403-SEPARATION', 'An initiator cannot approve their own action', 403);
    requireThat(payload.capsule_digest === record.capsule_digest && payload.evidence_graph_digest === this.graph(t, record).digest && payload.policy_digest === digest(this.policy(t)), 'INV-409-STATE', 'Approval no longer matches action, evidence or policy', 409);
    integer(payload.approved_at, 'approval time', now - 300000, now + 5000); integer(payload.expires_at, 'approval expiry', now + 1, Math.min(record.capsule.expires_at, payload.approved_at + 300000));
    // Only a LIVE approval binds the signer: a lapsed envelope stops counting
    // in evaluation, and it must not also burn the signer's future votes —
    // otherwise ESCROW past the 5-minute approval TTL permanently wedges the
    // quorum (w11-lifecycle F3).
    requireThat(!record.approvals.some(a => a.payload.signer_id === payload.signer_id && a.payload.expires_at > now), 'INV-409-REPLAY', 'Signer already approved this action', 409);
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
    const idx = this._auditIndex(t);
    // Rows are mutable store records — each is reported with its chain
    // anchor state so an injected containment/revocation row can never
    // pass as ledger history (w13-fixverify L7).
    const denials = this.store.list(t, 'containment', 10000).map(c => ({ kind: 'denied_consume', at: c.contained_at, code: c.code, subject_id: c.subject_id, capability_id: c.capability_id, resource: c.resource, request_id: c.request_id, anchored: (idx.denialsByReq?.get(c.request_id) ?? []).some(d => d.code === c.code && d.actor === c.subject_id && d.capability_id === (c.capability_id ?? null)) }));
    // The anchored digest is vault-keyed (w15-timing F3): the cross-check
    // must recompute the same MAC — a plain digest() compares against a
    // different construction and the flag is always 'identity-only', i.e.
    // dead code that hid row tampering (w17-fixverify).
    const metaMac = v => createHmac('sha256', this.vault.masterKey).update(canonical(v)).digest('base64url');
    const quarantines = this.store.list(t, 'revocation', 10000).filter(r => ['subject', 'device'].includes(r.kind) && idx.revoked.has(`${r.kind}:${r.id}`)).map(r => ({ kind: 'revocation', at: r.revoked_at, revoked: `${r.kind}:${r.id}`, by: r.actor, anchored: (idx.revocationDigests.get(`${r.kind}:${r.id}`) ?? null) === metaMac(r) ? true : 'identity-only' }));
    const sequence = [...denials, ...quarantines].sort((a, b) => a.at - b.at);
    return { sequence, dropped_requests: denials.length, unanchored_rows: sequence.filter(x => x.anchored !== true).length, affected_capabilities: [...new Set(denials.map(d => d.capability_id).filter(Boolean))], quarantined: quarantines.map(q => q.revoked), limitation: 'Software dataplane telemetry only; packet-level counters require a real network path.' };
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
      // Session-key shredding is decoupled from the reference-scan gate
      // below: the 'perception-session' kind is tombstoned in place, never
      // deleted, so a cumulative id count hits the flat scan cap once and
      // wedges shredding forever (w15-timing F2). Page the whole kind — a
      // shred can only remove residency, never falsify a reference.
      let session_keys_shredded = 0, session_rows_scanned = 0, session_scan_exhausted = true;
      for (let offset = 0; offset < 100000; offset += 2000) {
        const page = this.store.ids(p.tenant_id, 'perception-session', 2000, offset);
        if (!page.length) break;
        session_rows_scanned += page.length;
        for (const id of page) {
          try {
            const s = this.store.must(p.tenant_id, 'perception-session', id);
            if (typeof s._server_private === 'string' && s.expires_at <= now) {
              this.store.put(p.tenant_id, 'perception-session', id, { ...s, _server_private: null, key_shredded_at: now }, now);
              session_keys_shredded++;
            }
          } catch { /* undecryptable session rows are reported via corrupt */ }
        }
        if (page.length < 2000) break;
      }
      if (session_rows_scanned >= 100000) session_scan_exhausted = false;
      const truncated = evidenceIds.length === 20000 || capsuleIds.length === 20000 || coverageIdsList.length === 10000;
      let deleted = 0, held = 0;
      // Conservative batch boundary: do not erase if a reference could be outside this scan.
      if (truncated) return { deleted: 0, held: items.length, session_keys_shredded, session_rows_scanned, session_scan_exhausted, corrupt: corrupt.length, reason: 'Reference scan limit reached; no deletion performed', complete_payload_erasure: false, truncated: true };
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
      // Expired perception sessions surrender their ECDH private key: after
      // expiry no release may be minted from them, so the "ephemeral" key
      // material must not outlive the session in the encrypted ledger
      // (w11-timing MED-3). The record and its binding stay provable — only
      // the key field is tombstoned. The paged scan above already ran it.
      return { deleted, held, session_keys_shredded, session_rows_scanned, session_scan_exhausted, corrupt: corrupt.length, corrupt_ids: corrupt.slice(0, 64).map(([k, i]) => `${k}:${i}`), corrupt_shredded: corrupt.length, complete_payload_erasure: false, truncated: false, limitation: 'Record DEKs are destroyed and the WAL truncated; ciphertext remaining in pre-erasure backups or external copies is not reachable by this operation.' };
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
      // A ceremony must be born alive: born-expired ceremonies and ghost
      // custodians are dead weight that can only ever confuse the ledger
      // (w11-approval F7).
      requireThat(input.valid_until > now, 'INV-400-SCHEMA', 'Ceremony valid_until must be in the future', 400);
      const members = Object.values(this.identities(t));
      const domains = new Set();
      for (const c of input.custodians ?? []) {
        const identity = members.find(i => i.subject_id === c);
        requireThat(identity, 'INV-404-NOT-FOUND', `Ceremony custodian ${c} is not a registered identity subject`, 404);
        domains.add(identity.failure_domain ?? c);
      }
      requireThat(domains.size >= (input.threshold ?? 0), 'INV-400-SCHEMA', 'Custodian failure domains cannot meet the ceremony threshold', 400);
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
      // Dealing is bound to the ceremony: the security officer or a member
      // custodian — a non-member custodian must never burn the ceremony and
      // pocket every share (w11-approval F3).
      requireThat(this.identity(p).roles.includes('security') || ceremony.custodians.includes(p.subject_id), 'INV-403-ROLE', 'Only a security officer or a ceremony member may deal shares', 403);
      commitShares(ceremony, shares, now);
      this.store.put(p.tenant_id, 'ceremony', ceremony.ceremony_id, ceremony, now);
      this.store.audit(p.tenant_id, 'CEREMONY_SHARES_COMMITTED', p.subject_id, ceremony.ceremony_id, { count: ceremony.share_commitments.length }, now);
      for (const n of ceremony.notices) this.store.audit(p.tenant_id, 'RECOVERY_NOTICE_ISSUED', p.subject_id, ceremony.ceremony_id, { custodian: n.custodian, channel: n.channel, issued_at: n.issued_at, delay_ms: ceremony.min_delay_ms }, now);
      return ceremonyReport(ceremony);
    });
  }
  // A committed-but-compromised ceremony must be retirable, not left live
  // until valid_until: security or a member custodian aborts it
  // (w11-approval F7).
  abortCeremony(p, ceremony_id) {
    this.authorize(p, ['security', 'custodian']);
    return this.transaction(p, now => {
      this.assertHealthy(p.tenant_id, p.subject_id, this.identity(p).device_id, now);
      const ceremony = this.store.must(p.tenant_id, 'ceremony', identifier(ceremony_id));
      requireThat(this.identity(p).roles.includes('security') || ceremony.custodians.includes(p.subject_id), 'INV-403-ROLE', 'Only a security officer or a ceremony member may abort the ceremony', 403);
      requireThat(!['completed', 'aborted'].includes(ceremony.status), 'INV-409-STATE', 'Ceremony is already closed', 409);
      const prior = ceremony.status;
      ceremony.status = 'aborted';
      this.store.put(p.tenant_id, 'ceremony', ceremony.ceremony_id, ceremony, now);
      this.store.audit(p.tenant_id, 'CEREMONY_ABORTED', p.subject_id, ceremony.ceremony_id, { prior_status: prior }, now);
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
      const quorum = this.custodianQuorum(t, ceremony);
      requireThat(quorum.live >= ceremony.threshold, 'INV-409-STATE', 'Ceremony lacks a live custodian quorum across failure domains', 409);
      const shares = encodedShares.map(s => decodeShare(s));
      // (the plain-array polynomial and its random-coefficient Buffer are
      // zeroed inside shamir.split — deal side matches reconstruct side,
      // w15-timing F7)
      // A presented share counts only if its custodian's ack is still live —
      // a revoked custodian's leaked share cannot satisfy reconstruction
      // (w11-approval F2).
      for (const s of shares) requireThat(quorum.custodians.has(ceremony.custodians[s.x - 1]), 'INV-403-ROLE', 'Share presented for a custodian who did not acknowledge or is no longer live', 403);
      // The delay clock runs on the anchored commitment time, not the
      // mutable row field — a rewritten committed_at cannot pre-date the
      // share commitment the ledger actually attested (w17-redteam A2
      // residual). A ceremony with no anchored commit cannot reconstruct.
      const anchoredCommitted = this._auditIndex(t).ceremonyCommitted?.get(ceremony.ceremony_id);
      requireThat(anchoredCommitted !== undefined, 'INV-409-INTEGRITY', 'Ceremony share commitment is not ledger-anchored', 409);
      const { secret, artifact } = reconstructSecret({ ...ceremony, committed_at: anchoredCommitted }, shares, now);
      this.store.put(t, 'ceremony', ceremony.ceremony_id, ceremony, now);
      // The reconstructed secret's digest goes on the audit record so the
      // ledger can prove WHICH secret the quorum reconstructed (w6 F6). It
      // is keyed under the vault master key — a bare digest would be an
      // offline dictionary oracle for weak ceremony secrets (w11-timing
      // LOW-4): verification needs vault custody, which is the same
      // authority the ceremony already requires.
      const secret_digest = createHmac('sha256', this.vault.masterKey).update(canonical({ ceremony_id: ceremony.ceremony_id, secret: Buffer.from(secret).toString('base64url') })).digest('base64url');
      // Share material and the reconstructed secret are consumables — the
      // Buffers are zeroed before this endpoint returns (w11-timing MED-4).
      for (const s of shares) s.y.fill(0); secret.fill(0);
      this.store.audit(t, 'CEREMONY_RECONSTRUCTED', p.subject_id, ceremony.ceremony_id, { quorum: artifact.quorum, purpose: ceremony.purpose, secret_digest }, now);
      return { artifact, reconstructed: true, secret_digest, note: 'Secret reconstructed under ceremony quorum; raw material is not returned by this endpoint.' };
    });
  }
  splitCeremonySecret(p, ceremony_id, secretB64) {
    this.authorize(p, ['security', 'custodian']);
    return this.transaction(p, now => {
      this.assertHealthy(p.tenant_id, p.subject_id, this.identity(p).device_id, now);
      const ceremony = this.store.must(p.tenant_id, 'ceremony', identifier(ceremony_id));
      // Same dealer binding as commitCeremonyShares — a non-member must not
      // rebind the artifact digest and invalidate prior consent
      // (w11-approval F3).
      requireThat(this.identity(p).roles.includes('security') || ceremony.custodians.includes(p.subject_id), 'INV-403-ROLE', 'Only a security officer or a ceremony member may deal shares', 403);
      requireThat(ceremony.status === 'planned', 'INV-409-STATE', 'Shares were already committed for this ceremony', 409);
      requireThat(typeof secretB64 === 'string', 'INV-400-SCHEMA', 'Secret must be a base64url string');
      const secret = Buffer.from(secretB64, 'base64url');
      requireThat(secret.length >= 16 && secret.length <= 512, 'INV-400-SCHEMA', 'Secret size out of bounds');
      const shares = splitSecret(secret, ceremony);
      // The deal-side plaintext copy is consumable too — the reconstruct
      // path already zeroes its material (w11-timing MED-4); asymmetric
      // residency would leave the ceremony secret on the heap (w15-timing F7).
      secret.fill(0);
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
    requireThat(Object.hasOwn(SUITES, suite), 'INV-400-SCHEMA', 'Unknown signature suite');
    return this.transaction(p, now => {
      // KEY-007: a rotated key keeps the class's purpose binding — 'any' would
      // destroy the separation genesis established (w5 F-4).
      const pending = this.vault.generate(this._keyPurposes?.[key_class] ?? 'any', { pending: true, suite, tenant_id: p.tenant_id });
      this.persistVault();
      // The record states the requirement, not a binding that exists yet —
      // the bond materializes only when a ceremony references this key
      // (w11-approval design note).
      this.store.audit(p.tenant_id, 'ROTATION_PREPARED', p.subject_id, pending.key_id, { key_class, ceremony_required: true }, now);
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
      // Bare-key lookup covers pre-namespacing rows as well (w9-fixverify
      // NB-5): a legacy nonce row must still block the replay.
      const seen = this.store.db.prepare('SELECT capsule FROM nonces WHERE tenant=? AND nonce IN (?, ?)').get(t, 'perception:' + attestation.payload.nonce, attestation.payload.nonce);
      requireThat(!seen && !this._auditIndex(t).perceptionNonce.has(attestation.payload.nonce), 'INV-409-REPLAY', 'Attestation nonce already consumed', 409);
      this.store.db.prepare('INSERT INTO nonces VALUES(?,?,?)').run(t, 'perception:' + attestation.payload.nonce, `perception:${session.session_id}`);
      const stored = { ...session, _server_private: session._server_private.export({ type: 'pkcs8', format: 'pem' }), creator: p.subject_id };
      this.store.insert(t, 'perception-session', session.session_id, stored, now);
      this.store.audit(t, 'PERCEPTION_SESSION', p.subject_id, session.session_id, { component: session.component, assurance: session.assurance, firmware: session.firmware_version, nonce: attestation.payload.nonce }, now);
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
      // The cited decision must equal the one the chain attests — editing
      // the mutable decision object cannot launder provenance
      // (w13-fixverify L5).
      requireThat(this._auditIndex(t).decisions.get(record.capsule.capsule_id) === digest(record.decision), 'INV-409-INTEGRITY', 'Recorded decision diverges from the ledger', 409);
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
        // The narrated decision is the chain-anchored one — a tampered
        // decision object cannot receive an official explanation
        // (w13-fixverify L5).
        requireThat(this._auditIndex(p.tenant_id).decisions.get(record.capsule.capsule_id) === digest(record.decision), 'INV-409-INTEGRITY', 'Recorded decision diverges from the ledger', 409);
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

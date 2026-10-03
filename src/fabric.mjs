import { randomUUID, randomBytes, createHmac, createPrivateKey, createPublicKey } from 'node:crypto';
import { Store } from './store.mjs';
import { SimulatedTarget } from './target.mjs';
import { RuntimeGate } from './runtime.mjs';
import { digest, clone, canonical, hashBytes } from './canonical.mjs';
import { verifySigned, decrypt, ctEqual } from './crypto.mjs';
import { KeyVault, derivePublic } from './keystore.mjs';
import { merkleMemo, verifyInclusion } from './merkle.mjs';
import { httpJson, postOnce, readWithRetry, driftCheck, verifyManifest } from './connectors.mjs';
import { createCeremony, acknowledge, commitShares, splitSecret, reconstructSecret, ceremonyReport } from './ceremony.mjs';
import { decodeShare, encodeShare } from './shamir.mjs';
import { SUITES } from './crypto.mjs';
import { openSession, releaseFields, workspaceFallback, ASSURANCE } from './secureview.mjs';
import { extract, explain, classifyIntent } from './advisory.mjs';
import { fields, text, identifier, integer, uniqueStrings, validateProposal } from './schema.mjs';
import { evaluatePolicy, validatePolicy, policyDiff } from './policy.mjs';
import { declarePath, coverageManifest, applyDriftToPaths, effectiveStatus } from './coverage.mjs';
import { watermark, reconstructionCheck } from './datagate.mjs';
import { requireThat, InvariantError } from './errors.mjs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { existsSync, readFileSync, writeFileSync, mkdirSync, renameSync, rmSync, rmdirSync, statSync, openSync, writeSync, fsyncSync, closeSync, chmodSync } from 'node:fs';

// Issuer fields that legitimately rotate at runtime; everything else on the
// issuer record is a trust anchor and stays frozen (w11-redteam R12).
const ISSUER_MUTABLE = new Set(['issue_token', 'read_token', 'token_expires_at']);
// Read-surface scrub for material fields: key names an operator may
// plausibly store secret bytes under are over-redacted rather than leaked
// — a suppressed display field costs a reader, a verbatim secret costs the
// secret (w15-timing F1). Shared by capsuleView and the resources route,
// which must not serve registry material verbatim (w38-http LOW).
const secretFieldKey = k => /secret|private|password|passwd|passphrase|token|share|credential|seed|entropy|otp|pin|bearer|recovery|ssn|cvv|api.?key|auth.?key|master.?key|data.?key|access.?key|encryption.?key|signing.?key|session.?key|client.?key|aws_access_key_id|key.?material|_key$|^key$|^auth$|_auth$|^value$/i.test(k);
const scrubSecrets = v => (v && typeof v === 'object') ? (Array.isArray(v) ? v.map(scrubSecrets) : Object.fromEntries(Object.entries(v).map(([k, x]) => [k, secretFieldKey(k) ? '«redacted»' : scrubSecrets(x)]))) : v;
function redactMaterialFields(material_fields) {
  if (Array.isArray(material_fields?.rows)) {
    const { rows, ...rest } = material_fields;
    return { ...scrubSecrets(rest), row_count: rows.length, rows_digest: digest(rows) };
  }
  if (material_fields && typeof material_fields === 'object') return scrubSecrets(material_fields);
  // A scalar/null container has no keys to scrub — the route selected this
  // field because it is sensitive, so the whole value redacts (w40-fv F-8).
  if (material_fields === undefined || material_fields === null) return material_fields;
  return { redacted: true, value_digest: digest(material_fields) };
}

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
  // In-tx revocation-write flag feeding the floor check's probe skip
  // (w43-perf): set by the store record hook, cleared when the check runs.
  #floorDirty = null;
  // Tenants whose post-commit side effects failed in THIS process — the
  // next transaction() replays the idempotent ledger heal before new work
  // attests over a diverged dataplane (w22 F6).
  #pendingEffects = new Set();
  #denyAudit = new Map();
  #verifyMemo = new Map();
  #rejectMemo = new Map();
  #declaredRetired = {};
  // Signed end-of-chain watermarks (w24-fixverify W24-01): #pendingChainHeads
  // buffers per-commit appends. The file itself is untrusted input and is
  // re-read + re-verified on every fold — a post-boot rewrite must scream,
  // not ride a first-read cache forever.
  #auditSigners = {};
  #pendingChainHeads = null;
  #headFlushStarved = null;
  // Per-tx-depth snapshots of #pendingChainHeads — restored on savepoint
  // rollback so a doomed append never clobbers the outer head (w29-fv F12).
  #pendingHeadStack = null;
  #headFsyncTicks = 0;
  #cfShapeStmt = null;
  #capsuleIntegrityMemo = null;
  #cfScanStmt = null;
  // Flush hot-path caches (w28-http CI regression): the signer-death map
  // grows only on key-lifecycle audit rows, so it is maintained
  // incrementally from the append-only table instead of a full table
  // scan per flush; the verify-key set is content-addressed by a signature of
  // every input it consults; a stored head envelope's verification is
  // memoized on its serialized bytes plus the verifier fingerprint.
  _keyDeathCache = new Map();
  _verifyKeyCache = new Map();
  _headEnvVerifyCache = new Map();
  _suiteAllowCache = new Map();
  _signSelCache = new Map();
  // Non-null only inside a synchronous transaction() window: file-side
  // index probes memoize per transaction (see _auditIndex).
  _probeMemo = null;
  // Tenants whose chain is being sealed RIGHT NOW: the seal is the only
  // path allowed to move the signed watermark backward, so _auditIndex's
  // head checks stand down inside its transaction — the fold's per-row
  // signature verification keeps running (w25-clock F-2).
  #sealing = null;
  #sealCarry = new Map();
  #chainHeadRaw = undefined;
  #chainHeadParsed = null;
  #chainHeadVerdicts = new Map();
  // Incremental merkle per tenant — leaf list + subtree memo (w33-export F4).
  #merkle = new Map();
  _merkle(t) {
    let m = this.#merkle.get(t);
    if (!m) { m = merkleMemo(); this.#merkle.set(t, m); }
    m.sync(this.store.auditHashes(t));
    return m;
  }
  // Last-known durable head watermark per tenant — the file stays
  // authoritative (every locked bump re-reads it), but equal/regressed
  // bumps must not pay a lock + parse on every _auditIndex fold.
  #headWm = new Map();
  // Watermark entries that failed verification or were unsigned above the
  // committed head — surfaced in the seal report as named evidence rather
  // than silently absorbed (w38 runtime-gate F-2).
  #wmTamper = new Map();
  // Raw-bytes → parsed memo for the durable watermark file (w28-fixverify
  // F4: the file is re-read every call, the parse is what caches).
  #headWmRaw = undefined;
  #headWmParsed = null;
  #headWmStatKey = undefined;
  // entry-object → resolved seq memo: #headWmParsed returns the SAME entry
  // object while the file bytes are unchanged, so identity-keying skips the
  // signature re-verify on every fold (w38 CI: verify per read halved
  // evaluate() throughput; NFR-PERF-004 regressed on CI runners).
  #wmVerified = new Map();
  // audit-checkpoint row digest → attested size, pinned to the verifier-key
  // fingerprint — rotation invalidates, tampered row bytes re-verify (w38 CI).
  #cpHeadVerify = new Map();
  // Coverage-denominator memo: raw row count → decrypt-verified count
  // (w40-fv F-7).
  #verifiedRows = new Map();
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
        // Embedded-custody divergence: a vault-resident entry under the
        // configured id whose public half differs from the config binding
        // means the wrapped material no longer attests the declared key —
        // report config corruption, never silently keep both halves
        // (w28-crypto F9).
        const resident = this.vault.keys.get(key.key_id);
        requireThat(resident.public_key === key.public_key, 'INV-503-CONFIG', `Tenant ${klass} key material diverges from vault residency`, 503);
      }
      auditSigners[tenant] = { key_id: t.keys.audit.key_id, public_key: t.keys.audit.public_key, keys: () => this.auditPublicKeys(tenant), sign: (payload, purpose = 'audit') => { const sel = this._signingKeyId(tenant, 'audit'); const e = this.vault.keys.get(sel.key_id); this.assertSuiteAllowed(tenant, e?.suite ?? 'Ed25519'); return this.vault.envelope(sel.key_id, purpose, this._recoveryBody(sel, payload), { allowPending: sel.recovery, tenant_id: tenant }); } };
    }
    // Both migrators consult one dedup index so a ciphertext grafted
    // between the two DBs is caught by whichever side sees it second
    // (w19-aad W19-1).
    const aadDedup = new Map();
    this.store = new Store(join(directory, 'fabric.db'), encryption, auditSigners, { aadDedup });
    // A wiped fabric.db beside surviving deployment artifacts is not a
    // fresh start — re-genesis would silently forgive revocations and
    // re-arm spent nonces (w30-store F1). Either artifact is unambiguous
    // proof of prior operation: the keystore wraps keys minted at
    // provisioning, and target.db holds state committed by earlier
    // transactions. Vault-injected opens are provisioning contexts —
    // bootstrap legitimately writes the keystore BEFORE the first boot —
    // so the gate guards only boots that load their trust anchor from
    // the directory. The honest escape is deleting the whole directory.
    if (vault === null && (existsSync(join(this.directory, 'keystore.json')) || existsSync(join(this.directory, 'target.db'))) && this.store._stmt('SELECT COUNT(*) n FROM audit').get().n === 0)
      throw new InvariantError('INV-503-STORAGE', 'Prior-deployment artifacts exist but the audit ledger is empty — refusing to silently re-genesis a wiped deployment; delete the deployment directory for a true fresh start', 503);
    // Per-tenant wipe gate (w31-fixverify F1): a global audit count lets a
    // file-writer erase ONE tenant's rows and head entries while a sibling
    // keeps the deployment alive — the wiped tenant then silently
    // re-genesises, forgiving revocations and re-arming spent nonces and
    // idempotency keys. For each configured tenant, an empty own ledger
    // alongside ANY per-tenant residue — a chain-heads entry, a durable
    // watermark entry, leftover rows, or a peer's signed head envelope
    // attesting the tenant existed — refuses the boot; only a residue-free
    // tenant may legitimately genesis.
    if (vault === null) {
      const residue = t =>
        this.store._stmt('SELECT COUNT(*) n FROM records WHERE tenant=?').get(t).n > 0
        || this.store._stmt('SELECT COUNT(*) n FROM nonces WHERE tenant=?').get(t).n > 0
        || this.store._stmt('SELECT COUNT(*) n FROM idempotency WHERE tenant=?').get(t).n > 0
        || this.store._stmt('SELECT COUNT(*) n FROM deks WHERE tenant=?').get(t).n > 0
        || this.store._stmt('SELECT COUNT(*) n FROM usage WHERE tenant=?').get(t).n > 0
        || this.store._stmt('SELECT COUNT(*) n FROM data_access WHERE tenant=?').get(t).n > 0;
      // target.db carries committed mutations too — wiping fabric.db while
      // target state survives is the same silent re-genesis, so its tables
      // join the residue probe (w32-store F4).
      let targetResidue = () => false;
      if (existsSync(join(this.directory, 'target.db'))) {
        try {
          const tdb = new DatabaseSync(join(this.directory, 'target.db'), { readOnly: true });
          try {
            const tenantTables = [];
            for (const { name } of tdb.prepare("SELECT name FROM sqlite_master WHERE type='table'").all())
              if (tdb.prepare(`PRAGMA table_info("${name.replaceAll('"', '""')}")`).all().some(c => c.name === 'tenant')) tenantTables.push(name);
            targetResidue = t => tenantTables.some(tbl => tdb.prepare(`SELECT 1 FROM "${tbl.replaceAll('"', '""')}" WHERE tenant=? LIMIT 1`).get(t) !== undefined);
          } finally { tdb.close(); }
        } catch { /* unreadable target.db: SimulatedTarget's own open reports it */ }
      }
      const headFile = this._readChainHeadFile();
      const headEntries = headFile && headFile !== 'oversized' && headFile.tenants && !Array.isArray(headFile.tenants) ? headFile.tenants : {};
      const watermarkEntries = this._readHeadWatermark() ?? {};
      const auditCount = this.store._stmt('SELECT COUNT(*) n FROM audit WHERE tenant=?');
      for (const t of Object.keys(this.#tenants)) {
        if (auditCount.get(t).n > 0) continue;
        let attested = headEntries[t] !== undefined || watermarkEntries[t] !== undefined;
        if (!attested) {
          // A surviving peer's signed head names the tenants that had
          // committed rows when it was minted — verify signatures before
          // trusting the list, a planted envelope attests nothing.
          for (const [other, env] of Object.entries(headEntries)) {
            if (other === t) continue;
            try {
              const pl = verifySigned(env, this._verifyKeysCached(other, 'audit'), 'audit');
              if (Array.isArray(pl?.tenants) && pl.tenants.includes(t)) { attested = true; break; }
            } catch { /* unverifiable peer entry attests nothing */ }
          }
        }
        if (attested || residue(t) || targetResidue(t))
          throw new InvariantError('INV-503-STORAGE', `Prior-deployment residue exists for tenant '${t}' but its audit ledger is empty — refusing to silently re-genesis a wiped tenant; delete the deployment directory for a true fresh start`, 503);
      }
    }
    this.target = new SimulatedTarget(join(directory, 'target.db'), encryption, { aadDedup });
    // End-of-chain commitment (w24-fixverify W24-01): every committed audit
    // append moves a vault-signed {seq,hash} watermark persisted outside the
    // audited table (chain-heads.json). A file-writer truncating the tail can
    // roll rows back but cannot forge the signature to pull the watermark
    // back — the fold refuses to run below it.
    this.#auditSigners = auditSigners;
    this.store.onAuditAppend = (tenant, seq, hash) => { (this._ownSeq ??= new Map()).set(tenant, Math.max(this._ownSeq.get(tenant) ?? 0, seq)); this._chainHeadNote(tenant, seq, hash); };
    // Inside a write transaction the revocation floor inputs change only
    // through this connection's own puts/removes — flag them so an index
    // that has seen no such write can skip the per-call floor rescan
    // (w43-perf). A flag surviving its own rollback only costs one extra
    // rescan — it can never skip a check that mattered.
    this.store.onRecordWrite = (tenant, kind) => { if (kind === 'revocation') (this.#floorDirty ??= new Set()).add(tenant); };
    // A bare store.tx commit is a real commit edge too — audit() self-wraps
    // in one when no fabric transaction is open, and the pending head must
    // not wait for a later edge (w28-store F2, w28-regression w25/w27).
    this.store.onTxCommit = () => this._flushChainHeadsGuarded();
    // Pending heads ride the same tx boundary as the anchor floor: a
    // savepoint that rolls back must restore the note map — otherwise the
    // doomed append's note clobbers the outer committed append's head and
    // the phantom check silently starves the watermark (w29-fixverify F12).
    this.store.onTxDepth = ev => {
      if (ev === 'push') (this.#pendingHeadStack ??= []).push(new Map(this.#pendingChainHeads ?? []));
      else if (ev === 'pop') this.#pendingHeadStack?.pop();
      else if (ev === 'rollback') {
        const snap = this.#pendingHeadStack?.pop(); if (snap !== undefined) this.#pendingChainHeads = snap;
        // A mid-tx fold may have consumed appends the rollback just erased
        // — an index head past the committed tip is a phantom anchor that
        // would wedge every later fold on a false tamper label (w41-seal
        // F2). Bare store.tx callers get the same eviction transaction()
        // applies on its own rollback path.
        for (const [t, idx] of this.#auditIdx ?? [])
          if (idx.maxSeq > this.store.auditHeadSeq(t)) this.#auditIdx.delete(t);
        // The same doomed appends could have minted phantom key-death /
        // succession / ceremony facts in _keyDeathCache — a mid-tx scan
        // folds uncommitted rows too. Evict on rollback so the cache can
        // never outlive the rows that produced it (w43-store F-1).
        this._keyDeathCache.clear();
        // The tx-window facts memo lives outside _keyDeathCache: its hit
        // key still matches because _auditAppends is not decremented by a
        // rollback, so without this eviction the window keeps serving
        // phantom deaths minted by the doomed rows (w46-store M-1).
        for (const k of [...(this._probeMemo?.keys() ?? [])]) if (k.startsWith('cf:')) this._probeMemo.delete(k);
        // Same phantom class in the honoured-grants memo: its key mixes
        // idx.maxSeq (rewound by the doomed-appends eviction above) with
        // monotone dirt counters, so a rollback that rewinds a doomed
        // JIT_GRANT_ISSUED to an identically-shaped refill hits a stale
        // entry and serves a grant the chain no longer attests
        // (w47-fixverify HIGH-3). WeakMap has no clear — rebind it.
        this._grantsMemo = new WeakMap();
      }
    };
    // Migration accounting is observable, not silent: every re-sealed,
    // collided, ambiguous or unreadable row lands on the tenant's ledger
    // at open (w19-aad W19-2). Durable meta_kv markers (written inside the
    // migrations' own commits) signal a completed migration whose
    // attestation may not have landed — a restart that lost the in-memory
    // maps still surfaces the marker at next open (w43-store F-4). The
    // marker is plaintext in an attacker-writable table, so it is a
    // trigger, never a source: the attestation carries only the live
    // counters this process computed plus each marker's DIGEST — copying
    // the marker's counters would let a planted row mint signed-but-false
    // attestations (w44-ledger F2).
    const migPending = new Map();
    for (const src of [this.store, this.target]) {
      let rows = [];
      try { rows = src._stmt("SELECT tenant,value FROM meta_kv WHERE key='aad_migration'").all(); }
      catch (e) {
        // meta_kv is created unconditionally in the store ctor — a failed
        // read on a table the schema swears exists is a dropped table, not
        // a pre-marker database: classify it as tamper evidence rather
        // than absorbing the pending markers silently (w46-seal F-2).
        const exists = src._stmt("SELECT COUNT(*) n FROM sqlite_master WHERE type='table' AND name='meta_kv'").get()?.n > 0;
        if (!exists) throw new InvariantError('INV-409-INTEGRITY', 'Ledger schema diverged (meta_kv dropped) — tamper evidence', 409, { cause: e });
        throw e;
      }
      for (const r of rows) {
        let d = migPending.get(r.tenant); if (!d) { d = { digests: [] }; migPending.set(r.tenant, d); }
        if (d.digests.length < 4) d.digests.push(hashBytes(r.value));
      }
    }
    // Dedupe membership counts only VERIFIED signed migration rows —
    // audit_seq_guard permits an unsigned append at MAX(seq)+1, so an
    // attacker-planted envelope carrying the digest in marker_digests must
    // never suppress the attestation that names the residue (w45-ledger
    // HIGH-1). The SQL narrows to parsed type+field (a LIKE over raw text
    // would let any planted row match — w44-store M-1); the verify pass
    // makes the plant evidence, not cover. And the narrowing itself can be
    // dup-keyed: json_extract reads the FIRST member where JSON.parse
    // reads the LAST, so a grafted decoy 'payload' carrying the digest
    // would satisfy the SQL while the verified bytes name nothing — every
    // dup member makes the row a candidate and the PARSED envelope decides
    // attestation, never the SQL hit (w46-ledger HIGH-1).
    const aadDedupeStmt = this.store._stmt("SELECT envelope FROM audit WHERE tenant=? AND json_valid(envelope) AND ((json_extract(envelope,'$.payload.type') IN ('AAD_MIGRATION','AAD_MIGRATION_MARKER') AND instr(COALESCE(json_extract(envelope,'$.payload.metadata.marker_digests'),''), ?) > 0) OR EXISTS (SELECT 1 FROM json_each(envelope,'$') GROUP BY \"key\" HAVING COUNT(*)>1) OR EXISTS (SELECT 1 FROM json_each(envelope,'$.payload') GROUP BY \"key\" HAVING COUNT(*)>1))");
    const aadAttested = (t, d) => {
      for (const row of aadDedupeStmt.all(t, d)) {
        try {
          const env = JSON.parse(row.envelope), pl = env?.payload;
          verifySigned(env, this.auditPublicKeys(t), 'audit');
          if ((pl?.type === 'AAD_MIGRATION' || pl?.type === 'AAD_MIGRATION_MARKER')
            && Array.isArray(pl?.metadata?.marker_digests) && pl.metadata.marker_digests.includes(d)) return true;
          // Verified but names no attested digest: a dup-graft decoy — it
          // is evidence, never attestation (w46-ledger HIGH-1).
        } catch { /* unsigned or malformed candidate — evidence, not cover */ }
      }
      return false;
    };
    // Durable twin on the append-only chain: the meta_kv marker survives a
    // file-writer's guard-drop + delete + verbatim-recreate (w47-fixverify
    // HIGH-2). A boot that migrates rows also lands a signed
    // AAD_MIGRATION_PENDING row naming the migration digest — append-only
    // means no attacker can erase the owed attestation; a later open
    // re-derives it from the chain with the marker gone. The marker stays
    // as the cheap same-boot signal; the pending row is the cross-boot
    // continuity witness.
    for (const [origin, src] of [['store', this.store], ['target', this.target]])
      for (const [t, s] of (src.aadMigration ?? new Map())) {
        if (!(s.migrated + s.transplants + s.ambiguous + s.skipped > 0)) continue;
        const mid = hashBytes(canonical({ origin, migrated: s.migrated, transplants: s.transplants, ambiguous: s.ambiguous, skipped: s.skipped }));
        let landed = false;
        try { this.store.tx(() => { this.store.clock(this.clock()); this.store.audit(t, 'AAD_MIGRATION_PENDING', 'system', 'fabric-open', { origin, ...s, migration_id: mid }, this.clock()); }); landed = true; }
        catch (e) { if (!String(e?.code ?? '').startsWith('INV-')) throw e; /* unsignable tenant or wedged chain — the marker still signals; the pending path must never brick an open */ }
        if (landed) {
          const d = migPending.get(t) ?? { digests: [] };
          if (!d.digests.includes(mid) && d.digests.length < 8) d.digests.push(mid);
          (d.pendStats ??= new Map()).set(mid, { origin, ...s });
          migPending.set(t, d);
        }
      }
    // Pendings from earlier boots: verified signed rows only — a planted
    // unsigned pending names nothing (same dedupe doctrine as markers).
    // Each pending's migration_id joins the fresh-filter set so the
    // attestation below names the owed residue exactly once.
    const pendingScan = this.store._stmt("SELECT tenant,envelope FROM audit WHERE json_valid(envelope) AND (json_extract(envelope,'$.payload.type')='AAD_MIGRATION_PENDING' OR EXISTS (SELECT 1 FROM json_each(envelope,'$') GROUP BY \"key\" HAVING COUNT(*)>1) OR EXISTS (SELECT 1 FROM json_each(envelope,'$.payload') GROUP BY \"key\" HAVING COUNT(*)>1))");
    for (const row of this.store._schemaGuard(() => pendingScan.all())) {
      let env; try { env = JSON.parse(row.envelope); } catch { continue; }
      const pl = env?.payload, mid = pl?.metadata?.migration_id;
      if (pl?.type !== 'AAD_MIGRATION_PENDING' || typeof mid !== 'string') continue;
      let ok = false;
      try { ok = verifySigned(env, this.auditPublicKeys(row.tenant), 'audit').tenant_id === row.tenant; } catch { ok = false; }
      if (!ok) continue;
      const d = migPending.get(row.tenant) ?? { digests: [] };
      if (!d.digests.includes(mid) && d.digests.length < 8) d.digests.push(mid);
      (d.pendStats ??= new Map()).set(mid, { origin: pl.metadata?.origin ?? null, migrated: pl.metadata?.migrated ?? 0, transplants: pl.metadata?.transplants ?? 0, ambiguous: pl.metadata?.ambiguous ?? 0, skipped: pl.metadata?.skipped ?? 0 });
      migPending.set(row.tenant, d);
    }
    // Sanctioned post-attest marker cleanup: the aad_marker_keep guard is
    // dropped for the delete and recreated verbatim immediately — a
    // missing or respelled guard is INV-503 evidence on the next open
    // (w46-store M-2). The marker row is never deletable in-band on a
    // live deployment.
    const markerGuardSql = "CREATE TRIGGER aad_marker_keep BEFORE DELETE ON meta_kv WHEN OLD.key='aad_migration' BEGIN SELECT RAISE(ABORT, 'aad migration marker is evidence'); END";
    const markerGuardUpdSql = "CREATE TRIGGER aad_marker_keep_upd BEFORE UPDATE ON meta_kv WHEN OLD.key='aad_migration' BEGIN SELECT RAISE(ABORT, 'aad migration marker is evidence'); END";
    const markerGuardInsSql = "CREATE TRIGGER aad_marker_keep_ins BEFORE INSERT ON meta_kv WHEN NEW.key='aad_migration' BEGIN SELECT RAISE(ABORT, 'aad migration marker is evidence'); END";
    const dropAadMarker = (db, t) => {
      db.exec('DROP TRIGGER IF EXISTS aad_marker_keep');
      db.exec('DROP TRIGGER IF EXISTS aad_marker_keep_upd');
      db.exec('DROP TRIGGER IF EXISTS aad_marker_keep_ins');
      try { db.prepare("DELETE FROM meta_kv WHERE tenant=? AND key='aad_migration'").run(t); }
      catch (e) { if (/no such (table|column)|malformed|not a database/i.test(e?.message ?? '')) throw new InvariantError('INV-409-INTEGRITY', 'Ledger schema diverged — tamper evidence', 409, { cause: e }); throw e; }
      finally {
        db.exec(`CREATE TRIGGER IF NOT EXISTS ${markerGuardSql.slice('CREATE TRIGGER '.length)}`);
        db.exec(`CREATE TRIGGER IF NOT EXISTS ${markerGuardUpdSql.slice('CREATE TRIGGER '.length)}`);
        db.exec(`CREATE TRIGGER IF NOT EXISTS ${markerGuardInsSql.slice('CREATE TRIGGER '.length)}`);
      }
    };
    for (const t of new Set([...this.store.aadMigration.keys(), ...this.target.aadMigration.keys(), ...migPending.keys()])) {
      const marker = migPending.get(t);
      if (!Object.hasOwn(this.store.auditSigners, t)) {
        // A marker naming a tenant this deployment cannot sign for is
        // foreign residue: a planted row must neither wedge every open
        // (the unsignable-attest rollback, w44-ledger F1) nor sit as
        // silent permanent evidence the chain never saw (w44-store
        // HIGH-1). Attest its digests once under this fabric's own chain,
        // then drop it — deduped so replays cannot spam anchors.
        const attestor = Object.keys(this.store.auditSigners)[0];
        if (attestor) {
          const fresh = marker ? marker.digests.filter(d => !aadAttested(attestor, d)) : [];
          // A wedged chain must not kill construction here — a planted
          // marker plus a poisoned head would otherwise wedge every open
          // with sealAuditChain (the remediation) unreachable forever
          // (w45-seal F-1). Leave the marker, finish opening, let the
          // wedge surface through the index; a post-seal open re-attests.
          let anchored = fresh.length === 0;
          if (!anchored) try { this.store.tx(() => { this.store.audit(attestor, 'AAD_MIGRATION_MARKER', 'system', 'fabric-open', { claimed_tenant: t, reason: 'unconfigured-tenant', marker_digests: fresh }, this.clock()); }); anchored = true; }
          catch (e) { if (!String(e?.code ?? '').startsWith('INV-409')) throw e; /* wedged chain — marker survives, seal stays reachable; non-wedge faults (forged clock, ENOSPC, contention) still convict */ }
          // Dropped only once the residue has a VERIFIED anchor — digests
          // minted just now or already on chain. With no signer to attest
          // under, it stays for a later configured open rather than being
          // erased unnamed (w45-ledger HIGH-1/LOW-5).
          if (anchored) {
            try { dropAadMarker(this.store.db, t); } catch { /* cosmetic */ }
            try { dropAadMarker(this.target.db, t); } catch { /* cosmetic */ }
          }
        }
        continue;
      }
      const s = { migrated: 0, transplants: 0, ambiguous: 0, skipped: 0, reverted: 0 };
      for (const m of [this.store.aadMigration.get(t), this.target.aadMigration.get(t)]) if (m) for (const k of Object.keys(s)) s[k] += m[k] ?? 0;
      // A replayed marker must not mint a second anchor for the same
      // content — only digests the chain has not already attested are
      // fresh (w44-store M-1).
      const fresh = marker ? marker.digests.filter(d => !aadAttested(t, d)) : [];
      if (s.migrated + s.transplants + s.ambiguous + s.skipped > 0 || fresh.length) {
        const meta = fresh.length ? { ...s, recovered_marker: true, marker_digests: fresh, ...(marker.pendStats ? { pending_stats: fresh.map(d0 => marker.pendStats.get(d0)).filter(Boolean) } : {}) } : s;
        // Same wedge doctrine as the ghost path: on a convicted head the
        // tx rolls back, the marker survives, and the open continues into
        // the wedged index where sealAuditChain remediates (w45-seal F-1).
        try { this.store.tx(() => { this.store.clock(this.clock()); this.store.audit(t, 'AAD_MIGRATION', 'system', 'fabric-open', meta, this.clock()); dropAadMarker(this.store.db, t); }); }
        catch (e) { if (!String(e?.code ?? '').startsWith('INV-409')) throw e; /* wedged chain — marker survives, seal stays reachable */ }
      } else {
        dropAadMarker(this.store.db, t);
      }
    }
    // Target-side markers clear after the attestation lands: a crash in
    // the gap leaves a stale marker that re-attests at the next open —
    // never silently unattested (w43-store F-4).
    for (const t of migPending.keys()) { if (!Object.hasOwn(this.store.auditSigners, t)) continue; try { dropAadMarker(this.target.db, t); } catch { /* clears at next open */ } }
    // A dropped meta_kv self-heals EMPTY at open (the schema's CREATE IF
    // NOT EXISTS runs before this): pending markers and fold_floor are
    // destroyed and every read still succeeds — the only drop class that
    // would otherwise produce no named row. Non-empty audit under an
    // empty meta_kv is that drop's residue; attest it under this fabric's
    // own chain instead of absorbing it silently (w46-seal F-2).
    for (const src of [this.store, this.target]) {
      let tenants = [];
      try {
        if ((src._stmt('SELECT COUNT(*) n FROM meta_kv').get()?.n ?? 0) === 0)
          tenants = src._stmt('SELECT DISTINCT tenant FROM audit').all().map(r => r.tenant);
      } catch { /* a diverged schema convicts through the schema-guarded readers */ }
      for (const t of tenants) {
        if (!Object.hasOwn(this.store.auditSigners, t)) continue;
        try { this.store.tx(() => { this.store.audit(t, 'STORE_SCHEMA_RESIDUE', 'system', 'fabric-open', { reason: 'meta_kv-empty-under-nonempty-audit', detail: 'dropped meta_kv recreated empty — prior markers and fold_floor lost' }, this.clock()); }); }
        catch (e) { if (!String(e?.code ?? '').startsWith('INV-409')) throw e; /* wedged chain — residue waits for a healed open */ }
      }
    }
    // Stray triggers are dropped silently at open on both stores — name
    // every drop on the chain instead. A file-writer's planted trigger
    // payload must leave signed residue, not just vanish (w48-fixverify
    // MEDIUM; the drops happen inside the store constructors before the
    // fabric can sign, so the residue lands on the first configured
    // tenant here).
    {
      const residue = [['store.db', this.store._strayTriggers], ['target.db', this.target._strayTriggers]]
        .filter(([, names]) => names?.length);
      if (residue.length) {
        const attestor = Object.keys(this.store.auditSigners)[0];
        if (attestor) {
          const detail = residue.map(([db, names]) => `${db}: ${names.join(', ')}`).join('; ');
          try { this.store.tx(() => { this.store.audit(attestor, 'STORE_SCHEMA_RESIDUE', 'system', 'fabric-open', { reason: 'foreign-triggers-dropped', detail }, this.clock()); }); }
          catch (e) { if (!String(e?.code ?? '').startsWith('INV-409')) throw e; /* wedged chain — residue waits for a healed open */ }
        }
      }
    }
    this.runtime = new RuntimeGate(this);
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
      // Two live identities may never share a subject_id — identity()
      // resolves by subject alone, so a second enrollment would silently
      // rebind the effective device, grants and evidence expectations
      // (w31-runtime F-4). Re-enrollment must revoke the old row first.
      const seenSubjects = new Set();
      for (const idn of Object.values(t.identities ?? {})) {
        // Any present subject_id dedupes — a non-string id still resolves
        // through identity()'s string-keyed map, so skipping it would let
        // numeric duplicates rebind the same subject (w32-fixverify F-5).
        if (idn?.revoked === true || idn?.subject_id == null) continue;
        const sid = String(idn.subject_id);
        requireThat(!seenSubjects.has(sid), 'INV-503-CONFIG', `Tenant ${tenant} maps two live identities to subject ${sid}`, 503);
        seenSubjects.add(sid);
      }
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
      const anchoredInfo = this._anchoredConfigSnapshot(tenant);
      const anchored = anchoredInfo.digest;
      const expected = anchored ?? existing?.digest;
      if (anchored === null && (anchoredInfo.sawSnapshotRow || anchoredInfo.sawSeal)) {
        // A baseline that once anchored is gone (poisoned snapshot rows, or
        // a seal that cut them): auto-minting a fresh baseline would
        // launder whatever tamper removed it — flag drift with no expected
        // digest and leave re-anchoring to a governed CONFIG_REASSERTED
        // (w32-fixverify F-2).
        this._configDrift.add(tenant);
        try {
          this.store.tx(() => { this.store.put(tenant, 'config-flag', 'drift', { detected_at: this.clock(), expected: null, observed: configDigest, baseline_lost: true }, this.clock()); this.store.audit(tenant, 'CONFIG_DRIFT', 'system', 'config', { expected: null, observed: configDigest, changed_sections: ['unknown'], consequence: 'gate-privileges-withdrawn' }, this.clock()); });
        } catch (e) {
          if (e?.code !== 'INV-409-AUDIT-TAMPER') throw e;
          this.store.put(tenant, 'config-flag', 'drift', { detected_at: this.clock(), expected: null, observed: configDigest, baseline_lost: true }, this.clock());
        }
      } else if (expected !== undefined && expected !== configDigest) {
        const changed = existing?.sections ? Object.keys(sections).filter(k => existing.sections[k] !== sections[k]) : ['unknown'];
        this._configDrift.add(tenant);
        // The drift record needs a signature — a wedged (pre-seal) chain
        // cannot mint one, yet construction must still survive so the seal
        // stays reachable; the unsigned flag row keeps the gate armed
        // either way (w31-runtime F-2).
        try {
          this.store.tx(() => { this.store.put(tenant, 'config-flag', 'drift', { detected_at: this.clock(), expected, observed: configDigest }, this.clock()); this.store.audit(tenant, 'CONFIG_DRIFT', 'system', 'config', { expected, observed: configDigest, changed_sections: changed, consequence: 'gate-privileges-withdrawn' }, this.clock()); });
        } catch (e) {
          if (e?.code !== 'INV-409-AUDIT-TAMPER') throw e;
          this.store.put(tenant, 'config-flag', 'drift', { detected_at: this.clock(), expected, observed: configDigest }, this.clock());
        }
      } else {
        if (!existing) this.store.tx(() => { this.store.put(tenant, 'config-snapshot', 'current', { digest: configDigest, taken_at: this.clock(), sections }, this.clock()); });
        // Signing the snapshot needs a verifiable chain — on a poisoned
        // (pre-seal) ledger the fold wedges, and cold-boot must still
        // construct so sealAuditChain stays reachable (w31-runtime F-2).
        try {
          if (anchored === null) this.store.tx(() => { this.store.audit(tenant, 'CONFIG_SNAPSHOT', 'system', 'config', { config_digest: configDigest }, this.clock()); });
        } catch (e) { if (e?.code !== 'INV-409-AUDIT-TAMPER') throw e; /* wedged chain: the snapshot re-lands post-seal */ }
      }
    } } catch (error) { this.close(); throw error; }
    // Rebuild the clock-recovery wedge set from the chains themselves: the
    // in-memory flag is only a cache, so a restart must not forget a tenant
    // an anchored CLOCK_RECOVERED named unverifiable (w25-clock F-5). A
    // tenant whose chain still cannot fold needs no flag — every call to
    // _auditIndex already refuses it with the fold's own error.
    for (const tn of Object.keys(this.#tenants)) {
      try { if (this._auditIndex(tn).clockUnverifiable === true) (this._clockRecoveryUnverifiable ??= new Set()).add(tn); }
      catch { /* fold failure is already terminal for that tenant */ }
    }
    // Freeze tenant configuration last (post-reconcile): a mid-session edit
    // of identities/issuers/keys must trip drift detection like a file-level
    // change, and immutability is the only honest in-process answer
    // (w11-redteam R12).
    for (const t of Object.keys(this.#tenants)) this.#setTenant(t, this.#tenants[t]);
    // Bootstrap appends are committed through store.tx, which never passes
    // the transaction() flush edge — leave the head watermarks landed now or
    // every subsequent open would read committed rows with no signed head
    // (w25-clock F-4).
    this._flushChainHeads();
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
    // The scan enforces the same dead-key window as the fold — a row
    // signed after its key's anchored death is not anchored evidence
    // (w21-crypto F-3).
    const keyDeadAt = new Map();
    const dead = e => {
      const pl = e?.payload, meta = pl?.metadata ?? {};
      // The EARLIEST anchored death wins — a later event naming the same
      // key must never move its death forward and reopen the window
      // (w22-fixverify F12).
      if (pl?.type === 'AUTHORITY_REVOKED' && typeof pl.reference === 'string' && pl.reference.startsWith('key:')) keyDeadAt.set(pl.reference.slice(4), Math.min(keyDeadAt.get(pl.reference.slice(4)) ?? Infinity, pl.sequence));
      if (pl?.type === 'KEY_ROTATED' && meta.key_class === 'audit' && meta.previous_key_id) keyDeadAt.set(meta.previous_key_id, Math.min(keyDeadAt.get(meta.previous_key_id) ?? Infinity, pl.sequence));
      const kid = e?.protected?.key_id, deadAt = kid !== undefined ? keyDeadAt.get(kid) : undefined;
      return deadAt !== undefined && deadAt < pl?.sequence;
    };
    try {
      for (;;) {
        const page = this.store.auditPage(t, { after, limit: 5000 });
        for (const row of page.entries) {
          const e = row.envelope;
          if (dead(e)) continue;
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
  // Returns {digest, sawSnapshotRow, sawSeal}: digest is the last verified
  // baseline; sawSnapshotRow marks that snapshot-typed payloads exist in the
  // chain but none verified (poisoned baseline = tamper, never "no baseline
  // yet"); sawSeal marks an AUDIT_SEALED anchor — a sealed-away baseline
  // must be re-asserted through governance, not silently re-minted
  // (w32-fixverify F-2).
  _anchoredConfigSnapshot(t) {
    let latest = null, after = 0, sawSnapshotRow = false, sawSeal = false;
    // Same dead-key window as the fold — a snapshot minted after its
    // signing key's anchored death cannot seed the drift baseline
    // (w21-crypto F-3).
    const keyDeadAt = new Map();
    try {
      for (;;) {
        const page = this.store.auditPage(t, { after, limit: 5000 });
        for (const row of page.entries) {
          const e = row.envelope, pl = e?.payload, meta = pl?.metadata ?? {};
          // Earliest anchored death wins (w22-fixverify F12).
          if (pl?.type === 'AUTHORITY_REVOKED' && typeof pl.reference === 'string' && pl.reference.startsWith('key:')) keyDeadAt.set(pl.reference.slice(4), Math.min(keyDeadAt.get(pl.reference.slice(4)) ?? Infinity, pl.sequence));
          if (pl?.type === 'KEY_ROTATED' && meta.key_class === 'audit' && meta.previous_key_id) keyDeadAt.set(meta.previous_key_id, Math.min(keyDeadAt.get(meta.previous_key_id) ?? Infinity, pl.sequence));
          if (pl?.type === 'AUDIT_SEALED') sawSeal = true;
          if (pl?.type === 'CONFIG_SNAPSHOT' || pl?.type === 'CONFIG_REASSERTED') {
            sawSnapshotRow = true;
            const kid = e?.protected?.key_id, deadAt = kid !== undefined ? keyDeadAt.get(kid) : undefined;
            try {
              verifySigned(e, this.auditPublicKeys(t), 'audit');
              if (!(deadAt !== undefined && deadAt < pl.sequence) && pl.metadata?.config_digest) latest = pl.metadata.config_digest;
            } catch { /* forged row: ignore */ }
          }
        }
        if (page.next_cursor === null) break;
        after = page.next_cursor;
      }
    } catch { /* poisoned chain: no baseline — drift gates stay up */ }
    return { digest: latest, sawSnapshotRow, sawSeal };
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
          // A null baseline is a free baseline ONLY when the chain never
          // held one — a poisoned or sealed-away baseline must not be
          // re-minted under the repoint (w32-fixverify F-2).
          if ((anchoredBaseline.digest === null && !anchoredBaseline.sawSnapshotRow && !anchoredBaseline.sawSeal) || digest({ tenant, sections: preSections }) === anchoredBaseline.digest) {
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
      // Paginate the whole table — a fixed cap would let planted garbage
      // rows starve legitimate grant replay out of the heal pass
      // (w28-store F10).
      for (let off = 0;; off += 1000) {
        const page = this.store.ids(tenant, 'jit-grant', 1000, off);
        if (!page.length) break;
        for (const id of page) {
          let jg; try { jg = this.store.must(tenant, 'jit-grant', id); } catch { continue; }
          // Forged grant rows replay into the dataplane — only rows the chain
          // anchors (new scope_digest, or the legacy grant_digest scheme with
          // every row field proven against the issuing request) may replay
          // (w13-fixverify L10, w16-fixverify F4/F7).
          if (jg.grant?.grant_id && !grants.some(g => g.grant_id === jg.grant.grant_id) && idx && this._grantAnchored(tenant, idx, jg.grant.grant_id, jg.grant)) this.target.grant(tenant, jg.grant.grant_id, jg.grant);
        }
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
    if (existsSync(storePath)) {
      // Ownership drift on the vault files is reverted at open — the
      // custody sweep writes never hardened an existing deployment whose
      // files predated the chmod-on-write rule (w43-store F-5). A failed
      // tighten is custody failure inside the INV-503 taxonomy, never a
      // silently weakened vault (w46-store L-2): the keystore that cannot
      // be made owner-only is refused rather than trusted wider than the
      // custody rule allows.
      try { chmodSync(storePath, 0o600); } catch (e) { throw new InvariantError('INV-503-STORAGE', 'keystore.json cannot be made owner-only', 503, { cause: e }); }
      try { chmodSync(masterPath, 0o600); } catch (e) { throw new InvariantError('INV-503-STORAGE', 'master.key cannot be made owner-only', 503, { cause: e }); }
      // The commit marker is file-writer shaped too — a corrupt or
      // shapeless master.key classifies as config corruption, never a raw
      // SyntaxError/TypeError off the boot path (w28-crypto F4).
      let master = null;
      try { master = JSON.parse(readFileSync(masterPath, 'utf8'))?.master_key; } catch (e) { throw new InvariantError('INV-503-CONFIG', 'master.key is unparseable — vault commit marker corrupt', 503, { cause: e }); }
      requireThat(typeof master === 'string' && master.length > 0, 'INV-503-CONFIG', 'master.key carries no string master_key', 503);
      return KeyVault.load(storePath, master);
    }
    return new KeyVault(randomBytes(32).toString('base64url'));
  }
  _committedTenants() {
    try { return this.store._stmt('SELECT DISTINCT tenant FROM audit ORDER BY tenant').all().map(r => r.tenant); }
    catch { return Object.keys(this.#tenants); }
  }
  _chainHeadNote(tenant, seq, hash) {
    // A head minted inside the seal's transaction is the ONE sanctioned
    // backward move: the monotone gate would otherwise drop the seal's
    // re-anchor envelope and the file would wedge the cut it was made to
    // repair (w27-chainheads F0).
    (this.#pendingChainHeads ??= new Map()).set(tenant, { seq, hash, reanchor: this.#sealing?.has(tenant) === true });
    // Appends committed outside a fabric transaction (denial audits, drift
    // flags, seal sweeps) flush immediately — inside a tx the watermark must
    // not outlive a rollback, so it waits for the commit edge.
    // A committed bare append's flush can lose the lock race — the pending
    // heads are re-buffered by restore() and retried on the next edge; the
    // committed write is never reported back as an error (w28-store F5).
    if (!this.store.db.isTransaction) this._flushChainHeadsGuarded();
  }
  // Flush failures are swallowed at every commit edge by design (a
  // committed write is never reported back as an error) — but a
  // permanently-starved flush is tamper evidence, not contention: a
  // lock file pinned in the future freezes the durable anchors while
  // commits keep landing and the unwitnessed window grows without bound
  // (w48-store W48-1). Count consecutive losses and name them on the
  // chain at the next transaction boundary — a file-side marker can be
  // deleted, a signed ledger row cannot.
  _flushChainHeadsGuarded() {
    try { this._flushChainHeads(); this.#headFlushStarved = null; }
    catch (e) {
      const s = this.#headFlushStarved ??= { count: 0, tenants: new Set(), code: e?.code ?? 'ERR' };
      s.count++;
      s.code = e?.code ?? s.code;
      for (const t of this.#pendingChainHeads?.keys() ?? []) s.tenants.add(t);
    }
  }
  // Single mkdir-dir lock covering BOTH chain-heads files. The owner token
  // keeps a stale-expired holder that resumes from deleting the NEW
  // holder's lock (w27-chainheads F4); the self-check keeps it from
  // clobbering the file with a stale snapshot.
  _headFileLock(fn) {
    const lockPath = join(this.directory, 'chain-heads.json.lock');
    const deadline = Date.now() + 4_000;
    const token = `${process.pid}:${randomBytes(8).toString('hex')}`;
    for (let attempt = 0;; attempt++) {
      try { mkdirSync(lockPath); writeFileSync(join(lockPath, 'owner'), token); break; }
      catch (err) {
        if (err?.code !== 'EEXIST') throw err;
        // An expired stale lock dir is cleared and retried; a live-held
        // lock past the deadline reports the honest gate code — never a
        // raw EEXIST off the commit edge (w27-fixverify W27-10).
        // A lock dir pinned in the FUTURE is stale too — a write-capable
        // attacker can otherwise mint an immortal lock that starves every
        // flush while commits keep landing (w48-store W48-1).
        try { if (Math.abs(Date.now() - statSync(lockPath).mtimeMs) > 8_000) rmSync(lockPath, { recursive: true, force: true }); } catch { /* lost the race to clear it */ }
        if (Date.now() > deadline) throw new InvariantError('INV-503-GATE', 'Chain-head file lock held by a live peer beyond the deadline', 503);
        const spin = Date.now() + Math.min(2 * (attempt + 1), 20);
        while (Date.now() < spin) { /* bounded backoff; the locked section is microseconds */ }
      }
    }
    const lockAt = Date.now();
    try { return fn(() => Date.now() - lockAt > 8_000); }
    finally {
      try { if (readFileSync(join(lockPath, 'owner'), 'utf8') === token) rmSync(lockPath, { recursive: true, force: true }); } catch { /* a peer cleared or took the lock */ }
    }
  }
  _flushChainHeads() {
    if (!this.#pendingChainHeads?.size) return;
    const pending = this.#pendingChainHeads; this.#pendingChainHeads = new Map();
    // A rolled-back append can never move the watermark: the buffered seq
    // pointing past the committed tail — or onto a DIFFERENT row that
    // reused its slot — is a phantom, not a head (w24-fixverify). The
    // ledger check runs BEFORE the file lock so the critical section
    // never waits on sqlite's busy_timeout while holding it
    // (w25-concurrency: a second fabric's locked section blocking on the
    // database serialised every writer into multi-second stalls).
    const landed = new Map();
    const landedStmt = (this._flushLandedStmt ??= this.store._stmt('SELECT hash FROM audit WHERE tenant=? AND seq=?'));
    for (const [tenant, h] of pending) {
      const row = landedStmt.get(tenant, h.seq);
      if (!row || row.hash !== h.hash) continue;
      // A reanchor head is sanctioned only while it is still the tenant's
      // committed TIP — a delayed seal head must never overwrite a peer's
      // legitimately higher watermark that landed in between
      // (w28-fixverify F3). Degraded to monotone, a stale reanchor can
      // only lose — drop it like a rolled-back phantom.
      if (h.reanchor) {
        const tip = (this._flushTipStmt ??= this.store._stmt('SELECT seq,hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1')).get(tenant);
        if (!(tip && tip.seq === h.seq && tip.hash === h.hash)) continue;
      }
      landed.set(tenant, h);
    }
    if (!landed.size) return;
    // Signing consults the audit index (rotation steering) — sqlite again —
    // so envelopes are produced BEFORE the lock as well; a peer that lands
    // a later head first simply wins the monotone compare below and our
    // pre-signed envelope is discarded harmlessly. One tenant's signing
    // fault drops only its own pending head — never the whole batch
    // (w28-store F4). The verifier key sets are resolved pre-lock too: the
    // vault scan (decrypt+derivePublic per key) must not run inside the
    // shared critical section (w28-fixverify F8).
    const restore = () => { for (const [t, h] of landed) if (!this.#pendingChainHeads.has(t)) this.#pendingChainHeads.set(t, h); };
    const signed = [];
    try {
      for (const [tenant, h] of landed) {
        try {
          // The signer-death window is resolved pre-lock too — and from
          // the raw row scan, never the index fold: the fold legitimately
          // wedges on the corrupt/missing head this flush exists to heal,
          // so consulting it here would deadlock the recovery (w28-crypto
          // F3, w28-regression w25/w27).
          const deadAt = this._keyDeaths(tenant);
          // The head this flush heals may already be perceived 'corrupt'
          // by an outside-tx fold — its cached verdict must not wedge the
          // signature that repairs it: resolve the signing path under the
          // seal scope, where the fold skips the corrupt-head require
          // (w29-fixverify F10).
          const alreadySealed = this.#sealing?.has(tenant) === true;
          if (!alreadySealed) (this.#sealing ??= new Set()).add(tenant);
          try {
            // The signed head also binds the tenants that had committed
            // audit rows at mint time — a per-tenant wipe that strips the
            // victim's file entry and every row is exposed by a surviving
            // peer envelope attesting the tenant existed (w31-fixverify F1).
            // And it attests the residue present at mint — the newest
            // export checkpoint, the checkpoint-row COUNT and the
            // revocation floor count — so a rewind that deletes those
            // rows to bury their anchors convicts at the next fold
            // (w33-export F1/F6). This convicts only a deletion under a
            // SURVIVING head: replaying a genuine older head plus a
            // consistent cleanup folds clean on cold boot — that bound
            // is external-witnessing, documented in SECURITY.md
            // (w34-fixverify H-1).
            // The claims the head signs must themselves be attestable:
            // a planted 'audit-checkpoint' records row signed into the
            // head would wedge every later fold on the impossible claim,
            // and deleting the plant cannot heal what the signature
            // already attested (w38-store F-1). Count only checkpoints
            // that verify under the tenant's audit keys, and bind the
            // revocation claim to the VERIFIED floor: rows whose id
            // carries an anchored revocation claim. A planted records
            // row is uncounted; an anchorless-carried ref is not a
            // floor row and must not inflate the claim — else the
            // re-anchor path deadlocks on its own fresh head
            // (w37 M-1 / w38-store F-1).
            let checkpoint = 0, checkpoints = 0;
            const cpKeys = this._verifyKeysCached(tenant, 'audit');
            // Verify each distinct checkpoint row once per verifier-key
            // fingerprint — the flush runs on every commit edge, so the
            // ECDSA cost is paid per row digest, not per append (w38 CI:
            // the sweep halved evaluate() headroom on shared runners).
            const cpFp = Object.keys(cpKeys).sort().map(k => `${k}:${cpKeys[k].public_key}`).join('|');
            let cpCache = this.#cpHeadVerify.get(tenant);
            if (cpCache?.fp !== cpFp) { cpCache = { fp: cpFp, sizes: new Map() }; this.#cpHeadVerify.set(tenant, cpCache); }
            for (const stored of (this._cpSweepStmt ??= this.store._stmt("SELECT id, value FROM records WHERE tenant=? AND kind='audit-checkpoint' ORDER BY created, id LIMIT 1000000")).all(tenant)) {
              const id = stored.id;
              // An unreadable or undecryptable stored row is planted
              // residue — the claim counts only what VERIFIES, and a
              // get() throw must not strand the pending head (w38 CI).
              // The cached verdict keys on the row's raw ciphertext: an
              // attacker rewrite that preserves the id lands on different
              // bytes and re-decrypts (w43-perf).
              let entry = cpCache.sizes.get(id);
              if (entry?.value !== stored.value) entry = undefined;
              if (entry === undefined) {
                entry = { value: stored.value, size: null };
                let row;
                try { row = this.store.get(tenant, 'audit-checkpoint', id); } catch { continue; }
                try {
                  const pl = verifySigned(row, cpKeys, 'checkpoint');
                  entry.size = pl.tenant_id === tenant && Number.isSafeInteger(pl.size) ? pl.size : null;
                } catch { /* planted or undecryptable — not attestable residue */ }
                if (cpCache.sizes.size < 4_096) cpCache.sizes.set(id, entry);
              }
              const size = entry.size;
              if (size === null) continue;
              checkpoints++;
              checkpoint = Math.max(checkpoint, size);
            }
            const ridxMint = this._auditIndex(tenant);
            let revocations = 0;
            for (const row of (this._revScanStmt ??= this.store._stmt("SELECT id FROM records WHERE tenant=? AND kind='revocation'")).all(tenant))
              if (ridxMint.revoked.has(row.id)) revocations++;
            // The head attests the durable watermark floor it saw at mint:
            // a later strip of the watermark file is then distinguishable
            // from first contact — the floor's EXISTENCE is anchored in a
            // signed record, not in the deletable file (w40-fv F-1). The
            // durable entry resolves through the same verifier the fold
            // uses, so an unverifiable stored entry claims its honest cap.
            const wmRaw = this._readHeadWatermark();
            const wmEntry = wmRaw && typeof wmRaw === 'object' ? wmRaw[tenant] : undefined;
            // Never attest a floor above this head's own seq: a seal cut is
            // the one sanctioned regression, and its re-anchor settles the
            // durable floor at the cut point — a head attesting the pre-cut
            // floor would wedge the fold it just minted (w40-fv F-1 rework).
            // An oversized (planted-bloat) watermark file reads as no entry,
            // so it attests this head's own seq — a weaker claim would let a
            // later strip hide behind the understated floor (w41-fv F-9).
            const floorSeq = wmEntry === undefined ? (wmRaw === 'oversized' ? h.seq : 0) : Math.min(this.#watermarkSeq(tenant, wmEntry), h.seq);
            signed.push([tenant, h, this.#auditSigners[tenant].sign({ tenant_id: tenant, seq: h.seq, hash: h.hash, tenants: this._committedTenants(), checkpoint, checkpoints, revocations, floor_seq: floorSeq }, 'audit'), this._verifyKeysCached(tenant, 'audit'), deadAt]);
          } finally { if (!alreadySealed) this.#sealing.delete(tenant); }
        }
        catch { if (!this.#pendingChainHeads.has(tenant)) this.#pendingChainHeads.set(tenant, h); }
      }
    } catch (err) { restore(); throw err; }
    const path = join(this.directory, 'chain-heads.json');
    // Two fabric instances over one directory race on the read-merge-write
    // window: each sees the same pre-image and the later writer drops the
    // earlier's tenant heads — a file that regresses under authentic
    // signatures reads as replay on the next fold (w25-concurrency). The
    // lock dir is atomic create-or-fail; a crashed holder's stale dir
    // expires so the file can never wedge forever.
    try {
      this._headFileLock(staleHold => {
        // Held the lock too long — it may already have been expired and
        // retaken, so this snapshot could clobber a peer's fresh write.
        // Abort and let the next flush land the pending heads (w27 F4).
        if (staleHold()) { restore(); return; }
        const headFile = this._readChainHeadFile();
        // Planted bloat or a corrupt read starts the merge from an empty
        // honest file — planted envelopes are dropped, never carried
        // (w28-crypto F10).
        const file = typeof headFile === 'object' && headFile !== null ? headFile : { format: 'IF-CHAINHEAD-1', tenants: {} };
        // A JSON-valid wrong-shape tenants field is planted state, not a
        // read — normalize in the writer and refuse it in the reader
        // (w27-chainheads F5).
        if (!file.tenants || typeof file.tenants !== 'object' || Array.isArray(file.tenants)) file.tenants = {};
        const wmWinners = new Map();
        for (const [tenant, h, env, pubs, deadAt] of signed) {
          // Monotone per tenant — but on the VERIFIED payload only. An
          // existing entry whose signature fails is planted state: it may
          // claim a far-future seq and monotone-wedge every honest head
          // forever, so it is overwritten, never compared (w27 F1). A
          // same-seq head with a DIFFERENT hash must be replaced — the
          // seal is the one writer that legitimately signs a new tip at a
          // reused seq — and a pending head minted inside the seal's
          // transaction may move backward (w27 F0).
          const existing = file.tenants[tenant];
          if (existing) {
            // Verify an unchanged stored envelope once: the serialized
            // bytes plus the verifier-key fingerprint pin the result, so a
            // flush that re-reads its own last write pays no ECDSA cost.
            // A tampered envelope changes the serialization (re-verify),
            // a key rotation changes the fingerprint (re-verify).
            const serialized = JSON.stringify(existing);
            const fp = Object.keys(pubs).sort().map(k => `${k}:${pubs[k].public_key}`).join('|');
            const vc = this._headEnvVerifyCache.get(tenant);
            let existingPl = vc?.serialized === serialized && vc?.fp === fp ? vc.pl : null;
            if (!(vc?.serialized === serialized && vc?.fp === fp)) {
              try { existingPl = verifySigned(existing, pubs, 'audit'); } catch { /* forged — falls through to overwrite */ }
              this._headEnvVerifyCache.set(tenant, { serialized, fp, pl: existingPl });
            }
            // A verifiable-but-dead-signed head is replay, not authority:
            // an envelope attesting a seq past its signer's ledger death
            // loses the compare and is overwritten (w28-crypto F3).
            const deadSeq = deadAt.get(existing?.protected?.key_id);
            const deadSigned = deadSeq !== undefined && existingPl?.seq > deadSeq;
            if (existingPl && !deadSigned && existingPl.tenant_id === tenant && Number.isSafeInteger(existingPl.seq)
              && (existingPl.seq > h.seq || (existingPl.seq === h.seq && existingPl.hash === h.hash))
              && !h.reanchor) { wmWinners.set(tenant, { seq: existingPl.seq, envelope: existing }); continue; }
          }
          file.tenants[tenant] = env;
          wmWinners.set(tenant, { seq: h.seq, envelope: env });
        }
        // Re-verify the hold immediately before committing the file: a
        // holder that stalled past the stale window may already have been
        // cleared and replaced — writing now would clobber the peer's
        // fresh merge with our stale pre-image (w28-store F3,
        // w28-fixverify F2).
        if (staleHold()) { restore(); return; }
        mkdirSync(this.directory, { recursive: true, mode: 0o700 });
        // The signed head is a peer-facing hint, so fsync is cadenced
        // (every 16th write) instead of paid on every audit append. A
        // crashed-away rewrite does NOT degrade to the previous head —
        // the rename already unlinked it: the torn file reads 'corrupt'
        // and wedges INV-409 until sealAuditChain re-anchors (loud and
        // recoverable, never silently stale). The durable floor is
        // head-watermark.json, which keeps per-write fsync (w43-perf;
        // w43-seal F-4 stays intact; overclaim corrected w44-store L-2).
        const fsyncHead = (this.#headFsyncTicks = (this.#headFsyncTicks ?? 0) + 1) % 16 === 0;
        this.#writeFileSynced(`${path}.tmp`, canonical(file) + '\n', fsyncHead);
        renameSync(`${path}.tmp`, path);
        if (fsyncHead) this.#fsyncDir();
        // Our own write changed the bytes after the cached read — drop the
        // snapshot so the next _chainHead re-reads what we just landed.
        this.#chainHeadRaw = undefined;
        // The watermark rides the same critical section: its durable floor
        // is exactly the verified head this flush just landed, so the same
        // envelope doubles as the watermark's signature — no second signing
        // pass and no second lock acquisition on the commit edge (w38 CI:
        // the standalone bump's sign+lock+write on every fold regressed
        // NFR-PERF-004). Non-flush bump callers still self-sign headmark
        // envelopes.
        try {
          const rawWm = this._readHeadWatermark();
          // Clone + sanitize: the shared cached parse must not be mutated
          // before the write lands, and planted canonical-illegal entries
          // must not freeze every flush (w40-fv F-4/F-9).
          let droppedPlanted = [];
          const wmFile = this.#sanitizeWmTenants(rawWm && typeof rawWm === 'object' ? { ...rawWm } : {}, d => { droppedPlanted = d; });
          let wmChanged = false;
          for (const [tenant, win] of wmWinners) {
            const cur = wmFile[tenant];
            // A higher VERIFIED entry survives: overwriting it would
            // launder the two-file rollback it exists to convict (heads
            // replayed low, watermark left high → wedge on the next fold).
            // The compare runs on the resolved floor — a forged entry
            // claiming a huge seq is no floor and is replaced, never
            // preserved to suppress every future winner (w39-seal F-1).
            if (cur !== undefined && this.#watermarkSeq(tenant, cur) > win.seq) continue;
            wmFile[tenant] = { seq: win.seq, envelope: win.envelope };
            this.#headWm.set(tenant, win.seq);
            // The landed entry is verified-clean — the flag it replaces
            // must not report as still-live tamper (w40-fv F-5). Any
            // planted entries dropped from the file are named next, so
            // the drop survives to the next seal report.
            this.#wmTamper.delete(tenant);
            // A dropped planted entry is attributed to the tenant key it
            // occupied — the drop count is file metadata, not a seq
            // (w41-fv F-8).
            for (const dt of droppedPlanted) this.#wmTamper.set(dt, { kind: 'planted_content' });
            wmChanged = true;
          }
          // The durable floor tracks the committed tip on every flush — a
          // regressed, forged or stale entry is replaced the moment a
          // winner lands, with file+dir fsync every write (w43-seal F-4).
          if (wmChanged) {
            const wpath = join(this.directory, 'head-watermark.json');
            this.#writeFileSynced(`${wpath}.tmp`, canonical({ format: 'IF-HEADMARK-1', tenants: wmFile }) + '\n');
            renameSync(`${wpath}.tmp`, wpath);
            this.#fsyncDir();
            this.#headWmRaw = undefined;
            this.#headWmStatKey = undefined;
          }
        } catch (err) {
          // A held lock degrades honestly to the fold's own bump path —
          // but a WRITE failure (planted .tmp dir, fs error) freezes the
          // durable floor while heads keep advancing: name the loss so
          // the seal reports it instead of the file pretending a floor
          // exists (w41-fv F-6).
          if (err?.code !== 'INV-503-GATE') for (const tenant of wmWinners.keys()) this.#wmTamper.set(tenant, { kind: 'write_failed' });
        }
      });
    } catch (err) { restore(); throw err; }
  }
  _readChainHeadFile() {
    let raw = null;
    try {
      const p = join(this.directory, 'chain-heads.json');
      // Planted bloat is untrusted input: an oversized heads file is
      // tamper evidence, never a document to parse into memory
      // (w28-crypto F10). The reader treats it as corruption; the writer
      // drops its contents rather than merging planted state.
      if (statSync(p).size > 262_144) { this.#chainHeadRaw = 'oversized'; this.#chainHeadParsed = 'oversized'; this.#chainHeadVerdicts.clear(); return 'oversized'; }
      raw = readFileSync(p, 'utf8');
    } catch { /* absent or unreadable */ }
    if (raw !== this.#chainHeadRaw) {
      this.#chainHeadRaw = raw;
      try { this.#chainHeadParsed = raw === null ? null : JSON.parse(raw); } catch { this.#chainHeadParsed = null; }
      this.#chainHeadVerdicts.clear();
    }
    return this.#chainHeadParsed;
  }
  // The verified head for a tenant: the envelope re-verifies against the
  // tenant's audit keys on every call — the file is untrusted input, so a
  // post-boot rewrite (truncated head, forged signature, malformed claim)
  // is tamper evidence on the next fold, never a cached pass ('corrupt'),
  // and a deleted file simply loses the watermark it cannot re-forge.
  // Every call still re-reads the file bytes; verdicts cache only against
  // the exact raw content, which can never skip verification of new bytes.
  _chainHead(tenant) {
    const file = this._readChainHeadFile();
    if (this.#chainHeadVerdicts.has(tenant)) return this.#chainHeadVerdicts.get(tenant);
    // Planted bloat reads as the same tamper evidence a malformed file
    // does — never as an absent watermark (w28-crypto F10).
    const env = file === 'oversized' ? undefined : file?.tenants?.[tenant];
    let verdict;
    if (file === 'oversized') verdict = 'corrupt';
    else
    // A committed ledger row implies a head was signed for it — the flush
    // runs on the commit edge of every append. Committed rows without a
    // head file therefore mean the file was deleted (or this store predates
    // the watermark): fail closed and let sealAuditChain re-anchor the
    // verified tip (w25-fixverify W25-01, w25-clock F-4). Inside a
    // transaction the same query sees uncommitted rows, where absence is
    // the legitimate pre-flush state — the watermark only binds committed
    // history anyway.
    if (!env) verdict = this.store.db.isTransaction || this.store._stmt('SELECT COALESCE(MAX(seq),0) m FROM audit WHERE tenant=?').get(tenant).m === 0 ? undefined : 'corrupt';
    else {
      let pl = null;
      try { pl = verifySigned(env, this.auditPublicKeys(tenant), 'audit'); } catch { /* falls to corrupt */ }
      // A non-object tenants map is planted state — the reader fails
      // closed exactly like a forged envelope (w27-chainheads F5).
      if (!file.tenants || typeof file.tenants !== 'object' || Array.isArray(file.tenants)) verdict = 'corrupt';
      else verdict = (!pl || pl.tenant_id !== tenant || !Number.isSafeInteger(pl.seq) || typeof pl.hash !== 'string') ? 'corrupt' : { seq: pl.seq, hash: pl.hash, checkpoint: Number.isSafeInteger(pl.checkpoint) ? pl.checkpoint : undefined, checkpoints: Number.isSafeInteger(pl.checkpoints) ? pl.checkpoints : undefined, revocations: Number.isSafeInteger(pl.revocations) ? pl.revocations : undefined, floor_seq: Number.isSafeInteger(pl.floor_seq) ? pl.floor_seq : undefined };
    }
    this.#chainHeadVerdicts.set(tenant, verdict);
    return verdict;
  }
  // Durable "highest consumed head" per tenant (w27-chainheads F2,
  // w27-fixverify W27-02): the in-memory seenHeadSeq dies with the
  // process, so a directory-level rollback (audit rows + chain-heads.json
  // restored together) verifies clean on a cold open. The watermark file
  // raises the attack to a consistent rollback of THREE files — partial
  // replays wedge. Bootstraps at the current head on first contact so
  // pre-w27 deployments migrate silently; a consistent whole-directory
  // restore is the documented residual (SECURITY.md).
  _readHeadWatermark() {
    // Re-read every call — the durable floor is cross-process state, so a
    // peer's advance must be visible on the next check, not just at cache
    // install (w28-fixverify F4). Parsed values memoize on the raw bytes.
    // Planted bloat is the same tamper class the head file convicts: an
    // oversized watermark file is evidence, never a document to parse
    // (w40-fv F-6 — parity with chain-heads' 256KB gate).
    let raw = null;
    try {
      const p = join(this.directory, 'head-watermark.json');
      // Stat-gate: re-read only when the inode/mtime/size changed — an
      // atomic rename lands on a different inode, an in-place rewrite on a
      // new mtime, so a cached parse can never serve a peer's advance
      // (w45-perf). The stat itself still runs every call.
      const st = statSync(p);
      if (st.size > 262_144) return 'oversized';
      const statKey = `${st.dev}:${st.ino}:${st.mtimeMs}:${st.size}`;
      if (statKey === this.#headWmStatKey) return this.#headWmParsed;
      raw = readFileSync(p, 'utf8');
      this.#headWmStatKey = statKey;
    } catch { /* absent or unreadable */ }
    if (raw === this.#headWmRaw) return this.#headWmParsed;
    this.#headWmRaw = raw;
    try { const f = raw === null ? null : JSON.parse(raw); this.#headWmParsed = f?.tenants && typeof f.tenants === 'object' && !Array.isArray(f.tenants) ? f.tenants : null; } catch { this.#headWmParsed = null; }
    return this.#headWmParsed;
  }
  // A parsed tenants map is untrusted input twice over: entries whose keys
  // or values canonical() cannot emit are planted junk — reserializing them
  // throws and freezes every bump for every tenant, silently (w40-fv F-4).
  // The writer keeps only canonicalizable tenant-shaped entries; any drop
  // is attested on the seal path as planted content.
  #sanitizeWmTenants(map, onDrop) {
    const clean = {};
    const dropped = [];
    for (const [k, v] of Object.entries(map ?? {})) {
      // One slot short of the canonical cap so the writer's own entry
      // always fits — a full map would canonical-throw the write itself.
      if (Object.keys(clean).length >= 255) { dropped.push(k); continue; }
      try { canonical({ [k]: v }); clean[k] = v; } catch { dropped.push(k); }
    }
    if (dropped.length) onDrop?.(dropped);
    return clean;
  }
  // The honest coverage denominator (w40-fv F-7): only rows whose
  // ciphertext decrypts under the row AAD are dataset content — planted
  // ciphertext junk must never deflate coverage toward zero. Memoized on
  // a content fingerprint so the O(dataset) decrypt rescan runs only when
  // the table actually moved.
  _verifiedDatasetRows(tenant, dataset) {
    const memoKey = `${tenant}:${dataset}`;
    // The memo fingerprint binds CONTENT, not row count — a delete+insert
    // or an in-place ciphertext rewrite preserves COUNT(*) but must still
    // invalidate the verified tally (w41-fv F-5).
    const fp = createHmac('sha256', 'dataset-rows');
    for (const r of this.target._stmt('SELECT row_id, data FROM dataset_rows WHERE tenant=? AND dataset=? ORDER BY row_id').all(tenant, dataset)) {
      fp.update(r.row_id); fp.update('\x00'); fp.update(r.data); fp.update('\x00');
    }
    const raw = fp.digest('hex');
    const cached = this.#verifiedRows.get(memoKey);
    if (cached?.raw === raw) return cached.verified;
    const dek = this.target.key(tenant);
    let verified = 0;
    for (const r of this.target._stmt('SELECT row_id, data FROM dataset_rows WHERE tenant=? AND dataset=?').all(tenant, dataset))
      try { decrypt(r.data, dek, canonical(['target', 'dataset', tenant, dataset, r.row_id])); verified++; } catch { /* planted ciphertext */ }
    this.#verifiedRows.set(memoKey, { raw, verified });
    return verified;
  }
  // Returns true when the durable file now carries seq for the tenant.
  _bumpHeadWatermark(tenant, seq, { force = false, reanchor = false } = {}) {
    // A downward move is sanctioned only inside the seal scope — anywhere
    // else a lower seq degrades to the ordinary monotone path
    // (w28-fixverify F1: the seal is the one legal head regression, and the
    // durable floor must move with it or every fold wedges afterward).
    const mayReanchor = reanchor && this.#sealing?.has(tenant) === true;
    // A stripped state never rewrites outside a seal re-anchor: minting a
    // signed entry over it would launder the evidence the bootstrap just
    // named (w40-fv F-1).
    if (!mayReanchor && this.#wmTamper.get(tenant)?.kind === 'floor_stripped') return false;
    // Fast path: a bump that does not advance past the last-known durable
    // value is a no-op — _auditIndex calls this on every fold, so the lock
    // only happens when the committed head actually moved.
    if (!force && !mayReanchor) {
      const known = this._headWatermark(tenant);
      if (known !== undefined && seq <= known) return true;
    }
    let wrote = false;
    try {
      this._headFileLock(staleHold => {
        if (staleHold()) return;
        const rawWm = this._readHeadWatermark();
        // Clone before mutating: the parsed map is shared cache state — a
        // write aborted below (stale hold, canonical throw) must never
        // leave a phantom entry the file does not carry (w40-fv F-9).
        let droppedPlanted = [];
        const tenants = this.#sanitizeWmTenants(rawWm && typeof rawWm === 'object' ? { ...rawWm } : {}, d => { droppedPlanted = d; });
        // The monotone compare must run on the RESOLVED floor, not the raw
        // stored seq: a forged {seq: huge, envelope: garbage} entry
        // otherwise satisfies "already ahead" forever and silently kills
        // the durable rollback floor (w39-seal F-1). An unverifiable entry
        // resolves to the committed head — it is no floor and is replaced.
        const priorEntry = tenants[tenant];
        const priorSeq = priorEntry === undefined ? undefined : this.#watermarkSeq(tenant, priorEntry);
        if (!mayReanchor && !force && (priorSeq ?? 0) >= seq) { this.#headWm.set(tenant, priorSeq); wrote = true; return; }
        // Signed entries only: the file lives inside the attacker's write
        // scope, so a bare number is forgeable into a floor above the head
        // that wedges every fold (w38 runtime-gate F-2). Falls back to a
        // bare seq only before the signer exists — the read-side clamp
        // below keeps an unsigned entry from pinning above the head.
        // Sign with the vault directly — going through _signingKeyId would
        // re-enter _auditIndex, which is exactly the call path that leads
        // here (fold → _headWatermark → bump → sign → fold …).
        let envelope = null;
        const signKid = this.keys(tenant).audit?.key_id;
        // The direct vault.envelope call skips assertSuiteAllowed — a live
        // configured key is always in the allowed suite set, so no
        // wrong-suite headmark can be minted this way (w40-fv F-12).
        if (signKid) {
          // A key the ledger already killed at or before the claimed seq
          // must not attest it — the fold-free row scan is what the head
          // flush consults for the same reason (w39-crypto F1). A vault
          // refusal (pending/diverged/dead flag) degrades to an unsigned
          // floor — named loudly via the tamper set rather than silently
          // sharing the bootstrap shape (w39-crypto F2).
          const facts = this._chainFacts(tenant);
          const deadAt = facts.dead.get(signKid);
          if (deadAt !== undefined && seq > deadAt) {
            // The configured signer is ledger-dead: steer to the successor
            // the chain itself designates — a signature-verified
            // KEY_ROTATED for a landed rotation, else the quorum-designated
            // pending key the same fold-free facts attest — signed with the
            // same recovery marker the steered path would carry (w39-crypto
            // F2). No designation, a dead successor, or a vault refusal
            // falls back to a named unsigned floor — never a silent one.
            const succ = facts.succ.get(signKid) ?? this._designatedAuditSuccessor(tenant);
            const se = succ ? this.vault.keys.get(succ) : null;
            if (se && !se.revoked && se.generated_inside !== false && facts.dead.get(succ) === undefined && this.ownsVaultKey(tenant, succ)) {
              try { envelope = this.vault.envelope(succ, 'audit', { tenant_id: tenant, format: 'IF-HEADMARK-1', head_seq: seq, recovery_signing: { superseded_key: signKid } }, { allowPending: true, tenant_id: tenant }); }
              catch { /* refused — named below */ }
            }
            if (!envelope) this.#wmTamper.set(tenant, { kind: 'dead_signer', seq });
          }
          else {
            try { envelope = this.vault.envelope(signKid, 'audit', { tenant_id: tenant, format: 'IF-HEADMARK-1', head_seq: seq }, { tenant_id: tenant }); }
            catch { this.#wmTamper.set(tenant, { kind: 'sign_failed', seq }); }
          }
        }
        tenants[tenant] = envelope ? { seq, envelope } : seq;
        const path = join(this.directory, 'head-watermark.json');
        // Re-verify the hold before committing — a stale hold may have
        // been cleared and retaken; our pre-image must never clobber the
        // peer's fresh floor (w28-store F3 / w28-fixverify F2).
        if (staleHold()) return;
        mkdirSync(this.directory, { recursive: true, mode: 0o700 });
        this.#writeFileSynced(`${path}.tmp`, canonical({ format: 'IF-HEADMARK-1', tenants }) + '\n');
        renameSync(`${path}.tmp`, path);
        this.#fsyncDir();
        this.#headWm.set(tenant, seq);
        // Our own SIGNED write is verified-clean by construction — a tamper
        // flag raised before it must not outlive the repair it reports
        // (w40-fv F-5). An unsigned fallback write repairs nothing: its
        // degradation flag (dead_signer / sign_failed) is exactly what must
        // survive to the seal surface (w39-crypto F2). The planted-content
        // drop is named AFTER the clear so it survives until the next
        // verified resolution reads the landed entry.
        if (envelope) this.#wmTamper.delete(tenant);
        for (const dt of droppedPlanted) this.#wmTamper.set(dt, { kind: 'planted_content' });
        wrote = true;
      });
    } catch (err) {
      // A held lock degrades to the in-memory guard — but a real write
      // failure leaves the durable floor frozen with the file pretending
      // it exists; the seal must see the loss (w41-fv F-6).
      if (err?.code !== 'INV-503-GATE') this.#wmTamper.set(tenant, { kind: 'write_failed', seq });
    }
    return wrote;
  }
  _headWatermark(tenant) {
    // The durable file is authoritative when present — always consulted,
    // so a peer's advance is never hidden by this process's cache
    // (w28-fixverify F4). The in-memory floor fills only the file-absent
    // bootstrap window.
    const wm = this._readHeadWatermark();
    const entry = wm && typeof wm === 'object' ? wm[tenant] : undefined;
    if (wm === 'oversized') this.#wmTamper.set(tenant, { kind: 'malformed' });
    if (entry !== undefined) {
      const seq = this.#watermarkSeq(tenant, entry);
      this.#headWm.set(tenant, seq);
      return seq;
    }
    if (this.#headWm.has(tenant)) return this.#headWm.get(tenant);
    // Bootstrap: absent file adopts the currently committed head (or 0 for
    // a fresh store) — covers first-contact upgrades. A signed head that
    // attests a nonzero floor proves the file once held this tenant: losing
    // the entry is strip evidence, so the bootstrap honors the attested
    // floor and names the event instead of minting a signed cover for the
    // attacker's position (w40-fv F-1). A consistent whole-directory
    // restore below the attested floor remains the documented residual.
    const head = this._chainHead(tenant);
    const attested = head && head !== 'corrupt' && Number.isSafeInteger(head.floor_seq) ? head.floor_seq : 0;
    if (attested > 0) {
      this.#wmTamper.set(tenant, { kind: 'floor_stripped' });
      this.#headWm.set(tenant, attested);
      return attested;
    }
    const adopted = head && head !== 'corrupt' ? head.seq : 0;
    // The durable floor must exist from the first contact — force the
    // write even for seq 0. Only a confirmed write is cached: a claimed
    // floor the file never got would be a phantom a peer's cold open
    // cannot share (w28-fixverify F7).
    if (this._bumpHeadWatermark(tenant, adopted, { force: true })) this.#headWm.set(tenant, adopted);
    return adopted;
  }
  // Resolve a stored watermark entry to the floor it may honestly pin.
  // Signed {seq, envelope} entries verify and may sit above the head (a
  // peer legitimately advanced). A bare number predates signing or was
  // planted — it can never pin above the committed head; a forged-high
  // unsigned entry degrades to the bootstrap floor and is named in the
  // tamper set the seal reports (w38 runtime-gate F-2).
  #watermarkSeq(tenant, entry) {
    const memo = this.#wmVerified.get(tenant);
    if (memo?.entry === entry) {
      // A memoized pass must not outlive its signer's ledger death —
      // re-check the death window on every hit (w41-fv F-7).
      const kid = entry && typeof entry === 'object' ? entry.envelope?.protected?.key_id : undefined;
      const deadAt = kid === undefined ? undefined : this._keyDeaths(tenant).get(kid);
      if (deadAt === undefined || !Number.isSafeInteger(memo.seq) || memo.seq <= deadAt) return memo.seq;
    }
    const done = seq => { this.#wmVerified.set(tenant, { entry, seq }); return seq; };
    const head = this._chainHead(tenant);
    const cap = head && head !== 'corrupt' ? head.seq : 0;
    if (entry !== null && typeof entry === 'object') {
      // Two signed shapes bind a floor: a self-signed headmark envelope
      // ({format:'IF-HEADMARK-1', head_seq}) from non-flush bump callers,
      // and a regular chain-head envelope ({seq, hash, …}) copied in by the
      // flush — both pin the entry seq to a verified audit-purpose
      // signature for this tenant (w38 runtime-gate F-2).
      const verified = (() => { try { const p = verifySigned(entry.envelope, this.auditPublicKeys(tenant), 'audit'); const bound = p.format === 'IF-HEADMARK-1' ? p.head_seq : p.seq; return p.tenant_id === tenant && bound === entry.seq; } catch { return false; } })();
      // The signer-death window every other consumer enforces: an entry
      // attesting a seq past its signer's ledger death is dead-signed
      // evidence — honoring it lets a compromised-then-revoked key pin a
      // permanent wedge (w39-crypto F3).
      const deadAt = this._keyDeaths(tenant).get(entry.envelope?.protected?.key_id);
      const deadSigned = deadAt !== undefined && Number.isSafeInteger(entry.seq) && entry.seq > deadAt;
      if (verified && !deadSigned && Number.isSafeInteger(entry.seq) && entry.seq >= 0) { this.#wmTamper.delete(tenant); return done(entry.seq); }
      this.#wmTamper.set(tenant, { kind: 'signature', seq: Number.isSafeInteger(entry.seq) ? entry.seq : undefined });
      return done(cap);
    }
    // A bare integer is at most tolerated — never exculpatory: it is the one
    // entry shape an attacker can write without keys, so resolving it must
    // NOT clear live tamper evidence (floor_stripped, unsigned_above_head,
    // dead_signer, sign_failed). Only a verified signed supersession clears
    // the flag (w43-seal F-5 / w43-store F-2).
    // And a signed-floor deployment never honestly regresses to a bare int:
    // the committed head attests floor_seq > 0 only after signed entries
    // exist, so an unsigned in-range entry is a synthesized downgrade —
    // resolve it, named, rather than letting the third signed leg silently
    // void (w44-seal F-2). Pre-signer deployments keep the silent path.
    if (Number.isSafeInteger(entry) && entry >= 0 && entry <= cap) {
      if (head !== 'corrupt' && Number.isSafeInteger(head?.floor_seq) && head.floor_seq > 0 && !this.#wmTamper.has(tenant)) this.#wmTamper.set(tenant, { kind: 'unsigned_downgrade', seq: entry });
      return done(entry);
    }
    if (Number.isSafeInteger(entry) && entry > cap) { this.#wmTamper.set(tenant, { kind: 'unsigned_above_head', seq: entry }); return done(cap); }
    this.#wmTamper.set(tenant, { kind: 'malformed' });
    return done(cap);
  }
  // The seal report names every watermark entry that failed verification
  // or was unsigned above the committed head — spreadable into any of its
  // result shapes (w38 runtime-gate F-2). Scoped to the sealing tenant:
  // tenant A's report must not leak tenant B's file-integrity state
  // (w39-seal F-4).
  // Durable-file writes that a signed chain row claims must actually
  // survive the crash window the claim commits across — write+rename alone
  // leaves the rename in page cache while the AUDIT_WM_REANCHORED row is
  // already synchronous=FULL durable (w43-seal F-4). File fsync plus a
  // directory fsync for the rename entry closes the gap.
  #writeFileSynced(path, contents, fsync = true) {
    const fd = openSync(path, 'w', 0o600);
    try { writeSync(fd, contents); if (fsync) fsyncSync(fd); }
    finally { closeSync(fd); }
  }
  #fsyncDir() {
    try { const fd = openSync(this.directory, 'r'); try { fsyncSync(fd); } finally { closeSync(fd); } }
    catch { /* directory fsync unsupported on some filesystems — file fsync still landed */ }
  }
  #wmTamperAttest(tenant) {
    const entry = this.#wmTamper.get(tenant);
    return entry ? { head_watermark_tampered: [{ tenant_id: tenant, kind: entry.kind, ...(entry.seq !== undefined ? { seq: entry.seq } : {}) }] } : {};
  }
  // A head's checkpoint attestation binds CONTENT, not mere presence: a
  // planted 'audit-checkpoint' row inflates the floor count and satisfies a
  // get()!==null check while carrying attacker-chosen bytes — every claimed
  // checkpoint must still verify as a signed checkpoint envelope under the
  // tenant's audit keys (w36-fixverify L-3).
  _checkpointAttested(tenant, size) {
    let cp; try { cp = this.store.get(tenant, 'audit-checkpoint', `cp-${size}`); } catch { return false; }
    if (!cp) return false;
    try { const pl = verifySigned(cp, this.auditPublicKeys(tenant), 'checkpoint'); return pl.tenant_id === tenant && pl.size === size; }
    catch { return false; }
  }
  _verifiedCheckpointCount(tenant) {
    let n = 0;
    for (const id of this.store.ids(tenant, 'audit-checkpoint', 1_000_000)) {
      try { if (verifySigned(this.store.get(tenant, 'audit-checkpoint', id), this.auditPublicKeys(tenant), 'checkpoint').tenant_id === tenant) n++; }
      catch { /* a planted or undecryptable row is not a verified checkpoint */ }
    }
    return n;
  }
  persistVault() {
    mkdirSync(this.directory, { recursive: true, mode: 0o700 });
    // Write order: keystore first, master.key last — the master file is the
    // commit marker, so a crash mid-write can never pair a stale master key
    // with a keystore it did not wrap (w6-ceremony F12).
    // Two instances persisting concurrently used to diverge: the second
    // overwrote keystore.json under ITS master while skipping the existing
    // master.key — a permanently mismatched pair and a deterministic
    // INV-503-CONFIG wedge on next open (w48-store W48-2). Lock the whole
    // persist, and when master.key already exists verify the pair BEFORE
    // committing: a divergent master's keystore must scream immediately
    // rather than clobber the consistent pair the other instance wrote.
    const lockPath = join(this.directory, 'vault-persist.lock');
    const deadline = Date.now() + 4_000;
    for (let attempt = 0;; attempt++) {
      try { mkdirSync(lockPath); break; }
      catch (err) {
        if (err?.code !== 'EEXIST') throw err;
        try { if (Math.abs(Date.now() - statSync(lockPath).mtimeMs) > 8_000) rmSync(lockPath, { recursive: true, force: true }); } catch { /* lost the race to clear it */ }
        if (Date.now() > deadline) throw new InvariantError('INV-503-GATE', 'Vault persist lock held by a live peer beyond the deadline', 503);
        const spin = Date.now() + Math.min(2 * (attempt + 1), 20);
        while (Date.now() < spin) { /* bounded backoff; the locked section is milliseconds */ }
      }
    }
    const ksTmp = join(this.directory, `keystore.${process.pid}.${randomBytes(8).toString('hex')}.tmp`);
    const ksPath = join(this.directory, 'keystore.json'), masterPath = join(this.directory, 'master.key');
    try {
      this.vault.save(ksTmp);
      if (existsSync(masterPath)) {
        // Verify BEFORE the rename commits: the keystore about to replace
        // the file must unwrap under the master already on disk — refuse
        // to clobber a consistent pair with a divergent master's write.
        try { KeyVault.load(ksTmp, JSON.parse(readFileSync(masterPath, 'utf8'))?.master_key); }
        catch (e) { rmSync(ksTmp, { force: true }); throw new InvariantError('INV-503-CONFIG', 'Persisted keystore does not unwrap under the existing master.key — concurrent divergent persist or tamper evidence', 503, { cause: e }); }
        renameSync(ksTmp, ksPath);
      } else {
        renameSync(ksTmp, ksPath);
        // Randomized tmp name: a fixed one is a squat target and a stale
        // leftover masquerades as an in-flight write (w48-store W48-2).
        const mkTmp = join(this.directory, `master.key.${process.pid}.${randomBytes(8).toString('hex')}.tmp`);
        this.#writeFileSynced(mkTmp, canonical({ format: 'IF-MASTERKEY-1', warning: 'software vault master key; custody is the operator\'s responsibility', master_key: this.vault.masterKey.toString('base64url') }) + '\n');
        renameSync(mkTmp, masterPath);
      }
      this.#fsyncDir();
    } finally {
      try { rmSync(lockPath, { recursive: true, force: true }); } catch { /* a peer cleared or took the lock */ }
    }
  }
  // Live, failure-domain-deduplicated custodian consent for a ceremony:
  // acknowledgements from revoked identities or from the same failure
  // domain do not count toward quorum (w6 F7/F9).
  // A pending key may take over signing only when the threshold quorum
  // designated it: a ceremony whose anchored plan names the key in
  // `rotation.new_key_id` for this key class, which gathered at least
  // `threshold` custodian acknowledgements, and which was never aborted.
  // prepareRotation alone is a unilateral substitution path — a lone
  // `security` identity must not pick the tenant signer (w18-crypto F3).
  ceremonyDesignated(t, kid, klass) {
    const idx = this._auditIndex(t);
    for (const [cid, plannedDigest] of idx.ceremonyPlanned ?? []) {
      // Abort kills designation; completion and consumption do not —
      // they are the designation's success lifecycle (the pending key
      // signs its own landing rotation). The anchored plan digest binds
      // designation to exactly one kid regardless (w19-lifecycle F6).
      if (idx.ceremonyAborted?.has(cid)) continue;
      const ceremony = this.store.get(t, 'ceremony', cid);
      // Only a key.rotate ceremony designates a signer — a recovery-labeled
      // ceremony carrying a rotation spec is outside the designation
      // contract (w20-ceremony residual).
      if (!ceremony || ceremony.purpose !== 'key.rotate' || ceremony.rotation?.new_key_id !== kid || ceremony.rotation?.key_class !== klass) continue;
      const planDigest = this._ceremonyPlanDigest(ceremony);
      if (planDigest === null || !ctEqual(planDigest, plannedDigest)) continue;
      // The designation bar is the live quorum, not a raw anchored-ack
      // count — same-domain signers, revoked custodians and stale-digest
      // acks must not satisfy designation where custodianQuorum refuses
      // them (w18-fixverify2 MEDIUM). A fabricated or tampered plan can
      // never satisfy it either — the row's own threshold is not the bar
      // (w19-lifecycle F1).
      const q = this.custodianQuorum(t, ceremony);
      if (q.planAnchored && q.live >= Math.max(1, ceremony.threshold)) return true;
    }
    return false;
  }
  // The plan digest is recomputed from the plan terms — the artifact digest
  // itself legitimately mutates at share-commit (it folds the commitments
  // in), so the anchor binds the terms instead (w17-redteam A2).
  _ceremonyPlanDigest(ceremony) {
    try { return digest({ ceremony_id: ceremony.ceremony_id, tenant_id: ceremony.tenant_id, purpose: ceremony.purpose, threshold: ceremony.threshold, custodians: [...(ceremony.custodians ?? [])].sort(), valid_until: ceremony.valid_until, min_delay_ms: ceremony.min_delay_ms, devices: ceremony.devices ?? null, rotation: ceremony.rotation ?? null }); }
    catch { return null; /* forged rows with non-canonical fields fail closed, never crash the gate */ }
  }
  _ceremonyPlanAnchored(t, ceremony) {
    const planned = this._auditIndex(t).ceremonyPlanned?.get(ceremony.ceremony_id);
    const planDigest = this._ceremonyPlanDigest(ceremony);
    return planned !== undefined && planDigest !== null && ctEqual(planDigest, planned);
  }
  // The consent epoch a custodian must have signed: the plan digest
  // pre-commit, or the commit rebind recomputed from anchored terms and
  // the ANCHORED commitment set post-commit. A share_commitments row that
  // diverges from the anchored commitments_digest can never name a consent
  // epoch — null fails every digest comparison closed (w20-ceremony W20-2).
  _ceremonyConsentDigest(t, ceremony) {
    const committed = this._auditIndex(t).ceremonyCommitted?.get(ceremony.ceremony_id);
    if (!committed) return this._ceremonyPlanDigest(ceremony);
    if (typeof committed.commitments_digest !== 'string') return null;
    try {
      if (digest(ceremony.share_commitments ?? []) !== committed.commitments_digest) return null;
      return digest({ ceremony_id: ceremony.ceremony_id, tenant_id: ceremony.tenant_id, purpose: ceremony.purpose, threshold: ceremony.threshold, custodians: ceremony.custodians, valid_until: ceremony.valid_until, min_delay_ms: ceremony.min_delay_ms, share_commitments: ceremony.share_commitments.map(c => c.commitment) });
    } catch { return null; }
  }
  custodianQuorum(t, ceremony) {
    // The ceremony row must descend from an anchored plan: its governance
    // fields (threshold, custodians, validity, rotation) must recompute to
    // the digest the signed CEREMONY_PLANNED event attested. planAnchored
    // tells callers the row survived that check — a `live >= threshold`
    // comparison alone is `0 >= 0` on any unanchored or tampered row
    // (w19-lifecycle F1).
    if (!this._ceremonyPlanAnchored(t, ceremony))
      return { count: ceremony.acknowledgements?.length ?? 0, live: 0, custodians: new Set(), planAnchored: false };
    // The digest a custodian must have signed is computed from anchored
    // terms, never the mutable artifact_digest row field: pre-commit it is
    // the plan digest; post-commit it is the commit rebind recomputed from
    // anchored terms + the anchored commitment set. A flipped
    // artifact_digest can neither resurrect superseded consent nor wedge
    // live consent (w20-ceremony W20-2).
    const consentDigest = this._ceremonyConsentDigest(t, ceremony);
    if (consentDigest === null)
      return { count: ceremony.acknowledgements?.length ?? 0, live: 0, custodians: new Set(), planAnchored: true };
    const ids = this.identities(t);
    const domains = new Set(), live = new Set();
    for (const a of ceremony.acknowledgements) {
      // Only consent to the CURRENT anchored epoch counts: an
      // acknowledgement bound to a superseded digest attested different
      // terms (w7-seam F4).
      if (a.payload?.artifact_digest !== consentDigest) continue;
      // One custodian contributes exactly one seat no matter how many
      // envelopes or enrolments they carry — the live count is distinct
      // subjects, and domains is the diversity view over the SAME subjects
      // (w20-ceremony W20-1).
      if (live.has(a.payload?.custodian)) continue;
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
      if (!(this._auditIndex(t).ceremonyAcks.get(ceremony.ceremony_id) ?? new Map()).has(a.payload.custodian)) continue;
      live.add(a.payload.custodian);
      domains.add(identity.failure_domain ?? a.payload.custodian);
    }
    // Anchored consent survives row truncation: a custodian whose ack the
    // ledger attests for THIS artifact still counts even when the mutable
    // envelope was deleted — the envelope verified at acknowledge time and
    // the chain is the evidence (w19-lifecycle F5). Revocation is still
    // consulted live: a revoked custodian's anchored consent lapses.
    for (const [custodian, ack] of this._auditIndex(t).ceremonyAcks.get(ceremony.ceremony_id) ?? new Map()) {
      if (live.has(custodian) || ack?.artifact_digest !== consentDigest) continue;
      const identity = ids[ack.key_id];
      if (!identity || identity.revoked || identity.subject_id !== custodian) continue;
      live.add(custodian); domains.add(identity.failure_domain ?? custodian);
    }
    return { count: ceremony.acknowledgements.length, live: domains.size, custodians: live, planAnchored: true };
  }
  // The served lifecycle status comes from the chain, not the row: the
  // fold's anchored lifecycle always wins over a mutated status field
  // (w20-ceremony residual — GET /v1/ceremonies must not echo tampered
  // rows to operators).
  ceremonyStatus(t, ceremony) {
    const idx = this._auditIndex(t);
    if (idx.ceremonyAborted?.has(ceremony.ceremony_id)) return 'aborted';
    if (idx.ceremonyCompleted?.has(ceremony.ceremony_id)) return 'completed';
    if (idx.ceremonyCommitted?.has(ceremony.ceremony_id)) return 'committed';
    if (idx.ceremonyPlanned?.has(ceremony.ceremony_id)) return 'live';
    return 'unanchored';
  }
  close() {
    // Paths that append through store.tx bypass the transaction() flush
    // edge — land any pending watermarks before the vault unloads, or the
    // next open reads committed rows with no signed head (w25-clock F-4).
    try { this._flushChainHeads(); } catch { /* a store already gone can still close */ }
    this.target.close(); this.store.close();
  }
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
  executionPublic(t) { return this._verifyKeysCached(t, 'execution'); }
  auditPublicKeys(t) { return this._verifyKeysCached(t, 'audit'); }
  // Fold-free incremental scan of the security-significant chain surface —
  // signer deaths, rotation designations and ceremony facts the
  // head-watermark bump and the seal prescan need without re-entering
  // _auditIndex (the bump runs inside the fold's own head-sync window,
  // where a re-entrant fold throws INV-503). The extraction mirrors the
  // fold's shapes exactly: revoke() writes reference:'<kind>:<id>'; carried
  // events unfold at their ORIGINAL seq (orig_seq) the way #foldApply
  // replays them, and floor_derived refs stay exempt exactly as the fold's
  // keyDeadAt enforcement exempts them (w39-seal F-6, w39-crypto F2).
  _chainFacts(tenant) {
    // Raw sqlite schema failures (a dropped or rewritten audit table) are
    // integrity evidence inside the INV taxonomy, never bare ERR_SQLITE
    // noise on a direct caller — parity with _auditIndex and the store's
    // bulk readers (w46-store M-3).
    try { return this._chainFactsInner(tenant); }
    catch (e) {
      if (e instanceof InvariantError) throw e;
      if (/no such table|no such column|not a database|malformed/i.test(e?.message ?? ''))
        throw new InvariantError('INV-409-INTEGRITY', 'Ledger schema diverged — tamper evidence', 409, { cause: e });
      throw e;
    }
  }
  _chainFactsInner(tenant) {
    // Signature-verified rows only: an unverified planted row can never
    // mint a death, a quorum, or a successor here — the fold itself
    // wedges on that same plant, so absorbing it would only fabricate
    // attacker-chosen facts (w41-fv F-1).
    // The tip hash joins the fingerprint too: the payload-hash chain makes
    // each row's hash a function of every row before it, so the tip hash
    // fingerprints the WHOLE table — a mid-table rewrite that preserves
    // count/max/seal-tip still diverges (a refill commit can replay an
    // abort's seqs with different content) (w43-store F-1).
    // In-transaction memo: under our own IMMEDIATE lock the audit table
    // can only move through this store's writes, so once the fingerprint
    // has run once in a tx window, repeat calls in the same window are
    // fresh whenever no append of ours landed in between (w44-perf). The
    // memo dies with the window (transaction() resets _probeMemo), so
    // out-of-tx calls always pay the real fingerprint — peer writes
    // between transactions can never hide behind it.
    const cfMemoKey = `cf:${tenant}`, cfAppends = this.store._auditAppends ?? 0;
    if (this._probeMemo) { const hit = this._probeMemo.get(cfMemoKey); if (hit?.appends === cfAppends) return hit.cached; }
    let cached = this._keyDeathCache.get(tenant);
    // Deletes renumber the tail (audit_seq_guard lands inserts at
    // MAX(seq)+1), so the seq cursor alone is blind to a regressed table:
    // any count/maxSeq drop re-derives the whole set (w41-fv F-3). A new
    // seal writes its AUDIT_SEALED/CARRY rows below the cursor, so the
    // seal tip joins the fingerprint too — their carried revocations and
    // lifecycle deaths must re-derive (w41-seal F6). A rewrite preserving
    // all three is the fold's own hash-chain conviction — these facts
    // never need to outlive a convicted table.
    // The tip hash must be RECOMPUTED, not read: the stored hash column is
    // attacker clay, and an envelope rewrite that preserves it would leave
    // this fingerprint unchanged while the facts it guards are poisoned —
    // the fingerprint binds the column AND the row bytes together so
    // either half of the lie re-derives (w44-fixverify F-7). A new seal
    // always lands as an append, so count/max-seq/tip all move and the
    // fingerprint re-derives — no separate seal probe is needed, and a
    // parsed-type subquery would only re-parse every envelope above the
    // floor on every index call (w44 CI perf regression).
    const shape = (this.#cfShapeStmt ??= this.store._stmt(
      'SELECT COUNT(*) n, COALESCE(MAX(seq),0) m,'
      + ' (SELECT hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1) h,'
      + ' (SELECT envelope FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1) e'
      + ' FROM audit WHERE tenant=?',
    )).get(tenant, tenant, tenant);
    shape.h = shape.h !== null ? `${shape.h}\x00${hashBytes(shape.e)}` : null;
    delete shape.e;
    const prevDead = cached?.dead, prevRefs = cached?.refsDead;
    if (cached && (shape.m < cached.throughSeq || shape.n < cached.count || shape.h !== cached.tipHash)) cached = undefined;
    cached ??= { throughSeq: 0, count: 0, dead: new Map(), succ: new Map(), refsDead: new Set(), floorRefs: new Set(), cer: { planned: new Map(), aborted: new Set(), committed: new Map(), acks: new Map() } };
    cached.succ ??= new Map(); cached.refsDead ??= new Set(); cached.floorRefs ??= new Set();
    cached.cer ??= { planned: new Map(), aborted: new Set(), committed: new Map(), acks: new Map() };
    // Rescan only when the committed tail actually advanced — an identical
    // (n, m, s) shape is the same table this cache already folded, so the
    // empty-delta scan is pure cost (w43-perf). An uncommitted in-tx append
    // still bumps m/n here because the cursor table is this connection's own.
    // Stored envelope text is attacker-writable: a respelled row
    // ('\u0074ype') folds identically yet vanishes from a LIKE scan, so
    // every fold-free scan keys on the PARSED type — json_valid guards
    // malformed rows the LIKE would have skipped (w44-store H-3).
    // Duplicate keys break parsed-type scans too: sqlite reads the FIRST
    // dup member where JSON.parse reads the LAST, so a decoy '"payload"'
    // spliced before the real one would vanish here while folding as its
    // true type below (w45-fv HIGH). Canonical writers never mint dup
    // keys, so any dup at root or $.payload is adversarial — the row must
    // always be a candidate and let the JS parse speak.
    if (shape.m > cached.throughSeq) for (const row of (this.#cfScanStmt ??= this.store._stmt("SELECT seq,envelope FROM audit WHERE tenant=? AND seq>? AND json_valid(envelope) AND (json_extract(envelope,'$.payload.type') IN ('AUTHORITY_REVOKED','KEY_ROTATED','AUDIT_SEALED','AUDIT_SEAL_CARRY') OR json_extract(envelope,'$.payload.type') LIKE 'CEREMONY_%' OR EXISTS (SELECT 1 FROM json_each(envelope,'$') GROUP BY \"key\" HAVING COUNT(*)>1) OR EXISTS (SELECT 1 FROM json_each(envelope,'$.payload') GROUP BY \"key\" HAVING COUNT(*)>1))")).all(tenant, cached.throughSeq)) {
      let env; try { env = JSON.parse(row.envelope); } catch { continue; }
      const pl = env?.payload, meta = pl?.metadata;
      let verified;
      const isVerified = () => verified ??= (() => { try { verifySigned(env, this.auditPublicKeys(tenant), 'audit'); return true; } catch { return false; } })();
      const apply = (type, reference, actor, meta2, atSeq) => {
        // Carried entries share their carrier's verdict: apply() only
        // runs for unfold when the AUDIT_SEALED/CARRY envelope verified.
        if (!isVerified()) return;
        if (type === 'AUTHORITY_REVOKED' && typeof reference === 'string') {
          cached.refsDead.add(reference);
          if (reference.startsWith('key:')) cached.dead.set(reference.slice(4), Math.min(cached.dead.get(reference.slice(4)) ?? Infinity, atSeq));
        }
        if (type === 'KEY_ROTATED' && meta2?.key_class === 'audit' && typeof meta2?.previous_key_id === 'string') {
          cached.dead.set(meta2.previous_key_id, Math.min(cached.dead.get(meta2.previous_key_id) ?? Infinity, atSeq));
          // A verified rotation names its successor in the row reference —
          // the designation the headmark bump steers to where
          // _signingKeyId would re-enter the fold (w39-crypto F2, field
          // layout corrected w41-fv F-2).
          if (typeof reference === 'string') cached.succ.set(meta2.previous_key_id, reference);
        }
        if (type === 'CEREMONY_PLANNED' && typeof reference === 'string' && typeof meta2?.digest === 'string') cached.cer.planned.set(reference, meta2.digest);
        if (type === 'CEREMONY_ABORTED' && typeof reference === 'string') cached.cer.aborted.add(reference);
        if (type === 'CEREMONY_SHARES_COMMITTED' && typeof reference === 'string') cached.cer.committed.set(reference, meta2?.commitments_digest ?? null);
        if (type === 'CEREMONY_ACKNOWLEDGED' && typeof reference === 'string' && meta2?.custodian === actor)
          (cached.cer.acks.get(reference) ?? cached.cer.acks.set(reference, new Map()).get(reference)).set(actor, { digest: meta2?.artifact_digest ?? null, kid: meta2?.key_id ?? null });
      };
      apply(pl?.type, pl?.reference, pl?.actor, meta, row.seq);
      if ((pl?.type === 'AUDIT_SEALED' || pl?.type === 'AUDIT_SEAL_CARRY') && isVerified()) {
        for (const rv of Array.isArray(meta?.revocations_carryover) ? meta.revocations_carryover : [])
          if (typeof rv?.reference === 'string' && rv.floor_derived !== true) {
            cached.refsDead.add(rv.reference);
            if (rv.reference.startsWith('key:')) cached.dead.set(rv.reference.slice(4), Math.min(cached.dead.get(rv.reference.slice(4)) ?? Infinity, typeof rv.orig_seq === 'number' ? rv.orig_seq : row.seq));
          }
          // A floor-derived 'key:' ref never pins a death window — the
          // ref may be planted — but it still names a claim the row
          // level enforces as revoked everywhere else, so signer
          // selection must steer away from it the same way (w43-seal
          // floor-pin LOW).
          else if (typeof rv?.reference === 'string' && rv.reference.startsWith('key:')) cached.floorRefs.add(rv.reference.slice(4));
        for (const lc of Array.isArray(meta?.lifecycle_carryover) ? meta.lifecycle_carryover : [])
          apply(lc?.type, lc?.reference ?? null, lc?.actor ?? null, lc?.metadata, typeof lc?.orig_seq === 'number' ? lc.orig_seq : row.seq);
      }
    }
    // Deaths and revoked references are monotone facts — a rescan that
    // produces FEWER of them than the last derivation means folded rows
    // were rewritten into non-matching envelopes mid-table (the memo's
    // fingerprint only sees count/max-seq/tip). Name the regression as
    // tamper evidence rather than silently un-killing a dead signer
    // (w44-fixverify F-7).
    // During a seal's own delete/repoint window the rescan legitimately
    // sees fewer dead facts — the seal IS the authorized remover, and the
    // carried facts unfold again once the seal row lands. Suppressing the
    // regression latch while #sealCarry is armed keeps the seal's own
    // deletes from minting a phantom facts_regressed attestation that
    // would then suppress real wm-tamper evidence for the process's life
    // (w47-seal F-1). Peers cannot interleave: the seal holds the
    // IMMEDIATE write boundary, so mid-window fact loss is ours alone.
    const sealInFlight = this.#sealCarry.has(tenant);
    if (!sealInFlight && !this.#wmTamper.has(tenant) && prevDead && cached.dead.size < prevDead.size) this.#wmTamper.set(tenant, { kind: 'facts_regressed' });
    else if (!sealInFlight && !this.#wmTamper.has(tenant) && prevRefs) { for (const r of prevRefs) if (!cached.refsDead.has(r)) { this.#wmTamper.set(tenant, { kind: 'facts_regressed' }); break; } }
    // The watermark tracks the committed tail, not the last matching row —
    // shape.m already IS that tail, so no second tip probe is needed.
    if (shape.m > cached.throughSeq) cached.throughSeq = shape.m;
    cached.count = shape.n;
    cached.tipHash = shape.h ?? null;
    this._keyDeathCache.set(tenant, cached);
    this._probeMemo?.set(cfMemoKey, { appends: cfAppends, cached });
    return cached;
  }
  _keyDeaths(tenant) { return this._chainFacts(tenant).dead; }
  // Fold-free mirror of ceremonyDesignated + custodianQuorum for the audit
  // class — the headmark bump cannot re-enter the fold, so a pending
  // successor must be found from the same anchored facts: an unaborted
  // CEREMONY_PLANNED whose digest re-binds the ceremony row, a quorum of
  // live distinct-domain custodians whose anchored acks name the current
  // consent epoch, and a healthy tenant-owned pending vault key
  // (w39-crypto F2). Divergence from the fold can only ever shrink this
  // set — the bump falls back to a named unsigned floor, never to a
  // guessed signer.
  _auditDesignationHolds({ cer, refsDead }, tenant, kid) {
    const ids = this.tenant(tenant).identities ?? {};
    for (const [cid, plannedDigest] of cer.planned) {
      if (cer.aborted.has(cid)) continue;
      const ceremony = this.store.get(tenant, 'ceremony', cid);
      if (!ceremony || ceremony.purpose !== 'key.rotate' || ceremony.rotation?.new_key_id !== kid || ceremony.rotation?.key_class !== 'audit') continue;
      const planDigest = this._ceremonyPlanDigest(ceremony);
      if (planDigest === null || !ctEqual(planDigest, plannedDigest)) continue;
      // Consent epoch — pre-commit the plan digest, post-commit the
      // anchored rebind, exactly as _ceremonyConsentDigest computes it.
      let consent = planDigest;
      const commitments = cer.committed.get(cid);
      if (commitments !== undefined) {
        if (typeof commitments !== 'string' || digest(ceremony.share_commitments ?? []) !== commitments) continue;
        try { consent = digest({ ceremony_id: cid, tenant_id: tenant, purpose: ceremony.purpose, threshold: ceremony.threshold, custodians: ceremony.custodians, valid_until: ceremony.valid_until, min_delay_ms: ceremony.min_delay_ms, share_commitments: (ceremony.share_commitments ?? []).map(c => c.commitment) }); }
        catch { continue; }
      }
      const domains = new Set();
      for (const [custodian, ack] of cer.acks.get(cid) ?? []) {
        if (ack?.digest !== consent) continue;
        const identity = ids[ack?.kid];
        if (!identity || identity.revoked || identity.subject_id !== custodian) continue;
        if (refsDead.has(`subject:${custodian}`) || refsDead.has(`key:${ack.kid}`) || refsDead.has(`device:${identity.device_id}`)) continue;
        domains.add(identity.failure_domain ?? custodian);
      }
      if (domains.size >= Math.max(1, ceremony.threshold ?? 1)) return true;
    }
    return false;
  }
  _designatedAuditSuccessor(tenant) {
    const facts = this._chainFacts(tenant);
    const needed = this._keyPurposes.audit ?? ['audit'];
    for (const [kid, e] of this.vault.keys.entries()) {
      if (!e.pending || e.revoked || e.generated_inside === false || facts.dead.has(kid)) continue;
      if (!this.ownsVaultKey(tenant, kid)) continue;
      if (!(e.purpose === 'any' || needed.every(x => (Array.isArray(e.purpose) ? e.purpose : [e.purpose]).includes(x)))) continue;
      if (this._auditDesignationHolds(facts, tenant, kid)) return kid;
    }
    return undefined;
  }
  _verifyKeysCached(t, klass) {
    const parts = [klass, JSON.stringify(this.keys(t)[klass] ?? null), JSON.stringify(this.keys(t).retired ?? null)];
    // tenant_id/suite/exportable join the signature: membership consults
    // ownsVaultKey (tenant binding) and the suite pin, so an in-process
    // field flip must not ride a stale inclusive map (w39-crypto F6).
    for (const [kid, e] of this.vault.keys) parts.push(kid, String(e.public_key), String(!!e.pending), String(!!e.revoked), String(e.generated_inside === false), String(e.tenant_id ?? ''), String(e.suite ?? ''), String(e.exportable ?? ''), JSON.stringify(e.purpose));
    const dr = this.#declaredRetired[t]; if (dr) for (const [k, v] of dr) parts.push(k, String(v));
    const sig = parts.join('\x00');
    const key = `${t}:${klass}`;
    const c = this._verifyKeyCache.get(key);
    if (c?.sig === sig) return c.out;
    const out = this._verifyKeys(t, klass);
    this._verifyKeyCache.set(key, { sig, out });
    return out;
  }
  // Resolves the key allowed to mint class envelopes right now: the bound
  // key when live, else the pending, tenant-owned successor minted before
  // the revoke — the designed escape that keeps a compromise-response from
  // bricking the tenant (w11-lifecycle F1/F2). Recovery envelopes carry a
  // `recovery_signing` marker naming the superseded key, so the ledger tells
  // the truth about which authority signed.
  _signingKeyId(t, klass) {
    // Every input the resolution consults lives in append-only fold sets
    // or the vault's own flag checks: a revocation, rotation, ceremony
    // stage, or grant lands as a NEW fold entry, so the sizes of those
    // sets change exactly when the answer can change (w28-http CI
    // regression: the lookup ran per signature). Vault-flag divergence
    // without a lifecycle event re-verifies at envelope() — a stale sel
    // can refuse a signature, never forge one.
    const idx0 = this._auditIndex(t);
    // Designation reads the ceremony row's plan bytes too — include them,
    // but only while plans exist (the common eval path has none).
    let cer = '';
    if (idx0.ceremonyPlanned?.size) {
      this._cerRowQ ??= this.store._stmt('SELECT value FROM records WHERE tenant=? AND kind=? AND id=?');
      for (const cid of idx0.ceremonyPlanned.keys()) cer += `${cid}=${this._cerRowQ.get(t, 'ceremony', cid)?.value ?? '-'};`;
    }
    const selFp = `${this.keys(t)[klass]?.key_id}|${idx0.revoked.size}|${idx0.rotationsByPrev?.size ?? 0}|${idx0.rotationKeys?.size ?? 0}|${idx0.ceremonyPlanned?.size ?? 0}|${idx0.ceremonyCommitted?.size ?? 0}|${idx0.ceremonyCompleted?.size ?? 0}|${idx0.ceremonyAborted?.size ?? 0}|${idx0.ceremonyRotationConsumed?.size ?? 0}|${idx0.ceremonyAcks?.size ?? 0}|${idx0.grants?.size ?? 0}|${cer}`;
    const selKey = `${t}:${klass}`;
    const selHit = this._signSelCache.get(selKey);
    if (selHit?.fp === selFp) return selHit.sel;
    const sel = this._signingKeyIdResolve(t, klass);
    this._signSelCache.set(selKey, { fp: selFp, sel });
    return sel;
  }
  _signingKeyIdResolve(t, klass) {
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
      && (e.purpose === 'any' || needed.every(x => (Array.isArray(e.purpose) ? e.purpose : [e.purpose]).includes(x)))
      && this.ceremonyDesignated(t, kid, klass));
    requireThat(successor, 'INV-401-SIGNATURE', `${klass} signing key unavailable and no ceremony-designated pending successor exists — rotate first`, 401);
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
    // The declared per-key suite is an input to verification too — a stale
    // OK must not survive a suite repin on the same public material
    // (w22-fixverify F7). Policy suite floors are enforced outside this memo
    // at every call site (assertSuiteAllowed), so they are not keyed here.
    const ck = `${Object.entries(keys).map(([k, v]) => `${k}:${digest(v?.public_key ?? '').slice(0, 16)}:${v?.suite ?? ''}:${v?.revoked ? 1 : 0}`).sort().join(',')}|${purpose}|${digest(envelope)}`;
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
    return this.vault.envelope(sel.key_id, purpose, this._recoveryBody(sel, payload), { allowPending: sel.recovery, tenant_id: t });
  }
  // The explicit key_id path is internal-only (the rotation-succession
  // outcome signer) — it still enforces tenant ownership and ledger
  // revocation; the purpose pin lives at the vault sign call (w13 L10).
  signAudit(t, payload, purpose = 'audit', key_id = null, { allowPending = false } = {}) {
    const sel = key_id ? { key_id, recovery: false } : this._signingKeyId(t, 'audit');
    if (key_id) {
      // revoked() sees AUTHORITY_REVOKED only — a KEY_ROTATED death is a
      // ledger death too and must refuse signing identically (w39-crypto
      // F4). keyDeadAt covers both death flavors in the fold.
      const dead = this._auditIndex(t).keyDeadAt?.has(key_id) === true;
      requireThat(this.ownsVaultKey(t, key_id) && !this.revoked(t, 'key', key_id) && !dead, 'INV-401-SIGNATURE', 'Signing key revoked or foreign', 401);
      // The marker follows the binding, not the resolution path: a pending
      // successor standing in for the configured key signs marked, whoever
      // steered it there — else the same act yields two ledger shapes
      // (w39-crypto F5).
      const bound = this.keys(t).audit?.key_id;
      const e0 = this.vault.keys.get(key_id);
      if (e0?.pending === true && key_id !== bound) { sel.recovery = true; sel.superseded = bound ?? null; }
    }
    const e = this.vault.keys.get(sel.key_id);
    this.assertSuiteAllowed(t, e?.suite ?? 'Ed25519');
    return this.vault.envelope(sel.key_id, purpose, this._recoveryBody(sel, payload), { allowPending: allowPending || sel.recovery, tenant_id: t });
  }
  assertSuiteAllowed(t, suite) {
    let allowed = this._allowedSuites(t);
    if (allowed !== null) requireThat((allowed ?? ['Ed25519']).includes(suite), 'INV-451-POLICY', 'Signature suite retired by constitution', 451);
  }
  // The suites that can still sign under this tenant: every unrevoked,
  // non-pending vault key bound to it. A constitution whose allowed_suites
  // retires one of these can never sign its own POLICY_ACTIVATED — the
  // gate it installs would refuse that very signature and wedge every
  // later transaction (w30-policy F9). Retirement is legal only after the
  // live keys have rotated off the suite.
  _coversLiveSuites(t, candidate) {
    const suites = candidate?.algorithms?.allowed_suites;
    if (!suites) return true;
    for (const [kid, e] of this.vault.keys) {
      if (!e.revoked && !e.pending && this.ownsVaultKey(t, kid) && !suites.includes(e.suite)) return false;
    }
    return true;
  }
  // The allowed-suite answer changes only with the served constitution or
  // the anchor set that vouches for it — both are digest-bound, so the
  // resolution memoizes on exactly that content (w28-http CI regression:
  // the check runs per signature, and per-evaluation sign volume made the
  // full policy() walk the hot path). A policy row swap changes a digest;
  // a new anchor changes the tail signature; staged timing flags flip the
  // booleans — every input is captured.
  _allowedSuites(t) {
    const anchors = (() => { try { return this._auditIndex(t).policyAnchors; } catch { return null; } })();
    const nonStaged = anchors ? [...anchors].reverse().find(a => !a.staged) : null;
    const stagedAnchor = anchors ? [...anchors].reverse().find(a => a.staged) : null;
    const now = this.clock();
    // The fingerprint must capture every input the resolution consults:
    // the raw stored value of both policy rows (a ciphertext swap changes
    // the bytes even when the decrypted content would compare equal, and
    // the miss path re-reads them through the integrity-checked get()) and
    // the anchor digests that vouch for them. Raw bytes stand in for
    // digest(row-content): equal content re-encrypted yields a cheap
    // conservative miss, different content always differs (w28-http CI
    // regression — two digests of the full policy documents per
    // signature was the hot path).
    this._policyRowQ ??= this.store._stmt('SELECT value FROM records WHERE tenant=? AND kind=? AND id=?');
    const av = this._policyRowQ.get(t, 'policy', 'active')?.value ?? null;
    const sv = this._policyRowQ.get(t, 'policy', 'staged')?.value ?? null;
    const stagedMeta = sv ? this.store.readValue(t, 'policy', 'staged', sv) : null;
    const fp = `${av}|${sv}|${nonStaged?.digest ?? '-'}|${stagedAnchor?.digest ?? '-'}|${stagedAnchor?.activate_at ?? '-'}|${anchors === null}|${stagedMeta ? (stagedMeta.activate_at <= now) + (stagedMeta.policy.expires_at > now ? '2' : '1') : '0'}`;
    const hit = this._suiteAllowCache.get(t);
    if (hit?.fp === fp) return hit.allowed;
    let allowed = null;
    try { allowed = this.policy(t).algorithms?.allowed_suites; }
    catch (e) {
      if (e?.code !== 'INV-409-INTEGRITY') throw e;
      // policy() fails closed on two honest windows: genesis bootstrap
      // (the signing calls that write the constitution's own anchors) and
      // the activation transaction (the 'active' row already carries the
      // staged successor while its POLICY_ACTIVATED anchor is still
      // uncommitted). Enforce against anchor-VERIFIED content in both —
      // the row that matches a real anchor, or verbatim genesis with no
      // anchors at all (w28-crypto F8).
      // The index itself may be the reason policy() failed — a corrupt or
      // missing chain-head wedges the fold while the flush that heals it
      // needs this very signature. Unresolvable anchors degrade to 'no
      // authoritative constitution consultable', which is already
      // fail-closed on every policy-gated path (w28-regression w25/w27).
      let anchors = [];
      try { anchors = [...this._auditIndex(t).policyAnchors].reverse(); } catch { /* wedged fold — anchor data unreachable */ }
      const nonStaged = anchors.find(a => !a.staged), stagedAnchor = anchors.find(a => a.staged);
      const active = this.store.get(t, 'policy', 'active'), staged = this.store.get(t, 'policy', 'staged');
      const activeD = active && digest(active), stagedD = staged && digest(staged.policy);
      if (activeD && nonStaged && activeD === nonStaged.digest) allowed = active.algorithms?.allowed_suites;
      else if (activeD && stagedAnchor && activeD === stagedAnchor.digest) allowed = active.algorithms?.allowed_suites;
      else if (stagedD && stagedAnchor && stagedD === stagedAnchor.digest) allowed = staged.policy.algorithms?.allowed_suites;
      else {
        const genesis = this.#tenants[t]?.genesis_policy;
        if (activeD && genesis && activeD === digest(genesis) && !nonStaged && !stagedAnchor) allowed = genesis.algorithms?.allowed_suites;
        // Fully divergent: no anchor-verified constitution is resolvable —
        // remediation signing (reanchorPolicy) must stay reachable to
        // repair it, but the gate must never degrade to "any suite": only
        // the vault-bound audit key's own suite may sign while the
        // constitution is unverifiable (w29-fixverify F11).
        else {
          const boundSuite = this.vault.keys.get(this.tenant(t).keys?.audit?.key_id)?.suite;
          allowed = boundSuite ? [boundSuite] : [];
        }
      }
    }
    this._suiteAllowCache.set(t, { fp, allowed });
    return allowed;
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
    const [iid, identity] = Object.entries(this.tenant(t).identities).find(([, v]) => v.subject_id === p.subject_id) ?? [];
    requireThat(identity?.roles?.includes('security'), 'INV-403-ROLE', 'Role denied for security', 403);
    (this.#sealing ??= new Set()).add(t);
    // A refusal thrown mid-seal still speaks the watermark tamper evidence
    // it carries — the attestation otherwise only rides the result shapes
    // (w39-seal F-10).
    try { return this._sealAuditChain(p, t, iid); }
    catch (e) { if (e instanceof InvariantError && this.#wmTamper.size) e.details = { ...(e.details ?? {}), ...this.#wmTamperAttest(t) }; throw e; }
    finally { this.#sealing.delete(t); }
  }
  _sealAuditChain(p, t, iid) {
    // A config-revoked principal must not seal either — the frozen identity
    // set still knows that flag even when the chain is unreadable
    // (w25-clock F-7).
    requireThat(!this.tenant(t).identities[iid]?.revoked, 'INV-403-QUARANTINE', 'A revoked identity cannot seal the audit chain', 403);
    const keys = this.auditPublicKeys(t);
    const rows = this.store._stmt('SELECT seq,previous,hash,envelope FROM audit WHERE tenant=? ORDER BY seq').all(t);
    // The seal scan enforces the same signing window the index does — a row
    // signed by a key the chain already killed (revoke or audit-class
    // rotation) is poison, not a verifiable leaf: otherwise a dead-key row
    // would verify, the seal would find nothing to cut, and the index
    // would stay wedged forever (w16-fixverify F3). Revocations seen on the
    // consumed prefix are also collected: an operator whose own revocation
    // is already on-chain cannot truncate the ledger that attests it
    // (w16-fixverify F10).
    const keyDeadAt = new Map(), revokedSeen = new Set(), auditSuccessions = new Map();
    // Seal-residue bookkeeping for the F-H recount below: surviving seals'
    // attested page counts and per-class carry totals, and the surviving
    // pages bound to each seal seq.
    const sealClaims = new Map(), carrySeen = new Map();
    // A verified carry page bound to a SURVIVING seal but stored on the
    // doomed span still counts toward that seal's claim — the seal writes
    // it back verbatim (bound to the original seal_seq) before commit so
    // the post-seal recount sees exactly the binding it claims
    // (w49-seal F1).
    const carryRestores = [];
    // Surviving anchors bind floor-row content too: a revocation floor row
    // whose AUTHORITY_REVOKED anchor survives below the cut must prove its
    // stored bytes against that anchor's record_digest — not land in
    // floor_derived, and not pass with planted content (w36-fixverify L-2).
    const revDigests = new Map();
    // The scan must enforce the same acceptance rules as the fold — a row
    // that verifies here but violates the fold's future-time bound would be
    // reported "already verifies" while _auditIndex wedges: signed poison
    // the seal could never cut (w17-fixverify).
    const consumeNow = this.clock();
    let previous = '0'.repeat(64), firstBad = null, prevPlTime = 0, prevPlSeq = 0;
    for (const r of rows) {
      let ok = false, env = null;
      try {
        env = JSON.parse(r.envelope);
        const kid = env?.protected?.key_id, deadAt = kid !== undefined ? keyDeadAt.get(kid) : undefined;
        // The stored `previous` column joins the check — every append
        // writes it yet nothing compared it, so stored-column surgery on
        // it would pass unnamed (w49-seal LOW).
        ok = ctEqual(digest(env.payload), r.hash) && env.payload.sequence === r.seq && ctEqual(env.payload.previous, previous) && r.previous === previous
          && !(deadAt !== undefined && deadAt < r.seq)
          && (typeof env.payload.time !== 'number' || env.payload.time <= Math.max(consumeNow, prevPlTime) + 60_000)
          && verifySigned(env, keys, 'audit').tenant_id === t;
      } catch { ok = false; }
      if (!ok) { firstBad = r.seq; break; }
      previous = r.hash;
      prevPlTime = Math.max(prevPlTime, typeof env.payload.time === 'number' ? env.payload.time : prevPlTime);
      prevPlSeq = env.payload.sequence;
      const meta = env.payload.metadata ?? {};
      if (env.payload.type === 'AUTHORITY_REVOKED') {
        revokedSeen.add(env.payload.reference);
        if (typeof meta.record_digest === 'string' && typeof env.payload.reference === 'string') revDigests.set(env.payload.reference, meta.record_digest);
        if (typeof env.payload.reference === 'string' && env.payload.reference.startsWith('key:')) keyDeadAt.set(env.payload.reference.slice(4), Math.min(keyDeadAt.get(env.payload.reference.slice(4)) ?? Infinity, r.seq));
      }
      // Revocations a surviving seal/carrier row re-attested count as seen
      // — a carried revocation enforces the same gate on the caller that a
      // raw AUTHORITY_REVOKED does (w33-seal O-1).
      // Surviving seals unfold BOTH carry classes into the death window
      // the same way the fold does: a 'key:' carried revocation and a
      // carried audit-class KEY_ROTATED each pin their key's death at the
      // carrying row — without them the prescan accepts rows the fold
      // would refuse (w36-seal F-B).
      if ((env.payload.type === 'AUDIT_SEALED' || env.payload.type === 'AUDIT_SEAL_CARRY')) {
        for (const rv of Array.isArray(meta.revocations_carryover) ? meta.revocations_carryover : [])
          // floor_derived entries are unverifiable claims — they still
          // enforce in idx.revoked, but a planted floor row promoted
          // through a surviving seal must never aim the caller gate or
          // fake a key death (w38-store F-2).
          if (rv?.floor_derived !== true && typeof rv?.reference === 'string') {
            revokedSeen.add(rv.reference);
            // Carried deaths pin at orig_seq like the fold — pinning at
            // the carrying row's seq lets the prescan accept rows the
            // fold itself refuses (w48-crypto F-w48-3).
            if (rv.reference.startsWith('key:')) keyDeadAt.set(rv.reference.slice(4), Math.min(keyDeadAt.get(rv.reference.slice(4)) ?? Infinity, typeof rv.orig_seq === 'number' ? rv.orig_seq : r.seq));
          }
        for (const lc of Array.isArray(meta.lifecycle_carryover) ? meta.lifecycle_carryover : [])
          if (lc?.type === 'KEY_ROTATED' && lc?.metadata?.key_class === 'audit' && typeof lc.metadata.previous_key_id === 'string') {
            keyDeadAt.set(lc.metadata.previous_key_id, Math.min(keyDeadAt.get(lc.metadata.previous_key_id) ?? Infinity, typeof lc.orig_seq === 'number' ? lc.orig_seq : r.seq));
            // The carried rotation's attested successor survives as a
            // repoint candidate — the seal's carry re-attests its
            // designation (w47-seal F-3).
            if (typeof lc.reference === 'string') auditSuccessions.set(lc.reference, lc.metadata.previous_key_id);
          }
      }
      // Seal-residue bookkeeping: every surviving seal attests a page
      // count and per-class carry totals; pages bind by seal_seq. An
      // amputated page is destroyed attested authority — refuse every
      // remediation path instead of healing the shortfall (w36-seal F-H).
      if (env.payload.type === 'AUDIT_SEALED') sealClaims.set(r.seq, { pages: typeof meta.carryover_pages === 'number' ? meta.carryover_pages : 0, totals: meta.carryover_totals ?? null, sums: { spend: Array.isArray(meta.spend_carryover) ? meta.spend_carryover.length : 0, access: Array.isArray(meta.access_carryover) ? meta.access_carryover.length : 0, revocations: Array.isArray(meta.revocations_carryover) ? meta.revocations_carryover.length : 0, capabilities: Array.isArray(meta.capabilities_cut) ? meta.capabilities_cut.length : 0, lifecycle: Array.isArray(meta.lifecycle_carryover) ? meta.lifecycle_carryover.length : 0 } });
      if (env.payload.type === 'AUDIT_SEAL_CARRY' && typeof meta.seal_seq === 'number') {
        const pg = carrySeen.get(meta.seal_seq) ?? { count: 0, sums: { spend: 0, access: 0, revocations: 0, capabilities: 0, lifecycle: 0 } };
        pg.count++;
        pg.sums.spend += (Array.isArray(meta.spend_carryover) ? meta.spend_carryover.length : 0); pg.sums.access += (Array.isArray(meta.access_carryover) ? meta.access_carryover.length : 0); pg.sums.revocations += (Array.isArray(meta.revocations_carryover) ? meta.revocations_carryover.length : 0); pg.sums.capabilities += (Array.isArray(meta.capabilities_cut) ? meta.capabilities_cut.length : 0); pg.sums.lifecycle += (Array.isArray(meta.lifecycle_carryover) ? meta.lifecycle_carryover.length : 0);
        carrySeen.set(meta.seal_seq, pg);
      }
      if (env.payload.type === 'KEY_ROTATED' && meta.key_class === 'audit' && meta.previous_key_id) {
        keyDeadAt.set(meta.previous_key_id, Math.min(keyDeadAt.get(meta.previous_key_id) ?? Infinity, r.seq));
        auditSuccessions.set(env.payload.reference, meta.previous_key_id); // newest last, keyed by new key
      }
    }
    // Seal-residue enforcement runs on every path — cut or re-anchor. A
    // page doomed AND verifiable is re-carried by the cut (its content is
    // not lost), so it counts toward the seal's claim; a page destroyed
    // outright can never be honestly re-attested (w36-seal F-H).
    const checkSealResidue = () => {
      for (const [sealSeq, claim] of sealClaims) {
        const seen = carrySeen.get(sealSeq) ?? { count: 0, sums: { spend: 0, access: 0, revocations: 0, capabilities: 0, lifecycle: 0 } };
        requireThat(seen.count === claim.pages, 'INV-409-INTEGRITY', `Audit seal at seq ${sealSeq} attests ${claim.pages} carryover page(s) but only ${seen.count} survive — restore the amputated carry before remediating`, 409);
        // Classes the historical seal never attested are absent — a
        // pre-totals-class seal must not wedge remediation (w38-store F-3).
        if (claim.totals) for (const cls of ['spend', 'access', 'revocations', 'capabilities', 'lifecycle'])
          if (claim.totals[cls] !== undefined)
            requireThat(claim.sums[cls] + seen.sums[cls] === claim.totals[cls], 'INV-409-INTEGRITY', `Audit seal at seq ${sealSeq} attests ${claim.totals[cls]} carried ${cls} entr(ies) but only ${claim.sums[cls] + seen.sums[cls]} survive — restore the amputated carry before remediating`, 409);
      }
      // A surviving page bound to a seal row that does not exist at all is
      // destruction of the seal itself. A page bound to a DOOMED seal
      // (seal_seq >= firstBad, when a cut is running) is legitimate — its
      // seal's content is being re-carried by this very remediation.
      for (const [sealSeq] of carrySeen)
        requireThat(sealClaims.has(sealSeq) || (firstBad !== null && sealSeq >= firstBad), 'INV-409-INTEGRITY', 'Audit carryover page references a seal row that does not exist', 409);
    };
    // The revoked-caller refusal binds BOTH paths — a subject whose own
    // revocation is on-chain must not clear the wedge on the early return
    // any more than it may cut the chain (w21-fixverify H-3).
    const callerRefs = [`subject:${p.subject_id}`, `key:${iid}`, ...(this.tenant(t).identities[iid]?.device_id ? [`device:${this.tenant(t).identities[iid].device_id}`] : [])];
    requireThat(!callerRefs.some(ref => revokedSeen.has(ref)), 'INV-403-QUARANTINE', 'A revoked identity cannot seal the audit chain', 403);
    // The signed head is consulted on BOTH paths: a cut that mints a fresh
    // head over regressed residue launders the destruction the head
    // attested (w36-fixverify HIGH-1).
    const head = this._chainHead(t);
    if (firstBad === null) {
      // Carryover pages a surviving seal attested must still all exist — a
      // missing page is destroyed attested authority, not a re-anchor
      // opportunity (w36-seal F-H). Refuse before the head reconciliation
      // can attest a healed chain over the amputation.
      checkSealResidue();
      // The ledger itself verifies but the signed watermark may not cover
      // the tip (deleted or replayed chain-heads.json — w25-clock F-4,
      // w25-fixverify W25-01). Re-anchor the verified tip under a signed
      // AUDIT_HEAD_REANCHORED event — the append's own flush writes the
      // fresh head envelope.
      const tip = rows.at(-1);
      let headReanchored = false, wmReanchored = false, abandonedHead = null;
      // Repairs below erase the live tamper flag — snapshot it first so
      // the report can name what the repair fixed, not just what remains
      // (w40-fv F-5: a flag cleared by its own repair must still be
      // attested once).
      const preTamper = this.#wmTamper.has(t) ? { ...this.#wmTamper.get(t) } : null;
      const wmAttested = () => {
        const seen = new Set(), out = [];
        for (const e of [preTamper && { tenant_id: t, kind: preTamper.kind, ...(preTamper.seq !== undefined ? { seq: preTamper.seq } : {}) }, ...(this.#wmTamperAttest(t).head_watermark_tampered ?? [])])
          if (e && !seen.has(e.kind)) { seen.add(e.kind); out.push(e); }
        return out.length ? { head_watermark_tampered: out } : {};
      };
      // A genuinely-signed head attesting rows that no longer exist is
      // DELETION residue, not a stale watermark: repairing it under the
      // 'chain already verifies' framing is exactly how a tail-delete gets
      // laundered into silence — deleted RUNTIME_ALLOWED/DATA_ACCESSED/
      // AUTHORITY_REVOKED events evaporate with zero trace (w34-runtime
      // F-1). The re-anchor must attest the abandoned head's own claims —
      // and REFUSE when those claims regressed (floor rows deleted along
      // with their anchors), because the residue floor can then never be
      // honestly re-minted.
      if (head && head !== 'corrupt' && tip && (head.seq > tip.seq || (head.seq === tip.seq && !ctEqual(head.hash, tip.hash)))) {
        requireThat(!(head.revocations !== undefined && this.store.ids(t, 'revocation', 1_000_000).length < head.revocations), 'INV-409-INTEGRITY', 'Signed head attests a revocation floor that regressed — restore the deleted rows before re-anchoring', 409);
        requireThat(!(head.checkpoints !== undefined && this._verifiedCheckpointCount(t) < head.checkpoints), 'INV-409-INTEGRITY', 'Signed head attests audit checkpoints that regressed — restore them before re-anchoring', 409);
        if (head.checkpoint) requireThat(this._checkpointAttested(t, head.checkpoint), 'INV-409-INTEGRITY', 'Signed head attests an audit checkpoint that no longer verifies', 409);
        abandonedHead = { abandoned_head_seq: head.seq, abandoned_head_hash: head.hash };
      } else if (!tip && head && head !== 'corrupt' && head.seq > 0)
        // The whole attested chain is gone — there is nothing honest to
        // re-anchor to.
        requireThat(false, 'INV-409-INTEGRITY', 'Signed head attests rows that no longer exist — restore from backup', 409);
      // Floor rows no surviving anchor attests: a planted revocation row
      // wedges floorCheck while this path reports health — name the
      // unanchored refs so the verdict is a diagnosis, not an all-clear
      // (w34-fixverify L-6, w34-runtime F-3 C1).
      const floorDivergent = this.store.ids(t, 'revocation', 1_000_000).filter(id => !revokedSeen.has(id)).slice(0, 512);
      // A durable watermark left ABOVE the committed tip — the
      // seal-window crash gap or an inflated head-watermark.json — must
      // be repairable here, or the tenant wedges INV-409 on every fold
      // while seal reports 'chain already verifies' (w32-store F-2/F-3).
      // The chain just proved itself to this exact tip, so re-anchoring
      // the floor at the tip is the one honest downward move.
      const wmNow = this._headWatermark(t);
      if (tip && wmNow !== undefined && wmNow > tip.seq) {
        // The signed floor is being moved DOWN — the claim "the chain once
        // stood at seq wmNow" is destroyed. Attest the abandoned watermark
        // exactly as a head regression is attested, or a rolled chain
        // reseals silently (w39-seal F-2).
        const abandonedWm = this._readHeadWatermark()?.[t];
        // Mint the attestation only when the floor actually moved — a
        // signed AUDIT_WM_REANCHORED over a write that never landed
        // claims a repair the durable file never took (w41-seal F3).
        if (this._bumpHeadWatermark(t, tip.seq, { reanchor: true })) {
          this.store.audit(t, 'AUDIT_WM_REANCHORED', p.subject_id, 'audit', { reanchored_tip_seq: tip.seq, abandoned_watermark_seq: wmNow, abandoned_watermark_signed: abandonedWm !== null && typeof abandonedWm === 'object' && abandonedWm?.envelope !== undefined }, this.clock());
          wmReanchored = true;
        }
      }
      else if (tip && wmNow !== undefined && wmNow < tip.seq) {
        // A floor BELOW the verified tip is a replay or a strip — the
        // floor only advances honestly, so re-anchor it forward to the
        // tip the scan just proved and name the regressed position
        // (w40-fv F-2).
        if (this._bumpHeadWatermark(t, tip.seq, { reanchor: true })) {
          // The superseded value is named, not accused: wmNow < tip.seq
          // is just as often the ordinary crash gap between the last
          // commit and the watermark write as it is an attacker replay —
          // 'superseded' is the honest label (w43-seal naming LOW).
          this.store.audit(t, 'AUDIT_WM_REANCHORED', p.subject_id, 'audit', { reanchored_tip_seq: tip.seq, superseded_watermark_seq: wmNow }, this.clock());
          wmReanchored = true;
        }
      }
      if (tip && !(head && head !== 'corrupt' && head.seq === tip.seq && ctEqual(head.hash, tip.hash))) {
        const now = this.clock();
        // A 'corrupt' verdict means committed rows exist without a
        // verifiable head — the residue claims are destroyed evidence,
        // not absent ones. Name the loss inside the re-anchor event so
        // repairing the tip can never read as a clean mint
        // (w38-fixverify F-1).
        this.store.audit(t, 'AUDIT_HEAD_REANCHORED', p.subject_id, 'audit', { reanchored_tip_seq: tip.seq, reanchored_tip_hash: tip.hash, ...(abandonedHead ?? {}), ...(head === 'corrupt' ? { prior_head_unverifiable: true } : {}) }, now);
        // Report only what actually landed: the head write raced a peer's
        // monotone compare before — claiming a re-anchor the file never
        // took was the lie that let a wedged tenant report healed
        // (w27-chainheads F0).
        const newTip = this.store._stmt('SELECT seq,hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get(t);
        const moved = this._chainHead(t);
        headReanchored = moved && moved !== 'corrupt' && newTip && moved.seq === newTip.seq && ctEqual(moved.hash, newTip.hash);
      }
      // A wedge planted by an integrity cause clears only when the SAME
      // set of causes re-proves clean — a cert-only sweep clearing over a
      // still-divergent capsule row is the same lie the wedge exists to
      // deny, and a clear must land on the signed ledger, not just in a
      // return value (w21-fixverify H-2/H-3, L-1).
      if (this._clockUnverifiable(t)) {
        const sweep = this._wedgeIntegrity(t);
        if (sweep.ok) {
          const now = this.clock();
          // The recovery that flagged this tenant let every expired-window
          // authority resurrect silently — a clear that names none of them
          // launders it (w45-runtime F1). Name what came back, computed
          // against attested chain time like recoverClock's veto span.
          let resurrected = [];
          try { resurrected = this._resurrectedAuthorities(t, this._auditIndex(t), now); } catch { /* fold fresh-failed: sweep verdict stands, name nothing */ }
          this.store.tx(() => { this.store.audit(t, 'AUDIT_WEDGE_CLEARED', p.subject_id, 'audit', { sealed_at_seq: null, cleared_by: p.subject_id, resurrected: resurrected.slice(-512).reverse(), resurrected_total: resurrected.length }, now); });
          this.#auditIdx?.delete(t);
          // The flag may live only on the chain (restart, no in-memory set)
          // — clear whichever representation exists (w25-clock F-5).
          this._clockRecoveryUnverifiable?.delete(t);
          return { sealed: false, reason: 'chain already verifies', unverifiable_cleared: true, resurrected_total: resurrected.length, ...wmAttested(), ...(floorDivergent.length ? { floor_divergent: floorDivergent } : {}) };
        }
        return { sealed: false, reason: `unverifiable state persists (${sweep.detail ?? 'fold failure'}) — repair the divergent rows and reseal`, ...wmAttested(), ...(floorDivergent.length ? { floor_divergent: floorDivergent } : {}) };
      }
      return { sealed: false, reason: abandonedHead ? 'audit chain regressed below the signed head — abandoned tip attested' : 'chain already verifies', head_reanchored: headReanchored, watermark_reanchored: wmReanchored, ...(abandonedHead ? { head_regressed: true, ...abandonedHead } : {}), ...wmAttested(), ...(floorDivergent.length ? { floor_divergent: floorDivergent } : {}) };
    }
    let repointUndo = null, activated = null, clearUnverifiable = false;
    try {
      const out = this.store.tx(() => {
      const now = this.clock();
      // Suspend and restore the guards inside one transaction — if the
      // recreate fails the delete rolls back with it.
      // SQLite trigger names are attacker-shaped strings — interpolate
      // unquoted and a file-writer's planted trigger name is a raw SQL
      // payload inside this privileged transaction (w28-store F1).
      for (const tr of this.store._stmt("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
        this.store.db.exec(`DROP TRIGGER "${String(tr.name).replace(/"/g, '""')}"`);
      // Attest what the DELETE actually removes, computed INSIDE the
      // transaction — rows appended between the pre-scan and the cut are
      // destroyed too and must be named in the signed record
      // (w17-redteam B1).
      // `removed` is computed after the payload-doomed evaluation below —
      // it names the same set the DELETE destroys (w34-runtime F-2).
      // Spend authority must survive remediation: the cut span's verifiable
      // RUNTIME_ALLOWED/DATA_ACCESSED events are re-attested inside the
      // AUDIT_SEALED record (w31-runtime F-1). A capability whose
      // CAPABILITY_ISSUED anchor is cut is named in capabilities_cut —
      // consume() requires the issuance anchor, so it can never ride a
      // provable envelope it no longer has.
      const carrySpend = [], carryAccess = [], capsCut = [], carryRevoked = [], carryLifecycle = [], droppedEvents = [];
      let droppedEventsOverflow = 0;
      // Carry dedup: a doomed event and a doomed seal re-attesting it can
      // coexist in one span — a (capability,request) spend, an access row
      // and a revocation each count once (w33-seal).
      const spendKeys = new Set(), accessKeys = new Set(), revokedKeys = new Set();
      const addSpend = u => { const k = `${u.capability}:${u.request_id}`; if (!spendKeys.has(k)) { spendKeys.add(k); carrySpend.push(u); } };
      // Two disclosures differing ONLY in columns/request_id/wedged flags
      // are distinct evidence — a dedup key that collapses them silently
      // drops signed coverage (w34-runtime F-4, w34-fixverify L-5).
      const addAccess = a => { const k = `${a.subject}|${a.dataset}|${a.at}|${a.certificate_id}|${JSON.stringify(a.row_ids)}|${JSON.stringify(a.columns)}|${a.request_id}|${a.wedged}|${a.gate_denied}`; if (!accessKeys.has(k)) { accessKeys.add(k); carryAccess.push(a); } };
      const addRevoked = rv => { if (typeof rv?.reference !== 'string' || revokedKeys.has(rv.reference)) return; revokedKeys.add(rv.reference); carryRevoked.push(rv); };
      // capabilities_cut names refs, not events — a cap both doomed and
      // re-carried by a doomed seal is still cut only once
      // (w34-fixverify L-7).
      const capKeys = new Set();
      const addCap = c => { if (typeof c !== 'string' || capKeys.has(c)) return; capKeys.add(c); capsCut.push(c); };
      // Lifecycle entries dedup the same way: an event a prior seal already
      // re-attested is re-carried exactly once — array projections (denials,
      // coverage replay, policy anchors) would otherwise double-count
      // (w34-composite CRITICAL-1).
      const lifecycleKeys = new Set();
      const addLifecycle = lc => { const k = `${lc.type}|${lc.reference}|${lc.time}|${digest(lc.metadata ?? {})}`; if (!lifecycleKeys.has(k)) { lifecycleKeys.add(k); carryLifecycle.push(lc); } };
      let doomedSnapshotSeen = false;
      // Doomed means the PAYLOAD claims a sequence at/past firstBad — the
      // stored seq/hash columns are attacker-writable, so gating carry on
      // `digest(payload)===r.hash && payload.sequence===r.seq` let a
      // file-writer evict authentic signed events from the carryover and
      // launder a spend refund, un-burn a request id, or un-revoke an
      // authority (w34-runtime F-2). Every row is evaluated by envelope
      // truth: signature, tenant binding, payload sequence ≥ firstBad
      // (the anti-replay bind — a grafted copy of a SURVIVING event
      // claims its original seq and is excluded), the dead-key window
      // and the future-time bound. Rows whose stored columns diverge
      // from their payload are carried AND counted — the divergence is
      // evidence. Payload-seq gaps the deleted rows can no longer name
      // are attested as deleted_gaps.
      const doomedVerified = [], doomedRevDigests = new Map();
      let divergentStored = 0;
      // The classification reads the table INSIDE this transaction — the
      // prescan snapshot is already stale: a verified peer append (or
      // attacker surgery) landing between the prescan and the cut is
      // destroyed or carried by exactly the set this loop sees, never by
      // what existed minutes ago (w41-seal F1: a verified peer event
      // silently deleted would launder its spend authority).
      const cutRows = this.store._stmt('SELECT seq,hash,envelope FROM audit WHERE tenant=? ORDER BY seq').all(t);
      // livedUntil records the furthest time a SIGNATURE-VERIFIED doomed row
      // attests the gate believed it had reached. A verified payload's time
      // is signed by the vault-bound audit key — present in the table it
      // attests forward-living (or forward-believing), even when the fold's
      // consume-time bound still must cut the row itself (w42-runtime F2).
      // Unverifiable rows stay clay: their time claims never lift it. The
      // horizon is transitive: a doomed seal's own meta.lived_until is the
      // same attestation carried one generation forward — dropping it on a
      // reseal would silently erase the resurrection horizon (w43-seal F-1).
      let livedUntil = 0;
      for (const r of cutRows) {
        let pl = null, unverifiedType = null, futureVerified = null;
        try {
          const env = JSON.parse(r.envelope), kid = env?.protected?.key_id, deadAt = kid !== undefined ? keyDeadAt.get(kid) : undefined;
          unverifiedType = typeof env?.payload?.type === 'string' ? env.payload.type : null;
          if (typeof env?.payload?.sequence === 'number' && env.payload.sequence >= firstBad
            && !(deadAt !== undefined && deadAt < env.payload.sequence)
            && verifySigned(env, keys, 'audit').tenant_id === t) {
            if (typeof env.payload.time === 'number') livedUntil = Math.max(livedUntil, env.payload.time);
            const sm = env.payload.metadata;
            if ((env.payload.type === 'AUDIT_SEALED' || env.payload.type === 'AUDIT_SEAL_CARRY') && typeof sm?.lived_until === 'number')
              livedUntil = Math.max(livedUntil, sm.lived_until);
            if (typeof env.payload.time !== 'number' || env.payload.time <= Math.max(consumeNow, prevPlTime) + 60_000) {
              pl = env.payload;
              if (env.payload.sequence !== r.seq || !ctEqual(digest(env.payload), r.hash)) divergentStored++;
            } else {
              // Verified signature but beyond the fold's time bound: the row
              // still lifts the horizon (its time is signed), yet its
              // semantic content cannot be re-attested — the drop entry must
              // name the bindings the signature proves were destroyed so an
              // operator can re-issue deliberately (w43-seal F-2).
              const fm = env.payload.metadata ?? {};
              futureVerified = { reference: env.payload.reference ?? null, request_id: fm.request_id ?? null, at: env.payload.time };
            }
          }
        } catch { /* unverifiable rows are why the seal runs */ }
        // A doomed row that fails re-verification can never be re-attested —
        // but the seal must NAME what it destroyed: removed hashes alone tell
        // nobody *what* authority died, so a laundered replay would be
        // invisible (w34-composite CRITICAL-1). Entries carry seq+hash plus
        // the envelope's own (unverified) type claim as a hint.
        if (pl) doomedVerified.push({ pl, storedSeq: r.seq });
        else if (r.seq >= firstBad) droppedEvents.push({ seq: Number.isInteger(r.seq) ? r.seq : null, hash: r.hash, ...(Number.isInteger(r.seq) ? {} : { stored_seq: String(r.seq).slice(0, 64) }), ...(unverifiedType ? { type_hint: unverifiedType } : {}), ...(futureVerified ? { verified_future: true, ...futureVerified } : {}) });
      }
      // Carry in payload order — the causal issue order the fold replays —
      // even when stored columns were rewritten to scramble positions.
      doomedVerified.sort((a, b) => a.pl.sequence - b.pl.sequence);
      // Deleted rows name themselves only by the hole they leave: payload
      // sequence gaps among the verifiable doomed events (and between the
      // last verified prefix row and the first doomed one) attest rows
      // that were destroyed before the seal ran (w34-runtime F-2).
      const deletedGaps = [];
      // deletedGapsTotal counts RANGES; deletedRowsTotal counts the rows
      // those ranges destroyed. A deleted row is destroyed and
      // unre-verifiable exactly like a dropped one — it must feed the
      // same worst-case INV-429 budget, or DELETE becomes a quieter
      // corruption flavor that keeps the reconstruction gate open
      // (w39-seal F-3/F-9). Rows physically present inside a gap (the
      // doomed-but-unverifiable flavor already tallied in dropped_events)
      // are subtracted so no row is attested twice.
      const presentInGap = this.store._stmt('SELECT COUNT(*) c FROM audit WHERE tenant=? AND seq BETWEEN ? AND ?');
      let gapFrom = prevPlSeq, deletedGapsTotal = 0, deletedRowsTotal = 0;
      for (const { pl } of doomedVerified) {
        if (pl.sequence > gapFrom + 1) { deletedGapsTotal++; deletedRowsTotal += (pl.sequence - 1 - gapFrom) - presentInGap.get(t, gapFrom + 1, pl.sequence - 1).c; if (deletedGaps.length < 64) deletedGaps.push([gapFrom + 1, pl.sequence - 1]); }
        gapFrom = Math.max(gapFrom, pl.sequence);
      }
      // The tail beyond the last verifiable doomed payload names its seq
      // span but contributes NOTHING to the destroyed-row total: the
      // stored tip is attacker-shaped (a planted row at seq 1e6 mints a
      // 999,993-row claim into a signed record — w41-seal F5), so only
      // gaps bounded by verified payloads attest magnitudes; every
      // physical row inside the tail range is already named under
      // dropped_events.
      const preDeleteMax = this.store._stmt('SELECT COALESCE(MAX(seq),0) m FROM audit WHERE tenant=?').get(t).m;
      if (preDeleteMax > gapFrom) { deletedGapsTotal++; if (deletedGaps.length < 64) deletedGaps.push([gapFrom + 1, preDeleteMax]); }
      for (const { pl } of doomedVerified) {
        const meta = pl.metadata ?? {};
        if (pl.type === 'RUNTIME_ALLOWED') addSpend({ capability: pl.reference, subject: pl.actor, resource: meta.resource ?? null, request_id: meta.request_id ?? null, cost: typeof meta.cost === 'number' && meta.cost >= 0 ? meta.cost : 0, at: pl.time });
        else if (pl.type === 'DATA_ACCESSED') addAccess({ subject: pl.reference, dataset: meta.dataset, row_ids: meta.row_ids ?? [], columns: meta.columns ?? [], at: meta.at ?? pl.time, certificate_id: meta.certificate_id ?? null, request_id: meta.request_id ?? null, wedged: meta.wedged === true, gate_denied: meta.gate_denied === true, journal_missing: meta.journal_missing === true });
        else if (pl.type === 'CAPABILITY_ISSUED') addCap(pl.reference);
        // A verifiable doomed revocation is CARRIED, never rescinded: the
        // seal must not silently un-revoke what it cannot disprove —
        // including the sealing caller's own revocation (w32-seal F-5).
        else if (pl.type === 'AUTHORITY_REVOKED' && typeof pl.reference === 'string') { addRevoked({ reference: pl.reference, kind: meta.kind ?? null, id: meta.id ?? null, at: pl.time, orig_seq: pl.sequence }); if (typeof meta.record_digest === 'string') doomedRevDigests.set(pl.reference, meta.record_digest); }
        // CONFIG_SNAPSHOT/REASSERTED feed doomedSnapshotSeen (the repoint
        // rule) AND the lifecycle carry — the fold's configSnapshot baseline
        // must survive the cut too.
        else if (pl.type === 'CONFIG_SNAPSHOT' || pl.type === 'CONFIG_REASSERTED') { doomedSnapshotSeen = true; addLifecycle({ type: pl.type, reference: pl.reference ?? null, actor: pl.actor ?? null, time: pl.time ?? null, orig_seq: pl.sequence, metadata: meta }); }
        // A second seal cutting below a prior seal (or its carry pages)
        // must carry the carryover forward — the authority a seal already
        // re-attested can never be silently dropped by the next one.
        else if (pl.type === 'AUDIT_SEALED' || pl.type === 'AUDIT_SEAL_CARRY') {
          // A doomed carry page bound to a SURVIVING seal keeps that seal's
          // attestation honest — its content re-carries into this seal, so
          // the residue recount below still finds it (w36-seal F-H).
          if (pl.type === 'AUDIT_SEAL_CARRY' && typeof meta.seal_seq === 'number' && sealClaims.has(meta.seal_seq)) {
            const pg = carrySeen.get(meta.seal_seq) ?? { count: 0, sums: { spend: 0, access: 0, revocations: 0, capabilities: 0, lifecycle: 0 } };
            pg.count++;
            pg.sums.spend += (Array.isArray(meta.spend_carryover) ? meta.spend_carryover.length : 0); pg.sums.access += (Array.isArray(meta.access_carryover) ? meta.access_carryover.length : 0); pg.sums.revocations += (Array.isArray(meta.revocations_carryover) ? meta.revocations_carryover.length : 0); pg.sums.capabilities += (Array.isArray(meta.capabilities_cut) ? meta.capabilities_cut.length : 0); pg.sums.lifecycle += (Array.isArray(meta.lifecycle_carryover) ? meta.lifecycle_carryover.length : 0);
            carrySeen.set(meta.seal_seq, pg);
            // The surviving seal's claim already counts this page — the
            // seal writes it back verbatim under the same seal_seq before
            // commit so the post-seal recount sees the binding it claimed
            // (w49-seal F1).
            carryRestores.push({ reference: pl.reference ?? null, actor: pl.actor, metadata: meta });
          }
          for (const u of meta.spend_carryover ?? []) addSpend(u); for (const a of meta.access_carryover ?? []) addAccess(a); for (const c of meta.capabilities_cut ?? []) addCap(c); for (const rv of meta.revocations_carryover ?? []) addRevoked(rv); for (const lc of meta.lifecycle_carryover ?? []) addLifecycle(lc); for (const de of meta.dropped_events ?? []) droppedEvents.push(de); droppedEventsOverflow += Math.max(0, (meta.carryover_totals?.dropped_events ?? (Array.isArray(meta.dropped_events) ? meta.dropped_events.length : 0)) - (Array.isArray(meta.dropped_events) ? meta.dropped_events.length : 0));
        }
        // Every other verifiable doomed event — proposals, evidence,
        // approvals, certificate issuance, reservations, dispatches,
        // outcomes, releases, compensations, cancels, grants, rotations,
        // policy anchors, coverage, ceremonies, denials — is re-attested as
        // a lifecycle carry entry so the rebuilt fold keeps enforcing the
        // destroyed anchors (spent certs stay spent, cancelled stay dead,
        // composite children stay bound). Without this the seal was a
        // laundering oracle (w34-composite CRITICAL-1).
        else addLifecycle({ type: pl.type, reference: pl.reference ?? null, actor: pl.actor ?? null, time: pl.time ?? null, orig_seq: pl.sequence, metadata: meta });
      }
      // Every surviving seal's attested carry residue must survive the cut
      // intact-or-re-carried: a page destroyed outright is unrecoverable
      // attested authority, and re-anchoring over it launders the
      // amputation (w36-seal F-H).
      checkSealResidue();
      // Mirror tables are attacker-writable and add NOTHING provable: every
      // honest usage/data_access row duplicates a doomed-verified
      // RUNTIME_ALLOWED/DATA_ACCESSED event already carried above, and any
      // row without such an event is phantom by definition. The w32
      // pair-witness bound still let planted rows ride arbitrary
      // cost/request_id/row_ids into the SIGNED carryover — mirrors are
      // simply never admitted (w33-seal F-2/F-3/F-5/F-6).
      // Cutting a span also cuts whatever authority events it held. The
      // revocation floor is a STORED row — a floor row whose anchoring
      // event is unverifiable or destroyed must never be DELETED (that
      // silently un-revoked the authority, including a security caller
      // erasing their own condemnation — w33-seal F-1/F-1b). Every
      // orphaned floor ref instead carries forward with floor_derived:
      // true, so the revocation keeps enforcing and the fold's floorCheck
      // stays satisfied. A planted floor row would brick its ref — that is
      // the fail-closed direction, and planting a floor already wedges
      // floorCheck in live operation.
      const survivingRevoked = new Set();
      for (const r of this.store._stmt('SELECT envelope FROM audit WHERE tenant=? AND seq<?').all(t, firstBad)) {
        try {
          const pl = verifySigned(JSON.parse(r.envelope), keys, 'audit'), m2 = pl?.metadata ?? {};
          if (pl?.type === 'AUTHORITY_REVOKED' && typeof pl.reference === 'string') survivingRevoked.add(pl.reference);
          else if (pl?.type === 'AUDIT_SEALED' || pl?.type === 'AUDIT_SEAL_CARRY')
            for (const rv of Array.isArray(m2.revocations_carryover) ? m2.revocations_carryover : [])
              // floor_derived refs were never anchored — keeping them out
              // of survivingRevoked stops a planted floor promoted by a
              // prior seal from gating the seal caller or re-asserting
              // itself as signed evidence (w38-store F-2).
              if (rv?.floor_derived !== true && typeof rv?.reference === 'string') survivingRevoked.add(rv.reference);
        } catch { /* unverifiable survivors cannot happen — the pre-scan verified them */ }
      }
      // A floor row orphaned of every anchor carries floor_derived —
      // indistinguishable from a planted one, so fail closed and NAME it
      // in the result. But when the doomed span still holds the ref's
      // verifiable anchoring event, its record_digest binds the honest
      // row: a floor row whose content fails that digest is planted
      // tamper, attested under planted_floor_refs — while the anchored
      // revocation itself is still carried by its event (w34-runtime F-3).
      const metaMac = v => createHmac('sha256', this.vault.masterKey).update(canonical(v)).digest('base64url');
      const plantedFloor = [], floorDerived = [];
      for (const floorId of this.store.ids(t, 'revocation', 1_000_000)) {
        // A ref attested by a SURVIVING anchor or surviving seal carryover
        // is enforced already — never re-carried, never floor_derived. But
        // the row's stored bytes still bind that anchor's record_digest:
        // skipping the row must not skip the planted-content check
        // (w36-fixverify L-2).
        if (survivingRevoked.has(floorId)) {
          const survivingDigest = revDigests.get(floorId);
          if (survivingDigest !== undefined) {
            let matches = false;
            try { matches = ctEqual(metaMac(this.store.get(t, 'revocation', floorId)), survivingDigest); } catch { /* undecryptable planted content */ }
            if (!matches) plantedFloor.push(floorId);
          }
          continue;
        }
        const anchoredDigest = doomedRevDigests.get(floorId);
        if (anchoredDigest !== undefined) {
          let matches = false;
          try { matches = ctEqual(metaMac(this.store.get(t, 'revocation', floorId)), anchoredDigest); } catch { /* undecryptable planted content */ }
          if (!matches) plantedFloor.push(floorId);
          continue; // already carried from its verifiable event
        }
        // Only name floor-derived what actually lacks verifiable evidence —
        // a ref already carried by a verifiable doomed anchor (or a prior
        // seal's signed carryover) must not be labelled orphaned
        // (w36-fixverify L-2).
        if (!revokedKeys.has(floorId)) {
          addRevoked({ reference: floorId, kind: null, id: null, at: now, floor_derived: true });
          floorDerived.push(floorId);
        }
      }
      // The planted-floor check is asymmetric by necessity — it sees only
      // floor rows that EXIST. A floor row DELETED while its verifiable
      // anchor still condemned the ref must be named too: enforced, but
      // invisible in revocations() and unreachable by re-anchor
      // (w36-fixverify M-1).
      const murderedFloor = [];
      const nameMurdered = ref => {
        let floorRow; try { floorRow = this.store.get(t, 'revocation', ref); } catch { floorRow = 'unreadable'; }
        // Deleted AND unreadable rows both mean the condemned ref's
        // floor is gone as evidence — a corrupted-to-ciphertext row
        // must not evade naming (w38-fixverify F-3). A digested anchor
        // already convicted its content under planted_floor_refs —
        // don't name the same row twice.
        if ((floorRow === null || floorRow === 'unreadable') && !plantedFloor.includes(ref)) murderedFloor.push(ref);
      };
      for (const rv of carryRevoked) {
        if (rv.floor_derived === true) continue;
        nameMurdered(rv.reference);
      }
      // A ref whose SURVIVING anchor still condemns it while its floor row
      // was deleted is murdered all the same — the anchor was never cut,
      // so carryRevoked never saw it (w36-fixverify M-1).
      for (const ref of survivingRevoked) nameMurdered(ref);
      // Mirror rows are never carried — but their residue is NAMED, never
      // silently ignored: a corrupted anchor erases the spend/disclosure
      // evidence its mirror duplicated, and the signed seal must record
      // what it declined to re-attest so the refund surfaces as evidence
      // rather than silence (w33-fixverify F-1). Bounded by construction:
      // at most MIRROR_SAMPLE entries are named; the full count is always
      // attested. Naming is evidence, not authority — a planted row gets
      // named as dropped residue, never trusted.
      const droppedMirrors = [];
      let droppedMirrorCount = 0;
      const MIRROR_SAMPLE = 512;
      for (const u of this.store._stmt('SELECT subject, resource, at, cost, capability, request FROM usage WHERE tenant=?').all(t)) {
        droppedMirrorCount++;
        if (droppedMirrors.length < MIRROR_SAMPLE) droppedMirrors.push({ table: 'usage', capability: u.capability, request: u.request, subject: u.subject, cost: u.cost, at: u.at });
      }
      for (const a of this.store._stmt('SELECT subject, dataset, row_id, column_name, at FROM data_access WHERE tenant=?').all(t)) {
        droppedMirrorCount++;
        if (droppedMirrors.length < MIRROR_SAMPLE) droppedMirrors.push({ table: 'data_access', subject: a.subject, dataset: a.dataset, row_id: a.row_id, column: a.column_name, at: a.at });
      }
      // Revocation carried from any VERIFIABLE source — surviving chain,
      // doomed span, a prior seal's carryover — binds the sealer too: a
      // revoked actor cannot seal away the record that revokes them
      // (w32-seal F-5, w33-seal F-1b/O-1). floor_derived refs are
      // different: they carry no signed evidence at all, so letting them
      // gate the caller would let a single planted `records` row aim the
      // refusal at whichever operator runs the repair — the carry keeps
      // them enforcing in idx.revoked and the result names them, but an
      // unverifiable claim may not brick the sealer (w34-fixverify H-2,
      // w34-runtime F-3 C2/C3).
      const revokedKept = new Set([...survivingRevoked, ...carryRevoked.filter(r => !r.floor_derived).map(r => r.reference)]);
      requireThat(!callerRefs.some(ref => revokedKept.has(ref)), 'INV-403-QUARANTINE', 'A revoked identity cannot seal the audit chain', 403);
      // A carried 'key:' revocation — verifiable inside the doomed span —
      // must also reach the signing death window before the repoint
      // check: otherwise the consumed revocation never triggers the
      // repoint and the seal's own write hits the vault-flag divergence
      // (w33-fixverify F-4). floor_derived refs are excluded: they carry
      // no signed evidence, so they steer the repoint directly (below)
      // but never pin a death window — the same exemption the fold
      // applies at foldApply (w44-seal F-3).
      for (const rv of carryRevoked)
        if (rv.reference.startsWith('key:') && !rv.floor_derived) keyDeadAt.set(rv.reference.slice(4), Math.min(keyDeadAt.get(rv.reference.slice(4)) ?? Infinity, firstBad));
      // A doomed audit-class KEY_ROTATED riding lifecycle carryover kills
      // its predecessor exactly like foldApply replays it — leaving it out
      // of the death window lets the seal sign its own carry pages under a
      // key this very seal condemns: dead-signed pages that wedge the fold
      // permanently (w36-seal F-B).
      for (const lc of carryLifecycle)
        if (lc?.type === 'KEY_ROTATED' && lc?.metadata?.key_class === 'audit' && typeof lc.metadata.previous_key_id === 'string') {
          keyDeadAt.set(lc.metadata.previous_key_id, Math.min(keyDeadAt.get(lc.metadata.previous_key_id) ?? Infinity, firstBad));
          // The carried rotation's attested SUCCESSOR stays a legal
          // repoint target too: it was chain-designated by a verified row
          // the doomed span condemned — the carry preserves that
          // attestation, so the repoint must see it or a live signer goes
          // invisible and the seal dies deterministic INV-503 (w47-seal F-3).
          if (typeof lc.reference === 'string') auditSuccessions.set(lc.reference, lc.metadata.previous_key_id);
        }
      // Install the pending-carry tolerance BEFORE the delete/repoint
      // section — the repoint block re-folds mid-seal (ceremonyDesignated,
      // the CONFIG_SNAPSHOT audit write's signer resolution) and without
      // this the kept floor rows trip floorCheck while the seal is still
      // assembling (w33-fixverify F-3). Cleared in the finally below on
      // every path.
      this.#sealCarry.set(t, new Set(carryRevoked.map(r => r.reference)));
      // Designations written on the doomed span can never be seen by the
      // mid-seal refold (ceremonyDesignated folds only surviving rows):
      // evaluate every pending key's ceremony designation against the raw
      // chain facts NOW, before the doomed-row delete erases them
      // (w49-seal F3). A rescan failure shrinks the set, never widens it —
      // the post-delete fold remains the authority.
      const designatedBeforeCut = new Set();
      try {
        const facts = this._chainFacts(t);
        const neededP = this._keyPurposes.audit ?? ['audit'];
        for (const [kid, e] of this.vault.keys.entries()) {
          if (!e.pending || e.revoked || e.generated_inside === false || facts.dead.has(kid)) continue;
          if (!this.ownsVaultKey(t, kid)) continue;
          if (!(e.purpose === 'any' || neededP.every(x => (Array.isArray(e.purpose) ? e.purpose : [e.purpose]).includes(x)))) continue;
          if (this._auditDesignationHolds(facts, t, kid)) designatedBeforeCut.add(kid);
        }
      } catch { /* rescan is advisory — the post-delete fold still decides */ }
      let removed = [], sealSeq = firstBad, abandonedHead = null;
      try {
      // Doom is payload-defined (w34-runtime F-2): the cut covers every
      // stored row at/past firstBad AND any verified-doomed row whose
      // stored seq was rewritten below the cut — a survivor whose stored
      // column disagrees with its signed sequence would wedge the rebuilt
      // fold permanently.
      const doomedStored = new Set();
      for (const r of this.store._stmt('SELECT seq FROM audit WHERE tenant=? AND seq>=?').all(t, firstBad)) doomedStored.add(r.seq);
      for (const v of doomedVerified) doomedStored.add(v.storedSeq);
      removed = this.store._stmt(`SELECT seq,hash FROM audit WHERE tenant=? AND seq IN (SELECT value FROM json_each(?)) ORDER BY seq`).all(t, JSON.stringify([...doomedStored])).map(r => r.hash);
      this.store._stmt('DELETE FROM audit WHERE tenant=? AND seq IN (SELECT value FROM json_each(?))').run(t, JSON.stringify([...doomedStored]));
      // A planted same-name trigger on a sibling table would make the bare
      // CREATE below die mid-statement — sqlite trigger names are global,
      // not table-scoped. Drop our names first: the guards are fixed schema
      // (a stray carrying our name is exactly what the open-time sweep and
      // text check exist to refuse), and a collide-then-wedge would leave
      // the audit table permanently unprotected (w47-seal F-2).
      this.store.db.exec(`
        DROP TRIGGER IF EXISTS no_audit_update;
        DROP TRIGGER IF EXISTS no_audit_delete;
        DROP TRIGGER IF EXISTS audit_seq_guard;
        CREATE TRIGGER no_audit_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
        CREATE TRIGGER no_audit_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
        CREATE TRIGGER audit_seq_guard BEFORE INSERT ON audit
          WHEN NEW.seq <> (SELECT COALESCE(MAX(seq),0)+1 FROM audit WHERE tenant=NEW.tenant)
          BEGIN SELECT RAISE(ABORT, 'audit sequence must extend the head'); END;`);
      // The signed head's residue claims bind the cut path too — the
      // no-cut branch refuses when floor/checkpoint attestations regressed
      // because the residue can never be honestly re-minted; minting a
      // FRESH head over the same regression on the cut path was the w35
      // hole (w36-fixverify HIGH-1).
      if (head && head !== 'corrupt') {
        requireThat(!(head.revocations !== undefined && this.store.ids(t, 'revocation', 1_000_000).length < head.revocations), 'INV-409-INTEGRITY', 'Signed head attests a revocation floor that regressed — restore the deleted rows before sealing', 409);
        requireThat(!(head.checkpoints !== undefined && this._verifiedCheckpointCount(t) < head.checkpoints), 'INV-409-INTEGRITY', 'Signed head attests audit checkpoints that regressed — restore them before sealing', 409);
        if (head.checkpoint) requireThat(this._checkpointAttested(t, head.checkpoint), 'INV-409-INTEGRITY', 'Signed head attests an audit checkpoint that no longer verifies', 409);
      }
      // A head attesting doomed-or-deleted rows is abandoned, not
      // contradicted — attest it on the seal record exactly like the
      // re-anchor path does, so the tail's disappearance is on the signed
      // ledger instead of silently overwritten by the fresh head
      // (w36-fixverify HIGH-1).
      const postTip = this.store._stmt('SELECT seq,hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get(t);
      // Every attested row may be gone (postTip undefined): the seal still
      // re-anchors — from genesis — but the head it leaves behind is named
      // on the signed record, exactly like a partial cut (w36-fixverify
      // HIGH-1). Residue claims that can never be honestly re-minted
      // (revocation floor, checkpoints) already refused above.
      abandonedHead = head && head !== 'corrupt' && (!postTip || head.seq > postTip.seq || (head.seq === postTip.seq && !ctEqual(head.hash, postTip.hash)))
        ? { abandoned_head_seq: head.seq, abandoned_head_hash: head.hash }
        : null;
      // Deleted chain-heads.json must not pass the residue consult
      // silently: the signature-bound floor/checkpoint claims are gone
      // with the file, so nothing can refuse them — but the seal record
      // itself must attest that the prior attestation was destroyed,
      // turning the wipe from silent un-binding into named evidence
      // (w38-fixverify F-1).
      if (head === 'corrupt') abandonedHead = { ...(abandonedHead ?? {}), prior_head_unverifiable: true };
      // The seal row itself must survive the signing window it just
      // enforced: when the consumed prefix killed the configured audit key,
      // repoint onto the newest chain-attested successor before sealing —
      // otherwise AUDIT_SEALED would be the next dead-key row it should
      // have cut (w16-fixverify F3).
      const tenant = this.tenant(t), configuredAudit = tenant.keys?.audit?.key_id;
      // A floor-derived 'key:' claim names a revocation the row level
      // already enforces — the configured signer must not attest the seal
      // under it, and the repoint must not land on another claimed key
      // (w43-seal floor-pin LOW). It never pins a death window, so a
      // planted floor can only steer selection, never fake a window.
      // floorRefs only fill from a PRIOR seal's carry unfold — this seal's
      // own floor_derived key claims live in carryRevoked and must join the
      // steering set or the repoint silently stops seeing them (w44
      // regression: fold-derived claims must steer, never pin).
      const floorKeyClaims = new Set(this._chainFacts(t).floorRefs);
      for (const rv of carryRevoked) if (rv?.floor_derived === true && typeof rv?.reference === 'string' && rv.reference.startsWith('key:')) floorKeyClaims.add(rv.reference.slice(4));
      if (configuredAudit === undefined || keyDeadAt.has(configuredAudit) || floorKeyClaims.has(configuredAudit)) {
        const needed = this._keyPurposes?.audit ?? [];
        // The attested-succession arm is a repoint onto a VAULT key: it
        // must satisfy the same ownership and purpose gates the
        // un-attested fallback below requires — a chain-attested
        // succession naming a foreign-vault or purpose-less key id is no
        // repoint target (w48-fixverify LOW parity).
        let successor = [...auditSuccessions.keys()].reverse().find(k => {
          const e = this.vault.keys.get(k);
          return e && !e.revoked && e.generated_inside !== false && !keyDeadAt.has(k) && !floorKeyClaims.has(k)
            && this.ownsVaultKey(t, k)
            && (e.purpose === 'any' || needed.every(x => (Array.isArray(e.purpose) ? e.purpose : [e.purpose]).includes(x)));
        });
        // No chain-attested succession (the key was revoked without a
        // rotation event): fall back to the newest live pending tenant-owned
        // vault key that covers the audit purposes — a revoke-without-rotate
        // must not leave the chain unsealable while a valid signer waits in
        // the vault (w17-fixverify).
        if (!successor)
          successor = [...this.vault.keys.entries()].reverse().find(([kid, e]) => e.pending && !e.revoked
            && e.generated_inside !== false && !keyDeadAt.has(kid) && !floorKeyClaims.has(kid) && this.ownsVaultKey(t, kid)
            && (e.purpose === 'any' || needed.every(x => (Array.isArray(e.purpose) ? e.purpose : [e.purpose]).includes(x)))
            && (designatedBeforeCut.has(kid) || this.ceremonyDesignated(t, kid, 'audit')))?.[0];
        // Name the blockers: a planted floor-derived 'key:' ref can aim
        // this refusal at the configured signer — the operator must see
        // exactly which carried claims demand the repoint so the runbook
        // can point at the planted row (w34-fixverify H-2, w34-runtime
        // F-3 C3).
        requireThat(successor, 'INV-503-CONFIG', `No live audit signing key can attest the seal${configuredAudit !== undefined ? ` — configured signer ${configuredAudit} is ${floorKeyClaims.has(configuredAudit) && !keyDeadAt.has(configuredAudit) ? 'floor-claimed by an unverifiable revocation row' : 'dead or missing'}` : ''}; carried key deaths: ${[...keyDeadAt.keys()].slice(0, 16).join(', ') || 'none'}${floorKeyClaims.size ? `; floor-claimed: ${[...floorKeyClaims].slice(0, 16).join(', ')}` : ''}`, 503);
        const entry = this.vault.keys.get(successor);
        const wasPending = entry.pending, savedTenant = this.tenant(t);
        if (entry.pending) { this.vault.activate(successor); activated = successor; }
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
        // Same rule as _reconcileLedger: a null baseline is free only when
        // the chain never carried one — and a baseline this seal just cut
        // must not re-mint either (w32-fixverify F-2).
        if ((anchoredBaseline.digest === null && !anchoredBaseline.sawSnapshotRow && !anchoredBaseline.sawSeal && !doomedSnapshotSeen) || digest({ tenant: t, sections: preSections }) === anchoredBaseline.digest) {
          const postSections = this._configSections(this.tenant(t));
          this.store.audit(t, 'CONFIG_SNAPSHOT', p.subject_id, 'config', { config_digest: digest({ tenant: t, sections: postSections }) }, now);
          this.store.put(t, 'config-snapshot', 'current', { digest: digest({ tenant: t, sections: postSections }), taken_at: now, sections: postSections }, now);
        }
      }
      // Carryover is bounded by construction, never by luck: a carryover
      // larger than the canonical envelope limits would abort the seal
      // mid-transaction and leave the wedge unsealable forever (w33-seal
      // F-4). The head carries at most CARRY_PAGE entries per array; the
      // overflow lands on signed AUDIT_SEAL_CARRY pages chained to the
      // seal's own seq.
      const CARRY_PAGE = 512;
      const carryPages = [];
      for (let off = CARRY_PAGE; off < Math.max(carrySpend.length, carryAccess.length, carryRevoked.length, capsCut.length, carryLifecycle.length); off += CARRY_PAGE)
        carryPages.push({ spend_carryover: carrySpend.slice(off, off + CARRY_PAGE), access_carryover: carryAccess.slice(off, off + CARRY_PAGE), revocations_carryover: carryRevoked.slice(off, off + CARRY_PAGE), capabilities_cut: capsCut.slice(off, off + CARRY_PAGE), lifecycle_carryover: carryLifecycle.slice(off, off + CARRY_PAGE) });
      // Carry pages the cut destroyed but a surviving seal still claims are
      // re-minted verbatim under their original seal_seq — the claim's
      // recount must see the binding intact-or-restored, not silently
      // amputated (w49-seal F1). They append AFTER this seal's own pages so
      // the fold's seal_seq binding is preserved on every surviving claim.
      const restorePages = carryRestores.map(rc => ({ reference: rc.reference, actor: rc.actor, metadata: rc.metadata }));
      // The pages must bind the seal's ACTUAL assigned sequence, not the
      // nominal firstBad: the repoint's interposed CONFIG_SNAPSHOT takes
      // firstBad itself, sliding the seal to firstBad+1 and leaving every
      // page unbound at the fold's seal_seq check — a seal that permanently
      // wedges the chain it just repaired (w36-seal F-A).
      // The cut span's attested time horizon survives the cut: the veto
      // span recoverClock may consult extends only as far as the chain
      // itself attests the gate lived — a forged-high clock row can never
      // stretch the resurrection veto past this bound (w42-runtime F2).
      // sealed_at_seq names the chain's expected cut position — the signed
      // payload sequence past the last verifiable row — never firstBad's
      // stored-column value: a row with a rewritten stored seq must not
      // shape the seal's own attestation (w49-seal F2). On a contiguous
      // honest chain the two are identical.
      const sealWrite = this.store.audit(t, 'AUDIT_SEALED', p.subject_id, 'audit', { sealed_at_seq: prevPlSeq + 1, removed_count: removed.length, removed_head: removed[0] ?? null, removed_tail: removed.at(-1) ?? null, lived_until: livedUntil || null, spend_carryover: carrySpend.slice(0, CARRY_PAGE), access_carryover: carryAccess.slice(0, CARRY_PAGE), capabilities_cut: capsCut.slice(0, CARRY_PAGE), revocations_carryover: carryRevoked.slice(0, CARRY_PAGE), lifecycle_carryover: carryLifecycle.slice(0, CARRY_PAGE), carryover_pages: carryPages.length, carryover_totals: { spend: carrySpend.length, access: carryAccess.length, revocations: carryRevoked.length, capabilities: capsCut.length, lifecycle: carryLifecycle.length, mirrors_dropped: droppedMirrorCount, dropped_events: droppedEvents.length + droppedEventsOverflow, deleted_events: deletedRowsTotal, divergent_stored: divergentStored, deleted_gaps_total: deletedGapsTotal }, dropped_mirrors: droppedMirrors, dropped_events: droppedEvents.slice(0, CARRY_PAGE), deleted_gaps: deletedGaps.slice(0, 64), planted_floor_refs: plantedFloor.slice(0, 512), floor_derived: floorDerived.slice(0, 512), murdered_floor_refs: murderedFloor.slice(0, 512), ...(abandonedHead ?? {}) }, now);
      sealSeq = sealWrite?.envelope?.payload?.sequence ?? firstBad;
      for (let i = 0; i < carryPages.length; i++)
        this.store.audit(t, 'AUDIT_SEAL_CARRY', p.subject_id, 'audit', { seal_seq: sealSeq, page: i + 1, ...carryPages[i] }, now);
      // Doomed carry pages a surviving seal still claimed are restored
      // verbatim under their original seal_seq — amputated, they would
      // leave the claim's recount finding fewer pages than attested
      // (w49-seal F1). The restore marks itself honestly so the ledger
      // shows the re-mint happened, never claiming an unbroken lineage.
      for (const rc of restorePages)
        this.store.audit(t, 'AUDIT_SEAL_CARRY', p.subject_id, 'audit', { ...rc.metadata, restored_from_doomed_span: true, restored_actor: rc.actor ?? null }, now);
      }
      finally { this.#sealCarry.delete(t); }
      this.#auditIdx?.delete(t);
      clearUnverifiable = true;
      // The operator who signs unverifiable authority must SEE it: the
      // result names every floor-derived ref promoted into the signed
      // record, every planted row convicted by digest, and the carryover
      // totals — never a bare sealed:true over attacker-chosen claims
      // (w34-fixverify H-2/L-4, w34-runtime F-3).
      return { sealed: true, sealed_at_seq: firstBad, seal_seq: sealSeq, removed_count: removed.length, carryover_totals: { spend: carrySpend.length, access: carryAccess.length, revocations: carryRevoked.length, capabilities: capsCut.length, lifecycle: carryLifecycle.length, mirrors_dropped: droppedMirrorCount, dropped_events: droppedEvents.length + droppedEventsOverflow, deleted_events: deletedRowsTotal, divergent_stored: divergentStored, deleted_gaps_total: deletedGapsTotal, deleted_rows_total: deletedRowsTotal }, floor_derived: floorDerived.slice(0, 512), planted_floor_refs: plantedFloor.slice(0, 512), murdered_floor_refs: murderedFloor.slice(0, 512), deleted_gaps: deletedGaps.slice(0, 64), ...this.#wmTamperAttest(t), ...(abandonedHead ?? {}) };
      });
      // The seal committed through store.tx — the repoint's ledger binding
      // is durable, so post-commit faults can no longer claim the ledger
      // rejected it: the in-memory repoint and vault activation stay.
      repointUndo = null;
      // A post-commit flush fault is retried on the next transaction edge —
      // the pending heads were re-buffered by restore(); the committed seal
      // is never reported back as denied (w28-store F5, w28-fixverify F5).
      this._flushChainHeadsGuarded();
      // Post-commit durability: the repoint's ledger binding committed,
      // so the vault activation must persist now — a restart that sees the
      // config repoint but a still-pending vault key bricks every
      // audit-emitting operation with INV-401-SIGNATURE (w19-lifecycle F4).
      // In-memory bookkeeping likewise applies only once the tx committed
      // (w19-lifecycle F8). A persist fault here must NOT undo the repoint —
      // memory would diverge from the committed ledger — and must not skip
      // the wedge clear: the seal the flag waited for landed. The fault is
      // reported on the result so the operator sees durability is pending
      // (w20-fixverify F-5).
      // persistVault failure must NOT clear the wedge — the seal landed
      // but durability is pending; keep the flag honest and say so on the
      // result (w21-fixverify M-5).
      try { if (activated) this.persistVault(); }
      catch (persistErr) {
        return { ...out, wedge_cleared: false, vault_persist_error: persistErr instanceof Error ? persistErr.message : String(persistErr) };
      }
      // The cut path must re-prove the SAME integrity set the no-cut path
      // requires: a still-divergent anchored row (missing cert/capsule,
      // dead-key residue) keeps the wedge honestly — claiming 'cleared'
      // while it fails is the lie the wedge exists to deny (w32-seal F-6).
      const sealSweep = this._wedgeIntegrity(t);
      // The clock-recovery wedge clears whenever the chain verified and the
      // seal committed — its condition is resolved. Residual anchored-row
      // divergence is a different class: reported honestly via wedge_cleared
      // and still screamed per-access by _mustAnchored/_certSpendIntegrity
      // rather than bricking the tenant (w32-seal F-6, w19-F8b).
      if (clearUnverifiable) this._clockRecoveryUnverifiable?.delete(t);
      // The head write inside this seal's scope can regress only because
      // the pending heads carried reanchor — verify it actually landed:
      // 'sealed' with a stale watermark is a still-wedged tenant, not a
      // success report (w27-chainheads F0).
      const sealedTip = this.store._stmt('SELECT seq,hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get(t);
      // The durable watermark must move backward WITH the seal — the one
      // sanctioned re-anchor; otherwise every subsequent fold wedges on
      // durable-wm > committed-head forever (w28-fixverify F1). Honored
      // only while #sealing holds this tenant.
      if (sealedTip) this._bumpHeadWatermark(t, sealedTip.seq, { reanchor: true });
      const sealedHead = this._chainHead(t);
      const sealedWm = this._headWatermark(t);
      const sealedMoved = sealedHead && sealedHead !== 'corrupt' && sealedTip && sealedHead.seq === sealedTip.seq && ctEqual(sealedHead.hash, sealedTip.hash)
        && (sealedWm === undefined || sealedWm <= sealedTip.seq);
      return { ...out, wedge_cleared: clearUnverifiable && sealSweep.ok && sealedMoved === true, head_reanchored: sealedMoved === true, ...(sealSweep.ok ? {} : { integrity_detail: sealSweep.detail }) };
    } catch (sealErr) {
      // Any fault inside the repoint window — activation, the re-anchor
      // snapshot, the seal row itself — must undo the in-memory repoint:
      // memory may never claim a binding the ledger rejected. The cached
      // index can hold phantom-consumed rows folded inside the aborted tx,
      // so it is dropped unconditionally — the next read rebuilds from the
      // committed head (w18-fixverify F10/F11).
      repointUndo?.(); this.#auditIdx?.delete(t); throw sealErr;
    }
  }
  // Wedged-tenant test that survives restart: the in-memory flag covers the
  // session that flagged it, the anchored CLOCK_RECOVERED carries it across
  // reboots (w25-clock F-5). A tenant whose index cannot fold right now is
  // unverifiable by definition — but a fold failure must still surface as
  // its own INV-409 downstream, so we fall back to the in-memory flag only.
  _clockUnverifiable(t) {
    if (this._clockRecoveryUnverifiable?.has(t)) return true;
    try { return this._auditIndex(t).clockUnverifiable === true; } catch { return false; }
  }
  // The EXACT integrity causes recoverClock wedges on — fold failure,
  // anchored cert rows missing/unverifiable, anchored capsule rows missing
  // or divergent. sealAuditChain's clear re-proves all of them through
  // this single implementation so no cause can slip past the clear
  // (w21-fixverify H-2). Returns {ok, detail} for an honest refusal reason.
  _wedgeIntegrity(tenant, idx = null) {
    try { idx ??= this._auditIndex(tenant); } catch { return { ok: false, detail: 'fold failure' }; }
    try {
      for (const id of idx.issuedCerts ?? []) {
        let c; try { c = this.store.get(tenant, 'certificate', id); } catch { c = null; }
        requireThat(c, 'INV-503-TIME', 'anchored certificate row missing');
        if (idx.outcomes.has(id) || idx.reserved.has(id)) continue;
        let envOk = false;
        // The envelope must bind THIS row id — a sibling cert's valid
        // envelope transplanted onto this row is not a pass
        // (w21-fixverify L-2).
        try { envOk = verifySigned(c.envelope, this.executionPublic(tenant), 'action-certificate').certificate_id === id; } catch { envOk = false; }
        requireThat(envOk, 'INV-503-TIME', 'anchored certificate envelope does not verify for its row');
      }
      for (const [id, anchoredCapsuleDigest] of idx.proposedDigest ?? []) {
        // A capsule the tenant's own retention sweep shredded is the
        // remediation, not the wound — its tombstone satisfies the sweep
        // (same carve-out _mustAnchored applies, w33-fixverify F-5).
        if (idx.tombstones?.get(id)?.kind === 'capsule') continue;
        let r; try { r = this.store.get(tenant, 'capsule', id); } catch { r = null; }
        requireThat(r && this._capsuleDigestOf(r) === anchoredCapsuleDigest, 'INV-503-TIME', 'anchored capsule row missing or divergent');
      }
      return { ok: true, idx };
    } catch (e) { return { ok: false, detail: e?.message ?? 'integrity failure' }; }
  }
  // The authority set recoverClock's veto protects, enumerated by the same
  // doctrine but collected instead of thrown: entries whose expiry the
  // chain attested as passed (expiry <= attested high-water) yet lies ahead
  // of the current (possibly rewound) clock are the ones a recovery
  // resurrected. sealAuditChain names them in AUDIT_WEDGE_CLEARED so a
  // clear never launders a silent resurrection (w45-runtime F1).
  _resurrectedAuthorities(tenant, idx, now) {
    const resurrected = [];
    const attestedMax = Math.max(idx.prevPlTime ?? 0, idx.livedUntil ?? 0);
    const inSpan = exp => typeof exp === 'number' && exp > now && exp <= attestedMax;
    const get = (kind, id) => { try { return this.store.get(tenant, kind, id); } catch { return null; } };
    for (const id of idx.issuedCerts ?? []) {
      if (idx.outcomes.has(id) || idx.reserved.has(id) || this.revoked(tenant, 'certificate', id)) continue;
      if (inSpan(get('certificate', id)?.envelope?.payload?.expires_at)) resurrected.push({ kind: 'certificate', id });
    }
    for (const [id] of idx.proposedDigest ?? []) {
      const certId = idx.issuedCert.get(id);
      if (certId && (idx.outcomes.has(certId) || idx.reserved.has(certId))) continue;
      if ((idx.cancelled ?? new Set()).has(id) || (certId && (idx.cancelled ?? new Set()).has(certId)) || this.revoked(tenant, 'capsule', id) || (certId && this.revoked(tenant, 'certificate', certId))) continue;
      if (inSpan(idx.proposedExpiry?.get(id) ?? get('capsule', id)?.capsule?.expires_at)) resurrected.push({ kind: 'capsule', id });
    }
    for (const id of idx.capabilities ?? []) {
      if (this.revoked(tenant, 'capability', id)) continue;
      if (inSpan(idx.capabilityMeta?.get(id)?.expires_at ?? get('capability', id)?.payload?.expires_at)) resurrected.push({ kind: 'capability', id });
    }
    for (const [grantId, gm] of idx.grantMeta ?? [])
      if (!this.revoked(tenant, 'grant', grantId) && inSpan(gm.expires_at)) resurrected.push({ kind: 'grant', id: grantId });
    for (const [sid, s] of idx.perceptionSessions ?? [])
      if (!this.revoked(tenant, 'perception-session', sid) && inSpan(s.expires_at)) resurrected.push({ kind: 'perception-session', id: sid });
    for (const [keyId, idn] of Object.entries(this.tenant(tenant).identities ?? {}))
      if (!idn.revoked && !this.revoked(tenant, 'key', keyId) && !this.revoked(tenant, 'device', idn.device_id) && !this.revoked(tenant, 'subject', idn.subject_id) && inSpan(idn.health_expires_at)) resurrected.push({ kind: 'device-health', id: keyId });
    for (const [hash, entry] of Object.entries(this.tenant(tenant).auth ?? {}))
      if (!this.revoked(tenant, 'token', hash) && inSpan(entry.expires_at)) resurrected.push({ kind: 'token', id: hash });
    return resurrected;
  }
  recoverClock(p) {
    this.authorize(p, ['security', 'policy_admin']);
    return this.store.tx(() => {
      const now = this.clock();
      const prior = this.store._stmt('SELECT last FROM clock WHERE id=1').get()?.last ?? null;
      const unverifiable = [];
      // The mutable clock row can be rewound by a raw UPDATE — forging a
      // LOW last would shrink the resurrection span the veto scans. The
      // effective prior therefore unions the mutable last with every
      // tenant's chain-anchored event time: the ledger remembers how far
      // forward we actually went, and a faked last cannot erase that
      // (w25-clock F-1).
      let anchoredLast = 0;
      const tenantIdx = new Map();
      for (const tenant of Object.keys(this.#tenants)) {
        try { const idx = this._auditIndex(tenant); tenantIdx.set(tenant, idx); anchoredLast = Math.max(anchoredLast, idx.prevPlTime ?? 0, idx.livedUntil ?? 0); }
        catch { /* fold failure: flagged unconditionally below */ }
      }
      // A sabotaged tenant's horizon can never join anchoredLast, so a
      // rewind crossing only ITS horizon produces no veto run — and under
      // the old in-loop flagging the tenant was never named at all
      // (w45-runtime F1 aggravator). Flag it unconditionally: the recovery
      // anchor must record which tenants it could not verify, whether or
      // not a veto ever fired.
      for (const tenant of Object.keys(this.#tenants))
        if (!tenantIdx.has(tenant)) { unverifiable.push(tenant); (this._clockRecoveryUnverifiable ??= new Set()).add(tenant); }
      // The resurrection veto may only span time the ledger itself attests:
      // `prior` is mutable clay — a forged HIGH last would stretch the veto
      // span across every live authority and dead-lock the recovery it
      // feeds (w42-runtime F2). Expiry is evaluated on host time either
      // way, so nothing beyond `anchoredLast` was ever honestly dead.
      const effectivePrior = Math.min(Math.max(prior ?? 0, anchoredLast), Math.max(anchoredLast, now));
      // A backward step (snapshot restore) is survivable, but never silently:
      // it must not re-open the validity window of any authority that the
      // ledger watched lapse. Any certificate or live-status capsule whose
      // expiry falls inside the rewound span would resurrect — refuse
      // (w9-network F4). Forward steps need no such check.
      if (effectivePrior > 0 && now < effectivePrior) {
        for (const tenant of Object.keys(this.#tenants)) {
          // A tenant whose chain cannot fold cannot prove it has no
          // resurrection candidate — it is blocked alone, never allowed to
          // veto recovery for every other tenant (w18-fixverify F12). It
          // transacts again once sealAuditChain repairs the chain.
          const idx = tenantIdx.get(tenant);
          if (idx === undefined) { if (!unverifiable.includes(tenant)) unverifiable.push(tenant); (this._clockRecoveryUnverifiable ??= new Set()).add(tenant); continue; }
          // Anchored enumeration only: deleting or flag-flipping a mutable
          // row can never launder an expired authority past the veto — a
          // missing or divergent anchored row IS the veto evidence
          // (w18-fixverify F5). Consumption and terminal state likewise
          // read from the fold, never from row flags.
          // Veto evidence is per-tenant isolated, same as the fold above:
          // one tenant's missing or divergent anchored row blocks THAT
          // tenant until sealAuditChain — it must never veto the recovery
          // every other tenant needs to transact again (w19-lifecycle F3).
          try {
            // Integrity causes come from the SAME implementation the
            // wedge-clear re-proves — no subset can pass here and fail
            // the repair path (w21-fixverify H-2).
            requireThat(this._wedgeIntegrity(tenant, idx).ok, 'INV-503-TIME', 'Anchored row integrity check failed');
            // Resurrection vetoes stay here: they need now/prior.
            for (const id of idx.issuedCerts ?? []) {
              if (idx.outcomes.has(id) || idx.reserved.has(id)) continue;
              // A revoked certificate is already dead authority — skipping
              // it keeps a legitimately dead cert from deadlocking the
              // recovery it shouldn't gate (w25-clock F-6).
              if (this.revoked(tenant, 'certificate', id)) continue;
              const c = this.store.get(tenant, 'certificate', id);
              const exp = c.envelope.payload.expires_at;
              requireThat(exp <= now || exp > effectivePrior, 'INV-503-TIME', 'Clock recovery would resurrect an expired certificate', 503);
            }
            for (const [id] of idx.proposedDigest ?? []) {
              const r = this.store.get(tenant, 'capsule', id);
              // Only a certified capsule can dispatch — a proposed-only
              // capsule cannot resurrect, and a terminally-anchored one is
              // spent. Both facts live on the chain, not the mutable status.
              const certId = idx.issuedCert.get(id);
              if (certId && (idx.outcomes.has(certId) || idx.reserved.has(certId))) continue;
              // Cancelled/revoked capsules are anchored-dead too — they can
              // never dispatch again, so a lapsed expiry inside them must
              // not deadlock recovery. A capsule whose certificate is
              // anchored-revoked is equally dead (w25-clock F-6).
              if ((idx.cancelled ?? new Set()).has(id) || (certId && (idx.cancelled ?? new Set()).has(certId)) || this.revoked(tenant, 'capsule', id) || (certId && this.revoked(tenant, 'certificate', certId))) continue;
              // The capsule lifetime is anchored at proposal: a row rolled
              // back to an earlier ciphertext image cannot hide a lapsed
              // expiry (w24-fixverify W24-07).
              const anchoredExp = idx.proposedExpiry?.get(id);
              requireThat((anchoredExp ?? r.capsule.expires_at) <= now || (anchoredExp ?? r.capsule.expires_at) > effectivePrior, 'INV-503-TIME', 'Clock recovery would resurrect an expired action', 503);
              // Approval envelopes inside an UNCERTIFIED live capsule carry
              // a 5-minute expiry — one that lapsed inside the rewound span
              // would silently re-count toward quorum. A certified
              // capsule's approvals are already consumed, so resurrecting
              // them changes nothing (w23 W23-01). The anchored fold
              // survives a rollback to the pre-approval row image; pre-anchor
              // approvals still veto via the mutable list (w24-fixverify
              // W24-07).
              if (!certId) for (const a of [...(idx.approvalExpiry?.get(id) ?? []), ...(r.approvals ?? []).map(x => ({ expires_at: x?.payload?.expires_at }))])
                requireThat(!(typeof a?.expires_at === 'number' && a.expires_at > now && a.expires_at <= effectivePrior), 'INV-503-TIME', 'Clock recovery would resurrect an expired approval', 503);
              // Attached evidence lapses inside the same span and was
              // never scanned — its anchored expiry vetoes resurrection
              // exactly like an approval's (w24-fixverify W24-07).
              if (!certId) for (const ev of [...(idx.evidenceExpiry?.get(id) ?? []), ...(r.evidence ?? []).map(x => {
                // The mutable list carries evidence ROW ids — resolve the
                // row's own signed expires_at, or fall back to a missing
                // expiry that can never veto (w25-fixverify W25-05).
                let evRow = null; try { evRow = this.store.get(tenant, 'evidence', x) ?? null; } catch { evRow = null; }
                return { expires_at: evRow?.envelope?.payload?.expires_at };
              })])
                requireThat(!(typeof ev?.expires_at === 'number' && ev.expires_at > now && ev.expires_at <= effectivePrior), 'INV-503-TIME', 'Clock recovery would resurrect expired evidence', 503);
            }
            // Signed capabilities are bearer authority with an expiry — an
            // un-revoked capability whose window lapsed inside the rewound
            // span resurrects exactly like a certificate (w23 W23-01).
            for (const id of idx.capabilities ?? []) {
              if (this.revoked(tenant, 'capability', id)) continue;
              // The anchored CAPABILITY_ISSUED expiry is the authority —
              // a deleted capability row must never read as "no expiry";
              // its absence is tamper evidence that isolates the tenant
              // (w24-fixverify W24-04).
              const capRow = this.store.get(tenant, 'capability', id);
              requireThat(capRow !== undefined && capRow !== null, 'INV-409-INTEGRITY', 'Anchored capability row is missing from the store', 409);
              const exp = idx.capabilityMeta?.get(id)?.expires_at ?? capRow.payload?.expires_at;
              requireThat(!(typeof exp === 'number' && exp > now && exp <= effectivePrior), 'INV-503-TIME', 'Clock recovery would resurrect an expired capability', 503);
            }
            // JIT grants fold their expiry at anchor time — a grant that
            // lapsed inside the rewound span revives inside the target's
            // scope evaluator (w23 W23-01).
            for (const [grantId, gm] of idx.grantMeta ?? [])
              if (!this.revoked(tenant, 'grant', grantId))
                requireThat(!(typeof gm.expires_at === 'number' && gm.expires_at > now && gm.expires_at <= effectivePrior), 'INV-503-TIME', 'Clock recovery would resurrect an expired grant', 503);
            // Perception sessions carry anchored expiries — one that
            // lapsed in the span would re-open its release/fallback paths
            // (w23 W23-01).
            for (const [sid, s] of idx.perceptionSessions ?? [])
              if (!this.revoked(tenant, 'perception-session', sid))
                requireThat(!(typeof s.expires_at === 'number' && s.expires_at > now && s.expires_at <= effectivePrior), 'INV-503-TIME', 'Clock recovery would resurrect an expired perception session', 503);
            // Device health evidence gates privileged operations through
            // assertHealthy — a configured expiry inside the rewound span
            // resurrects the gate's pass state. Identities whose authority
            // is already dead (revoked key, device or subject) cannot
            // resurrect and never veto (w23 W23-01).
            for (const [keyId, idn] of Object.entries(this.tenant(tenant).identities ?? {}))
              if (!idn.revoked && !this.revoked(tenant, 'key', keyId) && !this.revoked(tenant, 'device', idn.device_id) && !this.revoked(tenant, 'subject', idn.subject_id))
                requireThat(!(typeof idn.health_expires_at === 'number' && idn.health_expires_at > now && idn.health_expires_at <= effectivePrior), 'INV-503-TIME', 'Clock recovery would resurrect expired device health evidence', 503);
            // Bearer access tokens are authority too: an entry whose expiry
            // falls inside the rewound span would resurrect exactly like a
            // certificate. An already-revoked token cannot resurrect — the
            // operator's path out of the veto is to revoke it first
            // (w22-http F6).
            for (const [hash, entry] of Object.entries(this.tenant(tenant).auth ?? {}))
              if (!this.revoked(tenant, 'token', hash))
                requireThat(!(entry.expires_at > now && entry.expires_at <= effectivePrior), 'INV-503-TIME', 'Clock recovery would resurrect an expired access token', 503);
          } catch (err) {
            // Integrity failures (missing, divergent or unverifiable
            // anchored rows) isolate the tenant — but an intact anchored
            // authority whose window genuinely resurrects is real veto
            // evidence for everyone and must keep refusing globally
            // (w9-network F4 kept under w19-lifecycle F3 isolation).
            if (err?.code === 'INV-503-TIME' && /resurrect/.test(err.message)) throw err;
            unverifiable.push(tenant); (this._clockRecoveryUnverifiable ??= new Set()).add(tenant); continue;
          }
        }
      }
      // Recovery records the discontinuity explicitly: prior_last is what
      // the ledger believed, recovered_at is the operator-asserted honest
      // host time. An external verifier sees the jump on the signed chain
      // — time discontinuity is evidence, not silent rewriting (w7-clock F1).
      this.store.clock(now, { recovery: true });
      // prior_last is what the MUTABLE row believed; anchored_last is what
      // the folded chains attest — both recorded so a forged-low clock row
      // still leaves its true rewind span on the signed ledger (w25-clock F-1).
      this.store.audit(p.tenant_id, 'CLOCK_RECOVERED', p.subject_id, 'local-gate', { prior_last: prior, anchored_last: anchoredLast || null, recovered_at: now, regression_ms: effectivePrior > 0 ? effectivePrior - now : 0, unverifiable_tenants: unverifiable }, now);
      // In-memory authority lives outside the store: console sessions minted
      // against the old clock would resurrect in the rewound span. The HTTP
      // layer registers a reaper (w22-http F6).
      this.onClockRecovery?.(now, prior);
      return { recovered_at: now, prior_last: prior, unverifiable_tenants: unverifiable };
    });
  }
  identity(p) {
    const identity = Object.values(this.tenant(p.tenant_id).identities).find(x => x.subject_id === p.subject_id);
    requireThat(identity && !identity.revoked, 'INV-401-AUTH', 'Authentication required', 401); return identity;
  }
  authorize(p, roles, { auditDeny = true } = {}) {
    // An ambient-cookie GET is forged-by-design (<img>/<link> rides the
    // ambient session): minting a signed denial row against the victim
    // from it is unconsented evidence, so the server marks the resolved
    // principal and the mint stays quiet — the denial itself still
    // refuses (w45-http M-1b).
    auditDeny &&= p?._ambient_get !== true;
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
    // The suppression window only covers a FORWARD-looking dedup: a
    // rewound clock must mint fresh evidence, not silently suppress every
    // denial until the memo's stale timestamp passes (w49-runtime W49-2).
    if (last !== undefined && now - last >= 0 && now - last < 60_000) return;
    // The window is consumed only by a write that lands — a failed audit
    // insert must not suppress the next identical denial's evidence
    // (w18-fixverify F14).
    try { this.store.audit(t, 'AUTHORIZATION_DENIED', subject_id ?? 'anonymous', null, { code, message: String(message).slice(0, 200) }, now); this.#denyAudit.set(key, now); } catch { /* ledger write failure does not change the verdict */ }
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
    // Memo on the raw row bytes: an unchanged stored capsule pays its one
    // ECDSA verify + three content digests once — a rewritten row digests
    // to different ciphertext and re-verifies in full, so the memo can
    // never launder a tamper (w44-perf). The capsule id joins the key so
    // a same-bytes transplant lands under its own name.
    const raw = record?.capsule?.capsule_id !== undefined ? this.store._stmt('SELECT value FROM records WHERE tenant=? AND kind=? AND id=?').get(t, 'capsule', record.capsule.capsule_id)?.value : undefined;
    const mk = typeof raw === 'string' ? `ci:${t}:${hashBytes(raw)}` : null;
    if (mk && this.#capsuleIntegrityMemo?.has(mk)) return clone(this.#capsuleIntegrityMemo.get(mk));
    const payload = this.#capsuleIntegrity(t, record);
    if (mk) { this.#capsuleIntegrityMemo ??= new Map(); if (this.#capsuleIntegrityMemo.size >= 4096) this.#capsuleIntegrityMemo.clear(); this.#capsuleIntegrityMemo.set(mk, clone(payload)); }
    return payload;
  }
  #capsuleIntegrity(t, record) {
    const intent = record?.capsule?.request_intent;
    requireThat(intent && typeof intent === 'object', 'INV-409-INTEGRITY', 'Capsule carries no signed request intent', 409);
    const kid = intent?.protected?.key_id, signer = kid ? this.identities(t)[kid] : null;
    requireThat(signer, 'INV-409-INTEGRITY', 'Request intent signed by an unknown identity', 409);
    let payload = null;
    try { payload = verifySigned(intent, { [kid]: { public_key: signer.public_key } }, 'capsule-intent'); } catch { payload = null; }
    requireThat(payload, 'INV-409-INTEGRITY', 'Request intent signature no longer verifies', 409);
    const { request_intent, capsule_id, tenant_id, received_at, ...signedInput } = record.capsule;
    requireThat(digest(payload) === digest(signedInput), 'INV-409-INTEGRITY', 'Stored capsule diverged from the signed request intent', 409);
    requireThat(record.capsule_digest === this._capsuleDigestOf(record), 'INV-409-INTEGRITY', 'Stored capsule digest does not match its contents', 409);
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
    // The journal binding covers composite-child rows too — they carry the
    // same journal_digest commitment, so deleting a child's durable
    // journal screams exactly like a standalone's (w24-lifecycle W24-7).
    if (pl?.status === 'VERIFIED' && pl?.journal_digest) {
      const journal = this.target.outcome(t, pl.certificate_id);
      requireThat(journal && digest(journal) === pl.journal_digest, 'INV-409-INTEGRITY', 'Outcome journal digest does not match the durable dispatch journal', 409);
    }
    // The served row must equal the chain's own attested verdict: a stale
    // post-cancel row or a ciphertext transplant of a superseded verdict
    // is tamper evidence, never a quiet serve (w24-lifecycle W24-6).
    const oidx = this._auditIndex(t);
    // Seal carryover now re-anchors every verifiable EXECUTION_OUTCOME — a
    // served outcome with NO chain anchor at all is unverifiable evidence,
    // not a missing fold: treat it as tamper, never as "no anchor to
    // compare" (w34-composite MEDIUM-2). Composite children anchor through
    // the parent's child_outcomes explode (any status counts — a stored
    // mid-flight row is attested while its parent named it).
    const anchoredStatus = oidx.outcomes.get(pl.certificate_id) ?? oidx.childOutcomeAnchors?.get(pl.certificate_id);
    requireThat(anchoredStatus !== undefined, 'INV-409-INTEGRITY', 'Outcome claims a verdict the signed ledger never attested', 409);
    requireThat(pl.status === anchoredStatus, 'INV-409-INTEGRITY', 'Outcome status contradicts the anchored verdict', 409);
    const anchoredDigest = oidx.outcomeDigests.get(pl.certificate_id);
    if (anchoredDigest) requireThat(digest(envelope) === anchoredDigest, 'INV-409-INTEGRITY', 'Outcome row diverges from the anchored verdict digest', 409);
    return envelope;
  }
  // Mutable lifecycle flags are caches derived from the anchored folds —
  // `consumed` is set atomically with EXECUTION_RESERVED and cleared
  // atomically with EXECUTION_RELEASED, so consumed === reserved.has in
  // every legitimate state. Any divergence is tamper evidence, never a
  // veto the row can cast over the signed chain (w24-lifecycle W24-3).
  _certSpendIntegrity(t, idx, certId, stored) {
    if (stored === undefined) stored = this.store.get(t, 'certificate', certId);
    // Planted spend: the row claims consumption the chain never attested —
    // tamper evidence, never a quiet replay refusal. The reverse
    // direction (flag cleared under a real reservation) needs no scream:
    // every anchored gate already refuses on the fold's word.
    requireThat(!(stored?.consumed === true && !idx.reserved.has(certId) && !idx.outcomes.has(certId)), 'INV-409-INTEGRITY', 'Certificate consumed flag planted where the ledger attests no spend — tamper evidence', 409);
  }
  // Parents binding a capsule through the anchored CERTIFICATE_ISSUED
  // membership map, resolved to the ones still LIVE: a parent cert counts
  // while the chain attests no outcome for it AND it can still legally
  // fire — an expired or revoked parent cert (or a murdered parent row)
  // resolves the binding instead of binding children forever
  // (w24-lifecycle W24-4).
  _boundLiveParents(t, idx, capsuleId, now) {
    return [...idx.parentChildren.keys()].filter(pid => {
      if (!(idx.parentChildren.get(pid) ?? []).includes(capsuleId)) return false;
      const parentCertId = idx.issuedCert.get(pid);
      // Any anchored parent outcome releases the binding — including an
      // UNCERTAIN verdict. Binding children under UNCERTAIN would deadlock:
      // the parent can only reach a terminal verdict by children settling,
      // which itself requires them to execute (w32-composite F-5 resolved
      // by superseding verdicts — the fold's anchored outcome map already
      // denies planted/murdered rows the unbind).
      if (parentCertId === undefined || idx.outcomes.has(parentCertId)) return false;
      // The ledger attests this parent certificate existed — an absent row
      // is destructive tampering, so scream rather than silently unbind the
      // lineage (w25-fixverify W25-02).
      const row = this.store.get(t, 'certificate', parentCertId);
      requireThat(row, 'INV-409-INTEGRITY', 'Anchored parent certificate row is missing', 409);
      try {
        const pp = verifySigned(row.envelope, this.executionPublic(t), 'action-certificate');
        // Signature validity is not enough — the envelope must BE this
        // certificate: a grafted donor envelope (expired but genuinely
        // signed) would silently unbind a live parent's children into
        // solo spends (w29-lifecycle F3). Where the anchor recorded the
        // issued envelope digest the row bytes must match it too.
        requireThat(pp.certificate_id === parentCertId, 'INV-409-INTEGRITY', 'Parent certificate row carries a foreign signed envelope', 409);
        const anchoredCertDigest = idx.issuedCertDigests?.get(parentCertId);
        requireThat(anchoredCertDigest === undefined || digest(row.envelope) === anchoredCertDigest, 'INV-409-INTEGRITY', 'Parent certificate envelope diverges from the anchored issuance', 409);
        return pp.expires_at > now && !this.revoked(t, 'certificate', parentCertId);
      } catch (e) { if (e?.code === 'INV-409-INTEGRITY') throw e; return false; }
    });
  }
  // IDN: JIT grants merge with static identity grants. A grant only ever adds
  // scope already permitted by the runtime policy; it cannot exceed it.
  grantsFor(tenant, subject_id, now) {
    const cfg = this.tenant(tenant);
    const identity = Object.values(cfg.identities).find(x => x.subject_id === subject_id);
    const idx = this._auditIndex(tenant);
    // Attested chain time is the monotone floor for expiry: a grant that
    // any attested row saw die stays dead — a rewound host clock must not
    // resuscitate expired scope the chain already observed pass
    // (w45-seal F-5, w45-runtime F1 family).
    const effNow = Math.max(now, idx.prevPlTime ?? 0);
    // Every input to the honoured-list derivation below is captured in
    // the memo key: the fold view (maxSeq covers incremental appends;
    // revoked/grants sizes cover fold content at a fixed tip), the mutable
    // stores' dirt counters and the heal-window flag. Expiry is applied
    // per call against effNow — the memo holds the pre-expiry honoured
    // list so a real-clock read still hits the anchor/anchor-proof work
    // instead of re-deriving it every millisecond (w47-perf). Identity
    // objects live and die with the tenant config, so a re-attested
    // config holds no stale entries (w45-perf).
    const mk = `${subject_id}|${idx.maxSeq}|${idx.revoked.size}|${idx.grants.size}|${this.store._dirtSeq ?? 0}|${this.target._dirtSeq ?? 0}|${this.#pendingEffects.has(tenant) ? 1 : 0}`;
    const memos = (this._grantsMemo ??= new WeakMap());
    let memo = memos.get(identity ?? cfg);
    const hit = memo?.get(mk);
    const base = hit?.base ?? (identity?.grants ?? { resources: [], actions: [], destinations: [], columns: [], row_ids: [] });
    const honoured = hit?.honoured ?? (() => {
      // Without a single anchored JIT grant every grants-table row fails
      // _grantAnchored outright — skip the decrypt scan instead of paying
      // it per authorize/evaluate (w43-perf). The anchored set still
      // drives the row path below whenever it is nonempty.
      const list = [];
      for (const g of (idx.grants.size ? this.target.grantRows(tenant, subject_id) : [])) {
        // A grants-table row is derived state, never authority: it is
        // honored only when a ledger JIT_GRANT_ISSUED event anchors it —
        // either by scope_digest or, for pre-upgrade grants, by the
        // issuing request's digest with every row field proven equal
        // (w11-redteam R2/R11, w16-fixverify F4). A ledger-revoked grant
        // is dead no matter what the mutable row says — the dataplane
        // flag is a cache; idx.revoked is the authority (w17-idx F2).
        if (g.revoked || idx.revoked.has(`grant:${g.grant_id}`)) continue;
        if (!this._grantAnchored(tenant, idx, g.grant_id, g)) continue;
        list.push(g);
      }
      return list;
    })();
    // CON-008: grant-carried roles merge too — support access confers its
    // operational role ONLY for the grant window; no standing access
    // remains after expiry or revocation. Expiry is filtered here against
    // the caller's effective time — the honoured list is clock-free.
    const merged = { roles: [...(identity?.roles ?? [])], resources: [...base.resources], actions: [...base.actions], destinations: [...base.destinations], columns: [...base.columns], row_ids: [...base.row_ids] };
    // Per-grant authority tuples (w27-policy F1): each honoured grant is
    // an indivisible scope — enforcement tests a selection against ONE
    // tuple, never the flat union, so fields approved for a service
    // cannot launder rows of an unrelated dataset (and vice versa).
    const tuples = [{ resources: base.resources ?? [], actions: base.actions ?? [], destinations: base.destinations ?? [], columns: base.columns ?? [], row_ids: base.row_ids ?? [] }];
    for (const g of honoured) {
      if (g.expires_at <= effNow) continue;
      for (const k of Object.keys(merged)) for (const v of g[k] ?? []) if (!merged[k].includes(v)) merged[k].push(v);
      tuples.push({ resources: g.resources ?? [], actions: g.actions ?? [], destinations: g.destinations ?? [], columns: g.columns ?? [], row_ids: g.row_ids ?? [] });
    }
    // Murdered grant detection: an anchored JIT_GRANT_ISSUED names scope
    // the ledger attests was issued. The issuing jit-grant record lands
    // in-tx before the anchor, so it can never be legitimately missing on
    // a modern (scope_digest) mint — its absence is murder, row or no row
    // (w44-runtime F3). The dataplane grants row is a post-commit effect:
    // its absence is indistinguishable from the heal gap, so it only
    // convicts once no heal is pending and the anchor predates this tx
    // window. Legacy grant_digest-only anchors predate the record kind and
    // stay exempt on the record leg (w15). Expired anchored grants are
    // exempt — expiry is an honest end of life, not evidence.
    for (const gid of idx.grants.keys()) {
      if (idx.revoked.has(`grant:${gid}`)) continue;
      const gm = idx.grantMeta.get(gid);
      if (gm?.expires_at !== undefined && gm.expires_at <= effNow) continue;
      const record = this.store.get(tenant, 'jit-grant', gid);
      // The row's mere existence is not life — a murdered grants row is
      // ciphertext written by a writer who can INSERT gibberish but not
      // encrypt: decrypt-verifying under the grant AAD separates a live
      // row from a forged one, and a forgery counts as murder, not as the
      // heal exemption (w49-runtime W49-1).
      const rowCt = this.target._schemaGuard(() => this.target._stmt('SELECT value FROM grants WHERE tenant=? AND grant_id=?').get(tenant, gid)?.value);
      let row = false;
      if (rowCt !== undefined && rowCt !== null) {
        try { this.target._dec(rowCt, tenant, canonical(['target', 'grant', tenant, gid])); row = true; }
        catch { row = false; }
      }
      if (record && row) continue;
      if (!record && (gm?.recordRequired === true || !row))
        throw new InvariantError('INV-409-INTEGRITY', 'Ledger-anchored JIT grant rows are missing — tamper evidence', 409);
      // The apply gap between the in-tx anchor and the post-commit grants
      // row is a sequence window, never a clock compare: gm.at is monotone
      // chain time, so a recoverClock rewind stretched the old `at >= now`
      // carve-out into a silent-murder window for the full rewind depth
      // (w45-runtime F2). Eight seqs covers an in-flight heal on this
      // process AND a peer reading mid-apply — any attested row past the
      // window closes it deterministically. A crashed apply the chain
      // itself named (EFFECT_APPLY_FAILED for this cert) is exempted
      // honestly: the residue is attested, not wedged (w45-runtime F3).
      // The window must close on EITHER bound: nine appends prove a peer's
      // mid-apply is long past, and sixty seconds of wall time does the
      // same on an idle tenant where seq never advances — the seq-only
      // bound left an idle-tenant murder silent forever (w46-fixverify
      // M-2). Both still dominate the real apply gap (~ms).
      const healWindow = (typeof gm?.seq === 'number' && idx.maxSeq - gm.seq <= 8)
        && (typeof gm?.at === 'number' && effNow - gm.at <= 60_000);
      const namedFailure = idx.effectFailedCerts?.has(gid.replace(/^jit-/, '')) === true;
      if (record && !row && !this.#pendingEffects?.has(tenant) && !healWindow && !namedFailure)
        throw new InvariantError('INV-409-INTEGRITY', 'Ledger-anchored JIT grant rows are missing — tamper evidence', 409);
    }
    merged.tuples = tuples;
    // The throw paths above are intentionally NOT memoized — a murder
    // verdict re-derives on every call so evidence stays fresh (w45-perf).
    // What IS memoized is the clock-free honoured list and the identity
    // base: expiry filtering and the merge above run per call against the
    // caller's effective time (w47-perf).
    if (memo === undefined) { memo = new Map(); memos.set(identity ?? cfg, memo); }
    if (memo.size < 64) memo.set(mk, { base, honoured });
    return merged;
  }
  // A capability's whole selection must fit inside ONE honoured grant tuple
  // — the flat per-field union is observability only (w27-policy F1).
  _grantCovers(tuples, sel) {
    return tuples.some(g => g.resources.includes(sel.resource)
      && g.actions.includes(sel.action)
      && g.destinations.includes(sel.destination)
      && (sel.columns ?? []).every(c => g.columns.includes(c))
      && (sel.row_ids ?? []).every(id => g.row_ids.includes(id)));
  }
  activateDuePolicies(t, now) {
    // Staged deployment (POL-008/013): a verified policy.change with a staged
    // clause stores the next constitution as 'staged'; it promotes exactly one
    // version at activate_at. Versions can never regress.
    const staged = this.store.get(t, 'policy', 'staged');
    if (!staged) return null;
    if (staged.activate_at <= now) {
      // The active fetch stays behind the due-gate and never asserts: a
      // planted staged row must not demand that an 'active' row exist —
      // a missing or divergent active is exactly the state reanchorPolicy
      // repairs, and every transaction runs this sweep (w18-fixverify F6).
      const active = this.store.get(t, 'policy', 'active');
      // The version ladder may only consume ANCHORED content: the mutable
      // 'active' row supplies the baseline version solely when it matches
      // its last non-staged ledger anchor — otherwise a planted row
      // regresses the constitution and the signed POLICY_ACTIVATED
      // launders the regression (w17-idx F1).
      const activeAnchor = [...this._auditIndex(t).policyAnchors].reverse().find(a => !a.staged);
      // A due-but-stale row (superseded version race, or expired before its
      // slot) must never wedge every transaction — retire it honestly and
      // move on (policy-audit F1/F3).
      if (!activeAnchor || !active || digest(active) !== activeAnchor.digest || staged.policy.version !== active.version + 1 || staged.policy.expires_at <= now) {
        this.store.remove(t, 'policy', 'staged');
        this.store.audit(t, 'POLICY_SUPERSEDED', 'system', staged.policy.policy_id, { version: staged.policy.version, reason: !activeAnchor || digest(active) !== activeAnchor.digest ? 'divergent-active-row' : (staged.policy.expires_at <= now ? 'expired-before-activation' : 'version-superseded') }, now);
        return null;
      }
      // The promoter must demand the same ledger anchor the getter does —
      // a store-level 'staged' write can never launder into an anchored
      // active constitution by being promoted (w12-lifecycle F2). An
      // unanchored staged row is tamper evidence: retire it loudly instead
      // of letting a mutable row mint a signed POLICY_ACTIVATED.
      // Only the LATEST staged anchor governs — any earlier staged draft
      // is spent once a successor anchors — and the row must match both
      // its content digest and its anchored activation slot: a swapped or
      // back-dated row is tamper evidence, not a constitution candidate
      // (w18-fixverify F8/F9).
      const stagedAnchor = [...this._auditIndex(t).policyAnchors].reverse().find(a => a.staged);
      const stagedAnchored = stagedAnchor && stagedAnchor.digest === digest(staged.policy) && stagedAnchor.activate_at === staged.activate_at;
      if (!stagedAnchored) {
        this.store.remove(t, 'policy', 'staged');
        this.store.audit(t, 'POLICY_SUPERSEDED', 'system', staged.policy.policy_id, { version: staged.policy.version, reason: 'unanchored-staged-row', policy_digest: digest(staged.policy) }, now);
        return null;
      }
      // A staged constitution that retires a suite a live vault key still
      // signs under can never anchor its own activation — promoting it
      // would throw INV-451 inside this sweep's transaction and wedge every
      // later transaction on the same due row. Supersede it honestly
      // instead (w30-policy F9); the refusal writes under the CURRENT
      // constitution, whose gate the live keys still satisfy.
      if (!this._coversLiveSuites(t, staged.policy)) {
        this.store.remove(t, 'policy', 'staged');
        this.store.audit(t, 'POLICY_SUPERSEDED', 'system', staged.policy.policy_id, { version: staged.policy.version, reason: 'suite-retirement-under-live-keys', policy_digest: digest(staged.policy) }, now);
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
  transaction(principal, fn, { allowDuringDrift = false, recoveryPath = false } = {}) {
    // The index probes (signed-head verify, durable watermark compare,
    // revocation floor, tip divergence) are cross-process freshness gates.
    // Within one synchronous transaction nothing this process does can
    // move them and a peer's file rewrite lands in the next fold's probes
    // at worst one transaction late — the same lag that already exists
    // between a peer write and our next read. Memoize them per
    // transaction instead of paying two file reads plus three queries on
    // each of the ~90 index touches an evaluation makes (w28-http CI
    // regression). Standalone callers keep per-call freshness: the map is
    // only live for the transaction's synchronous window.
    const prevProbeMemo = this._probeMemo, prevOwnSeq = this._ownSeq;
    this._probeMemo = new Map(); this._ownSeq = new Map();
    try {
      this.authorize(principal, ['operator', 'approver', 'custodian', 'security', 'auditor', 'policy_admin', 'workload'], { auditDeny: false });
      // RUN-010: a drifting gate configuration withdraws privileges until a
      // security actor re-attests the observed config snapshot.
      // Drift quarantine is durable (a 'config-flag' record), not just the
      // in-memory set — a second Fabric instance on the same deployment
      // cannot transact through a drift it never noticed (concurrency-audit M4).
      requireThat(allowDuringDrift || (!this._configDrift.has(principal.tenant_id) && !this._auditIndex(principal.tenant_id).tenantDrifted), 'INV-403-QUARANTINE', 'Configuration drift withdrew gate privileges pending security re-attestation', 403);
      // A tenant whose chain could not fold during a clock rewind stays
      // closed until sealAuditChain repairs it — proceeding would risk
      // resurrecting authority the veto sweep could not see (w18-fixverify F12).
      requireThat(!this._clockUnverifiable(principal.tenant_id), 'INV-503-TIME', 'Tenant chain could not be verified during clock recovery — seal the audit chain first', 503);
      // A previous commit's head flush may have lost the lock race — land
      // it now, before this tx's own flush, so the watermark lag window
      // stays bounded to a single commit (w27-chainheads F3).
      if (this.#pendingChainHeads?.size) this._flushChainHeadsGuarded();
      // A starved flush is chain evidence, not silent contention: land the
      // witness row inside a committed tx so the unwitnessed window is
      // attested forever, naming every tenant whose anchor froze
      // (w48-store W48-1).
      if (this.#headFlushStarved?.count) {
        const starved = this.#headFlushStarved; this.#headFlushStarved = null;
        try { this.store.tx(() => { for (const t of starved.tenants) this.store.audit(t, 'HEAD_FLUSH_STARVED', 'system', 'chain-heads', { consecutive: starved.count, code: starved.code }, this.clock()); }); }
        catch { /* a wedged ledger keeps the counters for the next edge */ if (!(this.#headFlushStarved?.count)) this.#headFlushStarved = starved; }
      }
      // In-session heal for failed post-commit effects: replay the same
      // idempotent ledger heal open() runs before new work attests over a
      // dataplane an earlier verdict already diverged from (w22 F6).
      if (this.#pendingEffects.has(principal.tenant_id)) {
        this.#pendingEffects.delete(principal.tenant_id);
        try { this._reconcileLedger(); } catch (healError) { this.#pendingEffects.add(principal.tenant_id); throw healError; }
      }
      const txResult = this.store.tx(() => {
        // The IMMEDIATE lock is the snapshot boundary: probe answers minted
        // during the pre-lock gate checks (authorize, the drift fold at the
        // top of this function) predate whatever peer commit the lock just
        // waited on — inside the lock every probe must re-derive once or a
        // stale head memo can serve a phantom verdict (e.g. a rolling
        // budget the winner already spent, w47b DAT-002).
        this._probeMemo.clear();
        const now = this.clock(); this.store.clock(now, { recoveryPath }); this.activateDuePolicies(principal.tenant_id, now); return fn(now);
      });
      // Post-commit edge: the signed chain-head watermark moves only after
      // its anchors are durable — a rolled-back tx can never leave a
      // watermark pointing at rows that do not exist (w24-fixverify W24-01).
      // A post-commit flush fault must not turn a committed transaction
      // into an error + falsified rejection rows — pending heads are
      // re-buffered by restore() and retried on the next edge
      // (w28-store F5).
      this._flushChainHeadsGuarded();
      // A nested transaction's own appends merge into the outer probe
      // window ONLY on success: they committed inside the outer savepoint
      // scope, so the outer fold still has to see them (w47-perf).
      // Merging on the rolled-back arm inflates the claimed maxSeq with
      // rows that never landed — a phantom claim that masks the
      // watermark/commit divergence gates (w48-fixverify LOW).
      if (prevOwnSeq && this._ownSeq) for (const [k, v] of this._ownSeq) prevOwnSeq.set(k, Math.max(prevOwnSeq.get(k) ?? 0, v));
      return txResult;
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
        // Same rewind asymmetry as #denyAudit: a rewound clock produces a
        // negative diff that must mint, not suppress (w49-runtime W49-2).
        const rDiff = rNow - (this.#rejectMemo.get(rKey) ?? -Infinity);
        if (!(rDiff >= 0 && rDiff < 60_000)) {
          try { this.store.tx(() => { const now = this.clock(); this.store.clock(now); this.store.audit(principal.tenant_id, 'SECURITY_OPERATION_REJECTED', principal.subject_id, 'local-gate', { code: error.code }, now); }); this.#rejectMemo.set(rKey, rNow); } catch { /* ledger unavailable — surface the real rejection */ }
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
      // A dropped or rewritten table anywhere on the gate path is the
      // same integrity evidence _schemaGuard produces on the store — the
      // taxonomy must not fork on which DB the tamper hit (w45-fv F-4).
      if (/no such table|no such column|not a database|malformed/i.test(error?.message ?? ''))
        throw new InvariantError('INV-409-INTEGRITY', 'Ledger schema diverged — tamper evidence', 409, { cause: error });
      // RUN-009: infrastructure failures get a stable documented code instead
      // of leaking driver internals (e.g. node:sqlite ERR_INVALID_STATE).
      throw new InvariantError('INV-503-GATE', 'Internal gate failure', 503);
    }
    finally {
      // The merge lives on the success arm above; here only the memos
      // restore (w48-fixverify LOW).
      this._probeMemo = prevProbeMemo; this._ownSeq = prevOwnSeq;
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
      data_keys: digest({ encryption_key_wrapped: tenant.encryption_key_wrapped ?? null, encryption_key: tenant.encryption_key ? digest(tenant.encryption_key) : null, watermark_key_wrapped: tenant.watermark_key_wrapped ?? null, watermark_key: tenant.watermark_key ? digest(tenant.watermark_key) : null, tokenise_key_wrapped: tenant.tokenise_key_wrapped ?? null, tokenise_key: tenant.tokenise_key ? digest(tenant.tokenise_key) : null })
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
  // One fold case per anchored event type, shared by the live fold and the
  // seal carryover replay: a carried lifecycle entry is a seal-attested
  // re-anchor of an event the cut span destroyed — replaying it through the
  // same projection keeps reservations, outcomes, cancels, parent bindings
  // and every other anchored fact enforceable after remediation
  // (w34-composite CRITICAL-1).
  #foldApply(idx, pl, seq, t) {
    const meta = pl.metadata ?? {};
    switch (pl.type) {
      case 'AUTHORITY_REVOKED': idx.revoked.add(pl.reference);
        if (meta.record_digest) idx.revocationDigests.set(pl.reference, meta.record_digest);
        // The revocation row itself may still be signed by the dying
        // key — the window closes only for LATER seqs. A carried
        // revocation pins the death at its ORIGINAL chain position
        // (orig_seq), never the carrying page's: replaying at the page
        // seq would reopen the kill window between the true death and
        // the re-anchor (w43-seal F-1, same doctrine as KEY_ROTATED).
        if (typeof pl.reference === 'string' && pl.reference.startsWith('key:')) idx.keyDeadAt.set(pl.reference.slice(4), Math.min(idx.keyDeadAt.get(pl.reference.slice(4)) ?? Infinity, typeof pl.orig_seq === 'number' ? pl.orig_seq : seq));
        break;
      case 'KEY_ROTATED':
        // A carried rotation pins its predecessor's death at the event's
        // OWN chain position (orig_seq), not the carrying page's — the
        // seal re-attests where the death actually happened
        // (w36-seal F-D).
        if (meta.key_class === 'audit' && meta.previous_key_id) idx.keyDeadAt.set(meta.previous_key_id, Math.min(idx.keyDeadAt.get(meta.previous_key_id) ?? Infinity, typeof pl.orig_seq === 'number' ? pl.orig_seq : seq));
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
        // Anchored ceremony spend: a mutable rotation_consumed row flag
        // can neither erase nor fake a spend the ledger recorded
        // (w18-fixverify F13).
        // Anchored ceremony spend maps to the capsule that consumed it —
        // a mutable rotation_consumed row flag can neither erase nor fake
        // a spend the ledger recorded, and never wedges a live rotation
        // (w18-fixverify F13, w20-ceremony residual). Pre-capsule anchors
        // carry null and fail closed.
        if (typeof meta.ceremony_id === 'string') idx.ceremonyRotationConsumed.set(meta.ceremony_id, meta.capsule_id ?? null);
        break;
      case 'ROTATION_PREPARED': if (typeof pl.reference === 'string') idx.rotationKeys.add(pl.reference); break;
      case 'EVIDENCE_ATTACHED': { const l = idx.attached.get(pl.reference) ?? []; l.push(meta.evidence_id); idx.attached.set(pl.reference, l); idx.evidenceIds.add(meta.evidence_id); if (meta.expires_at !== undefined) { const el = (idx.evidenceExpiry ??= new Map()).get(pl.reference) ?? []; el.push({ evidence_id: meta.evidence_id, expires_at: meta.expires_at }); idx.evidenceExpiry.set(pl.reference, el); } break; }
      case 'CAPSULE_PROPOSED': idx.proposedAt.set(pl.reference, pl.time); if (meta.nonce) idx.proposedNonce.add(meta.nonce); if (meta.capsule_digest) idx.proposedDigest.set(pl.reference, meta.capsule_digest); if (meta.idem_key) idx.proposedIdem.set(meta.idem_key, { request: meta.idem_request, capsule_id: pl.reference }); if (typeof meta.expires_at === 'number') (idx.proposedExpiry ??= new Map()).set(pl.reference, meta.expires_at); break;
      // Anchored approval/evidence lifetimes: a capsule row rolled back
      // to a pre-approval image cannot hide a lapsed vote or envelope
      // from the resurrection veto (w24-fixverify W24-07).
      case 'EXACT_ACTION_APPROVED': { const l = (idx.approvalExpiry ??= new Map()).get(pl.reference) ?? []; l.push({ signer_id: meta.signer_id ?? null, expires_at: meta.expires_at ?? null }); idx.approvalExpiry.set(pl.reference, l); break; }
      case 'CERTIFICATE_ISSUED': idx.issued.add(pl.reference); if (meta.certificate_id) { idx.issuedCert.set(pl.reference, meta.certificate_id); idx.issuedCerts.add(meta.certificate_id); if (meta.certificate_digest) (idx.issuedCertDigests ??= new Map()).set(meta.certificate_id, meta.certificate_digest); } if (Array.isArray(meta.children)) idx.parentChildren.set(pl.reference, meta.children); break;
      case 'JIT_GRANT_ISSUED': idx.grants.set(meta.grant_id, meta.scope_digest ?? meta.grant_digest); if (meta.grant_id) idx.grantMeta.set(meta.grant_id, { expires_at: meta.expires_at, at: pl.time, seq, recordRequired: meta.scope_digest !== undefined }); break;
      case 'CAPABILITY_ISSUED': (idx.capabilities ??= new Set()).add(pl.reference); (idx.capabilityMeta ??= new Map()).set(pl.reference, { expires_at: meta.expires_at ?? null, digest: meta.digest ?? null }); break;
      case 'POLICY_GENESIS': case 'POLICY_ACTIVATED': case 'EMERGENCY_POLICY_ACTIVATED': if (meta.policy_digest) idx.policyAnchors.push({ staged: false, digest: meta.policy_digest }); break;
      case 'POLICY_STAGED': if (meta.policy_digest) idx.policyAnchors.push({ staged: true, digest: meta.policy_digest, activate_at: meta.activate_at ?? null }); break;
      case 'POLICY_SIMULATED': if (meta.candidate_digest) idx.simulated.push({ candidate_digest: meta.candidate_digest, baseline_digest: meta.baseline_digest ?? null, at: pl.time }); break;
      case 'CONNECTOR_DRIFT': idx.issuerDrift.add(pl.reference); break;
      case 'CONNECTOR_REVALIDATED': idx.issuerDrift.delete(pl.reference); break;
      case 'CONFIG_DRIFT': case 'CONFIG_REASSERTED': if (meta.config_digest) idx.configSnapshot = meta.config_digest; break;
      case 'CONFIG_SNAPSHOT': if (meta.config_digest) idx.configSnapshot = meta.config_digest; break;
      // A crashed post-commit apply the chain itself named is evidence,
      // not a wedge: the grantsFor murder check honours this anchor as
      // honest residue instead of convicting every reader on the peer
      // process (w45-runtime F3).
      case 'EFFECT_APPLY_FAILED': (idx.effectFailedCerts ??= new Set()).add(pl.reference); break;
      case 'POLICY_EVALUATED': if (meta.decision_digest) idx.decisions.set(pl.reference, meta.decision_digest); if (meta.decision) (idx.decisionStatus ??= new Map()).set(pl.reference, meta.decision); break;
      // Per-capability and per-subject indexes keep consume() checks
      // bounded — a linear pass over the whole runtime history per
      // request was a quadratic wall-clock sink (w17-idx F8).
      case 'RUNTIME_ALLOWED': { const u = { capability: pl.reference, subject: pl.actor, resource: meta.resource ?? null, request_id: meta.request_id ?? null, cost: typeof meta.cost === 'number' ? meta.cost : 0, at: pl.time }; idx.runtimeUse.push(u); const cl = idx.runtimeUseByCap.get(u.capability) ?? []; cl.push(u); idx.runtimeUseByCap.set(u.capability, cl); const sl = idx.runtimeUseBySubject.get(u.subject) ?? []; sl.push(u); idx.runtimeUseBySubject.set(u.subject, sl); break; }
      case 'PERCEPTION_SESSION': if (meta.nonce) idx.perceptionNonce.add(meta.nonce); if (meta.channel_digest) idx.perceptionSessions.set(pl.reference, { creator: meta.creator ?? null, expires_at: meta.expires_at ?? null, channel_digest: meta.channel_digest, component: meta.component ?? null, signing_key_id: meta.signing_key_id ?? null, assurance: meta.assurance ?? null, firmware: meta.firmware ?? null, minted_at: pl.time }); break;
      case 'DATA_ACCESSED': idx.dataAccess.push({ subject: pl.reference, dataset: meta.dataset, row_ids: meta.row_ids ?? [], columns: meta.columns ?? [], at: meta.at ?? pl.time, certificate_id: meta.certificate_id ?? null, request_id: meta.request_id ?? null, wedged: meta.wedged === true, gate_denied: meta.gate_denied === true, journal_missing: meta.journal_missing === true }); break;
      // The reservation's anchored time bounds the crash-gap window an
      // honest EXECUTION_DISPATCHED can lose — an unanchored journal far
      // outside it is tamper evidence, never a settleable FAILED
      // (w23-fixverify F-a).
      case 'EXECUTION_RESERVED': idx.reserved.add(pl.reference); (idx.reservedAt ??= new Map()).set(pl.reference, pl.time); (idx.reservedMeta ??= new Map()).set(pl.reference, meta.composite_child_of ?? null); break;
      // A released reservation frees the cert's one spend slot — the
      // journal-less child returns to free authority exactly once
      // (w22 F2).
      case 'EXECUTION_RELEASED': idx.reserved.delete(pl.reference); idx.reservedAt?.delete(pl.reference); idx.reservedMeta?.delete(pl.reference); (idx.released ??= new Set()).add(pl.reference); break;
      case 'EXECUTION_COMPENSATED': (idx.compensated ??= new Set()).add(pl.reference); break;
      case 'RETENTION_DELETED': (idx.tombstones ??= new Map()).set(pl.reference, { key_id: meta.key_id ?? null, kind: meta.kind ?? null }); break;
      case 'EXECUTION_DISPATCHED': if (meta.journal_digest) idx.dispatched.set(pl.reference, meta.journal_digest); (idx.dispatchedMeta ??= new Map()).set(pl.reference, meta.composite_child_of ?? null); break;
      // Pre-dispatch intent: anchored BEFORE target.execute so 'dispatch
      // attempted but no journal anywhere' is a named state rather than
      // releasable clay — the composite release path can no longer mistake
      // a murdered journal for a never-dispatched child (w43-runtime C2).
      case 'EXECUTION_INTENT': (idx.intended ??= new Set()).add(pl.reference); (idx.intendedMeta ??= new Map()).set(pl.reference, meta.composite_child_of ?? null); break;
      // Outcome status AND envelope digest both fold — a served row that
      // diverges from the anchored verdict (post-cancel stale row,
      // ciphertext transplant of a superseded verdict) is tamper
      // evidence, never a quiet serve (w24-lifecycle W24-6).
      case 'EXECUTION_OUTCOME': idx.outcomes.set(pl.reference, meta.status); if (meta.outcome_digest) (idx.outcomeDigests ??= new Map()).set(pl.reference, meta.outcome_digest);
        // A composite parent's outcome event also settles its children:
        // child outcome rows land in the same signed verdict, so the
        // fold must mark each child cert spent too — otherwise a row
        // delete lets a settled child replay (w32-composite F-4).
        // EVERY named child anchors under childOutcomeAnchors (non-terminal
        // labels included): a mid-flight child's stored outcome row is
        // chain-attested even while UNCERTAIN — without it the strict
        // anchor check could not tell a legit mid-flight row from a
        // planted verdict (w34-composite MEDIUM-2).
        if (meta.child_outcomes && typeof meta.child_outcomes === 'object')
          for (const [childCapsule, childStatus] of Object.entries(meta.child_outcomes)) {
            const childCert = idx.issuedCert.get(childCapsule);
            if (childCert !== undefined) {
              (idx.childOutcomeAnchors ??= new Map()).set(childCert, childStatus);
              if (['VERIFIED', 'FAILED', 'COMPENSATED'].includes(childStatus)) idx.outcomes.set(childCert, childStatus);
            }
          }
        break;
      case 'ACTION_CANCELLED': (idx.cancelled ??= new Set()).add(pl.reference); if (meta.certificate_id && idx.issuedCert.get(pl.reference) === meta.certificate_id) idx.outcomes.set(meta.certificate_id, 'CANCELLED'); break;
      // Dry-run marker is anchored too — a mutable last_at a row-writer
      // can backdate would let every call mint a new EXECUTION_DRY_RUN
      // anchor (w24-lifecycle W24-3).
      case 'EXECUTION_DRY_RUN': (idx.dryRunAt ??= new Map()).set(pl.reference, pl.time); break;
      case 'RUNTIME_DENIED': { const d = { request_id: pl.reference, actor: pl.actor, code: meta.code ?? null, capability_id: meta.capability_id ?? null, unverified_capability_id: meta.unverified_capability_id ?? null, at: pl.time }; idx.denials.push(d); const rl = idx.denialsByReq.get(d.request_id) ?? []; rl.push(d); idx.denialsByReq.set(d.request_id, rl); break; }
      // 'gate-deny' containment lines are minted outside any request
      // (quarantine denials, operation rejections) — they bind the
      // containment audit's own dedup bucket, not a request_id. Folding
      // them into denialsByReq['gate-deny'] lets the containment report
      // enumerate them and lets ensureMurdered locate the unsigned line
      // a row-writer deletes (w49-runtime W49-4).
      case 'AUTHORIZATION_DENIED':
      case 'SECURITY_OPERATION_REJECTED': { const d = { request_id: 'gate-deny', actor: pl.actor, code: meta.code ?? null, capability_id: null, at: pl.time }; const rl = idx.denialsByReq.get('gate-deny') ?? []; rl.push(d); idx.denialsByReq.set('gate-deny', rl); break; }
      // A governed spec re-pin anchors the new spec content digest the
      // drift check must accept — the frozen registration baseline alone
      // could never honour an honest issuer record-set change
      // (w49-ledger F4).
      case 'ISSUER_SPEC_REPINNED': if (typeof meta.spec_digest === 'string') (idx.issuerRepins ??= new Map()).set(pl.reference, meta.spec_digest); break;
      case 'COVERAGE_DECLARED':
        // Identity-anchored declarations carry meta.identity_digest; a
        // legacy anchor's meta.digest covered the WHOLE row (status
        // included) — keep them in separate slots so a current row can
        // verify against its own digest only while untouched
        // (w21-fixverify M-4).
        if (meta.identity_digest ?? meta.digest) {
          idx.coverageAnchors.set(pl.reference, meta.identity_digest ?? null);
          if (!meta.identity_digest && meta.digest) (idx.coverageAnchorsLegacy ??= new Map()).set(pl.reference, meta.digest);
        }
        // Re-declaration starts a new epoch: the replay below must seed
        // from the declaration in force at the answer time, not collapse
        // every era into the latest row (w21-fixverify H-1).
        (idx.coverageDeclarations ??= []).push({ path_id: pl.reference, status: meta.status, at: pl.time, evidence_at: meta.status === 'UNCOVERED' ? null : pl.time, max_age_ms: meta.max_age_ms ?? null, seq: seq });
        (idx.coverageDeclared ??= new Map()).set(pl.reference, { status: meta.status, at: pl.time, evidence_at: meta.status === 'UNCOVERED' ? null : pl.time, max_age_ms: meta.max_age_ms ?? null, seq: seq });
        break;
      case 'COVERAGE_TRANSITION': (idx.coverageTransitions ??= []).push({ path_id: pl.reference, to: meta.to, cause: meta.cause, at: meta.at ?? pl.time, evidence_at: meta.evidence_at ?? null, seq: seq }); break;
      // Validations are replay events too: refreshing an already-ENFORCED
      // path emits no transition, so the anchored replay must apply the
      // validation's own evidence_at refresh (w20-fixverify regression).
      case 'COVERAGE_TECHNICAL_VALIDATION': (idx.coverageValidations ??= []).push({ path_id: pl.reference, evidence_id: meta.evidence_id ?? null, issuer: meta.issuer, at: pl.time, seq: seq, validation: true }); break;
      case 'CEREMONY_PLANNED': if (meta.digest) idx.ceremonyPlanned.set(pl.reference, meta.digest); break;
      case 'CEREMONY_SHARES_COMMITTED': idx.ceremonyCommitted.set(pl.reference, { at: pl.time, commitments_digest: meta.commitments_digest ?? null }); break;
      // Only a chain-recorded acknowledgement attests that the consent
      // flow ran — the mutable ceremony row's ack list is a cache, never
      // the quorum's authority (w17-fixverify H1).
      case 'CEREMONY_ACKNOWLEDGED': if (meta.custodian === pl.actor) { const s = idx.ceremonyAcks.get(pl.reference) ?? new Map(); s.set(pl.actor, { artifact_digest: meta.artifact_digest ?? null, key_id: meta.key_id ?? null }); idx.ceremonyAcks.set(pl.reference, s); } break;
      case 'CEREMONY_ABORTED': idx.ceremonyAborted ??= new Set(); idx.ceremonyAborted.add(pl.reference); break;
      // Anchored lifecycle, not row status: flipping the mutable
      // ceremony row can never resurrect an aborted ceremony, replay a
      // completed reconstruction, or re-open a committed deal
      // (w18-fixverify F2).
      case 'CEREMONY_RECONSTRUCTED': idx.ceremonyCompleted ??= new Set(); idx.ceremonyCompleted.add(pl.reference); break;
      // 'All custodians notified' attests through the chain — the
      // mutable notices array can be padded or truncated at will
      // (w18-fixverify F15).
      case 'RECOVERY_NOTICE_ISSUED': if (meta.custodian) { const ns = idx.ceremonyNotices.get(pl.reference) ?? new Set(); ns.add(meta.custodian); idx.ceremonyNotices.set(pl.reference, ns); } break;
      // The clock-recovery wedge persists on the chain itself — a restart
      // must not forget that a tenant's chain could not be verified, and
      // only a signed seal/clear lifts it (w25-clock F-5).
      case 'CLOCK_RECOVERED': idx.clockUnverifiable = Array.isArray(meta.unverifiable_tenants) && meta.unverifiable_tenants.includes(t); break;
      case 'AUDIT_SEALED': case 'AUDIT_WEDGE_CLEARED': case 'AUDIT_SEAL_CARRY': {
        if (pl.type === 'AUDIT_SEAL_CARRY') {
          // A carryover page replays only when it names the seal it
          // belongs to — honest pages land immediately after their
          // AUDIT_SEALED row inside one transaction; a stray or
          // mis-pointed page is fold tampering, not data (w33-seal F-4).
          requireThat(meta.seal_seq === idx.lastSealSeq, 'INV-409-INTEGRITY', 'Audit carryover page references no live seal', 409);
        } else {
          idx.clockUnverifiable = false;
          if (pl.type === 'AUDIT_SEALED') { idx.lastSealSeq = seq; (idx.sealSeqs ??= new Set()).add(seq); }
          // The seal's attested time horizon survives its cut — the
          // resurrection veto may span only what the chain attests the
          // gate lived through (w42-runtime F2).
          if (typeof meta.lived_until === 'number') idx.livedUntil = Math.max(idx.livedUntil ?? 0, meta.lived_until);
        }
        // A seal (and its overflow pages) re-attests the cut span's
        // surviving spend and disclosure authority (w31-runtime F-1):
        // replay it into the same indexes a live event would feed, or
        // remediation silently resets budgets, un-consumes request ids
        // and erases reconstruction history.
        for (const u of Array.isArray(meta.spend_carryover) ? meta.spend_carryover : []) {
          const x = { capability: u.capability, subject: u.subject, resource: u.resource ?? null, request_id: u.request_id ?? null, cost: typeof u.cost === 'number' ? u.cost : 0, at: u.at };
          idx.runtimeUse.push(x);
          if (idx.runtimeUseByCap) { const cl = idx.runtimeUseByCap.get(x.capability) ?? []; cl.push(x); idx.runtimeUseByCap.set(x.capability, cl); }
          if (idx.runtimeUseBySubject) { const sl = idx.runtimeUseBySubject.get(x.subject) ?? []; sl.push(x); idx.runtimeUseBySubject.set(x.subject, sl); }
        }
        for (const a of Array.isArray(meta.access_carryover) ? meta.access_carryover : []) idx.dataAccess.push(a);
        // A seal must not silently un-revoke what it carried: replay
        // each carried revocation into the live revoked set (and the
        // dead-key window for key revocations) at the carrying row's own
        // seq (w32-seal F-5). Orphaned floor rows arrive as
        // floor_derived entries — same enforcement (w33-seal F-1).
        for (const rv of Array.isArray(meta.revocations_carryover) ? meta.revocations_carryover : []) {
          if (typeof rv?.reference !== 'string') continue;
          idx.revoked.add(rv.reference);
          // floor_derived entries carry no signed evidence — track them
          // apart so revoke() can offer a re-anchor path and the report
          // can label them honestly (w34-fixverify M-3).
          if (rv.floor_derived === true) (idx.revokedFloor ??= new Set()).add(rv.reference);
          // A floor-derived 'key:' ref still enforces through idx.revoked
          // above (fail closed — the claim may be a real orphaned
          // revocation), but it carries no attested time: pinning a death
          // seq would let a planted floor fake a key-death window the
          // prescan deliberately exempts (w40-fv F-13).
          if (rv.reference.startsWith('key:') && rv.floor_derived !== true) idx.keyDeadAt.set(rv.reference.slice(4), Math.min(idx.keyDeadAt.get(rv.reference.slice(4)) ?? Infinity, typeof rv.orig_seq === 'number' ? rv.orig_seq : seq));
        }
        // Every other verifiable doomed event re-anchors here: reservations,
        // outcomes, cancels, certificate issuance, the parent↔child binding,
        // policy anchors, coverage, ceremonies — replayed through THIS same
        // fold so a seal can never launder a spent or bound certificate into
        // a fresh spend (w34-composite CRITICAL-1). Entries carry the
        // seal-attested {type, reference, actor, time, metadata} slice; the
        // writer already excluded the dedicated-array types above.
        for (const c of Array.isArray(meta.lifecycle_carryover) ? meta.lifecycle_carryover : [])
          if (typeof c?.type === 'string' && !['AUDIT_SEALED', 'AUDIT_SEAL_CARRY', 'AUDIT_WEDGE_CLEARED'].includes(c.type))
            // orig_seq keeps the carried event's own chain position: a
            // doomed KEY_ROTATED's death check must be judged at the seq
            // it actually happened, not the carrying page's seq
            // (w36-seal F-D).
            this.#foldApply(idx, { type: c.type, reference: c.reference ?? null, actor: c.actor ?? null, time: c.time ?? null, orig_seq: typeof c.orig_seq === 'number' ? c.orig_seq : null, metadata: c.metadata ?? {}, tenant_id: t }, seq, t);
        // Doomed rows that failed re-verification could not be carried — the
        // seal names them in dropped_events. DELETE-destroyed rows are the
        // same class of evidence loss (attested as deleted_gaps) — both
        // feeds are honest evidence the ledger cannot re-derive, so
        // reconstruction budgeting treats them as worst-case coverage
        // rather than under-reporting erased disclosure (w34-composite
        // MEDIUM-1, w39-seal F-3).
        const droppedNow = (typeof meta.carryover_totals?.dropped_events === 'number' ? meta.carryover_totals.dropped_events : (Array.isArray(meta.dropped_events) ? meta.dropped_events.length : 0))
          + (typeof meta.carryover_totals?.deleted_events === 'number' ? meta.carryover_totals.deleted_events : 0);
        idx.sealDroppedEvents = (idx.sealDroppedEvents ?? 0) + droppedNow;
        // The reconstruction gate only wedges while the drop is FRESH — a
        // seal that dropped evidence months ago must not INV-429 every
        // honest export forever (w49-runtime W49-3). Track the newest
        // dropping seal's chain time; readers bound it by their window.
        if (droppedNow > 0) idx.sealDroppedAt = Math.max(idx.sealDroppedAt ?? 0, pl.time ?? 0);
        break;
      }
    }
  }

  _auditIndex(t, _retried = false) {
    // Raw sqlite schema failures (a dropped or rewritten audit table) are
    // integrity evidence inside the INV taxonomy, never bare ERR_SQLITE
    // noise escaping to callers (w44-store M-2).
    try { return this._auditIndexInner(t, _retried); }
    catch (e) {
      if (e instanceof InvariantError) throw e;
      if (/no such table|no such column|not a database|malformed/i.test(e?.message ?? ''))
        throw new InvariantError('INV-409-INTEGRITY', 'Ledger schema diverged — tamper evidence', 409, { cause: e });
      throw e;
    }
  }
  _auditIndexInner(t, _retried = false) {
    let idx = this.#auditIdx.get(t);
    if (!idx) { idx = { maxSeq: 0, building: false, revoked: new Set(), attached: new Map(), evidenceIds: new Set(), proposedNonce: new Set(), proposedAt: new Map(), proposedDigest: new Map(), proposedIdem: new Map(), issued: new Set(), issuedCert: new Map(), issuedCerts: new Set(), grants: new Map(), grantMeta: new Map(), rotations: new Map(), rotationsByPrev: new Map(), rotationKeys: new Set(), policyAnchors: [], dataAccess: [], perceptionNonce: new Set(), reserved: new Set(), reservedAt: new Map(), reservedMeta: new Map(), dispatched: new Map(), dispatchedMeta: new Map(), outcomes: new Map(), outcomeDigests: new Map(), childOutcomeAnchors: new Map(), cancelled: new Set(), dryRunAt: new Map(), keyDeadAt: new Map(), parentChildren: new Map(), simulated: [], issuerDrift: new Set(), issuerRepins: new Map(), sealDroppedAt: 0, tenantDrifted: false, configSnapshot: null, decisions: new Map(), runtimeUse: [], runtimeUseByCap: new Map(), runtimeUseBySubject: new Map(), revocationDigests: new Map(), denials: [], denialsByReq: new Map(), ceremonyAcks: new Map(), ceremonyPlanned: new Map(), ceremonyCommitted: new Map(), ceremonyAborted: new Set(), ceremonyCompleted: new Set(), ceremonyNotices: new Map(), ceremonyRotationConsumed: new Map(), coverageAnchors: new Map(), coverageDeclared: new Map(), coverageTransitions: [], coverageValidations: [], perceptionSessions: new Map(), capabilities: new Set() }; this.#auditIdx.set(t, idx); }
    // One prepared statement per index for the head probe — evaluation
    // touches the index dozens of times and a fresh prepare per call was
    // most of that cost. Semantics unchanged: the query still re-reads
    // MAX(seq) and the consumed-tip hash on every call.
    idx.headQ ??= this.store._stmt("SELECT m.maxSeq, h.headHash FROM (SELECT COALESCE(MAX(seq),0) maxSeq FROM audit WHERE tenant=?) m LEFT JOIN (SELECT hash headHash FROM audit WHERE tenant=? AND seq=?) h");
    // The revocation floor check must hold on every call, not only on a
    // re-fold: a planted 'revocation' record row after the index cached
    // otherwise hides forever (w25 C2 regression). In-tx consistency is
    // preserved — revoke writes its event before the floor row inside the
    // same transaction, and the fold consumes uncommitted rows first.
    idx.floorQ ??= this.store._stmt("SELECT id FROM records WHERE tenant=? AND kind='revocation'");
    // The seal's own write folds before its AUDIT_SEALED row lands: revocations
    // carried into that row are still anchored-intent — the floor may keep them
    // without tripping the divergence check (w32-seal F-5).
    const pendingCarry = this.#sealCarry?.get(t);
    const floorCheck = () => { for (const row of idx.floorQ.all(t)) requireThat(idx.revoked.has(row.id) || pendingCarry?.has(row.id), 'INV-409-INTEGRITY', 'Revocation state diverges from the ledger', 409); };
    // Inside BEGIN IMMEDIATE the audit table can only grow through this
    // connection's own appends — BEGIN IMMEDIATE holds the single-writer
    // lock for the whole transaction, so the committed tail is pinned and
    // the only freshness a per-call head probe adds over the transaction
    // memo is our own appends, which _ownSeq already tracks (w47-perf).
    // The memo is keyed on the consumed tip: probe.headHash is the row
    // hash AT idx.maxSeq — a new tip gets one fresh probe, an unchanged
    // tip reuses it, and append-only triggers make the stored hash
    // immutable for the duration either way. Standalone reads keep the
    // per-call probe — the freshness doctrine's cross-process gate.
    const probe = this._probeMemo
      ? (() => { const key = 'q:' + t + ':' + idx.maxSeq; let p = this._probeMemo.get(key); if (p === undefined) { p = idx.headQ.get(t, t, idx.maxSeq); this._probeMemo.set(key, p); } return p; })()
      : idx.headQ.get(t, t, idx.maxSeq);
    const maxSeq = Math.max(probe.maxSeq, this._probeMemo ? (this._ownSeq?.get(t) ?? 0) : 0);
    // Re-entrancy must fail closed: a nested caller handed the mid-fold
    // partial projection could observe anchors that the committed chain
    // never attested (w17-idx F9). Nothing inside the fold recurses
    // today — if a future path does, it wedges loudly, never silently.
    requireThat(!idx.building, 'INV-503-INTEGRITY', 'Re-entrant audit index fold', 503);
    // End-of-chain commitment (w24-fixverify W24-01): the signed watermark
    // can never sit beyond the stored tail — truncating audit rows rewinds
    // the table but cannot forge the signature to pull the watermark back,
    // so the fold screams instead of running a shorter chain. A watermark
    // behind the tail is legitimate lag (it advances post-commit only).
    const sealing = this.#sealing?.has(t) === true;
    let sealRecount, reVerify;
    // A seal cut legitimately moves the committed tail below the consumed
    // point — the incremental index is stale beyond repair and must refold
    // the surviving chain from zero (w25-clock F-3).
    if (sealing && idx.maxSeq > maxSeq) { this.#auditIdx.delete(t); return this._auditIndex(t); }
    // The seal is the one sanctioned way to move the signed head backward —
    // inside its transaction the watermark gates stand down while the
    // fold's per-row verification still runs (w25-clock F-2/F-3).
    if (!sealing) {
      requireThat(idx.maxSeq <= maxSeq, 'INV-409-AUDIT-TAMPER', 'Audit truncated below the consumed index', 409);
      // File-side probes (signed head verify + compare, durable watermark,
      // tip hash) run once per synchronous transaction window — the map
      // transaction() installs. Outside it they run on every call, so
      // standalone reads keep per-call file freshness (w28-fixverify F4,
      // w28-http CI regression).
      if (this._probeMemo?.get(t) !== true) {
      try {
      const committedHead = this._chainHead(t);
      requireThat(committedHead !== 'corrupt', 'INV-409-INTEGRITY', 'Chain head watermark failed ledger signature verification', 409);
      // The durable watermark floors the committed rows themselves, not
      // just the file head: a tenant whose head entry was STRIPPED while
      // its watermark entry survives still has wmSeq > maxSeq after its
      // rows are erased — gating the check on committedHead misses exactly
      // that surgery (w31-fixverify F1).
      const wmSeq = this._headWatermark(t);
      requireThat(!(wmSeq > maxSeq), 'INV-409-INTEGRITY', 'Audit ledger regressed below the durable head watermark', 409);
      if (committedHead) {
        // Replaying an OLDER signed head regresses the watermark — the
        // signature is authentic, the position is a lie. Compare against
        // the last head this index actually consumed (not idx.maxSeq,
        // which legitimately runs ahead mid-transaction on uncommitted
        // appends) (w25-fixverify W25-01, w25-issuerd F2).
        requireThat(!(committedHead.seq < (idx.seenHeadSeq ?? 0)), 'INV-409-INTEGRITY', 'Signed chain head regressed below the consumed watermark', 409);
        requireThat(!(wmSeq > committedHead.seq), 'INV-409-INTEGRITY', 'Signed chain head regressed below the durable watermark', 409);
        // The watermark floors its own attestation: the signed head claims
        // the durable floor it saw at mint, so a resolved floor below that
        // claim is a replayed or rewritten watermark, never a live one
        // (w40-fv F-1).
        requireThat(!(Number.isSafeInteger(committedHead.floor_seq) && wmSeq !== undefined && wmSeq < committedHead.floor_seq), 'INV-409-INTEGRITY', 'Durable watermark regressed below its own attestation in the signed head', 409);
        idx.seenHeadSeq = committedHead.seq;
        // The in-ledger fold marker commits atomically with every audit row
        // and is not part of the replayable file pair: a marker ahead of the
        // signed head means either the head file lost its last flush (crash)
        // or the pair was rolled back — the fold cannot tell crash from
        // surgery, so it names the divergence as live tamper evidence for
        // the seal surface instead of pretending a floor exists
        // (w44-fixverify F-2).
        try {
          const marker = this.store._stmt("SELECT value FROM meta_kv WHERE tenant=? AND key='fold_floor'").get(t)?.value;
          const markerSeq = typeof marker === 'string' && /^\d+:/.test(marker) ? Number(marker.slice(0, marker.indexOf(':'))) : undefined;
          if (Number.isSafeInteger(markerSeq) && markerSeq > committedHead.seq && !this.#wmTamper.has(t)) this.#wmTamper.set(t, { kind: 'floor_marker_ahead', seq: markerSeq });
        } catch { /* marker read failure — the file-side gates still stand */ }
        this._bumpHeadWatermark(t, committedHead.seq);
        requireThat(!(committedHead.seq > maxSeq), 'INV-409-INTEGRITY', 'Audit chain truncated below the signed head watermark', 409);
        // A signed head BELOW the committed tip beside a watermark that
        // cannot vouch for it is a replayed pair, not a live head — an
        // honest commit lag always keeps the live wm entry (it rides the
        // same flush), so only file surgery produces the pair (w40-fv F-2).
        // "Cannot vouch" is EVERY tamper state that means the resolved
        // floor is not the file's honest word — stripped, malformed,
        // forged signature, or an unsigned claim above the head. Our own
        // degraded writes (dead_signer/sign_failed/write_failed) still
        // pin a real floor and stay honest (w41-fv F-4: a planted junk
        // entry must not launder the strip it replaces). Ungated, this
        // check would wedge every racing fold in a shared deployment:
        // peers' committed rows legitimately outrun their head flush by
        // a window.
        const wmVouchless = { floor_stripped: 1, malformed: 1, signature: 1, unsigned_above_head: 1 }[this.#wmTamper.get(t)?.kind];
        requireThat(!(committedHead.seq < maxSeq && !this.store.db.isTransaction && wmVouchless), 'INV-409-INTEGRITY', 'Signed chain head regressed below the committed tip beside a watermark that cannot vouch — a replayed pair is not a head', 409);
        // The signed head also attests the residue it saw at mint: the
        // newest export checkpoint and the revocation floor count. A
        // rewind that deletes those rows to bury their anchors convicts —
        // replayed heads cannot un-claim what they signed for
        // (w33-export F1/F6).
        if (committedHead.checkpoint) requireThat(this._checkpointAttested(t, committedHead.checkpoint), 'INV-409-INTEGRITY', 'Signed head attests an audit checkpoint that no longer verifies', 409);
        // Older checkpoints are witnesses too: the head also binds their
        // COUNT, so deleting a prior export's cp row convicts under any
        // surviving head (w34-fixverify L-1). Only rows that still verify
        // as signed checkpoints count — a planted 'audit-checkpoint'
        // record row must not inflate the floor (w36-fixverify L-3).
        // Heads minted before the field existed legitimately lack it —
        // absent means unclaimed.
        if (committedHead.checkpoints !== undefined) requireThat(this._verifiedCheckpointCount(t) >= committedHead.checkpoints, 'INV-409-INTEGRITY', 'Audit checkpoint floor regressed below the signed head', 409);
        if (committedHead.revocations !== undefined) requireThat(this.store.ids(t, 'revocation', 1_000_000).length >= committedHead.revocations, 'INV-409-INTEGRITY', 'Revocation floor regressed below the signed head', 409);
      }
      if (committedHead && committedHead.seq === maxSeq && committedHead.seq > 0) {
        idx.tipQ ??= this.store._stmt('SELECT hash FROM audit WHERE tenant=? AND seq=?');
        const tipRow = idx.tipQ.get(t, committedHead.seq);
        requireThat(tipRow && ctEqual(tipRow.hash, committedHead.hash), 'INV-409-INTEGRITY', 'Audit head row diverges from the signed watermark', 409);
      }
      // A seal's attested carry residue must still all EXIST — a deleted
      // AUDIT_SEAL_CARRY page never re-folds, so the fold's own replay
      // bookkeeping cannot see the amputation; the recount is derived
      // from the table itself (w36-seal F-H). It runs POST-FOLD at the
      // two index exits below (never during sealing): placed there the
      // sealSeqs gate reflects every committed seal, so a page deleted
      // between the seal commit and the next read cannot slip a
      // diminished carry past the first call (w38 self-audit). The
      // recount is memoized on the table's (maxSeq,rowCount)
      // fingerprint PLUS a point-hash spot-check of every seal/carry row
      // the last recount saw: an in-place rewrite of a consumed page
      // keeps (maxSeq,count) but changes that row's hash, so the fp
      // flips and the page is re-counted as destroyed residue
      // (w39-seal F-5). The spot-check is indexed point lookups —
      // the parsed-type scan itself stays once-per-flip, keeping
      // NFR-PERF-004's decision budget honest on the CI runner (w37 CI fix).
      sealRecount = () => {
        if (sealing || (idx.sealSeqs?.size ?? 0) === 0) return;
        const fpRow = this.store._stmt('SELECT COUNT(*) c, COALESCE(MAX(seq),0) m FROM audit WHERE tenant=?').get(t);
        let sealFp = `${fpRow.m}:${fpRow.c}`;
        if (idx.sealRows?.length) {
          idx.sealPt ??= this.store._stmt('SELECT hash FROM audit WHERE tenant=? AND seq=?');
          for (const r of idx.sealRows) { const row = idx.sealPt.get(t, r.seq); if (!row || row.hash !== r.hash) { sealFp += `:${r.seq}!`; break; } }
        }
        if (idx.sealScanFp === sealFp) return;
        idx.sealScanFp = sealFp;
        const claims = new Map(), seen = new Map(), sealRows = [];
        const recountKeys = this.auditPublicKeys(t);
        for (const r of this.store._stmt("SELECT seq,hash,envelope FROM audit WHERE tenant=? AND json_valid(envelope) AND (json_extract(envelope,'$.payload.type') IN ('AUDIT_SEALED','AUDIT_SEAL_CARRY') OR EXISTS (SELECT 1 FROM json_each(envelope,'$') GROUP BY \"key\" HAVING COUNT(*)>1) OR EXISTS (SELECT 1 FROM json_each(envelope,'$.payload') GROUP BY \"key\" HAVING COUNT(*)>1))").all(t)) {
          sealRows.push({ seq: r.seq, hash: r.hash });
          let env; try { env = JSON.parse(r.envelope); } catch { continue; }
          // Unsigned attacker JSON must never satisfy a signed claim —
          // a forged AUDIT_SEALED/CARRY at a consumed seq counts as
          // destroyed residue, not as a surviving one (w38-fixverify
          // F-2). The parsed-type scan touches rare rows, so per-row
          // ECDSA stays bounded.
          try { verifySigned(env, recountKeys, 'audit'); } catch { continue; }
          const pl = env?.payload, m = pl?.metadata ?? {};
          if (pl?.type === 'AUDIT_SEALED') claims.set(r.seq, { pages: typeof m.carryover_pages === 'number' ? m.carryover_pages : 0, totals: m.carryover_totals ?? null, sums: { spend: Array.isArray(m.spend_carryover) ? m.spend_carryover.length : 0, access: Array.isArray(m.access_carryover) ? m.access_carryover.length : 0, revocations: Array.isArray(m.revocations_carryover) ? m.revocations_carryover.length : 0, capabilities: Array.isArray(m.capabilities_cut) ? m.capabilities_cut.length : 0, lifecycle: Array.isArray(m.lifecycle_carryover) ? m.lifecycle_carryover.length : 0 } });
          else if (pl?.type === 'AUDIT_SEAL_CARRY' && typeof m.seal_seq === 'number') {
            const pg = seen.get(m.seal_seq) ?? { count: 0, sums: { spend: 0, access: 0, revocations: 0, capabilities: 0, lifecycle: 0 } };
            pg.count++;
            pg.sums.spend += Array.isArray(m.spend_carryover) ? m.spend_carryover.length : 0;
            pg.sums.access += Array.isArray(m.access_carryover) ? m.access_carryover.length : 0;
            pg.sums.revocations += Array.isArray(m.revocations_carryover) ? m.revocations_carryover.length : 0;
            pg.sums.capabilities += Array.isArray(m.capabilities_cut) ? m.capabilities_cut.length : 0;
            pg.sums.lifecycle += Array.isArray(m.lifecycle_carryover) ? m.lifecycle_carryover.length : 0;
            seen.set(m.seal_seq, pg);
          }
        }
        for (const [sealSeq, claim] of claims) {
          const pg = seen.get(sealSeq) ?? { count: 0, sums: { spend: 0, access: 0, revocations: 0, capabilities: 0, lifecycle: 0 } };
          requireThat(pg.count === claim.pages, 'INV-409-INTEGRITY', `Audit seal at seq ${sealSeq} attests ${claim.pages} carryover page(s) but only ${pg.count} survive — restore the amputated carry`, 409);
          // Seals predating a totals class legitimately lack the key —
          // an honest historical seal must not wedge on a class it
          // never attested (w38-store F-3).
          if (claim.totals) for (const cls of ['spend', 'access', 'revocations', 'capabilities', 'lifecycle'])
            if (claim.totals[cls] !== undefined)
              requireThat((claim.sums[cls] + pg.sums[cls]) === claim.totals[cls], 'INV-409-INTEGRITY', `Audit seal at seq ${sealSeq} attests ${claim.totals[cls]} carried ${cls} entr(ies) but only ${claim.sums[cls] + pg.sums[cls]} survive — restore the amputated carry`, 409);
        }
        for (const [sealSeq] of seen)
          requireThat(claims.has(sealSeq), 'INV-409-INTEGRITY', 'Audit carryover page references a seal row that does not exist', 409);
        idx.sealRows = sealRows;
      };
      // A consumed row is still attacker-writable clay: surgery on a
      // mid-chain envelope after the index consumed it leaves every
      // folded fact stale — the watermark, the head pin and the recount
      // all look past the prefix (w41-http F7). A bounded rotating window
      // of consumed rows re-verifies inside the same per-transaction
      // freshness window the other file probes use; a row that no longer
      // verifies convicts the table the way a fresh page would.
      reVerify = () => {
        if (idx.maxSeq <= 0) return;
        // The window is sized to the chain: ceil(n/32) rows per fold keeps
        // a full-prefix re-verification inside 32 folds without making a
        // fold on a short chain pay eight signature checks (NFR-PERF-004).
        const span = Math.max(1, Math.ceil(idx.maxSeq / 32));
        const from = idx.integrityCursor ?? 1;
        const to = Math.min(idx.maxSeq, from + span - 1);
        idx.integrityCursor = to >= idx.maxSeq ? 1 : to + 1;
        idx.reVerifyQ ??= this.store._stmt('SELECT seq,hash,envelope FROM audit WHERE tenant=? AND seq BETWEEN ? AND ? ORDER BY seq');
        const rKeys = this.auditPublicKeys(t);
        for (const r of idx.reVerifyQ.all(t, from, to)) {
          let pl = null;
          if (this.store.selfRowEnv?.(t, r.seq) === hashBytes(r.envelope)) {
            // Self-written row still carrying its minted bytes: the
            // byte-for-byte match means the signature is the one this
            // instance produced (w43-perf).
            try { pl = JSON.parse(r.envelope).payload; } catch { pl = null; }
          } else {
            try { pl = verifySigned(JSON.parse(r.envelope), rKeys, 'audit'); } catch { pl = null; }
          }
          requireThat(pl && pl.sequence === r.seq && digest(pl) === r.hash, 'INV-409-INTEGRITY', `Consumed audit row ${r.seq} diverges from what the index folded — mid-chain surgery`, 409);
        }
      };
      this._probeMemo?.set(t, true);
      } catch (err) {
        // A standalone read sees the file side and the table side at
        // different instants: a peer's commit + head/watermark flush can
        // land between this connection's headQ probe and its file reads,
        // producing a momentary head<watermark or head>tail view that is
        // a live race, not tamper evidence (w43-race: racing gate workers
        // wedged on INV-409-INTEGRITY mid-flight). Retry once on a fresh
        // view — inside a write transaction the peer cannot interleave,
        // so the first verdict stands there, and a genuinely diverged
        // pair convicts identically on the second look.
        if (err?.code === 'INV-409-INTEGRITY' && !this.store.db.isTransaction && !_retried) {
          this._probeMemo?.delete(t);
          return this._auditIndex(t, true);
        }
        throw err;
      }
      }
    }
    // Same-seq head replacement cannot resync silently: the stored head row
    // must still carry the hash the index last consumed — otherwise a
    // tail rewrite slipped under the MAX(seq) watermark. Sealing moves the
    // head legitimately, so the seal scope skips this like the other
    // watermark assertions above (w12-provenance F10 / w25-clock F-3).
    if (!sealing && idx.maxSeq > 0 && idx.headHash !== undefined) {
      requireThat(probe.headHash != null && ctEqual(probe.headHash, idx.headHash), 'INV-409-AUDIT-TAMPER', 'Audit head diverged from the consumed index', 409);
    }
    if (idx.maxSeq === maxSeq) {
      // The floor check re-scans on every call outside a write tx — a
      // planted 'revocation' record row can land between calls and the
      // index must convict it on the very next read (w25 C2). Inside
      // BEGIN IMMEDIATE the records table can only change through this
      // connection's own writes, which flag #floorDirty — an unflagged
      // rescan would re-check an identical table. Pre-tx plants are
      // still convicted by the standalone calls the freshness doctrine
      // requires around every transaction (w43-perf).
      // Both memo cursors must be restored before a retry: sealRecount
      // stamps sealScanFp ahead of its claims loop and reVerify advances
      // integrityCursor ahead of its span check — a retried call that
      // kept them would skip the exact state it came to re-verify and
      // pass a wedge through (w43-race).
      const recountFpBefore = idx.sealScanFp, cursorBefore = idx.integrityCursor;
      try {
        if (!this.store.db.isTransaction || this.#floorDirty?.delete(t)) floorCheck();
        this.#floorDirty?.delete(t);
        sealRecount?.(); reVerify?.();
      } catch (err) {
        // Same live-race window as the file probes: a peer's revocation or
        // in-flight seal commit can land between the head probe and the
        // caught-up rescan. Re-check on a fresh view once — a genuinely
        // diverged floor convicts identically (w43-race).
        if (err?.code === 'INV-409-INTEGRITY' && !this.store.db.isTransaction && !_retried) {
          idx.sealScanFp = recountFpBefore; idx.integrityCursor = cursorBefore;
          this._probeMemo?.delete(t);
          return this._auditIndex(t, true);
        }
        throw err;
      }
      return idx;
    }
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
      // The page surface classifies dead-signed rows INV-409-AUDIT-TAMPER;
      // under the fold the same rows carry the INTEGRITY verdict
      // (w14 W13-01) — translate only the signing-window case at the
      // fold's read boundary; row-integrity failures keep TAMPER.
      let pageEntries;
      try { pageEntries = this.store.auditPage(t, { after: idx.maxSeq, limit: 2_000_000 }).entries; }
      catch (err) {
        if (err && err.code === 'INV-409-AUDIT-TAMPER' && /past its ledger death/.test(err.message || '')) throw new InvariantError('INV-409-INTEGRITY', err.message, 409);
        throw err;
      }
      for (const e of pageEntries) {
      // Signing-window enforcement (w13-supply W13-01): a revoked or
      // rotated-out key keeps verifying entries signed during its
      // authority but can never mint an entry appended AFTER its on-chain
      // death — the verification set is still every legitimate key, the
      // window binds which seqs it may cover.
      const kid = e.envelope?.protected?.key_id, deadAt = kid !== undefined ? idx.keyDeadAt.get(kid) : undefined;
      // A row this instance minted needs no second ECDSA pass — only when
      // the stored bytes reserialize identically to the minted envelope
      // (a signature or payload transplant breaks the match and falls
      // through to full verification) (w43-perf).
      let pl;
      let selfMinted = false;
      try { selfMinted = e.envelope !== undefined && this.store.selfRowEnv?.(t, e.sequence) === hashBytes(canonical(e.envelope)); } catch { selfMinted = false; }
      if (selfMinted) pl = deadAt !== undefined && deadAt < e.sequence ? null : e.envelope?.payload;
      else { try { pl = e.envelope && !(deadAt !== undefined && deadAt < e.sequence) ? verifySigned(e.envelope, keys, 'audit') : null; } catch { pl = null; } }
      requireThat(pl && pl.tenant_id === t, 'INV-409-INTEGRITY', 'Audit row fails ledger signature verification', 409);
      // Time-sanity bound (w13-supply W13-04): a forged row claiming a
      // far-future timestamp can never be consumed silently — chain time
      // may exceed the operator clock only by the previous entry's own
      // stamp (legitimate rewinds) plus a read-race allowance. Rows that
      // fail wedge the index; remediation is the seal runbook.
      requireThat(typeof pl.time !== 'number' || pl.time <= Math.max(consumeNow, prevPlTime) + 60_000, 'INV-409-INTEGRITY', 'Audit row claims an impossible future timestamp', 409);
      prevPlTime = Math.max(prevPlTime, typeof pl.time === 'number' ? pl.time : prevPlTime);
      this.#foldApply(idx, pl, e.sequence, t);
        idx.maxSeq = Math.max(idx.maxSeq, e.sequence ?? 0);
      }
      // Stamp the LAST CONSUMED seq, not the page head — a tenant over the
      // page limit must not claim full coverage while mid-table rows went
      // unread (w12-supply W12-04). The head pin tracks the consumed tip.
      const tip = this.store._stmt('SELECT hash FROM audit WHERE tenant=? AND seq=?').get(t, idx.maxSeq);
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
      floorCheck();
      sealRecount?.();
      reVerify?.();
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
    // Memoize on the exact inputs the resolution reads: the two rows' raw
    // ciphertext (a store rewrite lands on different bytes), the fold view
    // (maxSeq covers appends; anchors size covers fold content) and the
    // clock (the staged-activation comparison is time-bound). Ciphertext
    // equality is checked per hit — a planted same-seq row never reuses a
    // verified result (w45-perf).
    const rawStmt = (this._policyRawStmt ??= this.store._stmt('SELECT value FROM records WHERE tenant=? AND kind=? AND id=?'));
    const stagedRaw = rawStmt.get(t, 'policy', 'staged')?.value ?? null, activeRaw = rawStmt.get(t, 'policy', 'active')?.value ?? null;
    const pIdx = this._auditIndex(t), now = this.clock();
    const mk = `${t}|${pIdx.maxSeq}|${pIdx.policyAnchors?.size ?? 0}|${now}`;
    const ent = this._policyMemo?.get(mk);
    if (ent && ent.stagedRaw === stagedRaw && ent.activeRaw === activeRaw) return ent.result;
    const staged = this.store.get(t, 'policy', 'staged'), active = this._mustAnchored(t, 'policy', 'active');
    const anchors = pIdx.policyAnchors;
    const anchor = [...anchors].reverse().find(a => !a.staged);
    // An empty anchor must NOT vacuously pass: on the pre-upgrade ledgers
    // this exists for, ANY rewritten 'active' row would verify. Fail
    // closed — reanchorPolicy is the break-glass that establishes the
    // first anchor under a signed remediation event (w16-fixverify F6).
    requireThat(anchor && digest(active) === anchor.digest, 'INV-409-INTEGRITY', 'Active policy diverges from its ledger-anchored activation', 409);
    // The getter serves staged content only when the row IS the latest
    // staged anchor verbatim — content digest AND activation slot. A
    // swapped or back-dated row degrades to 'active' rather than throwing,
    // so tamper cannot wedge every reader; the transaction-path sweep
    // retires it loudly instead (w18-fixverify F8/F9).
    if (staged && staged.activate_at <= now && staged.policy.version === active.version + 1 && staged.policy.expires_at > now) {
      const stagedAnchor = [...anchors].reverse().find(a => a.staged);
      if (stagedAnchor && stagedAnchor.digest === digest(staged.policy) && stagedAnchor.activate_at === staged.activate_at) { const result = staged.policy; this._policyMemoSet(mk, stagedRaw, activeRaw, result); return result; }
    }
    this._policyMemoSet(mk, stagedRaw, activeRaw, active);
    return active;
  }
  _policyMemoSet(mk, stagedRaw, activeRaw, result) {
    const memos = (this._policyMemo ??= new Map());
    if (memos.size < 64) memos.set(mk, { stagedRaw, activeRaw, result });
  }
  // The policy object's canonical digest is a pure function of the same
  // memoized object: re-serializing it per call pays a sha256 on bytes
  // that provably did not change (w47-perf). Object identity is the
  // honesty boundary — a caller mutating the returned object would break
  // the memo's contract, and nothing in the codebase mutates a served
  // policy (writes land through store.put on fresh clones).
  _policyDigest(t, policy = null) {
    const p = policy ?? this.policy(t);
    let d = (this._policyDigestMemo ??= new WeakMap()).get(p);
    if (d === undefined) { d = digest(p); this._policyDigestMemo.set(p, d); }
    return d;
  }
  // Capsule content inside a record is fixed at propose: the mutable
  // fields (evidence, approvals, decision, status) all live beside it, so
  // the canonical digest over record.capsule can memo on object identity
  // within the record instance's lifetime (w47-perf).
  _capsuleDigestOf(record) {
    let d = (this._capsuleDigestMemo ??= new WeakMap()).get(record.capsule);
    if (d === undefined) { d = digest(record.capsule); this._capsuleDigestMemo.set(record.capsule, d); }
    return d;
  }
  identities(t) { const iIdx = this._auditIndex(t).revoked; return Object.fromEntries(Object.entries(this.tenant(t).identities).map(([id, v]) => [id, { ...v, revoked: v.revoked || iIdx.has(`key:${id}`) || iIdx.has(`subject:${v.subject_id}`) || iIdx.has(`device:${v.device_id}`) }])); }
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
    // The health binding must follow the (subject, device) enrolment the
    // caller actually presents — first-found resolution would let a stale
    // second enrolment sign while the healthy first is checked
    // (w20-ceremony W20-3). The enrolment key is the map's own key: a
    // key-class revocation on it kills live authority on the spend path
    // exactly like the signing path (w42-runtime F3).
    const [kid, identity] = Object.entries(this.tenant(t).identities).find(([, x]) => x.subject_id === subject && x.device_id === device) ?? [];
    requireThat(identity && !identity.revoked && !this.revoked(t, 'key', kid) && identity.health_expires_at > now, 'INV-403-HEALTH', 'Configured device health evidence expired or mismatched', 403);
  }
  getCapsule(p, id) { this.authorize(p, ['operator', 'approver', 'custodian', 'security', 'policy_admin', 'auditor']); return this.capsuleView(this._mustAnchored(p.tenant_id, 'capsule', identifier(id)), p.tenant_id); }
  // A capsule read never returns raw dataset rows: current_state snapshots
  // are needed internally for predicates and target equality checks, but the
  // read surface exposes only their digest (w6-tenancy F1).
  capsuleView(record, tenant = null) {
    const view = clone(record);
    // The stored status is a mutable cache — a (ciphertext,DEK) pair
    // rollback resurrects pre-cancel bytes and serves them as truth.
    // Terminal states are chain-anchored: CANCELLED, the cert outcome,
    // EXECUTING's reservation, CERTIFIED's issuance. The view must agree
    // with the ledger or scream (w38-http M-1).
    if (tenant !== null && record.capsule?.capsule_id) {
      const idx = this._auditIndex(tenant), cid = record.capsule.capsule_id, certId = idx.issuedCert.get(cid);
      const anchored = idx.cancelled?.has(cid) ? 'CANCELLED'
        : certId && idx.outcomes.has(certId) ? idx.outcomes.get(certId)
        : certId && idx.reserved.has(certId) ? 'EXECUTING'
        : certId ? 'CERTIFIED' : null;
      requireThat(anchored === null ? !['CANCELLED', 'CERTIFIED', 'EXECUTING', 'VERIFIED', 'UNCERTAIN', 'FAILED', 'COMPENSATED'].includes(record.status) : record.status === anchored, 'INV-409-INTEGRITY', 'Capsule status diverges from its ledger-anchored state', 409);
    }
    const redact = redactMaterialFields;
    if (view.capsule?.current_state?.material_fields) view.capsule.current_state = { ...view.capsule.current_state, material_fields: redact(view.capsule.current_state.material_fields) };
    // The signed intent envelope carries the proposal input verbatim — an
    // unredacted payload would re-expose every row (w6-fix F1). The served
    // copy is a projection; verification happens at attach time.
    const intent = view.capsule?.request_intent?.payload;
    if (intent?.current_state?.material_fields) intent.current_state = { ...intent.current_state, material_fields: redact(intent.current_state.material_fields) };
    if (intent?.requested_state?.material_fields) intent.requested_state = { ...intent.requested_state, material_fields: redact(intent.requested_state.material_fields) };
    return view;
  }
  // The resources route serves target state verbatim — registry material
  // fields get the same secret-name scrub the capsule view applies
  // (w38-http LOW).
  resourceStateView(state) {
    // The container was selected as sensitive: redact its projection for
    // every shape — a scalar or absent field must not pass verbatim
    // (w40-fv F-8).
    if (state && typeof state === 'object')
      return { ...state, material_fields: redactMaterialFields(state.material_fields) };
    return state;
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
      // A deleted idempotency receipt must not silently re-mint: the chain
      // anchored the first (key, request) bind, so an anchored same-request
      // replays to its live capsule and a divergent request dies exactly
      // like the receipt's hash mismatch would have (w30-store F4).
      const anchoredIdem = this._auditIndex(p.tenant_id).proposedIdem.get(idempotencyKey);
      if (anchoredIdem) {
        requireThat(ctEqual(anchoredIdem.request ?? '', digest(input)), 'INV-409-IDEMPOTENCY', 'Idempotency key reused for a different request', 409);
        const live = this.store.get(p.tenant_id, 'capsule', anchoredIdem.capsule_id);
        // A deleted capsule row whose PROPOSED anchor survives is tamper
        // unless the chain tombstoned it through retention shredding —
        // then it is an honest miss (w32-fixverify F-3).
        const tIdx = this._auditIndex(p.tenant_id);
        requireThat(live || !tIdx.proposedDigest.has(anchoredIdem.capsule_id) || tIdx.tombstones?.get(anchoredIdem.capsule_id)?.kind === 'capsule', 'INV-409-INTEGRITY', 'Anchored capsule row is missing — storage tamper', 409);
        requireThat(live, 'INV-404-NOT-FOUND', 'Capsule shredded — the idempotency receipt retains no plaintext', 404);
        return live;
      }
      const prior = this.store._stmt('SELECT capsule FROM nonces WHERE tenant=? AND nonce IN (?, ?)').get(p.tenant_id, 'capsule:' + input.nonce, input.nonce);
      // The nonce table is a fast index, not the authority — deleting the
      // row cannot replay a nonce whose CAPSULE_PROPOSED already sits on the
      // signed chain (w11-redteam R10).
      requireThat(!prior && !this._auditIndex(p.tenant_id).proposedNonce.has(input.nonce), 'INV-409-REPLAY', 'Nonce is already bound to another action', 409);
      const capsule = { ...clone(input), request_intent: clone(requestIntent), capsule_id: randomUUID(), tenant_id: p.tenant_id, received_at: now };
      const record = { capsule, capsule_digest: digest(capsule), status: 'CANONICALISED', evidence: [], approvals: [], decision: null, certificate_id: null, created_at: now };
      this.store._landed(() => this.store._stmt('INSERT INTO nonces VALUES(?,?,?)').run(p.tenant_id, 'capsule:' + input.nonce, capsule.capsule_id), 'nonce burn');
      this.store.insert(p.tenant_id, 'capsule', capsule.capsule_id, record, now);
      this.store.audit(p.tenant_id, 'CAPSULE_PROPOSED', p.subject_id, capsule.capsule_id, { capsule_digest: record.capsule_digest, action_type: capsule.action.type, nonce: input.nonce, expires_at: capsule.expires_at, idem_key: idempotencyKey, idem_request: digest(input) }, now);
      return record;
    }, {
      // The receipt must not preserve plaintext the retention shredder
      // later destroys — store a redacted reference and resolve the LIVE
      // record on replay (w28-crypto F1).
      project: r => ({ capsule_id: r.capsule.capsule_id, capsule_digest: r.capsule_digest, status: r.status }),
      resolve: stored => {
        // Receipts written before this scheme still hold the full record —
        // honour them as stored.
        if (stored?.capsule !== undefined) return stored;
        let live = null;
        try { live = this.store.get(p.tenant_id, 'capsule', stored?.capsule_id); } catch { /* shredded or unreadable */ }
        const rIdx = this._auditIndex(p.tenant_id);
        requireThat(live || !(stored?.capsule_id && rIdx.proposedDigest.has(stored.capsule_id) && rIdx.tombstones?.get(stored.capsule_id)?.kind !== 'capsule'), 'INV-409-INTEGRITY', 'Anchored capsule row is missing — storage tamper', 409);
        requireThat(live, 'INV-404-NOT-FOUND', 'Capsule shredded — the idempotency receipt retains no plaintext', 404);
        return live;
      }
    }));
  }
  // A file-writer deleting a row whose id the signed chain anchors must
  // surface as tamper evidence, not an ordinary miss — get() first, then
  // upgrade absent-but-anchored to INV-409 (w30-store F5).
  _mustAnchored(tenant, kind, id) {
    const row = this.store.get(tenant, kind, id);
    if (row !== null) return row;
    const idx = this._auditIndex(tenant);
    // The anchored-kinds map must cover every chain-anchored record kind —
    // otherwise deleting a coverage path, a ceremony, a perception session,
    // a capability or a JIT grant still reads as an ordinary miss while its
    // anchor persists on the signed chain (w31-fixverify F3). A tombstoned
    // evidence row is a legitimately-shredded resource: its absence must
    // read INV-404, never tamper (w31-fixverify F4).
    const anchored = (kind === 'capsule' && idx.proposedDigest.has(id) && idx.tombstones?.get(id)?.kind !== 'capsule')
      || (kind === 'certificate' && idx.issuedCerts.has(id))
      || (kind === 'evidence' && idx.evidenceIds.has(id) && !(idx.tombstones?.has(id)))
      || (kind === 'coverage' && (idx.coverageDeclared?.has(id) || idx.coverageAnchors?.has(id)) && idx.tombstones?.get(id)?.kind !== 'coverage')
      || (kind === 'ceremony' && (idx.ceremonyPlanned?.has(id) || idx.ceremonyCommitted?.has(id) || idx.ceremonyCompleted?.has(id) || idx.ceremonyAborted?.has(id)))
      || (kind === 'perception-session' && idx.perceptionSessions?.has(id))
      || (kind === 'capability' && idx.capabilities?.has(id))
      || (kind === 'jit-grant' && idx.grants?.has(id))
      || (kind === 'policy' && id === 'active' && idx.policyAnchors.length > 0)
      || (kind === 'config-snapshot' && id === 'current' && idx.configSnapshot !== null);
    requireThat(!anchored, 'INV-409-INTEGRITY', `Anchored ${kind} row is missing — storage tamper`, 409);
    requireThat(false, 'INV-404-NOT-FOUND', 'Resource not found', 404);
  }
  ensureMutable(record) { requireThat(!['DENY', 'CANCELLED', 'CERTIFIED', 'EXECUTING', 'VERIFIED', 'UNCERTAIN', 'FAILED', 'COMPENSATED'].includes(record.status), 'INV-409-STATE', 'Action is immutable in its current state', 409); }
  // Supersession is derived from attach ORDER on the chain — the stored
  // superseded_by flag is only a cache; a later same-issuer+kind envelope
  // retires a non-conflict predecessor (mirrors attachEvidence semantics).
  // rows: [{ id, e }] — e is the live evidence row or null when deleted.
  _supersededMap(t, rows) {
    // A dead member's attach family comes from the anchored
    // RETENTION_DELETED event — the mutable tomb row may not redefine it
    // (w23-fixverify F-e). Unanchored identity claims read as unknown.
    const tombId = x => x.e ? null : this._auditIndex(t).tombstones?.get(x.id);
    const kindOf = x => x.e ? x.e.envelope?.payload?.kind : tombId(x)?.kind;
    const kidOf = x => x.e ? x.e.envelope?.protected?.key_id : tombId(x)?.key_id;
    const superseded = new Map();
    // The issuer's LATEST signed statement wins for its own kind — including
    // a supports envelope that retracts an earlier conflict. A veto only
    // stays sticky against a DIFFERENT issuer (w11-lifecycle F4). Only a
    // LIVE signed envelope may supersede: a tombstoned member's mutable
    // tomb row can lie about kind/key_id to un-supersede itself under the
    // issuer's own newer attach (dead-supersedes-live — w23-fixverify F-e).
    // The issuer's freshest SIGNED claim wins, not the latest attach — a
    // stale `supports` re-attached after a newer `conflict` can never
    // retract the fresher veto (w25-issuerd W25-F1). Ties on acquired_at
    // break toward the later attach so a same-timestamp re-issue still
    // supersedes deterministically; a tomb (no signed time) loses to any
    // live family member.
    const acqOf = (y) => y.e?.envelope?.payload?.acquired_at ?? -Infinity;
    const better = (a, ai, b, bi) => { const ab = acqOf(a), bb = acqOf(b); return bb > ab || (bb === ab && bi > ai); };
    rows.forEach((x, i) => { if (kindOf(x) !== undefined) { let wi = -1; rows.forEach((y, j) => { if (y.e && kindOf(y) === kindOf(x) && kidOf(y) === kidOf(x) && (wi < 0 || better(rows[wi], wi, y, j))) wi = j; }); if (wi >= 0 && wi !== i) superseded.set(x.id, rows[wi].id); } });
    return superseded;
  }
  graph(t, record, policy = null) {
    // Set membership is ledger-derived, not read off the mutable capsule
    // record: only envelopes whose EVIDENCE_ATTACHED event sits on the
    // signed chain count — deleting an id from record.evidence or planting
    // one changes nothing (w11-redteam R3/R15).
    // One index fold serves the whole graph pass: the folded revocation
    // and drift sets cannot change mid-map on this connection, and a
    // per-item _auditIndex probe was most of evaluate()'s call cost
    // (w43-perf). Semantics unchanged — same anchored set, read once.
    const gIdx = this._auditIndex(t);
    const attachedIds = gIdx.attached.get(record.capsule.capsule_id) ?? [];
    // Evidence-binding rules come from the POLICY UNDER EVALUATION — a
    // simulation must test the candidate constitution's bindings, not
    // silently evaluate under the active one (w23-policy F9).
    const bindingPolicy = policy ?? this.policy(t);
    const rows = attachedIds.map(id => this.store.get(t, 'evidence', id) ? { id, e: this.store.get(t, 'evidence', id) } : { id, e: null });
    const superseded = this._supersededMap(t, rows);
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
        const bindings = (bindingPolicy.rules[record.capsule.action.type]?.evidence_bindings ?? {})[e.envelope.payload.kind] ?? {};
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
      return { ...e, binding_failed, superseded_by: superseded.get(id) ?? null, revoked: gIdx.revoked.has(`evidence:${id}`) || gIdx.revoked.has(`issuer:${e.envelope.protected.key_id}`) || gIdx.revoked.has(`key:${e.envelope.protected.key_id}`), drifted: gIdx.issuerDrift.has(e.envelope.protected.key_id), issuer: semantic };
    });
    const graph_digest = digest(items.map(e => ({ envelope_digest: digest(e.envelope), issuer_digest: digest(e.issuer), revoked: e.revoked })).sort((a, b) => a.envelope_digest < b.envelope_digest ? -1 : 1));
    return { items, digest: graph_digest };
  }
  attachEvidence(p, id, envelope) {
    this.authorize(p, ['operator', 'security', 'policy_admin']);
    return this.transaction(p, now => {
      const t = p.tenant_id, record = this._mustAnchored(t, 'capsule', id); this.ensureMutable(record);
      this._capsuleIntegrity(t, record);
      // Attaching wipes collected approvals by design (new evidence invalidates
      // the evaluation), so only the proposing actor may do it — a third party
      // must not grief another actor's capsule (HTTP-audit finding).
      requireThat(record.capsule.actor.subject_id === p.subject_id, 'INV-403-SCOPE', 'Only the proposing actor may attach evidence', 403);
      this.assertHealthy(t, record.capsule.actor.subject_id, record.capsule.actor.device_id, now);
      const payload = this.verifyEvidenceEnvelope(t, envelope, record.capsule.action.type);
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
      // Supersession follows the signed acquired_at ordering the eval graph
      // already enforces — a stale envelope may attach but can only retire
      // predecessors at least as old as itself; it can never retract a
      // fresher claim (w25-issuerd W25-F1). When the new envelope is itself
      // the stale one, mark it superseded by the freshest live predecessor.
      let staleUnder = null;
      for (const eid of attached) {
        const e = this.store.get(t, 'evidence', eid);
        if (e && !e.superseded_by && e.envelope?.protected?.key_id === envelope.protected.key_id && e.envelope?.payload?.kind === payload.kind && !this.revoked(t, 'issuer', e.envelope.protected.key_id) && !this.revoked(t, 'key', e.envelope.protected.key_id)) {
          if ((e.envelope?.payload?.acquired_at ?? -Infinity) <= (payload.acquired_at ?? -Infinity)) {
            e.superseded_by = payload.evidence_id;
            this.store.put(t, 'evidence', eid, e, now);
          } else if (!staleUnder || (e.envelope?.payload?.acquired_at ?? -Infinity) > (this.store.get(t, 'evidence', staleUnder)?.envelope?.payload?.acquired_at ?? -Infinity)) staleUnder = eid;
        }
      }
      // A declared registry version pins the envelope — omitting the field
      // can never skip the drift check (w18-issuerd F-8).
      requireThat(issuer.version === undefined || payload.issuer_version === issuer.version, 'INV-403-SCOPE', 'Issuer version drifted from registration', 403);
      this.store.insert(t, 'evidence', payload.evidence_id, { payload: clone(payload), envelope: clone(envelope), legal_hold: false, superseded_by: staleUnder }, now);
      record.evidence.push(payload.evidence_id); record.status = 'EVIDENCED'; record.approvals = []; record.decision = null;
      this.store.put(t, 'capsule', id, record, now); this.store.audit(t, 'EVIDENCE_ATTACHED', p.subject_id, id, { evidence_id: payload.evidence_id, evidence_digest: digest(envelope), expires_at: payload.expires_at }, now);
      return { evidence_id: payload.evidence_id, evidence_graph_digest: this.graph(t, record).digest };
    });
  }
  verifyEvidenceEnvelope(t, envelope, actionType = null) {
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
    // ceiling — the stricter of its evidence-kind and action-class ceilings
    // applies (w22-ledger).
    const retention = this.policy(t).retention;
    if (retention) {
      const ceiling = payload.acquired_at + Math.min(retention.per_kind?.[payload.kind] ?? retention.default_ms, actionType !== null ? (retention.per_action?.[actionType] ?? retention.default_ms) : retention.default_ms);
      requireThat(payload.retention_until <= ceiling, 'INV-400-SCHEMA', `Retention exceeds the policy ceiling for kind ${payload.kind}`, 400);
    }
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
    const t = p.tenant_id, record = this._mustAnchored(t, 'capsule', capsule_id);
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
        // Dependent paths match the drifted connector by DECLARED key_id
        // first — a renamed issuer keeps its key so the binding survives
        // (w31-coverage F8); the legacy name match stays for paths declared
        // before key binding existed. Paths page past the store cap (F9).
        const paths = this._allCoverage(p.tenant_id);
        const transitioned = applyDriftToPaths(paths, path => path.connector_key_id === key_id || (path.connector_key_id === undefined && path.target === issuer.name));
        for (const path of transitioned) this.coverageTransition(p.tenant_id, path, 'UNKNOWN', `connector-unreachable:${key_id}`, now);
        this.store.audit(p.tenant_id, 'CONNECTOR_DRIFT', p.subject_id, key_id, { drifted: 'unreachable', code: e.code ?? 'transport', coverage_paths_staled: transitioned.length }, now);
        if (transitioned.length) this.store.audit(p.tenant_id, 'COVERAGE_STALED', p.subject_id, key_id, { paths: transitioned.map(x => x.path_id) }, now);
        return { drifted: true, changes: [{ field: 'endpoint', detail: 'unreachable' }], checked_at: now, coverage_paths_staled: transitioned.length };
      });
    }
    let observedPayload;
    try {
      // verifyManifest runs the shared contract — signature, schema,
      // expiry, issued-at sanity and the declared freshness floor (a
      // manifest minted before the window replays stale issuer state as
      // "no drift", w9-network F8). The suite gate and the signed-horizon
      // cap stay gate-side (w20-fixverify F-15).
      observedPayload = verifyManifest(observed, { [key_id]: issuer }, this.clock(), { max_age_ms: 300000 });
      this.assertSuiteAllowed(p.tenant_id, observed.protected.suite);
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
    // Registered baseline: only fields the stored config actually declares
    // may compare — an undeclared baseline records the observed value
    // informationally instead of false-drifting every pre-upgrade tenant
    // (w21-fixverify M-3). The spec pin is the EFFECTIVE pin: a governed
    // anchored ISSUER_SPEC_REPINNED supersedes the frozen registration
    // digest — honest issuer record-set changes are re-provisioned through
    // repinIssuerSpec, never file surgery (w49-ledger F4).
    const registered = { connector_id: `issuer:${issuer.name}`, version: issuer.version ?? '1.0.0', actions: issuer.kinds, channel: issuer.channel, key_id, permissions: issuer.permissions, limitations: issuer.limitations, idempotency: issuer.idempotency, coverage_implications: issuer.coverage_implications, spec_digest: this._auditIndex(p.tenant_id).issuerRepins?.get(key_id) ?? issuer.spec_digest };
    const result = driftCheck(registered, { connector_id: observedPayload.connector_id, version: observedPayload.version, actions: observedPayload.actions, channel: observedPayload.domain, key_id: observed.protected.key_id, permissions: observedPayload.permissions, limitations: observedPayload.limitations, idempotency: observedPayload.idempotency, coverage_implications: observedPayload.coverage_implications, spec_digest: observedPayload.spec_digest }, this.clock());
    return this.transaction(p, now => {
      // A clean re-check clears the suspension; a drifted one records it and
      // stops the issuer's evidence until then (MED-2).
      this.store.remove(p.tenant_id, 'issuer-drift', key_id);
      if (!result.drifted) { this.store.audit(p.tenant_id, 'CONNECTOR_REVALIDATED', p.subject_id, key_id, { configuration_digest: result.configuration_digest }, now); return result; }
      this.store.put(p.tenant_id, 'issuer-drift', key_id, { drifted_at: now, changes: result.changes }, now);
      // COV-004/CON-006 consequence: paths depending on the drifted connector
      // lose their observation evidence and fall to UNKNOWN until revalidated.
      // Each transition emits a coverage event and an owner task (COV-005/009).
      const paths = this._allCoverage(p.tenant_id);
      const transitioned = applyDriftToPaths(paths, path => path.connector_key_id === key_id || (path.connector_key_id === undefined && path.target === issuer.name));
      for (const path of transitioned) this.coverageTransition(p.tenant_id, path, 'UNKNOWN', `connector-drift:${key_id}`, now);
      this.store.audit(p.tenant_id, 'CONNECTOR_DRIFT', p.subject_id, key_id, { changes: result.changes, configuration_digest: result.configuration_digest, coverage_paths_staled: transitioned.length }, now);
      if (transitioned.length) this.store.audit(p.tenant_id, 'COVERAGE_STALED', p.subject_id, key_id, { paths: transitioned.map(x => x.path_id) }, now);
      return { ...result, coverage_paths_staled: transitioned.length };
    });
  }
  // The governed re-provisioning path the spec pin exists for: a
  // legitimate issuer record-set change is indistinguishable from file
  // tampering at the digest level, so the new content is re-pinned ON THE
  // CHAIN by an authorized principal rather than edited into the frozen
  // registration. The anchored ISSUER_SPEC_REPINNED is the authority the
  // drift check consults — restart-consistent by construction
  // (w49-ledger F4).
  async repinIssuerSpec(p, key_id) {
    this.authorize(p, ['security']);
    const issuer = this.tenant(p.tenant_id).issuers[key_id];
    requireThat(issuer?.endpoint, 'INV-404-NOT-FOUND', 'Issuer endpoint not found', 404);
    // The re-pin binds what the issuer ACTUALLY serves — the verified
    // manifest's own spec_digest — never a caller-supplied digest: an
    // operator pinning bytes the issuer does not serve would re-pin the
    // drift it is meant to clear (w49-ledger F4).
    let observed;
    try { const res = await readWithRetry(`${issuer.endpoint}/v1/issuers/${issuer.name}/manifest?tenant=${p.tenant_id}`, { timeout_ms: 10000, retries: 2, headers: (issuer.read_token ?? issuer.issue_token) ? { Authorization: `Bearer ${issuer.read_token ?? issuer.issue_token}` } : undefined }); observed = res.data; }
    catch (e) { throw new InvariantError('INV-503-CONNECTOR', `Issuer unreachable — cannot observe the spec to re-pin: ${e?.message ?? 'transport error'}`, 503, { cause: e }); }
    let observedPayload;
    try {
      observedPayload = verifyManifest(observed, { [key_id]: issuer }, this.clock(), { max_age_ms: 300000 });
      this.assertSuiteAllowed(p.tenant_id, observed.protected.suite);
    } catch (e) {
      if (e instanceof InvariantError) throw e;
      throw new InvariantError('INV-401-CONNECTOR', 'Issuer manifest failed verification — refusing to pin unproven content', 401, { cause: e });
    }
    const next = observedPayload.spec_digest;
    requireThat(typeof next === 'string' && next.length > 0, 'INV-409-INTEGRITY', 'Issuer manifest carries no spec digest to pin', 409);
    const idx = this._auditIndex(p.tenant_id);
    const prior = idx.issuerRepins?.get(key_id) ?? issuer.spec_digest;
    requireThat(next !== prior, 'INV-409-CONFLICT', 'Issuer spec digest already pinned — nothing to re-provision', 409);
    return this.transaction(p, now => {
      this.store.audit(p.tenant_id, 'ISSUER_SPEC_REPINNED', p.subject_id, key_id, { spec_digest: next, prior_digest: prior ?? null }, now);
      // The re-pin settles the drift row honestly — the next drift check
      // compares the observed digest against this anchored pin.
      this.store.remove(p.tenant_id, 'issuer-drift', key_id);
      return { repinned: true, key_id, prior_digest: prior ?? null, spec_digest: next };
    });
  }
  approvalChallenge(p, id, signer_id = null) {
    this.authorize(p, ['approver', 'custodian']); const r = this._mustAnchored(p.tenant_id, 'capsule', id); this.ensureMutable(r);
    if (signer_id !== null) text(signer_id, 'signer_id', 128);
    // The caller may pin WHICH of their enrolled keys signs — canonical
    // ordering must not silently choose a key the caller's hardware cannot
    // reach (w30-policy F4a).
    const now = this.clock(), key = Object.entries(this.identities(p.tenant_id)).find(([kid, v]) => v.subject_id === p.subject_id && (signer_id === null || kid === signer_id));
    requireThat(key, 'INV-404-NOT-FOUND', 'No enrolled signing key for this subject', 404);
    // Device quarantine applies on the approval plane too (runtime-audit F-10).
    this.assertHealthy(p.tenant_id, p.subject_id, this.identity(p).device_id, now);
    return { tenant_id: p.tenant_id, capsule_id: id, capsule_digest: r.capsule_digest, evidence_graph_digest: this.graph(p.tenant_id, r).digest, policy_digest: this._policyDigest(p.tenant_id), signer_id: key[0], approved_at: now, expires_at: Math.min(now + 300000, r.capsule.expires_at) };
  }
  approve(p, envelope) {
    this.authorize(p, ['approver', 'custodian']);
    return this.transaction(p, now => {
      const identity = this.identity(p), capsuleId = verifySigned(envelope, this.identities(p.tenant_id), 'action-approval').capsule_id, accepted = this.approveInner(p, capsuleId, envelope, now);
      return { accepted: true, software_key: !identity.hardware_backed, approvals: accepted.approvals };
    });
  }
  evaluation(t, record, now, policy = this.policy(t)) {
    const graph = this.graph(t, record, policy), identities = this.identities(t);
    if (record.capsule.action.type === 'policy.change') {
      const candidateDigest = digest(record.capsule.requested_state.policy);
      // Simulation freshness (policy-audit F11): 'reviewed' means reviewed
      // RECENTLY — a simulation older than an hour cannot authorise a
      // constitution change.
      // 'reviewed' is chain-anchored, not a mutable simulation row — a
      // planted record can never satisfy the gate (w13-fixverify M2).
      const reviewed = this._auditIndex(t).simulated.some(s => s.candidate_digest === candidateDigest && s.baseline_digest === this._policyDigest(t) && s.at > now - 3600000);
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
        // Certified-ness and binding are anchored, never mutable row state:
        // the child must carry an unspent chain-attested certificate and
        // must not already be bound under a live composite parent — a
        // second live parent would consume the sibling-bound cert and
        // brick the first verdict-less (w24-lifecycle W24-3/W24-4).
        const caid = this._auditIndex(t), childCertId = caid.issuedCert.get(childId);
        const childCertAnchored = caid.issued.has(childId) && childCertId !== undefined && !caid.outcomes.has(childCertId) && !caid.reserved.has(childCertId);
        if (!childCertAnchored) problems.push({ code: 'CHILD_STATE', child: childId, status: child.status });
        else if (this._boundLiveParents(t, caid, childId, now).filter(pid => pid !== record.capsule.capsule_id).length) problems.push({ code: 'CHILD_BOUND', child: childId });
        const cert = childCertId ? this.store.get(t, 'certificate', childCertId) : null;
        // A composite over an already-dead child certificate mints a parent
        // that can only bail — the dead child is an admission problem, not a
        // dispatch-time surprise (w8-composite F9). A planted consumed flag
        // on a live cert is tamper evidence, not a quiet admission veto.
        if (cert) this._certSpendIntegrity(t, caid, childCertId, cert);
        const cp = cert?.envelope?.payload;
        if (!cert || !cp || cp.issued_at > now || cp.expires_at <= now || this.revoked(t, 'certificate', cp.certificate_id)) problems.push({ code: 'CHILD_CERT', child: childId });
        else certs.push(cert);
      }
      if (problems.length) return { decision: 'ESCROW', reasons: problems.map(x => ({ code: x.code, message: `Composite child ${x.child}: ${x.code.toLowerCase().replace(/_/g, ' ')}${x.status ? ` (${x.status})` : ''}` })), explanation: 'Every child of a composite must be independently certified.', owner: record.capsule.actor.subject_id, expires_at: record.capsule.expires_at, evaluated_at: now, policy_version: policy.version, policy_digest: digest(policy), eligible_signers: [] };
    }
    // The approval's signed challenge binds the RECOMPUTED capsule digest —
    // an approval granted over a capsule that has since been rewritten
    // (with a synced stored digest) must silently drop out (w11 F2).
    const capsuleDigest = this._capsuleDigestOf(record), policyDigest = this._policyDigest(t, policy);
    const approvals = record.approvals.filter(a => a.payload.policy_digest === policyDigest && a.payload.evidence_graph_digest === graph.digest && a.payload.capsule_digest === capsuleDigest).map(a => {
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
    return evaluatePolicy({ capsule: capsuleForEval, policy, evidence: graph.items.filter(e => !e.superseded_by && !e.binding_failed), approvals, identities, quarantined: this.revoked(t, 'subject', record.capsule.actor.subject_id) || this.revoked(t, 'device', record.capsule.actor.device_id), now, digests: { policy_digest: policyDigest, capsule_digest: capsuleDigest } });
  }
  evaluate(p, id) {
    this.authorize(p, ['operator', 'policy_admin', 'approver', 'custodian']);
    return this.transaction(p, now => {
      const record = this._mustAnchored(p.tenant_id, 'capsule', id); this.ensureMutable(record); this._capsuleIntegrity(p.tenant_id, record);
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
      const t = p.tenant_id, r = this._mustAnchored(t, 'capsule', id); this.ensureMutable(r); this._capsuleIntegrity(t, r);
      // Mint-state is ledger-derived: clearing the record field cannot
      // resurrect a second certificate — CERTIFICATE_ISSUED on the signed
      // chain is the authority (w11-redteam R8).
      const certIdx = this._auditIndex(t);
      // A planted certificate_id pointer while the chain attests no
      // issuance is tamper evidence, never a quiet replay refusal
      // (w24-lifecycle W24-3).
      requireThat(!(r.certificate_id && !certIdx.issued.has(id)), 'INV-409-INTEGRITY', 'Capsule carries a certificate pointer the ledger never issued', 409);
      requireThat(!certIdx.issued.has(id), 'INV-409-REPLAY', 'Action already has a certificate', 409);
      // Cancellation is a chain verdict: restoring the capsule row to a
      // pre-cancel image cannot mint fresh authority over it
      // (w32-composite F-1). Re-propose for a new action.
      requireThat(!certIdx.cancelled?.has(id), 'INV-409-STATE', 'Action was cancelled on the ledger — propose a fresh action', 409);
      this.assertFreshSnapshot(t, r.capsule);
      const decision = this.evaluation(t, r, now), policy = this.policy(t);
      requireThat(decision.decision === 'ALLOW', 'INV-412-EVIDENCE', 'Only ALLOW may receive an execution certificate', 412, decision);
      this.assertHealthy(t, r.capsule.actor.subject_id, r.capsule.actor.device_id, now);
      // Minting on behalf of another actor still requires the minting
      // principal's device to be healthy (w11-approval F6).
      if (p.subject_id !== r.capsule.actor.subject_id) this.assertHealthy(t, p.subject_id, this.identity(p).device_id, now);
      // A data.export certificate is only mintable when the watermark key
      // already exists — resolving it after irrevocable egress would wedge
      // the cert EXECUTING with the disclosure unattestable (w20-datagate
      // F3). Fail before the certificate exists, not after the journal.
      if (r.capsule.action.type === 'data.export') requireThat(this.dataKey(t, 'watermark'), 'INV-503-CONFIG', `Tenant ${t} has no watermark data key`, 503);
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
      if (r.capsule.action.type === 'action.composite') for (const childId of r.capsule.requested_state.children ?? []) { const child = this._mustAnchored(t, 'capsule', childId); child.composite_parents = [...new Set([...(child.composite_parents ?? []), id])]; this.store.put(t, 'capsule', childId, child, now); }
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
      const stored = this._mustAnchored(t, 'certificate', cert.certificate_id), record = this.store.get(t, 'capsule', cert.capsule_id);
      const idx = this._auditIndex(t);
      // A capsule the ledger attests as proposed but the store cannot
      // serve is destructive tampering — integrity, not a bare 404 that
      // erases the anchored lifecycle behind a missing-row error
      // (w29-lifecycle F5).
      requireThat(record || !idx.proposedDigest.has(cert.capsule_id), 'INV-409-INTEGRITY', 'Anchored capsule row is missing', 409);
      if (!record) this._mustAnchored(t, 'capsule', cert.capsule_id);
      this._capsuleIntegrity(t, record);
      requireThat(record.capsule.tenant_id === t, 'INV-403-SCOPE', 'Capsule tenant does not match the certificate tenant', 403);
      requireThat(digest(stored.envelope) === digest(envelope), 'INV-401-CERTIFICATE', 'Certificate does not match issued authority', 401);
      // Mutable lifecycle flags are advisory caches — a `consumed`/status
      // row value can never veto what the anchored folds attest, and a
      // contradicting flag is tamper evidence, not a replay verdict
      // (w24-lifecycle W24-3).
      this._certSpendIntegrity(t, idx, cert.certificate_id, stored);
      // Anchored issuance is admission, not a post-dispatch check: a cert
      // whose CERTIFICATE_ISSUED was cut by a seal (record rows survive a
      // seal) must never reserve and commit a real target mutation only to
      // wedge at finish (w29-lifecycle F4).
      requireThat(idx.issued.has(cert.capsule_id) && idx.issuedCert.get(cert.capsule_id) === cert.certificate_id, 'INV-401-CERTIFICATE', 'Certificate is not anchored as issued for this capsule', 401);
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
      // Consumption and cancellation are chain verdicts, not row state: a
      // flipped `consumed`/`status` pair can never un-spend or un-cancel
      // what the signed ledger already attested (w12-lifecycle F3).
      requireThat(!idx.outcomes.has(cert.certificate_id) && !idx.reserved.has(cert.certificate_id) && !idx.cancelled?.has(cert.capsule_id), 'INV-409-REPLAY', 'Certificate already consumed or cancelled on the ledger', 409);
      // Candidate parents come from the anchored membership map itself —
      // enumerating capsule rows would let a store writer delete the parent
      // row and unbind the child even though CERTIFICATE_ISSUED still
      // attests the binding (w16-fixverify F2). Terminal-ness resolves from
      // the anchored outcome of the anchored parent certificate — the
      // mutable parent row is never consulted. A parent cert that can
      // never legally fire — expired, revoked or its row murdered —
      // resolves the binding too (w24-lifecycle W24-4).
      requireThat(this._boundLiveParents(t, idx, record.capsule.capsule_id, now).filter(pid => pid !== record.capsule.capsule_id).length === 0, 'INV-409-STATE', 'Composite child certificates execute only through their parent', 409);
      // A quarantined actor or dispatcher is refused before evidence work —
      // the containment denial must land as INV-403, not as an evidence
      // miss (w9-network F6/F7).
      this.assertHealthy(t, record.capsule.actor.subject_id, record.capsule.actor.device_id, now);
      // The dispatching endpoint must be healthy too — a quarantined-device
      // principal cannot relay another actor's certificate (w9-network F6).
      if (p.subject_id !== record.capsule.actor.subject_id) this.assertHealthy(t, p.subject_id, this.identity(p).device_id, now);
      requireThat(record.capsule_digest === cert.capsule_digest && this.graph(t, record).digest === cert.evidence_graph_digest && this._policyDigest(t) === cert.policy_digest, 'INV-409-STATE', 'Action, evidence or policy changed', 409);
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
        const ridx2 = this._auditIndex(t);
        const recon = reconstructionCheck(this.store.db, this.target.db, { tenant: t, subject: record.capsule.actor.subject_id, dataset: req.dataset, rows: req.row_ids, columns: req.columns, now, policy: this.policy(t).runtime.reconstruction, record: false, access: ridx2.dataAccess, droppedEvents: ridx2.sealDroppedEvents ?? 0, sealDroppedAt: ridx2.sealDroppedAt ?? 0, verifiedRowCount: (dt, ds) => this._verifiedDatasetRows(dt, ds) });
        requireThat(recon.allowed, 'INV-429-BUDGET', 'Reconstruction limit reached', 429, { coverage_percent: recon.coverage_percent, dataset_coverage_percent: recon.dataset_coverage_percent });
      }
      if (dryRun || this.policy(t).mode === 'shadow') {
        // Dry runs are free per call — without a floor they amplify the
        // chain unboundedly: one marker row per cert per window keeps the
        // attestation cheap and honest (w22 F7).
        // The dedupe marker is the anchored EXECUTION_DRY_RUN fold — a
        // mutable last_at a row-writer could backdate would let every
        // call mint a fresh anchor (w24-lifecycle W24-3).
        const lastDry = idx.dryRunAt.get(cert.certificate_id);
        if (lastDry === undefined || now - lastDry >= 60000) {
          this.store.audit(t, 'EXECUTION_DRY_RUN', p.subject_id, cert.certificate_id, { no_mutation: true }, now);
        }
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
          // Anchored lifecycle + anchored spend: forged row flags can
          // neither fake a spend nor block a live ceremony — the ledger's
          // recorded lifecycle is the only consulted state
          // (w18-fixverify F2/F13).
          const cidx = this._auditIndex(t);
          requireThat(ceremony && ceremony.valid_until > now && ceremony.purpose === 'key.rotate'
            && !(cidx.ceremonyAborted?.has(req.ceremony_id) || cidx.ceremonyCompleted?.has(req.ceremony_id))
            && !cidx.ceremonyRotationConsumed?.has(req.ceremony_id), 'INV-409-STATE', 'key.rotate requires a live, unconsumed key.rotate ceremony', 409);
          requireThat(ceremony.rotation?.key_class === req.key_class && ceremony.rotation?.new_key_id === req.new_key_id, 'INV-403-SCOPE', 'Ceremony is not bound to this rotation', 403);
          // The quorum bond needs an ANCHORED plan and positive live
          // consent — `live >= threshold` alone reads both operands off
          // the mutable row and a planted threshold:0 row satisfies 0>=0
          // (w19-lifecycle F1).
          const rotationQuorum = this.custodianQuorum(t, ceremony);
          requireThat(rotationQuorum.planAnchored && rotationQuorum.live >= Math.max(1, ceremony.threshold), 'INV-409-STATE', 'Ceremony lacks a live custodian quorum across failure domains', 409);
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
    // The journal's own clock is the dispatch instant, not the reservation
    // time — the wedge report must distinguish when the target actually
    // committed (w22 F9).
    const dispatchNow = this.clock();
    // The certificate must still be live at the DISPATCH instant — a cert
    // reserved at T but dispatched at T' ≥ expires_at would commit a real
    // mutation then wedge UNCERTAIN forever (w24-lifecycle W24-1). This is
    // a deterministic terminal refusal before any target write: the
    // consumed slot is spent either way, so it is not released.
    if (!(dispatchNow >= cert.issued_at && dispatchNow < cert.expires_at)) return this.finish(p, cert, null, 'FAILED', 'CERTIFICATE_EXPIRED_PRE_DISPATCH');
    let raw, dispatchError = null;
    // Dispatch intent anchors BEFORE the target write: the window between
    // the journal's own COMMIT inside target.execute and our journal read
    // is attacker-writable — a murdered journal must never look like a
    // never-dispatched reservation (w43-runtime C2). The intent marks the
    // dispatch as attempted; the EXECUTION_DISPATCHED row below still binds
    // the journal's digest.
    this.store.tx(() => this.store.audit(p.tenant_id, 'EXECUTION_INTENT', p.subject_id, cert.certificate_id, {}, dispatchNow));
    try { raw = this.target.execute(capsule, cert.certificate_id, dispatchNow, fault); }
    catch (e) { dispatchError = e; }
    // Dispatch is anchored on the signed chain the moment the durable
    // journal exists — including an after-commit fault whose journal
    // survived while its response was lost, so reconcile can honestly
    // confirm VERIFIED against the anchor. A planted journal without the
    // anchored event can never mint VERIFIED (w12-provenance F16).
    const journal = this.target.outcome(p.tenant_id, cert.certificate_id);
    if (journal) this.store.tx(() => this.store.audit(p.tenant_id, 'EXECUTION_DISPATCHED', p.subject_id, cert.certificate_id, { journal_digest: digest(journal) }, dispatchNow));
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
    const executed = [], wedged = [], attemptedFailed = [];
    // Sibling egress overlay: children inside one composite dispatch
    // sequentially, so a later export child must see the earlier siblings'
    // egress in its coverage check — otherwise one composite can bypass
    // the reconstruction budget the per-child ledger fold never fed back
    // in time (w27-datagate F1).
    const siblingAccess = [];
    const bail = (reason) => {
      const compensations = [];
      // Compensation runs in reverse EXECUTION order; the executed array
      // itself must keep dispatch order for the signed ledger (M2).
      for (const done of [...executed].reverse()) {
        // A child already settled terminal — e.g. an outcome a reconcile
        // wrote before this bail ran — keeps its recorded verdict: it is
        // never compensated back into the parent's compensated:true list,
        // and the verdict fork is named instead of hidden (w22 F3).
        const priorOutcome = this.store.get(t, 'outcome', done.child.certificate_id);
        if (priorOutcome && ['VERIFIED', 'FAILED', 'COMPENSATED'].includes(priorOutcome.payload.status)) compensations.push({ capsule_id: done.child.capsule.capsule_id, compensated: false, settled: priorOutcome.payload.status });
        else compensations.push({ capsule_id: done.child.capsule.capsule_id, ...this.target.compensate(done.child.capsule, done.prior, this.clock(), done.child.certificate_id) });
      }
      return this.finishComposite(p, cert, capsule, executed, 'COMPENSATED', reason, compensations, this.clock(), wedged, attemptedFailed);
    };
    for (const childId of children) {
      let child, childCert, childNow;
      try {
        this.store.tx(() => {
          // Per-child authority is evaluated against a FRESH clock reading,
          // not the parent reservation time — wall clock may have advanced
          // across earlier child dispatches (concurrency-audit M1).
          childNow = this.clock(); this.store.clock(childNow);
          child = this._mustAnchored(t, 'capsule', childId);
          // Each child's stored capsule must still equal its chain-attested
          // proposal — a graft onto the child record (current_state or
          // action rewrite) fails before it can be dispatched under the
          // parent's composite authority (w13-timing M-3).
          this._capsuleIntegrity(t, child);
          const childStored = this._mustAnchored(t, 'certificate', child.certificate_id);
          childCert = childStored.envelope.payload;
          requireThat(!this.revoked(t, 'key', childStored.envelope.protected.key_id) && !this.revoked(t, 'certificate', childCert.certificate_id) && childCert.issued_at <= childNow && childCert.expires_at > childNow, 'INV-401-CERTIFICATE', 'Child certificate expired or revoked', 401);
          // Same anchored spend-truth as a standalone execute(): mutable
          // consumed/status flags are tamper evidence, never a veto, and
          // the ledger's reserved/outcome folds are the authority
          // (w24-lifecycle W24-3).
          const cidx = this._auditIndex(t);
          this._certSpendIntegrity(t, cidx, childCert.certificate_id, childStored);
          // A cancelled child capsule is dead authority regardless of what
          // its (possibly grafted) row claims — the chain verdict binds
          // (w32-composite F-1).
          requireThat(!cidx.outcomes.has(childCert.certificate_id) && !cidx.reserved.has(childCert.certificate_id) && !cidx.dispatched.has(childCert.certificate_id) && !cidx.cancelled?.has(childId), 'INV-409-REPLAY', 'Child certificate consumed or cancelled on the ledger', 409);
          requireThat(child.capsule_digest === childCert.capsule_digest && this.graph(t, child).digest === childCert.evidence_graph_digest && this._policyDigest(t) === childCert.policy_digest, 'INV-409-STATE', 'Child action, evidence or policy changed', 409);
          requireThat(this.evaluation(t, child, childNow).decision === 'ALLOW', 'INV-412-EVIDENCE', 'Child execution predicates no longer hold', 412);
          this.assertHealthy(t, child.capsule.actor.subject_id, child.capsule.actor.device_id, childNow);
          const state = child.capsule.action.type === 'secret.use' ? this.target.secretState(t, child.capsule.requested_state.secret_id) : this.target.state(t, child.capsule.action.target_resource);
          requireThat(state.version === child.capsule.current_state.version && state.digest === child.capsule.current_state.digest, 'INV-409-STATE', 'Child target state changed', 409);
          // A denied export child refuses before its cert is consumed —
          // same reservation-time rule as a standalone export (w10-datagate F3).
          if (child.capsule.action.type === 'data.export') {
            const req = child.capsule.requested_state;
            const cidx2 = this._auditIndex(t);
            const recon = reconstructionCheck(this.store.db, this.target.db, { tenant: t, subject: child.capsule.actor.subject_id, dataset: req.dataset, rows: req.row_ids, columns: req.columns, now: childNow, policy: this.policy(t).runtime.reconstruction, record: false, access: [...cidx2.dataAccess, ...siblingAccess], droppedEvents: cidx2.sealDroppedEvents ?? 0, sealDroppedAt: cidx2.sealDroppedAt ?? 0, verifiedRowCount: (dt, ds) => this._verifiedDatasetRows(dt, ds) });
            requireThat(recon.allowed, 'INV-429-BUDGET', 'Reconstruction limit reached', 429, { coverage_percent: recon.coverage_percent, dataset_coverage_percent: recon.dataset_coverage_percent });
            siblingAccess.push({ subject: child.capsule.actor.subject_id, dataset: req.dataset, row_ids: req.row_ids, columns: req.columns, at: childNow, certificate_id: childCert.certificate_id });
          }
          childStored.consumed = true; childStored.status = 'EXECUTING'; childStored.transaction_id = childCert.certificate_id;
          child.status = 'EXECUTING';
          this.store.put(t, 'certificate', childCert.certificate_id, childStored, childNow); this.store.put(t, 'capsule', childId, child, childNow);
          this.store.audit(t, 'EXECUTION_RESERVED', p.subject_id, childCert.certificate_id, { capsule_digest: childCert.capsule_digest, composite_child_of: cert.certificate_id }, childNow);
        });
      } catch (e) {
        // Tamper-evidence and integrity codes are NEVER a child verdict:
        // laundering them into a bail reason writes a signed COMPENSATED
        // verdict over siblings an attacker chose to attack — propagate
        // instead and let reconcile settle the parent honestly
        // (w32-composite F-3).
        if (e?.code && (/^INV-409-(INTEGRITY|AUDIT-TAMPER)/.test(e.code) || /^INV-503-/.test(e.code))) throw e;
        return bail(`CHILD_REVALIDATION_FAILED:${e.code ?? 'UNKNOWN'}`);
      }
      // The journal's own clock is the dispatch instant, not the
      // reservation time — the wedge-report "executed_at" must distinguish
      // when the target actually committed (w22 F9).
      const dispatchNow = this.clock();
      // The child certificate must still be live at ITS dispatch instant —
      // composite dispatches accumulate earlier children's wall time, so a
      // child checked at reservation can cross expiry before its write:
      // deterministic terminal refusal, no target mutation (w24 W24-2).
      if (!(dispatchNow >= childCert.issued_at && dispatchNow < childCert.expires_at)) {
        try { this.finish(p, childCert, null, 'FAILED', 'CERTIFICATE_EXPIRED_PRE_DISPATCH'); attemptedFailed.push(childId); } catch { /* bail proceeds regardless */ }
        return bail('CHILD_EXECUTION_FAILED:CERTIFICATE_EXPIRED_PRE_DISPATCH');
      }
      let raw, dispatchError = null;
      // Pre-dispatch intent anchor — same window, same murder defence as
      // the standalone path: intent + no journal + no dispatch anchor is a
      // named wedge, never 'releasable' (w43-runtime C2).
      this.store.tx(() => this.store.audit(t, 'EXECUTION_INTENT', p.subject_id, childCert.certificate_id, { composite_child_of: cert.certificate_id }, dispatchNow));
      try { raw = this.target.execute(child.capsule, childCert.certificate_id, dispatchNow, fault); }
      catch (e) { dispatchError = e; }
      // Same dispatch anchor as a standalone: any durable journal is
      // attested on the chain, so a wedged child can be honestly settled
      // later while a planted journal can never mint VERIFIED
      // (w12-provenance F16).
      const childJournal = this.target.outcome(t, childCert.certificate_id);
      if (childJournal) this.store.tx(() => this.store.audit(t, 'EXECUTION_DISPATCHED', p.subject_id, childCert.certificate_id, { journal_digest: digest(childJournal), composite_child_of: cert.certificate_id }, dispatchNow));
      if (dispatchError instanceof InvariantError) {
        // A deterministic refusal is a FAILED child outcome, honestly
        // recorded — same rule as a standalone execution (runtime-audit F-9).
        // It is also an ATTEMPTED child: the parent report must not label a
        // refused dispatch NOT_ATTEMPTED next to its FAILED row (w22 F9).
        try { this.finish(p, childCert, null, 'FAILED', dispatchError.code ?? 'INV-500'); attemptedFailed.push(childId); } catch { /* bail must proceed regardless */ }
        return bail(`CHILD_EXECUTION_FAILED:${dispatchError.code ?? 'UNKNOWN'}`);
      }
      if (dispatchError) {
        // The reservation committed but the dispatch did not conclude: the
        // child is honestly wedged (EXECUTING, reconcilable later) and the
        // parent outcome must name it rather than understate the loss (M2).
        // A wedged export with a durable journal may already have egressed
        // rows — attest the pending disclosure or it stays invisible
        // (w27-datagate F2).
        // The touch is observability — a fold or lock fault inside it must
        // never swallow the wedged-outcome record (w28-fixverify F6).
        if (child.capsule.action.type === 'data.export' && childJournal) { try { this._touchWedgedEgress(t, child, childCert, dispatchNow, childJournal); } catch { /* bail proceeds regardless */ } }
        wedged.push(childId);
        return bail(`CHILD_EXECUTION_FAILED:${dispatchError.code ?? 'UNKNOWN'}`);
      }
      // A child's reply earns VERIFIED only under the same response rules as
      // a standalone execution (runtime-audit F-2).
      if (!this._validateTargetResponse(child, childCert, raw, this.clock(), { postRead: true }).valid) {
        if (child.capsule.action.type === 'data.export' && childJournal) { try { this._touchWedgedEgress(t, child, childCert, dispatchNow, childJournal); } catch { /* bail proceeds regardless */ } }
        wedged.push(childId);
        return bail('CHILD_EXECUTION_FAILED:TARGET_RESPONSE_INVALID');
      }
      executed.push({ child, raw, prior: child.capsule.current_state.material_fields });
    }
    return this.finishComposite(p, cert, capsule, executed, 'VERIFIED', 'CHILDREN_VERIFIED', [], this.clock());
  }
  finishComposite(p, cert, capsule, executed, status, reason, compensations, execNow, wedged = [], attemptedFailed = []) {
    const post = [];
    const envelope = this.transaction(p, now => {
      const t = p.tenant_id, r = this._mustAnchored(t, 'capsule', cert.capsule_id), stored = this._mustAnchored(t, 'certificate', cert.certificate_id);
      this._certSpendIntegrity(t, this._auditIndex(t), cert.certificate_id, stored);
      requireThat(this._auditIndex(t).reserved.has(cert.certificate_id), 'INV-409-STATE', 'Certificate was never reserved for execution', 409);
      this._capsuleIntegrity(t, r);
      // The composite parent certificate re-proves itself like any other:
      // signed under an attested execution key, chain-anchored at issuance,
      // and the caller-presented payload equal to the issued payload
      // (w13-store F1).
      const issuedParent = verifySigned(stored.envelope, this.executionPublic(t), 'action-certificate');
      requireThat(this._auditIndex(t).issued.has(cert.capsule_id) && digest(cert) === digest(issuedParent), 'INV-401-CERTIFICATE', 'Presented certificate does not match the issued authority', 401);
      const existing = this.store.get(t, 'outcome', cert.certificate_id);
      // Terminality is anchored, not row-derived: an EXECUTION_OUTCOME
      // event attests the verdict, so a deleted served row is integrity
      // evidence — never a fresh chance to re-fire effects and demote the
      // anchored verdict (w29-lifecycle F2).
      const anchoredOutcome = this._auditIndex(t).outcomes.get(cert.certificate_id);
      requireThat(existing || !['VERIFIED', 'FAILED', 'COMPENSATED'].includes(anchoredOutcome), 'INV-409-INTEGRITY', 'Anchored terminal outcome lost its served row — restore before reconciling', 409);
      // A planted terminal outcome must scream INTEGRITY, not wedge the cert
      // behind a state check (w13-fixverify L6).
      if (existing) this._outcomeIntegrity(t, existing, cert.certificate_id);
      requireThat(!existing || !['VERIFIED', 'FAILED', 'COMPENSATED'].includes(existing.payload.status), 'INV-409-STATE', 'A terminal execution outcome cannot be overwritten', 409);
      // Compensation is claimed only where it actually ran — a refused or
      // never-attempted unwind makes the outcome honestly FAILED, not
      // COMPENSATED (w8-composite F1).
      // A claimed compensation is attested only when the target journaled
      // it — the durable comp:<certId> row proves the unwind ran, and the
      // chain anchors it so a later reconcile settles from journal+anchor
      // rather than an in-memory array (w22 F4).
      for (const c of compensations ?? []) {
        if (c.compensated !== true) continue;
        // The child's certificate resolves from the anchored index, never
        // the mutable capsule.certificate_id pointer — a repointed row
        // must not name a foreign live cert for release/attestation
        // (w23-fixverify F-b/F-c).
        const ccId = this._auditIndex(t).issuedCert.get(c.capsule_id);
        const cRow = this.store.get(t, 'capsule', c.capsule_id);
        const compJournal = ccId ? this.target.outcome(t, `comp:${ccId}`) : null;
        // Presence alone does not attest: the journal must bind THIS
        // child's capsule digest — a donor compensate() binding a foreign
        // capsule is evidence of nothing for this child.
        if (compJournal && cRow && compJournal.capsule_digest === digest(cRow.capsule)) { c.attested = true; this.store.audit(t, 'EXECUTION_COMPENSATED', p.subject_id, ccId, { capsule_id: c.capsule_id, journal_digest: digest(compJournal) }, now); }
        else { c.compensated = false; c.reason = 'COMPENSATION_UNJOURNALED'; }
      }
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
        const childRecord = this._mustAnchored(t, 'capsule', childCapsuleId), childStored = this._mustAnchored(t, 'certificate', done.child.certificate_id);
        const childCertId = childStored.envelope.payload.certificate_id;
        const priorOutcome = this.store.get(t, 'outcome', childCertId);
        // A planted child outcome must scream INTEGRITY, not silently skip
        // post-effects while the parent attests success (w13-fixverify H2).
        if (priorOutcome) this._outcomeIntegrity(t, priorOutcome, childCertId);
        const settledTerminal = priorOutcome && ['VERIFIED', 'FAILED', 'COMPENSATED'].includes(priorOutcome.payload.status);
        // A journaled unwind outranks a parent UNCERTAIN: the child
        // honestly settles COMPENSATED instead of ratcheting UNCERTAIN
        // over already-reverted resources (w22 F4).
        let childStatus = compensatedIds.has(childCapsuleId) ? 'COMPENSATED' : status === 'VERIFIED' ? 'VERIFIED' : status === 'UNCERTAIN' ? 'UNCERTAIN' : 'FAILED';
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
          // Same crash-gap split as finish(): an unanchored journal demotes
          // to honest FAILED; a mismatched anchor is tamper evidence (w22 F1).
          const childJournal = this.target.outcome(t, childCertId);
          requireThat(childJournal && digest(childJournal) === digest(done.raw), 'INV-409-INTEGRITY', 'Child journal diverged from the recorded dispatch', 409);
          const childAnchored = this._auditIndex(t).dispatched.get(childCertId);
          if (childAnchored === undefined) {
            // The crash-gap verdict only applies to a journal written
            // inside the reservation window — a planted journal outside
            // it is tamper evidence, not a settleable FAILED
            // (w23-fixverify F-a).
            const reservedAt = this._auditIndex(t).reservedAt?.get(childCertId);
            requireThat(reservedAt !== undefined && childJournal.execution_time >= reservedAt && childJournal.execution_time - reservedAt <= 60000, 'INV-409-INTEGRITY', 'Unanchored child journal outside the reservation window — tamper evidence', 409);
            status = 'FAILED'; reason = 'DISPATCH_UNATTESTED'; childStatus = 'FAILED';
          }
          else requireThat(childAnchored === digest(childJournal), 'INV-409-INTEGRITY', 'Child outcome lacks a ledger-anchored dispatch', 409);
        }
        if (status === 'VERIFIED' && childStatus === 'VERIFIED' && !settledTerminal) {
          const childJournal = this.target.outcome(t, childCertId);
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
          const childPayload = { certificate_id: childCertId, capsule_digest: childStored.envelope.payload.capsule_digest, target_transaction_id: childCertId, observed_state_digest: done.raw?.observed_state_digest ?? null, status: childStatus, reason: childStatus === status ? reason : `PARENT_${status}:${reason}`, execution_time: done.raw?.execution_time ?? execNow, reconciliation_evidence: done.raw ? digest(done.raw) : null, journal_digest: done.raw ? digest(done.raw) : null, simulation: true, output: null, watermarks: extras?.watermarks ?? null, gate_denied: extras?.gate_denied?.detail ?? null, composite_child_of: cert.certificate_id, supersedes: priorOutcome ? digest(priorOutcome) : null };
          this.store.put(t, 'outcome', childCertId, this.signAudit(t, childPayload, 'outcome'), now);
        }
      }
      // A reserved child whose dispatch never committed a journal is
      // released back to CERTIFIED inside this terminal write — nothing
      // durable ran to roll back, and the reservation must not burn a
      // live, approved action forever (w22 F2). A journaled wedge keeps
      // its reservation: it may still reconcile to a real verdict.
      for (const childId of wedged) {
        // Anchored binding, never the mutable row pointer — a repointed
        // wedged child must not free a foreign cert's live reservation
        // under a vault-signed EXECUTION_RELEASED (w23-fixverify F-b).
        const wc = this.store.get(t, 'capsule', childId), wcertId = this._auditIndex(t).issuedCert.get(childId);
        const wstored = wcertId ? this.store.get(t, 'certificate', wcertId) : null;
        // A wedged export child whose dispatch reached the chain but whose
        // journal is gone attests its declared worst-case selection — the
        // murdered-journal window must never leave the disclosure
        // unattested while the child stays wedged (w43-runtime C2).
        if (wc && wcertId && wc.capsule.action.type === 'data.export' && !this.target.outcome(t, wcertId)
          && (this._auditIndex(t).dispatched.has(wcertId) || this._auditIndex(t).intended?.has(wcertId)))
          try { this._attestMurderedEgress(t, wc.capsule, wstored?.envelope?.payload ?? { certificate_id: wcertId }, now); } catch { /* bail proceeds regardless */ }
        // Anchored spend-truth: a wedged child releases only while the
        // ledger still attests its reservation with no journal and no
        // outcome — the mutable consumed flag never casts the deciding
        // vote, and a contradicting flag screams (w24-lifecycle W24-3).
        if (wstored) this._certSpendIntegrity(t, this._auditIndex(t), wcertId, wstored);
        // Anchored dispatch outranks the mutable journal probe: a deleted
        // transactions row can never make a dispatched cert look
        // never-run (w24-fixverify W24-02). But the crash-gap works both
        // ways: the journal is attacker-DELETABLE, so 'reserved + no
        // anchor + no journal' cannot alone prove the mutation never
        // committed. The pre-state compare below only guards the
        // intent-less residue (chains predating intent anchoring) — under
        // rewindable ciphertext it cannot vouch alone (w32-composite F-2).
        // Anchored dispatch-intent outranks every never-ran proof: an
        // anchored EXECUTION_INTENT attests the dispatch was attempted —
        // its journal and post-fact anchors may have been murdered — so
        // the child can never release under 'reserved_not_dispatched'.
        // (w44-seal F-1). The chain anchors alone decide release: under an
        // intact chain 'reserved without intent/dispatch/outcome' can only
        // mean dispatch never started — a murdered anchor wedges the fold
        // long before this code runs, so the set cannot lie. The pre-state
        // oracle the mutating arm consulted (target version + digest) is
        // gone entirely: it is attacker-rewindable ciphertext that can
        // always present 'never ran', and under an intact chain it adds no
        // truth the anchors do not already carry (w44-fixverify F-1). The
        // honest crash-gap child (intent anchored, dispatch never reached)
        // stays wedged for reconcile either way.
        const releasable = wc && wcertId && wstored
          && this._auditIndex(t).reserved.has(wcertId) && !this._auditIndex(t).outcomes.has(wcertId) && !this._auditIndex(t).dispatched.has(wcertId) && !this.target.outcome(t, wcertId)
          && !(this._auditIndex(t).intended?.has(wcertId))
          && (() => {
            this._capsuleIntegrity(t, wc);
            return wc.capsule.action.type !== 'data.export' || !(this._auditIndex(t).dataAccess ?? []).some(a => a.certificate_id === wcertId);
          })();
        if (releasable) {
          wstored.consumed = false; wstored.status = 'CERTIFIED'; delete wstored.transaction_id;
          wc.status = 'CERTIFIED';
          this.store.put(t, 'certificate', wcertId, wstored, now); this.store.put(t, 'capsule', childId, wc, now);
          this.store.audit(t, 'EXECUTION_RELEASED', p.subject_id, wcertId, { capsule_id: childId, reason: 'reserved_not_dispatched' }, now);
          childOutcomes[childId] = 'RELEASED';
        }
      }
      // The terminal record names every child's fate — wedged, attempted-
      // failed and never-attempted children are accounted, not hidden
      // (w8-composite F7, w22 F9).
      for (const childId of capsule.requested_state.children ?? []) childOutcomes[childId] ??= wedged.includes(childId) ? (this._auditIndex(t).released?.has(this._auditIndex(t).issuedCert.get(childId)) ? 'RELEASED' : 'WEDGED') : attemptedFailed.includes(childId) ? 'FAILED' : 'NOT_ATTEMPTED';
      const payload = { certificate_id: cert.certificate_id, capsule_digest: cert.capsule_digest, target_transaction_id: cert.certificate_id, observed_state_digest: digest({ children: executed.map(e => e.child.capsule.capsule_id), compensations }), status, reason, execution_time: execNow, reconciliation_evidence: digest(executed.map(e => e.raw)), simulation: true, output: null, composite: true, children: executed.map(e => e.child.capsule.capsule_id), child_outcomes: childOutcomes, wedged_children: wedged.length ? wedged : null, compensations, supersedes: existing ? digest(existing) : null };
      const envelope = this.signAudit(t, payload, 'outcome');
      this.store.put(t, 'outcome', cert.certificate_id, envelope, now); stored.status = status; r.status = status;
      this.store.put(t, 'certificate', cert.certificate_id, stored, now); this.store.put(t, 'capsule', cert.capsule_id, r, now);
      this.store.audit(t, 'EXECUTION_OUTCOME', p.subject_id, cert.certificate_id, { status, reason, outcome_digest: digest(envelope), composite: true, child_outcomes: childOutcomes, wedged_children: wedged.length ? wedged : null, supersedes: existing ? digest(existing) : null }, now);
      return envelope;
    });
    // Same post-commit contract as finish(): failures mark the tenant for
    // the in-session heal and land an EFFECT_APPLY_FAILED anchor (w22 F6).
    const postFailures = [];
    for (const fn of post) { try { fn(); } catch (e) { postFailures.push(e); } }
    if (postFailures.length) {
      this.#pendingEffects.add(p.tenant_id);
      try { this.store.tx(() => this.store.audit(p.tenant_id, 'EFFECT_APPLY_FAILED', p.subject_id, cert.certificate_id, { failures: postFailures.length, code: postFailures[0]?.code ?? null }, this.clock())); } catch { /* ledger unavailable — the marker still queues the heal */ }
    }
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
    // output_row_ids joined the journal in w24-datagate F4 — pre-change
    // journals lack it, so the shape accepts either arity and the content
    // check below binds it when present.
    const keyArity = Object.keys(raw ?? {}).length - responseKeys.length;
    let responseShape = raw && typeof raw === 'object' && !Array.isArray(raw) && (keyArity === 0 || (keyArity === 1 && Object.hasOwn(raw, 'output_row_ids'))) && responseKeys.every(key => Object.hasOwn(raw, key)) && (r.capsule.action.type === 'data.export' ? raw.observed_state === null : (raw.observed_state && typeof raw.observed_state === 'object' && !Array.isArray(raw.observed_state))) && (raw.output === null || Array.isArray(raw.output)) && (raw.output_row_ids === undefined || raw.output_row_ids === null || (Array.isArray(raw.output_row_ids) && raw.output_row_ids.every(x => typeof x === 'string')));
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
        // The journaled physical ids, when present, must be exactly the
        // authorised set — a planted list cannot redirect attribution
        // (w24-datagate F4).
        if (outputValid && raw.output_row_ids !== undefined) outputValid = Array.isArray(raw.output_row_ids) && raw.output_row_ids.length === raw.output.length && raw.output_row_ids.every(id => requested.row_ids.includes(id));
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
      // allow_weakening is a property of the TRANSITION's approval set,
      // not of the installed constitution — a flag persisted into the
      // stored policy would silently entitle later weakening waves.
      // Strip it before staging/anchoring so every digest binds the
      // governed form (w23-policy F13).
      const { allow_weakening: _aw, ...candidate } = r.capsule.requested_state.policy;
      const next = candidate, active = this.policy(t);
      // A lapsed activation — a sibling took the version, or a staged
      // candidate already pends — must never throw inside the outcome
      // transaction: the journal committed, so the honest verdict is FAILED
      // (w10-cert F2).
      if (next.version !== active.version + 1) return { activation_superseded: { detail: 'POLICY_SEQUENCE_LAPSED' } };
      // A staged candidate pending activation conflicts with ANY second
      // activation — immediate or staged alike (w10-cert F2).
      if (this.store.get(t, 'policy', 'staged')) return { activation_superseded: { detail: 'POLICY_STAGED_CONFLICT' } };
      // A constitution that retires a suite a live vault key still signs
      // under can never anchor its own activation — the gate it installs
      // would refuse the POLICY_ACTIVATED signature itself and wedge every
      // later transaction. The honest verdict is a FAILED outcome before
      // any anchor exists (w30-policy F9).
      if (!this._coversLiveSuites(t, next)) return { activation_superseded: { detail: 'POLICY_SUITE_LAPSED' } };
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
        const cidxR = this._auditIndex(t);
        // The anchored spend names the consuming capsule; a tampered
        // rotation_consumed row flag can neither keep a second rotation
        // alive nor wedge this one — when no spend is anchored yet the
        // ledger has no opinion and the flag is display-only.
        const anchoredSpend = cidxR.ceremonyRotationConsumed.get(req.ceremony_id);
        preconditions = preconditions && ceremony && ceremony.purpose === 'key.rotate' && (anchoredSpend === undefined || anchoredSpend === r.capsule.capsule_id)
          && ceremony.rotation?.key_class === req.key_class && ceremony.rotation?.new_key_id === req.new_key_id
          && !(cidxR.ceremonyAborted?.has(req.ceremony_id) || cidxR.ceremonyCompleted?.has(req.ceremony_id));
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
      this.store.audit(t, 'KEY_ROTATED', p.subject_id, req.new_key_id, { key_class: klass, previous_key_id: previous.key_id, ceremony_id: req.ceremony_id, capsule_id: r.capsule.capsule_id, revoke_old: revokeOld }, now);
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
      // The beneficiary's revocation status is ledger-authoritative at the
      // minting point — a subject quarantined between evaluation and
      // certificate must not still collect granted scope (w27-policy F4).
      requireThat(!this.revoked(t, 'subject', req.subject_id), 'INV-403-SCOPE', 'JIT grant beneficiary is subject-revoked', 403);
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
    // exactly-once per certificate — a wedged disclosure touch does NOT
    // settle the billing obligation: when reconcile later settles the
    // child VERIFIED, the real charge still lands (w28-fixverify F6).
    const alreadyCharged = this._auditIndex(t).dataAccess.some(a => a.certificate_id === cert.certificate_id && a.wedged !== true && a.gate_denied !== true);
    const ridx = this._auditIndex(t);
    const recon = reconstructionCheck(this.store.db, this.target.db, { tenant: t, subject, dataset: requested.dataset, rows: requested.row_ids, columns: requested.columns, now, policy: this.policy(t).runtime.reconstruction, record: !alreadyCharged, access: ridx.dataAccess, droppedEvents: ridx.sealDroppedEvents ?? 0, sealDroppedAt: ridx.sealDroppedAt ?? 0, verifiedRowCount: (dt, ds) => this._verifiedDatasetRows(dt, ds) });
    const weight = this.policy(t).runtime.sensitivity_weights[dataset.classification] ?? 1;
    const cost = requested.row_ids.length * requested.columns.length * weight;
    // A squatted mirror row cannot even fail the insert — upsert folds the
    // honest charge into whatever the insider pre-planted (w12-provenance
    // F17): the row is a billing projection, the chain decides. The `at`
    // merge is monotone-safe — MAX keeps a planted future timestamp from
    // tripping no_usage_rewind and aborting the whole finish transaction
    // with the disclosure still unattested (w42-runtime F1).
    if (!alreadyCharged)
      this.store._landed(() => this.store._stmt('INSERT INTO usage VALUES(?,?,?,?,?,?,?) ON CONFLICT(tenant,capability,request) DO UPDATE SET cost=cost+excluded.cost,at=MAX(at,excluded.at)').run(t, subject, requested.dataset, now, cost, requestKey, cert.certificate_id), 'usage mirror');
    // A denied egress still disclosed — the journal committed the rows
    // before this check ran. The chain must attest that honestly: the
    // DATA_ACCESSED event carries gate_denied so the denied disclosure is
    // never invisible to the ledger, and the same anchor makes the charge
    // exactly-once on any later re-fire (w20-datagate F4).
    if (!recon.allowed) {
      if (!alreadyCharged)
        this.store.audit(t, 'DATA_ACCESSED', subject, subject, { dataset: requested.dataset, row_ids: requested.row_ids, columns: requested.columns, at: now, certificate_id: cert.certificate_id, gate_denied: true }, now);
      return { gate_denied: { code: 'INV-429-BUDGET', detail: { row_count: recon.row_count, column_count: recon.column_count, coverage_percent: recon.coverage_percent } } };
    }
    // Egress disclosure is attested on the signed chain — the touch table
    // is a mirror; wiping it can never reset coverage (w11-redteam R9).
    if (!alreadyCharged)
      this.store.audit(t, 'DATA_ACCESSED', subject, subject, { dataset: requested.dataset, row_ids: requested.row_ids, columns: requested.columns, at: now, certificate_id: cert.certificate_id }, now);
    // Watermarking requires the dedicated key — falling back to the
    // row-encryption key would fuse two distinct primitives (w10-datagate F10).
    const tenantWatermarkKey = this.dataKey(t, 'watermark');
    requireThat(tenantWatermarkKey, 'INV-503-CONFIG', `Tenant ${t} has no watermark data key`, 503);
    // Watermark rows bind the PHYSICAL ids — the plan's declared set when
    // the target does not report them back; a transformed projection id
    // can never launder a different row (w25-datagate W25-06).
    const egressRowIds = raw.output_row_ids ?? requested.row_ids;
    return { watermarks: watermark(raw.output ?? [], { tenant: t, dataset: requested.dataset, subject, requestId: cert.certificate_id, capabilityId: `cert:${cert.certificate_id}`, tenantWatermarkKey, rowIds: egressRowIds }).watermarks };
  }
  // A wedged export child disclosed rows through a durable journal whose
  // child outcome was never recorded — without its own DATA_ACCESSED the
  // disclosure is invisible to coverage accounting and the ledger
  // (w27-datagate F2). The touch certifies the pending disclosure under
  // the child certificate id so reconcile still recognises exactly-once.
  _touchWedgedEgress(t, child, childCert, now, journal = null) {
    if (this._auditIndex(t).dataAccess.some(a => a.certificate_id === childCert.certificate_id)) return;
    const req = child.capsule.requested_state;
    if (!req?.row_ids?.length || !req?.columns?.length) return;
    const subject = child.capsule.actor.subject_id;
    // Attest the rows the durable journal actually discharged — the
    // declared request may overstate the real egress (w28-fixverify F10).
    const rowIds = journal?.output_row_ids ?? req.row_ids;
    this.store.audit(t, 'DATA_ACCESSED', subject, subject, { dataset: req.dataset, row_ids: rowIds, columns: req.columns, at: now, certificate_id: childCert.certificate_id, wedged: true }, now);
  }
  // The execution journal is deletable clay while EXECUTION_DISPATCHED /
  // EXECUTION_INTENT anchor it: a murdered journal under an export cert
  // would leave a real disclosure invisible to the reconstruction ledger
  // forever (w43-runtime C1/C2). Without the journal the honest bound is
  // the certificate's DECLARED selection — the gate authorized at most
  // those rows, so charging them is worst-case honest, same doctrine as
  // seal-dropped coverage. journal_missing marks the attestation class.
  _attestMurderedEgress(t, capsule, cert, now) {
    // Dedup on the flag, not the certificate: an earlier wedged attestation
    // of a different class (wedged but not journal_missing) must not
    // suppress the murdered-journal evidence — the two classes name
    // different tamper shapes for the seal surface (w44-fixverify F-8).
    if (this._auditIndex(t).dataAccess.some(a => a.certificate_id === cert.certificate_id && a.journal_missing === true)) return;
    const req = capsule.requested_state;
    if (!req?.row_ids?.length || !req?.columns?.length) return;
    const subject = capsule.actor?.subject_id ?? cert.actor ?? null;
    this.store.audit(t, 'DATA_ACCESSED', subject, subject, { dataset: req.dataset, row_ids: req.row_ids, columns: req.columns, at: now, certificate_id: cert.certificate_id, wedged: true, journal_missing: true }, now);
  }
  finish(p, cert, raw, status, reason, { postRead = false } = {}) {
    const post = [];
    // An anchored EXECUTION_DISPATCHED whose durable journal is gone is
    // murder evidence, not ambiguity — the missing journal itself is the
    // proof rows may have left the dataplane, so exports attest their
    // declared worst case before the verdict screams (w43-runtime C1).
    {
      const mt = p.tenant_id, midx = this._auditIndex(mt);
      if (midx.dispatched.has(cert.certificate_id) && !this.target.outcome(mt, cert.certificate_id)) {
        const capRow = this.store.get(mt, 'capsule', cert.capsule_id);
        if (capRow?.capsule?.action?.type === 'data.export') { try { this.store.tx(() => this._attestMurderedEgress(mt, capRow.capsule, cert, this.clock())); } catch { /* the wedge below names it anyway */ } }
        throw new InvariantError('INV-409-INTEGRITY', 'Anchored dispatch journal is missing — tamper evidence', 409);
      }
    }
    const envelope = this.transaction(p, now => {
      const t = p.tenant_id, r = this._mustAnchored(t, 'capsule', cert.capsule_id), stored = this._mustAnchored(t, 'certificate', cert.certificate_id);
      // finish is reachable only after the reservation consumed the
      // certificate — an outcome row cannot be forged ahead of dispatch
      // (w11 F4). Record integrity is re-proven before effects fire (w11 F1).
      // The reservation anchor, not the mutable consumed flag, proves the
      // certificate entered execution — a flipped flag without a signed
      // EXECUTION_RESERVED fails here (w12-provenance F16). The mutable
      // consumed flag itself is tamper-checked, never the authority
      // (w24-lifecycle W24-3).
      this._certSpendIntegrity(t, this._auditIndex(t), cert.certificate_id, stored);
      requireThat(this._auditIndex(t).reserved.has(cert.certificate_id), 'INV-409-STATE', 'Certificate was never reserved for execution', 409);
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
      // Terminality is anchored, not row-derived: a deleted outcome row
      // cannot re-open finish() for a second, demoted verdict — the
      // anchored EXECUTION_OUTCOME attests the terminal state and the
      // missing served row is integrity evidence (w29-lifecycle F2).
      const anchoredOutcome = this._auditIndex(t).outcomes.get(cert.certificate_id);
      requireThat(existing || !['VERIFIED', 'FAILED', 'COMPENSATED'].includes(anchoredOutcome), 'INV-409-INTEGRITY', 'Anchored terminal outcome lost its served row — restore before reconciling', 409);
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
        // A committed journal WITHOUT the anchor is the crash gap: the
        // anchor can never be post-hoc signed (that would let a planted
        // journal self-attest), so the cert settles FAILED with the
        // divergence named — never a permanent INV-409 wedge (w22 F1).
        // A mismatched anchor stays tamper evidence — the integrity scream.
        const anchoredDispatch = this._auditIndex(t).dispatched.get(cert.certificate_id);
        if (anchoredDispatch === undefined) {
          // The crash-gap verdict only applies to a journal written inside
          // the reservation window — a planted journal outside it is
          // tamper evidence, not a settleable FAILED (w23-fixverify F-a).
          const reservedAt = this._auditIndex(t).reservedAt?.get(cert.certificate_id);
          requireThat(reservedAt !== undefined && raw.execution_time >= reservedAt && raw.execution_time - reservedAt <= 60000, 'INV-409-INTEGRITY', 'Unanchored journal outside the reservation window — tamper evidence', 409);
          status = 'FAILED'; reason = 'DISPATCH_UNATTESTED';
        }
        else requireThat(anchoredDispatch === digest(journal), 'INV-409-INTEGRITY', 'Anchored dispatch does not match the durable journal', 409);
      }
      const { valid } = this._validateTargetResponse(r, cert, raw, now, { postRead });
      if (status === 'VERIFIED' && !valid) { status = 'UNCERTAIN'; reason = 'TARGET_RESPONSE_INVALID'; }
      // Effects fire only under a VERIFIED verdict — an unattested or
      // demoted dispatch never mints post-effects (w22 F1).
      const extras = status === 'VERIFIED' && valid ? this._applyVerifiedEffects(p, t, r, cert, raw, now, post) : null;
      if (extras?.gate_denied) { status = 'FAILED'; reason = extras.gate_denied.code; }
      if (extras?.rotation_precondition_lapsed) { status = 'FAILED'; reason = 'ROTATION_PRECONDITION_LAPSED'; }
      if (extras?.activation_superseded) { status = 'FAILED'; reason = extras.activation_superseded.detail; }
      // Egress is irrevocable: an export whose journal durably committed
      // rows is charged and watermarked even when the verdict lands
      // non-VERIFIED (dispatch-unattested wedge, invalid response) — the
      // same doctrine finishComposite applies to wedged children; without
      // it a standalone wedged export leaves rows disclosed but invisible
      // to coverage accounting forever (w29-datagate F1).
      let wedgedExtras = null;
      if (r.capsule.action.type === 'data.export' && status !== 'VERIFIED' && !existing) {
        const eidx = this._auditIndex(t);
        if (journal && raw && digest(raw) === digest(journal)) wedgedExtras = this._recordExportEgress(p, t, r, cert, raw, now);
        // Dispatch intent anchored but no journal anywhere — the window a
        // murdered journal hides in. Attest the declared worst case so the
        // disclosure stays on the coverage ledger (w43-runtime C1).
        else if (!journal && eidx.intended?.has(cert.certificate_id)) this._attestMurderedEgress(t, r.capsule, cert, now);
      }
      // H1: revocation cannot abort a committed reservation — it stops NEW
      // reservations. A revocation that landed between reservation and this
      // finish is recorded and flagged rather than hidden, so the ledger
      // shows the race instead of pretending it never happened.
      const revokedMidFlight = this.revoked(t, 'certificate', cert.certificate_id) || this.revoked(t, 'key', stored.envelope.protected.key_id);
      const payload = { certificate_id: cert.certificate_id, capsule_digest: cert.capsule_digest, target_transaction_id: cert.certificate_id, observed_state_digest: valid ? raw.observed_state_digest : null, status, reason, execution_time: valid ? raw.execution_time : now, reconciliation_evidence: valid ? digest(raw) : null, journal_digest: status === 'VERIFIED' ? digest(journal) : null, simulation: true, output: valid && !extras?.gate_denied ? raw.output : null, watermarks: extras?.watermarks ?? wedgedExtras?.watermarks ?? null, gate_denied: extras?.gate_denied?.detail ?? wedgedExtras?.gate_denied?.detail ?? null, revoked_post_reservation: revokedMidFlight || null, composite_child_of: this._auditIndex(t).dispatchedMeta.get(cert.certificate_id) ?? this._auditIndex(t).reservedMeta.get(cert.certificate_id) ?? null, supersedes: existing ? digest(existing) : null };
      const envelope = this.signAudit(t, payload, 'outcome', extras?.outcome_key_id ?? null, { allowPending: extras?.outcome_allow_pending === true });
      this.store.put(t, 'outcome', cert.certificate_id, envelope, now); stored.status = status; r.status = status;
      this.store.put(t, 'certificate', cert.certificate_id, stored, now); this.store.put(t, 'capsule', cert.capsule_id, r, now);
      this.store.audit(t, 'EXECUTION_OUTCOME', p.subject_id, cert.certificate_id, { status, reason, outcome_digest: digest(envelope), supersedes: existing ? digest(existing) : null, revoked_post_reservation: revokedMidFlight || null }, now);
      if (revokedMidFlight) this.store.audit(t, 'EXECUTION_COMPLETED_POST_REVOCATION', p.subject_id, cert.certificate_id, { status, outcome_digest: digest(envelope) }, now);
      return envelope;
    });
    // Post-commit effects apply best-effort but never silently: a failure
    // marks the tenant for the idempotent ledger heal at the next
    // transaction and lands an EFFECT_APPLY_FAILED anchor — a VERIFIED
    // verdict over a diverged dataplane must scream, not pretend (w22 F6).
    const postFailures = [];
    for (const fn of post) { try { fn(); } catch (e) { postFailures.push(e); } }
    if (postFailures.length) {
      this.#pendingEffects.add(p.tenant_id);
      try { this.store.tx(() => this.store.audit(p.tenant_id, 'EFFECT_APPLY_FAILED', p.subject_id, cert.certificate_id, { failures: postFailures.length, code: postFailures[0]?.code ?? null }, this.clock())); } catch { /* ledger unavailable — the marker still queues the heal */ }
    }
    return envelope;
  }
  reconcile(p, id) {
    this.authorize(p, ['operator', 'security', 'policy_admin']); const t = p.tenant_id, stored = this._mustAnchored(t, 'certificate', id);
    // A recorded outcome without a consumed reservation is always forged
    // (w11 F4) — the consumed check precedes every stored-row read, and the
    // row itself must re-verify as a vault-signed envelope before it is
    // served (w11 F5).
    // A stored outcome row is integrity-proven before the state checks —
    // tamper evidence outranks 'not started' (a planted row must scream
    // INTEGRITY, never hide behind state ordering).
    const current = this.store.get(t, 'outcome', id);
    if (current) this._outcomeIntegrity(t, current, id);
    // Anchored reservation is the authority — an un-flipped consumed flag
    // cannot hide a wedged cert from recovery (w24-lifecycle W24-3).
    this._certSpendIntegrity(t, this._auditIndex(t), id, stored);
    requireThat(this._auditIndex(t).reserved.has(id), 'INV-409-STATE', 'Execution has not started', 409);
    // COMPENSATED is terminal too — reconcile returns any settled outcome
    // instead of throwing where VERIFIED/FAILED simply answer (w7-seam F8).
    if (current && ['VERIFIED', 'FAILED', 'COMPENSATED'].includes(current.payload.status)) return this._outcomeIntegrity(t, current, id);
    const cert = stored.envelope.payload, raw = this.target.outcome(t, id);
    const record = this.store.get(t, 'capsule', cert.capsule_id);
    // A missing capsule row for an anchored issuance is the same
    // destructive tampering — reconcile must scream, not die on a bare
    // 404 (w29-lifecycle F5).
    requireThat(record || !this._auditIndex(t).proposedDigest.has(cert.capsule_id), 'INV-409-INTEGRITY', 'Anchored capsule row is missing', 409);
    if (!record) this._mustAnchored(t, 'capsule', cert.capsule_id);
    // A cert bound to a LIVE composite parent settles only through
    // finishComposite — an operator reconcile landing mid-composite would
    // fire irreversible effects under a verdict the parent then
    // contradicts with its own bail (w22 F3). Same anchored derivation as
    // execute(): a parent counts while its anchored certificate carries
    // no anchored outcome.
    const ridx = this._auditIndex(t);
    const liveParent = this._boundLiveParents(t, ridx, cert.capsule_id, this.clock())[0];
    requireThat(!liveParent, 'INV-409-STATE', 'Certificate is bound to a live composite parent — reconcile the parent first', 409);
    // Anchored dispatch with no surviving journal is murder evidence —
    // serving or minting UNCERTAIN over it launders a real disclosure out
    // of the ledger (w43-runtime C1). Export certs attest their declared
    // worst-case selection first, then the verdict screams.
    if (ridx.dispatched.has(id) && !raw) {
      if (record.capsule.action.type === 'data.export') { try { this.store.tx(() => this._attestMurderedEgress(t, record.capsule, cert, this.clock())); } catch { /* the wedge below names it anyway */ } }
      throw new InvariantError('INV-409-INTEGRITY', 'Anchored dispatch journal is missing — tamper evidence', 409);
    }
    // Intent anchored but never dispatch-confirmed and no journal: the
    // same worst-case egress attestation applies — the verdict itself
    // stays honestly UNCERTAIN (the journal may never have committed).
    if (!raw && record.capsule.action.type === 'data.export' && ridx.intended?.has(id) && !ridx.dispatched.has(id))
      try { this.store.tx(() => this._attestMurderedEgress(t, record.capsule, cert, this.clock())); } catch { /* attestation is best-effort; the UNCERTAIN verdict still lands */ }
    if (record.capsule.action.type === 'action.composite') {
      // A wedged composite reconciles per-child, never as a fake standalone:
      // children whose target journal wrote are recorded executed, the rest
      // are wedged — and they keep their own live certificates so a fresh
      // composite can still spend them (w7-seam F9). Parent capsules never
      // write a target journal row — the outcome aggregates the child
      // outcome rows each child settle wrote (w8-composite F16).
      const executed = [], wedged = [], reconciledCompensations = [];
      let allSettledVerified = true, anyFailed = false, anyCompensated = false;
      for (const childId of record.capsule.requested_state.children ?? []) {
        const childCapsule = this.store.get(t, 'capsule', childId);
        // An anchored issuance for a child whose capsule row is gone is
        // destructive tampering of the same class a missing anchored cert
        // row is — scream, never silently classify it NOT_ATTEMPTED while
        // every later path dies on a bare 404 (w29-lifecycle F5).
        requireThat(childCapsule || !ridx.issued.has(childId), 'INV-409-INTEGRITY', 'Anchored child capsule row is missing', 409);
        // Cert bindings resolve from the anchored CERTIFICATE_ISSUED map —
        // the mutable capsule.certificate_id pointer can be repointed at a
        // foreign settled cert to mint parent verdicts (w23-fixverify F-h).
        const anchoredCertId = ridx.issuedCert.get(childId);
        // A deleted child certificate row under an anchored mint is the same
        // destructive tamper as the murdered capsule above — it must scream
        // INTEGRITY, never classify the child as never-attempted
        // (w42-runtime F4).
        requireThat(this.store.get(t, 'certificate', anchoredCertId) || !anchoredCertId, 'INV-409-INTEGRITY', 'Anchored child certificate row is missing', 409);
        const childCert = anchoredCertId ? this.store.get(t, 'certificate', anchoredCertId) : null;
        const certId = childCert?.envelope?.payload?.certificate_id;
        const childOutcome = certId ? this.store.get(t, 'outcome', certId) : null;
        // A planted child outcome can never mint a parent verdict: the row
        // re-proves itself as a gate-signed envelope bound to this cert
        // before its status counts (w13-fixverify H2).
        if (childOutcome) this._outcomeIntegrity(t, childOutcome, certId);
        if (childCapsule) this._capsuleIntegrity(t, childCapsule);
        const childRaw = childCert ? this.target.outcome(t, certId) : null;
        // A journaled unwind is a real child fate even without an outcome
        // row: the comp:<certId> journal + its EXECUTION_COMPENSATED anchor
        // settle the child COMPENSATED instead of ratcheting UNCERTAIN
        // over already-reverted resources (w22 F4).
        const compJournal = certId ? this.target.outcome(t, `comp:${certId}`) : null;
        // Presence alone does not attest a compensation — the journal must
        // bind THIS child's capsule digest, or a donor compensate() mints
        // COMPENSATED over a mutation that was never reverted
        // (w23-fixverify F-c).
        const compJournalOk = compJournal && childCapsule && compJournal.capsule_digest === digest(childCapsule.capsule);
        const settled = childOutcome && ['VERIFIED', 'FAILED', 'COMPENSATED'].includes(childOutcome.payload.status) ? childOutcome.payload.status : null;
        // Anchored dispatch whose journal is gone: the same murder
        // evidence a standalone reconcile screams on — classifying this
        // child wedged would launder the disappearance (w43-runtime C1).
        if (!settled && certId && ridx.dispatched.has(certId) && !childRaw) {
          if (childCapsule?.capsule?.action?.type === 'data.export' && childCert) { try { this.store.tx(() => this._attestMurderedEgress(t, childCapsule.capsule, childCert.envelope?.payload ?? { certificate_id: certId }, this.clock())); } catch { /* the wedge below names it anyway */ } }
          throw new InvariantError('INV-409-INTEGRITY', 'Anchored dispatch journal is missing — tamper evidence', 409);
        }
        if (settled === 'FAILED') anyFailed = true;
        if (settled === 'COMPENSATED') anyCompensated = true;
        if (settled !== 'VERIFIED') allSettledVerified = false;
        if (compJournalOk && !settled) reconciledCompensations.push({ capsule_id: childId, compensated: true });
        if (childCapsule && childCert && (childRaw || settled || compJournalOk)) executed.push({ child: { ...childCapsule, certificate_id: certId }, raw: childRaw, prior: childCapsule.capsule.current_state.material_fields });
        // Anchored spend facts classify the wedge too — a deleted journal
        // plus a rolled-back consumed flag must still read as WEDGED,
        // never as never-attempted (w24-fixverify W24-02).
        else if (certId && (ridx.reserved.has(certId) || ridx.dispatched.has(certId))) wedged.push(childId);
        else if (childCert?.consumed === true) wedged.push(childId);
        else if (certId && ridx.released?.has(certId)) wedged.push(childId);
        // Never-reserved children are honestly NOT_ATTEMPTED, not WEDGED —
        // they left no durable trace at all; an already-RELEASED child
        // keeps its released label on repeat reconciles (w22 F9/F2).
      }
      // All children settled VERIFIED → the parent is VERIFIED; a failed or
      // compensated child resolves the parent FAILED (a COMPENSATED child
      // row can only be written alongside a terminal parent outcome, so
      // reaching one here names an orphaned compensation — never a clean
      // parent verdict — w10-cert F7); anything incomplete stays honestly
      // UNCERTAIN.
      const settled = wedged.length === 0 && allSettledVerified ? 'VERIFIED' : (anyFailed || anyCompensated) ? 'FAILED' : 'UNCERTAIN';
      const reasonMap = { VERIFIED: 'RECONCILED_FROM_CHILD_OUTCOMES', FAILED: anyCompensated && !anyFailed ? 'RECONCILED_CHILD_COMPENSATED_ORPHANED' : 'RECONCILED_CHILD_FAILED', UNCERTAIN: 'COMPOSITE_INTERRUPTED_CHILDREN_ATTEMPTED' };
      // An unchanged verdict over identical inputs returns the existing
      // row — reconcile is read-mostly and must not write a superseding
      // row per call (w22 F7). The signature compares the verdict AND the
      // per-child labels finishComposite would write now, so a child that
      // settled, journaled or released since never passes as unchanged.
      if (current?.payload?.status === settled) {
        const prospective = {};
        for (const done of executed) {
          const po = this.store.get(t, 'outcome', done.child.certificate_id);
          prospective[done.child.capsule.capsule_id] = po && ['VERIFIED', 'FAILED', 'COMPENSATED'].includes(po.payload.status) ? po.payload.status
            : reconciledCompensations.some(c => c.capsule_id === done.child.capsule.capsule_id) ? 'COMPENSATED'
            : settled === 'VERIFIED' ? 'VERIFIED' : settled === 'UNCERTAIN' ? 'UNCERTAIN' : 'FAILED';
        }
        for (const childId of record.capsule.requested_state.children ?? []) {
          const ccId = ridx.issuedCert.get(childId);
          // A murdered outcome row for an executed child must never dedupe
          // as unchanged — row existence is part of the signature
          // (w23-fixverify F-f).
          if (!wedged.includes(childId)) {
            const exists = executed.some(d => d.child.capsule.capsule_id === childId) && this.store.get(t, 'outcome', ccId);
            if (executed.some(d => d.child.capsule.capsule_id === childId) && !exists) prospective[childId] = '__MISSING__';
          }
          prospective[childId] ??= wedged.includes(childId) ? (ccId && ridx.released?.has(ccId) ? 'RELEASED' : 'WEDGED') : 'NOT_ATTEMPTED';
        }
        if (digest({ status: settled, children: prospective }) === digest({ status: current.payload.status, children: current.payload.child_outcomes })) return this._outcomeIntegrity(t, current, id);
      }
      return this.finishComposite(p, cert, record.capsule, executed, settled, reasonMap[settled], reconciledCompensations, this.clock(), wedged);
    }
    // Same dedupe for a standalone UNCERTAIN over an absent journal: the
    // input set (journal present?) is identical, so the existing row
    // answers instead of a superseding rewrite (w22 F7).
    if (!raw && current?.payload?.status === 'UNCERTAIN') return this._outcomeIntegrity(t, current, id);
    // A journaled but INVALID dispatch also settles UNCERTAIN exactly
    // once — identical inputs can never mint a new verdict, so a repeat
    // reconcile serves the row instead of ratcheting another superseding
    // write (w24-lifecycle W24-1).
    if (raw && current?.payload?.status === 'UNCERTAIN' && !this._validateTargetResponse(record, cert, raw, this.clock(), { postRead: true }).valid) return this._outcomeIntegrity(t, current, id);
    return this.finish(p, cert, raw, raw ? 'VERIFIED' : 'UNCERTAIN', raw ? 'RECONCILED_FROM_TARGET_JOURNAL' : 'NO_TARGET_CONFIRMATION_DO_NOT_RETRY');
  }
  cancel(p, id) {
    this.authorize(p, ['operator', 'security', 'policy_admin']);
    return this.transaction(p, now => {
      const r = this.store.get(p.tenant_id, 'capsule', id);
      const cancelIdx = this._auditIndex(p.tenant_id);
      // A capsule the chain proposed but the store lost is destructive
      // tampering — cancel must scream integrity, not a bare 404
      // (w29-lifecycle F5).
      requireThat(r || !cancelIdx.proposedDigest.has(id), 'INV-409-INTEGRITY', 'Anchored capsule row is missing', 409);
      if (!r) this._mustAnchored(p.tenant_id, 'capsule', id);
      // Terminal state is derived from the anchored folds, never the
      // mutable status field: re-cancelling, cancelling a dispatched or
      // settled cert — all refuse on the signed chain's word, and a
      // tampered row can neither slip the gate nor hold a live action
      // hostage (w24-lifecycle W24-3/W24-6).
      // A DENY verdict is terminal too — the anchored evaluation fold
      // refuses rewrites of it, so a DENY can never be whitewashed into a
      // CANCELLED record (w11-lifecycle F7, w24-lifecycle W24-3).
      requireThat(!cancelIdx.cancelled.has(id) && cancelIdx.decisionStatus?.get(id) !== 'DENY', 'INV-409-STATE', 'Dispatched or terminal action cannot be cancelled; reconcile first — an anchored wedge may be permanent', 409);
      // The cert binding resolves from the anchored CERTIFICATE_ISSUED
      // index — the mutable capsule.certificate_id pointer can be nulled
      // or repointed at a foreign cert to slip the guard (w23-fixverify F-i).
      const cancelCertId = cancelIdx.issuedCert.get(id);
      requireThat(!(cancelCertId && (cancelIdx.reserved.has(cancelCertId) || cancelIdx.outcomes.has(cancelCertId))), 'INV-409-STATE', 'Dispatched or terminal action cannot be cancelled; reconcile first — an anchored wedge may be permanent', 409);
      this.assertHealthy(p.tenant_id, p.subject_id, this.identity(p).device_id, now);
      // Same anti-grief rule attachEvidence already carries: only the
      // proposing actor — or a privileged role — may cancel (w9-network F9).
      const callerRoles = this.grantsFor(p.tenant_id, p.subject_id, now).roles ?? this.identity(p).roles;
      requireThat(r.capsule.actor.subject_id === p.subject_id || callerRoles.some(x => ['security', 'policy_admin'].includes(x)), 'INV-403-SCOPE', 'Only the proposing actor or a privileged role may cancel', 403);
      r.status = 'CANCELLED'; this.store.put(p.tenant_id, 'capsule', id, r, now);
      // The certificate row must not keep reading as a live CERTIFIED
      // authority after its action is cancelled (w10-cert F8). The flip
      // binds the anchored cert — a repointed mutable pointer must not
      // brand a foreign cert row CANCELLED (w23-fixverify F-i).
      const cert = cancelCertId ? this.store.get(p.tenant_id, 'certificate', cancelCertId) : null;
      if (cert && cert.status === 'CERTIFIED') { cert.status = 'CANCELLED'; this.store.put(p.tenant_id, 'certificate', cancelCertId, cert, now); }
      // The served layer must agree with the chain verdict: cancel writes
      // the CANCELLED outcome row its anchor attests, so a stale
      // pre-cancel row can never keep serving a divergent verdict
      // (w24-lifecycle W24-6).
      if (cancelCertId) {
        const prior = this.store.get(p.tenant_id, 'outcome', cancelCertId);
        const cancelOutcome = this.signAudit(p.tenant_id, { certificate_id: cancelCertId, capsule_digest: cert?.envelope?.payload?.capsule_digest ?? null, target_transaction_id: cancelCertId, observed_state_digest: null, status: 'CANCELLED', reason: 'ACTION_CANCELLED', execution_time: now, reconciliation_evidence: null, journal_digest: null, simulation: true, output: null, supersedes: prior ? digest(prior) : null }, 'outcome');
        this.store.put(p.tenant_id, 'outcome', cancelCertId, cancelOutcome, now);
        this.store.audit(p.tenant_id, 'EXECUTION_OUTCOME', p.subject_id, cancelCertId, { status: 'CANCELLED', reason: 'ACTION_CANCELLED', outcome_digest: digest(cancelOutcome), supersedes: prior ? digest(prior) : null }, now);
      }
      // The anchored binding names the killed cert — never the mutable
      // capsule.certificate_id pointer, which a store-level writer can
      // repoint at a foreign live cert to launder an anchored CANCELLED
      // verdict onto it (w29-lifecycle F1). The fold additionally ignores
      // any certificate_id that does not match the anchored issuance map.
      this.store.audit(p.tenant_id, 'ACTION_CANCELLED', p.subject_id, id, { certificate_id: cancelCertId ?? null }, now); return { status: r.status };
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
    requireThat(['certificate', 'evidence', 'issuer', 'key', 'subject', 'device', 'capability', 'grant', 'token', 'perception-session'].includes(input.kind), 'INV-400-SCHEMA', 'Unsupported revocation type');
    const env = this.transaction(p, now => {
      // Revocation must name a live authority — revoking a nonexistent id
      // would be silent record pollution.
      const t = p.tenant_id;
      const exists = {
        certificate: () => this._mustAnchored(t, 'certificate', input.id),
        evidence: () => this._mustAnchored(t, 'evidence', input.id),
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
        // An anchored issuance whose row was murdered stays revocable —
        // existence resolves through the chain so the floor can anchor the
        // revocation over the gap instead of refusing on a bare 404
        // (w42-runtime F5).
        capability: () => this.store.get(t, 'capability', input.id) ?? (this._auditIndex(t).capabilities?.has(input.id) ? { anchored_only: true } : null),
        grant: () => this.target.allGrants(t).some(g => g.grant_id === input.id),
        token: () => Object.hasOwn(this.tenant(t).auth, input.id) ? this.tenant(t).auth[input.id] : null,
        // A session resolves through the chain — its mutable row is a
        // cache, the anchored PERCEPTION_SESSION event is the authority
        // (w43-fv pre-existing veto remediation).
        'perception-session': () => this._auditIndex(t).perceptionSessions?.has(input.id) ? { anchored_only: true } : null,
        // `exists` itself is a table lookup — the prototype chain must not
        // shadow a kind either.
      }[Object.hasOwn({ certificate:1, evidence:1, issuer:1, key:1, subject:1, device:1, capability:1, grant:1, token:1, 'perception-session':1 }, input.kind) ? input.kind : ''];
      requireThat(exists?.(), 'INV-404-NOT-FOUND', `No live ${input.kind} authority with that id`, 404);
      // Re-revocation is refused: the first revocation's `revoked_at` is the
      // forensically important fact and must never be rewritten (w11 F6).
      // Exception: a ref that survives ONLY as a floor_derived seal carry —
      // unverifiable authority the seal had to preserve — may be re-anchored
      // by a fresh signed revocation so the floor regains real evidence
      // (w34-fixverify M-3).
      const revRef = `${input.kind}:${input.id}`, revIdx = this._auditIndex(t);
      // ...or a ref whose signed anchor survives while its floor row was
      // deleted outright: the digest condemns a revocation that no stored
      // row enforces — re-anchoring re-mints the floor instead of leaving
      // the murder silent (w36-fixverify M-1). An unreadable planted row
      // heals the same way — the fresh put overwrites it under the new
      // digest.
      let revFloorRow; try { revFloorRow = this.store.get(t, 'revocation', revRef); } catch { revFloorRow = 'unreadable'; }
      const reanchorable = (revIdx.revokedFloor?.has(revRef) && !revIdx.revocationDigests.has(revRef))
        || (revIdx.revocationDigests.has(revRef) && (revFloorRow === null || revFloorRow === 'unreadable'));
      requireThat(!this.revoked(t, input.kind, input.id) || reanchorable, 'INV-409-STATE', 'Authority already revoked', 409);
      // The bound execution or audit signer cannot be revoked without a
      // quorum-designated pending successor covering its purposes — the
      // recovery rotation needs certificates and outcome signatures to keep
      // flowing, and only the successor supplies them (w10-cert F5,
      // w11-lifecycle F1/F2: an unguarded execution-key revoke bricked the
      // whole tenant). A merely-prepared key is NOT enough: a lone
      // `security` identity could then substitute the tenant signer without
      // any custodian involvement — the successor must be named in a
      // custodian-acked ceremony's rotation spec (w18-crypto F3).
      for (const klass of ['execution', 'audit']) if (input.kind === 'key' && input.id === this.keys(t)[klass]?.key_id) {
        const needed = this._keyPurposes[klass] ?? [];
        const successor = [...this.vault.keys.entries()].some(([kid, e]) => e.pending && !e.revoked && this.chainOwnsVaultKey(t, kid)
          && (e.purpose === 'any' || needed.every(x => (Array.isArray(e.purpose) ? e.purpose : [e.purpose]).includes(x)))
          && this.ceremonyDesignated(t, kid, klass));
        requireThat(successor, 'INV-409-STATE', `Revoking the active ${klass} signer requires a pending successor covering the ${klass} purposes that a custodian-acked rotation ceremony designated — prepare and ack a key.rotate ceremony first`, 409);
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
    }, { recoveryPath: true });
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
    const items = this.store.list(p.tenant_id, 'revocation', 10000).filter(i => idx.revoked.has(`${i.kind}:${i.id}`)).map(i => ({ ...i, anchored: idx.revocationDigests.has(`${i.kind}:${i.id}`) && ctEqual(idx.revocationDigests.get(`${i.kind}:${i.id}`), metaMac(i)) ? true : (idx.revokedFloor?.has(`${i.kind}:${i.id}`) ? 'floor-derived' : 'identity-only') }));
    // Enforced-but-floorless refs: the signed chain condemns a revocation
    // whose mutable row was deleted — a murdered floor row must still
    // surface in the report or the enforced state is invisible to the
    // operator who would re-anchor it (w36-fixverify M-1).
    const floorSeen = new Set(items.map(i => `${i.kind}:${i.id}`));
    for (const ref of idx.revoked) {
      const sep = ref.indexOf(':');
      if (sep <= 0 || floorSeen.has(ref)) continue;
      items.push({ kind: ref.slice(0, sep), id: ref.slice(sep + 1), revoked_at: null, actor: null, reason_digest: null, anchored: 'anchorless-carried' });
    }
    return { quarantine: items.filter(i => ['subject', 'device'].includes(i.kind)).filter(i => !kind || i.kind === kind), items: kind ? items.filter(i => i.kind === kind) : items };
  }
  listGrants(p, subject = null) {
    this.authorize(p, ['operator', 'security', 'auditor']);
    const now = this.clock();
    const items = this.target.allGrants(p.tenant_id).filter(g => !subject || g.subject_id === subject);
    // The dataplane row's own revoked flag is mutable ciphertext — a
    // replayed pre-revoke ciphertext restores it to live-looking even
    // though the chain's revocation still denies the grant. The honest
    // listing marks what the LEDGER believes (w49-fixverify C-1).
    const idx = this._auditIndex(p.tenant_id);
    const annotated = items.map(g => ({ ...g, ledger_revoked: idx.revoked.has(`grant:${g.grant_id}`) }));
    // A grant row that failed decryption was silently skipped — the count
    // names the hidden-grant evidence the scan just saw (w38-runtime L-1).
    return { now, items: annotated, corrupt_grant_rows: this.target._corruptGrantRows ?? 0 };
  }
  simulate(p, candidate) {
    this.authorize(p, ['policy_admin', 'security']); validatePolicy(candidate); requireThat(candidate.tenant_id === p.tenant_id, 'INV-403-SCOPE', 'Policy scope mismatch', 403);
    return this.transaction(p, now => {
      const active = this.policy(p.tenant_id), records = this.store.list(p.tenant_id, 'capsule', 500);
      const results = records.map(r => { const e = this.evaluation(p.tenant_id, { ...r, capsule: { ...r.capsule, policy_version: candidate.version } }, now, candidate); return { capsule_id: r.capsule.capsule_id, observed_status: r.status, projected: e.decision, projected_reasons: e.reasons.map(x => x.code) }; });
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
    // The transition anchors on the signed chain — served manifests and
    // coverageAt history derive status from these events, so a forged
    // coverage row can never mint ENFORCED under the gate's signature
    // (w20-datagate F2).
    this.store.audit(tenant, 'COVERAGE_TRANSITION', 'system', path.path_id, { to, cause, at: now, evidence_at: path.evidence_at }, now);
    // Owner tasks exist only for degraded/unprotected states — a promotion
    // is a resolution, not a new obligation. UNCOVERED means the path is
    // declared unprotected: the owner must close it or enforce it.
    if (to === 'UNKNOWN' || to === 'UNCOVERED') {
      const taskId = `${cause}:${path.path_id}`, prev = this.store.get(tenant, 'coverage-task', taskId);
      this.store.put(tenant, 'coverage-task', taskId, prev?.status === 'open' ? { ...prev, refreshed_at: now } : { path_id: path.path_id, owner: path.owner, cause, opened_at: now, status: 'open', required_action: to === 'UNKNOWN' ? 'attach independently executed technical validation evidence' : 'close this declared-unprotected path or bring it under enforced coverage' }, now);
    } else {
      // A promotion closes every open task for this path — drift tasks must
      // not linger after revalidation (w8-composite F12). Task ids are
      // `${cause}:${path_id}`, so the sweep matches by exact suffix in SQL
      // rather than paging the capped id list — past 10k tasks an unclosed
      // obligation can never survive a promotion (w31-coverage F7).
      for (const row of this.store._stmt("SELECT id FROM records WHERE tenant=? AND kind='coverage-task' AND substr(id, -?) = ?").all(tenant, path.path_id.length + 1, ':' + path.path_id)) {
        const task = this.store.get(tenant, 'coverage-task', row.id);
        if (task && task.path_id === path.path_id && task.status === 'open') this.store.put(tenant, 'coverage-task', row.id, { ...task, status: 'closed', closed_at: now }, now);
      }
    }
  }
  // Rows page through the store's cap so a tenant with >10k declared
  // paths still gets every path swept and attested (w31-coverage F9).
  _allCoverage(tenant) {
    const rows = [];
    for (let off = 0;; off += 5000) {
      const page = this.store.list(tenant, 'coverage', 5000, off);
      if (!page.length) break;
      rows.push(...page);
      if (page.length < 5000) break;
    }
    return rows;
  }
  coverage(p) {
    this.authorize(p, ['operator', 'approver', 'custodian', 'security', 'auditor', 'policy_admin']);
    return this.transaction(p, now => {
      const idx = this._auditIndex(p.tenant_id);
      const rows = this._allCoverage(p.tenant_id);
      // Anchoring binds the declared identity tuple AND the chain-attested
      // status: a forged row over a declared path_id serves its anchored
      // status (never a planted ENFORCED), and identity-divergent rows
      // demote to unanchored_rows (w20-datagate F2).
      const anchoredIdentity = path => {
        try { return digest({ path_id: path.path_id, action_type: path.action_type, target: path.target, environment: path.environment, connector_version: path.connector_version, owner: path.owner, path_class: path.path_class, ...(path.connector_key_id !== undefined ? { connector_key_id: path.connector_key_id } : {}), configuration_digest: path.configuration_digest, max_age_ms: path.max_age_ms }); } catch { return null; }
      };
      const anchoredStatus = path => {
        const declared = idx.coverageDeclared?.get(path.path_id);
        if (!declared) return null;
        let s = { status: declared.status, evidence_at: declared.evidence_at };
        const events = [...(idx.coverageTransitions ?? []), ...(idx.coverageValidations ?? [])].sort((a, b) => a.seq - b.seq);
        // Epoch bound: transitions/validations from BEFORE the current
        // declaration must not promote it — a re-declared path inherits
        // nothing from the prior era (w21-fixverify H-1).
        for (const e of events) if (e.path_id === path.path_id && e.seq >= declared.seq) {
          if (e.validation) s.evidence_at = e.at;
          else { if (e.to !== undefined) s.status = e.to; s.evidence_at = e.evidence_at; }
        }
        return s;
      };
      // Evidence-expiry sweeps the ANCHORED state, not the mutable row: a
      // forged stale evidence_at (or a planted never-declared path) cannot
      // mint a real UNKNOWN transition + owner task — only genuinely stale
      // anchored evidence demotes (w31-coverage F2/F10). A declared path
      // whose row was deleted stays visible to the manifest below.
      for (const path of rows) {
        const anchored = anchoredStatus(path);
        if (anchored !== null && (anchored.status === 'MONITORED' || anchored.status === 'ENFORCED') && effectiveStatus({ ...path, status: anchored.status, evidence_at: anchored.evidence_at }, now) === 'UNKNOWN')
          this.coverageTransition(p.tenant_id, path, 'UNKNOWN', 'evidence-expired', now);
      }
      // Only chain-declared paths may appear in a vault-signed manifest —
      // a forged coverage row cannot claim ENFORCED under the gate's
      // signature; planted rows are reported separately, never attested
      // (w17-redteam A3).
      const anchoredRows = rows.filter(path => anchoredStatus(path) !== null && (idx.coverageAnchors.get(path.path_id) === anchoredIdentity(path) || (!idx.coverageAnchors.get(path.path_id) && (idx.coverageAnchorsLegacy?.get(path.path_id) === digest(path)))))
        .map(path => {
          const anchored = anchoredStatus(path);
          const declared = idx.coverageDeclared.get(path.path_id);
          const validated = (idx.coverageValidations ?? []).filter(v => v.path_id === path.path_id).at(-1);
          // The signed manifest sources validation issuer/evidence/at and
          // declared_at from the CHAIN — the mutable row's own
          // technical_validation/declared_at/evidence_digest are display
          // data a row-writer could rewrite at will (w31-coverage F5).
          const { evidence_digest: _rowDigest, ...rowFields } = path;
          return { ...rowFields, status: anchored.status, evidence_at: anchored.evidence_at, declared_at: declared?.at ?? null, technical_validation: validated ? { evidence_id: validated.evidence_id, issuer: validated.issuer, at: validated.at, outcome: 'supports' } : null, row_status: anchored.status !== path.status ? path.status : null };
        });
      // A path declared on the chain whose row was deleted is still owed
      // an attestation — enumerate declared path_ids the row list can
      // never reach and name them honestly (w31-coverage F1).
      const missing = [...(idx.coverageDeclared?.keys() ?? [])].filter(pid => !rows.some(r => r.path_id === pid));
      const unanchored = rows.filter(path => !anchoredRows.some(a => a.path_id === path.path_id)).map(path => path.path_id);
      // Open obligations derive from the anchored state — erased task rows
      // cannot hide a path the chain still calls UNKNOWN/UNCOVERED
      // (w31-coverage F6). The mutable task rows stay as display cache.
      const obligations = anchoredRows.filter(r => r.status === 'UNKNOWN' || r.status === 'UNCOVERED')
        .map(r => ({ path_id: r.path_id, owner: r.owner, status: r.status, required_action: r.status === 'UNKNOWN' ? 'attach independently executed technical validation evidence' : 'close this declared-unprotected path or bring it under enforced coverage' }));
      return coverageManifest(p.tenant_id, anchoredRows, now, payload => this.signAudit(p.tenant_id, payload, 'coverage'), { unanchored, missing, obligations });
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
    // History replays chain-anchored events only — forged coverage-event
    // rows can never rewrite the past a signed manifest attests
    // (w20-datagate F2). The mutable table stays as a display mirror.
    const idx = this._auditIndex(p.tenant_id), paths = {};
    // The declaration in force at atTime is the LATEST one with
    // d.at <= atTime — not the newest overall: era-1 history must still
    // answer honestly inside era-1 instants even after a later
    // re-declaration (w21-fixverify H-1).
    const declByPath = {};
    for (const d of idx.coverageDeclarations ?? []) {
      if (d.at > atTime) continue;
      const cur = declByPath[d.path_id];
      if (!cur || d.seq > cur.seq) declByPath[d.path_id] = d;
    }
    for (const d of Object.values(declByPath)) paths[d.path_id] = { path_id: d.path_id, status: d.status, evidence_at: d.evidence_at, max_age_ms: d.max_age_ms, decl_seq: d.seq };
    // Ledger order (seq), not wall time, decides replay order — a refresh
    // validation on an already-ENFORCED path writes no transition, so both
    // event streams merge by seq into one honest history.
    const events = [...(idx.coverageTransitions ?? []), ...(idx.coverageValidations ?? [])].sort((a, b) => a.seq - b.seq);
    for (const e of events) {
      const p = paths[e.path_id];
      if (!p || e.at > atTime || e.seq < p.decl_seq) continue;
      if (e.validation) { p.evidence_at = e.at; continue; }
      if (e.to !== undefined) p.status = e.to;
      p.evidence_at = e.evidence_at;
    }
    const out = {};
    for (const [id, s] of Object.entries(paths)) { const { decl_seq, ...rest } = s; out[id] = { ...rest, status: effectiveStatus(s, atTime), stored_status: s.status }; }
    return { at: atTime, paths: out };
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
      // The anchor binds the immutable identity tuple — status and evidence
      // fields legitimately drift through anchored transitions, so they are
      // excluded from the identity digest and verified through the chain
      // instead (w20-datagate F2).
      this.store.audit(p.tenant_id, 'COVERAGE_DECLARED', p.subject_id, path.path_id, { digest: digest(path), identity_digest: digest({ path_id: path.path_id, action_type: path.action_type, target: path.target, environment: path.environment, connector_version: path.connector_version, owner: path.owner, path_class: path.path_class, ...(path.connector_key_id !== undefined ? { connector_key_id: path.connector_key_id } : {}), configuration_digest: path.configuration_digest, max_age_ms: path.max_age_ms }), status: path.status, max_age_ms: path.max_age_ms }, now); return path;
    });
  }
  // COV-010: technical validation attaches an independently executed bypass
  // test result to a path — the only way a path can claim stronger than
  // MONITORED is a verified evidence envelope, never a checkbox.
  technicalValidation(p, path_id, envelope) {
    this.authorize(p, ['security']); return this.transaction(p, now => {
      const path = this.store.must(p.tenant_id, 'coverage', identifier(path_id));
      const idx = this._auditIndex(p.tenant_id);
      // The evidence schema is reused; its capsule_digest field binds the
      // validation to this path rather than to an action.
      const payload = this.verifyEvidenceEnvelope(p.tenant_id, envelope, path.action_type);
      // Same trust bar as attachEvidence: the envelope must bind THIS
      // tenant, carry fresh acquisition, and cite only dependencies that
      // already exist as ledger evidence — a cross-tenant, stale or
      // phantom-referencing envelope can never promote a coverage path
      // (w30-issuerd F4 mirrors attachEvidence's three gates).
      requireThat(payload.tenant_id === p.tenant_id, 'INV-403-SCOPE', 'Evidence scope mismatch', 403);
      requireThat(payload.acquired_at > now - 7 * 86400000, 'INV-400-SCHEMA', 'Evidence too old to attach', 400);
      for (const dep of payload.dependencies ?? []) requireThat(this.store.get(p.tenant_id, 'evidence', dep) !== null, 'INV-400-SCHEMA', 'Dependencies must resolve to ledger evidence', 400);
      // Same trust bar as attachEvidence: revoked signer, drifted connector,
      // out-of-kind envelope or a non-supporting outcome cannot promote a
      // coverage path (w5 F-6).
      requireThat(!this.revoked(p.tenant_id, 'issuer', envelope.protected.key_id) && !this.revoked(p.tenant_id, 'key', envelope.protected.key_id) && !this.revoked(p.tenant_id, 'evidence', payload.evidence_id), 'INV-401-EVIDENCE', 'Validation source revoked', 401);
      requireThat(!idx.issuerDrift.has(envelope.protected.key_id), 'INV-403-QUARANTINE', 'Issuer connector drifted — validation suspended pending revalidation', 403);
      const issuer = this.tenant(p.tenant_id).issuers[envelope.protected.key_id];
      requireThat(issuer.kinds.includes(payload.kind), 'INV-403-SCOPE', 'Issuer is not trusted for this evidence kind', 403);
      requireThat(issuer.version === undefined || payload.issuer_version === issuer.version, 'INV-403-SCOPE', 'Issuer version drifted from registration', 403);
      // The same trust floor evaluatePolicy applies to action evidence:
      // advisory opinions, sub-threshold confidence and communication-channel
      // issuers can never promote a coverage path — and the kind is pinned so
      // a generic attestation cannot masquerade as a bypass test (w7-seam F1).
      requireThat(payload.kind === 'technical_validation', 'INV-403-SCOPE', 'Validation evidence must be technical_validation kind', 403);
      requireThat(!payload.advisory && (payload.confidence ?? 0) >= 90, 'INV-400-SCHEMA', 'Advisory or low-confidence evidence cannot validate a path', 400);
      requireThat(issuer.channel !== 'communication', 'INV-403-SCOPE', 'Communication-channel issuers cannot technically validate a path', 403);
      requireThat(payload.claim === 'supports', 'INV-400-SCHEMA', 'Technical validation requires a supporting outcome', 400);
      // The envelope binds the path's ledger-anchored identity tuple — the
      // same declaration anchor the manifest verifies — never a row-derived
      // digest a row-writer could reshape: mutable edits (status,
      // evidence_at, technical_validation, declared_at) can neither unbind
      // an anchored validation nor mint a new envelope against the planted
      // fields (w31-coverage F3). A legacy-declared path predating the
      // identity tuple binds the whole-row digest its declaration
      // originally anchored (coverageAnchors stores null there, and a path
      // with NO anchored declaration at all is a planted row — refuse it
      // outright rather than attesting a phantom).
      const anchoredIdentityDigest = idx.coverageAnchors?.get(path.path_id) ?? idx.coverageAnchorsLegacy?.get(path.path_id);
      requireThat(anchoredIdentityDigest !== undefined, 'INV-409-INTEGRITY', 'Coverage path has no ledger-anchored declaration', 409);
      requireThat(payload.capsule_digest === anchoredIdentityDigest, 'INV-400-SCHEMA', 'Validation evidence must bind the anchored identity of this path', 400);
      // A connector can never attest its own path — the issuer named by the
      // path's declared connector (by key_id or by legacy name binding) may
      // not sign the validation, and a declared connector that drifted must
      // re-validate before its path may promote (w31-coverage F4).
      const declaredConnector = path.connector_key_id ?? Object.entries(this.tenant(p.tenant_id).issuers ?? {}).find(([, i]) => i.name === path.target)?.[0];
      requireThat(envelope.protected.key_id !== declaredConnector, 'INV-403-SCOPE', 'The covered connector cannot technically validate its own path', 403);
      requireThat(!(declaredConnector && idx.issuerDrift.has(declaredConnector)), 'INV-403-QUARANTINE', 'Declared connector drifted — coverage promotion suspended pending revalidation', 403);
      // Promotion requires a FRESH validation: an anchored prior validation
      // can never re-promote the same path — the attacker's canonical move
      // is replaying a stale envelope after it has already anchored
      // (w31-coverage F3).
      const lastValidation = (idx.coverageValidations ?? []).filter(v => v.path_id === path.path_id).at(-1);
      requireThat(!lastValidation || payload.acquired_at > lastValidation.at, 'INV-409-INTEGRITY', 'Validation evidence must be fresher than the path\'s last anchored validation', 409);
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
      this.store.audit(p.tenant_id, 'COVERAGE_TECHNICAL_VALIDATION', p.subject_id, path.path_id, { issuer: envelope.protected.key_id, evidence_id: payload.evidence_id }, now);
      return path;
    });
  }
  // AUD-003/005/010 + transparency: the audit log is a hash-chained signed log
  // whose heads also commit to a Merkle tree, so inclusion and consistency
  // proofs can be checked offline by anyone holding the export.
  auditProof(p, sequence) {
    this.authorize(p, ['auditor', 'security', 'operator']);
    integer(sequence, 'sequence', 1);
      const m = this._merkle(p.tenant_id);
      requireThat(sequence <= m.size, 'INV-404-NOT-FOUND', 'Sequence beyond log head', 404);
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
      // AUD-007: a proof READ is support access — same immutable record
      // an export writes (w22-ledger).
      this._auditAccess(p.tenant_id, p.subject_id, 'proof', { sequence });
      return { format: 'IF-MERKLE-1', tenant_id: p.tenant_id, sequence, size: m.size, leaf_hash: m.leaves[sequence - 1], leaf_signature_verified: true, path: m.proof(sequence - 1), root: m.root(), verify: 'leaf = sha256(0x00||entry_hash); node = sha256(0x01||left||right); subtree partition = maximal aligned power-of-two split', pin: { root: m.root(), size: m.size }, witness_instruction: 'store `pin` off-box — an in-band proof is only as strong as the head replay residual; pinning (root,size) externally converts it to conviction (w34-fixverify H-1)' };
  }
  auditConsistency(p, first) {
    this.authorize(p, ['auditor', 'security', 'operator']);
    integer(first, 'first size', 1);
      const m = this._merkle(p.tenant_id);
      requireThat(first <= m.size, 'INV-404-NOT-FOUND', 'First size beyond log head', 404);
      const proof = m.consistency(first);
      this._auditAccess(p.tenant_id, p.subject_id, 'consistency', { first });
      return { format: 'IF-MERKLE-1', tenant_id: p.tenant_id, first, second: m.size, first_root: m.root(0, first), second_root: m.root(), proof, pin: { root: m.root(), size: m.size } };
  }
  verifyAuditProof(tenant, proof, pinned = null) {
    // Stateless helper for the offline verifier and tests. When `pinned`
    // ({root, size} from a previously trusted checkpoint) is supplied, the
    // claimed tree is bound to it — an RFC-6962 inclusion proof is only
    // meaningful relative to a pinned (root, size).
    requireThat(proof && typeof proof === 'object' && !Array.isArray(proof), 'INV-400-SCHEMA', 'Invalid proof', 400);
    // The tenant arg binds the proof — a caller on tenant B must never
    // verify tenant A's tree as `valid:true` (w34-fixverify L-2).
    requireThat(proof.tenant_id === tenant, 'INV-403-SCOPE', 'Proof tenant mismatch', 403);
    if (pinned) requireThat(pinned.root === proof.root && pinned.size === proof.size, 'INV-409-FORK', 'Proof does not match the pinned checkpoint', 409);
    return verifyInclusion(proof.leaf_hash, proof.sequence - 1, proof.size, proof.path, proof.root);
  }
  exportAudit(p, purpose) {
    this.authorize(p, ['auditor', 'security']); text(purpose, 'audit export purpose', 256);
    return this.transaction(p, now => {
      // Same keyed-digest treatment as revocation reasons — an exported
      // log must not hand an offline oracle for enumerable export purposes
      // like "quarterly PCI audit" (w15-timing F4).
      this.store.audit(p.tenant_id, 'AUDIT_ACCESSED', p.subject_id, 'tenant-log', { surface: 'export', purpose_digest: createHmac('sha256', this.vault.masterKey).update(canonical({ purpose })).digest('base64url') }, now);
      return this.store.auditExport(p.tenant_id, now);
    });
  }
  // AUD-007: every audit-log READ records itself — support access must
  // leave the same immutable record an export writes (w22-ledger). The
  // access row lands after the served data so a paged reader never sees
  // the row its own request appended.
  _auditAccess(t, actor, surface, detail) {
    const now = this.clock(); this.store.clock(now);
    this.store.audit(t, 'AUDIT_ACCESSED', actor, 'tenant-log', { surface, ...detail }, now);
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
    // AUD-010 projections filter AFTER verification. A single raw page
    // filtered down can serve far under the requested limit — page forward
    // until the projection fills or the chain ends, bounded at 64 raw
    // pages so a sparse projection cannot pin the request (w38-http LOW).
    const PROJECTIONS = {
      finance: ['CAPSULE_PROPOSED', 'EVIDENCE_ATTACHED', 'EXACT_ACTION_APPROVED', 'BATCH_APPROVED', 'CERTIFICATE_ISSUED', 'EXECUTION_RESERVED', 'EXECUTION_OUTCOME', 'EXECUTION_DRY_RUN', 'ACTION_CANCELLED', 'EXECUTION_COMPLETED_POST_REVOCATION', 'POLICY_EVALUATED'],
      privacy: ['RETENTION_DELETED', 'RETENTION_HOLD_CHANGED', 'CAPABILITY_ISSUED', 'RUNTIME_ALLOWED', 'PERCEPTION_SESSION', 'PERCEPTION_RELEASE', 'PERCEPTION_FALLBACK', 'AUDIT_ACCESSED'],
      technical: ['CONFIG_DRIFT', 'CONFIG_REASSERTED', 'CONFIG_SNAPSHOT', 'CONNECTOR_DRIFT', 'COVERAGE_DECLARED', 'COVERAGE_STALED', 'COVERAGE_TECHNICAL_VALIDATION', 'COVERAGE_TRANSITION', 'CLOCK_RECOVERED', 'KEY_ROTATED', 'ROTATION_PREPARED', 'CEREMONY_PLANNED', 'CEREMONY_ACKNOWLEDGED', 'CEREMONY_SHARES_COMMITTED', 'CEREMONY_RECONSTRUCTED', 'EVIDENCE_ACQUISITION_FAILED', 'ISSUER_SPEC_REPINNED', 'REMEDIATION_REQUESTED', 'JIT_GRANT_ISSUED', 'RECOVERY_NOTICE_ISSUED', 'POLICY_GENESIS', 'POLICY_STAGED', 'POLICY_SIMULATED', 'POLICY_SUPERSEDED', 'EMERGENCY_POLICY_ACTIVATED', 'AI_ADVISORY', 'SECURITY_OPERATION_REJECTED', 'AUTHORITY_REVOKED'],
    };
    let viewTypes = null;
    if (options.view !== undefined) {
      requireThat(Object.hasOwn(PROJECTIONS, options.view), 'INV-400-SCHEMA', `Unknown audit projection ${options.view}`);
      viewTypes = new Set(PROJECTIONS[options.view]);
    }
    const wanted = options.limit ?? 1000;
    const entries = [];
    let nextCursor = null, scanned = 0;
    // The raw-page cap bounds storage reads, not verify work: a cold scan
    // pays an Ed25519 verify per row (~115µs), so 64×5000 rows is a ~35-45s
    // event-loop blockade for every tenant on the process. Bound the loop
    // on wall-clock too — a time-out returns the honest partial page plus
    // the cursor to continue, identical semantics to the page cap
    // (w47-http MED).
    const deadline = Date.now() + 2000;
    for (let after = options.after; after === options.after || nextCursor !== null;) {
      const raw = this.store.auditPage(p.tenant_id, { after, limit: wanted });
      this.#verifyAuditPageEntries(p.tenant_id, raw.entries);
      if (viewTypes) { for (const e of raw.entries) if (viewTypes.has(e.envelope.payload.type)) entries.push(e); }
      else entries.push(...raw.entries);
      nextCursor = raw.next_cursor;
      if (entries.length >= wanted || nextCursor === null || ++scanned >= 64 || Date.now() > deadline) break;
      after = nextCursor;
    }
    // If accumulation overshot the limit, the served tail is truncated —
    // the cursor must then be the last SERVED row's seq (not the raw page
    // end) or the truncated matching rows are silently skipped (w38-http).
    const page = { entries: entries.slice(0, wanted), next_cursor: entries.length > wanted ? entries[wanted - 1].sequence : nextCursor };
    if (this.auditDigestOnly(p)) page.entries = page.entries.map(e => this.auditEntryScoped(e));
    // AUD-007: a paged audit READ is support access — record it after the
    // page is served so the row lands after, never inside, the result
    // (w22-ledger).
    this._auditAccess(p.tenant_id, p.subject_id, 'page', { after: options.after ?? 0, limit: options.limit ?? null, view: options.view ?? null, served: page.entries.length });
    return page;
  }
  #verifyAuditPageEntries(tenant, pageEntries) {
    // The audit READ surface is evidence: every served row must be a real
    // vault-signed entry, not an in-process forgery appended under the seq
    // trigger (w12 red-team). A row that fails signature verification flags
    // loudly rather than blending into history.
    const keys = this.auditPublicKeys(tenant), deadAt = this._auditIndex(tenant).keyDeadAt;
    // A verified row's signature verdict never changes — memoize on
    // (seq, envelope digest) so each page serves O(limit) map hits
    // instead of O(limit) signature verifications. The key must cover
    // the verified BYTES: keying on the stored hash column alone would
    // let an insider tamper only the envelope and be served from cache
    // (w18-http F-3). The dead-key window is re-checked every call —
    // it tightens after later revocations.
    const memo = this._pageVerifyMemo ??= new Map();
    for (const e of pageEntries) {
      let ok = false; try {
        const kid = e.envelope?.protected?.key_id, dead = kid !== undefined ? deadAt.get(kid) : undefined;
        if (e.envelope && !(dead !== undefined && dead < e.sequence)) {
          const memoKey = `${tenant}:${e.sequence}:${digest(e.envelope)}`;
          if (memo.has(memoKey)) ok = true;
          else {
            ok = verifySigned(e.envelope, keys, 'audit').tenant_id === tenant;
            if (ok) { if (memo.size > 100000) memo.clear(); memo.set(memoKey, true); }
          }
        }
      } catch { ok = false; }
      requireThat(ok, 'INV-409-INTEGRITY', 'Audit page contains a row whose ledger signature does not verify', 409);
    }
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
        const record = this._mustAnchored(p.tenant_id, 'capsule', capsuleId);
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
    const record = this._mustAnchored(t, 'capsule', capsuleId); this.ensureMutable(record); this._capsuleIntegrity(t, record);
    requireThat(identity.subject_id !== record.capsule.actor.subject_id, 'INV-403-SEPARATION', 'An initiator cannot approve their own action', 403);
    requireThat(payload.capsule_digest === record.capsule_digest && payload.evidence_graph_digest === this.graph(t, record).digest && payload.policy_digest === this._policyDigest(t), 'INV-409-STATE', 'Approval no longer matches action, evidence or policy', 409);
    integer(payload.approved_at, 'approval time', now - 300000, now + 5000); integer(payload.expires_at, 'approval expiry', now + 1, Math.min(record.capsule.expires_at, payload.approved_at + 300000));
    // Only a LIVE approval on the SAME binding blocks the signer: a lapsed
    // envelope stops counting in evaluation, and one bound to a stale
    // action/evidence/policy digest stops counting identically — it must not
    // also burn the signer's re-approval of the changed material for the
    // remainder of its TTL (w11-lifecycle F3, w28-http F-06).
    requireThat(!record.approvals.some(a => a.payload.signer_id === payload.signer_id && a.payload.expires_at > now
      && a.payload.capsule_digest === payload.capsule_digest && a.payload.evidence_graph_digest === payload.evidence_graph_digest && a.payload.policy_digest === payload.policy_digest), 'INV-409-REPLAY', 'Signer already approved this action', 409);
    record.approvals.push(clone(envelope)); this.store.put(t, 'capsule', capsuleId, record, now);
    this.store.audit(t, 'EXACT_ACTION_APPROVED', p.subject_id, capsuleId, { approval_digest: digest(envelope), signer_id: payload.signer_id, expires_at: payload.expires_at }, now);
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
    // The anchored check binds the occurrence within ±2s, not exact
    // equality: the containment row's contained_at and the anchored
    // denial's payload time are two different clock reads (n0 before the
    // tx, now inside it) — strict equality marks honestly-anchored rows
    // unanchored, indistinguishable from murdered ones (w49-runtime W49-5).
    const denials = this.store.list(t, 'containment', 10000).map(c => ({ kind: 'denied_consume', at: c.contained_at, code: c.code, subject_id: c.subject_id, capability_id: c.capability_id, unverified_capability_id: c.unverified_capability_id ?? null, resource: c.resource, request_id: c.request_id, dropped_requests: c.dropped_requests, anchored: (idx.denialsByReq?.get(c.request_id) ?? []).some(d => d.code === c.code && d.actor === c.subject_id && d.capability_id === (c.capability_id ?? null) && Math.abs(d.at - c.contained_at) <= 2_000) }));
    // The anchored digest is vault-keyed (w15-timing F3): the cross-check
    // must recompute the same MAC — a plain digest() compares against a
    // different construction and the flag is always 'identity-only', i.e.
    // dead code that hid row tampering (w17-fixverify).
    const metaMac = v => createHmac('sha256', this.vault.masterKey).update(canonical(v)).digest('base64url');
    const quarantines = this.store.list(t, 'revocation', 10000).filter(r => ['subject', 'device'].includes(r.kind) && idx.revoked.has(`${r.kind}:${r.id}`)).map(r => ({ kind: 'revocation', at: r.revoked_at, revoked: `${r.kind}:${r.id}`, by: r.actor, anchored: idx.revocationDigests.has(`${r.kind}:${r.id}`) && ctEqual(idx.revocationDigests.get(`${r.kind}:${r.id}`), metaMac(r)) ? true : 'identity-only' }));
    const sequence = [...denials, ...quarantines].sort((a, b) => a.at - b.at);
    // Murdered denial evidence runs the other direction too: every
    // anchored RUNTIME_DENIED event must still find its mutable
    // containment row, or the report attests the deletion instead of
    // blending it into the sequence (w43-runtime M4). The binding is by
    // OCCURRENCE, not by triple presence — a murdered row masked by a
    // fresh same-triple denial still counts as missing (w44-runtime F2):
    // each anchor consumes one matching row. The row multiset spans the
    // WHOLE table, paged until every anchor resolves — the served window
    // is newest-N by the mutable 'created' column, so an anchored row
    // outside it must never fabricate missing evidence (w45-runtime F4).
    // Occurrence binding keys on (triple, timestamp): caller-controlled
    // request_id CAN repeat across events, so a per-triple multiset lets a
    // fresh same-triple row claim the murdered OLDER anchor's seat and the
    // report names the live row as the victim. Each anchor instead claims
    // the surviving row whose contained_at is nearest its own `at` (≤2s —
    // the pair is minted from the same clock read, so exact matches rule
    // and the bound only absorbs clock granularity), making the murdered
    // occurrence itself the named victim (w46-fixverify M-1).
    const rowsByTriple = new Map();
    for (let off = 0; ;) {
      const pageRows = this.store.list(t, 'containment', 10000, off);
      if (!pageRows.length) break;
      off += pageRows.length;
      for (const c of pageRows) {
        const k = `${c.request_id}|${c.code}|${c.subject_id}`;
        let arr = rowsByTriple.get(k); if (!arr) { arr = []; rowsByTriple.set(k, arr); }
        arr.push(c.contained_at);
      }
      if (pageRows.length < 10000) break;
    }
    for (const arr of rowsByTriple.values()) arr.sort((a, b) => a - b);
    // Name the NEWEST victims first — a >512-row murder must always
    // surface the freshest evidence inside the cap, with the uncapped
    // total published alongside so saturation can never read as 512
    // (w45-runtime F5).
    const missingDenials = [];
    let missingTotal = 0;
    for (const d of [...idx.denials].reverse()) {
      const arr = rowsByTriple.get(`${d.request_id}|${d.code}|${d.actor}`);
      let hit = -1, best = Infinity;
      if (arr) for (let i = 0; i < arr.length; i++) { const dt = Math.abs(arr[i] - d.at); if (dt < best) { best = dt; hit = i; } }
      if (hit >= 0 && best <= 2_000) { arr.splice(hit, 1); continue; }
      missingTotal++;
      if (missingDenials.length < 512) missingDenials.push({ request_id: d.request_id, code: d.code, subject_id: d.actor, at: d.at });
    }
    this._auditAccess(t, p.subject_id, 'containment', { denials: denials.length, revocations: quarantines.length });
    // The counter sums each row's dropped_requests tally — the 60s dedup
    // collapses a burst into one row whose counter the writer still
    // increments, so the report counts requests, not surviving rows
    // (w43-runtime dropped_requests LOW). A malformed or planted tally
    // degrades to one request per row, never a crash. The tally lives on
    // mutable ciphertext: it is a CLAIMED counter, not an anchored one —
    // a captured (value,wrapped) replay rewinds it silently, so the
    // report must name it unanchored and publish the chain-derived floor
    // alongside (w44-runtime F1).
    const droppedRequests = denials.reduce((n, d) => n + (Number.isInteger(d.dropped_requests) && d.dropped_requests > 0 ? d.dropped_requests : 1), 0);
    return { sequence, dropped_requests: droppedRequests, dropped_requests_unanchored: droppedRequests, anchored_denial_events: idx.denials.length, unanchored_fields: ['dropped_requests', 'contained_at', 'device_id', 'resource', 'destination', 'unverified_capability_id'], unanchored_rows: sequence.filter(x => x.anchored !== true).length, anchored_denials_missing_rows: missingDenials, anchored_denials_missing_total: missingTotal, affected_capabilities: [...new Set(denials.map(d => d.capability_id).filter(Boolean))], quarantined: quarantines.map(q => q.revoked), limitation: 'Software dataplane telemetry only; packet-level counters require a real network path.' };
  }
  retention(p, input) {
    this.authorize(p, ['security']); fields(input, ['evidence_id', 'legal_hold']); identifier(input.evidence_id); requireThat(typeof input.legal_hold === 'boolean', 'INV-400-SCHEMA', 'Legal hold must be boolean');
    return this.transaction(p, now => { const e = this._mustAnchored(p.tenant_id, 'evidence', input.evidence_id); e.legal_hold = input.legal_hold; this.store.put(p.tenant_id, 'evidence', input.evidence_id, e, now); this.store.audit(p.tenant_id, 'RETENTION_HOLD_CHANGED', p.subject_id, input.evidence_id, { legal_hold: input.legal_hold }, now); return { evidence_id: input.evidence_id, legal_hold: input.legal_hold }; });
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
      for (const id of capsuleIds) { try { records.push(this._mustAnchored(p.tenant_id, 'capsule', id)); } catch { corrupt.push(['capsule', id]); } }
      // Coverage rows join the reference scan per-id: one corrupt coverage
      // record must not wedge the whole sweep (w8-fixverify F5).
      for (const id of coverageIdsList) { try { const c = this.store.must(p.tenant_id, 'coverage', id); if (c.technical_validation?.evidence_id) citedEvidence.add(c.technical_validation.evidence_id); } catch { corrupt.push(['coverage', id]); } }
      // Live references are computed BEFORE any shred: an actively
      // referenced corrupt row is held, not erased — the same hold rule
      // that applies to decryptable rows must cover corrupt ones, or the
      // sweep un-references evidence a live capsule still needs (w22 F5).
      const liveRefs = new Set();
      for (const r of records) if (Array.isArray(r.evidence) && !['VERIFIED', 'FAILED', 'DENY', 'CANCELLED', 'COMPENSATED'].includes(r.status)) for (const eid of r.evidence) liveRefs.add(eid);
      for (const eid of citedEvidence) liveRefs.add(eid);
      // Undecryptable residue is itself erased — a corrupt row can never
      // become readable again, so keeping it only leaks ciphertext
      // indefinitely (DEK-audit F5).
      for (const [kind, id] of corrupt) {
        if (kind === 'evidence' && liveRefs.has(id)) continue;
        this.store.shred(p.tenant_id, kind, id);
        // A corrupt-row shred is retention too — anchor the tombstone or
        // the anchored-but-missing row reads as tamper evidence forever
        // instead of the honest miss it is (w32-fixverify F-3).
        this.store.audit(p.tenant_id, 'RETENTION_DELETED', p.subject_id, id, { crypto_shred: true, corrupt: true, key_id: null, kind }, now);
      }
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
        const activeReference = liveRefs.has(e.payload.evidence_id);
        if (e.legal_hold || activeReference) { held++; continue; }
        const original_digest = digest(e.envelope);
        // put(), not insert(): an issuer may legitimately re-mint a shredded
        // evidence_id — a stale tombstone must then be overwritten, or the
        // sweep wedges permanently on INV-409-CONFLICT (DEK-audit F1).
        // Re-minted evidence ids overwrite the tombstone but never erase the
        // receipt history — earlier erasures stay provable (w8-fixverify F7).
        const priorTomb = this.store.get(p.tenant_id, 'evidence-tombstone', e.payload.evidence_id);
        const superseded = priorTomb ? [...(priorTomb.superseded ?? []), { original_digest: priorTomb.original_digest, deleted_at: priorTomb.deleted_at }] : [];
        // key_id+kind persist so a later same-issuer+kind attach can still
        // retire this deleted member in the evidence graph (w22 F5).
        this.store.put(p.tenant_id, 'evidence-tombstone', e.payload.evidence_id, { evidence_id: e.payload.evidence_id, original_digest, deleted_at: now, superseded, key_id: e.envelope?.protected?.key_id ?? null, kind: e.payload?.kind ?? null }, now);
        this.store.shred(p.tenant_id, 'evidence', e.payload.evidence_id); deleted++;
        // The tombstone's issuer+kind anchor on the chain — the mutable
        // tomb row may not redefine which attach family it claims to retire
        // (w23-fixverify F-e).
        this.store.audit(p.tenant_id, 'RETENTION_DELETED', p.subject_id, e.payload.evidence_id, { original_digest, crypto_shred: true, key_id: e.envelope?.protected?.key_id ?? null, kind: e.payload?.kind ?? null }, now);
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
        const identity = members.find(i => i.subject_id === c && !i.revoked && i.roles?.includes('custodian'));
        // Existence alone is not consentability: a subject without a live
        // custodian-role enrolment can never ack — the ceremony would wedge
        // below threshold forever and burn its anchored id (w20-ceremony
        // W20-4).
        requireThat(identity, 'INV-403-ROLE', `Ceremony custodian ${c} holds no live custodian-role enrolment`, 403);
        domains.add(identity.failure_domain ?? c);
      }
      requireThat(domains.size >= (input.threshold ?? 0), 'INV-400-SCHEMA', 'Custodian failure domains cannot meet the ceremony threshold', 400);
      const ceremony = createCeremony({ ...input, tenant_id: t });
      // An anchored ceremony id is burned forever: a row writer who deletes
      // the row must not reopen the id — a replan would inherit every ack
      // the ledger already anchored for it (w18-fixverify2 B6).
      const pidx = this._auditIndex(t);
      requireThat(!pidx.ceremonyPlanned?.has(ceremony.ceremony_id), 'INV-409-CONFLICT', 'Ceremony id is already anchored in the ledger — plan a new id', 409);
      this.store.insert(t, 'ceremony', ceremony.ceremony_id, ceremony, now);
      this.store.audit(t, 'CEREMONY_PLANNED', p.subject_id, ceremony.ceremony_id, { digest: ceremony.artifact_digest, threshold: ceremony.threshold }, now);
      return ceremony;
    });
  }
  acknowledgeCeremony(p, envelope) {
    this.authorize(p, ['custodian']);
    return this.transaction(p, now => {
      const t = p.tenant_id, payload = verifySigned(envelope, this.identities(t), 'ceremony-acknowledgement');
      this.assertSuiteAllowed(t, envelope.protected.suite);
      fields(payload, ['ceremony_id', 'artifact_digest', 'custodian', 'acknowledged_at']);
      // Health is checked on the enrolment that actually signed the ack —
      // not the subject's first-found one — so a stale second enrolment
      // cannot attest while the healthy first answers for it
      // (w20-ceremony W20-3).
      const ackIdentity = this.identities(t)[envelope.protected.key_id];
      requireThat(ackIdentity?.subject_id === p.subject_id, 'INV-403-SCOPE', 'Acknowledgement signer does not match the custodian identity', 403);
      this.assertHealthy(t, p.subject_id, ackIdentity.device_id, now);
      const ceremony = this.store.must(t, 'ceremony', identifier(payload.ceremony_id));
      // Anchored lifecycle wins over the mutable row: a status flip can
      // never re-open consent on a ceremony the ledger already closed
      // (w18-fixverify F2).
      const cidx = this._auditIndex(t);
      requireThat(!(cidx.ceremonyAborted?.has(ceremony.ceremony_id) || cidx.ceremonyCompleted?.has(ceremony.ceremony_id)), 'INV-409-STATE', 'Ceremony is ledger-anchored as closed', 409);
      // Lifecycle events may only accumulate on a ceremony the chain
      // actually planned — a planted row must not collect anchored
      // consent (w19-lifecycle F7).
      requireThat(this._ceremonyPlanAnchored(t, ceremony), 'INV-409-INTEGRITY', 'Ceremony has no anchored plan', 409);
      // Consent binds to the anchored epoch, not the mutable
      // artifact_digest the row carries: post-commit the epoch is the
      // commit rebind, so flipping artifact_digest cannot erase the acks
      // that were already verified (w20-ceremony W20-2).
      requireThat(payload.custodian === p.subject_id && payload.artifact_digest === this._ceremonyConsentDigest(t, ceremony), 'INV-403-SCOPE', 'Acknowledgement scope mismatch', 403);
      // Ceremony-bound device pinning: when the ceremony declared which
      // device a custodian acknowledges from, the live identity must match
      // (w6 F7).
      if (ceremony.devices?.[p.subject_id]) requireThat(ackIdentity.device_id === ceremony.devices[p.subject_id], 'INV-403-SCOPE', 'Acknowledgement device does not match the ceremony binding', 403);
      requireThat(Math.abs(payload.acknowledged_at - now) <= 300000, 'INV-409-STATE', 'Acknowledgement timestamp outside window', 409);
      acknowledge(ceremony, p.subject_id, envelope, now);
      // The stored digest tracks the consent epoch the acks attest — the
      // commit rebind after shares commit — so an artifact_digest flip can
      // never widen what was acknowledged (w20-ceremony W20-2).
      ceremony.artifact_digest = this._ceremonyConsentDigest(t, ceremony);
      this.store.put(t, 'ceremony', ceremony.ceremony_id, ceremony, now);
      // The acknowledged artifact + signing key ride the anchor so a
      // truncated ack array cannot wedge quorum — the chain re-supplies
      // the consent that was already verified (w19-lifecycle F5).
      this.store.audit(t, 'CEREMONY_ACKNOWLEDGED', p.subject_id, ceremony.ceremony_id, { custodian: p.subject_id, artifact_digest: ceremony.artifact_digest, key_id: envelope.protected.key_id }, now);
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
      // Anchored lifecycle + anchored commitment: a row flip can neither
      // resurrect a closed ceremony nor re-open an already-committed deal
      // to restart the delay clock (w18-fixverify F2).
      const cidx = this._auditIndex(p.tenant_id);
      requireThat(!(cidx.ceremonyAborted?.has(ceremony.ceremony_id) || cidx.ceremonyCompleted?.has(ceremony.ceremony_id) || cidx.ceremonyCommitted?.has(ceremony.ceremony_id)), 'INV-409-STATE', 'Ceremony is ledger-anchored as closed or committed', 409);
      requireThat(this._ceremonyPlanAnchored(p.tenant_id, ceremony), 'INV-409-INTEGRITY', 'Ceremony has no anchored plan', 409);
      commitShares(ceremony, shares, now);
      this.store.put(p.tenant_id, 'ceremony', ceremony.ceremony_id, ceremony, now);
      // The commitment SET is anchored, not just its count: a swapped
      // share_commitments list must diverge from what the quorum actually
      // committed to (w19-lifecycle F2).
      this.store.audit(p.tenant_id, 'CEREMONY_SHARES_COMMITTED', p.subject_id, ceremony.ceremony_id, { count: ceremony.share_commitments.length, commitments_digest: digest(ceremony.share_commitments) }, now);
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
      // An anchored-closed ceremony can never be aborted a second time —
      // a row-status flip does not re-open the kill switch (w18-fixverify F2).
      const cidx = this._auditIndex(p.tenant_id);
      requireThat(!(cidx.ceremonyAborted?.has(ceremony.ceremony_id) || cidx.ceremonyCompleted?.has(ceremony.ceremony_id)), 'INV-409-STATE', 'Ceremony is ledger-anchored as closed', 409);
      requireThat(this._ceremonyPlanAnchored(p.tenant_id, ceremony), 'INV-409-INTEGRITY', 'Ceremony has no anchored plan', 409);
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
      // One-shot: a completed or aborted ceremony can never be re-run with
      // a different share subset — the status must land on the stored row,
      // not just on the working clone (w18-crypto F4).
      requireThat(!['completed', 'aborted'].includes(ceremony.status), 'INV-409-STATE', 'Ceremony is already closed', 409);
      // The anchored lifecycle is the authority: a row-status flip can
      // never resurrect what the ledger already closed (w18-fixverify F2).
      const cidx = this._auditIndex(t);
      requireThat(!(cidx.ceremonyAborted?.has(ceremony.ceremony_id) || cidx.ceremonyCompleted?.has(ceremony.ceremony_id)), 'INV-409-STATE', 'Ceremony is ledger-anchored as closed', 409);
      // The consent quorum and the share quorum are one set: every presented
      // share must belong to a custodian who acknowledged the committed
      // artifact, and the acknowledgements themselves must span distinct
      // failure domains with all custodians still live (w6 F5/F7/F9).
      // Committed-set divergence is an integrity event, not a state one —
      // it must report before the quorum denial so tampering can never
      // hide behind an innocent-looking refusal (w20-ceremony W20-2).
      const anchoredCommitted = cidx.ceremonyCommitted?.get(ceremony.ceremony_id);
      requireThat(anchoredCommitted !== undefined, 'INV-409-INTEGRITY', 'Ceremony share commitment is not ledger-anchored', 409);
      // Ceremonies committed before the digest existed carry no field —
      // grandfathered events pass on the anchor alone, every event minted
      // since binds the commitment bytes exactly (w20-fixverify F-3).
      requireThat(anchoredCommitted.commitments_digest === null || (typeof anchoredCommitted.commitments_digest === 'string' && digest(ceremony.share_commitments) === anchoredCommitted.commitments_digest), 'INV-409-INTEGRITY', 'Ceremony share commitments diverge from the anchored commitment set', 409);
      const quorum = this.custodianQuorum(t, ceremony);
      // Same F1 contract as the rotation bond: the plan anchor is required
      // and the floor is at least one live custodian — a row-minted
      // threshold can never conjure 0 >= 0.
      requireThat(quorum.planAnchored && quorum.live >= Math.max(1, ceremony.threshold), 'INV-409-STATE', 'Ceremony lacks a live custodian quorum across failure domains', 409);
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
      // share commitment the ledger actually attested, and the commitment
      // bytes were proven anchored above (w17-redteam A2, w19 F2).
      // 'Every custodian was notified' attests through the chain, not the
      // mutable notices array — a padded or truncated row can neither fake
      // coverage nor wedge a legitimate reconstruction (w18-fixverify F15).
      const notified = cidx.ceremonyNotices?.get(ceremony.ceremony_id) ?? new Set();
      requireThat(ceremony.custodians.every(c => notified.has(c)), 'INV-409-STATE', 'Custodian notice coverage is not ledger-anchored', 409);
      const settled = { ...ceremony, committed_at: anchoredCommitted.at, notices: ceremony.custodians.map(c => ({ custodian: c })) };
      const { secret, artifact } = reconstructSecret(settled, shares, now);
      // The status flip inside reconstructSecret lands on the clone passed
      // to it — re-apply it to the stored row so the one-shot invariant
      // actually persists (w18-crypto F4).
      ceremony.status = 'completed';
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
      // Same anchored-closed/committed guard as commitCeremonyShares — a
      // row flipped back to 'planned' cannot re-deal the secret
      // (w18-fixverify F2).
      const cidx = this._auditIndex(p.tenant_id);
      requireThat(!(cidx.ceremonyAborted?.has(ceremony.ceremony_id) || cidx.ceremonyCompleted?.has(ceremony.ceremony_id) || cidx.ceremonyCommitted?.has(ceremony.ceremony_id)), 'INV-409-STATE', 'Ceremony is ledger-anchored as closed or committed', 409);
      requireThat(this._ceremonyPlanAnchored(p.tenant_id, ceremony), 'INV-409-INTEGRITY', 'Ceremony has no anchored plan', 409);
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
      this.store.audit(p.tenant_id, 'CEREMONY_SHARES_COMMITTED', p.subject_id, ceremony.ceremony_id, { count: ceremony.share_commitments.length, commitments_digest: digest(ceremony.share_commitments) }, now);
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
      const purpose = this._keyPurposes?.[key_class];
      requireThat(purpose, 'INV-503-CONFIG', `No purpose map for key class ${key_class} — a pending key minted 'any' would float across classes`, 503);
      const pending = this.vault.generate(purpose, { pending: true, suite, tenant_id: p.tenant_id });
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
      // Health before crypto work: a quarantined caller pays no attestation
      // cost (w26-perception F-10).
      this.assertHealthy(t, p.subject_id, this.identity(p).device_id, now);
      // Replay guard BEFORE the attestation crypto — a forged replay pays a
      // cheap SELECT + anchored-set probe, not a signature verify and a
      // P-256 keygen (w30-perception F4). Bare-key lookup covers
      // pre-namespacing rows as well (w9-fixverify NB-5).
      const nonce = attestation?.payload?.nonce ?? null;
      const seen = this.store._stmt('SELECT capsule FROM nonces WHERE tenant=? AND nonce IN (?, ?)').get(t, 'perception:' + nonce, nonce);
      requireThat(!seen && !this._auditIndex(t).perceptionNonce.has(nonce), 'INV-409-REPLAY', 'Attestation nonce already consumed', 409);
      // The constitutional suite floor reaches attestation like every other
      // signature consumer — a retired suite cannot mint sessions under a
      // component that still holds its key (w30-perception F3).
      fields(attestation, ['protected', 'payload', 'signature']);
      this.assertSuiteAllowed(t, attestation.protected.suite);
      const session = openSession(component, attestation, this.policy(t), now);
      // Live-session cap: each mint writes a durable row AND a signed chain
      // event — an authorized caller must not grow either without bound
      // (w26-perception F-9). The anchored index counts only sessions that
      // have not expired.
      let live = 0, minted = 0;
      for (const [, s] of this._auditIndex(t).perceptionSessions) { if ((s.expires_at ?? 0) > now) live++; if ((s.minted_at ?? 0) > now - 3_600_000) minted++; }
      requireThat(live < 64, 'INV-429-QUOTA', 'Perception live-session cap reached (64)', 429);
      // The durable-growth bound the cap exists for: expiring-session churn
      // (1ms TTLs) still lands a row, a nonce and a signed chain event per
      // mint — bound the mint RATE, not only the live window
      // (w27-fixverify W27-03).
      requireThat(minted < 256, 'INV-429-QUOTA', 'Perception mint-rate cap reached (256/hour)', 429);
      this.store._landed(() => this.store._stmt('INSERT INTO nonces VALUES(?,?,?)').run(t, 'perception:' + attestation.payload.nonce, `perception:${session.session_id}`), 'nonce burn');
      const stored = { ...session, _server_private: session._server_private.export({ type: 'pkcs8', format: 'pem' }), creator: p.subject_id };
      this.store.insert(t, 'perception-session', session.session_id, stored, now);
      // The channel identity is anchored, not merely stored: creator, expiry
      // and the ECDH pair digest ride in the signed event so a planted or
      // rewritten session row can never swap the release key, stretch the
      // TTL or hijack the creator binding (w18-issuerd F-1).
      this.store.audit(t, 'PERCEPTION_SESSION', p.subject_id, session.session_id, { component: session.component, assurance: session.assurance, firmware: session.firmware_version, nonce: attestation.payload.nonce, creator: p.subject_id, expires_at: session.expires_at, channel_digest: digest({ component_ecdh: session.component_ecdh, server_ephemeral: session.server_ephemeral }), signing_key_id: component.signing.key_id }, now);
      return { session_id: session.session_id, assurance: session.assurance, production: false, component: session.component, expires_at: session.expires_at, ephemeral_public: session.server_ephemeral };
    });
  }
  perceptionRelease(p, session_id, release) {
    this.authorize(p, ['operator', 'approver', 'custodian', 'security']);
    const t = p.tenant_id, sid = identifier(session_id);
    // An expired session shreds its private half on first observation,
    // not only when the operator sweep runs — the residency window is
    // 'until someone looks', never 'until cron' (w26-perception F-10).
    // The tombstone must commit: writing it inside the refusal's
    // transaction would roll the shred back with the refuse.
    let probe = null;
    try { probe = this.store.must(t, 'perception-session', sid); } catch { /* the tx below reports the honest error */ }
    if (probe && (!(probe.expires_at > this.clock()) || probe._server_private == null)) {
      if (probe._server_private != null) { probe._server_private = null; this.store.put(t, 'perception-session', sid, probe, this.clock()); }
      requireThat(false, 'INV-409-STATE', 'Perception session expired or retired', 409);
    }
    return this.transaction(p, now => {
      const session = this.store.must(t, 'perception-session', sid);
      this.assertHealthy(t, p.subject_id, this.identity(p).device_id, now);
      // A session is bound to its creator — another identity cannot release
      // into someone else's sealed channel (runtime-audit F-12).
      requireThat(session.creator === p.subject_id, 'INV-403-SCOPE', 'Perception session belongs to another identity', 403);
      // The sealed-channel binding is chain-anchored: a row carrying a
      // swapped component key, a stretched expiry or a forged creator can
      // never pass — the ledger attests what the session was minted as
      // (w18-issuerd F-1).
      const anchoredSession = this._auditIndex(t).perceptionSessions.get(sid);
      const releaseComponent = anchoredSession ? this.perceptionComponents[t]?.[anchoredSession.component] : null;
      requireThat(anchoredSession && anchoredSession.creator === session.creator && anchoredSession.expires_at === session.expires_at && anchoredSession.channel_digest === digest({ component_ecdh: session.component_ecdh, server_ephemeral: session.server_ephemeral })
        // Anchors written before the assurance/firmware fields existed
        // carry null — they may ONLY claim the component's configured
        // values. Tolerating a bare null let a planted row label ride the
        // sealed release trail as 'hardware-enclave' (w27-fixverify W27-04).
        && (anchoredSession.assurance == null ? session.assurance === (releaseComponent?.assurance ?? ASSURANCE.dev) : anchoredSession.assurance === session.assurance)
        // A component that declares no firmware pins the minted constant,
        // not a config-shaped hole a planted row can claim through
        // (w28-fixverify F9).
        && (anchoredSession.firmware == null ? session.firmware_version === (releaseComponent?.firmware_version ?? session.firmware_version) : anchoredSession.firmware === session.firmware_version), 'INV-409-INTEGRITY', 'Perception session diverges from its ledger-anchored binding', 409);
      // The anchored digest binds only the public halves of the ECDH pair —
      // the seal key comes from the stored private half. Re-prove the pair:
      // a swapped _server_private can never re-key the release to an
      // attacker, and an honest session's private always re-derives the
      // anchored ephemeral (w20-fixverify F-1).
      // The pre-tx probe shreds expired rows — a tombstone between probe
      // and tx still refuses honestly rather than tripping on a null key.
      requireThat(session._server_private != null && session.expires_at > now, 'INV-409-STATE', 'Perception session expired or retired', 409);
      requireThat(createPublicKey(createPrivateKey(session._server_private)).export({ type: 'spki', format: 'pem' }) === session.server_ephemeral, 'INV-409-INTEGRITY', 'Perception session private half diverges from the anchored ephemeral', 409);
      // Component credential revocation reaches live sessions and binds the
      // ATTESTING key the session anchored — a rotated component cannot
      // launder sessions its retired key minted, and revoking that key still
      // reaches them after the config moved on (w18-issuerd F-5,
      // w20-fixverify F-2). Sessions anchored before the binding carried a
      // key id fail CLOSED rather than substituting the live config key —
      // the substitute would let them outlive revocation of the key that
      // actually minted them; re-mint is the honest path (w30-perception F2).
      // The anchored kid must bind the component's configured signing key —
      // any other non-revoked string is a forged anchor carrying a phantom
      // key id that the revocation probe can never reach (w31-fixverify F7).
      // A session minted under a retired component key refuses: re-minting
      // under the live key is the honest path, and revocation still reaches
      // the retired id through the same requireThat.
      const attestingKid = anchoredSession.signing_key_id;
      requireThat(releaseComponent && attestingKid === releaseComponent.signing.key_id && !this.revoked(t, 'key', attestingKid), 'INV-403-SCOPE', 'Perception component signing credential is revoked or unknown', 403);
      // Release provenance must be real: a cited capsule or evidence record
      // that does not exist would write forged authority into the signed
      // audit trail (runtime-audit F-6).
      requireThat(release && typeof release === 'object' && !Array.isArray(release) && release.fields && typeof release.fields === 'object' && !Array.isArray(release.fields), 'INV-400-SCHEMA', 'Invalid release', 400);
      text(release.purpose, 'purpose', 512);
      this._releaseCitation(t, release, p, now);
      // Policy revocation reaches LIVE sessions: mint-time gates re-run on
      // every release so a tightened constitution cannot be outlived for
      // the session TTL (w26-perception F-3). Firmware/assurance read from
      // the anchored event, not the mutable row (F-4).
      const effective = { ...session, assurance: anchoredSession.assurance ?? session.assurance, firmware_version: anchoredSession.firmware ?? session.firmware_version };
      const sp = this.policy(t).secure_perception ?? {};
      requireThat(sp.enabled !== false, 'INV-451-POLICY', 'Secure Perception was disabled for live sessions', 451);
      requireThat(sp.required_assurance !== 'hardware-enclave', 'INV-451-INTEGRITY', 'Hardware-enclave assurance cannot be served by the software profile', 451);
      requireThat((sp.allowed_firmware ?? []).includes(effective.firmware_version), 'INV-401-ATTESTATION', 'Session firmware no longer trusted by policy', 401);
      const result = releaseFields(effective, release, this.policy(t), now);
      // The value digest rides the ledger: sealed content can never
      // misstate evaluated state without the audit trail carrying what was
      // actually committed (w18-issuerd F-4).
      this.store.audit(t, 'PERCEPTION_RELEASE', p.subject_id, session_id, { fields: result.binding.fields, fields_digest: digest(release.fields), assurance: result.assurance, capsule_id: release.capsule_id ?? null, evidence_ref: release.evidence_ref ?? null }, now);
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
    const checkCapsule = (record, id) => {
      requireThat(record && record.capsule.expires_at > now, 'INV-404-NOT-FOUND', 'Release cites no live capsule', 404);
      // The row key must equal the capsule the row claims to be — a decided
      // capsule's contents transplanted under a foreign id would otherwise
      // cite the wrong provenance label into the signed trail
      // (w30-perception F1).
      requireThat(record.capsule.capsule_id === id, 'INV-409-INTEGRITY', 'Capsule row diverges from its record key — storage tamper', 409);
      // Mutable rows feed a SIGNED citation — the capsule must prove its
      // anchored proposal, verified request intent and self-consistent
      // digest before any row field is trusted, and the actor binding
      // comes from the verified intent payload, never the mutable actor
      // field (w21-crypto F-1).
      const intentPayload = this._capsuleIntegrity(t, record);
      requireThat(intentPayload.actor?.subject_id === p.subject_id, 'INV-403-SCOPE', 'Release cites a capsule belonging to another actor', 403);
      requireThat(record.decision, 'INV-409-STATE', 'Release cites an undecided capsule', 409);
      // The cited decision must equal the one the chain attests — editing
      // the mutable decision object cannot launder provenance
      // (w13-fixverify L5).
      requireThat(this._auditIndex(t).decisions.get(record.capsule.capsule_id) === digest(record.decision), 'INV-409-INTEGRITY', 'Recorded decision diverges from the ledger', 409);
      // Polarity is part of integrity: a citation asserts the gate released
      // this capsule — ESCROW/DENY verdicts are anchored, but they are not
      // provenance for a release (w22-fixverify F2).
      requireThat(record.decision?.decision === 'ALLOW', 'INV-412-EVIDENCE', 'Release cites a capsule that did not resolve to allow', 412);
      return record;
    };
    let cited = null;
    if (release.capsule_id !== undefined) {
      const cid = identifier(release.capsule_id, 'capsule');
      cited = checkCapsule(this.store.get(t, 'capsule', cid), cid);
    }
    if (release.evidence_ref !== undefined) {
      const eid = identifier(release.evidence_ref, 'evidence');
      const ev = this.store.get(t, 'evidence', eid);
      const payload = ev?.envelope?.payload;
      requireThat(payload, 'INV-404-NOT-FOUND', 'Release cites nonexistent evidence', 404);
      // The citation path enforces the same integrity bar as every other
      // evidence consumer — a mutable row cited into the signed release
      // trail must bind its cloned payload, re-verify its signature, and
      // respect revocation/quarantine (w21-crypto F-1).
      requireThat(digest(ev.payload) === digest(ev.envelope.payload), 'INV-409-INTEGRITY', 'Stored evidence diverged from its signed envelope', 409);
      const iss = this.tenant(t).issuers[ev.envelope.protected.key_id];
      requireThat(typeof iss?.public_key === 'string', 'INV-401-EVIDENCE', 'Unknown evidence issuer', 401);
      this._verifyCached(ev.envelope, { [ev.envelope.protected.key_id]: { public_key: iss.public_key, suite: iss.suite } }, 'evidence');
      requireThat(payload.tenant_id === t && payload.capsule_digest !== undefined, 'INV-409-INTEGRITY', 'Cited evidence names a different tenant or no action', 409);
      requireThat(!this.revoked(t, 'evidence', release.evidence_ref) && !this.revoked(t, 'issuer', ev.envelope.protected.key_id) && !this.revoked(t, 'key', ev.envelope.protected.key_id) && !this._auditIndex(t).issuerDrift.has(ev.envelope.protected.key_id), 'INV-403-QUARANTINE', 'Cited evidence is revoked or quarantined', 403);
      requireThat(payload.expires_at > now, 'INV-412-EVIDENCE', 'Release cites expired evidence', 412);
      requireThat(payload.advisory !== true, 'INV-412-EVIDENCE', 'Advisory evidence cannot be cited as authority', 412);
      // Integrity proves the envelope is authentic, not that it says what a
      // citation needs: a signed CONFLICT is a denial, and a superseded
      // attestation is withdrawn — neither is provenance (w22-fixverify F2).
      requireThat(payload.claim === 'supports', 'INV-412-EVIDENCE', 'Release cites evidence that does not assert support', 412);
      // Same row-key binding as the capsule side: a signed evidence
      // envelope transplanted under a foreign id would put the WRONG id on
      // the trail while the signature keeps verifying (w30-perception F1).
      requireThat(payload.evidence_id === eid, 'INV-409-INTEGRITY', 'Evidence row diverges from its record key — storage tamper', 409);
      // An evidence-only citation still binds the capsule it supports — the
      // citation can never float free of its evaluated context.
      const backing = cited ?? (() => {
        const key = this.store.ids(t, 'capsule', 10000).find(k => this.store.get(t, 'capsule', k)?.capsule_digest === payload.capsule_digest);
        return checkCapsule(key === undefined ? null : this.store.get(t, 'capsule', key), key);
      })();
      if (cited) requireThat(payload.capsule_digest === cited.capsule_digest, 'INV-403-SCOPE', 'Evidence does not support the cited capsule', 403);
      else cited = backing;
      // Supersession derives from the anchored attach order, not the
      // mutable superseded_by cache — a row writer can neither cite
      // withdrawn evidence nor deny live evidence by flipping the flag
      // (w30-perception F1).
      const fam = (this._auditIndex(t).attached.get(backing.capsule.capsule_id) ?? []).map(id => ({ id, e: this.store.get(t, 'evidence', id) }));
      requireThat(!this._supersededMap(t, fam).has(eid), 'INV-412-EVIDENCE', 'Release cites superseded evidence', 412);
    }
    return cited;
  }
  perceptionFallback(p, release) {
    this.authorize(p, ['operator', 'approver', 'custodian', 'security']);
    requireThat(release && typeof release === 'object' && !Array.isArray(release), 'INV-400-SCHEMA', 'Invalid release', 400);
    requireThat(release.fields && typeof release.fields === 'object' && !Array.isArray(release.fields), 'INV-400-SCHEMA', 'fields must be an object', 400);
    text(release.purpose, 'purpose');
    // The justification for a PLAINTEXT release is the accountability
    // field — it must be a bounded string and it must ride the signed
    // trail, or a 200KB/object reason could bypass both the label and the
    // ledger (w26-perception F-7).
    if (release.reason !== undefined) text(release.reason, 'reason', 256);
    return this.transaction(p, now => {
      this.assertHealthy(p.tenant_id, p.subject_id, this.identity(p).device_id, now);
      this._releaseCitation(p.tenant_id, release, p, now);
      const result = workspaceFallback(release, this.policy(p.tenant_id), now);
      this.store.audit(p.tenant_id, 'PERCEPTION_FALLBACK', p.subject_id, 'workspace', { fields: result.binding.fields, fields_digest: digest(release.fields), assurance: result.assurance, capsule_id: release.capsule_id ?? null, evidence_ref: release.evidence_ref ?? null, reason: release.reason ?? null }, now);
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
        const record = this._mustAnchored(p.tenant_id, 'capsule', identifier(input.capsule_id ?? ''));
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

import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { tightenOwnerOnly } from './keystore.mjs';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import { encrypt, decrypt, verifySigned, ctEqual } from './crypto.mjs';
import { merkleRoot } from './merkle.mjs';
import { canonical, digest, hashBytes } from './canonical.mjs';
import { requireThat, InvariantError } from './errors.mjs';

// Record/dek AAD is an injective tuple encoding — distinct (kind,id)
// pairs can never collide on one encryption context (DEK-audit F6):
// '/'-delimited strings would alias (kind='x',id='a/b') with
// (kind='x/a',id='b').
const recAad = (tenant, kind, id) => canonical({ tenant, kind, id });
const dekAad = (tenant, kind, id) => canonical({ tenant, kind, id, dek: true });
// Rows sealed before the canonical-tuple AAD change carry '/`-joined AADs.
// There is no legacy read path — pre-upgrade ciphertext stays sealed until
// _migrateAad re-seals it under the tuple form (fail-closed: a ciphertext
// that cannot be attributed to exactly one (tenant,kind,id) is quarantined,
// never guessed at). The legacy constants exist only so the migrator can
// enumerate and re-seal old rows (w8-fixverify F1, w19-aad).
const legacyAad = (tenant, kind, id) => `${tenant}/${kind}/${id}`;
const legacyDekAad = (tenant, kind, id) => `${tenant}/${kind}/${id}/dek`;
// The idempotency cache seals under its own disjoint tuple domain — the
  // previous slash form sat inside the legacy records-AAD space and let a
  // raw-writer transplant a sealed receipt into a records row (w18-crypto F1).
const idemAad = (tenant, scope, key) => canonical({ idempotency: true, tenant, scope, key });
// The fold-residue keep triggers — canonical CREATE text shared by every
// emitter (guards install, heal-path recreate, fabric drain recreate).
// A heal that re-created the pre-w60 text used to silently drop the
// `fold_floor_retired` arms for the rest of the process lifetime, and
// _installIntegrityGuards' legacy map accepted the downgrade as expected
// legacy text (w61-runtime F-1 / w61-seal F-2): one emitter, one source.
export const RESIDUE_KEEP_TRIGGERS = [
  ['fold_residue_keep', "CREATE TRIGGER fold_residue_keep BEFORE DELETE ON meta_kv WHEN OLD.key='fold_floor_healed' OR substr(OLD.key,1,18)='fold_floor_healed.' OR OLD.key='fold_floor_retired' BEGIN SELECT RAISE(ABORT, 'fold-floor residue is evidence'); END"],
  ['fold_residue_keep_upd', "CREATE TRIGGER fold_residue_keep_upd BEFORE UPDATE ON meta_kv WHEN OLD.key='fold_floor_healed' OR substr(OLD.key,1,18)='fold_floor_healed.' OR OLD.key='fold_floor_retired' OR NEW.key='fold_floor_healed' OR substr(NEW.key,1,18)='fold_floor_healed.' OR NEW.key='fold_floor_retired' BEGIN SELECT RAISE(ABORT, 'fold-floor residue is evidence'); END"],
  ['fold_residue_keep_ins', "CREATE TRIGGER fold_residue_keep_ins BEFORE INSERT ON meta_kv WHEN NEW.key='fold_floor_healed' OR substr(NEW.key,1,18)='fold_floor_healed.' OR NEW.key='fold_floor_retired' BEGIN SELECT RAISE(ABORT, 'fold-floor residue is evidence'); END"],
];

// Envelope-scan duplicate-member coverage for every level the pipeline
// reads: sqlite's json_extract/json_each resolve the FIRST duplicate member
// while JSON.parse consumers resolve the LAST, so a spliced dup can hide a
// field from the scan on a row that still verifies — making the row a
// candidate is the only honest answer (w65-runtime F-1). One shared
// fragment: every audit-envelope scanning query appends it identically.
// The lifecycle_carryover element level needs je.type='object' guarding —
// json_each on a scalar element raises 'malformed JSON' and fails the scan.
// The fifth clause descends one level further — dup keys inside an
// element's own `metadata` object (w66-runtime F-1). Coverage still stops
// at lc[*].metadata.*: deeper free-form nesting has no schema-defined
// sub-object, and no scan selects on those paths.
export const DUP_KEY_PROBE = ` OR EXISTS (SELECT 1 FROM json_each(envelope,'$') GROUP BY "key" HAVING COUNT(*)>1) OR EXISTS (SELECT 1 FROM json_each(envelope,'$.payload') GROUP BY "key" HAVING COUNT(*)>1) OR EXISTS (SELECT 1 FROM json_each(envelope,'$.payload.metadata') GROUP BY "key" HAVING COUNT(*)>1) OR EXISTS (SELECT 1 FROM json_each(envelope,'$.payload.metadata.lifecycle_carryover') je, json_each(CASE WHEN je.type='object' THEN je.value ELSE '{}' END) jk GROUP BY je.key, jk.key HAVING COUNT(*)>1) OR EXISTS (SELECT 1 FROM json_each(envelope,'$.payload.metadata.lifecycle_carryover') je2, json_each(CASE WHEN je2.type='object' AND json_type(je2.value,'$.metadata')='object' THEN json_extract(je2.value,'$.metadata') ELSE '{}' END) jm GROUP BY je2.key, jm.key HAVING COUNT(*)>1)`;




export class Store {
  constructor(path, tenantKeys, auditSigners, { aadDedup } = {}) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    // A hostile or foreign file must surface inside the ledger taxonomy
    // from the first touch — a raw ERR_SQLITE_ERROR here is a tamper no
    // INV-* alert can see (w30-store F2).
    try { this.db = new DatabaseSync(path); } catch (e) { throw new InvariantError('INV-503-STORAGE', 'Ledger file is unreadable or not a database', 503, { cause: e }); }
    // Owner-only like the keystore pair — the shared helper skips the
    // syscall on a compliant file, so read-only mounts answer with the
    // INV taxonomy instead of a raw EROFS (w53-fixverify M-3).
    tightenOwnerOnly(path, 'fabric.db');
    this.tenantKeys = tenantKeys;
    // Shared with the simulated target: a byte-identical ciphertext under
    // two identities is always a transplant — the cross-DB graft only
    // resolves when both migrators consult the same index (w19-aad W19-1).
    this._aadDedup = aadDedup ?? new Map();
    this._sp = 0;
    // auditSigners[tenant] = {key_id, public_key, sign(payload) -> envelope}.
    // Signing runs inside the keystore; the store never sees private material.
    this.auditSigners = auditSigners;
    // secure_delete=ON zeroes freed pages, so a deleted DEK row leaves no
    // recoverable copy in the database file itself.
    // busy_timeout bounds queueing behind a contending writer at 30s; a
    // contender that still loses gets INV-503-LEDGER, not a raw sqlite error
    // (concurrency-audit H2). Long writers should stay chunked regardless.
    // Constructor pragma/schema/probe writes contend behind writers too — a
    // lost busy-timeout race must surface in the ledger taxonomy, not as raw
    // sqlite internals (w20-fixverify F-12).
    try {
      this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=30000; PRAGMA secure_delete=ON;');
      // Crash window (crypto-audit M-4): if the process died between a shred's
      // committed DELETE and the post-commit TRUNCATE, wrapped-DEK copies stay
      // reachable in the WAL. Truncating at open bounds that residue to uptime.
      // (Physical slack on disk sectors is out of scope — see SECURITY.md.)
      this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
      const version = this._stmt('PRAGMA user_version').get().user_version;
      requireThat(version <= 1, 'INV-503-STORAGE', 'Database schema is newer than this application', 503);
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS records (tenant TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL,
          value TEXT NOT NULL, created INTEGER NOT NULL, PRIMARY KEY(tenant,kind,id));
        CREATE TABLE IF NOT EXISTS audit (tenant TEXT NOT NULL, seq INTEGER NOT NULL, previous TEXT NOT NULL,
          hash TEXT NOT NULL, envelope TEXT NOT NULL, PRIMARY KEY(tenant,seq));
        CREATE TABLE IF NOT EXISTS nonces (tenant TEXT NOT NULL, nonce TEXT NOT NULL, capsule TEXT NOT NULL, PRIMARY KEY(tenant,nonce));
        CREATE TABLE IF NOT EXISTS idempotency (tenant TEXT NOT NULL, scope TEXT NOT NULL, key TEXT NOT NULL,
          hash TEXT NOT NULL, result TEXT NOT NULL, PRIMARY KEY(tenant,scope,key));
        CREATE TABLE IF NOT EXISTS deks (tenant TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL,
          wrapped TEXT NOT NULL, PRIMARY KEY(tenant,kind,id));
        CREATE TABLE IF NOT EXISTS usage (tenant TEXT NOT NULL, subject TEXT NOT NULL, resource TEXT NOT NULL,
          at INTEGER NOT NULL, cost INTEGER NOT NULL, capability TEXT NOT NULL, request TEXT NOT NULL,
          PRIMARY KEY(tenant,capability,request));
        CREATE INDEX IF NOT EXISTS usage_window ON usage(tenant,subject,resource,at);
        CREATE TABLE IF NOT EXISTS clock (id INTEGER PRIMARY KEY CHECK(id=1), last INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS meta_kv (tenant TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(tenant,key));
        CREATE TABLE IF NOT EXISTS data_access(tenant TEXT, subject TEXT, dataset TEXT, row_id TEXT, column_name TEXT, at INTEGER);
        CREATE INDEX IF NOT EXISTS data_access_ix ON data_access(tenant,subject,dataset,at);
        PRAGMA user_version=1;
      `);
    } catch (e) {
      if (e instanceof InvariantError) throw e;
      if (e?.errcode === 5 || e?.errcode === 6 || /database .*locked/i.test(e?.message ?? '')) throw new InvariantError('INV-503-LEDGER', 'Ledger writer contention exceeded the wait bound; retry', 503);
      if (/readonly|not authorized/i.test(e?.message ?? '')) throw new InvariantError('INV-503-STORAGE', 'Ledger database file is not writable', 503);
      if (e?.errcode !== undefined || e?.code === 'ERR_SQLITE_ERROR' || /not a database|malformed|no such column|no such table/i.test(e?.message ?? '')) throw new InvariantError('INV-503-STORAGE', 'Ledger schema is unrecognised — refusing to interpret a foreign or corrupt database', 503, { cause: e });
      throw e;
    }
    // Migration runs BEFORE the append-only guards exist: its donor-revert
    // closures legitimately UPDATE/DELETE idempotency and dek rows
    // (w21-store F-6 ordering).
    try { this._migrateAad(); } catch (e) { if (e instanceof InvariantError) throw e; throw new InvariantError('INV-503-STORAGE', 'Ledger schema is unrecognised — refusing to interpret a foreign or corrupt database', 503, { cause: e }); }
    try {
      this._installIntegrityGuards();
    } catch (e) {
      if (e instanceof InvariantError) throw e;
      if (e?.errcode === 5 || e?.errcode === 6 || /database .*locked/i.test(e?.message ?? '')) throw new InvariantError('INV-503-LEDGER', 'Ledger writer contention exceeded the wait bound; retry', 503);
      if (/readonly|not authorized/i.test(e?.message ?? '')) throw new InvariantError('INV-503-STORAGE', 'Ledger database file is not writable', 503);
      if (e?.errcode !== undefined || e?.code === 'ERR_SQLITE_ERROR' || /not a database|malformed|no such column|no such table/i.test(e?.message ?? '')) throw new InvariantError('INV-503-STORAGE', 'Ledger schema is unrecognised — refusing to interpret a foreign or corrupt database', 503, { cause: e });
      throw e;
    }
  }
  // Signer-death window shared by the export/page verifiers: a key revoked
  // or rotated out of service ON THE CHAIN must not be attesting rows
  // sequenced after its death — the fabric fold enforces this for the live
  // index; standalone verification lacked it (w28-crypto F2).
  _auditKeyDeaths(tenant) {
    // A dropped or rewritten audit table classifies in the ledger taxonomy,
    // never raw ERR_SQLITE noise on the bulk reader (w46-store M-3).
    return this._schemaGuard(() => this._auditKeyDeathsInner(tenant));
  }
  _auditKeyDeathsInner(tenant) {
    const dead = new Map();
    // Stored envelope text is attacker-writable: a respelled row
    // ('\u0074ype') folds identically yet vanishes from a LIKE scan, so
    // every fold-free death/rotation/seal sweep keys on the PARSED type
    // (json_valid guards malformed rows the LIKE would have skipped —
    // the fold convicts those rows separately) (w44-store H-3). And a
    // dup-key decoy — sqlite reads the FIRST dup member where JSON.parse
    // reads the LAST — must always be a candidate: canonical writers
    // never mint dups, so any dup at root or $.payload is adversarial
    // evidence the JS parse must see (w45-fv HIGH).
    for (const row of this._stmt("SELECT seq,envelope FROM audit WHERE tenant=? AND json_valid(envelope) AND (json_extract(envelope,'$.payload.type') IN ('AUTHORITY_REVOKED','KEY_ROTATED','AUDIT_SEALED','AUDIT_SEAL_CARRY')" + DUP_KEY_PROBE + ")").all(tenant)) {
      let env; try { env = JSON.parse(row.envelope); } catch { continue; }
      const pl = env?.payload, meta = pl?.metadata;
      // Earliest death wins — a second death event must never extend a
      // key's life (w34-fixverify L-3).
      if (pl?.type === 'AUTHORITY_REVOKED' && typeof pl.reference === 'string' && pl.reference.startsWith('key:')) dead.set(pl.reference.slice(4), Math.min(dead.get(pl.reference.slice(4)) ?? Infinity, row.seq));
      if (pl?.type === 'KEY_ROTATED' && meta?.key_class === 'audit' && typeof meta?.previous_key_id === 'string') dead.set(meta.previous_key_id, Math.min(dead.get(meta.previous_key_id) ?? Infinity, row.seq));
      // A seal's revocations_carryover carries 'key:<kid>' refs — the live
      // fold kills that key at the carrying row's seq, so the offline/page
      // verifier must agree or it accepts rows the fabric refuses
      // (w33-seal O-3).
      if (pl?.type === 'AUDIT_SEALED' || pl?.type === 'AUDIT_SEAL_CARRY') {
        // Carried deaths pin at the carried event's own orig_seq — the
        // same position the fabric fold enforces — not the carrying
        // row's seq, or standalone verification would accept rows signed
        // inside the carried death window (w38-fixverify F-4).
        for (const rv of Array.isArray(meta?.revocations_carryover) ? meta.revocations_carryover : [])
          // floor_derived entries are unverifiable claims — the fold
          // exempts them from the death window and so does this sweep,
          // or the standalone extractors would diverge from the fold on
          // the same live chain (w48-crypto F-w48-2).
          if (rv?.floor_derived !== true && typeof rv?.reference === 'string' && rv.reference.startsWith('key:'))
            dead.set(rv.reference.slice(4), Math.min(dead.get(rv.reference.slice(4)) ?? Infinity, typeof rv.orig_seq === 'number' ? rv.orig_seq : row.seq));
        // A doomed audit-class KEY_ROTATED rides lifecycle_carryover now —
        // its predecessor-death pin must unfold exactly like the fold's
        // replay, or the verifiers accept rows signed past a carried
        // rotation (w34 seal parity).
        for (const lc of Array.isArray(meta?.lifecycle_carryover) ? meta.lifecycle_carryover : [])
          if (lc?.type === 'KEY_ROTATED' && lc?.metadata?.key_class === 'audit' && typeof lc.metadata.previous_key_id === 'string')
            dead.set(lc.metadata.previous_key_id, Math.min(dead.get(lc.metadata.previous_key_id) ?? Infinity, typeof lc.orig_seq === 'number' ? lc.orig_seq : row.seq));
      }
    }
    return dead;
  }
  // Tamper-evidence for the tables a file-level writer would rewrite:
  // append-only audit (existing bar) plus the replay/clock/billing-control
  // tables whose value IS their integrity (w21-store F-6). Trigger text is
  // compared verbatim — a `WHERE 0`-gated or WHEN-gated replacement body
  // can carry the RAISE literal while never firing (w21-store F-1).
  _installIntegrityGuards() {
    // [full CREATE text as stored in sqlite_master, abort message the
    // functional probe must surface]. The seq guard keeps its WHEN (the
    // head arithmetic cannot be a plain body) but the verbatim text
    // comparison binds it byte-for-byte.
    const guards = [
      ['no_audit_update', "CREATE TRIGGER no_audit_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END", 'append-only audit'],
      ['no_audit_delete', "CREATE TRIGGER no_audit_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END", 'append-only audit'],
      // Chain-squat guard (store-audit MED-1): an insert must extend the
      // head exactly; earlier positions and gaps are rejected.
      ['audit_seq_guard', "CREATE TRIGGER audit_seq_guard BEFORE INSERT ON audit WHEN NEW.seq <> (SELECT COALESCE(MAX(seq),0)+1 FROM audit WHERE tenant=NEW.tenant) BEGIN SELECT RAISE(ABORT, 'audit sequence must extend the head'); END", 'audit sequence must extend the head'],
      // Replay-detector rows are insert-only — a file-writer deleting
      // nonces resurrects every spent nonce (w21-store F-6).
      ['no_nonce_update', "CREATE TRIGGER no_nonce_update BEFORE UPDATE ON nonces BEGIN SELECT RAISE(ABORT, 'append-only nonces'); END", 'append-only nonces'],
      ['no_nonce_delete', "CREATE TRIGGER no_nonce_delete BEFORE DELETE ON nonces BEGIN SELECT RAISE(ABORT, 'append-only nonces'); END", 'append-only nonces'],
      // Idempotency receipts are insert-only (the AAD migrator ran before
      // these guards exist) — rewriting or deleting a receipt re-opens
      // replay of the guarded operation.
      ['no_idem_update', "CREATE TRIGGER no_idem_update BEFORE UPDATE ON idempotency BEGIN SELECT RAISE(ABORT, 'append-only idempotency'); END", 'append-only idempotency'],
      ['no_idem_delete', "CREATE TRIGGER no_idem_delete BEFORE DELETE ON idempotency BEGIN SELECT RAISE(ABORT, 'append-only idempotency'); END", 'append-only idempotency'],
      // The clock row itself is never deleted — a file-writer cannot make
      // a spent rewind detector forget the last asserted time. A decrease
      // guard is impossible: recoverClock legitimately writes `last` back
      // to the operator-asserted host time (the regression itself is
      // attested on the signed chain as CLOCK_RECOVERED).
      ['no_clock_delete', "CREATE TRIGGER no_clock_delete BEFORE DELETE ON clock BEGIN SELECT RAISE(ABORT, 'clock is monotone'); END", 'clock is monotone'],
      // data_access is an insert-only audit mirror.
      ['no_access_update', "CREATE TRIGGER no_access_update BEFORE UPDATE ON data_access BEGIN SELECT RAISE(ABORT, 'append-only data_access'); END", 'append-only data_access'],
      ['no_access_delete', "CREATE TRIGGER no_access_delete BEFORE DELETE ON data_access BEGIN SELECT RAISE(ABORT, 'append-only data_access'); END", 'append-only data_access'],
      // usage rows legitimately accumulate cost via ON CONFLICT UPDATE —
      // only row deletion is forbidden (billing falsification).
      ['no_usage_delete', "CREATE TRIGGER no_usage_delete BEFORE DELETE ON usage BEGIN SELECT RAISE(ABORT, 'append-only usage'); END", 'append-only usage'],
      // A file-writer can still UPDATE usage: lowering cost erases spend
      // (budget re-use = billing falsification), rewinding `at` shrinks the
      // window queries bill against, and rewriting the identity columns
      // moves a receipt to another subject/capability/request. The one
      // legitimate update is the accumulate path — cost only ever grows
      // and `at` only moves forward (w23 W23-07).
      ['no_usage_rewind', "CREATE TRIGGER no_usage_rewind BEFORE UPDATE ON usage WHEN NEW.cost < OLD.cost OR NEW.at < OLD.at OR NEW.tenant <> OLD.tenant OR NEW.subject <> OLD.subject OR NEW.resource <> OLD.resource OR NEW.capability <> OLD.capability OR NEW.request <> OLD.request BEGIN SELECT RAISE(ABORT, 'usage is monotone'); END", 'usage is monotone'],
      // The AAD migration marker is the only durable signal between the
      // migration commit and the fabric's attestation — a live delete in
      // the gap silently suppresses the evidence row (w46-store M-2). The
      // sanctioned post-attest cleanup drops and recreates this guard
      // verbatim; an attacker's delete now aborts in-band.
      ['aad_marker_keep', "CREATE TRIGGER aad_marker_keep BEFORE DELETE ON meta_kv WHEN OLD.key='aad_migration' BEGIN SELECT RAISE(ABORT, 'aad migration marker is evidence'); END", 'aad migration marker is evidence'],
      // A bare UPDATE rewrites the marker with no delete firing at all —
      // cover the update arm identically (w47-fixverify HIGH-1). No code
      // path ever UPDATEs the marker row; only the sanctioned
      // drop+delete+recreate sequence may touch it. NEW.key is covered
      // too — a rename-in (`UPDATE meta_kv SET key='aad_migration'` on an
      // innocent row) mints the marker without any INSERT (w58-fv F-2).
      ['aad_marker_keep_upd', "CREATE TRIGGER aad_marker_keep_upd BEFORE UPDATE ON meta_kv WHEN OLD.key='aad_migration' OR NEW.key='aad_migration' BEGIN SELECT RAISE(ABORT, 'aad migration marker is evidence'); END", 'aad migration marker is evidence'],
      // INSERT OR REPLACE never fires BEFORE DELETE — recursive_triggers
      // is off, so the implicit conflict-delete skips every guard and a
      // REPLACE rewrote the marker silently (w48-store W48-4). The
      // sanctioned marker write drops+recreates this guard inside its
      // own transaction.
      ['aad_marker_keep_ins', "CREATE TRIGGER aad_marker_keep_ins BEFORE INSERT ON meta_kv WHEN NEW.key='aad_migration' BEGIN SELECT RAISE(ABORT, 'aad migration marker is evidence'); END", 'aad migration marker is evidence'],
      // The heal-residue rows are the only durable signal between a
      // divergent-marker heal and its attestation — a bare DELETE +
      // restart erased the whole conviction unnamed (w57-runtime F-1).
      // The sanctioned write/retire paths drop+recreate these verbatim
      // inside their own transactions; an attacker's delete now aborts
      // in-band like the aad marker's.
      // `fold_floor_retired` joins the family (w60-seal F-1): the durable
      // consumption marker is evidence exactly like the heal rows.
      ...RESIDUE_KEEP_TRIGGERS.map(([name, sql]) => [name, sql, 'fold-floor residue is evidence']),
    ];
    // Pre-w58 verbatim texts of the triggers we have since hardened — a
    // database written by the previous build stores THAT text, so the
    // text-check below would wedge on an honest upgrade. Legacy-verbatim
    // bodies are dropped and recreated to current text; any other shape
    // is tamper evidence and still fails (w58-fv F-2).
    const legacyGuardText = new Map([
      ['aad_marker_keep_upd', ["CREATE TRIGGER aad_marker_keep_upd BEFORE UPDATE ON meta_kv WHEN OLD.key='aad_migration' BEGIN SELECT RAISE(ABORT, 'aad migration marker is evidence'); END"]],
      ['fold_residue_keep', ["CREATE TRIGGER fold_residue_keep BEFORE DELETE ON meta_kv WHEN OLD.key='fold_floor_healed' OR substr(OLD.key,1,18)='fold_floor_healed.' BEGIN SELECT RAISE(ABORT, 'fold-floor residue is evidence'); END"]],
      ['fold_residue_keep_upd', [
        "CREATE TRIGGER fold_residue_keep_upd BEFORE UPDATE ON meta_kv WHEN OLD.key='fold_floor_healed' OR substr(OLD.key,1,18)='fold_floor_healed.' BEGIN SELECT RAISE(ABORT, 'fold-floor residue is evidence'); END",
        "CREATE TRIGGER fold_residue_keep_upd BEFORE UPDATE ON meta_kv WHEN OLD.key='fold_floor_healed' OR substr(OLD.key,1,18)='fold_floor_healed.' OR NEW.key='fold_floor_healed' OR substr(NEW.key,1,18)='fold_floor_healed.' BEGIN SELECT RAISE(ABORT, 'fold-floor residue is evidence'); END"
      ]],
      ['fold_residue_keep_ins', ["CREATE TRIGGER fold_residue_keep_ins BEFORE INSERT ON meta_kv WHEN NEW.key='fold_floor_healed' OR substr(NEW.key,1,18)='fold_floor_healed.' BEGIN SELECT RAISE(ABORT, 'fold-floor residue is evidence'); END"]]
    ]);
    const norm = s => (s ?? '').replace(/\s+/g, ' ').trim();
    for (const [name, sql] of guards) this.db.exec(`CREATE TRIGGER IF NOT EXISTS ${sql.slice('CREATE TRIGGER '.length)}`);
    // Text check: the STORED body must equal our literal — feature tests
    // (WHEN present, RAISE literal) are evadable by WHERE-gated bodies
    // (w21-store F-1).
    const triggers = new Map(this._stmt("SELECT name, sql FROM sqlite_master WHERE type='trigger'").all().map(x => [x.name, x.sql ?? '']));
    for (const [name, sql] of guards) {
      const stored = norm(triggers.get(name));
      if (stored === norm(sql)) continue;
      if ((legacyGuardText.get(name) ?? []).some(t => stored === norm(t))) {
        this.db.exec(`DROP TRIGGER "${name}"`);
        this.db.exec(`CREATE TRIGGER ${sql.slice('CREATE TRIGGER '.length)}`);
        triggers.set(name, sql);
        continue;
      }
      throw new InvariantError('INV-503-STORAGE', `integrity trigger missing or tampered: ${name}`, 503);
    }
    // Enumeration, not just existence: a file-writer can plant EXTRA
    // triggers whose names or bodies smuggle SQL into our own privileged
    // paths (DROP TRIGGER batch, the seal's delete pass, or any ordinary
    // write that fires the payload). Anything not in the known guard set
    // is removed at open — quoted, never interpolated (w28-store F1).
    const knownTriggers = new Set(guards.map(([name]) => name));
    for (const stray of this._stmt("SELECT name FROM sqlite_master WHERE type='trigger'").all().map(r => r.name).filter(n => !knownTriggers.has(n))) {
      this.db.exec(`DROP TRIGGER "${String(stray).replace(/"/g, '""')}"`);
      (this._strayTriggers ??= []).push(stray);
    }
    // Functional probes: each forbidden write must abort with THAT
    // trigger's own RAISE message — an unrelated failure (a primary-key
    // collision on a pre-seeded probe row, a broken trigger raising a
    // different error) must never count as 'enforced' (w21-store F-1).
    // The probe tenant is unique per boot, so nothing pre-seeded can
    // collide with it.
    const probe = (fn, msg) => {
      this.db.exec('SAVEPOINT integrity_probe');
      let ok = false;
      try {
        fn();
      } catch (e) {
        // Contention is not enforcement evidence — it propagates to the
        // caller's INV-503-LEDGER translation (w20-fixverify F-12).
        if (e?.errcode === 5 || e?.errcode === 6 || /database .*locked/i.test(e?.message ?? '')) throw e;
        if (e?.message === msg) ok = true;
        else throw new InvariantError('INV-503-STORAGE', `Integrity probe fault: ${e?.message ?? e}`, 503);
      } finally {
        this.db.exec('ROLLBACK TO integrity_probe'); this.db.exec('RELEASE integrity_probe');
      }
      return ok;
    };
    const pt = `__integrity_probe__:${randomBytes(8).toString('hex')}`;
    const insAudit = seq => this._stmt('INSERT INTO audit VALUES(?,?,?,?,?)').run(pt, seq, 'x', 'x', '{}');
    requireThat(probe(() => { insAudit(1); this._stmt('UPDATE audit SET hash=? WHERE tenant=?').run('y', pt); }, 'append-only audit'), 'INV-503-STORAGE', 'Audit append-only UPDATE trigger not enforced', 503);
    requireThat(probe(() => { insAudit(1); this._stmt('DELETE FROM audit WHERE tenant=?').run(pt); }, 'append-only audit'), 'INV-503-STORAGE', 'Audit append-only DELETE trigger not enforced', 503);
    requireThat(probe(() => insAudit(7), 'audit sequence must extend the head'), 'INV-503-STORAGE', 'Audit sequence guard not enforced', 503);
    for (const [table, msg] of [['nonces', 'append-only nonces'], ['idempotency', 'append-only idempotency'], ['data_access', 'append-only data_access']]) {
      const ins = { nonces: () => this._stmt('INSERT INTO nonces VALUES(?,?,?)').run(pt, 'n', 'c'),
        idempotency: () => this._stmt('INSERT INTO idempotency VALUES(?,?,?,?,?)').run(pt, 's', 'k', 'h', 'r'),
        data_access: () => this._stmt('INSERT INTO data_access VALUES(?,?,?,?,?,?)').run(pt, 's', 'd', 'r', 'c', 0) }[table];
      const col = { nonces: 'capsule', idempotency: 'result', data_access: 'subject' }[table];
      requireThat(probe(() => { ins(); this._stmt(`UPDATE ${table} SET ${col}=? WHERE tenant=?`).run('y', pt); }, msg), 'INV-503-STORAGE', `${table} append-only UPDATE trigger not enforced`, 503);
      requireThat(probe(() => { ins(); this._stmt(`DELETE FROM ${table} WHERE tenant=?`).run(pt); }, msg), 'INV-503-STORAGE', `${table} append-only DELETE trigger not enforced`, 503);
    }
    requireThat(probe(() => { this._stmt('INSERT INTO usage VALUES(?,?,?,?,?,?,?)').run(pt, 's', 'r', 0, 0, 'c', 'q'); this._stmt('DELETE FROM usage WHERE tenant=?').run(pt); }, 'append-only usage'), 'INV-503-STORAGE', 'usage append-only DELETE trigger not enforced', 503);
    requireThat(probe(() => { this._stmt('INSERT INTO usage VALUES(?,?,?,?,?,?,?)').run(pt, 's', 'r', 100, 5, 'c', 'q'); this._stmt('UPDATE usage SET cost=? WHERE tenant=?').run(4, pt); }, 'usage is monotone'), 'INV-503-STORAGE', 'usage monotone UPDATE trigger not enforced', 503);
    // INSERT OR IGNORE seeds when absent without firing the delete guard on
    // an existing row; `last=last-1` is a backward write on any live value.
    requireThat(probe(() => { this._stmt('INSERT OR IGNORE INTO clock VALUES(1,100)').run(); this._stmt('DELETE FROM clock WHERE id=1').run(); }, 'clock is monotone'), 'INV-503-STORAGE', 'clock delete trigger not enforced', 503);
    // The marker guard fires only on the evidence key — other meta_kv rows
    // (fold_floor) must stay writable, and a WHEN-less body that aborts
    // every delete would wedge them (w46-store M-2).
    // Seeding an aad_migration row must drop the INSERT arm first —
    // schema DDL inside the savepoint rolls back with the probe
    // (w48-store W48-4).
    requireThat(probe(() => { this.db.exec('DROP TRIGGER aad_marker_keep_ins'); this._stmt("INSERT OR REPLACE INTO meta_kv VALUES(?, 'aad_migration', '{}')").run(pt); this._stmt("DELETE FROM meta_kv WHERE tenant=? AND key='aad_migration'").run(pt); }, 'aad migration marker is evidence'), 'INV-503-STORAGE', 'aad_migration marker delete trigger not enforced', 503);
    requireThat(probe(() => { this.db.exec('DROP TRIGGER aad_marker_keep_ins'); this._stmt("INSERT OR REPLACE INTO meta_kv VALUES(?, 'aad_migration', '{}')").run(pt); this._stmt("UPDATE meta_kv SET value='{}' WHERE tenant=? AND key='aad_migration'").run(pt); }, 'aad migration marker is evidence'), 'INV-503-STORAGE', 'aad_migration marker update trigger not enforced', 503);
    requireThat(probe(() => { this._stmt("INSERT INTO meta_kv VALUES(?, 'aad_migration', '{}')").run(pt); }, 'aad migration marker is evidence'), 'INV-503-STORAGE', 'aad_migration marker insert trigger not enforced', 503);
    // Same three arms for the heal-residue plane (w57-runtime F-1) —
    // exercised on the keyed form AND the legacy bare key AND a second
    // key suffix, so a guard that only covers one spelling cannot pass
    // (w58-fv F-1). The rename-in arm mints evidence by moving an
    // innocent row onto a residue key (w58-fv F-2).
    requireThat(probe(() => { this.db.exec('DROP TRIGGER fold_residue_keep_ins'); this._stmt("INSERT OR REPLACE INTO meta_kv VALUES(?, 'fold_floor_healed.1', '{}')").run(pt); this._stmt("DELETE FROM meta_kv WHERE tenant=? AND key='fold_floor_healed.1'").run(pt); }, 'fold-floor residue is evidence'), 'INV-503-STORAGE', 'fold-floor residue delete trigger not enforced', 503);
    requireThat(probe(() => { this.db.exec('DROP TRIGGER fold_residue_keep_ins'); this._stmt("INSERT OR REPLACE INTO meta_kv VALUES(?, 'fold_floor_healed.2', '{}')").run(pt); this._stmt("DELETE FROM meta_kv WHERE tenant=? AND key='fold_floor_healed.2'").run(pt); }, 'fold-floor residue is evidence'), 'INV-503-STORAGE', 'fold-floor residue delete trigger not enforced on second key', 503);
    requireThat(probe(() => { this.db.exec('DROP TRIGGER fold_residue_keep_ins'); this._stmt("INSERT OR REPLACE INTO meta_kv VALUES(?, 'fold_floor_healed', '{}')").run(pt); this._stmt("DELETE FROM meta_kv WHERE tenant=? AND key='fold_floor_healed'").run(pt); }, 'fold-floor residue is evidence'), 'INV-503-STORAGE', 'fold-floor residue delete trigger not enforced on bare key', 503);
    requireThat(probe(() => { this.db.exec('DROP TRIGGER fold_residue_keep_ins'); this._stmt("INSERT OR REPLACE INTO meta_kv VALUES(?, 'fold_floor_healed.1', '{}')").run(pt); this._stmt("UPDATE meta_kv SET value='{}' WHERE tenant=? AND key='fold_floor_healed.1'").run(pt); }, 'fold-floor residue is evidence'), 'INV-503-STORAGE', 'fold-floor residue update trigger not enforced', 503);
    requireThat(probe(() => { this.db.exec('DROP TRIGGER fold_residue_keep_ins'); this._stmt("INSERT INTO meta_kv VALUES(?, 'innocent', 'x')").run(pt); this._stmt("UPDATE meta_kv SET key='fold_floor_healed.9' WHERE tenant=? AND key='innocent'").run(pt); }, 'fold-floor residue is evidence'), 'INV-503-STORAGE', 'fold-floor residue rename-in not enforced', 503);
    requireThat(probe(() => { this._stmt("INSERT INTO meta_kv VALUES(?, 'fold_floor_healed.1', '{}')").run(pt); }, 'fold-floor residue is evidence'), 'INV-503-STORAGE', 'fold-floor residue insert trigger not enforced', 503);
    requireThat(probe(() => { this.db.exec('DROP TRIGGER aad_marker_keep_ins'); this._stmt("INSERT INTO meta_kv VALUES(?, 'aad_probe', 'x')").run(pt); this._stmt("UPDATE meta_kv SET key='aad_migration' WHERE tenant=? AND key='aad_probe'").run(pt); }, 'aad migration marker is evidence'), 'INV-503-STORAGE', 'aad_migration rename-in not enforced', 503);
    // The counter-arm: a BEFORE INSERT RAISE(IGNORE) throws nothing and
    // fires no guard — the write just vanishes while every caller reads
    // success (w48-fixverify CRITICAL). Probe that the ledger's most
    // sensitive inserts LAND, not merely that forbidden writes abort.
    const probeLanded = (run, what) => {
      this.db.exec('SAVEPOINT integrity_probe');
      try { requireThat(run().changes === 1, 'INV-503-STORAGE', `${what} abandoned — foreign trigger interference`, 503); }
      finally { this.db.exec('ROLLBACK TO integrity_probe'); this.db.exec('RELEASE integrity_probe'); }
    };
    probeLanded(() => insAudit(1), 'audit insert');
    probeLanded(() => this._stmt("INSERT INTO meta_kv VALUES(?, 'integrity_probe', '{}')").run(pt), 'meta_kv insert');
    // The probes above journal WAL frames even though they roll back —
    // truncate so boot-time verification leaves no residual pages behind
    // (w19-aad W19-3 measures post-migration WAL size).
    try { this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); } catch { /* contention: next armed write retries */ }
    // Clock-floor anchoring (w22-fixverify F1): `clock.last` is a mutable
    // row — a file-writer UPDATE rewinds the regression detector silently.
    // The signed chain already attests a monotone time floor (every entry's
    // payload.time), so the live `last` must sit at or above the newest
    // attested time — UNLESS the chain itself carries a CLOCK_RECOVERED
    // entry attesting the rewound value (recoverClock's honest backward
    // step). Seed both anchors here; audit() keeps them current.
    // The floor seeds from the newest VERIFIABLE row, never the newest
    // row: a file-writer appending a well-formed unsigned tail entry
    // (the seq trigger admits MAX+1) would otherwise plant a far-future
    // floor and wedge every subsequent write — or, walked back past, a
    // LOW floor that hides a rewind (w23 W23-02). Up to 64 tail rows are
    // tried; a tail with no verifiable entry at all is tamper evidence
    // that bricks the open rather than silently seeding zero.
    this._chainFloor = 0; this._lastRecoveredAt = null;
    let floorSeeded = false;
    try {
    for (const row of this._stmt('SELECT tenant,envelope FROM audit ORDER BY rowid DESC LIMIT 64').all()) {
      try {
        const env = JSON.parse(row.envelope);
        const signer = this._signer(row.tenant), pub = signer.keys ? signer.keys() : { [signer.key_id]: { public_key: signer.public_key } };
        verifySigned(env, pub, 'audit');
        const t = env?.payload?.time;
        if (typeof t === 'number' && Number.isFinite(t)) { this._chainFloor = t; floorSeeded = true; break; }
      } catch { /* forged or unverifiable tail row — keep walking back */ }
    }
    requireThat(floorSeeded || this._stmt('SELECT COUNT(*) n FROM audit').get().n === 0, 'INV-409-AUDIT-TAMPER', 'Audit tail carries no verifiable entry — ledger tamper', 409);
    for (const row of this._stmt("SELECT tenant,envelope FROM audit WHERE json_valid(envelope) AND (json_extract(envelope,'$.payload.type')='CLOCK_RECOVERED'" + DUP_KEY_PROBE + ") ORDER BY rowid DESC LIMIT 512").all()) {
      try {
        const env = JSON.parse(row.envelope);
        if (env?.payload?.type !== 'CLOCK_RECOVERED') continue;
        const signer = this._signer(row.tenant), pub = signer.keys ? signer.keys() : { [signer.key_id]: { public_key: signer.public_key } };
        verifySigned(env, pub, 'audit');
        this._lastRecoveredAt = env.payload.metadata?.recovered_at ?? null;
        break; // newest VERIFIED recovery wins — unsigned planted rows are skipped
      } catch { /* tampered candidate — skip to an older verified one */ }
    }
    // A rewound floor with no attested recovery is tamper, detected at open
    // before any transaction can ride it (in-process detection lives in
    // clock() below). An ABSENT clock row is legitimate — the row is only
    // materialised by the first transaction, and the delete trigger makes
    // a file-writer's removal impossible anyway.
    const seedRow = this._stmt('SELECT last FROM clock WHERE id=1').get();
    requireThat(!seedRow || seedRow.last >= this._chainFloor || (this._lastRecoveredAt !== null && seedRow.last >= this._lastRecoveredAt), 'INV-409-AUDIT-TAMPER', 'Clock floor rewound below attested chain time', 409);
    } catch (e) {
      // A wrong-shape table answers the probes with raw sqlite errors — a
      // foreign database must classify as storage tamper, not escape the
      // INV taxonomy (w30-store F2).
      if (e instanceof InvariantError) throw e;
      throw new InvariantError('INV-503-STORAGE', 'Ledger schema is unrecognised — refusing to interpret a foreign or corrupt database', 503, { cause: e });
    }
  }
  // One-shot migration: re-seal every ciphertext still bound under the
  // legacy slash-form AAD space, then never consult that space again. The
  // slash forms are a transplant surface — a legacy `deks.wrapped` copied
  // into `records(kind, id+'/dek')` decrypts to the bare DEK, defeating
  // crypto-shredding for that record (w18-crypto F2) — and the only
  // honest closure is migrating out of it. A row that verifies under
  // neither form was already unreadable; it stays sealed and fails loudly
  // on read, never silently skipped.
  _migrateAad() {
    const master = t => this.key(t);
    // Per-tenant accounting surfaced to the fabric's AAD_MIGRATION audit
    // event: a silent skip is indistinguishable from a clean open
    // (w19-aad W19-2).
    const stats = this.aadMigration = new Map();
    const mark = (tenant, k) => { const s = stats.get(tenant) ?? { migrated: 0, transplants: 0, ambiguous: 0, skipped: 0 }; s[k]++; stats.set(tenant, s); };
    // A grafted donor is reverted, not migrated — the accounting must undo
    // the donor's mark too or the AAD_MIGRATION event claims a migration
    // that was undone (w20-fixverify F-9). The closure travels inside the
    // dedup entry because the donor may belong to the sibling migrator.
    const unmark = tenant => { const s = stats.get(tenant); if (s && s.migrated > 0) { s.migrated--; s.reverted = (s.reverted ?? 0) + 1; } };
    // A byte-identical ciphertext under two identities can never be
    // legitimate — fresh IVs forbid it. On a collision BOTH rows stay
    // legacy-sealed: the donor cannot be proven, so neither earns a
    // canonical binding (w19-aad W19-1). The earlier row's original bytes
    // are restored in the same transaction.
    const seen = this._aadDedup;
    // A slash anywhere in an AAD component makes the legacy string
    // non-unique, and a records id ending '/dek' aliases the four-segment
    // dek space exactly ('id=dek' alone cannot — a three-segment record
    // AAD never equals a four-segment dek AAD, w20-fixverify F-11);
    // records rows whose kind names a target table alias that space.
    // None can be proven non-transplanted — they stay sealed for review.
    const slashy = (...parts) => parts.some(p => typeof p === 'string' && p.includes('/'));
    const spaceAlias = kind => ['resource', 'transaction', 'secret', 'grant', 'idempotency'].includes(kind);
    this.db.exec('BEGIN IMMEDIATE');
    try {
      // Each row is isolated: a ciphertext that fails BOTH AAD forms was
      // already unreadable — it must stay sealed and keep failing on read,
      // never wedge the open for every other tenant.
      for (const r of this._stmt('SELECT tenant,kind,id,wrapped FROM deks').all()) {
        try { decrypt(r.wrapped, master(r.tenant), dekAad(r.tenant, r.kind, r.id)); continue; } catch { /* legacy-sealed or corrupt */ }
        const prior = seen.get(r.wrapped);
        // Cross-DB collision: reverting through the donor's prepared
        // statement would write outside this transaction AND strand the
        // live donor row on the sibling database — a graft is detected
        // and counted, but the donor keeps its canonical binding
        // (w24-fixverify W24-06).
        if (prior) { if (prior.db === this.db) { prior.revert?.(); prior.unmark?.(); } mark(r.tenant, 'transplants'); continue; }
        if (slashy(r.tenant, r.kind, r.id)) { seen.set(r.wrapped, {}); mark(r.tenant, 'ambiguous'); continue; }
        try {
          const bare = decrypt(r.wrapped, master(r.tenant), legacyDekAad(r.tenant, r.kind, r.id));
          const upd = this._stmt('UPDATE deks SET wrapped=? WHERE tenant=? AND kind=? AND id=?'), orig = r.wrapped;
          seen.set(orig, { db: this.db, revert: () => { upd.run(orig, r.tenant, r.kind, r.id); this._shredded = true; }, unmark: () => unmark(r.tenant) });
          upd.run(encrypt(bare, master(r.tenant), dekAad(r.tenant, r.kind, r.id)), r.tenant, r.kind, r.id);
          mark(r.tenant, 'migrated');
        } catch { mark(r.tenant, 'skipped'); }
      }
      const recs = this._stmt('SELECT tenant,kind,id,value FROM records').all();
      const dekRow = this._stmt('SELECT wrapped FROM deks WHERE tenant=? AND kind=? AND id=?');
      for (const r of recs) {
        try {
          const d = dekRow.get(r.tenant, r.kind, r.id);
          const key = d ? Buffer.from(decrypt(d.wrapped, master(r.tenant), dekAad(r.tenant, r.kind, r.id)), 'base64url') : master(r.tenant);
          try { decrypt(r.value, key, recAad(r.tenant, r.kind, r.id)); continue; } catch { /* legacy-sealed or corrupt */ }
        } catch {
          // A dedup hit lives here too: a cross-DB graft may fail the local
          // DEK unwrap before ever reaching the canonical check — it is a
          // detected transplant, not a skipped row (w20-fixverify F-10).
          const grafted = seen.get(r.value);
          if (grafted) { if (grafted.db === this.db) { grafted.revert?.(); grafted.unmark?.(); } mark(r.tenant, 'transplants'); }
          else mark(r.tenant, 'skipped');
          continue;
        }
        const prior = seen.get(r.value);
        if (prior) { if (prior.db === this.db) { prior.revert?.(); prior.unmark?.(); } mark(r.tenant, 'transplants'); continue; }
        if (slashy(r.tenant, r.kind, r.id) || spaceAlias(r.kind) || r.id.endsWith('/dek')) { seen.set(r.value, {}); mark(r.tenant, 'ambiguous'); continue; }
        try {
          const d = dekRow.get(r.tenant, r.kind, r.id);
          const key = d ? Buffer.from(decrypt(d.wrapped, master(r.tenant), dekAad(r.tenant, r.kind, r.id)), 'base64url') : master(r.tenant);
          const plain = decrypt(r.value, key, legacyAad(r.tenant, r.kind, r.id));
          const upd = this._stmt('UPDATE records SET value=? WHERE tenant=? AND kind=? AND id=?'), orig = r.value;
          seen.set(orig, { db: this.db, revert: () => { upd.run(orig, r.tenant, r.kind, r.id); this._shredded = true; }, unmark: () => unmark(r.tenant) });
          upd.run(encrypt(plain, key, recAad(r.tenant, r.kind, r.id)), r.tenant, r.kind, r.id);
          mark(r.tenant, 'migrated');
        } catch { mark(r.tenant, 'skipped'); }
      }
      for (const r of this._stmt('SELECT tenant,scope,key,result FROM idempotency').all()) {
        try { decrypt(r.result, master(r.tenant), idemAad(r.tenant, r.scope, r.key)); continue; } catch { /* legacy-sealed or corrupt */ }
        const prior = seen.get(r.result);
        if (prior) { if (prior.db === this.db) { prior.revert?.(); prior.unmark?.(); } mark(r.tenant, 'transplants'); continue; }
        if (slashy(r.tenant, r.scope, r.key)) { seen.set(r.result, {}); mark(r.tenant, 'ambiguous'); continue; }
        try {
          const plain = decrypt(r.result, master(r.tenant), `${r.tenant}/idempotency/${r.scope}/${r.key}`);
          const upd = this._stmt('UPDATE idempotency SET result=? WHERE tenant=? AND scope=? AND key=?'), orig = r.result;
          seen.set(orig, { db: this.db, revert: () => { upd.run(orig, r.tenant, r.scope, r.key); this._shredded = true; }, unmark: () => unmark(r.tenant) });
          upd.run(encrypt(plain, master(r.tenant), idemAad(r.tenant, r.scope, r.key)), r.tenant, r.scope, r.key);
          mark(r.tenant, 'migrated');
        } catch { mark(r.tenant, 'skipped'); }
      }
      // The migration's own accounting is durable evidence too: the
      // per-tenant stats persist inside the same tx that re-sealed the
      // rows, so a crash after COMMIT but before the fabric's
      // AAD_MIGRATION attestation still surfaces at the next open
      // (w43-store F-4).
      for (const [mtenant, ms] of stats)
        if (ms.migrated + ms.transplants + ms.ambiguous + ms.skipped > 0)
          this._schemaGuard(() => {
            // The INSERT arm of the marker guard must drop for the
            // sanctioned write — same drop+recreate-in-tx discipline the
            // delete path uses (w48-store W48-4).
            this.db.exec('DROP TRIGGER IF EXISTS aad_marker_keep_ins');
            try { this._landed(() => this._stmt("INSERT OR REPLACE INTO meta_kv VALUES(?, 'aad_migration', ?)").run(mtenant, JSON.stringify(ms)), 'aad-migration marker'); }
            finally { this.db.exec("CREATE TRIGGER IF NOT EXISTS aad_marker_keep_ins BEFORE INSERT ON meta_kv WHEN NEW.key='aad_migration' BEGIN SELECT RAISE(ABORT, 'aad migration marker is evidence'); END"); }
          });
      this.db.exec('COMMIT');
      // Legacy ciphertext physically lingers in the WAL until a checkpoint
      // — truncate now so the dead form cannot be revived (w19-aad W19-3).
      // Transplants count too: a detected graft reverts the donor row's
      // bytes, and those writes deserve the same WAL hygiene (w23 W23-10).
      let touched = 0; for (const s of stats.values()) touched += s.migrated + (s.transplants ?? 0);
      if (touched > 0) { this._shredded = true; this.checkpoint(); }
    } catch (e) {
      if (this.db.isTransaction) this.db.exec('ROLLBACK');
      // The migration's BEGIN IMMEDIATE is a writer too — a lost
      // busy-timeout race surfaces in the ledger taxonomy, not raw
      // sqlite internals (w19-aad W19-4).
      if (e?.errcode === 5 || e?.errcode === 6 || /database .*locked/i.test(e?.message ?? '')) throw new InvariantError('INV-503-LEDGER', 'Ledger writer contention exceeded the wait bound; retry', 503);
      throw e;
    }
  }
  close() { this.db.close(); }
  tx(fn) {
    // In-memory chain anchors (_chainFloor/_lastRecoveredAt) ride the same
    // rollback boundary as the rows they summarise — an aborted write must
    // never leave the detector anchored to a time that was never committed.
    this._anchorStack ??= [];
    this._anchorStack.push([this._chainFloor ?? 0, this._lastRecoveredAt ?? null]);
    this.onTxDepth?.('push');
    const anchorsPop = () => { this._anchorStack.pop(); this.onTxDepth?.('pop'); };
    const anchorsRollback = () => { const [f, r] = this._anchorStack.pop() ?? [0, null]; this._chainFloor = f; this._lastRecoveredAt = r; this.onTxDepth?.('rollback'); };
    // Nested calls run under a SAVEPOINT: a callee's ROLLBACK can then never
    // destroy the outer transaction's writes (concurrency-audit L2).
    if (this.db.isTransaction) {
      const sp = `sp_${++this._sp}`;
      let savepoint = false;
      try {
        // The SAVEPOINT sits inside the try: a faulting exec has already
        // pushed the anchor stack, so the catch must always restore it —
        // only the rollback itself is gated on the savepoint existing
        // (w30-store F3).
        this.db.exec(`SAVEPOINT ${sp}`); savepoint = true;
        const result = this._schemaGuard(fn);
        if (result && typeof result.then === 'function') throw new Error('Transactions must be synchronous');
        this.db.exec(`RELEASE ${sp}`);
        anchorsPop();
        return result;
      } catch (e) {
        // The rollback itself may fault (release on an auto-rolled-back
        // savepoint, contention mid-rollback) — the original error still
        // surfaces, the anchors still restore, or the detector stays
        // pinned to a phantom floor for the process's life (w23 W23-06).
        if (savepoint) { try { this.db.exec(`ROLLBACK TO ${sp}; RELEASE ${sp}`); } catch (rb) { if (e instanceof Error) e.rollback_error = rb?.message ?? String(rb); } }
        anchorsRollback();
        throw e;
      }
    }
    try {
      this.db.exec('BEGIN IMMEDIATE');
      const result = this._schemaGuard(fn);
      if (result && typeof result.then === 'function') throw new Error('Transactions must be synchronous');
      this.db.exec('COMMIT');
      anchorsPop();
      // Post-commit edge for observers (chain-head flush): a bare audit()
      // append through this self-wrapped tx must land its signed watermark
      // here, not wait for a later fabric transaction (w28-store F2,
      // w28-regression w25/w27).
      try { this.onTxCommit?.(); } catch { /* observers re-buffer and retry on the next edge */ }
      // Post-commit WAL truncation so shredded DEK material never lingers in
      // the log — runs outside the transaction, where SQLite allows it.
      this.checkpoint();
      return result;
    } catch (e) {
      // The outer ROLLBACK itself may fault (contention mid-rollback, an
      // already-dead connection): the original error still surfaces and the
      // anchors still restore — an unguarded ROLLBACK throws PAST both and
      // leaves isTransaction true, silently absorbing every later write
      // into the doomed scope (w31-fixverify F6). The annotation must not
      // assume the thrown value is an Error either.
      if (this.db.isTransaction) { try { this.db.exec('ROLLBACK'); } catch (rb) { if (e instanceof Error) e.rollback_error = rb?.message ?? String(rb); } }
      anchorsRollback();
      // A lost busy-timeout race must surface as a fabric error, not a raw
      // SQLITE_BUSY leaking internals (concurrency-audit H2).
      if (e?.errcode === 5 || e?.errcode === 6 || /database .*locked/i.test(e?.message ?? '')) throw new InvariantError('INV-503-LEDGER', 'Ledger writer contention exceeded the wait bound; retry', 503);
      throw e;
    }
  }
  _signer(tenant) {
    // Same prototype-member bar as key() (w21-store F-10).
    requireThat(Object.hasOwn(this.auditSigners, tenant), 'INV-404-NOT-FOUND', 'Resource not found', 404);
    return this.auditSigners[tenant];
  }
  key(tenant) {
    // Prototype-member names must not resolve through Object.prototype —
    // key('toString') is an unclassified crash otherwise (w21-store F-10).
    requireThat(Object.hasOwn(this.tenantKeys, tenant), 'INV-404-NOT-FOUND', 'Resource not found', 404);
    return Buffer.from(this.tenantKeys[tenant], 'base64url');
  }
  dek(tenant, kind, id) {
    this._addr(tenant, kind, id);
    const row = this._schemaGuard(() => this._stmt('SELECT wrapped FROM deks WHERE tenant=? AND kind=? AND id=?').get(tenant, kind, id));
    if (!row) return null;
    // Unwrapped-key memo keyed on the wrapped ciphertext: a grafted wrap
    // misses and re-derives through decrypt, so substitution still reads
    // as tamper (w47-perf). The buffer is copied on handout — callers get
    // key material they cannot mutate into the memo.
    const dk = `${tenant}|${kind}|${id}|${hashBytes(row.wrapped)}`;
    const dmem = this._dekMemo ??= new Map();
    const dhit = dmem.get(dk);
    if (dhit !== undefined) return Buffer.from(dhit);
    // A wrapped DEK that fails to authenticate is storage-layer tamper
    // evidence in the ledger taxonomy — never a raw crypto TypeError
    // (w43-store F-3, same doctrine as readValue's ciphertext path).
    try {
      const dek = Buffer.from(decrypt(row.wrapped, this.key(tenant), dekAad(tenant, kind, id)), 'base64url');
      if (dmem.size >= 1024) dmem.delete(dmem.keys().next().value);
      dmem.set(dk, dek);
      return Buffer.from(dek);
    }
    catch { throw new InvariantError('INV-503-STORAGE', 'Wrapped data key does not authenticate', 503); }
  }
  // Non-string addressing coerces at the SQL layer (TEXT affinity makes
  // id=5 match id='5') — the write side must not address rows the
  // string-guarded put() would have refused (w21-store F-11).
  _addr(tenant, kind, id) {
    requireThat(typeof tenant === 'string' && typeof kind === 'string' && typeof id === 'string', 'INV-400-SCHEMA', 'Store keys must be strings', 400);
  }
  get(tenant, kind, id) {
    this._addr(tenant, kind, id);
    const row = this._schemaGuard(() => this._stmt('SELECT value FROM records WHERE tenant=? AND kind=? AND id=?').get(tenant, kind, id));
    if (!row) return null;
    // Plaintext memo keyed on the row's own ciphertext AND its wrapped
    // DEK: an unchanged pair serves an identical decrypted object without
    // re-running GCM, while a grafted ciphertext or a murdered/grafted DEK
    // changes the key and forces the honest decrypt path — including the
    // INV-409 a dangling ciphertext earns (w47-perf). Callers may mutate
    // the returned object, so every hit returns a private clone and the
    // memo copy is never handed out.
    const dekRow = this._schemaGuard(() => this._stmt('SELECT wrapped FROM deks WHERE tenant=? AND kind=? AND id=?').get(tenant, kind, id));
    const mk = `${tenant}|${kind}|${id}|${hashBytes(row.value)}|${hashBytes(dekRow?.wrapped ?? '-')}`;
    const mem = this._plainMemo ??= new Map();
    const hit = mem.get(mk);
    if (hit !== undefined) return structuredClone(hit);
    // Records written before per-record DEKs fall back to the tenant key.
    const plain = this.readValue(tenant, kind, id, row.value);
    if (mem.size >= 1024) mem.delete(mem.keys().next().value);
    mem.set(mk, structuredClone(plain));
    return plain;
  }
  must(tenant, kind, id) {
    const row = this.get(tenant, kind, id); requireThat(row, 'INV-404-NOT-FOUND', 'Resource not found', 404); return row;
  }
  put(tenant, kind, id, value, at) {
    // Non-string addressing would coerce into a different AAD than callers
    // compute — born-corrupt rows (w8-fixverify F8).
    requireThat(typeof tenant === 'string' && typeof kind === 'string' && typeof id === 'string', 'INV-400-SCHEMA', 'Store keys must be strings', 400);
    // An overwrite supersedes the previous ciphertext and wrapped DEK — arm
    // the WAL checkpoint so the old material is truncated at commit instead
    // of lingering in the log until a shred (DEK-audit F3).
    if (this._schemaGuard(() => this._stmt('SELECT 1 FROM records WHERE tenant=? AND kind=? AND id=?').get(tenant, kind, id))
      || this._schemaGuard(() => this._stmt('SELECT 1 FROM deks WHERE tenant=? AND kind=? AND id=?').get(tenant, kind, id))) this._shredded = true;
    const dek = randomBytes(32);
    // The record+DEK pair must land atomically — a bare-autocommit crash
    // between them leaves a ciphertext with no key that then reads as
    // INV-409 'tamper' instead of a crash artifact (w28-store F8). A dropped
    // table or planted trigger on the write is tamper evidence, not raw
    // sqlite noise (w47-fixverify M-1).
    const pair = () => this._schemaGuard(() => {
      this._landed(() => this._stmt('INSERT INTO records VALUES(?,?,?,?,?) ON CONFLICT(tenant,kind,id) DO UPDATE SET value=excluded.value').run(tenant, kind, id, encrypt(value, dek, recAad(tenant, kind, id)), at), 'record write');
      this._landed(() => this._stmt('INSERT INTO deks VALUES(?,?,?,?) ON CONFLICT(tenant,kind,id) DO UPDATE SET wrapped=excluded.wrapped').run(tenant, kind, id, encrypt(dek.toString('base64url'), this.key(tenant), dekAad(tenant, kind, id))), 'dek write');
    });
    if (this.db.isTransaction) pair(); else this.tx(pair);
    if (!this.db.isTransaction) this.checkpoint();
    // Record-table dirt: memoized readers (grantsFor/policy) key on this
    // counter so any rewrite — committed or rolled back — forces a fresh
    // read instead of serving a stale projection (w45-perf).
    this._dirtSeq = (this._dirtSeq ?? 0) + 1;
    this.onRecordWrite?.(tenant, kind, id);
  }
  insert(tenant, kind, id, value, at) {
    requireThat(!this.get(tenant, kind, id), 'INV-409-CONFLICT', 'Record already exists', 409); this.put(tenant, kind, id, value, at);
  }
  list(tenant, kind, limit = 500, offset = 0) {
    return this._schemaGuard(() => this._stmt('SELECT id,value FROM records WHERE tenant=? AND kind=? ORDER BY created DESC,id LIMIT ? OFFSET ?').all(tenant, kind, limit, offset))
      .map(row => this.readValue(tenant, kind, row.id, row.value));
  }
  // Id-only enumeration: sweeps must not let one undecryptable row wedge the
  // whole pass (store-audit MED-3) — callers isolate failures per id.
  ids(tenant, kind, limit = 500, offset = 0) {
    return this._schemaGuard(() => this._stmt('SELECT id FROM records WHERE tenant=? AND kind=? ORDER BY created DESC,id LIMIT ? OFFSET ?').all(tenant, kind, limit, offset).map(r => r.id));
  }
  remove(tenant, kind, id) {
    this._addr(tenant, kind, id);
    this._shredded = true;
    // The DEK+record delete pair must land or roll back together — a crash
    // between them leaves a dekless row that wedges the revocation floor
    // probe as fake tamper evidence (w32-store F5).
    const pair = () => {
      this._stmt('DELETE FROM deks WHERE tenant=? AND kind=? AND id=?').run(tenant, kind, id);
      this._stmt('DELETE FROM records WHERE tenant=? AND kind=? AND id=?').run(tenant, kind, id);
      // A planted BEFORE DELETE RAISE(IGNORE) swallows the row silently —
      // changes()==0 is indistinguishable from absent at the delta level,
      // so probe the residue: a surviving row is trigger evidence, never
      // 'already gone' (w50-fv F-2).
      requireThat(!this._stmt('SELECT 1 FROM deks WHERE tenant=? AND kind=? AND id=?').get(tenant, kind, id)
        && !this._stmt('SELECT 1 FROM records WHERE tenant=? AND kind=? AND id=?').get(tenant, kind, id),
        'INV-409-INTEGRITY', 'Delete refused by a planted trigger — tamper evidence', 409);
    };
    if (this.db.isTransaction) pair(); else this.tx(pair);
    if (!this.db.isTransaction) this.checkpoint(); // non-tx paths must not leave the DEK in the WAL (store-audit LOW)
    this._dirtSeq = (this._dirtSeq ?? 0) + 1;
    this.onRecordWrite?.(tenant, kind, id);
  }
  readValue(tenant, kind, id, wrapped) {
    const key = this.dek(tenant, kind, id) ?? this.key(tenant);
    // A corrupted ciphertext is tamper evidence, not a code crash — every
    // decrypt failure classifies in the ledger taxonomy (w21-store F-7).
    try { return decrypt(wrapped, key, recAad(tenant, kind, id)); }
    catch (e) { throw new InvariantError('INV-409-INTEGRITY', 'Stored ciphertext does not authenticate', 409); }
  }
  shred(tenant, kind, id) {
    // Same address guard as every sibling: a numeric id would bind with no
    // TEXT-affinity coercion, silently erase nothing, and report 'not
    // present' while the ciphertext row survives (w24-crypto F8).
    this._addr(tenant, kind, id);
    // Crypto-shredding: destroy the record DEK (secure_delete zeroes its
    // page) and drop the ciphertext; then truncate the WAL so no reachable
    // copy of the wrapped key remains. Pre-erasure backups are out of scope
    // and stay honest in the retention report.
    // The pair deletes atomically when no caller tx is open — a crash
    // between them leaves dekless residue, not a verdict (w32-store F5).
    const pair = () => {
      const changes = this._stmt('DELETE FROM deks WHERE tenant=? AND kind=? AND id=?').run(tenant, kind, id).changes
        + this._stmt('DELETE FROM records WHERE tenant=? AND kind=? AND id=?').run(tenant, kind, id).changes;
      // Same residue probe as remove(): a swallowed delete must convict,
      // not read as 'nothing was there' (w50-fv F-2).
      requireThat(!this._stmt('SELECT 1 FROM deks WHERE tenant=? AND kind=? AND id=?').get(tenant, kind, id)
        && !this._stmt('SELECT 1 FROM records WHERE tenant=? AND kind=? AND id=?').get(tenant, kind, id),
        'INV-409-INTEGRITY', 'Shred refused by a planted trigger — tamper evidence', 409);
      return changes;
    };
    const changes = this.db.isTransaction ? pair() : this.tx(pair);
    this._shredded = this._shredded || changes > 0;
    this._dirtSeq = (this._dirtSeq ?? 0) + 1;
    if (!this.db.isTransaction) this.checkpoint();
    return changes > 0;
  }
  // Called post-commit (tx) and at open: truncates the WAL after shredding so
  // no reachable copy of a destroyed wrapped DEK remains in the log. The
  // checkpoint result is honoured — a busy/partial truncate keeps the shred
  // flag armed so the next commit retries (store-audit HIGH-1).
  checkpoint() {
    if (!this._shredded) return;
    // SQLITE_LOCKED (contended reader/writer) surfaces as a throw, not
    // busy=1 — a committed write must still report success, with the shred
    // flag left armed for the next commit to retry (w8-fixverify F2).
    try {
      const r = this._stmt('PRAGMA wal_checkpoint(TRUNCATE)').get();
      if (!r.busy && r.checkpointed >= r.log) this._shredded = false;
    } catch { /* contention: flag stays armed */ }
  }
  // Re-read the chain tail when the in-memory anchors are about to fail a
  // legality check. The anchors are per-instance caches seeded at open —
  // a peer instance's appends (entries, and CLOCK_RECOVERED above all)
  // move the true floor forward and attest rewinds this instance never
  // saw. Called only on the would-fail path so the common write costs no
  // extra scan (w23 W23-03).
  _refreshChainAnchors() {
    const newest = this._stmt('SELECT tenant,envelope FROM audit ORDER BY rowid DESC LIMIT 1').get();
    if (newest && newest.envelope !== this._anchorScanned) {
      this._anchorScanned = newest.envelope;
      try {
        const env = JSON.parse(newest.envelope);
        const signer = this._signer(newest.tenant), pub = signer.keys ? signer.keys() : { [signer.key_id]: { public_key: signer.public_key } };
        verifySigned(env, pub, 'audit');
        if (typeof env?.payload?.time === 'number' && Number.isFinite(env.payload.time) && env.payload.time > (this._chainFloor ?? 0)) this._chainFloor = env.payload.time;
      } catch { /* unverifiable head — floor holds its last attested value */ }
    }
    for (const row of this._stmt("SELECT tenant,envelope FROM audit WHERE json_valid(envelope) AND (json_extract(envelope,'$.payload.type')='CLOCK_RECOVERED'" + DUP_KEY_PROBE + ") ORDER BY rowid DESC LIMIT 512").all()) {
      try {
        const env = JSON.parse(row.envelope);
        if (env?.payload?.type !== 'CLOCK_RECOVERED') continue;
        const signer = this._signer(row.tenant), pub = signer.keys ? signer.keys() : { [signer.key_id]: { public_key: signer.public_key } };
        verifySigned(env, pub, 'audit');
        const at = env.payload.metadata?.recovered_at;
        if (typeof at === 'number' && (this._lastRecoveredAt === null || at > this._lastRecoveredAt)) this._lastRecoveredAt = at;
        break; // newest verified recovery wins, same as at open
      } catch { /* tampered candidate — skip to an older verified one */ }
    }
  }
  clock(now, { recovery = false, recoveryPath = false } = {}) {
    requireThat(Number.isSafeInteger(now) && now > 0, 'INV-503-TIME', 'Clock unavailable', 503);
    const row = this._stmt('SELECT last FROM clock WHERE id=1').get();
    // recoveryPath: remediation ops (the veto's prescribed revokes) must
    // run during a halted clock — they may not advance the row forward nor
    // rewind it: the detector stays at its honest high-water mark while the
    // op's audit entry lands at chain-floor time (w22-fixverify F1).
    // Anchors are per-instance caches: a peer's appended CLOCK_RECOVERED
    // must become visible without a restart, and the floor must track the
    // peer's committed head — the memory check is authoritative only when
    // it PASSES; a would-be failure re-reads the chain first (w23 W23-03).
    const floorLegal = v => v >= (this._chainFloor ?? 0) || (this._lastRecoveredAt !== null && v >= this._lastRecoveredAt);
    if (recoveryPath && row && now < row.last) {
      if (!floorLegal(row.last)) { this._refreshChainAnchors(); requireThat(floorLegal(row.last), 'INV-409-AUDIT-TAMPER', 'Clock floor rewound below attested chain time', 409); }
      return now;
    }
    requireThat(recovery || !row || now >= row.last, 'INV-503-TIME', 'Clock regression; security operations halted', 503);
    // Anchored floor: `last` sitting below the chain's attested time is
    // legal only inside the span an on-chain CLOCK_RECOVERED attested —
    // anything deeper is a file-writer's silent rewind (w22-fixverify F1).
    // The recovery path itself must not dead-end on the rewound state it
    // exists to repair: a below-floor row may move FORWARD here because
    // the same transaction lands the attesting CLOCK_RECOVERED (w23 W23-04).
    if (row && !floorLegal(row.last)) {
      this._refreshChainAnchors();
      requireThat(floorLegal(row.last) || (recovery && now >= row.last), 'INV-409-AUDIT-TAMPER', 'Clock floor rewound below attested chain time', 409);
    }
    // Recovery writes the operator-asserted host time: `last` is the
    // regression detector, not the time source — expiry is evaluated
    // against host time either way, and an over-high `last` would wedge
    // the gate permanently after an honest rewind (VM snapshot restore).
    this._landed(() => this._stmt('INSERT INTO clock VALUES(1,?) ON CONFLICT(id) DO UPDATE SET last=excluded.last').run(now), 'clock ratchet');
    return now;
  }
  auditHeadSeq(tenant) {
    return this._schemaGuard(() => this._stmt('SELECT COALESCE(MAX(seq),0) s FROM audit WHERE tenant=?').get(tenant).s);
  }
  // Prepared-statement memo: statement compilation is the dominant sqlite
  // cost on the hot path, and node:sqlite transparently recompiles a
  // cached statement after schema drift — a genuinely dropped table still
  // throws the same 'no such table' a fresh prepare would, so the INV
  // taxonomy classifies identically (w47-perf).
  _stmt(sql) {
    const mem = this._stmts ??= new Map();
    let st = mem.get(sql);
    if (!st) {
      if (mem.size >= 256) mem.delete(mem.keys().next().value);
      mem.set(sql, st = this.db.prepare(sql));
    }
    return st;
  }
  // A BEFORE ... RAISE(IGNORE) trigger abandons the statement silently —
  // no error, COMMIT succeeds, the caller holds success, and the row
  // never lands: audit appends, nonce burns, idempotency receipts and
  // budget mirrors all vanish while every caller reads 'ok'
  // (w48-fixverify CRITICAL). Security-critical writes assert their
  // change count inside the same transaction instead of trusting the
  // silent return.
  _totalChanges() { return Number(this._stmt('SELECT total_changes() tc').get().tc); }
  // changes() counts only the top-level statement — an AFTER trigger's
  // side-effects (a silent revert, a shadow row, a planted mirror) never
  // show in it. total_changes() counts every row the connection touched,
  // trigger work included: measuring the statement-level delta catches the
  // last laundering arm (w49-fixverify C-2). The write runs inside a
  // transaction so no peer can interleave between the delta probe and the
  // statement itself; `expect` is the number of legitimate row writes the
  // statement performs — total_changes counts an upsert over an existing
  // row as 1 (the implicit delete is not a change), so every single-row
  // statement is 1 and any trigger side-effect pushes the delta past it.
  _landed(write, what, expect = 1) {
    return this._schemaGuard(() => this.tx(() => {
      const before = this._totalChanges();
      const result = write();
      requireThat(result?.changes >= 1, 'INV-409-INTEGRITY', `${what} abandoned — ledger write refused by a foreign trigger`, 409);
      const delta = this._totalChanges() - before;
      requireThat(delta === expect, 'INV-409-INTEGRITY', `${what} produced ${delta} row write(s) in one statement — foreign trigger side-effects`, 409);
      return result;
    }));
  }
  // A dropped or rewritten table is integrity evidence inside the INV
  // taxonomy, never bare sqlite noise escaping to callers (w44-store M-2).
  _schemaGuard(run) {
    try { return run(); }
    catch (e) {
      if (/no such table|no such column|not a database|malformed/i.test(e?.message ?? ''))
        throw new InvariantError('INV-409-INTEGRITY', 'Ledger schema diverged — tamper evidence', 409, { cause: e });
      // Trigger-raised aborts arrive as SQLITE_CONSTRAINT_TRIGGER
      // (errcode 1811): EVERY abort on a guarded write path is tamper
      // evidence — a planted mimic trigger replaying a known guard's
      // RAISE text is indistinguishable from the real guard firing, so
      // the allowlist arm laundered planted payloads into raw errors
      // (w48-store W48-3). The one legitimate-fire exception is the audit
      // seq-guard on a multi-writer head race — the append path re-
      // discriminates it via the unwrapped cause (w50-fv F-1).
      if (e?.errcode === 1811)
        throw new InvariantError('INV-409-INTEGRITY', 'Ledger write refused by a trigger — tamper evidence', 409, { cause: e });
      // Contention is not tamper evidence — busy/locked propagates for
      // the outer layers' INV-503-LEDGER translation.
      if (e?.errcode === 5 || e?.errcode === 6 || /database .*locked/i.test(e?.message ?? '')) throw e;
      // Extended sqlite codes carry the primary class in the low byte —
      // BUSY_SNAPSHOT/RECOVERY/TIMEOUT (261/517/769) are the same
      // contention class as a bare busy, not surgery evidence (w50-fv
      // F-5). Contention stays raw so outer layers translate/retry.
      const base = typeof e?.errcode === 'number' ? e.errcode & 0xFF : null;
      if (base === 5 || base === 6) throw e;
      // NOMEM/INTERRUPT/SCHEMA are engine faults — honest infrastructure,
      // never mislabeled tamper.
      if (base !== null && [7, 9, 17].includes(base))
        throw new InvariantError('INV-503-LEDGER', `Ledger engine fault: ${e?.message ?? 'sqlite error'}`, 503, { cause: e });
      // Storage-class faults (readonly file, I/O error, corrupt image,
      // disk full, can't-open) are infrastructure, not surgery evidence —
      // a filled disk must not read as tamper (w49-fixverify M-4). The low
      // byte holds the primary code under better-sqlite's extended codes.
      if (base !== null && [8, 10, 11, 13, 14, 15].includes(base))
        throw new InvariantError('INV-503-STORAGE', `Ledger storage fault: ${e?.message ?? 'sqlite error'}`, 503, { cause: e });
      // The whole CONSTRAINT family (base 19: CHECK/FK/UNIQUE plus the
      // 1811 TRIGGER abort already handled above) is guard evidence — a
      // planted constraint guard is indistinguishable from our own, and
      // ours never fire on a legitimate write (w51-fv F-5).
      if (base === 19)
        throw new InvariantError('INV-409-INTEGRITY', `Ledger access refused by a constraint guard — tamper evidence: ${e?.message ?? 'sqlite error'}`, 409, { cause: e });
      // Unmapped sqlite codes (TOOBIG, MISMATCH, MISUSE, NOLFS, RANGE,
      // …) are honest engine faults — mislabeling them INTEGRITY would
      // mint false tamper evidence from infrastructure noise
      // (w51-fv F-5).
      if (e?.code === 'ERR_SQLITE_ERROR' || typeof e?.errcode === 'number')
        throw new InvariantError('INV-503-LEDGER', `Ledger engine fault: ${e?.message ?? 'sqlite error'}`, 503, { cause: e });
      throw e;
    }
  }
  audit(tenant, type, actor, reference, metadata, now) {
    // Entry + clock-ratchet must commit together: outside a transaction a
    // crash (or SQLITE_BUSY) between them leaves clock.last below the
    // chain floor and the NEXT OPEN bricks on INV-409-AUDIT-TAMPER with no
    // in-band recovery (w28-store F2). Inside a tx the caller's boundary
    // already covers the pair.
    if (!this.db.isTransaction) return this.tx(() => this.audit(tenant, type, actor, reference, metadata, now));
    const last = this._schemaGuard(() => this._stmt('SELECT seq,hash,envelope FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get(tenant));
    // The chain's `time` is a monotone logical clock: verifyAudit requires
    // non-decreasing entry times, so an accepted host rewind must not write
    // a regressed value into the chain (it would break verification
    // permanently — w7-clock F1). The rewound host reading is still on the
    // record inside the CLOCK_RECOVERED entry's metadata.
    // priorTime is the monotone floor: chain time never steps back, so a
    // legitimate clock rewind (recoverClock) stays verifiable. A forged
    // head claiming a far-future timestamp gets no silent credit — the
    // index's consume-time bound wedges on it instead (w13-supply W13-04).
    // A malformed head envelope is tamper evidence, not a permanent wedge
    // of raw SyntaxErrors — classify it like the read path does
    // (w21-store F-2).
    let priorTime = 0;
    if (last) {
      let head;
      try { head = JSON.parse(last.envelope); } catch { throw new InvariantError('INV-409-AUDIT-TAMPER', 'Audit head envelope is unparseable — ledger tamper', 409); }
      requireThat(typeof head?.payload?.time === 'number' && Number.isFinite(head.payload.time), 'INV-409-AUDIT-TAMPER', 'Audit head envelope carries no valid time — ledger tamper', 409);
      priorTime = head.payload.time;
    }
    // Consult the fold-floor marker BEFORE signing: a stored value no
    // honest path emits is planted garbage the marker block below heals —
    // and the append must carry what it SAW on the SIGNED payload, or the
    // only durable record of the divergence sits in attacker-writable
    // meta_kv (forgeable residue, clobberable pointer — w56). The field
    // names the marker this append observed, whether or not the heal
    // below overwrote it — a marker left divergent on purpose is equally
    // documented. Well-formed means exactly what the fold reader convicts
    // as malformed — `^\d+:` alone called '5:', '0:x' and '5:a:b' honest
    // and let the overwrite evaporate a planted marker unnamed (w56
    // self-audit). Read inside this same tx so the marker block sees the
    // same snapshot.
    const floorPrior = this._schemaGuard(() => this._stmt("SELECT value FROM meta_kv WHERE tenant=? AND key='fold_floor'").get(tenant)?.value);
    const floorPriorParts = typeof floorPrior === 'string' ? floorPrior.split(':') : null;
    const floorPriorSeq = floorPriorParts !== null && /^\d+$/.test(floorPriorParts[0]) ? Number(floorPriorParts[0]) : undefined;
    const floorPriorWellFormed = floorPriorParts !== null && floorPriorParts.length === 2 && Number.isSafeInteger(floorPriorSeq) && floorPriorSeq >= 1 && floorPriorParts[1] !== '';
    // A marker naming a seq ahead of every committed row is never honest:
    // marker writes are atomic with their row's append, so a committed
    // marker's seq is always <= the committed tip at this snapshot —
    // `floorPriorSeq > last.seq` is a plant that would wedge the guarded
    // UPSERT (and every later epoch attestation) forever (w66-seal F-2).
    const floorPriorAhead = floorPriorSeq !== undefined && floorPriorSeq > (last?.seq ?? 0);
    // A well-formed in-range marker whose hash half names bytes the
    // stored row does not carry is a transplant: the guarded UPSERT
    // only loses to seq, so it survived every honest append unnamed
    // (w67-fv N-1). Name it divergent like the malformed/ahead shapes.
    const floorPriorForeign = floorPriorWellFormed && !floorPriorAhead
      ? this._stmt('SELECT hash FROM audit WHERE tenant=? AND seq=?').get(tenant, floorPriorSeq)?.hash !== floorPriorParts[1]
      : false;
    const divergentMarker = floorPrior !== undefined && (!floorPriorWellFormed || floorPriorAhead || floorPriorForeign) ? String(floorPrior).slice(0, 200) : undefined;
    // The key is reserved evidence: a caller-supplied fold_floor_divergent
    // must never ride the signed envelope verbatim when no divergence was
    // observed — it would let a file-writer pair planted residue with a
    // forged 'anchor' (w57-fv NIT-1). Strip it unconditionally, then set
    // the observed value.
    const healedMeta = (() => {
      if (metadata !== null && typeof metadata === 'object') {
        const m = { ...metadata };
        delete m.fold_floor_divergent;
        if (divergentMarker !== undefined) m.fold_floor_divergent = divergentMarker;
        return m;
      }
      return divergentMarker !== undefined ? { fold_floor_divergent: divergentMarker } : metadata;
    })();
    const entry = { tenant_id: tenant, sequence: (last?.seq ?? 0) + 1, previous: last?.hash ?? '0'.repeat(64), type, actor, reference, metadata: healedMeta, time: Math.max(now, priorTime) };
    // Chain anchors kept current in-process: the newest signed time IS the
    // floor the clock row is compared against, and the newest recovery
    // explains any backward clock discontinuity (w22-fixverify F1). The
    // floor compare below must use the pre-entry value — `last` trails the
    // committed chain, it is not required to pre-empt the in-flight entry.
    // Side effects are post-insert: committing the anchor/ratchet bumps
    // BEFORE the fallible sign+insert would leave a phantom floor
    // outliving the aborted write (w23 W23-05).
    const floorBefore = this._chainFloor ?? 0;
    // The crow legality check honours the IN-FLIGHT attestation: an
    // honest backward recovery writes `last` below the floor and lands
    // its explaining CLOCK_RECOVERED right here — refusing would wedge
    // the repair path on the state it exists to fix (w23 W23-04).
    const recoveredBefore = type === 'CLOCK_RECOVERED' ? (entry.metadata?.recovered_at ?? this._lastRecoveredAt) : this._lastRecoveredAt;
    const crow = this._schemaGuard(() => this._stmt('SELECT last FROM clock WHERE id=1').get());
    requireThat(!crow || crow.last >= floorBefore || (recoveredBefore !== null && crow.last >= recoveredBefore), 'INV-409-AUDIT-TAMPER', 'Clock floor rewound below attested chain time', 409);
    // Hash what is actually attested: the signer may add a bound marker (the
    // recovery_signing annotation when a pending successor signs after a
    // key-revoke — w11-lifecycle F2), so the row digest binds the envelope's
    // payload, not the pre-signature entry.
    const signer = this._signer(tenant);
    // The head we extend must verify: a file-writer planting a parseable
    // but unverifiable row must not get every subsequent entry silently
    // chained atop a permanent wedge (w22-fixverify F8). Memoised by head
    // hash — the head rarely changes between appends.
    if (last) {
      this._verifiedHeads ??= new Map();
      // The memo key binds the stored hash column to the row's actual
      // bytes: the hash column is attacker-writable, so keying on it alone
      // would let a planted row borrow a previously-verified hash while
      // carrying a different envelope (w46-store L-1).
      const vkey = `${last.seq}:${last.hash}:${hashBytes(last.envelope)}`;
      if (!this._verifiedHeads.has(vkey)) {
        // A head this instance minted skips the ECDSA pass when the stored
        // bytes still digest to the minted hash — byte-identical means the
        // signature is the one this signer produced (w43-perf).
        const selfMinted = this._selfRows?.get(tenant)?.get(last.seq) === hashBytes(last.envelope);
        if (!selfMinted) {
          const pub = signer.keys ? signer.keys() : { [signer.key_id]: { public_key: signer.public_key } };
          try { verifySigned(JSON.parse(last.envelope), pub, 'audit'); } catch (e) { throw new InvariantError('INV-409-AUDIT-TAMPER', 'Audit head does not verify — ledger tamper', 409, { cause: e }); }
        }
        if (this._verifiedHeads.size >= 64) this._verifiedHeads.clear();
        this._verifiedHeads.set(vkey, true);
      }
    }
    const envelope = signer.sign(entry);
    const hash = digest(envelope.payload);
    const envText = canonical(envelope);
    try {
      this._landed(() => this._stmt('INSERT INTO audit VALUES(?,?,?,?,?)').run(tenant, entry.sequence, entry.previous, hash, envText), 'audit append');
    } catch (e) {
      // A peer instance appending between our head-read and this insert
      // trips the seq guard — that is a retryable conflict, not tamper
      // and not raw sqlite internals leaking to callers (w23 W23-09).
      // errcode 517 = SQLITE_BUSY_SNAPSHOT: a deferred reader's snapshot
      // went stale under a peer write — same retry semantics as busy.
      // _schemaGuard wraps every trigger abort (errcode 1811) as INTEGRITY
      // with the sqlite error as `cause` — discriminate on the RAW error
      // so the real audit_seq_guard firing on an honest multi-writer head
      // race stays retryable INV-409-CONFLICT instead of a false tamper
      // verdict, while the mimic text it replays still dies here (w50-fv
      // F-1: classification must happen against the unwrapped error).
      const raw = e?.details?.cause ?? e?.cause ?? e;
      if (raw?.errcode === 5 || raw?.errcode === 6 || raw?.errcode === 517 || /database .*locked|database is busy/i.test(raw?.message ?? '')) throw new InvariantError('INV-503-LEDGER', 'Ledger writer contention exceeded the wait bound; retry', 503);
      if (raw?.errcode === 1811) {
        // A trigger aborted the insert — prove which. The guard's RAISE
        // text is attacker-replayable through a planted AFTER trigger, so
        // the discriminator is the slot itself, not the message: if a row
        // now owns the attempted seq, a peer append won the race and the
        // real seq guard could have fired — retryable conflict. If the
        // slot is still free no legitimate guard could have fired — the
        // refusal is foreign-trigger evidence either way (w50-fv F-1).
        let headNow;
        try { headNow = this._stmt('SELECT COALESCE(MAX(seq),0) m FROM audit WHERE tenant=?').get(tenant)?.m; }
        catch (probe) { throw new InvariantError('INV-409-INTEGRITY', 'Ledger schema diverged — tamper evidence', 409, { cause: probe }); }
        if (Number.isInteger(headNow) && headNow < entry.sequence)
          throw new InvariantError('INV-409-INTEGRITY', 'Audit append refused by a foreign trigger — tamper evidence', 409, { cause: e });
        throw new InvariantError('INV-409-CONFLICT', 'Audit head moved during append; retry', 409);
      }
      // A dropped or rewritten table is integrity evidence, never raw
      // sqlite noise on the write path (w44-store M-2).
      if (/no such table|no such column|not a database|malformed/i.test(raw?.message ?? '')) throw new InvariantError('INV-409-INTEGRITY', 'Ledger schema diverged — tamper evidence', 409, { cause: e });
      // Storage-class faults are infrastructure, not surgery — same split
      // as _schemaGuard (w49-fixverify M-4).
      if (typeof raw?.errcode === 'number' && [8, 10, 11, 13, 14, 15].includes(raw.errcode & 0xFF)) throw new InvariantError('INV-503-STORAGE', `Audit storage fault: ${raw?.message ?? 'sqlite error'}`, 503, { cause: e });
      // A grafted-PK collision (1555) or any other sqlite-class fault on
      // the audit append is tamper evidence, never raw internals
      // (w48-store W48-3).
      if (raw?.code === 'ERR_SQLITE_ERROR' || typeof raw?.errcode === 'number') throw new InvariantError('INV-409-INTEGRITY', `Audit append refused: ${raw?.message ?? 'sqlite error'}`, 409, { cause: e });
      throw e;
    }
    // In-ledger fold marker: the signed head files are peer-facing hints
    // that replay backward losslessly, so a coherent two-file rollback
    // needs a witness inside the write boundary the file pair cannot
    // reach — this marker commits atomically with the audit row it names,
    // survives tail-cuts (it is not a chained row), and a fresh open can
    // attest any head/watermark pair that claims less than it
    // (w44-fixverify F-2). The marker only ever ADVANCES: a stored marker
    // ahead of this append is divergence evidence (rolled-back tail,
    // planted floor) that an honest write must never launder — it is the
    // only unsigned witness to destroyed fold progress, and overwriting
    // it retired the conviction on the next consult (w54-runtime F-1).
    // The DO UPDATE ... WHERE guard keeps the regression denial atomic
    // against racing writers; the post-write probe then asserts the
    // stored marker covers this row's position, which also convicts a
    // foreign trigger that silently eats the write (same _landed
    // discipline, expressed for a statement that may legitimately
    // write zero rows).
    this._schemaGuard(() => this.tx(() => {
      const before = this._totalChanges();
      // The stored marker was consulted before this append signed — a
      // value no honest path emits (' 999999999:x', 'abc', a bare hash) is
      // planted garbage: CAST parses its prefix arbitrarily (high → the
      // guarded UPDATE refuses and every later append wedges on the
      // probe, remediation included; low → it is silently overwritten).
      // Both directions heal here and bind the healed content to this
      // commit — a planted marker can never brick the append path or
      // evaporate unnamed (w55-runtime F-1, w55-fv C-1/M-3). `floorPrior`
      // was read inside this same tx before the entry signed, so the
      // snapshot is identical.
      this._stmt("INSERT INTO meta_kv VALUES(?,'fold_floor',?) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value WHERE CAST(substr(meta_kv.value,1,instr(meta_kv.value,':')-1) AS INTEGER) < CAST(substr(excluded.value,1,instr(excluded.value,':')-1) AS INTEGER)").run(tenant, `${entry.sequence}:${hash}`);
      const delta = this._totalChanges() - before;
      requireThat(delta <= 1, 'INV-409-INTEGRITY', `fold-floor marker produced ${delta} row writes in one statement — foreign trigger side-effects`, 409);
      let stored = this._stmt("SELECT value FROM meta_kv WHERE tenant=? AND key='fold_floor'").get(tenant)?.value;
      const storedParts = typeof stored === 'string' ? stored.split(':') : null;
      const storedSeqProbe = storedParts !== null && /^\d+$/.test(storedParts[0]) ? Number(storedParts[0]) : undefined;
      const storedWellFormed = storedParts !== null && storedParts.length === 2 && Number.isSafeInteger(storedSeqProbe) && storedSeqProbe >= 1 && storedParts[1] !== '';
      // A well-formed-shaped marker ahead of every row we can see is a
      // plant: the guarded UPSERT refuses it (stored CAST >= excluded) and
      // so does every FUTURE honest mint — the epoch attestation would
      // stay broken forever while `/^\d+:/` kept passing it (w66-seal
      // F-2). Compare against the visible committed tip — a concurrent
      // commit's marker legitimately exceeds our own entry.sequence but
      // never exceeds the tip it was written for.
      const tipNow = this._stmt('SELECT MAX(seq) m FROM audit WHERE tenant=?').get(tenant)?.m ?? entry.sequence;
      // An in-range marker must also bind the real hash of the row it
      // names: the guarded UPSERT only loses to a stored seq >= our own,
      // so a survivor naming OUR seq (or a peer's just-committed row)
      // with foreign bytes is a forge that otherwise stands until the
      // next append silently overwrites it — the envelope already names
      // the divergence and the residue pointer must land (w67-fv N-1).
      const storedRef = storedWellFormed && Number.isSafeInteger(storedSeqProbe) && storedSeqProbe <= tipNow
        ? this._stmt('SELECT hash FROM audit WHERE tenant=? AND seq=?').get(tenant, storedSeqProbe)
        : undefined;
      if (stored !== undefined && !(storedWellFormed && storedSeqProbe <= tipNow && storedRef !== undefined && storedRef.hash === storedParts[1])) {
        // The refused update left a divergent marker in place — overwrite
        // it outright (with the TRUE tip when a concurrent commit is
        // visible, else our own entry). A real foreign trigger fighting
        // the heal re-fires on this write and the re-probe below still
        // convicts.
        const tipRowNow = tipNow === entry.sequence ? { seq: entry.sequence, hash } : this._stmt('SELECT seq, hash FROM audit WHERE tenant=? AND seq=?').get(tenant, tipNow);
        this._stmt("UPDATE meta_kv SET value=? WHERE tenant=? AND key='fold_floor'").run(`${tipRowNow?.seq ?? entry.sequence}:${tipRowNow?.hash ?? hash}`, tenant);
        stored = this._stmt("SELECT value FROM meta_kv WHERE tenant=? AND key='fold_floor'").get(tenant)?.value;
      }
      if (floorPrior !== undefined && (!floorPriorWellFormed || floorPriorAhead || floorPriorForeign) && stored !== floorPrior) {
        // Evidence, not laundering: the residue row is a POINTER into the
        // signed chain — this append's own envelope already carries
        // fold_floor_divergent, so the row can be verified against
        // anchored bytes and a planted residue cannot mint a phantom conviction
        // (w56-store MED). It survives until a report retires it — never
        // deleted on first read (w56-store HIGH). Written ONLY when the
        // marker actually changed. An ahead-of-tip marker is no longer
        // left standing (w66-seal F-2 reversed that w56 doctrine: standing
        // forever meant wedged forever — it is healed above and writes
        // its pointer here like any other divergence). Landed-check it like every security
        // write: a foreign RAISE(IGNORE) trigger eating this insert must
        // convict (w56-store LOW). The row is keyed PER HEAL — two heals
        // before a report must both reach the surface, never overwrite
        // each other into a single conviction (w57-seal F1). The claim
        // binds the envelope's own 200-char bound — a divergent marker
        // longer than the bound would otherwise verify as unanchored
        // forever (w57-runtime F-2). The fold_residue_keep guards are
        // dropped verbatim for this sanctioned write and recreated
        // immediately — a file-writer delete aborts in-band instead of
        // erasing the conviction (w57-runtime F-1).
        const residueKeyBase = `fold_floor_healed.${entry.sequence}`;
        const residueClaim = `${entry.sequence}:${String(floorPrior).slice(0, 200)}`;
        // A row already standing at the heal's own key is itself evidence
        // — a prior heal's unconsumed claim or a plant — and must never
        // be absorbed by this write (w64-seal F-6). Land under a sibling
        // `.N` suffix instead: the prefix scan + value-matched drains and
        // the claim union all cover it, and both contents reach the
        // report. Same claim at a sibling is the idempotent re-heal.
        let residueKey = residueKeyBase;
        {
          let v = this._stmt("SELECT value FROM meta_kv WHERE tenant=? AND key=?").get(tenant, residueKey)?.value;
          for (let i = 2; v !== undefined && v !== residueClaim; i++) {
            requireThat(i <= 64, 'INV-409-INTEGRITY', 'fold-floor healed residue key space exhausted — planted sibling rows', 409);
            residueKey = `${residueKeyBase}.${i}`;
            v = this._stmt("SELECT value FROM meta_kv WHERE tenant=? AND key=?").get(tenant, residueKey)?.value;
          }
        }
        this.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep');
        this.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_upd');
        this.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_ins');
        try { this._stmt("INSERT INTO meta_kv VALUES(?,?,?) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value").run(tenant, residueKey, residueClaim); }
        finally {
          // Plain CREATE, not IF NOT EXISTS — a planted impostor under
          // our name must not keep the recreate a no-op (w58-fv F-1);
          // the drops above already cleared any same-named row. Emitted
          // from the shared RESIDUE_KEEP_TRIGGERS text — a local stale
          // copy once downgraded the `fold_floor_retired` arms invisibly
          // for the rest of the process lifetime (w61-runtime F-1).
          for (const [, sql] of RESIDUE_KEEP_TRIGGERS) this.db.exec(sql);
        }
        const landedResidue = this._stmt("SELECT value FROM meta_kv WHERE tenant=? AND key=?").get(tenant, residueKey)?.value;
        requireThat(landedResidue === residueClaim, 'INV-409-INTEGRITY', 'fold-floor healed residue refused after write — foreign trigger side-effects', 409);
      }
      const storedSeq = typeof stored === 'string' && /^\d+:/.test(stored) ? Number(stored.split(':')[0]) : undefined;
      // The upper bound matters as much as the lower: a `\d+`-shaped
      // ahead-of-tip plant surviving the heal (a foreign trigger eating
      // the overwrite) still satisfies `>= entry.sequence` — convict it
      // (w66-seal F-2).
      requireThat(storedSeq !== undefined && storedSeq >= entry.sequence && storedSeq <= tipNow, 'INV-409-INTEGRITY', `fold-floor marker write ${stored === undefined ? 'missing' : 'refused'} after write — foreign trigger side-effects`, 409);
    }));
    // Post-commit ordering: only a landed entry may move the anchors and
    // ratchet the detector (w23 W23-05). Our own head is the newest
    // verifiable row — mark it scanned so a later refresh skips it.
    this._anchorScanned = envText;
    // Append counter for the fabric's in-tx chain-facts memo: inside an
    // IMMEDIATE transaction the table can only move through our writes, so
    // a memo keyed on this counter (scoped to the tx window) is sound
    // without re-running the tamper fingerprint (w44-perf).
    this._auditAppends = (this._auditAppends ?? 0) + 1;
    if (entry.time > floorBefore) this._chainFloor = entry.time;
    if (type === 'CLOCK_RECOVERED') this._lastRecoveredAt = entry.metadata?.recovered_at ?? this._lastRecoveredAt;
    // Every committed write ratchets the detector to its own host time —
    // bypass paths (denial audit, drift flags, snapshots) commit entries
    // outside transaction()'s clock() call, and `last` trailing the chain
    // with no attested recovery is what makes a file-writer's rewind
    // detectable instead of invisible (w22-fixverify F1). MAX keeps the
    // honest high-water during a halted or recovered span; the legality
    // assert runs on the pre-write row so the ratchet itself can never
    // launder a rewind.
    this._landed(() => this._stmt('INSERT INTO clock VALUES(1,?) ON CONFLICT(id) DO UPDATE SET last=MAX(clock.last, excluded.last)').run(now), 'clock ratchet');
    // End-of-chain commitment: the fabric moves its signed head watermark
    // post-commit — a truncated tail can never drag the watermark back
    // with it (w24-fixverify W24-01).
    this.onAuditAppend?.(tenant, entry.sequence, hash);
    // Self-write memo: this instance minted the row's signature over these
    // exact BYTES — the memo binds the serialized envelope, so a signature
    // or payload transplant lands as a mismatch and falls back to full
    // verification (w43-perf; a payload-only digest would miss a signature
    // swap — w41-http F7). Bounded per tenant; a stale entry after
    // rollback/rewrite only ever falls back to full verify.
    {
      this._selfRows ??= new Map();
      let sr = this._selfRows.get(tenant);
      if (!sr) { sr = new Map(); this._selfRows.set(tenant, sr); }
      sr.set(entry.sequence, hashBytes(envText));
      if (sr.size > 8192) sr.delete(sr.keys().next().value);
    }
    return { hash, envelope, time: entry.time, seq: entry.sequence };
  }
  // Serialized-envelope digest this instance minted for (tenant, seq) —
  // consumers skip the ECDSA pass only while the stored bytes still match
  // byte-for-byte (w43-perf).
  selfRowEnv(tenant, seq) { return this._selfRows?.get(tenant)?.get(seq); }
  auditHashes(tenant) {
    return this._schemaGuard(() => this._stmt('SELECT hash FROM audit WHERE tenant=? ORDER BY seq').all(tenant).map(r => r.hash));
  }
  auditPage(tenant, { after = 0, limit = 1000 } = {}) {
    // Cursor hygiene: limit=0 would crash on rows.at(-1), a negative limit
    // turns into an UNBOUNDED sqlite read (LIMIT -1 = no bound), and a
    // negative cursor silently anchors wrong — classify all of it as a
    // schema fault before the query runs. Any positive limit is honoured:
    // the internal index fold legitimately pages through the entire chain
    // (w23 W23-08).
    requireThat(Number.isSafeInteger(after) && after >= 0 && Number.isSafeInteger(limit) && limit >= 1, 'INV-400-SCHEMA', 'Invalid audit cursor or limit', 400);
    const rows = this._schemaGuard(() => this._stmt('SELECT seq,previous,hash,envelope FROM audit WHERE tenant=? AND seq>? ORDER BY seq LIMIT ?').all(tenant, after, limit));
    const signer = this._signer(tenant), public_keys = signer.keys ? signer.keys() : { [signer.key_id]: { public_key: signer.public_key } };
    // Serving the log is a security surface: re-verify each row's stored
    // hash against its signed payload and check chain continuity back to the
    // row preceding the page — an injected or rewritten row cannot pass
    // (store-audit MED-5).
    const anchor = after ? this._schemaGuard(() => this._stmt('SELECT hash FROM audit WHERE tenant=? AND seq=?').get(tenant, after)) : null;
    // Death map spans the WHOLE chain, not just the page — a page reader
    // must catch a row signed after its key's earlier revocation
    // (w28-crypto F2).
    const deadAt = this._auditKeyDeaths(tenant);
    requireThat(after === 0 || anchor, 'INV-409-AUDIT-TAMPER', 'Audit cursor does not resolve to a stored row', 409);
    let previous = anchor?.hash ?? '0'.repeat(64);
    const entries = rows.map(r => {
      // A malformed envelope is tamper evidence, not a crash: it lands as
      // the same INV-409-AUDIT-TAMPER as a hash break (w13-fixverify L10).
      let envelope;
      try { envelope = JSON.parse(r.envelope); } catch { throw new InvariantError('INV-409-AUDIT-TAMPER', 'Audit row failed integrity verification', 409); }
      // A payload-less envelope is tamper evidence too — guard before
      // digest so the failure classifies as AUDIT-TAMPER, not a bare
      // schema crash (w18-fixverify F16).
      // The stored `previous` column is checked too — it is written by
      // every audit() append but was never compared, so stored-column
      // surgery on it would go unnamed (w49-seal LOW).
      requireThat(envelope.payload !== undefined && ctEqual(digest(envelope.payload), r.hash) && envelope.payload.sequence === r.seq && ctEqual(envelope.payload.previous, previous) && r.previous === previous, 'INV-409-AUDIT-TAMPER', 'Audit row failed integrity verification', 409);
      // Hash+previous are attacker-computable (the seq trigger permits a raw
      // MAX+1 append): without signature verification the read path would
      // serve an unsigned forged row as a legitimate chain entry (w15).
      // Rows this instance minted skip the ECDSA pass only when the stored
      // BYTES match the memo — byte-identical means the signature is the
      // one this signer produced (w43-perf).
      if (this._selfRows?.get(tenant)?.get(r.seq) !== hashBytes(r.envelope)) {
        try { verifySigned(envelope, public_keys, 'audit'); }
        catch { throw new InvariantError('INV-409-AUDIT-TAMPER', 'Audit row failed signature verification', 409); }
      }
      // The signed payload must attest THIS tenant's row — a validly
      // signed foreign-tenant envelope keyed under this tenant is still
      // tamper evidence (w21-store F-8).
      requireThat(envelope.payload.tenant_id === tenant, 'INV-409-AUDIT-TAMPER', 'Audit row attests a different tenant', 409);
      // Signer-death window on the page surface too (w28-crypto F2).
      const deadSeq = deadAt.get(envelope.protected?.key_id);
      requireThat(!(deadSeq !== undefined && r.seq > deadSeq), 'INV-409-AUDIT-TAMPER', 'Audit row signed by a key past its ledger death', 409);
      previous = r.hash;
      return { sequence: r.seq, hash: r.hash, envelope };
    });
    return { entries, next_cursor: rows.length === limit ? rows.at(-1).seq : null };
  }
  auditExport(tenant, now = null) {
    const signer = this._signer(tenant), public_keys = signer.keys ? signer.keys() : { [signer.key_id]: { public_key: signer.public_key } };
    // Export runs the same per-row pass as auditPage — a tampered-but-
    // parseable row must not fold silently into the checkpoint the signer
    // attests (w16-fixverify F11). The signed head would otherwise vouch
    // for attacker JSON.
    let previous = '0'.repeat(64);
    const deadAt = this._auditKeyDeaths(tenant);
    const rows = this._schemaGuard(() => this._stmt('SELECT seq,previous,hash,envelope FROM audit WHERE tenant=? ORDER BY seq').all(tenant)).map(r => {
      let envelope;
      try { envelope = JSON.parse(r.envelope); }
      catch { throw new InvariantError('INV-409-AUDIT-TAMPER', 'Audit row failed integrity verification', 409); }
      requireThat(envelope.payload !== undefined && ctEqual(digest(envelope.payload), r.hash) && envelope.payload.sequence === r.seq && ctEqual(envelope.payload.previous, previous) && r.previous === previous, 'INV-409-AUDIT-TAMPER', 'Audit row failed integrity verification', 409);
      try { verifySigned(envelope, public_keys, 'audit'); }
      catch { throw new InvariantError('INV-409-AUDIT-TAMPER', 'Audit row failed signature verification', 409); }
      // The signed payload must attest THIS tenant's row — a validly
      // signed foreign-tenant envelope keyed under this tenant is still
      // tamper evidence (w21-store F-8).
      requireThat(envelope.payload.tenant_id === tenant, 'INV-409-AUDIT-TAMPER', 'Audit row attests a different tenant', 409);
      // Rows sequenced after their signer's ledger death cannot be
      // legitimate — a revoked/rotated-out key attesting later history is
      // replay, not authority (w28-crypto F2).
      const deadSeq = deadAt.get(envelope.protected?.key_id);
      requireThat(!(deadSeq !== undefined && r.seq > deadSeq), 'INV-409-AUDIT-TAMPER', 'Audit row signed by a key past its ledger death', 409);
      previous = r.hash;
      return { hash: r.hash, envelope };
    });
    const checkpoint = signer.sign({ tenant_id: tenant, size: rows.length, head: rows.at(-1)?.hash ?? '0'.repeat(64), tree_head: merkleRoot(rows.map(r => r.hash)) }, 'checkpoint');
    // Witness checkpoints (store-audit HIGH-2): the previous export's signed
    // checkpoint travels in the bundle, so amputating or rewriting a suffix of
    // the log after an export breaks verification instead of self-certifying.
    // A file-level attacker can still delete the stored witness too — a truly
    // pinned anchor requires an external copy of a checkpoint, which
    // verifyAudit(priorCheckpoint) accepts; this closes the common case.
    const priorRow = this._schemaGuard(() => this._stmt("SELECT id,value FROM records WHERE tenant=? AND kind='audit-checkpoint' ORDER BY created DESC LIMIT 1").get(tenant));
    const prior_checkpoint = priorRow ? this.readValue(tenant, 'audit-checkpoint', priorRow.id, priorRow.value) : null;
    if (now !== null) this.put(tenant, 'audit-checkpoint', `cp-${checkpoint.payload.size}`, checkpoint, now);
    return { format: 'IF-AUDIT-1', public_keys, prior_checkpoint, checkpoint, entries: rows };
  }
  idempotent(tenant, scope, key, requestHash, fn, { project = null, resolve = null } = {}) {
    // SELECT-then-INSERT is atomic only inside a transaction — refuse to run
    // outside one rather than silently depending on the caller (L4).
    requireThat(this.db.isTransaction, 'INV-500-STORE', 'idempotent() must run inside store.tx()', 500);
    requireThat(typeof key === 'string' && /^[A-Za-z0-9_-]{8,128}$/.test(key), 'INV-400-SCHEMA', 'An 8–128 character Idempotency-Key is required');
    const row = this._stmt('SELECT hash,result FROM idempotency WHERE tenant=? AND scope=? AND key=?').get(tenant, scope, key);
    if (row) {
      requireThat(ctEqual(row.hash, requestHash), 'INV-409-IDEMPOTENCY', 'Idempotency key reused for a different request', 409);
      // A corrupt or transplanted receipt surfaces in the ledger taxonomy,
      // not as a raw cipher/TypeError (w22-fixverify F9).
      let stored;
      try { stored = decrypt(row.result, this.key(tenant), idemAad(tenant, scope, key)); }
      catch (e) { throw new InvariantError('INV-409-INTEGRITY', 'Stored idempotency receipt failed integrity', 409, { cause: e }); }
      return resolve ? resolve(stored) : stored;
    }
    const result = fn();
    // The receipt may carry a redacted projection — callers that want the
    // stored value minimal (shredder-safe) pass project/resolve; without
    // them the full result is receipt+response as before (w28-crypto F1).
    this._landed(() => this._stmt('INSERT INTO idempotency VALUES(?,?,?,?,?)').run(tenant, scope, key, requestHash, encrypt(project ? project(result) : result, this.key(tenant), idemAad(tenant, scope, key))), 'idempotency receipt');
    return result;
  }
}
export function verifyAudit(bundle, pinnedKeys, priorCheckpoint = null) {
  requireThat(bundle.format === 'IF-AUDIT-1' && Array.isArray(bundle.entries), 'INV-400-AUDIT', 'Unsupported audit format');
  const checkpoint = verifySigned(bundle.checkpoint, pinnedKeys, 'checkpoint');
  // A stored witness from a previous export acts as the pin when the caller
  // supplies none — verify it under the same keys before trusting it.
  const prior = priorCheckpoint ?? (bundle.prior_checkpoint ? verifySigned(bundle.prior_checkpoint, pinnedKeys, 'checkpoint') : null);
  let previous = '0'.repeat(64), sequence = 0, time = 0;
  // The signer-death window the fabric fold enforces must hold for the
  // standalone verifier too: revocation/rotation events inside the bundle
  // bound which key may attest which sequence (w28-crypto F2).
  const deadAt = new Map(), signedSeqs = [];
  for (const item of bundle.entries) {
    const entry = verifySigned(item.envelope, pinnedKeys, 'audit');
    requireThat(entry.tenant_id === checkpoint.tenant_id && entry.sequence === ++sequence && ctEqual(entry.previous, previous) && entry.time >= time && ctEqual(digest(entry), item.hash), 'INV-409-AUDIT', 'Audit continuity failure', 409);
    const meta = entry.metadata;
    // Earliest death wins — last-write-wins would let a later duplicate
    // death extend the signing window (w34-fixverify L-3).
    if (entry.type === 'AUTHORITY_REVOKED' && typeof entry.reference === 'string' && entry.reference.startsWith('key:')) deadAt.set(entry.reference.slice(4), Math.min(deadAt.get(entry.reference.slice(4)) ?? Infinity, entry.sequence));
    if (entry.type === 'KEY_ROTATED' && meta?.key_class === 'audit' && typeof meta?.previous_key_id === 'string') deadAt.set(meta.previous_key_id, Math.min(deadAt.get(meta.previous_key_id) ?? Infinity, entry.sequence));
    // Sealed carryover unfolds the same as _auditKeyDeaths — a 'key:' ref
    // carried by AUDIT_SEALED/AUDIT_SEAL_CARRY kills the key at the carrying
    // row (w33-export F2 parity).
    if (entry.type === 'AUDIT_SEALED' || entry.type === 'AUDIT_SEAL_CARRY') {
      // Carried deaths pin at the death's ORIGINAL position (orig_seq),
      // never the carrying row's seq — standalone verification must apply
      // the same death window the fold does, or a bundle row signed inside
      // the carried window verifies here while the fold refuses it
      // (w48-crypto F-w48-1). floor_derived claims are exempt — they pin
      // no death, same as the fold (w48-crypto F-w48-2).
      for (const rv of Array.isArray(meta?.revocations_carryover) ? meta.revocations_carryover : [])
        if (rv?.floor_derived !== true && typeof rv?.reference === 'string' && rv.reference.startsWith('key:'))
          deadAt.set(rv.reference.slice(4), Math.min(deadAt.get(rv.reference.slice(4)) ?? Infinity, typeof rv.orig_seq === 'number' ? rv.orig_seq : entry.sequence));
      // Carried audit-class rotations pin the predecessor's death at its
      // original position too — lifecycle_carryover parity with the
      // fold's replay (w34, w48-crypto F-w48-1).
      for (const lc of Array.isArray(meta?.lifecycle_carryover) ? meta.lifecycle_carryover : [])
        if (lc?.type === 'KEY_ROTATED' && lc?.metadata?.key_class === 'audit' && typeof lc.metadata.previous_key_id === 'string')
          deadAt.set(lc.metadata.previous_key_id, Math.min(deadAt.get(lc.metadata.previous_key_id) ?? Infinity, typeof lc.orig_seq === 'number' ? lc.orig_seq : entry.sequence));
    }
    signedSeqs.push([entry.sequence, item.envelope?.protected?.key_id]);
    previous = item.hash; time = entry.time;
    if (prior && sequence === prior.size) requireThat(ctEqual(previous, prior.head), 'INV-409-FORK', 'Witness checkpoint disagrees', 409);
  }
  for (const [seq, kid] of signedSeqs) {
    const dead = deadAt.get(kid);
    requireThat(!(dead !== undefined && seq > dead), 'INV-409-AUDIT', 'Audit entry signed by a key past its ledger death', 409);
  }
  requireThat(checkpoint.size === sequence && ctEqual(checkpoint.head, previous) && (!prior || (checkpoint.tenant_id === prior.tenant_id && sequence >= prior.size)), 'INV-409-AUDIT', 'Missing or inconsistent checkpoint', 409);
  // The signed tree_head anchors the entry set under the Merkle root —
  // recompute it rather than trusting the attested value (crypto-audit I-1).
  requireThat(ctEqual(checkpoint.tree_head, merkleRoot(bundle.entries.map(i => i.hash))), 'INV-409-AUDIT', 'Checkpoint tree head does not match the audit entries', 409);
  return { valid: true, entries: sequence, head: previous, tenant_id: checkpoint.tenant_id };
}

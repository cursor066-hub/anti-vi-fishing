import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, chmodSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import { encrypt, decrypt, verifySigned, ctEqual } from './crypto.mjs';
import { merkleRoot } from './merkle.mjs';
import { canonical, digest } from './canonical.mjs';
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


export class Store {
  constructor(path, tenantKeys, auditSigners, { aadDedup } = {}) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    // A hostile or foreign file must surface inside the ledger taxonomy
    // from the first touch — a raw ERR_SQLITE_ERROR here is a tamper no
    // INV-* alert can see (w30-store F2).
    try { this.db = new DatabaseSync(path); } catch (e) { throw new InvariantError('INV-503-STORAGE', 'Ledger file is unreadable or not a database', 503, { cause: e }); }
    chmodSync(path, 0o600);
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
      const version = this.db.prepare('PRAGMA user_version').get().user_version;
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
    const dead = new Map();
    for (const row of this.db.prepare("SELECT seq,envelope FROM audit WHERE tenant=? AND (envelope LIKE '%\"type\":\"AUTHORITY_REVOKED\"%' OR envelope LIKE '%\"type\":\"KEY_ROTATED\"%')").all(tenant)) {
      let env; try { env = JSON.parse(row.envelope); } catch { continue; }
      const pl = env?.payload, meta = pl?.metadata;
      if (pl?.type === 'AUTHORITY_REVOKED' && meta?.kind === 'key' && typeof meta.id === 'string') dead.set(meta.id, row.seq);
      if (pl?.type === 'KEY_ROTATED' && meta?.key_class === 'audit' && typeof meta?.previous_key_id === 'string') dead.set(meta.previous_key_id, row.seq);
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
    ];
    const norm = s => (s ?? '').replace(/\s+/g, ' ').trim();
    for (const [name, sql] of guards) this.db.exec(`CREATE TRIGGER IF NOT EXISTS ${sql.slice('CREATE TRIGGER '.length)}`);
    // Text check: the STORED body must equal our literal — feature tests
    // (WHEN present, RAISE literal) are evadable by WHERE-gated bodies
    // (w21-store F-1).
    const triggers = new Map(this.db.prepare("SELECT name, sql FROM sqlite_master WHERE type='trigger'").all().map(x => [x.name, x.sql ?? '']));
    for (const [name, sql] of guards)
      if (norm(triggers.get(name)) !== norm(sql)) throw new InvariantError('INV-503-STORAGE', `integrity trigger missing or tampered: ${name}`, 503);
    // Enumeration, not just existence: a file-writer can plant EXTRA
    // triggers whose names or bodies smuggle SQL into our own privileged
    // paths (DROP TRIGGER batch, the seal's delete pass, or any ordinary
    // write that fires the payload). Anything not in the known guard set
    // is removed at open — quoted, never interpolated (w28-store F1).
    const knownTriggers = new Set(guards.map(([name]) => name));
    for (const stray of this.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger'").all().map(r => r.name).filter(n => !knownTriggers.has(n))) {
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
    const insAudit = seq => this.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run(pt, seq, 'x', 'x', '{}');
    requireThat(probe(() => { insAudit(1); this.db.prepare('UPDATE audit SET hash=? WHERE tenant=?').run('y', pt); }, 'append-only audit'), 'INV-503-STORAGE', 'Audit append-only UPDATE trigger not enforced', 503);
    requireThat(probe(() => { insAudit(1); this.db.prepare('DELETE FROM audit WHERE tenant=?').run(pt); }, 'append-only audit'), 'INV-503-STORAGE', 'Audit append-only DELETE trigger not enforced', 503);
    requireThat(probe(() => insAudit(7), 'audit sequence must extend the head'), 'INV-503-STORAGE', 'Audit sequence guard not enforced', 503);
    for (const [table, msg] of [['nonces', 'append-only nonces'], ['idempotency', 'append-only idempotency'], ['data_access', 'append-only data_access']]) {
      const ins = { nonces: () => this.db.prepare('INSERT INTO nonces VALUES(?,?,?)').run(pt, 'n', 'c'),
        idempotency: () => this.db.prepare('INSERT INTO idempotency VALUES(?,?,?,?,?)').run(pt, 's', 'k', 'h', 'r'),
        data_access: () => this.db.prepare('INSERT INTO data_access VALUES(?,?,?,?,?,?)').run(pt, 's', 'd', 'r', 'c', 0) }[table];
      const col = { nonces: 'capsule', idempotency: 'result', data_access: 'subject' }[table];
      requireThat(probe(() => { ins(); this.db.prepare(`UPDATE ${table} SET ${col}=? WHERE tenant=?`).run('y', pt); }, msg), 'INV-503-STORAGE', `${table} append-only UPDATE trigger not enforced`, 503);
      requireThat(probe(() => { ins(); this.db.prepare(`DELETE FROM ${table} WHERE tenant=?`).run(pt); }, msg), 'INV-503-STORAGE', `${table} append-only DELETE trigger not enforced`, 503);
    }
    requireThat(probe(() => { this.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?)').run(pt, 's', 'r', 0, 0, 'c', 'q'); this.db.prepare('DELETE FROM usage WHERE tenant=?').run(pt); }, 'append-only usage'), 'INV-503-STORAGE', 'usage append-only DELETE trigger not enforced', 503);
    requireThat(probe(() => { this.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?)').run(pt, 's', 'r', 100, 5, 'c', 'q'); this.db.prepare('UPDATE usage SET cost=? WHERE tenant=?').run(4, pt); }, 'usage is monotone'), 'INV-503-STORAGE', 'usage monotone UPDATE trigger not enforced', 503);
    // INSERT OR IGNORE seeds when absent without firing the delete guard on
    // an existing row; `last=last-1` is a backward write on any live value.
    requireThat(probe(() => { this.db.prepare('INSERT OR IGNORE INTO clock VALUES(1,100)').run(); this.db.prepare('DELETE FROM clock WHERE id=1').run(); }, 'clock is monotone'), 'INV-503-STORAGE', 'clock delete trigger not enforced', 503);
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
    for (const row of this.db.prepare('SELECT tenant,envelope FROM audit ORDER BY rowid DESC LIMIT 64').all()) {
      try {
        const env = JSON.parse(row.envelope);
        const signer = this._signer(row.tenant), pub = signer.keys ? signer.keys() : { [signer.key_id]: { public_key: signer.public_key } };
        verifySigned(env, pub, 'audit');
        const t = env?.payload?.time;
        if (typeof t === 'number' && Number.isFinite(t)) { this._chainFloor = t; floorSeeded = true; break; }
      } catch { /* forged or unverifiable tail row — keep walking back */ }
    }
    requireThat(floorSeeded || this.db.prepare('SELECT COUNT(*) n FROM audit').get().n === 0, 'INV-409-AUDIT-TAMPER', 'Audit tail carries no verifiable entry — ledger tamper', 409);
    for (const row of this.db.prepare("SELECT tenant,envelope FROM audit WHERE envelope LIKE '%\"type\":\"CLOCK_RECOVERED\"%' ORDER BY rowid DESC LIMIT 512").all()) {
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
    const seedRow = this.db.prepare('SELECT last FROM clock WHERE id=1').get();
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
      for (const r of this.db.prepare('SELECT tenant,kind,id,wrapped FROM deks').all()) {
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
          const upd = this.db.prepare('UPDATE deks SET wrapped=? WHERE tenant=? AND kind=? AND id=?'), orig = r.wrapped;
          seen.set(orig, { db: this.db, revert: () => { upd.run(orig, r.tenant, r.kind, r.id); this._shredded = true; }, unmark: () => unmark(r.tenant) });
          upd.run(encrypt(bare, master(r.tenant), dekAad(r.tenant, r.kind, r.id)), r.tenant, r.kind, r.id);
          mark(r.tenant, 'migrated');
        } catch { mark(r.tenant, 'skipped'); }
      }
      const recs = this.db.prepare('SELECT tenant,kind,id,value FROM records').all();
      const dekRow = this.db.prepare('SELECT wrapped FROM deks WHERE tenant=? AND kind=? AND id=?');
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
          const upd = this.db.prepare('UPDATE records SET value=? WHERE tenant=? AND kind=? AND id=?'), orig = r.value;
          seen.set(orig, { db: this.db, revert: () => { upd.run(orig, r.tenant, r.kind, r.id); this._shredded = true; }, unmark: () => unmark(r.tenant) });
          upd.run(encrypt(plain, key, recAad(r.tenant, r.kind, r.id)), r.tenant, r.kind, r.id);
          mark(r.tenant, 'migrated');
        } catch { mark(r.tenant, 'skipped'); }
      }
      for (const r of this.db.prepare('SELECT tenant,scope,key,result FROM idempotency').all()) {
        try { decrypt(r.result, master(r.tenant), idemAad(r.tenant, r.scope, r.key)); continue; } catch { /* legacy-sealed or corrupt */ }
        const prior = seen.get(r.result);
        if (prior) { if (prior.db === this.db) { prior.revert?.(); prior.unmark?.(); } mark(r.tenant, 'transplants'); continue; }
        if (slashy(r.tenant, r.scope, r.key)) { seen.set(r.result, {}); mark(r.tenant, 'ambiguous'); continue; }
        try {
          const plain = decrypt(r.result, master(r.tenant), `${r.tenant}/idempotency/${r.scope}/${r.key}`);
          const upd = this.db.prepare('UPDATE idempotency SET result=? WHERE tenant=? AND scope=? AND key=?'), orig = r.result;
          seen.set(orig, { db: this.db, revert: () => { upd.run(orig, r.tenant, r.scope, r.key); this._shredded = true; }, unmark: () => unmark(r.tenant) });
          upd.run(encrypt(plain, master(r.tenant), idemAad(r.tenant, r.scope, r.key)), r.tenant, r.scope, r.key);
          mark(r.tenant, 'migrated');
        } catch { mark(r.tenant, 'skipped'); }
      }
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
        const result = fn();
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
      const result = fn();
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
    const row = this.db.prepare('SELECT wrapped FROM deks WHERE tenant=? AND kind=? AND id=?').get(tenant, kind, id);
    return row ? Buffer.from(decrypt(row.wrapped, this.key(tenant), dekAad(tenant, kind, id)), 'base64url') : null;
  }
  // Non-string addressing coerces at the SQL layer (TEXT affinity makes
  // id=5 match id='5') — the write side must not address rows the
  // string-guarded put() would have refused (w21-store F-11).
  _addr(tenant, kind, id) {
    requireThat(typeof tenant === 'string' && typeof kind === 'string' && typeof id === 'string', 'INV-400-SCHEMA', 'Store keys must be strings', 400);
  }
  get(tenant, kind, id) {
    this._addr(tenant, kind, id);
    const row = this.db.prepare('SELECT value FROM records WHERE tenant=? AND kind=? AND id=?').get(tenant, kind, id);
    if (!row) return null;
    // Records written before per-record DEKs fall back to the tenant key.
    return this.readValue(tenant, kind, id, row.value);
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
    if (this.db.prepare('SELECT 1 FROM records WHERE tenant=? AND kind=? AND id=?').get(tenant, kind, id)
      || this.db.prepare('SELECT 1 FROM deks WHERE tenant=? AND kind=? AND id=?').get(tenant, kind, id)) this._shredded = true;
    const dek = randomBytes(32);
    // The record+DEK pair must land atomically — a bare-autocommit crash
    // between them leaves a ciphertext with no key that then reads as
    // INV-409 'tamper' instead of a crash artifact (w28-store F8).
    const pair = () => {
      this.db.prepare('INSERT INTO records VALUES(?,?,?,?,?) ON CONFLICT(tenant,kind,id) DO UPDATE SET value=excluded.value').run(tenant, kind, id, encrypt(value, dek, recAad(tenant, kind, id)), at);
      this.db.prepare('INSERT INTO deks VALUES(?,?,?,?) ON CONFLICT(tenant,kind,id) DO UPDATE SET wrapped=excluded.wrapped').run(tenant, kind, id, encrypt(dek.toString('base64url'), this.key(tenant), dekAad(tenant, kind, id)));
    };
    if (this.db.isTransaction) pair(); else this.tx(pair);
    if (!this.db.isTransaction) this.checkpoint();
  }
  insert(tenant, kind, id, value, at) {
    requireThat(!this.get(tenant, kind, id), 'INV-409-CONFLICT', 'Record already exists', 409); this.put(tenant, kind, id, value, at);
  }
  list(tenant, kind, limit = 500, offset = 0) {
    return this.db.prepare('SELECT id,value FROM records WHERE tenant=? AND kind=? ORDER BY created DESC,id LIMIT ? OFFSET ?').all(tenant, kind, limit, offset)
      .map(row => this.readValue(tenant, kind, row.id, row.value));
  }
  // Id-only enumeration: sweeps must not let one undecryptable row wedge the
  // whole pass (store-audit MED-3) — callers isolate failures per id.
  ids(tenant, kind, limit = 500, offset = 0) {
    return this.db.prepare('SELECT id FROM records WHERE tenant=? AND kind=? ORDER BY created DESC,id LIMIT ? OFFSET ?').all(tenant, kind, limit, offset).map(r => r.id);
  }
  remove(tenant, kind, id) {
    this._addr(tenant, kind, id);
    this._shredded = true;
    // The DEK+record delete pair must land or roll back together — a crash
    // between them leaves a dekless row that wedges the revocation floor
    // probe as fake tamper evidence (w32-store F5).
    const pair = () => {
      this.db.prepare('DELETE FROM deks WHERE tenant=? AND kind=? AND id=?').run(tenant, kind, id);
      this.db.prepare('DELETE FROM records WHERE tenant=? AND kind=? AND id=?').run(tenant, kind, id);
    };
    if (this.db.isTransaction) pair(); else this.tx(pair);
    if (!this.db.isTransaction) this.checkpoint(); // non-tx paths must not leave the DEK in the WAL (store-audit LOW)
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
    const pair = () => this.db.prepare('DELETE FROM deks WHERE tenant=? AND kind=? AND id=?').run(tenant, kind, id).changes
      + this.db.prepare('DELETE FROM records WHERE tenant=? AND kind=? AND id=?').run(tenant, kind, id).changes;
    const changes = this.db.isTransaction ? pair() : this.tx(pair);
    this._shredded = this._shredded || changes > 0;
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
      const r = this.db.prepare('PRAGMA wal_checkpoint(TRUNCATE)').get();
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
    const newest = this.db.prepare('SELECT tenant,envelope FROM audit ORDER BY rowid DESC LIMIT 1').get();
    if (newest && newest.envelope !== this._anchorScanned) {
      this._anchorScanned = newest.envelope;
      try {
        const env = JSON.parse(newest.envelope);
        const signer = this._signer(newest.tenant), pub = signer.keys ? signer.keys() : { [signer.key_id]: { public_key: signer.public_key } };
        verifySigned(env, pub, 'audit');
        if (typeof env?.payload?.time === 'number' && Number.isFinite(env.payload.time) && env.payload.time > (this._chainFloor ?? 0)) this._chainFloor = env.payload.time;
      } catch { /* unverifiable head — floor holds its last attested value */ }
    }
    for (const row of this.db.prepare("SELECT tenant,envelope FROM audit WHERE envelope LIKE '%\"type\":\"CLOCK_RECOVERED\"%' ORDER BY rowid DESC LIMIT 512").all()) {
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
    const row = this.db.prepare('SELECT last FROM clock WHERE id=1').get();
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
    this.db.prepare('INSERT INTO clock VALUES(1,?) ON CONFLICT(id) DO UPDATE SET last=excluded.last').run(now);
    return now;
  }
  auditHeadSeq(tenant) {
    return this.db.prepare('SELECT COALESCE(MAX(seq),0) s FROM audit WHERE tenant=?').get(tenant).s;
  }
  audit(tenant, type, actor, reference, metadata, now) {
    // Entry + clock-ratchet must commit together: outside a transaction a
    // crash (or SQLITE_BUSY) between them leaves clock.last below the
    // chain floor and the NEXT OPEN bricks on INV-409-AUDIT-TAMPER with no
    // in-band recovery (w28-store F2). Inside a tx the caller's boundary
    // already covers the pair.
    if (!this.db.isTransaction) return this.tx(() => this.audit(tenant, type, actor, reference, metadata, now));
    const last = this.db.prepare('SELECT seq,hash,envelope FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get(tenant);
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
    const entry = { tenant_id: tenant, sequence: (last?.seq ?? 0) + 1, previous: last?.hash ?? '0'.repeat(64), type, actor, reference, metadata, time: Math.max(now, priorTime) };
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
    const crow = this.db.prepare('SELECT last FROM clock WHERE id=1').get();
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
      if (!this._verifiedHeads.has(last.hash)) {
        const pub = signer.keys ? signer.keys() : { [signer.key_id]: { public_key: signer.public_key } };
        try { verifySigned(JSON.parse(last.envelope), pub, 'audit'); } catch (e) { throw new InvariantError('INV-409-AUDIT-TAMPER', 'Audit head does not verify — ledger tamper', 409, { cause: e }); }
        if (this._verifiedHeads.size >= 64) this._verifiedHeads.clear();
        this._verifiedHeads.set(last.hash, true);
      }
    }
    const envelope = signer.sign(entry);
    const hash = digest(envelope.payload);
    try {
      this.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run(tenant, entry.sequence, entry.previous, hash, canonical(envelope));
    } catch (e) {
      // A peer instance appending between our head-read and this insert
      // trips the seq guard — that is a retryable conflict, not tamper
      // and not raw sqlite internals leaking to callers (w23 W23-09).
      // errcode 517 = SQLITE_BUSY_SNAPSHOT: a deferred reader's snapshot
      // went stale under a peer write — same retry semantics as busy.
      if (e?.errcode === 5 || e?.errcode === 6 || e?.errcode === 517 || /database .*locked|database is busy/i.test(e?.message ?? '')) throw new InvariantError('INV-503-LEDGER', 'Ledger writer contention exceeded the wait bound; retry', 503);
      if (/audit sequence must extend the head/.test(e?.message ?? '')) throw new InvariantError('INV-409-CONFLICT', 'Audit head moved during append; retry', 409);
      throw e;
    }
    // Post-commit ordering: only a landed entry may move the anchors and
    // ratchet the detector (w23 W23-05). Our own head is the newest
    // verifiable row — mark it scanned so a later refresh skips it.
    this._anchorScanned = canonical(envelope);
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
    this.db.prepare('INSERT INTO clock VALUES(1,?) ON CONFLICT(id) DO UPDATE SET last=MAX(clock.last, excluded.last)').run(now);
    // End-of-chain commitment: the fabric moves its signed head watermark
    // post-commit — a truncated tail can never drag the watermark back
    // with it (w24-fixverify W24-01).
    this.onAuditAppend?.(tenant, entry.sequence, hash);
    return { hash, envelope };
  }
  auditHashes(tenant) {
    return this.db.prepare('SELECT hash FROM audit WHERE tenant=? ORDER BY seq').all(tenant).map(r => r.hash);
  }
  auditPage(tenant, { after = 0, limit = 1000 } = {}) {
    // Cursor hygiene: limit=0 would crash on rows.at(-1), a negative limit
    // turns into an UNBOUNDED sqlite read (LIMIT -1 = no bound), and a
    // negative cursor silently anchors wrong — classify all of it as a
    // schema fault before the query runs. Any positive limit is honoured:
    // the internal index fold legitimately pages through the entire chain
    // (w23 W23-08).
    requireThat(Number.isSafeInteger(after) && after >= 0 && Number.isSafeInteger(limit) && limit >= 1, 'INV-400-SCHEMA', 'Invalid audit cursor or limit', 400);
    const rows = this.db.prepare('SELECT seq,hash,envelope FROM audit WHERE tenant=? AND seq>? ORDER BY seq LIMIT ?').all(tenant, after, limit);
    const signer = this._signer(tenant), public_keys = signer.keys ? signer.keys() : { [signer.key_id]: { public_key: signer.public_key } };
    // Serving the log is a security surface: re-verify each row's stored
    // hash against its signed payload and check chain continuity back to the
    // row preceding the page — an injected or rewritten row cannot pass
    // (store-audit MED-5).
    const anchor = after ? this.db.prepare('SELECT hash FROM audit WHERE tenant=? AND seq=?').get(tenant, after) : null;
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
      requireThat(envelope.payload !== undefined && ctEqual(digest(envelope.payload), r.hash) && envelope.payload.sequence === r.seq && ctEqual(envelope.payload.previous, previous), 'INV-409-AUDIT-TAMPER', 'Audit row failed integrity verification', 409);
      // Hash+previous are attacker-computable (the seq trigger permits a raw
      // MAX+1 append): without signature verification the read path would
      // serve an unsigned forged row as a legitimate chain entry (w15).
      try { verifySigned(envelope, public_keys, 'audit'); }
      catch { throw new InvariantError('INV-409-AUDIT-TAMPER', 'Audit row failed signature verification', 409); }
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
    const rows = this.db.prepare('SELECT seq,hash,envelope FROM audit WHERE tenant=? ORDER BY seq').all(tenant).map(r => {
      let envelope;
      try { envelope = JSON.parse(r.envelope); }
      catch { throw new InvariantError('INV-409-AUDIT-TAMPER', 'Audit row failed integrity verification', 409); }
      requireThat(envelope.payload !== undefined && ctEqual(digest(envelope.payload), r.hash) && envelope.payload.sequence === r.seq && ctEqual(envelope.payload.previous, previous), 'INV-409-AUDIT-TAMPER', 'Audit row failed integrity verification', 409);
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
    const priorRow = this.db.prepare("SELECT id,value FROM records WHERE tenant=? AND kind='audit-checkpoint' ORDER BY created DESC LIMIT 1").get(tenant);
    const prior_checkpoint = priorRow ? this.readValue(tenant, 'audit-checkpoint', priorRow.id, priorRow.value) : null;
    if (now !== null) this.put(tenant, 'audit-checkpoint', `cp-${checkpoint.payload.size}`, checkpoint, now);
    return { format: 'IF-AUDIT-1', public_keys, prior_checkpoint, checkpoint, entries: rows };
  }
  idempotent(tenant, scope, key, requestHash, fn, { project = null, resolve = null } = {}) {
    // SELECT-then-INSERT is atomic only inside a transaction — refuse to run
    // outside one rather than silently depending on the caller (L4).
    requireThat(this.db.isTransaction, 'INV-500-STORE', 'idempotent() must run inside store.tx()', 500);
    requireThat(typeof key === 'string' && /^[A-Za-z0-9_-]{8,128}$/.test(key), 'INV-400-SCHEMA', 'An 8–128 character Idempotency-Key is required');
    const row = this.db.prepare('SELECT hash,result FROM idempotency WHERE tenant=? AND scope=? AND key=?').get(tenant, scope, key);
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
    this.db.prepare('INSERT INTO idempotency VALUES(?,?,?,?,?)').run(tenant, scope, key, requestHash, encrypt(project ? project(result) : result, this.key(tenant), idemAad(tenant, scope, key)));
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
    if (entry.type === 'AUTHORITY_REVOKED' && meta?.kind === 'key' && typeof meta.id === 'string') deadAt.set(meta.id, entry.sequence);
    if (entry.type === 'KEY_ROTATED' && meta?.key_class === 'audit' && typeof meta?.previous_key_id === 'string') deadAt.set(meta.previous_key_id, entry.sequence);
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

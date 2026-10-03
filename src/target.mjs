import { DatabaseSync } from 'node:sqlite';
import { dirname } from 'node:path';
import { mkdirSync, chmodSync } from 'node:fs';
import { digest, clone, canonical, hashBytes } from './canonical.mjs';
import { encrypt, decrypt } from './crypto.mjs';
import { buildPlan, verifyPlan, executePlan } from './datagate.mjs';
import { requireThat, InvariantError } from './errors.mjs';
import { randomBytes } from 'node:crypto';

// Controlled target simulator. It NEVER talks to a real bank, ERP, OS, or
// cloud. Resources and dataset rows live in real tables with per-tenant AES-256-GCM
// at rest; dataset reads go through the verified query plan (IF-DATA-1) — no
// caller text ever reaches SQL.
// Tuple AADs joined by canonical(): a slash-joined AAD collides if any
// identifier ever admits '/' — 'a/b'+'c' vs 'a'+'b/c' encrypt the same
// context. Writes use the tuple form; the legacy slash space was migrated
// away at open and is dead thereafter — a live fallback IS the transplant
// surface (w18-crypto F1/F2, uniform closure).
const AAD = (...parts) => canonical(parts);
export class SimulatedTarget {
  _dec(value, tenant, tuple) {
    // Plaintext memo keyed on (tuple AAD, ciphertext): an unchanged row
    // serves an identical object without re-running GCM, a grafted or
    // transplanted value changes the key and re-derives through the
    // authenticating decrypt — every miss still classifies inside the
    // INV-409 taxonomy exactly like before (w47-perf). Hits hand out a
    // private clone; the memo copy is never exposed to callers.
    const mk = `${tenant}|${tuple}|${hashBytes(value)}`;
    const mem = this._decMemo ??= new Map();
    const hit = mem.get(mk);
    if (hit !== undefined) return structuredClone(hit);
    // A corrupted ciphertext is tamper evidence, not a code crash — every
    // decrypt failure classifies in the ledger taxonomy (w21-store F-7).
    const plain = (() => {
      try { return decrypt(value, this.key(tenant), tuple); }
      catch (e) { throw new InvariantError('INV-409-INTEGRITY', 'Stored ciphertext does not authenticate', 409); }
    })();
    if (mem.size >= 1024) mem.delete(mem.keys().next().value);
    mem.set(mk, structuredClone(plain));
    return plain;
  }
  constructor(path, tenantKeys, { aadDedup } = {}) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    // A hostile or foreign file must surface inside the ledger taxonomy
    // from the first touch — a raw ERR_SQLITE_ERROR here is a tamper no
    // INV-* alert can see (w31-fixverify F2, mirrors the store gate).
    try { this.db = new DatabaseSync(path); } catch (e) { throw new InvariantError('INV-503-STORAGE', 'Target ledger file is unreadable or not a database', 503, { cause: e }); }
    chmodSync(path, 0o600); this.keys = tenantKeys;
    // Shared with the ledger store — the same ciphertext must never mint
    // canonical bindings on both sides of a cross-DB graft (w19-aad W19-1).
    this._aadDedup = aadDedup ?? new Map();
    this._sp = 0; // savepoint counter for nested tx() (w21-store F-3)
    // Same contention contract as the ledger store: constructor writes lose
    // a busy-timeout race as INV-503-LEDGER, never a raw sqlite error
    // (w20-fixverify F-12).
    try {
      // user_version stamps the schema like the ledger store does: a
      // file-writer swapping in a foreign sqlite database is caught by the
      // version marker before any encrypted row is trusted (w28-store F10).
      // The marker must be READ before it is re-stamped — stamping alone
      // silently adopts any foreign file (w29-fixverify F9).
      this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=30000; PRAGMA secure_delete=ON;');
      const version = this._stmt('PRAGMA user_version').get().user_version;
      requireThat(version <= 1, 'INV-503-STORAGE', 'Database schema is newer than this application', 503);
      // The data_access disclosure log lives in the ledger store — every
      // reconstructionCheck touchDb is store.db; a shadow table here was
      // dead schema (w38-runtime L-3). Existing files may still carry the
      // empty table — it is simply unused.
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS resources(tenant TEXT, id TEXT, version INTEGER, value TEXT, PRIMARY KEY(tenant,id));
        CREATE TABLE IF NOT EXISTS transactions(tenant TEXT,id TEXT,value TEXT,PRIMARY KEY(tenant,id));
        CREATE TABLE IF NOT EXISTS dataset_rows(tenant TEXT, dataset TEXT, row_id TEXT, data TEXT, PRIMARY KEY(tenant,dataset,row_id));
        CREATE TABLE IF NOT EXISTS secrets_registry(tenant TEXT, secret_id TEXT, version INTEGER, value TEXT, PRIMARY KEY(tenant,secret_id));
        CREATE TABLE IF NOT EXISTS grants(tenant TEXT, grant_id TEXT, value TEXT, PRIMARY KEY(tenant,grant_id));
        CREATE TABLE IF NOT EXISTS meta_kv (tenant TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(tenant,key));
        CREATE INDEX IF NOT EXISTS grants_subject ON grants(tenant);
        PRAGMA user_version=1;`);
      // Crash residue: a post-delete checkpoint that never ran leaves superseded
      // ciphertext in the WAL — truncate at open like the ledger store does
      // (w8-fixverify F3).
      this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    } catch (e) {
      if (e instanceof InvariantError) throw e;
      if (e?.errcode === 5 || e?.errcode === 6 || /database .*locked/i.test(e?.message ?? '')) throw new InvariantError('INV-503-LEDGER', 'Ledger writer contention exceeded the wait bound; retry', 503);
      if (/readonly|not authorized/i.test(e?.message ?? '')) throw new InvariantError('INV-503-STORAGE', 'Target database file is not writable', 503);
      // A swapped-in foreign or truncated sqlite file must classify inside
      // the taxonomy, not escape as a raw sqlite error (w31-fixverify F2).
      if (e?.errcode !== undefined || e?.code === 'ERR_SQLITE_ERROR' || /not a database|malformed|no such column|no such table/i.test(e?.message ?? '')) throw new InvariantError('INV-503-STORAGE', 'Target schema is unrecognised — refusing to interpret a foreign or corrupt database', 503, { cause: e });
      throw e;
    }
    // Migration faults get the same classification — a foreign schema's
    // missing column must not leak a raw sqlite error (w31-fixverify F2).
    try { this._migrateAad(); } catch (e) { if (e instanceof InvariantError) throw e; throw new InvariantError('INV-503-STORAGE', 'Target schema is unrecognised — refusing to interpret a foreign or corrupt database', 503, { cause: e }); }
    // The AAD migration marker is the only durable signal between the
    // migration commit and the fabric's attestation — a live delete in the
    // gap silently suppresses the evidence row (w46-store M-2, parity with
    // the ledger store's guard). The sanctioned post-attest cleanup drops
    // and recreates this guard verbatim.
    try {
      // A bare UPDATE rewrites the marker with no delete firing; INSERT
      // OR REPLACE never fires BEFORE DELETE either (recursive_triggers
      // off) — all three arms carry the same abort (w47-fv HIGH-1 +
      // w48-store W48-4, parity with the ledger store).
      const expected = "CREATE TRIGGER aad_marker_keep BEFORE DELETE ON meta_kv WHEN OLD.key='aad_migration' BEGIN SELECT RAISE(ABORT, 'aad migration marker is evidence'); END";
      const expectedUpd = "CREATE TRIGGER aad_marker_keep_upd BEFORE UPDATE ON meta_kv WHEN OLD.key='aad_migration' BEGIN SELECT RAISE(ABORT, 'aad migration marker is evidence'); END";
      const expectedIns = "CREATE TRIGGER aad_marker_keep_ins BEFORE INSERT ON meta_kv WHEN NEW.key='aad_migration' BEGIN SELECT RAISE(ABORT, 'aad migration marker is evidence'); END";
      this.db.exec(`CREATE TRIGGER IF NOT EXISTS ${expected.slice('CREATE TRIGGER '.length)}`);
      this.db.exec(`CREATE TRIGGER IF NOT EXISTS ${expectedUpd.slice('CREATE TRIGGER '.length)}`);
      this.db.exec(`CREATE TRIGGER IF NOT EXISTS ${expectedIns.slice('CREATE TRIGGER '.length)}`);
      const norm = s => (s ?? '').replace(/\s+/g, ' ').trim();
      const stored = new Map(this._stmt("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name IN ('aad_marker_keep','aad_marker_keep_upd','aad_marker_keep_ins')").all().map(r => [r.name, r.sql ?? '']));
      requireThat(norm(stored.get('aad_marker_keep')) === norm(expected), 'INV-503-STORAGE', 'integrity trigger missing or tampered: aad_marker_keep', 503);
      requireThat(norm(stored.get('aad_marker_keep_upd')) === norm(expectedUpd), 'INV-503-STORAGE', 'integrity trigger missing or tampered: aad_marker_keep_upd', 503);
      requireThat(norm(stored.get('aad_marker_keep_ins')) === norm(expectedIns), 'INV-503-STORAGE', 'integrity trigger missing or tampered: aad_marker_keep_ins', 503);
      for (const stray of this._stmt("SELECT name FROM sqlite_master WHERE type='trigger'").all().map(r => r.name).filter(n => !['aad_marker_keep', 'aad_marker_keep_upd', 'aad_marker_keep_ins'].includes(n))) {
        this.db.exec(`DROP TRIGGER "${String(stray).replace(/"/g, '""')}"`);
        (this._strayTriggers ??= []).push(stray);
      }
      const pt = `__integrity_probe__:${randomBytes(8).toString('hex')}`;
      const probeOk = (run) => {
        this.db.exec('SAVEPOINT integrity_probe');
        let ok = false;
        try { run(); } catch (e) {
          if (e?.errcode === 5 || e?.errcode === 6 || /database .*locked/i.test(e?.message ?? '')) throw e;
          if (e?.message === 'aad migration marker is evidence') ok = true;
          else throw new InvariantError('INV-503-STORAGE', `Integrity probe fault: ${e?.message ?? e}`, 503);
        } finally {
          this.db.exec('ROLLBACK TO integrity_probe'); this.db.exec('RELEASE integrity_probe');
        }
        return ok;
      };
      // Seed drops the INSERT arm inside the probe savepoint — the
      // schema change rolls back with it (w48-store W48-4).
      requireThat(probeOk(() => {
        this.db.exec('DROP TRIGGER aad_marker_keep_ins');
        this._stmt("INSERT OR REPLACE INTO meta_kv VALUES(?, 'aad_migration', '{}')").run(pt);
        this._stmt("DELETE FROM meta_kv WHERE tenant=? AND key='aad_migration'").run(pt);
      }), 'INV-503-STORAGE', 'aad_migration marker delete trigger not enforced', 503);
      requireThat(probeOk(() => {
        this.db.exec('DROP TRIGGER aad_marker_keep_ins');
        this._stmt("INSERT OR REPLACE INTO meta_kv VALUES(?, 'aad_migration', '{}')").run(pt);
        this._stmt("UPDATE meta_kv SET value='{}' WHERE tenant=? AND key='aad_migration'").run(pt);
      }), 'INV-503-STORAGE', 'aad_migration marker update trigger not enforced', 503);
      requireThat(probeOk(() => {
        this._stmt("INSERT INTO meta_kv VALUES(?, 'aad_migration', '{}')").run(pt);
      }), 'INV-503-STORAGE', 'aad_migration marker insert trigger not enforced', 503);
      // Counter-arm probe: a BEFORE INSERT RAISE(IGNORE) fires no guard —
      // writes must be proven to LAND (w48-fixverify CRITICAL).
      const probeLanded = (run, what) => {
        this.db.exec('SAVEPOINT integrity_probe');
        try { requireThat(run().changes === 1, 'INV-503-STORAGE', `${what} abandoned — foreign trigger interference`, 503); }
        finally { this.db.exec('ROLLBACK TO integrity_probe'); this.db.exec('RELEASE integrity_probe'); }
      };
      probeLanded(() => this._stmt("INSERT INTO meta_kv VALUES(?, 'integrity_probe', '{}')").run(pt), 'meta_kv insert');
      probeLanded(() => this._stmt('INSERT INTO grants VALUES(?,?,?)').run(pt, 'probe-grant', 'x'), 'grants insert');
      try { this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); } catch { /* contention: next armed write retries */ }
    } catch (e) {
      if (e instanceof InvariantError) throw e;
      if (e?.errcode === 5 || e?.errcode === 6 || /database .*locked/i.test(e?.message ?? '')) throw new InvariantError('INV-503-LEDGER', 'Target writer contention exceeded the wait bound; retry', 503);
      throw e;
    }
  }
  // One-shot migration out of the legacy slash-form AAD space — same shape
  // as the ledger store's migration: each row that only authenticates
  // under the legacy form is re-sealed under its tuple form in one tx, a
  // row authenticating under neither stays sealed and keeps failing on
  // read (w18-crypto F1/F2).
  _migrateAad() {
    const spec = [
      ['resources', 'value', r => [AAD('target', 'resource', r.tenant, r.id), `${r.tenant}/resource/${r.id}`], r => [r.tenant, r.id]],
      ['transactions', 'value', r => [AAD('target', 'transaction', r.tenant, r.id), `${r.tenant}/transaction/${r.id}`], r => [r.tenant, r.id]],
      ['dataset_rows', 'data', r => [AAD('target', 'dataset', r.tenant, r.dataset, r.row_id), `${r.tenant}/dataset/${r.dataset}/${r.row_id}`], r => [r.tenant, r.dataset, r.row_id]],
      ['secrets_registry', 'value', r => [AAD('target', 'secret', r.tenant, r.secret_id), `${r.tenant}/secret/${r.secret_id}`], r => [r.tenant, r.secret_id]],
      ['grants', 'value', r => [AAD('target', 'grant', r.tenant, r.grant_id), `${r.tenant}/grant/${r.grant_id}`], r => [r.tenant, r.grant_id]],
    ];
    // Same accounting + transplant defenses as the ledger store's
    // migration: identical bytes under two identities quarantines BOTH
    // rows, slash-bearing identities stay sealed, and nothing is skipped
    // silently (w19-aad W19-1/W19-2).
    const stats = this.aadMigration = new Map();
    const mark = (tenant, k) => { const s = stats.get(tenant) ?? { migrated: 0, transplants: 0, ambiguous: 0, skipped: 0 }; s[k]++; stats.set(tenant, s); };
    // Same honest accounting as the store migrator: a grafted donor is
    // reverted, and its 'migrated' mark must unwind with it — the sibling
    // migrator's dedup hit invokes this closure (w20-fixverify F-9).
    const unmark = tenant => { const s = stats.get(tenant); if (s && s.migrated > 0) { s.migrated--; s.reverted = (s.reverted ?? 0) + 1; } };
    const seen = this._aadDedup;
    const slashy = (...parts) => parts.some(p => typeof p === 'string' && p.includes('/'));
    this.db.exec('BEGIN IMMEDIATE');
    try {
      for (const [table, col, aads, pks] of spec) {
        const where = table === 'dataset_rows' ? 'tenant=? AND dataset=? AND row_id=?'
          : table === 'secrets_registry' ? 'tenant=? AND secret_id=?'
          : table === 'grants' ? 'tenant=? AND grant_id=?'
          : 'tenant=? AND id=?';
        for (const r of this._stmt(`SELECT * FROM ${table}`).all()) {
          const [tuple, legacy] = aads(r);
          try { decrypt(r[col], this.key(r.tenant), tuple); continue; } catch { /* legacy-sealed or corrupt */ }
          const prior = seen.get(r[col]);
          // Cross-DB collision: the donor's revert closure runs on the
          // sibling database — outside this transaction and against a live
          // row. A graft is detected and counted; the donor keeps its
          // canonical binding instead of being stranded (w24-fixverify
          // W24-06).
          if (prior) { if (prior.db === this.db) { prior.revert?.(); prior.unmark?.(); } mark(r.tenant, 'transplants'); continue; }
          if (slashy(r.tenant, r.id, r.dataset, r.row_id, r.secret_id, r.grant_id)) { seen.set(r[col], {}); mark(r.tenant, 'ambiguous'); continue; }
          try {
            const plain = decrypt(r[col], this.key(r.tenant), legacy);
            const upd = this._stmt(`UPDATE ${table} SET ${col}=? WHERE ${where}`), orig = r[col];
            // A same-DB revert supersedes THIS connection's ciphertext —
            // re-arm its WAL-truncate flag or the donor's legacy bytes
            // linger until an unrelated write (w21-store F-9).
            seen.set(orig, { db: this.db, revert: () => { upd.run(orig, ...pks(r)); this._deleted = true; }, unmark: () => unmark(r.tenant) });
            upd.run(encrypt(plain, this.key(r.tenant), tuple), ...pks(r));
            mark(r.tenant, 'migrated');
          } catch { mark(r.tenant, 'skipped'); }
        }
      }
      // Same durable accounting as the ledger store's migration: the
      // stats persist inside this tx so a crash before the fabric's
      // attestation still surfaces them at the next open (w43-store F-4).
      for (const [mtenant, ms] of stats)
        if (ms.migrated + ms.transplants + ms.ambiguous + ms.skipped > 0)
          this._schemaGuard(() => {
            // Sanctioned marker write: drop the INSERT arm inside this
            // tx, recreate before it closes (w48-store W48-4).
            this.db.exec('DROP TRIGGER IF EXISTS aad_marker_keep_ins');
            try { this._landed(() => this._stmt("INSERT OR REPLACE INTO meta_kv VALUES(?, 'aad_migration', ?)").run(mtenant, JSON.stringify(ms)), 'aad-migration marker'); }
            finally { this.db.exec("CREATE TRIGGER IF NOT EXISTS aad_marker_keep_ins BEFORE INSERT ON meta_kv WHEN NEW.key='aad_migration' BEGIN SELECT RAISE(ABORT, 'aad migration marker is evidence'); END"); }
          });
      this.db.exec('COMMIT');
      // Truncate post-migration so dead legacy ciphertext does not linger
      // in the WAL (w19-aad W19-3).
      let migrated = 0; for (const s of stats.values()) migrated += s.migrated;
      if (migrated > 0) { try { this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); } catch { /* contention: residue clears at next open */ } }
    } catch (e) {
      if (this.db.isTransaction) this.db.exec('ROLLBACK');
      // BEGIN IMMEDIATE contention surfaces in the ledger taxonomy, not
      // as a raw sqlite error (w19-aad W19-4).
      if (e?.errcode === 5 || e?.errcode === 6 || /database .*locked/i.test(e?.message ?? '')) throw new InvariantError('INV-503-LEDGER', 'Ledger writer contention exceeded the wait bound; retry', 503);
      throw e;
    }
  }
  close() { this.db.close(); }
  // Prepared-statement memo: node:sqlite recompiles a cached statement
  // after schema drift, and a dropped table still throws the same error a
  // fresh prepare would — identical INV classification (w47-perf).
  _stmt(sql) {
    const mem = this._stmts ??= new Map();
    let st = mem.get(sql);
    if (!st) {
      if (mem.size >= 256) mem.delete(mem.keys().next().value);
      mem.set(sql, st = this.db.prepare(sql));
    }
    return st;
  }
  tx(fn) {
    // Same contract as Store.tx: a nested call nests via SAVEPOINT so a
    // callee's failure cannot half-commit inside the outer transaction,
    // BEGIN contention surfaces as INV-503-LEDGER, and a ROLLBACK that
    // itself fails must not mask the original error (w21-store F-3).
    if (this.db.isTransaction) {
      const sp = `sp_${++this._sp}`;
      this.db.exec(`SAVEPOINT ${sp}`);
      try { const r = fn(); requireThat(typeof r?.then !== 'function', 'INV-409-STATE', 'Transactions must be synchronous — an async body commits before it runs', 409); this.db.exec(`RELEASE ${sp}`); return r; }
      // A RAISE(ROLLBACK) trigger destroys the whole transaction and the
      // savepoint with it — the rollback itself then faults, and the
      // original trigger evidence must still surface, not a bare 'no
      // such savepoint' that masks it (w50-fv F-7; store.mjs twin).
      catch (e) { try { this.db.exec(`ROLLBACK TO ${sp}; RELEASE ${sp}`); } catch (rb) { if (e instanceof Error) e.rollback_error = rb?.message ?? String(rb); } throw e; }
    }
    try {
      this.db.exec('BEGIN IMMEDIATE');
      const r = fn();
      requireThat(typeof r?.then !== 'function', 'INV-409-STATE', 'Transactions must be synchronous — an async body commits before it runs', 409);
      this.db.exec('COMMIT');
      // Deleted ciphertext must not linger in the WAL — any armed delete
      // truncates the log right at the commit boundary (DEK-audit F4). A
      // contended checkpoint throws SQLITE_LOCKED after the COMMIT: the write
      // is durable, so the flag stays armed for the next tx instead of
      // failing committed work (w8-fixverify F2).
      if (this._deleted) try { this._checkpointDeleted(); } catch { /* retry next tx */ }
      return r;
    } catch (e) {
      try { if (this.db.isTransaction) this.db.exec('ROLLBACK'); } catch { /* rollback failure must not mask the real error */ }
      if (e?.errcode === 5 || e?.errcode === 6 || /database .*locked/i.test(e?.message ?? '')) throw new InvariantError('INV-503-LEDGER', 'Ledger writer contention exceeded the wait bound; retry', 503);
      throw e;
    }
  }
  // TRUNCATE returns {busy,log,checkpointed}: a reader holding a WAL mark
  // makes the call a silent no-op — only disarm the delete flag when the
  // log actually folded, so a later armed write retries (w22-fixverify F4).
  _checkpointDeleted() {
    const r = this._stmt('PRAGMA wal_checkpoint(TRUNCATE)').get();
    if (r && !r.busy && (r.checkpointed ?? 0) >= (r.log ?? 0)) this._deleted = false;
  }
  key(tenant) { requireThat(Object.hasOwn(this.keys, tenant), 'INV-404-NOT-FOUND', 'Resource not found', 404); return Buffer.from(this.keys[tenant], 'base64url'); }
  exists(tenant, id) {
    return this._stmt('SELECT 1 FROM resources WHERE tenant=? AND id=?').get(tenant, id) !== undefined;
  }
  _readResource(tenant, id) {
    const row = this._stmt('SELECT version,value FROM resources WHERE tenant=? AND id=?').get(tenant, id);
    return row ? { version: row.version, value: this._dec(row.value, tenant, AAD('target', 'resource', tenant, id)) } : { version: 0, value: null };
  }
  state(tenant, id) {
    const res = this._readResource(tenant, id);
    const material_fields = res.value ?? {};
    // 'rows' is a read-model projection for real datasets only. A write whose
    // payload merely contains a 'columns' key (e.g. a JIT grant) must not
    // start projecting rows — the stored record and its digest would drift
    // apart (w5 F-6 post-read).
    if (material_fields.columns && material_fields.rows === undefined && this._stmt('SELECT 1 FROM dataset_rows WHERE tenant=? AND dataset=? LIMIT 1').get(tenant, id)) {
      material_fields.rows = this.datasetRows(tenant, id);
    }
    return { version: res.version, digest: digest(material_fields), material_fields };
  }
  datasetRows(tenant, dataset) {
    return this._stmt('SELECT row_id, data FROM dataset_rows WHERE tenant=? AND dataset=? ORDER BY row_id').all(tenant, dataset)
      // Registry columns win the spread — a stored 'id'/'version' member
      // must not shadow the row's identity or counter (w9-schema F-7).
      .map(r => ({ ...this._dec(r.data, tenant, AAD('target', 'dataset', tenant, dataset, r.row_id)), id: r.row_id }));
  }
  // Provisioning/fault harness only: not reachable through the HTTP API.
  // The versioned read-modify-write runs in a transaction like every other
  // mutation — a parallel seed can never produce a lost update (concurrency
  // audit L3).
  seed(tenant, id, fields) {
    const { rows, ...meta } = fields;
    return this.tx(() => {
      const state = this._readResource(tenant, id);
      this._deleted = true; // upsert supersedes ciphertext — truncate at commit (w8-fixverify F3)
      this._landed(() => this._stmt('INSERT INTO resources VALUES(?,?,?,?) ON CONFLICT(tenant,id) DO UPDATE SET version=excluded.version,value=excluded.value').run(tenant, id, state.version + 1, encrypt(meta, this.key(tenant), AAD('target', 'resource', tenant, id))), 'resource write');
      if (Array.isArray(rows)) {
        this._stmt('DELETE FROM dataset_rows WHERE tenant=? AND dataset=?').run(tenant, id);
        for (const row of rows) {
          const { id: row_id, ...data } = row;
          this._landed(() => this._stmt('INSERT INTO dataset_rows VALUES(?,?,?,?)').run(tenant, id, row_id, encrypt(data, this.key(tenant), AAD('target', 'dataset', tenant, id, row_id))), 'dataset row write');
        }
        // Post-state settle: the delete may legitimately touch zero rows,
        // but after the rewrite the dataset must hold exactly what was
        // authorised — a swallowed arm on either side screams (w48-fv).
        const settled = this._stmt('SELECT COUNT(*) n FROM dataset_rows WHERE tenant=? AND dataset=?').get(tenant, id)?.n;
        requireThat(settled === rows.length, 'INV-409-INTEGRITY', 'Dataset rewrite diverged from the authorised row set — foreign trigger interference', 409);
      }
    });
  }
  seedSecret(tenant, secret_id, fields) {
    return this.tx(() => {
      const state = this._stmt('SELECT version FROM secrets_registry WHERE tenant=? AND secret_id=?').get(tenant, secret_id);
      this._writeSecret(tenant, secret_id, (state?.version ?? 0) + 1, fields);
    });
  }
  secret(tenant, secret_id) {
    const row = this._stmt('SELECT version,value FROM secrets_registry WHERE tenant=? AND secret_id=?').get(tenant, secret_id);
    return row ? { ...this._dec(row.value, tenant, AAD('target', 'secret', tenant, secret_id)), version: row.version } : null;
  }
  // For secret.use the DECISIVE record is the registry row — that is the state
  // a capsule must bind, not an arbitrary resources row (w5 F-7).
  secretState(tenant, secret_id) {
    const row = this.secret(tenant, secret_id);
    const material_fields = row ? Object.fromEntries(Object.entries(row).filter(([k]) => k !== 'version')) : {};
    return { version: row?.version ?? 0, digest: digest(material_fields), material_fields };
  }
  _writeSecret(tenant, secret_id, version, fields) {
    this._deleted = true; // secret upsert supersedes ciphertext (w8-fixverify F3)
    this._landed(() => this._stmt('INSERT INTO secrets_registry VALUES(?,?,?,?) ON CONFLICT(tenant,secret_id) DO UPDATE SET version=excluded.version,value=excluded.value').run(tenant, secret_id, version, encrypt(fields, this.key(tenant), AAD('target', 'secret', tenant, secret_id))), 'secret write');
  }
  grant(tenant, grant_id, value) {
    this._deleted = true; // grant upsert supersedes ciphertext (w8-fixverify F3)
    this._landed(() => this._stmt('INSERT INTO grants VALUES(?,?,?) ON CONFLICT(tenant,grant_id) DO UPDATE SET value=excluded.value').run(tenant, grant_id, encrypt(value, this.key(tenant), AAD('target', 'grant', tenant, grant_id))), 'grant write');
    this._dirtSeq = (this._dirtSeq ?? 0) + 1; // grants-table dirt invalidates grantsFor memos (w45-perf)
    // Bare callers arm the flag but never reach tx()'s post-commit
    // checkpoint — truncate on the autocommit path too, like the store
    // does (w21-store F-5).
    if (!this.db.isTransaction) try { this._checkpointDeleted(); } catch { /* retry on next armed write */ }
  }
  // One undecryptable grant row must not wedge every authorize() call — a
  // corrupt row can only ever HIDE a grant (anchoring is the authority), so
  // it is skipped and counted, never fatal (w17-fixverify). The count is
  // evidence the operator must see: it resets per scan and surfaces on the
  // grant listing, or a tamper could silently make grants disappear
  // (w38-runtime L-1).
  // A dropped or rewritten table is integrity evidence inside the INV
  // taxonomy, never bare sqlite noise escaping to callers (w45-fv M).
  // A silent RAISE(IGNORE) trigger abandons the statement — no error,
  // COMMIT succeeds, the row never lands (w48-fixverify CRITICAL).
  _totalChanges() { return Number(this._stmt('SELECT total_changes() tc').get().tc); }
  // changes() counts only the top-level statement — an AFTER trigger's
  // side-effects (a silent revert, a shadow row, a planted mirror) never
  // show in it. total_changes() counts every row the connection touched,
  // trigger work included: the statement-level delta catches the last
  // laundering arm (w49-fixverify C-2). The write runs inside a
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
  _schemaGuard(run) {
    try { return run(); }
    catch (e) {
      if (/no such table|no such column|not a database|malformed/i.test(e?.message ?? ''))
        throw new InvariantError('INV-409-INTEGRITY', 'Ledger schema diverged — tamper evidence', 409, { cause: e });
      // EVERY trigger abort on a guarded path is tamper evidence — a
      // mimic replaying a known RAISE text is indistinguishable, so the
      // allowlist laundered planted payloads into raw errors (w48-store
      // W48-3). Our own guards never fire on a legitimate write.
      if (e?.errcode === 1811)
        throw new InvariantError('INV-409-INTEGRITY', 'Ledger access refused by a trigger — tamper evidence', 409, { cause: e });
      if (e?.errcode === 5 || e?.errcode === 6 || /database .*locked/i.test(e?.message ?? '')) throw e;
      // Extended sqlite codes carry the primary class in the low byte —
      // BUSY_SNAPSHOT/RECOVERY/TIMEOUT are the same contention class as a
      // bare busy, and NOMEM/INTERRUPT/SCHEMA are engine faults — honest
      // infrastructure, never mislabeled tamper (w50-fv F-5).
      const base = typeof e?.errcode === 'number' ? e.errcode & 0xFF : null;
      if (base === 5 || base === 6) throw e;
      if (base !== null && [7, 9, 17].includes(base))
        throw new InvariantError('INV-503-LEDGER', `Ledger engine fault: ${e?.message ?? 'sqlite error'}`, 503, { cause: e });
      // Storage-class faults (readonly, I/O, corrupt, full, cant-open)
      // are infrastructure, not surgery evidence (w49-fixverify M-4).
      if (base !== null && [8, 10, 11, 13, 14, 15].includes(base))
        throw new InvariantError('INV-503-STORAGE', `Ledger storage fault: ${e?.message ?? 'sqlite error'}`, 503, { cause: e });
      // Any remaining sqlite-class fault is schema/integrity evidence,
      // not raw internals for callers to pattern-match (w48-store W48-3).
      if (e?.code === 'ERR_SQLITE_ERROR' || typeof e?.errcode === 'number')
        throw new InvariantError('INV-409-INTEGRITY', `Ledger access fault: ${e?.message ?? 'sqlite error'}`, 409, { cause: e });
      throw e;
    }
  }
  grants(tenant, subject_id, now) {
    const out = []; let corrupt = 0;
    for (const r of this._schemaGuard(() => this._stmt('SELECT grant_id, value FROM grants WHERE tenant=?').all(tenant))) {
      let g; try { g = this._dec(r.value, tenant, AAD('target', 'grant', tenant, r.grant_id)); } catch { corrupt++; continue; }
      if (g.subject_id === subject_id && g.expires_at > now && !g.revoked) out.push(g);
    }
    this._corruptGrantRows = corrupt;
    return out;
  }
  // The honoured-grants projection without the clock filter: callers that
  // memoize on content (grantsFor) need expiry applied against their own
  // effective time after the fetch, not baked into the row read
  // (w47-perf).
  grantRows(tenant, subject_id) {
    const out = []; let corrupt = 0;
    for (const r of this._schemaGuard(() => this._stmt('SELECT grant_id, value FROM grants WHERE tenant=?').all(tenant))) {
      let g; try { g = this._dec(r.value, tenant, AAD('target', 'grant', tenant, r.grant_id)); } catch { corrupt++; continue; }
      if (g.subject_id === subject_id) out.push(g);
    }
    this._corruptGrantRows = corrupt;
    return out;
  }
  allGrants(tenant) {
    const out = []; let corrupt = 0;
    for (const r of this._schemaGuard(() => this._stmt('SELECT grant_id, value FROM grants WHERE tenant=?').all(tenant))) {
      try { out.push(this._dec(r.value, tenant, AAD('target', 'grant', tenant, r.grant_id))); } catch { corrupt++; }
    }
    this._corruptGrantRows = corrupt;
    return out;
  }
  revokeGrant(tenant, grant_id) {
    // Read-modify-write inside tx(): an interleaved re-grant on a second
    // connection must not be clobbered by a stale revocation of the
    // pre-revocation value (w21-store F-4), and tx() truncates the WAL
    // residue at commit (w21-store F-5).
    return this.tx(() => {
      const row = this._stmt('SELECT value FROM grants WHERE tenant=? AND grant_id=?').get(tenant, grant_id);
      requireThat(row, 'INV-404-NOT-FOUND', 'Grant not found', 404);
      const value = this._dec(row.value, tenant, AAD('target', 'grant', tenant, grant_id));
      value.revoked = true;
      this._deleted = true; // revoke supersedes ciphertext (w8-fixverify F3)
      this._landed(() => this._stmt('UPDATE grants SET value=? WHERE tenant=? AND grant_id=?').run(encrypt(value, this.key(tenant), AAD('target', 'grant', tenant, grant_id)), tenant, grant_id), 'grant revocation');
      this._dirtSeq = (this._dirtSeq ?? 0) + 1;
      return value;
    });
  }
  outcome(tenant, id) {
    const row = this._stmt('SELECT value FROM transactions WHERE tenant=? AND id=?').get(tenant, id);
    return row ? this._dec(row.value, tenant, AAD('target', 'transaction', tenant, id)) : null;
  }
  // Verified dataset read: caller scope is compiled into a QueryPlan, rebound
  // against the authorising grant, then executed with bound parameters only.
  readDataset(tenant, id, columns, rowIds, ceiling, grant = null) {
    const dataset = this.state(tenant, id).material_fields;
    requireThat(Array.isArray(dataset.columns), 'INV-404-NOT-FOUND', 'Dataset not found', 404);
    const plan = buildPlan({ dataset: id, columns, row_ids: rowIds, max_rows: ceiling }, dataset.columns);
    // The plan rebinds to the authorising scope when a distinct authority
    // exists (the capability payload on the consume path); on the certified
    // export path the capsule's requested_state IS the authority — the
    // reflexive check stays as a shape guard, and the finish-time
    // exactOutput recompute is the real binding (w20-datagate F8).
    verifyPlan(plan, grant ?? { dataset: id, columns, row_ids: rowIds, max_rows: ceiling });
    const result = executePlan(this.db, plan, tenant, (row, r) => this._dec(r.data, tenant, AAD('target', 'dataset', tenant, id, row)));
    return result;
  }
  execute(capsule, transactionId, now, fault = null) {
    const tenant = capsule.tenant_id, id = capsule.action.target_resource;
    const prior = this.outcome(tenant, transactionId); if (prior) return prior;
    if (fault === 'before-dispatch') throw new Error('Simulated transport timeout before dispatch');
    // 'state-conflict' simulates a DETERMINISTIC refusal raised inside the
    // target transaction (e.g. a predicate the reservation check could not
    // see) — the outcome must record FAILED, never UNCERTAIN.
    if (fault === 'state-conflict') throw new InvariantError('INV-409-STATE', 'Simulated deterministic target refusal', 409);
    let outcome;
    // A caller already inside a transaction cannot nest a bare BEGIN — the
    // inner COMMIT would commit the caller's writes early (w28-store F10).
    requireThat(!this.db.isTransaction, 'INV-503-LEDGER', 'Target execute cannot nest inside a live transaction', 503);
    try {
      // BEGIN inside the try: contention on the BEGIN itself must surface
      // as INV-503-LEDGER, not a raw sqlite error (w21-store F-3).
      this.db.exec('BEGIN IMMEDIATE');
      const requested = capsule.requested_state, type = capsule.action.type;
      const state = type === 'secret.use' ? this.secretState(tenant, requested.secret_id) : this.state(tenant, id);
      requireThat(state.version === capsule.current_state.version && state.digest === capsule.current_state.digest, 'INV-409-STATE', 'Target state changed', 409);
      let next = { ...state.material_fields, ...clone(requested) }, output = null, output_row_ids = null;
      if (['finance.vendor.create', 'finance.beneficiary.create'].includes(type)) requireThat(state.version === 0, 'INV-409-STATE', 'Resource already exists', 409);
      if (type === 'finance.bank.change') { requireThat(state.version > 0, 'INV-409-STATE', 'Bank change requires existing resource', 409); next.first_payment_done = false; next.payment_eligible_at = now + 60000; }
      if (type === 'finance.payment.first') {
        requireThat(state.version > 0 && id === requested.beneficiary_id && state.material_fields.bank_account === requested.bank_account && state.material_fields.currency === requested.currency && state.material_fields.first_payment_done !== true && (state.material_fields.payment_eligible_at ?? 0) <= now, 'INV-409-STATE', 'Beneficiary, first-payment or cooldown predicate failed', 409);
        next = { ...state.material_fields, first_payment_done: true, payment: clone(requested), payment_transaction: transactionId };
      }
      if (type === 'data.export') {
        requireThat(requested.dataset === id, 'INV-451-POLICY', 'Dataset binding mismatch', 451);
        const datasetResult = this.readDataset(tenant, id, requested.columns, requested.row_ids, requested.max_rows);
        output = datasetResult.rows; output_row_ids = datasetResult.row_ids;
        next = state.material_fields;
      }
      if (type === 'identity.mfa.reset' || type === 'identity.authenticator.enroll' || type === 'identity.account.recover') {
        next = { ...state.material_fields, ...clone(requested), last_identity_operation: { type, at: now, transaction: transactionId } };
      }
      if (type === 'key.rotate') {
        next = { ...state.material_fields, ...clone(requested), rotated_at: now, rotation_transaction: transactionId };
      }
      if (type === 'secret.use') {
        const secret = this.secret(tenant, requested.secret_id);
        requireThat(secret && (secret.allowed_operations ?? []).includes(requested.operation), 'INV-451-POLICY', 'Secret or operation unavailable', 451);
        requireThat(secret.workload_id === requested.workload_id, 'INV-403-SCOPE', 'Workload binding mismatch', 403);
        next = { ...state.material_fields, last_use: { secret_id: requested.secret_id, operation: requested.operation, workload_id: requested.workload_id, at: now, transaction: transactionId } };
      }
      if (type === 'backup.delete') {
        requireThat(state.material_fields.recovery_set === requested.recovery_set, 'INV-409-STATE', 'Recovery set mismatch', 409);
        next = { ...state.material_fields, deleted_backups: [...(state.material_fields.deleted_backups ?? []), { backup_id: requested.backup_id, at: now, transaction: transactionId }] };
      }
      if (fault === 'before-commit') throw new Error('Simulated target transaction failure');
      if (type === 'secret.use') this._writeSecret(tenant, requested.secret_id, state.version + 1, next);
      else if (type !== 'data.export') { this._deleted = true; this._landed(() => this._stmt('INSERT INTO resources VALUES(?,?,?,?) ON CONFLICT(tenant,id) DO UPDATE SET version=excluded.version,value=excluded.value').run(tenant, id, state.version + 1, encrypt(next, this.key(tenant), AAD('target', 'resource', tenant, id))), 'resource write'); }
      // An export's observed_state would persist the WHOLE dataset —
      // including columns the requester may not see — into the durable
      // journal for no validation benefit: the digest alone proves the
      // snapshot. Export entries keep the digest and the authorised output
      // only (w10-datagate F5). A secret.use row gets the same treatment
      // a fortiori — the registry material may carry secret bytes, so the
      // journal holds only the digest-bearing projection (w15-timing F9).
      const journalState = type === 'data.export' ? null
        : type === 'secret.use' ? { withheld: true, material_digest: digest(next) }
        : next;
      outcome = { target_transaction_id: transactionId, capsule_digest: digest(capsule), authorised_requested_digest: digest(requested), observed_state_digest: digest(next), observed_state: journalState, output, output_row_ids, status: 'VERIFIED', execution_time: now, simulation: true };
      this._landed(() => this._stmt('INSERT INTO transactions VALUES(?,?,?)').run(tenant, transactionId, encrypt(outcome, this.key(tenant), AAD('target', 'transaction', tenant, transactionId))), 'outcome journal');
      this.db.exec('COMMIT');
      // Same commit-boundary truncation as tx() — durable on success, armed
      // for a later retry when the log is contended (w8-fixverify F2/F3).
      if (this._deleted) try { this._checkpointDeleted(); } catch { /* retry later */ }
    } catch (e) {
      try { if (this.db.isTransaction) this.db.exec('ROLLBACK'); } catch { /* a failing ROLLBACK must not mask the real error (w21-store F-3) */ }
      if (e?.errcode === 5 || e?.errcode === 6 || /database .*locked/i.test(e?.message ?? '')) throw new InvariantError('INV-503-LEDGER', 'Ledger writer contention exceeded the wait bound; retry', 503);
      // Two processes racing the same transactionId hit the PK constraint
      // inside the write — the loser must get the stored outcome, not an
      // error (store-audit LOW: idempotent replay under contention). The
      // constraint code lives on e.errcode — e.code is always the generic
      // ERR_SQLITE_ERROR (w28-store F6).
      if (e?.errcode === 1555 || e?.errcode === 2067 || /PRIMARYKEY|UNIQUE/.test(String(e?.message ?? ''))) {
        const prior = this.outcome(tenant, transactionId);
        if (prior) return prior;
      }
      throw e;
    }
    if (fault === 'after-commit') throw new Error('Simulated response lost after durable commit');
    if (fault === 'malformed-response') return { status: 'VERIFIED' };
    if (fault === 'altered-response') return { ...outcome, authorised_requested_digest: '0'.repeat(64) };
    return outcome;
  }
  // Compensation for a previously executed child of a composite action. Only
  // registered, verifiable compensations exist: registry-state restoration for
  // non-monetary mutations. Monetary effects cannot be un-sent — the record
  // says so instead of pretending.
  compensate(capsule, priorState, now, certId = null) {
    const tenant = capsule.tenant_id, id = capsule.action.target_resource, type = capsule.action.type;
    const compensatable = ['finance.vendor.create', 'finance.beneficiary.create', 'finance.bank.change', 'identity.mfa.reset', 'identity.authenticator.enroll', 'identity.account.recover', 'cloud.firewall.change', 'code.release', 'key.rotate', 'backup.delete'];
    if (!compensatable.includes(type)) {
      return { compensated: false, reason: 'NON_COMPENSATABLE_EFFECT', note: 'Effect cannot be reversed; a separately authorised remedy action is required.' };
    }
    // Read-modify-write inside one tx — a second concurrent compensation
    // cannot lose-update the version counter (concurrency-audit L3).
    return this.tx(() => {
      const state = this.state(tenant, id);
      // The restore may only overwrite the child's own write: if a later
      // authorised action already moved the resource past the compensated
      // version, reverting would silently erase it (w10-cert F6).
      const expected = capsule.current_state.version + 1;
      if (state.version !== expected) return { compensated: false, reason: 'STALE_COMPENSATION', note: `Registry moved past the compensated write (version ${state.version}, expected ${expected}); a separately authorised remedy action is required.` };
      this._deleted = true; // restoration supersedes ciphertext (w8-fixverify F3)
      this._landed(() => this._stmt('UPDATE resources SET version=?, value=? WHERE tenant=? AND id=?').run(state.version + 1, encrypt({ ...priorState, compensated_at: now, compensation_of: digest(capsule) }, this.key(tenant), AAD('target', 'resource', tenant, id)), tenant, id), 'compensation restore');
      // The unwind is journaled like a dispatch: a crash between this commit
      // and the parent's outcome write stays reconstructible — the chain
      // anchors EXECUTION_COMPENSATED only against this durable row
      // (w22 F4).
      if (certId) this._landed(() => this._stmt('INSERT INTO transactions VALUES(?,?,?)').run(tenant, `comp:${certId}`, encrypt({ target_transaction_id: `comp:${certId}`, capsule_digest: digest(capsule), compensated_at: now, restored_version: state.version + 1, status: 'COMPENSATED', simulation: true }, this.key(tenant), AAD('target', 'transaction', tenant, `comp:${certId}`))), 'compensation journal');
      return { compensated: true, restored_version: state.version + 1 };
    });
  }
  manifest() {
    return { connector_id: 'controlled-sqlite-target', version: '1.1.0', environment: 'simulation', production_supported: false, credentials: 'customer-local software encryption key; no external target credentials', idempotency: 'durable unique transaction id; mutating timeout never retried automatically', permissions: ['local simulated resource read', 'local simulated resource mutation', 'verified dataset query plans', 'registered compensation for non-monetary mutations'], limitations: ['No bank/ERP API integration', 'No target-wide bypass guarantee', 'No hardware-backed credential isolation', 'No actual network/cloud/identity/secret/backup mutation', 'Composite atomicity is compensation-based, not transactional'], upgrade_rule: 'coverage becomes UNKNOWN until compatibility and bypass tests pass' };
  }
}

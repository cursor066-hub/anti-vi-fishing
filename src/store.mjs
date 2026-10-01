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
// Reads fall back to the legacy form so an upgraded store never strands (or,
// worse, shreds) live ciphertext; every put() re-seals under the tuple form
// (w8-fixverify F1).
const legacyAad = (tenant, kind, id) => `${tenant}/${kind}/${id}`;
const legacyDekAad = (tenant, kind, id) => `${tenant}/${kind}/${id}/dek`;
const decryptEither = (wrapped, key, aad, legacy) => {
  try { return decrypt(wrapped, key, aad); } catch { return decrypt(wrapped, key, legacy); }
};

export class Store {
  constructor(path, tenantKeys, auditSigners) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path); chmodSync(path, 0o600);
    this.tenantKeys = tenantKeys;
    this._sp = 0;
    // auditSigners[tenant] = {key_id, public_key, sign(payload) -> envelope}.
    // Signing runs inside the keystore; the store never sees private material.
    this.auditSigners = auditSigners;
    // secure_delete=ON zeroes freed pages, so a deleted DEK row leaves no
    // recoverable copy in the database file itself.
    // busy_timeout bounds queueing behind a contending writer at 30s; a
    // contender that still loses gets INV-503-LEDGER, not a raw sqlite error
    // (concurrency-audit H2). Long writers should stay chunked regardless.
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
      CREATE TRIGGER IF NOT EXISTS no_audit_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
      CREATE TRIGGER IF NOT EXISTS no_audit_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
      -- Chain-squat guard (store-audit MED-1): an insert must extend the head
      -- exactly; earlier positions and gaps are rejected by the engine.
      CREATE TRIGGER IF NOT EXISTS audit_seq_guard BEFORE INSERT ON audit
        WHEN NEW.seq <> (SELECT COALESCE(MAX(seq),0)+1 FROM audit WHERE tenant=NEW.tenant)
        BEGIN SELECT RAISE(ABORT, 'audit sequence must extend the head'); END;
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
    // A DB file whose append-only/seq triggers were weakened out-of-band is a
    // tampered ledger — refuse to open rather than silently audit into a
    // writable chain (w11-redteam R18). A plain DROP is healed by the CREATE
    // statements above; what survives is a same-name trigger whose body no
    // longer aborts, so the check binds the trigger text, not just the name.
    const triggers = new Map(this.db.prepare("SELECT name, sql FROM sqlite_master WHERE type='trigger'").all().map(x => [x.name, x.sql ?? '']));
    for (const name of ['no_audit_update', 'no_audit_delete', 'audit_seq_guard'])
      if (!triggers.get(name)?.includes('RAISE(ABORT')) throw new Error(`audit integrity trigger missing or weakened: ${name}`);
    // The append-only pair must fire unconditionally — a WHEN-gated or
    // re-tabled same-name trigger is a smuggled no-op.
    for (const name of ['no_audit_update', 'no_audit_delete'])
      if (/WHEN/i.test(triggers.get(name)) || !triggers.get(name).includes('ON audit')) throw new Error(`audit integrity trigger weakened: ${name}`);
    // Text checks are evadable (a shadow trigger can carry a matching
    // name/body while never firing on `audit`) — the definitive test is
    // functional: attempt each forbidden write inside a savepoint and
    // require the abort (w13-timing H-1). The probe tenant's rows are
    // rolled back, so boot never mutates the chain.
    const probe = fn => {
      this.db.exec('SAVEPOINT integrity_probe');
      let aborted = false;
      try { fn(); } catch { aborted = true; }
      finally { this.db.exec('ROLLBACK TO integrity_probe'); this.db.exec('RELEASE integrity_probe'); }
      return aborted;
    };
    const pt = '__integrity_probe__';
    requireThat(probe(() => { this.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run(pt, 1, 'x', 'x', '{}'); this.db.prepare('UPDATE audit SET hash=? WHERE tenant=?').run('y', pt); }), 'INV-503-STORAGE', 'Audit append-only UPDATE trigger not enforced', 503);
    requireThat(probe(() => { this.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run(pt, 1, 'x', 'x', '{}'); this.db.prepare('DELETE FROM audit WHERE tenant=?').run(pt); }), 'INV-503-STORAGE', 'Audit append-only DELETE trigger not enforced', 503);
    requireThat(probe(() => this.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run(pt, 7, 'x', 'x', '{}')), 'INV-503-STORAGE', 'Audit sequence guard not enforced', 503);
  }
  close() { this.db.close(); }
  tx(fn) {
    // Nested calls run under a SAVEPOINT: a callee's ROLLBACK can then never
    // destroy the outer transaction's writes (concurrency-audit L2).
    if (this.db.isTransaction) {
      const sp = `sp_${++this._sp}`;
      this.db.exec(`SAVEPOINT ${sp}`);
      try {
        const result = fn();
        if (result && typeof result.then === 'function') throw new Error('Transactions must be synchronous');
        this.db.exec(`RELEASE ${sp}`);
        return result;
      } catch (e) { this.db.exec(`ROLLBACK TO ${sp}; RELEASE ${sp}`); throw e; }
    }
    try {
      this.db.exec('BEGIN IMMEDIATE');
      const result = fn();
      if (result && typeof result.then === 'function') throw new Error('Transactions must be synchronous');
      this.db.exec('COMMIT');
      // Post-commit WAL truncation so shredded DEK material never lingers in
      // the log — runs outside the transaction, where SQLite allows it.
      this.checkpoint();
      return result;
    } catch (e) {
      if (this.db.isTransaction) this.db.exec('ROLLBACK');
      // A lost busy-timeout race must surface as a fabric error, not a raw
      // SQLITE_BUSY leaking internals (concurrency-audit H2).
      if (e?.errcode === 5 || /database is locked/i.test(e?.message ?? '')) throw new InvariantError('INV-503-LEDGER', 'Ledger writer contention exceeded the wait bound; retry', 503);
      throw e;
    }
  }
  key(tenant) {
    requireThat(this.tenantKeys[tenant], 'INV-404-NOT-FOUND', 'Resource not found', 404);
    return Buffer.from(this.tenantKeys[tenant], 'base64url');
  }
  dek(tenant, kind, id) {
    const row = this.db.prepare('SELECT wrapped FROM deks WHERE tenant=? AND kind=? AND id=?').get(tenant, kind, id);
    return row ? Buffer.from(decryptEither(row.wrapped, this.key(tenant), dekAad(tenant, kind, id), legacyDekAad(tenant, kind, id)), 'base64url') : null;
  }
  get(tenant, kind, id) {
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
    this.db.prepare('INSERT INTO records VALUES(?,?,?,?,?) ON CONFLICT(tenant,kind,id) DO UPDATE SET value=excluded.value').run(tenant, kind, id, encrypt(value, dek, recAad(tenant, kind, id)), at);
    this.db.prepare('INSERT INTO deks VALUES(?,?,?,?) ON CONFLICT(tenant,kind,id) DO UPDATE SET wrapped=excluded.wrapped').run(tenant, kind, id, encrypt(dek.toString('base64url'), this.key(tenant), dekAad(tenant, kind, id)));
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
    this._shredded = true;
    this.db.prepare('DELETE FROM deks WHERE tenant=? AND kind=? AND id=?').run(tenant, kind, id);
    this.db.prepare('DELETE FROM records WHERE tenant=? AND kind=? AND id=?').run(tenant, kind, id);
    if (!this.db.isTransaction) this.checkpoint(); // non-tx paths must not leave the DEK in the WAL (store-audit LOW)
  }
  readValue(tenant, kind, id, wrapped) {
    const key = this.dek(tenant, kind, id) ?? this.key(tenant);
    return decryptEither(wrapped, key, recAad(tenant, kind, id), legacyAad(tenant, kind, id));
  }
  shred(tenant, kind, id) {
    // Crypto-shredding: destroy the record DEK (secure_delete zeroes its
    // page) and drop the ciphertext; then truncate the WAL so no reachable
    // copy of the wrapped key remains. Pre-erasure backups are out of scope
    // and stay honest in the retention report.
    const changes = this.db.prepare('DELETE FROM deks WHERE tenant=? AND kind=? AND id=?').run(tenant, kind, id).changes
      + this.db.prepare('DELETE FROM records WHERE tenant=? AND kind=? AND id=?').run(tenant, kind, id).changes;
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
  clock(now, { recovery = false } = {}) {
    requireThat(Number.isSafeInteger(now) && now > 0, 'INV-503-TIME', 'Clock unavailable', 503);
    const row = this.db.prepare('SELECT last FROM clock WHERE id=1').get();
    requireThat(recovery || !row || now >= row.last, 'INV-503-TIME', 'Clock regression; security operations halted', 503);
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
    const priorTime = last ? JSON.parse(last.envelope).payload.time : 0;
    const entry = { tenant_id: tenant, sequence: (last?.seq ?? 0) + 1, previous: last?.hash ?? '0'.repeat(64), type, actor, reference, metadata, time: Math.max(now, priorTime) };
    // Hash what is actually attested: the signer may add a bound marker (the
    // recovery_signing annotation when a pending successor signs after a
    // key-revoke — w11-lifecycle F2), so the row digest binds the envelope's
    // payload, not the pre-signature entry.
    const envelope = this.auditSigners[tenant].sign(entry);
    const hash = digest(envelope.payload);
    this.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run(tenant, entry.sequence, entry.previous, hash, canonical(envelope));
    return { hash, envelope };
  }
  auditHashes(tenant) {
    return this.db.prepare('SELECT hash FROM audit WHERE tenant=? ORDER BY seq').all(tenant).map(r => r.hash);
  }
  auditPage(tenant, { after = 0, limit = 1000 } = {}) {
    const rows = this.db.prepare('SELECT seq,hash,envelope FROM audit WHERE tenant=? AND seq>? ORDER BY seq LIMIT ?').all(tenant, after, limit);
    const signer = this.auditSigners[tenant], public_keys = signer.keys ? signer.keys() : { [signer.key_id]: { public_key: signer.public_key } };
    // Serving the log is a security surface: re-verify each row's stored
    // hash against its signed payload and check chain continuity back to the
    // row preceding the page — an injected or rewritten row cannot pass
    // (store-audit MED-5).
    const anchor = after ? this.db.prepare('SELECT hash FROM audit WHERE tenant=? AND seq=?').get(tenant, after) : null;
    requireThat(after === 0 || anchor, 'INV-409-AUDIT-TAMPER', 'Audit cursor does not resolve to a stored row', 409);
    let previous = anchor?.hash ?? '0'.repeat(64);
    const entries = rows.map(r => {
      // A malformed envelope is tamper evidence, not a crash: it lands as
      // the same INV-409-AUDIT-TAMPER as a hash break (w13-fixverify L10).
      let envelope;
      try { envelope = JSON.parse(r.envelope); } catch { throw new InvariantError('INV-409-AUDIT-TAMPER', 'Audit row failed integrity verification', 409); }
      requireThat(ctEqual(digest(envelope.payload), r.hash) && envelope.payload.sequence === r.seq && ctEqual(envelope.payload.previous, previous), 'INV-409-AUDIT-TAMPER', 'Audit row failed integrity verification', 409);
      // Hash+previous are attacker-computable (the seq trigger permits a raw
      // MAX+1 append): without signature verification the read path would
      // serve an unsigned forged row as a legitimate chain entry (w15).
      try { verifySigned(envelope, public_keys, 'audit'); }
      catch { throw new InvariantError('INV-409-AUDIT-TAMPER', 'Audit row failed signature verification', 409); }
      previous = r.hash;
      return { sequence: r.seq, hash: r.hash, envelope };
    });
    return { entries, next_cursor: rows.length === limit ? rows.at(-1).seq : null };
  }
  auditExport(tenant, now = null) {
    const rows = this.db.prepare('SELECT hash,envelope FROM audit WHERE tenant=? ORDER BY seq').all(tenant).map(r => {
      try { return { hash: r.hash, envelope: JSON.parse(r.envelope) }; }
      catch { throw new InvariantError('INV-409-AUDIT-TAMPER', 'Audit row failed integrity verification', 409); }
    });
    const signer = this.auditSigners[tenant], public_keys = signer.keys ? signer.keys() : { [signer.key_id]: { public_key: signer.public_key } };
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
  idempotent(tenant, scope, key, requestHash, fn) {
    // SELECT-then-INSERT is atomic only inside a transaction — refuse to run
    // outside one rather than silently depending on the caller (L4).
    requireThat(this.db.isTransaction, 'INV-500-STORE', 'idempotent() must run inside store.tx()', 500);
    requireThat(typeof key === 'string' && /^[A-Za-z0-9_-]{8,128}$/.test(key), 'INV-400-SCHEMA', 'An 8–128 character Idempotency-Key is required');
    const row = this.db.prepare('SELECT hash,result FROM idempotency WHERE tenant=? AND scope=? AND key=?').get(tenant, scope, key);
    if (row) {
      requireThat(ctEqual(row.hash, requestHash), 'INV-409-IDEMPOTENCY', 'Idempotency key reused for a different request', 409);
      return decrypt(row.result, this.key(tenant), `${tenant}/idempotency/${scope}/${key}`);
    }
    const result = fn();
    this.db.prepare('INSERT INTO idempotency VALUES(?,?,?,?,?)').run(tenant, scope, key, requestHash, encrypt(result, this.key(tenant), `${tenant}/idempotency/${scope}/${key}`));
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
  for (const item of bundle.entries) {
    const entry = verifySigned(item.envelope, pinnedKeys, 'audit');
    requireThat(entry.tenant_id === checkpoint.tenant_id && entry.sequence === ++sequence && ctEqual(entry.previous, previous) && entry.time >= time && ctEqual(digest(entry), item.hash), 'INV-409-AUDIT', 'Audit continuity failure', 409);
    previous = item.hash; time = entry.time;
    if (prior && sequence === prior.size) requireThat(ctEqual(previous, prior.head), 'INV-409-FORK', 'Witness checkpoint disagrees', 409);
  }
  requireThat(checkpoint.size === sequence && ctEqual(checkpoint.head, previous) && (!prior || (checkpoint.tenant_id === prior.tenant_id && sequence >= prior.size)), 'INV-409-AUDIT', 'Missing or inconsistent checkpoint', 409);
  // The signed tree_head anchors the entry set under the Merkle root —
  // recompute it rather than trusting the attested value (crypto-audit I-1).
  requireThat(ctEqual(checkpoint.tree_head, merkleRoot(bundle.entries.map(i => i.hash))), 'INV-409-AUDIT', 'Checkpoint tree head does not match the audit entries', 409);
  return { valid: true, entries: sequence, head: previous, tenant_id: checkpoint.tenant_id };
}

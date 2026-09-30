import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, chmodSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import { encrypt, decrypt, verifySigned } from './crypto.mjs';
import { merkleRoot } from './merkle.mjs';
import { canonical, digest } from './canonical.mjs';
import { requireThat } from './errors.mjs';

export class Store {
  constructor(path, tenantKeys, auditSigners) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path); chmodSync(path, 0o600);
    this.tenantKeys = tenantKeys;
    // auditSigners[tenant] = {key_id, public_key, sign(payload) -> envelope}.
    // Signing runs inside the keystore; the store never sees private material.
    this.auditSigners = auditSigners;
    // secure_delete=ON zeroes freed pages, so a deleted DEK row leaves no
    // recoverable copy in the database file itself.
    this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON;');
    const version = this.db.prepare('PRAGMA user_version').get().user_version;
    requireThat(version <= 1, 'INV-503-STORAGE', 'Database schema is newer than this application', 503);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS records (tenant TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL,
        value TEXT NOT NULL, created INTEGER NOT NULL, PRIMARY KEY(tenant,kind,id));
      CREATE TABLE IF NOT EXISTS audit (tenant TEXT NOT NULL, seq INTEGER NOT NULL, previous TEXT NOT NULL,
        hash TEXT NOT NULL, envelope TEXT NOT NULL, PRIMARY KEY(tenant,seq));
      CREATE TRIGGER IF NOT EXISTS no_audit_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
      CREATE TRIGGER IF NOT EXISTS no_audit_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
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
      PRAGMA user_version=1;
    `);
  }
  close() { this.db.close(); }
  tx(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = fn();
      if (result && typeof result.then === 'function') throw new Error('Transactions must be synchronous');
      this.db.exec('COMMIT'); return result;
    } catch (e) { this.db.exec('ROLLBACK'); throw e; }
  }
  key(tenant) {
    requireThat(this.tenantKeys[tenant], 'INV-404-NOT-FOUND', 'Resource not found', 404);
    return Buffer.from(this.tenantKeys[tenant], 'base64url');
  }
  dek(tenant, kind, id) {
    const row = this.db.prepare('SELECT wrapped FROM deks WHERE tenant=? AND kind=? AND id=?').get(tenant, kind, id);
    return row ? Buffer.from(decrypt(row.wrapped, this.key(tenant), `${tenant}/${kind}/${id}/dek`), 'base64url') : null;
  }
  get(tenant, kind, id) {
    const row = this.db.prepare('SELECT value FROM records WHERE tenant=? AND kind=? AND id=?').get(tenant, kind, id);
    if (!row) return null;
    // Records written before per-record DEKs fall back to the tenant key.
    return decrypt(row.value, this.dek(tenant, kind, id) ?? this.key(tenant), `${tenant}/${kind}/${id}`);
  }
  must(tenant, kind, id) {
    const row = this.get(tenant, kind, id); requireThat(row, 'INV-404-NOT-FOUND', 'Resource not found', 404); return row;
  }
  put(tenant, kind, id, value, at) {
    const dek = randomBytes(32), aad = `${tenant}/${kind}/${id}`;
    this.db.prepare('INSERT INTO records VALUES(?,?,?,?,?) ON CONFLICT(tenant,kind,id) DO UPDATE SET value=excluded.value').run(tenant, kind, id, encrypt(value, dek, aad), at);
    this.db.prepare('INSERT INTO deks VALUES(?,?,?,?) ON CONFLICT(tenant,kind,id) DO UPDATE SET wrapped=excluded.wrapped').run(tenant, kind, id, encrypt(dek.toString('base64url'), this.key(tenant), `${aad}/dek`));
  }
  insert(tenant, kind, id, value, at) {
    requireThat(!this.get(tenant, kind, id), 'INV-409-CONFLICT', 'Record already exists', 409); this.put(tenant, kind, id, value, at);
  }
  list(tenant, kind, limit = 500, offset = 0) {
    return this.db.prepare('SELECT id,value FROM records WHERE tenant=? AND kind=? ORDER BY created DESC,id LIMIT ? OFFSET ?').all(tenant, kind, limit, offset)
      .map(row => decrypt(row.value, this.dek(tenant, kind, row.id) ?? this.key(tenant), `${tenant}/${kind}/${row.id}`));
  }
  remove(tenant, kind, id) {
    this.db.prepare('DELETE FROM deks WHERE tenant=? AND kind=? AND id=?').run(tenant, kind, id);
    this.db.prepare('DELETE FROM records WHERE tenant=? AND kind=? AND id=?').run(tenant, kind, id);
  }
  shred(tenant, kind, id) {
    // Crypto-shredding: destroy the record DEK (secure_delete zeroes its
    // page) and drop the ciphertext; then truncate the WAL so no reachable
    // copy of the wrapped key remains. Pre-erasure backups are out of scope
    // and stay honest in the retention report.
    const changes = this.db.prepare('DELETE FROM deks WHERE tenant=? AND kind=? AND id=?').run(tenant, kind, id).changes
      + this.db.prepare('DELETE FROM records WHERE tenant=? AND kind=? AND id=?').run(tenant, kind, id).changes;
    this._shredded = this._shredded || changes > 0;
    return changes > 0;
  }
  // Call outside any transaction: truncates the WAL after shredding so no
  // reachable copy of a destroyed wrapped DEK remains in the log.
  checkpoint() {
    if (this._shredded) { this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); this._shredded = false; }
  }
  clock(now) {
    requireThat(Number.isSafeInteger(now) && now > 0, 'INV-503-TIME', 'Clock unavailable', 503);
    const row = this.db.prepare('SELECT last FROM clock WHERE id=1').get();
    requireThat(!row || now >= row.last, 'INV-503-TIME', 'Clock regression; security operations halted', 503);
    this.db.prepare('INSERT INTO clock VALUES(1,?) ON CONFLICT(id) DO UPDATE SET last=excluded.last').run(now);
  }
  audit(tenant, type, actor, reference, metadata, now) {
    const last = this.db.prepare('SELECT seq,hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get(tenant);
    const entry = { tenant_id: tenant, sequence: (last?.seq ?? 0) + 1, previous: last?.hash ?? '0'.repeat(64), type, actor, reference, metadata, time: now };
    const hash = digest(entry), envelope = this.auditSigners[tenant].sign(entry);
    this.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run(tenant, entry.sequence, entry.previous, hash, canonical(envelope));
    return { hash, envelope };
  }
  auditHashes(tenant) {
    return this.db.prepare('SELECT hash FROM audit WHERE tenant=? ORDER BY seq').all(tenant).map(r => r.hash);
  }
  auditPage(tenant, { after = 0, limit = 1000 } = {}) {
    const rows = this.db.prepare('SELECT seq,hash,envelope FROM audit WHERE tenant=? AND seq>? ORDER BY seq LIMIT ?').all(tenant, after, limit);
    return { entries: rows.map(r => ({ sequence: r.seq, hash: r.hash, envelope: JSON.parse(r.envelope) })), next_cursor: rows.length === limit ? rows.at(-1).seq : null };
  }
  auditExport(tenant) {
    const rows = this.db.prepare('SELECT hash,envelope FROM audit WHERE tenant=? ORDER BY seq').all(tenant).map(r => ({ hash: r.hash, envelope: JSON.parse(r.envelope) }));
    const signer = this.auditSigners[tenant], public_keys = signer.keys ? signer.keys() : { [signer.key_id]: { public_key: signer.public_key } };
    const checkpoint = signer.sign({ tenant_id: tenant, size: rows.length, head: rows.at(-1)?.hash ?? '0'.repeat(64), tree_head: merkleRoot(rows.map(r => r.hash)) }, 'checkpoint');
    return { format: 'IF-AUDIT-1', public_keys, checkpoint, entries: rows };
  }
  idempotent(tenant, scope, key, requestHash, fn) {
    requireThat(typeof key === 'string' && /^[A-Za-z0-9_-]{8,128}$/.test(key), 'INV-400-SCHEMA', 'An 8–128 character Idempotency-Key is required');
    const row = this.db.prepare('SELECT hash,result FROM idempotency WHERE tenant=? AND scope=? AND key=?').get(tenant, scope, key);
    if (row) {
      requireThat(row.hash === requestHash, 'INV-409-IDEMPOTENCY', 'Idempotency key reused for a different request', 409);
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
  let previous = '0'.repeat(64), sequence = 0, time = 0;
  for (const item of bundle.entries) {
    const entry = verifySigned(item.envelope, pinnedKeys, 'audit');
    requireThat(entry.tenant_id === checkpoint.tenant_id && entry.sequence === ++sequence && entry.previous === previous && entry.time >= time && digest(entry) === item.hash, 'INV-409-AUDIT', 'Audit continuity failure', 409);
    previous = item.hash; time = entry.time;
    if (priorCheckpoint && sequence === priorCheckpoint.size) requireThat(previous === priorCheckpoint.head, 'INV-409-FORK', 'Witness checkpoint disagrees', 409);
  }
  requireThat(checkpoint.size === sequence && checkpoint.head === previous && (!priorCheckpoint || (checkpoint.tenant_id === priorCheckpoint.tenant_id && sequence >= priorCheckpoint.size)), 'INV-409-AUDIT', 'Missing or inconsistent checkpoint', 409);
  return { valid: true, entries: sequence, head: previous, tenant_id: checkpoint.tenant_id };
}

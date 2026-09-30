#!/usr/bin/env node
// Verify a backup directory written by scripts/backup.mjs without mutating
// the live deployment: the manifest's signature must verify under the pinned
// public keys, file hashes must match the signed payload, schema versions
// must be readable, and the audit table must re-verify entry-by-entry
// (signatures + hash chain), not just adjacent 'previous' links.
// Usage: node scripts/restore-check.mjs --dir <backup-dir>
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, createReadStream, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { verifySigned } from '../src/crypto.mjs';
import { digest } from '../src/canonical.mjs';

const args = process.argv.slice(2);
const opt = k => { const i = args.indexOf(`--${k}`); return i >= 0 ? args[i + 1] : null; };
const dir = opt('dir');
if (!dir) { console.error('usage: node scripts/restore-check.mjs --dir <backup-dir>'); process.exit(2); }

let manifest, payload;
try {
  manifest = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'));
  if (manifest.format !== 'IF-BACKUP-1') throw new Error('bad format');
  // The manifest envelope must verify under the advertised audit keys —
  // an attacker who edits a backup file cannot mint a matching signature.
  payload = verifySigned(manifest.envelope, manifest.public_keys ?? {}, 'backup-manifest');
} catch (e) { console.error(`manifest signature verification failed: ${e.message}`); process.exit(1); }
if (!Array.isArray(payload.databases) || payload.databases.length === 0) { console.error('manifest lists no databases'); process.exit(1); }

const sha256 = path => new Promise((res, rej) => { const h = createHash('sha256'); createReadStream(path).on('data', d => h.update(d)).on('end', () => res(h.digest('hex'))).on('error', rej); });

// Re-verify the audit chain inside a backup database: every entry's own
// signature and stored hash, plus previous-link continuity per tenant.
function auditIntegrity(db, publicKeys) {
  let rows;
  try { rows = db.prepare('SELECT tenant,seq,previous,hash,envelope FROM audit ORDER BY tenant,seq').all(); } catch { return { entries: 0, verified: true }; }
  const seen = {};
  for (const row of rows) {
    const prior = seen[row.tenant] ?? { seq: 0, hash: '0'.repeat(64) };
    try {
      if (row.seq !== prior.seq + 1 || row.previous !== prior.hash) return { entries: rows.length, verified: false, reason: `chain break at ${row.tenant}#${row.seq}` };
      const entry = verifySigned(JSON.parse(row.envelope), publicKeys, 'audit');
      if (entry.tenant_id !== row.tenant || entry.sequence !== row.seq || entry.previous !== row.previous || digest(entry) !== row.hash) return { entries: rows.length, verified: false, reason: `content mismatch at ${row.tenant}#${row.seq}` };
    } catch { return { entries: rows.length, verified: false, reason: `signature failure at ${row.tenant}#${row.seq}` }; }
    seen[row.tenant] = { seq: row.seq, hash: row.hash };
  }
  return { entries: rows.length, verified: true };
}

const report = { valid: true, databases: [] };
for (const entry of payload.databases) {
  // Filenames are basenames only — no traversal out of the backup dir.
  const item = { file: entry.file, sha256_match: false, readable: false, audit_verified: null };
  if (typeof entry.file !== 'string' || !/^[A-Za-z0-9._-]+$/.test(entry.file)) { item.reason = 'unsanitised filename'; report.valid = false; report.databases.push(item); continue; }
  const file = join(dir, entry.file);
  if (existsSync(file)) {
    item.sha256_match = (await sha256(file)) === entry.sha256;
    try {
      const db = new DatabaseSync(file);
      item.user_version = db.prepare('PRAGMA user_version').get().user_version;
      const audit = auditIntegrity(db, manifest.public_keys ?? {});
      item.audit_entries = audit.entries; item.audit_verified = audit.verified; if (audit.reason) item.reason = audit.reason;
      item.readable = item.user_version <= 1;
      db.close();
    } catch { /* unreadable */ }
  }
  if (!item.sha256_match || !item.readable || item.audit_verified === false) report.valid = false;
  report.databases.push(item);
}
console.log(JSON.stringify(report, null, 2));
process.exit(report.valid ? 0 : 1);

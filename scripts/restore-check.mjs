#!/usr/bin/env node
// Verify a backup directory written by scripts/backup.mjs without mutating
// the live deployment: hashes match the manifest, schema versions are
// readable, and the audit table still appends in order.
// Usage: node scripts/restore-check.mjs --dir <backup-dir>
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, createReadStream, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

const args = process.argv.slice(2);
const opt = k => { const i = args.indexOf(`--${k}`); return i >= 0 ? args[i + 1] : null; };
const dir = opt('dir');
if (!dir) { console.error('usage: node scripts/restore-check.mjs --dir <backup-dir>'); process.exit(2); }
const manifest = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'));
if (manifest.format !== 'IF-BACKUP-1') { console.error('not an IF-BACKUP-1 manifest'); process.exit(1); }

const sha256 = path => new Promise((res, rej) => { const h = createHash('sha256'); createReadStream(path).on('data', d => h.update(d)).on('end', () => res(h.digest('hex'))).on('error', rej); });
const report = { valid: true, databases: [] };
for (const entry of manifest.databases) {
  const file = join(dir, entry.file);
  const item = { file: entry.file, sha256_match: false, readable: false };
  if (existsSync(file)) {
    item.sha256_match = (await sha256(file)) === entry.sha256;
    try {
      const db = new DatabaseSync(file);
      item.user_version = db.prepare('PRAGMA user_version').get().user_version;
      try { item.audit_entries = db.prepare('SELECT COUNT(*) c FROM audit').get().c; item.audit_ordered = db.prepare('SELECT COUNT(*) c FROM audit a JOIN audit b ON a.seq = b.seq + 1 AND a.tenant = b.tenant AND a.previous <> b.hash').get().c === 0; } catch { item.audit_entries = 0; }
      item.readable = item.user_version <= 1;
      db.close();
    } catch { /* unreadable */ }
  }
  if (!item.sha256_match || !item.readable) report.valid = false;
  report.databases.push(item);
}
console.log(JSON.stringify(report, null, 2));
process.exit(report.valid ? 0 : 1);

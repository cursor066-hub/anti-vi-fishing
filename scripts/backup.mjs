#!/usr/bin/env node
// Online backup of the fabric SQLite stores using the engine's own backup
// API (consistent snapshot under WAL — never a raw file copy of a live db).
// Usage: node scripts/backup.mjs --dir <deployment-dir> --out <backup-dir>
import { DatabaseSync, backup } from 'node:sqlite';
import { mkdirSync, writeFileSync, chmodSync, createReadStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, basename } from 'node:path';

const args = process.argv.slice(2);
const opt = k => { const i = args.indexOf(`--${k}`); return i >= 0 ? args[i + 1] : null; };
const dir = opt('dir'), out = opt('out');
if (!dir || !out) { console.error('usage: node scripts/backup.mjs --dir <deployment> --out <backup-dir>'); process.exit(2); }

const sha256 = path => new Promise((res, rej) => { const h = createHash('sha256'); createReadStream(path).on('data', d => h.update(d)).on('end', () => res(h.digest('hex'))).on('error', rej); });

const databases = ['fabric.db', 'target.db'].map(n => join(dir, n));
mkdirSync(out, { recursive: true, mode: 0o700 });
const manifest = { format: 'IF-BACKUP-1', created_at: new Date().toISOString(), source_dir: dir, databases: [] };
for (const src of databases) {
  let db;
  try { db = new DatabaseSync(src); } catch { console.error(`skip missing ${src}`); continue; }
  const dest = join(out, basename(src));
  db.exec('PRAGMA wal_checkpoint(FULL)');
  await backup(db, dest);
  const version = db.prepare('PRAGMA user_version').get().user_version;
  db.close();
  chmodSync(dest, 0o600);
  manifest.databases.push({ file: basename(src), sha256: await sha256(dest), user_version: version });
}
// Key material lives outside the database (vault file / config); a complete
// deployment backup must include them separately under custodian control.
writeFileSync(join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { mode: 0o600 });
console.log(JSON.stringify(manifest));

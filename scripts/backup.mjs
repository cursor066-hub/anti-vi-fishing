#!/usr/bin/env node
// Online backup of the fabric SQLite stores using the engine's own backup
// API (consistent snapshot under WAL — never a raw file copy of a live db).
// The manifest is SIGNED with the tenant audit key so a tampered backup
// cannot re-certify itself by recomputing hashes (store-audit HIGH-3).
// Usage: node scripts/backup.mjs --dir <deployment-dir> --out <backup-dir>
import { DatabaseSync, backup } from 'node:sqlite';
import { mkdirSync, writeFileSync, readFileSync, chmodSync, createReadStream, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, basename } from 'node:path';
import { signed } from '../src/crypto.mjs';
import { KeyVault } from '../src/keystore.mjs';

const args = process.argv.slice(2);
const opt = k => { const i = args.indexOf(`--${k}`); return i >= 0 ? args[i + 1] : null; };
const dir = opt('dir'), out = opt('out');
if (!dir || !out) { console.error('usage: node scripts/backup.mjs --dir <deployment> --out <backup-dir>'); process.exit(2); }

const sha256 = path => new Promise((res, rej) => { const h = createHash('sha256'); createReadStream(path).on('data', d => h.update(d)).on('end', () => res(h.digest('hex'))).on('error', rej); });

// Resolve the manifest signer: the deployment vault when present, otherwise
// the embedded audit key of the first tenant (dev/test custody).
const configPath = join(dir, 'config.json');
const config = existsSync(configPath) ? JSON.parse(readFileSync(configPath, 'utf8')) : null;
const firstTenant = config ? Object.values(config.tenants ?? {})[0] : null;
const public_keys = {};
if (config) for (const t of Object.values(config.tenants ?? {})) public_keys[t.keys.audit.key_id] = { public_key: t.keys.audit.public_key };
let signManifest = null;
const masterPath = join(dir, 'master.key'), storePath = join(dir, 'keystore.json');
if (existsSync(masterPath) && existsSync(storePath)) {
  const vault = KeyVault.load(storePath, JSON.parse(readFileSync(masterPath, 'utf8')).master_key);
  // Signer: the configured audit key, else the first vault key purpose-bound
  // to 'backup-manifest' (config-less dirs still sign honestly).
  const configured = firstTenant?.keys?.audit?.key_id;
  const kid = configured ?? vault.list().find(e => (Array.isArray(e.purpose) ? e.purpose : [e.purpose]).includes('backup-manifest') && !e.pending && !e.revoked)?.key_id;
  if (kid) signManifest = payload => vault.envelope(kid, 'backup-manifest', payload);
  if (!configured) for (const e of vault.list()) if ((Array.isArray(e.purpose) ? e.purpose : [e.purpose]).includes('backup-manifest')) public_keys[e.key_id] = { public_key: e.public_key };
} else if (firstTenant?.keys?.audit?.private_key) {
  const audit = firstTenant.keys.audit;
  signManifest = payload => signed(payload, { key_id: audit.key_id, private_key: audit.private_key, suite: audit.suite ?? 'Ed25519' }, 'backup-manifest');
}
if (!signManifest) { console.error('cannot sign the backup manifest: no vault or embedded audit key in the deployment directory'); process.exit(1); }

const databases = ['fabric.db', 'target.db'].map(n => join(dir, n));
mkdirSync(out, { recursive: true, mode: 0o700 });
const payload = { format: 'IF-BACKUP-1', created_at: new Date().toISOString(), source_dir: dir, databases: [] };
for (const src of databases) {
  // DatabaseSync CREATES a missing file — probing existence first keeps an
  // absent source from producing a certified empty backup (w7-backup F2).
  if (!existsSync(src)) { console.error(`skip missing ${src}`); continue; }
  let db;
  try { db = new DatabaseSync(src); } catch { console.error(`skip unreadable ${src}`); continue; }
  const dest = join(out, basename(src));
  // TRUNCATE, not FULL: no -wal sidecar may survive next to the artifact —
  // an unhashed sidecar would control the view a verifier opens
  // (w7-backup F4).
  db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  await backup(db, dest);
  const version = db.prepare('PRAGMA user_version').get().user_version;
  const entry = { file: basename(src), sha256: await sha256(dest), user_version: version };
  // Commit each tenant's audit head into the signed payload — a
  // tail-truncated backup must fail verification instead of re-certifying
  // (w7-backup F3).
  try {
    const heads = {};
    for (const row of db.prepare('SELECT tenant,seq,hash FROM audit ORDER BY tenant,seq').all()) heads[row.tenant] = { entries: row.seq, head_hash: row.hash };
    entry.audit_heads = heads;
  } catch { /* this database carries no audit table */ }
  db.close();
  chmodSync(dest, 0o600);
  payload.databases.push(entry);
}
if (!payload.databases.length) { console.error('no databases were backed up'); process.exit(1); }
// Key material lives outside the database (vault file / config); a complete
// deployment backup must include them separately under custodian control.
const manifest = { format: 'IF-BACKUP-1', envelope: signManifest(payload), public_keys };
writeFileSync(join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { mode: 0o600 });
console.log(JSON.stringify(payload));

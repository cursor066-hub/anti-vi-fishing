#!/usr/bin/env node
// Verify a backup directory written by scripts/backup.mjs without mutating
// the live deployment. The manifest's signature must verify under a trust
// anchor OUTSIDE the artifact (--trusted-keys — a deployment config.json or
// a {key_id: {public_key}} map), file hashes must match the signed payload,
// the audit table must re-verify entry-by-entry (signatures + hash chain +
// the committed per-tenant head/length), and cross-database references must
// be consistent. The artifact's own advertised keys are informational only —
// a self-certifying manifest would let a write-only attacker re-sign a
// forged backup (w7-backup F1).
// Usage: node scripts/restore-check.mjs --dir <backup-dir> --trusted-keys <file>
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, createReadStream, existsSync, lstatSync, realpathSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { verifySigned } from '../src/crypto.mjs';
import { digest } from '../src/canonical.mjs';

const args = process.argv.slice(2);
// A flag never satisfies an option's value (same guard as backup.mjs).
const opt = k => { const i = args.indexOf(`--${k}`); const v = i >= 0 ? args[i + 1] : null; return v && !v.startsWith('--') ? v : null; };
const dir = opt('dir'), trustedPath = opt('trusted-keys');
if (!dir || !trustedPath) { console.error('usage: node scripts/restore-check.mjs --dir <backup-dir> --trusted-keys <config.json|key-map.json>'); process.exit(2); }

// The trust anchor MUST live outside the artifact — an anchor file inside
// --dir is authored by the same hand that wrote the manifest, so the whole
// verification self-certifies (w23-supply F1).
{
  const dirReal = realpathSync(dir), anchorReal = realpathSync(trustedPath);
  if (anchorReal === dirReal || anchorReal.startsWith(`${dirReal}/`)) { console.error('trust anchor must live OUTSIDE the backup directory — an in-tree anchor self-certifies'); process.exit(2); }
}

// External trust anchor: either a deployment config.json (audit keys are
// extracted per tenant — execution keys and other tenants' audit keys never
// validate audit rows) or a raw {key_id: {public_key}} map (w8-tooling F1).
let trustedFlat, trustedFor, anchorIsConfig = false;
try {
  const raw = JSON.parse(readFileSync(trustedPath, 'utf8'));
  if (raw.tenants) {
    anchorIsConfig = true;
    const perTenant = {};
    for (const [name, t] of Object.entries(raw.tenants))
      for (const k of [t.keys?.audit].filter(Boolean)) perTenant[name] = { [k.key_id]: { public_key: k.public_key } };
    trustedFlat = Object.assign({}, ...Object.values(perTenant));
    trustedFor = tenant => perTenant[tenant] ?? {};
  } else {
    trustedFlat = raw;
    trustedFor = () => trustedFlat;
  }
  if (!Object.keys(trustedFlat ?? {}).length) throw new Error('empty trust anchor');
} catch (e) { console.error(`cannot load trusted keys: ${e.message}`); process.exit(2); }

let manifest, payload;
try {
  manifest = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'));
  if (manifest.format !== 'IF-BACKUP-1') throw new Error('bad format');
  payload = verifySigned(manifest.envelope, trustedFlat, 'backup-manifest');
} catch (e) { console.error(`manifest signature verification failed: ${e.message}`); process.exit(1); }
if (!Array.isArray(payload.databases) || payload.databases.length === 0) { console.error('manifest lists no databases'); process.exit(1); }
// A BARE key-map anchor that is verbatim the manifest's own advertised key
// map is the artifact supplying its own anchor — refuse even if it sat
// outside --dir (w23-supply F1). A deployment config is exempt: it is
// operator custody established independently of the artifact, and a
// manifest that verifies under it was signed by the real audit key (a
// forged backup never survives the signature check above).
if (!anchorIsConfig && manifest.public_keys && digest(manifest.public_keys) === digest(trustedFlat)) { console.error('trusted keys equal the manifest\'s advertised key map — the artifact supplied its own anchor'); process.exit(1); }
if (payload.complete === false) console.error('WARNING: manifest declares an incomplete (partial) backup — expected databases are missing');
// Signed provenance is verified and surfaced — a replayed or foreign
// deployment's backup must be visibly attributable (w8-tooling F2/F5).
if (payload.format !== 'IF-BACKUP-1' || typeof payload.source_dir !== 'string' || typeof payload.created_at !== 'string') { console.error('manifest payload lacks signed format/source_dir/created_at'); process.exit(1); }

const sha256 = path => new Promise((res, rej) => { const h = createHash('sha256'); createReadStream(path).on('data', d => h.update(d)).on('end', () => res(h.digest('hex'))).on('error', rej); });

// Re-verify the audit chain inside a backup database: every entry's own
// signature and stored hash, previous-link continuity per tenant — and the
// per-tenant head (length + final hash) must equal the manifest's signed
// commitment, so a suffix-truncated backup cannot pass (w7-backup F3).
function auditIntegrity(db, publicKeysFor, committed) {
  let rows;
  try { rows = db.prepare('SELECT tenant,seq,previous,hash,envelope FROM audit ORDER BY tenant,seq').all(); }
  catch { return { entries: 0, verified: false, reason: 'audit table missing' }; }
  const seen = {};
  for (const row of rows) {
    const prior = seen[row.tenant] ?? { seq: 0, hash: '0'.repeat(64) };
    try {
      if (row.seq !== prior.seq + 1 || row.previous !== prior.hash) return { entries: rows.length, verified: false, reason: `chain break at ${row.tenant}#${row.seq}` };
      const entry = verifySigned(JSON.parse(row.envelope), publicKeysFor(row.tenant), 'audit');
      if (entry.tenant_id !== row.tenant || entry.sequence !== row.seq || entry.previous !== row.previous || digest(entry) !== row.hash) return { entries: rows.length, verified: false, reason: `content mismatch at ${row.tenant}#${row.seq}` };
    } catch { return { entries: rows.length, verified: false, reason: `signature failure at ${row.tenant}#${row.seq}` }; }
    seen[row.tenant] = { seq: row.seq, hash: row.hash };
  }
  if (committed) for (const [tenant, head] of Object.entries(committed)) {
    const live = seen[tenant];
    if (!live || live.seq !== head.entries || live.hash !== head.head_hash) return { entries: rows.length, verified: false, reason: `audit head mismatch for ${tenant}` };
    if (!seen[tenant] || !Object.keys(trustedFor(tenant)).length) return { entries: rows.length, verified: false, reason: `no trusted audit key for ${tenant}` };
  }
  return { entries: rows.length, verified: true, heads: seen };
}

const report = { valid: true, databases: [] };
const opened = {};
for (const entry of payload.databases) {
  // Filenames are basenames only — no traversal, no dotfiles, no '.'/'..'
  // (w7-backup F6).
  const item = { file: entry.file, sha256_match: false, readable: false, audit_verified: null };
  if (typeof entry.file !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+)*$/.test(entry.file)) { item.reason = 'unsanitised filename'; report.valid = false; report.databases.push(item); continue; }
  const file = join(dir, entry.file);
  if (!existsSync(file)) { report.valid = false; report.databases.push(item); continue; }
  // A symlinked artifact or an unhashed WAL sidecar means the bytes we hash
  // and the bytes we open are not the bytes the manifest committed
  // (w7-backup F4).
  if (lstatSync(file).isSymbolicLink()) { item.reason = 'symlinked artifact'; report.valid = false; report.databases.push(item); continue; }
  if (existsSync(`${file}-wal`)) { item.reason = 'unhashed wal sidecar present'; report.valid = false; report.databases.push(item); continue; }
  item.sha256_match = (await sha256(file)) === entry.sha256;
  try {
    const db = new DatabaseSync(file);
    item.user_version = db.prepare('PRAGMA user_version').get().user_version;
    const hasAudit = db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit'").get() !== undefined;
    const committed = entry.audit_heads;
    // A db the manifest says carries audit history must actually carry it —
    // a dropped table is not a vacuous pass (w7-backup F7).
    if (committed && !hasAudit) { item.audit_verified = false; item.reason = 'committed audit history but audit table missing'; }
    else if (hasAudit) {
      // A db carrying an audit table under a manifest that committed no
      // audit_heads cannot prove it is not suffix-truncated (w8-tooling F5).
      if (!committed) { item.audit_verified = false; item.reason = 'audit table present but manifest committed no heads'; report.valid = false; report.databases.push(item); db.close(); continue; }
      const audit = auditIntegrity(db, trustedFor, committed);
      item.audit_entries = audit.entries; item.audit_verified = audit.verified; if (audit.reason) item.reason = audit.reason;
      opened[entry.file] = { db, auditHeads: audit.heads };
    } else opened[entry.file] = { db };
    item.readable = item.user_version <= 1;
    // Committed schema level must match the live db — a different
    // user_version under a matching hash means the manifest lied
    // (w8-tooling F5).
    if (item.readable && entry.user_version !== undefined && entry.user_version !== item.user_version) { item.reason = 'user_version mismatch'; item.readable = false; }
    if (!opened[entry.file]) db.close();
  } catch { /* unreadable */ }
  if (!item.sha256_match || !item.readable || item.audit_verified === false) report.valid = false;
  report.databases.push(item);
}

// Cross-database consistency: sequential snapshots can pair a target.db
// write with a fabric.db that predates it — every recorded transaction must
// resolve to a certificate in the same backup's fabric.db (w7-backup F5).
const fabricDb = opened['fabric.db']?.db, targetDb = opened['target.db']?.db;
if (fabricDb && targetDb) {
  try {
    const certIds = new Set(fabricDb.prepare("SELECT id FROM records WHERE kind='certificate'").all().map(r => r.id));
    const orphans = targetDb.prepare('SELECT id FROM transactions').all().filter(r => !certIds.has(r.id));
    if (orphans.length) { report.valid = false; report.databases.push({ file: 'target.db', reason: `torn cross-database snapshot: ${orphans.length} transaction(s) without a certificate` }); }
  } catch {
    // A skipped check is a finding, not a pass — a db lacking the schema
    // this check needs cannot silently verify clean (w23-supply F13).
    report.databases.push({ file: 'cross-database', reason: 'cross-database consistency check could not run — required tables absent (integrity unproven)' });
    report.skipped_checks = [...(report.skipped_checks ?? []), 'cross-database-consistency'];
  }
}
for (const { db } of Object.values(opened)) db.close();
// Every file in --dir must be manifest-accounted — an unlisted extra
// (planted script, WAL sidecar of a non-listed db) is uninspected content
// riding on a signed manifest (w23-supply F13).
{
  const listed = new Set([...payload.databases.map(d => d.file), 'manifest.json']);
  const extras = readdirSync(dir).filter(f => !listed.has(f));
  if (extras.length) { report.valid = false; report.extra_files = extras; }
}
report.manifest = { signer_key_id: manifest.envelope?.protected?.key_id ?? null, source_dir: payload.source_dir, created_at: payload.created_at, complete: payload.complete ?? true };
console.log(JSON.stringify(report, null, 2));
process.exit(report.valid ? 0 : 1);

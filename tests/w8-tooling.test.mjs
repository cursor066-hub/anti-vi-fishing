import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { bootstrap, loadConfiguration } from '../src/bootstrap.mjs';
import { Fabric } from '../src/fabric.mjs';
import { KeyVault } from '../src/keystore.mjs';
import { generateKey, signed, verifySigned } from '../src/crypto.mjs';
import { canonical, digest } from '../src/canonical.mjs';
import { createHash } from 'node:crypto';

const root = new URL('..', import.meta.url).pathname;
const node = process.execPath;
const run = (script, args) => spawnSync(node, [join(root, script), ...args], { encoding: 'utf8' });

function deployment(t, tenants = ['acme', 'globex']) {
  const base = mkdtempSync(join(tmpdir(), 'if-w8tool-'));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const dir = join(base, 'dep');
  bootstrap(dir, tenants);
  const f = new Fabric(loadConfiguration(dir), dir);
  for (const tenant of tenants) f.store.put(tenant, 'note', `n-${tenant}`, { v: 1 }, Date.now());
  f.close();
  return dir;
}

test('W8-TOOLING restore-check: execution keys never join the audit trust anchor (F1)', t => {
  const dir = deployment(t), out = join(dir, 'backup');
  assert.equal(run('scripts/backup.mjs', ['--dir', dir, '--out', out]).status, 0);
  const clean = run('scripts/restore-check.mjs', ['--dir', out, '--trusted-keys', join(dir, 'config.json')]);
  assert.equal(clean.status, 0, clean.stderr);
  const report = JSON.parse(clean.stdout);
  assert.equal(report.valid, true);
  // Signed provenance is surfaced so a replayed backup is attributable (F2).
  assert.equal(typeof report.manifest.signer_key_id, 'string');
  assert.equal(report.manifest.source_dir, dir);
  assert.equal(typeof report.manifest.created_at, 'string');

  // Forge: re-sign acme's audit chain with an attacker key planted in the
  // trust anchor's EXECUTION slot, then honestly re-commit heads, file hash
  // and manifest signature. A flat key map verifies this; audit-only anchors
  // must fail.
  const cfg = loadConfiguration(dir);
  const auditK = cfg.tenants.acme.keys.audit;
  const planted = generateKey();
  const db = new DatabaseSync(join(out, 'fabric.db'));
  // Lift the append-only trigger inside the artifact copy to replay rows —
  // the deploy-time audit table correctly refuses updates.
  for (const t of db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all()) db.exec(`DROP TRIGGER ${t.name}`);
  const rows = db.prepare("SELECT seq, envelope FROM audit WHERE tenant='acme' ORDER BY seq").all();
  assert.ok(rows.length >= 1);
  let lastHash;
  for (const row of rows) {
    const entry = verifySigned(JSON.parse(row.envelope), { [auditK.key_id]: { public_key: auditK.public_key } }, 'audit');
    const forged = signed(entry, { key_id: planted.key_id, private_key: planted.private_key, suite: planted.suite }, 'audit');
    lastHash = digest(entry);
    db.prepare("UPDATE audit SET envelope=?, hash=? WHERE tenant='acme' AND seq=?").run(JSON.stringify(forged), lastHash, row.seq);
  }
  db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  db.close();
  const vault = KeyVault.load(join(dir, 'keystore.json'), JSON.parse(readFileSync(join(dir, 'master.key'), 'utf8')).master_key);
  const manifest = JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8'));
  const payload = manifest.envelope.payload;
  const fabricEntry = payload.databases.find(d => d.file === 'fabric.db');
  fabricEntry.audit_heads = { ...fabricEntry.audit_heads, acme: { entries: rows.length, head_hash: lastHash } };
  fabricEntry.sha256 = createHash('sha256').update(readFileSync(join(out, 'fabric.db'))).digest('hex');
  manifest.envelope = vault.envelope(auditK.key_id, 'backup-manifest', payload);
  writeFileSync(join(out, 'manifest.json'), canonical(manifest) + '\n', { mode: 0o600 });

  // Anchor copy that names the planted key under keys.execution — a flat
  // extraction would admit it; audit-only scoping must not.
  const tamperedCfg = JSON.parse(readFileSync(join(dir, 'config.json'), 'utf8'));
  tamperedCfg.tenants.acme.keys.execution = { key_id: planted.key_id, public_key: planted.public_key };
  const trustedPath = join(dir, 'trusted-tampered.json');
  writeFileSync(trustedPath, canonical(tamperedCfg) + '\n', { mode: 0o600 });
  const tampered = run('scripts/restore-check.mjs', ['--dir', out, '--trusted-keys', trustedPath]);
  assert.equal(tampered.status, 1);
  const bad = JSON.parse(tampered.stdout).databases.find(d => d.file === 'fabric.db');
  assert.equal(bad.audit_verified, false);
  assert.match(bad.reason, /signature failure/);
});

test('W8-TOOLING restore-check: db carrying audit table without committed heads fails (F5)', t => {
  const dir = deployment(t), out = join(dir, 'backup');
  assert.equal(run('scripts/backup.mjs', ['--dir', dir, '--out', out]).status, 0);
  const cfg = loadConfiguration(dir), auditK = cfg.tenants.acme.keys.audit;
  const vault = KeyVault.load(join(dir, 'keystore.json'), JSON.parse(readFileSync(join(dir, 'master.key'), 'utf8')).master_key);
  const manifest = JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8'));
  const payload = manifest.envelope.payload;
  for (const d of payload.databases) delete d.audit_heads;
  manifest.envelope = vault.envelope(auditK.key_id, 'backup-manifest', payload);
  writeFileSync(join(out, 'manifest.json'), canonical(manifest) + '\n', { mode: 0o600 });
  const r = run('scripts/restore-check.mjs', ['--dir', out, '--trusted-keys', join(dir, 'config.json')]);
  assert.equal(r.status, 1);
  assert.ok(JSON.parse(r.stdout).databases.some(d => d.reason === 'audit table present but manifest committed no heads'));
});

test('W8-TOOLING cli sign: keyfile consistency + option parse errors (F7)', t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-w8cli-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const key = generateKey(), keyPath = join(dir, 'k.json'), input = join(dir, 'in.json'), output = join(dir, 'out.json');
  writeFileSync(keyPath, JSON.stringify(key), { mode: 0o600 });
  writeFileSync(input, canonical({ a: 1 }) + '\n');
  const ok = run('src/cli.mjs', ['sign', '--key', keyPath, '--input', input, '--output', output]);
  assert.equal(ok.status, 0, ok.stderr);
  assert.ok(verifySigned(JSON.parse(readFileSync(output, 'utf8')), { [key.key_id]: { public_key: key.public_key } }, 'action-approval'));

  const bad = { ...key, public_key: generateKey().public_key };
  writeFileSync(keyPath, JSON.stringify(bad), { mode: 0o600 });
  const badKey = run('src/cli.mjs', ['sign', '--key', keyPath, '--input', input, '--output', output + '2']);
  assert.equal(badKey.status, 1);
  assert.match(badKey.stderr, /INV-401-SIGNATURE/);

  // A flag in value position is a parse error — never a filename (F7).
  const flag = run('src/cli.mjs', ['sign', '--key', keyPath, '--input', input, '--output', '--purpose']);
  assert.equal(flag.status, 1);
  assert.match(flag.stderr, /INV-400-SCHEMA/);
});

test('W8-TOOLING cli init: duplicated tenants dedupe instead of half-writing (F9)', t => {
  const dir = join(mkdtempSync(join(tmpdir(), 'if-w8init-')), 'dep');
  const r = run('src/cli.mjs', ['init', '--dir', dir, '--tenants', 'acme,acme,globex']);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(Object.keys(loadConfiguration(dir).tenants).sort(), ['acme', 'globex']);
});

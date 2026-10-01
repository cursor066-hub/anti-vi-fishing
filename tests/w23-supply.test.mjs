// w23-supply regression suite — the release/tooling auditor's findings on
// 1305cfe: flags may never be swallowed as option values, trust anchors
// never live inside the artifact they anchor, signing keys require 0600,
// missing trees and manifests fail closed, and the foreign-cwd webcrypto
// verifier anchors its corpus to the repo.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const ROOT = new URL('..', import.meta.url).pathname;
const run = (file, args, opts = {}) => spawnSync(process.execPath, [join(ROOT, file), ...args], { encoding: 'utf8', timeout: 120000, ...opts });
const py = (file, args) => spawnSync('python3', [join(ROOT, file), ...args], { encoding: 'utf8', timeout: 60000 });

// F3: a flag must never satisfy an option's value — `--out` followed by
// another flag is a usage error, not a directory named after the flag.
test('w23 F3a: backup --out refuses a flag-shaped value', () => {
  const dir = mkdtempSync(join(tmpdir(), 'w23-dep-'));
  try {
    const out = run('scripts/backup.mjs', ['--dir', dir, '--out', '--allow-partial']);
    assert.equal(out.status, 2);
    assert.match(out.stderr, /usage/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('w23 F3b: restore-check --trusted-keys refuses a flag-shaped value', () => {
  const dir = mkdtempSync(join(tmpdir(), 'w23-dep-'));
  try {
    const out = run('scripts/restore-check.mjs', ['--dir', dir, '--trusted-keys', '--out']);
    assert.equal(out.status, 2);
    assert.match(out.stderr, /usage/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// F10: a backup equal in/out pair is an in-place rewrite — refused before
// any vault or database is touched.
test('w23 F10: backup --out equal to --dir is refused', () => {
  const dir = mkdtempSync(join(tmpdir(), 'w23-dep-'));
  try {
    const out = run('scripts/backup.mjs', ['--dir', dir, '--out', dir]);
    assert.equal(out.status, 2);
    assert.match(out.stderr, /must not equal/i);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// F11: a deployment without its databases is a failed backup unless
// --allow-partial is declared — never a silently empty manifest.
test('w23 F11: backup of a database-less deployment exits 1', () => {
  const dir = mkdtempSync(join(tmpdir(), 'w23-dep-'));
  const out = mkdtempSync(join(tmpdir(), 'w23-out-'));
  try {
    writeFileSync(join(dir, 'config.json'), JSON.stringify({ tenants: {} }));
    const res = run('scripts/backup.mjs', ['--dir', dir, '--out', out]);
    assert.equal(res.status, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); rmSync(out, { recursive: true, force: true }); }
});

// F14: a world-readable signing key is refused — the file mode must be
// exactly 0600 before a single byte of key material is read for signing.
test('w23 F14: release-sign refuses a signing key with permissive mode', () => {
  const dir = mkdtempSync(join(tmpdir(), 'w23-sign-'));
  try {
    const key = join(dir, 'key.pem'), pub = join(dir, 'key.pub');
    const pair = generateKeyPairSync('ed25519');
    writeFileSync(key, pair.privateKey.export({ type: 'pkcs8', format: 'pem' }));
    writeFileSync(pub, pair.publicKey.export({ type: 'spki', format: 'pem' }));
    chmodSync(key, 0o644);
    const out = run('scripts/release-sign.mjs', ['--key', key, '--public-key', pub]);
    assert.equal(out.status, 1);
    assert.match(out.stderr, /permissions|0600/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// F13: a bare `--tree` (or one followed by a flag) is a usage error — the
// verifier may not silently verify an implicit directory.
test('w23 F13a: verify-release --tree requires a directory value', () => {
  const out = run('scripts/verify-release.mjs', ['att.json', 'anchors.json', '--tree', '--ack-self-anchors']);
  assert.equal(out.status, 2);
  assert.match(out.stderr, /INV-400-USAGE|--tree/);
});

// F3/F13: trust anchors resolving inside the artifact tree self-certify —
// the verdict fails before any signature is even parsed.
test('w23 F13b: in-tree anchors are refused with INV-412-ANCHORS', () => {
  const dir = mkdtempSync(join(tmpdir(), 'w23-tree-'));
  try {
    writeFileSync(join(dir, 'att.json'), '{}');
    writeFileSync(join(dir, 'anchors.json'), '{}');
    const out = run('scripts/verify-release.mjs', ['att.json', 'anchors.json', '--tree', dir]);
    assert.equal(out.status, 1);
    assert.match(out.stderr, /INV-412-ANCHORS/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// F1: restore-check's trust anchor must live OUTSIDE the backup dir — an
// in-tree anchor self-certifies.
test('w23 F1: restore-check refuses an in-tree trust anchor', () => {
  const dir = mkdtempSync(join(tmpdir(), 'w23-bak-'));
  try {
    const keys = join(dir, 'keys.json');
    writeFileSync(keys, '{}');
    const out = run('scripts/restore-check.mjs', ['--dir', dir, '--trusted-keys', keys]);
    assert.equal(out.status, 2);
    assert.match(out.stderr, /OUTSIDE|in-tree/i);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// F1b: a backup dir without a signed manifest fails closed.
test('w23 F1b: restore-check exits 1 on a manifest-less directory', () => {
  const dir = mkdtempSync(join(tmpdir(), 'w23-bak-'));
  const outside = mkdtempSync(join(tmpdir(), 'w23-keys-'));
  try {
    writeFileSync(join(outside, 'keys.json'), JSON.stringify({ 'k1': { public_key: 'x' } }));
    const out = run('scripts/restore-check.mjs', ['--dir', dir, '--trusted-keys', join(outside, 'keys.json')]);
    assert.equal(out.status, 1);
    assert.match(out.stderr, /manifest/i);
  } finally { rmSync(dir, { recursive: true, force: true }); rmSync(outside, { recursive: true, force: true }); }
});

// F12/F2: the Python canonicalizer shares the strict parser — the real
// corpus verifies, and a duplicate-key payload is rejected outright.
test('w23 F12: canonical-vectors.py verifies the shipped corpus', { skip: process.platform === 'win32' }, () => {
  const out = py('scripts/canonical-vectors.py', [join(ROOT, 'examples', 'canonical-vectors.json')]);
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /"valid": true/);
});

test('w23 F12b: canonical-vectors.py rejects a duplicate-key vector file', { skip: process.platform === 'win32' }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'w23-cv-'));
  try {
    const f = join(dir, 'dup.json');
    writeFileSync(f, '[{"name":"dup","value":{"a":1,"a":2},"sha256":"x"}]');
    const out = py('scripts/canonical-vectors.py', [f]);
    assert.notEqual(out.status, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// F11: the WebCrypto vector verifier anchors its corpus via import.meta.url
// — it verifies identically from a foreign cwd.
test('w23 F11b: verify-vectors-webcrypto runs from a foreign cwd', () => {
  const dir = mkdtempSync(join(tmpdir(), 'w23-cwd-'));
  try {
    const out = run('scripts/verify-vectors-webcrypto.mjs', [], { cwd: dir });
    assert.equal(out.status, 0, out.stderr);
    assert.match(out.stdout, /webcrypto:/i);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

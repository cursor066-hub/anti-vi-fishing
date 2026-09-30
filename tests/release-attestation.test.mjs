// NFR-SEC-007 engineering evidence: signed release provenance. The release
// pipeline produces an IF-RELEASE-1 attestation binding the manifest
// digest, source commit and file inventory to a release key; consumers
// verify it offline against pinned trust anchors.
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { signed } from '../src/crypto.mjs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const ROOT = new URL('..', import.meta.url).pathname;
const run = (args) => spawnSync('node', args, { cwd: ROOT, encoding: 'utf8' });
const ok = (r) => { assert.equal(r.status, 0, r.stderr || r.stdout); return JSON.parse(r.stdout.trim().split('\n').at(-1)); };

test('release attestation signs and verifies against pinned anchors', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'rel-')); t.after(() => {}); // tmpdir is per-run; contents are evidence
  const sign = (extra = []) => run(['scripts/release-sign.mjs', '--key', `${dir}/release-key.pem`, '--public-key', `${dir}/release-key.pub`, '--out', `${dir}/attestation.json`, ...extra]);

  ok(run(['scripts/release-sign.mjs', '--generate-fixture-key', dir]));
  const out = ok(sign());
  assert.match(out.key_id, /^[0-9a-f]{32}$/);

  const anchors = { [out.key_id]: { public_key: readFileSync(`${dir}/release-key.pub`, 'utf8'), suite: 'Ed25519' } };
  writeFileSync(`${dir}/anchors.json`, JSON.stringify(anchors));
  const res = ok(run(['scripts/verify-release.mjs', `${dir}/attestation.json`, `${dir}/anchors.json`]));
  assert.equal(res.valid, true);
  assert.equal(res.key_id, out.key_id);
  // Wrong anchor must be refused, not silently trusted.
  const bad = spawnSync('node', ['scripts/verify-release.mjs', `${dir}/attestation.json`, `${dir}/release-key.pub`], { cwd: ROOT, encoding: 'utf8' });
  assert.notEqual(bad.status, 0);
});

test('tampered attestation payload fails verification', () => {
  const dir = mkdtempSync(join(tmpdir(), 'rel-tamper-'));
  ok(run(['scripts/release-sign.mjs', '--generate-fixture-key', dir]));
  const out = ok(run(['scripts/release-sign.mjs', '--key', `${dir}/release-key.pem`, '--public-key', `${dir}/release-key.pub`, '--out', `${dir}/attestation.json`]));
  writeFileSync(`${dir}/anchors.json`, JSON.stringify({ [out.key_id]: { public_key: readFileSync(`${dir}/release-key.pub`, 'utf8'), suite: 'Ed25519' } }));

  const env = JSON.parse(readFileSync(`${dir}/attestation.json`, 'utf8'));
  env.payload.materials.tracked_file_count += 1;
  writeFileSync(`${dir}/attestation-tampered.json`, JSON.stringify(env));
  const res = run(['scripts/verify-release.mjs', `${dir}/attestation-tampered.json`, `${dir}/anchors.json`]);
  assert.notEqual(res.status, 0);
  const body = JSON.parse(res.stderr.trim().split('\n').at(-1));
  assert.equal(body.code, 'INV-401-SIGNATURE');
});

test('validly-signed attestation for a different manifest is refused', () => {
  const dir = mkdtempSync(join(tmpdir(), 'rel-drift-'));
  ok(run(['scripts/release-sign.mjs', '--generate-fixture-key', dir]));
  const out = ok(run(['scripts/release-sign.mjs', '--key', `${dir}/release-key.pem`, '--public-key', `${dir}/release-key.pub`, '--out', `${dir}/attestation.json`]));
  const key = { key_id: out.key_id, public_key: readFileSync(`${dir}/release-key.pub`, 'utf8'), private_key: readFileSync(`${dir}/release-key.pem`, 'utf8'), suite: 'Ed25519' };
  writeFileSync(`${dir}/anchors.json`, JSON.stringify({ [out.key_id]: { public_key: key.public_key, suite: 'Ed25519' } }));
  // A VALID signature over provenance pointing at a foreign manifest must
  // reach INV-412-PROVENANCE — signature alone never suffices.
  const env = JSON.parse(readFileSync(`${dir}/attestation.json`, 'utf8'));
  env.payload.materials.manifest_sha256 = '0'.repeat(64);
  writeFileSync(`${dir}/attestation-drift.json`, JSON.stringify(signed(env.payload, key, 'release.attestation'), null, 2));
  const res = run(['scripts/verify-release.mjs', `${dir}/attestation-drift.json`, `${dir}/anchors.json`]);
  assert.notEqual(res.status, 0);
  assert.equal(JSON.parse(res.stderr.trim().split('\n').at(-1)).code, 'INV-412-PROVENANCE');
});

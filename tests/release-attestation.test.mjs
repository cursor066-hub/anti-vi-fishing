// NFR-SEC-007 engineering evidence: signed release provenance. The release
// pipeline produces an IF-RELEASE-1 attestation binding the manifest
// digest, source commit and file inventory to a release key; consumers
// verify it offline against pinned trust anchors.
//
// The suite runs against a SCRATCH repository built from the shipped
// scripts + src tree — the release tooling anchors at its own repo root, so
// exercising it here would make every assertion depend on this checkout's
// ambient cleanliness (mid-pipeline trees are dirty by construction).
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { signed } from '../src/crypto.mjs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';

const ROOT = new URL('..', import.meta.url).pathname;
const run = (args, cwd) => spawnSync(process.execPath, args, { cwd, encoding: 'utf8', env: { ...process.env, IF_TEST_ANCHORS: '1' } });
const ok = (r) => { assert.equal(r.status, 0, r.stderr || r.stdout); return JSON.parse(r.stdout.trim().split('\n').at(-1)); };

// A pristine, minimal release repo: the shipped scripts, the src tree they
// import, and a generated manifest — all committed, all clean.
const scratch = () => {
  const dir = mkdtempSync(join(tmpdir(), 'rel-repo-'));
  cpSync(join(ROOT, 'src'), join(dir, 'src'), { recursive: true });
  cpSync(join(ROOT, 'scripts'), join(dir, 'scripts'), { recursive: true });
  execFileSync('git', ['init', '-q'], { cwd: dir });
  execFileSync('git', ['add', '-A'], { cwd: dir });
  execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-qm', 'x'], { cwd: dir });
  execFileSync(process.execPath, [join(dir, 'scripts', 'manifest.mjs')], { cwd: dir });
  execFileSync('git', ['add', 'MANIFEST.sha256'], { cwd: dir });
  execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-qm', 'manifest'], { cwd: dir });
  return dir;
};

// Key material and attestations live OUTSIDE the scratch repo — untracked
// files inside a release tree are (correctly) verification failures.
const fixture = (dir) => {
  const keys = mkdtempSync(join(tmpdir(), 'rel-keys-'));
  ok(run(['scripts/release-sign.mjs', '--generate-fixture-key', keys], dir));
  const sign = (extra = []) => run(['scripts/release-sign.mjs', '--key', `${keys}/release-key.pem`, '--public-key', `${keys}/release-key.pub`, '--out', `${keys}/attestation.json`, ...extra], dir);
  const anchors = (out) => writeFileSync(`${keys}/anchors.json`, JSON.stringify({ [out.key_id]: { public_key: readFileSync(`${keys}/release-key.pub`, 'utf8'), suite: 'Ed25519' } }));
  return { keys, sign, anchors };
};

test('release attestation signs and verifies against pinned anchors', () => {
  const dir = scratch(), { keys, sign, anchors } = fixture(dir);
  const out = ok(sign());
  assert.match(out.key_id, /^[0-9a-f]{32}$/);

  anchors(out);
  const res = ok(run(['scripts/verify-release.mjs', `${keys}/attestation.json`, `${keys}/anchors.json`], dir));
  assert.equal(res.valid, true);
  assert.equal(res.key_id, out.key_id);
  // Wrong anchor must be refused, not silently trusted.
  const bad = run(['scripts/verify-release.mjs', `${keys}/attestation.json`, `${keys}/release-key.pub`], dir);
  assert.notEqual(bad.status, 0);
});

test('tampered attestation payload fails verification', () => {
  const dir = scratch(), { keys, sign, anchors } = fixture(dir);
  const out = ok(sign());
  anchors(out);

  const env = JSON.parse(readFileSync(`${keys}/attestation.json`, 'utf8'));
  env.payload.materials.tracked_file_count += 1;
  writeFileSync(`${keys}/attestation-tampered.json`, JSON.stringify(env));
  const res = run(['scripts/verify-release.mjs', `${keys}/attestation-tampered.json`, `${keys}/anchors.json`], dir);
  assert.notEqual(res.status, 0);
  const body = JSON.parse(res.stderr.trim().split('\n').at(-1));
  assert.equal(body.code, 'INV-401-SIGNATURE');
});

test('validly-signed attestation for a different manifest is refused', () => {
  const dir = scratch(), { keys, sign, anchors } = fixture(dir);
  const out = ok(sign());
  const key = { key_id: out.key_id, public_key: readFileSync(`${keys}/release-key.pub`, 'utf8'), private_key: readFileSync(`${keys}/release-key.pem`, 'utf8'), suite: 'Ed25519' };
  anchors(out);
  // A VALID signature over provenance pointing at a foreign manifest must
  // reach INV-412-PROVENANCE — signature alone never suffices.
  const env = JSON.parse(readFileSync(`${keys}/attestation.json`, 'utf8'));
  env.payload.materials.manifest_sha256 = '0'.repeat(64);
  writeFileSync(`${keys}/attestation-drift.json`, JSON.stringify(signed(env.payload, key, 'release.attestation'), null, 2));
  const res = run(['scripts/verify-release.mjs', `${keys}/attestation-drift.json`, `${keys}/anchors.json`], dir);
  assert.notEqual(res.status, 0);
  assert.equal(JSON.parse(res.stderr.trim().split('\n').at(-1)).code, 'INV-412-PROVENANCE');
});

test('dirty tree and test-env-gated overrides are refused honestly', () => {
  const dir = scratch(), { keys, sign } = fixture(dir);
  // A dirty working tree must refuse signing — provenance would otherwise
  // claim a commit the bytes do not match (supply-chain M5).
  writeFileSync(join(dir, 'dirty-marker'), 'x');
  const denied = sign();
  assert.notEqual(denied.status, 0);
  assert.match(denied.stderr, /not clean/);
  // And without IF_TEST_ANCHORS the fixture-key override is unreachable —
  // a production invocation cannot mint release-shaped key material.
  const env = { ...process.env }; delete env.IF_TEST_ANCHORS;
  const noEnv = spawnSync(process.execPath, ['scripts/release-sign.mjs', '--generate-fixture-key', keys], { cwd: dir, encoding: 'utf8', env });
  assert.equal(noEnv.status, 2);
  assert.match(noEnv.stderr, /IF_TEST_ANCHORS/);
});

test('CI-bound provenance verifies under --require-ci only with ci claims', () => {
  const dir = scratch(), { keys, sign, anchors } = fixture(dir);
  // Sign inside a simulated CI environment — invocation.ci must carry the
  // run identity into the signed provenance (w11-supply SC-07).
  const ciEnv = { ...process.env, IF_TEST_ANCHORS: '1', GITHUB_ACTIONS: 'true', GITHUB_RUN_ID: '123', GITHUB_RUN_ATTEMPT: '1', GITHUB_REPOSITORY: 'o/r', GITHUB_REF: 'refs/tags/v1', GITHUB_SHA: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dir, encoding: 'utf8' }).trim() };
  const signedInCi = spawnSync(process.execPath, ['scripts/release-sign.mjs', '--key', `${keys}/release-key.pem`, '--public-key', `${keys}/release-key.pub`, '--out', `${keys}/attestation.json`], { cwd: dir, encoding: 'utf8', env: ciEnv });
  const out = ok(signedInCi);
  anchors(out);
  const env = JSON.parse(readFileSync(`${keys}/attestation.json`, 'utf8'));
  assert.equal(env.payload.invocation.ci.run_id, '123');
  assert.equal(env.payload.invocation.ci.repository, 'o/r');
  const res = ok(run(['scripts/verify-release.mjs', `${keys}/attestation.json`, `${keys}/anchors.json`, '--require-ci'], dir));
  assert.equal(res.valid, true);
  assert.equal(res.ci.run_id, '123');
});

test('w14 W12-03: a stitched attestation (CI sha ≠ source commit) fails --require-ci', () => {
  const dir = scratch(), { keys, sign, anchors } = fixture(dir);
  // Attest CI claims for a DIFFERENT sha than the signed tree — the bind
  // must fail even though every field is present.
  const ciEnv = { ...process.env, IF_TEST_ANCHORS: '1', GITHUB_ACTIONS: 'true', GITHUB_RUN_ID: '123', GITHUB_RUN_ATTEMPT: '1', GITHUB_REPOSITORY: 'o/r', GITHUB_REF: 'refs/tags/v1', GITHUB_SHA: '0'.repeat(40) };
  const signedInCi = spawnSync(process.execPath, ['scripts/release-sign.mjs', '--key', `${keys}/release-key.pem`, '--public-key', `${keys}/release-key.pub`, '--out', `${keys}/attestation.json`], { cwd: dir, encoding: 'utf8', env: ciEnv });
  anchors(ok(signedInCi));
  const res = run(['scripts/verify-release.mjs', `${keys}/attestation.json`, `${keys}/anchors.json`, '--require-ci'], dir);
  assert.notEqual(res.status, 0);
  assert.match(res.stderr, /CI sha does not match/);
});

// Offline consumer-side verification of a release attestation produced by
// scripts/release-sign.mjs. Recomputes the manifest digest, RE-HASHES every
// manifest-listed file (the attestation must describe the tree in front of
// it, not merely the manifest file — supply-chain C1), verifies the
// envelope signature against a PINNED trust-anchor file (never a key
// embedded in the artifact — w8-tooling F1 discipline), and checks the
// provenance's source commit when git is available.
//
// usage: node scripts/verify-release.mjs [attestation.json] [anchors.json]
// anchors.json: { "key_id": { "public_key": "<pem>", "suite": "Ed25519" } }
import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { verifySigned } from '../src/crypto.mjs';
import { digest } from '../src/canonical.mjs';

process.chdir(new URL('..', import.meta.url).pathname);
const attPath = process.argv[2] ?? 'reports/release-attestation.json';
const anchorsPath = process.argv[3] ?? 'deploy/release-trust-anchors.json';
const fail = (code, msg) => { console.error(JSON.stringify({ valid: false, code, error: msg })); process.exit(1); };

if (!existsSync(attPath)) fail('INV-404-ATTESTATION', `attestation not found: ${attPath}`);
if (!existsSync(anchorsPath)) fail('INV-404-ANCHORS', `trust anchors not found: ${anchorsPath} — verification requires operator-pinned keys, not keys shipped inside the release`);
const attestation = JSON.parse(readFileSync(attPath, 'utf8'));
const anchors = JSON.parse(readFileSync(anchorsPath, 'utf8'));

let payload;
try { payload = verifySigned(attestation, anchors, 'release.attestation'); } catch (e) { fail(e.code ?? 'INV-401-SIGNATURE', e.message); }

if (payload?._type !== 'https://invariant-fabric.dev/release-provenance/v1' || payload.buildType !== 'IF-RELEASE-1')
  fail('INV-400-SCHEMA', 'attestation is not an IF-RELEASE-1 provenance');
if (!existsSync('MANIFEST.sha256')) fail('INV-404-MANIFEST', 'MANIFEST.sha256 missing from this tree');
const manifestSha = createHash('sha256').update(readFileSync('MANIFEST.sha256', 'utf8')).digest('hex');
if (payload.materials?.manifest_sha256 !== manifestSha)
  fail('INV-412-PROVENANCE', 'manifest digest in attestation does not match the tree');

// The attestation binds the manifest; the manifest must bind the tree.
// manifest.mjs --verify re-hashes every listed file, refuses symlinks, and
// flags unexpected extras — works identically in a git checkout and an
// exported tarball (supply-chain C1/H1).
const tree = spawnSync(process.execPath, ['scripts/manifest.mjs', '--verify'], { encoding: 'utf8' });
if (tree.status !== 0) fail('INV-412-PROVENANCE', `tree does not match the attested manifest: ${(tree.stderr || tree.stdout).trim()}`);

// Commit/inventory checks are supplemental to per-file hashing (which is
// git-independent). When git is unavailable they are reported as skipped —
// never silently treated as verified (supply-chain H1).
const skipped = [];
const head = spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' });
const tracked = spawnSync('git', ['ls-files'], { encoding: 'utf8' });
if (head.status === 0 && tracked.status === 0) {
  const files = tracked.stdout.split('\n').filter(Boolean).sort();
  if (payload.invocation?.source_commit !== head.stdout.trim()) fail('INV-412-PROVENANCE', 'attestation was minted for a different source commit');
  if (payload.materials?.tracked_file_count !== files.length || payload.materials?.inventory_digest !== digest({ files }))
    fail('INV-412-PROVENANCE', 'file inventory has drifted from the attested release');
} else {
  skipped.push('source_commit', 'tracked_file_count', 'inventory_digest');
}
console.log(JSON.stringify({ valid: true, key_id: attestation.protected.key_id, commit: payload.invocation.source_commit, manifest_sha256: manifestSha, timestamp: payload.timestamp, ...(skipped.length ? { skipped_checks: skipped } : {}) }));

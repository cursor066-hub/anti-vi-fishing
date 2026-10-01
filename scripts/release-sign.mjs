// Produces an SLSA-lite release attestation: a signed IF-CJSON-1 envelope
// binding the release manifest digest, source commit, toolchain and file
// inventory to a release signing key. The attestation is written to
// reports/release-attestation.json; consumers verify it offline with
// scripts/verify-release.mjs against a pinned trust-anchor file.
//
// Key material is NEVER read from the repository: --key points at a PEM the
// release operator holds (KMS-wrapped in production). --generate-fixture-key
// exists for tests and CI roundtrips only.
import { existsSync, readFileSync, writeFileSync, mkdirSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { signed, generateKey } from '../src/crypto.mjs';
import { derivePublic } from '../src/keystore.mjs';
import { digest } from '../src/canonical.mjs';

process.chdir(new URL('..', import.meta.url).pathname);
// A flag is never a value: `--key --out` must fail, not read '--out' as the
// key path — same guard src/cli.mjs enforces (w23-supply F14).
const arg = (name) => { const i = process.argv.indexOf(`--${name}`); if (i < 0) return undefined; const v = process.argv[i + 1]; return v !== undefined && !String(v).startsWith('--') ? v : undefined; };
const has = (name) => process.argv.includes(`--${name}`);

// Test-only conveniences are unreachable in a production invocation: key
// generation, key_id/anchor overrides and the dirty-tree bypass all require
// IF_TEST_ANCHORS=1 in the environment — CI sets it only in the test job,
// never in the release job (w11-supply SC-09).
const TEST_ENV = process.env.IF_TEST_ANCHORS === '1';
const needsTestEnv = flag => { if (flag && !TEST_ENV) { console.error(`${flag} requires IF_TEST_ANCHORS=1 — test-only override, refused in production`); process.exit(2); } };
needsTestEnv(has('generate-fixture-key') ? '--generate-fixture-key' : null);
needsTestEnv(has('key-id') ? '--key-id' : null);
needsTestEnv(has('test-anchors-out') ? '--test-anchors-out' : null);

if (has('generate-fixture-key')) {
  const key = generateKey(arg('suite') ?? 'Ed25519');
  const dir = arg('generate-fixture-key') ?? 'var';
  mkdirSync(dir, { recursive: true });
  writeFileSync(`${dir}/release-key.pem`, key.private_key, { mode: 0o600 });
  writeFileSync(`${dir}/release-key.pub`, key.public_key);
  console.log(JSON.stringify({ key_id: key.key_id, public_key_path: `${dir}/release-key.pub` }));
  process.exit(0);
}

const keyPath = arg('key'), publicPath = arg('public-key');
if (!keyPath || !publicPath) {
  console.error('usage: node scripts/release-sign.mjs --key <private.pem> --public-key <public.pem> [--key-id <id>] [--suite Ed25519|ES256] [--out path]');
  console.error('   or: node scripts/release-sign.mjs --generate-fixture-key [dir] [--suite ...]');
  process.exit(2);
}
// The release signer is the highest-value key operation in the repo — it
// enforces the same 0600 custody rule cli.mjs sign does (w23-supply F14).
if (existsSync(keyPath) && (statSync(keyPath).mode & 0o077) !== 0) { console.error('signing key file permissions must be 0600'); process.exit(1); }

const head = spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' });
const manifestRaw = existsSync('MANIFEST.sha256') ? readFileSync('MANIFEST.sha256', 'utf8') : '';
if (!manifestRaw || head.status !== 0) { console.error('MANIFEST.sha256 missing or git unavailable — sign a tracked release tree'); process.exit(1); }

// An attestation over HEAD must describe HEAD: staged or dirty working
// files would let provenance claim a commit the bytes do not match
// (supply-chain M5). Refuse to sign anything but a clean tree.
const dirty = spawnSync('git', ['status', '--porcelain'], { encoding: 'utf8' });
if (dirty.status !== 0 || dirty.stdout.trim()) { console.error('working tree is not clean — commit or stash changes before signing'); process.exit(1); }
// And the manifest must be fresh at signing time — otherwise the stale
// inventory is cemented into signed provenance (supply-chain M5).
const fresh = spawnSync(process.execPath, ['scripts/manifest.mjs', '--verify'], { encoding: 'utf8' });
if (fresh.status !== 0) { console.error(`manifest is stale — regenerate before signing: ${(fresh.stderr || fresh.stdout).trim()}`); process.exit(1); }

const tracked = spawnSync('git', ['ls-files'], { encoding: 'utf8' });
const files = tracked.status === 0 ? tracked.stdout.split('\n').filter(Boolean).sort() : [];
const key = { key_id: arg('key-id') ?? digest({ public_key: readFileSync(publicPath, 'utf8') }).slice(0, 32), public_key: readFileSync(publicPath, 'utf8'), private_key: readFileSync(keyPath, 'utf8'), suite: arg('suite') ?? 'Ed25519' };
// The advertised public half must be the private half's own public —
// otherwise the attestation claims an identity the signer never had
// (w21-crypto F-5).
if (derivePublic(key.private_key) !== key.public_key) { console.error('signing keypair is inconsistent — public.pem does not match the private key'); process.exit(1); }

// Provenance binds the CI run when one exists — a laptop-built envelope is
// then distinguishable from a pipeline-built one by the presence and values
// of invocation.ci (w11-supply SC-07). verify-release.mjs --require-ci
// asserts the claim set.
const ci = process.env.GITHUB_ACTIONS === 'true'
  ? { run_id: process.env.GITHUB_RUN_ID, run_attempt: process.env.GITHUB_RUN_ATTEMPT, repository: process.env.GITHUB_REPOSITORY, ref: process.env.GITHUB_REF, sha: process.env.GITHUB_SHA }
  : null;

const provenance = {
  _type: 'https://invariant-fabric.dev/release-provenance/v1',
  buildType: 'IF-RELEASE-1',
  builder: { id: `node:${process.version}` },
  invocation: { source_commit: head.stdout.trim(), node: process.version, platform: process.platform, parameters: { suite: key.suite }, ...(ci ? { ci } : {}) },
  materials: { manifest_sha256: createHash('sha256').update(manifestRaw).digest('hex'), tracked_file_count: files.length, inventory_digest: digest({ files }) },
  subject: { name: 'invariant-fabric-release', manifest: 'MANIFEST.sha256' },
  timestamp: new Date().toISOString()
};
const attestation = signed(provenance, key, 'release.attestation');
const out = arg('out') ?? 'reports/release-attestation.json';
mkdirSync(out.split('/').slice(0, -1).join('/') || '.', { recursive: true });
writeFileSync(out, JSON.stringify(attestation, null, 2) + '\n');
// Convenience for tests/CI ONLY: emit the trust-anchor file verify-release
// consumes. Production anchors are pinned by the CONSUMER, never shipped —
// the flag is named for its test purpose so no operator mistakes a
// self-minted anchor for pinning (supply-chain M5).
const anchorsOut = arg('test-anchors-out');
if (anchorsOut) {
  mkdirSync(anchorsOut.split('/').slice(0, -1).join('/') || '.', { recursive: true });
  writeFileSync(anchorsOut, JSON.stringify({ [key.key_id]: { public_key: key.public_key, suite: key.suite } }, null, 2) + '\n');
}
console.log(JSON.stringify({ attestation: out, key_id: key.key_id, manifest_sha256: provenance.materials.manifest_sha256, commit: provenance.invocation.source_commit }));

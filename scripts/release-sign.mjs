// Produces an SLSA-lite release attestation: a signed IF-CJSON-1 envelope
// binding the release manifest digest, source commit, toolchain and file
// inventory to a release signing key. The attestation is written to
// reports/release-attestation.json; consumers verify it offline with
// scripts/verify-release.mjs against a pinned trust-anchor file.
//
// Key material is NEVER read from the repository: --key points at a PEM the
// release operator holds (KMS-wrapped in production). --generate-fixture-key
// exists for tests and CI roundtrips only.
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { signed, generateKey } from '../src/crypto.mjs';
import { digest } from '../src/canonical.mjs';

process.chdir(new URL('..', import.meta.url).pathname);
const arg = (name) => { const i = process.argv.indexOf(`--${name}`); return i >= 0 ? process.argv[i + 1] : undefined; };
const has = (name) => process.argv.includes(`--${name}`);

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

const provenance = {
  _type: 'https://invariant-fabric.dev/release-provenance/v1',
  buildType: 'IF-RELEASE-1',
  builder: { id: `node:${process.version}` },
  invocation: { source_commit: head.stdout.trim(), node: process.version, platform: process.platform, parameters: { suite: key.suite } },
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

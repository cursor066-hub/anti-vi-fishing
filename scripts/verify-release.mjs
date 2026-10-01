// Offline consumer-side verification of a release attestation produced by
// scripts/release-sign.mjs. Recomputes the manifest digest, RE-HASHES every
// manifest-listed file (the attestation must describe the tree in front of
// it, not merely the manifest file — supply-chain C1), verifies the
// envelope signature against a PINNED trust-anchor file, and checks the
// provenance's source commit when git is available.
//
// SELF-CONTAINED BY DESIGN (w15-supply F-1): this file imports nothing from
// the artifact under verification — no ../src/*, no spawned in-tree helper.
// A distributor who trojans the release's own crypto/manifest code cannot
// influence the verdict. Consumers should pin THIS file out-of-band (e.g.
// checksum it once from a trusted clone), since the artifact could carry a
// trojaned copy; verifying with the shipped copy is a convenience, not a
// trust anchor.
//
// usage: node scripts/verify-release.mjs <attestation.json> <anchors.json>
//        [--allow-skips] [--require-ci] [--anchors-in-tree]
// anchors.json: { "key_id": { "public_key": "<pem>", "suite": "Ed25519" } }
// The anchors file is REQUIRED and must live OUTSIDE the artifact tree —
// a trust anchor shipped inside the release it vouches for is no anchor
// (w15-supply F-2). --anchors-in-tree overrides for CI's fixture roundtrip.
import { existsSync, readFileSync, readdirSync, lstatSync, realpathSync } from 'node:fs';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { join, relative, sep } from 'node:path';

// ---- IF-CJSON-1 canonicalization (inlined copy of src/canonical.mjs) ----
const PROTO_KEYS = new Set(['__defineGetter__', '__defineSetter__', '__lookupGetter__', '__lookupSetter__', '__proto__', 'constructor', 'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString', 'toString', 'valueOf', 'prototype', 'watch', 'unwatch']);
const die = msg => { throw Object.assign(new Error(msg), { code: 'INV-400-SCHEMA' }); };
function canonical(value, depth = 0) {
  if (depth > 32) die('Maximum nesting depth exceeded');
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) die('Only safe non-negative-zero integers are supported');
    return String(value);
  }
  if (typeof value === 'string') {
    if (value !== value.normalize('NFC') || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) die('Strings must be valid NFC Unicode');
    if (value.length > 65536) die('String too long');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (value.length > 10000) die('Array too long');
    return '[' + Array.from(value, v => canonical(v, depth + 1)).join(',') + ']';
  }
  if (value && typeof value === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    const keys = Object.keys(value).sort();
    if (keys.length > 256) die('Object too large');
    return '{' + keys.map(k => {
      if (!/^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$/.test(k) || PROTO_KEYS.has(k)) die('Unsupported object key');
      return JSON.stringify(k) + ':' + canonical(value[k], depth + 1);
    }).join(',') + '}';
  }
  die('Unsupported canonical value');
}
const digest = value => createHash('sha256').update(canonical(value)).digest('hex');

// ---- envelope verification (inlined copy of src/crypto.mjs verify path) ----
const SUITES = {
  Ed25519: { hash: null, dsaEncoding: null },
  ES256: { hash: 'sha256', dsaEncoding: 'ieee-p1363' }
};
// P-256 n/2: ECDSA (r, s) and (r, n−s) are both valid; low-s is canonical.
const P256_HALF_ORDER = BigInt('0x7FFFFFFF80000000FFFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8');
function verifySuite(suite, message, publicPem, signature) {
  const s = Object.hasOwn(SUITES, suite) ? SUITES[suite] : undefined;
  if (!s) return false;
  if (s.dsaEncoding === 'ieee-p1363' && signature.length === 64) {
    const scalar = BigInt('0x' + signature.subarray(32).toString('hex'));
    if (scalar > P256_HALF_ORDER) return false;
  }
  const key = s.dsaEncoding ? { key: createPublicKey(publicPem), dsaEncoding: s.dsaEncoding } : createPublicKey(publicPem);
  return verify(s.hash, message, key, signature);
}
const sigFail = (code, msg) => { throw Object.assign(new Error(msg), { code }); };
function verifySigned(envelope, publicKeys, purpose) {
  if (!(envelope && Object.keys(envelope).sort().join() === 'payload,protected,signature')) sigFail('INV-401-SIGNATURE', 'Invalid signed envelope');
  const h = envelope.protected;
  if (!(h && Object.keys(h).sort().join() === 'key_id,profile,purpose,suite' && h.profile === 'IF-CJSON-1' && Object.hasOwn(SUITES, h.suite) && h.purpose === purpose)) sigFail('INV-401-SIGNATURE', 'Unsupported signature context');
  const key = Object.hasOwn(publicKeys ?? {}, h.key_id) ? publicKeys[h.key_id] : undefined;
  if (!(key && !key.revoked)) sigFail('INV-401-SIGNATURE', 'Signer unavailable');
  if (key.suite !== undefined && key.suite !== h.suite) sigFail('INV-401-SIGNATURE', 'Envelope suite differs from the anchor-declared suite');
  if (!(typeof envelope.signature === 'string' && /^[A-Za-z0-9_-]{86}$/.test(envelope.signature)
    && Buffer.from(envelope.signature, 'base64url').toString('base64url') === envelope.signature)) sigFail('INV-401-SIGNATURE', 'Invalid signature encoding');
  let ok = false;
  try { ok = verifySuite(h.suite, Buffer.from(canonical({ protected: h, payload: envelope.payload })), key.public_key, Buffer.from(envelope.signature, 'base64url')); } catch { ok = false; }
  if (!ok) sigFail('INV-401-SIGNATURE', 'Signature verification failed');
  return envelope.payload;
}

// ---- manifest verification (inlined copy of manifest.mjs --verify) ----
const sha = f => createHash('sha256').update(readFileSync(f)).digest('hex');
const TARBALL_EXCLUDE = new Set(['.git']);
const GIT_MODE_EXEMPT = new Set(['node_modules', '.git', 'var']);
const EXCLUDE_FILES = new Set(['MANIFEST.sha256']);
function* walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    // A release tree carrying installed dependencies unhashed IS the anomaly
    // the walk exists to catch — only the object store is exempt (w15 F-5).
    if (entry.isDirectory()) { if (!TARBALL_EXCLUDE.has(entry.name)) yield* walk(p); }
    else if ((entry.isFile() || entry.isSymbolicLink()) && !EXCLUDE_FILES.has(entry.name)) yield p;
  }
}
function manifestVerify() {
  const listed = readFileSync('MANIFEST.sha256', 'utf8').trim().split('\n').filter(Boolean)
    .map(line => { const [hash, ...rest] = line.split('  '); return { hash, name: rest.join('  ') }; });
  const names = new Set(listed.map(l => l.name));
  const problems = [];
  for (const { hash, name } of listed) {
    if (!existsSync(name)) { problems.push(`missing: ${name}`); continue; }
    let st; try { st = lstatSync(name); } catch { problems.push(`unreadable: ${name}`); continue; }
    if (st.isSymbolicLink()) { problems.push(`symlinked: ${name}`); continue; }
    // Only regular files hash — a FIFO/socket/device at a listed path would
    // otherwise block the read forever (w15-supply F-7).
    if (!st.isFile()) { problems.push(`non-regular: ${name}`); continue; }
    try { if (sha(name) !== hash) problems.push(`tampered: ${name}`); }
    catch { problems.push(`unreadable: ${name}`); }
  }
  const tracked = spawnSync('git', ['ls-files', '-z'], { encoding: 'utf8' });
  let extras = [];
  if (tracked.status === 0) {
    const trackedFiles = tracked.stdout.split('\0').filter(Boolean);
    for (const f of trackedFiles) if (!names.has(f) && !EXCLUDE_FILES.has(f)) problems.push(`unlisted tracked file: ${f}`);
    const untracked = spawnSync('git', ['ls-files', '--others', '-z'], { encoding: 'utf8' });
    if (untracked.status === 0) extras = untracked.stdout.split('\0').filter(f => f && !EXCLUDE_FILES.has(f) && !GIT_MODE_EXEMPT.has(f.split('/')[0]));
  } else {
    extras = [...walk('.')].map(p => relative('.', p)).filter(f => !names.has(f));
  }
  for (const e of extras) problems.push(`unexpected file: ${e}`);
  return problems;
}

// ---------------------------------------------------------------------------
process.chdir(new URL('..', import.meta.url).pathname);
const args = process.argv.slice(2).filter(a => !a.startsWith('--'));
const attPath = args[0], anchorsPath = args[1];
const fail = (code, msg) => { console.error(JSON.stringify({ valid: false, code, error: msg })); process.exit(1); };

if (!attPath || !anchorsPath) fail('INV-400-USAGE', 'usage: node scripts/verify-release.mjs <attestation.json> <anchors.json> [--allow-skips] [--require-ci] [--anchors-in-tree] — the trust-anchor file is REQUIRED and must live outside the artifact');
if (!existsSync(attPath)) fail('INV-404-ATTESTATION', `attestation not found: ${attPath}`);
if (!existsSync(anchorsPath)) fail('INV-404-ANCHORS', `trust anchors not found: ${anchorsPath} — verification requires operator-pinned keys, not keys shipped inside the release`);
// An anchors path resolving inside the artifact root is a self-issued key —
// the release would vouch for itself (w15-supply F-2).
const root = realpathSync('.'), anchorReal = realpathSync(anchorsPath);
if ((anchorReal === root || anchorReal.startsWith(root + sep)) && !process.argv.includes('--anchors-in-tree'))
  fail('INV-412-ANCHORS', 'trust anchors resolve inside the artifact tree — pin them out-of-band, or pass --anchors-in-tree for the CI fixture roundtrip');

let payload;
try { payload = verifySigned(JSON.parse(readFileSync(attPath, 'utf8')), JSON.parse(readFileSync(anchorsPath, 'utf8')), 'release.attestation'); } catch (e) { fail(e.code ?? 'INV-401-SIGNATURE', e.message); }

if (payload?._type !== 'https://invariant-fabric.dev/release-provenance/v1' || payload.buildType !== 'IF-RELEASE-1')
  fail('INV-400-SCHEMA', 'attestation is not an IF-RELEASE-1 provenance');
if (!existsSync('MANIFEST.sha256')) fail('INV-404-MANIFEST', 'MANIFEST.sha256 missing from this tree');
const manifestSha = sha('MANIFEST.sha256');
if (payload.materials?.manifest_sha256 !== manifestSha)
  fail('INV-412-PROVENANCE', 'manifest digest in attestation does not match the tree');
// A pinned anchor that is itself manifest-covered certifies nothing — the
// manifest was already attacker-rewritable at that point.
if (readFileSync('MANIFEST.sha256', 'utf8').split('\n').some(l => l.endsWith('  ' + relative('.', anchorsPath))))
  console.error(JSON.stringify({ warning: 'anchors file is listed inside the release manifest — an in-tree key cannot anchor the release', code: 'INV-412-ANCHORS' }));

// The attestation binds the manifest; the manifest binds the tree — inlined
// above so no artifact code ever executes during verification (w15 F-1).
const treeProblems = manifestVerify();
if (treeProblems.length) fail('INV-412-PROVENANCE', `tree does not match the attested manifest: ${JSON.stringify(treeProblems)}`);

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
// A consumer keying on `valid` must not be told a release verified when its
// provenance checks were skipped — skipped means NOT proven, not OK
// (w11-supply SC-11). --allow-skips restores the disclose-only mode for
// tarball consumers who accept per-file-hash coverage alone.
const allowSkips = process.argv.includes('--allow-skips');
if (skipped.length && !allowSkips) fail('INV-412-PROVENANCE', `provenance checks skipped without --allow-skips: ${skipped.join(', ')}`);
// --require-ci asserts the attestation binds a CI run (w11-supply SC-07):
// run identity fields must be present and non-empty, and the attested CI
// sha must name the same commit the tree was minted from — a stitched
// attestation (CI claims pasted onto a laptop build) fails the bind
// (w13-supply W12-03).
if (process.argv.includes('--require-ci')) {
  const ci = payload.invocation?.ci;
  if (!ci?.run_id || !ci?.repository || !ci?.sha) fail('INV-412-PROVENANCE', 'attestation does not bind a CI run (--require-ci)');
  if (ci.sha !== payload.invocation?.source_commit) fail('INV-412-PROVENANCE', 'attested CI sha does not match the attested source commit');
}
console.log(JSON.stringify({ valid: true, key_id: JSON.parse(readFileSync(attPath, 'utf8')).protected.key_id, commit: payload.invocation?.source_commit ?? null, manifest_sha256: manifestSha, timestamp: payload.timestamp, ...(payload.invocation?.ci ? { ci: payload.invocation.ci } : {}), ...(skipped.length ? { skipped_checks: skipped } : {}) }));

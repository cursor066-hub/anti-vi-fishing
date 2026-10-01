// w21-issuerd regression suite — dedicated log key, append-before-commit,
// O_NOFOLLOW/O_NONBLOCK node custody, spec-dir custody, log size cap,
// read-path probe charging, real unauthenticated stamps, route charset,
// ttl/name/advisory validation, tokenless-registry warnings, uniform 401,
// dead plaintext+digest specs, hashed provenance segments.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, symlinkSync, mkdirSync, chmodSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKey } from '../src/crypto.mjs';
import { canonical, digest } from '../src/canonical.mjs';
import { createIssuerServer, writeIssuer, answerQuery, loadIssuers } from '../src/issuerd.mjs';
import { ISSUER_RULES, issuerRecords } from '../src/bootstrap.mjs';
import { httpJson } from '../src/connectors.mjs';
import { hasCode } from './helpers.mjs';

const mkSpec = (over = {}) => ({ issuer: 'bank', tenant: 'acme', version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds: ISSUER_RULES.bank, records: issuerRecords().bank, ...over });
const issueBody = { kind: 'ownership', subject_id: 'operator', claims: { account: 'TESTBANK000001', owner_id: 'vendor-1' }, capsule_digest: 'a'.repeat(64), tenant_id: 'acme' };
const serve = async (t, dir, opts = {}) => {
  const logPath = opts.logPath ?? join(dir, 'issuance.log');
  const srv = createIssuerServer(loadIssuers(dir), { port: 0, logPath, ...opts });
  await srv.listen();
  t.after(async () => { await srv.close().catch(() => {}); });
  return { srv, logPath, port: srv.server.address().port };
};

// F-1 — the chain key is a dedicated `<log>.key` secret: adding a whole
// issuer spec to the registry must not invalidate the prior segment.
test('w21-issuerd F-1: issuer-set changes do not brick the issuance chain', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  writeIssuer(dir, { ...mkSpec(), issue_token: 'tok-a' });
  const logPath = join(dir, 'issuance.log');
  const first = await serve(t, dir, { logPath });
  await httpJson(`http://127.0.0.1:${first.port}/v1/issuers/bank/issue`, { method: 'POST', body: issueBody, token: 'tok-a' });
  await first.srv.close();
  // Mint the key on first boot, then grow the registry: the same log must
  // still verify because the key no longer derives from the issuer set.
  writeIssuer(dir, { ...mkSpec({ issuer: 'erp' }), issue_token: 'tok-b' });
  const second = await serve(t, dir, { logPath });
  const res = await httpJson(`http://127.0.0.1:${second.port}/v1/issuers/bank/issue`, { method: 'POST', body: issueBody, token: 'tok-a' });
  assert.equal(res.status, 201);
  const lines = readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
  assert.equal(lines.length, 2, 'the new server extended the same chain, not a re-genesis');
  assert.equal(lines[1].sequence, 2);
  assert.equal(lines[1].previous, lines[0].digest);
});

// F-2 — a failed append must not burn a sequence: chain state commits only
// after the write is durable.
test('w21-issuerd F-2: a failed append leaves no phantom sequence', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  writeIssuer(dir, { ...mkSpec(), issue_token: 'tok-a' });
  const logPath = join(dir, 'issuance.log');
  const { srv, port } = await serve(t, dir, { logPath });
  await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/issue`, { method: 'POST', body: issueBody, token: 'tok-a' });
  const kept = readFileSync(logPath, 'utf8');
  // Make the append fail: a directory at logPath gives EISDIR on open.
  rmSync(logPath); mkdirSync(logPath);
  const res = await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/issue`, { method: 'POST', body: issueBody, token: 'tok-a' });
  assert.equal(res.status, 500, 'the logging failure surfaces, it is not swallowed');
  rmSync(logPath, { recursive: true }); writeFileSync(logPath, kept, { mode: 0o600 });
  const ok = await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/issue`, { method: 'POST', body: issueBody, token: 'tok-a' });
  assert.equal(ok.status, 201);
  const lines = readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
  assert.equal(lines.at(-1).sequence, 2, 'sequence 2 was retried — not burned by the failed append');
  await srv.close();
  // And the recovered chain boots clean.
  const srv2 = createIssuerServer(loadIssuers(dir), { port: 0, logPath });
  await srv2.listen(); t.after(() => srv2.close());
});

// F-3 — O_NOFOLLOW + fstat: a dangling symlink or a FIFO at the log path
// refuses custody instead of redirecting writes or hanging the boot.
test('w21-issuerd F-3: non-regular log paths refuse at boot and at append', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  writeIssuer(dir, { ...mkSpec(), issue_token: 'tok-a' });
  const issuers = loadIssuers(dir);
  // Dangling symlink — ELOOP, uniform INV-503-CONFIG.
  const dangling = join(dir, 'dangling.log');
  symlinkSync(join(dir, 'nowhere.log'), dangling);
  assert.throws(() => createIssuerServer(issuers, { port: 0, logPath: dangling }), hasCode('INV-503-CONFIG'));
  // FIFO — O_NONBLOCK keeps the open from hanging; fstat refuses it.
  const fifo = join(dir, 'fifo.log');
  execFileSync('mkfifo', [fifo]);
  assert.throws(() => createIssuerServer(issuers, { port: 0, logPath: fifo }), hasCode('INV-503-CONFIG'));
  // Swap-to-symlink mid-run: the append path refuses the planted link too.
  const logPath = join(dir, 'live.log');
  const { srv, port } = await serve(t, dir, { logPath });
  await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/issue`, { method: 'POST', body: issueBody, token: 'tok-a' });
  rmSync(logPath); symlinkSync('/tmp/attacker-chosen.log', logPath);
  const res = await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/issue`, { method: 'POST', body: issueBody, token: 'tok-a' });
  assert.equal(res.status, 500);
  assert.equal(existsSync('/tmp/attacker-chosen.log'), false, 'no bytes escaped through the planted link');
  await srv.close();
});

// F-4 — spec custody: a world-writable issuer dir or a symlinked spec
// refuses at load, not at serve time.
test('w21-issuerd F-4: writable dirs and symlinked specs refuse at load', t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  writeIssuer(dir, mkSpec());
  chmodSync(dir, 0o777);
  assert.throws(() => loadIssuers(dir), hasCode('INV-503-CONFIG'), 'a group/world-writable issuer dir refuses');
  chmodSync(dir, 0o700);
  const outside = join(mkdtempSync(join(tmpdir(), 'if-issuer-out-')), 'bank.issuer.json');
  writeFileSync(outside, readFileSync(join(dir, 'bank.issuer.json')), { mode: 0o600 });
  rmSync(join(dir, 'bank.issuer.json')); symlinkSync(outside, join(dir, 'bank.issuer.json'));
  assert.throws(() => loadIssuers(dir), hasCode('INV-503-CONFIG'), 'a symlinked spec refuses');
});

// F-5 — the log has a residency ceiling: the next logged event refuses
// honestly once the cap is reached (operator archives + rotates).
test('w21-issuerd F-5: the log size cap refuses new entries honestly', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  writeIssuer(dir, { ...mkSpec(), issue_token: 'tok-a' });
  const logPath = join(dir, 'capped.log');
  const { port } = await serve(t, dir, { logPath, log_max_bytes: 150 });
  const first = await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/issue`, { method: 'POST', body: issueBody, token: 'tok-a' });
  assert.equal(first.status, 201, 'the first entry fits under the cap');
  const res = await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/issue`, { method: 'POST', body: issueBody, token: 'tok-a' });
  assert.equal(res.status, 503);
  assert.equal(res.data.error.code, 'INV-503-CONFIG');
});

// F-6 — refused reads ride the probe budget and the chain, even under a
// valid foreign read credential.
test('w21-issuerd F-6: foreign-bearer read probing is probe-budgeted and logged', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  writeIssuer(dir, { ...mkSpec(), read_token: 'tok-read' });
  const logPath = join(dir, 'probe.log');
  const { port } = await serve(t, dir, { logPath });
  let saw429 = 0;
  for (let i = 0; i < 35; i++) {
    const r = await httpJson(`http://127.0.0.1:${port}/v1/issuers/ghost/manifest`, { token: 'tok-read' });
    if (r.status === 404) continue;
    if (r.status === 429) { saw429++; break; }
    assert.fail(`unexpected status ${r.status} on a refused read`);
  }
  assert.ok(saw429 > 0, 'the 30/min probe bucket binds under a valid foreign token');
  const entries = readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
  assert.ok(entries.some(e => e.refused === true && e.route === 'manifest'), 'refused reads land in the chain');
});

// F-7 — an authenticated caller refused at a foreign issuer is stamped
// unauthenticated:false, not a blanket true.
test('w21-issuerd F-7: refused issues stamp the real authentication state', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  writeIssuer(dir, { ...mkSpec(), issue_token: 'tok-a' });
  writeIssuer(dir, { ...mkSpec({ issuer: 'erp' }), issue_token: 'tok-b' });
  const logPath = join(dir, 'auth.log');
  const { port } = await serve(t, dir, { logPath });
  const res = await httpJson(`http://127.0.0.1:${port}/v1/issuers/erp/issue`, { method: 'POST', body: issueBody, token: 'tok-a' });
  assert.equal(res.status, 404);
  const entries = readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
  const refused = entries.find(e => e.refused === true && e.code === 'INV-404-NOT-FOUND');
  assert.ok(refused, 'the refusal is logged');
  assert.equal(refused.unauthenticated, false, 'the caller WAS authenticated — the stamp is honest');
});

// F-8 — issuer names must fit the route charset at load AND at write.
test('w21-issuerd F-8: names outside the route charset refuse at load and write', t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  writeFileSync(join(dir, 'x.issuer.json'), canonical(mkSpec({ issuer: 'bad.name' })) + '\n', { mode: 0o600 });
  assert.throws(() => loadIssuers(dir), hasCode('INV-400-SCHEMA'), 'a dotted name would load but never route');
  assert.throws(() => writeIssuer(dir, mkSpec({ issuer: 'bad.name' })), hasCode('INV-400-SCHEMA'));
  assert.throws(() => writeIssuer(dir, mkSpec({ issuer: 'bad:name' })), hasCode('INV-400-SCHEMA'));
});

// F-9 — semantics: huge ttl_ms, proto/exotic extract names, proto expect
// keys and non-boolean advisory all refuse at boot.
test('w21-issuerd F-9: dangerous kind rules refuse at boot', t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  // JSON.stringify, not canonical(): a proto expect key must reach the
  // LOADER's validation, not die in the test's own canonicalizer.
  const put = (kinds, file = 'x.issuer.json') => writeFileSync(join(dir, file), JSON.stringify({ ...mkSpec(), kinds }) + '\n', { mode: 0o600 });
  put({ ownership: { lookup: 'a:${claims.a}', confidence: 50, ttl_ms: Number.MAX_SAFE_INTEGER } });
  assert.throws(() => loadIssuers(dir), hasCode('INV-400-SCHEMA'), 'a ttl overflowing `now` arithmetic refuses');
  rmSync(join(dir, 'x.issuer.json'));
  put({ ownership: { lookup: 'a:${claims.a}', confidence: 50, extract: ['__proto__'] } });
  assert.throws(() => loadIssuers(dir), hasCode('INV-400-SCHEMA'), 'a proto extract name refuses');
  rmSync(join(dir, 'x.issuer.json'));
  put({ ownership: { lookup: 'a:${claims.a}', confidence: 50, expect: { constructor: 1 } } });
  assert.throws(() => loadIssuers(dir), hasCode('INV-400-SCHEMA'), 'a proto expect key refuses');
  rmSync(join(dir, 'x.issuer.json'));
  put({ ownership: { lookup: 'a:${claims.a}', confidence: 50, advisory: 'yes' } });
  assert.throws(() => loadIssuers(dir), hasCode('INV-400-SCHEMA'), 'a string advisory would sign Boolean("yes")===true');
});

// F-10 — a mixed token/tokenless registry warns at bind: the tokenless
// issuer is unreachable and the operator must see why.
test('w21-issuerd F-10: a mixed registry warns about unreachable issuers', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  writeIssuer(dir, { ...mkSpec(), issue_token: 'tok-a' });
  writeIssuer(dir, mkSpec({ issuer: 'erp' }));
  const seen = [];
  const orig = process.stderr.write;
  process.stderr.write = c => { seen.push(String(c)); return true; };
  try { const srv = createIssuerServer(loadIssuers(dir), { port: 0 }); t.after(() => srv.close().catch(() => {})); }
  finally { process.stderr.write = orig; }
  assert.ok(seen.some(l => l.includes('erp')), 'the tokenless issuer is named in the warning');
});

// F-11 — deployment state never fingerprints through refusal codes: a
// tokenless registry on loopback without the opt-in answers uniform 401.
test('w21-issuerd F-11: config-state refusals collapse to uniform 401', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  writeIssuer(dir, mkSpec());
  const { port } = await serve(t, dir);
  const res = await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/manifest`);
  assert.equal(res.status, 401, 'no 503 fingerprint of the tokenless registry');
  assert.equal(res.data.error.code, 'INV-401-AUTH');
});

// F-12 — plaintext + digest for one scope is a dead credential: refuse the
// config at boot instead of silently preferring the digest.
test('w21-issuerd F-12: a plaintext token shadowed by a digest refuses at boot', t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  writeFileSync(join(dir, 'a.issuer.json'), canonical({ ...mkSpec(), read_token: 'plain', issue_token_digest: digest('x') }) + '\n', { mode: 0o600 });
  assert.throws(() => loadIssuers(dir), hasCode('INV-400-SCHEMA'), 'read_token dead under a shadowing digest');
  rmSync(join(dir, 'a.issuer.json'));
  writeFileSync(join(dir, 'a.issuer.json'), canonical({ ...mkSpec(), issue_token: 'plain', issue_token_digest: digest('x') }) + '\n', { mode: 0o600 });
  assert.throws(() => loadIssuers(dir), hasCode('INV-400-SCHEMA'), 'issue_token dead under its own digest');
});

// F-15 — the provenance lookup segment is issuer-keyed material: a lookup
// template with no static prefix cannot echo caller text into the signed
// provenance string.
test('w21-issuerd F-15: provenance never echoes caller lookup material', t => {
  const spec = { ...mkSpec(), kinds: { ownership: { lookup: '${claims.account}', confidence: 50 } } };
  const req = { tenant_id: 'acme', kind: 'ownership', subject_id: 'op', claims: { account: 'CALLER-CONTROLLED' }, capsule_digest: 'a'.repeat(64) };
  const env = answerQuery(spec, req, Date.now());
  const seg = /record:(\S+):lookup/.exec(env.payload.provenance)?.[1];
  assert.ok(/^[a-f0-9]{24}$/.test(seg), 'the segment is issuer-keyed hash material, not caller text');
  assert.ok(!env.payload.provenance.includes('CALLER-CONTROLLED'));
});

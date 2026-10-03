// Wave-48b regression tests: the w48-issuerd pass findings — spec-content
// digest anchored to the ledger (H1), sidecar file discipline on
// .head/.lock (H2/M1/L2), a watermark refusing re-genesis on ANY surviving
// head (H3), IPv6 /64 canonical bucketing (M2), unauthenticated refusal
// aggregation (M3), and key_id derivation binding (L1).
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, readFileSync, unlinkSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture, hasCode } from './helpers.mjs';
import { createIssuerServer, loadIssuers, writeIssuer, specDigest, slash64 } from '../src/issuerd.mjs';
import { ISSUER_RULES, issuerRecords } from '../src/bootstrap.mjs';
import { generateKey } from '../src/crypto.mjs';
import { canonical, digest } from '../src/canonical.mjs';
import { driftCheck } from '../src/connectors.mjs';

const spec = (over = {}) => ({ issuer: 'bank', tenant: 'acme', version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds: ISSUER_RULES.bank, records: issuerRecords().bank, issue_token: 'issue-tok', read_token: 'read-tok', ...over });
const issueBody = { tenant_id: 'acme', capsule_digest: 'a'.repeat(64), kind: 'ownership', subject_id: 'operator', claims: { account: 'TESTBANK000001', owner_id: 'vendor-1' } };

async function serve(t, dir, opts = {}) {
  const srv = createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', ...opts });
  await srv.listen(); t.after(() => srv.close().catch(() => {}));
  const port = srv.server.address().port;
  const req = (method, path, { token, body } = {}) => new Promise((resolve, reject) => {
    const headers = { Host: `127.0.0.1:${port}`, Connection: 'close' };
    if (token) headers.Authorization = `Bearer ${token}`;
    let payload;
    if (body !== undefined) { payload = canonical(body); headers['Content-Type'] = 'application/json'; headers['Content-Length'] = Buffer.byteLength(payload); }
    const rq = http.request(`http://127.0.0.1:${port}${path}`, { method, headers }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    rq.on('error', reject); rq.end(payload);
  });
  return { srv, port, req };
}

// --- H1: the spec's semantic body is digest-pinned into the ledger at
// provisioning; a file-level records/kinds edit drifts at checkIssuerDrift
// even though the private key and every custody bit still verify ---
test('w48b issuerd H1: bootstrap pins the spec-content digest; a poisoned record store drifts', async t => {
  const h = fixture(t, ['acme']);
  const [bankKeyId, bank] = Object.entries(h.f.tenant('acme').issuers).find(([, v]) => v.name === 'bank');
  assert.equal(bank.spec_digest, specDigest({ issuer: 'bank', tenant: 'acme', version: '1.0.0', channel: 'authoritative', kinds: ISSUER_RULES.bank, records: issuerRecords().bank }),
    'the registered issuer carries the digest of the spec body bootstrap wrote');
  const dir = mkdtempSync(join(tmpdir(), 'w48b-h1-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const body = { issuer: 'bank', tenant: 'acme', channel: 'authoritative', version: '1.0.0', key: h.setup.issuerKeys.acme.bank, kinds: ISSUER_RULES.bank, records: issuerRecords().bank, read_token: bank.read_token };
  writeIssuer(dir, body);
  const srv = createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', clock: () => h.now() });
  await srv.listen();
  h.repoint(bankKeyId, `http://127.0.0.1:${srv.server.address().port}`);
  assert.equal((await h.f.checkIssuerDrift(h.p('security'), bankKeyId)).drifted, false, 'an unmodified spec body does not drift');
  await srv.close();
  // Same key, same signed manifest machinery — a planted record row must
  // still drift at the anchored digest (the spec file is writeable by the
  // attacker; the ledger's pin is not).
  unlinkSync(join(dir, 'bank.issuer.json'));
  writeIssuer(dir, { ...body, records: { ...issuerRecords().bank, 'account:PLANTED': { owner: 'attacker', status: 'active', verified_at: 1 } } });
  const srv2 = createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', clock: () => h.now() });
  t.after(() => srv2.close().catch(() => {}));
  await srv2.listen();
  h.repoint(bankKeyId, `http://127.0.0.1:${srv2.server.address().port}`);
  const drifted = await h.f.checkIssuerDrift(h.p('security'), bankKeyId);
  assert.equal(drifted.drifted, true, 'a spec-body edit must surface as drift');
  assert.ok(drifted.changes.some(c => c.field === 'spec_digest'), 'the convicted field is spec_digest');
});

test('w48b issuerd H1: specDigest is blind to credentials and sensitive to records/kinds', t => {
  const base = spec({ key: generateKey() });
  const d = specDigest(base);
  // Token material rotates without touching the semantic pin.
  assert.equal(d, specDigest({ ...base, issue_token: 'rotated', read_token: 'other', key: generateKey() }));
  assert.notEqual(d, specDigest({ ...base, records: { ...base.records, 'account:X': { owner: 'e', status: 'active' } } }), 'a record row edit changes the pin');
  assert.notEqual(d, specDigest({ ...base, kinds: {} }), 'a kind-table edit changes the pin');
  // And the drift comparator convicts a mismatch / tolerates an undeclared
  // baseline.
  const convicted = driftCheck({ spec_digest: 'a'.repeat(64) }, { spec_digest: 'b'.repeat(64) }, 1700000000000);
  assert.ok(convicted.drifted && convicted.changes.some(c => c.field === 'spec_digest'));
  const baseline = driftCheck({}, { spec_digest: 'b'.repeat(64) }, 1700000000000);
  assert.ok(!baseline.drifted && baseline.changes.some(c => c.field === 'spec_digest_undeclared_baseline' && c.informational === true));
});

// --- H3: a surviving head watermark with a missing/empty log is always
// tamper evidence — regardless of what the watermark claims ---
test('w48b issuerd H3: a deleted log under a surviving head refuses re-genesis', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'w48b-h3-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeIssuer(dir, spec());
  const logPath = join(dir, 'issuance.log');
  const a = await serve(t, dir, { logPath });
  await a.req('POST', '/v1/issuers/bank/issue', { token: 'issue-tok', body: issueBody });
  await a.srv.close();
  assert.ok(existsSync(`${logPath}.head`), 'watermark written');
  unlinkSync(logPath); // the log vanishes whole — no truncation prefix left
  assert.throws(() => createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', logPath }), hasCode('INV-503-CONFIG'), 'absent log under a surviving watermark refuses');
});

test('w48b issuerd H3: a format-flipped head cannot launder a truncated log', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'w48b-h3b-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeIssuer(dir, spec());
  const logPath = join(dir, 'issuance.log');
  const a = await serve(t, dir, { logPath });
  await a.req('POST', '/v1/issuers/bank/issue', { token: 'issue-tok', body: issueBody });
  await a.srv.close();
  // The attacker wipes the log and flips the watermark's format field —
  // a pattern-matching guard would read this as "no valid watermark".
  writeFileSync(logPath, '');
  writeFileSync(`${logPath}.head`, JSON.stringify({ format: 'NOT-THE-HEAD', sequence: 0 }) + '\n');
  assert.throws(() => createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', logPath }), hasCode('INV-503-CONFIG'), 'any surviving head over an empty log refuses');
  // The honest first-boot path: no log and no watermark genesises cleanly.
  unlinkSync(`${logPath}.head`);
  const clean = createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', logPath });
  await clean.listen(); await clean.close();
});

// --- H2/M1/L2: sidecar file discipline — directories and FIFOs at the
// .lock/.head paths refuse named instead of hanging or dying raw ---
test('w48b issuerd H2/L2: a directory or FIFO at .lock refuses boot with a named code', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'w48b-lock-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeIssuer(dir, spec());
  const logPath = join(dir, 'issuance.log');
  mkdirSync(`${logPath}.lock`);
  assert.throws(() => createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', logPath }), hasCode('INV-503-CONFIG'), 'a directory at .lock refuses named, not a raw EISDIR');
  rmSync(`${logPath}.lock`, { recursive: true });
  execFileSync('mkfifo', [`${logPath}.lock`]);
  assert.throws(() => createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', logPath }), hasCode('INV-503-CONFIG'), 'a FIFO at .lock refuses named — no blocking read');
});

test('w48b issuerd M1: a directory or FIFO at .head refuses boot and refuses append', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'w48b-head-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeIssuer(dir, spec());
  const logPath = join(dir, 'issuance.log');
  // Boot-side: a live log over a directory watermark refuses named.
  const a = await serve(t, dir, { logPath });
  await a.req('POST', '/v1/issuers/bank/issue', { token: 'issue-tok', body: issueBody });
  await a.srv.close();
  rmSync(`${logPath}.head`);
  mkdirSync(`${logPath}.head`);
  assert.throws(() => createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', logPath }), hasCode('INV-503-CONFIG'), 'a directory at .head refuses boot named');
  // Runtime-side: plant a FIFO at .head under a RUNNING daemon — the next
  // append must refuse as a named 503, never a raw crash or a hung write.
  // A fresh segment (no log, no watermark) boots cleanly first.
  rmSync(`${logPath}.head`, { recursive: true }); unlinkSync(logPath);
  const b = await serve(t, dir, { logPath });
  execFileSync('mkfifo', [`${logPath}.head`]);
  const res = await b.req('POST', '/v1/issuers/bank/issue', { token: 'issue-tok', body: issueBody });
  assert.equal(res.status, 503, 'the append refuses as a named config fault');
  assert.ok(JSON.parse(res.body).error?.code === 'INV-503-CONFIG', 'the refusal carries the named code');
});

// --- M2: IPv6 /64 bucketing parses the address — compressed literals and
// zone ids cannot split a bucket per host ---
test('w48b issuerd M2: IPv6 /64 buckets collapse on the canonical prefix', t => {
  assert.equal(slash64('2001:db8::1'), slash64('2001:db8::dead:beef'), 'two hosts in one /64 share a bucket');
  assert.equal(slash64('2001:db8::1'), slash64('2001:db8:0:0:ffff:1:2:3'), 'compressed and expanded forms collapse together');
  assert.notEqual(slash64('2001:db8::1'), slash64('2001:db8:1::1'), 'a different /64 keeps its own bucket');
  assert.equal(slash64('fe80::1%eth0'), slash64('fe80::2'), 'a zone id is interface noise, not identity');
  assert.equal(slash64('::1'), '0:0:0:0::/64');
  assert.equal(slash64('not-an-ip'), 'not-an-ip', 'unparseable input stays a stable bucket key');
});

// --- M3: unauthenticated refusals aggregate per window; authenticated
// refusals keep per-event provenance ---
test('w48b issuerd M3: an unauthenticated probe burst mints one chained line per window', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'w48b-m3-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeIssuer(dir, spec());
  const logPath = join(dir, 'issuance.log');
  let clock = 1700000000000;
  const a = await serve(t, dir, { logPath, clock: () => clock });
  // Three probes inside one window — a single aggregate line must carry
  // the burst, not three entries.
  for (let i = 0; i < 3; i++) await a.req('GET', '/v1/bogus');
  clock += 61000;
  await a.req('GET', '/v1/bogus'); // window 2: line reports the prior count
  await a.srv.close();
  const lines = readFileSync(logPath, 'utf8').trim().split('\n').map(JSON.parse);
  const bursts = lines.filter(l => l.probe_burst === true);
  assert.equal(bursts.length, 2, 'one chained line per 60s window, not per request');
  assert.equal(bursts[0].route, 'unknown' ); assert.equal(bursts[0].refused, true);
  assert.equal(bursts[1].prior_window_probes, 3, 'the second window reports the first window\u2019s total probe count');
});

test('w48b issuerd M3: an authenticated refusal still lands per-event', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'w48b-m3b-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeIssuer(dir, spec());
  writeIssuer(dir, spec({ issuer: 'erp', issue_token: 'erp-tok' }));
  const logPath = join(dir, 'issuance.log');
  const a = await serve(t, dir, { logPath });
  for (let i = 0; i < 2; i++) await a.req('POST', '/v1/issuers/erp/issue', { token: 'issue-tok', body: issueBody });
  await a.srv.close();
  const lines = readFileSync(logPath, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(lines.filter(l => l.refused === true && l.unauthenticated === false).length, 2, 'authenticated refusals keep one line each');
});

// --- L1: key_id is a commitment to the public key — a divergent spec
// refuses at load, not at the fabric's verifier ---
test('w48b issuerd L1: a spec whose key_id does not derive from its public key refuses load', t => {
  const dir = mkdtempSync(join(tmpdir(), 'w48b-l1-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeIssuer(dir, spec({ key: { ...generateKey(), key_id: 'd'.repeat(32) } }));
  assert.throws(() => loadIssuers(dir), hasCode('INV-400-SCHEMA'), 'a non-derived key_id refuses at boot');
});

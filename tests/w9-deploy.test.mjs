import test from 'node:test';
import http from 'node:http';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, chmodSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { fixture, hasCode } from './helpers.mjs';
import { createIssuerServer, writeIssuer, answerQuery, loadIssuers } from '../src/issuerd.mjs';
import { createServer } from '../src/server.mjs';
import { ISSUER_RULES, issuerRecords, bootstrap } from '../src/bootstrap.mjs';
import { generateKey } from '../src/crypto.mjs';
import { digest, parseStrict } from '../src/canonical.mjs';
import { httpJson } from '../src/connectors.mjs';
import { InvariantError } from '../src/errors.mjs';

// Wave-9 deploy/bootstrap audit regressions: daemon crash on float metrics,
// error-detail echo, issuer-name enumeration oracle, socket hardening,
// custody checks, digest-stored issuer tokens, early rate bucketing.

const spec = (name, tokens = {}, kinds = ISSUER_RULES.bank) => ({ issuer: name, tenant: 'acme', version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds, records: issuerRecords().bank, ...tokens });
const issueBody = { kind: 'ownership', subject_id: 'operator', claims: { account: 'TESTBANK000001', owner_id: 'vendor-1' }, capsule_digest: 'a'.repeat(64), tenant_id: 'acme' };

test('w9-deploy F1: /health after issuance stays up and reports an integer p50', async t => {
  const srv = createIssuerServer({ 'acme:bank': spec('bank', { issue_token: 'tok', read_token: 'tok' }) }, { port: 0, host: '127.0.0.1' });
  await srv.listen(); t.after(() => srv.close());
  const port = srv.server.address().port;
  assert.equal((await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/issue`, { method: 'POST', body: issueBody, token: 'tok' })).status, 201);
  const health = await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/health?tenant=acme`, { token: 'tok' });
  assert.equal(health.status, 200);
  assert.ok(Number.isInteger(health.data.metrics.p50_ms), 'p50 must be an integer — a float once crashed canonical()');
  // The daemon survived the once-deterministic ERR_HTTP_HEADERS_SENT exit.
  assert.equal((await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/manifest?tenant=acme`, { token: 'tok' })).status, 200);
});

test('w9-deploy F2: issuerd error responses never echo internal details', async t => {
  const srv = createIssuerServer({ 'acme:bank': spec('bank', { issue_token: 'tok' }) }, { port: 0, host: '127.0.0.1' });
  await srv.listen(); t.after(() => srv.close());
  const port = srv.server.address().port;
  const r = await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/issue`, { method: 'POST', body: { ...issueBody, kind: 'never-served' }, token: 'tok' });
  assert.equal(r.status, 412);
  assert.deepEqual(Object.keys(r.data.error).sort(), ['code', 'message']);
});

test('w9-deploy F4: a wrong-issuer bearer gets the same 404 as a missing name', async t => {
  const issuers = { 'acme:bank': spec('bank', { issue_token: 'tok-b', read_token: 'tok-b' }), 'acme:hris': spec('hris', { issue_token: 'tok-a', read_token: 'tok-a' }, ISSUER_RULES.hris) };
  const srv = createIssuerServer(issuers, { port: 0, host: '127.0.0.1' });
  await srv.listen(); t.after(() => srv.close());
  const port = srv.server.address().port;
  for (const path of ['/v1/issuers/bank/manifest?tenant=acme', '/v1/issuers/bank/health?tenant=acme'])
    assert.equal((await httpJson(`http://127.0.0.1:${port}${path}`, { token: 'tok-a' })).status, 404, path);
  assert.equal((await httpJson(`http://127.0.0.1:${port}/v1/issuers/ghost/manifest?tenant=acme`, { token: 'tok-a' })).status, 404);
  assert.equal((await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/issue`, { method: 'POST', body: issueBody, token: 'tok-a' })).status, 404);
  // Control: the real holder still resolves.
  assert.equal((await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/manifest?tenant=acme`, { token: 'tok-b' })).status, 200);
});

test('w9-deploy F5: issuerd pins Host and carries socket timeouts', async t => {
  const srv = createIssuerServer({ 'acme:bank': spec('bank', { issue_token: 'tok' }) }, { port: 0, host: '127.0.0.1' });
  await srv.listen(); t.after(() => srv.close());
  assert.equal(srv.server.requestTimeout, 15000);
  assert.equal(srv.server.headersTimeout, 8000);
  assert.equal(srv.server.keepAliveTimeout, 5000);
  assert.equal(srv.server.maxRequestsPerSocket, 100);
  const port = srv.server.address().port;
  const r = await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/manifest`, { token: 'tok', headers: { Host: 'rebinding.example' } });
  assert.equal(r.status, 400); assert.equal(r.data.error.code, 'INV-400-HOST');
});

test('w9-deploy F6: serve refuses world/group-readable keystore, not just config', async t => {
  const dir = join(mkdtempSync(join(tmpdir(), 'if-cli-')), 'deploy'); t.after(() => rmSync(dir, { recursive: true }));
  bootstrap(dir, ['acme']);
  chmodSync(join(dir, 'keystore.json'), 0o644);
  const cli = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
  assert.throws(() => execFileSync(process.execPath, [cli, 'serve', '--dir', dir, '--port', '19551'], { encoding: 'utf8', timeout: 20000 }),
    e => (`${e.stdout ?? ''}${e.stderr ?? ''}${e.message}`).includes('INV-503-CONFIG'));
});

test('w9-deploy F7: bootstrap issuer specs carry bearer digests, not plaintext tokens', async t => {
  const dir = join(mkdtempSync(join(tmpdir(), 'if-boot-')), 'deploy'); t.after(() => rmSync(dir, { recursive: true }));
  bootstrap(dir, ['acme']);
  const file = readdirSync(join(dir, 'issuers')).find(f => f.includes('bank'));
  const saved = parseStrict(readFileSync(join(dir, 'issuers', file), 'utf8'));
  assert.equal(saved.issue_token, undefined); assert.equal(saved.read_token, undefined);
  assert.match(saved.issue_token_digest, /^[a-f0-9]{64}$/); assert.match(saved.read_token_digest, /^[a-f0-9]{64}$/);
  const issuers = loadIssuers(join(dir, 'issuers'));
  const srv = createIssuerServer(issuers, { port: 0, host: '127.0.0.1' });
  await srv.listen(); t.after(() => srv.close());
  const port = srv.server.address().port;
  // The fabric's own plaintext copy in config.json still authenticates.
  const cfg = parseStrict(readFileSync(join(dir, 'config.json'), 'utf8'));
  const bank = Object.values(cfg.tenants.acme.issuers).find(i => i.name === 'bank');
  assert.equal((await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/issue`, { method: 'POST', body: issueBody, token: bank.issue_token })).status, 201);
  assert.equal((await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/issue`, { method: 'POST', body: issueBody, token: 'forged' })).status, 401);
});

test('w9-deploy F9: the coarse bucket is spent before request validation', async t => {
  const srv = createIssuerServer({ 'acme:bank': spec('bank', { issue_token: 'tok' }) }, { port: 0, host: '127.0.0.1' });
  await srv.listen(); t.after(() => srv.close());
  const port = srv.server.address().port;
  // Host-failing requests must consume the per-IP budget: 600 of them, then
  // a well-formed request is rate-limited rather than reaching the handler.
  for (let i = 0; i < 600; i++)
    assert.equal((await httpJson(`http://127.0.0.1:${port}/healthz`, { headers: { Host: 'spoofed' } })).status, 400, `request ${i}`);
  const limited = await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/manifest?tenant=acme`, { token: 'tok' });
  assert.equal(limited.status, 429); assert.equal(limited.data.error.code, 'INV-429-RATE');
});

test('w9-deploy F10: constructor-name kinds miss own-property lookup; tokenless daemon stays closed', async t => {
  const s = spec('bank', { issue_token: 'tok' });
  assert.throws(() => answerQuery(s, { ...issueBody, kind: 'constructor' }, Date.now()), hasCode('INV-412-EVIDENCE'));
  assert.throws(() => answerQuery(s, { ...issueBody, kind: 'toString' }, Date.now()), hasCode('INV-412-EVIDENCE'));
  const closed = createIssuerServer({ 'acme:bank': spec('bank') }, { port: 0, host: '127.0.0.1' });
  await closed.listen(); t.after(() => closed.close());
  const port = closed.server.address().port;
  // Tokenless spec without the opt-in must not serve — even on loopback.
  assert.equal((await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/manifest?tenant=acme`)).status, 503);
  const open = createIssuerServer({ 'acme:bank': spec('bank') }, { port: 0, host: '127.0.0.1', allow_insecure_loopback: true });
  await open.listen(); t.after(() => open.close());
  const openPort = open.server.address().port;
  assert.equal((await httpJson(`http://127.0.0.1:${openPort}/v1/issuers/bank/manifest?tenant=acme`)).status, 200);
  // '0.0.0.0' is not loopback for outbound cleartext either.
  await assert.rejects(() => httpJson('http://0.0.0.0:1/'), hasCode('INV-400-CONNECTOR'));
});

test('w9-deploy F3: --trust-proxy keys rate buckets on X-Forwarded-For from a loopback peer', async t => {
  const h = fixture(t);
  const origin = 'http://127.0.0.1:17778';
  const app = createServer(h.f, { port: 0, origin, trustProxy: true }); await app.listen(); t.after(() => app.close());
  const port = app.server.address().port;
  const hit = xff => new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: '/session', method: 'POST', headers: { Host: '127.0.0.1:17778', Origin: origin, 'X-Forwarded-For': xff, 'Content-Type': 'application/json', 'Content-Length': 2 } },
      res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', reject); req.end('{}');
  });
  // Login bucket is 20/min per identity — a single forged XFF must exhaust
  // only its own bucket, not the shared loopback one.
  for (let i = 0; i < 20; i++) assert.notEqual(await hit('10.9.9.9'), 429, `request ${i}`);
  assert.equal(await hit('10.9.9.9'), 429);
  assert.notEqual(await hit('10.9.9.8'), 429);
});

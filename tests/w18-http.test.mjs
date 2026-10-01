import test from 'node:test';
import http from 'node:http';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from '../src/server.mjs';
import { createIssuerServer, writeIssuer, loadIssuers } from '../src/issuerd.mjs';
import { ISSUER_RULES, issuerRecords } from '../src/bootstrap.mjs';
import { generateKey } from '../src/crypto.mjs';
import { httpJson } from '../src/connectors.mjs';
import { fixture, hasCode } from './helpers.mjs';

// w18-http second-pass regressions: the five LOW findings from the live
// surface audit — bodiless-POST content contract, grants role parity,
// memoized page verification, and issuerd wire-contract parity.

function raw(url, { method = 'GET', body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(url, { method, headers }, res => {
      const c = []; res.on('data', x => c.push(x));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, data: Buffer.concat(c).toString('utf8') }));
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

async function httpFixture(t) {
  const h = fixture(t), app = createServer(h.f, { port: 0, origin: 'http://127.0.0.1:17777' }); await app.listen(); t.after(() => app.close()); const port = app.server.address().port;
  const request = (path, { method = 'GET', body, token = h.setup.credentials.acme.operator, headers = {} } = {}) =>
    raw(`http://127.0.0.1:${port}${path}`, { method, body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body), headers: { Host: '127.0.0.1:17777', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers } });
  return { ...h, request };
}

// F-2: bodiless POSTs honour the strict contract — a text/plain garbage
// payload cannot smuggle a state change, a non-empty JSON body is a
// schema error, and bytes are drained before the response commits.
test('w18 F-2: bodiless POST routes reject garbage and non-JSON bodies', async t => {
  const h = await httpFixture(t), token = h.setup.credentials.acme.security;
  for (const path of ['/v1/policy/reanchor', '/v1/clock/recover', '/v1/audit/seal', '/v1/config-drift/reassert']) {
    const garb = await h.request(path, { method: 'POST', token, body: 'not-json!!', headers: { 'Content-Type': 'text/plain' } });
    assert.equal(garb.status, 415, `${path}: ${garb.data}`);
    const nonempty = await h.request(path, { method: 'POST', token, body: { x: 1 } });
    assert.equal(nonempty.status, 400, `${path}: ${nonempty.data}`);
  }
  // An empty JSON object passes the contract — the operation itself then
  // refuses on its own honest merits (healthy chain anchor).
  const clean = await h.request('/v1/policy/reanchor', { method: 'POST', token, body: {} });
  assert.equal(clean.status, 409, clean.data);
});

// F-3: the audit-page verification memo is keyed on the verified bytes —
// with a warm cache, a forged tail row appended under the seq trigger
// still misses the memo (its envelope was never verified) and wedges the
// page loudly. (Rewriting an existing row is already impossible: the
// append-only trigger rejects UPDATE — proven by ERR_SQLITE_ERROR.)
test('w18 F-3: forged tail row defeats a warm page-verify memo', t => {
  const h = fixture(t);
  h.f.auditPageScoped(h.p('security'), {});
  const head = h.f.store.db.prepare("SELECT seq,hash FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get();
  h.f.store.db.prepare('INSERT INTO audit (tenant,seq,previous,hash,envelope) VALUES (?,?,?,?,?)')
    .run('acme', head.seq + 1, head.hash, 'deadbeef', '{}');
  assert.throws(() => h.f.auditPageScoped(h.p('security'), {}), e => /^INV-/.test(e.code ?? ''));
  assert.throws(() => h.f.store.db.prepare("UPDATE audit SET envelope='{}' WHERE tenant='acme' AND seq=1").run(),
    e => e.code === 'ERR_SQLITE_ERROR', 'the append-only trigger already denies envelope rewrites');
});

// F-1: the grants surface is operator/security/auditor end-to-end — the
// route guard and the console affordance agree (no tab that always 403s).
test('w18 F-1: policy_admin is denied on /v1/grants end-to-end', async t => {
  const h = await httpFixture(t);
  const r = await h.request('/v1/grants', { token: h.setup.credentials.acme['policy-admin'] });
  assert.equal(r.status, 403, r.data);
});

// F-4/F-5: issuerd parity — strict content type on /issue, closed query
// params, the same security-header set, and malformed unauthenticated
// traffic lands in the issuance log bounded by the probe bucket.
test('w18 F-4/F-5: issuerd enforces the wire contract and logs malformed probes', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  writeIssuer(dir, { issuer: 'bank', tenant: 'acme', version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds: ISSUER_RULES.bank, records: issuerRecords().bank });
  const logPath = join(dir, 'issuance.log');
  const srv = createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', allow_insecure_loopback: true, logPath });
  await srv.listen(); t.after(() => srv.close());
  const base = `http://127.0.0.1:${srv.server.address().port}`;
  const bad = await httpJson(`${base}/v1/issuers/bank/issue`, { method: 'POST', body: { x: 1 }, headers: { 'Content-Type': 'text/plain' } });
  assert.equal(bad.status, 415, JSON.stringify(bad.data));
  assert.equal((await httpJson(`${base}/v1/issuers?rogue=1`)).status, 400, 'undeclared query parameter refused');
  const log = readFileSync(logPath, 'utf8').trim().split('\n').map(l => JSON.parse(l));
  assert.ok(log.some(l => l.malformed === true), 'malformed probe landed in the issuance chain');
  const health = await raw(`${base}/v1/issuers/bank/health`);
  assert.equal(health.headers['cross-origin-resource-policy'], 'same-origin');
  assert.equal(health.headers['content-security-policy'], "default-src 'none'");
});

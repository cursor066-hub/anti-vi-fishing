import test from 'node:test';
import http from 'node:http';
import assert from 'node:assert/strict';
import { createServer } from '../src/server.mjs';
import { fixture, runtimeInput, runtimeRequest, hasCode } from './helpers.mjs';
import { Worker } from 'node:worker_threads';
import { actionAvailability, typedValue, csvSelection, nextAction } from '../web/app.js';
import { bootstrap, loadConfiguration } from '../src/bootstrap.mjs';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { signed } from '../src/crypto.mjs';
import { proposal } from '../src/schema.mjs';
import { randomUUID } from 'node:crypto';

async function httpFixture(t) {
  const h = fixture(t), app = createServer(h.f, { port: 0, origin: 'http://127.0.0.1:17777' }); await app.listen(); t.after(() => app.close()); const port = app.server.address().port;
  async function request(path, { method = 'GET', body, token = h.setup.credentials.acme.operator, headers = {} } = {}) {
    const payload = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
    return new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, path, method, headers: { Host: '127.0.0.1:17777', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(payload === undefined ? {} : { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }), ...headers } }, response => {
        const chunks = []; response.on('data', c => chunks.push(c)); response.on('end', () => { const content = Buffer.concat(chunks).toString('utf8'); let data; try { data = JSON.parse(content); } catch { data = content; }
          resolve({ response: { headers: { get: key => Array.isArray(response.headers[key]) ? response.headers[key][0] : response.headers[key] } }, status: response.statusCode, data }); });
      }); req.on('error', reject); req.end(payload);
    });
  }
  return { ...h, request, app };
}
test('HTTP: health, ready, console assets and hardened headers are served', async t => { const h = await httpFixture(t); for (const path of ['/healthz', '/readyz', '/', '/app.js', '/style.css']) { const r = await h.request(path, { token: null }); assert.equal(r.status, 200, path); assert.equal(r.response.headers.get('x-content-type-options'), 'nosniff'); assert.match(r.response.headers.get('content-security-policy'), /frame-ancestors 'none'/); } });
test('HTTP: missing/expired auth, cross origin, unknown host, traversal and cross-tenant objects denied', async t => {
  const h = await httpFixture(t), r = h.proposed(); assert.equal((await h.request('/v1/me', { token: null })).status, 401);
  assert.equal((await h.request('/v1/me', { headers: { Origin: 'https://evil.example' } })).status, 403);
  assert.equal((await h.request('/v1/me', { headers: { Host: 'evil.example' } })).status, 400);
  assert.equal((await h.request('/config.json')).status, 404);
  assert.equal((await h.request(`/v1/action-capsules/${r.capsule.capsule_id}`, { token: h.setup.credentials.globex.operator })).status, 404);
  assert.equal((await h.request('/v1/resources/dataset-1')).status, 403);
  assert.equal((await h.request('/v1/action-capsules', { token: h.setup.credentials.acme.auditor })).status, 403);
});
test('HTTP: duplicate keys, wrong content-type and huge bodies reject safely', async t => {
  const h = await httpFixture(t); assert.equal((await h.request('/v1/certificates', { method: 'POST', body: '{"capsule_id":"a","capsule_id":"b"}' })).status, 400);
  assert.equal((await h.request('/v1/certificates', { method: 'POST', body: '{}', headers: { 'Content-Type': 'text/plain' } })).status, 415);
  assert.equal((await h.request('/v1/certificates', { method: 'POST', body: 'x'.repeat(1048600) })).status, 413);
});
test('HTTP: same-origin HttpOnly cookie session requires CSRF and logs out', async t => {
  const h = await httpFixture(t), login = await h.request('/session', { method: 'POST', token: null, body: { token: h.setup.credentials.acme.operator }, headers: { Origin: 'http://127.0.0.1:17777' } });
  assert.equal(login.status, 200); const cookie = login.response.headers.get('set-cookie'); assert.match(cookie, /HttpOnly/); assert.match(cookie, /SameSite=Strict/); const headers = { Cookie: cookie.split(';')[0], Origin: 'http://127.0.0.1:17777' };
  assert.equal((await h.request('/v1/me', { token: null, headers })).status, 200);
  assert.equal((await h.request('/session/logout', { method: 'POST', token: null, body: {}, headers })).status, 403);
  assert.equal((await h.request('/session/logout', { method: 'POST', token: null, body: {}, headers: { ...headers, 'X-CSRF-Token': login.data.csrf_token } })).status, 200);
  assert.equal((await h.request('/v1/me', { token: null, headers })).status, 401);
});
test('HTTP: full propose -> evidence -> independent signatures -> ALLOW -> certificate -> execute -> audit', async t => {
  const h = await httpFixture(t), type = 'finance.beneficiary.create', resource = `new-${randomUUID()}`;
  const input = proposal(type, h.actor(), h.f.target.state('acme', resource), { vendor_id: 'vendor-1', bank_account: 'TESTBANK000004', currency: 'EUR' }, h.now(), { action: { type, target_resource: resource, purpose: 'API contract integration' } });
  const created = await h.request('/v1/action-capsules', { method: 'POST', body: input, headers: { 'Idempotency-Key': randomUUID() } }); assert.equal(created.status, 201); const r = created.data, id = r.capsule.capsule_id;
  for (const issuer of ['bank', 'registry']) {
    const payload = { evidence_id: randomUUID(), tenant_id: 'acme', capsule_digest: r.capsule_digest, kind: 'ownership', content_digest: 'a'.repeat(64), acquired_at: h.now(), expires_at: h.now() + 600000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 'HTTP synthetic fixture', retention_until: h.now() + 900000 };
    assert.equal((await h.request(`/v1/action-capsules/${id}/evidence`, { method: 'POST', body: signed(payload, h.setup.issuerKeys.acme[issuer], 'evidence') })).status, 201);
  }
  for (const subject of ['custodian-1', 'custodian-2']) {
    const token = h.setup.credentials.acme[subject], challenge = await h.request(`/v1/action-capsules/${id}/approval-challenge`, { token }); assert.equal(challenge.status, 200);
    assert.equal((await h.request('/v1/approvals', { method: 'POST', token, body: signed(challenge.data, h.setup.custodianKeys.acme[subject], 'action-approval') })).status, 201);
  }
  const evaluation = await h.request(`/v1/action-capsules/${id}/evaluate`, { method: 'POST', body: {} }); assert.equal(evaluation.data.decision, 'ALLOW');
  const cert = await h.request('/v1/certificates', { method: 'POST', body: { capsule_id: id } }); assert.equal(cert.status, 201);
  const outcome = await h.request('/gate/v1/execute', { method: 'POST', body: { certificate: cert.data, dry_run: false } }); assert.equal(outcome.data.payload.status, 'VERIFIED');
  assert.equal((await h.request('/gate/v1/execute', { method: 'POST', body: { certificate: cert.data, dry_run: false } })).status, 409);
  assert.equal((await h.request('/v1/audit-exports', { method: 'POST', token: h.setup.credentials.acme.auditor, body: { purpose: 'Contract validation' } })).status, 200);
});
test('PER-007 PER-009: Secure Perception remains explicitly unavailable and fails closed', async t => { const h = await httpFixture(t), result = await h.request('/v1/secure-perception/session', { method: 'POST', body: {} }); assert.equal(result.status, 501); assert.match(result.data.error.message, /no plaintext release/); });
function runWorker(data) { return new Promise((resolve, reject) => { const worker = new Worker(new URL('./race-worker.mjs', import.meta.url), { workerData: data }); worker.once('message', resolve); worker.once('error', reject); worker.once('exit', code => { if (code) reject(new Error(`Worker exit ${code}`)); }); }); }
test('COM-003 NFR-TST-002: eight independent gate workers race; exactly one certificate is consumed', async t => {
  const h = fixture(t), { certificate, record } = h.ready(), data = { config: h.setup.config, directory: h.directory, now: h.now(), principal: h.p(), certificate };
  const results = await Promise.all(Array.from({ length: 8 }, () => runWorker(data))); assert.equal(results.filter(r => r.success).length, 1, JSON.stringify(results)); assert.ok(results.filter(r => !r.success).every(r => r.code === 'INV-409-REPLAY')); assert.equal(h.f.target.state('acme', record.capsule.action.target_resource).version, 1);
});
test('DAT-002: concurrent gates cannot overspend shared rolling budget', async t => {
  const h = fixture(t), policy = h.f.policy('acme'); policy.runtime.windows[0].limit = 2; h.f.store.put('acme', 'policy', 'active', policy, h.now()); const cap = h.f.runtime.issue(h.p(), runtimeInput());
  const results = await Promise.all(Array.from({ length: 8 }, () => runWorker({ config: h.setup.config, directory: h.directory, now: h.now(), principal: h.p(), runtime: runtimeRequest(cap) })));
  assert.equal(results.filter(r => r.success).length, 1, JSON.stringify(results)); assert.ok(results.filter(r => !r.success).every(r => r.code === 'INV-429-BUDGET'));
});
test('NFR-SEC-004: bootstrap creates random credentials, private files and refuses overwrite', t => {
  const h = fixture(t), directory = join(h.directory, 'new-deployment'); bootstrap(directory); const config = loadConfiguration(directory); assert.equal(config.profile, 'engineering'); assert.ok(readFileSync(join(directory, 'access-tokens.json'), 'utf8').length > 100); assert.throws(() => bootstrap(directory), hasCode('INV-409-CONFLICT')); assert.throws(() => new h.f.constructor({ ...config, profile: 'production' }, directory), hasCode('INV-503-RELEASE'));
});
test('UX-002 UX-003: UI state logic exposes no generic approval or executable non-ALLOW state', () => {
  assert.equal(actionAvailability('ESCROW', ['operator']).mint, false); assert.equal(actionAvailability('CERTIFIED', ['auditor']).execute, false); assert.equal(actionAvailability('CERTIFIED', ['operator']).execute, true); assert.match(nextAction('UNCERTAIN'), /Do not submit/);
  for (const value of ['', '0', '-1', '1.1', '1e3']) assert.throws(() => typedValue(value, 'positive')); assert.equal(typedValue('100', 'positive'), 100); assert.throws(() => csvSelection('a,a'));
});
test('UX-007: static interface labels all named inputs and uses no unsafe DOM injection sink', () => {
  const html = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8'), js = readFileSync(new URL('../web/app.js', import.meta.url), 'utf8');
  for (const m of html.matchAll(/<(?:input|select|textarea)\b[^>]*\bid="([^"]+)"/g)) assert.ok(html.includes(`for="${m[1]}"`), m[1]); assert.doesNotMatch(js, /\.innerHTML\s*=|insertAdjacentHTML|\beval\(/); assert.match(html, /not Secure Perception/); assert.match(html, /role="status"/);
});

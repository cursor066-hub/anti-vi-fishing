import test from 'node:test';
import http from 'node:http';
import assert from 'node:assert/strict';
import { createServer, ROUTE_METHODS } from '../src/server.mjs';
import { fixture, installPolicy, runtimeInput, runtimeRequest, hasCode } from './helpers.mjs';
import { Worker } from 'node:worker_threads';
import { actionAvailability, typedValue, csvSelection, nextAction } from '../web/app.js';
import { bootstrap, loadConfiguration } from '../src/bootstrap.mjs';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { signed } from '../src/crypto.mjs';
import { openRelease } from '../src/secureview.mjs';
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
  assert.equal((await h.request('/v1/action-capsules', { token: h.setup.credentials.acme.auditor })).status, 200);
  assert.equal((await h.request('/v1/action-capsules', { method: 'POST', token: h.setup.credentials.acme.auditor, body: { input: {}, signature: {} } })).status, 403);
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
test('HTTP UX-001: full propose -> evidence -> independent signatures -> ALLOW -> certificate -> execute -> audit', async t => {
  const h = await httpFixture(t), type = 'finance.beneficiary.create', resource = `new-${randomUUID()}`;
  const input = proposal(type, h.actor(), h.f.target.state('acme', resource), { vendor_id: 'vendor-1', bank_account: 'TESTBANK000004', currency: 'EUR' }, h.now(), { action: { type, target_resource: resource, purpose: 'API contract integration' } });
  const created = await h.request('/v1/action-capsules', { method: 'POST', body: { input, signature: signed(input, h.setup.identityKeys.acme.operator, 'capsule-intent') }, headers: { 'Idempotency-Key': randomUUID() } }); assert.equal(created.status, 201); const r = created.data, id = r.capsule.capsule_id;
  for (const issuer of ['bank', 'registry']) {
    const payload = { evidence_id: randomUUID(), tenant_id: 'acme', capsule_digest: r.capsule_digest, kind: 'ownership', content_digest: 'a'.repeat(64), acquired_at: h.now(), expires_at: h.now() + 600000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 'HTTP synthetic fixture', retention_until: h.now() + 900000, issuer_version: '1.0.0', claims: { account: 'TESTBANK000004', owner_id: resource } };
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
test('PER-007 PER-009: Secure Perception is dev-attested: forged attestations fail, releases are encrypted envelopes, no plaintext path', async t => {
  const h = await httpFixture(t);
  const bogus = await h.request('/v1/secure-perception/sessions', { method: 'POST', body: { attestation: { protected: { profile: 'IF-CJSON-1', suite: 'Ed25519', key_id: 'x', purpose: 'component-attestation' }, payload: { component: 'secure-view-acme', firmware_version: 'if-secureview-dev-1', nonce: 'a'.repeat(64) }, signature: 'x'.repeat(86) } } });
  assert.equal(bogus.status, 401);
  const component = h.setup.componentSecrets.acme['secure-view-acme'];
  const attestation = component.attest('b'.repeat(64), h.now() + 300000);
  const session = await h.request('/v1/secure-perception/sessions', { method: 'POST', body: { attestation } });
  assert.equal(session.status, 201, JSON.stringify(session.data)); assert.equal(session.data.assurance, 'dev-attested-software'); assert.equal(session.data.production, false);
  const release = await h.request('/v1/secure-perception/release', { method: 'POST', body: { session_id: session.data.session_id, fields: { secret_field: 'sensitive-value-123' }, purpose: 'review' } });
  assert.equal(release.status, 200); assert.equal(release.data.mode, 'secure-perception');
  assert.ok(!release.data.ciphertext.includes('sensitive-value-123'), 'ciphertext must not contain plaintext');
  const opened = openRelease({ ...component, _ecdh_private: component.ecdh_private }, release.data, session.data, h.now());
  assert.equal(opened.data.secret_field, 'sensitive-value-123');
  installPolicy(h, p => { p.secure_perception.fallback = 'denied'; });
  const denied = await h.request('/v1/secure-perception/fallback', { method: 'POST', body: { fields: { x: 'y' }, purpose: 'review' } });
  assert.equal(denied.status, 451);
});
function runWorker(data) { return new Promise((resolve, reject) => { const worker = new Worker(new URL('./race-worker.mjs', import.meta.url), { workerData: data }); worker.once('message', resolve); worker.once('error', reject); worker.once('exit', code => { if (code) reject(new Error(`Worker exit ${code}`)); }); }); }
test('COM-003 NFR-TST-002: eight independent gate workers race; exactly one certificate is consumed', async t => {
  const h = fixture(t), { certificate, record } = h.ready(), data = { config: h.setup.config, directory: h.directory, now: h.now(), principal: h.p(), certificate };
  const results = await Promise.all(Array.from({ length: 8 }, () => runWorker(data))); assert.equal(results.filter(r => r.success).length, 1, JSON.stringify(results)); assert.ok(results.filter(r => !r.success).every(r => r.code === 'INV-409-REPLAY')); assert.equal(h.f.target.state('acme', record.capsule.action.target_resource).version, 1);
});
test('DAT-002: concurrent gates cannot overspend shared rolling budget', async t => {
  const h = fixture(t); installPolicy(h, p => { p.runtime.windows[0].limit = 2; }); const cap = h.f.runtime.issue(h.p(), runtimeInput());
  const results = await Promise.all(Array.from({ length: 8 }, () => runWorker({ config: h.setup.config, directory: h.directory, now: h.now(), principal: h.p(), runtime: runtimeRequest(cap) })));
  assert.equal(results.filter(r => r.success).length, 1, JSON.stringify(results)); assert.ok(results.filter(r => !r.success).every(r => r.code === 'INV-429-BUDGET'));
});
test('NFR-SEC-004: bootstrap creates random credentials, private files and refuses overwrite', t => {
  const h = fixture(t), directory = join(h.directory, 'new-deployment'); bootstrap(directory); const config = loadConfiguration(directory); assert.equal(config.profile, 'engineering'); assert.ok(readFileSync(join(directory, 'access-tokens.json'), 'utf8').length > 100); assert.throws(() => bootstrap(directory), hasCode('INV-409-CONFLICT')); assert.throws(() => new h.f.constructor({ ...config, profile: 'production' }, directory), hasCode('INV-503-RELEASE'));
});
test('UX-002 UX-003 UX-005: UI state logic exposes no generic approval or executable non-ALLOW state', () => {
  assert.equal(actionAvailability('ESCROW', ['operator']).mint, false); assert.equal(actionAvailability('CERTIFIED', ['auditor']).execute, false); assert.equal(actionAvailability('CERTIFIED', ['operator']).execute, true); assert.match(nextAction('UNCERTAIN'), /Do not submit/);
  for (const value of ['', '0', '-1', '1.1', '1e3']) assert.throws(() => typedValue(value, 'positive')); assert.equal(typedValue('100', 'positive'), 100); assert.throws(() => csvSelection('a,a'));
});
test('UX-007: static interface labels all named inputs and uses no unsafe DOM injection sink', () => {
  const html = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8'), js = readFileSync(new URL('../web/app.js', import.meta.url), 'utf8');
  for (const m of html.matchAll(/<(?:input|select|textarea)\b[^>]*\bid="([^"]+)"/g)) assert.ok(html.includes(`for="${m[1]}"`), m[1]); assert.doesNotMatch(js, /\.innerHTML\s*=|insertAdjacentHTML|\beval\(/); assert.match(html, /not Secure Perception/); assert.match(html, /role="status"/);
});

test('UX-006 NET-010: /v1/approvals/batch and /v1/containment are real routes', async t => {
  const h = await httpFixture(t);
  const r1 = h.proposed(), r2 = h.proposed();
  for (const r of [r1, r2]) { h.evidence(r); h.evidence(r, { issuer: 'registry' }); }
  const subject = 'custodian-1', token = h.setup.credentials.acme[subject];
  const signatures = [];
  for (const r of [r1, r2]) {
    const challenge = h.f.approvalChallenge(h.p(subject), r.capsule.capsule_id);
    signatures.push(signed(challenge, h.setup.custodianKeys.acme[subject], 'action-approval'));
  }
  const ids = [r1.capsule.capsule_id, r2.capsule.capsule_id];
  const ok = await h.request('/v1/approvals/batch', { method: 'POST', token, body: { capsule_ids: ids, signatures } });
  assert.equal(ok.status, 201, JSON.stringify(ok.data)); assert.equal(ok.data.accepted, 2);
  const missing = await h.request('/v1/approvals/batch', { method: 'POST', token, body: { capsule_ids: ids, signatures: [signatures[0]] } });
  assert.equal(missing.status, 400);
  const roles = await h.request('/v1/approvals/batch', { method: 'POST', token: h.setup.credentials.acme.operator, body: { capsule_ids: ids, signatures } });
  assert.equal(roles.status, 403);
  const report = await h.request('/v1/containment', { token: h.setup.credentials.acme.security });
  assert.equal(report.status, 200); assert.ok(Array.isArray(report.data.sequence)); assert.equal(report.data.dropped_requests, 0); assert.match(report.data.limitation, /Software dataplane/);
});

test('RUN-006: rejection metrics count by reason code on the live HTTP surface', async t => {
  const h = await httpFixture(t);
  await h.request('/v1/action-capsules', { token: null }); // 401
  await h.request('/v1/revocations', { method: 'POST', token: h.setup.credentials.acme.auditor, body: {} }); // 403 role
  const m = await h.request('/v1/metrics', { token: h.setup.credentials.acme.security });
  assert.equal(m.status, 200);
  assert.equal(m.data.scope, 'tenant');
  // Requests whose principal never resolves (bad/missing token) cannot be
  // charged to any tenant; attributable rejections are counted per tenant.
  assert.equal(m.data.unauthorised, 0);
  assert.ok(m.data.rejections['INV-403-ROLE'] >= 1, JSON.stringify(m.data.rejections));
  const g = await h.request('/v1/metrics', { token: h.setup.credentials.globex.security });
  assert.equal(g.data.scope, 'tenant');
  assert.deepEqual(g.data.rejections, {}, 'one tenant must not observe another tenant\'s traffic');
});

test('UX-007: the controlled-workspace fallback succeeds end-to-end when policy permits', async t => {
  const h = await httpFixture(t);
  // Default policy permits 'controlled-workspace': the operator sees plaintext
  // fields over the normal channel, honestly labelled non-production.
  const out = await h.request('/v1/secure-perception/fallback', { method: 'POST', body: { fields: { account: 'TEST-1', amount: 50 }, purpose: 'review', reason: 'secure display unavailable' } });
  assert.equal(out.status, 200, JSON.stringify(out.data));
  assert.equal(out.data.mode, 'controlled-workspace');
  assert.equal(out.data.production, false);
  assert.equal(out.data.assurance, 'workspace-unattested');
  assert.equal(out.data.data.account, 'TEST-1');
  assert.deepEqual(out.data.binding.fields, ['account', 'amount']);
});

test('AUD-009: security evidence continues while optional analytics is disabled', async t => {
  const h = await httpFixture(t);
  // Product analytics is off by design; the required security evidence (the
  // signed audit chain) is unaffected.
  const metrics = await h.request('/v1/metrics', { token: h.setup.credentials.acme.security });
  assert.equal(metrics.status, 200);
  assert.equal(metrics.data.analytics_enabled, false);
  const audit = await h.request('/v1/audit/entries?limit=5', { token: h.setup.credentials.acme.auditor });
  assert.equal(audit.status, 200);
  assert.ok(audit.data.entries.length >= 1);
});

// w5-http-contract auditor regressions (report w5-http-contract.md).
test('w5-H1: malformed proof objects reject 400, never crash to 500', async t => {
  const h = await httpFixture(t), token = h.setup.credentials.acme.auditor;
  for (const proof of [null, 'x', [], 5]) {
    const r = await h.request('/v1/audit/verify-proof', { method: 'POST', token, body: { proof } });
    assert.equal(r.status, 400, `proof=${JSON.stringify(proof)}`); assert.equal(r.data.error.code, 'INV-400-SCHEMA');
  }
});

test('w5-H2: perception fallback rejects type-confused fields/purpose', async t => {
  const h = await httpFixture(t);
  for (const bad of [{ fields: 'x', purpose: 1 }, { fields: null, purpose: null }, { fields: [1], purpose: 'ok' }]) {
    const r = await h.request('/v1/secure-perception/fallback', { method: 'POST', body: bad });
    assert.equal(r.status, 400, JSON.stringify(bad));
  }
});

test('w5-M3/L7: query params obey the canonical integer grammar and uniqueness', async t => {
  const h = await httpFixture(t);
  for (const bad of ['0x10', '1e2', '+5', '%205%20', '5.0', '007', '0b101'])
    assert.equal((await h.request(`/v1/action-capsules?limit=${bad}`)).status, 400, bad);
  assert.equal((await h.request('/v1/action-capsules?limit=25&limit=50')).status, 400);
  assert.equal((await h.request('/v1/action-capsules?bogus=1')).status, 400);
  assert.equal((await h.request('/v1/action-capsules?LIMIT=25')).status, 400);
  assert.equal((await h.request('/v1/me?debug=1')).status, 400);
  assert.equal((await h.request('/v1/audit/consistency')).status, 200);
});

test('w5-M6: non-canonical request targets are rejected, not normalized', async t => {
  const h = await httpFixture(t);
  for (const bad of ['/v1/../v1/me', '/v1\\me', '/%2e%2e/v1/me', '/v1/a/../me'])
    assert.equal((await h.request(bad)).status, 400, bad);
});

test('w5-M4/L4/L5: connectors auth-gated; unknown resource and key 404', async t => {
  const h = await httpFixture(t);
  assert.equal((await h.request('/v1/connectors', { token: null })).status, 401);
  assert.equal((await h.request('/v1/connectors')).status, 200);
  assert.equal((await h.request('/v1/resources/does-not-exist')).status, 404);
  assert.equal((await h.request('/v1/keys/no-such-key/attest', { token: h.setup.credentials.acme.security })).status, 404);
});

// NFR-MNT-001: route↔spec parity — every documented path is a real route.
test('w5-M8: a wrong method on a documented path is a 405 on every route', async t => {
  const h = await httpFixture(t), spec = JSON.parse(readFileSync('docs/openapi.json', 'utf8'));
  for (const template of Object.keys(ROUTE_METHODS)) assert.ok(spec.paths[template], `route ${template} missing from openapi.json`);
  for (const [template, ops] of Object.entries(spec.paths)) {
    const wrong = ['GET', 'POST'].find(m => !Object.keys(ops).includes(m.toLowerCase()));
    if (!wrong) continue;
    const path = template.replaceAll(/\{[^}]+\}/g, 'x-1');
    const r = await h.request(path, { method: wrong });
    assert.equal(r.status, 405, `${wrong} ${path}`); assert.equal(r.data.error.code, 'INV-405-METHOD');
  }
});

test('HTTP: refusal responses carry the INV-* reason code, not just a status', async t => {
  const h = await httpFixture(t); const r = h.proposed();
  const cases = [
    ['/v1/me', { headers: { Host: 'evil.example' } }, 400, 'INV-400-HOST'],
    ['/v1/me', { headers: { Origin: 'https://evil.example' } }, 403, 'INV-403-ORIGIN'],
    ['/v1/me', { method: 'DELETE' }, 405, 'INV-405-METHOD'],
    ['/v1/action-capsules', { method: 'POST', body: '{', headers: { 'Content-Type': 'text/plain' } }, 415, 'INV-415-CONTENT'],
    ['/v1/action-capsules/' + r.capsule.capsule_id + '/outcome', {}, 404, 'INV-404-NOT-FOUND'],
    ['/v1/me', { token: 'forged-token' }, 401, 'INV-401-AUTH'],
  ];
  for (const [path, opts, status, code] of cases) {
    const res = await h.request(path, opts);
    assert.equal(res.status, status, `${path}: ${status}`);
    assert.equal(res.data?.error?.code, code, `${path}: ${code}`);
  }
  // Oversized body announces its limit before a byte is read.
  const big = await h.request('/v1/action-capsules', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': String(2 * 1048576) }, body: null });
  assert.equal(big.status, 413); assert.equal(big.data?.error?.code, 'INV-413-BODY');
});

import test from 'node:test';
import http from 'node:http';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture, hasCode, runtimeInput, setTenant, installPolicy } from './helpers.mjs';
import { createServer } from '../src/server.mjs';
import { createIssuerServer, loadIssuers } from '../src/issuerd.mjs';
import { httpJson } from '../src/connectors.mjs';
import { verifySigned, signed } from '../src/crypto.mjs';
import { digest } from '../src/canonical.mjs';

// Wave-22 HTTP/console audit regressions: rightmost XFF hop, authorize
// before field-shape, clipped expires_in, cookie Secure policy, connection
// bound, clock-recovery authority veto + session reaper, Content-Type
// tolerance — plus w22-ledger regressions: audit-read access rows,
// per-action retention ceilings, issuerd accessed entries, console
// coverage table, and the rollback drill.

function rawRequest(port, { path, method = 'GET', headers = {}, payload } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method, headers }, res => {
      const chunks = []; res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject); req.end(payload);
  });
}

test('w22-http F1: rate buckets key on the RIGHTMOST XFF hop, not client-controlled leftmost', async t => {
  const h = fixture(t);
  const origin = 'http://127.0.0.1:17779';
  const app = createServer(h.f, { port: 0, origin, trustProxy: true, proxySecret: 'test-proxy-secret-1234' });
  await app.listen(); t.after(() => app.close());
  const port = app.server.address().port;
  const hit = xff => rawRequest(port, { path: '/session', method: 'POST', headers: { Host: '127.0.0.1:17779', Origin: origin, 'X-Fabric-Proxy': 'test-proxy-secret-1234', 'X-Forwarded-For': xff, 'Content-Type': 'application/json', 'Content-Length': 2 }, payload: '{}' }).then(r => r.status);
  // Rotating the client-controlled leftmost hop must NOT rotate the bucket:
  // the proxy-vouched rightmost '10.9.9.9' exhausts its own login bucket.
  for (let i = 0; i < 20; i++) assert.notEqual(await hit(`10.1.1.${i}, 10.9.9.9`), 429, `request ${i}`);
  assert.equal(await hit('172.16.0.1, 10.9.9.9'), 429, 'rightmost hop shares the exhausted bucket');
  assert.notEqual(await hit('10.9.9.8'), 429, 'a different rightmost hop is a different identity');
});

test('w22-http F2: unauthorized callers get 403 before field-shape can leak the whitelist', async t => {
  const h = fixture(t);
  const origin = 'http://127.0.0.1:17778';
  const app = createServer(h.f, { port: 0, origin });
  await app.listen(); t.after(() => app.close());
  const port = app.server.address().port;
  const post = (path, token, body) => rawRequest(port, { path, method: 'POST', headers: { Host: '127.0.0.1:17778', Origin: origin, Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, payload: JSON.stringify(body) }).then(r => r.status);
  const cred = h.setup.credentials.acme;
  // Denied principal (403) vs authorized-role principal (400 on bad fields):
  // the role check must fire before field-shape validation leaks the schema.
  for (const [path, denied, allowed, body] of [
    ['/v1/audit-exports', cred.operator, cred.auditor, { purpose: 'x', smuggled: 1 }],
    ['/gate/v1/execute', cred.auditor, cred.operator, { certificate: {}, smuggled: 1 }],
    ['/v1/certificates', cred.auditor, cred.operator, { capsule_id: 'x', smuggled: 1 }],
    ['/v1/retention/sweep', cred.operator, cred.security, { smuggled: 1 }],
    ['/v1/keys/rotate-prepare', cred.operator, cred.security, { key_class: 'x', smuggled: 1 }],
    ['/v1/action-capsules', cred.auditor, cred.operator, { input: {}, signature: {}, smuggled: 1 }],
  ]) {
    assert.equal(await post(path, denied, body), 403, `${path} must deny unauthorized before fields`);
    assert.equal(await post(path, allowed, body), 400, `${path} authorized caller reaches field validation`);
  }
  // Consume inside the gate: operator is authorized → 400 on bad fields.
  assert.equal(await post('/gate/v1/runtime', cred.operator, { smuggled: 1 }), 400, 'consume shape after auth');
  assert.equal(await post('/gate/v1/runtime', cred.auditor, { smuggled: 1 }), 403, 'consume denied before fields');
});

test('w22-http F3+F4+F7: session expires_in is the real clipped lifetime; Secure on non-loopback-http origins; charset param accepted', async t => {
  const h = fixture(t);
  // Shorten the operator token to 30s so the 900s ceiling visibly clips.
  h.reconfigure(cfg => { const tn = cfg.tenants.acme; for (const entry of Object.values(tn.auth ?? {})) if (entry.subject_id === 'operator') entry.expires_at = h.now() + 30000; });
  const origin = 'https://gate.internal:8443'; // non-loopback https
  const app = createServer(h.f, { port: 0, origin });
  await app.listen(); t.after(() => app.close());
  const port = app.server.address().port;
  const login = await rawRequest(port, { path: '/session', method: 'POST', headers: { Host: 'gate.internal:8443', Origin: origin, 'Content-Type': 'application/json' }, payload: JSON.stringify({ token: h.setup.credentials.acme.operator }) });
  assert.equal(login.status, 200);
  const data = JSON.parse(login.body);
  assert.ok(data.expires_in <= 30 && data.expires_in > 0, `expires_in must reflect the clipped token lifetime, got ${data.expires_in}`);
  assert.match(login.headers['set-cookie']?.[0] ?? '', /; Secure/, 'non-loopback origin must set Secure');
  // A charset parameter on the media type is the same contract.
  const body = JSON.stringify({ purpose: 'x' });
  const charset = await rawRequest(port, { path: '/v1/audit-exports', method: 'POST', headers: { Host: 'gate.internal:8443', Origin: origin, Authorization: `Bearer ${h.setup.credentials.acme.auditor}`, 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) }, payload: body });
  assert.notEqual(charset.status, 415, 'charset parameter must not trip the media-type gate');
});

test('w22-http F5: the listener carries a bound on simultaneous connections', () => {
  assert.match(readFileSync(new URL('../src/server.mjs', import.meta.url), 'utf8'), /server\.on\('connection'.*destroy/s, 'unbounded accepts are a raw fd-exhaustion vector');
});

test('w22-http F6: clock recovery reaps sessions resurrected in the rewound span', async t => {
  const h = fixture(t);
  const origin = 'http://127.0.0.1:17781';
  const app = createServer(h.f, { port: 0, origin });
  await app.listen(); t.after(() => app.close());
  const port = app.server.address().port;
  const login = await rawRequest(port, { path: '/session', method: 'POST', headers: { Host: '127.0.0.1:17781', Origin: origin, 'Content-Type': 'application/json' }, payload: JSON.stringify({ token: h.setup.credentials.acme.operator }) });
  assert.equal(login.status, 200);
  const cookie = login.headers['set-cookie'][0].split(';')[0];
  const me = () => rawRequest(port, { path: '/v1/me', headers: { Host: '127.0.0.1:17781', Origin: origin, Cookie: cookie } }).then(r => r.status);
  assert.equal(await me(), 200);
  // Move forward past the session's 15-minute lifetime, land a clock row,
  // then regress so the session's expiry falls inside the rewound span.
  h.set(h.now() + 960000);
  h.f.store.tx(() => { const n = h.f.clock(); h.f.store.clock(n); });
  h.set(h.now() - 900000);
  h.f.recoverClock(h.p('security'));
  assert.equal(await me(), 401, 'a session whose expiry falls in the rewound span must not resurrect');
});

test('w22-ledger AUD-007: every audit-log READ records itself on the chain', t => {
  const h = fixture(t);
  h.f.auditPageScoped(h.p('auditor'), { after: 0, limit: 5 });
  h.f.auditProof(h.p('auditor'), 1);
  h.f.auditConsistency(h.p('auditor'), 1);
  h.f.containmentReport(h.p('security'));
  h.f.exportAudit(h.p('auditor'), 'regression');
  const surfaces = h.f.exportAudit(h.p('auditor'), 'readback').entries.filter(e => e.envelope?.payload?.type === 'AUDIT_ACCESSED').map(e => e.envelope.payload.metadata.surface);
  for (const s of ['page', 'proof', 'consistency', 'containment', 'export']) assert.ok(surfaces.includes(s), `missing access record for ${s}`);
});

test('w22-ledger AUD-006: action-class retention ceilings bound evidence like kind ceilings', t => {
  const h = fixture(t);
  const tenant = 'acme';
  // Install a constitution whose per_action ceiling is tighter than default
  // for data.read but silent for data.export — through the governed
  // policy.change pipeline (the only honest policy-edit path).
  installPolicy(h, p => { p.retention = { ...(p.retention ?? {}), default_ms: p.retention?.default_ms ?? 31536000000, per_kind: p.retention?.per_kind ?? {}, per_action: { 'data.export': 1000 } }; });
  // The envelope must be genuinely signed — the retention gate sits behind
  // signature verification inside verifyEvidenceEnvelope.
  const issEntry = Object.values(h.setup.config.tenants[tenant].issuers ?? {}).find(i => i.name === 'bank' || i.issuer_id === 'bank');
  const base = { kind: 'ownership', evidence_id: 'ev-aud6', tenant_id: tenant, capsule_digest: 'b'.repeat(64), content_digest: 'a'.repeat(64), acquired_at: h.now(), expires_at: h.now() + 1000, retention_until: h.now() + 2000, confidence: 90, advisory: false, claim: 'supports', dependencies: [], provenance: 'test', claims: {}, ...(issEntry?.version !== undefined ? { issuer_version: issEntry.version } : {}) };
  const envelope = signed(base, h.setup.issuerKeys[tenant]['bank'], 'evidence');
  assert.throws(() => h.f.verifyEvidenceEnvelope(tenant, envelope, 'data.export'), hasCode('INV-400-SCHEMA'), 'action ceiling must cap the envelope retention claim');
  assert.doesNotThrow(() => h.f.verifyEvidenceEnvelope(tenant, envelope, 'finance.payment.first'), 'unlisted actions keep the default ceiling');
});

test('w22-ledger issuerd: successful reads land accessed entries on the issuance chain', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'w22-issuerd-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { writeIssuer } = await import('../src/issuerd.mjs');
  const { generateKey } = await import('../src/crypto.mjs');
  const { ISSUER_RULES, issuerRecords } = await import('../src/bootstrap.mjs');
  writeIssuer(dir, { issuer: 'bank', tenant: 'acme', version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds: ISSUER_RULES.bank, records: issuerRecords().bank, issue_token: 'tok', read_token: 'tok' });
  const logPath = join(dir, 'issuance.log');
  const srv = createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', logPath });
  await srv.listen(); t.after(() => srv.close());
  const port = srv.server.address().port;
  await httpJson(`http://127.0.0.1:${port}/v1/issuers`, { token: 'tok' });
  await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/manifest?tenant=acme`, { token: 'tok' });
  await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/health?tenant=acme`, { token: 'tok' });
  const routes = readFileSync(logPath, 'utf8').trim().split('\n').map(l => JSON.parse(l)).filter(e => e.accessed === true).map(e => e.route);
  for (const r of ['issuers-list', 'manifest', 'health']) assert.ok(routes.includes(r), `missing accessed entry for ${r}`);
});

test('w22-ledger UX-009: the console renders the coverage manifest as a real per-path table', () => {
  const html = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8');
  const js = readFileSync(new URL('../web/app.js', import.meta.url), 'utf8');
  assert.match(html, /id="coverage-rows"/, 'coverage section needs a rows tbody');
  assert.match(js, /coverage-rows/, 'app.js must populate the coverage table');
  assert.doesNotMatch(js, /Coverage: Simulation only; production enforcement not established/, 'detail must show the anchored status, not a static disclaimer');
});

test('w22-ledger NFR-OPS-005: the drill simulates a bad release and a byte-exact rollback', () => {
  const sim = readFileSync(new URL('../scripts/simulate.mjs', import.meta.url), 'utf8');
  assert.match(sim, /BAD-RELEASE/, 'the drill must mutate the live deployment');
  assert.match(sim, /copyFileSync\(backupFile, liveFile\)/, 'the drill must restore the verified backup');
  const results = JSON.parse(readFileSync(new URL('../reports/simulation-results.json', import.meta.url), 'utf8'));
  const names = results.scenarios.map(s => s.name);
  assert.ok(names.includes('Rollback of fabric.db restores byte-identical deployment'), 'rollback byte-identity scenario missing');
  assert.ok(names.includes('Rolled-back store opens and audit chain re-verifies'), 'rollback health scenario missing');
});

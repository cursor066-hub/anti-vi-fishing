import test from 'node:test';
import http from 'node:http';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, chmodSync, writeFileSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { fixture, hasCode } from './helpers.mjs';
import { createIssuerServer, loadIssuers, writeIssuer } from '../src/issuerd.mjs';
import { createServer } from '../src/server.mjs';
import { ISSUER_RULES, issuerRecords, bootstrap, loadConfiguration } from '../src/bootstrap.mjs';
import { generateKey } from '../src/crypto.mjs';
import { applyTransforms } from '../src/datagate.mjs';
import { httpJson } from '../src/connectors.mjs';
import { digest } from '../src/canonical.mjs';

// Wave-10 fix-verification regressions: IPv6 URL crash, Host pinning,
// proxy-secret gating, digest format, mixed-registry refusal, 'null' tenant,
// proto-name transforms, connector JSON, config grammar.

const spec = (name, tokens = {}, kinds = ISSUER_RULES.bank, tenant = 'acme') => ({ issuer: name, tenant, version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds, records: issuerRecords().bank, ...tokens });
const issueBody = { kind: 'ownership', subject_id: 'operator', claims: { account: 'TESTBANK000001', owner_id: 'vendor-1' }, capsule_digest: 'a'.repeat(64), tenant_id: 'acme' };

test('w10 F-1: issuerd serves an IPv6 bind without the URL-constructor crash', async t => {
  let srv;
  try { srv = createIssuerServer({ 'acme:bank': spec('bank', { read_token: 'tok' }) }, { port: 0, host: '::1' }); await srv.listen(); }
  catch { t.skip('IPv6 loopback unavailable on this host'); return; }
  t.after(() => srv.close());
  const port = srv.server.address().port;
  // Raw request: the connector's own destination policy would refuse ::1,
  // but the regression is server-side (base-URL construction).
  const status = await new Promise((resolve, reject) => {
    const req = http.request({ host: '::1', port, path: '/v1/issuers/bank/manifest?tenant=acme', headers: { Host: `[::1]:${port}`, Authorization: 'Bearer tok' } },
      res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', reject); req.end();
  });
  assert.equal(status, 200);
});

test('w10 F-8: issuerd rejects a bare-address Host', async t => {
  const srv = createIssuerServer({ 'acme:bank': spec('bank', { read_token: 'tok' }) }, { port: 0, host: '127.0.0.1' });
  await srv.listen(); t.after(() => srv.close());
  const port = srv.server.address().port;
  for (const host of ['127.0.0.1', '[::ffff:127.0.0.1]', 'rebinding.example'])
    assert.equal((await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/manifest?tenant=acme`, { token: 'tok', headers: { Host: host } })).status, 400, host);
  // The socket-observed authority is the only one honoured.
  assert.equal((await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/manifest?tenant=acme`, { token: 'tok', headers: { Host: `127.0.0.1:${port}` } })).status, 200);
});

test('w10 F-13: issuerd refuses absolute-form and query-mismatched request targets', async t => {
  const srv = createIssuerServer({ 'acme:bank': spec('bank', { read_token: 'tok' }) }, { port: 0, host: '127.0.0.1' });
  await srv.listen(); t.after(() => srv.close());
  const port = srv.server.address().port;
  for (const target of [`http://127.0.0.1:${port}/healthz`, 'https://evil.example/v1/x', '/healthz\nInjected: 1']) {
    const status = await new Promise(resolve => {
      let req;
      try { req = http.request({ host: '127.0.0.1', port, path: target, method: 'GET', headers: { Host: `127.0.0.1:${port}` } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); }); }
      catch { resolve(599); return; } // refused client-side is also a refusal
      req.on('error', () => resolve(599)); req.end();
    });
    assert.notEqual(status, 200, target);
  }
  // The pathname-parsed route must match the raw target — a sneaky query
  // that changes the decoded path is refused.
  const r = await httpJson(`http://127.0.0.1:${port}/healthz?path=../../etc`, { headers: { Host: `127.0.0.1:${port}` } });
  assert.notEqual(r.status, 200);
});

test('w10 F-3: loadIssuers refuses malformed token digests at boot', async t => {
  for (const field of ['issue_token_digest', 'read_token_digest']) {
    const dir = mkdtempSync(join(tmpdir(), 'if-iss-')); t.after(() => rmSync(dir, { recursive: true }));
    writeIssuer(dir, spec('bank', { [field]: 'not-a-hex-digest' }));
    assert.throws(() => loadIssuers(dir), hasCode('INV-400-SCHEMA'), field);
  }
  const dir = mkdtempSync(join(tmpdir(), 'if-iss-')); t.after(() => rmSync(dir, { recursive: true }));
  writeIssuer(dir, spec('bank', { issue_token_digest: 'zz'.repeat(32) }));
  writeIssuer(dir, spec('hris', { issue_token_digest: digest('Bearer ok') }, ISSUER_RULES.hris));
  // One malformed file fails the whole load — partial registries are unsafe.
  assert.throws(() => loadIssuers(dir), hasCode('INV-400-SCHEMA'));
});

test('w10 F-5: a tokened issuer credential cannot mint through an open issuer', async t => {
  const issuers = {
    'acme:bank': spec('bank', { issue_token: 'tok-bank', read_token: 'tok-bank' }),
    'acme:hris': spec('hris', {}, ISSUER_RULES.hris), // opted-in open issuer
  };
  const srv = createIssuerServer(issuers, { port: 0, host: '127.0.0.1', allow_insecure_loopback: true });
  await srv.listen(); t.after(() => srv.close());
  const port = srv.server.address().port;
  // Presenting the bank's credential to the open issuer is refused — it must
  // not mint under a registry credential that isn't its own.
  const r = await httpJson(`http://127.0.0.1:${port}/v1/issuers/hris/issue`, { method: 'POST', token: 'tok-bank', body: { ...issueBody, kind: 'identity_proof' } });
  assert.equal(r.status, 404, JSON.stringify(r.data));
  // A mixed registry is closed by definition: the tokenless issuer is
  // unreachable unauthenticated (openLoopback requires ALL issuers
  // tokenless) — and any presented foreign credential is refused above.
  const open = await httpJson(`http://127.0.0.1:${port}/v1/issuers/hris/manifest?tenant=acme`);
  assert.equal(open.status, 401);
});

test("w10 F-6: a tenant literally named 'null' cannot be reached without the tenant param", async t => {
  const issuers = { 'null:bank': spec('bank', { read_token: 'tok' }, ISSUER_RULES.bank, 'null') };
  const srv = createIssuerServer(issuers, { port: 0, host: '127.0.0.1' });
  await srv.listen(); t.after(() => srv.close());
  const port = srv.server.address().port;
  // No ?tenant= — the bare name is ambiguous and must not resolve to tenant 'null'.
  assert.equal((await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/manifest`, { token: 'tok' })).status, 404);
  assert.equal((await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/manifest?tenant=null`, { token: 'tok' })).status, 200);
});

test('w10 F-9: proto-named transform keys miss the transform lookup instead of crashing', t => {
  const rows = [{ constructor: 1, watch: 'x', id: 7 }];
  for (const key of ['constructor', 'watch', 'unwatch', '__proto__']) {
    const transforms = JSON.parse(`{"${key}":{"op":"constant","arg":"X"}}`);
    const out = applyTransforms(rows, transforms, { subject_id: 's', tenant_id: 'acme' });
    assert.equal(out.length, 1);
    assert.equal(typeof out[0].id, 'number');
  }
  // Control: a real transform still applies.
  const applied = applyTransforms([{ salary: 100 }], { salary: { op: 'constant', arg: 0 } }, {});
  assert.equal(applied[0].salary, 0);
});

test('w10 F-10: connector malformed JSON is INV-502-CONNECTOR, not a caller fault', async t => {
  const stub = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"truncated":'); });
  await new Promise(r => stub.listen(0, '127.0.0.1', r)); t.after(() => stub.close());
  const port = stub.address().port;
  await assert.rejects(() => httpJson(`http://127.0.0.1:${port}/data`, { timeout_ms: 5000 }), hasCode('INV-502-CONNECTOR'));
  const bad = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(Buffer.from([0xff, 0xfe])); });
  await new Promise(r => bad.listen(0, '127.0.0.1', r)); t.after(() => bad.close());
  await assert.rejects(() => httpJson(`http://127.0.0.1:${bad.address().port}/data`), hasCode('INV-502-CONNECTOR'));
});

test('w10 F-12: loadConfiguration enforces strict grammar and refuses proto-named tenants', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-cfg-')); t.after(() => rmSync(dir, { recursive: true }));
  // Strict grammar: duplicate keys and comments fail at load, not silently.
  writeFileSync(join(dir, 'config.json'), '{"tenants":{"acme":{}},"tenants":{}}');
  assert.throws(() => loadConfiguration(dir), hasCode('INV-400-SCHEMA'));
  // Proto-member keys never survive the strict parser itself — the
  // canonicaliser refuses them before the tenant-name check can run.
  for (const name of ['constructor', 'watch', 'unwatch', 'toString', 'hasOwnProperty']) {
    writeFileSync(join(dir, 'config.json'), `{"tenants":{"${name}":{}}}`);
    assert.throws(() => loadConfiguration(dir), hasCode('INV-400-SCHEMA'), name);
  }
  // Charset violations that DO parse hit the config-time refusal.
  for (const name of ['Acme', '1acme', 'ACME']) {
    writeFileSync(join(dir, 'config.json'), JSON.stringify({ tenants: { [name]: {} } }));
    assert.throws(() => loadConfiguration(dir), hasCode('INV-503-CONFIG'), name);
  }
  writeFileSync(join(dir, 'config.json'), JSON.stringify({ tenants: { acme: {} } }));
  loadConfiguration(dir); // clean config loads
  // Defence in depth: tenant() itself refuses proto-member names even if a
  // config was loaded by other means.
  const h = fixture(t);
  assert.throws(() => h.f.tenant('constructor'), hasCode('INV-404-NOT-FOUND'));
  assert.throws(() => h.f.authorize({ subject_id: 'operator', tenant_id: 'hasOwnProperty' }, ['operator']), hasCode('INV-401-AUTH'));
});

test('w10 F-4: serve refuses group-readable custodian/component/issuer files', async t => {
  const cli = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
  const dir = join(mkdtempSync(join(tmpdir(), 'if-cli-')), 'deploy'); t.after(() => rmSync(dir, { recursive: true }));
  bootstrap(dir, ['acme']);
  const custodianFile = readdirSync(join(dir, 'offline-custodians'))[0];
  writeFileSync(join(dir, 'fabric.db-wal'), ''); // present the sidecar so the sweep can see it
  for (const target of [join('offline-custodians', custodianFile), 'component-acme.json', join('issuers', readdirSync(join(dir, 'issuers'))[0]), 'fabric.db-wal']) {
    const abs = join(dir, target);
    chmodSync(abs, 0o644);
    assert.throws(() => execFileSync(process.execPath, [cli, 'serve', '--dir', dir, '--port', '19553'], { encoding: 'utf8', timeout: 20000 }),
      e => (`${e.stdout ?? ''}${e.stderr ?? ''}${e.message}`).includes('INV-503-CONFIG'), target);
    chmodSync(abs, 0o600);
  }
});

test('w10 F-2: --trust-proxy without a proxy secret is a startup error', async t => {
  const h = fixture(t);
  assert.throws(() => createServer(h.f, { port: 0, origin: 'http://x', trustProxy: true }), hasCode('INV-503-CONFIG'));
  assert.throws(() => createServer(h.f, { port: 0, origin: 'http://x', trustProxy: true, proxySecret: 'short' }), hasCode('INV-503-CONFIG'));
});

test('w10 F-2: X-Forwarded-For without the secret falls back to the socket peer', async t => {
  const h = fixture(t);
  const origin = 'http://127.0.0.1:17778';
  const app = createServer(h.f, { port: 0, origin, trustProxy: true, proxySecret: 'proxy-secret-0123456789' }); await app.listen(); t.after(() => app.close());
  const port = app.server.address().port;
  const hit = secret => new Promise((resolve, reject) => {
    const headers = { Host: '127.0.0.1:17778', Origin: origin, 'X-Forwarded-For': '10.9.9.7', 'Content-Type': 'application/json', 'Content-Length': 2 };
    if (secret) headers['X-Fabric-Proxy'] = secret;
    const req = http.request({ host: '127.0.0.1', port, path: '/session', method: 'POST', headers },
      res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', reject); req.end('{}');
  });
  // 20 wrong-secret requests all land in the shared loopback bucket; the
  // forged XFF identity's bucket stays untouched (its own quota remains).
  for (let i = 0; i < 20; i++) assert.notEqual(await hit('wrong'), 429, `request ${i}`);
  assert.notEqual(await hit('proxy-secret-0123456789'), 429, 'secreted request keeps its own quota');
});

test('w10 NB-4: capsule-depth refusal names the storable bound at admission', async t => {
  const h = fixture(t);
  const { proposal, validateProposal } = await import('../src/schema.mjs');
  const { signed } = await import('../src/crypto.mjs');
  const { randomUUID } = await import('node:crypto');
  // Input depth exactly 30: the request-intent envelope still canonicalises
  // (bound 32), so validateProposal's domain check is the first failure a
  // caller sees — 'storable depth bound', not 'Maximum nesting depth'.
  const deep27 = {}; let cur = deep27;
  for (let i = 0; i < 27; i++) { cur.n = {}; cur = cur.n; }
  const input = proposal('finance.beneficiary.create', h.actor(), f => f, { vendor_id: 'vendor-1', bank_account: 'TESTBANK1', currency: 'EUR', extra: deep27 }, h.now());
  input.current_state = { version: 1, digest: digest({}), material_fields: {} };
  assert.throws(() => validateProposal(input), e => e?.code === 'INV-400-SCHEMA' && /storable depth bound/.test(e.message));
  // End-to-end: the signed-intent path reaches the same domain refusal.
  const intent = signed(input, h.setup.identityKeys.acme.operator, 'capsule-intent');
  assert.throws(() => h.f.propose(h.p(), input, randomUUID(), intent), e => e?.code === 'INV-400-SCHEMA' && /storable depth bound/.test(e.message));
});

test('w10 NB-2: the prototype-member blacklist is a literal set in canonical.mjs', async t => {
  const src = readFileSync(fileURLToPath(new URL('../src/canonical.mjs', import.meta.url)), 'utf8');
  // A getOwnPropertyNames(Object.prototype) enumeration would silently
  // shrink if the runtime ever extended the prototype — the set must be
  // spelled out literally so a diff shows it.
  assert.ok(!src.includes('getOwnPropertyNames(Object.prototype)'), 'blacklist must be a literal set');
  assert.ok(/new Set\(\[[^\]]*'constructor'/.test(src), 'blacklist literal must include constructor');
});

test('w10 B3: a perception attestation nonce replays exactly once', async t => {
  const h = fixture(t);
  const component = h.setup.componentSecrets.acme['secure-view-acme'];
  const attestation = component.attest('c'.repeat(64), h.now() + 300000);
  const first = h.f.perceptionSession(h.p(), attestation);
  assert.equal(first.assurance, 'dev-attested-software');
  // Same nonce → replay refusal.
  assert.throws(() => h.f.perceptionSession(h.p(), component.attest('c'.repeat(64), h.now() + 300000)), hasCode('INV-409-REPLAY'));
  // A legacy bare-nonce row also blocks the replay (pre-namespacing rows).
  h.f.store.db.prepare('INSERT INTO nonces VALUES(?,?,?)').run('acme', 'd'.repeat(64), 'legacy');
  assert.throws(() => h.f.perceptionSession(h.p(), component.attest('d'.repeat(64), h.now() + 300000)), hasCode('INV-409-REPLAY'));
});

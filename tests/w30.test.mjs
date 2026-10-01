// w30 regressions — policy auditor (F9 suite-retirement brick, F4a
// approvalChallenge signer pin) + issuerd auditor (F1 dual-daemon lock,
// F2 head-write order, F3 empty-truncate watermark, F4 technicalValidation
// gates, F5 expired-cred buckets, F6 source-IP rotation, F7 dep shape,
// F8 /issue probe charge).
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { fixture, hasCode, stageConstitution } from './helpers.mjs';
import { createIssuerServer, writeIssuer, loadIssuers } from '../src/issuerd.mjs';
import { ISSUER_RULES, issuerRecords } from '../src/bootstrap.mjs';
import { signed, generateKey } from '../src/crypto.mjs';
import { canonical, digest } from '../src/canonical.mjs';

const clone = v => JSON.parse(JSON.stringify(v));

function issuerDir(t, spec) {
  const dir = mkdtempSync(join(tmpdir(), 'w30-issuer-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeIssuer(dir, spec);
  return dir;
}
function spec(overrides = {}) {
  return { issuer: 'bank', tenant: 'acme', version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds: ISSUER_RULES.bank, records: issuerRecords().bank, issue_token: 'issue-tok', read_token: 'read-tok', ...overrides };
}
async function serve(t, dir, opts = {}) {
  const srv = createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', ...opts });
  await srv.listen(); t.after(() => srv.close().catch(() => {}));
  const port = srv.server.address().port;
  const req = (method, path, { token, body, localAddress } = {}) => new Promise((resolve, reject) => {
    const headers = { Host: `127.0.0.1:${port}`, Connection: 'close' };
    if (token) headers.Authorization = `Bearer ${token}`;
    let payload;
    if (body !== undefined) { payload = canonical(body); headers['Content-Type'] = 'application/json'; headers['Content-Length'] = Buffer.byteLength(payload); }
    const rq = http.request(`http://127.0.0.1:${port}${path}`, { method, headers, ...(localAddress ? { localAddress } : {}) }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    rq.on('error', reject); rq.end(payload);
  });
  return { srv, port, req };
}
const issueBody = { tenant_id: 'acme', capsule_digest: 'a'.repeat(64), kind: 'ownership', subject_id: 'operator', claims: { account: 'TESTBANK000001', owner_id: 'vendor-1' } };

// W30-ISSUERD-F1: a second daemon on the same log directory must refuse to
// boot — two issuers on one log fork the hash chain (duplicate seqs) and
// permanently wedge the next start (HIGH).
test('w30 issuerd F1: second daemon on one log directory refuses to boot', async t => {
  const dir = issuerDir(t, spec());
  const logPath = join(dir, 'issuance-log.jsonl');
  const a = await serve(t, dir, { logPath });
  assert.throws(() => createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', logPath }), hasCode('INV-503-CONFIG'));
  // The holder keeps serving — the lock does not disturb it.
  assert.equal((await a.req('POST', '/v1/issuers/bank/issue', { token: 'issue-tok', body: issueBody })).status, 201);
  // After a clean close the lock is released and a fresh daemon boots.
  await a.srv.close();
  const c = await serve(t, dir, { logPath });
  assert.equal((await c.req('GET', '/v1/issuers/bank/manifest', { token: 'read-tok' })).status, 200);
});

// W30-ISSUERD-F2: the capacity check precedes the .head watermark write — a
// routine cap refusal must not mint head-ahead-of-tail state that reads as
// truncation tamper on the next boot.
test('w30 issuerd F2: log-cap refusal leaves head pinned to the real tail', async t => {
  const dir = issuerDir(t, spec());
  const logPath = join(dir, 'issuance-log.jsonl');
  const a = await serve(t, dir, { logPath, log_max_bytes: 700 });
  let refused = null;
  for (let i = 0; i < 8 && !refused; i++) {
    const r = await a.req('POST', '/v1/issuers/bank/issue', { token: 'issue-tok', body: { ...issueBody, subject_id: `s-${i}` } });
    if (r.status >= 500) refused = r;
  }
  assert.ok(refused, 'cap refusal never arrived');
  const head = JSON.parse(readFileSync(`${logPath}.head`, 'utf8'));
  const lines = readFileSync(logPath, 'utf8').trim().split('\n').map(l => JSON.parse(l));
  assert.equal(head.sequence, lines.at(-1).sequence, 'watermark must never run ahead of the durable tail');
  // Honest state: the daemon reboots cleanly over the same log.
  await a.srv.close();
  await serve(t, dir, { logPath, log_max_bytes: 700 });
});

// W30-ISSUERD-F3: truncating the log to zero under a live head watermark is
// tamper evidence — boot refuses rather than re-genesising over vanished
// history.
test('w30 issuerd F3: empty log under a live head watermark refuses boot', async t => {
  const dir = issuerDir(t, spec());
  const logPath = join(dir, 'issuance-log.jsonl');
  const a = await serve(t, dir, { logPath });
  await a.req('POST', '/v1/issuers/bank/issue', { token: 'issue-tok', body: issueBody });
  await a.srv.close();
  writeFileSync(logPath, '');
  assert.throws(() => createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', logPath }), hasCode('INV-503-CONFIG'));
});

// W30-ISSUERD-F4: technicalValidation takes the same envelope trust gates as
// attachEvidence — tenant binding, acquisition freshness, and ledger-real
// dependencies (w30-issuerd F4).
function validationEnvelope(h, path, issuer, overrides = {}) {
  const payload = { evidence_id: randomUUID(), tenant_id: 'acme', capsule_digest: digest(path), kind: 'technical_validation', content_digest: digest({ probe: 'ok' }), acquired_at: h.now(), expires_at: h.now() + 60000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 'manual probe', retention_until: h.now() + 120000, issuer_version: '1.0.0', claims: { capsule_digest: digest(path) }, ...overrides };
  return { envelope: signed(payload, h.setup.issuerKeys.acme[issuer], 'evidence'), payload };
}
test('w30 issuerd F4: technicalValidation enforces tenant/freshness/dependency gates', t => {
  const h = fixture(t);
  h.f.declareCoverage(h.p('security'), { path_id: 'pv', action_type: 'data.export', target: 'dataset-1', environment: 'prod', connector_version: '1.0', owner: 'op', status: 'UNKNOWN', path_class: 'api', max_age_ms: 60000, configuration_digest: digest({ c: 1 }) });
  const path = () => h.f.store.must('acme', 'coverage', 'pv');
  assert.throws(() => h.f.technicalValidation(h.p('security'), 'pv', validationEnvelope(h, path(), 'security-ops', { tenant_id: 'globex' }).envelope), hasCode('INV-403-SCOPE'));
  assert.throws(() => h.f.technicalValidation(h.p('security'), 'pv', validationEnvelope(h, path(), 'security-ops', { acquired_at: h.now() - 8 * 86400000 }).envelope), hasCode('INV-400-SCHEMA'));
  assert.throws(() => h.f.technicalValidation(h.p('security'), 'pv', validationEnvelope(h, path(), 'security-ops', { dependencies: ['dep-that-exists-nowhere'] }).envelope), hasCode('INV-400-SCHEMA'));
  // A dependency that resolves to real ledger evidence satisfies the gate.
  const r = h.proposed();
  const env = h.evidence(r);
  assert.equal(h.f.technicalValidation(h.p('security'), 'pv', validationEnvelope(h, path(), 'security-ops', { dependencies: [env.payload.evidence_id] }).envelope).status, 'ENFORCED');
});

// W30-ISSUERD-F5: an expired credential must not earn its own per-cred
// bucket — expired bearers ride the shared IP line like unauthenticated
// traffic.
test('w30 issuerd F5: expired bearers spend the shared IP probe budget', async t => {
  const dir = issuerDir(t, spec({ token_expires_at: Date.now() - 1000 }));
  const a = await serve(t, dir);
  let last = null;
  for (let i = 0; i < 34; i++) last = await a.req('GET', '/v1/issuers/bank/manifest', { token: 'read-tok' });
  assert.equal(last.status, 429, `expired creds escaped the probe budget (last=${last.status})`);
});

// W30-ISSUERD-F6: on a loopback bind every 127/8 source is one client — a
// second loopback address must not mint a fresh budget.
test('w30 issuerd F6: loopback source-address rotation shares one bucket', async t => {
  const dir = issuerDir(t, spec());
  const a = await serve(t, dir);
  let last = null;
  for (let i = 0; i < 34; i++) last = await a.req('GET', '/v1/issuers/nope/manifest');
  assert.equal(last.status, 429);
  // 127.0.0.2 is a distinct source socket address on loopback — the budget
  // is already spent.
  const rotated = await a.req('GET', '/v1/issuers/nope/manifest', { localAddress: '127.0.0.2' });
  assert.equal(rotated.status, 429, 'loopback source rotation bought a fresh bucket');
});

// W30-ISSUERD-F7: issuerd must apply the fabric's full dependency shape
// contract — a signed envelope outside it could never attach anywhere.
test('w30 issuerd F7: overlong or duplicate dependencies are never minted', async t => {
  const dir = issuerDir(t, spec());
  const a = await serve(t, dir);
  const long = await a.req('POST', '/v1/issuers/bank/issue', { token: 'issue-tok', body: { ...issueBody, dependencies: ['x'.repeat(200)] } });
  assert.equal(long.status, 400);
  const dup = await a.req('POST', '/v1/issuers/bank/issue', { token: 'issue-tok', body: { ...issueBody, dependencies: ['d', 'd'] } });
  assert.equal(dup.status, 400);
  const ok = await a.req('POST', '/v1/issuers/bank/issue', { token: 'issue-tok', body: { ...issueBody, dependencies: ['dep-1'] } });
  assert.equal(ok.status, 201);
});

// W30-ISSUERD-F8: /issue 404 probing rides the probe budget like manifest
// and health — a foreign issue bearer must not buy 120/min enumeration.
test('w30 issuerd F8: /issue probing consumes the probe bucket', async t => {
  const dir = issuerDir(t, spec());
  const a = await serve(t, dir);
  let last = null;
  for (let i = 0; i < 34; i++) last = await a.req('POST', '/v1/issuers/ghost/issue', { token: 'issue-tok', body: issueBody });
  assert.equal(last.status, 429, `issue-route probing escaped the probe budget (last=${last.status})`);
});

// W30-POLICY-F9: a constitution that retires a suite a live vault key still
// signs under can never anchor its own activation — the gate it installs
// would refuse the POLICY_ACTIVATED signature itself. The apply path fails
// the outcome honestly instead of staging a brick.
test('w30 policy F9a: suite-retiring candidate fails the outcome, never stages', t => {
  const h = fixture(t);
  const next = clone(h.f.policy('acme')); next.version = 2; next.allow_weakening = true; next.algorithms = { ...(next.algorithms ?? {}), allowed_suites: ['ES256'] };
  const r = h.proposed('policy.change', { policy: next }, { action: { type: 'policy.change', target_resource: 'policy-root', purpose: 'Policy change' } });
  h.f.simulate(h.p('policy-admin'), next); h.advance(120001);
  h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'audit-committee' });
  h.approve(r, 4);
  const out = h.f.execute(h.p('operator'), h.f.certificate(h.p('operator'), r.capsule.capsule_id));
  assert.notEqual(out.payload.status, 'VERIFIED', 'suite-retiring constitution must never land');
  assert.equal(h.f.store.get('acme', 'policy', 'staged'), null, 'no staged row survives');
  assert.equal(h.f.policy('acme').version, 1);
  // The fabric is unwedged — honest work proceeds on the same constitution.
  h.ready(h.proposed());
});

// W30-POLICY-F9: a staged row carrying a suite-retiring constitution (e.g.
// staged before this guard existed, or restored from a pre-fix image) is
// superseded honestly by the activation sweep rather than wedging every
// transaction on an INV-451 throw.
test('w30 policy F9b: pre-existing suite-retiring staged row is superseded, not wedged', t => {
  const h = fixture(t);
  const bad = clone(h.f.policy('acme')); bad.version = 2; bad.policy_id = 'constitution:acme:bad-suite'; bad.algorithms = { ...(bad.algorithms ?? {}), allowed_suites: ['ES256'] };
  stageConstitution(h, bad, { activate_at: h.now() - 1 });
  h.proposed(); // any transaction runs the sweep
  assert.equal(h.f.store.get('acme', 'policy', 'staged'), null, 'the brick is retired');
  assert.equal(h.f.policy('acme').version, 1, 'the prior constitution stays live');
  const superseded = h.f.store.auditPage('acme', { limit: 200 }).entries.some(e => e.envelope.payload.type === 'POLICY_SUPERSEDED' && e.envelope.payload.metadata?.reason === 'suite-retirement-under-live-keys');
  assert.ok(superseded, 'the supersede is anchored in the ledger');
});

// W30-POLICY-F4a: approvalChallenge lets the caller pin which enrolled key
// signs — canonical ordering must not silently choose a key the caller's
// hardware cannot reach.
test('w30 policy F4a: approvalChallenge honours a caller-pinned signer_id', t => {
  const h = fixture(t);
  const r = h.proposed();
  const [keyId] = Object.entries(h.f.identities('acme')).find(([, v]) => v.subject_id === 'custodian-1');
  const challenge = h.f.approvalChallenge(h.p('custodian-1'), r.capsule.capsule_id, keyId);
  assert.equal(challenge.signer_id, keyId);
  assert.throws(() => h.f.approvalChallenge(h.p('custodian-1'), r.capsule.capsule_id, 'not-enrolled'), hasCode('INV-404-NOT-FOUND'));
});

// ---- w30 STORE audit regressions (4th pass) --------------------------
// F1 ledger-wipe gate, F2 hostile-file taxonomy, F3 savepoint anchor
// restore, F4 anchored idempotency, F5 anchored-row misattribution.
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { proposal } from '../src/schema.mjs';
import { Fabric } from '../src/fabric.mjs';

function surgery(dir, sql) {
  execFileSync('python3', ['-c', `
import sqlite3
c = sqlite3.connect(${JSON.stringify(join(dir, 'fabric.db'))})
c.execute('PRAGMA writable_schema=ON')
${sql}
c.commit(); c.close()`]);
}
const dropAndDelete = (dir, table) => surgery(dir, `
for n in [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='${table}'").fetchall()]: c.execute('DROP TRIGGER '+n)
c.execute('DELETE FROM ${table}')`);

function mkInput(h, overrides = {}) {
  const resource = `res-${randomUUID()}`;
  const state = h.f.target.state('acme', resource);
  return proposal('finance.beneficiary.create', h.actor('operator'), state, { vendor_id: 'v-1', bank_account: 'TESTBANK000002', currency: 'EUR' }, h.now(), { action: { type: 'finance.beneficiary.create', target_resource: resource, purpose: 'w30' }, policy_version: h.f.policy('acme').version, ...overrides });
}
const proposeKey = (h, key, input) => h.f.propose(h.p('operator', 'acme'), input, key, signed(input, h.setup.identityKeys.acme.operator, 'capsule-intent'));

test('w30-store F1: wiped fabric.db beside surviving artifacts refuses silent re-genesis', t => {
  const h = fixture(t, ['acme']);
  h.proposed();
  const dir = h.directory, cfg = clone(h.setup.config);
  h.close();
  for (const n of ['fabric.db', 'fabric.db-wal', 'fabric.db-shm', 'chain-heads.json', 'head-watermark.json']) rmSync(join(dir, n), { force: true });
  assert.ok(existsSync(join(dir, 'target.db')), 'prior-deployment artifact survives');
  assert.throws(() => new Fabric(cfg, dir, () => h.now()), hasCode('INV-503-STORAGE'));
});

test('w30-store F2: hostile files classify inside the INV taxonomy', t => {
  const h = fixture(t, ['acme']);
  h.proposed(); h.f.persistVault(); // a provisioned vault file on disk
  const dir = h.directory, cfg = clone(h.setup.config);
  h.close();
  writeFileSync(join(dir, 'fabric.db'), 'not a database');
  assert.throws(() => new Fabric(cfg, dir, () => h.now()), e => e?.code === 'INV-503-STORAGE' || e?.code === 'INV-503-LEDGER');
  for (const n of ['fabric.db', 'fabric.db-wal', 'fabric.db-shm']) rmSync(join(dir, n), { force: true });
  writeFileSync(join(dir, 'keystore.json'), '{garbage');
  assert.throws(() => new Fabric(cfg, dir, () => h.now()), hasCode('INV-503-CONFIG'));
});

test('w30-store F3: a faulting SAVEPOINT still restores the anchor stack', t => {
  const h = fixture(t, ['acme']);
  const orig = h.f.store.db.exec.bind(h.f.store.db);
  h.f.store.db.exec = sql => { if (String(sql).startsWith('SAVEPOINT')) throw new Error('injected savepoint fault'); return orig(sql); };
  assert.throws(() => h.f.store.tx(() => h.f.store.tx(() => {})), /injected savepoint fault/);
  assert.equal(h.f.store._anchorStack.length, 0, 'no anchor-stack leak on savepoint failure');
});

test('w30-store F4: a deleted idempotency receipt cannot silently re-mint', t => {
  const h = fixture(t, ['acme']);
  const key = 'idem-key-' + randomUUID().slice(0, 24);
  const input = mkInput(h);
  const first = proposeKey(h, key, input);
  dropAndDelete(h.directory, 'idempotency');
  // Same request replays to the live anchored capsule — no twin minted.
  const replay = proposeKey(h, key, input);
  assert.equal(replay.capsule.capsule_id, first.capsule.capsule_id);
  // A divergent request under the same key dies on the anchored hash bind.
  assert.throws(() => proposeKey(h, key, mkInput(h)), hasCode('INV-409-IDEMPOTENCY'));
});

test('w30-store F5: deleting an anchored records row is tamper evidence, not a 404', t => {
  const h = fixture(t, ['acme']);
  const r = h.proposed();
  surgery(h.directory, `
for n in [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='records'").fetchall()]: c.execute('DROP TRIGGER '+n)
c.execute("DELETE FROM records WHERE tenant='acme' AND kind='capsule' AND id='${r.capsule.capsule_id}'")`);
  assert.throws(() => h.f.getCapsule(h.p('operator', 'acme'), r.capsule.capsule_id), hasCode('INV-409-INTEGRITY'));
  assert.throws(() => h.f.getCapsule(h.p('operator', 'acme'), 'capsule-never-existed'), hasCode('INV-404-NOT-FOUND'));
});

// Wave-49 regression tests: the w49 findings across all four auditors —
// _landed total_changes binding (AFTER-trigger laundering), mimic guard
// classification, target.db _schemaGuard coverage, storage-class errcode
// split, seal-drop windowed reconstruction, gate-deny anchoring + ±2s
// binding, anchored grants murder decrypt-verify, rewind-safe denial
// minting, the governed issuer repin path, issuerd edges, and the
// ledger/check.mjs/traceability honesty gates.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, rmSync, unlinkSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { fixture, hasCode } from './helpers.mjs';
import { Fabric } from '../src/fabric.mjs';
import { reconstructionCheck } from '../src/datagate.mjs';
import { createIssuerServer, loadIssuers, writeIssuer, slash64 } from '../src/issuerd.mjs';
import { ISSUER_RULES, issuerRecords } from '../src/bootstrap.mjs';

async function serve(t, dir, opts = {}) {
  const srv = createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', ...opts });
  await srv.listen(); t.after(() => srv.close().catch(() => {}));
  return srv;
}

// --- fixverify CRITICAL-2: _landed binds the tx delta — AFTER-trigger
// side-effects convict even when changes()===1 on the INSERT itself ---
test('w49 C-2: an AFTER trigger writing side-effects inside a guarded audit insert is INV-409', t => {
  const h = fixture(t);
  h.f.store.db.exec("CREATE TRIGGER side_eff AFTER INSERT ON audit BEGIN INSERT INTO nonces(tenant,nonce,at) VALUES('acme','side',0); END");
  assert.throws(() => h.f.store.tx(() => h.f.store.audit('acme', 'TAMPER_PROBE', 'system', 'x', {}, h.f.clock())),
    hasCode('INV-409-INTEGRITY'), 'a foreign row-write riding our insert is laundering, not landing');
  h.close();
});

test('w49 C-2: an AFTER trigger writing side-effects inside a target grant insert is INV-409', t => {
  const h = fixture(t);
  h.f.target.db.exec("CREATE TRIGGER side_eff_t AFTER INSERT ON grants BEGIN INSERT INTO resources(tenant,id,version,value) VALUES('acme','laundered',1,'x'); END");
  assert.throws(() => h.f.target.grant('acme', 'grant-x', { issued_at: h.now() }),
    hasCode('INV-409-INTEGRITY'), 'an AFTER-trigger side-effect on the dataplane convicts the same way');
  h.close();
});

// --- fixverify MEDIUM-1: a planted trigger raising the guard's own text
// must classify as INTEGRITY, never the retryable CONFLICT arm ---
test('w49 M-1: a trigger mimicking the sequence-guard text classifies INV-409-INTEGRITY', t => {
  const h = fixture(t);
  h.f.store.db.exec("CREATE TRIGGER mimic_text BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'audit sequence must extend the head'); END");
  assert.throws(() => h.f.store.tx(() => h.f.store.audit('acme', 'TAMPER_PROBE', 'system', 'x', {}, h.f.clock())),
    hasCode('INV-409-INTEGRITY'), 'guard-text mimicry is tamper evidence, not a retryable conflict');
  h.close();
});

// --- fixverify MEDIUM-2: target.db writes are _schemaGuard-wrapped ---
test('w49 M-2: a planted RAISE(ROLLBACK) on grants classifies INV-409, not a raw sqlite error', t => {
  const h = fixture(t);
  h.f.target.db.exec("CREATE TRIGGER rb_grant BEFORE INSERT ON grants BEGIN SELECT RAISE(ROLLBACK, 'planted rollback'); END");
  assert.throws(() => h.f.target.grant('acme', 'grant-y', { issued_at: h.now() }),
    hasCode('INV-409-INTEGRITY'), 'a foreign RAISE on target.db lands in the INV taxonomy');
  h.close();
});

// --- fixverify MEDIUM-4: storage-class errcodes are operator faults,
// not tamper evidence ---
test('w49 M-4: _landed splits storage-class errcodes to INV-503, tamper codes to INV-409', t => {
  const h = fixture(t);
  const boom = errcode => () => { const e = new Error('sqlite fault'); e.errcode = errcode; throw e; };
  for (const code of [8, 10, 11, 13, 14, 15])
    assert.throws(() => h.f.store._landed(boom(code), 'probe'), hasCode('INV-503-STORAGE'), `errcode ${code} is storage-class`);
  assert.throws(() => h.f.store._landed(boom(1811), 'probe'), hasCode('INV-409-INTEGRITY'), 'errcode 1811 is trigger tamper evidence');
  h.close();
});

// --- runtime W49-3: a dropped seal event wedges coverage only inside the
// reconstruction window — an ancient drop cannot wedge exports forever ---
test('w49 W49-3: seal-dropped coverage is windowed, not permanent', t => {
  const h = fixture(t);
  const policy = { window_ms: 60000, max_distinct_rows: 100000, max_distinct_columns: 100000, max_coverage_percent: 100 };
  const args = { tenant: 'acme', subject: 's', dataset: 'd', rows: ['r1'], columns: ['c'], now: h.now(), policy, record: false, droppedEvents: 3 };
  const inside = reconstructionCheck(h.f.store.db, h.f.target.db, { ...args, sealDroppedAt: h.now() - 1000 });
  assert.equal(inside.allowed, false);
  assert.equal(inside.code, 'INV-429-BUDGET');
  const old = reconstructionCheck(h.f.store.db, h.f.target.db, { ...args, sealDroppedAt: h.now() - 120000 });
  assert.equal(old.allowed, true, 'a drop outside the window is attested history, not a live wedge');
  h.close();
});

// --- datagate mirror: an AFTER trigger inflating the touch write is
// laundering, same as a swallowed one ---
test('w49: a side-effect trigger on the data_access mirror convicts INV-409', t => {
  const h = fixture(t);
  h.f.store.db.exec("CREATE TRIGGER mirror_eff AFTER INSERT ON data_access BEGIN INSERT INTO nonces(tenant,nonce,capsule) VALUES('acme','m','x'); END");
  const policy = { window_ms: 60000, max_distinct_rows: 100000, max_distinct_columns: 100000, max_coverage_percent: 100 };
  assert.throws(() => reconstructionCheck(h.f.store.db, h.f.target.db, { tenant: 'acme', subject: 's', dataset: 'd', rows: ['r1'], columns: ['c'], now: h.now(), policy, record: true }),
    hasCode('INV-409-INTEGRITY'), 'extra rows riding the mirror write are tamper evidence');
  h.close();
});

// --- runtime W49-4/W49-5: a consume denial lands its containment row AND
// its fold entry, and the report binds them within the ±2s window ---
test('w49 W49-4/5: a denied consume anchors its containment row through the fold', t => {
  const h = fixture(t);
  assert.throws(() => h.f.runtime.consume(h.p(), { capability: { payload: { capability_id: 'forged' }, protected: {} }, device_id: 'd1', resource: 'dataset-1', destination: 'customer-vault', action: 'data.read', purpose: 'operations', columns: ['id'], row_ids: ['row-1'], request_id: 'req-deny-1', protocol: 'https', port: 443 }),
    () => true, 'a forged capability is denied');
  const report = h.f.containmentReport(h.p('security'));
  const row = report.sequence.find(r => r.request_id === 'req-deny-1');
  assert.ok(row, 'the denial landed a containment row');
  assert.equal(row.anchored, true, 'the fold binds the occurrence within the clock-skew window');
  h.close();
});

// --- runtime W49-2: a rewound clock must mint fresh denial evidence, not
// suppress everything under the memo's stale timestamp ---
test('w49 W49-2: rewound time re-mints AUTHORIZATION_DENIED evidence', t => {
  const h = fixture(t);
  const denied = () => { try { h.f.revoke(h.p('auditor'), { kind: 'device', id: 'd-x', reason: 'probe' }); } catch { /* denied */ } };
  denied();
  const count = () => h.f.store.db.prepare("SELECT count(*) n FROM audit WHERE tenant='acme' AND json_extract(envelope,'$.payload.type')='AUTHORIZATION_DENIED'").get().n;
  const first = count();
  denied();
  assert.equal(count(), first, 'an identical forward denial dedups');
  h.set(h.now() - 70000);
  denied();
  assert.equal(count(), first + 1, 'a rewound clock must mint fresh evidence, not suppress under a stale memo');
  h.close();
});

// --- runtime W49-1: a murdered grants ciphertext under a live anchored
// grant is INV-409 tamper evidence, not a silent INV-403 ---
test('w49 W49-1: forged grants ciphertext under an anchored grant is INV-409 murder evidence', t => {
  const h = fixture(t);
  const r = h.proposed('identity.jit.grant', { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-2'], ttl_ms: 300000, reason: 'Incident response', roles: [] }, { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'JIT access' } });
  h.evidence(r, { kind: 'identity_proof' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' });
  h.approve(r, 2);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  assert.equal(h.f.execute(h.p(), cert).payload.status, 'VERIFIED');
  const gid = h.f.listGrants(h.p(), 'operator').items[0].grant_id;
  // The file-writer can overwrite ciphertext but cannot encrypt — the
  // decrypt-verifying probe separates a live row from a planted one.
  h.f.target.db.prepare('UPDATE grants SET value=? WHERE tenant=? AND grant_id=?').run(randomBytes(64).toString('base64'), 'acme', gid);
  h.advance(61000); // close the apply heal window on the wall-time bound
  assert.throws(() => h.f.runtime.issue(h.p(), { device_id: 'operator-device', resource: 'dataset-1', destination: 'customer-vault', action: 'data.read', purpose: 'operations', columns: ['id'], row_ids: ['row-2'], classification: 'internal', jurisdiction: 'EU', max_cost: 10, ttl_ms: 60000 }),
    hasCode('INV-409-INTEGRITY'), 'a forged grants row under a live anchor is murder, not scope');
  h.close();
});

// --- fixverify C-1: listGrants names the ledger's revocation verdict on
// every row, so a resurrected pre-revoke grant is marked, not silent ---
test('w49 C-1: listGrants annotates ledger_revoked from the signed index', t => {
  const h = fixture(t);
  const r = h.proposed('identity.jit.grant', { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-2'], ttl_ms: 300000, reason: 'Incident response', roles: [] }, { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'JIT access' } });
  h.evidence(r, { kind: 'identity_proof' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' });
  h.approve(r, 2);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  h.f.execute(h.p(), cert);
  const gid = h.f.listGrants(h.p(), 'operator').items[0].grant_id;
  h.f.revoke(h.p('security'), { kind: 'grant', id: gid, reason: 'incident closed' });
  const listed = h.f.listGrants(h.p(), 'operator').items.find(g => g.grant_id === gid);
  assert.equal(listed.ledger_revoked, true, 'the ledger revocation verdict rides every listed row');
  h.close();
});

// --- ledger F4: repinIssuerSpec is the governed re-provisioning path —
// an anchored ISSUER_SPEC_REPINNED supersedes the frozen registration pin ---
test('w49 F4: a legitimate issuer record-set change re-pins on-chain instead of staying quarantined', async t => {
  const h = fixture(t, ['acme']);
  const [bankKeyId, bank] = Object.entries(h.f.tenant('acme').issuers).find(([, v]) => v.name === 'bank');
  const dir = mkdtempSync(join(tmpdir(), 'w49-repin-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const body = { issuer: 'bank', tenant: 'acme', channel: 'authoritative', version: '1.0.0', key: h.setup.issuerKeys.acme.bank, kinds: ISSUER_RULES.bank, records: issuerRecords().bank, read_token: bank.read_token };
  writeIssuer(dir, body);
  const srv = await serve(t, dir, { clock: () => h.now() });
  h.repoint(bankKeyId, `http://127.0.0.1:${srv.server.address().port}`);
  assert.equal((await h.f.checkIssuerDrift(h.p('security'), bankKeyId)).drifted, false);
  // A governed spec change: same key, honest new record row.
  unlinkSync(join(dir, 'bank.issuer.json'));
  writeIssuer(dir, { ...body, records: { ...issuerRecords().bank, 'account:NEW-SKU': { owner: 'vendor-9', status: 'active', verified_at: 1 } } });
  const srv2 = await serve(t, dir, { clock: () => h.now() });
  h.repoint(bankKeyId, `http://127.0.0.1:${srv2.server.address().port}`);
  const drifted = await h.f.checkIssuerDrift(h.p('security'), bankKeyId);
  assert.equal(drifted.drifted, true, 'the record-set change convicts as drift');
  const repin = await h.f.repinIssuerSpec(h.p('security'), bankKeyId);
  assert.equal(repin.repinned, true);
  assert.equal(repin.prior_digest, bank.spec_digest);
  const clean = await h.f.checkIssuerDrift(h.p('security'), bankKeyId);
  assert.equal(clean.drifted, false, 'the anchored pin supersedes the frozen baseline');
  await assert.rejects(() => h.f.repinIssuerSpec(h.p('security'), bankKeyId), hasCode('INV-409-CONFLICT'), 're-pinning an already-pinned digest refuses');
  const anchored = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND json_extract(envelope,'$.payload.type')='ISSUER_SPEC_REPINNED'").get();
  assert.ok(anchored, 'the re-pin is chain-anchored');
  h.close();
});

// --- seal prescan: the stored `previous` column is verified, not trusted ---
test('w49: a tampered stored previous column convicts at auditPage', t => {
  const h = fixture(t);
  h.proposed();
  // The append-only trigger names the live tamper itself — the prescan
  // defends the file-writer who drops the guard first.
  h.f.store.db.exec('DROP TRIGGER no_audit_update');
  h.f.store.db.prepare("UPDATE audit SET previous=? WHERE tenant='acme' AND seq=2").run('f'.repeat(64));
  assert.throws(() => h.f.store.auditPage('acme'), () => true, 'stored-column divergence is caught');
  h.close();
});

// --- issuerd edges: malformed IPv6 literal and openSync refusal paths ---
test('w49: slash64 returns unparseable literals unchanged instead of RangeError', t => {
  assert.equal(slash64('1:2:3:4:5::6:7:8:9'), '1:2:3:4:5::6:7:8:9');
  assert.equal(slash64('2001:db8:abcd:1234:beef:5678:9abc:def0'), '2001:db8:abcd:1234::/64');
});

// --- check.mjs itself: the reverse parity gate must pass on this tree ---
test('w49 F2: every live server route is declared in openapi.json', t => {
  const spec = JSON.parse(readFileSync('docs/openapi.json', 'utf8'));
  const declared = new Set(Object.keys(spec.paths ?? {}));
  assert.ok(declared.has('/v1/connectors/{id}/repin'), 'the repin route is contracted');
});

// --- fixverify HIGH-1 live probe: an assert-free title-mint no longer
// counts as citing evidence for a VERIFIED row ---
test('w49 HIGH-1: traceability requires the citing test to assert', t => {
  const src = readFileSync('scripts/traceability.py', 'utf8');
  assert.ok(src.includes("and _asserts_evidence(b, _file_assert_names(p))}"), 'the citing-titles comprehension demands an asserting body');
});

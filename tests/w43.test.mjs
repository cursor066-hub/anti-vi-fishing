// w43 regression suite — hostile-audit wave fixes: murdered execution
// journals wedge + attest egress (C1/C2), lived_until transitivity across
// re-seals (seal F-1), verified-future doomed rows name their bindings
// (seal F-2), bare-int watermark resolution never clears live tamper flags
// (seal F-5/store F-2), murdered JIT grants name murder (runtime H1),
// usage PK-squat read-back + >2^53 cost scream INV-409 (runtime M1/M2),
// unverified capability attribution split + anchored-denial enumeration
// (runtime M3/M4), seal-route validation ordering + conditional
// break-glass + traceability assert-gate (fv M1-M3), key-death cache
// rollback/tip-hash + durable AAD-migration markers + keystore perms on
// open (store F-1/F-4/F-5), floor-derived key claims steer the repoint
// (seal pin LOW), perception-session revocability + veto skip,
// dropped_requests counts requests not rows, and consume's murder check
// outranks expiry (check-order LOW).
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { chmodSync, writeFileSync, statSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID, randomBytes } from 'node:crypto';
import { fixture, hasCode, runtimeInput, runtimeRequest, plantAadMarker } from './helpers.mjs';
import { Fabric } from '../src/fabric.mjs';
import { createServer } from '../src/server.mjs';

const exportCert = (h, { actor = 'operator', row = 'row-1', columns = ['id'] } = {}) => {
  const principal = h.p(actor);
  const r = h.proposed('data.export', { dataset: 'dataset-1', columns, row_ids: [row], max_rows: 1, classification: 'internal', jurisdiction: 'EU' }, { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Operations' }, destination: 'customer-vault' }, principal);
  h.evidence(r, { kind: 'dataset_authority' }); h.approve(r, 1);
  return { record: r, certificate: h.f.certificate(principal, r.capsule.capsule_id) };
};
const beneChild = (h, n) => { const r = h.proposed('finance.beneficiary.create', { vendor_id: `vendor-${n}`, bank_account: `TESTBANK00000${n}`, currency: 'EUR' }); h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const compositeOf = (h, children) => { const r = h.proposed('action.composite', { children }, { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'Batch' } }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const jitCert = h => { const r = h.proposed('identity.jit.grant', { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-1'], ttl_ms: 300000, reason: 'Incident', roles: [] }, { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'JIT' } }); h.evidence(r, { kind: 'identity_proof' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const wmPath = h => join(h.directory, 'head-watermark.json');
const dropAuditGuards = h => {
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
    h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
};

async function httpFixture(t, serverOpts = {}) {
  const h = fixture(t), app = createServer(h.f, { port: 0, origin: 'http://127.0.0.1:17777', ...serverOpts });
  await app.listen(); t.after(() => app.close());
  const port = app.server.address().port;
  const request = (path, { method = 'GET', body, token = h.setup.credentials.acme.security, headers = {}, rawBody } = {}) => new Promise((resolve, reject) => {
    const payload = rawBody ?? (body === undefined ? undefined : JSON.stringify(body));
    const req = http.request({ host: '127.0.0.1', port, path, method, headers: { Host: '127.0.0.1:17777', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(payload === undefined ? {} : { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }), ...headers } }, response => {
      const chunks = []; response.on('data', c => chunks.push(c)); response.on('end', () => { const s = Buffer.concat(chunks).toString('utf8'); let data; try { data = JSON.parse(s); } catch { data = s; } resolve({ status: response.statusCode, data, headers: response.headers }); });
    }); req.on('error', reject); req.end(payload);
  });
  return { ...h, request, app, port };
}

// --- C1: a murdered execution journal is a named wedge + attested egress, never silent ---
test('w43 C1: anchored dispatch + murdered export journal wedges INV-409 and attests the egress', t => {
  const h = fixture(t);
  const { certificate } = exportCert(h);
  const certId = certificate.payload.certificate_id;
  const outcome = h.f.execute(h.p(), certificate, { fault: 'after-commit' });
  assert.equal(outcome.payload.status, 'UNCERTAIN');
  h.f.target.db.prepare('DELETE FROM transactions WHERE tenant=? AND id=?').run('acme', certId);
  assert.throws(() => h.f.reconcile(h.p('security'), certId), hasCode('INV-409-INTEGRITY'));
  const access = h.f._auditIndex('acme').dataAccess.find(a => a.certificate_id === certId);
  assert.ok(access?.journal_missing === true && access.wedged === true, 'worst-case egress attested');
});

test('w43 C1b: the same murder in finish() refuses to settle silently', t => {
  const h = fixture(t);
  const c = beneChild(h, 1);
  const certId = c.certificate.payload.certificate_id;
  h.f.execute(h.p(), c.certificate, { fault: 'after-commit' });
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='outcome' AND id=?").run(certId);
  h.f.target.db.prepare('DELETE FROM transactions WHERE tenant=? AND id=?').run('acme', certId);
  assert.throws(() => h.f.reconcile(h.p('security'), certId), hasCode('INV-409-INTEGRITY'));
});

// --- C2: a composite export child murdered post-anchor is wedged + attested, never releasable ---
test('w43 C2: murdered composite export child is WEDGED and its egress attested — never releasable', t => {
  const h = fixture(t);
  const ex = exportCert(h), bene = beneChild(h, 1);
  const parent = compositeOf(h, [bene.record.capsule.capsule_id, ex.record.capsule.capsule_id]);
  const exId = ex.certificate.payload.certificate_id;
  const orig = h.f.target.execute.bind(h.f.target);
  h.f.target.execute = (capsule, id, now, fault) => {
    const res = orig(capsule, id, now, fault);
    if (id === exId) { h.f.target.db.prepare('DELETE FROM transactions WHERE tenant=? AND id=?').run('acme', exId); throw new Error('response lost; journal murdered'); }
    return res;
  };
  const out = h.f.execute(h.p(), parent.certificate);
  h.f.target.execute = orig;
  const idx = h.f._auditIndex('acme');
  assert.equal(idx.intended?.has(exId), true, 'EXECUTION_INTENT anchored before the dispatch');
  assert.equal(idx.released?.has(exId) ?? false, false, 'murdered journal can never release a cert');
  assert.equal(out.payload.child_outcomes[ex.record.capsule.capsule_id], 'WEDGED');
  const access = idx.dataAccess.find(a => a.certificate_id === exId);
  assert.ok(access?.journal_missing === true, 'declared worst-case egress attested');
  assert.throws(() => h.f.execute(h.p(), ex.certificate), hasCode('INV-409-REPLAY'));
});

// --- seal F-1: lived_until is transitive across seals ---
test('w43 seal F-1: the lived_until horizon survives a second seal — clock rollback still vetoes', t => {
  const h = fixture(t);
  const c = beneChild(h, 9);
  const far = h.now() + 365 * 86400_000;
  h.livedForward(far);
  assert.equal(h.f._auditIndex('acme').livedUntil >= far, true, 'first seal attests the horizon');
  // Corrupt a surviving row below the seal — the next seal drops the carrier.
  dropAuditGuards(h);
  const below = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1 OFFSET 1").get().seq;
  h.f.store.db.prepare("UPDATE audit SET hash='00' WHERE tenant='acme' AND seq=?").run(below);
  h.f.invalidateAuditIndex('acme');
  h.f.sealAuditChain(h.p('security'));
  const idx = h.f._auditIndex('acme');
  assert.equal(idx.livedUntil >= far, true, 're-carried horizon keeps the attested span');
  h.set(h.now() + 1000);
  assert.throws(() => h.f.recoverClock(h.p('security')), hasCode('INV-503-TIME'));
});

// --- seal F-5 / store F-2: a bare-int entry never clears live tamper evidence ---
test('w43 seal F-5: bare-int watermark resolution keeps floor_stripped evidence alive', t => {
  const h = fixture(t);
  h.proposed(); h.proposed(); // two flushes worth of signed head
  h.close();
  rmSync(wmPath(h), { force: true });
  const f2 = new Fabric(h.setup.config, h.directory, h.now);
  try {
    f2._headWatermark('acme'); // floor_stripped bootstrap
    const headSeq = f2.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get().seq;
    writeFileSync(wmPath(h), JSON.stringify({ acme: headSeq }));
    f2._headWatermark('acme'); // bare-int resolve must NOT clear the flag
    const out = f2.sealAuditChain(h.p('security'));
    const tampered = out.head_watermark_tampered ?? [];
    assert.ok(tampered.some(x => x.kind === 'floor_stripped'), `flag must survive bare-int resolve: ${JSON.stringify(out)}`);
  } finally { f2.close(); }
});

// --- runtime H1: a murdered anchored JIT grant screams INV-409, not INV-403 ---
test('w43 runtime H1: murdered jit-grant rows under a live anchor name the murder', t => {
  const h = fixture(t);
  const cert = jitCert(h);
  h.f.execute(h.p(), cert.certificate);
  const grantId = `jit-${cert.certificate.payload.certificate_id}`;
  const narrowed = h.clone(h.setup.config);
  for (const ident of Object.values(narrowed.tenants.acme.identities)) if (ident.subject_id === 'operator') ident.grants = { resources: [], actions: [], destinations: [], columns: [], row_ids: [] };
  h.close();
  const f2 = new Fabric(narrowed, h.directory, h.now);
  try {
    f2.reassertConfig(h.p('security'));
    const cap = f2.runtime.issue(h.p(), runtimeInput({ columns: ['id'] }));
    f2.target.db.prepare('DELETE FROM grants WHERE tenant=? AND grant_id=?').run('acme', grantId);
    f2.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='jit-grant'").run();
    assert.throws(() => f2.runtime.consume(h.p(), runtimeRequest(cap)), hasCode('INV-409-INTEGRITY'));
  } finally { f2.close(); }
});

// --- runtime M1/M2: usage PK squat read-back + >2^53 cost both scream INV-409-REPLAY ---
test('w43 runtime M1: a squatted usage row with divergent billing is replay evidence', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  const req = runtimeRequest(cap);
  h.f.store.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?)').run('acme', 'mallory', 'other-dataset', h.now() + 1, 999, cap.payload.capability_id, req.request_id);
  assert.throws(() => h.f.runtime.consume(h.p(), req), hasCode('INV-409-REPLAY'));
});

test('w43 runtime M2: a squatted usage cost above 2^53 is replay evidence, not a gate fault', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  const req = runtimeRequest(cap);
  h.f.store.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?)').run('acme', cap.payload.subject_id, cap.payload.resource, h.now(), '9007199254740993', cap.payload.capability_id, req.request_id);
  assert.throws(() => h.f.runtime.consume(h.p(), req), hasCode('INV-409-REPLAY'));
});

// --- runtime M3: unverified capability attribution is named, never laundered ---
test('w43 runtime M3: an unverified envelope lands in unverified_capability_id only', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  const forged = { ...cap, payload: { ...cap.payload, capability_id: 'cap-victim' }, signature: 'A'.repeat(86) };
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(forged)), hasCode('INV-401-SIGNATURE'));
  const rows = h.f.store.ids('acme', 'containment').map(id => h.f.store.get('acme', 'containment', id));
  const denial = rows.find(r => r?.unverified_capability_id === 'cap-victim');
  assert.ok(denial, 'unverified claim named');
  assert.equal(denial.capability_id, null, 'never served as proven attribution');
});

// --- runtime M4: a murdered containment row is enumerated from the chain ---
test('w43 runtime M4: murdered containment rows surface in anchored_denials_missing_rows', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  try { h.f.runtime.consume(h.p(), { ...runtimeRequest(cap), port: 99 }); } catch { /* the denial is what we need */ }
  const anchored = h.f._auditIndex('acme').denials;
  assert.ok(anchored.length >= 1);
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='containment'").run();
  const report = h.f.containmentReport(h.p('security'));
  assert.ok(report.anchored_denials_missing_rows.length >= 1, 'murdered denial named from the anchor');
});

// --- fixverify M1: query validation precedes the seal mutation ---
test('w43 fv M1: /v1/audit/seal validates params before writing the ledger', async t => {
  const h = await httpFixture(t);
  const before = h.f.store.db.prepare("SELECT COUNT(*) n FROM audit WHERE tenant='acme'").get().n;
  const res = await h.request('/v1/audit/seal?bogus=1', { method: 'POST' });
  assert.equal(res.status, 400);
  const after = h.f.store.db.prepare("SELECT COUNT(*) n FROM audit WHERE tenant='acme'").get().n;
  assert.equal(after, before, 'a 400 must never mint a seal');
});

// --- fixverify M2: break-glass enforces chain-derived checks on a healthy chain ---
test('w43 fv M2: a revoked token cannot seal on a healthy chain', async t => {
  const h = await httpFixture(t);
  const control = await h.request('/v1/audit/seal', { method: 'POST' });
  assert.equal(control.status, 200);
  const hash = [...Object.entries(h.f.tenantMap().acme.auth)].find(([, e]) => e.subject_id === 'security')?.[0];
  assert.ok(hash, 'security token hash found');
  h.f.revoke(h.p('security'), { kind: 'token', id: hash, reason: 'test' });
  const res = await h.request('/v1/audit/seal', { method: 'POST' });
  assert.equal(res.status, 401, 'healthy chain still refuses a dead credential');
});

// --- fixverify M3: the traceability assert gate rejects literal-borne asserts ---
test('w43 fv M3: assert-shaped text inside literals cannot mint evidence', t => {
  const src = 'scripts/traceability.py';
  const probe = `
src = open('${src}').read()
exec(src[:src.index('def evidence_blocks')], {'__file__': '${src}'})
print(bool(_asserts("test('X', () => { const s = 'assert.ok(1)'; })")))
print(bool(_asserts("test('X', () => { const r = /assert.ok(1)/; })")))
print(bool(_asserts("test('X', () => { assert.ok(1); })")))
`;
  const out = execFileSync('python3', ['-c', `g={'__file__':'scripts/traceability.py'}\nexec(open('scripts/traceability.py').read()[:open('scripts/traceability.py').read().index('def evidence_blocks')], g)\nprint(bool(g['_asserts']("test('X', () => { const s = 'assert.ok(1)'; })")))\nprint(bool(g['_asserts']("test('X', () => { const r = /assert.ok(1)/; })")))\nprint(bool(g['_asserts']("test('X', () => { assert.ok(1); })")))`], { cwd: new URL('..', import.meta.url).pathname }).toString().trim().split('\n');
  assert.deepEqual(out, ['False', 'False', 'True']);
});

// --- store F-1: rollback leaves no phantom key deaths ---
test('w43 store F-1: a rolled-back revocation poisons no key-death facts', t => {
  const h = fixture(t);
  assert.throws(() => h.f.store.tx(() => {
    h.f.store.audit('acme', 'AUTHORITY_REVOKED', 'security', 'key:killer-1', {}, h.now());
    h.f._keyDeaths('acme'); // memoize the doomed death inside the tx
    throw new Error('abort');
  }), /abort/);
  assert.equal(h.f._keyDeaths('acme').has('killer-1'), false, 'rollback evicts the cache');
  // Refill the same seq shape — the tip-hash fingerprint still convicts residue.
  h.f.store.tx(() => h.f.store.audit('acme', 'HEALTH_ASSERTION', 'fixture', 'x', {}, h.now()));
  assert.equal(h.f._keyDeaths('acme').has('killer-1'), false);
});

// --- store F-4: durable aad_migration markers attest on reopen ---
test('w43 store F-4: a crash-surviving migration marker re-attests at the next open', t => {
  const h = fixture(t);
  plantAadMarker(h.f.store.db, 'acme', JSON.stringify({ migrated: 2, transplants: 1, ambiguous: 0, skipped: 3 }));
  h.reconfigure(() => {});
  assert.equal(h.f.store.db.prepare("SELECT COUNT(*) n FROM meta_kv WHERE tenant='acme' AND key='aad_migration'").get().n, 0, 'marker consumed');
  const events = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND envelope LIKE '%AAD_MIGRATION%'").all();
  assert.ok(events.length >= 1, 'migration attested on the signed chain');
});

// --- store F-5: keystore permissions self-heal on open ---
test('w43 store F-5: permissive keystore/master files are tightened at open', t => {
  const h = fixture(t);
  h.f.persistVault();
  h.close();
  chmodSync(join(h.directory, 'keystore.json'), 0o644);
  chmodSync(join(h.directory, 'master.key'), 0o644);
  const f2 = new Fabric(h.setup.config, h.directory, h.now);
  try {
    assert.equal(statSync(join(h.directory, 'keystore.json')).mode & 0o777, 0o600);
    assert.equal(statSync(join(h.directory, 'master.key')).mode & 0o777, 0o600);
  } finally { f2.close(); }
});

// --- seal pin LOW: a floor-derived key claim steers the repoint ---
test('w43 seal pin: a floor-derived key claim demands repoint or refuses honestly', t => {
  const h = fixture(t);
  const auditKid = h.f.tenant('acme').keys.audit.key_id;
  h.f.store.put('acme', 'revocation', `key:${auditKid}`, { reference: `key:${auditKid}`, actor: 'planted', at: h.now() }, h.now());
  // Floor claims only carry on a real cut — doom the tail row so the
  // sweep runs and the claim lands in the signed carry.
  dropAuditGuards(h);
  const tail = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get().seq;
  h.f.store.db.prepare("UPDATE audit SET hash='00' WHERE tenant='acme' AND seq=?").run(tail);
  h.f.invalidateAuditIndex('acme');
  // The doomed-tail carry promotes the planted 'key:' claim into the
  // signing death window on the spot: the repoint demands a successor and
  // none exists in the fixture — the honest outcome is a named refusal,
  // never a seal signed under the claimed key.
  assert.throws(() => h.f.sealAuditChain(h.p('security')), hasCode('INV-503-CONFIG'));
});

// --- perception-session revocability + veto skip ---
test('w43 veto: a revoked perception session no longer blocks clock recovery', t => {
  const h = fixture(t);
  const component = h.setup.componentSecrets.acme['secure-view-acme'];
  const sid = h.f.perceptionSession(h.p(), component.attest(randomBytes(32).toString('hex'), h.now() + 100_000))?.session_id;
  assert.ok(sid, 'session minted');
  const far = h.now() + 120_000;
  h.livedForward(far);
  h.set(far - 60_000); // rewind lands inside the session's expiry window
  assert.throws(() => h.f.recoverClock(h.p('security')), hasCode('INV-503-TIME'));
  h.f.revoke(h.p('security'), { kind: 'perception-session', id: sid, reason: 'test' });
  const out = h.f.recoverClock(h.p('security'));
  assert.equal(typeof out.recovered_at, 'number');
});

// --- dropped_requests counts denied requests, not surviving rows ---
test('w43 containment: a deduped denial burst still counts every request', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  for (let i = 0; i < 3; i++) { try { h.f.runtime.consume(h.p(), { ...runtimeRequest(cap), port: 99 }); } catch { /* denials counted */ } }
  const rows = h.f.store.ids('acme', 'containment').map(id => h.f.store.get('acme', 'containment', id)).filter(Boolean);
  assert.equal(rows.length, 1, '60s dedup keeps one row');
  const report = h.f.containmentReport(h.p('security'));
  assert.equal(report.dropped_requests, 3, 'the report counts requests');
});

// --- consume check-order: murder evidence outranks expiry ---
test('w43 consume order: an expired capability with a murdered row names the murder', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ ttl_ms: 5000 }));
  h.set(h.now() + 60_000);
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='capability' AND id=?").run(cap.payload.capability_id);
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap)), hasCode('INV-409-INTEGRITY'));
});

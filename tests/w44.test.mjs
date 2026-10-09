// w44 hostile-fix regression tests: the w44 auditor wave attacked the w43
// wave itself — composite release doctrine, signed head-pair rollback,
// the traceability assert gate, the fold fingerprint, egress dedup.
// Every test asserts the FIXED behavior; the attack shapes come from the
// auditor PoCs verbatim (w44-fixverify/w44-seal/w44-ledger reports).
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fixture, hasCode, runtimeInput, runtimeRequest, plantAadMarker } from './helpers.mjs';
import { createServer } from '../src/server.mjs';
import { Fabric } from '../src/fabric.mjs';
import { KeyVault } from '../src/keystore.mjs';

const exportCert = (h, { actor = 'operator', row = 'row-1', columns = ['id'] } = {}) => {
  const principal = h.p(actor);
  const r = h.proposed('data.export', { dataset: 'dataset-1', columns, row_ids: [row], max_rows: 1, classification: 'internal', jurisdiction: 'EU' }, { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Operations' }, destination: 'customer-vault' }, principal);
  h.evidence(r, { kind: 'dataset_authority' }); h.approve(r, 1);
  return { record: r, certificate: h.f.certificate(principal, r.capsule.capsule_id) };
};
const beneChild = (h, n) => { const r = h.proposed('finance.beneficiary.create', { vendor_id: `vendor-${n}`, bank_account: `TESTBANK00000${n}`, currency: 'EUR' }); h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const compositeOf = (h, children) => { const r = h.proposed('action.composite', { children }, { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'Batch' } }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const jitCert = h => { const r = h.proposed('identity.jit.grant', { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-1'], ttl_ms: 300000, reason: 'Incident', roles: [] }, { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'JIT' } }); h.evidence(r, { kind: 'identity_proof' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const dropAuditGuards = h => {
  const rows = h.f.store.db.prepare("SELECT name, sql FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all();
  for (const tr of rows) h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
  return () => { for (const tr of rows) if (tr.sql) h.f.store.db.exec(tr.sql); };
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

// ============================================================================
// w44-fixverify F-1: mutating composite children NEVER release — the pre-state
// oracle (target version+digest) is attacker-rewindable ciphertext, so
// 'reserved + no anchors + pre-state matches' cannot distinguish a murdered
// committed mutation from an honest never-ran one. Murder the journal in the
// commit window AND replay the pre-state row: the child must stay WEDGED.
// ============================================================================
test('w44 F-1: pre-state replay cannot release a wedged mutating child — no double execution', t => {
  const h = fixture(t);
  const bene = beneChild(h, 1), decoy = beneChild(h, 91);
  const parent = compositeOf(h, [bene.record.capsule.capsule_id, decoy.record.capsule.capsule_id]);
  const certId = bene.certificate.payload.certificate_id;
  const resource = bene.record.capsule.action.target_resource;
  const preRows = h.f.target.db.prepare('SELECT * FROM resources WHERE tenant=? AND id=?').all('acme', resource);
  const orig = h.f.target.execute.bind(h.f.target);
  h.f.target.execute = (capsule, id, now, fault) => {
    const res = orig(capsule, id, now, fault);
    h.f.target.db.prepare('DELETE FROM transactions WHERE tenant=? AND id=?').run('acme', id);
    h.f.target.db.prepare('DELETE FROM resources WHERE tenant=? AND id=?').run('acme', resource);
    const ins = h.f.target.db.prepare('INSERT INTO resources VALUES(?,?,?,?)');
    for (const r of preRows) ins.run(r.tenant, r.id, r.version, r.value);
    throw new Error('response lost; journal murdered in commit window');
  };
  const out = h.f.execute(h.p(), parent.certificate);
  h.f.target.execute = orig;
  const idx = h.f._auditIndex('acme');
  assert.equal(idx.intended.has(certId), true, 'intent anchored');
  assert.equal(idx.dispatched.has(certId), false, 'no dispatch anchor (crash window)');
  assert.equal(idx.outcomes.has(certId), false);
  // FIXED: no release over mutable pre-state — the child stays wedged for
  // reconcile, and the reserved cert can never re-fire (no double dispatch).
  assert.equal(out.payload.child_outcomes[bene.record.capsule.capsule_id], 'WEDGED', 'mutating child never releases on clay pre-state');
  assert.equal(h.f._auditIndex('acme').released?.has(certId) ?? false, false);
  assert.throws(() => h.f.execute(h.p(), bene.certificate), e => /^INV-409/.test(e?.code ?? ''), 'still-reserved cert cannot re-fire');
});

test('w44 F-1b: murdered journal without pre-state replay stays WEDGED', t => {
  const h = fixture(t);
  const bene = beneChild(h, 2), decoy = beneChild(h, 92);
  const parent = compositeOf(h, [bene.record.capsule.capsule_id, decoy.record.capsule.capsule_id]);
  const orig = h.f.target.execute.bind(h.f.target);
  h.f.target.execute = (capsule, id, now, fault) => {
    const res = orig(capsule, id, now, fault);
    h.f.target.db.prepare('DELETE FROM transactions WHERE tenant=? AND id=?').run('acme', id);
    throw new Error('response lost; journal murdered');
  };
  const out = h.f.execute(h.p(), parent.certificate);
  h.f.target.execute = orig;
  assert.equal(out.payload.child_outcomes[bene.record.capsule.capsule_id], 'WEDGED', 'un-replayed state keeps the murder wedged');
  assert.throws(() => h.f.execute(h.p(), bene.certificate), e => /^INV-409/.test(e?.code ?? ''));
});

// ============================================================================
// w44-fixverify F-2: signed head-pair rollback — both files are inside the
// attacker's write scope, so a coherent rollback erases a revocation from the
// fold's view. The in-ledger fold_floor marker (committed atomically with
// each audit row, outside the file pair) names the divergence at fresh open.
// ============================================================================
test('w44 F-2: two-file head rollback past a revocation attests floor_marker_ahead', t => {
  const h = fixture(t);
  const hash = [...Object.entries(h.f.tenantMap().acme.auth)].find(([, e]) => e.subject_id === 'security')?.[0];
  const snap = '/tmp/w44-head-snap'; mkdirSync(snap, { recursive: true });
  const files = ['chain-heads.json', 'head-watermark.json'];
  for (const f of files) if (existsSync(join(h.directory, f))) copyFileSync(join(h.directory, f), join(snap, f));
  h.f.revoke(h.p('security'), { kind: 'token', id: hash, reason: 'compromise' });
  assert.equal(h.f.revoked('acme', 'token', hash), true, 'revoked');
  const revRow = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND envelope LIKE '%AUTHORITY_REVOKED%' ORDER BY seq DESC LIMIT 1").get();
  dropAuditGuards(h);
  h.f.store.db.prepare("DELETE FROM audit WHERE tenant='acme' AND seq=?").run(revRow.seq);
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='revocation'").run();
  for (const f of files) if (existsSync(join(snap, f))) copyFileSync(join(snap, f), join(h.directory, f));
  h.f.persistVault(); h.close();
  const f2 = new Fabric(h.setup.config, h.directory, h.now);
  try {
    // The fold itself is clean — the coherent rollback is indistinguishable
    // from an older world inside the replayable pair. But the in-ledger
    // fold_floor marker survived the surgery and names it: the seal surface
    // carries named evidence, never silence (w44-fixverify F-2).
    assert.equal(f2.revoked('acme', 'token', hash), false, 'residual bound: a coherent all-file rollback still reads unrevoked');
    const marker = f2.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor'").get()?.value;
    const tip = f2.store.db.prepare("SELECT MAX(seq) s FROM audit WHERE tenant='acme'").get().s;
    assert.ok(Number(marker?.split(':')[0]) > tip, 'in-ledger marker attests the higher tip the files claim never happened');
    const seal = f2.sealAuditChain(h.p('security'));
    assert.ok(seal.head_watermark_tampered?.some(x => x.kind === 'floor_marker_ahead' && x.tenant_id === 'acme'), `rollback must be named: ${JSON.stringify(seal.head_watermark_tampered)}`);
  } finally { f2.close(); }
});

test('w44 F-2b: honest flow never sets floor_marker_ahead', t => {
  const h = fixture(t);
  const bene = beneChild(h, 7);
  h.f.execute(h.p(), bene.certificate);
  const marker = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor'").get()?.value;
  const tip = h.f.store.db.prepare("SELECT MAX(seq) s FROM audit WHERE tenant='acme'").get().s;
  assert.equal(Number(marker?.split(':')[0]), tip, 'marker tracks the tip');
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.ok(!seal.head_watermark_tampered?.some(x => x.kind === 'floor_marker_ahead'), `clean flow must not attest: ${JSON.stringify(seal.head_watermark_tampered)}`);
});

// ============================================================================
// w44-fixverify F-6: the traceability assert-gate must reject dead shapes —
// asserts inside if(false), never-invoked function literals, timer callbacks
// and after an unconditional t.skip are decorative, not evidence.
// ============================================================================
test('w44 F-6: dead/unreachable asserts no longer satisfy the assert-gate', t => {
  const src = execFileSync('python3', ['-c', `
g={'__file__':'scripts/traceability.py'}
exec(open('scripts/traceability.py').read()[:open('scripts/traceability.py').read().index('def evidence_blocks')], g)
print(bool(g['_asserts']("test('X', () => { if (false) assert.ok(1); })")))
print(bool(g['_asserts']("test('X', () => { const f = () => assert.ok(1); })")))
print(bool(g['_asserts']("test('X', t => { t.skip('unavailable'); assert.ok(1); })")))
print(bool(g['_asserts']("test('X', () => { setTimeout(() => assert.ok(1), 0); })")))
print(bool(g['_asserts']("test('X', t => { assert.ok(1); })")))
print(bool(g['_asserts']("test('X', t => { if (flag) assert.ok(1); })")))
print(bool(g['_asserts']("test('X', t => { if (x) t.skip('maybe'); assert.ok(1); })")))
print(bool(g['_asserts']("test('X', t => { assert.throws(() => { assert.ok(1); }); })")))
`], { cwd: new URL('..', import.meta.url).pathname }).toString().trim().split('\n');
  assert.deepEqual(src, ['False', 'False', 'False', 'False', 'True', 'True', 'True', 'True'],
    `dead shapes must not mint citations: ${src}`);
});

// ============================================================================
// w44-fixverify F-7: the chain-facts fingerprint recomputes the tip from row
// bytes — an envelope rewrite that preserves the stored hash column can no
// longer ride the memo; the refold convicts the row.
// ============================================================================
test('w44 F-7: tip-envelope rewrite with preserved hash column re-derives and convicts', t => {
  const h = fixture(t);
  h.f.store.tx(() => h.f.store.audit('acme', 'AUTHORITY_REVOKED', 'security', 'key:stale-1', {}, h.now()));
  assert.equal(h.f._keyDeaths('acme').has('stale-1'), true);
  dropAuditGuards(h);
  const row = h.f.store.db.prepare("SELECT seq,hash FROM audit WHERE tenant='acme' AND envelope LIKE '%stale-1%'").get();
  h.f.store.db.prepare("UPDATE audit SET envelope='{\"payload\":{\"type\":\"GARBAGE\"}}' WHERE tenant='acme' AND seq=?").run(row.seq);
  // FIXED: the fingerprint binds hash column + row bytes — the rewrite
  // re-derives instead of riding the stale memo, and the vanished death
  // is named as facts_regressed tamper evidence rather than silently
  // un-killing a dead signer.
  assert.equal(h.f._keyDeaths('acme').has('stale-1'), false, 'memo not ridden — the rewrite re-derived');
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.ok(seal.head_watermark_tampered?.some(x => x.kind === 'facts_regressed' && x.tenant_id === 'acme'), `regression must be named: ${JSON.stringify(seal.head_watermark_tampered)}`);
});

test('w44 F-7b: mid-table rewrite rides the facts memo fail-closed — the death over-reports, never launders', t => {
  const h = fixture(t);
  h.f.store.tx(() => h.f.store.audit('acme', 'AUTHORITY_REVOKED', 'security', 'key:stale-2', {}, h.now()));
  beneChild(h, 8); // real appends AFTER the revocation so it sits mid-table
  assert.equal(h.f._keyDeaths('acme').has('stale-2'), true);
  dropAuditGuards(h);
  const row = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND envelope LIKE '%stale-2%'").get();
  h.f.store.db.prepare("UPDATE audit SET envelope='{\"payload\":{\"type\":\"GARBAGE\"}}' WHERE tenant='acme' AND seq=?").run(row.seq);
  // Bounded residual (w44-fixverify F-7): the memo covers count/max-seq/tip —
  // a mid-table rewrite preserving all three keeps reporting the stale death
  // (fail-closed DoS direction only). The next append changes the shape and
  // the full fold wedges on the forged row — laundering is impossible.
  assert.equal(h.f._keyDeaths('acme').has('stale-2'), true, 'stale death persists — attacker gains nothing');
  // The first fold re-verify wedges on the forged row — the memo can only
  // ever delay conviction, never launder it.
  h.f.invalidateAuditIndex('acme');
  assert.throws(() => h.f._auditIndex('acme'), e => /^INV-409/.test(e?.code ?? ''), 'fold convicts the forged row');
});

// ============================================================================
// w44-fixverify F-8: egress attestation dedup is per-CLASS — a real charge
// entry must not suppress the journal_missing murder attestation.
// ============================================================================
test('w44 F-8: a real disclosure entry does not suppress journal_missing attestation', t => {
  const h = fixture(t);
  const ex = exportCert(h);
  h.f.execute(h.p(), ex.certificate);
  const certId = ex.certificate.payload.certificate_id;
  // A real charged disclosure exists for this certificate.
  assert.ok(h.f._auditIndex('acme').dataAccess.some(a => a.certificate_id === certId && !a.journal_missing), 'charged entry present');
  // Murder evidence for the same certificate must still mint its own class.
  h.f.store.tx(() => h.f._attestMurderedEgress('acme', ex.record.capsule, { certificate_id: certId }, h.now()));
  const jm = h.f._auditIndex('acme').dataAccess.filter(a => a.certificate_id === certId && a.journal_missing === true);
  assert.equal(jm.length, 1, 'journal_missing attestation minted beside the real charge');
  // And the same-class dedup still holds — a second call adds nothing.
  h.f.store.tx(() => h.f._attestMurderedEgress('acme', ex.record.capsule, { certificate_id: certId }, h.now()));
  assert.equal(h.f._auditIndex('acme').dataAccess.filter(a => a.certificate_id === certId && a.journal_missing === true).length, 1, 'idempotent');
});

// ============================================================================
// w44-ledger F5 (hold): a planted aad_migration marker attests digests, never
// attacker-chosen counts.
// ============================================================================
test('w44 L-5: planted aad_migration marker attests digests only, never counts', t => {
  const h = fixture(t);
  plantAadMarker(h.f.store.db, 'acme', JSON.stringify({ migrated: 4242, transplants: 0, ambiguous: 0, skipped: 0 }));
  h.reconfigure(() => {});
  const rows = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND envelope LIKE '%AAD_MIGRATION%'").all();
  assert.ok(rows.length >= 1, 'planted marker produced the attestation');
  const body = rows.map(r => r.envelope).join(' ');
  assert.ok(!body.includes('4242'), 'attacker-chosen counts never signed');
  assert.ok(body.includes('recovered_marker') && body.includes('marker_digests'), 'digests-only attestation');
});

// ============================================================================
// w44-runtime (hold): murdered jit-grant record + grants row → INV-409.
// ============================================================================
test('w44 R-1: half-murdered jit grant still names murder, not denial', t => {
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
    f2.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='jit-grant'").run();
    f2.target.db.prepare('DELETE FROM grants WHERE tenant=? AND grant_id=?').run('acme', grantId);
    assert.throws(() => f2.runtime.consume(h.p(), runtimeRequest(cap)), hasCode('INV-409-INTEGRITY'), 'murdered grant names murder');
  } finally { f2.close(); }
});

// ============================================================================
// Holds: malformed seal query, planted intent row, transplanted intent,
// intent survives seal, nested savepoint cache rollback.
// ============================================================================
test('w44 H-1: malformed query never reaches sealAuditChain', async t => {
  const h = await httpFixture(t);
  const before = h.f.store.db.prepare("SELECT COUNT(*) n FROM audit WHERE tenant='acme'").get().n;
  for (const p of ['/v1/audit/seal?bogus=1', '/v1/audit/seal?x=', '/v1/audit/seal?%41=1']) {
    const r = await h.request(p, { method: 'POST' });
    assert.equal(r.status, 400, `${p} rejected`);
  }
  assert.equal(h.f.store.db.prepare("SELECT COUNT(*) n FROM audit WHERE tenant='acme'").get().n, before, 'no seal minted');
});

test('w44 H-2: planted unsigned EXECUTION_INTENT wedges the fold, seal remediates', t => {
  const h = fixture(t);
  const c = beneChild(h, 3);
  const certId = c.certificate.payload.certificate_id;
  dropAuditGuards(h);
  const last = h.f.store.db.prepare("SELECT seq,hash FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get();
  const forged = { payload: { tenant_id: 'acme', sequence: last.seq + 1, previous: last.hash, type: 'EXECUTION_INTENT', actor: 'operator', reference: certId, metadata: {}, time: h.now() } };
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', last.seq + 1, last.hash, 'f'.repeat(64), JSON.stringify(forged));
  assert.throws(() => h.f.execute(h.p(), c.certificate), e => /^INV-409/.test(e?.code ?? ''), 'planted row wedges');
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.equal(seal.sealed, true, 'seal cuts the forged tail — wedge is recoverable');
  assert.doesNotThrow(() => h.f.execute(h.p(), c.certificate), 'honest execute proceeds after remediation');
});

test('w44 H-3: transplanted signed intent envelope fails chain binding', t => {
  const h = fixture(t);
  const a = exportCert(h), b = beneChild(h, 5);
  h.f.execute(h.p(), a.certificate);
  const intentRow = h.f.store.db.prepare("SELECT * FROM audit WHERE tenant='acme' AND envelope LIKE '%EXECUTION_INTENT%' ORDER BY seq DESC LIMIT 1").get();
  dropAuditGuards(h);
  const last = h.f.store.db.prepare("SELECT seq,hash FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get();
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', last.seq + 1, last.hash, intentRow.hash, intentRow.envelope);
  assert.throws(() => h.f.execute(h.p(), b.certificate), e => /^INV-409/.test(e?.code ?? ''), 'transplanted envelope wedges');
});

test('w44 H-4: EXECUTION_INTENT survives a seal — cut-tail cannot un-anchor intent', t => {
  const h = fixture(t);
  const ex = exportCert(h), bene = beneChild(h, 6);
  const parent = compositeOf(h, [bene.record.capsule.capsule_id, ex.record.capsule.capsule_id]);
  const exId = ex.certificate.payload.certificate_id;
  const orig = h.f.target.execute.bind(h.f.target);
  h.f.target.execute = (capsule, id, now, fault) => {
    const res = orig(capsule, id, now, fault);
    if (id === exId) { h.f.target.db.prepare('DELETE FROM transactions WHERE tenant=? AND id=?').run('acme', exId); throw new Error('lost'); }
    return res;
  };
  h.f.execute(h.p(), parent.certificate);
  h.f.target.execute = orig;
  dropAuditGuards(h);
  const tail = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get().seq;
  h.f.store.db.prepare("UPDATE audit SET hash='00' WHERE tenant='acme' AND seq=?").run(tail);
  h.f.invalidateAuditIndex('acme');
  h.f.sealAuditChain(h.p('security'));
  assert.equal(h.f._auditIndex('acme').intended.has(exId), true, 'intent re-anchored by lifecycle carryover');
  assert.throws(() => h.f.execute(h.p(), ex.certificate), hasCode('INV-409-REPLAY'));
});

test('w44 H-5: nested savepoint rollback leaves no phantom key deaths', t => {
  const h = fixture(t);
  assert.throws(() => h.f.store.tx(() => {
    h.f.store.audit('acme', 'AUTHORITY_REVOKED', 'security', 'key:outer-1', {}, h.now());
    assert.equal(h.f._keyDeaths('acme').has('outer-1'), true, 'mid-tx fold sees the row');
    assert.throws(() => h.f.store.tx(() => {
      h.f.store.audit('acme', 'AUTHORITY_REVOKED', 'security', 'key:inner-1', {}, h.now());
      assert.equal(h.f._keyDeaths('acme').has('inner-1'), true);
      throw new Error('abort-inner');
    }), /abort-inner/);
    assert.equal(h.f._keyDeaths('acme').has('inner-1'), false, 'inner rollback evicted the death');
    assert.equal(h.f._keyDeaths('acme').has('outer-1'), true, 'outer row still seen mid-tx');
    throw new Error('abort-outer');
  }), /abort-outer/);
  assert.equal(h.f._keyDeaths('acme').has('outer-1'), false, 'outer rollback evicted too');
});

test('w44 H-6: usage PK squat with divergent fields screams; identical mirror admits', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  for (const [subj, res, at] of [['mallory', 'dataset-1', h.now()], ['operator', 'other', h.now()], ['operator', 'dataset-1', h.now() + 1]]) {
    const req = runtimeRequest(cap);
    h.f.store.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?)').run('acme', subj, res, at, 1, cap.payload.capability_id, req.request_id);
    assert.throws(() => h.f.runtime.consume(h.p(), req), hasCode('INV-409-REPLAY'));
  }
  const cap2 = h.f.runtime.issue(h.p(), runtimeInput());
  const req2 = runtimeRequest(cap2);
  const cost = req2.row_ids.length * cap2.payload.columns.length * cap2.payload.runtime_policy.sensitivity_weights[cap2.payload.classification];
  h.f.store.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?)').run('acme', cap2.payload.subject_id, cap2.payload.resource, h.now(), cost, cap2.payload.capability_id, req2.request_id);
  assert.doesNotThrow(() => h.f.runtime.consume(h.p(), req2), 'identical mirror row admits — benign');
});

// ---- w44-store report findings (7th pass: meta_kv markers, fsync,
// respelled envelopes, schema taxonomy, key-object cache) ----

test('w44-store H-1/M-1: a ghost-tenant aad_migration marker is attested once, then cleared — never a boot wedge', t => {
  const h = fixture(t);
  plantAadMarker(h.f.store.db, 'ghost', JSON.stringify({ migrated: 1 }));
  h.close();
  const f2 = new Fabric(h.setup.config, h.directory, h.now);
  try {
    const rows = f2.store.db.prepare("SELECT envelope FROM audit WHERE json_valid(envelope) AND json_extract(envelope,'$.payload.type')='AAD_MIGRATION_MARKER'").all();
    assert.equal(rows.length, 1, 'the foreign marker attests once as tamper evidence under this chain');
    const pl = JSON.parse(rows[0].envelope).payload;
    assert.equal(pl.metadata.claimed_tenant, 'ghost');
    assert.equal(f2.store.db.prepare("SELECT COUNT(*) n FROM meta_kv WHERE key='aad_migration'").get().n, 0, 'marker cleared — no residue, no wedge');
  } finally { f2.close(); }
  // A replayed marker dedupes against the chain — same content mints no
  // second anchor (w44-store M-1).
  const f3 = new Fabric(h.setup.config, h.directory, h.now);
  try {
    plantAadMarker(f3.store.db, 'ghost', JSON.stringify({ migrated: 1 }));
    f3.close();
    const f4 = new Fabric(h.setup.config, h.directory, h.now);
    try {
      assert.equal(f4.store.db.prepare("SELECT COUNT(*) n FROM audit WHERE json_valid(envelope) AND json_extract(envelope,'$.payload.type')='AAD_MIGRATION_MARKER'").get().n, 1, 'replayed marker deduped');
      assert.equal(f4.store.db.prepare("SELECT COUNT(*) n FROM meta_kv WHERE key='aad_migration'").get().n, 0);
    } finally { f4.close(); }
  } catch (e) { try { f3.close(); } catch { /* already closed */ } throw e; }
});

test('w44-store H-1b: an Infinity-valued marker parses as evidence, never wedges as INV-400', t => {
  const h = fixture(t);
  plantAadMarker(h.f.store.db, 'acme', '{"migrated":1e309}');
  h.close();
  const f2 = new Fabric(h.setup.config, h.directory, h.now);
  try {
    // The marker is digest-only evidence — its content is never trusted
    // enough to reach canonical(), so an Infinity payload cannot wedge
    // the open path. The delete alone is not the pass condition: the
    // digest must land on a VERIFIED AAD_MIGRATION row first (w45-ledger
    // MEDIUM-2 — an unattested delete is the laundering hole).
    const rows = f2.store.db.prepare("SELECT envelope FROM audit WHERE json_valid(envelope) AND json_extract(envelope,'$.payload.type')='AAD_MIGRATION'").all();
    assert.equal(rows.length, 1, 'marker digest attested on the migration row');
    assert.equal(JSON.parse(rows[0].envelope).payload.metadata?.recovered_marker, true);
    assert.equal(f2.store.db.prepare("SELECT COUNT(*) n FROM meta_kv WHERE key='aad_migration'").get().n, 0);
  } finally { f2.close(); }
});

test('w44-store H-3a: a respelled AUTHORITY_REVOKED still folds the death window on store surfaces', t => {
  const h = fixture(t);
  // Anchor a key death directly — revoke() itself is ceremony-gated, the
  // fold only cares about the signed row.
  h.f.store.audit('acme', 'AUTHORITY_REVOKED', 'security', 'key:dead-kid-1', { reason: 'compromise' }, h.now());
  const row = h.f.store.db.prepare("SELECT seq,envelope FROM audit WHERE tenant='acme' AND json_valid(envelope) AND json_extract(envelope,'$.payload.type')='AUTHORITY_REVOKED' ORDER BY seq DESC LIMIT 1").get();
  const __r = dropAuditGuards(h);
  const respelled = row.envelope.replace('"type":"AUTHORITY_REVOKED"', '"\\u0074ype":"AUTHORITY_REVOKED"');
  assert.notEqual(respelled, row.envelope);
  // The respelled text parses to the identical payload — it verifies and
  // folds normally, so the row must NOT vanish from the death window.
  assert.equal(JSON.parse(respelled).payload.type, 'AUTHORITY_REVOKED');
  h.f.store.db.prepare('UPDATE audit SET envelope=? WHERE tenant=? AND seq=?').run(respelled, 'acme', row.seq);
  __r();
  h.f.invalidateAuditIndex('acme');
  assert.equal(h.f.store._auditKeyDeaths('acme').has('dead-kid-1'), true, 'parsed-type scan survives the respell');
  assert.equal(h.f._keyDeaths('acme').has('dead-kid-1'), true, 'chain-facts scan survives the respell');
});

test('w44-store M-2: a dropped audit table classifies INV-409 on the write path', t => {
  const h = fixture(t);
  dropAuditGuards(h);
  h.f.store.db.exec('DROP TABLE audit');
  h.f.invalidateAuditIndex('acme');
  assert.throws(() => h.f.store.audit('acme', 'AAD_MIGRATION', 'system', 'x', {}, h.now()), hasCode('INV-409-INTEGRITY'), 'raw sqlite noise must not escape the write path');
});

test('w44-store H-2: vault.save leaves an owner-only MAC-valid file', t => {
  const h = fixture(t);
  const kf = join(h.directory, 'keystore-test.json');
  h.f.vault.generate('backup-manifest');
  h.f.vault.save(kf);
  const st = statSync(kf);
  assert.equal(st.mode & 0o777, 0o600);
  const re = KeyVault.load(kf, h.f.vault.masterKey.toString('base64url'));
  assert.ok(re.list().some(k => (Array.isArray(k.purpose) ? k.purpose : [k.purpose]).includes('backup-manifest')));
});

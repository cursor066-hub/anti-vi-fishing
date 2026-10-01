// w29-lifecycle: the anchored lifecycle is the authority — a store-level
// writer can never launder, unbind, orphan or silently swallow it via
// mutable rows. Fifth-pass regression tests for the attacks the w29
// hostile audit demonstrated.
import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode } from './helpers.mjs';
import { clone } from '../src/canonical.mjs';

// W29-F1: a planted capsule.certificate_id pointer must never land an
// anchored CANCELLED verdict on the foreign live certificate — the
// ACTION_CANCELLED event binds only the anchored issuance.
test('W29-F1: planted certificate_id cannot cancel a foreign anchored cert', t => {
  const h = fixture(t);
  const victim = h.ready();
  const victimCertId = victim.certificate.payload.certificate_id;
  const victimCapsuleId = victim.record.capsule.capsule_id;
  const atk = h.proposed();
  const atkId = atk.capsule.capsule_id;

  // store-writer primitive: plant the victim's cert id on the attacker's row
  const rec = h.f.store.must('acme', 'capsule', atkId);
  rec.certificate_id = victimCertId;
  h.f.store.put('acme', 'capsule', atkId, rec, h.now());

  h.f.cancel(h.p(), atkId);

  // the foreign certificate was never anchored as cancelled
  assert.equal(h.f._auditIndex('acme').outcomes.get(victimCertId), undefined);
  assert.ok(h.f._auditIndex('acme').cancelled.has(atkId));
  // …and it still spends as the live authority it is
  const out = h.f.execute(h.p(), victim.certificate);
  assert.equal(out.payload.status, 'VERIFIED');
  assert.equal(h.f._auditIndex('acme').outcomes.get(victimCertId), 'VERIFIED');
  assert.equal(h.f.store.must('acme', 'certificate', victimCertId).status, 'VERIFIED');
});

// W29-F2: terminality is anchored, not row-derived — deleting the outcome
// row is integrity evidence, never a chance to re-fire finish and demote
// an anchored VERIFIED into FAILED.
test('W29-F2: deleting the outcome row screams integrity, never rewrites anchored VERIFIED', t => {
  const h = fixture(t);
  const next = clone(h.f.policy('acme')); next.version += 1; next.allow_weakening = true;
  const r = h.proposed('policy.change', { policy: next },
    { action: { type: 'policy.change', target_resource: 'policy-root', purpose: 'Amend constitution' } });
  h.f.simulate(h.p('policy-admin'), next); h.advance(120001);
  h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'audit-committee' });
  h.approve(r, 4);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  const certId = cert.payload.certificate_id;

  const out = h.f.execute(h.p(), cert);
  assert.equal(out.payload.status, 'VERIFIED');
  assert.equal(h.f.policy('acme').version, next.version);

  const outcomes = () => h.f.store.db.prepare(
    "SELECT COUNT(*) c FROM audit WHERE tenant='acme' AND json_extract(envelope,'$.payload.type')='EXECUTION_OUTCOME' AND json_extract(envelope,'$.payload.reference')=?").get(certId).c;
  assert.equal(outcomes(), 1);

  // store-writer deletes the mutable outcome row
  h.f.store.shred('acme', 'outcome', certId);

  // reconcile must scream integrity — the anchored verdict is terminal
  assert.throws(() => h.f.reconcile(h.p('security'), certId), hasCode('INV-409-INTEGRITY'));
  assert.equal(h.f._auditIndex('acme').outcomes.get(certId), 'VERIFIED', 'anchored verdict never demoted');
  assert.equal(outcomes(), 1, 'no second EXECUTION_OUTCOME anchor may land');
});

// W29-F3: a grafted donor envelope on the parent cert row is tamper
// evidence — the child must never silently unbind into a solo spend.
test('W29-F3: parent-cert envelope graft screams integrity, never unbinds a live child', t => {
  const h = fixture(t);
  const dead = h.proposed('finance.beneficiary.create',
    { vendor_id: 'vd', bank_account: 'TESTBANK000009', currency: 'EUR' }, { expires_at: h.now() + 4000 });
  h.evidence(dead); h.evidence(dead, { issuer: 'registry' }); h.approve(dead, 2);
  const deadCert = h.f.certificate(h.p(), dead.capsule.capsule_id);

  const kid = n => {
    const r = h.proposed('finance.beneficiary.create', { vendor_id: `v${n}`, bank_account: `TESTBANK00001${n}`, currency: 'EUR' });
    h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2);
    return { r, cert: h.f.certificate(h.p(), r.capsule.capsule_id) };
  };
  const c1 = kid(1), c2 = kid(2);
  const comp = h.proposed('action.composite',
    { children: [c1.r.capsule.capsule_id, c2.r.capsule.capsule_id] },
    { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'Batch' } });
  h.approve(comp, 2);
  const parentCert = h.f.certificate(h.p(), comp.capsule.capsule_id);
  const parentCertId = parentCert.payload.certificate_id;
  h.advance(5000);

  assert.throws(() => h.f.execute(h.p(), c1.cert), hasCode('INV-409-STATE'));

  // graft: parent cert row now carries the expired donor envelope
  const pRow = h.f.store.must('acme', 'certificate', parentCertId);
  pRow.envelope = h.f.store.must('acme', 'certificate', deadCert.payload.certificate_id).envelope;
  h.f.store.put('acme', 'certificate', parentCertId, pRow, h.now());

  // the graft must scream — the child can never unbind solo
  assert.throws(() => h.f.execute(h.p(), c1.cert), hasCode('INV-409-INTEGRITY'));
  assert.equal(h.f._auditIndex('acme').outcomes.has(c1.cert.payload.certificate_id), false);
  assert.throws(() => h.f.execute(h.p(), parentCert), hasCode('INV-401-CERTIFICATE'));
});

// W29-F4: anchored issuance is admission — a seal-orphaned certificate
// refuses before reservation, dispatch or any real target mutation.
test('W29-F4: a seal-orphaned certificate refuses before reservation or dispatch', t => {
  const h = fixture(t);
  const { record, certificate } = h.ready();
  const certId = certificate.payload.certificate_id;

  // simulate file-level corruption of the CERTIFICATE_ISSUED audit row
  const row = h.f.store.db.prepare(
    "SELECT seq FROM audit WHERE tenant='acme' AND json_extract(envelope,'$.payload.type')='CERTIFICATE_ISSUED'").get();
  h.f.store.db.exec('DROP TRIGGER no_audit_update');
  h.f.store.db.prepare('UPDATE audit SET envelope=? WHERE tenant=? AND seq=?')
    .run('{"protected":{},"payload":{},"signature":"x"}', 'acme', row.seq);
  h.f.store.db.exec("CREATE TRIGGER no_audit_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;");

  const seal = h.f.sealAuditChain(h.p('security'));
  assert.equal(seal.sealed, true);
  assert.equal(h.f._auditIndex('acme').issued.has(record.capsule.capsule_id), false);

  // refused at admission — nothing may commit
  assert.throws(() => h.f.execute(h.p(), certificate), hasCode('INV-401-CERTIFICATE'));
  assert.equal(h.f._auditIndex('acme').reserved.has(certId), false, 'no reservation anchor');
  assert.equal(h.f._auditIndex('acme').dispatched.has(certId), false, 'no dispatch anchor');
  assert.equal(h.f.target.outcome('acme', certId), null, 'no real target mutation without anchored issuance');
  assert.throws(() => h.f.reconcile(h.p('security'), certId), hasCode('INV-409-STATE'));
});

// W29-F5: an anchored-certified child whose capsule row was deleted is
// destructive tampering — parent reconcile screams, never swallows it.
test('W29-F5: deleted anchored child capsule row screams integrity on parent reconcile', t => {
  const h = fixture(t);
  const kid = n => {
    const r = h.proposed('finance.beneficiary.create', { vendor_id: `w${n}`, bank_account: `TESTBANK00002${n}`, currency: 'EUR' });
    h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2);
    return { r, cert: h.f.certificate(h.p(), r.capsule.capsule_id) };
  };
  const c1 = kid(1), c2 = kid(2);
  const comp = h.proposed('action.composite',
    { children: [c1.r.capsule.capsule_id, c2.r.capsule.capsule_id] },
    { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'Batch' } });
  h.approve(comp, 2);
  const parentCert = h.f.certificate(h.p(), comp.capsule.capsule_id);
  const parentCertId = parentCert.payload.certificate_id;

  assert.throws(() => h.f.execute(h.p(), parentCert, { fault: 'process-crash' }), /process death/i);
  assert.ok(h.f._auditIndex('acme').reserved.has(parentCertId));

  h.f.store.shred('acme', 'capsule', c1.r.capsule.capsule_id);
  assert.equal(h.f._auditIndex('acme').issued.has(c1.r.capsule.capsule_id), true);

  // parent reconcile screams instead of classifying the child NOT_ATTEMPTED
  assert.throws(() => h.f.reconcile(h.p('security'), parentCertId), hasCode('INV-409-INTEGRITY'));

  // and every downstream path on the murdered row screams too
  const code = fn => { try { fn(); return null; } catch (e) { return e.code; } };
  assert.equal(code(() => h.f.execute(h.p(), c1.cert)), 'INV-409-INTEGRITY');
  assert.equal(code(() => h.f.cancel(h.p(), c1.r.capsule.capsule_id)), 'INV-409-INTEGRITY');
});

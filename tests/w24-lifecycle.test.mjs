// Wave-24 lifecycle regressions — every test asserts the honest terminal
// semantics the w24 lifecycle auditor falsified on 20f8fa7 (W24-1..W24-7):
// reservation-window expiry, mutable-row vetoes replaced by anchored folds,
// cross-parent double-binding, anchored lineage/journal binding, and the
// served-row-vs-chain divergence tamper trap.
import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode } from './helpers.mjs';
import { digest } from '../src/canonical.mjs';

const JIT_REQ = { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-1'], ttl_ms: 60000, reason: 'Incident', roles: [] };
const JIT_OVR = { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'JIT' } };
const jitChild = h => { const r = h.proposed('identity.jit.grant', JIT_REQ, JIT_OVR); h.evidence(r, { kind: 'identity_proof', issuer: 'hris' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const beneChild = (h, n) => { const r = h.proposed('finance.beneficiary.create', { vendor_id: `vendor-${n}`, bank_account: `TESTBANK00000${n}`, currency: 'EUR' }); h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const composite = (h, children) => { const r = h.proposed('action.composite', { children }, { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'Batch' } }); h.approve(r, 2); return r; };

// W24-1 standalone: the clock moves inside the reservation window — the
// cert expires before dispatch, so the outcome is an honest FAILED
// (CERTIFICATE_EXPIRED_PRE_DISPATCH), never a wedged in-flight cert.
test('w24 W24-1: expiry inside the reservation window settles FAILED pre-dispatch', t => {
  const h = fixture(t), { certificate } = h.ready();
  const orig = h.f.store.audit.bind(h.f.store);
  h.f.store.audit = (tenant, type, actor, ref, meta, now) => {
    const r = orig(tenant, type, actor, ref, meta, now);
    if (type === 'EXECUTION_RESERVED') h.advance(60000);
    return r;
  };
  const out = h.f.execute(h.p(), certificate);
  assert.equal(out.payload.status, 'FAILED');
  assert.equal(out.payload.reason, 'CERTIFICATE_EXPIRED_PRE_DISPATCH');
  // Terminal and anchored — reconcile answers from the recorded verdict.
  assert.equal(h.f._auditIndex('acme').outcomes.get(certificate.payload.certificate_id), 'FAILED');
  assert.equal(h.f.reconcile(h.p('security'), certificate.payload.certificate_id).payload.status, 'FAILED');
});

// W24-1 composite: a child cert that expires mid-dispatch is settled
// FAILED — the wedge can never swallow the slot forever.
test('w24 W24-1b: a composite child expiring mid-dispatch fails honestly', t => {
  const h = fixture(t);
  const c1 = beneChild(h, 1), c2 = beneChild(h, 2);
  const r = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const parentCert = h.f.certificate(h.p(), r.capsule.capsule_id);
  // Advance inside c1's own reservation commit — c1 passes its
  // reservation-time cert check but is dead by its dispatch instant.
  const origAudit = h.f.store.audit.bind(h.f.store);
  h.f.store.audit = (tenant, type, actor, ref, meta, now) => {
    const res = origAudit(tenant, type, actor, ref, meta, now);
    if (type === 'EXECUTION_RESERVED' && ref === c1.certificate.payload.certificate_id) h.advance(60000);
    return res;
  };
  const out = h.f.execute(h.p(), parentCert);
  assert.equal(out.payload.status, 'COMPENSATED');
  assert.equal(out.payload.reason, 'CHILD_EXECUTION_FAILED:CERTIFICATE_EXPIRED_PRE_DISPATCH');
  assert.equal(out.payload.child_outcomes[c1.record.capsule.capsule_id], 'FAILED');
  assert.equal(h.f._auditIndex('acme').outcomes.get(c1.certificate.payload.certificate_id), 'FAILED');
  // The never-attempted sibling was never touched by the chain — no
  // collateral reservation or outcome wedge (its own cert also expired in
  // the same window, so it refuses expiry, not a phantom veto).
  const c2Id = c2.certificate.payload.certificate_id;
  assert.equal(h.f._auditIndex('acme').outcomes.has(c2Id), false);
  assert.equal(h.f._auditIndex('acme').reserved.has(c2Id), false);
  assert.throws(() => h.f.execute(h.p(), c2.certificate), hasCode('INV-401-CERTIFICATE'));
});

// W24-3: a planted consumed flag on a chain-free cert is tamper evidence —
// INV-409-INTEGRITY, never a quiet replay refusal the plant could fake.
test('w24 W24-3: a planted consumed flag screams INV-409-INTEGRITY', t => {
  const h = fixture(t), { certificate } = h.ready();
  const certId = certificate.payload.certificate_id;
  const certRow = h.f.store.must('acme', 'certificate', certId);
  certRow.consumed = true;
  h.f.store.put('acme', 'certificate', certId, certRow, h.now());
  assert.throws(() => h.f.execute(h.p(), certificate), hasCode('INV-409-INTEGRITY'));
});

// W24-3: a planted certificate_id on an uncertified capsule is likewise
// tamper evidence, not a replay mimic the planted row could launder.
test('w24 W24-3b: a planted certificate_id screams INV-409-INTEGRITY', t => {
  const h = fixture(t), r = h.proposed();
  h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2);
  const row = h.f.store.must('acme', 'capsule', r.capsule.capsule_id);
  row.certificate_id = 'cert-forged-pointer';
  h.f.store.put('acme', 'capsule', r.capsule.capsule_id, row, h.now());
  assert.throws(() => h.f.certificate(h.p(), r.capsule.capsule_id), hasCode('INV-409-INTEGRITY'));
});

// W24-4: once parent A anchors a binding over c1, a second composite over
// the same child cannot certify — the anchored binding is the one lock
// no mutable field can dodge.
test('w24 W24-4: a live parent binding blocks a second composite at admission', t => {
  const h = fixture(t);
  const c1 = jitChild(h), c2 = beneChild(h, 2), c3 = beneChild(h, 3);
  const rA = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  h.f.certificate(h.p(), rA.capsule.capsule_id);
  const rB = composite(h, [c1.record.capsule.capsule_id, c3.record.capsule.capsule_id]);
  const d = h.f.evaluate(h.p(), rB.capsule.capsule_id);
  assert.equal(d.decision, 'ESCROW');
  assert.ok(d.reasons.some(x => x.code === 'CHILD_BOUND'));
  assert.throws(() => h.f.certificate(h.p(), rB.capsule.capsule_id), hasCode('INV-412-EVIDENCE'));
});

// W24-4 dead-parent resolution: once the bound parent cert expires, the
// binding dissolves and the child is free authority again.
test('w24 W24-4b: an expired parent releases the anchored child binding', t => {
  const h = fixture(t);
  const c1 = jitChild(h), c2 = beneChild(h, 2);
  const rA = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const parentCert = h.f.certificate(h.p(), rA.capsule.capsule_id);
  // Parent never dispatched; revoke its authority — a dead parent dissolves
  // the binding on the anchored fold, not the mutable parent row.
  h.f.revoke(h.p('security'), { kind: 'certificate', id: parentCert.payload.certificate_id, reason: 'parent retired' });
  const out = h.f.execute(h.p(), c1.certificate);
  assert.equal(out.payload.status, 'VERIFIED');
});

// W24-5 doctrine (w44): composite_child_of is derived from the anchored
// reservation/dispatch folds — a wedged child keeps its anchored lineage
// and can never be freed into a solo dispatch.
test('w24 W24-5: an intent-anchored wedged child keeps its anchored lineage — never freed solo', t => {
  const h = fixture(t);
  const c1 = jitChild(h), c2 = beneChild(h, 2);
  const r = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const parentCert = h.f.certificate(h.p(), r.capsule.capsule_id);
  const orig = h.f.target.execute.bind(h.f.target);
  let calls = 0;
  h.f.target.execute = (capsule, id, now, fault) => { calls += 1; if (calls === 2) throw new Error('child dispatch lost mid-flight'); return orig(capsule, id, now, fault); };
  h.f.execute(h.p(), parentCert);
  const c2cert = c2.certificate.payload.certificate_id;
  assert.ok(!h.f._auditIndex('acme').released?.has(c2cert), 'no EXECUTION_RELEASED');
  assert.equal(h.f._auditIndex('acme').intendedMeta?.get(c2cert), parentCert.payload.certificate_id, 'the intent fold pins the composite lineage');
  assert.throws(() => h.f.execute(h.p(), c2.certificate), 'a consumed wedged cert cannot dispatch solo');
});

// W24-6: the anchored CANCELLED verdict outranks a stale UNCERTAIN row —
// served state diverging from the signed chain is tamper evidence.
test('w24 W24-6: a stale UNCERTAIN row against anchored CANCELLED screams', t => {
  const h = fixture(t);
  const c1 = jitChild(h);
  // Certify, never dispatch, cancel — the chain anchors CANCELLED.
  h.f.cancel(h.p(), c1.record.capsule.capsule_id);
  const c1Id = c1.certificate.payload.certificate_id;
  assert.equal(h.f._auditIndex('acme').outcomes.get(c1Id), 'CANCELLED');
  // Post-cancel stale wedge: the row reads UNCERTAIN but the chain already
  // settled CANCELLED — _outcomeIntegrity must scream, not serve.
  const row = h.f.store.must('acme', 'outcome', c1Id);
  row.payload.status = 'UNCERTAIN';
  h.f.store.put('acme', 'outcome', c1Id, row, h.now());
  assert.throws(() => h.f.reconcile(h.p('security'), c1Id), hasCode('INV-409-INTEGRITY'));
});

// W24-7: the child outcome's journal binding is anchored — deleting the
// child dispatch journal turns the served VERIFIED row into tamper
// evidence, never a safe verdict.
test('w24 W24-7: a deleted child dispatch journal voids the served outcome', t => {
  const h = fixture(t);
  const c1 = jitChild(h), c2 = beneChild(h, 2);
  const r = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const parentCert = h.f.certificate(h.p(), r.capsule.capsule_id);
  const out = h.f.execute(h.p(), parentCert);
  assert.equal(out.payload.status, 'VERIFIED');
  const c1Id = c1.certificate.payload.certificate_id;
  // Insider journal-delete: the anchored outcome's journal_digest now has
  // no durable log to back it — reconcile must scream, not serve.
  h.f.target.db.prepare('DELETE FROM transactions WHERE tenant=? AND id=?').run('acme', c1Id);
  assert.throws(() => h.f.reconcile(h.p('security'), c1Id), hasCode('INV-409-INTEGRITY'));
});

// W24-3 dry-run: the dedupe window is anchored — backdating the mutable
// marker cannot mint a second EXECUTION_DRY_RUN anchor inside the window.
test('w24 W24-3c: a backdated dry-run marker cannot re-anchor the dedupe window', t => {
  const h = fixture(t), { certificate } = h.ready();
  h.f.execute(h.p(), certificate, { dryRun: true });
  const row = h.f.store.must('acme', 'certificate', certificate.payload.certificate_id);
  row.last_dry_run_at = h.now() - 120000;
  h.f.store.put('acme', 'certificate', certificate.payload.certificate_id, row, h.now());
  // The anchored dryRunAt still says "just ran" — dedupe mints no second
  // EXECUTION_DRY_RUN anchor inside the window.
  const head = h.f.store.auditHeadSeq('acme');
  h.f.execute(h.p(), certificate, { dryRun: true });
  assert.equal(h.f.store.auditHeadSeq('acme'), head);
});

// W24-4 direction check: cancelling the live parent dissolves the binding —
// the chain's ACTION_CANCELLED fold is what releases the children.
test('w24 W24-4c: a cancelled parent releases its anchored child binding', t => {
  const h = fixture(t);
  const c1 = jitChild(h), c2 = beneChild(h, 2);
  const rA = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  h.f.certificate(h.p(), rA.capsule.capsule_id);
  h.f.cancel(h.p(), rA.capsule.capsule_id);
  const out = h.f.execute(h.p(), c1.certificate);
  assert.equal(out.payload.status, 'VERIFIED');
});

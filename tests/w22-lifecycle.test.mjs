// Wave-22 composite/execute lifecycle regressions — every test asserts the
// honest terminal semantics the w22 lifecycle auditor falsified on 84eb1c0
// (F1..F9): crash-gap dispatch, reservation release, verdict forks,
// journaled compensation, tombstone supersession, post-effect failure,
// write amplification, planted usage rows and label honesty.
import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode, runtimeInput, runtimeRequest } from './helpers.mjs';
import { digest } from '../src/canonical.mjs';

const JIT_REQ = { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-1'], ttl_ms: 60000, reason: 'Incident', roles: [] };
const JIT_OVR = { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'JIT' } };
const jitChild = h => { const r = h.proposed('identity.jit.grant', JIT_REQ, JIT_OVR); h.evidence(r, { kind: 'identity_proof', issuer: 'hris' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const beneChild = (h, n) => { const r = h.proposed('finance.beneficiary.create', { vendor_id: `vendor-${n}`, bank_account: `TESTBANK00000${n}`, currency: 'EUR' }); h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const composite = (h, children) => { const r = h.proposed('action.composite', { children }, { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'Batch' } }); h.approve(r, 2); return r; };
const killNthDispatch = (h, n) => { const orig = h.f.target.execute.bind(h.f.target); let calls = 0; h.f.target.execute = (capsule, id, now, fault) => { calls += 1; if (calls === n) throw new Error('child dispatch lost mid-flight'); return orig(capsule, id, now, fault); }; };
const auditCount = (h, type, ref) => h.f.store.db.prepare("SELECT COUNT(*) n FROM audit WHERE tenant='acme' AND envelope LIKE ? AND envelope LIKE ?").get(`%"type":"${type}"%`, `%${ref}%`).n;

// F1: a committed journal with no anchored EXECUTION_DISPATCHED is the
// crash gap — the cert settles FAILED/DISPATCH_UNATTESTED, never wedged.
test('w22 F1: journaled dispatch without its anchor settles DISPATCH_UNATTESTED', t => {
  const h = fixture(t);
  const c = beneChild(h, 1);
  // Reserve then die before dispatch — consumed + reserved, no journal.
  assert.throws(() => h.f.execute(h.p(), c.certificate, { fault: 'process-crash' }));
  // The durable journal committed while the anchor tx died: plant exactly
  // that state through the same target path the real dispatch used.
  h.f.target.execute(c.record.capsule, c.certificate.payload.certificate_id, h.now());
  const out = h.f.reconcile(h.p('security'), c.certificate.payload.certificate_id);
  assert.equal(out.payload.status, 'FAILED');
  assert.equal(out.payload.reason, 'DISPATCH_UNATTESTED');
  // Terminal: a second reconcile answers from the recorded verdict.
  assert.equal(h.f.reconcile(h.p('security'), c.certificate.payload.certificate_id).payload.status, 'FAILED');
});

// F2: a reserved child whose dispatch never journaled is released back to
// free authority inside the parent's terminal write.
test('w22 F2: journal-less wedged child is released, not burned', t => {
  const h = fixture(t);
  const c1 = jitChild(h), c2 = beneChild(h, 2);
  const r = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const parentCert = h.f.certificate(h.p(), r.capsule.capsule_id);
  killNthDispatch(h, 2);
  h.f.execute(h.p(), parentCert);
  assert.equal(h.f.store.must('acme', 'certificate', c2.certificate.payload.certificate_id).consumed, false);
  assert.ok(h.f._auditIndex('acme').released.has(c2.certificate.payload.certificate_id));
  // The released cert spends its one slot again — a new capsule is not
  // needed to use the still-live authority.
  const second = h.f.execute(h.p(), c2.certificate);
  assert.equal(second.payload.status, 'VERIFIED');
});

// F3a: reconcile(child) refuses while the composite parent is still live —
// effects must not fire under a verdict the parent's bail can contradict.
test('w22 F3: a child bound to a live composite parent cannot be reconciled solo', t => {
  const h = fixture(t);
  const c1 = jitChild(h), c2 = beneChild(h, 2);
  const r = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  h.f.certificate(h.p(), r.capsule.capsule_id);
  // Parent issued, never dispatched — live. A solo child reconcile refuses.
  assert.throws(() => h.f.reconcile(h.p('security'), c1.certificate.payload.certificate_id), hasCode('INV-409-STATE'));
});

// F4: a journaled unwind anchors EXECUTION_COMPENSATED — reconcile settles
// the child COMPENSATED from journal+anchor, never ratcheting UNCERTAIN.
test('w22 F4: journaled compensation anchors and settles COMPENSATED', t => {
  const h = fixture(t);
  const c1 = beneChild(h, 1), c2 = jitChild(h);
  const r = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const parentCert = h.f.certificate(h.p(), r.capsule.capsule_id);
  killNthDispatch(h, 2); // c2's dispatch dies in-band → bail compensates c1
  const out = h.f.execute(h.p(), parentCert);
  assert.equal(out.payload.status, 'FAILED');
  assert.match(out.payload.reason, /^COMPENSATION_INCOMPLETE:/);
  // beneChild is compensatable — its unwind journaled + anchored.
  assert.ok(h.f.target.outcome('acme', `comp:${c1.certificate.payload.certificate_id}`));
  assert.ok(h.f._auditIndex('acme').compensated.has(c1.certificate.payload.certificate_id));
  assert.equal(out.payload.child_outcomes[c1.record.capsule.capsule_id], 'COMPENSATED');
});

// F5: a shredded evidence member is retired by a later same-issuer+kind
// attach — a deleted conflict veto cannot wedge the capsule forever.
test('w22 F5: a deleted conflict member is superseded by a later same-issuer+kind attach', t => {
  const h = fixture(t);
  const r = h.proposed();
  const conflict = h.evidence(r, { kind: 'ownership', claim: 'conflict', advisory: true, claims: {} });
  // Shred the conflict envelope's row directly — tombstone path.
  const evId = conflict.payload.evidence_id;
  h.f.store.shred('acme', 'evidence', evId);
  h.f.store.put('acme', 'evidence-tombstone', evId, { evidence_id: evId, original_digest: digest(conflict), deleted_at: h.now(), superseded: [], key_id: conflict.protected.key_id, kind: conflict.payload.kind }, h.now());
  // The real sweep also anchors the deletion on the chain — the tombstone's
  // issuer+kind identity comes from RETENTION_DELETED, not the mutable row.
  h.f.store.audit('acme', 'RETENTION_DELETED', 'retention-sweep', evId, { original_digest: digest(conflict), crypto_shred: true, key_id: conflict.protected.key_id, kind: conflict.payload.kind }, h.now());
  h.evidence(r, { kind: 'ownership' });
  const graph = h.f.graph('acme', h.f.store.must('acme', 'capsule', r.capsule.capsule_id));
  const deletedItem = graph.items.find(i => i.payload.evidence_id === evId);
  assert.ok(deletedItem.superseded_by, 'a tombstoned member must be superseded like a live one');
});

// F6: a post-commit side-effect failure lands EFFECT_APPLY_FAILED and the
// tenant heals via the idempotent ledger replay on the next transaction.
test('w22 F6: post-commit effect failure anchors and heals', t => {
  const h = fixture(t);
  const c = jitChild(h);
  const origGrant = h.f.target.grant.bind(h.f.target);
  h.f.target.grant = () => { throw new Error('simulated dataplane loss'); };
  const out = h.f.execute(h.p(), c.certificate);
  assert.equal(out.payload.status, 'VERIFIED');
  assert.equal(auditCount(h, 'EFFECT_APPLY_FAILED', c.certificate.payload.certificate_id), 1);
  // Dataplane diverged — the grant never landed. Restore + any new
  // transaction replays the idempotent heal.
  assert.equal(h.f.target.allGrants('acme').length, 0);
  h.f.target.grant = origGrant;
  h.proposed(); // a transaction entrypoint
  assert.equal(h.f.target.allGrants('acme').length, 1, 'the next transaction replays the missed grant');
});

// F7: dry runs and unchanged reconciles write no amplification rows.
test('w22 F7: dry-run and UNCERTAIN reconcile dedupe', t => {
  const h = fixture(t);
  const c = beneChild(h, 1);
  h.f.execute(h.p(), c.certificate, { dryRun: true });
  h.f.execute(h.p(), c.certificate, { dryRun: true });
  assert.equal(auditCount(h, 'EXECUTION_DRY_RUN', c.certificate.payload.certificate_id), 1);
  // Crash-wedge then reconcile twice: the second returns the same row.
  assert.throws(() => h.f.execute(h.p(), c.certificate, { fault: 'process-crash' }));
  const o1 = h.f.reconcile(h.p('security'), c.certificate.payload.certificate_id);
  assert.equal(o1.payload.status, 'UNCERTAIN');
  const seqBefore = h.f.store.auditHeadSeq('acme');
  const o2 = h.f.reconcile(h.p('security'), c.certificate.payload.certificate_id);
  assert.equal(o2.payload.status, 'UNCERTAIN');
  assert.equal(digest(o2), digest(o1));
  assert.equal(h.f.store.auditHeadSeq('acme'), seqBefore, 'an unchanged UNCERTAIN reconcile writes nothing');
});

// F8: a planted usage row is replay evidence — identical fields fold, any
// other shape screams INV-409-REPLAY, never a 500.
test('w22 F8: a conflicting usage row screams INV-409-REPLAY', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  const requestId = 'req-squat-1';
  // Insider squats the usage PK with a conflicting billing shape.
  h.f.store.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?)').run('acme', 'mallory', 'dataset-9', h.now(), 9999, cap.payload.capability_id, requestId);
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap, { request_id: requestId })), hasCode('INV-409-REPLAY'));
});

// F9: a cert the chain knows as executing refuses cancel even when the
// mutable row's status field was tampered back to CERTIFIED.
test('w22 F9: chain-executing certificate refuses cancel', t => {
  const h = fixture(t);
  const c = beneChild(h, 1);
  assert.throws(() => h.f.execute(h.p(), c.certificate, { fault: 'process-crash' }));
  // Tamper the mutable row back to a cancellable-looking state — the chain
  // still says reserved-without-outcome.
  const rec = h.f.store.must('acme', 'capsule', c.record.capsule.capsule_id);
  rec.status = 'CERTIFIED'; h.f.store.put('acme', 'capsule', c.record.capsule.capsule_id, rec, h.now());
  assert.throws(() => h.f.cancel(h.p(), c.record.capsule.capsule_id), hasCode('INV-409-STATE'));
});

// w23-fixverify regression suite — hostile re-verification of the w22
// lifecycle fixes on 1305cfe. Every test asserts the anchored-binding
// semantics the auditor falsified: tombstone identity comes from the
// signed chain (not the mutable tomb row), compensation requires a
// journaled unwind bound to THIS child's capsule, the crash-gap window is
// bounded, and cancel/reconcile resolve certificates from the anchored
// index, never the mutable capsule.certificate_id pointer.
import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode, installPolicy } from './helpers.mjs';
import { digest, clone } from '../src/canonical.mjs';

const JIT_REQ = { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-1'], ttl_ms: 60000, reason: 'Incident', roles: [] };
const JIT_OVR = { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'JIT' } };
const jitChild = h => { const r = h.proposed('identity.jit.grant', JIT_REQ, JIT_OVR); h.evidence(r, { kind: 'identity_proof', issuer: 'hris' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const beneChild = (h, n) => { const r = h.proposed('finance.beneficiary.create', { vendor_id: `vendor-${n}`, bank_account: `TESTBANK00000${n}`, currency: 'EUR' }); h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const composite = (h, children) => { const r = h.proposed('action.composite', { children }, { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'Batch' } }); h.approve(r, 2); return r; };
const killNthDispatch = (h, n) => { const orig = h.f.target.execute.bind(h.f.target); let calls = 0; h.f.target.execute = (capsule, id, now, fault) => { calls += 1; if (calls === n) throw new Error('child dispatch lost mid-flight'); return orig(capsule, id, now, fault); }; };

// F-a: an unanchored child journal OUTSIDE the reservation window is tamper
// evidence — INV-409-INTEGRITY, never the crash-gap FAILED settle.
test('w23 F-a: journal stamped outside the reservation window screams INTEGRITY', t => {
  const h = fixture(t);
  const c = beneChild(h, 1);
  assert.throws(() => h.f.execute(h.p(), c.certificate, { fault: 'process-crash' }));
  const certId = c.certificate.payload.certificate_id;
  const reservedAt = h.f._auditIndex('acme').reservedAt.get(certId);
  assert.equal(typeof reservedAt, 'number');
  // Backdated far before the reservation: outside the 60s crash window.
  h.f.target.execute(c.record.capsule, certId, reservedAt - 61000);
  assert.throws(() => h.f.reconcile(h.p('security'), certId), hasCode('INV-409-INTEGRITY'));
});

test('w23 F-a2: journal inside the reservation window still settles FAILED honestly', t => {
  const h = fixture(t);
  const c = beneChild(h, 1);
  assert.throws(() => h.f.execute(h.p(), c.certificate, { fault: 'process-crash' }));
  const certId = c.certificate.payload.certificate_id;
  h.f.target.execute(c.record.capsule, certId, h.f._auditIndex('acme').reservedAt.get(certId) + 30000);
  const out = h.f.reconcile(h.p('security'), certId);
  assert.equal(out.payload.status, 'FAILED');
  assert.equal(out.payload.reason, 'DISPATCH_UNATTESTED');
});

// F-b/F-c: compensation presence does not attest — the comp:<certId>
// journal must bind THIS child's capsule digest.
test('w23 F-b: a compensation journal bound to a foreign capsule is not attestation', t => {
  const h = fixture(t);
  const c1 = beneChild(h, 1), c2 = jitChild(h);
  const r = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const parentCert = h.f.certificate(h.p(), r.capsule.capsule_id);
  // The bail unwind's journal will carry a forged capsule_digest — the
  // transplanted attestation must not count for this child.
  const orig = h.f.target.outcome.bind(h.f.target);
  let forged = false;
  h.f.target.outcome = (tenant, id) => { const row = orig(tenant, id); if (!forged && id.startsWith('comp:')) { forged = true; return { ...row, capsule_digest: '0'.repeat(64) }; } return row; };
  killNthDispatch(h, 2);
  const out = h.f.execute(h.p(), parentCert);
  assert.equal(out.payload.status, 'FAILED');
  assert.match(out.payload.reason, /^COMPENSATION_INCOMPLETE:/);
  // The unread journal can never anchor EXECUTION_COMPENSATED.
  assert.equal(h.f._auditIndex('acme').compensated?.has(c1.certificate.payload.certificate_id) ?? false, false);
  assert.notEqual(out.payload.child_outcomes[c1.record.capsule.capsule_id], 'COMPENSATED');
});

// F-e: a deleted member's attach family comes from the anchored
// RETENTION_DELETED event — mutating the tomb row's identity fields cannot
// change which family it belongs to, and a dead member never supersedes a
// live envelope.
test('w23 F-e: tombstoned member keeps its chain-anchored family; dead never supersedes live', t => {
  const h = fixture(t);
  const r = h.proposed();
  const e1 = h.evidence(r, { kind: 'ownership' });
  const e2 = h.evidence(r, { kind: 'ownership' });
  // e2 is the issuer's LATEST ownership statement → e1 superseded while live.
  let graph = h.f.graph('acme', h.f.store.must('acme', 'capsule', r.capsule.capsule_id));
  const live1 = graph.items.find(i => i.payload.evidence_id === e1.payload.evidence_id);
  assert.equal(live1.superseded_by, e2.payload.evidence_id);
  // Shred e1 through the retention path: tomb row + anchored tombstone.
  h.f.store.shred('acme', 'evidence', e1.payload.evidence_id);
  h.f.store.put('acme', 'evidence-tombstone', e1.payload.evidence_id, { evidence_id: e1.payload.evidence_id, original_digest: digest(e1), deleted_at: h.now(), superseded: [], key_id: e1.protected.key_id, kind: e1.payload.kind }, h.now());
  h.f.store.audit('acme', 'RETENTION_DELETED', 'security', e1.payload.evidence_id, { original_digest: digest(e1), crypto_shred: true, key_id: e1.protected.key_id, kind: e1.payload.kind }, h.now());
  // Insider lies about the tomb row's family — anchored identity wins.
  const tomb = h.f.store.must('acme', 'evidence-tombstone', e1.payload.evidence_id);
  h.f.store.put('acme', 'evidence-tombstone', e1.payload.evidence_id, { ...tomb, kind: 'advisory', key_id: 'forged-key' }, h.now());
  graph = h.f.graph('acme', h.f.store.must('acme', 'capsule', r.capsule.capsule_id));
  const dead1 = graph.items.find(i => i.payload.evidence_id === e1.payload.evidence_id);
  assert.equal(dead1.revoked, true);
  assert.equal(dead1.superseded_by, e2.payload.evidence_id, 'anchored family supersedes even with a lying tomb row');
});

// F-b: the wedged-release loop resolves the cert from the anchored index —
// repointing a wedged child's row at a foreign in-flight cert must not free
// the victim's reservation under a vault-signed EXECUTION_RELEASED.
test('w23 F-b: a repointed wedged child cannot release a foreign cert reservation', t => {
  const h = fixture(t);
  // Victim: consumed + EXECUTION_RESERVED anchored, no journal (crash wedge).
  const victim = beneChild(h, 9);
  assert.throws(() => h.f.execute(h.p(), victim.certificate, { fault: 'process-crash' }));
  const victimId = victim.certificate.payload.certificate_id;
  const c1 = beneChild(h, 1), c2 = beneChild(h, 2);
  const r = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const parentCert = h.f.certificate(h.p(), r.capsule.capsule_id);
  killNthDispatch(h, 2); // c2 wedges: reserved, journal-less
  const origFC = h.f.finishComposite.bind(h.f);
  h.f.finishComposite = () => { throw new Error('parent outcome lost'); };
  assert.throws(() => h.f.execute(h.p(), parentCert));
  h.f.finishComposite = origFC;
  // Insider repoints the wedged child's row at the victim cert.
  const c2Rec = h.f.store.must('acme', 'capsule', c2.record.capsule.capsule_id);
  h.f.store.put('acme', 'capsule', c2.record.capsule.capsule_id, { ...c2Rec, certificate_id: victimId }, h.now());
  const out = h.f.reconcile(h.p('security'), parentCert.payload.certificate_id);
  // The release binds c2's anchored cert — the victim keeps its reservation.
  assert.equal(out.payload.child_outcomes[c2.record.capsule.capsule_id], 'RELEASED');
  assert.equal(h.f._auditIndex('acme').released.has(c2.certificate.payload.certificate_id), true);
  assert.equal(h.f._auditIndex('acme').released.has(victimId), false, 'the foreign cert must not be freed');
  assert.equal(h.f.store.must('acme', 'certificate', victimId).consumed, true);
});

// F-f: a murdered child outcome row must never dedupe as unchanged — row
// existence is part of the signature, and reconcile re-heals the row.
test('w23 F-f: a deleted child outcome row re-heals instead of deduping', t => {
  const h = fixture(t);
  const c1 = beneChild(h, 1), c2 = beneChild(h, 2);
  const r = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const parentCert = h.f.certificate(h.p(), r.capsule.capsule_id);
  // Wedge the parent after both child dispatches journaled.
  const origFC = h.f.finishComposite.bind(h.f);
  h.f.finishComposite = () => { throw new Error('parent outcome lost'); };
  assert.throws(() => h.f.execute(h.p(), parentCert));
  h.f.finishComposite = origFC;
  const first = h.f.reconcile(h.p('security'), parentCert.payload.certificate_id);
  assert.equal(first.payload.status, 'UNCERTAIN');
  const c1Id = c1.certificate.payload.certificate_id;
  assert.ok(h.f.store.get('acme', 'outcome', c1Id), 'child outcome row exists');
  // Insider murders the recorded child verdict.
  h.f.store.shred('acme', 'outcome', c1Id);
  assert.equal(h.f.store.get('acme', 'outcome', c1Id), null);
  h.f.reconcile(h.p('security'), parentCert.payload.certificate_id);
  assert.ok(h.f.store.get('acme', 'outcome', c1Id), 'the murdered row is re-healed, not deduped away');
});

// F-i: cancel resolves the certificate through the anchored issuedCert
// index — a repointed mutable capsule row cannot redirect the flip.
test('w23 F-i: cancel acts on the chain-anchored certificate, not the row pointer', t => {
  const h = fixture(t);
  const victim = beneChild(h, 1), donor = beneChild(h, 2);
  const anchoredCert = victim.certificate.payload.certificate_id;
  // Insider repoints the capsule's certificate_id at the donor's cert.
  const rec = h.f.store.must('acme', 'capsule', victim.record.capsule.capsule_id);
  h.f.store.put('acme', 'capsule', victim.record.capsule.capsule_id, { ...rec, certificate_id: donor.certificate.payload.certificate_id }, h.now());
  const out = h.f.cancel(h.p(), victim.record.capsule.capsule_id);
  assert.equal(out.status, 'CANCELLED');
  assert.equal(h.f.store.must('acme', 'certificate', anchoredCert).status, 'CANCELLED');
  // The donor certificate remains live — the repointed row cannot burn it.
  assert.equal(h.f.store.must('acme', 'certificate', donor.certificate.payload.certificate_id).status, 'CERTIFIED');
});

// F9: evidence bindings evaluate under the CANDIDATE constitution during
// simulation — a binding the successor ADDS must count against the
// projected verdict (graph's binding policy threads, not the active one).
test('w23 F9: graph evaluates evidence bindings under the supplied policy', t => {
  const h = fixture(t);
  const r = h.proposed('finance.beneficiary.create', { vendor_id: 'v-1', bank_account: 'TESTBANK000009', currency: 'EUR' });
  // Attach enforces the active binding — claims carry account.
  h.evidence(r);
  const record = h.f.store.must('acme', 'capsule', r.capsule.capsule_id);
  const underActive = h.f.graph('acme', record);
  assert.equal(underActive.items.find(i => i.envelope.payload.kind === 'ownership').binding_failed, false);
  // A candidate that ALSO binds 'curr' to requested_state.currency fails
  // the same envelope — the claims never signed that field.
  const candidate = clone(h.f.policy('acme'));
  candidate.rules['finance.beneficiary.create'].evidence_bindings = { ownership: { account: 'requested_state.bank_account', curr: 'requested_state.currency' } };
  const underCandidate = h.f.graph('acme', record, candidate);
  assert.equal(underCandidate.items.find(i => i.envelope.payload.kind === 'ownership').binding_failed, true);
});

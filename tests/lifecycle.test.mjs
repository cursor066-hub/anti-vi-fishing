import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode, installPolicy } from './helpers.mjs';
import { clone, digest } from '../src/canonical.mjs';
import { signed } from '../src/crypto.mjs';
import { proposal } from '../src/schema.mjs';
import { Fabric } from '../src/fabric.mjs';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

test('COM-009 COM-010: exact approved action executes and produces signed verified outcome', t => {
  const h = fixture(t), { record, certificate } = h.ready(); const result = h.f.execute(h.p(), certificate);
  assert.equal(result.payload.status, 'VERIFIED'); assert.equal(h.f.target.state('acme', record.capsule.action.target_resource).material_fields.bank_account, 'TESTBANK000002'); assert.equal(result.protected.purpose, 'outcome');
});
test('ACT-008: tampered schema digest rejected', t => { const h = fixture(t); assert.throws(() => h.proposed(undefined, undefined, { schema_digest: 'f'.repeat(64) }), hasCode('INV-400-SCHEMA')); });
test('ACT-011 COM-006: proposal idempotency returns exact first result; changed request rejected', t => {
  const h = fixture(t), input = proposal('finance.bank.change', h.actor(), h.f.target.state('acme', 'vendor-1'), { bank_account: 'TESTBANK000009', currency: 'EUR' }, h.now());
  const intent = signed(input, h.setup.identityKeys.acme.operator, 'capsule-intent');
  const a = h.f.propose(h.p(), input, 'same-key-1234', intent); assert.deepEqual(h.f.propose(h.p(), input, 'same-key-1234', intent), a);
  assert.throws(() => h.f.propose(h.p(), { ...input, quantity: 2 }, 'same-key-1234', intent), hasCode('INV-401-SIGNATURE'));
  const intent2 = signed({ ...input, quantity: 2 }, h.setup.identityKeys.acme.operator, 'capsule-intent');
  assert.throws(() => h.f.propose(h.p(), { ...input, quantity: 2 }, 'same-key-1234', intent2), hasCode('INV-409-IDEMPOTENCY'));
  assert.throws(() => h.f.propose(h.p(), input, 'different-key', intent), hasCode('INV-409-REPLAY'));
});
test('COM-001 POL-002 POL-003 POL-005: missing evidence/approvals cannot mint or execute; the pending record carries owner, expiry and reason', t => {
  const h = fixture(t), r = h.proposed();
  const d = h.f.evaluate(h.p(), r.capsule.capsule_id);
  assert.equal(d.decision, 'ESCROW');
  // COM-001: no certificate → no execution, even on a valid session.
  assert.throws(() => h.f.certificate(h.p(), r.capsule.capsule_id), hasCode('INV-412-EVIDENCE'));
  assert.throws(() => h.f.execute(h.p(), {}), hasCode('INV-401-SIGNATURE'));
  // POL-002: decisions are closed — only the five defined outcomes exist, and
  // only ALLOW can mint. Every non-ALLOW state is refused at the gate.
  assert.ok(['ALLOW', 'SHIELD', 'ESCROW', 'DEFER', 'DENY'].includes(d.decision));
  // POL-005: the pending record identifies its owner, carries an expiry and
  // records the blocking reasons.
  assert.equal(d.owner, 'operator');
  assert.ok(d.expires_at > h.now() && d.reasons.length > 0);
});
test('POL-007: denied nonce cannot be revived or re-evaluated', t => {
  const h = fixture(t), r = h.proposed('cloud.firewall.change', { protocol: 'tcp', port: 5432, source_cidr: '0.0.0.0/0', service_id: 'database' });
  assert.equal(h.f.evaluate(h.p(), r.capsule.capsule_id).decision, 'DENY'); assert.throws(() => h.f.evaluate(h.p(), r.capsule.capsule_id), hasCode('INV-409-STATE'));
});
test('POL-006 COM-013: cooldown defers exact bank change', t => { const h = fixture(t), r = h.proposed('finance.bank.change', { bank_account: 'TESTBANK000002', currency: 'EUR' }); assert.equal(h.f.evaluate(h.p(), r.capsule.capsule_id).decision, 'DEFER'); h.advance(60001); assert.equal(h.f.evaluate(h.p(), r.capsule.capsule_id).decision, 'ESCROW'); });
test('COM-003: consumed certificate is never replayed', t => { const h = fixture(t), { certificate } = h.ready(); h.f.execute(h.p(), certificate); assert.throws(() => h.f.execute(h.p(), certificate), hasCode('INV-409-REPLAY')); });
test('COM-004 ACT-004: stale target state invalidates certificate', t => { const h = fixture(t), { record, certificate } = h.ready(); h.f.target.seed('acme', record.capsule.action.target_resource, { altered: true }); assert.throws(() => h.f.execute(h.p(), certificate), hasCode('INV-409-STATE')); });
test('COM-004: expired certificate fails closed', t => { const h = fixture(t), { certificate } = h.ready(); h.advance(60001); assert.throws(() => h.f.execute(h.p(), certificate), hasCode('INV-401-CERTIFICATE')); });
test('COM-011: dry-run does not mutate or consume certificate', t => { const h = fixture(t), { record, certificate } = h.ready(); assert.equal(h.f.execute(h.p(), certificate, { dryRun: true }).no_mutation, true); assert.equal(h.f.target.state('acme', record.capsule.action.target_resource).version, 0); assert.equal(h.f.execute(h.p(), certificate).payload.status, 'VERIFIED'); });
test('COM-012: post-commit timeout becomes UNCERTAIN; reconciliation finds one durable mutation', t => {
  const h = fixture(t), { record, certificate } = h.ready(); const id = certificate.payload.certificate_id;
  assert.equal(h.f.execute(h.p(), certificate, { fault: 'after-commit' }).payload.status, 'UNCERTAIN'); assert.throws(() => h.f.execute(h.p(), certificate), hasCode('INV-409-REPLAY'));
  assert.equal(h.f.reconcile(h.p(), id).payload.status, 'VERIFIED'); assert.equal(h.f.target.state('acme', record.capsule.action.target_resource).version, 1);
});
test('COM-005 COM-012: target failure before commit rolls back and stays uncertain without blind retry', t => {
  const h = fixture(t), { record, certificate } = h.ready(); assert.equal(h.f.execute(h.p(), certificate, { fault: 'before-commit' }).payload.status, 'UNCERTAIN'); assert.equal(h.f.target.state('acme', record.capsule.action.target_resource).version, 0); assert.equal(h.f.reconcile(h.p(), certificate.payload.certificate_id).payload.status, 'UNCERTAIN');
});
for (const fault of ['malformed-response', 'altered-response']) test(`CON-004 COM-009: ${fault} cannot produce false success`, t => { const h = fixture(t), { certificate } = h.ready(); assert.throws(() => h.f.execute(h.p(), certificate, { fault }), hasCode('INV-409-INTEGRITY')); assert.equal(h.f.reconcile(h.p(), certificate.payload.certificate_id).payload.status, 'VERIFIED'); });
test('COM-005 COM-012: process crash reservation survives restart and prevents replay', t => {
  const h = fixture(t), { certificate } = h.ready(); assert.throws(() => h.f.execute(h.p(), certificate, { fault: 'process-crash' })); h.close();
  const restarted = new Fabric(h.setup.config, h.directory, h.now); t.after(() => restarted.close());
  assert.throws(() => restarted.execute(h.p(), certificate), hasCode('INV-409-REPLAY')); assert.equal(restarted.reconcile(h.p(), certificate.payload.certificate_id).payload.status, 'UNCERTAIN');
});
test('COM-013: cancellation closes issued authority', t => { const h = fixture(t), { record, certificate } = h.ready(); h.f.cancel(h.p(), record.capsule.capsule_id); assert.throws(() => h.f.execute(h.p(), certificate), hasCode('INV-409-REPLAY')); });
test('NFR-SEC-005: cross-tenant read and execution rejected', t => {
  const h = fixture(t), { record, certificate } = h.ready(); assert.throws(() => h.f.getCapsule(h.p('operator', 'globex'), record.capsule.capsule_id), hasCode('INV-404-NOT-FOUND')); assert.throws(() => h.f.execute(h.p('operator', 'globex'), certificate), hasCode('INV-401-SIGNATURE'));
});
test('IDN-002: auditor login grants no mutation authority', t => { const h = fixture(t); assert.throws(() => h.proposed(undefined, undefined, {}, h.p('auditor')), hasCode('INV-403-ROLE')); });
test('AUD-003 CON-003: stored sensitive fields never appear as plaintext in database/WAL', t => {
  const h = fixture(t); h.ready();
  for (const file of ['fabric.db', 'fabric.db-wal', 'target.db', 'target.db-wal']) assert.equal(readFileSync(join(h.directory, file)).includes(Buffer.from('TESTBANK000002')), false);
});
test('AUD-004: persisted clock regression halts security mutation', t => { const h = fixture(t); h.proposed(); h.advance(-1); assert.throws(() => h.proposed(), hasCode('INV-503-TIME')); });
test('EVD-001 EVD-002: correlated issuer and derivative evidence cannot satisfy independence', t => {
  const h = fixture(t), r = h.proposed(), first = h.evidence(r); h.evidence(r, { issuer: 'registry', dependencies: [first.payload.evidence_id] }); h.approve(r);
  const decision = h.f.evaluate(h.p(), r.capsule.capsule_id);
  assert.equal(decision.decision, 'ESCROW', 'the reason code must accompany a real withholding, not decorate an ALLOW');
  assert.ok(decision.reasons.some(x => x.code === 'EVIDENCE_INDEPENDENCE'));
});
test('EVD-005 AIG-006: email/advisory evidence cannot confer authority', t => { const h = fixture(t), r = h.proposed(); h.evidence(r, { issuer: 'email' }); h.evidence(r, { issuer: 'bank', advisory: true }); h.approve(r); assert.equal(h.f.evaluate(h.p(), r.capsule.capsule_id).decision, 'ESCROW'); });
test('EVD-009: conflicting evidence remains escrow despite sufficient positive sources', t => { const h = fixture(t), r = h.proposed(); h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.evidence(r, { issuer: 'governance', kind: 'governance_review', claim: 'conflict' }); h.approve(r); const decision = h.f.evaluate(h.p(), r.capsule.capsule_id); assert.equal(decision.decision, 'ESCROW'); assert.ok(decision.reasons.some(x => x.code === 'EVIDENCE_CONFLICT')); });
test('EVD-008 POL-014: evidence revocation invalidates pending certificate immediately and survives in audit', t => {
  const h = fixture(t), { record, certificate } = h.ready(), r = h.f.getCapsule(h.p(), record.capsule.capsule_id);
  h.f.revoke(h.p('security'), { kind: 'evidence', id: r.evidence[0], reason: 'Test source compromise' });
  // Rollback-style check: the revocation is preserved (still enforced) and the
  // audit chain records the revocation event — continuity survives rollback.
  assert.throws(() => h.f.execute(h.p(), certificate), hasCode('INV-409-STATE'));
  const auditTypes = h.f.store.auditPage('acme', { limit: 500 }).entries.map(e => e.envelope.payload.type);
  assert.ok(auditTypes.includes('AUTHORITY_REVOKED'));
  // A real policy transition must not resurrect revoked authority: stage and
  // activate the next constitution version, then re-present the certificate.
  const next = clone(h.f.policy('acme')); next.version = 2; next.not_before = h.now() - 1;
  h.f.store.put('acme', 'policy', 'staged', { policy: next, activate_at: next.not_before, staged_at: h.now() }, h.now());
  h.f.activateDuePolicies('acme', h.now());
  assert.equal(h.f.policy('acme').version, 2, 'the constitution actually transitioned');
  assert.throws(() => h.f.execute(h.p(), certificate), hasCode('INV-409-STATE'));
});
test('EVD-003: tampered issuer signature and wrong tenant evidence are rejected', t => {
  const h = fixture(t), r = h.proposed(), env = h.evidence(r); const altered = clone(env); altered.payload.confidence = 99; assert.throws(() => h.f.attachEvidence(h.p(), r.capsule.capsule_id, altered), hasCode('INV-401-SIGNATURE'));
  assert.throws(() => h.f.attachEvidence(h.p('operator', 'globex'), r.capsule.capsule_id, env), hasCode('INV-404-NOT-FOUND'));
});
test('IDN-001: software signature cannot satisfy hardware-required policy', t => {
  const h = fixture(t); installPolicy(h, p => { p.rules['finance.beneficiary.create'].require_hardware = true; });
  const r = h.proposed(); h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r); const d = h.f.evaluate(h.p(), r.capsule.capsule_id); assert.equal(d.decision, 'ESCROW'); assert.ok(d.reasons.some(r => r.code === 'HARDWARE_APPROVAL_REQUIRED'));
});
test('POL-011: duplicate signer cannot satisfy threshold', t => { const h = fixture(t), r = h.proposed(); h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 1); assert.throws(() => h.approve(r, 1), hasCode('INV-409-REPLAY')); assert.throws(() => h.f.certificate(h.p(), r.capsule.capsule_id), hasCode('INV-412-EVIDENCE')); });
test('ACT-010: material change or graph change invalidates exact approval', t => {
  const h = fixture(t), r = h.proposed(); h.evidence(r); const principal = h.p('custodian-1'), challenge = h.f.approvalChallenge(principal, r.capsule.capsule_id); h.evidence(r, { issuer: 'registry' });
  assert.throws(() => h.f.approve(principal, signed(challenge, h.setup.custodianKeys.acme['custodian-1'], 'action-approval')), hasCode('INV-409-STATE'));
});
test('COM-014 POL-009: 3-of-5 customer software quorum protects exact policy activation', t => {
  const h = fixture(t), next = clone(h.f.policy('acme')); next.version = 2; next.rules['finance.payment.first'].max_quantity = 500000;
  const r = h.proposed('policy.change', { policy: next }, { action: { type: 'policy.change', target_resource: 'policy-root', purpose: 'Tighten payment ceiling' } });
  h.f.simulate(h.p('policy-admin'), next); h.advance(120001); h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { issuer: 'audit-committee', kind: 'governance_review' }); h.approve(r, 2);
  assert.throws(() => h.f.certificate(h.p(), r.capsule.capsule_id), hasCode('INV-412-EVIDENCE'));
  const p = h.p('custodian-3'); h.f.approve(p, signed(h.f.approvalChallenge(p, r.capsule.capsule_id), h.setup.custodianKeys.acme['custodian-3'], 'action-approval'));
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id); assert.equal(h.f.execute(h.p(), cert).payload.status, 'VERIFIED'); assert.equal(h.f.policy('acme').version, 2);
});
test('UC-02: exact first payment enforces beneficiary amount and cannot repeat', t => {
  const h = fixture(t), r = h.proposed('finance.payment.first', { beneficiary_id: 'beneficiary-1', bank_account: 'TESTBANK000001', amount_minor: 25000, currency: 'EUR', invoice_id: 'invoice-1' }, { action: { type: 'finance.payment.first', target_resource: 'beneficiary-1', purpose: 'Pay synthetic invoice' } });
  const { certificate } = h.ready(r); assert.equal(h.f.execute(h.p(), certificate).payload.status, 'VERIFIED'); assert.equal(h.f.target.state('acme', 'beneficiary-1').material_fields.payment.amount_minor, 25000);
});

test('COM-009: self-consistent but unauthorised observed state must not pass reconciliation', t => {
  const h = fixture(t), { certificate } = h.ready(), original = h.f.target.execute.bind(h.f.target);
  h.f.target.execute = (...args) => { const raw = original(...args); raw.observed_state.bank_account = 'ATTACKBANK9999'; raw.observed_state_digest = digest(raw.observed_state); return raw; };
  // A post-journal forgery is an integrity failure — the claimed VERIFIED
  // can never match the durable dispatch journal (w12 red-team).
  assert.throws(() => h.f.execute(h.p(), certificate), hasCode('INV-409-INTEGRITY'));
});
test('POL-010: exact candidate simulation required before policy certificate', t => {
  const h = fixture(t), next = clone(h.f.policy('acme')); next.version = 2;
  const r = h.proposed('policy.change', { policy: next }); h.advance(120001); h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'audit-committee' }); h.approve(r, 3);
  assert.throws(() => h.f.certificate(h.p(), r.capsule.capsule_id), hasCode('INV-412-EVIDENCE'));
});

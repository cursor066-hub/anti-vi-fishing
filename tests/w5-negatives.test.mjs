import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, createHash } from 'node:crypto';
import { fixture, hasCode, runtimeInput, runtimeRequest } from './helpers.mjs';
import { proposal } from '../src/schema.mjs';
import { generateKey, signed } from '../src/crypto.mjs';
import { digest, clone } from '../src/canonical.mjs';
import { verifyAudit } from '../src/store.mjs';
import { Fabric } from '../src/fabric.mjs';
import { createConfiguration } from '../src/bootstrap.mjs';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Negative-branch sweep (w5-testquality §5): each test names the guard it
// exercises so a removed or reordered check turns red.

test('fabric: actor field must equal the authenticated subject', t => {
  const h = fixture(t);
  const state = h.f.target.state('acme', 'vendor-1');
  const input = proposal('finance.bank.change', { subject_id: 'operator', identity_class: 'workforce', device_id: 'operator-device' }, state, { bank_account: 'TESTBANK000009', currency: 'EUR' }, h.now());
  const intent = signed(input, h.setup.identityKeys.acme.operator, 'capsule-intent');
  // Signed by operator's key but submitted under a different authorised
  // subject — the actor binding refuses it before intent verification.
  assert.throws(() => h.f.propose(h.p('policy-admin'), input, randomUUID(), intent), hasCode('INV-403-ACTOR'));
});

test('fabric: a capsule without request intent is refused', t => {
  const h = fixture(t);
  const state = h.f.target.state('acme', 'vendor-1');
  const input = proposal('finance.bank.change', h.actor(), state, { bank_account: 'TESTBANK000009', currency: 'EUR' }, h.now());
  assert.throws(() => h.f.propose(h.p(), input, randomUUID(), null), hasCode('INV-401-SIGNATURE'));
});

test('fabric: supporting evidence whose claims do not describe this action is refused', t => {
  const h = fixture(t); const r = h.proposed();
  const payload = { evidence_id: randomUUID(), tenant_id: 'acme', capsule_digest: r.capsule_digest, kind: 'ownership', content_digest: digest({ x: 1 }), acquired_at: h.now(), expires_at: h.now() + 600000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 'Synthetic test issuer', retention_until: h.now() + 660000, claims: { account: 'SOMEONE_ELSES_ACCOUNT', owner_id: r.capsule.action.target_resource } };
  const env = signed(payload, h.setup.issuerKeys.acme.bank, 'evidence');
  assert.throws(() => h.f.attachEvidence(h.p(), r.capsule.capsule_id, env), hasCode('INV-403-SCOPE'));
});

test('fabric: an attestation for an unknown perception component is refused', t => {
  const h = fixture(t);
  const ghost = generateKey();
  const attestation = signed({ component: 'no-such-component', firmware_version: 'x', nonce: 'd'.repeat(64), expires_at: h.now() + 300000 }, ghost, 'component-attestation');
  assert.throws(() => h.f.perceptionSession(h.p(), attestation), hasCode('INV-401-ATTESTATION'));
});

test('runtime: data.read with empty rows or columns is refused', t => {
  const h = fixture(t);
  for (const input of [runtimeInput({ columns: [] }), runtimeInput({ row_ids: [] })]) {
    assert.throws(() => h.f.runtime.issue(h.p(), input), hasCode('INV-400-SCHEMA'));
  }
});

test('runtime: capability limits beyond policy ceilings are refused', t => {
  const h = fixture(t);
  const policy = h.f.policy('acme');
  assert.throws(() => h.f.runtime.issue(h.p(), runtimeInput({ max_cost: policy.runtime.max_cost + 1 })), hasCode('INV-403-SCOPE'));
  assert.throws(() => h.f.runtime.issue(h.p(), runtimeInput({ ttl_ms: policy.capability_ttl_ms + 1 })), hasCode('INV-403-SCOPE'));
});

test('runtime: consuming a forged capability envelope is refused', t => {
  const h = fixture(t);
  const forged = signed({ capability_id: randomUUID(), tenant_id: 'acme', subject_id: 'operator', resource: 'dataset-1', destination: 'customer-vault', action: 'data.read', purpose: 'operations', columns: ['id'], row_ids: ['row-1'], classification: 'internal', jurisdiction: 'EU', max_cost: 1, ttl_ms: 60000, issued_at: h.now(), expires_at: h.now() + 60000, policy_digest: 'x'.repeat(64), policy_version: 1, gate_id: h.f.config.gate_id, runtime_policy: h.f.policy('acme').runtime, request_id: 'r' }, generateKey(), 'capability');
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(forged)), e => e.code?.startsWith('INV-40'));
});

test('target: secret.use refuses undeclared operations and workload mismatch', t => {
  const h = fixture(t);
  // An operation the constitution never allows is denied at evaluation — no
  // certificate can be minted for it.
  const denied = h.proposed('secret.use', { secret_id: 'secret-erp-1', operation: 'export', workload_id: 'workload-1' }, { action: { type: 'secret.use', target_resource: 'secret-erp-1', purpose: 'Secret op' } });
  h.evidence(denied, { kind: 'workload_attestation' }); h.evidence(denied, { kind: 'workload_attestation', issuer: 'cloud-attestor' }); h.approve(denied, 2);
  const verdict = h.f.evaluate(h.p(), denied.capsule.capsule_id);
  assert.equal(verdict.decision, 'DENY');
  assert.ok(verdict.reasons.some(x => x.code === 'SECRET_EXTRACTION'));
  // A declared operation against the wrong workload mints but fails at the
  // target's binding check.
  const wrong = h.proposed('secret.use', { secret_id: 'secret-erp-1', operation: 'sign', workload_id: 'workload-9' }, { action: { type: 'secret.use', target_resource: 'secret-erp-1', purpose: 'Secret op' } });
  h.evidence(wrong, { kind: 'workload_attestation' }); h.evidence(wrong, { kind: 'workload_attestation', issuer: 'cloud-attestor' }); h.approve(wrong, 2);
  const cert = h.f.certificate(h.p(), wrong.capsule.capsule_id);
  const outcome = h.f.execute(h.p(), cert);
  assert.equal(outcome.payload.status, 'FAILED');
  assert.equal(outcome.payload.reason, 'INV-403-SCOPE');
});

test('store: a newer on-disk schema version is refused at open', t => {
  const directory = mkdtempSync(join(tmpdir(), 'if-store-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const setup = createConfiguration(['acme'], 1788648000000);
  const f = new Fabric(setup.config, directory, () => 1788648000000);
  f.close();
  const sqlite = new DatabaseSync(join(directory, 'fabric.db'));
  sqlite.exec('PRAGMA user_version = 2'); sqlite.close();
  assert.throws(() => new Fabric(setup.config, directory, () => 1788648000000), hasCode('INV-503-STORAGE'));
});

test('store: exported audit with a non-monotonic entry time fails continuity', t => {
  const h = fixture(t); h.proposed();
  const bundle = h.f.exportAudit(h.p('auditor'), 'Monotonicity probe');
  // Move an entry's timestamp backwards, re-sign the envelope and repair the
  // hash so only the monotonic-time arm can catch it.
  const tampered = clone(bundle);
  const entry = { ...tampered.entries[1].envelope.payload, time: tampered.entries[0].envelope.payload.time - 1 };
  tampered.entries[1].envelope = h.f.store.auditSigners.acme.sign(entry);
  tampered.entries[1].hash = digest(entry);
  assert.throws(() => verifyAudit(tampered, bundle.public_keys), hasCode('INV-409-AUDIT'));
});

test('store: exported audit with an inconsistent checkpoint fails', t => {
  const h = fixture(t); h.proposed();
  const bundle = h.f.exportAudit(h.p('auditor'), 'Checkpoint probe');
  // Re-sign the tampered checkpoint with the audit key so the signature is
  // valid and only the consistency arm can fire.
  const tampered = clone(bundle);
  tampered.checkpoint = h.f.store.auditSigners.acme.sign({ ...tampered.checkpoint.payload, size: tampered.checkpoint.payload.size + 1 }, 'checkpoint');
  assert.throws(() => verifyAudit(tampered, bundle.public_keys), hasCode('INV-409-AUDIT'));
});

test('schema: account charset, nonce length, payment and export invariants are enforced', t => {
  const h = fixture(t);
  const state = h.f.target.state('acme', 'vendor-1');
  const actor = h.actor();
  for (const mutate of [
    i => { i.requested_state.bank_account = 'BAD@ACCOUNT!'; },
    i => { i.nonce = 'short'; },
    i => { i.requested_state.currency = 'XXX'; },
  ]) {
    const input = proposal('finance.bank.change', actor, state, { bank_account: 'TESTBANK000009', currency: 'EUR' }, h.now());
    mutate(input);
    assert.throws(() => h.f.propose(h.p(), input, randomUUID(), signed(input, h.setup.identityKeys.acme.operator, 'capsule-intent')), hasCode('INV-400-SCHEMA'));
  }
  // Payment: destination must equal the bank account.
  const pstate = h.f.target.state('acme', 'beneficiary-1');
  const pay = proposal('finance.payment.first', actor, pstate, { beneficiary_id: 'beneficiary-1', bank_account: 'TESTBANK000001', amount_minor: 25000, currency: 'EUR', invoice_id: 'i-1' }, h.now());
  pay.destination = 'OTHER-ACCOUNT';
  assert.throws(() => h.f.propose(h.p(), pay, randomUUID(), signed(pay, h.setup.identityKeys.acme.operator, 'capsule-intent')), hasCode('INV-400-SCHEMA'));
  // Export: exclusions must not cover requested columns, quantity must equal rows.
  const dstate = h.f.target.state('acme', 'dataset-1');
  const exp = proposal('data.export', actor, dstate, { dataset: 'dataset-1', columns: ['id'], row_ids: ['row-1'], max_rows: 1, classification: 'internal', jurisdiction: 'EU' }, h.now());
  exp.quantity = 7;
  assert.throws(() => h.f.propose(h.p(), exp, randomUUID(), signed(exp, h.setup.identityKeys.acme.operator, 'capsule-intent')), hasCode('INV-400-SCHEMA'));
});

test('POL-008: a staged policy activates, then a fresh capsule is evaluated and executed under it', t => {
  const h = fixture(t);
  const canary = clone(h.f.policy('acme'));
  canary.version = 2; canary.policy_id = 'constitution:acme:v2'; canary.not_before = h.now() + 120000;
  canary.rules['finance.payment.first'].max_quantity = 10000;
  const pc = h.proposed('policy.change', { policy: canary }, { action: { type: 'policy.change', target_resource: 'policy-root', purpose: 'Staged rollout' } });
  h.f.simulate(h.p('policy-admin'), canary);
  h.advance(120001); // STAGED_DELAY refuses a not_before inside min_delay_ms
  h.evidence(pc, { kind: 'governance_review' }); h.evidence(pc, { kind: 'governance_review', issuer: 'audit-committee' }); h.approve(pc, 3);
  const cert = h.f.certificate(h.p(), pc.capsule.capsule_id);
  assert.equal(h.f.execute(h.p(), cert).payload.status, 'VERIFIED');
  h.advance(120001); h.proposed(); // any transaction promotes the staged constitution
  assert.equal(h.f.policy('acme').version, 2);
  // Post-activation seam: an over-limit payment is denied under v2, an
  // in-limit one mints, executes and verifies.
  const over = h.proposed('finance.payment.first', { beneficiary_id: 'beneficiary-1', bank_account: 'TESTBANK000001', amount_minor: 25000, currency: 'EUR', invoice_id: 'i-over' }, { policy_version: 2, action: { type: 'finance.payment.first', target_resource: 'beneficiary-1', purpose: 'Over limit' } });
  const denied = h.f.evaluate(h.p(), over.capsule.capsule_id);
  assert.equal(denied.decision, 'DENY');
  assert.ok(denied.reasons.some(x => x.code === 'QUANTITY_LIMIT'));
  const within = h.proposed('finance.payment.first', { beneficiary_id: 'beneficiary-1', bank_account: 'TESTBANK000001', amount_minor: 5000, currency: 'EUR', invoice_id: 'i-ok' }, { policy_version: 2, action: { type: 'finance.payment.first', target_resource: 'beneficiary-1', purpose: 'Within limit' } });
  const { certificate } = h.ready(within);
  assert.equal(h.f.execute(h.p(), certificate).payload.status, 'VERIFIED');
});

test('fabric: approveInner rejects an envelope bound to a different capsule', t => {
  const h = fixture(t); const a = h.proposed(), b = h.proposed();
  const envelope = h.approvalEnvelope(a, 'custodian-1');
  assert.throws(() => h.f.approveInner(h.p('custodian-1'), b.capsule.capsule_id, envelope, h.now()), hasCode('INV-403-SCOPE'));
});

test('fabric: a ceremony acknowledgement cannot name another custodian', t => {
  const h = fixture(t);
  const ceremony = h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-ack-neg', purpose: 'key.recovery', threshold: 2, custodians: ['custodian-1', 'custodian-2', 'custodian-3'], valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  const artifact = h.f.store.must('acme', 'ceremony', ceremony.ceremony_id).artifact_digest;
  const forged = signed({ ceremony_id: ceremony.ceremony_id, artifact_digest: artifact, custodian: 'custodian-2', acknowledged_at: h.now() }, h.setup.identityKeys.acme['custodian-1'], 'ceremony-acknowledgement');
  assert.throws(() => h.f.acknowledgeCeremony(h.p('custodian-1'), forged), hasCode('INV-403-SCOPE'));
});

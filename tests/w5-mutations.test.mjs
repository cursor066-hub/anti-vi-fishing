import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture, hasCode, runtimeInput, runtimeRequest } from './helpers.mjs';
import { proposal } from '../src/schema.mjs';
import { generateKey, signed } from '../src/crypto.mjs';
import { digest } from '../src/canonical.mjs';

// Mutation-kill suite. Each case corresponds to a verifier-mutant that escaped
// the original tests (w5-testquality audit §3): the guard exists in src/ but no
// test could see it die. Every test drives the real code path and asserts the
// specific refusal code — a removed or weakened check turns this red.

function evidenceEnvelope(h, record, mutate = {}) {
  const rs = record.capsule.requested_state ?? {};
  const claims = { account: rs.bank_account ?? 'TESTBANK000001', owner_id: record.capsule.action.target_resource };
  const payload = { evidence_id: randomUUID(), tenant_id: record.capsule.tenant_id, capsule_digest: record.capsule_digest, kind: 'ownership', content_digest: digest({ source: 'synthetic-only', claim: 'supports' }), acquired_at: h.now(), expires_at: h.now() + 600000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 'Synthetic test issuer', retention_until: h.now() + 660000, claims, ...mutate };
  return signed(payload, h.setup.issuerKeys[record.capsule.tenant_id].bank, 'evidence');
}

test('E1: two custodians sharing one failure domain cannot satisfy the independent-domain quorum', t => {
  const h = fixture(t);
  const r = h.proposed(); h.evidence(r); h.evidence(r, { issuer: 'registry' });
  // Register a real custodian that colludes with custodian-1 — same blast zone.
  const colluder = generateKey();
  h.f.tenant('acme').identities[colluder.key_id] = { public_key: colluder.public_key, subject_id: 'custodian-x', identity_class: 'workforce', roles: ['custodian', 'approver'], device_id: 'custodian-x-device', failure_domain: 'acme-custodian-1', hardware_backed: false, health_expires_at: h.now() + 86400000, grants: { resources: [], actions: [], destinations: [], columns: [], row_ids: [] } };
  const record = h.f.getCapsule(h.p(), r.capsule.capsule_id);
  const envelope = signed({ tenant_id: 'acme', capsule_id: r.capsule.capsule_id, capsule_digest: r.capsule_digest, evidence_graph_digest: h.f.graph('acme', record).digest, policy_digest: digest(h.f.policy('acme')), signer_id: colluder.key_id, approved_at: h.now(), expires_at: Math.min(h.now() + 300000, r.capsule.expires_at) }, colluder, 'action-approval');
  h.f.approve(h.p('custodian-x'), envelope); // signature and role are valid — the approval is accepted
  h.approve(r, ['custodian-1']);
  const decision = h.f.evaluate(h.p(), r.capsule.capsule_id);
  assert.equal(decision.decision, 'ESCROW');
  assert.deepEqual(decision.eligible_signers.length, 1, 'colluding domains must count once');
  assert.ok(decision.reasons.some(x => x.code === 'APPROVAL_THRESHOLD'), JSON.stringify(decision.reasons));
});

test('E2: an envelope claiming a signer_id other than its signing key is refused', t => {
  const h = fixture(t); const r = h.proposed(); h.evidence(r); h.evidence(r, { issuer: 'registry' });
  const [otherKeyId] = Object.entries(h.f.identities('acme')).find(([, v]) => v.subject_id === 'custodian-2');
  const forged = h.approvalEnvelope(r, 'custodian-1', { signer_id: otherKeyId });
  assert.throws(() => h.f.approve(h.p('custodian-1'), forged), hasCode('INV-403-SCOPE'));
});

test('E3: evidence bound to capsule A cannot be attached to capsule B', t => {
  const h = fixture(t); const a = h.proposed(); const b = h.proposed();
  const foreign = evidenceEnvelope(h, a);
  assert.throws(() => h.f.attachEvidence(h.p(), b.capsule.capsule_id, foreign), hasCode('INV-403-SCOPE'));
});

test('E4: evidence acquired more than 7 days ago is refused', t => {
  const h = fixture(t); const r = h.proposed();
  const stale = evidenceEnvelope(h, r, { acquired_at: h.now() - 8 * 86400000 });
  assert.throws(() => h.f.attachEvidence(h.p(), r.capsule.capsule_id, stale), hasCode('INV-400-SCHEMA'));
});

test('E5: an approval signed outside the 300-second freshness window is refused', t => {
  const h = fixture(t); const r = h.proposed(); h.evidence(r); h.evidence(r, { issuer: 'registry' });
  const stale = h.approvalEnvelope(r, 'custodian-1', { approved_at: h.now() - 400000, expires_at: h.now() - 400000 + 300000 });
  assert.throws(() => h.f.approve(h.p('custodian-1'), stale), hasCode('INV-400-SCHEMA'));
  const future = h.approvalEnvelope(r, 'custodian-1', { approved_at: h.now() + 60000 });
  assert.throws(() => h.f.approve(h.p('custodian-1'), future), hasCode('INV-400-SCHEMA'));
});

test('E6: a second first-payment to the same beneficiary is a FAILED outcome, never VERIFIED', t => {
  const h = fixture(t);
  const pay = () => h.proposed('finance.payment.first', { beneficiary_id: 'beneficiary-1', bank_account: 'TESTBANK000001', amount_minor: 25000, currency: 'EUR', invoice_id: randomUUID() }, { action: { type: 'finance.payment.first', target_resource: 'beneficiary-1', purpose: 'Pay synthetic invoice' } });
  const first = h.ready(pay());
  assert.equal(h.f.execute(h.p(), first.certificate).payload.status, 'VERIFIED');
  const second = h.ready(pay());
  const outcome = h.f.execute(h.p(), second.certificate);
  assert.equal(outcome.payload.status, 'FAILED');
  assert.equal(outcome.payload.reason, 'INV-409-STATE');
});

test('E7: creating an already-existing resource is a FAILED outcome, never silent idempotency', t => {
  const h = fixture(t);
  const r = h.proposed('finance.beneficiary.create', { vendor_id: 'beneficiary-1', bank_account: 'TESTBANK000001', currency: 'EUR' }, { action: { type: 'finance.beneficiary.create', target_resource: 'beneficiary-1', purpose: 'Recreate' } });
  const { certificate } = h.ready(r);
  const outcome = h.f.execute(h.p(), certificate);
  assert.equal(outcome.payload.status, 'FAILED');
  assert.equal(outcome.payload.reason, 'INV-409-STATE');
});

test('E8: a capability minted on an internal dataset dies when the dataset is reclassified', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  h.f.target.seed('acme', 'dataset-1', { classification: 'restricted', jurisdiction: 'EU' });
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap)), hasCode('INV-409-STATE'));
});

test('E9: the 33rd evidence attachment on one capsule is refused', t => {
  const h = fixture(t); const r = h.proposed();
  for (let i = 0; i < 32; i++) h.evidence(r);
  assert.throws(() => h.evidence(r), hasCode('INV-429-CAPACITY'));
});

test('E10: evidence dependencies must already be attached to this capsule', t => {
  const h = fixture(t); const a = h.proposed(); const b = h.proposed();
  const foreignId = h.evidence(a).payload.evidence_id;
  for (const dep of [foreignId, 'nonexistent-evidence']) {
    const env = evidenceEnvelope(h, b, { dependencies: [dep] });
    assert.throws(() => h.f.attachEvidence(h.p(), b.capsule.capsule_id, env), hasCode('INV-400-SCHEMA'), dep);
  }
});

test('M-issuer-version: an envelope claiming a different issuer version than registered is refused', t => {
  const h = fixture(t); const r = h.proposed();
  const drifted = evidenceEnvelope(h, r, { issuer_version: '0.9.0' });
  assert.throws(() => h.f.attachEvidence(h.p(), r.capsule.capsule_id, drifted), hasCode('INV-403-SCOPE'));
  const current = evidenceEnvelope(h, r, { issuer_version: '1.0.0' });
  h.f.attachEvidence(h.p(), r.capsule.capsule_id, current); // matching version attaches
});

test('M-policy-digest: an approval bound to a stale policy digest is refused', t => {
  const h = fixture(t); const r = h.proposed(); h.evidence(r); h.evidence(r, { issuer: 'registry' });
  const stale = h.approvalEnvelope(r, 'custodian-1', { policy_digest: '0'.repeat(64) });
  assert.throws(() => h.f.approve(h.p('custodian-1'), stale), hasCode('INV-409-STATE'));
  // And the same check fires when the policy moved after signing.
  const signedNow = h.approvalEnvelope(r, 'custodian-1');
  h.f.store.put('acme', 'policy', 'active', { ...h.f.policy('acme'), version: 99 }, h.now());
  assert.throws(() => h.f.approve(h.p('custodian-1'), signedNow), hasCode('INV-409-STATE'));
});

test('M-created-at: a capsule whose declared creation time lies outside the window is refused', t => {
  const h = fixture(t);
  const state = h.f.target.state('acme', 'vendor-1');
  const input = proposal('finance.bank.change', { subject_id: 'operator', identity_class: 'workforce', device_id: 'operator-device' }, state, { bank_account: 'TESTBANK000009', currency: 'EUR' }, h.now());
  const stale = { ...input, created_at: h.now() - 400000 };
  const intent = signed(stale, h.setup.identityKeys.acme.operator, 'capsule-intent');
  assert.throws(() => h.f.propose(h.p(), stale, randomUUID(), intent), hasCode('INV-400-SCHEMA'));
  const future = { ...input, created_at: h.now() + 60000 };
  assert.throws(() => h.f.propose(h.p(), future, randomUUID(), signed(future, h.setup.identityKeys.acme.operator, 'capsule-intent')), hasCode('INV-400-SCHEMA'));
});

test('M-ceremony-floor: reconstruction with zero custodian acknowledgements is refused', t => {
  const h = fixture(t);
  const id = `cer-${randomUUID()}`;
  h.f.createCeremony(h.p('security'), { ceremony_id: id, purpose: 'recovery', threshold: 2, custodians: ['custodian-1', 'custodian-2', 'custodian-3'], valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  assert.throws(() => h.f.reconstructCeremony(h.p('security'), id, []), hasCode('INV-409-STATE'));
});

test('M-ceremony-gate: key.rotate citing an unacknowledged ceremony is refused at application time', t => {
  const h = fixture(t);
  const id = `cer-${randomUUID()}`;
  const pending = h.f.prepareRotation(h.p('security'), 'execution');
  h.f.createCeremony(h.p('security'), { ceremony_id: id, purpose: 'key.rotate', threshold: 2, custodians: ['custodian-1', 'custodian-2'], valid_until: h.now() + 3600000, min_delay_ms: 120000, rotation: { key_class: 'execution', new_key_id: pending.key_id } });
  const r = h.proposed('key.rotate', { key_class: 'execution', new_key_id: pending.key_id, new_public_key: pending.public_key, ceremony_id: id, revoke_old: false }, { action: { type: 'key.rotate', target_resource: 'key-store', purpose: 'Rotation drill' } });
  h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'audit-committee' }); h.approve(r, 3); h.advance(61000);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  assert.throws(() => h.f.execute(h.p(), cert), hasCode('INV-409-STATE'));
});

test('M-nonce-replay: an attestation nonce mints exactly one perception session', t => {
  const h = fixture(t);
  const component = h.setup.componentSecrets.acme['secure-view-acme'];
  const attestation = component.attest('c'.repeat(64), h.now() + 300000);
  h.f.perceptionSession(h.p(), attestation);
  assert.throws(() => h.f.perceptionSession(h.p(), attestation), hasCode('INV-409-REPLAY'));
});

test('M-audit-cursor: a page cursor that does not resolve to a stored row is refused', t => {
  const h = fixture(t); h.ready();
  assert.throws(() => h.f.store.auditPage('acme', { after: 999999 }), hasCode('INV-409-AUDIT-TAMPER'));
  // A gap insert is refused by the engine itself.
  assert.throws(() => h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', 999999, 'x'.repeat(64), 'y'.repeat(64), '{}'), /audit sequence must extend the head/);
});

test('M-ghost-change: bank.change on a nonexistent resource is a FAILED outcome', t => {
  const h = fixture(t);
  const r = h.proposed('finance.bank.change', { bank_account: 'TESTBANK000009', currency: 'EUR' }, { action: { type: 'finance.bank.change', target_resource: 'vendor-ghost', purpose: 'Ghost change' } });
  h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2); h.advance(61000);
  const certificate = h.f.certificate(h.p(), r.capsule.capsule_id);
  const outcome = h.f.execute(h.p(), certificate);
  assert.equal(outcome.payload.status, 'FAILED');
  assert.equal(outcome.payload.reason, 'INV-409-STATE');
});

test('D5/E-fanout: consuming a capability on a fifth distinct resource trips the fan-out ceiling', t => {
  const h = fixture(t);
  const policy = h.f.policy('acme');
  policy.runtime.services = ['erp-service', 'svc-2', 'svc-3', 'svc-4', 'svc-5'];
  policy.runtime.destinations = [...new Set([...policy.runtime.destinations, ...policy.runtime.services])];
  h.f.store.put('acme', 'policy', 'active', policy, h.now());
  const [keyId, identity] = Object.entries(h.f.tenant('acme').identities).find(([, v]) => v.subject_id === 'operator');
  identity.grants.resources = [...new Set([...identity.grants.resources, ...policy.runtime.services])];
  identity.grants.destinations = [...new Set([...identity.grants.destinations, ...policy.runtime.services])];
  for (const service of policy.runtime.services.slice(0, 4)) {
    const cap = h.f.runtime.issue(h.p(), runtimeInput({ action: 'service.connect', resource: service, destination: service, columns: [], row_ids: [] }));
    h.f.runtime.consume(h.p(), runtimeRequest(cap, { columns: [], row_ids: [] }));
  }
  const fifth = h.f.runtime.issue(h.p(), runtimeInput({ action: 'service.connect', resource: 'svc-5', destination: 'svc-5', columns: [], row_ids: [] }));
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(fifth, { columns: [], row_ids: [] })), hasCode('INV-429-FANOUT'));
});

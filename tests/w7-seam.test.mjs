// w7-seam regression tests — cross-component findings verified by PoCs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, randomBytes } from 'node:crypto';
import { fixture, hasCode } from './helpers.mjs';
import { signed } from '../src/crypto.mjs';
import { digest } from '../src/canonical.mjs';
import { signAcknowledgement } from '../src/ceremony.mjs';

function certified(h, type = 'finance.beneficiary.create', requested = { vendor_id: 'vendor-1', bank_account: 'TESTBANK000002', currency: 'EUR' }, overrides = {}) {
  const r = h.proposed(type, requested, overrides);
  h.evidence(r);
  if (type !== 'data.export') h.evidence(r, { issuer: 'registry' });
  h.approve(r, 2);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  return { record: r, certificate: cert };
}

function validationEnvelope(h, path, issuer, overrides = {}) {
  const payload = { evidence_id: randomUUID(), tenant_id: 'acme', capsule_digest: digest(path), kind: 'technical_validation', content_digest: digest({ probe: 'ok' }), acquired_at: h.now(), expires_at: h.now() + 60000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 'manual probe', retention_until: h.now() + 120000, issuer_version: '1.0.0', claims: { capsule_digest: digest(path) }, ...overrides };
  return { envelope: signed(payload, h.setup.issuerKeys.acme[issuer], 'evidence'), payload };
}

// w7-seam F1: coverage promotion applies the same trust floor as action
// evidence — advisory flag, sub-90 confidence, communication channel and
// out-of-kind envelopes can never promote a path; the cited evidence row is
// persisted on the ledger rather than left dangling. (COV-010 trust floor)
test('w7-seam F1: technicalValidation enforces advisory/confidence/channel/kind bars and persists evidence', t => {
  const h = fixture(t);
  h.f.declareCoverage(h.p('security'), { path_id: 'pv', action_type: 'data.export', target: 'dataset-1', environment: 'prod', connector_version: '1.0', owner: 'op', status: 'UNKNOWN', path_class: 'api', max_age_ms: 60000, configuration_digest: digest({ c: 1 }) });
  const path = () => h.f.store.must('acme', 'coverage', 'pv');
  assert.throws(() => h.f.technicalValidation(h.p('security'), 'pv', validationEnvelope(h, path(), 'security-ops', { advisory: true }).envelope), hasCode('INV-400-SCHEMA'));
  assert.throws(() => h.f.technicalValidation(h.p('security'), 'pv', validationEnvelope(h, path(), 'security-ops', { confidence: 55 }).envelope), hasCode('INV-400-SCHEMA'));
  assert.throws(() => h.f.technicalValidation(h.p('security'), 'pv', validationEnvelope(h, path(), 'security-ops', { kind: 'ownership' }).envelope), hasCode('INV-403-SCOPE'));
  assert.throws(() => h.f.technicalValidation(h.p('security'), 'pv', validationEnvelope(h, path(), 'email').envelope), hasCode('INV-403-SCOPE'));
  const { envelope, payload } = validationEnvelope(h, path(), 'security-ops');
  // A passed independent bypass test is the ENFORCED criterion (w8-composite F13).
  assert.equal(h.f.technicalValidation(h.p('security'), 'pv', envelope).status, 'ENFORCED');
  const stored = h.f.store.get('acme', 'evidence', payload.evidence_id);
  assert.ok(stored && stored.envelope, 'cited validation evidence resolves on the ledger');
});

// w7-seam F2 + F10: coverageAt replays oldest→newest (the store returns
// newest-first), and re-validation refreshes the evidence window so a
// MONITORED path stays alive.
test('w7-seam F2/F10: history replays in order and revalidation extends coverage', t => {
  const h = fixture(t);
  h.f.declareCoverage(h.p('security'), { path_id: 'pr', action_type: 'data.export', target: 'dataset-1', environment: 'prod', connector_version: '1.0', owner: 'op', status: 'UNKNOWN', path_class: 'api', max_age_ms: 60000, configuration_digest: digest({ c: 2 }) });
  const t0 = h.now();
  const path = () => h.f.store.must('acme', 'coverage', 'pr');
  h.advance(1000);
  h.f.technicalValidation(h.p('security'), 'pr', validationEnvelope(h, path(), 'security-ops').envelope);
  const t2 = h.now();
  // F2: replay at t2 must answer MONITORED — oldest event applied last would
  // falsify it back to UNKNOWN. (COV-009 arbitrary-instant replay)
  assert.equal(h.f.coverageAt(h.p('auditor'), t2).paths['pr'].status, 'ENFORCED', 'validated paths carry the ENFORCED status (w8-composite F13)');
  assert.equal(h.f.coverageAt(h.p('auditor'), t0 + 500).paths['pr'].status, 'UNKNOWN', 'status before validation stays UNKNOWN');
  // F10: age past the window, re-validate, evidence window refreshes.
  h.advance(70000);
  assert.equal(h.f.coverageAt(h.p('auditor'), h.now()).paths['pr'].status, 'UNKNOWN', 'stale evidence drops the path');
  h.f.technicalValidation(h.p('security'), 'pr', validationEnvelope(h, path(), 'security-ops').envelope);
  assert.equal(h.f.coverageAt(h.p('auditor'), h.now() + 55000).paths['pr'].status, 'ENFORCED', 'revalidation restarted the freshness window');
});

// w7-seam F3: issuer-drift quarantine reaches evaluation, not just attach —
// evidence attached while the issuer was healthy loses authority on drift.
test('w7-seam F3: drifted issuer evidence stops counting at evaluation', t => {
  const h = fixture(t);
  const r = h.proposed();
  h.evidence(r);
  h.evidence(r, { issuer: 'registry' });
  h.approve(r, 2);
  assert.equal(h.f.evaluate(h.p(), r.capsule.capsule_id).decision, 'ALLOW');
  // Drift is chain-anchored, not a mutable record (w13-fixverify M3): the
  // CONNECTOR_DRIFT event is what suspends the issuer — a bare
  // 'issuer-drift' store row can no longer gate or ungate anything.
  h.f.store.insert('acme', 'issuer-drift', h.setup.issuerKeys.acme['registry'].key_id, { drifted_at: h.now(), changes: [{ field: 'manifest', detail: 'invalid' }] }, h.now());
  h.f.store.audit('acme', 'CONNECTOR_DRIFT', 'test', h.setup.issuerKeys.acme['registry'].key_id, { drifted: 'manifest' }, h.now());
  const decision = h.f.evaluate(h.p(), r.capsule.capsule_id);
  assert.notEqual(decision.decision, 'ALLOW');
});

// w7-seam F4: acknowledgements bound to the superseded (pre-commit) artifact
// stop counting at the rebound artifact — and the custodian can re-acknowledge.
test('w7-seam F4: stale-digest acks excluded from quorum; custodian re-acks', t => {
  const h = fixture(t);
  const custodians = ['custodian-1', 'custodian-2', 'custodian-3'];
  const c = h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-seam', purpose: 'key.recovery', threshold: 2, custodians, valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  // Two custodians consent to the PLANNED artifact (no share commitments).
  for (const subject of custodians.slice(0, 2)) h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(c, subject, h.setup.custodianKeys.acme[subject], h.now()));
  const s = h.f.splitCeremonySecret(h.p('security'), 'cer-seam', randomBytes(32).toString('base64url'));
  const committed = h.f.store.must('acme', 'ceremony', 'cer-seam');
  assert.notEqual(committed.artifact_digest, c.artifact_digest, 'commit rebinds the artifact');
  assert.equal(h.f.custodianQuorum('acme', committed).live, 0, 'pre-commit acks no longer count');
  h.advance(120001);
  assert.throws(() => h.f.reconstructCeremony(h.p('security'), 'cer-seam', [s.shares[0].share, s.shares[1].share]), hasCode('INV-409-STATE'), 'reconstruction refuses stale consent');
  // Re-acknowledgement is not a duplicate — the earlier ack attested another artifact.
  for (const subject of custodians.slice(0, 2)) h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(committed, subject, h.setup.custodianKeys.acme[subject], h.now()));
  assert.equal(h.f.custodianQuorum('acme', h.f.store.must('acme', 'ceremony', 'cer-seam')).live, 2);
  const rec = h.f.reconstructCeremony(h.p('security'), 'cer-seam', [s.shares[0].share, s.shares[1].share]);
  assert.equal(rec.reconstructed, true);
});

// w7-seam F5 + F7: rotation pre-flight runs at reservation — a second
// certified rotation on the same ceremony fails BEFORE its cert is consumed
// or its journal writes; revoke_old:false leaves the retiring key alive and
// attests honestly.
test('w7-seam F5/F7: ceremony spent at reservation; revoke_old honored', t => {
  const h = fixture(t);
  const pending = h.f.prepareRotation(h.p('security'), 'execution');
  const previous = h.f.keys('acme').execution.key_id;
  const custodians = ['custodian-1', 'custodian-2'];
  const c = h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-rot-seam', purpose: 'key.rotate', threshold: 2, custodians, valid_until: h.now() + 3600000, min_delay_ms: 120000, rotation: { key_class: 'execution', new_key_id: pending.key_id } });
  for (const subject of custodians) h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(c, subject, h.setup.custodianKeys.acme[subject], h.now()));
  const propose = (newKey, ceremony_id) => {
    const r = h.proposed('key.rotate', { key_class: 'execution', new_key_id: newKey.key_id, new_public_key: newKey.public_key, ceremony_id, revoke_old: false }, { action: { type: 'key.rotate', target_resource: 'key-registry', purpose: 'Rotation' } });
    h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'audit-committee' });
    h.approve(r, 3);
    return r;
  };
  // Both capsules are proposed together and minted at the same instant —
  // the rotation cooldown is long enough that sequential advances would
  // outlive the 60s certificate TTL.
  const r1 = propose(pending, 'cer-rot-seam'), r2 = propose(pending, 'cer-rot-seam');
  h.advance(60001);
  const first = { r: r1, cert: h.f.certificate(h.p(), r1.capsule.capsule_id) };
  const second = { r: r2, cert: h.f.certificate(h.p(), r2.capsule.capsule_id) };
  assert.equal(h.f.execute(h.p(), first.cert).payload.status, 'VERIFIED');
  // The ceremony was spent atomically with the first reservation.
  assert.equal(h.f.store.must('acme', 'ceremony', 'cer-rot-seam').rotation_consumed, first.r.capsule.capsule_id);
  // The second certified rotation never reaches the journal: its
  // reservation fails, the certificate stays live, no wedge.
  assert.throws(() => h.f.execute(h.p(), second.cert), hasCode('INV-409-STATE'));
  const stored2 = h.f.store.must('acme', 'certificate', second.cert.payload.certificate_id);
  assert.equal(stored2.consumed, false);
  assert.equal(h.f.store.must('acme', 'capsule', second.r.capsule.capsule_id).status, 'CERTIFIED');
  assert.equal(h.f.target.outcome('acme', second.cert.payload.certificate_id), null, 'no journal row for a rejected reservation');
  assert.equal(h.f.store.get('acme', 'outcome', second.cert.payload.certificate_id), null);
  // F7: revoke_old:false left the retiring key alive, attested honestly.
  const rotRecord = h.f.store.must('acme', 'key-rotation', pending.key_id);
  assert.equal(rotRecord.revoke_old, false);
  assert.ok(!h.f.vault.keys.get(previous)?.revoked, 'retiring key stays signable when revoke_old=false');
});

// w7-seam F6: a composite cannot wrap another composite — the nested child
// would dispatch as a generic mutation and orphan live grandchildren.
test('w7-seam F6: nested composite child escrows CHILD_TYPE', t => {
  const h = fixture(t);
  const l1 = certified(h), l2 = certified(h, 'finance.beneficiary.create', { vendor_id: 'vendor-2', bank_account: 'TESTBANK000003', currency: 'EUR' });
  const inner = h.proposed('action.composite', { children: [l1.record.capsule.capsule_id, l2.record.capsule.capsule_id] }, { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'inner' } });
  h.approve(inner, 2);
  h.f.certificate(h.p(), inner.capsule.capsule_id);
  const l3 = certified(h, 'finance.beneficiary.create', { vendor_id: 'vendor-3', bank_account: 'TESTBANK000004', currency: 'USD' });
  const outer = h.proposed('action.composite', { children: [inner.capsule.capsule_id, l3.record.capsule.capsule_id] }, { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'outer' } });
  h.approve(outer, 2);
  const decision = h.f.evaluate(h.p(), outer.capsule.capsule_id);
  assert.equal(decision.decision, 'ESCROW');
  assert.ok(decision.reasons.some(r => r.code === 'CHILD_TYPE'));
});

// w7-seam F9: a wedged composite reconciles with composite bookkeeping —
// executed children marked, wedged children stay spendable under their own
// certificates.
test('w7-seam F9: wedged composite reconciles composite-aware', t => {
  const h = fixture(t);
  const c1 = certified(h);
  const c2 = certified(h, 'finance.beneficiary.create', { vendor_id: 'vendor-2', bank_account: 'TESTBANK000003', currency: 'EUR' });
  const r = h.proposed('action.composite', { children: [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id] }, { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'pair' } });
  h.approve(r, 2);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  assert.throws(() => h.f.execute(h.p(), cert, { fault: 'process-crash' }), /process death/i);
  const outcome = h.f.reconcile(h.p('security'), cert.payload.certificate_id);
  assert.equal(outcome.payload.status, 'UNCERTAIN');
  assert.equal(outcome.payload.composite, true);
  assert.deepEqual([...outcome.payload.wedged_children].sort(), [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id].sort());
  // Wedged children keep live authority — they can still execute standalone.
  const child1 = h.f.execute(h.p(), c1.certificate);
  assert.equal(child1.payload.status, 'VERIFIED');
});

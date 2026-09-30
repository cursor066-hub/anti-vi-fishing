// Wave-8 hostile audit regressions: composite lifecycle + coverage plane.
// Every test asserts the honest terminal semantics the w8-composite auditor
// falsified on the pinned commit (F1..F16).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { fixture, hasCode } from './helpers.mjs';
import { digest } from '../src/canonical.mjs';
import { signed } from '../src/crypto.mjs';
import { createIssuerServer, loadIssuers, writeIssuer } from '../src/issuerd.mjs';
import { ISSUER_RULES } from '../src/bootstrap.mjs';
import { coverageAt } from '../src/coverage.mjs';

const JIT_REQ = { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-1'], ttl_ms: 60000, reason: 'Incident', roles: [] };
const JIT_OVR = { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'JIT' } };
const EXPORT_REQ = { dataset: 'dataset-1', columns: ['id'], row_ids: ['row-1'], max_rows: 1, classification: 'internal', jurisdiction: 'EU' };
const EXPORT_OVR = { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Operations' }, destination: 'customer-vault' };

const jitChild = h => { const r = h.proposed('identity.jit.grant', JIT_REQ, JIT_OVR); h.evidence(r, { kind: 'identity_proof', issuer: 'hris' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const beneChild = (h, n) => { const r = h.proposed('finance.beneficiary.create', { vendor_id: `vendor-${n}`, bank_account: `TESTBANK00000${n}`, currency: 'EUR' }); h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const exportChild = h => { const r = h.proposed('data.export', EXPORT_REQ, EXPORT_OVR); h.evidence(r, { kind: 'dataset_authority' }); h.approve(r, 1); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const composite = (h, children) => { const r = h.proposed('action.composite', { children }, { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'Batch' } }); h.approve(r, 2); return r; };
const killNthDispatch = (h, n) => { const orig = h.f.target.execute.bind(h.f.target); let calls = 0; h.f.target.execute = (capsule, id, now, fault) => { calls += 1; if (calls === n) throw new Error('child dispatch lost mid-flight'); return orig(capsule, id, now, fault); }; };

// F9: a composite may not mint a certificate over an already-dead child cert.
test('w8 F9: composite over an expired child certificate escrows at evaluation', t => {
  const h = fixture(t);
  const c1 = jitChild(h), c2 = beneChild(h, 2);
  const childCert = h.f.store.must('acme', 'certificate', c1.certificate.payload.certificate_id);
  h.advance(childCert.envelope.payload.expires_at - h.now() + 1);
  const r = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const evald = h.f.evaluate(h.p(), r.capsule.capsule_id);
  assert.equal(evald.decision, 'ESCROW');
  assert.ok(evald.reasons.some(x => x.code === 'CHILD_CERT'), 'expired child cert is named as the problem');
  assert.throws(() => h.f.certificate(h.p(), r.capsule.capsule_id), hasCode('INV-412-EVIDENCE'));
});

// F8: a bound child certificate can only be spent through its parent.
test('w8 F8: a certified composite child certificate refuses solo execution', t => {
  const h = fixture(t);
  const c1 = jitChild(h), c2 = beneChild(h, 2);
  const r = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const parentCert = h.f.certificate(h.p(), r.capsule.capsule_id);
  assert.throws(() => h.f.execute(h.p(), c1.certificate), hasCode('INV-409-STATE'));
  const out = h.f.execute(h.p(), parentCert);
  assert.equal(out.payload.status, 'VERIFIED');
  assert.equal(out.payload.child_outcomes[c1.record.capsule.capsule_id], 'VERIFIED');
  assert.equal(out.payload.child_outcomes[c2.record.capsule.capsule_id], 'VERIFIED');
});

// F1+F3+F6+F7+F16: a bail over a non-compensatable child is honestly FAILED;
// every executed child carries a terminal outcome row; reconcile can neither
// resurrect a child nor re-fire its effects; every child is accounted.
test('w8 F1/F3/F7/F16: uncompensated bail records FAILED parent + per-child outcomes', t => {
  const h = fixture(t);
  const c1 = jitChild(h), c2 = beneChild(h, 2);
  const r = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const parentCert = h.f.certificate(h.p(), r.capsule.capsule_id);
  killNthDispatch(h, 2);
  const out = h.f.execute(h.p(), parentCert);
  // jit.grant is non-compensatable — COMPENSATED would be a lie (F1).
  assert.equal(out.payload.status, 'FAILED');
  assert.match(out.payload.reason, /^COMPENSATION_INCOMPLETE:/);
  assert.ok(out.payload.wedged_children.includes(c2.record.capsule.capsule_id));
  // F7: the terminal record names every child's fate.
  assert.equal(out.payload.child_outcomes[c1.record.capsule.capsule_id], 'FAILED');
  assert.equal(out.payload.child_outcomes[c2.record.capsule.capsule_id], 'WEDGED');
  // F3/F4: reconcile(child) returns the recorded verdict — no resurrection,
  // no JIT grant minted, no effect replay.
  const childOutcome = h.f.reconcile(h.p(), c1.certificate.payload.certificate_id);
  assert.equal(childOutcome.payload.status, 'FAILED');
  assert.equal(childOutcome.payload.composite_child_of, parentCert.payload.certificate_id);
  assert.equal(h.f.store.list('acme', 'jit-grant', 100).length, 0, 'a failed-bail child must not mint a live grant');
  // F16: the parent settles from its recorded outcome, forever.
  assert.equal(h.f.reconcile(h.p(), parentCert.payload.certificate_id).payload.status, 'FAILED');
});

// F6: a VERIFIED composite cannot double-fire child effects on reconcile.
test('w8 F4/F6: a verified composite child settles to its recorded outcome without re-firing effects', t => {
  const h = fixture(t);
  const c1 = jitChild(h), c2 = beneChild(h, 2);
  const r = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const parentCert = h.f.certificate(h.p(), r.capsule.capsule_id);
  assert.equal(h.f.execute(h.p(), parentCert).payload.status, 'VERIFIED');
  assert.equal(h.f.store.list('acme', 'jit-grant', 100).length, 1);
  const childOutcome = h.f.reconcile(h.p(), c1.certificate.payload.certificate_id);
  assert.equal(childOutcome.payload.status, 'VERIFIED');
  assert.equal(childOutcome.payload.composite_child_of, parentCert.payload.certificate_id);
  assert.equal(h.f.store.list('acme', 'jit-grant', 100).length, 1, 'reconcile must not mint a second grant');
});

// F2: an export child that egressed rows under a bail still writes usage and
// watermarks — irrevocable egress can never skip the ledger.
test('w8 F2: an egressed export inside a failed composite is charged and watermarked', t => {
  const h = fixture(t);
  const c1 = exportChild(h), c2 = beneChild(h, 2);
  const r = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const parentCert = h.f.certificate(h.p(), r.capsule.capsule_id);
  killNthDispatch(h, 2);
  const out = h.f.execute(h.p(), parentCert);
  assert.equal(out.payload.status, 'FAILED');
  const childOutcome = h.f.reconcile(h.p(), c1.certificate.payload.certificate_id);
  assert.equal(childOutcome.payload.status, 'FAILED');
  const usage = h.f.store.db.prepare("SELECT * FROM usage WHERE tenant='acme' AND capability=? AND request=?").all(`cert:${c1.certificate.payload.certificate_id}`, c1.certificate.payload.certificate_id);
  assert.equal(usage.length, 1, 'the egressed export is charged even though the parent failed');
  assert.ok(Array.isArray(childOutcome.payload.watermarks) && childOutcome.payload.watermarks.length === 1, 'egressed rows carry attribution watermarks');
});

// F5: reconcile recomputes expected state against the EXECUTION instant — a
// later validation instant must not falsify a journal entry.
test('w8 F5: reconcile verifies a time-embedded journal entry after the clock moved', t => {
  const h = fixture(t);
  const r = h.proposed('identity.mfa.reset', { subject_id: 'operator', authenticator_id: 'auth-1' }, { action: { type: 'identity.mfa.reset', target_resource: 'identity-ops', purpose: 'protected reset' } });
  h.evidence(r, { issuer: 'hris', kind: 'recovery_authority' }); h.evidence(r, { issuer: 'registry', kind: 'identity_proof' }); h.approve(r, 2);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  assert.equal(h.f.execute(h.p(), cert, { fault: 'after-commit' }).payload.status, 'UNCERTAIN');
  h.advance(300000); // the reconcile instant has moved far past dispatch time
  assert.equal(h.f.reconcile(h.p(), cert.payload.certificate_id).payload.status, 'VERIFIED');
});

const coverageValidationEnvelope = (h, path, issuer = 'security-ops') => {
  const payload = { evidence_id: randomUUID(), tenant_id: 'acme', capsule_digest: digest(path), kind: 'technical_validation', content_digest: digest({ probe: 'ok' }), acquired_at: h.now(), expires_at: h.now() + 60000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 'manual probe', retention_until: h.now() + 120000, claims: { capsule_digest: digest(path) } };
  return signed(payload, h.setup.issuerKeys.acme[issuer], 'evidence');
};

// F11+F13: re-declare preserves earned evidence; validation earns ENFORCED
// and an UNCOVERED path cannot be re-declared MONITORED on a bare signature.
test('w8 F11/F13: re-declare preserves validation; UNCOVERED cannot self-promote; validation earns ENFORCED', t => {
  const h = fixture(t);
  const declare = (status) => h.f.declareCoverage(h.p('security'), { path_id: 'p-x', action_type: 'data.read', target: 'dataset-1', environment: 'prod', connector_version: '1.0', owner: 'op', status, path_class: 'api', max_age_ms: 60000, configuration_digest: digest({ cfg: 1 }) });
  declare('UNCOVERED');
  const validated = h.f.technicalValidation(h.p('security'), 'p-x', coverageValidationEnvelope(h, h.f.store.must('acme', 'coverage', 'p-x')));
  assert.equal(validated.status, 'ENFORCED', 'a passed bypass test is the ENFORCED criterion');
  const earned = h.f.store.must('acme', 'coverage', 'p-x').technical_validation;
  assert.ok(earned, 'validation evidence recorded');
  // F11: re-declaring the identical path must not wipe earned evidence.
  declare('UNCOVERED');
  const after = h.f.store.must('acme', 'coverage', 'p-x');
  assert.deepEqual(after.technical_validation, earned, 'identical re-declare preserves technical_validation');
  assert.equal(after.evidence_at, earned.at);
  // A bare UNCOVERED→MONITORED re-declare with no evidence is UNKNOWN, never
  // MONITORED — coverage cannot be asserted without observation.
  const h2 = fixture(t);
  h2.f.declareCoverage(h2.p('security'), { path_id: 'p-y', action_type: 'data.read', target: 'dataset-1', environment: 'prod', connector_version: '1.0', owner: 'op', status: 'UNCOVERED', path_class: 'api', max_age_ms: 60000, configuration_digest: digest({ cfg: 9 }) });
  h2.f.declareCoverage(h2.p('security'), { path_id: 'p-y', action_type: 'data.read', target: 'dataset-1', environment: 'prod', connector_version: '1.0', owner: 'op', status: 'MONITORED', path_class: 'api', max_age_ms: 60000, configuration_digest: digest({ cfg: 9 }) });
  assert.equal(h2.f.store.must('acme', 'coverage', 'p-y').status, 'UNKNOWN', 'a bare signature cannot mint MONITORED over nothing');
});

// F10+F12+F14: same-ms drift must not replay before the declaration; a
// repeat drift at the same instant must not wedge the drift transaction;
// an unreachable issuer stales its dependent paths.
test('w8 F10/F12/F14: unreachable issuer stales paths; same-ms replays keep write order; re-drift never throws', async t => {
  const h = fixture(t, ['acme']);
  const [bankKeyId, bank] = Object.entries(h.setup.config.tenants.acme.issuers).find(([, v]) => v.name === 'bank');
  const dir = mkdtempSync(join(tmpdir(), 'if-unreach-')); t.after(() => rmSync(dir, { recursive: true }));
  writeIssuer(dir, { issuer: 'bank', tenant: 'acme', channel: 'authoritative', version: '1.0.0', key: h.setup.issuerKeys.acme['bank'], kinds: ISSUER_RULES.bank, records: [], issue_token: bank.issue_token, read_token: bank.read_token });
  const srv = createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', clock: () => h.now() });
  await srv.listen();
  bank.endpoint = `http://127.0.0.1:${srv.server.address().port}`;
  h.f.declareCoverage(h.p('security'), { path_id: 'p-bank', action_type: 'payment.submit', target: 'bank', environment: 'prod', connector_version: '1.0.0', owner: 'op', status: 'MONITORED', path_class: 'api', max_age_ms: 600000, configuration_digest: 'a'.repeat(64) });
  assert.equal((await h.f.checkIssuerDrift(h.p('security'), bankKeyId)).drifted, false);
  // Kill the issuer → unreachable → drifted AND the dependent path stales.
  await srv.close();
  const drifted = await h.f.checkIssuerDrift(h.p('security'), bankKeyId);
  assert.equal(drifted.drifted, true);
  assert.equal(drifted.coverage_paths_staled, 1, 'F14: unreachable issuer stales dependent paths');
  assert.equal(h.f.store.must('acme', 'coverage', 'p-bank').status, 'UNKNOWN');
  // F10: declare + drift happened at the same frozen instant — the replay
  // must keep write order, so the answer is UNKNOWN, never resurrected.
  assert.equal(h.f.coverageAt(h.p('auditor'), h.now()).paths['p-bank'].status, 'UNKNOWN');
  // F12: a repeated unreachable check at the same ms must not throw inside
  // the drift transaction (coverage-event/task ids are upserts).
  const again = await h.f.checkIssuerDrift(h.p('security'), bankKeyId);
  assert.equal(again.drifted, true);
});

// F10 unit pin: coverageAt replays same-ms events in write order, not id order.
test('w8 F10 (unit): same-ms coverage events replay in insertion order', () => {
  const at = 1000;
  const events = [
    { path_id: 'p', type: 'declared', path: { status: 'MONITORED', evidence_at: at, max_age_ms: 60000 }, at },
    { path_id: 'p', type: 'transitioned', to: 'UNKNOWN', evidence_at: null, at, cause: 'connector-drift:bank' },
  ];
  assert.equal(coverageAt(events, at)['p'].status, 'UNKNOWN');
  // Lexically 'connector-drift:*' sorts BEFORE 'declared' — id ordering would
  // resurrect the stale declaration; insertion order cannot.
  assert.equal(coverageAt([...events].reverse(), at)['p'].status, 'MONITORED',
    'reversed input order is honoured — the caller must pass write order');
});

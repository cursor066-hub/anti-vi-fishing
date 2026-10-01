import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, createHmac } from 'node:crypto';
import { fixture, hasCode, setTenant, runtimeInput, runtimeRequest, stageConstitution } from './helpers.mjs';
import { TRANSFORMS } from '../src/datagate.mjs';
import { canonical, digest } from '../src/canonical.mjs';
import { signed } from '../src/crypto.mjs';

// Wave-10 regressions: certificate/execute lifecycle and datagate findings —
// actor-bound export egress, reservation-time reconstruction denial,
// dataset-wide coverage, journal minimisation, quorum separation and
// watermark binding/key hygiene.

const exportCert = (h, { actor = 'operator', row = 'row-1', columns = ['id'], extra = {} } = {}) => {
  const principal = h.p(actor);
  const r = h.proposed('data.export', { dataset: 'dataset-1', columns, row_ids: [row], max_rows: 1, classification: 'internal', jurisdiction: 'EU', ...extra }, { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Operations' }, destination: 'customer-vault' }, principal);
  h.evidence(r, { kind: 'dataset_authority' }); h.approve(r, 1);
  return { record: r, certificate: h.f.certificate(principal, r.capsule.capsule_id) };
};

// w10-dg F1: a certificate spendable by anyone would let a relay receive
// plaintext egress while the ledger bills the approved actor.
test('w10-dg F1: export rows release only to the approved actor', t => {
  const h = fixture(t);
  const { certificate } = exportCert(h);
  assert.throws(() => h.f.execute(h.p('policy-admin'), certificate), hasCode('INV-403-SCOPE'));
  // Control: the approved actor still executes.
  const own = exportCert(h);
  assert.equal(h.f.execute(h.p(), own.certificate).payload.status, 'VERIFIED');
});

// w10-dg F2: a second identity (jit.grant-derived or any peer) must not let
// the dataset's total disclosure exceed the window cap.
test('w10-dg F2: dataset-wide coverage binds across subject identities', t => {
  const h = fixture(t);
  const policy = h.clone(h.f.policy('acme'));
  policy.version += 1; policy.not_before = h.now();
  policy.runtime.reconstruction.max_coverage_percent = 100;      // subjects never trip
  policy.runtime.reconstruction.max_dataset_coverage_percent = 50; // union cap: ≤1 of 3 rows
  stageConstitution(h, policy);
  h.f.activateDuePolicies('acme', h.now());
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  h.f.runtime.consume(h.p(), runtimeRequest(cap)); // operator touches row-1
  // A different subject's export of a NEW row crosses the union cap even
  // though their own subject ledger is empty.
  const principal = h.p('policy-admin');
  const r = h.proposed('data.export', { dataset: 'dataset-1', columns: ['id'], row_ids: ['row-2'], max_rows: 1, classification: 'internal', jurisdiction: 'EU' }, { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Operations' }, destination: 'customer-vault', policy_version: 2 }, principal);
  const evPayload = { evidence_id: randomUUID(), tenant_id: 'acme', capsule_digest: r.capsule_digest, kind: 'dataset_authority', content_digest: digest({ source: 'synthetic-only', claim: 'supports' }), acquired_at: h.now(), expires_at: h.now() + 600000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 'Synthetic test issuer; no external authority assertion', retention_until: h.now() + 660000, issuer_version: '1.0.0', claims: { dataset: 'dataset-1' } };
  h.f.attachEvidence(principal, r.capsule.capsule_id, signed(evPayload, h.setup.issuerKeys.acme.registry, 'evidence'));
  h.approve(r, 1);
  const cert = h.f.certificate(principal, r.capsule.capsule_id);
  let denied; try { h.f.execute(principal, cert); } catch (e) { denied = e; }
  assert.equal(denied?.code, 'INV-429-BUDGET');
  assert.equal(denied.details.dataset_coverage_percent > 50, true, 'denial reports the union coverage');
  assert.equal(h.f.store.must('acme', 'certificate', cert.payload.certificate_id).consumed ?? false, false);
});

// w10-dg F4: last-two reveals the whole value on short cells.
test('w10-dg F4: short cells suppress instead of leaking through last-two', () => {
  assert.equal(TRANSFORMS.mask('ab'), '••••');
  assert.equal(TRANSFORMS.mask(42), '••••');
  assert.equal(TRANSFORMS.mask('abc'), '••••bc');
  assert.equal(TRANSFORMS.mask(null), null);
});

// w10-dg F5: the durable journal must not persist a whole-dataset snapshot
// (which includes columns the requester may not see) for an export.
test('w10-dg F5: the export journal keeps the digest, not the snapshot', t => {
  const h = fixture(t);
  const { certificate } = exportCert(h);
  h.f.execute(h.p(), certificate);
  const journal = h.f.target.outcome('acme', certificate.payload.certificate_id);
  assert.equal(journal.observed_state, null);
  assert.equal(typeof journal.observed_state_digest, 'string');
});

// w10-dg F6: the grant's beneficiary must not count toward its own quorum.
test('w10-dg F6: jit.grant beneficiary cannot sit in its own approver quorum', t => {
  const h = fixture(t);
  const r = h.proposed('identity.jit.grant', { subject_id: 'custodian-2', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-1'], ttl_ms: 60000, reason: 'Support', roles: ['operator'] }, { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'Support' } });
  h.evidence(r, { kind: 'identity_proof' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' });
  h.approve(r, ['custodian-1', 'custodian-2']);
  const decision = h.f.evaluate(h.p(), r.capsule.capsule_id);
  assert.equal(decision.decision, 'ESCROW');
  const [beneficiaryKey] = Object.entries(h.f.identities('acme')).find(([, v]) => v.subject_id === 'custodian-2');
  assert.equal(decision.eligible_signers.includes(beneficiaryKey), false, 'the beneficiary never counts');
});

// w10-dg F7: export watermarks bind tenant, capability and request — a
// caller-chosen request id can never collide two disclosures.
test('w10-dg F7: export watermarks bind tenant, capability and request', t => {
  const h = fixture(t);
  const { certificate } = exportCert(h);
  const out = h.f.execute(h.p(), certificate);
  const certId = certificate.payload.certificate_id;
  const key = Buffer.from(h.f.tenant('acme').watermark_key, 'base64url');
  const expected = createHmac('sha256', key).update(canonical({ tenant: 'acme', dataset: 'dataset-1', subject: 'operator', capability_id: `cert:${certId}`, request_id: certId, row: out.payload.output[0] })).digest('hex').slice(0, 24);
  assert.equal(out.payload.watermarks[0].tag, expected);
});

// w10-dg F8: denied consumes are ledger-bounded — identical (subject,
// code, capability) denials re-record at most once per 60s so a crafted
// flood cannot mint unbounded chain rows; a distinct incident (different
// request id AND different denial class) still lands its own record
// (w17-idx F7).
test('w10-dg F8: identical denied consumes share one containment record; distinct ones land separately', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  const request = runtimeRequest(cap, { columns: ['passport'], request_id: 'req-dup' });
  for (let i = 0; i < 3; i++) assert.throws(() => h.f.runtime.consume(h.p(), request), hasCode('INV-403-SCOPE'));
  const rows = h.f.store.list('acme', 'containment', 100).filter(c => c.capability_id === cap.payload.capability_id);
  assert.equal(rows.length, 1, 'identical denials record once — the ledger still proves the denial');
  // A genuinely different denial (replay of an already-consumed request)
  // records its own containment row.
  const cap2 = h.f.runtime.issue(h.p(), runtimeInput());
  const req2 = runtimeRequest(cap2);
  h.f.runtime.consume(h.p(), req2);
  assert.throws(() => h.f.runtime.consume(h.p(), req2), hasCode('INV-409-REPLAY'));
  const all = h.f.store.list('acme', 'containment', 100);
  assert.equal(all.length, 2, 'each distinct denial class lands once');
});

// w10-dg F9: the declared aggregate transform must actually be admissible.
test('w10-dg F9: the declared aggregate transform is admissible and applies', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ columns: ['id', 'region'], transforms: { region: { op: 'aggregate', arg: 100 } } }));
  const out = h.f.runtime.consume(h.p(), runtimeRequest(cap));
  assert.equal(out.rows[0].region, null, 'non-numeric cells bucket to null');
});

// w10-dg F10: watermarking requires the dedicated key — no silent downgrade
// to the row-encryption key.
test('w10-dg F10: a tenant without a watermark key cannot serve watermarked rows', t => {
  const h = fixture(t);
  setTenant(h, 'acme', tn => { delete tn.watermark_key; });
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap)), hasCode('INV-503-CONFIG'));
});

// w10-cert F2: a policy.change whose activation precondition lapsed between
// certification and dispatch resolves to an honest FAILED outcome, never a
// wedge inside the outcome transaction.
test('w10-cert F2: a superseded policy activation is FAILED, not wedged', t => {
  const h = fixture(t), next = h.clone(h.f.policy('acme'));
  next.version = 2; next.not_before = h.now(); next.expires_at = h.now() + 86400000;
  const r = h.proposed('policy.change', { policy: next }, { action: { type: 'policy.change', target_resource: 'policy-root', purpose: 'Succession' } });
  h.f.simulate(h.p('policy-admin'), next);
  h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'audit-committee' });
  h.approve(r, 3); h.advance(120001);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  // A rival staged deployment sits awaiting its activation window between
  // certification and dispatch — the certificate's precondition is void.
  h.f.store.put('acme', 'policy', 'staged', { policy: h.clone(next), activate_at: h.now() + 3600000, staged_at: h.now() }, h.now());
  const out = h.f.execute(h.p(), cert);
  assert.equal(out.payload.status, 'FAILED');
  assert.equal(out.payload.reason, 'POLICY_STAGED_CONFLICT');
});

// w10-cert F3: the egress charge is idempotent — a re-fired finish path
// bills and touches the disclosure exactly once.
test('w10-cert F3: a re-fired egress charge never double-bills or double-touches', t => {
  const h = fixture(t);
  const { record, certificate } = exportCert(h);
  const certPayload = certificate.payload;
  const raw = { output: [{ id: 'row-1', name: 'Synthetic Ada' }] };
  h.f._recordExportEgress(h.p(), 'acme', record, certPayload, raw, h.now());
  h.f._recordExportEgress(h.p(), 'acme', record, certPayload, raw, h.now());
  const usage = h.f.store.db.prepare("SELECT count(*) AS n FROM usage WHERE tenant='acme' AND request=?").get(certPayload.certificate_id).n;
  assert.equal(usage, 1, 'one certificate bills once');
  const touches = h.f.store.db.prepare("SELECT count(*) AS n FROM data_access WHERE tenant='acme' AND dataset='dataset-1'").get().n;
  assert.equal(touches, 1, 'the disclosure is touched once, not per invocation');
});

// w10-cert F6: compensation may only overwrite the child's own write — a
// resource that moved past the compensated version refuses to revert.
test('w10-cert F6: stale compensation refuses to clobber a later write', t => {
  const h = fixture(t);
  const r = h.proposed('finance.beneficiary.create', { vendor_id: 'vendor-1', bank_account: 'TESTBANK000002', currency: 'EUR' });
  h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  h.f.execute(h.p(), cert); // resource -> v1
  const first = h.f.target.compensate(r.capsule, r.capsule.current_state.material_fields, h.now()); // restores to v2
  assert.equal(first.compensated, true);
  const second = h.f.target.compensate(r.capsule, r.capsule.current_state.material_fields, h.now());
  assert.equal(second.compensated, false);
  assert.equal(second.reason, 'STALE_COMPENSATION');
});

// w10-cert F7+F4: composite children record their parent binding on the
// outcome and on the capsule marker.
test('w10-cert F7: composite child outcomes name their parent certificate', t => {
  const h = fixture(t);
  const certOf = type => { const r = h.proposed(type, { vendor_id: `v-${randomUUID().slice(0, 8)}`, bank_account: `TESTBANK${randomUUID().slice(0, 8).toUpperCase()}`, currency: 'EUR' }); h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
  const c1 = certOf('finance.beneficiary.create'), c2 = certOf('finance.beneficiary.create');
  const composite = h.proposed('action.composite', { children: [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id] }, { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'pair' } });
  h.approve(composite, 2);
  const parentCert = h.f.certificate(h.p(), composite.capsule.capsule_id);
  // The parent binding is an indexed marker written at certification.
  for (const child of [c1, c2]) assert.ok(h.f.store.must('acme', 'capsule', child.record.capsule.capsule_id).composite_parents.includes(composite.capsule.capsule_id));
  assert.equal(h.f.execute(h.p(), parentCert).payload.status, 'VERIFIED');
  for (const child of [c1, c2]) {
    const outcome = h.f.store.must('acme', 'outcome', child.certificate.payload.certificate_id);
    assert.equal(outcome.payload.composite_child_of, parentCert.payload.certificate_id);
  }
});

// w10-cert F8: cancelling a certified capsule marks the certificate row
// CANCELLED too — it must never read as an unspent live authority.
test('w10-cert F8: a cancelled action leaves a CANCELLED certificate row', t => {
  const h = fixture(t);
  const { record, certificate } = exportCert(h);
  h.f.cancel(h.p(), record.capsule.capsule_id);
  const stored = h.f.store.must('acme', 'certificate', certificate.payload.certificate_id);
  assert.equal(stored.status, 'CANCELLED');
  assert.throws(() => h.f.execute(h.p(), certificate), hasCode('INV-409-REPLAY'));
});

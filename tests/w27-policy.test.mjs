import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode, installPolicy, runtimeInput, runtimeRequest } from './helpers.mjs';

// w27-policy auditor findings F1–F5: grant-tuple laundering, jit actions
// catalog, evidence-binding paths, beneficiary liveness, quantity binding.
const JIT_OVR = { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'JIT' } };
const jit = (h, req) => { const r = h.proposed('identity.jit.grant', req, JIT_OVR); h.evidence(r, { kind: 'identity_proof', issuer: 'hris' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' }); h.approve(r, 2); return r; };
const jitMinted = (h, req) => { const r = jit(h, req); h.f.execute(h.p(), h.f.certificate(h.p(), r.capsule.capsule_id)); return r; };

test('w27-policy F1: a service-scoped JIT grant cannot launder dataset rows', t => {
  const h = fixture(t);
  // The classic launder: a grant whose scope tuple is service-only must not
  // extend the subject's dataset reach. Union-merge would have allowed
  // dataset rows + service actions to mix freely; tuple semantics cannot.
  jitMinted(h, { subject_id: 'operator', resources: ['erp-service'], actions: ['service.connect'], destinations: ['erp-service'], columns: [], row_ids: [], ttl_ms: 60000, reason: 'svc', roles: [] });
  assert.throws(() => h.f.runtime.issue(h.p(), runtimeInput({ row_ids: ['row-9'] })), hasCode('INV-403-SCOPE'), 'row outside every grant tuple is denied');
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  assert.equal(h.f.runtime.consume(h.p(), runtimeRequest(cap)).decision, 'ALLOW', 'static scope still serves its own tuple');
});

test('w27-policy F1b: grant fields are indivisible — a row-9 dataset grant does not widen columns', t => {
  const h = fixture(t);
  // A fourth real row outside the static grant's row list.
  const dataset = h.f.target.state('acme', 'dataset-1').material_fields;
  h.f.target.seed('acme', 'dataset-1', { ...dataset, rows: [...dataset.rows, { id: 'row-9', name: 'Synthetic Mab', region: 'US', passport: 'SYNTHETIC-NOT-REAL-9' }] });
  jitMinted(h, { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['region'], row_ids: ['row-9'], ttl_ms: 60000, reason: 'row-9 only', roles: [] });
  // Union semantics would allow name+region on row-9 (name arrives from the
  // static grant, row-9 from the JIT grant). Per-tuple semantics deny it —
  // neither tuple covers the whole selection.
  assert.throws(() => h.f.runtime.issue(h.p(), runtimeInput({ columns: ['region', 'name'], row_ids: ['row-9'] })), hasCode('INV-403-SCOPE'));
  // The approved tuple itself serves.
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ columns: ['region'], row_ids: ['row-9'] }));
  assert.equal(h.f.runtime.consume(h.p(), runtimeRequest(cap)).decision, 'ALLOW');
});

test('w27-policy F2: jit.grant actions outside the runtime vocabulary are denied', t => {
  const h = fixture(t);
  const r = h.proposed('identity.jit.grant', { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read', 'database.drop'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-1'], ttl_ms: 60000, reason: 'bad action', roles: [] }, JIT_OVR);
  h.evidence(r, { kind: 'identity_proof', issuer: 'hris' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' }); h.approve(r, 2);
  assert.equal(h.f.evaluate(h.p(), r.capsule.capsule_id).decision, 'DENY');
});

test('w27-policy F3: evidence binding paths must resolve on a real capsule', t => {
  const h = fixture(t);
  assert.throws(() => installPolicy(h, p => { p.rules['data.export'].evidence_bindings = { dataset_authority: { subject: 'subject_id' } }; }), hasCode('INV-400-SCHEMA'), 'bare subject_id never resolves');
  assert.throws(() => installPolicy(h, p => { p.rules['data.export'].evidence_bindings = { dataset_authority: { dst: 'action.destination' } }; }), hasCode('INV-400-SCHEMA'), 'action.destination never resolves');
  assert.doesNotThrow(() => installPolicy(h, p => { p.rules['data.export'].evidence_bindings = { dataset_authority: { dst: 'destination', who: 'actor.subject_id' } }; }), 'top-level destination resolves');
});

test('w27-policy F4: jit.grant beneficiary must be registered and unrevoked', t => {
  const h = fixture(t);
  const ghost = h.proposed('identity.jit.grant', { subject_id: 'ghost-user', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-1'], ttl_ms: 60000, reason: 'ghost', roles: [] }, JIT_OVR);
  h.evidence(ghost, { kind: 'identity_proof', issuer: 'hris' }); h.evidence(ghost, { kind: 'identity_proof', issuer: 'registry' }); h.approve(ghost, 2);
  assert.equal(h.f.evaluate(h.p(), ghost.capsule.capsule_id).decision, 'DENY', 'unregistered beneficiary denied at admission');
  // A beneficiary quarantined between admission and minting gets no grant —
  // revocation is ledger-authoritative at the minting point.
  const ok = jit(h, { subject_id: 'auditor', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-1'], ttl_ms: 60000, reason: 'for auditor', roles: [] });
  h.f.revoke(h.p('security'), { kind: 'subject', id: 'auditor', reason: 'quarantined between admission and minting' });
  const cert = h.f.certificate(h.p(), ok.capsule.capsule_id);
  assert.throws(() => h.f.execute(h.p(), cert), hasCode('INV-403-SCOPE'), 'revoked beneficiary gets no minted grant');
});

test('w27-policy F5: jit.grant quantity is bound to the granted scope size', t => {
  const h = fixture(t);
  assert.throws(() => h.proposed('identity.jit.grant', { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-1', 'row-2'], ttl_ms: 60000, reason: 'count', roles: [] }, { ...JIT_OVR, quantity: 999999 }), hasCode('INV-400-SCHEMA'), 'quantity ≠ row count is schema-rejected');
});

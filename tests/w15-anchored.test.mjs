// Wave-15 regressions: the w13 store/fixverify audit fixes. Same threat
// model as w12 — a store-level writer who cannot reach the vault signers
// must not be able to mint, launder, un-anchor or wedge security state.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture, hasCode, runtimeInput, runtimeRequest } from './helpers.mjs';
import { digest } from '../src/canonical.mjs';
import { verifySigned } from '../src/crypto.mjs';

const dropAuditTriggers = h => {
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
    h.f.store.db.exec(`DROP TRIGGER ${tr.name}`);
};

// A raw-SQL edit to any audit row is detected on every read surface even
// after the append-only triggers are dropped — the JSON.parse/verify path
// can never serve attacker JSON (w13-store F1).
test('w15: auditPage rejects a tampered audit envelope, including malformed JSON', t => {
  const h = fixture(t);
  h.ready();
  dropAuditTriggers(h);
  const maxSeq = h.f.store.db.prepare('SELECT MAX(seq) s FROM audit WHERE tenant=?').get('acme').s;
  h.f.store.db.prepare('UPDATE audit SET envelope=? WHERE tenant=? AND seq=?').run(JSON.stringify({ payload: { sequence: maxSeq, type: 'FORGED' }, signature: 'forged' }), 'acme', maxSeq);
  assert.throws(() => h.f.store.auditPage('acme', { after: maxSeq - 1, limit: 5 }), hasCode('INV-409-AUDIT-TAMPER'));
  h.f.store.db.prepare('UPDATE audit SET envelope=? WHERE tenant=? AND seq=?').run('{broken', 'acme', maxSeq);
  assert.throws(() => h.f.store.auditPage('acme', { after: maxSeq - 1, limit: 5 }), hasCode('INV-409-AUDIT-TAMPER'));
  assert.throws(() => h.f.store.auditExport('acme'), hasCode('INV-409-AUDIT-TAMPER'));
});

// The index consumes only vault-signed events: a raw INSERT minting a
// self-consistent "signed" row (attacker-computable hash+previous, junk
// signature) wedges the index at verifySigned — the red-team root cause
// on cd4e71b stays dead (w13-store F1).
test('w15: a raw chain INSERT cannot mint a consumed event', t => {
  const h = fixture(t);
  h.ready();
  const last = h.f.store.db.prepare('SELECT seq,hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get('acme');
  const payload = { tenant_id: 'acme', sequence: last.seq + 1, previous: last.hash, type: 'POLICY_ACTIVATED', actor: 'mallory', reference: 'policy', metadata: { policy_digest: 'x', reanchored: true }, time: h.now() };
  const envelope = { payload, protected: { key_id: 'mallory', algorithm: 'Ed25519' }, signature: 'forged' };
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', last.seq + 1, last.hash, digest(payload), JSON.stringify(envelope));
  assert.throws(() => h.f._auditIndex('acme'), e => /^INV-409/.test(e.code ?? ''));
  assert.throws(() => h.proposed(), e => /^INV-409/.test(e.code ?? ''), 'gate fails closed on a poisoned tail');
  assert.throws(() => h.f.store.auditPage('acme', { after: last.seq, limit: 5 }), hasCode('INV-409-AUDIT-TAMPER'), 'the read path does not serve unsigned rows');
});

// A certificate row swapped to another valid envelope cannot launder a
// forged finish — issuance is anchored on the chain AND the payload is
// re-proven byte-for-byte (w13-store F2/L10).
test('w15: a swapped certificate envelope cannot launder a forged finish', t => {
  const h = fixture(t);
  const a = h.ready(), b = h.ready();
  const storedA = h.f.store.must('acme', 'certificate', a.certificate.payload.certificate_id);
  h.f.store.put('acme', 'certificate', a.certificate.payload.certificate_id, { ...storedA, envelope: b.certificate }, h.now());
  assert.throws(() => h.f.execute(h.p(), a.certificate), hasCode('INV-401-CERTIFICATE'));
});

// A planted outcome row without a vault signature dies on integrity, not
// state-ordering — the certify path cannot be walled behind a forgery
// (w13-fixverify L6).
test('w15: a planted outcome row fails integrity on the finish path', t => {
  const h = fixture(t);
  const r = h.ready();
  // A real outcome row IS the signed envelope {payload, protected,
  // signature} — a mis-shaped forgery would die at the wrong branch and
  // never exercise verifySigned (w16-fixverify F8).
  h.f.store.put('acme', 'outcome', r.certificate.payload.certificate_id, { payload: { outcome_id: 'planted', status: 'VERIFIED', certificate_id: r.certificate.payload.certificate_id }, protected: { key_id: 'mallory', algorithm: 'Ed25519' }, signature: 'forged' }, h.now());
  assert.throws(() => h.f.execute(h.p(), r.certificate), hasCode('INV-409-INTEGRITY'));
});

// Capability usage rides the chain — a forged 'usage' row can neither
// mint a replay-denial nor, once deleted, un-deny a real replay
// (w13-store M5).
test('w15: forged and deleted usage rows cannot move the replay/budget ledger', t => {
  const h = fixture(t);
  h.ready();
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  // Forge a usage row — the anchored index is authority, so the forge
  // burns no budget and mints no denial for a real request.
  h.f.store.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?)')
    .run('acme', 'operator', cap.payload.resource, h.now(), 999999, cap.payload.capability_id, 'forged-request');
  const req = runtimeRequest(cap);
  assert.equal(h.f.runtime.consume(h.p(), req).decision, 'ALLOW');
  // A real consume anchors RUNTIME_ALLOWED — deleting every usage row can
  // never replay it.
  // The usage table is append-only too — a file-writer must drop the
  // guard before wiping, and the chain still refuses the replay
  // (w21-store F-6).
  h.f.store.db.exec('DROP TRIGGER no_usage_delete');
  h.f.store.db.prepare('DELETE FROM usage').run();
  assert.throws(() => h.f.runtime.consume(h.p(), req), hasCode('INV-409-REPLAY'));
});

// The decision anchor binds each capsule to its signed POLICY_EVALUATED
// digest — a store-level rewrite of the decision row diverges from what
// the ledger attests (w13-store M1).
test('w15: a rewritten decision diverges from its anchored digest on a certified capsule', t => {
  const h = fixture(t);
  const r = h.ready();
  const cid = r.record.capsule.capsule_id;
  // The certify path anchors the stored decision on the chain — the
  // certify-only flow (no evaluate() call) must also carry an anchor or
  // honest capsules wedge forever (w16-fixverify F5/F8).
  const stored = h.f.store.must('acme', 'capsule', cid);
  const anchored = h.f._auditIndex('acme').decisions.get(cid);
  assert.equal(anchored, digest(stored.decision), 'certificate() anchors the decision it stores');
  // explain narrates the anchored decision — rewriting the stored decision
  // object diverges and is refused.
  h.f.store.put('acme', 'capsule', cid, { ...stored, decision: { ...stored.decision, decision: 'DENY' } }, h.now());
  assert.notEqual(digest(h.f.store.must('acme', 'capsule', cid).decision), anchored);
  assert.throws(() => h.f.advise(h.p(), { operation: 'explain', capsule_id: cid }), hasCode('INV-409-INTEGRITY'));
});

// Grants are merged only under their anchored scope digest — a widened
// grants-table row is silently discarded, never merged (w13-store H1).
test('w15: a scope-widened grants row is dropped, not merged', t => {
  const h = fixture(t);
  const r = h.proposed('identity.jit.grant', { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: [], ttl_ms: 300000, reason: 'Incident', roles: [] }, { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'JIT' } });
  h.evidence(r, { kind: 'identity_proof' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' }); h.approve(r, 2);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  h.f.execute(h.p(), cert);
  const grantId = `jit-${cert.payload.certificate_id}`;
  assert.ok(h.f.grantsFor('acme', 'operator', h.now()).resources.includes('dataset-1'));
  // Widen the live grants row — the anchored scope digest disowns it.
  h.f.target.grant('acme', grantId, { grant_id: grantId, subject_id: 'operator', resources: ['dataset-1', 'vault-secrets'], actions: ['data.read', 'data.export'], destinations: ['customer-vault'], columns: ['id'], row_ids: [], roles: ['security'], expires_at: h.now() + 300000 });
  const live = h.f.grantsFor('acme', 'operator', h.now());
  assert.equal(live.resources.includes('vault-secrets'), false, 'forged scope never merges');
  assert.equal(live.actions.includes('data.export'), false);
  assert.equal(live.roles.includes('security'), false);
  // The legacy grant_digest fallback cannot launder a row either: cite the
  // real issuing capsule but declare a different scope — every row field
  // must equal the anchored request (w16-fixverify F4).
  const reqState = r.capsule.requested_state;
  const evNow = h.now();
  h.f.store.audit('acme', 'JIT_GRANT_ISSUED', 'operator', reqState.subject_id, { grant_id: 'legacy-G1', grant_digest: digest(reqState) }, evNow);
  h.f.target.grant('acme', 'legacy-G1', { grant_id: 'legacy-G1', subject_id: reqState.subject_id, resources: ['vault-secrets'], actions: reqState.actions, destinations: ['attacker-vault'], columns: reqState.columns, row_ids: reqState.row_ids, roles: ['security'], expires_at: evNow + reqState.ttl_ms, issued_at: evNow, issued_by: `action:${r.capsule.capsule_id}` });
  const after = h.f.grantsFor('acme', 'operator', h.now());
  assert.equal(after.resources.includes('vault-secrets'), false, 'legacy fallback demands field equality');
  assert.equal(after.roles.includes('security'), false);
});

// Issuer drift quarantine holds until a SIGNED revalidation — deleting the
// mutable 'issuer-drift' record cannot clear it (w13-store M3).
test('w15: deleting the issuer-drift record cannot clear an anchored quarantine', t => {
  const h = fixture(t);
  const bankId = Object.keys(h.f.tenant('acme').issuers).find(k => h.f.tenant('acme').issuers[k].name === 'bank');
  h.f.store.audit('acme', 'CONNECTOR_DRIFT', 'test', bankId, { drifted: 'manifest' }, h.now());
  h.f.store.remove('acme', 'issuer-drift', bankId); // the row is observability, not authority
  const r = h.proposed();
  assert.throws(() => h.evidence(r, { issuer: 'bank' }), hasCode('INV-403-QUARANTINE'));
  h.f.store.audit('acme', 'CONNECTOR_REVALIDATED', 'test', bankId, { configuration_digest: 'clean' }, h.now());
  h.evidence(r, { issuer: 'bank' });
});

// Containment report exposes anchoring per row: forged rows are labelled
// unanchored and counted, never passed as ledger history (w13-store M7).
test('w15: containmentReport marks forged denial rows unanchored', t => {
  const h = fixture(t);
  h.ready();
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  // Real anchored denial: resource outside the capability's signed scope.
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap, { resource: 'off-grant' })), hasCode('INV-403-SCOPE'));
  // Forged containment row — observability only, flagged unanchored.
  h.f.store.put('acme', 'containment', `deny:${randomUUID()}`, { contained_at: h.now(), subject_id: 'operator', device_id: null, capability_id: cap.payload.capability_id, resource: 'x', destination: null, action: null, code: 'INV-999-FORGED', request_id: 'forged-request', dropped_requests: 1 }, h.now());
  const report = h.f.containmentReport(h.p('security'));
  const forged = report.sequence.find(x => x.request_id === 'forged-request');
  assert.equal(forged.anchored, false, 'forged row is labelled unanchored');
  assert.ok(report.unanchored_rows >= 1);
  const real = report.sequence.find(x => x.code === 'INV-403-SCOPE');
  assert.equal(real.anchored, true, 'real denial is chain-anchored');
  // Replaying a real (request_id, code) pair with different actor/capability
  // is still unanchored — the pair alone is not the anchor (w16-fixverify F9).
  h.f.store.put('acme', 'containment', `deny:${randomUUID()}`, { contained_at: h.now(), subject_id: 'mallory', device_id: null, capability_id: 'cap-other', resource: 'x', destination: null, action: null, code: real.code, request_id: real.request_id, dropped_requests: 1 }, h.now());
  const report2 = h.f.containmentReport(h.p('security'));
  const replayed = report2.sequence.filter(x => x.request_id === real.request_id && x.subject_id === 'mallory');
  assert.equal(replayed.length, 1);
  assert.equal(replayed[0].anchored, false, 'pair-replayed row is unanchored');
});

// Real revocations anchor their record digest — a payload edit flips the
// row to 'identity-only' in the incident report (w13-fixverify L7).
test('w15: revocations() reports anchored state and flags a tampered record', t => {
  const h = fixture(t);
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'lost' });
  const pick = list => list.items.find(i => i.kind === 'device' && i.id === 'operator-device');
  assert.equal(pick(h.f.revocations(h.p('security'))).anchored, true);
  const row = h.f.store.get('acme', 'revocation', 'device:operator-device');
  h.f.store.put('acme', 'revocation', 'device:operator-device', { ...row, reason: 'whitewashed' }, h.now());
  assert.equal(pick(h.f.revocations(h.p('security'))).anchored, 'identity-only', 'edited record loses its anchor match');
  assert.equal(h.f.revoked('acme', 'device', 'operator-device'), true, 'revocation still stands regardless');
});

// The policy anchor cannot be laundered: reanchorPolicy refuses while the
// anchor already matches, and a forged active policy row can only be
// RESTORED from the anchored copy — signing a fresh anchor over the
// observed (attacker-chosen) state would launder it (w13-store H3,
// w17-redteam A1).
test('w15: reanchorPolicy refuses a healthy anchor and restores a real divergence', t => {
  const h = fixture(t);
  assert.throws(() => h.f.reanchorPolicy(h.p('security')), hasCode('INV-409-STATE'));
  const active = h.f.store.must('acme', 'policy', 'active');
  h.f.store.put('acme', 'policy', 'active', { ...active, version: 'forged-v9' }, h.now());
  assert.throws(() => h.f.policy('acme'), hasCode('INV-409-INTEGRITY'));
  const re = h.f.reanchorPolicy(h.p('security'));
  assert.equal(re.reanchored, true);
  assert.equal(h.f.policy('acme').version, active.version, 'the anchored constitution is restored — forged content never signed');
});

// auditProof verifies the leaf's live signature — proofs name the leaf
// digest that a reader re-checks under the audit anchor (w13-store L5).
test('w15: auditProof serves a re-verified leaf', t => {
  const h = fixture(t);
  h.ready();
  const p = h.f.auditProof(h.p('security'), 1);
  assert.equal(p.leaf_signature_verified, true);
  const leaf = h.f.store.auditPage('acme', { after: 0, limit: 1 }).entries[0];
  assert.ok(verifySigned(leaf.envelope, h.f.auditPublicKeys('acme'), 'audit'));
  assert.equal(digest(leaf.envelope.payload), p.leaf_hash);
});

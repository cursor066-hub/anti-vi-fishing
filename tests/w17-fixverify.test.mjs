// Wave-17 regressions: the w16 fix-verification audit findings. Same
// threat model as w12/w15 — a store-level writer who cannot reach the
// vault signers must not rewind bindings, un-anchor memberships, launder
// grants, mint a signing window, or truncate the ledger that attests
// their own revocation.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture, hasCode, runtimeInput, runtimeRequest } from './helpers.mjs';
import { digest } from '../src/canonical.mjs';
import { Fabric } from '../src/fabric.mjs';

const JIT_REQ = { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-1'], ttl_ms: 60000, reason: 'Incident', roles: [] };
const JIT_OVR = { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'JIT' } };
const jitChild = h => { const r = h.proposed('identity.jit.grant', JIT_REQ, JIT_OVR); h.evidence(r, { kind: 'identity_proof', issuer: 'hris' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const beneChild = (h, n) => { const r = h.proposed('finance.beneficiary.create', { vendor_id: `vendor-${n}`, bank_account: `TESTBANK00000${n}`, currency: 'EUR' }); h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const composite = (h, children) => { const r = h.proposed('action.composite', { children }, { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'Batch' } }); h.approve(r, 2); return r; };

// F2: the anchored membership map is enumerated, not the capsule table —
// deleting the parent row cannot unbind a certified composite child.
test('w17 F2: deleting the parent capsule row cannot unbind a certified composite child', t => {
  const h = fixture(t);
  const c1 = jitChild(h), c2 = beneChild(h, 2);
  const parent = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const parentCert = h.f.certificate(h.p(), parent.capsule.capsule_id);
  assert.throws(() => h.f.execute(h.p(), c1.certificate), hasCode('INV-409-STATE'));
  h.f.store.remove('acme', 'capsule', parent.capsule.capsule_id);
  assert.throws(() => h.f.execute(h.p(), c1.certificate), hasCode('INV-409-STATE'), 'anchored parentage survives parent-row deletion');
  assert.throws(() => h.f.execute(h.p(), c2.certificate), hasCode('INV-409-STATE'));
  // The deleted parent cannot dispatch either — the binding dead-mans, it
  // never silently unbinds.
  assert.throws(() => h.f.execute(h.p(), parentCert), hasCode('INV-404-NOT-FOUND'));
});

// F3: key-rotation RECORDS are hints, never authority — deleting the
// newest record cannot rewind the binding; the newest ANCHORED KEY_ROTATED
// event decides, and a re-pointed snapshot is written only when the rest
// of the config is untouched.
test('w17 F3: deleting the newest rotation record cannot rewind the anchored binding', t => {
  const h = fixture(t);
  const keyA = h.f.keys('acme').audit.key_id;
  // Two chain-attested audit-class successions A→B→C (vault-generated
  // pending keys, anchored events — the records are the mutable mirrors).
  const prepB = h.f.prepareRotation(h.p('security'), 'audit');
  const prepC = h.f.prepareRotation(h.p('security'), 'audit');
  h.f.store.put('acme', 'key-rotation', 'rot-B', { new_key_id: prepB.key_id, new_public_key: prepB.public_key, key_class: 'audit', previous_key_id: keyA, revoke_old: false, rotated_at: h.now() }, h.now());
  h.f.store.audit('acme', 'KEY_ROTATED', 'security', prepB.key_id, { key_class: 'audit', previous_key_id: keyA, ceremony_id: 'cer-b', revoke_old: false }, h.now());
  h.f.store.put('acme', 'key-rotation', 'rot-C', { new_key_id: prepC.key_id, new_public_key: prepC.public_key, key_class: 'audit', previous_key_id: prepB.key_id, revoke_old: false, rotated_at: h.now() }, h.now());
  h.f.store.audit('acme', 'KEY_ROTATED', 'security', prepC.key_id, { key_class: 'audit', previous_key_id: prepB.key_id, ceremony_id: 'cer-c', revoke_old: false }, h.now());
  // The rewind attack: delete the newest record AND smuggle a config
  // change past the snapshot the re-point would write.
  h.f.store.remove('acme', 'key-rotation', 'rot-C');
  const cfg = h.clone(h.setup.config);
  cfg.tenants.acme.auth['rogue-token'] = { subject_id: 'rogue', roles: ['operator'] };
  h.f.persistVault(); h.close();
  const g = new Fabric(cfg, h.directory, () => h.now());
  t.after(() => { try { g.close(); } catch { /* fixture teardown may have closed it */ } });
  // Selection came from the chain: the binding lands on C — the newest
  // anchored rotation — never on the rewound record set.
  assert.equal(g.keys('acme').audit.key_id, prepC.key_id, 'newest anchored rotation wins');
  // The rogue auth token kept the re-point's snapshot from minting:
  // drift is flagged, not laundered.
  assert.equal(g._configDrift.has('acme') || g.store.get('acme', 'config-flag', 'drift')?.drift, true, 'auth tamper is drift, not baseline');
  // And the index was never fed a dead-key row.
  assert.doesNotThrow(() => g._auditIndex('acme'));
});

// F3-window: sealAuditChain enforces the signing window while scanning —
// a dead-key-signed row is cut even though it verifies, and the seal
// itself attests under the chain's live successor.
test('w17 F3: sealAuditChain cuts a dead-key row and attests under the live successor', t => {
  const h = fixture(t);
  const keyA = h.f.keys('acme').audit.key_id;
  const prepB = h.f.prepareRotation(h.p('security'), 'audit');
  h.f.store.audit('acme', 'KEY_ROTATED', 'security', prepB.key_id, { key_class: 'audit', previous_key_id: keyA, ceremony_id: 'cer-b', revoke_old: false }, h.now());
  // A tail row signed under A AFTER the rotation killed it — valid
  // signature, dead key. This is the wedge scenario.
  const last = h.f.store.db.prepare('SELECT seq,hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get('acme');
  const payload = { tenant_id: 'acme', sequence: last.seq + 1, previous: last.hash, type: 'AUDIT_ACCESSED', actor: 'mallory', reference: 'x', metadata: {}, time: h.now() };
  const env = h.f.signAudit('acme', payload, 'audit', keyA);
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', last.seq + 1, last.hash, digest(env.payload), JSON.stringify(env));
  assert.throws(() => h.f._auditIndex('acme'), e => /^INV-409/.test(e.code ?? ''), 'dead-key row wedges the index');
  const sealed = h.f.sealAuditChain(h.p('security'));
  assert.equal(sealed.sealed, true, 'the seal sees the dead-key row as poison');
  // The seal itself signed under the anchored successor — the rebuilt
  // index consumes the seal row without choking.
  const sealRow = h.f.store.auditPage('acme', { after: last.seq, limit: 5 }).entries.at(-1);
  assert.equal(sealRow.envelope.protected.key_id, prepB.key_id, 'seal attests under the anchored successor');
  assert.doesNotThrow(() => h.f._auditIndex('acme'));
  assert.equal(h.f.keys('acme').audit.key_id, prepB.key_id, 'binding repointed to the chain-attested key');
  assert.ok(h.f.signAudit('acme', { x: 1 }, 'audit').signature, 'gate signs again');
});

// F6: reanchorPolicy bootstraps a ledger whose anchor set is empty —
// policy() fails closed until security signs the first anchor.
test('w17 F6: reanchorPolicy bootstraps the first anchor; policy() fails closed meanwhile', t => {
  const h = fixture(t);
  // Simulate the pre-upgrade anchorless ledger: the cached index's anchor
  // set emptied — policy() must not vacuously trust any stored row.
  const idx = h.f._auditIndex('acme');
  idx.policyAnchors = [];
  assert.throws(() => h.f.policy('acme'), hasCode('INV-409-INTEGRITY'), 'empty anchor set fails closed');
  const re = h.f.reanchorPolicy(h.p('security'));
  assert.equal(re.reanchored, true, 'bootstrap anchor is allowed when none exists');
  // The signed anchor landed: the index folds it and the row verifies.
  const anchored = [...h.f._auditIndex('acme').policyAnchors].reverse().find(a => !a.staged);
  assert.equal(anchored.digest, digest(h.f.store.must('acme', 'policy', 'active')));
  assert.doesNotThrow(() => h.f.policy('acme'));
});

// F4/F7: the legacy grant_digest fallback demands full field equality —
// and an honestly shaped legacy grant replays onto a wiped dataplane.
test('w17 F7: a legacy grant_digest-anchored grant replays after a dataplane wipe', t => {
  const h = fixture(t);
  const r = h.proposed('identity.jit.grant', { subject_id: 'operator', resources: ['dataset-legacy'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: [], ttl_ms: 300000, reason: 'legacy', roles: [] }, JIT_OVR);
  const req = r.capsule.requested_state, evNow = h.now();
  // A legacy-style anchor: grant_digest only — no scope_digest — the
  // pre-scope-digest ledger form the fallback exists for.
  h.f.store.audit('acme', 'JIT_GRANT_ISSUED', 'operator', req.subject_id, { grant_id: 'legacy-G1', grant_digest: digest(req), expires_at: evNow + req.ttl_ms }, evNow);
  const grant = { grant_id: 'legacy-G1', subject_id: req.subject_id, resources: req.resources, actions: req.actions ?? [], destinations: req.destinations, columns: req.columns, row_ids: req.row_ids, roles: req.roles ?? [], expires_at: evNow + req.ttl_ms, issued_at: evNow, issued_by: `action:${r.capsule.capsule_id}`, revoked: false };
  h.f.store.put('acme', 'jit-grant', 'legacy-G1', { grant }, evNow);
  h.f.target.grant('acme', 'legacy-G1', grant);
  assert.ok(h.f.grantsFor('acme', 'operator', h.now()).resources.includes('dataset-legacy'), 'honest legacy grant merges');
  // Wipe the dataplane mirror — reconcile replays it from the anchor.
  h.f.target.db.prepare('DELETE FROM grants').run();
  h.reconfigure(() => {});
  assert.ok(h.f.grantsFor('acme', 'operator', h.now()).resources.includes('dataset-legacy'), 'anchor replays the legacy grant');
  // A row that flips a single field dies even under the fallback.
  h.f.target.grant('acme', 'legacy-G1', { ...grant, roles: ['security'] });
  assert.equal(h.f.grantsFor('acme', 'operator', h.now()).roles.includes('security'), false, 'field-mutated row stays dropped');
});

// F10: a principal whose own revocation is already on the consumed prefix
// cannot seal the chain that attests it.
test('w17 F10: a revoked security identity cannot seal the audit chain', t => {
  const h = fixture(t);
  h.ready();
  h.f.revoke(h.p('security'), { kind: 'subject', id: 'security', reason: 'offboarded' });
  // Poison the tail so a seal is genuinely needed.
  const last = h.f.store.db.prepare('SELECT seq,hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get('acme');
  const payload = { tenant_id: 'acme', sequence: last.seq + 1, previous: last.hash, type: 'FORGED', actor: 'mallory', reference: 'x', metadata: {}, time: h.now() };
  const env = { payload, protected: { key_id: 'mallory', algorithm: 'Ed25519' }, signature: 'forged' };
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', last.seq + 1, last.hash, digest(payload), JSON.stringify(env));
  assert.throws(() => h.f.sealAuditChain(h.p('security')), hasCode('INV-403-QUARANTINE'));
});

// F11: auditExport runs the full per-row pass — an attacker-consistent
// row (right hash, right previous) with a forged signature still cannot
// fold into a signed checkpoint.
test('w17 F11: auditExport refuses a self-consistent forged-signature row', t => {
  const h = fixture(t);
  h.ready();
  const last = h.f.store.db.prepare('SELECT seq,hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get('acme');
  const payload = { tenant_id: 'acme', sequence: last.seq + 1, previous: last.hash, type: 'AUDIT_ACCESSED', actor: 'mallory', reference: 'export', metadata: {}, time: h.now() };
  const env = { payload, protected: { key_id: 'mallory', algorithm: 'Ed25519' }, signature: 'forged' };
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', last.seq + 1, last.hash, digest(payload), JSON.stringify(env));
  assert.throws(() => h.f.store.auditExport('acme'), hasCode('INV-409-AUDIT-TAMPER'));
});

// F13: rotation RECORDS steer signing attribution only when the chain
// corroborates the succession — a forged record cannot mint a
// recovery_signing attribution under a pending key.
test('w17 F13: a forged key-rotation record cannot steer signing attribution', t => {
  const h = fixture(t);
  const configured = h.f.keys('acme').audit.key_id;
  const prep = h.f.prepareRotation(h.p('security'), 'audit'); // a real pending vault key
  h.f.store.put('acme', 'key-rotation', 'forged-rot', { new_key_id: prep.key_id, new_public_key: prep.public_key, key_class: 'audit', previous_key_id: configured, revoke_old: false, rotated_at: h.now() }, h.now());
  h.ready(); // every audit row must still attest under the configured key
  const entries = h.f.store.auditPage('acme', { after: 0, limit: 1000 }).entries;
  const last = entries.at(-1);
  assert.equal(last.envelope.protected.key_id, configured, 'no anchor, no steering');
  assert.equal(last.envelope.payload.recovery_signing, undefined, 'no recovery attribution without an anchored rotation');
});

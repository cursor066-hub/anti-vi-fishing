// Wave-17 regressions: the w16 fix-verification audit findings. Same
// threat model as w12/w15 — a store-level writer who cannot reach the
// vault signers must not rewind bindings, un-anchor memberships, launder
// grants, mint a signing window, or truncate the ledger that attests
// their own revocation.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture, hasCode, runtimeInput, runtimeRequest, designateSuccessor } from './helpers.mjs';
import { digest } from '../src/canonical.mjs';
import { Fabric } from '../src/fabric.mjs';
import { signAcknowledgement } from '../src/ceremony.mjs';

const CUSTODIANS = ['custodian-1', 'custodian-2', 'custodian-3'];

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
  // never silently unbinds (an anchored-proposed capsule gone from the
  // store is integrity evidence, w29-lifecycle F5).
  assert.throws(() => h.f.execute(h.p(), parentCert), hasCode('INV-409-INTEGRITY'));
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
  // signature, dead key. This is the wedge scenario. signAudit refuses dead
  // keys (w39 F4), so mint at the vault primitive — the compromised-key path.
  const last = h.f.store.db.prepare('SELECT seq,hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get('acme');
  const payload = { tenant_id: 'acme', sequence: last.seq + 1, previous: last.hash, type: 'AUDIT_ACCESSED', actor: 'mallory', reference: 'x', metadata: {}, time: h.now() };
  const env = h.f.vault.envelope(keyA, 'audit', payload, { tenant_id: 'acme' });
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

// ---------------------------------------------------------------------------
// w17-fixverify wave-2: quorum anchoring, seal repair, drift baseline, and
// corrupt-row tolerance.

// H1: the mutable ceremony row's ack list is a cache — a store-planted ack
// with a forged signature must not mint custodian quorum, and the
// reservation-time key.rotate gate must refuse it.
test('w17 H1: a store-planted forged acknowledgement cannot mint custodian quorum', t => {
  const h = fixture(t);
  const pending = h.f.prepareRotation(h.p('security'), 'audit');
  const c = h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-forged', purpose: 'key.rotate', threshold: 2, custodians: CUSTODIANS, valid_until: h.now() + 3600000, min_delay_ms: 120000, rotation: { key_class: 'audit', new_key_id: pending.key_id } });
  h.f.acknowledgeCeremony(h.p('custodian-1'), signAcknowledgement(c, 'custodian-1', h.setup.custodianKeys.acme['custodian-1'], h.now()));
  // The plant: a real-looking envelope bound to this ceremony but with a
  // garbage signature — the old code counted it.
  const forged = signAcknowledgement(c, 'custodian-2', h.setup.custodianKeys.acme['custodian-2'], h.now());
  const row = h.f.store.must('acme', 'ceremony', 'cer-forged');
  row.acknowledgements.push({ ...forged, signature: 'AAAA' });
  h.f.store.put('acme', 'ceremony', 'cer-forged', row, h.now());
  assert.equal(h.f.custodianQuorum('acme', h.f.store.must('acme', 'ceremony', 'cer-forged')).live, 1, 'forged signature never counts');
  const r = h.proposed('key.rotate', { key_class: 'audit', new_key_id: pending.key_id, new_public_key: pending.public_key, ceremony_id: 'cer-forged', revoke_old: false }, { action: { type: 'key.rotate', target_resource: 'key-registry', purpose: 'Rotation' } });
  h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'audit-committee' }); h.approve(r, 3); h.advance(60001);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  assert.throws(() => h.f.execute(h.p(), cert), hasCode('INV-409-STATE'), 'quorum gate refuses the planted quorum');
});

// H1b: even a VALIDLY-signed envelope cannot mint quorum when the chain never
// recorded that custodian's acknowledgement — the ledger is the authority,
// not the signature bytes alone.
test('w17 H1b: a validly-signed ack planted without its chain event cannot mint quorum', t => {
  const h = fixture(t);
  const c = h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-planted', purpose: 'key.rotate', threshold: 2, custodians: CUSTODIANS, valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  h.f.acknowledgeCeremony(h.p('custodian-1'), signAcknowledgement(c, 'custodian-1', h.setup.custodianKeys.acme['custodian-1'], h.now()));
  const row = h.f.store.must('acme', 'ceremony', 'cer-planted');
  row.acknowledgements.push(signAcknowledgement(c, 'custodian-2', h.setup.custodianKeys.acme['custodian-2'], h.now()));
  h.f.store.put('acme', 'ceremony', 'cer-planted', row, h.now());
  assert.equal(h.f.custodianQuorum('acme', h.f.store.must('acme', 'ceremony', 'cer-planted')).live, 1, 'no chain event, no consent');
});

// Seal-scan parity: a row that verifies but violates the fold's future-time
// bound is signed poison the seal must cut — before the fix it reported
// "already verifies" while the index stayed wedged.
test('w17 M2: sealAuditChain cuts a signed future-time poison row', t => {
  const h = fixture(t);
  const keyA = h.f.keys('acme').audit.key_id;
  const last = h.f.store.db.prepare('SELECT seq,hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get('acme');
  const payload = { tenant_id: 'acme', sequence: last.seq + 1, previous: last.hash, type: 'AUDIT_ACCESSED', actor: 'mallory', reference: 'x', metadata: {}, time: h.now() + 3600000 };
  const env = h.f.signAudit('acme', payload, 'audit', keyA);
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', last.seq + 1, last.hash, digest(env.payload), JSON.stringify(env));
  assert.throws(() => h.f._auditIndex('acme'), e => /^INV-409/.test(e.code ?? ''), 'future-time row wedges the index');
  const sealed = h.f.sealAuditChain(h.p('security'));
  assert.equal(sealed.sealed, true, 'the seal sees the bound violation as poison');
  assert.doesNotThrow(() => h.f._auditIndex('acme'));
});

// Revoke-without-rotation fallback: when the configured audit key is killed
// by revocation with no KEY_ROTATED succession, the seal repoints onto the
// live pending tenant-owned successor instead of bricking at INV-503.
test('w17 M3: seal survives an audit key revoked without a rotation succession', t => {
  const h = fixture(t);
  const keyA = h.f.keys('acme').audit.key_id;
  const pending = designateSuccessor(h, 'audit'); // revoke guard demands a quorum-designated successor
  h.f.revoke(h.p('security'), { kind: 'key', id: keyA, reason: 'compromised' });
  const last = h.f.store.db.prepare('SELECT seq,hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get('acme');
  const payload = { tenant_id: 'acme', sequence: last.seq + 1, previous: last.hash, type: 'FORGED', actor: 'mallory', reference: 'x', metadata: {}, time: h.now() };
  const env = { payload, protected: { key_id: 'mallory', algorithm: 'Ed25519' }, signature: 'forged' };
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', last.seq + 1, last.hash, digest(payload), JSON.stringify(env));
  const sealed = h.f.sealAuditChain(h.p('security'));
  assert.equal(sealed.sealed, true, 'seal succeeds via the pending fallback');
  const sealRow = h.f.store.auditPage('acme', { after: last.seq, limit: 5 }).entries.at(-1);
  assert.equal(sealRow.envelope.protected.key_id, pending.key_id, 'seal attests under the pending successor');
  assert.equal(h.f.keys('acme').audit.key_id, pending.key_id);
  assert.doesNotThrow(() => h.f._auditIndex('acme'));
});

// Drift baseline is the FILE view: a chain-attested repoint (rotation or
// seal) must not drift-quarantine the tenant — not now, not on the next
// boot, and configDriftStatus agrees the declared config is unchanged.
test('w17 M1: a chain-attested repoint is not configuration drift', t => {
  const h = fixture(t);
  const keyA = h.f.keys('acme').audit.key_id;
  const prepB = h.f.prepareRotation(h.p('security'), 'audit');
  h.f.store.audit('acme', 'KEY_ROTATED', 'security', prepB.key_id, { key_class: 'audit', previous_key_id: keyA, ceremony_id: 'cer-b', revoke_old: false }, h.now());
  const last = h.f.store.db.prepare('SELECT seq,hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get('acme');
  const payload = { tenant_id: 'acme', sequence: last.seq + 1, previous: last.hash, type: 'FORGED', actor: 'mallory', reference: 'x', metadata: {}, time: h.now() };
  const env = { payload, protected: { key_id: 'mallory', algorithm: 'Ed25519' }, signature: 'forged' };
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', last.seq + 1, last.hash, digest(payload), JSON.stringify(env));
  assert.equal(h.f.sealAuditChain(h.p('security')).sealed, true);
  assert.equal(h.f.keys('acme').audit.key_id, prepB.key_id, 'repoint landed in memory');
  assert.equal(h.f._auditIndex('acme').tenantDrifted, false, 'repoint is ledger business, not drift');
  assert.equal(h.f.configDriftStatus(h.p('security')).drifted, false);
  h.reconfigure(() => {});
  assert.equal(h.f._configDrift.has('acme'), false, 'no boot-time drift either');
  assert.equal(h.f._auditIndex('acme').tenantDrifted, false);
});

// M4: the containment report's revocation anchor flag recomputes the keyed
// MAC honestly — an injected or field-flipped revocation row degrades to
// 'identity-only', a real one reports anchored.
test('w17 M4: containmentReport anchors real revocations and degrades tampered rows', t => {
  const h = fixture(t);
  h.ready();
  h.f.revoke(h.p('security'), { kind: 'subject', id: 'custodian-5', reason: 'offboarded' });
  const report = h.f.containmentReport(h.p('security'));
  const entry = report.sequence.find(q => q.kind === 'revocation' && q.revoked === 'subject:custodian-5');
  assert.equal(entry.anchored, true, 'real revocation is chain-anchored');
  // A tampered row — same id, flipped field — degrades honestly.
  const row = h.f.store.must('acme', 'revocation', 'subject:custodian-5');
  h.f.store.put('acme', 'revocation', 'subject:custodian-5', { ...row, reason: 'rewritten' }, h.now());
  const report2 = h.f.containmentReport(h.p('security'));
  assert.equal(report2.sequence.find(q => q.kind === 'revocation' && q.revoked === 'subject:custodian-5').anchored, 'identity-only', 'field-tampered row loses its anchor');
});

// M5: corrupt encrypted grant rows are residue, not a wedge — a single
// undecryptable jit-grant row can only hide a grant, never forge one.
test('w17 M5: a corrupt grant row cannot wedge authorize or cold-start', t => {
  const h = fixture(t);
  h.ready();
  // Poison the dataplane grant table with undecryptable ciphertext.
  h.f.target.db.prepare('INSERT INTO grants VALUES(?,?,?)').run('acme', 'corrupt-G', Buffer.from('garbage'));
  assert.doesNotThrow(() => h.f.grantsFor('acme', 'operator', h.now()), 'authorize path tolerates the corrupt row');
  assert.doesNotThrow(() => h.ready());
  // Same tolerance on the ledger-side jit-grant store at cold-open.
  h.f.store.put('acme', 'jit-grant', 'corrupt-S', { grant: { grant_id: 'corrupt-S' } }, h.now());
  h.f.store.db.prepare("UPDATE records SET value=? WHERE tenant='acme' AND kind='jit-grant' AND id='corrupt-S'").run(Buffer.from('garbage'));
  assert.doesNotThrow(() => h.reconfigure(() => {}), 'cold-start tolerates a corrupt jit-grant row');
});

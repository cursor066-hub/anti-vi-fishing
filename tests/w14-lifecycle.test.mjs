// Regression tests for the w14 batch: provenance F2/F10/F11 and
// lifecycle F4/F5 — evidence binding at evaluation, audit-head
// replacement, rollback phantoms, conflict supersession, pre-tx
// quarantine containment.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { digest, canonical } from '../src/canonical.mjs';
import { InvariantError } from '../src/errors.mjs';
import { signed } from '../src/crypto.mjs';
import { Store } from '../src/store.mjs';
import { fixture, hasCode as hc, designateSuccessor } from './helpers.mjs';

const hasCode = code => e => e.code === code;

// F2: a real signed envelope transplanted under this action's
// chain-attested evidence id dies on the capsule_digest binding at
// evaluation — attach-time checks alone cannot stop the in-place rewrite.
test('w14 F2: transplanted evidence cannot answer for a sibling capsule', t => {
  const h = fixture(t);
  const a = h.proposed(), b = h.proposed();
  h.evidence(a); h.evidence(b);
  const [aId] = h.f.store.must('acme', 'capsule', a.capsule.capsule_id).evidence;
  const [bId] = h.f.store.must('acme', 'capsule', b.capsule.capsule_id).evidence;
  const aRow = h.f.store.must('acme', 'evidence', aId);
  // Rewrite B's attached row in place to carry A's signed envelope.
  h.f.store.put('acme', 'evidence', bId, aRow, h.now());
  h.f.invalidateAuditIndex();
  assert.throws(() => h.f.evaluate(h.p(), b.capsule.capsule_id), hasCode('INV-409-INTEGRITY'));
});

// F10: a same-seq tail replacement cannot resync under the cached
// MAX(seq) watermark — the index re-pins the head hash on every build.
test('w14 F10: a same-seq head replacement wedges the index', t => {
  const h = fixture(t);
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'hostile device' });
  h.f._auditIndex('acme'); // consume the head
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all()) h.f.store.db.exec(`DROP TRIGGER ${tr.name}`);
  const head = h.f.store.db.prepare("SELECT seq,envelope FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get();
  const fake = JSON.parse(head.envelope);
  fake.payload.type = 'NOTHING_HAPPENED';
  fake.payload.metadata = { note: 'replaced under the same seq' };
  // Recompute the stored-row binding exactly as the insider would — the
  // row must survive auditPage's own checks but diverge from the index's
  // pinned head hash.
  const newHash = digest(fake.payload);
  h.f.store.db.prepare('DELETE FROM audit WHERE tenant=? AND seq=?').run('acme', head.seq);
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', head.seq, fake.payload.previous, newHash, JSON.stringify(fake));
  assert.throws(() => h.f._auditIndex('acme'), e => /^INV-409-(AUDIT-TAMPER|INTEGRITY)$/.test(e.code));
});

// F11: projections absorbed inside a rolled-back transaction must not
// survive as phantom anchors — the index cache is invalidated on rollback.
test('w14 F11: a rolled-back write leaves no phantom anchor', t => {
  const h = fixture(t);
  assert.throws(() => h.f.transaction(h.p(), now => {
    h.f.store.audit('acme', 'AUTHORITY_REVOKED', 'operator', 'device:phantom', { reason: 'phantom' }, now);
    h.f._auditIndex('acme'); // absorb inside the doomed tx
    throw new InvariantError('INV-409-STATE', 'boom', 409);
  }), e => e.code === 'INV-409-STATE');
  assert.equal(h.f._auditIndex('acme').revoked.has('device:phantom'), false, 'phantom revocation survived the rollback');
});

// F4: the issuer's own later supports envelope retracts its earlier
// conflict — a signed veto is sticky only against a different issuer.
test('w14 F4: a same-issuer supports envelope resolves its earlier conflict', t => {
  const h = fixture(t);
  const r = h.proposed();
  h.evidence(r, { claim: 'conflict' });
  assert.ok(h.f.evaluate(h.p(), r.capsule.capsule_id).reasons.some(x => x.code === 'EVIDENCE_CONFLICT'));
  // Same issuer+kind signs a fresh supports envelope — a retraction —
  // then the second independent domain and a quorum over the NEW graph.
  h.evidence(r);
  h.evidence(r, { issuer: 'registry' });
  h.approve(r, 2);
  const d = h.f.evaluate(h.p(), r.capsule.capsule_id);
  assert.ok(!d.reasons.some(x => x.code === 'EVIDENCE_CONFLICT'), `conflict still counted: ${d.explanation}`);
  assert.equal(d.decision, 'ALLOW', `still wedged: ${d.explanation}`);
});

// F5: a pre-transaction quarantine denial on propose() writes the
// containment row, same as an in-transaction one.
test('w14 F5: a quarantined propose lands in the containment ledger', t => {
  const h = fixture(t);
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'hostile device' });
  const before = h.f.store.db.prepare("SELECT COUNT(*) c FROM records WHERE tenant='acme' AND kind='containment'").get().c;
  assert.throws(() => h.proposed(), hasCode('INV-403-QUARANTINE'));
  const after = h.f.store.db.prepare("SELECT COUNT(*) c FROM records WHERE tenant='acme' AND kind='containment'").get().c;
  assert.ok(after > before, 'quarantined proposal left no containment row');
});

// ---- w14b: w13-supply + w13-timing residual batch ----

// W13-01: a revoked audit key cannot mint entries appended after its
// on-chain death — the signing window binds each key to its authority span.
test('w14 W13-01: a revoked audit key cannot sign post-revocation rows', t => {
  const h = fixture(t);
  const auditKey = h.setup.config.tenants.acme.keys.audit;
  // The revoke guard needs a pending successor — minted the sanctioned
  // way: chain-anchored by ROTATION_PREPARED so the vault entry is
  // provably this tenant's (w17 D1 — a bare vault.generate is
  // indistinguishable from a relabeled foreign key).
  designateSuccessor(h, 'audit');
  h.f.revoke(h.p('security'), { kind: 'key', id: auditKey.key_id, reason: 'leaked' });
  h.f._auditIndex('acme'); // consume the revocation
  // Forge a self-consistent append signed by the DEAD key.
  const head = h.f.store.db.prepare("SELECT seq,hash FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get();
  const payload = { tenant_id: 'acme', sequence: head.seq + 1, previous: head.hash, type: 'AUTHORITY_REVOKED', actor: 'mallory', reference: 'subject:operator', metadata: { reason: 'forged by dead key' }, time: h.now() };
  const envelope = signed(payload, { key_id: auditKey.key_id, private_key: auditKey.private_key }, 'audit');
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', head.seq + 1, head.hash, digest(payload), canonical(envelope));
  assert.throws(() => h.f._auditIndex('acme'), hasCode('INV-409-INTEGRITY'));
});

// W13-01 recovery edge: rows legitimately signed by the pending successor
// AFTER the revocation still verify — the window closes only on the dead key.
test('w14 W13-01b: recovery-signed rows pass the signing window', t => {
  const h = fixture(t);
  const auditKey = h.setup.config.tenants.acme.keys.audit;
  designateSuccessor(h, 'audit');
  h.f.revoke(h.p('security'), { kind: 'key', id: auditKey.key_id, reason: 'leaked' });
  // Recovery signing under the pending successor — post-revocation rows
  // must still verify and be consumed.
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'post-revocation work' });
  assert.equal(h.f.revoked('acme', 'device', 'operator-device'), true);
});

// W12-02 amplifier: the auth surface must read #tenants, never the
// writable config.tenants mirror — a mirror-planted token cannot auth.
test('w14 W12-02: tenantMap is immune to config-mirror writes', t => {
  const h = fixture(t);
  h.f.config.tenants.acme = { ...h.f.config.tenants.acme, auth: { deadbeef: { subject_id: 'mallory', expires_at: h.now() + 60000 } } };
  assert.equal(h.f.tenantMap().acme.auth.deadbeef, undefined, 'mirror-planted token visible to the auth path');
});

// NEW-MED-1: a poisoned tail can be sealed — the wedge lifts, and the
// removal itself lands on the chain as a signed AUDIT_SEALED event.
test('w14 NEW-MED-1: sealAuditChain removes the poisoned tail under a signed seal', t => {
  const h = fixture(t);
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'hostile' });
  const head = h.f.store.db.prepare("SELECT seq,hash FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get();
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', head.seq + 1, head.hash, 'x'.repeat(64), '{"payload":{"time":1},"signatures":[{"signature":"AA"}]}');
  assert.throws(() => h.f._auditIndex('acme'), e => /^INV-409-(INTEGRITY|AUDIT-TAMPER)$/.test(e.code));
  const res = h.f.sealAuditChain(h.p('security'));
  assert.equal(res.sealed, true); assert.equal(res.sealed_at_seq, head.seq + 1);
  assert.doesNotThrow(() => h.f._auditIndex('acme'), 'index still wedged after sealing');
  const seal = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get();
  assert.equal(JSON.parse(seal.envelope).payload.type, 'AUDIT_SEALED');
  // A healthy chain refuses to seal.
  const again = h.f.sealAuditChain(h.p('security'));
  assert.equal(again.sealed, false);
});

// H-1: the boot-time trigger check is functional — a shadow trigger that
// textually matches but never fires on `audit` cannot pass reopen.
test('w14 H-1: a shadow same-name trigger fails the functional probe', t => {
  const h = fixture(t);
  h.f.store.db.exec(`DROP TRIGGER no_audit_update;
    CREATE TRIGGER no_audit_update BEFORE UPDATE ON records
    BEGIN SELECT 'carries " ON audit " text'; SELECT RAISE(ABORT, 'append-only audit'); END;`);
  // A second connection on the same file re-runs the boot probe — the
  // fixture stays open, only the shadowed file is rejected.
  assert.throws(() => new Store(join(h.directory, 'fabric.db'), { acme: Buffer.alloc(32).toString('base64url') }, {}),
    e => /INV-503-STORAGE|UPDATE trigger/.test(e.code ?? e.message));
  // Restore the real guard so later consumers of this file open cleanly.
  h.f.store.db.exec(`DROP TRIGGER no_audit_update;
    CREATE TRIGGER no_audit_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;`);
});

// W13-04: a forged head claiming a far-future timestamp wedges the index
// on consume — the inflate-and-sign path fails loud, seal remediation
// applies; chain time stays monotone for legitimate rewinds.
test('w14 W13-04: a forged future-dated head wedges the index', t => {
  const h = fixture(t);
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all()) h.f.store.db.exec(`DROP TRIGGER ${tr.name}`);
  const head = h.f.store.db.prepare("SELECT seq,hash FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get();
  const future = h.now() + 10_000_000_000;
  const payload = { tenant_id: 'acme', sequence: head.seq + 1, previous: head.hash, type: 'CLOCK_RECOVERED', actor: 'mallory', reference: 'x', metadata: {}, time: future };
  // The inflated head must carry a real signature to reach the time
  // bound — sign it with the live audit key (the leaked-key class of
  // attacker this guard exists for).
  const auditKey = h.setup.config.tenants.acme.keys.audit;
  const fake = signed(payload, { key_id: auditKey.key_id, private_key: auditKey.private_key }, 'audit');
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', head.seq + 1, head.hash, digest(payload), canonical(fake));
  assert.throws(() => h.f._auditIndex('acme'), hasCode('INV-409-INTEGRITY'), 'future-dated forged row consumed silently');
});

// M-1: identical-code denials dedup by (tenant, subject, code) — a
// varying message string cannot un-budget the signed ledger.
test('w14 M-1: denial dedup ignores the free-text message', t => {
  const h = fixture(t);
  const before = h.f.store.db.prepare("SELECT COUNT(*) c FROM audit WHERE tenant='acme'").get().c;
  h.f._rejectionAudit('acme', 'mallory', 'INV-403-QUARANTINE', 'attempt one');
  h.f._rejectionAudit('acme', 'mallory', 'INV-403-QUARANTINE', 'a different string');
  h.f._rejectionAudit('acme', 'mallory', 'INV-403-QUARANTINE', 'yet another');
  const after = h.f.store.db.prepare("SELECT COUNT(*) c FROM audit WHERE tenant='acme'").get().c;
  assert.equal(after - before, 1, 'message variation flooded the denial ledger');
});

// M-2: a scalar under 'value' in material_fields is redacted — it is
// exactly the shape a registry secret takes.
test('w14 M-2: capsuleView redacts scalar value fields', t => {
  const h = fixture(t);
  const view = h.f.capsuleView({ capsule: { current_state: { material_fields: { value: 'sk-live-secret', nested: { api_token: 'x' }, plain: 42 } } } });
  assert.equal(view.capsule.current_state.material_fields.value, '«redacted»');
  assert.equal(view.capsule.current_state.material_fields.nested.api_token, '«redacted»');
  assert.equal(view.capsule.current_state.material_fields.plain, 42);
});

// M-3: the stored capsule row must equal its chain-attested proposal —
// an in-place rewrite of requested_state fails evaluation.
test('w14 M-3: an in-place capsule rewrite fails the proposal anchor', t => {
  const h = fixture(t);
  const r = h.proposed();
  const stored = h.f.store.must('acme', 'capsule', r.capsule.capsule_id);
  stored.capsule.requested_state = { ...stored.capsule.requested_state, extra_graft: true };
  stored.capsule_digest = digest(stored.capsule); // consistent re-digest — still dies on the anchor
  h.f.store.put('acme', 'capsule', r.capsule.capsule_id, stored, h.now());
  h.f.invalidateAuditIndex();
  assert.throws(() => h.f.evaluate(h.p(), r.capsule.capsule_id), hasCode('INV-409-INTEGRITY'));
});

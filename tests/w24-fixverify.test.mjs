// Wave-24 fix-verification regressions — the w24-fixverify auditor
// falsified the wave's own fixes on 20f8fa7 (W24-01..W24-07): the signed
// chain-head watermark, anchored wedged-release/child guards, anchored
// capability/approval/evidence expiry vetoes, emergencyWeakening blind
// spots and cross-DB aadDedup donor protection.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fixture, hasCode } from './helpers.mjs';
import { digest, clone } from '../src/canonical.mjs';
import { encrypt } from '../src/crypto.mjs';
import { Fabric } from '../src/fabric.mjs';
import { emergencyWeakening, defaultPolicy } from '../src/policy.mjs';

const JIT_REQ = { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-1'], ttl_ms: 60000, reason: 'Incident', roles: [] };
const JIT_OVR = { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'JIT' } };
const jitChild = h => { const r = h.proposed('identity.jit.grant', JIT_REQ, JIT_OVR); h.evidence(r, { kind: 'identity_proof', issuer: 'hris' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const beneChild = (h, n) => { const r = h.proposed('finance.beneficiary.create', { vendor_id: `vendor-${n}`, bank_account: `TESTBANK00000${n}`, currency: 'EUR' }); h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const composite = (h, children) => { const r = h.proposed('action.composite', { children }, { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'Batch' } }); h.approve(r, 2); return r; };
const headSeq = h => h.f.store.db.prepare("SELECT MAX(seq) m FROM audit WHERE tenant='acme'").get().m;
// A committed future-dated row proves the clock moved forward; setting
// the wall clock back then runs recoverClock's resurrection veto.
const rewindWithProbe = (h, span) => {
  h.advance(span);
  h.f.store.tx(() => { const n = h.f.clock(); h.f.store.clock(n); h.f.store.audit('acme', 'HEALTH_ASSERTION', 'operator', 'probe', {}, n); });
  h.set(h.now() - span);
};
// The append-only triggers are a defense-in-depth gate the file-writer
// bypasses physically — tamper tests drop them exactly like w14 does.
const dropAuditTriggers = h => { for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all()) h.f.store.db.exec(`DROP TRIGGER ${tr.name}`); };

// ── W24-01: signed end-of-chain watermark ─────────────────────────────

test('w24-fixverify W24-01a: truncating the audit tail below the signed head screams', t => {
  const h = fixture(t);
  const { certificate } = h.ready();
  h.f.execute(h.p(), certificate);
  assert.ok(headSeq(h) > 0);
  // A row-level file writer deletes the newest committed rows — the
  // watermark cannot be forged backward, so the fold must refuse.
  dropAuditTriggers(h);
  h.f.store.db.prepare("DELETE FROM audit WHERE tenant='acme' AND seq=?").run(headSeq(h));
  h.f.invalidateAuditIndex('acme');
  assert.throws(() => h.f._auditIndex('acme'), hasCode('INV-409-INTEGRITY'));
});

test('w24-fixverify W24-01b: rewriting the tip row under the same seq screams', t => {
  const h = fixture(t);
  const { certificate } = h.ready();
  h.f.execute(h.p(), certificate);
  const tip = headSeq(h);
  dropAuditTriggers(h);
  // Same-seq replacement keeps MAX(seq) — only the signed head's hash
  // exposes the rewrite (the fold's own headHash pins it too).
  h.f.store.db.prepare("UPDATE audit SET hash='deadbeef', previous='cafe' WHERE tenant='acme' AND seq=?").run(tip);
  h.f.invalidateAuditIndex('acme');
  assert.throws(() => h.f._auditIndex('acme'), hasCode('INV-409-INTEGRITY'));
});

test('w24-fixverify W24-01c: a corrupted watermark envelope fails closed', t => {
  const h = fixture(t);
  const { certificate } = h.ready();
  h.f.execute(h.p(), certificate);
  // The file is untrusted input: a signature that no longer verifies must
  // wedge the fold, never silently downgrade to "no head".
  const path = join(h.directory, 'chain-heads.json');
  const file = JSON.parse(readFileSync(path, 'utf8'));
  file.tenants.acme.signature = file.tenants.acme.signature.slice(0, -4) + 'AAAA';
  writeFileSync(path, JSON.stringify(file));
  h.f.invalidateAuditIndex('acme');
  assert.throws(() => h.f._auditIndex('acme'), hasCode('INV-409-INTEGRITY'));
  // Same failure closes a cold boot — the file is verified at read time.
  const f2 = new Fabric(clone(h.setup.config), h.directory, () => h.now());
  try { assert.throws(() => f2._auditIndex('acme'), hasCode('INV-409-INTEGRITY')); } finally { f2.close(); }
});

test('w24-fixverify W24-01d: a rolled-back tx leaves no phantom head and keeps working', t => {
  const h = fixture(t);
  const { certificate } = h.ready();
  const headBefore = headSeq(h);
  try {
    h.f.transaction(h.p(), now => { h.f.store.audit('acme', 'AUTHORITY_REVOKED', 'operator', 'device:phantom', {}, now); throw new Error('boom'); });
  } catch { /* rolled back */ }
  assert.ok(headSeq(h) >= headBefore, 'the chain stays append-only across the rollback');
  // The gate stays healthy: the doomed append moved no watermark.
  const out = h.f.execute(h.p(), certificate);
  assert.equal(out.payload.status, 'VERIFIED');
});

// ── W24-02: wedged release binds the anchored dispatch ────────────────

test('w24-fixverify W24-02: a dispatched-but-wedged child with a deleted journal is never released', t => {
  const h = fixture(t);
  const c1 = beneChild(h, 1), c2 = beneChild(h, 2);
  const r = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const parentCert = h.f.certificate(h.p(), r.capsule.capsule_id);
  const c1CertId = c1.certificate.payload.certificate_id;
  // c1's dispatch commits its journal AND its anchored EXECUTION_DISPATCHED;
  // then the mutable journal row is deleted (file-level attacker) and the
  // response validation fails — the old probe released the cert on the
  // missing row alone. The anchored dispatch must outrank the deleted row.
  const origV = h.f._validateTargetResponse.bind(h.f);
  let cut = false;
  h.f._validateTargetResponse = (child, cert, raw, now, o) => {
    if (!cut && cert.certificate_id === c1CertId) {
      cut = true;
      assert.equal(h.f.target.db.prepare("DELETE FROM transactions WHERE tenant='acme' AND id=?").run(c1CertId).changes, 1, 'journal row existed to delete');
      assert.ok(h.f._auditIndex('acme').dispatched.has(c1CertId), 'anchored dispatch is committed');
      return { valid: false, reason: 'TEST_CUT' };
    }
    return origV(child, cert, raw, now, o);
  };
  const out = h.f.execute(h.p(), parentCert);
  assert.equal(out.payload.child_outcomes[c1.record.capsule.capsule_id], 'WEDGED');
  assert.equal(h.f._auditIndex('acme').released?.has(c1CertId) ?? false, false, 'anchored dispatch forbids the release');
  assert.equal(h.f.store.must('acme', 'certificate', c1CertId).consumed, true, 'the spend slot stays burned');
});

// ── W24-03: composite child guard is anchored ─────────────────────────

test('w24-fixverify W24-03: a child with an anchored dispatch can never re-enter a composite', t => {
  const h = fixture(t);
  const c1 = beneChild(h, 1), c2 = beneChild(h, 2);
  // Anchor a dispatch for c1 outside any parent — a wedged prior run.
  const c1CertId = c1.certificate.payload.certificate_id;
  h.f.store.audit('acme', 'EXECUTION_DISPATCHED', 'operator', c1CertId, { journal_digest: digest({ synthetic: 1 }) }, h.now());
  const r = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const parentCert = h.f.certificate(h.p(), r.capsule.capsule_id);
  // The anchored fold catches the spent slot — the composite terminates
  // honestly instead of re-dispatching the wedged child.
  const out = h.f.execute(h.p(), parentCert);
  assert.match(out.payload.reason, /INV-409-REPLAY/, `expected replay refusal, got ${out.payload.status}:${out.payload.reason}`);
});

// ── W24-04: capability veto is anchored ───────────────────────────────

const CAP_REQ = { device_id: 'operator-device', resource: 'dataset-1', destination: 'customer-vault', action: 'data.read', purpose: 'operations', columns: ['id'], row_ids: ['row-1'], classification: 'internal', jurisdiction: 'EU', max_cost: 10, ttl_ms: 60000 };

test('w24-fixverify W24-04a: a deleted anchored capability row isolates its tenant', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), CAP_REQ);
  const capId = cap.payload.capability_id;
  assert.ok(h.f._auditIndex('acme').capabilities.has(capId));
  // File-level attacker deletes the store row — the anchored CAPABILITY_ISSUED
  // still names it, so "no row" is tamper evidence, not "no expiry".
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='capability' AND id=?").run(capId);
  // Rewind inside the capability's window so the veto scan runs. The
  // future-dated probe wedges the fold; the seal repair precedes the
  // recovery verdict exactly like the w17-idx F4 path.
  rewindWithProbe(h, 200000);
  h.f.invalidateAuditIndex('acme');
  h.f.sealAuditChain(h.p('security'));
  const out = h.f.recoverClock(h.p('security'));
  assert.ok(out.unverifiable_tenants.includes('acme'), 'missing anchored row isolates the tenant');
  assert.throws(() => h.f.transaction(h.p(), () => {}), hasCode('INV-503-TIME'), 'isolated tenant stays closed');
});

test('w24-fixverify W24-04b: an anchored capability expiry vetoes resurrection inside the rewound span', t => {
  const h = fixture(t);
  h.f.runtime.issue(h.p(), CAP_REQ); // expires now+60000
  rewindWithProbe(h, 120000); // probe at T+120000, head back to T — expiry lands inside
  h.f.invalidateAuditIndex('acme');
  h.f.sealAuditChain(h.p('security'));
  assert.throws(() => h.f.recoverClock(h.p('security')), hasCode('INV-503-TIME'));
});

// ── W24-07: approval + evidence expiry vetoes are anchored ────────────

test('w24-fixverify W24-07a: an anchored approval expiry vetoes clock recovery', t => {
  const h = fixture(t);
  const r = h.proposed(); // uncertified — its approvals stay live
  h.approve(r, 1); // anchored EXACT_ACTION_APPROVED, expires_at = now+300000
  const anchored = h.f._auditIndex('acme').approvalExpiry.get(r.capsule.capsule_id);
  assert.ok(anchored?.length === 1 && anchored[0].expires_at === h.now() + 300000, 'approval expiry is folded from the chain');
  rewindWithProbe(h, 400000); // expiry T+300000 lands inside (T, T+400000]
  h.f.invalidateAuditIndex('acme');
  h.f.sealAuditChain(h.p('security'));
  assert.throws(() => h.f.recoverClock(h.p('security')), e => e.code === 'INV-503-TIME' && /expired approval/.test(e.message));
});

test('w24-fixverify W24-07b: an anchored evidence expiry vetoes clock recovery', t => {
  const h = fixture(t);
  // The capsule's own expiry must sit OUTSIDE the rewound span or the
  // action veto legitimately fires first — push it to the TTL ceiling.
  const r = h.proposed('finance.beneficiary.create', { vendor_id: 'v-ev', bank_account: 'TESTBANK000009', currency: 'EUR' }, { expires_at: 1788648000000 + 3600000 });
  h.evidence(r); // anchored EVIDENCE_ATTACHED, expires_at = now+600000
  const anchored = h.f._auditIndex('acme').evidenceExpiry.get(r.capsule.capsule_id);
  assert.ok(anchored?.length === 1 && anchored[0].expires_at === h.now() + 600000, 'evidence expiry is folded from the chain');
  rewindWithProbe(h, 700000); // expiry T+600000 lands inside (T, T+700000]
  h.f.invalidateAuditIndex('acme');
  h.f.sealAuditChain(h.p('security'));
  assert.throws(() => h.f.recoverClock(h.p('security')), e => e.code === 'INV-503-TIME' && /expired evidence/.test(e.message));
});

// ── W24-05: emergencyWeakening blind spots ────────────────────────────

test('w24-fixverify W24-05: window_ms, per_action moves and dropped deprecation entries are refused', () => {
  const base = () => defaultPolicy('acme');
  const weak = mutate => { const next = clone(base()); next.policy_id = 'constitution:acme'; next.version = 2; mutate(next); return emergencyWeakening(base(), next, 1000); };
  // A widened reconstruction window is a stealth budget cut.
  assert.equal(weak(n => { n.runtime.reconstruction.window_ms *= 10; }), 'runtime.reconstruction.window_ms');
  // per_action ceilings take the same union semantics as per_kind.
  assert.equal(weak(n => { n.retention.per_action = { 'finance.beneficiary.create': 1000 }; }), 'retention.per_action.finance.beneficiary.create');
  // A dropped deprecation entry re-enables a dead algorithm silently.
  const b = base(); b.algorithms.deprecation = [{ suite: 'Ed25519', not_before: 1000, reason: 'rotated' }];
  const dropped = clone(b); dropped.version = 2; dropped.algorithms.deprecation = [];
  assert.equal(emergencyWeakening(b, dropped, 1000), 'algorithms.deprecation');
});

// ── W24-06: cross-DB aadDedup keeps the donor canonical ───────────────

test('w24-fixverify W24-06: a cross-db graft counts the transplant without stranding the donor', t => {
  const h = fixture(t);
  // Donor: a legacy-AAD-sealed records row in fabric.db — it migrates on
  // first open, and the dedup index remembers its ORIGINAL bytes.
  const ct = encrypt('donor-secret', h.f.store.key('acme'), 'acme/jit-grant/g-donor');
  h.f.store.db.prepare("INSERT INTO records (tenant,kind,id,value,created) VALUES ('acme','jit-grant','g-donor',?,0)").run(ct);
  // Graft the identical ciphertext into the sibling db's transactions
  // table — byte-identical ciphertext under a second identity is a
  // transplant, and the target migrator sees it second.
  h.f.target.db.prepare("INSERT INTO transactions (tenant,id,value) VALUES ('acme','graft-1',?)").run(ct);
  const f2 = new Fabric(clone(h.setup.config), h.directory, () => h.now());
  try {
    // The graft is detected and counted on the SECOND (target) migrator…
    assert.equal(f2.target.aadMigration.get('acme').transplants, 1);
    // …but the donor in fabric.db keeps its canonical binding and reads.
    assert.equal(f2.store.get('acme', 'jit-grant', 'g-donor'), 'donor-secret');
    // The grafted row stays legacy-sealed — reads classify as tamper
    // evidence, never the donor's plaintext.
    assert.throws(() => f2.target.outcome('acme', 'graft-1'), hasCode('INV-409-INTEGRITY'));
  } finally { f2.close(); }
});

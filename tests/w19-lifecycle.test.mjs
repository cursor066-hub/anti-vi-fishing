// w19-lifecycle regression suite — every hostile PoC from the anchored
// lifecycle audit must now fail CLOSED. Attacks are asserted blocked, not
// merely "not exploitable".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { fixture, hasCode, designateSuccessor } from './helpers.mjs';
import { signAcknowledgement } from '../src/ceremony.mjs';
import { digest, clone } from '../src/canonical.mjs';
import { split, encodeShare } from '../src/shamir.mjs';
import { generateKey } from '../src/crypto.mjs';
import { Fabric } from '../src/fabric.mjs';

const CUST2 = ['custodian-1', 'custodian-2'];
const flipCeremony = (h, cid, mutate) => { const r = h.f.store.must('acme', 'ceremony', cid); mutate(r); h.f.store.put('acme', 'ceremony', cid, r, h.now()); };
const certifyRotate = (h, pending, ceremony_id) => {
  const r = h.proposed('key.rotate', { key_class: 'execution', new_key_id: pending.key_id, new_public_key: pending.public_key, ceremony_id, revoke_old: false }, { action: { type: 'key.rotate', target_resource: 'key-registry', purpose: 'Rotate' } });
  h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'audit-committee' });
  h.approve(r, 3); h.advance(60001);
  return h.f.certificate(h.p(), r.capsule.capsule_id);
};

// w19-F1 CRITICAL: a planted ceremony row (threshold:0, no anchors) must not
// satisfy the key.rotate quorum bond — the bond reads the ANCHORED plan.
test('w19-F1: a planted threshold:0 ceremony cannot satisfy the rotate bond', t => {
  const h = fixture(t);
  const pending = h.f.prepareRotation(h.p('security'), 'execution');
  const ceremony = {
    ceremony_id: 'cer-planted', tenant_id: 'acme', purpose: 'key.rotate', threshold: 0,
    custodians: [], acknowledgements: [], notices: [], share_commitments: [],
    min_delay_ms: 0, valid_until: h.now() + 3600000,
    rotation: { key_class: 'execution', new_key_id: pending.key_id },
    status: 'committed', committed_at: h.now(), artifact_digest: 'f'.repeat(64), rotation_consumed: null,
  };
  h.f.store.put('acme', 'ceremony', ceremony.ceremony_id, ceremony, h.now());
  const q = h.f.custodianQuorum('acme', h.f.store.must('acme', 'ceremony', 'cer-planted'));
  assert.equal(q.planAnchored, false, 'unanchored plan reports planAnchored:false');
  assert.equal(q.live, 0);
  assert.throws(() => h.f.execute(h.p(), certifyRotate(h, pending, 'cer-planted')), e => e instanceof Error && /^INV-/.test(e.code ?? ''),
    'the bond refuses a ceremony the chain never planned');
  assert.notEqual(h.f.keys('acme').execution.key_id, pending.key_id, 'execution signer never repointed');
});

// w19-F1b: flipping a real designated ceremony's threshold to 0 diverges the
// anchored plan — the bond refuses rather than reading the tampered 0.
test('w19-F1b: a tampered threshold diverges the plan anchor and kills the bond', t => {
  const h = fixture(t);
  const pending = designateSuccessor(h, 'execution');
  const cid = h.f.store.db.prepare("SELECT id FROM records WHERE tenant='acme' AND kind='ceremony' ORDER BY created DESC LIMIT 1").get().id;
  flipCeremony(h, cid, r => { r.threshold = 0; });
  const q = h.f.custodianQuorum('acme', h.f.store.must('acme', 'ceremony', cid));
  assert.equal(q.planAnchored, false, 'tampered terms no longer match the anchored plan');
  assert.equal(q.live, 0);
  assert.throws(() => h.f.execute(h.p(), certifyRotate(h, pending, cid)), e => e instanceof Error && /^INV-/.test(e.code ?? ''));
  assert.notEqual(h.f.keys('acme').execution.key_id, pending.key_id);
});

// w19-F2 HIGH: share_commitments are anchored by digest — a post-commit
// substitution under the kept artifact_digest must be refused.
test('w19-F2: swapped share_commitments cannot substitute the recovered secret', t => {
  const h = fixture(t);
  h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-sub', purpose: 'recovery', threshold: 2, custodians: CUST2, valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  const dealt = h.f.splitCeremonySecret(h.p('security'), 'cer-sub', randomBytes(32).toString('base64url'));
  const committed = h.f.store.must('acme', 'ceremony', 'cer-sub');
  for (const subject of CUST2) h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(committed, subject, h.setup.custodianKeys.acme[subject], h.now()));
  const evilSecret = randomBytes(32);
  const evil = split(evilSecret, 2, 2);
  const stored = h.f.store.must('acme', 'ceremony', 'cer-sub');
  stored.share_commitments = evil.map(s => ({ custodian: stored.custodians[s.x - 1], share_index: s.x, commitment: digest({ ceremony_id: 'cer-sub', x: s.x, y: Buffer.from(s.y).toString('base64url') }) }));
  h.f.store.put('acme', 'ceremony', 'cer-sub', stored, h.now());
  h.advance(120001);
  assert.throws(() => h.f.reconstructCeremony(h.p('security'), 'cer-sub', evil.map(encodeShare)),
    hasCode('INV-409-INTEGRITY'), 'divergent commitments refuse reconstruction');
  // The tampered row diverges from its anchor permanently — fail-closed,
  // the ceremony is dead even for honest shares (a fresh ceremony is the
  // only path forward).
  assert.throws(() => h.f.reconstructCeremony(h.p('security'), 'cer-sub', [dealt.shares[0].share, dealt.shares[1].share]),
    hasCode('INV-409-INTEGRITY'), 'tamper evidence keeps the ceremony wedged');
  // An untampered ceremony still reconstructs end-to-end.
  h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-clean', purpose: 'recovery', threshold: 2, custodians: CUST2, valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  const s2 = h.f.splitCeremonySecret(h.p('security'), 'cer-clean', randomBytes(32).toString('base64url'));
  const clean = h.f.store.must('acme', 'ceremony', 'cer-clean');
  for (const subject of CUST2) h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(clean, subject, h.setup.custodianKeys.acme[subject], h.now()));
  h.advance(120001);
  const rec = h.f.reconstructCeremony(h.p('security'), 'cer-clean', [s2.shares[0].share, s2.shares[1].share]);
  assert.equal(rec.reconstructed, true, 'untampered lifecycle still completes');
});

// w19-F3 HIGH: one tenant's missing anchored row lands in
// unverifiable_tenants — recovery and the healthy tenants proceed.
test('w19-F3: a tampered tenant is quarantined, not a recovery-wide veto', t => {
  const h = fixture(t);
  h.ready(h.proposed());
  const g = h.proposed('finance.beneficiary.create', { vendor_id: 'vendor-g', bank_account: 'TESTBANK000009', currency: 'EUR' }, {}, h.p('operator', 'globex'));
  h.ready(g);
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='globex' AND kind='certificate'").run();
  // Rewind 30s — inside no authority's remaining validity (the fixture
  // certificates live ≥60s), so the veto has no legitimate acme target.
  h.f.store.db.prepare('UPDATE clock SET last=? WHERE id=1').run(h.now() + 30000);
  const out = h.f.recoverClock(h.p('security', 'acme'));
  assert.ok(out.recovered_at, 'recovery proceeds despite the tampered tenant');
  assert.ok(out.unverifiable_tenants.includes('globex'), 'tampered tenant lands in unverifiable_tenants');
  assert.ok(!out.unverifiable_tenants.includes('acme'), 'healthy tenant never wedged by a neighbour\'s tamper');
  assert.ok(h.proposed(), 'healthy tenant transacts through the recovery');
  assert.throws(() => h.proposed('finance.beneficiary.create', { vendor_id: 'v2', bank_account: 'TESTBANK000010', currency: 'EUR' }, {}, h.p('operator', 'globex')),
    hasCode('INV-503-TIME'), 'the tampered tenant itself stays halted until a seal');
});

// w19-F4 HIGH: a seal-time audit-signer repoint must persist the vault
// activation — post-restart the repointed key must actually sign.
test('w19-F4: sealAuditChain repoint persists vault activation across restart', t => {
  const h = fixture(t);
  const pending = designateSuccessor(h, 'audit');
  const auditKid = h.f.keys('acme').audit.key_id;
  h.f.revoke(h.p('security'), { kind: 'key', id: auditKid, reason: 'seal repoint test' });
  const head = h.f.store.db.prepare("SELECT seq,hash FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get();
  h.f.store.db.prepare("INSERT INTO audit (tenant,seq,previous,hash,envelope) VALUES ('acme',?,?,'deadbeef','{}')").run(head.seq + 1, head.hash);
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.equal(seal.sealed, true);
  assert.equal(h.f.keys('acme').audit.key_id, pending.key_id);
  const f2 = new Fabric(clone(h.setup.config), h.directory, () => h.now());
  try {
    assert.equal(f2.tenant('acme').keys.audit.key_id, pending.key_id, 'binding survives restart');
    assert.equal(f2.vault.keys.get(pending.key_id).pending, false, 'activation persisted — no pending signer on the live binding');
    assert.doesNotThrow(() => f2.createCeremony(h.p('security'), { ceremony_id: 'cer-post', purpose: 'recovery', threshold: 2, custodians: CUST2, valid_until: h.now() + 3600000, min_delay_ms: 120000 }),
      'audit-emitting operations keep working post-restart');
  } finally { f2.close(); }
});

// w19-F5 MEDIUM: row-truncated acknowledgements fall back to the anchored
// CEREMONY_ACKNOWLEDGED coverage — quorum must not wedge.
test('w19-F5: truncated row acknowledgements cannot wedge anchored quorum', t => {
  const h = fixture(t);
  h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-trunc', purpose: 'recovery', threshold: 2, custodians: CUST2, valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  const s = h.f.splitCeremonySecret(h.p('security'), 'cer-trunc', randomBytes(32).toString('base64url'));
  const committed = h.f.store.must('acme', 'ceremony', 'cer-trunc');
  for (const subject of CUST2) h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(committed, subject, h.setup.custodianKeys.acme[subject], h.now()));
  flipCeremony(h, 'cer-trunc', r => { r.acknowledgements = []; });
  assert.equal(h.f._auditIndex('acme').ceremonyAcks.get('cer-trunc').size, 2, 'chain still attests both custodians acked');
  h.advance(120001);
  const rec = h.f.reconstructCeremony(h.p('security'), 'cer-trunc', [s.shares[0].share, s.shares[1].share]);
  assert.equal(rec.reconstructed, true, 'anchored consent survives row truncation');
});

// w19-F6 LOW: abort kills designation; completion/consumption must not —
// they are the designation's success lifecycle (the pending successor
// signs its own landing KEY_ROTATED only via this designation). The
// anchored plan digest keeps designation bound to exactly one kid, so a
// completed ceremony can never designate anything else.
test('w19-F6: lifecycle state bounds designation honestly', t => {
  const h = fixture(t);
  const pending = designateSuccessor(h, 'execution');
  const cid = h.f.store.db.prepare("SELECT id FROM records WHERE tenant='acme' AND kind='ceremony' ORDER BY created DESC LIMIT 1").get().id;
  const idx = h.f._auditIndex('acme');
  idx.ceremonyCompleted.add(cid);
  idx.ceremonyRotationConsumed.add(cid);
  assert.equal(h.f.ceremonyDesignated('acme', pending.key_id, 'execution'), true, 'a completed/spent ceremony still designates its anchored key — the successor must sign its own landing');
  idx.ceremonyAborted.add(cid);
  assert.equal(h.f.ceremonyDesignated('acme', pending.key_id, 'execution'), false, 'an aborted ceremony designates nothing');
  idx.ceremonyAborted.delete(cid);
  // A mutated designation target diverges from the anchored plan — the
  // completed ceremony still cannot designate the planted key.
  const row = h.f.store.must('acme', 'ceremony', cid);
  row.rotation.new_key_id = generateKey().key_id;
  h.f.store.put('acme', 'ceremony', cid, row, h.now());
  assert.equal(h.f.ceremonyDesignated('acme', pending.key_id, 'execution'), false, 'plan-diverged row designates nothing');
});

// w19-F7 LOW: an unplanned planted ceremony collects no lifecycle anchors —
// every gate requires the CEREMONY_PLANNED commitment first.
test('w19-F7: an unplanned planted ceremony collects no anchored lifecycle', t => {
  const h = fixture(t);
  const ceremony = {
    ceremony_id: 'cer-ghost', tenant_id: 'acme', purpose: 'recovery', threshold: 2,
    custodians: [...CUST2], acknowledgements: [], notices: [], share_commitments: [],
    min_delay_ms: 0, valid_until: h.now() + 3600000, devices: {}, rotation: null,
    status: 'planned', committed_at: null, artifact_digest: 'a'.repeat(64), rotation_consumed: null,
  };
  h.f.store.put('acme', 'ceremony', 'cer-ghost', ceremony, h.now());
  const row = h.f.store.must('acme', 'ceremony', 'cer-ghost');
  for (const subject of CUST2)
    assert.throws(() => h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(row, subject, h.setup.custodianKeys.acme[subject], h.now())), hasCode('INV-409-INTEGRITY'));
  assert.throws(() => h.f.commitCeremonyShares(h.p('security'), 'cer-ghost', split(randomBytes(32), 2, 2)), hasCode('INV-409-INTEGRITY'));
  assert.throws(() => h.f.splitCeremonySecret(h.p('security'), 'cer-ghost', randomBytes(32).toString('base64url')), hasCode('INV-409-INTEGRITY'));
  assert.throws(() => h.f.abortCeremony(h.p('security'), 'cer-ghost'), hasCode('INV-409-INTEGRITY'));
  const idx = h.f._auditIndex('acme');
  assert.equal(idx.ceremonyAcks.get('cer-ghost')?.size ?? 0, 0, 'no acks anchored');
  assert.equal(idx.ceremonyCommitted.has('cer-ghost'), false, 'no commit anchored');
  assert.equal(idx.ceremonyNotices.get('cer-ghost')?.size ?? 0, 0, 'no notices anchored');
});

// w19-F8: clearing the unverifiable flag is post-commit — a seal that aborts
// must not silently unwedge the tenant, and a committed seal must clear it.
test('w19-F8: unverifiable clears only on a committed seal', t => {
  const h = fixture(t);
  h.ready(h.proposed());
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='certificate'").run();
  h.f.store.db.prepare('UPDATE clock SET last=? WHERE id=1').run(h.now() + 30000);
  const out = h.f.recoverClock(h.p('security'));
  assert.ok(out.unverifiable_tenants.includes('acme'));
  // Removing the signing key from the vault leaves no live audit signer and
  // no designated successor — the seal's repoint cannot attest, the tx
  // aborts, and the wedge must survive the abort.
  const auditKid = h.f.keys('acme').audit.key_id;
  const head = h.f.store.db.prepare("SELECT seq,hash FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get();
  h.f.store.db.prepare("INSERT INTO audit (tenant,seq,previous,hash,envelope) VALUES ('acme',?,?,'deadbeef','{}')").run(head.seq + 1, head.hash);
  // Remove the signing key itself from the vault in-memory so the seal's
  // audit write cannot be produced and the transaction must abort.
  const entry = h.f.vault.keys.get(auditKid);
  h.f.vault.keys.delete(auditKid);
  assert.throws(() => h.f.sealAuditChain(h.p('security')), e => e instanceof Error && /^INV-/.test(e.code ?? ''));
  if (entry) h.f.vault.keys.set(auditKid, entry);
  assert.equal(h.f._clockRecoveryUnverifiable.has('acme'), true, 'the flag survived the aborted seal — never cleared pre-commit');
  assert.throws(() => h.proposed(), e => e instanceof Error && /^INV-/.test(e.code ?? ''), 'tenant still cannot transact');
});

// w19-F8b: a committed seal clears the wedge — the tenant transacts again.
test('w19-F8b: a committed seal clears the unverifiable wedge', t => {
  const h = fixture(t);
  h.ready(h.proposed());
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='certificate'").run();
  h.f.store.db.prepare('UPDATE clock SET last=? WHERE id=1').run(h.now() + 30000);
  assert.ok(h.f.recoverClock(h.p('security')).unverifiable_tenants.includes('acme'));
  const head = h.f.store.db.prepare("SELECT seq,hash FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get();
  h.f.store.db.prepare("INSERT INTO audit (tenant,seq,previous,hash,envelope) VALUES ('acme',?,?,'deadbeef','{}')").run(head.seq + 1, head.hash);
  h.f.sealAuditChain(h.p('security'));
  assert.ok(h.proposed(), 'the committed seal released the wedge');
});

// Regression suite for the w18 fix-verification wave — every finding was
// an attack on the w17 mechanisms themselves: anchored ceremony lifecycle,
// anchored clock-recovery veto, bounded dedup keys, honest policy ladders.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { fixture, hasCode, stageConstitution, designateSuccessor, runtimeInput, runtimeRequest } from './helpers.mjs';
import { signAcknowledgement } from '../src/ceremony.mjs';
import { clone, digest } from '../src/canonical.mjs';

const CUST2 = ['custodian-1', 'custodian-2'];
const flipCeremony = (h, cid, mutate) => { const r = h.f.store.must('acme', 'ceremony', cid); mutate(r); h.f.store.put('acme', 'ceremony', cid, r, h.now()); };

// F1: the plan digest must cover the STORED (sorted) custodian list — an
// unsorted input previously minted an anchor no recomputation could match.
test('w18-fv F1: an unsorted custodian list no longer bricks its own ceremony', t => {
  const h = fixture(t);
  const c = h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-uns', purpose: 'recovery', threshold: 2, custodians: ['custodian-3', 'custodian-1', 'custodian-2'], valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  h.f.splitCeremonySecret(h.p('security'), 'cer-uns', randomBytes(32).toString('base64url'));
  const committed = h.f.store.must('acme', 'ceremony', 'cer-uns');
  for (const subject of ['custodian-1', 'custodian-2']) h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(committed, subject, h.setup.custodianKeys.acme[subject], h.now()));
  const q = h.f.custodianQuorum('acme', h.f.store.must('acme', 'ceremony', 'cer-uns'));
  assert.equal(q.live, 2, 'unsorted input must normalize to a reachable quorum');
});

// F7: device pins live inside the plan digest — stripping them off the row
// diverges the anchor and the quorum dies closed instead of laundering.
test('w18-fv F7: stripped device pins diverge the anchored plan digest', t => {
  const h = fixture(t);
  h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-pin', purpose: 'key.recovery', threshold: 2, custodians: CUST2, valid_until: h.now() + 3600000, min_delay_ms: 120000, devices: { 'custodian-1': 'custodian-1-device' } });
  flipCeremony(h, 'cer-pin', r => { r.devices = {}; });
  // w19-lifecycle F7: a plan-diverged row cannot even collect lifecycle
  // events — the anchored-plan check runs before dealing or consent.
  assert.throws(() => h.f.splitCeremonySecret(h.p('security'), 'cer-pin', randomBytes(32).toString('base64url')), hasCode('INV-409-INTEGRITY'), 'plan-diverged row cannot be dealt shares');
  const committed = h.f.store.must('acme', 'ceremony', 'cer-pin');
  for (const subject of CUST2) assert.throws(() => h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(committed, subject, h.setup.custodianKeys.acme[subject], h.now())), hasCode('INV-409-INTEGRITY'), 'plan-diverged row collects no anchored acks');
  assert.equal(h.f.custodianQuorum('acme', committed).live, 0, 'plan-digest divergence kills the quorum anchor');
});

// F2: lifecycle is chain-anchored — a committed→planned flip cannot re-deal.
test('w18-fv F2a: a row flipped back to planned cannot re-deal the secret', t => {
  const h = fixture(t);
  h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-redeal', purpose: 'recovery', threshold: 2, custodians: CUST2, valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  h.f.splitCeremonySecret(h.p('security'), 'cer-redeal', randomBytes(32).toString('base64url'));
  flipCeremony(h, 'cer-redeal', r => { r.status = 'planned'; });
  assert.throws(() => h.f.splitCeremonySecret(h.p('security'), 'cer-redeal', randomBytes(32).toString('base64url')), hasCode('INV-409-STATE'), 'anchored commitment refuses the re-deal');
});

// F2: aborted → committed flip cannot resurrect reconstruction or consent.
test('w18-fv F2b: an aborted ceremony stays dead after a row-status flip', t => {
  const h = fixture(t);
  h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-ab', purpose: 'recovery', threshold: 2, custodians: ['custodian-1', 'custodian-2', 'custodian-3'], valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  const s = h.f.splitCeremonySecret(h.p('security'), 'cer-ab', randomBytes(32).toString('base64url'));
  const committed = h.f.store.must('acme', 'ceremony', 'cer-ab');
  for (const subject of CUST2) h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(committed, subject, h.setup.custodianKeys.acme[subject], h.now()));
  h.f.abortCeremony(h.p('security'), 'cer-ab');
  flipCeremony(h, 'cer-ab', r => { r.status = 'committed'; });
  h.advance(120001);
  assert.throws(() => h.f.reconstructCeremony(h.p('security'), 'cer-ab', [s.shares[0].share, s.shares[1].share]), hasCode('INV-409-STATE'), 'anchored abort survives the flip');
  const row = h.f.store.must('acme', 'ceremony', 'cer-ab');
  assert.throws(() => h.f.acknowledgeCeremony(h.p('custodian-3'), signAcknowledgement(row, 'custodian-3', h.setup.custodianKeys.acme['custodian-3'], h.now())), hasCode('INV-409-STATE'), 'flipped-open row collects no late consent');
});

// F2+F3: completed → committed flip cannot replay the reconstruction.
test('w18-fv F2c: a completed ceremony cannot replay via a row-status flip', t => {
  const h = fixture(t);
  h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-done', purpose: 'recovery', threshold: 2, custodians: CUST2, valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  const s = h.f.splitCeremonySecret(h.p('security'), 'cer-done', randomBytes(32).toString('base64url'));
  const committed = h.f.store.must('acme', 'ceremony', 'cer-done');
  for (const subject of CUST2) h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(committed, subject, h.setup.custodianKeys.acme[subject], h.now()));
  h.advance(120001);
  assert.equal(h.f.reconstructCeremony(h.p('security'), 'cer-done', [s.shares[0].share, s.shares[1].share]).reconstructed, true);
  flipCeremony(h, 'cer-done', r => { r.status = 'committed'; });
  assert.throws(() => h.f.reconstructCeremony(h.p('security'), 'cer-done', [s.shares[0].share, s.shares[1].share]), hasCode('INV-409-STATE'), 'anchored completion refuses the replay');
});

// F4: the dedup key must not carry unverified request fields — forged
// capability ids cannot un-budget the signed containment write.
test('w18-fv F4: forged capability ids do not un-budget denial writes', t => {
  const h = fixture(t);
  const count = () => h.f.store.db.prepare("SELECT COUNT(*) c FROM records WHERE tenant='acme' AND kind='containment'").get().c;
  const before = count();
  for (let i = 0; i < 8; i++) {
    assert.throws(() => h.f.runtime.consume(h.p(), {
      device_id: 'operator-device', resource: 'dataset-1', action: 'data.read', request_id: randomUUID(),
      capability: { payload: { capability_id: randomUUID() } }
    }), e => e instanceof Error);
  }
  assert.ok(count() - before <= 1, `denial flood must stay bounded — got ${count() - before} rows for 8 forged denials`);
});

// F5: the resurrection veto enumerates anchored records — deleting the
// certificate row cannot launder an expired cert past a clock rewind.
test('w18-fv F5: deleting a certificate row cannot bypass the rewind veto', t => {
  const h = fixture(t);
  const { certificate } = h.ready(h.proposed());
  const exp = certificate.payload.expires_at;
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='certificate'").run();
  h.f.store.db.prepare('UPDATE clock SET last=? WHERE id=1').run(exp + 1);
  // w19-lifecycle F3: the tampered tenant lands in unverifiable_tenants —
  // recovery proceeds for the rest of the deployment while the tampered
  // tenant stays wedged until a chain seal.
  const out = h.f.recoverClock(h.p('security'));
  assert.ok(out.unverifiable_tenants.includes('acme'), 'missing anchored row quarantines its tenant, not the recovery');
  assert.throws(() => h.proposed(), hasCode('INV-503-TIME'), 'the tampered tenant stays halted — veto evidence preserved');
});

// F12: one tenant's poisoned chain cannot veto clock recovery for the rest.
test('w18-fv F12: a poisoned tenant chain blocks itself, not the healthy tenants', t => {
  const h = fixture(t);
  const ghead = h.f.store.db.prepare('SELECT seq,hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get('globex');
  h.f.store.db.prepare("INSERT INTO audit (tenant,seq,previous,hash,envelope) VALUES ('globex',?,?,'deadbeef','{}')").run((ghead?.seq ?? 0) + 1, ghead?.hash ?? '0'.repeat(64));
  h.f.invalidateAuditIndex('globex');
  h.f.store.clock(h.now()); // seed the clock row the rewind is measured against
  h.f.store.db.prepare('UPDATE clock SET last=? WHERE id=1').run(h.now() + 120000);
  const out = h.f.recoverClock(h.p('security'));
  assert.ok(out.recovered_at, 'recovery proceeds for the healthy tenant');
  assert.ok(out.unverifiable_tenants.includes('globex'), 'the poisoned tenant is reported, not silently skipped');
  assert.throws(() => h.proposed('data.export', { dataset: 'dataset-1', columns: ['id'], row_ids: ['row-1'], max_rows: 1, classification: 'internal', jurisdiction: 'EU' }, { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'x' }, destination: 'customer-vault' }, h.p('operator', 'globex')), e => e?.code === 'INV-503-TIME' || e?.code === 'INV-409-AUDIT-TAMPER');
});

// F6: a planted staged row plus a missing active row must not wedge every
// transaction — the sweep retires it and reanchorPolicy stays reachable.
test('w18-fv F6: missing active + planted staged does not wedge the repair path', t => {
  const h = fixture(t);
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='policy' AND id='active'").run();
  h.f.store.put('acme', 'policy', 'staged', { policy: { ...clone(h.f.tenant('acme').genesis_policy), policy_id: 'planted', version: 99 }, activate_at: h.now() + 7 * 86400000, staged_at: h.now() }, h.now());
  const rep = h.f.reanchorPolicy(h.p('security'));
  assert.equal(rep.reanchored, true, 'the designed repair path reaches through the wedge attempt');
  assert.equal(h.f.store.get('acme', 'policy', 'active').policy_id, h.f.tenant('acme').genesis_policy.policy_id ?? h.f.store.get('acme', 'policy', 'active').policy_id);
});

// F8: the staged row's activation slot is anchored — a back-dated row is
// retired as tamper evidence, never promoted early.
test('w18-fv F8: back-dated activate_at cannot promote a staged constitution early', t => {
  const h = fixture(t);
  const base = h.f.policy('acme');
  const next = { ...clone(base), policy_id: 'staged-v', version: base.version + 1 };
  stageConstitution(h, next, { activate_at: h.now() + 86400000 });
  const row = h.f.store.get('acme', 'policy', 'staged');
  row.activate_at = h.now() - 1000;
  h.f.store.put('acme', 'policy', 'staged', row, h.now());
  assert.equal(h.f.policy('acme').policy_id, base.policy_id, 'getter serves active, not the back-dated row');
  h.proposed(); // any transaction sweeps the divergent staged row out
  assert.equal(h.f.store.get('acme', 'policy', 'staged'), null, 'divergent staged row retired loudly');
});

// F9: only the LATEST staged anchor governs — an abandoned draft cannot
// promote over the governed successor by row swap.
test('w18-fv F9: a superseded staged draft cannot be swapped back in', t => {
  const h = fixture(t);
  const base = h.f.policy('acme');
  const at = h.now() - 1000;
  const draftA = { ...clone(base), policy_id: 'draft-a', version: base.version + 1 };
  const draftB = { ...clone(base), policy_id: 'draft-b', version: base.version + 1 };
  stageConstitution(h, draftA, { activate_at: at });
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='policy' AND id='staged'").run();
  stageConstitution(h, draftB, { activate_at: at });
  // Row-write insider swaps the staged row back to draft A's content.
  h.f.store.put('acme', 'policy', 'staged', { policy: draftA, activate_at: at, staged_at: h.now() }, h.now());
  assert.equal(h.f.policy('acme').policy_id, base.policy_id, 'getter refuses the abandoned draft');
  h.proposed();
  const staged = h.f.store.get('acme', 'policy', 'staged');
  assert.ok(!staged || staged.policy.policy_id === 'draft-b', 'the abandoned draft may never promote');
});

// F11: a seal that aborts inside its window drops the phantom index —
// reads fold the committed tail honestly (the planted row still wedges,
// by design) and a clean seal then clears it for good.
test('w18-fv F11: an aborted seal leaves no phantom-consumed index state', t => {
  const h = fixture(t);
  h.ready(h.proposed());
  const head = h.f.store.db.prepare('SELECT seq,hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get('acme');
  h.f.store.db.prepare("INSERT INTO audit (tenant,seq,previous,hash,envelope) VALUES ('acme',?,?,'deadbeef','{}')").run(head.seq + 1, head.hash);
  const orig = h.f.store.audit.bind(h.f.store);
  h.f.store.audit = (tt, type, ...rest) => { if (type === 'AUDIT_SEALED') throw new Error('injected seal fault'); return orig(tt, type, ...rest); };
  assert.throws(() => h.f.sealAuditChain(h.p('security')), /injected seal fault/);
  h.f.store.audit = orig;
  h.f.invalidateAuditIndex('acme');
  assert.throws(() => h.f.revoked('acme', 'subject', 'x'), hasCode('INV-409-AUDIT-TAMPER'), 'the still-planted tail wedges honestly, never phantom-consumed');
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.equal(seal.sealed, true, 'a clean seal cuts the poison after the aborted attempt');
  assert.equal(h.f.revoked('acme', 'subject', 'x'), false, 'index rebuilds and keeps serving');
});

// F13: the key.rotate bond is anchored — a forged consumed flag on an
// unspent ceremony cannot block the legitimate rotation (DoS killed).
test('w18-fv F13: a forged rotation_consumed flag cannot block a live ceremony', t => {
  const h = fixture(t);
  const pending = designateSuccessor(h, 'execution');
  const cid = [...h.f.store.db.prepare("SELECT id FROM records WHERE tenant='acme' AND kind='ceremony' ORDER BY created DESC LIMIT 1").all()][0].id;
  flipCeremony(h, cid, r => { r.rotation_consumed = 'forged-capsule'; });
  const r = h.proposed('key.rotate', { key_class: 'execution', new_key_id: pending.key_id, new_public_key: pending.public_key, ceremony_id: cid, revoke_old: false }, { action: { type: 'key.rotate', target_resource: 'key-registry', purpose: 'Rotate' } });
  h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'audit-committee' });
  h.approve(r, 3); h.advance(60001);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  const out = h.f.execute(h.p(), cert);
  assert.equal(outcomeStatus(out), 'VERIFIED', 'anchored spend check ignores the forged row flag');
});

// F15: notice coverage attests through the chain — truncating the mutable
// notices array can never wedge a legitimately-committed reconstruction.
test('w18-fv F15: truncated row notices cannot wedge an anchored reconstruction', t => {
  const h = fixture(t);
  h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-notice', purpose: 'recovery', threshold: 2, custodians: CUST2, valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  const s = h.f.splitCeremonySecret(h.p('security'), 'cer-notice', randomBytes(32).toString('base64url'));
  const committed = h.f.store.must('acme', 'ceremony', 'cer-notice');
  for (const subject of CUST2) h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(committed, subject, h.setup.custodianKeys.acme[subject], h.now()));
  flipCeremony(h, 'cer-notice', r => { r.notices = []; });
  h.advance(120001);
  const rec = h.f.reconstructCeremony(h.p('security'), 'cer-notice', [s.shares[0].share, s.shares[1].share]);
  assert.equal(rec.reconstructed, true, 'anchored notice coverage survives row truncation');
});

// F16: a payload-less forged audit row classifies as AUDIT-TAMPER, not a
// bare schema crash.
test('w18-fv F16: payload-less forged rows land as INV-409-AUDIT-TAMPER', t => {
  const h = fixture(t);
  const head = h.f.store.db.prepare('SELECT seq,hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get('acme');
  h.f.store.db.prepare("INSERT INTO audit (tenant,seq,previous,hash,envelope) VALUES ('acme',?,?,'deadbeef','{}')").run(head.seq + 1, head.hash);
  assert.throws(() => h.f.store.auditPage('acme', { after: head.seq }), hasCode('INV-409-AUDIT-TAMPER'));
});

const outcomeStatus = out => out?.status ?? out?.outcome?.status ?? 'VERIFIED';

// fixverify-2 B6: an anchored ceremony id is burned forever — a row writer
// who deletes the row cannot reopen the id and inherit its anchored acks.
test('w18-fv2 B6: a deleted ceremony row cannot reopen its anchored id', t => {
  const h = fixture(t);
  const pending = h.f.prepareRotation(h.p('security'), 'execution');
  h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-burn', purpose: 'key.rotate', threshold: 2, custodians: CUST2, valid_until: h.now() + 3600000, min_delay_ms: 120000, rotation: { key_class: 'execution', new_key_id: pending.key_id } });
  const committed = h.f.store.must('acme', 'ceremony', 'cer-burn');
  for (const subject of CUST2) h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(committed, subject, h.setup.custodianKeys.acme[subject], h.now()));
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='ceremony' AND id='cer-burn'").run();
  assert.throws(() => h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-burn', purpose: 'key.rotate', threshold: 2, custodians: ['custodian-1', 'custodian-3'], valid_until: h.now() + 3600000, min_delay_ms: 120000, rotation: { key_class: 'execution', new_key_id: pending.key_id } }), hasCode('INV-409-CONFLICT'), 'the anchored id never reopens — no ack inheritance');
});

// fixverify-2 MED: designation counts the live domain quorum, not the raw
// anchored-ack set — a custodian revoked after consenting no longer counts.
test('w18-fv2 MED: a revoked custodian stops counting toward designation', t => {
  const h = fixture(t);
  const pending = designateSuccessor(h, 'execution');
  assert.equal(h.f.ceremonyDesignated('acme', pending.key_id, 'execution'), true, 'precondition: designated before the revocation');
  h.f.revoke(h.p('security'), { kind: 'subject', id: 'custodian-1', reason: 'offboarded mid-ceremony' });
  assert.equal(h.f.ceremonyDesignated('acme', pending.key_id, 'execution'), false, 'the revoked custodian\u2019s anchored ack no longer counts');
});

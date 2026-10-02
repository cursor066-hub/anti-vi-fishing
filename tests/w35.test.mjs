// w35: fixverify (devin-40a598e2) + runtime-gate (devin-5b675a4c) reports —
// the seal's doom boundary, head semantics and floor handling attacked with
// write-only insider primitives: tail-deletion laundering, stored-column
// surgery on doomed rows, planted floor rows aimed at the sealer, and
// checkpoint-floor deletion under a surviving head.
import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, runtimeInput, runtimeRequest } from './helpers.mjs';

const dropAuditGuards = h => {
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
    h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
};
const corruptAt = (h, seq) =>
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?").run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', seq);
const seqOf = (h, pattern) =>
  h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND envelope LIKE ? ORDER BY seq").get(pattern)?.seq;
const sealMeta = h => JSON.parse(h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND envelope LIKE '%AUDIT_SEALED%' ORDER BY seq DESC LIMIT 1").get().envelope).payload.metadata;
const maxSeq = h => h.f.store.db.prepare("SELECT COALESCE(MAX(seq),0) m FROM audit WHERE tenant='acme'").get().m;
const auditEvents = h => h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND envelope LIKE ?").all('%AUDIT_HEAD_REANCHORED%').map(r => JSON.parse(r.envelope).payload);

// --- F-1 (runtime-gate HIGH): delete the tail behind a signed head -------
// The head/watermark keep seq+hash high while the doomed region verifies —
// the old code returned 'chain already verifies' and laundered the loss.
test('w35 F-1: tail deletion under a surviving head attests the abandoned tip', t => {
  const h = fixture(t);
  const { certificate } = h.ready();
  h.f.execute(h.p('operator'), certificate);
  const tipSeq = maxSeq(h);
  const tipHash = h.f.store.db.prepare("SELECT hash FROM audit WHERE tenant='acme' AND seq=?").get(tipSeq).hash;
  dropAuditGuards(h);
  h.f.store.db.prepare("DELETE FROM audit WHERE tenant='acme' AND seq>=?").run(tipSeq - 1); // survivors verify — no cut needed
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, false);
  assert.equal(r.head_regressed, true, 'the seal must name the regression, never claim clean');
  assert.ok(r.reason.includes('regressed'), r.reason);
  assert.equal(r.abandoned_head_seq, tipSeq);
  assert.equal(r.abandoned_head_hash, tipHash);
  const ev = auditEvents(h).at(-1);
  assert.equal(ev.metadata.abandoned_head_seq, tipSeq, 'the audit event attests the abandoned tip');
  assert.equal(ev.metadata.abandoned_head_hash, tipHash);
});

// Same attack, but the deleted span included a revocation event AND its
// floor row — the surviving head's residue count regresses, so the seal
// refuses rather than attest an unverifiable floor state.
test('w35 F-1b: tail deletion that regresses the revocation floor refuses', t => {
  const h = fixture(t);
  h.ready();
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ max_cost: 10 }));
  h.f.revoke(h.p('security'), { kind: 'capability', id: cap.payload.capability_id, reason: 'spent' });
  h.f.auditProof(h.p('auditor'), 1); // a signed write mints a head that claims the floor
  const revSeq = seqOf(h, '%AUTHORITY_REVOKED%');
  dropAuditGuards(h);
  h.f.store.db.prepare("DELETE FROM audit WHERE tenant='acme' AND seq>=?").run(revSeq);
  h.f.store.db.prepare("DELETE FROM deks WHERE tenant='acme' AND kind='revocation'").run();
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='revocation'").run();
  assert.throws(() => h.f.sealAuditChain(h.p('security')), e => e?.code === 'INV-409-INTEGRITY' && /floor|revocation/i.test(e.message));
});

// --- F-2 (runtime-gate HIGH): stored-column surgery on doomed rows -------
// Rewrite hash on a doomed RUNTIME_ALLOWED row — the envelope still signs
// true, so the carry must rescue the spend by payload truth.
test('w35 F-2: hash-column surgery on a doomed spend cannot launder the refund', t => {
  const h = fixture(t);
  const { certificate } = h.ready();
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ max_cost: 100 }));
  h.f.runtime.consume(h.p(), runtimeRequest(cap, { request_id: 'req-f2' }));
  h.f.execute(h.p('operator'), certificate);
  const allowSeq = seqOf(h, '%RUNTIME_ALLOWED%');
  const doomAt = seqOf(h, '%CAPABILITY_ISSUED%');
  dropAuditGuards(h);
  corruptAt(h, doomAt); // doom the spend and everything after it
  assert.ok(allowSeq > doomAt, 'spend lands inside the doomed span');
  // Surgery: rewrite the doomed spend's stored hash — old code dropped it
  // from carry (digest mismatch) AND left the row divergent.
  h.f.store.db.prepare("UPDATE audit SET hash=? WHERE tenant='acme' AND seq=?").run('FAKEHASH', allowSeq);
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  assert.ok(sealMeta(h).spend_carryover.some(u => u.request_id === 'req-f2'), 'payload truth carries the spend, stored divergence is evidence');
  assert.equal(r.carryover_totals.divergent_stored, 1, 'the divergent stored column is counted, not hidden');
  // The request id stays burned — replaying refuses (the cut issuance
  // anchor kills the capability outright; a surviving cap would hit
  // INV-409-REPLAY on the carried spend).
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap, { request_id: 'req-f2' })), e => e?.code === 'INV-409-REPLAY' || e?.code === 'INV-401-CAPABILITY');
});

// Rewrite the stored seq of a doomed row BELOW firstBad — a `seq>=firstBad`
// cut would strand it to re-wedge the rebuilt fold; the payload-defined
// doom boundary deletes it with the rest.
test('w35 F-2b: stored-seq rewrite below the cut cannot strand a doomed row', t => {
  const h = fixture(t);
  const { certificate } = h.ready();
  h.f.execute(h.p('operator'), certificate);
  const resSeq = seqOf(h, '%EXECUTION_RESERVED%');
  const outcomeSeq = seqOf(h, '%EXECUTION_OUTCOME%');
  dropAuditGuards(h);
  // Slide the doomed outcome's stored seq to an unused low value — under a
  // stored-seq cut it would survive the delete with a divergent payload.
  h.f.store.db.prepare("UPDATE audit SET seq=0 WHERE tenant='acme' AND seq=?").run(outcomeSeq);
  corruptAt(h, resSeq);
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  assert.equal(r.carryover_totals.divergent_stored >= 1, true);
  assert.doesNotThrow(() => h.f._auditIndex('acme'), 'no stranded divergent row re-wedges the fold');
});

// Deleted doomed rows are named as payload-seq gaps — the chain cannot
// re-derive what it deleted, so the seal attests the range.
test('w35 F-2c: deleted doomed rows are attested as deleted_gaps', t => {
  const h = fixture(t);
  const { certificate } = h.ready();
  h.f.execute(h.p('operator'), certificate);
  const resSeq = seqOf(h, '%EXECUTION_RESERVED%');
  const dispSeq = seqOf(h, '%EXECUTION_DISPATCHED%');
  dropAuditGuards(h);
  h.f.store.db.prepare("DELETE FROM audit WHERE tenant='acme' AND seq=?").run(dispSeq);
  corruptAt(h, resSeq);
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  assert.ok(r.deleted_gaps.some(([from, to]) => from <= dispSeq && to >= dispSeq), `deleted_gaps names seq ${dispSeq}: ${JSON.stringify(r.deleted_gaps)}`);
});

// --- F-3 (runtime-gate HIGH): planted floor rows ------------------------
// A planted revocation floor on an arbitrary subject + one corrupted row:
// the seal carries it floor_derived, enforces it, NAMES it — and the
// operator it aims at is not bricked out of the repair.
test('w35 F-3: a planted floor row is carried, enforced, named — and cannot brick the sealer', t => {
  const h = fixture(t);
  const { certificate } = h.ready();
  h.f.execute(h.p('operator'), certificate);
  h.f.store.put('acme', 'revocation', 'subject:security', { kind: 'subject', id: 'security', reason: 'planted', revoked_at: h.now(), revoked_by: 'attacker' }, h.now());
  dropAuditGuards(h);
  corruptAt(h, seqOf(h, '%EXECUTION_RESERVED%'));
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true, 'a planted unverifiable claim cannot brick the operator running the repair');
  assert.ok(r.floor_derived.includes('subject:security'), 'the planted ref is named on the result');
  assert.equal(h.f.revoked('acme', 'subject', 'security'), true, 'fail closed: the planted claim still enforces');
  const items = h.f.revocations(h.p('auditor')).items;
  assert.equal(items.find(i => i.id === 'security')?.anchored, 'floor-derived', 'the report labels the carry honestly');
});

// The planted floor's content is convicted when a verifiable anchor for
// the same ref sits in the doomed span — record_digest mismatch names the
// row under planted_floor_refs.
test('w35 F-3b: a floor row whose content fails its anchored digest is convicted as planted', t => {
  const h = fixture(t);
  const { certificate } = h.ready();
  h.f.execute(h.p('operator'), certificate);
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ max_cost: 10 }));
  h.f.revoke(h.p('security'), { kind: 'capability', id: cap.payload.capability_id, reason: 'honest revocation' });
  // Tamper the stored floor value — the doomed AUTHORITY_REVOKED still
  // anchors the honest content by record_digest.
  h.f.store.put('acme', 'revocation', `capability:${cap.payload.capability_id}`, { kind: 'capability', id: cap.payload.capability_id, reason: 'PLANTED rewrite', revoked_at: h.now(), revoked_by: 'attacker' }, h.now());
  dropAuditGuards(h);
  corruptAt(h, seqOf(h, '%EXECUTION_RESERVED%'));
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  assert.ok(r.planted_floor_refs.includes(`capability:${cap.payload.capability_id}`), 'planted content is convicted by its own anchored digest');
  assert.ok(!r.floor_derived.includes(`capability:${cap.payload.capability_id}`), 'a doomed-span anchor carries by its event, not by the floor');
});

// --- H-2/M-3: the re-anchor path ---------------------------------------
// A floor-derived-only ref may be re-anchored by a fresh signed
// revocation so the floor regains real evidence.
test('w35 M-3: a floor-derived revocation can be re-anchored by a fresh revoke', t => {
  const h = fixture(t);
  h.ready();
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ max_cost: 10 }));
  h.f.revoke(h.p('security'), { kind: 'capability', id: cap.payload.capability_id, reason: 'first' });
  dropAuditGuards(h);
  corruptAt(h, seqOf(h, '%AUTHORITY_REVOKED%'));
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  assert.ok(r.floor_derived.includes(`capability:${cap.payload.capability_id}`));
  assert.doesNotThrow(() => h.f.revoke(h.p('security'), { kind: 'capability', id: cap.payload.capability_id, reason: 're-anchored' }), 're-anchor is permitted for floor-derived-only refs');
  const items = h.f.revocations(h.p('auditor')).items;
  assert.equal(items.find(i => i.id === cap.payload.capability_id)?.anchored, true, 're-anchored ref verifies against its new anchor');
});

// --- H-1: planted key: floor aimed at the configured signer -------------
// Planting key:<configured-kid> must not brick the seal silently — the
// INV-503 refusal names the carried key deaths so the runbook points at
// the planted row.
test('w35 H-1: a planted key: floor aimed at the signer names itself in the refusal', t => {
  const h = fixture(t);
  const { certificate } = h.ready();
  h.f.execute(h.p('operator'), certificate);
  const auditKid = h.f.tenant('acme').keys?.audit?.key_id;
  assert.ok(auditKid);
  h.f.store.put('acme', 'revocation', `key:${auditKid}`, { kind: 'key', id: auditKid, reason: 'planted', revoked_at: h.now(), revoked_by: 'attacker' }, h.now());
  dropAuditGuards(h);
  corruptAt(h, seqOf(h, '%EXECUTION_RESERVED%'));
  // The floor kills the configured signer — no live successor exists in
  // this fixture's vault, so the seal must refuse LOUDLY.
  assert.throws(() => h.f.sealAuditChain(h.p('security')), e => e?.code === 'INV-503-CONFIG' && e.message.includes(auditKid), 'the refusal names the blocking key ref');
});

// --- L-6: planted floor on a clean chain is disclosed -------------------
test('w35 L-6: a divergent floor on a verifying chain is named in the no-cut result', t => {
  const h = fixture(t);
  h.ready();
  h.f.store.put('acme', 'revocation', 'subject:phantom', { kind: 'subject', id: 'phantom', reason: 'planted', revoked_at: h.now(), revoked_by: 'attacker' }, h.now());
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, false);
  assert.ok(r.floor_divergent.includes('subject:phantom'), 'the seal names residue it refuses to silently keep');
});

// --- L-1: checkpoint floor deletion under a surviving head --------------
test('w35 L-1: deleting an old checkpoint row regresses below the signed head', t => {
  const h = fixture(t);
  h.ready();
  h.f.exportAudit(h.p('auditor'), 'quarterly review'); // mints a witness checkpoint
  const cps = h.f.store.ids('acme', 'audit-checkpoint', 100);
  assert.ok(cps.length >= 1);
  h.f.store.db.prepare("DELETE FROM deks WHERE tenant='acme' AND kind='audit-checkpoint'").run();
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='audit-checkpoint'").run();
  assert.throws(() => h.f._auditIndex('acme'), e => e?.code === 'INV-409-INTEGRITY' && /checkpoint/i.test(e.message));
});

// --- L-2: verifyAuditProof binds the tenant ----------------------------
test('w35 L-2: verifyAuditProof refuses a cross-tenant proof', t => {
  const h = fixture(t);
  h.f.store.audit('acme', 'AUDIT_ACCESSED', 'security', 'audit', {}, h.now());
  const proof = h.f.auditProof(h.p('auditor'), 1);
  assert.equal(h.f.verifyAuditProof('acme', proof), true);
  assert.throws(() => h.f.verifyAuditProof('globex', proof), e => e?.code === 'INV-403-SCOPE');
});

// --- H-1b: proofs carry a pin for external witnessing -------------------
test('w35 H-1b: auditProof exposes a pin the operator can store off-box', t => {
  const h = fixture(t);
  h.ready();
  const proof = h.f.auditProof(h.p('auditor'), 1);
  assert.equal(proof.pin.root, proof.root);
  assert.equal(proof.pin.size, proof.size);
  assert.equal(h.f.verifyAuditProof('acme', proof, proof.pin), true, 'the pin is the verification anchor');
});

// --- M-1: doomed RETENTION_DELETED carries (regression, w34 wave) -------
test('w35 M-1: a doomed retention tombstone survives the seal via lifecycle carryover', t => {
  const h = fixture(t);
  h.ready();
  const fresh = h.proposed();
  const ev = h.evidence(fresh, { kind: 'ownership' });
  h.f.cancel(h.p(), fresh.capsule.capsule_id); // terminal — evidence no longer a live ref
  // Corrupt the evidence row so the sweep shreds it and anchors a
  // RETENTION_DELETED tombstone — then doom the tombstone event itself.
  h.f.store.db.prepare("UPDATE deks SET wrapped='tampered' WHERE tenant='acme' AND kind='evidence' AND id=?").run(ev.payload.evidence_id);
  h.f.retentionSweep(h.p('security'));
  const tombSeq = seqOf(h, '%RETENTION_DELETED%');
  assert.ok(tombSeq, 'the sweep anchored a signed tombstone');
  dropAuditGuards(h);
  // Doom the span containing the tombstone — the tombstone row itself must
  // stay verifiable so it is carried, not dropped.
  corruptAt(h, seqOf(h, '%ACTION_CANCELLED%'));
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  assert.ok(sealMeta(h).lifecycle_carryover.some(c => c.type === 'RETENTION_DELETED'), 'the tombstone re-anchors under the seal');
  assert.ok(h.f._auditIndex('acme').tombstones?.has(ev.payload.evidence_id), 'the carried tombstone still protects the integrity carve');
});

// w37: seal residue honesty wave — carry pages bind the seal's REAL seq
// (the repoint's interposed CONFIG_SNAPSHOT used to slide it), carried
// KEY_ROTATED rows kill the old signer before the seal's own writes, every
// remediation path recounts attested carry residue instead of healing
// amputations, the cut consults the signed head's floor/checkpoint claims,
// murdered revocation floor rows are named and re-anchorable, and the
// standalone verifiers share the reference-based key-death window.
import test from 'node:test';
import assert from 'node:assert/strict';
import { rmSync } from 'node:fs';
import { join } from 'node:path';
import { fixture, designateSuccessor } from './helpers.mjs';
import { digest, canonical } from '../src/canonical.mjs';

const dropAuditGuards = h => {
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
    h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
};
const corruptAt = (h, seq) =>
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?")
    .run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', seq);
const delRow = (h, seq) => h.f.store.db.prepare("DELETE FROM audit WHERE tenant='acme' AND seq=?").run(seq);
const delRecord = (h, kind, id) => {
  h.f.store.db.prepare('DELETE FROM deks WHERE tenant=? AND kind=? AND id=?').run('acme', kind, id);
  h.f.store.db.prepare('DELETE FROM records WHERE tenant=? AND kind=? AND id=?').run('acme', kind, id);
};
const chainRows = h => h.f.store.db.prepare("SELECT seq,envelope FROM audit WHERE tenant='acme' ORDER BY seq").all()
  .map(r => ({ seq: r.seq, env: JSON.parse(r.envelope) }));
const seqOf = (h, like) => h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND envelope LIKE ? ORDER BY seq DESC LIMIT 1").get(like).seq;
const lastSeq = h => h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get().seq;

// A seal that must carry >512 lifecycle entries (=> pages) while the audit
// signer dies inside the doomed span — the F-A interposition scenario.
const buildSealedWithPages = t => {
  const h = fixture(t);
  const auditKid = h.f.tenant('acme').keys.audit.key_id;
  const pending = designateSuccessor(h, 'audit');
  for (let i = 0; i < 600; i++) h.f.store.audit('acme', 'W37_PAD', 'operator', `pad-${i}`, { i }, h.now());
  const rot = h.f.store.audit('acme', 'KEY_ROTATED', 'security', pending.key_id, { key_class: 'audit', previous_key_id: auditKid, revoke_old: false }, h.now());
  const rotSeq = rot.envelope.payload.sequence;
  dropAuditGuards(h);
  corruptAt(h, seqOf(h, '%pad-0%')); // dooms the 600 pads + the rotation
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  return { h, auditKid, pending, rotSeq, r };
};

test('w37 F-A: carry pages bind the seal row that actually exists, not the nominal cut point', t => {
  const { h, pending, r } = buildSealedWithPages(t);
  const rows = chainRows(h);
  const seal = rows.find(x => x.env.payload.type === 'AUDIT_SEALED');
  const pages = rows.filter(x => x.env.payload.type === 'AUDIT_SEAL_CARRY');
  assert.ok(pages.length >= 1, 'carryover >512 must spill onto pages');
  // The repoint interposed a CONFIG_SNAPSHOT at sealed_at_seq: the seal
  // landed one slot later — pages stamped with the nominal seq would wedge
  // the fold's seal_seq bind forever (F-A).
  assert.ok(seal.env.payload.sequence > seal.env.payload.metadata.sealed_at_seq, 'interposed snapshot moved the seal row');
  assert.equal(r.seal_seq, seal.env.payload.sequence);
  for (const p of pages) assert.equal(p.env.payload.metadata.seal_seq, seal.env.payload.sequence);
  // F-B: the pages are signed by the designated successor, never the dead key.
  for (const p of pages) assert.equal(p.env.protected.key_id, pending.key_id);
  assert.doesNotThrow(() => h.f._auditIndex('acme'), 'sealed chain must fold cleanly');
});

test('w37 F-D: a carried KEY_ROTATED pins the death at its own seq, not the page seq', t => {
  const { h, auditKid, rotSeq } = buildSealedWithPages(t);
  const idx = h.f._auditIndex('acme');
  assert.equal(idx.keyDeadAt.get(auditKid), rotSeq, 'carried rotation death must pin at the original chain position');
});

test('w37 F-B: a doomed-but-carried rotation repoints to its own attested successor, never dead-signs', t => {
  const h = fixture(t);
  const auditKid = h.f.tenant('acme').keys.audit.key_id;
  const pending = h.f.prepareRotation(h.p('security'), 'audit');
  h.f.store.audit('acme', 'KEY_ROTATED', 'security', pending.key_id, { key_class: 'audit', previous_key_id: auditKid, revoke_old: false }, h.now());
  dropAuditGuards(h);
  corruptAt(h, seqOf(h, '%KEY_ROTATED%') - 1);
  // The doomed rotation row is itself a verified chain designation — the
  // seal's carry re-attests its successor, so the repoint sees pending and
  // signs every carry page under it, never the condemned key (w47-seal F-3).
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  const rows = chainRows(h);
  const seal = rows.find(x => x.env.payload.type === 'AUDIT_SEALED');
  assert.equal(seal.env.protected.key_id, pending.key_id, 'the seal row signs under the carried successor');
  for (const p of rows.filter(x => x.env.payload.type === 'AUDIT_SEAL_CARRY'))
    assert.equal(p.env.protected.key_id, pending.key_id, 'carry pages sign under the successor, not the dead key');
  assert.doesNotThrow(() => h.f._auditIndex('acme'), 'sealed chain must fold cleanly');
});

test('w37 F-H: deleting a carry page refuses remediation on every path', t => {
  // Early path: the amputated page plus every row above it is destroyed —
  // the prescan sees a clean chain but the surviving seal's attestation no
  // longer holds. (The cut mints an AUDIT_WM_REANCHORED attestation above
  // the carry pages since w52-fv, so the tip row itself is no longer a
  // page — delete it too to keep the prefix contiguous.)
  {
    const { h, r } = buildSealedWithPages(t);
    const pages = chainRows(h).filter(x => x.env.payload.type === 'AUDIT_SEAL_CARRY');
    dropAuditGuards(h);
    for (const row of chainRows(h).filter(x => x.seq >= pages.at(-1).seq)) delRow(h, row.seq);
    assert.throws(() => h.f.sealAuditChain(h.p('security')), e => e?.code === 'INV-409-INTEGRITY' && /carryover page|amputated/.test(e.message));
  }
  // Cut path: a middle page is amputated, leaving a corruption gap plus the
  // residue shortfall — the seal still refuses.
  {
    const { h } = buildSealedWithPages(t);
    const pages = chainRows(h).filter(x => x.env.payload.type === 'AUDIT_SEAL_CARRY');
    const mid = pages[0];
    dropAuditGuards(h);
    delRow(h, mid.seq);
    corruptAt(h, mid.seq + 1); // force the cut path so the residue check runs inside it too
    assert.throws(() => h.f.sealAuditChain(h.p('security')), e => e?.code === 'INV-409-INTEGRITY');
  }
});

test('w37 HIGH-1: the cut consults the signed head — regressed revocation floor refuses', t => {
  const h = fixture(t); h.ready();
  h.f.revoke(h.p('security'), { kind: 'subject', id: 'auditor', reason: 'drill' });
  const head = h.f._chainHead('acme');
  assert.ok(head && head.revocations >= 1, 'head must attest the revocation floor');
  dropAuditGuards(h);
  delRecord(h, 'revocation', 'subject:auditor');
  corruptAt(h, lastSeq(h));
  assert.throws(() => h.f.sealAuditChain(h.p('security')), e => e?.code === 'INV-409-INTEGRITY' && /revocation floor|checkpoint/.test(e.message));
});

test('w37 HIGH-1: a cut under an attested tip names the retired head', t => {
  // The head attests exactly the tip the cut retires — self-inflicted
  // abandonment the seal's own carry claims already account for, so the
  // record names it 'superseded' (w52-fv: 'abandoned' is reserved for
  // attestation the seal did NOT itself retire, and convicts the fold).
  {
    const h = fixture(t); h.ready();
    const head = h.f._chainHead('acme');
    assert.ok(head && head.seq > 0);
    dropAuditGuards(h);
    corruptAt(h, lastSeq(h) - 2); // a mid-chain cut: the head attests a tip that no longer exists
    const r = h.f.sealAuditChain(h.p('security'));
    assert.equal(r.sealed, true);
    assert.equal(r.superseded_head_seq, head.seq);
    assert.equal(r.superseded_head_hash, head.hash);
    const seal = chainRows(h).find(x => x.env.payload.type === 'AUDIT_SEALED');
    assert.equal(seal.env.payload.metadata.superseded_head_seq, head.seq);
  }
  // Tail destruction on top of the cut: the head attests content the seal
  // did NOT retire — a real abandoned-head conviction.
  {
    const h = fixture(t); h.ready();
    const head = h.f._chainHead('acme');
    dropAuditGuards(h);
    delRow(h, lastSeq(h)); delRow(h, lastSeq(h)); // tip falls below the attested head
    corruptAt(h, lastSeq(h) - 1); // force the cut path
    const r = h.f.sealAuditChain(h.p('security'));
    assert.equal(r.sealed, true);
    assert.equal(r.abandoned_head_seq, head.seq);
    const seal = chainRows(h).find(x => x.env.payload.type === 'AUDIT_SEALED');
    assert.equal(seal.env.payload.metadata.abandoned_head_seq, head.seq);
  }
});

test('w37 HIGH-1/L-1: an unverifiable stored tail counts toward deleted_gaps_total', t => {
  const h = fixture(t); h.ready();
  const tip = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get().seq;
  dropAuditGuards(h);
  corruptAt(h, tip - 1); // mid-span corruption forces the cut
  corruptAt(h, tip); // the tail is corrupt-but-stored: unverifiable residue beyond the last good payload
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  assert.ok(r.carryover_totals.deleted_gaps_total >= 1);
  assert.ok(r.deleted_gaps.some(g => g[0] <= tip && g[1] >= tip), 'the unverifiable tail must be named as a gap');
});

test('w37 M-1: a murdered revocation floor is named, listed, and re-anchorable', t => {
  const h = fixture(t); h.ready();
  h.f.revoke(h.p('security'), { kind: 'subject', id: 'auditor', reason: 'drill' });
  for (let i = 0; i < 2; i++) h.f.store.audit('acme', 'W37_PAD', 'operator', `pad-${i}`, {}, h.now()); // the anchor must SURVIVE the cut
  // No surviving head claim may veto this scenario — remove the head files
  // entirely so only the chain itself speaks.
  rmSync(join(h.directory, 'chain-heads.json'), { force: true });
  rmSync(join(h.directory, 'head-watermark.json'), { force: true });
  dropAuditGuards(h);
  delRecord(h, 'revocation', 'subject:auditor'); // floor murdered, anchor survives
  corruptAt(h, lastSeq(h));
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  assert.ok(r.murdered_floor_refs.includes('subject:auditor'), `murdered floor must be named, got ${JSON.stringify(r.murdered_floor_refs)}`);
  const list = h.f.revocations(h.p('security'));
  const item = list.items.find(i => i.kind === 'subject' && i.id === 'auditor');
  assert.equal(item?.anchored, 'anchorless-carried');
  // Re-anchor path: the digested anchor survives but the floor row is gone —
  // a fresh signed revocation re-mints it instead of refusing forever.
  const env = h.f.revoke(h.p('security'), { kind: 'subject', id: 'auditor', reason: 're-anchor after floor murder' });
  assert.ok(env);
  assert.ok(h.f.store.get('acme', 'revocation', 'subject:auditor') !== null, 'floor row re-minted');
});

test('w37 L-2: a surviving-anchored floor row with rewritten content is convicted, not skipped', t => {
  const h = fixture(t); h.ready();
  h.f.revoke(h.p('security'), { kind: 'subject', id: 'auditor', reason: 'drill' });
  for (let i = 0; i < 2; i++) h.f.store.audit('acme', 'W37_PAD', 'operator', `pad-${i}`, {}, h.now()); // the anchor must SURVIVE the cut
  // Rewrite the floor row's ciphertext — the anchor survives below the cut.
  h.f.store.db.prepare("UPDATE records SET value=? WHERE tenant='acme' AND kind='revocation' AND id='subject:auditor'").run('planted');
  dropAuditGuards(h);
  corruptAt(h, lastSeq(h));
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  assert.ok(r.planted_floor_refs.includes('subject:auditor'), 'planted floor content under a surviving anchor must be named');
  assert.equal(r.floor_derived.includes('subject:auditor'), false, 'a digested anchor means the row is never orphaned');
});

test('w37 L-3: planted audit-checkpoint rows cannot inflate the attested floor', t => {
  const h = fixture(t);
  h.f.exportAudit(h.p('auditor'), 'checkpoint drill');
  const head = h.f._chainHead('acme');
  assert.ok(head?.checkpoints >= 1, 'head must attest the export checkpoint');
  // Plant a garbage cp row and delete the real one — raw row count stays
  // constant while verified count regresses to zero.
  h.f.store.db.prepare("INSERT INTO records(tenant,kind,id,value,created) VALUES('acme','audit-checkpoint','cp-planted','{}',0)").run();
  for (const id of h.f.store.db.prepare("SELECT id FROM records WHERE tenant='acme' AND kind='audit-checkpoint' AND id LIKE 'cp-%'").all().map(r => r.id))
    if (id !== 'cp-planted') delRecord(h, 'audit-checkpoint', id);
  assert.throws(() => h.f._auditIndex('acme'), e => e?.code === 'INV-409-INTEGRITY');
});

test('w37 F-C: a row signed after its key-revocation seq fails every verifier path', t => {
  const h = fixture(t);
  const pending = h.f.prepareRotation(h.p('security'), 'audit'); // pending vault key, never the live signer
  h.f.store.audit('acme', 'AUTHORITY_REVOKED', 'security', `key:${pending.key_id}`, { reason: 'drill' }, h.now());
  // Forge exactly what a store-level insider would plant: a VALID k2
  // signature over a payload sequenced after the key's death — the
  // signature verifies, the position is the lie.
  const last = h.f.store.db.prepare("SELECT seq,hash FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get();
  const payload = { tenant_id: 'acme', sequence: last.seq + 1, previous: last.hash, type: 'W37_DEAD_SIGNED', actor: 'operator', reference: 'x', metadata: {}, time: h.now() };
  const env = h.f.vault.envelope(pending.key_id, 'audit', payload, { allowPending: true, tenant_id: 'acme' });
  dropAuditGuards(h);
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', payload.sequence, payload.previous, digest(payload), canonical(env));
  assert.throws(() => h.f._auditIndex('acme'), e => /^INV-409/.test(e?.code ?? ''));
  assert.throws(() => h.f.exportAudit(h.p('auditor'), 'parity'), e => /^INV-409/.test(e?.code ?? ''));
});

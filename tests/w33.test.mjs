// w33 regressions — seal/carryover 2nd pass: floor-orphaned revocations fail
// closed (F-1), a revoked caller cannot self-seal a corrupted revocation
// (F-1b), mirror tables never enter signed carryover (F-2/F-3/F-5), carryover
// pages bound the seal write (F-4), carryover forwarding across seals (F-6),
// offline key-death window agrees with the fold (O-3).
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fixture, hasCode, runtimeInput, runtimeRequest, designateSuccessor } from './helpers.mjs';
import { digest } from '../src/canonical.mjs';
import { merkleRoot, verifyInclusion } from '../src/merkle.mjs';
import { createServer } from '../src/server.mjs';

const dropAuditTriggers = db => { for (const tr of db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all()) db.exec(`DROP TRIGGER "${String(tr.name).replace(/"/g, '""')}"`); };
const restoreAuditTriggers = db => db.exec(`
  CREATE TRIGGER no_audit_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
  CREATE TRIGGER no_audit_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
  CREATE TRIGGER audit_seq_guard BEFORE INSERT ON audit WHEN NEW.seq <> (SELECT COALESCE(MAX(seq),0)+1 FROM audit WHERE tenant=NEW.tenant) BEGIN SELECT RAISE(ABORT, 'audit sequence must extend the head'); END;`);
const corruptAt = (h, seq) => {
  dropAuditTriggers(h.f.store.db);
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?").run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', seq);
  restoreAuditTriggers(h.f.store.db);
};
const seqOf = (h, like) => h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND envelope LIKE ? ORDER BY seq DESC LIMIT 1").get(like).seq;
const sealMeta = h => JSON.parse(h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND envelope LIKE '%AUDIT_SEALED%' ORDER BY seq DESC LIMIT 1").get().envelope).payload.metadata;

// w33-seal F-1: a corrupted AUTHORITY_REVOKED inside the doomed span leaves an
// orphaned floor row. The seal must CARRY that ref (floor_derived), never
// delete it — deleting silently un-revoked the authority.
test('w33 seal F1: a corrupted revocation anchor stays revoked via floor-derived carry', t => {
  const h = fixture(t, ['acme']);
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ max_cost: 10 }));
  h.f.revoke(h.p('security'), { kind: 'capability', id: cap.payload.capability_id, reason: 'kill it' });
  assert.equal(h.f.revoked('acme', 'capability', cap.payload.capability_id), true);
  // Corrupt the revocation row itself — its anchor can never verify again.
  corruptAt(h, seqOf(h, '%AUTHORITY_REVOKED%'));
  assert.equal(h.f.sealAuditChain(h.p('security')).sealed, true);
  assert.equal(h.f.revoked('acme', 'capability', cap.payload.capability_id), true, 'the floor-derived carry keeps the revocation live');
  const floor = h.f.store.get('acme', 'revocation', `capability:${cap.payload.capability_id}`);
  assert.ok(floor, 'the floor row is kept, never dropped by the seal');
  const carry = sealMeta(h).revocations_carryover.find(r => r.reference === `capability:${cap.payload.capability_id}`);
  assert.ok(carry?.floor_derived === true, 'the carry names the ref as floor-derived');
  // And the floor row still satisfies floorCheck — no wedge from kept state.
  assert.doesNotThrow(() => h.f._auditIndex('acme'));
});

// w33-seal F-1b revised by w34-fixverify H-2 / w34-runtime F-3: a
// chain-revoked subject who corrupts its own AUTHORITY_REVOKED row leaves
// only a floor-derived carry — unverifiable authority. The carry still
// ENFORCES the revocation in idx.revoked (they can never clear themselves)
// but no longer bricks the caller: gating the sealer on an unverifiable
// claim let a single planted `records` row aim INV-403 at whichever
// operator runs the repair. The seal succeeds, names the ref under
// floor_derived, and the next privileged call still refuses the condemned.
test('w33 seal F1b: a corrupted revocation carries floor-derived, still enforces, never bricks the sealer', t => {
  const h = fixture(t, ['acme']);
  h.f.revoke(h.p('security'), { kind: 'subject', id: 'security', reason: 'condemned' });
  // While the revocation verifies the caller is refused outright.
  assert.throws(() => h.f.sealAuditChain(h.p('security')), hasCode('INV-403-QUARANTINE'));
  // Corrupting their own anchor: the orphaned floor carries the ref, the
  // seal completes and names it, and the revocation keeps enforcing —
  // the condemned actor can run the repair but not erase the verdict.
  corruptAt(h, seqOf(h, '%AUTHORITY_REVOKED%'));
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.equal(seal.sealed, true, 'an unverifiable floor claim cannot brick the seal');
  assert.ok(seal.floor_derived.includes('subject:security'), 'the planted/unverifiable ref is named in the result');
  assert.equal(h.f.revoked('acme', 'subject', 'security'), true, 'floor-derived carry still enforces the revocation');
  assert.throws(() => h.f.revoke(h.p('security'), { kind: 'key', id: 'k-any' }), hasCode('INV-403-QUARANTINE'), 'the condemned actor stays condemned after sealing');
});

// w33-seal F-2: a planted mirror request_id cannot burn a victim's genuine
// request — mirrors are never admitted, so a never-anchored id stays free.
test('w33 seal F2: a planted mirror request id does not burn the real request', t => {
  const h = fixture(t, ['acme']);
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ max_cost: 1000 }));
  const req = runtimeRequest(cap);
  h.f.runtime.consume(h.p(), req);
  // Attacker pre-spends the victim's NEXT request id through the mirror.
  const victimId = 'victim-next-request';
  h.f.store.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?)').run('acme', h.p().subject_id, cap.payload.resource, h.now(), 1, cap.payload.capability_id, victimId);
  corruptAt(h, seqOf(h, '%CAPABILITY_ISSUED%'));
  assert.equal(h.f.sealAuditChain(h.p('security')).sealed, true);
  assert.ok(!sealMeta(h).spend_carryover.some(u => u.request_id === victimId), 'planted mirror never enters the signed carryover');
  // fixverify F-1: the dropped residue is named — the seal never under-attests
  // silently what it refused to re-attest.
  assert.ok(sealMeta(h).carryover_totals.mirrors_dropped >= 1, 'the mirror residue is counted in the signed record');
  assert.ok(sealMeta(h).dropped_mirrors.some(m => m.table === 'usage' && m.request === victimId), 'the dropped mirror row is named as evidence');
  // The request id was never genuinely spent — but the seal dropped an
  // unverifiable anchor, so consume budgets the residue at worst-case
  // coverage (w38-runtime F-1): the denial is INV-429, never a
  // request-already-spent shadow of the planted mirror.
  const cap2 = h.f.runtime.issue(h.p(), runtimeInput({ max_cost: 1000 }));
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap2, { request_id: victimId })), hasCode('INV-429-BUDGET'));
});

// w33-seal F-4: carryover is bounded by construction — a doomed span carrying
// more than one page of entries still seals, and the overflow lands on signed
// AUDIT_SEAL_CARRY rows that fold back into the same indexes.
test('w33 seal F4: carryover overflow lands on signed AUDIT_SEAL_CARRY pages', t => {
  const h = fixture(t, ['acme']);
  // 600 doomed-verified CAPABILITY_ISSUED anchors overflow the 512-entry
  // head page; a few doomed verifiable revocations prove the pages fold.
  const caps = [];
  for (let i = 0; i < 600; i++) caps.push(h.f.runtime.issue(h.p(), runtimeInput({ max_cost: 10 })));
  for (const c of caps.slice(0, 5)) h.f.revoke(h.p('security'), { kind: 'capability', id: c.payload.capability_id, reason: 'kill' });
  const first = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq LIMIT 1").get().seq;
  corruptAt(h, first);
  assert.equal(h.f.sealAuditChain(h.p('security')).sealed, true);
  const meta = sealMeta(h);
  assert.equal(meta.carryover_totals.capabilities >= 600, true, 'all 600 doomed issuances are accounted');
  assert.ok(meta.carryover_pages >= 1, 'overflow paged onto AUDIT_SEAL_CARRY rows');
  const sealSeq = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND envelope LIKE '%AUDIT_SEALED%'").get().seq;
  const pages = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND envelope LIKE '%AUDIT_SEAL_CARRY%' ORDER BY seq").all().map(r => JSON.parse(r.envelope).payload);
  assert.equal(pages.length, meta.carryover_pages, 'the signed count of pages matches the rows');
  assert.ok(pages.every(pl => pl.metadata.seal_seq === sealSeq), 'every page names the seal it belongs to');
  // The fold replays the pages: carried revocations are live.
  const idx = h.f._auditIndex('acme');
  for (const c of caps.slice(0, 5)) assert.ok(idx.revoked.has(`capability:${c.payload.capability_id}`), 'carried revocation folds live');
});

// w33-seal F-6: a second seal cutting below a prior AUDIT_SEALED forwards the
// carryover — and with mirrors gone there is no re-witnessed gate to reopen.
test('w33 seal F6: a second seal under a prior seal re-carries its carryover', t => {
  const h = fixture(t, ['acme']);
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ max_cost: 1000 }));
  const req = runtimeRequest(cap);
  h.f.runtime.consume(h.p(), req);
  corruptAt(h, seqOf(h, '%CAPABILITY_ISSUED%'));
  assert.equal(h.f.sealAuditChain(h.p('security')).sealed, true);
  // Second seal: corrupt a row BEFORE the first seal — its carryover must
  // forward, and fresh mirror rows planted between seals stay dead.
  h.f.store.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?)').run('acme', h.p().subject_id, cap.payload.resource, h.now(), 777, cap.payload.capability_id, 'wave-2');
  const early = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq LIMIT 2").all();
  corruptAt(h, early[1].seq);
  assert.equal(h.f.sealAuditChain(h.p('security')).sealed, true);
  const meta = sealMeta(h);
  const reqs = meta.spend_carryover.map(u => u.request_id);
  assert.ok(reqs.includes(req.request_id), 'the first seal’s carryover is forwarded');
  assert.ok(!reqs.includes('wave-2'), 'the second wave of mirrors is dropped');
});

// w33-fixverify F-3: a doomed revocation + a live key repoint must not
// deadlock the seal — the repoint's mid-seal refolds tolerate the kept
// floor rows through the pending carry set.
test('w33 FV F3: a repoint meeting floor-carried revocations does not brick the seal', t => {
  const h = fixture(t, ['acme']);
  h.ready();
  const auditKid = h.f.tenant('acme').keys?.audit?.key_id;
  designateSuccessor(h, 'audit');
  h.f.revoke(h.p('security'), { kind: 'key', id: auditKid, reason: 'rotate out' });
  h.f.revoke(h.p('security'), { kind: 'subject', id: 'custodian-2', reason: 'gone' });
  // The custodian revocation's own anchor is destroyed — floor-derived carry.
  corruptAt(h, seqOf(h, '%AUTHORITY_REVOKED%'));
  assert.equal(h.f.sealAuditChain(h.p('security')).sealed, true, 'the seal completes through the repoint + carried floor rows');
  assert.equal(h.f.revoked('acme', 'subject', 'custodian-2'), true, 'the doomed revocation is still carried');
});

// w33-fixverify F-4: destroying the audit key's own revocation row leaves it
// dead only via the floor — the carried 'key:' ref must still trigger the
// repoint so the seal can sign under the designated successor.
test('w33 FV F4: a floor-carried audit-key revocation still repoints the signer', t => {
  const h = fixture(t, ['acme']);
  h.ready();
  const auditKid = h.f.tenant('acme').keys?.audit?.key_id;
  const pending = designateSuccessor(h, 'audit');
  h.f.revoke(h.p('security'), { kind: 'key', id: auditKid, reason: 'suspect' });
  // Corrupt the revocation's own anchor — only the floor row knows it now.
  corruptAt(h, seqOf(h, '%AUTHORITY_REVOKED%'));
  assert.equal(h.f.sealAuditChain(h.p('security')).sealed, true, 'the dead-key repoint fires inside the seal');
  const sealRow = JSON.parse(h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND envelope LIKE '%AUDIT_SEALED%' ORDER BY seq DESC LIMIT 1").get().envelope);
  assert.equal(sealRow.protected.key_id, pending.key_id, 'the seal is signed by the ceremony-designated successor');
});

// w33-fixverify F-5: a legitimately tombstoned capsule must not wedge the
// integrity sweep — the tenant's own remediation is not a tamper.
test('w33 FV F5: a shredded capsule tombstone passes the wedge sweep', t => {
  const h = fixture(t, ['acme']);
  const record = h.proposed('finance.beneficiary.create', { vendor_id: 'v-t', bank_account: 'TESTBANK000093', currency: 'EUR' });
  const id = record.capsule.capsule_id;
  h.f.store.db.prepare("UPDATE records SET value=? WHERE tenant='acme' AND kind='capsule' AND id=?").run('AA==', id);
  const sweep = h.f.retentionSweep(h.p('security'));
  assert.ok(sweep.corrupt >= 1, 'corrupt capsule shredded and tombstoned');
  assert.equal(h.f._wedgeIntegrity('acme').ok, true, 'a chain-tombstoned capsule does not wedge the sweep');
});

// w33-seal O-3: the offline verifier's signer-death window unfolds carried
// 'key:' revocations — a key killed only inside a seal still counts dead.
test('w33 seal O3: a carried key revocation kills the key for offline verification', t => {
  const h = fixture(t, ['acme']);
  h.ready();
  // Revoke the audit key's actor binding via a key revocation, then corrupt
  // the revocation's anchor so only the floor carries it.
  const auditKid = h.f.tenant('acme').keys?.audit?.key_id;
  designateSuccessor(h, 'audit');
  h.f.revoke(h.p('security'), { kind: 'key', id: auditKid, reason: 'suspect' });
  corruptAt(h, seqOf(h, '%AUTHORITY_REVOKED%'));
  assert.equal(h.f.sealAuditChain(h.p('security')).sealed, true);
  const dead = h.f.store._auditKeyDeaths('acme');
  assert.ok(dead.has(auditKid), 'the carried key revocation reaches the offline death window');
});

// w33-fixverify F-5 detail: a floor-derived 'key:' carry is what feeds the
// death window — the offline and fold verdicts must agree for the same
// destroyed-revocation state.

// ---- w33-export findings (export/proof surface) ----
// F-1: the signed head's residue claims convict deletions of unguarded rows.
test('w33 export F1a: a deleted revocation floor trips the signed head residue claim', t => {
  const h = fixture(t, ['acme']);
  h.f.revoke(h.p('security'), { kind: 'subject', id: 'custodian-2', reason: 'condemned' });
  assert.equal(h.f.revoked('acme', 'subject', 'custodian-2'), true);
  // The attacker deletes the floor row to bury the anchor — floorCheck has
  // nothing left to check, but the signed head's revocation count cannot be
  // un-claimed.
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='revocation' AND id='subject:custodian-2'").run();
  assert.throws(() => h.f._auditIndex('acme'), hasCode('INV-409-INTEGRITY'), 'the head attests a revocation floor the attacker cannot un-claim');
});

test('w33 export F1b: a deleted export checkpoint trips the signed head residue claim', t => {
  const h = fixture(t, ['acme']);
  h.f.exportAudit(h.p('auditor'), 'quarterly review');
  const cps = h.f.store.ids('acme', 'audit-checkpoint', 100);
  assert.equal(cps.length, 1, 'the export wrote a witness checkpoint record');
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='audit-checkpoint'").run();
  assert.throws(() => h.f._auditIndex('acme'), hasCode('INV-409-INTEGRITY'), 'the head attests a checkpoint the attacker cannot un-claim');
});

// F-2: the independent webcrypto verifier enforces the signer-death window —
// a posthumously-signed bundle must reject exactly like node verifyAudit.
test('w33 export F2: webcrypto verifier rejects a posthumously-signed bundle', async t => {
  const h = fixture(t, ['acme']);
  const auditKid = h.f.tenant('acme').keys?.audit?.key_id;
  const exported = h.f.exportAudit(h.p('auditor'), 'baseline trust');
  const row = payload => ({ hash: digest(payload), envelope: h.f.vault.envelope(auditKid, 'audit', payload) });
  // A revocation that kills the audit key, then a row signed by that same key
  // one sequence later — every envelope verifies; the death window must not.
  const r1 = row({ tenant_id: 'acme', sequence: 1, previous: '0'.repeat(64), type: 'AUTHORITY_REVOKED', actor: 'mallory', reference: `key:${auditKid}`, time: 1, metadata: {} }); // canonical key-death encoding (w37 F-C)
  const r2 = row({ tenant_id: 'acme', sequence: 2, previous: r1.hash, type: 'AUDIT_ACCESSED', actor: 'mallory', reference: 'tenant-log', time: 2, metadata: {} });
  const bundle = { format: 'IF-AUDIT-1', prior_checkpoint: null, checkpoint: h.f.vault.envelope(auditKid, 'checkpoint', { tenant_id: 'acme', size: 2, head: r2.hash, tree_head: merkleRoot([r1.hash, r2.hash]) }), entries: [r1, r2] };
  const dir = mkdtempSync(join(tmpdir(), 'w33-exp-'));
  const b = join(dir, 'bundle.json'), tr = join(dir, 'trust.json');
  writeFileSync(b, JSON.stringify(bundle)); writeFileSync(tr, JSON.stringify(exported.public_keys));
  const script = fileURLToPath(new URL('../scripts/verify-export-webcrypto.mjs', import.meta.url));
  let out = '';
  try { execFileSync(process.execPath, [script, b, tr], { stdio: 'pipe' }); } catch (e) { out = String(e.stdout) + String(e.stderr); }
  assert.match(out, /ledger death/, 'the second verifier must reject a posthumous signer like the fold does');
  // Parity sanity: the honest export still verifies clean under node.
  const clean = fileURLToPath(new URL('../scripts/verify-export-webcrypto.mjs', import.meta.url));
  const ok = execFileSync(process.execPath, [clean, (() => { const p = join(dir, 'clean.json'); writeFileSync(p, JSON.stringify(exported)); return p; })(), tr], { stdio: 'pipe' }).toString();
  assert.match(ok, /"valid":true/);
});

// F-3: /v1/audit/verify-proof verifies the proof's own (root,size) claim —
// no circular pin to attacker-writable DB state. An optional caller pin binds
// an externally witnessed checkpoint.
test('w33 export F3: verify-proof checks the proofs own claim, not live clay', async t => {
  const h = fixture(t, ['acme']);
  const proof = h.f.auditProof(h.p('auditor'), 1);
  // Rows arrive after the proof — it stays verifiable against its own claim.
  h.f.revoke(h.p('security'), { kind: 'subject', id: 'custodian-2', reason: 'x' });
  assert.equal(h.f.verifyAuditProof('acme', proof), true, 'an older proof still verifies on its own claim');
  assert.equal(h.f.verifyAuditProof('acme', proof, { root: proof.root, size: proof.size }), true);
  assert.throws(() => h.f.verifyAuditProof('acme', proof, { root: proof.root, size: proof.size + 1 }), hasCode('INV-409-FORK'));
  // The HTTP route agrees: a stale-size proof is valid (the pin is the
  // caller's business), and a wrong caller pin forks.
  const app = createServer(h.f, { port: 0, origin: 'http://127.0.0.1:17777' });
  await app.listen(); t.after(() => app.close());
  const port = app.server.address().port;
  const post = body => new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = http.request({ host: '127.0.0.1', port, path: '/v1/audit/verify-proof', method: 'POST', headers: { Host: '127.0.0.1:17777', Authorization: `Bearer ${h.setup.credentials.acme.auditor}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, data: JSON.parse(Buffer.concat(chunks).toString()) }));
    }); req.on('error', reject); req.end(payload);
  });
  assert.equal((await post({ proof })).data.valid, true, 'the route no longer circular-pins to live DB state');
  assert.equal((await post({ proof, pin: { root: proof.root, size: proof.size } })).status, 200);
  assert.equal((await post({ proof, pin: { root: proof.root, size: proof.size + 7 } })).status, 409);
});

// F-4: incremental merkle — the memoized tree recomputes identically to the
// naive full re-hash, across growth.
test('w33 export F4: memoized merkle agrees with naive recomputation', t => {
  const h = fixture(t, ['acme']);
  h.ready(); h.ready();
  const c = h.f.auditConsistency(h.p('auditor'), 3);
  const hashes = h.f.store.auditHashes('acme');
  // The consistency read appends its own access row, so `second` (the size at
  // call time) is the honest bound to recompute against.
  assert.equal(c.first_root, merkleRoot(hashes.slice(0, 3)));
  assert.equal(c.second_root, merkleRoot(hashes.slice(0, c.second)));
  const proof = h.f.auditProof(h.p('auditor'), 2);
  assert.equal(verifyInclusion(proof.leaf_hash, 1, proof.size, proof.path, proof.root), true);
  // Growth path: more rows, then consistency still recomputes identically.
  h.ready(); h.ready();
  const c2 = h.f.auditConsistency(h.p('auditor'), 5);
  const h2 = h.f.store.auditHashes('acme');
  assert.equal(c2.first_root, merkleRoot(h2.slice(0, 5)));
  assert.equal(c2.second_root, merkleRoot(h2.slice(0, c2.second)));
});

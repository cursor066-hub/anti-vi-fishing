// w39: seal 4th-pass + crypto/vault + ledger/docs 15th-pass — a forged
// unsigned head-watermark entry can no longer satisfy the monotone compare
// (resolved floor only), a signed stranded floor is re-anchored with a
// signed AUDIT_WM_REANCHORED attestation, deleted payload positions inside
// a doomed span are counted once, the seal recount spot-checks stored
// hashes so an in-place carry-page rewrite flips the fingerprint, dead
// signers are refused on every path, and the ledger's VERIFIED gate is
// itself enforced by the generator.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { rmSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fixture } from './helpers.mjs';
import { signAcknowledgement } from '../src/ceremony.mjs';
import { generateKey } from '../src/crypto.mjs';
import { createServer } from '../src/server.mjs';

const dropAuditGuards = h => {
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
    h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
};
const corruptAt = (h, seq) =>
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?")
    .run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', seq);
const delRow = (h, seq) => h.f.store.db.prepare("DELETE FROM audit WHERE tenant='acme' AND seq=?").run(seq);
const chainRows = h => h.f.store.db.prepare("SELECT seq,envelope FROM audit WHERE tenant='acme' ORDER BY seq").all()
  .map(r => ({ seq: r.seq, env: JSON.parse(r.envelope) }));
const lastSeq = h => h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get().seq;
const writeWm = (h, entry) => writeFileSync(join(h.directory, 'head-watermark.json'), JSON.stringify({ format: 'IF-HEADMARK-1', tenants: { acme: entry } }) + '\n', { mode: 0o600 });

// Rotate the audit class through the full ceremony so the previous key is
// chain-dead (KEY_ROTATED pins its death) — returns { oldKid, newKid }.
const rotateAudit = h => {
  const oldKid = h.f.keys('acme').audit.key_id;
  const pending = h.f.prepareRotation(h.p('security'), 'audit');
  const custodians = ['custodian-1', 'custodian-2'];
  const c = h.f.createCeremony(h.p('security'), { ceremony_id: `cer-w39-${oldKid.slice(0, 8)}`, purpose: 'key.rotate', threshold: 2, custodians, valid_until: h.now() + 3600000, min_delay_ms: 120000, rotation: { key_class: 'audit', new_key_id: pending.key_id } });
  for (const s of custodians) h.f.acknowledgeCeremony(h.p(s), signAcknowledgement(c, s, h.setup.custodianKeys.acme[s], h.now()));
  const r = h.proposed('key.rotate', { key_class: 'audit', new_key_id: pending.key_id, new_public_key: pending.public_key, ceremony_id: c.ceremony_id, revoke_old: true }, { action: { type: 'key.rotate', target_resource: 'key-registry', purpose: 'Rotation' } });
  h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'audit-committee' }); h.approve(r, 3); h.advance(60001);
  h.f.execute(h.p(), h.f.certificate(h.p(), r.capsule.capsule_id));
  return { oldKid, newKid: pending.key_id };
};

test('w39-seal F-1: a forged bare watermark entry can never pin the floor', t => {
  const h = fixture(t); h.ready();
  const tip = lastSeq(h);
  // The attacker's whole primitive: one unsigned integer written into the
  // durable file. Pre-w39 the monotone compare read it raw and the forged
  // floor stayed satisfied forever — a later consistent rollback would go
  // undetected and any future head <= forged seq could never re-bump.
  writeWm(h, tip + 999999);
  const resolved = h.f._headWatermark('acme');
  assert.equal(resolved, tip, 'the resolved floor clamps to the committed head — the forged number is no floor');
  assert.doesNotThrow(() => h.f._auditIndex('acme'), 'the fold must not wedge on an unsigned forge');
  // The next honest bump replaces the plant under a signed envelope.
  h.f.store.audit('acme', 'W39_PAD', 'operator', 'pad', {}, h.now());
  const after = JSON.parse(readFileSync(join(h.directory, 'head-watermark.json'), 'utf8')).tenants.acme;
  assert.ok(typeof after === 'object' && typeof after.envelope === 'object', 'the forged entry must be replaced by a signed floor');
  assert.equal(after.seq, tip + 1);
});

test('w39-seal F-1/F-4: a forged envelope entry clamps to the tip and the seal names it', t => {
  const h = fixture(t); h.ready();
  const tip = lastSeq(h);
  // Object shape with garbage envelope — unsigned forged floor.
  writeWm(h, { seq: tip + 5000, envelope: { payload: { seq: tip + 5000 }, signatures: [{ signature: 'AA' }] } });
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, false);
  const tamp = r.head_watermark_tampered;
  assert.ok(Array.isArray(tamp) && tamp.length === 1, `forged watermark must be attested, got ${JSON.stringify(tamp)}`);
  assert.equal(tamp[0].tenant_id, 'acme');
  assert.equal(tamp[0].kind, 'signature');
  assert.equal(tamp[0].seq, tip + 5000);
});

test('w39-seal F-2/F-4: a signed stranded floor wedges honestly and the seal re-anchors it', t => {
  const h = fixture(t); h.ready();
  const tip = lastSeq(h);
  // A real signature over a floor the chain cannot support — the crash-gap
  // case: the fold wedges, the seal lowers it and records the abandon.
  const kid = h.f.keys('acme').audit.key_id;
  const env = h.f.vault.envelope(kid, 'audit', { tenant_id: 'acme', format: 'IF-HEADMARK-1', head_seq: tip + 50 }, { tenant_id: 'acme' });
  writeWm(h, { seq: tip + 50, envelope: env });
  assert.throws(() => h.f._auditIndex('acme'), e => e.code === 'INV-409-INTEGRITY');
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, false, 'the chain verifies — this is re-anchor, not a cut');
  assert.equal(r.watermark_reanchored, true, 'the result must name the watermark repair');
  const ev = chainRows(h).find(x => x.env.payload.type === 'AUDIT_WM_REANCHORED');
  assert.ok(ev, 'the re-anchor must land on the signed chain');
  assert.equal(ev.env.payload.metadata.reanchored_tip_seq, tip);
  assert.equal(ev.env.payload.metadata.abandoned_watermark_seq, tip + 50);
  assert.equal(ev.env.payload.metadata.abandoned_watermark_signed, true, 'the abandoned claim carried a real signature — named, not silently cleared');
  assert.doesNotThrow(() => h.f._auditIndex('acme'), 'post-re-anchor fold must run');
  assert.equal(h.f._headWatermark('acme') >= tip + 1, true, 'the durable floor now tracks the live tip');
});

test('w39-crypto F3: a headmark signed by a key dead before its claim is tamper evidence', t => {
  const h = fixture(t); h.ready();
  const tip = lastSeq(h);
  // Mint a genuinely signed floor BEFORE the death — a captured envelope
  // replayed after the signer died at rotation.
  const oldKid = h.f.keys('acme').audit.key_id;
  const env = h.f.vault.envelope(oldKid, 'audit', { tenant_id: 'acme', format: 'IF-HEADMARK-1', head_seq: tip + 9000 }, { tenant_id: 'acme' });
  rotateAudit(h);
  writeWm(h, { seq: tip + 9000, envelope: env });
  const resolved = h.f._headWatermark('acme');
  const head = h.f._chainHead('acme');
  assert.equal(resolved, head.seq, 'a dead-signed floor resolves to the committed head — never honored');
  const r = h.f.sealAuditChain(h.p('security'));
  const tamp = r.head_watermark_tampered;
  assert.ok(Array.isArray(tamp) && tamp.length === 1, `dead-signed floor must be attested, got ${JSON.stringify(tamp)}`);
  assert.equal(tamp[0].kind, 'signature');
});

test('w39-seal F-3: deleted positions inside a doomed span are counted once', t => {
  const h = fixture(t); h.ready();
  for (let i = 0; i < 6; i++) h.f.store.audit('acme', 'W39_PAD', 'operator', `pad-${i}`, {}, h.now());
  const tip = lastSeq(h);
  rmSync(join(h.directory, 'chain-heads.json'), { force: true });
  rmSync(join(h.directory, 'head-watermark.json'), { force: true });
  dropAuditGuards(h);
  delRow(h, tip - 3);       // physically absent — deleted
  corruptAt(h, tip - 1);    // present but unverifiable — dropped, not deleted
  corruptAt(h, tip);        // present but unverifiable — dropped, not deleted
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  assert.equal(r.carryover_totals.deleted_events, 1, `exactly the physically-absent row counts as deleted — got ${r.carryover_totals.deleted_events}`);
  assert.equal(r.carryover_totals.deleted_rows_total, r.carryover_totals.deleted_events, 'result-level total agrees');
  assert.ok(r.deleted_gaps.some(g => g[0] <= tip - 3 && g[1] >= tip - 3), 'the deleted seq is a named gap');
});

test('w39-seal F-5: an in-place hash rewrite of a consumed carry page wedges the fold', t => {
  const h = fixture(t);
  // A seal carrying >512 entries spills onto AUDIT_SEAL_CARRY pages.
  for (let i = 0; i < 600; i++) h.f.store.audit('acme', 'W39_PAD', 'operator', `pad-${i}`, { i }, h.now());
  dropAuditGuards(h);
  corruptAt(h, h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND envelope LIKE '%pad-0%'").get().seq);
  const r0 = h.f.sealAuditChain(h.p('security'));
  assert.equal(r0.sealed, true);
  const carry = chainRows(h).find(x => x.env.payload.type === 'AUDIT_SEAL_CARRY');
  assert.ok(carry, 'a carry page exists to attack');
  // Consume the fold once so the recount memo holds (seq,hash) pairs…
  h.f._auditIndex('acme');
  dropAuditGuards(h);
  // …then rewrite the page's stored hash with the row intact — (maxSeq,
  // count) does not move; only the spot-check sees the surgery.
  h.f.store.db.prepare("UPDATE audit SET hash='deadbeef' WHERE tenant='acme' AND seq=?").run(carry.seq);
  let err;
  try { h.f._auditIndex('acme'); } catch (e) { err = e; }
  assert.ok(err && err.code === 'INV-409-INTEGRITY', `the page rewrite must refuse INV-409, got ${err?.code}`);
});

test('w39-crypto F4: the explicit-key sign path refuses a rotation-dead key', t => {
  const h = fixture(t); h.ready();
  const { oldKid } = rotateAudit(h);
  assert.equal(h.f.revoked('acme', 'key', oldKid), false, 'a KEY_ROTATED death is not an AUTHORITY_REVOKED row — only the ledger death gate can catch it');
  assert.throws(() => h.f.signAudit('acme', { probe: 1 }, 'audit', oldKid), e => e.code === 'INV-401-SIGNATURE');
  // The live bound key still signs through the same explicit path.
  const env = h.f.signAudit('acme', { probe: 1 }, 'audit', h.f.keys('acme').audit.key_id);
  assert.equal(env.payload.probe, 1);
});

test('w39-crypto F5: an unbound pending key signing explicitly carries the recovery marker', t => {
  const h = fixture(t); h.ready();
  // A pending key minted outside any ceremony is not the bound signer — the
  // same act must read identically whichever path steered it there.
  const pending = h.f.prepareRotation(h.p('security'), 'audit');
  const bound = h.f.keys('acme').audit.key_id;
  const env = h.f.signAudit('acme', { probe: 1 }, 'audit', pending.key_id, { allowPending: true });
  assert.equal(env.payload.recovery_signing?.superseded_key, bound, 'an explicit pending-key signature must self-name as recovery');
});

test('w39-crypto F6: a tenant_id field flip on a vault entry evicts it from verification', t => {
  const h = fixture(t); h.ready();
  // A generated tenant-owned key joins the verify set via vault membership
  // — flipping its tenant field must evict it, which only happens if the
  // memo signature covers tenant_id (w39-crypto F6).
  const extra = h.f.vault.generate('any', { tenant_id: 'acme' });
  assert.ok(h.f.auditPublicKeys('acme')[extra.key_id], 'a generated tenant-owned key joins the verify set');
  h.f.vault.keys.get(extra.key_id).tenant_id = 'globex';
  assert.equal(h.f.auditPublicKeys('acme')[extra.key_id], undefined, 'tenant-bound verification must re-derive — no stale memoized key set');
});

test('w39-crypto F7: vault.generate/importKey clone the caller-purpose array', t => {
  const h = fixture(t); h.ready();
  const purposes = ['audit'];
  const gen = h.f.vault.generate(purposes, { tenant_id: 'acme' });
  purposes.push('execution');
  assert.deepEqual(h.f.vault.keys.get(gen.key_id).purpose, ['audit'], 'stored purpose must not track the caller array');
  assert.throws(() => h.f.vault.sign(gen.key_id, 'execution', 'x', { tenant_id: 'acme' }), e => e.code === 'INV-403-SCOPE');
  const kp = generateKey();
  const impPurposes = ['attest'];
  const imp = h.f.vault.importKey({ key_id: 'imp-w39', public_key: kp.public_key, private_key: kp.private_key }, impPurposes, { tenant_id: 'acme' });
  impPurposes.push('audit');
  assert.deepEqual(h.f.vault.keys.get(imp.key_id).purpose, ['attest']);
});

test('w39-ledger F2: privileged routes authorize before parsing the body', async t => {
  const h = fixture(t); h.ready();
  const app = createServer(h.f, { port: 0, origin: 'http://127.0.0.1:17777' });
  await app.listen(); t.after(() => app.close());
  const port = app.server.address().port;
  const request = (path, { method = 'GET', body, token = h.setup.credentials.acme.auditor } = {}) => new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const req = http.request({ host: '127.0.0.1', port, path, method, headers: { Host: '127.0.0.1:17777', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(payload === undefined ? {} : { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }) } }, response => {
      const chunks = []; response.on('data', c => chunks.push(c)); response.on('end', () => { let data; try { data = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { data = null; } resolve({ status: response.statusCode, data }); });
    }); req.on('error', reject); req.end(payload);
  });
  for (const path of ['/v1/approvals', '/v1/approvals/batch', '/v1/ceremonies', '/v1/revocations']) {
    const res = await request(path, { method: 'POST', body: { malformed: true, fields: { never: 'parses' } } });
    assert.equal(res.status, 403, `${path} must refuse the wrong role before inspecting the body, got ${res.status}`);
    assert.match(res.data?.error?.code ?? '', /^INV-403/, `${path} must surface the authorization code, not a body-parse error`);
  }
});

test('w39-ledger F4/F8/F9: honest limitation text lands in the generated ledger', () => {
  const csv = readFileSync('docs/requirements.csv', 'utf8');
  const ux = csv.split('\n').find(l => l.startsWith('UX-001,'));
  assert.match(ux, /approval_threshold/, 'UX-001 must name the in-engine floor, not only missing human studies');
  const key = csv.split('\n').find(l => l.startsWith('KEY-006,'));
  assert.match(key, /post-quantum suite is implemented/, 'KEY-006 must name the real residual');
  const cmp = csv.split('\n').find(l => l.startsWith('NFR-CMP-001,'));
  assert.match(cmp, /self-labelled/, 'NFR-CMP-001 must name the in-repo producible artifact');
});

test('w39-ledger F6/F7: the generator gate runs byte-clean against the committed ledger', () => {
  // --check recomputes every artifact — including the VERIFIED-evidence
  // assert and exact test-body binding — and refuses any drift.
  const out = execFileSync('python3', ['scripts/traceability.py', '--check'], { encoding: 'utf8' });
  assert.match(out, /"VERIFIED_IN_ENGINEERING_PROFILE": 173/);
});

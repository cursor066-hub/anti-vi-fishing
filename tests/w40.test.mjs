// w40: fix-verification of the watermark machinery itself — the signed head
// now attests the durable floor it saw at mint (floor_seq), a stripped entry
// falls to the attestation and is named instead of laundered, a replayed
// stale head wedges, the bump compares against the RESOLVED floor, planted
// canonical-illegal content can never freeze the writer, a landed write
// clears the tamper flag it repaired, coverage denominators count only
// decrypt-verified rows, material_fields redaction covers scalar containers,
// and connectionCap rejects non-integer config.
import test from 'node:test';
import assert from 'node:assert/strict';
import { rmSync, statSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fixture, runtimeInput, runtimeRequest, designateSuccessor } from './helpers.mjs';
import { Fabric } from '../src/fabric.mjs';
import { clone, canonical, digest } from '../src/canonical.mjs';
import { verifySigned } from '../src/crypto.mjs';
import { signAcknowledgement } from '../src/ceremony.mjs';
import { createServer } from '../src/server.mjs';
import { reconstructionCheck } from '../src/datagate.mjs';

const dropAuditGuards = h => {
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
    h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
};
const lastSeq = h => h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get().seq;
const wmPath = h => join(h.directory, 'head-watermark.json');
const headsPath = h => join(h.directory, 'chain-heads.json');
const writeWm = (h, tenants) => writeFileSync(wmPath(h), JSON.stringify({ format: 'IF-HEADMARK-1', tenants }) + '\n', { mode: 0o600 });
const coldOpen = (t, h) => {
  h.close();
  const cold = new Fabric(clone(h.setup.config), h.directory, () => h.now());
  t.after(() => cold.close());
  return cold;
};

test('w40-fv F-1: a stripped watermark entry resolves to the head-attested floor and is named, never laundered', t => {
  const h = fixture(t, ['acme']);
  h.proposed(); h.f._auditIndex('acme');
  const claimed = JSON.parse(readFileSync(headsPath(h), 'utf8')).tenants.acme.payload.floor_seq;
  assert.ok(claimed > 0, 'the signed head must carry a floor claim for this test to mean anything');
  // The attacker's whole primitive: delete the tenant's watermark entry.
  const wm = JSON.parse(readFileSync(wmPath(h), 'utf8'));
  delete wm.tenants.acme;
  writeFileSync(wmPath(h), JSON.stringify(wm));
  const cold = coldOpen(t, h);
  const resolved = cold._headWatermark('acme');
  assert.equal(resolved, claimed, 'the floor falls to the signed head attestation — never to zero, never above it');
  // The bootstrap must not mint a signed cover for the strip.
  const after = JSON.parse(readFileSync(wmPath(h), 'utf8'));
  assert.equal(after.tenants.acme, undefined, 'no signed entry may be minted over a stripped state');
  assert.doesNotThrow(() => cold._auditIndex('acme'), 'a consistent state below the attested floor still folds');
  const r = cold.sealAuditChain(h.p('security'));
  assert.ok((r.head_watermark_tampered ?? []).some(e => e.kind === 'floor_stripped'), `the strip must be named — got ${JSON.stringify(r.head_watermark_tampered)}`);
  assert.equal(r.watermark_reanchored, true, 'the seal re-anchors the repaired floor forward to the proven tip');
});

test('w40-fv F-2: a replayed stale head beside a stripped watermark wedges the fold; the seal re-anchors the tip', t => {
  const h = fixture(t, ['acme']);
  h.proposed(); h.f._auditIndex('acme');
  const staleHeads = readFileSync(headsPath(h), 'utf8');
  for (let i = 0; i < 4; i++) h.f.store.audit('acme', 'W40_PAD', 'operator', `pad-${i}`, {}, h.now());
  // Roll back the head file and strip the watermark entry: an honest commit
  // lag always keeps the live wm entry — only file surgery produces the
  // pair, so it wedges where a racing fold must not.
  writeFileSync(headsPath(h), staleHeads);
  writeWm(h, {});
  const cold = coldOpen(t, h);
  assert.throws(() => cold._auditIndex('acme'), e => e.code === 'INV-409-INTEGRITY', 'a signed head below the committed tip beside a stripped watermark is a replay, not a head');
  const r = cold.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, false, 'the rows verify — this is re-anchor, not a cut');
  assert.equal(r.head_reanchored, true, 'the seal must attest the repair');
  assert.doesNotThrow(() => cold._auditIndex('acme'), 'the re-anchored head heals the wedge');
});

test('w40-fv F-2: a replayed watermark below its own attestation wedges and the seal repairs forward', t => {
  const h = fixture(t, ['acme']);
  h.proposed(); h.f._auditIndex('acme');
  const oldEntry = JSON.parse(readFileSync(wmPath(h), 'utf8')).tenants.acme; // signed entry at the early floor
  for (let i = 0; i < 4; i++) h.f.store.audit('acme', 'W40_PAD', 'operator', `pad-${i}`, {}, h.now());
  // Replay the OLD signed entry — its signature is real; its position is
  // below the floor the current head itself attested.
  const wm = JSON.parse(readFileSync(wmPath(h), 'utf8'));
  wm.tenants.acme = oldEntry;
  writeFileSync(wmPath(h), JSON.stringify(wm));
  assert.throws(() => h.f._auditIndex('acme'), e => e.code === 'INV-409-INTEGRITY', 'a resolved floor below its own signed attestation must wedge');
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, false, 'the chain verifies — repair, not a cut');
  assert.equal(r.watermark_reanchored, true, 'the seal moves the floor forward to the proven tip');
  assert.doesNotThrow(() => h.f._auditIndex('acme'), 'fold runs clean after the re-anchor');
});

test('w40-fv F-3: a forged unverifiable high entry cannot freeze the monotone bump', t => {
  const h = fixture(t, ['acme']);
  h.proposed(); h.f._auditIndex('acme');
  const tip = lastSeq(h);
  // Envelope-shaped garbage above the head — the resolved floor clamps to
  // the committed tip, so the next honest bump must still proceed.
  writeWm(h, { acme: { seq: tip + 999999, envelope: { payload: { seq: tip + 999999 }, signatures: [{ signature: 'AA' }] } } });
  h.f.store.audit('acme', 'W40_PAD', 'operator', 'pad', {}, h.now());
  const after = JSON.parse(readFileSync(wmPath(h), 'utf8')).tenants.acme;
  assert.ok(typeof after === 'object' && typeof after.envelope === 'object', 'the forge must be replaced by a signed floor');
  assert.equal(after.seq, tip + 1);
  assert.doesNotThrow(() => h.f._auditIndex('acme'), 'the fold runs clean over the repaired entry');
});

test('w40-fv F-4: planted canonical-illegal entries can never freeze the writer', t => {
  const h = fixture(t, ['acme']);
  h.proposed(); h.f._auditIndex('acme');
  // __proto__ parses as an own key but canonical() refuses it — pre-fix a
  // single planted key made every bump throw inside the catch-all and the
  // file stayed permanently unwritable.
  writeFileSync(wmPath(h), '{"format":"IF-HEADMARK-1","tenants":{"__proto__":1}}');
  h.f.store.audit('acme', 'W40_PAD', 'operator', 'pad', {}, h.now());
  const after = readFileSync(wmPath(h), 'utf8');
  const parsed = JSON.parse(after);
  assert.equal(Object.hasOwn(parsed.tenants, '__proto__'), false, 'the planted key is dropped, not reserialized');
  assert.doesNotThrow(() => canonical(parsed), 'the rewritten file is canonical-clean');
  assert.ok(typeof parsed.tenants.acme === 'object' && parsed.tenants.acme.envelope, 'the honest bump still landed');
  assert.doesNotThrow(() => h.f._auditIndex('acme'));
});

test('w40-fv F-5: a landed write clears the tamper flag it repaired', t => {
  const h = fixture(t, ['acme']);
  h.proposed(); h.f._auditIndex('acme');
  const tip = lastSeq(h);
  // A forged entry raises the flag on the next resolution…
  writeWm(h, { acme: { seq: tip + 5000, envelope: { payload: { seq: tip + 5000 }, signatures: [{ signature: 'AA' }] } } });
  h.f._auditIndex('acme');
  // …and the next honest landed write repairs it — the flag must not
  // survive to be reported forever as live tamper.
  h.f.store.audit('acme', 'W40_PAD', 'operator', 'pad', {}, h.now());
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, false);
  assert.deepEqual(r.head_watermark_tampered ?? [], [], 'a repaired entry must not keep reporting as tamper');
});

test('w40-fv F-6: an oversized watermark file is evidence and the writer recovers it', t => {
  const h = fixture(t, ['acme']);
  h.proposed(); h.f._auditIndex('acme');
  // 300KB of planted bloat — the same class chain-heads.json already gates.
  writeFileSync(wmPath(h), '{"format":"IF-HEADMARK-1","tenants":{"pad":"' + 'x'.repeat(300_000) + '"}}');
  const resolved = h.f._headWatermark('acme');
  assert.ok(typeof resolved === 'number' && resolved >= 0, 'the floor resolves honestly over the unreadable file');
  h.f.store.audit('acme', 'W40_PAD', 'operator', 'pad', {}, h.now());
  assert.ok(statSync(wmPath(h)).size < 262_144, 'the bump rewrites a clean file');
  assert.doesNotThrow(() => h.f._auditIndex('acme'));
});

test('w40-fv F-7: planted ciphertext rows cannot deflate the coverage denominator', t => {
  const h = fixture(t, ['acme']);
  h.f.target.seed('acme', 'dataset-1', {
    columns: ['id', 'name'], classification: 'internal', jurisdiction: 'EU',
    rows: [{ id: 'row-1', name: 'a' }, { id: 'row-2', name: 'b' }, { id: 'row-3', name: 'c' }, { id: 'row-4', name: 'd' }],
  });
  // 100 attacker-inserted ciphertext rows that can never decrypt —
  // pre-fix they inflated COUNT(*) and collapsed coverage toward zero.
  for (let i = 0; i < 100; i++)
    h.f.target.db.prepare('INSERT INTO dataset_rows VALUES(?,?,?,?)').run('acme', 'dataset-1', `junk-${i}`, 'AAAA');
  assert.equal(h.f._verifiedDatasetRows('acme', 'dataset-1'), 4, 'only decrypt-verified rows count as dataset content');
  const recon = reconstructionCheck(h.f.store.db, h.f.target.db, { tenant: 'acme', subject: 'operator', dataset: 'dataset-1', rows: ['row-1'], columns: ['id'], now: h.now(), policy: { max_distinct_rows: 10000, max_distinct_columns: 10000, max_coverage_percent: 100 }, record: false, verifiedRowCount: (t, d) => h.f._verifiedDatasetRows(t, d) });
  assert.equal(recon.allowed, true);
  assert.equal(recon.coverage_percent, 25, `coverage must bind the 4 real rows, not 104 — got ${recon.coverage_percent}`);
});

test('w40-fv F-8: scalar material_fields and named key variants redact on the projection route', t => {
  const h = fixture(t, ['acme']);
  // A scalar container has no keys to scrub — the field was selected as
  // sensitive, so the whole value must not be served verbatim.
  const scalar = h.f.resourceStateView({ id: 'res-1', material_fields: 'sk_live_secret_value' });
  assert.equal(scalar.material_fields.redacted, true);
  assert.equal(typeof scalar.material_fields.value_digest, 'string', 'a digest stands in for the value');
  for (const key of ['masterkey', 'authkey', 'auth_key', 'datakey', 'access_key', 'encryptionkey', 'signing_key']) {
    const view = h.f.resourceStateView({ id: 'res-1', material_fields: { [key]: 'secret' } });
    assert.equal(view.material_fields[key], '«redacted»', `${key} must redact`);
  }
  const benign = h.f.resourceStateView({ id: 'res-1', material_fields: { label: 'ok' } });
  assert.equal(benign.material_fields.label, 'ok');
});

test('w40-fv F-9: a bump cannot mutate the shared cached parse of the file', t => {
  const h = fixture(t, ['acme']);
  h.proposed(); h.f._auditIndex('acme');
  const snapshot = h.f._readHeadWatermark();
  assert.ok(snapshot && typeof snapshot === 'object');
  const beforeSeq = snapshot.acme?.seq;
  h.f._bumpHeadWatermark('acme', 999, { force: true });
  assert.equal(snapshot.acme?.seq, beforeSeq, 'the cached parse must not gain entries the file did not carry');
  const reread = h.f._readHeadWatermark();
  assert.equal(reread.acme.seq, 999, 'the re-read reflects the landed write');
});

test('w40-fv F-10: a non-integer or negative connectionCap refuses at construction', async t => {
  const h = fixture(t, ['acme']);
  for (const bad of [NaN, -1, 1.5, 'many', Infinity]) {
    let err;
    try { createServer(h.f, { port: 0, connectionCap: bad }); } catch (e) { err = e; }
    assert.ok(err && err.code === 'INV-400-CONFIG', `connectionCap=${String(bad)} must refuse, got ${err?.code}`);
  }
  const zero = createServer(h.f, { port: 0, connectionCap: 0 });
  await zero.listen(); await zero.close();
  assert.ok(zero, 'zero is a legal posture — probes only');
});

test('w39-crypto F2: a dead bound headmark signer steers to the quorum-designated pending successor — undesignated death names dead_signer', t => {
  const h = fixture(t, ['acme']);
  h.proposed(); h.f._auditIndex('acme');
  const bound = h.f.keys('acme').audit.key_id;
  // Revoke the bound audit signer with a ceremony-designated pending
  // successor standing by — the compromise-response shape the steering
  // exists for. The bound key stays bound (no rotation landed), so the
  // bump's fold-free scan must find the designation itself.
  const pending = designateSuccessor(h, 'audit');
  h.f.revoke(h.p('security'), { kind: 'key', id: bound, reason: 'signer compromise drill' });
  h.f.store.audit('acme', 'W40_PAD', 'operator', 'post-revoke', {}, h.now());
  const wm = JSON.parse(readFileSync(wmPath(h), 'utf8')).tenants.acme;
  assert.equal(typeof wm, 'object', 'the floor stays signed under the designated successor — no unsigned gap');
  const p = verifySigned(wm.envelope, h.f.auditPublicKeys('acme'), 'audit');
  assert.equal(wm.envelope.protected.key_id, pending.key_id, 'headmark signed by the quorum-designated pending successor');
  assert.equal(p.recovery_signing?.superseded_key, bound, 'the recovery marker names the superseded signer');
  assert.equal(p.seq, wm.seq, 'the head envelope attests the seq it carries');
  // The fold-free bump path — where _signingKeyId cannot run — steers
  // identically: its minimal headmark shape signs under the same
  // designated successor with the same recovery marker.
  h.f._bumpHeadWatermark('acme', lastSeq(h), { force: true });
  const bumped = JSON.parse(readFileSync(wmPath(h), 'utf8')).tenants.acme;
  const p2 = verifySigned(bumped.envelope, h.f.auditPublicKeys('acme'), 'audit');
  assert.equal(bumped.envelope.protected.key_id, pending.key_id, 'the fold-free bump steers to the same designated successor');
  assert.equal(p2.format, 'IF-HEADMARK-1');
  assert.equal(p2.head_seq, bumped.seq, 'the bump envelope attests the seq it carries');
  assert.equal(p2.recovery_signing?.superseded_key, bound, 'the bump carries the same recovery marker');
});

test('w39-crypto F2: a killed signer with no chain designation writes a named unsigned floor, never a silent one', t => {
  const h = fixture(t, ['acme']);
  h.proposed(); h.f._auditIndex('acme');
  const bound = h.f.keys('acme').audit.key_id;
  // A bound signer with NO live designation is only reachable through
  // surgery — the revoke() gate itself requires a designated successor.
  // Plant the death row: the fold-free scan takes every parsed death
  // fail-closed (it never needs the signature), so the bump must refuse
  // to sign under it and name the refusal.
  dropAuditGuards(h);
  const head = h.f.store.db.prepare("SELECT seq,hash FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get();
  const forged = { protected: { profile: 'IF-CJSON-1', suite: 'Ed25519', key_id: bound, purpose: 'audit' }, payload: { type: 'AUTHORITY_REVOKED', tenant_id: 'acme', sequence: head.seq + 1, time: h.now(), actor: 'planted', reference: `key:${bound}`, metadata: { reason_digest: 'x', record_digest: 'y' } }, signature: 'A'.repeat(86) };
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', head.seq + 1, head.hash, digest(forged.payload), JSON.stringify(forged));
  h.f._bumpHeadWatermark('acme', head.seq + 2, { force: true });
  const wm = JSON.parse(readFileSync(wmPath(h), 'utf8')).tenants.acme;
  assert.equal(typeof wm, 'number', 'a designation-free dead signer signs nothing — the floor is honestly unsigned');
  // The degraded state is named on the tamper attest the seal merges into
  // every refusal — the planted row wedges the fold, so the refusal's
  // details carry it.
  let named = false;
  try { const r = h.f.sealAuditChain(h.p('security')); named = (r.head_watermark_tampered ?? []).some(x => x.tenant_id === 'acme' && x.kind === 'dead_signer'); }
  catch (e) { named = (e.details?.head_watermark_tampered ?? []).some(x => x.tenant_id === 'acme' && x.kind === 'dead_signer'); }
  assert.ok(named, 'dead_signer must be named on the seal surface');
});

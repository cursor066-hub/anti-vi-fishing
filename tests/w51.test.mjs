// Wave-51 regression tests: self-audit findings on ac93be3 —
// gate-deny containment rows bind the anchor's own minted (monotonic) time,
// so a clock rewind cannot reopen the ±2s binding and fabricate a
// missing-row murder verdict on honest operation.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { fixture, hasCode } from './helpers.mjs';
import { signed } from '../src/crypto.mjs';
import { Fabric } from '../src/fabric.mjs';
import { clone } from '../src/canonical.mjs';
import { ISSUER_RULES } from '../src/bootstrap.mjs';
import { ISSUER_MANIFEST_PERMISSIONS, ISSUER_MANIFEST_LIMITATIONS, ISSUER_MANIFEST_IDEMPOTENCY, ISSUER_MANIFEST_COVERAGE } from '../src/connectors.mjs';

// --- self-audit: rewound clock + quarantine denial → the row must bind the
// anchor's signed entry.time (max(now, priorTime)), not the rewound `now` ---
test('w51-1: a quarantine denial row binds its anchor after a clock rewind', t => {
  const h = fixture(t);
  // Seed the head so priorTime is the current fixture time.
  h.f.revoke(h.p('security'), { kind: 'subject', id: 'operator', reason: 'quarantine probe' });
  // Rewind the injectable clock 10s below the committed head time and attest
  // the recovery — the next denial's anchor mints at max(now, priorTime) =
  // head time; a row stamped with raw `now` would sit 10s behind and read
  // as a murdered row.
  h.set(h.now() - 10_000);
  h.f.recoverClock(h.p('security'));
  assert.throws(() => h.f.assertHealthy('acme', 'operator', 'operator-device', h.now()), hasCode('INV-403-QUARANTINE'));
  const rep = h.f.containmentReport(h.p('security'));
  assert.equal(rep.anchored_denials_missing_total, 0, 'the rewound-anchor denial still binds its own row');
  assert.equal(rep.anchored_denials_missing_rows.length, 0);
  h.close();
});

// --- the row's contained_at equals the folded anchor's signed `at` exactly ---
test('w51-2: contained_at equals the anchor entry.time after a rewind', t => {
  const h = fixture(t);
  h.f.revoke(h.p('security'), { kind: 'subject', id: 'operator', reason: 'quarantine probe' });
  const headBefore = h.f.store.auditHeadSeq('acme');
  const rewound = h.now() - 10_000;
  h.set(rewound);
  h.f.recoverClock(h.p('security'));
  assert.throws(() => h.f.assertHealthy('acme', 'operator', 'operator-device', h.now()), hasCode('INV-403-QUARANTINE'));
  const idx = h.f._auditIndex('acme');
  const anchors = (idx.denialsByReq?.get('gate-deny') ?? []).filter(d => d.contained === true);
  const newest = anchors.sort((a, b) => b.at - a.at)[0];
  assert.ok(newest, 'a contained gate-deny anchor folded');
  const rows = h.f.store.db.prepare("SELECT id FROM records WHERE tenant='acme' AND kind='containment' ORDER BY created DESC LIMIT 1").all();
  const row = h.f.store.get('acme', 'containment', rows[0].id);
  assert.equal(row.contained_at, newest.at, 'row stamped with the anchor\'s monotonic time, not the rewound clock');
  assert.ok(newest.at > rewound, 'anchor minted at monotonic max(now, priorTime), not the rewound now');
  assert.ok(h.f.store.auditHeadSeq('acme') > headBefore, 'the denial anchor committed');
  h.close();
});

// --- w51-http F1/F2/F3: the repin remediation seam must feed the same
// chain-anchored enforcement plane (idx.issuerDrift) the drift check
// feeds — named drift without armed quarantine is the hole ---
const bankEntry = h => Object.entries(h.f.tenant('acme').issuers).find(([, v]) => v.name === 'bank');
const manifestServer = async (t, key, now, over = {}) => {
  const srv = http.createServer((req, res) => {
    const payload = { connector_id: 'issuer:bank', version: '1.0.0', domain: 'authoritative',
      actions: Object.keys(ISSUER_RULES.bank), permissions: ISSUER_MANIFEST_PERMISSIONS,
      limitations: ISSUER_MANIFEST_LIMITATIONS, idempotency: ISSUER_MANIFEST_IDEMPOTENCY,
      coverage_implications: ISSUER_MANIFEST_COVERAGE, spec_digest: 'e'.repeat(64),
      issued_at: now(), expires_at: now() + 600000, ...over };
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(signed(payload, key, 'connector-manifest')));
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  t.after(() => srv.close());
  return `http://127.0.0.1:${srv.address().port}`;
};
const driftEvents = h => h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND json_extract(envelope,'$.payload.type') IN ('CONNECTOR_DRIFT','CONNECTOR_REVALIDATED','ISSUER_SPEC_REPINNED')").all().map(r => JSON.parse(r.envelope).payload.type);

test('w51-http F1: residual drift on repin arms the anchored quarantine', async t => {
  const h = fixture(t, ['acme']);
  const [bankKeyId] = bankEntry(h);
  h.repoint(bankKeyId, await manifestServer(t, h.setup.issuerKeys.acme.bank, h.now, { spec_digest: 'f'.repeat(64), permissions: ['mint-anything'] }));
  const repin = await h.f.repinIssuerSpec(h.p('security'), bankKeyId);
  assert.equal(repin.quarantined, true);
  assert.ok(h.f._auditIndex('acme').issuerDrift.has(bankKeyId), 'residual drift must reach idx.issuerDrift');
  assert.ok(driftEvents(h).includes('CONNECTOR_DRIFT'), 'a CONNECTOR_DRIFT conviction must mint');
  // The suspension is real: evidence attach refuses under the quarantine.
  const r = h.proposed();
  assert.throws(() => h.evidence(r, { issuer: 'bank' }), hasCode('INV-403-QUARANTINE'));
  h.close();
});

test('w51-http F2: a clean repin over a live quarantine revalidates in the same transaction', async t => {
  const h = fixture(t, ['acme']);
  const [bankKeyId] = bankEntry(h);
  // Convict first: served spec_digest diverges from the registered pin.
  h.repoint(bankKeyId, await manifestServer(t, h.setup.issuerKeys.acme.bank, h.now, { spec_digest: 'f'.repeat(64) }));
  await h.f.checkIssuerDrift(h.p('security'), bankKeyId);
  assert.ok(h.f._auditIndex('acme').issuerDrift.has(bankKeyId), 'precondition: quarantine armed');
  // The operator repins to the spec actually being served — digest settles,
  // residual clean → the suspension lifts in the same transaction.
  const repin = await h.f.repinIssuerSpec(h.p('security'), bankKeyId);
  assert.equal(repin.repinned, true);
  assert.equal(repin.quarantined, false, 'a clean repin discloses the lifted suspension');
  assert.ok(!h.f._auditIndex('acme').issuerDrift.has(bankKeyId), 'quarantine cleared by the repin');
  const events = driftEvents(h);
  assert.ok(events.includes('ISSUER_SPEC_REPINNED') && events.includes('CONNECTOR_REVALIDATED'), 'pin and revalidation both anchored');
  assert.ok(!h.f.store.db.prepare("SELECT 1 FROM records WHERE tenant='acme' AND kind='issuer-drift' AND id=?").get(bankKeyId), 'forensic row removed only when quarantine cleared');
  h.close();
});

test('w51-http F3a: repin on an invalid manifest convicts durably like the drift check', async t => {
  const h = fixture(t, ['acme']);
  const [bankKeyId] = bankEntry(h);
  // Replay scenario: a validly-signed but expired manifest.
  h.repoint(bankKeyId, await manifestServer(t, h.setup.issuerKeys.acme.bank, h.now, { issued_at: h.now() - 600000, expires_at: h.now() - 1000 }));
  await assert.rejects(() => h.f.repinIssuerSpec(h.p('security'), bankKeyId), hasCode('INV-401-CONNECTOR'));
  assert.ok(driftEvents(h).includes('CONNECTOR_DRIFT'), 'the conviction must be durable evidence, not a transient refusal');
  assert.ok(h.f._auditIndex('acme').issuerDrift.has(bankKeyId), 'quarantine armed by the repin refusal');
  assert.ok(h.f.store.db.prepare("SELECT 1 FROM records WHERE tenant='acme' AND kind='issuer-drift' AND id=?").get(bankKeyId), 'forensic row written');
  h.close();
});

test('w51-http F3b: repin on an unreachable issuer convicts durably like the drift check', async t => {
  const h = fixture(t, ['acme']);
  const [bankKeyId] = bankEntry(h);
  h.repoint(bankKeyId, 'http://127.0.0.1:1'); // nothing listens — connect refused
  await assert.rejects(() => h.f.repinIssuerSpec(h.p('security'), bankKeyId), hasCode('INV-503-CONNECTOR'));
  assert.ok(driftEvents(h).includes('CONNECTOR_DRIFT'), 'unreachability convicts on the ledger');
  assert.ok(h.f._auditIndex('acme').issuerDrift.has(bankKeyId), 'quarantine armed by the repin refusal');
  h.close();
});

// --- w51-seal F-1/F-2/F-3: the seal re-anchor/cut seams must not launder
// destroyed attestation, mint claims about a stale prescan tip, or accept a
// moved chain under the write lock ---
const dropAuditGuards = h => {
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
    h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
};
const corruptAt = (h, seq) =>
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?")
    .run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', seq);

test('w51-seal F-1: murdering a tip seal keeps the reconstruction wedge armed', t => {
  const h = fixture(t);
  for (let i = 0; i < 3; i++) h.f.store.audit('acme', 'W51_PAD', 'operator', `pad-${i}`, {}, h.now());
  dropAuditGuards(h);
  corruptAt(h, h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND envelope LIKE '%pad-0%'").get().seq);
  const r0 = h.f.sealAuditChain(h.p('security'));
  assert.equal(r0.sealed, true);
  assert.ok((h.f._auditIndex('acme').sealDroppedEvents ?? 0) >= 1, 'precondition: the fresh seal attests dropped rows');
  // Murder the tip AUDIT_SEALED row: the chain still verifies (nothing
  // references the tip forward) but the signed head still attests it.
  dropAuditGuards(h);
  h.f.store.db.prepare("DELETE FROM audit WHERE tenant='acme' AND seq=(SELECT MAX(seq) FROM audit WHERE tenant='acme')").run();
  const r1 = h.f.sealAuditChain(h.p('security'));
  assert.equal(r1.head_regressed, true, 'the re-anchor attests the abandoned head');
  const idx = h.f._auditIndex('acme');
  assert.ok((idx.sealDroppedEvents ?? 0) >= 1, 'a destroyed attested tip pins a pessimistic drop claim — the wedge must not release on murder');
  assert.ok((idx.sealDroppedAt ?? 0) > 0, 'the window binds the discovery time');
  h.close();
});

test('w51-seal F-2: a peer commit between prescan and reconcile refuses instead of minting stale claims', t => {
  const h = fixture(t);
  // A clean chain: sealAuditChain takes the no-cut reconcile path.
  for (let i = 0; i < 3; i++) h.f.store.audit('acme', 'W51_PAD', 'operator', `pad-${i}`, {}, h.now());
  const f2 = new Fabric(clone(h.setup.config), h.directory, () => h.now());
  // Emulate the race: a peer instance commits between f1's prescan and its
  // reconcile transaction — the shape assert must refuse, not mint
  // reanchored_tip_seq claims against a tip that moved.
  const origTx = h.f.store.tx.bind(h.f.store);
  h.f.store.tx = fn => { f2.store.audit('acme', 'W51_PEER', 'operator', 'peer-1', {}, h.now()); return origTx(fn); };
  assert.throws(() => h.f.sealAuditChain(h.p('security')), hasCode('INV-503-GATE'));
  // Nothing about the stale tip was attested.
  const claims = h.f.store.db.prepare("SELECT COUNT(*) c FROM audit WHERE tenant='acme' AND json_extract(envelope,'$.payload.type') IN ('AUDIT_WM_REANCHORED','AUDIT_HEAD_REANCHORED')").get().c;
  assert.equal(claims, 0, 'no re-anchor claim may mint against a moved chain');
  // The retry on a fresh prescan lands honestly.
  h.f.store.tx = origTx;
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, false);
  f2.close();
  h.close();
});

test('w51-seal F-3: a peer commit between prescan and cut refuses instead of a phantom sealed_at_seq', t => {
  const h = fixture(t);
  for (let i = 0; i < 4; i++) h.f.store.audit('acme', 'W51_PAD', 'operator', `pad-${i}`, {}, h.now());
  dropAuditGuards(h);
  corruptAt(h, h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND envelope LIKE '%pad-2%'").get().seq);
  const f2 = new Fabric(clone(h.setup.config), h.directory, () => h.now());
  const origTx = h.f.store.tx.bind(h.f.store);
  // An honest peer cannot append to a corrupted chain — the racing commit
  // is a peer SEAL cutting the same break (w51-seal F-3's emulation).
  h.f.store.tx = fn => { f2.sealAuditChain(h.p('security')); return origTx(fn); };
  assert.throws(() => h.f.sealAuditChain(h.p('security')), hasCode('INV-503-GATE'));
  // Only the peer's seal landed — no phantom seal asserts a boundary that
  // never existed on the live chain.
  const seals = h.f.store.db.prepare("SELECT COUNT(*) c FROM audit WHERE tenant='acme' AND json_extract(envelope,'$.payload.type')='AUDIT_SEALED'").get().c;
  assert.equal(seals, 1, 'a moved chain must refuse the cut — the seal record must never describe a fictional boundary');
  h.f.store.tx = origTx;
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, false, 'the peer already cut — the retry verifies instead of sealing a second phantom');
  f2.close();
  h.close();
});

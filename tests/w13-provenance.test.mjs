// Wave-13 provenance-layer regressions (auditor findings F9, F13–F19):
// every security decision that used to trust a mutable row now anchors on
// the signed chain, a vault attestation, or a private field — an insider
// holding in-process SQL + object mutation can no longer counterfeit them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode } from './helpers.mjs';
import { signed } from '../src/crypto.mjs';

// F9: delete the AUTHORITY_REVOKED row BEFORE the index consumes it — the
// surviving 'revocation' floor row must indict the gap and wedge the gate,
// not silently un-revoke the device.
test('w13 F9: a pre-consumption revoke-event delete wedges on the floor row', t => {
  const h = fixture(t);
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'hostile device' });
  // Consume nothing: evict the cached index so the deletion happens before
  // the event is ever projected — the exact race the auditor named.
  h.f._auditIdx?.clear();
  const row = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get();
  // The append-only triggers would stop a bare delete — the insider drops
  // them first, exactly what the store audit documented (open-time guard
  // catches it only on the NEXT boot; the floor check catches it NOW).
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all()) h.f.store.db.exec(`DROP TRIGGER ${tr.name}`);
  h.f.store.db.prepare('DELETE FROM audit WHERE tenant=? AND seq=?').run('acme', row.seq);
  assert.throws(() => h.f.revoked('acme', 'device', 'operator-device'), hasCode('INV-409-INTEGRITY'));
});

// F13: planting a tenant row in the mutable config map mints nothing — the
// authoritative set lives behind the private field.
test('w13 F13: a phantom tenant injected into config.tenants cannot transact', t => {
  const h = fixture(t);
  h.f.config.tenants.ghost = { keys: {}, identities: {}, issuers: {}, genesis_policy: {}, genesis_signatures: [], auth: {}, components: {} };
  assert.throws(() => h.f.tenant('ghost'), hasCode('INV-404-NOT-FOUND'));
  assert.throws(() => h.f.authorize({ subject_id: 'x', tenant_id: 'ghost' }, ['operator']), hasCode('INV-401-AUTH'));
});

// F14: the tenant swap itself is unreachable — no public setter exists.
test('w13 F14: no reachable seam swaps a tenant object in place', t => {
  const h = fixture(t);
  assert.equal(typeof h.f._setTenant, 'undefined');
  // Even swapping the mirror entry changes nothing the gate reads.
  const mirror = h.f.config.tenants.acme;
  h.f.config.tenants.acme = { keys: {}, identities: {}, issuers: {} };
  assert.equal(h.f.tenant('acme'), h.f.tenant('acme'));
  assert.ok(Object.keys(h.f.tenant('acme').identities).length > 0, 'the authoritative tenant survived the mirror swap');
  h.f.config.tenants.acme = mirror;
});

// F15: the issuer endpoint is a frozen trust anchor — a live re-point that
// would exfiltrate the Bearer token to a hostile host cannot be written.
test('w13 F15: issuer endpoint assignment throws on the frozen record', t => {
  const h = fixture(t);
  const issuer = Object.values(h.f.tenant('acme').issuers)[0];
  assert.throws(() => { issuer.endpoint = 'https://attacker.invalid'; }, TypeError);
});

// F16a: the insider writes the target journal directly (bypassing the
// fabric, exactly as in-process SQL access allows) and flips consumed —
// a real ciphertext, no reservation, no dispatch anchor. VERIFIED refuses.
test('w13 F16: a journal written out-of-band cannot mint VERIFIED', t => {
  const h = fixture(t);
  const { record, certificate } = h.ready();
  const id = certificate.payload.certificate_id;
  h.f.target.execute(record.capsule, id, h.now()); // raw dispatch — no chain events
  const stored = h.f.store.must('acme', 'certificate', id);
  stored.consumed = true; stored.status = 'EXECUTING';
  h.f.store.put('acme', 'certificate', id, stored, h.now());
  const journal = h.f.target.outcome('acme', id);
  assert.ok(journal, 'planted journal is durable');
  assert.throws(() => h.f.reconcile(h.p(), id), e => e.code === 'INV-409-INTEGRITY' || e.code === 'INV-409-STATE');
});

// F16b: deleting the EXECUTION_RESERVED event before the index consumes it
// leaves a consumed flag that can never satisfy the reservation anchor.
test('w13 F16b: a deleted reservation event strands the consumed flag', t => {
  const h = fixture(t);
  const { certificate } = h.ready();
  const id = certificate.payload.certificate_id;
  // Begin a real execution, kill it before dispatch (journal absent).
  assert.equal(h.f.execute(h.p(), certificate, { fault: 'before-dispatch' }).payload.status, 'UNCERTAIN');
  h.f._auditIdx?.clear();
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all()) h.f.store.db.exec(`DROP TRIGGER ${tr.name}`);
  const res = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND envelope LIKE '%EXECUTION_RESERVED%' ORDER BY seq DESC LIMIT 1").get();
  h.f.store.db.prepare('DELETE FROM audit WHERE tenant=? AND seq=?').run('acme', res.seq);
  h.f._auditIdx?.clear();
  // A mid-chain delete trips the tamper guard; a reservation that never
  // anchored fails the state check — both refusals are the wedge working.
  assert.throws(() => h.f.reconcile(h.p(), id), e => /^INV-409-(STATE|INTEGRITY|AUDIT-TAMPER)$/.test(e.code));
});

// F17: a squatted usage row cannot suppress the charge — only a signed
// DATA_ACCESSED event for THIS certificate counts.
test('w13 F17: a squatted usage row cannot suppress the disclosure charge', t => {
  const h = fixture(t, ['acme']);
  const r = h.proposed('data.export', { dataset: 'dataset-1', columns: ['id'], row_ids: ['row-1'], max_rows: 1, classification: 'internal', jurisdiction: 'EU' }, { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Operations' }, destination: 'customer-vault' });
  h.evidence(r); h.evidence(r, { issuer: 'registry', kind: 'dataset_authority' }); h.approve(r, 2);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  const certId = cert.payload.certificate_id;
  // Squat the billing mirror before the real charge — the F17 attack.
  h.f.store.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?)').run('acme', 'operator', 'dataset-1', h.now(), 999999, `cert:${certId}`, certId);
  h.f.execute(h.p(), cert);
  const accesses = h.f._auditIndex('acme').dataAccess.filter(a => a.certificate_id === certId);
  assert.equal(accesses.length, 1, 'the disclosure was attested despite the squatted row');
  const charges = h.f.store.db.prepare('SELECT * FROM usage WHERE capability=?').all(`cert:${certId}`);
  assert.equal(charges.length, 1);
  assert.ok(charges[0].cost > 999999, 'the honest charge folded into the squatted row — no suppression');
});

// F18: a genuine signed outcome transplanted under a sibling certificate's
// key refuses on the row-key binding.
test('w13 F18: a transplanted outcome cannot answer for a sibling certificate', t => {
  const h = fixture(t);
  const a = h.ready(), b = h.ready();
  h.f.execute(h.p(), a.certificate);
  const real = h.f.store.get('acme', 'outcome', a.certificate.payload.certificate_id);
  h.f.store.put('acme', 'outcome', b.certificate.payload.certificate_id, real, h.now());
  const stored = h.f.store.must('acme', 'certificate', b.certificate.payload.certificate_id);
  stored.consumed = true; h.f.store.put('acme', 'certificate', b.certificate.payload.certificate_id, stored, h.now());
  assert.throws(() => h.f.reconcile(h.p(), b.certificate.payload.certificate_id), hasCode('INV-409-INTEGRITY'));
});

// F19: flipping the parent's mutable status cannot unbind children — only
// a chain-anchored outcome resolves the parent.
test('w13 F19: parent status tamper cannot free bound children early', t => {
  const h = fixture(t);
  const certified = (suffix = '') => {
    const r = h.proposed('finance.beneficiary.create', { vendor_id: `vendor-${suffix || 'X'}`, bank_account: `TESTBANK0000${suffix || '1'}`, currency: 'EUR' });
    h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2);
    return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) };
  };
  const c1 = certified('A'), c2 = certified('B');
  const r = h.proposed('action.composite', { children: [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id] }, { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'pair' } });
  h.approve(r, 2);
  h.f.certificate(h.p(), r.capsule.capsule_id);
  // Attacker flips the parent's status to look settled — children stay bound.
  const parent = h.f.store.must('acme', 'capsule', r.capsule.capsule_id);
  parent.status = 'SETTLED'; h.f.store.put('acme', 'capsule', r.capsule.capsule_id, parent, h.now());
  assert.throws(() => h.f.execute(h.p(), c1.certificate), hasCode('INV-409-STATE'));
});

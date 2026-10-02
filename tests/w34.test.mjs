// w34: seal lifecycle carryover — a seal must re-attest (or loudly name)
// every verifiable doomed event, not just spend/access/revocation/capability
// rows. Before this wave the seal laundered certificates: cut the
// reservation/dispatch/outcome/cancel/binding anchors and remediation
// re-armed a spent cert for replay (composite audit CRITICAL-1).
import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helpers.mjs';

// --- attacker primitives (write-only insider, no vault keys) -------------
const dropAuditGuards = h => {
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
    h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
};
const corruptFirstMatching = (h, pattern) => {
  const row = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND envelope LIKE ? ORDER BY seq").get(pattern);
  assert.ok(row, `anchor row for ${pattern}`);
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?").run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', row.seq);
  return row.seq;
};
const snapRecord = (h, kind, id) => ({
  value: h.f.store.db.prepare('SELECT value FROM records WHERE tenant=? AND kind=? AND id=?').get('acme', kind, id)?.value,
  wrapped: h.f.store.db.prepare('SELECT wrapped FROM deks WHERE tenant=? AND kind=? AND id=?').get('acme', kind, id)?.wrapped,
});
const restoreRecord = (h, kind, id, snap) => {
  h.f.store.db.prepare('UPDATE records SET value=? WHERE tenant=? AND kind=? AND id=?').run(snap.value, 'acme', kind, id);
  h.f.store.db.prepare('UPDATE deks SET wrapped=? WHERE tenant=? AND kind=? AND id=?').run(snap.wrapped, 'acme', kind, id);
};
const delRecord = (h, kind, id) => {
  h.f.store.db.prepare('DELETE FROM deks WHERE tenant=? AND kind=? AND id=?').run('acme', kind, id);
  h.f.store.db.prepare('DELETE FROM records WHERE tenant=? AND kind=? AND id=?').run('acme', kind, id);
};
const sealMeta = h => JSON.parse(h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND envelope LIKE '%AUDIT_SEALED%' ORDER BY seq DESC LIMIT 1").get().envelope).payload.metadata;

// F-A regression: a spent certificate stays spent after the seal cuts its
// lifecycle anchors and the mutable rows are rolled back.
test('w34: seal-cut certificate cannot replay — spent state survives remediation', t => {
  const h = fixture(t);
  const { record, certificate: cert } = h.ready();
  const certId = cert.payload.certificate_id;
  const target = record.capsule.action.target_resource;
  const certSnap = snapRecord(h, 'certificate', certId);
  assert.equal(h.f.execute(h.p('operator'), cert).payload.status, 'VERIFIED');
  assert.equal(h.f.target.state('acme', target).version, 1);

  dropAuditGuards(h);
  corruptFirstMatching(h, '%EXECUTION_RESERVED%'); // dooms RESERVED+DISPATCHED+OUTCOME
  assert.equal(h.f.sealAuditChain(h.p('security')).sealed, true);

  restoreRecord(h, 'certificate', certId, certSnap); // consumed=false again
  delRecord(h, 'outcome', certId);                   // stale signed verdict
  h.f.target.db.prepare('DELETE FROM transactions WHERE tenant=? AND id=?').run('acme', certId);
  h.f.target.db.prepare('DELETE FROM resources WHERE tenant=? AND id=?').run('acme', target);

  assert.throws(() => h.f.execute(h.p('operator'), cert), e => e?.code === 'INV-409-REPLAY');
});

// F-B regression: a cancelled certificate stays cancelled after the seal.
test('w34: seal-cut cancel cannot resurrect — cancellation survives remediation', t => {
  const h = fixture(t);
  const { record, certificate: cert } = h.ready();
  const certId = cert.payload.certificate_id;
  const target = record.capsule.action.target_resource;
  const certSnap = snapRecord(h, 'certificate', certId);
  h.f.cancel(h.p('operator'), record.capsule.capsule_id);
  assert.throws(() => h.f.execute(h.p('operator'), cert), e => e?.code?.startsWith('INV-'));

  dropAuditGuards(h);
  corruptFirstMatching(h, '%EXECUTION_OUTCOME%'); // dooms CANCELLED outcome + ACTION_CANCELLED
  assert.equal(h.f.sealAuditChain(h.p('security')).sealed, true);
  restoreRecord(h, 'certificate', certId, certSnap);
  delRecord(h, 'outcome', certId);

  assert.throws(() => h.f.execute(h.p('operator'), cert), e => e?.code === 'INV-409-REPLAY' || e?.code === 'INV-409-STATE' || e?.code === 'INV-409-INTEGRITY');
  assert.equal(h.f.target.state('acme', target).version, 0, 'cancelled cert mutated nothing');
});

// F-C regression: cutting the parent CERTIFICATE_ISSUED must not unbind the
// composite children — the binding is re-attested by the carryover.
test('w34: seal-cut parent issuance keeps composite children bound', t => {
  const h = fixture(t);
  const c1 = h.ready(), c2 = h.ready();
  const r = h.proposed('action.composite', { children: [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id] }, { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'Batch' } });
  h.approve(r, 2);
  const parentCert = h.f.certificate(h.p('operator'), r.capsule.capsule_id);
  assert.throws(() => h.f.execute(h.p('operator'), c1.certificate), e => e?.code === 'INV-409-STATE' || e?.code === 'INV-409-REPLAY');

  const snaps = [c1, c2].map(c => snapRecord(h, 'certificate', c.certificate.payload.certificate_id));
  const childTargets = [c1, c2].map(c => c.record.capsule.action.target_resource);
  const o1 = h.f.execute(h.p('operator'), parentCert);
  assert.equal(o1.payload.status, 'VERIFIED');

  dropAuditGuards(h);
  const seq = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND envelope LIKE '%CERTIFICATE_ISSUED%' ORDER BY seq DESC").get().seq;
  const env = JSON.parse(h.f.store.db.prepare('SELECT envelope FROM audit WHERE tenant=? AND seq=?').get('acme', seq).envelope);
  assert.equal(env.payload.reference, r.capsule.capsule_id, 'corrupting the parent issuance row');
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?").run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', seq);
  assert.equal(h.f.sealAuditChain(h.p('security')).sealed, true);

  [c1, c2].forEach((c, i) => {
    const certId = c.certificate.payload.certificate_id;
    restoreRecord(h, 'certificate', certId, snaps[i]);
    delRecord(h, 'outcome', certId);
    h.f.target.db.prepare('DELETE FROM transactions WHERE tenant=? AND id=?').run('acme', certId);
    h.f.target.db.prepare('DELETE FROM resources WHERE tenant=? AND id=?').run('acme', childTargets[i]);
  });

  // Children remain both bound AND settled — no solo replay, no parent rebind.
  for (const c of [c1, c2]) {
    assert.throws(() => h.f.execute(h.p('operator'), c.certificate), e => e?.code === 'INV-409-REPLAY' || e?.code === 'INV-409-STATE' || e?.code === 'INV-409-INTEGRITY');
  }
});

// The seal head must publish what it carried and what it could not verify —
// lifecycle entries replay into the live fold, unverifiable rows are named.
test('w34: seal head names carried lifecycle entries and dropped events', t => {
  const h = fixture(t);
  const { certificate: cert } = h.ready();
  h.f.execute(h.p('operator'), cert);

  dropAuditGuards(h);
  const doomedSeq = corruptFirstMatching(h, '%EXECUTION_RESERVED%');
  const doomedHash = h.f.store.db.prepare('SELECT hash FROM audit WHERE tenant=? AND seq=?').get('acme', doomedSeq).hash;
  assert.equal(h.f.sealAuditChain(h.p('security')).sealed, true);

  const meta = sealMeta(h);
  const carriedTypes = new Set((meta.lifecycle_carryover ?? []).map(c => c.type));
  // Corrupting EXECUTION_RESERVED dooms everything after it: DISPATCHED and
  // OUTCOME are verifiable originals and MUST be carried forward, or the
  // spend they settle would launder. RESERVED itself is destroyed.
  assert.ok(carriedTypes.has('EXECUTION_DISPATCHED'), `dispatch re-anchored (carried: ${[...carriedTypes].join(',')})`);
  assert.ok(carriedTypes.has('EXECUTION_OUTCOME'), `outcome re-anchored (carried: ${[...carriedTypes].join(',')})`);
  assert.equal(meta.carryover_totals.lifecycle, meta.lifecycle_carryover.length);
  // The corrupted row itself could not verify → it is named, not silent.
  const dropped = meta.dropped_events ?? [];
  assert.equal(meta.carryover_totals.dropped_events, dropped.length);
  assert.ok(dropped.some(d => d.seq === doomedSeq && d.hash === doomedHash), `dropped_events names seq ${doomedSeq}`);
});

// MEDIUM-1: dropped anchors force worst-case reconstruction coverage — the
// ledger cannot re-derive erased disclosure, so budgets must not trip on it.
test('w34: dropped seal events count as worst-case reconstruction coverage', t => {
  const h = fixture(t);
  h.ready();
  dropAuditGuards(h);
  corruptFirstMatching(h, '%CAPSULE_PROPOSED%');
  assert.equal(h.f.sealAuditChain(h.p('security')).sealed, true);

  const idx = h.f._auditIndex('acme');
  assert.ok(idx.sealDroppedEvents > 0, 'seal reports dropped events');
  // The prospector path refuses a data.export the moment any doomed anchor
  // went unverifiable — erased history could hide full-dataset disclosure.
  assert.equal(typeof idx.sealDroppedEvents, 'number');
});

// MEDIUM-2: an outcome row no anchored event ever attested is tamper
// evidence — the seal names-but-cannot-carry an unverifiable outcome, so a
// surviving stored verdict with no anchor fails closed, not "no anchor to
// compare".
test('w34: unanchored outcome row fails closed', t => {
  const h = fixture(t);
  const { certificate: cert } = h.ready();
  const certId = cert.payload.certificate_id;
  h.f.execute(h.p('operator'), cert);

  // Corrupt the EXECUTION_OUTCOME envelope — the seal destroys it but can
  // only name it as dropped; the signed outcome row outlives its anchor.
  dropAuditGuards(h);
  corruptFirstMatching(h, '%EXECUTION_OUTCOME%');
  assert.equal(h.f.sealAuditChain(h.p('security')).sealed, true);
  const meta = sealMeta(h);
  assert.ok((meta.dropped_events ?? []).length > 0, 'unverifiable outcome named as dropped');
  assert.throws(() => h.f.reconcile(h.p('operator'), certId), e => e?.code === 'INV-409-INTEGRITY');
});

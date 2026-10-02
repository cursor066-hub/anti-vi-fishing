// Wave-25 regression suite — chain-head watermark hardening (W25-01/F-2/F-3/F-4),
// anchored clock-recovery prior (F-1), persistent wedge flag (F-5),
// resurrection-veto skips for dead authority (F-6), seal identity revocation
// (F-7), anchored parent-cert fail-closed (W25-02), transform_min_bucket
// emergency floor (W25-04), physical-row watermark binding (W25-06),
// signed acquired_at supersession (W25-F1).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { fixture, hasCode } from './helpers.mjs';
import { clone, digest } from '../src/canonical.mjs';
import { signed } from '../src/crypto.mjs';
import { emergencyWeakening } from '../src/policy.mjs';
import { watermark } from '../src/datagate.mjs';
import { Fabric } from '../src/fabric.mjs';

const HEADS = h => join(h.directory, 'chain-heads.json');
const dropAuditTriggers = db => { for (const tr of db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all()) db.exec(`DROP TRIGGER ${tr.name}`); };
const restoreAuditTriggers = db => db.exec(`
  CREATE TRIGGER no_audit_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
  CREATE TRIGGER no_audit_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
  CREATE TRIGGER audit_seq_guard BEFORE INSERT ON audit WHEN NEW.seq <> (SELECT COALESCE(MAX(seq),0)+1 FROM audit WHERE tenant=NEW.tenant) BEGIN SELECT RAISE(ABORT, 'audit sequence must extend the head'); END;`);

const evidenceEnvelope = (h, record, { kind = 'ownership', issuer = 'bank', claim = 'supports', acquired_at, expiry } = {}) => {
  const tenant = record.capsule.tenant_id;
  const issEntry = Object.values(h.setup.config.tenants[tenant].issuers ?? {}).find(i => i.name === issuer || i.issuer_id === issuer);
  const rs = record.capsule.requested_state ?? {};
  const claims = claim !== 'supports' ? {} : { account: rs.bank_account ?? 'TESTBANK000001', owner_id: record.capsule.action.target_resource };
  const payload = { evidence_id: randomUUID(), tenant_id: tenant, capsule_digest: record.capsule_digest, kind, content_digest: digest({ source: 'synthetic-only', claim }), acquired_at, expires_at: expiry ?? h.now() + 600000, confidence: 100, advisory: false, claim, dependencies: [], provenance: 'Synthetic test issuer; no external authority assertion', retention_until: (expiry ?? h.now() + 600000) + 60000, claims, ...(issEntry?.version !== undefined ? { issuer_version: issEntry.version } : {}) };
  return signed(payload, h.setup.issuerKeys[tenant][issuer], 'evidence');
};

// W25-01/F-4: deleting chain-heads.json must wedge the index fail-closed —
// committed rows without a signed head is the deleted-watermark tell.
test('w25 W25-01: a deleted chain-head file wedges the index; seal re-anchors the verified tip', t => {
  const h = fixture(t, ['acme']);
  h.ready();
  assert.ok(existsSync(HEADS(h)), 'watermark file exists after committed appends');
  unlinkSync(HEADS(h));
  assert.throws(() => h.f._auditIndex('acme'), hasCode('INV-409-INTEGRITY'), 'committed rows with no head file must wedge');
  const res = h.f.sealAuditChain(h.p('security'));
  assert.equal(res.head_reanchored, true, 'seal re-anchors the verified tip');
  assert.doesNotThrow(() => h.f._auditIndex('acme'), 'index folds after re-anchor');
  assert.ok(existsSync(HEADS(h)), 'fresh signed head written');
  const last = h.f.store.auditPage('acme', { after: 0, limit: 1000 }).entries.at(-1);
  assert.equal(last.envelope.payload.type, 'AUDIT_HEAD_REANCHORED', 're-anchor lands on the signed chain');
});

// W25-01 replay: an OLDER authentic head (stolen earlier bytes) regresses the
// watermark below what the index already consumed — the signature is real,
// the position is a lie.
test('w25 W25-01b: replaying an older signed head wedges the consumed index', t => {
  const h = fixture(t, ['acme']);
  h.ready();
  const stale = readFileSync(HEADS(h), 'utf8');
  h.proposed(); // advances the chain past the captured head
  h.f._auditIndex('acme'); // consume to the new tip
  writeFileSync(HEADS(h), stale);
  assert.throws(() => h.f._auditIndex('acme'), hasCode('INV-409-INTEGRITY'), 'stale signed head regresses below the consumed index');
  const res = h.f.sealAuditChain(h.p('security'));
  assert.equal(res.head_reanchored, true);
  assert.doesNotThrow(() => h.f._auditIndex('acme'));
});

// F-3: cutting a span that anchored revocations must reconcile the revocation
// floor rows — the un-revocation is attested on the seal, never silent.
// Corrupting the revocation row itself puts it INSIDE the cut span.
// F-3 (revised by w33-seal F-1): a floor row whose anchoring event is cut or
// corrupted is NEVER deleted — the seal carries the ref forward marked
// floor_derived, so the revocation keeps enforcing. Deleting it was a silent
// un-revocation of real authority.
test('w25 F-3: sealing over an AUTHORITY_REVOKED span carries the orphaned floor row forward', t => {
  const h = fixture(t, ['acme']);
  h.ready();
  h.f.revoke(h.p('security'), { kind: 'device', id: 'custodian-1-device', reason: 'rotate out' });
  assert.equal(h.f.revoked('acme', 'device', 'custodian-1-device'), true);
  const revokeSeq = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND envelope LIKE '%AUTHORITY_REVOKED%'").get().seq;
  // Corrupt the revocation row itself — the seal cut must start at it.
  dropAuditTriggers(h.f.store.db);
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?").run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', revokeSeq);
  restoreAuditTriggers(h.f.store.db);
  // The fold consumes rows lazily; the seal's own pre-scan is what verifies
  // every signature and pins the cut at the corrupted row.
  const sealed = h.f.sealAuditChain(h.p('security'));
  assert.equal(sealed.sealed, true);
  assert.equal(h.f.revoked('acme', 'device', 'custodian-1-device'), true, 'a revocation its anchor cannot prove stays revoked — fail closed');
  assert.ok(h.f.store.get('acme', 'revocation', 'device:custodian-1-device'), 'orphaned floor row is kept, not dropped');
  const sealRow = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get();
  const pl = JSON.parse(sealRow.envelope).payload;
  assert.equal(pl.type, 'AUDIT_SEALED');
  assert.ok((pl.metadata.revocations_carryover ?? []).some(r => r.reference === 'device:custodian-1-device' && r.floor_derived === true), 'the floor-derived carry is named in the signed seal record');
});

// W25-02: a composite parent cert's anchored binding is ledger-proven — a
// deleted cert row must scream INV-409, not silently unbind children.
test('w25 W25-02: deleting an anchored parent certificate row fails closed', t => {
  const h = fixture(t);
  const child = h.ready();
  const child2 = h.ready(h.proposed());
  const r = h.proposed('action.composite', { children: [child.record.capsule.capsule_id, child2.record.capsule.capsule_id] }, { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'Batch' } });
  h.approve(r, 2);
  const parentCert = h.f.certificate(h.p(), r.capsule.capsule_id);
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='certificate' AND id=?").run(parentCert.payload.certificate_id);
  assert.throws(() => h.f.execute(h.p(), child.certificate), hasCode('INV-409-INTEGRITY'), 'anchored parent row missing must scream, not unbind');
});

// F-1: a forged-LOW clock.last cannot shrink the resurrection veto span —
// the anchored fold time is the real floor.
test('w25 F-1: a forged-low clock.last still vets the anchored rewind span', t => {
  const h = fixture(t, ['acme']);
  const T0 = h.now();
  const r = h.proposed('finance.beneficiary.create', { vendor_id: 'v-f1', bank_account: 'TESTBANK1', currency: 'EUR' }, { expires_at: T0 + 150000 });
  h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2);
  h.f.certificate(h.p(), r.capsule.capsule_id); // cert exp ≈ T0+150000
  h.advance(200000); // anchored last event at T0+200000
  h.proposed();
  // Forge the mutable clock last far below the anchored maximum, then rewind
  // the operator clock into the span where the certificate lapses.
  h.f.store.db.prepare('UPDATE clock SET last=? WHERE id=1').run(T0 - 5000);
  h.set(T0 + 100000);
  assert.throws(() => h.f.recoverClock(h.p('security')), hasCode('INV-503-TIME'), 'a cert expiring inside the anchored span still vetoes');
});

// F-6: dead authority inside the span must not veto — a revoked certificate
// cannot resurrect, so recovery proceeds past it.
test('w25 F-6: a revoked certificate inside the rewind span does not deadlock recovery', t => {
  const h = fixture(t, ['acme']);
  const T0 = h.now();
  const r = h.proposed('finance.beneficiary.create', { vendor_id: 'v-f6', bank_account: 'TESTBANK2', currency: 'EUR' }, { expires_at: T0 + 150000 });
  h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  h.f.revoke(h.p('security'), { kind: 'certificate', id: cert.payload.certificate_id, reason: 'compromised' });
  h.advance(200000); h.proposed();
  h.set(T0 + 100000);
  const rec = h.f.recoverClock(h.p('security'));
  assert.equal(rec.recovered_at, T0 + 100000);
  assert.equal(rec.unverifiable_tenants.length, 0);
});

// F-7: a config-revoked identity may not run the break-glass seal.
test('w25 F-7: a revoked identity cannot seal the audit chain', t => {
  const h = fixture(t, ['acme']);
  const [keyId] = Object.entries(h.f.tenant('acme').identities).find(([, v]) => v.subject_id === 'security');
  // The reopen itself re-attests drift through the revoked principal — the
  // refused reassert proves the fabric booted with the revoked identity.
  assert.throws(() => h.reconfigure(cfg => { cfg.tenants.acme.identities[keyId].revoked = true; }), hasCode('INV-401-AUTH'));
  assert.throws(() => h.f.sealAuditChain(h.p('security')), hasCode('INV-403-QUARANTINE'));
});

// W25-04: emergencyWeakening must refuse lowering the transform bucket floor.
test('w25 W25-04: lowering runtime.transform_min_bucket is an emergency weakening', t => {
  const h = fixture(t, ['acme']);
  const base = h.f.policy('acme');
  const next = clone(base); next.runtime = { ...next.runtime, transform_min_bucket: (base.runtime.transform_min_bucket ?? 10) - 5 };
  assert.equal(emergencyWeakening(base, next, h.now()), 'runtime.transform_min_bucket');
  const dropped = clone(base); delete dropped.runtime.transform_min_bucket;
  assert.equal(emergencyWeakening(base, dropped, h.now()), 'runtime.transform_min_bucket', 'dropping the floor also weakens');
  const tightened = clone(base); tightened.runtime = { ...tightened.runtime, transform_min_bucket: (base.runtime.transform_min_bucket ?? 10) + 5 };
  assert.equal(emergencyWeakening(base, tightened, h.now()), null, 'raising the floor is not a weakening');
});

// W25-06: the watermark binds the physical row_id from the plan, never a
// transformed 'id' field the projection may have rewritten.
test('w25 W25-06: watermark binds the physical row id, not the projected id', t => {
  const ctx = { tenant: 'acme', dataset: 'ds', subject: 'op', requestId: 'req-1', tenantWatermarkKey: Buffer.alloc(32).toString('base64url'), rowIds: ['row-physical-9'] };
  const out = watermark([{ id: 'transformed-constant', name: 'x' }], ctx);
  assert.equal(out.watermarks[0].row_id, 'row-physical-9', 'physical storage id wins over the projected id field');
  assert.throws(() => watermark([{ id: 'x' }], { ...ctx, rowIds: undefined }), hasCode('INV-409-STATE'), 'a missing physical id cannot watermark');
});

// W25-F1: supersession follows the SIGNED acquired_at — a stale 'supports'
// re-attached after a fresher 'conflict' cannot retract the veto.
test('w25 W25-F1: stale evidence re-attach cannot retract a fresher signed claim', t => {
  const h = fixture(t, ['acme']);
  const r = h.proposed();
  const supports = evidenceEnvelope(h, r, { claim: 'supports', acquired_at: h.now() });
  h.f.attachEvidence(h.p('operator'), r.capsule.capsule_id, supports);
  h.advance(60000);
  const conflict = evidenceEnvelope(h, r, { claim: 'conflict', acquired_at: h.now() });
  h.f.attachEvidence(h.p('operator'), r.capsule.capsule_id, conflict);
  // Attach a STALE supports whose signed acquired_at predates the conflict.
  const stale = evidenceEnvelope(h, r, { claim: 'supports', acquired_at: h.now() - 30000 });
  h.f.attachEvidence(h.p('operator'), r.capsule.capsule_id, stale);
  const items = h.f.graph('acme', h.f.store.must('acme', 'capsule', r.capsule.capsule_id)).items;
  const byId = id => items.find(x => x.payload.evidence_id === id);
  assert.equal(byId(conflict.payload.evidence_id).superseded_by, null, 'fresher signed claim stays authoritative');
  assert.equal(byId(stale.payload.evidence_id).superseded_by, conflict.payload.evidence_id, 'stale attach is itself superseded');
});

// F-5: the wedge flag is rebuilt from the chains at construction — a restart
// must not forget a wedged tenant nor clear a flag the chain still carries.
test('w25 F-5: a wedged tenant stays refused across a fabric restart', t => {
  const h = fixture(t, ['acme', 'globex']);
  const T0 = h.now();
  h.advance(200000);
  h.proposed(); // an acme event at the forward time — anchored floor moves
  // Wedge globex: an unverifiable audit row makes its fold fail.
  const ghead = h.f.store.db.prepare("SELECT seq,hash FROM audit WHERE tenant='globex' ORDER BY seq DESC LIMIT 1").get();
  dropAuditTriggers(h.f.store.db);
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('globex', ghead.seq + 1, ghead.hash, 'x'.repeat(64), '{"payload":{"time":1},"signatures":[{"signature":"AA"}]}');
  restoreAuditTriggers(h.f.store.db);
  h.set(T0 + 100000); // rewind below the last committed row time
  const rec = h.f.recoverClock(h.p('security'));
  assert.ok(rec.unverifiable_tenants.includes('globex'), 'wedged tenant named in the recovery record');
  assert.equal(h.f._clockRecoveryUnverifiable.has('globex'), true);
  // A fresh fabric open over the same directory TOLERATES the wedge — the
  // bootstrap snapshot/drift appends cannot sign on a poisoned chain, but
  // construction must survive or sealAuditChain itself is unreachable
  // (w31-runtime F-2). The tenant's fold still refuses on demand.
  const g = new Fabric(h.setup.config, h.directory, () => T0 + 100000);
  t.after(() => g.close());
  assert.throws(() => g._auditIndex('globex'), e => /^INV-409/.test(e.code), 'the wedge itself is still live');
  assert.throws(() => h.f._auditIndex('globex'), e => /^INV-409/.test(e.code), 'the wedge itself is still live');
});

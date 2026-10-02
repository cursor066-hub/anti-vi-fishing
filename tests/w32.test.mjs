// w32 regressions — seal carryover positional/witness bounds (seal F-1..F-6),
// mirror-table injection defence (store F1), durable-watermark repair
// (store F2/F3), target.db wipe residue (store F4), atomic dek+record
// deletes (store F5), poisoned/sealed config baselines (fixverify F-2),
// tombstoned capsule 404s (fixverify F-3), non-string subject dedupe
// (fixverify F-5), cancelled re-mint refusal, provably-untouched release,
// integrity-code propagation, child-outcome folding and UNCERTAIN binding
// (composite F-1..F-5).
import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fixture, hasCode, runtimeInput, runtimeRequest } from './helpers.mjs';
import { Fabric } from '../src/fabric.mjs';
import { digest, clone } from '../src/canonical.mjs';

const dropAuditTriggers = db => { for (const tr of db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all()) db.exec(`DROP TRIGGER "${String(tr.name).replace(/"/g, '""')}"`); };
const restoreAuditTriggers = db => db.exec(`
  CREATE TRIGGER no_audit_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
  CREATE TRIGGER no_audit_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
  CREATE TRIGGER audit_seq_guard BEFORE INSERT ON audit WHEN NEW.seq <> (SELECT COALESCE(MAX(seq),0)+1 FROM audit WHERE tenant=NEW.tenant) BEGIN SELECT RAISE(ABORT, 'audit sequence must extend the head'); END;`);
const corruptTail = h => {
  const bad = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get().seq;
  corruptAt(h, bad); return bad;
};
const corruptAt = (h, seq) => {
  dropAuditTriggers(h.f.store.db);
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?").run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', seq);
  restoreAuditTriggers(h.f.store.db);
};
const seqOf = (h, like) => h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND envelope LIKE ? ORDER BY seq DESC LIMIT 1").get(like).seq;
const sealMeta = h => JSON.parse(h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND envelope LIKE '%AUDIT_SEALED%' ORDER BY seq DESC LIMIT 1").get().envelope).payload.metadata;

// seal F-1/F-3: a replayed envelope grafted into the doomed span (valid
// signature, wrong seq binding) must NOT be carried — the carryover accepts
// only rows whose payload sequence matches their row position.
test('w32 seal F1: a grafted replayed envelope is not carried into AUDIT_SEALED', t => {
  const h = fixture(t, ['acme']);
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ max_cost: 3 }));
  const req = runtimeRequest(cap);
  h.f.runtime.consume(h.p(), req);
  // Graft: copy the valid RUNTIME_ALLOWED envelope onto a fresh tail row —
  // its payload.sequence still names its original row, so it is a replay.
  const real = h.f.store.db.prepare("SELECT seq,envelope FROM audit WHERE tenant='acme' AND envelope LIKE '%RUNTIME_ALLOWED%'").get();
  const tipSeq = h.f.store.db.prepare("SELECT MAX(seq) m FROM audit WHERE tenant='acme'").get().m;
  dropAuditTriggers(h.f.store.db);
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', tipSeq + 1, 'x', digest(JSON.parse(real.envelope).payload), real.envelope);
  restoreAuditTriggers(h.f.store.db);
  // Doomed span must cover both the graft and the real spend anchor.
  corruptAt(h, real.seq - 1);
  assert.equal(h.f.sealAuditChain(h.p('security')).sealed, true);
  const carried = sealMeta(h).spend_carryover.filter(u => u.request_id === req.request_id);
  assert.equal(carried.length, 1, 'the honest spend carries exactly once — the grafted duplicate is dropped');
});

// seal F-2/F-4 + store F1 + fixverify F-1/F-4 + w33-seal F-2/F-5/F-6:
// mirror tables are never admitted into the signed carryover — a pair
// witness still let planted cost/request_id/row_ids ride it, so mirrors were
// dropped entirely. Only doomed-verified event content is re-attested.
test('w32 seal F2/F4 + w33: no usage/data_access mirror row ever carries into a signed seal', t => {
  const h = fixture(t, ['acme']);
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ max_cost: 1000 }));
  const req = runtimeRequest(cap);
  h.f.runtime.consume(h.p(), req);
  const capId = cap.payload.capability_id, subj = h.p().subject_id;
  // Planted mirror rows on a fully witnessed pair — every honest-looking
  // shape is still unprovable and must be dropped.
  h.f.store.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?)').run('acme', 'phantom', 'res', h.now(), 999, 'phantom-cap', 'phantom-req');
  h.f.store.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?)').run('acme', subj, cap.payload.resource, h.now(), -5, capId, 'neg-req');
  h.f.store.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?)').run('acme', subj, cap.payload.resource, h.now(), 999999999, capId, 'inflated-req');
  h.f.store.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?)').run('acme', subj, cap.payload.resource, h.now(), 1, capId, 'mirror-req');
  h.f.store.db.prepare('INSERT INTO data_access VALUES(?,?,?,?,?,?)').run('acme', 'phantom-sub', 'phantom-ds', 'row-x', 'id', h.now());
  h.f.store.db.prepare('INSERT INTO data_access VALUES(?,?,?,?,?,?)').run('acme', subj, cap.payload.resource, 'row-poison', 'ssn', h.now());
  // Doom the span that contains this capability's anchors.
  corruptAt(h, seqOf(h, '%CAPABILITY_ISSUED%'));
  assert.equal(h.f.sealAuditChain(h.p('security')).sealed, true);
  const meta = sealMeta(h);
  const reqs = meta.spend_carryover.map(u => u.request_id);
  assert.ok(!reqs.includes('phantom-req'), 'unwitnessed spend not carried');
  assert.ok(!reqs.includes('neg-req'), 'negative-cost spend not carried');
  assert.ok(!reqs.includes('inflated-req'), 'inflated-cost spend not carried');
  assert.ok(!reqs.includes('mirror-req'), 'even a perfectly honest-looking mirror row is never signed');
  assert.ok(reqs.includes(req.request_id), 'the doomed-verified RUNTIME_ALLOWED event still carries');
  assert.ok(!meta.access_carryover.some(a => a.subject === 'phantom-sub'), 'unwitnessed access not carried');
  assert.ok(!meta.access_carryover.some(a => (a.row_ids ?? []).includes('row-poison')), 'planted access row not carried');
});

// seal F-5: a doomed AUTHORITY_REVOKED is carried into AUDIT_SEALED and
// folds back into live revocation state — the seal can never un-revoke.
test('w32 seal F5: a revocation inside the doomed span survives the seal', t => {
  const h = fixture(t, ['acme']);
  h.f.revoke(h.p('security'), { kind: 'subject', id: 'operator', reason: 'test' });
  // Doom the revocation itself: corrupt the row just before its anchor.
  corruptAt(h, seqOf(h, '%AUTHORITY_REVOKED%') - 1);
  assert.equal(h.f.sealAuditChain(h.p('security')).sealed, true);
  assert.equal(h.f.revoked('acme', 'subject', 'operator'), true, 'carried revocation stays live after the seal');
  assert.ok(sealMeta(h).revocations_carryover.some(r => r.reference === 'subject:operator'), 'seal names the carried revocation');
  assert.ok(h.f.store.db.prepare("SELECT COUNT(*) n FROM records WHERE tenant='acme' AND kind='revocation' AND id='subject:operator'").get().n === 1, 'the floor row is kept');
});

// seal F-5 caller side: a revoked sealer cannot erase its own revocation.
test('w32 seal F5: a subject revoked inside the doomed span cannot run the seal', t => {
  const h = fixture(t, ['acme']);
  h.f.revoke(h.p('security'), { kind: 'subject', id: 'security', reason: 'doomed revoke' });
  corruptAt(h, seqOf(h, '%AUTHORITY_REVOKED%') - 1);
  assert.throws(() => h.f.sealAuditChain(h.p('security')), hasCode('INV-403-QUARANTINE'));
});

// seal F-6: the cut path must re-prove the anchored integrity set before it
// may report the wedge cleared — a still-divergent anchored row keeps it.
test('w32 seal F6: a seal over still-divergent rows does not claim wedge_cleared', t => {
  const h = fixture(t, ['acme']);
  const { record, certificate } = h.ready();
  // Anchor more events AFTER the issuance so the cert's own anchor survives
  // the cut — then murder its records row.
  h.proposed('finance.beneficiary.create', { vendor_id: 'v-s', bank_account: 'TESTBANK000091', currency: 'EUR' });
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='certificate' AND id=?").run(certificate.payload.certificate_id);
  corruptTail(h);
  const res = h.f.sealAuditChain(h.p('security'));
  assert.equal(res.sealed, true);
  assert.equal(res.wedge_cleared, false, 'a still-divergent anchored row keeps the wedge honestly');
  assert.ok(typeof res.integrity_detail === 'string', 'the surviving divergence is named');
});

// store F-2/F-3 + w38 runtime-gate F-2: watermark entries are signed — an
// unsigned entry planted above the committed tip is clamped to the head
// (a forged floor can no longer wedge the fold) and named as tamper; a
// genuinely SIGNED watermark stranded above the tip still wedges and the
// seal's no-cut branch repairs it.
test('w32 store F2/F3: an unsigned inflated watermark clamps instead of wedging', t => {
  const h = fixture(t, ['acme']);
  h.proposed();
  const tip = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get().seq;
  const wpath = join(h.directory, 'head-watermark.json');
  const file = JSON.parse(readFileSync(wpath, 'utf8'));
  file.tenants.acme = tip + 50;
  writeFileSync(wpath, JSON.stringify(file));
  assert.doesNotThrow(() => h.f._auditIndex('acme'), 'a forged unsigned floor cannot pin above the committed head');
  const res = h.f.sealAuditChain(h.p('security'));
  assert.equal(res.sealed, false, 'chain verifies — no cut needed');
  assert.ok((res.head_watermark_tampered ?? []).some(e => e.tenant_id === 'acme' && e.kind === 'unsigned_above_head'), 'the planted floor must be named in the seal report');
});

test('w32 store F2/F3: a signed watermark stranded above the committed tip still wedges and is repaired', t => {
  const h = fixture(t, ['acme']);
  h.proposed();
  // Advance the chain so the signed watermark bumps to the new tip, then
  // roll back rows + chain-heads together — the signed floor now sits
  // legitimately above the committed tip (the crash-gap shape).
  const headsPath = join(h.directory, 'chain-heads.json');
  const staleHeads = readFileSync(headsPath, 'utf8');
  const staleSeq = JSON.parse(staleHeads).tenants.acme.payload.seq;
  h.proposed(); h.f._auditIndex('acme');
  const entry = JSON.parse(readFileSync(join(h.directory, 'head-watermark.json'), 'utf8')).tenants.acme;
  assert.equal(typeof entry, 'object', 'watermark entries are signed envelopes');
  assert.ok(entry.seq > staleSeq);
  dropAuditTriggers(h.f.store.db);
  h.f.store.db.prepare("DELETE FROM audit WHERE tenant='acme' AND seq>?").run(staleSeq);
  restoreAuditTriggers(h.f.store.db);
  writeFileSync(headsPath, staleHeads);
  // Cold fabric: no in-memory consumed index — the signed watermark is
  // the only catch between this and a clean verify (w27 F-2 shape).
  h.close();
  const cold = new Fabric(clone(h.setup.config), h.directory, () => h.now());
  t.after(() => cold.close());
  assert.throws(() => cold._auditIndex('acme'), hasCode('INV-409-INTEGRITY'), 'a signed floor above the committed tip must still wedge');
  const res = cold.sealAuditChain(h.p('security'));
  assert.equal(res.sealed, false, 'chain verifies — no cut needed');
  assert.equal(cold._headWatermark('acme'), staleSeq, 'watermark re-anchored at the verified tip');
  assert.doesNotThrow(() => cold._auditIndex('acme'), 'fold works again post-repair');
});

// fixverify F-2: a baseline that once anchored but verifies no more must
// never be silently re-minted under the tampered config — drift, no baseline.
test('w32 fixverify F2: a sealed-away config baseline drifts and never re-mints', t => {
  const h = fixture(t, ['acme']);
  h.proposed();
  // Corrupt the anchored CONFIG_SNAPSHOT row, then seal — the span cut
  // destroys the baseline. A fresh open must drift-flag, not re-baseline.
  corruptAt(h, seqOf(h, '%CONFIG_SNAPSHOT%'));
  assert.equal(h.f.sealAuditChain(h.p('security')).sealed, true);
  h.close();
  const f2 = new Fabric(h.setup.config, h.directory, () => h.now());
  t.after(() => f2.close());
  assert.equal(f2.configDriftStatus(h.p('security')).drifted, true, 'a lost baseline is drift, not a free re-baseline');
  assert.equal(f2.store.db.prepare("SELECT COUNT(*) n FROM audit WHERE tenant='acme' AND envelope LIKE '%CONFIG_SNAPSHOT%'").get().n, 0, 'no auto-baseline is minted over a sealed-away baseline');
});

// fixverify F-3: a capsule shredded by retentionSweep (corrupt row) must
// tombstone — anchored-but-missing then reads as an honest 404, never 409.
test('w32 fixverify F3: a retention-shredded capsule resolves 404 not 409', t => {
  const h = fixture(t, ['acme']);
  const record = h.proposed('finance.beneficiary.create', { vendor_id: 'v-t', bank_account: 'TESTBANK000093', currency: 'EUR' });
  const id = record.capsule.capsule_id;
  // Corrupt the row's ciphertext so the sweep shreds it legitimately.
  h.f.store.db.prepare("UPDATE records SET value=? WHERE tenant='acme' AND kind='capsule' AND id=?").run('AA==', id);
  const sweep = h.f.retentionSweep(h.p('security'));
  assert.ok(sweep.corrupt >= 1, 'corrupt capsule shredded');
  assert.throws(() => h.f.certificate(h.p(), id), hasCode('INV-404-NOT-FOUND'), 'tombstoned capsule is an honest miss');
});

// fixverify F-5: subject dedupe must bind non-string ids too — a numeric and
// a string id naming the same subject is the same collision.
test('w32 fixverify F5: numeric subject_id still collides with its string twin', t => {
  const h = fixture(t, ['acme']);
  h.close();
  const cfg = JSON.parse(JSON.stringify(h.setup.config));
  const proto = Object.values(cfg.tenants.acme.identities)[0];
  cfg.tenants.acme.identities['i-numeric'] = { ...proto, subject_id: 42, device_id: 'dev-42' };
  cfg.tenants.acme.identities['i-string'] = { ...proto, subject_id: '42', device_id: 'dev-42b' };
  assert.throws(() => new Fabric(cfg, h.directory, () => h.now()), hasCode('INV-503-CONFIG'));
});

// store F4: wiping fabric.db while target.db survives is the same silent
// re-genesis — the per-tenant residue probe covers target tables too.
test('w32 store F4: surviving target.db rows trip the per-tenant wipe gate', t => {
  const h = fixture(t, ['acme', 'globex']);
  h.proposed('finance.beneficiary.create', { vendor_id: 'v-g', bank_account: 'TESTBANK000095', currency: 'EUR' }, {}, h.p('operator', 'globex'));
  h.proposed('finance.beneficiary.create', { vendor_id: 'v-a', bank_account: 'TESTBANK000097', currency: 'EUR' }, {}, h.p('operator', 'acme'));
  h.close();
  const db = new DatabaseSync(join(h.directory, 'fabric.db'));
  for (const tr of db.prepare("SELECT name FROM sqlite_master WHERE type='trigger'").all()) db.exec(`DROP TRIGGER "${String(tr.name).replace(/"/g, '""')}"`);
  for (const table of ['audit', 'records', 'nonces', 'idempotency', 'deks', 'usage', 'data_access'])
    db.prepare(`DELETE FROM ${table} WHERE tenant=?`).run('globex');
  db.close();
  for (const file of ['chain-heads.json', 'head-watermark.json']) {
    const p = join(h.directory, file);
    try { const j = JSON.parse(readFileSync(p, 'utf8')); if (j.tenants) delete j.tenants.globex; writeFileSync(p, JSON.stringify(j)); } catch { /* absent */ }
  }
  assert.throws(() => new Fabric(h.setup.config, h.directory, h.now), hasCode('INV-503-STORAGE'));
});

// composite F-1: a capsule cancelled on the chain must never mint authority
// again — a restored row image cannot launder the cancellation.
test('w32 composite F1: a cancelled capsule cannot be re-certified from a restored row', t => {
  const h = fixture(t, ['acme']);
  const r = h.proposed('finance.beneficiary.create', { vendor_id: 'v-c', bank_account: 'TESTBANK000099', currency: 'EUR' });
  const id = r.capsule.capsule_id;
  h.evidence(r); h.approve(r, 2);
  h.f.cancel(h.p(), id);
  // The file-writer restores the pre-cancel row — the chain verdict binds.
  const img = h.f.store.get('acme', 'capsule', id);
  img.status = 'CANONICALISED'; img.certificate_id = null;
  h.f.store.put('acme', 'capsule', id, img, h.now());
  assert.throws(() => h.f.certificate(h.p(), id), hasCode('INV-409-STATE'));
});

const jitChild = h => { const r = h.proposed('identity.jit.grant', { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-1'], ttl_ms: 60000, reason: 'Incident', roles: [] }, { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'JIT' } }); h.evidence(r, { kind: 'identity_proof', issuer: 'hris' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const beneChild = (h, n) => { const r = h.proposed('finance.beneficiary.create', { vendor_id: `vendor-${n}`, bank_account: `TESTBANK000${n}`, currency: 'EUR' }); h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const composite = (h, children) => { const r = h.proposed('action.composite', { children }, { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'Batch' } }); h.approve(r, 2); return r; };
// Journal commits but the EXECUTION_DISPATCHED anchor dies — the crash gap.
const killDispatchAnchor = h => {
  const orig = h.f.store.audit.bind(h.f.store);
  h.f.store.audit = (t, type, ...a) => type === 'EXECUTION_DISPATCHED' ? (() => { throw new Error('anchor write lost'); })() : orig(t, type, ...a);
  return orig;
};

// composite F-2: 'reserved + no anchor + no journal' cannot prove the
// mutation never ran — the release also requires the target to still show
// the pre-state. A deleted journal over a committed bump stays wedged.
test('w32 composite F2: a wedged child whose journal was deleted over a committed mutation is never released', t => {
  const h = fixture(t, ['acme']);
  const c1 = jitChild(h), c2 = beneChild(h, 32);
  const parent = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const parentCert = h.f.certificate(h.p(), parent.capsule.capsule_id);
  const orig = killDispatchAnchor(h);
  try { h.f.execute(h.p(), parentCert); } catch { /* the aborted anchor propagates */ }
  h.f.store.audit = orig;
  const wcertId = h.f._auditIndex('acme').issuedCert.get(c1.record.capsule.capsule_id);
  assert.ok(h.f.target.outcome('acme', wcertId), 'the child journal committed — the mutation is durable');
  // Now the file-writer deletes the journal — 'never ran' must still fail.
  h.f.target.db.prepare('DELETE FROM transactions WHERE tenant=? AND id=?').run('acme', wcertId);
  const out = h.f.reconcile(h.p('security'), parentCert.payload.certificate_id);
  assert.equal(out.payload.status, 'UNCERTAIN', 'the child stays wedged — no signed release over a committed mutation');
  assert.equal(out.payload.child_outcomes[c1.record.capsule.capsule_id], 'WEDGED');
  assert.ok(!h.f._auditIndex('acme').released?.has(wcertId), 'no EXECUTION_RELEASED was minted');
});

// composite F-2 control: a child genuinely never dispatched (nothing
// committed, state untouched) still releases honestly.
test('w32 composite F2: a never-dispatched wedged child still releases', t => {
  const h = fixture(t, ['acme']);
  const c1 = jitChild(h), c2 = beneChild(h, 33);
  const parent = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const parentCert = h.f.certificate(h.p(), parent.capsule.capsule_id);
  const orig = h.f.target.execute.bind(h.f.target);
  let calls = 0;
  h.f.target.execute = (capsule, id, now, fault) => { calls++; if (calls === 2) throw new Error('lost before journal'); return orig(capsule, id, now, fault); };
  const out = h.f.execute(h.p(), parentCert);
  const c2cert = h.f._auditIndex('acme').issuedCert.get(c2.record.capsule.capsule_id);
  assert.equal(out.payload.child_outcomes[c2.record.capsule.capsule_id], 'RELEASED', 'untouched wedged child releases honestly');
  assert.ok(h.f._auditIndex('acme').released?.has(c2cert));
});

// composite F-3: a child-side integrity verdict is tamper evidence, never a
// bail reason — it propagates instead of writing a COMPENSATED launder.
test('w32 composite F3: a child integrity failure propagates past the bail', t => {
  const h = fixture(t, ['acme']);
  const c1 = jitChild(h), c2 = beneChild(h, 34);
  const parent = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const parentCert = h.f.certificate(h.p(), parent.capsule.capsule_id);
  // Graft c2's stored capsule — integrity must propagate, not launder.
  const row = h.f.store.get('acme', 'capsule', c2.record.capsule.capsule_id);
  row.capsule.current_state = { ...row.capsule.current_state, version: 99 };
  h.f.store.put('acme', 'capsule', c2.record.capsule.capsule_id, row, h.now());
  assert.throws(() => h.f.execute(h.p(), parentCert), hasCode('INV-409-INTEGRITY'));
  assert.equal(h.f.store.get('acme', 'outcome', parentCert.payload.certificate_id), null, 'no attested parent verdict was written over tamper');
});

// composite F-4: child verdicts fold from the parent's signed outcome — a
// deleted child outcome row can never make the ledger forget the spend.
test('w32 composite F4: child outcomes fold from the anchored parent event', t => {
  const h = fixture(t, ['acme']);
  const c1 = jitChild(h), c2 = beneChild(h, 35);
  const parent = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const parentCert = h.f.certificate(h.p(), parent.capsule.capsule_id);
  const out = h.f.execute(h.p(), parentCert);
  assert.equal(out.payload.status, 'VERIFIED');
  const c1Cert = h.f._auditIndex('acme').issuedCert.get(c1.record.capsule.capsule_id);
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='outcome' AND id=?").run(c1Cert);
  assert.equal(h.f._auditIndex('acme').outcomes.get(c1Cert), 'VERIFIED', 'the murdered row cannot un-settle the child');
  assert.throws(() => h.f.execute(h.p(), c1.certificate), hasCode('INV-409-REPLAY'));
});

// composite F-5 (INFO, resolved by semantics): an anchored UNCERTAIN parent
// verdict releases its children — binding under UNCERTAIN would deadlock the
// parent forever (children must execute for the parent to settle). A planted
// or murdered outcome row still cannot unbind: the fold only admits anchored
// EXECUTION_OUTCOME events.
test('w32 composite F5: an anchored UNCERTAIN verdict lets never-reserved children execute standalone', t => {
  const h = fixture(t, ['acme']);
  const c1 = jitChild(h), c2 = beneChild(h, 36);
  const parent = composite(h, [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id]);
  const parentCert = h.f.certificate(h.p(), parent.capsule.capsule_id);
  const orig = killDispatchAnchor(h);
  try { h.f.execute(h.p(), parentCert); } catch { /* wedge */ }
  h.f.store.audit = orig;
  const out = h.f.reconcile(h.p('security'), parentCert.payload.certificate_id);
  assert.equal(out.payload.status, 'UNCERTAIN');
  // The never-reserved child keeps live authority and executes standalone —
  // its settle then supersedes the parent's verdict on the next reconcile.
  assert.equal(h.f.execute(h.p(), c2.certificate).payload.status, 'VERIFIED');
});

// store F5: remove/shred run their dek+record delete pair atomically — a
// rolled-back pair leaves both rows, never a dekless record.
test('w32 store F5: remove/shred pair rolls back together', t => {
  const h = fixture(t, ['acme']);
  h.f.store.insert('acme', 'note', 'n1', { x: 1 }, h.now());
  try {
    h.f.store.tx(() => { h.f.store.shred('acme', 'note', 'n1'); throw new Error('abort mid-shred'); });
  } catch { /* rolled back */ }
  const dek = h.f.store.db.prepare("SELECT COUNT(*) n FROM deks WHERE tenant='acme' AND kind='note' AND id='n1'").get().n;
  const rec = h.f.store.db.prepare("SELECT COUNT(*) n FROM records WHERE tenant='acme' AND kind='note' AND id='n1'").get().n;
  assert.ok(dek === 0 && rec === 0 || dek === 1 && rec === 1, 'the pair is atomic — no dekless residue');
  // Standalone shred still destroys both.
  h.f.store.shred('acme', 'note', 'n1');
  assert.equal(h.f.store.db.prepare("SELECT COUNT(*) n FROM records WHERE tenant='acme' AND kind='note' AND id='n1'").get().n, 0);
});

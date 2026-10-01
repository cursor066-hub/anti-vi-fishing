// w29-lifecycle: the anchored lifecycle is the authority — a store-level
// writer can never launder, unbind, orphan or silently swallow it via
// mutable rows. Fifth-pass regression tests for the attacks the w29
// hostile audit demonstrated.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, rmSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fixture, hasCode } from './helpers.mjs';
import { clone } from '../src/canonical.mjs';
import { generateKey } from '../src/crypto.mjs';
import { Fabric } from '../src/fabric.mjs';

// W29-F1: a planted capsule.certificate_id pointer must never land an
// anchored CANCELLED verdict on the foreign live certificate — the
// ACTION_CANCELLED event binds only the anchored issuance.
test('W29-F1: planted certificate_id cannot cancel a foreign anchored cert', t => {
  const h = fixture(t);
  const victim = h.ready();
  const victimCertId = victim.certificate.payload.certificate_id;
  const victimCapsuleId = victim.record.capsule.capsule_id;
  const atk = h.proposed();
  const atkId = atk.capsule.capsule_id;

  // store-writer primitive: plant the victim's cert id on the attacker's row
  const rec = h.f.store.must('acme', 'capsule', atkId);
  rec.certificate_id = victimCertId;
  h.f.store.put('acme', 'capsule', atkId, rec, h.now());

  h.f.cancel(h.p(), atkId);

  // the foreign certificate was never anchored as cancelled
  assert.equal(h.f._auditIndex('acme').outcomes.get(victimCertId), undefined);
  assert.ok(h.f._auditIndex('acme').cancelled.has(atkId));
  // …and it still spends as the live authority it is
  const out = h.f.execute(h.p(), victim.certificate);
  assert.equal(out.payload.status, 'VERIFIED');
  assert.equal(h.f._auditIndex('acme').outcomes.get(victimCertId), 'VERIFIED');
  assert.equal(h.f.store.must('acme', 'certificate', victimCertId).status, 'VERIFIED');
});

// W29-F2: terminality is anchored, not row-derived — deleting the outcome
// row is integrity evidence, never a chance to re-fire finish and demote
// an anchored VERIFIED into FAILED.
test('W29-F2: deleting the outcome row screams integrity, never rewrites anchored VERIFIED', t => {
  const h = fixture(t);
  const next = clone(h.f.policy('acme')); next.version += 1; next.allow_weakening = true;
  const r = h.proposed('policy.change', { policy: next },
    { action: { type: 'policy.change', target_resource: 'policy-root', purpose: 'Amend constitution' } });
  h.f.simulate(h.p('policy-admin'), next); h.advance(120001);
  h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'audit-committee' });
  h.approve(r, 4);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  const certId = cert.payload.certificate_id;

  const out = h.f.execute(h.p(), cert);
  assert.equal(out.payload.status, 'VERIFIED');
  assert.equal(h.f.policy('acme').version, next.version);

  const outcomes = () => h.f.store.db.prepare(
    "SELECT COUNT(*) c FROM audit WHERE tenant='acme' AND json_extract(envelope,'$.payload.type')='EXECUTION_OUTCOME' AND json_extract(envelope,'$.payload.reference')=?").get(certId).c;
  assert.equal(outcomes(), 1);

  // store-writer deletes the mutable outcome row
  h.f.store.shred('acme', 'outcome', certId);

  // reconcile must scream integrity — the anchored verdict is terminal
  assert.throws(() => h.f.reconcile(h.p('security'), certId), hasCode('INV-409-INTEGRITY'));
  assert.equal(h.f._auditIndex('acme').outcomes.get(certId), 'VERIFIED', 'anchored verdict never demoted');
  assert.equal(outcomes(), 1, 'no second EXECUTION_OUTCOME anchor may land');
});

// W29-F3: a grafted donor envelope on the parent cert row is tamper
// evidence — the child must never silently unbind into a solo spend.
test('W29-F3: parent-cert envelope graft screams integrity, never unbinds a live child', t => {
  const h = fixture(t);
  const dead = h.proposed('finance.beneficiary.create',
    { vendor_id: 'vd', bank_account: 'TESTBANK000009', currency: 'EUR' }, { expires_at: h.now() + 4000 });
  h.evidence(dead); h.evidence(dead, { issuer: 'registry' }); h.approve(dead, 2);
  const deadCert = h.f.certificate(h.p(), dead.capsule.capsule_id);

  const kid = n => {
    const r = h.proposed('finance.beneficiary.create', { vendor_id: `v${n}`, bank_account: `TESTBANK00001${n}`, currency: 'EUR' });
    h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2);
    return { r, cert: h.f.certificate(h.p(), r.capsule.capsule_id) };
  };
  const c1 = kid(1), c2 = kid(2);
  const comp = h.proposed('action.composite',
    { children: [c1.r.capsule.capsule_id, c2.r.capsule.capsule_id] },
    { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'Batch' } });
  h.approve(comp, 2);
  const parentCert = h.f.certificate(h.p(), comp.capsule.capsule_id);
  const parentCertId = parentCert.payload.certificate_id;
  h.advance(5000);

  assert.throws(() => h.f.execute(h.p(), c1.cert), hasCode('INV-409-STATE'));

  // graft: parent cert row now carries the expired donor envelope
  const pRow = h.f.store.must('acme', 'certificate', parentCertId);
  pRow.envelope = h.f.store.must('acme', 'certificate', deadCert.payload.certificate_id).envelope;
  h.f.store.put('acme', 'certificate', parentCertId, pRow, h.now());

  // the graft must scream — the child can never unbind solo
  assert.throws(() => h.f.execute(h.p(), c1.cert), hasCode('INV-409-INTEGRITY'));
  assert.equal(h.f._auditIndex('acme').outcomes.has(c1.cert.payload.certificate_id), false);
  assert.throws(() => h.f.execute(h.p(), parentCert), hasCode('INV-401-CERTIFICATE'));
});

// W29-F4: anchored issuance is admission — a seal-orphaned certificate
// refuses before reservation, dispatch or any real target mutation.
test('W29-F4: a seal-orphaned certificate refuses before reservation or dispatch', t => {
  const h = fixture(t);
  const { record, certificate } = h.ready();
  const certId = certificate.payload.certificate_id;

  // simulate file-level corruption of the CERTIFICATE_ISSUED audit row
  const row = h.f.store.db.prepare(
    "SELECT seq FROM audit WHERE tenant='acme' AND json_extract(envelope,'$.payload.type')='CERTIFICATE_ISSUED'").get();
  h.f.store.db.exec('DROP TRIGGER no_audit_update');
  h.f.store.db.prepare('UPDATE audit SET envelope=? WHERE tenant=? AND seq=?')
    .run('{"protected":{},"payload":{},"signature":"x"}', 'acme', row.seq);
  h.f.store.db.exec("CREATE TRIGGER no_audit_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;");

  const seal = h.f.sealAuditChain(h.p('security'));
  assert.equal(seal.sealed, true);
  assert.equal(h.f._auditIndex('acme').issued.has(record.capsule.capsule_id), false);

  // refused at admission — nothing may commit
  assert.throws(() => h.f.execute(h.p(), certificate), hasCode('INV-401-CERTIFICATE'));
  assert.equal(h.f._auditIndex('acme').reserved.has(certId), false, 'no reservation anchor');
  assert.equal(h.f._auditIndex('acme').dispatched.has(certId), false, 'no dispatch anchor');
  assert.equal(h.f.target.outcome('acme', certId), null, 'no real target mutation without anchored issuance');
  assert.throws(() => h.f.reconcile(h.p('security'), certId), hasCode('INV-409-STATE'));
});

// W29-F5: an anchored-certified child whose capsule row was deleted is
// destructive tampering — parent reconcile screams, never swallows it.
test('W29-F5: deleted anchored child capsule row screams integrity on parent reconcile', t => {
  const h = fixture(t);
  const kid = n => {
    const r = h.proposed('finance.beneficiary.create', { vendor_id: `w${n}`, bank_account: `TESTBANK00002${n}`, currency: 'EUR' });
    h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2);
    return { r, cert: h.f.certificate(h.p(), r.capsule.capsule_id) };
  };
  const c1 = kid(1), c2 = kid(2);
  const comp = h.proposed('action.composite',
    { children: [c1.r.capsule.capsule_id, c2.r.capsule.capsule_id] },
    { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'Batch' } });
  h.approve(comp, 2);
  const parentCert = h.f.certificate(h.p(), comp.capsule.capsule_id);
  const parentCertId = parentCert.payload.certificate_id;

  assert.throws(() => h.f.execute(h.p(), parentCert, { fault: 'process-crash' }), /process death/i);
  assert.ok(h.f._auditIndex('acme').reserved.has(parentCertId));

  h.f.store.shred('acme', 'capsule', c1.r.capsule.capsule_id);
  assert.equal(h.f._auditIndex('acme').issued.has(c1.r.capsule.capsule_id), true);

  // parent reconcile screams instead of classifying the child NOT_ATTEMPTED
  assert.throws(() => h.f.reconcile(h.p('security'), parentCertId), hasCode('INV-409-INTEGRITY'));

  // and every downstream path on the murdered row screams too
  const code = fn => { try { fn(); return null; } catch (e) { return e.code; } };
  assert.equal(code(() => h.f.execute(h.p(), c1.cert)), 'INV-409-INTEGRITY');
  assert.equal(code(() => h.f.cancel(h.p(), c1.r.capsule.capsule_id)), 'INV-409-INTEGRITY');
});

// W29-DATAGATE: egress is irrevocable — a standalone data.export whose
// EXECUTION_DISPATCHED anchor died in the commit gap still egressed rows,
// so the wedge must charge usage, attest DATA_ACCESSED and watermark —
// never leave the disclosure invisible to the coverage ledger.
test('W29-DATAGATE: wedged standalone export is charged, attested and watermarked', t => {
  const h = fixture(t);
  const r = h.proposed('data.export',
    { dataset: 'dataset-1', columns: ['id', 'name'], row_ids: ['row-1'], max_rows: 1, classification: 'internal', jurisdiction: 'EU' },
    { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Operations' }, destination: 'customer-vault' });
  h.evidence(r, { kind: 'dataset_authority' }); h.approve(r, 1);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  const certId = cert.payload.certificate_id;

  // Reserve then die before dispatch — the durable journal commits while
  // the EXECUTION_DISPATCHED anchor never lands (the real crash gap).
  assert.throws(() => h.f.execute(h.p(), cert, { fault: 'process-crash' }), /process death/i);
  h.f.target.execute(r.capsule, certId, h.now());
  assert.ok(h.f.target.outcome('acme', certId), 'rows durably egressed');

  const out = h.f.reconcile(h.p('security'), certId);
  assert.equal(out.payload.status, 'FAILED');
  assert.equal(out.payload.reason, 'DISPATCH_UNATTESTED');

  // …but the egress is honest on the ledger: charged, attested, watermarked
  const access = h.f._auditIndex('acme').dataAccess.filter(a => a.certificate_id === certId);
  assert.equal(access.length, 1, 'exactly one DATA_ACCESSED attestation');
  assert.deepEqual(access[0].row_ids, ['row-1']);
  const charge = h.f.store.db.prepare("SELECT * FROM usage WHERE tenant='acme' AND capability=? AND request=?").get(`cert:${certId}`, certId);
  assert.ok(charge, 'usage billing mirror exists');
  assert.ok(out.payload.watermarks?.length >= 1, 'watermarks recorded on the outcome');

  // coverage accounting now sees the disclosed rows — a same-subject
  // export of the same rows hits the reconstruction window, not a clean slate
  const recon = h.f._auditIndex('acme').dataAccess.length;
  assert.ok(recon >= 1);
});

// W29-F12: pending chain-head notes ride the tx boundary — a savepoint
// that rolls back must restore the note map, never clobber the outer
// committed append's head into permanent watermark starvation.
test('W29-F12: a rolled-back savepoint append never starves the committed head', t => {
  const h = fixture(t);
  h.ready();
  const headsPath = join(h.directory, 'chain-heads.json');
  const headSeq = () => JSON.parse(readFileSync(headsPath, 'utf8')).tenants.acme?.payload?.seq ?? null;
  const tipSeq = () => h.f.store.db.prepare("SELECT COALESCE(MAX(seq),0) m FROM audit WHERE tenant='acme'").get().m;

  h.f.store.tx(() => {
    h.f.store.audit('acme', 'AUDIT_ACCESSED', 'operator', 'acme', { probe: 'outer' }, h.now());
    try { h.f.store.tx(() => { h.f.store.audit('acme', 'AUDIT_ACCESSED', 'operator', 'acme', { probe: 'rolled' }, h.now()); throw new Error('rb'); }); } catch {}
  });
  assert.equal(headSeq(), tipSeq(), 'the committed append still lands its head');

  // starvation pattern: every tx carries a trailing rolled-back append —
  // the head must keep advancing on the committed rows alone
  for (let i = 0; i < 3; i++) h.f.store.tx(() => {
    h.f.store.audit('acme', 'AUDIT_ACCESSED', 'operator', 'acme', { probe: `c${i}` }, h.now());
    try { h.f.store.tx(() => { h.f.store.audit('acme', 'AUDIT_ACCESSED', 'operator', 'acme', { probe: `r${i}` }, h.now()); throw new Error('rb'); }); } catch {}
  });
  assert.equal(headSeq(), tipSeq(), 'head never starves behind the committed tip');
});

// W29-F9a: the target store must READ user_version before re-stamping it —
// a foreign sqlite file with a newer schema marker is refused, never
// silently adopted (w29-fixverify F9).
test('W29-F9a: the target db read-checks user_version — foreign db refused', t => {
  const h = fixture(t);
  h.ready();
  const cfg = h.clone(h.setup.config), dir = h.directory;
  h.close();
  rmSync(join(dir, 'target.db'), { force: true });
  const alien = new DatabaseSync(join(dir, 'target.db'));
  alien.exec('CREATE TABLE alien (x); PRAGMA user_version=9;');
  alien.close();
  assert.throws(() => new Fabric(cfg, dir, () => h.now()), hasCode('INV-503-STORAGE'));
});

// W29-F9b: reopening over a read-only database file surfaces the honest
// storage code — never a raw ERR_SQLITE_ERROR (w29-fixverify F9).
test('W29-F9b: a read-only target db reports INV-503-STORAGE', t => {
  const h = fixture(t);
  const cfg = h.clone(h.setup.config), dir = h.directory;
  h.close();
  chmodSync(join(dir, 'target.db'), 0o444);
  try { assert.throws(() => new Fabric(cfg, dir, () => h.now()), hasCode('INV-503-STORAGE')); }
  finally { chmodSync(join(dir, 'target.db'), 0o600); }
});

// W29-F10: a fold that already perceived the head file 'corrupt' must not
// wedge the healing flush — a head buffered behind a stalled flush re-lands
// on the next non-signing commit even after an outside-tx fold cached the
// 'corrupt' verdict (w29-fixverify F10).
test('W29-F10: a cached corrupt-head verdict cannot wedge the healing flush', t => {
  const h = fixture(t);
  h.ready();
  const headsPath = join(h.directory, 'chain-heads.json');
  const tipSeq = () => h.f.store.db.prepare("SELECT COALESCE(MAX(seq),0) m FROM audit WHERE tenant='acme'").get().m;

  // Buffer a head behind a one-shot stalled flush — the append commits,
  // the signed head stays pending for the next transaction.
  const origLock = h.f._headFileLock;
  h.f._headFileLock = () => { throw new Error('lock-stall'); };
  try { h.f.store.audit('acme', 'AUDIT_ACCESSED', 'operator', 'acme', { probe: 'pending' }, h.now()); }
  finally { h.f._headFileLock = origLock; }
  const seq = tipSeq();
  assert.ok(seq > 0);

  // The attacker swaps in a corrupt head file — the fold wedges loudly and
  // caches the 'corrupt' verdict.
  const forged = { protected: { profile: 'IF-CJSON-1', suite: 'Ed25519', key_id: 'x', purpose: 'audit' },
    payload: { tenant_id: 'acme', seq, hash: 'z'.repeat(64) }, signature: 'A'.repeat(86) };
  writeFileSync(headsPath, JSON.stringify({ format: 'IF-CHAINHEAD-1', tenants: { acme: forged } }));
  assert.throws(() => h.f._auditIndex('acme'), hasCode('INV-409-INTEGRITY'));

  // A commit that signs no audit row still runs the post-commit flush —
  // the head signature resolves under the seal scope and the file heals.
  h.f.store.put('acme', 'note', 'heal', { v: 1 }, h.now());
  const head = JSON.parse(readFileSync(headsPath, 'utf8')).tenants.acme;
  assert.equal(head?.payload?.seq, seq, 'the pending signed head lands at the committed tip');
  assert.ok(head?.signature?.length > 10);
  assert.doesNotThrow(() => h.f._auditIndex('acme'), 'the fold recovers once an authentic head lands');
});

// W29-F11: under an anchor wedge the suite gate must never degrade to
// "any suite" — only the vault-bound audit key's own suite may sign for
// remediation; a foreign suite stays denied (w29-fixverify F11).
test('W29-F11: an anchor wedge degrades to the bound key suite, never to any suite', t => {
  const h = fixture(t);
  h.ready();
  const es = generateKey('ES256');
  h.f.vault.importKey({ key_id: 'es-audit', public_key: es.public_key, private_key: es.private_key }, 'audit', { suite: 'ES256', tenant_id: 'acme' });
  assert.throws(() => h.f.signAudit('acme', { probe: 'healthy' }, 'audit', 'es-audit'), hasCode('INV-451-POLICY'));

  // anchor-divergence wedge: tamper the active policy row off-anchor
  const active = h.f.store.get('acme', 'policy', 'active');
  h.f.store.put('acme', 'policy', 'active', { ...active, tampered_field: 'x' }, h.now());
  assert.throws(() => h.f.policy('acme'), hasCode('INV-409-INTEGRITY'));

  // under the wedge a foreign suite still cannot sign
  assert.throws(() => h.f.signAudit('acme', { probe: 'wedged' }, 'audit', 'es-audit'), hasCode('INV-451-POLICY'));
  // …while remediation signing on the bound suite stays reachable
  const env = h.f.signAudit('acme', { probe: 'remediation' }, 'audit');
  assert.equal(env.protected.suite, 'Ed25519');
});

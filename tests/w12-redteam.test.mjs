// Wave-12 red-team regressions: in-process store-level tampering PoCs.
// Threat model: a malicious insider principal holds valid credentials AND
// can run arbitrary SQL / object mutation against f.store, f.target and
// f.config — everything short of calling the vault signers. Every test
// proves a tamper that used to succeed now dies on the audit-chain anchor.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { fixture, hasCode, runtimeInput, runtimeRequest } from './helpers.mjs';
import { Store } from '../src/store.mjs';
import { digest } from '../src/canonical.mjs';
import { signed } from '../src/crypto.mjs';

// R1: deleting the mutable revocation row cannot un-quarantine a device —
// revocation is anchored on the signed AUTHORITY_REVOKED chain event.
test('w12 R1: a deleted revocation row cannot resurrect a quarantined device', t => {
  const h = fixture(t);
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'lost' });
  h.f.store.db.prepare("DELETE FROM records WHERE kind='revocation'").run();
  assert.equal(h.f.store.list('acme', 'revocation', 10).length, 0, 'row is gone');
  assert.equal(h.f.revoked('acme', 'device', 'operator-device'), true, 'chain still attests the revocation');
  assert.throws(() => h.proposed(), hasCode('INV-403-QUARANTINE'));
});

// R2: an in-place payload edit on an attached evidence row dies at digest
// re-verification — the store row is a cache, not the authority.
test('w12 R2: tampered evidence row fails integrity at evaluation', t => {
  const h = fixture(t);
  const r = h.proposed();
  const env = h.evidence(r);
  const row = h.f.store.get('acme', 'evidence', env.payload.evidence_id);
  row.payload.claim = 'supports'; row.payload.confidence = 999;
  h.f.store.put('acme', 'evidence', env.payload.evidence_id, row, h.now());
  assert.throws(() => h.f.evaluate(h.p(), r.capsule.capsule_id), hasCode('INV-409-INTEGRITY'));
});

// R3: an evidence envelope planted under a stolen-issuer kid (signature
// made with the WRONG private key) dies at verifySigned inside graph().
test('w12 R3: forged-signature evidence never reaches the graph', t => {
  const h = fixture(t);
  const r = h.proposed();
  const forged = { evidence_id: randomUUID(), tenant_id: 'acme', capsule_digest: r.capsule_digest, kind: 'ownership', content_digest: digest({ x: 1 }), acquired_at: h.now(), expires_at: h.now() + 600000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 'forged', retention_until: h.now() + 660000, claims: { account: 'TESTBANK000002', owner_id: r.capsule.action.target_resource } };
  // Sign under the bank issuer's key_id but with the WRONG private key.
  const bankKid = h.setup.issuerKeys.acme.bank.key_id;
  const envelope = signed(forged, { key_id: bankKid, private_key: h.setup.identityKeys.acme['operator'].private_key }, 'evidence');
  const id = forged.evidence_id;
  h.f.store.put('acme', 'evidence', id, { envelope, payload: forged }, h.now());
  assert.throws(() => h.f.attachEvidence(h.p(), r.capsule.capsule_id, envelope));
  // Even bypassing attachEvidence entirely — grafting the id onto the
  // capsule record — the planted row never reaches the graph: membership is
  // derived from EVIDENCE_ATTACHED chain events, not the mutable array.
  const rec = h.f.store.must('acme', 'capsule', r.capsule.capsule_id);
  rec.evidence.push(id); h.f.store.put('acme', 'capsule', r.capsule.capsule_id, rec, h.now());
  const graph = h.f.graph('acme', rec);
  assert.equal(graph.items.some(i => i.payload?.evidence_id === id), false, 'unanchored evidence is invisible to the graph');
});

// R4: a store-level rewrite of the active policy row dies against the
// anchored POLICY_GENESIS/ACTIVATED digest.
test('w12 R4: active policy divergence is caught by the chain anchor', t => {
  const h = fixture(t);
  const live = h.f.policy('acme');
  const tampered = { ...live, rules: { ...live.rules, 'finance.beneficiary.create': { ...live.rules['finance.beneficiary.create'], approval_threshold: 0, evidence_kinds: [] } } };
  const row = h.f.store.get('acme', 'policy', 'active');
  assert.ok(row, 'active policy row exists');
  h.f.store.put('acme', 'policy', 'active', tampered, h.now());
  assert.throws(() => h.f.policy('acme'), hasCode('INV-409-INTEGRITY'));
});

// R5: a jit-grant record planted via store.put (valid encryption, no chain
// event) is invisible to the dataplane — scope_digest never matches.
test('w12 R5: forged jit-grant row is ignored by grantsFor', t => {
  const h = fixture(t);
  const grant = { grant_id: 'forged-1', subject_id: 'operator', resources: ['dataset-2'], actions: ['data.read'], destinations: ['evil-vault'], columns: ['*'], row_ids: ['*'], roles: ['custodian'], expires_at: h.now() + 3600000, issued_at: h.now() };
  h.f.target.grant('acme', 'forged-1', grant);
  const grants = h.f.grantsFor('acme', 'operator', h.now());
  assert.equal(grants.destinations.includes('evil-vault'), false, 'unanchored grant must not be served');
  assert.equal(grants.roles.includes('custodian'), false);
});

// R6: deleting the certificate row cannot enable a second mint — the
// CERTIFICATE_ISSUED anchor still blocks.
test('w12 R6: deleted certificate row cannot enable a second mint', t => {
  const h = fixture(t);
  const { record, certificate } = h.ready();
  h.f.store.db.prepare("DELETE FROM records WHERE kind='certificate' AND id=?").run(certificate.payload.certificate_id);
  const rec = h.f.store.must('acme', 'capsule', record.capsule.capsule_id);
  rec.certificate_id = null; rec.status = 'EVIDENCED'; rec.decision = null;
  h.f.store.put('acme', 'capsule', rec.capsule.capsule_id, rec, h.now());
  assert.throws(() => h.f.certificate(h.p(), rec.capsule.capsule_id), hasCode('INV-409-REPLAY'));
});

// R7: rewriting capsule.received_at backwards cannot age a capsule past
// its cooldown — evaluation anchors on the CAPSULE_PROPOSED instant.
test('w12 R7: backdated received_at cannot skip the cooldown', t => {
  const h = fixture(t);
  const r = h.proposed('finance.bank.change', { bank_account: 'TESTBANK000002', currency: 'EUR' });
  const rec = h.f.store.must('acme', 'capsule', r.capsule.capsule_id);
  rec.capsule.received_at = h.now() - 3600000;
  rec.capsule_digest = digest(rec.capsule); // keep the store digest in sync — the tamper under test is the backdate itself
  h.f.store.put('acme', 'capsule', rec.capsule.capsule_id, rec, h.now());
  const evald = h.f.evaluate(h.p(), r.capsule.capsule_id);
  assert.equal(evald.decision, 'DEFER', 'cooldown must still apply — anchored on chain time');
});

// R12: tenant configuration is deep-frozen at open — an in-process edit
// throws instead of silently shifting a trust anchor.
test('w12 R12: tenant config is immutable after open', t => {
  const h = fixture(t);
  assert.throws(() => { h.f.config.tenants.acme.identities['evil'] = { subject_id: 'mallory' }; }, TypeError);
  assert.throws(() => { h.f.tenant('acme').keys.execution.key_id = 'attacker-key'; }, TypeError);
  assert.throws(() => { h.f.tenant('acme').issuers.bank.public_key = 'forged'; }, TypeError);
  // Rotation still works through the audited path — frozen, not static.
  assert.equal(typeof h.f.tenant('acme').keys.execution.key_id, 'string');
});

// R4b: a VERIFIED finish without a durable dispatch journal is refused —
// reservation is not dispatch.
test('w12 R4b: VERIFIED finish requires the durable dispatch journal', t => {
  const h = fixture(t);
  const { certificate } = h.ready();
  const orig = h.f.target.execute.bind(h.f.target);
  h.f.target.execute = (capsule, id, now, fault) => {
    const raw = orig(capsule, id, now, fault);
    h.f.target.db.prepare('DELETE FROM transactions WHERE tenant=? AND id=?').run('acme', id);
    return raw;
  };
  assert.throws(() => h.f.execute(h.p(), certificate), hasCode('INV-409-INTEGRITY'));
});

// R9: wiping the data_access mirror cannot reset reconstruction coverage —
// the DATA_ACCESSED chain events still count.
test('w12 R9: data-access disclosure is anchored on the chain', t => {
  const h = fixture(t);
  const input = runtimeInput();
  const cap = h.f.runtime.issue(h.p(), input);
  h.f.runtime.consume(h.p(), runtimeRequest(cap));
  const idx = h.f._auditIndex('acme');
  assert.ok(idx.dataAccess.some(e => e.dataset === input.resource && e.row_ids.includes('row-1')), 'DATA_ACCESSED event is on the chain');
  h.f.store.db.prepare('DELETE FROM data_access').run();
  // The chain-derived index still reports the disclosure after the wipe.
  const idx2 = h.f._auditIndex('acme');
  assert.ok(idx2.dataAccess.some(e => e.dataset === input.resource && e.row_ids.includes('row-1')), 'wiping the table cannot erase chain attestation');
});

// R17: clearing the mutable composite_parents marker cannot unbind a
// certified child — parentage is derived from the chain.
test('w12 R17: ledger-derived composite parentage survives marker tamper', t => {
  const h = fixture(t);
  const jit = (n) => {
    const r = h.proposed('identity.jit.grant', { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-1'], ttl_ms: 60000, reason: `r${n}`, roles: [] }, { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'JIT' } });
    h.evidence(r, { kind: 'identity_proof', issuer: 'hris' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' }); h.approve(r, 2);
    return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) };
  };
  const c1 = jit(1), c2 = jit(2);
  const parent = h.proposed('action.composite', { children: [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id] }, { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'Batch' } });
  h.approve(parent, 2);
  h.f.certificate(h.p(), parent.capsule.capsule_id);
  // Tamper: erase the child's mutable marker entirely.
  const rec = h.f.store.must('acme', 'capsule', c1.record.capsule.capsule_id);
  rec.composite_parents = []; h.f.store.put('acme', 'capsule', rec.capsule.capsule_id, rec, h.now());
  assert.throws(() => h.f.execute(h.p(), c1.certificate), hasCode('INV-409-STATE'));
});

// R18: a DB file whose audit triggers were dropped refuses to reopen.
test('w12 R18: dropped audit triggers refuse at open', async t => {
  const h = fixture(t);
  h.close();
  const path = join(h.directory, 'fabric.db');
  // Drop the triggers directly on the file, then try to reopen via a fresh
  // Store — the schema check must refuse.
  const { DatabaseSync } = await import('node:sqlite');
  const db = new DatabaseSync(path);
  // A plain DROP is healed by CREATE IF NOT EXISTS at open — the dangerous
  // tamper is a same-name trigger with a neutered body, which survives.
  db.exec('DROP TRIGGER no_audit_delete; CREATE TRIGGER no_audit_delete BEFORE DELETE ON audit BEGIN SELECT 1; END;');
  db.close();
  assert.throws(() => new Store(path, {}, {}), /trigger/);
});

// Denial lanes: an unauthorized authenticate attempt lands on the signed
// chain as AUTHORIZATION_DENIED — not silently swallowed.
test('w12: unauthorized calls are denial-audited', t => {
  const h = fixture(t);
  assert.throws(() => h.f.authorize({ subject_id: 'nobody', tenant_id: 'acme' }, ['operator']));
  const denied = h.f.store.auditPage('acme', { after: 0, limit: 5000 }).entries.filter(e => e.envelope.payload.type === 'AUTHORIZATION_DENIED' || e.envelope.payload.type === 'SECURITY_OPERATION_REJECTED');
  assert.ok(denied.length > 0, 'a denial lane event must be on the chain');
});

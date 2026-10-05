// w42-runtime: spend-path authority must follow the anchored enrolment and
// the ledger's own attested span — planted store rows can never veto an
// honest attestation, dead-lock a recovery, or be mislabeled as never-
// existed. Regression tests for the w42 hostile audit findings.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture, hasCode, runtimeInput, runtimeRequest } from './helpers.mjs';
import { digest } from '../src/canonical.mjs';

// F1: a squatted usage row carrying the egress billing key and a far-future
// `at` cannot abort the finish transaction — the upsert folds the honest
// charge monotonically and the disclosure still anchors.
test('w42-runtime F1: planted usage squat cannot wedge the export attestation', t => {
  const h = fixture(t);
  const r = h.proposed('data.export',
    { dataset: 'dataset-1', columns: ['id', 'name'], row_ids: ['row-1'], max_rows: 1, classification: 'internal', jurisdiction: 'EU' },
    { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Operations' }, destination: 'customer-vault' });
  h.evidence(r, { kind: 'dataset_authority' }); h.approve(r, 1);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  const certId = cert.payload.certificate_id;
  // Squat the deterministic billing key with a future timestamp — without
  // the monotone merge this trips no_usage_rewind inside the finish tx.
  h.f.store.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?)').run('acme', 'operator', 'dataset-1', h.now() + 86400000, 1, `cert:${certId}`, certId);
  const out = h.f.execute(h.p(), cert);
  assert.equal(out.payload.status, 'VERIFIED');
  assert.ok(h.f._auditIndex('acme').dataAccess.some(a => a.certificate_id === certId), 'DATA_ACCESSED anchored despite the squat');
  const charge = h.f.store.db.prepare('SELECT at, cost FROM usage WHERE tenant=? AND capability=? AND request=?').get('acme', `cert:${certId}`, certId);
  assert.equal(charge.at, h.now() + 86400000, 'monotone merge keeps the planted timestamp rather than wedging');
  assert.ok(charge.cost > 1, 'honest cost folded into the squatted row');
});

// F2: a forged HIGH clock.last may not stretch the resurrection veto across
// every live authority — the veto span is capped at chain-attested time.
test('w42-runtime F2: forged-high clock.last cannot dead-lock recoverClock', t => {
  const h = fixture(t);
  const { certificate } = h.ready();
  assert.equal(h.f.execute(h.p(), certificate).payload.status, 'VERIFIED');
  // Forge a persisted clock years beyond the attested span — every live
  // expiry would fall inside the veto window under the old union.
  h.f.store.db.prepare('UPDATE clock SET last=? WHERE id=1').run(h.now() + 315360000000);
  const rec = h.f.recoverClock(h.p('security'));
  assert.equal(rec.recovered_at, h.now(), 'recovery proceeds — nothing unattested was ever honestly dead');
  // The gate is live again after the bounded recovery.
  h.proposed();
});

// F3: a key-class revocation on the enrolled identity key must kill live
// authority on the spend path exactly like the signing path — the health
// probe consults the folded revocation, not only the stored flag.
test('w42-runtime F3: revoked enrolment key denies the spend path', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  assert.equal(h.f.runtime.consume(h.p(), runtimeRequest(cap)).decision, 'ALLOW');
  const [kid] = Object.entries(h.f.identities('acme')).find(([, v]) => v.subject_id === 'operator' && v.device_id === 'operator-device');
  h.f.revoke(h.p('security'), { kind: 'key', id: kid, reason: 'w42 probe' });
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap)), hasCode('INV-403-HEALTH'));
});

const jitChild = h => { const r = h.proposed('identity.jit.grant', { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-1'], ttl_ms: 60000, reason: 'Incident', roles: [] }, { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'JIT' } }); h.evidence(r, { kind: 'identity_proof', issuer: 'hris' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };
const beneChild = (h, n) => { const r = h.proposed('finance.beneficiary.create', { vendor_id: `vendor-${n}`, bank_account: `TESTBANK00000${n}`, currency: 'EUR' }); h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2); return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) }; };

// F4: an anchored child certificate whose row was murdered is destructive
// tampering — the composite reconcile must scream INTEGRITY, never classify
// the child as never-attempted.
test('w42-runtime F4: murdered anchored child certificate screams on reconcile', t => {
  const h = fixture(t);
  const c1 = jitChild(h), c2 = beneChild(h, 2);
  const r = h.proposed('action.composite', { children: [c1.record.capsule.capsule_id, c2.record.capsule.capsule_id] }, { action: { type: 'action.composite', target_resource: 'composite-ledger', purpose: 'Batch' } });
  h.approve(r, 2);
  const parentCert = h.f.certificate(h.p(), r.capsule.capsule_id);
  // Wedge the parent in the commit gap: reservation anchored, no outcome.
  assert.throws(() => h.f.execute(h.p(), parentCert, { fault: 'process-crash' }), /process death/i);
  // Murder the anchored child certificate row.
  h.f.store.db.prepare("DELETE FROM records WHERE kind='certificate' AND id=?").run(c1.certificate.payload.certificate_id);
  h.f.invalidateAuditIndex('acme');
  assert.throws(() => h.f.reconcile(h.p('security'), parentCert.payload.certificate_id), hasCode('INV-409-INTEGRITY'));
});

// F5: an anchored capability whose row was deleted is integrity evidence —
// consume names the murder (not 'unknown'), and revoke can still anchor the
// revocation over the gap.
test('w42-runtime F5: murdered anchored capability row is tamper evidence', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  const capId = cap.payload.capability_id;
  h.f.store.db.prepare("DELETE FROM records WHERE kind='capability' AND id=?").run(capId);
  h.f.invalidateAuditIndex('acme');
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap)), hasCode('INV-409-INTEGRITY'));
  // The gap stays revocable — the floor anchors the revocation over the
  // murdered row instead of refusing on a bare 404.
  h.f.revoke(h.p('security'), { kind: 'capability', id: capId, reason: 'w42 probe' });
  assert.equal(h.f.revoked('acme', 'capability', capId), true);
});

// L-3: an envelope transplanted in under an anchored capability id must
// diverge from both the stored row and the anchored issuance digest.
test('w42-runtime L-3: transplanted capability envelope is convicted', t => {
  const h = fixture(t);
  const cap1 = h.f.runtime.issue(h.p(), runtimeInput());
  const cap2 = h.f.runtime.issue(h.p(), runtimeInput());
  // Swap the stored envelopes: each row now holds the other's envelope.
  const id1 = cap1.payload.capability_id, id2 = cap2.payload.capability_id;
  h.f.store.put('acme', 'capability', id1, cap2, h.now()); h.f.store.put('acme', 'capability', id2, cap1, h.now());
  // Presenting cap1: its own row now holds cap2's envelope — diverges.
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap1)), hasCode('INV-409-INTEGRITY'));
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap2)), hasCode('INV-409-INTEGRITY'));
});

// L-2: a capability envelope minted without a network snapshot must not
// inherit whatever the live policy now allows — it falls to the restrictive
// built-in defaults.
test('w42-runtime L-2: missing network snapshot falls to restrictive defaults', async t => {
  const h = fixture(t);
  const { installPolicy } = await import('./helpers.mjs');
  installPolicy(h, p => { p.runtime.network.allowed_protocols = [...(p.runtime.network.allowed_protocols ?? ['https']), 'ftp']; p.runtime.network.allowed_ports = [...(p.runtime.network.allowed_ports ?? [443]), 21]; });
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  // A legacy mint: same signed payload shape minus the network section —
  // anchored honestly so the only divergence is the missing snapshot.
  const legacy = { ...cap.payload, capability_id: randomUUID(), runtime_policy: { ...cap.payload.runtime_policy } };
  delete legacy.runtime_policy.network;
  const env = h.f.signExecution('acme', legacy, 'capability');
  h.f.store.tx(() => { h.f.store.insert('acme', 'capability', legacy.capability_id, env, h.now()); h.f.store.audit('acme', 'CAPABILITY_ISSUED', 'operator', legacy.capability_id, { digest: digest(env), resource: legacy.resource, expires_at: legacy.expires_at }, h.now()); });
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(env, { protocol: 'ftp', port: 21 })), hasCode('INV-400-SCHEMA'));
  assert.equal(h.f.runtime.consume(h.p(), runtimeRequest(env)).decision, 'ALLOW');
});

// Sanity: an untouched capability still spends — the integrity bindings
// never wedge an honest path.
test('w42-runtime sanity: honest capability still consumes', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  assert.equal(h.f.runtime.consume(h.p(), runtimeRequest(cap)).decision, 'ALLOW');
});

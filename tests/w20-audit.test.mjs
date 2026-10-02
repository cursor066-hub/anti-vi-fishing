// w20 regression suite — datagate 3rd-pass (F1/F3/F4/F5/F6) + ceremony
// third-pass (W20-1..W20-4 + anchored rotation spend) findings, asserted
// as FAILING attacks: every PoC the auditors demonstrated now refuses.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { fixture, hasCode, setTenant, runtimeInput, runtimeRequest, installPolicy } from './helpers.mjs';
import { signAcknowledgement } from '../src/ceremony.mjs';
import { generateKey } from '../src/crypto.mjs';
import { digest } from '../src/canonical.mjs';

const CUST2 = ['custodian-1', 'custodian-2'];
const flipCeremony = (h, cid, mutate) => { const r = h.f.store.must('acme', 'ceremony', cid); mutate(r); h.f.store.put('acme', 'ceremony', cid, r, h.now()); };
const GENESIS_GRANTS = { resources: ['dataset-1', 'erp-service'], actions: ['data.read', 'service.connect'], destinations: ['customer-vault', 'erp-service'], columns: ['id', 'name', 'region'], row_ids: ['row-1', 'row-2', 'row-3'] };
const addIdentity = (h, subject, keyB, { domain = `${subject}-second-domain`, device = `${subject}-device-b`, health = h.now() + 86400000 } = {}) =>
  setTenant(h, 'acme', tn => {
    tn.identities[keyB.key_id] = {
      public_key: keyB.public_key, subject_id: subject, identity_class: 'workforce',
      roles: ['approver', 'custodian'], device_id: device, failure_domain: domain,
      hardware_backed: false, health_expires_at: health, grants: GENESIS_GRANTS,
    };
  });
const secondIdentityKey = (h, subject) => {
  const first = h.setup.custodianKeys.acme[subject].key_id;
  let keyB = generateKey();
  while (keyB.key_id < first) keyB = generateKey();
  return keyB;
};
const certifyRotate = (h, pending, ceremony_id) => {
  const r = h.proposed('key.rotate', { key_class: 'execution', new_key_id: pending.key_id, new_public_key: pending.public_key, ceremony_id, revoke_old: false }, { action: { type: 'key.rotate', target_resource: 'key-registry', purpose: 'Rotate' } });
  h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'audit-committee' });
  h.approve(r, 3); h.advance(60001);
  return h.f.certificate(h.p(), r.capsule.capsule_id);
};
const certifyExport = h => {
  const r = h.proposed('data.export', { dataset: 'dataset-1', columns: ['id'], row_ids: ['row-1'], max_rows: 1, classification: 'internal', jurisdiction: 'EU' }, { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Operations' }, destination: 'customer-vault' });
  h.evidence(r, { kind: 'dataset_authority' });
  h.approve(r, 1);
  return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) };
};

// ─── datagate F1: catalog boundaries on data.export ─────────────────────────
test('w20-datagate F1: export to an undeclared dataset denies, restricted columns shield', t => {
  const h = fixture(t);
  const denied = h.proposed('data.export', { dataset: 'dataset-9', columns: ['id'], row_ids: ['row-1'], max_rows: 1, classification: 'internal', jurisdiction: 'EU' }, { action: { type: 'data.export', target_resource: 'dataset-9', purpose: 'Operations' }, destination: 'customer-vault' });
  h.evidence(denied, { kind: 'dataset_authority' }); h.approve(denied, 1);
  assert.equal(h.f.evaluate(h.p(), denied.capsule.capsule_id).decision, 'DENY', 'dataset outside the declared catalog denies outright');
  const shielded = h.proposed('data.export', { dataset: 'dataset-1', columns: ['id', 'passport'], row_ids: ['row-1'], max_rows: 1, classification: 'internal', jurisdiction: 'EU' }, { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Operations' }, destination: 'customer-vault' });
  h.evidence(shielded, { kind: 'dataset_authority' }); h.approve(shielded, 1);
  assert.equal(h.f.evaluate(h.p(), shielded.capsule.capsule_id).decision, 'SHIELD', 'a catalog-forbidden column shields to its declared subset');
});

// ─── datagate F3: no watermark key, no export certificate ───────────────────
test('w20-datagate F3: certificate() refuses an export without a watermark key', t => {
  const h = fixture(t);
  const r = h.proposed('data.export', { dataset: 'dataset-1', columns: ['id'], row_ids: ['row-1'], max_rows: 1, classification: 'internal', jurisdiction: 'EU' }, { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Operations' }, destination: 'customer-vault' });
  h.evidence(r, { kind: 'dataset_authority' }); h.approve(r, 1);
  setTenant(h, 'acme', tn => { delete tn.watermark_key; delete tn.watermark_key_wrapped; });
  assert.throws(() => h.f.certificate(h.p(), r.capsule.capsule_id), hasCode('INV-503-CONFIG'),
    'a tenant without a watermark key cannot mint export certificates');
});

// ─── datagate F4: denied egress is still attested ───────────────────────────
test('w20-datagate F4: a denied export disclosure lands DATA_ACCESSED gate_denied', t => {
  const h = fixture(t);
  // Tighten the reconstruction budget so a disclosure that admitted at
  // reservation can still be denied at egress — the denial must be
  // attested (billing/forensics cannot be starved by a denial).
  installPolicy(h, p => { p.runtime.reconstruction = { window_ms: 86400000, max_distinct_rows: 2, max_distinct_columns: 2, max_coverage_percent: 66 }; });
  const { record, certificate } = certifyExport(h);
  // Reserve the certificate, then die before dispatch — the durable
  // reservation survives, as in production's post-reserve crash window.
  assert.throws(() => h.f.execute(h.p(), certificate, { fault: 'process-crash' }), /process death/);
  // Between reservation and finish another disclosure spends the budget —
  // the egress-time check must deny what admission let through.
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ row_ids: ['row-2', 'row-3'] }));
  h.f.runtime.consume(h.p(), runtimeRequest(cap));
  const raw = h.f.target.execute(record.capsule, certificate.payload.certificate_id, h.now());
  // Dispatch is anchored on the signed chain before finish, as execute()
  // does once the durable target journal exists.
  const journal = h.f.target.outcome('acme', certificate.payload.certificate_id);
  h.f.store.tx(() => h.f.store.audit('acme', 'EXECUTION_DISPATCHED', 'operator', certificate.payload.certificate_id, { journal_digest: digest(journal) }, h.now()));
  const out = h.f.finish(h.p(), certificate.payload, raw, 'VERIFIED', 'TARGET_RECONCILED', { postRead: true });
  assert.equal(out.payload.status, 'FAILED');
  assert.equal(out.payload.reason, 'INV-429-BUDGET');
  const row = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND json_extract(envelope,'$.payload.type')='DATA_ACCESSED' ORDER BY seq DESC LIMIT 1").get();
  assert.equal(JSON.parse(row.envelope).payload.metadata.gate_denied, true, 'denied disclosures are attested once — never free, never silent');
});

// ─── datagate F5: tokenise requires its own data key ────────────────────────
test('w20-datagate F5: tokenise transforms refuse without a tokenise key', t => {
  const h = fixture(t);
  setTenant(h, 'acme', tn => { delete tn.tokenise_key; delete tn.tokenise_key_wrapped; });
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ transforms: { name: { op: 'tokenise' } } }));
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap)), hasCode('INV-503-CONFIG'),
    'a tokenise transform under a tenant without a tokenise key fails closed');
});

// ─── datagate F6: DATA_ACCESSED carries the consuming capability ────────────
test('w20-datagate F6: DATA_ACCESSED binds capability_id and request_id', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  const req = runtimeRequest(cap);
  h.f.runtime.consume(h.p(), req);
  const row = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND json_extract(envelope,'$.payload.type')='DATA_ACCESSED' ORDER BY seq DESC LIMIT 1").get();
  const meta = JSON.parse(row.envelope).payload.metadata;
  assert.equal(meta.capability_id, cap.payload.capability_id);
  assert.equal(meta.request_id, req.request_id, 'the attestation names the capability and the request it answered');
});

// ─── W20-1: one custodian can never double-count failure domains ────────────
test('w20-ceremony W20-1: a second live enrollment for one custodian is refused', t => {
  const h = fixture(t);
  const keyB = secondIdentityKey(h, 'custodian-1');
  // The smuggle surface is closed by configuration: two live identities
  // may never share a subject_id, so no sibling key can exist to double a
  // custodian's domain (w31-runtime F-4).
  assert.throws(() => addIdentity(h, 'custodian-1', keyB), hasCode('INV-503-CONFIG'));
});

// ─── W20-2: artifact_digest flips are dead — consent epoch is anchored ──────
test('w20-ceremony W20-2: flipping artifact_digest cannot resurrect pre-commit consent', t => {
  const h = fixture(t);
  h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-flip', purpose: 'recovery', threshold: 2, custodians: CUST2, valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  const planned = h.f.store.must('acme', 'ceremony', 'cer-flip');
  const D0 = planned.artifact_digest;
  for (const subject of CUST2) h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(planned, subject, h.setup.custodianKeys.acme[subject], h.now()));
  const dealt = h.f.splitCeremonySecret(h.p('security'), 'cer-flip', randomBytes(32).toString('base64url'));
  flipCeremony(h, 'cer-flip', r => { r.artifact_digest = D0; });
  assert.equal(h.f.custodianQuorum('acme', h.f.store.must('acme', 'ceremony', 'cer-flip')).live, 0,
    'the consent epoch comes from the chain — a row flip cannot rewind it');
  h.advance(120001);
  assert.throws(() => h.f.reconstructCeremony(h.p('security'), 'cer-flip', [dealt.shares[0].share, dealt.shares[1].share]),
    e => e instanceof Error, 'reconstruction still refuses pre-commit consent');
});

test('w20-ceremony W20-2b: the flip is dead even with the envelope list emptied', t => {
  const h = fixture(t);
  h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-flip2', purpose: 'recovery', threshold: 2, custodians: CUST2, valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  const planned = h.f.store.must('acme', 'ceremony', 'cer-flip2');
  const D0 = planned.artifact_digest;
  for (const subject of CUST2) h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(planned, subject, h.setup.custodianKeys.acme[subject], h.now()));
  h.f.splitCeremonySecret(h.p('security'), 'cer-flip2', randomBytes(32).toString('base64url'));
  flipCeremony(h, 'cer-flip2', r => { r.artifact_digest = D0; r.acknowledgements = []; });
  assert.equal(h.f.custodianQuorum('acme', h.f.store.must('acme', 'ceremony', 'cer-flip2')).live, 0,
    'anchored acks are judged against the anchored commit digest, not the row');
});

test('w20-ceremony W20-2c: a flipped row cannot wedge honest post-commit consent', t => {
  const h = fixture(t);
  h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-wedge', purpose: 'recovery', threshold: 2, custodians: CUST2, valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  h.f.splitCeremonySecret(h.p('security'), 'cer-wedge', randomBytes(32).toString('base64url'));
  const committed = h.f.store.must('acme', 'ceremony', 'cer-wedge');
  for (const subject of CUST2) h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(committed, subject, h.setup.custodianKeys.acme[subject], h.now()));
  flipCeremony(h, 'cer-wedge', r => { r.artifact_digest = 'f'.repeat(64); });
  assert.equal(h.f.custodianQuorum('acme', h.f.store.must('acme', 'ceremony', 'cer-wedge')).live, 2,
    'the quorum reads the anchored commit epoch — row edits cannot kill it');
});

// ─── W20-3: health checks bind the signing device ───────────────────────────
test('w20-ceremony W20-3: an expired-health sibling device cannot enroll under the custodian subject', t => {
  const h = fixture(t);
  const keyB = secondIdentityKey(h, 'custodian-1');
  // The sibling-enrollment dodge is closed outright — one subject maps to
  // one live identity, so no second device can share the custodian's
  // subject to dodge the health gate (w31-runtime F-4).
  assert.throws(() => addIdentity(h, 'custodian-1', keyB, { health: h.now() - 1 }), hasCode('INV-503-CONFIG'));
});

// ─── W20-4: non-custodians and dead custodians cannot be planned ────────────
test('w20-ceremony W20-4: a custodian without a live custodian-role enrolment refuses at plan', t => {
  const h = fixture(t);
  assert.throws(() => h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-dead', purpose: 'recovery', threshold: 2, custodians: ['custodian-1', 'auditor'], valid_until: h.now() + 3600000, min_delay_ms: 120000 }),
    hasCode('INV-403-ROLE'), 'a subject with no custodian role can never consent — refuse at plan, not at wedge');
  h.f.revoke(h.p('security'), { kind: 'key', id: h.setup.custodianKeys.acme['custodian-2'].key_id, reason: 'lost device' });
  assert.throws(() => h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-dead2', purpose: 'recovery', threshold: 2, custodians: CUST2, valid_until: h.now() + 3600000, min_delay_ms: 120000 }),
    hasCode('INV-403-ROLE'), 'a revoked custodian enrolment cannot be planned into a ceremony');
  // The honest flow still plans, acks, and reconstructs.
  h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-live', purpose: 'recovery', threshold: 2, custodians: ['custodian-1', 'custodian-3'], valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  assert.equal(h.f.ceremonyStatus('acme', h.f.store.must('acme', 'ceremony', 'cer-live')), 'live');
});

// ─── residual: rotation spend anchored + designation excludes key.rotate ────
test('w20-residual: the rotation spend is anchored — a reused ceremony cannot spend twice', t => {
  const h = fixture(t);
  const pending = h.f.prepareRotation(h.p('security'), 'execution');
  const ceremony = h.f.createCeremony(h.p('security'), {
    ceremony_id: 'cer-spend', purpose: 'key.rotate', threshold: 2, custodians: CUST2,
    valid_until: h.now() + 3600000, min_delay_ms: 120000,
    rotation: { key_class: 'execution', new_key_id: pending.key_id },
  });
  for (const subject of CUST2) h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(ceremony, subject, h.setup.custodianKeys.acme[subject], h.now()));
  const out = h.f.execute(h.p(), certifyRotate(h, pending, 'cer-spend'));
  assert.equal(out.payload.status, 'VERIFIED');
  // A second certified rotation citing the same ceremony can never satisfy
  // the anchored spend — the first KEY_ROTATED already consumed it.
  const pending2 = h.f.prepareRotation(h.p('security'), 'execution');
  assert.throws(() => h.f.execute(h.p(), certifyRotate(h, pending2, 'cer-spend')), hasCode('INV-409-STATE'),
    'the ceremony is spent on the chain, not on the row');
});

test('w20-residual: designation binds purpose — a recovery-labelled rotation spec cannot designate', t => {
  const h = fixture(t);
  const pending = h.f.prepareRotation(h.p('security'), 'execution');
  // A recovery-labelled ceremony carrying a rotation spec is outside the
  // designation contract — only key.rotate ceremonies designate (and that
  // one does).
  const mislabeled = h.f.createCeremony(h.p('security'), {
    ceremony_id: 'cer-purpose', purpose: 'recovery', threshold: 2, custodians: CUST2,
    valid_until: h.now() + 3600000, min_delay_ms: 120000,
    rotation: { key_class: 'execution', new_key_id: pending.key_id },
  });
  for (const subject of CUST2) h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(mislabeled, subject, h.setup.custodianKeys.acme[subject], h.now()));
  assert.equal(h.f.ceremonyDesignated('acme', pending.key_id, 'execution'), false,
    'a recovery-labelled ceremony never designates a signer');
  const proper = h.f.createCeremony(h.p('security'), {
    ceremony_id: 'cer-purpose-ok', purpose: 'key.rotate', threshold: 2, custodians: CUST2,
    valid_until: h.now() + 3600000, min_delay_ms: 120000,
    rotation: { key_class: 'execution', new_key_id: pending.key_id },
  });
  for (const subject of CUST2) h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(proper, subject, h.setup.custodianKeys.acme[subject], h.now()));
  assert.equal(h.f.ceremonyDesignated('acme', pending.key_id, 'execution'), true,
    'the key.rotate ceremony designates its named successor');
});

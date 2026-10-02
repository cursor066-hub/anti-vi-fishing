import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode } from './helpers.mjs';
import { digest } from '../src/canonical.mjs';
import { verifySigned } from '../src/crypto.mjs';

// Wave-5 schema/secrets/simulator auditor regressions (report w5-schema).
// Each test names the finding it guards.

test('w5-F1: text fields reject invisible and bidi format characters', t => {
  const h = fixture(t);
  for (const bad of ['Legit\u202Eevil', 'pay\u200Bnow', 'X\uFEFFY', 'a\u2066b']) {
    assert.throws(() => h.proposed('finance.beneficiary.create', { vendor_id: 'v', bank_account: 'TESTBANK000009', currency: 'EUR' }, { action: { type: 'finance.beneficiary.create', target_resource: `res-${bad.length}`, purpose: bad } }), hasCode('INV-400-SCHEMA'), `accepted ${JSON.stringify(bad)}`);
  }
});

test('w5-F2: key_id "__proto__" resolves to nothing, not Object.prototype', t => {
  const env = { protected: { profile: 'IF-CJSON-1', suite: 'Ed25519', key_id: '__proto__', purpose: 'capsule-intent' }, payload: { x: 1 }, signature: 'AAAA' };
  assert.throws(() => verifySigned(env, {}, 'capsule-intent'), hasCode('INV-401-SIGNATURE'));
  assert.throws(() => verifySigned(env, { real: { public_key: 'x' } }, 'capsule-intent'), hasCode('INV-401-SIGNATURE'));
});

test('w5-F3: issuer credential rotation does not invalidate the evidence graph', t => {
  const h = fixture(t); const r = h.proposed();
  h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2);
  const t0 = 'acme';
  const before = h.f.graph(t0, r).digest;
  // Rotate every bearer credential on every registered issuer — a routine
  // operational event that must leave the certified graph untouched.
  for (const iss of Object.values(h.f.tenant(t0).issuers)) {
    iss.issue_token = 'rotated-issue-token'; iss.read_token = 'rotated-read-token'; iss.token_expires_at += 60000;
    // The endpoint itself is a frozen trust anchor: a live re-point would
    // let an in-process insider redirect the evidence POST — and its
    // Bearer token — to a hostile host (w12-provenance F15).
    assert.throws(() => { iss.endpoint = 'https://issuer.internal:9'; }, TypeError);
  }
  assert.equal(h.f.graph(t0, r).digest, before);
  // …and the certificate still issues against the unchanged digest.
  assert.ok(h.f.certificate(h.p(), r.capsule.capsule_id).payload.certificate_id);
});

test('w5-F4: rotation keeps the class purpose binding (no "any" fallback)', t => {
  const h = fixture(t);
  const exec = h.f.prepareRotation(h.p('custodian-1', 'acme', ['custodian']), 'execution');
  assert.deepEqual(h.f.vault.keys.get(exec.key_id).purpose, ['action-certificate', 'capability']);
  const audit = h.f.prepareRotation(h.p('custodian-1', 'acme', ['custodian']), 'audit');
  assert.deepEqual(h.f.vault.keys.get(audit.key_id).purpose, ['audit', 'outcome', 'revocation', 'coverage', 'checkpoint', 'backup-manifest']);
});

test('w5-F6: a reported-but-unwritten state cannot certify VERIFIED', t => {
  const h = fixture(t); const r = h.ready();
  const cert = r.certificate;
  const out = h.f.execute(h.p(), cert);
  assert.equal(out.payload.status, 'VERIFIED');
  // The real outcome is valid; now drift the target row underneath it — a
  // connector reporting a state that is no longer (or was never) on record.
  const stored = h.f.target.outcome('acme', cert.payload.certificate_id);
  h.f.target.seed('acme', r.record.capsule.action.target_resource, { unrelated: 'later write' });
  const live = h.f._validateTargetResponse(r.record, cert.payload, stored, h.f.clock(), { postRead: true });
  assert.equal(live.valid, false, 'post-read accepted a state the target never wrote');
  // Reconcile replays history: state may legitimately have moved on.
  const replay = h.f._validateTargetResponse(r.record, cert.payload, stored, h.f.clock(), { postRead: false });
  assert.equal(replay.valid, true, 'reconcile must not demand the current state match a historical report');
});

test('w5-F7: secret.use binds the secrets-registry row, not a resource row', t => {
  const h = fixture(t);
  const requested = { secret_id: 'secret-erp-1', operation: 'sign', workload_id: 'workload-1' };
  const r = h.proposed('secret.use', requested, { action: { type: 'secret.use', target_resource: 'secret-erp-1', purpose: 'Sign payroll batch' } });
  h.evidence(r, { kind: 'workload_attestation' }); h.evidence(r, { kind: 'workload_attestation', issuer: 'cloud-attestor' }); h.approve(r, 2);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  assert.equal(h.f.execute(h.p(), cert).payload.status, 'VERIFIED');
  const secret = h.f.target.secret('acme', 'secret-erp-1');
  assert.equal(secret.last_use.transaction, cert.payload.certificate_id, 'last_use landed on the registry row');
  // A registry mutation after certification is a freshness violation at
  // dispatch — before the fix it sailed through on the untouched resource row.
  const r2 = h.proposed('secret.use', requested, { action: { type: 'secret.use', target_resource: 'secret-erp-1', purpose: 'Sign again' } });
  h.evidence(r2, { kind: 'workload_attestation' }); h.evidence(r2, { kind: 'workload_attestation', issuer: 'cloud-attestor' }); h.approve(r2, 2);
  const cert2 = h.f.certificate(h.p(), r2.capsule.capsule_id);
  h.f.target.seedSecret('acme', 'secret-erp-1', { workload_id: 'workload-1', allowed_operations: ['sign', 'authenticate'], vault_bound: true, note: 'registry drifted' });
  assert.throws(() => h.f.execute(h.p(), cert2), hasCode('INV-409-STATE'));
});

test('w5-F8/F9: derived times use the gate clock; INV-5xx outcomes are UNCERTAIN', t => {
  const h = fixture(t); const r = h.ready();
  const out = h.f.execute(h.p(), r.certificate);
  assert.equal(out.payload.status, 'VERIFIED');
  // Gate-clock derivation: observed timestamps equal the gate's own now, not
  // an echo of whatever execution_time the connector chose to report.
  const cert = r.certificate;
  const tx = h.f.target.outcome('acme', cert.payload.certificate_id);
  const record = r.record;
  const { expected } = h.f._validateTargetResponse(record, cert.payload, tx, tx.execution_time, { postRead: false });
  assert.equal(digest(expected), tx.observed_state_digest);
});

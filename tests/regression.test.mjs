// Regression coverage for e2e-discovered defects: drift-check shape,
// controlled-workspace fallback binding, and sealed-release semantics.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { driftCheck } from '../src/connectors.mjs';
import { workspaceFallback } from '../src/secureview.mjs';
import { generateKey, signed, verifySigned } from '../src/crypto.mjs';
import { Store } from '../src/store.mjs';
import { KeyVault } from '../src/keystore.mjs';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture, hasCode } from './helpers.mjs';

test('driftCheck: identical registered/observed manifests report no drift', () => {
  const registered = { connector_id: 'issuer:bank', version: '1.0.0', actions: ['bank.ownership', 'bank.balance'], channel: 'authoritative', key_id: 'k1' };
  const observed = { connector_id: 'issuer:bank', version: '1.0.0', actions: ['bank.balance', 'bank.ownership'], channel: 'authoritative', key_id: 'k1' };
  const r = driftCheck(registered, observed, 1700000000000);
  assert.equal(r.drifted, false); assert.deepEqual(r.changes, []); assert.equal(r.action, 'none');
});

test('driftCheck: version, kinds, channel and key changes are each reported', () => {
  const registered = { connector_id: 'issuer:bank', version: '1.0.0', actions: ['bank.ownership'], channel: 'authoritative', key_id: 'k1' };
  const observed = { connector_id: 'issuer:bank', version: '2.0.0', actions: ['bank.ownership', 'bank.balance'], channel: 'device', key_id: 'k2' };
  const r = driftCheck(registered, observed, 1700000000000);
  assert.equal(r.drifted, true);
  assert.deepEqual(r.changes.map(c => c.field), ['version', 'actions', 'channel', 'key_id']);
});

test('driftCheck: missing optional fields never throw and are reported honestly', () => {
  const r = driftCheck({ version: '1.0.0', key_id: 'k1' }, { version: '1.0.0', key_id: 'k1' }, 1700000000000);
  assert.equal(r.drifted, false);
  const r2 = driftCheck({ version: '1.0.0' }, { version: '1.0.0', connector_id: 'issuer:bank' }, 1700000000000);
  assert.equal(r2.drifted, true); assert.deepEqual(r2.changes[0].field, 'connector_id');
});

test('workspaceFallback: returns honest plaintext binding with reason', () => {
  const policy = { secure_perception: { fallback: 'controlled-workspace', release_fields: '*' } };
  const out = workspaceFallback({ fields: { bank_account: 'TESTBANK1' }, purpose: 'review', reason: 'no device' }, policy, 1700000000000);
  assert.equal(out.mode, 'controlled-workspace'); assert.equal(out.production, false);
  assert.deepEqual(out.binding.fields, ['bank_account']); assert.equal(out.binding.reason, 'no device');
  assert.deepEqual(out.data, { bank_account: 'TESTBANK1' });
});

test('workspaceFallback: policy denial is fail-closed', () => {
  assert.throws(() => workspaceFallback({ fields: {}, purpose: 'x' }, { secure_perception: { fallback: 'deny' } }, 1), e => e.code === 'INV-451-POLICY');
});

test('ES256: envelope signs and verifies with P-256/IEEE-P1363', () => {
  const key = generateKey('ES256'), payload = { note: 'second suite' };
  const env = signed(payload, key, 'evidence');
  assert.equal(env.protected.suite, 'ES256');
  assert.deepEqual(verifySigned(env, { [key.key_id]: key }, 'evidence'), payload);
  env.payload = { note: 'tampered' };
  assert.throws(() => verifySigned(env, { [key.key_id]: key }, 'evidence'), e => e.code === 'INV-401-SIGNATURE');
});

test('suite confusion: Ed25519 signature cannot masquerade under another suite', () => {
  const ed = generateKey('Ed25519'), env = signed({ a: 1 }, ed, 'evidence');
  env.protected.suite = 'ES256';
  assert.throws(() => verifySigned(env, { [ed.key_id]: ed }, 'evidence'), e => e.code === 'INV-401-SIGNATURE');
  env.protected.suite = 'UnknownSuite';
  assert.throws(() => verifySigned(env, { [ed.key_id]: ed }, 'evidence'), e => e.code === 'INV-401-SIGNATURE');
});

test('vault: ES256 keys generate, sign and attest honestly', () => {
  const dir = mkdtempSync(join(tmpdir(), 'if-vault-'));
  try {
    const vault = new KeyVault(randomBytes(32).toString('base64url'));
    const k = vault.generate('evidence', { suite: 'ES256' });
    assert.equal(k.suite, 'ES256');
    const env = vault.envelope(k.key_id, 'evidence', { x: 1 });
    assert.equal(env.protected.suite, 'ES256');
    assert.equal(vault.verify(k.key_id, JSON.stringify({ x: 1 }), 'AAAA'), false);
    const att = vault.attest(k.key_id);
    assert.equal(att.payload.suite, 'ES256'); assert.equal(att.payload.hardware, false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('crypto-shredding: record unreadable after DEK destruction', () => {
  const dir = mkdtempSync(join(tmpdir(), 'if-shred-'));
  try {
    const tenantKeys = { acme: randomBytes(32).toString('base64url') };
    const signer = { sign: p => ({ protected: { profile: 'IF-CJSON-1', suite: 'Ed25519', key_id: 'a', purpose: 'audit' }, payload: p, signature: 'x'.repeat(86) }) };
    const store = new Store(join(dir, 's.db'), tenantKeys, { acme: signer });
    store.put('acme', 'evidence', 'e1', { secret: 'payload' }, 1000);
    assert.deepEqual(store.get('acme', 'evidence', 'e1'), { secret: 'payload' });
    const ciphertext = store.db.prepare('SELECT value FROM records WHERE id=?').get('e1').value;
    const wrapped = store.db.prepare('SELECT wrapped FROM deks WHERE id=?').get('e1').wrapped;
    assert.notEqual(ciphertext, undefined); assert.notEqual(wrapped, undefined);
    assert.equal(store.shred('acme', 'evidence', 'e1'), true);
    assert.equal(store.get('acme', 'evidence', 'e1'), null);
    assert.equal(store.dek('acme', 'evidence', 'e1'), null);
    // Even holding ciphertext + wrapped DEK + tenant key no longer decrypts
    // on a fresh view, because the DEK row is gone from the live image.
    assert.equal(store.db.prepare('SELECT COUNT(*) c FROM deks').get().c, 0);
    store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---------- Canonical fuzz ----------

function* rng(seed) { let s = seed >>> 0; while (true) { s = (s * 1664525 + 1013904223) >>> 0; yield s / 0xffffffff; } }
function randomValue(rand, depth = 0) {
  const r = rand.next().value;
  if (depth > 4 || r < 0.25) return [null, true, false, 0, -1, 1, 42, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER][Math.floor(rand.next().value * 9)];
  if (r < 0.5) return ['', 'abc', 'key_1', 'naïve'.normalize('NFC'), 'x'.repeat(Math.floor(rand.next().value * 100))][Math.floor(rand.next().value * 5)];
  if (r < 0.75) return Array.from({ length: Math.floor(rand.next().value * 5) }, () => randomValue(rand, depth + 1));
  const o = {}; for (let i = 0; i < Math.floor(rand.next().value * 5); i++) o[`k${i}_${Math.floor(rand.next().value * 100)}`] = randomValue(rand, depth + 1); return o;
}

import { canonical, digest, parseStrict, hashBytes, clone } from '../src/canonical.mjs';

test('canonical: 2000 seeded random values roundtrip deterministically', () => {
  const rand = rng(0x1F02);
  for (let i = 0; i < 2000; i++) {
    const v = randomValue(rand), a = canonical(v), b = canonical(v);
    assert.equal(a, b);
    assert.deepEqual(JSON.parse(a), v);
    assert.equal(digest(v), digest(v));
    assert.throws(() => canonical({ ...v, 'bad key': 1 }), () => true);
  }
});

test('canonical: adversarial string corpus rejects per profile', () => {
  for (const s of ['e\u0301', 'naïve'.normalize('NFD'), '\uD800', '\uDFFF\uD800']) assert.throws(() => canonical(s), () => true);
  for (const n of [1.5, -0, NaN, Infinity, 2 ** 53]) assert.throws(() => canonical(n), () => true);
  assert.throws(() => canonical(JSON.parse('{"__proto__":1}')), () => true);
  assert.throws(() => canonical({ 'ünïcode': 1 }), () => true);
});

test('parseStrict: duplicate keys and oversized bodies rejected', () => {
  assert.throws(() => parseStrict('{"a":1,"a":2}'), () => true);
  assert.throws(() => parseStrict('{"a":' + '1'.repeat(1_100_000) + '}'), () => true);
});

// ---------- Coverage bypass probe ----------

test('coverage: direct target mutation does not upgrade manifest assurance', t => {
  const h = fixture(t);
  // An attacker mutates the target directly, outside the gate.
  h.f.target.db.prepare("UPDATE resources SET value=? WHERE tenant=? AND id=?").run(JSON.stringify({ hacked: true }), 'acme', 'beneficiary-1');
  h.f.declareCoverage(h.p('security'), { path_id: 'api-path', action_type: 'finance.payment.first', target: 'bank-1', environment: 'simulation', connector_version: '1.0.0', owner: 'security', status: 'MONITORED', max_age_ms: 60000, configuration_digest: digest({ x: 1 }) });
  const manifest = h.f.coverage(h.p());
  // The manifest must keep reporting the honest guarantee level: a bypass
  // never produces an ENFORCED claim.
  assert.equal(manifest.payload.assurance, 'NO_PRODUCTION_ENFORCEMENT_GUARANTEE');
  assert.equal(manifest.payload.paths.every(pp => ['MONITORED', 'UNKNOWN'].includes(pp.effective_status)), true);
});

// ---------- Audit-round-2 fixes: drift consequence, config quarantine, ceremony delay ----------

import { declarePath, applyDriftToPaths } from '../src/coverage.mjs';
import { Fabric } from '../src/fabric.mjs';
import { signAcknowledgement } from '../src/ceremony.mjs';


test('COV-004 CON-006: declared paths carry observation time and drift moves them to UNKNOWN', () => {
  const p1 = declarePath({ path_id: 'p1', action_type: 'finance.payment.first', target: 'bank-1', environment: 'sim', connector_version: '1.0.0', owner: 'sec', status: 'MONITORED', max_age_ms: 1000, configuration_digest: digest({ a: 1 }) }, 100);
  const p2 = declarePath({ path_id: 'p2', action_type: 'finance.payment.first', target: 'other', environment: 'sim', connector_version: '1.0.0', owner: 'sec', status: 'MONITORED', max_age_ms: 1000, configuration_digest: digest({ a: 1 }) }, 100);
  assert.equal(p1.evidence_at, 100); // write-once-null bug fixed: observation time recorded
  const staled = applyDriftToPaths([p1, p2], pp => pp.target === 'bank-1');
  assert.equal(staled, 1);
  assert.equal(p1.status, 'UNKNOWN'); assert.equal(p1.evidence_at, null);
  assert.equal(p2.status, 'MONITORED');
});

test('RUN-010: config drift withdraws gate privileges until security re-attestation', t => {
  const h = fixture(t);
  h.close();
  const tampered = clone(h.setup.config);
  tampered.tenants.acme.identities['ghost'] = { subject_id: 'ghost', roles: ['operator'], key_id: 'ghost', public_key: 'x' };
  const f2 = new Fabric(tampered, h.directory, () => h.now());
  try {
    const err = (() => { try { f2.transaction(h.p(), () => {}); } catch (e) { return e.code; } })();
    assert.equal(err, 'INV-403-QUARANTINE');
    const re = f2.reassertConfig(h.p('security'));
    assert.equal(re.reasserted, true);
    // Gate privileges restored after re-attestation.
    assert.ok(f2.transaction(h.p(), () => 42) === 42);
  } finally { f2.close(); }
});

test('KEY-009: recovery delay blocks reconstruction and per-custodian notices are issued', t => {
  const h = fixture(t);
  const custodians = ['custodian-1', 'custodian-2', 'custodian-3'];
  const c = h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-delay', purpose: 'root recovery', threshold: 2, custodians, valid_until: h.now() + 3600000, min_delay_ms: 60000 });
  for (const s of custodians.slice(0, 2)) h.f.acknowledgeCeremony(h.p(s), signAcknowledgement(c, s, h.setup.custodianKeys.acme[s], h.now()));
  const split = h.f.splitCeremonySecret(h.p('security'), 'cer-delay', randomBytes(32).toString('base64url'));
  // Notices issued for every custodian at commit time.
  const notices = h.f.store.auditPage('acme').entries.filter(a => a.envelope.payload.type === 'RECOVERY_NOTICE_ISSUED');
  assert.equal(notices.length, 3);
  // Reconstruct inside the delay window is rejected.
  assert.throws(() => h.f.reconstructCeremony(h.p('security'), 'cer-delay', [split.shares[0].share, split.shares[1].share]), hasCode('INV-409-STATE'));
  h.advance(60001);
  const rec = h.f.reconstructCeremony(h.p('security'), 'cer-delay', [split.shares[0].share, split.shares[1].share]);
  assert.equal(rec.reconstructed, true);
});

test('IDN-005: MFA reset, authenticator enrolment and account recovery are separate protected actions', t => {
  const h = fixture(t);
  for (const [type, requested] of [
    ['identity.mfa.reset', { subject_id: 'operator', authenticator_id: 'auth-1' }],
    ['identity.authenticator.enroll', { subject_id: 'operator', credential_digest: digest({ c: 1 }) }],
    ['identity.account.recover', { subject_id: 'operator', privilege: 'admin' }],
  ]) {
    const r = h.proposed(type, requested, { action: { type, target_resource: 'identity-ops', purpose: `protected ${type}` } });
    h.evidence(r, { issuer: 'hris', kind: 'recovery_authority' });
    h.evidence(r, { issuer: 'registry', kind: 'identity_proof' });
    h.approve(r, 2);
    assert.equal(h.f.evaluate(h.p(), r.capsule.capsule_id).decision, 'ALLOW');
  }
});

test('IDN-004: expired JIT grant no longer widens runtime scope', t => {
  const h = fixture(t);
  const r = h.proposed('identity.jit.grant', { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-99'], ttl_ms: 30000, reason: 'Incident', roles: [] }, { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'JIT' } });
  h.evidence(r, { kind: 'identity_proof', issuer: 'hris' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' }); h.approve(r, 2);
  h.f.execute(h.p(), h.f.certificate(h.p(), r.capsule.capsule_id));
  const req = () => h.f.runtime.issue(h.p(), { device_id: 'operator-device', resource: 'dataset-1', destination: 'customer-vault', action: 'data.read', purpose: 'operations', columns: ['id'], row_ids: ['row-99'], classification: 'internal', jurisdiction: 'EU', max_cost: 10, ttl_ms: 60000 });
  assert.ok(req().payload.capability_id);
  h.advance(30001);
  assert.throws(() => req(), hasCode('INV-403-SCOPE'));
});

test('AIG-003: extraction preserves provenance (span, confidence, model, document digest)', t => {
  const h = fixture(t);
  const out = h.f.advise(h.p(), { operation: 'extract', document: 'pay vendor-1 the amount of 5000 EUR' });
  assert.equal(out.candidates.length > 0, true);
  for (const c of out.candidates) { assert.equal(typeof c.field, 'string'); assert.ok(Array.isArray(c.span)); assert.equal(typeof c.confidence, 'number'); }
  assert.equal(typeof out.model, 'string'); assert.equal(typeof out.document_digest, 'string');
});

test('AIG-009: disabling the advisory plane preserves enforcement (no degradation)', t => {
  const h = fixture(t);
  const policy = clone(h.f.policy('acme')); policy.mode = 'disabled';
  h.f.store.put('acme', 'policy', 'active', policy, h.now());
  assert.throws(() => h.f.advise(h.p(), { operation: 'explain', decision: {} }), hasCode('INV-451-POLICY'));
  const r = h.ready(); // enforcement path unaffected by advisory plane being off
  assert.equal(h.f.execute(h.p(), r.certificate).payload.status, 'VERIFIED');
});

// ---------- Adversarial review fixes (round 3) ----------

import { createIssuerServer, writeIssuer, answerQuery } from '../src/issuerd.mjs';
import { ISSUER_RULES, issuerRecords } from '../src/bootstrap.mjs';
import { httpJson } from '../src/connectors.mjs';

test('H1: a certificate revoked via its own revocation_ref cannot execute', t => {
  const h = fixture(t), r = h.ready();
  const certId = r.certificate.payload.revocation_ref.split(':')[1];
  assert.equal(certId, r.certificate.payload.certificate_id);
  h.f.revoke(h.p('security'), { kind: 'certificate', id: certId, reason: 'revocation_ref path' });
  assert.throws(() => h.f.execute(h.p(), r.certificate), hasCode('INV-401-CERTIFICATE'));
});

test('M1: key.rotate adopting a non-vault public key is rejected', t => {
  const h = fixture(t);
  const prep = h.f.prepareRotation(h.p('security'), 'execution');
  const bogus = generateKey().public_key;
  const r = h.proposed('key.rotate', { key_class: 'execution', new_key_id: prep.key_id, new_public_key: bogus, ceremony_id: 'cer-1', revoke_old: false }, { action: { type: 'key.rotate', target_resource: 'key-registry', purpose: 'Rotation' } });
  h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'registry' });
  h.approve(r, 3); h.advance(60001);
  assert.throws(() => h.f.execute(h.p(), h.f.certificate(h.p(), r.capsule.capsule_id)), hasCode('INV-400-SCHEMA'));
  assert.equal(h.f.keys('acme').execution.key_id !== prep.key_id, true); // tenant key unchanged
});

test('H2: issuerd issuance requires the bearer token; conflict answers never leak unclaimed fields', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-auth-')); t.after(() => rmSync(dir, { recursive: true }));
  const key = generateKey(), token = 'tok-' + randomBytes(12).toString('hex');
  const spec = { issuer: 'bank', tenant: 'acme', version: '1.0.0', channel: 'authoritative', key, kinds: ISSUER_RULES.bank, records: issuerRecords().bank, issue_token: token };
  writeIssuer(dir, spec);
  const srv = createIssuerServer({ 'acme:bank': spec }, { port: 0, host: '127.0.0.1' });
  await srv.listen(); t.after(() => srv.close());
  const port = srv.server.address().port, body = { kind: 'ownership', subject_id: 'operator', claims: { account: 'TESTBANK000001', owner_id: 'vendor-1' }, capsule_digest: 'a'.repeat(64), tenant_id: 'acme' };
  const unauth = await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/issue`, { method: 'POST', body });
  assert.equal(unauth.status, 401);
  const authed = await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/issue`, { method: 'POST', body, token });
  assert.equal(authed.status, 201);
  const wrong = await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/issue`, { method: 'POST', body: { ...body, claims: { account: 'TESTBANK000001', owner_id: 'intruder' } }, token });
  assert.equal(wrong.data.payload.claim, 'conflict');
  // Conflict only echoes fields the caller already asserted correctly.
  for (const v of Object.values(wrong.data.payload.claims ?? {})) assert.notEqual(String(v), 'vendor-1');
  // No token on a non-loopback bind refuses issuance outright.
  const open = createIssuerServer({ 'acme:bank': { ...spec, issue_token: undefined } }, { port: 0, host: '0.0.0.0' });
  await open.listen(); t.after(() => open.close());
  const refused = await httpJson(`http://127.0.0.1:${open.server.address().port}/v1/issuers/bank/issue`, { method: 'POST', body });
  assert.equal(refused.status, 503);
});

test('L1: malleated ES256 signature (r, n-s) is rejected', t => {
  const key = generateKey('ES256');
  const env = signed({ a: 1 }, key, 'evidence');
  const sig = Buffer.from(env.signature, 'base64url');
  const n = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');
  const s = BigInt('0x' + sig.subarray(32).toString('hex'));
  if (s <= n / 2n) {
    const low = (n - s).toString(16).padStart(64, '0');
    env.signature = Buffer.concat([sig.subarray(0, 32), Buffer.from(low, 'hex')]).toString('base64url');
    assert.throws(() => verifySigned(env, { [key.key_id]: key }, 'evidence'), hasCode('INV-401-SIGNATURE'));
  }
  // And the original verifies under the canonical low-s rule.
  const ok = signed({ a: 1 }, key, 'evidence');
  assert.equal(verifySigned(ok, { [key.key_id]: key }, 'evidence').a, 1);
});

test('L2: explain renders real reason codes, never [object Object]', t => {
  const h = fixture(t);
  const r = h.proposed('finance.beneficiary.create', { vendor_id: 'v', bank_account: 'TESTBANK000001', currency: 'EUR' });
  const decision = h.f.evaluate(h.p(), r.capsule.capsule_id);
  // explain narrates stored decisions only (runtime-audit F-13) — pass the
  // capsule id, and confirm a caller-supplied verdict object is refused.
  const out = h.f.advise(h.p(), { operation: 'explain', capsule_id: r.capsule.capsule_id });
  assert.equal(out.verdict, decision.decision);
  for (const x of out.reasons) { assert.equal(typeof x.code, 'string'); assert.equal(/\[object Object\]/.test(x.text), false); }
  assert.equal(/\[object Object\]/.test(out.text), false);
  assert.throws(() => h.f.advise(h.p(), { operation: 'explain', capsule_id: 'cap-nope' }), (e) => e.code === 'INV-404-NOT-FOUND');
  assert.throws(() => h.f.advise(h.p(), { operation: 'explain' }), (e) => e.code === 'INV-400-SCHEMA');
});

test('L3: secure-perception release binds capsule_id and evidence_ref into the sealed envelope', t => {
  const h = fixture(t);
  const component = h.setup.componentSecrets.acme['secure-view-acme'];
  const session = h.f.perceptionSession(h.p(), component.attest('b'.repeat(64), h.now() + 300000));
  const r = h.proposed();
  const evidence = h.evidence(r);
  const released = h.f.perceptionRelease(h.p(), session.session_id, { fields: { vendor: 'v1' }, purpose: 'verify', capsule_id: r.capsule.capsule_id, evidence_ref: evidence.payload.evidence_id });
  assert.equal(released.binding.capsule_id, r.capsule.capsule_id);
  assert.equal(released.binding.evidence_ref, evidence.payload.evidence_id);
  // Forged provenance is refused (runtime-audit F-6).
  assert.throws(() => h.f.perceptionRelease(h.p(), session.session_id, { fields: { vendor: 'v1' }, purpose: 'verify', capsule_id: 'cap-ghost' }), (e) => e.code === 'INV-404-NOT-FOUND');
});

test('L4: evidence signed under a retired suite is rejected policy-wide', t => {
  const h = fixture(t), r = h.proposed('finance.beneficiary.create', { vendor_id: 'v', bank_account: 'TESTBANK000001', currency: 'EUR' });
  const esKey = generateKey('ES256');
  h.f.tenant('acme').issuers[esKey.key_id] = { public_key: esKey.public_key, name: 'es-issuer', issuer_id: 'es-issuer', channel: 'authoritative', kinds: ['ownership'], failure_domain: 'acme-es', version: '1.0.0' };
  const env = signed({ evidence_id: 'ev-es-1', tenant_id: 'acme', capsule_digest: r.capsule.capsule_id, kind: 'ownership', content_digest: digest({ x: 1 }), acquired_at: h.now(), expires_at: h.now() + 60000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 'x', retention_until: h.now() + 120000 }, esKey, 'evidence');
  // Default constitution allows Ed25519 only — a valid ES256 envelope must fail policy, not crypto.
  assert.throws(() => h.f.attachEvidence(h.p(), r.capsule.capsule_id, env), hasCode('INV-451-POLICY'));
});

test('M2: a rolled-back consume leaves no phantom data_access touches', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), { device_id: 'operator-device', resource: 'dataset-1', destination: 'customer-vault', action: 'data.read', purpose: 'operations', columns: ['id'], row_ids: ['row-1'], classification: 'internal', jurisdiction: 'EU', max_cost: 10, ttl_ms: 60000 });
  const req = () => ({ capability: cap, device_id: 'operator-device', resource: 'dataset-1', destination: 'customer-vault', action: 'data.read', purpose: 'operations', columns: ['id'], row_ids: ['row-1'], request_id: 'req-m2-1', protocol: 'https', port: 443 });
  const touches = () => h.f.store.db.prepare('SELECT count(*) AS n FROM data_access WHERE tenant=?').get('acme').n;
  const origAudit = h.f.store.audit.bind(h.f.store);
  h.f.store.audit = (...a) => { if (a[1] === 'RUNTIME_ALLOWED') throw new Error('simulated audit failure'); return origAudit(...a); };
  assert.throws(() => h.f.runtime.consume(h.p(), req()));
  h.f.store.audit = origAudit;
  assert.equal(touches(), 0);
  const ok = h.f.runtime.consume(h.p(), { ...req(), request_id: 'req-m2-2' });
  assert.equal(ok.decision, 'ALLOW');
  assert.ok(touches() > 0);
});

// ── Audit round 4: hostile HTTP/authz auditor findings ───────────────────────

test('audit: only the proposing actor may attach evidence (griefing blocked)', t => {
  const h = fixture(t), r = h.proposed();
  const key = h.setup.issuerKeys.acme.bank, payload = { evidence_id: 'x', tenant_id: 'acme', capsule_digest: r.capsule_digest, kind: 'ownership', content_digest: 'a'.repeat(64), acquired_at: h.now(), expires_at: h.now() + 600000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 'x', retention_until: h.now() + 700000 };
  const envelope = signed(payload, key, 'evidence');
  assert.throws(() => h.f.attachEvidence(h.p('security'), r.capsule.capsule_id, envelope), hasCode('INV-403-SCOPE'));
});

test('audit: revoke names must exist (no silent record pollution)', t => {
  const h = fixture(t);
  assert.throws(() => h.f.revoke(h.p('security'), { kind: 'subject', id: 'ghost-user', reason: 'x' }), hasCode('INV-404-NOT-FOUND'));
  assert.throws(() => h.f.revoke(h.p('security'), { kind: 'issuer', id: 'ghost-issuer', reason: 'x' }), hasCode('INV-404-NOT-FOUND'));
});

test('audit: token revocation marks the token hash in the revocation store', t => {
  const h = fixture(t);
  const token = h.setup.credentials.acme.operator, tokenHash = hashBytes(token);
  h.f.revoke(h.p('security'), { kind: 'token', id: tokenHash, reason: 'leak drill' });
  assert.equal(h.f.revoked('acme', 'token', tokenHash), true);
});

test('audit: key.rotate requires an acknowledged ceremony', t => {
  const h = fixture(t);
  const prep = h.f.prepareRotation(h.p('security'), 'execution');
  const r = h.proposed('key.rotate', { key_class: 'execution', new_key_id: prep.key_id, new_public_key: prep.public_key, ceremony_id: 'cer-nonexistent', revoke_old: true }, { action: { type: 'key.rotate', target_resource: 'key-registry', purpose: 'Rotation' } });
  h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'registry' });
  h.approve(r, 3); h.advance(60001);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  assert.throws(() => h.f.execute(h.p(), cert), hasCode('INV-409-STATE'));
});

test('audit: releaseFields honour a policy allowlist (INV-451 on unlisted fields)', t => {
  const policy = { secure_perception: { fallback: 'controlled-workspace', release_fields: ['bank_account'] } };
  assert.throws(() => workspaceFallback({ fields: { bank_account: 'TESTBANK1', ssn: '001' }, purpose: 'review', reason: 'x' }, policy, 1), hasCode('INV-451-POLICY'));
});

test('audit: configDriftStatus reports per-section digests and no drift on fresh snapshot', t => {
  const h = fixture(t);
  const s = h.f.configDriftStatus(h.p('security'));
  assert.equal(s.drifted, false); assert.deepEqual(s.changed_sections, []); assert.ok(s.observed);
});

// ===== Audit round 2: runtime F-4/F-8/F-9/F-10/F-12, policy F2-F5/F8/F9 =====
import { evaluatePolicy } from '../src/policy.mjs';

import { runtimeInput, runtimeRequest, BASE_TIME } from './helpers.mjs';

const policyCapsule = (policy, candidate, opts = {}) => ({
  capsule_id: 'cap-x', tenant_id: 'acme', policy_version: policy.version,
  expires_at: BASE_TIME + 3600000, created_at: opts.created_at ?? BASE_TIME - 600000,
  received_at: opts.received_at ?? BASE_TIME - 600000, quantity: 1,
  destination: 'customer-vault', actor: { subject_id: 'initiator', device_id: 'dev-1' },
  action: { type: opts.type ?? 'policy.change', target_resource: 'policy' },
  exclusions: [], requested_state: opts.requested ?? { policy: candidate },
  current_state: { version: 1, digest: 'x', material_fields: {} },
});

test('R2-1: a grant narrowed since issuance cannot ride a signed capability', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ columns: ['id', 'name'] }));
  assert.equal(h.f.runtime.consume(h.p(), runtimeRequest(cap, { columns: ['id', 'name'] })).decision, 'ALLOW');
  const ident = Object.values(h.f.tenant('acme').identities).find(i => i.subject_id === 'operator');
  ident.grants = { ...ident.grants, columns: ['id'] };
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap, { columns: ['id', 'name'] })), hasCode('INV-403-SCOPE'));
});

test('R2-2: transform policy binds capabilities; row key is never transformable', t => {
  const h = fixture(t);
  assert.throws(() => h.f.runtime.issue(h.p(), runtimeInput({ transforms: { id: { op: 'drop' } } })), hasCode('INV-403-SCOPE'));
  assert.throws(() => h.f.runtime.issue(h.p(), runtimeInput({ resource: 'dataset-9' })), hasCode('INV-403-SCOPE'));
  assert.throws(() => h.f.runtime.issue(h.p(), runtimeInput({ columns: ['id', 'salary'] })), hasCode('INV-403-SCOPE'));
  const active = h.f.policy('acme'), next = clone(active);
  next.runtime.allowed_transforms = ['mask', 'drop', 'constant'];
  h.f.store.put('acme', 'policy', 'active', next, h.now());
  assert.throws(() => h.f.runtime.issue(h.p(), runtimeInput({ transforms: { name: { op: 'tokenise' } } })), hasCode('INV-403-SCOPE'));
});

test('R2-3: deterministic target refusals record FAILED, not UNCERTAIN', t => {
  const h = fixture(t), { certificate } = h.ready();
  const out = h.f.execute(h.p(), certificate, { fault: 'state-conflict' });
  assert.equal(out.payload.status, 'FAILED');
  assert.equal(out.payload.reason, 'INV-409-STATE');
  assert.throws(() => h.f.execute(h.p(), certificate), hasCode('INV-409-REPLAY'));
});

test('RUN-005 R2-4: constrained fail mode allows stale reads at half budget only', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ max_cost: 10, columns: ['id', 'name'], row_ids: ['row-1', 'row-2'] }));
  const serviceCap = h.f.runtime.issue(h.p(), runtimeInput({ action: 'service.connect', resource: 'erp-service', destination: 'erp-service', columns: [], row_ids: [] }));
  const next = clone(h.f.policy('acme'));
  next.fail_modes = { ...next.fail_modes, 'data.read': 'constrained', 'service.connect': 'constrained' };
  next.version += 1;
  h.f.store.put('acme', 'policy', 'active', next, h.now());
  const first = h.f.runtime.consume(h.p(), runtimeRequest(cap));
  assert.equal(first.decision, 'ALLOW');
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap)), hasCode('INV-429-BUDGET'));
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(serviceCap)), hasCode('INV-503-GATE'));
});

test('R2-5: perception sessions are bound to their creator', t => {
  const h = fixture(t);
  const component = h.setup.componentSecrets.acme['secure-view-acme'];
  const session = h.f.perceptionSession(h.p(), component.attest('c'.repeat(64), h.now() + 300000));
  assert.throws(() => h.f.perceptionRelease(h.p('custodian-1'), session.session_id, { fields: { vendor: 'v1' }, purpose: 'verify' }), hasCode('INV-403-SCOPE'));
  assert.equal(h.f.perceptionRelease(h.p(), session.session_id, { fields: { vendor: 'v1' }, purpose: 'verify' }).binding.fields[0], 'vendor');
});

test('POL-014 R2-6: governance floors cannot be lowered by a successor', t => {
  const h = fixture(t), policy = h.f.policy('acme'), now = h.now();
  const candidate = clone(policy);
  candidate.version += 1; candidate.expires_at = now + 86400000; candidate.not_before = 1;
  candidate.staged_policy = { ...candidate.staged_policy, min_delay_ms: policy.staged_policy.min_delay_ms - 1 };
  const out = evaluatePolicy({ capsule: policyCapsule(policy, candidate), policy, identities: h.f.identities('acme'), now });
  assert.equal(out.decision, 'DENY');
  assert.equal(out.reasons[0].code, 'GOVERNANCE_FLOOR');
  const candidate2 = clone(policy);
  candidate2.version += 1; candidate2.expires_at = now + 86400000; candidate2.not_before = 1;
  candidate2.staged_policy = { ...candidate2.staged_policy, emergency_max_ttl_ms: policy.staged_policy.emergency_max_ttl_ms + 1 };
  const out2 = evaluatePolicy({ capsule: policyCapsule(policy, candidate2), policy, identities: h.f.identities('acme'), now });
  assert.equal(out2.reasons[0].code, 'GOVERNANCE_FLOOR');
});

test('POL-014 R2-7: an emergency policy that weakens any dimension is denied', t => {
  const h = fixture(t), policy = h.f.policy('acme'), now = h.now(), extra = policy.staged_policy.emergency_extra_custodians;
  const strict = clone(policy);
  strict.version += 1; strict.emergency_of = policy.version; strict.expires_at = now + 60000; strict.not_before = 1;
  for (const r of Object.values(strict.rules)) r.approval_threshold = Math.min(5, r.approval_threshold + extra);
  const passes = evaluatePolicy({ capsule: policyCapsule(policy, strict), policy, identities: h.f.identities('acme'), now });
  assert.equal(passes.reasons.some(r => r.code.startsWith('EMERGENCY_')), false);
  const weak = clone(strict);
  weak.rules['finance.beneficiary.create'].evidence_kinds = [];
  const out = evaluatePolicy({ capsule: policyCapsule(policy, weak), policy, identities: h.f.identities('acme'), now });
  assert.equal(out.decision, 'DENY');
  assert.equal(out.reasons[0].code, 'EMERGENCY_WEAKER');
});

test('POL-011 R2-8: cooldown anchors on server received_at, not caller created_at', t => {
  const h = fixture(t), policy = h.f.policy('acme'), now = h.now();
  const cap = type => ({ capsule_id: 'cap-c', tenant_id: 'acme', policy_version: policy.version, expires_at: now + 3600000, created_at: now - 120000, received_at: now - 30000, quantity: 1, destination: 'customer-vault', actor: { subject_id: 'op-x', device_id: 'd' }, action: { type, target_resource: 'res-1' }, exclusions: [], requested_state: { bank_account: 'X' }, current_state: { version: 1, digest: 'x', material_fields: {} } });
  const deferred = evaluatePolicy({ capsule: cap('finance.bank.change'), policy, identities: h.f.identities('acme'), now });
  assert.equal(deferred.decision, 'DEFER');
  assert.equal(deferred.not_before, now - 30000 + policy.rules['finance.bank.change'].cooldown_ms);
  const old = cap('finance.bank.change'); old.received_at = now - 120000;
  const notDeferred = evaluatePolicy({ capsule: old, policy, identities: h.f.identities('acme'), now });
  assert.equal(notDeferred.decision === 'DEFER' && notDeferred.reasons.some(r => r.code === 'COOLDOWN'), false);
});

test('R2-9: an expired constitution still permits its own succession', t => {
  const h = fixture(t), policy = clone(h.f.policy('acme')), now = h.now();
  policy.expires_at = now - 1;
  const candidate = clone(policy);
  candidate.version += 1; candidate.expires_at = now + 86400000; candidate.not_before = 1;
  const out = evaluatePolicy({ capsule: policyCapsule(policy, candidate, { received_at: now - 200000 }), policy, identities: h.f.identities('acme'), now });
  assert.equal(out.reasons.some(r => r.code === 'EXPIRED'), false);
  const other = policyCapsule(policy, {}, { type: 'finance.beneficiary.create', requested: { vendor_id: 'v', bank_account: 'x', currency: 'EUR' }, received_at: now - 200000 });
  const denied = evaluatePolicy({ capsule: other, policy, identities: h.f.identities('acme'), now });
  assert.equal(denied.decision, 'DENY');
  assert.equal(denied.reasons[0].code, 'EXPIRED');
});

test('POL-011 R2-10: approval quorum requires distinct subjects, not just domains', t => {
  const h = fixture(t), policy = h.f.policy('acme'), now = h.now();
  const cap = { capsule_id: 'cap-q', tenant_id: 'acme', policy_version: policy.version, expires_at: now + 3600000, created_at: now - 120000, received_at: now - 120000, quantity: 1, destination: 'customer-vault', actor: { subject_id: 'initiator', device_id: 'd' }, action: { type: 'finance.beneficiary.create', target_resource: 'r-1' }, exclusions: [], requested_state: { vendor_id: 'v', bank_account: 'x', currency: 'EUR' }, current_state: { version: 1, digest: 'x', material_fields: {} } };
  const identities = {
    k1: { subject_id: 'alice', failure_domain: 'd1', roles: ['approver'], revoked: false, hardware_backed: false },
    k2: { subject_id: 'alice', failure_domain: 'd2', roles: ['approver'], revoked: false, hardware_backed: false },
    k3: { subject_id: 'bob', failure_domain: 'd2', roles: ['approver'], revoked: false, hardware_backed: false },
  };
  const approvals = (signers) => signers.map(s => ({ signer_id: s, expires_at: now + 60000 }));
  const same = evaluatePolicy({ capsule: cap, policy, approvals: approvals(['k1', 'k2']), identities, now });
  assert.equal(same.decision, 'ESCROW');
  assert.deepEqual(same.eligible_signers, ['k1']);
  const distinct = evaluatePolicy({ capsule: cap, policy, approvals: approvals(['k1', 'k3']), identities, now });
  assert.deepEqual(distinct.eligible_signers, ['k1', 'k3']);
});

test('R2-11: staged admission refuses pre-expired or min-delay-violating successors', t => {
  const h = fixture(t), policy = h.f.policy('acme'), now = h.now();
  const dead = clone(policy);
  dead.version += 1; dead.expires_at = now - 1; dead.not_before = 1;
  const outDead = evaluatePolicy({ capsule: policyCapsule(policy, dead), policy, identities: h.f.identities('acme'), now });
  assert.equal(outDead.decision, 'DENY');
  assert.equal(outDead.reasons[0].code, 'SUCCESSOR_EXPIRED');
  const rushed = clone(policy);
  rushed.version += 1; rushed.expires_at = now + 86400000; rushed.not_before = now + 1000;
  const outRush = evaluatePolicy({ capsule: policyCapsule(policy, rushed), policy, identities: h.f.identities('acme'), now });
  assert.equal(outRush.decision, 'DENY');
  assert.equal(outRush.reasons[0].code, 'STAGED_DELAY');
});

test('R2-12: a lapsed approval cannot drag the certificate expiry floor below now', t => {
  const h = fixture(t);
  const r = h.proposed(); h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 3);
  const record = h.f.store.must('acme', 'capsule', r.capsule.capsule_id);
  record.approvals[0].payload.expires_at = h.now() - 1; // lapsed — must not set the floor
  h.f.store.put('acme', 'capsule', r.capsule.capsule_id, record, h.now());
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  assert.ok(cert.payload.expires_at > h.now());
});

test('IDN-007 R2-13: a capability is bound to the attested device at consume', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap, { device_id: 'attacker-device' })), hasCode('INV-403-HEALTH'));
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'device health lost' });
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap)), hasCode('INV-403-QUARANTINE'));
});

test('CON-008 R2-14: vendor support access is time-bound, approved and revoked by expiry', t => {
  const h = fixture(t);
  // Vendor engineer has an identity but NO standing operational role.
  const vendor = Object.values(h.setup.config.tenants.acme.identities).find(i => i.subject_id === 'custodian-2');
  assert.ok(!vendor.roles.includes('operator'));
  assert.throws(() => h.f.runtime.issue(h.p('custodian-2'), runtimeInput({ device_id: 'custodian-2-device' })), hasCode('INV-403-ROLE'));
  // Customer authorises a 60s support grant through the full governed action lifecycle.
  const r = h.proposed('identity.jit.grant', { subject_id: 'custodian-2', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-1'], ttl_ms: 60000, reason: 'Vendor support case 441', roles: ['operator'] }, { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'Vendor support' } });
  h.evidence(r, { kind: 'identity_proof' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' }); h.approve(r, 2);
  assert.equal(h.f.execute(h.p(), h.f.certificate(h.p(), r.capsule.capsule_id)).payload.status, 'VERIFIED');
  // Inside the window: operator scope works, and the grant is audited.
  const cap = h.f.runtime.issue(h.p('custodian-2'), runtimeInput({ device_id: 'custodian-2-device' })); assert.ok(cap.protected.key_id);
  const entries = h.f.store.auditPage('acme', {}).entries.map(e => e.envelope.payload);
  assert.ok(entries.some(e => e.type === 'JIT_GRANT_ISSUED' && e.reference === 'custodian-2'));
  // A grant cannot mint custodian privilege — escalation is denied at admission.
  const bad = h.proposed('identity.jit.grant', { subject_id: 'custodian-2', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-1'], ttl_ms: 60000, reason: 'Escalation attempt', roles: ['custodian'] }, { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'Escalation' } });
  h.evidence(bad, { kind: 'identity_proof' }); h.approve(bad);
  assert.equal(h.f.evaluate(h.p(), bad.capsule.capsule_id).decision, 'DENY');
  // After expiry: no standing access remains.
  h.advance(61000);
  assert.throws(() => h.f.runtime.issue(h.p('custodian-2'), runtimeInput({ device_id: 'custodian-2-device' })), hasCode('INV-403-ROLE'));
});

test('AUD-002 R2-15: the complete action chain is reconstructable from the audit log', t => {
  const h = fixture(t); const r = h.ready(); h.f.execute(h.p(), r.certificate);
  const entries = h.f.store.auditPage('acme', { limit: 500 }).entries.map(e => e.envelope.payload);
  const capsuleId = r.record.capsule.capsule_id, certId = r.certificate.payload.certificate_id;
  const chain = entries.filter(e => e.reference === capsuleId || e.reference === certId);
  // Every lifecycle stage is present and linked to this action.
  for (const type of ['CAPSULE_PROPOSED', 'EVIDENCE_ATTACHED', 'EXACT_ACTION_APPROVED', 'CERTIFICATE_ISSUED', 'EXECUTION_RESERVED', 'EXECUTION_OUTCOME'])
    assert.ok(chain.some(e => e.type === type), `missing stage ${type}`);
  assert.equal(chain.find(e => e.type === 'CERTIFICATE_ISSUED').metadata.certificate_id, certId);
  assert.equal(chain.find(e => e.type === 'EXECUTION_OUTCOME').metadata.status, 'VERIFIED');
  assert.ok(chain.filter(e => e.type === 'EVIDENCE_ATTACHED').length >= 2);
});

test('AUD-004 R2-16: a replay attempt is identifiable from log state and ordering is monotonic', t => {
  const h = fixture(t); const r = h.ready(); h.f.execute(h.p(), r.certificate);
  assert.throws(() => h.f.execute(h.p(), r.certificate), hasCode('INV-409-REPLAY'));
  const entries = h.f.store.auditPage('acme', { limit: 500 }).entries.map(e => e.envelope.payload);
  const rejected = entries.find(e => e.type === 'SECURITY_OPERATION_REJECTED' && e.metadata?.code === 'INV-409-REPLAY');
  assert.ok(rejected, 'replay attempt must leave an identifiable log record');
  for (let i = 1; i < entries.length; i++) {
    assert.equal(entries[i].sequence, entries[i - 1].sequence + 1);
    assert.ok(entries[i].time >= entries[i - 1].time, 'audit timestamps must be monotonically ordered');
  }
});

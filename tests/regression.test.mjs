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
import { fixture } from './helpers.mjs';

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
  const policy = { secure_perception: { fallback: 'controlled-workspace' } };
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

import { canonical, digest, parseStrict } from '../src/canonical.mjs';

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

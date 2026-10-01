// w24-crypto wave regression tests — attestation binding (F1), vault
// admission (F2/F3), protected-header scalars (F4), ciphertext encoding
// (F5), MAC compares (F6), invisible chars (F7), shred guard (F8),
// nonce namespace (F9).
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fixture, hasCode } from './helpers.mjs';
import { KeyVault, verifyAttestation } from '../src/keystore.mjs';
import { generateKey, signed, verifySigned, signSuite, encrypt, decrypt } from '../src/crypto.mjs';
import { canonical } from '../src/canonical.mjs';
import { text } from '../src/schema.mjs';

const vault = () => new KeyVault(randomBytes(32).toString('base64url'));

// ── F1: key attestations are time/tenant/nonce/liveness bound ─────────

test('w24-crypto F1a: attest binds tenant, window and nonce; fresh artifact verifies', () => {
  const v = vault();
  const k = v.generate(['audit'], { tenant_id: 'acme' });
  const now = 1800000000000;
  const att = v.attest(k.key_id, { now, ttl_ms: 60000, nonce: 'ch-1' });
  assert.equal(att.payload.tenant_id, 'acme');
  assert.equal(att.payload.issued_at, now);
  assert.equal(att.payload.expires_at, now + 60000);
  assert.equal(att.payload.nonce, 'ch-1');
  const pl = verifyAttestation(att, v.attestorPublicKeys(), { now: now + 1, nonce: 'ch-1', tenant_id: 'acme', vault: v });
  assert.equal(pl.subject_key_id, k.key_id);
});

test('w24-crypto F1b: an expired attestation fails closed', () => {
  const v = vault();
  const k = v.generate(['audit'], { tenant_id: 'acme' });
  const att = v.attest(k.key_id, { now: 1800000000000, ttl_ms: 60000 });
  assert.throws(() => verifyAttestation(att, v.attestorPublicKeys(), { now: 1800000000000 + 60001 }), hasCode('INV-401-ATTESTATION'));
});

test('w24-crypto F1c: nonce and tenant pins reject foreign artifacts', () => {
  const v = vault();
  const k = v.generate(['audit'], { tenant_id: 'acme' });
  const att = v.attest(k.key_id, { now: 1800000000000, ttl_ms: 60000, nonce: 'mine' });
  assert.throws(() => verifyAttestation(att, v.attestorPublicKeys(), { now: 1800000000001, nonce: 'theirs' }), hasCode('INV-401-ATTESTATION'));
  assert.throws(() => verifyAttestation(att, v.attestorPublicKeys(), { now: 1800000000001, tenant_id: 'globex' }), hasCode('INV-401-ATTESTATION'));
});

test('w24-crypto F1d: a revoked subject key fails the vault liveness check', () => {
  const v = vault();
  const k = v.generate(['audit'], { tenant_id: 'acme' });
  const att = v.attest(k.key_id, { now: 1800000000000, ttl_ms: 600000 });
  v.revoke(k.key_id);
  // Signature still verifies against attestor keys, but the vault-aware
  // path refuses the dead subject.
  assert.throws(() => verifyAttestation(att, v.attestorPublicKeys(), { now: 1800000000001, vault: v }), hasCode('INV-401-ATTESTATION'));
});

// ── F2/F3: importKey/generate admission parity ─────────────────────────

test('w24-crypto F2: importKey validates id, purpose and tenant like generate', () => {
  const v = vault();
  const a = generateKey();
  assert.throws(() => v.importKey({ key_id: 5, public_key: a.public_key, private_key: a.private_key }, ['audit']), hasCode('INV-400-SCHEMA'));
  assert.throws(() => v.importKey({ key_id: 'a/b', public_key: a.public_key, private_key: a.private_key }, ['audit']), hasCode('INV-400-SCHEMA'));
  assert.throws(() => v.importKey({ key_id: 'imp-1', public_key: a.public_key, private_key: a.private_key }, undefined), hasCode('INV-400-SCHEMA'));
  assert.throws(() => v.importKey({ key_id: 'imp-2', public_key: a.public_key, private_key: a.private_key }, ['audit'], { tenant_id: { t: 1 } }), hasCode('INV-400-SCHEMA'));
  assert.doesNotThrow(() => v.importKey({ key_id: 'imp-3', public_key: a.public_key, private_key: a.private_key }, ['audit'], { tenant_id: 'acme' }));
});

test('w24-crypto F3: reserved ids and namespace pollution are refused in both paths', () => {
  const v = vault();
  const a = generateKey();
  for (const bad of ['attestor', 'a/b', 'x y']) {
    assert.throws(() => v.generate(['audit'], { key_id: bad }), hasCode('INV-400-SCHEMA'), `generate(${bad})`);
    assert.throws(() => v.importKey({ key_id: bad, public_key: a.public_key, private_key: a.private_key }, ['audit']), hasCode('INV-400-SCHEMA'), `importKey(${bad})`);
  }
  // A numeric tenant binding is refused on both paths.
  assert.throws(() => v.generate(['audit'], { tenant_id: 5 }), hasCode('INV-400-SCHEMA'));
});

// ── F4: protected-header fields must be scalar ─────────────────────────

test('w24-crypto F4: array-coerced suite and key_id never reach verification', () => {
  const k = generateKey();
  const payload = { note: 'x' };
  for (const h of [
    { profile: 'IF-CJSON-1', suite: ['Ed25519'], key_id: k.key_id, purpose: 'p' },
    { profile: 'IF-CJSON-1', suite: 'Ed25519', key_id: [k.key_id], purpose: 'p' },
  ]) {
    // A correctly-signed malleated header must still be refused — the wire
    // schema is stricter than the coercion ToPropertyKey would allow.
    const env = { protected: h, payload, signature: signSuite('Ed25519', Buffer.from(canonical({ protected: h, payload })), k.private_key) };
    assert.throws(() => verifySigned(env, { [k.key_id]: { public_key: k.public_key } }, 'p'), hasCode('INV-401-SIGNATURE'));
  }
});

// ── F5: decrypt admits only canonical ciphertext spellings ─────────────

test('w24-crypto F5: malleated ciphertext spellings are refused', () => {
  const key = randomBytes(32);
  const ct = encrypt('secret', key, 'aad/1');
  for (const bad of [`${ct}.junk`, `${ct}.`, `${ct}..`, `${ct}=`, `${ct.split('.')[0]}!.${ct.split('.').slice(1).join('.')}`, 5, null]) {
    assert.throws(() => decrypt(bad, key, 'aad/1'), hasCode('INV-400-SCHEMA'), JSON.stringify(bad));
  }
  assert.equal(decrypt(ct, key, 'aad/1'), 'secret');
});

// ── F6: keyed-MAC compares are constant-time everywhere ────────────────

test('w24-crypto F6: every keyed-MAC compare routes through ctEqual', () => {
  const issuerd = readFileSync('src/issuerd.mjs', 'utf8');
  assert.match(issuerd, /ctEqual\(logMac\(rest\), d\)/);
  const fabric = readFileSync('src/fabric.mjs', 'utf8');
  assert.doesNotMatch(fabric, /revocationDigests\.get\([^)]*\) \?\? null\) ===/);
});

// ── F7: text() refuses invisible/format characters ─────────────────────

test('w24-crypto F7: format characters outside the old blocklist are refused', () => {
  for (const c of ['a­min', 'a᠎min', 'a؜min', 'a͏min', 'aᅟmin', 'a︀min', 'a\u{1BCA0}min', 'a\u{1D173}min', 'a\u{E0100}min']) {
    assert.throws(() => text(c, 'field'), hasCode('INV-400-SCHEMA'), JSON.stringify(c));
  }
  assert.equal(text('ordinary purpose', 'field'), 'ordinary purpose');
});

// ── F8: shred applies the address guard ────────────────────────────────

test('w24-crypto F8: shred refuses a non-string id instead of erasing nothing', t => {
  const h = fixture(t);
  assert.throws(() => h.f.store.shred('acme', 'capsule', 5), hasCode('INV-400-SCHEMA'));
});

// ── F9: capsule nonces cannot squat foreign namespaces ─────────────────

test('w24-crypto F9: a colon-bearing nonce is refused at proposal admission', t => {
  const h = fixture(t);
  assert.throws(() => h.proposed('finance.beneficiary.create', { vendor_id: 'v-n', bank_account: 'TESTBANK000009', currency: 'EUR' }, { nonce: 'perception:deadbeefdeadbeef' }), hasCode('INV-400-SCHEMA'));
});

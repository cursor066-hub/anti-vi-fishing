import test from 'node:test';
import http from 'node:http';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomUUID, randomBytes } from 'node:crypto';
import { fixture, hasCode, installPolicy, runtimeInput } from './helpers.mjs';
import { parseStrict, canonical, digest } from '../src/canonical.mjs';
import { signed, verifySigned, generateKey } from '../src/crypto.mjs';
import { KeyVault, verifyAttestation } from '../src/keystore.mjs';
import { createServer } from '../src/server.mjs';

// w8-canonical auditor regressions — src/canonical.mjs, crypto.mjs,
// keystore.mjs, fabric.mjs evidence binding + revoke oracle + nonce
// namespaces, schema-layer type confusion (report w8-canonical.md).

test('CAN-F1: revocation existence oracle is own-property only — prototype members cannot mint revocation records', t => {
  const h = fixture(t);
  for (const [kind, id] of [['issuer', 'toString'], ['key', 'valueOf'], ['token', 'constructor'], ['key', 'constructor']])
    assert.throws(() => h.f.revoke(h.p('security'), { kind, id, reason: 'phantom' }), hasCode('INV-404-NOT-FOUND'), `${kind}:${id}`);
  // '__proto__' fails identifier grammar even earlier — still never a record.
  assert.throws(() => h.f.revoke(h.p('security'), { kind: 'issuer', id: '__proto__', reason: 'phantom' }), hasCode('INV-400-SCHEMA'));
  // The kind dispatch itself is prototype-safe: 'constructor' is not a kind.
  assert.throws(() => h.f.revoke(h.p('security'), { kind: 'constructor', id: 'anything', reason: 'x' }), hasCode('INV-400-SCHEMA'));
  assert.equal(h.f.revoked('acme', 'issuer', 'constructor'), false);
  // Control: a real issuer id still revokes normally.
  const realIssuer = Object.keys(h.f.tenant('acme').issuers)[0];
  const env = h.f.revoke(h.p('security'), { kind: 'issuer', id: realIssuer, reason: 'rotated' });
  assert.ok(env.signature); assert.equal(h.f.revoked('acme', 'issuer', realIssuer), true);
});

test('CAN-F2: evidence binding on an inherited member can never be satisfied by a constant claim', t => {
  const h = fixture(t);
  const rec = h.proposed('finance.beneficiary.create', { vendor_id: 'vendor-1', bank_account: 'TESTBANK000002', currency: 'EUR' });
  // A hostile or buggy policy may bind a claim to a non-scalar path —
  // enforcement must fail closed, not compare '[object Object]'. The poisoned
  // constitution arrives through the governed amendment pipeline itself.
  installPolicy(h, p => { p.rules['finance.beneficiary.create'].evidence_bindings.ownership.fake_fn = 'requested_state.toString'; });
  const payload = { evidence_id: randomUUID(), tenant_id: 'acme', capsule_digest: rec.capsule_digest, kind: 'ownership', content_digest: digest({ x: 1 }), acquired_at: h.now(), expires_at: h.now() + 600000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 't', retention_until: h.now() + 660000, claims: { account: 'TESTBANK000002', fake_fn: 'function toString() { [native code] }' } };
  const envelope = signed(payload, h.setup.issuerKeys.acme.bank, 'evidence');
  assert.throws(() => h.f.attachEvidence(h.p('operator'), rec.capsule.capsule_id, envelope), hasCode('INV-403-SCOPE'));
});

test('CAN-F2b: evidence binding on an object-valued leaf is refused at the governance gate', t => {
  const h = fixture(t);
  // The hardening is upstream of enforcement: validatePolicy refuses to even
  // install a constitution binding a claim to a non-scalar leaf.
  assert.throws(() => installPolicy(h, p => { p.rules['finance.beneficiary.create'].evidence_bindings.ownership.fake_obj = 'requested_state'; }), hasCode('INV-400-SCHEMA'));
  // And a non-scalar claim is schema-invalid at envelope verify regardless.
  const rec = h.proposed('finance.beneficiary.create', { vendor_id: 'vendor-1', bank_account: 'TESTBANK000002', currency: 'EUR' });
  const bad = { evidence_id: randomUUID(), tenant_id: 'acme', capsule_digest: rec.capsule_digest, kind: 'ownership', content_digest: digest({ x: 1 }), acquired_at: h.now(), expires_at: h.now() + 600000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 't', retention_until: h.now() + 660000, claims: { account: 'TESTBANK000002', fake_obj: { entirely: 'different' } } };
  assert.throws(() => h.f.attachEvidence(h.p('operator'), rec.capsule.capsule_id, signed(bad, h.setup.issuerKeys.acme.bank, 'evidence')), hasCode('INV-400-SCHEMA'));
});

test('CAN-F3: verifyAttestation shares verifySigned strictness — extra keys, malleated encoding, prototype key_id', () => {
  const vault = new KeyVault(randomBytes(32).toString('base64url'));
  const att = vault.attest(vault.generate('audit').key_id);
  assert.ok(verifyAttestation(att, vault.attestorPublicKeys()).subject_key_id);
  // Extra unsigned envelope member.
  assert.throws(() => verifyAttestation({ ...att, unsigned_extra: 1 }, vault.attestorPublicKeys()), hasCode('INV-401-SIGNATURE'));
  // Padding-bit malleation of the signature decodes to the same bytes —
  // still not the canonical encoding.
  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const mut = { ...att, signature: att.signature.slice(0, -1) + B64[B64.indexOf(att.signature.at(-1)) ^ 1] };
  assert.throws(() => verifyAttestation(mut, vault.attestorPublicKeys()), hasCode('INV-401-SIGNATURE'));
  // Inherited-member key_id resolves nothing.
  const bad = { ...att, protected: { ...att.protected, key_id: '__proto__' } };
  assert.throws(() => verifyAttestation(bad, vault.attestorPublicKeys()), hasCode('INV-401-SIGNATURE'));
  // Malformed signature type surfaces as INV-401, not a raw TypeError.
  assert.throws(() => verifyAttestation({ ...att, signature: 5 }, vault.attestorPublicKeys()), hasCode('INV-401-SIGNATURE'));
});

test('CAN-F4: every body the parser admits fits inside the envelope wrap — depth 31 in, 32 out', () => {
  const deep31 = JSON.parse('['.repeat(31) + '1' + ']'.repeat(31));
  assert.doesNotThrow(() => parseStrict('['.repeat(31) + '1' + ']'.repeat(31)));
  assert.throws(() => parseStrict('['.repeat(32) + '1' + ']'.repeat(32)), hasCode('INV-400-SCHEMA'));
  // The admitted depth-31 body signs and verifies inside the envelope.
  const key = generateKey();
  const env = signed(deep31, key, 'evidence');
  assert.deepEqual(verifySigned(env, { [key.key_id]: { public_key: key.public_key } }, 'evidence'), deep31);
});

test('CAN-F5: schema-layer type confusion surfaces as INV-400-SCHEMA, never 500/503', t => {
  const h = fixture(t);
  assert.throws(() => h.f.runtime.issue(h.p(), runtimeInput({ transforms: { name: null } })), hasCode('INV-400-SCHEMA'));
  assert.throws(() => h.f.runtime.issue(h.p(), runtimeInput({ transforms: { name: 'x' } })), hasCode('INV-400-SCHEMA'));
  h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-typed', purpose: 'key.recovery', threshold: 2, custodians: ['custodian-1', 'custodian-2'], valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  assert.throws(() => h.f.splitCeremonySecret(h.p('security'), 'cer-typed', 12345), hasCode('INV-400-SCHEMA'));
  assert.throws(() => h.f.splitCeremonySecret(h.p('security'), 'cer-typed', { toString: 'x' }), hasCode('INV-400-SCHEMA'));
});

test('CAN-F6: canonical() rejects every Object.prototype member name as a key', () => {
  for (const k of [...Object.getOwnPropertyNames(Object.prototype), 'prototype', 'watch', 'unwatch'])
    assert.throws(() => canonical({ [k]: 1 }), hasCode('INV-400-SCHEMA'), k);
  assert.throws(() => parseStrict('{"toString":1}'), hasCode('INV-400-SCHEMA'));
  assert.equal(canonical({ id: 'toString' }), '{"id":"toString"}'); // values are unaffected
  // -0 is a number-grammar violation even though it cannot be expressed as a
  // vectors-file input (JSON.stringify writes it as 0) — pinned here instead.
  assert.throws(() => canonical(-0), hasCode('INV-400-SCHEMA'));
  assert.throws(() => canonical({ n: -0 }), hasCode('INV-400-SCHEMA'));
});

test('CAN-F7: committed parse vectors and envelope rejection vectors are honoured by the shipped implementation', () => {
  for (const v of JSON.parse(readFileSync('vectors/parse-vectors.json', 'utf8')).vectors) {
    if (v.expect === 'accept') assert.doesNotThrow(() => parseStrict(v.text), v.name);
    else assert.throws(() => parseStrict(v.text), hasCode('INV-400-SCHEMA'), v.name);
  }
  for (const v of JSON.parse(readFileSync('vectors/envelope-vectors.json', 'utf8')).vectors) {
    if (v.expect !== 'reject') continue;
    assert.throws(() => verifySigned(v.envelope, { [v.key_id]: { public_key: v.public_key } }, v.purpose), hasCode('INV-401-SIGNATURE'), v.name);
  }
});

test('CAN-F10: evidence claims must be a scalar map — strings, numbers and arrays are schema-invalid', t => {
  const h = fixture(t), rec = h.proposed();
  for (const claims of ['text', [], 5]) {
    const payload = { evidence_id: randomUUID(), tenant_id: 'acme', capsule_digest: rec.capsule_digest, kind: 'ownership', content_digest: digest({ x: 1 }), acquired_at: h.now(), expires_at: h.now() + 600000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 't', retention_until: h.now() + 660000, claims };
    assert.throws(() => h.f.attachEvidence(h.p('operator'), rec.capsule.capsule_id, signed(payload, h.setup.issuerKeys.acme.bank, 'evidence')), hasCode('INV-400-SCHEMA'), JSON.stringify(claims));
  }
});

test('CAN-F11: prototype-member suite names never satisfy the suite allowlist', () => {
  const key = generateKey(), env = signed({ a: 1 }, key, 'evidence');
  for (const suite of ['__proto__', 'constructor', 'hasOwnProperty'])
    assert.throws(() => verifySigned({ ...env, protected: { ...env.protected, suite } }, { [key.key_id]: { public_key: key.public_key } }, 'evidence'), hasCode('INV-401-SIGNATURE'), suite);
});

// HTTP-level nonce namespace proof (F8 + F12): '-0' rejects in the query
// grammar, and a capsule nonce cannot squat on a perception attestation.
async function httpFixture(t) {
  const h = fixture(t), app = createServer(h.f, { port: 0, origin: 'http://127.0.0.1:17777' }); await app.listen(); t.after(() => app.close());
  const port = app.server.address().port;
  const request = (path, { method = 'GET', body, token = h.setup.credentials.acme.operator } = {}) => new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
    const req = http.request({ host: '127.0.0.1', port, path, method, headers: { Host: '127.0.0.1:17777', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(payload === undefined ? {} : { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }) } }, response => {
      const chunks = []; response.on('data', c => chunks.push(c)); response.on('end', () => { let data; try { data = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { data = null; } resolve({ status: response.statusCode, data }); });
    }); req.on('error', reject); req.end(payload);
  });
  return { ...h, request, app };
}

test('CAN-F8: query grammar rejects -0 exactly like the body grammar', async t => {
  const h = await httpFixture(t);
  assert.equal((await h.request('/v1/action-capsules?limit=-0')).status, 400);
  assert.equal((await h.request('/v1/action-capsules?limit=-0&offset=-0')).status, 400);
  assert.equal((await h.request('/v1/action-capsules?limit=1')).status, 200);
});

test('CAN-F12: capsule nonces and perception attestation nonces live in separate namespaces', async t => {
  const h = await httpFixture(t);
  const nonce = 'a'.repeat(64); // a 64-hex string is a legal capsule nonce
  h.proposed('finance.beneficiary.create', { vendor_id: 'vendor-1', bank_account: 'TESTBANK000002', currency: 'EUR' }, { nonce });
  // The capsule nonce is stored under its own prefix.
  const rows = h.f.store.db.prepare('SELECT nonce FROM nonces WHERE tenant=?').all('acme').map(r => r.nonce);
  assert.ok(rows.includes('capsule:' + nonce), JSON.stringify(rows));
  // A perception attestation carrying the SAME raw nonce must still open —
  // the replay namespaces do not collide (previously INV-409-REPLAY).
  const component = h.setup.componentSecrets.acme['secure-view-acme'];
  const session = await h.request('/v1/secure-perception/sessions', { method: 'POST', body: { attestation: component.attest(nonce, h.now() + 300000) } });
  assert.equal(session.status, 201, JSON.stringify(session.data));
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { canonical, digest, parseStrict } from '../src/canonical.mjs';
import { signed, generateKey, verifySigned, encrypt, decrypt } from '../src/crypto.mjs';
import { randomBytes } from 'node:crypto';

test('ACT-001 ACT-003: stable field order and exact material binding', () => {
  assert.equal(canonical({ b: 2, a: 'café' }), '{"a":"café","b":2}'); assert.equal(digest({ a: 1, b: 2 }), digest({ b: 2, a: 1 })); assert.notEqual(digest({ amount: 10 }), digest({ amount: 11 }));
});
test('ACT-007: ambiguous encodings and unknown types rejected', () => {
  for (const value of [NaN, Infinity, -0, 1.1, 9007199254740992, undefined, new Date(), { a: undefined }, 'café', '\uD800', { 'unsafe/key': 1 }]) assert.throws(() => canonical(value));
});
test('ACT-003: strict parser rejects duplicate keys, trailing values and prototype keys', () => {
  for (const value of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"__proto__":{}}', '[1,]', '{"a":1,}', '{}{}', '{"a":NaN}', '01', '"unterminated', ' '.repeat(10)]) assert.throws(() => parseStrict(value), value);
});
test('ACT-003: 2000 deterministic canonical round trips with integer and Unicode vectors', () => {
  let seed = 0x12345678; const random = () => { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; return seed >>> 0; };
  for (let i = 0; i < 2000; i++) { const value = { index: i, values: [random(), Boolean(random() % 2), null, 'Žižek 🛡 café'], nested: { x: random() } }; assert.equal(canonical(parseStrict(canonical(value))), canonical(value)); }
});
test('ACT-007: oversized nesting and bodies rejected', () => { assert.throws(() => parseStrict('['.repeat(40) + '0' + ']'.repeat(40))); assert.throws(() => parseStrict(' '.repeat(1048577))); });
test('COM-002 KEY-007: Ed25519 domain-separated signatures reject every altered field', () => {
  const key = generateKey(), pubs = { [key.key_id]: key }, value = { tenant: 'acme', amount: 10 };
  const env = signed(value, key, 'action-certificate'); assert.deepEqual(verifySigned(env, pubs, 'action-certificate'), value);
  assert.throws(() => verifySigned(env, pubs, 'audit')); assert.throws(() => verifySigned({ ...env, payload: { ...value, amount: 11 } }, pubs, 'action-certificate'));
  assert.throws(() => verifySigned(env, {}, 'action-certificate')); assert.throws(() => verifySigned(env, { [key.key_id]: { ...key, revoked: true } }, 'action-certificate'));
});
test('AUD-003: AES-GCM binds ciphertext to tenant, record id and key', () => {
  const key = randomBytes(32), cipher = encrypt({ account: 'secret-test-account' }, key, 'acme/record/1');
  assert.deepEqual(decrypt(cipher, key, 'acme/record/1'), { account: 'secret-test-account' }); assert.throws(() => decrypt(cipher, key, 'globex/record/1')); assert.throws(() => decrypt(cipher, randomBytes(32), 'acme/record/1'));
});

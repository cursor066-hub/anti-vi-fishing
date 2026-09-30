import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { canonical, parseStrict } from '../src/canonical.mjs';
import { verifySigned } from '../src/crypto.mjs';

const cv = JSON.parse(readFileSync('vectors/canonical-vectors.json', 'utf8'));
const ev = JSON.parse(readFileSync('vectors/envelope-vectors.json', 'utf8'));

test('IF-CJSON-1: every recorded vector produces the recorded output', () => {
  for (const v of cv.vectors) {
    if (v.canonical === null) assert.throws(() => canonical(v.input), undefined, v.name);
    else assert.equal(canonical(v.input), v.canonical, v.name);
  }
});

test('IF-ENVELOPE-1: recorded envelopes verify under node:crypto', () => {
  for (const v of ev.vectors) {
    const env = v.envelope;
    const payload = verifySigned(env, { [v.key_id]: { public_key: v.public_key } }, v.purpose);
    assert.deepEqual(payload, env.payload);
  }
});

test('parseStrict: rejects every duplicate-key injection', () => {
  assert.throws(() => parseStrict('{"a":1,"a":2}'));
  assert.throws(() => parseStrict('{"a":{"b":1,"b":2}}'));
  assert.throws(() => parseStrict('{"a":1,"b":2,"a":3}'));
});

test('IF-CJSON-1: non-serialisable edge values reject (cannot appear on the wire)', () => {
  assert.throws(() => canonical(-0));
  assert.throws(() => canonical(NaN));
  assert.throws(() => canonical(Infinity));
  assert.throws(() => canonical('lone\uD800surrogate'));
  assert.throws(() => canonical({ n: 1n }));
  assert.throws(() => canonical(Symbol('x')));
});

test('parseStrict: envelope text still parses and verifies end-to-end', () => {
  const env = ev.vectors[0].envelope;
  const reparsed = parseStrict(JSON.stringify(env));
  assert.equal(canonical(verifySigned(reparsed, { [ev.vectors[0].key_id]: { public_key: ev.vectors[0].public_key } }, ev.vectors[0].purpose)), canonical(env.payload));
});

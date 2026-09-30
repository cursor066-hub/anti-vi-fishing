// Generates IF-CJSON-1 canonicalisation + Ed25519 envelope conformance vectors.
// The vectors are verified by scripts/verify-vectors.py (Python) and
// scripts/verify-vectors-webcrypto.mjs (WebCrypto), anchoring the wire format
// across three independent implementations. Keys in vectors/keys.json are
// generated for test vectors only — they protect nothing.
import { writeFileSync, mkdirSync, existsSync, readFileSync } from 'node:fs';
import { canonical } from '../src/canonical.mjs';
import { generateKey, signed } from '../src/crypto.mjs';

const out = 'vectors';
mkdirSync(out, { recursive: true });

const inputs = [
  { name: 'empty-object', input: {} },
  { name: 'empty-array', input: [] },
  { name: 'null', input: null },
  { name: 'booleans', input: [true, false] },
  { name: 'integers', input: [0, 1, -1, 9007199254740991, -9007199254740991] },
  { name: 'sorted-keys', input: { b: 1, a: 2, 'a.1': 3, 'a:1': 4, '_z': 5 } },
  { name: 'nested', input: { x: [{ y: { z: [1, 'two', null] } }], a: {} } },
  { name: 'nfc-unicode', input: { s: 'cafe\u0301'.normalize('NFC'), cjk: '' } },
  { name: 'escapes', input: { s: 'q"b\\c\t\n\u0001end' } },
  { name: 'negative-float', input: { n: -0.5 }, error: true },
  { name: 'float', input: { n: 1.5 }, error: true },
  { name: 'unsafe-int', input: { n: 9007199254740993 }, error: true },
  { name: 'non-nfc-string', input: { s: 'cafe\u0301' }, error: true },
  { name: 'proto-key', input: JSON.parse('{"x":1,"__proto__":2}'), error: true },
  { name: 'non-ascii-key', input: { 'clé': 1 }, error: true },
];
const canonicalVectors = inputs.map(v => {
  try { return { name: v.name, input: v.input, canonical: canonical(v.input) }; }
  catch (e) { return { name: v.name, input: v.input, canonical: null, error: v.error === true ? e.code ?? 'IF-CJSON' : (() => { throw e; })() }; }
});
for (const v of canonicalVectors) if (!v.error && !v.canonical) throw new Error(`Vector ${v.name} unexpectedly failed`);

// Committed vector keys are reused when present so Ed25519 vectors are
// byte-stable across regenerations — the committed vector file is then
// exactly what CI verifies (release-audit H2). Fresh keys are minted only
// on a first run. ECDSA signatures remain random per sign; the ES256 file
// is verified at its committed state rather than diffed.
function loadKeys() {
  const path = 'vectors/keys.json';
  if (!existsSync(path)) return null;
  const stored = JSON.parse(readFileSync(path, 'utf8')).keys;
  if (stored.length >= 3) return { ed: [{ ...stored[0], suite: 'Ed25519' }, { ...stored[1], suite: 'Ed25519' }], es256: { ...stored[2], suite: 'ES256' } };
  return null;
}
const existing = loadKeys();
const keys = existing?.ed ?? [generateKey(), generateKey()];
const payloads = [
  { name: 'capability-shaped', purpose: 'capability', payload: { capability_id: 'cap-001', subject_id: 'operator-1', action: 'data.read', columns: ['id', 'name'], row_ids: ['row-1'], max_cost: 10, issued_at: 1700000000000, expires_at: 1700000060000 } },
  { name: 'evidence-shaped', purpose: 'evidence', payload: { evidence_id: 'ev-001', kind: 'ownership', claim: 'supports', capsule_digest: 'a'.repeat(64), subject_id: 'acct-1', acquired_at: 1700000000000, issuer_version: '1.0.0', claims: { account: 'TESTBANK000001', verified_at: 1700000000000 } } },
  { name: 'unicode-payload', purpose: 'evidence', payload: { note: 'cafe\u0301'.normalize('NFC') + ' ', nested: { deep: [{ v: 1 }, { v: -2 }] } } },
  { name: 'empty-payload', purpose: 'capability', payload: {} },
];
const envelopeVectors = payloads.map((v, i) => {
  const key = keys[i % keys.length];
  return { name: v.name, purpose: v.purpose, key_id: key.key_id, public_key: key.public_key, envelope: signed(v.payload, key, v.purpose) };
});

const es256Key = existing?.es256 ?? generateKey('ES256');
const es256Vectors = payloads.slice(0, 2).map(v => ({ name: `es256-${v.name}`, purpose: v.purpose, key_id: es256Key.key_id, public_key: es256Key.public_key, envelope: signed(v.payload, es256Key, v.purpose) }));

writeFileSync(`${out}/canonical-vectors.json`, JSON.stringify({ format: 'IF-CJSON-1 conformance vectors v1', vectors: canonicalVectors }, null, 1) + '\n');
writeFileSync(`${out}/envelope-vectors.json`, JSON.stringify({ format: 'IF-ENVELOPE-1 conformance vectors v1', message: 'canonical({protected, payload}) UTF-8', vectors: envelopeVectors }, null, 1) + '\n');
writeFileSync(`${out}/envelope-es256-vectors.json`, JSON.stringify({ format: 'IF-ENVELOPE-1 conformance vectors v1', message: 'canonical({protected, payload}) UTF-8; ECDSA P-256/SHA-256 signatures in IEEE-P1363 form', vectors: es256Vectors }, null, 1) + '\n');
writeFileSync(`${out}/keys.json`, JSON.stringify({ warning: 'TEST VECTOR KEYS ONLY — generated solely for cross-implementation conformance vectors; they protect nothing and must never be used operationally', keys: [...keys, es256Key].map(k => ({ key_id: k.key_id, public_key: k.public_key, private_key: k.private_key })) }, null, 1) + '\n');
console.log(`Wrote ${canonicalVectors.length} canonical + ${envelopeVectors.length} envelope vectors`);

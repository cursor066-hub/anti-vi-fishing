// Third-implementation conformance check: verifies the same envelope vectors
// through the WebCrypto API surface (crypto.subtle), which is a different
// Ed25519 verification path than node:crypto's sign/verify.
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { canonical } from '../src/canonical.mjs';

const subtle = webcrypto.subtle;
const spki = pem => Buffer.from(pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''), 'base64');
const b64url = s => Buffer.from(s, 'base64url');

const cv = JSON.parse(readFileSync('vectors/canonical-vectors.json', 'utf8'));
const ev = JSON.parse(readFileSync('vectors/envelope-vectors.json', 'utf8'));
let failed = 0;
for (const v of cv.vectors) {
  try { const got = canonical(v.input); if (got !== v.canonical || v.canonical === null) { failed++; console.log(`FAIL canonical/${v.name}`); } }
  catch { if (v.canonical !== null) { failed++; console.log(`FAIL canonical/${v.name} (threw)`); } }
}
for (const v of ev.vectors) {
  const env = v.envelope, message = Buffer.from(canonical({ protected: env.protected, payload: env.payload }));
  const key = await subtle.importKey('spki', spki(v.public_key), { name: 'Ed25519' }, false, ['verify']);
  const ok = await subtle.verify({ name: 'Ed25519' }, key, b64url(env.signature), message);
  if (!ok) { failed++; console.log(`FAIL webcrypto-signature/${v.name}`); }
  const tampered = Buffer.from(message); tampered[0] ^= 1;
  if (await subtle.verify({ name: 'Ed25519' }, key, b64url(env.signature), tampered)) { failed++; console.log(`FAIL webcrypto-tamper/${v.name}`); }
}
console.log(`webcrypto: ${cv.vectors.length} canonical + ${ev.vectors.length} envelope vectors, ${failed} failures`);

const ev2 = JSON.parse(readFileSync('vectors/envelope-es256-vectors.json', 'utf8'));
for (const v of ev2.vectors) {
  const env = v.envelope, message = Buffer.from(canonical({ protected: env.protected, payload: env.payload }));
  const key = await subtle.importKey('spki', spki(v.public_key), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const ok = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, b64url(env.signature), message);
  if (!ok) { failed++; console.log(`FAIL webcrypto-es256/${v.name}`); }
  const tampered = Buffer.from(message); tampered[0] ^= 1;
  if (await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, b64url(env.signature), tampered)) { failed++; console.log(`FAIL webcrypto-es256-tamper/${v.name}`); }
}
console.log(`webcrypto: ${ev2.vectors.length} ES256 envelope vectors, ${failed} total failures`);
process.exitCode = failed ? 1 : 0;

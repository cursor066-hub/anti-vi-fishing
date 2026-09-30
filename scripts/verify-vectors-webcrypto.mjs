// Third-implementation conformance check: verifies the same envelope vectors
// through the WebCrypto API surface (crypto.subtle), which is a different
// Ed25519/ECDSA verification path than node:crypto's sign/verify.
//
// The canonicalizer below is an independent reimplementation of IF-CJSON-1
// (mirroring scripts/verify-vectors.py rule-for-rule) — it deliberately does
// NOT import src/canonical.mjs, so a bug in the shipped canonicalizer cannot
// self-verify (release-audit H3). Three genuinely independent
// canonicalizers then exist: src/canonical.mjs (generator), this file, and
// the Python implementation.
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';

// ---- independent IF-CJSON-1 canonicalizer (no src/ imports) ----
const KEY_RE = /^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$/;
// Parity with src/canonical.mjs: every Object.prototype member name is a
// forbidden key (w8-canonical F6).
const FORBIDDEN = new Set(['__proto__', 'prototype', 'constructor', 'toString',
  'toLocaleString', 'valueOf', 'hasOwnProperty', 'isPrototypeOf',
  'propertyIsEnumerable', '__defineGetter__', '__defineSetter__',
  '__lookupGetter__', '__lookupSetter__', 'watch', 'unwatch']);
class CanonError extends Error {}
function escString(s) {
  let out = '"';
  for (const ch of s) {
    const o = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (ch === '\b') out += '\\b';
    else if (ch === '\t') out += '\\t';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\f') out += '\\f';
    else if (ch === '\r') out += '\\r';
    else if (o < 0x20) out += `\\u${o.toString(16).padStart(4, '0')}`;
    else if (o >= 0xD800 && o <= 0xDFFF && ch.length === 1) throw new CanonError('lone surrogate');
    else out += ch;
  }
  return out + '"';
}
function canon(value, depth = 0) {
  if (depth > 32) throw new CanonError('depth');
  if (value === null) return 'null';
  if (value === true || value === false) return value ? 'true' : 'false';
  if (typeof value === 'number') {
    // '-0' is not a canonical integer (w8-canonical F7).
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new CanonError('non-integer');
    return String(value);
  }
  if (typeof value === 'string') {
    if (value.normalize('NFC') !== value) throw new CanonError('non-NFC');
    for (let i = 0; i < value.length; i++) {
      const o = value.charCodeAt(i);
      if (o >= 0xD800 && o <= 0xDFFF) {
        if (o < 0xDC00 && i + 1 < value.length && value.charCodeAt(i + 1) >= 0xDC00 && value.charCodeAt(i + 1) <= 0xDFFF) { i++; continue; }
        throw new CanonError('surrogate');
      }
    }
    if (value.length > 65536) throw new CanonError('too long');
    return escString(value);
  }
  if (Array.isArray(value)) {
    if (value.length > 10000) throw new CanonError('array too long');
    return '[' + value.map(v => canon(v, depth + 1)).join(',') + ']';
  }
  if (value && typeof value === 'object') {
    const keys = Object.keys(value);
    if (keys.length > 256) throw new CanonError('object too large');
    for (const k of keys) if (!KEY_RE.test(k) || FORBIDDEN.has(k)) throw new CanonError('bad key');
    return '{' + keys.sort().map(k => `${escString(k)}:${canon(value[k], depth + 1)}`).join(',') + '}';
  }
  throw new CanonError('unsupported value');
}
// ---- end independent canonicalizer ----

const subtle = webcrypto.subtle;
const spki = pem => Buffer.from(pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''), 'base64');
const b64url = s => Buffer.from(s, 'base64url');

const cv = JSON.parse(readFileSync('vectors/canonical-vectors.json', 'utf8'));
const ev = JSON.parse(readFileSync('vectors/envelope-vectors.json', 'utf8'));
let failed = 0;
for (const v of cv.vectors) {
  try { const got = canon(v.input); if (got !== v.canonical || v.canonical === null) { failed++; console.log(`FAIL canonical/${v.name}`); } }
  catch { if (v.canonical !== null) { failed++; console.log(`FAIL canonical/${v.name} (threw)`); } }
}
async function verifyEnvelope(env, purpose, public_key) {
  // Mirrors verifySigned: exact 3-key envelope, exact 4-key protected
  // header, purpose binding, canonical base64url signature encoding.
  if (!env || Object.keys(env).sort().join() !== 'payload,protected,signature') return false;
  const h = env.protected;
  if (!h || Object.keys(h).sort().join() !== 'key_id,profile,purpose,suite') return false;
  if (h.profile !== 'IF-CJSON-1' || h.suite !== 'Ed25519' || h.purpose !== purpose) return false;
  if (typeof env.signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(env.signature)) return false;
  if (Buffer.from(env.signature, 'base64url').toString('base64url') !== env.signature) return false;
  const message = Buffer.from(canon({ protected: h, payload: env.payload }));
  const key = await subtle.importKey('spki', spki(public_key), { name: 'Ed25519' }, false, ['verify']);
  return subtle.verify({ name: 'Ed25519' }, key, b64url(env.signature), message);
}
for (const v of ev.vectors) {
  const env = v.envelope;
  if (v.expect === 'reject') {
    if (await verifyEnvelope(env, v.purpose, v.public_key)) { failed++; console.log(`FAIL webcrypto-rejection/${v.name}`); }
    continue;
  }
  if (!await verifyEnvelope(env, v.purpose, v.public_key)) { failed++; console.log(`FAIL webcrypto-signature/${v.name}`); continue; }
  const message = Buffer.from(canon({ protected: env.protected, payload: env.payload }));
  const key = await subtle.importKey('spki', spki(v.public_key), { name: 'Ed25519' }, false, ['verify']);
  const tampered = Buffer.from(message); tampered[0] ^= 1;
  if (await subtle.verify({ name: 'Ed25519' }, key, b64url(env.signature), tampered)) { failed++; console.log(`FAIL webcrypto-tamper/${v.name}`); }
}
console.log(`webcrypto: ${cv.vectors.length} canonical + ${ev.vectors.length} envelope vectors, ${failed} failures`);

const ev2 = JSON.parse(readFileSync('vectors/envelope-es256-vectors.json', 'utf8'));
for (const v of ev2.vectors) {
  const env = v.envelope, message = Buffer.from(canon({ protected: env.protected, payload: env.payload }));
  const key = await subtle.importKey('spki', spki(v.public_key), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const ok = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, b64url(env.signature), message);
  if (!ok) { failed++; console.log(`FAIL webcrypto-es256/${v.name}`); }
  const tampered = Buffer.from(message); tampered[0] ^= 1;
  if (await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, b64url(env.signature), tampered)) { failed++; console.log(`FAIL webcrypto-es256-tamper/${v.name}`); }
}
console.log(`webcrypto: ${ev2.vectors.length} ES256 envelope vectors, ${failed} total failures`);
// A truncated corpus must not pass: per-vector asserts alone would let a
// commit halve coverage undetected (w11-supply SC-10).
if (cv.vectors.length < 18 || ev.vectors.length < 11 || ev2.vectors.length < 2) { console.error(`FAIL webcrypto-corpus: truncated vector sets (canonical=${cv.vectors.length}, envelope=${ev.vectors.length}, es256=${ev2.vectors.length})`); process.exit(1); }
process.exitCode = failed ? 1 : 0;

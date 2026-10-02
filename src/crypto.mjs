import { generateKeyPairSync, createPrivateKey, createPublicKey, sign, verify, randomBytes, createCipheriv, createDecipheriv, timingSafeEqual } from 'node:crypto';
import { canonical, digest } from './canonical.mjs';
import { requireThat } from './errors.mjs';

// Constant-time equality for fixed-length secret comparisons (MACs,
// tokens, commitments). `===` exits on the first differing byte and leaks
// the match prefix; both inputs here are public-form strings/hex/base64
// whose lengths are fixed by construction (w11-timing LOW-1/2/3).
export const ctEqual = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
};
export const SUITES = {
  Ed25519: { curve: 'ed25519', namedCurve: null, hash: null, dsaEncoding: null },
  ES256: { curve: 'ec', namedCurve: 'P-256', hash: 'sha256', dsaEncoding: 'ieee-p1363' }
};
// P-256 group order n: ECDSA (r, s) and (r, n-s) are equivalent; canonical
// low-s is enforced on both sign and verify so signatures are non-malleable.
const P256_ORDER = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');
// KeyObject materialization is a pure function of the PEM — a rotated key
// always arrives as different text, so the object cannot go stale. The
// cache is bounded and self-evicting (oldest-insertion first) (w43-perf).
const KEY_OBJECTS = new Map();
const keyObject = (ctor) => (pem) => {
  const k = `${ctor.name}:${pem}`;
  let obj = KEY_OBJECTS.get(k);
  if (obj === undefined) {
    obj = ctor(pem);
    KEY_OBJECTS.set(k, obj);
    if (KEY_OBJECTS.size > 512) KEY_OBJECTS.delete(KEY_OBJECTS.keys().next().value);
  }
  return obj;
};
const privateKeyOf = keyObject(createPrivateKey), publicKeyOf = keyObject(createPublicKey);
export function signSuite(suite, message, privatePem) {
  const s = Object.hasOwn(SUITES, suite) ? SUITES[suite] : undefined;
  requireThat(s, 'INV-400-SCHEMA', 'Unsupported algorithm suite');
  const key = s.dsaEncoding ? { key: privateKeyOf(privatePem), dsaEncoding: s.dsaEncoding } : privateKeyOf(privatePem);
  const sig = sign(s.hash, message, key);
  if (s.dsaEncoding === 'ieee-p1363' && sig.length === 64) {
    const scalar = BigInt('0x' + sig.subarray(32).toString('hex'));
    if (scalar > P256_ORDER / 2n) {
      const low = P256_ORDER - scalar, out = Buffer.concat([sig.subarray(0, 32), Buffer.from(low.toString(16).padStart(64, '0'), 'hex')]);
      return out.toString('base64url');
    }
  }
  return sig.toString('base64url');
}
// P-256 group order n/2: ECDSA (r, s) and (r, n-s) are both valid for the
// same message, so low-s is the canonical form — high-s is rejected.
const P256_HALF_ORDER = BigInt('0x7FFFFFFF80000000FFFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8');
export function verifySuite(suite, message, publicPem, signature) {
  const s = Object.hasOwn(SUITES, suite) ? SUITES[suite] : undefined;
  if (!s) return false;
  if (s.dsaEncoding === 'ieee-p1363' && signature.length === 64) {
    const scalar = BigInt('0x' + signature.subarray(32).toString('hex'));
    if (scalar > P256_HALF_ORDER) return false;
  }
  const key = s.dsaEncoding ? { key: publicKeyOf(publicPem), dsaEncoding: s.dsaEncoding } : publicKeyOf(publicPem);
  return verify(s.hash, message, key, signature);
}
export function generateKey(suite = 'Ed25519') {
  const s = Object.hasOwn(SUITES, suite) ? SUITES[suite] : undefined;
  requireThat(s, 'INV-400-SCHEMA', 'Unsupported algorithm suite');
  const { privateKey, publicKey } = generateKeyPairSync(s.curve, s.namedCurve ? { namedCurve: s.namedCurve } : {});
  const pub = publicKey.export({ type: 'spki', format: 'pem' });
  return { key_id: digest({ public_key: pub }).slice(0, 32), public_key: pub, private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }), suite };
}
export function signed(payload, key, purpose) {
  const protectedHeader = { profile: 'IF-CJSON-1', suite: key.suite ?? 'Ed25519', key_id: key.key_id, purpose };
  const message = Buffer.from(canonical({ protected: protectedHeader, payload }));
  return { protected: protectedHeader, payload, signature: signSuite(protectedHeader.suite, message, key.private_key) };
}
export function verifySigned(envelope, publicKeys, purpose) {
  requireThat(envelope && Object.keys(envelope).sort().join() === 'payload,protected,signature', 'INV-401-SIGNATURE', 'Invalid signed envelope', 401);
  const h = envelope.protected;
  requireThat(h && Object.keys(h).sort().join() === 'key_id,profile,purpose,suite' && h.profile === 'IF-CJSON-1'
    && typeof h.key_id === 'string' && typeof h.suite === 'string' && typeof h.purpose === 'string',
    'INV-401-SIGNATURE', 'Unsupported signature context', 401);
  requireThat(Object.hasOwn(SUITES, h.suite) && h.purpose === purpose, 'INV-401-SIGNATURE', 'Unsupported signature context', 401);
  const key = Object.hasOwn(publicKeys ?? {}, h.key_id) ? publicKeys[h.key_id] : undefined;
  requireThat(key && !key.revoked, 'INV-401-SIGNATURE', 'Signer unavailable', 401);
  // An anchor that declares a suite pins it — the protected header is
  // attacker-writable and must not relabel the key's algorithm (supply F-L3).
  if (key.suite !== undefined) requireThat(key.suite === h.suite, 'INV-401-SIGNATURE', 'Envelope suite differs from the anchor-declared suite', 401);
  // Require canonical base64url: mutating unused padding bits must not
  // produce an accepted alternative encoding of the same signature.
  requireThat(typeof envelope.signature === 'string' && /^[A-Za-z0-9_-]{86}$/.test(envelope.signature)
    && Buffer.from(envelope.signature, 'base64url').toString('base64url') === envelope.signature, 'INV-401-SIGNATURE', 'Invalid signature encoding', 401);
  let ok = false;
  try { ok = verifySuite(h.suite, Buffer.from(canonical({ protected: h, payload: envelope.payload })), key.public_key, Buffer.from(envelope.signature, 'base64url')); } catch { ok = false; }
  requireThat(ok, 'INV-401-SIGNATURE', 'Signature verification failed', 401);
  return envelope.payload;
}
export function encrypt(value, key, aad) {
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad));
  const data = Buffer.concat([cipher.update(canonical(value), 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), data].map(b => b.toString('base64url')).join('.');
}
export function decrypt(value, key, aad) {
  // Canonical admission: exactly three base64url segments that round-trip
  // — a malleated spelling (extra segments, padding, foreign chars) is a
  // different wire object, and string-keyed dedup must not miss it
  // (w24-crypto F5).
  const parts = typeof value === 'string' ? value.split('.') : [];
  requireThat(parts.length === 3 && parts.every(x => x.length > 0 && Buffer.from(x, 'base64url').toString('base64url') === x), 'INV-400-SCHEMA', 'Invalid ciphertext encoding', 400);
  const [iv, tag, data] = parts.map(x => Buffer.from(x, 'base64url'));
  const decipher = createDecipheriv('aes-256-gcm', key, iv); decipher.setAAD(Buffer.from(aad)); decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8'));
}

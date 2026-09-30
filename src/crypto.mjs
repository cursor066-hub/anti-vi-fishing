import { generateKeyPairSync, createPrivateKey, createPublicKey, sign, verify, randomBytes, createCipheriv, createDecipheriv, timingSafeEqual } from 'node:crypto';
import { canonical, digest } from './canonical.mjs';
import { requireThat } from './errors.mjs';

export function generateKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pub = publicKey.export({ type: 'spki', format: 'pem' });
  return { key_id: digest({ public_key: pub }).slice(0, 32), public_key: pub, private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }) };
}
export function signed(payload, key, purpose) {
  const protectedHeader = { profile: 'IF-CJSON-1', suite: 'Ed25519', key_id: key.key_id, purpose };
  const message = Buffer.from(canonical({ protected: protectedHeader, payload }));
  return { protected: protectedHeader, payload, signature: sign(null, message, createPrivateKey(key.private_key)).toString('base64url') };
}
export function verifySigned(envelope, publicKeys, purpose) {
  requireThat(envelope && Object.keys(envelope).sort().join() === 'payload,protected,signature', 'INV-401-SIGNATURE', 'Invalid signed envelope', 401);
  const h = envelope.protected;
  requireThat(h && Object.keys(h).sort().join() === 'key_id,profile,purpose,suite' && h.profile === 'IF-CJSON-1' && h.suite === 'Ed25519' && h.purpose === purpose, 'INV-401-SIGNATURE', 'Unsupported signature context', 401);
  const key = publicKeys[h.key_id];
  requireThat(key && !key.revoked, 'INV-401-SIGNATURE', 'Signer unavailable', 401);
  requireThat(typeof envelope.signature === 'string' && /^[A-Za-z0-9_-]{86}$/.test(envelope.signature), 'INV-401-SIGNATURE', 'Invalid signature encoding', 401);
  let ok = false;
  try { ok = verify(null, Buffer.from(canonical({ protected: h, payload: envelope.payload })), createPublicKey(key.public_key), Buffer.from(envelope.signature, 'base64url')); } catch { ok = false; }
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
  const [iv, tag, data] = value.split('.').map(x => Buffer.from(x, 'base64url'));
  const decipher = createDecipheriv('aes-256-gcm', key, iv); decipher.setAAD(Buffer.from(aad)); decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8'));
}
export function secretEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aa = Buffer.from(a), bb = Buffer.from(b); return aa.length === bb.length && timingSafeEqual(aa, bb);
}

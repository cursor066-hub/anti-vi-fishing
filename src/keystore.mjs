import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, chmodSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import { canonical, digest } from './canonical.mjs';
import { encrypt, decrypt } from './crypto.mjs';
import { fields, text, identifier, integer } from './schema.mjs';
import { requireThat, InvariantError } from './errors.mjs';

// IF-SOFTHSM-1: software keystore profile. Keys are generated inside the
// vault, never leave it in plaintext (private material at rest is wrapped
// under the vault master key), signing happens inside, and each key can be
// attested — honestly labelled generated_inside software, hardware:false.
// This is NOT a real HSM: the attestation says so (KEY-003 honest profile).

export const SUITES = { Ed25519: { id: 'Ed25519', introduced: 1, status: 'approved' } };
export const FIRMWARE = 'if-softhsm-1.0.0';
export const STORE_FORMAT = 'IF-SOFTHSM-STORE-1';

export class KeyVault {
  constructor(masterKey, { firmware = FIRMWARE } = {}) {
    this.masterKey = Buffer.from(masterKey, 'base64url');
    requireThat(this.masterKey.length === 32, 'INV-400-SCHEMA', 'Vault master key must be 32 bytes');
    this.firmware = firmware; this.keys = new Map();
    this.attestor = this._generateRaw();
  }
  _generateRaw() {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const public_pem = publicKey.export({ type: 'spki', format: 'pem' });
    return { key_id: digest({ public_key: public_pem }).slice(0, 32), public_key: public_pem, private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }) };
  }
  has(key_id) { return this.keys.has(key_id) && !this.keys.get(key_id).revoked; }
  entry(key_id) { const e = this.keys.get(key_id); requireThat(e && !e.revoked && !e.pending, 'INV-401-SIGNATURE', 'Key unavailable, revoked or pending activation', 401); return e; }
  generate(purpose, { suite = 'Ed25519', exportable = false, key_id = null, pending = false } = {}) {
    requireThat(SUITES[suite]?.status === 'approved', 'INV-400-SCHEMA', 'Unapproved algorithm suite');
    text(purpose, 'key purpose', 64);
    const raw = this._generateRaw();
    const id = key_id ?? raw.key_id;
    requireThat(!this.keys.has(id), 'INV-409-CONFLICT', 'Key id already exists', 409);
    this.keys.set(id, { key_id: id, public_key: raw.public_key, purpose, suite, exportable, revoked: false, pending, generated_inside: true, wrapped: encrypt(raw.private_key, this.masterKey, `vault/${id}`), created_firmware: this.firmware });
    return { key_id: id, public_key: raw.public_key, suite, purpose, exportable, pending };
  }
  // A pending key cannot sign until a verified key.rotate action activates it.
  activate(key_id) {
    const e = this.keys.get(key_id);
    requireThat(e && !e.revoked, 'INV-401-SIGNATURE', 'Key unavailable or revoked', 401);
    requireThat(e.pending, 'INV-409-STATE', 'Key is not pending activation', 409);
    e.pending = false;
    return { key_id, activated: true };
  }
  // Import of externally generated material (dev/test path and ceremony
  // reconstruction). Imported keys are recorded generated_inside:false so the
  // attestation stays honest.
  importKey(key, purpose, { exportable = false, suite = 'Ed25519' } = {}) {
    fields(key, ['key_id', 'public_key', 'private_key']);
    requireThat(typeof key.private_key === 'string' && key.private_key.includes('PRIVATE KEY') && key.private_key.length <= 8192, 'INV-400-SCHEMA', 'Invalid private key');
    requireThat(!this.keys.has(key.key_id), 'INV-409-CONFLICT', 'Key id already exists', 409);
    this.keys.set(key.key_id, { key_id: key.key_id, public_key: key.public_key, purpose, suite, exportable, revoked: false, generated_inside: false, wrapped: encrypt(key.private_key, this.masterKey, `vault/${key.key_id}`), created_firmware: 'imported' });
    return { key_id: key.key_id, public_key: key.public_key, suite, purpose, exportable };
  }
  _private(key_id) { return decrypt(this.entry(key_id).wrapped, this.masterKey, `vault/${key_id}`); }
  sign(key_id, purpose, message) {
    const e = this.entry(key_id);
    requireThat(e.purpose === purpose || e.purpose === 'any', 'INV-403-SCOPE', `Key is bound to purpose ${e.purpose}`, 403);
    return sign(null, Buffer.isBuffer(message) ? message : Buffer.from(message), createPrivateKey(this._private(key_id))).toString('base64url');
  }
  verify(key_id, message, signatureB64) {
    const e = this.entry(key_id);
    try { return verify(null, Buffer.isBuffer(message) ? message : Buffer.from(message), createPublicKey(e.public_key), Buffer.from(signatureB64, 'base64url')); } catch { return false; }
  }
  publicKey(key_id) { return this.entry(key_id).public_key; }
  // Envelope signing with the IF-CJSON-1 profile; identical wire shape to
  // crypto.signed() but the private key never leaves the vault.
  envelope(key_id, purpose, payload) {
    const h = { profile: 'IF-CJSON-1', suite: this.entry(key_id).suite, key_id, purpose };
    return { protected: h, payload, signature: this.sign(key_id, purpose, canonical({ protected: h, payload })) };
  }
  export(key_id) {
    const e = this.entry(key_id);
    requireThat(e.exportable, 'INV-403-SCOPE', 'Key is marked non-exportable', 403);
    return { key_id, public_key: e.public_key, private_key: this._private(key_id) };
  }
  revoke(key_id) { const e = this.keys.get(key_id); requireThat(e, 'INV-404-NOT-FOUND', 'Key not found', 404); e.revoked = true; e.pending = false; return { key_id, revoked: true }; }
  list() { return [...this.keys.values()].map(({ wrapped, ...e }) => e); }
  attest(key_id) {
    const e = this.entry(key_id);
    const h = { profile: 'IF-CJSON-1', suite: 'Ed25519', key_id: this.attestor.key_id, purpose: 'key-attestation' };
    const payload = { subject_key_id: key_id, public_key: e.public_key, purpose: e.purpose, suite: e.suite, firmware: this.firmware, generated_inside: e.generated_inside, exportable: e.exportable, profile: 'IF-SOFTHSM-1', hardware: false };
    return { protected: h, payload, signature: sign(null, Buffer.from(canonical({ protected: h, payload })), createPrivateKey(this.attestor.private_key)).toString('base64url') };
  }
  attestorPublicKeys() { return { [this.attestor.key_id]: { public_key: this.attestor.public_key } }; }
  save(path) {
    const state = { format: STORE_FORMAT, firmware: this.firmware, attestor_wrapped: encrypt(this.attestor.private_key, this.masterKey, 'vault/attestor'), keys: this.list().map(e => ({ ...e, wrapped: this.keys.get(e.key_id).wrapped })) };
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    writeFileSync(path, canonical(state) + '\n', { mode: 0o600 });
    chmodSync(path, 0o600);
  }
  static load(path, masterKey) {
    const state = JSON.parse(readFileSync(path, 'utf8'));
    requireThat(state.format === STORE_FORMAT, 'INV-503-CONFIG', 'Unrecognised keystore format', 503);
    const vault = new KeyVault(masterKey, { firmware: state.firmware });
    vault.attestor.private_key = decrypt(state.attestor_wrapped, vault.masterKey, 'vault/attestor');
    for (const e of state.keys) vault.keys.set(e.key_id, { ...e, wrapped: e.wrapped });
    return vault;
  }
  static open(directory) {
    const storePath = `${directory}/keystore.json`, masterPath = `${directory}/master.key`;
    if (existsSync(storePath) && existsSync(masterPath)) return KeyVault.load(storePath, JSON.parse(readFileSync(masterPath, 'utf8')).master_key);
    const masterKey = randomBytes(32).toString('base64url');
    return new KeyVault(masterKey);
  }
}
export function verifyAttestation(envelope, attestorKeys) {
  const h = envelope?.protected;
  requireThat(h && h.profile === 'IF-CJSON-1' && h.purpose === 'key-attestation', 'INV-401-SIGNATURE', 'Invalid attestation envelope', 401);
  const key = attestorKeys[h.key_id];
  requireThat(key && !key.revoked, 'INV-401-SIGNATURE', 'Attestor unavailable', 401);
  const ok = verify(null, Buffer.from(canonical({ protected: h, payload: envelope.payload })), createPublicKey(key.public_key), Buffer.from(envelope.signature, 'base64url'));
  requireThat(ok, 'INV-401-SIGNATURE', 'Attestation signature failed', 401);
  return envelope.payload;
}

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, randomBytes, createHmac } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, chmodSync, existsSync, renameSync, rmSync } from 'node:fs';
import { dirname } from 'node:path';
import { canonical, digest } from './canonical.mjs';
import { encrypt, decrypt, SUITES, verifySuite, signSuite, verifySigned, ctEqual } from './crypto.mjs';
import { fields, text, identifier, integer } from './schema.mjs';
import { requireThat, InvariantError } from './errors.mjs';

export const derivePublic = pem => createPublicKey(createPrivateKey(pem)).export({ type: 'spki', format: 'pem' });
const stateMac = (masterKey, state) => createHmac('sha256', masterKey).update(canonical(state)).digest('base64url');

// IF-SOFTHSM-1: software keystore profile. Keys are generated inside the
// vault, never leave it in plaintext (private material at rest is wrapped
// under the vault master key), signing happens inside, and each key can be
// attested — honestly labelled generated_inside software, hardware:false.
// This is NOT a real HSM: the attestation says so (KEY-003 honest profile).

export { SUITES };
export const FIRMWARE = 'if-softhsm-1.0.0';
export const STORE_FORMAT = 'IF-SOFTHSM-STORE-1';

export class KeyVault {
  constructor(masterKey, { firmware = FIRMWARE } = {}) {
    this.masterKey = Buffer.from(masterKey, 'base64url');
    requireThat(this.masterKey.length === 32, 'INV-400-SCHEMA', 'Vault master key must be 32 bytes');
    this.firmware = firmware; this.keys = new Map();
    this.attestor = this._generateRaw();
  }
  _generateRaw(suite = 'Ed25519') {
    const s = Object.hasOwn(SUITES, suite) ? SUITES[suite] : undefined;
    requireThat(s, 'INV-400-SCHEMA', 'Unsupported algorithm suite');
    const { privateKey, publicKey } = generateKeyPairSync(s.curve, s.namedCurve ? { namedCurve: s.namedCurve } : {});
    const public_pem = publicKey.export({ type: 'spki', format: 'pem' });
    return { key_id: digest({ public_key: public_pem }).slice(0, 32), public_key: public_pem, private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }) };
  }
  has(key_id) { return this.keys.has(key_id) && !this.keys.get(key_id).revoked; }
  entry(key_id) { const e = this.keys.get(key_id); requireThat(e && !e.revoked && !e.pending, 'INV-401-SIGNATURE', 'Key unavailable, revoked or pending activation', 401); return e; }
  publicKey(key_id) { return this.keys.get(key_id)?.public_key ?? null; }
  generate(purpose, { suite = 'Ed25519', exportable = false, key_id = null, pending = false, tenant_id = null } = {}) {
    requireThat(Object.hasOwn(SUITES, suite), 'INV-400-SCHEMA', 'Unapproved algorithm suite');
    for (const p of Array.isArray(purpose) ? purpose : [purpose]) text(p, 'key purpose', 64);
    const raw = this._generateRaw(suite);
    const id = key_id ?? raw.key_id;
    // A caller-chosen id becomes a Map key, an AAD suffix and a wire
    // key_id: prototype-member names would silently poison downstream
    // verification sets (w21-crypto F-6), and 'attestor' would alias the
    // attestor's own wrap AAD 'vault/attestor' (w24-crypto F3).
    requireThat(!['__proto__', 'prototype', 'constructor', 'attestor'].includes(id), 'INV-400-SCHEMA', 'Key id collides with a reserved name', 400);
    requireThat(typeof id === 'string' && id.length <= 128 && /^[A-Za-z0-9_.:-]+$/.test(id), 'INV-400-SCHEMA', 'Invalid key id', 400);
    requireThat(!this.keys.has(id), 'INV-409-CONFLICT', 'Key id already exists', 409);
    requireThat(tenant_id === null || (typeof tenant_id === 'string' && tenant_id.length <= 128), 'INV-400-SCHEMA', 'Invalid tenant binding', 400);
    // The vault is process-global — every entry carries its owning tenant so
    // no tenant-scoped path can sign, rotate, revoke or list another
    // tenant's material (w6-tenancy F2/F3/F4).
    this.keys.set(id, { key_id: id, tenant_id, public_key: raw.public_key, purpose, suite, exportable, revoked: false, pending, generated_inside: true, wrapped: encrypt(raw.private_key, this.masterKey, `vault/${id}`), created_firmware: this.firmware });
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
  importKey(key, purpose, { exportable = false, suite = 'Ed25519', tenant_id = null } = {}) {
    fields(key, ['key_id', 'public_key', 'private_key']);
    requireThat(typeof key.private_key === 'string' && key.private_key.includes('PRIVATE KEY') && key.private_key.length <= 8192, 'INV-400-SCHEMA', 'Invalid private key');
    requireThat(Object.hasOwn(SUITES, suite), 'INV-400-SCHEMA', 'Unapproved algorithm suite');
    // The advertised public key must be the public half of the private key —
    // otherwise the vault would attest a foreign identity while signing with
    // whatever private material was handed in (crypto-audit M-2).
    requireThat(derivePublic(key.private_key) === key.public_key, 'INV-401-SIGNATURE', 'Imported keypair is inconsistent', 401);
    // Same admission gate as generate(): a non-string id coerces inside the
    // wrap AAD ('vault/' + 5 aliases 'vault/5'), an uncanonicalizable purpose
    // wedges save(), and 'attestor' aliases the attestor wrap (w24-crypto
    // F2/F3).
    requireThat(typeof key.key_id === 'string' && key.key_id.length <= 128 && /^[A-Za-z0-9_.:-]+$/.test(key.key_id), 'INV-400-SCHEMA', 'Invalid key id', 400);
    requireThat(!['__proto__', 'prototype', 'constructor', 'attestor'].includes(key.key_id), 'INV-400-SCHEMA', 'Key id collides with a reserved name', 400);
    for (const p of Array.isArray(purpose) ? purpose : [purpose]) text(p, 'key purpose', 64);
    requireThat(tenant_id === null || (typeof tenant_id === 'string' && tenant_id.length <= 128), 'INV-400-SCHEMA', 'Invalid tenant binding', 400);
    requireThat(!this.keys.has(key.key_id), 'INV-409-CONFLICT', 'Key id already exists', 409);
    this.keys.set(key.key_id, { key_id: key.key_id, tenant_id, public_key: key.public_key, purpose, suite, exportable, revoked: false, generated_inside: false, wrapped: encrypt(key.private_key, this.masterKey, `vault/${key.key_id}`), created_firmware: 'imported' });
    return { key_id: key.key_id, public_key: key.public_key, suite, purpose, exportable };
  }
  _private(key_id, entry = null) { return decrypt((entry ?? this.entry(key_id)).wrapped, this.masterKey, `vault/${key_id}`); }
  sign(key_id, purpose, message, { allowPending = false, tenant_id = null } = {}) {
    const e = this.keys.get(key_id);
    requireThat(e && !e.revoked && (allowPending || !e.pending), 'INV-401-SIGNATURE', 'Key unavailable, revoked or pending activation', 401);
    // The vault's own tenant invariant: a scoped entry must never mint for
    // another tenant when the caller names one (w21-crypto F-7).
    requireThat(!tenant_id || !e.tenant_id || e.tenant_id === tenant_id, 'INV-403-SCOPE', 'Key belongs to another tenant', 403);
    requireThat(e.purpose === 'any' || e.purpose === purpose || (Array.isArray(e.purpose) && e.purpose.includes(purpose)), 'INV-403-SCOPE', `Key is bound to purpose ${e.purpose}`, 403);
    requireThat(Object.hasOwn(SUITES, e.suite), 'INV-400-SCHEMA', 'Unapproved algorithm suite');
    return signSuite(e.suite, Buffer.isBuffer(message) ? message : Buffer.from(message), this._private(key_id, e));
  }
  verify(key_id, message, signatureB64) {
    const e = this.entry(key_id);
    try {
      if (!Object.hasOwn(SUITES, e.suite)) return false;
      return verifySuite(e.suite, Buffer.isBuffer(message) ? message : Buffer.from(message), e.public_key, Buffer.from(signatureB64, 'base64url'));
    } catch { return false; }
  }
  // Envelope signing with the IF-CJSON-1 profile; identical wire shape to
  // crypto.signed() but the private key never leaves the vault.
  // allowPending is the single scoped exception for recovery signing: when a
  // class's configured key is revoked, its pending successor must be able to
  // sign marked recovery envelopes or the tenant bricks (w11-lifecycle F1/F2).
  // Callers opt in only through Fabric._signingKeyId — pending keys can never
  // silently mint ordinary signatures.
  envelope(key_id, purpose, payload, { allowPending = false, tenant_id = null } = {}) {
    const e = this.keys.get(key_id);
    requireThat(e && !e.revoked && (allowPending || !e.pending), 'INV-401-SIGNATURE', 'Key unavailable, revoked or pending activation', 401);
    requireThat(!tenant_id || !e.tenant_id || e.tenant_id === tenant_id, 'INV-403-SCOPE', 'Key belongs to another tenant', 403);
    const h = { profile: 'IF-CJSON-1', suite: e.suite, key_id, purpose };
    return { protected: h, payload, signature: this.sign(key_id, purpose, canonical({ protected: h, payload }), { allowPending, tenant_id }) };
  }
  export(key_id) {
    const e = this.entry(key_id);
    requireThat(e.exportable, 'INV-403-SCOPE', 'Key is marked non-exportable', 403);
    return { key_id, public_key: e.public_key, private_key: this._private(key_id) };
  }
  revoke(key_id) { const e = this.keys.get(key_id); requireThat(e, 'INV-404-NOT-FOUND', 'Key not found', 404); e.revoked = true; e.pending = false; return { key_id, revoked: true }; }
  list() { return [...this.keys.values()].map(({ wrapped, ...e }) => e); }
  // Key attestations are time-bound, tenant-bound claims: the payload
  // carries issued_at/expires_at/tenant_id (and an optional verifier
  // nonce) so an artifact minted for one scope cannot replay forever or
  // port across tenants (w24-crypto F1).
  attest(key_id, { now = Date.now(), ttl_ms = 60000, nonce = null } = {}) {
    const e = this.entry(key_id);
    requireThat(Number.isSafeInteger(now) && Number.isSafeInteger(ttl_ms) && ttl_ms > 0 && ttl_ms <= 86400000, 'INV-400-SCHEMA', 'Invalid attestation window', 400);
    const h = { profile: 'IF-CJSON-1', suite: 'Ed25519', key_id: this.attestor.key_id, purpose: 'key-attestation' };
    const payload = { subject_key_id: key_id, tenant_id: e.tenant_id, public_key: e.public_key, purpose: e.purpose, suite: e.suite, firmware: this.firmware, generated_inside: e.generated_inside, exportable: e.exportable, profile: 'IF-SOFTHSM-1', hardware: false, issued_at: now, expires_at: now + ttl_ms, ...(nonce !== null ? { nonce } : {}) };
    return { protected: h, payload, signature: sign(null, Buffer.from(canonical({ protected: h, payload })), createPrivateKey(this.attestor.private_key)).toString('base64url') };
  }
  attestorPublicKeys() { return { [this.attestor.key_id]: { public_key: this.attestor.public_key } }; }
  save(path) {
    const state = { format: STORE_FORMAT, firmware: this.firmware, attestor: { key_id: this.attestor.key_id, public_key: this.attestor.public_key }, attestor_wrapped: encrypt(this.attestor.private_key, this.masterKey, 'vault/attestor'), keys: this.list().map(e => ({ ...e, wrapped: this.keys.get(e.key_id).wrapped })) };
    // The state file is MAC'd under the master key: a write-only attacker
    // (backup tampering, restore injection) cannot flip purpose/exportable/
    // public_key metadata without breaking authentication (crypto-audit H-2).
    state.mac = stateMac(this.masterKey, state);
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    // Atomic write: temp + rename so a crash mid-save cannot leave a torn
    // vault file that fails MAC/parse at next open (concurrency-audit L5).
    const tmp = `${path}.${randomBytes(6).toString('hex')}.tmp`;
    try { writeFileSync(tmp, canonical(state) + '\n', { mode: 0o600 }); chmodSync(tmp, 0o600); renameSync(tmp, path); }
    catch (e) { rmSync(tmp, { force: true }); throw e; }
  }
  static load(path, masterKey) {
    const { mac, ...state } = JSON.parse(readFileSync(path, 'utf8'));
    requireThat(state.format === STORE_FORMAT, 'INV-503-CONFIG', 'Unrecognised keystore format', 503);
    const vault = new KeyVault(masterKey, { firmware: state.firmware });
    requireThat(ctEqual(stateMac(vault.masterKey, state), mac), 'INV-503-CONFIG', 'Keystore integrity check failed (state MAC mismatch)', 503);
    const attestorPrivate = (() => { try { return decrypt(state.attestor_wrapped, vault.masterKey, 'vault/attestor'); } catch { throw new InvariantError('INV-503-CONFIG', 'Keystore attestor fails to unwrap', 503); } })();
    // Restore the full attestor identity — persisting only the private key
    // corrupted key_id/public_key on every restart (crypto-audit H-1).
    requireThat(state.attestor && derivePublic(attestorPrivate) === state.attestor.public_key, 'INV-503-CONFIG', 'Attestor identity inconsistent', 503);
    vault.attestor = { key_id: state.attestor.key_id, public_key: state.attestor.public_key, private_key: attestorPrivate };
    for (const e of state.keys) {
      // A duplicate id inside one MAC-valid state file must fail, not
      // silently overwrite (w21-crypto F-9).
      requireThat(!vault.keys.has(e.key_id), 'INV-503-CONFIG', `Duplicate key id ${e.key_id} in keystore`, 503);
      // Verify every entry's advertised public key matches its private half.
      const priv = (() => { try { return decrypt(e.wrapped, vault.masterKey, `vault/${e.key_id}`); } catch { throw new InvariantError('INV-503-CONFIG', `Key ${e.key_id} fails to unwrap`, 503); } })();
      requireThat(derivePublic(priv) === e.public_key, 'INV-503-CONFIG', `Key ${e.key_id} has inconsistent public material`, 503);
      vault.keys.set(e.key_id, { ...e, wrapped: e.wrapped });
    }
    return vault;
  }
  static open(directory) {
    const storePath = `${directory}/keystore.json`, masterPath = `${directory}/master.key`;
    if (existsSync(storePath) && !existsSync(masterPath)) throw new InvariantError('INV-503-CONFIG', 'Keystore exists but master key is missing — refusing to silently regenerate', 503);
    // Master without keystore is a stale-commit-marker state — refuse, do
    // not silently re-key (w9-schema F-4).
    if (!existsSync(storePath) && existsSync(masterPath)) throw new InvariantError('INV-503-CONFIG', 'Master key exists but keystore is missing — refusing to silently re-key', 503);
    if (existsSync(storePath) && existsSync(masterPath)) {
      // A corrupt master file is a config failure with an INV code, not a
      // raw parser exception escaping the taxonomy (w11-fixverify R4).
      const master = (() => { try { return JSON.parse(readFileSync(masterPath, 'utf8')); } catch { throw new InvariantError('INV-503-CONFIG', 'master.key is unreadable or corrupt', 503); } })();
      return KeyVault.load(storePath, master.master_key);
    }
    const masterKey = randomBytes(32).toString('base64url');
    return new KeyVault(masterKey);
  }
}
// One verifier, one strictness level: attestations pass through the same
// envelope checks as every other signed object — exact 3-key envelope,
// exact 4-key protected header, required suite, canonical base64url
// signature, own-property key lookup, and uniform INV-401 failures
// (w8-canonical F3).
// Verifying an attestation checks the claim, not just the signature: the
// artifact must name a live window and its tenant; callers that pin a
// nonce or tenant enforce the binding here, and a verifier holding the
// vault can additionally require the subject key to still be live
// (w24-crypto F1).
export function verifyAttestation(envelope, attestorKeys, { now = Date.now(), nonce = undefined, tenant_id = undefined, vault = undefined } = {}) {
  const payload = verifySigned(envelope, attestorKeys, 'key-attestation');
  requireThat(Number.isSafeInteger(payload.issued_at) && Number.isSafeInteger(payload.expires_at)
    && payload.issued_at <= payload.expires_at && payload.expires_at > now,
    'INV-401-ATTESTATION', 'Attestation carries no live validity window', 401);
  if (nonce !== undefined) requireThat(payload.nonce === nonce, 'INV-401-ATTESTATION', 'Attestation nonce does not match the verifier challenge', 401);
  if (tenant_id !== undefined) requireThat(payload.tenant_id === tenant_id, 'INV-401-ATTESTATION', 'Attestation belongs to another tenant', 401);
  if (vault !== undefined) {
    const e = vault.keys.get(payload.subject_key_id);
    requireThat(e && !e.revoked && !e.pending && e.public_key === payload.public_key, 'INV-401-ATTESTATION', 'Attested key is no longer live', 401);
  }
  return payload;
}

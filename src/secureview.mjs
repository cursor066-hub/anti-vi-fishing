import { generateKeyPairSync, diffieHellman, hkdfSync, createCipheriv, createDecipheriv, randomBytes, createPublicKey, createPrivateKey } from 'node:crypto';
import { canonical, digest, parseStrict } from './canonical.mjs';
import { signed, verifySigned, generateKey } from './crypto.mjs';
import { fields, text, identifier, integer, uniqueStrings } from './schema.mjs';
import { requireThat, InvariantError } from './errors.mjs';

// IF-SP-1: Secure Perception — engineering (dev-attested) profile.
// A viewing component registers a self-signed component attestation; the
// envelope channel to it is real ECDH(P-256) + HKDF + AES-256-GCM, so only the
// attested component's private key can open released fields. The assurance
// label honestly reports 'dev-attested-software'; policy may demand
// 'hardware-enclave' for higher tiers, which this profile cannot satisfy —
// those releases are denied rather than faked.

export const ASSURANCE = { dev: 'dev-attested-software', workspace: 'workspace-unattested', enclave: 'hardware-enclave' };

export function createComponent(name, firmwareVersion) {
  const signing = generateKey();
  const ecdh = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    name, firmware_version: firmwareVersion, signing,
    ecdh_public: ecdh.publicKey.export({ type: 'spki', format: 'pem' }), _ecdh_private: ecdh.privateKey,
    attest(nonce) {
      return signed({ component: name, firmware_version: firmwareVersion, nonce, generated_inside: false, assurance: ASSURANCE.dev, production: false, capabilities: ['field-release', 'evidence-viewer'] }, signing, 'component-attestation');
    }
  };
}

export function openSession(component, attestation, policy, now) {
  fields(attestation, ['protected', 'payload', 'signature']);
  verifySigned(attestation, { [component.signing.key_id]: { public_key: component.signing.public_key } }, 'component-attestation');
  const sp = policy.secure_perception ?? {};
  requireThat(sp.enabled !== false, 'INV-451-POLICY', 'Secure Perception is disabled by policy', 451);
  requireThat((sp.allowed_firmware ?? []).includes(attestation.payload.firmware_version), 'INV-401-ATTESTATION', 'Component firmware not trusted by policy', 401);
  requireThat(attestation.payload.nonce === sp.nonce || /^[a-f0-9]{64}$/.test(attestation.payload.nonce ?? ''), 'INV-400-SCHEMA', 'Bad attestation nonce');
  const server = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const session = {
    session_id: 'sv-' + digest({ component: attestation.payload.component, now, salt: randomBytes(8).toString('hex') }).slice(0, 24),
    component: attestation.payload.component, firmware_version: attestation.payload.firmware_version,
    component_public: component.signing.public_key, component_ecdh: component.ecdh_public,
    assurance: ASSURANCE.dev, production: false, expires_at: now + (sp.session_ttl_ms ?? 300000),
    _server_private: server.privateKey, server_ephemeral: server.publicKey.export({ type: 'spki', format: 'pem' })
  };
  return session;
}

function deriveKey(session) {
  const priv = typeof session._server_private === 'string' ? createPrivateKey(session._server_private) : session._server_private;
  const shared = diffieHellman({ privateKey: priv, publicKey: createPublicKey(session.component_ecdh) });
  return Buffer.from(hkdfSync('sha256', shared, Buffer.from('if-secure-perception-1'), Buffer.from(session.session_id), 32));
}

export function releaseFields(session, release, policy, now) {
  // release: {capsule_id?, evidence_ref?, fields: {name:value}, purpose}
  fields(release, ['fields', 'purpose']);
  requireThat(session.expires_at > now, 'INV-409-STATE', 'Perception session expired', 409);
  const sp = policy.secure_perception ?? {};
  const allowed = sp.release_fields ?? Object.keys(release.fields);
  for (const f of Object.keys(release.fields)) requireThat(allowed.includes(f), 'INV-451-POLICY', `Field ${f} not releasable under perception policy`, 451);
  const binding = { session_id: session.session_id, purpose: release.purpose, fields: Object.keys(release.fields).sort(), capsule_id: release.capsule_id ?? null, expires_at: session.expires_at, issued_at: now };
  const plaintext = canonical({ ...binding, data: release.fields });
  const key = deriveKey(session); const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    mode: 'secure-perception', assurance: session.assurance, production: false, binding,
    ephemeral_public: session.server_ephemeral, nonce: nonce.toString('base64url'),
    ciphertext: ciphertext.toString('base64url'), tag: cipher.getAuthTag().toString('base64url')
  };
}

export function openRelease(component, release) {
  // Component-side open: used by the dev console component and tests. Proves
  // the ciphertext is only readable with the attested component's private key.
  const priv = typeof component._ecdh_private === 'string' ? createPrivateKey(component._ecdh_private) : component._ecdh_private;
  const shared = diffieHellman({ privateKey: priv, publicKey: createPublicKey(release.ephemeral_public) });
  const key = Buffer.from(hkdfSync('sha256', shared, Buffer.from('if-secure-perception-1'), Buffer.from(release.binding.session_id), 32));
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(release.nonce, 'base64url'));
  decipher.setAuthTag(Buffer.from(release.tag, 'base64url'));
  const plaintext = Buffer.concat([decipher.update(Buffer.from(release.ciphertext, 'base64url')), decipher.final()]).toString('utf8');
  return parseStrict(plaintext);
}

export function workspaceFallback(release, policy, now) {
  // Controlled-workspace fallback: plaintext fields over the normal channel,
  // honestly labelled — only when policy explicitly permits it.
  const sp = policy.secure_perception ?? {};
  requireThat(sp.fallback === 'controlled-workspace', 'INV-451-POLICY', 'Policy denies unencrypted release fallback', 451);
  return { mode: 'controlled-workspace', assurance: ASSURANCE.workspace, production: false, binding: { purpose: release.purpose, fields: Object.keys(release.fields).sort(), issued_at: now }, data: release.fields };
}

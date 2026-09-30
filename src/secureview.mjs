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
    attest(nonce, expires_at) {
      return signed({ component: name, firmware_version: firmwareVersion, nonce, expires_at, generated_inside: false, assurance: ASSURANCE.dev, production: false, capabilities: ['field-release', 'evidence-viewer'] }, signing, 'component-attestation');
    }
  };
}

export function openSession(component, attestation, policy, now) {
  fields(attestation, ['protected', 'payload', 'signature']);
  verifySigned(attestation, { [component.signing.key_id]: { public_key: component.signing.public_key } }, 'component-attestation');
  const sp = policy.secure_perception ?? {};
  requireThat(sp.enabled !== false, 'INV-451-POLICY', 'Secure Perception is disabled by policy', 451);
  requireThat((sp.allowed_firmware ?? []).includes(attestation.payload.firmware_version), 'INV-401-ATTESTATION', 'Component firmware not trusted by policy', 401);
  // Attestations must be fresh and nonce-bound: expiry is mandatory, the
  // nonce must be a 64-hex value, and when policy pins a nonce it must match
  // exactly. Fabric additionally rejects nonce reuse across sessions
  // (replay), so a captured attestation cannot mint a second session.
  requireThat(/^[a-f0-9]{64}$/.test(attestation.payload.nonce ?? ''), 'INV-400-SCHEMA', 'Bad attestation nonce');
  requireThat(Number.isSafeInteger(attestation.payload.expires_at) && attestation.payload.expires_at > now, 'INV-401-ATTESTATION', 'Attestation expired or missing expiry', 401);
  requireThat(!sp.nonce || attestation.payload.nonce === sp.nonce, 'INV-400-SCHEMA', 'Attestation nonce does not match policy');
  const server = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const session = {
    session_id: 'sv-' + digest({ component: attestation.payload.component, now, salt: randomBytes(8).toString('hex') }).slice(0, 24),
    component: attestation.payload.component, firmware_version: attestation.payload.firmware_version,
    component_public: component.signing.public_key, component_ecdh: component.ecdh_public,
    assurance: ASSURANCE.dev, production: false, expires_at: now + (sp.session_ttl_ms ?? 300000),
    nonce: attestation.payload.nonce ?? null,
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
  fields(release, ['fields', 'purpose'], ['capsule_id', 'evidence_ref']);
  requireThat(session.expires_at > now, 'INV-409-STATE', 'Perception session expired', 409);
  const allowed = releaseAllowlist(policy);
  if (allowed) for (const f of Object.keys(release.fields)) requireThat(allowed.includes(f), 'INV-451-POLICY', `Field ${f} not releasable under perception policy`, 451);
  const binding = { session_id: session.session_id, purpose: release.purpose, fields: Object.keys(release.fields).sort(), capsule_id: release.capsule_id ?? null, evidence_ref: release.evidence_ref ?? null, expires_at: session.expires_at, issued_at: now };
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
  const inner = parseStrict(plaintext);
  // The outer binding is unauthenticated metadata — the authenticated copy
  // inside the ciphertext must agree with it, or the release was tampered.
  const { data, ...innerBinding } = inner;
  requireThat(canonical(innerBinding) === canonical(release.binding), 'INV-401-TAMPER', 'Release binding does not match the authenticated plaintext', 401);
  return inner;
}

// Field allowlist: an array restricts names; the explicit wildcard '*' marks a
// deliberate unrestricted engineering profile. An unset field FAILS CLOSED — a
// policy author cannot accidentally release whatever a caller names.
export function releaseAllowlist(policy) {
  const rf = (policy.secure_perception ?? {}).release_fields;
  if (rf === '*') return null; // explicit unrestricted
  requireThat(Array.isArray(rf), 'INV-451-POLICY', 'secure_perception.release_fields must be an explicit allowlist (or "*" in the engineering profile)', 451);
  return rf;
}

export function workspaceFallback(release, policy, now) {
  requireThat(release && typeof release === 'object' && !Array.isArray(release) && release.fields && typeof release.fields === 'object' && !Array.isArray(release.fields), 'INV-400-SCHEMA', 'Invalid release', 400);
  // Controlled-workspace fallback: plaintext fields over the normal channel,
  // honestly labelled — only when policy explicitly permits it.
  const sp = policy.secure_perception ?? {};
  // The fallback is gated by the whole perception clause, not just the
  // fallback key: perception disabled or hardware-required means NO
  // plaintext path exists at all (runtime-audit F-5).
  requireThat(sp.enabled !== false, 'INV-451-POLICY', 'Secure Perception is disabled by policy', 451);
  requireThat(sp.required_assurance !== 'hardware-enclave', 'INV-451-POLICY', 'Hardware-enclave assurance permits no software fallback', 451);
  requireThat(sp.fallback === 'controlled-workspace', 'INV-451-POLICY', 'Policy denies unencrypted release fallback', 451);
  const allowed = releaseAllowlist(policy);
  if (allowed) for (const f of Object.keys(release.fields)) requireThat(allowed.includes(f), 'INV-451-POLICY', `Field ${f} not releasable under perception policy`, 451);
  return { mode: 'controlled-workspace', assurance: ASSURANCE.workspace, production: false, binding: { purpose: release.purpose, fields: Object.keys(release.fields).sort(), reason: release.reason ?? null, issued_at: now }, data: release.fields };
}

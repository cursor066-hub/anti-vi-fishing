// w26 secure-perception hostile-audit regression tests.
// F-1: openRelease pins the session's server ephemeral — a release forged
//   from the component's PUBLIC ecdh key can no longer open.
// F-2: envelope labels (mode/assurance/production/ephemeral) are AAD-bound —
//   a flipped label breaks the tag.
// F-3: policy revocation reaches live sessions (enabled:false, pulled
//   firmware, hardware-enclave requirement) — mint-time gates re-run.
// F-4: session assurance/firmware are ledger-anchored — a planted row
//   cannot write 'hardware-enclave' into the signed release trail.
// F-6/F-10: an expired session shreds its private half on first
//   observation and refuses INV-409-STATE, never INV-503-GATE.
// F-7: fallback reason is typed (256-char string) and rides the audit meta.
// F-9: live sessions are capped (64 per tenant).
// F-10: attestation capabilities/generated_inside claims are typed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, diffieHellman, hkdfSync, createCipheriv, createPublicKey, randomBytes } from 'node:crypto';
import { canonical } from '../src/canonical.mjs';
import { signed } from '../src/crypto.mjs';
import { openRelease } from '../src/secureview.mjs';
import { fixture, hasCode, installPolicy } from './helpers.mjs';

const component = h => h.setup.componentSecrets.acme['secure-view-acme'];
const open = c => ({ ...c, _ecdh_private: c._ecdh_private ?? c.ecdh_private });
const mint = (h, nonce) => h.f.perceptionSession(h.p(), component(h).attest(nonce, h.now() + 300000));
const fresh = () => randomBytes(32).toString('hex');
const rel = (h, sid) => h.f.perceptionRelease(h.p(), sid, { fields: { vendor: 'v1' }, purpose: 'verify' });

// The attacker builds a release with ONLY public material: its own ECDH
// pair DH'd against the component's public key — no secrets needed.
function forgedRelease(componentPem, binding, data) {
  const attacker = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const shared = diffieHellman({ privateKey: attacker.privateKey, publicKey: createPublicKey(componentPem) });
  const key = Buffer.from(hkdfSync('sha256', shared, Buffer.from('if-secure-perception-1'), Buffer.from(binding.session_id), 32));
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const ephemeral = attacker.publicKey.export({ type: 'spki', format: 'pem' });
  cipher.setAAD(canonical({ mode: 'secure-perception', assurance: 'dev-attested-software', production: false, ephemeral_public: ephemeral }));
  const ciphertext = Buffer.concat([cipher.update(canonical({ ...binding, data }), 'utf8'), cipher.final()]);
  return { mode: 'secure-perception', assurance: 'dev-attested-software', production: false, binding, ephemeral_public: ephemeral, nonce: nonce.toString('base64url'), ciphertext: ciphertext.toString('base64url'), tag: cipher.getAuthTag().toString('base64url') };
}

test('w26 F-1: a release forged from the public ECDH key is refused', t => {
  const h = fixture(t);
  const comp = component(h);
  const session = mint(h, fresh());
  const release = rel(h, session.session_id);
  assert.equal(openRelease(open(comp), release, session, h.now()).data.vendor, 'v1');
  const binding = { session_id: session.session_id, purpose: 'verify', fields: ['balance'], capsule_id: 'cap-fabricated', evidence_ref: 'ev-fabricated', expires_at: session.expires_at, issued_at: h.now() };
  const forged = forgedRelease(comp.ecdh_public, binding, { balance: -1 });
  assert.throws(() => openRelease(open(comp), forged, session, h.now()), hasCode('INV-401-TAMPER'));
});

test('w26 F-2: flipped envelope labels break the tag', t => {
  const h = fixture(t);
  const comp = component(h);
  const session = mint(h, fresh());
  const release = rel(h, session.session_id);
  for (const flip of [
    { ...release, assurance: 'hardware-enclave' },
    { ...release, production: true },
    { ...release, mode: 'controlled-workspace' },
    { ...release, ephemeral_public: generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ type: 'spki', format: 'pem' }) },
  ]) assert.throws(() => openRelease(open(comp), flip, session, h.now()), hasCode('INV-401-TAMPER'));
});

test('w26 F-3: policy revocation reaches live sessions', t => {
  const h = fixture(t);
  const s1 = mint(h, fresh());
  installPolicy(h, p => { p.secure_perception.enabled = false; });
  assert.throws(() => rel(h, s1.session_id), hasCode('INV-451-POLICY'));
  const h2 = fixture(t);
  const s2 = mint(h2, fresh());
  installPolicy(h2, p => { p.secure_perception.allowed_firmware = ['never-minted-fw']; });
  assert.throws(() => rel(h2, s2.session_id), hasCode('INV-401-ATTESTATION'));
});

test('w26 F-4: a planted assurance label on the session row is refused', t => {
  const h = fixture(t);
  const session = mint(h, fresh());
  const row = h.f.store.must('acme', 'perception-session', session.session_id);
  row.assurance = 'hardware-enclave';
  h.f.store.put('acme', 'perception-session', session.session_id, row, h.now());
  assert.throws(() => rel(h, session.session_id), hasCode('INV-409-INTEGRITY'));
});

test('w26 F-6/F-10: expired sessions shred on observation and refuse INV-409', t => {
  const h = fixture(t);
  const session = mint(h, fresh());
  h.set(session.expires_at + 1);
  assert.throws(() => rel(h, session.session_id), hasCode('INV-409-STATE'));
  const after = h.f.store.must('acme', 'perception-session', session.session_id);
  assert.equal(after._server_private, null, 'first observation shreds the private half');
  // A tombstoned session refuses with the same honest code, not INV-503-GATE.
  assert.throws(() => rel(h, session.session_id), hasCode('INV-409-STATE'));
});

test('w26 F-7: fallback reason is typed and recorded in the audit meta', t => {
  const h = fixture(t);
  installPolicy(h, p => { p.secure_perception.fallback = 'controlled-workspace'; });
  assert.throws(() => h.f.perceptionFallback(h.p(), { fields: { x: 'y' }, purpose: 'p', reason: { arbitrary: ['object'] } }), hasCode('INV-400-SCHEMA'));
  assert.throws(() => h.f.perceptionFallback(h.p(), { fields: { x: 'y' }, purpose: 'p', reason: 'r'.repeat(300) }), hasCode('INV-400-SCHEMA'));
  const out = h.f.perceptionFallback(h.p(), { fields: { x: 'y' }, purpose: 'p', reason: 'operator approval #42' });
  assert.equal(out.binding.reason, 'operator approval #42');
  const row = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get();
  assert.equal(JSON.parse(row.envelope).payload.metadata.reason, 'operator approval #42');
});

test('w26 F-9: live sessions are capped per tenant', t => {
  const h = fixture(t);
  for (let i = 0; i < 64; i++) mint(h, fresh());
  assert.throws(() => mint(h, fresh()), hasCode('INV-429-QUOTA'));
});

test('w26 F-10: decorative attestation claims are still typed', t => {
  const h = fixture(t);
  const comp = component(h);
  // Re-sign mutated payloads so only the type check stands between them
  // and acceptance — a forged-signature path would test nothing here.
  const base = comp.attest(fresh(), h.now() + 300000).payload;
  for (const payload of [
    { ...base, capabilities: 'field-release' },
    { ...base, capabilities: [1] },
    { ...base, generated_inside: 'yes' },
  ]) assert.throws(() => h.f.perceptionSession(h.p(), signed(payload, comp.signing, 'component-attestation')), hasCode('INV-400-SCHEMA'));
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fixture, hasCode } from './helpers.mjs';
import { signed, SUITES } from '../src/crypto.mjs';
import { ASSURANCE } from '../src/secureview.mjs';
import { clone } from '../src/canonical.mjs';

test('KEY-011: component firmware trust is policy-enforced — a validly signed attestation on revoked firmware is rejected', t => {
  const h = fixture(t), component = h.setup.componentSecrets.acme['secure-view-acme'];
  // Signed by the REAL component key so only the firmware trust gate can fail it.
  const forged = signed({ component: 'secure-view-acme', firmware_version: 'if-secureview-dev-0', nonce: 'b'.repeat(64), expires_at: h.now() + 300000, generated_inside: false, assurance: ASSURANCE.dev, production: false, capabilities: ['field-release', 'evidence-viewer'] }, component.signing, 'component-attestation');
  assert.throws(() => h.f.perceptionSession(h.p(), forged), hasCode('INV-401-ATTESTATION'));
});
test('KEY-011b: removing a firmware from policy.allowed_firmware revokes session capability for previously valid attestations', t => {
  const h = fixture(t), component = h.setup.componentSecrets.acme['secure-view-acme'];
  const policy = clone(h.f.policy('acme')); policy.secure_perception.allowed_firmware = [];
  h.f.store.put('acme', 'policy', 'active', policy, h.now());
  assert.throws(() => h.f.perceptionSession(h.p(), component.attest('b'.repeat(64), h.now() + 300000)), hasCode('INV-401-ATTESTATION'));
});
test('KEY-006: the agility inventory names every SUITES entry and every suite the policy allowlist can accept', t => {
  const doc = readFileSync(join(new URL('.', import.meta.url).pathname, '../docs/ALGORITHM-AGILITY.md'), 'utf8');
  for (const suite of Object.keys(SUITES)) assert.ok(doc.includes('`' + suite + '`'), `inventory is missing suite ${suite}`);
  for (const suite of ['Ed25519', 'ES256']) assert.ok(doc.includes(suite));
  // Every documented suite token must resolve in code — the inventory cannot
  // describe a suite that does not exist.
  for (const token of doc.match(/`E[DS][a-z0-9]+`/g) ?? []) assert.ok(Object.hasOwn(SUITES, token.slice(1, -1)), `inventory describes unknown suite ${token}`);
});

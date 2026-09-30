// Regression coverage for e2e-discovered defects: drift-check shape,
// controlled-workspace fallback binding, and sealed-release semantics.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { driftCheck } from '../src/connectors.mjs';
import { workspaceFallback } from '../src/secureview.mjs';

test('driftCheck: identical registered/observed manifests report no drift', () => {
  const registered = { connector_id: 'issuer:bank', version: '1.0.0', actions: ['bank.ownership', 'bank.balance'], channel: 'authoritative', key_id: 'k1' };
  const observed = { connector_id: 'issuer:bank', version: '1.0.0', actions: ['bank.balance', 'bank.ownership'], channel: 'authoritative', key_id: 'k1' };
  const r = driftCheck(registered, observed, 1700000000000);
  assert.equal(r.drifted, false); assert.deepEqual(r.changes, []); assert.equal(r.action, 'none');
});

test('driftCheck: version, kinds, channel and key changes are each reported', () => {
  const registered = { connector_id: 'issuer:bank', version: '1.0.0', actions: ['bank.ownership'], channel: 'authoritative', key_id: 'k1' };
  const observed = { connector_id: 'issuer:bank', version: '2.0.0', actions: ['bank.ownership', 'bank.balance'], channel: 'device', key_id: 'k2' };
  const r = driftCheck(registered, observed, 1700000000000);
  assert.equal(r.drifted, true);
  assert.deepEqual(r.changes.map(c => c.field), ['version', 'actions', 'channel', 'key_id']);
});

test('driftCheck: missing optional fields never throw and are reported honestly', () => {
  const r = driftCheck({ version: '1.0.0', key_id: 'k1' }, { version: '1.0.0', key_id: 'k1' }, 1700000000000);
  assert.equal(r.drifted, false);
  const r2 = driftCheck({ version: '1.0.0' }, { version: '1.0.0', connector_id: 'issuer:bank' }, 1700000000000);
  assert.equal(r2.drifted, true); assert.deepEqual(r2.changes[0].field, 'connector_id');
});

test('workspaceFallback: returns honest plaintext binding with reason', () => {
  const policy = { secure_perception: { fallback: 'controlled-workspace' } };
  const out = workspaceFallback({ fields: { bank_account: 'TESTBANK1' }, purpose: 'review', reason: 'no device' }, policy, 1700000000000);
  assert.equal(out.mode, 'controlled-workspace'); assert.equal(out.production, false);
  assert.deepEqual(out.binding.fields, ['bank_account']); assert.equal(out.binding.reason, 'no device');
  assert.deepEqual(out.data, { bank_account: 'TESTBANK1' });
});

test('workspaceFallback: policy denial is fail-closed', () => {
  assert.throws(() => workspaceFallback({ fields: {}, purpose: 'x' }, { secure_perception: { fallback: 'deny' } }, 1), e => e.code === 'INV-451-POLICY');
});

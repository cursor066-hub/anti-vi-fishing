import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture, hasCode, runtimeInput } from './helpers.mjs';
import { createIssuerServer } from '../src/issuerd.mjs';
import { ISSUER_RULES, issuerRecords } from '../src/bootstrap.mjs';
import { generateKey, signed } from '../src/crypto.mjs';
import { digest, canonical } from '../src/canonical.mjs';
import { proposal } from '../src/schema.mjs';
import { httpJson } from '../src/connectors.mjs';

// Wave-9 fix-verification regressions: malformed wire bytes normalised to
// the error taxonomy, own-property issuer resolution, transforms container
// typing, storable-depth admission, legacy nonce replay coverage, literal
// forbidden-key set.

const spec = (name, tokens = {}, kinds = ISSUER_RULES.bank) => ({ issuer: name, tenant: 'acme', version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds, records: issuerRecords().bank, ...tokens });
const issueBody = { kind: 'ownership', subject_id: 'operator', claims: { account: 'TESTBANK000001', owner_id: 'vendor-1' }, capsule_digest: 'a'.repeat(64), tenant_id: 'acme' };

test('w9-fixverify NB-1: malformed UTF-8 bodies get INV-400-SCHEMA, not a 500', async t => {
  const srv = createIssuerServer({ 'acme:bank': spec('bank', { issue_token: 'tok' }) }, { port: 0, host: '127.0.0.1' });
  await srv.listen(); t.after(() => srv.close());
  const port = srv.server.address().port;
  const res = await fetch(`http://127.0.0.1:${port}/v1/issuers/bank/issue`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok' }, body: Buffer.from([0x7b, 0xff, 0xfe, 0x7d]) });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error.code, 'INV-400-SCHEMA');
});

test('w9-fixverify: a proto-member issuer name resolves to the same 404 as a ghost', async t => {
  const srv = createIssuerServer({ 'acme:bank': spec('bank', { issue_token: 'tok', read_token: 'tok' }) }, { port: 0, host: '127.0.0.1' });
  await srv.listen(); t.after(() => srv.close());
  const port = srv.server.address().port;
  assert.equal((await httpJson(`http://127.0.0.1:${port}/v1/issuers/toString/manifest?tenant=acme`, { token: 'tok' })).status, 404);
  assert.equal((await httpJson(`http://127.0.0.1:${port}/v1/issuers/constructor/issue`, { method: 'POST', body: issueBody, token: 'tok' })).status, 404);
});

test('w9-fixverify F5: transforms container types are schema errors, not signed payloads', t => {
  const h = fixture(t); const p = h.p();
  for (const transforms of [null, 5, true, [], 'x'])
    assert.throws(() => h.f.runtime.issue(p, runtimeInput({ transforms })), hasCode('INV-400-SCHEMA'), JSON.stringify(transforms));
  // Control: a real transform still issues.
  assert.ok(h.f.runtime.issue(p, runtimeInput({ transforms: { name: { op: 'mask' } } })).payload.capability_id);
});

test('w9-fixverify NB-4: proposals are depth-bounded at admission, before any write', t => {
  const h = fixture(t);
  const st = h.f.target.state('acme', 'res-depth');
  let nested = 0; for (let i = 0; i < 26; i++) nested = [nested];
  st.material_fields.deep = nested; st.digest = digest(st.material_fields);
  const input29 = proposal('finance.beneficiary.create', h.actor(), st, { vendor_id: 'v-1', bank_account: 'TESTBANK000002', currency: 'EUR' }, h.now());
  assert.ok(h.f.propose(h.p(), input29, randomUUID(), signed(input29, h.setup.identityKeys.acme.operator, 'capsule-intent')).capsule.capsule_id, 'depth 29 must be accepted');
  let nested2 = 0; for (let i = 0; i < 27; i++) nested2 = [nested2];
  st.material_fields.deep = nested2; st.digest = digest(st.material_fields);
  const input30 = proposal('finance.beneficiary.create', h.actor(), st, { vendor_id: 'v-1', bank_account: 'TESTBANK000002', currency: 'EUR' }, h.now(), { nonce: `depth-30-${randomUUID()}` });
  const intent30 = signed(input30, h.setup.identityKeys.acme.operator, 'capsule-intent');
  assert.throws(() => h.f.propose(h.p(), input30, randomUUID(), intent30), hasCode('INV-400-SCHEMA'));
  // Nothing was written: the same nonce is not replay-blocked afterwards.
  const shallow = proposal('finance.beneficiary.create', h.actor(), h.f.target.state('acme', 'res-depth-2'), { vendor_id: 'v-1', bank_account: 'TESTBANK000002', currency: 'EUR' }, h.now(), { nonce: input30.nonce });
  assert.ok(h.f.propose(h.p(), shallow, randomUUID(), signed(shallow, h.setup.identityKeys.acme.operator, 'capsule-intent')).capsule.capsule_id, 'nonce must be free after the rejected proposal');
});

test('w9-fixverify NB-5: a legacy bare nonce row still blocks replay', t => {
  const h = fixture(t);
  const nonce = `legacy-${randomUUID()}`;
  h.f.store.db.prepare('INSERT INTO nonces VALUES(?,?,?)').run('acme', nonce, 'legacy-capsule');
  const input = proposal('finance.beneficiary.create', h.actor(), h.f.target.state('acme', 'res-leg'), { vendor_id: 'v-1', bank_account: 'TESTBANK000002', currency: 'EUR' }, h.now(), { nonce });
  assert.throws(() => h.f.propose(h.p(), input, randomUUID(), signed(input, h.setup.identityKeys.acme.operator, 'capsule-intent')), hasCode('INV-409-REPLAY'));
});

test('w9-fixverify NB-2: the forbidden key set is the literal three-verifier list', () => {
  for (const k of ['__proto__', 'prototype', 'constructor', 'toString', 'toLocaleString', 'valueOf', 'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable', '__defineGetter__', '__defineSetter__', '__lookupGetter__', '__lookupSetter__', 'watch', 'unwatch'])
    assert.throws(() => canonical({ [k]: 1 }), hasCode('INV-400-SCHEMA'), k);
});

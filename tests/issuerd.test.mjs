import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { fixture, hasCode } from './helpers.mjs';
import { createIssuerServer, writeIssuer, answerQuery, loadIssuers } from '../src/issuerd.mjs';
import { ISSUER_RULES, issuerRecords } from '../src/bootstrap.mjs';
import { signed, generateKey } from '../src/crypto.mjs';
import { digest } from '../src/canonical.mjs';
import { httpJson } from '../src/connectors.mjs';
import { InvariantError } from '../src/errors.mjs';

// Wave-3 issuerd-audit regressions: issuer kind ceilings, evidence↔action
// claim binding, drift suspension, tenant isolation, scoped directory,
// enumeration-oracle removal.

// HIGH-1: an issuer key can attest only its registered kinds — a compromised
// bank key must not mint governance_review evidence.
test('EVD-001 CON-002: issuer kind ceiling — bank key cannot mint governance_review', t => {
  const h = fixture(t);
  const r = h.proposed('security.case.investigate', { case_id: 'CASE-001', scope: ['fraud'] }, { action: { type: 'security.case.investigate', target_resource: 'case-ledger', purpose: 'Audit' } });
  const payload = { evidence_id: randomUUID(), tenant_id: 'acme', capsule_digest: r.capsule_digest, kind: 'governance_review', content_digest: digest('x'), acquired_at: h.now(), expires_at: h.now() + 600000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 'forged', retention_until: h.now() + 900000, claims: {} };
  assert.throws(() => h.f.attachEvidence(h.p(), r.capsule.capsule_id, signed(payload, h.setup.issuerKeys.acme.bank, 'evidence')), hasCode('INV-403-SCOPE'));
  // The legitimate governance issuer still works.
  h.evidence(r, { kind: 'governance_review' });
  h.evidence(r, { issuer: 'audit-committee', kind: 'governance_review' });
  h.approve(r, 1);
  assert.notEqual(h.f.evaluate(h.p(), r.capsule.capsule_id).decision, 'DENY');
});

// HIGH-2: 'supports' evidence must describe this action's declared content.
test('EVD-001: evidence bound to a different bank account is rejected at attach', t => {
  const h = fixture(t);
  const r = h.proposed('finance.bank.change', { bank_account: 'ATTACKER-ACCT-1', currency: 'EUR' }, { action: { type: 'finance.bank.change', target_resource: 'vendor-1', purpose: 'Audit' } });
  const payload = { evidence_id: randomUUID(), tenant_id: 'acme', capsule_digest: r.capsule_digest, kind: 'ownership', content_digest: digest('x'), acquired_at: h.now(), expires_at: h.now() + 600000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 'true fact, wrong subject', retention_until: h.now() + 900000, claims: { account: 'TESTBANK000001', owner_id: 'vendor-1' } };
  assert.throws(() => h.f.attachEvidence(h.p(), r.capsule.capsule_id, signed(payload, h.setup.issuerKeys.acme.bank, 'evidence')), hasCode('INV-403-SCOPE'));
  // Correct content binds.
  const ok = { ...payload, evidence_id: randomUUID(), claims: { account: 'ATTACKER-ACCT-1', owner_id: 'vendor-1' } };
  h.f.attachEvidence(h.p(), r.capsule.capsule_id, signed(ok, h.setup.issuerKeys.acme.bank, 'evidence'));
  // A 'conflict' answer carries minimal claims by design and stays attachable
  // (it can never satisfy a supports requirement).
  const neg = { ...payload, evidence_id: randomUUID(), claim: 'conflict', claims: {} };
  h.f.attachEvidence(h.p(), r.capsule.capsule_id, signed(neg, h.setup.issuerKeys.acme.registry, 'evidence'));
});

// MED-2: a drifted connector stops being trusted until a clean re-check.
// Drift quarantine is chain-anchored (w13-fixverify M3): only signed
// CONNECTOR_DRIFT/CONNECTOR_REVALIDATED events move the gate — the mutable
// 'issuer-drift' row is observability, not authority.
test('CON-006: issuer-drift flag suspends evidence until cleared', t => {
  const h = fixture(t);
  const r = h.proposed();
  const bankId = Object.keys(h.f.tenant('acme').issuers).find(k => h.f.tenant('acme').issuers[k].name === 'bank');
  // A mutable row alone mints no quarantine.
  h.f.store.put('acme', 'issuer-drift', bankId, { drifted_at: h.now(), changes: [{ field: 'actions' }] }, h.now());
  h.evidence(r, { issuer: 'bank' });
  h.f.store.audit('acme', 'CONNECTOR_DRIFT', 'test', bankId, { drifted: 'manifest' }, h.now());
  assert.throws(() => h.evidence(r, { issuer: 'bank' }), hasCode('INV-403-QUARANTINE'));
  h.f.store.remove('acme', 'issuer-drift', bankId);
  h.f.store.audit('acme', 'CONNECTOR_REVALIDATED', 'test', bankId, { configuration_digest: 'x' }, h.now());
  h.evidence(r, { issuer: 'bank' });
});

// MED-3/MED-5: daemon never signs tenants it does not serve; a missing record
// is a signed conflict, not a distinguishable 412 oracle.
test('RUN-007 NFR-SEC-005: issuerd refuses cross-tenant issuance; record miss is an in-band conflict', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  const key = generateKey();
  const spec = { issuer: 'bank', tenant: 'acme', version: '1.0.0', channel: 'authoritative', key, kinds: ISSUER_RULES.bank, records: issuerRecords().bank };
  assert.throws(() => answerQuery(spec, { tenant_id: 'globex', kind: 'ownership', subject_id: 'operator', claims: { account: 'TESTBANK000001', owner_id: 'vendor-1' }, capsule_digest: 'a'.repeat(64) }, Date.now()), e => e instanceof InvariantError && e.code === 'INV-403-SCOPE');
  writeIssuer(dir, spec);
  const srv = createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', allow_insecure_loopback: true });
  await srv.listen(); t.after(() => srv.close());
  const port = srv.server.address().port;
  const missing = await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/issue`, { method: 'POST', body: { kind: 'ownership', subject_id: 'operator', claims: { account: 'GHOST-9', owner_id: 'nobody' }, capsule_digest: 'a'.repeat(64), tenant_id: 'acme' } });
  assert.equal(missing.status, 201); assert.equal(missing.data.payload.claim, 'conflict'); assert.equal(Object.keys(missing.data.payload.claims ?? {}).length, 0);
  const hit = await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/issue`, { method: 'POST', body: { kind: 'ownership', subject_id: 'operator', claims: { account: 'TESTBANK000001', owner_id: 'vendor-1' }, capsule_digest: 'a'.repeat(64), tenant_id: 'acme' } });
  assert.equal(hit.status, 201); assert.equal(hit.data.payload.claim, 'supports'); assert.equal(hit.data.payload.claims.account, 'TESTBANK000001');
  const xtenant = await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/issue`, { method: 'POST', body: { kind: 'ownership', subject_id: 'operator', claims: { account: 'TESTBANK000001', owner_id: 'vendor-1' }, capsule_digest: 'a'.repeat(64), tenant_id: 'globex' } });
  assert.equal(xtenant.status, 403);
});

// MED-4: the issuer directory is scoped to the token holder's tenant.
test('NFR-SEC-005: /v1/issuers lists only the holder tenant', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  const mk = (tenant, token) => ({ issuer: 'bank', tenant, version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds: ISSUER_RULES.bank, records: issuerRecords().bank, read_token: token });
  const acme = mk('acme', 'tok-acme'), globex = mk('globex', 'tok-globex');
  writeIssuer(dir, { ...acme, issuer: 'bank' }); writeIssuer(dir, { ...globex, issuer: 'bank2' });
  const issuers = loadIssuers(dir);
  const srv = createIssuerServer(issuers, { port: 0, host: '127.0.0.1' });
  await srv.listen(); t.after(() => srv.close());
  const port = srv.server.address().port;
  const list = await httpJson(`http://127.0.0.1:${port}/v1/issuers`, { headers: { Authorization: 'Bearer tok-acme' } });
  assert.equal(list.status, 200);
  assert.ok(Object.values(list.data).every(i => i.tenant === 'acme'), JSON.stringify(list.data));
});

// LOW-4: issuer names that collide with Object.prototype register and resolve.
test('loadIssuers: prototype-colliding issuer names stay resolvable', t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  writeIssuer(dir, { issuer: 'constructor', tenant: 'acme', version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds: ISSUER_RULES.bank, records: issuerRecords().bank });
  const issuers = loadIssuers(dir);
  assert.equal(issuers['acme:constructor'].issuer, 'constructor');
  assert.equal(issuers['constructor'].issuer, 'constructor');
});

// LOW-4: tenant/issuer names containing ':' cannot collide on registry keys.
test('loadIssuers: ":" and malformed tenants are rejected at spec load', t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  writeIssuer(dir, { issuer: 'b:bank', tenant: 'a', version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds: {}, records: {} });
  assert.throws(() => loadIssuers(dir), hasCode('INV-400-SCHEMA'));
});

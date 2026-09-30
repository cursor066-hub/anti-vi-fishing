import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode, runtimeInput, runtimeRequest } from './helpers.mjs';
import { verifyAudit } from '../src/store.mjs';
import { clone, digest } from '../src/canonical.mjs';
import { signed } from '../src/crypto.mjs';

test('RUN-001 DAT-001: local scoped synthetic data read enforces rows and columns', t => {
  const h = fixture(t), cap = h.f.runtime.issue(h.p(), runtimeInput()), result = h.f.runtime.consume(h.p(), runtimeRequest(cap)); assert.equal(result.rows.length, 1); assert.deepEqual(Object.keys(result.rows[0]), ['id', 'name']); assert.equal(result.cost, 2); assert.equal(result.attribution.subject_id, 'operator');
});
test('DAT-002 DAT-009: low-and-slow extraction accumulates across newly minted capabilities', t => {
  const h = fixture(t);
  for (let i = 0; i < 50; i++) { const cap = h.f.runtime.issue(h.p(), runtimeInput()); h.f.runtime.consume(h.p(), runtimeRequest(cap)); h.advance(1001); }
  const cap = h.f.runtime.issue(h.p(), runtimeInput()); assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap)), hasCode('INV-429-BUDGET'));
});
test('DAT-002: rolling budget recovers after bounded window expires', t => {
  const h = fixture(t), policy = h.f.policy('acme'); policy.runtime.windows[0].limit = 2; h.f.store.put('acme', 'policy', 'active', policy, h.now()); let cap = h.f.runtime.issue(h.p(), runtimeInput()); h.f.runtime.consume(h.p(), runtimeRequest(cap)); assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap)), hasCode('INV-429-BUDGET')); h.advance(60001); cap = h.f.runtime.issue(h.p(), runtimeInput()); assert.equal(h.f.runtime.consume(h.p(), runtimeRequest(cap)).decision, 'ALLOW');
});
test('DAT-003: server-controlled sensitivity weight increases information charge', t => {
  const h = fixture(t), policy = h.f.policy('acme'); policy.runtime.classifications.push('confidential'); h.f.store.put('acme', 'policy', 'active', policy, h.now()); const ds = h.f.target.state('acme', 'dataset-1').material_fields; ds.classification = 'confidential'; h.f.target.seed('acme', 'dataset-1', ds);
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ classification: 'confidential' })); assert.equal(h.f.runtime.consume(h.p(), runtimeRequest(cap)).cost, 10);
});
for (const [field, value] of [['destination', 'evil-vault'], ['device_id', 'stolen-device'], ['resource', 'dataset-2'], ['purpose', 'marketing']]) test(`RUN-002 DAT-004: ${field} binding cannot be broadened`, t => { const h = fixture(t), cap = h.f.runtime.issue(h.p(), runtimeInput()); assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap, { [field]: value }))); });
test('DAT-006: SQL-shaped columns and unrestricted row sets rejected', t => { const h = fixture(t); assert.throws(() => h.f.runtime.issue(h.p(), runtimeInput({ columns: ['name; DROP TABLE resources'] })), hasCode('INV-403-SCOPE')); const cap = h.f.runtime.issue(h.p(), runtimeInput()); assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap, { columns: ['passport'] })), hasCode('INV-403-SCOPE')); });
test('RUN-007: cross-tenant capability cannot be consumed', t => { const h = fixture(t), cap = h.f.runtime.issue(h.p(), runtimeInput()); assert.throws(() => h.f.runtime.consume(h.p('operator', 'globex'), runtimeRequest(cap)), hasCode('INV-401-SIGNATURE')); });
test('RUN-004 IDN-008: device quarantine rejects issued capability immediately', t => { const h = fixture(t), cap = h.f.runtime.issue(h.p(), runtimeInput()); h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'Synthetic compromised device' }); assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap)), hasCode('INV-403-QUARANTINE')); });
test('RUN-003: stale configured device health prevents renewal', t => { const h = fixture(t); h.advance(86400001); assert.throws(() => h.f.runtime.issue(h.p(), runtimeInput()), hasCode('INV-403-HEALTH')); });
test('RUN-002: runtime request replay does not spend twice or return data twice', t => { const h = fixture(t), cap = h.f.runtime.issue(h.p(), runtimeInput()), request = runtimeRequest(cap); h.f.runtime.consume(h.p(), request); assert.throws(() => h.f.runtime.consume(h.p(), request), hasCode('INV-409-REPLAY')); });
test('NET-003 NET-004: local service envelope rejects other port and excess request rate', t => {
  const h = fixture(t), cap = h.f.runtime.issue(h.p(), runtimeInput({ action: 'service.connect', resource: 'erp-service', destination: 'erp-service', columns: [], row_ids: [] }));
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap, { port: 22 })), hasCode('INV-400-SCHEMA'));
  for (let i = 0; i < 20; i++) assert.equal(h.f.runtime.consume(h.p(), runtimeRequest(cap)).decision, 'ALLOW');
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap)), hasCode('INV-429-RATE'));
});
test('DAT-005 POL-004: restricted export requires explicit new SHIELD proposal', t => {
  const h = fixture(t), r = h.proposed('data.export', { dataset: 'dataset-1', columns: ['name', 'passport'], row_ids: ['row-1'], max_rows: 1, classification: 'internal', jurisdiction: 'EU' }, { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Operations' }, destination: 'customer-vault' });
  const decision = h.f.evaluate(h.p(), r.capsule.capsule_id); assert.equal(decision.decision, 'SHIELD'); assert.deepEqual(decision.transformation.columns, ['name']); assert.throws(() => h.f.certificate(h.p(), r.capsule.capsule_id), hasCode('INV-412-EVIDENCE'));
});
test('AUD-001 AUD-005: export verifies with pinned root and rejects edit, reorder, removal and wrong root', t => {
  const h = fixture(t); h.ready(); const bundle = h.f.exportAudit(h.p('auditor'), 'Offline verification'); assert.equal(verifyAudit(bundle, bundle.public_keys).valid, true);
  const changed = clone(bundle); changed.entries[0].envelope.payload.actor = 'attacker'; assert.throws(() => verifyAudit(changed, bundle.public_keys));
  const deleted = clone(bundle); deleted.entries.splice(2, 1); assert.throws(() => verifyAudit(deleted, bundle.public_keys));
  const reordered = clone(bundle); reordered.entries.reverse(); assert.throws(() => verifyAudit(reordered, bundle.public_keys)); assert.throws(() => verifyAudit(bundle, {}));
});
test('AUD-008: externally pinned prior checkpoint detects a fork and truncation', t => {
  const h = fixture(t); h.proposed(); const a = h.f.exportAudit(h.p('auditor'), 'Witness checkpoint'); h.proposed(); const b = h.f.exportAudit(h.p('auditor'), 'Later checkpoint');
  assert.equal(verifyAudit(b, a.public_keys, a.checkpoint.payload).valid, true); assert.throws(() => verifyAudit(b, a.public_keys, { ...a.checkpoint.payload, head: 'f'.repeat(64) }), hasCode('INV-409-FORK')); assert.throws(() => verifyAudit(a, a.public_keys, b.checkpoint.payload));
});
test('AUD-001: append-only triggers reject SQL update and deletion', t => { const h = fixture(t); assert.throws(() => h.f.store.db.exec("DELETE FROM audit WHERE tenant='acme'")); assert.throws(() => h.f.store.db.exec("UPDATE audit SET hash='forged' WHERE tenant='acme'")); });
test('AUD-007: audit export access is itself recorded', t => { const h = fixture(t), bundle = h.f.exportAudit(h.p('auditor'), 'Authorised inspection'); assert.equal(bundle.entries.at(-1).envelope.payload.type, 'AUDIT_ACCESSED'); });
test('DAT-012: expired evidence is held for active actions and legal hold; terminal evidence logically deleted', t => {
  const h = fixture(t), r = h.proposed(), ev = h.evidence(r); h.f.retention(h.p('security'), { evidence_id: ev.payload.evidence_id, legal_hold: true }); h.advance(700000); assert.equal(h.f.retentionSweep(h.p('security')).held, 1);
  h.f.retention(h.p('security'), { evidence_id: ev.payload.evidence_id, legal_hold: false }); assert.equal(h.f.retentionSweep(h.p('security')).held, 1); h.f.cancel(h.p(), r.capsule.capsule_id); assert.equal(h.f.retentionSweep(h.p('security')).deleted, 1); assert.equal(h.f.store.get('acme', 'evidence', ev.payload.evidence_id), null);
});
test('COV-002 COV-007 COV-008: no manual declaration can claim ENFORCED or production guarantee', t => {
  const h = fixture(t), input = { path_id: 'api-path', action_type: 'finance.payment.first', target: 'bank-1', environment: 'simulation', connector_version: '1.0.0', owner: 'security', status: 'MONITORED', max_age_ms: 60000, configuration_digest: digest({ configuration: 1 }) };
  h.f.declareCoverage(h.p('security'), input); const m = h.f.coverage(h.p()); assert.equal(m.payload.guarantee, false); assert.equal(m.protected.purpose, 'coverage'); assert.throws(() => h.f.declareCoverage(h.p('security'), { ...input, status: 'ENFORCED' }), hasCode('INV-400-SCHEMA'));
});
test('POL-010 UX-008: policy simulation records diff without activating candidate', t => { const h = fixture(t); h.proposed(); const p = clone(h.f.policy('acme')); p.rules['finance.payment.first'].max_quantity = 10; const result = h.f.simulate(h.p('policy-admin'), p); assert.ok(result.diff.length); assert.equal(result.activation, false); assert.notEqual(h.f.policy('acme').rules['finance.payment.first'].max_quantity, 10); });
test('POL-012: fewer than 3 customer bootstrap signers cannot start the service', t => { const h = fixture(t), config = clone(h.setup.config); config.tenants.acme.genesis_signatures.length = 2; assert.throws(() => { const f = new h.f.constructor(config, h.directory, h.now); f.close(); }, hasCode('INV-503-CONFIG')); });

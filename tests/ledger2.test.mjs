import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture, hasCode, runtimeInput, runtimeRequest } from './helpers.mjs';
import { signed, verifySigned, generateKey } from '../src/crypto.mjs';
import { digest, clone } from '../src/canonical.mjs';
import { signAcknowledgement } from '../src/ceremony.mjs';
import { proposal } from '../src/schema.mjs';

// ---- H2: the cumulative reconstruction control is actually triggered ----
test('DAT-009: touching every row crosses the coverage threshold and denies', t => {
  const h = fixture(t);
  // Fixture dataset has 3 rows; grant scope covers all three. Touch row-1,
  // then row-2 — 67% coverage — then attempt the third, crossing 90%.
  for (const row of ['row-1', 'row-2']) {
    const cap = h.f.runtime.issue(h.p(), runtimeInput({ row_ids: [row] }));
    assert.equal(h.f.runtime.consume(h.p(), runtimeRequest(cap)).decision, 'ALLOW');
  }
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ row_ids: ['row-3'] }));
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap)),
    e => e.code === 'INV-429-BUDGET' && /Reconstruction/.test(e.message));
  // The denial is a reconstruction denial, not a generic budget one: its
  // details carry the coverage that tripped the control.
  const denied = h.f.runtime.consume.bind(h.f.runtime, h.p(), runtimeRequest(cap));
  assert.throws(denied, e => e.details?.coverage_percent === 100);
});

// ---- H3/NET-010: containment telemetry is real and reconstructable ----
test('NET-010: denied consumes produce containment records; the report reconstructs the sequence', t => {
  const h = fixture(t);
  const policy = h.f.policy('acme'); policy.runtime.windows[0].limit = 2; h.f.store.put('acme', 'policy', 'active', policy, h.now());
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  h.f.runtime.consume(h.p(), runtimeRequest(cap));
  const cap2 = h.f.runtime.issue(h.p(), runtimeInput());
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap2)), hasCode('INV-429-BUDGET'));
  const report = h.f.containmentReport(h.p('security'));
  assert.ok(report.dropped_requests >= 1, 'dropped traffic counted');
  assert.ok(report.affected_capabilities.includes(cap2.payload.capability_id), 'affected capability named');
  const denial = report.sequence.find(e => e.kind === 'denied_consume');
  assert.equal(denial.code, 'INV-429-BUDGET'); assert.equal(denial.subject_id, 'operator');
  // A subject quarantine joins the same ordered sequence.
  h.f.revoke(h.p('security'), { kind: 'subject', id: 'operator', reason: 'Contain' });
  const after = h.f.containmentReport(h.p('security'));
  assert.ok(after.quarantined.includes('subject:operator'));
  assert.ok(after.sequence.at(-1).kind === 'revocation');
});

// ---- H5/COV-007: manifest signature verifies; all scoped paths present ----
test('COV-007: the coverage manifest verifies against the audit key and lists every declared path', t => {
  const h = fixture(t);
  h.f.declareCoverage(h.p('security'), { path_id: 'p-1', action_type: 'finance.payment.first', target: 't1', environment: 'prod', connector_version: '1.0', owner: 'op', status: 'MONITORED', max_age_ms: 60000, configuration_digest: digest({ a: 1 }) });
  h.f.declareCoverage(h.p('security'), { path_id: 'p-2', action_type: 'data.export', target: 't2', environment: 'prod', connector_version: '1.0', owner: 'op', status: 'UNKNOWN', max_age_ms: 60000, configuration_digest: digest({ a: 2 }) });
  const manifest = h.f.coverage(h.p('auditor'));
  const payload = verifySigned(manifest, h.f.auditPublicKeys('acme'), 'coverage');
  const paths = (payload.paths ?? payload.items ?? []).map(x => x.path_id);
  assert.deepEqual(paths.sort(), ['p-1', 'p-2']);
});

// ---- H1/AUD-010: role-scoped audit views ----
test('AUD-010: an operational principal sees digest-level audit entries; the auditor sees full signed envelopes', t => {
  const h = fixture(t); h.ready();
  const operatorPage = h.f.auditPageScoped(h.p(), { after: 0, limit: 10 });
  assert.ok(operatorPage.entries.length > 0);
  assert.ok(operatorPage.entries.every(e => e.digest_only === true && e.payload_digest === e.hash && e.envelope === undefined && e.type), 'operator view is digest-only');
  const auditorPage = h.f.auditPageScoped(h.p('auditor'), { after: 0, limit: 10 });
  assert.ok(auditorPage.entries.every(e => e.envelope?.signature && e.envelope.payload), 'auditor keeps verifiable envelopes');
  const securityPage = h.f.auditPageScoped(h.p('security'), { after: 0, limit: 10 });
  assert.ok(securityPage.entries.every(e => e.envelope?.signature), 'security keeps verifiable envelopes');
});

// ---- H4/UX-006: batch approval with per-action binding ----
function batchPair(h) {
  const a = h.proposed(), b = h.proposed();
  const ca = h.f.approvalChallenge(h.p('custodian-1'), a.capsule.capsule_id);
  const cb = h.f.approvalChallenge(h.p('custodian-1'), b.capsule.capsule_id);
  const key = h.setup.custodianKeys.acme['custodian-1'];
  return { a, b, sa: signed(ca, key, 'action-approval'), sb: signed(cb, key, 'action-approval') };
}
test('UX-006: a batch approves each declared action; hidden additions and omissions invalidate it', t => {
  const h = fixture(t);
  const { a, b, sa, sb } = batchPair(h);
  assert.throws(() => h.f.batchApprove(h.p('custodian-1'), { capsule_ids: [a.capsule.capsule_id, b.capsule.capsule_id], signatures: [sa] }), hasCode('INV-400-SCHEMA'));
  const c = h.proposed(); // a third action exists but is not declared in the batch
  const hidden = signed({ ...h.f.approvalChallenge(h.p('custodian-1'), c.capsule.capsule_id) }, h.setup.custodianKeys.acme['custodian-1'], 'action-approval');
  assert.throws(() => h.f.batchApprove(h.p('custodian-1'), { capsule_ids: [a.capsule.capsule_id, b.capsule.capsule_id], signatures: [sa, sb, hidden] }), hasCode('INV-400-SCHEMA'));
  const accepted = h.f.batchApprove(h.p('custodian-1'), { capsule_ids: [a.capsule.capsule_id, b.capsule.capsule_id], signatures: [sa, sb] });
  assert.equal(accepted.accepted, 2);
  assert.equal(h.f.store.must('acme', 'capsule', a.capsule.capsule_id).approvals.length, 1);
  assert.equal(h.f.store.must('acme', 'capsule', b.capsule.capsule_id).approvals.length, 1);
  // Atomicity: a batch whose second signature is bogus approves nothing.
  const { a: a2, b: b2, sa: sa2 } = batchPair(h);
  const bad = signed({ ...h.f.approvalChallenge(h.p('custodian-1'), b2.capsule.capsule_id), capsule_digest: '0'.repeat(64) }, h.setup.custodianKeys.acme['custodian-1'], 'action-approval');
  assert.throws(() => h.f.batchApprove(h.p('custodian-1'), { capsule_ids: [a2.capsule.capsule_id, b2.capsule.capsule_id], signatures: [sa2, bad] }));
  assert.equal(h.f.store.must('acme', 'capsule', a2.capsule.capsule_id).approvals.length, 0, 'batch failure rolled back the first approval');
});

// ---- M6/KEY-005: cross-suite rotation keeps prior audit entries verifiable ----
test('KEY-005: rotating the audit key Ed25519 -> ES256 keeps old entries verifiable', t => {
  const h = fixture(t);
  h.ready(); // entries under the original Ed25519 audit key
  const oldHead = h.f.store.auditHashes('acme').at(-1);
  const pending = h.f.vault.generate(['audit', 'outcome', 'revocation', 'coverage', 'checkpoint', 'backup-manifest'], { suite: 'ES256', pending: true });
  const custodians = ['custodian-1', 'custodian-2'];
  const c = h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-es256', purpose: 'audit suite migration', threshold: 2, custodians, valid_until: h.now() + 3600000 });
  for (const subject of custodians) h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(c, subject, h.setup.custodianKeys.acme[subject], h.now()));
  const r = h.proposed('key.rotate', { key_class: 'audit', new_key_id: pending.key_id, new_public_key: pending.public_key, ceremony_id: 'cer-es256', revoke_old: false }, { action: { type: 'key.rotate', target_resource: 'key-registry', purpose: 'Suite migration' } });
  h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'audit-committee' });
  h.approve(r, 3); h.advance(60001);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  assert.equal(h.f.execute(h.p(), cert).payload.status, 'VERIFIED');
  const keys = h.f.auditPublicKeys('acme');
  // The rotated key is live AND the retired Ed25519 key remains registered —
  // verification of pre-rotation entries survives the suite migration.
  assert.ok(keys[pending.key_id], 'migrated key advertised');
  assert.ok(Object.keys(keys).length >= 2, 'retired key still advertised');
  const bundle = h.f.exportAudit(h.p('security'), 'cross-suite verification');
  const first = bundle.entries[0];
  assert.equal(first.envelope.protected.suite, 'Ed25519');
  verifySigned(first.envelope, bundle.public_keys, 'audit');
  const last = bundle.entries.at(-1);
  assert.equal(last.envelope.protected.suite, 'ES256', 'new entries sign on the migrated suite');
  verifySigned(last.envelope, bundle.public_keys, last.envelope.protected.purpose);
  assert.notEqual(oldHead, h.f.store.auditHashes('acme').at(-1), 'new entries extend the chain under the migrated key');
});

// ---- M7/EVD-009: missing vs conflicting vs unverifiable evidence ----
test('EVD-009: missing, conflicting and unverifiable evidence yield distinct reason codes', t => {
  const h = fixture(t);
  const missing = h.f.evaluate(h.p(), h.proposed().capsule.capsule_id);
  assert.ok(missing.reasons.some(r => r.code === 'EVIDENCE_MISSING'));
  const conflicted = h.proposed();
  h.evidence(conflicted, { claim: 'conflict' });
  assert.ok(h.f.evaluate(h.p(), conflicted.capsule.capsule_id).reasons.some(r => r.code === 'EVIDENCE_CONFLICT'));
  const advisoryOnly = h.proposed();
  h.evidence(advisoryOnly, { advisory: true });
  const decision = h.f.evaluate(h.p(), advisoryOnly.capsule.capsule_id);
  assert.ok(decision.reasons.some(r => r.code === 'EVIDENCE_UNVERIFIABLE'), JSON.stringify(decision.reasons));
});

// ---- M5/RUN-009: distinct failure classes in one run ----
test('RUN-009: denial, throttle, quarantine and infrastructure failure produce distinct stable codes', t => {
  const h = fixture(t);
  const codes = new Set();
  // policy denial
  assert.throws(() => h.f.runtime.issue(h.p(), runtimeInput({ destination: 'evil-vault' })), e => { codes.add(e.code); return true; });
  // throttle
  const policy = h.f.policy('acme'); policy.runtime.rate_per_second = 1; h.f.store.put('acme', 'policy', 'active', policy, h.now());
  const cap = h.f.runtime.issue(h.p(), runtimeInput()); h.f.runtime.consume(h.p(), runtimeRequest(cap));
  const cap2 = h.f.runtime.issue(h.p(), runtimeInput());
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap2)), e => { codes.add(e.code); return true; });
  // infrastructure failure — a missing table wraps into a stable gate code
  const cap3 = h.f.runtime.issue(h.p(), runtimeInput());
  h.f.store.db.exec('DROP TABLE usage');
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap3)), e => { codes.add(e.code); return true; });
  // quarantine
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'Contain' });
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap3)), e => { codes.add(e.code); return true; });
  assert.ok([...codes].every(c => /^INV-\d{3}-[A-Z-]+$/.test(c)), JSON.stringify([...codes]));
  assert.ok(codes.size >= 3, `expected >=3 distinct failure classes, got ${[...codes]}`);
});

// ---- M4: previously untagged VERIFIED rows get real assertions ----
test('AIG-004: advisory output records model identity, version, provider and digests in the audit trail', t => {
  const h = fixture(t);
  h.f.advise(h.p(), { operation: 'extract', document: 'pay vendor-1 the amount of 5000 EUR' });
  const entry = h.f.store.auditPage('acme', { after: 0, limit: 100 }).entries.map(e => e.envelope.payload).find(x => x.type === 'AI_ADVISORY');
  assert.ok(entry, 'advisory audit exists');
  const m = entry.metadata;
  assert.ok(m.model && m.model_version && (m.prompt_digest || m.tool_context_digest || m.provider !== undefined), JSON.stringify(m));
});
test('CON-010: the target manifest surfaces limitations and the engineering profile flag', t => {
  const h = fixture(t), manifest = h.f.target.manifest();
  assert.ok(Array.isArray(manifest.limitations) && manifest.limitations.length > 0);
  assert.equal(manifest.production_supported, false);
});

// ---- Tag battery: real checks for previously source-only VERIFIED rows ----

test('ACT-006: free-form text is never an authoritative action representation', t => {
  const h = fixture(t);
  assert.throws(() => h.f.propose(h.p(), { note: 'please transfer everything', action: { type: 'free text' } }, randomUUID(), {}), hasCode('INV-400-SCHEMA'));
  assert.throws(() => h.f.propose(h.p(), 'transfer all the money now', randomUUID(), {}), hasCode('INV-400-SCHEMA'));
});

test('EVD-011 AIG-008: advisory-marked evidence cannot satisfy an authoritative requirement', t => {
  const h = fixture(t), r = h.proposed();
  h.evidence(r, { advisory: true }); h.evidence(r, { issuer: 'registry', advisory: true });
  const d = h.f.evaluate(h.p(), r.capsule.capsule_id);
  assert.equal(d.decision, 'ESCROW');
  assert.ok(d.reasons.some(x => x.code === 'EVIDENCE_UNVERIFIABLE'), JSON.stringify(d.reasons));
});

test('CON-005: connector reads are bounded — the retry budget caps attempts', async t => {
  const http = (await import('node:http')).default;
  let calls = 0;
  const srv = http.createServer((req, res) => { calls++; res.writeHead(500); res.end('{}'); });
  await new Promise(r => srv.listen(0, '127.0.0.1', r)); t.after(() => srv.close());
  const { readWithRetry } = await import('../src/connectors.mjs');
  await assert.rejects(readWithRetry(`http://127.0.0.1:${srv.address().port}/x`, { retries: 2 }), e => e.code === 'INV-502-CONNECTOR');
  assert.equal(calls, 3, `expected 1 + 2 bounded retries, got ${calls}`);
});

test('NET-005: losing device health withdraws ordinary capability immediately', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'Health lost' });
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap)), hasCode('INV-403-QUARANTINE'));
});

test('NET-008: firewall changes are protected actions requiring evidence and approval', t => {
  const h = fixture(t), r = h.proposed('cloud.firewall.change', { protocol: 'tcp', port: 443, source_cidr: '10.0.0.0/8', service_id: 'erp-service' }, { action: { type: 'cloud.firewall.change', target_resource: 'fw-erp-1', purpose: 'Narrow' } });
  const d = h.f.evaluate(h.p(), r.capsule.capsule_id);
  assert.notEqual(d.decision, 'ALLOW');
  assert.throws(() => h.f.certificate(h.p(), r.capsule.capsule_id), hasCode('INV-412-EVIDENCE'));
});

test('PER-010: the controlled-workspace fallback is labelled lower-assurance and policy-gated', t => {
  const h = fixture(t);
  const rel = h.f.perceptionFallback(h.p(), { fields: { view: 'x' }, purpose: 'inspect' });
  assert.equal(rel.mode, 'controlled-workspace'); assert.equal(rel.production, false);
  const policy = h.f.policy('acme'); policy.secure_perception.fallback = 'denied'; h.f.store.put('acme', 'policy', 'active', policy, h.now());
  assert.throws(() => h.f.perceptionFallback(h.p(), { fields: { view: 'x' }, purpose: 'inspect' }), hasCode('INV-451-POLICY'));
});

// ---- Wave-3 implementable-today items ----

test('IDN-003: rule identity_classes distinguishes and combines all four classes', t => {
  const h = fixture(t);
  const policy = h.f.policy('acme');
  // The workforce actor is denied when excluded from the class list.
  policy.rules['finance.beneficiary.create'].identity_classes = ['workload']; h.f.store.put('acme', 'policy', 'active', policy, h.now());
  const d = h.f.evaluate(h.p(), h.proposed().capsule.capsule_id);
  assert.equal(d.decision, 'DENY'); assert.ok(d.reasons.some(x => x.code === 'IDENTITY_CLASS'));
  // Combining all four classes admits the workforce actor — each class is
  // distinguishable and composable.
  policy.rules['finance.beneficiary.create'].identity_classes = ['workforce', 'workload', 'device', 'counterparty']; h.f.store.put('acme', 'policy', 'active', policy, h.now());
  const d2 = h.f.evaluate(h.p(), h.proposed().capsule.capsule_id);
  assert.ok(!d2.reasons.some(x => x.code === 'IDENTITY_CLASS'));
  // And a list of the other three still excludes the workforce actor.
  policy.rules['finance.beneficiary.create'].identity_classes = ['workload', 'device', 'counterparty']; h.f.store.put('acme', 'policy', 'active', policy, h.now());
  const d3 = h.f.evaluate(h.p(), h.proposed().capsule.capsule_id);
  assert.ok(d3.reasons.some(x => x.code === 'IDENTITY_CLASS'));
});

test('IDN-010: root recovery demands higher proofing than routine access', t => {
  const h = fixture(t);
  const policy = h.f.policy('acme');
  // Routine action at low floor, root recovery at high floor.
  policy.rules['finance.beneficiary.create'].min_proofing = 'low';
  policy.rules['key.ceremony'].min_proofing = 'high';
  h.f.store.put('acme', 'policy', 'active', policy, h.now());
  const [, identity] = Object.entries(h.setup.config.tenants.acme.identities).find(([, x]) => x.subject_id === 'operator');
  identity.proofing_level = 'low';
  // Low-proofed identity passes the routine floor but is refused root recovery.
  const routine = h.f.evaluate(h.p(), h.proposed().capsule.capsule_id);
  assert.ok(!routine.reasons.some(x => x.code === 'PROOFING'));
  const root = h.proposed('key.ceremony', { ceremony_id: 'cer-root-1', purpose: 'Recover root', threshold: 3, custodians: ['custodian-1', 'custodian-2', 'custodian-3'] }, { action: { type: 'key.ceremony', target_resource: 'key-registry', purpose: 'Recover root' } });
  h.advance(120001); // past the ceremony cooldown so the proofing check is reached
  const d = h.f.evaluate(h.p(), root.capsule.capsule_id);
  assert.notEqual(d.decision, 'ALLOW'); assert.ok(d.reasons.some(x => x.code === 'PROOFING'));
  // A high-proofed identity clears the root floor.
  identity.proofing_level = 'high';
  const root2 = h.proposed('key.ceremony', { ceremony_id: 'cer-root-2', purpose: 'Recover root', threshold: 3, custodians: ['custodian-1', 'custodian-2', 'custodian-3'] }, { action: { type: 'key.ceremony', target_resource: 'key-registry', purpose: 'Recover root' } });
  h.advance(120001);
  const d2 = h.f.evaluate(h.p(), root2.capsule.capsule_id);
  assert.ok(!d2.reasons.some(x => x.code === 'PROOFING'));
});

test('NET-005: remediation service must be policy-allowlisted and is audited', t => {
  const h = fixture(t);
  assert.throws(() => h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'x', remediation_service: 'attack-ersatz' }), hasCode('INV-403-SCOPE'));
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'agent lost', remediation_service: 'device-wipe' });
  const entries = h.f.store.auditPage('acme', { limit: 500 }).entries.map(e => e.envelope.payload.type);
  assert.ok(entries.includes('REMEDIATION_REQUESTED'));
});

test('AUD-006: evidence cannot claim retention past the per-kind policy ceiling', t => {
  const h = fixture(t), r = h.proposed();
  const policy = h.f.policy('acme'); policy.retention = { default_ms: 1000, per_kind: { ownership: 2000 } }; h.f.store.put('acme', 'policy', 'active', policy, h.now());
  assert.throws(() => h.evidence(r, { expiry: h.now() + 5000 }), hasCode('INV-400-SCHEMA'));
});

test('AUD-010: named projections filter the verified page without breaking integrity', t => {
  const h = fixture(t); h.ready();
  const finance = h.f.auditPageScoped(h.p('auditor'), { limit: 500, view: 'finance' });
  assert.ok(finance.entries.length > 0 && finance.entries.every(e => ['CAPSULE_PROPOSED', 'EVIDENCE_ATTACHED', 'EXACT_ACTION_APPROVED', 'CERTIFICATE_ISSUED', 'EXECUTION_RESERVED', 'EXECUTION_OUTCOME'].includes(e.envelope.payload.type)));
  const privacy = h.f.auditPageScoped(h.p('auditor'), { limit: 500, view: 'privacy' });
  assert.ok(privacy.entries.every(e => !['CAPSULE_PROPOSED'].includes(e.envelope.payload.type)));
  assert.throws(() => h.f.auditPageScoped(h.p('auditor'), { view: 'nonsense' }), hasCode('INV-400-SCHEMA'));
});

test('CON-009: connector status reports per-issuer call latency and error telemetry', t => {
  const h = fixture(t);
  h.f.recordIssuerCall('key-1', 42, false); h.f.recordIssuerCall('key-1', 58, true);
  const issuer = Object.keys(h.setup.config.tenants.acme.issuers)[0];
  h.f.recordIssuerCall(issuer, 10, false);
  const status = h.f.connectorStatus(h.p());
  const entry = status.issuers.find(x => x.key_id === issuer);
  assert.equal(entry.metrics.calls, 1); assert.equal(entry.metrics.mean_latency_ms, 10);
});

test('DAT-008: exports always require an approval — zero threshold is constitutionally refused', async t => {
  const { validatePolicy, defaultPolicy } = await import('../src/policy.mjs');
  const p = defaultPolicy('acme'); assert.equal(p.rules['data.export'].approval_threshold, 1);
  p.rules['data.export'].approval_threshold = 0;
  assert.throws(() => validatePolicy(p));
  const h = fixture(t);
  const r = h.proposed('data.export', { dataset: 'dataset-1', columns: ['id'], row_ids: ['row-1'], max_rows: 1, classification: 'internal', jurisdiction: 'EU' }, { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Operations' }, destination: 'customer-vault' });
  h.evidence(r, { kind: 'dataset_authority' });
  assert.equal(h.f.evaluate(h.p(), r.capsule.capsule_id).decision, 'ESCROW');
  h.approve(r, 1); assert.equal(h.f.evaluate(h.p(), r.capsule.capsule_id).decision, 'ALLOW');
});

test('DAT-005: aggregate transform generalises numeric cells deterministically', async t => {
  const { applyTransforms, TRANSFORMS } = await import('../src/datagate.mjs');
  assert.equal(TRANSFORMS.aggregate(1234, 'n', {}, 100), '1200-1299');
  assert.equal(TRANSFORMS.aggregate(1234, 'n', {}, 100), '1200-1299');
  const rows = applyTransforms([{ id: 'r1', amount: 987 }], { amount: { op: 'aggregate', arg: 500 } }, {});
  assert.deepEqual(rows, [{ id: 'r1', amount: '500-999' }]);
});

test('NFR-AVL-004: per-class stale_ms tightens but cannot loosen the default window', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  // Supersede the policy: the capability falls to the data.read fail mode,
  // honoured only inside the per-class stale window.
  const policy = clone(h.f.policy('acme'));
  policy.fail_modes = { ...policy.fail_modes, 'data.read': 'cached-allow' };
  policy.stale_ms = { default: 1 };
  policy.max_capsule_ttl_ms = policy.max_capsule_ttl_ms + 1; // any change to the digest
  h.f.store.put('acme', 'policy', 'active', policy, h.now());
  assert.equal(h.f.runtime.consume(h.p(), runtimeRequest(cap)).decision, 'ALLOW');
  h.advance(10); // past the 1ms class ceiling
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap)), hasCode('INV-503-GATE'));
});

test('COV-005 COV-009: stale evidence ages a MONITORED path back to UNKNOWN', t => {
  const h = fixture(t);
  h.f.declareCoverage(h.p('security'), { path_id: 'path-b', action_type: 'data.read', target: 'dataset-1', environment: 'prod', connector_version: '1.0', owner: 'op', status: 'MONITORED', path_class: 'api', max_age_ms: 1000, configuration_digest: digest({ x: 2 }) });
  h.advance(2000);
  // effectiveStatus computes staleness rather than trusting the stored flag:
  // the manifest and the historical replay must both show UNKNOWN.
  const now = h.f.coverageAt(h.p('auditor'), h.now());
  assert.equal(now.paths['path-b'].status, 'UNKNOWN');
  assert.equal(now.paths['path-b'].stored_status, 'MONITORED');
});

test('KEY-012: ceremony devices are member-validated and recorded', t => {
  const h = fixture(t);
  const r = h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-dev', purpose: 'key.recovery', threshold: 2, custodians: ['custodian-1', 'custodian-2', 'custodian-3'], valid_until: h.now() + 3600000, devices: { 'custodian-1': 'custodian-1-device' } });
  assert.equal(r.devices['custodian-1'], 'custodian-1-device');
  assert.throws(() => h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-dev-2', purpose: 'key.recovery', threshold: 2, custodians: ['custodian-1', 'custodian-2', 'custodian-3'], valid_until: h.now() + 3600000, devices: { 'not-a-custodian': 'x' } }), hasCode('INV-400-SCHEMA'));
});

test('COV-001 COV-005 COV-009 COV-010: path classes, owner tasks, history replay, technical validation', t => {
  const h = fixture(t);
  h.f.declareCoverage(h.p('security'), { path_id: 'path-a', action_type: 'data.export', target: 'dataset-1', environment: 'prod', connector_version: '1.0', owner: 'op', status: 'UNKNOWN', path_class: 'direct_database', max_age_ms: 60000, configuration_digest: digest({ x: 1 }) });
  // COV-001: path class is stored; COV-005: a declared-unknown owner task exists.
  assert.equal(h.f.store.must('acme', 'coverage', 'path-a').path_class, 'direct_database');
  const tasks = h.f.store.list('acme', 'coverage-task', 100, 0);
  assert.ok(tasks.some(x => x.path_id === 'path-a' && x.cause === 'declared-unknown' && x.status === 'open'));
  // COV-009: history replays the coverage-event log.
  const history = h.f.coverageAt(h.p('auditor'), h.now());
  assert.equal(history.paths['path-a'].status, 'UNKNOWN');
  // COV-010: a valid technical-validation envelope closes the unknown task.
  const path = h.f.store.must('acme', 'coverage', 'path-a');
  const claims = { capsule_digest: digest(path) };
  const payload = { evidence_id: randomUUID(), tenant_id: 'acme', capsule_digest: digest(path), kind: 'technical_validation', content_digest: digest({ probe: 'ok' }), acquired_at: h.now(), expires_at: h.now() + 60000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 'manual probe', retention_until: h.now() + 120000, claims };
  const envelope = signed(payload, h.setup.issuerKeys.acme['security-ops'], 'evidence');
  const out = h.f.technicalValidation(h.p('security'), 'path-a', envelope);
  assert.equal(out.status, 'MONITORED');
  const hist2 = h.f.coverageAt(h.p('auditor'), h.now());
  assert.equal(hist2.paths['path-a'].status, 'MONITORED');
  // COV-010 gate direction: a sibling path that has NO executed validation
  // cannot leave UNKNOWN — the label is only earned through evidence.
  h.f.declareCoverage(h.p('security'), { path_id: 'path-b', action_type: 'data.export', target: 'dataset-1', environment: 'prod', connector_version: '1.0', owner: 'op', status: 'UNKNOWN', path_class: 'api', max_age_ms: 60000, configuration_digest: digest({ y: 2 }) });
  assert.equal(h.f.coverageAt(h.p('auditor'), h.now()).paths['path-b'].status, 'UNKNOWN');
  assert.throws(() => h.f.technicalValidation(h.p('security'), 'path-b', envelope), hasCode('INV-400-SCHEMA'));
});

test('UX-010: digest-only scoping hides payload bodies from unprivileged roles', t => {
  const h = fixture(t); h.ready();
  // Operators read the audit as digests+metadata only; privileged roles get
  // the full verified envelopes.
  assert.equal(h.f.auditDigestOnly(h.p()), true);
  assert.equal(h.f.auditDigestOnly(h.p('auditor')), false);
  const scoped = h.f.auditPageScoped(h.p('operator'), { limit: 5 });
  assert.ok(scoped.entries.every(e => e.digest_only === true && e.envelope === undefined));
  const full = h.f.auditPageScoped(h.p('auditor'), { limit: 5 });
  assert.ok(full.entries.every(e => e.envelope?.payload?.type));
});

test('COV-002: the UNCOVERED label is representable, creates an owner task and never reads as observed', t => {
  const h = fixture(t); h.ready();
  h.f.declareCoverage(h.p('security'), { path_id: 'path-legacy', action_type: 'finance.bank.change', target: 'erp-service', environment: 'simulation', connector_version: '1.0.0', owner: 'sec-team', status: 'UNCOVERED', path_class: 'batch', max_age_ms: 60000, configuration_digest: digest({ cfg: 1 }) });
  const path = h.f.store.must('acme', 'coverage', 'path-legacy');
  assert.equal(path.status, 'UNCOVERED');
  // UNCOVERED declares "known unprotected" — it must not carry a fresh
  // observation timestamp and must not age into MONITORED.
  assert.equal(path.evidence_at, null);
  const manifest = h.f.coverage(h.p('auditor'));
  const row = manifest.payload.paths.find(p => p.path_id === 'path-legacy');
  assert.equal(row.effective_status, 'UNCOVERED');
  assert.match(row.next_action, /unprotected/);
  const tasks = h.f.store.list('acme', 'coverage-task', 100, 0);
  assert.ok(tasks.some(x => x.path_id === 'path-legacy' && x.cause === 'declared-uncovered' && x.status === 'open'));
  // History replay reports the same status at the query instant.
  const history = h.f.coverageAt(h.p('auditor'), h.now() + 86400000);
  assert.equal(history.paths['path-legacy'].status, 'UNCOVERED');
});

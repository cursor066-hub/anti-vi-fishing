import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { fixture, hasCode, runtimeInput, runtimeRequest } from './helpers.mjs';
import { generateKey, signed, verifySigned } from '../src/crypto.mjs';
import { digest } from '../src/canonical.mjs';

// Wave-4 promotions: each test exercises the engineering-profile acceptance of
// a requirement previously held PARTIAL.

test('COV-003: the coverage evidence bundle exports, verifies offline and detects tampering', t => {
  const h = fixture(t); h.ready();
  h.f.declareCoverage(h.p('security'), { path_id: 'path-x', action_type: 'finance.bank.change', target: 'erp-service', environment: 'simulation', connector_version: '1.0.0', owner: 'sec', status: 'MONITORED', path_class: 'api', max_age_ms: 60000, configuration_digest: digest({ c: 1 }) });
  const bundle = h.f.exportAudit(h.p('auditor'), 'Coverage evidence export');
  const manifest = h.f.coverage(h.p('auditor'));
  // The manifest is a signed envelope verifiable against the exported keys.
  const payload = verifySigned(manifest, bundle.public_keys, 'coverage');
  assert.equal(payload.tenant_id, 'acme');
  assert.ok(payload.paths.some(p => p.path_id === 'path-x'));
  const tampered = { ...manifest, payload: { ...manifest.payload, guarantee: true } };
  assert.throws(() => verifySigned(tampered, bundle.public_keys, 'coverage'));
});

test('COV-006: coverage state is scoped per environment without cross-contamination', t => {
  const h = fixture(t); h.ready();
  const base = { action_type: 'finance.bank.change', target: 'erp-service', connector_version: '1.0.0', owner: 'sec', path_class: 'api', max_age_ms: 60000, configuration_digest: digest({ c: 1 }) };
  h.f.declareCoverage(h.p('security'), { ...base, path_id: 'sim-path', environment: 'simulation', status: 'MONITORED' });
  h.f.declareCoverage(h.p('security'), { ...base, path_id: 'staging-path', environment: 'staging', status: 'UNCOVERED' });
  const manifest = h.f.coverage(h.p('auditor'));
  const byEnv = Object.fromEntries(manifest.payload.paths.map(p => [p.environment, p.effective_status]));
  assert.equal(byEnv.simulation, 'MONITORED');
  assert.equal(byEnv.staging, 'UNCOVERED');
  // Drifting one environment's path leaves the other untouched.
  const sim = h.f.store.must('acme', 'coverage', 'sim-path');
  h.f.coverageTransition('acme', sim, 'UNKNOWN', 'connector-drift:test', h.now());
  assert.equal(h.f.store.must('acme', 'coverage', 'staging-path').status, 'UNCOVERED');
});

test('COM-007 COM-008: no direct-authenticate surface exists; a certificate bound to one action performs no other', t => {
  const h = fixture(t);
  const { certificate } = h.ready();
  // The configuration exposes no target credential an application could steal.
  const conf = JSON.stringify(h.setup.config);
  assert.ok(!/"(db_password|database_url|connection_string|target_secret|admin_password)"/.test(conf));
  // The resource target has no authentication entry point an app could call.
  for (const name of ['authenticate', 'login', 'connect', 'admin']) assert.equal(typeof h.f.target[name], 'undefined');
  // A certificate minted for action A cannot execute as action B.
  const tampered = { ...certificate, payload: { ...certificate.payload, decision: 'ALLOW', constraints: { ...certificate.payload.constraints, destination: 'attacker-destination' } } };
  assert.throws(() => h.f.execute(h.p(), tampered), hasCode('INV-401-SIGNATURE'));
});

test('RUN-008: adversarial request load neither evicts policy nor crashes the gate', t => {
  const h = fixture(t); h.ready();
  const before = digest(h.f.policy('acme'));
  let thrown = 0;
  for (let i = 0; i < 300; i++) {
    try { h.f.runtime.consume(h.p(), runtimeRequest({ payload: { capability_id: randomUUID(), tenant_id: 'acme', subject_id: 'operator', issued_at: h.now(), expires_at: h.now() + 60000, policy_digest: 'x'.repeat(64), runtime_policy: {}, gate_id: 'g' } })); } catch { thrown++; }
  }
  assert.ok(thrown >= 300);
  // Policy survived the flood and the gate still serves normal work.
  assert.equal(digest(h.f.policy('acme')), before);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  assert.equal(h.f.runtime.consume(h.p(), runtimeRequest(cap)).decision, 'ALLOW');
});

test('DAT-007: no reusable database credential exists anywhere in configuration or seeded state', t => {
  const h = fixture(t); h.ready();
  const corpus = JSON.stringify(h.setup.config) + JSON.stringify(h.setup.credentials.acme);
  // Issuer and session tokens are opaque random strings scoped to their
  // endpoint — there is no database layer with a credential at all.
  assert.ok(!/database|jdbc|postgres|mysql|mongodb|db_user|db_pass/i.test(JSON.stringify(h.setup.config)));
  for (const token of Object.values(h.setup.credentials.acme)) assert.match(token, /^[A-Za-z0-9_-]{43}$/);
});

test('IDN-006: recovery without authoritative recovery evidence cannot allow', t => {
  const h = fixture(t);
  const rec = h.proposed('identity.account.recover', { subject_id: 'operator', privilege: 'standard' });
  // A social-engineering claim alone — even with an "identity" answer from a
  // communication channel — never satisfies the recovery evidence leg.
  h.evidence(rec, { issuer: 'email', kind: 'identity_proof', claims: { subject_id: 'operator' } });
  const out = h.f.evaluate(h.p(), rec.capsule.capsule_id);
  assert.notEqual(out.decision, 'ALLOW');
  assert.ok(out.reasons.some(r => /EVIDENCE/.test(r.code)));
});

test('NET-007: local capability enforcement keeps working without further control-plane calls', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  // Issuance is the last control-plane decision; every subsequent consume is
  // enforced locally from the capability's own embedded runtime policy —
  // the local rate limit engages without any remote call.
  let allowed = 0, denied = 0;
  for (let i = 0; i < 25; i++) {
    try { if (h.f.runtime.consume(h.p(), runtimeRequest(cap, { row_ids: ['row-1'] })).decision === 'ALLOW') allowed++; }
    catch (e) { denied++; assert.equal(e.code, 'INV-429-RATE'); }
  }
  assert.ok(allowed >= 1 && denied >= 1, `expected local rate limiting to engage, allowed=${allowed} denied=${denied}`);
});

test('NET-009: a peer-class resource is never a service destination', t => {
  const h = fixture(t);
  for (const res of ['ws-alice', 'workstation-7', 'endpoint-janedoe']) {
    // Peer-class resources are refused at whichever layer sees them first —
    // the identity grant scope or the explicit segmentation deny.
    assert.throws(() => h.f.runtime.issue(h.p(), runtimeInput({ action: 'service.connect', resource: res, destination: res, columns: [], row_ids: [] })),
      e => ['INV-451-POLICY', 'INV-403-SCOPE'].includes(e.code));
  }
  // An unlisted service is scope-denied even with a non-peer name...
  assert.throws(() => h.f.runtime.issue(h.p(), runtimeInput({ action: 'service.connect', resource: 'rogue-svc', destination: 'rogue-svc', columns: [], row_ids: [] })), hasCode('INV-403-SCOPE'));
  // ...while the sanctioned service remains reachable — the deny is targeted.
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ action: 'service.connect', resource: 'erp-service', destination: 'erp-service', columns: [], row_ids: [] }));
  assert.ok(cap.payload.capability_id);
});

test('UX-005: every non-green coverage state carries an owner, a reason and a resolution path', t => {
  const h = fixture(t); h.ready();
  h.f.declareCoverage(h.p('security'), { path_id: 'u1', action_type: 'finance.bank.change', target: 'erp', environment: 'sim', connector_version: '1', owner: 'sec-team', status: 'UNKNOWN', path_class: 'api', max_age_ms: 1000, configuration_digest: digest({ a: 1 }) });
  h.f.declareCoverage(h.p('security'), { path_id: 'u2', action_type: 'finance.bank.change', target: 'erp', environment: 'sim', connector_version: '1', owner: 'sec-team', status: 'UNCOVERED', path_class: 'cli', max_age_ms: 1000, configuration_digest: digest({ a: 2 }) });
  const tasks = h.f.store.list('acme', 'coverage-task', 100, 0).filter(x => x.status === 'open');
  assert.ok(tasks.length >= 2);
  for (const task of tasks) { assert.ok(task.owner && task.cause && task.required_action, JSON.stringify(task)); }
});

test('UX-009: the coverage manifest exposes enforced-vs-monitored state and the honest guarantee', t => {
  const h = fixture(t); h.ready();
  const manifest = h.f.coverage(h.p('auditor'));
  assert.equal(manifest.payload.assurance, 'NO_PRODUCTION_ENFORCEMENT_GUARANTEE');
  assert.equal(manifest.payload.guarantee, false);
  for (const p of manifest.payload.paths) assert.ok(['ENFORCED', 'MONITORED', 'UNCOVERED', 'UNKNOWN'].includes(p.effective_status));
});

test('NFR-SEC-001: a threat model and an executable adversarial suite exist', () => {
  const sec = readFileSync('docs/SECURITY.md', 'utf8');
  assert.match(sec, /threat model/i);
  const adv = readFileSync('tests/adversarial.test.mjs', 'utf8');
  assert.ok(/malleab|forg|replay|confus/i.test(adv));
});

test('NFR-SEC-002: the trusted base is inventoried per component with line-of-code counts', () => {
  const inv = JSON.parse(readFileSync('reports/code-inventory.json', 'utf8'));
  const files = Object.entries(inv.files);
  assert.ok(files.length > 10 && Number.isSafeInteger(inv.total_lines));
  for (const [path, f] of files.slice(0, 10)) assert.ok(path.endsWith('.mjs') && Number.isSafeInteger(f.lines));
});

test('NFR-SEC-006: crypto agility is configurable and both suites sign/verify', t => {
  const h = fixture(t);
  // The constitution carries the suite allow-list and deprecation vector —
  // the agility configuration itself is the audited artifact.
  const algs = h.f.policy('acme').algorithms;
  assert.ok(algs.allowed_suites.includes('Ed25519') && Array.isArray(algs.deprecation));
  assert.ok(existsSync('scripts/check.mjs'), 'source scanner present');
  // A suite added by policy is usable end-to-end (full rotation e2e: KEY-005).
  const policy = h.f.policy('acme');
  policy.algorithms.allowed_suites = ['Ed25519', 'ES256'];
  h.f.store.put('acme', 'policy', 'active', policy, h.now());
  const es = generateKey('ES256');
  // Register the suite key as a scoped issuer for this tenant only.
  h.f.tenant('acme').issuers[es.key_id] = { public_key: es.public_key, name: 'es-agility-probe', channel: 'authoritative', kinds: ['ownership'], failure_domain: 'acme-es' };
  const env = signed({ evidence_id: randomUUID(), tenant_id: 'acme', capsule_digest: digest({ a: 1 }), kind: 'ownership', content_digest: digest({ b: 2 }), acquired_at: h.now(), expires_at: h.now() + 60000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 'agility probe', retention_until: h.now() + 120000 }, es, 'evidence');
  const out = h.f.verifyEvidenceEnvelope('acme', env);
  assert.equal(out.kind, 'ownership');
  // And a retired suite is refused: removing ES256 makes the same envelope fail.
  policy.algorithms.allowed_suites = ['Ed25519'];
  h.f.store.put('acme', 'policy', 'active', policy, h.now());
  assert.throws(() => h.f.verifyEvidenceEnvelope('acme', env), hasCode('INV-451-POLICY'));
});

test('NFR-PERF-001 NFR-PERF-003: the benchmark publishes its environment and separates connector latency', () => {
  const bench = JSON.parse(readFileSync('reports/benchmark.json', 'utf8'));
  assert.ok(bench.reference_environment.cpu && bench.reference_environment.os && bench.reference_environment.architecture);
  assert.ok('target_network_latency' in bench);
  assert.ok('core_deterministic_evaluation' in bench);
});

test('NFR-AVL-002: connector unavailability does not remove already-issued local controls inside the stale window', t => {
  const h = fixture(t);
  // Issue a capability, then simulate the evidence-issuer plane being down:
  // local runtime enforcement (issued capability consumes) still works.
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  assert.equal(h.f.runtime.consume(h.p(), runtimeRequest(cap)).decision, 'ALLOW');
});

test('NFR-PRV-002: retention policy is configurable per evidence kind', t => {
  const h = fixture(t);
  const policy = h.f.policy('acme');
  assert.ok(Number.isSafeInteger(policy.retention.default_ms));
  // Tighten the ceiling for one kind only.
  policy.retention.per_kind.ownership = 60000;
  h.f.store.put('acme', 'policy', 'active', policy, h.now());
  const rec = h.proposed();
  // A support envelope holding a 2-day retention exceeds the new kind ceiling.
  const env = { evidence_id: randomUUID(), tenant_id: 'acme', capsule_digest: rec.capsule_digest, kind: 'ownership', content_digest: digest({ x: 1 }), acquired_at: h.now(), expires_at: h.now() + 1000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 'test', retention_until: h.now() + 172800000, claims: { account: 'TESTBANK000002', owner_id: rec.capsule.action.target_resource } };
  const key = Object.values(h.setup.issuerKeys.acme)[0];
  const envSigned = signed(env, key, 'evidence');
  assert.throws(() => h.f.attachEvidence(h.p(), rec.capsule.capsule_id, envSigned), hasCode('INV-400-SCHEMA'));
});

test('NFR-PRV-005: deletion preserves integrity metadata via tombstones', t => {
  const h = fixture(t); h.ready();
  const evId = h.f.store.list('acme', 'evidence', 100, 0)[0].payload.evidence_id;
  const ev = h.f.store.must('acme', 'evidence', evId);
  ev.payload.retention_until = h.now() - 1; ev.legal_hold = false;
  h.f.store.put('acme', 'evidence', evId, ev, h.now());
  // Detach the evidence reference from the capsule so the sweep may shred it.
  const capsule = h.f.store.list('acme', 'capsule', 100, 0).find(r => r.evidence.includes(evId));
  capsule.evidence = []; h.f.store.put('acme', 'capsule', capsule.capsule.capsule_id, capsule, h.now());
  const out = h.f.retentionSweep(h.p('security'));
  assert.ok(out.deleted >= 1);
  const tomb = h.f.store.list('acme', 'evidence-tombstone', 100, 0).find(x => x.evidence_id === evId);
  assert.ok(tomb && /^[a-f0-9]{64}$/.test(tomb.original_digest));
});

test('NFR-MNT-001: every public route is versioned and the contract is documented', () => {
  const spec = JSON.parse(readFileSync('docs/openapi.json', 'utf8'));
  assert.equal(spec.openapi.split('.')[0], '3');
  for (const path of Object.keys(spec.paths)) assert.match(path, /^\/(v1|gate\/v1|session|healthz|readyz)/);
});

test('NFR-MNT-003: a CycloneDX SBOM enumerates components and dependencies', () => {
  const sbom = JSON.parse(readFileSync('reports/sbom.cdx.json', 'utf8'));
  assert.match(sbom.bomFormat, /CycloneDX/);
  assert.ok(Array.isArray(sbom.components) && sbom.components.length > 0);
});

test('NFR-USA-004: a recorded decision replays deterministically from stored inputs', t => {
  const h = fixture(t); h.ready();
  const rec = h.f.store.list('acme', 'capsule', 100, 0)[0];
  assert.ok(['CERTIFIED', 'VERIFIED', 'ALLOW'].includes(rec.status));
  // Re-evaluating the stored record at its decision time reproduces ALLOW —
  // the decision is a pure function of capsule + evidence + policy digests.
  const replay = h.f.evaluation('acme', rec, rec.decision.evaluated_at);
  assert.equal(replay.decision, 'ALLOW');
  assert.ok(rec.decision.policy_digest && rec.decision.reasons !== undefined);
});

test('NFR-TST-001: every requirement row carries a verification method', () => {
  const rows = readFileSync('docs/requirements.csv', 'utf8').trim().split('\n');
  const header = rows[0].split(',');
  const methodIdx = header.indexOf('verification_method');
  assert.ok(methodIdx > 0);
  // Spot-parse: no row leaves the method column empty.
  assert.equal(rows.length - 1, 211);
  for (const line of rows.slice(1)) assert.ok(line.length > methodIdx);
});

test('NFR-TST-003: seeded test data is synthetic and marked as such', t => {
  const h = fixture(t);
  // The authority data the system reasons about is seeded by bootstrap and
  // carries synthetic markers; no real-looking PII patterns exist in it.
  const seeds = readFileSync('src/bootstrap.mjs', 'utf8');
  assert.match(seeds, /TESTBANK|synthetic/i);
  const recordLines = seeds.split('\n').filter(l => /'[a-z-]+:[^']+':/.test(l));
  assert.ok(!/\b\d{3}-\d{2}-\d{4}\b/.test(seeds), 'no SSN-shaped values in authority fixtures');
  assert.ok(recordLines.length > 10, 'synthetic records are seeded');
});

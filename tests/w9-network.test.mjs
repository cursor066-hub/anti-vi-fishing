import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { fixture, hasCode, runtimeInput, runtimeRequest } from './helpers.mjs';
import { Fabric } from '../src/fabric.mjs';
import { emergencyWeakening } from '../src/policy.mjs';
import { hashBytes, clone } from '../src/canonical.mjs';
import { signed, generateKey } from '../src/crypto.mjs';

// Wave-9 network/quarantine/containment audit regressions: full-section
// config snapshots, emergency-comparator completeness, signed capability
// channel binding, forward-only clock recovery, revoke atomicity,
// executor-device binding, containment coverage, manifest freshness.

test('w9-network F1: the config snapshot watches auth, keys, components and data keys', t => {
  const h = fixture(t);
  for (const [label, mutate] of [
    ['auth-inject', c => { const forged = hashBytes('Bearer forged-token'); c.tenants.acme.auth[forged] = { subject_id: 'security', expires_at: h.now() + 9e10 }; }],
    ['components-inject', c => { c.tenants.acme.components['evil-component'] = { signing_key_id: 'evil', signing: { key_id: 'evil', public_key: generateKey().public_key }, ecdh_public: 'x', firmware_version: 'evil-1', assurance: 'dev-attested-software' }; }],
    ['auth-expiry-extend', c => { const k = Object.keys(c.tenants.acme.auth)[0]; c.tenants.acme.auth[k].expires_at = h.now() + 9e10; }],
    // An execution-key swap never even reaches the drift check — the
    // constructor's keystore binding refuses the impersonating key first.
    ['execution-key-swap', c => { c.tenants.acme.keys.execution = { key_id: 'rogue', public_key: generateKey().public_key }; }]
  ]) {
    const tampered = clone(h.setup.config); mutate(tampered);
    if (label === 'execution-key-swap') { assert.throws(() => new Fabric(tampered, h.directory, () => h.now()), hasCode('INV-503-CONFIG')); continue; }
    const f2 = new Fabric(tampered, h.directory, () => h.now());
    const s = f2.configDriftStatus({ subject_id: 'security', tenant_id: 'acme' });
    assert.equal(s.drifted, true, label);
    assert.ok(s.changed_sections.length > 0, label);
    f2.close();
  }
  // Control: an untouched config reopens clean.
  const f3 = new Fabric(clone(h.setup.config), h.directory, () => h.now());
  assert.equal(f3.configDriftStatus({ subject_id: 'security', tenant_id: 'acme' }).drifted, false);
  f3.close();
});

test('w9-network F2: an emergency policy cannot weaken network, remediation, bindings or windows', t => {
  const h = fixture(t);
  const b = h.f.policy('acme');
  const extra = b.staged_policy.emergency_extra_custodians;
  const withChange = mut => {
    const n = clone(b);
    // A valid emergency candidate already raises every approval threshold
    // by the staged extra-custodian factor — keep that clause satisfied so
    // each assertion isolates the field it mutates.
    for (const [t, r] of Object.entries(n.rules)) r.approval_threshold = b.rules[t].approval_threshold + extra;
    mut(n); return emergencyWeakening(b, n);
  };
  assert.equal(withChange(n => { n.runtime.network.deny_workstation_peers = false; }), 'runtime.network.deny_workstation_peers');
  assert.equal(withChange(n => { n.runtime.network.allowed_protocols.push('ftp'); }), 'runtime.network.allowed_protocols');
  assert.equal(withChange(n => { n.runtime.network.allowed_ports.push(8443); }), 'runtime.network.allowed_ports');
  assert.equal(withChange(n => { n.runtime.remediation_services.push('evil.example'); }), 'runtime.remediation_services');
  assert.equal(withChange(n => { n.runtime.windows = []; }), 'runtime.windows');
  const ruleWithBindings = Object.entries(b.rules).find(([, r]) => r.evidence_bindings && Object.keys(r.evidence_bindings).length);
  if (ruleWithBindings) assert.equal(withChange(n => { n.rules[ruleWithBindings[0]].evidence_bindings = {}; }), `${ruleWithBindings[0]}.evidence_bindings`);
  // Control: a strict tightening still reports no weakening.
  assert.equal(withChange(n => { n.runtime.network.allowed_ports = [443]; }), null);
});

test('w9-network F3: a widened live policy cannot retro-extend a signed capability channel', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ action: 'service.connect', resource: 'erp-service', destination: 'erp-service', columns: [], row_ids: [] }));
  assert.equal(h.f.runtime.consume(h.p(), runtimeRequest(cap, { protocol: 'https', port: 443 })).decision, 'ALLOW');
  // Widen the live policy: the capability's signed snapshot still denies.
  const widened = clone(h.f.policy('acme')); widened.runtime.network.allowed_ports.push(8443); widened.runtime.network.allowed_protocols.push('ftp');
  h.f.store.put('acme', 'policy', 'active', widened, h.now());
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap, { protocol: 'ftp', port: 443 })), hasCode('INV-400-SCHEMA'));
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap, { protocol: 'https', port: 8443 })), hasCode('INV-400-SCHEMA'));
  // Control: the originally-allowed channel still works.
  assert.equal(h.f.runtime.consume(h.p(), runtimeRequest(cap)).decision, 'ALLOW');
});

test('w9-network F4: clock recovery never resurrects lapsed authority', t => {
  const h = fixture(t);
  // An unconsumed certificate lapses while the ledger stands far ahead.
  h.ready(); // certificate issued at fixture time with its expiry window
  h.f.store.clock(h.now() + 86400000);
  // Rewinding into the span containing its expiry would resurrect it.
  assert.throws(() => h.f.recoverClock(h.p('security')), hasCode('INV-503-TIME'));
  // Control: a rewind that re-opens nothing is the legitimate snapshot-
  // restore path — the gate recovers to the operator-asserted host time.
  const h2 = fixture(t);
  h2.proposed(); // ledger written at advanced fixture time
  const prior = h2.f.store.db.prepare('SELECT last FROM clock WHERE id=1').get().last;
  h2.set(prior - 30000);
  assert.equal(h2.f.recoverClock(h2.p('security')).recovered_at, prior - 30000);
});

test('w9-network F5: a failed grant revocation leaves no phantom revoke', t => {
  const h = fixture(t);
  h.ready();
  const grantId = `grant-${randomUUID()}`;
  h.f.target.grant('acme', grantId, { grant_id: grantId, subject_id: 'operator', roles: ['operator'], resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: [], issued_at: h.now(), expires_at: h.now() + 60000 });
  // Sabotage the audit signature path so the ledger write fails.
  const origSign = h.f.vault.envelope.bind(h.f.vault);
  h.f.vault.envelope = () => { throw new Error('signing dead'); };
  assert.throws(() => h.f.revoke(h.p('security'), { kind: 'grant', id: grantId, reason: 'test' }));
  h.f.vault.envelope = origSign;
  // Neither the ledger nor the dataplane may show the revoke.
  assert.equal(h.f.revoked('acme', 'grant', grantId), false);
  assert.equal(!h.f.target.allGrants('acme').find(g => g.grant_id === grantId).revoked, true);
  // Control: a clean revoke still kills the grant.
  h.f.revoke(h.p('security'), { kind: 'grant', id: grantId, reason: 'test' });
  assert.equal(h.f.target.allGrants('acme').find(g => g.grant_id === grantId).revoked, true);
});

test('w9-network F6: a quarantined-device principal cannot dispatch another actor\'s certificate', t => {
  const h = fixture(t);
  const { certificate } = h.ready();
  h.f.revoke(h.p('security'), { kind: 'device', id: 'policy-admin-device', reason: 'lost' });
  assert.throws(() => h.f.execute(h.p('policy-admin'), certificate), hasCode('INV-403-QUARANTINE'));
  // Control: the actor's own healthy path still executes.
  assert.equal(h.f.execute(h.p(), certificate).payload.status, 'VERIFIED');
});

test('w9-network F7: quarantine denials on execute join the containment ledger', t => {
  const h = fixture(t);
  const { certificate } = h.ready();
  // Device quarantine reaches the in-transaction health check, so the
  // dropped request lands in the containment ledger.
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'gone' });
  assert.throws(() => h.f.execute(h.p(), certificate), hasCode('INV-403-QUARANTINE'));
  const report = h.f.containmentReport(h.p('security'));
  assert.ok(report.dropped_requests >= 1, 'denied execute must count as dropped traffic');
});

test('w9-network F8: a stale issuer manifest is drift, not freshness', async t => {
  const h = fixture(t);
  const [issuerKeyId, issuer] = Object.entries(h.setup.config.tenants.acme.issuers).find(([, i]) => i.name === 'bank');
  const key = h.setup.issuerKeys.acme.bank;
  const manifest = extra => signed({ connector_id: 'issuer:bank', version: issuer.version ?? '1.0.0', domain: issuer.channel, actions: Object.keys(issuer.kinds), permissions: [], limitations: [], idempotency: {}, coverage_implications: [], issued_at: h.now(), expires_at: h.now() + 400000, ...extra }, key, 'connector-manifest');
  const serve = body => new Promise(resolve => { const srv = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); }); srv.listen(0, '127.0.0.1', () => resolve(srv)); });
  const run = async body => {
    const srv = await serve(body); t.after(() => srv.close());
    issuer.endpoint = `http://127.0.0.1:${srv.address().port}`;
    return assert.rejects(() => h.f.checkIssuerDrift(h.p('security'), issuerKeyId), hasCode('INV-401-CONNECTOR'));
  };
  // A captured manifest minted before the freshness window must not
  // suppress drift detection, and an issuer cannot sign itself a
  // weeks-long horizon (w9-network F8).
  await run(manifest({ issued_at: h.now() - 29 * 86400000 }));
  assert.ok(h.f.store.get('acme', 'issuer-drift', issuerKeyId), 'stale manifest must register as drift');
  h.f.store.remove('acme', 'issuer-drift', issuerKeyId);
  await run(manifest({ expires_at: h.now() + 86400000 * 30 }));
  assert.ok(h.f.store.get('acme', 'issuer-drift', issuerKeyId), 'over-long manifest horizon must register as drift');
});

test('w9-network F9: an unrelated operator cannot cancel another actor\'s capsule', t => {
  const h = fixture(t);
  // A second operator identity joins via the legitimate path — config edit
  // plus a security re-assertion (the drift snapshot gates it at boot).
  const op2key = generateKey();
  h.setup.config.tenants.acme.identities[op2key.key_id] = { public_key: op2key.public_key, subject_id: 'operator-2', identity_class: 'workforce', roles: ['operator'], device_id: 'operator-2-device', failure_domain: 'acme-op2', hardware_backed: false, health_expires_at: h.now() + 86400000, grants: { resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: [] } };
  h.f.reassertConfig(h.p('security'));
  const record = h.proposed();
  assert.throws(() => h.f.cancel(h.p('operator-2'), record.capsule.capsule_id), hasCode('INV-403-SCOPE'));
  // Control: the actor still cancels their own.
  assert.equal(h.f.cancel(h.p(), record.capsule.capsule_id).status, 'CANCELLED');
});

test('w9-network F10: an idempotent replay cannot slip past a fresh quarantine', t => {
  const h = fixture(t);
  const record = h.proposed();
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'quarantined' });
  assert.throws(() => h.f.propose(h.p(), record.capsule.request_intent.payload, `idem-${randomUUID()}`, record.capsule.request_intent), hasCode('INV-403-QUARANTINE'));
});

test('w9-network F11: a re-assertion audit records the previous section digests', t => {
  const h = fixture(t);
  const tampered = clone(h.setup.config);
  tampered.tenants.acme.auth[hashBytes('Bearer forged-token')] = { subject_id: 'security', expires_at: h.now() + 9e10 };
  const f2 = new Fabric(tampered, h.directory, () => h.now()); t.after(() => f2.close());
  f2.reassertConfig({ subject_id: 'security', tenant_id: 'acme' });
  const entry = f2.store.auditPage('acme', { limit: 100 }).entries.map(e => e.envelope.payload).find(e => e.type === 'CONFIG_REASSERTED');
  assert.ok(entry, 'CONFIG_REASSERTED audit missing');
  assert.ok(entry.metadata.previous_sections?.auth && entry.metadata.changed_sections.includes('auth'), JSON.stringify(entry.metadata));
});

test('w9-network F12: the deploy unit carries clock/syscall/sandbox hardening', () => {
  const unit = readFileSync('deploy/invariant-engineering.service', 'utf8');
  for (const hardening of ['ProtectClock=true', 'SystemCallFilter=', 'MemoryDenyWriteExecute=true', 'RestrictNamespaces=true'])
    assert.ok(unit.includes(hardening), `unit missing ${hardening}`);
});

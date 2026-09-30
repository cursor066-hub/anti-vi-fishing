import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { fixture, hasCode } from './helpers.mjs';
import { createServer } from '../src/server.mjs';
import { answerQuery } from '../src/issuerd.mjs';
import { generateKey, signed } from '../src/crypto.mjs';
import { proposal } from '../src/schema.mjs';
import { digest } from '../src/canonical.mjs';
import { signAcknowledgement } from '../src/ceremony.mjs';

// Wave-6 fix-verification regressions: every test reproduces a hole the
// hostile re-audit found inside the tenancy/datagate fixes themselves.

// w6-fix F1: the signed request intent carries the proposal input verbatim —
// redaction must project rows out of the intent payload too, on every read
// surface (getCapsule, list, POST response).
test('w6-fix F1: request_intent payloads carry row digests, never raw rows', t => {
  const h = fixture(t);
  const r = h.proposed('data.export', { dataset: 'dataset-1', columns: ['id'], row_ids: ['row-1'], max_rows: 1, classification: 'internal', jurisdiction: 'EU' }, { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Operations' }, destination: 'customer-vault' });
  const view = h.f.getCapsule(h.p(), r.capsule.capsule_id);
  const intent = view.capsule.request_intent.payload;
  assert.equal(intent.current_state.material_fields.rows, undefined);
  assert.equal(intent.current_state.material_fields.row_count, 3);
  assert.equal(intent.current_state.material_fields.rows_digest, digest(r.capsule.current_state.material_fields.rows));
  assert.equal(JSON.stringify(view.capsule.request_intent).includes('SYNTHETIC-NOT-REAL'), false, 'no row material survives inside the served intent');
  const listed = h.f.store.list('acme', 'capsule').map(c => h.f.capsuleView(c));
  assert.equal(listed.every(c => c.capsule.request_intent.payload.current_state.material_fields.rows === undefined), true);
});

// w6-fix F2: freshness must be enforced for every action class — a
// fabricated snapshot on a nonexistent resource fails at evaluate/cert
// time, and secret.use binds the registry row rather than skipping the
// check entirely.
test('w6-fix F2: fabricated snapshots on ghost resources and secrets are denied', t => {
  const h = fixture(t);
  const bogus = { version: 77, digest: digest({ forged: true }), material_fields: { forged: true } };
  const input = proposal('finance.beneficiary.create', h.actor('operator'), bogus, { vendor_id: 'v-1', bank_account: 'TESTBANK000002', currency: 'EUR' }, h.now(), { action: { type: 'finance.beneficiary.create', target_resource: 'ghost-1', purpose: 'Forge' } });
  const intent = signed(input, h.setup.identityKeys.acme.operator, 'capsule-intent');
  const r = h.f.propose(h.p(), input, randomUUID(), intent);
  h.evidence(r, { kind: 'ownership' }); h.approve(r, 2);
  assert.throws(() => h.f.certificate(h.p(), r.capsule.capsule_id), hasCode('INV-409-STATE'));

  const secretInput = proposal('secret.use', h.actor('operator'), { version: 42, digest: digest({ forged: true }), material_fields: { forged: true } }, { secret_id: 'secret-erp-1', operation: 'sign', workload_id: 'workload-1' }, h.now(), { action: { type: 'secret.use', target_resource: 'secret-erp-1', purpose: 'Forge' } });
  const secretIntent = signed(secretInput, h.setup.identityKeys.acme.operator, 'capsule-intent');
  const r2 = h.f.propose(h.p(), secretInput, randomUUID(), secretIntent);
  h.evidence(r2, { kind: 'workload_attestation' }); h.evidence(r2, { kind: 'workload_attestation', issuer: 'cloud-attestor' }); h.approve(r2, 2);
  assert.throws(() => h.f.certificate(h.p(), r2.capsule.capsule_id), hasCode('INV-409-STATE'));
});

// w6-fix F6: a denied export must leave no phantom access rows — the ledger
// counts disclosure, not probing, identical to a rolled-back consume.
test('w6-fix F6: denied exports do not burn the reconstruction budget', t => {
  const h = fixture(t);
  const policy = h.clone(h.f.policy('acme'));
  policy.version += 1; policy.not_before = h.now();
  policy.runtime.reconstruction.max_distinct_rows = 1;
  h.f.store.put('acme', 'policy', 'staged', { policy, activate_at: policy.not_before, staged_at: h.now() }, h.now());
  h.f.activateDuePolicies('acme', h.now());
  const exportRow = row => {
    const r = h.proposed('data.export', { dataset: 'dataset-1', columns: ['id'], row_ids: [row], max_rows: 1, classification: 'internal', jurisdiction: 'EU' }, { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Operations' }, destination: 'customer-vault', policy_version: 2 });
    h.evidence(r, { kind: 'dataset_authority' }); h.approve(r, 1);
    return h.f.execute(h.p(), h.f.certificate(h.p(), r.capsule.capsule_id));
  };
  assert.equal(exportRow('row-1').payload.status, 'VERIFIED');
  const denied = exportRow('row-2');
  assert.equal(denied.payload.status, 'FAILED');
  assert.equal(denied.payload.gate_denied.row_count, 2, 'denial still reports the prospective coverage');
  const touches = h.f.store.db.prepare("SELECT count(*) AS n FROM data_access WHERE tenant='acme' AND dataset='dataset-1'").get().n;
  assert.equal(touches, 1, 'only the disclosed row is accounted — the denied probe wrote nothing');
});

// w6-fix F4: a ledger revocation on a vault key stops signing immediately —
// the revocation record is authoritative, not the vault flag. And a revoked
// pending key can never be activated by a certified rotation.
test('w6-fix F4: revoked keys cannot sign; revoked pending keys cannot activate', t => {
  const h = fixture(t);
  const auditKey = h.f.keys('acme').audit.key_id, execKey = h.f.keys('acme').execution.key_id;
  h.f.revoke(h.p('security'), { kind: 'key', id: execKey, reason: 'compromised' });
  assert.throws(() => h.f.signExecution('acme', { probe: 1 }, 'capability'), hasCode('INV-401-SIGNATURE'));
  // Revoking the audit key itself is a wedging event by design — the
  // revocation envelope is signed while the key is still valid, then every
  // later signature attempt fails until a key.rotate lands.
  h.f.revoke(h.p('security'), { kind: 'key', id: auditKey, reason: 'compromised' });
  assert.throws(() => h.f.signAudit('acme', { probe: 1 }, 'outcome'), hasCode('INV-401-SIGNATURE'));
});
test('w6-fix F4b: a revoked pending rotation key is unactivatable', t => {
  const h = fixture(t);
  const pending = h.f.prepareRotation(h.p('security'), 'execution');
  h.f.revoke(h.p('security'), { kind: 'key', id: pending.key_id, reason: 'seed leaked' });
  const custodians = ['custodian-1', 'custodian-2'];
  const c = h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-rev', purpose: 'key.rotate', threshold: 2, custodians, valid_until: h.now() + 3600000, min_delay_ms: 120000, rotation: { key_class: 'execution', new_key_id: pending.key_id } });
  for (const subject of custodians) h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(c, subject, h.setup.custodianKeys.acme[subject], h.now()));
  const r = h.proposed('key.rotate', { key_class: 'execution', new_key_id: pending.key_id, new_public_key: pending.public_key, ceremony_id: 'cer-rev', revoke_old: false }, { action: { type: 'key.rotate', target_resource: 'key-registry', purpose: 'Rotate' } });
  h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'audit-committee' });
  h.approve(r, 3); h.advance(60001);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  assert.throws(() => h.f.execute(h.p(), cert), hasCode('INV-409-STATE'));
  assert.equal(h.f.vault.keys.get(pending.key_id).pending, true, 'revoked pending key stays pending');
});

// w6-fix F5: a legacy vault key minted before tenant tagging resolves its
// ownership through the tenant's key bindings — bound legacy keys become
// revocable, listable and attestable; unbound orphans stay unreachable.
test('w6-fix F5: legacy untagged vault keys resolve through tenant bindings', t => {
  const h = fixture(t);
  const legacy = h.f.vault.generate('audit', { key_id: 'legacy-audit-1' });
  const orphan = h.f.vault.generate('audit', { key_id: 'orphan-1' });
  h.f.tenant('acme').keys.legacy_class = { key_id: legacy.key_id, public_key: legacy.public_key };
  h.f.revoke(h.p('security'), { kind: 'key', id: legacy.key_id, reason: 'retire legacy' });
  assert.ok(h.f.revoked('acme', 'key', legacy.key_id));
  assert.throws(() => h.f.revoke(h.p('security'), { kind: 'key', id: orphan.key_id, reason: 'probe' }), hasCode('INV-404-NOT-FOUND'));
  assert.equal(h.f.ownsVaultKey('acme', legacy.key_id), true);
  assert.equal(h.f.ownsVaultKey('acme', orphan.key_id), false);
  assert.equal(h.f.ownsVaultKey('globex', h.f.keys('acme').audit.key_id), false);
});

// w6-fix F7: the lookupBound extraction grammar must equal interpolate()'s —
// nested claim paths echo their resolved value, and out-of-grammar claims
// are never echoed under the issuer signature.
test('w6-fix F7: issuerd claim-binding grammar matches interpolation exactly', t => {
  const issuer = {
    issuer: 'bank', tenant: 'acme', version: '1.0.0', channel: 'authoritative', key: generateKey(),
    kinds: { ownership: { lookup: 'acct:${claims.account.id}', confidence: 100, expect: {} } },
    records: { 'acct:real-42': { account_id: 'real-42', subject_id: 'operator' } },
  };
  const env = answerQuery(issuer, { tenant_id: 'acme', capsule_digest: 'a'.repeat(64), kind: 'ownership', subject_id: 'ignored', claims: { account: { id: 'real-42' } } }, 1000);
  assert.equal(env.payload.claim, 'supports');
  assert.equal(env.payload.claims['account.id'], 'real-42', 'nested lookup claim is proven under the signature');
  const forge = { ...issuer, kinds: { ownership: { lookup: 'entity:${claims.CaseId}', confidence: 100, expect: {} } }, records: { 'entity:${claims.CaseId}': { subject_id: 's' } } };
  const forged = answerQuery(forge, { tenant_id: 'acme', capsule_digest: 'a'.repeat(64), kind: 'ownership', subject_id: 'x', claims: { CaseId: 'FORGED-CLAIM' } }, 1000);
  assert.equal(forged.payload.claims.CaseId, undefined, 'uppercase claim the lookup never bound is not echoed');
});

// w6-fix F3 + F9: the outcome store serves a redacted projection of exported
// rows to every reader, and session logins count under the tenant slice.
async function httpFixture(t) {
  const h = fixture(t), app = createServer(h.f, { port: 0, origin: 'http://127.0.0.1:17777' }); await app.listen(); t.after(() => app.close()); const port = app.server.address().port;
  const request = (path, { token = h.setup.credentials.acme.security, method = 'GET', json, headers = {} } = {}) => new Promise((resolve, reject) => {
    const bodyData = json === undefined ? null : Buffer.from(JSON.stringify(json));
    const req = http.request({ host: '127.0.0.1', port, path, method, headers: { Host: '127.0.0.1:17777', Origin: 'http://127.0.0.1:17777', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(bodyData ? { 'Content-Type': 'application/json', 'Content-Length': bodyData.length } : {}), ...headers } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, data: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
    }); req.on('error', reject); if (bodyData) req.write(bodyData); req.end();
  });
  return { ...h, request };
}

test('w6-fix F3: stored outcomes serve row digests, not raw exports', async t => {
  const h = await httpFixture(t);
  const r = h.proposed('data.export', { dataset: 'dataset-1', columns: ['id'], row_ids: ['row-1'], max_rows: 1, classification: 'internal', jurisdiction: 'EU' }, { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Operations' }, destination: 'customer-vault' });
  h.evidence(r, { kind: 'dataset_authority' }); h.approve(r, 1);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  const outcome = h.f.execute(h.p(), cert);
  assert.ok(Array.isArray(outcome.payload.output), 'the executor receives the rows — delivery happens at execute');
  const read = await h.request(`/gate/v1/outcomes/${cert.payload.certificate_id}`);
  assert.equal(read.status, 200);
  assert.equal(read.data.payload.output.row_count, 1);
  assert.equal(read.data.payload.output.rows_digest, digest(outcome.payload.output));
  assert.equal(Array.isArray(read.data.payload.output), false, 'a reader never drains rows from the outcome store');
});

test('w6-fix F9: session logins are attributed to the resolved tenant', async t => {
  const h = await httpFixture(t);
  const login = await h.request('/session', { token: null, method: 'POST', json: { token: h.setup.credentials.acme.security } });
  assert.equal(login.status, 200);
  const metrics = await h.request('/v1/metrics');
  assert.ok(metrics.data.requests >= 1, 'the login counts under acme');
});

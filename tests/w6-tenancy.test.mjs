import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { fixture, hasCode, stageConstitution } from './helpers.mjs';
import { createServer } from '../src/server.mjs';
import { answerQuery } from '../src/issuerd.mjs';
import { ISSUER_RULES, issuerRecords } from '../src/bootstrap.mjs';
import { generateKey } from '../src/crypto.mjs';
import { signAcknowledgement } from '../src/ceremony.mjs';
import { digest } from '../src/canonical.mjs';

// Wave-6 tenancy/datagate regressions: dataset-row redaction on read
// surfaces, cross-tenant vault-key theft, the revoke existence oracle,
// export-path reconstruction budget, and issuerd claim binding.

// w6-F1: the capsule read surface must never serve raw dataset rows —
// approvers verify digests, not data they were never granted.
test('w6-F1: capsule views and certificates carry row digests, never raw rows', t => {
  const h = fixture(t);
  const r = h.proposed('data.export', { dataset: 'dataset-1', columns: ['id'], row_ids: ['row-1'], max_rows: 1, classification: 'internal', jurisdiction: 'EU' }, { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Operations' }, destination: 'customer-vault' });
  const stored = h.f.store.must('acme', 'capsule', r.capsule.capsule_id);
  assert.ok(Array.isArray(stored.capsule.current_state.material_fields.rows), 'stored capsule keeps the snapshot');
  const view = h.f.capsuleView(stored);
  assert.equal(view.capsule.current_state.material_fields.rows, undefined);
  assert.equal(view.capsule.current_state.material_fields.row_count, 3);
  assert.equal(view.capsule.current_state.material_fields.rows_digest, digest(stored.capsule.current_state.material_fields.rows));
  assert.equal(view.capsule.current_state.material_fields.passport, undefined, 'no column values survive redaction');
  h.evidence(r, { kind: 'dataset_authority' }); h.approve(r, 1);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  const cs = cert.payload.constraints.current_state;
  assert.deepEqual(Object.keys(cs).sort(), ['digest', 'material_fields_digest', 'version']);
  assert.equal(cs.version, stored.capsule.current_state.version);
  assert.equal(cs.material_fields_digest, digest(stored.capsule.current_state.material_fields));
});

// w6-F3: a certified rotation in tenant A must not activate a pending key
// minted for tenant B — the vault is process-global, ownership is checked
// inside the outcome transaction.
test('w6-F3: certified key.rotate cannot activate another tenant\'s pending key', t => {
  const h = fixture(t);
  const stolen = h.f.prepareRotation(h.p('security', 'globex'), 'execution');
  const custodians = ['custodian-1', 'custodian-2'];
  const c = h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-theft', purpose: 'key.rotate', threshold: 2, custodians, valid_until: h.now() + 3600000, min_delay_ms: 120000, rotation: { key_class: 'execution', new_key_id: stolen.key_id } });
  for (const subject of custodians) h.f.acknowledgeCeremony(h.p(subject), signAcknowledgement(c, subject, h.setup.custodianKeys.acme[subject], h.now()));
  const r = h.proposed('key.rotate', { key_class: 'execution', new_key_id: stolen.key_id, new_public_key: stolen.public_key, ceremony_id: 'cer-theft', revoke_old: false }, { action: { type: 'key.rotate', target_resource: 'key-registry', purpose: 'Theft attempt' } });
  h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'audit-committee' });
  h.approve(r, 3); h.advance(60001);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  assert.throws(() => h.f.execute(h.p(), cert), hasCode('INV-403-SCOPE'));
  assert.equal(h.f.vault.keys.get(stolen.key_id).pending, true, 'foreign pending key must not be activated');
});

// w6-F4: revoke('key') must not be a cross-tenant existence oracle — a
// foreign vault key answers INV-404 exactly like an absent one.
test('w6-F4: revoking another tenant\'s vault key is an INV-404, not a silent no-op', t => {
  const h = fixture(t);
  const foreign = h.f.keys('globex').execution.key_id;
  assert.throws(() => h.f.revoke(h.p('security'), { kind: 'key', id: foreign, reason: 'probe' }), hasCode('INV-404-NOT-FOUND'));
  assert.throws(() => h.f.revoke(h.p('security'), { kind: 'key', id: 'no-such-key', reason: 'probe' }), hasCode('INV-404-NOT-FOUND'));
});

// w6-F5: a certified data.export passes the same cumulative reconstruction
// budget as a capability read — crossing it fails the outcome and suppresses
// the payload rows.
test('w6-F5: an export that crosses the reconstruction budget fails with output suppressed', t => {
  const h = fixture(t);
  const policy = h.clone(h.f.policy('acme'));
  policy.version += 1; policy.not_before = h.now();
  policy.runtime.reconstruction.max_distinct_rows = 1;
  stageConstitution(h, policy);
  h.f.activateDuePolicies('acme', h.now());
  assert.equal(h.f.policy('acme').runtime.reconstruction.max_distinct_rows, 1);
  const exportRow = row => {
    const r = h.proposed('data.export', { dataset: 'dataset-1', columns: ['id'], row_ids: [row], max_rows: 1, classification: 'internal', jurisdiction: 'EU' }, { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Operations' }, destination: 'customer-vault', policy_version: 2 });
    h.evidence(r, { kind: 'dataset_authority' }); h.approve(r, 1);
    return h.f.execute(h.p(), h.f.certificate(h.p(), r.capsule.capsule_id));
  };
  assert.equal(exportRow('row-1').payload.status, 'VERIFIED');
  // The denial fires at reservation — before the certificate is consumed or
  // the journal writes — so nothing egresses and nothing bills (w10-datagate F3).
  const r2 = h.proposed('data.export', { dataset: 'dataset-1', columns: ['id'], row_ids: ['row-2'], max_rows: 1, classification: 'internal', jurisdiction: 'EU' }, { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Operations' }, destination: 'customer-vault', policy_version: 2 });
  h.evidence(r2, { kind: 'dataset_authority' }); h.approve(r2, 1);
  const cert2 = h.f.certificate(h.p(), r2.capsule.capsule_id);
  assert.throws(() => h.f.execute(h.p(), cert2), hasCode('INV-429-BUDGET'));
  assert.equal(h.f.store.must('acme', 'certificate', cert2.payload.certificate_id).consumed ?? false, false, 'denied reservation leaves the certificate unspent');
  assert.equal(h.f.store.get('acme', 'outcome', cert2.payload.certificate_id) ?? null, null, 'no outcome without egress');
});

// w6-F2+F6: /v1/keys and /v1/metrics are tenant-scoped on the live surface.
async function httpFixture(t) {
  const h = fixture(t), app = createServer(h.f, { port: 0, origin: 'http://127.0.0.1:17777' }); await app.listen(); t.after(() => app.close()); const port = app.server.address().port;
  const request = (path, { token = h.setup.credentials.acme.security } = {}) => new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, headers: { Host: '127.0.0.1:17777', ...(token ? { Authorization: `Bearer ${token}` } : {}) } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, data: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
    }); req.on('error', reject); req.end();
  });
  return { ...h, request };
}

test('w6-F2: /v1/keys and attest expose only the caller\'s own vault entries', async t => {
  const h = await httpFixture(t);
  const own = h.f.keys('acme').execution.key_id, foreign = h.f.keys('globex').execution.key_id;
  const acmeKeys = await h.request('/v1/keys');
  const ids = acmeKeys.data.keys.map(k => k.key_id);
  assert.ok(ids.includes(own)); assert.ok(!ids.includes(foreign));
  assert.equal((await h.request(`/v1/keys/${foreign}/attest`)).status, 404);
  assert.equal((await h.request(`/v1/keys/${own}/attest`)).status, 200);
});

// w6-F7: issuerd 'supports' answers echo only fields the issuer actually
// verified — expect/extract fields, the resolved subject, and identifiers
// bound into the lookup template. Caller-invented claims stay unsigned.
test('w6-F7: issuerd never signs unverified caller claims', t => {
  const issuer = { issuer: 'bank', tenant: 'acme', version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds: ISSUER_RULES.bank, records: issuerRecords().bank };
  const record = issuerRecords().bank['account:TESTBANK000001'];
  const env = answerQuery(issuer, { tenant_id: 'acme', capsule_digest: 'a'.repeat(64), kind: 'ownership', subject_id: 'intruder', claims: { account: 'TESTBANK000001', owner_id: record.owner, subject_id: 'operator', ssn: '000-00-0000', fabricated: 'yes' }, dependencies: [] }, 1000);
  assert.equal(env.payload.claim, 'supports');
  assert.equal(env.payload.claims.ssn, undefined);
  assert.equal(env.payload.claims.fabricated, undefined);
  assert.equal(env.payload.claims.account, 'TESTBANK000001', 'lookup-bound identifier is proven');
  // claims.subject_id is caller input on a kind whose lookup never verified
  // it — the record carries no subject and neither the lookup nor an expect
  // rule bound it, so it must not be echoed under the signature at all.
  assert.equal(env.payload.claims.subject_id, undefined);
});

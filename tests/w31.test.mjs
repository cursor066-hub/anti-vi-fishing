// w31 regressions — fixverify F1-F7 (per-tenant wipe gate, target.db
// taxonomy, widened anchored kinds, tombstone subtraction, replay mislabel,
// guarded outer ROLLBACK, component-key binding) + coverage F1-F10 (anchored
// enumeration, anchored sweep, anchored identity binding, connector
// self-validation, chain-sourced manifest, open obligations, task sweep,
// paged listing, drift by key_id).
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fixture, hasCode, coverageIdentity, setTenant, runtimeInput, runtimeRequest, installPolicy } from './helpers.mjs';
import { Fabric } from '../src/fabric.mjs';
import { signed, generateKey } from '../src/crypto.mjs';
import { digest } from '../src/canonical.mjs';
import { proposal } from '../src/schema.mjs';
import { validatePolicy } from '../src/policy.mjs';
import { clone } from '../src/canonical.mjs';
import { createIssuerServer, writeIssuer, loadIssuers } from '../src/issuerd.mjs';
import { ISSUER_RULES, issuerRecords } from '../src/bootstrap.mjs';

const declarePath = (h, path_id, status = 'UNCOVERED', extra = {}) =>
  h.f.declareCoverage(h.p('security'), { path_id, action_type: 'data.read', target: 'dataset-1', environment: 'prod', connector_version: '1.0', owner: 'op', status, path_class: 'api', max_age_ms: 60000, configuration_digest: digest({ cfg: 1 }), ...extra });
const validationEnvelope = (h, path, issuer = 'security-ops', overrides = {}) => {
  const payload = { evidence_id: randomUUID(), tenant_id: 'acme', capsule_digest: coverageIdentity(path), kind: 'technical_validation', content_digest: digest({ probe: 'ok' }), acquired_at: h.now(), expires_at: h.now() + 60000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 'manual probe', retention_until: h.now() + 120000, issuer_version: '1.0.0', claims: { capsule_digest: coverageIdentity(path) }, ...overrides };
  return { envelope: signed(payload, h.setup.issuerKeys.acme[issuer], 'evidence'), payload };
};

// F1: a file-writer erasing ONE tenant's rows+file entries while a peer
// tenant keeps the deployment alive must still refuse the boot — the wiped
// tenant is attested by the peer's signed head envelope.
test('w31 fixverify F1: per-tenant wipe refuses silent re-genesis via peer attestation', t => {
  const h = fixture(t, ['acme', 'globex']);
  h.proposed('finance.beneficiary.create', { vendor_id: 'v-1', bank_account: 'TESTBANK000003', currency: 'EUR' }, {}, h.p('operator', 'globex'));
  // An acme commit AFTER globex's rows lands a signed acme head envelope
  // whose `tenants` field attests that globex had committed entries.
  h.proposed('finance.beneficiary.create', { vendor_id: 'v-2', bank_account: 'TESTBANK000005', currency: 'EUR' }, {}, h.p('operator', 'acme'));
  h.close();
  const db = new DatabaseSync(join(h.directory, 'fabric.db'));
  // A file-writer drops the append-only guards it needs (trigger surgery
  // is inside the threat model — arbitrary write to the sqlite file).
  db.exec('DROP TRIGGER no_audit_delete; DROP TRIGGER no_nonce_delete; DROP TRIGGER no_idem_delete');
  for (const table of ['audit', 'records', 'nonces', 'idempotency', 'deks', 'usage', 'data_access'])
    db.prepare(`DELETE FROM ${table} WHERE tenant=?`).run('globex');
  db.close();
  for (const file of ['chain-heads.json', 'head-watermark.json']) {
    const p = join(h.directory, file);
    if (!existsSync(p)) continue;
    const j = JSON.parse(readFileSync(p, 'utf8'));
    if (j.tenants) delete j.tenants.globex; else delete j.globex;
    writeFileSync(p, JSON.stringify(j));
  }
  assert.throws(() => new Fabric(h.setup.config, h.directory, h.now), hasCode('INV-503-STORAGE'));
});

// F1 residue path: peer envelope absent AND rows survive — residue alone
// refuses (delete the peer's attestation too, keep globex records).
test('w31 fixverify F1: per-tenant residue without peer attestation still refuses', t => {
  const h = fixture(t, ['acme', 'globex']);
  h.proposed('finance.beneficiary.create', { vendor_id: 'v-1', bank_account: 'TESTBANK000004', currency: 'EUR' }, {}, h.p('operator', 'globex'));
  h.close();
  const db = new DatabaseSync(join(h.directory, 'fabric.db'));
  db.exec('DROP TRIGGER no_audit_delete');
  db.prepare('DELETE FROM audit WHERE tenant=?').run('globex');
  db.close();
  // records/nonces survive for globex → residue refuses even though no
  // chain-head entry needs to be planted at all.
  assert.throws(() => new Fabric(h.setup.config, h.directory, h.now), hasCode('INV-503-STORAGE'));
});

// F2: a corrupt target.db must classify inside INV-503-STORAGE, never
// surface as a raw SQLITE_CORRUPT / UNKNOWN crash.
test('w31 fixverify F2: corrupt target.db surfaces INV-503-STORAGE at boot', t => {
  const h = fixture(t, ['acme']);
  h.close();
  writeFileSync(join(h.directory, 'target.db'), 'planted bytes — not a sqlite file');
  assert.throws(() => new Fabric(h.setup.config, h.directory, h.now), hasCode('INV-503-STORAGE'));
});

// F3: deleting a chain-anchored coverage row surfaces INV-409, not a bare
// INV-404 — same for a perception session and a JIT grant.
test('w31 fixverify F3: widened anchored kinds report tamper, not a miss', t => {
  const h = fixture(t, ['acme']);
  declarePath(h, 'p-anchored');
  h.f.store.remove('acme', 'coverage', 'p-anchored');
  assert.throws(() => h.f._mustAnchored('acme', 'coverage', 'p-anchored'), hasCode('INV-409-INTEGRITY'));
  // Perception session: mint one, delete the row, mustAnchored reports
  // tamper (its PERCEPTION_SESSION anchor persists).
  const component = h.setup.componentSecrets.acme['secure-view-acme'];
  const session = h.f.perceptionSession(h.p(), component.attest('d'.repeat(64), h.now() + 300000));
  h.f.store.remove('acme', 'perception-session', session.session_id);
  assert.throws(() => h.f._mustAnchored('acme', 'perception-session', session.session_id), hasCode('INV-409-INTEGRITY'));
  // A never-anchored id in the same kinds stays an honest INV-404.
  assert.throws(() => h.f._mustAnchored('acme', 'coverage', 'p-never'), hasCode('INV-404-NOT-FOUND'));
});

// F4: a retention-shredded evidence row is INV-404 (legitimately gone), a
// row-deleted anchored evidence row is INV-409 (tamper).
test('w31 fixverify F4: tombstoned evidence is 404, deleted evidence is 409', t => {
  const h = fixture(t, ['acme']);
  const r = h.proposed();
  const ev = h.evidence(r);
  const eid = ev.payload.evidence_id;
  // Raw delete → the evidence_id anchor persists with NO tombstone → tamper.
  h.f.store.remove('acme', 'evidence', eid);
  assert.throws(() => h.f._mustAnchored('acme', 'evidence', eid), hasCode('INV-409-INTEGRITY'));
  // Retention-shredded → RETENTION_DELETED tombstone → honest miss.
  const r2 = h.proposed();
  const ev2 = h.evidence(r2, { expiry: h.now() + 1000 });
  h.f.cancel(h.p(), r2.capsule.capsule_id); // un-reference so the sweep may shred
  h.advance(70000); // past retention_until (expiry + 60000)
  assert.ok(h.f.retentionSweep(h.p('security')).deleted >= 1);
  assert.equal(h.f.store.get('acme', 'evidence', ev2.payload.evidence_id), null);
  assert.throws(() => h.f._mustAnchored('acme', 'evidence', ev2.payload.evidence_id), hasCode('INV-404-NOT-FOUND'));
});

// F5: replaying an idempotency key whose anchored capsule row was deleted
// must classify as tamper (INV-409), never the honest-miss INV-404. The
// chain-anchored idem binding fires before any receipt/path resolution.
test('w31 fixverify F5: idempotent replay over a deleted anchored capsule is INV-409', t => {
  const h = fixture(t, ['acme']);
  const idem = randomUUID(), resource = `res-${randomUUID()}`;
  const p = h.p('operator', 'acme');
  const state = h.f.target.state('acme', resource);
  const input = proposal('finance.beneficiary.create', h.actor('operator'), state, { vendor_id: 'vendor-1', bank_account: 'TESTBANK000001', currency: 'EUR' }, h.now(), { action: { type: 'finance.beneficiary.create', target_resource: resource, purpose: 'Synthetic verification' }, policy_version: h.f.policy('acme').version });
  const intent = signed(input, h.setup.identityKeys.acme['operator'], 'capsule-intent');
  const record = h.f.propose(p, input, idem, intent);
  // The CAPSULE_PROPOSED anchor persists past the row's deletion — a
  // file-writer cannot turn the replay into an honest miss.
  h.f.store.remove('acme', 'capsule', record.capsule.capsule_id);
  assert.throws(() => h.f.propose(p, input, idem, intent), hasCode('INV-409-INTEGRITY'));
});

// F6: a non-Error throw inside a transaction must propagate the ORIGINAL
// value — never a TypeError from writing .rollback_error onto a primitive.
test('w31 fixverify F6: non-Error tx throw propagates past the rollback guard', t => {
  const h = fixture(t, ['acme']);
  assert.throws(() => h.f.store.tx(() => { throw 'plain-string-error'; }), e => e === 'plain-string-error');
});

// F7: a perception session anchored under the component's RETIRED signing
// key must not release once the config moved on — the anchored kid binds
// the live component credential, never any non-revoked string.
test('w31 fixverify F7: session minted under retired component key refuses release', t => {
  const h = fixture(t, ['acme']);
  const component = h.setup.componentSecrets.acme['secure-view-acme'];
  const session = h.f.perceptionSession(h.p(), component.attest('e'.repeat(64), h.now() + 300000));
  const rotated = generateKey();
  setTenant(h, 'acme', tn => { tn.components['secure-view-acme'].signing = { key_id: rotated.key_id, public_key: rotated.public_key, suite: 'Ed25519' }; });
  assert.throws(() => h.f.perceptionRelease(h.p(), session.session_id, { fields: { vendor: 'v1' }, purpose: 'verify' }), hasCode('INV-403-SCOPE'));
});

// coverage F1: a chain-declared path whose row was deleted is named in
// missing_rows — never silently absent from the signed manifest.
test('w31 coverage F1: deleted declared path is named in missing_rows', t => {
  const h = fixture(t, ['acme']);
  declarePath(h, 'p-gone');
  h.f.store.remove('acme', 'coverage', 'p-gone');
  const manifest = h.f.coverage(h.p('security'));
  assert.ok(manifest.payload.missing_rows.includes('p-gone'), `missing_rows must name the deleted path: ${JSON.stringify(manifest.payload.missing_rows)}`);
  assert.ok(!manifest.payload.paths.some(p => p.path_id === 'p-gone'));
});

// coverage F2+F10: the staleness sweep reads ANCHORED evidence_at only —
// row-only staleness and never-declared planted rows mint no transitions.
test('w31 coverage F2/F10: row-planted staleness mints no UNKNOWN transition', t => {
  const h = fixture(t, ['acme']);
  declarePath(h, 'p-sweep', 'MONITORED');
  const env = validationEnvelope(h, h.f.store.must('acme', 'coverage', 'p-sweep'));
  h.f.technicalValidation(h.p('security'), 'p-sweep', env.envelope); // anchored ENFORCED, fresh evidence_at
  const transitionsBefore = h.f.store.db.prepare("SELECT COUNT(*) n FROM audit WHERE tenant='acme' AND envelope LIKE '%COVERAGE_TRANSITION%'").get().n;
  // Plant a stale evidence_at on the row only — the anchored evidence is
  // still fresh, so no transition may fire.
  const path = h.f.store.must('acme', 'coverage', 'p-sweep');
  h.f.store.put('acme', 'coverage', 'p-sweep', { ...path, evidence_at: h.now() - 10 * 60000 }, h.now());
  // Plant a never-declared row claiming stale MONITORED — no declaration
  // anchor exists, so it can never mint a transition or a task either.
  h.f.store.insert('acme', 'coverage', 'p-phantom', { path_id: 'p-phantom', action_type: 'data.read', target: 'dataset-1', environment: 'prod', connector_version: '1.0', owner: 'op', status: 'MONITORED', path_class: 'api', max_age_ms: 60000, configuration_digest: digest({ cfg: 2 }), evidence_at: h.now() - 10 * 60000, declared_at: h.now() - 70000 }, h.now());
  const manifest = h.f.coverage(h.p('security'));
  const transitionsAfter = h.f.store.db.prepare("SELECT COUNT(*) n FROM audit WHERE tenant='acme' AND envelope LIKE '%COVERAGE_TRANSITION%'").get().n;
  assert.equal(transitionsAfter, transitionsBefore, 'row-planted staleness minted a phantom transition');
  assert.equal(h.f.store.db.prepare("SELECT COUNT(*) n FROM records WHERE tenant='acme' AND kind='coverage-task' AND substr(id,-9)=':p-phantom'").get().n, 0);
  assert.ok(manifest.payload.unanchored_rows.includes('p-phantom'));
  assert.ok(!manifest.payload.paths.some(p => p.path_id === 'p-phantom'));
  // And honest anchored staleness still demotes: advance past max_age so
  // the chain-anchored evidence expires — the sweep must fire.
  h.advance(120000);
  h.f.coverage(h.p('security'));
  assert.equal(h.f.store.db.prepare("SELECT COUNT(*) n FROM audit WHERE tenant='acme' AND envelope LIKE '%COVERAGE_TRANSITION%' AND envelope LIKE '%p-sweep%'").get().n >= 1, true);
});

// coverage F3: validation envelopes bind the ANCHORED identity — a
// whole-row digest and a mutated-row tuple both refuse.
test('w31 coverage F3: validation binds the anchored identity tuple', t => {
  const h = fixture(t, ['acme']);
  declarePath(h, 'p-bind');
  const path = h.f.store.must('acme', 'coverage', 'p-bind');
  // Legacy whole-row digest on a new-style declaration refuses.
  assert.throws(() => h.f.technicalValidation(h.p('security'), 'p-bind', validationEnvelope(h, path, 'security-ops', { capsule_digest: digest(path), claims: { capsule_digest: digest(path) } }).envelope), hasCode('INV-400-SCHEMA'));
  // Mutate an identity field on the row — an envelope minted against the
  // mutated tuple must refuse (it binds the planted fields, not the anchor).
  h.f.store.put('acme', 'coverage', 'p-bind', { ...path, owner: 'attacker' }, h.now());
  const mutated = h.f.store.must('acme', 'coverage', 'p-bind');
  assert.throws(() => h.f.technicalValidation(h.p('security'), 'p-bind', validationEnvelope(h, mutated).envelope), hasCode('INV-400-SCHEMA'));
  // Restore and bind the anchored identity — the honest path still works.
  h.f.store.put('acme', 'coverage', 'p-bind', path, h.now());
  assert.equal(h.f.technicalValidation(h.p('security'), 'p-bind', validationEnvelope(h, h.f.store.must('acme', 'coverage', 'p-bind')).envelope).status, 'ENFORCED');
  // A never-declared planted row cannot be validated at all.
  h.f.store.insert('acme', 'coverage', 'p-undeclared', { path_id: 'p-undeclared', action_type: 'data.read', target: 'dataset-1', environment: 'prod', connector_version: '1.0', owner: 'op', status: 'MONITORED', path_class: 'api', max_age_ms: 60000, configuration_digest: digest({ cfg: 3 }), evidence_at: h.now(), declared_at: h.now() }, h.now());
  const planted = h.f.store.must('acme', 'coverage', 'p-undeclared');
  assert.throws(() => h.f.technicalValidation(h.p('security'), 'p-undeclared', validationEnvelope(h, planted).envelope), hasCode('INV-409-INTEGRITY'));
});

// coverage F3 replay: a stale validation envelope can never re-promote —
// freshness requires acquired_at strictly greater than the last anchored
// validation's ledger time.
test('w31 coverage F3: replayed validation is refused, fresh re-validation passes', t => {
  const h = fixture(t, ['acme']);
  declarePath(h, 'p-fresh');
  const path = () => h.f.store.must('acme', 'coverage', 'p-fresh');
  assert.equal(h.f.technicalValidation(h.p('security'), 'p-fresh', validationEnvelope(h, path()).envelope).status, 'ENFORCED');
  // Same acquired_at as the anchored validation → replay, refused.
  assert.throws(() => h.f.technicalValidation(h.p('security'), 'p-fresh', validationEnvelope(h, path()).envelope), hasCode('INV-409-INTEGRITY'));
  h.advance(1000);
  assert.equal(h.f.technicalValidation(h.p('security'), 'p-fresh', validationEnvelope(h, path()).envelope).status, 'ENFORCED');
});

// coverage F4: the covered connector can never validate its own path.
test('w31 coverage F4: the covered connector cannot validate its own path', t => {
  const h = fixture(t, ['acme']);
  // Path target 'bank' binds the 'bank' issuer connector by name.
  h.f.declareCoverage(h.p('security'), { path_id: 'p-bank', action_type: 'payment.submit', target: 'bank', environment: 'prod', connector_version: '1.0.0', owner: 'op', status: 'UNCOVERED', path_class: 'api', max_age_ms: 600000, configuration_digest: 'a'.repeat(64) });
  const path = h.f.store.must('acme', 'coverage', 'p-bank');
  assert.throws(() => h.f.technicalValidation(h.p('security'), 'p-bank', validationEnvelope(h, path, 'bank').envelope), hasCode('INV-403-SCOPE'));
  // An independent validator still promotes the path.
  assert.equal(h.f.technicalValidation(h.p('security'), 'p-bank', validationEnvelope(h, path, 'security-ops').envelope).status, 'ENFORCED');
});

// coverage F5: the manifest's technical_validation and declared_at come
// from the signed chain — mutable row writes can never reshape them.
test('w31 coverage F5: manifest validation fields are chain-sourced', t => {
  const h = fixture(t, ['acme']);
  declarePath(h, 'p-chain');
  const env = validationEnvelope(h, h.f.store.must('acme', 'coverage', 'p-chain'));
  h.f.technicalValidation(h.p('security'), 'p-chain', env.envelope);
  // Forge the row's validation block + declared_at — the manifest must
  // show the anchored values.
  const row = h.f.store.must('acme', 'coverage', 'p-chain');
  h.f.store.put('acme', 'coverage', 'p-chain', { ...row, declared_at: h.now() - 86400000, technical_validation: { evidence_id: 'ev-forged', issuer: 'mallory', at: h.now(), outcome: 'supports' } }, h.now());
  const entry = h.f.coverage(h.p('security')).payload.paths.find(x => x.path_id === 'p-chain');
  assert.equal(entry.technical_validation.evidence_id, env.payload.evidence_id);
  assert.notEqual(entry.technical_validation.issuer, 'mallory');
  assert.equal(entry.declared_at, h.now() /* anchored declare time */);
});

// coverage F6+F7: open obligations derive from the anchored state and the
// promotion sweep closes open tasks by exact-suffix SQL — erased or
// oddly-keyed task rows can neither hide an obligation nor linger.
test('w31 coverage F6/F7: obligations survive erased tasks; sweep closes every open task', t => {
  const h = fixture(t, ['acme']);
  declarePath(h, 'p-obl', 'UNCOVERED');
  // Erase the mutable task row — the manifest must still carry the
  // obligation because the chain still declares the path UNCOVERED.
  h.f.store.remove('acme', 'coverage-task', 'declared-uncovered:p-obl');
  const manifest = h.f.coverage(h.p('security'));
  assert.ok(manifest.payload.open_obligations.some(o => o.path_id === 'p-obl' && o.status === 'UNCOVERED'));
  // Now plant an open task with a cause-keyed id and promote — the
  // suffix sweep must close it (id is `cause:path_id`).
  h.f.store.insert('acme', 'coverage-task', 'evidence-expired:p-obl', { path_id: 'p-obl', owner: 'op', cause: 'evidence-expired', status: 'open', opened_at: h.now() }, h.now());
  h.f.technicalValidation(h.p('security'), 'p-obl', validationEnvelope(h, h.f.store.must('acme', 'coverage', 'p-obl')).envelope);
  assert.equal(h.f.store.get('acme', 'coverage-task', 'evidence-expired:p-obl').status, 'closed');
  assert.ok(!h.f.coverage(h.p('security')).payload.open_obligations.some(o => o.path_id === 'p-obl'));
});

// coverage F8+F9: the drift sweep matches the declared connector_key_id —
// a path pinned to a drifted issuer by key stales even when its target
// names something else — and pages through every declared path.
test('w31 coverage F8: drift stales paths pinned by connector_key_id', async t => {
  const h = fixture(t, ['acme']);
  const [bankKeyId, bank] = Object.entries(h.f.tenant('acme').issuers).find(([, v]) => v.name === 'bank');
  const dir = mkdtempSync(join(tmpdir(), 'if-w31drift-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeIssuer(dir, { issuer: 'bank', tenant: 'acme', channel: 'authoritative', version: '1.0.0', key: h.setup.issuerKeys.acme['bank'], kinds: ISSUER_RULES.bank, records: issuerRecords().bank, issue_token: bank.issue_token, read_token: bank.read_token });
  const srv = createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', clock: () => h.now() });
  await srv.listen();
  h.repoint(bankKeyId, `http://127.0.0.1:${srv.server.address().port}`);
  // Path pinned to the bank connector by key id while its target names a
  // different system — a name-only drift matcher would leave it covered.
  h.f.declareCoverage(h.p('security'), { path_id: 'p-keyed', action_type: 'data.read', target: 'not-bank', environment: 'prod', connector_version: '1.0', owner: 'op', status: 'MONITORED', path_class: 'api', max_age_ms: 60000, configuration_digest: digest({ cfg: 4 }), connector_key_id: bankKeyId });
  assert.equal((await h.f.checkIssuerDrift(h.p('security'), bankKeyId)).drifted, false);
  await srv.close();
  const drifted = await h.f.checkIssuerDrift(h.p('security'), bankKeyId);
  assert.equal(drifted.drifted, true);
  assert.equal(drifted.coverage_paths_staled, 1, 'key-pinned path must stale on connector drift');
});

// runtime-gate F-1: a seal must carry spend authority — the cut span's
// verifiable RUNTIME_ALLOWED/DATA_ACCESSED events re-attest inside
// AUDIT_SEALED, consumed request ids stay consumed, budgets keep their
// charge, and a capability whose issuance anchor was cut can never spend
// again even though its signed envelope still verifies.
const dropAuditTriggers = db => { for (const tr of db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all()) db.exec(`DROP TRIGGER "${String(tr.name).replace(/"/g, '""')}"`); };
const restoreAuditTriggers = db => db.exec(`
  CREATE TRIGGER no_audit_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
  CREATE TRIGGER no_audit_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
  CREATE TRIGGER audit_seq_guard BEFORE INSERT ON audit WHEN NEW.seq <> (SELECT COALESCE(MAX(seq),0)+1 FROM audit WHERE tenant=NEW.tenant) BEGIN SELECT RAISE(ABORT, 'audit sequence must extend the head'); END;`);

test('w31 runtime F1: seal carries spend + request ids; cut-anchor capability refuses', t => {
  const h = fixture(t, ['acme']);
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ max_cost: 3 }));
  const req = runtimeRequest(cap);
  assert.equal(h.f.runtime.consume(h.p(), req).decision, 'ALLOW'); // charged 2 of 3
  const cap2 = h.f.runtime.issue(h.p(), runtimeInput({ max_cost: 1000 }));
  // Corrupt the first consume event — the seal cuts it and everything
  // after (cap's issuance anchor stays, its spend and cap2's issuance go).
  const bad = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND envelope LIKE '%DATA_ACCESSED%' ORDER BY seq LIMIT 1").get().seq;
  dropAuditTriggers(h.f.store.db);
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?").run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', bad);
  restoreAuditTriggers(h.f.store.db);
  assert.equal(h.f.sealAuditChain(h.p('security')).sealed, true);
  // The seal re-attested the surviving spend inside AUDIT_SEALED.
  const sealPl = JSON.parse(h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND envelope LIKE '%AUDIT_SEALED%' ORDER BY seq DESC LIMIT 1").get().envelope).payload;
  assert.ok(sealPl.metadata.spend_carryover.some(u => u.request_id === req.request_id), 'consumed request id carried into the seal record');
  // cap2's CAPABILITY_ISSUED anchor was cut — the envelope still verifies
  // but has no provable birth, so it can never spend.
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap2)), hasCode('INV-401-CAPABILITY'));
  // Replaying the carried request id still refuses as replay.
  assert.throws(() => h.f.runtime.consume(h.p(), req), hasCode('INV-409-REPLAY'));
  // And the budget kept its charge: 2 carried + 2 fresh > max_cost 3.
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap)), hasCode('INV-429-BUDGET'));
});

// runtime-gate F-2: a wedged (pre-seal) chain must not deadlock cold boot —
// construction survives so sealAuditChain stays reachable; the tenant's
// fold still refuses on demand.
test('w31 runtime F2: cold boot tolerates a wedged tenant', t => {
  const h = fixture(t, ['acme']);
  const bad = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq LIMIT 1 OFFSET 1").get().seq;
  dropAuditTriggers(h.f.store.db);
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?").run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', bad);
  restoreAuditTriggers(h.f.store.db);
  h.close();
  const f2 = new Fabric(h.setup.config, h.directory, () => h.now());
  t.after(() => f2.close());
  assert.throws(() => f2._auditIndex('acme'), e => /^INV-409/.test(e.code), 'the wedge itself is still live');
  assert.equal(f2.sealAuditChain({ tenant_id: 'acme', subject_id: 'security' }).sealed, true, 'remediation reachable on the same boot');
  const f3 = new Fabric(h.setup.config, h.directory, () => h.now());
  t.after(() => f3.close());
  assert.ok(f3._auditIndex('acme').maxSeq > 0, 'post-seal open folds cleanly');
});

// runtime-gate F-3: under constrained staleness the response must report
// the headroom the gate actually enforces (half the cap), not the full
// signed maximum.
test('w31 runtime F3: constrained consume reports effective headroom', t => {
  const h = fixture(t, ['acme']);
  installPolicy(h, p => { p.capability_ttl_ms = 300000; });
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ max_cost: 10, columns: ['id', 'name'], row_ids: ['row-1', 'row-2'], ttl_ms: 300000 }));
  installPolicy(h, p => { p.fail_modes = { ...p.fail_modes, 'data.read': 'constrained' }; });
  const res = h.f.runtime.consume(h.p(), runtimeRequest(cap));
  assert.equal(res.decision, 'ALLOW');
  // cost = 2 rows x 2 cols x weight 1 = 4; effective max = 10/2 = 5.
  assert.equal(res.remaining_capability_cost, 1, 'remaining reports the enforced half-budget');
});

// runtime-gate F-5: a classification with no sensitivity weight is a
// schema defect at policy validation — it can never reach consume as a
// NaN-cost capability.
test('w31 runtime F5: unpriced classification is refused at validation', t => {
  const h = fixture(t, ['acme']);
  const next = clone(h.f.policy('acme'));
  next.runtime.classifications = [...next.runtime.classifications, 'secret'];
  assert.throws(() => validatePolicy(next), hasCode('INV-400-SCHEMA'));
});

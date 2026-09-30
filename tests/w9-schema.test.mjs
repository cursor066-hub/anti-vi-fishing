import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture, hasCode } from './helpers.mjs';
import { loadIssuers, writeIssuer, answerQuery } from '../src/issuerd.mjs';
import { ISSUER_RULES, issuerRecords } from '../src/bootstrap.mjs';
import { KeyVault } from '../src/keystore.mjs';
import { SimulatedTarget } from '../src/target.mjs';
import { generateKey } from '../src/crypto.mjs';
import { encrypt } from '../src/crypto.mjs';
import { canonical } from '../src/canonical.mjs';
import { randomBytes } from 'node:crypto';

// Wave-9 schema/bootstrap audit regressions: vault asymmetry, spec shape,
// subject echo, spread shadowing, tuple AADs.

const spec = (name, over = {}) => ({ issuer: name, tenant: 'acme', version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds: ISSUER_RULES.bank, records: issuerRecords().bank, ...over });
const issueBody = { kind: 'ownership', subject_id: 'operator', claims: { account: 'TESTBANK000001', owner_id: 'vendor-1' }, capsule_digest: 'a'.repeat(64), tenant_id: 'acme' };

test('w9-schema F-4: master.key without keystore.json refuses to silently re-key', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-vault-')); t.after(() => rmSync(dir, { recursive: true }));
  writeFileSync(join(dir, 'master.key'), canonical({ format: 'IF-MASTERKEY-1', master_key: randomBytes(32).toString('base64url') }) + '\n');
  assert.throws(() => KeyVault.open(dir), hasCode('INV-503-CONFIG'));
  // Fabric path: a deployment dir with only master.key must not boot.
  const h = fixture(t);
  const { Fabric } = await import('../src/fabric.mjs');
  const empty = mkdtempSync(join(tmpdir(), 'if-fab-')); t.after(() => rmSync(empty, { recursive: true }));
  writeFileSync(join(empty, 'master.key'), canonical({ format: 'IF-MASTERKEY-1', master_key: randomBytes(32).toString('base64url') }) + '\n');
  assert.throws(() => new Fabric(h.setup.config, empty), hasCode('INV-503-CONFIG'));
});

test('w9-schema F-5: issuer specs validate shape, not just presence', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-iss-')); t.after(() => rmSync(dir, { recursive: true }));
  const bad = [
    { kinds: null }, { records: null }, { kinds: 'x' }, { records: [] },
    { key: { key_id: 'x' } }, { token_expires_at: '2026-10-01' },
    { token_expires_at: 1.5 }, { kinds: { ownership: 'flat' } },
  ];
  for (const over of bad) {
    writeFileSync(join(dir, 'bank.issuer.json'), JSON.stringify(spec('bank', over)), { mode: 0o600 });
    assert.throws(() => loadIssuers(dir), hasCode('INV-400-SCHEMA'), JSON.stringify(over));
  }
});

test('w9-schema F-3: caller-supplied request.subject_id never enters signed claims', t => {
  const s = spec('bank');
  // The stock ownership record carries no subject_id: the query's own
  // subject parameter must not be stamped under the signature.
  const env = answerQuery(s, issueBody, Date.now());
  assert.equal(env.payload.claim, 'supports', JSON.stringify(env.payload));
  assert.equal(env.payload.claims.subject_id, undefined);
  // The record's own subject still binds.
  s.records['account:TESTBANK000001'].subject_id = 'record-owner';
  const env2 = answerQuery(s, issueBody, Date.now());
  assert.equal(env2.payload.claim, 'supports');
  assert.equal(env2.payload.claims.subject_id, 'record-owner');
});

test('w9-schema F-7/F-8: stored id/version cannot shadow registry columns; tuple AADs both open', t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-tgt-')); t.after(() => rmSync(dir, { recursive: true }));
  const keys = { acme: randomBytes(32).toString('base64url') };
  const target = new SimulatedTarget(join(dir, 'target.db'), keys); t.after(() => target.close());
  target.seed('acme', 'ds-1', { columns: ['id', 'v'], rows: [{ id: 'row-1', v: 1, id_note: 'data-not-column' }] });
  const rows = target.datasetRows('acme', 'ds-1');
  assert.equal(rows[0].id, 'row-1', 'stored fields must not shadow the row_id projection');
  // A poisoned stored 'id' member still cannot shadow the registry column.
  const k = Buffer.from(keys.acme, 'base64url');
  target.db.prepare('INSERT INTO dataset_rows VALUES(?,?,?,?)').run('acme', 'ds-1', 'row-real', encrypt({ id: 'evil', v: 2 }, k, canonical(['target', 'dataset', 'acme', 'ds-1', 'row-real'])));
  assert.equal(target.datasetRows('acme', 'ds-1').find(r => r.v === 2).id, 'row-real');
  target.seedSecret('acme', 's-1', { version: 999, allowed_operations: ['read'], workload_id: 'w1' });
  const secret = target.secret('acme', 's-1');
  assert.equal(secret.version, 1, 'stored version member must not shadow the registry counter');
});

test('w9-schema F-8: legacy slash-AAD ciphertexts still decrypt after the migration', t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-tgt-')); t.after(() => rmSync(dir, { recursive: true }));
  const key = randomBytes(32).toString('base64url');
  const target = new SimulatedTarget(join(dir, 'target.db'), { acme: key }); t.after(() => target.close());
  // Hand-write a row under the PRE-migration slash AAD, then read it.
  const legacy = encrypt({ v: 42 }, Buffer.from(key, 'base64url'), 'acme/dataset/ds-2/row-9');
  target.db.prepare('INSERT INTO dataset_rows VALUES(?,?,?,?)').run('acme', 'ds-2', 'row-9', legacy);
  const rows = target.datasetRows('acme', 'ds-2');
  assert.equal(rows[0].v, 42);
  // The AADs are context-bound: a legacy resource ciphertext cannot be
  // replayed as a dataset row (context separation preserved).
  const res = encrypt({ planted: true }, Buffer.from(key, 'base64url'), 'acme/resource/ds-2');
  target.db.prepare('INSERT INTO dataset_rows VALUES(?,?,?,?)').run('acme', 'ds-2', 'row-10', res);
  assert.throws(() => target.datasetRows('acme', 'ds-2'), e => e instanceof Error);
});

test('w9-schema F-9: a leftover deployment dir gets an actionable refusal', async t => {
  const { bootstrap } = await import('../src/bootstrap.mjs');
  const dir = mkdtempSync(join(tmpdir(), 'if-boot-')); t.after(() => rmSync(dir, { recursive: true }));
  assert.throws(() => bootstrap(dir, ['acme']), e => /remove it and retry/.test(e.message));
});

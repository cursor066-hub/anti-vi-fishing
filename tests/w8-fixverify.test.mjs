import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes } from 'node:crypto';
import { fixture } from './helpers.mjs';
import { Store } from '../src/store.mjs';
import { encrypt } from '../src/crypto.mjs';

// w8-fixverify F1: rows sealed before the canonical-tuple AAD change stay
// readable — record bodies and wrapped DEKs both fall back to the legacy
// '/`-joined AAD instead of failing closed and getting shredded as "corrupt".
test('F1: pre-AAD-upgrade rows decrypt via the legacy fallback', t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-legacy-')); t.after(() => rmSync(dir, { recursive: true }));
  const tenantKey = randomBytes(32);
  const store = new Store(join(dir, 'fabric.db'), { acme: tenantKey.toString('base64url') }, {});
  t.after(() => store.close());
  // Pre-DEK era row: value sealed under the tenant key with '/`-joined AAD.
  const policy = { version: 3, rules: { 'finance.payment.first': { quorum: 2 } } };
  store.db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run('acme', 'policy', 'v1', encrypt(policy, tenantKey, 'acme/policy/v1'), 1);
  assert.deepEqual(store.get('acme', 'policy', 'v1'), policy);
  // Pre-tuple DEK era: wrapped key under '<aad>/dek', value under '<aad>'.
  const dek = randomBytes(32), capsule = { capsule_id: 'c1', state: 'ALLOW' };
  store.db.prepare('INSERT INTO deks VALUES(?,?,?,?)').run('acme', 'capsule', 'c1', encrypt(dek.toString('base64url'), tenantKey, 'acme/capsule/c1/dek'));
  store.db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run('acme', 'capsule', 'c1', encrypt(capsule, dek, 'acme/capsule/c1'), 2);
  assert.deepEqual(store.get('acme', 'capsule', 'c1'), capsule);
  assert.deepEqual(store.list('acme', 'capsule', 10), [capsule]);
  // put() re-seals under the tuple AAD — readable, and the legacy form no
  // longer applies to the fresh ciphertext.
  store.put('acme', 'capsule', 'c1', { ...capsule, state: 'DENY' }, 3);
  assert.equal(store.get('acme', 'capsule', 'c1').state, 'DENY');
});

// w8-fixverify F2: a contended checkpoint (SQLITE_LOCKED, not busy=1) must not
// fail a committed write — the shred flag stays armed and the next commit
// retries.
test('F2: a contended WAL checkpoint keeps committed work green and the flag armed', t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-wal-')); t.after(() => rmSync(dir, { recursive: true }));
  const tenantKey = randomBytes(32);
  const store = new Store(join(dir, 'fabric.db'), { acme: tenantKey.toString('base64url') }, {});
  store.db.exec('PRAGMA busy_timeout=500'); // keep the contention probe fast
  const reader = new DatabaseSync(join(dir, 'fabric.db'));
  reader.exec('BEGIN'); reader.prepare('SELECT value FROM records LIMIT 1').get();
  t.after(() => { try { reader.exec('ROLLBACK'); } catch { /* already rolled back */ } reader.close(); store.close(); });
  store.put('acme', 'capsule', 'x', { v: 1 }, 1);
  store._shredded = true;
  store.checkpoint(); // contention is absorbed; the flag stays armed
  assert.equal(store._shredded, true);
  store.tx(() => { store.put('acme', 'capsule', 'y', { v: 2 }, 2); });
  assert.deepEqual(store.get('acme', 'capsule', 'y'), { v: 2 });
  reader.exec('ROLLBACK');
  store.tx(() => { store.put('acme', 'capsule', 'z', { v: 3 }, 3); });
  assert.equal(store.db.prepare('PRAGMA wal_checkpoint').get().log, 0);
  assert.equal(store._shredded, false);
});

// w8-fixverify F3: every ciphertext-superseding target write arms the commit
// boundary truncation — grants, secrets and revocations included, not just
// dataset reseeds.
test('F3: superseding target writes truncate the WAL at commit', t => {
  const h = fixture(t, ['acme']);
  const log = () => h.f.target.db.prepare('PRAGMA wal_checkpoint').get().log;
  h.f.target.tx(() => { h.f.target.grant('acme', 'g1', { subject_id: 'x', expires_at: 9e12 }); });
  h.f.target.tx(() => { h.f.target.grant('acme', 'g1', { subject_id: 'x', expires_at: 9e12, v: 2 }); });
  assert.equal(log(), 0);
  h.f.target.seedSecret('acme', 's1', { allowed_operations: ['use'], workload_id: 'w1' });
  h.f.target.seedSecret('acme', 's1', { allowed_operations: ['use'], workload_id: 'w1', v: 2 });
  assert.equal(log(), 0);
  h.f.target.revokeGrant('acme', 'g1');
  h.f.target.tx(() => { h.f.target.exists('acme', 'noop'); });
  assert.equal(log(), 0);
  // Compensation path arms too: a restored resource supersedes its outcome.
  h.f.target.tx(() => { h.f.target.seed('acme', 'res-1', { balance: 5 }); });
  assert.equal(log(), 0);
});

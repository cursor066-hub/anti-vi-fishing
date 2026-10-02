// w19-aad regression suite — the AAD migration must never launder a planted
// transplant into a canonical binding. Every legacy-era graft from the
// hostile PoC is asserted quarantined (both sides stay sealed: fail-closed).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { Store } from '../src/store.mjs';
import { SimulatedTarget } from '../src/target.mjs';
import { encrypt } from '../src/crypto.mjs';
import { TRANSFORMS } from '../src/datagate.mjs';

const KEY = randomBytes(32).toString('base64url');
const keys = { acme: KEY };
const master = Buffer.from(KEY, 'base64url');
const T = 'acme';
let dir;
test.beforeEach(t => { dir = mkdtempSync(join(tmpdir(), 'w19-aad-')); });
test.afterEach(t => { rmSync(dir, { recursive: true, force: true }); });

const freshStore = name => { const p = join(dir, name); const s = new Store(p, keys, {}); s.close(); return p; };
const freshTarget = name => { const p = join(dir, name); const t0 = new SimulatedTarget(p, keys); t0.close(); return p; };
const raw = p => new DatabaseSync(p);
const stats = (s, t = T) => s.aadMigration?.get(t) ?? { migrated: 0, transplants: 0, ambiguous: 0, skipped: 0 };

// W19-1/A1 — the exact w18-crypto F2 primitive: a wrapped DEK transplanted
// into records(kind, id+'/dek') must never become a readable record — and
// the donor DEK must not launder either (both stay sealed).
test('w19-aad A1: a transplanted DEK quarantines both rows — no bare-DEK read', t => {
  const p = freshStore('a1.db'), db = raw(p);
  const dek = randomBytes(32), secret = { ssn: 'victim-plaintext' };
  const wrappedDek = encrypt(dek.toString('base64url'), master, `${T}/payroll/e-7/dek`);
  db.prepare('INSERT INTO deks VALUES(?,?,?,?)').run(T, 'payroll', 'e-7', wrappedDek);
  db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run(T, 'payroll', 'e-7', encrypt(secret, dek, `${T}/payroll/e-7`), 1);
  db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run(T, 'payroll', 'e-7/dek', wrappedDek, 1);
  db.close();
  const s = new Store(p, keys, {});
  assert.throws(() => s.get(T, 'payroll', 'e-7/dek'), 'the planted row never reads as a bare DEK');
  assert.throws(() => s.get(T, 'payroll', 'e-7'), 'the donor DEK was reverted — victim fails closed');
  assert.ok(stats(s).transplants >= 1, 'cross-identity duplicate ciphertext is counted');
  s.close();
});

// W19-1/A2 — colliding slash identities can never be proven non-transplanted:
// both copies stay sealed for operator review.
test('w19-aad A2: slash-ambiguous identities quarantine instead of migrating', t => {
  const p = freshStore('a2.db'), db = raw(p);
  const dek = randomBytes(32);
  db.prepare('INSERT INTO deks VALUES(?,?,?,?)').run(T, 'a', 'b/c', encrypt(dek.toString('base64url'), master, `${T}/a/b/c/dek`));
  const ct = encrypt({ flag: 'dup' }, dek, `${T}/a/b/c`);
  db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run(T, 'a', 'b/c', ct, 1);
  db.prepare('INSERT INTO deks VALUES(?,?,?,?)').run(T, 'a/b', 'c', db.prepare('SELECT wrapped FROM deks WHERE kind=? AND id=?').get('a', 'b/c').wrapped);
  db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run(T, 'a/b', 'c', ct, 1);
  db.close();
  const s = new Store(p, keys, {});
  assert.throws(() => s.get(T, 'a/b', 'c'), 'colliding twin never becomes a canonical row');
  assert.throws(() => s.get(T, 'a', 'b/c'), 'ambiguous donor stays sealed too');
  const st = stats(s);
  assert.ok(st.ambiguous >= 1 && st.transplants >= 1, `ambiguous+transplant accounting — got ${JSON.stringify(st)}`);
  s.close();
});

// W19-1/A3 — an idempotency receipt grafted into records('idempotency',…)
// aliases the idempotency space: both rows stay sealed.
test('w19-aad A3: idempotency-alias records rows quarantine', t => {
  const p = freshStore('a3.db'), db = raw(p);
  const receipt = encrypt({ receipt: 'sealed-op-result' }, master, `${T}/idempotency/pay/k-9`);
  db.prepare('INSERT INTO idempotency VALUES(?,?,?,?,?)').run(T, 'pay', 'k-9', 'hash-x', receipt);
  db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run(T, 'idempotency', 'pay/k-9', receipt, 1);
  db.close();
  const s = new Store(p, keys, {});
  assert.throws(() => s.get(T, 'idempotency', 'pay/k-9'), 'the grafted receipt never reads through records');
  s.close();
});

// W19-1/A4 — a planted colliding deks row cannot launder a foreign DEK; the
// donor record fails closed instead of serving a wrong key.
test('w19-aad A4: planted DEK alias quarantines the colliding identity', t => {
  const p = freshStore('a4.db'), db = raw(p);
  const dekA = randomBytes(32);
  db.prepare('INSERT INTO deks VALUES(?,?,?,?)').run(T, 'x', 'y/z', encrypt(dekA.toString('base64url'), master, `${T}/x/y/z/dek`));
  db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run(T, 'x', 'y/z', encrypt({ a: 1 }, dekA, `${T}/x/y/z`), 1);
  db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run(T, 'x/y', 'z', encrypt({ b: 2 }, master, `${T}/x/y/z`), 1);
  const stolen = db.prepare('SELECT wrapped FROM deks WHERE kind=? AND id=?').get('x', 'y/z').wrapped;
  db.prepare('INSERT INTO deks VALUES(?,?,?,?)').run(T, 'x/y', 'z', stolen);
  db.close();
  const s = new Store(p, keys, {});
  assert.throws(() => s.get(T, 'x/y', 'z'));
  assert.throws(() => s.get(T, 'x', 'y/z'), 'the donor fails closed rather than serving a laundered DEK');
  s.close();
});

// W19-1/A5 — cross-DB: a secrets_registry ciphertext copied into the store's
// records space is caught by the SHARED dedup — both sides stay sealed.
test('w19-aad A5: a cross-DB graft quarantines on both stores', t => {
  const tp = freshTarget('a5-target.db'), sp = freshStore('a5-store.db');
  const tdb = raw(tp), sdb = raw(sp);
  const secretCt = encrypt({ api_secret: 'live-key-material' }, master, `${T}/secret/s-1`);
  tdb.prepare('INSERT INTO secrets_registry VALUES(?,?,?,?)').run(T, 's-1', 1, secretCt);
  sdb.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run(T, 'secret', 's-1', secretCt, 1);
  tdb.close(); sdb.close();
  const dedup = new Map();
  const s = new Store(sp, keys, {}, { aadDedup: dedup });
  const t1 = new SimulatedTarget(tp, keys, { aadDedup: dedup });
  assert.throws(() => s.get(T, 'secret', 's-1'), 'grafted secret never reads through the ledger store');
  assert.throws(() => t1.secretState(T, 's-1'), 'the donor target row stays sealed too — dedup is cross-DB');
  assert.ok((s.aadMigration?.get(T)?.transplants ?? 0) + (t1.aadMigration?.get(T)?.transplants ?? 0) >= 1, 'shared dedup counted the graft');
  s.close(); t1.close();
});

// W19-1/A6b — dataset_rows colliding (dataset,row_id) identities quarantine.
test('w19-aad A6b: target dataset_rows collisions quarantine', t => {
  const tp = freshTarget('a6b.db'), tdb = raw(tp);
  const ct = encrypt({ balance: 9000 }, master, `${T}/dataset/a/b/c`);
  tdb.prepare('INSERT INTO dataset_rows VALUES(?,?,?,?)').run(T, 'a/b', 'c', ct);
  tdb.prepare('INSERT INTO dataset_rows VALUES(?,?,?,?)').run(T, 'a', 'b/c', ct);
  tdb.close();
  const t1 = new SimulatedTarget(tp, keys);
  // Both colliding rows stay sealed — the dataset read fails loudly instead
  // of serving an authoritative laundered twin.
  assert.throws(() => t1.datasetRows(T, 'a'), 'no laundered twin is served');
  assert.throws(() => t1.datasetRows(T, 'a/b'), 'the donor row fails closed too');
  t1.close();
});

// W19-1/A6c — a records ciphertext planted into target resources quarantines.
test('w19-aad A6c: a records ciphertext cannot launder into target state', t => {
  const sp = freshStore('a6c-store.db'), tp = freshTarget('a6c-target.db');
  const sdb = raw(sp), tdb = raw(tp);
  const ct = encrypt({ balance: 1337 }, master, `${T}/resource/res-9`);
  sdb.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run(T, 'resource', 'res-9', ct, 1);
  tdb.prepare('INSERT INTO resources VALUES(?,?,?,?)').run(T, 'res-9', 3, ct);
  sdb.close(); tdb.close();
  const dedup = new Map();
  const s = new Store(sp, keys, {}, { aadDedup: dedup });
  const t1 = new SimulatedTarget(tp, keys, { aadDedup: dedup });
  assert.throws(() => t1.state(T, 'res-9'), 'planted resource state never becomes authoritative');
  s.close(); t1.close();
});

// W19-2 — silent skips are counted: a corrupt row surfaces in the migration
// accounting instead of being indistinguishable from a clean open.
test('w19-aad W19-2: unmigratable rows are counted, never silently skipped', t => {
  const p = freshStore('a6.db'), db = raw(p);
  const good = encrypt({ ok: 1 }, master, `${T}/k/good`);
  const parts = encrypt({ bad: 1 }, master, `${T}/k/bad`).split('.');
  parts[2] = Buffer.from('tampered').toString('base64url');
  db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run(T, 'k', 'good', good, 1);
  db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run(T, 'k', 'bad', parts.join('.'), 1);
  db.close();
  const s = new Store(p, keys, {});
  assert.equal(s.get(T, 'k', 'good')?.ok, 1, 'clean rows still migrate and read');
  const st = stats(s);
  assert.ok(st.skipped >= 1, `corrupt row counted as skipped — got ${JSON.stringify(st)}`);
  assert.throws(() => s.get(T, 'k', 'bad'), 'the corrupt row fails loudly on read');
  s.close();
});

// W19-3 — post-migration checkpoint truncates the WAL so dead legacy bytes
// cannot linger in the main DB file image.
test('w19-aad W19-3: migration checkpoints the WAL after re-sealing', t => {
  const p = freshStore('a7.db'), db = raw(p);
  const dek = randomBytes(32);
  db.prepare('INSERT INTO deks VALUES(?,?,?,?)').run(T, 'k', 'i', encrypt(dek.toString('base64url'), master, `${T}/k/i/dek`));
  db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run(T, 'k', 'i', encrypt({ v: 7 }, dek, `${T}/k/i`), 1);
  db.close();
  const s = new Store(p, keys, {});
  assert.equal(s.get(T, 'k', 'i')?.v, 7, 'clean legacy rows migrate normally');
  const wal = join(dir, 'a7.db-wal');
  assert.equal(readFileSize(wal), 0, 'WAL truncated post-migration — dead legacy bytes gone');
  s.close();
});

// Adjacent fix — datagate tokenise tuple-binding: component-boundary slashes
// can no longer collide across tenant/dataset joins.
test('w19-aad: datagate tokenise binds components as a canonical tuple', t => {
  const ctx = { tenantKey: KEY };
  const t1 = TRANSFORMS.tokenise('v', 'f', { ...ctx, tenant: 'a/b', dataset: 'c' });
  const t2 = TRANSFORMS.tokenise('v', 'f', { ...ctx, tenant: 'a', dataset: 'b/c' });
  const t3 = TRANSFORMS.tokenise('v', 'f', { ...ctx, tenant: 'a/b', dataset: 'c' });
  assert.notEqual(t1, t2, '(a/b,c) and (a,b/c) can no longer tokenise identically');
  assert.equal(t1, t3, 'still deterministic for the same tuple');
});

import { statSync } from 'node:fs';
const readFileSize = p => { try { return statSync(p).size; } catch { return 0; } };

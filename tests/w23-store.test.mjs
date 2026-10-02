// w23-store regression suite — the clock-floor anchors, recovery veto sweep,
// savepoint hygiene and usage ledger must hold under file-level tamper and
// peer-instance incoherence (auditor findings W23-01..W23-10).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { Store } from '../src/store.mjs';
import { generateKey, signed, encrypt } from '../src/crypto.mjs';
import { fixture, runtimeInput } from './helpers.mjs';

const hasCode = code => e => e?.code === code;
const KEY = randomBytes(32).toString('base64url');
const keys = { acme: KEY };
const auditKey = generateKey();
const signer = {
  key_id: auditKey.key_id, public_key: auditKey.public_key,
  keys: () => ({ [auditKey.key_id]: { public_key: auditKey.public_key } }),
  sign: p => signed(p, auditKey, 'audit'),
};
const signers = { acme: signer };
const T = 'acme';
let dir;
test.beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'w23-store-')); });
test.afterEach(() => { rmSync(dir, { recursive: true, force: true }); });
const mkstore = name => new Store(join(dir, name), keys, signers);

// W23-01 — the resurrection veto must cover capabilities, JIT grants,
// perception sessions, live approvals and device health, not only
// certificates/capsules/tokens.
test('w23 W23-01a: a capability expiring inside the rewound span vetoes recovery', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  assert.ok(cap.payload.expires_at > h.now());
  // Ledger stands where the capability lapses; the rewind re-opens it.
  const span = cap.payload.expires_at - h.now() + 1000;
  h.f.store.tx(() => h.f.store.clock(h.now() + span));
  assert.throws(() => h.f.recoverClock(h.p('security')), hasCode('INV-503-TIME'), 'un-revoked resurrecting capability must veto');
  // Operator remediation: revoke the resurrecting authority, then recover.
  h.f.revoke(h.p('security'), { kind: 'capability', id: cap.payload.capability_id, reason: 'clock rewind' });
  assert.ok(h.f.recoverClock(h.p('security')).recovered_at);
});

test('w23 W23-01b: a JIT grant lapsing inside the rewound span vetoes recovery', t => {
  const h = fixture(t);
  const gid = `grant-${randomBytes(4).toString('hex')}`;
  const grant = { grant_id: gid, subject_id: 'operator', roles: ['operator'], resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: [], issued_at: h.now(), expires_at: h.now() + 60000 };
  h.f.target.grant(T, gid, grant);
  h.f.store.audit(T, 'JIT_GRANT_ISSUED', 'operator', 'operator', { grant_id: gid, scope_digest: 'd', expires_at: grant.expires_at }, h.now());
  h.f.store.tx(() => h.f.store.clock(h.now() + 120000));
  assert.throws(() => h.f.recoverClock(h.p('security')), hasCode('INV-503-TIME'), 'un-revoked resurrecting grant must veto');
  h.f.revoke(h.p('security'), { kind: 'grant', id: gid, reason: 'clock rewind' });
  assert.ok(h.f.recoverClock(h.p('security')).recovered_at);
});

// W23-02 — the open-time floor seeds from the newest VERIFIABLE row, never
// from a forged tail append the seq trigger legitimately admits.
test('w23 W23-02: a forged audit tail cannot seed the clock floor', t => {
  const p = join(dir, 's.db');
  const s = mkstore('s.db');
  s.tx(() => { s.clock(1000); s.audit(T, 'GENESIS', 'op', 'ref', {}, 1000); });
  s.close();
  // File-writer append: seq guard admits MAX+1, the row is well-formed but
  // unsigned — it must not seed the floor.
  const db = new DatabaseSync(p);
  db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run(T, 2, 'x'.repeat(64), 'y'.repeat(64), JSON.stringify({ protected: {}, payload: { time: 9999999999999, sequence: 2, type: 'GENESIS' }, signature: 'forged' }));
  db.close();
  const s2 = mkstore('s.db');
  t.after(() => s2.close());
  assert.equal(s2._chainFloor, 1000, 'floor seeds from the last verifiable entry');
  // And the honest floor still catches a planted rewind.
  s2.db.prepare('UPDATE clock SET last=500').run();
  assert.throws(() => s2.clock(800), hasCode('INV-409-AUDIT-TAMPER'));
});

test('w23 W23-02b: a chain tail with no verifiable entry bricks the open', t => {
  const p = join(dir, 's.db');
  const s = mkstore('s.db'); s.close();
  const db = new DatabaseSync(p);
  db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run(T, 1, '0'.repeat(64), 'x'.repeat(64), JSON.stringify({ protected: {}, payload: { time: 1, sequence: 1, type: 'GENESIS' }, signature: 'forged' }));
  db.close();
  assert.throws(() => mkstore('s.db'), hasCode('INV-409-AUDIT-TAMPER'), 'a fully-forged tail must not silently seed floor 0');
});

// W23-03 — peer instance coherence: a recovery committed by ANOTHER process
// must legalize this instance's rewound row without a restart.
test('w23 W23-03: a peer-committed CLOCK_RECOVERED is discovered on the fail path', t => {
  const p = join(dir, 's.db');
  const A = mkstore('s.db'); const B = mkstore('s.db');
  t.after(() => { A.close(); B.close(); });
  A.tx(() => { A.clock(2000); A.audit(T, 'GENESIS', 'op', 'ref', {}, 2000); });
  assert.equal(A._chainFloor, 2000); assert.equal(A._lastRecoveredAt, null);
  // Peer B repairs to 1500: forward-legal under the floor, attested on-chain.
  B.tx(() => { B.clock(1500, { recovery: true }); B.audit(T, 'CLOCK_RECOVERED', 'op', 'local-gate', { prior_last: 2000, recovered_at: 1500 }, 1500); });
  // A's anchors are stale (floor 2000, no recovery) — the shared row now
  // reads 1500. A write must refresh, discover B's attestation and pass.
  const now = A.clock(1600);
  assert.equal(now, 1600, 'peer recovery legalizes the row without a restart');
  assert.equal(A._lastRecoveredAt, 1500);
});

// W23-04 — a planted rewind below the floor must repair through the in-app
// recovery path, not dead-end on the state it exists to fix.
test('w23 W23-04: a planted clock rewind repairs through recoverClock', t => {
  const h = fixture(t);
  h.proposed();
  // File-writer rewind: clock.last drops below every attested chain time.
  h.f.store.db.prepare('UPDATE clock SET last=1').run();
  const r = h.f.recoverClock(h.p('security'));
  assert.equal(r.recovered_at, h.now(), 'forward repair of a planted rewind must land');
  // The discontinuity is attested on the signed chain.
  const tail = h.f.store.auditPage('acme', { after: 0, limit: 100000 }).entries.at(-1);
  assert.equal(tail.envelope.payload.type, 'CLOCK_RECOVERED');
  assert.equal(tail.envelope.payload.metadata.prior_last, 1);
});

// W23-05 — a failed audit() must not leave a phantom floor or a phantom
// clock ratchet behind.
test('w23 W23-05: an aborted audit() bumps no anchors and writes no ratchet', t => {
  const s = mkstore('s.db'); t.after(() => s.close());
  let fail = true;
  const flaky = { ...signer, sign: p => { if (fail) throw new Error('signer-boom'); return signed(p, auditKey, 'audit'); } };
  s.auditSigners[T] = flaky;
  assert.throws(() => s.audit(T, 'X', 'a', 'r', {}, 5000), /signer-boom/);
  assert.equal(s._chainFloor, 0, 'a phantom floor must not survive the abort');
  assert.equal(s.db.prepare('SELECT last FROM clock WHERE id=1').get(), undefined, 'a phantom ratchet must not survive the abort');
  fail = false;
  s.audit(T, 'X', 'a', 'r', {}, 5000);
  assert.equal(s._chainFloor, 5000);
});

// W23-06 — a faulting nested rollback must still restore anchors and surface
// the ORIGINAL error.
test('w23 W23-06: a faulting savepoint rollback restores anchors and rethrows the cause', t => {
  const s = mkstore('s.db'); t.after(() => s.close());
  const orig = s.db.exec.bind(s.db);
  s.db.exec = sql => /^ROLLBACK TO sp_/.test(sql) ? (() => { throw new Error('rollback-fail'); })() : orig(sql);
  const marker = new Error('inner-failure');
  let caught;
  s.tx(() => {
    try { s.tx(() => { s._chainFloor = 7777; throw marker; }); } catch (e) { caught = e; }
  });
  assert.equal(caught, marker, 'the original error surfaces, not the rollback fault');
  assert.equal(caught.rollback_error, 'rollback-fail', 'the rollback fault rides as evidence');
  assert.equal(s._chainFloor, 0, 'anchors restored despite the rollback fault');
  assert.equal(s._anchorStack.length, 0, 'no orphaned anchor frames');
});

// W23-07 — usage rows accumulate only: cost/at never move backward and the
// receipt's identity columns are immutable.
test('w23 W23-07: usage rows are monotone — rewind updates abort', t => {
  const s = mkstore('s.db'); t.after(() => s.close());
  s.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?)').run(T, 'subj', 'res', 100, 5, 'cap', 'req');
  // The legitimate accumulate path still works.
  s.db.prepare('INSERT INTO usage VALUES(?,?,?,?,?,?,?) ON CONFLICT(tenant,capability,request) DO UPDATE SET cost=cost+excluded.cost,at=excluded.at').run(T, 'subj', 'res', 200, 3, 'cap', 'req');
  assert.equal(s.db.prepare('SELECT cost FROM usage').get().cost, 8);
  assert.equal(s.db.prepare('SELECT at FROM usage').get().at, 200);
  assert.throws(() => s.db.prepare('UPDATE usage SET cost=1').run(), /usage is monotone/, 'cost rewind falsifies billing');
  assert.throws(() => s.db.prepare('UPDATE usage SET at=50').run(), /usage is monotone/, 'window rewind falsifies billing');
  assert.throws(() => s.db.prepare("UPDATE usage SET subject='other'").run(), /usage is monotone/, 'identity rewrite moves the receipt');
  assert.throws(() => s.db.prepare("UPDATE usage SET request='other'").run(), /usage is monotone/, 'request rewrite enables replay');
});

// W23-08 — degenerate cursors classify as schema faults, not crashes or
// unbounded reads.
test('w23 W23-08: auditPage refuses degenerate cursors and limits', t => {
  const s = mkstore('s.db'); t.after(() => s.close());
  s.tx(() => s.audit(T, 'X', 'a', 'r', {}, 1000));
  assert.throws(() => s.auditPage(T, { limit: 0 }), hasCode('INV-400-SCHEMA'), 'limit=0 must not reach rows.at(-1)');
  assert.throws(() => s.auditPage(T, { limit: -1 }), hasCode('INV-400-SCHEMA'), 'LIMIT -1 is an unbounded read');
  assert.throws(() => s.auditPage(T, { limit: 1.5 }), hasCode('INV-400-SCHEMA'));
  assert.throws(() => s.auditPage(T, { after: -1 }), hasCode('INV-400-SCHEMA'));
  // Boundary page: ending exactly at head is a clean empty page.
  const head = s.auditPage(T, { after: 0, limit: 1 });
  assert.equal(head.entries.length, 1); assert.equal(head.next_cursor, 1);
  const tail = s.auditPage(T, { after: 1, limit: 1000 });
  assert.deepEqual(tail.entries, []); assert.equal(tail.next_cursor, null);
});

// W23-09 — a cross-instance head race classifies as a retryable conflict,
// never a raw sqlite error.
test('w23 W23-09: a stale-snapshot audit append classifies cleanly', t => {
  const p = join(dir, 's.db');
  const A = mkstore('s.db'); const B = mkstore('s.db');
  t.after(() => { A.close(); B.close(); });
  A.tx(() => { A.clock(1000); A.audit(T, 'X', 'a', 'r', {}, 1000); });
  // B opens a deferred transaction — its snapshot is frozen at head seq=1.
  B.db.exec('BEGIN');
  assert.equal(B.db.prepare('SELECT COALESCE(MAX(seq),0) s FROM audit').get().s, 1);
  // A moves the real head forward.
  A.tx(() => A.audit(T, 'Y', 'a', 'r2', {}, 2000));
  // B's append either trips the seq guard or its snapshot refuses the write —
  // both must surface in the INV taxonomy, not as raw sqlite.
  assert.throws(() => B.audit(T, 'Z', 'a', 'r3', {}, 3000),
    e => e instanceof Error && /^INV-(503-LEDGER|409-CONFLICT|409-AUDIT-TAMPER)$/.test(e.code ?? ''), 'raw sqlite internals must not reach the caller');
  if (B.db.isTransaction) B.db.exec('ROLLBACK');
});

// W23-10 — a transplant-only migration pass still truncates the WAL so the
// reverted donor bytes do not linger in the log.
test('w23 W23-10: transplant detection checkpoints the WAL', t => {
  const p = join(dir, 't.db');
  { const s = new Store(p, keys, {}); s.close(); }
  const db = new DatabaseSync(p);
  const master = Buffer.from(KEY, 'base64url');
  const dek = randomBytes(32), secret = { ssn: 'victim' };
  const wrappedDek = encrypt(dek.toString('base64url'), master, `${T}/payroll/e-7/dek`);
  db.prepare('INSERT INTO deks VALUES(?,?,?,?)').run(T, 'payroll', 'e-7', wrappedDek);
  db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run(T, 'payroll', 'e-7', encrypt(secret, dek, `${T}/payroll/e-7`), 1);
  db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run(T, 'payroll', 'e-7/dek', wrappedDek, 1);
  db.close();
  const s = new Store(p, keys, {});
  t.after(() => s.close());
  const stats = s.aadMigration?.get(T) ?? {};
  assert.ok((stats.transplants ?? 0) >= 1, 'the graft is detected as a transplant');
  assert.ok(!existsSync(`${p}-wal`) || statSync(`${p}-wal`).size === 0, 'reverted donor bytes must not linger in the WAL');
});

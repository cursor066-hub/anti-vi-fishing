// Wave-48 regression tests: the auditor findings implemented in this wave —
// landed-checks on every security-critical write (RAISE(IGNORE) swallow is
// INV-409), open-time INSERT probes, stray-trigger naming on the chain,
// classify-all _schemaGuard, _ownSeq success-arm merge, aad marker INSERT
// guard, key-death extractor parity (orig_seq + floor_derived), chain-head
// lock starvation evidence, persistVault locking and verify-before-commit,
// bootstrap save durability, and the ledger's execution-bound evidence gate.
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { fixture, hasCode } from './helpers.mjs';
import { Fabric } from '../src/fabric.mjs';
import { verifyAudit } from '../src/store.mjs';

// --- fixverify CRITICAL: a planted RAISE(IGNORE) trigger must not swallow a write silently ---
test('w48: a planted RAISE(IGNORE) on audit INSERT convicts as INV-409-INTEGRITY, not silent success', t => {
  const h = fixture(t);
  h.f.store.db.exec("CREATE TRIGGER swallow_ins BEFORE INSERT ON audit BEGIN SELECT RAISE(IGNORE); END");
  assert.throws(() => h.f.store.tx(() => h.f.store.audit('acme', 'TAMPER_PROBE', 'system', 'x', {}, h.f.clock())),
    hasCode('INV-409-INTEGRITY'), 'an abandoned insert must throw tamper evidence, never report success');
  h.close();
});

test('w48: a planted RAISE(IGNORE) on target grants convicts as INV-409-INTEGRITY', t => {
  const h = fixture(t);
  h.f.target.db.exec("CREATE TRIGGER swallow_grant BEFORE INSERT ON grants BEGIN SELECT RAISE(IGNORE); END");
  assert.throws(() => h.f.target.grant('acme', 'grant-x', { issued_at: h.now() }),
    hasCode('INV-409-INTEGRITY'), 'the silent drop on a production landed write is classified tamper evidence');
  h.close();
});

test('w48: a planted RAISE(IGNORE) on nonces convicts the mint path', t => {
  const h = fixture(t);
  h.f.store.db.exec("CREATE TRIGGER swallow_nonce BEFORE INSERT ON nonces BEGIN SELECT RAISE(IGNORE); END");
  assert.throws(() => h.proposed(), hasCode('INV-409-INTEGRITY'),
    'a swallowed nonce burn is tamper evidence, not a successful mint');
  h.close();
});

// --- fixverify MEDIUM: classify-all schema guard — foreign ABORT = INV-409 ---
test('w48: a foreign RAISE(ABORT) trigger on audit classifies INV-409-INTEGRITY inside tx', t => {
  const h = fixture(t);
  h.f.store.db.exec("CREATE TRIGGER mimic_guard BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'planted abort'); END");
  assert.throws(() => h.f.store.tx(() => h.f.store.audit('acme', 'TAMPER_PROBE', 'system', 'x', {}, h.f.clock())),
    hasCode('INV-409-INTEGRITY'), 'a foreign RAISE inside a guarded write is tamper evidence');
  h.close();
});

// --- fixverify CRITICAL (b): stray foreign triggers are named on the chain ---
test('w48: stray foreign triggers planted on both DBs are dropped AND attested by name', t => {
  const h = fixture(t);
  h.proposed();
  h.f.store.db.exec("CREATE TRIGGER foreign_store BEFORE INSERT ON nonces BEGIN SELECT RAISE(IGNORE); END");
  h.f.target.db.exec("CREATE TRIGGER foreign_target BEFORE INSERT ON resources BEGIN SELECT RAISE(IGNORE); END");
  h.close();
  const f2 = new Fabric(h.setup.config, h.directory, h.now);
  try {
    const row = f2.store.db.prepare("SELECT envelope FROM audit WHERE json_extract(envelope,'$.payload.type')='STORE_SCHEMA_RESIDUE' ORDER BY seq DESC LIMIT 1").get();
    assert.ok(row, 'a dropped foreign trigger must be attested on the chain');
    const meta = JSON.parse(row.envelope).payload.metadata;
    assert.equal(meta.reason, 'foreign-triggers-dropped');
    assert.ok(meta.detail.includes('foreign_store'), `store drop named: ${meta.detail}`);
    assert.ok(meta.detail.includes('foreign_target'), `target drop named: ${meta.detail}`);
    assert.equal(f2.store.db.prepare("SELECT COUNT(*) n FROM sqlite_master WHERE type='trigger' AND name='foreign_store'").get().n, 0);
    assert.equal(f2.target.db.prepare("SELECT COUNT(*) n FROM sqlite_master WHERE type='trigger' AND name='foreign_target'").get().n, 0);
  } finally { f2.close(); }
});

// --- fixverify LOW: aad_migration marker INSERT arm is guarded on both DBs ---
test('w48: aad_migration marker is unforgeable via INSERT OR REPLACE on both stores', t => {
  const h = fixture(t);
  for (const db of [h.f.store.db, h.f.target.db]) {
    assert.throws(() => db.prepare("INSERT OR REPLACE INTO meta_kv VALUES('acme','aad_migration','{\"planted\":1}')").run(),
      e => /aad migration marker is evidence/.test(e?.message ?? ''), 'the INSERT arm of the marker guard aborts the forge');
    assert.throws(() => db.prepare("INSERT INTO meta_kv VALUES('acme','aad_migration','{\"planted\":1}')").run(),
      e => /aad migration marker is evidence/.test(e?.message ?? ''), 'plain INSERT is guarded too');
    // Non-marker keys stay writable — the WHEN-scoped guard must not over-block.
    assert.doesNotThrow(() => db.prepare("INSERT OR REPLACE INTO meta_kv VALUES('acme','other_key','{}')").run());
  }
  h.close();
});

// --- fixverify LOW: rolled-back inner appends must not merge into the outer claimed tail ---
test('w48: a rolled-back inner append leaves no phantom seq claim and the chain stays sealable', t => {
  const h = fixture(t);
  h.proposed();
  const seqBefore = h.f.store.db.prepare("SELECT MAX(seq) s FROM audit WHERE tenant='acme'").get().s;
  h.f.store.tx(() => {
    h.f.store.audit('acme', 'OUTER_ROW', 'system', 'x', {}, h.f.clock());
    try { h.f.store.tx(() => { h.f.store.audit('acme', 'INNER_DOOMED', 'system', 'x', {}, h.f.clock()); throw new Error('doom'); }); }
    catch { /* inner rollback is honest */ }
    h.f.store.audit('acme', 'OUTER_ROW2', 'system', 'x', {}, h.f.clock());
  });
  const rows = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND seq > ? ORDER BY seq").all(seqBefore).map(r => r.seq);
  assert.deepEqual(rows, [seqBefore + 1, seqBefore + 2], 'the rolled-back inner append leaves no committed row and no seq hole');
  // Reopen: the fold must verify clean — a phantom merge would inflate the
  // claimed tail and convict the honest chain.
  h.close();
  const f2 = new Fabric(h.setup.config, h.directory, h.now);
  try { assert.doesNotThrow(() => f2.sealAuditChain(h.p('security')), 'post-rollback chain seals cleanly'); }
  finally { f2.close(); }
});

// --- store CRITICAL W48-1: a far-future-mtime lock is stale, not immortal ---
test('w48: a chain-head lock pinned in the FUTURE is cleared as stale, commits never starve', t => {
  const h = fixture(t);
  const lockPath = join(h.directory, 'chain-heads.json.lock');
  mkdirSync(lockPath);
  utimesSync(lockPath, new Date(Date.now() + 600_000), new Date(Date.now() + 600_000));
  assert.doesNotThrow(() => h.proposed(), 'a future-dated lock dir is stale evidence, never an immortal wedge');
  assert.equal(existsSync(lockPath), false, 'the stale lock was cleared');
  h.close();
});

test('w48: a live-held chain-head lock starves the flush — commits land and the loss is attested on-chain', t => {
  const h = fixture(t);
  h.proposed();
  const lockPath = join(h.directory, 'chain-heads.json.lock');
  mkdirSync(lockPath); // fresh mtime — held by "a live peer" beyond the deadline
  // The commit itself lands; only the unwitnessed head file is starved.
  assert.doesNotThrow(() => h.f.store.tx(() => h.f.store.audit('acme', 'PENDING_HEAD', 'system', 'x', {}, h.f.clock())),
    'a starved flush must not block the commit');
  // A lock whose mtime ages past the stale window is legitimately cleared,
  // so the live holder refreshes it — and the next transaction's pending
  // retry starves again, attesting the unwitnessed window on-chain.
  utimesSync(lockPath, new Date(), new Date());
  h.f.transaction(h.p('operator'), () => h.f.store.audit('acme', 'AFTER_STARVED', 'system', 'x', {}, h.f.clock()));
  const row = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND json_extract(envelope,'$.payload.type')='HEAD_FLUSH_STARVED'").get();
  assert.ok(row, 'a persistently starved flush window is attested on the signed chain');
  const meta = JSON.parse(row.envelope).payload.metadata;
  assert.ok(meta.consecutive >= 1, 'the attestation carries the consecutive-loss count');
  rmSync(lockPath, { recursive: true, force: true });
  h.close();
});

// --- store HIGH W48-2: persistVault never clobbers a consistent pair with a divergent master ---
test('w48: persistVault refuses to overwrite keystore.json under a divergent on-disk master', t => {
  const h = fixture(t);
  const dir = h.directory;
  h.f.persistVault();
  const ksBefore = readFileSync(join(dir, 'keystore.json'));
  // Simulate a concurrent instance's divergent master landing on disk.
  writeFileSync(join(dir, 'master.key'), JSON.stringify({ format: 'IF-MASTERKEY-1', master_key: randomBytes(32).toString('base64url') }) + '\n');
  assert.throws(() => h.f.persistVault(), hasCode('INV-503-CONFIG'),
    'a divergent persist must refuse before the rename commits');
  assert.deepEqual(readFileSync(join(dir, 'keystore.json')), ksBefore, 'the consistent keystore was not clobbered');
  h.close();
});

test('w48: persistVault on an existing pair under the same master commits normally', t => {
  const h = fixture(t);
  h.f.persistVault();
  const f2 = new Fabric(h.setup.config, h.directory, h.now);
  try { assert.doesNotThrow(() => f2.persistVault(), 'a same-master instance persists without refusal'); }
  finally { f2.close(); }
  h.close();
});

// --- crypto F-w48-2: _auditKeyDeaths pins carried deaths at orig_seq and exempts floor_derived ---
test('w48: _auditKeyDeaths pins carried key deaths at orig_seq and exempts floor_derived', t => {
  const h = fixture(t);
  h.proposed();
  const maxSeq = h.f.store.db.prepare("SELECT MAX(seq) s FROM audit WHERE tenant='acme'").get().s;
  const carry = (carryovers) => JSON.stringify({ payload: { type: 'AUDIT_SEALED', reference: 'seal-x', metadata: { revocations_carryover: carryovers } } });
  // A carried non-floor 'key:' death pins at orig_seq, not the carrying row.
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', maxSeq + 1, 'x', 'x', carry([{ reference: 'key:ghost-kid', orig_seq: 7, at: h.now() }]));
  let dead = h.f.store._auditKeyDeaths('acme');
  assert.equal(dead.get('ghost-kid'), 7, 'the carried death pins at the death position, not the carrier row');
  // The same claim flagged floor_derived pins nothing — the fold's own
  // exemption (a planted floor claim never manufactures a death window).
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', maxSeq + 2, 'x', 'x', carry([{ reference: 'key:ghost-kid2', orig_seq: 3, at: h.now(), floor_derived: true }]));
  dead = h.f.store._auditKeyDeaths('acme');
  assert.equal(dead.get('ghost-kid2'), undefined, 'a floor_derived key claim is exempt');
  h.close();
});

// --- crypto F-w48-1/3 parity smoke: a sealed chain still verifies end-to-end ---
test('w48: verifyAudit accepts a sealed chain — carried-death orig_seq pinning does not over-convict', t => {
  const h = fixture(t);
  h.proposed();
  // Convict a mid row and seal — the seal writes AUDIT_SEALED + carry rows.
  const midSeq = h.f.store.db.prepare("SELECT MAX(seq) s FROM audit WHERE tenant='acme'").get().s - 1;
  h.f.store.db.exec('DROP TRIGGER no_audit_update');
  h.f.store.db.prepare("UPDATE audit SET envelope='{}' WHERE tenant='acme' AND seq=?").run(midSeq);
  assert.doesNotThrow(() => h.f.sealAuditChain(h.p('security')));
  h.proposed();
  const bundle = h.f.exportAudit(h.p('auditor'), 'w48 parity smoke');
  assert.doesNotThrow(() => verifyAudit(bundle, bundle.public_keys), 'carried-death parity must not convict the honest sealed chain');
  h.close();
});

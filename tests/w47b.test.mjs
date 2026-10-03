// w47b regression tests — the w47 auditor batch: marker UPDATE guards,
// planted-trigger taxonomy, seal trigger-collision hardening, pending-row
// marker continuity, the rollback-evicted honoured-grant memo, containment
// request_id normalization, and the issuerd connection/liveness fixes.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EventEmitter } from 'node:events';
import { fixture, runtimeInput, runtimeRequest, hasCode, plantAadMarker } from './helpers.mjs';
import { Fabric } from '../src/fabric.mjs';
import { createIssuerServer } from '../src/issuerd.mjs';
import { ISSUER_RULES, issuerRecords } from '../src/bootstrap.mjs';
import { generateKey } from '../src/crypto.mjs';

// --- fixverify HIGH-1: the aad_migration marker is update-guarded too ---
test('w47b store: in-place UPDATE of the evidence marker aborts in-band', t => {
  const h = fixture(t);
  plantAadMarker(h.f.store.db, 'acme', '{\"migrated\":1}');
  assert.throws(
    () => h.f.store.db.prepare("UPDATE meta_kv SET value='{}' WHERE tenant='acme' AND key='aad_migration'").run(),
    e => /aad migration marker is evidence/.test(e?.message ?? ''),
    'a bare UPDATE could launder attested residue to nothing — the guard refuses');
  h.close();
});

test('w47b target: marker UPDATE guard exists on the target store too', t => {
  const h = fixture(t);
  plantAadMarker(h.f.target.db, 'acme', '{\"migrated\":1}');
  assert.throws(
    () => h.f.target.db.prepare("UPDATE meta_kv SET value='{}' WHERE tenant='acme' AND key='aad_migration'").run(),
    e => /aad migration marker is evidence/.test(e?.message ?? ''));
  h.close();
});

// --- fixverify M-1: a foreign planted RAISE is integrity evidence ---
test('w47b store: a planted foreign trigger on records classifies INV-409-INTEGRITY', t => {
  const h = fixture(t);
  h.f.store.db.exec("CREATE TRIGGER planted_no BEFORE INSERT ON records BEGIN SELECT RAISE(ABORT, 'tamper payload'); END");
  assert.throws(
    () => h.proposed(),
    hasCode('INV-409-INTEGRITY'),
    'a foreign RAISE on the write path is tamper evidence, not raw sqlite internals');
  h.close();
});

test('w47b target: a foreign RAISE inside a guarded write classifies INV-409-INTEGRITY', t => {
  const h = fixture(t);
  h.f.target.db.exec("CREATE TRIGGER planted_m BEFORE INSERT ON meta_kv BEGIN SELECT RAISE(ABORT, 'tamper payload'); END");
  assert.throws(
    () => h.f.target._schemaGuard(() => h.f.target._stmt("INSERT INTO meta_kv VALUES('acme','k','{}')").run()),
    hasCode('INV-409-INTEGRITY'),
    'a foreign RAISE on the target write path is tamper evidence too');
  h.close();
});

// --- seal F-2: a planted same-name trigger cannot wedge the guard restore ---
test('w47b seal F-2: the seal drops a colliding trigger name and restores its own guard', t => {
  const h = fixture(t);
  h.proposed(); // a few committed rows so the chain has a mid row to convict
  // Convict a mid-chain row: rewrite an envelope under a dropped guard.
  const midSeq = h.f.store.db.prepare("SELECT MAX(seq) s FROM audit WHERE tenant='acme'").get().s - 1;
  h.f.store.db.exec('DROP TRIGGER no_audit_update');
  h.f.store.db.prepare("UPDATE audit SET envelope='{}' WHERE tenant='acme' AND seq=?").run(midSeq);
  // Plant a same-named trigger on a sibling table — sqlite trigger names
  // are global, so a bare CREATE would die mid-statement and leave the
  // audit table unprotected.
  h.f.store.db.exec("CREATE TRIGGER no_audit_update BEFORE UPDATE ON meta_kv BEGIN SELECT RAISE(ABORT, 'planted'); END");
  assert.doesNotThrow(() => h.f.sealAuditChain(h.p('security')), 'the seal must not die on the planted name collision');
  const trig = h.f.store.db.prepare("SELECT sql FROM sqlite_master WHERE type='trigger' AND name='no_audit_update'").get();
  assert.ok(trig && /ON audit\b/.test(trig.sql), 'the real append-only guard is recreated on audit');
  h.close();
});

// --- fixverify HIGH-2: a murdered marker cannot silence the owed attestation ---
test('w47b fixverify HIGH-2: a verified AAD_MIGRATION_PENDING row drives attestation with the marker gone', t => {
  const h = fixture(t);
  // Land a signed pending row — the durable twin a file-writer cannot
  // erase — then close. No marker row exists: the chain alone must carry
  // the owed attestation across the reboot.
  h.f.store.tx(() => h.f.store.audit('acme', 'AAD_MIGRATION_PENDING', 'system', 'fabric-open',
    { origin: 'store', migrated: 3, transplants: 0, ambiguous: 0, skipped: 0, migration_id: 'pmid-1' }, h.f.clock()));
  h.close();
  const f2 = new Fabric(h.setup.config, h.directory, h.now);
  try {
    const env = f2.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND json_extract(envelope,'$.payload.type')='AAD_MIGRATION' ORDER BY seq DESC LIMIT 1").get();
    assert.ok(env, 'the next open attests the pending migration even though the marker is gone');
    const meta = JSON.parse(env.envelope).payload.metadata;
    assert.ok(meta.marker_digests.includes('pmid-1'), 'the attestation names the pending migration digest');
    assert.equal(meta.pending_stats?.[0]?.migrated, 3, 'the pending stats ride into the attestation honestly');
    assert.equal(f2.store.db.prepare("SELECT COUNT(*) n FROM meta_kv WHERE key='aad_migration'").get().n, 0,
      'no marker is re-seeded');
  } finally { f2.close(); }
});

// --- fixverify HIGH-3: a rollback must evict the honoured-grant memo ---
test('w47b fixverify HIGH-3: a rolled-back phantom JIT grant is never served', t => {
  const h = fixture(t);
  const before = h.f.grantsFor('acme', 'operator', h.now());
  // Doomed transaction: an uncommitted JIT_GRANT_ISSUED row folds into the
  // tx-window scan; the grant query inside the window can cache it under a
  // key that survives identically after a refill.
  try {
    h.f.store.tx(() => {
      h.f.store.audit('acme', 'JIT_GRANT_ISSUED', 'system', 'phantom', {
        grant_id: 'phantom-grant',
        scope_digest: 'ph'.repeat(32),
        expires_at: h.now() + 60000,
      }, h.f.clock());
      try { h.f.grantsFor('acme', 'operator', h.now()); } catch { /* the phantom may murder-check inside the window — either way the cache is armed */ }
      throw new Error('doomed');
    });
  } catch (e) { assert.equal(e.message, 'doomed'); }
  const after = h.f.grantsFor('acme', 'operator', h.now());
  assert.deepEqual(after.tuples, before.tuples, 'the phantom grant must not outlive its doomed row');
  h.close();
});

// --- runtime F2: request_id-less denials match the anchored reference ---
test('w47b runtime F2: a denial without request_id is not counted missing', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  const req = runtimeRequest(cap);
  delete req.request_id;
  try { h.f.runtime.consume(h.p(), { ...req, port: 99 }); } catch { /* the denial lands */ }
  const rep = h.f.containmentReport(h.p('security'));
  assert.equal(rep.anchored_denials_missing_total, 0,
    'the stored row and the anchored reference now spell request_id the same way');
  h.close();
});

// --- issuerd HIGH: over-cap sockets must still decrement on close ---
test('w47b http HIGH: destroying an over-cap socket does not wedge the counter', async t => {
  const srv = createIssuerServer({}, { port: 0, host: '127.0.0.1' });
  // Node wraps socket.on through socketListenerWrap — real EventEmitter
  // sockets make the close handlers fireable from the harness.
  const socks = []; let destroyed = 0;
  const sock = () => { const s = new EventEmitter(); s.destroy = () => destroyed++; s.setTimeout = () => {}; socks.push(s); return s; };
  for (let i = 0; i < 2050; i++) srv.server.emit('connection', sock());
  assert.equal(destroyed, 2, 'two over-cap sockets are destroyed');
  for (const s of socks) s.emit('close');
  srv.server.emit('connection', sock());
  assert.equal(destroyed, 2, 'a fresh connection after the flood is NOT rejected — the counter drained');
  // Never listened: nothing to close beyond the emitter surface.
});

// --- issuerd LOW: unauthenticated unknown-path probes consume budget and log ---
test('w47b http LOW: an unauthenticated 404 probe lands in the issuance log', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'issuerd-log-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const spec = { issuer: 'bank', tenant: 'acme', version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds: ISSUER_RULES.bank, records: issuerRecords().bank, read_token: 'tok' };
  const srv = createIssuerServer({ 'acme:bank': spec }, { port: 0, host: '127.0.0.1', logPath: join(dir, 'issuance.jsonl') });
  await srv.listen(); t.after(() => srv.close());
  const port = srv.server.address().port;
  const res = await fetch(`http://127.0.0.1:${port}/v1/nonsense`);
  assert.equal(res.status, 404);
  const lines = readFileSync(join(dir, 'issuance.jsonl'), 'utf8').trim().split('\n').map(l => JSON.parse(l));
  assert.ok(lines.some(l => l.refused === true && l.route === 'unknown' && l.unauthenticated === true),
    'the silent fallthrough is a logged, budgeted probe now');
});

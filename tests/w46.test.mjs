// w46 regression tests: the 8th store/crash-consistency hostile pass
// attacked the tx-window memos, the aad_migration marker durability, the
// unguarded bulk audit readers, the head-verification memo key, and the
// vault chmod swallow. Every test asserts the FIXED behavior; attack
// shapes come from the auditor PoCs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helpers.mjs';
import { Fabric } from '../src/fabric.mjs';
import { hashBytes } from '../src/canonical.mjs';

const dropAuditTriggers = db => { for (const tr of db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all()) db.exec(`DROP TRIGGER "${String(tr.name).replace(/"/g, '""')}"`); };

test('w46-store M-1: a rolled-back revocation cannot keep minting phantom deaths through the tx-window memo', t => {
  const h = fixture(t);
  const tenant = 'acme';
  // Inside the tx: append a death and force the facts fold so the cf:
  // memo caches it; the rollback then proves whether the memo evicts.
  try {
    h.f.store.tx(() => {
      h.f.store.audit(tenant, 'AUTHORITY_REVOKED', 'security', 'key:audit-phantom', {}, h.now());
      assert.equal(h.f._keyDeaths(tenant).has('audit-phantom'), true, 'in-tx fold sees the pending death');
      throw new Error('abort');
    });
    assert.fail('tx must propagate the abort');
  } catch (e) { assert.equal(e.message, 'abort'); }
  // The row is gone but _auditAppends kept its bump — a memo keyed on the
  // append counter alone would still report the death it folded.
  assert.equal(h.f.store.db.prepare('SELECT COUNT(*) n FROM audit WHERE tenant=?').get(tenant).n > 0, true, 'pre-abort rows remain');
  assert.equal(h.f._keyDeaths(tenant).has('audit-phantom'), false, 'rolled-back death is gone from the facts surface');
  h.close();
});

test('w46-store M-2a: the aad_migration marker is delete-guarded on the live ledger', t => {
  const h = fixture(t);
  h.f.store.db.prepare("INSERT INTO meta_kv VALUES('acme','aad_migration','{\"migrated\":1}')").run();
  assert.throws(() => h.f.store.db.prepare("DELETE FROM meta_kv WHERE tenant='acme' AND key='aad_migration'").run(),
    e => /aad migration marker is evidence/.test(e?.message ?? ''), 'a live delete of the evidence marker aborts in-band');
  h.close();
});

test('w46-store M-2b: the marker guard exists on the target store too', t => {
  const h = fixture(t);
  h.f.target.db.prepare("INSERT INTO meta_kv VALUES('acme','aad_migration','{\"migrated\":1}')").run();
  assert.throws(() => h.f.target.db.prepare("DELETE FROM meta_kv WHERE tenant='acme' AND key='aad_migration'").run(),
    e => /aad migration marker is evidence/.test(e?.message ?? ''), 'target-side evidence marker aborts on delete');
  h.close();
});

test('w46-store M-2c: sanctioned post-attest cleanup still clears the marker through the guard', t => {
  const h = fixture(t);
  // A configured-tenant marker attests on the next open, then drops —
  // the guard's drop+recreate path is the sanctioned delete (w45-ledger
  // HIGH-1d parity exercised through the new guard).
  h.f.store.db.prepare("INSERT INTO meta_kv VALUES('acme','aad_migration',?)").run(JSON.stringify({ migrated: 2 }));
  h.close();
  const f2 = new Fabric(h.setup.config, h.directory, h.now);
  try {
    assert.equal(f2.store.db.prepare("SELECT COUNT(*) n FROM meta_kv WHERE key='aad_migration'").get().n, 0, 'attested marker is dropped by the sanctioned path');
    const trig = f2.store.db.prepare("SELECT sql FROM sqlite_master WHERE type='trigger' AND name='aad_marker_keep'").get();
    assert.ok(trig, 'the guard is recreated after the sanctioned delete');
    assert.throws(() => {
      f2.store.db.prepare("INSERT INTO meta_kv VALUES('acme','aad_migration','{}')").run();
      f2.store.db.prepare("DELETE FROM meta_kv WHERE tenant='acme' AND key='aad_migration'").run();
    }, e => /aad migration marker is evidence/.test(e?.message ?? ''), 'the recreated guard still fires');
  } finally { f2.close(); }
});

test('w46-store M-2d: non-marker meta_kv rows stay writable beside the guard', t => {
  const h = fixture(t);
  h.f.store.db.prepare("INSERT INTO meta_kv VALUES('acme','other_key','v')").run();
  h.f.store.db.prepare("DELETE FROM meta_kv WHERE tenant='acme' AND key='other_key'").run();
  assert.equal(h.f.store.db.prepare("SELECT COUNT(*) n FROM meta_kv WHERE key='other_key'").get().n, 0, 'the WHEN-scoped guard only guards the evidence key');
  h.close();
});

test('w46-store M-3a: a dropped audit table classifies INV-409 on auditExport', t => {
  const h = fixture(t);
  dropAuditTriggers(h.f.store.db);
  h.f.store.db.exec('DROP TABLE audit');
  assert.throws(() => h.f.store.auditExport('acme'), e => e?.code === 'INV-409-INTEGRITY', 'bulk export classifies schema divergence as integrity evidence');
  h.close();
});

test('w46-store M-3b: a dropped audit table classifies INV-409 on auditHashes and auditPage', t => {
  const h = fixture(t);
  dropAuditTriggers(h.f.store.db);
  h.f.store.db.exec('DROP TABLE audit');
  assert.throws(() => h.f.store.auditHashes('acme'), e => e?.code === 'INV-409-INTEGRITY');
  assert.throws(() => h.f.store.auditPage('acme'), e => e?.code === 'INV-409-INTEGRITY');
  assert.throws(() => h.f.store._auditKeyDeaths('acme'), e => e?.code === 'INV-409-INTEGRITY');
  h.close();
});

test('w46-store M-3c: a dropped audit table classifies INV-409 on the direct chain-facts path', t => {
  const h = fixture(t);
  dropAuditTriggers(h.f.store.db);
  h.f.store.db.exec('DROP TABLE audit');
  h.f.invalidateAuditIndex('acme');
  assert.throws(() => h.f._keyDeaths('acme'), e => e?.code === 'INV-409-INTEGRITY', '_chainFacts classifies inside the taxonomy, not raw sqlite');
  h.close();
});

test('w46-ledger HIGH-1: a dup-keyed graft cannot launder marker attestation', t => {
  const h = fixture(t);
  const tenant = 'acme';
  const markerValue = JSON.stringify({ migrated: 4 });
  h.f.store.db.prepare("INSERT INTO meta_kv VALUES('acme','aad_migration',?)").run(markerValue);
  const D = hashBytes(markerValue);
  // Graft a forged first 'payload' member onto any signed row — the SQL
  // narrowing saw its type+digest while verifySigned passed on the last
  // (genuine) member, so the planted marker read as 'already attested'
  // and was silently deleted (w46-ledger HIGH-1 PoC).
  const row = h.f.store.db.prepare('SELECT seq,envelope FROM audit WHERE tenant=? ORDER BY seq LIMIT 1').get(tenant);
  const grafted = `{"payload":{"type":"AAD_MIGRATION","metadata":{"marker_digests":["${D}"]}},` + row.envelope.slice(1);
  dropAuditTriggers(h.f.store.db);
  h.f.store.db.prepare('UPDATE audit SET envelope=? WHERE tenant=? AND seq=?').run(grafted, tenant, row.seq);
  h.close();
  const f2 = new Fabric(h.setup.config, h.directory, h.now);
  try {
    // The graft is a decoy candidate, never an attestation: the real
    // AAD_MIGRATION anchor still lands naming this marker's digest.
    const attested = f2.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND json_valid(envelope) AND json_extract(envelope,'$.payload.type') IN ('AAD_MIGRATION','AAD_MIGRATION_MARKER')").all()
      .some(r => { try { const md = JSON.parse(r.envelope).payload?.metadata?.marker_digests; return Array.isArray(md) && md.includes(D); } catch { return false; } });
    assert.equal(attested, true, 'the marker digest must be attested on chain — the graft cannot launder it');
    assert.equal(f2.store.db.prepare("SELECT COUNT(*) n FROM meta_kv WHERE key='aad_migration'").get().n, 0, 'marker clears only through the attested path');
  } finally { f2.close(); }
});

test('w46-store L-1: a rewritten envelope under a borrowed verified hash no longer skips the head check', t => {
  const h = fixture(t);
  const tenant = 'acme';
  // Land two rows so the head's hash is memoized as verified.
  h.f.store.audit(tenant, 'CONFIG_SNAPSHOT', 'security', 'warmup-a', {}, h.now());
  h.f.store.audit(tenant, 'CONFIG_SNAPSHOT', 'security', 'warmup-b', {}, h.now());
  const head = h.f.store.db.prepare('SELECT seq,hash,envelope FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get(tenant);
  // Surgery: keep the stored hash column (the memo's old key) but rewrite
  // the envelope bytes to attacker-chosen content — under the hash-only
  // key the next append would have chained on a lie without re-verifying.
  const evil = JSON.stringify({ payload: { type: 'AUTHORITY_REVOKED', reference: 'principal:everyone', actor: 'attacker', time: 1 }, signature: 'f'.repeat(88), key_id: 'audit' });
  dropAuditTriggers(h.f.store.db);
  h.f.store.db.prepare('UPDATE audit SET envelope=? WHERE tenant=? AND seq=?').run(evil, tenant, head.seq);
  assert.throws(() => h.f.store.audit(tenant, 'CONFIG_SNAPSHOT', 'security', 'after-murder', {}, h.now()),
    e => e?.code === 'INV-409-AUDIT-TAMPER', 'the head check re-fires when the bytes under a known hash diverge');
  h.close();
});

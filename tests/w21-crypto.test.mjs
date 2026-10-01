// w21-crypto/store regression suite — release-citation anchored integrity
// (w21-crypto F-1), vault key-id hygiene + tenant binding + load wraps
// (F-6/F-7/F-9), dead-key windows in the anchored scans (F-3), store
// append-only triggers + head/tenant tamper classification, target.tx
// nesting — each asserted against the behavior the auditor demonstrated.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, createHmac } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { fixture, hasCode, designateSuccessor } from './helpers.mjs';
import { KeyVault } from '../src/keystore.mjs';
import { signed, generateKey } from '../src/crypto.mjs';
import { digest, canonical } from '../src/canonical.mjs';

const T = 'acme';

// ─── w21-crypto F-6/F-8: vault key ids must never collide with prototypes ──
test('w21-crypto F-6: generate() rejects a prototype-member key id', t => {
  const h = fixture(t);
  for (const id of ['__proto__', 'prototype', 'constructor'])
    assert.throws(() => h.f.vault.generate('audit', { key_id: id }), hasCode('INV-400-SCHEMA'), `key_id ${id} refused`);
  assert.doesNotThrow(() => h.f.vault.generate('audit', { key_id: `k-${randomBytes(4).toString('hex')}` }));
});

test('w21-crypto F-8: importKey() rejects a prototype-member key id', t => {
  const h = fixture(t);
  const k = generateKey();
  k.key_id = '__proto__';
  assert.throws(() => h.f.vault.importKey(k, 'audit'), hasCode('INV-400-SCHEMA'));
});

// ─── w21-crypto F-7: vault enforces tenant binding when the caller names it ─
test('w21-crypto F-7: sign/envelope refuse a foreign tenant id', t => {
  const h = fixture(t);
  const kid = h.f.vault.generate('audit', { tenant_id: 'acme' }).key_id;
  assert.throws(() => h.f.vault.envelope(kid, 'audit', { x: 1 }, { tenant_id: 'globex' }), hasCode('INV-403-SCOPE'));
  assert.throws(() => h.f.vault.sign(kid, 'audit', 'msg', { tenant_id: 'globex' }), hasCode('INV-403-SCOPE'));
  assert.doesNotThrow(() => h.f.vault.envelope(kid, 'audit', { x: 1 }, { tenant_id: 'acme' }));
  // An unscoped key may still sign for a named tenant (config bootstrap).
  const free = h.f.vault.generate('audit');
  assert.doesNotThrow(() => h.f.vault.envelope(free.key_id, 'audit', { x: 1 }, { tenant_id: 'acme' }));
});

// ─── w21-crypto F-9: keystore load wraps unwrap/duplicate faults ───────────
const mac = (master, st) => createHmac('sha256', master).update(canonical(st)).digest('base64url');
const keyState = t => {
  const directory = mkdtempSync(join(tmpdir(), 'ks-'));
  t?.after(() => rmSync(directory, { recursive: true }));
  const master = randomBytes(32).toString('base64url'), path = join(directory, 'keystore.json');
  const v = new KeyVault(master); v.generate('audit'); v.save(path);
  return { master, path, state: JSON.parse(readFileSync(path, 'utf8')) };
};

test('w21-crypto F-9: a duplicate key id inside a MAC-valid file is refused', t => {
  const { master, path, state } = keyState(t);
  const { mac: _drop, ...body } = state;
  body.keys.push({ ...body.keys[0] });
  writeFileSync(path, JSON.stringify({ ...body, mac: mac(master, body) }));
  assert.throws(() => KeyVault.load(path, master), hasCode('INV-503-CONFIG'));
});

test('w21-crypto F-9b: a corrupt wrapped blob surfaces INV-503-CONFIG', t => {
  const { master, path, state } = keyState(t);
  const { mac: _drop, ...body } = state;
  body.keys[0].wrapped = 'forged-blob';
  writeFileSync(path, JSON.stringify({ ...body, mac: mac(master, body) }));
  assert.throws(() => KeyVault.load(path, master), hasCode('INV-503-CONFIG'));
});

// ─── w21-crypto F-1: release citations re-prove anchored integrity ──────────
test('w21-crypto F-1: a cited capsule rewritten at the row is refused', t => {
  const h = fixture(t);
  const { record } = h.ready();
  const id = record.capsule.capsule_id;
  const row = h.f.store.must(T, 'capsule', id);
  // Mutable-row tamper: the actor field no longer matches the signed intent.
  h.f.store.put(T, 'capsule', id, { ...row, capsule: { ...row.capsule, actor: { ...row.capsule.actor, subject_id: 'mallory' } } }, h.now());
  assert.throws(() => h.f.perceptionFallback(h.p(), { fields: { note: 'x' }, purpose: 'test', capsule_id: id }), hasCode('INV-409-INTEGRITY'), 'tampered capsule row cannot be cited');
});

test('w21-crypto F-1b: a cited evidence row diverging from its envelope dies', t => {
  const h = fixture(t);
  const record = h.proposed();
  const env = h.evidence(record, { kind: 'ownership' });
  const eid = env.payload.evidence_id;
  const row = h.f.store.must(T, 'evidence', eid);
  h.f.store.put(T, 'evidence', eid, { ...row, payload: { ...row.payload, kind: 'forged' } }, h.now());
  assert.throws(() => h.f.perceptionFallback(h.p(), { fields: { note: 'x' }, purpose: 'test', evidence_ref: eid }), hasCode('INV-409-INTEGRITY'));
});

test('w21-crypto F-1c: revoked evidence can never be cited into a release', t => {
  const h = fixture(t);
  const record = h.proposed();
  const env = h.evidence(record, { kind: 'ownership' });
  h.f.revoke(h.p('security'), { kind: 'evidence', id: env.payload.evidence_id, reason: 'retracted' });
  assert.throws(() => h.f.perceptionFallback(h.p(), { fields: { note: 'x' }, purpose: 'test', evidence_ref: env.payload.evidence_id }), hasCode('INV-403-QUARANTINE'));
});

// ─── w21-crypto F-3: anchored scans enforce the dead-key window ─────────────
test('w21-crypto F-3: a dead key cannot mint the anchored config snapshot', t => {
  const h = fixture(t);
  h.f.reassertConfig(h.p('security'));
  const before = h.f._anchoredConfigSnapshot(T);
  assert.ok(before, 'a live snapshot baseline exists');
  const auditKey = h.setup.config.tenants.acme.keys.audit;
  designateSuccessor(h, 'audit');
  h.f.revoke(h.p('security'), { kind: 'key', id: auditKey.key_id, reason: 'leaked' });
  // Plant a self-consistent CONFIG_SNAPSHOT signed by the DEAD key — the
  // scan must skip it instead of adopting a poisoned drift baseline.
  const head = h.f.store.db.prepare("SELECT seq,hash FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get();
  const payload = { tenant_id: 'acme', sequence: head.seq + 1, previous: head.hash, type: 'CONFIG_SNAPSHOT', actor: 'mallory', reference: 'config', metadata: { config_digest: 'deadbeef'.repeat(8) }, time: h.now() };
  const envelope = signed(payload, { key_id: auditKey.key_id, private_key: auditKey.private_key }, 'audit');
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', head.seq + 1, head.hash, digest(payload), canonical(envelope));
  assert.equal(h.f._anchoredConfigSnapshot(T), before, 'dead-key snapshot never reaches the baseline');
});

// ─── w21-store: append-only triggers actually fire at runtime ───────────────
test('w21-store: direct UPDATE/DELETE on append-only tables aborts', t => {
  const h = fixture(t);
  h.proposed(); // seeds a nonces row — row-level triggers only fire on matched rows
  h.f.store.audit(T, 'BOOT', 'system', 'boot', {}, h.now());
  assert.throws(() => h.f.store.db.prepare("UPDATE audit SET envelope='x' WHERE tenant=?").run(T), /append-only audit/);
  assert.throws(() => h.f.store.db.prepare("DELETE FROM audit WHERE tenant=?").run(T), /append-only audit/);
  assert.throws(() => h.f.store.db.prepare("DELETE FROM nonces WHERE tenant=?").run(T), /append-only nonces/);
  h.f.store.clock(h.now()); // seeds the rewind-detector row
  assert.throws(() => h.f.store.db.prepare("DELETE FROM clock WHERE id=1").run(), /clock is monotone/);
  // A seq-squat insert (a gap ahead of the head) aborts too.
  const head = h.f.store.db.prepare('SELECT MAX(seq) s FROM audit WHERE tenant=?').get(T).s;
  assert.throws(() => h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run(T, head + 5, 'x', 'x', '{}'), /audit sequence must extend the head/);
});

test('w21-store: a tampered integrity trigger fails the verbatim reinstall check', t => {
  const h = fixture(t);
  h.f.store.db.exec("DROP TRIGGER no_audit_update");
  h.f.store.db.exec("CREATE TRIGGER no_audit_update BEFORE UPDATE ON audit WHEN NEW.seq < 0 BEGIN SELECT RAISE(ABORT, 'never fires'); END");
  // The stored text no longer matches byte-for-byte — reinstall must
  // refuse, not silently adopt the weakened guard.
  assert.throws(() => h.f.store._installIntegrityGuards(), /integrity trigger missing or tampered/);
});

test('w21-store: corrupt head envelope surfaces INV-409-AUDIT-TAMPER', t => {
  const h = fixture(t);
  h.f.store.audit(T, 'BOOT', 'system', 'boot', {}, h.now());
  // Attacker with file access drops the update guard, corrupts the head
  // envelope — the next keyed append must fail classified, not with a
  // bare JSON parser error.
  const path = h.f.store.db.location();
  const db2 = new DatabaseSync(path);
  db2.exec('DROP TRIGGER no_audit_update');
  db2.prepare("UPDATE audit SET envelope='{corrupt' WHERE tenant=? AND seq=(SELECT MAX(seq) FROM audit WHERE tenant=?)").run(T, T);
  db2.close();
  assert.throws(() => h.f.store.audit(T, 'NEXT', 'system', 'x', {}, h.now()), hasCode('INV-409-AUDIT-TAMPER'));
});

test('w21-store: a valid envelope attesting another tenant dies at export', t => {
  const h = fixture(t);
  // An acme-signed row that ATTESTS a different tenant id — the signature
  // verifies, so only the tenant binding catches it.
  const head = h.f.store.db.prepare("SELECT seq,hash FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get() ?? { seq: 0, hash: '0'.repeat(64) };
  const auditKid = h.f.tenant(T).keys.audit.key_id;
  const payload = { tenant_id: 'globex', sequence: head.seq + 1, previous: head.hash, type: 'BOOT', actor: 'mallory', reference: 'x', metadata: {}, time: h.now() };
  const envelope = h.f.vault.envelope(auditKid, 'audit', payload);
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', head.seq + 1, head.hash, digest(envelope.payload), canonical(envelope));
  assert.throws(() => h.f.store.auditPage('acme', { after: 0, limit: 100 }), hasCode('INV-409-AUDIT-TAMPER'));
});

// ─── w21-store: target.tx nesting ───────────────────────────────────────────
test('w21-store: a nested target.tx rolls back to its savepoint', t => {
  const h = fixture(t);
  const ts = h.f.target;
  assert.throws(() => ts.tx(() => {
    ts.grant(T, 'g-outer', 'outer-value');
    ts.tx(() => { ts.grant(T, 'g-inner', 'inner-value'); throw new Error('inner abort'); });
  }), /inner abort/);
  assert.equal(ts.db.prepare('SELECT COUNT(*) c FROM grants WHERE tenant=?').get(T).c, 0, 'outer tx rolled back the surviving write too');
  ts.tx(() => { ts.grant(T, 'g-outer', 'outer-value'); try { ts.tx(() => { ts.grant(T, 'g-inner', 'inner-value'); throw new Error('inner'); }); } catch { /* inner rolled back */ } });
  const rows = ts.db.prepare('SELECT grant_id FROM grants WHERE tenant=?').all(T).map(r => r.grant_id);
  assert.deepEqual(rows, ['g-outer'], 'inner savepoint rolled back, outer commit kept');
});

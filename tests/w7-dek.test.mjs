// Wave-7 regression: DEK lifecycle / crypto-shredding audit findings
// (w7-dek F1-F6) plus the remaining perception/advisory tail (P-3, P-8, A-1).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { fixture, hasCode } from './helpers.mjs';
import { KeyVault } from '../src/keystore.mjs';
import { createConfiguration } from '../src/bootstrap.mjs';
import { Fabric } from '../src/fabric.mjs';
import { extract } from '../src/advisory.mjs';
import { digest } from '../src/canonical.mjs';

test('DEK F1: retention sweep survives a re-minted tombstone id', t => {
  const h = fixture(t); h.ready();
  const evId = h.f.store.list('acme', 'evidence', 100, 0)[0].payload.evidence_id;
  const shred = () => {
    const ev = h.f.store.must('acme', 'evidence', evId);
    ev.payload.retention_until = h.now() - 1; ev.legal_hold = false;
    h.f.store.put('acme', 'evidence', evId, ev, h.now());
    const capsule = h.f.store.list('acme', 'capsule', 100, 0).find(r => r.evidence.includes(evId));
    if (capsule) { capsule.evidence = capsule.evidence.filter(x => x !== evId); h.f.store.put('acme', 'capsule', capsule.capsule.capsule_id, capsule, h.now()); }
  };
  shred();
  assert.ok(h.f.retentionSweep(h.p('security')).deleted >= 1);
  assert.ok(h.f.store.list('acme', 'evidence-tombstone', 100, 0).some(x => x.evidence_id === evId));
  // An issuer legitimately re-mints the shredded evidence_id — the next
  // sweep must not wedge on the stale tombstone (was: INV-409-CONFLICT
  // rolling back the entire sweep forever).
  h.f.store.put('acme', 'evidence', evId, { payload: { evidence_id: evId, retention_until: h.now() - 1 }, envelope: { protected: {}, payload: {}, signature: 'x' }, legal_hold: false }, h.now());
  const out = h.f.retentionSweep(h.p('security'));
  assert.ok(out.deleted >= 1 && out.corrupt === 0);
});

test('DEK F5: undecryptable residue is shredded by the sweep, not kept forever', t => {
  const h = fixture(t); h.ready();
  h.f.store.db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run('acme', 'evidence', 'ev-corrupt', 'not-a-real-ciphertext', h.now());
  const out = h.f.retentionSweep(h.p('security'));
  assert.ok(out.corrupt >= 1 && out.corrupt_shredded >= 1);
  assert.equal(h.f.store.db.prepare("SELECT 1 FROM records WHERE kind='evidence' AND id='ev-corrupt'").get(), undefined);
});

test('DEK F6: record AAD is injective — transplanted ciphertext never decrypts', t => {
  const h = fixture(t);
  // (kind='x', id='a/b') must never alias (kind='x/a', id='b').
  h.f.store.put('acme', 'x', 'a/b', { v: 'first' }, h.now());
  h.f.store.put('acme', 'x/a', 'b', { v: 'second' }, h.now());
  assert.equal(h.f.store.get('acme', 'x', 'a/b').v, 'first');
  assert.equal(h.f.store.get('acme', 'x/a', 'b').v, 'second');
  // Transplant A's ciphertext + wrapped DEK under a new id — AAD binds the
  // (tenant,kind,id) tuple so the moved material is undecryptable.
  const row = h.f.store.db.prepare("SELECT value FROM records WHERE kind='x' AND id='a/b'").get();
  const dek = h.f.store.db.prepare("SELECT wrapped FROM deks WHERE kind='x' AND id='a/b'").get();
  h.f.store.db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run('acme', 'x', 'moved', row.value, h.now());
  h.f.store.db.prepare('INSERT INTO deks VALUES(?,?,?,?)').run('acme', 'x', 'moved', dek.wrapped);
  assert.throws(() => h.f.store.get('acme', 'x', 'moved'));
});

test('DEK F2: deployment config carries data keys wrapped under the vault master key', t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-dek-'));
  const vault = new KeyVault(randomBytes(32).toString('base64url'));
  const setup = createConfiguration(['acme'], Date.now(), { vault });
  const row = setup.config.tenants.acme;
  assert.equal(row.encryption_key, undefined);
  assert.equal(row.watermark_key, undefined);
  assert.ok(typeof row.encryption_key_wrapped === 'string' && typeof row.watermark_key_wrapped === 'string');
  const f = new Fabric(setup.config, dir, () => Date.now(), { vault });
  // config.json alone cannot decrypt records — the unwrap needs master.key.
  f.store.put('acme', 'evidence', 'ev-x', { payload: { evidence_id: 'ev-x' }, envelope: {}, legal_hold: false }, Date.now());
  assert.equal(f.store.get('acme', 'evidence', 'ev-x').payload.evidence_id, 'ev-x');
  f.store.close(); f.target.close();
});

test('P-3: a release cannot cite a capsule belonging to another actor', t => {
  const h = fixture(t);
  const component = h.setup.componentSecrets.acme['secure-view-acme'];
  const r = h.proposed(); // proposed by 'operator'
  const session = h.f.perceptionSession(h.p('custodian-1'), component.attest(randomBytes(32).toString('hex'), h.now() + 300000));
  assert.throws(() => h.f.perceptionRelease(h.p('custodian-1'), session.session_id, { fields: { vendor: 'v1' }, purpose: 'inspect', capsule_id: r.capsule.capsule_id }), hasCode('INV-403-SCOPE'));
});

test('P-8: fallback release validates and binds citations', t => {
  const h = fixture(t); h.ready();
  const r = h.ready().record; // ALLOW-decided authority (w8-fixverify F4, w22-fv F2)
  assert.throws(() => h.f.perceptionFallback(h.p(), { fields: { view: 'x' }, purpose: 'inspect', capsule_id: 'cap-ghost' }), hasCode('INV-404-NOT-FOUND'));
  const out = h.f.perceptionFallback(h.p(), { fields: { view: 'x' }, purpose: 'inspect', capsule_id: r.capsule.capsule_id });
  assert.equal(out.binding.capsule_id, r.capsule.capsule_id);
  // w8-fixverify F4 + w22-fixverify F2: undecided capsules, capsules decided
  // to anything but ALLOW, advisory evidence and mismatched capsule↔evidence
  // pairs are all refused — a citation can never float free of allowed
  // authority.
  const r2 = h.proposed();
  assert.throws(() => h.f.perceptionFallback(h.p(), { fields: { view: 'x' }, purpose: 'inspect', capsule_id: r2.capsule.capsule_id }), hasCode('INV-409-STATE'));
  const r3 = h.proposed(); h.evidence(r3); h.f.evaluate(h.p(), r3.capsule.capsule_id);
  assert.throws(() => h.f.perceptionFallback(h.p(), { fields: { view: 'x' }, purpose: 'inspect', capsule_id: r3.capsule.capsule_id }), hasCode('INV-412-EVIDENCE'), 'an ESCROW-decided capsule is not release authority');
  const advisory = h.evidence(h.proposed(), { advisory: true });
  assert.throws(() => h.f.perceptionFallback(h.p(), { fields: { view: 'x' }, purpose: 'inspect', evidence_ref: advisory.payload.evidence_id }), hasCode('INV-412-EVIDENCE'));
  const foreign = h.evidence(h.proposed(), {});
  assert.throws(() => h.f.perceptionFallback(h.p(), { fields: { view: 'x' }, purpose: 'inspect', capsule_id: r.capsule.capsule_id, evidence_ref: foreign.payload.evidence_id }), hasCode('INV-403-SCOPE'));
});

test('DEK F4: deleted dataset rows do not linger in the target WAL', t => {
  const h = fixture(t);
  h.f.target.seed('acme', 'dataset-1', { columns: ['id', 'v'], rows: [{ id: 'r1', v: 'a' }, { id: 'r2', v: 'b' }] });
  h.f.target.seed('acme', 'dataset-1', { columns: ['id', 'v'], rows: [{ id: 'r1', v: 'a2' }] });
  // The delete inside the second seed armed the commit-boundary checkpoint —
  // the WAL reports zero un-checkpointed frames immediately.
  assert.equal(h.f.target.db.prepare('PRAGMA wal_checkpoint').get().log, 0);
});

test('A-1: extraction honours the canonical-covered document limit', t => {
  assert.throws(() => extract('x'.repeat(65537)), hasCode('INV-400-SCHEMA'));
  const out = extract('x'.repeat(65536));
  assert.equal(out.advisory, true);
});

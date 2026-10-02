import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { fixture, hasCode, designateSuccessor } from './helpers.mjs';
import { encrypt, decrypt } from '../src/crypto.mjs';
import { signAcknowledgement } from '../src/ceremony.mjs';

// w18-crypto wave: legacy-AAD transplant closure, quorum-designated
// successors, and the ceremony one-shot invariant.

// F1+F2: the legacy slash-form AAD space is closed after open — a raw-DB
// transplant of sealed ciphertext into `records` can no longer decrypt.
test('w18-crypto F1+F2: legacy-AAD transplant cannot decrypt (records, deks, idempotency)', t => {
  const h = fixture(t);
  const store = h.f.store;
  store.put('acme', 'x-kind', 'x-id', { v: 'secret' }, h.now());
  const wrappedDek = store.db.prepare('SELECT wrapped FROM deks WHERE tenant=? AND kind=? AND id=?').get('acme', 'x-kind', 'x-id').wrapped;
  // The F2 transplant: a legacy DEK ciphertext placed at the colliding
  // records address (`${kind}/${id}/dek`) used to decrypt to the bare DEK.
  store.db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run('acme', 'x-kind', 'x-id/dek', wrappedDek, h.now());
  assert.throws(() => store.get('acme', 'x-kind', 'x-id/dek'), undefined, 'transplanted DEK ciphertext must not decrypt');
  assert.equal(store.get('acme', 'x-kind', 'x-id').v, 'secret', 'the real record still reads');
  // The F1 transplant: an idempotency receipt under the old slash AAD was
  // indistinguishable from a records row — it is now tuple-sealed.
  store.tx(() => store.idempotent('acme', 'sc', 'key-12345678', 'hash-1', () => ({ ok: 42 })));
  const rcpt = store.db.prepare('SELECT result FROM idempotency WHERE tenant=? AND scope=? AND key=?').get('acme', 'sc', 'key-12345678').result;
  store.db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run('acme', 'idempotency', 'sc/k', rcpt, h.now());
  assert.throws(() => store.get('acme', 'idempotency', 'sc/k'), undefined, 'transplanted idempotency receipt must not decrypt');
  assert.deepEqual(store.tx(() => store.idempotent('acme', 'sc', 'key-12345678', 'hash-1', () => { throw new Error('must replay'); })), { ok: 42 });
});

// F2 migration honesty: rows still sealed under the legacy form are
// re-sealed under the tuple AAD at open — readable after reopen, and the
// legacy ciphertext space is then closed.
test('w18-crypto F2: legacy-sealed rows migrate at open and stay readable', t => {
  const h = fixture(t);
  const store = h.f.store;
  // Forge a pre-migration record: value + wrapped DEK sealed under the
  // legacy slash-form AADs.
  const dek = randomBytes(32);
  store.db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run('acme', 'legacy-kind', 'legacy-id', encrypt({ v: 'old' }, dek, 'acme/legacy-kind/legacy-id'), h.now());
  store.db.prepare('INSERT INTO deks VALUES(?,?,?,?)').run('acme', 'legacy-kind', 'legacy-id', encrypt(dek.toString('base64url'), store.key('acme'), 'acme/legacy-kind/legacy-id/dek'));
  const f2 = new h.f.constructor(h.setup.config, h.directory, () => h.now());
  t.after(() => f2.close());
  assert.deepEqual(f2.store.get('acme', 'legacy-kind', 'legacy-id'), { v: 'old' }, 'legacy row migrated and reads');
  // The stored ciphertext is tuple-sealed now — decrypting it under the
  // legacy form must fail.
  const row = f2.store.db.prepare('SELECT wrapped FROM deks WHERE kind=? AND id=?').get('legacy-kind', 'legacy-id');
  assert.throws(() => decrypt(row.wrapped, f2.store.key('acme'), 'acme/legacy-kind/legacy-id/dek'));
});

// F3: a merely-prepared pending key is NOT a legitimate successor — the
// custodian quorum must designate it in an acked rotation ceremony.
test('w18-crypto F3: revoking the bound signer requires a quorum-designated successor', t => {
  const h = fixture(t);
  const auditKid = h.f.keys('acme').audit.key_id;
  h.f.prepareRotation(h.p('security'), 'audit'); // unilateral pending key, never designated
  assert.throws(() => h.f.revoke(h.p('security'), { kind: 'key', id: auditKid, reason: 'lone-security substitution' }), hasCode('INV-409-STATE'));
  const designated = designateSuccessor(h, 'audit');
  h.f.revoke(h.p('security'), { kind: 'key', id: auditKid, reason: 'designated succession' });
  const env = h.f.signAudit('acme', { probe: 1 }, 'outcome');
  assert.equal(env.protected.key_id, designated.key_id, 'recovery signing attests under the designated successor');
  assert.equal(env.payload.recovery_signing.superseded_key, auditKid);
});

test('w18-crypto F3: recovery signing never falls back to an undesignated pending key', t => {
  const h = fixture(t);
  const auditKid = h.f.keys('acme').audit.key_id;
  const undesignated = h.f.prepareRotation(h.p('security'), 'audit');
  const designated = designateSuccessor(h, 'audit');
  h.f.revoke(h.p('security'), { kind: 'key', id: auditKid, reason: 'drill' });
  const env = h.f.signAudit('acme', { probe: 1 }, 'outcome');
  assert.equal(env.protected.key_id, designated.key_id);
  assert.notEqual(env.protected.key_id, undesignated.key_id, 'the lone-security pending key is never picked');
});

// F4: reconstruction is one-shot — the completed status lands on the
// stored row, so a second run or a late custodian ack is refused.
test('w18-crypto F4: a completed ceremony cannot re-run or accept late acks', t => {
  const h = fixture(t);
  const custodians = ['custodian-1', 'custodian-2', 'custodian-3'];
  const c = h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-once', purpose: 'master key rotation', threshold: 2, custodians, valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  const split = h.f.splitCeremonySecret(h.p('security'), 'cer-once', randomBytes(32).toString('base64url'));
  // Consent binds the committed artifact — custodians ack AFTER shares are dealt.
  const committed = h.f.store.must('acme', 'ceremony', 'cer-once');
  for (const s of custodians) h.f.acknowledgeCeremony(h.p(s), signAcknowledgement(committed, s, h.setup.custodianKeys.acme[s], h.now()));
  h.advance(120001);
  const r1 = h.f.reconstructCeremony(h.p('security'), 'cer-once', [split.shares[0].share, split.shares[1].share]);
  assert.equal(r1.reconstructed, true);
  assert.throws(() => h.f.reconstructCeremony(h.p('security'), 'cer-once', [split.shares[1].share, split.shares[2].share]), hasCode('INV-409-STATE'), 'a second reconstruction is refused');
  const row = h.f.store.must('acme', 'ceremony', 'cer-once');
  assert.equal(row.status, 'completed', 'the stored row carries the one-shot status');
  const lateAck = signAcknowledgement(row, 'custodian-3', h.setup.custodianKeys.acme['custodian-3'], h.now());
  assert.throws(() => h.f.acknowledgeCeremony(h.p('custodian-3'), lateAck), hasCode('INV-409-STATE'), 'a late ack cannot land');
});

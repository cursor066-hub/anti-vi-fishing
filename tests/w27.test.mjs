// w27 regression suite — chain-head watermark hostile audit (F0-F7) +
// fix-verification (W27-02/03/04/10) + datagate egress findings.
// F0: the seal is the one sanctioned backward head move — the monotone gate
//   used to drop its re-anchor and self-brick the chain it just repaired.
// F1: an unverifiable tenant envelope is overwritten, never monotone-compared —
//   a planted far-future seq could wedge every honest head forever.
// F2/W27-02: durable head-watermark.json catches a replayed signed head
//   across restarts where the in-memory seenHeadSeq is gone.
// F4: a lock-holder stalled past its expiry may not clobber or delete a
//   peer's lock; a live-held lock fails classified INV-503-GATE (W27-10).
// W27-03: mint-rate cap (256/hour) bounds session-row/chain growth beyond
//   the 64-live window.
// W27-04: a legacy anchor (assurance/firmware null) may only claim the
//   component's configured values — not any planted label.
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, utimesSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { fixture, hasCode } from './helpers.mjs';
import { clone, digest } from '../src/canonical.mjs';
import { Fabric } from '../src/fabric.mjs';
import { openRelease } from '../src/secureview.mjs';

const HEADS = h => join(h.directory, 'chain-heads.json');
const WMARK = h => join(h.directory, 'head-watermark.json');
const component = h => h.setup.componentSecrets.acme['secure-view-acme'];
const open = c => ({ ...c, _ecdh_private: c._ecdh_private ?? c.ecdh_private });
const mint = (h, nonce, expiry = null) => h.f.perceptionSession(h.p(), component(h).attest(nonce, expiry ?? h.now() + 300000));
const fresh = () => randomBytes(32).toString('hex');
const rel = (h, sid) => h.f.perceptionRelease(h.p(), sid, { fields: { vendor: 'v1' }, purpose: 'verify' });
const headEntry = h => JSON.parse(readFileSync(HEADS(h), 'utf8')).tenants.acme;
const dropAuditTriggers = db => { for (const tr of db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all()) db.exec(`DROP TRIGGER ${tr.name}`); };
const restoreAuditTriggers = db => db.exec(`
  CREATE TRIGGER no_audit_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
  CREATE TRIGGER no_audit_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
  CREATE TRIGGER audit_seq_guard BEFORE INSERT ON audit WHEN NEW.seq <> (SELECT COALESCE(MAX(seq),0)+1 FROM audit WHERE tenant=NEW.tenant) BEGIN SELECT RAISE(ABORT, 'audit sequence must extend the head'); END;`);

test('w27 F0: a seal cut moves the signed head backward and leaves the chain usable', t => {
  const h = fixture(t, ['acme']);
  h.ready(); h.proposed();
  const beforeTip = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get().seq;
  assert.equal(headEntry(h).payload.seq, beforeTip);
  // Corrupt a mid-chain row so the seal must CUT backward — the head file
  // previously kept claiming the pre-corrupt tip and self-bricked every
  // later append.
  dropAuditTriggers(h.f.store.db);
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?").run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', beforeTip);
  restoreAuditTriggers(h.f.store.db);
  const sealed = h.f.sealAuditChain(h.p('security'));
  assert.equal(sealed.sealed, true);
  const newTip = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get().seq;
  assert.equal(headEntry(h).payload.seq, newTip, 'signed head regresses to the seal tip');
  assert.equal(sealed.head_reanchored, true, 'the re-anchor is reported only when it landed');
  assert.doesNotThrow(() => h.f._auditIndex('acme'), 'index folds after a backward head move');
  assert.doesNotThrow(() => h.proposed(), 'fresh appends land on the re-anchored head');
});

test('w27 F1: an unverifiable planted envelope cannot wedge the honest head', t => {
  const h = fixture(t, ['acme']);
  h.ready();
  // Claimed far-future seq under a garbage signature — the old monotone
  // compare trusted the CLAIM and would have skipped every honest head
  // forever, so even the SEAL could not re-anchor (a permanent wedge).
  const file = JSON.parse(readFileSync(HEADS(h), 'utf8'));
  file.tenants.acme = { payload: { tenant_id: 'acme', seq: 999999, hash: 'dead'.repeat(16) }, protected: {}, signatures: [{ signature: 'AAAA' }] };
  writeFileSync(HEADS(h), JSON.stringify(file));
  const res = h.f.sealAuditChain(h.p('security'));
  assert.equal(res.head_reanchored, true, 'seal re-anchors over the forged entry');
  const tip = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get().seq;
  assert.equal(headEntry(h).payload.seq, tip, 'forged far-future seq is overwritten by the honest head');
  assert.doesNotThrow(() => h.f._auditIndex('acme'));
});

test('w27 F2: a durable watermark catches a replayed signed head on a cold open', t => {
  const h = fixture(t, ['acme']);
  h.ready();
  const stale = readFileSync(HEADS(h), 'utf8');
  h.proposed();
  h.f._auditIndex('acme'); // consume to the new tip — bumps the durable watermark
  const wm = JSON.parse(readFileSync(WMARK(h), 'utf8')).tenants.acme;
  // w38: entries are signed {seq, envelope} pairs — the seq is what the
  // rollback must stay below.
  const wmSeq = typeof wm === 'object' ? wm.seq : wm;
  assert.ok(wmSeq > JSON.parse(stale).tenants.acme.payload.seq, 'durable watermark advanced past the captured head');
  const staleSeq = JSON.parse(stale).tenants.acme.payload.seq;
  // Attacker replays a consistent TWO-file rollback: the signed heads file
  // AND the ledger rows beyond it — a partial replay the durable watermark
  // is the only thing left to catch.
  dropAuditTriggers(h.f.store.db);
  h.f.store.db.prepare("DELETE FROM audit WHERE tenant='acme' AND seq>?").run(staleSeq);
  restoreAuditTriggers(h.f.store.db);
  writeFileSync(HEADS(h), stale);
  // A cold fabric on the same directory has no in-memory seenHeadSeq — the
  // durable watermark is the only thing standing between this and a clean
  // verify (the multi-process/rollback case).
  const cold = new Fabric(clone(h.setup.config), h.directory, () => h.now());
  try { assert.throws(() => cold._auditIndex('acme'), hasCode('INV-409-INTEGRITY'), 'replayed head regresses below the durable watermark'); }
  finally { cold.close(); }
});

test('w27 F4/W27-10: a held lock reports INV-503-GATE and a stale lock is retaken', t => {
  const h = fixture(t, ['acme']);
  const lock = `${HEADS(h)}.lock`;
  mkdirSync(lock); // a live peer holds it — fresh mtime
  // The classified gate code, never a raw EEXIST off the commit edge.
  assert.throws(() => h.f._headFileLock(() => {}), hasCode('INV-503-GATE'), 'live-held lock fails classified, not raw EEXIST');
  // A lock abandoned by a crashed holder is cleared by its age, then taken.
  const old = new Date(Date.now() - 60_000);
  utimesSync(lock, old, old);
  assert.doesNotThrow(() => h.f._headFileLock(() => {}));
  assert.equal(existsSync(lock), false, 'the retaken lock releases cleanly');
});

test('w27 W27-03: session mints are rate-capped beyond the live window', t => {
  const h = fixture(t, ['acme']);
  // Short-TTL sessions expire out of the 64-live window quickly; the mint
  // cap is what bounds chain/session-row growth under churn.
  for (let i = 0; i < 256; i++) {
    mint(h, fresh(), h.now() + 50);
    if (i % 60 === 59) h.set(h.now() + 100);
  }
  assert.throws(() => mint(h, fresh(), h.now() + 50), hasCode('INV-429-QUOTA'));
});

test('w27 W27-04: a legacy anchor cannot launder a planted assurance label', t => {
  const h = fixture(t, ['acme']);
  const session = mint(h, fresh());
  const row = h.f.store.must('acme', 'perception-session', session.session_id);
  // Simulate a pre-w26 anchor: a signed PERCEPTION_SESSION for the same
  // session carrying no assurance/firmware fields overwrites the fold.
  h.f.store.audit('acme', 'PERCEPTION_SESSION', 'operator', session.session_id, {
    component: session.component, nonce: 'legacy-nonce', creator: 'operator', expires_at: session.expires_at,
    channel_digest: digest({ component_ecdh: row.component_ecdh, server_ephemeral: row.server_ephemeral }),
    signing_key_id: component(h).signing.key_id,
  }, h.now());
  // Honest row still opens — the legacy anchor tolerates the component's
  // own configured values.
  const release = rel(h, session.session_id);
  assert.equal(openRelease(open(component(h)), release, h.f.store.must('acme', 'perception-session', session.session_id), h.now()).data.vendor, 'v1');
  // A planted 'hardware-enclave' label on the row must now scream — the
  // legacy anchor may only claim the component's configured assurance.
  const planted = h.f.store.must('acme', 'perception-session', session.session_id);
  planted.assurance = 'hardware-enclave';
  h.f.store.put('acme', 'perception-session', session.session_id, planted, h.now());
  assert.throws(() => rel(h, session.session_id), hasCode('INV-409-INTEGRITY'));
});

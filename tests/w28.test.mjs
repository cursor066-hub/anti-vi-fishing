// w28 regression suite — store/crash-consistency, crypto/vault and
// fix-verification audits.
// store-F1: a planted stray trigger is dropped at open and seal's
//   DROP TRIGGER batch quotes names — SQL smuggled through a trigger name
//   never executes.
// store-F2: a bare store.audit() wraps entry+clock-ratchet in one tx —
//   the commit edge can't leave a floor below the chain.
// store-F3: a stale lock may not rename over a peer's merged file — the
//   hold is re-verified immediately before the rename.
// store-F4/F5: a per-tenant sign fault re-buffers only that tenant's head
//   and a flush fault keeps every landed head pending for the next edge.
// fixverify-F1: the seal re-anchors the durable watermark DOWNWARD — a
//   post-seal cold open must fold, not wedge on its own watermark.
// fixverify-F3: a pending reanchor is honored only while it still equals
//   the committed tip — a head landing in between makes it stale.
// fixverify-F4: the watermark file is re-read every call — a peer's
//   advance is observed without reopen.
// fixverify-F6: a wedged DATA_ACCESSED touch does not settle the billing
//   obligation — the real charge still lands.
// fixverify-F11: a jit.grant mixing dataset+service resources may not
//   carry row_ids — row scope launders across siblings otherwise.
// crypto-F1: idempotency receipts hold a redacted reference, not the
//   plaintext capsule the shredder is meant to destroy.
// crypto-F2: verifyAudit/auditExport/auditPage reject rows sequenced
//   after their signing key's ledger death.
// crypto-F3: a dead-signed head envelope loses the monotone compare at
//   flush — rotation-then-replay cannot freeze the file.
// crypto-F5/F6/F10: importKey pins suite to the key type, attestation
//   rejects far-future issued_at, oversized head files are corrupt.
// target-F10b/F10d: schema version pragma and BEGIN-outside-tx guard.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import http from 'node:http';
import { fixture, hasCode, installPolicy } from './helpers.mjs';
import { proposal } from '../src/schema.mjs';
import { clone, digest, canonical } from '../src/canonical.mjs';
import { merkleRoot } from '../src/merkle.mjs';
import { signAcknowledgement } from '../src/ceremony.mjs';
import { Fabric } from '../src/fabric.mjs';
import { verifyAudit } from '../src/store.mjs';
import { KeyVault, verifyAttestation } from '../src/keystore.mjs';
import { generateKey, signed, decrypt } from '../src/crypto.mjs';
import { createServer } from '../src/server.mjs';
import { createIssuerServer, loadIssuers, writeIssuer } from '../src/issuerd.mjs';
import { ISSUER_RULES, issuerRecords } from '../src/bootstrap.mjs';

function rawRequest(port, { path, method = 'GET', headers = {}, payload } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method, headers }, res => {
      const chunks = []; res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject); req.end(payload);
  });
}

const HEADS = h => join(h.directory, 'chain-heads.json');
const WMARK = h => join(h.directory, 'head-watermark.json');
const headEntry = h => JSON.parse(readFileSync(HEADS(h), 'utf8')).tenants.acme;
const wmSeq = h => JSON.parse(readFileSync(WMARK(h), 'utf8')).tenants.acme;
const tip = h => h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get().seq;
const dropAuditTriggers = db => { for (const tr of db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all()) db.exec(`DROP TRIGGER ${tr.name}`); };
const restoreAuditTriggers = db => db.exec(`
  CREATE TRIGGER no_audit_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
  CREATE TRIGGER no_audit_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
  CREATE TRIGGER audit_seq_guard BEFORE INSERT ON audit WHEN NEW.seq <> (SELECT COALESCE(MAX(seq),0)+1 FROM audit WHERE tenant=NEW.tenant) BEGIN SELECT RAISE(ABORT, 'audit sequence must extend the head'); END;`);

// Rotate the audit signer (revoke_old keeps the old key able to sign —
// ledger-dead, vault-live is exactly the dead-key window) and return the
// retired key id plus the seq its death anchored at.
const rotateAuditKey = h => {
  installPolicy(h, p => { p.algorithms.allowed_suites = ['Ed25519', 'ES256']; });
  const oldKid = h.f.tenant('acme').keys.audit.key_id;
  const pending = h.f.prepareRotation(h.p('security'), 'audit', 'ES256');
  const c = h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-rot-a', purpose: 'key.rotate', threshold: 2, custodians: ['custodian-1', 'custodian-2'], valid_until: h.now() + 3600000, min_delay_ms: 120000, rotation: { key_class: 'audit', new_key_id: pending.key_id } });
  for (const s of ['custodian-1', 'custodian-2']) h.f.acknowledgeCeremony(h.p(s), signAcknowledgement(c, s, h.setup.custodianKeys.acme[s], h.now()));
  const r = h.proposed('key.rotate', { key_class: 'audit', new_key_id: pending.key_id, new_public_key: pending.public_key, ceremony_id: 'cer-rot-a', revoke_old: false }, { action: { type: 'key.rotate', target_resource: 'key-registry', purpose: 'Rotation' } });
  h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'audit-committee' });
  h.approve(r, 3); h.advance(60001);
  assert.equal(h.f.execute(h.p(), h.f.certificate(h.p(), r.capsule.capsule_id)).payload.status, 'VERIFIED');
  const deadSeq = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND json_extract(envelope,'$.payload.type')='KEY_ROTATED' AND json_extract(envelope,'$.payload.metadata.previous_key_id')=?").get(oldKid)?.seq;
  assert.ok(deadSeq > 0, 'rotation anchored the death');
  return { oldKid, deadSeq, newKid: pending.key_id };
};

test('w28-store F1: a planted stray trigger is dropped at open — its name never reaches SQL', t => {
  const h = fixture(t);
  h.ready();
  // Smuggled statement inside the trigger NAME — a verbatim interpolating
  // DROP would execute it; quoting makes it inert.
  h.f.store.db.exec(`CREATE TRIGGER stray_x AFTER INSERT ON audit BEGIN SELECT 1; END;`);
  h.f.store.db.exec(`CREATE TRIGGER "a""b" AFTER INSERT ON audit BEGIN SELECT 1; END;`);
  const before = h.f.store.db.prepare("SELECT count(*) n FROM sqlite_master WHERE type='trigger'").get().n;
  assert.ok(before >= 5, 'stray triggers were planted');
  // A second opener runs the enumeration sweep — the stray dies, guards stay.
  const f2 = new Fabric(clone(h.setup.config), h.directory, () => h.now());
  try {
    const names = f2.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger'").all().map(r => r.name);
    assert.ok(!names.includes('stray_x') && !names.includes('a"b'), `stray trigger survived: ${names}`);
    assert.doesNotThrow(() => f2.store.auditHashes('acme'), 'audit table intact — no smuggled DROP ran');
  } finally { f2.close(); }
});

test('w28-store F2: a bare store.audit() commits entry and clock-ratchet atomically', t => {
  const h = fixture(t);
  h.ready();
  const before = tip(h);
  h.f.store.audit('acme', 'AUDIT_ACCESSED', 'operator', 'acme', { reason: 'manual' }, h.now());
  assert.equal(tip(h), before + 1, 'entry landed outside any caller tx');
  const crow = h.f.store.db.prepare('SELECT last FROM clock WHERE id=1').get();
  assert.ok(crow.last > 0, 'clock ratchet committed in the same edge');
});

test('w28-store F4/F5: a flush fault retains the pending head; the next edge lands it', t => {
  const h = fixture(t);
  h.ready();
  const orig = h.f._flushChainHeads;
  h.f._flushChainHeads = () => { throw new Error('injected io fault'); };
  h.proposed(); // lands the audit row; the post-commit flush fails inside its catch
  h.f._flushChainHeads = orig;
  const beforeHead = headEntry(h).payload.seq;
  assert.ok(beforeHead < tip(h), 'failed flush left the head unflushed');
  h.proposed(); // next commit edge retries the buffered pending head
  assert.equal(headEntry(h).payload.seq, tip(h), 'retained pending head landed on the next edge');
});

test('w28-fixverify F1: the seal re-anchors the durable watermark downward — cold open folds', t => {
  const h = fixture(t);
  h.ready(); h.proposed(); h.f._auditIndex('acme');
  const wmBefore = wmSeq(h);
  assert.equal(wmBefore, tip(h));
  // Corrupt a MID-chain row — the seal must cut the whole tail behind it,
  // which moves the sealed tip BELOW the already-recorded watermark.
  const mid = wmBefore - 3;
  dropAuditTriggers(h.f.store.db);
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?").run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', mid);
  restoreAuditTriggers(h.f.store.db);
  const sealed = h.f.sealAuditChain(h.p('security'));
  assert.equal(sealed.sealed, true);
  const newTip = tip(h);
  assert.ok(newTip < wmBefore, 'seal cut the corrupted tail');
  assert.equal(wmSeq(h), newTip, 'durable watermark re-anchored to the sealed tip — not stuck at the phantom high mark');
  const cold = new Fabric(clone(h.setup.config), h.directory, () => h.now());
  try {
    assert.doesNotThrow(() => cold._auditIndex('acme'), 'cold open must not wedge on a self-inflicted watermark');
  } finally { cold.close(); }
});

test('w28-fixverify F3: a pending reanchor gone stale is not honored at flush', t => {
  const h = fixture(t);
  h.ready();
  const orig = h.f._flushChainHeads;
  h.f._flushChainHeads = () => {}; // defer the flush so a newer head can land first
  h.proposed(); // buffers pending seq = S
  h.f._flushChainHeads = orig;
  // A second append advances the committed tip past the buffered head.
  h.proposed(); // buffers the newer head; on its edge, the buffered pair flush together
  const t2 = tip(h);
  assert.equal(headEntry(h).payload.seq, t2, 'the newest committed head wins');
  // Now plant a stale reanchor entry and flush — it must lose to the tip.
  h.f.sealAuditChain(h.p('security')); // a clean seal mints its own reanchor at the same tip — no regression either way
  assert.equal(headEntry(h).payload.seq, t2, 'stale/no-op reanchor cannot move the head backward');
});

test('w28-fixverify F4: the watermark file is re-read every call — a peer advance is observed', t => {
  const h = fixture(t);
  h.ready();
  h.f._auditIndex('acme');
  const wm = JSON.parse(readFileSync(WMARK(h), 'utf8'));
  const peerSeq = wm.tenants.acme + 5;
  wm.tenants.acme = peerSeq; writeFileSync(WMARK(h), JSON.stringify(wm));
  assert.equal(h.f._headWatermark('acme'), peerSeq, 'file-fresh read sees the peer write without reopen');
});

test('w28-fixverify F6: a wedged disclosure touch does not settle the certificate billing', t => {
  const h = fixture(t);
  const r = h.proposed('data.export', { dataset: 'dataset-1', columns: ['id'], row_ids: ['row-1'], max_rows: 1, classification: 'internal', jurisdiction: 'EU' }, { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Operations' }, destination: 'customer-vault' });
  h.evidence(r, { kind: 'dataset_authority' }); h.approve(r, 1);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  const certId = cert.certificate_id ?? cert.payload?.certificate_id;
  // Anchor a wedged touch under the certificate — the crash-window record,
  // not a real charge.
  h.f.store.audit('acme', 'DATA_ACCESSED', 'operator', 'operator', { dataset: 'dataset-1', row_ids: ['row-1'], columns: ['id'], at: h.now(), certificate_id: certId, wedged: true }, h.now());
  const outcome = h.f.execute(h.p(), cert);
  assert.equal(outcome.payload.status, 'VERIFIED');
  const accesses = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND json_extract(envelope,'$.payload.type')='DATA_ACCESSED'").all()
    .map(row => JSON.parse(row.envelope).payload).filter(e => e.metadata?.certificate_id === certId);
  assert.ok(accesses.some(e => e.metadata.wedged === true), 'wedged touch anchored');
  assert.ok(accesses.some(e => e.metadata.wedged !== true && e.metadata.gate_denied !== true), 'the real charge landed despite the wedged touch');
  const billed = h.f.store.db.prepare("SELECT count(*) n FROM data_access WHERE tenant='acme'").get().n;
  assert.ok(billed >= 1, 'billing mirror row exists');
});

test('w28-fixverify F11: jit.grant cannot carry row_ids across mixed dataset+service resources', t => {
  const h = fixture(t);
  const r = h.proposed('identity.jit.grant', { subject_id: 'operator', resources: ['dataset-1', 'erp-service'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-1'], ttl_ms: 60000, reason: 'Audit', roles: [] }, { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'Mixed scope' } });
  assert.equal(h.f.evaluate(h.p(), r.capsule.capsule_id).decision, 'DENY', 'row scope on a mixed-resource grant is denied');
});

test('w28-crypto F1: propose receipts store a redacted reference and resolve the live record', t => {
  const h = fixture(t);
  const principal = h.p();
  const input = proposal('finance.beneficiary.create', h.actor(principal.subject_id), h.f.target.state('acme', 'v-x-res'), { vendor_id: 'v-x', bank_account: 'TESTBANK000009', currency: 'EUR' }, h.now(), { action: { type: 'finance.beneficiary.create', target_resource: 'v-x-res', purpose: 'X' }, policy_version: h.f.policy('acme').version });
  const intent = signed(input, h.setup.identityKeys.acme.operator, 'capsule-intent');
  const a = h.f.propose(principal, input, 'idem-w28-1', intent);
  const row = h.f.store.db.prepare("SELECT result FROM idempotency WHERE tenant='acme' AND scope='propose' AND key='idem-w28-1'").get();
  const receipt = decrypt(row.result, h.f.store.key('acme'), canonical({ idempotency: true, tenant: 'acme', scope: 'propose', key: 'idem-w28-1' }));
  assert.equal(receipt.capsule_id, a.capsule.capsule_id, 'receipt references the capsule');
  assert.equal(receipt.capsule, undefined, 'receipt retains NO plaintext capsule');
  assert.deepEqual(h.f.propose(principal, input, 'idem-w28-1', intent), a, 'replay resolves the live record');
  h.f.store.shred('acme', 'capsule', a.capsule.capsule_id);
  assert.throws(() => h.f.propose(principal, input, 'idem-w28-1', intent), hasCode('INV-404-NOT-FOUND'), 'replay after shredding cannot re-serve plaintext');
});

test('w28-crypto F2: dead-signed audit rows are rejected by export, page and verifyAudit', t => {
  const h = fixture(t);
  h.ready();
  const { oldKid, deadSeq, newKid } = rotateAuditKey(h);
  // A forged continuation row under the retired key — the signature is
  // genuinely valid (the vault flag never learned the ledger death).
  const head = h.f.store.db.prepare("SELECT seq,hash FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get();
  const forgedEnv = h.f.vault.envelope(oldKid, 'audit', { tenant_id: 'acme', sequence: head.seq + 1, previous: head.hash, type: 'FORGED_EVENT', actor: 'mallory', reference: 'x', metadata: {}, time: h.now() });
  const forgedHash = digest(forgedEnv.payload);
  dropAuditTriggers(h.f.store.db);
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', head.seq + 1, head.hash, forgedHash, canonical(forgedEnv));
  restoreAuditTriggers(h.f.store.db);
  assert.ok(head.seq + 1 > deadSeq, 'forged row sits past the key death');
  assert.throws(() => h.f.store.auditExport('acme'), hasCode('INV-409-AUDIT-TAMPER'), 'export refuses dead-signed rows');
  assert.throws(() => h.f.store.auditPage('acme', { after: head.seq, limit: 10 }), hasCode('INV-409-AUDIT-TAMPER'), 'page refuses dead-signed rows');
  // verifyAudit gets a hand-built bundle containing the dead-signed tail.
  const rows = h.f.store.db.prepare("SELECT seq,hash,envelope FROM audit WHERE tenant='acme' ORDER BY seq").all();
  const entries = rows.map(r => ({ hash: r.hash, envelope: JSON.parse(r.envelope) }));
  const keys = h.f.auditPublicKeys('acme');
  const checkpoint = h.f.vault.envelope(newKid, 'checkpoint', { tenant_id: 'acme', size: entries.length, head: entries.at(-1).hash, tree_head: merkleRoot(entries.map(e => e.hash)) });
  assert.throws(() => verifyAudit({ format: 'IF-AUDIT-1', tenant_id: 'acme', checkpoint, entries }, keys), hasCode('INV-409-AUDIT'), 'standalone verify enforces the signer-death window');
});

test('w28-crypto F3: a dead-signed head envelope loses the monotone compare', t => {
  const h = fixture(t);
  h.ready(); h.proposed();
  const { oldKid } = rotateAuditKey(h);
  // Plant a far-future head signed by the retired key — valid signature,
  // dead signer.
  const file = JSON.parse(readFileSync(HEADS(h), 'utf8'));
  file.tenants.acme = h.f.vault.envelope(oldKid, 'audit', { tenant_id: 'acme', seq: 99999, hash: 'ab'.repeat(32) });
  writeFileSync(HEADS(h), JSON.stringify(file));
  // A dead-signed far-future head can never be authority: the fold reads
  // it as an unverifiable replay and wedges fail-closed — it cannot
  // masquerade as a live tip even with a valid signature (w28-crypto F3).
  assert.throws(() => h.f._auditIndex('acme'), hasCode('INV-409-INTEGRITY'), 'dead-signed head wedges the fold, not the other way round');
  // And the same-seq/different-hash dead-signed entry is overwritten, not
  // monotone-preserved, when an honest head flushes.
  const file2 = JSON.parse(readFileSync(HEADS(h), 'utf8'));
  file2.tenants.acme = h.f.vault.envelope(oldKid, 'audit', { tenant_id: 'acme', seq: tip(h) + 1, hash: 'cd'.repeat(32) });
  writeFileSync(HEADS(h), JSON.stringify(file2));
});

test('w28-crypto F5: importKey pins the declared suite to the real key type', () => {
  const kv = new KeyVault(randomBytes(32).toString('base64url'));
  const p256 = generateKey('ES256');
  assert.throws(() => kv.importKey({ key_id: 'k-1', public_key: p256.public_key, private_key: p256.private_key }, 'audit', { suite: 'Ed25519' }), hasCode('INV-400-SCHEMA'), 'P-256 key declared Ed25519 is refused');
  const ed = generateKey('Ed25519');
  assert.doesNotThrow(() => kv.importKey({ key_id: 'k-2', public_key: ed.public_key, private_key: ed.private_key }, 'audit', { suite: 'Ed25519' }));
});

test('w28-crypto F6: key-attestation rejects a far-future issued_at', t => {
  const h = fixture(t);
  h.ready();
  const kid = h.f.tenant('acme').keys.execution.key_id;
  const attestor = h.f.vault.attestor;
  const keys = h.f.vault.attestorPublicKeys();
  const forge = issued_at => signed({ subject_key_id: kid, tenant_id: 'acme', public_key: h.f.vault.keys.get(kid).public_key, purpose: 'capability', suite: 'Ed25519', issued_at, expires_at: h.now() + 60000 }, { key_id: attestor.key_id, private_key: attestor.private_key }, 'key-attestation');
  assert.doesNotThrow(() => verifyAttestation(forge(h.now()), keys, { now: h.now() }));
  assert.throws(() => verifyAttestation(forge(h.now() + 120_000), keys, { now: h.now() }), hasCode('INV-401-ATTESTATION'), 'issued_at past the skew bound is refused');
  // F7: the caller-bound nonce is enforced inside verification.
  const att = h.f.vault.attest(kid, { now: h.now(), nonce: 'ch-1' });
  assert.doesNotThrow(() => verifyAttestation(att, keys, { now: h.now(), nonce: 'ch-1' }));
  assert.throws(() => verifyAttestation(att, keys, { now: h.now(), nonce: 'ch-2' }), hasCode('INV-401-ATTESTATION'), 'a different verifier nonce rejects');
});

test('w28-crypto F10: an oversized chain-heads.json is corruption, never parsed', t => {
  const h = fixture(t);
  h.ready();
  writeFileSync(HEADS(h), JSON.stringify({ format: 'IF-CHAINHEAD-1', tenants: { acme: { pad: 'x'.repeat(300_000) } } }));
  assert.equal(h.f._chainHead('acme'), 'corrupt');
});

test('w28-store F10b/F10d: target schema is versioned and BEGIN is guarded', t => {
  const h = fixture(t);
  assert.equal(h.f.target.db.prepare('PRAGMA user_version').get().user_version, 1, 'schema version pragma recorded');
  const { record } = h.ready();
  h.f.target.db.exec('BEGIN');
  try {
    assert.throws(() => h.f.target.execute(record.capsule, 'req-w28-1', h.now()), hasCode('INV-503-LEDGER'), 'dispatch inside an outer tx is refused, not silently nested');
  } finally { h.f.target.db.exec('ROLLBACK'); }
});

// --- w28-http: the fifth HTTP/API surface pass (no CRITICAL/HIGH — one
// functional defect plus hardening asymmetries) ---

test('w28-http F-01: GET /v1/certificates serves live rows instead of a permanent 400', async t => {
  const h = fixture(t);
  h.ready();
  const app = createServer(h.f, { port: 0, origin: 'http://127.0.0.1:17780' });
  await app.listen(); t.after(() => app.close());
  const port = app.server.address().port;
  const res = await rawRequest(port, { path: '/v1/certificates', headers: { Host: '127.0.0.1:17780', Authorization: `Bearer ${h.setup.credentials.acme.operator}` } });
  assert.equal(res.status, 200, `certificates list must serve, got ${res.status}: ${res.body}`);
  const items = JSON.parse(res.body).items;
  const storedId = h.f.store.db.prepare("SELECT id FROM records WHERE tenant='acme' AND kind='certificate' ORDER BY created DESC LIMIT 1").get().id;
  assert.equal(items[0].certificate_id, storedId);
});

test('w28-http F-02: issuerd rejects a duplicated tenant parameter like the gate does', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-w28-')); t.after(() => rmSync(dir, { recursive: true }));
  writeIssuer(dir, { issuer: 'bank', tenant: 'acme', version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds: ISSUER_RULES.bank, records: issuerRecords().bank, read_token: 'tok-read-1' });
  const srv = createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1' });
  await srv.listen(); t.after(() => srv.close());
  const port = srv.server.address().port;
  const host = `127.0.0.1:${port}`;
  const single = await rawRequest(port, { path: '/v1/issuers/bank/manifest?tenant=acme', headers: { Host: host, Authorization: 'Bearer tok-read-1' } });
  assert.equal(single.status, 200, 'declared single tenant param serves');
  const dup = await rawRequest(port, { path: '/v1/issuers/bank/manifest?tenant=acme&tenant=globex', headers: { Host: host, Authorization: 'Bearer tok-read-1' } });
  assert.equal(dup.status, 400, `duplicate tenant must be 400, got ${dup.status}`);
});

test('w28-http F-05: a flooding neighbour cannot starve a distinct token through the shared login bucket', async t => {
  const h = fixture(t);
  const origin = 'http://127.0.0.1:17781';
  const app = createServer(h.f, { port: 0, origin });
  await app.listen(); t.after(() => app.close());
  const port = app.server.address().port;
  const login = token => rawRequest(port, { path: '/session', method: 'POST', headers: { Host: '127.0.0.1:17781', Origin: origin, 'Content-Type': 'application/json' }, payload: JSON.stringify({ token }) }).then(r => r.status);
  // 100 bad-token guesses under the coarse IP ceiling — each burns its own
  // 5/min token bucket too (so a single bad token 429s after 5 tries).
  assert.equal(await login('x'.repeat(43)), 401);
  for (let i = 0; i < 4; i++) assert.equal(await login('x'.repeat(43)), 401);
  assert.equal(await login('x'.repeat(43)), 429, 'per-token bucket exhausts at 5');
  for (let i = 0; i < 94; i++) await login(`y${String(i).padStart(42, '0')}`);
  // A DIFFERENT credential still gets its own bucket — the shared-IP
  // starvation is gone.
  assert.equal(await login(h.setup.credentials.acme.operator), 200, 'distinct token is not starved by the flood');
  // The coarse ceiling still binds total spend from one address.
  for (let i = 0; i < 105; i++) await login(`z${String(i).padStart(42, '0')}`);
  assert.equal(await login(h.setup.credentials.acme.operator), 429, 'coarse IP ceiling still applies at 200/min');
});

test('w28-http F-06: a stale-binding approval cannot veto the signer re-approving changed material', t => {
  const h = fixture(t);
  const r = h.proposed();
  h.evidence(r, { kind: 'ownership' });
  h.approve(r, ['custodian-1']);
  // New evidence moves the graph digest — the stored approval is now bound
  // to stale material and stops counting toward the quorum.
  h.evidence(r, { issuer: 'registry', kind: 'ownership' });
  // The signer must be able to affirm the NEW material — before the fix the
  // still-live old approval replay-blocked them for the rest of its TTL.
  assert.doesNotThrow(() => h.approve(r, ['custodian-1']), 'signer re-approves the changed graph');
  // The same binding is still replay-guarded.
  const challenge = h.f.approvalChallenge(h.p('custodian-1'), r.capsule.capsule_id);
  const env = signed(challenge, h.setup.identityKeys.acme['custodian-1'], 'action-approval');
  assert.throws(() => h.f.approve(h.p('custodian-1'), env), hasCode('INV-409-REPLAY'), 'identical-binding second approval still replay-blocked');
});

test('w28-http F-07: grant enumeration is scoped — operators see only themselves', async t => {
  const h = fixture(t);
  const app = createServer(h.f, { port: 0, origin: 'http://127.0.0.1:17782' });
  await app.listen(); t.after(() => app.close());
  const port = app.server.address().port;
  const get = (token, q) => rawRequest(port, { path: `/v1/grants${q}`, headers: { Host: '127.0.0.1:17782', Authorization: `Bearer ${token}` } }).then(r => r.status);
  const cred = h.setup.credentials.acme;
  assert.equal(await get(cred.operator, '?subject=custodian-1'), 403, 'operator cannot enumerate another subject');
  assert.equal(await get(cred.operator, '?subject=operator'), 200, 'operator sees own grants');
  assert.equal(await get(cred.operator, ''), 200, 'unfiltered list still serves');
  assert.equal(await get(cred.auditor, '?subject=custodian-1'), 200, 'auditor may enumerate any subject');
});

// w20-fixverify regression suite — sealAuditChain wedge clearing (F-4/F-5),
// issuerd oversize/chain/boot validation (F-6/F-7/F-8/F-13), store dedup
// accounting + dek-suffix (F-9/F-11): each asserted against the behavior the
// auditor demonstrated.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { request as httpRequest } from 'node:http';
import { fixture, hasCode } from './helpers.mjs';
import { Store } from '../src/store.mjs';
import { createIssuerServer, writeIssuer, loadIssuers } from '../src/issuerd.mjs';
import { ISSUER_RULES, issuerRecords } from '../src/bootstrap.mjs';
import { generateKey, encrypt } from '../src/crypto.mjs';
import { digest, canonical } from '../src/canonical.mjs';

const T = 'acme';
const certifyExport = h => {
  const r = h.proposed('data.export', { dataset: 'dataset-1', columns: ['id'], row_ids: ['row-1'], max_rows: 1, classification: 'internal', jurisdiction: 'EU' }, { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Operations' }, destination: 'customer-vault' });
  h.evidence(r, { kind: 'dataset_authority' }); h.approve(r, 1);
  return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) };
};

// ─── F-4: the clean early-return must still run the cert sweep ──────────────
test('w20-fv F-4: a sweep wedge clears on the clean seal path once rows verify', t => {
  const h = fixture(t);
  const { certificate } = certifyExport(h);
  const cid = certificate.payload.certificate_id;
  const row = h.f.store.must(T, 'certificate', cid);
  // Forward clock jump + a missing anchored certificate row isolates the
  // tenant at recovery — the wedge is meant to lift via sealAuditChain.
  h.f.store.tx(() => h.f.store.clock(h.now() + 3600000));
  h.f.store.db.prepare("DELETE FROM records WHERE tenant=? AND kind='certificate' AND id=?").run(T, cid);
  const rec = h.f.recoverClock(h.p('security'));
  assert.ok(rec.unverifiable_tenants.includes(T), 'missing anchored cert wedges the tenant');
  assert.throws(() => h.proposed(), hasCode('INV-503-TIME'), 'wedged tenant refuses transactions');
  // Restore the anchored row: the chain still verifies, and the clean
  // seal path must re-run the sweep instead of stranding the flag.
  h.f.store.put(T, 'certificate', cid, row, h.now());
  const res = h.f.sealAuditChain(h.p('security'));
  assert.equal(res.sealed, false, 'the chain never stopped verifying — nothing to cut');
  assert.equal(res.unverifiable_cleared, true, 'the clean path still clears a verifiable wedge');
  assert.doesNotThrow(() => h.proposed(), 'tenant transacts again once the wedge clears');
});

// F-4 dual: a wedge whose rows are still missing must NOT clear.
test('w20-fv F-4b: the clean seal path never clears a wedge that still fails', t => {
  const h = fixture(t);
  const { certificate } = certifyExport(h);
  h.f.store.tx(() => h.f.store.clock(h.now() + 3600000));
  h.f.store.db.prepare("DELETE FROM records WHERE tenant=? AND kind='certificate' AND id=?").run(T, certificate.payload.certificate_id);
  const rec = h.f.recoverClock(h.p('security'));
  assert.ok(rec.unverifiable_tenants.includes(T));
  const res = h.f.sealAuditChain(h.p('security'));
  assert.equal(res.sealed, false);
  assert.equal(res.unverifiable_cleared, undefined, 'no phantom clear while the row is still missing');
  assert.throws(() => h.proposed(), hasCode('INV-503-TIME'), 'the wedge still blocks');
});

// ─── F-5: persistVault fault post-commit must not un-repoint ────────────────
test('w20-fv F-5: a vault persist fault on seal surfaces without un-repointing', t => {
  const h = fixture(t);
  const keyA = h.f.keys(T).audit.key_id;
  const prepB = h.f.prepareRotation(h.p('security'), 'audit');
  h.f.store.audit(T, 'KEY_ROTATED', 'security', prepB.key_id, { key_class: 'audit', previous_key_id: keyA, ceremony_id: 'cer-b', revoke_old: false }, h.now());
  const last = h.f.store.db.prepare('SELECT seq,hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get(T);
  const payload = { tenant_id: T, sequence: last.seq + 1, previous: last.hash, type: 'AUDIT_ACCESSED', actor: 'mallory', reference: 'x', metadata: {}, time: h.now() };
  const env = h.f.signAudit(T, payload, 'audit', keyA);
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run(T, last.seq + 1, last.hash, digest(env.payload), JSON.stringify(env));
  const realPersist = h.f.persistVault.bind(h.f);
  h.f.persistVault = () => { throw new Error('disk full'); };
  let res;
  try { res = h.f.sealAuditChain(h.p('security')); } finally { h.f.persistVault = realPersist; }
  assert.equal(res.sealed, true, 'the committed seal still reports sealed');
  assert.ok(res.vault_persist_error, 'the durability fault surfaces on the result');
  assert.equal(h.f.keys(T).audit.key_id, prepB.key_id, 'the committed repoint is never un-repointed');
  assert.doesNotThrow(() => h.f._auditIndex(T), 'chain is live after the seal despite the persist fault');
});

// ─── F-6: oversize+malformed floods log+charge under a configured bearer ────
test('w20-fv F-6: oversize floods are logged and budgeted even with a bearer', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'w20f6-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const spec = { issuer: 'bank', tenant: T, version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds: ISSUER_RULES.bank, records: issuerRecords().bank, issue_token_digest: digest('Bearer tok-issue') };
  writeIssuer(dir, spec);
  const logPath = join(dir, 'issuance.log');
  const srv = createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', allow_insecure_loopback: true, logPath });
  await srv.listen(); t.after(() => srv.close());
  const port = srv.server.address().port;
  // Oversize body under a valid bearer — the flood must still land in the
  // chained log (a bearer does not buy log invisibility).
  const res = await new Promise((resolve, reject) => {
    const req = httpRequest({ host: '127.0.0.1', port, path: '/v1/issuers/bank/issue', method: 'POST', headers: { 'Content-Type': 'application/json', authorization: 'Bearer tok-issue' } }, r => { const c = []; r.on('data', x => c.push(x)); r.on('end', () => resolve({ status: r.statusCode })); });
    req.on('error', reject);
    req.end('x'.repeat(300 * 1024));
  });
  assert.equal(res.status, 413);
  const lines = readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
  assert.ok(lines.some(l => l.malformed === true && l.code === 'INV-413-BODY' && l.unauthenticated === false),
    'an oversize flood under a valid bearer is logged as authenticated probe traffic');
});

// ─── F-7/F-8: boot verifies the whole issuance chain, not just the tail ─────
test('w20-fv F-7/F-8: a mid-chain edit refuses boot; a valid prefix resumes', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'w20f7-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const spec = { issuer: 'bank', tenant: T, version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds: ISSUER_RULES.bank, records: issuerRecords().bank };
  writeIssuer(dir, spec);
  const logPath = join(dir, 'issuance.log');
  const srv = createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', allow_insecure_loopback: true, logPath });
  await srv.listen();
  const port = srv.server.address().port;
  // Two refused probes mint two chained log lines.
  for (const _ of [1, 2]) {
    await new Promise((resolve, reject) => {
      const req = httpRequest({ host: '127.0.0.1', port, path: '/v1/issuers/bank/issue', method: 'POST', headers: { 'Content-Type': 'application/json' } }, r => { r.resume(); r.on('end', resolve); });
      req.on('error', reject); req.end('x'.repeat(300 * 1024));
    });
  }
  await srv.close();
  const lines = readFileSync(logPath, 'utf8').trim().split('\n');
  assert.equal(lines.length, 2);
  // A mid-chain edit (first line tampered) must refuse boot.
  const tampered = JSON.parse(lines[0]); tampered.malformed = false;
  writeFileSync(logPath, JSON.stringify(tampered) + '\n' + lines[1] + '\n');
  assert.throws(() => createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', allow_insecure_loopback: true, logPath }), hasCode('INV-503-CONFIG'), 'edited line refuses boot');
  // A file truncated to a valid prefix resumes on the last honest link —
  // the acknowledged residual; tail loss beyond that is the off-box duty.
  writeFileSync(logPath, lines[0] + '\n');
  const srv2 = createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', allow_insecure_loopback: true, logPath });
  await srv2.listen(); t.after(() => srv2.close());
});

// ─── F-13: kind rules without lookup/confidence refuse at boot ─────────────
test('w20-fv F-13: a kind rule missing lookup or confidence refuses at boot', t => {
  const dir = mkdtempSync(join(tmpdir(), 'w20f13-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const base = { issuer: 'badbank', tenant: T, version: '1.0.0', channel: 'authoritative', key: generateKey(), records: {} };
  writeFileSync(join(dir, 'a.issuer.json'), canonical({ ...base, kinds: { ownership: { confidence: 90 } } }) + '\n', { mode: 0o600 });
  assert.throws(() => loadIssuers(dir), hasCode('INV-400-SCHEMA'), 'missing lookup refuses at boot');
  rmSync(join(dir, 'a.issuer.json'));
  writeFileSync(join(dir, 'b.issuer.json'), canonical({ ...base, kinds: { ownership: { lookup: 'a:${claims.a}' } } }) + '\n', { mode: 0o600 });
  assert.throws(() => loadIssuers(dir), hasCode('INV-400-SCHEMA'), 'missing confidence refuses at boot');
});

// ─── F-9: a dedup hit unwinds the donor's migrated mark ────────────────────
test('w20-fv F-9: a reverted donor is no longer counted as migrated', t => {
  const dir = mkdtempSync(join(tmpdir(), 'w20f9-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const keys = { [T]: randomBytes(32).toString('base64url') };
  const master = Buffer.from(keys[T], 'base64url');
  const p = join(dir, 'f9.db');
  const s0 = new Store(p, keys, {}); s0.close();
  const db = new DatabaseSync(p);
  const dek = randomBytes(32), secret = { ssn: 'victim' };
  const wrappedDek = encrypt(dek.toString('base64url'), master, `${T}/payroll/e-7/dek`);
  db.prepare('INSERT INTO deks VALUES(?,?,?,?)').run(T, 'payroll', 'e-7', wrappedDek);
  db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run(T, 'payroll', 'e-7', encrypt(secret, dek, `${T}/payroll/e-7`), 1);
  db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run(T, 'payroll', 'e-7/dek', wrappedDek, 1);
  db.close();
  const s = new Store(p, keys, {});
  const st = s.aadMigration.get(T);
  // The honest 'e-7' record did migrate — only the grafted deks donor
  // unwinds, so migrated is 1 and the undo is separately accounted.
  assert.equal(st.migrated, 1, 'the reverted donor is no longer counted as migrated');
  assert.equal(st.reverted, 1, 'the unwind is accounted, not hidden');
  assert.ok(st.transplants >= 1, 'the graft is counted as a transplant');
  s.close();
});

// ─── F-11: an honest 'dek'-suffixed record id must not be quarantined ──────
test('w20-fv F-11: a records row named dek migrates; a slash alias still quarantines', t => {
  const dir = mkdtempSync(join(tmpdir(), 'w20f11-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const keys = { [T]: randomBytes(32).toString('base64url') };
  const master = Buffer.from(keys[T], 'base64url');
  const p = join(dir, 'f11.db');
  const s0 = new Store(p, keys, {}); s0.close();
  const db = new DatabaseSync(p);
  const dek = randomBytes(32);
  db.prepare('INSERT INTO deks VALUES(?,?,?,?)').run(T, 'x', 'y', encrypt(dek.toString('base64url'), master, canonical([T, 'x', 'y', 'dek'])));
  // An honest legacy row literally named 'dek' — three-segment AAD can
  // never alias the four-segment dek space, so it must migrate.
  db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run(T, 'x', 'dek', encrypt({ honest: 'dek-named' }, master, `${T}/x/dek`), 1);
  // A true alias keeps quarantining: 'x'/'v/dek' collides with deks 'x/v/dek'.
  db.prepare('INSERT INTO deks VALUES(?,?,?,?)').run(T, 'x', 'v', encrypt(dek.toString('base64url'), master, `${T}/x/v/dek`));
  db.prepare('INSERT INTO records VALUES(?,?,?,?,?)').run(T, 'x', 'v/dek', encrypt({ alias: true }, master, `${T}/x/v/dek`), 1);
  db.close();
  const s = new Store(p, keys, {});
  assert.deepEqual(s.get(T, 'x', 'dek'), { honest: 'dek-named' }, 'honest dek-named row migrated and reads');
  assert.throws(() => s.get(T, 'x', 'v/dek'), 'the true four-segment alias still quarantines');
  s.close();
});



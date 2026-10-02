import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { fixture, installPolicy } from './helpers.mjs';
import { createServer } from '../src/server.mjs';
import { bootstrap } from '../src/bootstrap.mjs';
import { signed, verifySigned, generateKey } from '../src/crypto.mjs';
import { KeyVault } from '../src/keystore.mjs';
import { verifyAudit } from '../src/store.mjs';
import { hashBytes } from '../src/canonical.mjs';
import { hasCode } from './helpers.mjs';

// Wave-7 fix regressions: clock recovery monotonicity, expired-policy
// succession, session binding to token revocation, session caps, and the
// backup/restore verifier's external trust anchor + commitments.

// w7-clock F1: recovery accepts the operator-asserted rewound host time —
// `last` is a regression detector, not the time source, so writing the
// monotone maximum would wedge the gate permanently after an honest rewind
// (VM snapshot restore). The discontinuity itself lands on the signed
// chain as evidence, and chain verification still passes: integrity is
// seq+hash+signature, never wall-clock order.
test('w7-clock F1: recoverClock records the discontinuity and un-wedges the gate', t => {
  const h = fixture(t);
  h.advance(60000);
  h.proposed(); // lands an audit entry at the advanced time
  const lastBefore = h.f.store.db.prepare('SELECT last FROM clock WHERE id=1').get().last;
  h.set(lastBefore - 30000); // host clock rewound (snapshot restore)
  assert.throws(() => h.proposed(), hasCode('INV-503-TIME'), 'rewind halts the gate until recovery');
  const out = h.f.recoverClock(h.p('security'));
  assert.equal(out.recovered_at, lastBefore - 30000, 'the ledger accepts the operator-asserted host time');
  assert.equal(out.prior_last, lastBefore, 'the discontinuity is on record');
  h.proposed(); // the gate lives again at the rewound time
  const bundle = h.f.exportAudit(h.p('auditor'), 'clock recovery chain check');
  const recovered = bundle.entries.find(e => e.envelope.payload.type === 'CLOCK_RECOVERED');
  assert.ok(recovered, 'the recovery event is on the signed chain');
  assert.equal(recovered.envelope.payload.metadata.prior_last, lastBefore);
  assert.equal(recovered.envelope.payload.metadata.regression_ms, 30000);
  assert.equal(verifyAudit(bundle, bundle.public_keys).valid, true, 'chain integrity is unaffected by the time discontinuity');
});

// w7-clock F2: an expired constitution must still mint the certificate for
// its own succession — otherwise a lapsed policy wedges the tenant forever.
test('w7-clock F2: succession certificates survive an expired active policy', t => {
  const h = fixture(t);
  // A short-lived successor installs through real governance and then
  // lapses — the active constitution is honestly expired, not a store
  // rewrite (which the chain anchor now refuses, w12 red-team).
  installPolicy(h, p => { p.expires_at = h.now() + 122000; });
  h.advance(3000); // past v2's expiry — the live constitution has lapsed
  // v3 inherits v2's allow_weakening declaration — drop it: reviving a
  // lapsed constitution is no weakening, so the plain threshold applies.
  const next = h.clone(h.f.policy('acme')); next.version += 1; delete next.allow_weakening; next.not_before = h.now(); next.expires_at = h.now() + 86400000;
  const r = h.proposed('policy.change', { policy: next }, { action: { type: 'policy.change', target_resource: 'policy-root', purpose: 'Succession' } });
  h.f.simulate(h.p('policy-admin'), next);
  h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'audit-committee' });
  h.approve(r, 3); h.advance(120001);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  assert.ok(cert.payload.expires_at > h.now(), 'the succession certificate is alive, not stillborn');
});

async function httpFixture(t) {
  const h = fixture(t), app = createServer(h.f, { port: 0, origin: 'http://127.0.0.1:17777' }); await app.listen(); t.after(() => app.close()); const port = app.server.address().port;
  const request = (path, { token = h.setup.credentials.acme.security, method = 'GET', json, headers = {} } = {}) => new Promise((resolve, reject) => {
    const bodyData = json === undefined ? null : Buffer.from(JSON.stringify(json));
    const req = http.request({ host: '127.0.0.1', port, path, method, headers: { Host: '127.0.0.1:17777', Origin: 'http://127.0.0.1:17777', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(bodyData ? { 'Content-Type': 'application/json', 'Content-Length': bodyData.length } : {}), ...headers } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, data: JSON.parse(Buffer.concat(chunks).toString('utf8')), headers: res.headers }));
    }); req.on('error', reject); if (bodyData) req.write(bodyData); req.end();
  });
  const cookieOf = res => (res.headers['set-cookie'] ?? []).find(c => c.startsWith('if_session='))?.match(/if_session=([A-Za-z0-9_-]{43})/)?.[1];
  return { ...h, request, cookieOf };
}

// w7-clock F3 / w7-console F2: a cookie session minted from a token dies the
// moment that token is revoked — revocation is re-checked per request, not
// only at mint time.
test('w7-clock F3: token revocation kills its cookie sessions immediately', async t => {
  const h = await httpFixture(t);
  const token = h.setup.credentials.acme.security;
  const login = await h.request('/session', { token: null, method: 'POST', json: { token } });
  assert.equal(login.status, 200);
  const sid = h.cookieOf(login); assert.ok(sid);
  const alive = await h.request('/v1/me', { token: null, headers: { Cookie: `if_session=${sid}` } });
  assert.equal(alive.status, 200);
  h.f.revoke(h.p('security'), { kind: 'token', id: hashBytes(token), reason: 'credential leak' });
  const dead = await h.request('/v1/me', { token: null, headers: { Cookie: `if_session=${sid}` } });
  assert.equal(dead.status, 401, 'the session dies with its credential, without waiting for expiry');
});

// w7-console F4: logout retires every sibling session minted from the same
// credential — the stolen-token blast radius ends at the sweep.
test('w7-console F4: logout kills every sibling session of the same token', async t => {
  const h = await httpFixture(t);
  const token = h.setup.credentials.acme.security;
  const a = await h.request('/session', { token: null, method: 'POST', json: { token } });
  const b = await h.request('/session', { token: null, method: 'POST', json: { token } });
  const c = await h.request('/session', { token: null, method: 'POST', json: { token: h.setup.credentials.acme.operator } });
  assert.equal(a.status + b.status + c.status, 600);
  const bye = await h.request('/session/logout', { token: null, method: 'POST', json: {}, headers: { Cookie: `if_session=${h.cookieOf(a)}`, 'X-CSRF-Token': a.data.csrf_token } });
  assert.equal(bye.status, 200);
  assert.equal((await h.request('/v1/me', { token: null, headers: { Cookie: `if_session=${h.cookieOf(b)}` } })).status, 401, 'sibling minted from the same token is gone');
  assert.equal((await h.request('/v1/me', { token: null, headers: { Cookie: `if_session=${h.cookieOf(c)}` } })).status, 200, 'a session minted from a different credential survives');
});

// w7-console F1: the per-tenant session ceiling stops one flooded tenant
// from exhausting the global pool. The cap is configured to 10 for the run
// — the production default of 250 sits above the 20/min login rate limit.
test('w7-console F1: per-tenant session cap fires before the global cap', async t => {
  const h = fixture(t), app = createServer(h.f, { port: 0, origin: 'http://127.0.0.1:17777', tenantSessionCap: 10 });
  await app.listen(); t.after(() => app.close());
  const port = app.server.address().port;
  const token = h.setup.credentials.acme.security;
  const login = () => new Promise((resolve, reject) => {
    const bodyData = Buffer.from(JSON.stringify({ token }));
    const req = http.request({ host: '127.0.0.1', port, path: '/session', method: 'POST', headers: { Host: '127.0.0.1:17777', Origin: 'http://127.0.0.1:17777', 'Content-Type': 'application/json', 'Content-Length': bodyData.length } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, data: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
    }); req.on('error', reject); req.write(bodyData); req.end();
  });
  for (let i = 0; i < 10; i++) assert.equal((await login()).status, 200, `login ${i}`);
  const overflow = await login();
  assert.equal(overflow.status, 503, 'the session cap for the tenant is refused');
  assert.equal(overflow.data.error.code, 'INV-503-CAPACITY');
  // The OTHER tenant's pool is untouched — the flood was tenant-scoped.
  const globex = await new Promise((resolve, reject) => {
    const bodyData = Buffer.from(JSON.stringify({ token: h.setup.credentials.globex.security }));
    const req = http.request({ host: '127.0.0.1', port, path: '/session', method: 'POST', headers: { Host: '127.0.0.1:17777', Origin: 'http://127.0.0.1:17777', 'Content-Type': 'application/json', 'Content-Length': bodyData.length } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode }));
    }); req.on('error', reject); req.write(bodyData); req.end();
  });
  assert.equal(globex.status, 200, 'a second tenant still logs in under its own ceiling');
});

// Backup/restore verifier honesty: external trust anchor, committed audit
// heads, sidecar/symlink rejection, cross-database consistency.
function drill(t) {
  const dir = mkdtempSync(join(tmpdir(), 'if-w7-backup-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  bootstrap(join(dir, 'deploy'), ['acme'], Date.now());
  const out = join(dir, 'backup');
  const run = spawnSync(process.execPath, ['scripts/backup.mjs', '--dir', join(dir, 'deploy'), '--out', out], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  const cfg = join(dir, 'deploy', 'config.json');
  const verify = () => spawnSync(process.execPath, ['scripts/restore-check.mjs', '--dir', out, '--trusted-keys', cfg], { encoding: 'utf8' });
  const manifest = () => JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8'));
  const auditKey = () => JSON.parse(readFileSync(cfg, 'utf8')).tenants.acme.keys.audit;
  const vault = () => KeyVault.load(join(dir, 'deploy', 'keystore.json'), JSON.parse(readFileSync(join(dir, 'deploy', 'master.key'), 'utf8')).master_key);
  // Re-sign a mutated payload with the REAL deployment audit key — the
  // signature and file hashes then match, so only the structural checks
  // under test can catch the tampering.
  const resign = mutate => {
    const signedPayload = verifySigned(manifest().envelope, { [auditKey().key_id]: { public_key: auditKey().public_key } }, 'backup-manifest');
    mutate(signedPayload);
    for (const e of signedPayload.databases) { try { e.sha256 = createHash('sha256').update(readFileSync(join(out, e.file))).digest('hex'); } catch { /* injected entries keep a dummy hash */ } }
    writeFileSync(join(out, 'manifest.json'), JSON.stringify({ format: 'IF-BACKUP-1', envelope: vault().envelope(auditKey().key_id, 'backup-manifest', signedPayload), public_keys: manifest().public_keys }, null, 2));
  };
  return { dir, out, cfg, verify, manifest, resign };
}

test('w7-backup F1: the manifest must verify under an external trust anchor, not keys inside the artifact', t => {
  const { out, verify, cfg, dir } = drill(t);
  const noAnchor = spawnSync(process.execPath, ['scripts/restore-check.mjs', '--dir', out], { encoding: 'utf8' });
  assert.equal(noAnchor.status, 2, 'no trust anchor → refuses to verify');
  assert.equal(verify().status, 0, 'the real deployment config verifies the drill');
  // A write-only attacker forges a manifest signed by THEIR OWN key shipped
  // inside the artifact — the exact self-certifying path the old verifier
  // trusted.
  const rogue = generateKey();
  const forged = { format: 'IF-BACKUP-1', envelope: signed({ format: 'IF-BACKUP-1', databases: [{ file: 'fabric.db', sha256: '0'.repeat(64), user_version: 1 }] }, { key_id: rogue.key_id, private_key: rogue.private_key, suite: 'Ed25519' }, 'backup-manifest'), public_keys: { [rogue.key_id]: { public_key: rogue.public_key } } };
  writeFileSync(join(out, 'manifest.json'), JSON.stringify(forged, null, 2));
  const check = verify();
  assert.equal(check.status, 1, 'a manifest signed by attacker keys inside the artifact is rejected');
});

test('w7-backup F4: wal sidecars and symlinked artifacts are rejected', t => {
  const { out, verify, dir } = drill(t);
  writeFileSync(join(out, 'fabric.db-wal'), Buffer.alloc(8192));
  const wal = verify();
  assert.equal(wal.status, 1);
  assert.match(wal.stdout, /wal sidecar/);
  rmSync(join(out, 'fabric.db-wal'));
  rmSync(join(out, 'fabric.db'));
  symlinkSync(join(dir, 'deploy', 'target.db'), join(out, 'fabric.db'));
  const link = verify();
  assert.equal(link.status, 1);
  assert.match(link.stdout, /symlink/);
});

test('w7-backup F3/F7: committed audit heads catch truncation and a dropped audit table', t => {
  const { out, verify, resign } = drill(t);
  // The drill db carries real audit rows (bootstrap writes them). Dropping
  // the table while the manifest commits heads must fail — even when the
  // payload is re-signed by the legitimate key and every file hash matches.
  const db = new DatabaseSync(join(out, 'fabric.db'));
  db.exec('DROP TABLE audit'); db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); db.close();
  resign(() => {});
  const check = verify();
  assert.equal(check.status, 1);
  assert.match(check.stdout, /audit table missing|audit head mismatch/);
});

test('w7-backup F6: traversal entries inside a signed payload are rejected', t => {
  const { verify, resign } = drill(t);
  resign(payload => payload.databases.push({ file: '..', sha256: '0'.repeat(64), user_version: 1 }));
  const check = verify();
  assert.equal(check.status, 1);
  assert.match(check.stdout, /unsanitised filename/);
});

test('w7-backup F5: a torn cross-database snapshot fails the referential check', t => {
  const { out, verify, resign } = drill(t);
  const db = new DatabaseSync(join(out, 'target.db'));
  db.prepare('INSERT INTO transactions VALUES(?,?,?)').run('acme', 'phantom-certificate', Buffer.alloc(64).toString('base64'));
  db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); db.close();
  resign(() => {});
  const check = verify();
  assert.equal(check.status, 1);
  assert.match(check.stdout, /torn cross-database snapshot/);
});

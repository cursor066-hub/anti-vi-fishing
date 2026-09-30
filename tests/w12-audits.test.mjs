// Wave-12 audit regressions: timing/side-channel + secret-handling fixes
// (w11-timing re-audit) and supply-chain round-2 hardening (w11-supply).
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { fixture, hasCode } from './helpers.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

// ---- w11-timing NEW-MED-1: revocation is not retroactive erasure ----
test('w12: routine audit-key revocation keeps pre-rotation outcomes verifiable', t => {
  const h = fixture(t);
  const { certificate } = h.ready();
  const result = h.f.execute(h.p(), certificate);
  assert.equal(result.payload.status, 'VERIFIED');
  const auditKid = h.setup.config.tenants.acme.keys.audit.key_id;
  assert.equal(result.protected.key_id, auditKid, 'outcome was signed by the bound audit key');
  // The bound signer cannot be revoked without a pending successor
  // (w11-lifecycle F1) — prepareRotation supplies it.
  h.f.prepareRotation(h.p('security'), 'audit');
  h.f.revoke(h.p('security'), { kind: 'key', id: auditKid, reason: 'routine retirement' });
  // The retired key's authentic signature still anchors the stored row —
  // revocation gates future signing, never the reading of history.
  const stored = h.f.store.must('acme', 'outcome', certificate.payload.certificate_id);
  const view = h.f.outcomeView('acme', stored);
  assert.equal(view.payload.status, 'VERIFIED');
  assert.equal(view.protected.key_id, auditKid);
});

// ---- w11-timing MED-3: expired perception sessions surrender their key ----
test('w12: retentionSweep tombstones the ECDH private key of expired sessions', t => {
  const h = fixture(t);
  const component = h.setup.componentSecrets.acme['secure-view-acme'];
  const session = h.f.perceptionSession(h.p(), component.attest('e'.repeat(64), h.now() + 1000));
  const before = h.f.store.must('acme', 'perception-session', session.session_id);
  assert.equal(typeof before._server_private, 'string');
  // A live session is untouched by the sweep.
  const first = h.f.retentionSweep(h.p('security'));
  assert.equal(first.session_keys_shredded, 0);
  assert.equal(typeof h.f.store.must('acme', 'perception-session', session.session_id)._server_private, 'string');
  // After expiry no release may be minted (session.expires_at gate) — the
  // ephemeral private material must not persist.
  h.advance(2000);
  const res = h.f.retentionSweep(h.p('security'));
  assert.ok(res.session_keys_shredded >= 1);
  const after = h.f.store.must('acme', 'perception-session', session.session_id);
  assert.equal(after._server_private, null);
  assert.equal(typeof after.key_shredded_at, 'number');
});

// ---- w11-timing LOW-7: object material_fields never serve secret bytes ----
test('w12: capsuleView scrubs secret-shaped values in object material fields', t => {
  const h = fixture(t);
  h.f.target.seedSecret('acme', 'secret-x', { workload_id: 'workload-1', allowed_operations: ['sign'], value: { password: 'SUPER-SECRET-BYTES' }, signing_key: 'PRIVATE-MATERIAL' });
  const r = h.proposed('secret.use', { secret_id: 'secret-x', operation: 'sign', workload_id: 'workload-1' }, { action: { type: 'secret.use', target_resource: 'secret-x', purpose: 'Secret op' } });
  const view = h.f.capsuleView(h.f.store.must('acme', 'capsule', r.capsule.capsule_id));
  const served = JSON.stringify(view);
  assert.ok(!served.includes('SUPER-SECRET-BYTES'), 'secret bytes absent from the served view');
  assert.ok(!served.includes('PRIVATE-MATERIAL'), 'key material absent from the served view');
  // Non-secret operational fields remain readable — redaction is by key
  // shape, not wholesale object removal.
  assert.ok(served.includes('workload-1'));
});

// ---- w11-timing NEW-LOW-1: denial-audit deduplication bound ----
test('w12: identical pre-transaction denials audit once per 60-second window', t => {
  const h = fixture(t);
  const count = () => h.f.store.auditPage('acme', { limit: 10000 }).entries.filter(e => e.envelope?.payload?.type === 'AUTHORIZATION_DENIED' && e.envelope.payload.metadata?.code === 'INV-403-ROLE').length;
  const before = count();
  const deny = () => { try { h.f.revoke(h.p('custodian-1'), { kind: 'device', id: 'x', reason: 'x' }); } catch (e) { assert.equal(e.code, 'INV-403-ROLE'); } };
  deny(); deny(); deny();
  assert.equal(count() - before, 1, 'burst of identical denials recorded once');
  h.advance(60_001);
  deny();
  assert.equal(count() - before, 2, 'a new window records a fresh entry');
});

// ---- w11-supply SC-01/SC-02: manifest set-equality + ignore-proof extras ----
test('w12: manifest --verify flags tracked-but-unlisted files and ignored payloads', t => {
  const dir = mkdtempSync(join(tmpdir(), 'mani-repo-'));
  cpSync(join(root, 'scripts', 'manifest.mjs'), join(dir, 'scripts', 'manifest.mjs'), { recursive: true });
  const init = () => {
    execFileSync('git', ['init', '-q'], { cwd: dir });
    execFileSync('git', ['add', '-A'], { cwd: dir });
    execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-qm', 'x'], { cwd: dir });
    execFileSync(process.execPath, [join(dir, 'scripts', 'manifest.mjs')], { cwd: dir });
  };
  init();
  const verify = () => execFileSync(process.execPath, [join(dir, 'scripts', 'manifest.mjs'), '--verify'], { cwd: dir, encoding: 'utf8' });
  const verifyFails = (rx) => { try { verify(); assert.fail('manifest --verify should have failed'); } catch (e) { assert.ok(rx.test(e.stderr ?? e.stdout ?? ''), `${e.stderr || e.stdout}`); } };
  assert.equal(JSON.parse(verify()).manifest_fresh, true);
  // SC-01: a TRACKED file absent from the manifest ships un-hashed inside
  // git-archive releases — set equality must catch it.
  writeFileSync(join(dir, 'stowaway.mjs'), 'export const x = 1;\n');
  execFileSync('git', ['add', 'stowaway.mjs'], { cwd: dir });
  execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-qm', 'stowaway'], { cwd: dir });
  verifyFails(/unlisted tracked file: stowaway\.mjs/);
  execFileSync('git', ['rm', '-q', 'stowaway.mjs'], { cwd: dir });
  execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-qm', 'unstow'], { cwd: dir });
  // SC-02: a payload hidden behind .gitignore in a non-exempt path is still
  // an unexpected file — the extras scan does not consult ignore rules.
  writeFileSync(join(dir, '.gitignore'), 'ignored-payload.sh\n');
  writeFileSync(join(dir, 'ignored-payload.sh'), '#!/bin/sh\n');
  verifyFails(/unexpected file: ignored-payload\.sh/);
});

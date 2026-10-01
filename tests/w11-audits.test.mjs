import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { fixture, hasCode, designateSuccessor } from './helpers.mjs';
import { signAcknowledgement } from '../src/ceremony.mjs';
import { signed, verifySigned, generateKey } from '../src/crypto.mjs';
import { digest } from '../src/canonical.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

// Wave-11 audit regressions: stored-record integrity anchors (red-team),
// revocation-brick lifecycle fixes, evidence supersession, approval TTL
// replay, pre-transaction denial auditing, supply-chain manifest truth.

// ---- red-team F1/F2: store-level capsule tamper dies on the signed intent ----
test('w11: mutating a stored capsule row fails the signed-intent integrity check', t => {
  const h = fixture(t);
  const r = h.proposed();
  const rec = h.f.store.must('acme', 'capsule', r.capsule.capsule_id);
  // The attacker controls the whole row, including the stored digest field.
  rec.capsule.requested_state.bank_account = 'ATTACKERCONTROLLED';
  rec.capsule_digest = digest(rec.capsule);
  h.f.store.put('acme', 'capsule', r.capsule.capsule_id, rec, h.now());
  // The capsule_digest column agrees with the tampered payload — but the
  // signed request_intent no longer covers it.
  for (const op of [
    () => h.f.evaluate(h.p(), r.capsule.capsule_id),
    () => h.f.certificate(h.p(), r.capsule.capsule_id),
  ]) assert.throws(op, hasCode('INV-409-INTEGRITY'));
});

test('w11: a planted outcome row (no vault signature) fails integrity on read', t => {
  const h = fixture(t);
  const { certificate } = h.ready();
  // Plant a consumed cert + an outcome envelope signed by an identity key —
  // the store-level write path with no vault custody.
  const stored = h.f.store.must('acme', 'certificate', certificate.payload.certificate_id);
  stored.consumed = true;
  h.f.store.put('acme', 'certificate', certificate.payload.certificate_id, stored, h.now());
  const forged = signed({ certificate_id: certificate.payload.certificate_id, status: 'VERIFIED', tenant_id: 'acme' }, h.setup.identityKeys.acme['custodian-1'], 'outcome');
  h.f.store.put('acme', 'outcome', certificate.payload.certificate_id, forged, h.now());
  assert.throws(() => h.f.reconcile(h.p(), certificate.payload.certificate_id), hasCode('INV-409-INTEGRITY'));
});

test('w11: finish on an unreserved certificate is a forged-outcome rejection', t => {
  const h = fixture(t);
  const { certificate } = h.ready();
  assert.throws(() => h.f.finish(h.p(), certificate.payload, { observed_state_digest: 'x'.repeat(64) }, 'VERIFIED', 'forged'), hasCode('INV-409-STATE'));
});

// ---- red-team F7: pre-transaction denials land in the ledger ----
test('w11: a role denial outside a transaction still writes AUTHORIZATION_DENIED', t => {
  const h = fixture(t);
  const before = h.f.store.auditPage('acme', { limit: 10000 }).entries.length;
  assert.throws(() => h.f.revoke(h.p('custodian-1'), { kind: 'device', id: 'x', reason: 'x' }), hasCode('INV-403-ROLE'));
  const entries = h.f.store.auditPage('acme', { limit: 10000 }).entries.slice(before);
  assert.ok(entries.some(e => e.envelope?.payload?.type === 'AUTHORIZATION_DENIED' && e.envelope.payload.metadata?.code === 'INV-403-ROLE'), JSON.stringify(entries.map(e => e.envelope?.payload?.type)));
});

test('w11: a quarantined-device propose denial writes audit AND containment', t => {
  const h = fixture(t);
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'lost' });
  assert.throws(() => h.proposed(), hasCode('INV-403-QUARANTINE'));
  const containment = h.f.store.list('acme', 'containment', 100);
  assert.ok(containment.some(c => c.device_id === 'operator-device'), 'denial joined the containment ledger');
  const entries = h.f.store.auditPage('acme', { limit: 10000 }).entries;
  assert.ok(entries.some(e => e.envelope?.payload?.type === 'AUTHORIZATION_DENIED' && e.envelope.payload.metadata?.code === 'INV-403-QUARANTINE'));
});

// ---- red-team F6: grant-carried privileged roles are filtered ----
test('w11: a grant carrying security role cannot mint privilege', t => {
  const h = fixture(t);
  h.f.target.grant('acme', 'grant-x', { grant_id: 'grant-x', subject_id: 'operator', roles: ['security', 'policy_admin'], resources: [], actions: [], destinations: [], columns: [], row_ids: [], expires_at: h.now() + 60000, revoked: false });
  const merged = h.f.grantsFor('acme', 'operator', h.now());
  assert.ok(!merged.roles.includes('security') && !merged.roles.includes('policy_admin'), JSON.stringify(merged.roles));
  assert.throws(() => h.f.getCapsule(h.p('auditor', 'acme'), 'x'), hasCode('INV-404-NOT-FOUND')); // control: auditor still works
});

// ---- lifecycle F1: unguarded execution-key revoke is refused ----
test('w11-lifecycle F1: revoking the execution key without a pending successor is refused', t => {
  const h = fixture(t);
  const execKid = h.f.keys('acme').execution.key_id;
  assert.throws(() => h.f.revoke(h.p('security'), { kind: 'key', id: execKid, reason: 'compromise drill' }), hasCode('INV-409-STATE'));
});

// ---- lifecycle F1: the recovery chain stays live across the revoke ----
test('w11-lifecycle F1: exec-key recovery — pending successor signs marked certs, rotation completes', t => {
  const h = fixture(t);
  const pending = h.f.prepareRotation(h.p('security'), 'execution');
  const custodians = ['custodian-1', 'custodian-2'];
  const c = h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-exec', purpose: 'key.rotate', threshold: 2, custodians, valid_until: h.now() + 3600000, min_delay_ms: 120000, rotation: { key_class: 'execution', new_key_id: pending.key_id } });
  for (const s of custodians) h.f.acknowledgeCeremony(h.p(s), signAcknowledgement(c, s, h.setup.custodianKeys.acme[s], h.now()));
  const execKid = h.f.keys('acme').execution.key_id;
  h.f.revoke(h.p('security'), { kind: 'key', id: execKid, reason: 'compromise drill' });
  // The rotation capsule can still mint: its certificate is signed by the
  // pending successor and honestly marked as recovery signing.
  const r = h.proposed('key.rotate', { key_class: 'execution', new_key_id: pending.key_id, new_public_key: pending.public_key, ceremony_id: 'cer-exec', revoke_old: true }, { action: { type: 'key.rotate', target_resource: 'key-registry', purpose: 'Recovery' } });
  h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'audit-committee' });
  h.approve(r, 3); h.advance(60001);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  assert.equal(cert.protected.key_id, pending.key_id, 'certificate signed by the pending successor');
  assert.equal(cert.payload.recovery_signing.superseded_key, execKid);
  const outcome = h.f.execute(h.p(), cert);
  assert.equal(outcome.payload.status, 'VERIFIED');
  // Post-rotation the new key is the configured signer — no recovery marker.
  const { certificate: c2 } = h.ready();
  assert.equal(c2.protected.key_id, pending.key_id);
  assert.equal(c2.payload.recovery_signing, undefined);
  assert.equal(h.f.execute(h.p(), c2).payload.status, 'VERIFIED');
});

// ---- lifecycle F2: revoked audit key settles in-flight work via successor ----
test('w11-lifecycle F2: audit-key revoke with pending successor keeps outcomes settling', t => {
  const h = fixture(t);
  const { certificate } = h.ready();
  const pendingAudit = designateSuccessor(h, 'audit');
  h.f.revoke(h.p('security'), { kind: 'key', id: h.f.keys('acme').audit.key_id, reason: 'compromise drill' });
  const outcome = h.f.execute(h.p(), certificate);
  assert.equal(outcome.payload.status, 'VERIFIED');
  assert.equal(outcome.protected.key_id, pendingAudit.key_id, 'outcome signed by the pending audit successor');
  assert.equal(outcome.payload.recovery_signing.superseded_key, h.f.keys('acme').audit.key_id);
});

test('w11-lifecycle F2: audit rotation completes when the predecessor is already revoked', t => {
  const h = fixture(t);
  const pendingAudit = h.f.prepareRotation(h.p('security'), 'audit');
  const custodians = ['custodian-1', 'custodian-2'];
  const c = h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-aud', purpose: 'key.rotate', threshold: 2, custodians, valid_until: h.now() + 3600000, min_delay_ms: 120000, rotation: { key_class: 'audit', new_key_id: pendingAudit.key_id } });
  for (const s of custodians) h.f.acknowledgeCeremony(h.p(s), signAcknowledgement(c, s, h.setup.custodianKeys.acme[s], h.now()));
  const oldAudit = h.f.keys('acme').audit.key_id;
  h.f.revoke(h.p('security'), { kind: 'key', id: oldAudit, reason: 'compromise drill' });
  const r = h.proposed('key.rotate', { key_class: 'audit', new_key_id: pendingAudit.key_id, new_public_key: pendingAudit.public_key, ceremony_id: 'cer-aud', revoke_old: true }, { action: { type: 'key.rotate', target_resource: 'key-registry', purpose: 'Recovery' } });
  h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'audit-committee' });
  h.approve(r, 3); h.advance(60001);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  const outcome = h.f.execute(h.p(), cert);
  assert.equal(outcome.payload.status, 'VERIFIED');
  // The outcome attesting the succession is signed by the incoming key.
  assert.equal(outcome.protected.key_id, pendingAudit.key_id);
  // New audit writes now sign under the activated successor, no marker.
  h.ready();
  const last = h.f.store.auditPage('acme', { limit: 10000 }).entries.at(-1);
  assert.equal(last.envelope.protected.key_id, pendingAudit.key_id);
  assert.equal(last.envelope.payload.recovery_signing, undefined);
});

// ---- lifecycle F3: lapsed approvals free the signer instead of burning it ----
test('w11-lifecycle F3: an expired approval no longer blocks re-approval', t => {
  const h = fixture(t);
  const r = h.proposed();
  h.evidence(r, {}); h.evidence(r, { issuer: 'registry' });
  const challenge = h.f.approvalChallenge(h.p('custodian-1'), r.capsule.capsule_id);
  h.f.approve(h.p('custodian-1'), signed(challenge, h.setup.identityKeys.acme['custodian-1'], 'action-approval'));
  h.advance(300001); // past the 5-minute approval TTL
  const challenge2 = h.f.approvalChallenge(h.p('custodian-1'), r.capsule.capsule_id);
  const res = h.f.approve(h.p('custodian-1'), signed(challenge2, h.setup.identityKeys.acme['custodian-1'], 'action-approval'));
  assert.equal(res.approvals, 2, 'lapsed approval no longer counts toward the replay guard');
});

// ---- lifecycle F4: superseded evidence stops wedging; conflicts stay sticky ----
test('w11-lifecycle F4: fresh same-issuer evidence supersedes the expired envelope', t => {
  const h = fixture(t);
  const r = h.proposed();
  h.evidence(r, { expiry: h.now() + 60000 });
  h.advance(120000);
  const d1 = h.f.evaluate(h.p(), r.capsule.capsule_id);
  assert.ok(d1.reasons.some(x => x.code === 'EVIDENCE_EXPIRED' || x.code === 'EVIDENCE_STALE'), JSON.stringify(d1.reasons));
  // A fresh envelope from the same issuer+kind retires the stale one.
  h.evidence(r, {});
  const d2 = h.f.evaluate(h.p(), r.capsule.capsule_id);
  assert.ok(!d2.reasons.some(x => x.code === 'EVIDENCE_EXPIRED' || x.code === 'EVIDENCE_STALE'), JSON.stringify(d2.reasons));
});

// w14: the issuer's own later supports envelope is a signed retraction and
// DOES supersede its conflict — a veto is sticky only against a different
// issuer, or there would be no honest way to resolve one (w11-lifecycle F4).
test('w11-lifecycle F4: a conflict survives supports from a different issuer, but its own issuer may retract it', t => {
  const h = fixture(t);
  const r = h.proposed();
  h.evidence(r, { claim: 'conflict' });
  // A DIFFERENT issuer's later supports cannot launder the veto away.
  h.evidence(r, { issuer: 'registry' });
  assert.ok(h.f.evaluate(h.p(), r.capsule.capsule_id).reasons.some(x => x.code === 'EVIDENCE_CONFLICT'));
  // The vetoing issuer itself may retract it with a fresh supports envelope.
  const s = h.proposed();
  h.evidence(s, { claim: 'conflict' });
  h.evidence(s, {}); // same issuer+kind — a signed retraction
  const d = h.f.evaluate(h.p(), s.capsule.capsule_id);
  assert.ok(!d.reasons.some(x => x.code === 'EVIDENCE_CONFLICT'), JSON.stringify(d.reasons));
});

// ---- lifecycle F6/F7: re-revoke and terminal-status cancels are refused ----
test('w11-lifecycle F6: re-revocation preserves the first response', t => {
  const h = fixture(t);
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'first' });
  assert.throws(() => h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'second' }), hasCode('INV-409-STATE'));
  const stored = h.f.store.get('acme', 'revocation', 'device:operator-device');
  assert.equal(stored.reason, 'first');
});

test('w11-lifecycle F7: terminal capsules cannot be re-cancelled or whitewashed', t => {
  const h = fixture(t);
  const r = h.proposed();
  h.f.cancel(h.p(), r.capsule.capsule_id);
  assert.throws(() => h.f.cancel(h.p(), r.capsule.capsule_id), hasCode('INV-409-STATE'));
  const denied = h.proposed('cloud.firewall.change', { protocol: 'tcp', port: 443, source_cidr: '0.0.0.0/0', service_id: 'svc-1' });
  const d = h.f.evaluate(h.p(), denied.capsule.capsule_id);
  assert.equal(d.decision, 'DENY');
  assert.throws(() => h.f.cancel(h.p(), denied.capsule.capsule_id), hasCode('INV-409-STATE'));
});

// ---- supply-chain M3: pinned sample-bundle identity ----
test('w11-supply M3: the pinned sample bundle binds a fixed signer and tenant', t => {
  const bundle = JSON.parse(readFileSync(join(root, 'reports', 'sample-audit.pinned.json'), 'utf8'));
  const trust = JSON.parse(readFileSync(join(root, 'reports', 'sample-pinned-trust.pinned.json'), 'utf8'));
  assert.equal(bundle.checkpoint.protected.key_id, '88c14b4920c8d07e879cae1fb52ab1d2');
  assert.equal(bundle.checkpoint.payload.tenant_id, 'acme');
  assert.deepEqual(Object.keys(trust), ['88c14b4920c8d07e879cae1fb52ab1d2']);
});

// ---- supply-chain L4: manifest --verify catches tampering and injected files ----
test('w11-supply L4: manifest --verify detects tampered and unexpected files', t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-mani-')); t.after(() => rmSync(dir, { recursive: true }));
  mkdirSync(join(dir, 'scripts'));
  cpSync(join(root, 'scripts', 'manifest.mjs'), join(dir, 'scripts', 'manifest.mjs'));
  writeFileSync(join(dir, 'a.mjs'), 'export const x = 1;\n');
  execFileSync('git', ['init', '-q'], { cwd: dir });
  execFileSync('git', ['add', '-A'], { cwd: dir });
  execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-qm', 'x'], { cwd: dir });
  execFileSync(process.execPath, [join(dir, 'scripts', 'manifest.mjs')], { cwd: dir });
  // Clean tree verifies.
  const ok = JSON.parse(execFileSync(process.execPath, [join(dir, 'scripts', 'manifest.mjs'), '--verify'], { cwd: dir, encoding: 'utf8' }));
  assert.equal(ok.manifest_fresh, true);
  // A tampered file fails.
  writeFileSync(join(dir, 'a.mjs'), 'export const x = 2;\n');
  assert.throws(() => execFileSync(process.execPath, [join(dir, 'scripts', 'manifest.mjs'), '--verify'], { cwd: dir, stdio: 'pipe' }), /manifest_fresh/);
  // Restore and add an injected extra file — still fails.
  writeFileSync(join(dir, 'a.mjs'), 'export const x = 1;\n');
  writeFileSync(join(dir, 'payload.sh'), 'echo owned\n');
  assert.throws(() => execFileSync(process.execPath, [join(dir, 'scripts', 'manifest.mjs'), '--verify'], { cwd: dir, stdio: 'pipe' }));
});

// ---- timing/side-channel: keystore MAC tamper is refused ----
test('w11-timing: a tampered keystore state fails the MAC check', async t => {
  const h = fixture(t);
  const dir = h.directory;
  h.f.persistVault(); h.close();
  const state = JSON.parse(readFileSync(join(dir, 'keystore.json'), 'utf8'));
  state.keys[0].public_key = generateKey().public_key; // tamper under the MAC
  writeFileSync(join(dir, 'keystore.json'), JSON.stringify(state));
  const { KeyVault } = await import('../src/keystore.mjs');
  const master = JSON.parse(readFileSync(join(dir, 'master.key'), 'utf8')).master_key;
  assert.throws(() => KeyVault.load(join(dir, 'keystore.json'), master), hasCode('INV-503-CONFIG'));
});

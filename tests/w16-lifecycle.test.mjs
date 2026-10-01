// w12-lifecycle regression: the auditor's PoCs against the provenance model.
// Each test replays the attack and asserts the honest outcome at HEAD.
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture, hasCode, stageConstitution } from './helpers.mjs';
import { clone, digest } from '../src/canonical.mjs';

const ROOT = new URL('..', import.meta.url).pathname;

test('w12-lifecycle F2: an unanchored staged row is retired, never promoted', t => {
  const h = fixture(t);
  // A sacrificial capsule must exist BEFORE the forge — with the poisoned
  // staged row present, the getter refuses and no new proposal can mint.
  const victim = h.proposed();
  // Insider row-write: a forged staged policy (zero approvals, zero evidence)
  // already due — exactly the auditor's PoC shape.
  const forged = clone(h.f.policy('acme'));
  forged.version = 2; forged.policy_id = 'constitution:acme:forged'; forged.not_before = h.now() - 1;
  forged.rules['finance.beneficiary.create'].approval_threshold = 0;
  forged.rules['finance.beneficiary.create'].evidence_kinds = [];
  h.f.store.put('acme', 'policy', 'staged', { policy: forged, activate_at: forged.not_before, staged_at: h.now() }, h.now());
  // The getter refuses it pre-promotion…
  assert.throws(() => h.f.policy('acme'), hasCode('INV-409-INTEGRITY'));
  // …and the first transaction after the forge retires the row instead of
  // minting a signed POLICY_ACTIVATED over it (w12-lifecycle F2).
  h.f.cancel(h.p(), victim.capsule.capsule_id);
  assert.equal(h.f.store.get('acme', 'policy', 'staged'), null, 'unanchored staged row retired');
  const superseded = h.f.store.auditPage('acme', { limit: 2000 }).entries.map(e => e.envelope.payload)
    .filter(p => p.type === 'POLICY_SUPERSEDED').at(-1);
  assert.equal(superseded?.metadata?.reason, 'unanchored-staged-row');
  // The tenant stays functional under the honest constitution — a forged
  // row leaves a signed indictment, not a wedge and not a takeover.
  assert.equal(h.f.policy('acme').policy_id.includes('forged'), false);
  const r = h.proposed(); assert.ok(r.capsule.capsule_id);
});

test('w12-lifecycle F2b: a legitimately anchored staged policy still promotes', t => {
  const h = fixture(t);
  const next = clone(h.f.policy('acme')); next.version = 2; next.policy_id = 'constitution:acme:v2'; next.not_before = h.now() - 1;
  stageConstitution(h, next);
  h.f.activateDuePolicies('acme', h.now());
  assert.equal(h.f.policy('acme').version, 2);
});

test('w12-lifecycle F3: a cancelled certificate cannot be un-cancelled by row tamper', t => {
  const h = fixture(t), { certificate } = h.ready();
  const certId = certificate.payload.certificate_id, capsuleId = certificate.payload.capsule_id;
  h.f.cancel(h.p(), capsuleId);
  // Insider row-write: flip the cancelled rows back to spendable. The chain
  // already attested the cancel — the verdict is derived there now.
  const certRow = h.f.store.must('acme', 'certificate', certId), capRow = h.f.store.must('acme', 'capsule', capsuleId);
  certRow.status = 'CERTIFIED'; capRow.status = 'CERTIFIED';
  h.f.store.put('acme', 'certificate', certId, certRow, h.now());
  h.f.store.put('acme', 'capsule', capsuleId, capRow, h.now());
  assert.throws(() => h.f.execute(h.p(), certificate), hasCode('INV-409-REPLAY'));
});

test('w12-lifecycle F3b: a consumed certificate cannot be un-spent by row tamper', t => {
  const h = fixture(t), { certificate } = h.ready();
  const out = h.f.execute(h.p(), certificate);
  assert.equal(out.payload.status, 'VERIFIED');
  const certId = certificate.payload.certificate_id, capsuleId = certificate.payload.capsule_id;
  const certRow = h.f.store.must('acme', 'certificate', certId), capRow = h.f.store.must('acme', 'capsule', capsuleId);
  certRow.consumed = false; certRow.status = 'CERTIFIED'; capRow.status = 'CERTIFIED';
  h.f.store.put('acme', 'certificate', certId, certRow, h.now());
  h.f.store.put('acme', 'capsule', capsuleId, capRow, h.now());
  // The EXECUTION_RESERVED/OUTCOME anchors make the spend chain-derived —
  // resetting mutable rows cannot buy a second dispatch.
  assert.throws(() => h.f.execute(h.p(), certificate), hasCode('INV-409-REPLAY'));
});

test('w12-lifecycle F6: a deleted anchored evidence row revokes, not wedges', t => {
  const h = fixture(t), r = h.proposed();
  h.evidence(r); h.evidence(r, { issuer: 'registry' });
  const attached = h.f._auditIndex('acme').attached.get(r.capsule.capsule_id);
  assert.equal(attached.length, 2);
  // Insider row-delete: the chain still attests membership, the row is gone,
  // and no tombstone row exists either — the graph must not die.
  h.f.store.remove('acme', 'evidence', attached[0]);
  const g = h.f.graph('acme', h.f.store.must('acme', 'capsule', r.capsule.capsule_id));
  const dead = g.items.find(i => i.payload.evidence_id === attached[0]);
  assert.equal(dead.revoked, true, 'missing row counts as revoked');
  assert.equal(dead.issuer.failure_domain, 'deleted');
  // Evaluation is a clean verdict, not an INV-404 — and the revoked item
  // cannot satisfy the ownership requirement, so the honest outcome is
  // denial/escrow, never a silent pass.
  const d = h.f.evaluate(h.p(), r.capsule.capsule_id);
  assert.notEqual(d.decision, 'ALLOW');
});

test('w12-lifecycle F1: an aborted post-due transaction leaves no index wedge', t => {
  const h = fixture(t);
  const next = clone(h.f.policy('acme')); next.version = 2; next.policy_id = 'constitution:acme:v2'; next.not_before = h.now() + 240000;
  stageConstitution(h, next, { activate_at: next.not_before });
  const victim = h.proposed();
  h.advance(240001);
  // First post-due tx aborts after activateDuePolicies writes — the fold
  // must not poison the cached index (the auditor's permanent-wedge PoC).
  assert.throws(() => h.f.certificate(h.p(), victim.capsule.capsule_id), hasCode('INV-412-EVIDENCE'));
  assert.ok(h.f.policy('acme').version === 2, 'committed promotion survives');
  h.proposed(); // propose must work — no AUDIT-TAMPER wedge
  h.f.cancel(h.p(), victim.capsule.capsule_id);
});

// --- supply-chain (w15) ---
const scratch = () => {
  const dir = mkdtempSync(join(tmpdir(), 'rel-repo-'));
  cpSync(join(ROOT, 'src'), join(dir, 'src'), { recursive: true });
  cpSync(join(ROOT, 'scripts'), join(dir, 'scripts'), { recursive: true });
  execFileSync('git', ['init', '-q'], { cwd: dir });
  execFileSync('git', ['add', '-A'], { cwd: dir });
  execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-qm', 'x'], { cwd: dir });
  execFileSync(process.execPath, [join(dir, 'scripts', 'manifest.mjs')], { cwd: dir });
  execFileSync('git', ['add', 'MANIFEST.sha256'], { cwd: dir });
  execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-qm', 'manifest'], { cwd: dir });
  return dir;
};
const run = (args, cwd) => spawnSync(process.execPath, args, { cwd, encoding: 'utf8', env: { ...process.env, IF_TEST_ANCHORS: '1' }, timeout: 30000 });

test('w15-supply F-1: trojaned in-tree verification code cannot launder a tampered release', t => {
  const dir = scratch();
  const keys = mkdtempSync(join(tmpdir(), 'rel-keys-'));
  assert.equal(run(['scripts/release-sign.mjs', '--generate-fixture-key', keys], dir).status, 0);
  const out = JSON.parse(run(['scripts/release-sign.mjs', '--key', `${keys}/release-key.pem`, '--public-key', `${keys}/release-key.pub`, '--out', `${keys}/attestation.json`], dir).stdout.trim().split('\n').at(-1));
  writeFileSync(`${keys}/anchors.json`, JSON.stringify({ [out.key_id]: { public_key: execFileSync('cat', [`${keys}/release-key.pub`], { encoding: 'utf8' }), suite: 'Ed25519' } }));
  // Trojan every in-tree component the OLD verifier executed: the manifest
  // checker always reports fresh, and the crypto module is gutted. The new
  // verifier executes neither — a tampered file still fails provenance.
  writeFileSync(join(dir, 'scripts', 'manifest.mjs'), 'console.log(JSON.stringify({manifest_fresh:true,manifest_files:0}));\n');
  writeFileSync(join(dir, 'src', 'crypto.mjs'), 'export function verifySigned(){ return {}; } export function signed(){} export function generateKey(){} export function encrypt(){} export function decrypt(){} export const ctEqual=()=>true;\n');
  writeFileSync(join(dir, 'src', 'server.mjs'), '// tampered payload line\n');
  const res = run(['scripts/verify-release.mjs', `${keys}/attestation.json`, `${keys}/anchors.json`], dir);
  assert.notEqual(res.status, 0, 'trojaned tree must not verify');
  assert.equal(JSON.parse(res.stderr.trim().split('\n').at(-1)).code, 'INV-412-PROVENANCE');
  rmSync(dir, { recursive: true, force: true });
});

test('w15-supply F-2: trust anchors inside the artifact are refused', t => {
  const dir = scratch();
  const keys = mkdtempSync(join(tmpdir(), 'rel-keys-'));
  assert.equal(run(['scripts/release-sign.mjs', '--generate-fixture-key', keys], dir).status, 0);
  const out = JSON.parse(run(['scripts/release-sign.mjs', '--key', `${keys}/release-key.pem`, '--public-key', `${keys}/release-key.pub`, '--out', `${keys}/attestation.json`], dir).stdout.trim().split('\n').at(-1));
  // Anchors living inside the artifact tree — a self-issued key.
  writeFileSync(join(dir, 'anchors-in-tree.json'), JSON.stringify({ [out.key_id]: { public_key: execFileSync('cat', [`${keys}/release-key.pub`], { encoding: 'utf8' }), suite: 'Ed25519' } }));
  const res = run(['scripts/verify-release.mjs', `${keys}/attestation.json`, 'anchors-in-tree.json'], dir);
  assert.notEqual(res.status, 0);
  assert.equal(JSON.parse(res.stderr.trim().split('\n').at(-1)).code, 'INV-412-ANCHORS');
  // The explicit override exists for the CI fixture roundtrip only — and the
  // untracked in-tree file still fails manifest set-equality.
  const flagged = run(['scripts/verify-release.mjs', `${keys}/attestation.json`, 'anchors-in-tree.json', '--anchors-in-tree'], dir);
  assert.notEqual(flagged.status, 0);
  rmSync(dir, { recursive: true, force: true });
});

test('w15-supply F-7/F-8: a FIFO at a listed path fails instead of hanging; deleted files report', t => {
  const dir = scratch();
  // Non-regular file standing at a manifest-listed path.
  const victim = execFileSync('head', ['-1', 'MANIFEST.sha256'], { cwd: dir, encoding: 'utf8' }).trim().split('  ')[1];
  execFileSync('rm', [victim], { cwd: dir });
  execFileSync('mkfifo', [victim], { cwd: dir });
  const res = run(['scripts/manifest.mjs', '--verify'], dir);
  assert.notEqual(res.status, 0, 'FIFO must fail verification, not hang');
  assert.match(res.stderr, /non-regular/);
  execFileSync('rm', [victim], { cwd: dir });
  // A tracked file deleted without git rm reports in problems, not a stack.
  writeFileSync(join(dir, 'victim2.txt'), 'x');
  execFileSync('git', ['add', 'victim2.txt'], { cwd: dir });
  const res2 = run(['scripts/manifest.mjs'], dir);
  execFileSync('rm', [join(dir, 'victim2.txt')], { cwd: dir });
  const res3 = run(['scripts/manifest.mjs'], dir);
  assert.match(res3.stderr + res3.stdout, /unreadable|missing|problems/);
  rmSync(dir, { recursive: true, force: true });
});

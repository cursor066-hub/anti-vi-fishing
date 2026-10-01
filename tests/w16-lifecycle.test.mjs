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
  // The getter refuses to serve it — it degrades to the honest active
  // constitution rather than wedging every read (w18-fixverify F9), and
  // the sweep retires the forged row loudly on the next transaction…
  assert.equal(h.f.policy('acme').policy_id.includes('forged'), false, 'unanchored staged row is never served');
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

// --- w15-timing ---
import { answerQuery } from '../src/issuerd.mjs';
import { generateKey } from '../src/crypto.mjs';

test('w15-timing F1: capsuleView redacts nested arrays and non-regex secret key names', t => {
  const h = fixture(t);
  const record = h.f.store.must('acme', 'capsule', h.proposed().capsule.capsule_id);
  record.capsule.current_state.material_fields = {
    passphrase: 'hunter2',
    recovery_codes: ['rk-1', 'rk-2'],
    nested: { items: [{ secret: 'inside-array' }, { pin: '0420' }] },
    backup: { seed_phrase: 'alpha bravo charlie', apikey: 'AKIAEXAMPLE', otp_secret: 'JBSWY3DPEHPK3PXP' },
    rows: [{ id: 'row-1', name: 'Ada' }],
    safe_label: 'public descriptor'
  };
  const view = h.f.capsuleView(record).capsule.current_state.material_fields;
  assert.equal(view.passphrase, '«redacted»');
  assert.equal(view.recovery_codes, '«redacted»', 'a secret-named array key redacts whole');
  assert.equal(view.nested.items[0].secret, '«redacted»');
  assert.equal(view.nested.items[1].pin, '«redacted»');
  assert.equal(view.backup.seed_phrase, '«redacted»');
  assert.equal(view.backup.apikey, '«redacted»');
  assert.equal(view.safe_label, 'public descriptor', 'non-secret fields survive');
  assert.equal(view.row_count, 1);
  const text = JSON.stringify(view);
  for (const leak of ['hunter2', 'rk-1', 'inside-array', 'alpha bravo', 'AKIAEXAMPLE']) assert.equal(text.includes(leak), false, `${leak} leaked`);
});

test('w15-timing F2: session-key shredding is decoupled from the reference-scan gate', t => {
  const h = fixture(t);
  // Seed enough perception-session rows to have wedged the old flat-cap
  // path (sessionIds.length === 10000 → truncated → return before shred).
  h.f.store.tx(() => {
    for (let i = 0; i < 10001; i++)
      h.f.store.put('acme', 'perception-session', `s-${i}`, { session_id: `s-${i}`, expires_at: h.now() - 1, _server_private: null }, h.now());
    h.f.store.put('acme', 'perception-session', 'live-key', { session_id: 'live-key', expires_at: h.now() - 1, _server_private: 'PEM MATERIAL' }, h.now());
  });
  const out = h.f.retentionSweep(h.p('security'));
  assert.equal(out.truncated, false);
  assert.equal(out.session_keys_shredded, 1, 'the expired ECDH key was still shredded past 10k cumulative rows');
  assert.equal(out.session_scan_exhausted, true);
  assert.equal(h.f.store.must('acme', 'perception-session', 'live-key')._server_private, null);
});

test('w15-timing F9: a secret.use outcome journals the digest, not the registry material', t => {
  const h = fixture(t);
  const requested = { secret_id: 'secret-erp-1', operation: 'sign', workload_id: 'workload-1' };
  const r = h.proposed('secret.use', requested, { action: { type: 'secret.use', target_resource: 'secret-erp-1', purpose: 'Sign payroll batch' } });
  h.evidence(r, { kind: 'workload_attestation' }); h.evidence(r, { kind: 'workload_attestation', issuer: 'cloud-attestor' }); h.approve(r, 2);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  assert.equal(h.f.execute(h.p(), cert).payload.status, 'VERIFIED');
  const journal = h.f.target.outcome('acme', cert.payload.certificate_id);
  assert.equal(journal.observed_state.withheld, true, 'journal carries the digest projection, not the row');
  assert.equal(journal.observed_state.material_digest, journal.observed_state_digest);
  assert.equal(JSON.stringify(journal.observed_state).includes('api_key'), false, 'registry material stays out of the durable journal');
});

test('w15-timing F11: issuerd content/request digests are keyed, not bare sha256 oracles', () => {
  const issuer = {
    issuer: 'custom', tenant: 'acme', version: '1.0.0', channel: 'authoritative', key: generateKey(),
    kinds: { ownership: { lookup: 'acct:${claims.account}', confidence: 90, expect: {} } },
    records: { 'acct:a-1': { account_id: 'a-1', credential: 'p'.repeat(8) } }
  };
  const env = answerQuery(issuer, { tenant_id: 'acme', capsule_digest: 'a'.repeat(64), kind: 'ownership', subject_id: 'x', claims: { account: 'a-1' } }, 1000);
  assert.match(env.payload.content_digest, /^[a-f0-9]{64}$/, 'hex shape preserved for schema compat');
  assert.notEqual(env.payload.content_digest, digest({ issuer: 'custom', key: 'acct:a-1', record: issuer.records['acct:a-1'] }), 'no longer recomputable without the issuer key');
  const miss = answerQuery(issuer, { tenant_id: 'acme', capsule_digest: 'a'.repeat(64), kind: 'ownership', subject_id: 'x', claims: { account: 'ghost' } }, 1000);
  assert.notEqual(miss.payload.content_digest, digest({ issuer: 'custom', key: 'acct:ghost', record: null }), 'miss path keyed too');
});

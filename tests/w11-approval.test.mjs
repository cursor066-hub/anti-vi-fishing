// Wave-11 approval/ceremony/quorum audit regressions: quarantine reaches
// stored consent, revoked custodians lose share-standing, dealer binding,
// key-signed domain attribution, constitutional floors under root key
// actions, caller-device health on privileged reads, and ceremony lifecycle
// hygiene (born-alive, abort path).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { fixture, hasCode, setTenant } from './helpers.mjs';
import { signAcknowledgement } from '../src/ceremony.mjs';
import { generateKey } from '../src/crypto.mjs';
import { validatePolicy } from '../src/policy.mjs';
import { clone } from '../src/canonical.mjs';
import { answerQuery, loadIssuers, writeIssuer } from '../src/issuerd.mjs';
import { applyTransforms } from '../src/datagate.mjs';
import { KeyVault } from '../src/keystore.mjs';
import { bootstrap, loadConfiguration } from '../src/bootstrap.mjs';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CUSTODIANS = ['custodian-1', 'custodian-2', 'custodian-3'];

function committedCeremony(h, id = `cer-${randomUUID().slice(0, 8)}`, custodians = CUSTODIANS, threshold = 2) {
  const c = h.f.createCeremony(h.p('security'), { ceremony_id: id, purpose: 'root recovery', threshold, custodians, valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  return { ceremony: c, split: h.f.splitCeremonySecret(h.p('security'), c.ceremony_id, randomBytes(32).toString('base64url')) };
}
function ack(h, ceremony, custodian) {
  const current = h.f.store.must('acme', 'ceremony', ceremony.ceremony_id);
  h.f.acknowledgeCeremony(h.p(custodian), signAcknowledgement(current, custodian, h.setup.custodianKeys.acme[custodian], h.now()));
}

// w11-approval F1: a quarantined approver device must withdraw the approval
// that identity already lodged — stored consent dies with the device.
test('w11 F1: quarantining an approver device withdraws its stored approval', t => {
  const h = fixture(t);
  const r = h.proposed();
  h.evidence(r); h.evidence(r, { issuer: 'registry' });
  h.approve(r, ['custodian-1', 'custodian-2']);
  assert.equal(h.f.evaluate(h.p(), r.capsule.capsule_id).decision, 'ALLOW');
  h.f.revoke(h.p('security'), { kind: 'device', id: 'custodian-1-device', reason: 'device compromised' });
  const decision = h.f.evaluate(h.p(), r.capsule.capsule_id);
  assert.equal(decision.decision, 'ESCROW', 'one live approval remains — quorum lost');
  assert.throws(() => h.f.certificate(h.p(), r.capsule.capsule_id), hasCode('INV-412-EVIDENCE'));
  // Submission-side still refuses with the quarantine code, not the generic
  // signer-unavailable.
  assert.throws(() => h.f.approvalChallenge(h.p('custodian-1'), r.capsule.capsule_id), hasCode('INV-403-QUARANTINE'));
});

test('w11 F1b: quarantining a custodian device withdraws its ceremony consent', t => {
  const h = fixture(t);
  const { ceremony } = committedCeremony(h);
  ack(h, ceremony, 'custodian-1'); ack(h, ceremony, 'custodian-2');
  assert.equal(h.f.custodianQuorum('acme', h.f.store.must('acme', 'ceremony', ceremony.ceremony_id)).live, 2);
  h.f.revoke(h.p('security'), { kind: 'device', id: 'custodian-1-device', reason: 'device compromised' });
  assert.equal(h.f.custodianQuorum('acme', h.f.store.must('acme', 'ceremony', ceremony.ceremony_id)).live, 1);
});

// w11-approval F2: a share whose custodian was revoked after acking must not
// satisfy reconstruction — revocation revokes.
test('w11 F2: a revoked custodian share cannot reconstruct', t => {
  const h = fixture(t);
  const { ceremony, split } = committedCeremony(h);
  ack(h, ceremony, 'custodian-1'); ack(h, ceremony, 'custodian-2'); ack(h, ceremony, 'custodian-3');
  const key = Object.entries(h.f.identities('acme')).find(([, v]) => v.subject_id === 'custodian-1')[0];
  h.f.revoke(h.p('security'), { kind: 'key', id: key, reason: 'share store compromised' });
  const live = h.f.custodianQuorum('acme', h.f.store.must('acme', 'ceremony', ceremony.ceremony_id));
  assert.equal(live.live, 2, 'custodian-2/3 still hold quorum');
  h.advance(120001);
  assert.throws(
    () => h.f.reconstructCeremony(h.p('security'), ceremony.ceremony_id, [split.shares[0].share, split.shares[1].share]),
    hasCode('INV-403-ROLE'), 'custodian-1 share cannot stand in for a revoked member');
  const rec = h.f.reconstructCeremony(h.p('security'), ceremony.ceremony_id, [split.shares[1].share, split.shares[2].share]);
  assert.deepEqual(rec.artifact.quorum, [2, 3]);
});

// w11-approval F3: dealing is bound — a non-member custodian cannot burn a
// ceremony and pocket every share.
test('w11 F3: a non-member custodian cannot deal shares for the ceremony', t => {
  const h = fixture(t);
  h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-deal', purpose: 'root recovery', threshold: 2, custodians: CUSTODIANS, valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  assert.throws(() => h.f.splitCeremonySecret(h.p('custodian-4'), 'cer-deal', randomBytes(32).toString('base64url')), hasCode('INV-403-ROLE'));
  // A member custodian may deal (witnessed ceremony operation).
  const split = h.f.splitCeremonySecret(h.p('custodian-1'), 'cer-deal', randomBytes(32).toString('base64url'));
  assert.equal(split.shares.length, 3);
});

// w11-approval F4: quorum domains attribute to the signing identity, not the
// subject's last-registered one.
test('w11 F4: quorum counts the signing key domain, not a sibling identity', t => {
  const h = fixture(t);
  const { ceremony, split } = committedCeremony(h, 'cer-dom', ['custodian-1', 'custodian-2'], 2);
  const ids = h.f.tenant('acme').identities;
  const [c1key] = Object.entries(ids).find(([, v]) => v.subject_id === 'custodian-1');
  const [c2key] = Object.entries(ids).find(([, v]) => v.subject_id === 'custodian-2');
  // After creation (which verified distinct domains), both signing keys end
  // up in acme-SHARED and custodian-1 picks up a second registered identity
  // carrying a distinct domain label — e.g. mid-rollover. Frozen config:
  // legitimate edits take the sanctioned clone-and-swap path.
  const key = generateKey();
  setTenant(h, 'acme', tn => {
    tn.identities[c1key].failure_domain = 'acme-SHARED';
    tn.identities[c2key].failure_domain = 'acme-SHARED';
    tn.identities[key.key_id] = { public_key: key.public_key, subject_id: 'custodian-1', identity_class: 'workforce', roles: ['custodian'], device_id: 'custodian-1-device', failure_domain: 'acme-DOMAIN-B', hardware_backed: false, health_expires_at: h.now() + 86400000, grants: { resources: [], actions: [], destinations: [], columns: [], row_ids: [] } };
  });
  ack(h, ceremony, 'custodian-1'); // signed by c1key — the SHARED domain
  ack(h, ceremony, 'custodian-2'); // also SHARED
  const q = h.f.custodianQuorum('acme', h.f.store.must('acme', 'ceremony', ceremony.ceremony_id));
  assert.equal(q.live, 1, 'both signatures originate from one failure domain — the sibling identity cannot inflate independence');
  h.advance(120001);
  assert.throws(() => h.f.reconstructCeremony(h.p('security'), ceremony.ceremony_id, [split.shares[0].share, split.shares[1].share]), hasCode('INV-409-STATE'));
});

// w11-approval F5: the constitution pins floors under root key actions.
test('w11 F5: key.rotate and key.ceremony cannot lose their custodian floor', t => {
  const h = fixture(t);
  const policy = h.clone(h.f.policy('acme'));
  policy.rules['key.rotate'].approval_threshold = 1;
  assert.throws(() => validatePolicy(policy), hasCode('INV-400-SCHEMA'));
  const p2 = h.clone(h.f.policy('acme'));
  p2.rules['key.rotate'].approval_role = 'approver';
  assert.throws(() => validatePolicy(p2), hasCode('INV-451-POLICY'));
  const p3 = h.clone(h.f.policy('acme'));
  p3.rules['key.rotate'].cooldown_ms = 0;
  assert.throws(() => validatePolicy(p3), hasCode('INV-400-SCHEMA'));
  const p4 = h.clone(h.f.policy('acme'));
  p4.rules['key.ceremony'].cooldown_ms = 0;
  assert.throws(() => validatePolicy(p4), hasCode('INV-400-SCHEMA'));
  // The ceremony delay floor follows the pinned rule, not a zeroable policy
  // field: a zero-delay ceremony is now impossible to declare.
  assert.throws(() => h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-zero', purpose: 'x', threshold: 2, custodians: CUSTODIANS, valid_until: h.now() + 3600000, min_delay_ms: 0 }), hasCode('INV-400-SCHEMA'));
});

// w11-approval F6: privileged plane operations check the caller's own device.
test('w11 F6: a quarantined caller cannot evaluate, certify or deal', t => {
  const h = fixture(t);
  const r = h.proposed();
  h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r, 2);
  h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-deal2', purpose: 'root recovery', threshold: 2, custodians: CUSTODIANS, valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  h.f.revoke(h.p('security'), { kind: 'device', id: 'policy-admin-device', reason: 'lost' });
  assert.throws(() => h.f.evaluate(h.p('policy-admin'), r.capsule.capsule_id), hasCode('INV-403-QUARANTINE'));
  assert.throws(() => h.f.certificate(h.p('policy-admin'), r.capsule.capsule_id), hasCode('INV-403-QUARANTINE'));
  h.f.revoke(h.p('security'), { kind: 'device', id: 'custodian-1-device', reason: 'lost' });
  assert.throws(() => h.f.splitCeremonySecret(h.p('custodian-1'), 'cer-deal2', randomBytes(32).toString('base64url')), hasCode('INV-403-QUARANTINE'));
});

// w11-approval F7: ceremony lifecycle hygiene — born-alive, abortable, no
// consent past validity, artifact names only the consumed shares.
test('w11 F7a: born-expired and ghost-custodian ceremonies are refused', t => {
  const h = fixture(t);
  assert.throws(() => h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-dead', purpose: 'x', threshold: 2, custodians: CUSTODIANS, valid_until: h.now() - 1, min_delay_ms: 120000 }), hasCode('INV-400-SCHEMA'));
  assert.throws(() => h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-ghost', purpose: 'x', threshold: 2, custodians: ['custodian-1', 'ghost-1'], valid_until: h.now() + 3600000, min_delay_ms: 120000 }), hasCode('INV-404-NOT-FOUND'));
});

test('w11 F7b: abort retires a live ceremony — no consent, no shares, no reconstruct', t => {
  const h = fixture(t);
  const { ceremony, split } = committedCeremony(h, 'cer-abort');
  assert.throws(() => h.f.abortCeremony(h.p('custodian-4'), 'cer-abort'), hasCode('INV-403-ROLE'), 'non-member cannot abort');
  const report = h.f.abortCeremony(h.p('custodian-1'), 'cer-abort');
  assert.equal(report.status, 'aborted');
  assert.throws(() => ack(h, ceremony, 'custodian-2'), hasCode('INV-409-STATE'));
  h.advance(120001);
  assert.throws(() => h.f.reconstructCeremony(h.p('security'), 'cer-abort', [split.shares[0].share, split.shares[1].share]), hasCode('INV-409-STATE'));
  const types = h.f.store.auditPage('acme', { after: 0, limit: 1000 }).entries.map(e => e.envelope.payload.type);
  assert.ok(types.includes('CEREMONY_ABORTED'), 'the abort is on the signed ledger');
});

test('w11 F7c: consent on a lapsed ceremony is refused', t => {
  const h = fixture(t);
  const { ceremony } = committedCeremony(h, 'cer-lapse');
  h.set(h.now() + 3600001);
  assert.throws(() => ack(h, ceremony, 'custodian-1'), hasCode('INV-409-STATE'));
});

test('w11 F7d: the artifact quorum lists only the consumed shares', t => {
  const h = fixture(t);
  const { ceremony, split } = committedCeremony(h, 'cer-quorum-list', CUSTODIANS, 2);
  ack(h, ceremony, 'custodian-1'); ack(h, ceremony, 'custodian-2'); ack(h, ceremony, 'custodian-3');
  h.advance(120001);
  const rec = h.f.reconstructCeremony(h.p('security'), ceremony.ceremony_id, [split.shares[0].share, split.shares[1].share, split.shares[2].share]);
  assert.equal(rec.artifact.quorum.length, 2, 'the third presented share is not in the attested quorum');
});

// w11-fixverify residuals: the honest low-severity closes.
test('w11-fixverify R1: an unbound claims.subject_id is never echoed under the signature', t => {
  const issuer = {
    issuer: 'custom', tenant: 'acme', version: '1.0.0', channel: 'authoritative', key: generateKey(),
    kinds: { ownership: { lookup: 'acct:${claims.account}', confidence: 90, expect: {} } },
    records: { 'acct:a-1': { account_id: 'a-1', status: 'active' } }
  };
  const env = answerQuery(issuer, { tenant_id: 'acme', capsule_digest: 'a'.repeat(64), kind: 'ownership', subject_id: 'x', claims: { account: 'a-1', subject_id: 'victim' } }, 1000);
  assert.equal(env.payload.claim, 'supports');
  assert.equal(env.payload.claims.subject_id, undefined, 'the lookup never bound subject_id — the caller cannot stamp a victim identity');
  // Same kind with an expect rule that does verify the claim echoes it.
  const bound = { ...issuer, kinds: { recovery: { lookup: 'case:${claims.case_id}', confidence: 90, expect: { subject: '${claims.subject_id}' } } }, records: { 'case:c-1': { subject: 'operator' } } };
  const env2 = answerQuery(bound, { tenant_id: 'acme', capsule_digest: 'a'.repeat(64), kind: 'recovery', subject_id: 'x', claims: { case_id: 'c-1', subject_id: 'operator' } }, 1000);
  assert.equal(env2.payload.claims.subject_id, 'operator', 'expect-verified subjects still echo');
});

test('w11-fixverify R2: a proto-named transform op is a schema error, not silent wrong output', () => {
  const rows = [{ id: 'row-1', secret: 'abc' }];
  assert.throws(() => applyTransforms(rows, { secret: { op: 'hasOwnProperty' } }, {}), hasCode('INV-400-SCHEMA'));
  assert.deepEqual(applyTransforms(rows, { secret: { op: 'mask' } }, {})[0].secret, '••••bc');
});

test('w11-fixverify R3: a key-inconsistent issuer spec refuses to boot', t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-'));
  t.after(() => rmSync(dir, { recursive: true }));
  const key = generateKey(), other = generateKey();
  writeIssuer(dir, { issuer: 'bank', version: '1.0.0', channel: 'authoritative', key, kinds: {}, records: {} });
  // Write a spec whose private key does not derive its public half.
  writeIssuer(dir, { issuer: 'evil', version: '1.0.0', channel: 'authoritative', key: { ...key, private_key: other.private_key }, kinds: {}, records: {} });
  assert.throws(() => loadIssuers(dir), hasCode('INV-400-SCHEMA'));
});

test('w11-fixverify R4: a corrupt master.key is INV-503-CONFIG, not a raw parse error', t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-vault-'));
  t.after(() => rmSync(dir, { recursive: true }));
  writeFileSync(join(dir, 'keystore.json'), '{}'); writeFileSync(join(dir, 'master.key'), '{not json');
  assert.throws(() => KeyVault.open(dir), hasCode('INV-503-CONFIG'));
});

test('w11-fixverify R5: a dangling deployment symlink gets the actionable refusal', t => {
  const parent = mkdtempSync(join(tmpdir(), 'if-boot-'));
  t.after(() => rmSync(parent, { recursive: true }));
  const target = join(parent, 'deployment');
  symlinkSync(join(parent, 'gone'), target);
  assert.throws(() => bootstrap(target, ['acme']), hasCode('INV-409-CONFLICT'));
});

test('w11-fixverify R6: non-object tenant rows refuse at config load', t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-cfg-'));
  t.after(() => rmSync(dir, { recursive: true }));
  writeFileSync(join(dir, 'config.json'), JSON.stringify({ tenants: { acme: 12345 } }));
  assert.throws(() => loadConfiguration(dir), hasCode('INV-503-CONFIG'));
  writeFileSync(join(dir, 'config.json'), JSON.stringify({}));
  assert.throws(() => loadConfiguration(dir), hasCode('INV-503-CONFIG'));
});

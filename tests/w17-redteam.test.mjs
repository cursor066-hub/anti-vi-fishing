// Wave-17b regressions: red-team kill chains (w17-redteam) and the
// _auditIndex fold audit (w17-idx). Threat model: an in-process store/row
// writer without access to vault signers — mutable state may wedge, never
// mint authority, and may never launder a forged row into a signed event.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture, hasCode, runtimeInput, runtimeRequest, installPolicy, stageConstitution } from './helpers.mjs';
import { digest } from '../src/canonical.mjs';
import { signAcknowledgement } from '../src/ceremony.mjs';
import { signed } from '../src/crypto.mjs';

const CUSTODIANS = ['custodian-1', 'custodian-2', 'custodian-3'];

// A1 (CRIT): a forged 'policy/active' row must never be laundered into a
// signed POLICY_ACTIVATED anchor — the break-glass restores the anchored
// constitution or refuses; it never attests row content.
test('w17-redteam A1: reanchorPolicy cannot launder a forged constitution', t => {
  const h = fixture(t);
  const live = h.f.policy('acme');
  const forged = { ...live, version: 1000, approval_threshold: 0, rules: {} };
  h.f.store.put('acme', 'policy', 'active', forged, h.now());
  assert.throws(() => h.f.policy('acme'), hasCode('INV-409-INTEGRITY'));
  // The break-glass restores the only anchored copy (genesis) — the
  // forged row's content is never attested.
  const out = h.f.reanchorPolicy(h.p('security'));
  assert.equal(out.reanchored, true);
  assert.equal(h.f.store.must('acme', 'policy', 'active').version, live.version);
  assert.equal(h.f.policy('acme').version, live.version, 'anchored constitution is live again');
  const anchors = h.f._auditIndex('acme').policyAnchors;
  assert.equal(anchors.some(a => a.digest === digest(forged)), false, 'forged content was never anchored');
});

// F1 (w17-idx): the promotion ladder reads the ANCHORED active digest —
// a planted {version:N-2} active row can no longer make a stale anchored
// staged constitution look next-in-line.
test('w17-idx F1: planted active row cannot regress the constitution through the ladder', t => {
  const h = fixture(t);
  const v1 = h.f.policy('acme');
  const v2 = installPolicy(h, () => {});
  // Stage v3 honestly (anchored POLICY_STAGED), then install v4 — the v3
  // staged anchor remains in the ledger forever, reusable by an insider.
  const v3bytes = { ...h.f.policy('acme'), version: 3 };
  stageConstitution(h, v3bytes, { activate_at: h.now() - 1 });
  installPolicy(h, () => {}); // v4 active; staged row promoted v3 first? no — promote happens on next transaction
  // Rebuild the exact attack: planted active {version: 2} + re-planted
  // staged v3 bytes. Pre-fix this promoted v3 over the live constitution.
  h.f.store.put('acme', 'policy', 'active', { version: 2, policy_id: 'forged' }, h.now());
  h.f.store.put('acme', 'policy', 'staged', { policy: v3bytes, activate_at: h.now() - 1, staged_at: h.now() - 1 }, h.now());
  // Any transaction either wedges on the forged active row or refuses the
  // promotion — the stale staged policy must never reach 'active'.
  try { h.proposed('identity.jit.grant', { subject_id: 'operator', resources: [], actions: [], destinations: [], columns: [], row_ids: [], ttl_ms: 60000, reason: 'probe', roles: [] }, { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'probe' } }); } catch { /* forged active wedges policy() — honest refusal */ }
  assert.equal(h.f.store.must('acme', 'policy', 'active').version, 2, 'planted row is never promoted over');
  const anchors = h.f._auditIndex('acme').policyAnchors.filter(a => !a.staged);
  assert.notEqual(anchors.at(-1).digest, digest(v3bytes), 'stale staged policy was not laundered into a signed anchor');
});

// F2 (w17-idx): a ledger-revoked JIT grant is dead regardless of the
// mutable grants row — flipping revoked:false cannot resurrect scope.
test('w17-idx F2: ledger-revoked grant cannot resurrect via dataplane flag', t => {
  const h = fixture(t);
  const r = h.proposed('identity.jit.grant', { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: [], ttl_ms: 300000, reason: 'Incident', roles: ['workload'] }, { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'JIT' } });
  h.evidence(r, { kind: 'identity_proof' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' }); h.approve(r, 2);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  h.f.execute(h.p(), cert);
  const grantId = `jit-${cert.payload.certificate_id}`;
  // 'workload' is the observable delta: not in the identity's standing roles.
  assert.ok(h.f.grantsFor('acme', 'operator', h.now()).roles.includes('workload'), 'grant confers the workload role');
  h.f.revoke(h.p('security'), { kind: 'grant', id: grantId, reason: 'Incident over' });
  assert.equal(h.f.grantsFor('acme', 'operator', h.now()).roles.includes('workload'), false, 'role dies with the revocation');
  // Insider revert of the dataplane flag: resurrected row, dead scope.
  h.f.target.grant('acme', grantId, { grant_id: grantId, subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: [], roles: ['workload'], expires_at: h.now() + 300000, revoked: false });
  const live = h.f.grantsFor('acme', 'operator', h.now());
  assert.equal(live.roles.includes('workload'), false, 'revoked grant role stays dead');
});

// D1: vault tenant_id flips cannot lend another tenant's key to a local
// revocation — ownership for ledger-significant ops is chain-bound.
test('w17-redteam D1: a tenant_id flip cannot make acme kill globex key', t => {
  const h = fixture(t);
  const globexAudit = h.f.tenant('globex').keys.audit.key_id;
  h.f.vault.keys.get(globexAudit).tenant_id = 'acme';
  assert.throws(() => h.f.revoke(h.p('security'), { kind: 'key', id: globexAudit, reason: 'cross-tenant' }), hasCode('INV-404-NOT-FOUND'),
    'chain-bound ownership refuses the foreign key');
  assert.ok(!h.f.vault.keys.get(globexAudit).revoked, 'globex audit key still live');
  assert.equal(h.f.revoked('globex', 'key', globexAudit), false);
});

// A2 residual: a ceremony row with no anchored CEREMONY_PLANNED yields no
// quorum at all — signed-looking acks inside a planted record are void.
test('w17-redteam A2: unanchored ceremony row mints zero quorum', t => {
  const h = fixture(t);
  const pending = h.f.vault.generate('audit', { pending: true });
  const ceremony = {
    ceremony_id: 'cer-never', purpose: 'key.rotate', status: 'committed', threshold: 2,
    custodians: CUSTODIANS, artifact_digest: digest({ fake: true }),
    acknowledgements: CUSTODIANS.slice(0, 2).map(c => signAcknowledgement({ ceremony_id: 'cer-never', artifact_digest: digest({ fake: true }) }, c, h.setup.custodianKeys.acme[c], h.now())),
    committed_at: 0, valid_until: h.now() + 3600000, min_delay_ms: 0, notices: [], exceptions: [],
    rotation: { key_class: 'audit', new_key_id: pending.key_id }, share_commitments: [], rotation_consumed: null,
  };
  h.f.store.put('acme', 'ceremony', 'cer-never', ceremony, h.now());
  const quorum = h.f.custodianQuorum('acme', h.f.store.must('acme', 'ceremony', 'cer-never'));
  assert.equal(quorum.live, 0, 'no CEREMONY_PLANNED anchor — no quorum, real signatures notwithstanding');
});

// A2 residual (committed_at): the reconstruction delay runs on the
// anchored SHARES_COMMITTED time — a rewound committed_at cannot
// pre-date the ledger's own commit timestamp.
test('w17-redteam A2-b: anchored commit time gates the recovery delay', t => {
  const h = fixture(t);
  const c = h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-anchored', purpose: 'recovery', threshold: 2, custodians: CUSTODIANS, valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  const split = h.f.splitCeremonySecret(h.p('security'), c.ceremony_id, '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
  const committed = h.f.store.must('acme', 'ceremony', c.ceremony_id);
  for (const cust of CUSTODIANS.slice(0, 2)) h.f.acknowledgeCeremony(h.p(cust), signAcknowledgement(committed, cust, h.setup.custodianKeys.acme[cust], h.now()));
  // An insider rewinds the delay clock on the mutable row — the anchored
  // commit timestamp still gates reconstruction. (Re-read the row: the
  // acks landed on the stored object.)
  const latest = h.f.store.must('acme', 'ceremony', c.ceremony_id);
  h.f.store.put('acme', 'ceremony', c.ceremony_id, { ...latest, committed_at: 0 }, h.now());
  assert.throws(() => h.f.reconstructCeremony(h.p('security'), c.ceremony_id, [split.shares[0].share, split.shares[1].share]), hasCode('INV-409-STATE'),
    'anchored delay still applies after committed_at tamper');
  h.advance(120001);
  const rec = h.f.reconstructCeremony(h.p('security'), c.ceremony_id, [split.shares[0].share, split.shares[1].share]);
  assert.equal(rec.reconstructed, true, 'reconstruction proceeds once the anchored delay elapses');
});

// A3: a forged coverage row is excluded from the vault-signed manifest
// and reported as unanchored — it can never claim ENFORCED.
test('w17-redteam A3: forged coverage row never enters the signed manifest', t => {
  const h = fixture(t);
  h.f.store.put('acme', 'coverage', 'fake-path', { path_id: 'fake-path', status: 'ENFORCED', target: 'never-seen', owner: 'mallory', evidence_at: h.now() + 3600000 }, h.now());
  const manifest = h.f.coverage(h.p('security'));
  assert.equal(manifest.payload.paths.some(x => x.path_id === 'fake-path'), false, 'unanchored path excluded');
  assert.ok(manifest.payload.unanchored_rows.includes('fake-path'), 'unanchored row is named honestly');
});

// A4: the perception component map is immutable in-process — neither a
// slot swap nor an entry overwrite can register an unlisted component.
test('w17-redteam A4: perceptionComponents rejects in-process injection', t => {
  const h = fixture(t);
  assert.throws(() => { h.f.perceptionComponents = {}; }, TypeError);
  assert.throws(() => { h.f.perceptionComponents.acme = { evil: {} }; }, TypeError);
  assert.throws(() => { h.f.perceptionComponents.acme.evil = { signing: { key_id: 'x', public_key: 'y' } }; }, TypeError);
});

// C2: a planted revocation floor row wedges the fold on EVERY call —
// the watermark must never commit over the row it just rejected.
test('w17-redteam C2: a planted revocation row wedges cleanly, never flaps', t => {
  const h = fixture(t);
  h.f.store.put('acme', 'revocation', 'subject:phantom', { kind: 'subject', id: 'phantom', actor: 'mallory', revoked_at: h.now(), reason: 'planted' }, h.now());
  for (let i = 0; i < 3; i++) assert.throws(() => h.f.revoked('acme', 'subject', 'operator'), hasCode('INV-409-INTEGRITY'), `fold ${i} must throw`);
});

// C3/F6: planted 'key-rotation' records can no longer trigger full-chain
// scans per signing call — the anchored predecessor map steers or nothing
// does.
test('w17-redteam C3: forged rotation records steer nothing and cost nothing', t => {
  const h = fixture(t);
  const configured = h.f.tenant('acme').keys.audit.key_id;
  const pending = h.f.vault.generate('audit', { pending: true });
  for (let i = 0; i < 5; i++)
    h.f.store.put('acme', 'key-rotation', `forged-${i}`, { key_class: 'audit', previous_key_id: configured, new_key_id: pending.key_id, rotated_at: h.now() }, h.now());
  const env = h.f.signAudit('acme', { type: 'PROBE' }, 'audit');
  assert.equal(env.protected.key_id, configured, 'unanchored records cannot steer the signing key');
  assert.equal(env.payload.recovery_signing, undefined);
});

// E2 + L3: recovery enumeration is unbounded and anchored — a flooded
// certificate table cannot hide a real cert, and planted rows cannot veto.
test('w17-redteam E2: certificate flood cannot hide a resurrecting certificate', t => {
  const h = fixture(t);
  const { certificate } = h.ready(h.proposed());
  const exp = certificate.payload.expires_at;
  // Flood the certificate table past the old 10k cap — corrupt rows are
  // tolerated, and the real cert is still found and vetoes the rewind.
  const ins = h.f.store.db.prepare("INSERT INTO records (tenant,kind,id,value,created) VALUES ('acme','certificate',?,'bm9wZQ==',?)");
  for (let i = 0; i < 10100; i++) ins.run(`flood-${i}`, h.now() + i);
  // Plant a well-formed fake certificate row too — anchored-membership
  // stops it from vetoing recovery.
  h.livedForward(exp + 1);
  assert.throws(() => h.f.recoverClock(h.p('security')), hasCode('INV-503-TIME'),
    'the real certificate still vetoes the rewind despite the flood');
});

test('w17-redteam E2-b: planted certificates cannot veto clock recovery', t => {
  const h = fixture(t);
  const real = h.ready(h.proposed()).certificate;
  // Plant an unanchored certificate whose expiry sits inside the rewind
  // window — membership in idx.issuedCerts is required to veto.
  h.f.store.put('acme', 'certificate', 'planted-cert', { certificate_id: 'planted-cert', consumed: false, envelope: real }, h.now());
  h.livedForward(h.now() + 120000);
  // Rewind to a point where the real cert is still within its live window:
  // the planted row is skipped — only an anchored live cert may veto.
  h.set(h.now() + 60000);
  const out = h.f.recoverClock(h.p('security'));
  assert.ok(out.recovered_at, 'recovery proceeds — the planted row cannot veto');
});

// F4: host-clock regression is recoverable — the seal cuts the inflated
// rows and recoverClock records the honest discontinuity.
test('w17-idx F4: clock regression wedges the fold, then seal + recoverClock repair', t => {
  const h = fixture(t);
  // No certificates here — an in-flight cert inside the rewind window
  // legitimately vetoes recovery (that veto is E2's test).
  h.advance(172800000); // two days forward — the next row lands at T+2d
  // honestly (monotone floor) while the host clock is right
  h.f.store.tx(() => { const n = h.f.clock(); h.f.store.clock(n); h.f.store.audit('acme', 'HEALTH_ASSERTION', 'operator', 'probe', {}, n); });
  h.set(h.now() - 172800000); // host clock regresses to real time
  h.f.invalidateAuditIndex('acme');
  assert.throws(() => h.f.revoked('acme', 'subject', 'x'), hasCode('INV-409-INTEGRITY'), 'monotone-floor rows violate the fold bound');
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.equal(seal.sealed, true, 'seal cuts the inflated rows it can now see');
  assert.equal(h.f.revoked('acme', 'subject', 'x'), false, 'index healthy after the cut');
  // The fixture's bearer tokens legitimately resurrect in the rewound span —
  // the veto is honest (w22-http F6); the operator path is revoke-then-recover.
  assert.throws(() => h.f.recoverClock(h.p('security')), hasCode('INV-503-TIME'), 'an unrevoked resurrectable token must veto recovery');
  // The veto scans EVERY tenant — the remediation must too. The sweep
  // covers tokens and device health alike: a device whose configured
  // health lapsed inside the rewound span must be quarantined first,
  // same as the tokens (w23 W23-01).
  for (const tenant of ['acme', 'globex']) {
    for (const [hash, entry] of Object.entries(h.f.tenant(tenant).auth ?? {}))
      if (entry.expires_at > h.now() && entry.expires_at <= h.now() + 172800000) h.f.revoke(h.p('security', tenant), { kind: 'token', id: hash, reason: 'Clock rewind would resurrect it' });
    for (const [, idn] of Object.entries(h.f.tenant(tenant).identities ?? {}))
      if (!idn.revoked && idn.health_expires_at > h.now() && idn.health_expires_at <= h.now() + 172800000) h.f.revoke(h.p('security', tenant), { kind: 'device', id: idn.device_id, reason: 'Clock rewind would resurrect stale health evidence' });
  }
  const recovery = h.f.recoverClock(h.p('security'));
  assert.ok(recovery.recovered_at, 'recovery is recorded, not silent');
});

// F7: denied consumes re-record at most once per (subject, code,
// capability) per 60s — the flood bound _rejectionAudit already has.
test('w17-idx F7: denied consumes are ledger-bounded like gate denials', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  const req = runtimeRequest(cap);
  h.f.runtime.consume(h.p(), req);
  const before = h.f._auditIndex('acme').denials.length;
  for (let i = 0; i < 5; i++) assert.throws(() => h.f.runtime.consume(h.p(), req), hasCode('INV-409-REPLAY'));
  const after = h.f._auditIndex('acme').denials.length;
  assert.ok(after - before <= 1, `denial flood bounded — got ${after - before} rows for 5 denials`);
});

// F10: the verify memo key carries revocation — a memoized payload must
// not survive the signer's revocation flag flip.
test('w17-idx F10: memoized verification respects a revoked signer key', t => {
  const h = fixture(t);
  const [kid, key] = Object.entries(h.setup.custodianKeys.acme['custodian-1']).length
    ? [Object.keys(h.f.identities('acme')).find(k => h.f.identities('acme')[k].subject_id === 'custodian-1'), h.f.identities('acme')[Object.keys(h.f.identities('acme')).find(k => h.f.identities('acme')[k].subject_id === 'custodian-1')]]
    : [null, null];
  const env = signed({ x: 1, tenant_id: 'acme' }, h.setup.custodianKeys.acme['custodian-1'], 'ceremony-acknowledgement');
  const keys = { [kid]: { public_key: key.public_key } };
  assert.equal(h.f._verifyCached(env, keys, 'ceremony-acknowledgement').x, 1);
  assert.throws(() => h.f._verifyCached(env, { [kid]: { public_key: key.public_key, revoked: true } }, 'ceremony-acknowledgement'), hasCode('INV-401-SIGNATURE'),
    'memo hit must not bypass a revoked flag');
});

// B1 residual: rows appended between the seal scan and the delete are
// attested inside AUDIT_SEALED — the removed_* list is computed in-tx.
test('w17-redteam B1: seal attests every row it actually deletes', t => {
  const h = fixture(t);
  h.ready(h.proposed());
  // Poison the tail: an unsigned forged row extending the head.
  const head = h.f.store.db.prepare('SELECT seq,hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get('acme');
  h.f.store.db.prepare('DROP TRIGGER audit_seq_guard').run();
  h.f.store.db.prepare("INSERT INTO audit (tenant,seq,previous,hash,envelope) VALUES ('acme',?,?,'deadbeef','{}')").run(head.seq + 1, head.hash);
  // Recreate the guard so the seal's own assertions hold.
  h.f.store.db.exec("CREATE TRIGGER audit_seq_guard BEFORE INSERT ON audit WHEN NEW.seq <> (SELECT COALESCE(MAX(seq),0)+1 FROM audit WHERE tenant=NEW.tenant) BEGIN SELECT RAISE(ABORT, 'audit sequence must extend the head'); END;");
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.equal(seal.sealed, true);
  assert.equal(seal.removed_count, 1, 'the planted row is counted in the attestation');
  const remaining = h.f.store.db.prepare('SELECT COUNT(*) c FROM audit WHERE tenant=? AND seq>?').get('acme', head.seq).c;
  assert.equal(remaining, 1, 'only the AUDIT_SEALED row sits past the old head');
});

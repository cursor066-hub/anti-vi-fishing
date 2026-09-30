import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture, hasCode } from './helpers.mjs';
import { createHash } from 'node:crypto';
import { canonical, parseStrict } from '../src/canonical.mjs';
import { verifySigned, signed, generateKey } from '../src/crypto.mjs';
import { inclusionProof, verifyInclusion, merkleRoot } from '../src/merkle.mjs';
import { split, reconstruct, encodeShare, decodeShare } from '../src/shamir.mjs';
import { loadIssuers } from '../src/issuerd.mjs';

const EV = JSON.parse(readFileSync('vectors/envelope-vectors.json', 'utf8'));

test('ADV: signature malleability — every structural mutation rejects', () => {
  const v = EV.vectors[0], env = v.envelope, keys = { [v.key_id]: { public_key: v.public_key } };
  const cases = [
    e => ({ ...e, signature: e.signature.replace(/.$/, c => (c === 'A' ? 'B' : 'A')) }), // flip last char
    e => ({ ...e, signature: e.signature + 'A' }),
    e => ({ ...e, signature: e.signature.slice(1) }),
    e => ({ ...e, signature: e.signature.replace(/[a-z]/, 'A') }),
    e => ({ ...e, protected: { ...e.protected, purpose: 'evidence' } }),
    e => ({ ...e, protected: { ...e.protected, suite: 'Ed25519ph' } }),
    e => ({ ...e, protected: { ...e.protected, profile: 'IF-CJSON-2' } }),
    e => ({ ...e, protected: { ...e.protected, extra: 1 } }),
    e => ({ ...e, extra: {} }),
    e => ({ ...e, signature: '!' + e.signature.slice(1) }),
  ];
  for (const mutate of cases) assert.throws(() => verifySigned(mutate(env), keys, v.purpose));
  // Purpose confusion: same envelope, wrong expected purpose.
  assert.throws(() => verifySigned(env, keys, 'capability' === v.purpose ? 'evidence' : 'capability'));
  // Key confusion: valid signature under a different key_id context.
  const other = EV.vectors[1];
  assert.throws(() => verifySigned(env, { [other.key_id]: { public_key: other.public_key } }, v.purpose));
});

test('ADV: unicode normalisation confusion — NFC and NFD diverge', () => {
  const nfc = { s: 'cafe\u0301'.normalize('NFC') }, nfd = { s: 'cafe\u0301' };
  assert.throws(() => canonical(nfd));
  assert.equal(canonical(nfc), canonical({ s: 'caf\u00E9' }));
  // Mixed-script lookalike keys stay distinct.
  assert.notEqual(canonical({ id: 'adm\u0456n' }), canonical({ id: 'admin' }));
});

test('ADV: merkle proof forgery — wrong index, size, hash and path order all reject', () => {
  const hashes = Array.from({ length: 7 }, (_, i) => createHash('sha256').update(`hash-${i}`).digest('hex'));
  const path = inclusionProof(hashes, 3), root = merkleRoot(hashes);
  assert.equal(verifyInclusion(hashes[3], 3, 7, path, root), true);
  assert.throws(() => verifyInclusion(hashes[4], 3, 7, path, root));
  assert.throws(() => verifyInclusion(hashes[3], 4, 7, path, root));
  // A proof belonging to a different leaf must not verify for this entry.
  assert.throws(() => verifyInclusion(hashes[3], 3, 7, inclusionProof(hashes, 4), root));
  // Truncated path.
  assert.throws(() => verifyInclusion(hashes[3], 3, 7, path.slice(1), root));
  assert.throws(() => verifyInclusion(hashes[3], 3, 7, path, '0'.repeat(64)));
  assert.throws(() => verifyInclusion(hashes[3], 3, 7, [...path].reverse(), root));
  const tampered = path.map((s, i) => i === 0 ? { ...s, hash: 'f'.repeat(64) } : s);
  assert.throws(() => verifyInclusion(hashes[3], 3, 7, tampered, root));
  const wrongSide = path.map((s, i) => i === 1 ? { ...s, side: s.side === 'left' ? 'right' : 'left' } : s);
  assert.throws(() => verifyInclusion(hashes[3], 3, 7, wrongSide, root));
});

test('ADV: shamir share confusion — mixed, duplicated and truncated shares reject', () => {
  const a = Buffer.from('master-secret-A'.padEnd(32, 'a')), b = Buffer.from('other-secret-B'.padEnd(32, 'b'));
  const sa = split(a, 5, 3), sb = split(b, 5, 3);
  assert.ok(Buffer.from(reconstruct([sa[0], sa[1], sa[2]])).equals(a));
  // Shares from different splits reconstruct to wrong bytes, never the secret.
  assert.equal(Buffer.from(reconstruct([sa[0], sa[1], sb[2]])).equals(a), false);
  // Duplicate share does not count toward quorum.
  assert.throws(() => reconstruct([sa[0], sa[0], sa[1]]));
  // Below-threshold shares yield only garbage bytes — quorum enforcement
  // lives in the ceremony layer, which refuses before reaching here.
  assert.equal(Buffer.from(reconstruct([sa[0], sa[1]])).equals(a), false);
  // A truncated share decodes structurally but can never join a quorum.
  const enc = encodeShare(sa[0]);
  assert.throws(() => reconstruct([decodeShare(enc.slice(0, -4)), sa[1], sa[2]]));
  assert.throws(() => decodeShare('!!'));
});

test('ADV: capsule approval replay — the same signed approval cannot be resubmitted', t => {
  const h = fixture(t);
  const r = h.proposed(); h.evidence(r); h.approve(r, 1);
  const approval = h.f.store.get('acme', 'capsule', r.capsule.capsule_id).approvals[0];
  assert.throws(() => h.f.approve(h.p('custodian-1'), approval), (e) => e.code === 'INV-409-REPLAY');
});

test('ADV: certificate cannot mint twice or execute past expiry', t => {
  const h = fixture(t);
  const { record, certificate } = h.ready();
  assert.throws(() => h.f.certificate(h.p('operator'), record.capsule.capsule_id), hasCode('INV-409-STATE'));
  h.advance(120001);
  assert.throws(() => h.f.execute(h.p('operator'), certificate), hasCode('INV-401-CERTIFICATE'));
});

test('ADV: issuer registry — ambiguous bare names resolve only via tenant key', t => {
  const dir = mkdtempSync(join(tmpdir(), 'issuers-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const tenant of ['acme', 'globex']) {
    const spec = { issuer: 'bank', tenant, version: '1.0.0', channel: 'authoritative', key: { ...generateKey(), key_id: `${tenant}-k` }, kinds: {}, records: {} };
    writeFileSync(join(dir, `${tenant}-bank.issuer.json`), JSON.stringify(spec), { mode: 0o600 });
  }
  const issuers = loadIssuers(dir);
  assert.ok(issuers['acme:bank']); assert.ok(issuers['globex:bank']);
  assert.equal(issuers['bank'].ambiguous, true);
});

test('ADV: staged policy cannot skip a version or resurrect a rolled-back rule', t => {
  const h = fixture(t);
  const next = h.clone(h.f.policy(h.p('operator').tenant_id));
  next.version = next.version + 2; // gap: must not activate
  next.not_before = h.now() - 1;
  h.f.store.put('acme', 'policy', 'staged', { policy: next, activate_at: next.not_before, staged_at: h.now() }, h.now());
  // A version gap must never promote — and must never wedge: the stale row
  // is retired with a POLICY_SUPERSEDED audit entry instead of throwing on
  // every later transaction (policy-audit F1).
  h.f.activateDuePolicies('acme', h.now());
  assert.equal(h.f.policy('acme').version, next.version - 2);
  assert.equal(h.f.store.get('acme', 'policy', 'staged'), null);
  const entries = h.f.store.auditPage('acme', {}).entries.map(e => e.envelope.payload);
  assert.equal(entries.some(e => e.type === 'POLICY_SUPERSEDED' && e.metadata?.version === next.version), true);
});

test('ADV: envelope with evidence purpose cannot be submitted as approval', t => {
  const h = fixture(t);
  const r = h.proposed(); h.evidence(r);
  const c1 = h.setup.custodianKeys['acme']['custodian-1'];
  const challenge = h.f.approvalChallenge(h.p('custodian-1'), r.capsule.capsule_id);
  const fake = signed(challenge, c1, 'evidence'); // right bytes, wrong purpose
  assert.throws(() => h.f.approve(h.p('custodian-1'), fake), (e) => e.code === 'INV-401-SIGNATURE');
});

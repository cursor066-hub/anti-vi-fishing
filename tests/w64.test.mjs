// Wave-64 regression tests: fixverify F-5/F-10 (negated-member folding),
// F-6 (switch/case own-arm consumption), F-7 (same-line else chains),
// F-8 (rebound aliases), ledger F-4/F-5 (?. / .at() seed spellings,
// nested braceless else binding); seal F-1..F-6 (dead configured signer,
// claim-seq <= marker_seq binding, unsafe-integer claims, mint-vs-field
// cap, claims_dropped, occupied residue keys); runtime F-1/F-2/F-3
// (claims_dropped mirror, residueLikeStmt dup-key clause, oversized
// marker convergence). Gate probes eval a live slice of the shipped
// scanner — tested code cannot drift from shipped code.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync , mkdtempSync, writeFileSync, rmSync} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fixture, designateSuccessor } from './helpers.mjs';
import { Fabric } from '../src/fabric.mjs';
const probeFile = src => {
  const dir = mkdtempSync(join(tmpdir(), 'gate-probe-'));
  const file = join(dir, 'probe.mjs');
  writeFileSync(file, src);
  try { return execFileSync(process.execPath, [file], { encoding: 'utf8', cwd: new URL('..', import.meta.url).pathname }).trim(); }
  finally { rmSync(dir, { recursive: true, force: true }); }
};

const ROOT = new URL('..', import.meta.url).pathname;
const collectRun = (lines, verb) => {
  const src = readFileSync(new URL('../scripts/check.mjs', import.meta.url).pathname, 'utf8');
  const helpers = src.slice(src.indexOf('// === shared source scanners'), src.indexOf('// === end shared source scanners'));
  const block = src.slice(src.indexOf('const NONROLE'), src.indexOf('const authorizeAt'));
  assert.ok(block.includes('collectAuthorize'), 'the slice carries the shipped scanner');
  return JSON.parse(probeFile([
    helpers, block,
    `globalThis.process.stdout.write(JSON.stringify(collectAuthorize(${JSON.stringify(lines)}, 0, ${lines.length + 2}, true, ${JSON.stringify(verb)})));`
  ].join('\n')));
};
const HEAD = "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {";
const HEAD2 = "if (req.method === 'GET' && (m = /^\\/x\\/(.*)\\/(.*)/.exec(path))) {";

const residueRows = h => h.f.store.db.prepare(
  "SELECT key,value FROM meta_kv WHERE tenant='acme' AND (key='fold_floor_healed' OR substr(key,1,18)='fold_floor_healed.')").all();
const dropResidueGuards = h => {
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_upd');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_ins');
};
const healOnce = (h, garbage) => {
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(garbage);
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
};
const putMarker = (h, env, claims = null) => {
  dropResidueGuards(h);
  h.f.store.db.prepare("INSERT INTO meta_kv (tenant,key,value) VALUES ('acme','fold_floor_retired',?) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value")
    .run(JSON.stringify({ claims: claims ?? (env ? JSON.parse(env.payload ?? '{}')?.fold_floor_retired ?? [] : []), env }));
};
const sealKinds = h => (h.f.sealAuditChain(h.p('security')).head_watermark_tampered ?? []).map(e => e.kind);
const committedTip = h => h.f.store.db.prepare("SELECT MAX(seq) m FROM audit WHERE tenant='acme'").get().m;
const tipHashAt = (h, seq) => h.f.store.db.prepare("SELECT hash FROM audit WHERE tenant='acme' AND seq=?").get(seq)?.hash ?? null;

// ============================================================================
// w64-fv F-5/F-10: negated member compares fold against the bound member —
// `m[1]==='a' || m[1]!=='b'` is dead scope for 'b' (both sides false —
// 'b' can never satisfy its own exclusion, a deterministic fold). For an
// UNBOUND outsider 'c' a lone positive vote is only an id-filter, not a
// dispatch discriminator — the `!==` side mints conditional (w68-ledger
// F-1); two positive votes prove the member and restore the fold.
// ============================================================================
test('w64-fv F-5: ||-memberneg folds dead for the excluded verb, conditional for outsiders under a lone vote', () => {
  const dead = collectRun([HEAD, "  if (m[1]==='a' || m[1]!=='b') { authorize(p,['r']); }", '}'], 'b');
  assert.equal(dead.roles, null, `b can never enter: ${JSON.stringify(dead)}`);
  assert.equal(dead.any, false, 'b mints no reachability evidence either');
  const cond = collectRun([HEAD, "  if (m[1]==='a' || m[1]!=='b') { authorize(p,['r']); }", '}'], 'c');
  assert.equal(cond.roles, null, `lone 'a' vote is an id-filter — conditional for c: ${JSON.stringify(cond)}`);
  assert.equal(cond.any, true);
  const proven2 = collectRun([HEAD, "  if (m[1]==='d') { serve(); }", "  if (m[1]==='a' || m[1]!=='b') { authorize(p,['r']); }", '}'], 'c');
  assert.deepEqual(proven2.roles, ['r'], `two positive votes prove the member — c folds back to unconditional: ${JSON.stringify(proven2)}`);
  const taut = collectRun([HEAD, "  if (m[1]==='a' && m[1]!=='b') { authorize(p,['r']); }", '}'], 'a');
  assert.deepEqual(taut.roles, ['r'], `the &&-tautology is unconditional for 'a': ${JSON.stringify(taut)}`);
  const deadAnd = collectRun([HEAD, "  if (m[1]==='a' && m[1]!=='b') { authorize(p,['r']); }", '}'], 'b');
  assert.equal(deadAnd.roles, null, 'b satisfies neither && side');
  assert.equal(deadAnd.any, false);
});

// A flag conjunct failing the droppable test still seeds the pair maps —
// the same-member literal must not mint unconditional for other verbs.
test('w64-fv F-10: flag&&pair stays conditional for bound, unreachable for unbound', () => {
  const bound = collectRun([HEAD, "  if (flag && m[1]==='a') { authorize(p,['r']); }", '}'], 'a');
  assert.equal(bound.roles, null, `the flag still gates for 'a': ${JSON.stringify(bound)}`);
  assert.equal(bound.any, true);
  const unbound = collectRun([HEAD, "  if (flag && m[1]==='a') { authorize(p,['r']); }", '  authorize(p,[\'b\']);', '}'], 'b');
  assert.deepEqual(unbound.roles, ['b'], `the a-only arm contributes nothing to 'b': ${JSON.stringify(unbound)}`);
});

// ============================================================================
// w64-fv F-6: switch/case arms — `case 'a'` is row-a's own arm (mints
// unconditional for 'a'), `default` serves the unbound verbs, and a
// `break`-gated frame consumes its own arm only.
// ============================================================================
test('w64-fv F-6: switch case arms consume by verb, default serves the unbound', () => {
  const own = collectRun([HEAD, "  switch (m[1]) { case 'a': authorize(p,['ra']); break; default: authorize(p,['rd']); }", '}'], 'a');
  assert.deepEqual(own.roles, ['ra'], `case 'a' is row-a's unconditional arm: ${JSON.stringify(own)}`);
  const unbound = collectRun([HEAD, "  switch (m[1]) { case 'a': authorize(p,['ra']); break; default: authorize(p,['rd']); }", '}'], 'b');
  assert.deepEqual(unbound.roles, ['rd'], `default serves the unbound 'b': ${JSON.stringify(unbound)}`);
  const tail = collectRun([HEAD, "  switch (m[1]) { case 'a': authorize(p,['ra']); }", "  authorize(p,['tail']);", '}'], 'a');
  assert.deepEqual(tail.roles, ['ra', 'tail'], `own-case plus tail: ${JSON.stringify(tail)}`);
  const foreign = collectRun([HEAD2, "  switch (norm(m[2])) { case 'x': authorize(p,['rx']); }", "  authorize(p,['tail']);", '}'], 'a');
  assert.deepEqual(foreign.roles, ['tail'], `an m[2]-armed switch is foreign scope for m[1]-bound 'a': ${JSON.stringify(foreign)}`);
});

// ============================================================================
// w64-fv F-7: a same-line `else if`/`else` chain binds the pending if —
// 'b' satisfies the `m[1]==='b'` arm, never the trailing else.
// ============================================================================
test('w64-fv F-7: same-line else-if chains bind per-verb', () => {
  const b = collectRun([HEAD, "  if (m[1]==='a') { A(); } else if (m[1]==='b') { B(); } else { authorize(p,['re']); }", '}'], 'b');
  assert.equal(b.roles, null, `b takes its own arm, not the else: ${JSON.stringify(b)}`);
  assert.equal(b.any, false, 'the else is dead scope for b');
  const c = collectRun([HEAD, "  if (m[1]==='a') { A(); } else if (m[1]==='b') { B(); } else { authorize(p,['re']); }", '}'], 'c');
  assert.deepEqual(c.roles, ['re'], `c falls to the else arm: ${JSON.stringify(c)}`);
});

// ============================================================================
// w64-fv F-8: a rebound alias is last-write-wins — `q = other` unbinds the
// dispatcher, so `q[1]==='a'` is an unknowable gate (conditional), not a
// dispatch pair. The x mint still conditions 'b' honestly.
// ============================================================================
test('w64-fv F-8: a rebound alias unbinds — post-rebind compares are gates', () => {
  const r = collectRun([HEAD, "  const q = m; q = other;", "  if (q[1]==='a') { authorize(p,['x']); }",
    "  if (m[1]==='b') { return; }", "  authorize(p,['a']);", '}'], 'b');
  assert.equal(r.roles, null, `other[1] is unknowable — 'x' mints conditional, 'a' is dead: ${JSON.stringify(r)}`);
  assert.equal(r.any, true);
});

// ============================================================================
// w64-ledger F-4: seed spellings — `m?.[N]` optional-chain and `m.at(N)`
// binds dispatch pairs like `m[N]` does.
// ============================================================================
test('w64-ledger F-4: optional-chain and .at() member spellings seed pairs', () => {
  const opt = collectRun([HEAD, "  if (m?.[1]==='a') { authorize(p,['a']); }", '}'], 'a');
  assert.deepEqual(opt.roles, ['a'], `m?.[1]==='a' is the same dispatch pair: ${JSON.stringify(opt)}`);
  const at = collectRun([HEAD, "  if (m.at(1)==='a') { authorize(p,['a']); }", '}'], 'a');
  assert.deepEqual(at.roles, ['a'], `m.at(1)==='a' binds the member too: ${JSON.stringify(at)}`);
  const atDead = collectRun([HEAD, "  if (m.at(1)==='a') { authorize(p,['a']); }", "  authorize(p,['b']);", '}'], 'b');
  assert.deepEqual(atDead.roles, ['b'], `the .at arm is dead scope for 'b': ${JSON.stringify(atDead)}`);
});

// ============================================================================
// w64-ledger F-5: a nested braceless `if` inside an own arm's body still
// gates — `if (m[1]==='a') if (m[2]==='x') authorize` mints only when
// m[2]==='x'; the else binds the INNER if.
// ============================================================================
test('w64-ledger F-5: nested braceless if inside the own arm stays conditional', () => {
  const r = collectRun([HEAD2, "  if (m[1]==='a') if (m[2]==='x') authorize(p,['x']); else authorize(p,['a']);", '}'], 'a');
  assert.equal(r.roles, null, `a mints only when m[2]!=='x' — conditional: ${JSON.stringify(r)}`);
  assert.equal(r.any, true, 'the x mint is reachability evidence');
});

// ============================================================================
// w64-seal F-1: a rotated-out configured signer never signs marker
// envelopes — the write steers to the live successor, so the marker is
// born honored instead of self-refusing.
// ============================================================================
test('w64-seal F-1: marker writes steer off a dead configured signer', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const auditKid = h.f.tenant('acme').keys.audit.key_id;
  const pending = designateSuccessor(h, 'audit');
  h.f.store.audit('acme', 'KEY_ROTATED', 'security', pending.key_id, { key_class: 'audit', previous_key_id: auditKid, revoke_old: false }, h.now());
  // The configured key is dead in the fold but still configured — under
  // w63 semantics the next marker write signed under it, birthing an
  // env that every consult refuses (permanent forged latch).
  healOnce(h, 'dead-signer');
  const kinds = sealKinds(h);
  assert.ok(kinds.includes('floor_marker_healed') || kinds.length === 0 || !kinds.includes('floor_marker_retired_forged'),
    `no self-refusing marker: ${kinds}`);
  const raw = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
  if (raw !== undefined) {
    const parsed = JSON.parse(raw);
    if (parsed?.env !== undefined)
      assert.notEqual(parsed.env?.protected?.key_id, auditKid,
        'a marker env must not be signed by the dead configured key');
  }
  // A second seal round must not find a forged marker latched by the first.
  const kinds2 = sealKinds(h);
  assert.ok(!kinds2.includes('floor_marker_retired_forged'),
    `the marker plane is not self-bricked: ${kinds2}`);
  h.close();
});

// ============================================================================
// w64-seal F-2: a claim anchored above its envelope's own marker_seq is
// dishonest — a backdated env cannot suppress heals it never saw.
// ============================================================================
test('w64-seal F-2: a claim anchored above marker_seq refuses the env', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'seq-bound');
  const claim = residueRows(h)[0]?.value;
  assert.ok(claim, 'a residue claim stands');
  const claimSeq = Number(claim.split(':')[0]);
  const tip = committedTip(h);
  assert.ok(claimSeq <= tip, 'fixture sanity');
  // marker_seq one below the claim's own anchor — the env asserts it
  // consumed to a tip that predates the claim it names: forged content.
  const env = h.f.store.auditSigners['acme'].sign({ tenant_id: 'acme', fold_floor_retired: [claim], marker_seq: claimSeq - 1 }, 'audit');
  putMarker(h, env, [claim]);
  const kinds = sealKinds(h);
  assert.ok(kinds.includes('floor_marker_retired_forged') || kinds.includes('floor_marker_retired_unauthenticated'),
    `a claim above marker_seq convicts the env: ${kinds}`);
  h.close();
});

// Boundary: marker_seq == the claim's anchor is honest (the env could
// have seen the claim it names).
test('w64-seal F-2c: a marker_seq covering the claim verifies', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'seq-bound-ok');
  const claim = residueRows(h)[0]?.value;
  assert.ok(claim, 'a residue claim stands');
  const tip = committedTip(h);
  const ok = h.f.store.auditSigners['acme'].sign({ tenant_id: 'acme', fold_floor_retired: [claim], marker_seq: tip, marker_tip_hash: tipHashAt(h, tip) }, 'audit');
  putMarker(h, ok, [claim]);
  const kinds = sealKinds(h);
  assert.ok(!kinds.includes('floor_marker_retired_forged') && !kinds.includes('floor_marker_retired_unauthenticated'),
    `a marker_seq covering the claim verifies: ${kinds}`);
  h.close();
});

// ============================================================================
// w64-seal F-2b: `retired` honors the same recency window as `retiring` —
// a backdated marker cannot suppress the retired-echo conviction.
// ============================================================================
test('w64-seal F-2b: a stale retired set cannot suppress the echo', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'stale-retired');
  const claim = residueRows(h)[0]?.value;
  assert.ok(claim, 'a residue claim stands');
  // Authentically signed, marker_seq deep in the past — under w63
  // semantics `retired` was signature-anchored and suppressed the echo
  // regardless of staleness.
  const env = h.f.store.auditSigners['acme'].sign({ tenant_id: 'acme', fold_floor_retired: [claim], marker_seq: -100000 }, 'audit');
  putMarker(h, env, [claim]);
  const kinds = sealKinds(h);
  assert.ok(kinds.includes('floor_marker_residue_retired_echo') || kinds.includes('floor_marker_retired_forged'),
    `a stale retired set cannot suppress the echo: ${kinds}`);
  h.close();
});

// ============================================================================
// w64-seal F-3: a claim whose seq is not a safe integer is flagged like a
// past-tip claim — it never reaches the signed marker set.
// ============================================================================
test('w64-seal F-3: unsafe-integer claim seqs flag premature, never mint', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'prime');
  h.f.sealAuditChain(h.p('security'));
  // Plant a residue row whose seq head is shaped but unreachable — the
  // `\d+:` filter passes it; the seq itself is dishonest.
  dropResidueGuards(h);
  h.f.store.db.prepare("INSERT INTO meta_kv (tenant,key,value) VALUES ('acme','fold_floor_healed.9',?)").run('99999999999999999999:x');
  const kinds = sealKinds(h);
  assert.ok(kinds.includes('floor_marker_residue_premature') || kinds.includes('floor_marker_retired_unshaped') || kinds.includes('floor_marker_healed_unanchored'),
    `the unsafe seq is flagged: ${kinds}`);
  const raw = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
  if (raw !== undefined) {
    const authed = (() => { try { return JSON.parse(raw); } catch { return null; } })();
    const text = JSON.stringify(authed);
    assert.ok(!text.includes('99999999999999999999'), `the unsafe claim never enters the signed set: ${text.slice(0, 300)}`);
  }
  h.close();
});

// ============================================================================
// w64-seal F-4 + runtime F-3: the 4096 bound caps the marker FIELD, not
// the mints — an oversized signed marker converges instead of wedging.
// ============================================================================
test('w64-seal F-4: an oversized prior still mints fresh claims', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  // An honest-signed marker over the write contract — 4097 prior claims.
  const prior = Array.from({ length: 4097 }, (_, i) => `1:p${i}`);
  const env = h.f.store.auditSigners['acme'].sign({ tenant_id: 'acme', fold_floor_retired: prior, marker_seq: committedTip(h), marker_tip_hash: tipHashAt(h, committedTip(h)) }, 'audit');
  putMarker(h, env, prior);
  // A fresh heal convicts, retires — its claim must reach a chain mint
  // even though prior alone exceeds the field cap.
  healOnce(h, 'fresh');
  const kinds = sealKinds(h);
  assert.ok(kinds.includes('floor_marker_healed'), `the heal convicts: ${kinds}`);
  const mint = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND json_extract(envelope,'$.payload.type')='FOLD_RESIDUE_RETIRED'").all()
    .map(r => JSON.parse(r.envelope).payload).find(p => (p.metadata?.retired_claims ?? []).some(c => typeof c === 'string' && c.endsWith(':fresh')));
  assert.ok(mint, 'the fresh claim is minted despite prior > 4096');
  h.close();
});

// ============================================================================
// w64-runtime F-1 / seal F-5: the claims[] sample admits its truncation —
// 20 rejected claims report 16 named + claims_dropped: 4.
// ============================================================================
test('w64-runtime F-1: claims_dropped admits the sample truncation', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const unshaped = Array.from({ length: 20 }, (_, i) => `claim-${i}`);
  const env = h.f.store.auditSigners['acme'].sign({ tenant_id: 'acme', fold_floor_retired: unshaped, marker_seq: committedTip(h), marker_tip_hash: tipHashAt(h, committedTip(h)) }, 'audit');
  putMarker(h, env, unshaped);
  const seal = h.f.sealAuditChain(h.p('security'));
  const flags = seal.head_watermark_tampered ?? [];
  const mal = flags.find(e => e.kind === 'floor_marker_retired_malformed');
  assert.ok(mal, `malformed claims convict: ${flags.map(f => f.kind)}`);
  assert.equal(mal.claims.length, 16, `the sample is bounded: ${mal.claims.length}`);
  assert.equal(mal.claims_dropped, 4, `the dropped tail is admitted: ${JSON.stringify(mal)}`);
  h.close();
});

// ============================================================================
// w64-runtime F-2 / fv F-9: the residue rescan carries the sibling scan's
// duplicate-key clause — a mint row respelled with a decoy first
// `payload` member still enumerates, so the claim stays consumed.
// ============================================================================
test('w64-runtime F-2: a dup-key respelled mint stays on the residue plane', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'dupkey');
  h.f.sealAuditChain(h.p('security'));
  // The retire mint exists (the heal convicted and retired).
  const mintRow = h.f.store.db.prepare("SELECT seq,envelope FROM audit WHERE tenant='acme' AND json_extract(envelope,'$.payload.type')='FOLD_RESIDUE_RETIRED'").get();
  assert.ok(mintRow, 'a retire mint stands');
  // Splice a decoy FIRST `"payload"` member into the stored envelope —
  // json_extract reads the first (INNOCUOUS), JSON.parse reads the last
  // (real). Signature/hash bind the parsed form, so the row verifies.
  const env = JSON.parse(mintRow.envelope);
  // Build it byte-exactly: {"payload":{"type":"INNOCUOUS"}, + the
  // original object's body + } — first member is the decoy, last wins.
  const dupText = `{"payload":{"type":"INNOCUOUS"},${mintRow.envelope.slice(1)}`;
  assert.ok(JSON.parse(dupText).payload.type === 'FOLD_RESIDUE_RETIRED', 'the last member still parses real');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS no_audit_update');
  h.f.store.db.prepare('UPDATE audit SET envelope=? WHERE tenant=? AND seq=?').run(dupText, 'acme', mintRow.seq);
  h.f.store.db.exec("CREATE TRIGGER no_audit_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END");
  // Corrupt the marker + replant the residue row, then force a fresh
  // consult on a second fabric instance (the first instance's in-memory
  // cursor already consumed the mint).
  dropResidueGuards(h);
  h.f.store.db.prepare("UPDATE meta_kv SET value='corrupt' WHERE tenant='acme' AND key='fold_floor_retired'").run();
  // The real claim the mint carried — read it back from the mint payload.
  const mintedClaims = env.payload.metadata?.retired_claims ?? env.payload.retired_claims ?? [];
  assert.ok(mintedClaims.length > 0, 'the mint carries claims');
  for (const c of mintedClaims) h.f.store.db.prepare("INSERT INTO meta_kv (tenant,key,value) VALUES ('acme',?,?)").run(`fold_floor_healed.r${Math.random()}`.slice(0, 60), c);
  const f2 = new Fabric(h.setup.config, h.directory, () => h.now());
  try {
    const kinds = (f2.sealAuditChain(h.p('security')).head_watermark_tampered ?? []).map(e => e.kind);
    assert.ok(!kinds.includes('floor_marker_healed'),
      `the dup-key'd mint still binds the claim — no heal re-fire: ${kinds}`);
  } finally { f2.close(); h.close(); }
});

// ============================================================================
// w64-seal F-6: a row planted at the heal's own residue key is never
// absorbed — the heal lands under a `.N` sibling and both rows reach the
// evidence plane.
// ============================================================================
test('w64-seal F-6: an occupied residue key lands the heal on a sibling', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  // Plant a foreign row at the key the next heal would take. The heal's
  // seq is the NEXT appended seq — plant against the floor marker's own
  // heal path by pre-writing the key for the upcoming append's seq.
  const nextSeq = committedTip(h) + 1;
  dropResidueGuards(h);
  h.f.store.db.prepare("INSERT INTO meta_kv (tenant,key,value) VALUES ('acme',?,?)").run(`fold_floor_healed.${nextSeq}`, `${nextSeq}:planted`);
  healOnce(h, 'occupied');
  const rows = residueRows(h).map(r => r.key);
  assert.ok(rows.includes(`fold_floor_healed.${nextSeq}`), 'the planted row still stands');
  assert.ok(rows.some(k => k.startsWith(`fold_floor_healed.${nextSeq}.`)),
    `the heal landed on a sibling key rather than absorbing the plant: ${JSON.stringify(rows)}`);
  h.close();
});

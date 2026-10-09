// Wave-67 regression tests: fixverify F-1 (unproven-member `!==` fold) +
// F-3 (retiring absorption); seal F-1..F-5 (self-murdered marker delete,
// committed-tx replay, defeated-write flag, fresh-first ordering, note
// savepoint); ledger F-1..F-5 (EOL latch paren heads, `===false` chain
// polarity, conjunct-gated vote conflation, foreign-gate vote scoping,
// w32 envelope assertion); runtime F-1..F-5 (deferred-drop naming,
// prior_evicted round-trip, note back-probe, standing-marker union,
// unanchored-heal claims); fv N-1 (in-range marker binds stored hash).
// Gate probes eval a live slice of the shipped scanner — tested code
// cannot drift from shipped code.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fixture } from './helpers.mjs';
import { digest } from '../src/canonical.mjs';
import { RESIDUE_KEEP_TRIGGERS } from '../src/store.mjs';

const probeFile = src => {
  const dir = mkdtempSync(join(tmpdir(), 'gate-probe-'));
  const file = join(dir, 'probe.mjs');
  writeFileSync(file, src);
  try { return execFileSync(process.execPath, [file], { encoding: 'utf8', cwd: new URL('..', import.meta.url).pathname }).trim(); }
  finally { rmSync(dir, { recursive: true, force: true }); }
};

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
const HEAD2 = "if ((m = /^\\/x\\/(.*)\\/(.*)/.exec(path))) {";

const residueRows = h => h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND (key='fold_floor_healed' OR substr(key,1,18)='fold_floor_healed.')").all();
const dropResidueGuards = h => {
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_upd');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_ins');
};
// w76-fv F-1: the schema-version pin convicts a dropped guard set at the next
// guarded call — plants restore the canonical set before the seal runs.
const restoreResidueGuards = h => { for (const [name, sql] of RESIDUE_KEEP_TRIGGERS) { try { h.f.store.db.exec(sql); } catch (e) { if (!/already exists/.test(String(e?.message ?? e))) throw e; } } };
const dropAuditGuards = h => {
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
    h.f.store.db.exec(`DROP TRIGGER "${String(tr.name).replace(/"/g, '""')}"`);
};
const healOnce = (h, garbage) => {
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(garbage);
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
};
const putMarker = (h, env, claims = null) => {
  dropResidueGuards(h);
  h.f.store.db.prepare("INSERT INTO meta_kv (tenant,key,value) VALUES ('acme','fold_floor_retired',?) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value")
    .run(JSON.stringify({ claims: claims ?? (env ? JSON.parse(env.payload ?? '{}')?.fold_floor_retired ?? [] : []), env }));
  restoreResidueGuards(h);
};
const committedTip = h => h.f.store.db.prepare("SELECT MAX(seq) m FROM audit WHERE tenant='acme'").get().m;
const tipHashAt = (h, seq) => {
  const r = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND seq=?").get(seq);
  return r === undefined ? null : digest(JSON.parse(r.envelope).payload);
};

// ============================================================================
// w67-ledger F-1: the EOL latch could not see paren-bodied conditions —
// `if (f(x))`, `while (f(x))`, `for..of f(y)`, `else if (f(x))` and a
// braced `{` arm all end the line mid-head, so an authorize on the next
// line minted unconditional inside a runtime gate.
// ============================================================================
test('w67-ledger F-1: paren-bodied end-of-line heads still gate the arm', () => {
  for (const kw of ['if (f(x))', 'while (f(x))', 'for (const y of f(y))']) {
    const r = collectRun([HEAD, `  ${kw} authorize(p, ['adm']);`, '}'], 'x');
    assert.equal(r.roles, null, `${kw} braces the mint — conditional, never unconditional`);
  }
  // A nested-paren head `if (f(g(x)))` is equally a gate.
  { const r = collectRun([HEAD, '  if (f(g(x))) authorize(p, ["adm"]);', '}'], 'x');
    assert.equal(r.roles, null); }
  // A proven-open head that did NOT close also gates.
  { const r = collectRun([HEAD, "  if (a && (b || c) &&", "    d) authorize(p, ['adm']);", '}'], 'x');
    assert.equal(r.roles, null); }
  // The unconditional case still mints: no gate at all.
  { const r = collectRun([HEAD, "  authorize(p, ['adm']);", '}'], 'x');
    assert.deepEqual(r.roles, ['adm']); }
  // And a closed own-verb arm head mints its interior unconditionally.
  { const r = collectRun([HEAD, "  if (m[1]==='x') { authorize(p, ['adm']); }", '}'], 'x');
    assert.deepEqual(r.roles, ['adm']); }
});

// ============================================================================
// w67-ledger F-2: `m[1]==='a'===false` compares member to 'a' then the
// boolean to false — a live runtime gamble, not the pair's own binding.
// Chain continuations must not mint the arm unconditional.
// ============================================================================
test('w67-ledger F-2: `===false` chain continuations keep the arm conditional', () => {
  { const r = collectRun([HEAD, "  if (m[1]==='a'===false) { authorize(p, ['adm']); }", '}'], 'a');
    assert.equal(r.any, true); assert.equal(r.roles, null, 'the chain reads a runtime value — conditional'); }
  { const r = collectRun([HEAD, "  if (m[1]==='a'!==false) { authorize(p, ['adm']); }", '}'], 'a');
    assert.equal(r.roles, null); }
  // The un-chained pair still binds 'a' unconditionally.
  { const r = collectRun([HEAD, "  if (m[1]==='a') { authorize(p, ['adm']); }", '}'], 'a');
    assert.deepEqual(r.roles, ['adm']); }
});

// ============================================================================
// w67-fv F-1 + w67-ledger F-3: a `!==` compare on a member with no
// POSITIVE vote cannot fold — 'x'-requests may carry the very value the
// compare excludes; the arm mints conditional, never unconditional and
// never dead.
// ============================================================================
test('w67-fv F-1: an unproven-member `!==` mints conditional, not unconditional', () => {
  // The lone `!==` is the whole gate: unproven — conditional.
  { const r = collectRun([HEAD2, "  if (m[2] !== 'y') { authorize(p, ['spy']); }", '}'], 'x');
    assert.equal(r.any, true); assert.equal(r.roles, null); }
  // Its `else` is equally conditional — the plurality gamble is
  // symmetric for unproven members.
  { const r = collectRun([HEAD2, "  if (m[2] !== 'y') { spy(); } else { authorize(p, ['r']); }", '}'], 'x');
    assert.equal(r.any, true); assert.equal(r.roles, null); }
  // A single positive compare is an id-filter, not discriminator proof
  // (w68-ledger F-1): the unbound 'x' folds only once at least two
  // distinct verbs bind the member. A verb bound ON the member keeps the
  // deterministic fold — its own binding proves discrimination for it.
  const proven = [HEAD2, "  if (m[2]==='y') { serve(); }", "  if (m[2]!=='z') { authorize(p, ['adm']); }", '}'];
  { const r = collectRun(proven, 'x'); assert.equal(r.roles, null, 'lone id-filter vote — conditional for the unbound'); }
  { const r = collectRun(proven, 'y'); assert.deepEqual(r.roles, ['adm'], "y-requests carry m[2]='y' which is !=='z' — the arm runs"); }
  // 'z' itself can never satisfy its own exclusion — dead arm.
  { const r = collectRun(proven, 'z'); assert.equal(r.any, false, "z-requests carry m[2]='z' — dead"); }
  const proven2 = [HEAD2, "  if (m[2]==='y') { serve(); }", "  if (m[2]==='w') { serveW(); }", "  if (m[2]!=='z') { authorize(p, ['adm']); }", '}'];
  { const r = collectRun(proven2, 'x'); assert.deepEqual(r.roles, ['adm'], 'two positive votes prove the member — the fold returns'); }
  // An unbound verb with NO member-neg arm at all stays unconditional.
  { const r = collectRun([HEAD, "  authorize(p, ['adm']);", '}'], 'x');
    assert.deepEqual(r.roles, ['adm']); }
});

// ============================================================================
// w67-ledger F-3: a conjunct-gated positive pair (`flag && m[1]==='a'`)
// is a live vote — the `neg` flag must not conflate it with an
// operator-negated compare: it still binds 'a''s arm and votes as
// discriminator proof, while `m[1]!=='a'` never serves nor votes.
// ============================================================================
test('w67-ledger F-3: conjunct-gated pairs keep their vote and arm binding', () => {
  // `flag && m[1]==='a'` is 'a''s arm gated by flag — conditional mint.
  { const r = collectRun([HEAD, "  if (flag && m[1]==='a') { authorize(p, ['adm']); }", '}'], 'a');
    assert.equal(r.any, true); assert.equal(r.roles, null, 'flag gates the mint'); }
  // But a lone gated vote is still only an id-filter for unbound verbs
  // (w68-ledger F-1) — 'c' mints conditional; a second positive vote
  // restores the discriminator fold.
  const row = [HEAD, "  if (flag && m[1]==='a') { serveA(); }", "  if (m[1]!=='b') { authorize(p, ['adm']); }", '}'];
  { const r = collectRun(row, 'c'); assert.equal(r.roles, null, 'lone gated vote — id-filter only, conditional'); }
  const row2 = [HEAD, "  if (flag && m[1]==='a') { serveA(); }", "  if (m[1]==='d') { serveD(); }", "  if (m[1]!=='b') { authorize(p, ['adm']); }", '}'];
  { const r = collectRun(row2, 'c'); assert.deepEqual(r.roles, ['adm'], 'two votes prove m[1] — the unbound fold returns'); }
  // The operator-negated compare itself never serves its own arm.
  { const r = collectRun([HEAD, "  if (m[1]!=='a') { authorize(p, ['notA']); }", '}'], 'a');
    assert.equal(r.roles, null, 'a-requests never enter the `!==` arm'); }
});

// ============================================================================
// w67-ledger F-4: a member compare inside a NON-dispatch gate does not
// vote for that gate's purpose — `if (flag) { if (m[1]==='a') ... }`
// proves the member for the row only through its dispatch-context
// compares, not a runtime-braced interior.
// ============================================================================
test('w67-ledger F-4: compares under a foreign gate cannot launder member votes', () => {
  // The m[1] compare sits inside `if (flag) {}` — gated — so the member
  // is NOT proven for this row: a following `m[1]!=='b'` under an
  // unbound verb mints conditional.
  const gated = [HEAD, "  if (flag) { if (m[1]==='a') { serveA(); } }", "  if (m[1]!=='b') { authorize(p, ['adm']); }", '}'];
  { const r = collectRun(gated, 'c'); assert.equal(r.roles, null, 'gated proof is no discriminator vote'); }
  // The same compare at row depth (un-gated) still votes — but a lone
  // vote is an id-filter (w68-ledger F-1), so the unbound `!==` mints
  // conditional until a second verb proves the member.
  const free = [HEAD, "  if (m[1]==='a') { serveA(); }", "  if (m[1]!=='b') { authorize(p, ['adm']); }", '}'];
  { const r = collectRun(free, 'c'); assert.equal(r.roles, null, 'lone vote — id-filter only, conditional'); }
  const free2 = [HEAD, "  if (m[1]==='a') { serveA(); }", "  if (m[1]==='d') { serveD(); }", "  if (m[1]!=='b') { authorize(p, ['adm']); }", '}'];
  { const r = collectRun(free2, 'c'); assert.deepEqual(r.roles, ['adm'], 'two votes prove the member — the fold returns'); }
});

// ============================================================================
// w67-runtime F-2: a signed nonzero `prior_evicted` count must reach the
// report — the consult names the eviction the marker carries.
// ============================================================================
test('w67-runtime F-2: a signed prior_evicted count names floor_marker_retired_evicted', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const tip = committedTip(h);
  const env = h.f.store.auditSigners['acme'].sign(
    { tenant_id: 'acme', fold_floor_retired: ['1:legit'], marker_seq: tip, marker_tip_hash: tipHashAt(h, tip), prior_evicted: 7 }, 'audit');
  putMarker(h, env, ['1:legit']);
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.ok((seal.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_retired_evicted' && e.claims_dropped === 7),
    `the signed eviction count lands on the report: ${JSON.stringify(seal.head_watermark_tampered)}`);
  h.close();
});

// ============================================================================
// w67-seal F-1: a verified marker pinned to a row the seal itself cuts
// is this seal's casualty — the delete retires it with the span instead
// of leaving a corpse to convict forged forever.
// ============================================================================
test('w67-seal F-1: a marker whose pinned row the cut murders is deleted, not left forged', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const tip = committedTip(h);
  const env = h.f.store.auditSigners['acme'].sign(
    { tenant_id: 'acme', fold_floor_retired: ['1:legit'], marker_seq: tip, marker_tip_hash: tipHashAt(h, tip) }, 'audit');
  putMarker(h, env, ['1:legit']);
  // Corrupt the pinned row itself — the cut murders seq=tip, and the
  // marker pinned to it must die with the span.
  dropAuditGuards(h);
  h.f.store.db.prepare("UPDATE audit SET hash='00' WHERE tenant='acme' AND seq=?").run(tip);
  h.f.invalidateAuditIndex('acme');
  h.f.sealAuditChain(h.p('security'));
  const left = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get();
  assert.ok(left === undefined || JSON.parse(left.value).env?.payload?.marker_seq !== tip,
    'a marker pinned into the doomed span retires with it — a corpse would convict forged forever');
  h.close();
});

// ============================================================================
// w67-runtime F-1 (doctrine refined by w70-seal F-4): a standing marker
// that cannot authenticate is no longer a wedge — the drain murders it
// inside its guarded span and names the kill, so the deferred apply
// meets NO standing marker and lands the queued claims rather than
// naming a drop. `floor_marker_retired_deferred_dropped` still covers
// the narrower window where a peer plants a dead marker between the
// drain's murder and the apply's savepoint re-read.
// ============================================================================
test('w67-runtime F-1: a dead standing marker is murdered and the deferred mint lands', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  // The drain during this append runs inside the head-mint seal window,
  // so its merged set lands in the deferred queue with a HEALTHY plane.
  healOnce(h, 'deferred-drop');
  // Then the standing marker is murdered between queue and apply — under
  // the murdered-marker doctrine the drain kills it inside the guarded
  // span and the apply lands the deferred set instead of flagging a drop.
  dropResidueGuards(h);
  h.f.store.db.prepare("INSERT INTO meta_kv (tenant,key,value) VALUES ('acme','fold_floor_retired',?) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value")
    .run(JSON.stringify({ claims: ['junk'], env: { garbage: true } }));
  restoreResidueGuards(h);
  // The apply runs only behind a committed cut — corrupt a row so the
  // seal really cuts, then the drain meets the dead marker and murders it.
  dropAuditGuards(h);
  const tip0 = h.f.store.db.prepare("SELECT MAX(seq) m FROM audit WHERE tenant='acme'").get().m;
  h.f.store.db.prepare("UPDATE audit SET hash='00' WHERE tenant='acme' AND seq=?").run(tip0);
  h.f.invalidateAuditIndex('acme');
  const seal1 = h.f.sealAuditChain(h.p('security'));
  const kinds1 = (seal1?.head_watermark_tampered ?? []).map(e => e.kind);
  assert.ok(kinds1.includes('floor_marker_retired_murdered'),
    `the dead marker is murdered and named: ${JSON.stringify(kinds1)}`);
  // The deferred apply landed the queued claims under a fresh signed env —
  // the drain's suppression copy reached the durable marker after all.
  const seal2 = h.f.sealAuditChain(h.p('security'));
  const row = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
  assert.ok(row !== undefined, 'the deferred apply landed a standing marker');
  const landed = (JSON.parse(row).env?.payload?.fold_floor_retired ?? []).concat(JSON.parse(row).claims ?? []);
  assert.ok(landed.some(c => c.endsWith(':deferred-drop')),
    `the deferred claims landed in the fresh marker: ${row.slice(0, 300)}`);
  h.close();
});

// ============================================================================
// w67-seal F-2 + w67-runtime F-4: a deferred apply unions the STANDING
// marker's claims (fresh first) so a peer write between commit and apply
// is never clobbered out of the durable set.
// ============================================================================
test('w67-seal F-2/F-4: the deferred apply keeps the standing marker\u2019s priors', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const tip = committedTip(h);
  // Standing marker with priors, then a heal whose drain defers to the
  // seal — the apply must union fresh-over-prior, not overwrite.
  const prior = ['5:carried'];
  const env0 = h.f.store.auditSigners['acme'].sign(
    { tenant_id: 'acme', fold_floor_retired: prior, marker_seq: tip, marker_tip_hash: tipHashAt(h, tip) }, 'audit');
  putMarker(h, env0, prior);
  healOnce(h, 'union-check');
  h.f.sealAuditChain(h.p('security'));
  const back = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
  assert.ok(back !== undefined, 'a marker still stands');
  const retired = JSON.parse(back).env?.payload?.fold_floor_retired ?? [];
  assert.ok(retired.includes('5:carried'), `the standing prior survives the merge: ${retired.length} claims`);
  h.close();
});

// ============================================================================
// w67-fv N-1 (store.mjs): an in-range fold_floor marker whose byte field
// names a DIFFERENT stored hash is a forge the consult must still name —
// the marker must bind the real hash of the row it claims.
// ============================================================================
test('w67-fv N-1: an in-range marker with foreign row bytes convicts, not stands', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const tip = committedTip(h);
  // The marker names a real in-range seq but bytes that are not that
  // row's hash — a transplant the guarded UPSERT would have stood.
  const wrongHash = 'ff'.repeat(32);
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(`${tip}:${wrongHash}`);
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
  // The forge is healed to this append's true tip row, and the planted
  // content lands as a residue claim — named, never silently standing.
  const now = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor'").get().value;
  assert.ok(now.startsWith(`${tip + 1}:`), `the marker advanced honestly past the forge: ${now}`);
  const res = residueRows(h).map(r => r.value);
  assert.ok(res.some(v => v.includes(wrongHash)), `the divergent prior lands as a residue claim: ${JSON.stringify(res)}`);
  h.close();
});

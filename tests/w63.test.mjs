// Wave-63 regression tests: ledger F-1/F-2/F-3/F-7 (deadTail statement
// stops, rawBraces brace desync, `[^;{]*` condition span, gate
// self-coverage), seal F-1..F-5 (dead-signer boundary/type-pun,
// dispatchPure conjunct, verbPos from-line, over-covered unions, seq-0
// claim samples), runtime F-1..F-6 (cap wedge, stale retiring note,
// retire-path errcode split, _verifyKeys catch, canonical rescan,
// corrupt-marker no-overwrite), fixverify F-1..F-6 (braced guard-return
// tails, braceless non-if guard-returns, member-keyed siblingArms, else
// arm latches, nestedHead, declaration-order aliases). The gate probes
// eval a live slice of the shipped scanner — tested code cannot drift
// from shipped code.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync , mkdtempSync, writeFileSync, rmSync} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fixture, designateSuccessor } from './helpers.mjs';
import { signed } from '../src/crypto.mjs';
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
const tipHashAt = (h, seq) => h.f.store.db.prepare("SELECT hash FROM audit WHERE tenant='acme' AND seq=?").get(seq)?.hash ?? null;

// ============================================================================
// w63-ledger F-1: a dead operand's tail stops at `;` — a same-line
// statement after the dead span is live and mints.
// ============================================================================
test('w63-ledger F-1: deadTail does not swallow the `;`-separated tail', () => {
  const r = collectRun([HEAD, "  const z = false && y; authorize(p, ['mid']);", '}'], 'a');
  assert.deepEqual(r.roles, ['mid'], `the call after the dead operand's ';' is live: ${JSON.stringify(r)}`);
  const dead = collectRun([HEAD, "  const z = false && authorize(p, ['hid']);", '}'], 'a');
  assert.equal(dead.roles, null, 'a call INSIDE the dead operand still mints nothing');
  const ors = collectRun([HEAD, "  const z = true || y; authorize(p, ['mid2']);", '}'], 'a');
  assert.deepEqual(ors.roles, ['mid2'], 'the `||` dead arm stops at `;` too');
});

// ============================================================================
// w63-ledger F-2: braces inside a dead operand keep their `lm` positions —
// the `{` that follows stays ordinal-aligned, so the conditional `if`
// mints conditional, not unconditional.
// ============================================================================
test('w63-ledger F-2: dead-operand braces do not desync the rawBraces map', () => {
  const r = collectRun([HEAD, "  const a = false && f({y}), b = q; if (cond) { authorize(p, ['operator']); }", '}'], 'a');
  assert.equal(r.roles, null, `a conditional if arm must not mint unconditional: ${JSON.stringify(r)}`);
  assert.equal(r.any, true, 'the conditional call is reachability evidence');
  const ctl = collectRun([HEAD, "  const a = f({y}), b = q; if (cond) { authorize(p, ['operator']); }", '}'], 'a');
  assert.equal(ctl.roles, null, 'the no-dead-operand control agrees');
});

// ============================================================================
// w63-ledger F-3: a control-head condition carrying `{` parses by
// balance-scan — `if (f({y})) return` still gates the tail.
// ============================================================================
test('w63-ledger F-3: brace-bearing conditions keep the return cut honest', () => {
  const r = collectRun([HEAD, "  if (m[1] === 'a') { if (0) dead(); }",
    "  if (m[1] === 'a') { if (f({y})) return send(1); authorize(p, ['s']); }", '}'], 'a');
  assert.equal(r.roles, null, `the {y}-bearing condition still gates the tail: ${JSON.stringify(r)}`);
  assert.equal(r.any, true, 'the tail is conditional, not invisible');
  const ctl = collectRun([HEAD, "  if (m[1] === 'a') { if (0) dead(); }",
    "  if (m[1] === 'a') { if (f(y)) return send(1); authorize(p, ['s']); }", '}'], 'a');
  assert.equal(ctl.roles, null, 'the brace-free control stays conditional too');
});

// ============================================================================
// w63-fv F-1: a braced conditional whose body exits gates the tail —
// `if (bad) { return; } authorize` is conditional on `!bad`, while a
// dead-for-this-verb frame's exit arms mint nothing at all.
// ============================================================================
test('w63-fv F-1: a braced exit-arm marks the tail conditional', () => {
  const r = collectRun([HEAD, "  if (bad) { return; }", "  authorize(p, ['g']);", '}'], 'a');
  assert.equal(r.roles, null, `a guard-returned tail is conditional: ${JSON.stringify(r)}`);
  assert.equal(r.any, true);
  const dead = collectRun([HEAD, "  if (0) { dead(); }", "  authorize(p, ['g']);", '}'], 'a');
  assert.deepEqual(dead.roles, ['g'], 'a dead-for-everyone frame leaves no conditional mark');
  const nested = collectRun([HEAD, "  if (bad) { if (x) { y(); } return; }", "  authorize(p, ['g']);", '}'], 'a');
  assert.equal(nested.roles, null, 'a deeper-exit arm still conditions the tail');
  const braceless = collectRun([HEAD, "  if (c) return;", "  authorize(p, ['g']);", '}'], 'a');
  assert.equal(braceless.roles, null, 'the braceless guard-return twin stays conditional');
});

// ============================================================================
// w63-fv F-2: braceless `while`/`for` guard-returns gate the tail the same
// way `if` does — `while (c) return;` makes everything after conditional.
// ============================================================================
test('w63-fv F-2: braceless loop guard-returns mark the tail conditional', () => {
  for (const head of ["while (c) return;", "for (const it of items) return serve();", "L: while (cond) return;"]) {
    const r = collectRun([HEAD, `  ${head} authorize(p, ['g']);`, '}'], 'a');
    assert.equal(r.roles, null, `${head} must gate the tail: ${JSON.stringify(r)}`);
    assert.equal(r.any, true);
  }
});

// ============================================================================
// w63-fv F-3: siblingArm is member-keyed — a guard on a member this row's
// verb never binds is a real gate (conditional); a same-member disjoint
// literal (`m[1]==='b'` on an m[1]-bound 'a' row) is dead scope.
// ============================================================================
test('w63-fv F-3: cross-member guard-returns gate; same-member disjoints stay dead', () => {
  const bound = verb => [HEAD2, `  if (m[1]===\x27${verb}\x27) x();`, "  if (m[2]==='x') return serve();", "  authorize(p, ['adm']);", "}"];
  const cross = collectRun(bound('a'), 'a');
  assert.equal(cross.roles, null, `an m[2] guard gates an m[1]-bound row: ${JSON.stringify(cross)}`);
  assert.equal(cross.any, true);
  const same = collectRun([HEAD2, "  if (m[1]==='a') x();", "  if (m[1]==='b') return serve();", "  authorize(p, ['adm']);", "}"], 'a');
  assert.deepEqual(same.roles, ['adm'], `a disjoint same-member arm is dead scope for 'a': ${JSON.stringify(same)}`);
  const orCross = collectRun([HEAD2, "  if (m[1]==='a') x();", "  if (m[2]==='x' || m[2]==='y') return serve();", "  authorize(p, ['adm']);", "}"], 'a');
  assert.equal(orCross.roles, null, 'cross-member || guard stays a gate');
});

// ============================================================================
// w63-fv F-4: else-arm latches — an ours-dispatch `else` is dead scope for
// the row's verb; a sibling arm's `else` is live; a live-head chain's
// `else` is conditional — in braced, braceless, and multiline spellings.
// ============================================================================
test('w63-fv F-4: ours-arm else is dead, sibling-arm else is live', () => {
  const oursDead = collectRun([HEAD, "  if (m[1]==='a') {", "    if (m[1]==='a') { x(); } else authorize(p,['adm']);", "  }", "}"], 'a');
  assert.equal(oursDead.roles, null, `the ours-arm's else never runs for 'a': ${JSON.stringify(oursDead)}`);
  const oursDeadBraceless = collectRun([HEAD, "  if (m[1]==='a') { if (m[1]==='a') x(); else authorize(p,['adm']); }", "}"], 'a');
  assert.equal(oursDeadBraceless.roles, null, 'the braceless ours-else is dead too');
  const oursDeadMulti = collectRun([HEAD, "  if (m[1]==='a') {", "    if (m[1]==='a') {", "      x();", "    } else authorize(p,['adm']);", "  }", "}"], 'a');
  assert.equal(oursDeadMulti.roles, null, 'the multiline ours-else binds to the closed arm');
  const sibLive = collectRun([HEAD, "  if (m[1]==='b') {", "    if (m[1]==='a') { x(); } else authorize(p,['adm']);", "  }", "}"], 'b');
  assert.deepEqual(sibLive.roles, ['adm'], `the sibling arm's else is 'b's live arm: ${JSON.stringify(sibLive)}`);
  const sibLiveBraceless = collectRun([HEAD, "  if (m[1]==='b') { if (m[1]==='a') x(); else authorize(p,['adm']); }", "}"], 'b');
  assert.deepEqual(sibLiveBraceless.roles, ['adm'], 'the braceless sibling-else is live');
  const chainCond = collectRun([HEAD, "  if (m[1]==='b') {", "    if (m[2]==='x') { x(); } else if (m[1]==='a') { y(); } else authorize(p,['adm']);", "  }", "}"], 'b');
  assert.equal(chainCond.roles, null, 'a live-head chain else is conditional, not unconditional');
  assert.equal(chainCond.any, true);
});

// A live `if`'s else is gated on `!cond` — it can never mint
// unconditionally (w63-fv F-4's under-mint direction), and the statement
// after a completed else-arm is free again.
test('w63-fv F-4b: a live braceless/braced else mints conditional', () => {
  for (const shape of ["  if (c) x(); else authorize(p,['g']);", "  if (c) { x(); } else authorize(p,['g']);"]) {
    const r = collectRun([HEAD, shape, '}'], 'a');
    assert.equal(r.roles, null, `${shape} gates on !cond: ${JSON.stringify(r)}`);
    assert.equal(r.any, true);
  }
  const multi = collectRun([HEAD, "  if (c) x();", "  else authorize(p,['g']);", "}"], 'a');
  assert.equal(multi.roles, null, 'a newline else binds the pending if');
  const after = collectRun([HEAD, "  if (c) x(); else y();", "  authorize(p,['g']);", "}"], 'a');
  assert.deepEqual(after.roles, ['g'], 'the statement after a completed else-arm is free');
});

// ============================================================================
// w63-fv F-5: a nested guard head before the ours dispatch gates the arm —
// `if (x) if (m[1]==='a') {…}` is 'a'-conditional on x.
// ============================================================================
test('w63-fv F-5: a nested guard-if before the ours arm stays conditional', () => {
  const r = collectRun([HEAD, "  if (m[1]==='a') { if (x) if (m[1]==='a') { authorize(p,['g']); } }", "}"], 'a');
  assert.equal(r.roles, null, `the outer guard gates the nested ours arm: ${JSON.stringify(r)}`);
  assert.equal(r.any, true);
});

// ============================================================================
// w63-fv F-6: alias resolution is position-keyed — `q[1]==='a'` written
// BEFORE `q = m` never binds the dispatcher retroactively.
// ============================================================================
test('w63-fv F-6: an alias declared after the compare does not bind it', () => {
  const r = collectRun(["if (q[1]==='a') { authorize(p,['g']); }", "const q = m;", "if (q[1]==='a') { authorize(p,['h']); }"], 'a');
  assert.deepEqual(r.roles, ['h'], `pre-declaration q is unbound; post-declaration q binds 'a': ${JSON.stringify(r)}`);
  const unbound = collectRun(["if (q[1]==='a') { authorize(p,['g']); }"], 'a');
  assert.equal(unbound.roles, null, 'a never-declared alias is a gate, not a dispatch');
  assert.equal(unbound.any, true);
  const ctl = collectRun(["const q = m;", "if (q[1]==='a') { authorize(p,['g']); }"], 'a');
  assert.deepEqual(ctl.roles, ['g'], 'a declared-then-compared alias still dispatches');
});

// ============================================================================
// w63-seal F-2: extra `&&` conjuncts off the dispatch fields kill purity —
// a flag/kind operand or a member-compare on an unbound member keeps the
// arm conditional. Path/method/binds alone stay dispatch.
// ============================================================================
test('w63-seal F-2: non-dispatch conjuncts keep the arm conditional', () => {
  const flag = collectRun(["if ((m=/^\\/v1\\/x$/.exec(path)) && req.method==='POST' && flag==='on') {", "  authorize(p,['admin']);", "}"], 'a');
  assert.equal(flag.roles, null, `flag conjunct gates: ${JSON.stringify(flag)}`);
  const memneg = collectRun(["if ((m=/^\\/v1\\/x$/.exec(path)) && req.method==='POST' && m[1]!==null) {", "  authorize(p,['admin']);", "}"], 'a');
  assert.equal(memneg.roles, null, 'an unbound memberneg conjunct gates too');
  const clean = collectRun(["if (path === '/v1/x' && req.method === 'GET') {", "  authorize(p,['admin']);", "}"], 'a');
  assert.deepEqual(clean.roles, ['admin'], 'a pure path+method head still dispatches');
  const bind = collectRun([HEAD, "  authorize(p,['admin']);", "}"], 'a');
  assert.deepEqual(bind.roles, ['admin'], 'the regex-bind head still dispatches');
});

// ============================================================================
// w63-seal F-3: the from-line keeps its own verb's pair filter — an else-if
// chain scanned for 'b' mints 'b's arm, never 'a's role.
// ============================================================================
test('w63-seal F-3: the from-line scan honors its own verb pairs', () => {
  const r = collectRun(["if (m[1]==='a') { authorize(p,['user']); } else if (m[1]==='b') { authorize(p,['admin']); }"], 'b');
  assert.ok(!(r.roles ?? []).includes('user'), `a's arm cannot land on row b: ${JSON.stringify(r)}`);
});

// ============================================================================
// w63-seal F-1: the dead-signer gate — a non-integer `marker_seq` or a seq
// at-or-past the signer's death row refuses the envelope entirely.
// ============================================================================
test('w63-seal F-1: a type-punned marker_seq convicts forged, never honored', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'pun');
  const claim = residueRows(h)[0]?.value;
  assert.ok(claim, 'a residue claim stands');
  // A signed env carrying `marker_seq` as a string skips no check — it is
  // refused outright (the gate is the payload's own seq binding).
  const env = h.f.store.auditSigners['acme'].sign({ tenant_id: 'acme', fold_floor_retired: [claim], fold_floor_retiring: [claim], marker_seq: 'not-an-int' }, 'audit');
  putMarker(h, env, [claim]);
  const kinds = sealKinds(h);
  assert.ok(kinds.includes('floor_marker_retired_forged'), `a type-punned marker_seq is forged: ${kinds}`);
  h.close();
});

test('w63-seal F-1b: a rotated-out signer cannot mint past its death row', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'dead-boundary');
  const claim = residueRows(h)[0]?.value;
  assert.ok(claim, 'a residue claim stands');
  // Rotate the audit key the honest way: designate a successor, land a
  // KEY_ROTATED row, let the fold repoint — the old key stays verifiable
  // (a retired keeper proves historical envelopes) but carries a death
  // row that must bound its marker_seq assertions.
  const auditKid = h.f.tenant('acme').keys.audit.key_id;
  // The vault keeps private material wrapped — the fixture's config key
  // record carries it for test-signing.
  const deadKey = { key_id: auditKid, suite: 'Ed25519', private_key: h.setup.config.tenants.acme.keys.audit.private_key };
  const pending = designateSuccessor(h, 'audit');
  const rot = h.f.store.audit('acme', 'KEY_ROTATED', 'security', pending.key_id, { key_class: 'audit', previous_key_id: auditKid, revoke_old: false }, h.now());
  const rotSeq = rot.envelope.payload.sequence;
  h.f.sealAuditChain(h.p('security'));
  const deadAt = h.f._keyDeaths('acme').get(auditKid);
  assert.equal(deadAt, rotSeq, `the rotation pins the death row: ${deadAt}`);
  // The dead key still verifies — the gate must refuse its assertions at
  // and past the death row. marker_seq == deadAt is an honest-verify-only
  // boundary: the key died before that tip could exist.
  dropResidueGuards(h);
  const boundary = signed({ tenant_id: 'acme', fold_floor_retired: [claim], marker_seq: deadAt, marker_tip_hash: tipHashAt(h, deadAt) }, deadKey, 'audit');
  h.f.store.db.prepare("INSERT INTO meta_kv (tenant,key,value) VALUES ('acme','fold_floor_retired',?) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value")
    .run(JSON.stringify({ claims: [claim], env: boundary }));
  const kinds = sealKinds(h);
  assert.ok(kinds.includes('floor_marker_retired_forged') || kinds.includes('floor_marker_retired_unauthenticated'),
    `a dead-signer envelope at its own death row is refused: ${kinds}`);
  // And below the boundary the same key is honored — the gate is exactly
  // `died <= marker_seq`, not a blanket dead-key refusal.
  const below = signed({ tenant_id: 'acme', fold_floor_retired: [claim], marker_seq: deadAt - 1, marker_tip_hash: tipHashAt(h, deadAt - 1) }, deadKey, 'audit');
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor_retired'")
    .run(JSON.stringify({ claims: [claim], env: below }));
  const kinds2 = sealKinds(h);
  assert.ok(!kinds2.includes('floor_marker_retired_forged') && !kinds2.includes('floor_marker_retired_unauthenticated'),
    `a pre-death marker_seq verifies: ${kinds2}`);
  h.close();
});

// ============================================================================
// w63-runtime F-2: the retiring note's freshness window — a marker env
// whose marker_seq is older than the residue cursor's own scan window
// cannot suppress the retired_echo conviction.
// ============================================================================
test('w63-runtime F-2: a stale retiring note cannot mute the echo', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'stale-note');
  const claim = residueRows(h)[0]?.value;
  assert.ok(claim, 'a residue claim stands');
  // marker_seq far behind any committed tip — the env is authentically
  // signed but its `retiring` claim was minted long before this scan's
  // window, so it reads as replayed, not in-flight. (At fixture scale the
  // scan.seq - 8192 bound is only crossable by a stale-in-history seq.)
  const env = h.f.store.auditSigners['acme'].sign({ tenant_id: 'acme', fold_floor_retired: [claim], fold_floor_retiring: [claim], marker_seq: -100000 }, 'audit');
  putMarker(h, env, [claim]);
  const kinds = sealKinds(h);
  // w64-seal F-2 hardened this further: an env whose marker_seq sits
  // below its own named claims is refused as forged outright — the
  // retired/retiring sets never reach the consult — and the standing
  // row re-heals instead of being suppressed.
  assert.ok(kinds.includes('floor_marker_retired_forged'),
    `a stale env is refused as forged: ${kinds}`);
  assert.ok(kinds.includes('floor_marker_healed'),
    `the unconsumed row re-heals — nothing suppresses it: ${kinds}`);
  h.close();
});

// ============================================================================
// w63-runtime F-6: a corrupt standing marker is never overwritten by the
// retiring note — the consult names it again on the next pass.
// Doctrine updated w70-seal F-4: never-overwritten used to mean IMMORTAL —
// the keep triggers made the corrupt row undeletable while the mint gate
// refused to cover it, so one planted row wedged the suppression plane
// forever. The drain now MURDERS the row inside its guarded span (flagged
// `floor_marker_retired_murdered` post-commit); the invariant that
// survives is the one F-6 actually guarded — corrupt content is never
// laundered into a signed envelope.
// ============================================================================
test('w63-runtime F-6: a corrupt marker is not silently overwritten', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'first');
  h.f.sealAuditChain(h.p('security'));
  dropResidueGuards(h);
  h.f.store.db.prepare("UPDATE meta_kv SET value='not json' WHERE tenant='acme' AND key='fold_floor_retired'").run();
  const kinds1 = sealKinds(h);
  assert.ok(kinds1.includes('floor_marker_retired_malformed'), `corrupt marker convicts: ${kinds1}`);
  // A second heal + seal round must still see the corrupt row — the note
  // savepoint must not have laundered it into a fresh signed envelope.
  healOnce(h, 'second');
  const kinds2 = sealKinds(h);
  // The murder flag rides the first report that observed the kill — the
  // malformed conviction may already have retired on delivery, so the
  // honest check is: the corrupt bytes are gone from disk AND were
  // convicted, never covered by a signed envelope.
  assert.ok(kinds2.includes('floor_marker_retired_murdered') || kinds2.includes('floor_marker_retired_malformed') || kinds2.includes('floor_marker_retired_unauthenticated') || kinds1.includes('floor_marker_retired_murdered'),
    `the corrupt marker's conviction survives the cycle: ${kinds2} / ${kinds1}`);
  const raw = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
  assert.notEqual(raw, 'not json', 'the corrupt value was murdered, not overwritten nor laundered');
  h.close();
});

// ============================================================================
// w63-seal F-4: the heals_dropped over-cover names what it unions — a
// standing row no flag ever claimed rides the union only under a named
// overcovered flag carrying the extra claims.
// ============================================================================
test('w63-seal F-4: cap-overflow unions are named with their claims', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  // Overflow the 256-heal flag cap — every heal past cap drops its own
  // slot, so the retire unions every standing residue row and must name
  // the extras it consumed.
  for (let i = 0; i < 260; i++) healOnce(h, `over-${i}`);
  const seal = h.f.sealAuditChain(h.p('security'));
  const flags = seal.head_watermark_tampered ?? [];
  const healed = flags.find(e => e.kind === 'floor_marker_healed');
  assert.ok(healed, 'the heals convicted');
  // heals_dropped rides its own report row (the cap is an envelope, not a
  // deletion) — the counter attests every heal observed past 256.
  const dropped = flags.find(e => e.kind === 'floor_marker_healed' && (e.heals_dropped ?? 0) > 0);
  assert.ok(dropped, `cap overflow is attested: ${JSON.stringify(flags.filter(f => f.kind === 'floor_marker_healed').map(f => f.heals_dropped))}`);
  const over = flags.find(e => e.kind === 'floor_marker_retired_overcovered');
  assert.ok(over, `unioned extras are named: ${flags.map(f => f.kind)}`);
  assert.ok(Array.isArray(over.claims) && over.claims.length > 0, 'the overcovered flag carries a claim sample');
  h.close();
});

// ============================================================================
// w63-seal F-5: rejected-claim flags carry a bounded claims[] sample —
// eight distinct unshaped values produce flags naming each claim, not one
// collapsed seq:0 slot.
// ============================================================================
test('w63-seal F-5: unshaped env claims are individually named', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'prime');
  h.f.sealAuditChain(h.p('security'));
  // An authentically signed env whose retired list carries unshaped
  // claims — the consult names each into the flag's claims[] sample
  // instead of collapsing them all into one seq:0 slot.
  const unshaped = ['bare', 'no-colon', 'still.no.colon'];
  const _tip = h.f.store.db.prepare("SELECT MAX(seq) m FROM audit WHERE tenant='acme'").get().m;
  const env = h.f.store.auditSigners['acme'].sign({ tenant_id: 'acme', fold_floor_retired: unshaped, marker_seq: _tip, marker_tip_hash: tipHashAt(h, _tip) }, 'audit');
  putMarker(h, env, unshaped);
  const seal = h.f.sealAuditChain(h.p('security'));
  const flags = seal.head_watermark_tampered ?? [];
  const mal = flags.find(e => e.kind === 'floor_marker_retired_malformed');
  assert.ok(mal, `unshaped claims are named: ${flags.map(f => f.kind)}`);
  assert.ok(Array.isArray(mal.claims) && mal.claims.length === unshaped.length,
    `every rejected claim is in the sample: ${JSON.stringify(mal.claims)}`);
  h.close();
});

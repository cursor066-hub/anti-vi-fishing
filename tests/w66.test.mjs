// Wave-66 regression tests: fixverify F-1..F-6 (required marker_tip_hash
// pin, polarity-blind method folds, literal-bearing-view poisoning,
// escaped method literals, plurality else-flip, nested provable heads);
// seal F-1/F-2 (pre-pin envelope replay, ahead-shaped fold_floor heal);
// ledger F-1/F-2 (string-literal route spoof, enclosingGate boundary);
// runtime F-1/F-2 (lc[*].metadata dup probe, prior_evicted accounting).
// Gate probes eval a live slice of the shipped scanner — tested code
// cannot drift from shipped code.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fixture } from './helpers.mjs';
import { DUP_KEY_PROBE } from '../src/store.mjs';
import { digest } from '../src/canonical.mjs';

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
// The marker_tip_hash pin verifies `digest(JSON.parse(envelope).payload)`
// — the stored `hash` column is a different (chained) digest and is
// attacker clay anyway.
const tipHashAt = (h, seq) => {
  const r = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND seq=?").get(seq);
  return r === undefined ? null : digest(JSON.parse(r.envelope).payload);
};
const markerValue = h => h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor'").get()?.value;

// ============================================================================
// w66-fv F-2: method-compare dead judgment must not be polarity-blind —
// `!(req.method==='PUT')`, `f(req.method==='PUT')`, and
// `(req.method==='PUT')===false` under a GET row are all TRUE bodies,
// not dead arms: folding them dead mints the else unconditionally.
// ============================================================================
test('w66-fv F-2: wrapped method compares never fold dead', () => {
  for (const [label, cond] of [
    ['negated', '!(req.method===\'PUT\')'],
    ['call-wrapped', 'f(req.method===\'PUT\')'],
    ['===false', '(req.method===\'PUT\')===false'],
    ['!==false', '(req.method===\'PUT\')!==false'],
  ]) {
    const r = collectRun([HEAD, `  if (${cond}) authorize(p,['spy']);`, "  else authorize(p,['r']);", "}"], 'GET');
    assert.equal(r.any, true, `${label}: the call was seen`);
    assert.equal(r.roles, null, `${label}: a wrapped compare never mints the else unconditional — ${JSON.stringify(r)}`);
  }
  // The bare compare still folds dead — regression pin.
  { const r = collectRun([HEAD, "  if (req.method==='PUT') authorize(p,['spy']);", "  else authorize(p,['r']);", "}"], 'GET');
    assert.deepEqual(r.roles, ['r']); }
  // `req.method !== 'PUT'` under a GET row is provably TRUE — the arm
  // serves unconditionally, its else is dead.
  { const r = collectRun([HEAD, "  if (req.method!=='PUT') authorize(p,['spy']);", "  else authorize(p,['r']);", "}"], 'GET');
    assert.deepEqual(r.roles, ['spy']); }
});

// ============================================================================
// w66-fv F-3: the row's method binding reads the literal-bearing view —
// `req.method === 'PUT'` planted in a comment or string on the head
// line must not re-bind the row, and only the FIRST match decides.
// ============================================================================
test('w66-fv F-3: comment/string method literals cannot poison the row binding', () => {
  { const r = collectRun([HEAD + " // req.method === 'PUT'", "  if (req.method === 'PUT') authorize(p,['spy']);", "  else authorize(p,['r']);", "}"], 'GET');
    assert.deepEqual(r.roles, ['r'], `comment-planted PUT must not re-bind the row: ${JSON.stringify(r)}`); }
  { const r = collectRun([HEAD, "  const s = 'req.method === \"PUT\"';", "  if (req.method === 'PUT') authorize(p,['spy']);", "  else authorize(p,['r']);", "}"], 'GET');
    assert.deepEqual(r.roles, ['r'], `string-planted PUT must not re-bind the row: ${JSON.stringify(r)}`); }
});

// ============================================================================
// w66-fv F-4: escaped method literals decode — `'P\x55T'` IS 'PUT' under
// real JS semantics and folds dead under a GET row; `'G\\ET'` keeps its
// backslash (`\\` decodes to `\`, not 'E') so it is NOT 'GET'.
// ============================================================================
test('w66-fv F-4: escaped method literals decode like the JS engine', () => {
  // hex escape: 'P\x55T' === 'PUT' → dead under GET → else unconditional
  { const r = collectRun([HEAD, "  if (req.method === 'P\\x55T') authorize(p,['spy']);", "  else authorize(p,['r']);", "}"], 'GET');
    assert.deepEqual(r.roles, ['r']); }
  // unicode escape: 'PT' === 'PUT'
  { const r = collectRun([HEAD, "  if (req.method === 'P\\u0055T') authorize(p,['spy']);", "  else authorize(p,['r']);", "}"], 'GET');
    assert.deepEqual(r.roles, ['r']); }
  // codepoint escape: 'P\u{55}T' === 'PUT'
  { const r = collectRun([HEAD, "  if (req.method === 'P\\u{55}T') authorize(p,['spy']);", "  else authorize(p,['r']);", "}"], 'GET');
    assert.deepEqual(r.roles, ['r']); }
  // octal escape: 'P\125T' === 'PUT'
  { const r = collectRun([HEAD, "  if (req.method === 'P\\125T') authorize(p,['spy']);", "  else authorize(p,['r']);", "}"], 'GET');
    assert.deepEqual(r.roles, ['r']); }
  // escaped backslash: 'G\\ET' decodes 'G\ET' — never 'GET' → dead under GET
  { const r = collectRun([HEAD, "  if (req.method === 'G\\\\ET') authorize(p,['spy']);", "  else authorize(p,['r']);", "}"], 'GET');
    assert.deepEqual(r.roles, ['r']); }
  // unknown escape: 'G\ET' IS 'GET' under JS semantics — the arm serves
  { const r = collectRun([HEAD, "  if (req.method === 'G\\ET') authorize(p,['spy']);", "  else authorize(p,['r']);", "}"], 'GET');
    assert.deepEqual(r.roles, ['spy']); }
});

// ============================================================================
// w66-fv F-5: a plurality arm on a member the row cannot prove is a verb
// discriminator is a model gamble — its else mints conditional, never
// unconditional. A member proven by two verb bindings still resolves.
// ============================================================================
test('w66-fv F-5: plurality gambles keep else conditional, proven members still resolve', () => {
  // m[2] bound by no verb — a lone compare is an id-filter, not dispatch.
  { const r = collectRun([HEAD2, "  if (m[2]==='y') authorize(p,['spy']);", "  else authorize(p,['r']);", "}"], 'x');
    assert.equal(r.any, true);
    assert.equal(r.roles, null, `plurality gamble mints conditional: ${JSON.stringify(r)}`); }
  // Two verbs bind m[2] → proven discriminator → the else is 'x''s own.
  { const r = collectRun([HEAD2, "  if (m[2]==='y') authorize(p,['spy']);", "  if (m[2]==='z') authorize(p,['q']);", "  else authorize(p,['r']);", "}"], 'x');
    assert.deepEqual(r.roles, ['r'], `proven-member else resolves unconditionally: ${JSON.stringify(r)}`); }
});

// ============================================================================
// w66-fv F-6 + w66-ledger F-2: enclosing provable heads never gate —
// `if (true)`/`if (m[1]==='a')` (this row's own member) bodies run
// unconditionally whether braced, braceless same-line, or braceless
// across a newline; an unproven enclosing `if (x)` still gates.
// ============================================================================
test('w66-fv F-6: provably-entered nested heads mint unconditional, unproven still gate', () => {
  for (const [label, lines] of [
    ['braced', [HEAD, "  if (true) {", "    if (m[1]==='a') authorize(p,['adm']);", "  }", "}"]],
    ['same-line', [HEAD, "  if (true) if (m[1]==='a') authorize(p,['adm']);", "}"]],
    ['newline', [HEAD, "  if (true)", "    if (m[1]==='a') authorize(p,['adm']);", "}"]],
    ['own-member braceless newline', [HEAD, "  if (m[1]==='a')", "    authorize(p,['adm']);", "}"]],
    ['double own-member', [HEAD, "  if (m[1]==='a') if (m[1]==='a') authorize(p,['adm']);", "}"]],
  ]) {
    const r = collectRun(lines, 'a');
    assert.deepEqual(r.roles, ['adm'], `${label}: provably-entered nested head mints unconditional — ${JSON.stringify(r)}`);
  }
  // An unproven enclosing head still gates — `if (x) if (m[1]==='a')`
  // must not read live through the outer gate.
  for (const [label, lines] of [
    ['same-line unproven outer', [HEAD, "  if (x) if (m[1]==='a') authorize(p,['adm']);", "}"]],
    ['newline unproven outer', [HEAD, "  if (x)", "    if (m[1]==='a') authorize(p,['adm']);", "}"]],
    ['newline flag gate', [HEAD, "  if (flag)", "    authorize(p,['adm']);", "}"]],
    ['newline foreign member', [HEAD, "  if (m[1]==='b')", "    authorize(p,['adm']);", "}"]],
  ]) {
    const r = collectRun(lines, 'a');
    assert.equal(r.roles, null, `${label}: unproven enclosing head keeps the mint conditional — ${JSON.stringify(r)}`);
  }
});

// ============================================================================
// w66-ledger F-1: `req.method === 'X'`/`path === '…'` planted inside a
// string literal can never win the route-head scan — detection runs on
// the masked view and reads the literal back at the same span.
// ============================================================================
test('w66-ledger F-1: string-literal compare spoof cannot win the head scan', () => {
  const src = readFileSync(new URL('../scripts/check.mjs', import.meta.url).pathname, 'utf8');
  const helpers = src.slice(src.indexOf('// === shared source scanners'), src.indexOf('// === end shared source scanners'));
  // Build the masked view with the shipped maskStrings — the probe pair
  // can never drift apart.
  const litRun = (raw, nameSrc) => JSON.parse(probeFile([
    helpers,
    `const d = deadState(); const masked = maskStrings(stripDead(${JSON.stringify(raw)}, d), d);`,
    `globalThis.process.stdout.write(JSON.stringify(literalCmps(masked, ${JSON.stringify(raw)}, ${JSON.stringify(nameSrc)})));`
  ].join('\n')));
  // Real compares decode — method and path both bind at masked positions.
  const raw =    "      if (path === '/healthz' && req.method === 'GET') {";
  assert.deepEqual(litRun(raw, 'req\\.method').map(c => c.value), ['GET']);
  assert.deepEqual(litRun(raw, '\\bpath\\b|url\\.pathname\\b|req\\.url\\b').map(c => c.value), ['/healthz']);
  // A compare inside a STRING literal never leaves the masked view.
  const raw2 = "      if (path === 'x' + \"req.method === 'PUT'\" + 'y') {";
  assert.equal(litRun(raw2, 'req\\.method').length, 0, 'string contents carry no compare');
  // Alternation groups bind the operator for every alternative —
  // `path ===` in a multi-name scan must fold (w66 fix: (?:name) group).
  assert.equal(litRun(raw, '\\bpath\\b|url\\.pathname\\b|req\\.url\\b').length, 1);
});

// ============================================================================
// w66-seal F-1 + w66-fv F-1: the marker_tip_hash pin is REQUIRED — an env
// minted before the pin existed (no field), or pinning a row that does
// not exist, can never authenticate a planted claim set.
// ============================================================================
test('w66-seal F-1: env without marker_tip_hash never authenticates', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'pre-pin-replay');
  const claim = residueRows(h)[0]?.value;
  assert.ok(claim, 'a residue claim stands');
  const tip = committedTip(h);
  // A pre-w65-shaped env — marker_seq only, no tip pin.
  const env = h.f.store.auditSigners['acme'].sign(
    { tenant_id: 'acme', fold_floor_retired: [claim], marker_seq: tip }, 'audit');
  putMarker(h, env, [claim]);
  const kinds = sealKinds(h);
  assert.ok(kinds.some(k => /unauthenticated|forged|premature|unshaped/.test(k)) || residueRows(h).length > 0,
    `a pin-less env is refused — the residue still convicts: ${kinds}`);
  h.close();
});

test('w66-fv F-1: a pin naming a row that never existed refuses the env', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'ghost-row-pin');
  const claim = residueRows(h)[0]?.value;
  assert.ok(claim, 'a residue claim stands');
  const tip = committedTip(h);
  // marker_seq beyond every committed row — the pin recompute finds
  // nothing and the env must refuse (the both-undefined escape is dead).
  const env = h.f.store.auditSigners['acme'].sign(
    { tenant_id: 'acme', fold_floor_retired: [claim], marker_seq: tip + 5000, marker_tip_hash: tipHashAt(h, tip) }, 'audit');
  putMarker(h, env, [claim]);
  const kinds = sealKinds(h);
  assert.ok(kinds.some(k => /unauthenticated|forged|premature|unshaped/.test(k)) || residueRows(h).length > 0,
    `a ghost-row pin is refused — the residue still convicts: ${kinds}`);
  h.close();
});

// ============================================================================
// w66-runtime F-1: DUP_KEY_PROBE descends into `lc[*].metadata` — a dup
// member there keeps the row's scan candidacy. Coverage honestly stops
// one level deeper: arbitrary free-form nesting has no schema sub-object.
// ============================================================================
test('w66-runtime F-1: dup members inside lc[*].metadata keep scan candidacy', t => {
  const h = fixture(t);
  h.ready();
  const db = h.f.store.db;
  db.exec('CREATE TEMP TABLE probe_t (envelope TEXT)');
  const put = env => db.prepare('INSERT INTO probe_t (envelope) VALUES (?)').run(env);
  const hits = () => db.prepare(`SELECT COUNT(*) n FROM probe_t WHERE (0 ${DUP_KEY_PROBE})`).get().n;
  // lc[*].metadata dup — the fifth clause must fetch it.
  put('{"payload":{"type":"T","metadata":{"lifecycle_carryover":[{"type":"H","metadata":{"k":1,"k":2}}]}}}');
  assert.equal(hits(), 1, 'a dup inside lc[*].metadata is probe-visible');
  // lc[*] top-level dup still covered (clause four).
  put('{"payload":{"type":"T","metadata":{"lifecycle_carryover":[{"type":"A","type":"B"}]}}}');
  assert.equal(hits(), 2, 'a lc[*] top-level dup is probe-visible');
  // Honest coverage bound: free-form depth beyond lc[*].metadata has no
  // schema-defined sub-object — documented, not a silent gap.
  put('{"payload":{"type":"T","metadata":{"lifecycle_carryover":[{"type":"H","metadata":{"n":{"a":1,"a":2}}}]}}}');
  assert.equal(hits(), 2, 'deeper free-form nesting is outside the probe contract');
  put('{"payload":{"type":"T","metadata":{"lifecycle_carryover":[{"type":"H","metadata":{"k":1}}]}}}');
  assert.equal(hits(), 2, 'a clean envelope matches nothing');
  db.exec('DROP TABLE probe_t');
  h.close();
});

// ============================================================================
// w66-runtime F-2: the split-budget merge accounts what it drops — the
// signed marker payload carries `prior_evicted` so evicted prior claims
// are counted, never indistinguishable churn.
// ============================================================================
test('w66-runtime F-2: the retired marker signs a prior_evicted count', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  // A standing authenticated marker carrying a prior flood, then a real
  // heal — the seal retires the conviction, the drain merges fresh+prior
  // over the 4096 cap, and the post-commit replay signs the eviction
  // count under the post-cut tip.
  const tip = committedTip(h);
  // Non-`seq:`-shaped priors: a `\d+:` head beyond marker_seq would fail
  // the env's future-claim gate outright (w64-seal F-2) — bare claims
  // authenticate and still exercise the merge cap.
  const prior = Array.from({ length: 4100 }, (_, i) => `prior-${i}:x`);
  const env0 = h.f.store.auditSigners['acme'].sign(
    { tenant_id: 'acme', fold_floor_retired: prior, marker_seq: tip, marker_tip_hash: tipHashAt(h, tip) }, 'audit');
  putMarker(h, env0, prior);
  healOnce(h, 'eviction-pressure');
  h.f.sealAuditChain(h.p('security'));
  const back = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
  assert.ok(back !== undefined, 'the post-commit replay mints a merged marker');
  const pl = JSON.parse(back).env?.payload ?? {};
  assert.equal(typeof pl.prior_evicted, 'number', `the merged marker accounts dropped priors: ${String(back).slice(0, 200)}`);
  assert.ok(pl.prior_evicted >= 1, `a 4101-claim merge over the 4096 cap evicts a counted tail — got ${pl.prior_evicted}`);
  h.close();
});

// ============================================================================
// w66-seal F-2: the ahead-of-tip heal — a `\d+`-shaped plant is covered
// by the rewritten w54 F-1a test (append heals it, residue + envelope
// attest it). Here: a marker at a row that EXISTS but with a wrong hash
// still convicts forged — healing is not forgiveness.
// ============================================================================
test('w66-seal F-2: an existing-seq marker with wrong hash is forged, not healed', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const tip = committedTip(h);
  // seq is real but the hash half names different bytes — a transplant.
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(`${tip}:${'f'.repeat(64)}`);
  const seal = h.f.sealAuditChain(h.p('security'));
  const kinds = (seal.head_watermark_tampered ?? []).map(e => e.kind);
  assert.ok(kinds.some(k => /forged|ahead|healed/.test(k)), `a hash-mismatched in-span marker is named: ${kinds}`);
  h.close();
});

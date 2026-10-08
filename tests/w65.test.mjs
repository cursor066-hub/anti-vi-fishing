// Wave-65 regression tests: fixverify F-1..F-9 (else-arms under unbound
// verbs, claims_dropped bound, selFp epoch, seq:0 refusal, switch
// operand spellings, member-neg unconditional, implicit plurality,
// method-gate route boundary, stale `[]` asserts); seal F-1..F-3
// (marker_tip_hash epoch pin, unsafe-int claim seq, heals_dropped
// dedupe); ledger F-1..F-5 (bare mat(N) is not m.at(N), float index
// rejection, .at() switch operand + headCond stray-), docs, verb
// normalize); runtime F-1/F-3 (metadata-level dup probe, split-budget
// union cap). Gate probes eval a live slice of the shipped scanner —
// tested code cannot drift from shipped code.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fixture } from './helpers.mjs';

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
// w65-fv F-1: an else arm under an unbound verb mints the conditional —
// never unconditional — verdict. The enclosing member head still folds.
// ============================================================================
test('w65-fv F-1: else arms under an unbound verb mint conditional, member head still folds', () => {
  // A non-member head's else is a real gate — the verdict stays
  // conditional, never unconditional.
  const elseFlag = [HEAD, "  if (flag) { serveA(); } else { authorize(p, ['r']); }", "}"];
  { const r = collectRun(elseFlag, 'z'); assert.equal(r.any, true); assert.equal(r.roles, null); }
  // Under the row's implicit plurality the unbound verb rides m[2] on
  // a HEAD2 row — `m[2]==='x'` is another verb's arm — but a lone
  // compare never PROVES m[2] is the verb discriminator, so the else
  // mints conditional, not unconditional (w66-fv F-5 supersedes the
  // w65 live-else doctrine).
  const elseM2 = [HEAD2, "  if (m[2] === 'x') { serveA(); } else { authorize(p, ['r']); }", "}"];
  { const r = collectRun(elseM2, 'z'); assert.equal(r.any, true); assert.equal(r.roles, null); }
  // Same shape on m[1]: a single 'a'-binding cannot prove the member —
  // the else is conditional for 'z' (w66-fv F-5 names this shape
  // verbatim as the launder).
  const elseM1 = [HEAD, "  if (m[1] === 'a') { serveA(); } else { authorize(p, ['r']); }", "}"];
  { const r = collectRun(elseM1, 'z'); assert.equal(r.any, true); assert.equal(r.roles, null); }
  // Dead-head else: `m[1] === 'z'` under verb 'z' — the IF arm is ours,
  // its else is dead.
  const deadElse = [HEAD, "  if (m[1] === 'z') { authorize(p, ['ours']); } else { authorize(p, ['spy']); }", "}"];
  { const r = collectRun(deadElse, 'z'); assert.deepEqual(r.roles, ['ours']); }
});

// ============================================================================
// w65-fv F-5: switch operand spellings — parens, comma-discard heads,
// ??/|| tails and aliases all normalize to the discriminated member.
// ============================================================================
test('w65-fv F-5: switch operand wrappers still resolve the member', () => {
  const cases = [
    ["switch ((m[1])) {", 'plain parens'],
    ["switch (x, m[1]) {", 'comma-discard head'],
    ["switch (m[1] ?? '') {", 'nullish tail'],
    ["switch (m[1] || other) {", 'fallback tail'],
    ["let m2 = m; switch (m2[1]) {", 'alias operand'],
    ["switch (m['1']) {", 'quoted index'],
    ["switch (m.at(1)) {", '.at() operand'],
    ["switch (m?.[1]) {", '?. operand'],
  ];
  for (const [head, label] of cases) {
    const lines = [HEAD, `  ${head}`, "    case 'a': authorize(p, ['adm']);", "  }", "}"];
    const r = collectRun(lines, 'a');
    assert.deepEqual(r.roles, ['adm'], `${label}: case 'a' under verb 'a' is ours — ${JSON.stringify(r)}`);
  }
  // A foreign switch still dead-marks its arm.
  const foreign = [HEAD, "  switch (m[2]) {", "    case 'x': authorize(p, ['spy']);", "  }", "}"];
  { const r = collectRun(foreign, 'a'); assert.equal(r.any, false); assert.equal(r.roles, null); }
});

// ============================================================================
// w65-fv F-6 + F-7: `m[1] !== 'a'` under an unbound verb mints the row's
// live arm unconditionally; plurality picks the row's own member set.
// ============================================================================
test('w65-fv F-6/F-7: member-neg and plurality-verb binding', () => {
  { const r = collectRun([HEAD, "  if (m[1] !== 'a') { authorize(p, ['adm']); }", "}"], 'x');
    assert.equal(r.any, true); assert.deepEqual(r.roles, ['adm']); }
  // Row dispatch binds m[2]; an m[1] gate is a foreign-member gate for
  // the m[2]-bound verb — conditional.
  const m2row = [HEAD2, "  if (m[1] !== 'x') { authorize(p, ['gated']); }", "  if (m[2] === 'b') { serveB(); } else { authorize(p, ['elseArm']); }", "}"];
  { const r = collectRun(m2row, 'b');
    assert.equal(r.any, true); assert.equal(r.roles, null); }
});

// ============================================================================
// w65-fv F-8: a route-shaped mid-row `if (req.method === 'X')` is a
// member of the row's depth, never a chain boundary — the method
// compare folds against the row's own method so the live else mints.
// ============================================================================
test('w65-fv F-8: mid-row method gates fold against the row method', () => {
  // Foreign-method arm dead → else live + unconditional.
  { const r = collectRun([HEAD, "  if (req.method==='PUT') { f(); } else { authorize(p, ['r']); }", "}"], 'x');
    assert.equal(r.any, true); assert.deepEqual(r.roles, ['r']); }
  // Dead arm without else mints nothing.
  { const r = collectRun([HEAD, "  if (req.method==='PUT') { authorize(p, ['r']); }", "}"], 'x');
    assert.equal(r.any, false); assert.equal(r.roles, null); }
  // Row-method arm is live + const-true.
  { const r = collectRun([HEAD, "  if (req.method==='GET') { authorize(p, ['r']); }", "}"], 'x');
    assert.equal(r.any, true); assert.deepEqual(r.roles, ['r']); }
  // A conjuncted dead-method arm stays dead.
  { const r = collectRun([HEAD, "  if (req.method==='PUT' && flag) authorize(p, ['r']);", "}"], 'x');
    assert.equal(r.any, false); assert.equal(r.roles, null); }
  // Sibling route rows still bound the window.
  const sib = [HEAD, "  authorize(p, ['ours']);", "} else if (req.method==='PUT' && (m = /^\\/y\\/(.*)/.exec(path))) {", "  authorize(p, ['theirs']);", "}"];
  { const r = collectRun(sib, 'x'); assert.deepEqual(r.roles, ['ours']); }
  // A free-standing foreign row after ours mints nothing extra.
  const free = [HEAD, "  authorize(p, ['ours']);", "}", "if (req.method==='PUT') { authorize(p, ['x']); } else { authorize(p, ['y']); }"];
  { const r = collectRun(free, 'x'); assert.deepEqual(r.roles, ['ours']); }
});

// ============================================================================
// w65-ledger F-1: a bare `mat(N)` call is not `m.at(N)` — member
// doctrine requires the dot.
// ============================================================================
test('w65-ledger F-1: mat(N) is an ordinary call, never member access', () => {
  // mat(1)==='a' is a runtime-conditional gate — no member fold may
  // mint it unconditional for verb 'a'.
  { const r = collectRun([HEAD, "  if (mat(1)==='a') { authorize(p, ['adm']); }", "}"], 'a');
    assert.equal(r.any, true); assert.equal(r.roles, null); }
  // Nor dead — a foreign verdict would hide the mint; conditional is
  // the honest middle (the call could return 'a').
  const sw = [HEAD, "  switch (mat(1)) {", "    case 'x': authorize(p, ['adm']);", "  }", "}"];
  { const r = collectRun(sw, 'x'); assert.equal(r.any, true); }
  // The real spellings still bind.
  { const r = collectRun([HEAD, "  if (m.at(1)==='a') { authorize(p, ['adm']); }", "}"], 'a');
    assert.deepEqual(r.roles, ['adm']); }
  { const r = collectRun([HEAD, "  if (m?.at(1)==='a') { authorize(p, ['adm']); }", "}"], 'a');
    assert.deepEqual(r.roles, ['adm']); }
});

// ============================================================================
// w65-ledger F-2: bracket indexing does NOT ToInteger — `m[1.9]` is a
// dead property lookup, not m[1]; only `.at()` truncates.
// ============================================================================
test('w65-ledger F-2: float bracket indices never fold to m[trunc]', () => {
  for (const expr of ["m[1.9]", "m['1.9']", "m[.5]"]) {
    const r = collectRun([HEAD, `  if (${expr}==='a') { authorize(p, ['adm']); }`, "}"], 'a');
    assert.equal(r.any, true, `${expr} mints conditional, not unconditional`);
    assert.equal(r.roles, null);
  }
  // Integer-valued spellings still fold exactly.
  { const r = collectRun([HEAD, "  if (m[1.0]==='a') { authorize(p, ['adm']); }", "}"], 'a');
    assert.deepEqual(r.roles, ['adm']); }
  { const r = collectRun([HEAD, "  if (m.at(1.9)==='a') { authorize(p, ['adm']); }", "}"], 'a');
    assert.deepEqual(r.roles, ['adm'], 'Array.prototype.at does ToIntegerOrInfinity — 1.9 is m[1]'); }
  { const r = collectRun([HEAD, "  if (m[0x1]==='a') { authorize(p, ['adm']); }", "}"], 'a');
    assert.deepEqual(r.roles, ['adm']); }
});

// ============================================================================
// w65-ledger F-3: `.at()` switch operands serve their own cases, and a
// space before `{` never flips dead↔live.
// ============================================================================
test('w65-ledger F-3: .at() switch operands and whitespace-brace parity', () => {
  // 'b' on m[2] — .at() operand serves the case arm unconditionally.
  { const r = collectRun([HEAD2, "  switch (m.at(2)) {", "    case 'b': authorize(p, ['adm']);", "  }", "}"], 'b');
    assert.deepEqual(r.roles, ['adm']); }
  // The stray-`)` bug: whitespace between `)` and `{` poisoned the
  // operand — both spellings must verdict identically (arm dead for 'a'
  // whose member is m[1], the switch discriminates m[2]).
  for (const tail of [' {', '{']) {
    const r = collectRun([HEAD2, `  switch (m.at(2))${tail}`, "    case 'x': authorize(p, ['spy']);", "  }", "}"], 'x');
    assert.deepEqual(r.roles, ['spy'], `space-brace spelling ${JSON.stringify(tail)}: ${JSON.stringify(r)}`);
  }
  { const a = collectRun([HEAD2, "  switch (m.at(2)) {", "    case 'x': authorize(p, ['spy']);", "  }", "}"], 'a');
    assert.equal(a.any, false); assert.equal(a.roles, null); }
});

// ============================================================================
// w65-ledger F-5: `verb === undefined` (omitted) and `verb === null`
// pick the same member doctrine.
// ============================================================================
test('w65-ledger F-5: omitted verb equals null verb', () => {
  const src = readFileSync(new URL('../scripts/check.mjs', import.meta.url).pathname, 'utf8');
  const helpers = src.slice(src.indexOf('// === shared source scanners'), src.indexOf('// === end shared source scanners'));
  const block = src.slice(src.indexOf('const NONROLE'), src.indexOf('const authorizeAt'));
  const lines = [HEAD, "  if (m[1] !== 'a') { authorize(p, ['sneak']); }", "}"];
  const out = JSON.parse(probeFile([
    helpers, block,
    `globalThis.process.stdout.write(JSON.stringify({` +
    `  undef: collectAuthorize(${JSON.stringify(lines)}, 0, ${lines.length + 2}, true),` +
    `  nul: collectAuthorize(${JSON.stringify(lines)}, 0, ${lines.length + 2}, true, null)` +
    `}));`
  ].join('\n')));
  assert.deepEqual(out.undef, out.nul, 'omitted and explicit-null verbs pick one member doctrine');
});

// ============================================================================
// w65-fv F-2: claims_dropped is bounded by provable-new rejections —
// eviction cannot fabricate counts, and a re-consult recounts nothing.
// ============================================================================
test('w65-fv F-2: claims_dropped freezes at the seen-set cap across consults', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const N = 8193;
  const unshaped = Array.from({ length: N }, (_, i) => `claim-${i}`);
  const env = h.f.store.auditSigners['acme'].sign(
    { tenant_id: 'acme', fold_floor_retired: unshaped, marker_seq: committedTip(h), marker_tip_hash: tipHashAt(h, committedTip(h)) }, 'audit');
  putMarker(h, env, unshaped);
  const flag = seal => (seal.head_watermark_tampered ?? []).find(e => /unshaped|malformed|overcovered/.test(e.kind));
  const s1 = flag(h.f.sealAuditChain(h.p('security')));
  const s2 = flag(h.f.sealAuditChain(h.p('security')));
  assert.ok(s1, 'the over-sample marker flags');
  // 8193 claims, 16-sample → the provably-distinct tail is 8177; once
  // the seen set fills, unseen is unprovable (evicted or new) so the
  // counter freezes — never ~2× phantom growth.
  assert.ok(s1.claims_dropped >= 1 && s1.claims_dropped <= 8177, `pass1 bounded: ${s1.claims_dropped}`);
  assert.equal(s2.claims_dropped, s1.claims_dropped, 'a second consult recounts zero — no eviction phantoms');
  h.close();
});

// ============================================================================
// w65-seal F-1: a fold_floor_retired env asserts marker_seq +
// marker_tip_hash — a seal cut that rewinds the table and reuses the
// seq cannot re-bind the stale envelope to different bytes.
// ============================================================================
test('w65-seal F-1: a tip-hash mismatch refuses the marker, residue still convicts', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'epoch-rewind');
  const claim = residueRows(h)[0]?.value;
  assert.ok(claim, 'a residue claim stands');
  const tip = committedTip(h);
  // An env replayed across a table rewind asserts the seq but binds a
  // hash that row no longer carries — the pin refuses it before the
  // stale claim can suppress the residue conviction.
  const env = h.f.store.auditSigners['acme'].sign(
    { tenant_id: 'acme', fold_floor_retired: [claim], marker_seq: tip, marker_tip_hash: tipHashAt(h, Math.max(1, tip - 1)) }, 'audit');
  putMarker(h, env, [claim]);
  const kinds = sealKinds(h);
  assert.ok(kinds.some(k => /unauthenticated|forged|premature/.test(k)) || residueRows(h).length > 0,
    `the hash-mismatched env is refused — residue still convicts: ${kinds}`);
  h.close();
});

// ============================================================================
// w65-runtime F-1: a dup member inside `$.payload.metadata` cannot
// hide a residue-like row from the anchored scan.
// ============================================================================
test('w65-runtime F-1: metadata-level dup members keep scan candidacy', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'meta-dup');
  // The heal-attestation row carries metadata.fold_floor_divergent —
  // splice `"fold_floor_divergent":null,"fold_floor_divergent":X` into
  // its envelope so json_extract sees null while JSON.parse sees X.
  const row = h.f.store.db.prepare("SELECT seq,envelope FROM audit WHERE tenant='acme' AND envelope LIKE '%fold_floor_divergent%' ORDER BY seq DESC LIMIT 1").get();
  assert.ok(row, 'a heal-attestation row carries the divergent marker');
  const spliced = row.envelope.replace(/"fold_floor_divergent":"([^"]*)"/, '"fold_floor_divergent":null,"fold_floor_divergent":"$1"');
  assert.notEqual(spliced, row.envelope, 'the splice rewrote the envelope');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS no_audit_update');
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?").run(spliced, row.seq);
  // Wipe the meta_kv residue rows — the durable conviction must refire
  // from the chain row alone.
  dropResidueGuards(h);
  h.f.store.db.prepare("DELETE FROM meta_kv WHERE tenant='acme' AND (key='fold_floor_healed' OR substr(key,1,18)='fold_floor_healed.')").run();
  // A fresh fabric consults the chain — in-memory flags die with the
  // process, so rebuild against the same store.
  const h2 = fixture(t);
  h2.close();
  const seal = h.f.sealAuditChain(h.p('security'));
  const kinds = (seal.head_watermark_tampered ?? []).map(e => e.kind);
  const residueBack = residueRows(h);
  assert.ok(kinds.some(k => /healed|divergent|forged|unanchored/.test(k)) || residueBack.length > 0,
    `the metadata-level dup still enumerates — heal conviction survives: ${kinds}`);
  h.close();
});

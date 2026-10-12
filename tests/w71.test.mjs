// Wave-71 regression tests: fv F-2/F-3 (dead-fn escapes — comma-call,
// bracket member calls, Promise.try, handler assignment — and `!!`/`typeof`
// member-compare folds), ledger F-1..F-5 (enclosing-scope assert shadows,
// in-body destructure/param shadow grammars, capability-shape outside scan,
// predicate-call evidence, NUL-density binary detection), seal F-1..F-4
// (infra-fault propagation on marker consults, dead-pin murder naming,
// apply-side murder, defeated-murder claims before throw), runtime F-1..F-4
// (_seenTotal merges, deferred_apply_error on raw seal faults, in-tx
// deferredAdd guard). Gate probes eval a live slice of the shipped scanner
// — tested code cannot drift from shipped code.
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

const CHECK_SRC = readFileSync(new URL('../scripts/check.mjs', import.meta.url).pathname, 'utf8');
const HELPERS = CHECK_SRC.slice(CHECK_SRC.indexOf('// === shared source scanners'), CHECK_SRC.indexOf('// === end shared source scanners'));
const NONROLE_BLOCK = CHECK_SRC.slice(CHECK_SRC.indexOf('const NONROLE'), CHECK_SRC.indexOf('const authorizeAt'));

const collectRun = (lines, verb) => {
  assert.ok(NONROLE_BLOCK.includes('collectAuthorize'), 'the slice carries the shipped scanner');
  return JSON.parse(probeFile([
    HELPERS, NONROLE_BLOCK,
    `globalThis.process.stdout.write(JSON.stringify(collectAuthorize(${JSON.stringify(lines)}, 0, ${lines.length + 2}, true, ${JSON.stringify(verb)})));`
  ].join('\n')));
};
const HEAD2 = "if ((m = /^\\/x\\/(.*)\\/(.*)/.exec(path))) {";

const residueRows = h => h.f.store.db.prepare("SELECT key,value FROM meta_kv WHERE tenant='acme' AND (key='fold_floor_healed' OR substr(key,1,18)='fold_floor_healed.')").all();
const committedTip = h => h.f.store.db.prepare("SELECT MAX(seq) m FROM audit WHERE tenant='acme'").get().m;
const dropResidueGuards = h => {
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_upd');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_ins');
};
// The version pin (w76-fv F-1) convicts a diverged trigger set at the
// next guarded call, so a plant that dropped the keep guards must put
// them back from the same shared text the drain recreates them with —
// the planted row itself is untouched by the guards once landed.
const restoreResidueGuards = h => { for (const [, sql] of RESIDUE_KEEP_TRIGGERS) h.f.store.db.exec(sql); };
const healOnce = (h, garbage) => {
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(garbage);
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
};
// Force the cut path: one rewritten audit row makes the seal CUT instead
// of taking the 'chain already verifies' return. Deferred-apply arms only
// engage on sealed:true — the post-commit retire drains outside any tx
// there (in-tx drains mint in-tx since w71-runtime F-4).
const dropAuditGuards = h => {
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
    h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
};
const corruptAt = (h, seq) =>
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?")
    .run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', seq);
const divergeChain = h => {
  // Corrupt a sacrificial TIP row appended here — the cut rewinds only
  // this row, so heal claims anchored to earlier seqs stay inside the
  // committed window. A rewind past a claim's own seq makes it
  // premature: drained unsigned, never staged for the deferred apply.
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
  dropAuditGuards(h);
  corruptAt(h, h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get().seq);
};
const putMarker = (h, env, claims = null) => {
  dropResidueGuards(h);
  h.f.store.db.prepare("INSERT INTO meta_kv (tenant,key,value) VALUES ('acme','fold_floor_retired',?) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value")
    .run(JSON.stringify({ claims: claims ?? (env ? (typeof env.payload === 'string' ? JSON.parse(env.payload) : env.payload)?.fold_floor_retired ?? [] : []), env }));
  restoreResidueGuards(h);
};
const markerRow = h => h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
const tipHashAt = (h, seq) => {
  const r = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND seq=?").get(seq);
  return r === undefined ? null : digest(JSON.parse(r.envelope).payload);
};
const tamperKinds = res => (res.head_watermark_tampered ?? []).map(e => e.kind);
const findKind = (res, re) => (res.head_watermark_tampered ?? []).filter(e => re.test(e.kind));

// ============================================================================
// w71-fv F-3: `!!(...)` is a truthiness wrap, not a negation — the pair
// binds through negatedCompare parity + memberCmpFold unwrap so
// `!!(m[2]==='x')` decides the arm like the bare compare; and
// `typeof m[N]` folds to the capture's real type ('string') — the
// `m[N]===` inside it is a type predicate, not a member-vs-verb compare,
// so it neither kills nor votes the side.
// ============================================================================
test('w71-fv F-3: `!!` unwraps and typeof member folds the real capture type', () => {
  // 'x' binds m[1] via the head compare — the verb literal in `m[2]==='x'`
  // then folds const-true for 'x' (the auditor's baseline).
  const H = "if (m[1]==='x') {";
  { const r = collectRun([H, "  if (!!(m[2]==='x')) { authorize(p, ['adm']); }", '}'], 'x');
    assert.deepEqual(r.roles, ['adm'], `x — the !!-wrapped member compare serves its arm: ${JSON.stringify(r)}`); }
  { const r = collectRun([H, "  if (!!(m[2]==='x')) { authorize(p, ['adm']); }", '}'], 'y');
    assert.deepEqual(r.roles, null, `y — the !!-wrapped arm is dead for it: ${JSON.stringify(r)}`); }
  { const r = collectRun([H, "  if (typeof m[2]==='string' && m[2]==='x') { authorize(p, ['adm']); }", '}'], 'x');
    assert.deepEqual(r.roles, ['adm'], `x — a regex capture is always a string: ${JSON.stringify(r)}`); }
  { const r = collectRun([H, "  if (typeof m[2]==='string' && m[2]==='x') { authorize(p, ['adm']); }", '}'], 'y');
    assert.deepEqual(r.roles, null, `y — the compare decides, the typeof is folded truth: ${JSON.stringify(r)}`); }
  { const r = collectRun([H, "  if (typeof m[2]==='number' && m[2]==='x') { authorize(p, ['adm']); }", '}'], 'x');
    assert.deepEqual(r.roles, null, `typeof 'number' on a string capture is a dead conjunct: ${JSON.stringify(r)}`); }
  { const r = collectRun([H, "  if (typeof m[2]==='string') { authorize(p, ['adm']); }", '}'], 'x');
    assert.deepEqual(r.roles, ['adm'], `the always-true typeof predicate mints unconditional: ${JSON.stringify(r)}`); }
});

// ============================================================================
// w71-fv F-2: dead-fn escape arms — an indirect comma call `(0,g)()`, a
// bracket member call `g['call'](x)` / `g?.['apply'](x)`, `Promise.try(g)`,
// and a handler assignment `el.onclick = g` all invoke or expose the
// function — none may blank its body. A plain `x = g` stays dead.
// ============================================================================
test('w71-fv F-2: comma-call, member-call, Promise.try and handler-assignment escapes keep bodies alive', () => {
  for (const escape of ['(0, g)();', "g['call'](null);", "g?.['apply'](null, []);", 'Promise.try(g);', 'el.onclick = g;']) {
    const r = collectRun([HEAD2, "  const g = () => { authorize(p, ['adm']); };", `  ${escape}`, '}'], 'x');
    assert.equal(r.any, true, `${escape} — the body is reachable through the escape: ${JSON.stringify(r)}`);
    assert.equal(r.roles, null, `${escape} — indirect dispatch mints conditional, not unconditional: ${JSON.stringify(r)}`);
  }
  { const r = collectRun([HEAD2, "  const g = () => { authorize(p, ['adm']); };", "  x = g;", '}'], 'x');
    assert.equal(r.any, false, 'a plain reference never invokes — the body is still dead'); }
});

// ============================================================================
// w71-ledger F-3: the outside-scan gate now matches HTTP capability
// SHAPES, not `req.` spellings — any listener, dispatch switch, loose
// method compare, URL parse, sub-path predicate, searchParams read or
// non-authorization header access is an unaudited surface. Pure outbound
// client shapes (connectors) stay exempt. The regex is the shipped one.
// ============================================================================
test('w71-ledger F-3 + w72-fv F-3: the outside-scan binds capability shapes, not spelling', () => {
  // The shipped check is now a block: the big alternation plus a
  // destructure-rebind conjunction. Extract all three literals by
  // anchor and rebuild the shipped conjunction.
  const reB = CHECK_SRC.indexOf('/req\\.method|req\\.url|url\\.pathname');
  const reE = CHECK_SRC.indexOf('/.test(dispatchText)', reB);
  assert.ok(reB > 0 && reE > reB, 'the shipped outside-scan regex is extractable');
  const RE = new RegExp(CHECK_SRC.slice(reB, reE + 1).slice(1, -1));
  // The destructure arm is a `new RegExp` template interpolating REQ_RX
  // (w76-ledger F-3 alias set) — rebuild it from the shipped file's
  // literal bytes by the template's own rules (`\\` → `\`, then the
  // ${REQ_RX} interpolation with the no-alias REQ_RX these probes
  // assume). Tested code cannot drift from shipped code — no eval.
  const deB = CHECK_SRC.indexOf('const dispatchRebind = new RegExp(`');
  const deE = CHECK_SRC.indexOf('`).test(dispatchText)', deB);
  assert.ok(deB > 0 && deE > deB, 'the shipped destructure arm is extractable');
  const REQ_RX = '(?:req|request)';
  const DESTR = new RegExp(CHECK_SRC.slice(deB + 'const dispatchRebind = new RegExp(`'.length, deE).replaceAll('\\\\', '\\').replaceAll('${REQ_RX}', REQ_RX));
  const usB = CHECK_SRC.indexOf('&& /', deE) + 3;
  const usE = CHECK_SRC.indexOf('/.test(dispatchText)', usB);
  assert.ok(usB > 3 && usE > usB, 'the shipped rebind-use arm is extractable');
  const USE = new RegExp(CHECK_SRC.slice(usB, usE + 1).slice(1, -1));
  const flagged = s => RE.test(s) || (DESTR.test(s) && USE.test(s));
  for (const line of [
    "const srv = new Server();",
    "const srv = new http.Server();",
    "srv.listen(8080);",
    "srv['listen'](8080);",
    "srv['on']('request', h);",
    "srv['once']('connection', h);",
    "srv.on('upgrade', (r, s) => {});",
    "srv.once('clientError', h);",
    "switch (q.method) {",
    "switch (r['method']) {",
    "if (m.method == 'GET') {",
    "if (r['method'] == 'GET') {",
    "const u = new URL(q.url, base);",
    "const u = new URL(r['url'], base);",
    "const u = URL.parse(q.url);",
    "q.url.startsWith('/v1');",
    "r['url'].startsWith('/v1');",
    "/^\\/x/.test(q.url);",
    "u.searchParams.get('a');",
    "u['searchParams'].get('a');",
    "req.headers['x-tenant'];",
    "r['headers']['x-tenant'];",
    "req.headers;",
    "q.url.at(0);",
    "path.pathname === '/x';",
    "r['pathname'] === '/x';",
    "req.method",
    "const { url } = req; url === '/v1/x';",
    "const { method, pathname } = req; pathname.startsWith('/v');",
    "const { searchParams } = req; searchParams.get('k');",
  ]) assert.ok(flagged(line), `a dispatch surface must flag: ${line}`);
  for (const line of [
    "import { request } from '../src/connectors.mjs';",
    "const r = http.request('https://api', cb);",
    "span.setAttribute('http.method', 'GET');",
    "const q = request.get(url);",
    "const { url } = config; url === '/x';",
    "const { method } = opts; method === 'PUT';",
  ]) assert.ok(!flagged(line), `an outbound/non-dispatch shape stays exempt: ${line}`);
});

// ============================================================================
// w71-ledger F-4: a credential CALL only serves the claim when its verdict
// is used — a discarded `bearerMatches('x','y');` minted 'issuer bearer
// token' rows. Throwing calls enforce in bare position; predicates count
// behind gate-shaped contexts (condition, continuation, return/case,
// argument, comparison) or an assignment whose binding is read.
// ============================================================================
const AUTH_BLOCK = CHECK_SRC.slice(CHECK_SRC.indexOf('const AUTH_CALL'), CHECK_SRC.indexOf('if (r.roles.length === 1'));
const unguardedAuthRun = lines => {
  assert.ok(AUTH_BLOCK.includes('unguardedAuth'), 'the slice carries the shipped predicate-doctrine block');
  return JSON.parse(probeFile([
    HELPERS, NONROLE_BLOCK,
    `const lines = ${JSON.stringify(lines)};`,
    'const hi = 0;',
    'const wEnd = lines.length;',
    'const windowDeadFn = deadFnLines(lines, hi, wEnd);',
    AUTH_BLOCK,
    'globalThis.process.stdout.write(JSON.stringify({ unguardedAuth }));'
  ].join('\n'))).unguardedAuth;
};
test('w71-ledger F-4: only a USED credential call serves the claim', () => {
  const arm = tail => ["if (req.method === 'GET') {", ...tail, "}"];
  // Discarded predicate verdicts resolve nothing.
  assert.equal(unguardedAuthRun(arm(["  bearerMatches('x','y');", "  serve(req);"])), false,
    'a discarded bearerMatches mints nothing');
  assert.equal(unguardedAuthRun(arm(["  const ok = checkAuth(req);", "  serve(req);"])), false,
    'a bound-but-unread verdict mints nothing');
  // Used verdicts and throwing calls count.
  assert.equal(unguardedAuthRun(arm(["  const ok = checkAuth(req);", "  if (!ok) return deny();", "  serve(req);"])), true,
    'a bound verdict that is read resolves the credential');
  assert.equal(unguardedAuthRun(arm(["  if (!checkAuth(req)) return deny();", "  serve(req);"])), true,
    'a predicate in condition position resolves the credential');
  assert.equal(unguardedAuthRun(arm(["  authorize(req);", "  serve(req);"])), true,
    'a bare throwing call enforces');
  assert.equal(unguardedAuthRun(arm(["  return checkAuth(req);"])), true,
    'a returned verdict is used by the caller');
  assert.equal(unguardedAuthRun(arm(["  const ok = checkAuth(req) && serve(req);"])), true,
    'a predicate feeding a logic continuation is used');
});

// ============================================================================
// w71-ledger F-5 + w73-ledger F-6: planted bytes used to exempt the whole
// file from the secret/sink scans — first one NUL, then one undecodable
// byte. w73 removed the exemption machinery outright: every tracked file
// answers the rules under a tolerant utf8 read.
// ============================================================================
test('w71-ledger F-5/w73-ledger F-6: no byte stream exempts the secret scan', () => {
  // The exemption machinery is gone entirely (w73-ledger F-6): one
  // undecodable byte used to excuse a planted secret from the whole
  // file's audit — every tracked file now answers the rules under a
  // tolerant utf8 read.
  assert.ok(!/isBinary|TEXT_EXT/.test(CHECK_SRC), 'binary-exemption machinery must not return');
  const i = CHECK_SRC.indexOf('const SECRET_RULES');
  const j = CHECK_SRC.indexOf('];', i);
  assert.ok(i > 0 && j > i, 'the shipped SECRET_RULES is extractable');
  const out = JSON.parse(probeFile(`${CHECK_SRC.slice(i, j + 2)}
const dense = Buffer.alloc(8192, 0); for (let k = 0; k < 100; k++) dense[k * 40] = 65;
const planted = Buffer.concat([dense, Buffer.from('AKIA' + 'IOSFODNN7EXAMPLE'), Buffer.from([0, 1, 2])]);
process.stdout.write(JSON.stringify([...SECRET_RULES].filter(([n, r]) => r.test(planted.toString('utf8'))).map(([n]) => n)));`));
  assert.deepEqual(out, ['cloud credential pattern'],
    `a credential behind 8192 NUL-dense bytes still convicts: ${JSON.stringify(out)}`);
});

// ============================================================================
// w71-ledger F-1/F-2: assert-name bindings in ENCLOSING scopes shadow the
// body's asserts — a wrapper param, a bare-block/let/catch/computed-method
// binding, a var or a destructure all neuter the assert calls inside. The
// probe executes the shipped traceability scanner (helpers only, no report
// assert) on crafted test texts.
// ============================================================================
const traceProbe = cases => {
  const dir = mkdtempSync(join(tmpdir(), 'trace-probe-'));
  const root = new URL('..', import.meta.url).pathname;
  writeFileSync(join(dir, 'probe.py'), `import json, sys, pathlib
root = pathlib.Path(${JSON.stringify(root)})
src = (root / 'scripts/traceability.py').read_text()
src = src[:src.index('for row in rows:')]
mod = {'__file__': str(root / 'scripts/traceability.py')}
exec(compile(src, 't.py', 'exec'), mod)
cases = json.loads(pathlib.Path(sys.argv[1]).read_text())
out = []
for c in cases:
    mod['_body_scope_shadows'].clear()
    bodies = mod['_test_bodies'](mod['_strip_comments'](c['text']))
    out.append([mod['_asserts'](b) for b in bodies])
print(json.dumps(out))
`);
  writeFileSync(join(dir, 'cases.json'), JSON.stringify(cases));
  try { return JSON.parse(execFileSync('python3', [join(dir, 'probe.py'), join(dir, 'cases.json')], { encoding: 'utf8', cwd: root }).trim()); }
  finally { rmSync(dir, { recursive: true, force: true }); }
};
test('w71-ledger F-1: enclosing-scope bindings shadow the body asserts', () => {
  const honest = "import assert from 'node:assert';\ntest('EVIL-1 fake', () => {\n  assert.throws(() => { throw new Error('x'); });\n});";
  const [h, param, fn, catchB, methodP, arrowP, varB] = traceProbe([
    { text: honest },
    { text: "import assert from 'node:assert';\nexport const run = (assert) => {\n  test('EVIL-1 fake', () => {\n    assert.throws(() => { throw new Error('x'); });\n  });\n};" },
    { text: "import assert from 'node:assert';\nexport function run(assert) {\n  test('EVIL-1 fake', () => {\n    assert.throws(() => { throw new Error('x'); });\n  });\n}" },
    { text: "import assert from 'node:assert';\ntry {} catch (assert) {\n  test('EVIL-1 fake', () => {\n    assert.ok(1);\n  });\n}" },
    { text: "import assert from 'node:assert';\nconst obj = {\n  ['k'](assert) {\n    test('EVIL-1 fake', () => { assert.ok(1); });\n  }\n};" },
    { text: "import assert from 'node:assert';\n((assert) => {\n  test('EVIL-1 fake', () => { assert.ok(1); });\n})(null);" },
    { text: "import assert from 'node:assert';\nconst noop = () => {};\n{\n  var assert = noop;\n  test('EVIL-1 fake', () => {\n    assert.ok(1);\n  });\n}" },
  ]);
  assert.ok(h[0] >= 1, `honest baseline mints: ${JSON.stringify(h)}`);
  for (const [name, hits] of [['wrapper param', param], ['function param', fn], ['catch binding', catchB], ['computed-method param', methodP], ['IIFE arrow param', arrowP], ['bare-block var', varB]])
    assert.deepEqual(hits, [0], `${name} binding shadows every assert in the body: ${JSON.stringify(hits)}`);
});
test('w71-ledger F-2: in-body destructure/param grammars shadow the assert', () => {
  const [nestedObj, nestedArr, localParam, honestD] = traceProbe([
    { text: "import assert from 'node:assert';\ntest('EVIL-1 fake', () => {\n  const { x: { assert } } = { x: { assert: () => {} } };\n  assert.ok(1);\n});" },
    { text: "import assert from 'node:assert';\ntest('EVIL-1 fake', () => {\n  const { x: [assert] } = { x: [() => {}] };\n  assert.ok(1);\n});" },
    { text: "import assert from 'node:assert';\ntest('EVIL-1 fake', () => {\n  ((assert) => { assert.ok(1); })(() => {});\n});" },
    { text: "import assert from 'node:assert';\ntest('EVIL-1 fake', () => {\n  const { x: { other } } = { x: { other: () => {} } };\n  assert.ok(1);\n});" },
  ]);
  for (const [name, hits] of [['nested object destructure', nestedObj], ['nested array destructure', nestedArr], ['body-local arrow param', localParam]])
    assert.deepEqual(hits, [0], `${name} rebinds the assert name: ${JSON.stringify(hits)}`);
  assert.ok(honestD[0] >= 1, `a non-assert destructure keeps the assert live: ${JSON.stringify(honestD)}`);
});

// ============================================================================
// w71-seal F-1 + runtime F-3: an infra fault inside the marker consult is
// not a verdict — the consult degrades to no-consult and the marker stands
// untouched; it must never be murdered, mislabeled forged, or defeat-flagged.
// ============================================================================
test('w71-seal F-1: a transient consult fault degrades to no-consult — never a verdict', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'consult-fault');
  h.f.sealAuditChain(h.p('security'));
  const standing = markerRow(h);
  assert.ok(standing !== undefined, 'an authentic marker stands');
  const origKeys = h.f.auditPublicKeys;
  h.f.auditPublicKeys = (tenant) => {
    if (new Error().stack.includes('retiredClaimsOf')) throw new Error('transient key-catalog fault');
    return origKeys.call(h.f, tenant);
  };
  let threw = false;
  try { h.f.sealAuditChain(h.p('security')); } catch { threw = true; }
  delete h.f.auditPublicKeys;
  assert.equal(markerRow(h), standing, 'the marker survives a consult fault untouched');
  const res = h.f.sealAuditChain(h.p('security'));
  assert.equal(markerRow(h), standing, 'the same marker re-verifies once the fault clears');
  assert.equal(findKind(res, /floor_marker_retired_(forged|unauthenticated|murdered|pin_murdered|marker_defeated)/).length, 0,
    `no forged/murder/defeat conviction minted from a fault: ${JSON.stringify(tamperKinds(res))}`);
  h.close();
});

// ============================================================================
// w71-seal F-2: a marker pinned to a dead seq can never authenticate
// again — the pin murder kills it and names `pin@<seq>` + the murdered
// claims. A transient tip-row read fault propagates: no murder, no flag.
// ============================================================================
test('w71-seal F-2: a dead pin murders the marker by name; a read fault never does', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const tip = committedTip(h);
  const deadPin = h.f.store.auditSigners['acme'].sign(
    { tenant_id: 'acme', fold_floor_retired: ['9:never-landed'], marker_seq: tip + 5000, marker_tip_hash: tipHashAt(h, tip) }, 'audit');
  putMarker(h, deadPin, ['9:never-landed']);
  // Transient read fault inside the pin-murder probe: it must propagate
  // — never murder on an unread row, never latch the pin flag.
  const origStmt = h.f.store._stmt.bind(h.f.store);
  let hit = true;
  h.f.store._stmt = (...a) => {
    // Scoped to the pin-murder's own tip read — the marker-row read at
    // the top of the probe is already honest (swallows to absent), and
    // everything outside this call must see the real statement.
    if (hit && typeof a[0] === 'string' && a[0].includes('SELECT envelope FROM audit') && new Error().stack.includes('murderDeadRetiredPin')) { hit = false; throw new Error('transient tip-row read fault'); }
    return origStmt(...a);
  };
  let e1 = null;
  try { h.f.sealAuditChain(h.p('security')); } catch (e) { e1 = e; }
  h.f.store._stmt = origStmt;
  assert.ok(hit === false, 'the faulted consult actually drove the pin probe');
  assert.ok(markerRow(h) !== undefined, 'a transient fault cannot murder the marker');
  assert.ok(!((e1?.details?.head_watermark_tampered) ?? []).some(e => e.kind === 'floor_marker_retired_pin_murdered'),
    'no pin-murder conviction off an unread row');
  const res = h.f.sealAuditChain(h.p('security'));
  const pins = findKind(res, /floor_marker_retired_pin_murdered/);
  const entries = pins.length ? pins : findKind(h.f.sealAuditChain(h.p('security')), /floor_marker_retired_pin_murdered/);
  assert.ok(entries.length === 1, `the dead-pin murder names itself: ${JSON.stringify(tamperKinds(res))}`);
  assert.ok(entries[0].claims?.includes(`pin@${tip + 5000}`), `the dead pin position is named: ${JSON.stringify(entries[0])}`);
  assert.ok(entries[0].claims?.includes('9:never-landed'), `the murdered claims are named: ${JSON.stringify(entries[0])}`);
  assert.equal(markerRow(h), undefined, 'the dead-pin row is gone');
  h.close();
});

// ============================================================================
// w71-seal F-3 + fv F-1: the deferred apply murders a proved-corrupt marker
// inside its own guarded span — the old drop path left the wedge standing
// on every drain-less pass — and the queued claims still land under a
// fresh envelope. The murder names itself post-commit.
// ============================================================================
test('w71-seal F-3: the deferred apply murders the corrupt marker inside its savepoint', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'apply-murder-a');
  h.f.sealAuditChain(h.p('security'));
  healOnce(h, 'apply-murder-b');
  // Retain a non-empty queue: the seal must CUT so the post-commit retire
  // drains 'b' outside any tx and stages the replay; a transient apply
  // fault then keeps every claim.
  divergeChain(h);
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  let busyOnce = true;
  h.f.store.db.exec = (sql) => {
    if (busyOnce && String(sql).includes('SAVEPOINT deferred_mint')) { busyOnce = false; throw Object.assign(new Error('database is locked'), { errcode: 5 }); }
    return origExec(sql);
  };
  const res2 = h.f.sealAuditChain(h.p('security'));
  h.f.store.db.exec = origExec;
  assert.equal(res2.sealed, true, 'the cut path is what defers the drain past commit');
  assert.ok(typeof res2.deferred_apply_error === 'string', `the busy apply rides the result: ${res2.deferred_apply_error}`);
  // The cut may legitimately murder the standing marker — its pin dies
  // with the rewritten epoch — so the corrupt row is planted outright,
  // not edited in place. No residue drains on the next pass, so the
  // drain never reaches its own murder arm — the deferred apply is the
  // only path that reads the proved-corrupt row: it murders inside its
  // savepoint and the queued claims still land under a fresh envelope.
  dropResidueGuards(h);
  h.f.store.db.prepare("INSERT INTO meta_kv (tenant,key,value) VALUES ('acme','fold_floor_retired',?) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value").run('{"corrupt');
  restoreResidueGuards(h);
  h.f.sealAuditChain(h.p('security'));
  const res4 = h.f.sealAuditChain(h.p('security'));
  const murdered = findKind(res4, /floor_marker_retired_murdered/);
  assert.ok(murdered.length === 1, `the apply murders the corrupt row by name: ${JSON.stringify(tamperKinds(res4))}`);
  assert.ok(String(murdered[0].claims?.[0]).includes('corrupt'), `the murdered row is named: ${JSON.stringify(murdered[0])}`);
  const landed = JSON.parse(markerRow(h) ?? 'null');
  assert.ok(landed?.env !== undefined, 'the queued claims re-anchor under a fresh envelope');
  const pl = typeof landed.env.payload === 'string' ? JSON.parse(landed.env.payload) : landed.env.payload;
  assert.ok(Array.isArray(pl.fold_floor_retired) && pl.fold_floor_retired.length >= 1, 'the retained queue landed in the fresh marker');
  h.close();
});

// ============================================================================
// w71-seal F-4: a defeated murder names the standing row BEFORE it throws
// — a consult-path drain swallows the error entirely, so the conviction
// must already ride the flag.
// ============================================================================
test('w71-seal F-4: a defeated drain murder names the row before the swallow', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'defeat-drain');
  h.f.sealAuditChain(h.p('security'));
  healOnce(h, 'defeat-drain-b');
  // Corrupt the standing marker and eat the murder's DELETE — staged at
  // the statement layer: a real eating trigger is convictable live-DDL
  // before the write even runs (w76-fv F-1), so the swallow is faked by
  // a delete that reports zero changes while the row reads back standing.
  // The landed probe must name the row it could not remove before the
  // error crosses the drain boundary. The InvariantError then aborts the
  // seal — the conviction must already ride the flag AND the thrown
  // details, not wait for a clean pass.
  dropResidueGuards(h);
  h.f.store.db.prepare("UPDATE meta_kv SET value='{\"corrupt' WHERE tenant='acme' AND key='fold_floor_retired'").run();
  restoreResidueGuards(h);
  const origStmt = h.f.store._stmt.bind(h.f.store);
  const origPrep = h.f.store.db.prepare.bind(h.f.store.db);
  const fake = { run: () => ({ changes: 0 }), get: () => undefined, all: () => [] };
  h.f.store._stmt = (sql) => {
    if (typeof sql === 'string' && sql.includes('DELETE FROM meta_kv') && sql.includes('fold_floor_retired')) return fake;
    return origStmt(sql);
  };
  h.f.store.db.prepare = (sql) => {
    if (typeof sql === 'string' && sql.includes('DELETE FROM meta_kv') && sql.includes('fold_floor_retired')) return fake;
    return origPrep(sql);
  };
  let e1 = null, e2 = null;
  try { h.f.sealAuditChain(h.p('security')); } catch (e) { e1 = e; }
  try { h.f.sealAuditChain(h.p('security')); } catch (e) { e2 = e; }
  h.f.store._stmt = origStmt;
  h.f.store.db.prepare = origPrep;
  for (const e of [e1, e2]) {
    assert.ok(e !== null, 'the armed trigger aborts every seal — no silent wedge');
    assert.equal(e.details?.marker_defeated, 'fold_floor_retired', `the thrown details name the defeated delete: ${JSON.stringify(e.details)}`);
    assert.ok(String(e.details?.claims?.[0]).includes('corrupt'), `the standing row is named on the throw: ${JSON.stringify(e.details)}`);
  }
  assert.ok(String(markerRow(h)).includes('corrupt'), 'the eaten delete leaves the row standing');
  const res3 = h.f.sealAuditChain(h.p('security'));
  const defeated = findKind(res3, /floor_marker_retired_marker_defeated/);
  assert.ok(defeated.length === 1, `the latched conviction delivers on the next clean seal: ${JSON.stringify(tamperKinds(res3))}`);
  assert.ok(String(defeated[0].claims?.[0]).includes('corrupt'), `the standing row is named: ${JSON.stringify(defeated[0])}`);
  const murdered = findKind(res3, /floor_marker_retired_murdered/);
  const murderedAll = murdered.length ? murdered : findKind(h.f.sealAuditChain(h.p('security')), /floor_marker_retired_murdered/);
  assert.ok(murderedAll.length === 1, `the next unopposed drain murders the row: ${JSON.stringify(tamperKinds(res3))}`);
  assert.ok(String(murderedAll[0].claims?.[0]).includes('corrupt'), `the murdered row is named: ${JSON.stringify(murderedAll[0])}`);
  h.close();
});

// ============================================================================
// w71-runtime F-1 (static-parity fix): `_seenTotal` — the monotone
// distinct-claim ledger — merges on all three #wmTamperSet branches. The
// >8192 eviction window is unreachable through the fixture's own
// sequencing in one process, so the merge contract is asserted by grep.
// ============================================================================
test('w71-runtime F-1: _seenTotal max-merges on every tamper-set branch', () => {
  const src = readFileSync(new URL('../src/fabric.mjs', import.meta.url).pathname, 'utf8');
  const set = src.slice(src.indexOf('#wmTamperSet(tenant, flag)'), src.indexOf('#wmTamperClaim(tenant, kind, claim)'));
  assert.ok(/cur\.kind === flag\.kind[\s\S]*?cur\._seenTotal = Math\.max\(cur\._seenTotal \?\? flag\._seenTotal, flag\._seenTotal\)/.test(set),
    'the same-kind merge carries the monotone ledger');
  assert.ok(/prev\._seenTotal = Math\.max\(prev\._seenTotal \?\? flag\._seenTotal, flag\._seenTotal\)/.test(set),
    'the masked-slot merge carries the monotone ledger');
  assert.ok(/_seenTotal: flag\._seenTotal/.test(set), 'a fresh masked slot carries the ledger');
});

// ============================================================================
// w71-runtime F-2: a raw (non-InvariantError) seal fault post-commit still
// attests the deferred-apply fault — the queue retained for retry is named
// on the thrown object, not silently dropped.
// ============================================================================
test('w71-runtime F-2: a raw post-commit seal fault still attests the apply fault', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'raw-fault');
  // The deferred queue only stages from post-commit drains — the seal
  // must CUT (a sealed:false consult mints in-tx since w71-runtime F-4).
  divergeChain(h);
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  let busyOnce = true;
  h.f.store.db.exec = (sql) => {
    if (busyOnce && String(sql).includes('SAVEPOINT deferred_mint')) { busyOnce = false; throw Object.assign(new Error('database is locked'), { errcode: 5 }); }
    return origExec(sql);
  };
  const res0 = h.f.sealAuditChain(h.p('security'));   // commits; apply faults busy → queue retained
  h.f.store.db.exec = origExec;
  assert.equal(res0.sealed, true, 'the cut path staged the deferred queue');
  assert.ok(typeof res0.deferred_apply_error === 'string', `the queue retained for replay: ${res0.deferred_apply_error}`);
  // A raw post-commit fault: the head-watermark re-anchor bumps outside
  // any transaction — the appended tip row kept wmNow above the cut's
  // surviving tip, so the re-anchor arm is on the committed path — and
  // #sealTxCommitted already carries the tenant into the finally's apply.
  const origBump = h.f._bumpHeadWatermark;
  let fired = false;
  h.f._bumpHeadWatermark = (...a) => {
    if (!fired && !h.f.store.db.isTransaction) { fired = true; throw new Error('head-wm post-commit IOERR'); }
    return origBump.apply(h.f, a);
  };
  // Rearm the busy fault so the finally's apply also faults.
  let busyAgain = true;
  h.f.store.db.exec = (sql) => {
    if (busyAgain && String(sql).includes('SAVEPOINT deferred_mint')) { busyAgain = false; throw Object.assign(new Error('database is locked'), { errcode: 5 }); }
    return origExec(sql);
  };
  divergeChain(h);   // the second seal must CUT to reach the post-commit read
  let e1 = null;
  try { h.f.sealAuditChain(h.p('security')); } catch (e) { e1 = e; }
  h.f._bumpHeadWatermark = origBump;
  h.f.store.db.exec = origExec;
  assert.ok(fired, 'the raw post-commit fault actually fired');
  assert.ok(e1 !== null && !(e1 instanceof Error && 'code' in e1 && e1.code), 'the raw fault propagates');
  assert.ok(typeof e1?.deferred_apply_error === 'string' && /locked|contention|deferred/i.test(e1.deferred_apply_error),
    `the apply fault attests on the raw seal fault: ${e1?.deferred_apply_error}`);
  const res = h.f.sealAuditChain(h.p('security'));
  assert.ok(res !== null && typeof res === 'object', 'the tenant still seals after the fault clears');
  h.close();
});

// ============================================================================
// w71-runtime F-4 (static-parity fix): the deferred queue only accepts
// claims OUTSIDE a transaction — a drain inside an abortable tx that
// rolled back would leave phantom claims whose residue deletes rolled
// back with it. The in-tx mint arm must be the immediate else.
// ============================================================================
test('w71-runtime F-4: deferredAdd is gated outside-transaction; in-tx mints in-tx', () => {
  const src = readFileSync(new URL('../src/fabric.mjs', import.meta.url).pathname, 'utf8');
  const drain = src.slice(src.indexOf('const prevFresh'), src.indexOf("db.exec('DROP TRIGGER IF EXISTS fold_residue_keep');", src.indexOf('const prevFresh')));
  // `db.isTransaction` inside the drain is always true (its own savepoint
  // already started) — the gate must snapshot the caller's tx state.
  const snapIdx = src.indexOf('const callerInTx = db.isTransaction;');
  const drainSpIdx = src.indexOf("db.exec('SAVEPOINT residue_drain')", snapIdx);
  assert.ok(snapIdx !== -1 && snapIdx < drainSpIdx,
    'the caller tx state is snapshotted BEFORE the drain savepoint');
  assert.ok(/this\.#sealing\?\.has\(tenant\) && !callerInTx/.test(drain),
    'the defer requires a live seal AND a non-transactional caller');
  assert.ok(/deferredAdd = new Set\(\[\.\.\.retired, \.\.\.prior\]\)/.test(drain),
    'the defer queues the uncapped union for the post-commit replay');
  assert.ok(/else if \(!\(prev !== undefined && prevAuthed === null\)\)[\s\S]*?env = this\.#mintRetiredEnvelope/.test(drain),
    'the in-tx arm mints the envelope in place — never a phantom queue');
});

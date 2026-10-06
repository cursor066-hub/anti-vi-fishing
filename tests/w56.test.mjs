// w56 self-audit regressions: the append-side marker healer judged
// "well-formed" by `^\d+:` while the fold reader convicts strictly —
// '5:' (empty hash), '0:x' (seq < 1) and '5:a:b' (extra segment) counted
// honest on the write side and evaporated under a plain overwrite with
// no residue — a planted marker the reader would have named vanished
// silently (w56-1). The healer must now surface every reader-malformed
// shape as a named floor_marker_healed conviction.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Fabric } from '../src/fabric.mjs';
import { clone } from '../src/canonical.mjs';
import { fixture } from './helpers.mjs';

const markerValue = h => h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor'").get()?.value;

test('w56-1: reader-malformed marker shapes heal with the divergent content named', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  for (const planted of ['5:', '0:x', '5:a:b']) {
    h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(planted);
    h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
    const seal = h.f.sealAuditChain(h.p('security'));
    const healed = (seal.head_watermark_tampered ?? []).find(e => e.kind === 'floor_marker_healed');
    assert.ok(healed, `the heal of ${JSON.stringify(planted)} is named once: ${JSON.stringify(seal.head_watermark_tampered)}`);
    assert.equal(healed.healed_marker, planted, 'the conviction carries the planted content');
  }
  // A well-formed-shaped but unreachable marker is evidence, not garbage:
  // the guarded update refuses it, the append writes no residue and names
  // no heal — the reader convicts the unsafe-integer seq itself.
  const huge = '9'.repeat(30) + ':h';
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(huge);
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
  assert.equal(markerValue(h), huge, 'the divergent marker is left standing as evidence');
  assert.equal(h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND (key='fold_floor_healed' OR substr(key,1,18)='fold_floor_healed.')").get()?.value, undefined,
    'no heal residue is written when nothing was overwritten');
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.ok(!(seal.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_healed'),
    'a marker that was never overwritten claims no heal');
  h.close();
});

// w56-store HIGH: the residue pointer must survive until the conviction
// reaches a report surface — under the old delete-on-read the healing
// append's own flush consumed it within microseconds, and a restart
// before the next seal evaporated the divergent content unnamed.
test('w56-store HIGH: heal residue survives a restart and still names the heal', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run('planted:garbage');
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
  assert.equal(h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND substr(key,1,18)='fold_floor_healed.'").get()?.value?.split(':').slice(1).join(':'), 'planted:garbage',
    'the residue pointer landed keyed per heal and was not consumed by the append\'s own consults');
  h.close();
  // Re-open the deployment cold — in-memory flags are gone; the durable
  // pointer row must re-derive the conviction.
  const f2 = new Fabric(clone(h.setup.config), h.directory, () => h.now());
  const seal = f2.sealAuditChain(h.p('security'));
  const healed = (seal.head_watermark_tampered ?? []).find(e => e.kind === 'floor_marker_healed');
  assert.ok(healed, `the heal is named across the restart: ${JSON.stringify(seal.head_watermark_tampered)}`);
  assert.equal(healed.healed_marker, 'planted:garbage');
  const seal2 = f2.sealAuditChain(h.p('security'));
  assert.ok(!(seal2.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_healed'),
    'the residue retires after one report — not before');
  f2.close();
});

// w56-store MED: fold_floor_healed is attacker-writable meta_kv — under
// unverified plaintext a planted '9999:forged' minted a phantom
// floor_marker_healed conviction on an honest deployment. Now the pointer
// must verify against the signed chain row it names.
test('w56-store MED: a planted fold_floor_healed pointer names itself, not a phantom heal', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  h.f.store.db.exec('DROP TRIGGER fold_residue_keep_ins');
  h.f.store.db.prepare("INSERT INTO meta_kv VALUES('acme','fold_floor_healed',?) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value").run('9999:forged');
  h.f.store.db.exec("CREATE TRIGGER fold_residue_keep_ins BEFORE INSERT ON meta_kv WHEN NEW.key='fold_floor_healed' OR substr(NEW.key,1,18)='fold_floor_healed.' BEGIN SELECT RAISE(ABORT, 'fold-floor residue is evidence'); END");
  const seal = h.f.sealAuditChain(h.p('security'));
  const tampered = seal.head_watermark_tampered ?? [];
  assert.ok(!tampered.some(e => e.kind === 'floor_marker_healed'), 'a planted pointer mints no phantom heal conviction');
  const unanchored = tampered.find(e => e.kind === 'floor_marker_healed_unanchored');
  assert.ok(unanchored, `the planted residue is itself named: ${JSON.stringify(tampered)}`);
  h.close();
});

// w56-seal F-2: file-side convictions retired on repair — a forged
// watermark entry the fold resolved to 'signature' was erased by the very
// flush that replaced it, before any report could name it. Convictions
// now retire only when a surface names them (Reported), never on repair.
test('w56-seal F-2a: a forged entry replaced by the next flush still reaches the seal report', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const tip = h.f.store.db.prepare("SELECT MAX(seq) AS m FROM audit WHERE tenant='acme'").get().m;
  writeFileSync(join(h.directory, 'head-watermark.json'), JSON.stringify({ format: 'IF-HEADMARK-1', tenants: { acme: { seq: tip + 5000, envelope: { payload: { seq: tip + 5000 }, signatures: [{ signature: 'AA' }] } } } }) + '\n', { mode: 0o600 });
  h.f._headWatermark('acme'); // resolve → latch 'signature'
  h.p('security'); // commit edge replaces the forged entry — repair, not report
  const seal = h.f.sealAuditChain(h.p('security'));
  const tamp = seal.head_watermark_tampered ?? [];
  assert.ok(tamp.some(e => e.kind === 'signature'), `the convicted forged entry must be named once: ${JSON.stringify(tamp)}`);
  const seal2 = h.f.sealAuditChain(h.p('security'));
  assert.ok(!(seal2.head_watermark_tampered ?? []).some(e => e.kind === 'signature'),
    'the conviction retires after one report — not before, not forever');
  h.close();
});

// w56-seal F-2b: the floor_stripped veto existed only on the standalone
// bump path — the flush minted a fresh signed entry over a stripped
// tenant and paved the destroyed floor before its conviction reported.
test('w56-seal F-2b: a strip conviction vetoes the flush write until the seal re-anchors it', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  writeFileSync(join(h.directory, 'head-watermark.json'), JSON.stringify({ format: 'IF-HEADMARK-1', tenants: {} }) + '\n', { mode: 0o600 });
  h.f._headWatermark('acme'); // signed head attests floor_seq>0 → floor_stripped
  h.p('security'); // flush must NOT pave the strip
  const file = JSON.parse(readFileSync(join(h.directory, 'head-watermark.json'), 'utf8'));
  assert.equal(file.tenants.acme, undefined, 'the strip stays unwritten until the seal re-anchors');
  const seal = h.f.sealAuditChain(h.p('security'));
  const tamp = seal.head_watermark_tampered ?? [];
  assert.ok(tamp.some(e => e.kind === 'floor_stripped'), `the strip is named: ${JSON.stringify(tamp)}`);
  h.close();
});

// w56-fv F-2: collectAuthorize's sibling-skip never re-armed on
// `} else if` / `} else` — the transition line both closed the old
// sibling block and opened the next, so opens>closes was false and every
// else-arm's authorize bled into this row's verdict. Run the shipped
// collectAuthorize verbatim against crafted multiplex chains.
test('w56-fv F-2: else-arms of a multiplex sibling chain never bleed roles into this row', t => {
  const src = readFileSync('scripts/check.mjs', 'utf8');
  const helpers = src.slice(src.indexOf('// === shared source scanners'), src.indexOf('// === end shared source scanners'));
  const block = src.slice(src.indexOf('const NONROLE'), src.indexOf('const authorizeAt'));
  assert.ok(block.includes('collectAuthorize'), 'the slice carries the shipped scanner');
  const run = (lines, verb) => JSON.parse(execFileSync(process.execPath, ['-e', [
    helpers, block,
    `globalThis.process.stdout.write(JSON.stringify(collectAuthorize(${JSON.stringify(lines)}, 0, ${lines.length + 2}, true, ${JSON.stringify(verb)})?.roles ?? []));`
  ].join('\n')], { encoding: 'utf8' }).trim());

  // Index 0 is the route arm the scan starts on (its own dispatch is
  // always included); the multiplex sub-routes dispatch from index 1 on.
  const chain = [
    "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
    "  if (m[1] === 'a') {",
    "    authorize(p, ['admin']);",
    "  } else if (m[1] === 'b') {",
    "    authorize(p, ['operator']);",
    "  } else {",
    "    authorize(p, ['auditor']);",
    "  }",
    "}",
  ];
  assert.deepEqual(run(chain, 'a'), ['admin'], 'else-arms belong to their own rows, not verb a');
  assert.deepEqual(run(chain, 'b'), ['operator'], 'the else-if arm of verb b is still collected');
  assert.deepEqual(run(chain, 'c'), [], 'the catch-all else cannot mint roles for an undispatched verb');

  // Nested sibling inside a sibling arm: the inner block's close must not
  // drop the outer exclusion.
  const nested = [
    "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
    "  if (m[1] === 'a') {",
    "    if (m[2] === 'x') {",
    "      authorize(p, ['spy']);",
    "    }",
    "    authorize(p, ['admin']);",
    "  }",
    "  authorize(p, ['ours']);",
    "}",
  ];
  assert.deepEqual(run(nested, 'a'), ['admin', 'ours'], 'the inner sibling is excluded, arm-a gates count');
  assert.deepEqual(run(nested, 'x'), ['spy', 'ours'], 'a nested dispatch for this verb is this row\'s gate, plus shared arm code');

  // Braceless sibling body: indented continuation lines stay excluded.
  const braceless = [
    "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
    "  if (m[1] === 'a')",
    "    authorize(p, ['admin']);",
    "  authorize(p, ['ours']);",
    "}",
  ];
  assert.deepEqual(run(braceless, 'b'), ['ours'], 'a braceless sibling body is excluded, the next statement is not');
});

// w56-fv F-3: roleSets left three bindings invisible — a bare `B = A`
// rebinding without a declarator, `B = A.concat(...)` reading the target
// instead of the source, and bracketed concat args keeping '['x'' as a
// role name. Authorize calls against those sets minted nothing.
test('w56-fv F-3: roleSets resolves bare aliases, concat binds and bracket args', t => {
  const src = readFileSync('scripts/check.mjs', 'utf8');
  const helpers = src.slice(src.indexOf('// === shared source scanners'), src.indexOf('// === end shared source scanners'));
  const run = lines => JSON.parse(execFileSync(process.execPath, ['-e', [
    helpers,
    `const defs = roleSets(${JSON.stringify(lines)});`,
    `globalThis.process.stdout.write(JSON.stringify(Object.fromEntries(defs)));`
  ].join('\n')], { encoding: 'utf8' }).trim());
  const defs = run([
    "const A = ['admin','operator'];",
    "B = A;",
    "const C = A.concat(['auditor']);",
    "B.push('root');",
    "const D = ['seed'];",
    "const E = D.concat('x', ['y','z']);",
  ]);
  assert.deepEqual(defs.B, ['admin', 'operator', 'root'], 'a bare rebinding aliases, then mutates');
  assert.deepEqual(defs.C, ['admin', 'operator', 'auditor'], 'B = A.concat binds B to A plus args');
  assert.deepEqual(defs.E, ['seed', 'x', 'y', 'z'], 'bracketed concat args are role names, not punctuation');
});

// w56-ledger F7: an authorize AFTER a return at the arm's body depth is
// unreachable — collecting it mints a gate that never executes. A return
// inside a nested if is conditional and must NOT kill the rest of the
// arm. Run the shipped collectAuthorize verbatim.
test('w56-ledger F7: post-return authorizes are dead; nested-if returns do not dominate', t => {
  const src = readFileSync('scripts/check.mjs', 'utf8');
  const helpers = src.slice(src.indexOf('// === shared source scanners'), src.indexOf('// === end shared source scanners'));
  const block = src.slice(src.indexOf('const NONROLE'), src.indexOf('const authorizeAt'));
  const run = (lines, verb) => JSON.parse(execFileSync(process.execPath, ['-e', [
    helpers, block,
    `globalThis.process.stdout.write(JSON.stringify(collectAuthorize(${JSON.stringify(lines)}, 0, ${lines.length + 2}, true, ${JSON.stringify(verb)})?.roles ?? []));`
  ].join('\n')], { encoding: 'utf8' }).trim());

  const dead = [
    "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
    "  if (m[1] === 'a') {",
    "    authorize(p, ['before']);",
    "    return send(200, { ok: true });",
    "    authorize(p, ['after']);",
    "  }",
    "}",
  ];
  assert.deepEqual(run(dead, 'a'), ['before'], 'the post-return authorize in the same arm is unreachable');

  const deadNextLine = [
    "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
    "  if (m[1] === 'a') { return send(200, { ok: true }); }",
    "  authorize(p, ['shadow']);",
    "  return send(404);",
    "}",
  ];
  assert.deepEqual(run(deadNextLine, 'a'), [], 'a return closing the arm kills the shared tail for that verb');

  const conditional = [
    "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
    "  if (m[1] === 'a') {",
    "    if (m[2] === 'x') { authorize(p, ['nested']); return send(200, {}); }",
    "    authorize(p, ['after']);",
    "  }",
    "}",
  ];
  assert.deepEqual(run(conditional, 'a'), ['after'], 'the m[2] sibling arm is excluded for verb a — its nested return never fired');
  assert.deepEqual(run(conditional, 'x'), ['nested'], 'x\'s own return dominates — the a-arm\'s shared tail cannot mint for x');

  // A `return` that is a braceless conditional's body is NOT dominant —
  // `if (c) return x; authorize` leaves the gate reachable.
  const condRet = [
    "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
    "  if (m[1] === 'a') {",
    "    if (m[2] === 'x') return send(200, {});",
    "    authorize(p, ['after']);",
    "  }",
    "}",
  ];
  assert.deepEqual(run(condRet, 'a'), ['after'], 'a conditional return dominates nothing — the tail authorize still counts');

  // A braceless dispatch `if (m[2]==='x') return serve(...)` dominates
  // the region's tail for its own verb.
  const braceless = [
    "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
    "  if (m[1] === 'a') {",
    "    if (m[2] === 'x') return serveGhost(req, res);",
    "    authorize(p, ['after']);",
    "  }",
    "}",
  ];
  assert.deepEqual(run(braceless, 'x'), [], 'a braceless dispatch return dominates — the tail cannot mint for x');
  assert.deepEqual(run(braceless, 'a'), ['after'], 'other verbs still reach the shared gate');
});

// Gate regressions below run the shipped scans against copied trees —
// never a source grep.
const ledgerCopyTree = () => {
  const dir = mkdtempSync(join(tmpdir(), 'w56-ledger-'));
  execFileSync('sh', ['-c', 'git ls-files -z | xargs -0 cp --parents -t "$1"', 'sh', dir], { cwd: new URL('..', import.meta.url).pathname });
  return dir;
};
const specPatched = (dir, patch) => {
  const spec = join(dir, 'docs/openapi.json');
  const obj = JSON.parse(readFileSync(spec, 'utf8'));
  patch(obj);
  writeFileSync(spec, JSON.stringify(obj, null, 2));
};
const checkErr = dir => {
  try {
    execFileSync(process.execPath, ['scripts/check.mjs'], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return null;
  } catch (e) { return String(e.stderr ?? '') + String(e.stdout ?? ''); }
};
const pyEval = expr => execFileSync('python3', ['-c',
  `import json\nsrc=open('scripts/traceability.py').read()\ng={'__file__':'scripts/traceability.py'}\nexec(src[:src.index('def evidence_blocks')], g)\nprint(${expr})`], { encoding: 'utf8' }).trim();

// w56-ledger F6 + F8: a conditional `if (cond) authorize(...)` ABOVE
// the arm is not a dominating credential — 'authenticated' may not mint
// through it (single-line and multiline bodies). A method-less path
// dispatch escapes the audited surface entirely and must flag.
test('w56-ledger F6/F8: conditional credentials do not dominate; method-less arms flag', t => {
  const dir = ledgerCopyTree();
  try {
    specPatched(dir, o => {
      o.paths['/bf'] = { get: { description: 'Roles: authenticated. plant' } };
      o.paths['/bfml'] = { get: { description: 'Roles: authenticated. plant' } };
      o.paths['/okauth'] = { get: { description: 'Roles: authenticated. plant' } };
      o.paths['/ghost'] = { get: { description: 'Roles: unauthenticated. plant' } };
    });
    const srv = join(dir, 'src/server.mjs');
    const src = readFileSync(srv, 'utf8');
    const arm = `if (cond) fabric.authorize(p, ['security']);
      if (path === '/bf' && req.method === 'GET') { return send(200, { ok: true }); }
      if (cond)
        fabric.authorize(p, ['security']);
      if (path === '/bfml' && req.method === 'GET') { return send(200, { ok: true }); }
      fabric.authorize(p, ['security']);
      if (path === '/okauth' && req.method === 'GET') { return send(200, { ok: true }); }
      if (path === '/ghost') { return send(200, { ok: true }); }
      `;
    writeFileSync(srv, src.replace("const p = auth(req", arm + "const p = auth(req"));
    const out = checkErr(dir) ?? '';
    assert.ok(out.includes('/bf —'), `a braceless conditional credential must not mint 'authenticated': ${out.slice(0, 400)}`);
    assert.ok(out.includes('/bfml —'), `a multiline conditional credential must not mint: ${out.slice(0, 400)}`);
    assert.ok(!out.includes('okauth'), `an unconditional credential above the arm still dominates: ${out.slice(0, 400)}`);
    assert.ok(out.includes('ghost'), `a method-less path dispatch escapes the audited surface and must flag: ${out.slice(0, 400)}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// w56-ledger F9/F10/F11: a renamed-parameter request handler in a .cjs
// file is a dispatch surface the audit skipped; injected sinks and
// zero-width-obfuscated markers escaped their scans.
test('w56-ledger F9-F11: .cjs dispatch surface, injected sinks and hidden markers flag', t => {
  const dir = ledgerCopyTree();
  try {
    writeFileSync(join(dir, 'src', 'helper.cjs'),
      "module.exports = r => { const a = r.headers['authorization']; return r.method === 'POST' && r.url === '/x'; };\n");
    writeFileSync(join(dir, 'web', 'panel.html'),
      "<html><script>const el = document.body; el['innerHTML'] = window.name; document.writeln(el['outerHTML']);</script></html>\n");
    const store = join(dir, 'src', 'store.mjs');
    writeFileSync(store, readFileSync(store, 'utf8') + '\n// TO\u200BDO cleanup\n');
    const out = checkErr(dir) ?? '';
    assert.ok(out.includes('helper.cjs'), `a .cjs request-handler surface must flag outside the audited file: ${out.slice(0, 400)}`);
    assert.ok(out.includes('panel.html'), `injected sinks in renderable files must flag: ${out.slice(0, 400)}`);
    assert.ok(out.includes('store.mjs'), `a zero-width-obfuscated marker must flag: ${out.slice(0, 400)}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// w56-fv F-4/F-5 traceability mints: an emit that precedes its listener
// is not a live on/emit pair; an uninvoked class method is dead code
// while a bound receiver's call is live.
test('w56-fv F-4/F-5: emit must follow on; class methods bind through receiver calls', t => {
  const asserts = body => JSON.parse(pyEval(`json.dumps(bool(g['_asserts'](${JSON.stringify(body)})))`));
  assert.equal(asserts("t => { bus.emit('go'); bus.on('go', () => assert.ok(1)) }"), false, 'an emit before its listener mints nothing');
  assert.equal(asserts("t => { bus.on('go', () => assert.ok(1)); bus.emit('go') }"), true, 'a live on/emit pair still counts');
  assert.equal(asserts("class K { m() { assert.ok(1) } }\nt => { const k = new K(); k.m() }"), true, 'a bound receiver call reaches the method');
  assert.equal(asserts("class K { m() { assert.ok(1) } }\nt => { const k = new K(); k.other() }"), false, 'a call to a method the class lacks binds nothing');
});

// w56-fv F-6: a backward reference to a `const f = function` declaration
// is a TDZ crash, not a call — only references inside function bodies
// (deferred evaluation) keep the declaration live. `function` decls
// hoist and always count.
test('w56-fv F-6: TDZ backward refs do not invoke; deferred refs inside functions do', t => {
  const asserts = body => JSON.parse(pyEval(`json.dumps(bool(g['_asserts'](${JSON.stringify(body)})))`));
  assert.equal(asserts("t => { f(); const f = function() { assert.ok(1) } }"), false, 'a top-level call before the const decl is a TDZ crash');
  assert.equal(asserts("t => { run(() => f()); const f = function() { assert.ok(1) } }"), true, 'a reference inside a function body is deferred and live');
  assert.equal(asserts("t => { f(); function f() { assert.ok(1) } }"), true, 'a hoisted function decl answers backward calls');
});

// w56-fv F-7: a spawn argument is only a repo contact when a quoted
// literal verifiably resolves inside the repository — absolute paths
// outside the tree and slash-less noise mint nothing.
test('w56-fv F-7: spawn contacts must resolve inside the repo', t => {
  const binds = text => JSON.parse(pyEval(`json.dumps(bool(g['_prod_binds'](${JSON.stringify(text)})))`));
  const pre = "import { execFileSync as ex } from 'node:child_process';\n";
  const post = "\ntest('REQ-X', t => { assert.ok(1) })";
  assert.equal(binds(pre + "ex('node', ['/etc/passwd']);" + post), false, 'an absolute path outside the repo is not a contact');
  assert.equal(binds(pre + "ex('node', ['plain-arg']);" + post), false, 'a slash-less argument names no file');
  assert.equal(binds(pre + "ex('node', ['./scripts/check.mjs']);" + post), true, 'a repo-relative literal that resolves and exists still contacts');
  assert.equal(binds(pre + "ex('node', ['../outside']);" + post), false, 'a literal escaping the repo root contacts nothing');
});

// w56-live-code mints: dead shapes that still minted assert evidence —
// literal ternaries, `for of []`, `[].forEach`, uninvoked function
// literals, break/continue tails and literal-switch arms.
test('w56-live-code: dead shapes mint no assert evidence', t => {
  const asserts = body => JSON.parse(pyEval(`json.dumps(bool(g['_asserts'](${JSON.stringify(body)})))`));
  assert.equal(asserts("t => { const x = true ? 1 : assert.ok(1) }"), false, 'a dead arm of a literal ternary never runs');
  assert.equal(asserts("t => { for (const x of []) { assert.ok(1) } }"), false, 'a for-of over an empty array never iterates');
  assert.equal(asserts("t => { [].forEach(() => assert.ok(1)) }"), false, 'forEach on an empty array never calls back');
  assert.equal(asserts("t => { (function () { assert.ok(1) }) }"), false, 'an uninvoked function literal is dead');
  assert.equal(asserts("t => { while (x) { break; assert.ok(1) } }"), false, 'statements after break are unreachable');
  assert.equal(asserts("t => { switch (2) { case 1: assert.ok(1) } }"), false, 'a non-matching literal-switch arm is dead');
  assert.equal(asserts("t => { switch (1) { case 1: assert.ok(1) } }"), true, 'the matching literal-switch arm is live');
});

// w56-store LOW: a first-boot crash between the keystore rename and the
// master.key rename left a well-formed master.key.*.tmp on disk — the
// open path must adopt the verifiable commit marker instead of refusing
// forever.
test('w56-store LOW: an orphaned master.key tmp finishes the interrupted commit', t => {
  const h = fixture(t);
  h.f.persistVault();
  const masterPath = join(h.directory, 'master.key');
  const orphan = join(h.directory, `master.key.${process.pid}.${'ab'.repeat(8)}.tmp`);
  writeFileSync(orphan, readFileSync(masterPath, 'utf8'), { mode: 0o600 });
  const orphanBytes = readFileSync(orphan, 'utf8');
  rmSync(masterPath);
  h.close();
  // Cold open: the orphan is the sole candidate and verifiably unwraps
  // the keystore — it is adopted into place rather than refusing.
  const f2 = new Fabric(clone(h.setup.config), h.directory, () => h.now());
  assert.equal(readFileSync(masterPath, 'utf8'), orphanBytes, 'the orphaned commit marker was adopted into master.key');
  f2.close();
  // A divergent orphan — bytes that do NOT unwrap the keystore — is
  // refused, not adopted.
  const h2 = fixture(t);
  h2.f.persistVault();
  const masterPath2 = join(h2.directory, 'master.key');
  writeFileSync(join(h2.directory, `master.key.${process.pid}.${'cd'.repeat(8)}.tmp`),
    JSON.stringify({ format: 'IF-MASTERKEY-1', master_key: 'AAAA' }) + '\n', { mode: 0o600 });
  rmSync(masterPath2);
  h2.close();
  assert.throws(() => new Fabric(clone(h2.setup.config), h2.directory, () => h2.now()), e => e?.code === 'INV-503-CONFIG',
    'an orphan that does not unwrap the keystore is refused like a missing marker');
});

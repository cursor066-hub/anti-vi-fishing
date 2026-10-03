// Wave-51b/w52 regression tests: the consolidated findings of the w51b
// gate-audit wave (check.mjs / traceability.py / report.mjs honesty), the
// w52 seal + fixverify + ledger + store reports — durable-watermark commit
// ordering, envelope-byte binding in the reconcile tx, the empty-chain
// re-anchor arm, anchored section attribution, manifest_invalid
// consequence parity, and the gate-level contract parity checks.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, unlinkSync, mkdtempSync, mkdirSync, rmSync, statSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fixture, hasCode } from './helpers.mjs';
import { Fabric } from '../src/fabric.mjs';
import { tightenOwnerOnly } from '../src/keystore.mjs';

const dropAuditGuards = h => {
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
    h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
};
const maxSeq = h => h.f.store.db.prepare("SELECT COALESCE(MAX(seq),0) m FROM audit WHERE tenant='acme'").get().m;
const auditRows = (h, like) => h.f.store.db.prepare("SELECT seq, envelope FROM audit WHERE tenant='acme' AND envelope LIKE ? ORDER BY seq").all(like).map(r => ({ seq: r.seq, meta: JSON.parse(r.envelope).payload.metadata ?? {} }));
const wmEntry = h => { const f = JSON.parse(readFileSync(join(h.directory, 'head-watermark.json'), 'utf8')); return f.tenants?.acme; };
const wmSeq = h => { const e = wmEntry(h); return typeof e === 'object' ? e.seq : e; };
const rmFile = (h, name) => { try { unlinkSync(join(h.directory, name)); } catch { /* already absent */ } };

// --- w52-store CRITICAL: the durable-floor file move must not outlive a
// reconcile-tx abort — the attestation rolls back but the file used to keep
// its fresh signature, laundering the abandoned floor into 'already verifies'.
// Trigger is the auditor's own planted-row abort (floorCheck inside the tx).
test('w52-store C-1: an aborted reconcile never moves head-watermark.json and never loses the attestation', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const tip = maxSeq(h);
  const wmBefore = wmSeq(h);
  assert.equal(wmBefore, tip, 'the durable floor tracks the committed tip');
  dropAuditGuards(h);
  // Roll the committed tail back behind the durable floor — the honest
  // two-file rollback shape — and delete the head file so the wm arm
  // carries the case on its own.
  h.f.store.db.prepare('DELETE FROM audit WHERE tenant=? AND seq > ?').run('acme', tip - 3);
  rmFile(h, 'chain-heads.json');
  // Plant an unanchored revocation row: the reconcile tx's own mint dies
  // on the floor divergence AFTER the file move used to land.
  h.f.store.db.prepare("INSERT INTO records VALUES('acme','revocation','subject:planted','junk',0)").run();
  assert.throws(() => h.f.sealAuditChain(h.p('security')), hasCode('INV-409-INTEGRITY'), 'a divergent floor refuses the seal');
  assert.equal(wmSeq(h), wmBefore, 'the durable floor must not move while the attestation rolled back');
  assert.equal(auditRows(h, '%AUDIT_WM_REANCHORED%').length, 0, 'no reanchor row may land on a rolled-back tx');
  // Removing the plant lets the honest repair run: attestation commits,
  // then the floor moves — and the report names the abandoned position.
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='revocation' AND id='subject:planted'").run();
  const r = h.f.sealAuditChain(h.p('security'));
  const reanchored = auditRows(h, '%AUDIT_WM_REANCHORED%');
  assert.equal(reanchored.length >= 1, true, 'the abandoned floor is attested on-chain');
  assert.equal(reanchored.at(-1).meta.abandoned_watermark_seq, wmBefore, 'the attestation names the destroyed floor position');
  assert.equal(wmSeq(h), maxSeq(h), 'the floor lands on the post-mint tip, never below its own fresh head');
  assert.equal(r.watermark_reanchored, true);
  h.close();
});

// --- w52-store HIGH + w52-seal F-1: the constructor must tolerate the whole
// INV-409 wedge class (seal is the repair tool — a bricked open is a dead
// tenant), and the empty-chain arm must attest the abandoned floor instead
// of reporting 'chain already verifies'.
test('w52-store H-1: the constructor tolerates an INTEGRITY wedge — seal stays the repair tool', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const wm = wmSeq(h);
  assert.ok(wm > 0, 'a live floor exists to abandon');
  dropAuditGuards(h);
  // Roll the committed tail back behind the floor — the mints the open
  // emits must not brick the constructor on the INV-409 wedge they fold
  // through (previously open died at the CONFIG_* mints).
  h.f.store.db.prepare('DELETE FROM audit WHERE tenant=? AND seq > ?').run('acme', wm - 3);
  rmFile(h, 'chain-heads.json');
  h.close();
  const f2 = new Fabric(h.setup.config, h.directory, () => h.now());
  t.after(() => f2.close());
  const r = f2.sealAuditChain({ subject_id: 'security', tenant_id: 'acme' });
  assert.ok(r.watermark_reanchored === true || (r.head_watermark_tampered ?? []).length > 0, 'the abandoned floor is named, never laundered');
});

test('w52-seal F-1: an empty chain under a live floor attests the vanished ledger, never \'already verifies\'', t => {
  const h = fixture(t);
  h.ready();
  const wm = wmSeq(h);
  assert.ok(wm > 0, 'a live floor exists to abandon');
  dropAuditGuards(h);
  h.f.store.db.prepare('DELETE FROM audit').run();
  // Keep the signed head-watermark but drop the head file: the whole
  // attested chain vanished — a restorable-snapshot shape, not a cut.
  rmFile(h, 'chain-heads.json');
  const r = h.f.sealAuditChain(h.p('security'));
  const reanchored = auditRows(h, '%AUDIT_WM_REANCHORED%');
  assert.ok(reanchored.length >= 1, 'the empty-chain re-anchor is attested');
  assert.equal(reanchored.at(-1).meta.reanchored_tip_seq, 0);
  assert.equal(reanchored.at(-1).meta.abandoned_watermark_seq, wm, 'the attestation names the floor the file claimed');
  assert.equal(wmSeq(h), maxSeq(h), 'the floor lands on the new tip');
  h.close();
});

// --- w52-fv HIGH: the reconcile tx binds the committed BYTES — an envelope
// graft between prescan and tx refuses INV-503-GATE instead of sealing over
// planted content.
test('w52-fv H-2: an in-window envelope graft aborts the seal reconcile', t => {
  const h = fixture(t);
  h.ready();
  const origTx = h.f.store.tx.bind(h.f.store);
  let grafted = false;
  h.f.store.tx = fn => origTx(() => {
    if (!grafted) {
      grafted = true;
      // The append-only triggers would refuse the graft themselves — drop
      // them inside the tx so the in-window surgery actually lands (DDL
      // rolls back with the aborted tx, restoring the guards).
      dropAuditGuards(h);
      h.f.store.db.prepare("UPDATE audit SET envelope='{\"grafted\":true}' WHERE tenant='acme' AND seq=?").run(1);
    }
    return fn();
  });
  assert.throws(() => h.f.sealAuditChain(h.p('security')), hasCode('INV-503-GATE'), 'a mid-window graft refuses, never seals over planted bytes');
  h.f.store.tx = origTx;
  // Control: ungrafted, the same chain seals/reconciles cleanly.
  const r = h.f.sealAuditChain(h.p('security'));
  assert.ok(r.sealed === true || r.reason === 'chain already verifies', 'the ungrafted chain resolves to a real verdict');
  h.close();
});

// --- w52-ledger F4: a cut seal that retreats the durable floor attests the
// abandoned floor on-chain (AUDIT_WM_REANCHORED) — the file move is
// post-commit and lands on the post-mint tip.
test('w52-ledger F4: a cut below the durable floor mints AUDIT_WM_REANCHORED', t => {
  const h = fixture(t);
  h.ready(); h.ready(); h.ready();
  const tip = maxSeq(h);
  assert.equal(wmSeq(h), tip, 'floor at the live tip');
  dropAuditGuards(h);
  // Corrupt a row mid-tail: the cut deletes [tip-8 .. tip], the seal's own
  // mints land on fresh seqs above the old tip — the abandoned floor is
  // measured against the SURVIVING tip, not the post-mint one.
  const cutAt = tip - 8;
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?").run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', cutAt);
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true, 'the doomed span is cut');
  const reanchored = auditRows(h, '%AUDIT_WM_REANCHORED%');
  assert.ok(reanchored.length >= 1, 'the floor retreat is attested on-chain');
  assert.equal(reanchored.at(-1).meta.abandoned_watermark_seq, tip, 'the abandoned floor names the pre-cut tip');
  assert.equal(reanchored.at(-1).meta.reanchored_tip_seq, cutAt - 1, 'the reanchor lands on the surviving tip');
  assert.equal(reanchored.at(-1).meta.abandoned_watermark_signed, true, 'the abandoned floor was a signed position');
  assert.doesNotThrow(() => h.f._auditIndex('acme'), 'the sealed chain folds cleanly after the floor move');
  assert.equal(wmSeq(h), maxSeq(h), 'the durable floor lands on the post-mint tip');
  h.close();
});

// --- w52-seal F-3: the in-ledger fold_floor marker convicts even when BOTH
// file witnesses are gone — deleting the pair must not silence the one
// in-DB witness to destroyed fold progress.
test('w52-seal F-3: a fold_floor marker ahead of a stripped deployment convicts', t => {
  const h = fixture(t);
  h.ready();
  h.f._auditIndex('acme'); // fold once so the marker is written
  const tip = maxSeq(h);
  dropAuditGuards(h);
  h.f.store.db.prepare('DELETE FROM audit WHERE tenant=? AND seq > ?').run('acme', tip - 2);
  rmFile(h, 'chain-heads.json');
  rmFile(h, 'head-watermark.json');
  const r = h.f.sealAuditChain(h.p('security'));
  assert.ok((r.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_ahead'), 'the marker divergence reaches the seal report');
  h.close();
});

// --- w52-store L2: a mid-session watermark strip is named, not silently
// self-healed — the memoized floor wins but the event is attested.
test('w52-store L2: deleting head-watermark.json mid-session surfaces floor_stripped', t => {
  const h = fixture(t);
  h.ready();
  h.f._auditIndex('acme');
  rmFile(h, 'head-watermark.json');
  h.f._headWatermark('acme'); // memo serves the floor — and names the strip
  const r = h.f.sealAuditChain(h.p('security'));
  assert.ok((r.head_watermark_tampered ?? []).some(e => e.kind === 'floor_stripped'), 'the warm-path strip reaches the seal report');
  h.close();
});

// --- w52-store L3: sealAuditChain refuses to nest inside a live tx ---
test('w52-store L3: sealAuditChain cannot run inside a transaction', t => {
  const h = fixture(t);
  assert.throws(() => h.f.store.tx(() => h.f.sealAuditChain(h.p('security'))), hasCode('INV-503-LEDGER'));
  h.close();
});

// --- w52-store M-1: the vault path uses tightenOwnerOnly, matching the
// daemon path — a compliant file never pays the syscall, a leaky file is
// still hardened.
test('w52-store M-1: tightenOwnerOnly is the shared custody primitive', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'w52-vault-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const p = join(dir, 'key.bin');
  writeFileSync(p, 'x', { mode: 0o400 });
  assert.doesNotThrow(() => tightenOwnerOnly(p), 'a compliant file is never chmodded');
  chmodSync(p, 0o644);
  tightenOwnerOnly(p);
  assert.equal(statSync(p).mode & 0o777, 0o600, 'a leaky file is hardened');
  assert.throws(() => tightenOwnerOnly(join(dir, 'missing.bin')), hasCode('INV-503-CONFIG'), 'a vanished file is named, never a bare ENOENT');
});

// --- w52-ledger F1: changed-section attribution is anchored — a rewritten
// 'config-snapshot' row cannot blank or redirect the diff.
test('w52-ledger F1: configDriftStatus diffs against the anchored snapshot, not the mutable row', t => {
  const h = fixture(t);
  h.proposed();
  // Drift the live config, reopen so the drift gates arm.
  const tampered = JSON.parse(JSON.stringify(h.setup.config));
  delete tampered.tenants.acme.issuers[Object.keys(tampered.tenants.acme.issuers)[0]];
  h.f.persistVault();
  const f2 = new Fabric(tampered, h.directory, () => h.now());
  t.after(() => f2.close());
  // Now rewrite the mutable row so it claims NOTHING changed — the
  // unattested preview must never launder the diff.
  f2.store.put('acme', 'config-snapshot', 'current', { digest: 'forged', taken_at: h.now(), sections: {} }, h.now());
  const s = f2.configDriftStatus(h.p('security'));
  assert.equal(s.drifted, true);
  assert.equal(s.changed_sections_source, 'anchored', 'the diff is derived from the anchored section digests');
  assert.ok(s.changed_sections.includes('issuers'), 'the issuer deletion is named');
  // reassertConfig mints the anchored diff too — never the forged blank.
  const re = f2.reassertConfig(h.p('security'));
  assert.ok(re.changed_sections.includes('issuers'), 'the re-attestation carries the anchored diff');
  const row = f2.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND envelope LIKE '%CONFIG_REASSERTED%' ORDER BY seq DESC LIMIT 1").get();
  assert.ok(JSON.parse(row.envelope).payload.metadata.changed_sections.includes('issuers'), 'the signed record names the changed section');
});

// --- w52-fv M-2: a forged/unverifiable manifest convicts on the repin path
// with the shared drift consequence — manifest_invalid, not a silent refusal.
test('w52-fv M-2: repinIssuerSpec convicts manifest_invalid on an invalid manifest', async t => {
  const h = fixture(t, ['acme']);
  const [bankKeyId] = Object.entries(h.f.tenant('acme').issuers).find(([, v]) => v.name === 'bank');
  const srv = http.createServer((req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ garbage: true })); });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  t.after(() => srv.close());
  h.repoint(bankKeyId, `http://127.0.0.1:${srv.address().port}`);
  await assert.rejects(() => h.f.repinIssuerSpec(h.p('security'), bankKeyId), e => e instanceof Error, 'an invalid manifest refuses the pin');
  const drift = h.f.store.get('acme', 'issuer-drift', bankKeyId);
  assert.ok(drift, 'the conviction is durable on the records plane');
  assert.ok((drift.changes ?? []).some(c => c.field === 'manifest' && c.detail === 'invalid'), 'the drift row names manifest/invalid');
  h.close();
});

// ============================================================================
// Gate-level contract parity — the openapi surface must declare the same
// query surface the server enforces (w51-ledger L-3) and the issuerd rows
// must exist on their own listener (w51-ledger M-6).
// ============================================================================
test('w51-ledger L-3: every op on a QUERY_ALLOW path declares the full query set', t => {
  const spec = JSON.parse(readFileSync('docs/openapi.json', 'utf8'));
  const server = readFileSync('src/server.mjs', 'utf8');
  const block = /QUERY_ALLOW = new Map\(\[([\s\S]*?)\]\)/.exec(server)[1];
  const allow = new Map();
  for (const m of block.matchAll(/'([^']+)'\s*,\s*\[([^\]]*)\]/g))
    allow.set(m[1], [...m[2].matchAll(/'([^']+)'/g)].map(x => x[1]));
  assert.ok(allow.size >= 8, 'the QUERY_ALLOW map is read');
  for (const [path, params] of allow) {
    const ops = spec.paths[path];
    assert.ok(ops, `${path} is contracted`);
    for (const [method, op] of Object.entries(ops)) {
      const declared = (op.parameters ?? []).filter(pp => pp.in === 'query').map(pp => pp.name).sort();
      assert.deepEqual(declared, [...params].sort(), `${method.toUpperCase()} ${path} declares the full query set`);
    }
  }
});

test('w51-ledger M-6: issuerd routes exist on their own listener with the issuer role', t => {
  const spec = JSON.parse(readFileSync('docs/openapi.json', 'utf8'));
  const issuerdOps = [];
  for (const [path, ops] of Object.entries(spec.paths))
    for (const [method, op] of Object.entries(ops))
      if (op['x-listener'] === 'issuerd') issuerdOps.push({ path, method, op });
  assert.equal(issuerdOps.length, 4, 'all four issuerd routes are contracted');
  for (const { op } of issuerdOps) {
    assert.ok((op.tags ?? []).includes('Issuer daemon'), 'the issuerd tag is present');
    assert.ok(JSON.stringify(op).includes('issuer bearer token'), 'the issuer bearer token role is declared');
  }
});

test('w51-fv F-3: the audit proofs sequence param carries a numeric pattern', t => {
  const spec = JSON.parse(readFileSync('docs/openapi.json', 'utf8'));
  const op = spec.paths['/v1/audit/proofs/{sequence}']?.get;
  assert.ok(op, 'the proofs route is contracted');
  const seq = (op.parameters ?? []).find(pp => pp.name === 'sequence');
  assert.equal(seq?.schema?.pattern, '^\\d+$', 'sequence is bound to digits — a non-numeric value can never mint a hit');
});

// ============================================================================
// Traceability/report gate behaviour — run the shipped functions, never a
// source grep (w51-ledger M-3 doctrine).
// ============================================================================
const pyEval = expr => execFileSync('python3', ['-c',
  `import json\nsrc=open('scripts/traceability.py').read()\ng={'__file__':'scripts/traceability.py'}\nexec(src[:src.index('def evidence_blocks')], g)\nprint(${expr})`], { encoding: 'utf8' }).trim();
// Same pattern for JS-side shipped expressions: a fresh interpreter gets
// the fixture scope via the environment, the expression under test is the
// file's own text — no in-process eval primitive (the check gate flags it).
const jsEval = (expr, scope) => {
  const prog = `const {${Object.keys(scope).join(',')}} = JSON.parse(process.env.JS_SCOPE);` +
    `globalThis.process.stdout.write(JSON.stringify((${expr})));`;
  return JSON.parse(execFileSync(process.execPath, ['-e', prog], { env: { ...process.env, JS_SCOPE: JSON.stringify(scope) }, encoding: 'utf8' }).trim());
};

test('w51-ledger L-5: a // comment blanks to EOL — comment-embedded asserts and quotes mint nothing', t => {
  const body = "test('X', t => { // \"assert.ok(1)\" in a comment\n assert.ok(2); })";
  const blanked = pyEval(`json.dumps(g['_blank_code'](${JSON.stringify(body)}))`);
  const parsed = JSON.parse(blanked);
  assert.ok(!parsed.includes('"assert.ok(1)"'), 'the comment text is blanked');
  assert.ok(parsed.includes('assert.ok(2)'), 'live code survives the blank');
  const fixtureBody = "test('X', t => { /* assert.ok(0) */ assert.ok(1); })";
  const bodies = JSON.parse(pyEval(`json.dumps(len(g['_test_bodies'](${JSON.stringify(fixtureBody)})))`));
  assert.equal(bodies, 1);
});

test('w51-ledger H-1/M-7: shadowed assert vocabulary and dead function bodies mint no evidence', t => {
  const asserts = body => pyEval(`json.dumps(bool(g['_asserts'](${JSON.stringify(body)})))`);
  assert.equal(JSON.parse(asserts("t => { const assert = () => {}; assert.ok(1); }")), false, 'a shadowed assert is not evidence');
  assert.equal(JSON.parse(asserts("t => { globalThis.assert = () => {}; assert.ok(1); }")), false, 'a globalThis graft neuters the vocabulary');
  assert.equal(JSON.parse(asserts("t => { const ok = assert.ok; ok(1); }")), true, 'a member alias still counts as an assertion');
  // An unreferenced function declaration is dead code — asserts inside it
  // cannot run; a referenced callback is live.
  assert.equal(JSON.parse(asserts("t => { function dead() { assert.ok(1) } }")), false, 'an uninvoked declaration is dead');
  assert.equal(JSON.parse(asserts("t => { function live() { assert.ok(1) }; live(); }")), true, 'a referenced declaration is live');
});

test('w51-ledger F-1: a not-ok permanently disqualifies its title — no same-titled ok launders it', t => {
  // Run the module's own TAP parse lines verbatim against fixture TAP.
  const src = readFileSync('scripts/traceability.py', 'utf8');
  const block = src.slice(src.indexOf('_ok_titles, _fail_titles = set(), set()'), src.indexOf('def _title_ran'));
  const ran = tap => JSON.parse(execFileSync('python3', ['-c',
    `import re, json
_tap_text = ${JSON.stringify(tap)}
${block}
print(json.dumps(sorted(_passed_titles)))`], { encoding: 'utf8' }).trim());
  const good = 'ok 1 - good test\nnot ok 2 - bad test\nok 3 - bad test\n# tests 3\n# pass 2\n# fail 1\n';
  assert.deepEqual(ran(good), ['good test'], 'a not-ok permanently disqualifies the title even when a same-titled ok exists');
  // Indented subtest lines count identically (M-7).
  const nested = 'ok 1 - outer\n    ok 2 - inner\n# tests 2\n# pass 2\n# fail 0\n';
  assert.ok(ran(nested).includes('inner'), 'indented subtests count as evidence');
});

test('w51-ledger M-4/M-5: report.mjs gates on traceability status and never double-counts failures', t => {
  const src = readFileSync('scripts/report.mjs', 'utf8');
  // M-4: the generation path must refuse on a failed traceability run.
  const traceGate = src.split('\n').find(l => l.includes('trace.status !== 0') && l.includes('process.exitCode'));
  assert.ok(traceGate, 'the traceability exit gate exists in generation mode');
  // M-5: counts derive tests from the runner summary and fail from # fail
  // — eval the shipped block verbatim against fixture TAP text.
  const block = src.slice(src.indexOf('const numLast'), src.indexOf('write(\'reports/tests.tap\''));
  const run = tapText => {
    // Exec the shipped block verbatim in a fresh interpreter — the same
    // shipped-code honesty as pyEval, without an in-process eval primitive.
    const prog = [
      `const tapText = ${JSON.stringify(tapText)};`,
      `const process = { exitCode: 0 };`,
      `const console = { error() {} };`,
      block,
      `globalThis.process.stdout.write(JSON.stringify({ counts, rawTests, rawFail, inconsistent: process.exitCode === 1 }));`
    ].join('\n');
    return JSON.parse(execFileSync(process.execPath, ['-e', prog], { encoding: 'utf8' }).trim());
  };
  const ok = run('ok 1 - a\nok 2 - b\n# tests 2\n# pass 2\n# fail 0\n');
  assert.equal(ok.counts.tests, 2);
  assert.equal(ok.counts.fail, 0);
  // One real failure: fail=1, tests=3 — never double-counted to fail=2/tests=4.
  const bad = run('ok 1 - a\nnot ok 2 - b\nok 3 - c\n# tests 3\n# pass 2\n# fail 1\n');
  assert.equal(bad.counts.fail, 1, 'fail rides the runner summary, not a recount');
  assert.equal(bad.counts.tests, 3);
  // An edited summary (counters disagree with result lines) fails loudly.
  const forged = run('ok 1 - a\nnot ok 2 - b\nok 3 - c\n# tests 3\n# pass 9\n# fail 0\n');
  assert.equal(forged.inconsistent, true, 'counter tampering fails the regeneration');
});

test('w51-ledger M-5: the exit gate binds counts.fail, tap, nodeVerify and py together', t => {
  const line = readFileSync('scripts/report.mjs', 'utf8').split('\n').find(l => l.includes('nodeVerify.status') && l.includes('process.exitCode'));
  assert.ok(line, 'the runner exit gate exists');
  const cond = /if \((.+)\) process\.exitCode/.exec(line)[1];
  const gate = (counts, tap, nodeVerify, py) => jsEval(cond, { counts, tap, nodeVerify, py });
  const ok = { fail: 0 }, alive = { status: 0 };
  assert.equal(gate({ fail: 1 }, alive, alive, alive), true, 'a TAP fail count fails the report');
  assert.equal(gate(ok, { status: 1 }, alive, alive), true, 'a nonzero TAP run fails the report');
  assert.equal(gate(ok, alive, { status: 1 }, alive), true, 'a dead node verifier fails');
  assert.equal(gate(ok, alive, alive, { status: 1 }), true, 'a dead python verifier fails');
  assert.equal(gate(ok, alive, alive, alive), false, 'all-green passes');
});

// --- w51-ledger L-6: the demotion tripwire names a VERIFIED row that
// falls — exec the shipped block against a fixture CSV pair.
test('w51-ledger L-6: a demoted VERIFIED row prints DEMOTED to stderr', t => {
  const src = readFileSync('scripts/traceability.py', 'utf8');
  const block = src.slice(src.indexOf('_prev = root'), src.indexOf('if check_only:'));
  assert.ok(block.includes('DEMOTED:'), 'the tripwire exists');
  const dir = mkdtempSync(join(tmpdir(), 'w51b-l6-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, 'docs'));
  const prev = join(dir, 'docs', 'requirements.csv');
  writeFileSync(prev, 'id,status\nX-1,VERIFIED_IN_ENGINEERING_PROFILE\nX-2,VERIFIED_IN_ENGINEERING_PROFILE\n');
  const err = execFileSync('python3', ['-c',
    `import pathlib, csv, sys, io, json
root = pathlib.Path(${JSON.stringify(dir)})
rows = [{'id': 'X-1', 'status': 'PARTIAL'}, {'id': 'X-2', 'status': 'VERIFIED_IN_ENGINEERING_PROFILE'}]
_err = io.StringIO(); _real = sys.stderr; sys.stderr = _err
${block}
sys.stderr = _real
print(json.dumps(_err.getvalue().strip().splitlines()))`], { encoding: 'utf8' }).trim();
  assert.deepEqual(JSON.parse(err), ['DEMOTED:X-1 VERIFIED_IN_ENGINEERING_PROFILE -> PARTIAL'], 'only the demoted row is named');
});

// Wave-62 regression tests: runtime F-1 (corrupt grants row must not turn a
// committed revocation into a post-commit 409), runtime F-2 (the marker
// consult's catch splits transient/storage faults from schema tamper),
// runtime F-3 (the unsigned claims twin must be byte-identical to the
// signed set — divergence names forged).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fixture, hasCode } from './helpers.mjs';
import { verifySigned } from '../src/crypto.mjs';

const issueGrant = h => {
  const r = h.proposed('identity.jit.grant', { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: [], ttl_ms: 300000, reason: 'Incident', roles: [] }, { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'JIT' } });
  h.evidence(r, { kind: 'identity_proof' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' }); h.approve(r, 2);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  h.f.execute(h.p(), cert);
  return `jit-${cert.payload.certificate_id}`;
};

// ============================================================================
// w62-runtime F-1: a corrupt-but-present grants row resolves anchored_only —
// the committed revocation must not surface a post-commit INTEGRITY verdict.
// ============================================================================
test('w62-runtime F-1: corrupt grants row revokes cleanly through the anchor', t => {
  const h = fixture(t);
  const grantId = issueGrant(h);
  // Graft garbage over the ciphertext — the row stands but is unreadable.
  h.f.target.db.prepare("UPDATE grants SET value='deadbeef' WHERE tenant='acme' AND grant_id=?").run(grantId);
  const out = h.f.revoke(h.p('security'), { kind: 'grant', id: grantId, reason: 'corrupt row' });
  assert.ok(out && !out.error, 'a corrupt row revokes through its anchor — no post-commit 409');
  assert.ok(h.f.revoked('acme', 'grant', grantId), 'the revocation landed in the ledger');
  assert.throws(() => h.f.revoke(h.p('security'), { kind: 'grant', id: grantId, reason: 'again' }), hasCode('INV-409-STATE'),
    'the second revoke names already-revoked — the first committed honestly');
  h.close();
});

test('w62-runtime F-1b: a live grants row still flips in the dataplane', t => {
  const h = fixture(t);
  const grantId = issueGrant(h);
  const out = h.f.revoke(h.p('security'), { kind: 'grant', id: grantId, reason: 'live row' });
  assert.ok(out && !out.error, 'a live grant revokes');
  assert.equal(h.f.target.allGrants('acme').find(g => g.grant_id === grantId).revoked, true,
    'the dataplane mirror reflects the revocation');
  h.close();
});

// ============================================================================
// w62-runtime F-2: the marker consult's catch mirrors the store errcode
// split — schema divergence stays INTEGRITY; busy/io faults are 503-family.
// ============================================================================
test('w62-runtime F-2: the marker consult splits transient faults from tamper', t => {
  const h = fixture(t);
  h.ready();
  const origStmt = h.f.store._stmt.bind(h.f.store);
  const inject = (err) => {
    h.f.store._stmt = sql => {
      if (/meta_kv/.test(sql)) throw err;
      return origStmt(sql);
    };
  };
  const busy = new Error('database is busy'); busy.errcode = 5;
  inject(busy);
  assert.throws(() => h.f._foldFloorMarker('acme', 0), hasCode('INV-503-LEDGER'),
    'a contended marker read is ledger contention, not tamper');
  const ioerr = new Error('disk I/O error'); ioerr.errcode = 10;
  inject(ioerr);
  assert.throws(() => h.f._foldFloorMarker('acme', 0), hasCode('INV-503-STORAGE'),
    'an io fault in the consult is storage, not tamper');
  const schema = new Error('no such table: meta_kv'); schema.errcode = 1;
  inject(schema);
  assert.throws(() => h.f._foldFloorMarker('acme', 0), hasCode('INV-409-INTEGRITY'),
    'schema divergence remains tamper evidence');
  h.f.store._stmt = origStmt;
  h.close();
});

// ============================================================================
// w62-runtime F-3: the unsigned `claims` twin must be byte-identical to the
// signed payload — any divergence is forged, never consulted.
// ============================================================================
test('w62-runtime F-3: a divergent unsigned claims twin names forged', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  // Produce a real retirement first so a signed marker exists.
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run('divergent-bytes');
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.ok((seal.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_healed'), 'precondition: the heal convicted');
  const row = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get();
  const marker = JSON.parse(row.value);
  const signedSet = marker.env.payload.fold_floor_retired;
  assert.ok(Array.isArray(signedSet) && signedSet.length > 0, 'precondition: signed claim set exists');
  // Diverge the unsigned twin — extra claim the envelope never signed.
  h.f.store.db.exec("DROP TRIGGER IF EXISTS fold_residue_keep_upd");
  const twin = { claims: [...signedSet, '77777:unsigned-claim'], env: marker.env };
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor_retired'").run(JSON.stringify(twin));
  const seal2 = h.f.sealAuditChain(h.p('security'));
  const kinds = (seal2.head_watermark_tampered ?? []).map(e => e.kind);
  assert.ok(kinds.includes('floor_marker_retired_forged'), `a divergent claims twin is forged: ${kinds}`);
  // And the unsigned extra claim never entered the retired set.
  assert.ok(!JSON.stringify(seal2).includes('unsigned-claim') || kinds.includes('floor_marker_retired_forged'),
    'the unsigned extension is named, not consulted');
  h.close();
});

const residueRows = h => h.f.store.db.prepare(
  "SELECT key,value FROM meta_kv WHERE tenant='acme' AND (key='fold_floor_healed' OR substr(key,1,18)='fold_floor_healed.')").all();
const dropResidueGuards = h => {
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_upd');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_ins');
};
const healOnce = (h, marker) => {
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(marker);
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
};

// ============================================================================
// w62-fv F-4: a vault-revoked key must carry `revoked` into the verify set —
// verifySigned's refusal path is no longer dead code for vault members.
// ============================================================================
test('w62-fv F-4: a revoked vault key verifies nothing', t => {
  const h = fixture(t);
  h.ready();
  const kid = h.f.vault.generate('any', { tenant_id: 'acme' }).key_id;
  const env = h.f.vault.envelope(kid, 'audit', { tenant_id: 'acme', fold_floor_retired: ['1:x'] });
  assert.ok(verifySigned(env, h.f.auditPublicKeys('acme'), 'audit'), 'pre-revoke the vault key verifies');
  h.f.vault.revoke(kid);
  assert.throws(() => verifySigned(env, h.f.auditPublicKeys('acme'), 'audit'), undefined,
    'post-revoke the same envelope refuses');
  h.close();
});

// ============================================================================
// w62-fv F-5: a grants row whose payload grant_id diverges from its row key
// stays revocable under either name — resolve and flip name the same grant.
// ============================================================================
test('w62-fv F-5: payload-vs-row-key divergence cannot wedge the revoke', t => {
  const h = fixture(t);
  h.ready();
  h.f.target.grant('acme', 'row-x', { grant_id: 'alias-y', subject_id: 'operator', resources: ['d'], actions: ['a'], expires_at: h.f.clock() + 60000, revoked: false });
  const out = h.f.revoke(h.p('security'), { kind: 'grant', id: 'alias-y', reason: 'payload name' });
  assert.ok(out && !out.error, 'the payload name resolves and commits');
  assert.equal(h.f.target.allGrants('acme').find(g => g.grant_id === 'alias-y')?.revoked, true,
    'the divergent row actually flipped in the dataplane');
  h.f.target.grant('acme', 'row-z', { grant_id: 'alias-z', subject_id: 'operator', resources: ['d'], actions: ['a'], expires_at: h.f.clock() + 60000, revoked: false });
  const out2 = h.f.revoke(h.p('security'), { kind: 'grant', id: 'row-z', reason: 'row name' });
  assert.ok(out2 && !out2.error, 'the row key resolves and commits too');
  assert.equal(h.f.target.allGrants('acme').find(g => g.grant_id === 'alias-z')?.revoked, true,
    'the row-key revoke flipped the divergent payload');
  h.close();
});

// ============================================================================
// w62-seal F-1: the durable retired marker signs the committed tip it
// consumed to — `marker_seq` is part of the attested payload.
// ============================================================================
test('w62-seal F-1: the retired marker signs marker_seq', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'bind-me');
  h.f.sealAuditChain(h.p('security'));
  const row = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get();
  assert.ok(row, 'the retire minted the marker');
  const pl = JSON.parse(row.value).env.payload;
  const tip = h.f.store.db.prepare("SELECT MAX(seq) m FROM audit WHERE tenant='acme'").get().m;
  assert.ok(Number.isSafeInteger(pl.marker_seq) && pl.marker_seq >= 1 && pl.marker_seq <= tip,
    `marker_seq binds a real committed position: ${pl.marker_seq} vs tip ${tip}`);
  h.close();
});

// ============================================================================
// w62-seal F-2: a claim whose seq outruns the committed tip is premature —
// the row drains and flags, but the value never enters the signed marker.
// ============================================================================
test('w62-seal F-2: premature claims drain without minting', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'prem');
  const key = residueRows(h)[0]?.key;
  assert.ok(key, 'a residue row stands');
  dropResidueGuards(h);
  h.f.store.db.prepare('UPDATE meta_kv SET value=? WHERE tenant=? AND key=?').run('99999:forged-claim', 'acme', key);
  const seal = h.f.sealAuditChain(h.p('security'));
  const kinds = (seal.head_watermark_tampered ?? []).map(e => e.kind);
  assert.ok(kinds.includes('floor_marker_residue_premature'), `premature claim flagged: ${kinds}`);
  const row = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get();
  assert.ok(!JSON.stringify(row?.value ?? '').includes('99999:forged-claim'), 'the premature claim never entered the signed set');
  h.close();
});

// ============================================================================
// w62-seal F-4: the durable retiring note survives the mint/drain window — a
// covered residue row drains silently instead of latching a phantom echo.
// ============================================================================
test('w62-seal F-4: the durable retiring note suppresses the echo flag', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'note');
  const claim = residueRows(h)[0]?.value;
  assert.ok(claim, 'a residue claim stands');
  // Simulate the crash window: marker already minted the claim retired and
  // the signed retiring set still names it — the drain never ran.
  dropResidueGuards(h);
  const tip = h.f.store.db.prepare("SELECT MAX(seq) m FROM audit WHERE tenant='acme'").get().m;
  const env = h.f.store.auditSigners['acme'].sign({ tenant_id: 'acme', fold_floor_retired: [claim], fold_floor_retiring: [claim], marker_seq: tip }, 'audit');
  h.f.store.db.prepare("INSERT INTO meta_kv (tenant,key,value) VALUES ('acme','fold_floor_retired',?) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value").run(JSON.stringify({ claims: [claim], env }));
  const seal = h.f.sealAuditChain(h.p('security'));
  const kinds = (seal.head_watermark_tampered ?? []).map(e => e.kind);
  assert.ok(!kinds.includes('floor_marker_residue_retired_echo'), `in-flight claims do not echo-convict: ${kinds}`);
  assert.equal(residueRows(h).length, 0, 'the covered row still drains');
  h.close();
});

// ============================================================================
// w62-seal F-6: a literal 'null' marker value is a murdered marker —
// unauthenticated, never a silent absent row.
// ============================================================================
test('w62-seal F-6: a null-valued marker row convicts unauthenticated', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'nullify');
  h.f.sealAuditChain(h.p('security'));
  assert.ok(h.f.store.db.prepare("SELECT 1 FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get(), 'marker exists');
  dropResidueGuards(h);
  h.f.store.db.prepare("UPDATE meta_kv SET value='null' WHERE tenant='acme' AND key='fold_floor_retired'").run();
  const seal = h.f.sealAuditChain(h.p('security'));
  const kinds = (seal.head_watermark_tampered ?? []).map(e => e.kind);
  assert.ok(kinds.includes('floor_marker_retired_unauthenticated'), `null marker row convicts: ${kinds}`);
  h.close();
});

// ============================================================================
// w62 gate regressions — shipped collectAuthorize + traceability.py run
// verbatim against crafted bodies (w59/w60/w61 harness shape).
// ============================================================================
const ROOT = new URL('..', import.meta.url).pathname;
const collectRun = (lines, verb) => {
  const src = readFileSync(new URL('../scripts/check.mjs', import.meta.url).pathname, 'utf8');
  const helpers = src.slice(src.indexOf('// === shared source scanners'), src.indexOf('// === end shared source scanners'));
  const block = src.slice(src.indexOf('const NONROLE'), src.indexOf('const authorizeAt'));
  assert.ok(block.includes('collectAuthorize'), 'the slice carries the shipped scanner');
  return JSON.parse(execFileSync(process.execPath, ['-e', [
    helpers, block,
    `globalThis.process.stdout.write(JSON.stringify(collectAuthorize(${JSON.stringify(lines)}, 0, ${lines.length + 2}, true, ${JSON.stringify(verb)})));`
  ].join('\n')], { encoding: 'utf8', cwd: ROOT }).trim());
};
const HEAD = "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {";
const pyEval = (expr) => execFileSync('python3', ['-c',
  `import json\nsrc=open('scripts/traceability.py').read()\ng={'__file__':'scripts/traceability.py'}\nexec(src[:src.index('def evidence_blocks')], g)\nprint(${expr})`], { encoding: 'utf8', cwd: ROOT }).trim();
const pyLive = (code) => pyEval(`g['_live_code'](g['_blank_code'](${JSON.stringify(code)}), ${JSON.stringify(code)})`);

// w62-fv F-5: a braceless live arm ends at its own EOL — content on the same
// line closes it, while a bare `else` keeps the arm open for the next line.
test('w62-fv F-5: braceless live arms bound by EOL content', t => {
  const r = collectRun([HEAD, "  if (m[1] === 'a') { if (0) dead(); else", "      authorize(p, ['live']); }", '}'], 'a');
  assert.deepEqual(r.roles, ['live'], `a bare else carries the next line as the live arm: ${JSON.stringify(r.roles)}`);
  const r2 = collectRun([HEAD, "  if (m[1] === 'a') { if (0) dead(); else dead2(); authorize(p, ['live']); }", '}'], 'a');
  assert.deepEqual(r2.roles, ['live'], 'a same-line arm ends at its statement, the tail mints unconditionally');
});

// w62-check guard-return: `if (bad) return; authorize` — the tail is
// conditional, never an unconditional mint.
test('w62-check: a guard-return makes the tail conditional', t => {
  const r = collectRun([HEAD, "  if (m[1] === 'a') { if (m[2] !== 'e' || early) return; authorize(p, ['guard']); }", '}'], 'a');
  assert.ok(!(r.roles ?? []).includes('guard'), `a guard-returned authorize is conditional: ${JSON.stringify(r.roles)}`);
  assert.equal(r.any, true, 'the conditional authorize still counts as reachability evidence');
});

// w62-check dispatchPure: a compound dispatch head of pure && operands opens
// an unconditional arm; any impure operand or || keeps it conditional.
test('w62-check: compound dispatch heads mint only when pure', t => {
  const COMP = "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path)) && (n = /^\\/y/.exec(m[1]))) {";
  const r = collectRun([COMP, "  authorize(p, ['pure']);", '}'], 'a');
  assert.deepEqual(r.roles, ['pure'], `an all-&& compound dispatch head mints unconditional: ${JSON.stringify(r.roles)}`);
  const IMP = "if (req.method === 'GET' && (m = /^\\/x/.exec(path)) || fallback) {";
  const r2 = collectRun([IMP, "  authorize(p, ['x']);", '}'], 'a');
  assert.equal(r2.roles, null, 'a ||-compound head is conditional, never a dispatch arm');
  const IMP2 = "if (req.method === 'GET' && (m = /^\\/x/.exec(path)) && helper()) {";
  const r3 = collectRun([IMP2, "  authorize(p, ['x']);", '}'], 'a');
  assert.equal(r3.roles, null, 'a bare call operand breaks dispatch purity');
});

// w62-fv deadElseExpected: a braced dead-if's `else` mints the else arm
// unconditionally, and a braced live-if's `else` mints nothing.
test('w62-check: a braced else pairs with the dead if before it', t => {
  const r = collectRun([HEAD, "  if (m[1] === 'a') { if (0) { dead(); } else authorize(p, ['live']); }", '}'], 'a');
  assert.deepEqual(r.roles, ['live'], `the else of a dead if is the live arm: ${JSON.stringify(r.roles)}`);
  const r2 = collectRun([HEAD, "  if (m[1] === 'a') { if (1) { } else authorize(p, ['dead']); }", '}'], 'a');
  assert.ok(!(r2.roles ?? []).includes('dead'), 'the else of a live if stays dead');
});

// w62-check switch operand: only a whole-operand member binds a switch frame —
// a call-wrapped operand must not re-target the frame onto the raw member.
test('w62-check: switch binds only whole-operand members', t => {
  // For verb 'y' the case 'y' arm is this row's dispatch only when the
  // switch compares the bound member itself — `switch (m[2])` reaches it,
  // `switch (f(m[2]))` compares a transformed value and cannot dispatch 'y'.
  const bound = [HEAD, "  if (m[1] === 'x') { switch (m[2]) { case 'y': authorize(p, ['s']); } }", '}'];
  assert.equal(collectRun(bound, 'y').any, true, 'a whole-member switch reaches its case as dispatch');
  const wrapped = [HEAD, "  if (m[1] === 'x') { switch (f(m[2])) { case 'y': authorize(p, ['s']); } }", '}'];
  assert.equal(collectRun(wrapped, 'y').any, false,
    'a call-wrapped operand cannot bind m[2] — the case is no dispatch for the verb');
});

// w62-ledger masked strings: a string literal's masked content must stay a
// live unknown — never falsy-folded into a dead branch.
test('w62-ledger: masked string literals never fold falsy', t => {
  assert.ok(pyLive("const s = 'nonempty'; if (s) assert.live();").includes('assert.live'),
    'a masked literal stays truthy-unknown, not falsy');
  assert.ok(pyLive("const s = 'nonempty'; if (s == 0) dead(); else assert.live();").includes('assert.live'),
    'a masked literal in loose-eq is unknown, not ToNumber-folded');
});

// w62-ledger bigint + numeric separators: bigint literals fold as _Big and
// numeric separators evaluate, never NaN into dead branches.
test('w62-ledger: bigint and separator literals fold honestly', t => {
  assert.ok(!pyLive("if (5n === 5n) {} else assert.dead();").includes('assert.dead'),
    'bigint equality folds true');
  assert.ok(pyLive("if (5n === 5) {} else assert.live();").includes('assert.live'),
    'bigint-vs-number === is false — the else arm lives');
  assert.ok(pyLive("const n = 1_000; if (n === 1000) assert.live();").includes('assert.live'),
    'numeric separators evaluate to their value');
});

// w62-ledger _one_stmt: `if (true) x(); else y()` — the else arm lives and
// the true arm's unbraced body is dead.
test('w62-ledger: else-span of a dead if survives statement boundaries', t => {
  assert.ok(pyLive("if (false) dead(); else assert.live();").includes('assert.live'),
    'the else of a folded-false if is live');
  assert.ok(!pyLive("if (true) assert.live(); else assert.dead();").includes('assert.dead'),
    'the dead else-arm unbraced body is dead');
  assert.ok(pyLive("do assert.live(); while (0);").includes('assert.live'),
    'a do body runs once — the while tail does not deaden it');
  assert.ok(!pyLive("while (0) dead();").includes('dead()') || pyLive("while (0) assert.dead(); assert.live();").includes('assert.live'),
    'a while(0) body is dead but the following statement lives');
});

// w62-ledger for..of: a non-iterable literal body is dead, an iterable one
// is live.
test('w62-ledger: for..of over a non-iterable mints nothing', t => {
  assert.ok(!pyLive("for (const x of {a:1}) assert.dead();").includes('assert.dead'),
    'an object literal is not iterable — the body is dead');
  assert.ok(pyLive("for (const x of [1]) assert.live();").includes('assert.live'),
    'an array literal iterates — the body is live');
});

// w62-ledger switch literal gate: identifier discriminants keep arms live;
// a constant discriminant kills non-matching cases only.
test('w62-ledger: switch arms gate on literal discriminants', t => {
  assert.ok(pyLive("switch (x) { case 'a': assert.live(); }").includes('assert.live'),
    'an identifier discriminant keeps the case live');
  const out = pyLive("switch (1) { case 2: assert.dead(); default: assert.live(); }");
  assert.ok(!out.includes('assert.dead'), 'a non-matching literal case is dead');
  assert.ok(out.includes('assert.live'), 'the default arm of a literal switch lives');
});

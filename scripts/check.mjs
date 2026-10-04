import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

// Run from the repository root regardless of the caller's cwd — a gate that
// follows the invoking directory verifies whatever tree the caller chose
// (w8-tooling F3).
process.chdir(new URL('..', import.meta.url).pathname);

// Scan every TRACKED code file in the repository — one enumeration source
// shared with manifest.mjs so a committed hostile file cannot shelter in a
// directory the walk forgot (supply-chain M4). Without git (an exported
// tarball) the walk covers everything except package manager and runtime
// state; a hidden dir cannot shelter code either way (w8-tooling F6).
const SKIP = new Set(['node_modules', '.git', 'var', '__pycache__']);
// .ts/.mts/.cts are live code on Node 24 type-stripping — a dispatch
// file renamed that way escaped the audit silently (w57-ledger F6).
const CODE_EXT = /\.(mjs|js|cjs|ts|mts|cts)$/;
const ANY_EXT = /\.(mjs|js|cjs|ts)$/;
let files = [];
// Every spawned helper gets a wall-clock ceiling — a hung subprocess must
// fail the gate, never stall it forever (w23-supply F17). Fifteen minutes:
// under --test-concurrency several copy-tree gate runs share the box and a
// healthy python3 traceability can legitimately need more than five —
// a ceiling only has to outlive honest load, a real wedge never finishes
// either way (w55 regen: python3 ETIMEDOUT at 300s under 4-way suites).
const SPAWN_OPTS = { encoding: 'utf8', timeout: 900000 };
const tracked = spawnSync('git', ['ls-files', '-z'], SPAWN_OPTS);
if (tracked.status === 0) {
  files = tracked.stdout.split('\0').filter(f => ANY_EXT.test(f));
} else {
  const walk = dir => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory() && SKIP.has(entry.name)) continue;
      const p = join(dir, entry.name).replaceAll('\\', '/');
      if (entry.isDirectory()) walk(p); else if (ANY_EXT.test(p)) files.push(p);
    }
  };
  walk('.');
}
files.sort();

let failed = false;
// Secrets-bearing patterns are dangerous in ANY tracked file, not only code:
// a PEM or cloud key committed inside docs/, web/, deploy/ or a JSON blob
// leaks exactly the same (w15-supply F-11). Code rules stay code-scoped.
// vectors/keys.json is a declared conformance fixture — its key material is
// generated test data, intentionally committed.
const SECRET_RULES = [
  ['embedded private key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['cloud credential pattern', /\bAKIA[0-9A-Z]{16}\b/]
];
// Secrets-bearing content is detected by CONTENT, not an extension
// allowlist: every tracked non-binary file is scanned — a committed
// evil.pem/.key/.crt hides under no extension gap (w23-supply F4).
// vectors/keys.json stays the declared conformance fixture exemption.
let textFiles = [];
if (tracked.status === 0) {
  textFiles = tracked.stdout.split('\0').filter(f => f && f !== 'vectors/keys.json');
} else {
  const walkText = dir => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory() && SKIP.has(entry.name)) continue;
      const p = join(dir, entry.name).replaceAll('\\', '/');
      if (entry.isDirectory()) walkText(p); else if (p !== 'vectors/keys.json') textFiles.push(p);
    }
  };
  walkText('.');
}
const isBinary = file => { try { const buf = readFileSync(file); return buf.subarray(0, Math.min(buf.length, 8192)).includes(0); } catch { return true; } };
for (const file of textFiles) {
  if (!existsSync(file) || isBinary(file)) continue;
  const s = readFileSync(file, 'utf8');
  for (const [name, regex] of SECRET_RULES) if (regex.test(s)) { console.error(`${file}: ${name}`); failed = true; }
}

for (const file of files.filter(f => CODE_EXT.test(f) && existsSync(f))) {
  const check = spawnSync(process.execPath, ['--check', file], SPAWN_OPTS);
  if (check.status !== 0) { console.error(check.stderr); failed = true; }
}

// Secrets, code-injection sinks and unfinished markers are forbidden in
// committed files — not only .mjs/.ts code: a .py/.sh helper, a workflow
// .yml or an .html asset can shelter the same sink (w31-ledger F7). Sink
// rules target extensions whose content can EXECUTE or RENDER — prose docs
// legitimately quote the patterns when documenting this gate. Marker rules
// run on every tracked text file: an unfinished marker anywhere (docs
// included) is dishonest. vectors/keys.json stays the declared fixture
// exemption.
const SINK_EXT = /\.(mjs|js|cjs|ts|jsx|tsx|py|sh|bash|zsh|ps1|yml|yaml|html|htm|json)$/;
const SINK_RULES = [
  // The vm specifier is spelled in pieces so this file does not flag its
  // own rule table (w49-ledger F-1).
  // Member-invoked, parenthesized and concatenated spellings of the
  // same sink are equally unforgeable — plain identifier patterns could
  // not see them (w57-ledger F7).
  ['dynamic eval', new RegExp(`\\beval\\s*\\(|new\\s+Function\\s*\\(|eval\\s*\\/\\*\\*\\/\\s*\\(|\\bFunction\\s*\\(|eval\\s*\\.\\s*(?:call|apply)\\s*\\(|new\\s*\\(\\s*Function\\s*\\)|\\(\\s*Function\\s*\\)\\s*\\(|['"]ev['"]\\s*\\+\\s*['"]al['"]|['"]e['"]\\s*\\+\\s*['"]val['"]|Reflect\\.(?:apply|construct)\\s*\\(\\s*(?:eval|Function)|node:${'v'}m|from\\s+['"](?:node:)?${'v'}m['"]|require\\s*\\(\\s*['"](?:node:)?${'v'}m['"]|import\\s*\\(\\s*['"](?:node:)?${'v'}m['"]|runIn(?:This|New)?Context`)],
  ['string-timed code', /\bset(?:Timeout|Interval)\s*\(\s*['"`]/],
  ['embedded private key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['cloud credential pattern', /\bAKIA[0-9A-Z]{16}\b/]
];
// The marker words are split so this scanner does not flag its own
// source. 'XXX' stays out deliberately — it is a real ISO-4217 value in
// test fixtures, not an unfinished marker (w53-ledger MEDIUM). Spaced and
// dotted two-word spellings are the same marker — the alternation could
// not see them (w54-ledger M-1).
const MARKER_RULES = [
  // Multi-char separators, letter-spacing, NBSP/tab and fullwidth
  // spellings are the same marker — a separated or widened spelling
  // still names an unfinished plant (w55-ledger H-2). The separator
  // classes live inside the pattern so this comment names none of them.
  ['unfinished code marker', new RegExp(`\\b(?:${'T'}[ \\t\\u00A0._-]*${'O'}[ \\t\\u00A0._-]*${'D'}[ \\t\\u00A0._-]*${'O'}|${'Ｔ'}[ \\t\\u00A0._-]*${'Ｏ'}[ \\t\\u00A0._-]*${'Ｄ'}[ \\t\\u00A0._-]*${'Ｏ'}|${'F'}[ \\t\\u00A0._-]*${'I'}[ \\t\\u00A0._-]*${'X'}[ \\t\\u00A0._-]*${'M'}[ \\t\\u00A0._-]*${'E'}|${'Ｆ'}[ \\t\\u00A0._-]*${'Ｉ'}[ \\t\\u00A0._-]*${'Ｘ'}[ \\t\\u00A0._-]*${'Ｍ'}[ \\t\\u00A0._-]*${'Ｅ'}|${'T' + 'BD'}|${'W' + 'IP'}|${'HA' + 'CK'})\\b`)],
  // The triple-X word followed by a colon is a planted unfinished-marker
  // label, not the ISO-4217 fixture value — the bare word stays exempt
  // (w54-fv M-5).
  ['unfinished code marker (xxx label)', new RegExp(`\\b${'XX' + 'X'}\\s*:`)]
];
// Case-insensitive on authored files: a lowercase marker is the same
// unfinished code (w49-ledger F-1). reports/ is exempt — '# to'+'do N'
// lines are generated TAP protocol fields, not authored markers; the few
// files that legitimately name node:test's skip/defer vocabulary dodge
// the literal word instead.
const MARKER_LOOSE = [
  ['unfinished code marker (any case)', new RegExp(`\\b(?:${'T'}[ \\t\\u00A0._-]*${'O'}[ \\t\\u00A0._-]*${'D'}[ \\t\\u00A0._-]*${'O'}|${'Ｔ'}[ \\t\\u00A0._-]*${'Ｏ'}[ \\t\\u00A0._-]*${'Ｄ'}[ \\t\\u00A0._-]*${'Ｏ'}|${'F'}[ \\t\\u00A0._-]*${'I'}[ \\t\\u00A0._-]*${'X'}[ \\t\\u00A0._-]*${'M'}[ \\t\\u00A0._-]*${'E'}|${'Ｆ'}[ \\t\\u00A0._-]*${'Ｉ'}[ \\t\\u00A0._-]*${'Ｘ'}[ \\t\\u00A0._-]*${'Ｍ'}[ \\t\\u00A0._-]*${'Ｅ'}|${'T' + 'BD'}|${'W' + 'IP'}|${'HA' + 'CK'})\\b`, 'i')],
  ['unfinished code marker (xxx label any case)', new RegExp(`\\b${'XX' + 'X'}\\s*:`, 'i')]
];
// DOM-injection sinks matter in ANY code that renders — not only src/ and
// web/: an .html asset or script-generated page outside those roots could
// carry a live sink (w49-ledger F-1). Tests legitimately contain these
// strings inside regexes that assert their absence; this file exempts
// itself because it hosts the rules.
const RENDER_ONLY = [
  // Bracket-member assignment, writeln, and the Function constructor are
  // the same sink under a different spelling (w56-ledger F10).
  ['DOM injection', /\.(?:innerHTML|outerHTML)\s*(?:=|\+=)|\[\s*['"](?:innerHTML|outerHTML)['"]\s*\]\s*(?:=|\+=)|\[\s*['"](?:inner|outer)['"]\s*\+\s*['"]HTML['"]\s*\]\s*(?:=|\+=)|Reflect\.set\s*\([^)]*['"](?:inner|outer)HTML['"]|insertAdjacentHTML|(?:document|doc|d|el|target|element|node)\s*\.\s*write(?:ln)?\s*\(|new\s*\(?\s*Function\s*\)?\s*\(/]
];
for (const file of textFiles) {
  if (file === 'vectors/keys.json' || !existsSync(file) || isBinary(file)) continue;
  const s = readFileSync(file, 'utf8');
  // Zero-width/format chars embedded in a marker hide it from the
  // pattern while a human still reads the unfinished-work word —
  // normalize them away before the marker rules test (w56-ledger F11).
  const snorm = s.replace(/[\u00AD\u034F\u061C\u180E\u200B-\u200F\u202A-\u202F\u2060\u2063-\u2064\u3000\uFE0F\uFEFF]/g, '');
  // check.mjs exempts itself only from the DOM rules — its rule table
  // legitimately hosts the sink literals; sinks and markers still apply.
  const renderable = file !== 'scripts/check.mjs' && (file.startsWith('src/') || file.startsWith('web/') || /\.(?:html?|jsx|tsx)$/.test(file)) && !file.startsWith('tests/');
  const rules = [...(SINK_EXT.test(file) ? SINK_RULES : []), ...(renderable ? RENDER_ONLY : []), ...MARKER_RULES, ...(file.startsWith('reports/') ? [] : MARKER_LOOSE)];
  for (const [name, regex] of rules) if (regex.test(name.includes('marker') ? snorm : s)) { console.error(`${file}: ${name}`); failed = true; }
}

// Route-role parity: every role list the OpenAPI generator declares must
// match the role gate actually executed — either the authorize() call on
// the handler line(s) in server.mjs or the first authorize() inside the
// delegated fabric method (w20-ledger F-4: the generator table is
// hand-maintained, so without this a drifted contract is "verified"
// only by its own output). The line-analysis helpers below live at
// module scope — the route-role parity block and the reverse dispatch
// audit share them (w55-ledger: block-scoped helpers left auditDispatch
// crashing on an undefined codeSpan).
// === shared source scanners (extracted verbatim by tests/w50b H-2) ===
const isIf = l => /^\s*(?:\}\s*)?(?:else\s+)?if\s*\(/.test(l);
// A single-statement validation guard (queryCheck/noBody) is not a
// handler boundary — the fabric call that carries the role gate may
// legitimately sit below it (w43-fv M1 ordering). The condition close
// is found by balanced parens on the literal-blanked view — a nested
// call inside the condition (`if (q.t && p.query) queryCheck(...)`)
// fooled the first-`)` scan into missing the guard (w56-ledger G-7).
const isValidationGuard = l => {
  const m = /^\s*if\s*\(/.exec(l);
  if (!m) return false;
  const cs = codeSpan(l);
  let d = 0, end = -1;
  for (let i = cs.indexOf('(', m.index); i < cs.length; i++) {
    if (cs[i] === '(') d++;
    else if (cs[i] === ')' && --d === 0) { end = i; break; }
  }
  return end !== -1 && /^\s*(queryCheck|noBody)\s*\(/.test(cs.slice(end + 1));
};
// A route-arm `if` is the only `if` that bounds a handler scan — a
// nested `if` inside the arm is part of the handler, not a boundary
// (w55-ledger C4-c).
const isRouteArmIf = l => isIf(l) && /(?:\bpath\b|req\.method|req\.url|url\.pathname)\s*===\s*'|\/\^/.test(l);
// Dead short-circuit arms can never evaluate: `false && authorize(...)`
// and `true || authorize(...)` carry the literal without ever executing
// it — strip them before any auth-claim evidence is collected
// (w54-ledger H-2). Comments are stripped first: `// auth(req)` is dead
// text that launders the same way.
const stripComment = l => {
  let q = null;
  for (let i = 0; i < l.length - 1; i++) {
    const c = l[i];
    if (q) { if (c === '\\') i++; else if (c === q) q = null; continue; }
    if (c === "'" || c === '"' || c === '`') { q = c; continue; }
    if (c === '/' && l[i + 1] === '/' && l[i - 1] !== '\\') return l.slice(0, i);
  }
  return l;
};
// A brace inside a string literal or comment is not syntax — counting
// raw characters skews every depth/scope measurement (w55-fv H-2).
// `codeSpan` returns the line with quoted spans blanked to spaces and
// the trailing comment dropped, so structural counting sees only code.
const codeSpan = l => {
  const out = l.split('');
  let q = null;
  for (let i = 0; i < out.length; i++) {
    const c = out[i];
    if (q) { if (c === '\\') { out[i] = ' '; if (i + 1 < out.length) out[++i] = ' '; } else { out[i] = ' '; if (c === q) q = null; } continue; }
    if (c === "'" || c === '"' || c === '`') { q = c; out[i] = ' '; continue; }
    if (c === '/' && out[i + 1] === '/') { for (let j = i; j < out.length; j++) out[j] = ' '; break; }
  }
  return out.join('');
};
// Whether `pos` sits inside a string literal or a line comment on the
// same line — a 'false &&' inside quotes is data, not a dead operand
// (w55-fv H-3: string-first matching ate real code after the literal).
const inString = (l, pos) => {
  let q = null;
  for (let i = 0; i < Math.min(pos, l.length - 1); i++) {
    const c = l[i];
    if (q) { if (c === '\\') i++; else if (c === q) q = null; continue; }
    if (c === "'" || c === '"' || c === '`') { q = c; continue; }
    if (c === '/' && l[i + 1] === '/') return true;
  }
  return q !== null;
};
// `false &&`/`true ||` are always dead as the short-circuit's left
// operand — including behind `||`, `&&`, `?` and `:` which all bind
// looser and leave the literal in operand position (w55-fv H-3). The
// live exceptions are only positions where the literal is another
// operator's operand: comparisons (`x === false &&`), unary/binary
// arithmetic and single bitwise ops (`a | false &&` binds `(a|false)`
// to &&). A dead arm that spills past the line end keeps eating lines
// until a statement terminator — the continuation carries the same
// unreachable operand (w55-fv H-3 multiline).
// The multi-line dead-operand continuation is per-SCAN state, not
// module state — a `false &&` spilling past one scan's window armed the
// NEXT scan's first lines as dead, laundering real code across caller
// boundaries (w56-ledger G-6). Each scan builds its own `deadState()`.
const deadState = () => ({ pending: false, block: false });
const deadContinues = m => !/;|\{|\}|,/.test(m);
const stripDead = (l, dead = deadState()) => {
  if (dead.pending) {
    if (/^\s*(?:case\b|default\b|\}|\)|\])/.test(l)) dead.pending = false;
    else { if (!deadContinues(l)) dead.pending = false; return ' '; }
  }
  let out = stripComment(l);
  // A /* */ run is dead text too — its authorize-shaped content minted
  // evidence exactly like a //-comment did (w57-ledger F2). Block
  // comments span lines through `dead.block`.
  {
    const chars = out.split('');
    for (let i = 0; i < chars.length; i++) {
      const c = chars[i];
      if (dead.block) {
        if (c === '*' && chars[i + 1] === '/') { chars[i] = ' '; chars[i + 1] = ' '; i++; dead.block = false; }
        else chars[i] = ' ';
        continue;
      }
      if (c === '/' && chars[i + 1] === '*' && !inString(chars.join(''), i)) { chars[i] = ' '; chars[i + 1] = ' '; i++; dead.block = true; }
    }
    out = chars.join('');
  }
  const livePrefix = i => { const b = out.slice(0, i).trimEnd(); return /[=!<>]=+\s*$|[&^~%+\-*/!<>]\s*$/.test(b) && !/(?:\|\||&&|\?|:)\s*$/.test(b); };
  // Splice right-to-left: replacing earlier spans first would drift the
  // indices the later matches were collected on.
  for (const m of [...out.matchAll(/\b(?:false|0|null|undefined|!true)\s*&&[^;{}]*/g)].reverse()) {
    if (inString(out, m.index) || livePrefix(m.index)) continue;
    if (deadContinues(m[0])) dead.pending = true;
    out = out.slice(0, m.index) + ' ' + out.slice(m.index + m[0].length);
  }
  for (const m of [...out.matchAll(/\b(?:true|!false|1)\s*\|\|[^;{}]*/g)].reverse()) {
    if (inString(out, m.index) || livePrefix(m.index)) continue;
    if (deadContinues(m[0])) dead.pending = true;
    out = out.slice(0, m.index) + ' ' + out.slice(m.index + m[0].length);
  }
  return out;
};
// `maskStrings` blanks the CONTENTS of quoted literals on an already
// stripped line — call-detection runs on it so evidence inside a string
// can never mint; positions are preserved so the unmasked line still
// supplies argument text (w57-ledger F2). A template literal left open
// at line end tracks `dead.str` so line two is not treated as code.
const maskStrings = (text, dead) => {
  const out = text.split('');
  let q = dead.str ?? null;
  for (let i = 0; i < out.length; i++) {
    const c = out[i];
    if (q) { if (c === '\\') { out[i] = ' '; if (i + 1 < out.length) out[++i] = ' '; } else { out[i] = ' '; if (c === q) q = null; } continue; }
    if (c === "'" || c === '"' || c === '`') { q = c; out[i] = ' '; }
  }
  dead.str = q === '`' ? q : null;
  return out.join('');
};
// A call guarded by `cond &&`, `x ||`, a ternary or an inline `if` on
// its own statement resolves only some requests — it cannot satisfy an
// unconditional 'authenticated' or role claim, though it still breaks
// 'unauthenticated' (w57-ledger F3). A call sitting INSIDE the control
// keyword's own parentheses — `if (!auth(req)) return 401` — is the
// condition itself: it evaluates unconditionally, and the operators
// before it (`x && auth`) are what condition it (w57 h-3 parity).
const guardedPrefix = (masked, callStart) => {
  const stmt = masked.slice(Math.max(masked.lastIndexOf(';', callStart - 1), masked.lastIndexOf('}', callStart - 1), masked.lastIndexOf('{', callStart - 1)) + 1, callStart);
  const open = [];
  for (let i = 0; i < stmt.length; i++) { if (stmt[i] === '(') open.push(i); else if (stmt[i] === ')') open.pop(); }
  for (let i = open.length - 1; i >= 0; i--) {
    if (/(?:^|[^\w$])(?:if|for|while|switch|catch)\s*$/.test(stmt.slice(0, open[i])))
      return /&&|\|\||\?/.test(stmt.slice(open[i] + 1));
  }
  return /&&|\|\||\?|(?:^|[^\w$])if\s*\(|(?:^|[^\w$])(?:else|for|while|do)(?:\s|$)/.test(stmt);
};
// A verb-dispatch `m[N]` under any index spelling: `m['2']`, `m[+2]`,
// `m[02]`, `m[2 ]` all dispatch exactly like `m[2]` — the sibling-arm
// boundary must see every spelling (w57-ledger F4).
const DISPATCH_IDX = "m\\s*\\[\\s*['\"]?\\s*\\+?\\s*\\d+\\s*['\"]?\\s*\\]";
const DISPATCH_2 = new RegExp("m\\s*\\[\\s*['\"]?\\s*\\+?\\s*2\\s*['\"]?\\s*\\]");
// A role gate may name its set through a module-scope constant —
// `authorize(p, ADMIN_SET)` gates exactly as honestly as the literal
// array, and treating it as no gate turns a real role check into a
// satisfied 'unauthenticated' claim (w54-fixverify H-3). The same
// reasoning covers let/var declarations, plain reassignments, alias
// bindings (const B = A) and .push/.concat mutations — any of them may
// carry or grow the gate's role set (w55-fv M-5).
const roleSets = lines => {
  const defs = new Map();
  // Brackets inside push/concat argument lists are punctuation, not part
  // of the role name — `B.concat(['x','y'])` split raw and kept '['x''
  // and ''y]' (w56-fv F-3).
  const roleArgs = s => s.replace(/[[\]]/g, '').split(',').map(x => x.trim().replace(/['"]/g, '')).filter(Boolean);
  const dead = deadState();
  for (const l of lines) {
    const s = stripDead(l, dead);
    const m = /\b(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*\[([^\]]*)\]/.exec(s);
    // No early continue: a compact line like `const A=['x']; B=A;` must
    // bind BOTH — the array arm and the alias arms below (w57-fv NEW-5).
    if (m) defs.set(m[1], roleArgs(m[2]));
    const alias = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*[;\s]/.exec(s);
    if (alias && defs.has(alias[2])) defs.set(alias[1], [...defs.get(alias[2])]);
    else {
      // A bare `B = A` rebinding is the same alias — module-level lets
      // often rebind without a declarator and the hole made
      // authorize(p, B) invisible (w56-fv F-3).
      const bare = /\b([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*[;\s]/.exec(s);
      if (bare && defs.has(bare[2])) defs.set(bare[1], [...defs.get(bare[2])]);
    }
    for (const c of s.matchAll(/\b(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*\.\s*concat\s*\(([^)]*)\)/g))
      // B = A.concat(...) binds B to A's content plus the args — reading
      // the target made an unbound B stay empty and the set invisible
      // (w56-fv F-3).
      defs.set(c[1], [...(defs.get(c[2]) ?? []), ...roleArgs(c[3])]);
    for (const p of s.matchAll(/\b([A-Za-z_$][\w$]*)\s*\.\s*push\s*\(([^)]*)\)/g))
      if (defs.has(p[1])) defs.get(p[1]).push(...roleArgs(p[2]));
  }
  return defs;
};
// === end shared source scanners ===
{
  const server = readFileSync('src/server.mjs', 'utf8').split('\n');
  const fabric = readFileSync('src/fabric.mjs', 'utf8').split('\n');
  const issuerd = readFileSync('src/issuerd.mjs', 'utf8').split('\n');
  // Parity runs on the EMITTED contract, not the generator's source: an
  // operation() call planted outside the literal table writes real openapi
  // paths the regex never saw (w23-supply F5).
  const spec = JSON.parse(readFileSync('docs/openapi.json', 'utf8'));
  const rows = [];
  for (const [path, ops] of Object.entries(spec.paths ?? {})) {
    for (const [method, op] of Object.entries(ops)) {
      if (!['get', 'post', 'put', 'delete', 'patch'].includes(method)) continue;
      const m = /^Roles: ([^.]+)\./.exec(op.description ?? '');
      if (!m) { console.error(`route-role parity: ${method} ${path} — contract row lacks a Roles declaration`); failed = true; continue; }
      rows.push({ path, method, roles: m[1].split(',').map(s => s.trim()), listener: op['x-listener'] ?? null });
    }
  }
  const NONROLE = new Set(['bound subject', 'token holder', 'authenticated', 'unauthenticated', 'issuer bearer token']);
  const sortR = r => [...r].sort().join(',');
  const collectAuthorize = (lines, from, depth, breakIf = true, verb = null) => {
    const defs = roleSets(lines);
    const found = new Set();
    let depthCur = 0;
    const skipStack = [];
    let skipIndent = null;
    let ourChainDepth = null;
    const dead = deadState();
    // An unconditional `return` inside this row's arm ends its dispatch —
    // an authorize placed AFTER it can never gate this verb, only
    // sibling rows that didn't return early (w56-ledger F7). `deadArmDepth`
    // is the statement depth inside the row's arm body; `tailDead` latches
    // for the rest of the row's scan.
    // Depths whose `return` dominates this row's tail: the route arm's
    // body depth (every verb falls to it when its chain ends without
    // exiting) plus each dispatched sub-arm's body depth (w56-ledger F7).
    const deadDepths = new Set();
    let tailDead = false;
    // Any authorize call seen (guarded or not) is reported via `.any` — a
    // conditional gate still breaks an 'unauthenticated' claim even
    // though it cannot satisfy a role claim (w57-ledger F3).
    const sawAny = { v: false };
    for (let i = from; i < Math.min(from + depth, lines.length); i++) {
      // Only a route-arm-shaped `if` bounds the scan — a nested `if`
      // inside the handler is part of the handler and its gate still
      // counts (w55-ledger C4-c: `if (p.tenant_id) { authorize }` hid a
      // real role gate under an 'authenticated' claim).
      if (i !== from && breakIf && isRouteArmIf(lines[i]) && !isValidationGuard(lines[i])) break;
      const cs = codeSpan(lines[i]);
      const opens = (cs.match(/\{/g) ?? []).length;
      const closes = (cs.match(/\}/g) ?? []).length;
      // A multiplexed arm (one regex `if` serving several contract paths)
      // dispatches sub-routes through inner `if (m[N] === 'x')` tests —
      // an authorize inside a sibling's sub-route belongs to that row,
      // not this one. `verb` names this row's sub-route; without it
      // every gate in the arm counts (w55-ledger C4-c over-collection).
      // Sibling interiors stack: `} else if (m[1]==='b') {` closes one
      // sibling block and opens the next on the same line, so the new
      // interior must re-arm at the post-close depth — a single
      // opens>closes check left every else-arm collected and bled the
      // sibling's roles into this row (w56-fv F-2). A `} else`
      // continuation of a sibling chain is sibling too: it serves the
      // chain's catch-all row, not this verb — excluding it errs toward
      // flagging, never laundering.
      let l = stripDead(lines[i], dead);
      // `lm` is the string-blanked twin: call detection runs on it so an
      // authorize/dispatch/return inside a string literal mints nothing;
      // the verb argument is read back from `l` at the same position
      // (w57-ledger F2/F4).
      const lm = maskStrings(l, dead);
      const disp = verb && i !== from ? [...lm.matchAll(new RegExp(DISPATCH_IDX + '\\s*===', 'g'))]
        .map(x => { const v = new RegExp(DISPATCH_IDX + "\\s*===\\s*'([^']+)'").exec(l.slice(x.index)); return v ? v[1] : null; }).filter(Boolean) : [];
      const afterCloses = depthCur - closes;
      let popped = false;
      while (skipStack.length && afterCloses < skipStack[skipStack.length - 1].d) { skipStack.pop(); popped = true; }
      // A braceless sibling body stays excluded while following lines
      // keep a deeper indent than the dispatch line (blank lines ride).
      if (skipIndent !== null && l.trim() !== '' && (/^\s*/.exec(l)[0].length <= skipIndent || /^\s*\}/.test(l))) skipIndent = null;
      const isElse = /^\s*\}?\s*else\b/.test(l);
      // The dispatch chain OUR verb rides ends at our arm's closing `}` —
      // a `} else` past it serves the catch-all row, never ours. A chain
      // with more else-arms keeps the marker until a non-else line drops
      // below it.
      let ourChainClosed = false;
      if (ourChainDepth !== null && afterCloses < ourChainDepth) {
        if (isElse) ourChainClosed = true; else ourChainDepth = null;
      }
      const topIsSib = skipStack.length > 0 && !skipStack[skipStack.length - 1].ours;
      const inSib = topIsSib;
      const sibling = disp.length > 0 && !disp.includes(verb);
      const ours = disp.length > 0 && disp.includes(verb);
      // A `} else` continuing a sibling chain — or our own chain once our
      // arm closed — is sibling too: its catch-all roles must not bleed
      // into this row. A dispatch naming THIS verb is ours even inside a
      // sibling region: `if (m[2]==='ourverb')` nested in arm-a is this
      // row's gate, not arm-a's.
      const elseSibling = isElse && !ours && (popped || inSib || ourChainClosed);
      const excluded = (inSib && !ours) || skipIndent !== null || sibling || elseSibling;
      if (sibling || elseSibling) {
        const lastOpen = l.lastIndexOf('{'), lastClose = l.lastIndexOf('}');
        // An unmatched last `{` opens a block whose interior continues
        // past this line; otherwise the body is braceless (indent-bound).
        if (lastOpen > lastClose) skipStack.push({ d: afterCloses + opens, ours: false });
        else if (opens === 0) skipIndent = /^\s*/.exec(l)[0].length;
      }
      // A dispatch carrying THIS verb opens our arm — inside a sibling
      // region its block counts for us; at top level remember the chain
      // depth so the trailing `} else` is recognized as a sibling. The
      // arm's BODY sits one level past the dispatch line when a `{`
      // opens it — but a braceless or same-line-closed dispatch still
      // dominates: `if (m[2]==='x') return serve(...)` kills the
      // enclosing region's tail for this verb exactly like the braced
      // arm does (w56-ledger F7).
      if (ours) {
        if (l.includes('{')) deadDepths.add(depthCur + 1); else deadDepths.add(depthCur);
        if (l.lastIndexOf('{') > l.lastIndexOf('}')) {
          if (skipStack.length > 0) skipStack.push({ d: afterCloses + opens, ours: true });
          else ourChainDepth = afterCloses + opens;
        }
      } else if (i === from && opens > 0) deadDepths.add(depthCur + 1);
      if (!excluded && !tailDead) {
        // A `return` at a dominating depth kills the row's tail — cut
        // the line at it, latch dead, and stop crediting authorizes that
        // sit past the exit (w56-ledger F7). A return nested deeper
        // (inside its own `{`) is conditional and kills nothing.
        if (deadDepths.size > 0) {
          // `ld` must start at the line's opening depth — `afterCloses`
          // already subtracted this line's `}` chars, so a self-contained
          // `{ ... }` later on the same line would under-read the depth at
          // the return (w56-ledger F7 self-test).
          let ld = depthCur, cut = -1;
          for (let ci = 0; ci < lm.length; ci++) {
            const c = lm[ci];
            if (c === '{') ld++;
            else if (c === '}') ld--;
            else if (deadDepths.has(ld) && /^(?:return|throw)\b/.test(lm.slice(ci)) && !/[\w$]/.test(lm[ci - 1] ?? ' ')
              // A `return`/`throw` that is the braceless body of an
              // if/else/for/while on this line is conditional — it
              // dominates nothing and the row's tail stays live
              // (w56-ledger F7) — UNLESS the braceless if is THIS verb's
              // own dispatch: an `if (m[N]==='ourverb') return send(...)`
              // is unconditional for this row and its tail is dead
              // (w57-fv NEW-1). Statements after an unconditional throw
              // are the same dead evidence (w57-ledger F3/F13).
              && (ours || !/\b(?:if|for|while)\s*\([^;{]*\)\s*$|\belse(?:\s+if\s*\([^;{]*\))?\s*$/.test(lm.slice(0, ci)))) { cut = ci; break; }
          }
          if (cut !== -1) { l = l.slice(0, cut); tailDead = true; }
        }
        const lmx = maskStrings(l, { pending: false, block: dead.block });
        for (const m of lmx.matchAll(/authorize\(\s*p\s*,\s*[^\s)]/g)) {
          sawAny.v = true;
          if (guardedPrefix(lmx, m.index)) continue;  // conditional gate — cannot satisfy a role claim (w57-ledger F3)
          const args = l.slice(m.index);
          const am = /authorize\(\s*p\s*,\s*\[([^\]]+)\]/.exec(args);
          if (am) { for (const r of am[1].split(',')) found.add(r.trim().replace(/['"]/g, '')); continue; }
          const nm = /authorize\(\s*p\s*,\s*([A-Za-z_$][\w$]*)\s*\)/.exec(args);
          if (nm) for (const r of defs.get(nm[1]) ?? []) found.add(r);
        }
      }
      depthCur += opens - closes;
    }
    return { roles: found.size ? [...found] : null, any: sawAny.v };
  };
  const authorizeAt = (lines, from, depth = 6, verb = null) => collectAuthorize(lines, from, depth, true, verb).roles;
  const fabricRoles = name => {
    const idx = fabric.findIndex(l => new RegExp(`^\\s{2}(async )?${name}\\(`).test(l));
    if (idx === -1) return null;
    const defs = roleSets(fabric);
    const found = new Set();
    const fdead = deadState();
    for (let i = idx; i < Math.min(idx + 140, fabric.length); i++) {
      if (i !== idx && /^\s{2}(async )?[a-zA-Z_]+\(/.test(fabric[i])) break;
      const fl = stripDead(fabric[i], fdead), fm = maskStrings(fl, fdead);
      // Comments and string literals carry no gate — the call is found on
      // the masked view, its argument read back from the stripped line,
      // and a same-statement `cond && authorize` is a conditional gate
      // that cannot satisfy a role claim (w57-ledger F2/F3).
      for (const m of fm.matchAll(/this\.authorize\(\s*p\s*,\s*[^\s)]/g)) {
        if (guardedPrefix(fm, m.index)) continue;
        const args = fl.slice(m.index);
        const am = /this\.authorize\(\s*p\s*,\s*\[([^\]]+)\]/.exec(args);
        if (am) { for (const r of am[1].split(',')) found.add(r.trim().replace(/['"]/g, '')); continue; }
        const nm = /this\.authorize\(\s*p\s*,\s*([A-Za-z_$][\w$]*)\s*\)/.exec(args);
        if (nm) for (const r of defs.get(nm[1]) ?? []) found.add(r);
      }
      const rm = /roles\?*\.includes\(/.exec(fm);
      if (rm && /requireThat/.test(fm)) {
        const rv = /roles\?*\.includes\('([^']+)'\)/.exec(fl.slice(rm.index));
        if (rv) found.add(rv[1]);
      }
    }
    return found.size ? [...found] : null;
  };
  for (const r of rows) {
    // The row's handler lives in its own listener's dispatch file — an
    // issuerd contract row cannot borrow server.mjs's audit, and vice
    // versa (w52-ledger M-6).
    const lines = r.listener === 'issuerd' ? issuerd : server;
    const segs = r.path.split('/').filter(Boolean);
    const staticSegs = segs.filter(s => !s.startsWith('{'));
    const param = r.path.includes('{');
    // A route condition may span lines — join the if's continuations for
    // matching (its '{' may sit lines below), while the boundary index
    // stays the first line (w55-ledger H-3 multi-line condition).
    const condText = i => {
      let t = lines[i];
      for (let j = i + 1; j < Math.min(i + 6, lines.length); j++) {
        const prev = codeSpan(lines[j - 1]).trimEnd();
        const pd = (t.match(/\(/g)?.length ?? 0) - (t.match(/\)/g)?.length ?? 0);
        if (/\{|;/.test(prev) || (pd <= 0 && !/[&|?:,]\s*$/.test(prev))) break;
        t += ' ' + lines[j];
      }
      return t;
    };
    const hi = lines.findIndex((l, i) =>
      isIf(l) && condText(i).includes(`req.method === '${r.method.toUpperCase()}'`) &&
      (condText(i).includes(`path === '${r.path}'`) || condText(i).includes(`url.pathname === '${r.path}'`) || condText(i).includes(`req.url === '${r.path}'`) || (param && /\^\\\//.test(condText(i)) && staticSegs.every(s => condText(i).includes(s)))));
    // The handler window: the dispatch arm until the next ROUTE boundary.
    // A nested `if` inside the arm's own block is part of the handler, not
    // a boundary — a real auth call one `if` deep is reachability-true
    // (w54-ledger H-3). The boundary is an `if` at the arm's own depth.
    const windowEnd = () => {
      if (hi === -1) return hi;
      // The arm-bounded window: 40 lines truncated long handlers and let
      // a late authorize hide behind a lying 'unauthenticated' claim
      // (w57-ledger F5).
      const end = Math.min(hi + 160, lines.length);
      let depth = 0;
      // A multi-line `if (` condition continues until its block opens, and
      // a brace-less arm's body is the next statement — neither may close
      // the window early (w55-ledger H-3).
      let condOpen = false, braceless = false, inner = 0;
      for (let i = hi; i < end; i++) {
        const l = lines[i];
        // Braces inside strings/comments are data, not syntax — a route
        // pattern or JSON literal skewing depth both stretches and clips
        // windows wrongly (w55-fv H-2).
        const cs = codeSpan(l);
        const lead = (cs.match(/^\s*\}+/)?.[0].match(/\}/g)?.length ?? 0);
        const opens = (cs.match(/\{/g)?.length ?? 0), closes = (cs.match(/\}/g)?.length ?? 0);
        if (i !== hi && !condOpen && !braceless && depth - lead <= 0) {
          if (isIf(l) && !DISPATCH_2.test(l) && !isValidationGuard(l)) return i;
          // The arm's own `else` is its complement — the else body never
          // runs for this route, so a credential there cannot launder the
          // claim (w55-ledger C4-b).
          if (/^\s*\}?\s*else\b/.test(cs)) return i;
          // A one-line arm closes on its own line — the next statement at
          // the arm's depth is dispatch plumbing (the shared `const p =
          // auth(req` setup), not part of this handler. Counting it would
          // launder a zero-auth arm behind the dispatch-wide call
          // (w54-ledger H-1).
          if (!isIf(l) && !/^\s*[\}\])]/.test(l)) return i;
        }
        if (condOpen) {
          // Still inside the arm's condition — its text is never a
          // boundary; the block's '{' ends it.
          if (opens > closes) condOpen = false;
          depth += opens - closes;
          continue;
        }
        if (braceless) {
          // The brace-less body is one statement — nested blocks track
          // `inner`; the statement ends at ';' or when a nested block
          // closes back to zero without a dangling continuation.
          inner += opens - closes;
          if ((/;/.test(cs) && inner <= 0) || (opens + closes > 0 && inner <= 0 && !/[,?:]|&&|\|\|\s*$/.test(cs.trimEnd()))) { braceless = false; inner = 0; depth = 0; }
          continue;
        }
        depth += opens - closes;
        if (i === hi && depth <= 0 && /\bif\s*\(/.test(cs) && !/[\{;]/.test(cs)) {
          const pd = (cs.match(/\(/g)?.length ?? 0) - (cs.match(/\)/g)?.length ?? 0);
          if (pd > 0 || /[&|?:,]\s*$/.test(cs.trimEnd())) condOpen = true;
          else braceless = true;
        }
      }
      return end;
    };
    const wEnd = windowEnd();
    const windowCode = hi === -1 ? '' : (() => { const d = deadState(); return lines.slice(hi, wEnd).map(x => stripDead(x, d)).join('\n'); })();
    // Evidence regexes run on the STRING-BLANKED twin: a 'auth(req)' or
    // authorize-shaped literal inside a string or /* */ comment mints
    // nothing (w57-ledger F2).
    const windowMasked = hi === -1 ? '' : (() => { const d = deadState(); return lines.slice(hi, wEnd).map(x => maskStrings(stripDead(x, d), d)).join('\n'); })();
    // An unconditional claim ('authenticated', 'token holder',
    // 'issuer bearer token') needs at least one UNGUARDED credential
    // call — `flag && auth(req)` serves unauthenticated traffic and is
    // not a gate (w57-ledger F3). Each masked line is checked per
    // call position.
    const AUTH_CALL = /auth\(req|authenticateToken|authBreakglass\(|authorize\(|anyBearer\(|bearerMatches\(|issuerAuthOk\(|bearerDigest\(/g;
    const unguardedAuth = hi === -1 ? false : (() => {
      const d = deadState();
      return lines.slice(hi, wEnd).map(x => maskStrings(stripDead(x, d), d))
        .some(ml => [...ml.matchAll(AUTH_CALL)].some(m => !guardedPrefix(ml, m.index)));
    })();
    if (r.roles.length === 1 && NONROLE.has(r.roles[0])) {
      // Non-role claims are still contract claims: 'unauthenticated' must
      // name a handler that runs no auth, 'token holder' must actually
      // resolve a credential, 'issuer bearer token' must resolve the
      // issuerd bearer machinery — and no non-role row may hide a role
      // gate (w51-ledger H-3, w52-ledger M-6).
      if (hi === -1) { console.error(`route-role parity: ${r.method} ${r.path} — cannot resolve the handler behind a '${r.roles[0]}' claim`); failed = true; continue; }
      // The claim window spans the whole arm, not a fixed 12 lines — a
      // handler longer than the window hid its authorize behind a lying
      // 'unauthenticated' row (w57-ledger F5).
      const gate = collectAuthorize(lines, hi, Math.max(2, wEnd - hi));
      if (r.roles[0] === 'unauthenticated' && (gate.any || /auth\(req|authenticateToken/.test(windowMasked))) { console.error(`route-role parity: ${r.method} ${r.path} — claims unauthenticated but the handler authenticates`); failed = true; continue; }
      if (r.roles[0] === 'token holder' && !unguardedAuth) { console.error(`route-role parity: ${r.method} ${r.path} — claims token holder but no credential resolves`); failed = true; continue; }
      if (r.roles[0] === 'issuer bearer token' && !unguardedAuth) { console.error(`route-role parity: ${r.method} ${r.path} — claims issuer bearer token but no bearer gate resolves`); failed = true; continue; }
      if (r.roles[0] !== 'unauthenticated' && gate.any) { console.error(`route-role parity: ${r.method} ${r.path} — claims '${r.roles[0]}' but a role gate [${gate.roles ?? []}] resolves`); failed = true; continue; }
      // 'authenticated' / 'bound subject' claims still mean a credential
      // resolves — inline in the handler window or via the shared
      // dispatch auth above the arm (server.mjs authenticates once for
      // every route below it). A zero-auth arm claiming authenticated is
      // a contract lie nothing else checks (w53-ledger HIGH-2).
      // Only dispatch-path CALLS count — the scan starts at the
      // http.createServer callback so `function authenticateToken`/
      // `function auth(` declarations and their bodies (which sit above
      // every route) cannot launder the claim.
      const dispatchStart = lines.findIndex(l => /\b(?:http|https)\.createServer\s*\(|createServer\s*\(\s*\{/.test(l) && !/function\s+createServer/.test(l));
      // Only statements at the ARM's own block level count as 'above the
      // arm' — an auth call nested inside another route's block is
      // unreachable for this path and must not launder the claim
      // (w54-ledger H-1). The depth is measured, not assumed: the arms
      // sit inside a try{} so their level is whatever the braces say.
      const priorCalls = [];
      let priorAuthed = false;
      if (dispatchStart !== -1) {
        let depth = 0;
        const rows = [];
        for (let i = dispatchStart; i <= hi; i++) {
          const l = lines[i];
          const cs = codeSpan(l);
          const lead = (cs.match(/^\s*\}+/)?.[0].match(/\}/g)?.length ?? 0);
          rows.push({ i, stmtDepth: depth - lead });
          depth += (cs.match(/\{/g)?.length ?? 0) - (cs.match(/\}/g)?.length ?? 0);
          if (depth < 0) depth = 0;
        }
        const armDepth = rows.at(-1)?.stmtDepth ?? 1;
        let braceless = false;
        const priorDead = deadState();
        for (const r of rows.slice(1, -1)) {
          const l = lines[r.i];
          if (r.stmtDepth !== armDepth) continue;
          const cs = codeSpan(l);
          // A braceless `if (c)`/`else`/`for`/`while` at arm depth makes
          // ONLY the one statement after it conditional — the next
          // arm-depth statement is its body, not an unconditional call
          // (w56-ledger F6).
          if (braceless && cs.trim() !== '') { braceless = false; continue; }
          if (/^\s*(?:\}\s*)?(?:if|else\s+if|else|for|while|do)\b/.test(cs)) {
            const bal = (cs.match(/\{/g)?.length ?? 0) - (cs.match(/\}/g)?.length ?? 0);
            if (bal <= 0) {
              // Locate the clause's controlling `)` — text after it on
              // the same line is the (consumed) body, so the flag only
              // survives when the body is due on the NEXT statement.
              const pm = /\b(?:if|for|while)\s*\(/.exec(cs);
              if (!pm) { const rest0 = cs.replace(/^\s*(?:\}\s*)?(?:else|do)\b/, ''); braceless = rest0.trim() === ''; }
              else {
                let d = 0, condEnd = -1;
                for (let ci = cs.indexOf('(', pm.index); ci < cs.length; ci++) {
                  if (cs[ci] === '(') d++;
                  else if (cs[ci] === ')' && --d === 0) { condEnd = ci + 1; break; }
                }
                braceless = condEnd === -1 || cs.slice(condEnd).trim() === '';
              }
            }
            continue;
          }
          if (/^\s*(?:async\s+)?function\s/.test(l)) continue;
          const pl = stripDead(l, priorDead), pm = maskStrings(pl, priorDead);
          priorCalls.push(pl);
          for (const am of pm.matchAll(/auth\(req|authenticateToken|authBreakglass\(|authorize\(/g))
            if (!guardedPrefix(pm, am.index)) priorAuthed = true;
        }
      }
      if ((r.roles[0] === 'authenticated' || r.roles[0] === 'bound subject')
          && !unguardedAuth
          && !priorAuthed) {
        console.error(`route-role parity: ${r.method} ${r.path} — claims '${r.roles[0]}' but no credential resolves on or above the handler`); failed = true; continue;
      }
      continue;
    }
    if (r.listener === 'issuerd' && !(r.roles.length === 1 && r.roles[0] === 'issuer bearer token')) { console.error(`route-role parity: ${r.method} ${r.path} — issuerd rows may only claim 'issuer bearer token'`); failed = true; continue; }
    let code = null;
    if (hi !== -1) {
      const lastSeg = segs[segs.length - 1];
      // The role-row window spans the whole arm too — the fixed 6-line
      // bound let a long handler hide its gate (w57-ledger F5).
      code = authorizeAt(lines, hi, Math.max(6, wEnd - hi), !lastSeg.startsWith('{') ? lastSeg : null);
      if (!code) {
        for (let i = hi; i < Math.min(hi + Math.max(12, wEnd - hi), lines.length); i++) {
          if (i !== hi && isRouteArmIf(lines[i]) && !DISPATCH_2.test(lines[i]) && !isValidationGuard(lines[i])) break;
          const verb = segs[segs.length - 1];
          if (param && !verb.startsWith('{') && !lines[i].includes(verb)) continue;
          const names = [...lines[i].matchAll(/fabric\.([a-zA-Z_]+)\(p[\s,)]/g)].map(x => x[1]);
          const vkey = verb.replace(/-/g, '').toLowerCase();
          const name = names.find(n => n.toLowerCase().includes(vkey)) ?? names[0];
          if (name) { code = fabricRoles(name); break; }
        }
      }
    }
    if (!code) { console.error(`route-role parity: ${r.method} ${r.path} — cannot resolve the role gate`); failed = true; }
    else if (sortR(code) !== sortR(r.roles)) { console.error(`route-role parity: ${r.method} ${r.path} — code=[${sortR(code)}] openapi=[${sortR(r.roles)}]`); failed = true; }
  }
}

// Reverse parity: every live route handler in server.mjs must be declared
// in the emitted contract — an undeclared route is undocumented live code
// the forward parity above never audits (w49-ledger F-2).
{
  const spec = JSON.parse(readFileSync('docs/openapi.json', 'utf8'));
  const declared = new Set();
  for (const [p, ops] of Object.entries(spec.paths ?? {})) {
    const norm = p.split('/').map(s => (s.startsWith('{') && s.endsWith('}') ? '{}' : s)).join('/');
    for (const m of Object.keys(ops)) if (['get', 'post', 'put', 'delete', 'patch'].includes(m)) declared.add(`${m.toUpperCase()} ${norm}`);
  }
  const server = readFileSync('src/server.mjs', 'utf8').split('\n');
  const issuerd = readFileSync('src/issuerd.mjs', 'utf8').split('\n');
  // A literal alternation group (a|b) expands into one path per arm; every
  // other capture group normalizes to the contract's {} placeholder.
  const expandAlternations = rx => {
    let paths = [rx];
    const ALT = /\(([^()]*\|[^()]*)\)/;
    for (let guard = 0; guard < 8; guard++) {
      const i = paths.findIndex(p => ALT.test(p));
      if (i === -1) return paths;
      const m = ALT.exec(paths[i]);
      paths.splice(i, 1, ...m[1].split('|').map(a => paths[i].split(m[0]).join(a)));
    }
    return paths;
  };
  // A '//' inside a string literal (URL, template) is not a comment — the
  // module-scope stripComment above is quote-aware for exactly that
  // reason (w51-ledger H-2).
  // Conditions are audited against the ENCLOSING condition too: a route
  // split across lines or nested under a `// comment`-stripped parent
  // still resolves against its full effective context (w51-ledger H-2).
  const routeSeen = (eff, line) => {
    const meths = [...eff.matchAll(/req\.method\s*===\s*'([A-Z]+)'/g)].map(m => m[1]);
    const lits = [...eff.matchAll(/(?:\bpath\b|req\.url|url\.pathname)\s*===\s*'([^']+)'/g)].map(m => m[1]);
    const rxxs = [...eff.matchAll(/\/\^(.+?)\$\/\.(?:exec|test)\((?:path|req\.url|url\.pathname)\)/g)].map(m => m[1]);
    // Every live handler must take an auditable shape — a `!==`, an
    // `includes()` set, an aliased variable, a switch or a handler table
    // escapes the audit silently (w50-ledger H-2, w51-ledger H-2).
    if (!meths.length) { console.error(`route-spec parity: unauditable method dispatch — ${line.trim().slice(0, 100)}`); failed = true; return; }
    if (!lits.length && !rxxs.length) { console.error(`route-spec parity: unauditable path dispatch — ${line.trim().slice(0, 100)}`); failed = true; return; }
    for (const lit of lits)
      for (const m of meths) if (!declared.has(`${m} ${lit}`)) { console.error(`route-spec parity: ${m} ${lit} handled but absent from docs/openapi.json`); failed = true; }
    for (const r of rxxs) {
      const raw = r.replace(/\\\//g, '/');
      for (const p of expandAlternations(raw)) {
        // Capture groups AND bare char-class quantifiers both mean 'one
        // dynamic segment' — normalize either to the contract's {}
        // placeholder (issuerd's allowlist uses [A-Za-z0-9_-]+ bare).
        const norm = p.replace(/\([^()]+\)/g, '{}').replace(/\[[^\]]*\][+*]/g, '{}');
        for (const m of meths) if (!declared.has(`${m} ${norm}`)) { console.error(`route-spec parity: ${m} ${norm} handled but absent from docs/openapi.json`); failed = true; }
      }
    }
  };
  const auditDispatch = lines => {
  const pending = [];   // confirmed enclosing conditions
  const aliases = new Map(); // const x = req.method|req.url|path bindings
  let tentative = null; // a condition start whose body has not opened yet
  let depth = 0;
  for (const line of lines) {
    const code = stripComment(line);
    const trimmed = code.trim();
    // A leading '}' closes enclosing scopes — drop conditions started at
    // or below the now-closed depth before evaluating this line's context.
    // Braces inside strings/comments are data — the enclosing-scope
    // tracking counts only code (w55-fv H-2).
    const cs0 = codeSpan(code);
    const lead = /^\s*\}+/.exec(cs0)?.[0].match(/\}/g)?.length ?? 0;
    if (lead) { depth = Math.max(0, depth - lead); while (pending.length && pending.at(-1).depth > depth) pending.pop(); tentative = null; }
    // Simple const aliases of the dispatch names resolve into the
    // effective text — `const m = req.method` is the canonicalization
    // pattern, not a hiding place; anything else (req['method'], a
    // switch, an includes-set) stays invisible and is flagged when it
    // reaches a serving line (w51-ledger H-2).
    for (const m of code.matchAll(/\b(?:const|let|var)\s+(\w+)\s*=\s*(req\.method|req\.url|path|url\.pathname)\b/g)) if (m[1] !== 'path' && !aliases.has(m[1])) aliases.set(m[1], m[2]);
    let eff = pending.map(c => c.text).join(' ') + (tentative ? tentative.text : '') + code;
    for (const [n, tok] of aliases) eff = eff.replace(new RegExp(`\\b${n}\\b`, 'g'), tok === 'url.pathname' ? 'path' : tok);
    // Dispatch shapes this gate cannot see are failures, not skips:
    // switch dispatch, non-bare aliasing, path arms that serve without
    // any method arm (w51-ledger H-2).
    // Computed-member and destructured dispatch spellings are the same
    // route under a name the audit cannot read — `req['url']`, `const
    // { url } = req`, a renamed handler param (`u.pathname`), and
    // `.once('request', …)` listeners all flag unauditable rather than
    // skip silently (w57-ledger F6). `url`/`meta` receivers are URL
    // objects (`url.pathname`, `import.meta.url`), not renamed requests.
    if (/\b(?:const|let|var)\s*\{[^}]*\}\s*=\s*(?:req|request)\b|\b(?:req|request)\s*\[\s*['"](?:method|url)['"]\s*\]|\b(?!req\b|request\b|res\b|response\b|url\b|meta\b|import\b)(?<!\.)[A-Za-z_$][\w$]*\.(?:method|url|pathname)\s*(?:===|!==)\s*['"`]|\b(?:once|on)\s*\(\s*['"]request['"]/.test(code)
        && !/req\.method\s*===\s*'[A-Z]+'.*(?:\bpath\b|req\.url|url\.pathname)\s*===\s*'|\b(?:const|let|var)\s+\w+\s*=\s*(?:req\.method|req\.url|path|url\.pathname)\b/.test(code))
      { console.error(`route-spec parity: unauditable dispatch form — ${line.trim().slice(0, 100)}`); failed = true; }
    else if (/\bswitch\s*\([^)]*(?:req\.method|req\.url|path|url\.pathname|['"]method['"]|['"]url['"])/.test(code)) { console.error(`route-spec parity: unauditable switch dispatch — ${line.trim().slice(0, 100)}`); failed = true; }
    else if (/(?:\bpath\b|req\.url|req\s*\[\s*['"]url['"]\s*\]|\w+\.pathname)\s*===\s*'|\.exec\((?:path|req\.url|url\.pathname|\w+\.pathname)\)/.test(code) && !/req\.method|req\s*\[\s*['"]method['"]\s*\]/.test(eff)) { console.error(`route-spec parity: path arm with no enclosing method gate — ${line.trim().slice(0, 100)}`); failed = true; }
    else if (/req\.method/.test(eff) && /\bpath\b|req\.url|url\.pathname/.test(eff)) routeSeen(eff, line);
    // Track enclosing conditions: an `if (` whose block stays open
    // past this line governs the lines below it; a balanced line
    // (single-line handler) closes what it opened and must not leak its
    // condition onto the next line. A tentative `if (` collects until a
    // net-opening '{' confirms it or a ';' kills it (multi-line route
    // conditions, w51-ledger H-2).
    const opens = (cs0.match(/\{/g)?.length ?? 0), closes = (cs0.match(/\}/g)?.length ?? 0) - lead;
    if (/\bif\s*\(/.test(code)) {
      if (opens > closes) { if (tentative) { tentative.text += ' ' + code; pending.push(tentative); } else pending.push({ depth: depth + 1, text: code }); tentative = null; }
      else {
        // A `if (` whose parens stay open is a multi-line condition —
        // collect it until its block opens or a ';' proves a brace-less
        // arm. A balanced `if (` is a complete statement, not a
        // continuation (w55-ledger H-3: tentative was never assigned, so
        // multi-line conditions lost their method context).
        const pd = (cs0.match(/\(/g)?.length ?? 0) - (cs0.match(/\)/g)?.length ?? 0);
        tentative = pd > 0 || /[&|,]\s*$/.test(cs0.trimEnd()) ? { depth: depth + 1, text: code } : null;
      }
    } else if (tentative) {
      tentative.text += ' ' + code;
      if (opens > closes) { pending.push(tentative); tentative = null; }
      else if (code.includes(';')) tentative = null;
    }
    depth += opens - closes;
    if (depth < 0) depth = 0;
    while (pending.length && pending.at(-1).depth > depth) pending.pop();
  }
  };
  auditDispatch(server);
  // The issuerd daemon's own listener gets the same audit — its contract
  // is declared in openapi under x-listener, so an undeclared issuerd
  // dispatch is just as unverifiable as an undeclared fabric one
  // (w52-ledger M-6).
  auditDispatch(issuerd);
  // Live HTTP dispatch outside server.mjs escapes this gate entirely — a
  // second handler file is undocumented live code (w50-ledger H-2). The
  // scan is recursive: a nested file or a helper script cannot slip a
  // handler past the audit (w51-ledger H-2).
  // issuerd.mjs is exempt from THIS outside-scan because auditDispatch()
  // above already audits its dispatch — it is declared in openapi under
  // x-listener (w52-ledger M-6). cli.mjs only imports the audited
  // server.mjs surface; check.mjs is this file.
  const auditExempt = new Set(['src/server.mjs', 'src/issuerd.mjs', 'src/cli.mjs', 'scripts/check.mjs']);
  // The scan rides the TRACKED-file enumeration, not a directory walk: a
  // .cjs helper, a dispatch file outside src|scripts|web, or a symlink
  // landing on one all produced live HTTP surface the three-root walk
  // never saw (w54-ledger H-4). Test files legitimately stand up servers
  // and carry these literals — the exemption covers tests/*.mjs; a .js or
  // .cjs file under tests/ is not a test idiom and still scans
  // (w54-fv M-5).
  for (const p of files.filter(f => CODE_EXT.test(f) && !(f.startsWith('tests/') && f.endsWith('.mjs')) && !auditExempt.has(f) && existsSync(f)))
    // Dispatch-surface parity: a handler keying on req.url, the parsed
    // pathname, request headers or a server factory is an unaudited
    // HTTP surface even when it never reads req.method — and a
    // .js/.cjs-suffixed file is no safer than .mjs (w53-fv M-4,
    // w53-ledger HIGH-3, w54-ledger H-4). Renaming the parameter hides
    // nothing: any `X.method === 'GET'`, `X.url ===`, `X.headers[…]` or
    // a 'request' listener is a dispatch surface under any identifier
    // (w56-ledger F9).
    if (/req\.method|req\.url|url\.pathname|req\.headers|\b(?:req|request)\s*\[\s*['"](?:method|url)['"]\s*\]|\b\w+\.pathname\s*===\s*['"`]|createServer\s*\(|(?:on|once)\s*\(\s*['"]request['"]|\b[A-Za-z_$][\w$]*\.(?:method|url)\s*(?:===|!==)\s*['"`]|\b[A-Za-z_$][\w$]*\.headers\s*(?:\[\s*['"]authorization|\.authorization\b)/.test(readFileSync(p, 'utf8'))) { console.error(`route-spec parity: HTTP dispatch surface in ${p} — outside the audited file`); failed = true; }
}

// Query-parameter parity: the runtime allowlist (QUERY_ALLOW in
// src/server.mjs — method-agnostic) must equal the contract's declared
// in:'query' parameter set per path. A param the gate accepts but the
// contract doesn't declare is unverifiable surface; one the contract
// declares but the gate rejects is a contract lie (w52-ledger L-3).
{
  const src = readFileSync('src/server.mjs', 'utf8');
  const spec = JSON.parse(readFileSync('docs/openapi.json', 'utf8'));
  const qaBlock = /QUERY_ALLOW\s*=\s*new Map\(\[([\s\S]*?)\]\)/.exec(src);
  if (!qaBlock) { console.error('query-param parity: QUERY_ALLOW literal not found in src/server.mjs'); failed = true; }
  else {
    const gate = new Map();
    for (const m of qaBlock[1].matchAll(/\[\s*'([^']+)'\s*,\s*\[([^\]]*)\]\s*\]/g))
      gate.set(m[1], new Set([...m[2].matchAll(/'([^']+)'/g)].map(x => x[1])));
    const specQueries = new Map();
    for (const [p, ops] of Object.entries(spec.paths ?? {}))
      for (const [mth, op] of Object.entries(ops)) {
        if (!['get', 'post', 'put', 'delete', 'patch'].includes(mth)) continue;
        const names = (op.parameters ?? []).filter(x => x.in === 'query').map(x => x.name);
        if (names.length) {
          const s = specQueries.get(p) ?? new Set(); names.forEach(n => s.add(n)); specQueries.set(p, s);
        }
      }
    const eq = (a, b) => a.size === b.size && [...a].every(x => b.has(x));
    for (const [p, names] of gate)
      if (!eq(names, specQueries.get(p) ?? new Set())) { console.error(`query-param parity: ${p} — gate=[${[...names]}] contract=[${[...(specQueries.get(p) ?? [])]}]`); failed = true; }
    for (const p of specQueries.keys())
      if (!gate.has(p)) { console.error(`query-param parity: ${p} — contract declares query params the gate rejects`); failed = true; }
  }
}

// The README's declared suite size must equal the committed test summary —
// a stale count is a doc claim contradicted by the suite (w20-ledger F-5).
{
  const m = /(\d+)-test suite/.exec(readFileSync('README.md', 'utf8'));
  const summary = existsSync('reports/test-summary.json') ? JSON.parse(readFileSync('reports/test-summary.json', 'utf8')) : null;
  if (!m || !summary || Number(m[1]) !== summary.tests) { console.error(`README test count (${m?.[1] ?? 'missing'}) != reports/test-summary.json (${summary?.tests ?? 'missing'})`); failed = true; }
}

// MANIFEST.sha256 must describe exactly the tracked tree — silent drift fails.
const mf = spawnSync(process.execPath, ['scripts/manifest.mjs', '--verify'], SPAWN_OPTS);
if (mf.status !== 0) { console.error(mf.stderr || mf.stdout); failed = true; }

// The ledger honesty gate itself: requirements.csv and the summary must be
// the exact regeneration of traceability.py, whose evidence binding is
// execution-bound (cited tests must have passed in reports/tests.tap).
// Without this step `npm run check` alone proved nothing about the 173
// VERIFIED rows (w48-ledger F-6).
const tr = spawnSync('python3', ['scripts/traceability.py', '--check'], SPAWN_OPTS);
if (tr.status !== 0) { console.error(tr.stderr || tr.stdout); failed = true; }
console.log(JSON.stringify({ syntax_files: files.length, syntax_and_focused_source_checks: !failed, security_certification: false }));
if (failed) process.exitCode = 1;

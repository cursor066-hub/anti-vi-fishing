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
const ANY_EXT = /\.(mjs|js|cjs|ts|mts|cts)$/;
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
const SINK_EXT = /\.(mjs|js|cjs|ts|mts|cts|jsx|tsx|py|sh|bash|zsh|ps1|yml|yaml|html|htm|json)$/;
const SINK_RULES = [
  // The vm specifier is spelled in pieces so this file does not flag its
  // own rule table (w49-ledger F-1).
  // Member-invoked, parenthesized and concatenated spellings of the
  // same sink are equally unforgeable — plain identifier patterns could
  // not see them (w57-ledger F7).
  ['dynamic eval', new RegExp(`\\beval\\s*\\(|eval\\s*\\?\\s*\\.\\s*\\(|eval\\s*\\?\\s*\\.\\s*(?:call|apply|bind)\\s*\\(|\\(\\s*0\\s*,\\s*eval\\s*\\)\\s*\\(|eval\\s*\\/\\*[^*]*\\*\\/\\s*\\(|eval\\s*\\.\\s*bind\\s*\\(|eval\\s*\\[['"](?:call|apply|bind)['"]\\]|new\\s+Function\\s*\\(|eval\\s*\\/\\*\\*\\/\\s*\\(|\\bFunction\\s*\\(|eval\\s*\\.\\s*(?:call|apply)\\s*\\(|new\\s*\\([^)]*\\bFunction\\b|\\(\\s*Function\\s*\\)\\s*\\(|\\b[A-Za-z_$][\\w$]*\\s*=\\s*Function\\s*;|Function\\s*\\.\\s*(?:call|apply|bind)\\s*\\(|\\.constructor\\s*(?:\\.\\s*constructor\\s*)+\\(|globalThis\\s*\\[[^\\]]*['"][^\\]]*\\]\\s*\\(|globalThis\\s*\\.\\s*eval|import\\s*\\(\\s*['"\`]data:|['"]ev['"]\\s*\\+\\s*['"]al['"]|['"]e['"]\\s*\\+\\s*['"]val['"]|Reflect\\.(?:apply|construct)\\s*\\(\\s*(?:eval|Function)|node:${'v'}m|from\\s+['"](?:node:)?${'v'}m['"]|require\\s*\\(\\s*['"](?:node:)?${'v'}m['"]|import\\s*\\(\\s*['"](?:node:)?${'v'}m['"]|runIn(?:This|New)?Context`)],
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
  // ANY non-alphanumeric run between marker letters is a separator —
  // slashes, pluses, dashes, pipes, stars, spaces, em/en dashes all
  // spell the same unfinished plant (w58-fv F-7). The letters are split
  // literals so this table does not flag itself.
  ['unfinished code marker', new RegExp(`\\b(?:${'T'}[^A-Za-z0-9]{0,3}${'O'}[^A-Za-z0-9]{0,3}${'D'}[^A-Za-z0-9]{0,3}${'O'}|${'Ｔ'}[^A-Za-z0-9]{0,3}${'Ｏ'}[^A-Za-z0-9]{0,3}${'Ｄ'}[^A-Za-z0-9]{0,3}${'Ｏ'}|${'F'}[^A-Za-z0-9]{0,3}${'I'}[^A-Za-z0-9]{0,3}${'X'}[^A-Za-z0-9]{0,3}${'M'}[^A-Za-z0-9]{0,3}${'E'}|${'Ｆ'}[^A-Za-z0-9]{0,3}${'Ｉ'}[^A-Za-z0-9]{0,3}${'Ｘ'}[^A-Za-z0-9]{0,3}${'Ｍ'}[^A-Za-z0-9]{0,3}${'Ｅ'}|${'T'}[^A-Za-z0-9]{0,3}${'B'}[^A-Za-z0-9]{0,3}${'D'}|${'W'}[^A-Za-z0-9]{0,3}${'I'}[^A-Za-z0-9]{0,3}${'P'}|${'H'}[^A-Za-z0-9]{0,3}${'A'}[^A-Za-z0-9]{0,3}${'C'}[^A-Za-z0-9]{0,3}${'K'})\\b`)],
  // The triple-X word followed by a colon is a planted unfinished-marker
  // label, not the ISO-4217 fixture value — the bare word stays exempt
  // (w54-fv M-5); separated letter spellings are the same marker.
  ['unfinished code marker (xxx label)', new RegExp(`\\b${'X'}[^A-Za-z0-9]{0,3}${'X'}[^A-Za-z0-9]{0,3}${'X'}\\s*:`)]
];
// Case-insensitive on authored files: a lowercase marker is the same
// unfinished code (w49-ledger F-1). reports/ is exempt — its generated
// TAP summary lines name the deferred-count protocol field, not authored
// markers; the few files that legitimately name node:test's skip/defer
// vocabulary dodge the literal word instead.
const MARKER_LOOSE = [
  ['unfinished code marker (any case)', new RegExp(`\\b(?:${'T'}[^A-Za-z0-9]{0,3}${'O'}[^A-Za-z0-9]{0,3}${'D'}[^A-Za-z0-9]{0,3}${'O'}|${'Ｔ'}[^A-Za-z0-9]{0,3}${'Ｏ'}[^A-Za-z0-9]{0,3}${'Ｄ'}[^A-Za-z0-9]{0,3}${'Ｏ'}|${'F'}[^A-Za-z0-9]{0,3}${'I'}[^A-Za-z0-9]{0,3}${'X'}[^A-Za-z0-9]{0,3}${'M'}[^A-Za-z0-9]{0,3}${'E'}|${'Ｆ'}[^A-Za-z0-9]{0,3}${'Ｉ'}[^A-Za-z0-9]{0,3}${'Ｘ'}[^A-Za-z0-9]{0,3}${'Ｍ'}[^A-Za-z0-9]{0,3}${'Ｅ'}|${'T'}[^A-Za-z0-9]{0,3}${'B'}[^A-Za-z0-9]{0,3}${'D'}|${'W'}[^A-Za-z0-9]{0,3}${'I'}[^A-Za-z0-9]{0,3}${'P'}|${'H'}[^A-Za-z0-9]{0,3}${'A'}[^A-Za-z0-9]{0,3}${'C'}[^A-Za-z0-9]{0,3}${'K'})\\b`, 'i')],
  ['unfinished code marker (xxx label any case)', new RegExp(`\\b${'X'}[^A-Za-z0-9]{0,3}${'X'}[^A-Za-z0-9]{0,3}${'X'}\\s*:`, 'i')]
];
// DOM-injection sinks matter in ANY code that renders — not only src/ and
// web/: an .html asset or script-generated page outside those roots could
// carry a live sink (w49-ledger F-1). Tests legitimately contain these
// strings inside regexes that assert their absence; this file exempts
// itself because it hosts the rules.
const RENDER_ONLY = [
  // Bracket-member assignment, writeln, and the Function constructor are
  // the same sink under a different spelling (w56-ledger F10).
  ['DOM injection', /\.(?:innerHTML|outerHTML|srcdoc)\s*(?:=|\+=|\?\?=)|\[\s*['"](?:innerHTML|outerHTML|srcdoc)['"]\s*\]\s*(?:=|\+=|\?\?=)|\[\s*['"](?:inner|outer|srcdoc)['"]\s*\+\s*['"](?:HTML)?['"]\s*\]\s*(?:=|\+=|\?\?=)|Reflect\.set\s*\([^)]*['"](?:inner|outer|srcdoc)|Object\.assign\s*\([^)]*\binnerHTML\b|insertAdjacentHTML|(?:document|doc|d|el|target|element|node)\s*\.\s*write(?:ln)?\s*\(|document\s*\[[^\]]*writ[^\]]*\]|new\s*\(?\s*Function\s*\)?\s*\(/]
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
const deadState = () => ({ pending: false, block: false, pdepth: 0 });
// Whether the dead-operand span carries past this line: a `;`/`{`/`}` at
// paren depth 0 ends the statement, and so does a `,` — but a `,` inside
// an unclosed call/`(` group is an ARGUMENT separator inside the dead
// operand, so the span still owns the next line (w59-ledger F-4).
const deadContinues = (m, depth = 0) => {
  let d = depth;
  for (const c of m) {
    if (c === '(') d++;
    else if (c === ')') d--;
    else if (d <= 0 && (c === ';' || c === '{' || c === '}' || c === ',')) return { cont: false, depth: d };
  }
  return { cont: true, depth: d };
};
// A /* */ run is dead text too — its authorize-shaped content minted
// evidence exactly like a //-comment did (w57-ledger F2). The blanker is
// shared by every twin view (`lm`, `lraw`, and the depth arithmetic that
// reads them): a `/* { */` surviving in only one view desyncs the brace
// ordinals that map the twins and every depth-keyed decision
// (w60-ledger F-1/F-4). `/*` is unambiguous — it ALWAYS opens a comment,
// never division — and block comments span lines through `dead.block`.
const blankBlock = (out, dead) => {
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
  return chars.join('');
};
// A line ending in an infix/continuation token cannot complete its
// operand — the dead-operand span owns the next line. An expression-
// complete tail (`x`, `f(x)`, `'`string`'`) ends by ASI and owns
// nothing past the break (w60-ledger F-2/F-5).
const opTailOf = s => /[(.,?:+\-*\/%^<>=!&|~`]/.test(s.trimEnd().at(-1) ?? '');
const stripDead = (l, dead = deadState()) => {
  if (dead.pending) {
    // The dead operand owns this line unless a statement keyword opens
    // a fresh statement — an operand-start identifier/call included,
    // `false &&\nauthorize(...)` being exactly that shape (w60-ledger
    // F-2/F-5). A comment-or-blank line inside the operand waits for
    // the operand's start — pending unchanged.
    const seg = blankBlock(stripComment(l), dead);
    if (!/\S/.test(seg)) return ' ';
    if (!/^\s*(?:if|for|while|switch|return|const|let|var|function|class|throw|import|export|else|do|case|default|break|continue|try|catch|finally|[{}])/.test(seg)) {
      const nx = deadContinues(seg, dead.pdepth);
      dead.pending = nx.cont && (nx.depth > 0 || opTailOf(seg));
      dead.pdepth = nx.depth;
      return ' ';
    }
    dead.pending = false; dead.pdepth = 0;
  }
  let out = stripComment(l);
  out = blankBlock(out, dead);
  const livePrefix = i => { const b = out.slice(0, i).trimEnd(); return /[=!<>]=+\s*$|[&^~%+\-*/!<>]\s*$/.test(b) && !/(?:\|\||&&|\?|:)\s*$/.test(b); };
  // Splice right-to-left: replacing earlier spans first would drift the
  // indices the later matches were collected on. A match terminated BY
  // a `;`/`{`/`}` ended with its statement — only an unterminated
  // operand (EOL mid-expression) may carry `pending` into the next
  // line (w60-ledger F-2).
  for (const m of [...out.matchAll(/\b(?:false|0|null|undefined|!true)\s*&&[^;{}]*/g)].reverse()) {
    if (inString(out, m.index) || livePrefix(m.index)) continue;
    const nx = deadContinues(m[0]);
    // The operand carries past the break only when it is genuinely
    // unfinished — open depth or an operator tail; `false && x` ended
    // by ASI owns no next line (w60-ledger F-2/F-5).
    const nxt = out[m.index + m[0].length]; if (nx.cont && nxt !== ';' && nxt !== '}' && (nx.depth > 0 || opTailOf(m[0]))) { dead.pending = true; dead.pdepth = nx.depth; }
    out = out.slice(0, m.index) + ' ' + out.slice(m.index + m[0].length);
  }
  for (const m of [...out.matchAll(/\b(?:true|!false|1)\s*\|\|[^;{}]*/g)].reverse()) {
    if (inString(out, m.index) || livePrefix(m.index)) continue;
    const nx = deadContinues(m[0]);
    const nxt = out[m.index + m[0].length]; if (nx.cont && nxt !== ';' && nxt !== '}' && (nx.depth > 0 || opTailOf(m[0]))) { dead.pending = true; dead.pdepth = nx.depth; }
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
  let rx = false, rxClass = false;
  // `${ expr }` inside a template literal is live code, not string data —
  // an `auth(req)` inside the interpolation dodged every call scan while
  // the gate believed the row unauthenticated (w59-ledger F-7). The
  // template's literal segments still mask; inside `${}`s braces carry
  // the interpolation's own depth and strings mask recursively. `tStack`
  // persists across calls via `dead` so a template spanning lines keeps
  // its interpolation state.
  const tStack = dead ? (dead.tstack ??= []) : [];
  for (let i = 0; i < out.length; i++) {
    const c = out[i];
    if (rx) {
      if (c === '\\') { out[i] = ' '; if (i + 1 < out.length) out[++i] = ' '; continue; }
      if (c === '[') rxClass = true;
      else if (c === ']') rxClass = false;
      else if (c === '/' && !rxClass) rx = false;
      out[i] = ' ';
      continue;
    }
    if (q) {
      if (c === '\\') { out[i] = ' '; if (i + 1 < out.length) out[++i] = ' '; continue; }
      if (q === '`' && c === '$' && out[i + 1] === '{') { out[i] = ' '; out[i + 1] = ' '; i++; tStack.push(1); q = null; continue; }
      out[i] = ' ';
      if (c === q) q = null;
      continue;
    }
    if (tStack.length) {
      if (c === '{') tStack[tStack.length - 1]++;
      else if (c === '}') {
        tStack[tStack.length - 1]--;
        if (tStack[tStack.length - 1] === 0) { tStack.pop(); q = '`'; out[i] = ' '; continue; }
      } else if (c === "'" || c === '"' || c === '`') { q = c; out[i] = ' '; continue; }
      else if (c === '/') {
        let j = i - 1;
        while (j >= 0 && out[j] === ' ') j--;
        const prev = j < 0 ? '' : out[j];
        const word = /([A-Za-z_$][\w$]*)\s*$/.exec(text.slice(0, i))?.[1] ?? '';
        if (j < 0 || '=(:,[!&|?{};~^*%<>+-'.includes(prev) || /^(?:return|typeof|case|in|of|do|else|throw|delete|void|yield|await|new|instanceof)$/.test(word))
          { rx = true; out[i] = ' '; continue; }
      }
      continue;
    }
    if (c === "'" || c === '"' || c === '`') { q = c; out[i] = ' '; continue; }
    if (c === '/') {
      // A `/` right after an operator, keyword or statement edge opens a
      // regex literal — `/auth/` must not mint an auth call inside its
      // body (w58-ledger F4). A `/` after a value (identifier, `)`, `]`,
      // digit) is division.
      let j = i - 1;
      while (j >= 0 && out[j] === ' ') j--;
      const prev = j < 0 ? '' : out[j];
      const word = /([A-Za-z_$][\w$]*)\s*$/.exec(text.slice(0, i))?.[1] ?? '';
      if (j < 0 || '=(:,[!&|?{};~^*%<>+-'.includes(prev) || /^(?:return|typeof|case|in|of|do|else|throw|delete|void|yield|await|new|instanceof)$/.test(word))
        { rx = true; out[i] = ' '; continue; }
    }
  }
  dead.str = tStack.length ? null : (q === '`' ? '`' : null);
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
  return /&&|\|\||\?|=>|(?:^|[^\w$])if\s*\(|(?:^|[^\w$])(?:else|for|while|do|case|default)(?:\s|$)/.test(stmt);
};
// A call inside a conditional BODY gates only a slice of requests and
// cannot satisfy an unconditional 'authenticated' or role claim —
// `if (x) { authorize }`, an else/case/catch/try arm, an arrow body, a
// braceless `if (x)\n  authorize()`, a line broken after `&&`/`||`/`?`
///`:` (w58-fv F-3, w58-ledger F5). The tracker walks masked lines:
// `{`s after a control `)` (read back on the operand-live twin) or a
// conditional keyword open conditional depths, and a dangling opener
// makes the next statement conditional.
// A static expression folder for dead-condition judgment — the regex
// whitelist kept drifting one orthography behind (`0x0`, `''`, `void 0`,
// `false||false`, `(x,false)`, `1===1===1`, `for(;false;)`, `i<0`,
// `of ''`/`of new Set()`; w60-fv F-1, w60-ledger F-3/F-8). `litPrim`
// returns the JS value of a statically-known expression (with LV_*
// sentinels for unknown and for literal object/array/new forms), and
// `litVal` folds that to truthiness: true / false / LV_NUL (provable
// nullish — `x ?? y` cares) / null (not provable).
const LV_NUL = Symbol('litNullish'), LV_UNK = Symbol('litUnknown'), LV_OBJ = Symbol('litObject'), LV_ARR = Symbol('litArray');
const isLitMarker = v => v === LV_OBJ || v === LV_ARR || (typeof v === 'object' && v !== null && v.newCtor !== undefined);
const truthyPrim = v => isLitMarker(v) ? true : Boolean(v);
const topSplit = (t, ops) => {
  // Split `t` at depth-0 occurrences of any op (skipping strings). A
  // match at the expression start is a unary/sign, not a split point.
  const parts = [], found = [];
  let d = 0, cur = 0, i = 0, instr = null;
  while (i < t.length) {
    const c = t[i];
    if (instr) { if (c === '\\') { i += 2; continue; } if (c === instr) instr = null; i++; continue; }
    if (c === '"' || c === "'" || c === '`') { instr = c; i++; continue; }
    if (c === '(' || c === '[' || c === '{') { d++; i++; continue; }
    if (c === ')' || c === ']' || c === '}') { d--; i++; continue; }
    if (d === 0 && i > cur) {
      let hit = null;
      for (const op of ops) {
        if (!t.startsWith(op, i)) continue;
        if (op === '>' && t[i - 1] === '=') break;       // `=>` arrow tail, not a comparison
        hit = op; break;
      }
      if (hit) { parts.push(t.slice(cur, i)); found.push(hit); cur = i + hit.length; i = cur; continue; }
    }
    i++;
  }
  if (!found.length) return null;
  parts.push(t.slice(cur));
  return { parts, ops: found };
};
const ternaryParts = t => {
  // `a ? b : c` at depth 0 → [cond, a, b] — `?.`/`??` are not marks.
  let d = 0, instr = null, q = -1;
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (instr) { if (c === '\\') i++; else if (c === instr) instr = null; continue; }
    if (c === '"' || c === "'" || c === '`') { instr = c; continue; }
    if (c === '(' || c === '[' || c === '{') d++;
    else if (c === ')' || c === ']' || c === '}') d--;
    else if (d === 0 && c === '?' && t[i + 1] !== '.' && t[i + 1] !== '?' && t[i - 1] !== '?') { q = i; break; }
  }
  if (q < 0) return null;
  let d2 = 0, instr2 = null;
  for (let j = q + 1; j < t.length; j++) {
    const c = t[j];
    if (instr2) { if (c === '\\') j++; else if (c === instr2) instr2 = null; continue; }
    if (c === '"' || c === "'" || c === '`') { instr2 = c; continue; }
    if (c === '(' || c === '[' || c === '{') d2++;
    else if (c === ')' || c === ']' || c === '}') { if (d2 === 0) break; d2--; }
    else if (d2 === 0 && c === ':') return [t.slice(0, q), t.slice(q + 1, j), t.slice(j + 1)];
  }
  return null;
};
const litPrim = (e0, known) => {
  let t = e0.trim();
  // Unwrap balanced outer parens: `(false)` folds like `false`.
  while (t.startsWith('(')) {
    let d = 0, close = -1;
    for (let i = 0; i < t.length; i++) { const c = t[i]; if (c === '(') d++; else if (c === ')') { d--; if (d === 0) { close = i; break; } } }
    if (close !== t.length - 1) break;
    t = t.slice(1, -1).trim();
  }
  if (!t) return LV_UNK;
  const comma = topSplit(t, [',']); if (comma) return litPrim(comma.parts[comma.parts.length - 1], known);
  const ter = ternaryParts(t);
  if (ter) { const c = litVal(ter[0], known); if (c === true) return litPrim(ter[1], known); if (c === false || c === LV_NUL) return litPrim(ter[2], known); return LV_UNK; }
  for (const op of ['??', '||', '&&']) {
    const s = topSplit(t, [op]); if (!s) continue;
    const vals = s.parts.map(p => litPrim(p, known));
    if (op === '??') { for (let i = 0; i < vals.length - 1; i++) { if (vals[i] === LV_UNK) return LV_UNK; if (vals[i] !== null && vals[i] !== undefined) return vals[i]; } return vals[vals.length - 1]; }
    if (op === '||') { for (const v of vals) { if (v === LV_UNK) return LV_UNK; if (truthyPrim(v)) return v; } return vals[vals.length - 1]; }
    for (const v of vals) { if (v === LV_UNK) return LV_UNK; if (!truthyPrim(v)) return v; }
    return vals[vals.length - 1];
  }
  // Comparison binds tighter than the logic arms — `1===1===1` folds
  // left-associatively ((1===1)===1 → true===1 → false), `a instanceof
  // K` against a provable literal left (w60-fv F-7).
  const cm = topSplit(t, ['===', '!==', 'instanceof', '>=', '<=', '==', '!=', '>', '<']);
  if (cm) {
    let acc = litPrim(cm.parts[0], known);
    for (let i = 0; i < cm.ops.length; i++) {
      const op = cm.ops[i];
      if (acc === LV_UNK) return LV_UNK;
      if (op === 'instanceof') {
        const rn = /^\s*([A-Za-z_$][\w$]*)\s*$/.exec(cm.parts[i + 1])?.[1];
        if (!rn) return LV_UNK;
        if (acc === LV_OBJ) { acc = rn === 'Object'; continue; }
        if (acc === LV_ARR) { acc = rn === 'Array' || rn === 'Object'; continue; }
        if (typeof acc === 'object' && acc !== null && acc.newCtor !== undefined) { acc = rn === acc.newCtor || rn === 'Object'; continue; }
        return LV_UNK;
      }
      const b = litPrim(cm.parts[i + 1], known);
      if (b === LV_UNK) return LV_UNK;
      if (isLitMarker(acc) || isLitMarker(b)) return LV_UNK;
      acc = op === '===' ? acc === b : op === '!==' ? acc !== b : op === '==' ? acc == b : op === '!=' ? acc != b : op === '>=' ? acc >= b : op === '<=' ? acc <= b : op === '>' ? acc > b : acc < b;
    }
    return acc;
  }
  if (t === 'true') return true;
  if (t === 'false') return false;
  if (t === 'null') return null;
  if (t === 'undefined') return undefined;
  if (t === 'NaN') return NaN;
  if (t === 'Infinity') return Infinity;
  if (/^void\s/.test(t)) return undefined;
  if (/^typeof\s/.test(t)) return 'x';
  const sm = /^(['"`])((?:\\.|(?!\1)[^\\])*)\1$/s.exec(t);
  if (sm) {
    if (sm[1] === '`' && sm[2].includes('${')) return LV_UNK;
    return sm[2].replace(/\\([\\'"`nrtb0])/g, (m, c) => ({ n: '\n', r: '\r', t: '\t', b: '\b', '0': '\x00' })[c] ?? c);
  }
  if (/^[A-Za-z_$][\w$]*$/.test(t)) return known?.get(t) ?? LV_UNK;
  if (/^[+-]?(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+|\d[\d_]*(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?[nN]?$/.test(t)) {
    const n = Number(t.replace(/_/g, '').replace(/[nN]$/, ''));
    return Number.isNaN(n) ? LV_UNK : n;
  }
  if (t.startsWith('!')) { const v = litVal(t.slice(1), known); return v === null ? LV_UNK : v !== true; }
  if (/^[+-]/.test(t)) { const n = litPrim(t.slice(1), known); if (n === LV_UNK || isLitMarker(n)) return LV_UNK; const num = Number(n); return Number.isNaN(num) ? LV_UNK : (t[0] === '-' ? -num : num); }
  if (/^\{[\s\S]*\}$/.test(t)) return LV_OBJ;
  if (/^\[[\s\S]*\]$/.test(t)) return LV_ARR;
  const nm = /^new\s+([A-Za-z_$][\w$]*)/.exec(t); if (nm) return { newCtor: nm[1] };
  if (/\)\s*=>|^[\s\S]*=>|^\s*(?:async\s+)?function\b|^\s*class\b/.test(t)) return LV_OBJ;
  const fm = /^(Boolean|Number|String)\s*\(([\s\S]*)\)$/.exec(t);
  if (fm) {
    const v = litPrim(fm[2], known);
    if (v === LV_UNK) return LV_UNK;
    if (fm[1] === 'Boolean') return truthyPrim(v);
    if (fm[1] === 'Number') return isLitMarker(v) ? LV_UNK : Number(v);
    return isLitMarker(v) ? LV_UNK : String(v);
  }
  return LV_UNK;
};
const litVal = (e, known) => {
  const v = litPrim(e, known);
  if (v === LV_UNK) return null;
  if (v === null || v === undefined) return LV_NUL;
  return truthyPrim(v);
};
const condTracker = () => {
  const condDepths = [];
  const deadDepths = new Set();
  let pending = false;
  // A braceless provably-dead condition (`if (0) x()`) dead-spans its
  // single statement exactly like the braced arm — the `}`-free form
  // minted `any` where `if (0) { x() }` minted nothing (w60 gate hole).
  // Cleared at `;`/`}`/`else` on the line or across lines.
  let bracelessDead = false;
  // The word owning the `(` matching a trailing `)` — `if (`/`catch (`
  // gate their body; `for`/`while`/`switch`/`function` do not (w58
  // doctrine: a loop body is the handler's own scope). Runs on the
  // raw-masked twin (`lraw`) so a dead-operand blanked `)` cannot hide
  // the brace's owner (w59-ledger F-6).
  const parenOwner = prev => {
    let d = 0;
    for (let k = prev.length - 1; k >= 0; k--) {
      const c = prev[k];
      if (c === ')') d++;
      else if (c === '(') {
        d--;
        if (d === 0) return /([A-Za-z_$][\w$]*)\s*$/.exec(prev.slice(0, k))?.[1] ?? '';
      }
    }
    return null;
  };
  // A literal-false condition makes its block provably dead — not merely
  // conditional: `while (false)`, `for (const x of [])`, `if (false)`,
  // `else if (0)` bodies never run at all, so an authorize inside can
  // neither mint a role nor break an 'unauthenticated' claim
  // (w59-ledger F-6). `prev` ends with the condition's `)` (whitespace
  // tolerated); the cond slice ends at that `)`, not at the line end.
  const deadCond = prev => {
    let d = 0, close = -1;
    for (let k = prev.length - 1; k >= 0; k--) {
      const c = prev[k];
      if (c === ')') { if (d === 0) close = k; d++; }
      else if (c === '(') {
        d--;
        if (d === 0) {
          const head = /([A-Za-z_$][\w$]*)\s*$/.exec(prev.slice(0, k))?.[1] ?? '';
          const cond = prev.slice(k + 1, close);
          if (/^(?:if|while)$/.test(head)) {
            const v = litVal(cond, null);
            return v === false || v === LV_NUL;
          }
          if (head !== 'for') return false;
          // `for` heads are three spellings: classic `init;cond;step`
          // (dead when the middle clause folds falsy — the init's own
          // bound values count, so `let i=0;i<0` is dead), `of`/`in`
          // iteration (dead over a provably-empty iterable), and the
          // infinite `;;` form (live). (w60-fv F-1, w60-ledger F-3.)
          const s = topSplit(cond, [';']);
          if (!s) {
            const om = /\b(of|in)\s+([\s\S]+?)\s*$/.exec(cond);
            if (!om) return false;
            const operand = litPrim(om[2], null);
            if (om[1] === 'in') return operand === LV_OBJ || operand === null || operand === undefined;
            // `of` over `''`/`[]`/a fresh empty container iterates zero
            // times; over `{}`/null/undefined it throws before the body
            // runs — the body is dead either way.
            return operand === '' || operand === LV_ARR || operand === LV_OBJ || operand === null || operand === undefined
              || (typeof operand === 'object' && operand !== null && /^(?:Set|Map|WeakMap|WeakSet)$/.test(operand.newCtor ?? '') && /^new\s+[A-Za-z_$][\w$]*\s*(?:\(\s*(?:\[\s*\])?\s*\)|$)/.test(om[2]));
          }
          if (s.parts.length !== 3) return false;
          const mid = s.parts[1].trim();
          if (!mid) return false;
          const known = new Map();
          for (const decl of topSplit(s.parts[0], [','])?.parts ?? [s.parts[0]]) {
            const dm = /^(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*([\s\S]+)$/.exec(decl.trim());
            if (dm) { const v = litPrim(dm[2], known); if (v !== LV_UNK) known.set(dm[1], v); }
          }
          const v = litVal(mid, known);
          return v === false || v === LV_NUL;
        }
      }
    }
    return false;
  };
  // `line` walks one masked line at start depth `sd`. `mode` 'ours'
  // marks the row's own dispatch `{` — its body is the row's entry
  // scope and is unconditional even though its opener is an `if`;
  // 'sibling' marks a dispatch arm for a DIFFERENT verb — that arm is
  // dead for this row rather than conditional, so an own-verb arm
  // nested inside it still mints unconditionally (w56-fv F-2).
  const line = (lm, sd, mode, lraw) => {
    const condPos = new Uint8Array(lm.length);
    // `{` positions on the operand-live twin — stripDead COMPACTS dead
    // operands out of `lm`, so an `lraw.slice(0, ci)` offset would map
    // wrong. `{`s are dead-span boundaries and survive in both views,
    // so the n-th `{` in `lm` is the n-th `{` in `lraw` (w59-ledger F-6).
    const rawBraces = [];
    if (lraw) for (let i = 0; i < lraw.length; i++) if (lraw[i] === '{') rawBraces.push(i);
    let ld = sd, pendingUsed = pending, armBraceTaken = false, braceN = 0, pd = 0;
    pending = false;
    for (let ci = 0; ci < lm.length; ci++) {
      const c = lm[ci];
      if (bracelessDead && pd === 0 && (c === ';' || c === '}' || (c === 'e' && /^else\b/.test(lm.slice(ci))))) bracelessDead = false;
      if (c === '{') {
        // The brace-owner analysis needs a view where dead-operand
        // blanking left operators intact: stripDead eats `false &&` and
        // the `)` after it, so the masked `lm` cannot prove a `)` ever
        // closed the condition. `lraw` is the string-masked but operand-
        // live twin — the `)` test, the paren-owner word, the dead-
        // condition read, and the else/catch probes all run on it.
        const rawCi = lraw ? rawBraces[braceN] : undefined;
        const prevR = rawCi !== undefined ? lraw.slice(0, rawCi) : lm.slice(0, ci);
        braceN++;
        const parenHead = /\)\s*$/.test(prevR) ? parenOwner(prevR) : null;
        ld++;
        if (deadDepths.size > 0 || (parenHead !== null && deadCond(prevR))) deadDepths.add(ld);
        else {
          let cond;
          if (mode === 'ours' && !armBraceTaken && parenHead !== null) { cond = false; armBraceTaken = true; }
          else if (parenHead !== null) cond = mode === 'sibling' ? false : parenHead === 'if' || parenHead === 'catch';
          // try/finally bodies run unconditionally — only else/catch/
          // arrow/case/default bodies gate a slice of requests (w58: a
          // `try {` arm wrongly marked authenticateToken conditional).
          else if (/(?:\b(?:else|catch)\b|=>\s*$|\bcase\b[^;]*:\s*$|\bdefault\s*:\s*$)/.test(prevR)) cond = mode !== 'sibling';
          else if (pendingUsed) cond = mode !== 'sibling';
          else cond = false;
          if (cond) condDepths.push(ld);
        }
      } else if (c === '}') {
        deadDepths.delete(ld);
        while (condDepths.length && condDepths[condDepths.length - 1] >= ld) condDepths.pop();
        ld--;
      } else if (c === ';') pendingUsed = false;
      else if (c === '(') pd++;
      else if (c === ')') {
        // The `)` of a deadCond-proven control head with no `{` after
        // owns its braceless body statement — dead, not conditional.
        const prevR = lm.slice(0, ci + 1).trimEnd();
        const head = /\)\s*$/.test(prevR) ? parenOwner(prevR) : null;
        if ((head === 'if' || head === 'while' || head === 'for') && deadCond(prevR)) {
          let j = ci + 1;
          while (j < lm.length && /\s/.test(lm[j])) j++;
          if (j >= lm.length || lm[j] !== '{') bracelessDead = true;
        }
        pd--;
      }
      condPos[ci] = deadDepths.size > 0 || bracelessDead ? 2 : (condDepths.length > 0 || pendingUsed ? 1 : 0);
    }
    // A line ending on a conditional opener or a short-circuit/ternary
    // edge makes the NEXT statement conditional (braceless body or a
    // broken expression operand).
    const tail = lm.trimEnd();
    if (!/[;{}]\s*$/.test(tail)
        && /(?:\b(?:if|for|while|switch|catch)\s*(?:\([^()]*\)\s*)?|\belse\b|\bcatch\b|=>|&&|\|\||\?|:)\s*$/.test(tail)) pending = true;
    return { condPos, endDepth: ld };
  };
  return { line };
};
// A verb-dispatch `m[N]` under every index spelling — quoted, hex,
// octal, binary, float, unary-plus, optional-chain, `.at()` — and
// aliases bound by `sub = m[2]` / `const {2: sub} = m` all dispatch
// exactly like `m[2]` (w58-fv F-4). The index expression is parsed, not
// regex-spelled.
const DISP_IDX_EVAL = expr => {
  const t = expr.trim().replace(/^\++/, '');
  const q = /^['"`]([^'"`]+)['"`]?$/.exec(t);
  const raw = (q ? q[1] : t).trim();
  return /^\d+$/.test(raw) ? parseInt(raw, 10)
    : /^0x[0-9a-f]+$/i.test(raw) ? parseInt(raw, 16)
    : /^0o[0-7]+$/i.test(raw) ? parseInt(raw, 8)
    : /^0b[01]+$/i.test(raw) ? parseInt(raw, 2)
    : /^\d*\.\d+$/.test(raw) ? Math.trunc(parseFloat(raw))
    : null;
};
// Index-bearing member access on `m` — `m[…]`/`m?.[…]`/`m.at(…)` — plus
// the alias spellings (`sub === 'verb'` where `sub` was bound to
// `m[N]`). Matches run on the UNMASKED line so quoted digits survive;
// the caller rejects positions the masked twin proves are inside a
// literal (w58-fv F-4).
const DISP_MEMBER = /\bm\s*(?:\?\s*\.\s*)?(?:\[\s*([^\]]+)\]|\.?\s*at\s*\?\s*\.?\s*\(\s*([^)]*)\))/g;
const dispAliases = lines => {
  // name → resolved `m[N]` member. Surface-bound pairs otherwise
  // contradicted nothing: `let sub=m[1]; if(sub==='a'){…}else if(m[1]===
  // 'x'){…}` runs zero times for every verb but the gate never saw the
  // shared member (w60-fv F-4).
  const out = new Map();
  const dead = deadState();
  for (const l0 of lines) {
    const s = maskStrings(stripDead(l0, dead), dead);
    for (const m of s.matchAll(/\b(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*(?:m\s*(?:\?\s*\.\s*)?(?:\[\s*([^\]]+)\]|\.?\s*at\s*\?\s*\.?\s*\(\s*([^)]*)\))|([A-Za-z_$][\w$]*))/g)) {
      // Chained aliases (`sub2 = sub`) resolve through the map — member
      // binding, not surface binding.
      const resolved = m[4] !== undefined ? out.get(m[4]) : null;
      const idx = resolved ?? (() => { const v = DISP_IDX_EVAL(m[2] ?? m[3] ?? ''); return v === null ? null : `m[${v}]`; })();
      if (idx !== null) out.set(m[1], idx);
    }
    const d = /\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*m\b/.exec(s);
    if (d) for (const mm of d[1].matchAll(/['"`]?(\d+)['"`]?\s*:\s*([A-Za-z_$][\w$]*)/g)) out.set(mm[2], `m[${mm[1]}]`);
    // A `name = <anything not m[…]>` rebinding kills the alias — the
    // dispatcher's `sub` rebound to a literal kept resolving compares on
    // a name that no longer carried m[N] (w59-ledger F-5).
    for (const m of s.matchAll(/\b([A-Za-z_$][\w$]*)\s*(?<![=!<>])=(?![=])\s*/g)) {
      if (!out.has(m[1])) continue;
      const rhs = s.slice(m.index + m[0].length);
      if (/^m\s*(?:\?\s*\.\s*)?(?:\[|\.?\s*at\s*\?\s*\.?\s*\()/.test(rhs)) continue;
      // An identifier RHS keeps the binding only when that identifier is
      // itself a live alias — `x = undefined` must kill it.
      const ident = /^([A-Za-z_$][\w$]*)\s*(?:[;,]|$)/.exec(rhs)?.[1];
      if (!(ident && out.has(ident))) out.delete(m[1]);
    }
  }
  return out;
};
const DISPATCH_2 = new RegExp("m\\s*(?:\\?\\s*\\.\\s*)?(?:\\[|\\.?\\s*at\\s*\\?\\s*\\.?\\s*\\()");
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
    // Membership-changing mutations the declarator/alias arms cannot
    // read: `S[i] = 'r'` may carry a role, and splice/pop/shift/fill/
    // sort/unshift/reverse or a `.length` write leaves the set
    // unenumerable — drop it rather than guess (fail closed —
    // authorize(p, S) then resolves no roles and the row flags,
    // w58-ledger F11).
    for (const p of s.matchAll(/\b([A-Za-z_$][\w$]*)\s*\[\s*[^\]]+\]\s*=(?!=)\s*([^;]+)/g))
      if (defs.has(p[1])) defs.get(p[1]).push(...roleArgs(p[2]));
    for (const p of s.matchAll(/\b([A-Za-z_$][\w$]*)\s*\.\s*(?:splice|pop|shift|unshift|fill|sort|reverse|copyWithin)\s*\(/g))
      defs.delete(p[1]);
    const lenm = /\b([A-Za-z_$][\w$]*)\s*\.\s*length\s*=\s*([^;]+)/.exec(s);
    if (lenm && defs.has(lenm[1])) { if (lenm[2].trim() === '0') defs.set(lenm[1], []); else defs.delete(lenm[1]); }
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
  // A function body that is never invoked can mint no gate — `const g =
  // (req) => { authorize(...) };` declares a credential the row never
  // resolves (w59-ledger F-1). Compute the dead line set once per scan
  // window: a declaration is live iff its name is CALLED anywhere in the
  // window (hoisting makes call position irrelevant — `g()` before or
  // after the decl both keep it live). Method shorthand and property
  // values are not covered: a name-only match inside the decl itself
  // (`function g(`) is excluded from call evidence so it cannot
  // self-register.
  const deadFnLines = (lines, lo, hi) => {
    const bound = Math.min(hi, lines.length);
    const d0 = deadState();
    const ml = [];
    for (let i = lo; i < bound; i++) ml.push(maskStrings(stripDead(lines[i], d0), d0));
    // Declaration spellings: `const g = ()=>`/`g = x =>`, `function g(`,
    // `function* g(`, `async function(*/)? g(`, `const g = async
    // function*(`, object members `g: function`/`g: async ()=>`/method
    // shorthand `g(p){`, and class members `static g()`/`get g()`/
    // `set g(v)`/`#g()`/`*g()`/`static async *g()` (w60-fv F-2,
    // w60-ledger F-6).
    const PARAMS = String.raw`(?:\([\s\S]*?\)|[A-Za-z_$][\w$]*)`;
    const declRe = new RegExp([
      String.raw`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\s*\*?\s*)?${PARAMS}\s*=>`,
      String.raw`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?function\s*\*?\s*[A-Za-z_$]*\s*\(`,
      String.raw`\b(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(`,
      String.raw`\b([A-Za-z_$][\w$]*)\s*:\s*(?:async\s+)?function\s*\*?\s*[A-Za-z_$]*\s*\(`,
      String.raw`\b([A-Za-z_$][\w$]*)\s*:\s*(?:async\s+)?${PARAMS}\s*=>`,
      String.raw`(?:(?:^|[{,\s])|(?:\b(?:static|async|get|set)\s+)+|\*\s*)([#]?[A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{`,
    ].join('|'), 'g');
    const decls = [];
    const declPos = new Set();
    for (let i = 0; i < ml.length; i++)
      for (const dm of ml[i].matchAll(declRe)) {
        const g = dm[1] !== undefined ? 1 : dm[2] !== undefined ? 2 : dm[3] !== undefined ? 3 : dm[4] !== undefined ? 4 : dm[5] !== undefined ? 5 : 6;
        const name = dm[g];
        if (!name || name === 'if' || name === 'for' || name === 'while' || name === 'switch' || name === 'catch' || name === 'return' || name === 'function') continue;
        // The method-shorthand arm only counts a label position — `g()`
        // following `return`/`(`/`,` is a call, not a decl.
        if (g === 6) {
          const pre = ml[i].slice(0, dm.index).trimEnd();
          if (/[\w$.)\]]\s*$/.test(pre) && !/\b(?:static|async|get|set)\s*$|\*\s*$/.test(pre) && !/[{;,=:(]\s*$/.test(pre) && pre !== '') continue;
        }
        const nameAt = dm[0].lastIndexOf(name);
        declPos.add(`${i}:${dm.index + nameAt}`);
        decls.push({ name, li: i, start: dm.index + dm[0].length });
      }
    // A declaration is dead only when NOTHING outside its own decl name
    // references it at a use position — `g(`, `g\``, `g?.(`, `g.call`,
    // `foo(g)`, `x = g`, `setTimeout(g)` all escape the body (w60-ledger
    // F-6). Excluded positions: `.g` member reads, `g:`-key positions,
    // `function g`/`g: function` headers, and decl name tokens.
    const escapes = new Set();
    for (const d of decls) {
      if (escapes.has(d.name)) continue;
      const word = new RegExp(`\\b${d.name.replace(/\$/g, '\\$')}\\b`, 'g');
      for (let i = 0; i < ml.length; i++) {
        let found = false;
        for (const wm of ml[i].matchAll(word)) {
          const wi = wm.index;
          if (declPos.has(`${i}:${wi}`)) continue;
          const before = ml[i].slice(0, wi).trimEnd();
          const after = ml[i].slice(wi + d.name.length);
          if (/[.$]\s*$/.test(before)) continue;            // `.g` member access
          if (/^\s*:/.test(after)) continue;                 // `g:` object key
          if (/\bfunction\s*\*?\s*$/.test(before)) continue; // `function g` header
          if (/^\s*:\s*(?:async\s+)?function/.test(after)) continue; // `g: function`
          escapes.add(d.name); found = true; break;
        }
        if (found) break;
      }
    }
    const dead = new Set();
    for (const d of decls) {
      if (escapes.has(d.name)) continue;
      let j = d.li, dd = 0, seen = false;
      for (; j < ml.length; j++) {
        const cs = codeSpan(lines[lo + j]);
        const seg = j === d.li ? cs.slice(d.start) : cs;
        for (const ch of seg) { if (ch === '{') { dd++; seen = true; } else if (ch === '}') dd--; }
        if (seen && dd <= 0) break;
      }
      if (!seen) for (j = d.li; j < ml.length; j++) if (/;/.test(ml[j])) break;
      for (let k = d.li; k <= j && k < ml.length; k++) dead.add(lo + k);
    }
    return dead;
  };
  const collectAuthorize = (lines, from, depth, breakIf = true, verb = null) => {
    const defs = roleSets(lines);
    const aliases = dispAliases(lines);
    const deadFn = deadFnLines(lines, from, from + depth);
    const found = new Set();
    let depthCur = 0;
    const skipStack = [];
    let skipIndent = null;
    const chainSets = new Map();
    let ourChainDepth = null;
    const dead = deadState();
    // `deadM` feeds a parallel masking pipeline: the string-masked but
    // operand-live twin of each line — stripDead's operand blanking can
    // erase the `)` a brace-owner needs, so the brace analysis runs on
    // this view instead (w59-ledger F-6).
    const deadM = deadState();
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
    // Conditional bodies (`if/else/case/catch/try/=>`/braceless/
    // line-broken operands) cannot satisfy unconditional claims
    // (w58-fv F-3) — the tracker persists across the scanned lines.
    const tracker = condTracker();
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
      // (w57-ledger F2/F4). `deadPre` snapshots the line-entry string
      // state so the return-cut re-mask starts from the same template
      // context instead of a fresh object (w58-ledger F4).
      const deadPre = { pending: false, block: dead.block, str: dead.str };
      const lm = maskStrings(l, dead);
      // Depth arithmetic reads the fully-masked view — `//`/`/* */`
      // comments, string bodies and dead operands all blank — so every
      // `{`/`}` counted here is real structure. A phantom `/* } */`
      // previously desynced every depth-keyed decision downstream
      // (chainSets, skipStack, ourChainDepth, deadDepths) (w60-ledger
      // F-4).
      const opens = (lm.match(/\{/g) ?? []).length;
      const closes = (lm.match(/\}/g) ?? []).length;
      // `}` first matches THIS line's own opens — only a `}` that
      // outlives them is an enclosing close. A self-contained inner
      // block on one line (`if (m[1]==='a') { authorize(...) }`) must
      // not pop the sibling frame it sits inside (w60-fv F-3).
      let bal = 0, enclosingCloses = 0;
      for (const ch of lm) { if (ch === '{') bal++; else if (ch === '}') { if (bal > 0) bal--; else enclosingCloses++; } }
      // Dispatch verbs are read from the UNMASKED `l` (the masked twin
      // blanks quoted digits), each position checked against `lm` so a
      // dispatch spelling inside a string literal mints nothing
      // (w58-fv F-4).
      // Verb-dispatch compares are polarity- and conjunction-aware: a
      // compare names the verbs its arm serves unconditionally only when
      // the compare is POSITIVE (===/==, never !==/!= or a `!`-enclosed
      // member) AND its ||-term carries no top-level `&&`/`?:` — a
      // negated or conjunct-weakened compare's arm can never run for
      // that verb (or runs only under the extra conjunct), so its
      // authorize mints nothing (w59-fv F-1).
      // Depth-0 scan of lm[from,to): parens opened by a call/index or an
      // expression operand (identifier, `)`, `]`, `.`, `=` or another
      // binary operator before them) hide their interiors — only logical
      // grouping parens (preceded by `(`, `&&`, `||`, `!`, `?`, `:`, `,`
      // or the span edge) are transparent (w59-fv F-1).
      const TRANSPARENT_PAREN_PRED = new Set(['(', '&', '|', '!', '?', ':', ',', '']);
      const logicalScan = (from, to, hit) => {
        let d = 0;
        for (let k = from; k < to; k++) {
          const c = lm[k];
          if (c === '(') {
            let j = k - 1; while (j >= from && lm[j] === ' ') j--;
            if (!TRANSPARENT_PAREN_PRED.has(j >= from ? lm[j] : '')) d++;
          } else if (c === '[' || c === '{') d++;
          else if (c === ')' || c === ']' || c === '}') d--;
          else if (d === 0 && hit(c, k)) return true;
        }
        return false;
      };
      const armOf = pos => {
        // The arm-condition `(` that owns `pos`: walk enclosing parens
        // outward; a `(` preceded by a condition keyword opens the span,
        // anything else classifies the compare as an argument or operand
        // and it mints nothing.
        let d = 0, open = -1;
        for (let k = pos - 1; k >= 0; k--) {
          const c = lm[k];
          if (c === ')') { d++; continue; }
          if (c !== '(') continue;
          if (d > 0) { d--; continue; }
          let j = k - 1; while (j >= 0 && (lm[j] === ' ' || lm[j] === '\t')) j--;
          const ch = j >= 0 ? lm[j] : '';
          const word = /[\w$]+$/.exec(lm.slice(Math.max(0, j - 40), j + 1))?.[0] ?? '';
          if (word === 'if' || word === 'while' || word === 'for' || word === 'switch' || word === 'return' || word === 'case') { open = k; break; }
          if (word !== '' || ch === ')' || ch === ']' || ch === '.') return null;   // call/index args — a compare inside args serves no arm
          if ('=+-*/%<>^~[{'.includes(ch)) return null;   // operand position — the compare feeds an expression, not the condition
        }
        if (open < 0) return null;
        d = 0; let close = lm.length;
        for (let k = open; k < lm.length; k++) {
          const c = lm[k];
          if (c === '(') d++;
          else if (c === ')') { d--; if (d === 0) { close = k; break; } }
        }
        let last = open + 1; const terms = [];
        for (let k = open + 1; k < close; k++) {
          const c = lm[k];
          if (c === '(') d++;
          else if (c === ')' || c === ']' || c === '}') d--;
          else if (d === 0 && c === '|' && lm[k + 1] === '|') { terms.push([last, k]); k++; last = k + 1; }
        }
        terms.push([last, close]);
        let term = null;
        for (const ts of terms) if (pos >= ts[0] && pos < ts[1]) { term = ts; break; }
        return { open, term };
      };
      // A top-level `&&`, `?`, or `:` inside the term makes the compare a
      // conjunct — `m===v && x` serves v only when x also holds (or is
      // statically dead), and `?:` arms are conditional by shape. `?.`
      // and `??` are members/nullish, not conditionals.
      const conditionalTerm = term => {
        if (!term) return true;
        return logicalScan(term[0], term[1], (c, k) => (c === '&' && lm[k + 1] === '&') || (c === '?' && lm[k + 1] !== '.' && lm[k + 1] !== '?') || c === ':');
      };
      // `!(member===v)` / `!member===v` / `!member` — a `!` at logical
      // depth 0 before the member negates the compare.
      const negatedCompare = (term, memberStart) => {
        if (!term) return true;
        return logicalScan(term[0], memberStart, (c, k) => c === '!' && lm[k + 1] !== '=');
      };
      const pairs0 = verb && i !== from ? (() => {
        const out = [];
        for (const x of l.matchAll(DISP_MEMBER)) {
          if (lm[x.index] === ' ') continue;
          const idx = DISP_IDX_EVAL(x[1] ?? x[2] ?? '');
          if (idx === null) continue;
          const cmp = /^\s*([!=]={2,3})\s*'([^']+)'/.exec(l.slice(x.index + x[0].length));
          if (!cmp) continue;
          const a = armOf(x.index);
          if (!a) continue;
          if (negatedCompare(a.term, x.index)) continue;
          if (cmp[1][0] === '!') continue;
          if (conditionalTerm(a.term)) continue;
          out.push({ member: `m[${idx}]`, verb: cmp[2], pos: x.index });
        }
        for (const [nm, resolved] of aliases) {
          const v = new RegExp(`\\b${nm.replace(/\$/g, '\\$')}\\s*={2,3}\\s*'([^']+)'`).exec(l);
          if (v && lm[v.index] !== ' ') {
            const a = armOf(v.index);
            // The pair binds the RESOLVED member — two spellings of one
            // member contradict through the frame's pair set (w60-fv F-4).
            if (a && !negatedCompare(a.term, v.index) && !conditionalTerm(a.term)) out.push({ member: resolved, verb: v[1], pos: v.index });
          }
        }
        return out;
      })() : [];
      const afterCloses = depthCur - closes;
      const isElse = /^\s*\}?\s*else\b/.test(l);
      // An `else if` that repeats a (member,verb) pair an earlier arm of
      // the same chain already consumed can never run — every matching
      // request was taken by the earlier arm. Chains are tracked per
      // statement depth: a fresh `if` starts a new chain at its depth,
      // each `else if` adds its compares, and the chain dissolves once
      // the scan leaves that depth. A dead arm mints nothing — not even
      // '.any' — and a nested own-verb arm inside it cannot re-arm
      // (w59-ledger F-3).
      for (const d of [...chainSets.keys()]) if (d > afterCloses) chainSets.delete(d);
      const pairKey = p => `${p.member}|${p.verb}`;
      let deadArm = false;
      let pairs = pairs0;
      if (pairs.length > 0) {
        // `afterCloses` is the statement depth — a `} else` still carries
        // the closing `}` in depthCur, so its chain keyed at the `if`'s
        // depth is one level shallower (w59-ledger F-3).
        const chainD = afterCloses;
        if (isElse) {
          const consumed = new Set(chainSets.get(chainD) ?? []);
          const elseAt = /\belse\b/.exec(l)?.index ?? -1;
          const livePairs = [];
          for (const p of pairs) {
            if (p.pos > elseAt && consumed.has(pairKey(p))) continue;
            livePairs.push(p);
            consumed.add(pairKey(p));
          }
          deadArm = livePairs.length === 0;
          pairs = livePairs;
          chainSets.set(chainD, consumed);
        } else {
          chainSets.set(chainD, new Set(pairs.map(pairKey)));
        }
      }
      let popped = false;
      // A `}` swallowed by this line's own opens leaves the enclosing
      // frame intact — a self-contained inner block on one line must not
      // pop the sibling/ours frame it sits inside (w60-fv F-3).
      const afterEnclosing = depthCur - enclosingCloses;
      while (skipStack.length && afterEnclosing < skipStack[skipStack.length - 1].d) { skipStack.pop(); popped = true; }
      // A braceless sibling body stays excluded while following lines
      // keep a deeper indent than the dispatch line (blank lines ride).
      if (skipIndent !== null && l.trim() !== '' && (/^\s*/.exec(l)[0].length <= skipIndent || /^\s*\}/.test(l))) skipIndent = null;
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
      const sibling = pairs.length > 0 && !pairs.some(p => p.verb === verb);
      // An own-verb arm nested inside a sibling region mints only when it
      // can actually run: a nested compare on the SAME member as an
      // enclosing sibling arm's compare but naming a DIFFERENT verb is
      // statically dead (`if(m[2]==='abort'){ if(m[2]==='acknowledge')`),
      // so its authorize mints nothing (w59-fv F-2). Different members
      // (m[1] vs m[2]) or the else of a sibling chain stay reachable.
      const contradict = p => skipStack.some(s => s.ours === false && Array.isArray(s.pairs) && s.pairs.some(sp => sp.member === p.member && sp.verb !== p.verb));
      const ours = pairs.some(p => p.verb === verb && !contradict(p));
      // A `} else` continuing a sibling chain — or our own chain once our
      // arm closed — is sibling too: its catch-all roles must not bleed
      // into this row. A dispatch naming THIS verb is ours even inside a
      // sibling region: `if (m[2]==='ourverb')` nested in arm-a is this
      // row's gate, not arm-a's.
      // An `else`/`else if` after OUR arm already closed is dead for
      // this row even when it repeats our verb — the earlier arm
      // consumed every matching request, so its authorize mints nothing
      // (w59-ledger F-3). Before our arm, an else carrying our verb is
      // genuinely ours; one carrying another verb is sibling.
      const elseSibling = isElse && (ourChainClosed || (!ours && (popped || inSib)));
      const inDead = skipStack.some(s => s.dead);
      const excluded = deadArm || inDead || (inSib && !ours) || skipIndent !== null || sibling || elseSibling;
      // A braceless own-verb dispatch (`if (m[N]==='our') authorize(...)`)
      // runs its body unconditionally for this row — the guarded-call
      // doctrine would otherwise swallow the mint while the contract
      // claims a role (w60-ledger F-7). Positions past the condition's
      // closing `)` are the body.
      let oursBraceEnd = -1;
      if (ours && !lm.includes('{')) {
        const ih = /\bif\s*\(/.exec(lm);
        if (ih) {
          let dd = 0, k = ih.index + ih[0].length;
          for (; k < lm.length; k++) { const c = lm[k]; if (c === '(') dd++; else if (c === ')') { dd--; if (dd <= 0) break; } }
          if (dd <= 0) oursBraceEnd = k;
        }
      }
      // Walk the masked line for conditional-body state on EVERY line
      // (sibling `if{` blocks still open/close depths). The row's own
      // dispatch `{` is the unconditional entry scope; a sibling arm's
      // block is dead scope for this row — not conditional — so an
      // own-verb arm nested inside it still mints (w58-fv F-3,
      // w56-fv F-2).
      const scan = tracker.line(lm, depthCur, i === from || ours ? 'ours' : (sibling || elseSibling) ? 'sibling' : null, maskStrings(blankBlock(stripComment(lines[i]), deadM), deadM));
      if (sibling || elseSibling || deadArm) {
        const lastOpen = l.lastIndexOf('{'), lastClose = l.lastIndexOf('}');
        // An unmatched last `{` opens a block whose interior continues
        // past this line; otherwise the body is braceless (indent-bound).
        if (lastOpen > lastClose) skipStack.push({ d: afterCloses + opens, ours: false, pairs: sibling ? pairs : [], dead: deadArm });
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
        if (lm.includes('{')) deadDepths.add(depthCur + 1); else deadDepths.add(depthCur);
        if (lm.lastIndexOf('{') > lm.lastIndexOf('}')) {
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
        const lmx = maskStrings(l, deadPre);
        for (const m of lmx.matchAll(/authorize\(\s*p\s*,\s*[^\s)]/g)) {
          // Dead scope mints nothing at all — not even '.any' — since
          // the call can never execute (w59-ledger F-6).
          if (scan.condPos[m.index] === 2 || deadFn.has(i)) continue;
          sawAny.v = true;
          // A conditional gate — guarded statement prefix or a body
          // under if/else/case/catch/try/=> — cannot satisfy a role
          // claim (w57-ledger F3, w58-fv F-3). Positions past a
          // braceless own-dispatch `)` are the row's unconditional body,
          // not a guarded statement (w60-ledger F-7).
          const bodyUncond = oursBraceEnd >= 0 && m.index > oursBraceEnd;
          if (scan.condPos[m.index] || (!bodyUncond && guardedPrefix(lmx, m.index))) continue;
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
    const fdeadM = deadState();
    const ftrack = condTracker();
    let fdepth = 1;
    for (let i = idx; i < Math.min(idx + 140, fabric.length); i++) {
      if (i !== idx && /^\s{2}(async )?[a-zA-Z_]+\(/.test(fabric[i])) break;
      const fl = stripDead(fabric[i], fdead), fm = maskStrings(fl, fdead);
      const fscan = ftrack.line(fm, i === idx ? 1 : fdepth, false, maskStrings(blankBlock(stripComment(fabric[i]), fdeadM), fdeadM));
      fdepth = fscan.endDepth;
      // Comments and string literals carry no gate — the call is found on
      // the masked view, its argument read back from the stripped line,
      // and a same-statement `cond && authorize` or a conditional body
      // is a conditional gate that cannot satisfy a role claim
      // (w57-ledger F2/F3, w58-fv F-3).
      for (const m of fm.matchAll(/this\.authorize\(\s*p\s*,\s*[^\s)]/g)) {
        if (fscan.condPos[m.index] || guardedPrefix(fm, m.index)) continue;
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
    // A candidate `if` whose own condition is provably dead is a decoy —
    // it carries our literals to win `hi` while its arm can never run,
    // shadowing the real arm that does (w59-ledger F-2). Literal-false
    // first operands and `&&`-conjoined dead operands both mark it dead.
    const deadIfCond = t =>
      /\(\s*(?:false|!true|!1|0+|null|undefined|''|"")\s*&&/.test(t) ||
      /&&\s*(?:false|!true|!1|0+|null|undefined|''|"")\s*(?:\)|&&)/.test(t) ||
      /\(\s*(?:false|!true|!1|0+|null|undefined|''|"")\s*\)\s*(?:\{|$)/.test(t);
    const hi = lines.findIndex((l, i) =>
      isIf(l) && !deadIfCond(condText(i)) &&
      condText(i).includes(`req.method === '${r.method.toUpperCase()}'`) &&
      (condText(i).includes(`path === '${r.path}'`) || condText(i).includes(`url.pathname === '${r.path}'`) || condText(i).includes(`req.url === '${r.path}'`) || (param && /\^\\\//.test(condText(i)) && staticSegs.every(s => condText(i).includes(s)))));
    // The handler window: the dispatch arm until the next ROUTE boundary.
    // A nested `if` inside the arm's own block is part of the handler, not
    // a boundary — a real auth call one `if` deep is reachability-true
    // (w54-ledger H-3). The boundary is an `if` at the arm's own depth.
    const windowEnd = () => {
      if (hi === -1) return hi;
      // The arm-bounded window runs to the route boundary or file end —
      // any fixed cap truncates long handlers and lets a late authorize
      // hide behind a lying 'unauthenticated' claim (w58-ledger F12).
      const end = lines.length;
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
    // Never-invoked function bodies are dead scope — blanked from the
    // window so their evidence mints nothing (w59-ledger F-1).
    const windowDeadFn = hi === -1 ? new Set() : deadFnLines(lines, hi, wEnd);
    const windowMasked = hi === -1 ? '' : (() => { const d = deadState(); return lines.slice(hi, wEnd).map((x, j) => windowDeadFn.has(hi + j) ? ' ' : maskStrings(stripDead(x, d), d)).join('\n'); })();
    // An unconditional claim ('authenticated', 'token holder',
    // 'issuer bearer token') needs at least one UNGUARDED credential
    // call — `flag && auth(req)` serves unauthenticated traffic and is
    // not a gate (w57-ledger F3). Each masked line is checked per
    // call position.
    // Every spelling requires a real CALL — `typeof authenticateToken`
    // or a bare member-read minted on the unparenthesized arm
    // (w58-ledger F6); custom credential helpers count too
    // (w58-ledger F13).
    const AUTH_CALL = /\b(?:auth|authenticateToken|authBreakglass|authorize|anyBearer|bearerMatches|issuerAuthOk|bearerDigest|verifyJwt|bearer|verifyBearer|checkAuth)\s*\(\s*(?:req\b|p\b|request\b)?/g;
    const unguardedAuth = hi === -1 ? false : (() => {
      const d = deadState();
      const dM = deadState();
      const tr = condTracker();
      let sd = 0;
      for (let i = hi; i < wEnd; i++) {
        const ml = maskStrings(stripDead(lines[i], d), d);
        const scan = tr.line(ml, sd, i === hi ? 'ours' : null, maskStrings(blankBlock(stripComment(lines[i]), dM), dM));
        sd = scan.endDepth;
        for (const m of ml.matchAll(AUTH_CALL))
          if (!windowDeadFn.has(i) && !scan.condPos[m.index] && !guardedPrefix(ml, m.index)) return true;
      }
      return false;
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
      if (r.roles[0] === 'unauthenticated' && (gate.any || /\b(?:auth|authenticateToken|authBreakglass|authorize|verifyJwt|bearer)\s*\(/.test(windowMasked))) { console.error(`route-role parity: ${r.method} ${r.path} — claims unauthenticated but the handler authenticates`); failed = true; continue; }
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
        const priorDeadM = deadState();
        const ptrack = condTracker();
        for (const r of rows.slice(1, -1)) {
          const l = lines[r.i];
          const pl0 = stripDead(l, priorDead), pm = maskStrings(pl0, priorDead);
          const pscan = ptrack.line(pm, r.stmtDepth, false, maskStrings(blankBlock(stripComment(l), priorDeadM), priorDeadM));
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
          priorCalls.push(pl0);
          for (const am of pm.matchAll(/\b(?:auth|authenticateToken|authBreakglass|authorize|verifyJwt|bearer)\s*\(\s*(?:req\b|p\b|request\b)?/g))
            if (!pscan.condPos[am.index] && !guardedPrefix(pm, am.index)) priorAuthed = true;
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
    // Rebound RECEIVERS dispatch the same requests under a name the
    // audit cannot read — `const request = req` makes `request.method`/
    // `request.url`/`request.headers` invisible to both the
    // unauditable-flag arm and routeSeen (w58-ledger F2). Alias the
    // receiver so `X.method` resolves to `req.method`. A createServer
    // callback's first parameter is the request object by definition.
    for (const m of code.matchAll(/\b(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*(req|request)\b(?!\s*[.\[])/g))
      if (!['req', 'request'].includes(m[1]) && !aliases.has(m[1])) aliases.set(m[1], 'req');
    const cbp = /createServer\s*\((?:[^(),]*,\s*)?(?:async\s+)?\(\s*([A-Za-z_$][\w$]*)\s*,/.exec(code);
    if (cbp && !['req', 'request', 'res', 'response'].includes(cbp[1]) && !aliases.has(cbp[1])) aliases.set(cbp[1], 'req');
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
  // issuerd.mjs and cli.mjs are exempt from THIS outside-scan because
  // auditDispatch() already audits their dispatch — issuerd is declared
  // in openapi under x-listener, cli only instantiates the audited
  // server factory (w58-ledger F2). check.mjs is this file.
  auditDispatch(readFileSync('src/cli.mjs', 'utf8').split('\n'));
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

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
// Right bound of a dead `false &&`/`true ||` operand on its own line:
// a `,`, `:` or ternary `?` at the operand's own depth, a `||` (only
// the &&-arm — `false && a || b` evaluates `b`), or a `)`/`]` closing
// a group opened before the operand — the `[^;{}]*` tail swallowed
// live calls sitting in the same argument list (`helper(false && c,
// authorize(...))` minted nothing, w61-ledger F-3).
const deadTail = (s, orEnds) => {
  let d = 0, q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === '\\') i++; else if (c === q) q = null; continue; }
    if (c === "'" || c === '"' || c === '`') { q = c; continue; }
    if (c === '(' || c === '[') { d++; continue; }
    if (c === ')' || c === ']') { if (d === 0) return i; d--; continue; }
    if (d !== 0) continue;
    // `;`, `{` and `}` are statement/block boundaries — the dead span
    // must not swallow past them or same-line statements mint nothing
    // (w63-ledger F-1) and the brace ordinals mapping `lm` to `lraw`
    // desync (w63-ledger F-2).
    if (c === ',' || c === ':' || c === ';' || c === '{' || c === '}') return i;
    if (c === '?' && s[i + 1] !== '.') return i;
    if (orEnds && c === '|' && s[i + 1] === '|') return i;
  }
  return s.length;
};
// Braces inside a dead operand stay visible in `lm`: the twin `lraw`
// never loses them, so dropping them here would desync the n-th `{`
// ordinal map (w63-ledger F-2). Braces inside quote literals are not
// structural — quote-tracked so a `'\'` escape cannot unclose a string.
const braceKeep = seg => {
  let q = null, out = '';
  for (let i = 0; i < seg.length; i++) {
    const ch = seg[i];
    if (q) { if (ch === '\\') { out += '  '; i++; } else { if (ch === q) q = null; out += ' '; } continue; }
    if (ch === "'" || ch === '"' || ch === '`') { q = ch; out += ' '; continue; }
    out += ch === '{' || ch === '}' ? ch : ' ';
  }
  return out;
};
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
  for (const m of [...out.matchAll(/\b(?:false|0|null|undefined|!true)\s*&&/g)].reverse()) {
    if (inString(out, m.index) || livePrefix(m.index)) continue;
    const tail = deadTail(out.slice(m.index + m[0].length), true);
    const seg = out.slice(m.index + m[0].length, m.index + m[0].length + tail);
    const nx = deadContinues(seg);
    // The operand carries past the break only when it is genuinely
    // unfinished — open depth or an operator tail; `false && x` ended
    // by ASI owns no next line (w60-ledger F-2/F-5).
    // `false &&` at line end carries the operand too — the `&&` itself is
    // an unclosed operator tail whose operand starts on the next line
    // (`false &&\nauthorize` is the exact launder shape; an empty seg at
    // EOL read as complete and let the operand mint live, w60-ledger
    // F-2/F-5 + w55-fv H-3 regressions).
    const nxt = out[m.index + m[0].length + tail];
    const carries = nx.cont && nxt !== ';' && nxt !== '}' && (nx.depth > 0 || opTailOf(seg) || (seg.trim() === '' && nxt === undefined));
    if (carries) { dead.pending = true; dead.pdepth = nx.depth; }
    out = out.slice(0, m.index) + ' ' + braceKeep(seg) + out.slice(m.index + m[0].length + tail);
  }
  for (const m of [...out.matchAll(/\b(?:true|!false|1)\s*\|\|/g)].reverse()) {
    if (inString(out, m.index) || livePrefix(m.index)) continue;
    const tail = deadTail(out.slice(m.index + m[0].length), false);
    const seg = out.slice(m.index + m[0].length, m.index + m[0].length + tail);
    const nx = deadContinues(seg);
    const nxt = out[m.index + m[0].length + tail];
    const carries = nx.cont && nxt !== ';' && nxt !== '}' && (nx.depth > 0 || opTailOf(seg) || (seg.trim() === '' && nxt === undefined));
    if (carries) { dead.pending = true; dead.pdepth = nx.depth; }
    out = out.slice(0, m.index) + ' ' + braceKeep(seg) + out.slice(m.index + m[0].length + tail);
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
const guardedPrefix = (masked, callStart, from) => {
  // `from` is the provably-live arm's entry position: positions before
  // it (the `else` keyword itself, the dead arm's edge) are not guards —
  // but `cond &&` between the arm entry and the call still is (w62-fv
  // F-1).
  const floor = from === undefined || from < 0 ? 0 : from;
  const stmt = masked.slice(Math.max(masked.lastIndexOf(';', callStart - 1), masked.lastIndexOf('}', callStart - 1), masked.lastIndexOf('{', callStart - 1), floor - 1) + 1, callStart);
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
// Span-aware twin of topSplit — dispatch-purity checks need each operand's
// position on the line so a verb-compare pair can be mapped inside it
// (the masked view carries no literals to re-match) (w62-fv F-8).
const splitSpans = (t, ops, base = 0) => {
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
      for (const op of ops) { if (!t.startsWith(op, i)) continue; hit = op; break; }
      if (hit) { parts.push({ t: t.slice(cur, i), a: base + cur, b: base + i }); found.push(hit); cur = i + hit.length; i = cur; continue; }
    }
    i++;
  }
  if (!found.length) return null;
  parts.push({ t: t.slice(cur), a: base + cur, b: base + t.length });
  return { parts, ops: found };
};
// Operand classes on the masked view: a member-compare, a dispatcher
// exec/test/match bind, or a compare on anything else are dispatch
// shapes; a bare identifier, call, negation or `?:`-nested operand is a
// runtime gate (w62-ledger F-3). DISP_MEMBER is assigned below — this
// predicate only runs during scans, after the const initializes.
const dispOperandCls = op => {
  const t = op.trim();
  if (t === '' || t.startsWith('!') || /[?:]/.test(t)) return 'impure';
  DISP_MEMBER.lastIndex = 0;
  const member = DISP_MEMBER.test(t); DISP_MEMBER.lastIndex = 0;
  const cmp = /[!=]==?/.test(t);
  if (member && cmp) return /!={1,2}/.test(t) ? 'memberneg' : 'membercmp';
  if (/\(\s*[A-Za-z_$][\w$]*\s*=[^=]/.test(t) && /\.(?:exec|test|match)\s*\(/.test(t)) return 'bind';
  // A compare is serving-material only when it tests a dispatch field —
  // `path === '/x'`, `req.method === 'GET'`. `flag === 'on'` /
  // `kind === 'x'` gate on runtime state no request term controls, so
  // under a `&&`/`||` exemption they must classify impure — otherwise
  // `if ((m=/re/.exec(path)) && flag==='on') authorize` minted
  // unconditional behind a flag the request cannot satisfy
  // (w63-seal F-2).
  if (cmp) return DISP_FIELD.test(t) ? 'othercmp' : 'impure';
  return 'impure';
};
const DISP_FIELD = /\b(?:path|rawPath|rawTarget|target|url\.pathname|req\.(?:method|url|path|hostname?)|m)\b/;
// A dispatch `if`/`while`/`for`/`switch` head whose every `||`-side is a
// pure dispatch side carrying another verb's positive member-compare on
// a member THIS row's verb also binds is another ROW's arm — dead scope
// for this row, so a `;`-ended guard-return inside it does not
// condition the tail (w56-ledger F7). A side needs at least one
// bound-member compare to fail for this verb; an unbound member compare
// or a guard (`early`, `m[2]!=='e'`, `x || early`) sitting beside it
// cannot save the side — the bound conjunct already kills it for this
// row (w63-fv F-3). Module scope: the tracker's sibArm/bracelessDead
// checks and the collect-level sibling-line check share it.
const siblingArm = (condPair, verbPos, verbMembers, posMember) => {
  if (condPair === null) return false;
  const [cond, base] = condPair;
  const cls = dispOperandCls;
  const sides = splitSpans(cond, ['||'], base);
  const parts = sides === null ? [{ t: cond, a: base, b: base + cond.length }] : sides.parts;
  for (const side of parts) {
    const s = splitSpans(side.t, ['&&', '??', ',', ':', '?'], side.a);
    if (s !== null && s.ops.some(o => o !== '&&')) return false;
    const ops = s === null ? [side] : s.parts;
    let sideMember = false;
    for (const op of ops) {
      const c2 = cls(op.t);
      // `posMember` maps EVERY pair position to its member under any
      // spelling pairs resolved (direct, aliased, switched) — a side is
      // member-bound whenever one of those lands in it; a bare `m[N]`
      // compare with no pair counts as member-bound too. Same member +
      // different literal ⇒ disjoint ⇒ dead scope. `m[2]==='x'` ALONE
      // is reachable for an m[1]-bound row's requests, so it is a
      // guard, not dead scope; beside a bound compare it is dead
      // weight — the bound conjunct fails the whole side for this verb
      // either way (w63-fv F-3). An EMPTY verbMembers means the queried
      // verb binds no member in this row — a foreign row: every
      // member-compare arm dispatches a different verb and is dead
      // scope for it (w61-ledger F-5's `q[2]==='y'` under unbound 'x').
      let pm;
      for (const [p, mem] of posMember ?? []) if (p >= op.a && p < op.b) { pm = mem; break; }
      if (pm !== undefined || c2 === 'membercmp') {
        if ((verbPos ?? []).some(p => p >= op.a && p < op.b)) return false;
        if ((verbMembers?.size ?? 0) === 0 || (pm !== undefined && verbMembers.has(pm))) sideMember = true;
        continue;
      }
      if (c2 !== 'memberneg' && c2 !== 'othercmp' && c2 !== 'bind') return false;
    }
    if (!sideMember) return false;
  }
  return true;
};
// A condition is request-controlled when every operand is dispatch
// material — member compares, dispatch-field compares and regex binds:
// `m[1]==='a'`, `path === '/x'`, `req.method === 'GET'`,
// `(m = /re/.exec(path))`. `flag`, `early`, `kind === 'x'` and
// non-`&&` compositions are not — a gate the request cannot satisfy is
// never request-controlled (w59-fv F-2: an own-verb arm nested inside
// a request gate re-includes as this row's code).
const reqGateCond = condPair => {
  if (condPair === null) return false;
  const [cond, base] = condPair;
  const sides = splitSpans(cond, ['||'], base);
  const parts = sides === null ? [{ t: cond, a: base, b: base + cond.length }] : sides.parts;
  for (const side of parts) {
    const s = splitSpans(side.t, ['&&', '??', ',', ':', '?'], side.a);
    if (s !== null && s.ops.some(o => o !== '&&')) return false;
    for (const op of (s === null ? [side] : s.parts)) {
      const c2 = dispOperandCls(op.t);
      if (c2 !== 'membercmp' && c2 !== 'memberneg' && c2 !== 'othercmp' && c2 !== 'bind') return false;
    }
  }
  return true;
};
// The trailing `if (...)`/`for (...)`/`while (...)` head of a prefix,
// balance-scanned — a `[^;{]*` character-class cannot parse a condition
// carrying a `{` (`if (f({y})) return` used to fail the match and cut
// the whole tail, w63-ledger F-3). Returns [condText, condStart, kw] or
// null when the last control head does not close at the prefix end.
const tailCtlCond = (prefix, kws = 'if|for|while') => {
  const re = new RegExp(`\\b(${kws})\\s*\\(`, 'g');
  let m = null;
  for (;;) { const x = re.exec(prefix); if (!x) break; m = x; }
  if (!m) return null;
  const open = m.index + m[0].length - 1;
  let d = 0, q = null;
  for (let i = open; i < prefix.length; i++) {
    const c = prefix[i];
    if (q) { if (c === '\\') { i++; continue; } if (c === q) q = null; continue; }
    if (c === "'" || c === '"' || c === '`') { q = c; continue; }
    if (c === '(') d++;
    else if (c === ')') { d--; if (d === 0) return /^\s*$/.test(prefix.slice(i + 1)) ? [prefix.slice(open + 1, i), open + 1, m[1]] : null; }
  }
  return null;
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
  if (ter) { const c = litVal(ter[0], known); if (c === true) return litPrim(ter[1], known); if (c === false || c === LV_NUL) return litPrim(ter[2], known); const a = litPrim(ter[1], known), b = litPrim(ter[2], known); return a !== LV_UNK && a === b ? a : LV_UNK; }
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
  // {d, g}: d = the frame's body depth; g = the body carried a
  // dominating exit (`return`/`throw`/`break`/`continue`), so closing
  // the frame leaves the tail conditional instead of restoring the
  // unconditional span (w63-fv F-1).
  const condDepths = [];
  // Tail-conditional marks: a `}` that closed a live conditional frame
  // whose body exited (return/throw/…) leaves everything after it gated
  // on the frame's condition (w63-fv F-1). Kept separate from real
  // containing conditions — a call under ONLY tail marks still resolves
  // for every request that reaches it (the earlier arm not firing IS
  // the reachability condition of every later statement), so the
  // credential-resolution scans may look through them (condPosDeep).
  const condTail = [];
  const deadDepths = new Set();
  // Depth → opening-head kind for every entry in deadDepths — persists
  // across lines like its sibling so a `}` closing a dead arm on a
  // LATER line still knows the arm was an `if` and can arm its else's
  // live latch (a per-line map dropped multiline dead arms' elses into
  // conditional limbo — w61-fv F-9's own gap under w63-fv F-4).
  const deadHeads = new Map();
  let pending = false;
  // A braceless provably-dead condition (`if (0) x()`) dead-spans its
  // single statement exactly like the braced arm — the `}`-free form
  // minted `any` where `if (0) { x() }` minted nothing (w60 gate hole).
  // `{depth, nestedIf}` — cleared at `;`, at a `}` closing a scope at
  // or above the statement's own lexical depth (an object literal's `}`
  // used to clear it early and mint, w61-fv F-1), at a binding `else`,
  // or at EOL when the trailing token makes the statement ASI-complete
  // (a dead `if (0) x = f(p)` bled the dead span onto the next line's
  // live statement, w61-fv F-8).
  let bracelessDead = null;
  // The else-arm of a proven-dead `if` is provably LIVE — its statement
  // runs unconditionally where the dead arm never did (w61-fv F-9);
  // `{depth}`, cleared at the same boundaries (one statement arm).
  let bracelessLive = null;
  // A LIVE braceless `if`'s else-arm is gated on `!cond` — one
  // statement of conditional scope, cleared at `;`, a `}` at or
  // shallower than the arm's own block, or an EOL-closing tail
  // (w63-fv F-4: `if (c) x(); else authorize` minted unconditional).
  let bracelessCond = null;
  // Set when a `}` closes a proven-dead braced arm — the else of a dead
  // `if` is provably live; consumed by the next significant token.
  let deadElseExpected = null;
  // The else-arm of OUR OWN dispatch `if` is dead scope for this verb —
  // `if (m[1]==='a') x(); else authorize` can never run for an 'a'
  // request, yet it minted 'a' unconditionally (w63-fv F-4).
  // `pendingIfOurs` tracks the innermost braceless `if` awaiting a body
  // or an `else` — a nested `if` displaces it (the else binds the INNER
  // one). `deadElseArm` = {depth, arm} once armed.
  let pendingIfOurs = null, deadElseArm = null;
  // `oursIfArm` = the `{`-body depth of THIS row's braced dispatch arm;
  // when its `}` pops, `oursElseExpected` latches so a following `else`
  // (and every `else` of the same chain) is dead scope for this verb —
  // `if (m[1]==='a') { x(); } else authorize` can never run for 'a'
  // (w63-fv F-4, braced twin of the braceless latch).
  let oursIfArm = -1, oursIfNested = false, oursElseExpected = null;
  // Dispatch-chain failure ledger keyed by arm-head depth: the final
  // `else` of a chain runs for this row only when every prior head
  // failed for it. true — every head so far is dead-for-this-verb
  // (bound-member sibling arm, literal-dead cond, ours-else dead
  // scope); 'ours' — this row already took an arm (its else is dead
  // for this verb); false — a live head this verb might satisfy (the
  // else is conditional, never unconditional). A chain without a
  // member-bound foreign head is not a dispatch chain for this row
  // at all (w63-fv F-4's "live for everyone else").
  const chainFailed = new Map();
  // Parallel ledger: whether EVERY head of the accumulated chain was
  // request-controlled (member/dispatch-field compares and regex binds
  // only) — consulted by else-arm `bracelessCond` mints (w59-fv F-2).
  const chainFailedReq = new Map();
  // Callable-body `{` depths — a `return` inside a nested function or
  // arrow exits THAT callable, never the route's flow, so it must not
  // arm the guarded-tail latch on enclosing frames (w63-fv F-1
  // fallout: `() => { return g }` left the tail conditional). Persists
  // across lines — a multi-line callable stays a boundary.
  const callScopes = new Set();
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
            const emptyCtor = (typeof operand === 'object' && operand !== null && operand.newCtor !== undefined)
              && /^new\s+[A-Za-z_$][\w$]*\s*(?:\(\s*(?:\[\s*\])?\s*\)|$)/.test(om[2]);
            if (om[1] === 'in')
              // `in` iterates KEYS: dead only over provably keyless
              // operands — `in {a:1}`/`in [1]` DO run (the flat LV_OBJ/
              // LV_ARR markers mis-dead-spanned them, w61-fv F-7).
              return operand === null || operand === undefined
                || typeof operand === 'number' || typeof operand === 'boolean' || operand === ''
                || /^\s*\{\s*\}$/.test(om[2]) || /^\s*\[\s*\]$/.test(om[2])
                || (emptyCtor && /^(?:Set|Map|WeakMap|WeakSet|Array|Object)$/.test(operand.newCtor));
            // `of`: dead over a provably-empty iterable (`''`, `[]`,
            // fresh empty containers) or a non-iterable operand that
            // throws before the body (`{}`, null, numbers, booleans —
            // `of 5`/`of ''` used to stay live, w61-ledger F-4); `of [1]`
            // iterates and must NOT dead-span (w61-fv F-7).
            return operand === '' || operand === null || operand === undefined
              || typeof operand === 'number' || typeof operand === 'boolean'
              || operand === LV_OBJ || /^\s*\[\s*\]$/.test(om[2])
              || (emptyCtor && /^(?:Set|Map|WeakMap|WeakSet|Array)$/.test(operand.newCtor));
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
  const line = (lm, sd, mode, lraw, forUncond = false, verbPos = null, allPos = null, verbMembers = null, posMember = null) => {
    const condPos = new Uint8Array(lm.length), condPosDeep = new Uint8Array(lm.length), livePos = new Uint8Array(lm.length), liveArm = new Int32Array(lm.length);
    // `{` positions on the operand-live twin — stripDead COMPACTS dead
    // operands out of `lm`, so an `lraw.slice(0, ci)` offset would map
    // wrong. `{`s are dead-span boundaries and survive in both views,
    // so the n-th `{` in `lm` is the n-th `{` in `lraw` (w59-ledger F-6).
    const rawBraces = [];
    if (lraw) for (let i = 0; i < lraw.length; i++) if (lraw[i] === '{') rawBraces.push(i);
    let ld = sd, pendingUsed = pending, armBraceTaken = false, braceN = 0, pd = 0;
    let bracelessIfArm = -1, bracelessIfCond = null;
    // Stale chain entries below this line's entry depth are dropped —
    // a `}`-pop chain consult needs only entries for still-open scopes.
    for (const d of [...chainFailed.keys()]) if (d > sd) chainFailed.delete(d);
    for (const d of [...chainFailedReq.keys()]) if (d > sd) chainFailedReq.delete(d);
    pending = false;
    // A dead statement's operand tail decides at the NEXT line's head:
    // `x = a\n+b` is one statement — an operator/continuer-led line keeps
    // the dead span (w62-fv F-3). An `else` head stays dead here so the
    // in-loop arm flip can claim it live; every other non-continuer head
    // means ASI applied and the span is over.
    if (bracelessDead) {
      const elseH = /^\s*else\b/.test(lm);
      const contH = /^\s*(?:\+\+|--|\+|-|\*\*?|\/|%|\(|\[|\.|`|,|\?\??|&&|\|\||[&|^<>~=:!])/.test(lm);
      if (!elseH && !contH) bracelessDead = null;
    }
    for (let ci = 0; ci < lm.length; ci++) {
      const c = lm[ci];
      // The live-statement clear runs BEFORE the dead arm: the `;` that
      // ends a dead braceless statement and arms the else-live span is
      // the DEAD statement's edge — clearing here would self-consume the
      // arm in the same position (w61-fv F-9).
      if (bracelessLive && pd === 0 && (c === ';' || (c === '}' && ld <= bracelessLive.depth))) bracelessLive = null;
      // The ours-`if` else-arm is one statement — `;` ends it, `}`
      // closing its depth ends it (w63-fv F-4).
      // The else-chain of an ours `if` keeps its dead scope past `;`:
      // `else if (b) x; else y` — the `;` ends the else-if's body but a
      // further `else` of the chain is still dead, so the latch re-arms
      // as `oursElseExpected` at the arm's own depth (w63-fv F-4). `}`
      // at-or-below the arm depth closes the whole chain for good.
      if (deadElseArm && pd === 0 && (c === ';' || c === '}') && ld <= deadElseArm.depth) {
        if (c === ';' && ld === deadElseArm.depth) oursElseExpected = deadElseArm.depth;
        deadElseArm = null;
      }
      // A `}` that just closed a BRACED dead-if body leaves its `else`
      // as the live arm: the next non-space, non-`else` token expires the
      // latch — `if (0) {x} else authorize` mints unconditionally
      // (w61-fv F-9, braced twin of the braceless case). The arm was
      // dead-for-this-verb, so the else is unconditional only when the
      // chain ledger says this row failed EVERY prior head — an ours
      // chain's else is dead scope, a live-head chain's else is
      // conditional (w63-fv F-4's else for everyone else).
      if (deadElseExpected !== null && pd === 0 && !/\s/.test(c)) {
        if (c === 'e' && /^else\b/.test(lm.slice(ci))) {
          const cf = chainFailed.get(deadElseExpected);
          if (cf === 'ours') deadElseArm = { depth: deadElseExpected, arm: ci + 4 };
          else if (cf === false) bracelessCond = { depth: deadElseExpected, arm: ci + 4, req: chainFailedReq.get(deadElseExpected) === true };
          else bracelessLive = { depth: deadElseExpected, arm: ci + 4 };
        }
        deadElseExpected = null;
      }
      // The `else` after a BRACED ours-dispatch arm is dead scope for
      // this verb — latch `deadElseArm` on it the same way the braceless
      // pendingIfOurs path does (w63-fv F-4, braced variant). A `;` does
      // not expire the latch — it is the empty statement that may sit
      // between arm and else (`if (a) {x}; else`, and it is the `;` that
      // re-armed the latch inside an else-if chain).
      if (oursElseExpected !== null && pd === 0 && !/\s/.test(c) && c !== ';') {
        if (c === 'e' && /^else\b/.test(lm.slice(ci))) deadElseArm = { depth: oursElseExpected, arm: ci + 4 };
        oursElseExpected = null;
      }
      if (bracelessDead && pd === 0) {
        if (c === ';') {
          // `if (0) x; else y` — the `;` does not detach the else: it
          // binds this dead `if`, so its arm is the live one (w61-fv F-9).
          // With a nested `if` in the dead span the else binds THAT if
          // instead and stays dead (w61-fv F-1).
          const elseAhead = /^\s*else\b/.test(lm.slice(ci + 1));
          if (elseAhead && !bracelessDead.nestedIf) {
            const dead9 = bracelessDead.depth;
            const cf = chainFailed.get(dead9), arm = ci + 1 + /^\s*else\b/.exec(lm.slice(ci + 1))[0].length;
            bracelessDead = null;
            if (cf === 'ours') deadElseArm = { depth: dead9, arm };
            else if (cf === false) bracelessCond = { depth: dead9, arm, req: chainFailedReq.get(dead9) === true };
            else bracelessLive = { depth: dead9, arm };
          }
          else if (!elseAhead) bracelessDead = null;
        } else if (c === '}' && ld <= bracelessDead.depth) bracelessDead = null;
        else if (c === 'e' && /^else\b/.test(lm.slice(ci)) && ld <= bracelessDead.depth && !bracelessDead.nestedIf) {
          const cf = chainFailed.get(bracelessDead.depth);
          const dead9 = bracelessDead.depth;
          bracelessDead = null;
          if (cf === 'ours') deadElseArm = { depth: dead9, arm: ci + 4 };
          else if (cf === false) bracelessCond = { depth: dead9, arm: ci + 4, req: chainFailedReq.get(dead9) === true };
          else bracelessLive = { depth: dead9, arm: ci + 4 };
        }
      }
      // An `else` binds the innermost pending braceless `if` — when
      // that `if` is THIS row's dispatch, its else-arm is dead scope
      // for this verb (w63-fv F-4). A nested if displaced the pending
      // head, so the bind consumes whatever is pending.
      if (c === 'e' && pd === 0 && /^else\b/.test(lm.slice(ci)) && !/[\w$]/.test(lm[ci - 1] ?? ' ') && pendingIfOurs) {
        if (pendingIfOurs.ours) deadElseArm = { depth: pendingIfOurs.depth, arm: ci + 4 };
        // A LIVE braceless `if`'s else is gated on `!cond` — it can
        // never mint unconditionally, no matter the enclosing line
        // (w63-fv F-4's `if (c) x(); else authorize` under-mint). Skip
        // when a stronger consult already decided this else (dead-arm
        // latch armed it live or ours-arm dead).
        else if (!bracelessLive && !deadElseArm) bracelessCond = { depth: ld, arm: ci + 4, req: reqGateCond(pendingIfOurs.cond ?? null) };
        pendingIfOurs = null;
      } else if (pendingIfOurs && pd === 0 && ((c === '}' && ld <= pendingIfOurs.depth)
          || (pendingIfOurs.bodyDone && !/\s/.test(c) && !(c === 'e' && /^else\b/.test(lm.slice(ci)))))) pendingIfOurs = null;
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
        // A `{` opened inside an armed ours-else scope is dead — `else {`
        // or `else if (...) {` bodies cannot run for this verb (w63-fv
        // F-4). Marker 'oursElse' keeps the `}` from latching the
        // dead-arm else-as-live path (the else of a dead ours-else-if is
        // dead too, never live).
        const elseDead = deadDepths.size === 0 && deadElseArm !== null && ld === deadElseArm.depth + 1;
        // A `{` whose `if` head is a SIBLING verb's pure dispatch arm is
        // dead scope for this row — 'a' requests never satisfy
        // `m[1]==='b'` — and its `else` is the live arm through the
        // usual dead-if latch: `if (m[1]==='b') {x} else authorize`
        // mints for 'a' (w63-fv F-4 sibling direction). Runs on `lm` —
        // pair/posMember positions are lm-space.
        const sibArm = parenHead === 'if' && siblingArm(headCond(lm.slice(0, ci).trimEnd()), verbPos, verbMembers, posMember);
        if (deadDepths.size > 0 || elseDead || sibArm || (parenHead !== null && deadCond(prevR))) { deadDepths.add(ld); deadHeads.set(ld, elseDead ? 'oursElse' : parenHead); }
        else {
          let cond;
          // The 'ours' exemption claims only the ROW's dispatch arm —
          // the `if` head that owns this line's first statement. A
          // second-statement `if`, or a `while`/`for`/`switch`/`catch`
          // head anywhere, gates on its own condition; only callable
          // bodies (`function`, `f(x) {`) are dispatch-invoked and stay
          // unconditional (w62-fv F-2).
          // A chain continuation counts as first-statement too — the
          // leading `}` closes the previous arm and `else if (cond)` is
          // still this row's dispatch when the pair scan says so
          // (w56-fv F-2). Any other `;`/`{`/`}` before the `if` makes it
          // a second statement and the exemption dies (w62-fv F-2).
          const firstStmt = !/[;{}]/.test(prevR.replace(/^\s*}+\s*else\b(\s*if\b)?/, ''));
          // A same-line nested control head before the dispatch `if` —
          // `if (x) if (m[1]==='a') {` — gates the arm on the OUTER
          // condition: the inner head's purity cannot absorb it, and
          // `firstStmt` only watched `;{}` (w63-fv F-5).
          const hc5 = parenHead === 'if' ? headCond(prevR) : null;
          const nestedHead = hc5 !== null && /\b(?:if|for|while|switch)\s*\(/.test(prevR.slice(0, Math.max(0, hc5[2])));
          if (mode === 'ours' && !armBraceTaken && parenHead === 'if' && firstStmt && !nestedHead && dispatchPure(headCond(prevR), verbPos)) { cond = false; armBraceTaken = true; oursIfNested = oursIfArm >= 0; oursIfArm = ld; }
          else if (parenHead !== null) {
            // Callable bodies (`function(req,res) {`, `f(x) {`) run in
            // their handler's own scope — `function` heads on registered
            // handlers are invoked by the dispatch itself (marking them
            // conditional dropped the gate on 8 routes, w61-fv F-9
            // regression). Uninvoked DECLARED functions stay dead via
            // deadFnLines regardless (w61-ledger F-2). Control heads
            // (`while (cond) {`, `for`, `switch`, `catch`) gate their
            // bodies on the head's own condition (w62-fv F-2).
            if (parenHead === 'if' || parenHead === 'catch' || parenHead === 'while' || parenHead === 'switch') cond = mode !== 'sibling';
            // A `for (x of/in coll)` head enumerates a collection — calls
            // inside its body are iteration-wide, and under forUncond
            // (the credential-resolution scan) they are not a gate.
            else if (parenHead === 'for') cond = forUncond ? false : mode !== 'sibling';
            else cond = false;
          }
          // try/finally bodies run unconditionally — only else/catch/
          // arrow/case/default bodies gate a slice of requests (w58: a
          // `try {` arm wrongly marked authenticateToken conditional).
          // An else-block whose `if` was proven dead is the live arm —
          // its body runs unconditionally (w61-fv F-9).
          else if (/(?:\b(?:else|catch)\b|=>\s*$|\bcase\b[^;]*:\s*$|\bdefault\s*:\s*$)/.test(prevR)) { if (bracelessLive) { bracelessLive = null; cond = false; } else cond = mode !== 'sibling'; }
          else if (pendingUsed) cond = mode !== 'sibling';
          else cond = false;
          if (cond) condDepths.push({ d: ld, g: false, req: reqGateCond(headCond(prevR)) });
        }
        // Chain ledger for the else-arm consult: record how this `if`
        // arm resolves for THIS row — a bound-member sibling arm or a
        // literal-dead cond fails for it, an ours-dispatch or ours-else
        // head is one this row takes ('ours'), anything else is a live
        // head this verb might satisfy. An arm inside an already-dead
        // region updates nothing — its chain is moot (w63-fv F-4).
        if (parenHead === 'if' && (deadDepths.size === 0 || (deadDepths.size === 1 && deadDepths.has(ld)))) {
          const hc9 = headCond(prevR);
          const kwS = hc9 ? hc9[2] : -1;
          const cont = kwS >= 0 && /\belse\s*$/.test(prevR.slice(0, kwS));
          const res = elseDead ? 'ours' : (sibArm || deadCond(prevR) ? true : (oursIfArm === ld ? 'ours' : false));
          const prev9 = chainFailed.get(ld - 1);
          chainFailed.set(ld - 1, cont ? (prev9 === 'ours' || res === 'ours' ? 'ours' : (prev9 === false || res === false ? false : true)) : res);
          const resReq = reqGateCond(hc9), prevReq = chainFailedReq.get(ld - 1) ?? false;
          chainFailedReq.set(ld - 1, cont ? (prevReq && resReq) : resReq);
        }
        // A callable body's `{` opens a return-scope boundary — exits
        // inside it do not guard the enclosing route flow (w63-fv F-1).
        if ((parenHead !== null && !/^(?:if|catch|while|switch|for)$/.test(parenHead)) || (parenHead === null && /=>\s*$/.test(prevR))) callScopes.add(ld);
      } else if (c === '}') {
        const deadHead = deadHeads.get(ld);
        const wasDead = deadDepths.delete(ld);
        deadHeads.delete(ld);
        let guarded = false;
        const poppedGates = [];
        while (condDepths.length && condDepths[condDepths.length - 1].d >= ld) { const e = condDepths.pop(); if (e.g) guarded = true; poppedGates.push(e); }
        while (condTail.length && condTail[condTail.length - 1].d >= ld) condTail.pop();
        callScopes.delete(ld);
        ld--;
        // A `}` ending the else-arm's own block or any enclosing scope
        // ends the conditional statement — post-decrement ld <= depth
        // catches the arm's `{`-block (opened at depth+1) and every
        // shallower close; an inner `}` stays inside the arm.
        if (bracelessCond && ld <= bracelessCond.depth) bracelessCond = null;
        // A popped conditional frame whose body exited keeps the tail
        // gated — `if (cond) { return; } authorize` is conditional on
        // `!cond`, not free (w63-fv F-1). The marker lives until the
        // enclosing scope's own `}` pops it. A frame dead-for-this-verb
        // mints no mark: its exits never ran for this row, so the tail
        // stays free.
        if (guarded && !wasDead) condTail.push({ d: ld, g: false, req: poppedGates.length > 0 && poppedGates.every(e => e.req) });
        // A `}` closing a proven-dead arm: its `else` is the live arm —
        // latch the enclosing depth so the next `else` marks live
        // (w61-fv F-9, braced arm). Only a dead `if` arms it: `else`
        // cannot bind a dead while/for body in real JS (w62-ledger F-5).
        if (wasDead && deadHead === 'if') deadElseExpected = ld;
        // The `}` that pops the braced ours-dispatch arm latches the
        // else-expect: a following `else` is dead scope for this verb
        // (w63-fv F-4).
        if (oursIfArm === ld + 1) { oursIfArm = -1; oursIfNested = false; oursElseExpected = ld; }
        // A `}` returning to the pending statement's own depth ends that
        // statement — unless an `else` still binds it. A `}` deeper than
        // sd only closes a block inside the arm (w63-fv F-4 gate).
        if (ld <= sd && !/^\s*else\b/.test(lm.slice(ci + 1))) pendingUsed = false;
      } else if (c === ';') {
        // A `;` ends the pending arm only at the arm's own depth — one
        // inside the arm's braces is part of it; and when an `else`
        // still binds, the statement continues into the else arm
        // (`if (c) if (0) {x}; else y` keeps y gated on !c).
        if (ld <= sd && !/^\s*else\b/.test(lm.slice(ci + 1))) pendingUsed = false;
        // The else-arm statement ends at `;` — a following `else` keeps
        // it (the next else still gates on the same failed head).
        if (bracelessCond && !/^\s*else\b/.test(lm.slice(ci + 1))) bracelessCond = null;
        // A braceless `if (c) return|throw|continue|break;` guards the
        // rest of the enclosing scope — statements after it run only
        // when the guard failed, so they are conditional on `c`
        // (w62-ledger F-3). Same tail-conditional semantics as the
        // braced `}`-pop propagation.
        if (bracelessIfArm >= 0) {
          if (/^(?:return|throw|continue|break)\b/.test(lm.slice(bracelessIfArm, ci).trim()) && !siblingArm(bracelessIfCond, verbPos, verbMembers, posMember)) condTail.push({ d: ld, g: false, req: reqGateCond(bracelessIfCond) });
          bracelessIfArm = -1;
          bracelessIfCond = null;
        }
        // The `;` that ends a pending braceless `if`'s body — an `else`
        // may still bind across it; the next real token detaches the
        // pending head (w63-fv F-4).
        if (pendingIfOurs) pendingIfOurs.bodyDone = true;
      }
      else if (c === '(') pd++;
      else if (c === ')') {
        // The `)` of a deadCond-proven control head with no `{` after
        // owns its braceless body statement — dead, not conditional.
        const prevR = lm.slice(0, ci + 1).trimEnd();
        const head = /\)\s*$/.test(prevR) ? parenOwner(prevR) : null;
        if (head === 'if' && bracelessDead) bracelessDead.nestedIf = true;
        // `else if` — the `if` is itself the dead-arm's live else body,
        // so its OWN body gates on its condition again: end the live
        // span at the `)` and let the prefix guard score the body
        // (w61-fv F-9 follow-through).
        // A control head's `)` ends the live arm's statement — a new
        // statement follows, gated by its own condition. `if` covers the
        // `else if` chain; while/for/switch/catch leak identically when
        // left out (w62-ledger F-1).
        else if (bracelessLive && (head === 'if' || head === 'while' || head === 'for' || head === 'switch' || head === 'catch')) bracelessLive = null;
        // `while (0)` that TERMINATES a `do {…}`/`do x` block is a
        // statement end, not a head — the next statement runs
        // unconditionally and must not be dead-spanned (w61-fv F-9).
        let doTail = false;
        if (head === 'while') {
          const wi = prevR.lastIndexOf('while');
          const preW = prevR.slice(0, wi);
          let jw = preW.length - 1;
          while (jw >= 0 && /\s/.test(preW[jw])) jw--;
          if (jw >= 0 && preW[jw] === '}') {
            let d = 1, k = jw - 1;
            for (; k >= 0; k--) { const cc = preW[k]; if (cc === '}') d++; else if (cc === '{') { d--; if (d === 0) break; } }
            if (k >= 0) {
              let lj = k - 1; while (lj >= 0 && /\s/.test(preW[lj])) lj--;
              doTail = /[\w$]+$/.exec(preW.slice(0, lj + 1))?.[0] === 'do';
            }
          } else {
            const bs = Math.max(preW.lastIndexOf(';'), preW.lastIndexOf('{'), preW.lastIndexOf('}'));
            const seg = preW.slice(bs + 1);
            doTail = /\bdo\b/.test(seg) && !/\b(?:if|else|while|for|switch|catch|case)\b/.test(seg);
          }
        }
        // A control head inside an existing dead span merges into it —
        // re-arming fresh would let ITS `;` end the outer statement
        // early and mint (`if (0) if (0) y; else z` stays dead).
        // A `while` closing a `do` block owns nothing — the statement
        // after it runs unconditionally (w61-fv F-9).
        if (doTail && !bracelessDead) bracelessLive = { depth: ld, arm: ci + 1 };
        // A braceless `if`/`while`/`for` arm is remembered: if it ends
        // in a guard (`return`/`throw`/`continue`/`break`), its `;`
        // marks the rest of the block conditional — `while (cond)
        // return;` gates the tail exactly like `if (cond) return;`
        // (w63-fv F-2). `while` closing a `do` block owns no body.
        if (head === 'if' || head === 'for' || (head === 'while' && !doTail)) {
          let j = ci + 1;
          while (j < lm.length && /\s/.test(lm[j])) j++;
          const braceless = j >= lm.length || lm[j] !== '{';
          bracelessIfArm = braceless ? ci + 1 : -1;
          bracelessIfCond = bracelessIfArm >= 0 ? headCond(prevR) : null;
          if (head === 'if') {
            // Innermost pending `if` — an `else` binds this one, not any
            // outer arm. Ours iff its head is this row's dispatch.
            pendingIfOurs = braceless ? { depth: ld, ours: mode === 'ours' && dispatchPure(headCond(prevR), verbPos), cond: headCond(prevR) } : null;
          }
        }
        if (!bracelessDead && (head === 'if' || head === 'for' || (head === 'while' && !doTail)) && deadCond(prevR)) {
          let j = ci + 1;
          while (j < lm.length && /\s/.test(lm[j])) j++;
          if (j >= lm.length || lm[j] !== '{') bracelessDead = { depth: ld, nestedIf: false };
        }
        // A braceless `if` on a sibling verb's pure dispatch arm — dead
        // for this row, its `else` the live arm via the dead-span
        // else-flip: `if (m[1]==='b') x; else authorize` mints for 'a'
        // (w63-fv F-4 sibling braceless twin).
        if (!bracelessDead && head === 'if' && siblingArm(headCond(prevR), verbPos, verbMembers, posMember)) bracelessDead = { depth: ld, nestedIf: false };
        // The braceless twin of the `{`-handler chain ledger — a `)`
        // that closed an `if` head resolves this arm for this row
        // (bound-member sibling arm or literal-dead cond fails, ours
        // takes it, anything else is a live head) so the `else` latch
        // can tell unconditional from conditional (w63-fv F-4).
        if (head === 'if' && deadDepths.size === 0) {
          const hc9 = bracelessIfCond ?? headCond(prevR);
          const kwS = hc9 ? hc9[2] : -1;
          const cont = kwS >= 0 && /\belse\s*$/.test(prevR.slice(0, kwS));
          const res = bracelessDead ? true : (pendingIfOurs?.ours === true ? 'ours' : false);
          const prev9 = chainFailed.get(ld);
          chainFailed.set(ld, cont ? (prev9 === 'ours' || res === 'ours' ? 'ours' : (prev9 === false || res === false ? false : true)) : res);
          const resReq = reqGateCond(hc9), prevReq = chainFailedReq.get(ld) ?? false;
          chainFailedReq.set(ld, cont ? (prevReq && resReq) : resReq);
        }
        pd--;
      }
      // A `return`/`throw`/`break`/`continue` inside a live conditional
      // frame exits its scope — closing that frame must leave the tail
      // conditional, not restore the unconditional span (w63-fv F-1).
      // Every enclosing frame is marked (a nested exit still gates the
      // outer block's tail) — but exits inside a nested CALLABLE body
      // leave the route flow untouched (`callScopes`, w63-fv F-1).
      if (condDepths.length && callScopes.size === 0 && /^(?:return|throw|break|continue)\b/.test(lm.slice(ci)) && !/[\w$]/.test(lm[ci - 1] ?? ' '))
        for (const e of condDepths) if (e.d <= ld) e.g = true;
      // `pendingUsed` marks the whole statement conditional — a real
      // gate edge (`if (c)`, `&&`, `?`, `:`) stays conditional even
      // inside a provably-live arm: the arm is live only when entered.
      // A bare `else`/`=>` tail is the arm OPENER, not a gate — its
      // body positions keep the live-arm exemption (w61-fv F-9).
      // An own-verb dispatch arm consumes the request-controlled gates
      // that enclose it — `if (m[1]==='a') { if (m[2]==='x') { authorize
      // (['spy']); } }` mints 'spy' for x: the m[1] constraint is part of
      // the row's request binding, not a disqualifying condition
      // (w59-fv F-2/w56-fv F-2). Marks opened INSIDE the arm (d >
      // ownDepth) and non-request gates (`flag`, `x || early`) still
      // condition.
      // The exemption claims only a NESTED own-verb arm — the row's head
      // arm itself consumes nothing: a request-controlled guard inside
      // it (`if (m[2]==='x') return; authorize`) still conditions the
      // tail (w63-fv F-3).
      const ownDepth = (oursIfArm >= 0 && oursIfNested) ? oursIfArm : (pendingIfOurs?.ours === true ? pendingIfOurs.depth : -1);
      const inOwn = ownDepth >= 0 && ld >= ownDepth;
      const gates = e => !(inOwn && e.req && e.d <= ownDepth);
      condPos[ci] = deadDepths.size > 0 || bracelessDead || deadElseArm ? 2 : (condDepths.some(e => gates(e) && e.d <= ld) || condTail.some(e => gates(e) && e.d <= ld) || (bracelessCond !== null && !(inOwn && bracelessCond.req && bracelessCond.depth <= ownDepth)) || (pendingUsed && !(pendingUsed === 'arm' && bracelessLive && ld <= bracelessLive.depth)) ? 1 : 0);
      // Scope-only view for credential-resolution scans: containing
      // conditions and pending gates count, propagated exit-tails do
      // not — a call after `if (a) {…return…}` still resolves for every
      // request that reaches it.
      condPosDeep[ci] = deadDepths.size > 0 || bracelessDead || deadElseArm ? 2 : (condDepths.some(e => gates(e) && e.d <= ld) || (pendingUsed && !(pendingUsed === 'arm' && bracelessLive && ld <= bracelessLive.depth)) ? 1 : 0);
      // Positions a provably-live arm cover — the syntactic prefix
      // guard cannot see the dead-state, so `else authorize` / a
      // do-`while` tail would read conditional without this (w61-fv
      // F-9). 'Live' means provably-IN-the-arm, not exempt from guards:
      // the caller rescans the span between the arm's entry and the
      // call, so `else cond && authorize` still mints conditional
      // (w62-fv F-1).
      livePos[ci] = bracelessLive ? 1 : 0;
      liveArm[ci] = bracelessLive ? bracelessLive.arm ?? -1 : -1;
    }
    if (bracelessCond && lm.slice(bracelessCond.arm ?? 0).trim() !== ''
        && (/[A-Za-z0-9_$)\]}'"`]$/.test(lm.trimEnd()) || /(?:\+\+|--)$/.test(lm.trimEnd()))) bracelessCond = null;
    bracelessIfArm = -1;
    // The live arm's statement ends where any statement ends — an EOL on
    // an expression tail after the arm's own content means ASI closed
    // it; carrying the latch into the next statement mints unconditional
    // through any guard (w62-ledger F-1/F-2). `else` alone at EOL keeps
    // it — the arm's body statement hasn't arrived yet.
    if (bracelessLive && lm.slice(bracelessLive.arm ?? 0).trim() !== ''
        && (/[A-Za-z0-9_$)\]}'"`]$/.test(lm.trimEnd()) || /(?:\+\+|--)$/.test(lm.trimEnd()))) bracelessLive = null;
    // A line ending on a conditional opener or a short-circuit/ternary
    // edge makes the NEXT statement conditional (braceless body or a
    // broken expression operand). `else`/`=>` ends open an ARM — its
    // positions keep the live-arm exemption; every other opener is a
    // real gate whose conditional survives into the arm (w63-fv F-4
    // fallout: `if (c)` newline `if (0){x} else auth` over-minted).
    const tail = lm.trimEnd();
    if (!/[;{}]\s*$/.test(tail)
        && /(?:\b(?:if|for|while|switch|catch)\s*(?:\([^()]*\)\s*)?|\belse\b|\bcatch\b|=>|&&|\|\||\?|:)\s*$/.test(tail)) pending = /(?:\belse\b|=>)\s*$/.test(tail) ? 'arm' : 'gate';
    return { condPos, condPosDeep, livePos, liveArm, endDepth: ld };
  };
  // The dispatch `if`'s paren condition — between the `(` matching the
  // `)` that ends `prev` — must be dispatch-pure for the arm exemption:
  // every top-level `&&`-joined operand a compare or a dispatcher
  // exec-bind. A bare operand (`req.isAdmin`, `other`, `f(x)`, `!x`) or
  // any `||`/`??`/`,`/`?`/`:`-mixing is an extra runtime gate — the arm
  // body is conditional on it (w62-ledger F-3).
  const headCond = prev => {
    let d = 0;
    for (let k = prev.length - 1; k >= 0; k--) {
      const c = prev[k];
      if (c === ')') d++;
      else if (c === '(') {
        d--;
        if (d === 0) {
          const kw = /([A-Za-z_$][\w$]*)\s*$/.exec(prev.slice(0, k));
          return [prev.slice(k + 1, -1), k + 1, kw ? k - kw[0].length : -1];
        }
      }
    }
    return null;
  };
  const dispatchPure = (condPair, verbPos = null) => {
    if (condPair === null) return false;
    const [cond, base] = condPair;
    const cls = dispOperandCls;
    const sideOps = side => {
      const s = splitSpans(side.t, ['&&', '??', ',', ':', '?'], side.a);
      if (s === null) return [side];
      if (s.ops.some(o => o !== '&&')) return null;
      return s.parts;
    };
    // A pure side is all-`&&`-operands of dispatch shape. For the row's
    // own verb the arm must additionally SERVE it: a single-side head
    // serves when some operand is our verb's member-compare or a
    // dispatcher bind — `req.method==='GET' && (m=/x/.exec(path))`
    // defines what an 'a' request even is (w62-check). Under `||` a bind
    // no longer serves: it only gates the request (the regex can still
    // reject 'a'), so an alternation arm needs a side whose positive
    // member-compare the pair scan bound to this verb —
    // `m[1]==='a' || m[1]==='b'`/`m[1]==='a' || gate` still fire for
    // every 'a' request, `bind || fallback` never does (w59-fv F-1).
    // Another verb's member compare or a negated member gates the side
    // like any conjunct — `m[1]==='a' && m[2]==='b'` is 'b'-conditional
    // here; `x==='y'` alone serves no verb at all.
    const vcPos = op => (verbPos ?? []).some(p => p >= op.a && p < op.b);
    // An operand containing a bound pair position IS a dispatch compare
    // whatever its spelling — a resolved alias (`sub === 'a'`) carries
    // no `m[N]` surface yet bound through dispAliases (w63-seal F-2
    // fallout: the field narrowing classified it impure).
    const opPure = op => vcPos(op) || ['membercmp', 'memberneg', 'othercmp', 'bind'].includes(cls(op.t));
    // An operand containing a pair position IS this verb's positive
    // compare — whatever its spelling (`m[N]`, a resolved alias, a
    // `case` label). Other member-compares and negated members are
    // gates here (w60-fv F-4).
    const opServe = op => vcPos(op) || cls(op.t) === 'othercmp' || cls(op.t) === 'bind';
    const pureSide = side => {
      const ops = sideOps(side);
      return ops !== null && ops.every(opPure) ? ops : null;
    };
    const sides = splitSpans(cond, ['||'], base);
    if (sides === null) {
      const ops = pureSide({ t: cond, a: base, b: base + cond.length });
      if (ops === null) return false;
      // No bound pair on the line: the arm is dispatch-shaped only when
      // EVERY conjunct serves the request shape — dispatch-field compares
      // (`path`, `req.method`, `url`) or regex binds. A member compare on
      // an unbound member (`m[1]!=='health'`, `q==='x'`) is a gate the
      // request may fail, so it keeps the arm conditional (w63-seal F-2).
      if (verbPos === null) return ops.every(op => cls(op.t) === 'bind' || cls(op.t) === 'othercmp');
      return ops.some(op => vcPos(op) || cls(op.t) === 'bind');
    }
    if (verbPos === null) return sides.parts.every(s => pureSide(s) !== null);
    return sides.parts.some(side => {
      const ops = sideOps(side);
      return ops !== null && ops.every(opServe) && ops.some(vcPos);
    });
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
  // name → [{pos, member}] — bindings are POSITIONAL: a compare sees
  // only the last assignment before it — `q[1]==='a'` before `q = m`
  // never bound (TDZ/TypeError at runtime, minted anyway: w63-fv F-6);
  // a `q = <non-alias>` rebind kills only compares AFTER it. `member`
  // null marks a kill. `pos` = line*1e7 + char offset.
  const hist = new Map();
  const push = (nm, pos, member) => {
    const arr = hist.get(nm) ?? [];
    arr.push({ pos, member });
    hist.set(nm, arr);
  };
  const at = (nm, pos) => {
    const arr = hist.get(nm);
    if (!arr) return undefined;
    let v;
    for (const b of arr) { if (b.pos > pos) break; v = b.member; }
    return v === null ? undefined : v;
  };
  const dead = deadState();
  let li = 0;
  for (const l0 of lines) {
    const base = li++ * 1e7;
    const s = maskStrings(stripDead(l0, dead), dead);
    for (const m of s.matchAll(/\b(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*(?:m\s*(?:\?\s*\.\s*)?(?:\[\s*([^\]]+)\]|\.?\s*at\s*\?\s*\.?\s*\(\s*([^)]*)\))|([A-Za-z_$][\w$]*))/g)) {
      // Chained aliases (`sub2 = sub`) resolve through the binding live
      // AT THIS POSITION — member binding, not surface binding
      // (w63-fv F-6). `const q = m` binds the WHOLE dispatcher — `q[N]`
      // then dispatches exactly like `m[N]` (w61-ledger F-5).
      const resolved = m[4] === 'm' ? 'm' : m[4] !== undefined ? at(m[4], base + m.index) : null;
      const idx = resolved ?? (() => { const v = DISP_IDX_EVAL(m[2] ?? m[3] ?? ''); return v === null ? null : `m[${v}]`; })();
      if (idx !== null) push(m[1], base + m.index, idx);
    }
    const d = /\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*m\b/.exec(s);
    if (d) for (const mm of d[1].matchAll(/['"`]?(\d+)['"`]?\s*:\s*([A-Za-z_$][\w$]*)/g)) push(mm[2], base + d.index, `m[${mm[1]}]`);
    // A `name = <anything not m[…]>` rebinding kills the alias FROM ITS
    // POSITION — earlier compares keep the live binding (w63-fv F-6;
    // w59-ledger F-5).
    for (const m of s.matchAll(/\b([A-Za-z_$][\w$]*)\s*(?<![=!<>])=(?![=])\s*/g)) {
      if (!hist.has(m[1])) continue;
      const rhs = s.slice(m.index + m[0].length);
      if (/^m\s*(?:\?\s*\.\s*)?(?:\[|\.?\s*at\s*\?\s*\.?\s*\()/.test(rhs)) continue;
      // `name = m` binds the whole dispatcher, not a member — it keeps
      // the alias instead of reading as a non-m rebind (w61-ledger F-5).
      if (/^m\s*(?:[;,]|$)/.test(rhs)) continue;
      // An identifier RHS keeps the binding only when that identifier is
      // itself a live alias AT THIS POSITION — `x = undefined` kills.
      const ident = /^([A-Za-z_$][\w$]*)\s*(?:[;,]|$)/.exec(rhs)?.[1];
      if (!(ident && at(ident, base + m.index) !== undefined)) push(m[1], base + m.index, null);
    }
  }
  return { hist, at };
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
        decls.push({ name, li: i, start: dm.index + dm[0].length, group: g });
      }
    // Each decl's body span — the escape scan needs it so a self-
    // reference inside the body (`g()` in g's own body — a recursive call
    // is not an entry) cannot count as an escape, while a `g()` placed
    // AFTER the decl's own `}` on the same line still counts
    // (w61-ledger F-2's self-ref PoC, w60-fv F-2/F-6).
    for (const d of decls) {
      let j = d.li, dd = 0, seen = false;
      d.bodyStart = -1; d.bodyEnd = -1;
      for (; j < ml.length; j++) {
        const seg = j === d.li ? ml[j].slice(d.start) : ml[j];
        const off = j === d.li ? d.start : 0;
        for (let k = 0; k < seg.length; k++) {
          const ch = seg[k];
          if (ch === '{') { dd++; if (d.bodyStart < 0) d.bodyStart = off + k; seen = true; }
          else if (ch === '}') { dd--; if (seen && dd <= 0) { d.bodyEnd = off + k; break; } }
        }
        if (seen && dd <= 0) break;
      }
      if (!seen) for (j = d.li; j < ml.length; j++) { const sc = ml[j].indexOf(';'); if (sc >= 0) { d.bodyEnd = sc; break; } }
      d.end = j;
      // Inside = strictly between the body's own start and end positions.
      d.inBody = (i, wi) => {
        if (i < d.li || i > d.end) return false;
        const s = d.bodyStart >= 0 ? d.bodyStart : d.start;
        const e = d.bodyEnd >= 0 ? d.bodyEnd : Infinity;
        if (i === d.li && wi < s) return false;
        if (i === d.end && wi > e) return false;
        return true;
      };
    }
    // A declaration is dead only when NOTHING outside its own decl name
    // invokes it — a use POSITION is not an invocation: `x = g`, `foo(g)`,
    // `typeof g`, `return g`, `g === null`, `!g` all referenced or flowed
    // the name while the body stayed unreachable, yet minted liveness
    // anyway (w61-ledger F-2). Escapes are only PROVABLE invocations:
    // `g(`, `g?.(`, `(g)(`, tagged template `g\``, `new g`,
    // `g.call`/`.apply`/`.bind`, a member call `.g(` on a member decl, and
    // `g` inside a known callback-consumer's argument list
    // (setTimeout/setInterval/queueMicrotask/requestAnimationFrame/
    // nextTick and `.then|.catch|.finally|.on|.once|.addEventListener|.
    // forEach|.map|.filter|.reduce|.find|.sort|.flatMap|.every|.some` —
    // those receivers invoke their callback args). Excluded positions:
    // `.g` member reads, `g:`-key positions, `function g`/`g: function`
    // headers, decl name tokens, and occurrences inside the decl's own
    // body.
    const CALLBACK_CONSUMER = /(?:\bsetTimeout|\bsetInterval|\bqueueMicrotask|\brequestAnimationFrame|\bnextTick|\.(?:then|catch|finally|on|once|addEventListener|forEach|map|filter|reduce|find|sort|flatMap|every|some))\s*\([^)]*$/;
    const escapes = new Set();
    for (const d of decls) {
      if (escapes.has(d.name)) continue;
      const word = new RegExp(`\\b${d.name.replace(/\$/g, '\\$')}\\b`, 'g');
      for (let i = 0; i < ml.length; i++) {
        let found = false;
        for (const wm of ml[i].matchAll(word)) {
          const wi = wm.index;
          if (declPos.has(`${i}:${wi}`)) continue;
          if (d.inBody(i, wi)) continue;                     // self-reference inside its own body
          const before = ml[i].slice(0, wi).trimEnd();
          const after = ml[i].slice(wi + d.name.length);
          const memberDecl = d.group >= 4;
          if (/^\s*:/.test(after)) continue;                 // `g:` object key
          if (/\bfunction\s*\*?\s*$/.test(before)) continue; // `function g` header
          if (/^\s*:\s*(?:async\s+)?function/.test(after)) continue; // `g: function`
          if (/[.$]\s*$/.test(before)) {
            // `.g` is a member read — except `.g(`/`.g?.(` invokes a
            // member-decl's body (`o.g()` on `{ g() {} }`).
            if (memberDecl && /^\s*(?:\(|\?\s*\.\s*\()/.test(after)) { escapes.add(d.name); found = true; break; }
            continue;
          }
          // Tagged-template `g`x`` — maskStrings blanks the backticks on
          // the masked view, so the raw line supplies the tell (positions
          // align — maskStrings preserves them).
          const rawAfter = lines[lo + i].slice(wi + d.name.length);
          if (/^\s*\(/.test(after) || /^\s*\?\s*\.\s*\(/.test(after) || /^\s*`/.test(rawAfter)
            || /^\s*\.\s*(?:call|apply|bind)\b/.test(after) || /^\s*\?\s*\.\s*(?:call|apply|bind)\b/.test(after)
            || (/\(\s*$/.test(before) && /^\s*\)\s*\(/.test(after))
            || /\bnew\s*$/.test(before)
            || CALLBACK_CONSUMER.test(before)) {
            escapes.add(d.name); found = true; break;
          }
        }
        if (found) break;
      }
    }
    const dead = new Set();
    for (const d of decls) {
      if (escapes.has(d.name)) continue;
      for (let k = d.li; k <= d.end && k < ml.length; k++) dead.add(lo + k);
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
    // `switch (<dispatch member>)` frames — case literals inside bind
    // their member the way else-if compares do (w61-ledger F-5).
    const switchStack = [];
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
    // Members this row's verb dispatches on — accumulates as the scan
    // sees this verb's member-compare pairs; siblingArm consults it to
    // prove disjointness is same-member, not same-line (w63-fv F-3).
    const verbMemberSet = new Set();
    // Seed it row-wide: a sibling arm consults the set BEFORE the line
    // that binds the verb (`if(m[1]==='abort')` precedes
    // `if(m[1]==='acknowledge')`, w59-fv F-2 — incremental accumulation
    // left the earlier arm unprovable and broke w63-fv F-3's
    // bound-member disjointness test). Spellings mirror pairs0's:
    // direct `m[N]==='<verb>'`, whole-dispatcher alias `q[N]==='<verb>'`
    // resolved at its own position, and `switch(m[N])`/`case '<verb>'`.
    if (verb !== null) {
      let swM = null, swD = -1, swDepth = 0;
      for (let i2 = from; i2 < Math.min(from + depth, lines.length); i2++) {
        const l2 = lines[i2], lm2 = maskStrings(l2, deadM);
        if (swM !== null && swDepth <= swD) swM = null;
        for (const xm of l2.matchAll(/\bm\s*\[\s*([^\]]+)\s*\]\s*={2,3}\s*'([^']+)'/g))
          if (xm[2] === verb && lm2[xm.index] !== ' ') { const idx = DISP_IDX_EVAL(xm[1]); if (idx !== null) verbMemberSet.add(`m[${idx}]`); }
        for (const nm of aliases.hist.keys()) {
          const esc = nm.replace(/\$/g, '\\$');
          for (const xm of l2.matchAll(new RegExp(`\\b${esc}\\s*\\[\\s*([^\\]]+)\\s*\\]\\s*={2,3}\\s*'([^']+)'`, 'g')))
            if (xm[2] === verb && lm2[xm.index] !== ' ' && aliases.at(nm, i2 * 1e7 + xm.index) === 'm') { const idx = DISP_IDX_EVAL(xm[1]); if (idx !== null) verbMemberSet.add(`m[${idx}]`); }
        }
        for (const sm of lm2.matchAll(/\bswitch\s*\(\s*m\s*\[\s*([^\]]+)\s*\]\s*\)/g)) {
          const idx = DISP_IDX_EVAL(sm[1]);
          if (idx !== null) { swM = `m[${idx}]`; swD = swDepth; }
        }
        if (swM !== null)
          for (const cm of l2.matchAll(/\bcase\s*(?:'([^']+)'|"([^"]+)"|`([^`]+)`)/g))
            if ((cm[1] ?? cm[2] ?? cm[3]) === verb) verbMemberSet.add(swM);
        swDepth += (lm2.match(/\{/g) ?? []).length - (lm2.match(/\}/g) ?? []).length;
      }
    }
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
      // Pairs bind on the arm-head line too — `if (m[1]==='a') {…}`
      // scanned for verb 'b' must see the a-pair so the arm classifies
      // as sibling/dead for 'b', not 'ours' by default (w63-seal F-3).
      const pairs0 = verb ? (() => {
        const out = [];
        // A `switch (<member>)` opens a dispatch frame whose `case 'v'`
        // literals compare exactly like `m[N]==='v'` arms — unjudged
        // switches minted a bare 'any' for every verb (w61-ledger F-5).
        {
          const stmtDepth = depthCur - closes;
          while (switchStack.length && stmtDepth <= switchStack.at(-1).depth) switchStack.pop();
          for (const sm of l.matchAll(/\bswitch\s*\(/g)) {
            // Balanced-paren operand — `switch (f(m[2]))` truncated at
            // the first `)` re-targeted the frame onto the raw member
            // while cases compare the transformed value (w62-ledger
            // F-4). Only a whole-operand member/alias may bind.
            let d = 0, k = sm.index + sm[0].length, end = -1;
            for (; k < l.length; k++) { const c = l[k]; if (c === '(') d++; else if (c === ')') { if (d === 0) { end = k; break; } d--; } }
            if (end < 0) continue;
            const op = l.slice(sm.index + sm[0].length, end);
            DISP_MEMBER.lastIndex = 0;
            const dm = DISP_MEMBER.exec(op);
            let member = null;
            if (dm && dm[0].trim() === op.trim()) { const idx = DISP_IDX_EVAL(dm[1] ?? dm[2] ?? ''); if (idx !== null) member = `m[${idx}]`; }
            else { const r = aliases.at(op.trim(), i * 1e7 + sm.index); if (r !== undefined && r !== 'm') member = r; }
            // `stmtDepth` already counts this line's own `{` — the
            // switch's frame depth is one level shallower, so its case
            // labels sit strictly deeper.
            if (member !== null) switchStack.push({ member, depth: stmtDepth - 1, at: sm.index });
          }
          const top = switchStack.at(-1);
          if (top)
            for (const cm of l.matchAll(/\bcase\s*(?:'([^']+)'|"([^"]+)"|`([^`]+)`)/g))
              if (lm[cm.index] !== ' ' && (stmtDepth > top.depth || cm.index > top.at)) out.push({ member: top.member, verb: cm[1] ?? cm[2] ?? cm[3], pos: cm.index });
        }
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
        for (const nm of aliases.hist.keys()) {
          const esc = nm.replace(/\$/g, '\\$');
          // Whole-dispatcher alias — `q[N]==='verb'` dispatches like
          // `m[N]==='verb'` — only when the binding live AT THIS
          // COMPARE's position is the whole dispatcher (w61-ledger F-5,
          // w63-fv F-6).
          const re = new RegExp(`\\b${esc}\\s*(?:\\?\\s*\\.\\s*)?(?:\\[\\s*([^\\]]+)\\]|\\.?\\s*at\\s*\\?\\s*\\.?\\s*\\(\\s*([^)]*)\\))`, 'g');
          for (const x of l.matchAll(re)) {
            if (lm[x.index] === ' ') continue;
            if (aliases.at(nm, i * 1e7 + x.index) !== 'm') continue;
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
          const v = new RegExp(`\\b${esc}\\s*={2,3}\\s*'([^']+)'`).exec(l);
          if (v && lm[v.index] !== ' ') {
            const resolved = aliases.at(nm, i * 1e7 + v.index);
            const a = armOf(v.index);
            // The pair binds the RESOLVED member at the compare's own
            // position — two spellings of one member contradict through
            // the frame's pair set (w60-fv F-4, w63-fv F-6).
            if (resolved !== undefined && resolved !== 'm' && a && !negatedCompare(a.term, v.index) && !conditionalTerm(a.term)) out.push({ member: resolved, verb: v[1], pos: v.index });
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
      // Members this row's verb dispatches on, accumulated across the
      // scan — a sibling arm is provably disjoint only when its member
      // compare binds a member THIS verb also binds (w63-fv F-3).
      for (const p of pairs0) if (p.verb === verb) verbMemberSet.add(p.member);
      const posMemberMap = new Map(pairs0.map(p => [p.pos, p.member]));
      const verbPosLine = pairs.filter(p => p.verb === verb).map(p => p.pos);
      // A line is sibling territory for this row only when EVERY
      // control head on it provably fails for this verb — every
      // `if`/`else if`/`while`/`for`/`switch` head a bound-member
      // foreign dispatch arm and every `case` compare under a bound
      // member. A head this verb might satisfy (`if (flag)`,
      // `m[2]==='x'` for an m[1]-bound row, a do-`while` tail it just
      // evaluated) makes the line conditional territory: 'b' still
      // rides it, and the else of `if (m[1]==='a')` is 'b''s arm, so
      // the whole line cannot be 'a''s row either (w63-fv F-4).
      const sibling = (() => {
        if (pairs.length === 0 || pairs.some(p => p.verb === verb)) return false;
        // A line with an `else` tail is never wholly dead for a bound
        // verb — failing every prior head lands this verb inside the
        // else arm, so `if (m[1]==='b') {…} else authorize` still
        // serves 'a' (w63-fv F-4). An UNBOUND verb dispatches nowhere —
        // its else arms stay dead scope too (w56-fv F-2, w61 F-5).
        if (verbMemberSet.size !== 0 && /\belse\b/.test(lm)) return false;
        const headWord = open => {
          let j = open - 1; while (j >= 0 && (lm[j] === ' ' || lm[j] === '\t')) j--;
          return /[\w$]+$/.exec(lm.slice(Math.max(0, j - 40), j + 1))?.[0] ?? '';
        };
        const headDead = open => {
          let d = 0, close = -1;
          for (let k = open; k < lm.length; k++) { const c = lm[k]; if (c === '(') d++; else if (c === ')') { d--; if (d === 0) { close = k; break; } } }
          return close >= 0 && siblingArm([lm.slice(open + 1, close), open + 1], verbPosLine, verbMemberSet, posMemberMap);
        };
        for (const p of pairs) {
          const a = armOf(p.pos);
          // A `case` pair's pos sits ON the `case` keyword — the arm has
          // no parens of its own, so armOf cannot walk back to it; the
          // dispatch member it binds is the switch's operand (w61 F-5).
          if (a === null && !/^case\b/.test(lm.slice(p.pos))) return false;
          const w = a === null ? 'case' : headWord(a.open);
          if (w === 'case' || w === 'switch') { if (verbMemberSet.size !== 0 && !verbMemberSet.has(p.member)) return false; continue; }
          if (w !== 'if' && w !== 'while' && w !== 'for' && w !== 'switch') return false;
          if (w === 'while' && /\}\s*while\s*$/.test(lm.slice(0, a.open))) return false;
          if (!headDead(a.open)) return false;
        }
        // An `if`/`while`/`for`/`switch` head carrying NO pair still
        // counts — a live head this verb might satisfy rides the line
        // too. Heads inside an arm that is already dead for this verb
        // stay unreachable for it: demoting to conditional territory
        // lands on the same verdict (w63-fv F-4).
        for (const hm of lm.matchAll(/\b(?:if|while|for|switch)\s*\(/g)) {
          const open = hm.index + hm[0].length - 1;
          let d = 0, close = -1;
          for (let k = open; k < lm.length; k++) { const c = lm[k]; if (c === '(') d++; else if (c === ')') { d--; if (d === 0) { close = k; break; } } }
          if (close < 0) return false;
          if (!pairs.some(p => p.pos > open && p.pos < close)) {
            // A `switch (m[N])` head binds a member operand — for a
            // foreign row (no member bound anywhere) every case is dead
            // dispatch, and for a row bound on that member the cases
            // carry the arm semantics — only a cross-member switch head
            // is a live guard for this verb (w61-ledger F-5).
            const swc = lm.slice(open + 1, close);
            const swm = /^\s*m\s*\[\s*([^\]]+)\s*\]\s*$/.exec(swc);
            const swBound = swm !== null && (verbMemberSet.size === 0 || (DISP_IDX_EVAL(swm[1]) !== null && verbMemberSet.has(`m[${DISP_IDX_EVAL(swm[1])}]`)));
            if (!swBound && !siblingArm([swc, open + 1], verbPosLine, verbMemberSet, posMemberMap)) return false;
          }
        }
        return true;
      })();
      // An own-verb arm nested inside a sibling region mints only when it
      // can actually run: a nested compare on the SAME member as an
      // enclosing sibling arm's compare but naming a DIFFERENT verb is
      // statically dead (`if(m[2]==='abort'){ if(m[2]==='acknowledge')`),
      // so its authorize mints nothing (w59-fv F-2). Different members
      // (m[1] vs m[2]) or the else of a sibling chain stay reachable.
      const contradict = p => skipStack.some(s => s.ours === false && Array.isArray(s.pairs) && s.pairs.some(sp => sp.member === p.member && sp.verb !== p.verb));
      const ours = pairs.some(p => p.verb === verb && !contradict(p));
      // An `else`/`else if` after OUR arm already closed is dead for
      // this row even when it repeats our verb — the earlier arm
      // consumed every matching request, so its authorize mints nothing
      // (w59-ledger F-3). A `} else` continuing a FOREIGN chain is NOT
      // dead for this row — this verb reaches it whenever it failed
      // every prior head: the member-bound tracker latches decide
      // unconditional vs conditional per arm (w63-fv F-4's else for
      // everyone else). Before our arm, an else carrying our verb is
      // genuinely ours.
      const elseSibling = isElse && (ourChainClosed || (!ours && (popped || inSib) && verbMemberSet.size === 0));
      const inDead = skipStack.some(s => s.dead);
      const excluded = deadArm || inDead || (inSib && !ours) || skipIndent !== null || elseSibling || sibling;
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
      const scan = tracker.line(lm, depthCur, i === from || ours ? 'ours' : (sibling || elseSibling) ? 'sibling' : null, maskStrings(blankBlock(stripComment(lines[i]), deadM), deadM), false, i === from && pairs0.length === 0 ? null : pairs.filter(p => p.verb === verb).map(p => p.pos), pairs0.map(p => p.pos), verbMemberSet, new Map(pairs0.map(p => [p.pos, p.member])));
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
      // `ownDispatch(prefix, verbPos)` — the trailing braceless `if`
      // before a return/throw is THIS row's dispatch (and only this
      // row's dispatch) when some `||`-side unconditionally serves the
      // verb: every top-level `&&` operand on that side is a compare or
      // a dispatcher exec/test/match bind, and at least one is a
      // positive member-compare the pair scan bound to this verb (or a
      // bind). Other-verb member-compares and negated members gate the
      // side like any conjunct (w62-fv F-8).
      const ownDispatch = (prefix, verbPos) => {
        if (typeof verb !== 'string' || verb === '') return false;
        const t = tailCtlCond(prefix, 'if');
        if (!t) return false;
        const [cond, base] = t;
        const vcPos = op => (verbPos ?? []).some(p => p >= op.a && p < op.b);
        const sides = splitSpans(cond, ['||'], base);
        const parts = sides === null ? [{ t: cond, a: base, b: base + cond.length }] : sides.parts;
        return parts.some(side => {
          const s = splitSpans(side.t, ['&&', '??', ',', ':', '?'], side.a);
          if (s !== null && s.ops.some(o => o !== '&&')) return false;
          const ops = s === null ? [side] : s.parts;
          return ops.every(op => vcPos(op) || dispOperandCls(op.t) === 'othercmp' || dispOperandCls(op.t) === 'bind')
            && ops.some(vcPos);
        });
      };
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
              // (w57-fv NEW-1). Under `ours` the exemption needs the if's
              // own condition to be our dispatch — `if (m[N]==='ourverb'
              // [&& bind]*)` — any other guard (`if (early) return`,
              // `if (m[2]!=='e'||x) return`) keeps the tail conditional,
              // never dead and never unconditional (w62-fv F-8).
              && ((ours && ownDispatch(lm.slice(0, ci), pairs.filter(p => p.verb === verb).map(p => p.pos))) || !(tailCtlCond(lm.slice(0, ci), 'if|for|while') !== null || /\belse\s*$/.test(lm.slice(0, ci))))) { cut = ci; break; }
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
          if (scan.condPos[m.index] || (!bodyUncond && guardedPrefix(lmx, m.index, scan.livePos[m.index] ? scan.liveArm[m.index] : undefined))) continue;
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
        if (fscan.condPos[m.index] || guardedPrefix(fm, m.index, fscan.livePos[m.index] ? fscan.liveArm[m.index] : undefined)) continue;
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
        // Iteration over a collection is a credential resolver's
        // traversal, not a gate — `for` bodies count as unguarded scope
        // here (while/if/switch arms stay conditional).
        const scan = tr.line(ml, sd, i === hi ? 'ours' : null, maskStrings(blankBlock(stripComment(lines[i]), dM), dM), true);
        sd = scan.endDepth;
        for (const m of ml.matchAll(AUTH_CALL))
          if (!windowDeadFn.has(i) && !scan.condPosDeep[m.index] && !guardedPrefix(ml, m.index, scan.livePos[m.index] ? scan.liveArm[m.index] : undefined)) return true;
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
      if (r.roles[0] === 'unauthenticated' && (gate.any || new RegExp(AUTH_CALL.source).test(windowMasked))) { console.error(`route-role parity: ${r.method} ${r.path} — claims unauthenticated but the handler authenticates`); failed = true; continue; }
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
            if (!pscan.condPosDeep[am.index] && !guardedPrefix(pm, am.index, pscan.livePos[am.index] ? pscan.liveArm[am.index] : undefined)) priorAuthed = true;
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

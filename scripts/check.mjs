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
const CODE_EXT = /\.(mjs|js|cjs)$/;
const ANY_EXT = /\.(mjs|js|cjs|ts)$/;
let files = [];
// Every spawned helper gets a wall-clock ceiling — a hung subprocess must
// fail the gate, never stall it forever (w23-supply F17).
const SPAWN_OPTS = { encoding: 'utf8', timeout: 300000 };
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
  ['dynamic eval', new RegExp(`\\beval\\s*\\(|new\\s+Function\\s*\\(|eval\\s*\\/\\*\\*\\/\\s*\\(|\\bFunction\\s*\\(|Reflect\\.apply\\s*\\(\\s*eval|node:${'v'}m|from\\s+['"](?:node:)?${'v'}m['"]|require\\s*\\(\\s*['"](?:node:)?${'v'}m['"]|import\\s*\\(\\s*['"](?:node:)?${'v'}m['"]|runIn(?:This|New)?Context`)],
  ['string-timed code', /\bset(?:Timeout|Interval)\s*\(\s*['"`]/],
  ['embedded private key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['cloud credential pattern', /\bAKIA[0-9A-Z]{16}\b/]
];
// The marker words are split so this scanner does not flag its own
// source. 'XXX' stays out deliberately — it is a real ISO-4217 value in
// test fixtures, not an unfinished marker (w53-ledger MEDIUM).
const MARKER_RULES = [
  ['unfinished code marker', new RegExp(`\\b(?:${'TO' + 'DO'}|${'FIX' + 'ME'}|${'TO' + '-DO'}|${'T' + 'BD'}|${'W' + 'IP'}|${'HA' + 'CK'})\\b`)]
];
// Case-insensitive on authored files: a lowercase marker is the same
// unfinished code (w49-ledger F-1). reports/ is exempt — '# to'+'do N'
// lines are generated TAP protocol fields, not authored markers; the few
// files that legitimately name node:test's skip/defer vocabulary dodge
// the literal word instead.
const MARKER_LOOSE = [
  ['unfinished code marker (any case)', new RegExp(`\\b(?:${'TO' + 'DO'}|${'FIX' + 'ME'}|${'TO' + '-DO'}|${'T' + 'BD'}|${'W' + 'IP'}|${'HA' + 'CK'})\\b`, 'i')]
];
// DOM-injection sinks matter in ANY code that renders — not only src/ and
// web/: an .html asset or script-generated page outside those roots could
// carry a live sink (w49-ledger F-1). Tests legitimately contain these
// strings inside regexes that assert their absence; this file exempts
// itself because it hosts the rules.
const RENDER_ONLY = [
  ['DOM injection', /\.(?:innerHTML|outerHTML)\s*(?:=|\+=)|insertAdjacentHTML|document\.write\s*\(/]
];
for (const file of textFiles) {
  if (file === 'vectors/keys.json' || !existsSync(file) || isBinary(file)) continue;
  const s = readFileSync(file, 'utf8');
  // check.mjs exempts itself only from the DOM rules — its rule table
  // legitimately hosts the sink literals; sinks and markers still apply.
  const renderable = file !== 'scripts/check.mjs' && (file.startsWith('src/') || file.startsWith('web/') || /\.(?:html?|jsx|tsx)$/.test(file)) && !file.startsWith('tests/');
  const rules = [...(SINK_EXT.test(file) ? SINK_RULES : []), ...(renderable ? RENDER_ONLY : []), ...MARKER_RULES, ...(file.startsWith('reports/') ? [] : MARKER_LOOSE)];
  for (const [name, regex] of rules) if (regex.test(s)) { console.error(`${file}: ${name}`); failed = true; }
}

// Route-role parity: every role list the OpenAPI generator declares must
// match the role gate actually executed — either the authorize() call on
// the handler line(s) in server.mjs or the first authorize() inside the
// delegated fabric method (w20-ledger F-4: the generator table is
// hand-maintained, so without this a drifted contract is "verified"
// only by its own output).
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
  const isIf = l => /^\s*(?:\}\s*)?(?:else\s+)?if\s*\(/.test(l);
  // A single-statement validation guard (queryCheck/noBody) is not a
  // handler boundary — the fabric call that carries the role gate may
  // legitimately sit below it (w43-fv M1 ordering).
  const isValidationGuard = l => /^\s*if \([^)]*\)\s*(queryCheck|noBody)\s*\(/.test(l);
  // Union of EVERY authorize() in the window — the first call alone let a
  // second gate widen silently past the contract (w51-ledger M-1).
  const collectAuthorize = (lines, from, depth, breakIf = true) => {
    const found = new Set();
    for (let i = from; i < Math.min(from + depth, lines.length); i++) {
      if (i !== from && breakIf && isIf(lines[i]) && !isValidationGuard(lines[i])) break;
      for (const m of lines[i].matchAll(/authorize\(p,\s*\[([^\]]+)\]/g))
        for (const r of m[1].split(',')) found.add(r.trim().replace(/['"]/g, ''));
    }
    return found.size ? [...found] : null;
  };
  const authorizeAt = (lines, from, depth = 6) => collectAuthorize(lines, from, depth);
  const fabricRoles = name => {
    const idx = fabric.findIndex(l => new RegExp(`^\\s{2}(async )?${name}\\(`).test(l));
    if (idx === -1) return null;
    const found = new Set();
    for (let i = idx; i < Math.min(idx + 140, fabric.length); i++) {
      if (i !== idx && /^\s{2}(async )?[a-zA-Z_]+\(/.test(fabric[i])) break;
      for (const m of fabric[i].matchAll(/this\.authorize\(p,\s*\[([^\]]+)\]/g))
        for (const r of m[1].split(',')) found.add(r.trim().replace(/['"]/g, ''));
      const r = /roles\?*\.includes\('([^']+)'\)/.exec(fabric[i]);
      if (r && /requireThat/.test(fabric[i])) found.add(r[1]);
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
    const hi = lines.findIndex(l =>
      isIf(l) && l.includes(`req.method === '${r.method.toUpperCase()}'`) &&
      (l.includes(`path === '${r.path}'`) || l.includes(`url.pathname === '${r.path}'`) || l.includes(`req.url === '${r.path}'`) || (param && /\^\\\//.test(l) && staticSegs.every(s => l.includes(s)))));
    // The handler window: everything from the dispatch arm until the next
    // route boundary — this is what auth claims are checked against. Wide
    // enough to see a credential resolve inside a docstring-heavy handler.
    const windowEnd = () => { let e = hi === -1 ? hi : hi + 40; for (let i = hi + 1; i < Math.min(hi + 40, lines.length); i++) if (isIf(lines[i]) && !/m\[2\]/.test(lines[i]) && !isValidationGuard(lines[i])) { e = i; break; } return e; };
    const windowCode = hi === -1 ? '' : lines.slice(hi, windowEnd()).join('\n');
    if (r.roles.length === 1 && NONROLE.has(r.roles[0])) {
      // Non-role claims are still contract claims: 'unauthenticated' must
      // name a handler that runs no auth, 'token holder' must actually
      // resolve a credential, 'issuer bearer token' must resolve the
      // issuerd bearer machinery — and no non-role row may hide a role
      // gate (w51-ledger H-3, w52-ledger M-6).
      if (hi === -1) { console.error(`route-role parity: ${r.method} ${r.path} — cannot resolve the handler behind a '${r.roles[0]}' claim`); failed = true; continue; }
      const gate = collectAuthorize(lines, hi, 12);
      if (r.roles[0] === 'unauthenticated' && (gate || /auth\(req|authenticateToken/.test(windowCode))) { console.error(`route-role parity: ${r.method} ${r.path} — claims unauthenticated but the handler authenticates`); failed = true; continue; }
      if (r.roles[0] === 'token holder' && !/authenticateToken|auth\(req/.test(windowCode)) { console.error(`route-role parity: ${r.method} ${r.path} — claims token holder but no credential resolves`); failed = true; continue; }
      if (r.roles[0] === 'issuer bearer token' && !/anyBearer\(|bearerMatches\(|issuerAuthOk\(|bearerDigest\(/.test(windowCode)) { console.error(`route-role parity: ${r.method} ${r.path} — claims issuer bearer token but no bearer gate resolves`); failed = true; continue; }
      if (r.roles[0] !== 'unauthenticated' && gate) { console.error(`route-role parity: ${r.method} ${r.path} — claims '${r.roles[0]}' but a role gate [${gate}] resolves`); failed = true; continue; }
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
      const priorCalls = (dispatchStart === -1 ? lines : lines.slice(dispatchStart, hi)).filter(l => !/^\s*(?:async\s+)?function\s/.test(l)).join('\n');
      if ((r.roles[0] === 'authenticated' || r.roles[0] === 'bound subject')
          && !/auth\(req|authenticateToken|authBreakglass\(/.test(windowCode)
          && !/auth\(req|authenticateToken|authBreakglass\(|authorize\(/.test(priorCalls)) {
        console.error(`route-role parity: ${r.method} ${r.path} — claims '${r.roles[0]}' but no credential resolves on or above the handler`); failed = true; continue;
      }
      continue;
    }
    if (r.listener === 'issuerd' && !(r.roles.length === 1 && r.roles[0] === 'issuer bearer token')) { console.error(`route-role parity: ${r.method} ${r.path} — issuerd rows may only claim 'issuer bearer token'`); failed = true; continue; }
    let code = null;
    if (hi !== -1) {
      code = authorizeAt(lines, hi);
      if (!code) {
        for (let i = hi; i < Math.min(hi + 12, lines.length); i++) {
          if (i !== hi && isIf(lines[i]) && !/m\[2\]/.test(lines[i]) && !isValidationGuard(lines[i])) break;
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
  // naive split-on-first-// truncated lines and let real route conditions
  // escape the audit (w51-ledger H-2).
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
    const lead = /^\s*\}+/.exec(code)?.[0].match(/\}/g)?.length ?? 0;
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
    if (/\bswitch\s*\([^)]*(?:req\.method|req\.url|path|url\.pathname)/.test(code)) { console.error(`route-spec parity: unauditable switch dispatch — ${line.trim().slice(0, 100)}`); failed = true; }
    else if (/(?:\bpath\b|req\.url|url\.pathname)\s*===\s*'|\.exec\((?:path|req\.url|url\.pathname)\)/.test(code) && !/req\.method/.test(eff) && /send\(|fabric\.|res\./.test(code)) { console.error(`route-spec parity: path arm with no enclosing method gate — ${line.trim().slice(0, 100)}`); failed = true; }
    else if (/req\.method/.test(eff) && /\bpath\b|req\.url|url\.pathname/.test(eff)) routeSeen(eff, line);
    // Track enclosing conditions: an `if (` whose block stays open
    // past this line governs the lines below it; a balanced line
    // (single-line handler) closes what it opened and must not leak its
    // condition onto the next line. A tentative `if (` collects until a
    // net-opening '{' confirms it or a ';' kills it (multi-line route
    // conditions, w51-ledger H-2).
    const opens = (code.match(/\{/g)?.length ?? 0), closes = (code.match(/\}/g)?.length ?? 0) - lead;
    if (/\bif\s*\(/.test(code)) {
      if (opens > closes) { if (tentative) { tentative.text += ' ' + code; pending.push(tentative); } else pending.push({ depth: depth + 1, text: code }); }
      tentative = null;
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
  const walk = dir => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = `${dir}/${e.name}`;
      if (e.isDirectory() && !e.name.startsWith('.')) walk(p);
      else if (e.isFile() && /\.(?:mjs|js)$/.test(p) && !auditExempt.has(p))
        // Dispatch-surface parity: a handler keying on req.url, the parsed
        // pathname, request headers or a server factory is an unaudited
        // HTTP surface even when it never reads req.method — and a
        // .js-suffixed file is no safer than .mjs (w53-fv M-4, w53-ledger
        // HIGH-3).
        if (/req\.method|req\.url|url\.pathname|req\.headers|createServer\s*\(/.test(readFileSync(p, 'utf8'))) { console.error(`route-spec parity: HTTP dispatch surface in ${p} — outside the audited file`); failed = true; }
    }
  };
  walk('src'); walk('scripts'); walk('web');
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

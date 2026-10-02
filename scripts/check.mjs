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
  ['dynamic eval', new RegExp(`\\beval\\s*\\(|new\\s+Function\\s*\\(|eval\\s*\\/\\*\\*\\/\\s*\\(|\\bFunction\\s*\\(|Reflect\\.apply\\s*\\(\\s*eval|node:${'v'}m`)],
  ['string-timed code', /\bset(?:Timeout|Interval)\s*\(\s*['"`]/],
  ['embedded private key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['cloud credential pattern', /\bAKIA[0-9A-Z]{16}\b/]
];
// The marker words are split so this scanner does not flag its own source.
const MARKER_RULES = [
  ['unfinished code marker', new RegExp(`\\b(?:${'TO' + 'DO'}|${'FIX' + 'ME'})\\b`)]
];
// DOM-injection sinks only matter in code that renders — production sources
// and the console, INCLUDING static .html assets whose markup could carry a
// live sink (w31-ledger F7). Tests legitimately contain these strings
// inside regexes that assert their absence.
const RENDER_ONLY = [
  ['DOM injection', /\.(?:innerHTML|outerHTML)\s*(?:=|\+=)|insertAdjacentHTML|document\.write\s*\(/]
];
for (const file of textFiles) {
  if (file === 'vectors/keys.json' || !existsSync(file) || isBinary(file)) continue;
  const s = readFileSync(file, 'utf8');
  const rules = [...(SINK_EXT.test(file) ? SINK_RULES : []), ...((file.startsWith('src/') || file.startsWith('web/')) ? RENDER_ONLY : []), ...MARKER_RULES];
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
      rows.push({ path, method, roles: m[1].split(',').map(s => s.trim()) });
    }
  }
  const NONROLE = new Set(['bound subject', 'token holder', 'authenticated', 'unauthenticated']);
  const sortR = r => [...r].sort().join(',');
  const isIf = l => /^\s*if \(/.test(l);
  const authorizeAt = (lines, from, depth = 6) => {
    for (let i = from; i < Math.min(from + depth, lines.length); i++) {
      if (i !== from && isIf(lines[i])) break;
      const m = /authorize\(p,\s*\[([^\]]+)\]/.exec(lines[i]);
      if (m) return m[1].split(',').map(s => s.trim().replace(/['"]/g, ''));
    }
    return null;
  };
  const fabricRoles = name => {
    const idx = fabric.findIndex(l => new RegExp(`^\\s{2}(async )?${name}\\(`).test(l));
    if (idx === -1) return null;
    for (let i = idx; i < Math.min(idx + 140, fabric.length); i++) {
      if (i !== idx && /^\s{2}(async )?[a-zA-Z_]+\(/.test(fabric[i])) break;
      const m = /this\.authorize\(p,\s*\[([^\]]+)\]/.exec(fabric[i]);
      if (m) return m[1].split(',').map(s => s.trim().replace(/['"]/g, ''));
      const r = /roles\?*\.includes\('([^']+)'\)/.exec(fabric[i]);
      if (r && /requireThat/.test(fabric[i])) return [r[1]];
    }
    return null;
  };
  for (const r of rows) {
    if (r.roles.length === 1 && NONROLE.has(r.roles[0])) continue;
    const segs = r.path.split('/').filter(Boolean);
    const staticSegs = segs.filter(s => !s.startsWith('{'));
    const param = r.path.includes('{');
    const hi = server.findIndex(l =>
      isIf(l) && l.includes(`req.method === '${r.method.toUpperCase()}'`) &&
      (l.includes(`path === '${r.path}'`) || (param && /\^\\\//.test(l) && staticSegs.every(s => l.includes(s)))));
    let code = null;
    if (hi !== -1) {
      code = authorizeAt(server, hi);
      if (!code) {
        for (let i = hi; i < Math.min(hi + 8, server.length); i++) {
          if (i !== hi && isIf(server[i]) && !/m\[2\]/.test(server[i])) break;
          const verb = segs[segs.length - 1];
          if (param && !verb.startsWith('{') && !server[i].includes(verb)) continue;
          const names = [...server[i].matchAll(/fabric\.([a-zA-Z_]+)\(p[\s,)]/g)].map(x => x[1]);
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
console.log(JSON.stringify({ syntax_files: files.length, syntax_and_focused_source_checks: !failed, security_certification: false }));
if (failed) process.exitCode = 1;

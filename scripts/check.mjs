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
const SKIP = new Set(['node_modules', '.git', 'var']);
const CODE_EXT = /\.(mjs|js|cjs)$/;
const ANY_EXT = /\.(mjs|js|cjs|ts)$/;
let files = [];
const tracked = spawnSync('git', ['ls-files', '-z'], { encoding: 'utf8' });
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
for (const file of files.filter(f => CODE_EXT.test(f) && existsSync(f))) {
  const check = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (check.status !== 0) { console.error(check.stderr); failed = true; }
}

// Secrets, code-injection sinks and unfinished markers are forbidden in any
// committed code — tests and scripts get the same scrutiny as src/ (H4).
const ANYWHERE = [
  ['dynamic eval', new RegExp(`\\beval\\s*\\(|new\\s+Function\\s*\\(|eval\\s*\\/\\*\\*\\/\\s*\\(|\\bFunction\\s*\\(|Reflect\\.apply\\s*\\(\\s*eval|node:${'v'}m`)],
  ['string-timed code', /\bset(?:Timeout|Interval)\s*\(\s*['"`]/],
  ['embedded private key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['cloud credential pattern', /\bAKIA[0-9A-Z]{16}\b/],
  // The marker words are split so this scanner does not flag its own source.
  ['unfinished code marker', new RegExp(`\\b(?:${'TO' + 'DO'}|${'FIX' + 'ME'})\\b`)]
];
// DOM-injection sinks only matter in code that renders — production sources
// and the console. Tests legitimately contain these strings inside regexes
// that assert their absence.
const RENDER_ONLY = [
  ['DOM injection', /\.(?:innerHTML|outerHTML)\s*(?:=|\+=)|insertAdjacentHTML|document\.write\s*\(/]
];
for (const file of files) {
  if (!existsSync(file)) continue;
  const s = readFileSync(file, 'utf8');
  const rules = (file.startsWith('src/') || file.startsWith('web/')) ? [...ANYWHERE, ...RENDER_ONLY] : ANYWHERE;
  for (const [name, regex] of rules) if (regex.test(s)) { console.error(`${file}: ${name}`); failed = true; }
}

// MANIFEST.sha256 must describe exactly the tracked tree — silent drift fails.
const mf = spawnSync(process.execPath, ['scripts/manifest.mjs', '--verify'], { encoding: 'utf8' });
if (mf.status !== 0) { console.error(mf.stderr || mf.stdout); failed = true; }
console.log(JSON.stringify({ syntax_files: files.length, syntax_and_focused_source_checks: !failed, security_certification: false }));
if (failed) process.exitCode = 1;

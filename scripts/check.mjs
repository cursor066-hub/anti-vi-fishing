import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
const files = [];
function walk(dir) { for (const entry of readdirSync(dir, { withFileTypes: true })) { const p = join(dir, entry.name); if (entry.isDirectory()) walk(p); else if (/\.(mjs|js)$/.test(p)) files.push(p); } }
for (const dir of ['src', 'web', 'scripts', 'tests']) walk(dir);
let failed = false;
for (const file of files) { const check = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' }); if (check.status !== 0) { console.error(check.stderr); failed = true; } }
for (const file of files.filter(p => p.startsWith('src/') || p.startsWith('web/'))) {
  const s = readFileSync(file, 'utf8');
  for (const [name, regex] of [['dynamic eval', /\beval\s*\(/], ['DOM injection', /\.innerHTML\s*=/], ['embedded private key', /-----BEGIN (?:PRIVATE|RSA PRIVATE) KEY-----/], ['unfinished code marker', /\b(?:TODO|FIXME)\b/]]) if (regex.test(s)) { console.error(`${file}: ${name}`); failed = true; }
}
console.log(JSON.stringify({ syntax_files: files.length, syntax_and_focused_source_checks: !failed, security_certification: false })); if (failed) process.exitCode = 1;

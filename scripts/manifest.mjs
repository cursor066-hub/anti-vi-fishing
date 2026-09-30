// Regenerates MANIFEST.sha256 (or verifies it with --verify). The manifest
// is a sha256sum-style inventory of the shipped file set; check.mjs fails
// when it drifts from the working tree so it can never rot silently.
import { readdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';

// Anchor at the repository root — run from a subdirectory and the manifest
// would describe only that subtree (w8-tooling F3).
process.chdir(new URL('..', import.meta.url).pathname);

const EXCLUDE_DIRS = new Set(['node_modules', '.git', 'var', '.devin-files']);
const EXCLUDE_FILES = new Set(['MANIFEST.sha256']);
function* walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) { if (!EXCLUDE_DIRS.has(entry.name)) yield* walk(p); }
    else if (entry.isFile() && !EXCLUDE_FILES.has(entry.name)) yield p;
  }
}
// Only tracked files enter the manifest — generated/var state stays out.
const tracked = spawnSync('git', ['ls-files', '-z'], { encoding: 'utf8' });
// The manifest never lists itself: its own hash would make it permanently stale.
const files = (tracked.status === 0 ? tracked.stdout.split('\0').filter(Boolean) : [...walk('.')].map(p => relative('.', p)))
  .filter(f => !EXCLUDE_FILES.has(f)).sort();
const lines = files.map(f => `${createHash('sha256').update(readFileSync(f)).digest('hex')}  ${f}`);
const out = lines.join('\n') + '\n';
if (process.argv.includes('--verify')) {
  const current = existsSync('MANIFEST.sha256') ? readFileSync('MANIFEST.sha256', 'utf8') : '';
  if (current !== out) { console.error('MANIFEST.sha256 is stale — run `node scripts/manifest.mjs` and commit the result.'); process.exitCode = 1; }
  else console.log(JSON.stringify({ manifest_files: files.length, manifest_fresh: true }));
} else {
  writeFileSync('MANIFEST.sha256', out);
  console.log(JSON.stringify({ manifest_files: files.length, written: true }));
}

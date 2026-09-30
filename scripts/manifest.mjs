// Regenerates MANIFEST.sha256 (or verifies it with --verify). The manifest
// is a sha256sum-style inventory of the shipped file set; check.mjs fails
// when it drifts from the working tree so it can never rot silently.
//
// --verify does REAL per-file verification, not manifest-byte comparison:
// every listed file is re-hashed, missing/extra files and symlinked entries
// are failures. In a git tree the enumeration is `git ls-files` (same source
// as generation); in an exported tarball the manifest is the enumeration
// and any file outside the ignore set that is not listed is an extra.
import { readdirSync, readFileSync, writeFileSync, existsSync, lstatSync } from 'node:fs';
import { join, relative } from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';

// Anchor at the repository root — run from a subdirectory and the manifest
// would describe only that subtree (w8-tooling F3).
process.chdir(new URL('..', import.meta.url).pathname);

// Tarball-verify walks every file except the Git object store and installed
// dependencies: a release tree containing runtime state or session files IS
// an anomaly and must flag, not exempt (w11-supply SC-02).
const EXCLUDE_DIRS = new Set(['node_modules', '.git']);
// Git-mode untracked scan exempts the runtime dirs that legitimately hold
// state on a development checkout — but no .gitignore consultation, so a
// broadened ignore rule cannot hide a payload (w11-supply SC-02).
const GIT_MODE_EXEMPT = new Set(['node_modules', '.git', 'var', '.devin-files']);
const EXCLUDE_FILES = new Set(['MANIFEST.sha256']);
const sha = f => createHash('sha256').update(readFileSync(f)).digest('hex');
function* walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) { if (!EXCLUDE_DIRS.has(entry.name)) yield* walk(p); }
    else if ((entry.isFile() || entry.isSymbolicLink()) && !EXCLUDE_FILES.has(entry.name)) yield p;
  }
}

const gitFiles = () => {
  const t = spawnSync('git', ['ls-files', '-z'], { encoding: 'utf8' });
  return t.status === 0 ? t.stdout.split('\0').filter(Boolean) : null;
};

if (process.argv.includes('--verify')) {
  if (!existsSync('MANIFEST.sha256')) { console.error('MANIFEST.sha256 missing'); process.exit(1); }
  const listed = readFileSync('MANIFEST.sha256', 'utf8').trim().split('\n').filter(Boolean)
    .map(line => { const [hash, ...rest] = line.split('  '); return { hash, name: rest.join('  ') }; });
  const names = new Set(listed.map(l => l.name));
  const problems = [];
  for (const { hash, name } of listed) {
    if (!existsSync(name)) { problems.push(`missing: ${name}`); continue; }
    if (lstatSync(name).isSymbolicLink()) { problems.push(`symlinked: ${name}`); continue; }
    if (sha(name) !== hash) problems.push(`tampered: ${name}`);
  }
  // The invariant is set equality in BOTH directions: every tracked file is
  // listed AND every listed file is tracked/present. A committed file absent
  // from the manifest is a stowaway that ships inside git-archive releases
  // un-hashed (w11-supply SC-01).
  const tracked = gitFiles();
  let extras = [];
  if (tracked !== null) {
    for (const f of tracked) if (!names.has(f) && !EXCLUDE_FILES.has(f)) problems.push(`unlisted tracked file: ${f}`);
    // Untracked files are unexpected regardless of .gitignore — ignored
    // runtime dirs are exempt, but no ignore-rule consultation (w11-supply
    // SC-02). MANIFEST.sha256 itself may be untracked in a fresh checkout —
    // it is the verifier's own artifact, not payload.
    const untracked = spawnSync('git', ['ls-files', '--others', '-z'], { encoding: 'utf8' });
    if (untracked.status === 0) extras = untracked.stdout.split('\0').filter(f => f && !EXCLUDE_FILES.has(f) && !GIT_MODE_EXEMPT.has(f.split('/')[0]));
  } else {
    extras = [...walk('.')].map(p => relative('.', p)).filter(f => !names.has(f));
  }
  for (const e of extras) problems.push(`unexpected file: ${e}`);
  if (problems.length) { console.error(JSON.stringify({ manifest_fresh: false, problems })); process.exit(1); }
  console.log(JSON.stringify({ manifest_files: listed.length, manifest_fresh: true }));
  process.exit(0);
}

// Generation requires git — a manifest produced over an arbitrary on-disk
// walk cannot be compared against the committed tracked-file inventory and
// would silently certify whatever happens to be present (supply-chain L4).
const tracked = gitFiles();
if (tracked === null) { console.error('git ls-files unavailable — cannot enumerate the tracked file set'); process.exit(1); }
const files = tracked.filter(f => !EXCLUDE_FILES.has(f)).sort();
const problems = [];
const lines = files.map(f => {
  if (lstatSync(f).isSymbolicLink()) { problems.push(`symlinked: ${f}`); return null; }
  return `${sha(f)}  ${f}`;
});
if (problems.length) { console.error(JSON.stringify({ problems })); process.exit(1); }
writeFileSync('MANIFEST.sha256', lines.join('\n') + '\n');
console.log(JSON.stringify({ manifest_files: files.length, written: true }));

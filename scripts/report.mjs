// Regenerates every committed report artifact from LIVE data so a stale
// claim can never ship under green CI (release-audit H1, docs-audit M9,
// partial-audit C1). Runs the real suites — this is a generation step, so
// it takes about a minute. CI diffs its outputs against the committed tree.
import { spawnSync } from 'node:child_process';
import { writeFileSync, readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const now = new Date().toISOString();
// --check-only verifies committed reports match a fresh regeneration
// without writing — the read-only sibling of this generator
// (w8-tooling F10).
const checkOnly = process.argv.includes('--check-only');
const stale = [];
const run = (cmd, args, opts = {}) => spawnSync(cmd, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...opts });
const write = (path, content) => {
  if (checkOnly) { if (!existsSync(path) || readFileSync(path, 'utf8') !== content) stale.push(path); return; }
  writeFileSync(path, content);
};

// ---- 1. Full test suite → tests.tap / final-regression.tap + summaries ----
const tap = run(process.execPath, ['--test', '--test-concurrency=1', '--test-reporter=tap', 'tests/**/*.test.mjs']);
const tapText = (tap.stdout ?? '') + (tap.stderr ?? '');
// Strip per-test durations so the committed TAP is byte-stable.
const stableTap = tapText.replace(/ \([\d.]+ms\)/g, '').replace(/(duration_ms: )[\d.]+/g, '$10').replace(/(# duration_ms )[\d.]+/g, '$10');
const num = (re, s) => { const m = s.match(re); return m ? Number(m[1]) : 0; };
const counts = { pass: num(/# pass (\d+)/, tapText), fail: num(/# fail (\d+)/, tapText) + (tapText.match(/^not ok /gm) ?? []).length };
write('reports/tests.tap', stableTap);
write('reports/final-regression.tap', stableTap);
const testSummary = { tests: counts.pass + counts.fail, pass: counts.pass, fail: counts.fail, runner: 'node --test --test-reporter=tap tests/', generated_at: 'regenerated on demand by scripts/report.mjs', note: 'Live counts; per-test durations are stripped so the artifact is deterministic.' };
write('reports/test-summary.json', JSON.stringify(testSummary, null, 2) + '\n');
write('reports/final-regression-summary.json', JSON.stringify({ ...testSummary, scope: 'final regression baseline' }, null, 2) + '\n');

// ---- 2. Verifier outputs ----
const nodeVerify = run(process.execPath, ['scripts/verify-export.mjs', 'reports/sample-audit.json', 'reports/sample-pinned-trust.json']);
write('reports/verification-node.json', JSON.stringify({ verifier: 'scripts/verify-export.mjs (node:crypto)', exit: nodeVerify.status, output: (nodeVerify.stdout ?? '').trim() }, null, 2) + '\n');
const bun = run('bun', ['scripts/verify-export-webcrypto.mjs', 'reports/sample-audit.json', 'reports/sample-pinned-trust.json']);
if (bun.error || bun.status === null) write('reports/verification-webcrypto.json', JSON.stringify({ verifier: 'scripts/verify-export-webcrypto.mjs (bun WebCrypto)', exit: null, output: 'bun not installed on this machine — verifier not run' }, null, 2) + '\n');
else write('reports/verification-webcrypto.json', JSON.stringify({ verifier: 'scripts/verify-export-webcrypto.mjs (bun WebCrypto)', exit: bun.status, output: (bun.stdout ?? '').trim() }, null, 2) + '\n');
const py = run('python3', ['scripts/verify-vectors.py']);
write('reports/verification-python.json', JSON.stringify({ verifier: 'scripts/verify-vectors.py (Python cryptography)', exit: py.status, output: (py.stdout ?? '').trim() }, null, 2) + '\n');

// ---- 3. Static checks + production gate ----
const check = run(process.execPath, ['scripts/check.mjs']);
const checkOut = (check.stdout ?? '').trim().split('\n').at(-1);
write('reports/source-check.json', checkOut + '\n');
write('reports/artifact-audit.json', JSON.stringify({ check_exit: check.status, report: JSON.parse(checkOut), generated_at: 'scripts/report.mjs' }, null, 2) + '\n');
const gate = run(process.execPath, ['scripts/release-check.mjs']);
write('reports/production-gate.json', JSON.stringify({ verifier: 'scripts/release-check.mjs', exit: gate.status, expected_exit: 1, output: (gate.stdout ?? '').trim() }, null, 2) + '\n');

// ---- 4. Code inventory (the documented TCB) ----
const inventory = {};
const walk = (dir, prefix) => {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, prefix);
    else if (/\.(mjs|js|py|sh)$/.test(e.name)) {
      const s = readFileSync(p, 'utf8');
      inventory[p] = { lines: s.split('\n').length, bytes: statSync(p).size };
    }
  }
};
walk('src'); walk('web'); walk('scripts'); walk('tests');
write('reports/code-inventory.json', JSON.stringify({ generated_by: 'scripts/report.mjs', files: inventory, total_files: Object.keys(inventory).length, total_lines: Object.values(inventory).reduce((a, f) => a + f.lines, 0) }, null, 2) + '\n');

// ---- 5. SBOM — application AND the verification toolchain that proves it ----
const sbom = {
  bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: 'urn:uuid:00000000-0000-0000-0000-000000000000', version: 1,
  metadata: { timestamp: 'regenerated by scripts/report.mjs (deterministic)', tools: [{ name: 'scripts/report.mjs' }], component: { name: 'invariant-fabric', version: '0.1.0-engineering.1', type: 'application' } },
  components: [
    { type: 'library', name: 'node', version: process.version, scope: 'required' },
    ...Object.entries(process.versions).filter(([k]) => ['openssl', 'sqlite', 'v8', 'zlib', 'icu', 'napi'].includes(k)).map(([name, version]) => ({ type: 'library', name, version, scope: 'required', description: 'node vendored component' })),
    { type: 'application', name: 'bun', version: '1.3.14+', scope: 'required', description: 'verification toolchain: independent WebCrypto verifier' },
    { type: 'application', name: 'python', version: '3.12', scope: 'required', description: 'verification toolchain: independent canonicalizer + cryptography' },
    { type: 'library', name: 'cryptography', version: '46.0.7', scope: 'required', description: 'verification toolchain: pinned in CI' },
    { type: 'application', name: 'github-actions', version: 'checkout@v4;setup-bun@v2;setup-python@v5;setup-node@v4;upload-artifact@v4', scope: 'required', description: 'CI actions (tag-pinned)' }
  ],
  dependencies: [], externalReferences: [], properties: [{ name: 'third-party-application-dependencies', value: 'none (runtime); verification toolchain listed above' }]
};
write('reports/sbom.cdx.json', JSON.stringify(sbom, null, 2) + '\n');

// ---- 6. VERIFICATION.md + summary from the live ledger ----
run('python3', ['scripts/traceability.py']);
const ledgerSummary = existsSync('reports/requirements-summary.json') ? JSON.parse(readFileSync('reports/requirements-summary.json', 'utf8')) : null;
const statusCounts = ledgerSummary?.status_counts ?? {}, total = ledgerSummary?.total_requirements ?? 0;
const sims = existsSync('reports/simulation-results.json') ? JSON.parse(readFileSync('reports/simulation-results.json', 'utf8')).scenarios?.length : null;
const verification = {
  generated_by: 'scripts/report.mjs',
  engineering_checks: tap.status === 0 ? 'PASS' : 'FAIL',
  production_release: 'BLOCKED (expected)',
  unique_test_cases_executed: counts.pass,
  failed: counts.fail,
  scenarios_run: sims,
  requirement_status_counts: statusCounts,
  ledger_total: total
};
write('reports/verification-summary.json', JSON.stringify(verification, null, 2) + '\n');
write('reports/VERIFICATION.md', `# Verification report

## Executed evidence

**${counts.pass} automated test cases passed, ${counts.fail} failed** (node --test over tests/). TAP output in reports/tests.tap.

**${sims ?? 'N/A'} simulation scenarios** run by scripts/simulate.mjs (reports/simulation-results.json).

## Requirement ledger (generated, not hand-maintained)

| Status | Count |
|---|---|
${Object.entries(statusCounts).map(([k, v]) => `| ${k} | ${v} |`).join('\n')}

VERIFIED_IN_ENGINEERING_PROFILE means directly exercised in the declared engineering profile only — not closure of external/production acceptance. The production gate is expected BLOCKED: ${JSON.stringify(JSON.parse(readFileSync('reports/production-gate.json', 'utf8')).exit)} is the observed exit code (1 = blocked by named items).

Independent verification: node:crypto export verifier, WebCrypto/bun export verifier, Python cryptography vector verifier — see reports/verification-*.json.
`);
console.log(JSON.stringify(checkOnly ? { check_only: true, stale } : { regenerated: true, tests: counts, sims, ledger: statusCounts }));
if (stale.length) { console.error(`stale committed reports: ${stale.join(', ')} — run node scripts/report.mjs and commit`); process.exitCode = 1; }
if (counts.fail > 0 || tap.status !== 0) process.exitCode = 1;

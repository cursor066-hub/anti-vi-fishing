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
const staleDetail = [];
const run = (cmd, args, opts = {}) => spawnSync(cmd, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...opts });
const write = (path, content) => {
  if (checkOnly) {
    const committed = existsSync(path) ? readFileSync(path, 'utf8') : null;
    if (committed !== content) {
      stale.push(path);
      // First-differing-line context: a name without the diff is unfixable
      // when the divergence only reproduces in CI's environment (w22 CI).
      if (committed !== null) {
        const a = committed.split('\n'), b = content.split('\n');
        const i = a.findIndex((l, n) => l !== b[n]);
        staleDetail.push({ path, line: i + 1, committed: a.slice(Math.max(0, i - 1), i + 2), regenerated: b.slice(Math.max(0, i - 1), i + 2) });
      }
    }
    return;
  }
  writeFileSync(path, content);
};

// ---- 1. Full test suite → tests.tap / final-regression.tap + summaries ----
// Explicitly sort the test file list: --test's own glob expansion follows
// readdir order, which differs across filesystems and made committed
// tests.tap byte-unstable (w22 CI). Byte-order compare, NOT localeCompare —
// collation rules are locale-sensitive and diverge between dev machines
// and the CI image (w22 CI).
const testFiles = [];
const collectTests = (dir) => {
  for (const e of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
    const p = join(dir, e.name);
    if (e.isDirectory()) collectTests(p); else if (e.name.endsWith('.test.mjs')) testFiles.push(p);
  }
};
collectTests('tests');
const tap = run(process.execPath, ['--test', '--test-concurrency=1', '--test-reporter=tap', ...testFiles]);
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
// Verifiers run against the PINNED committed bundle — sample-*.json churns
// on every simulate run (fresh keys), so checking verifier output against it
// can never be byte-stable (w8-tooling F10 follow-up).
const nodeVerify = run(process.execPath, ['scripts/verify-export.mjs', 'reports/sample-audit.pinned.json', 'reports/sample-pinned-trust.pinned.json']);
write('reports/verification-node.json', JSON.stringify({ verifier: 'scripts/verify-export.mjs (node:crypto)', exit: nodeVerify.status, output: (nodeVerify.stdout ?? '').trim() }, null, 2) + '\n');
const bun = run('bun', ['scripts/verify-export-webcrypto.mjs', 'reports/sample-audit.pinned.json', 'reports/sample-pinned-trust.pinned.json']);
// verification-webcrypto.json is volatile evidence (see the source-check
// note below): its output depends on whether bun exists in this
// environment, so byte-equality across machines can never hold. The
// verifier itself is proven by the live bun step in CI (w20 CI gate).
const bunReport = { verifier: 'scripts/verify-export-webcrypto.mjs (bun WebCrypto)', exit: (bun.error || bun.status === null) ? null : bun.status, output: (bun.error || bun.status === null) ? 'bun not installed on this machine — verifier not run' : (bun.stdout ?? '').trim() };
const py = run('python3', ['scripts/verify-vectors.py']);
write('reports/verification-python.json', JSON.stringify({ verifier: 'scripts/verify-vectors.py (Python cryptography)', exit: py.status, output: (py.stdout ?? '').trim() }, null, 2) + '\n');

// ---- 3. Static checks + production gate ----
// source-check/artifact-audit snapshot a LIVE gate: check.mjs verifies
// MANIFEST.sha256 against the working tree, so its exit code is honestly
// environment-dependent — a clean checkout yields 0, a CI runner (already
// churned by conformance vector regeneration and simulate's tracked
// report writes) yields 1. Neither value is byte-stable, so these are
// volatile evidence like reports/benchmark.json: regenerated for the
// evidence upload, never compared for staleness. The gate itself is
// proven by the live `node scripts/check.mjs` CI step (w8-composite CI).
const writeVolatile = (path, content) => { if (!checkOnly) writeFileSync(path, content); };
const check = run(process.execPath, ['scripts/check.mjs']);
const checkOut = (check.stdout ?? '').trim().split('\n').at(-1);
// Volatile artifacts carry their provenance explicitly: which commit and
// which cleanliness state they describe — a snapshot that cannot be checked
// for freshness must at least be honest about what it saw (w11-supply SC-08).
const treeState = () => {
  const head = run('git', ['rev-parse', 'HEAD']);
  const status = run('git', ['status', '--porcelain']);
  return { commit: head.status === 0 ? head.stdout.trim() : null, clean: status.status === 0 ? !status.stdout.trim() : null };
};
const described = treeState();
const volatileReport = (report) => JSON.stringify({ described_tree: described, note: 'volatile evidence: describes the tree at generation time — freshness is proven by the live CI step, not by this snapshot (w11-supply SC-08)', report }, null, 2) + '\n';
writeVolatile('reports/source-check.json', volatileReport(JSON.parse(checkOut)));
writeVolatile('reports/artifact-audit.json', volatileReport({ check_exit: check.status, report: JSON.parse(checkOut) }));
writeVolatile('reports/verification-webcrypto.json', volatileReport(bunReport));
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
    // Enumerate every vendored component the runtime reports — a 6-name
    // allowlist hid undici/nghttp2/llhttp/uv/c-ares, the highest-CVE-density
    // parts of the Node binary (supply-chain H4). Empty versions (ngtcp2/
    // nghttp3 build off) are recorded honestly.
    ...Object.entries(process.versions).filter(([k]) => !['node', 'modules'].includes(k)).map(([name, version]) => ({ type: 'library', name, version: version || 'not built', scope: 'required', description: 'node vendored component' })),
    { type: 'application', name: 'bun', version: '1.3.14', scope: 'required', description: 'verification toolchain: independent WebCrypto verifier (exact CI pin)' },
    { type: 'application', name: 'python', version: '3.12', scope: 'required', description: 'verification toolchain: independent canonicalizer + cryptography' },
    { type: 'library', name: 'cryptography', version: '46.0.7', scope: 'required', description: 'verification toolchain: pinned in CI' },
    { type: 'application', name: 'github-actions', version: 'checkout@11d5960a;setup-bun@0c5077e5;setup-python@a26af69b;setup-node@49933ea5;upload-artifact@ea165f8d', scope: 'required', description: 'CI actions (SHA-pinned)' }
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
const tapFailNames = (tapText.match(/^not ok \d+ [^\n]*/gm) ?? []).slice(0, 25);
console.log(JSON.stringify(checkOnly ? { check_only: true, stale, stale_detail: staleDetail, tests: counts, tap_status: tap.status, tap_signal: tap.signal ?? null, tap_error: tap.error?.message ?? null, tap_failures: tapFailNames } : { regenerated: true, tests: counts, sims, ledger: statusCounts }));
if (stale.length) { console.error(`stale committed reports: ${stale.join(', ')} — run node scripts/report.mjs and commit`); process.exitCode = 1; }
if (counts.fail > 0 || tap.status !== 0) process.exitCode = 1;

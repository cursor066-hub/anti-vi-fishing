#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
command -v node >/dev/null
command -v bun >/dev/null || { printf '%s\n' 'Full verification requires Bun 1.3.14 for the independent verifier. No packages will be installed.' >&2; exit 2; }
command -v python3 >/dev/null
python3 -c 'import cryptography' 2>/dev/null || { printf '%s\n' "python3 'cryptography' package required (CI pins cryptography==46.0.7)" >&2; exit 2; }
node scripts/check.mjs
# Attestation roundtrip on the clean tree — mirrors CI ordering exactly
# (supply-chain M6): it must precede steps that regenerate tracked reports.
node scripts/release-sign.mjs --generate-fixture-key var/relkeys
node scripts/release-sign.mjs --key var/relkeys/release-key.pem --public-key var/relkeys/release-key.pub --out var/release-attestation.json --test-anchors-out var/relkeys/anchors.json
node scripts/verify-release.mjs var/release-attestation.json var/relkeys/anchors.json
node --test --test-concurrency=1 'tests/**/*.test.mjs'
node scripts/simulate.mjs
# Verify the committed vector set before regeneration (same ordering as CI).
python3 scripts/verify-vectors.py
node scripts/verify-vectors-webcrypto.mjs
node scripts/verify-export.mjs reports/sample-audit.json reports/sample-pinned-trust.json
bun scripts/verify-export-webcrypto.mjs reports/sample-audit.json reports/sample-pinned-trust.json
python3 scripts/canonical-vectors.py examples/canonical-vectors.json
npm run conformance
node scripts/benchmark.mjs --assert
node scripts/ai-eval.mjs
python3 scripts/traceability.py
node scripts/generate-contracts.mjs
# report.mjs --check-only + the same diff gate CI runs — verify.sh must
# FAIL on stale artifacts, never silently rewrite them (supply-chain M6).
node scripts/report.mjs --check-only
git diff --exit-code -- docs/ examples/ ai-eval/ vectors/canonical-vectors.json vectors/envelope-vectors.json vectors/parse-vectors.json vectors/keys.json reports/code-inventory.json reports/sbom.cdx.json reports/requirements-summary.json reports/simulation-results.json reports/VERIFICATION.md reports/verification-summary.json reports/test-summary.json reports/tests.tap reports/final-regression.tap reports/final-regression-summary.json reports/production-gate.json
# The production gate must exit 1 (BLOCKED); any other result is a broken gate.
set +e
node scripts/release-check.mjs
gate=$?
set -e
[ "$gate" -eq 1 ]
printf '%s\n' 'Engineering checks passed. Production acceptance is a separate gate and is expected to remain BLOCKED.'

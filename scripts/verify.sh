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
# IF_TEST_ANCHORS is required for the fixture-key/test-anchors overrides
# and is set ONLY for this test invocation (w11-supply SC-09).
IF_TEST_ANCHORS=1
export IF_TEST_ANCHORS
node scripts/release-sign.mjs --generate-fixture-key var/relkeys
node scripts/release-sign.mjs --key var/relkeys/release-key.pem --public-key var/relkeys/release-key.pub --out var/release-attestation.json --test-anchors-out var/relkeys/anchors.json
# --require-ci binds the attestation to a CI run; the fixture anchors ship
# in-tree so --anchors-in-tree is required for this roundtrip (w15-supply F-2).
REQUIRE_CI=
[ "${CI:-}" = "true" ] && REQUIRE_CI=--require-ci
node scripts/verify-release.mjs var/release-attestation.json var/relkeys/anchors.json $REQUIRE_CI --anchors-in-tree --ack-self-anchors
unset IF_TEST_ANCHORS
# 4-way file concurrency: fixtures are isolated (ephemeral ports, mkdtemp
# stores) — same assertions, shorter wall-clock (parity with report.mjs).
node --test --test-concurrency=4 'tests/**/*.test.mjs'
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
# Mirrors ci.yml exactly: directory-scoped porcelain (untracked `??` rows
# included), same exclusion set, `|| true` so a fully-filtered pipeline
# cannot kill the step under set -e (w15-supply F-6).
node scripts/report.mjs --check-only
# Same SHARED exclusion list and exact-path matching as ci.yml — substring
# filtering swallows 'x.evil' under 'x' (w23-supply F6).
stale="$(git status --porcelain -- docs/ examples/ ai-eval/ vectors/ reports/ | awk 'NR==FNR { if ($0 !~ /^#|^$/) excl[$0]=1; next } { f=$2; if (f != "" && !excl[f]) print }' scripts/stale-excludes.txt - || true)"
if [ -n "$stale" ]; then printf '%s\n' 'stale generated artifacts:' "$stale" >&2; exit 1; fi
# The production gate must exit 1 (BLOCKED); any other result is a broken gate.
set +e
node scripts/release-check.mjs
gate=$?
set -e
[ "$gate" -eq 1 ]
printf '%s\n' 'Engineering checks passed. Production acceptance is a separate gate and is expected to remain BLOCKED.'

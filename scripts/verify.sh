#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
command -v node >/dev/null
command -v bun >/dev/null || { printf '%s\n' 'Full verification requires Bun 1.3.14 for the independent verifier. No packages will be installed.' >&2; exit 2; }
command -v python3 >/dev/null
node scripts/check.mjs
node --test --test-concurrency=1 tests/*.test.mjs
node scripts/simulate.mjs
node scripts/verify-export.mjs reports/sample-audit.json reports/sample-pinned-trust.json
bun scripts/verify-export-webcrypto.mjs reports/sample-audit.json reports/sample-pinned-trust.json
python3 scripts/canonical-vectors.py examples/canonical-vectors.json
printf '%s\n' 'Engineering checks passed. Production acceptance is a separate gate and is expected to remain BLOCKED.'

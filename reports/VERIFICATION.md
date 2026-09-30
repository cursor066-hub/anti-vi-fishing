# Verification report

## Executed evidence

**83 distinct automated test cases passed across the recorded runs.** The full instrumented baseline passed 82/82, with no failures, skips, cancellations or unfinished tests. Final audit found malformed downstream data-output handling that required a tighter schema guard. After that repair, the affected API, concurrency, lifecycle, policy, runtime, audit and adversarial suites passed **76/76**. The unchanged canonicalization suite retains its earlier passing evidence. The final source has 83 test cases.

The independently generated simulation report passed **15/15 scenarios**, including exact finance mutation, replay, direct bypass, lost response after commit, target drift, advisory/email insufficiency, public-exposure denial, scoped reads, destination/column substitution, low-and-slow extraction, quarantine, audit integrity and audit deletion detection.

A clean local bootstrap and actual HTTP process were executed. Health and console returned success; token authentication and an exact synthetic capability read worked; SIGTERM shut down cleanly with no unexpected server error. This was HTTP/process verification, **not a browser screenshot or production deployment**.

The same signed **142-entry synthetic audit chain** passed both the Node verifier and independent Bun/WebCrypto verifier with a pinned public key. Negative tests changed signatures/content/order, removed entries, supplied wrong roots and duplicate JSON keys, and compared conflicting witnesses. Ten Unicode/nested/integer canonical vectors matched an independent Python implementation. Another test exercised 2,000 deterministic generated canonical round trips.

Eight independent worker threads opened separate gate/database connections to race a certificate; exactly one executed. Eight concurrent workers also contended for the final data budget; exactly one read succeeded. Persistence/restart and pre-/post-commit fault cases did not permit blind replay.

## Measured performance

Core deterministic evaluation p95: **0.239 ms**, p99: **0.330 ms**. Local integrated policy evaluation with encrypted SQLite state and signed audit measured approximately **404 evaluations/second** in the microbenchmark.

The local durable signed-audit runtime path measured **2.999 ms p99**, which **does not meet the SRS ≤1 ms target**. This was a warm, single-host synthetic microbenchmark with a virtual policy clock advanced to respect budget/rate limits, not a network-packet, production API-load, capacity or multi-zone test. Default HTTP rate limits are intentionally more restrictive than the module-level throughput measurement.

## Not verified / not completed

Browser rendering, real click journeys, responsive screenshots, WCAG, trusted display/input, WebAuthn, customer HSM/MPC custody, real ERP/bank/database/network integration, public-cloud deployment, multi-zone failover, production DR, independent penetration testing, current dependency advisories, published release provenance and legal/operational acceptance remain unverified or unimplemented. No automated pass substitutes for them.

The full SRS contains 211 numbered requirements. The matrix records 55 verified in the narrow engineering profile, 96 partial, 32 not implemented and 28 externally blocked. These counts are **not a claim of product-completion percentage**. The full product request remains incomplete and production release is deliberately blocked.

## Reproducibility and report provenance

Run the commands in README.md or `scripts/verify.sh` on the documented Node/Bun/Python runtimes. No dependency installation is required for the server. The verification script requires Bun for its independent verifier tests. Test/benchmark fixture data is synthetic; private fixture material was generated temporarily and is excluded from the delivery. File hashes in the archive manifest bind the delivered source and evidence files; they do not provide external signer authenticity.

This report names commands that were actually executed. Instrumented baseline code coverage is retained for transparency, including low UI-handler coverage. It is not presented as browser, end-to-end GUI, fuzz-completeness or ASVS certification.

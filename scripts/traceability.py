#!/usr/bin/env python3
"""Map every numbered SRS requirement, including unimplemented/external gaps.

--check mode: compute the same outputs and report files that differ from the
committed tree as `STALE: <path>` lines, exiting 1 — a verify-only sibling
that never rewrites the tree it is checking (w23-supply F7).
"""
import csv, io, json, re, sys, pathlib, collections, os
root = pathlib.Path(__file__).resolve().parents[1]
check_only = '--check' in sys.argv[1:]
source = (root / 'spec/Invariant_Fabric_SRS_and_System_Architecture.md').read_text()
rows = []
for line in source.splitlines():
    parts = [part.strip() for part in line.split('|')]
    if len(parts) >= 5 and re.fullmatch(r'(?:NFR-)?[A-Z]{2,4}-\d{3}', parts[1]):
        rows.append({'id': parts[1], 'requirement': parts[2], 'minimum_acceptance': parts[3]})
assert len(rows) == 211 and len({r['id'] for r in rows}) == 211
# Hand-maintained per-requirement proof status (w6-ledger S2 — deduped set).
# UX-001 demoted to PARTIAL: approval_threshold floors at >=1 for every rule,
# so 'no additional human approval' is unreachable in this profile. COV-003
# stays PARTIAL: ENFORCED IS reachable via verified technicalValidation
# evidence (fabric.mjs promote path + ledger2 test), but assessor-exportable
# bundles and independently executed rejection tests are still absent.
_verified_ids = '''COV-002 COV-004 COV-007 COV-008 ACT-001 ACT-002 ACT-003 ACT-004 ACT-005 ACT-006 ACT-007 ACT-008 ACT-009 ACT-010 ACT-011 ACT-012 EVD-001 EVD-002 EVD-003 EVD-004 EVD-005 EVD-006 EVD-007 EVD-008 EVD-009 EVD-010 EVD-011 POL-001 POL-002 POL-003 POL-004 POL-005 POL-006 POL-007 POL-008 POL-009 POL-010 POL-011 POL-012 POL-013 POL-014 POL-015 COM-001 COM-002 COM-003 COM-004 COM-005 COM-006 COM-007 COM-008 COM-009 COM-010 COM-011 COM-012 COM-013 COM-014 RUN-001 RUN-002 RUN-003 RUN-004 RUN-005 RUN-006 RUN-007 RUN-008 RUN-009 RUN-010 DAT-001 DAT-002 DAT-003 DAT-004 DAT-005 DAT-006 DAT-007 DAT-008 DAT-009 DAT-010 DAT-011 DAT-012 IDN-001 IDN-002 IDN-003 IDN-004 IDN-005 IDN-006 IDN-007 IDN-008 IDN-009 IDN-010 AUD-001 AUD-002 AUD-003 AUD-004 AUD-005 AUD-006 AUD-007 AUD-008 AUD-009 AUD-010 AIG-001 AIG-002 AIG-003 AIG-004 AIG-005 AIG-006 AIG-007 AIG-008 AIG-009 AIG-010 CON-001 CON-002 CON-003 CON-004 CON-005 CON-006 CON-007 CON-008 CON-009 CON-010 KEY-002 KEY-004 KEY-005 KEY-007 KEY-008 KEY-009 KEY-010 KEY-012 UX-003 UX-005 UX-006 UX-007 UX-008 UX-009 UX-010 PER-006 PER-007 PER-008 PER-009 PER-010 NET-002 NET-003 NET-004 NET-005 NET-006 NET-007 NET-008 NET-009 NET-010 COV-001 COV-005 COV-006 COV-009 NFR-OPS-004 NFR-OPS-005 NFR-SEC-001 NFR-SEC-004 NFR-SEC-005 NFR-SEC-006 NFR-MNT-001 NFR-MNT-002 NFR-MNT-003 NFR-MNT-004 NFR-MNT-005 NFR-AVL-002 NFR-AVL-004 NFR-PERF-001 NFR-PERF-003 NFR-PERF-004 NFR-PRV-005 NFR-USA-004 NFR-TST-001 NFR-TST-002 NFR-TST-003 NFR-TST-004'''.split()
assert len(_verified_ids) == len(set(_verified_ids)), 'verified set must not contain duplicate IDs'
verified = set(_verified_ids)
# w9-srs corrections: KEY-002 (Shamir quorum), NFR-TST-004 (release gate)
# and PER-006 (release-field constraints) are implemented and tested —
# promoted. NFR-SEC-002 overclaimed VERIFIED without an independent
# review artifact — demoted to PARTIAL. NFR-MNT-004 is met by the
# CODEOWNERS policy extended to every security-critical module. w10:
# NFR-SEC-007 gains a real signed-provenance path (release-sign.mjs +
# verify-release.mjs, tested roundtrip) — promoted NOT_IMPLEMENTED to
# PARTIAL; production-grade KMS signing remains external.
not_implemented = set('''NFR-AVL-003 NFR-OPS-003'''.split())
external = set('''PER-001 PER-002 PER-003 PER-004 PER-005 KEY-001 KEY-003 NFR-AVL-001 NFR-PRV-003 NFR-OPS-001 NFR-USA-001 NFR-USA-002 NFR-USA-003 NFR-CMP-001 NFR-CMP-003 NFR-CMP-004'''.split())
# w11-ledger corrections: KEY-006's inventory/transition-plan acceptance is
# a real document (docs/ALGORITHM-AGILITY.md bound to SUITES by test) and
# KEY-011's trusted-component firmware trust is implemented via
# secure_perception.allowed_firmware — both honest PARTIALs, not external.
by_prefix = {
'COV': ('Coverage/integration owner', 'R2', 'src/coverage.mjs; src/fabric.mjs', 'All four coverage labels are representable; actual target discovery, drift agents, independently executed bypass tests and historical guarantee intervals are not established. All manifests suppress production guarantee.'),
'ACT': ('Core security maintainer', 'R0', 'src/canonical.mjs; src/schema.mjs; src/fabric.mjs', 'Typed actions and same-actor certified-children composition are implemented. Cross-actor choreography and independent high-assurance protocol review are not.'),
'EVD': ('Evidence integration owner', 'R1', 'src/fabric.mjs; src/policy.mjs; src/issuerd.mjs', 'Independent signed evidence, issuer daemons and HTTP acquisition are implemented; real authority verification, issuer onboarding governance and external attestable record stores are not.'),
'POL': ('Customer policy governance owner', 'R2', 'src/policy.mjs; src/fabric.mjs', 'Deterministic local constitution, staged deployment via not_before and tightened-threshold emergency policies exist; production staged release infrastructure and protected full lifecycle remain gaps.'),
'COM': ('Gate security maintainer', 'R2', 'src/fabric.mjs; src/target.mjs', 'State/replay/reservation/observed-outcome behavior is tested against a simulator. Real target credential isolation and total mediation are not proven.'),
'RUN': ('Runtime enforcement owner', 'R4', 'src/runtime.mjs', 'Local software decisions, persistent budgets and signed config-snapshot integrity checks are implemented; packet integration, independent remote revocation and local-cache SLA are not established.'),
'DAT': ('Data gate/privacy owner', 'R3', 'src/runtime.mjs; src/target.mjs; src/fabric.mjs; src/datagate.mjs; src/store.mjs', 'Synthetic dataset selection, budgets, watermarking, reconstruction detection and per-record DEK crypto-shredding with WAL truncation are implemented. No real database query rewriting/credential broker; ciphertext surviving in pre-erasure backups is out of scope.'),
'IDN': ('Identity security owner', 'R3', 'src/server.mjs; src/fabric.mjs', 'Local 24-hour tokens, software approvals, quarantine and verified JIT grants are exercised. WebAuthn/federation, real device attestation and brokered service credentials are not integrated; MFA reset/recovery is governance-gated in the engineering profile.'),
'NET': ('Network enforcement owner', 'R4', 'src/runtime.mjs', 'Software envelope decisions only; no kernel, endpoint, switch, proxy, actual packet or network quarantine enforcement.'),
'PER': ('Trusted hardware owner', 'R5', 'src/server.mjs; src/secureview.mjs; docs/SECURITY.md', 'Hardware unavailable. A dev-attested software Secure Perception profile and a policy-gated controlled-workspace fallback exist and are honestly labelled; neither is a trusted display. No hostile-OS extraction or usability demonstration exists.'),
'KEY': ('Independent customer custodians', 'R2/R5', 'src/crypto.mjs; src/keystore.mjs; src/shamir.mjs; src/ceremony.mjs; docs/SECURITY.md', 'Software vault (IF-SOFTHSM-1), rotation, revocation, attestation, dual-suite agility (Ed25519+ES256) and Shamir threshold recovery with enforced delay and per-custodian notice records are implemented. No real HSM/MPC, certified custody, physical OOB channel, or post-quantum suite.'),
'AUD': ('Audit/privacy owner', 'R2', 'src/store.mjs; scripts/verify-export.mjs; scripts/verify-export-webcrypto.mjs', 'Signed local hash chain, cursor-paginated entry access and independently pinned checkpoint verification are implemented. External witness publication, a real analytics pipeline to segregate, and independent operational audit remain gaps.'),
'AIG': ('AI governance owner', 'R2', 'src/policy.mjs; src/advisory.mjs; docs/SECURITY.md', 'A deterministic advisory extractor exists with confidence/provenance marking and zero authority. External model providers, continuous evaluation and provider agreements are not implemented.'),
'CON': ('Target integration owner', 'R2', 'src/target.mjs; src/connectors.mjs; src/issuerd.mjs', 'Controlled SQLite target simulator plus real HTTP evidence issuers with manifest drift revalidation. Real bank/ERP/cloud APIs, least-privilege credentials and support workflow are missing.'),
'UX': ('Frontend/accessibility owner', 'R2', 'web/index.html; web/app.js; web/style.css', 'Full operator console (actions, policy, runtime, keys, ceremonies, connectors, proofs, perception, grants, audit) over the HTTP API exists. Browser rendering, responsive screenshots, Playwright journeys, WCAG and human comprehension studies were unavailable.'),
'NFR-SEC': ('Security/release owner', 'R2', 'docs/SECURITY.md; scripts/release-sign.mjs; scripts/verify-release.mjs; tests/', 'Focused security tests, an adversarial suite, a seeded canonical-JSON fuzz corpus and signed SLSA-lite release provenance (detached envelope + pinned-anchor verification) are implemented; ASVS certification, full SAST/DAST, advisory review, KMS-backed release signing and penetration assessment are not.'),
'NFR-PERF': ('Performance owner', 'R2/R4', 'reports/benchmark.json; scripts/benchmark.mjs', 'Single-host synthetic microbenchmark, not production load/soak evidence. Runtime signed-audit p99 does not meet the 1 ms target; see measured report.'),
'NFR-AVL': ('Platform/SRE owner', 'R2', 'docs/RUNBOOKS.md; scripts/backup.mjs; scripts/restore-check.mjs', 'Engine-native online backup and offline restore-verification tooling are implemented and drilled. No multi-zone deployment, consensus/replication, production availability measurement, SLA or validated RTO/RPO exercise.'),
'NFR-PRV': ('Privacy/legal owner', 'R2', 'docs/SECURITY.md; docs/RUNBOOKS.md', 'Synthetic data/minimisation defaults and logical retention only. Legal basis, DPIA, regional contracts, full deletion and biometric hardware evidence require external review/integration.'),
'NFR-OPS': ('Platform/SRE owner', 'R2', 'docs/RUNBOOKS.md; deploy/', 'Runbook and staging templates are supplied, but no assigned production account, operational staff, incident system or live release/DR exercise exists.'),
'NFR-MNT': ('Maintainer/release owner', 'R2', 'docs/API.md; docs/openapi.json; reports/sbom.cdx.json', 'Versioned engineering API, OpenAPI document and runtime inventory are supplied; human ownership, full dual certificate/policy conformance, lifecycle notices and release process are incomplete.'),
'NFR-USA': ('Product/accessibility researcher', 'R2/R5', 'web/; docs/WORKFLOWS.md', 'No browser, accessibility audit or independent human comprehension/usability study was available.'),
'NFR-CMP': ('Qualified legal/compliance owner', 'R2', 'docs/PRODUCTION-ACCEPTANCE.md; docs/SECURITY.md', 'No certification, legal opinion, executed compliance mapping, disclosure operation or sector/regulatory assessment is claimed.'),
'NFR-TST': ('Independent verification/release owner', 'R2', 'tests/; reports/tests.tap; docs/requirements.csv', 'Synthetic software and adversarial evidence is included; independent red team, real target tests and signed production acceptance remain unclosed.')
}
# Per-row limitation overrides where the shared prefix text understates or
# misframes the actual gap (w39-ledger F4/F8/F9).
_limitation_overrides = {
'UX-001': 'Full operator console exists, but the first-order blocker is in-engine: policy.mjs floors approval_threshold at >=1 per rule (>=3 for custody types) and requires signers >= requiredApprovals, so straight-through (zero-approval) processing is inexpressible in this profile — not merely unevidenced. Browser rendering, responsive screenshots, Playwright journeys, WCAG and human comprehension studies were unavailable.',
'KEY-006': 'The stated acceptance artifact exists — docs/ALGORITHM-AGILITY.md is the inventory mapping each algorithm use to an approved profile and transition plan, bound to SUITES by test. The real residual is that no post-quantum suite is implemented; introducing one is in-repo code work (ML-DSA ships in Node 24 crypto), not an external blocker — the row stays PARTIAL on that honest basis.',
'NFR-CMP-001': 'A self-labelled control-map document is in-repo producible (ASVS-CAPEC-MAP already carries the self-assessed class); only an authoritative, legal-reviewed mapping is external. The named minimum was deliberately deferred until an accountable owner exists.',
'NFR-CMP-003': 'The policy text and internal workflow document are in-repo producible; SECURITY.md deliberately refuses a fictitious reporting contact. The stated minimum was deliberately deferred until an accountable entity exists.',
'NFR-PERF-004': 'VERIFIED conditioned on environment_scale >= 0.9 in the committed benchmark: the live gate scales the asserted floor to the runner (>=40/s), but the row stands as proven only when the artifact also met the absolute 100/s bound — recorded honestly as absolute_requirement_floor_100_ops_met. A regenerated artifact on slower silicon keeps the scaled gate green while reporting the absolute bound unproven.',
}
# Recurse: a nested test file is still evidence — a flat glob would let an
# engineer move a citation into a subdirectory and silently strip the row
# while the suite itself still runs it (w49-ledger F-3).
tests = sorted((root/'tests').glob('**/*.test.mjs'), key=lambda p: p.name) + [root/'scripts/simulate.mjs', root/'scripts/ai-eval.mjs']
# Execution binding: a citing test must have actually RUN — appear as
# `ok N - <title>` without an unfinished-marker suffix in the committed
# TAP report —
# before it can mint VERIFIED evidence (w48-ledger F-1). The evidence is
# the last RECORDED pipeline run: prefer the TAP committed at HEAD —
# a stray or half-written worktree artifact (an interrupted regen left
# a failing TAP) must not poison or be laundered through this check;
# fall back to the working file only when no committed TAP exists yet.
import subprocess as _sp
_tap_text = None
try:
    _r = _sp.run(['git', 'show', 'HEAD:reports/tests.tap'], cwd=root, capture_output=True, text=True)
    if _r.returncode == 0 and _r.stdout.strip(): _tap_text = _r.stdout
except OSError: pass
if _tap_text is None:
    _tap = root / 'reports' / 'tests.tap'
    assert _tap.exists(), 'no TAP evidence at HEAD and no reports/tests.tap — nothing to bind citations against'
    _tap_text = _tap.read_text(errors='replace')
# A `not ok` permanently disqualifies its title — a same-titled `ok`
# elsewhere cannot launder a failing assertion into evidence, and a title
# that never printed is not evidence either (w51-ledger F-1). Indented
# lines are real subtests (t.test) — they count identically (M-7).
_ok_titles, _fail_titles = set(), set()
for _line in _tap_text.splitlines():
    _m = re.match(r'^\s*(ok|not ok)\s+\d+\s+-\s+(.*?)(?:\s+#\s*(?:SKIP|TO' + 'DO)\b.*)?$', _line)
    if _m and not re.search(r'#\s*(?:SKIP|TO' + 'DO)\b', _line):
        (_ok_titles if _m.group(1) == 'ok' else _fail_titles).add(_m.group(2).strip())
_passed_titles = _ok_titles - _fail_titles
# The summary counters must agree with the result lines they claim to
# count — '# fail 0' beside a 'not ok' line is edited evidence, not a
# report (w51-ledger F-1).
_tap_tests = re.search(r'(?m)^# tests (\d+)', _tap_text)
_tap_pass = re.search(r'(?m)^# pass (\d+)', _tap_text)
_tap_fail = re.search(r'(?m)^# fail (\d+)', _tap_text)
assert _tap_tests and _tap_pass is not None and _tap_fail is not None, 'TAP summary counters missing — cannot verify the evidence boundary'
_ok_lines = len(re.findall(r'(?m)^\s*ok\s+\d+\s+-', _tap_text))
_fail_lines = len(re.findall(r'(?m)^\s*not ok\s+\d+\s+-', _tap_text))
assert int(_tap_pass.group(1)) == _ok_lines and int(_tap_fail.group(1)) == _fail_lines and int(_tap_tests.group(1)) == _ok_lines + _fail_lines, \
    f'TAP counters inconsistent: # tests={_tap_tests.group(1)} # pass={_tap_pass.group(1)} # fail={_tap_fail.group(1)} but {_ok_lines} ok / {_fail_lines} not ok lines'
_literal_title_cites = None
def _title_ran(title, rid):
    # An interpolated template title (`RUN-002 DAT-004: ${field} …`) expands
    # to several TAP lines — match each literal segment in order
    # (w48-ledger F-1).
    parts = re.split(r'\$\{[^}]*\}', title.strip())
    if len(parts) == 1: return title.strip() in _passed_titles
    # An interpolation expands to ONE whitespace-free segment — letting
    # `.*` bridge the gap meant `RUN-001 ${x}` fullmatched an unrelated
    # passing test's title and inherited its execution (w56-ledger F5).
    # The one-word gap can still borrow a sacrificial SIBLING title: a
    # matched line that is itself a literal test title is that test's
    # own evidence — credit it here only when it also names this row
    # (w57-fv NEW-4).
    pat = re.compile('[^\\s]*'.join(re.escape(p) for p in parts))
    for t in _passed_titles:
        if not pat.fullmatch(t): continue
        cited = _literal_title_cites.get(t)
        if cited is not None and rid not in cited: continue
        return True
    return False
# A citation must name the requirement inside a real test() block that also
# runs a real assertion CALL EXPRESSION. Comments are stripped first, so an
# ID or the word 'assert' sitting in a comment cannot mint evidence —
# and a bare identifier or string mention is not an assertion either
# (w11-ledger F3, w23-supply F9). Block comments and whole-line //
# comments are removed; `//` inside string literals like 'https://x' is
# left alone by requiring whitespace or line-start before the marker.
def _strip_comments(text):
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    # `//` preceded by : or a word char is inside a string/URL — not a comment.
    # A backslash before `//` means an escaped slash inside a regex literal
    # (e.g. `mongodb:\/\/`), never a comment (w39-ledger F7).
    return re.sub(r'(?m)(?<![:/\w\\])//[^\n]*', '', text)
# Bare tokens (expect/throws/rejects/strictEqual/…) are NOT assert calls —
# a `const expect = () => {}` inside the body shadows them to no-ops while
# still minting evidence (w48-ledger F-1). Only names bound by the suite's
# real imports count, and a body-scope shadow of those names is stripped
# before matching (same finding).
# hasCode is a predicate FACTORY (assert.throws(fn, hasCode('INV-x'))) —
# calling it asserts nothing on its own; the enclosing assert.* call is
# the assertion (w49-ledger F-3).
# A `.`-preceded name is a member call, not the trusted binding —
# `stub.assert(x)` minted a call on the host object while the real
# assert namespace went unexercised (w59-ledger F-12).
_ASSERT_CALL = re.compile(r'(?<![\w$.])(?:assert(?:\.\w+)?|requireThat)\s*\(')
_ASSERT_NAME_SET = ('assert', 'requireThat', 'hasCode', 'expect', 'throws', 'rejects', 'strictEqual', 'deepStrictEqual', 'doesNotThrow')
# Every binding shape that can neuter an assert name: a local decl, a
# bare reassignment, an import from a non-node source, a globalThis
# graft, or a parameter shadow `(assert) =>` (w51-ledger H-1).
_SHADOWED_ASSERT = re.compile(
    r'\b(?:const|let|var|function)\s+(assert|requireThat|hasCode|expect|throws|rejects|strictEqual|deepStrictEqual|doesNotThrow)\b'
    r'|\b(assert|requireThat|hasCode|expect|throws|rejects|strictEqual|deepStrictEqual|doesNotThrow)\s*=(?!=)'
    # `assert.ok &&= noop` / `assert.ok ||= fn` / `assert.equal = stub`
    # replace one METHOD on the real object — the name is still the
    # trusted binding, so only the member-assignment is the shadow
    # (w57-ledger F9). Same arm as bare rebind: neuter the whole vocab.
    r'|\b(assert|requireThat|hasCode|expect|throws|rejects|strictEqual|deepStrictEqual|doesNotThrow)\s*\.\s*\w+\s*(?:&&=|\|\|=|\?\?=|=(?!=))'
    r'|\bimport\s+[^;\n]*?\bfrom\s+[\'"](?!node:)'
    r'|\bglobalThis\s*(?:\.\s*(assert|requireThat|hasCode|expect|throws|rejects|strictEqual|deepStrictEqual|doesNotThrow)\b|\[\s*[\'"](assert|requireThat|hasCode|expect|throws|rejects|strictEqual|deepStrictEqual|doesNotThrow)[\'"])'
    r'|\bObject\.assign\s*\(\s*globalThis\b'
    r'|\bdefineProperty\s*\(\s*globalThis\b'
    r'|\(\s*[^)]*\b(assert|requireThat|hasCode|expect|throws|rejects|strictEqual|deepStrictEqual|doesNotThrow)\b[^)]*\)\s*=>'
    # A classic-function parameter shadows the name for its whole body —
    # `function check(assert) { assert.ok(false) }` calls the parameter,
    # never node:assert; `function* check(assert)` is the same shadow
    # (w54-ledger H-5, w55-ledger H-1).
    r'|\bfunction\s*\*?\s*\w*\s*\([^)]*\b(assert|requireThat|hasCode|expect|throws|rejects|strictEqual|deepStrictEqual|doesNotThrow)\b[^)]*\)'
    # A shorthand-object/class method parameter shadows identically —
    # `{ check(assert) { … } }` binds `assert` for its body without the
    # `function` keyword (w55-ledger H-1).
    r'|(?<![\w$.])(?:async\s+|static\s+|get\s+|set\s+)*[A-Za-z_$][\w$]*\s*\([^)]*\b(assert|requireThat|hasCode|expect|throws|rejects|strictEqual|deepStrictEqual|doesNotThrow)\b[^)]*\)\s*\{'
    # A catch-param or bare for-head binding neuters the name for its
    # whole clause — `try {} catch (assert) { assert(...) }` and
    # `for (assert of x) assert(...)` never call node:assert (w53-fv H-1).
    r'|\bcatch\s*\(\s*(assert|requireThat|hasCode|expect|throws|rejects|strictEqual|deepStrictEqual|doesNotThrow)\s*\)'
    r'|\bfor\s*\(\s*(?:const|let|var\s+)?(assert|requireThat|hasCode|expect|throws|rejects|strictEqual|deepStrictEqual|doesNotThrow)\s+(?:of|in)\b'
    # Destructured shadows neuter the name the same way —
    # `const { assert } = fake` and `for (const [assert] of z)` bind a
    # local that is not node:assert; `class assert {}` does too. The
    # destructure may span lines — `const {\n  assert,\n} = fake` is the
    # same shadow (w54-fixverify M-4, w55-ledger H-1).
    # Only a value-side (or bare) destructure names a bound local:
    # `{k: assert}`/`{assert}` bind `assert`; `{assert: x}` binds `x`
    # and leaves the real assert untouched — the name must be followed
    # by `,`/`}`/`=` to shadow (w60-ledger F-11).
    r'|\b(?:const|let|var)\s*\{[^{}]*?\b(assert|requireThat|hasCode|expect|throws|rejects|strictEqual|deepStrictEqual|doesNotThrow)\s*(?=[,}=]|$)[^{}]*\}\s*='
    r'|\b(?:const|let|var)\s*\[[^\]]*\b(assert|requireThat|hasCode|expect|throws|rejects|strictEqual|deepStrictEqual|doesNotThrow)\b[^\]]*\]\s*='
    r'|\bfor\s*\(\s*(?:const|let|var)\s+[\[{][^\]}]*\b(assert|requireThat|hasCode|expect|throws|rejects|strictEqual|deepStrictEqual|doesNotThrow)\b'
    r'|\bclass\s+(assert|requireThat|hasCode|expect|throws|rejects|strictEqual|deepStrictEqual|doesNotThrow)\b'
    # A member write neuters the called method while the `assert.ok(`
    # token survives — `assert.ok = () => {}`, `assert['ok'] = f` and
    # `Object.assign(assert, {ok(){}})` all mint vacuously otherwise
    # (w56-ledger F1).
    r'|\b(assert|requireThat|hasCode|expect|throws|rejects|strictEqual|deepStrictEqual|doesNotThrow)\s*(?:\.\s*[\w$]+|\[\s*[\'"][\w$]+[\'"]\s*\])\s*=(?!=)'
    r'|\bObject\.(?:assign|definePropert(?:y|ies))\s*\(\s*(assert|requireThat|hasCode|expect|throws|rejects|strictEqual|deepStrictEqual|doesNotThrow)\b'
    # Reflect-mutation spellings neuter identically —
    # `Reflect.set(assert,'ok',noop)`,
    # `Reflect.defineProperty(assert,'ok',{value:noop})` and
    # `Reflect.apply(Object.defineProperty,assert,[…])` each replace a
    # method while the call token survives (w58-ledger F3).
    r'|\bReflect\.(?:set|defineProperty|deleteProperty)\s*\([^)]*\b(assert|requireThat|hasCode|expect|throws|rejects|strictEqual|deepStrictEqual|doesNotThrow)\b'
    r'|\bReflect\.apply\s*\(\s*Object\.(?:definePropert(?:y|ies)|assign)\s*,[^)]*\b(assert|requireThat|hasCode|expect|throws|rejects|strictEqual|deepStrictEqual|doesNotThrow)\b'
    # A destructure without a decl keyword binds in place —
    # `({ assert } = fake)` neuters the name identically to
    # `const { assert } = fake` (w59-ledger F-14).
    r'|\(\s*\{[^}]*\b(assert|requireThat|hasCode|expect|throws|rejects|strictEqual|deepStrictEqual|doesNotThrow)\b[^}]*\}\s*='
    # A computed-member write on a variable index neuters identically —
    # `assert[k] = f` replaces the same methods `assert['ok'] = f` does
    # (w59-ledger F-14).
    r'|\b(assert|requireThat|hasCode|expect|throws|rejects|strictEqual|deepStrictEqual|doesNotThrow)\s*\[\s*[\w$]+\s*\]\s*=(?!=)'
    # eval can rebind any name in scope — a body that evals can call
    # the real assert only inside its own string, and those contents are
    # already masked dead. Neuter the whole vocabulary (w59-ledger F-14).
    r'|\bev' + r'al\s*\('
)
def _bracket_end(s, i):
    # Index just past the bracket matching s[i]; -1 when unbalanced.
    # Input is literal-blanked, so string contents cannot disturb the
    # balance scan.
    want = {'{': '}', '[': ']', '(': ')'}.get(s[i])
    if want is None: return -1
    depth = 0
    for j in range(i, len(s)):
        if s[j] == s[i]: depth += 1
        elif s[j] == want:
            depth -= 1
            if depth == 0: return j + 1
    return -1
def _pattern_bind_names(pat, out):
    # Every name a JS binding pattern binds, walked recursively — a
    # nested `const { x: { assert } }`/`const { x: [assert] }` binds the
    # name exactly like the flat spellings the regex arms already cover
    # (w71-ledger F-2). `k:` names are property keys (not bindings); the
    # value side and bare names bind.
    inner = pat[1:-1]
    for el in _split_top(inner, ',') or [inner]:
        el = el.strip()
        if not el: continue
        if el.startswith('...'): el = el[3:].strip()
        if pat[0] == '{':
            kv = _split_top(el, ':')
            if kv is not None and len(kv) > 1: el = ':'.join(kv[1:]).strip()
        dv = _split_top(el, '=')
        if dv is not None: el = dv[0].strip()
        if not el: continue
        if re.fullmatch(r'[A-Za-z_$][\w$]*', el): out.append(el)
        elif el[:1] in '{[': _pattern_bind_names(el, out)
def _param_bind_names(text, out):
    # Names bound by a param-list content — plain names plus any
    # destructure patterns nested inside (w71-ledger F-2).
    for el in _split_top(text, ',') or [text]:
        el = el.strip()
        if el.startswith('...'): el = el[3:].strip()
        dv = _split_top(el, '=')
        if dv is not None: el = dv[0].strip()
        if not el: continue
        if el[:1] in '{[': _pattern_bind_names(el, out)
        elif re.fullmatch(r'[A-Za-z_$][\w$]*', el): out.append(el)
_PARAM_HEAD_EXCLUDE = re.compile(r'(?:if|for|while|switch|with|return|typeof|new|else|case|in|of|instanceof|void|delete|await|yield|do|import|using|throw|assert|class|function)\s*$')
def _shadow_events(blanked):
    # Shadow events as (pos, kind, names, match_text, span_end): the
    # regex arms plus real balance-walks the flat arms cannot express
    # (w71-ledger F-2) — `const { x: { assert } }`/`{ x: [assert] }`
    # destructures, `for (const {x:{assert}} of …)`, `catch ({…})`, and
    # param positions under computed method names (`{ ['m'](assert) {} }`)
    # or arrows (`({x:{assert}}) => …`). kind 'param' binds inside the
    # FOLLOWING block; kind 'decl' binds inside its enclosing block.
    for m in _SHADOWED_ASSERT.finditer(blanked):
        names = [g for g in m.groups() if g] or list(_ASSERT_NAME_SET)
        txt = m.group(0)
        # Param-headed bindings scope to their own BODY, not the
        # enclosing block (w73-ledger F-7): `function g(assert)`,
        # `check(assert) {`, `catch (assert)`, `for (const assert of x)`
        # each neuter the name only inside the clause they head — an
        # assert before or after the clause calls the real node:assert,
        # and block-wide scoping silently demoted honest rows. A BARE
        # `for (assert of x)` is no binding at all — an assignment to
        # the (import-bound) name that poisons the block from the `for`
        # onward.
        paren = txt.find('(')
        kind = 'decl'
        if paren > 0:
            head = txt[:paren].strip()
            if re.match(r'for\b', head):
                kind = 'param' if re.search(r'\b(?:const|let|var)\b', txt) else 'assign'
            elif re.match(r'catch\b|function\b', head):
                kind = 'param'
            elif txt.rstrip().endswith('{') and re.fullmatch(r'(?:async\s+|static\s+|get\s+|set\s+)*[A-Za-z_$][\w$]*', head):
                kind = 'param'
            if kind == 'param':
                apos = m.start() + paren
                aend = _bracket_end(blanked, apos)
                if aend != -1:
                    yield apos, 'param', names, txt, aend
                    continue
                kind = 'decl'
            if kind == 'assign':
                yield m.start(), 'assign', names, txt, m.end()
                continue
        yield m.start(), kind, names, txt, m.end()
    for m in re.finditer(r'\b(?:const|let|var)\s*[\[{]', blanked):
        e = _bracket_end(blanked, m.end() - 1)
        if e == -1 or not re.match(r'\s*(?:=|of\b|in\b)', blanked[e:]): continue
        out = []
        _pattern_bind_names(blanked[m.end() - 1:e], out)
        hits = [nm for nm in out if nm in _ASSERT_NAME_SET]
        if hits: yield m.start(), 'decl', hits, 'destructure', e
    # Param-position binds: `(` whose closing paren is followed by `{`
    # (function/method/catch bodies) or `=>` (arrow bodies). Control
    # keywords are excluded — `if (x)` evaluates, it never binds.
    for m in re.finditer(r'\(', blanked):
        e = _bracket_end(blanked, m.end() - 1)
        if e == -1: continue
        # `e` sits just past `)`; the body brace / arrow may follow
        # whitespace — `(assert) {`, `()  =>` both bind. An `=>`
        # follower binds UNCONDITIONALLY — `return (x = g(), assert) =>
        # {…}` still binds `assert` even though `return` precedes the
        # head (w72-ledger F-4). Only a `{` follower consults the
        # control-keyword exclusion — `if (x) {` evaluates, never binds.
        nxt = re.match(r'\s*(?:\{)|\s*=>', blanked[e:])
        if nxt is None: continue
        if not nxt.group(0).rstrip().endswith('=>') and _PARAM_HEAD_EXCLUDE.search(blanked[:m.start()].rstrip()): continue
        out = []
        _param_bind_names(blanked[m.end():e - 1], out)
        hits = [nm for nm in out if nm in _ASSERT_NAME_SET]
        if hits: yield m.start(), 'param', hits, 'param-head', e
# The assert namespace itself is import-bound: `import { strict as asrt }`
# or `import * as a` renames it — the probe runs on the resolved local
# names, not a hardcoded 'assert' (w51-ledger M-7). Names are trusted
# only when BOUND from the right source — a file that calls assert.ok
# without a node:assert binding crashes at runtime, and
# `import assert from './stub.mjs'` executes a real no-op, the strongest
# mint of all (w56-ledger F4).
# The repo's own helper names resolve only through repo-relative
# specifiers — the same name from an npm package or an unbound mention
# is a shadow, not the helper.
_REPO_ASSERT_NAMES = {'requireThat', 'hasCode', 'expect', 'throws', 'rejects', 'strictEqual', 'deepStrictEqual', 'doesNotThrow'}
def _import_binds(text):
    # (bound-names, specifier) for static imports, require() and awaited
    # dynamic imports — every way a module-level name can be bound.
    for m in re.finditer(r"\bimport\s+([^;\n]*?)\s+from\s+['\"]([^'\"]+)['\"]", text):
        yield m.group(1), m.group(2)
    for m in re.finditer(r"\b(?:const|let|var)\s+([^;=\n]*?)\s*=\s*(?:await\s+)?(?:require|import)\s*\(\s*['\"]([^'\"]+)['\"]", text):
        yield m.group(1), m.group(2)
def _bound_names(clause):
    bound = set()
    am = re.search(r'\*\s+as\s+(\w+)', clause)
    if am: bound.add(am.group(1))
    clause = re.sub(r'\*\s+as\s+\w+', ' ', clause).replace('{', ' ').replace('}', ' ')
    for spec in clause.split(','):
        spec = spec.strip()
        if not spec: continue
        bound.add(re.split(r'\s+as\s+', spec)[-1].strip())
    return {b for b in bound if re.fullmatch(r'\w+', b)}
def _resolve_spec(from_path, spec):
    base = (from_path.parent / spec).resolve()
    for cand in (base, base.with_suffix('.mjs'), base.with_suffix('.js'), base / 'index.mjs'):
        if cand.is_file(): return cand
    return None
_exports_memo = {}
def _module_assert_exports(mod_path):
    # Which names a repo module actually EXPORTS as real assertors:
    # re-exports of node:assert, or exported definitions whose own body
    # is non-trivial. `export const expect = () => {}` is a no-op stub,
    # not an assertor — importing it minted trusted assert evidence end
    # to end (w57-ledger F1).
    key = str(mod_path)
    if key in _exports_memo: return _exports_memo[key]
    try:
        text = _strip_comments(mod_path.read_text())
    except OSError:
        _exports_memo[key] = set(); return _exports_memo[key]
    out = set()
    # Memoized BEFORE the recursion: a circular re-export chain
    # (a.mjs ⇄ b.mjs) resolves to this in-progress set instead of
    # recursing forever, and the set keeps accumulating as `out`
    # mutates (w58-fv F-6).
    _exports_memo[key] = out
    imported_assert = set()
    for clause, spec in _import_binds(text):
        if spec.startswith('node:assert'):
            imported_assert |= _bound_names(clause)
        elif re.match(r'\.\.?/', spec):
            sub = _resolve_spec(mod_path, spec)
            if sub is not None:
                sub_exports = _module_assert_exports(sub)
                for b in _bound_names(clause):
                    if b in sub_exports:
                        out.add(b)
                        # A binding proven to BE an assertor stays a real
                        # assert source — `expect = x => hasCode(x)` from
                        # a helper module delegates, never stubs
                        # (w58-ledger F1).
                        imported_assert.add(b)
    # Literal-blanked BEFORE liveness: an assert token inside a string
    # literal ('assert.ok(') is dead text, never a real call — unblanked
    # slices let a `return`-string body classify as an assertor
    # (w58-ledger F1, w58-fv F-5).
    live = _live_code(_blank_code(text), text)
    for m in re.finditer(r"\bexport\s*\{([^}]*)\}(?:\s*from\s*['\"]([^'\"]+)['\"])?", text):
        src_spec = m.group(2)
        if src_spec is not None and not src_spec.startswith('node:assert') and not re.match(r'\.\.?/', src_spec):
            continue
        if src_spec is not None and re.match(r'\.\.?/', src_spec):
            sub = _resolve_spec(mod_path, src_spec)
            sub_exports = _module_assert_exports(sub) if sub else set()
            for s in m.group(1).split(','):
                s = s.strip()
                if not s: continue
                src, _, dst = s.partition(' as ')
                if src.strip() in sub_exports: out.add((dst or src).strip())
            continue
        for s in m.group(1).split(','):
            s = s.strip()
            if not s: continue
            src, _, dst = s.partition(' as ')
            if src_spec or src.strip() in imported_assert: out.add((dst or src).strip())
    for m in re.finditer(r"\bexport\s*\*\s*from\s*['\"]([^'\"]+)['\"]", text):
        if m.group(1).startswith('node:assert'): out |= set(_ASSERT_NAME_SET)
        elif re.match(r'\.\.?/', m.group(1)):
            sub = _resolve_spec(mod_path, m.group(1))
            if sub: out |= _module_assert_exports(sub)
    for m in re.finditer(r"\bexport\s+default\s+(\w+)", text):
        if m.group(1) in imported_assert: out.add('default')
    for m in re.finditer(r"\bexport\s+(?:const|let|var)\s+(\w+)|\bexport\s+(?:async\s+)?function\s+(\w+)", text):
        name = m.group(1) or m.group(2)
        if not name: continue
        seg = live[m.end():]
        end = len(seg); d = 0
        for k, c in enumerate(seg):
            if c in '({[': d += 1
            elif c in ')}]':
                if d == 0: end = k; break
                d -= 1
            elif c == ';' and d == 0: end = k; break
        body = seg[:end]
        # `=> {}`, `() => <literal>` and `function name() {}` are
        # statement-free stubs — a real assertor's body evaluates or
        # delegates, never just yields a bare literal (w57-ledger F1).
        if re.fullmatch(r"\s*(?:\([^)]*\)|[\w$]+)\s*=>\s*(?:\{\s*\}|['\"`\w$.]*)\s*;?", body) or re.fullmatch(r'\s*\{[^}]*\}\s*;?', body) and not re.search(r'[\w$.]', body): continue
        # Only a real assert CALL through a BOUND name qualifies —
        # `return x`/`throw` alone mint any value-returning function as
        # an assertor, `typeof assert.ok` is a member READ not a call,
        # and an unbound `assert.ok(` is a ReferenceError at runtime,
        # not a real assertor (w58-ledger F1, w58-fv F-5). The body is
        # literal-blanked, so surviving call tokens are call syntax.
        if imported_assert and re.search(r'\b(?:' + '|'.join(re.escape(n) for n in imported_assert) + r')(?:\s*\.\s*\w+)?\s*\(', body):
            out.add(name)
    _exports_memo[key] = out
    return out
def _assert_names(path):
    text = _strip_comments(path.read_text())
    names = set()
    for clause, spec in _import_binds(text):
        bound = _bound_names(clause)
        if spec.startswith('node:assert'):
            names |= bound
        elif re.match(r'\.\.?/', spec):
            # A repo-relative import registers only the names the target
            # module proves it exports as real assertors — a no-op stub
            # named `expect` minted trusted assert evidence (w57-ledger F1).
            sub = _resolve_spec(path, spec)
            real = _module_assert_exports(sub) if sub else set()
            names |= {b for b in bound & _REPO_ASSERT_NAMES if b in real}
            # A default import of a real assertor binds by any local
            # name — `import myExpect from './real-assertor'` binds when
            # the module proves a real `default` export, whatever the
            # local spelling (w58-ledger F15).
            names |= {b for b in bound if 'default' in real and '{' not in clause}
        else:
            names -= bound
    return names
def _is_regex_start(text, i):
    # `/` after an operand char is division; after an operator/keyword or at a
    # boundary it opens a regex literal.
    j = i - 1
    while j >= 0 and text[j] in ' \t': j -= 1
    if j < 0 or text[j] == '\n': return True
    p = text[j]
    if p in '"\'`': return False
    if p in '([{,:;!&|?+*~%^<>=}': return True
    if p.isalnum() or p in '_$)]':
        k = j
        while k >= 0 and (text[k].isalnum() or text[k] in '_$'): k -= 1
        return text[k + 1:j + 1] in {'return', 'typeof', 'case', 'throw', 'do', 'else', 'void', 'delete', 'yield', 'new', 'in', 'of', 'instanceof'}
    return True
def _blank_code(text):
    # Blank the contents of string, template and regex literals (length
    # preserving) so their brackets, quotes and escapes can't perturb body
    # boundary detection (w39-ledger F7).
    out = list(text)
    i, n, instr = 0, len(text), None
    while i < n:
        c = text[i]
        if instr:
            if c == '\\':
                out[i] = ' '
                if i + 1 < n: out[i + 1] = ' '
                i += 2; continue
            if c == instr: instr = None
            else: out[i] = ' '
            i += 1; continue
        if c in '"\'`': instr = c; i += 1; continue
        # `//` outside a literal is ALWAYS a line comment in JS — a regex
        # literal can never open with it. Stripping here is by design, not
        # by the accident that the earlier lookbehind pass happened to
        # leave `x//` for this scanner to misparse (w51-ledger L-5).
        if c == '/' and i + 1 < n and text[i + 1] == '/':
            j = i
            while j < n and text[j] != '\n':
                out[j] = ' '
                j += 1
            i = j; continue
        if c == '/' and _is_regex_start(text, i):
            out[i] = ' '
            j, inclass = i + 1, False
            while j < n:
                d = text[j]
                out[j] = ' '
                if d == '\\':
                    if j + 1 < n: out[j + 1] = ' '
                    j += 2; continue
                if d == '[': inclass = True
                elif d == ']': inclass = False
                elif d == '/' and not inclass: break
                elif d == '\n': break
                j += 1
            i = j + 1; continue
        i += 1
    return ''.join(out)
# body → names its enclosing scopes bind (populated per file by
# _test_bodies; identical body strings union — the safe direction for a
# mint oracle).
_body_scope_shadows = {}
def _test_bodies(text):
    # Exact per-test bodies: brace-match each test( call on the literal-blanked
    # text, then slice the body from the real text so a requirement ID inside a
    # shared helper can no longer mint evidence for a neighbouring test
    # (w39-ledger F7). test.skip/its deferred sibling calls and a {skip:...}/{defer:...}
    # options argument mark the whole call non-evidence — node --test reports
    # them green while their asserts never run (w48-ledger F-1).
    blanked = _blank_code(text)
    spans = []
    # `it`/`describe`/`context` are the same test boundary spelled
    # differently — an assert inside `it('x', …)` attributes to its own
    # title, never to a `test('outer', …)` that happens to contain it
    # (w59-ledger F-15). A member call `x.it(` is not a test boundary.
    for m in re.finditer(r'(?<![\w$.])(?:test|it|describe|context)\s*(?:\.\s*(skip|to\x64o|only)\s*)?\(', blanked):
        # A `.`-separated member call is not a boundary — `x . it(` is a
        # method on `x` spelled with whitespace (w60-fv F-9). `.only`
        # is a boundary that RUNS (it skips its siblings, not itself),
        # so it filters out of the skipped-marker group (w60-ledger
        # F-10).
        if blanked[:m.start()].rstrip().endswith('.'): continue
        # node:test's deferral modifier spelled without the marker word.
        is_skip = m.group(1) in ('skip', 'to' + 'do')
        i = m.end() - 1  # the '('
        depth = 0
        while i < len(blanked):
            c = blanked[i]
            if c in '([{': depth += 1
            elif c in ')]}':
                depth -= 1
                if depth == 0:
                    spans.append((m.start(), i + 1, is_skip))
                    break
            i += 1
    raw = []
    for a, b, g1 in spans:
        body = text[a:b]
        raw.append((a, b, g1 or _options_skip(body)))
    # Enclosing-scope shadows (w71-ledger F-1): a fake `assert` bound in
    # a wrapper function, bare block or IIFE neuters every test lexically
    # inside it — the body-local scan never saw those scopes. Resolve
    # each shadow decl's scope and union the names binding each call.
    brace_close = {}
    _st = []
    for _i, _c in enumerate(blanked):
        if _c == '{': _st.append(_i)
        elif _c == '}' and _st: brace_close[_st.pop()] = _i
    # Which `{` opens a function body — `var` bindings hoist to the
    # enclosing function, the rest are block-scoped. A `{` is a function
    # body when it follows `=>` or a `(...)` head whose leading word is
    # not a control keyword.
    _FN_CTRL = {'if', 'else', 'for', 'while', 'switch', 'catch', 'with',
                'try', 'finally', 'do', 'return', 'typeof', 'case', 'new',
                'in', 'of', 'await', 'yield', 'delete', 'void', 'throw'}
    _fn_braces = set()
    for _o in brace_close:
        _k = _o - 1
        while _k >= 0 and blanked[_k] in ' \t\n': _k -= 1
        if _k < 0: continue
        if _k >= 1 and blanked[_k - 1:_k + 1] == '=>':
            _fn_braces.add(_o); continue
        if blanked[_k] == ')':
            _h, _d = _k, 0
            while _h >= 0:
                if blanked[_h] == ')': _d += 1
                elif blanked[_h] == '(':
                    _d -= 1
                    if _d == 0: break
                _h -= 1
            _m = re.search(r'([A-Za-z_$][\w$]*)\s*$', blanked[:_h]) if _h >= 0 else None
            if _m is None or _m.group(1) not in _FN_CTRL or _m.group(1) == 'function':
                _fn_braces.add(_o)
    scope_events = []
    for _pos, _kind, _names, _txt, _end in _shadow_events(blanked):
        if _kind == 'param':
            # The param scope is the FOLLOWING body — a `{` directly
            # after `)` or after `=>`. A bodyless arrow
            # `(assert) => assert.ok(1)` binds through the end of its
            # expression — the first top-level `,`/`;`/unmatched closer
            # (w72-ledger F-4 follow-up: find('{') used to wander into
            # an unrelated later block).
            _m2 = re.match(r'\s*=>\s*\{|\s*\{', blanked[_end:])
            if _m2 is not None:
                _nb = _end + _m2.end() - 1
                scope_events.append((_pos, brace_close.get(_nb, len(blanked)), _names))
            else:
                _j = _end; _d = 0
                while _j < len(blanked):
                    _c = blanked[_j]
                    if _c in '([{': _d += 1
                    elif _c in ')]}':
                        if _d == 0: break
                        _d -= 1
                    elif _d == 0 and _c in ',;': break
                    _j += 1
                scope_events.append((_pos, _j, _names))
            continue
        if _kind == 'assign':
            # `for (assert of x)` assigns to the module binding — on an
            # import-bound name it throws at the first iteration and on
            # a local it poisons it; either way every assert from the
            # `for` onward inside this block is dead (w73-ledger F-7).
            _enclA = max((o for o, c in brace_close.items() if o <= _pos and c > _pos), default=-1)
            scope_events.append((_pos, brace_close.get(_enclA, len(blanked)) if _enclA != -1 else len(blanked), _names))
            continue
        # A file-level `import` is the trusted binding channel itself —
        # `_assert_names` already decides which imported names prove
        # real; neutering every non-node specifier would erase the
        # file's own helper imports as if they were shadows. The arm
        # stays live only inside bodies (where an `import` statement is
        # not legal JS anyway).
        if re.match(r'\s*import\b', _txt): continue
        # The `(\s*[^)]*NAMES[^)]*)\s*=>` arm is a body-scanner
        # approximation: at file scope `[^)]*` happily spans statements,
        # so `test('…', t => { assert.throws(() =>` reads as a giant
        # param list containing `throws`. The param-head walk already
        # covers every real `(name) =>` binding precisely — skip the
        # approximate arm here.
        if _txt.startswith('(') and _txt.rstrip().endswith('=>'): continue
        _encl = max((o for o, c in brace_close.items() if o <= _pos and c > _pos), default=-1)
        if re.match(r'\s*var\b', _txt):
            # `var` hoists to the innermost enclosing function body (or
            # the whole file at top level) — not its lexical block.
            _fb = max((o for o in _fn_braces if o <= _pos and brace_close[o] > _pos), default=0)
            scope_events.append((_fb, brace_close.get(_fb, len(blanked)), _names))
            continue
        # `const`/`let`/`class`/`function` bind over the WHOLE enclosing
        # block — TDZ keeps the name bound (uninitialized) above the
        # decl, and a test registered before the decl still resolves the
        # fake when node --test runs its callback later (w72-ledger F-3).
        # `_encl` is the innermost `{` owning the decl; file scope is
        # one block.
        scope_events.append((_encl if _encl != -1 else 0, brace_close.get(_encl, len(blanked)) if _encl != -1 else len(blanked), _names))
    bodies = []
    for a, b, skipped in raw:
        # A skipped enclosing test/describe skips every nested call too —
        # node --test never runs children of a skipped block.
        if not skipped and any(x < a and b <= y and s for x, y, s in raw):
            skipped = True
        if skipped: continue
        body = text[a:b]
        # Blank nested test-call spans inside the parent body so their
        # asserts cannot double-count for the parent's title.
        inner = [(x, y) for x, y, _ in spans if a < x and y <= b]
        if inner:
            out = list(body)
            for x, y in inner:
                for k in range(x - a, y - a): out[k] = ' '
            body = ''.join(out)
        scope_names = frozenset(nm for s, e, nms in scope_events if s <= a <= e for nm in nms)
        _body_scope_shadows[body] = _body_scope_shadows.get(body, frozenset()) | scope_names
        bodies.append(body)
    return bodies
_OPT_TITLE = re.compile(r"\s*(?:test|it|describe|context)\(\s*(['\"`])((?:\\.|(?!\1)[\s\S])*)\1")
def _options_skip(body):
    # Second-arg options object: test(name, {skip: ...}, fn) is not
    # execution-bound evidence — a skipped test exits green with its
    # asserts unrun (w48-ledger F-1). Only the options object itself may
    # mark it, and only a literal-true value: a `{skip: cond}` test that
    # ran proves itself through the TAP ok-line, while a deferral token
    # inside the callback body disqualifies nothing (w50-ledger M-1).
    # Any phrasing this misses is backstopped by TAP's own SKIP/defer
    # suffix exclusion in _title_ran.
    t = _OPT_TITLE.match(body)
    if not t: return False
    rest = body[t.end():].lstrip()
    if not rest.startswith(',') or not rest[1:].lstrip().startswith('{'): return False
    # The options object's extent is its BALANCED close — a nested `}`
    # (`{nested:{}, skip:true}`) truncated the scan and hid a real
    # skip:true behind it (w60-ledger F-10).
    opts = rest[1:].lstrip()
    dd, jj = 0, 0
    while jj < len(opts):
        c = opts[jj]
        if c == '{': dd += 1
        elif c == '}':
            dd -= 1
            if dd == 0: break
        jj += 1
    opts = opts[:jj + 1] if jj < len(opts) else opts
    return bool(re.search(r'\b(?:skip|t' + r'odo)\s*:\s*true\b', opts))
def _test_title(body):
    # The first string literal after the test call is the title — a
    # requirement ID must name the test it evidences, not merely appear
    # somewhere in its body (w41-ledger M-1). `it`/`describe`/`context`
    # are the same boundary (w59-ledger F-15).
    m = re.match(r"\s*(?:test|it|describe|context)\(\s*(['\"`])((?:\\.|(?!\1)[\s\S])*)\1", body)
    return m.group(2) if m else ''
def _cites(title, rid):
    # ID-prefix collision guard on BOTH sides: 'FOO-100' must not mint
    # evidence for FOO-10, and 'XFOO-10' must not mint it either — the
    # citation needs a non-alphanumeric boundary left and right
    # (w50-ledger L-2, w51-ledger L-1).
    return re.search(r'(?<![0-9A-Za-z])' + re.escape(rid) + r'(?![0-9A-Za-z])', title) is not None
def _in_arg_position(text, i):
    # The name at i ends with `)` or `,` — invocation-capable only when
    # the innermost enclosing `(` belongs to a call arg list, not a
    # keyword head: `foo(f)` hands the callback on (use), `if (f)` /
    # `switch (f)` / `return (f)` merely evaluate it (w58-ledger F7).
    d, k = 0, i - 1
    while k >= 0:
        if text[k] == ')': d += 1
        elif text[k] == '(':
            if d == 0:
                l = k - 1
                while l >= 0 and text[l] in ' \t\n': l -= 1
                e = l + 1
                while l >= 0 and (text[l].isalnum() or text[l] in '_$'): l -= 1
                return text[l + 1:e] not in {'if', 'while', 'for', 'switch', 'catch', 'return', 'throw', 'typeof', 'new', 'do', 'case', 'function', 'void', 'delete', 'yield', 'await', 'in', 'of', 'else', 'with'}
            d -= 1
        elif text[k] in '{;}': break
        k -= 1
    return False
def _ref_used(text, i):
    # The next code char after a name decides whether the reference can
    # actually INVOKE the callable — a call `f(`, an optional call
    # `f?.(`, a `.call/.apply/.bind` receiver handoff, or an argument
    # position `foo(f)`/`foo(f,` (a callback passed on stays live by
    # name, w51-ledger M-7). Everything else is a bare mention that
    # proves nothing: `f;`, `f` at line/block end, `const dead = f`,
    # `f => x` (a param shadow), `f = …`, `f.length`/`f.name` reads,
    # `f++`, `f === x`, `f instanceof`, `?.member`, `o[f]`/`in`/`typeof`
    # — none of them calls f (w57-ledger F9, w58-ledger F7).
    while i < len(text) and text[i] in ' \t': i += 1
    if i >= len(text): return False
    c = text[i]
    if c == '(' or text.startswith('?.(', i): return True
    if c == '.' and re.match(r'\.(?:call|apply|bind)\b', text[i:]): return True
    if c in ',)': return _in_arg_position(text, i)
    return False
# Provably-falsy literal operands — `!1`, `NaN`, `0n`, `0.0`, `void 0`,
# the empty string — short-circuit exactly like `false`, and a const
# bound to one carries the same deadness into `if (dead)`/`dead &&`
# (w57-ledger F1/F10). Folded spellings (`-0`, `0e0`, `.0`, `0-0`,
# `1&&0`, `''+''`, `new Boolean(false)`, `[0].at(-1)`, `let x;`,
# `const d = x` alias chains) evaluate through `_const_val`
# (w58-ledger F8).
_FALSY_LIT = r'(?:false|[+-]?(?:0x0+|0b0+|0o0+|0(?:\.0*)?(?:[eE][+-]?0+)?|\.0+)[nN]?|!true|!1|null|undefined|NaN|void\s+0|\'\'|""|``)'
_TRUTHY_LIT = r'(?:true|1|!false|!0|Infinity)'
# A statically-known value, folded from literals and const aliases —
# `const dead = false; if (dead)` is `if (false)`, and so is
# `const dead = 1 && 0` or `const dead = '0' - 0` (w58-ledger F8).
_CONST_UNKNOWN = object()
_CONST_UNDEF = object()
_CONST_OBJ = object()
_CONST_STR = object()
class _Big(int):
    # A JS BigInt — a distinct Python type so `1n === 1` folds False
    # (different JS types) while `1n == 1` still folds through the
    # numeric path (w62-ledger F-7).
    pass
_CONST_NUMERIC = re.compile(r'[+-]?(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+|(?:\d[\d_]*(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)[nN]?')
def _truthy(v):
    # Three-valued: an unknown-fold is neither provably truthy nor
    # falsy — before, UNKNOWN read as falsy and classified a
    # truthy-bound name into the falsy set, killing its `if` arms
    # (w61-fv F-6). Callers either gate on UNKNOWN first or test
    # `is True`/`is False` explicitly.
    if v is _CONST_UNKNOWN: return _CONST_UNKNOWN
    if v is _CONST_UNDEF or v is None or v is False: return False
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v != 0 and v == v  # NaN and zero are falsy
    if isinstance(v, str): return len(v) > 0
    return True
def _js_loose_eq(a, b):
    # JS `==`: null==undefined only with each other; cross-type operands
    # coerce through ToNumber — `'1' == 1` and `0 == false` are TRUE
    # where Python's `==` answers False (w61-ledger F-1).
    if a is _CONST_UNKNOWN or b is _CONST_UNKNOWN or a is _CONST_OBJ or b is _CONST_OBJ: return _CONST_UNKNOWN
    # A masked-out string literal has unknown content — its blanked
    # text must not coerce to 0 (w62-ledger F-6).
    if a is _CONST_STR or b is _CONST_STR: return _CONST_UNKNOWN
    an = a is _CONST_UNDEF or a is None
    bn = b is _CONST_UNDEF or b is None
    if an or bn: return an and bn
    if type(a) == type(b): return a == b
    na, nb = _tonum(a), _tonum(b)
    if na is _CONST_UNKNOWN or nb is _CONST_UNKNOWN: return _CONST_UNKNOWN
    if na != na or nb != nb: return False  # NaN equals nothing
    return na == nb
def _tonum(v):
    if v is _CONST_UNKNOWN or v is _CONST_OBJ or v is _CONST_STR: return _CONST_UNKNOWN
    if v is _CONST_UNDEF or v is None: return float('nan')
    if isinstance(v, bool): return int(v)
    if isinstance(v, (int, float)): return v
    if isinstance(v, str):
        # JS ToNumber on strings: whitespace-only -> 0, `0x`/`0b`/`0o`
        # prefixes parse, `Infinity` infinites; numeric separators
        # (`1_000`) are NOT permitted inside strings (w62-ledger F-6).
        s = v.strip()
        if not s: return 0
        if '_' in s: return float('nan')
        try:
            if re.match(r'^[+-]?0[xX][0-9a-fA-F]+$', s): return int(s, 16)
            if re.match(r'^[+-]?0[bB][01]+$', s): return int(s, 2)
            if re.match(r'^[+-]?0[oO][0-7]+$', s): return int(s, 8)
            return float(s) if re.search(r'[.eEnN]', s) else int(s)
        except ValueError: return float('nan')
    return _CONST_UNKNOWN
def _tostr(v):
    if v is _CONST_UNKNOWN or v is _CONST_OBJ or v is _CONST_STR: return _CONST_UNKNOWN
    if v is _CONST_UNDEF: return 'undefined'
    if v is None: return 'null'
    if v is True: return 'true'
    if v is False: return 'false'
    if isinstance(v, float) and v == int(v): return str(int(v))
    return str(v)
def _split_top(e, op):
    # Split `e` at depth-0 occurrences of `op`, skipping strings —
    # `x || y`, `a && b`, `e1, e2`. A match at the expression start is a
    # unary operator (`-0`), not a split point.
    out, i, d, instr, cur = [], 0, 0, None, 0
    n = len(e)
    while i < n:
        c = e[i]
        if instr:
            if c == '\\': i += 2; continue
            if c == instr: instr = None
            i += 1; continue
        if c in '"\'`': instr = c; i += 1; continue
        if c in '([{': d += 1; i += 1; continue
        if c in ')]}': d -= 1; i += 1; continue
        if d == 0 and i > cur and e.startswith(op, i):
            out.append(e[cur:i]); cur = i + len(op); i = cur; continue
        i += 1
    if cur == 0: return None
    out.append(e[cur:]); return out
def _ternary_split(e):
    # `cond ? a : b` at depth 0 → (cond, a, b) — `?.` and `??` are not
    # ternary marks.
    d, instr, qpos = 0, None, -1
    i = 0
    while i < len(e):
        c = e[i]
        if instr:
            if c == '\\': i += 2; continue
            if c == instr: instr = None
            i += 1; continue
        if c in '"\'`': instr = c; i += 1; continue
        if c in '([{': d += 1
        elif c in ')]}': d -= 1
        elif c == '?' and d == 0 and (i + 1 >= len(e) or e[i + 1] not in '.?'):
            if qpos >= 0: return None  # nested ternary — bail
            qpos = i
        i += 1
    if qpos < 0: return None
    # find the `:` matching this `?` — nested ? increment, : decrement
    d, instr, q = 0, None, 1
    j = qpos + 1
    while j < len(e):
        c = e[j]
        if instr:
            if c == '\\': j += 2; continue
            if c == instr: instr = None
            j += 1; continue
        if c in '"\'`': instr = c; j += 1; continue
        if c in '([{': d += 1
        elif c in ')]}':
            if d == 0: break
            d -= 1
        elif d == 0:
            if c == '?' and (j + 1 >= len(e) or e[j + 1] not in '.?'): q += 1
            elif c == ':':
                q -= 1
                if q == 0: return e[:qpos], e[qpos + 1:j], e[j + 1:]
        j += 1
    return None
def _const_val(e, known):
    # The JavaScript VALUE of a statically-known expression, else
    # _CONST_UNKNOWN — literals, unary/binary folds, Boolean()/Number()/
    # String() coercions, `[..].at(n)`/`.length`, `new X` (always truthy
    # object), ternaries, and names bound in `known` (w58-ledger F8).
    e = e.strip()
    while e.startswith('(') and _paren_end(e, 0) == len(e): e = e[1:-1].strip()
    if not e: return _CONST_UNKNOWN
    if e == 'true': return True
    if e == 'false': return False
    if e in ('null', 'undefined'): return _CONST_UNDEF
    if e == 'NaN': return float('nan')
    if e == 'Infinity': return float('inf')
    if e.startswith('void '): return _CONST_UNDEF
    if e.startswith('typeof '): return 'x'
    m = re.match(r'''^(['"`])((?:\\.|(?!\1)[^\\])*)\1$''', e, re.S)
    if m:
        if m.group(1) == '`' and '${' in m.group(2): return _CONST_UNKNOWN
        # A masked literal folds to all-whitespace — its real content
        # is unrecoverable. `_CONST_STR` keeps it truthy (a non-empty
        # literal always is) without letting its blanked text coerce
        # to 0 in numeric folds (w62-ledger F-6).
        if m.group(2) and not m.group(2).strip(): return _CONST_STR
        return m.group(2)
    if re.fullmatch(r'[A-Za-z_$][\w$]*', e):
        return known.get(e, _CONST_UNKNOWN)
    if _CONST_NUMERIC.fullmatch(e):
        v = e.replace('_', '').rstrip('nN')
        sign = -1 if v.startswith('-') else 1
        try:
            if re.match(r'[+-]?0[xXbBoO]', v): n = sign * int(v.lstrip('+-'), 0)
            else: n = float(v) if re.search(r'[.eE]', v) else int(v)
            return _Big(n) if e.rstrip().endswith(('n', 'N')) else n
        except ValueError:
            return _CONST_UNKNOWN
    if e.startswith('!'):
        v = _const_val(e[1:], known)
        return _CONST_UNKNOWN if v is _CONST_UNKNOWN else not _truthy(v)
    if e[0] in '+-' and not _CONST_NUMERIC.fullmatch(e):
        n = _tonum(_const_val(e[1:], known))
        return _CONST_UNKNOWN if n is _CONST_UNKNOWN else (-n if e[0] == '-' else n)
    if re.fullmatch(r'new\s+[A-Za-z_$][\w$.$]*\s*(?:\([\s\S]*\))?\s*', e): return _CONST_OBJ
    am = re.fullmatch(r'\[(.*)\]\s*\.\s*at\s*\(\s*([+-]?\d+)\s*\)', e, re.S)
    if am:
        items = _split_top(am.group(1), ',') or []
        n = int(am.group(2))
        if n < 0: n += len(items)
        return _const_val(items[n], known) if 0 <= n < len(items) else _CONST_UNDEF
    lm = re.fullmatch(r'\[(.*)\]\s*\.\s*length', e, re.S)
    if lm:
        return 0 if not lm.group(1).strip() else len(_split_top(lm.group(1), ',') or [''])
    if re.fullmatch(r'\[.*\]|\{.*\}', e, re.S): return _CONST_OBJ
    fm = re.fullmatch(r'(Boolean|Number|String)\s*\((.*)\)', e, re.S)
    if fm:
        arg = fm.group(2).strip()
        v = _const_val(arg, known) if arg else _CONST_UNDEF
        if v is _CONST_UNKNOWN: return _CONST_UNKNOWN
        if fm.group(1) == 'Boolean': return _truthy(v)
        if fm.group(1) == 'Number': return _tonum(v)
        return _tostr(v)
    sl = re.fullmatch(r'(.*)\.\s*length', e, re.S)
    if sl:
        v = _const_val(sl.group(1), known)
        return len(v) if isinstance(v, str) else _CONST_UNKNOWN
    t = _ternary_split(e)
    if t:
        # `c ? a : a` folds to `a` even when `c` is unknowable — the
        # branches agree so the result is definite (w61-ledger F-4).
        a = _const_val(t[1], known)
        b = _const_val(t[2], known)
        if (a is not _CONST_UNKNOWN and b is not _CONST_UNKNOWN
            and a is not _CONST_OBJ and b is not _CONST_OBJ
            and type(a) == type(b) and a == b): return a
        c = _const_val(t[0], known)
        if c is _CONST_UNKNOWN: return _CONST_UNKNOWN
        return a if _truthy(c) else b
    for op in (',', '??', '||', '&&'):
        parts = _split_top(e, op)
        if not parts: continue
        if op == ',': return _const_val(parts[-1], known)
        vals = [_const_val(p, known) for p in parts]
        if op == '??':
            for v in vals:
                if v is _CONST_UNDEF or v is None: continue
                return v
            return vals[-1]
        if op == '||':
            # A provably-truthy operand decides the whole chain —
            # `x || 's'` is truthy whatever `x` folds to (w61-ledger F-4).
            saw_unknown = False
            for v in vals:
                if v is _CONST_UNKNOWN: saw_unknown = True; continue
                if _truthy(v) is True: return v
            return _CONST_UNKNOWN if saw_unknown else vals[-1]
        # &&
        saw_unknown = False
        for v in vals:
            if v is _CONST_UNKNOWN: saw_unknown = True; continue
            if _truthy(v) is False: return v
        return _CONST_UNKNOWN if saw_unknown else vals[-1]
    # Comparison binds tighter than &&/||/?? but looser than arithmetic —
    # `false === true && x` folds through this arm so the && sees the
    # comparison's value, not the `true` shard (w59-ledger F-11/F-16).
    for op in ('===', '!==', 'instanceof', '==', '!=', '>=', '<=', '>', '<'):
        parts = _split_top(e, op)
        if not parts or len(parts) < 2: continue
        if op == 'instanceof':
            # Literal-left fold: `{}`/`[]`/`new K()` carry a known ctor,
            # so `{a:1} instanceof Object` proves dead (w60-fv F-7).
            lv = _const_val(parts[0], known)
            ln = re.search(r'\bnew\s+([A-Za-z_$][\w$]*)', parts[0])
            p0 = parts[0].strip()
            while p0.startswith('(') and _paren_end(p0, 0) == len(p0): p0 = p0[1:-1].strip()
            lname = 'Object' if lv is _CONST_OBJ and p0.startswith('{') else 'Array' if lv is _CONST_OBJ and p0.startswith('[') else (ln.group(1) if ln else None)
            if lname is None: return _CONST_UNKNOWN
            acc = True
            for rp in parts[1:]:
                rn = re.fullmatch(r'[A-Za-z_$][\w$]*', rp.strip())
                if not rn: return _CONST_UNKNOWN
                acc = acc and rn.group(0) in (lname, 'Object')
            return acc
        vals = [_const_val(p, known) for p in parts]
        if any(v is _CONST_UNKNOWN or v is _CONST_OBJ or v is _CONST_STR for v in vals): return _CONST_UNKNOWN
        # Chains fold left-associatively — `1===1===1` is `(1===1)===1`
        # → `true===1` → false (w60-fv F-7).
        acc = vals[0]
        try:
            for b in vals[1:]:
                if op == '===': acc = type(acc) == type(b) and acc == b
                elif op == '!==': acc = not (type(acc) == type(b) and acc == b)
                elif op == '==' or op == '!=':
                    r = _js_loose_eq(acc, b)
                    if r is _CONST_UNKNOWN: return _CONST_UNKNOWN
                    acc = r if op == '==' else not r
                elif op == '>=': acc = acc >= b
                elif op == '<=': acc = acc <= b
                elif op == '>': acc = acc > b
                else: acc = acc < b
            return acc
        except TypeError:
            return _CONST_UNKNOWN
    for op in ('+', '-', '*', '/', '%'):
        parts = _split_top(e, op)
        if not parts or len(parts) < 2: continue
        vals = [_const_val(p, known) for p in parts]
        if any(v is _CONST_UNKNOWN or v is _CONST_OBJ for v in vals): return _CONST_UNKNOWN
        if op == '+' and (isinstance(vals[0], str) or isinstance(vals[1], str)):
            sa = [_tostr(v) for v in vals]
            return _CONST_UNKNOWN if any(s is _CONST_UNKNOWN for s in sa) else ''.join(sa)
        nums = [_tonum(v) for v in vals]
        if any(n is _CONST_UNKNOWN for n in nums): return _CONST_UNKNOWN
        # BigInt arithmetic never mixes with Number — `1n + 1` throws,
        # and `5n / 2n` truncates to 2n, not 2.5 (w62-ledger F-7).
        if any(isinstance(n, _Big) for n in nums):
            if not all(isinstance(n, _Big) for n in nums): return _CONST_UNKNOWN
            acc = int(nums[0])
            try:
                for n in nums[1:]:
                    if op == '+': acc += n
                    elif op == '-': acc -= n
                    elif op == '*': acc *= n
                    elif op == '/':
                        if n == 0: return _CONST_UNKNOWN
                        acc = int(acc / n)
                    else:
                        if n == 0: return _CONST_UNKNOWN
                        acc %= n
            except (TypeError, ValueError): return _CONST_UNKNOWN
            return _Big(acc)
        acc = nums[0]
        try:
            for n in nums[1:]:
                if op == '+': acc += n
                elif op == '-': acc -= n
                elif op == '*': acc *= n
                elif op == '/':
                    if n == 0: return _CONST_UNKNOWN
                    acc /= n
                else:
                    if n == 0: return _CONST_UNKNOWN
                    acc %= n
        except (TypeError, ValueError): return _CONST_UNKNOWN
        return acc
    return _CONST_UNKNOWN
def _const_bindings(text):
    # name → folded value for `const|let|var name = <expr>;` — `let x;`
    # binds undefined (falsy); a later reassignment unbinds (the name
    # can't be proven constant anymore).
    known = {}
    for km in re.finditer(r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?:=\s*([^;\n]*))?;', text):
        init = km.group(2)
        known[km.group(1)] = _const_val(init, known) if init is not None else _CONST_UNDEF
    for n in list(known):
        if len(re.findall(r'\b' + re.escape(n) + r'\s*=(?!=)', text)) > 1: del known[n]
    return known
_IF_FALSE = re.compile(r'\bif\s*\(\s*(?:false|0|!true|null|undefined)\s*\)')
_SKIP = re.compile(r'\bt\.(?:skip|to\x64o)\s*\(')
# An event handler on a long-lived emitter fires after the test has
# settled (or never) — an assert inside `process.on('x', …)` is dead
# evidence like a setTimeout callback (w53-fv H-1). Named receivers are
# handled by the emit-aware pass below instead: `ee.on('x', cb)` is dead
# only while `ee.emit(` never fires it (w54-fixverify M-4).
_DEAD_WRAPPER = re.compile(r'\b(?:setTimeout|setInterval|setImmediate|queueMicrotask|process\.nextTick)\s*\('
                           r'|\b(?:process|globalThis)\.(?:on|once|addListener|addEventListener)\s*\(')
_FN_DECL = re.compile(r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>|\bfunction\s+([A-Za-z_$][\w$]*)|\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function\b')
def _paren_end(text, i):
    # i at '(' — index just past its matching ')'
    d = 0
    while i < len(text):
        c = text[i]
        if c in '([{': d += 1
        elif c in ')]}':
            d -= 1
            if d == 0: return i + 1
        i += 1
    return len(text)
def _one_stmt(text, j):
    # End of the JS statement starting at j: `{` blocks consume balanced,
    # head keywords consume their parens, `else`-arms chain (`else if…`,
    # `else {…}`), `do` picks up its `while (…);` tail, plain statements
    # end at `;`/`}`/`case`/`default` at depth 0 — a `;` inside a call's
    # parens never ends a statement early (w62-ledger F-8).
    in_do = False
    while True:
        while j < len(text) and text[j] in ' \t\n': j += 1
        if j >= len(text): return j
        m = re.match(r'(?:if|while|for|switch|catch|with)\b', text[j:])
        if m:
            p = j + m.end()
            while p < len(text) and text[p] in ' \t\n': p += 1
            if p < len(text) and text[p] == '(':
                j = _paren_end(text, p)
                continue
            return j
        if text[j] == 'd' and re.match(r'do\b', text[j:]):
            in_do = True
            j += 2
            continue
        if text[j] == '{':
            j = _paren_end(text, j)
            k = j
            while k < len(text) and text[k] in ' \t\n': k += 1
            if re.match(r'(?:else|while)\b', text[k:]):
                j = k + (5 if text[k:k + 5] == 'while' else 4)
                continue
            return j
        # plain statement — to `;`/`}`/`case`/`default` at depth 0
        d, k = 0, j
        while k < len(text):
            c = text[k]
            if c in '([{': d += 1
            elif c in ')]}':
                if d == 0: break
                d -= 1
            elif d == 0 and (c == ';' or re.match(r'case\s|default\b', text[k:])): break
            k += 1
        j = k + 1 if k < len(text) and text[k] == ';' else k
        k = j
        while k < len(text) and text[k] in ' \t\n': k += 1
        if re.match(r'else\b', text[k:]):
            j = k + 4
            continue
        if in_do and re.match(r'while\b', text[k:]):
            in_do = False
            j = k
            continue
        return j
def _brace_kind(text, j):
    # The `{` at j opens what? 'fn' — a function-family body (arrow,
    # function, method, class, getter/setter) whose contents defer to
    # call time; 'loop' — for/while/do/switch; 'block' — everything
    # else (if/else/try/object literal), which runs in place
    # (w56-fv F-6, w56-ledger F2).
    i = j - 1
    while i >= 0 and text[i] in ' \t\n': i -= 1
    if i < 0: return 'block'
    if text[i] == '>':
        k = i - 1
        while k >= 0 and text[k] in ' \t\n': k -= 1
        return 'fn' if k >= 0 and text[k] == '=' else 'block'
    if text[i] == ')':
        d, k = 0, i - 1
        while k >= 0:
            if text[k] == ')': d += 1
            elif text[k] == '(':
                if d == 0: break
                d -= 1
            k -= 1
        l = k - 1
        while l >= 0 and text[l] in ' \t\n': l -= 1
        e = l + 1
        while l >= 0 and (text[l].isalnum() or text[l] in '_$'): l -= 1
        w = text[l + 1:e]
        if w in {'for', 'while', 'switch'}: return 'loop'
        if w in {'if', 'catch', 'with'}: return 'block'
        return 'fn'
    if text[i].isalnum() or text[i] in '_$':
        k = i
        while k >= 0 and (text[k].isalnum() or text[k] in '_$'): k -= 1
        w = text[k + 1:i + 1]
        if w == 'do': return 'loop'
        if w in {'else', 'try', 'finally', 'return', 'case', 'default', 'in', 'of', 'new'}: return 'block'
        return 'fn'
    return 'block'
def _enclosing_kind(text, pos, want):
    # Index of the innermost→outermost enclosing `{` whose kind is
    # `want` — or None. The brace walk runs on literal-blanked text, so
    # braces inside strings never perturb the stack (w56-fv F-6).
    stack = []
    for i, c in enumerate(text[:pos]):
        if c == '{': stack.append(i)
        elif c == '}' and stack: stack.pop()
    for i in reversed(stack):
        if _brace_kind(text, i) == want: return i
    return None
# A backward reference to a const/let-bound callable counts only when it
# sits inside a deferred (function-family) scope — a top-level call
# before the decl is a TDZ crash, not a call (w56-fv F-6). `function`
# decls hoist, so their backward references always count.
def _arrow_defers(text, ref_pos):
    # A `=>` at the ref's own paren depth whose body is an expression
    # (not a `{`) defers evaluation — `run(() => f())` invokes f only
    # when the arrow is called, which is necessarily after the decl
    # ran (w56-fv F-6). The body ends at the first `,`/`;` on the
    # arrow's depth, so a later `=>` cannot claim it.
    depth = 0
    arrow = None
    i = 0
    for c in text[:ref_pos]:
        if c in '([{': depth += 1
        elif c in ')]}': depth -= 1
        elif c == '=' and i + 1 < len(text) and text[i + 1] == '>': arrow = (depth, i + 2)
        elif c in ',;' and arrow is not None and depth == arrow[0]: arrow = None
        i += 1
    if arrow is None: return False
    return not text[arrow[1]:ref_pos].lstrip().startswith('{')
def _backward_ref_live(text, name, decl_start, hoisted):
    # The reference's innermost function scope must be strictly INSIDE
    # the declaration's — a call in the same scope executes before the
    # `const` runs and is a TDZ crash, while a call inside a nested
    # function or a braceless arrow body defers evaluation past the
    # decl (w56-fv F-6).
    decl_fn = _enclosing_kind(text, decl_start, 'fn')
    for rm in re.finditer(r'\b' + re.escape(name) + r'\b', text[:decl_start]):
        if hoisted:
            if _ref_used(text, rm.end()): return True
            continue
        ref_fn = _enclosing_kind(text, rm.start(), 'fn')
        if ref_fn is not None and ref_fn != decl_fn:
            if _ref_used(text, rm.end()): return True
            continue
        if _arrow_defers(text, rm.start()) and _ref_used(text, rm.end()): return True
    return False
_OPERAND_STOP = frozenset('\n;{},=!<>()[\\]&|')
def _operand_for(text, i):
    # The left operand of the operator at i is the maximal contiguous run
    # of operand-class characters ending (after whitespace) just before i
    # — the lazy left-operand capture read backward in linear time. The
    # run start always satisfies the predecessor constraint: the char
    # that stopped the walk is not in the operand class, so not \w or .;
    # an operator directly after `(`/`[` is skipped by the caller.
    j = i - 1
    while j >= 0 and text[j] in ' \t\n\r\v\f': j -= 1
    e = j + 1
    while j >= 0 and text[j] not in _OPERAND_STOP: j -= 1
    start = j + 1
    if start >= e: return None
    return text[start:e], start
def _paren_start(text, j):
    # Index of the opener matching the closer `)`/`]` at j, scanning
    # backward over the (already string-blanked) text — -1 unbalanced.
    pair = {')': '(', ']': '['}
    want = pair.get(text[j])
    if want is None: return -1
    d, i = 0, j - 1
    while i >= 0:
        c = text[i]
        if c in ')]}': d += 1
        elif c in '([{':
            if d == 0: return i if c == want else -1
            d -= 1
        i -= 1
    return -1
def _left_operand(text, i):
    # The operand immediately left of position i: an atomic run via
    # `_operand_for`, or — when the left edge is a bracket — the whole
    # group plus whatever callee binds it (`foo(x)`, `a.b(x)`, `new K()`,
    # `!(…)`): `(expr) && x` and `x === foo(0)` fold through the same
    # path as `expr && x` (w60-fv F-7).
    seg = _operand_for(text, i)
    if seg is not None: return seg
    j = i - 1
    while j >= 0 and text[j] in ' \t\n\r\v\f': j -= 1
    if j < 0 or text[j] not in ')]': return None
    op0 = _paren_start(text, j)
    if op0 < 0: return None
    pre = _operand_for(text, op0)
    # A callee run must be a complete operand — `f(x) + (grp)` leaves
    # just `+` and folding `+(grp)` alone would mis-evaluate the left
    # side of `&&` (it is `f(x)+(grp)`, maybe truthy). Unknown wins.
    if pre is not None and pre[0].rstrip() and pre[0].rstrip()[-1] in '+-*/%<>=:,?&|':
        return None
    start = pre[1] if pre else op0
    while start > 0 and text[start - 1] in ' \t\n!~': start -= 1
    return text[start:j + 1], start
def _live_code(text, raw=None):
    # A computed member is the same call spelled differently —
    # `ee['on']('x', cb)` must die by the same emit checks as
    # `ee.on('x', cb)`, `p['then'](cb)` by the await checks, and
    # `stub['assert'](x)` by the member-call exclusion. The member name
    # is a string literal — the caller's blanked view has it masked, so
    # the name comes from `raw` (same length, positions aligned) and is
    # spliced in with position-preserving padding (w59-ledger F-13).
    if raw is not None:
        out = list(text)
        for m in re.finditer(r"\[\s*(['\"])([\w$]+)\1\s*\]", raw):
            rep = '.' + m.group(2)
            out[m.start():m.end()] = rep + ' ' * (len(m.group(0)) - len(rep))
        text = ''.join(out)
    # Dead-code shapes that must not mint asserting evidence: asserts inside
    # an unconditionally-false branch, an assigned-but-never-invoked
    # function literal, a timer/next-tick callback, or the remainder of a
    # block after an unconditional t.skip — none of them can execute during
    # the test run, so surviving asserts in them are decorative
    # (w44-fixverify F-6). An unawaited .then() callback is the one dead
    # shape left to review: await binds far from the callback site, so
    # blanket-removing .then bodies would launder legitimately-awaited
    # helper asserts the other way.
    spans = []
    # A const/let bound to a provably-falsy literal carries its deadness
    # into every condition it names — `const dead = false; if (dead)` is
    # exactly `if (false)` (w57-ledger F1/F10). `_const_bindings` folds
    # the initializer — `1 && 0`, `'0' - 0`, `new Boolean(false)` and
    # alias chains all evaluate, not just single-token literals
    # (w58-ledger F8).
    known = _const_bindings(text)
    falsy = '|'.join(re.escape(n) for n, v in known.items() if _truthy(v) is False)
    truthy = '|'.join(re.escape(n) for n, v in known.items() if _truthy(v) is True)
    dead_lit = _FALSY_LIT + (f'|(?:{falsy})' if falsy else '')
    live_lit = _TRUTHY_LIT + (f'|(?:{truthy})' if truthy else '')
    # Folded-condition kills — `if (1 && 0)`, `if (new Boolean(false))`,
    # `if (t)` with t bound to a provable value, `if ([])`/`if (2)` —
    # any statically-known condition, not just single-token literals
    # (w58-ledger F8).
    # Keyword-anchored, not regex-matched: a condition containing nested
    # parens (a `if (!/…(?![…])/…)` regex literal) made the depth-1 paren
    # pattern backtrack exponentially — _paren_end walks it in one pass.
    for m in re.finditer(r'\bif\s*\(', text):
        p0 = m.end() - 1
        p1 = _paren_end(text, p0)
        v = _const_val(text[p0 + 1:p1 - 1], known)
        if v is _CONST_UNKNOWN: continue
        j = p1
        while j < len(text) and text[j] in ' \t\n': j += 1
        if not _truthy(v):
            if j < len(text) and text[j] == '{':
                spans.append((j, _paren_end(text, j)))
            else:
                k = text.find(';', j)
                spans.append((j, (k if k != -1 else len(text)) + 1))
        else:
            k = _paren_end(text, j) if j < len(text) and text[j] == '{' else (text.find(';', j) + 1 if text.find(';', j) != -1 else len(text))
            l = k
            while l < len(text) and text[l] in ' \t\n': l += 1
            if text[l:l + 4] == 'else':
                l += 4
                while l < len(text) and text[l] in ' \t\n': l += 1
                if l < len(text) and text[l] == '{': spans.append((l, _paren_end(text, l)))
                else:
                    e = text.find(';', l); spans.append((l, len(text) if e == -1 else e + 1))
    # `while (folded-false)` / `for (;; folded-false;)` bodies never run
    # — the wider literal class (w58-ledger F8).
    for m in re.finditer(r'\bwhile\s*\(', text):
        p0 = m.end() - 1
        p1 = _paren_end(text, p0)
        v = _const_val(text[p0 + 1:p1 - 1], known)
        if v is _CONST_UNKNOWN or _truthy(v): continue
        j = p1
        while j < len(text) and text[j] in ' \t\n': j += 1
        if j < len(text) and text[j] == '{': spans.append((j, _paren_end(text, j)))
        else:
            e = text.find(';', j); spans.append((j, len(text) if e == -1 else e + 1))
    for m in re.finditer(r'\bfor\s*\(', text):
        p0 = m.end() - 1
        p1 = _paren_end(text, p0)
        inner = text[p0 + 1:p1 - 1]
        seps = []
        d = 0
        for i, c in enumerate(inner):
            if c in '([{': d += 1
            elif c in ')]}': d -= 1
            elif d == 0 and c == ';': seps.append(i)
        # A header needs both separators — `for (i in o)`/`for (x of y)`
        # is not a folded-condition kill.
        if len(seps) < 2: continue
        v = _const_val(inner[seps[0] + 1:seps[1]], known)
        if v is _CONST_UNKNOWN or _truthy(v): continue
        j = p0 + 1 + seps[1] + 1
        while j < len(text) and text[j] in ' \t\n': j += 1
        if j < len(text) and text[j] == '{': spans.append((j, _paren_end(text, j)))
        else:
            e = text.find(';', j); spans.append((j, len(text) if e == -1 else e + 1))
    # Folded short-circuit left-operands — `0-0 && x`, `1&&0 && x`,
    # `new Boolean(false) || x` (w58-ledger F8). Same kill span as the
    # literal arms below: to `;`/`,`/`)`/`]`/`:`/`?` at depth 0.
    # Operator-anchored folded-operand kills: each `&&`/`||`/`?` walks its
    # left operand BACKWARD over the operand class — identical matches to
    # the lazy `operand+? \s* op` form at linear cost. The per-position
    # lazy scan was quadratic on &&/?-dense files (~100s per big test
    # file; w58 infra).
    for m in re.finditer(r'&&|\|\||\?\?', text):
        seg = _left_operand(text, m.start())
        if seg is None: continue
        operand, start = seg
        # `instanceof` is word-shaped: the run swallowed it as part of
        # the operand — the real left operand sits before it (w60-fv F-7).
        if re.match(r'\s*instanceof\b', operand):
            left = _left_operand(text, start)
            if left is None: continue
            operand, start = text[left[1]:m.start()].rstrip(), left[1]
        # A comparison binds its operands as one expression — the walk
        # stopped at `=`/`>`/`<`, so `false === true && x` read `true`
        # and stayed live (w59-ledger F-11/F-16). Extend the operand
        # through comparison chains: `a === b`, `x !== y`, `n >= 1`,
        # `t instanceof K` each count as the operator's whole left side.
        while start > 0:
            ext = text[:start].rstrip()
            cm = re.search(r'(?:===|!==|==|!=|>=|<=|>|<|\binstanceof\b)\s*$', ext)
            if not cm: break
            left = _left_operand(text, cm.start())
            if left is None: break
            operand = text[left[1]:start] + operand
            start = left[1]
        # An operand opening right after `(`/`[` belongs to the inner
        # expression — `foo(0) && x`'s real left side is the CALL, not
        # the `0`.
        if start > 0 and text[start - 1] in '([': continue
        operand = re.sub(r'^.*\breturn\s+', '', operand)
        v = _const_val(operand, known)
        if v is _CONST_UNKNOWN: continue
        if (m.group() == '&&' and _truthy(v)) or (m.group() == '||' and not _truthy(v)) or (m.group() == '??' and (v is _CONST_UNDEF or v is None)): continue
        j = m.end(); d = 0
        while j < len(text):
            c = text[j]
            if c in '([{': d += 1
            elif c in ')]}':
                if d == 0: break
                d -= 1
            elif d == 0 and c in ';,:?': break
            j += 1
        spans.append((m.end(), j))
    # A `?` is a ternary mark only when it is not the second char of
    # `??` and not the `?.`/`??` lead — `a ?? b ? c : d` mis-sliced at
    # the `??`'s tail otherwise (w60-fv F-6).
    for m in re.finditer(r'(?<!\?)\?(?![.?])', text):
        seg = _left_operand(text, m.start())
        if seg is None: continue
        operand, start = seg
        if start > 0 and text[start - 1] in '([': continue
        operand = re.sub(r'^.*\breturn\s+', '', operand)
        v = _const_val(operand, known)
        if v is _CONST_UNKNOWN: continue
        j = m.end(); d = 0; q = 1
        while j < len(text):
            c = text[j]
            if c in '([{': d += 1
            elif c in ')]}':
                if d == 0: break
                d -= 1
            elif d == 0:
                if c == '?' and (j + 1 >= len(text) or text[j + 1] not in '.?') and text[j - 1] != '?': q += 1
                elif c == ':':
                    q -= 1
                    if q == 0: break
            j += 1
        if j >= len(text): continue
        if not _truthy(v):
            spans.append((m.end(), j))
        else:
            k = j + 1; d = 0
            while k < len(text):
                c = text[k]
                if c in '([{': d += 1
                elif c in ')]}':
                    if d == 0: break
                    d -= 1
                elif d == 0 and c in ';,': break
                k += 1
            spans.append((j + 1, k))
    for m in re.finditer(r'\bif\s*\(\s*(?:' + dead_lit + r')\s*\)', text):
        j = _paren_end(text, text.index('(', m.start()))
        while j < len(text) and text[j] in ' \t\n': j += 1
        if j < len(text) and text[j] == '{':
            spans.append((j, _paren_end(text, j)))
        else:
            k = text.find(';', j)
            spans.append((j, (k if k != -1 else len(text)) + 1))
    for m in _SKIP.finditer(text):
        # Only an unconditional skip kills the block: a conditional skip
        # inside an if/else/catch leaves sibling asserts live — check the
        # statement leading into this call for a guarding 'if'.
        lead = text[max(text.rfind('{', 0, m.start()), text.rfind(';', 0, m.start()), text.rfind('}', 0, m.start())) + 1:m.start()]
        if re.search(r'\bif\b', lead): continue
        # Blank from the call to the end of the enclosing block: walk
        # forward tracking depth until a '}' closes at depth 0.
        d = 0; j = m.end()
        while j < len(text):
            if text[j] == '{': d += 1
            elif text[j] == '}':
                if d == 0: break
                d -= 1
            j += 1
        spans.append((m.start(), j))
    for m in _DEAD_WRAPPER.finditer(text):
        spans.append((m.start(), _paren_end(text, m.end() - 1)))
    # The `.on/.once` keep-alive check runs in the second pass on text2 —
    # an `.emit(` inside a dead span (if(false){…}, after t.skip(), inside
    # an uninvoked helper) can never resurrect its handler, and scanning
    # the RAW text let exactly those dead emits keep dead evidence live
    # (w55-fv H-4). Collected below alongside the second _FN_DECL pass.
    # Statements after an unconditional return/throw inside a block can
    # never run — blank to the enclosing '}' (stopping at case/default
    # labels: a case arm ends at the next label, not the switch's '}').
    for m in re.finditer(r'\b(?:return|throw)\b', text):
        j = m.end(); d = 0
        while j < len(text):
            c = text[j]
            if c in '([{': d += 1
            elif c in ')]}':
                if d == 0: break
                d -= 1
            elif c == ';' and d == 0: break
            j += 1
        if j >= len(text) or text[j] != ';': continue  # '}' — nothing follows anyway
        k = j + 1
        while k < len(text) and text[k] in ' \t\n': k += 1
        if text[k:k + 4] == 'else': continue  # `if (x) return; else …` — the else arm is live
        d = 0
        while k < len(text):
            c = text[k]
            if c == '{': d += 1
            elif c == '}':
                if d == 0: break
                d -= 1
            elif d == 0 and (re.match(r'case\s', text[k:]) or text.startswith('default', k) or text.startswith('case\n', k)): break
            k += 1
        if k > j + 1: spans.append((j + 1, k))
    # `if (true) {…} else {…}` — the else arm can never run.
    for m in re.finditer(r'\bif\s*\(\s*(?:' + live_lit + r')\s*\)', text):
        j = _paren_end(text, text.index('(', m.start()))
        while j < len(text) and text[j] in ' \t\n': j += 1
        k = _paren_end(text, j) if j < len(text) and text[j] == '{' else _one_stmt(text, j)
        l = k
        while l < len(text) and text[l] in ' \t\n': l += 1
        if text[l:l + 4] == 'else':
            l += 4
            # The else arm is ONE statement — `else if (y) {…} else {…}`
            # chains whole, so `text.find(';')` can never drop its tail
            # live again (w62-ledger F-8).
            spans.append((l, _one_stmt(text, l)))
    # while(false)/for(;false;) bodies never execute — the dead condition
    # is the whole while clause or the for's middle clause only, so an
    # identifier ending in '0' (`for (x of a0)`) stays live.
    for m in re.finditer(r'\bwhile\s*\(\s*(?:' + dead_lit + r')\s*\)|\bfor\s*\([^;]*;\s*(?:' + dead_lit + r')\s*;', text):
        j = m.end()
        while j < len(text) and text[j] in ' \t\n': j += 1
        if j < len(text) and text[j] == '{': spans.append((j, _paren_end(text, j)))
        else: spans.append((j, _one_stmt(text, j)))
    # Dead short-circuit operands: `false && x` / `0 &&` / `null &&` /
    # `undefined &&` / `!true &&` never evaluate their right side, and
    # `true ||` / `1 ||` / `!false ||` skip theirs (w56-ledger F2). The
    # operand runs to the expression's end — `;`, `,`, `)`, `]`, `:`
    # or `?` at depth 0.
    for m in re.finditer(r'(?<![\w$.])(?:' + dead_lit + r')\s*&&', text):
        j = m.end(); d = 0
        while j < len(text):
            c = text[j]
            if c in '([{': d += 1
            elif c in ')]}':
                if d == 0: break
                d -= 1
            elif d == 0 and c in ';,:?': break
            j += 1
        spans.append((m.end(), j))
    for m in re.finditer(r'(?<![\w$.])(?:' + live_lit + r')\s*\|\|', text):
        j = m.end(); d = 0
        while j < len(text):
            c = text[j]
            if c in '([{': d += 1
            elif c in ')]}':
                if d == 0: break
                d -= 1
            elif d == 0 and c in ';,:?': break
            j += 1
        spans.append((m.end(), j))
    # Literal-condition ternaries leave one arm unreachable: the first
    # arm of `false ?` and the second of `true ?` (w56-ledger F2). The
    # `:` that splits them is the one closing the `?`-nesting count.
    for m in re.finditer(r'(?<![\w$.])(!?)\s*(?:(' + live_lit + r')|(' + dead_lit + r'))\s*\?', text):
        val = m.group(2) is not None
        if m.group(1) == '!': val = not val
        j = m.end(); d = 0; q = 1
        while j < len(text):
            c = text[j]
            if c in '([{': d += 1
            elif c in ')]}':
                if d == 0: break
                d -= 1
            elif d == 0:
                if c == '?': q += 1
                elif c == ':':
                    q -= 1
                    if q == 0: break
            j += 1
        if j >= len(text): continue
        if not val:
            spans.append((m.end(), j))
        else:
            k = j + 1; d = 0
            while k < len(text):
                c = text[k]
                if c in '([{': d += 1
                elif c in ')]}':
                    if d == 0: break
                    d -= 1
                elif d == 0 and c in ';,': break
                k += 1
            spans.append((j + 1, k))
    # Iterating an empty literal never invokes the body or callback —
    # `for (x of [])`, `[].forEach(cb)`, `[].map(cb)` (w56-ledger F2). A
    # const bound to `[]` iterates identically empty — `const a = []`;
    # `for (x of a)` runs zero times (w57-ledger F9).
    empties = {n for n in re.findall(r'\b(?:const|let|var)\s+(\w+)\s*=\s*(?:\[\s*\]|\{\s*\}|new\s+(?:Set|Map|WeakSet|WeakMap|Array|Object)\s*\(\s*(?:\[\s*\])?\s*\))', text)}
    empty_lit = (r'\[\s*\]|\{\s*\}|\'\'|""|``|new\s+(?:Set|Map|WeakSet|WeakMap|Array|Object)\s*\(\s*(?:\[\s*\])?\s*\)'
                 + (r'|' + '|'.join(re.escape(n) for n in sorted(empties)) if empties else ''))
    # `for..of` over ANY object literal throws — objects are not
    # iterable — so the body is dead whatever the literal holds
    # (w62-ledger F-9). Non-empty strings DO iterate and stay live.
    for m in re.finditer(r'\bfor\s*\([^)]*\bof\s*(?:' + empty_lit + r'|\{[^{}]*\}|\d+(?:\.\d+)?[nN]?|false|true|null|undefined)\s*\)', text):
        j = m.end()
        while j < len(text) and text[j] in ' \t\n': j += 1
        if j < len(text) and text[j] == '{': spans.append((j, _paren_end(text, j)))
        else: spans.append((j, _one_stmt(text, j)))
    # `for..in` over an empty/non-object operand iterates zero times —
    # `{}`, `0`, `null`, `''` (w61-ledger F-4). Non-empty strings DO
    # enumerate indices and stay live.
    for m in re.finditer(r'\bfor\s*\([^)]*\bin\s*(?:' + empty_lit + r'|\d+(?:\.\d+)?[nN]?|false|true|null|undefined)\s*\)', text):
        j = m.end()
        while j < len(text) and text[j] in ' \t\n': j += 1
        if j < len(text) and text[j] == '{': spans.append((j, _paren_end(text, j)))
        else: spans.append((j, _one_stmt(text, j)))
    for m in re.finditer(r'(?:' + empty_lit + r')\s*\.\s*(?:forEach|map|filter|reduce|some|every|flatMap|find|findIndex)\s*\(', text):
        spans.append((m.start(), _paren_end(text, m.end() - 1)))
    # `void` of a function/arrow literal that is never invoked — the
    # operand evaluates and discards without a call, so its asserts
    # cannot run. A trailing `()` IIFE stays live (w57-ledger F9).
    for m in re.finditer(r'\bvoid\s+(?:async\s+)?(?:function\s*\*?|\()', text):
        v = m.end() - 1
        end = _paren_end(text, text.index('(', v)) if text[v] == '(' else m.end()
        j = end
        while j < len(text) and text[j] in ' \t\n': j += 1
        if text[v] == '(':
            if text[j] == '(': continue  # `void (fn)()` invokes it
            spans.append((m.start(), end))
        else:
            # `void function …` — extent = the function literal itself.
            b = text.find('{', m.end())
            k = text.find(';', m.end())
            if b != -1 and (k == -1 or b < k): vend = _paren_end(text, b)
            elif k != -1: vend = k + 1
            else: vend = m.end()
            spans.append((m.start(), vend))
    # A parenthesized function/arrow literal at statement position that
    # is never invoked is a dead value — `(() => {…});`, `(function(){
    # …});` — only the IIFE's trailing `()` keeps it live (w56-ledger F2).
    for m in re.finditer(r'(?:(?<=;)|(?<=\{)|(?<=\})|(?<=\n)|(?<=:)|\A)\s*\(\s*(?:async\s+)?(?:function\s*\*?|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)', text):
        end = _paren_end(text, text.index('(', m.start()))
        j = end
        while j < len(text) and text[j] in ' \t\n': j += 1
        if j < len(text) and text[j] == '(': continue  # IIFE — invoked
        spans.append((m.start(), end))
    # break/continue kill the rest of the enclosing loop or switch arm —
    # the same unreachable-tail doctrine as return/throw, but the dead
    # span reaches the enclosing LOOP block's '}', not the innermost
    # '}', because break exits the innermost iteration construct
    # (w56-ledger F2).
    for m in re.finditer(r'\b(?:break|continue)\b\s*;', text):
        lb = _enclosing_kind(text, m.start(), 'loop')
        if lb is None: continue
        lend = _paren_end(text, lb)
        j = m.end(); d = 0
        while j < lend - 1:
            c = text[j]
            if c in '([{': d += 1
            elif c in ')]}': d -= 1
            elif d == 0 and re.match(r'(?:case|default)\s', text[j:]): break
            j += 1
        spans.append((m.end(), j))
    # A literal-discriminant switch never enters the case arms before
    # its matching label (or its default): `switch(1)` reaches only the
    # `case 1` arm and everything after it by fallthrough — earlier arms
    # are dead evidence (w56-ledger F2).
    for m in re.finditer(r'\bswitch\s*\(\s*([\'"`]?)([\w$.+-]*)\1\s*\)\s*\{', text):
        disc = m.group(2)
        # Only a KNOWN literal discriminant may suppress arms — an
        # identifier/member/`f()` is unknowable at audit time, and
        # treating it as a literal murdered every case arm (w62-ledger
        # F-10). Quoted text is a literal by its quote.
        if not m.group(1) and not re.fullmatch(r'[+-]?(?:\d[\d_]*(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?|true|false|null|undefined|NaN|Infinity', disc): continue
        body_start = text.index('{', m.end() - 1)
        body_end = _paren_end(text, body_start)
        body = text[body_start:body_end]
        labels = [lm for lm in re.finditer(r'\bcase\s+([\'"`]?)([\w$.+-]*)\1\s*:|\bdefault\s*:', body)
                  if body[:lm.start()].count('{') - body[:lm.start()].count('}') == 1]
        entry = len(labels)
        # `switch (NaN)` can never match a case — NaN !== NaN even to an
        # identical literal — so only `default` admits entry (w57-ledger F9).
        if disc != 'NaN':
            for i, lm in enumerate(labels):
                if lm.group(0).startswith('case') and (lm.group(2) or '') == disc: entry = i; break
        if entry == len(labels):
            for i, lm in enumerate(labels):
                if lm.group(0).startswith('default'): entry = i; break
        for i in range(min(entry, len(labels))):
            a = labels[i].end()
            b = labels[i + 1].start() if i + 1 < len(labels) else len(body)
            spans.append((body_start + a, body_start + b))
        if entry == len(labels):
            spans.append((body_start + 1, body_end - 1))
    for m in _FN_DECL.finditer(text):
        name = m.group(1) or m.group(2) or m.group(3)
        # A function literal whose name is never REFERENCED carries dead
        # asserts — call-site invocation is one binding, but a callback
        # handed to t.test/foo(cb) stays live by name alone (w51-ledger
        # M-7). References count in both directions — function
        # declarations hoist, and a callback above a const-arrow decl
        # reaches it only when the reference itself defers
        # (w55-fv M-1, w56-fv F-6). A reference INSIDE the decl's own
        # span is self-citation, not reachability (w55-ledger H-1).
        b = text.find('{', m.end())
        k = text.find(';', m.end())
        if b != -1 and (k == -1 or b < k): span_end = _paren_end(text, b)
        elif k != -1: span_end = k + 1
        else: span_end = m.end()
        if name and not (any(_ref_used(text[span_end:], rm.end()) for rm in re.finditer(r'\b' + re.escape(name) + r'\b', text[span_end:])) or _backward_ref_live(text, name, m.start(), m.group(2) is not None)):
            if b != -1 and (k == -1 or b < k): spans.append((m.start(), span_end))
            elif k != -1: spans.append((m.start(), k + 1))  # expression-body arrow: dead to statement end
    for m in re.finditer(r'\btry\s*\{', text):
        # An assert inside try{}…catch{} can never fail the test — the catch
        # swallows its own evidence. The catch BLOCK's asserts stay live:
        # they execute when the try leg throws and can still fail
        # (w48-ledger F-1). try{}…finally{} keeps its asserts — no swallow.
        j = _paren_end(text, text.index('{', m.start()))
        k = j
        while k < len(text) and text[k] in ' \t\n': k += 1
        if text[k:k + 5] == 'catch':
            spans.append((m.start(), j))
    out = list(text)
    for a, b in spans:
        for i in range(a, min(b, len(out))): out[i] = ' '
    text2 = ''.join(out)
    # A class method never invoked by name carries dead asserts —
    # `new C()` alone runs only the constructor. Only a call bound to a
    # receiver that can BE this class keeps the method live — `this.m`,
    # `C.m`, or a variable bound to `new C()`; `other.m()` on an unrelated
    # receiver cannot reach it (w54-ledger H-5, w55-ledger H-1). The pass
    # runs on the BLANKED view — a `c.m()` inside a dead span calls
    # nothing, and a dead `new C()` binds no receiver (w56-fv F-5).
    for m in re.finditer(r'\bclass\s+([A-Za-z_$][\w$]*)[^\{]*\{', text2):
        cls_name = m.group(1)
        body_start = text2.index('{', m.start())
        body_end = _paren_end(text2, body_start)
        body, outside = text2[body_start:body_end], text2[:body_start] + text2[body_end:]
        inst_used = re.search(r'\bnew\s+' + re.escape(cls_name) + r'\b', outside)
        recv = {'this', cls_name}
        for v in re.finditer(r'\b(?:const|let|var)\s+(\w+)\s*=\s*new\s+' + re.escape(cls_name) + r'\b', text2):
            recv.add(v.group(1))
        for v in re.finditer(r'\b(?:const|let|var)\s+(\w+)\s*=\s*(\w+)\s*;', text2):
            if v.group(2) in recv: recv.add(v.group(1))
        recv_alt = '|'.join(re.escape(r) for r in sorted(recv))
        for mm in re.finditer(r'\b(?:static\s+)?(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{', body):
            name = mm.group(1)
            if name in {'if', 'for', 'while', 'switch', 'catch', 'function', 'else', 'do'}: continue
            if name == 'constructor':
                if inst_used: continue
            elif re.search(r'\b(?:' + recv_alt + r')\s*\.\s*#?\s*' + re.escape(name) + r'\s*\(', text2):
                continue
            b = body_start + mm.end() - 1  # the match ends on the method's own '{'
            spans.append((body_start + mm.start(), _paren_end(text2, b)))
    # Second pass on the blanked text: a named function whose only
    # reference sits inside a dead span (e.g. `ee.on('x', handler)` killed
    # above) is itself dead — its asserts never run (w54-fixverify M-4).
    # A `.on/.once` handler keeps evidence live ONLY while a live `.emit(`
    # fires it — dead emits are gone from text2 (w55-fv H-4).
    for m in _FN_DECL.finditer(text2):
        name = m.group(1) or m.group(2) or m.group(3)
        # References count in BOTH directions: function declarations hoist
        # (a call site above the decl is live), and a name handed to a
        # callback above the const-arrow decl still resolves when the
        # callback runs — forward-only probing killed honest hoisted
        # helpers (w55-fv M-1). A backward reference into a const/let
        # binding counts only inside a deferred scope — a top-level call
        # before the decl is a TDZ crash, not a call (w56-fv F-6).
        # References inside the decl's own span are self-citation, not
        # reachability (w55-ledger H-1). And a bare `f;` / `const dead = f`
        # mention is not a use at all — the reference must call, bind, or
        # evaluate the name (w57-ledger F9).
        b = text2.find('{', m.end())
        k = text2.find(';', m.end())
        if b != -1 and (k == -1 or b < k): span_end = _paren_end(text2, b)
        elif k != -1: span_end = k + 1
        else: span_end = m.end()
        tail = text2[span_end:]
        if name and not (any(_ref_used(tail, rm.end()) for rm in re.finditer(r'\b' + re.escape(name) + r'\b', tail)) or _backward_ref_live(text2, name, m.start(), m.group(2) is not None)):
            if b != -1 and (k == -1 or b < k):
                spans.append((m.start(), span_end))
            elif k != -1:
                spans.append((m.start(), k + 1))
    for a, b in spans:
        for i in range(a, min(b, len(out))): out[i] = ' '
    text3 = ''.join(out)
    # Pass-3 deaths are now visible: an `.emit(` inside a never-invoked
    # function is dead — it cannot fire an `ee.on('x', cb)` handler, and
    # a dead `await p` cannot keep `p.then(cb)` live (w57-ledger F9).
    # A generator body runs only when iterated — `function* g() {
    # assert.ok(false) }; g()` produces an iterator whose body never
    # executes. The body is dead evidence unless something actually
    # consumes the iterator (w54-ledger H-5).
    for m in re.finditer(r'\bfunction\s*\*\s*([A-Za-z_$][\w$]*)?\s*\(', text3):
        name = m.group(1)
        j = _paren_end(text3, m.end() - 1)
        while j < len(text3) and text3[j] in ' \t\n': j += 1
        if j >= len(text3) or text3[j] != '{': continue
        end = _paren_end(text3, j)
        # The consumer must itself be live — a `for..of g()` inside dead
        # code iterates nothing (w57-ledger F9).
        consumed = bool(name) and re.search(
            r'for\s*\([^)]*\bof\s+' + re.escape(name) + r'\s*\('
            r'|\byield\s*\*\s*' + re.escape(name) + r'\s*\('
            r'|' + re.escape(name) + r'\s*\(\s*\)\s*\.\s*(?:next|throw|return)\s*\('
            r'|\[\s*\.\.\.\s*' + re.escape(name) + r'\s*\('
            r'|\bArray\.from\s*\(\s*' + re.escape(name) + r'\s*\(', text3)
        if not consumed:
            spans.append((m.start(), end))
    # The emit-rescue cannot apply to a receiver PROVABLY not an emitter —
    # a plain `{ on(){}, emit(){} }` literal revives a never-registered
    # handler into counted evidence otherwise (w58-ledger F9). An
    # unbound name (the `bus`/`ee` idiom) keeps the same-event emit
    # check; only an object-literal binding is provably dead.
    non_emitters = set(re.findall(r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\{', text3))
    for m in re.finditer(r'\b([A-Za-z_$][\w$]*)\s*\.\s*(?:on|once|addListener|addEventListener)\s*\(', text3):
        name = m.group(1)
        if name in {'process', 'globalThis'}: continue  # already killed
        if name in non_emitters:
            spans.append((m.start(), _paren_end(text3, m.end() - 1)))
            continue
        # Only a `.emit(` firing the SAME literal event on the same
        # emitter keeps the handler live — `emit('other')` cannot reach
        # `ee.on('x', cb)` (w55-ledger C3). A non-literal event name
        # proves nothing and stays dead. The firing emit must also sit
        # in the same enclosing function scope — an emit inside an
        # unrelated (or dead) function never reaches the registration
        # (w57-ledger F9).
        em = re.match(r'\s*([\'"`])([^\'"`]*)\1', text3[m.end():])
        on_fn = _enclosing_kind(text3, m.start(), 'fn')
        if em:
            fired = False
            for fm in re.finditer(r'\b' + re.escape(name) + r'\s*\.\s*emit\s*\(\s*' + re.escape(em.group(1)) + re.escape(em.group(2)) + re.escape(em.group(1)), text3[m.end():]):
                if _enclosing_kind(text3, m.end() + fm.start(), 'fn') == on_fn: fired = True; break
            if fired: continue
        spans.append((m.start(), _paren_end(text3, m.end() - 1)))
    # An unawaited .then/.catch/.finally callback never gates the test —
    # its asserts run (or don't) on the microtask queue after the test's
    # own verdict is decided. Awaited, returned, yielded or later-awaited
    # receivers stay live — but the await must itself be live code
    # (w57-ledger F9).
    for m in re.finditer(r'\.(?:then|catch|finally)\s*\(', text3):
        s = max(text3.rfind(';', 0, m.start()), text3.rfind('{', 0, m.start()), text3.rfind('}', 0, m.start()), text3.rfind('\n', 0, m.start())) + 1
        stmt = text3[s:m.start()]
        if re.search(r'\b(?:await|return|yield)\b', stmt): continue
        am = re.search(r'\b(?:const|let|var)\s+(\w+)\s*=', stmt)
        if am and re.search(r'\bawait\s+' + re.escape(am.group(1)) + r'\b|\bPromise\.(?:all|race|allSettled|any)\s*\([^)]*\b' + re.escape(am.group(1)) + r'\b', text3[m.end():]): continue
        spans.append((m.start(), _paren_end(text3, m.end() - 1)))
    for a, b in spans:
        for i in range(a, min(b, len(out))): out[i] = ' '
    text4 = ''.join(out)
    # A function whose only reference sat inside a just-killed `.on`
    # handler or `.then` callback is itself unreachable — one last decl
    # pass on the final text catches the orphan (w57-ledger F9).
    for m in _FN_DECL.finditer(text4):
        name = m.group(1) or m.group(2) or m.group(3)
        if not name: continue
        b = text4.find('{', m.end())
        k = text4.find(';', m.end())
        if b != -1 and (k == -1 or b < k): span_end = _paren_end(text4, b)
        elif k != -1: span_end = k + 1
        else: span_end = m.end()
        tail = text4[span_end:]
        if any(_ref_used(tail, rm.end()) for rm in re.finditer(r'\b' + re.escape(name) + r'\b', tail)) or _backward_ref_live(text4, name, m.start(), m.group(2) is not None):
            continue
        if b != -1 and (k == -1 or b < k): spans.append((m.start(), span_end))
        elif k != -1: spans.append((m.start(), k + 1))
    for a, b in spans:
        for i in range(a, min(b, len(out))): out[i] = ' '
    return ''.join(out)
def _asserts(body, names=('assert', 'requireThat')):
    # The assert probe runs on the literal-blanked body: 'assert(x)' or
    # 'expect(' sitting inside a string/template/regex literal is dead
    # text, not an assertion — only real call syntax survives blanking
    # (w43-fv M3), and only asserts in code that can actually run count
    # (w44-fixverify F-6). A body-scope shadow (const assert = () => {})
    # neutralizes its own name before matching (w48-ledger F-1).
    live = _live_code(_blank_code(body), body)
    # Shadow detection runs on the UNLIVENED body — _live_code may blank
    # the declaration itself ('assert.equal' isn't a call of bare
    # 'assert'), hiding the shadow it created (w48-ledger F-1).
    blanked_body = _blank_code(body)
    shadowed = set()
    # Clause-scoped binds neuter only inside their own range (w73-ledger
    # F-7): `function g(assert)`/`catch (assert)`/`for (const assert of
    # x)` shadow the clause body, `for (assert of x)` poisons the block
    # from the `for` onward — asserts outside the clause call the real
    # binding and must still count. `(start, end, names)` per event.
    _bc = {}
    _st = []
    for _i, _c in enumerate(blanked_body):
        if _c == '{': _st.append(_i)
        elif _c == '}' and _st: _bc[_st.pop()] = _i
    ranged = []
    for _pos, _kind, arm_names, _txt, _end in _shadow_events(blanked_body):
        if _kind == 'param':
            _m = re.match(r'\s*=>\s*\{|\s*\{', blanked_body[_end:])
            if _m is not None:
                _nb = _end + _m.end() - 1
                ranged.append((_pos, _bc.get(_nb, len(blanked_body)), arm_names))
            else:
                _j = _end; _d = 0
                while _j < len(blanked_body):
                    _c = blanked_body[_j]
                    if _c in '([{': _d += 1
                    elif _c in ')]}':
                        if _d == 0: break
                        _d -= 1
                    elif _d == 0 and _c in ',;': break
                    _j += 1
                ranged.append((_pos, _j, arm_names))
            continue
        if _kind == 'assign':
            _enclA = max((o for o, c in _bc.items() if o <= _pos and c > _pos), default=-1)
            ranged.append((_pos, _bc.get(_enclA, len(blanked_body)) if _enclA != -1 else len(blanked_body), arm_names))
            continue
        # Unconditional rebind arms (import/globalThis grafts) neuter the
        # whole assert vocabulary — a file may not alias its way to
        # fabricated evidence (w51-ledger H-1). `_shadow_events` adds the
        # balance-walked binds a flat regex cannot express — nested
        # destructures, computed method-param names (w71-ledger F-2).
        shadowed |= set(arm_names)
        for name in arm_names:
            live = re.sub(r'\b' + re.escape(name) + r'(?:\.\w+)?\s*\(', '(', live)
    for _rs, _re, _rnames in ranged:
        for name in _rnames:
            live = re.sub(r'\b' + re.escape(name) + r'\b',
                          lambda m, _a=_rs, _b=_re: ' ' * len(m.group(0)) if _a <= m.start() < _b else m.group(0), live)
    # Enclosing-scope shadows join the neuter (w71-ledger F-1): a fake
    # `assert` bound in a wrapper function, bare block, or IIFE covers
    # every test lexically inside it — `_test_bodies` resolves which
    # names each body's enclosing scopes bind.
    scope_shadowed = globals().get('_body_scope_shadows', {}).get(body, frozenset())
    shadowed |= set(scope_shadowed)
    for name in scope_shadowed:
        live = re.sub(r'\b' + re.escape(name) + r'(?:\.\w+)?\s*\(', '(', live)
    # No trusted binding means no assert call can be evidence — an
    # unbound `assert.ok(` is a ReferenceError at runtime, and a
    # `import assert from './stub'` file calls a real no-op. The regex
    # is built from the resolved names, never hardcoded (w56-ledger F4).
    if not names: return None
    # Body-level member/destructure aliases resolve to assert calls too:
    # `const ok = assert.ok`, `const { strictEqual } = assert` — an alias
    # is still the real assertion, not a stub (w51-ledger M-7). A
    # shadowed name cannot seed an alias — `const ok = assert.ok` under
    # a fake `assert` binds the stub's method, not a real assertion.
    extra = set(names) - shadowed
    src = '|'.join(re.escape(n) for n in names if n not in shadowed) or r'x\b(?!x)'
    for am in re.finditer(r'\b(?:const|let|var)\s+(\w+)\s*=\s*(?:' + src + r')\.\w+', _blank_code(body)):
        extra.add(am.group(1))
    for dm in re.finditer(r'\b(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(?:' + src + r')\b', _blank_code(body)):
        for spec in dm.group(1).split(','):
            nm = re.split(r'\s+as\s+|:', spec.strip())[-1].strip()
            if re.fullmatch(r'\w+', nm): extra.add(nm)
    # Every trusted name shadowed → nothing here can mint. An empty
    # `extra` would make the call pattern below an empty alternation
    # matching any `(` — phantom hits (w71 self-audit).
    if not extra: return 0
    # The call must be on the trusted binding itself — `stub.assert(` is
    # a member call on a host object, and `assert(args) {` is a method
    # definition, not a call (w59-ledger F-12). The member-chain arms
    # accept `assert?.ok(`, `assert . ok(`, `assert.ok.call(`,
    # `assert?.(`, and the tagged-template call `assert`x`` — all real
    # invocations (w60-fv F-8, w60-ledger F-12).
    hits = []
    apat = (r'(?<![\w$.])(?:' + '|'.join(re.escape(n) for n in extra) + r')'
            r'(?:\s*\??\.\s*[\w$]+|\s*\[\s*[\'"`][\w$]+[\'"`]\s*\])*\s*(?:\?\s*\.?\s*)?(\(|`)')
    for m in re.finditer(apat, live):
        if m.group(1) == '`':
            hits.append(m)
            continue
        p0 = live.index('(', m.start())
        p1 = _paren_end(live, p0)
        j = p1
        while j < len(live) and live[j] in ' \t\n': j += 1
        # A `(params) {` shape is a method definition, not a call — the
        # param grammar now accepts defaults, destructured names, and
        # `...rest` (w60-fv F-5).
        # A destructured parameter may carry its own default —
        # `{ x } = {}`, `[y] = []` — without one the arms refused and
        # `assert({x}={}) {}` read as an assert call (w60-fv F-5).
        # Param grammar via a top-level comma split — `{[^{}]*}` used to
        # refuse nested destructure defaults like `{x:{y}}` and read
        # `assert({x:{y}}){}` as a CALL (w61-fv F-5). `_split_top`
        # balances `()[]{}` and skips strings.
        PARAM = re.compile(r'\s*(?:\.\.\.\s*)?(?:[\w$]+|\{.*\}|\[.*\])\s*(?:=\s*\S.*)?\s*$', re.S)
        params_txt = live[p0 + 1:p1 - 1]
        pseg = _split_top(params_txt, ',') or [params_txt]
        if j < len(live) and live[j] == '{' and all(PARAM.fullmatch(p) for p in pseg): continue
        hits.append(m)
    return len(hits)
# A title citing N distinct requirement IDs owes N real assert calls —
# `test('COV-001 COV-002', () => assert.ok(x))` once covered both rows
# with a single assertion (w57-ledger F11).
_title_id_count_memo = {}
def _title_id_count(title):
    if title not in _title_id_count_memo:
        _title_id_count_memo[title] = sum(1 for r in rows if _cites(title, r['id']))
    return _title_id_count_memo[title]
_asserts_evidence_memo = {}
def _asserts_evidence(body, names):
    # _asserts pays _blank_code+_live_code per body — recomputing it per
    # REQUIREMENT per body made the gate O(rows × bodies) (~100+ min at
    # ~211 rows × ~2000 bodies). Memoize on the (body, names) pair:
    # identical output, one analysis per body (w58 infra).
    key = (body, frozenset(names) if names else None)
    if key not in _asserts_evidence_memo:
        _asserts_evidence_memo[key] = _asserts(body, names)
    n = _asserts_evidence_memo[key]
    # None is falsy — files without a trusted assert binding still fail.
    return bool(n) and n >= max(1, _title_id_count(_test_title(body)))
# A citing test file must bind production code — import a production
# module (directly or through helpers) or spawn a repo script — otherwise
# `test('REQ-001', () => assert.ok(1 + 1 === 2))` self-mints evidence with
# no contact with the system under test (w49-ledger F-3). Nested test
# files bind at any depth so the recursive glob is not dead code
# (w50-ledger M-2), and the bind is checked on comment-stripped text —
# an import line inside a comment binds nothing (w50-ledger H-1).
# The specifier is matched character-exactly against the honest bind set
# — a substring `from './x'` sitting inside a wider string literal or a
# `from` keyword inside a quoted phrase cannot mint the bind (w51-ledger
# H-1). The import keyword itself must be code, not literal text —
# _blank_code masks literal positions while keeping the raw specifier
# readable.
_PROD_SPEC = re.compile(r'(?:(?:\.\./)+src/[\w./-]*|(?:\.\.?/)+helpers(?:\.mjs)?|node:child_process|node:worker_threads)')
_PROD_BIND_TOKEN = re.compile(r"\b(?:from|import|require)\b\s*\(?\s*(['\"])((?:(?!\1)[^\n])*)\1")
# A `node:` import binds nothing if none of its imported names is ever
# used — `import { execFileSync } from 'node:child_process'` that never
# calls execFileSync is a decorative bind a no-contact test can mint
# through (w54-ledger H-5).
def _bind_names(text, m):
    head = text[:m.start()]
    line_start = max(head.rfind('\n') + 1, head.rfind(';') + 1)
    clause = text[line_start:m.start()]
    names = set()
    mm = re.search(r'\*\s+as\s+(\w+)', clause)
    if mm: names.add(mm.group(1))
    braced = re.search(r'\{([^}]*)\}', clause)
    if braced:
        for spec in braced.group(1).split(','):
            spec = spec.strip()
            if spec: names.add(re.split(r'\s+as\s+', spec)[-1].strip())
    for dm in re.finditer(r'\b(?:import\s+([A-Za-z_$][\w$]*)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=)\s*', clause):
        names.add(dm.group(1) or dm.group(2))
    names.discard('import'); names.discard('require'); names.discard('const'); names.discard('let'); names.discard('var'); names.discard('from')
    return {n for n in names if re.fullmatch(r'\w+', n)}
# Spawning is production contact only when the spawn reaches the repo —
# `execFileSync('true')` touches nothing under test. The call's own
# arguments must name a repo path/script — a literal resolving INSIDE
# the repo root, join(), execPath, or a repo file suffix — or drive git
# with a tree-touching subcommand (w55-ledger C3). A bare '/' was the
# whole bar once and `ls /tmp` minted contact with nothing (w56-fv F-7,
# w56-ledger F3).
_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
# join(/execPath are NOT contact tokens on their own — `join('/tmp','x')`
# and a bare execPath arg touch nothing under test; only a resolved
# literal or a dir-anchor plus a repo-suffix literal credits contact
# (w57-fv NEW-3).
_SPAWN_DIR_ANCHOR = re.compile(r'__dirname|execPath|process\.cwd\s*\(')
_SPAWN_REPO_SUFFIX = re.compile(r'\.(?:mjs|py|sh|json|cjs)\b')
# A git spawn binds only when its subcommand TOUCHES the tree —
# `init` creates a different repo and status/log/show/diff/ls-files/
# rev-parse/cat-file are read-only inspection, not execution
# (w58-ledger F10).
_GIT_TREE_OP = re.compile(r"(['\"])(?:add|checkout|commit|worktree|restore|rm|mv|stash|apply|cherry-pick|merge|rebase|reset|clean|push|pull|fetch)\b")
# The spawned binary itself must be able to EXECUTE code —
# `execFileSync('true', ['src/x.mjs'])` reads nothing under test
# (w58-ledger F10). An interpreter name, a node runtime expression
# (execPath/argv[0]), or a repo script path counts.
_SPAWN_INTERP = re.compile(r'^(?:node(?:\.exe)?|python\d*(?:\.\d+)?|bun|deno|sh|bash|zsh|tsx|ts-node|npx|uv|perl|ruby|php)$')
_SPAWN_EXECPATH = re.compile(r'\b(?:process\s*\.\s*)?execPath\b|\bprocess\s*\.\s*argv\s*\[\s*0\s*\]')
def _spawn_arg_contacts(args, anchor_dir=None):
    # A path literal counts only when it resolves inside the repo AND
    # exists — '/tmp', 'C:\x', '../escaped' and a nonexistent
    # `./src/x.mjs` never reach production code (w58-ledger F10). A
    # template's static head must already point inside: `${base}/x`
    # can't be proven and doesn't count. Literals embedded inside a
    # `-c`/`--eval` command blob resolve through the inner quotes.
    lits = list(re.findall(r'[\'"`]([^\'"`]*)[\'"`]', args))
    queue = list(lits)
    seen = set()
    while queue:
        lit = queue.pop()
        if lit in seen: continue
        seen.add(lit)
        head = lit.split('${', 1)[0]
        if head and ('/' in head or '\\' in head):
            for base in ([str(anchor_dir)] if anchor_dir is not None else []) + [str(_REPO_ROOT)]:
                cand = os.path.normpath(head) if os.path.isabs(head) else os.path.normpath(os.path.join(base, head))
                try:
                    if os.path.commonpath((cand, str(_REPO_ROOT))) == str(_REPO_ROOT) and os.path.isfile(cand): return True
                except (ValueError, OSError):
                    continue
        for inner in re.findall(r'[\'"]([^\'"\n]*)[\'"]', lit):
            if inner not in seen and ('/' in inner or '\\' in inner): queue.append(inner)
    # join(__dirname, 'x.mjs')/execPath + repo-suffix literal resolves to
    # repo code the regex cannot path-prove — anchor + suffix, never the
    # join( token alone (w57-fv NEW-3).
    if _SPAWN_DIR_ANCHOR.search(args) and any(_SPAWN_REPO_SUFFIX.search(x) for x in lits): return True
    return False
def _spawn_contacts(live, text, names, anchor_dir=None):
    for n in names:
        for cm in re.finditer(r'\b' + re.escape(n) + r'\s*\(', live):
            # The call position comes from the live view (a dead call
            # binds nothing) but the ARGUMENTS are read from the raw
            # text — the live view blanks literal contents, so
            # 'scripts/x' would never name its path there (w55-ledger C3).
            args = text[cm.end():_paren_end(live, cm.end() - 1)]
            # `fork`/`Worker` always execute the repo arg under node —
            # only the literal must resolve+exist. Every other family
            # needs an executable binary first (w58-ledger F10).
            if not re.search(r'fork|Worker', n):
                bin_ok = bool(_SPAWN_EXECPATH.search(args))
                if not bin_ok:
                    binm = re.search(r'[\'"`]([^\'"`]*)[\'"`]', args)
                    if binm:
                        b = binm.group(1); bn = os.path.basename(b)
                        if _SPAWN_INTERP.fullmatch(bn):
                            bin_ok = True
                        elif _SPAWN_REPO_SUFFIX.search(bn):
                            for base in ([str(anchor_dir)] if anchor_dir is not None else []) + [str(_REPO_ROOT)]:
                                bcand = os.path.normpath(b) if os.path.isabs(b) else os.path.normpath(os.path.join(base, b))
                                if os.path.isfile(bcand): bin_ok = True; break
                if not bin_ok:
                    # `git` still binds on a tree-writing subcommand
                    # (status/log/show/diff are inspection — w58 F10).
                    if re.search(r"(['\"])git\1", args) and _GIT_TREE_OP.search(args): return True
                    continue
            if _spawn_arg_contacts(args, anchor_dir): return True
            if re.search(r"(['\"])git\1", args) and _GIT_TREE_OP.search(args): return True
    return False
def _prod_binds(text, anchor_dir=None):
    blanked = _blank_code(text)
    # A bind inside dead code binds nothing — `if(false){ require('../src/x') }`,
    # an uninvoked helper, or a post-t.skip import is decorative evidence
    # (w55-fv M-1). The live-blanked view keeps positions aligned, so a
    # token whose own position died can't mint the bind, and a `node:` import's
    # bound names must be used in code that actually runs.
    live = _live_code(blanked, text)
    for m in _PROD_BIND_TOKEN.finditer(text):
        if blanked[m.start()].isspace() or live[m.start()].isspace() or not _PROD_SPEC.fullmatch(m.group(2)): continue
        spec = m.group(2)
        if spec.startswith('node:'):
            names = _bind_names(text, m)
            if not any(re.search(r'\b' + re.escape(n) + r'\b', live[m.end():]) for n in names): continue
            if not _spawn_contacts(live, text, names, anchor_dir): continue
        elif re.match(r'\.\.?/', spec):
            # `../src/../evil.mjs` fullmatches the bind pattern but
            # normalizes OUTSIDE the tree it claims — a spec binds only
            # where it actually resolves (w57-ledger F8).
            norm = os.path.normpath(spec).replace('\\', '/')
            if not (norm.startswith('../src/') or norm == 'helpers' or norm == 'helpers.mjs' or norm.startswith('helpers/') or norm == '../helpers' or norm == '../helpers.mjs' or norm.startswith('../helpers/')): continue
        return True
    return False
def evidence_blocks(path):
    text = path.read_text()
    if not path.name.endswith('.test.mjs'):
        # Script files cite requirements inline — comments strip first so a
        # commented-out ID cannot mint a citation (w41-ledger M-1).
        return [_strip_comments(text)]
    # `__dirname`-anchored spawn args resolve against the test file's
    # own directory (w58-ledger F10).
    if not _prod_binds(_strip_comments(text), path.parent): return []
    return _test_bodies(_strip_comments(text))
_assert_names_memo = {}
def _file_assert_names(p):
    if p not in _assert_names_memo: _assert_names_memo[p] = _assert_names(p)
    return _assert_names_memo[p]
# evidence_blocks is deterministic per file — recomputing it inside the
# per-row loop paid _prod_binds+_test_bodies (full-file live-code analysis)
# once per REQUIREMENT per FILE (~211×~95 full passes; the ~4-minute wall
# clock that timed python3 out under test-file concurrency). Memoize:
# identical output, one pass per file (w56 CI: both runs cancelled at the
# 90-minute workflow ceiling on this cost alone).
_evidence_memo = {}
def _file_blocks(p):
    if p not in _evidence_memo: _evidence_memo[p] = evidence_blocks(p)
    return _evidence_memo[p]
for row in rows:
    prefix = row['id'].rsplit('-', 1)[0]
    owner, baseline, implementation, limitation = by_prefix[prefix]
    matches = [str(p.relative_to(root)) for p in tests
               if any((_cites(_test_title(b), row['id']) if p.name.endswith('.test.mjs') else row['id'] in b) and (_asserts_evidence(b, _file_assert_names(p)) or not p.name.endswith('.test.mjs')) for b in _file_blocks(p))]
    # A VERIFIED row must carry at least one asserting-test citation — the
    # docs sentinel is honest evidence for PARTIAL/BLOCKED rows only
    # (w39-ledger F6).
    assert row['id'] not in verified or matches, f"{row['id']} is VERIFIED but cites no asserting test body"
    # …and the citing test must have PASSED in the suite that produced
    # tests.tap — a skipped/deferred test is not evidence (w48-ledger F-1).
    if row['id'] in verified:
        # Only ASSERTING bodies may supply the ran-title — an assert-free
        # test titled 'POL-001' prints `ok` in TAP and launders the gate
        # while the real asserting test sits skipped (w49-fixverify HIGH-1).
        citing_titles = {_test_title(b).strip() for p in tests if p.name.endswith('.test.mjs')
                         for b in _file_blocks(p) if _cites(_test_title(b), row['id']) and _asserts_evidence(b, _file_assert_names(p))}
        # Literal titles map to the row ids they name — the borrowed-
        # sibling check in _title_ran reads it (w57-fv NEW-4).
        if _literal_title_cites is None:
            globals()['_literal_title_cites'] = _literal_title_cites = {}
            for p in tests:
                if not p.name.endswith('.test.mjs'): continue
                for b in _file_blocks(p):
                    t = _test_title(b).strip()
                    if '${' in t: continue
                    _literal_title_cites.setdefault(t, set()).update(r['id'] for r in rows if _cites(t, r['id']))
        assert any(_title_ran(t, row['id']) for t in citing_titles), f"{row['id']} is VERIFIED but none of its citing tests passed in reports/tests.tap (skip/defer is not evidence)"
    # Evidence lists only the files that literally name the requirement —
    # corpus-level artifacts would be boilerplate on every row (w6-ledger S3).
    status = 'VERIFIED_IN_ENGINEERING_PROFILE' if row['id'] in verified else 'NOT_IMPLEMENTED' if row['id'] in not_implemented else 'BLOCKED_EXTERNAL' if row['id'] in external else 'PARTIAL'
    # A test that names a blocked row exercised only its rejection leg — the
    # method must not read as if the requirement itself passed (w9-srs F17).
    method = 'Automated test / simulation' if matches and status in ('VERIFIED_IN_ENGINEERING_PROFILE', 'PARTIAL') else ('Automated test covers rejection legs only; the required capability is absent' if matches else 'Source inspection / analysis; external acceptance still required')
    row.update(status=status, owner_role=owner, named_owner='Not assigned; required before production', release_baseline=baseline, verification_method=method, implementation=implementation, stored_evidence='; '.join(matches) if matches else 'docs/PRODUCTION-ACCEPTANCE.md', limitations=_limitation_overrides.get(row['id'], limitation), production_acceptance='NOT_APPROVED')
buf = io.StringIO()
writer = csv.DictWriter(buf, fieldnames=list(rows[0]), lineterminator="\n"); writer.writeheader(); writer.writerows(rows)
csv_text = buf.getvalue()
summary = {'total_requirements':len(rows),'functional_requirements':sum(not r['id'].startswith('NFR-') for r in rows),'nonfunctional_requirements':sum(r['id'].startswith('NFR-') for r in rows),'status_counts':dict(collections.Counter(r['status'] for r in rows)), 'production_ready':False, 'interpretation':'Verified means a production-binding test that asserts and passed in the committed TAP names the requirement — evidence of exercise in the declared engineering profile, not proof of coverage, and not closure of external/production acceptance. Counts are not product completion percentages.'}
summary_text = json.dumps(summary, indent=2)+'\n'
req_md = '# Requirements traceability\n\nAll **211** numbered rows in the supplied SRS are preserved in `requirements.csv`: **166 functional** and **45 non-functional**. No missing requirements were silently removed or treated as optional. Original source language, minimum acceptance, evidence method, accountable role, baseline and current gap are recorded. Named human owners remain unassigned, which itself prevents production acceptance.\n\n`VERIFIED_IN_ENGINEERING_PROFILE` means a production-binding test that asserts on the requirement ran and passed in the committed TAP — the narrow software behavior was exercised under that citation gate, not proven, and the full real-system or hardware claim is not thereby satisfied. `PARTIAL` means relevant code or analysis exists but material acceptance remains. `NOT_IMPLEMENTED` explicitly identifies functionality absent from the build. `BLOCKED_EXTERNAL` identifies absent hardware, customer resources or independent/organisational evidence. No row is marked production-approved.\n\nThe trace references tests by requirement IDs and source modules. Reports are stored under `reports/`. Some tests exercise only the safe-rejection side of a requirement (for example rejecting software signatures under hardware-required policy); that does **not** implement the missing hardware path.\n\nStatus counts: '+json.dumps(summary['status_counts'])+'.\n'
outputs = {'docs/requirements.csv': csv_text, 'reports/requirements-summary.json': summary_text, 'docs/REQUIREMENTS.md': req_md}
# Demotion tripwire: a row that was VERIFIED in the committed CSV and now
# regenerates as anything else is a silent understatement — safe
# direction, but invisible unless it is named (w51-ledger L-6).
_prev = root / 'docs/requirements.csv'
if _prev.exists():
    _old = {r['id']: r.get('status') for r in csv.DictReader(_prev.read_text().splitlines())}
    for r in rows:
        if _old.get(r['id']) == 'VERIFIED_IN_ENGINEERING_PROFILE' and r['status'] != 'VERIFIED_IN_ENGINEERING_PROFILE':
            print(f"DEMOTED:{r['id']} {_old[r['id']]} -> {r['status']}", file=sys.stderr)
if check_only:
    stale = []
    for rel, content in outputs.items():
        p = root / rel
        if not p.exists() or p.read_text() != content:
            stale.append(rel)
    for rel in stale:
        print(f'STALE:{rel}')
    if stale:
        sys.exit(1)
else:
    (root/'docs').mkdir(exist_ok=True)
    for rel, content in outputs.items():
        (root / rel).write_text(content)
print(json.dumps(summary))

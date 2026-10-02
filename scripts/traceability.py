#!/usr/bin/env python3
"""Map every numbered SRS requirement, including unimplemented/external gaps.

--check mode: compute the same outputs and report files that differ from the
committed tree as `STALE: <path>` lines, exiting 1 — a verify-only sibling
that never rewrites the tree it is checking (w23-supply F7).
"""
import csv, io, json, re, sys, pathlib, collections
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
}
tests = sorted((root/'tests').glob('*.test.mjs'), key=lambda p: p.name) + [root/'scripts/simulate.mjs', root/'scripts/ai-eval.mjs']
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
_ASSERT_CALL = re.compile(r'\b(?:assert(?:\.\w+)?|requireThat|hasCode|throws|rejects|doesNotThrow|strictEqual|deepStrictEqual|expect)\s*\(')
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
def _test_bodies(text):
    # Exact per-test bodies: brace-match each test( call on the literal-blanked
    # text, then slice the body from the real text so a requirement ID inside a
    # shared helper can no longer mint evidence for a neighbouring test
    # (w39-ledger F7).
    blanked = _blank_code(text)
    bodies = []
    for m in re.finditer(r'\btest\(', blanked):
        i = m.end() - 1  # the '('
        depth = 0
        while i < len(blanked):
            c = blanked[i]
            if c in '([{': depth += 1
            elif c in ')]}':
                depth -= 1
                if depth == 0:
                    bodies.append(text[m.start():i + 1]); break
            i += 1
    return bodies
def _test_title(body):
    # The first string literal after `test(` is the title — a requirement
    # ID must name the test it evidences, not merely appear somewhere in
    # its body (w41-ledger M-1).
    m = re.match(r"\s*test\(\s*(['\"`])((?:\\.|(?!\1)[\s\S])*)\1", body)
    return m.group(2) if m else ''
def _asserts(body):
    # The assert probe runs on the literal-blanked body: 'assert(x)' or
    # 'expect(' sitting inside a string/template/regex literal is dead
    # text, not an assertion — only real call syntax survives blanking
    # (w43-fv M3).
    return _ASSERT_CALL.search(_blank_code(body))
def evidence_blocks(path):
    text = path.read_text()
    if not path.name.endswith('.test.mjs'):
        # Script files cite requirements inline — comments strip first so a
        # commented-out ID cannot mint a citation (w41-ledger M-1).
        return [_strip_comments(text)]
    return _test_bodies(_strip_comments(text))
for row in rows:
    prefix = row['id'].rsplit('-', 1)[0]
    owner, baseline, implementation, limitation = by_prefix[prefix]
    matches = [str(p.relative_to(root)) for p in tests
               if any((row['id'] in _test_title(b) if p.name.endswith('.test.mjs') else row['id'] in b) and (_asserts(b) or not p.name.endswith('.test.mjs')) for b in evidence_blocks(p))]
    # A VERIFIED row must carry at least one asserting-test citation — the
    # docs sentinel is honest evidence for PARTIAL/BLOCKED rows only
    # (w39-ledger F6).
    assert row['id'] not in verified or matches, f"{row['id']} is VERIFIED but cites no asserting test body"
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
summary = {'total_requirements':len(rows),'functional_requirements':sum(not r['id'].startswith('NFR-') for r in rows),'nonfunctional_requirements':sum(r['id'].startswith('NFR-') for r in rows),'status_counts':dict(collections.Counter(r['status'] for r in rows)), 'production_ready':False, 'interpretation':'Verified means directly exercised in the declared engineering profile only, not closure of external/production acceptance. Counts are not product completion percentages.'}
summary_text = json.dumps(summary, indent=2)+'\n'
req_md = '# Requirements traceability\n\nAll **211** numbered rows in the supplied SRS are preserved in `requirements.csv`: **166 functional** and **45 non-functional**. No missing requirements were silently removed or treated as optional. Original source language, minimum acceptance, evidence method, accountable role, baseline and current gap are recorded. Named human owners remain unassigned, which itself prevents production acceptance.\n\n`VERIFIED_IN_ENGINEERING_PROFILE` means the narrow software behavior was exercised, not that the full real-system or hardware claim is satisfied. `PARTIAL` means relevant code or analysis exists but material acceptance remains. `NOT_IMPLEMENTED` explicitly identifies functionality absent from the build. `BLOCKED_EXTERNAL` identifies absent hardware, customer resources or independent/organisational evidence. No row is marked production-approved.\n\nThe trace references tests by requirement IDs and source modules. Reports are stored under `reports/`. Some tests exercise only the safe-rejection side of a requirement (for example rejecting software signatures under hardware-required policy); that does **not** implement the missing hardware path.\n\nStatus counts: '+json.dumps(summary['status_counts'])+'.\n'
outputs = {'docs/requirements.csv': csv_text, 'reports/requirements-summary.json': summary_text, 'docs/REQUIREMENTS.md': req_md}
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

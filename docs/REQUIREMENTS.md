# Requirements traceability

All **211** numbered rows in the supplied SRS are preserved in `requirements.csv`: **166 functional** and **45 non-functional**. No missing requirements were silently removed or treated as optional. Original source language, minimum acceptance, evidence method, accountable role, baseline and current gap are recorded. Named human owners remain unassigned, which itself prevents production acceptance.

`VERIFIED_IN_ENGINEERING_PROFILE` means a production-binding test that asserts on the requirement ran and passed in the committed TAP — the narrow software behavior was exercised under that citation gate, not proven, and the full real-system or hardware claim is not thereby satisfied. `PARTIAL` means relevant code or analysis exists but material acceptance remains. `NOT_IMPLEMENTED` explicitly identifies functionality absent from the build. `BLOCKED_EXTERNAL` identifies absent hardware, customer resources or independent/organisational evidence. No row is marked production-approved.

The trace references tests by requirement IDs and source modules. Reports are stored under `reports/`. Some tests exercise only the safe-rejection side of a requirement (for example rejecting software signatures under hardware-required policy); that does **not** implement the missing hardware path.

Status counts: {"VERIFIED_IN_ENGINEERING_PROFILE": 173, "PARTIAL": 20, "BLOCKED_EXTERNAL": 16, "NOT_IMPLEMENTED": 2}.

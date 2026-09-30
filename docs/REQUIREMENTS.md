# Requirements traceability

All **211** numbered rows in the supplied SRS are preserved in `requirements.csv`: **166 functional** and **45 non-functional**. No missing requirements were silently removed or treated as optional. Original source language, minimum acceptance, evidence method, accountable role, baseline and current gap are recorded. Named human owners remain unassigned, which itself prevents production acceptance.

`VERIFIED_IN_ENGINEERING_PROFILE` means the narrow software behavior was exercised, not that the full real-system or hardware claim is satisfied. `PARTIAL` means relevant code or analysis exists but material acceptance remains. `NOT_IMPLEMENTED` explicitly identifies functionality absent from the build. `BLOCKED_EXTERNAL` identifies absent hardware, customer resources or independent/organisational evidence. No row is marked production-approved.

The trace references tests by requirement IDs and source modules. Reports are stored under `reports/`. Some tests exercise only the safe-rejection side of a requirement (for example rejecting software signatures under hardware-required policy); that does **not** implement the missing hardware path.

Status counts: {"NOT_IMPLEMENTED": 32, "VERIFIED_IN_ENGINEERING_PROFILE": 55, "PARTIAL": 96, "BLOCKED_EXTERNAL": 28}.

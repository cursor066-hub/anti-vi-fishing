import { digest } from './canonical.mjs';
import { signed } from './crypto.mjs';
import { fields, identifier, oneOf, integer, text } from './schema.mjs';
import { requireThat } from './errors.mjs';

// The SRS path-class taxonomy (COV-001): every declared path must carry the
// execution class it covers so 'unknown' cannot hide behind a vague label.
export const PATH_CLASSES = ['web_ui', 'mobile', 'api', 'cli', 'batch', 'import', 'service_account', 'direct_database', 'recovery', 'emergency'];

export function declarePath(input, now) {
  fields(input, ['path_id', 'action_type', 'target', 'environment', 'connector_version', 'owner', 'status', 'max_age_ms', 'configuration_digest'], ['path_class', 'connector_key_id']);
  for (const f of ['path_id', 'target', 'owner']) identifier(input[f], f);
  if (input.connector_key_id !== undefined) identifier(input.connector_key_id, 'connector_key_id');
  for (const f of ['action_type', 'environment', 'connector_version']) text(input[f], f, 128);
  // Full SRS taxonomy (COV-002): ENFORCED is reserved to independently
  // validated paths (set only by technical-validation transitions), UNCOVERED
  // is an honest "known unprotected" declaration distinct from UNKNOWN
  // ("status not established").
  oneOf(input.status, ['MONITORED', 'UNKNOWN', 'UNCOVERED'], 'manually declared status'); integer(input.max_age_ms, 'maximum evidence age', 1000, 2592000000);
  oneOf(input.path_class ?? 'api', PATH_CLASSES, 'path class');
  requireThat(/^[a-f0-9]{64}$/.test(input.configuration_digest), 'INV-400-SCHEMA', 'Configuration digest is required');
  // Declaration counts as the latest observation for observed states;
  // UNCOVERED carries no observation and never silently upgrades.
  const observed = input.status !== 'UNCOVERED';
  return { ...input, path_class: input.path_class ?? 'api', declared_at: now, evidence_at: observed ? now : null, evidence_digest: null, technical_validation: null };
}
// A drifted or stale connector invalidates dependent paths: their status
// moves to UNKNOWN until evidence is re-attached. Returns the transitioned
// paths so the caller can emit owner tasks for each (COV-005).
export function applyDriftToPaths(paths, matcher) {
  const transitioned = [];
  for (const p of paths) if ((p.status === 'MONITORED' || p.status === 'ENFORCED') && matcher(p)) { p.status = 'UNKNOWN'; p.evidence_at = null; transitioned.push(p); }
  return transitioned;
}
// Effective status at a point in time: staleness is computed, not stored,
// so 'MONITORED' cannot be asserted after evidence has aged out.
export function effectiveStatus(path, now) {
  if (path.status === 'UNCOVERED') return 'UNCOVERED';
  return path.evidence_at !== null && now - path.evidence_at > path.max_age_ms ? 'UNKNOWN' : path.status;
}
// COV-009: reconstruct path status at an arbitrary historical instant from
// the append-only coverage event log. Audit claims about the past must
// reflect what was known then, not what is known now.
export function coverageAt(events, now) {
  const paths = {};
  // Replay must run oldest→newest: the store lists newest-first, and letting
  // the oldest event be applied last falsifies every historical answer
  // (w7-seam F2). The sort is stable on `at` — same-millisecond events keep
  // their insertion order, so a drift transition can never replay before
  // the declaration that preceded it (w8-composite F10). Callers must pass
  // events in write order.
  const ordered = [...events].sort((a, b) => a.at - b.at);
  for (const e of ordered.filter(e => e.at <= now)) {
    const s = paths[e.path_id] ?? {};
    if (e.type === 'declared') Object.assign(s, e.path);
    if (e.type === 'transitioned') { s.status = e.to; s.evidence_at = e.evidence_at; }
    if (e.type === 'technical_validation') { s.technical_validation = e.validation; s.evidence_at = e.at; }
    paths[e.path_id] = s;
  }
  // The replayed state is evaluated at the query instant: an evidence window
  // that has since lapsed cannot keep a path MONITORED in the answer.
  const out = {};
  for (const [id, s] of Object.entries(paths)) out[id] = { ...s, path_id: id, status: effectiveStatus(s, now), stored_status: s.status };
  return out;
}
export function coverageManifest(tenant, paths, now, sign, { unanchored = [], missing = [], obligations = [] } = {}) {
  const effective = paths.map(p => ({ ...p, anchored: true, effective_status: effectiveStatus(p, now), next_action: p.status === 'ENFORCED' ? 'Revalidate before evidence expires; verify all bypass paths.' : p.status === 'UNCOVERED' ? 'Close this path or bring it under enforced coverage; it is declared unprotected.' : 'Attach independently executed technical bypass evidence.' }));
  // Rows without a ledger-anchored COVERAGE_DECLARED event are excluded —
  // the manifest names them honestly instead of attesting their state
  // (w17-redteam A3). Paths declared on chain but deleted from rows are
  // named in missing_rows; open obligations derive from anchored status so
  // erased task rows can never hide them (w31-coverage F1/F6).
  // This distribution provides a simulator, not target-wide total mediation.
  return sign({ tenant_id: tenant, issued_at: now, profile: 'software-engineering', guarantee: false, assurance: 'NO_PRODUCTION_ENFORCEMENT_GUARANTEE', reason: 'Real target coverage and independent bypass assessment have not been supplied.', paths: effective, unanchored_rows: unanchored, missing_rows: missing, open_obligations: obligations, scope_digest: digest(effective) }, 'coverage');
}

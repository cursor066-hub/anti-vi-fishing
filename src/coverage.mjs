import { digest } from './canonical.mjs';
import { signed } from './crypto.mjs';
import { fields, identifier, oneOf, integer, text } from './schema.mjs';
import { requireThat } from './errors.mjs';

export function declarePath(input, now) {
  fields(input, ['path_id', 'action_type', 'target', 'environment', 'connector_version', 'owner', 'status', 'max_age_ms', 'configuration_digest']);
  for (const f of ['path_id', 'target', 'owner']) identifier(input[f], f);
  for (const f of ['action_type', 'environment', 'connector_version']) text(input[f], f, 128);
  oneOf(input.status, ['MONITORED', 'UNKNOWN'], 'manually declared status'); integer(input.max_age_ms, 'maximum evidence age', 1000, 2592000000);
  requireThat(/^[a-f0-9]{64}$/.test(input.configuration_digest), 'INV-400-SCHEMA', 'Configuration digest is required');
  // Declaration counts as the latest observation: staleness and drift can
  // later move the path to UNKNOWN when evidence_at ages out or is cleared.
  return { ...input, declared_at: now, evidence_at: now, evidence_digest: null, technical_validation: null };
}
// A drifted or stale connector invalidates dependent paths: their status
// moves to UNKNOWN until evidence is re-attached.
export function applyDriftToPaths(paths, matcher) {
  let staled = 0;
  for (const p of paths) if (p.status === 'MONITORED' && matcher(p)) { p.status = 'UNKNOWN'; p.evidence_at = null; staled++; }
  return staled;
}
export function coverageManifest(tenant, paths, now, sign) {
  const effective = paths.map(p => ({ ...p, effective_status: p.evidence_at !== null && now - p.evidence_at > p.max_age_ms ? 'UNKNOWN' : p.status, next_action: p.status === 'ENFORCED' ? 'Revalidate before evidence expires; verify all bypass paths.' : 'Attach independently executed technical bypass evidence.' }));
  // This distribution provides a simulator, not target-wide total mediation.
  return sign({ tenant_id: tenant, issued_at: now, profile: 'software-engineering', guarantee: false, assurance: 'NO_PRODUCTION_ENFORCEMENT_GUARANTEE', reason: 'Real target coverage and independent bypass assessment have not been supplied.', paths: effective, scope_digest: digest(effective) }, 'coverage');
}

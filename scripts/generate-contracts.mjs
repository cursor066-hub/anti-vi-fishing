import { writeFileSync } from 'node:fs';
import { SCHEMAS, SUPPORTED_CURRENCIES } from '../src/schema.mjs';
import { digest } from '../src/canonical.mjs';
const type = { text: { type: 'string', minLength: 1, maxLength: 512 }, id: { type: 'string', pattern: '^[A-Za-z0-9][A-Za-z0-9_.:-]*$', maxLength: 128 }, positive: { type: 'integer', minimum: 1, maximum: 1000000000000 }, currency: { type: 'string', enum: SUPPORTED_CURRENCIES }, account: { type: 'string', pattern: '^[A-Z0-9-]{6,64}$' }, hash: { type: 'string', pattern: '^[a-f0-9]{64}$' }, strings: { type: 'array', uniqueItems: true, maxItems: 256, items: { type: 'string', minLength: 1, maxLength: 128 } }, object: { type: 'object' } };
const object = (properties, required = Object.keys(properties)) => ({ type: 'object', additionalProperties: false, required, properties });
const Str = { type: 'string' }, Int = { type: 'integer' }, Ref = name => ({ $ref: `#/components/schemas/${name}` });
const components = {
  Error: object({ error: object({ code: Str, message: Str, request_id: Str }) }),
  Envelope: object({ protected: object({ profile: { const: 'IF-CJSON-1' }, suite: { enum: ['Ed25519', 'ES256'] }, key_id: Str, purpose: Str }), payload: { type: 'object' }, signature: { type: 'string', pattern: '^[A-Za-z0-9_-]{43,128}$' } }),
  State: object({ version: { type: 'integer', minimum: 0 }, digest: type.hash, material_fields: { type: 'object' } }),
  Empty: object({}),
  CertificateRequest: object({ capsule_id: type.id }),
  ExecuteRequest: object({ certificate: Ref('Envelope'), dry_run: { type: 'boolean' } }),
  Revocation: object({ kind: { enum: ['certificate', 'evidence', 'issuer', 'key', 'subject', 'device', 'capability', 'grant', 'token'] }, id: type.id, reason: type.text, remediation_service: type.text }, ['kind', 'id', 'reason']),
  CoverageDeclaration: object({ path_id: type.id, action_type: Str, target: type.id, environment: Str, connector_version: Str, owner: type.id, status: { enum: ['MONITORED', 'UNKNOWN', 'UNCOVERED'] }, path_class: { enum: ['web_ui', 'mobile', 'api', 'cli', 'batch', 'import', 'service_account', 'direct_database', 'recovery', 'emergency'] }, connector_key_id: type.id, max_age_ms: { type: 'integer', minimum: 1000, maximum: 2592000000 }, configuration_digest: type.hash }, ['path_id', 'action_type', 'target', 'environment', 'connector_version', 'owner', 'status', 'max_age_ms', 'configuration_digest']),
  AuditRequest: object({ purpose: type.text }),
  BatchApproval: object({ capsule_ids: { type: 'array', items: type.id, minItems: 2, maxItems: 32, uniqueItems: true }, signatures: { type: 'array', items: Ref('Envelope'), minItems: 2, maxItems: 32 } }),
  RetentionHold: object({ evidence_id: type.id, legal_hold: { type: 'boolean' } }),
  Session: object({ token: { type: 'string', minLength: 43, maxLength: 43 } }),
  Policy: { type: 'object', description: 'Strict executable schema is validatePolicy in src/policy.mjs; examples/default-policy.json is the complete schema-shaped instance. Unknown fields and governance weakening are rejected.' },
  CapabilityRequest: object({ device_id: type.id, resource: type.id, destination: type.text, action: { enum: ['data.read', 'service.connect'] }, purpose: type.text, columns: type.strings, row_ids: type.strings, classification: type.text, jurisdiction: type.text, max_cost: { type: 'integer', minimum: 1, maximum: 1000000000 }, ttl_ms: { type: 'integer', minimum: 1000, maximum: 300000 }, transforms: { type: 'object', description: 'Column-keyed transform policy ({op: mask|tokenise|drop|constant|aggregate})' } }),
  ProposalRequest: object({ input: Ref('Proposal'), signature: Ref('Envelope') }),
  RuntimeRequest: object({ capability: Ref('Envelope'), device_id: type.id, resource: type.id, destination: type.text, action: Str, purpose: type.text, columns: type.strings, row_ids: type.strings, request_id: type.id, protocol: { const: 'https' }, port: { const: 443 } }),
  AcquireEvidence: object({ issuer: type.id, kind: type.text, claims: { type: 'object' } }, ['issuer', 'kind', 'claims']),
  PerceptionSession: object({ attestation: { type: 'object' } }),
  PerceptionRelease: object({ session_id: type.id, fields: { type: 'object' }, purpose: type.text, capsule_id: type.id, evidence_ref: type.id }, ['session_id', 'fields', 'purpose']),
  PerceptionFallback: object({ fields: { type: 'object' }, purpose: type.text, reason: type.text, capsule_id: type.id, evidence_ref: type.id }, ['fields', 'purpose']),
  Advisory: object({ operation: { enum: ['extract', 'explain', 'intent'] }, document: { type: 'string', maxLength: 1000000 }, capsule_id: type.id }, ['operation']),
  // tenant_id is optional, not required: the fabric binds the ceremony to the
  // authenticated principal's tenant — a caller-supplied tenant_id is ignored
  // (declaring it required would claim an input the server never reads).
  CeremonyCreate: object({ ceremony_id: type.id, tenant_id: type.id, purpose: { type: 'string', minLength: 1, maxLength: 64 }, threshold: { type: 'integer', minimum: 2, maximum: 16 }, custodians: { type: 'array', items: type.id, minItems: 2, maxItems: 16, uniqueItems: true }, valid_until: { type: 'integer', minimum: 1 }, min_delay_ms: { type: 'integer', minimum: 0, maximum: 2592000000 }, devices: { type: 'object', description: 'Optional custodian→device_id binding map' }, rotation: object({ key_class: { enum: ['execution', 'audit'] }, new_key_id: type.id }) }, ['ceremony_id', 'purpose', 'threshold', 'custodians', 'valid_until']),
  // The acknowledgement body is the signed envelope itself.
  CeremonyAcknowledge: Ref('Envelope'),
  CeremonySplit: object({ secret: { type: 'string', minLength: 1, maxLength: 8192 } }),
  CeremonyReconstruct: object({ shares: { type: 'array', items: Str, minItems: 2, maxItems: 16 } }),
  RotatePrepare: object({ key_class: type.text, suite: { enum: ['Ed25519', 'ES256'] } }, ['key_class']),
  ProofVerify: object({ proof: { type: 'object' }, pin: object({ root: type.hash, size: type.positive }) }, ['proof'])
};
const variants = [];
for (const s of Object.values(SCHEMAS)) {
  const name = s.type.replaceAll('.', '_');
  const variant = object({ schema_id: { const: s.id }, schema_digest: { const: digest(s) }, actor: object({ subject_id: type.id, identity_class: { enum: ['workforce', 'workload', 'device', 'counterparty'] }, device_id: type.id }), action: object({ type: { const: s.type }, target_resource: type.id, purpose: type.text }), current_state: Ref('State'), requested_state: object(Object.fromEntries(Object.entries(s.requested).map(([k, v]) => [k, type[v]]))), destination: type.text, quantity: type.positive, exclusions: type.strings, evidence_refs: type.strings, policy_version: { type: 'integer', minimum: 1 }, nonce: { ...type.id, minLength: 16 }, created_at: Int, expires_at: Int, rollback_or_compensation: type.text, privacy_classification: { enum: ['internal', 'confidential', 'restricted'] } });
  components[name] = variant; variants.push(Ref(name));
}
components.Proposal = { oneOf: variants };
const paths = {};
function operation(path, method, description, role, request = null, status = 200) {
  const op = { operationId: method + path.replace(/[^a-zA-Z0-9]+/g, '_'), summary: description, description: `Roles: ${role}. Engineering profile; all target mutations are simulated.`, tags: [path.startsWith('/gate') ? 'Gate' : 'Control'], responses: { [status]: { description: 'Successful response; see API.md for exact record contracts', content: { 'application/json': { schema: { type: 'object' } } } }, default: { description: 'Reason-coded rejection', content: { 'application/json': { schema: Ref('Error') } } } } };
  if (request) op.requestBody = { required: true, content: { 'application/json': { schema: Ref(request) } } };
  const params = [...path.matchAll(/\{([^}]+)\}/g)].map(m => ({ name: m[1], in: 'path', required: true, schema: m[1] === 'sequence' ? { type: 'integer', minimum: 1 } : path.startsWith('/gate') || path.includes('resources') || path.includes('keys') || path.includes('ceremonies') ? type.id : { type: 'string', pattern: '^[A-Za-z0-9-]+$', maxLength: 128 } }));
  if (path === '/v1/action-capsules' && method === 'post') params.push({ name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', pattern: '^[A-Za-z0-9_-]{8,128}$' } });
  if (path === '/v1/audit/entries' && method === 'get') params.push(
    { name: 'cursor', in: 'query', required: false, schema: { type: 'integer', minimum: 0 } },
    { name: 'limit', in: 'query', required: false, schema: { type: 'integer', minimum: 1, maximum: 5000 } },
    { name: 'view', in: 'query', required: false, schema: { type: 'string', enum: ['finance', 'privacy', 'technical'] } });
  const qintSchema = (min, max) => ({ type: 'integer', minimum: min, ...(max ? { maximum: max } : {}), description: 'Canonical decimal integer grammar only (no hex/exponent/float/signed spellings); unknown or duplicate query parameters are rejected' });
  if (path === '/v1/coverage/history' && method === 'get') params.push({ name: 'at', in: 'query', required: false, schema: qintSchema(0, 1e14) });
  if (path === '/v1/audit/consistency' && method === 'get') params.push({ name: 'first', in: 'query', required: false, schema: qintSchema(1, 1e12) });
  if (path === '/v1/action-capsules' && method === 'get') params.push(
    { name: 'limit', in: 'query', required: false, schema: qintSchema(1, 100) },
    { name: 'offset', in: 'query', required: false, schema: qintSchema(0, 1e6) });
  if (path === '/v1/certificates' && method === 'get') params.push(
    { name: 'limit', in: 'query', required: false, schema: qintSchema(1, 200) },
    { name: 'offset', in: 'query', required: false, schema: qintSchema(0, 1e6) });
  if (path === '/v1/grants' && method === 'get') params.push({ name: 'subject', in: 'query', required: false, schema: type.id });
  if (path === '/v1/action-capsules/{id}/approval-challenge' && method === 'get') params.push({ name: 'signer_id', in: 'query', required: false, schema: type.id });
  if (path === '/v1/keys/{id}/attest' && method === 'get') params.push({ name: 'nonce', in: 'query', required: false, schema: { type: 'string', maxLength: 128, description: 'Caller-supplied challenge bound into the signed attestation — without it the artifact is freely replayable' } });
  if (params.length) op.parameters = params;
  paths[path] ??= {}; paths[path][method] = op;
  if (PUBLIC_PATHS.has(path)) op.security = [];
}
const PUBLIC_PATHS = new Set(['/healthz', '/readyz', '/', '/app.js', '/style.css']);
for (const row of [
 ['/healthz','get','Liveness','unauthenticated'], ['/readyz','get','Readiness (db probe)','unauthenticated'],
 ['/','get','Operator console HTML (static asset)','unauthenticated'], ['/app.js','get','Operator console script (static asset)','unauthenticated'], ['/style.css','get','Operator console stylesheet (static asset)','unauthenticated'],
 ['/v1/me','get','Current principal','authenticated'], ['/v1/schemas','get','Typed schema definitions and digests','authenticated'], ['/v1/policy','get','Read active constitution','operator, approver, custodian, policy_admin, security, auditor'],
 ['/v1/action-capsules','get','List capsules (limit 1–100 and offset)','operator, approver, custodian, security, policy_admin, auditor'], ['/v1/action-capsules','post','Propose exact action (input + capsule-intent envelope signed by the actor identity key)','operator, policy_admin, workload','ProposalRequest',201], ['/v1/action-capsules/{id}','get','Read exact capsule','operator, approver, custodian, security, policy_admin, auditor'],
 ['/v1/action-capsules/{id}/evidence','post','Attach a pre-signed evidence envelope','operator, security, policy_admin','Envelope',201], ['/v1/action-capsules/{id}/acquire-evidence','post','Pull signed evidence from a live issuer daemon (fabric derives binding claims)','operator, security, policy_admin','AcquireEvidence',201],
 ['/v1/action-capsules/{id}/evaluate','post','Evaluate deterministic policy','operator, policy_admin, approver, custodian','Empty'], ['/v1/action-capsules/{id}/cancel','post','Cancel undispatched authority','operator, security, policy_admin','Empty'], ['/v1/action-capsules/{id}/approval-challenge','get','Get exact digest-bound challenge','approver, custodian'],
 ['/v1/approvals','post','Submit offline-signed approval','approver, custodian','Envelope',201], ['/v1/approvals/batch','post','Batch-approve a declared 2-32 action set (one signature per capsule)','approver, custodian','BatchApproval',201], ['/v1/containment','get','Reconstruct the denied-consume / quarantine containment sequence','operator, security, auditor, policy_admin'],
 ['/v1/certificates','get','List certificates (limit 1–200 and offset)','operator, security, auditor, policy_admin'], ['/v1/certificates','post','Mint single-use authority after ALLOW','operator, policy_admin','CertificateRequest',201], ['/v1/certificates/{id}','get','Read issued certificate','operator, policy_admin, security'],
 ['/gate/v1/execute','post','Verify and execute or dry-run simulated target','operator, policy_admin','ExecuteRequest'], ['/gate/v1/outcomes/{id}','get','Read recorded outcome (read-only)','operator, security, policy_admin'], ['/gate/v1/outcomes/{id}','post','Reconcile target journal (may append outcome evidence)','operator, security, policy_admin'],
 ['/v1/resources/{id}','get','Read non-dataset synthetic target state','operator, policy_admin'], ['/v1/capabilities','post','Issue narrow local capability','operator, workload','CapabilityRequest',201], ['/gate/v1/runtime','post','Consume capability under shared budgets','bound subject','RuntimeRequest'],
 ['/v1/revocations','post','Permanently revoke local authority','security','Revocation',201], ['/v1/revocations','get','List revocations','operator, security, auditor, policy_admin'],
 ['/v1/coverage','get','Read signed conservative coverage manifest','operator, approver, custodian, security, auditor, policy_admin'], ['/v1/coverage','post','Declare monitored or unknown path','security','CoverageDeclaration',201], ['/v1/coverage/history','get','Coverage state reconstructed at instant ?at=','operator, approver, custodian, security, auditor, policy_admin'], ['/v1/coverage/{id}/technical-validation','post','Attach independently executed validation evidence to a path','security','Envelope'],
 ['/v1/connectors','get','Read simulator connector limitations','operator, security, policy_admin, auditor'], ['/v1/connectors/status','get','Issuer and target connector status incl. drift','operator, security, policy_admin, auditor'], ['/v1/connectors/{id}/drift-check','post','Live manifest drift check against issuer endpoint','security, policy_admin'],
 ['/v1/policies/simulate','post','Compare exact candidate without activation','policy_admin, security','Policy'], ['/v1/policy/history','get','Staged and historical policy versions','operator, security, auditor, policy_admin'], ['/v1/policy/reanchor','post','Re-anchor a diverged active policy under a signed remediation event','security','Empty'],
 ['/v1/audit-exports','post','Export audited purpose-bound integrity metadata','auditor, security','AuditRequest'],
 ['/v1/audit/entries','get','Paginated audit view (cursor + limit 1–5000)','operator, security, auditor, policy_admin'], ['/v1/audit/proofs/{sequence}','get','RFC 6962 inclusion proof','operator, security, auditor'], ['/v1/audit/consistency','get','Consistency proof between tree sizes','operator, security, auditor'], ['/v1/audit/verify-proof','post','Verify a supplied inclusion proof (optional external pin {root,size})','operator, security, auditor','ProofVerify'], ['/v1/audit/seal','post','Seal a poisoned audit tail: drops unverifiable rows under a signed AUDIT_SEALED event','security'],
 ['/v1/subjects','get','Identity inventory','operator, security, auditor, policy_admin'], ['/v1/grants','get','Active JIT grants','operator, security, auditor'],
 ['/v1/retention/hold','post','Set or release evidence legal hold','security','RetentionHold'], ['/v1/retention/sweep','post','Apply conservative logical retention','security','Empty'], ['/v1/metrics','get','Read process-wide counters without target payloads','security'],
 ['/v1/ceremonies','get','List key ceremonies','security, custodian, policy_admin'], ['/v1/ceremonies','post','Plan a threshold ceremony','security, custodian','CeremonyCreate',201],
 ['/v1/ceremonies/{id}/acknowledge','post','Custodian acknowledges participation','custodian','CeremonyAcknowledge'], ['/v1/ceremonies/{id}/split','post','Split exportable material into committed shares','security, custodian','CeremonySplit'], ['/v1/ceremonies/{id}/reconstruct','post','Reconstruct under ceremony quorum (digest returned, not material)','security, custodian','CeremonyReconstruct'], ['/v1/ceremonies/{id}/abort','post','Abort a live ceremony (security officer or member custodian)','security, custodian','Empty'],
 ['/v1/keys','get','List vault keys (public metadata only)','security, policy_admin'], ['/v1/keys/rotate-prepare','post','Pre-stage a pending rotation key','security, custodian','RotatePrepare',201], ['/v1/keys/{id}/attest','get','Vault-signed key attestation','security, auditor'],
 ['/v1/config-drift','get','Configuration drift status','security, policy_admin'], ['/v1/config-drift/reassert','post','Re-attest config after correction','security'], ['/v1/clock/recover','post','Audited clock repair after stall','security, policy_admin'],
 ['/v1/secure-perception/sessions','post','Open dev-attested sealed perception session','operator, approver, custodian, security','PerceptionSession',201], ['/v1/secure-perception/release','post','Release sealed fields under purpose binding','operator, approver, custodian, security','PerceptionRelease'], ['/v1/secure-perception/fallback','post','Labelled non-perception fallback submission','operator, approver, custodian, security','PerceptionFallback'],
 ['/v1/advisory','post','Deterministic advisory plane (never confers authority)','operator, approver, custodian, security, policy_admin, auditor','Advisory'],
 ['/session','post','Establish same-origin session','token holder','Session'], ['/session/logout','post','Destroy current cookie session','authenticated']
]) operation(...row);
paths['/session'].post.security = [];
const result = { openapi: '3.1.0', info: { title: 'Invariant Fabric engineering API', version: '1.0.0', description: 'Exact-action software enforcement and synthetic target execution. Not a production-certified deployment. JSON is restricted to IF-CJSON-1. Cookie mutations require Origin and X-CSRF-Token; bearer credentials are also supported. Strict runtime validation is authoritative.' }, servers: [{ url: 'http://127.0.0.1:8080' }], security: [{ bearerAuth: [] }], paths, components: { securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer' } }, schemas: components } };
writeFileSync('docs/openapi.json', JSON.stringify(result, null, 2) + '\n');
writeFileSync('examples/schema-catalog.json', JSON.stringify(SCHEMAS, null, 2) + '\n');
const { defaultPolicy } = await import('../src/policy.mjs'); writeFileSync('examples/default-policy.json', JSON.stringify(defaultPolicy('acme'), null, 2) + '\n');
console.log(JSON.stringify({ api_paths: Object.keys(paths).length, action_schemas: Object.keys(SCHEMAS).length }));

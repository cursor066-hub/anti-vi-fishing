import { writeFileSync } from 'node:fs';
import { SCHEMAS, SUPPORTED_CURRENCIES } from '../src/schema.mjs';
import { digest } from '../src/canonical.mjs';
const type = { text: { type: 'string', minLength: 1, maxLength: 512 }, id: { type: 'string', pattern: '^[A-Za-z0-9][A-Za-z0-9_.:-]*$', maxLength: 128 }, positive: { type: 'integer', minimum: 1, maximum: 1000000000000 }, currency: { type: 'string', enum: SUPPORTED_CURRENCIES }, account: { type: 'string', pattern: '^[A-Z0-9-]{6,64}$' }, hash: { type: 'string', pattern: '^[a-f0-9]{64}$' }, strings: { type: 'array', uniqueItems: true, maxItems: 256, items: { type: 'string', minLength: 1, maxLength: 128 } }, object: { type: 'object' } };
const object = (properties, required = Object.keys(properties)) => ({ type: 'object', additionalProperties: false, required, properties });
const Str = { type: 'string' }, Int = { type: 'integer' }, Ref = name => ({ $ref: `#/components/schemas/${name}` });
const components = {
  Error: object({ error: object({ code: Str, message: Str, request_id: Str }) }),
  Envelope: object({ protected: object({ profile: { const: 'IF-CJSON-1' }, suite: { const: 'Ed25519' }, key_id: Str, purpose: Str }), payload: { type: 'object' }, signature: { type: 'string', pattern: '^[A-Za-z0-9_-]{86}$' } }),
  State: object({ version: { type: 'integer', minimum: 0 }, digest: type.hash, material_fields: { type: 'object' } }),
  Empty: object({}),
  CertificateRequest: object({ capsule_id: type.id }),
  ExecuteRequest: object({ certificate: Ref('Envelope'), dry_run: { type: 'boolean' } }),
  Revocation: object({ kind: { enum: ['certificate', 'evidence', 'issuer', 'key', 'subject', 'device', 'capability'] }, id: type.id, reason: type.text }),
  CoverageDeclaration: object({ path_id: type.id, action_type: Str, target: type.id, environment: Str, connector_version: Str, owner: type.id, status: { enum: ['MONITORED', 'UNKNOWN'] }, max_age_ms: { type: 'integer', minimum: 1000, maximum: 2592000000 }, configuration_digest: type.hash }),
  AuditRequest: object({ purpose: type.text }),
  RetentionHold: object({ evidence_id: type.id, legal_hold: { type: 'boolean' } }),
  Session: object({ token: { type: 'string', minLength: 43, maxLength: 43 } }),
  Policy: { type: 'object', description: 'Strict executable schema is validatePolicy in src/policy.mjs; examples/default-policy.json is the complete schema-shaped instance. Unknown fields and governance weakening are rejected.' },
  CapabilityRequest: object({ device_id: type.id, resource: type.id, destination: type.text, action: { enum: ['data.read', 'service.connect'] }, purpose: type.text, columns: type.strings, row_ids: type.strings, classification: type.text, jurisdiction: type.text, max_cost: { type: 'integer', minimum: 1, maximum: 1000000000 }, ttl_ms: { type: 'integer', minimum: 1000, maximum: 300000 } }),
  RuntimeRequest: object({ capability: Ref('Envelope'), device_id: type.id, resource: type.id, destination: type.text, action: Str, purpose: type.text, columns: type.strings, row_ids: type.strings, request_id: type.id, protocol: { const: 'https' }, port: { const: 443 } })
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
  const params = [...path.matchAll(/\{([^}]+)\}/g)].map(m => ({ name: m[1], in: 'path', required: true, schema: type.id }));
  if (path === '/v1/action-capsules' && method === 'post') params.push({ name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', pattern: '^[A-Za-z0-9_-]{8,128}$' } });
  if (params.length) op.parameters = params;
  paths[path] ??= {}; paths[path][method] = op;
}
for (const row of [
 ['/v1/me','get','Current principal','authenticated'], ['/v1/schemas','get','Typed schema definitions and digests','authenticated'], ['/v1/policy','get','Read active constitution','operator, approver, custodian, policy_admin, security'],
 ['/v1/action-capsules','get','List capsules (limit 1–100 and offset)','operator, approver, custodian, security, policy_admin'], ['/v1/action-capsules','post','Propose exact action','operator, policy_admin, workload','Proposal',201], ['/v1/action-capsules/{id}','get','Read exact capsule','operator, approver, custodian, security, policy_admin'],
 ['/v1/action-capsules/{id}/evidence','post','Attach signed evidence','operator, security, policy_admin','Envelope',201], ['/v1/action-capsules/{id}/evaluate','post','Evaluate deterministic policy','operator, policy_admin, approver, custodian','Empty'], ['/v1/action-capsules/{id}/cancel','post','Cancel undispatched authority','operator, security, policy_admin','Empty'], ['/v1/action-capsules/{id}/approval-challenge','get','Get exact digest-bound challenge','approver, custodian'],
 ['/v1/approvals','post','Submit offline-signed approval','approver, custodian','Envelope',201], ['/v1/certificates','post','Mint single-use authority after ALLOW','operator, policy_admin','CertificateRequest',201], ['/v1/certificates/{id}','get','Read issued certificate','operator, policy_admin, security'],
 ['/gate/v1/execute','post','Verify and execute or dry-run simulated target','operator, policy_admin','ExecuteRequest'], ['/gate/v1/outcomes/{id}','get','Reconcile target journal (may append outcome evidence)','operator, policy_admin, security'],
 ['/v1/resources/{id}','get','Read non-dataset synthetic target state','operator, policy_admin'], ['/v1/capabilities','post','Issue narrow local capability','operator, workload','CapabilityRequest',201], ['/gate/v1/runtime','post','Consume capability under shared budgets','bound subject','RuntimeRequest'],
 ['/v1/revocations','post','Permanently revoke local authority','security','Revocation',201], ['/v1/coverage','get','Read signed conservative coverage manifest','operator, approver, custodian, security, auditor, policy_admin'], ['/v1/coverage','post','Declare monitored or unknown path','security','CoverageDeclaration',201],
 ['/v1/connectors','get','Read simulator connector limitations','authenticated'], ['/v1/policies/simulate','post','Compare exact candidate without activation','policy_admin, security','Policy'], ['/v1/audit-exports','post','Export audited purpose-bound integrity metadata','auditor, security','AuditRequest'],
 ['/v1/retention/hold','post','Set or release evidence legal hold','security','RetentionHold'], ['/v1/retention/sweep','post','Apply conservative logical retention','security','Empty'], ['/v1/metrics','get','Read process-wide counters without target payloads','security'],
 ['/session','post','Establish same-origin session','token holder','Session'], ['/session/logout','post','Destroy current cookie session','authenticated','Empty']
]) operation(...row);
paths['/session'].post.security = [];
const result = { openapi: '3.1.0', info: { title: 'Invariant Fabric engineering API', version: '1.0.0', description: 'Exact-action software enforcement and synthetic target execution. Not a production-certified deployment. JSON is restricted to IF-CJSON-1. Cookie mutations require Origin and X-CSRF-Token; bearer credentials are also supported. Strict runtime validation is authoritative.' }, servers: [{ url: 'http://127.0.0.1:8080' }], security: [{ bearerAuth: [] }], paths, components: { securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer' } }, schemas: components } };
writeFileSync('docs/openapi.json', JSON.stringify(result, null, 2) + '\n');
writeFileSync('examples/schema-catalog.json', JSON.stringify(SCHEMAS, null, 2) + '\n');
const { defaultPolicy } = await import('../src/policy.mjs'); writeFileSync('examples/default-policy.json', JSON.stringify(defaultPolicy('acme'), null, 2) + '\n');
console.log(JSON.stringify({ api_paths: Object.keys(paths).length, action_schemas: Object.keys(SCHEMAS).length }));

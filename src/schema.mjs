import { digest, canonical } from './canonical.mjs';
import { requireThat, invalid } from './errors.mjs';

export function fields(value, required, optional = []) {
  requireThat(value && typeof value === 'object' && !Array.isArray(value), 'INV-400-SCHEMA', 'Expected object');
  for (const key of required) if (!Object.hasOwn(value, key)) throw invalid(`Missing field: ${key}`);
  for (const key of Object.keys(value)) if (!required.includes(key) && !optional.includes(key)) throw invalid(`Unknown field: ${key}`);
}
export function text(value, name, max = 512) { requireThat(typeof value === 'string' && value.trim().length > 0 && value.length <= max && !/[\x00-\x1F\x7F]/.test(value), 'INV-400-SCHEMA', `Invalid ${name}`); return value; }
export function identifier(value, name = 'identifier') { text(value, name, 128); requireThat(/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/.test(value), 'INV-400-SCHEMA', `Invalid ${name}`); return value; }
export function integer(value, name, min = 0, max = Number.MAX_SAFE_INTEGER) { requireThat(Number.isSafeInteger(value) && value >= min && value <= max, 'INV-400-SCHEMA', `Invalid ${name}`); return value; }
export function oneOf(value, values, name) { requireThat(values.includes(value), 'INV-400-SCHEMA', `Unsupported ${name}`); return value; }
export function uniqueStrings(value, name, max = 64) {
  requireThat(Array.isArray(value) && value.length <= max && new Set(value).size === value.length, 'INV-400-SCHEMA', `Invalid ${name}`);
  value.forEach(v => text(v, name, 128)); return value;
}
export const SUPPORTED_CURRENCIES = ['EUR', 'USD', 'GBP', 'CHF', 'CAD', 'AUD', 'NZD', 'SGD'];
const types = {
  'finance.vendor.create': { name: 'text', tax_id: 'text', bank_account: 'account', currency: 'currency' },
  'finance.bank.change': { bank_account: 'account', currency: 'currency' },
  'finance.beneficiary.create': { vendor_id: 'id', bank_account: 'account', currency: 'currency' },
  'finance.payment.first': { beneficiary_id: 'id', bank_account: 'account', amount_minor: 'positive', currency: 'currency', invoice_id: 'id' },
  'data.export': { dataset: 'id', columns: 'strings', row_ids: 'strings', max_rows: 'positive', classification: 'text', jurisdiction: 'text' },
  'identity.mfa.reset': { subject_id: 'id', authenticator_id: 'id' },
  'identity.authenticator.enroll': { subject_id: 'id', credential_digest: 'hash' },
  'identity.account.recover': { subject_id: 'id', privilege: 'text' },
  'cloud.firewall.change': { protocol: 'text', port: 'positive', source_cidr: 'text', service_id: 'id' },
  'code.release': { source_commit: 'hash', artifact_digest: 'hash', provenance_digest: 'hash', test_digest: 'hash', deployment_target: 'id' },
  'secret.use': { secret_id: 'id', operation: 'text', workload_id: 'id' },
  'backup.delete': { backup_id: 'id', recovery_set: 'id' },
  'policy.change': { policy: 'object' }
};
export const SCHEMAS = Object.fromEntries(Object.entries(types).map(([type, requested]) => [type, { id: `if:${type}:1`, version: 1, type, requested, validation_profile: 'IF-ACTION-1', currency_profile: { codes: SUPPORTED_CURRENCIES, minor_units_per_major: 100 } }]));
export function validateRequested(type, requested) {
  const schema = SCHEMAS[type]; requireThat(schema, 'INV-400-SCHEMA', 'Unsupported action type'); fields(requested, Object.keys(schema.requested));
  for (const [key, rule] of Object.entries(schema.requested)) {
    const v = requested[key];
    if (rule === 'text') text(v, key);
    if (rule === 'id') identifier(v, key);
    if (rule === 'positive') integer(v, key, 1, 1_000_000_000_000);
    if (rule === 'strings') uniqueStrings(v, key, 256);
    if (rule === 'currency') requireThat(SUPPORTED_CURRENCIES.includes(v), 'INV-400-SCHEMA', 'Unsupported currency; this profile supports EUR, USD, GBP, CHF, CAD, AUD, NZD and SGD with two decimal minor units');
    if (rule === 'account') requireThat(typeof v === 'string' && /^[A-Z0-9-]{6,64}$/.test(v), 'INV-400-SCHEMA', 'Account must use exact uppercase canonical characters');
    if (rule === 'hash') requireThat(typeof v === 'string' && /^[a-f0-9]{64}$/.test(v), 'INV-400-SCHEMA', `${key} must be a SHA-256 digest`);
    if (rule === 'object') requireThat(v && typeof v === 'object' && !Array.isArray(v), 'INV-400-SCHEMA', `${key} must be an object`);
  }
  if (type === 'data.export') requireThat(requested.columns.length && requested.row_ids.length && requested.max_rows >= requested.row_ids.length, 'INV-400-SCHEMA', 'Export requires explicit nonempty fields and rows within ceiling');
  if (type === 'cloud.firewall.change') { integer(requested.port, 'port', 1, 65535); oneOf(requested.protocol, ['tcp', 'udp'], 'protocol'); }
}
export function validateProposal(input) {
  fields(input, ['schema_id', 'schema_digest', 'actor', 'action', 'current_state', 'requested_state', 'destination', 'quantity', 'exclusions', 'evidence_refs', 'policy_version', 'nonce', 'created_at', 'expires_at', 'rollback_or_compensation', 'privacy_classification']);
  fields(input.actor, ['subject_id', 'identity_class', 'device_id']); identifier(input.actor.subject_id); identifier(input.actor.device_id); oneOf(input.actor.identity_class, ['workforce', 'workload', 'device', 'counterparty'], 'identity class');
  fields(input.action, ['type', 'target_resource', 'purpose']); const schema = SCHEMAS[input.action.type]; requireThat(schema, 'INV-400-SCHEMA', 'Unsupported action type');
  requireThat(input.schema_id === schema.id && input.schema_digest === digest(schema), 'INV-400-SCHEMA', 'Schema identifier or digest mismatch');
  identifier(input.action.target_resource); text(input.action.purpose, 'purpose'); validateRequested(input.action.type, input.requested_state);
  fields(input.current_state, ['version', 'digest', 'material_fields']); integer(input.current_state.version, 'state version');
  requireThat(input.current_state.digest === digest(input.current_state.material_fields), 'INV-400-SCHEMA', 'Current state digest mismatch');
  requireThat(input.current_state.material_fields && typeof input.current_state.material_fields === 'object' && !Array.isArray(input.current_state.material_fields), 'INV-400-SCHEMA', 'Invalid material fields');
  text(input.destination, 'destination', 256); integer(input.quantity, 'quantity', 1, 1_000_000_000_000);
  uniqueStrings(input.exclusions, 'exclusions'); uniqueStrings(input.evidence_refs, 'evidence references');
  integer(input.policy_version, 'policy version', 1); identifier(input.nonce, 'nonce'); requireThat(input.nonce.length >= 16, 'INV-400-SCHEMA', 'Nonce must be at least 16 characters');
  integer(input.created_at, 'created time', 1); integer(input.expires_at, 'expiry', input.created_at + 1);
  text(input.rollback_or_compensation, 'rollback or compensation'); oneOf(input.privacy_classification, ['internal', 'confidential', 'restricted'], 'privacy classification');
  if (input.action.type === 'finance.payment.first') requireThat(input.quantity === input.requested_state.amount_minor && input.destination === input.requested_state.bank_account, 'INV-400-SCHEMA', 'Payment amount/destination mismatch');
  if (input.action.type === 'data.export') requireThat(input.quantity === input.requested_state.row_ids.length && !input.requested_state.columns.some(c => input.exclusions.includes(c)), 'INV-400-SCHEMA', 'Export quantity or exclusions mismatch');
  canonical(input); return input;
}
export function proposal(type, actor, state, requested, now, overrides = {}) {
  const schema = SCHEMAS[type];
  return { schema_id: schema.id, schema_digest: digest(schema), actor, action: { type, target_resource: 'vendor-1', purpose: 'Controlled integration validation' }, current_state: state, requested_state: requested, destination: requested.bank_account ?? 'customer-vault', quantity: requested.amount_minor ?? (requested.row_ids?.length || 1), exclusions: [], evidence_refs: [], policy_version: 1, nonce: crypto.randomUUID(), created_at: now, expires_at: now + 600000, rollback_or_compensation: 'Reconcile before any separately authorised compensation', privacy_classification: 'confidential', ...overrides };
}

import { mkdirSync, writeFileSync, existsSync, chmodSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { generateKey, signed } from './crypto.mjs';
import { hashBytes, canonical } from './canonical.mjs';
import { defaultPolicy } from './policy.mjs';
import { requireThat } from './errors.mjs';
import { Fabric } from './fabric.mjs';

export function createConfiguration(tenantNames = ['acme'], now = Date.now()) {
  const config = { format: 'IF-CONFIG-1', profile: 'engineering', gate_id: 'local-software-gate', tenants: {} }, credentials = {}, custodianKeys = {}, issuerKeys = {};
  for (const tenant of tenantNames) {
    requireThat(/^[a-z][a-z0-9-]{1,31}$/.test(tenant), 'INV-400-SCHEMA', 'Tenant must use lowercase alphanumeric characters');
    const policy = defaultPolicy(tenant), identities = {}, auth = {}, identityPrivate = {};
    const roles = [['operator', ['operator']], ['security', ['security']], ['auditor', ['auditor']], ['policy-admin', ['policy_admin']], ...Array.from({ length: 5 }, (_, i) => [`custodian-${i + 1}`, ['approver', 'custodian']])];
    credentials[tenant] = {}; custodianKeys[tenant] = {}; issuerKeys[tenant] = {};
    for (const [subject, role] of roles) {
      const key = generateKey(), token = randomBytes(32).toString('base64url');
      identities[key.key_id] = { public_key: key.public_key, subject_id: subject, identity_class: 'workforce', roles: role, device_id: `${subject}-device`, failure_domain: `${tenant}-${subject}`, hardware_backed: false, health_expires_at: now + 86400000, grants: { resources: ['dataset-1', 'erp-service'], actions: ['data.read', 'service.connect'], destinations: ['customer-vault', 'erp-service'], columns: ['id', 'name', 'region'], row_ids: ['row-1', 'row-2', 'row-3'] } };
      auth[hashBytes(token)] = { subject_id: subject, expires_at: now + 86400000 }; credentials[tenant][subject] = token; identityPrivate[subject] = key;
      if (role.includes('custodian')) custodianKeys[tenant][subject] = key;
    }
    const issuers = {};
    for (const [name, channel] of [['bank', 'authoritative'], ['registry', 'authoritative'], ['governance', 'authoritative'], ['email', 'communication']]) {
      const key = generateKey(); issuerKeys[tenant][name] = key;
      issuers[key.key_id] = { public_key: key.public_key, failure_domain: `${tenant}-${name}`, channel, kinds: ['ownership', 'dataset_authority', 'identity_proof', 'recovery_authority', 'build_provenance', 'test_result', 'workload_attestation', 'governance_review'] };
    }
    config.tenants[tenant] = { encryption_key: randomBytes(32).toString('base64url'), keys: { execution: generateKey(), audit: generateKey() }, identities, issuers, auth, genesis_policy: policy, genesis_signatures: Object.values(custodianKeys[tenant]).slice(0, 3).map(k => signed(policy, k, 'root-policy')) };
  }
  return { config, credentials, custodianKeys, issuerKeys };
}
export function bootstrap(directory, tenants = ['acme'], now = Date.now()) {
  directory = resolve(directory);
  requireThat(!existsSync(directory), 'INV-409-CONFLICT', 'Refusing to overwrite an existing deployment directory', 409);
  const setup = createConfiguration(tenants, now);
  mkdirSync(directory, { recursive: true, mode: 0o700 }); chmodSync(directory, 0o700);
  const signingDir = join(directory, 'offline-custodians'); mkdirSync(signingDir, { mode: 0o700 });
  const save = (path, value) => writeFileSync(path, canonical(value) + '\n', { mode: 0o600, flag: 'wx' });
  save(join(directory, 'config.json'), setup.config); save(join(directory, 'access-tokens.json'), setup.credentials);
  for (const tenant of tenants) {
    const audit = setup.config.tenants[tenant].keys.audit;
    save(join(directory, `trust-public-${tenant}.json`), { [audit.key_id]: { public_key: audit.public_key } });
    for (const [subject, key] of Object.entries(setup.custodianKeys[tenant])) save(join(signingDir, `${tenant}-${subject}.json`), key);
    for (const [name, key] of Object.entries(setup.issuerKeys[tenant])) save(join(signingDir, `${tenant}-issuer-${name}.json`), key);
  }
  const fabric = new Fabric(setup.config, directory, () => now);
  seedSyntheticResources(fabric, tenants); fabric.close();
  return { directory, config_path: join(directory, 'config.json'), credentials_path: join(directory, 'access-tokens.json'), signing_directory: signingDir, profile: 'engineering', production_ready: false };
}
export function seedSyntheticResources(fabric, tenants) {
  for (const tenant of tenants) {
    fabric.target.seed(tenant, 'beneficiary-1', { bank_account: 'TESTBANK000001', currency: 'EUR', first_payment_done: false, payment_eligible_at: 0 });
    fabric.target.seed(tenant, 'vendor-1', { name: 'Synthetic Vendor', bank_account: 'TESTBANK000001', currency: 'EUR' });
    fabric.target.seed(tenant, 'dataset-1', { columns: ['id', 'name', 'region', 'passport'], classification: 'internal', jurisdiction: 'EU', rows: [{ id: 'row-1', name: 'Synthetic Ada', region: 'EU', passport: 'SYNTHETIC-NOT-REAL-1' }, { id: 'row-2', name: 'Synthetic Lin', region: 'EU', passport: 'SYNTHETIC-NOT-REAL-2' }, { id: 'row-3', name: 'Synthetic Sam', region: 'EU', passport: 'SYNTHETIC-NOT-REAL-3' }] });
  }
}
export function loadConfiguration(directory) { return JSON.parse(readFileSync(join(resolve(directory), 'config.json'), 'utf8')); }

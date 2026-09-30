import { mkdirSync, writeFileSync, existsSync, chmodSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { randomBytes, generateKeyPairSync } from 'node:crypto';
import { generateKey, signed } from './crypto.mjs';
import { hashBytes, canonical, digest } from './canonical.mjs';
import { defaultPolicy } from './policy.mjs';
import { KeyVault } from './keystore.mjs';
import { requireThat } from './errors.mjs';
import { Fabric } from './fabric.mjs';
import { createComponent as createSecureViewComponent } from './secureview.mjs';

// Issuer roles used by the evidence mesh. kinds: what the issuer may attest.
export const ISSUER_ROLES = {
  bank: { channel: 'authoritative', kinds: ['ownership', 'payment_confirmation'] },
  registry: { channel: 'authoritative', kinds: ['ownership', 'dataset_authority', 'identity_proof', 'legal_registry'] },
  governance: { channel: 'authoritative', kinds: ['governance_review'] },
  hris: { channel: 'authoritative', kinds: ['identity_proof', 'recovery_authority'] },
  'device-attestation': { channel: 'device', kinds: ['device_health', 'workload_attestation'] },
  counterparty: { channel: 'counterparty', kinds: ['counterparty_credential', 'ownership'] },
  'build-pipeline': { channel: 'authoritative', kinds: ['build_provenance', 'test_result'] },
  email: { channel: 'communication', kinds: ['ownership', 'identity_proof'] }
};

// Evidence query rules per issuer role: deterministic record lookups used by
// issuerd. `expect` values may bind claim fields with ${claims.x}.
export const ISSUER_RULES = {
  bank: {
    ownership: { lookup: 'account:${claims.account}', expect: { status: 'active', owner: '${claims.owner_id}' }, extract: ['verified_at'], ttl_ms: 300000, confidence: 100 },
    payment_confirmation: { lookup: 'payment:${claims.transaction_id}', expect: { status: 'settled' }, extract: ['amount_minor', 'currency', 'settled_at'], ttl_ms: 600000, confidence: 100 }
  },
  registry: {
    ownership: { lookup: 'account:${claims.account}', expect: { owner: '${claims.owner_id}' }, extract: ['registered_at'], ttl_ms: 3600000, confidence: 96 },
    dataset_authority: { lookup: 'dataset:${claims.dataset}', expect: { steward: '${claims.steward}' }, extract: ['classification', 'jurisdiction'], ttl_ms: 3600000, confidence: 98 },
    identity_proof: { lookup: 'identity:${claims.subject_id}', expect: { proofing: '${claims.level}' }, extract: ['proofed_at'], ttl_ms: 3600000, confidence: 97 },
    legal_registry: { lookup: 'entity:${claims.entity}', expect: { registration: '${claims.registration}' }, extract: ['jurisdiction', 'status'], ttl_ms: 86400000, confidence: 98 }
  },
  governance: {
    governance_review: { lookup: 'review:${claims.ref}', expect: { approved: 'true' }, extract: ['quorum', 'decided_at'], ttl_ms: 86400000, confidence: 100 }
  },
  hris: {
    identity_proof: { lookup: 'employee:${claims.subject_id}', expect: { status: 'active', proofing: '${claims.level}' }, extract: ['employed_since'], ttl_ms: 3600000, confidence: 97 },
    recovery_authority: { lookup: 'recovery:${claims.case_id}', expect: { subject: '${claims.subject_id}', approved: 'true' }, extract: ['approved_by'], ttl_ms: 3600000, confidence: 99 }
  },
  'device-attestation': {
    device_health: { lookup: 'device:${claims.device_id}', expect: { health: 'pass' }, extract: ['firmware_version', 'attested_at'], ttl_ms: 300000, confidence: 96 },
    workload_attestation: { lookup: 'workload:${claims.workload_id}', expect: { attested: 'true' }, extract: ['image_digest', 'attested_at'], ttl_ms: 300000, confidence: 96 }
  },
  counterparty: {
    counterparty_credential: { lookup: 'counterparty:${claims.counterparty_id}', expect: { credential: '${claims.credential_digest}', status: 'active' }, extract: ['issued_at'], ttl_ms: 3600000, confidence: 98 },
    ownership: { lookup: 'account:${claims.account}', expect: { owner: '${claims.owner_id}' }, extract: [], ttl_ms: 3600000, confidence: 94 }
  },
  'build-pipeline': {
    build_provenance: { lookup: 'build:${claims.artifact_digest}', expect: { commit: '${claims.commit}', builder: 'reproducible-ci' }, extract: ['source_repo', 'built_at'], ttl_ms: 86400000, confidence: 99 },
    test_result: { lookup: 'test:${claims.test_digest}', expect: { status: 'pass' }, extract: ['suite', 'ran_at'], ttl_ms: 86400000, confidence: 99 }
  },
  email: {
    ownership: { lookup: 'inbox:${claims.thread_id}', expect: { confirmed: 'true' }, extract: [], ttl_ms: 600000, confidence: 60, advisory: true },
    identity_proof: { lookup: 'inbox:${claims.thread_id}', expect: { confirmed: 'true' }, extract: [], ttl_ms: 600000, confidence: 55, advisory: true }
  }
};

export function issuerRecords(tenant) {
  // Synthetic authority data — clearly labelled, deterministic, safe to ship.
  return {
    bank: {
      'account:TESTBANK000001': { owner: 'vendor-1', status: 'active', verified_at: 1788640000000 },
      'account:TESTBANK000002': { owner: 'vendor-1', status: 'active', verified_at: 1788640000000 },
      'payment:TX-SEED-1': { status: 'settled', amount_minor: 125000, currency: 'EUR', settled_at: 1788640000000 }
    },
    registry: {
      'account:TESTBANK000001': { owner: 'vendor-1', registered_at: 1788000000000 },
      'account:TESTBANK000002': { owner: 'vendor-1', registered_at: 1788000000000 },
      'dataset:dataset-1': { steward: 'operator', classification: 'internal', jurisdiction: 'EU' },
      'identity:operator': { proofing: 'high', proofed_at: 1788000000000 },
      'entity:synthetic-vendor-ltd': { registration: 'REG-SYNTH-001', jurisdiction: 'EU', status: 'active' }
    },
    governance: {
      'review:REV-2026-001': { approved: 'true', quorum: 3, decided_at: 1788600000000 }
    },
    hris: {
      'employee:operator': { status: 'active', proofing: 'high', employed_since: 1700000000000 },
      'recovery:CASE-001': { subject: 'operator', approved: 'true', approved_by: 'hris-board' }
    },
    'device-attestation': {
      'device:operator-device': { health: 'pass', firmware_version: 'if-endpoint-2.1.0', attested_at: 1788640000000 },
      'workload:workload-1': { attested: 'true', image_digest: 'a'.repeat(64), attested_at: 1788640000000 }
    },
    counterparty: {
      'counterparty:CP-SYNTH-1': { credential: 'b'.repeat(64), status: 'active', issued_at: 1788000000000 },
      'account:TESTBANK000001': { owner: 'vendor-1' }
    },
    'build-pipeline': {
      [`build:${'c'.repeat(64)}`]: { commit: 'd'.repeat(64), builder: 'reproducible-ci', source_repo: 'synthetic/app', built_at: 1788640000000 },
      [`test:${'e'.repeat(64)}`]: { status: 'pass', suite: 'synthetic-suite', ran_at: 1788640000000 }
    },
    email: {
      'inbox:THREAD-001': { confirmed: 'true' }
    }
  };
}

export function createConfiguration(tenantNames = ['acme'], now = Date.now(), { vault = null, issuerEndpoint = null } = {}) {
  const config = { format: 'IF-CONFIG-1', profile: 'engineering', gate_id: 'local-software-gate', tenants: {} }, credentials = {}, custodianKeys = {}, issuerKeys = {}, componentSecrets = {};
  for (const tenant of tenantNames) {
    requireThat(/^[a-z][a-z0-9-]{1,31}$/.test(tenant), 'INV-400-SCHEMA', 'Tenant must use lowercase alphanumeric characters');
    const policy = defaultPolicy(tenant), identities = {}, auth = {}, identityPrivate = {};
    const roles = [['operator', ['operator']], ['security', ['security']], ['auditor', ['auditor']], ['policy-admin', ['policy_admin']], ...Array.from({ length: 5 }, (_, i) => [`custodian-${i + 1}`, ['approver', 'custodian']])];
    credentials[tenant] = {}; custodianKeys[tenant] = {}; issuerKeys[tenant] = {}; componentSecrets[tenant] = {};
    for (const [subject, role] of roles) {
      const key = generateKey(), token = randomBytes(32).toString('base64url');
      identities[key.key_id] = { public_key: key.public_key, subject_id: subject, identity_class: 'workforce', roles: role, device_id: `${subject}-device`, failure_domain: `${tenant}-${subject}`, hardware_backed: false, health_expires_at: now + 86400000, grants: { resources: ['dataset-1', 'erp-service'], actions: ['data.read', 'service.connect'], destinations: ['customer-vault', 'erp-service'], columns: ['id', 'name', 'region'], row_ids: ['row-1', 'row-2', 'row-3'] } };
      auth[hashBytes(token)] = { subject_id: subject, expires_at: now + 86400000 }; credentials[tenant][subject] = token; identityPrivate[subject] = key;
      if (role.includes('custodian')) custodianKeys[tenant][subject] = key;
    }
    const issuers = {};
    const allKinds = [...new Set(Object.values(ISSUER_ROLES).flatMap(r => r.kinds))];
    for (const [name, role] of Object.entries(ISSUER_ROLES)) {
      const key = generateKey(); issuerKeys[tenant][name] = key;
      // Dev/test config registers the full kind set per issuer (authoritative
      // scoping is enforced by issuerd rules in real deployments: a daemon can
      // only answer the kinds in its rules file). This preserves the fixture
      // contract where any configured issuer may attest any kind.
      // The issuance endpoint is authenticated by a per-issuer bearer token
      // shared between the registered connector metadata and the daemon spec.
      const issue_token = randomBytes(24).toString('base64url');
      issuers[key.key_id] = { public_key: key.public_key, name, issuer_id: name, failure_domain: `${tenant}-${name}`, channel: role.channel, kinds: allKinds, version: '1.0.0', issue_token };
      if (issuerEndpoint) issuers[key.key_id].endpoint = `${issuerEndpoint}`;
    }
    // Dev Secure Perception component: generated per tenant; private material
    // goes to the component secret bundle (dev console), never into config.
    const component = createDevComponent(`secure-view-${tenant}`);
    componentSecrets[tenant][component.name] = component;
    const components = { [component.name]: { signing_key_id: component.signing.key_id, signing: { key_id: component.signing.key_id, public_key: component.signing.public_key }, ecdh_public: component.ecdh_public, firmware_version: component.firmware_version, assurance: 'dev-attested-software', production: false } };
    // Purpose-bound at creation — no 'any' wildcard signing authority.
    const execution = vault ? vault.generate(['action-certificate', 'capability'], {}) : generateKey();
    const audit = vault ? vault.generate(['audit', 'outcome', 'revocation', 'coverage', 'checkpoint', 'backup-manifest'], {}) : generateKey();
    config.tenants[tenant] = { encryption_key: randomBytes(32).toString('base64url'), watermark_key: randomBytes(32).toString('base64url'), keys: { execution: { key_id: execution.key_id, public_key: execution.public_key, custody: vault ? 'vault' : 'embedded', ...(vault ? {} : { private_key: execution.private_key }) }, audit: { key_id: audit.key_id, public_key: audit.public_key, custody: vault ? 'vault' : 'embedded', ...(vault ? {} : { private_key: audit.private_key }) } }, identities, issuers, components, auth, genesis_policy: policy, genesis_signatures: Object.values(custodianKeys[tenant]).slice(0, 3).map(k => signed(policy, k, 'root-policy')) };
  }
  return { config, credentials, custodianKeys, issuerKeys, componentSecrets, vault };
}

export function createDevComponent(name) {
  const c = createSecureViewComponent(name, 'if-secureview-dev-1');
  return { name, firmware_version: c.firmware_version, signing: c.signing, ecdh_public: c.ecdh_public, ecdh_private: c._ecdh_private.export({ type: 'pkcs8', format: 'pem' }), attest: c.attest };
}

export function bootstrap(directory, tenants = ['acme'], now = Date.now(), { issuerPort = 8090 } = {}) {
  directory = resolve(directory);
  requireThat(!existsSync(directory), 'INV-409-CONFLICT', 'Refusing to overwrite an existing deployment directory', 409);
  mkdirSync(directory, { recursive: true, mode: 0o700 }); chmodSync(directory, 0o700);
  // Deployment path: keys are generated INSIDE the software vault; config.json
  // on disk carries only public material (KEY-001/002 for this profile).
  const masterKey = randomBytes(32).toString('base64url');
  const vault = new KeyVault(masterKey);
  const setup = createConfiguration(tenants, now, { vault, issuerEndpoint: `http://127.0.0.1:${issuerPort}` });
  const save = (path, value) => writeFileSync(path, canonical(value) + '\n', { mode: 0o600, flag: 'wx' });
  save(join(directory, 'master.key'), { format: 'IF-MASTERKEY-1', warning: 'software vault master key; protect per the deployment runbook', master_key: masterKey });
  vault.save(join(directory, 'keystore.json'));
  save(join(directory, 'config.json'), setup.config); save(join(directory, 'access-tokens.json'), setup.credentials);
  const signingDir = join(directory, 'offline-custodians'); mkdirSync(signingDir, { mode: 0o700 });
  const issuerDir = join(directory, 'issuers'); mkdirSync(issuerDir, { mode: 0o700 });
  const records = issuerRecords();
  for (const tenant of tenants) {
    const audit = setup.config.tenants[tenant].keys.audit;
    save(join(directory, `trust-public-${tenant}.json`), { [audit.key_id]: { public_key: audit.public_key }, attestor: setup.vault.attestorPublicKeys() });
    for (const [subject, key] of Object.entries(setup.custodianKeys[tenant])) save(join(signingDir, `${tenant}-${subject}.json`), key);
    for (const [name, role] of Object.entries(ISSUER_ROLES)) {
      const key = setup.issuerKeys[tenant][name];
      const spec = { issuer: name, tenant, version: '1.0.0', channel: role.channel, key, kinds: ISSUER_RULES[name] ?? {}, records: records[name] ?? {}, issue_token: Object.values(setup.config.tenants[tenant].issuers).find(i => i.name === name)?.issue_token };
      save(join(issuerDir, `${tenant}-${name}.issuer.json`), spec);
    }
    // Dev secure-view component bundle for the operator console.
    const component = setup.componentSecrets[tenant][`secure-view-${tenant}`];
    save(join(directory, `component-${tenant}.json`), { name: component.name, firmware_version: component.firmware_version, signing: component.signing, ecdh_private: component.ecdh_private, note: 'dev component private material — engineering profile only' });
    save(join(directory, `config-snapshot-${tenant}.json`), { tenant, config_digest: digest(setup.config.tenants[tenant]), taken_at: now });
  }
  const fabric = new Fabric(setup.config, directory, () => now, { vault });
  seedSyntheticResources(fabric, tenants); fabric.persistVault(); fabric.close();
  return { directory, config_path: join(directory, 'config.json'), credentials_path: join(directory, 'access-tokens.json'), signing_directory: signingDir, issuer_directory: issuerDir, issuer_port: issuerPort, profile: 'engineering', production_ready: false };
}
export function seedSyntheticResources(fabric, tenants) {
  for (const tenant of tenants) {
    fabric.target.seed(tenant, 'beneficiary-1', { bank_account: 'TESTBANK000001', currency: 'EUR', first_payment_done: false, payment_eligible_at: 0 });
    fabric.target.seed(tenant, 'vendor-1', { name: 'Synthetic Vendor', bank_account: 'TESTBANK000001', currency: 'EUR' });
    fabric.target.seed(tenant, 'dataset-1', { columns: ['id', 'name', 'region', 'passport'], classification: 'internal', jurisdiction: 'EU', rows: [{ id: 'row-1', name: 'Synthetic Ada', region: 'EU', passport: 'SYNTHETIC-NOT-REAL-1' }, { id: 'row-2', name: 'Synthetic Lin', region: 'EU', passport: 'SYNTHETIC-NOT-REAL-2' }, { id: 'row-3', name: 'Synthetic Sam', region: 'EU', passport: 'SYNTHETIC-NOT-REAL-3' }] });
    fabric.target.seed(tenant, 'jit-grants', { note: 'JIT grant ledger for identity.jit.grant actions' });
    fabric.target.seed(tenant, 'key-registry', { note: 'Key rotation registry for key.rotate actions', active: {} });
    fabric.target.seed(tenant, 'model-registry', { note: 'AI advisory model registry', models: {} });
    fabric.target.seed(tenant, 'contract-ledger', { note: 'Executed contract records', contracts: {} });
    fabric.target.seed(tenant, 'case-ledger', { note: 'Security investigation case records', cases: {} });
    fabric.target.seed(tenant, 'composite-ledger', { note: 'Composite action coordination ledger' });
    fabric.target.seedSecret(tenant, 'secret-erp-1', { workload_id: 'workload-1', allowed_operations: ['sign', 'authenticate'], vault_bound: true });
    fabric.target.seed(tenant, 'backup-set-1', { recovery_set: 'recovery-set-1', backups: ['backup-2026-01', 'backup-2026-02'], deleted_backups: [] });
    fabric.target.seed(tenant, 'fw-erp-1', { service_id: 'erp-service', protocol: 'tcp', port: 443, source_cidr: '10.0.0.0/8' });
    fabric.target.seed(tenant, 'release-target-1', { deployment_target: 'production', last_release: null });
    fabric.target.seed(tenant, 'subject-operator', { subject_id: 'operator', mfa_status: 'enrolled', authenticators: ['auth-1'], privilege: 'standard' });
  }
}
export function loadConfiguration(directory) { return JSON.parse(readFileSync(join(resolve(directory), 'config.json'), 'utf8')); }

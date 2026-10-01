// w23-policy regression suite — the emergency/successor weakening algebra
// must cover EVERY constitution dimension: dropped stale_ms keys, fail-mode
// defaults, presence-gated allowlists, the perception nonce pin, retention
// ceilings, policy lineage, staged horizon and custodian headroom
// (auditor findings W23-POLICY F1..F13).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { defaultPolicy, validatePolicy, emergencyWeakening, evaluatePolicy } from '../src/policy.mjs';
import { clone } from '../src/canonical.mjs';
import { fixture, installPolicy } from './helpers.mjs';

const base = () => defaultPolicy('acme');
const weak = (mutate, now = 1000) => { const next = clone(base()); next.policy_id = 'constitution:acme'; next.version = 2; mutate(next); return emergencyWeakening(base(), next, now); };

// F9: stale_ms/fail_modes keys are closed consume-class vocabulary — a
// lookalike key mints a dead ceiling that never binds.
test('w23-policy F9: unknown consume-class keys are schema-invalid in stale_ms and fail_modes', () => {
  for (const field of ['stale_ms', 'fail_modes']) {
    const p = base();
    p[field] = { ...p[field], 'data.read\u2024x': field === 'stale_ms' ? 1000 : 'closed' };
    assert.throws(() => validatePolicy(p), /Unknown consume class/);
  }
  const p = base(); p.stale_ms = { ...p.stale_ms, '': 1000 };
  assert.throws(() => validatePolicy(p), /Unknown consume class/);
});

// F8: retention per_kind keys must pass the identifier grammar — a
// whitespace/dot-embedded key never names a real evidence kind.
test('w23-policy F8: retention per_kind keys are validated as identifiers', () => {
  const p = base();
  p.retention.per_kind = { 'not a kind': 60000 };
  assert.throws(() => validatePolicy(p), e => e.code === 'INV-400-SCHEMA');
  p.retention.per_kind = { 'ownership': 60000 };
  validatePolicy(p);
});

// F11: a successor may not renumber the policy_id the lineage's audit trail
// references.
test('w23-policy F11: emergency successor cannot renumber policy_id', () => {
  const next = clone(base()); next.version = 2; next.policy_id = 'constitution:other';
  assert.equal(emergencyWeakening(base(), next, 1000), 'policy_id');
});

// F2: deleting a declared stale_ms class key reverts it to the looser
// fallback — a dropped ceiling weakens exactly like a raised one.
test('w23-policy F2: dropping a stale_ms class against a looser fallback is weakening', () => {
  // A dropped class whose fallback equals its old ceiling is not a weakening.
  const safe = weak(n => { delete n.stale_ms['service.connect']; });
  assert.equal(safe, null);
  // A class tightened below the fallback, then dropped, silently weakens.
  const tightened = base(); tightened.stale_ms['data.read'] = 100000;
  const dropped = clone(tightened); dropped.version = 2; delete dropped.stale_ms['data.read'];
  assert.equal(emergencyWeakening(tightened, dropped, 1000), 'stale_ms.data.read');
});

// F10: a fail_modes class absent from the base compares against the base's
// default — 'closed' added where the default was 'closed' is additive, not
// a weakening; loosening a bound class is.
test('w23-policy F10: undeclared fail-mode classes resolve against the base default', () => {
  const same = weak(n => { n.fail_modes = { ...n.fail_modes }; });
  assert.equal(same, null);
  const looser = weak(n => { n.fail_modes['data.read'] = 'cached-allow'; });
  assert.equal(looser, 'fail_modes.data.read');
});

// F5: an empty destinations list is NOT a stricter allowlist — it removes
// the gate entirely; subset([], base) must not read as tightened.
test('w23-policy F5: emptying a destination allowlist is weakening, not strictness', () => {
  const withGate = base();
  withGate.rules['finance.beneficiary.create'].destinations = ['erp-service'];
  const dropped = clone(withGate); dropped.version = 2; dropped.rules['finance.beneficiary.create'].destinations = [];
  assert.equal(emergencyWeakening(withGate, dropped, 1000), 'finance.beneficiary.create.destinations');
  const same = clone(withGate); same.version = 2;
  assert.equal(emergencyWeakening(withGate, same, 1000), null);
});

// F3: presence-gated admission restrictions (identity_classes,
// min_proofing) may not silently drop or widen.
test('w23-policy F3: dropped identity_classes and lowered min_proofing weaken the rule', () => {
  const gated = base();
  gated.rules['finance.beneficiary.create'].identity_classes = ['human'];
  gated.rules['finance.beneficiary.create'].min_proofing = 'high';
  const dropClasses = clone(gated); dropClasses.version = 2; delete dropClasses.rules['finance.beneficiary.create'].identity_classes;
  assert.equal(emergencyWeakening(gated, dropClasses, 1000), 'finance.beneficiary.create.identity_classes');
  const dropProof = clone(gated); dropProof.version = 2; dropProof.rules['finance.beneficiary.create'].min_proofing = 'medium';
  assert.equal(emergencyWeakening(gated, dropProof, 1000), 'finance.beneficiary.create.min_proofing');
});

// F4: the secure_perception attestation pin may neither rotate nor drop in
// a successor — a changed pin re-opens replayed attestation payloads.
test('w23-policy F4: secure_perception nonce pin is bound across versions', () => {
  const pinned = base(); pinned.secure_perception.nonce = 'a'.repeat(64);
  const rotated = clone(pinned); rotated.version = 2; rotated.secure_perception.nonce = 'b'.repeat(64);
  assert.equal(emergencyWeakening(pinned, rotated, 1000), 'secure_perception.nonce');
  const dropped = clone(pinned); dropped.version = 2; delete dropped.secure_perception.nonce;
  assert.equal(emergencyWeakening(pinned, dropped, 1000), 'secure_perception.nonce');
});

// F1/F6: retention ceilings are enforcement dimensions — a dropped
// per_kind key inherits the default ceiling and may not exceed the
// declared value; the whole block may not vanish.
test('w23-policy F1/F6: retention ceilings bound dropped keys and the block itself', () => {
  const kept = weak(n => { n.retention.per_kind = { ownership: 1000 }; });
  assert.equal(kept, null);
  const block = base(); block.retention.per_kind = { ownership: 5000 };
  const dropped = clone(block); dropped.version = 2; dropped.retention.per_kind = {};
  assert.equal(emergencyWeakening(block, dropped, 1000), 'retention.per_kind.ownership');
  const gone = clone(block); gone.version = 2; delete gone.retention;
  assert.equal(emergencyWeakening(block, gone, 1000), 'retention');
});

const cap = (cand, now = 1000) => ({ tenant_id: 'acme', action: { type: 'policy.change', target_resource: 'policy-root' }, requested_state: { policy: cand }, policy_version: 1, expires_at: now + 60000, quantity: 1, actor: { subject_id: 'op' } });

// F7: a far-future not_before wedges the single staged amendment slot —
// admission must refuse it before the certificate is spent.
test('w23-policy F7: staged activation beyond the 30-day horizon is refused at admission', () => {
  const cand = clone(base()); cand.version = 2; cand.tenant_id = 'acme'; cand.not_before = 1000 + 2592000000 + 1;
  const out = evaluatePolicy({ capsule: cap(cand), policy: base(), now: 1000 });
  assert.equal(out.decision, 'DENY');
  assert.ok(out.reasons.some(r => r.code === 'STAGED_HORIZON'));
});

// F12: every rule must leave approval headroom for the installed emergency
// surcharge — an emergency path dead on arrival is not governance.
test('w23-policy F12: rules without emergency surcharge headroom are refused', () => {
  const cand = clone(base()); cand.version = 2; cand.tenant_id = 'acme';
  cand.rules['finance.beneficiary.create'].approval_threshold = 5;
  const out = evaluatePolicy({ capsule: cap(cand), policy: base(), now: 1000 });
  assert.equal(out.decision, 'DENY');
  assert.ok(out.reasons.some(r => r.code === 'EMERGENCY_HEADROOM'));
});

// F13 (fabric): the governance-declared allow_weakening flag is stripped
// before staging/storage — the stored constitution and its anchors carry
// the pure policy document, never the transition's permission slip.
test('w23-policy F13: allow_weakening never persists into staged/active policy rows', t => {
  const h = fixture(t);
  const installed = installPolicy(h, n => { n.rules['finance.beneficiary.create'].cooldown_ms = 7; });
  assert.equal(installed.allow_weakening, true, 'the declared successor carries the flag');
  const active = h.f.policy('acme');
  assert.equal(active.version, 2);
  assert.equal(Object.hasOwn(active, 'allow_weakening'), false, 'stored constitution drops the transition flag');
});

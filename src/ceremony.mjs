import { randomBytes } from 'node:crypto';
import { canonical, digest } from './canonical.mjs';
import { signed, verifySigned } from './crypto.mjs';
import { split, reconstruct, encodeShare, decodeShare } from './shamir.mjs';
import { fields, text, identifier, integer, uniqueStrings } from './schema.mjs';
import { requireThat, InvariantError } from './errors.mjs';

// IF-KEY-1: threshold key ceremony (KEY-004/005/008). A ceremony is a signed,
// quorum-acknowledged artifact describing which custodians hold shares of a
// secret (e.g. an exportable root/backup key), over which threshold, for which
// purpose. Reconstructing the secret cryptographically requires >= threshold
// distinct custodian shares — the approval record cannot bypass the math.

export function createCeremony({ ceremony_id, tenant_id, purpose, threshold, custodians, valid_until, min_delay_ms = 0, devices = {}, rotation = null }) {
  fields({ ceremony_id, tenant_id, purpose, threshold, custodians, valid_until }, ['ceremony_id', 'tenant_id', 'purpose', 'threshold', 'custodians', 'valid_until'], ['min_delay_ms', 'devices', 'rotation']);
  identifier(ceremony_id); identifier(tenant_id, 'tenant'); text(purpose, 'purpose', 64);
  integer(threshold, 'threshold', 2, custodians.length);
  uniqueStrings(custodians, 'custodians', 16); integer(valid_until, 'valid until', 1); integer(min_delay_ms, 'minimum delay', 0, 30 * 24 * 3600 * 1000);
  // KEY-012: when supplied, `devices` binds each custodian to the device that
  // will present its share — unknown custodians or malformed ids are rejected.
  requireThat(devices === null || typeof devices === 'object', 'INV-400-SCHEMA', 'devices must be a custodian→device map');
  for (const [custodian, device] of Object.entries(devices ?? {})) { requireThat(custodians.includes(custodian), 'INV-400-SCHEMA', 'devices names a non-custodian'); identifier(device, 'device'); }
  // A ceremony that authorizes a rotation is bound at creation to the exact
  // class and pending key it covers — custodians consent to that rotation,
  // not to any rotation that later cites the ceremony (w6-ceremony F3).
  if (rotation !== null && rotation !== undefined) {
    fields(rotation, ['key_class', 'new_key_id']);
    requireThat(['execution', 'audit'].includes(rotation.key_class), 'INV-400-SCHEMA', 'rotation.key_class must be execution or audit');
    identifier(rotation.new_key_id, 'rotation key');
  }
  return {
    ceremony_id, tenant_id, purpose, threshold, custodians: [...custodians].sort(), valid_until, min_delay_ms, devices, rotation,
    status: 'planned', acknowledgements: [], share_commitments: [], exceptions: [], notices: [], committed_at: null, rotation_consumed: null,
    artifact_digest: digest({ ceremony_id, tenant_id, purpose, threshold, custodians, valid_until, min_delay_ms, rotation })
  };
}

export function acknowledge(ceremony, custodian, ackEnvelope, now) {
  requireThat(ceremony.custodians.includes(custodian), 'INV-403-ROLE', 'Not a ceremony custodian', 403);
  requireThat(ceremony.status !== 'completed', 'INV-409-STATE', 'Ceremony already completed', 409);
  // A custodian who attested a superseded artifact digest must be able to
  // re-acknowledge the rebound artifact — only same-digest consent is a
  // duplicate (w7-seam F4).
  requireThat(!ceremony.acknowledgements.some(a => a.payload.custodian === custodian && a.payload.artifact_digest === ceremony.artifact_digest), 'INV-409-STATE', 'Custodian already acknowledged', 409);
  ceremony.acknowledgements.push(ackEnvelope);
  return ackEnvelope;
}

export function signAcknowledgement(ceremony, custodian, custodianKey, now) {
  return signed({ ceremony_id: ceremony.ceremony_id, artifact_digest: ceremony.artifact_digest, custodian, acknowledged_at: now }, custodianKey, 'ceremony-acknowledgement');
}

// Custodians commit to their shares before distribution: commitment is
// digest(x||y) so reconstruction can later prove which shares were used.
// Share indices must be exactly {1..n} and distinct, and each commitment is
// bound to its custodian by index (custodian at sorted position x−1), never
// by caller-supplied array position (crypto-audit M-6).
export function commitShares(ceremony, shares, now) {
  // Commitments are written exactly once: re-committing after custodians have
  // acknowledged would let a dealer swap the secret underneath their consent
  // (w6-ceremony F6/F10). The artifact digest is rebound below so an ack
  // issued before commit does not carry over.
  requireThat(ceremony.status === 'planned', 'INV-409-STATE', 'Shares were already committed for this ceremony', 409);
  const n = ceremony.custodians.length;
  requireThat(shares.length === n, 'INV-400-SCHEMA', 'Share count must equal custodian count');
  const indices = shares.map(s => s.x).sort((a, b) => a - b);
  requireThat(indices.every((x, i) => Number.isSafeInteger(x) && x === i + 1), 'INV-400-SCHEMA', 'Share indices must be exactly 1..n and distinct');
  for (const s of shares) requireThat(s.y instanceof Uint8Array, 'INV-400-SCHEMA', 'Share material must be bytes');
  // Commitments are bound to the ceremony: identical share bytes cannot
  // satisfy two ceremonies (w6-ceremony F16).
  ceremony.share_commitments = shares.map(s => ({ custodian: ceremony.custodians[s.x - 1], share_index: s.x, commitment: digest({ ceremony_id: ceremony.ceremony_id, x: s.x, y: Buffer.from(s.y).toString('base64url') }) }));
  // KEY-009 out-of-band notice: each custodian gets an independently
  // addressed notification record at share-commit time; the delay window
  // below gives them time to object before any reconstruction is legal.
  ceremony.notices = ceremony.custodians.map(c => ({ custodian: c, channel: 'recovery-notice', issued_at: now }));
  ceremony.committed_at = now;
  ceremony.status = 'committed';
  // Rebind the artifact: acknowledgements made before commit attested to a
  // digest that did not name the shares and must be re-collected.
  ceremony.artifact_digest = digest({ ceremony_id: ceremony.ceremony_id, tenant_id: ceremony.tenant_id, purpose: ceremony.purpose, threshold: ceremony.threshold, custodians: ceremony.custodians, valid_until: ceremony.valid_until, min_delay_ms: ceremony.min_delay_ms, share_commitments: ceremony.share_commitments.map(c => c.commitment) });
  return ceremony.share_commitments;
}

export function splitSecret(secretBytes, ceremony) {
  return split(secretBytes, ceremony.custodians.length, ceremony.threshold);
}

// Reconstruction: >= threshold shares, each verified against its published
// commitment, recompute the secret. Returns {secret, artifact} — artifact is
// audit evidence that a valid quorum participated.
export function reconstructSecret(ceremony, presentedShares, now) {
  // Only a committed, unexpired ceremony reconstructs — completed ceremonies
  // cannot be re-run with a different share subset (w6-ceremony F5).
  requireThat(ceremony.status === 'committed', 'INV-409-STATE', 'Ceremony is not committed or has already completed', 409);
  requireThat(ceremony.valid_until > now, 'INV-409-STATE', 'Ceremony validity has lapsed', 409);
  requireThat(presentedShares.length >= ceremony.threshold, 'INV-403-ROLE', 'Fewer than threshold shares presented', 403);
  // KEY-009 delay: reconstruction is illegal until the recovery delay has
  // elapsed since shares were committed (notices already issued then).
  requireThat(now >= (ceremony.committed_at ?? 0) + (ceremony.min_delay_ms ?? 0), 'INV-409-STATE', 'Recovery delay has not elapsed since share commitment', 409);
  requireThat(ceremony.notices.length === ceremony.custodians.length, 'INV-409-STATE', 'Recovery notices have not been issued to all custodians', 409);
  const byIndex = new Map();
  for (const s of presentedShares) {
    const commitment = ceremony.share_commitments.find(c => c.share_index === s.x);
    requireThat(commitment, 'INV-403-ROLE', `Share index ${s.x} was not committed in this ceremony`, 403);
    requireThat(commitment.commitment === digest({ ceremony_id: ceremony.ceremony_id, x: s.x, y: Buffer.from(s.y).toString('base64url') }), 'INV-403-ROLE', 'Share does not match its ceremony commitment', 403);
    byIndex.set(s.x, s);
  }
  const shares = [...byIndex.values()];
  requireThat(shares.length >= ceremony.threshold, 'INV-403-ROLE', 'Duplicate shares do not count toward threshold', 403);
  const secret = reconstruct(shares.slice(0, ceremony.threshold));
  const artifact = { ceremony_id: ceremony.ceremony_id, quorum: shares.map(s => s.x).sort((a, b) => a - b), reconstructed_at: now, purpose: ceremony.purpose };
  ceremony.status = 'completed';
  return { secret, artifact };
}

export function ceremonyReport(ceremony) {
  return {
    ceremony_id: ceremony.ceremony_id, status: ceremony.status, threshold: ceremony.threshold,
    custodians: ceremony.custodians, acknowledged: ceremony.acknowledgements.length,
    commitments: ceremony.share_commitments.length, exceptions: ceremony.exceptions,
    artifact_digest: ceremony.artifact_digest
  };
}

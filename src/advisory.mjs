import { digest, parseStrict } from './canonical.mjs';
import { fields, text, identifier } from './schema.mjs';
import { requireThat, InvariantError } from './errors.mjs';

// IF-AIG-1: the AI advisory plane. All models are deterministic, versioned
// extractors running as data processors: they turn documents into candidate
// claims for evidence and explanations for operator UX. They never authorise,
// never write state, and every output carries model identity + confidence so
// provenance stays honest (AIG-002..005). Model upgrades are staged via the
// eval suite (AIG-010) — see ai-eval/ and scripts/ai-eval.mjs.

export const MODELS = {
  'extract-v1': { version: 'extract-v1.3.0', kind: 'field-extraction' },
  'explain-v1': { version: 'explain-v1.1.0', kind: 'decision-explanation' },
  'intent-v1': { version: 'intent-v1.0.2', kind: 'intent-classification' }
};

const PATTERNS = [
  { field: 'account', re: /\b(TESTBANK\d{6,}|ACCT-[A-Z0-9-]{4,}|[A-Z]{2}\d{2}[A-Z0-9]{11,30})\b/g, confidence: 92 },
  { field: 'amount_minor', re: /\b(?:amount|total|sum|payment of)\s*[:=]?\s*(?:USD|EUR|GBP)?\s*(\d{1,13})(?:[.,](\d{2}))?\b/gi, confidence: 80, transform: m => Number(m[1]) * 100 + Number(m[2] ?? 0) },
  { field: 'currency', re: /\b(USD|EUR|GBP|JPY|CHF)\b/g, confidence: 90 },
  { field: 'invoice_id', re: /\b(?:invoice|inv)[\s#:]*([A-Z0-9-]{5,24})\b/gi, confidence: 78, transform: m => m[1] },
  { field: 'date', re: /\b(20\d{2}-\d{2}-\d{2})\b/g, confidence: 85 },
  { field: 'email', re: /\b([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})\b/gi, confidence: 95, transform: m => m[1] },
  { field: 'beneficiary', re: /\bbeneficiary\s*[:=]\s*([A-Z][A-Za-z .&-]{2,48})\b/g, confidence: 72, transform: m => m[1].trim() },
  { field: 'counterparty_id', re: /\b(CP-[A-Z0-9-]{3,20})\b/g, confidence: 80 }
];

// Extraction output: field candidates with spans + per-field confidence.
// Injected instruction text is data: it is never executed and the extractor's
// output schema cannot express directives, so prompt-injection can at worst
// produce a wrong field candidate — which the evidence issuer later confirms
// or conflicts (INV-412 / EVD-007).
export function extract(documentText, model = 'extract-v1') {
  text(documentText, 'document', 1_000_000);
  const m = MODELS[model]; requireThat(m && m.kind === 'field-extraction', 'INV-400-SCHEMA', 'Unknown extraction model');
  const candidates = [];
  for (const p of PATTERNS) {
    for (const match of documentText.matchAll(p.re)) {
      candidates.push({ field: p.field, value: p.transform ? p.transform(match) : match[0], span: [match.index, match.index + match[0].length], confidence: p.confidence });
    }
  }
  candidates.sort((a, b) => a.field.localeCompare(b.field) || a.span[0] - b.span[0]);
  return { model: m.version, document_digest: digest(documentText), candidates, advisory: true };
}

const REASON_TEXT = {
  ROLE: 'the requesting role is not permitted to initiate this action',
  MODE: 'the action is not available in the current operating mode',
  EVIDENCE_MISSING: 'required evidence has not been supplied or verified',
  EVIDENCE_CONFLICT: 'an authoritative source contradicted a submitted claim',
  EVIDENCE_STALE: 'evidence exceeded its freshness window',
  SHIELD: 'the action may proceed only with a shielded target scope',
  POLICY_CHANGE: 'the action would alter policy and requires a policy change request',
  ADMISSION: 'the admission check (certification target bound to canonical form) failed',
  UNKNOWN: 'no policy rule matched; default deny'
};
export function explain(decision, model = 'explain-v1') {
  const m = MODELS[model]; requireThat(m && m.kind === 'decision-explanation', 'INV-400-SCHEMA', 'Unknown explanation model');
  const reasons = (decision.reasons ?? []).map(r => ({ code: r, text: REASON_TEXT[r] ?? `policy returned ${r}` }));
  return { model: m.version, verdict: decision.verdict, reasons, advisory: true, text: `${decision.verdict}: ` + (reasons.map(r => r.text).join('; ') || 'request satisfied all policy conditions') };
}

const INTENT_WORDS = [
  [/vendor|supplier|payee/i, 'finance.vendor.add'], [/payment|invoice|transfer/i, 'finance.payment.execute'],
  [/beneficiar/i, 'finance.beneficiary.change'], [/refund/i, 'finance.refund.issue'], [/payroll/i, 'finance.payroll.submit'],
  [/dataset|row|query/i, 'data.read'], [/export|download/i, 'data.export'], [/key|rotat/i, 'key.rotate'],
  [/policy/i, 'policy.change'], [/deploy|rollout/i, 'policy.deploy'], [/revoke|quarantine/i, 'identity.session.revoke'],
  [/contract/i, 'legal.contract.execute'], [/investigat/i, 'security.case.investigate'], [/model/i, 'ai.model.deploy']
];
export function classifyIntent(textIn, model = 'intent-v1') {
  text(textIn, 'request text', 100000);
  const m = MODELS[model]; requireThat(m && m.kind === 'intent-classification', 'INV-400-SCHEMA', 'Unknown intent model');
  const matches = INTENT_WORDS.filter(([re]) => re.test(textIn)).map(([, type]) => type);
  const uniq = [...new Set(matches)];
  return { model: m.version, candidates: uniq.map(type => ({ action_type: type, confidence: uniq.length === 1 ? 74 : 58 })), advisory: true };
}

// The evidence-extraction bridge: deterministic candidates become advisory
// 'claims' for an issuer query. They remain unverified until an authoritative
// issuer signs a 'supports' envelope (EVD-007 keeps trust domains separate).
export function candidatesToClaims(extraction) {
  const claims = {};
  for (const c of extraction.candidates) if (!(c.field in claims)) claims[c.field] = c.value;
  return claims;
}

import { randomBytes } from 'node:crypto';
import { requireThat } from './errors.mjs';

// IF-SHAMIR-1: Shamir (k,n) secret sharing over GF(2^8) with the AES
// polynomial x^8+x^4+x^3+x+1 (0x11b). Each share is per-byte independent
// Lagrange evaluation at x=i. Shares reveal nothing below threshold k.

const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
(() => {
  // Generator is x+1 (0x03), the primitive element of GF(2^8) under 0x11b;
  // x (0x02) has order 51 and cannot generate the full field.
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x; LOG[x] = i;
    let x2 = x << 1; if (x2 & 0x100) x2 ^= 0x11b;
    x = x2 ^ x; // multiply by 3: x*2 ^ x
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();
const mul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);
const inv = a => (a === 0 ? 0 : EXP[255 - LOG[a]]);

function splitByte(secret, n, k, rand) {
  const poly = [secret, ...rand.slice(0, k - 1)];
  const shares = new Uint8Array(n);
  for (let i = 1; i <= n; i++) {
    let y = 0;
    for (let d = poly.length - 1; d >= 0; d--) y = mul(y, i) ^ poly[d];
    shares[i - 1] = y;
  }
  return shares;
}

// secret: Uint8Array. Returns [{x, y: Uint8Array}] for i=1..n.
export function split(secret, n, k) {
  requireThat(secret instanceof Uint8Array && secret.length >= 1 && secret.length <= 1024, 'INV-400-SHAMIR', 'Secret must be 1-1024 bytes');
  requireThat(Number.isSafeInteger(n) && n >= 2 && n <= 255 && Number.isSafeInteger(k) && k >= 2 && k <= n, 'INV-400-SHAMIR', 'Require 2 <= k <= n <= 255');
  const shares = Array.from({ length: n }, (_, i) => ({ x: i + 1, y: new Uint8Array(secret.length) }));
  for (let b = 0; b < secret.length; b++) {
    const col = splitByte(secret[b], n, k, randomBytes(k - 1));
    for (let i = 0; i < n; i++) shares[i].y[b] = col[i];
  }
  return shares;
}

function interpolateZero(points) {
  // Lagrange evaluation at x=0 over GF(256).
  let acc = 0;
  for (let i = 0; i < points.length; i++) {
    const [xi, yi] = points[i];
    let num = 1, den = 1;
    for (let j = 0; j < points.length; j++) {
      if (i === j) continue;
      num = mul(num, points[j][0]);
      den = mul(den, xi ^ points[j][0]);
    }
    acc ^= mul(yi, mul(num, inv(den)));
  }
  return acc;
}

export function reconstruct(shares, k = null) {
  requireThat(Array.isArray(shares) && shares.length >= 2, 'INV-400-SHAMIR', 'At least two shares are required');
  if (k !== null) requireThat(shares.length >= k, 'INV-400-SHAMIR', 'Fewer than k shares presented');
  const xs = new Set(shares.map(s => s.x));
  // x coordinates must be exact integers — a fractional x produces a
  // plausible-looking but wrong secret rather than an error.
  requireThat(xs.size === shares.length && shares.every(s => s.y instanceof Uint8Array && s.y.length === shares[0].y.length && Number.isSafeInteger(s.x) && s.x >= 1 && s.x <= 255), 'INV-400-SHAMIR', 'Malformed or duplicate share set');
  const out = new Uint8Array(shares[0].y.length);
  for (let b = 0; b < out.length; b++) out[b] = interpolateZero(shares.map(s => [s.x, s.y[b]]));
  return out;
}

// Deterministic share encoding for storage/export: base64url of x||y.
export function encodeShare(share) {
  return Buffer.concat([Buffer.from([share.x]), Buffer.from(share.y)]).toString('base64url');
}
export function decodeShare(text) {
  const raw = Buffer.from(String(text), 'base64url');
  requireThat(raw.length >= 2 && raw[0] >= 1, 'INV-400-SHAMIR', 'Malformed share encoding');
  return { x: raw[0], y: new Uint8Array(raw.subarray(1)) };
}

import { randomBytes } from 'node:crypto';
import { requireThat } from './errors.mjs';

// IF-SHAMIR-1: Shamir (k,n) secret sharing over GF(2^8) with the AES
// polynomial x^8+x^4+x^3+x+1 (0x11b). Each share is per-byte independent
// Lagrange evaluation at x=i. Shares reveal nothing below threshold k.

// GF(2^8) arithmetic without secret-indexed table lookups: bit-serial
// multiply with masked reduction, inversion via a^254 = ((a^127)^2). Table
// lookups at secret-derived offsets would index cache lines by share bytes
// — the classic finite-field cache-timing channel (w11-timing MED-1).
const mul = (a, b) => {
  let r = 0;
  for (let i = 0; i < 8; i++) {
    r ^= a & -(b >>> i & 1);
    const msb = a >>> 7;
    a = ((a << 1) ^ (msb * 0x1b)) & 0xff;
  }
  return r;
};
const inv = a => {
  let r = a; // a^1 → a^3 → a^7 → a^15 → a^31 → a^63 → a^127
  for (let i = 0; i < 6; i++) r = mul(mul(r, r), a);
  return mul(r, r); // a^254; a=0 stays 0
};

function splitByte(secret, n, k, rand) {
  const poly = [secret, ...rand.slice(0, k - 1)];
  const shares = new Uint8Array(n);
  for (let i = 1; i <= n; i++) {
    let y = 0;
    for (let d = poly.length - 1; d >= 0; d--) y = mul(y, i) ^ poly[d];
    shares[i - 1] = y;
  }
  // Deal-side consumables: the random coefficients and the polynomial row
  // (whose [0] is the secret byte) are zeroed — only the shares leave here
  // (w15-timing F7).
  rand.fill(0); poly.fill(0);
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

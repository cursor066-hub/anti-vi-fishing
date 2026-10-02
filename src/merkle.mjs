import { createHash } from 'node:crypto';
import { requireThat } from './errors.mjs';

// IF-MERKLE-1: RFC 6962-shaped binary Merkle tree over audit entry hashes.
// Domain separation: 0x00 for leaves, 0x01 for interior nodes.
export const leaf = h => createHash('sha256').update(Buffer.concat([Buffer.from([0x00]), Buffer.from(h, 'hex')])).digest('hex');
const node = (a, b) => createHash('sha256').update(Buffer.concat([Buffer.from([0x01]), Buffer.from(a, 'hex'), Buffer.from(b, 'hex')])).digest('hex');
const isDigest = h => /^[a-f0-9]{64}$/.test(h);

function checkHashes(hashes) {
  requireThat(Array.isArray(hashes) && hashes.every(isDigest), 'INV-400-MERKLE', 'Merkle leaves must be SHA-256 digests');
}

// Split point for size n: largest power of two strictly less than n (n > 1).
function split(n) { let k = 1; while (k * 2 < n) k *= 2; return k; }

function subtreeRoot(hashes, lo, hi) {
  const n = hi - lo;
  if (n === 1) return leaf(hashes[lo]);
  const k = split(n);
  return node(subtreeRoot(hashes, lo, lo + k), subtreeRoot(hashes, lo + k, hi));
}

export function merkleRoot(hashes) {
  checkHashes(hashes);
  if (hashes.length === 0) return '0'.repeat(64);
  return subtreeRoot(hashes, 0, hashes.length);
}

// Canonical maximal aligned power-of-2 partition of the range [lo, hi).
// Deterministic: recomputed by any verifier from sizes alone.
export function partition(lo, hi) {
  requireThat(Number.isSafeInteger(lo) && Number.isSafeInteger(hi) && lo >= 0 && hi >= lo, 'INV-400-MERKLE', 'Invalid partition range');
  const out = [];
  let p = lo;
  while (p < hi) {
    let k = 1;
    if (p === 0) { while (k * 2 <= hi) k *= 2; }
    else { while (p % (k * 2) === 0 && p + k * 2 <= hi) k *= 2; }
    while (p + k > hi) k /= 2;
    out.push([p, p + k]); p += k;
  }
  return out;
}

// Fold subtree hashes of a partition covering [lo,hi) into the tree root.
export function combine(subtrees) {
  requireThat(Array.isArray(subtrees) && subtrees.length >= 1, 'INV-400-MERKLE', 'Empty subtree list');
  for (const s of subtrees) {
    requireThat(Array.isArray(s) && s.length === 3 && Number.isSafeInteger(s[0]) && Number.isSafeInteger(s[1]) && s[1] > s[0] && isDigest(s[2]), 'INV-400-MERKLE', 'Malformed subtree');
  }
  const lo = subtrees[0][0], hi = subtrees.at(-1)[1];
  if (subtrees.length === 1) {
    requireThat(subtrees[0][0] === lo && subtrees[0][1] === hi && (subtrees[0][1] - subtrees[0][0] & (subtrees[0][1] - subtrees[0][0] - 1)) === 0, 'INV-400-MERKLE', 'Subtree is not a power-of-two range');
    return subtrees[0][2];
  }
  const n = hi - lo, k = split(n);
  const li = subtrees.findIndex(s => s[0] === lo + k);
  requireThat(li > 0, 'INV-400-MERKLE', 'Subtree partition does not align to the tree split');
  return node(combine(subtrees.slice(0, li)), combine(subtrees.slice(li)));
}

export function inclusionProof(hashes, index) {
  checkHashes(hashes);
  requireThat(Number.isSafeInteger(index) && index >= 0 && index < hashes.length, 'INV-400-MERKLE', 'Inclusion index out of range');
  const path = [];
  let lo = 0, hi = hashes.length;
  while (hi - lo > 1) {
    const k = split(hi - lo), mid = lo + k;
    if (index < mid) { path.push({ side: 'right', hash: subtreeRoot(hashes, mid, hi) }); hi = mid; }
    else { path.push({ side: 'left', hash: subtreeRoot(hashes, lo, mid) }); lo = mid; }
  }
  return path.reverse(); // leaf-sibling first, root-sibling last (RFC 6962 audit path order)
}

export function verifyInclusion(entryHash, index, size, path, expectedRoot) {
  requireThat(isDigest(entryHash) && isDigest(expectedRoot) && Array.isArray(path) && Number.isSafeInteger(index) && index >= 0 && index < size, 'INV-400-MERKLE', 'Malformed inclusion inputs');
  // RFC 6962 §2.1.1: fn = index of the leaf, sn = index of the last leaf.
  let acc = leaf(entryHash), fn = index, sn = size - 1, i = 0;
  while (sn > 0) {
    requireThat(i < path.length, 'INV-409-MERKLE', 'Inclusion proof does not verify', 409);
    const step = path[i++];
    requireThat(step && isDigest(step.hash) && ['left', 'right'].includes(step.side), 'INV-400-MERKLE', 'Malformed inclusion step');
    if (fn % 2 === 1 || fn === sn) {
      // acc is the right child, or the leftmost node of an uneven split
      requireThat(step.side === 'left', 'INV-409-MERKLE', 'Inclusion proof does not verify', 409);
      acc = node(step.hash, acc);
      while (fn % 2 === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else {
      requireThat(step.side === 'right', 'INV-409-MERKLE', 'Inclusion proof does not verify', 409);
      acc = node(acc, step.hash);
    }
    fn >>= 1; sn >>= 1;
  }
  requireThat(i === path.length && acc === expectedRoot, 'INV-409-MERKLE', 'Inclusion proof does not verify', 409);
  return true;
}

// Consistency proof between a first tree of size `first` and the full tree:
// subtree hashes for the canonical partitions of [0,first) and [first,size).
// Both ranges are recomputed by the verifier, so a missing or extra subtree
// cannot fold to a valid root.
export function consistencyProof(hashes, first) {
  checkHashes(hashes);
  requireThat(Number.isSafeInteger(first) && first >= 1 && first <= hashes.length, 'INV-400-MERKLE', 'Consistency bound out of range');
  const tail = first === hashes.length ? [] : partition(first, hashes.length).map(([a, b]) => [a, b, subtreeRoot(hashes, a, b)]);
  return { first_subtrees: partition(0, first).map(([a, b]) => [a, b, subtreeRoot(hashes, a, b)]), tail_subtrees: tail };
}

// Incremental merkle over an append-only leaf column: leaf list and
// subtree hashes memoize, so proof/consistency/root queries pay
// O(new leaves + log n) hashing instead of re-hashing the whole log per
// request (w33-export F4). The cache binds to leaf CONTENT — a rewritten
// or truncated prefix resets wholesale.
export function merkleMemo() {
  let leaves = [];
  const memo = new Map();
  const sub = (lo, hi) => {
    const n = hi - lo;
    if (n === 1) return leaf(leaves[lo]);
    const key = `${lo}:${hi}`;
    let v = memo.get(key);
    if (v === undefined) { const k = split(n); v = node(sub(lo, lo + k), sub(lo + k, hi)); memo.set(key, v); }
    return v;
  };
  return {
    sync(hashes) {
      checkHashes(hashes);
      if (leaves.length > hashes.length || leaves.some((h, i) => h !== hashes[i])) { leaves = []; memo.clear(); }
      for (let i = leaves.length; i < hashes.length; i++) leaves.push(hashes[i]);
      return leaves.length;
    },
    get size() { return leaves.length; },
    get leaves() { return leaves; },
    sub,
    root(lo = 0, hi = leaves.length) { return hi - lo === 0 ? '0'.repeat(64) : sub(lo, hi); },
    proof(index) {
      requireThat(Number.isSafeInteger(index) && index >= 0 && index < leaves.length, 'INV-400-MERKLE', 'Inclusion index out of range');
      const path = [];
      let lo = 0, hi = leaves.length;
      while (hi - lo > 1) {
        const k = split(hi - lo), mid = lo + k;
        if (index < mid) { path.push({ side: 'right', hash: sub(mid, hi) }); hi = mid; }
        else { path.push({ side: 'left', hash: sub(lo, mid) }); lo = mid; }
      }
      return path.reverse();
    },
    consistency(first, size = leaves.length) {
      requireThat(Number.isSafeInteger(first) && first >= 1 && first <= size, 'INV-400-MERKLE', 'Consistency bound out of range');
      const tail = first === size ? [] : partition(first, size).map(([a, b]) => [a, b, sub(a, b)]);
      return { first_subtrees: partition(0, first).map(([a, b]) => [a, b, sub(a, b)]), tail_subtrees: tail };
    }
  };
}

export function verifyConsistency(firstRoot, first, secondRoot, size, proof) {
  requireThat(isDigest(firstRoot) && isDigest(secondRoot) && Number.isSafeInteger(first) && first >= 1 && first <= size, 'INV-400-MERKLE', 'Malformed consistency inputs');
  requireThat(proof && Array.isArray(proof.first_subtrees) && Array.isArray(proof.tail_subtrees), 'INV-400-MERKLE', 'Malformed consistency proof');
  const expectedFirst = partition(0, first), expectedTail = partition(first, size);
  requireThat(proof.first_subtrees.length === expectedFirst.length && proof.tail_subtrees.length === expectedTail.length, 'INV-409-MERKLE', 'Consistency proof does not verify', 409);
  const same = (s, r) => s[0] === r[0] && s[1] === r[1];
  requireThat(proof.first_subtrees.every((s, i) => same(s, expectedFirst[i])) && proof.tail_subtrees.every((s, i) => same(s, expectedTail[i])), 'INV-409-MERKLE', 'Consistency proof does not verify', 409);
  requireThat(combine(proof.first_subtrees) === firstRoot, 'INV-409-MERKLE', 'Consistency proof does not verify', 409);
  requireThat(combine([...proof.first_subtrees, ...proof.tail_subtrees]) === secondRoot, 'INV-409-MERKLE', 'Consistency proof does not verify', 409);
  return true;
}

import { createHash } from "node:crypto";

/**
 * Deterministic binary Merkle tree over hex-encoded sha256 leaf hashes.
 *
 * - Empty input -> all-zero root, so a zero-leaf checkpoint is still well-defined.
 * - Odd levels duplicate the last node (Bitcoin / RFC 6962 style) so the shape is
 *   deterministic without padding leaves.
 * - Internal nodes hash raw left||right BYTES, not their hex strings.
 *
 * Byte-compatible with the openai-claw attestation tree, so proofs move between
 * the two systems unchanged.
 */
export function merkleRoot(leafHashesHex) {
  if (leafHashesHex.length === 0) return "0".repeat(64);
  let level = leafHashesHex.map(hexToBytes);
  while (level.length > 1) level = nextLevel(level);
  return bytesToHex(level[0]);
}

export function merkleProof(leafHashesHex, index) {
  if (index < 0 || index >= leafHashesHex.length) {
    throw new Error(`merkleProof: index ${index} out of range [0, ${leafHashesHex.length})`);
  }
  const steps = [];
  let level = leafHashesHex.map(hexToBytes);
  let idx = index;
  while (level.length > 1) {
    const isRight = idx % 2 === 1;
    const siblingIdx = isRight ? idx - 1 : Math.min(idx + 1, level.length - 1);
    steps.push({ side: isRight ? "left" : "right", hashHex: bytesToHex(level[siblingIdx]) });
    level = nextLevel(level);
    idx = Math.floor(idx / 2);
  }
  return steps;
}

export function verifyMerkleProof(leafHex, steps, rootHex) {
  let cur = hexToBytes(leafHex);
  for (const s of steps) {
    const sib = hexToBytes(s.hashHex);
    cur = s.side === "left" ? hashPair(sib, cur) : hashPair(cur, sib);
  }
  return bytesToHex(cur) === rootHex;
}

function nextLevel(level) {
  const next = [];
  for (let i = 0; i < level.length; i += 2) {
    const left = level[i];
    const right = i + 1 < level.length ? level[i + 1] : level[i];
    next.push(hashPair(left, right));
  }
  return next;
}

function hashPair(a, b) {
  const h = createHash("sha256");
  h.update(Buffer.from(a));
  h.update(Buffer.from(b));
  return new Uint8Array(h.digest());
}

function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error("hex length must be even");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(b) {
  let out = "";
  for (let i = 0; i < b.length; i++) out += b[i].toString(16).padStart(2, "0");
  return out;
}

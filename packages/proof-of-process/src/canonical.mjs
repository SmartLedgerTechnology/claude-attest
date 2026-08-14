import { createHash } from "node:crypto";

/**
 * Canonical JSON per RFC 8785 (JCS): keys sorted lexicographically, no
 * insignificant whitespace, undefined values stripped.
 *
 * Determinism is load-bearing: a verifier on a different machine MUST produce
 * byte-identical output, otherwise every leaf hash drifts and the signature
 * fails. Don't optimize without round-trip tests.
 */
export function canonicalJSON(value) {
  return serialize(value);
}

function serialize(v) {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error(`canonicalJSON: non-finite number ${v}`);
    return JSON.stringify(v);
  }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(serialize).join(",") + "]";
  if (typeof v === "object") {
    const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + serialize(v[k])).join(",") + "}";
  }
  throw new Error(`canonicalJSON: unsupported type ${typeof v}`);
}

export function sha256Hex(input) {
  const h = createHash("sha256");
  h.update(typeof input === "string" ? Buffer.from(input, "utf8") : Buffer.from(input));
  return h.digest("hex");
}

/** Hash an arbitrary JSON payload. This is what a leaf commits to. */
export function hashPayload(payload) {
  return sha256Hex(canonicalJSON(payload));
}

/**
 * Hash a leaf. `prev` participates, so the log is a hash chain as well as a
 * Merkle tree — reordering or splicing leaves breaks both structures.
 */
export function hashLeaf(leaf) {
  return sha256Hex(canonicalJSON(leaf));
}

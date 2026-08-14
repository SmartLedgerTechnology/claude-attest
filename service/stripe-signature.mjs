import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Stripe webhook signature verification.
 *
 * Implemented directly rather than pulling in the Stripe SDK: this is the one
 * piece of the billing integration where a subtle bug means anyone who learns
 * the endpoint URL can forge `checkout.session.completed` and grant themselves
 * a paid subscription. It is ~40 lines and worth being able to read in full.
 *
 * The scheme (Stripe's `Stripe-Signature` header):
 *
 *   Stripe-Signature: t=1614556800,v1=<hex>,v1=<hex during key rotation>
 *   signed_payload   = "<t>.<raw request body>"
 *   expected         = HMAC-SHA256(signed_payload, whsec)
 *
 * Three things that must be right:
 *
 *   RAW BODY   The signature covers the exact bytes Stripe sent. Any JSON
 *              parse-and-restringify before verification changes key order or
 *              whitespace and the signature fails. The body must reach this
 *              function untouched.
 *   TIMESTAMP  Rejecting old timestamps is what prevents replay: without it, a
 *              captured valid request can be resent forever.
 *   CONSTANT   Comparison must not short-circuit on the first differing byte.
 */

export const DEFAULT_TOLERANCE_SECONDS = 300;

export function parseSignatureHeader(header) {
  const out = { timestamp: null, signatures: [] };
  if (typeof header !== "string") return out;
  for (const part of header.split(",")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k === "t") out.timestamp = Number(v);
    else if (k === "v1") out.signatures.push(v);
  }
  return out;
}

/**
 * @param rawBody Buffer or string — the untouched request body.
 * @returns {{ok: boolean, reason?: string, event?: object}}
 */
export function verifyStripeSignature(rawBody, header, secret, opts = {}) {
  const tolerance = opts.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
  const now = opts.now ?? Math.floor(Date.now() / 1000);

  if (!secret) return { ok: false, reason: "no webhook secret configured" };

  const { timestamp, signatures } = parseSignatureHeader(header);
  if (!Number.isFinite(timestamp)) return { ok: false, reason: "missing or malformed timestamp" };
  if (signatures.length === 0) return { ok: false, reason: "no v1 signature present" };

  // Replay window. Also rejects timestamps implausibly far in the future.
  const age = now - timestamp;
  if (age > tolerance) return { ok: false, reason: `timestamp too old (${age}s > ${tolerance}s)` };
  if (age < -tolerance) return { ok: false, reason: "timestamp is in the future" };

  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, "utf8");
  const signedPayload = Buffer.concat([Buffer.from(`${timestamp}.`, "utf8"), body]);
  const expected = createHmac("sha256", secret).update(signedPayload).digest();

  // Stripe may send several v1 signatures while a secret is being rotated;
  // any one matching is valid.
  const matched = signatures.some((sig) => {
    let given;
    try {
      given = Buffer.from(sig, "hex");
    } catch {
      return false;
    }
    return given.length === expected.length && timingSafeEqual(given, expected);
  });
  if (!matched) return { ok: false, reason: "signature mismatch" };

  let event;
  try {
    event = JSON.parse(body.toString("utf8"));
  } catch (e) {
    return { ok: false, reason: `body is not valid JSON: ${e.message}` };
  }
  return { ok: true, event };
}

/** Test helper: produce a header the verifier will accept. Not used in production. */
export function signPayloadForTest(rawBody, secret, timestamp = Math.floor(Date.now() / 1000)) {
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, "utf8");
  const signedPayload = Buffer.concat([Buffer.from(`${timestamp}.`, "utf8"), body]);
  const sig = createHmac("sha256", secret).update(signedPayload).digest("hex");
  return `t=${timestamp},v1=${sig}`;
}

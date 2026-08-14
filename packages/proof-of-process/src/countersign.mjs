import { canonicalJSON, sha256Hex } from "./canonical.mjs";

/**
 * Countersignatures — the mechanism that lifts evidence above self-attestation.
 *
 * A creator signing their own record proves it has not changed since signing.
 * It cannot prove the record was not fabricated before signing, because the
 * creator holds the key. The only fix is a signature from a key the creator
 * does not control.
 *
 * WHAT A COUNTERSIGNER ACTUALLY WITNESSED matters enormously, and is the thing
 * most likely to be overstated, so it is a required field rather than an
 * implication:
 *
 *   observed: "submission"  The signer received this digest from an
 *                           authenticated client at a given time. It did NOT
 *                           watch the work happen — a client could still submit
 *                           the digest of a fabricated session. What this
 *                           defeats is backdating and repudiation, and it binds
 *                           the record to an account.
 *
 *   observed: "capture"     The signer observed the events as they occurred and
 *                           produced the record itself. Only a capture surface
 *                           that is not under the creator's control can honestly
 *                           claim this.
 *
 * A countersignature signs a STATEMENT, not the bare subject digest, so every
 * claim it makes — who signed, what they witnessed, when — is bound by the
 * signature. Signing only the digest would leave the surrounding metadata
 * freely editable, which would make the strongest field in the record the
 * easiest one to forge.
 */

export const COUNTERSIGN_VERSION = 1;
export const OBSERVED = { SUBMISSION: "submission", CAPTURE: "capture" };
export const ROLES = { PLATFORM: "platform", WITNESS: "witness" };

/**
 * Build the canonical statement a countersigner signs.
 *
 * `subject` is the attestation's header digest — the same value the creator
 * signed and the same value anchored on chain, which is what ties the
 * countersignature to one specific record.
 */
export function buildStatement({ role, signer, observed, observedAt, subject, clientKeyId = null }) {
  if (!ROLES[role?.toUpperCase?.()] && !Object.values(ROLES).includes(role)) {
    throw new Error(`countersign: unknown role "${role}"`);
  }
  if (!Object.values(OBSERVED).includes(observed)) {
    throw new Error(`countersign: observed must be one of ${Object.values(OBSERVED).join(", ")}`);
  }
  if (!/^[0-9a-f]{64}$/i.test(subject ?? "")) {
    throw new Error("countersign: subject must be a 64-char hex digest");
  }
  return {
    v: COUNTERSIGN_VERSION,
    type: "proof-of-process.countersignature",
    role,
    signer,
    observed,
    observedAt,
    subject,
    clientKeyId,
  };
}

/** The digest a countersigner actually signs. */
export function statementDigest(statement) {
  return sha256Hex(canonicalJSON(statement));
}

/**
 * Verify a countersignature against the record it claims to cover.
 *
 * Returns ok:null when the crypto peer dep is missing — a missing library is
 * not evidence of forgery, and a structural verify should still work offline.
 */
export async function verifyCountersignature(cs, subjectDigest) {
  if (!cs || typeof cs !== "object") return { ok: false, reason: "countersignature is not an object" };

  // Rebuild the statement from the countersignature's own fields. If any of
  // them were edited after signing, the digest changes and the check fails.
  let statement;
  try {
    statement = buildStatement({
      role: cs.role,
      signer: cs.signer,
      observed: cs.observed,
      observedAt: cs.observedAt,
      subject: cs.subject,
      clientKeyId: cs.clientKeyId ?? null,
    });
  } catch (e) {
    return { ok: false, reason: `malformed countersignature: ${e.message}` };
  }

  // The statement must be about THIS record.
  if (cs.subject !== subjectDigest) {
    return {
      ok: false,
      reason: `countersignature covers a different record (${cs.subject?.slice(0, 16)}… not ${subjectDigest?.slice(0, 16)}…)`,
    };
  }

  const digest = statementDigest(statement);
  try {
    if (cs.algorithm?.startsWith("ML-DSA")) {
      const mod = await import("@noble/post-quantum/ml-dsa");
      const impl = { "ML-DSA-44": mod.ml_dsa44, "ML-DSA-65": mod.ml_dsa65, "ML-DSA-87": mod.ml_dsa87 }[
        cs.algorithm
      ];
      if (!impl) return { ok: false, reason: `unknown ML-DSA parameter set: ${cs.algorithm}` };
      const ok = impl.verify(dec(cs.publicKey, cs.encoding), hex(digest), dec(cs.signature, cs.encoding));
      return ok ? { ok: true, statement } : { ok: false, reason: "countersignature did not verify" };
    }
    if (cs.algorithm === "ECDSA-secp256k1") {
      const { secp256k1 } = await import("@noble/curves/secp256k1");
      const ok = secp256k1.verify(dec(cs.signature, cs.encoding), hex(digest), dec(cs.publicKey, cs.encoding));
      return ok ? { ok: true, statement } : { ok: false, reason: "countersignature did not verify" };
    }
    return { ok: null, reason: `no verifier for algorithm ${cs.algorithm}` };
  } catch (e) {
    if (e?.code === "ERR_MODULE_NOT_FOUND") {
      return { ok: null, reason: "install @noble/post-quantum to check countersignatures" };
    }
    return { ok: false, reason: `countersignature check threw: ${e?.message ?? e}` };
  }
}

/**
 * Whether a verified countersignature is from a key the creator plausibly does
 * not control. A countersignature whose public key equals the creator's own is
 * theatre, and is rejected rather than counted.
 */
export function isIndependentOf(cs, creatorPublicKey) {
  return !!cs.publicKey && cs.publicKey !== creatorPublicKey;
}

function dec(s, encoding) {
  return new Uint8Array(Buffer.from(s, encoding === "hex" ? "hex" : "base64"));
}

function hex(h) {
  return new Uint8Array(Buffer.from(h, "hex"));
}

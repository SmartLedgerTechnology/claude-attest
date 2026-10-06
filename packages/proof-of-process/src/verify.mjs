import { canonicalJSON, hashLeaf, sha256Hex } from "./canonical.mjs";
import { merkleRoot } from "./merkle.mjs";
import { derive } from "./profile.mjs";
import { evidenceLevel, anchorClaimed } from "./evidence.mjs";
import { verifyCountersignature, isIndependentOf } from "./countersign.mjs";

export const CHECKPOINT_FORMAT = "proof-of-process.checkpoint.v1";
const SUPPORTED_FORMATS = new Set([CHECKPOINT_FORMAT]);
const SUPPORTED_ALGORITHMS = new Set(["ML-DSA-65", "ML-DSA-87", "ECDSA-secp256k1"]);

/**
 * Verify a claude-attest attestation.
 *
 * The checks are ordered by what they prove:
 *
 *   1. structure    — format is known, leaves are sequenced 0..N-1
 *   2. hashChain    — every leaf's `prev` equals the hash of the leaf before it,
 *                     so no leaf was spliced out of the middle of the log
 *   3. merkleRoot   — the tree recomputed from `leaves` matches the header
 *   4. anchorBinding— sha256(canonicalJSON(header)) equals the certificate's
 *                     payloadHash, i.e. the thing that got anchored on BSV is
 *                     THIS header and not some other one
 *   5. signature    — the ML-DSA signature over that digest verifies
 *   6. transcriptChain — the attested transcript uuids form an unbroken
 *                     parentUuid path, so no turn happened un-attested
 *
 * Checks 5 and 7 (on-chain confirmation) need optional peer deps. When those
 * are absent the check is reported as `null` (could not run) rather than false
 * — a missing library is not evidence of forgery.
 *
 * The verdict has three states, because "nothing failed" is not "everything
 * was checked":
 *
 *   verified    every required check ran and passed
 *   failed      at least one check ran and did not pass
 *   incomplete  nothing failed, but a required check could not run
 *
 * A check that could not run can never add up to a pass. Which checks are
 * required is decided here, from what the record claims — never from a field
 * the holder of the file can edit to make a check go away. `ok` is true only
 * for `verified`.
 */
export async function verifyAttestation(attestation, opts = {}) {
  const reasons = [];
  const checks = {
    format: false,
    leafContinuity: false,
    hashChain: false,
    merkleRoot: false,
    anchorBinding: null,
    signature: null,
    transcriptChain: null,
    onChain: null,
  };

  const { header, certificate } = attestation;
  // Leaves are optional. A published attestation deliberately omits them: the
  // Merkle root and the profile are already inside the signed header, so a
  // third party can verify every claim without the creator disclosing what was
  // said, typed, or run. Absent leaves are SKIPPED, never failed — "you didn't
  // show me your private log" is not evidence of tampering.
  const leavesDisclosed = Array.isArray(attestation.leaves);
  const leaves = leavesDisclosed ? attestation.leaves : [];

  if (!header || !SUPPORTED_FORMATS.has(header.format)) {
    reasons.push(`unsupported format: ${header?.format}`);
  } else {
    checks.format = true;
  }

  if (!leavesDisclosed) {
    checks.leafContinuity = null;
    checks.hashChain = null;
    checks.merkleRoot = null;
  }

  // 1. Sequence continuity.
  if (leavesDisclosed) {
    let continuous = leaves.length === header?.leafCount;
    if (!continuous) reasons.push(`leafCount ${header?.leafCount} != leaves.length ${leaves.length}`);
    for (let i = 0; i < leaves.length; i++) {
      if (leaves[i].seq !== i) {
        continuous = false;
        reasons.push(`leaf sequence break at index ${i}: seq=${leaves[i].seq}`);
        break;
      }
    }
    checks.leafContinuity = continuous;
  }

  // 2. Hash chain. The genesis leaf's prev is the all-zero hash.
  let chained = true;
  let expectedPrev = "0".repeat(64);
  for (const leaf of leavesDisclosed ? leaves : []) {
    if (leaf.prev !== expectedPrev) {
      chained = false;
      reasons.push(`hash chain break at seq=${leaf.seq}: prev=${leaf.prev?.slice(0, 12)}… expected ${expectedPrev.slice(0, 12)}…`);
      break;
    }
    expectedPrev = hashLeaf(leaf);
  }
  if (leavesDisclosed) checks.hashChain = chained;

  // 3. Merkle root.
  if (leavesDisclosed) {
    const root = merkleRoot(leaves.map(hashLeaf));
    checks.merkleRoot = root === header?.merkleRoot;
    if (!checks.merkleRoot) {
      reasons.push(`merkle root mismatch: computed ${root}, header ${header?.merkleRoot}`);
    }
  }

  // 4 + 5. Anchor binding and signature.
  const headerDigest = header ? sha256Hex(canonicalJSON(header)) : null;
  if (certificate) {
    checks.anchorBinding = headerDigest === certificate.payloadHash;
    if (!checks.anchorBinding) {
      reasons.push(
        `anchor binding failed: sha256(header)=${headerDigest?.slice(0, 16)}… but certificate.payloadHash=${certificate.payloadHash?.slice(0, 16)}…`
      );
    }
    if (opts.strict && !SUPPORTED_ALGORITHMS.has(certificate.algorithm)) {
      reasons.push(`unsupported signature algorithm: ${certificate.algorithm}`);
    }
    const sig = await verifySignature(certificate);
    checks.signature = sig.ok;
    if (sig.ok === false) reasons.push(sig.reason ?? "signature did not verify");
    if (sig.ok === null && opts.strict) {
      reasons.push(`signature not checked: ${sig.reason}`);
    }
  } else {
    reasons.push("no certificate: attestation was never anchored");
  }

  // 6. Transcript chain — the anti-omission check.
  if (header?.transcript) {
    const t = header.transcript;
    checks.transcriptChain = t.chainContiguous === true;
    if (t.cursorIntact === false) {
      reasons.push(
        "transcript was rewritten: the line at the previously attested position no longer carries the recorded uuid"
      );
    }
    if (t.parentsResolve === false) {
      reasons.push(
        `transcript has ${t.gapCount} line(s) whose parent is missing from the file — history was deleted out of the middle`
      );
    }
    if (!checks.transcriptChain && t.cursorIntact !== false && t.parentsResolve !== false) {
      reasons.push("transcript chain reported non-contiguous");
    }
  }

  // 7. On-chain confirmation, delegated to the NotaryHash SDK when present.
  //
  // Nothing in `certificate.anchor` is covered by the creator's signature, so
  // it is carried as `claimed` and is never reported as fact. The verified
  // fields below are filled only from the chain check's own result.
  const incomplete = [];
  if (checks.signature === null && certificate) incomplete.push("signature could not be checked");

  let anchorSummary = { present: false, state: "none" };
  if (certificate?.anchor || certificate?.spv) {
    const a = certificate.anchor ?? {};
    const claimed = anchorClaimed(certificate);
    anchorSummary = {
      present: true,
      // none: no anchor is claimed (the free tier). unconfirmed: one is claimed
      // and could not be confirmed. confirmed / failed: the chain check ran.
      state: claimed ? "unconfirmed" : "none",
      txid: null,
      blockHeight: null,
      blockTime: null,
      network: null,
      claimed: { network: a.network, txid: a.txid, blockHeight: a.blockHeight, blockTime: a.blockTime, type: a.type },
    };
    // Any claimed anchor must be confirmed, whatever the certificate calls its
    // network. Only a record that claims nothing has nothing to disprove — that
    // is the free tier, and it is reported as locally verified, not as broken.
    if (claimed) {
      const chain = opts.checkChain
        ? await (opts.verifyChain ?? verifyOnChain)(certificate, opts)
        : { ok: null, reason: "the chain check was not requested" };
      checks.onChain = chain.ok === true ? true : chain.ok === false ? false : null;
      if (checks.onChain === true) {
        anchorSummary.state = "confirmed";
        // The chain check ties these two to the proof: the raw transaction must
        // hash to this txid, and the network must be the one verified against.
        anchorSummary.txid = a.txid;
        anchorSummary.network = a.network;
        anchorSummary.blockHeight = chain.blockHeight ?? null;
        anchorSummary.blockTime = chain.blockTime ?? null;
      } else if (checks.onChain === false) {
        anchorSummary.state = "failed";
        reasons.push(chain.reason || "on-chain anchor did not verify");
      } else {
        incomplete.push(`anchor not confirmed: ${chain.reason || "the chain could not be consulted"}`);
      }
    }
  }

  // The profile is signed data; the ratios are derived at verify time on
  // purpose. A verifier should be able to argue with the interpretation
  // without being able to argue with the measurements.
  const profile = header?.profile ?? null;

  // Countersignatures raise the evidence level, but only once verified — an
  // unchecked countersignature is a claim, not evidence. Two ways one can be
  // present and still not count: it fails to verify, or it was made with the
  // creator's own key, which proves nothing the creator's signature didn't.
  const verifiedCounters = [];
  for (const c of attestation.countersignatures ?? []) {
    const result = await verifyCountersignature(c, headerDigest);
    if (result.ok !== true) {
      if (result.ok === false) {
        reasons.push(`countersignature (${c.role ?? "unknown"}): ${result.reason}`);
      }
      continue;
    }
    if (!isIndependentOf(c, certificate?.publicKey)) {
      reasons.push(
        `countersignature (${c.role ?? "unknown"}) uses the creator's own key — it adds no independent evidence`
      );
      continue;
    }
    verifiedCounters.push(c);
  }

  // Fail closed twice over: a false check fails the record even if it filed no
  // reason, and a reason fails it even if no check is marked false.
  const failed = reasons.length > 0 || Object.values(checks).includes(false);
  const verdict = failed ? "failed" : incomplete.length > 0 ? "incomplete" : "verified";

  return {
    ok: verdict === "verified",
    verdict,
    reasons,
    incomplete,
    checks,
    evidence: evidenceLevel(attestation, checks, verifiedCounters),
    anchor: anchorSummary,
    profile,
    derived: profile ? derive(profile) : null,
    capture: header?.capture ?? null,
    session: header
      ? { sessionId: header.sessionId, cwd: header.cwd, startedAt: header.startedAt, endedAt: header.endedAt }
      : null,
  };
}

/**
 * Verify the certificate's signature over its payloadHash. Returns ok:null when
 * the crypto peer dep is missing, so a bare `npx` verify still reports the
 * structural checks instead of failing outright.
 */
async function verifySignature(certificate) {
  const { algorithm, payloadHash, publicKey, signature, encoding } = certificate;
  try {
    if (algorithm?.startsWith("ML-DSA")) {
      const { ml_dsa44, ml_dsa65, ml_dsa87 } = await import("@noble/post-quantum/ml-dsa");
      const impl = { "ML-DSA-44": ml_dsa44, "ML-DSA-65": ml_dsa65, "ML-DSA-87": ml_dsa87 }[algorithm];
      if (!impl) return { ok: false, reason: `unknown ML-DSA parameter set: ${algorithm}` };
      const ok = impl.verify(
        decode(publicKey, encoding),
        hexToBytes(payloadHash),
        decode(signature, encoding)
      );
      return { ok, reason: ok ? undefined : "ML-DSA signature did not verify" };
    }
    if (algorithm === "ECDSA-secp256k1") {
      const { secp256k1 } = await import("@noble/curves/secp256k1");
      const ok = secp256k1.verify(decode(signature, encoding), hexToBytes(payloadHash), decode(publicKey, encoding));
      return { ok, reason: ok ? undefined : "ECDSA signature did not verify" };
    }
    return { ok: null, reason: `no verifier for algorithm ${algorithm}` };
  } catch (e) {
    if (e?.code === "ERR_MODULE_NOT_FOUND") {
      return { ok: null, reason: "install @noble/post-quantum to check signatures" };
    }
    return { ok: false, reason: `signature check threw: ${e?.message ?? e}` };
  }
}

/**
 * Confirm the certificate's anchor against block headers.
 *
 * Returns ok true / false / null. null means "could not tell" — a header source
 * down or throttled, sources not agreeing, no proof in the certificate yet — and
 * must never be read as a pass or as a failure. The SDK's own `ok` is false for
 * both invalid and indeterminate, so the three states are built from its parts.
 *
 * blockHeight and blockTime are the SDK's, read from the block header, and are
 * the only block facts a caller may present as verified.
 */
export async function verifyOnChain(certificate, opts = {}) {
  try {
    const sdk = await import("@smartledger/notaryhash");
    if (!sdk.DEFAULT_HEADER_POLICY || !sdk.BitailsHeaderProvider) {
      return { ok: null, reason: "@smartledger/notaryhash 2.1.4 or later is needed to check the on-chain anchor" };
    }
    // Two independent header sources that must agree: with one, the verifier
    // believes whatever that one source says.
    const headers =
      opts.headerProvider ??
      new sdk.MultiSourceHeaderProvider([
        new sdk.WocHeaderProvider("https://api.whatsonchain.com/v1/bsv/main"),
        new sdk.BitailsHeaderProvider("https://api.bitails.io"),
      ]);
    const v = await sdk.verifyCertificateStandalone(certificate, headers, opts.headerPolicy ?? sdk.DEFAULT_HEADER_POLICY);
    const reason = (v.reasons ?? []).join("; ");
    if (v.signatureValid === false || v.proofHashValid === false || v.anchorStatus === "invalid") {
      return { ok: false, reason: reason || "the certificate did not verify" };
    }
    if (v.anchorStatus === "valid") {
      if (v.ok !== true) return { ok: false, reason: reason || "the certificate did not verify" };
      return { ok: true, blockHeight: v.blockHeight ?? null, blockTime: v.blockTime ?? null };
    }
    return { ok: null, reason: reason || "the anchor could not be confirmed" };
  } catch (e) {
    if (e?.code === "ERR_MODULE_NOT_FOUND") {
      return { ok: null, reason: "install @smartledger/notaryhash to check the on-chain anchor" };
    }
    return { ok: null, reason: `on-chain check could not run: ${e?.message ?? e}` };
  }
}

function decode(s, encoding) {
  return new Uint8Array(Buffer.from(s, encoding === "hex" ? "hex" : "base64"));
}

function hexToBytes(hex) {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

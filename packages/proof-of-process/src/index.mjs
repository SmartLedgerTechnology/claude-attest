/**
 * proof-of-process — a portable format for attesting HOW a piece of work was
 * produced, and a verifier for it.
 *
 * The format describes a collaboration between a person and a model as a
 * hash-chained sequence of leaves, summarized by a signed checkpoint header
 * carrying a collaboration profile. Anchoring the header digest to a public
 * chain (via NotaryHash) turns it into a timestamp anyone can check.
 *
 * Nothing in this package is specific to any one tool. Capture adapters —
 * a Claude Code plugin, a browser extension, an editor add-in — produce
 * checkpoints in this format; this one verifier reads all of them.
 */

export { canonicalJSON, sha256Hex, hashPayload, hashLeaf } from "./canonical.mjs";
export { merkleRoot, merkleProof, verifyMerkleProof } from "./merkle.mjs";
export { verifyAttestation, CHECKPOINT_FORMAT } from "./verify.mjs";
export {
  PROFILE_VERSION,
  emptyProfile,
  newAccumulatorState,
  accumulate,
  finalizeProfile,
  mergeProfiles,
  derive,
} from "./profile.mjs";
export {
  COUNTERSIGN_VERSION,
  OBSERVED,
  ROLES,
  buildStatement,
  statementDigest,
  verifyCountersignature,
  isIndependentOf,
} from "./countersign.mjs";
export {
  EVIDENCE_LEVELS,
  COUNTERSIGNATURE_ROLES,
  evidenceLevel,
} from "./evidence.mjs";
export {
  ASSERTION_LABEL,
  ACTIONS_LABEL,
  DIGITAL_SOURCE_TYPES,
  recommendDigitalSourceType,
  buildProcessAssertion,
  buildActionsAssertion,
  buildManifestDefinition,
  buildGatheredAssertions,
} from "./c2pa.mjs";

/** The all-zero hash. Genesis leaf's `prev`, and the empty Merkle root. */
export const ZERO_HASH = "0".repeat(64);

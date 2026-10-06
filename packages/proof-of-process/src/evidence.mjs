/**
 * Evidence levels.
 *
 * A verification result is not pass/fail — an attestation can be cryptographically
 * perfect and still be weak evidence, because the person who signed it is the
 * person it vouches for. What actually varies is WHO stands behind the record.
 *
 *   1  Self Attested            the creator captured and signed their own work
 *   2  Platform Observed        the capture surface countersigned it
 *   3  Independently Witnessed  a party with no stake countersigned it
 *
 * Level 1 is honest and useful — it proves the record existed at a point in time
 * and has not changed. It does not close the fabrication hole, because the
 * operator holds the key. Only a signature from a key the creator does not
 * control does that, which is why the ladder exists rather than a single score.
 *
 * We report the level reached AND what the next one requires, so nobody has to
 * guess how much weight a given certificate carries.
 */

export const EVIDENCE_LEVELS = {
  // Two very different situations share level 0, and conflating them is a bad
  // first impression: a sound-but-unanchored record is the entire free tier,
  // not a failure. `report()` picks the accurate summary.
  0: { name: "Unverified", summary: "Integrity checks did not pass." },
  "0-unanchored": {
    name: "Locally Verified",
    summary: "Sound and tamper-evident, but not yet anchored to a public chain.",
  },
  "0-pending": {
    name: "Anchor Pending",
    summary: "An anchoring transaction is claimed, but it has not been confirmed in a block.",
  },
  1: {
    name: "Self Attested",
    summary: "Creator-controlled capture, cryptographically sealed and independently timestamped.",
  },
  2: {
    name: "Platform Observed",
    summary: "The capture surface countersigned the record alongside the creator.",
  },
  3: {
    name: "Independently Witnessed",
    summary: "A party with no stake in the outcome countersigned the record.",
  },
};

/** Roles a countersignature can be presented under. */
export const COUNTERSIGNATURE_ROLES = { PLATFORM: "platform", WITNESS: "witness" };

/**
 * Does this certificate CLAIM a public anchor?
 *
 * Everything in `certificate.anchor` is outside the creator's signature, so it
 * is only ever a claim. This answers "is there a claim that must be checked
 * against the chain", and deliberately ignores the `network` label: a label
 * the holder can edit must not be able to switch a check off.
 */
export function anchorClaimed(certificate) {
  const a = certificate?.anchor;
  return certificate?.spv != null || (!!a && (!!a.txid || a.blockHeight != null || a.blockTime != null));
}

/**
 * Determine the evidence level from verified checks plus any countersignatures.
 *
 * `checks` is the object produced by verifyAttestation. A countersignature only
 * counts once it has actually been verified — an unverified one is a claim, not
 * evidence, so callers must pass `verifiedCountersignatures`.
 */
export function evidenceLevel(attestation, checks, verifiedCountersignatures = []) {
  // `null` means "not disclosed", which is acceptable; `false` means "failed",
  // which is not. A published attestation withholds its leaves by design.
  const notFailed = (v) => v !== false;
  const integrity =
    checks.format === true &&
    notFailed(checks.leafContinuity) &&
    notFailed(checks.hashChain) &&
    notFailed(checks.merkleRoot);

  // A false transcript check is disqualifying; null (not applicable) is not.
  const structureIntact = integrity && checks.transcriptChain !== false;
  const signed = checks.signature === true && checks.anchorBinding === true;
  // A timestamp is something the chain check established, never something the
  // certificate says about itself: a block height typed into the file is not
  // evidence of a block.
  const timestamped = checks.onChain === true;
  // Claimed but unconfirmed is a real intermediate state: a transaction is
  // named, and no block we could verify contains it yet.
  const broadcast = anchorClaimed(attestation.certificate);

  // An anchor that was checked and did not verify is a failure, not a pending
  // timestamp, and no countersignature can lift a record above it.
  if (!structureIntact || !signed || checks.onChain === false) {
    return report(
      0,
      { integrity: structureIntact && checks.onChain !== false, signed, timestamped, broadcast },
      verifiedCountersignatures
    );
  }

  // An anchor still in the mempool is a pending timestamp, not an independent
  // one — nothing outside the issuing service has committed to it yet.
  if (!timestamped) {
    return report(
      0,
      { integrity: true, signed: true, timestamped: false, broadcast },
      verifiedCountersignatures,
      broadcast
        ? "the anchoring transaction has not been mined yet, or the chain could not be consulted"
        : "no anchor has been submitted"
    );
  }

  const roles = new Set(verifiedCountersignatures.map((c) => c.role));
  if (roles.has(COUNTERSIGNATURE_ROLES.WITNESS)) {
    return report(3, { integrity: true, signed: true, timestamped: true, broadcast }, verifiedCountersignatures);
  }
  if (roles.has(COUNTERSIGNATURE_ROLES.PLATFORM)) {
    return report(2, { integrity: true, signed: true, timestamped: true, broadcast }, verifiedCountersignatures);
  }
  return report(1, { integrity: true, signed: true, timestamped: true, broadcast }, verifiedCountersignatures);
}

function report(level, criteria, countersignatures, blockedBy) {
  // Integrity intact but no public timestamp is the free tier working exactly
  // as designed — say so, rather than implying something is broken.
  const soundButUnanchored = level === 0 && criteria.integrity && criteria.signed && !criteria.timestamped;
  const key = soundButUnanchored ? (criteria.broadcast ? "0-pending" : "0-unanchored") : level;
  const descriptor = EVIDENCE_LEVELS[key];

  const next = {
    0: soundButUnanchored
      ? criteria.broadcast
        ? "the anchoring transaction to be mined and confirmed against block headers (usually minutes)"
        : "anchoring this attestation to a public chain"
      : "pass the integrity, signature and timestamp checks",
    1: "a countersignature from the capture platform (role: platform)",
    2: "a countersignature from an independent witness (role: witness)",
    3: null,
  }[level];

  return {
    level,
    name: descriptor.name,
    summary: descriptor.summary,
    criteria,
    countersignatures: countersignatures.map((c) => ({ role: c.role, keyId: c.keyId })),
    nextLevelRequires: next,
    blockedBy: blockedBy ?? undefined,
    // Stated plainly so it survives being quoted out of context.
    caveat:
      level === 1
        ? "Level 1 does not establish authorship: the signing key is held by the creator, " +
          "so the record is unforgeable after signing but not before."
        : undefined,
  };
}

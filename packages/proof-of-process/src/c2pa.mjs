import { canonicalJSON, sha256Hex } from "./canonical.mjs";
import { derive } from "./profile.mjs";

/**
 * C2PA / Content Credentials interoperability.
 *
 * C2PA is the incumbent provenance standard and it already has the field that
 * matters here: every standard manifest must declare a `digitalSourceType`
 * saying whether an asset was captured, human-made, AI-generated, or a mix.
 *
 * Today that declaration is entirely self-reported. Nothing checks it, and
 * nothing can. What proof-of-process contributes is the missing half: a
 * measured, signed, blockchain-anchored record of how the work was actually
 * produced, attached to the manifest as evidence backing the declaration.
 *
 * Two integration paths, both supported here:
 *
 *   GATHERED   Another party — an editor, a publishing pipeline, a camera
 *              vendor — signs the manifest and includes our assertion as a
 *              `gathered_assertion`. We need no certificate and no place on a
 *              trust list. This is the path we should lead with.
 *
 *   STANDALONE We sign our own manifest. C2PA permits only X.509 signing, so
 *              this needs a real certificate, and until we are on a recognized
 *              trust list validators will report "valid signature, unknown
 *              signer". `buildManifestDefinition()` emits a c2patool-compatible
 *              definition for when that certificate exists.
 */

/** Reverse-DNS per C2PA custom-assertion rules; the trailing integer is the version. */
export const ASSERTION_LABEL = "ai.proofofprocess.process.v1";
export const ACTIONS_LABEL = "c2pa.actions.v2";

/** IPTC Digital Source Type vocabulary — the values C2PA points at. */
export const DIGITAL_SOURCE_TYPES = {
  digitalCapture: "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture",
  digitalCreation: "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCreation",
  humanEdits: "http://cv.iptc.org/newscodes/digitalsourcetype/humanEdits",
  trainedAlgorithmicMedia: "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
  compositeWithTrainedAlgorithmicMedia:
    "http://cv.iptc.org/newscodes/digitalsourcetype/compositeWithTrainedAlgorithmicMedia",
  compositeSynthetic: "http://cv.iptc.org/newscodes/digitalsourcetype/compositeSynthetic",
};

/**
 * Recommend the digitalSourceType the measurements will actually support.
 *
 * This is a RECOMMENDATION, deliberately, and the wording matters: C2PA's
 * digitalSourceType describes an *asset*, while a profile describes a
 * *session*, and one session can produce many assets of different character.
 * We can say what the session evidences; the creator still declares. Emitting
 * this as an authoritative label would be overreach, and would be the first
 * thing an opposing expert attacked.
 */
export function recommendDigitalSourceType(profile) {
  const d = derive(profile);

  if (profile.assistantTurns === 0 || profile.assistantOutputChars === 0) {
    return {
      value: DIGITAL_SOURCE_TYPES.digitalCreation,
      term: "digitalCreation",
      rationale: "No generative model output was recorded in this session.",
    };
  }

  if (profile.humanTurns === 0) {
    return {
      value: DIGITAL_SOURCE_TYPES.trainedAlgorithmicMedia,
      term: "trainedAlgorithmicMedia",
      rationale:
        `No human-originated input: all ${profile.unattendedTurns} input(s) came from an ` +
        `automated driver. The session ran unattended.`,
    };
  }

  // One instruction, no iteration: human-originated but not human-authored in
  // any sense a copyright examiner would credit.
  if (profile.humanTurns === 1 && profile.revisionCycles === 0) {
    return {
      value: DIGITAL_SOURCE_TYPES.trainedAlgorithmicMedia,
      term: "trainedAlgorithmicMedia",
      rationale:
        "A single human instruction with no subsequent revision. The human contribution is " +
        "direction only, with no iterative authorship evidenced.",
    };
  }

  // The human wrote more than the model did: this reads as human-authored work
  // that a model assisted, not model output a human steered.
  if (d.charRatio >= 1) {
    return {
      value: DIGITAL_SOURCE_TYPES.compositeWithTrainedAlgorithmicMedia,
      term: "compositeWithTrainedAlgorithmicMedia",
      rationale:
        `Human input (${profile.humanInputChars} chars) exceeds model output ` +
        `(${profile.assistantOutputChars} chars) across ${profile.humanTurns} turns, with ` +
        `${profile.revisionCycles} revision cycle(s). Consistent with human-authored work ` +
        `enhanced using a generative model.`,
    };
  }

  return {
    value: DIGITAL_SOURCE_TYPES.compositeSynthetic,
    term: "compositeSynthetic",
    rationale:
      `${profile.humanTurns} human turn(s) directing ${profile.assistantTurns} model turn(s), ` +
      `with ${profile.revisionCycles} revision cycle(s) (${Math.round(d.revisionRatio * 100)}% of ` +
      `human turns) over ${d.activeMinutes} active minute(s). Consistent with a mix of human and ` +
      `generative elements.`,
  };
}

/**
 * The custom assertion. This is the payload another party embeds as a
 * gathered_assertion, and it is self-contained: everything needed to verify
 * the claim independently is either in here or reachable from the txid.
 */
export function buildProcessAssertion(attestation, opts = {}) {
  const { header, certificate } = attestation;
  const profile = header.profile;
  const recommendation = recommendDigitalSourceType(profile);

  return {
    label: ASSERTION_LABEL,
    data: {
      version: 1,
      specification: "proof-of-process/1.0",

      // What was signed and anchored. A verifier recomputes this digest from
      // the attestation and matches it against the on-chain record.
      attestation: {
        format: header.format,
        sessionId: header.sessionId,
        merkleRoot: header.merkleRoot,
        headerDigest: sha256Hex(canonicalJSON(header)),
        leafCount: header.leafCount,
        algorithm: header.algorithm,
        publicKeyId: header.publicKeyId,
        startedAt: header.startedAt,
        endedAt: header.endedAt,
      },

      anchor: certificate?.anchor
        ? {
            protocol: `${certificate.protocol}/${certificate.version}`,
            network: certificate.anchor.network,
            txid: certificate.anchor.txid,
            blockHeight: certificate.anchor.blockHeight,
            blockTime: certificate.anchor.blockTime,
          }
        : null,

      capture: header.capture,

      // The measurements. Signed, so they cannot be adjusted after the fact
      // without breaking verification.
      profile,
      derived: derive(profile),

      integrity: {
        transcriptCursorIntact: header.transcript?.cursorIntact ?? null,
        transcriptParentsResolve: header.transcript?.parentsResolve ?? null,
        transcriptLineCount: header.transcript?.lineCount ?? null,
      },

      recommendedDigitalSourceType: recommendation,

      verify: opts.verifyUrl ?? verifyUrlFor(attestation, opts),

      // Stated inside the assertion on purpose: anyone reading this manifest
      // should see the limits without having to find our documentation.
      scope: {
        establishes: [
          "A transcript with this content existed at the anchored block time.",
          "It has not been altered since; no history was rewritten or deleted.",
          "The collaboration measurements are bound into the signature.",
        ],
        doesNotEstablish: [
          "Authorship — the signing key is held by the operator.",
          "That the declared digitalSourceType is correct for any specific asset; " +
            "the profile describes a session, which may produce several assets.",
        ],
      },
    },
  };
}

/**
 * The actions assertion. Where the custom assertion carries evidence, this is
 * the part standard C2PA tooling already understands and displays.
 */
export function buildActionsAssertion(attestation, opts = {}) {
  const { header, certificate } = attestation;
  const recommendation = recommendDigitalSourceType(header.profile);
  const when = blockTimeIso(certificate) ?? header.endedAt ?? undefined;

  const softwareAgent = {
    name: opts.softwareAgentName ?? modelName(header) ?? "AI assistant",
    version: header.capture?.surfaceVersion ?? undefined,
  };

  const actions = [
    {
      action: opts.action ?? "c2pa.created",
      when,
      softwareAgent,
      digitalSourceType: recommendation.value,
      description: recommendation.rationale,
      parameters: {
        "ai.proofofprocess.sessionId": header.sessionId,
        "ai.proofofprocess.headerDigest": sha256Hex(canonicalJSON(header)),
        "ai.proofofprocess.txid": certificate?.anchor?.txid ?? null,
      },
    },
  ];

  return {
    label: ACTIONS_LABEL,
    data: {
      actions,
      // We only observed one session. Other tools may have touched this asset,
      // and claiming otherwise would be false.
      allActionsIncluded: false,
    },
  };
}

/**
 * A c2patool-compatible manifest definition for the standalone path. Signing
 * material is intentionally left out: `alg`, `private_key`, and `sign_cert`
 * are supplied at signing time by whoever holds the X.509 certificate.
 */
export function buildManifestDefinition(attestation, opts = {}) {
  const { header } = attestation;
  return {
    claim_generator_info: [
      {
        name: opts.claimGenerator ?? "ProofOfProcess.ai",
        version: header.capture?.adapterVersion ?? "0.1.0",
      },
    ],
    title: opts.title ?? `Session ${header.sessionId}`,
    ...(opts.format ? { format: opts.format } : {}),
    ...(opts.taUrl ? { ta_url: opts.taUrl } : {}),
    assertions: [buildActionsAssertion(attestation, opts), buildProcessAssertion(attestation, opts)],
  };
}

/**
 * Everything a third party needs to embed us as gathered_assertions in their
 * own manifest, with the instruction attached so it does not need explaining.
 */
export function buildGatheredAssertions(attestation, opts = {}) {
  return {
    note:
      "Add these to your manifest. Our assertion belongs in gathered_assertions — it is " +
      "contributed evidence, not a claim by your signer. The actions assertion is a " +
      "recommendation derived from measured data; confirm it describes your asset before " +
      "declaring it as created_assertions.",
    assertions: [buildActionsAssertion(attestation, opts), buildProcessAssertion(attestation, opts)],
  };
}

function verifyUrlFor(attestation, opts) {
  const base = (opts.verifyBase ?? "https://proofofprocess.ai").replace(/\/$/, "");
  const id = attestation.notaryHashId ?? attestation.header?.sessionId;
  return `${base}/v/${id}`;
}

function blockTimeIso(certificate) {
  const t = certificate?.anchor?.blockTime;
  return Number.isFinite(t) ? new Date(t * 1000).toISOString() : null;
}

function modelName(header) {
  const models = header.capture?.models;
  return Array.isArray(models) && models.length ? models.join(", ") : null;
}

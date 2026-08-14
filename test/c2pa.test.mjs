import test from "node:test";
import assert from "node:assert/strict";
import {
  ASSERTION_LABEL,
  ACTIONS_LABEL,
  DIGITAL_SOURCE_TYPES,
  recommendDigitalSourceType,
  buildProcessAssertion,
  buildActionsAssertion,
  buildManifestDefinition,
  buildGatheredAssertions,
} from "../packages/proof-of-process/src/c2pa.mjs";
import { emptyProfile, finalizeProfile } from "../packages/proof-of-process/src/profile.mjs";
import { canonicalJSON, sha256Hex } from "../packages/proof-of-process/src/canonical.mjs";
import { merkleRoot } from "../packages/proof-of-process/src/merkle.mjs";
import { CHECKPOINT_FORMAT } from "../packages/proof-of-process/src/verify.mjs";

function profile(overrides) {
  return finalizeProfile({ ...emptyProfile(), ...overrides });
}

function attestation(prof, { anchored = true } = {}) {
  const header = {
    v: 1,
    format: CHECKPOINT_FORMAT,
    sessionId: "sess-1",
    capture: {
      surface: "claude-code",
      surfaceVersion: "2.1.218",
      adapter: "claude-attest",
      adapterVersion: "0.1.0",
      models: ["claude-opus-4-8"],
    },
    startedAt: "2026-01-01T00:00:00.000Z",
    endedAt: "2026-01-01T02:00:00.000Z",
    leafCount: 3,
    merkleRoot: merkleRoot([sha256Hex("a"), sha256Hex("b"), sha256Hex("c")]),
    transcript: { headUuid: "u9", cursorIntact: true, parentsResolve: true, lineCount: 42 },
    profile: prof,
    algorithm: "ML-DSA-65",
    publicKeyId: "keyid123",
  };
  return {
    header,
    leaves: [],
    notaryHashId: "nh-abc",
    certificate: {
      protocol: "NotaryHash",
      version: "1.0",
      algorithm: "ML-DSA-65",
      payloadHash: sha256Hex(canonicalJSON(header)),
      anchor: anchored
        ? {
            type: "batch",
            network: "bsv-mainnet",
            txid: "d4e5f6",
            blockHeight: 880123,
            blockTime: 1767225600,
          }
        : null,
    },
  };
}

/* ---- the recommendation ladder ---- */

test("no model output is human creation", () => {
  const r = recommendDigitalSourceType(profile({ humanTurns: 5, assistantTurns: 0 }));
  assert.equal(r.term, "digitalCreation");
  assert.equal(r.value, DIGITAL_SOURCE_TYPES.digitalCreation);
});

test("no human input is trained algorithmic media", () => {
  const r = recommendDigitalSourceType(
    profile({ humanTurns: 0, unattendedTurns: 3, assistantTurns: 9, assistantOutputChars: 8000 })
  );
  assert.equal(r.term, "trainedAlgorithmicMedia");
  assert.match(r.rationale, /unattended/);
});

test("a single prompt with no revision is trained algorithmic media", () => {
  const r = recommendDigitalSourceType(
    profile({ humanTurns: 1, revisionCycles: 0, assistantTurns: 4, humanInputChars: 22, assistantOutputChars: 40000 })
  );
  assert.equal(r.term, "trainedAlgorithmicMedia");
  assert.match(r.rationale, /direction only/);
});

test("iterative direction over model output is a synthetic composite", () => {
  const r = recommendDigitalSourceType(
    profile({
      humanTurns: 16,
      revisionCycles: 14,
      assistantTurns: 92,
      humanInputChars: 10190,
      assistantOutputChars: 43125,
      activeSpanSeconds: 5040,
    })
  );
  assert.equal(r.term, "compositeSynthetic");
  assert.match(r.rationale, /16 human turn/);
  assert.match(r.rationale, /14 revision cycle/);
});

test("human writing more than the model is AI-assisted human work", () => {
  const r = recommendDigitalSourceType(
    profile({ humanTurns: 40, revisionCycles: 35, assistantTurns: 40, humanInputChars: 90000, assistantOutputChars: 20000 })
  );
  assert.equal(r.term, "compositeWithTrainedAlgorithmicMedia");
  assert.match(r.rationale, /exceeds model output/);
});

/* ---- assertion shape ---- */

test("process assertion uses a reverse-DNS versioned label", () => {
  const a = buildProcessAssertion(attestation(profile({ humanTurns: 3, assistantTurns: 5, assistantOutputChars: 100 })));
  assert.equal(a.label, ASSERTION_LABEL);
  assert.match(a.label, /^ai\.proofofprocess\./);
  // C2PA requires POSIX-ish components separated by periods.
  for (const part of a.label.split(".")) assert.match(part, /^[a-zA-Z0-9][a-zA-Z0-9_-]*$/);
});

test("process assertion binds the exact digest that was anchored", () => {
  const att = attestation(profile({ humanTurns: 3, assistantTurns: 5, assistantOutputChars: 100 }));
  const a = buildProcessAssertion(att);
  assert.equal(a.data.attestation.headerDigest, sha256Hex(canonicalJSON(att.header)));
  assert.equal(a.data.attestation.headerDigest, att.certificate.payloadHash);
  assert.equal(a.data.anchor.txid, "d4e5f6");
  assert.equal(a.data.anchor.blockHeight, 880123);
});

test("process assertion carries the profile and states its own limits", () => {
  const a = buildProcessAssertion(attestation(profile({ humanTurns: 16, assistantTurns: 92, assistantOutputChars: 43125 })));
  assert.equal(a.data.profile.humanTurns, 16);
  assert.ok(a.data.derived.revisionRatio !== undefined);
  assert.ok(a.data.scope.doesNotEstablish.some((s) => /Authorship/.test(s)));
  assert.match(a.data.verify, /^https:\/\/proofofprocess\.ai\/v\/nh-abc$/);
});

test("verify base URL is overridable for self-hosted deployments", () => {
  const a = buildProcessAssertion(attestation(profile({ humanTurns: 2, assistantTurns: 2, assistantOutputChars: 10 })), {
    verifyBase: "https://proof.acme.internal/",
  });
  assert.equal(a.data.verify, "https://proof.acme.internal/v/nh-abc");
});

test("actions assertion uses the v2 label and does not claim completeness", () => {
  const a = buildActionsAssertion(attestation(profile({ humanTurns: 4, assistantTurns: 6, assistantOutputChars: 500 })));
  assert.equal(a.label, ACTIONS_LABEL);
  assert.equal(a.data.allActionsIncluded, false, "we only observed one session");
  const [action] = a.data.actions;
  assert.equal(action.action, "c2pa.created");
  assert.equal(typeof action.softwareAgent, "object");
  assert.equal(action.softwareAgent.name, "claude-opus-4-8");
  assert.ok(action.digitalSourceType.startsWith("http://cv.iptc.org/newscodes/digitalsourcetype/"));
});

test("actions timestamp comes from block time, not the local clock", () => {
  const a = buildActionsAssertion(attestation(profile({ humanTurns: 2, assistantTurns: 2, assistantOutputChars: 10 })));
  assert.equal(a.data.actions[0].when, new Date(1767225600 * 1000).toISOString());
});

test("unanchored attestations fall back to the header end time", () => {
  const a = buildActionsAssertion(
    attestation(profile({ humanTurns: 2, assistantTurns: 2, assistantOutputChars: 10 }), { anchored: false })
  );
  assert.equal(a.data.actions[0].when, "2026-01-01T02:00:00.000Z");
  const p = buildProcessAssertion(
    attestation(profile({ humanTurns: 2, assistantTurns: 2, assistantOutputChars: 10 }), { anchored: false })
  );
  assert.equal(p.data.anchor, null);
});

/* ---- integration surfaces ---- */

test("manifest definition is c2patool-shaped and omits signing material", () => {
  const m = buildManifestDefinition(attestation(profile({ humanTurns: 3, assistantTurns: 4, assistantOutputChars: 900 })), {
    title: "Chapter 3 draft",
    format: "text/markdown",
  });
  assert.equal(m.title, "Chapter 3 draft");
  assert.equal(m.format, "text/markdown");
  assert.equal(m.claim_generator_info[0].name, "ProofOfProcess.ai");
  assert.deepEqual(m.assertions.map((a) => a.label), [ACTIONS_LABEL, ASSERTION_LABEL]);
  // Signing material belongs to whoever holds the certificate.
  for (const k of ["private_key", "sign_cert", "alg"]) assert.ok(!(k in m), `${k} must not be emitted`);
});

test("gathered bundle tells the embedder where the assertion belongs", () => {
  const g = buildGatheredAssertions(attestation(profile({ humanTurns: 3, assistantTurns: 4, assistantOutputChars: 900 })));
  assert.match(g.note, /gathered_assertions/);
  assert.equal(g.assertions.length, 2);
});

test("assertions are JSON-serializable with no undefined leaking in", () => {
  const m = buildManifestDefinition(attestation(profile({ humanTurns: 3, assistantTurns: 4, assistantOutputChars: 900 })));
  const round = JSON.parse(JSON.stringify(m));
  assert.deepEqual(round.assertions[1].data.attestation.publicKeyId, "keyid123");
});

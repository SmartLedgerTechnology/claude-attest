import test from "node:test";
import assert from "node:assert/strict";
import { canonicalJSON, hashLeaf, sha256Hex } from "../packages/proof-of-process/src/canonical.mjs";
import { merkleRoot, merkleProof, verifyMerkleProof } from "../packages/proof-of-process/src/merkle.mjs";
import { verifyAttestation, CHECKPOINT_FORMAT } from "../packages/proof-of-process/src/verify.mjs";
import {
  emptyProfile,
  newAccumulatorState,
  accumulate,
  finalizeProfile,
  derive,
  mergeProfiles,
} from "../packages/proof-of-process/src/profile.mjs";
import { scanSince, profileFromLines } from "../src/transcript.mjs";

test("canonicalJSON sorts keys and is stable regardless of insertion order", () => {
  assert.equal(canonicalJSON({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalJSON({ a: 2, b: 1 }), canonicalJSON({ b: 1, a: 2 }));
  assert.equal(canonicalJSON({ a: undefined, b: 1 }), '{"b":1}');
  assert.throws(() => canonicalJSON({ a: NaN }), /non-finite/);
});

test("merkle root is deterministic and proofs verify", () => {
  const leaves = Array.from({ length: 7 }, (_, i) => sha256Hex(`leaf-${i}`));
  const root = merkleRoot(leaves);
  assert.equal(root, merkleRoot(leaves));
  assert.equal(merkleRoot([]), "0".repeat(64));
  for (let i = 0; i < leaves.length; i++) {
    assert.ok(verifyMerkleProof(leaves[i], merkleProof(leaves, i), root), `proof ${i} failed`);
  }
});

test("merkle root changes when any leaf changes", () => {
  const a = [sha256Hex("x"), sha256Hex("y")];
  const b = [sha256Hex("x"), sha256Hex("z")];
  assert.notEqual(merkleRoot(a), merkleRoot(b));
});

/** Build a well-formed chain of leaves for verifier tests. */
function buildLeaves(kinds) {
  const leaves = [];
  let prev = "0".repeat(64);
  kinds.forEach((kind, seq) => {
    const leaf = { v: 1, seq, ts: new Date(1700000000000 + seq * 1000).toISOString(), kind, payloadHash: sha256Hex(kind + seq), prev };
    prev = hashLeaf(leaf);
    leaves.push(leaf);
  });
  return leaves;
}

function buildAttestation(leaves, overrides = {}) {
  const header = {
    v: 1,
    format: CHECKPOINT_FORMAT,
    sessionId: "s1",
    capture: { surface: "claude-code", adapter: "claude-attest" },
    leafCount: leaves.length,
    merkleRoot: merkleRoot(leaves.map(hashLeaf)),
    transcript: { headUuid: "u3", chainContiguous: true, gapCount: 0 },
    profile: finalizeProfile(emptyProfile()),
    algorithm: "ML-DSA-65",
    publicKeyId: "abc",
    ...overrides.header,
  };
  return { header, leaves, certificate: null, ...overrides.top };
}

test("verifier passes a well-formed attestation's structural checks", async () => {
  const leaves = buildLeaves(["session_open", "human_input", "checkpoint"]);
  const report = await verifyAttestation(buildAttestation(leaves));
  assert.equal(report.checks.format, true);
  assert.equal(report.checks.leafContinuity, true);
  assert.equal(report.checks.hashChain, true);
  assert.equal(report.checks.merkleRoot, true);
  assert.equal(report.checks.transcriptChain, true);
});

test("verifier catches a spliced-out leaf", async () => {
  const leaves = buildLeaves(["a", "b", "c", "d"]);
  const tampered = [leaves[0], leaves[2], leaves[3]].map((l, i) => ({ ...l, seq: i }));
  const report = await verifyAttestation(buildAttestation(tampered));
  assert.equal(report.checks.hashChain, false);
  assert.equal(report.ok, false);
});

test("verifier catches a mutated leaf payload", async () => {
  const leaves = buildLeaves(["a", "b", "c"]);
  const attestation = buildAttestation(leaves);
  attestation.leaves[1] = { ...attestation.leaves[1], payloadHash: sha256Hex("forged") };
  const report = await verifyAttestation(attestation);
  assert.equal(report.checks.merkleRoot, false);
  assert.equal(report.ok, false);
});

test("verifier explains a rewritten transcript", async () => {
  const leaves = buildLeaves(["a", "b"]);
  const report = await verifyAttestation(
    buildAttestation(leaves, {
      header: { transcript: { headUuid: "u9", chainContiguous: false, cursorIntact: false, parentsResolve: true, gapCount: 0 } },
    })
  );
  assert.equal(report.checks.transcriptChain, false);
  assert.match(report.reasons.join(" "), /rewritten/);
});

test("verifier explains deleted history", async () => {
  const leaves = buildLeaves(["a", "b"]);
  const report = await verifyAttestation(
    buildAttestation(leaves, {
      header: { transcript: { headUuid: "u9", chainContiguous: false, cursorIntact: true, parentsResolve: false, gapCount: 4 } },
    })
  );
  assert.equal(report.checks.transcriptChain, false);
  assert.match(report.reasons.join(" "), /parent is missing/);
});

test("scanSince returns only lines after the cursor", () => {
  const lines = [
    { uuid: "a", parentUuid: null, type: "user" },
    { uuid: "b", parentUuid: "a", type: "assistant" },
    { uuid: "c", parentUuid: "b", type: "user" },
    { uuid: "d", parentUuid: "c", type: "assistant" },
  ];
  const scan = scanSince(lines, { uuid: "b", lineCount: 2 });
  assert.deepEqual(scan.newLines.map((l) => l.uuid), ["c", "d"]);
  assert.equal(scan.headUuid, "d");
  assert.equal(scan.chainContiguous, true);
  assert.equal(scan.batchSize, 2);
});

/**
 * Regression: parallel tool calls produce sibling `user` lines sharing one
 * parentUuid. A single-parent walk from the tail misses every sibling, which
 * made healthy sessions report as tampered with.
 */
test("scanSince accepts sibling branches from parallel tool calls", () => {
  const lines = [
    { uuid: "a", parentUuid: null, type: "user" },
    { uuid: "asst", parentUuid: "a", type: "assistant" },
    { uuid: "r1", parentUuid: "asst", type: "user", toolUseResult: {} },
    { uuid: "r2", parentUuid: "asst", type: "user", toolUseResult: {} },
    { uuid: "r3", parentUuid: "asst", type: "user", toolUseResult: {} },
  ];
  const scan = scanSince(lines, { uuid: null, lineCount: 0 });
  assert.equal(scan.chainContiguous, true);
  assert.equal(scan.parentsResolve, true);
  assert.equal(scan.gapCount, 0);
  assert.equal(scan.newLines.length, 5);
});

test("scanSince detects a rewritten transcript", () => {
  const lines = [
    { uuid: "a", parentUuid: null },
    { uuid: "REPLACED", parentUuid: "a" },
    { uuid: "c", parentUuid: "REPLACED" },
  ];
  // We previously attested 2 lines, ending at uuid "b" — which is now gone.
  const scan = scanSince(lines, { uuid: "b", lineCount: 2 });
  assert.equal(scan.cursorIntact, false);
  assert.equal(scan.chainContiguous, false);
});

test("scanSince detects lines deleted out of the middle", () => {
  // "c" survives but its parent "b" was removed, leaving a dangling reference.
  const lines = [
    { uuid: "a", parentUuid: null },
    { uuid: "c", parentUuid: "b" },
  ];
  const scan = scanSince(lines, { uuid: null, lineCount: 0 });
  assert.equal(scan.parentsResolve, false);
  assert.equal(scan.gapCount, 1);
  assert.equal(scan.chainContiguous, false);
});

test("scanSince reports batch size so late attestation is visible", () => {
  const lines = Array.from({ length: 50 }, (_, i) => ({
    uuid: `u${i}`,
    parentUuid: i === 0 ? null : `u${i - 1}`,
  }));
  const scan = scanSince(lines, { uuid: "u4", lineCount: 5 });
  assert.equal(scan.batchSize, 45);
  assert.equal(scan.cursorIntact, true);
  assert.equal(scan.chainContiguous, true);
});

test("profile distinguishes human input from tool results on user lines", () => {
  const lines = [
    { uuid: "1", type: "user", timestamp: "2026-01-01T00:00:00Z", origin: { kind: "human" }, promptSource: "typed", message: { role: "user", content: "build the thing" } },
    { uuid: "2", type: "assistant", timestamp: "2026-01-01T00:00:10Z", message: { content: [{ type: "text", text: "ok" }, { type: "tool_use" }] } },
    // A tool result — must NOT count as a human turn.
    { uuid: "3", type: "user", timestamp: "2026-01-01T00:00:20Z", toolUseResult: { ok: true }, message: { role: "user", content: [{ type: "tool_result" }] } },
    { uuid: "4", type: "user", timestamp: "2026-01-01T00:00:30Z", origin: { kind: "human" }, promptSource: "typed", message: { role: "user", content: "no, revise it" } },
  ];
  const p = profileFromLines(lines);
  assert.equal(p.humanTurns, 2);
  assert.equal(p.assistantTurns, 1);
  assert.equal(p.toolCalls, 1);
  assert.equal(p.revisionCycles, 1, "second human turn follows an assistant turn");
  assert.equal(p.promptSources.typed, 2);
});

test("profile flags unattended sessions", () => {
  const lines = [
    { uuid: "1", type: "user", timestamp: "2026-01-01T00:00:00Z", origin: { kind: "loop" }, message: { role: "user", content: "go" } },
    { uuid: "2", type: "assistant", timestamp: "2026-01-01T00:00:05Z", message: { content: [{ type: "text", text: "done" }] } },
  ];
  const p = profileFromLines(lines);
  assert.equal(p.humanTurns, 0);
  assert.equal(p.unattendedTurns, 1);
  assert.equal(derive(p).fullyUnattended, true);
});

test("active time excludes long idle gaps", () => {
  const p = emptyProfile();
  const s = newAccumulatorState();
  accumulate(p, { kind: "human_input", ts: "2026-01-01T00:00:00Z", chars: 5 }, s);
  accumulate(p, { kind: "assistant_output", ts: "2026-01-01T00:01:00Z", chars: 5 }, s);
  // 4-hour lunch break: counted in span, not in active time.
  accumulate(p, { kind: "human_input", ts: "2026-01-01T04:01:00Z", chars: 5 }, s);
  finalizeProfile(p);
  assert.equal(p.activeSpanSeconds, 60);
  assert.equal(p.spanSeconds, 14460);
});

test("profiles merge across sessions", () => {
  const a = finalizeProfile({ ...emptyProfile(), humanTurns: 3, revisionCycles: 2, firstEventAt: "2026-01-01T00:00:00Z", lastEventAt: "2026-01-01T01:00:00Z", promptSources: { typed: 3 } });
  const b = finalizeProfile({ ...emptyProfile(), humanTurns: 5, revisionCycles: 4, firstEventAt: "2026-01-02T00:00:00Z", lastEventAt: "2026-01-02T02:00:00Z", promptSources: { typed: 5 } });
  const m = mergeProfiles([a, b]);
  assert.equal(m.humanTurns, 8);
  assert.equal(m.revisionCycles, 6);
  assert.equal(m.promptSources.typed, 8);
  assert.equal(m.firstEventAt, "2026-01-01T00:00:00Z");
  assert.equal(m.lastEventAt, "2026-01-02T02:00:00Z");
});

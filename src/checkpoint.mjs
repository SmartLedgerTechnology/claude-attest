import fs from "node:fs";
import path from "node:path";
import { canonicalJSON, sha256Hex, hashLeaf } from "../packages/proof-of-process/src/canonical.mjs";
import { merkleRoot } from "../packages/proof-of-process/src/merkle.mjs";
import { CHECKPOINT_FORMAT } from "../packages/proof-of-process/src/verify.mjs";
import { emptyProfile, finalizeProfile } from "../packages/proof-of-process/src/profile.mjs";
import { readLeaves, readHead } from "./leaflog.mjs";
import { readTranscript, scanSince, profileFromLines, sessionFacts } from "./transcript.mjs";
import { loadIdentity } from "./identity.mjs";
import { anchor, requestCountersignature } from "./anchor.mjs";
import { sessionDir, loadConfig, debugLog } from "./paths.mjs";

export const ADAPTER = "claude-attest";
export const ADAPTER_VERSION = "0.1.0";

/**
 * Build the signed header for a session.
 *
 * The header is the ONLY thing that gets signed and anchored: it commits to the
 * leaves through `merkleRoot`, to the transcript through `transcript.headUuid`,
 * and to the collaboration shape through `profile`. Anchoring one 32-byte
 * digest per session is what keeps this affordable at any volume.
 */
export function buildHeader({ sessionId, leaves, transcript, profile, facts, identity }) {
  return {
    v: 1,
    format: CHECKPOINT_FORMAT,
    sessionId,
    capture: {
      surface: "claude-code",
      surfaceVersion: facts.surfaceVersion ?? null,
      entrypoint: facts.entrypoint ?? null,
      adapter: ADAPTER,
      adapterVersion: ADAPTER_VERSION,
      models: facts.models ?? [],
    },
    cwd: facts.cwd ?? null,
    gitBranch: facts.gitBranch ?? null,
    startedAt: leaves[0]?.ts ?? null,
    endedAt: leaves[leaves.length - 1]?.ts ?? new Date().toISOString(),
    leafCount: leaves.length,
    merkleRoot: merkleRoot(leaves.map(hashLeaf)),
    transcript,
    profile,
    algorithm: identity.algorithm,
    publicKeyId: identity.publicKeyId,
  };
}

/**
 * Finalize a session: assemble the header, anchor its digest, write the
 * attestation next to the leaf log.
 *
 * Idempotent by design — a session whose attestation already carries a
 * confirmed anchor is left alone, so `--sweep` can run as often as it likes.
 */
export async function finalizeSession(sessionId, opts = {}) {
  const dir = sessionDir(sessionId);
  const outPath = path.join(dir, "attestation.json");
  const config = { ...loadConfig(), ...opts };

  if (fs.existsSync(outPath) && !opts.force) {
    const existing = JSON.parse(fs.readFileSync(outPath, "utf8"));
    if (existing?.certificate?.anchor?.txid) return { skipped: true, path: outPath, attestation: existing };
  }

  const identity = loadIdentity();
  if (!identity) return { error: "no identity — run `claude-attest init`" };

  const leaves = readLeaves(dir);
  if (leaves.length === 0) return { error: "no leaves recorded for this session" };

  const head = readHead(dir);
  const meta = readMeta(dir);

  // Re-derive the profile and transcript state from the transcript itself
  // rather than trusting anything accumulated in the hot path.
  let transcript = { headUuid: head.lastAttestedUuid, chainContiguous: true, gapCount: 0, totalLines: head.attestedLineCount };
  let profile = emptyProfile();
  let facts = { cwd: meta.cwd ?? null, gitBranch: null, surfaceVersion: null, entrypoint: null, models: [] };

  const lines = readTranscript(meta.transcriptPath);
  if (lines.length) {
    // Re-scan against the cursor the checkpoints actually recorded, so
    // finalization confirms the same invariants the hooks claimed.
    const scan = scanSince(lines, {
      uuid: head.lastAttestedUuid,
      lineCount: head.attestedLineCount,
    });
    transcript = {
      headUuid: scan.headUuid,
      lineCount: scan.totalLines,
      cursorIntact: scan.cursorIntact,
      parentsResolve: scan.parentsResolve,
      chainContiguous: scan.chainContiguous,
      gapCount: scan.gapCount,
      unattestedAtFinalize: scan.batchSize,
      checkpointCursor: head.lastAttestedUuid,
    };
    profile = profileFromLines(lines);
    facts = sessionFacts(lines);
  } else {
    profile = finalizeProfile(profile);
    debugLog(`finalize: transcript unavailable at ${meta.transcriptPath}`);
    transcript.transcriptUnavailable = true;
  }

  const header = buildHeader({ sessionId, leaves, transcript, profile, facts, identity });
  const digest = sha256Hex(canonicalJSON(header));

  // Countersign in parallel with anchoring: both attest the same digest and
  // neither depends on the other's result.
  const [result, counter] = await Promise.all([
    anchor(digest, identity, config),
    requestCountersignature(digest, config),
  ]);

  const attestation = {
    header,
    leaves,
    certificate: result.certificate ?? null,
    countersignatures: counter.ok ? [counter.countersignature] : [],
    anchorStatus: result.ok ? "anchored" : "failed",
    anchorError: result.ok ? undefined : result.error,
    anchorBackend: result.backend,
    notaryHashId: result.id,
  };
  if (!counter.ok && !counter.skipped) {
    debugLog(`countersign unavailable: ${counter.error}`);
  }
  fs.writeFileSync(outPath, JSON.stringify(attestation, null, 2));
  return { path: outPath, attestation, digest, ok: result.ok };
}

export function writeMeta(dir, meta) {
  try {
    const p = path.join(dir, "meta.json");
    const existing = fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, "utf8")) : {};
    fs.writeFileSync(p, JSON.stringify({ ...existing, ...meta }, null, 2));
  } catch (e) {
    debugLog(`writeMeta failed: ${e.message}`);
  }
}

export function readMeta(dir) {
  try {
    const p = path.join(dir, "meta.json");
    if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch (e) {
    debugLog(`readMeta failed: ${e.message}`);
  }
  return {};
}

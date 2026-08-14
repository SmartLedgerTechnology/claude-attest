#!/usr/bin/env node
/**
 * Hot path. Runs on EVERY hook event, in a fresh process, while a human waits.
 *
 * Hard rules for this file:
 *   1. Node builtins and our zero-dep modules only. No crypto libraries, no
 *      network. Importing @noble here would add ~100ms to every tool call.
 *   2. Never throw, never write to stdout, never write to stderr. Claude Code
 *      surfaces both to the user or the model. Diagnostics go to debug.log.
 *   3. Always exit 0. An attestation plugin that can break someone's session
 *      is worse than no attestation plugin.
 */

import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { appendLeaf, appendLeaves, readHead, updateTranscriptCursor } from "../src/leaflog.mjs";
import { readTranscript, scanSince } from "../src/transcript.mjs";
import { writeMeta } from "../src/checkpoint.mjs";
import { sessionDir, debugLog } from "../src/paths.mjs";
import { hashPayload } from "../packages/proof-of-process/src/canonical.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

main();

async function main() {
  try {
    const input = await readStdin();
    if (!input) return exit();
    const evt = JSON.parse(input);
    const sessionId = evt.session_id;
    if (!sessionId) return exit();

    const dir = sessionDir(sessionId);
    handle(evt, dir, sessionId);
  } catch (e) {
    debugLog(`hook error: ${e.stack ?? e}`);
  }
  exit();
}

function handle(evt, dir, sessionId) {
  switch (evt.hook_event_name) {
    case "SessionStart":
      writeMeta(dir, {
        sessionId,
        cwd: evt.cwd,
        transcriptPath: evt.transcript_path,
        startedAt: new Date().toISOString(),
      });
      appendLeaf(dir, "session_open", {
        cwd: evt.cwd,
        source: evt.source ?? evt.matcher ?? null,
        permissionMode: evt.permission_mode ?? null,
      });
      // Self-healing: a session killed with SIGKILL never fires SessionEnd, so
      // sweep for unfinalized sessions whenever a new one starts.
      detach(["--sweep"]);
      break;

    case "UserPromptSubmit":
      appendLeaf(dir, "human_input", {
        promptId: evt.prompt_id,
        // Content is hashed, never stored. The leaf proves what was said
        // without disclosing it.
        contentHash: hashPayload(evt.user_prompt ?? ""),
        chars: (evt.user_prompt ?? "").length,
      });
      break;

    case "PreToolUse":
      appendLeaf(dir, "tool_intent", {
        tool: evt.tool_name,
        toolUseId: evt.tool_use_id,
        inputHash: hashPayload(evt.tool_input ?? {}),
        permissionMode: evt.permission_mode ?? null,
      });
      break;

    case "PostToolUse":
      appendLeaf(dir, "tool_effect", {
        tool: evt.tool_name,
        toolUseId: evt.tool_use_id,
        // Untruncated, unlike anything persisted in the transcript — this is
        // the gap that made openai-claw unable to align tool results.
        responseHash: hashPayload(evt.tool_response ?? null),
        ok: true,
      });
      break;

    case "PostToolUseFailure":
      appendLeaf(dir, "tool_effect", {
        tool: evt.tool_name,
        toolUseId: evt.tool_use_id,
        responseHash: hashPayload(evt.tool_response ?? null),
        ok: false,
      });
      break;

    // The human authorization record. Permission decisions do not appear in
    // the transcript in any reconstructable form, so these leaves are the only
    // evidence that a person was asked and answered.
    case "PermissionRequest":
      appendLeaf(dir, "consent_request", {
        tool: evt.tool_name,
        toolUseId: evt.tool_use_id,
        inputHash: hashPayload(evt.tool_input ?? {}),
      });
      break;

    case "PermissionDenied":
      appendLeaf(dir, "consent_denied", {
        tool: evt.tool_name,
        toolUseId: evt.tool_use_id,
        reason: evt.reason ?? null,
      });
      break;

    case "SubagentStart":
      appendLeaf(dir, "delegation_start", { agent: evt.matcher ?? evt.agent_type ?? null });
      break;

    case "SubagentStop":
      appendLeaf(dir, "delegation_stop", {
        agent: evt.matcher ?? evt.agent_type ?? null,
        resultHash: hashPayload(evt.last_assistant_message ?? null),
      });
      break;

    case "PreCompact":
    case "PostCompact":
      // Compaction rewrites context. Recording it means a verifier can tell
      // "content disappeared because it was compacted" from "content
      // disappeared because someone removed it".
      appendLeaf(dir, "compaction", { phase: evt.hook_event_name, trigger: evt.matcher ?? null });
      break;

    case "Stop":
      checkpoint(evt, dir);
      break;

    case "SessionEnd":
      appendLeaf(dir, "session_close", { reason: evt.matcher ?? evt.reason ?? null });
      // Detached so finalization survives the session process exiting.
      detach(["--finalize", evt.session_id]);
      break;

    default:
      break;
  }
}

/**
 * Turn boundary. Walk the transcript forward from the last attested uuid,
 * commit one leaf per new transcript line, and record the new cursor.
 *
 * This is what makes omission detectable: the cursor is a claim about where
 * the causal chain was, and the next checkpoint has to be able to walk back
 * to it via parentUuid.
 */
function checkpoint(evt, dir) {
  const head = readHead(dir);
  const lines = readTranscript(evt.transcript_path);
  if (!lines.length) return;

  const scan = scanSince(lines, { uuid: head.lastAttestedUuid, lineCount: head.attestedLineCount });
  if (scan.batchSize === 0 && scan.chainContiguous) return;

  const entries = scan.newLines.map((line) => ({
    kind: "transcript_line",
    payload: line,
    extra: { uuid: line.uuid, parentUuid: line.parentUuid ?? null },
  }));
  entries.push({
    kind: "checkpoint",
    payload: {
      headUuid: scan.headUuid,
      fromUuid: head.lastAttestedUuid,
      cursorIntact: scan.cursorIntact,
      parentsResolve: scan.parentsResolve,
      chainContiguous: scan.chainContiguous,
      gapCount: scan.gapCount,
      batchSize: scan.batchSize,
      lineCount: scan.totalLines,
      stopReason: evt.stop_reason ?? null,
    },
  });

  appendLeaves(dir, entries);
  updateTranscriptCursor(dir, scan.headUuid, scan.totalLines);
  writeMeta(dir, { transcriptPath: evt.transcript_path, cwd: evt.cwd });
}

function detach(args) {
  try {
    spawn(process.execPath, [path.join(HERE, "attestd.mjs"), ...args], {
      detached: true,
      stdio: "ignore",
    }).unref();
  } catch (e) {
    debugLog(`detach failed: ${e.message}`);
  }
}

function readStdin() {
  return new Promise((resolve) => {
    let data = "";
    // If stdin never closes, do not hang the session.
    const timer = setTimeout(() => resolve(data), 2000);
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => (data += c));
    process.stdin.on("end", () => {
      clearTimeout(timer);
      resolve(data);
    });
    process.stdin.on("error", () => {
      clearTimeout(timer);
      resolve(data);
    });
  });
}

function exit() {
  process.exit(0);
}

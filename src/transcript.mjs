import fs from "node:fs";
import {
  emptyProfile,
  newAccumulatorState,
  accumulate,
  finalizeProfile,
} from "../packages/proof-of-process/src/profile.mjs";
import { debugLog } from "./paths.mjs";

/**
 * Claude Code's transcript is the source of truth, not our hook stream.
 *
 * Hooks are advisory: a user can disable the plugin between turns, do some
 * work, and re-enable it, and a log built only from hook events would show no
 * sign of the gap. The transcript is written by Claude Code regardless, and
 * every line carries `uuid` + `parentUuid` — an existing causal chain.
 *
 * So each checkpoint records the transcript uuid it walked up to. The next
 * checkpoint walks back from the new head and must reach that uuid by following
 * parentUuid links. If it can't, turns happened that were never attested, and
 * `chainContiguous` goes false. That is the whole anti-omission mechanism.
 */

export function readTranscript(transcriptPath) {
  if (!transcriptPath || !fs.existsSync(transcriptPath)) return [];
  try {
    return fs
      .readFileSync(transcriptPath, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((l) => {
        try {
          return JSON.parse(l);
        } catch {
          return null;
        }
      })
      .filter((o) => o && typeof o.uuid === "string");
  } catch (e) {
    debugLog(`readTranscript failed: ${e.message}`);
    return [];
  }
}

/**
 * Scan the transcript for everything not yet attested, and check the structure
 * for signs of rewriting.
 *
 * A transcript is a TREE, not a linear chain: one assistant message issuing
 * several tool calls in parallel produces several `user` result lines that all
 * share its uuid as `parentUuid`. Walking a single parent path from the tail
 * therefore misses every sibling branch — an earlier version of this function
 * did exactly that and reported healthy sessions as tampered with.
 *
 * The file is append-only, so position is the honest cursor:
 *
 *   cursorIntact   the line at the previously-recorded position still carries
 *                  the uuid we recorded there. Fails if history was rewritten,
 *                  truncated, or replayed.
 *   parentsResolve every line's parentUuid names a line present in the file.
 *                  Fails if lines were deleted out of the middle.
 *   batchSize      how many lines this checkpoint is attesting at once. Large
 *                  batches are legitimate after an offline period, but they
 *                  mean this content is being attested late, and a verifier
 *                  should be able to see that rather than infer it.
 */
export function scanSince(lines, cursor = { uuid: null, lineCount: 0 }) {
  if (lines.length === 0) {
    return {
      newLines: [],
      headUuid: null,
      chainContiguous: true,
      cursorIntact: true,
      parentsResolve: true,
      gapCount: 0,
      batchSize: 0,
      totalLines: 0,
    };
  }

  const byUuid = new Map(lines.map((l) => [l.uuid, l]));
  const headUuid = lines[lines.length - 1].uuid;
  const attested = Math.min(cursor.lineCount ?? 0, lines.length);

  // Did the file we previously attested survive unchanged up to our cursor?
  const cursorIntact =
    attested === 0 || (cursor.uuid ? lines[attested - 1]?.uuid === cursor.uuid : true);

  // Lines whose parent is absent from the file: something was removed.
  const dangling = lines.filter((l) => l.parentUuid != null && !byUuid.has(l.parentUuid));

  const newLines = lines.slice(attested);

  return {
    newLines,
    headUuid,
    cursorIntact,
    parentsResolve: dangling.length === 0,
    chainContiguous: cursorIntact && dangling.length === 0,
    gapCount: dangling.length,
    batchSize: newLines.length,
    totalLines: lines.length,
  };
}

/**
 * Map transcript lines onto the surface-agnostic profile events.
 *
 * The subtle case is `type: "user"`: Claude Code uses it both for genuine human
 * input AND for tool results being fed back to the model. Only the former is a
 * human turn, and mistaking one for the other would inflate exactly the number
 * this product asks people to trust.
 */
export function profileFromLines(lines, base) {
  const profile = base ?? emptyProfile();
  const state = newAccumulatorState();

  for (const line of lines) {
    const ts = line.timestamp ?? new Date().toISOString();

    if (line.isSidechain) {
      accumulate(profile, { kind: "delegated", ts }, state);
      continue;
    }

    if (line.type === "user") {
      if (!isHumanInput(line)) continue;
      const content = line.message?.content;
      accumulate(
        profile,
        {
          kind: "human_input",
          ts,
          chars: typeof content === "string" ? content.length : 0,
          promptSource: line.promptSource,
          humanOriginated: line.origin?.kind === "human",
        },
        state
      );
      continue;
    }

    if (line.type === "assistant") {
      const blocks = Array.isArray(line.message?.content) ? line.message.content : [];
      let textChars = 0;
      let toolUses = 0;
      for (const b of blocks) {
        if (b.type === "text") textChars += (b.text ?? "").length;
        else if (b.type === "tool_use") toolUses++;
      }
      if (textChars > 0) accumulate(profile, { kind: "assistant_output", ts, chars: textChars }, state);
      for (let i = 0; i < toolUses; i++) accumulate(profile, { kind: "tool_call", ts }, state);
    }
  }

  return finalizeProfile(profile);
}

/**
 * A `user` line is real human input only when it carries prompt provenance.
 * Tool results come back as `user` lines too, but they have `toolUseResult`
 * and no `origin` / `promptSource`.
 */
function isHumanInput(line) {
  if (line.toolUseResult !== undefined) return false;
  if (line.sourceToolAssistantUUID) return false;
  return line.origin !== undefined || line.promptSource !== undefined;
}

/** Session-level facts worth binding into the signed header. */
export function sessionFacts(lines) {
  const last = lines[lines.length - 1] ?? {};
  const first = lines[0] ?? {};
  return {
    cwd: last.cwd ?? first.cwd ?? null,
    gitBranch: last.gitBranch ?? first.gitBranch ?? null,
    surfaceVersion: last.version ?? first.version ?? null,
    entrypoint: first.entrypoint ?? null,
    models: [
      ...new Set(lines.filter((l) => l.type === "assistant").map((l) => l.message?.model).filter(Boolean)),
    ],
  };
}

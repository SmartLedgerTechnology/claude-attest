/**
 * The collaboration profile.
 *
 * This is the part of a checkpoint that carries evidentiary weight, and it is
 * deliberately NOT a "was this human-led?" boolean. A person who types
 * "write me a novel" is 100% human-originated and contributed almost nothing;
 * a person who typed 400 prompts across three months, revised most outputs,
 * and edited the result by hand contributed a great deal. Both are "human-led".
 * Only the SHAPE of the collaboration separates them, so the shape is what we
 * measure and sign.
 *
 * Every field here is surface-agnostic — turns, characters, revisions, elapsed
 * time. Nothing in this module knows what Claude Code is. Adapters map their
 * native event stream onto `accumulate()`; the profile format stays stable
 * across capture surfaces so one verifier serves all of them.
 */

export const PROFILE_VERSION = 1;

/** Gaps longer than this are treated as the operator walking away, not working. */
const IDLE_THRESHOLD_SECONDS = 300;

export function emptyProfile() {
  return {
    v: PROFILE_VERSION,
    humanTurns: 0,
    assistantTurns: 0,
    toolCalls: 0,
    delegatedTurns: 0,
    unattendedTurns: 0,
    promptSources: {},
    humanInputChars: 0,
    assistantOutputChars: 0,
    revisionCycles: 0,
    maxConsecutiveUnattended: 0,
    firstEventAt: null,
    lastEventAt: null,
    spanSeconds: 0,
    activeSpanSeconds: 0,
  };
}

/**
 * Fold one normalized event into a profile. Adapters are responsible for
 * producing these events; see `src/transcript.mjs` for the Claude Code mapping.
 *
 * event = {
 *   kind: "human_input" | "assistant_output" | "tool_call" | "delegated",
 *   ts: ISO-8601 string,
 *   chars?: number,
 *   promptSource?: string,   // human_input only: how the input was produced
 *   humanOriginated?: bool,  // human_input only: false for loop/cron/SDK drivers
 * }
 */
export function accumulate(profile, event, state) {
  const ts = Date.parse(event.ts);
  if (Number.isFinite(ts)) {
    if (profile.firstEventAt === null || ts < Date.parse(profile.firstEventAt)) {
      profile.firstEventAt = event.ts;
    }
    if (profile.lastEventAt === null || ts > Date.parse(profile.lastEventAt)) {
      profile.lastEventAt = event.ts;
    }
    if (state.lastTs !== null) {
      const gap = (ts - state.lastTs) / 1000;
      if (gap > 0 && gap <= IDLE_THRESHOLD_SECONDS) profile.activeSpanSeconds += gap;
    }
    state.lastTs = ts;
  }

  switch (event.kind) {
    case "human_input": {
      const humanOriginated = event.humanOriginated !== false;
      if (humanOriginated) {
        profile.humanTurns++;
        profile.humanInputChars += event.chars ?? 0;
        state.consecutiveUnattended = 0;
        // A human input that follows at least one assistant output is a
        // revision, not an opening instruction. This ratio is what separates
        // iterative authorship from one-shot generation.
        if (state.sawAssistantSinceHuman) profile.revisionCycles++;
      } else {
        profile.unattendedTurns++;
        state.consecutiveUnattended++;
        profile.maxConsecutiveUnattended = Math.max(
          profile.maxConsecutiveUnattended,
          state.consecutiveUnattended
        );
      }
      if (event.promptSource) {
        profile.promptSources[event.promptSource] =
          (profile.promptSources[event.promptSource] ?? 0) + 1;
      }
      state.sawAssistantSinceHuman = false;
      break;
    }
    case "assistant_output":
      profile.assistantTurns++;
      profile.assistantOutputChars += event.chars ?? 0;
      state.sawAssistantSinceHuman = true;
      break;
    case "tool_call":
      profile.toolCalls++;
      break;
    case "delegated":
      profile.delegatedTurns++;
      break;
  }
  return profile;
}

export function newAccumulatorState() {
  return { lastTs: null, sawAssistantSinceHuman: false, consecutiveUnattended: 0 };
}

/** Close out derived fields. Call once, after the last accumulate(). */
export function finalizeProfile(profile) {
  if (profile.firstEventAt && profile.lastEventAt) {
    profile.spanSeconds = Math.max(
      0,
      Math.round((Date.parse(profile.lastEventAt) - Date.parse(profile.firstEventAt)) / 1000)
    );
  }
  profile.activeSpanSeconds = Math.round(profile.activeSpanSeconds);
  return profile;
}

/**
 * Merge profiles from multiple checkpoints (or multiple sessions) into one.
 * Used to profile a whole work rather than a single sitting — the unit a
 * creative actually cares about is "this manuscript", not "this session".
 */
export function mergeProfiles(profiles) {
  const out = emptyProfile();
  for (const p of profiles) {
    out.humanTurns += p.humanTurns;
    out.assistantTurns += p.assistantTurns;
    out.toolCalls += p.toolCalls;
    out.delegatedTurns += p.delegatedTurns;
    out.unattendedTurns += p.unattendedTurns;
    out.humanInputChars += p.humanInputChars;
    out.assistantOutputChars += p.assistantOutputChars;
    out.revisionCycles += p.revisionCycles;
    out.activeSpanSeconds += p.activeSpanSeconds;
    out.maxConsecutiveUnattended = Math.max(out.maxConsecutiveUnattended, p.maxConsecutiveUnattended);
    for (const [k, n] of Object.entries(p.promptSources ?? {})) {
      out.promptSources[k] = (out.promptSources[k] ?? 0) + n;
    }
    if (p.firstEventAt && (out.firstEventAt === null || Date.parse(p.firstEventAt) < Date.parse(out.firstEventAt))) {
      out.firstEventAt = p.firstEventAt;
    }
    if (p.lastEventAt && (out.lastEventAt === null || Date.parse(p.lastEventAt) > Date.parse(out.lastEventAt))) {
      out.lastEventAt = p.lastEventAt;
    }
  }
  return finalizeProfile(out);
}

/**
 * Human-readable derived ratios. Kept OUT of the signed profile on purpose:
 * they are opinions about the data, and opinions should be recomputable and
 * arguable rather than notarized. Verifiers derive them; signers don't.
 */
export function derive(profile) {
  const totalTurns = profile.humanTurns + profile.assistantTurns;
  const totalInputs = profile.humanTurns + profile.unattendedTurns;
  return {
    humanTurnRatio: totalTurns ? profile.humanTurns / totalTurns : 0,
    humanOriginationRatio: totalInputs ? profile.humanTurns / totalInputs : 0,
    revisionRatio: profile.humanTurns ? profile.revisionCycles / profile.humanTurns : 0,
    charRatio: profile.assistantOutputChars
      ? profile.humanInputChars / profile.assistantOutputChars
      : 0,
    activeMinutes: Math.round(profile.activeSpanSeconds / 60),
    fullyUnattended: profile.humanTurns === 0,
  };
}

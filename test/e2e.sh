#!/usr/bin/env bash
# End-to-end smoke test: drive the hook binary with real hook payloads against a
# real Claude Code transcript, then finalize and verify.
#
#   ./test/e2e.sh [path-to-transcript.jsonl]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TRANSCRIPT="${1:-}"
if [ -z "$TRANSCRIPT" ]; then
  # `find | head` would SIGPIPE find, which `pipefail` turns into a failure.
  TRANSCRIPT=$(find "$HOME/.claude/projects" -name '*.jsonl' -size +5k -print -quit 2>/dev/null)
fi
[ -f "$TRANSCRIPT" ] || { echo "no transcript found; pass one as \$1"; exit 1; }

export CLAUDE_ATTEST_HOME="${CLAUDE_ATTEST_HOME:-$(mktemp -d)/attest}"
export CLAUDE_ATTEST_DEBUG=1
SESSION="e2e-$$"
HOOK="node $ROOT/bin/attest-hook.mjs"

echo "transcript: $TRANSCRIPT"
echo "home:       $CLAUDE_ATTEST_HOME"
echo

[ -f "$CLAUDE_ATTEST_HOME/keys/attestor.json" ] || node "$ROOT/bin/attestd.mjs" init >/dev/null

fire() { echo "$1" | $HOOK; }

fire "$(jq -nc --arg s "$SESSION" --arg t "$TRANSCRIPT" --arg c "$PWD" \
  '{session_id:$s, transcript_path:$t, cwd:$c, hook_event_name:"SessionStart", source:"startup"}')"

fire "$(jq -nc --arg s "$SESSION" --arg c "$PWD" \
  '{session_id:$s, cwd:$c, hook_event_name:"UserPromptSubmit", prompt_id:"p1", user_prompt:"review the attestation design"}')"

fire "$(jq -nc --arg s "$SESSION" \
  '{session_id:$s, hook_event_name:"PreToolUse", tool_name:"Bash", tool_use_id:"t1", tool_input:{command:"ls -la"}, permission_mode:"default"}')"

fire "$(jq -nc --arg s "$SESSION" \
  '{session_id:$s, hook_event_name:"PermissionRequest", tool_name:"Bash", tool_use_id:"t1", tool_input:{command:"ls -la"}}')"

fire "$(jq -nc --arg s "$SESSION" \
  '{session_id:$s, hook_event_name:"PostToolUse", tool_name:"Bash", tool_use_id:"t1", tool_response:"total 48\ndrwxr-xr-x ..."}')"

fire "$(jq -nc --arg s "$SESSION" --arg t "$TRANSCRIPT" --arg c "$PWD" \
  '{session_id:$s, transcript_path:$t, cwd:$c, hook_event_name:"Stop", stop_reason:"end_turn", last_assistant_message:"done"}')"

fire "$(jq -nc --arg s "$SESSION" \
  '{session_id:$s, hook_event_name:"SessionEnd", matcher:"other"}')"

echo "leaves recorded: $(wc -l < "$CLAUDE_ATTEST_HOME/sessions/$SESSION/leaves.ndjson")"
echo
node "$ROOT/bin/attestd.mjs" finalize "$SESSION"
echo
node "$ROOT/bin/attestd.mjs" verify "$SESSION"

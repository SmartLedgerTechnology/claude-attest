---
description: Verify an attestation and show its collaboration profile
argument-hint: "[session-id or path to attestation.json]"
---

Verify the attestation for `$ARGUMENTS`. If no argument was given, run
`list` first and verify the most recently anchored session.

```
!node "${CLAUDE_PLUGIN_ROOT}/bin/attestd.mjs" verify $ARGUMENTS
```

Present the result to the user in two parts:

1. **Integrity** — did the hash chain, Merkle root, anchor binding, signature,
   and transcript chain all pass? If `transcriptChain` failed, explain plainly
   that turns took place which were never attested: either the plugin was
   disabled mid-session or the transcript was modified.

2. **Collaboration profile** — describe the shape of the work in plain language
   rather than reciting numbers. What matters is the ratio of human turns to
   model output, how many revision cycles there were, and how much of the
   session was unattended.

Be careful not to overstate what this proves. It is evidence about the
*process* — what happened, in what order, when. It is not proof of authorship
or of who was sitting at the keyboard.

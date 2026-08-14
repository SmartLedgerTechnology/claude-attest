---
description: Create the signing identity used to attest this machine's sessions
---

Create the attestation signing identity:

```
!node "${CLAUDE_PLUGIN_ROOT}/bin/attestd.mjs" init
```

After it runs, tell the user:

- Their key lives at `~/.claude-attest/keys/attestor.json` with mode 0600 and
  **should be backed up** — losing it means they can no longer sign under the
  same identity, though attestations already made stay valid.
- The key is protected by filesystem permissions only. Any process running as
  them — including this agent, via Bash — can read it. Offer to add a deny rule
  for `Read(~/.claude-attest/keys/**)` and `Bash(cat ~/.claude-attest/**)` to
  their settings if they want that closed off.
- Attestation is now recording, but anchoring is in `mock` mode until they set
  `NOTARYHASH_API_KEY`. Everything is signed and tamper-evident locally either
  way; the API key is what buys a public, third-party-checkable timestamp.

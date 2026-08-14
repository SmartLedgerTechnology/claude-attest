---
description: Show the attestation identity, anchor backend, and this session's capture state
---

Run the attestation status command and report the result to the user:

```
!node "${CLAUDE_PLUGIN_ROOT}/bin/attestd.mjs" status
```

Then list the captured sessions:

```
!node "${CLAUDE_PLUGIN_ROOT}/bin/attestd.mjs" list
```

Summarize for the user: whether an identity exists, which anchor backend is
configured, and how many sessions are captured but not yet anchored. If no
identity exists, tell them to run `/attest-init`. If the anchor backend is
`mock`, explain that attestations are signed and tamper-evident locally but
carry no public timestamp until a NotaryHash API key is configured.

# claude-attest — [ProofOfProcess.ai](https://proofofprocess.ai)

Blockchain-timestamped **proof of process** for human–AI collaboration.

A Claude Code plugin that records how work was actually produced — how many
times a person intervened, what they revised, what they authorized, how long
they spent — as a tamper-evident hash chain, signed with post-quantum
ML-DSA-65 and anchored to Bitcoin SV through [NotaryHash](https://notaryhash.com).

> **Where this sits.** ProofOfProcess.ai is the product and the verification
> surface. NotaryHash is the neutral BRC-141 anchoring layer beneath it, usable
> independently. `proof-of-process` is the open format and verifier;
> `claude-attest` is one capture adapter of several to come.

```
$ claude-attest verify 5bf636ee
VERIFIED

  pass  format          pass  anchorBinding
  pass  leafContinuity  pass  signature
  pass  hashChain       pass  transcriptChain
  pass  merkleRoot

collaboration profile
  human turns         16
  assistant turns     92
  tool calls          163
  revision cycles     14 (88% of human turns)
  unattended inputs   0
  human input         10190 chars
  model output        43125 chars
  active time         84 min of 5369 min elapsed
  prompt sources      {"typed":10,"suggestion_accepted":6}
```

## What this proves — and what it doesn't

**It proves:** a transcript with this exact content existed at a given block
time, has not changed since, and its structure shows no signs of rewriting or
deletion. The collaboration profile is bound into the signature, so the numbers
cannot be adjusted after the fact without breaking verification.

**It does not prove authorship.** Two limits, both deliberate and both stated
here rather than buried:

1. **The operator holds the key.** Self-attestation means a determined person
   could fabricate a transcript offline and sign it. The evidence is unforgeable
   *after* signing, not before. Closing this requires a second signer who is not
   the author — a publisher, university, employer, or escrow — co-signing
   checkpoints.
2. **"Human-led" is not a boolean.** Someone who types *"write me a novel"* is
   100% human-originated and contributed almost nothing. That is why this plugin
   emits a *profile* rather than a badge: the number of distinct human turns,
   the revision ratio, and the elapsed working time are what distinguish
   iterative authorship from one-shot generation. Interpretation is left to
   whoever is weighing the evidence.

Claiming more than this would not survive contact with anyone motivated to
argue the other side.

## Install

```bash
/plugin marketplace add SmartLedgerTechnology/claude-attest
/plugin install claude-attest@smartledger
```

Capture starts immediately and needs no dependencies — the hooks are pure Node
builtins. Signing, anchoring and verification need one install:

```bash
cd ~/.claude/plugins/**/claude-attest && npm install --omit=dev
/attest-init
```

If you skip that step nothing breaks; `claude-attest` tells you exactly what to
run the first time you need it.

Anchoring stays in `mock` mode — fully signed and tamper-evident locally, with
no public timestamp — until you [subscribe](https://proofofprocess.ai) and
configure a key:

```bash
export NOTARYHASH_API_KEY=...
export CLAUDE_ATTEST_ANCHOR=notaryhash
```

## Commands

| Command | What it does |
| --- | --- |
| `/attest-init` | Create the ML-DSA-65 signing identity |
| `/attest-status` | Identity, anchor backend, captured sessions |
| `/attest-verify [session]` | Verify an attestation and print its profile |

The same operations are available as a CLI (`claude-attest init|status|list|verify|finalize|sweep`).

## How it works

**Capture (hot path).** Every hook event appends one leaf to
`~/.claude-attest/sessions/<id>/leaves.ndjson`. A leaf holds a SHA-256 of the
payload and the hash of the leaf before it — never the content itself, so the
log is safe to sync, back up, or hand to an auditor without disclosing prompts,
code, or tool output. The hook uses Node builtins only: no crypto library, no
network, no measurable latency on a tool call.

**Checkpointing.** At each `Stop`, the plugin scans Claude Code's own transcript
and commits one leaf per new line. Because the transcript is append-only and
carries `uuid`/`parentUuid`, a verifier can check that the previously attested
position still holds the uuid recorded there (`cursorIntact`) and that no line
references a missing parent (`parentsResolve`). That is what makes deletion and
rewriting detectable rather than silent.

> The transcript is a **tree**, not a chain — parallel tool calls produce
> sibling lines sharing one `parentUuid`. Reachability is computed accordingly;
> walking a single parent path reports healthy sessions as tampered with.

**Sealing (cold path).** At `SessionEnd` a detached process builds the Merkle
root over all leaves, assembles a header carrying the root, the transcript
state, and the collaboration profile, signs `sha256(canonicalJSON(header))` with
ML-DSA-65, and submits it to NotaryHash. NotaryHash verifies the signature
*before* spending anything, writes the proof to a BSV `OP_RETURN`, and returns a
self-contained SPV certificate.

Anchoring one 32-byte digest per session is what keeps this affordable at any
volume. Batch mode shares a single transaction across many proofs via a Merkle
root.

**Self-healing.** A session killed with `SIGKILL` never fires `SessionEnd`, so
`SessionStart` sweeps for any session left unanchored.

## Verification

The verifier ships as a separate, dependency-free package —
[`@smartledger.technology/proof-of-process`](./packages/proof-of-process) — that
this plugin itself imports. An auditor runs the same code path that produced the
attestation, and needs neither Claude Code nor an account:

```bash
npx @smartledger.technology/proof-of-process verify attestation.json
```

Nothing in that package knows what Claude Code is. The format is
capture-surface-agnostic on purpose: a browser extension, an editor add-in, or a
different agent framework emits the same checkpoints, and one verifier reads all
of them.

## Evidence levels and the platform countersigner

A verification result is not pass/fail. An attestation can be cryptographically
perfect and still be weak evidence, because the person who signed it is the
person it vouches for. What varies is **who stands behind the record**:

| Level | Name | Requires |
| --- | --- | --- |
| 1 | Self Attested | integrity + creator signature + a **mined** anchor |
| 2 | Platform Observed | + a verified countersignature with `role: platform` |
| 3 | Independently Witnessed | + a verified countersignature with `role: witness` |

An anchor still in the mempool is **not** an independent timestamp — nothing
outside the issuing service has committed to it — so it reports level 0 until
mined.

### Running the countersigner

```bash
COUNTERSIGNER_API_KEYS=<key>[,<key>] \
COUNTERSIGNER_KEY=/data/countersigner.json \
node service/countersigner.mjs
```

Point the plugin at it and every finalized session is countersigned automatically:

```bash
export COUNTERSIGNER_URL=https://countersign.proofofprocess.ai
export COUNTERSIGNER_API_KEY=<key>
```

It is requested **in parallel with anchoring** and is non-fatal: a countersigner
that is down costs the upgrade to Level 2, never the record itself.

### What a countersignature does and does not say

The signed statement carries an explicit `observed` field, because this is the
claim most likely to be overstated:

- **`observed: "submission"`** — the signer received this digest from an
  authenticated client at a stated time. It did **not** watch the work happen; a
  client could still submit the digest of a fabricated session. What this
  defeats is **backdating and repudiation**, and it binds the record to an
  account.
- **`observed: "capture"`** — the signer observed the events as they occurred.
  Only a capture surface outside the creator's control can honestly claim this.

The service only ever issues `submission`. Two properties make that meaningful:

1. **The whole statement is signed, not just the digest.** Role, signer,
   `observed`, and timestamp are all inside the signed bytes, so promoting
   `submission` → `capture`, backdating, or renaming the signer all break
   verification. Signing the bare digest would leave the strongest field in the
   record the easiest one to forge.
2. **A countersignature made with the creator's own key is rejected**, not
   counted. Self-countersigning is theatre.

The service never sees content — only a 32-byte digest crosses the wire — so
operating it creates no confidentiality obligation over anyone's work.

## C2PA / Content Credentials

C2PA is the incumbent provenance standard, and every standard manifest must
declare a `digitalSourceType` — whether an asset was captured, human-made,
AI-generated, or a mix. **Today that declaration is entirely self-reported.**
Nothing checks it and nothing can.

That is the gap this fills. We do not compete with C2PA: C2PA describes what a
*file* is, we describe the *process* that produced it, and we make the
`digitalSourceType` declaration evidence-backed rather than asserted.

```bash
claude-attest c2pa <session>                      # assertions for someone else's manifest
claude-attest c2pa <session> --manifest --out m.json   # standalone c2patool definition
```

Two integration paths, both supported:

**Gathered (lead with this).** Another party — an editor, a publishing
pipeline, a camera vendor — signs the manifest and includes our assertion as a
`gathered_assertion`. C2PA explicitly allows assertions contributed by
non-signers, so **we need no X.509 certificate and no place on a trust list.**

**Standalone.** `--manifest` emits a c2patool-compatible definition. C2PA permits
only X.509 signing, so this needs a real certificate; until we are on a
recognized trust list, validators will report *valid signature, unknown signer*.
Signing material is deliberately omitted from the output — it is supplied at
signing time by whoever holds the certificate.

### The recommendation ladder

`digitalSourceType` is derived from the measured profile rather than declared:

| Measurement | IPTC term |
| --- | --- |
| No model output recorded | `digitalCreation` |
| No human-originated input | `trainedAlgorithmicMedia` |
| One instruction, no revision | `trainedAlgorithmicMedia` |
| Human input exceeds model output | `compositeWithTrainedAlgorithmicMedia` |
| Iterative human direction of model output | `compositeSynthetic` |

Each recommendation ships with the rationale that produced it, e.g. *"16 human
turns directing 92 model turns, with 14 revision cycles (88% of human turns)
over 84 active minutes."*

> **It is a recommendation, not a verdict.** `digitalSourceType` describes an
> *asset*; a profile describes a *session*, and one session can produce several
> assets of different character. We say what the session evidences — the creator
> still declares. The assertion states this limit inline, so anyone reading the
> manifest sees it without needing our documentation.

## Key custody

The signing seed lives at `~/.claude-attest/keys/attestor.json`, mode `0600` —
the same posture as `~/.ssh/id_ed25519`. **An agent with Bash access in the same
account can read it.** At minimum, deny it:

```json
{ "permissions": { "deny": [
  "Read(~/.claude-attest/keys/**)",
  "Bash(cat ~/.claude-attest/keys/**)"
]}}
```

The real fix is a signing daemon exposing only `sign(digest)` over a unix
socket, with the key owned by a different uid. Since anchoring needs a funded
BSV key anyway, a separate signing service is the natural shape — and it is what
the third-party-custody tier requires regardless.

## Configuration

`~/.claude-attest/config.json`, overridden by environment:

| Key | Env | Default |
| --- | --- | --- |
| `anchor` | `CLAUDE_ATTEST_ANCHOR` | `mock` |
| `notaryhashUrl` | `NOTARYHASH_URL` | `https://notaryhash.com` |
| — | `NOTARYHASH_API_KEY` | unset |
| `algorithm` | `CLAUDE_ATTEST_ALGORITHM` | `ML-DSA-65` |
| `batch` | `CLAUDE_ATTEST_BATCH` | `true` |

Set `CLAUDE_ATTEST_DEBUG=1` to write diagnostics to `~/.claude-attest/debug.log`.
Hooks never write to stdout or stderr — Claude Code surfaces both to the user or
the model.

## Development

```bash
npm install
npm test          # protocol + profile + tamper-detection tests
bash test/e2e.sh  # drives the hook binary against a real transcript
```

## License

MIT © SmartLedger.Technology

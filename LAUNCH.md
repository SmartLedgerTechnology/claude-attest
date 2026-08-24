# Launch post — drafts

Three versions: long-form (blog / HN text post), title options, and a short
social thread. All figures are real and taken from the live verify page.

---

## Long form

### I built a tool that records how AI-assisted work was actually made. Here's the receipt for the session that built it.

https://proofofprocess.ai/v/bac396056f98571f097661346e3b5852f5de2f28c43296ea6f8e36293cab8531

That page is a permanent, independently checkable record of the working session
that produced the tool. It's anchored in Bitcoin block 962,320. You don't have
to trust me or my servers to verify it — the proof checks against block headers.

Here's what it says about that session:

```
human turns          30
model turns         216
tool calls          346
revision cycles      29   (97% of human turns)
unattended inputs     0
human input       2,578 characters typed
model output    119,483 characters generated
active time         192 min across 51 hours
```

Look at the last two lines. The human typed **2,578 characters**. The model
produced **119,483** — about forty-six times more. By character count this is
overwhelmingly machine-generated.

Now look at the revision rate. **97% of that person's turns were corrections or
redirections** of something the model had just produced. Almost nothing was
accepted as it came out.

So: did a human make this?

"Yes" is misleading. "No" is misleading. Both answers are useless, and that is
the entire problem I wanted to solve.

### The thing nobody can currently prove

Every AI provenance conversation I've seen collapses into a boolean: was this
AI-generated, yes or no? Detection tools chase it and fail. Disclosure policies
demand it and get guesses. C2PA — the actual standard, with real adoption —
requires you to declare a `digitalSourceType` on every asset, and **that
declaration is entirely self-reported.** Nothing checks it. Nothing can.

Meanwhile the interesting question isn't answerable as a boolean at all.
Somebody who types "write me a novel" and ships the output is 100%
human-originated and contributed nothing. Somebody who typed 2,578 characters
across 30 turns and rejected 97% of what came back contributed a great deal.
The difference is the *shape* of the collaboration, and until now there was no
way to evidence it.

So the tool doesn't produce a badge. It produces a measured profile, signs it,
and anchors it. Interpretation is left to whoever is weighing the evidence — a
publisher, an examiner, a client, a court.

### What it actually establishes — and what it doesn't

I want to be precise here, because this space is full of overclaiming and an
evidence product that overclaims is worthless.

**It establishes:** a record with exactly this content existed at that block
time, it hasn't changed since, and the collaboration figures are bound into the
signature — so they can't be adjusted after the fact without breaking
verification.

**It does not establish authorship.** Two limits, both real:

1. **The operator holds the signing key.** A determined person could fabricate a
   transcript offline and sign it. The record is unforgeable *after* signing,
   not before. Closing that requires a second signer who isn't the author — a
   publisher, employer, or escrow — countersigning. That's built, and it's the
   difference between "Self Attested" and "Platform Observed" on the verify page.

2. **A session isn't an asset.** One working session can produce several files of
   very different character. The tool reports what the session evidences and
   recommends a C2PA `digitalSourceType`; the creator still declares.

If you want the short version: it proves **process**, not authorship. That's a
smaller claim than the category usually makes, and it's the one that survives
someone motivated to argue the other side.

### How it works

It's a Claude Code plugin. Hooks capture events as they happen — prompts, tool
calls, permission decisions, subagent delegation, compaction — into an
append-only hash-chained log. **Only hashes are stored, never content**, so the
log is safe to sync, back up, or hand to an auditor without disclosing your
prompts, code, or output.

A few details that turned out to matter:

- **The capture path is zero-dependency.** Node builtins only, no crypto
  library, no network. It has to be, because it runs on every tool call.
- **The transcript is a tree, not a chain.** Parallel tool calls produce sibling
  entries sharing one parent. My first implementation walked a single parent
  path and confidently reported healthy sessions as tampered with.
- **Absent evidence is not negative evidence.** An unmined anchor, a missing
  library, an undisclosed log — all report as *skipped*, never *failed*. Getting
  this wrong tells someone their sound record is broken.
- **Signing is ML-DSA-65 (FIPS 204), post-quantum.** These are meant to be
  evidence for decades. Anchoring is BSV, which costs about 26 satoshis — a
  fraction of a cent — so anchoring everything is affordable.

Verification ships as a separate, dependency-free package that the plugin itself
imports, so an auditor runs the same code path that produced the record and
needs neither Claude Code nor an account.

### Honest status

It works end to end and it's public. It also has **no users**. I built it,
tested it on itself, and I'm posting this because the next useful thing isn't
another feature — it's someone telling me why they wouldn't use it.

Particularly interested in hearing from anyone who has an actual AI-disclosure
obligation — a publisher, a university, an agency with a contract clause. You
have the problem this exists for, and I'd rather hear your objections than guess.

```
Plugin:  /plugin marketplace add SmartLedgerTechnology/claude-attest
         /plugin install claude-attest@smartledger
Source:  https://github.com/SmartLedgerTechnology/claude-attest
Site:    https://proofofprocess.ai
```

Free tier does the full capture, signing and tamper-evidence locally, with no
account and nothing leaving your machine. Anchoring is the paid part.

---

## Title options

1. Show HN: Proof of process for AI-assisted work — here's the receipt for the session that built it
2. Show HN: I recorded how this tool was built, and anchored the record to Bitcoin
3. The human typed 2,578 characters. The model wrote 119,483. Who made it?
4. Show HN: Verifiable proof of how human-AI work was actually produced

*Recommendation: (3) for a blog or X, (1) for Show HN — HN prefers a plain
description of the artifact over a hook.*

---

## Short social thread

**1/**
I built a tool that records how AI-assisted work was actually made, and anchored
the proof to Bitcoin.

Here's the record for the session that built the tool:
https://proofofprocess.ai/v/bac396056f98571f097661346e3b5852f5de2f28c43296ea6f8e36293cab8531

**2/**
The session: 30 human turns, 216 model turns, 346 tool calls.

The human typed 2,578 characters. The model produced 119,483.

But 97% of the human's turns were revisions — corrections to what the model had
just produced.

**3/**
So did a human make it?

"Yes" is misleading. "No" is misleading.

Every AI-provenance system I've seen tries to answer that as a boolean. It isn't
one. Someone who types "write me a novel" is 100% human-originated and
contributed nothing.

**4/**
C2PA — the actual provenance standard — makes you declare whether an asset is
AI-generated. That declaration is entirely self-reported. Nothing checks it.

This makes it evidence-backed: a measured profile, signed, anchored, verifiable
against block headers.

**5/**
What it proves: this record existed at that block time and hasn't changed. The
numbers are inside the signature.

What it does NOT prove: authorship. I hold the key. Closing that needs someone
who isn't me countersigning — which is the next tier up.

**6/**
It's a Claude Code plugin. Capture is zero-dependency and stores only hashes,
never your content.

Free tier: full local capture and tamper-evidence, no account.

https://github.com/SmartLedgerTechnology/claude-attest

**7/**
It has no users yet. I'd rather hear why you wouldn't use it than guess.

Especially if you have a real AI-disclosure obligation — a publisher, a
university, a contract clause. You have the problem this exists for.

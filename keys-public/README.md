# Public signer identities

The public half of every key ProofOfProcess signs with, committed here so the
identities are verifiable without asking our servers for them.

## Why this exists

A countersignature carries the public key that made it, so an old certificate
verifies on its own. But that is circular if you want to answer a different
question: *was this really ProofOfProcess's key, or one someone substituted?*

`countersigner-manifest.json` binds the key to the domain and the role. Its
authenticity rests on two independent things:

1. **Self-signature.** The countersigner signed a statement about its own
   manifest, which only the holder of the private key could produce.
2. **On-chain anchor.** That signed statement is anchored to BSV mainnet, so
   the binding is timestamped and cannot be backdated.

Both are in `countersigner-manifest.proof.json`. Neither depends on this
repository, our servers, or us remaining in business.

## Verify it yourself

```bash
# 1. The manifest digest the countersigner signed
node -e '
  const {canonicalJSON,sha256Hex}=await import("@smartledger.technology/proof-of-process");
  const m=require("./countersigner-manifest.json");
  console.log(sha256Hex(canonicalJSON(m)));
' --input-type=module          # must equal proof.selfSignature.subject

# 2. The self-signature verifies under the manifest's own public key
# 3. The anchored payload is sha256(canonicalJSON(proof.selfSignature))
#    Look the txid up on any BSV explorer.
```

## Rotation

If this key is ever replaced, the new manifest will be committed alongside this
one with a later `effectiveFrom`, and anchored the same way. Old
countersignatures stay valid — they carry the key that made them, and the
anchor proves when that key was current.

# Signing key operations

How the ProofOfProcess platform countersigning key is backed up, restored, and
rotated. Nothing secret lives in this file — it documents procedure only.

## What is at stake

The countersigning key produces platform countersignatures, which lift an
attestation from Level 1 (Self Attested) to Level 2 (Platform Observed). Its
public half is in `countersigner-manifest.json`, self-signed by the key, and
anchored to BSV mainnet (`countersigner-manifest.proof.json`).

Losing the private key does **not** invalidate anything already issued — every
countersignature carries the public key that made it, and the anchor proves when
that key was current. What is lost is the ability to issue new ones under this
identity, which stops every customer's Level 2 claims at whatever they hold.

A compromised key is far worse than a lost one: it lets someone forge
countersignatures that appear to come from us.

## Backup

The key is a 32-byte seed in a JSON file on a Docker volume. It is backed up
with [`age`](https://age-encryption.org), encrypted to **two** SSH public keys
the operator holds, so losing one recipient key does not lose the backup:

```bash
ssh <host> 'docker exec pop-countersigner cat /data/countersigner.json' \
  | age -R ~/.ssh/id_rsa.pub -R ~/.ssh/github_codenlighten.pub \
        -o countersigner-key-$(date -u +%Y%m%dT%H%M%SZ).age
```

Streaming through the pipe means the key is never written unencrypted to the
operator's disk.

**Verify every backup before trusting it.** A backup that has not been restored
is a hope, not a backup:

```bash
# byte-identical to the live file
age -d -i ~/.ssh/id_rsa <backup>.age | sha256sum

# and functionally complete: re-derive the public key from the seed and
# confirm it matches what the live service publishes
```

Keep at least one copy on different physical media from the server.

## Restore

Order matters: the service **generates a new key if the file is absent**, so
restore before starting it, or stop, restore, and restart.

```bash
age -d -i ~/.ssh/id_rsa <backup>.age > /tmp/countersigner.json
sha256sum /tmp/countersigner.json            # compare against the recorded hash
docker cp /tmp/countersigner.json pop-countersigner:/data/countersigner.json
docker exec pop-countersigner chown node:node /data/countersigner.json
docker exec pop-countersigner chmod 600 /data/countersigner.json
docker restart pop-countersigner
curl -s https://countersign.proofofprocess.ai/v1/pubkey   # keyId must be unchanged
shred -u /tmp/countersigner.json
```

## Rotation and compromise

Never swap the key silently — the whole point of the manifest is that the
key/domain binding is public and timestamped.

1. Generate the new key and let the service publish it.
2. Commit a new manifest with a later `effectiveFrom`, self-signed by the new
   key, and anchor it the same way.
3. State the retirement, including the block height after which the old key
   should no longer be trusted for new signatures.

Countersignatures made while the old key was current remain valid, and the
anchors are what let a verifier tell "signed while current" from "signed after
retirement".

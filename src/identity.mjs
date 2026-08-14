import fs from "node:fs";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { keysDir } from "./paths.mjs";

/**
 * The signing identity.
 *
 * Key material is a 32-byte seed stored base64 — the same representation the
 * NotaryHash SDK uses, so one key works with both this plugin and the
 * `notaryhash` CLI. ML-DSA-65 (FIPS 204) is the default because these
 * attestations are meant to be evidence for years, and a signature scheme that
 * a future quantum adversary can forge is not a good foundation for a document
 * you might need to rely on in 2045.
 *
 * SECURITY: the seed is protected by filesystem permissions alone (0600), the
 * same posture as ~/.ssh/id_ed25519. That means an agent with Bash access in
 * this same account can read it. See README "Key custody" — deny-listing the
 * key path is the minimum, and a separate signing daemon is the real fix.
 */

export const DEFAULT_ALGORITHM = "ML-DSA-65";

export function identityFile() {
  return path.join(keysDir(), "attestor.json");
}

export function identityExists() {
  return fs.existsSync(identityFile());
}

export function loadIdentity() {
  if (!identityExists()) return null;
  return JSON.parse(fs.readFileSync(identityFile(), "utf8"));
}

export async function createIdentity(algorithm = DEFAULT_ALGORITHM) {
  if (identityExists()) {
    throw new Error(`identity already exists at ${identityFile()} — move it aside to replace it`);
  }
  const seed = randomBytes(32);
  const publicKey = await derivePublicKey(algorithm, seed);
  const id = {
    algorithm,
    createdAt: new Date().toISOString(),
    privateKey: seed.toString("base64"),
    publicKey,
    publicKeyId: fingerprint(publicKey),
  };
  fs.writeFileSync(identityFile(), JSON.stringify(id, null, 2), { mode: 0o600 });
  return id;
}

/** Public-key-only view. This is what is safe to publish in a certificate. */
export function publicView(id) {
  return {
    algorithm: id.algorithm,
    publicKey: id.publicKey,
    publicKeyId: id.publicKeyId,
    createdAt: id.createdAt,
  };
}

async function mlDsa(algorithm) {
  const mod = await import("@noble/post-quantum/ml-dsa");
  const impl = { "ML-DSA-44": mod.ml_dsa44, "ML-DSA-65": mod.ml_dsa65, "ML-DSA-87": mod.ml_dsa87 }[
    algorithm
  ];
  if (!impl) throw new Error(`unsupported algorithm: ${algorithm}`);
  return impl;
}

async function derivePublicKey(algorithm, seed) {
  if (algorithm === "ECDSA-secp256k1") {
    const { secp256k1 } = await import("@noble/curves/secp256k1");
    return Buffer.from(secp256k1.getPublicKey(seed, true)).toString("hex");
  }
  const impl = await mlDsa(algorithm);
  return Buffer.from(impl.keygen(seed).publicKey).toString("base64");
}

/**
 * Sign a hex digest, producing exactly the body NotaryHash /v1/notarize expects.
 * Kept wire-compatible with the SDK's `sign()` so the anchor service verifies
 * this signature before spending anything to anchor it.
 */
export async function signDigest(id, digestHex) {
  const seed = Buffer.from(id.privateKey, "base64");
  const digest = Buffer.from(digestHex, "hex");
  const createdAt = new Date().toISOString();

  if (id.algorithm === "ECDSA-secp256k1") {
    const { secp256k1 } = await import("@noble/curves/secp256k1");
    const sig = secp256k1.sign(digest, seed, { prehash: false });
    return {
      algorithm: id.algorithm,
      hashAlgorithm: "SHA-256",
      payloadHash: digestHex,
      publicKey: id.publicKey,
      signature: Buffer.from(sig.toCompactRawBytes()).toString("hex"),
      encoding: "hex",
      createdAt,
    };
  }

  const impl = await mlDsa(id.algorithm);
  const keys = impl.keygen(seed);
  return {
    algorithm: id.algorithm,
    hashAlgorithm: "SHA-256",
    payloadHash: digestHex,
    publicKey: Buffer.from(keys.publicKey).toString("base64"),
    signature: Buffer.from(impl.sign(keys.secretKey, digest)).toString("base64"),
    encoding: "base64",
    createdAt,
  };
}

function fingerprint(publicKeyEncoded) {
  return createHash("sha256")
    .update(publicKeyEncoded)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "")
    .slice(0, 16);
}

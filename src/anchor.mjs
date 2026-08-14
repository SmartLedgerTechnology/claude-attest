import { signDigest } from "./identity.mjs";
import { debugLog } from "./paths.mjs";

/**
 * Anchor backends turn a signed checkpoint digest into a public timestamp.
 *
 * `notaryhash` POSTs to a NotaryHash service, which verifies the signature
 * before spending anything, writes the canonical proof to a BSV OP_RETURN, and
 * returns a self-contained certificate. Batch mode shares one transaction
 * across many proofs via a Merkle root — the per-attestation cost of a busy
 * coding session is otherwise pure waste.
 *
 * `mock` produces a certificate-shaped object with no network and no chain, so
 * the plugin is fully exercisable — and the whole free tier is usable — without
 * an account.
 */

export async function anchor(digestHex, identity, config) {
  const backend = config.anchor ?? "mock";
  try {
    if (backend === "mock") return await mockAnchor(digestHex, identity);
    if (backend === "notaryhash") return await notaryHashAnchor(digestHex, identity, config);
    throw new Error(`unknown anchor backend: ${backend}`);
  } catch (e) {
    debugLog(`anchor failed: ${e.stack ?? e}`);
    return { ok: false, error: e?.message ?? String(e), backend };
  }
}

async function notaryHashAnchor(digestHex, identity, config) {
  const body = await signDigest(identity, digestHex);
  if (config.batch !== false) body.batch = true;

  const headers = { "Content-Type": "application/json" };
  if (config.apiKey) headers["X-API-Key"] = config.apiKey;

  const url = `${String(config.notaryhashUrl).replace(/\/$/, "")}/v1/notarize`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.timeoutMs ?? 30_000);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      return {
        ok: false,
        backend: "notaryhash",
        error: `HTTP ${res.status}: ${data?.error ?? "notarize rejected"}`,
        // Keep the signature — a failed anchor should still leave a signed,
        // re-submittable attestation rather than discarding the evidence.
        certificate: { ...body, anchor: null },
      };
    }
    return { ok: true, backend: "notaryhash", id: data.id, certificate: data.certificate };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Ask the platform countersigner to attest that it received this digest.
 *
 * Optional and non-fatal: an attestation without a countersignature is still
 * valid Level 1 evidence, so a countersigner being unreachable must never cost
 * someone their record. It only costs them the upgrade to Level 2.
 */
export async function requestCountersignature(digestHex, config) {
  if (!config.countersignerUrl) return { ok: false, skipped: true };

  const url = `${String(config.countersignerUrl).replace(/\/$/, "")}/v1/countersign`;
  const headers = { "content-type": "application/json" };
  if (config.countersignerApiKey) headers["x-api-key"] = config.countersignerApiKey;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.timeoutMs ?? 15_000);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({ subject: digestHex }),
      signal: controller.signal,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}: ${data?.error ?? "countersign rejected"}` };
    if (!data.countersignature) return { ok: false, error: "response contained no countersignature" };
    return { ok: true, countersignature: data.countersignature };
  } catch (e) {
    debugLog(`requestCountersignature failed: ${e.message}`);
    return { ok: false, error: e?.message ?? String(e) };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Re-fetch a certificate from the issuing service.
 *
 * A certificate is written at broadcast time, when the transaction is still in
 * the mempool: `blockHeight` and `blockTime` are null and there is no SPV
 * envelope. Once the anchoring transaction is mined, the service's confirmation
 * poller fills all of that in — but our local copy does not know.
 *
 * Refreshing pulls the completed certificate, including the `spv` block
 * (rawTx + blockHash + merkle inclusion proof) that lets a verifier confirm the
 * anchor against Bitcoin block headers alone, with no dependency on the service
 * that issued it. That is the difference between "they say it is anchored" and
 * "the chain says it is anchored".
 */
export async function refreshCertificate(attestation, config) {
  const id = attestation.notaryHashId;
  if (!id) return { ok: false, error: "attestation has no NotaryHash id to refresh" };

  const url = `${String(config.notaryhashUrl).replace(/\/$/, "")}/v1/certificate/${id}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.timeoutMs ?? 30_000);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) return { ok: false, error: `HTTP ${res.status} fetching certificate ${id}` };
    const data = await res.json();
    const certificate = data.certificate ?? data;

    // The refreshed certificate must still commit to the same header we signed.
    // Anything else means we were handed someone else's proof.
    if (certificate.payloadHash !== attestation.certificate?.payloadHash) {
      return {
        ok: false,
        error:
          `refused: fetched certificate is for a different payload ` +
          `(${certificate.payloadHash?.slice(0, 16)}… vs ${attestation.certificate?.payloadHash?.slice(0, 16)}…)`,
      };
    }
    return { ok: true, certificate, confirmed: certificate.anchor?.blockHeight != null };
  } catch (e) {
    debugLog(`refreshCertificate failed: ${e.message}`);
    return { ok: false, error: e?.message ?? String(e) };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * The offline path. Still signs — the hash chain, the Merkle root and the
 * signature are all real and all verifiable; only the public timestamp is
 * absent. That is exactly the free tier: tamper-evident locally, not yet
 * provable to a third party.
 */
async function mockAnchor(digestHex, identity) {
  const body = await signDigest(identity, digestHex);
  return {
    ok: true,
    backend: "mock",
    certificate: {
      protocol: "NotaryHash",
      version: "1.0",
      mode: "full",
      ...body,
      anchor: { type: "direct", network: "mock", txid: null, vout: 0, blockHeight: null, blockTime: null },
    },
  };
}

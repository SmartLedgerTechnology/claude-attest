/**
 * Published records — what a verify link resolves to.
 *
 * Kept apart from the HTTP wiring so the rules can be tested without a server.
 * One rule runs through all of it: a field the caller supplies may be stored
 * and shown as the caller's claim, and may never decide where a record is
 * stored, which record a link resolves to, or what a reader is told was
 * verified. Every key and every verdict here is derived from something that
 * was checked.
 *
 *   pop:published:<digest>        the record, named by sha256(canonicalJSON(header))
 *   pop:published-alias:<id>      NotaryHash certificate id -> digest
 *
 * The alias exists so a NotaryHash id can be used in a verify link. A
 * certificate's id is its proof hash, which the SDK recomputes from the
 * certificate's own bytes — so an alias is derived from the certificate, never
 * accepted from the request, is written once and never overwritten, and is
 * re-checked against the record every time it is followed.
 */

import { canonicalJSON, sha256Hex } from "../packages/proof-of-process/src/canonical.mjs";
import { verifyAttestation } from "../packages/proof-of-process/src/verify.mjs";

const RECORD = "pop:published:";
const ALIAS = "pop:published-alias:";
const HEX64 = /^[0-9a-f]{64}$/;

/**
 * Is `id` this certificate's own NotaryHash id? True only when the proof hash
 * recomputed from the certificate equals it and the certificate's signature
 * verifies. Without the SDK the answer is "cannot tell", which is a no.
 */
export async function certificateOwnsId(certificate, id) {
  if (!HEX64.test(String(id)) || certificate?.proofHash !== id) return false;
  try {
    const sdk = await import("@smartledger/notaryhash");
    const v = sdk.verifyCertificateOffline(certificate);
    return v.proofHashValid === true && v.signatureValid === true;
  } catch {
    return false;
  }
}

/**
 * @param redis        a node-redis compatible client, or null for the in-memory
 *                     fallback used by tests and deployments without Redis
 * @param verify       verifyAttestation, injectable for tests
 * @param verifyOpts   extra options for every verification (header provider…)
 * @param ownsId       certificateOwnsId, injectable for tests
 * @param fetchImpl    fetch, injectable for tests
 * @param notaryhashUrl where certificates are refreshed from
 */
export function makePublishedStore({
  redis = null,
  verify = verifyAttestation,
  verifyOpts = {},
  ownsId = certificateOwnsId,
  fetchImpl = globalThis.fetch,
  notaryhashUrl = "https://notaryhash.com",
  refreshTimeoutMs = 8_000,
} = {}) {
  const memory = new Map();
  const get = async (k) => (redis ? await redis.get(k) : memory.get(k) ?? null);
  const set = async (k, v) => (redis ? await redis.set(k, v) : void memory.set(k, v));
  // Create-only: an existing key is left exactly as it is.
  const setIfAbsent = async (k, v) => {
    if (redis) return (await redis.set(k, v, { NX: true })) != null;
    if (memory.has(k)) return false;
    memory.set(k, v);
    return true;
  };

  const check = ({ header, certificate, countersignatures }) =>
    verify({ header, certificate, countersignatures }, { checkChain: true, ...verifyOpts });

  /** Is the record stored under this digest, right now, signed by this key? */
  async function signedBy(digest, publicKey) {
    const raw = await get(RECORD + digest);
    return !!raw && JSON.parse(raw).certificate?.publicKey === publicKey;
  }

  async function writeAlias(record) {
    const id = record.certificate?.proofHash;
    if (await ownsId(record.certificate, id)) await setIfAbsent(ALIAS + id, record.id);
  }

  /**
   * Store an attestation under its digest.
   *
   * Refused when it does not verify. A record whose anchor simply cannot be
   * confirmed yet is accepted — it renders as incomplete until it can be — but
   * one that fails a check is not hosted at all.
   */
  async function publish({ header, certificate, countersignatures }, auth = {}) {
    if (!header || !certificate) {
      return { ok: false, status: 400, error: "attestation must include a header and a certificate" };
    }
    // The record is named by the digest that was signed. Anyone holding the
    // attestation can derive the same id, and a mismatch here means the header
    // and the certificate do not belong together.
    const digest = sha256Hex(canonicalJSON(header));
    if (digest !== certificate.payloadHash) {
      return { ok: false, status: 400, error: "header does not match the certificate's payloadHash" };
    }

    const counters = Array.isArray(countersignatures) ? countersignatures : [];
    const report = await check({ header, certificate, countersignatures: counters });
    if (report.verdict === "failed") {
      return { ok: false, status: 400, error: "attestation did not verify", reasons: report.reasons };
    }

    const record = {
      id: digest,
      header,
      certificate,
      countersignatures: counters,
      customerId: auth.customerId ?? null,
      publishedVia: auth.via,
      publishedAt: new Date().toISOString(),
    };
    // Created atomically, so two keys racing for one digest cannot both win.
    // Re-publishing is how a record picks up a confirmed certificate, so it is
    // allowed — but only under the key that signed it the first time. Otherwise
    // anyone holding a header could replace its record with one signed by them.
    if (!(await setIfAbsent(RECORD + digest, JSON.stringify(record)))) {
      if (!(await signedBy(digest, certificate.publicKey))) {
        return { ok: false, status: 409, error: "this record is already published under a different signing key" };
      }
      await set(RECORD + digest, JSON.stringify(record));
    }
    await writeAlias(record);
    return { ok: true, id: digest, verdict: report.verdict };
  }

  /** Resolve a link's id to a record: by digest, or by a certificate id it owns. */
  async function load(id) {
    const direct = await get(RECORD + id);
    if (direct) return JSON.parse(direct);
    if (!HEX64.test(id)) return null;
    const aliased = await get(ALIAS + id);
    if (!aliased) return null;
    const raw = await get(RECORD + aliased);
    if (!raw) return null;
    const record = JSON.parse(raw);
    // Followed only if the record's certificate really carries this id. An
    // alias written before this rule existed proves nothing by being there.
    return (await ownsId(record.certificate, id)) ? record : null;
  }

  /**
   * Fetch the certificate again from the service that issued it.
   *
   * A certificate stored before its transaction was mined has no proof in it.
   * The response is untrusted input: it must be for the same digest, under the
   * same signing key, and must then pass the full verification itself before it
   * replaces anything.
   */
  async function refreshed(record) {
    const id = record.certificate?.proofHash;
    if (!HEX64.test(String(id)) || !fetchImpl) return null;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), refreshTimeoutMs);
    try {
      const res = await fetchImpl(`${String(notaryhashUrl).replace(/\/$/, "")}/v1/certificate/${id}`, {
        signal: controller.signal,
      });
      if (!res.ok) return null;
      const data = await res.json();
      const certificate = data?.certificate ?? data;
      if (certificate?.payloadHash !== record.id) return null;
      if (certificate.publicKey !== record.certificate.publicKey) return null;
      const report = await check({ ...record, certificate });
      if (report.checks.onChain !== true || report.verdict === "failed") return null;
      const next = { ...record, certificate, refreshedAt: new Date().toISOString() };
      if (!(await signedBy(record.id, certificate.publicKey))) return null;
      await set(RECORD + record.id, JSON.stringify(next));
      await writeAlias(next);
      return { record: next, report };
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Load a record and verify it from its stored bytes. Returns null when there
   * is nothing under that id.
   */
  async function view(id) {
    const record = await load(id);
    if (!record) return null;
    const report = await check(record);
    if (report.anchor?.state === "unconfirmed" || report.anchor?.state === "failed") {
      const better = await refreshed(record);
      if (better) return better;
    }
    return { record, report };
  }

  return { publish, load, view };
}

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { canonicalJSON, sha256Hex } from "../packages/proof-of-process/src/canonical.mjs";
import { makePublishedStore, certificateOwnsId } from "../service/published.mjs";

/**
 * Publishing and resolving verify links.
 *
 * The verifier itself is tested in verdict.test.mjs; here it is stubbed so the
 * storage rules can be exercised alone: nothing the caller supplies picks a
 * key, nothing already stored is displaced, and a fetched certificate is
 * untrusted until it verifies.
 */

const set = JSON.parse(fs.readFileSync(new URL("./fixtures/notaryhash-tamper-cases.json", import.meta.url), "utf8"));
const realCertificate = set.cases[0].certificate;

const ID_A = "a".repeat(64);
const ID_B = "b".repeat(64);

function attestation({ session = "s1", publicKey = "key-1", proofHash = ID_A, spv = false } = {}) {
  const header = { v: 1, format: "proof-of-process.checkpoint.v1", sessionId: session };
  const certificate = { payloadHash: sha256Hex(canonicalJSON(header)), publicKey, proofHash, anchor: { txid: "t" } };
  if (spv) certificate.spv = { rawTx: "00" };
  return { header, certificate, countersignatures: [] };
}

/** A verifier that confirms an anchor exactly when the certificate carries a proof. */
const stubVerify = async ({ certificate }) =>
  certificate.bad
    ? { verdict: "failed", reasons: ["signature did not verify"], checks: { onChain: null }, anchor: { state: "unconfirmed" } }
    : certificate.spv
      ? { verdict: "verified", reasons: [], checks: { onChain: true }, anchor: { state: "confirmed" } }
      : { verdict: "incomplete", reasons: [], checks: { onChain: null }, anchor: { state: "unconfirmed" } };

/** Owns an id when the certificate names it — the SDK's part is tested below. */
const stubOwns = async (certificate, id) => /^[0-9a-f]{64}$/.test(String(id)) && certificate?.proofHash === id;

const store = (extra = {}) => makePublishedStore({ verify: stubVerify, ownsId: stubOwns, fetchImpl: null, ...extra });

test("a record is stored under the digest of its header", async () => {
  const s = store();
  const a = attestation();
  const r = await s.publish(a, { via: "subscription", customerId: "cus_1" });
  assert.equal(r.ok, true);
  assert.equal(r.id, a.certificate.payloadHash);
  assert.equal((await s.load(r.id)).customerId, "cus_1");
});

test("a header that does not match the certificate is refused", async () => {
  const a = attestation();
  a.certificate.payloadHash = "0".repeat(64);
  const r = await store().publish(a);
  assert.equal(r.ok, false);
  assert.equal(r.status, 400);
});

test("an attestation that fails verification is not hosted", async () => {
  const s = store();
  const a = attestation();
  a.certificate.bad = true;
  const r = await s.publish(a);
  assert.equal(r.ok, false);
  assert.equal(r.status, 400);
  assert.deepEqual(r.reasons, ["signature did not verify"]);
  assert.equal(await s.load(a.certificate.payloadHash), null);
});

test("an unconfirmed anchor is hosted, and reported as incomplete", async () => {
  const r = await store().publish(attestation());
  assert.equal(r.ok, true);
  assert.equal(r.verdict, "incomplete");
});

test("the alias is the certificate's own id, never a value from the request", async () => {
  const s = store();
  const a = attestation({ proofHash: ID_A });
  // A request may still carry a notaryHashId; publish() has no way to take one.
  await s.publish({ ...a, notaryHashId: "invoice-2026-0042" });
  assert.equal(await s.load("invoice-2026-0042"), null, "a chosen path resolves to nothing");
  assert.equal((await s.load(ID_A)).id, a.certificate.payloadHash);
});

test("an existing alias is never repointed", async () => {
  const s = store();
  const first = attestation({ session: "first", proofHash: ID_A });
  const second = attestation({ session: "second", publicKey: "key-2", proofHash: ID_A });
  await s.publish(first);
  await s.publish(second);
  assert.equal((await s.load(ID_A)).id, first.certificate.payloadHash);
});

test("an alias planted in the store resolves to nothing unless the certificate owns it", async () => {
  // What a pre-existing, caller-chosen alias looks like: it points at a record
  // whose certificate has a different id.
  const memory = new Map();
  const redis = {
    get: async (k) => memory.get(k) ?? null,
    set: async (k, v, o) => (o?.NX && memory.has(k) ? null : (memory.set(k, v), "OK")),
  };
  const s = store({ redis });
  const a = attestation({ proofHash: ID_A });
  await s.publish(a);
  memory.set(`pop:published-alias:${ID_B}`, a.certificate.payloadHash);
  memory.set("pop:published-alias:case-17", a.certificate.payloadHash);
  assert.equal(await s.load(ID_B), null);
  assert.equal(await s.load("case-17"), null);
  assert.equal((await s.load(ID_A)).id, a.certificate.payloadHash);
});

test("a record can be re-published under the same key, and not under another", async () => {
  const s = store();
  const a = attestation();
  await s.publish(a);
  const confirmed = attestation({ spv: true });
  assert.equal((await s.publish(confirmed)).verdict, "verified");

  const usurper = attestation({ publicKey: "someone-else" });
  const r = await s.publish(usurper);
  assert.equal(r.ok, false);
  assert.equal(r.status, 409);
  assert.equal((await s.load(a.certificate.payloadHash)).certificate.publicKey, "key-1");
});

test("two keys racing to publish one digest cannot both win", async () => {
  const s = store();
  const mine = attestation();
  const theirs = attestation({ publicKey: "someone-else" });
  const results = await Promise.all([s.publish(mine), s.publish(theirs)]);
  assert.deepEqual(results.map((r) => r.ok).sort(), [false, true]);
  const winner = results[0].ok ? mine : theirs;
  assert.equal((await s.load(mine.certificate.payloadHash)).certificate.publicKey, winner.certificate.publicKey);
});

/* ------------------------------ refresh ---------------------------------- */

const serving = (certificate, status = 200) => async () => ({ ok: status === 200, status, json: async () => ({ certificate }) });

test("an unconfirmed record picks up a confirmed certificate once it verifies", async () => {
  const a = attestation();
  const s = store({ fetchImpl: serving({ ...a.certificate, spv: { rawTx: "00" } }) });
  await s.publish(a);
  const v = await s.view(a.certificate.payloadHash);
  assert.equal(v.report.verdict, "verified");
  assert.ok(v.record.certificate.spv, "the confirmed certificate replaced the stored one");
  assert.ok((await s.load(a.certificate.payloadHash)).certificate.spv);
});

test("a fetched certificate for another payload, or another key, is ignored", async () => {
  const a = attestation();
  for (const wrong of [
    { ...a.certificate, payloadHash: "f".repeat(64), spv: { rawTx: "00" } },
    { ...a.certificate, publicKey: "someone-else", spv: { rawTx: "00" } },
  ]) {
    const s = store({ fetchImpl: serving(wrong) });
    await s.publish(a);
    const v = await s.view(a.certificate.payloadHash);
    assert.equal(v.report.verdict, "incomplete");
    assert.equal(v.record.certificate.spv, undefined);
  }
});

test("a fetched certificate that does not verify is ignored", async () => {
  const a = attestation();
  const s = store({ fetchImpl: serving({ ...a.certificate, bad: true, spv: { rawTx: "00" } }) });
  await s.publish(a);
  const v = await s.view(a.certificate.payloadHash);
  assert.equal(v.report.verdict, "incomplete");
  assert.equal(v.record.certificate.bad, undefined);
});

test("a service that is down or has no such certificate changes nothing", async () => {
  const a = attestation();
  for (const fetchImpl of [serving(null, 404), serving(null, 503), async () => { throw new Error("timeout"); }]) {
    const s = store({ fetchImpl });
    await s.publish(a);
    const v = await s.view(a.certificate.payloadHash);
    assert.equal(v.report.verdict, "incomplete");
  }
});

test("an unknown id has no page", async () => {
  assert.equal(await store().view("nope"), null);
});

/* ---------------------- the real ownership check ------------------------- */

test("a real certificate owns its proof hash and nothing else", async () => {
  assert.equal(await certificateOwnsId(realCertificate, realCertificate.proofHash), true);
  assert.equal(await certificateOwnsId(realCertificate, ID_A), false);
  assert.equal(await certificateOwnsId(realCertificate, "invoice-2026-0042"), false);
});

test("writing someone else's id into a certificate does not make it the owner", async () => {
  const forged = { ...realCertificate, proofHash: ID_A };
  assert.equal(await certificateOwnsId(forged, ID_A), false);
});

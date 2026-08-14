import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import {
  buildStatement,
  statementDigest,
  verifyCountersignature,
  isIndependentOf,
  OBSERVED,
  ROLES,
} from "../packages/proof-of-process/src/countersign.mjs";

const SUBJECT = "a".repeat(64);

function makeSigner() {
  const seed = randomBytes(32);
  const keys = ml_dsa65.keygen(seed);
  return {
    publicKey: Buffer.from(keys.publicKey).toString("base64"),
    sign(digestHex) {
      return Buffer.from(ml_dsa65.sign(keys.secretKey, Buffer.from(digestHex, "hex"))).toString("base64");
    },
  };
}

function countersign(signer, overrides = {}) {
  const statement = buildStatement({
    role: ROLES.PLATFORM,
    signer: "proofofprocess.ai",
    observed: OBSERVED.SUBMISSION,
    observedAt: "2026-08-12T23:00:00.000Z",
    subject: SUBJECT,
    clientKeyId: "client-abc",
    ...overrides,
  });
  return {
    ...statement,
    algorithm: "ML-DSA-65",
    publicKey: signer.publicKey,
    signature: signer.sign(statementDigest(statement)),
    encoding: "base64",
  };
}

test("a well-formed countersignature verifies", async () => {
  const r = await verifyCountersignature(countersign(makeSigner()), SUBJECT);
  assert.equal(r.ok, true);
  assert.equal(r.statement.observed, OBSERVED.SUBMISSION);
});

test("the statement rejects an unknown role or observation", () => {
  assert.throws(() => buildStatement({ role: "auditor", signer: "x", observed: OBSERVED.SUBMISSION, observedAt: "t", subject: SUBJECT }), /unknown role/);
  assert.throws(() => buildStatement({ role: ROLES.PLATFORM, signer: "x", observed: "watched", observedAt: "t", subject: SUBJECT }), /observed must be/);
  assert.throws(() => buildStatement({ role: ROLES.PLATFORM, signer: "x", observed: OBSERVED.SUBMISSION, observedAt: "t", subject: "short" }), /64-char hex/);
});

/* ---- the metadata must be bound, not merely adjacent ---- */

test("upgrading `observed` from submission to capture breaks the signature", async () => {
  const cs = countersign(makeSigner());
  const forged = { ...cs, observed: OBSERVED.CAPTURE };
  const r = await verifyCountersignature(forged, SUBJECT);
  assert.equal(r.ok, false, "claiming to have witnessed the work must not be forgeable");
});

test("backdating observedAt breaks the signature", async () => {
  const cs = countersign(makeSigner());
  const r = await verifyCountersignature({ ...cs, observedAt: "2020-01-01T00:00:00.000Z" }, SUBJECT);
  assert.equal(r.ok, false);
});

test("promoting the role to witness breaks the signature", async () => {
  const cs = countersign(makeSigner());
  const r = await verifyCountersignature({ ...cs, role: ROLES.WITNESS }, SUBJECT);
  assert.equal(r.ok, false);
});

test("renaming the signer breaks the signature", async () => {
  const cs = countersign(makeSigner());
  const r = await verifyCountersignature({ ...cs, signer: "trustworthy-notary.example" }, SUBJECT);
  assert.equal(r.ok, false);
});

/* ---- it must cover THIS record ---- */

test("a countersignature for another record is refused", async () => {
  const cs = countersign(makeSigner());
  const r = await verifyCountersignature(cs, "b".repeat(64));
  assert.equal(r.ok, false);
  assert.match(r.reason, /different record/);
});

test("repointing the subject to another record breaks the signature", async () => {
  const cs = countersign(makeSigner());
  const other = "b".repeat(64);
  const r = await verifyCountersignature({ ...cs, subject: other }, other);
  assert.equal(r.ok, false, "subject is inside the signed statement");
});

test("a signature made by a different key does not verify", async () => {
  const cs = countersign(makeSigner());
  const r = await verifyCountersignature({ ...cs, publicKey: makeSigner().publicKey }, SUBJECT);
  assert.equal(r.ok, false);
});

/* ---- independence ---- */

test("a countersignature using the creator's own key is not independent", () => {
  const signer = makeSigner();
  const cs = countersign(signer);
  assert.equal(isIndependentOf(cs, signer.publicKey), false, "self-countersigning is theatre");
  assert.equal(isIndependentOf(cs, makeSigner().publicKey), true);
});

test("malformed input is rejected rather than throwing", async () => {
  assert.equal((await verifyCountersignature(null, SUBJECT)).ok, false);
  assert.equal((await verifyCountersignature({}, SUBJECT)).ok, false);
  assert.match((await verifyCountersignature({ role: "nope" }, SUBJECT)).reason, /malformed/);
});

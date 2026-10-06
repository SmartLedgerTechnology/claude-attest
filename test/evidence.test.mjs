import test from "node:test";
import assert from "node:assert/strict";
import { evidenceLevel, COUNTERSIGNATURE_ROLES } from "../packages/proof-of-process/src/evidence.mjs";

const allPass = {
  format: true,
  leafContinuity: true,
  hashChain: true,
  merkleRoot: true,
  anchorBinding: true,
  signature: true,
  transcriptChain: true,
  onChain: true,
};

// What the chain check concluded is carried by `checks.onChain`. The anchor
// fields inside a certificate are its holder's claim and decide nothing.
const unchecked = { ...allPass, onChain: null };

const confirmed = { certificate: { anchor: { txid: "abc", blockHeight: 962047 } } };
const mempool = { certificate: { anchor: { txid: "abc", blockHeight: null } } };

test("a sound, confirmed, self-signed attestation is level 1", () => {
  const e = evidenceLevel(confirmed, allPass, []);
  assert.equal(e.level, 1);
  assert.equal(e.name, "Self Attested");
  assert.match(e.caveat, /does not establish authorship/);
  assert.match(e.nextLevelRequires, /capture platform/);
});

test("an unmined anchor is not yet an independent timestamp", () => {
  const e = evidenceLevel(mempool, unchecked, []);
  assert.equal(e.level, 0);
  assert.equal(e.criteria.timestamped, false);
  assert.match(e.blockedBy, /has not been mined/);
});

test("broken integrity cannot reach any level", () => {
  const e = evidenceLevel(confirmed, { ...allPass, hashChain: false }, []);
  assert.equal(e.level, 0);
  assert.equal(e.criteria.integrity, false);
});

test("a rewritten transcript disqualifies, but a non-applicable check does not", () => {
  assert.equal(evidenceLevel(confirmed, { ...allPass, transcriptChain: false }, []).level, 0);
  assert.equal(evidenceLevel(confirmed, { ...allPass, transcriptChain: null }, []).level, 1);
});

test("a platform countersignature reaches level 2", () => {
  const e = evidenceLevel(confirmed, allPass, [
    { role: COUNTERSIGNATURE_ROLES.PLATFORM, keyId: "platform-key-1" },
  ]);
  assert.equal(e.level, 2);
  assert.equal(e.name, "Platform Observed");
  assert.match(e.nextLevelRequires, /independent witness/);
  assert.equal(e.caveat, undefined, "the authorship caveat is a level-1 statement");
});

test("an independent witness reaches level 3 and needs nothing further", () => {
  const e = evidenceLevel(confirmed, allPass, [
    { role: COUNTERSIGNATURE_ROLES.WITNESS, keyId: "notary-key-9" },
  ]);
  assert.equal(e.level, 3);
  assert.equal(e.name, "Independently Witnessed");
  assert.equal(e.nextLevelRequires, null);
});

test("the witness role wins when both countersignatures are present", () => {
  const e = evidenceLevel(confirmed, allPass, [
    { role: COUNTERSIGNATURE_ROLES.PLATFORM, keyId: "p" },
    { role: COUNTERSIGNATURE_ROLES.WITNESS, keyId: "w" },
  ]);
  assert.equal(e.level, 3);
  assert.equal(e.countersignatures.length, 2);
});

test("countersignatures cannot rescue a broken record", () => {
  const e = evidenceLevel(confirmed, { ...allPass, merkleRoot: false }, [
    { role: COUNTERSIGNATURE_ROLES.WITNESS, keyId: "w" },
  ]);
  assert.equal(e.level, 0, "a witness signature over a tampered record proves nothing");
});

test("a sound but unanchored record reads as locally verified, not broken", () => {
  const unanchored = { certificate: { anchor: { txid: null, network: "mock", blockHeight: null } } };
  const e = evidenceLevel(unanchored, unchecked, []);
  assert.equal(e.level, 0);
  assert.equal(e.name, "Locally Verified", "the free tier is not a failure state");
  assert.match(e.summary, /tamper-evident/);
  assert.match(e.nextLevelRequires, /anchoring/);
});

test("genuinely broken integrity still reads as unverified", () => {
  const confirmedAnchor = { certificate: { anchor: { txid: "abc", blockHeight: 1 } } };
  const e = evidenceLevel(confirmedAnchor, { ...allPass, merkleRoot: false }, []);
  assert.equal(e.level, 0);
  assert.equal(e.name, "Unverified");
  assert.match(e.summary, /did not pass/);
});

test("a broadcast-but-unmined anchor reads as pending, not unanchored", () => {
  const pending = { certificate: { anchor: { txid: "abc123", network: "bsv-mainnet", blockHeight: null } } };
  const e = evidenceLevel(pending, unchecked, []);
  assert.equal(e.level, 0);
  assert.equal(e.name, "Anchor Pending", "broadcast is not the same as absent");
  assert.match(e.nextLevelRequires, /mined/);
  assert.match(e.blockedBy, /not been mined/);
});

test("no anchor at all is distinct from a pending one", () => {
  const none = { certificate: { anchor: { txid: null, network: "mock", blockHeight: null } } };
  const e = evidenceLevel(none, unchecked, []);
  assert.equal(e.name, "Locally Verified");
  assert.match(e.blockedBy, /no anchor has been submitted/);
});

test("a block height written into the certificate is not a timestamp", () => {
  // The chain check did not run. The certificate saying it is in a block
  // cannot, on its own, reach level 1 — with or without countersignatures.
  const e = evidenceLevel(confirmed, unchecked, [{ role: COUNTERSIGNATURE_ROLES.WITNESS, keyId: "w" }]);
  assert.equal(e.level, 0);
  assert.equal(e.criteria.timestamped, false);
  assert.equal(e.name, "Anchor Pending");
});

test("an anchor that was checked and failed reads as unverified, not pending", () => {
  const e = evidenceLevel(confirmed, { ...allPass, onChain: false }, [
    { role: COUNTERSIGNATURE_ROLES.WITNESS, keyId: "w" },
  ]);
  assert.equal(e.level, 0);
  assert.equal(e.name, "Unverified");
});

test("the network label does not decide whether an anchor is claimed", () => {
  const relabelled = { certificate: { anchor: { txid: "abc", network: "mock", blockHeight: 620000 } } };
  const e = evidenceLevel(relabelled, unchecked, []);
  assert.equal(e.name, "Anchor Pending", "calling a claimed anchor mock does not make it the free tier");
});

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { randomBytes } from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import * as sdk from "@smartledger/notaryhash";
import { canonicalJSON, sha256Hex } from "../packages/proof-of-process/src/canonical.mjs";
import { verifyAttestation, verifyOnChain, CHECKPOINT_FORMAT } from "../packages/proof-of-process/src/verify.mjs";
import { renderVerifyPage } from "../service/verify-page.mjs";

/**
 * The verdict, and what a reader is shown.
 *
 * Nothing in `certificate.anchor` is signed, so every test here edits those
 * fields the way an attacker holding their own key would, and asserts that the
 * edit can neither produce a pass nor put a block or a date on the page.
 */

const Y2020 = 1577836800;
const FAKE_TXID = "ab".repeat(32);

/** A record signed by a fresh key, with whatever anchor the caller invents. */
function signed(anchor) {
  const keys = ml_dsa65.keygen(randomBytes(32));
  const header = { v: 1, format: CHECKPOINT_FORMAT, sessionId: "s1", leafCount: 0, merkleRoot: "0".repeat(64) };
  const digest = sha256Hex(canonicalJSON(header));
  const certificate = {
    protocol: "NotaryHash",
    version: "1.0",
    mode: "full",
    algorithm: "ML-DSA-65",
    hashAlgorithm: "SHA-256",
    payloadHash: digest,
    publicKey: Buffer.from(keys.publicKey).toString("base64"),
    signature: Buffer.from(ml_dsa65.sign(keys.secretKey, Buffer.from(digest, "hex"))).toString("base64"),
    encoding: "base64",
    createdAt: "2026-10-05T12:00:00.000Z",
    anchor,
  };
  return { header, certificate, countersignatures: [] };
}

const NO_ANCHOR = { type: "direct", network: "mock", txid: null, vout: 0, blockHeight: null, blockTime: null };

function page(attestation, report) {
  return renderVerifyPage({ id: attestation.certificate.payloadHash, report, header: attestation.header, certificate: attestation.certificate });
}
const headline = (html) => /<div class="big">([^<]*)</.exec(html)[1];

test("a signed record that claims no anchor is verified, and shows no block or time", async () => {
  const a = signed(NO_ANCHOR);
  const report = await verifyAttestation(a, { checkChain: true });
  assert.equal(report.verdict, "verified");
  assert.equal(report.ok, true);
  assert.equal(report.anchor.state, "none");
  assert.equal(report.evidence.name, "Locally Verified");
  const html = page(a, report);
  assert.equal(headline(html), "Verified");
  assert.match(html, /has not been anchored to a public chain/);
  assert.match(html, /carries no public timestamp/);
});

test("calling an invented anchor 'mock' does not switch the chain check off", async () => {
  const a = signed({ type: "direct", network: "mock", txid: FAKE_TXID, vout: 0, blockHeight: 620000, blockTime: Y2020 });
  const report = await verifyAttestation(a, { checkChain: true });
  assert.notEqual(report.verdict, "verified");
  assert.equal(report.ok, false);
  assert.notEqual(report.checks.onChain, true);
  assert.equal(report.evidence.level, 0, "an unverified block height reaches no level");
  const html = page(a, report);
  assert.notEqual(headline(html), "Verified");
  assert.doesNotMatch(html, /2020/, "the invented date is not printed");
  assert.doesNotMatch(html, /620000/, "the invented block is not printed");
});

test("dropping the block height does not make an invented anchor pass", async () => {
  const a = signed({ type: "direct", network: "bsv-mainnet", txid: FAKE_TXID, vout: 0, blockHeight: null, blockTime: Y2020 });
  const report = await verifyAttestation(a, { checkChain: true });
  assert.equal(report.verdict, "incomplete");
  assert.equal(report.ok, false);
  assert.equal(report.checks.onChain, null);
  assert.equal(report.anchor.state, "unconfirmed");
  assert.equal(report.evidence.name, "Anchor Pending");
  const html = page(a, report);
  assert.equal(headline(html), "Incomplete — not verified");
  assert.doesNotMatch(html, /2020/);
  assert.match(html, /Claimed transaction/);
  assert.match(html, /not verified/);
});

test("a claimed anchor is incomplete when the chain check is not requested", async () => {
  const a = signed({ type: "direct", network: "bsv-mainnet", txid: FAKE_TXID, vout: 0, blockHeight: 620000, blockTime: Y2020 });
  const report = await verifyAttestation(a);
  assert.equal(report.verdict, "incomplete");
  assert.match(report.incomplete.join(" "), /not requested/);
});

test("a chain check that could not run is incomplete, never a pass and never a failure", async () => {
  const a = signed({ type: "direct", network: "bsv-mainnet", txid: FAKE_TXID, vout: 0, blockHeight: 620000, blockTime: Y2020 });
  const report = await verifyAttestation(a, {
    checkChain: true,
    verifyChain: async () => ({ ok: null, reason: "header source did not answer" }),
  });
  assert.equal(report.verdict, "incomplete");
  assert.deepEqual(report.reasons, []);
  assert.match(report.incomplete.join(" "), /header source did not answer/);
});

test("a failed chain check fails the record and prints nothing the certificate claimed", async () => {
  const a = signed({ type: "direct", network: "bsv-mainnet", txid: FAKE_TXID, vout: 0, blockHeight: 620000, blockTime: Y2020 });
  const report = await verifyAttestation(a, {
    checkChain: true,
    verifyChain: async () => ({ ok: false, reason: "raw tx does not hash to the anchor txid" }),
  });
  assert.equal(report.verdict, "failed");
  assert.equal(report.anchor.state, "failed");
  assert.equal(report.evidence.name, "Unverified");
  const html = page(a, report);
  assert.equal(headline(html), "Not verified");
  assert.doesNotMatch(html, /2020/, "a date beside a refusal is still a date");
  assert.doesNotMatch(html, /620000/);
  assert.doesNotMatch(html, new RegExp(FAKE_TXID));
  assert.doesNotMatch(html, /Established/);
});

test("a confirmed anchor shows the chain's block and time, not the certificate's", async () => {
  const a = signed({ type: "direct", network: "bsv-mainnet", txid: FAKE_TXID, vout: 0, blockHeight: 620000, blockTime: Y2020 });
  const report = await verifyAttestation(a, {
    checkChain: true,
    verifyChain: async () => ({ ok: true, blockHeight: 954784, blockTime: 1782209816 }),
  });
  assert.equal(report.verdict, "verified");
  assert.equal(report.evidence.level, 1);
  assert.equal(report.anchor.state, "confirmed");
  assert.equal(report.anchor.blockHeight, 954784);
  assert.equal(report.anchor.blockTime, 1782209816);
  assert.equal(report.anchor.claimed.blockTime, Y2020, "the claim is kept, labelled as a claim");
  const html = page(a, report);
  assert.equal(headline(html), "Verified");
  assert.match(html, /954784/);
  assert.doesNotMatch(html, /620000/);
  assert.doesNotMatch(html, /Jan 2020/);
});

test("a signature that could not be checked is incomplete, not verified", async () => {
  const a = signed(NO_ANCHOR);
  a.certificate.algorithm = "SOME-FUTURE-SCHEME";
  const report = await verifyAttestation(a, { checkChain: true });
  assert.equal(report.checks.signature, null);
  assert.equal(report.verdict, "incomplete");
});

test("a false check fails the record even if it filed no reason", async () => {
  const a = signed(NO_ANCHOR);
  a.certificate.signature = a.certificate.signature.replace(/^.{4}/, "AAAA");
  const report = await verifyAttestation(a, { checkChain: true });
  assert.equal(report.checks.signature, false);
  assert.equal(report.verdict, "failed");
});

/* ------------------------------------------------------------------------- *
 * The certificate tamper set.
 *
 * Cases T00–T26 are by the notaryhash2026 session: single-field tampers of one
 * real NotaryHash batch certificate (BSV mainnet block 954784), with seven
 * pinned mainnet headers so the set runs with no network. The SPV cases trace
 * back to the 36-case suite written by the smart-git session. They are kept
 * here because this package delegates its chain check to that SDK: on SDK
 * 1.0.0, ten of these tampers were accepted.
 * ------------------------------------------------------------------------- */

const set = JSON.parse(fs.readFileSync(new URL("./fixtures/notaryhash-tamper-cases.json", import.meta.url), "utf8"));
const hex = (u) => Buffer.from(u).toString("hex");
const headerOf = (b) => ({ hash: b.hash, merkleRoot: b.merkleroot, height: b.height, time: b.time, raw: hex(sdk.headerFromFields(b)) });

/** Serves the pinned headers. `mutate` lets a test make the source lie. */
function pinnedHeaders(mutate = (h) => h) {
  const byHash = new Map(set.blocks.map((b) => [b.hash, b]));
  const byHeight = new Map(set.blocks.map((b) => [b.height, b]));
  return {
    async getHeader(hash) { const b = byHash.get(hash); return b ? mutate(headerOf(b)) : null; },
    async getHeaderAtHeight(h) { const b = byHeight.get(h); return b ? mutate(headerOf(b)) : null; },
    async tipHeight() { return Math.max(...byHeight.keys()); },
  };
}

for (const c of set.cases) {
  const expected = c.notaryhash.verdict === "accept";
  test(`tamper ${c.id} (${c.change}) is ${expected ? "accepted" : "refused"}`, async () => {
    const r = await verifyOnChain(c.certificate, { headerProvider: pinnedHeaders() });
    assert.equal(r.ok, expected, r.reason);
  });
}

const control = set.cases[0].certificate;

test("the verified block time comes from the header bytes, whatever a source reports", async () => {
  const TEN_YEARS = 315360000;
  const liar = pinnedHeaders((h) => ({ ...h, time: h.time + TEN_YEARS }));
  const r = await verifyOnChain(control, { headerProvider: new sdk.MultiSourceHeaderProvider([liar, pinnedHeaders()]) });
  assert.equal(r.ok, true);
  assert.equal(r.blockTime, set.blocks[0].time);
  assert.equal(r.blockHeight, set.blocks[0].height);
});

test("a single source with no header bytes is 'could not tell'", async () => {
  const bare = pinnedHeaders((h) => ({ ...h, raw: undefined }));
  const r = await verifyOnChain(control, { headerProvider: bare });
  assert.equal(r.ok, null);
});

test("a certificate relabelled to another network is refused", async () => {
  const relabelled = structuredClone(control);
  relabelled.anchor.network = "bsv-testnet";
  const r = await verifyOnChain(relabelled, { headerProvider: pinnedHeaders() });
  assert.equal(r.ok, false);
  assert.match(r.reason, /bsv-testnet/);
});

test("the transaction id shown as verified is the one the proof is for", async () => {
  const renamed = structuredClone(control);
  renamed.anchor.txid = "cd".repeat(32);
  const r = await verifyOnChain(renamed, { headerProvider: pinnedHeaders() });
  assert.equal(r.ok, false);
});

test("a proof with its anchor fields stripped is still checked", async () => {
  const a = signed(undefined);
  a.certificate.spv = control.spv;
  const report = await verifyAttestation(a, { checkChain: true });
  assert.notEqual(report.anchor.state, "none");
  assert.notEqual(report.verdict, "verified");
});

test("'*' cannot stand in for the sibling of a right-hand node", async () => {
  const starred = structuredClone(control);
  assert.equal(starred.spv.merkleProof.index % 2, 1, "the fixture's index is odd");
  starred.spv.merkleProof.nodes[0] = "*";
  const r = await verifyOnChain(starred, { headerProvider: pinnedHeaders() });
  assert.equal(r.ok, false);
});

test("a certificate with no proof in it yet is 'could not tell'", async () => {
  const unproven = structuredClone(control);
  delete unproven.spv;
  const r = await verifyOnChain(unproven, { headerProvider: pinnedHeaders() });
  assert.equal(r.ok, null);
});

import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import {
  verifyStripeSignature,
  signPayloadForTest,
  parseSignatureHeader,
} from "../service/stripe-signature.mjs";
import { KeyStore, hashKey, generateApiKey } from "../service/keystore.mjs";
import { handleEvent } from "../service/billing-events.mjs";

const SECRET = "whsec_test_abc123";

/* ------------------------- signature verification ------------------------- */

test("a correctly signed payload verifies", () => {
  const body = JSON.stringify({ id: "evt_1", type: "invoice.paid" });
  const r = verifyStripeSignature(body, signPayloadForTest(body, SECRET), SECRET);
  assert.equal(r.ok, true);
  assert.equal(r.event.id, "evt_1");
});

test("a forged body is rejected", () => {
  const real = JSON.stringify({ id: "evt_1", amount: 500 });
  const header = signPayloadForTest(real, SECRET);
  const forged = JSON.stringify({ id: "evt_1", amount: 999999 });
  assert.equal(verifyStripeSignature(forged, header, SECRET).ok, false);
});

test("the wrong secret is rejected", () => {
  const body = JSON.stringify({ id: "evt_1" });
  const r = verifyStripeSignature(body, signPayloadForTest(body, SECRET), "whsec_wrong");
  assert.equal(r.ok, false);
  assert.match(r.reason, /mismatch/);
});

test("an unsigned request is rejected", () => {
  const body = JSON.stringify({ id: "evt_1" });
  assert.equal(verifyStripeSignature(body, "", SECRET).ok, false);
  assert.equal(verifyStripeSignature(body, undefined, SECRET).ok, false);
  assert.match(verifyStripeSignature(body, "t=123", SECRET).reason, /no v1 signature/);
});

test("a replayed old request is rejected", () => {
  const body = JSON.stringify({ id: "evt_1" });
  const old = Math.floor(Date.now() / 1000) - 3600;
  const r = verifyStripeSignature(body, signPayloadForTest(body, SECRET, old), SECRET);
  assert.equal(r.ok, false);
  assert.match(r.reason, /too old/);
});

test("a future-dated request is rejected", () => {
  const body = JSON.stringify({ id: "evt_1" });
  const future = Math.floor(Date.now() / 1000) + 3600;
  const r = verifyStripeSignature(body, signPayloadForTest(body, SECRET, future), SECRET);
  assert.equal(r.ok, false);
  assert.match(r.reason, /future/);
});

test("re-serializing the body breaks the signature (raw bytes matter)", () => {
  // Stripe sends pretty-printed JSON. Parsing and re-stringifying it — which a
  // framework's body parser does by default — changes the bytes and the
  // signature no longer matches. The raw body must reach the verifier intact.
  const body = '{\n  "id": "evt_1",\n  "type": "invoice.paid"\n}';
  const header = signPayloadForTest(body, SECRET);
  assert.equal(verifyStripeSignature(body, header, SECRET).ok, true, "raw body verifies");

  const reserialized = JSON.stringify(JSON.parse(body));
  assert.notEqual(reserialized, body, "re-serialization must actually differ");
  assert.equal(verifyStripeSignature(reserialized, header, SECRET).ok, false);
});

test("multiple v1 signatures verify if any one matches (secret rotation)", () => {
  const body = JSON.stringify({ id: "evt_1" });
  const t = Math.floor(Date.now() / 1000);
  const good = createHmac("sha256", SECRET).update(`${t}.${body}`).digest("hex");
  const header = `t=${t},v1=${"0".repeat(64)},v1=${good}`;
  assert.equal(verifyStripeSignature(body, header, SECRET).ok, true);
});

test("no configured secret means no verification passes", () => {
  const body = JSON.stringify({ id: "evt_1" });
  const r = verifyStripeSignature(body, signPayloadForTest(body, SECRET), "");
  assert.equal(r.ok, false);
  assert.match(r.reason, /no webhook secret/);
});

test("signature header parsing tolerates junk", () => {
  const p = parseSignatureHeader("t=123,v1=abc,v0=zzz,garbage");
  assert.equal(p.timestamp, 123);
  assert.deepEqual(p.signatures, ["abc"]);
});

/* ------------------------------- key store -------------------------------- */

const HOUR = 3600;
const nowSec = () => Math.floor(Date.now() / 1000);

test("issued keys are stored hashed, never in plaintext", async () => {
  const store = new KeyStore();
  const { plaintext, record } = await store.issue({
    customerId: "cus_1", subscriptionId: "sub_1", tier: "creator", periodEnd: nowSec() + 30 * 24 * HOUR,
  });
  assert.match(plaintext, /^pop_[0-9a-f]{48}$/);
  assert.equal(record.keyHash, hashKey(plaintext));
  const dump = JSON.stringify([...store.memory.entries()]);
  assert.ok(!dump.includes(plaintext), "plaintext key must not appear anywhere in the store");
});

test("a valid key authorizes; an unknown one does not", async () => {
  const store = new KeyStore();
  const { plaintext } = await store.issue({ customerId: "cus_1", tier: "creator", periodEnd: nowSec() + HOUR });
  assert.equal((await store.authorize(plaintext)).ok, true);
  assert.equal((await store.authorize(generateApiKey())).ok, false);
  assert.equal((await store.authorize("")).ok, false);
  assert.equal((await store.authorize(null)).ok, false);
});

test("expiry is enforced independently of status", async () => {
  const store = new KeyStore();
  const { plaintext, record } = await store.issue({ customerId: "cus_1", tier: "creator", periodEnd: nowSec() });
  record.accessExpiresAt = new Date(Date.now() - 1000).toISOString();
  record.status = "active"; // stale status must not rescue an expired key
  await store.put(record);
  const r = await store.authorize(plaintext);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "expired");
});

test("revocation blocks a key that has not expired", async () => {
  const store = new KeyStore();
  const { plaintext } = await store.issue({ customerId: "cus_1", tier: "creator", periodEnd: nowSec() + 30 * 24 * HOUR });
  await store.revoke("cus_1", "canceled");
  const r = await store.authorize(plaintext);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "revoked");
});

test("renewal extends expiry and restores an active status", async () => {
  const store = new KeyStore();
  const { plaintext } = await store.issue({ customerId: "cus_1", tier: "creator", periodEnd: nowSec() });
  await store.suspend("cus_1");
  await store.renew("cus_1", { periodEnd: nowSec() + 30 * 24 * HOUR });
  const r = await store.authorize(plaintext);
  assert.equal(r.ok, true);
  assert.equal(r.record.status, "active");
});

/* ---------------------------- event handling ------------------------------ */

function harness({ status = "active", price = "price_creator" } = {}) {
  const store = new KeyStore();
  const seenIds = new Set();
  const seen = { has: async (id) => seenIds.has(id), add: async (id) => seenIds.add(id) };
  const sub = {
    id: "sub_1", status, customer: "cus_1",
    current_period_end: nowSec() + 30 * 24 * HOUR,
    items: { data: [{ price: { id: price } }] },
  };
  const stripe = { getSubscription: async () => sub };
  const tierForPrice = (p) => (p === "price_pro" ? "pro" : "creator");
  return { store, deps: { store, stripe, tierForPrice, seen }, sub };
}

const evt = (type, object, id = "evt_" + Math.random()) => ({ id, type, data: { object } });

test("checkout completion provisions exactly once", async () => {
  const { store, deps } = harness();
  const e = evt("checkout.session.completed", { mode: "subscription", customer: "cus_1", subscription: "sub_1" }, "evt_a");
  const r1 = await handleEvent(e, deps);
  assert.equal(r1.action, "provisioned");
  const claimed = await store.claim("cus_1");
  assert.equal((await store.authorize(claimed.plaintext)).ok, true);

  // Redelivery of the same event must not mint a second key.
  const r2 = await handleEvent(e, deps);
  assert.equal(r2.action, "duplicate");
});

test("a distinct redelivery for an existing customer does not mint a second key", async () => {
  const { deps } = harness();
  const obj = { mode: "subscription", customer: "cus_1", subscription: "sub_1" };
  await handleEvent(evt("checkout.session.completed", obj, "evt_a"), deps);
  const r = await handleEvent(evt("checkout.session.completed", obj, "evt_b"), deps);
  assert.equal(r.action, "already_provisioned");
  assert.equal(r.apiKey, undefined);
});

test("one-time checkout sessions are ignored", async () => {
  const { deps } = harness();
  const r = await handleEvent(evt("checkout.session.completed", { mode: "payment", customer: "cus_1" }), deps);
  assert.equal(r.action, "ignored");
});

test("cancellation revokes access", async () => {
  const { store, deps } = harness();
  await handleEvent(evt("checkout.session.completed", { mode: "subscription", customer: "cus_1", subscription: "sub_1" }), deps);
  const claimed = await store.claim("cus_1");
  await handleEvent(evt("customer.subscription.deleted", { id: "sub_1", customer: "cus_1" }), deps);
  assert.equal((await store.authorize(claimed.plaintext)).reason, "revoked");
});

test("payment failure suspends but does not revoke", async () => {
  const { store, deps } = harness();
  const p = await handleEvent(evt("checkout.session.completed", { mode: "subscription", customer: "cus_1", subscription: "sub_1" }), deps);
  const r = await handleEvent(evt("invoice.payment_failed", { customer: "cus_1", attempt_count: 1 }), deps);
  assert.equal(r.action, "suspended");
  const rec = await store.getByCustomer("cus_1");
  assert.equal(rec.status, "past_due");
  assert.notEqual(rec.status, "revoked", "one failed payment must not cut off a paying customer");
});

test("unpaid and canceled statuses revoke, past_due does not", async () => {
  for (const status of ["unpaid", "canceled", "incomplete_expired"]) {
    const { store, deps } = harness({ status });
    await store.issue({ customerId: "cus_1", tier: "creator", periodEnd: nowSec() + HOUR });
    const r = await handleEvent(evt("customer.subscription.updated", { id: "sub_1", customer: "cus_1" }), deps);
    assert.equal(r.action, "revoked", `${status} should revoke`);
  }
  const { deps } = harness({ status: "past_due" });
  const r = await handleEvent(evt("customer.subscription.updated", { id: "sub_1", customer: "cus_1" }), deps);
  assert.equal(r.action, "suspended");
});

test("entitlement follows the re-fetched subscription, not the stale payload", async () => {
  const { store, deps } = harness({ status: "canceled" });
  await store.issue({ customerId: "cus_1", tier: "creator", periodEnd: nowSec() + 30 * 24 * HOUR });
  // Payload claims active; Stripe says canceled. The fetch must win.
  const r = await handleEvent(evt("customer.subscription.updated", { id: "sub_1", customer: "cus_1", status: "active" }), deps);
  assert.equal(r.action, "revoked");
});

test("a subscription that becomes active without checkout is still provisioned", async () => {
  const { store, deps } = harness();
  const r = await handleEvent(evt("customer.subscription.created", { id: "sub_1", customer: "cus_1" }), deps);
  assert.equal(r.action, "provisioned");
  const claimed = await store.claim("cus_1");
  assert.equal((await store.authorize(claimed.plaintext)).ok, true);
});

test("invoice.paid extends an existing entitlement", async () => {
  const { store, deps } = harness();
  await handleEvent(evt("checkout.session.completed", { mode: "subscription", customer: "cus_1", subscription: "sub_1" }), deps);
  const p = { apiKey: (await store.claim("cus_1")).plaintext };
  const before = (await store.getByCustomer("cus_1")).accessExpiresAt;
  const rec = await store.getByCustomer("cus_1");
  rec.accessExpiresAt = new Date(Date.now() + 1000).toISOString();
  await store.put(rec);
  const r = await handleEvent(evt("invoice.paid", { customer: "cus_1", subscription: "sub_1" }), deps);
  assert.equal(r.action, "renewed");
  assert.equal((await store.getByCustomer("cus_1")).accessExpiresAt, before);
  assert.equal((await store.authorize(p.apiKey)).ok, true);
});

test("tier is derived from the price", async () => {
  const { store, deps } = harness({ price: "price_pro" });
  await handleEvent(evt("checkout.session.completed", { mode: "subscription", customer: "cus_1", subscription: "sub_1" }), deps);
  assert.equal((await store.getByCustomer("cus_1")).tier, "pro");
});

test("unrelated events are reported, not acted on", async () => {
  const { deps } = harness();
  const r = await handleEvent(evt("charge.refunded", { id: "ch_1" }), deps);
  assert.equal(r.action, "unhandled");
});

/* --------------------------- claim and rotation --------------------------- */

test("provisioning creates an entitlement with no key yet", async () => {
  const store = new KeyStore();
  const rec = await store.provision({ customerId: "cus_1", tier: "creator", periodEnd: nowSec() + 30 * 24 * HOUR });
  assert.equal(rec.keyHash, null);
  assert.equal(rec.claimedAt, null);
  assert.equal(rec.status, "active");
  assert.equal((await store.getByCustomer("cus_1")).customerId, "cus_1");
});

test("claiming mints a key exactly once", async () => {
  const store = new KeyStore();
  await store.provision({ customerId: "cus_1", tier: "creator", periodEnd: nowSec() + 30 * 24 * HOUR });

  const first = await store.claim("cus_1");
  assert.equal(first.ok, true);
  assert.match(first.plaintext, /^pop_[0-9a-f]{48}$/);
  assert.equal((await store.authorize(first.plaintext)).ok, true);

  const second = await store.claim("cus_1");
  assert.equal(second.ok, false);
  assert.equal(second.reason, "already claimed");
  assert.equal(second.plaintext, undefined, "a key must never be returned twice");
});

test("claiming is refused without an entitlement, or after revocation", async () => {
  const store = new KeyStore();
  assert.equal((await store.claim("cus_nobody")).ok, false);
  await store.provision({ customerId: "cus_1", tier: "creator", periodEnd: nowSec() + HOUR });
  await store.revoke("cus_1");
  const r = await store.claim("cus_1");
  assert.equal(r.ok, false);
  assert.equal(r.reason, "entitlement revoked");
});

test("rotation issues a new key and kills the old one immediately", async () => {
  const store = new KeyStore();
  const { plaintext: original } = await store.issue({ customerId: "cus_1", tier: "creator", periodEnd: nowSec() + 30 * 24 * HOUR });
  assert.equal((await store.authorize(original)).ok, true);

  const rotated = await store.rotate("cus_1");
  assert.equal(rotated.ok, true);
  assert.notEqual(rotated.plaintext, original);
  assert.equal((await store.authorize(rotated.plaintext)).ok, true);
  assert.equal((await store.authorize(original)).ok, false, "the old key must stop working at once");
});

test("an unclaimed entitlement authorizes nothing", async () => {
  const store = new KeyStore();
  await store.provision({ customerId: "cus_1", tier: "creator", periodEnd: nowSec() + 30 * 24 * HOUR });
  assert.equal((await store.authorize(generateApiKey())).ok, false);
});

test("the webhook records entitlement without minting a key", async () => {
  const { store, deps } = harness();
  const r = await handleEvent(evt("checkout.session.completed", { mode: "subscription", customer: "cus_1", subscription: "sub_1" }), deps);
  assert.equal(r.action, "provisioned");
  assert.equal(r.apiKey, undefined, "a webhook has nobody to hand a key to");
  const rec = await store.getByCustomer("cus_1");
  assert.equal(rec.keyHash, null);
  // The customer claims it afterwards.
  const claimed = await store.claim("cus_1");
  assert.equal(claimed.ok, true);
  assert.equal((await store.authorize(claimed.plaintext)).ok, true);
});

test("revocation after claiming blocks the issued key", async () => {
  const { store, deps } = harness();
  await handleEvent(evt("checkout.session.completed", { mode: "subscription", customer: "cus_1", subscription: "sub_1" }), deps);
  const claimed = await store.claim("cus_1");
  await handleEvent(evt("customer.subscription.deleted", { id: "sub_1", customer: "cus_1" }), deps);
  assert.equal((await store.authorize(claimed.plaintext)).reason, "revoked");
});

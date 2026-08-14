import test from "node:test";
import assert from "node:assert/strict";
import { KeyStore } from "../service/keystore.mjs";
import { reconcile } from "../service/reconcile.mjs";

const HOUR = 3600;
const nowSec = () => Math.floor(Date.now() / 1000);

function sub(id, customer, status, { price = "price_creator", periodEnd = nowSec() + 30 * 24 * HOUR } = {}) {
  return {
    id, customer, status, current_period_end: periodEnd,
    items: { data: [{ price: { id: price, lookup_key: price } }] },
  };
}

function deps(subs, store = new KeyStore()) {
  const pages = Array.isArray(subs[0]) ? subs : [subs];
  let call = 0;
  const stripe = {
    listSubscriptions: async () => {
      const data = pages[call] ?? [];
      const has_more = call < pages.length - 1;
      call++;
      return { data, has_more };
    },
  };
  return { store, deps: { store, stripe, tierForPrice: (p) => (p?.lookupKey === "price_pro" ? "pro" : "creator") } };
}

test("an active subscription with no entitlement gets provisioned", async () => {
  const { store, deps: d } = deps([sub("sub_1", "cus_1", "active")]);
  const s = await reconcile(d);
  assert.equal(s.provisioned, 1);
  const rec = await store.getByCustomer("cus_1");
  assert.equal(rec.status, "active");
  assert.equal(rec.tier, "creator");
  assert.equal(rec.keyHash, null, "still unclaimed until the customer collects it");
});

test("this is what saves a customer when webhooks never arrive", async () => {
  // The exact failure being defended against: payment succeeded, Stripe knows,
  // our webhook endpoint heard nothing.
  const { store, deps: d } = deps([sub("sub_1", "cus_paid", "active")]);
  assert.equal(await store.getByCustomer("cus_paid"), null);
  await reconcile(d);
  const rec = await store.getByCustomer("cus_paid");
  assert.ok(rec, "the paying customer must end up entitled regardless of webhooks");
  const claimed = await store.claim("cus_paid");
  assert.equal((await store.authorize(claimed.plaintext)).ok, true);
});

test("a subscription created outside Checkout is provisioned too", async () => {
  // No checkout session exists for these, so provisioning is the only route.
  const { store, deps: d } = deps([sub("sub_dash", "cus_dash", "trialing")]);
  await reconcile(d);
  assert.ok(await store.getByCustomer("cus_dash"));
});

test("an ended subscription revokes its entitlement", async () => {
  const store = new KeyStore();
  await store.provision({ customerId: "cus_1", subscriptionId: "sub_1", tier: "creator", periodEnd: nowSec() + HOUR });
  const { deps: d } = deps([sub("sub_1", "cus_1", "canceled")], store);
  const s = await reconcile(d);
  assert.equal(s.revoked, 1);
  assert.equal((await store.getByCustomer("cus_1")).status, "revoked");
});

test("an old dead subscription does not revoke a newer active one", async () => {
  const store = new KeyStore();
  // The customer resubscribed; their entitlement belongs to sub_2.
  await store.provision({ customerId: "cus_1", subscriptionId: "sub_2", tier: "creator", periodEnd: nowSec() + 30 * 24 * HOUR });
  const { deps: d } = deps([sub("sub_1", "cus_1", "canceled")], store);
  const s = await reconcile(d);
  assert.equal(s.revoked, 0, "the dead subscription is not the one that granted this entitlement");
  assert.equal((await store.getByCustomer("cus_1")).status, "active");
});

test("past_due keeps access; unpaid and canceled do not", async () => {
  for (const [status, expectRevoked] of [["past_due", 0], ["unpaid", 1], ["canceled", 1], ["incomplete_expired", 1]]) {
    const store = new KeyStore();
    await store.provision({ customerId: "c", subscriptionId: "s", tier: "creator", periodEnd: nowSec() + HOUR });
    const { deps: d } = deps([sub("s", "c", status)], store);
    const r = await reconcile(d);
    assert.equal(r.revoked, expectRevoked, `${status} should ${expectRevoked ? "" : "not "}revoke`);
  }
});

test("a reactivated subscription restores a revoked entitlement", async () => {
  const store = new KeyStore();
  await store.provision({ customerId: "cus_1", subscriptionId: "sub_1", tier: "creator", periodEnd: nowSec() + HOUR });
  await store.revoke("cus_1", "canceled");
  const { deps: d } = deps([sub("sub_1", "cus_1", "active")], store);
  const s = await reconcile(d);
  assert.equal(s.renewed, 1);
  assert.equal((await store.getByCustomer("cus_1")).status, "active");
});

test("a suspended entitlement recovers once payment succeeds", async () => {
  const store = new KeyStore();
  await store.provision({ customerId: "cus_1", subscriptionId: "sub_1", tier: "creator", periodEnd: nowSec() + 30 * 24 * HOUR });
  await store.suspend("cus_1", "payment_failed");
  const { deps: d } = deps([sub("sub_1", "cus_1", "active")], store);
  await reconcile(d);
  assert.equal((await store.getByCustomer("cus_1")).status, "active");
});

test("reconciliation is idempotent", async () => {
  const { store, deps: d } = deps([[sub("sub_1", "cus_1", "active")], [sub("sub_1", "cus_1", "active")]]);
  const first = await reconcile(d);
  assert.equal(first.provisioned, 1);
  const { deps: d2 } = deps([sub("sub_1", "cus_1", "active")], store);
  const second = await reconcile(d2);
  assert.equal(second.provisioned, 0, "a second pass must not re-provision");
  assert.equal(second.revoked, 0);
});

test("claimed keys survive reconciliation", async () => {
  const store = new KeyStore();
  await store.provision({ customerId: "cus_1", subscriptionId: "sub_1", tier: "creator", periodEnd: nowSec() + 30 * 24 * HOUR });
  const claimed = await store.claim("cus_1");
  const { deps: d } = deps([sub("sub_1", "cus_1", "active")], store);
  await reconcile(d);
  assert.equal((await store.authorize(claimed.plaintext)).ok, true, "reconciliation must not invalidate a working key");
});

test("pagination walks every page", async () => {
  const { store, deps: d } = deps([
    [sub("s1", "c1", "active"), sub("s2", "c2", "active")],
    [sub("s3", "c3", "active")],
  ]);
  const s = await reconcile(d);
  assert.equal(s.scanned, 3);
  assert.equal(s.provisioned, 3);
  assert.ok(await store.getByCustomer("c3"));
});

test("a Stripe outage is reported, not silently swallowed", async () => {
  const store = new KeyStore();
  const d = {
    store,
    tierForPrice: () => "creator",
    stripe: { listSubscriptions: async () => { throw new Error("stripe unreachable"); } },
  };
  const s = await reconcile(d);
  assert.equal(s.errors, 1);
  assert.equal(s.provisioned, 0);
});

test("one broken subscription does not stop the rest", async () => {
  const store = new KeyStore();
  const bad = { id: "s_bad", status: "active" }; // no customer
  const { deps: d } = deps([[bad, sub("s_ok", "c_ok", "active")]], store);
  const s = await reconcile(d);
  assert.equal(s.provisioned, 1);
  assert.ok(await store.getByCustomer("c_ok"));
});

test("tier changes propagate", async () => {
  const store = new KeyStore();
  await store.provision({ customerId: "cus_1", subscriptionId: "sub_1", tier: "creator", periodEnd: nowSec() + HOUR });
  const { deps: d } = deps([sub("sub_1", "cus_1", "active", { price: "price_pro" })], store);
  await reconcile(d);
  assert.equal((await store.getByCustomer("cus_1")).tier, "pro");
});

/* ---- cross-product isolation ----
 * This Stripe account hosts several unrelated businesses. Treating another
 * product's customer as ours would hand them a working key for free.
 */

// A realistic tier resolver: only prices we know, by lookup key.
const realTier = (p) => ({ pop_creator_monthly: "creator", pop_pro_monthly: "pro" }[p?.lookupKey] ?? null);

function priced(id, customer, status, lookupKey) {
  return {
    id, customer, status,
    current_period_end: nowSec() + 30 * 24 * HOUR,
    items: { data: [{ price: { id: "price_" + id, lookup_key: lookupKey, product: "prod_x" } }] },
  };
}

test("another product's active subscription is never provisioned", async () => {
  const store = new KeyStore();
  const stripe = { listSubscriptions: async () => ({ data: [priced("s1", "cus_valueproof", "active", null)], has_more: false }) };
  const s = await reconcile({ store, stripe, tierForPrice: realTier });
  assert.equal(s.provisioned, 0, "a foreign customer must not receive our product");
  assert.equal(await store.getByCustomer("cus_valueproof"), null);
});

test("our own subscription is still provisioned alongside foreign ones", async () => {
  const store = new KeyStore();
  const stripe = {
    listSubscriptions: async () => ({
      data: [
        priced("s1", "cus_other", "active", null),
        priced("s2", "cus_ours", "active", "pop_creator_monthly"),
      ],
      has_more: false,
    }),
  };
  const s = await reconcile({ store, stripe, tierForPrice: realTier });
  assert.equal(s.provisioned, 1);
  assert.ok(await store.getByCustomer("cus_ours"));
  assert.equal(await store.getByCustomer("cus_other"), null);
});

test("another product's cancellation never revokes our entitlement", async () => {
  const store = new KeyStore();
  await store.provision({ customerId: "cus_both", subscriptionId: "sub_ours", tier: "creator", periodEnd: nowSec() + 30 * 24 * HOUR });
  const stripe = { listSubscriptions: async () => ({ data: [priced("s_theirs", "cus_both", "canceled", null)], has_more: false }) };
  const s = await reconcile({ store, stripe, tierForPrice: realTier });
  assert.equal(s.revoked, 0);
  assert.equal((await store.getByCustomer("cus_both")).status, "active");
});

test("tier resolves by lookup key, which is stable across test and live", async () => {
  const store = new KeyStore();
  const stripe = { listSubscriptions: async () => ({ data: [priced("s1", "c1", "active", "pop_pro_monthly")], has_more: false }) };
  await reconcile({ store, stripe, tierForPrice: realTier });
  assert.equal((await store.getByCustomer("c1")).tier, "pro");
});

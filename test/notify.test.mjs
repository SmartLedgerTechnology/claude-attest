import test from "node:test";
import assert from "node:assert/strict";
import { Notifier, events } from "../service/notify.mjs";

/** A Notifier whose network layer is replaced, so tests send nothing. */
function stub({ chatId = "123", token = "t", fail = false } = {}) {
  const sent = [];
  const n = new Notifier({ token, chatId, log: () => {} });
  n._sent = sent;
  // Replace the private post step by overriding send's transport via fetch.
  globalThis.fetch = async (url, opts) => {
    sent.push(JSON.parse(opts.body));
    if (fail) throw new Error("network down");
    return { json: async () => ({ ok: true }) };
  };
  return { n, sent };
}

const realFetch = globalThis.fetch;
test.after(() => { globalThis.fetch = realFetch; });

test("sends when configured", async () => {
  const { n, sent } = stub();
  await n.send("signup", "hello");
  assert.equal(sent.length, 1);
  assert.equal(sent[0].text, "hello");
  assert.equal(sent[0].chat_id, "123");
});

test("stays silent when not configured", async () => {
  const { sent } = stub();
  const off = new Notifier({ token: null, chatId: null, log: () => {} });
  assert.equal(off.enabled, false);
  const r = await off.send("signup", "hello");
  assert.equal(r.reason, "disabled");
  assert.equal(sent.length, 0);
});

test("a missing chat id disables it (a token alone cannot deliver)", () => {
  assert.equal(new Notifier({ token: "t", chatId: null }).enabled, false);
  assert.equal(new Notifier({ token: null, chatId: "1" }).enabled, false);
});

test("identical alerts are collapsed", async () => {
  const { n, sent } = stub();
  await n.send("signup", "same");
  await n.send("signup", "same");
  await n.send("signup", "same");
  assert.equal(sent.length, 1, "a repeated alert must not repeat");
});

test("different alerts still get through", async () => {
  const { n, sent } = stub();
  await n.send("signup", "one");
  await n.send("signup", "two");
  assert.equal(sent.length, 2);
});

test("a runaway loop is rate limited rather than sending thousands", async () => {
  const { n, sent } = stub();
  for (let i = 0; i < 60; i++) await n.send("bug", `distinct ${i}`);
  // 20 real messages plus one "going quiet" notice.
  assert.ok(sent.length <= 21, `expected <=21, got ${sent.length}`);
  assert.match(sent[sent.length - 1].text, /going quiet|Going quiet/i);
});

test("a network failure never throws", async () => {
  const { n } = stub({ fail: true });
  const r = await n.send("signup", "hello");
  assert.equal(r.ok, false, "failure is reported, not raised");
});

test("messages carry no secrets and no customer PII", () => {
  const all = [
    events.signup({ tier: "creator", customerId: "cus_1", via: "checkout.session.completed" }),
    events.claimed({ customerId: "cus_1", tier: "creator" }),
    events.paymentFailed({ customerId: "cus_1", attempt: 2 }),
    events.canceled({ customerId: "cus_1", reason: "canceled" }),
    events.reconcileProvisioned({ customerId: "cus_1" }),
    events.published({ url: "https://proofofprocess.ai/v/abc" }),
    events.anchorFailed({ sessionId: "s1", error: "timeout" }),
    events.started({ mode: "live", version: "0.3.0" }),
  ].join("\n");
  for (const bad of ["sk_", "rk_", "whsec_", "pop_", "cs_", "privateKey", "@"]) {
    assert.ok(!all.includes(bad), `message text must not contain ${bad}`);
  }
  assert.ok(all.includes("cus_1"), "the Stripe customer id is the identifier we use");
});

test("the reconciler alert explains why it matters", () => {
  const m = events.reconcileProvisioned({ customerId: "cus_1" });
  assert.match(m, /webhook/i, "it must say the webhook did not arrive");
  assert.match(m, /Stripe/, "and point at where to look");
});

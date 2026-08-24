import test from "node:test";
import assert from "node:assert/strict";
import {
  normalizeEmail,
  clientIp,
  makeToken,
  RateLimiter,
  makeWaitlistStore,
  submit,
  confirm,
  unsubscribe,
} from "../service/waitlist.mjs";

const fresh = () => ({
  store: makeWaitlistStore(null),
  limiter: new RateLimiter({ max: 5 }),
  ip: "203.0.113.7",
});

/** Run the whole signup → click flow, the way a real person does it. */
async function signUp(ctx, email, source = "landing") {
  const r = await submit({ email, source }, ctx);
  assert.ok(r.sendConfirmation, `expected a confirmation to be owed for ${email}`);
  return confirm(r.sendConfirmation.token, ctx);
}

/* --------------------------------- addresses ------------------------------- */

test("an ordinary address is accepted and normalized", () => {
  assert.equal(normalizeEmail("  Greg@Example.COM "), "greg@example.com");
});

test("addresses that are certainly not addresses are rejected", () => {
  for (const bad of ["", "notanemail", "a@localhost", "a@b", "no spaces@x.com", "@x.com", "a@@x.com"]) {
    assert.equal(normalizeEmail(bad), null, `expected ${JSON.stringify(bad)} to be rejected`);
  }
});

test("non-strings are rejected rather than coerced", () => {
  for (const bad of [null, undefined, 12345, {}, ["a@b.com"]]) assert.equal(normalizeEmail(bad), null);
});

test("an absurdly long address is rejected before it reaches storage", () => {
  assert.equal(normalizeEmail(`${"a".repeat(300)}@x.com`), null);
});

test("unusual but legal addresses are not rejected", () => {
  // A strict pattern would throw these away, and each one belongs to a real person.
  for (const ok of ["a+tag@x.co.uk", "first.last@sub.domain.org", "x_y-z@example.io"]) {
    assert.equal(normalizeEmail(ok), ok, `expected ${ok} to be accepted`);
  }
});

/* ------------------------------- client address ---------------------------- */

test("the last X-Forwarded-For hop wins, because the proxy appends it", () => {
  assert.equal(clientIp({ "x-forwarded-for": "9.9.9.9, 203.0.113.7" }), "203.0.113.7");
});

test("with no proxy header the socket address is used", () => {
  assert.equal(clientIp({}, "198.51.100.4"), "198.51.100.4");
});

/* ---------------------------------- tokens --------------------------------- */

test("tokens are URL-safe, long, and not repeated", () => {
  const seen = new Set();
  for (let i = 0; i < 500; i++) {
    const t = makeToken();
    assert.match(t, /^[A-Za-z0-9_-]{32,}$/, "must survive a URL without escaping");
    assert.ok(!seen.has(t), "tokens must not collide");
    seen.add(t);
  }
});

/* -------------------------------- rate limit ------------------------------- */

test("a caller gets its budget and no more", () => {
  const l = new RateLimiter({ max: 3 });
  assert.deepEqual([l.allow("a"), l.allow("a"), l.allow("a"), l.allow("a")], [true, true, true, false]);
});

test("one noisy caller does not spend another's budget", () => {
  const l = new RateLimiter({ max: 2 });
  l.allow("a"); l.allow("a");
  assert.equal(l.allow("a"), false);
  assert.equal(l.allow("b"), true, "a second address must be unaffected");
});

test("the budget refills once the window passes", () => {
  let t = 0;
  const l = new RateLimiter({ max: 1, windowMs: 1000, now: () => t });
  assert.equal(l.allow("a"), true);
  assert.equal(l.allow("a"), false);
  t = 1001;
  assert.equal(l.allow("a"), true);
});

test("stale keys are evicted rather than accumulating forever", () => {
  let t = 0;
  const l = new RateLimiter({ max: 1, windowMs: 1000, maxKeys: 10, now: () => t });
  for (let i = 0; i < 12; i++) l.allow(`ip-${i}`);
  t = 5000;
  l.allow("trigger-eviction");
  assert.ok(l.hits.size < 12, `expected eviction, still holding ${l.hits.size} keys`);
});

/* --------------------------------- submit ---------------------------------- */

test("a good address is owed a confirmation and is NOT yet on the list", async () => {
  const ctx = fresh();
  const r = await submit({ email: "greg@example.com", source: "landing" }, ctx);
  assert.equal(r.status, 200);
  assert.equal(r.sendConfirmation.email, "greg@example.com");
  assert.equal(
    await ctx.store.size(),
    0,
    "an unconfirmed address must not count as a subscriber — nobody has proved they own it"
  );
});

test("the honeypot is answered like a success and sends nothing", async () => {
  const ctx = fresh();
  const r = await submit({ email: "bot@example.com", company: "Acme Inc" }, ctx);
  assert.equal(r.status, 200);
  assert.equal(r.sendConfirmation, undefined, "a bot must not cause an email to be sent");
  assert.equal(await ctx.store.size(), 0);
});

test("an empty honeypot is what a real browser sends, and must pass", async () => {
  const ctx = fresh();
  const r = await submit({ email: "greg@example.com", company: "" }, ctx);
  assert.ok(r.sendConfirmation);
});

test("a bad address is refused before it costs anyone their rate budget", async () => {
  const ctx = fresh();
  for (let i = 0; i < 20; i++) await submit({ email: "nope" }, ctx);
  const r = await submit({ email: "greg@example.com" }, ctx);
  assert.ok(r.sendConfirmation, "typos must not lock a person out of the form");
});

test("a flood of distinct valid addresses from one host is capped", async () => {
  const ctx = fresh();
  const codes = [];
  for (let i = 0; i < 7; i++) codes.push((await submit({ email: `x${i}@example.com` }, ctx)).status);
  assert.deepEqual(codes, [200, 200, 200, 200, 200, 429, 429]);
});

test("rotating the forgeable part of X-Forwarded-For does not buy a fresh budget", async () => {
  const store = makeWaitlistStore(null);
  const limiter = new RateLimiter({ max: 2 });
  const codes = [];
  for (let i = 0; i < 4; i++) {
    const ip = clientIp({ "x-forwarded-for": `9.9.9.${i}, 203.0.113.7` });
    codes.push((await submit({ email: `x${i}@example.com` }, { store, limiter, ip })).status);
  }
  assert.deepEqual(codes, [200, 200, 429, 429]);
});

/* ------------------------- not becoming a mail-bomb ------------------------ */

test("one address cannot be mailed twice in a row, even from a fresh source", async () => {
  const store = makeWaitlistStore(null);
  const victim = "victim@example.com";

  const first = await submit({ email: victim }, { store, limiter: new RateLimiter(), ip: "a" });
  assert.ok(first.sendConfirmation, "the first request should send");

  // A new IP with an untouched budget — the per-IP cap offers no protection here.
  const second = await submit({ email: victim }, { store, limiter: new RateLimiter(), ip: "b" });
  assert.equal(second.sendConfirmation, undefined, "the per-address cooldown must stop the second");
  assert.deepEqual(second.body, first.body, "and the response must not reveal that it was suppressed");
});

test("a confirmed subscriber is never re-mailed by submitting their address", async () => {
  const ctx = fresh();
  await signUp(ctx, "greg@example.com");

  const again = await submit({ email: "greg@example.com" }, { ...ctx, limiter: new RateLimiter() });
  assert.equal(again.status, 200);
  assert.equal(again.sendConfirmation, undefined, "the form must not re-mail an existing subscriber on demand");
});

test("pending, confirmed and brand new all answer identically", async () => {
  const ctx = fresh();
  const brandNew = await submit({ email: "new@example.com" }, ctx);
  const pending = await submit({ email: "new@example.com" }, ctx); // cooling down
  await signUp(ctx, "done@example.com");
  const confirmed = await submit({ email: "done@example.com" }, ctx);

  assert.deepEqual(pending.body, brandNew.body);
  assert.deepEqual(confirmed.body, brandNew.body);
  assert.equal(pending.status, confirmed.status);
});

/* --------------------------------- confirm --------------------------------- */

test("clicking the link puts the address on the list", async () => {
  const ctx = fresh();
  const r = await signUp(ctx, "greg@example.com");
  assert.equal(r.ok, true);
  assert.equal(r.email, "greg@example.com");
  assert.equal(await ctx.store.size(), 1);
});

test("a confirmation link works exactly once", async () => {
  const ctx = fresh();
  const { sendConfirmation } = await submit({ email: "greg@example.com" }, ctx);
  assert.equal((await confirm(sendConfirmation.token, ctx)).ok, true);
  assert.equal((await confirm(sendConfirmation.token, ctx)).ok, false, "a replayed link must not work");
});

test("a forged or expired token confirms nothing", async () => {
  const ctx = fresh();
  for (const bad of [makeToken(), "short", "", null, undefined, 42]) {
    assert.equal((await confirm(bad, ctx)).ok, false);
  }
  assert.equal(await ctx.store.size(), 0);
});

test("two people confirming are two subscribers, not one", async () => {
  const ctx = fresh();
  await signUp(ctx, "a@example.com");
  await signUp(ctx, "b@example.com");
  assert.equal(await ctx.store.size(), 2);
});

/* ------------------------------- unsubscribe ------------------------------- */

test("confirming yields the unsubscribe token every later message must carry", async () => {
  const ctx = fresh();
  const r = await signUp(ctx, "greg@example.com");
  assert.match(r.unsub, /^[A-Za-z0-9_-]{32,}$/);
  assert.notEqual(r.unsub, r.email);
});

test("an unsubscribe link works, and clicking it twice is still a success", async () => {
  const store = makeWaitlistStore(null);
  const ctx = { store, limiter: new RateLimiter(), ip: "a" };
  const token = (await signUp(ctx, "greg@example.com")).unsub;

  const first = await unsubscribe(token, { store });
  assert.deepEqual(first, { ok: true, removed: true });
  assert.equal(await store.size(), 0);

  const second = await unsubscribe(token, { store });
  assert.equal(second.ok, true, "a second click must not look like a failure to the person clicking it");
});

test("a forged unsubscribe token removes nobody", async () => {
  const ctx = fresh();
  await signUp(ctx, "greg@example.com");
  const r = await unsubscribe(makeToken(), ctx);
  assert.equal(r.removed, false);
  assert.equal(await ctx.store.size(), 1, "an existing subscriber must survive a bad token");
});

test("after unsubscribing, the record is genuinely gone", async () => {
  const store = makeWaitlistStore(null);
  const ctx = { store, limiter: new RateLimiter(), ip: "a" };
  await unsubscribe((await signUp(ctx, "greg@example.com")).unsub, { store });

  // Cooldown is per-address and still running, so this proves the record itself
  // is gone rather than merely hidden.
  assert.equal(await store.isConfirmed("greg@example.com"), false);
});

/* ------------------------------- redis shapes ------------------------------ */

test("the redis store round-trips a pending address and consumes it once", async () => {
  const kv = new Map();
  const hash = new Map();
  const store = makeWaitlistStore({
    hExists: async (_k, f) => hash.has(f),
    hSetNX: async (_k, f, v) => (hash.has(f) ? false : (hash.set(f, v), true)),
    hDel: async (_k, f) => void hash.delete(f),
    hLen: async () => hash.size,
    set: async (k, v) => void kv.set(k, v),
    get: async (k) => kv.get(k) ?? null,
    del: async (k) => void kv.delete(k),
    exists: async (k) => (kv.has(k) ? 1 : 0),
  });

  await store.putPending("tok", { email: "a@b.com", source: "site", at: "now" });
  assert.deepEqual(await store.takePending("tok"), { email: "a@b.com", source: "site", at: "now" });
  assert.equal(await store.takePending("tok"), null, "the token must be consumed");

  assert.equal(await store.confirm("a@b.com", { at: "now", source: "site", unsub: "u1" }), true);
  assert.equal(await store.confirm("a@b.com", { at: "now", source: "site", unsub: "u2" }), false);
  assert.equal(await store.size(), 1);
  assert.equal(await store.removeByUnsub("u1"), "a@b.com");
  assert.equal(await store.size(), 0);
});

test("confirming reports which page the person signed up from", () => {
  // Without this the operational alert had nothing to interpolate and read
  // "from: undefined".
  const ctx = fresh();
  return submit({ email: "greg@example.com", source: "post" }, ctx)
    .then((r) => confirm(r.sendConfirmation.token, ctx))
    .then((r) => assert.equal(r.source, "post"));
});

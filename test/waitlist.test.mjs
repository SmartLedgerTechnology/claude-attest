import test from "node:test";
import assert from "node:assert/strict";
import {
  normalizeEmail,
  clientIp,
  RateLimiter,
  makeWaitlistStore,
  submit,
} from "../service/waitlist.mjs";

const fresh = () => ({
  store: makeWaitlistStore(null),
  limiter: new RateLimiter({ max: 5 }),
  ip: "203.0.113.7",
});

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
  // Everything left of the final entry is client-supplied and forgeable.
  assert.equal(clientIp({ "x-forwarded-for": "9.9.9.9, 203.0.113.7" }), "203.0.113.7");
});

test("with no proxy header the socket address is used", () => {
  assert.equal(clientIp({}, "198.51.100.4"), "198.51.100.4");
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

test("a good address is accepted and reported once", async () => {
  const ctx = fresh();
  const r = await submit({ email: "greg@example.com", source: "landing" }, ctx);
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { ok: true });
  assert.equal(r.added.email, "greg@example.com");
  assert.equal(r.added.total, 1);
});

test("re-submitting is harmless and indistinguishable from the first time", async () => {
  const ctx = fresh();
  const first = await submit({ email: "greg@example.com" }, ctx);
  const again = await submit({ email: "  GREG@example.com " }, ctx);

  assert.deepEqual(again.body, first.body, "the response must not reveal that the address is known");
  assert.equal(again.status, 200);
  assert.equal(again.added, undefined, "a duplicate must not raise a second notification");
  assert.equal(await ctx.store.size(), 1, "and must not be stored twice");
});

test("the honeypot is answered like a success so a bot learns nothing", async () => {
  const ctx = fresh();
  const r = await submit({ email: "bot@example.com", company: "Acme Inc" }, ctx);
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { ok: true });
  assert.equal(r.added, undefined, "the address must not be recorded");
  assert.equal(await ctx.store.size(), 0);
});

test("an empty honeypot is what a real browser sends, and must pass", async () => {
  const ctx = fresh();
  const r = await submit({ email: "greg@example.com", company: "" }, ctx);
  assert.ok(r.added, "a person leaving the hidden field alone must get through");
});

test("a bad address is refused before it costs anyone their rate budget", async () => {
  const ctx = fresh();
  for (let i = 0; i < 20; i++) await submit({ email: "nope" }, ctx);
  const r = await submit({ email: "greg@example.com" }, ctx);
  assert.ok(r.added, "typos must not lock a person out of the form");
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

test("the source label is recorded but bounded", async () => {
  const ctx = fresh();
  const r = await submit({ email: "greg@example.com", source: "z".repeat(200) }, ctx);
  assert.equal(r.added.source.length, 32);
});

test("a missing source falls back rather than failing", async () => {
  const ctx = fresh();
  const r = await submit({ email: "greg@example.com" }, ctx);
  assert.equal(r.added.source, "site");
});

test("a garbage body is a 400, not a crash", async () => {
  const ctx = fresh();
  for (const body of [{}, null, undefined, { email: {} }, []]) {
    assert.equal((await submit(body, ctx)).status, 400);
  }
});

test("the redis store returns false for an address it already holds", async () => {
  // Mirrors hSetNX semantics: true on insert, false when the field exists.
  const hash = new Map();
  const store = makeWaitlistStore({
    hSetNX: async (_k, f, v) => (hash.has(f) ? false : (hash.set(f, v), true)),
    hLen: async () => hash.size,
  });
  assert.equal(await store.add("a@b.com", "{}"), true);
  assert.equal(await store.add("a@b.com", "{}"), false);
  assert.equal(await store.size(), 1);
});

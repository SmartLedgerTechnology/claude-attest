#!/usr/bin/env node
/**
 * ProofOfProcess billing service.
 *
 *   POST /v1/checkout        start a subscription (returns a Stripe Checkout URL)
 *   POST /v1/stripe/webhook  Stripe event intake — issues and revokes API keys
 *   POST /v1/portal          Stripe Billing Portal session for self-service
 *   POST /v1/authorize       internal: is this API key currently entitled?
 *   GET  /healthz
 *
 * Runs in exactly one Stripe mode, chosen by STRIPE_MODE. Mixing live and test
 * credentials in one process is how people accidentally charge real cards while
 * testing, so the mode is explicit and the wrong-prefix case is fatal at boot.
 */

import http from "node:http";
import { timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { KeyStore } from "./keystore.mjs";
import { verifyStripeSignature } from "./stripe-signature.mjs";
import { handleEvent, HANDLED_EVENTS } from "./billing-events.mjs";
import { verifyAttestation } from "../packages/proof-of-process/src/verify.mjs";
import { canonicalJSON, sha256Hex } from "../packages/proof-of-process/src/canonical.mjs";
import { renderVerifyPage } from "./verify-page.mjs";

const PORT = Number(process.env.PORT ?? 8788);
const HOST = process.env.HOST ?? "0.0.0.0";
const MODE = process.env.STRIPE_MODE ?? "test";
const SECRET_KEY = process.env.STRIPE_API_KEY ?? "";
const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET ?? "";
const SUCCESS_URL = process.env.CHECKOUT_SUCCESS_URL ?? "https://proofofprocess.ai/welcome?session={CHECKOUT_SESSION_ID}";
const CANCEL_URL = process.env.CHECKOUT_CANCEL_URL ?? "https://proofofprocess.ai/";
const PORTAL_RETURN_URL = process.env.PORTAL_RETURN_URL ?? "https://proofofprocess.ai/account";
const MAX_BODY = 4 * 1024 * 1024;
const PUBLIC_BASE = process.env.PUBLIC_BASE_URL ?? "https://proofofprocess.ai";
// Operational keys, mirroring the countersigner. Publishing is a subscriber
// feature, but we still need a path for demos, support, and our own records
// that does not require holding a subscription to our own product.
const OPERATOR_KEYS = new Set(
  (process.env.PUBLISH_API_KEYS ?? "").split(",").map((k) => k.trim()).filter(Boolean)
);

// Read once at boot: the page is static, and a disk read per request would be
// pure waste on the one endpoint a nervous new customer is staring at.
const HERE = path.dirname(fileURLToPath(import.meta.url));
const WELCOME_HTML = fs.readFileSync(path.join(HERE, "welcome.html"), "utf8");
const LANDING_HTML = fs.readFileSync(path.join(HERE, "landing.html"), "utf8");

// Price → tier. Lookup keys stay stable across test and live; price IDs do not.
const TIERS = {
  [process.env.PRICE_CREATOR ?? "pop_creator_monthly"]: "creator",
  [process.env.PRICE_PRO ?? "pop_pro_monthly"]: "pro",
};

if (!SECRET_KEY) fatal("STRIPE_API_KEY is not set");
if (!WEBHOOK_SECRET) fatal("STRIPE_WEBHOOK_SECRET is not set — refusing to start without signature verification");
if (MODE === "live" && !SECRET_KEY.includes("_live_")) fatal("STRIPE_MODE=live but the key is not a live key");
if (MODE === "test" && !SECRET_KEY.includes("_test_")) fatal("STRIPE_MODE=test but the key is not a test key");

const redis = await connectRedis();
const store = new KeyStore(redis);
// In-memory fallbacks so the service is exercisable without Redis.
const published = new Map();
const publishedAlias = new Map();
const seen = makeSeenSet();
const stripe = makeStripeClient(SECRET_KEY);

http.createServer(handle).listen(PORT, HOST, () =>
  console.error(`billing service on ${HOST}:${PORT} | stripe mode=${MODE}`)
);

async function handle(req, res) {
  try {
    const url = new URL(req.url, "http://localhost");
    if (req.method === "GET" && url.pathname === "/healthz") {
      return json(res, 200, { status: "ok", mode: MODE });
    }
    // The landing page is served from here rather than a static mount on Caddy:
    // adding a volume would require recreating the container that fronts every
    // site on this host. Serving ~17KB from memory is a fair trade for not
    // taking notaryhash.com down to publish a marketing page.
    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=300" });
      return res.end(LANDING_HTML);
    }
    // Served from this origin so the page's /v1/claim call is same-origin —
    // no CORS, and the key never crosses a domain boundary it needn't.
    if (req.method === "GET" && url.pathname === "/welcome") {
      res.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "referrer-policy": "no-referrer",
      });
      return res.end(WELCOME_HTML);
    }
    if (req.method === "GET" && url.pathname.startsWith("/v/")) {
      return await verifyPage(url.pathname.slice(3), res);
    }
    if (req.method === "POST" && url.pathname === "/v1/publish") return await publish(req, res);
    if (req.method === "POST" && url.pathname === "/v1/stripe/webhook") return await webhook(req, res);
    if (req.method === "POST" && url.pathname === "/v1/checkout") return await checkout(req, res);
    if (req.method === "POST" && url.pathname === "/v1/claim") return await claim(req, res);
    if (req.method === "POST" && url.pathname === "/v1/rotate") return await rotate(req, res);
    if (req.method === "POST" && url.pathname === "/v1/portal") return await portal(req, res);
    if (req.method === "POST" && url.pathname === "/v1/authorize") return await authorize(req, res);
    return json(res, 404, { error: "not found" });
  } catch (e) {
    console.error(`billing error: ${e?.stack ?? e}`);
    return json(res, 500, { error: "internal error" });
  }
}

/**
 * Stripe intake. The raw body is verified BEFORE parsing — the signature covers
 * the exact bytes sent, so anything that re-serializes first breaks it.
 *
 * We always answer 2xx once the signature is valid, even if our own handling
 * fails: a non-2xx makes Stripe retry for up to three days, and a poison event
 * would then block every later delivery. Failures are logged for replay, not
 * pushed back onto Stripe.
 */
async function webhook(req, res) {
  const raw = await readRaw(req);
  const result = verifyStripeSignature(raw, req.headers["stripe-signature"], WEBHOOK_SECRET);
  if (!result.ok) {
    console.error(`webhook rejected: ${result.reason}`);
    return json(res, 400, { error: result.reason });
  }
  const event = result.event;

  if (!HANDLED_EVENTS.has(event.type)) {
    return json(res, 200, { received: true, action: "unhandled" });
  }
  try {
    const outcome = await handleEvent(event, { store, stripe, tierForPrice, seen });
    // The plaintext key is deliberately not logged; it goes to the customer via
    // the success page, which looks it up by checkout session.
    const { apiKey, ...loggable } = outcome;
    console.error(`webhook ${event.type} -> ${JSON.stringify(loggable)}`);
    return json(res, 200, { received: true, action: outcome.action });
  } catch (e) {
    console.error(`webhook handling failed for ${event.id} (${event.type}): ${e?.stack ?? e}`);
    return json(res, 200, { received: true, action: "deferred" });
  }
}

/**
 * Publish an attestation so it can be verified from a link.
 *
 * Subscribers only: hosting is the thing a subscription actually buys, and it
 * is what stops this becoming free permanent storage for anyone.
 *
 * We store the header, certificate and countersignatures — never the leaves.
 * The Merkle root and the collaboration profile are already inside the signed
 * header, so a reader can verify every claim on the page while the creator's
 * event log, which reveals what they typed and ran, stays on their machine.
 */
async function publish(req, res) {
  const body = await readJson(req);
  const auth = await authorizePublisher(body?.apiKey ?? "");
  if (!auth.ok) return json(res, 401, { error: auth.reason ?? "unknown or expired API key" });

  const { header, certificate, countersignatures } = body?.attestation ?? {};
  if (!header || !certificate) return json(res, 400, { error: "attestation must include a header and a certificate" });

  // The record is named by the digest that was anchored. Anyone holding the
  // attestation can derive the same id, and a mismatch here means the header
  // and the certificate do not belong together.
  const digest = sha256Hex(canonicalJSON(header));
  if (digest !== certificate.payloadHash) {
    return json(res, 400, { error: "header does not match the certificate's payloadHash" });
  }

  const record = {
    id: digest,
    header,
    certificate,
    countersignatures: Array.isArray(countersignatures) ? countersignatures : [],
    customerId: auth.customerId ?? null,
    publishedVia: auth.via,
    publishedAt: new Date().toISOString(),
  };
  const payload = JSON.stringify(record);
  if (redis) {
    await redis.set(`pop:published:${digest}`, payload);
    if (body?.notaryHashId) await redis.set(`pop:published-alias:${body.notaryHashId}`, digest);
  } else {
    published.set(digest, payload);
    if (body?.notaryHashId) publishedAlias.set(body.notaryHashId, digest);
  }
  return json(res, 200, { id: digest, url: `${PUBLIC_BASE}/v/${digest}` });
}

/** Operational keys first, then subscriptions. Constant-time on the env path. */
async function authorizePublisher(key) {
  if (typeof key !== "string" || !key) return { ok: false, reason: "no API key" };
  for (const k of OPERATOR_KEYS) {
    const a = Buffer.from(k);
    const b = Buffer.from(key);
    if (a.length === b.length && timingSafeEqual(a, b)) return { ok: true, via: "operator" };
  }
  const r = await store.authorize(key);
  if (r.ok) return { ok: true, via: "subscription", customerId: r.record.customerId };
  return { ok: false, reason: r.reason === "unknown key" ? "unknown or expired API key" : `subscription ${r.reason}` };
}

async function loadPublished(id) {
  const direct = redis ? await redis.get(`pop:published:${id}`) : published.get(id);
  if (direct) return JSON.parse(direct);
  const aliased = redis ? await redis.get(`pop:published-alias:${id}`) : publishedAlias.get(id);
  if (!aliased) return null;
  const rec = redis ? await redis.get(`pop:published:${aliased}`) : published.get(aliased);
  return rec ? JSON.parse(rec) : null;
}

async function verifyPage(id, res) {
  const html = async (code, body) => {
    res.writeHead(code, { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=60" });
    res.end(body);
  };
  const rec = await loadPublished(decodeURIComponent(id || ""));
  if (!rec) return html(404, renderVerifyPage({ id, notFound: true }));

  // Verified here, on every request, from the stored bytes — never trusting a
  // verdict cached at publish time.
  const report = await verifyAttestation(
    { header: rec.header, certificate: rec.certificate, countersignatures: rec.countersignatures },
    { checkChain: true }
  );
  return html(200, renderVerifyPage({ id: rec.id, report, header: rec.header, certificate: rec.certificate, publishedAt: rec.publishedAt }));
}

async function checkout(req, res) {
  const body = await readJson(req);
  const lookupKey = body?.plan ?? "pop_creator_monthly";
  const prices = await stripe.listPrices(lookupKey);
  const price = prices?.data?.[0];
  if (!price) return json(res, 400, { error: `no active price with lookup_key '${lookupKey}'` });

  const session = await stripe.createCheckoutSession({
    mode: "subscription",
    "line_items[0][price]": price.id,
    "line_items[0][quantity]": "1",
    success_url: SUCCESS_URL,
    cancel_url: CANCEL_URL,
    ...(body?.email ? { customer_email: body.email } : {}),
    allow_promotion_codes: "true",
  });
  if (session.error) return json(res, 400, { error: session.error.message });
  return json(res, 200, { url: session.url, id: session.id });
}

/**
 * Deliver the API key to the person who paid.
 *
 * The Checkout session id is the proof of purchase: it arrives on the success
 * URL, it is unguessable, and it names exactly one customer. We resolve it
 * against Stripe rather than trusting anything the caller says about identity.
 *
 * The key is returned exactly once. There is no endpoint that returns it again,
 * because the store holds only its hash — a lost key is rotated, not recovered.
 */
async function claim(req, res) {
  const body = await readJson(req);
  const sessionId = body?.sessionId;
  if (typeof sessionId !== "string" || !sessionId.startsWith("cs_")) {
    return json(res, 400, { error: "sessionId must be a Stripe Checkout session id" });
  }

  const session = await stripe.getCheckoutSession(sessionId).catch(() => null);
  if (!session || session.error) return json(res, 404, { error: "unknown checkout session" });
  if (session.payment_status !== "paid" && session.status !== "complete") {
    return json(res, 402, { error: "this checkout session has not been paid" });
  }
  const customerId = typeof session.customer === "string" ? session.customer : session.customer?.id;
  if (!customerId) return json(res, 409, { error: "checkout session has no customer yet" });

  // `replace` is deliberate intent from the UI, never an accidental reload:
  // possession of the session id is the same proof we accepted for the first
  // claim, so re-issuing under it is no weaker — but it invalidates the
  // previous key, which must be a choice the customer makes knowingly.
  const result = body?.replace === true ? await store.rotate(customerId) : await store.claim(customerId);
  if (!result.ok) {
    const code = result.reason === "already claimed" ? 409 : 404;
    return json(res, code, {
      error: result.reason,
      ...(code === 409
        ? { canReplace: true, hint: "keys are shown once; request again with replace:true to issue a new one" }
        : {}),
    });
  }
  return json(res, 200, {
    apiKey: result.plaintext,
    tier: result.record.tier,
    expiresAt: result.record.accessExpiresAt,
    notice: "Store this now — it cannot be shown again.",
  });
}

/** Replace a lost or compromised key. Requires possession of the current one. */
async function rotate(req, res) {
  const body = await readJson(req);
  const auth = await store.authorize(body?.apiKey ?? "");
  if (!auth.record?.customerId) return json(res, 401, { error: "unknown or expired API key" });
  const result = await store.rotate(auth.record.customerId);
  if (!result.ok) return json(res, 409, { error: result.reason });
  return json(res, 200, {
    apiKey: result.plaintext,
    tier: result.record.tier,
    notice: "The previous key stopped working immediately.",
  });
}

async function portal(req, res) {
  const body = await readJson(req);
  // Identify the customer by their API key, so nobody can open someone else's
  // billing portal by guessing a customer id.
  const auth = await store.authorize(body?.apiKey ?? "");
  if (!auth.record?.customerId) return json(res, 401, { error: "unknown or expired API key" });
  const session = await stripe.createPortalSession({
    customer: auth.record.customerId,
    return_url: PORTAL_RETURN_URL,
  });
  if (session.error) return json(res, 400, { error: session.error.message });
  return json(res, 200, { url: session.url });
}

/** Internal entitlement check for the countersigner and other services. */
async function authorize(req, res) {
  const body = await readJson(req);
  const r = await store.authorize(body?.apiKey ?? "");
  return json(res, r.ok ? 200 : 401, {
    ok: r.ok,
    reason: r.reason,
    tier: r.record?.tier,
    expiresAt: r.record?.accessExpiresAt,
  });
}

function tierForPrice(priceId) {
  return TIERS[priceId] ?? "creator";
}

/* ------------------------------ Stripe client ----------------------------- */

/** Minimal form-encoded Stripe client — avoids a dependency on the full SDK. */
function makeStripeClient(key) {
  const call = async (method, path, params) => {
    const opts = {
      method,
      headers: {
        Authorization: "Basic " + Buffer.from(`${key}:`).toString("base64"),
        "Content-Type": "application/x-www-form-urlencoded",
      },
    };
    if (params) opts.body = new URLSearchParams(params).toString();
    const res = await fetch(`https://api.stripe.com${path}`, opts);
    return res.json();
  };
  return {
    getSubscription: async (id) => {
      const s = await call("GET", `/v1/subscriptions/${id}`);
      if (s.error) throw new Error(`stripe: ${s.error.message}`);
      return s;
    },
    getCheckoutSession: (id) => call("GET", `/v1/checkout/sessions/${id}`),
    listPrices: (lookupKey) =>
      call("GET", `/v1/prices?active=true&lookup_keys[]=${encodeURIComponent(lookupKey)}&expand[]=data.product`),
    createCheckoutSession: (params) => call("POST", "/v1/checkout/sessions", params),
    createPortalSession: (params) => call("POST", "/v1/billing_portal/sessions", params),
  };
}

/* --------------------------------- infra ---------------------------------- */

async function connectRedis() {
  const url = process.env.REDIS_URL;
  if (!url) {
    console.error("billing: REDIS_URL unset — using in-memory store (single process, not durable)");
    return null;
  }
  try {
    const { createClient } = await import("redis");
    const client = createClient({ url });
    client.on("error", (e) => console.error(`redis: ${e.message}`));
    await client.connect();
    console.error(`billing: connected to redis`);
    return client;
  } catch (e) {
    console.error(`billing: redis unavailable (${e.message}) — using in-memory store`);
    return null;
  }
}

/** Event-id dedupe. Bounded so a long-running process cannot grow without limit. */
function makeSeenSet() {
  const ids = new Set();
  const order = [];
  const LIMIT = 10_000;
  return {
    has: async (id) => ids.has(id),
    add: async (id) => {
      ids.add(id);
      order.push(id);
      if (order.length > LIMIT) ids.delete(order.shift());
    },
  };
}

function readRaw(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function readJson(req) {
  try {
    return JSON.parse((await readRaw(req)).toString("utf8") || "{}");
  } catch {
    return {};
  }
}

function json(res, code, obj) {
  const b = JSON.stringify(obj);
  res.writeHead(code, { "content-type": "application/json", "content-length": Buffer.byteLength(b) });
  res.end(b);
}

function fatal(msg) {
  console.error(`billing: ${msg}`);
  process.exit(1);
}

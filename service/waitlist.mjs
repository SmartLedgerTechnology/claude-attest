/**
 * "Keep me posted" — the one address field on the site.
 *
 * Kept out of the HTTP server so the rules can be tested without sockets, and
 * so the decisions are readable in one place. Three of them shape everything:
 *
 *   WE CANNOT SEND YET.  proofofprocess.ai has receive-only forwarding and no
 *     signing domain, so there is no list to blast even by accident. Until an
 *     ESP with DKIM exists this is a list of people to write to by hand, and
 *     the copy on the page promises nothing more than that.
 *
 *   THE ADDRESS STAYS HERE.  It goes to Redis and nowhere else — in particular
 *     not into the Telegram alert, for the same reason customer emails are kept
 *     out of it. See the NEVER SECRET rule in notify.mjs.
 *
 *   AN OPEN POST ENDPOINT WILL BE ABUSED.  A honeypot for the naive bots, and a
 *     per-IP hourly cap for everyone else. No CAPTCHA: it would punish the
 *     humans far more reliably than the bots.
 */

export const WINDOW_MS = 60 * 60 * 1000;
export const DEFAULT_MAX_PER_HOUR = 5;

/**
 * Deliberately loose. The only authoritative test of an address is sending to
 * it; a strict pattern mostly succeeds at rejecting valid addresses. This
 * rejects the things that are certainly not addresses and accepts the rest.
 */
export function normalizeEmail(v) {
  if (typeof v !== "string") return null;
  const e = v.trim().toLowerCase();
  if (e.length < 6 || e.length > 254) return null;
  return /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/.test(e) ? e : null;
}

/**
 * Caddy appends the peer it actually saw to X-Forwarded-For, so the LAST hop is
 * the one entry a client cannot forge. Everything to its left is client-supplied
 * — trusting it would let a single host rotate a header and spend everyone
 * else's budget.
 */
export function clientIp(headers, socketAddress) {
  const hops = String(headers?.["x-forwarded-for"] ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return hops.at(-1) ?? socketAddress ?? "unknown";
}

/** Fixed-window-per-key limiter, bounded so unique keys cannot grow it forever. */
export class RateLimiter {
  constructor({ max = DEFAULT_MAX_PER_HOUR, windowMs = WINDOW_MS, maxKeys = 5_000, now = () => Date.now() } = {}) {
    this.max = max;
    this.windowMs = windowMs;
    this.maxKeys = maxKeys;
    this.now = now;
    this.hits = new Map();
  }

  allow(key) {
    const t = this.now();
    if (this.hits.size > this.maxKeys) this.#evict(t);
    const hits = (this.hits.get(key) ?? []).filter((x) => t - x < this.windowMs);
    this.hits.set(key, hits);
    if (hits.length >= this.max) return false;
    hits.push(t);
    return true;
  }

  #evict(t) {
    for (const [k, v] of this.hits) {
      if (!v.some((x) => t - x < this.windowMs)) this.hits.delete(k);
    }
  }
}

/** Redis-backed when available, in-process otherwise, mirroring the rest of the service. */
export function makeWaitlistStore(redis, key = "pop:notify") {
  if (redis) {
    return {
      add: async (email, entry) => Boolean(await redis.hSetNX(key, email, entry)),
      size: () => redis.hLen(key),
    };
  }
  const mem = new Map();
  return {
    add: async (email, entry) => {
      if (mem.has(email)) return false;
      mem.set(email, entry);
      return true;
    },
    size: async () => mem.size,
  };
}

/**
 * @returns {{status: number, body: object, added?: {email: string, total: number, source: string}}}
 *
 * `added` is present only for an address that was not already on the list; the
 * caller uses it to raise a notification. The RESPONSE is identical either way
 * — telling a caller "already subscribed" would turn this into an oracle for
 * whether a given person has signed up.
 */
export async function submit(body, { store, limiter, ip, now = () => new Date() }) {
  // A field no human ever sees and a naive bot always fills in. It gets the same
  // 200 a person gets, so the bot learns nothing from the response.
  if (typeof body?.company === "string" && body.company.trim() !== "") {
    return { status: 200, body: { ok: true } };
  }

  const email = normalizeEmail(body?.email);
  if (!email) return { status: 400, body: { error: "That does not look like an email address." } };

  if (!limiter.allow(ip)) {
    return { status: 429, body: { error: "Too many attempts from here. Try again later." } };
  }

  const source = typeof body?.source === "string" ? body.source.slice(0, 32) : "site";
  const fresh = await store.add(email, JSON.stringify({ at: now().toISOString(), source }));
  const result = { status: 200, body: { ok: true } };
  if (fresh) result.added = { email, source, total: await store.size() };
  return result;
}

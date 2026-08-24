/**
 * "Keep me posted" — the one address field on the site.
 *
 * Kept out of the HTTP server so the rules can be tested without sockets, and
 * so the decisions are readable in one place.
 *
 * CONFIRMED OPT-IN.  Anyone can type anyone's address into a form on the open
 *   internet. Storing an address nobody proved they own, and then mailing it,
 *   is precisely the kind of unevidenced claim this company exists to argue
 *   against — so an address is pending until its owner clicks a link, and an
 *   address that is never confirmed is deleted rather than kept.
 *
 * THE FORM MUST NOT BECOME A WEAPON.  A signup form that emails whatever
 *   address it is handed is a mail-bomb aimed at third parties. Two independent
 *   limits: a per-IP hourly cap, and a per-ADDRESS cooldown, so flooding one
 *   victim cannot be achieved by rotating source addresses.
 *
 * EVERY ANSWER LOOKS THE SAME.  Submitting returns an identical response
 *   whether the address is new, pending, or already confirmed. Anything else
 *   turns the endpoint into an oracle for whether a given person signed up.
 */

import { randomBytes } from "node:crypto";

export const WINDOW_MS = 60 * 60 * 1000;
export const DEFAULT_MAX_PER_HOUR = 5;
/** How long a pending address survives unconfirmed before it is forgotten. */
export const PENDING_TTL_SECONDS = 7 * 24 * 60 * 60;
/** Minimum gap between confirmation mails to the same address, whoever asks. */
export const RESEND_COOLDOWN_MS = 60 * 60 * 1000;

/**
 * Deliberately loose. The only authoritative test of an address is sending to
 * it — which is exactly what confirmation does — so a strict pattern here would
 * mostly succeed at rejecting valid addresses.
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

/** URL-safe, unguessable, and never logged: these tokens are bearer capabilities. */
export function makeToken() {
  return randomBytes(32).toString("base64url");
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

/**
 * Redis-backed when available, in-process otherwise, mirroring the rest of the
 * service. Three namespaces:
 *
 *   pop:notify                  confirmed: email -> {at, source, unsub}
 *   pop:notify:pending:<token>  unconfirmed, expiring: -> {email, at, source}
 *   pop:notify:unsub:<token>    confirmed reverse index: -> email
 */
export function makeWaitlistStore(redis, prefix = "pop:notify") {
  const P = { list: prefix, pending: `${prefix}:pending:`, unsub: `${prefix}:unsub:`, cool: `${prefix}:cool:` };

  if (redis) {
    return {
      isConfirmed: async (email) => Boolean(await redis.hExists(P.list, email)),
      putPending: async (token, rec) =>
        redis.set(P.pending + token, JSON.stringify(rec), { EX: PENDING_TTL_SECONDS }),
      takePending: async (token) => {
        const raw = await redis.get(P.pending + token);
        if (!raw) return null;
        await redis.del(P.pending + token);
        return JSON.parse(raw);
      },
      confirm: async (email, rec) => {
        const added = Boolean(await redis.hSetNX(P.list, email, JSON.stringify(rec)));
        if (added) await redis.set(P.unsub + rec.unsub, email);
        return added;
      },
      removeByUnsub: async (token) => {
        const email = await redis.get(P.unsub + token);
        if (!email) return null;
        await redis.hDel(P.list, email);
        await redis.del(P.unsub + token);
        return email;
      },
      /** True when a confirmation was already sent recently to this address. */
      onCooldown: async (email) => Boolean(await redis.exists(P.cool + email)),
      startCooldown: async (email, ms) => redis.set(P.cool + email, "1", { PX: ms }),
      size: () => redis.hLen(P.list),
    };
  }

  const list = new Map();
  const pending = new Map();
  const unsub = new Map();
  const cool = new Map();
  const live = (m, k) => {
    const v = m.get(k);
    if (!v) return null;
    if (v.expires && v.expires < Date.now()) { m.delete(k); return null; }
    return v;
  };
  return {
    isConfirmed: async (email) => list.has(email),
    putPending: async (token, rec) => void pending.set(token, { rec, expires: Date.now() + PENDING_TTL_SECONDS * 1000 }),
    takePending: async (token) => {
      const hit = live(pending, token);
      if (!hit) return null;
      pending.delete(token);
      return hit.rec;
    },
    confirm: async (email, rec) => {
      if (list.has(email)) return false;
      list.set(email, rec);
      unsub.set(rec.unsub, email);
      return true;
    },
    removeByUnsub: async (token) => {
      const email = unsub.get(token);
      if (!email) return null;
      list.delete(email);
      unsub.delete(token);
      return email;
    },
    onCooldown: async (email) => Boolean(live(cool, email)),
    startCooldown: async (email, ms) => void cool.set(email, { rec: 1, expires: Date.now() + ms }),
    size: async () => list.size,
  };
}

/**
 * Step one: accept an address and decide whether a confirmation is owed.
 *
 * @returns {{status, body, sendConfirmation?: {email, token, source}}}
 *   `sendConfirmation` is present only when a mail should actually go out. The
 *   RESPONSE is identical either way.
 */
export async function submit(body, { store, limiter, ip, now = () => new Date() }) {
  // A field no human ever sees and a naive bot always fills in. It gets the same
  // 200 a person gets, so the bot learns nothing from the response.
  if (typeof body?.company === "string" && body.company.trim() !== "") {
    return { status: 200, body: ACCEPTED };
  }

  const email = normalizeEmail(body?.email);
  if (!email) return { status: 400, body: { error: "That does not look like an email address." } };

  if (!limiter.allow(ip)) {
    return { status: 429, body: { error: "Too many attempts from here. Try again later." } };
  }

  const source = typeof body?.source === "string" ? body.source.slice(0, 32) : "site";

  // Already on the list: say nothing new, and above all send nothing. Otherwise
  // the form would re-mail a subscriber on demand.
  if (await store.isConfirmed(email)) return { status: 200, body: ACCEPTED };

  // Per-address cooldown. The per-IP cap alone does not stop a flood aimed at
  // one victim from many sources; this does.
  if (await store.onCooldown(email)) return { status: 200, body: ACCEPTED };

  const token = makeToken();
  await store.putPending(token, { email, source, at: now().toISOString() });
  await store.startCooldown(email, RESEND_COOLDOWN_MS);
  return { status: 200, body: ACCEPTED, sendConfirmation: { email, token, source } };
}

const ACCEPTED = Object.freeze({
  ok: true,
  message: "Check your inbox — there's a link to confirm.",
});

/**
 * Step two: the click. Consumes the token, so a link works once.
 *
 * @returns {{ok, email?, alreadyConfirmed?}}
 */
export async function confirm(token, { store, now = () => new Date() }) {
  if (typeof token !== "string" || token.length < 20) return { ok: false };
  const rec = await store.takePending(token);
  if (!rec) return { ok: false };

  const unsub = makeToken();
  const added = await store.confirm(rec.email, { at: now().toISOString(), source: rec.source, unsub });
  // `unsub` is returned because every later message to this person must carry
  // their unsubscribe link, and this is where the token comes into existence.
  // `source` is carried through from the pending record: it is only known here,
  // and the confirmation is the first moment worth telling anyone about.
  return {
    ok: true,
    email: rec.email,
    source: rec.source,
    unsub,
    alreadyConfirmed: !added,
    total: await store.size(),
  };
}

/** Step three, whenever they like. Idempotent: a second click is still a success. */
export async function unsubscribe(token, { store }) {
  if (typeof token !== "string" || token.length < 20) return { ok: false };
  const email = await store.removeByUnsub(token);
  // A token that is already spent means the address is already gone, which is
  // the outcome the person wanted. Reporting failure would only alarm them.
  return { ok: true, removed: Boolean(email) };
}

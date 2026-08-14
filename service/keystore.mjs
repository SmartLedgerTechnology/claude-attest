import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Shared API-key store.
 *
 * The billing service writes keys here when a subscription starts; the
 * countersigner (and later NotaryHash) reads them on every request. Redis is
 * the backing store because it is already running on this host for NotaryHash's
 * coordination, and key lookup sits on the hot path of every signed request.
 *
 * Two decisions worth stating:
 *
 *   1. We store the SHA-256 of each key, never the key itself. A Redis dump, a
 *      backup, or an operator with CLI access therefore leaks nothing usable.
 *      The plaintext key exists exactly once — in the HTTP response that hands
 *      it to the customer.
 *
 *   2. Entitlement is an EXPIRY TIMESTAMP, not an `active` boolean. Renewals
 *      push it forward. If billing webhooks break entirely, keys lapse on their
 *      own instead of granting free service indefinitely — the failure mode
 *      points the safe way.
 */

const PREFIX = "pop:apikey:";
const TIER_PREFIX = "pop:customer:";

/** Grace beyond the paid period, so a slow renewal webhook never locks anyone out. */
const RENEWAL_LEEWAY_SECONDS = 2 * 24 * 60 * 60;

export function hashKey(plaintext) {
  return createHash("sha256").update(plaintext).digest("hex");
}

/** `pop_` + 24 random bytes, matching the convention already used on this host. */
export function generateApiKey() {
  return `pop_${randomBytes(24).toString("hex")}`;
}

export class KeyStore {
  /**
   * @param redis a node-redis compatible client, or null for the in-memory
   *   fallback used by tests and by any deployment without Redis.
   */
  constructor(redis = null) {
    this.redis = redis;
    this.memory = new Map();
  }

  /**
   * The customer record is canonical; the key-hash entry is a pointer to it.
   *
   * That direction matters: an entitlement exists from the moment a webhook
   * says someone paid, which is BEFORE any key has been minted. Indexing the
   * other way round would leave paid-but-unclaimed customers unrepresentable.
   */
  async #write(key, value) {
    if (this.redis) await this.redis.set(key, value);
    else this.memory.set(key, value);
  }

  async #read(key) {
    return this.redis ? await this.redis.get(key) : this.memory.get(key);
  }

  async put(record) {
    await this.#write(TIER_PREFIX + record.customerId, JSON.stringify(record));
    if (record.keyHash) await this.#write(PREFIX + record.keyHash, record.customerId);
    return record;
  }

  async getByCustomer(customerId) {
    const raw = await this.#read(TIER_PREFIX + customerId);
    return raw ? JSON.parse(raw) : null;
  }

  async getByHash(keyHash) {
    const customerId = await this.#read(PREFIX + keyHash);
    return customerId ? this.getByCustomer(customerId) : null;
  }

  /**
   * Record that a customer is entitled. No key is minted here — a webhook
   * handler has nobody to hand a plaintext key to, and a key that exists
   * without ever reaching its owner is just a liability sitting in a database.
   */
  async provision({ customerId, subscriptionId, tier, periodEnd }) {
    const record = {
      customerId,
      subscriptionId,
      tier,
      status: "active",
      keyHash: null,
      claimedAt: null,
      issuedAt: new Date().toISOString(),
      accessExpiresAt: expiryFrom(periodEnd),
    };
    await this.put(record);
    return record;
  }

  /**
   * Mint the plaintext key. Returns it EXACTLY once — the store keeps only the
   * hash, so a second claim cannot return the same value and we do not pretend
   * otherwise. Losing it means rotating, not recovering.
   */
  async claim(customerId) {
    const rec = await this.getByCustomer(customerId);
    if (!rec) return { ok: false, reason: "no entitlement for this customer" };
    if (rec.status === "revoked") return { ok: false, reason: "entitlement revoked" };
    if (rec.claimedAt) return { ok: false, reason: "already claimed", record: rec };

    const plaintext = generateApiKey();
    rec.keyHash = hashKey(plaintext);
    rec.claimedAt = new Date().toISOString();
    await this.put(rec);
    return { ok: true, plaintext, record: rec };
  }

  /**
   * Replace a customer's key, invalidating the old one. For a lost credential:
   * recovery is impossible by design, so rotation is the only remedy.
   */
  async rotate(customerId) {
    const rec = await this.getByCustomer(customerId);
    if (!rec) return { ok: false, reason: "no entitlement for this customer" };
    if (rec.status === "revoked") return { ok: false, reason: "entitlement revoked" };
    const previous = rec.keyHash;
    const plaintext = generateApiKey();
    rec.keyHash = hashKey(plaintext);
    rec.claimedAt = new Date().toISOString();
    rec.rotatedAt = rec.claimedAt;
    await this.put(rec);
    // Drop the stale pointer so the old key stops resolving immediately.
    if (previous && previous !== rec.keyHash) {
      if (this.redis) await this.redis.del(PREFIX + previous);
      else this.memory.delete(PREFIX + previous);
    }
    return { ok: true, plaintext, record: rec };
  }

  /** Convenience for tests and for flows that provision and claim together. */
  async issue({ customerId, subscriptionId, tier, periodEnd }) {
    await this.provision({ customerId, subscriptionId, tier, periodEnd });
    const claimed = await this.claim(customerId);
    return { plaintext: claimed.plaintext, record: claimed.record };
  }

  /** Push entitlement forward after a successful payment. */
  async renew(customerId, { periodEnd, tier, subscriptionId } = {}) {
    const rec = await this.getByCustomer(customerId);
    if (!rec) return null;
    rec.status = "active";
    rec.accessExpiresAt = expiryFrom(periodEnd);
    if (tier) rec.tier = tier;
    if (subscriptionId) rec.subscriptionId = subscriptionId;
    return this.put(rec);
  }

  /**
   * Mark a key unusable. We keep the record rather than deleting it: an audit
   * of "who had access when" is worth more than the bytes, and a customer who
   * resubscribes should not silently reuse a revoked credential.
   */
  async revoke(customerId, reason = "canceled") {
    const rec = await this.getByCustomer(customerId);
    if (!rec) return null;
    rec.status = "revoked";
    rec.revokedAt = new Date().toISOString();
    rec.revokedReason = reason;
    rec.accessExpiresAt = new Date().toISOString();
    return this.put(rec);
  }

  async suspend(customerId, reason = "payment_failed") {
    const rec = await this.getByCustomer(customerId);
    if (!rec) return null;
    rec.status = "past_due";
    rec.suspendedReason = reason;
    return this.put(rec);
  }

  /**
   * The authorization check services call. Constant-time on the hash so key
   * comparison cannot be timed, and expiry is evaluated independently of
   * status so a stale `active` record still lapses.
   */
  async authorize(plaintext, now = new Date()) {
    if (typeof plaintext !== "string" || !plaintext) return { ok: false, reason: "no key" };
    const rec = await this.getByHash(hashKey(plaintext));
    if (!rec) return { ok: false, reason: "unknown key" };
    // A record whose key was rotated away, or which was never claimed, cannot
    // authorize anything — and must not reach the comparison below.
    if (!rec.keyHash) return { ok: false, reason: "unknown key" };

    const given = Buffer.from(hashKey(plaintext), "hex");
    const known = Buffer.from(rec.keyHash, "hex");
    if (given.length !== known.length || !timingSafeEqual(given, known)) {
      return { ok: false, reason: "unknown key" };
    }
    if (rec.status === "revoked") return { ok: false, reason: "revoked", record: rec };
    if (rec.accessExpiresAt && new Date(rec.accessExpiresAt) <= now) {
      return { ok: false, reason: "expired", record: rec };
    }
    return { ok: true, record: rec };
  }
}

/**
 * Stripe reports period end as a Unix timestamp. Adding leeway means a renewal
 * webhook that arrives late — or gets retried for hours — never produces a
 * window where a paying customer is refused.
 */
function expiryFrom(periodEnd) {
  const base = Number.isFinite(periodEnd) ? periodEnd : Math.floor(Date.now() / 1000);
  return new Date((base + RENEWAL_LEEWAY_SECONDS) * 1000).toISOString();
}

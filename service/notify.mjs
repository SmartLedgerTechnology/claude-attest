/**
 * Operational notifications over Telegram.
 *
 * Deliberately narrow: this exists so a human learns about things they would
 * otherwise only discover by going looking — a signup, a failed payment, or a
 * sign that the billing plumbing is broken. It is not logging.
 *
 * Three rules, because a notifier that misbehaves is worse than none:
 *
 *   NEVER FATAL.    A Telegram outage must not fail a webhook, block a
 *                   provisioning, or take down a request. Every failure is
 *                   swallowed and logged.
 *   NEVER SECRET.   API keys, plaintext credentials and key material never
 *                   appear in a message. Messages transit a third party.
 *   NEVER SPAM.     A bug that fires in a loop would otherwise send thousands
 *                   of messages, so sending is rate-limited and repeated
 *                   identical alerts are collapsed.
 */

const API = "https://api.telegram.org";

/** Ceiling on messages per window, after which we go quiet and say so once. */
const MAX_PER_WINDOW = 20;
const WINDOW_MS = 60 * 60 * 1000;
/** Identical alerts inside this window are sent once. */
const DEDUPE_MS = 10 * 60 * 1000;

export class Notifier {
  constructor({ token, chatId, log = console.error, enabled = true } = {}) {
    this.token = token;
    this.chatId = chatId;
    this.log = log;
    this.enabled = Boolean(enabled && token && chatId);
    this.sent = [];
    this.recent = new Map();
    this.silenced = false;
  }

  /**
   * @param kind   short machine-ish label used for dedupe, e.g. "signup"
   * @param text   the message. Markdown is NOT used: customer-derived strings
   *               could otherwise break formatting or inject links.
   */
  async send(kind, text) {
    if (!this.enabled) return { ok: false, reason: "disabled" };

    const now = Date.now();
    const key = `${kind}:${text}`;
    const last = this.recent.get(key);
    if (last && now - last < DEDUPE_MS) return { ok: false, reason: "deduped" };

    this.sent = this.sent.filter((t) => now - t < WINDOW_MS);
    if (this.sent.length >= MAX_PER_WINDOW) {
      if (!this.silenced) {
        this.silenced = true;
        this.log(`notify: rate limit hit (${MAX_PER_WINDOW}/hour) — going quiet`);
        await this.#post("Too many notifications this hour. Going quiet until it settles.");
      }
      return { ok: false, reason: "rate-limited" };
    }
    this.silenced = false;
    this.recent.set(key, now);
    this.sent.push(now);
    return this.#post(text);
  }

  async #post(text) {
    try {
      const res = await fetch(`${API}/bot${this.token}/sendMessage`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          chat_id: this.chatId,
          text,
          disable_web_page_preview: true,
        }),
        signal: AbortSignal.timeout(10_000),
      });
      const data = await res.json().catch(() => ({}));
      if (!data.ok) this.log(`notify: telegram rejected: ${data.description ?? res.status}`);
      return { ok: Boolean(data.ok) };
    } catch (e) {
      // Swallowed on purpose — see NEVER FATAL above.
      this.log(`notify: send failed: ${e?.message ?? e}`);
      return { ok: false, reason: e?.message };
    }
  }
}

/* ------------------------------ message shapes ----------------------------- */

/**
 * Customer identity is the Stripe customer id, not the email address.
 * It links straight to the dashboard, is enough to act on, and keeps customer
 * PII out of a third-party chat service.
 */
export const events = {
  signup: (r) =>
    ["🎉 New subscriber", ` tier: ${r.tier}`, ` customer: ${r.customerId}`, ` via: ${r.via ?? "checkout"}`].join("\n"),

  claimed: (r) => ["🔑 API key claimed", ` customer: ${r.customerId}`, ` tier: ${r.tier}`].join("\n"),

  paymentFailed: (r) =>
    ["⚠️ Payment failed", ` customer: ${r.customerId}`, ` attempt: ${r.attempt ?? "?"}`, " Access continues during retries."].join("\n"),

  canceled: (r) => ["👋 Subscription ended", ` customer: ${r.customerId}`, ` reason: ${r.reason ?? "canceled"}`].join("\n"),

  published: (r) => ["📄 Record published", ` ${r.url}`].join("\n"),

  /**
   * The address itself stays in Redis. A running total is enough to know the
   * page is working, and keeps a stranger's email out of a third-party chat.
   */
  waitlist: (r) =>
    [
      "✉️ Someone confirmed their email",
      ` from: ${r.source ?? "unknown"}`,
      ` total on the list: ${r.total ?? "?"}`,
    ].join("\n"),

  /**
   * The reconciler provisioning anything means a customer paid and the webhook
   * did not arrive. The safety net worked, but the plumbing needs looking at —
   * which is exactly the kind of thing nobody notices without a nudge.
   */
  reconcileProvisioned: (r) =>
    [
      "🛟 Reconciler provisioned a customer",
      ` customer: ${r.customerId}`,
      " A payment succeeded without its webhook arriving.",
      " Check the live webhook endpoint URL and status in Stripe.",
    ].join("\n"),

  anchorFailed: (r) => ["⛓️ Anchoring failed", ` session: ${r.sessionId}`, ` ${r.error}`].join("\n"),

  started: (r) => [`▶️ Billing service started`, ` mode: ${r.mode}`, ` version: ${r.version ?? "?"}`].join("\n"),
};

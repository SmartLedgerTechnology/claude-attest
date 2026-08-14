/**
 * Stripe event → API key lifecycle.
 *
 * Kept separate from the HTTP server so the state machine can be tested without
 * sockets, and so the rules are readable in one place.
 *
 * Two principles govern everything here:
 *
 *   DON'T TRUST THE PAYLOAD.  Events arrive out of order and are retried for up
 *     to three days. A `subscription.updated` from an hour ago can land after a
 *     `deleted`. So for anything that decides entitlement we re-fetch the
 *     subscription and act on its CURRENT state. That is what `Subscriptions:
 *     read` was granted for.
 *
 *   IDEMPOTENCY.  Stripe can deliver the same event more than once. Every
 *     handler must be safe to run repeatedly, and we additionally dedupe on
 *     `event.id`.
 */

/** Subscription statuses that mean "revoke access", per Stripe's own guidance. */
const REVOKE_STATUSES = new Set(["canceled", "unpaid", "incomplete_expired"]);
/** Statuses that still entitle the customer. `past_due` is grace, not denial. */
const ACTIVE_STATUSES = new Set(["active", "trialing", "past_due"]);

export const HANDLED_EVENTS = new Set([
  "checkout.session.completed",
  "customer.subscription.created",
  "customer.subscription.updated",
  "customer.subscription.deleted",
  "invoice.paid",
  "invoice.payment_failed",
]);

/**
 * @param event    the verified Stripe event
 * @param deps     { store, stripe, tierForPrice, seen }
 * @returns {{action: string, detail?: object, apiKey?: string}}
 */
export async function handleEvent(event, deps) {
  const { store, seen } = deps;

  // Dedupe. Stripe redelivers on any non-2xx, and on its own retry schedule.
  if (seen && (await seen.has(event.id))) return { action: "duplicate" };

  const result = await dispatch(event, deps);

  if (seen) await seen.add(event.id);
  return result;
}

async function dispatch(event, deps) {
  const { store, stripe, tierForPrice } = deps;
  const obj = event.data?.object ?? {};

  switch (event.type) {
    /**
     * First provision. Checkout only tells us a payment succeeded once, so we
     * resolve the subscription it created and take entitlement from there.
     */
    case "checkout.session.completed": {
      if (obj.mode !== "subscription") return { action: "ignored", detail: { mode: obj.mode } };
      const customerId = obj.customer;
      const subscriptionId = obj.subscription;
      if (!customerId || !subscriptionId) {
        return { action: "incomplete", detail: { customerId, subscriptionId } };
      }
      const sub = await stripe.getSubscription(subscriptionId);
      if (!ACTIVE_STATUSES.has(sub.status)) {
        return { action: "not_active_yet", detail: { status: sub.status } };
      }

      // Idempotent: a redelivered checkout event must not mint a second key.
      const existing = await store.getByCustomer(customerId);
      if (existing && existing.status !== "revoked") {
        await store.renew(customerId, {
          periodEnd: sub.current_period_end,
          tier: tierForPrice(priceOf(sub)),
          subscriptionId,
        });
        return { action: "already_provisioned", detail: { customerId } };
      }

      // Record the entitlement only. The key itself is minted when the
      // customer claims it, because a webhook has nobody to hand it to.
      const record = await store.provision({
        customerId,
        subscriptionId,
        tier: tierForPrice(priceOf(sub)),
        periodEnd: sub.current_period_end,
      });
      return { action: "provisioned", detail: record };
    }

    case "customer.subscription.created":
    case "customer.subscription.updated": {
      const customerId = obj.customer;
      if (!customerId) return { action: "incomplete" };

      // Re-fetch rather than trusting a possibly stale payload.
      const sub = await stripe.getSubscription(obj.id).catch(() => obj);

      if (REVOKE_STATUSES.has(sub.status)) {
        await store.revoke(customerId, sub.status);
        return { action: "revoked", detail: { customerId, status: sub.status } };
      }
      if (sub.status === "past_due") {
        await store.suspend(customerId, "past_due");
        return { action: "suspended", detail: { customerId, status: sub.status } };
      }
      if (ACTIVE_STATUSES.has(sub.status)) {
        const updated = await store.renew(customerId, {
          periodEnd: sub.current_period_end,
          tier: tierForPrice(priceOf(sub)),
          subscriptionId: sub.id,
        });
        // A subscription can become active for a customer we never provisioned
        // (e.g. created outside Checkout). Provision now rather than silently
        // leaving a paying customer without a key.
        if (!updated) {
          const record = await store.provision({
            customerId,
            subscriptionId: sub.id,
            tier: tierForPrice(priceOf(sub)),
            periodEnd: sub.current_period_end,
          });
          return { action: "provisioned", detail: record };
        }
        return { action: "renewed", detail: { customerId, tier: updated.tier } };
      }
      // incomplete / paused — no entitlement change yet.
      return { action: "noop", detail: { status: sub.status } };
    }

    case "customer.subscription.deleted": {
      const customerId = obj.customer;
      if (!customerId) return { action: "incomplete" };
      await store.revoke(customerId, "subscription_deleted");
      return { action: "revoked", detail: { customerId } };
    }

    /** The renewal heartbeat: push entitlement forward. */
    case "invoice.paid": {
      const customerId = obj.customer;
      const subscriptionId = subscriptionOf(obj);
      if (!customerId) return { action: "incomplete" };
      let periodEnd;
      let tier;
      if (subscriptionId) {
        const sub = await stripe.getSubscription(subscriptionId).catch(() => null);
        if (sub) {
          if (!ACTIVE_STATUSES.has(sub.status)) return { action: "noop", detail: { status: sub.status } };
          periodEnd = sub.current_period_end;
          tier = tierForPrice(priceOf(sub));
        }
      }
      const rec = await store.renew(customerId, { periodEnd, tier, subscriptionId });
      return rec ? { action: "renewed", detail: { customerId } } : { action: "unknown_customer" };
    }

    /**
     * Payment failed. Deliberately NOT a revocation: Stripe retries with Smart
     * Retries over several days, and cutting a paying customer off on the first
     * failed attempt is both hostile and usually wrong. Revocation comes later
     * via the subscription reaching `unpaid` or `canceled`.
     */
    case "invoice.payment_failed": {
      const customerId = obj.customer;
      if (!customerId) return { action: "incomplete" };
      await store.suspend(customerId, "payment_failed");
      return { action: "suspended", detail: { customerId, attempt: obj.attempt_count ?? null } };
    }

    default:
      return { action: "unhandled", detail: { type: event.type } };
  }
}

function priceOf(sub) {
  return sub?.items?.data?.[0]?.price?.id ?? sub?.items?.data?.[0]?.plan?.id ?? null;
}

/** Stripe has moved this field around between API versions; accept both shapes. */
function subscriptionOf(invoice) {
  if (typeof invoice.subscription === "string") return invoice.subscription;
  if (invoice.subscription?.id) return invoice.subscription.id;
  const line = invoice.lines?.data?.find((l) => l.subscription);
  return typeof line?.subscription === "string" ? line.subscription : line?.subscription?.id ?? null;
}

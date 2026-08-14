/**
 * Billing reconciliation.
 *
 * Webhooks are a notification mechanism, not a source of truth. They can be
 * pointed at the wrong URL, silently dropped, retried past their window, or
 * simply never configured. Any billing system that depends on every webhook
 * arriving will eventually take someone's money and give them nothing.
 *
 * So the entitlement store is treated as a CACHE of Stripe's state, and this
 * reconciler periodically re-derives it from the source:
 *
 *   - a subscription that is active but has no entitlement  -> provision it
 *   - an entitlement whose subscription has ended           -> revoke it
 *   - an active subscription whose entitlement has drifted  -> renew it
 *
 * That makes correct behaviour independent of webhook delivery. Webhooks make
 * the system fast; reconciliation makes it right. It also covers subscriptions
 * created outside Checkout — from the Stripe dashboard, or by an invoice —
 * which have no session id and therefore no other route to provisioning.
 */

import { priceOf } from "./billing-events.mjs";

const ACTIVE = new Set(["active", "trialing", "past_due"]);
const DEAD = new Set(["canceled", "unpaid", "incomplete_expired"]);

/**
 * @param deps { store, stripe, tierForPrice, log }
 * @param opts { limit } maximum subscriptions to walk per run
 */
export async function reconcile(deps, opts = {}) {
  const { store, stripe, tierForPrice, log = () => {} } = deps;
  const summary = { scanned: 0, provisioned: 0, renewed: 0, revoked: 0, errors: 0 };

  let startingAfter = null;
  const pageLimit = opts.limit ?? 100;

  // Stripe's `status=all` includes ended subscriptions, which is what lets a
  // single pass both provision the missing and revoke the departed.
  for (let page = 0; page < (opts.maxPages ?? 20); page++) {
    let batch;
    try {
      batch = await stripe.listSubscriptions({ limit: pageLimit, startingAfter, status: "all" });
    } catch (e) {
      log(`reconcile: cannot list subscriptions: ${e.message}`);
      summary.errors++;
      break;
    }
    const items = batch?.data ?? [];
    if (items.length === 0) break;

    for (const sub of items) {
      summary.scanned++;
      try {
        await reconcileOne(sub, { store, tierForPrice, log }, summary);
      } catch (e) {
        summary.errors++;
        log(`reconcile: ${sub.id} failed: ${e.message}`);
      }
    }

    if (!batch.has_more) break;
    startingAfter = items[items.length - 1].id;
  }

  return summary;
}

async function reconcileOne(sub, { store, tierForPrice, log }, summary) {
  const customerId = typeof sub.customer === "string" ? sub.customer : sub.customer?.id;
  if (!customerId) return;

  const tier = tierForPrice(priceOf(sub));
  // This Stripe account hosts several unrelated products. A subscription we do
  // not recognize is somebody else's customer, and provisioning them would hand
  // out our product for free — so unknown prices are skipped entirely, in both
  // directions. Never provision, never revoke, on a subscription that isn't ours.
  if (!tier) return;

  const existing = await store.getByCustomer(customerId);

  if (ACTIVE.has(sub.status)) {
    if (!existing) {
      await store.provision({
        customerId,
        subscriptionId: sub.id,
        tier,
        periodEnd: sub.current_period_end,
      });
      summary.provisioned++;
      // Worth a loud log: it means a paying customer had no entitlement, which
      // is exactly the failure webhooks were supposed to prevent.
      log(`reconcile: PROVISIONED ${customerId} (${sub.id}, ${sub.status}) — had no entitlement`);
      return;
    }
    // A revoked entitlement whose subscription is active again (reactivation,
    // or a webhook we processed out of order) must come back.
    const stale =
      existing.status === "revoked" ||
      existing.status === "past_due" ||
      expiresBefore(existing.accessExpiresAt, sub.current_period_end);
    if (stale) {
      await store.renew(customerId, { periodEnd: sub.current_period_end, tier, subscriptionId: sub.id });
      summary.renewed++;
      log(`reconcile: renewed ${customerId} (${sub.id}, ${sub.status})`);
    }
    return;
  }

  if (DEAD.has(sub.status) && existing && existing.status !== "revoked") {
    // Only revoke when this entitlement actually belongs to the dead
    // subscription. A customer who cancelled once and resubscribed has a newer
    // subscription, and the old one's death must not take the new one down.
    if (existing.subscriptionId && existing.subscriptionId !== sub.id) return;
    await store.revoke(customerId, `reconcile:${sub.status}`);
    summary.revoked++;
    log(`reconcile: revoked ${customerId} (${sub.id}, ${sub.status})`);
  }
}

/** True when stored entitlement ends meaningfully before the paid period does. */
function expiresBefore(accessExpiresAt, periodEnd) {
  if (!accessExpiresAt || !Number.isFinite(periodEnd)) return false;
  const stored = Date.parse(accessExpiresAt);
  if (!Number.isFinite(stored)) return true;
  // The store adds leeway past period end; only treat a gap beyond that as drift.
  return stored < periodEnd * 1000;
}

/**
 * Subscription/Billing Routes
 * Wave 3 Billing & Onboarding (Task 3.3)
 *
 * Provides endpoints for:
 * - GET /api/billing/subscription - Get current subscription
 * - GET /api/billing/plans - List available plans
 * - POST /api/billing/checkout - Create checkout session
 * - POST /api/billing/portal - Create customer portal session
 * - POST /api/billing/webhook - Stripe webhook handler
 * - GET /api/billing/invoices - List invoices
 * - GET /api/billing/usage - Get current usage
 * - POST /api/billing/cancel - Cancel subscription
 */

import express from "express";
import { z } from "zod";
import {
  isStripeConfigured,
  PRICE_IDS,
  getPriceIdForPlan,
  createCheckoutSession,
  createPortalSession,
  getSubscription,
  cancelSubscription,
  reactivateSubscription,
  listInvoices,
  verifyWebhookSignature,
  handleWebhook,
} from "../billing/stripe.js";
import { audit, subscriptions, usage, tenantMemberships } from "../db/index.js";
import { PLANS, getPlan, TRACKABLE_RESOURCES, RESOURCE_LABELS } from "../lib/quotas.js";
import { validate } from "../lib/schemas.js";
import { requireUser } from "../middleware/auth.js";
import {
  detectTenant,
  requireTenant,
  requireTenantOwnerRole,
} from "../middleware/tenant-context.js";

const router = express.Router();

// ============================================================
// VALIDATION SCHEMAS
// ============================================================

const checkoutSchema = z.object({
  plan: z.enum(["pro", "enterprise"]),
});

const cancelSchema = z.object({
  immediately: z.boolean().optional().default(false),
});

// ============================================================
// GET /api/billing/subscription - Get current subscription
// ============================================================

/**
 * Get current subscription for the tenant
 * Requires authenticated user with tenant context
 * Returns plan, status, period dates, features
 */
router.get("/subscription", requireUser, detectTenant, requireTenant, async (req, res) => {
  try {
    const tenantId = req.tenantId;

    // Get subscription from database
    const subscription = await subscriptions.findByTenantId(tenantId);

    if (!subscription) {
      // No subscription record - return free plan defaults
      const freePlan = getPlan("free");
      return res.json({
        plan: "free",
        planName: freePlan.name,
        status: "active",
        limits: freePlan.limits,
        currentPeriodStart: null,
        currentPeriodEnd: null,
        cancelAtPeriodEnd: false,
        stripeConfigured: isStripeConfigured(),
      });
    }

    // Get plan details
    const plan = getPlan(subscription.plan);

    // Optionally fetch live data from Stripe
    let stripeData = null;
    if (subscription.stripe_subscription_id && isStripeConfigured()) {
      try {
        stripeData = await getSubscription(subscription.stripe_subscription_id);
      } catch (err) {
        console.error("[billing] Failed to fetch Stripe subscription:", err.message);
      }
    }

    res.json({
      plan: subscription.plan,
      planName: plan.name,
      status: subscription.status,
      limits: plan.limits,
      currentPeriodStart: subscription.current_period_start,
      currentPeriodEnd: subscription.current_period_end,
      cancelAtPeriodEnd: subscription.cancel_at_period_end,
      stripeConfigured: isStripeConfigured(),
      stripeCustomerId: subscription.stripe_customer_id || null,
      stripeSubscriptionId: subscription.stripe_subscription_id || null,
      // Include Stripe live data if available
      stripeStatus: stripeData?.status || null,
      paymentMethod: stripeData?.default_payment_method
        ? {
            brand: stripeData.default_payment_method.card?.brand,
            last4: stripeData.default_payment_method.card?.last4,
            expMonth: stripeData.default_payment_method.card?.exp_month,
            expYear: stripeData.default_payment_method.card?.exp_year,
          }
        : null,
    });
  } catch (err) {
    console.error("[billing] Error getting subscription:", err);
    res.status(500).json({ error: "Failed to get subscription" });
  }
});

// ============================================================
// GET /api/billing/plans - List available plans
// ============================================================

/**
 * List all available plans with pricing and features
 * Public route (no auth required)
 */
router.get("/plans", async (req, res) => {
  try {
    const plans = [];

    for (const [planId, plan] of Object.entries(PLANS)) {
      const planData = {
        id: planId,
        name: plan.name,
        limits: plan.limits,
        features: formatFeatures(plan.limits),
        priceId: PRICE_IDS[planId] || null,
        // Note: Actual pricing is managed in Stripe
        // Frontend can fetch price details if needed
      };

      plans.push(planData);
    }

    res.json({
      plans,
      stripeConfigured: isStripeConfigured(),
    });
  } catch (err) {
    console.error("[billing] Error listing plans:", err);
    res.status(500).json({ error: "Failed to list plans" });
  }
});

/**
 * Format plan limits into user-friendly features list
 */
function formatFeatures(limits) {
  const features = [];

  for (const [key, value] of Object.entries(limits)) {
    const label = RESOURCE_LABELS[key] || key;
    if (value === -1) {
      features.push(`Unlimited ${label.toLowerCase()}`);
    } else {
      features.push(`Up to ${value} ${label.toLowerCase()}`);
    }
  }

  return features;
}

// ============================================================
// POST /api/billing/checkout - Create checkout session
// ============================================================

/**
 * Create a Stripe checkout session for upgrading to a paid plan
 * Requires tenant owner
 */
router.post(
  "/checkout",
  requireUser,
  detectTenant,
  requireTenant,
  requireTenantOwnerRole,
  validate({ body: checkoutSchema }),
  async (req, res) => {
    try {
      if (!isStripeConfigured()) {
        return res.status(503).json({
          error: "Billing not configured",
          code: "BILLING_NOT_CONFIGURED",
          message: "Stripe is not configured. Contact support to upgrade your plan.",
        });
      }

      const { plan } = req.validatedBody;
      const tenant = req.tenant;

      // Check if price ID is configured for this plan
      const priceId = getPriceIdForPlan(plan);
      if (!priceId) {
        return res.status(400).json({
          error: "Plan not available",
          code: "PLAN_NOT_AVAILABLE",
          message: `The ${plan} plan is not currently available. Contact support.`,
        });
      }

      // Get base URL for redirects
      const baseUrl = process.env.USER_UI_URL || "http://localhost:5173";
      const successUrl = `${baseUrl}/billing?success=true&session_id={CHECKOUT_SESSION_ID}`;
      const cancelUrl = `${baseUrl}/billing?canceled=true`;

      // Create checkout session
      const session = await createCheckoutSession(tenant, priceId, successUrl, cancelUrl, {
        email: req.user.email,
        allowPromotionCodes: true,
      });

      // Audit log
      await audit.log(
        req.user.id,
        "billing.checkout.created",
        {
          tenantId: tenant.id,
          plan,
          sessionId: session.id,
        },
        req.ip,
      );

      res.json({
        url: session.url,
        sessionId: session.id,
      });
    } catch (err) {
      console.error("[billing] Error creating checkout session:", err);
      res.status(500).json({ error: "Failed to create checkout session" });
    }
  },
);

// ============================================================
// POST /api/billing/portal - Create customer portal session
// ============================================================

/**
 * Create a Stripe customer portal session
 * Allows managing subscription, payment methods, billing info
 * Requires tenant owner
 */
router.post(
  "/portal",
  requireUser,
  detectTenant,
  requireTenant,
  requireTenantOwnerRole,
  async (req, res) => {
    try {
      if (!isStripeConfigured()) {
        return res.status(503).json({
          error: "Billing not configured",
          code: "BILLING_NOT_CONFIGURED",
        });
      }

      const tenantId = req.tenantId;
      const subscription = await subscriptions.findByTenantId(tenantId);

      if (!subscription?.stripe_customer_id) {
        return res.status(400).json({
          error: "No billing account",
          code: "NO_BILLING_ACCOUNT",
          message: "You need to subscribe to a plan first to access the billing portal.",
        });
      }

      const baseUrl = process.env.USER_UI_URL || "http://localhost:5173";
      const returnUrl = `${baseUrl}/billing`;

      const portalSession = await createPortalSession(subscription.stripe_customer_id, returnUrl);

      // Audit log
      await audit.log(req.user.id, "billing.portal.created", { tenantId }, req.ip);

      res.json({
        url: portalSession.url,
      });
    } catch (err) {
      console.error("[billing] Error creating portal session:", err);
      res.status(500).json({ error: "Failed to create portal session" });
    }
  },
);

// ============================================================
// POST /api/billing/webhook - Stripe webhook handler
// ============================================================

/**
 * Handle Stripe webhook events
 * Requires raw body for signature verification
 * No auth required (Stripe verifies via signature)
 *
 * Note: This route needs raw body parsing, which should be
 * configured in server.js before JSON body parsing:
 *
 *   app.use('/api/billing/webhook', express.raw({ type: 'application/json' }));
 */
router.post("/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    const signature = req.headers["stripe-signature"];

    if (!signature) {
      return res.status(400).json({ error: "Missing Stripe signature" });
    }

    // Verify signature and construct event
    let event;
    try {
      event = verifyWebhookSignature(req.body, signature);
    } catch (err) {
      console.error("[billing] Webhook signature verification failed:", err.message);
      return res.status(400).json({ error: "Invalid signature" });
    }

    // Handle the event
    const result = await handleWebhook(event);

    console.log(`[billing] Webhook processed: ${event.type}`, result);

    // Acknowledge receipt
    res.json({ received: true, ...result });
  } catch (err) {
    console.error("[billing] Webhook error:", err);
    // Still return 200 to prevent Stripe retries for application errors
    res.status(200).json({ received: true, error: err.message });
  }
});

// ============================================================
// GET /api/billing/invoices - List invoices
// ============================================================

/**
 * List recent invoices for the tenant
 * Requires authenticated user with tenant context
 */
router.get("/invoices", requireUser, detectTenant, requireTenant, async (req, res) => {
  try {
    if (!isStripeConfigured()) {
      return res.json({ invoices: [] });
    }

    const tenantId = req.tenantId;
    const subscription = await subscriptions.findByTenantId(tenantId);

    if (!subscription?.stripe_customer_id) {
      return res.json({ invoices: [] });
    }

    const limit = Math.min(parseInt(req.query.limit) || 10, 100);
    const invoiceList = await listInvoices(subscription.stripe_customer_id, { limit });

    // Map to simplified format
    const invoices = invoiceList.data.map((inv) => ({
      id: inv.id,
      number: inv.number,
      status: inv.status,
      amount: inv.amount_paid / 100, // Convert cents to dollars
      currency: inv.currency.toUpperCase(),
      created: new Date(inv.created * 1000).toISOString(),
      periodStart: inv.period_start ? new Date(inv.period_start * 1000).toISOString() : null,
      periodEnd: inv.period_end ? new Date(inv.period_end * 1000).toISOString() : null,
      pdfUrl: inv.invoice_pdf,
      hostedUrl: inv.hosted_invoice_url,
    }));

    res.json({ invoices });
  } catch (err) {
    console.error("[billing] Error listing invoices:", err);
    res.status(500).json({ error: "Failed to list invoices" });
  }
});

// ============================================================
// GET /api/billing/usage - Get current usage
// ============================================================

/**
 * Get current usage for the tenant vs plan limits
 * Returns usage statistics for all tracked resources
 * Requires authenticated user with tenant context
 */
router.get("/usage", requireUser, detectTenant, requireTenant, async (req, res) => {
  try {
    const tenantId = req.tenantId;

    // Get current plan
    const subscription = await subscriptions.findByTenantId(tenantId);
    const planName = subscription?.plan || "free";
    const plan = getPlan(planName);

    // Calculate usage for each resource
    const usageData = {};

    for (const resource of TRACKABLE_RESOURCES) {
      const limit = plan.limits[resource];
      const current = await getResourceUsage(tenantId, resource);

      usageData[resource] = {
        label: RESOURCE_LABELS[resource] || resource,
        current,
        limit,
        unlimited: limit === -1,
        percentage: limit === -1 ? 0 : Math.min(100, Math.round((current / limit) * 100)),
        remaining: limit === -1 ? -1 : Math.max(0, limit - current),
      };
    }

    res.json({
      plan: planName,
      planName: plan.name,
      usage: usageData,
    });
  } catch (err) {
    console.error("[billing] Error getting usage:", err);
    res.status(500).json({ error: "Failed to get usage" });
  }
});

/**
 * Get current usage count for a resource
 * Queries appropriate tables based on resource type
 */
async function getResourceUsage(tenantId, resource) {
  // Import db functions dynamically to avoid circular dependencies
  const { query } = await import("../db/core.js");

  switch (resource) {
    case "users": {
      const result = await query(
        `SELECT COUNT(*)::int as count FROM tenant_memberships WHERE tenant_id = $1`,
        [tenantId],
      );
      return result.rows[0]?.count || 0;
    }

    case "agents": {
      // Count users with active containers in this tenant
      const result = await query(
        `SELECT COUNT(*)::int as count FROM users u
         INNER JOIN tenant_memberships tm ON u.id = tm.user_id
         WHERE tm.tenant_id = $1 AND u.container_id IS NOT NULL`,
        [tenantId],
      );
      return result.rows[0]?.count || 0;
    }

    case "api_calls_per_month": {
      // Sum API calls for all users in tenant this month
      const result = await query(
        `SELECT COALESCE(SUM(u.api_calls), 0)::int as count
         FROM usage u
         INNER JOIN tenant_memberships tm ON u.user_id = tm.user_id
         WHERE tm.tenant_id = $1
           AND u.date >= date_trunc('month', CURRENT_DATE)`,
        [tenantId],
      );
      return result.rows[0]?.count || 0;
    }

    case "storage_mb": {
      // TODO: Implement storage tracking
      // For now, return 0
      return 0;
    }

    case "groups": {
      const result = await query(`SELECT COUNT(*)::int as count FROM groups WHERE tenant_id = $1`, [
        tenantId,
      ]);
      return result.rows[0]?.count || 0;
    }

    case "resources_per_group": {
      // Get max resources in any single group
      const result = await query(
        `SELECT COALESCE(MAX(resource_count), 0)::int as count FROM (
           SELECT group_id, COUNT(*)::int as resource_count
           FROM group_resources gr
           INNER JOIN groups g ON gr.group_id = g.id
           WHERE g.tenant_id = $1
           GROUP BY group_id
         ) sub`,
        [tenantId],
      );
      return result.rows[0]?.count || 0;
    }

    default:
      return 0;
  }
}

// ============================================================
// POST /api/billing/cancel - Cancel subscription
// ============================================================

/**
 * Cancel the current subscription
 * Can cancel immediately or at end of billing period
 * Requires tenant owner
 */
router.post(
  "/cancel",
  requireUser,
  detectTenant,
  requireTenant,
  requireTenantOwnerRole,
  validate({ body: cancelSchema }),
  async (req, res) => {
    try {
      if (!isStripeConfigured()) {
        return res.status(503).json({
          error: "Billing not configured",
          code: "BILLING_NOT_CONFIGURED",
        });
      }

      const { immediately } = req.validatedBody;
      const tenantId = req.tenantId;
      const subscription = await subscriptions.findByTenantId(tenantId);

      if (!subscription?.stripe_subscription_id) {
        return res.status(400).json({
          error: "No active subscription",
          code: "NO_SUBSCRIPTION",
          message: "You don't have an active subscription to cancel.",
        });
      }

      // Cancel via Stripe
      const canceledSub = await cancelSubscription(
        subscription.stripe_subscription_id,
        immediately,
      );

      // Update local record
      if (immediately) {
        await subscriptions.update(subscription.id, {
          status: "canceled",
          plan: "free",
        });
      } else {
        await subscriptions.update(subscription.id, {
          cancel_at_period_end: true,
        });
      }

      // Audit log
      await audit.log(
        req.user.id,
        "billing.subscription.canceled",
        {
          tenantId,
          immediately,
          effectiveDate: immediately ? new Date().toISOString() : subscription.current_period_end,
        },
        req.ip,
      );

      res.json({
        success: true,
        message: immediately
          ? "Subscription canceled immediately. You have been downgraded to the free plan."
          : "Subscription will be canceled at the end of the current billing period.",
        canceledAt: immediately ? new Date().toISOString() : null,
        cancelAtPeriodEnd: !immediately,
        currentPeriodEnd: subscription.current_period_end,
      });
    } catch (err) {
      console.error("[billing] Error canceling subscription:", err);
      res.status(500).json({ error: "Failed to cancel subscription" });
    }
  },
);

// ============================================================
// POST /api/billing/resume - Resume canceled subscription
// ============================================================

/**
 * Resume a subscription that was set to cancel at period end
 * Requires tenant owner
 */
router.post(
  "/resume",
  requireUser,
  detectTenant,
  requireTenant,
  requireTenantOwnerRole,
  async (req, res) => {
    try {
      if (!isStripeConfigured()) {
        return res.status(503).json({
          error: "Billing not configured",
          code: "BILLING_NOT_CONFIGURED",
        });
      }

      const tenantId = req.tenantId;
      const subscription = await subscriptions.findByTenantId(tenantId);

      if (!subscription?.stripe_subscription_id) {
        return res.status(400).json({
          error: "No subscription to resume",
          code: "NO_SUBSCRIPTION",
        });
      }

      if (!subscription.cancel_at_period_end) {
        return res.status(400).json({
          error: "Subscription is not scheduled to cancel",
          code: "NOT_CANCELING",
        });
      }

      // Resume via Stripe
      await reactivateSubscription(subscription.stripe_subscription_id);

      // Update local record
      await subscriptions.update(subscription.id, {
        cancel_at_period_end: false,
      });

      // Audit log
      await audit.log(req.user.id, "billing.subscription.resumed", { tenantId }, req.ip);

      res.json({
        success: true,
        message: "Subscription has been resumed and will continue after the current period.",
      });
    } catch (err) {
      console.error("[billing] Error resuming subscription:", err);
      res.status(500).json({ error: "Failed to resume subscription" });
    }
  },
);

export default router;

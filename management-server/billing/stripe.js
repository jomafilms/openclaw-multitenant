/**
 * Stripe Billing Integration
 *
 * Provides:
 * - Customer management (create, get, update)
 * - Subscription management (create, get, update, cancel, reactivate)
 * - Checkout sessions (Stripe Checkout, Customer Portal)
 * - Webhook handling (signature verification, event processing)
 * - Price configuration (plan to price ID mapping)
 * - Usage-based billing (metered usage reporting)
 *
 * Environment variables:
 * - STRIPE_SECRET_KEY: Stripe API secret key
 * - STRIPE_WEBHOOK_SECRET: Webhook signing secret
 * - STRIPE_PRICE_PRO: Price ID for Pro plan
 * - STRIPE_PRICE_ENTERPRISE: Price ID for Enterprise plan
 */

import Stripe from "stripe";
import { subscriptions } from "../db/subscriptions.js";

// ============================================================
// STRIPE CLIENT INITIALIZATION
// ============================================================

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

// Initialize Stripe client (lazy - only when needed)
let stripeClient = null;

/**
 * Get the Stripe client instance
 * Throws if STRIPE_SECRET_KEY is not configured
 * @returns {Stripe} Stripe client instance
 */
function getStripe() {
  if (!stripeClient) {
    if (!STRIPE_SECRET_KEY) {
      throw new Error("STRIPE_SECRET_KEY environment variable is required");
    }
    stripeClient = new Stripe(STRIPE_SECRET_KEY, {
      apiVersion: "2024-12-18.acacia",
    });
  }
  return stripeClient;
}

/**
 * Check if Stripe is configured
 * @returns {boolean} True if Stripe credentials are present
 */
export function isStripeConfigured() {
  return Boolean(STRIPE_SECRET_KEY);
}

// ============================================================
// PRICE CONFIGURATION
// ============================================================

/**
 * Map plan names to Stripe price IDs
 * Reads from environment variables with fallback to empty string
 */
export const PRICE_IDS = {
  pro: process.env.STRIPE_PRICE_PRO || "",
  enterprise: process.env.STRIPE_PRICE_ENTERPRISE || "",
};

/**
 * Get Stripe price ID for a plan
 * @param {string} plan - Plan name (pro, enterprise)
 * @returns {string|null} Price ID or null if not found
 */
export function getPriceIdForPlan(plan) {
  const priceId = PRICE_IDS[plan?.toLowerCase()];
  if (!priceId) {
    return null;
  }
  return priceId;
}

/**
 * Get plan name from Stripe price ID
 * @param {string} priceId - Stripe price ID
 * @returns {string} Plan name or 'free' if not found
 */
export function getPlanFromPriceId(priceId) {
  for (const [plan, id] of Object.entries(PRICE_IDS)) {
    if (id === priceId) {
      return plan;
    }
  }
  return "free";
}

// ============================================================
// CUSTOMER MANAGEMENT
// ============================================================

/**
 * Create a Stripe customer for a tenant
 * @param {object} tenant - Tenant object with id, name, slug
 * @param {string} email - Customer email address
 * @returns {Promise<Stripe.Customer>} Created customer
 */
export async function createCustomer(tenant, email) {
  const stripe = getStripe();

  const customer = await stripe.customers.create({
    email,
    name: tenant.name,
    metadata: {
      tenant_id: tenant.id,
      tenant_slug: tenant.slug,
    },
  });

  // Link customer to tenant subscription
  await subscriptions.linkStripeCustomer(tenant.id, customer.id);

  return customer;
}

/**
 * Get Stripe customer by ID
 * @param {string} customerId - Stripe customer ID
 * @returns {Promise<Stripe.Customer>} Customer object
 */
export async function getCustomer(customerId) {
  const stripe = getStripe();
  return stripe.customers.retrieve(customerId);
}

/**
 * Update Stripe customer
 * @param {string} customerId - Stripe customer ID
 * @param {object} updates - Fields to update (email, name, metadata, etc.)
 * @returns {Promise<Stripe.Customer>} Updated customer
 */
export async function updateCustomer(customerId, updates) {
  const stripe = getStripe();

  const allowedFields = ["email", "name", "metadata", "description", "phone"];
  const filteredUpdates = {};

  for (const [key, value] of Object.entries(updates)) {
    if (allowedFields.includes(key)) {
      filteredUpdates[key] = value;
    }
  }

  return stripe.customers.update(customerId, filteredUpdates);
}

// ============================================================
// SUBSCRIPTION MANAGEMENT
// ============================================================

/**
 * Create a subscription for a customer
 * Uses payment_behavior: 'default_incomplete' for SCA compliance
 * @param {string} customerId - Stripe customer ID
 * @param {string} priceId - Stripe price ID
 * @param {object} options - Additional options
 * @param {string} options.trialDays - Trial period in days
 * @returns {Promise<Stripe.Subscription>} Created subscription with payment intent
 */
export async function createSubscription(customerId, priceId, options = {}) {
  const stripe = getStripe();

  const subscriptionParams = {
    customer: customerId,
    items: [{ price: priceId }],
    payment_behavior: "default_incomplete",
    payment_settings: {
      save_default_payment_method: "on_subscription",
    },
    expand: ["latest_invoice.payment_intent"],
  };

  // Add trial period if specified
  if (options.trialDays && options.trialDays > 0) {
    subscriptionParams.trial_period_days = options.trialDays;
  }

  const subscription = await stripe.subscriptions.create(subscriptionParams);

  // Get tenant ID from customer metadata
  const customer = await getCustomer(customerId);
  const tenantId = customer.metadata?.tenant_id;

  if (tenantId) {
    // Link subscription to tenant
    await subscriptions.linkStripeSubscription(tenantId, subscription.id);

    // Update plan based on price ID
    const plan = getPlanFromPriceId(priceId);
    if (plan !== "free") {
      await subscriptions.setPlan(tenantId, plan);
    }
  }

  return subscription;
}

/**
 * Get subscription by ID
 * @param {string} subscriptionId - Stripe subscription ID
 * @returns {Promise<Stripe.Subscription>} Subscription object
 */
export async function getSubscription(subscriptionId) {
  const stripe = getStripe();
  return stripe.subscriptions.retrieve(subscriptionId, {
    expand: ["latest_invoice.payment_intent", "customer"],
  });
}

/**
 * Update a subscription
 * Common use cases: change plan, update payment method
 * @param {string} subscriptionId - Stripe subscription ID
 * @param {object} updates - Fields to update
 * @returns {Promise<Stripe.Subscription>} Updated subscription
 */
export async function updateSubscription(subscriptionId, updates) {
  const stripe = getStripe();

  const subscriptionParams = {};

  // Handle plan change (new price)
  if (updates.priceId) {
    const subscription = await stripe.subscriptions.retrieve(subscriptionId);
    subscriptionParams.items = [
      {
        id: subscription.items.data[0].id,
        price: updates.priceId,
      },
    ];
    subscriptionParams.proration_behavior = updates.proration || "create_prorations";
  }

  // Handle other allowed fields
  const allowedFields = ["cancel_at_period_end", "default_payment_method", "metadata"];
  for (const [key, value] of Object.entries(updates)) {
    if (allowedFields.includes(key)) {
      subscriptionParams[key] = value;
    }
  }

  return stripe.subscriptions.update(subscriptionId, subscriptionParams);
}

/**
 * Cancel a subscription
 * @param {string} subscriptionId - Stripe subscription ID
 * @param {boolean} immediately - Cancel immediately or at period end (default: false)
 * @returns {Promise<Stripe.Subscription>} Canceled subscription
 */
export async function cancelSubscription(subscriptionId, immediately = false) {
  const stripe = getStripe();

  if (immediately) {
    return stripe.subscriptions.cancel(subscriptionId);
  }

  // Cancel at period end
  return stripe.subscriptions.update(subscriptionId, {
    cancel_at_period_end: true,
  });
}

/**
 * Reactivate a subscription that was scheduled to cancel
 * Only works if cancel_at_period_end was set to true
 * @param {string} subscriptionId - Stripe subscription ID
 * @returns {Promise<Stripe.Subscription>} Reactivated subscription
 */
export async function reactivateSubscription(subscriptionId) {
  const stripe = getStripe();

  const subscription = await stripe.subscriptions.retrieve(subscriptionId);

  // Can only reactivate if scheduled to cancel, not already canceled
  if (subscription.status === "canceled") {
    throw new Error(
      "Cannot reactivate a canceled subscription. Create a new subscription instead.",
    );
  }

  return stripe.subscriptions.update(subscriptionId, {
    cancel_at_period_end: false,
  });
}

// ============================================================
// CHECKOUT SESSIONS
// ============================================================

/**
 * Create a Stripe Checkout session for subscription signup
 * @param {object} tenant - Tenant object with id, name, slug
 * @param {string} priceId - Stripe price ID
 * @param {string} successUrl - URL to redirect on success
 * @param {string} cancelUrl - URL to redirect on cancel
 * @param {object} options - Additional options
 * @returns {Promise<Stripe.Checkout.Session>} Checkout session
 */
export async function createCheckoutSession(tenant, priceId, successUrl, cancelUrl, options = {}) {
  const stripe = getStripe();

  // Check if tenant already has a Stripe customer
  const subscription = await subscriptions.findByTenantId(tenant.id);
  let customerId = subscription?.stripe_customer_id;

  // Build checkout session params
  const sessionParams = {
    mode: "subscription",
    line_items: [
      {
        price: priceId,
        quantity: 1,
      },
    ],
    success_url: successUrl,
    cancel_url: cancelUrl,
    subscription_data: {
      metadata: {
        tenant_id: tenant.id,
        tenant_slug: tenant.slug,
      },
    },
    metadata: {
      tenant_id: tenant.id,
      tenant_slug: tenant.slug,
    },
  };

  // Use existing customer or create new one
  if (customerId) {
    sessionParams.customer = customerId;
  } else {
    sessionParams.customer_creation = "always";
    sessionParams.customer_email = options.email;
  }

  // Add trial if specified
  if (options.trialDays && options.trialDays > 0) {
    sessionParams.subscription_data.trial_period_days = options.trialDays;
  }

  // Allow promotion codes
  if (options.allowPromotionCodes) {
    sessionParams.allow_promotion_codes = true;
  }

  return stripe.checkout.sessions.create(sessionParams);
}

/**
 * Create a Customer Portal session
 * Allows customers to manage their subscription, payment methods, billing info
 * @param {string} customerId - Stripe customer ID
 * @param {string} returnUrl - URL to return to after portal session
 * @returns {Promise<Stripe.BillingPortal.Session>} Portal session
 */
export async function createPortalSession(customerId, returnUrl) {
  const stripe = getStripe();

  return stripe.billingPortal.sessions.create({
    customer: customerId,
    return_url: returnUrl,
  });
}

// ============================================================
// WEBHOOK HANDLING
// ============================================================

/**
 * Verify Stripe webhook signature
 * @param {string|Buffer} payload - Raw request body
 * @param {string} signature - Stripe-Signature header value
 * @returns {Stripe.Event} Verified event
 * @throws {Error} If signature is invalid
 */
export function verifyWebhookSignature(payload, signature) {
  const stripe = getStripe();

  if (!STRIPE_WEBHOOK_SECRET) {
    throw new Error(
      "STRIPE_WEBHOOK_SECRET environment variable is required for webhook verification",
    );
  }

  return stripe.webhooks.constructEvent(payload, signature, STRIPE_WEBHOOK_SECRET);
}

/**
 * Handle a verified webhook event
 * Syncs subscription state with local database
 * @param {Stripe.Event} event - Verified Stripe event
 * @returns {Promise<object>} Processing result
 */
export async function handleWebhook(event) {
  const result = {
    type: event.type,
    processed: false,
    message: "",
  };

  switch (event.type) {
    case "customer.subscription.created":
    case "customer.subscription.updated": {
      const subscription = event.data.object;
      await syncSubscriptionStatus(subscription);
      result.processed = true;
      result.message = `Synced subscription ${subscription.id}`;
      break;
    }

    case "customer.subscription.deleted": {
      const subscription = event.data.object;
      await handleSubscriptionDeleted(subscription);
      result.processed = true;
      result.message = `Processed cancellation for subscription ${subscription.id}`;
      break;
    }

    case "invoice.paid": {
      const invoice = event.data.object;
      await handleInvoicePaid(invoice);
      result.processed = true;
      result.message = `Recorded payment for invoice ${invoice.id}`;
      break;
    }

    case "invoice.payment_failed": {
      const invoice = event.data.object;
      await handlePaymentFailed(invoice);
      result.processed = true;
      result.message = `Recorded payment failure for invoice ${invoice.id}`;
      break;
    }

    case "checkout.session.completed": {
      const session = event.data.object;
      await handleCheckoutCompleted(session);
      result.processed = true;
      result.message = `Processed checkout session ${session.id}`;
      break;
    }

    default:
      result.message = `Unhandled event type: ${event.type}`;
  }

  return result;
}

/**
 * Sync subscription status from Stripe to local database
 * @param {Stripe.Subscription} stripeSubscription - Stripe subscription object
 */
async function syncSubscriptionStatus(stripeSubscription) {
  const priceId = stripeSubscription.items.data[0]?.price?.id;
  const plan = getPlanFromPriceId(priceId);

  await subscriptions.updateFromStripeWebhook(stripeSubscription.id, {
    status: stripeSubscription.status,
    plan,
    currentPeriodStart: stripeSubscription.current_period_start,
    currentPeriodEnd: stripeSubscription.current_period_end,
    cancelAtPeriodEnd: stripeSubscription.cancel_at_period_end,
  });
}

/**
 * Handle subscription deletion (cancellation completed)
 * @param {Stripe.Subscription} stripeSubscription - Stripe subscription object
 */
async function handleSubscriptionDeleted(stripeSubscription) {
  await subscriptions.updateFromStripeWebhook(stripeSubscription.id, {
    status: "canceled",
    cancelAtPeriodEnd: false,
  });

  // Downgrade to free plan
  const sub = await subscriptions.findByStripeSubscriptionId(stripeSubscription.id);
  if (sub) {
    await subscriptions.setPlan(sub.tenant_id, "free");
  }
}

/**
 * Handle successful invoice payment
 * @param {Stripe.Invoice} invoice - Stripe invoice object
 */
async function handleInvoicePaid(invoice) {
  // If this is a subscription invoice, ensure subscription is active
  if (invoice.subscription) {
    const sub = await subscriptions.findByStripeSubscriptionId(invoice.subscription);
    if (sub && sub.status !== "active") {
      await subscriptions.setStatus(sub.tenant_id, "active");
    }
  }
}

/**
 * Handle failed invoice payment
 * @param {Stripe.Invoice} invoice - Stripe invoice object
 */
async function handlePaymentFailed(invoice) {
  if (invoice.subscription) {
    const sub = await subscriptions.findByStripeSubscriptionId(invoice.subscription);
    if (sub) {
      await subscriptions.setStatus(sub.tenant_id, "past_due");
    }
  }
}

/**
 * Handle completed checkout session
 * Links new customer/subscription to tenant
 * @param {Stripe.Checkout.Session} session - Stripe checkout session
 */
async function handleCheckoutCompleted(session) {
  const tenantId = session.metadata?.tenant_id;
  if (!tenantId) {
    console.warn("[stripe] Checkout session completed without tenant_id in metadata");
    return;
  }

  // Link customer if new
  if (session.customer) {
    await subscriptions.linkStripeCustomer(tenantId, session.customer);
  }

  // Link subscription if subscription mode
  if (session.subscription) {
    await subscriptions.linkStripeSubscription(tenantId, session.subscription);

    // Fetch subscription to get plan details
    const stripe = getStripe();
    const subscription = await stripe.subscriptions.retrieve(session.subscription);
    const priceId = subscription.items.data[0]?.price?.id;
    const plan = getPlanFromPriceId(priceId);

    await subscriptions.setPlan(tenantId, plan);
    await subscriptions.setStatus(tenantId, subscription.status);
  }
}

// ============================================================
// USAGE-BASED BILLING
// ============================================================

/**
 * Report usage for metered billing
 * @param {string} subscriptionItemId - Stripe subscription item ID
 * @param {number} quantity - Usage quantity to report
 * @param {string} action - 'set' (replace) or 'increment' (add)
 * @param {object} options - Additional options
 * @param {number} options.timestamp - Unix timestamp for usage (default: now)
 * @returns {Promise<Stripe.UsageRecord>} Created usage record
 */
export async function reportUsage(subscriptionItemId, quantity, action = "set", options = {}) {
  const stripe = getStripe();

  const usageParams = {
    quantity,
    action,
  };

  if (options.timestamp) {
    usageParams.timestamp = options.timestamp;
  }

  return stripe.subscriptionItems.createUsageRecord(subscriptionItemId, usageParams);
}

/**
 * Get usage summary for a subscription item
 * @param {string} subscriptionItemId - Stripe subscription item ID
 * @returns {Promise<Stripe.ApiList<Stripe.UsageRecordSummary>>} Usage summaries
 */
export async function getUsageSummary(subscriptionItemId) {
  const stripe = getStripe();
  return stripe.subscriptionItems.listUsageRecordSummaries(subscriptionItemId);
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

/**
 * List invoices for a customer
 * @param {string} customerId - Stripe customer ID
 * @param {object} options - Pagination options
 * @returns {Promise<Stripe.ApiList<Stripe.Invoice>>} List of invoices
 */
export async function listInvoices(customerId, options = {}) {
  const stripe = getStripe();
  return stripe.invoices.list({
    customer: customerId,
    limit: options.limit || 10,
    starting_after: options.startingAfter,
  });
}

/**
 * Get upcoming invoice for a subscription
 * Useful for showing what customer will be charged next
 * @param {string} customerId - Stripe customer ID
 * @returns {Promise<Stripe.Invoice>} Upcoming invoice
 */
export async function getUpcomingInvoice(customerId) {
  const stripe = getStripe();
  return stripe.invoices.retrieveUpcoming({ customer: customerId });
}

/**
 * List payment methods for a customer
 * @param {string} customerId - Stripe customer ID
 * @param {string} type - Payment method type (default: 'card')
 * @returns {Promise<Stripe.ApiList<Stripe.PaymentMethod>>} Payment methods
 */
export async function listPaymentMethods(customerId, type = "card") {
  const stripe = getStripe();
  return stripe.paymentMethods.list({
    customer: customerId,
    type,
  });
}

// ============================================================
// EXPORTS
// ============================================================

export default {
  // Configuration
  isStripeConfigured,
  PRICE_IDS,
  getPriceIdForPlan,
  getPlanFromPriceId,

  // Customer management
  createCustomer,
  getCustomer,
  updateCustomer,

  // Subscription management
  createSubscription,
  getSubscription,
  updateSubscription,
  cancelSubscription,
  reactivateSubscription,

  // Checkout sessions
  createCheckoutSession,
  createPortalSession,

  // Webhook handling
  verifyWebhookSignature,
  handleWebhook,

  // Usage-based billing
  reportUsage,
  getUsageSummary,

  // Utilities
  listInvoices,
  getUpcomingInvoice,
  listPaymentMethods,
};

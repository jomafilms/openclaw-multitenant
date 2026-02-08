// Subscription operations for multi-tenant billing
// Manages tenant subscriptions, Stripe integration, and plan management
import { query } from "./core.js";

// Valid subscription plans
export const SUBSCRIPTION_PLANS = ["free", "pro", "enterprise"];

// Valid subscription statuses
export const SUBSCRIPTION_STATUSES = ["active", "past_due", "canceled", "unpaid", "trialing"];

export const subscriptions = {
  // ============================================
  // CRUD Operations
  // ============================================

  /**
   * Create a new subscription for a tenant
   * @param {string} tenantId - UUID of the tenant
   * @param {string} plan - Subscription plan (free, pro, enterprise)
   * @returns {object} Created subscription
   */
  async create(tenantId, plan = "free") {
    if (!SUBSCRIPTION_PLANS.includes(plan)) {
      throw new Error(`Invalid plan: ${plan}. Must be one of: ${SUBSCRIPTION_PLANS.join(", ")}`);
    }

    const res = await query(
      `INSERT INTO subscriptions (tenant_id, plan, status)
       VALUES ($1, $2, 'active')
       RETURNING *`,
      [tenantId, plan],
    );
    return res.rows[0];
  },

  /**
   * Find subscription by UUID
   * @param {string} id - Subscription UUID
   * @returns {object|undefined} Subscription or undefined
   */
  async findById(id) {
    const res = await query("SELECT * FROM subscriptions WHERE id = $1", [id]);
    return res.rows[0];
  },

  /**
   * Find subscription by tenant ID
   * @param {string} tenantId - Tenant UUID
   * @returns {object|undefined} Subscription or undefined
   */
  async findByTenantId(tenantId) {
    const res = await query("SELECT * FROM subscriptions WHERE tenant_id = $1", [tenantId]);
    return res.rows[0];
  },

  /**
   * Find subscription by Stripe customer ID
   * @param {string} customerId - Stripe customer ID
   * @returns {object|undefined} Subscription or undefined
   */
  async findByStripeCustomerId(customerId) {
    const res = await query("SELECT * FROM subscriptions WHERE stripe_customer_id = $1", [
      customerId,
    ]);
    return res.rows[0];
  },

  /**
   * Find subscription by Stripe subscription ID
   * @param {string} subscriptionId - Stripe subscription ID
   * @returns {object|undefined} Subscription or undefined
   */
  async findByStripeSubscriptionId(subscriptionId) {
    const res = await query("SELECT * FROM subscriptions WHERE stripe_subscription_id = $1", [
      subscriptionId,
    ]);
    return res.rows[0];
  },

  /**
   * Update subscription fields
   * @param {string} id - Subscription UUID
   * @param {object} updates - Fields to update
   * @returns {object|undefined} Updated subscription or undefined
   */
  async update(id, updates) {
    const allowedFields = [
      "plan",
      "status",
      "stripe_customer_id",
      "stripe_subscription_id",
      "current_period_start",
      "current_period_end",
      "cancel_at_period_end",
    ];

    const setClauses = [];
    const values = [id];
    let paramIndex = 2;

    for (const [key, value] of Object.entries(updates)) {
      if (allowedFields.includes(key)) {
        setClauses.push(`${key} = $${paramIndex}`);
        values.push(value);
        paramIndex++;
      }
    }

    if (setClauses.length === 0) {
      return this.findById(id);
    }

    setClauses.push("updated_at = NOW()");

    const res = await query(
      `UPDATE subscriptions SET ${setClauses.join(", ")} WHERE id = $1 RETURNING *`,
      values,
    );
    return res.rows[0];
  },

  // ============================================
  // Stripe Integration Helpers
  // ============================================

  /**
   * Link a Stripe customer ID to a tenant subscription
   * @param {string} tenantId - Tenant UUID
   * @param {string} stripeCustomerId - Stripe customer ID
   * @returns {object|undefined} Updated subscription or undefined
   */
  async linkStripeCustomer(tenantId, stripeCustomerId) {
    const res = await query(
      `UPDATE subscriptions
       SET stripe_customer_id = $2, updated_at = NOW()
       WHERE tenant_id = $1
       RETURNING *`,
      [tenantId, stripeCustomerId],
    );
    return res.rows[0];
  },

  /**
   * Link a Stripe subscription ID to a tenant subscription
   * @param {string} tenantId - Tenant UUID
   * @param {string} stripeSubscriptionId - Stripe subscription ID
   * @returns {object|undefined} Updated subscription or undefined
   */
  async linkStripeSubscription(tenantId, stripeSubscriptionId) {
    const res = await query(
      `UPDATE subscriptions
       SET stripe_subscription_id = $2, updated_at = NOW()
       WHERE tenant_id = $1
       RETURNING *`,
      [tenantId, stripeSubscriptionId],
    );
    return res.rows[0];
  },

  /**
   * Update subscription from Stripe webhook data
   * Handles status, plan, and period date updates
   * @param {string} stripeSubscriptionId - Stripe subscription ID
   * @param {object} data - Webhook data { status, plan, currentPeriodStart, currentPeriodEnd, cancelAtPeriodEnd }
   * @returns {object|undefined} Updated subscription or undefined
   */
  async updateFromStripeWebhook(stripeSubscriptionId, data) {
    const { status, plan, currentPeriodStart, currentPeriodEnd, cancelAtPeriodEnd } = data;

    const setClauses = ["updated_at = NOW()"];
    const values = [stripeSubscriptionId];
    let paramIndex = 2;

    if (status !== undefined) {
      // Map Stripe statuses to our statuses
      const mappedStatus = this.mapStripeStatus(status);
      setClauses.push(`status = $${paramIndex}`);
      values.push(mappedStatus);
      paramIndex++;
    }

    if (plan !== undefined && SUBSCRIPTION_PLANS.includes(plan)) {
      setClauses.push(`plan = $${paramIndex}`);
      values.push(plan);
      paramIndex++;
    }

    if (currentPeriodStart !== undefined) {
      // Stripe timestamps are in seconds, convert to timestamp
      const timestamp =
        typeof currentPeriodStart === "number"
          ? new Date(currentPeriodStart * 1000)
          : currentPeriodStart;
      setClauses.push(`current_period_start = $${paramIndex}`);
      values.push(timestamp);
      paramIndex++;
    }

    if (currentPeriodEnd !== undefined) {
      const timestamp =
        typeof currentPeriodEnd === "number" ? new Date(currentPeriodEnd * 1000) : currentPeriodEnd;
      setClauses.push(`current_period_end = $${paramIndex}`);
      values.push(timestamp);
      paramIndex++;
    }

    if (cancelAtPeriodEnd !== undefined) {
      setClauses.push(`cancel_at_period_end = $${paramIndex}`);
      values.push(cancelAtPeriodEnd);
      paramIndex++;
    }

    const res = await query(
      `UPDATE subscriptions SET ${setClauses.join(", ")} WHERE stripe_subscription_id = $1 RETURNING *`,
      values,
    );
    return res.rows[0];
  },

  /**
   * Map Stripe subscription status to our status values
   * @param {string} stripeStatus - Status from Stripe
   * @returns {string} Our internal status
   */
  mapStripeStatus(stripeStatus) {
    const statusMap = {
      active: "active",
      past_due: "past_due",
      canceled: "canceled",
      unpaid: "unpaid",
      trialing: "trialing",
      incomplete: "unpaid",
      incomplete_expired: "canceled",
      paused: "past_due",
    };
    return statusMap[stripeStatus] || "active";
  },

  // ============================================
  // Status Management
  // ============================================

  /**
   * Update subscription status for a tenant
   * @param {string} tenantId - Tenant UUID
   * @param {string} status - New status (active, past_due, canceled, unpaid)
   * @returns {object|undefined} Updated subscription or undefined
   */
  async setStatus(tenantId, status) {
    if (!SUBSCRIPTION_STATUSES.includes(status)) {
      throw new Error(
        `Invalid status: ${status}. Must be one of: ${SUBSCRIPTION_STATUSES.join(", ")}`,
      );
    }

    const res = await query(
      `UPDATE subscriptions
       SET status = $2, updated_at = NOW()
       WHERE tenant_id = $1
       RETURNING *`,
      [tenantId, status],
    );
    return res.rows[0];
  },

  /**
   * Change subscription plan for a tenant
   * @param {string} tenantId - Tenant UUID
   * @param {string} plan - New plan (free, pro, enterprise)
   * @returns {object|undefined} Updated subscription or undefined
   */
  async setPlan(tenantId, plan) {
    if (!SUBSCRIPTION_PLANS.includes(plan)) {
      throw new Error(`Invalid plan: ${plan}. Must be one of: ${SUBSCRIPTION_PLANS.join(", ")}`);
    }

    const res = await query(
      `UPDATE subscriptions
       SET plan = $2, updated_at = NOW()
       WHERE tenant_id = $1
       RETURNING *`,
      [tenantId, plan],
    );
    return res.rows[0];
  },

  /**
   * Mark subscription to cancel at end of billing period
   * @param {string} tenantId - Tenant UUID
   * @param {boolean} cancel - Whether to cancel at period end (default: true)
   * @returns {object|undefined} Updated subscription or undefined
   */
  async cancelAtPeriodEnd(tenantId, cancel = true) {
    const res = await query(
      `UPDATE subscriptions
       SET cancel_at_period_end = $2, updated_at = NOW()
       WHERE tenant_id = $1
       RETURNING *`,
      [tenantId, cancel],
    );
    return res.rows[0];
  },

  /**
   * Check if a tenant's subscription is active
   * @param {string} tenantId - Tenant UUID
   * @returns {boolean} True if subscription is active or trialing
   */
  async isActive(tenantId) {
    const res = await query(
      `SELECT 1 FROM subscriptions
       WHERE tenant_id = $1
         AND status IN ('active', 'trialing')`,
      [tenantId],
    );
    return res.rows.length > 0;
  },

  // ============================================
  // Reporting
  // ============================================

  /**
   * List subscriptions with optional filters
   * @param {object} options - Filter options
   * @param {string} options.status - Filter by status
   * @param {string} options.plan - Filter by plan
   * @param {number} options.limit - Max results (default: 100)
   * @param {number} options.offset - Offset for pagination (default: 0)
   * @returns {array} List of subscriptions
   */
  async list({ status, plan, limit = 100, offset = 0 } = {}) {
    const conditions = [];
    const values = [];
    let paramIndex = 1;

    if (status) {
      conditions.push(`status = $${paramIndex}`);
      values.push(status);
      paramIndex++;
    }

    if (plan) {
      conditions.push(`plan = $${paramIndex}`);
      values.push(plan);
      paramIndex++;
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    values.push(limit, offset);

    const res = await query(
      `SELECT s.*, t.name as tenant_name, t.slug as tenant_slug
       FROM subscriptions s
       LEFT JOIN tenants t ON s.tenant_id = t.id
       ${whereClause}
       ORDER BY s.created_at DESC
       LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`,
      values,
    );
    return res.rows;
  },

  /**
   * Get subscription metrics - counts by plan and status
   * @returns {object} Metrics object with plan and status counts
   */
  async getMetrics() {
    const [planCounts, statusCounts, totals] = await Promise.all([
      query(`
        SELECT plan, COUNT(*)::int as count
        FROM subscriptions
        GROUP BY plan
        ORDER BY plan
      `),
      query(`
        SELECT status, COUNT(*)::int as count
        FROM subscriptions
        GROUP BY status
        ORDER BY status
      `),
      query(`
        SELECT
          COUNT(*)::int as total,
          COUNT(*) FILTER (WHERE status IN ('active', 'trialing'))::int as active,
          COUNT(*) FILTER (WHERE cancel_at_period_end = true)::int as canceling,
          SUM(CASE WHEN plan = 'pro' THEN 1 ELSE 0 END)::int as pro_count,
          SUM(CASE WHEN plan = 'enterprise' THEN 1 ELSE 0 END)::int as enterprise_count
        FROM subscriptions
      `),
    ]);

    // Convert rows to objects
    const byPlan = {};
    for (const row of planCounts.rows) {
      byPlan[row.plan] = row.count;
    }

    const byStatus = {};
    for (const row of statusCounts.rows) {
      byStatus[row.status] = row.count;
    }

    return {
      byPlan,
      byStatus,
      ...totals.rows[0],
    };
  },

  /**
   * Find subscriptions expiring within a given number of days
   * Useful for sending renewal reminders
   * @param {number} days - Number of days from now
   * @returns {array} List of subscriptions expiring soon
   */
  async findExpiringWithin(days) {
    const res = await query(
      `SELECT s.*, t.name as tenant_name, t.slug as tenant_slug
       FROM subscriptions s
       LEFT JOIN tenants t ON s.tenant_id = t.id
       WHERE s.current_period_end IS NOT NULL
         AND s.current_period_end <= NOW() + INTERVAL '1 day' * $1
         AND s.current_period_end > NOW()
         AND s.status = 'active'
         AND s.cancel_at_period_end = false
       ORDER BY s.current_period_end ASC`,
      [days],
    );
    return res.rows;
  },

  /**
   * Delete a subscription (use with caution)
   * Typically only used for cleanup of test data
   * @param {string} id - Subscription UUID
   */
  async delete(id) {
    await query("DELETE FROM subscriptions WHERE id = $1", [id]);
  },
};

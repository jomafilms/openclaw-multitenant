import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { toast } from "../components/toast.js";
import { api, User } from "../lib/api.js";

// Billing types
interface Subscription {
  id: string;
  plan: "free" | "pro" | "enterprise";
  status: "active" | "past_due" | "canceling" | "canceled" | "trialing";
  currentPeriodStart: string;
  currentPeriodEnd: string;
  cancelAtPeriodEnd: boolean;
  stripeCustomerId?: string;
  stripeSubscriptionId?: string;
}

interface UsageData {
  users: { current: number; limit: number };
  agents: { current: number; limit: number };
  apiCalls: { current: number; limit: number };
  storage: { current: number; limit: number }; // in MB
  groups: { current: number; limit: number };
}

interface Plan {
  id: string;
  name: string;
  price: number; // monthly price in cents
  yearlyPrice?: number;
  features: string[];
  limits: {
    users: number;
    agents: number;
    apiCalls: number;
    storage: number;
    groups: number;
  };
}

interface Invoice {
  id: string;
  date: string;
  amount: number; // in cents
  status: "paid" | "open" | "void" | "uncollectible";
  pdfUrl?: string;
}

@customElement("ocmt-billing")
export class BillingPage extends LitElement {
  static styles = css`
    :host {
      display: block;
      max-width: 1000px;
      margin: 0 auto;
    }

    h1 {
      font-size: 1.8rem;
      margin-bottom: 8px;
    }

    .subtitle {
      color: #888;
      margin-bottom: 32px;
    }

    .section {
      margin-bottom: 40px;
    }

    .section h2 {
      font-size: 1.1rem;
      color: #888;
      margin-bottom: 16px;
      text-transform: uppercase;
      letter-spacing: 1px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .card {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 24px;
    }

    .card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 16px;
    }

    .card-title {
      font-size: 1.2rem;
      font-weight: 600;
    }

    /* Status badges */
    .badge {
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 0.8rem;
      font-weight: 500;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .badge-active {
      background: rgba(34, 197, 94, 0.2);
      color: #22c55e;
    }

    .badge-past-due {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
    }

    .badge-canceling {
      background: rgba(234, 179, 8, 0.2);
      color: #eab308;
    }

    .badge-trialing {
      background: rgba(79, 70, 229, 0.2);
      color: #818cf8;
    }

    /* Current plan section */
    .plan-info {
      display: flex;
      align-items: center;
      gap: 16px;
      margin-bottom: 16px;
    }

    .plan-name {
      font-size: 1.5rem;
      font-weight: 700;
      color: #818cf8;
    }

    .plan-details {
      color: #888;
      font-size: 0.9rem;
    }

    /* Usage progress bars */
    .usage-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
    }

    .usage-item {
      background: rgba(255, 255, 255, 0.03);
      border-radius: 8px;
      padding: 16px;
    }

    .usage-label {
      display: flex;
      justify-content: space-between;
      margin-bottom: 8px;
      font-size: 0.9rem;
    }

    .usage-name {
      color: #ccc;
    }

    .usage-value {
      color: #888;
    }

    .progress-bar {
      height: 8px;
      background: rgba(255, 255, 255, 0.1);
      border-radius: 4px;
      overflow: hidden;
    }

    .progress-fill {
      height: 100%;
      border-radius: 4px;
      transition: width 0.3s;
    }

    .progress-green {
      background: #22c55e;
    }

    .progress-yellow {
      background: #eab308;
    }

    .progress-red {
      background: #ef4444;
    }

    /* Plan comparison cards */
    .plans-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 16px;
    }

    .plan-card {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 24px;
      position: relative;
      transition: all 0.2s;
    }

    .plan-card:hover {
      border-color: rgba(79, 70, 229, 0.3);
    }

    .plan-card.current {
      border-color: #4f46e5;
      background: rgba(79, 70, 229, 0.1);
    }

    .plan-card-header {
      text-align: center;
      margin-bottom: 20px;
      padding-bottom: 20px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    }

    .plan-card-name {
      font-size: 1.3rem;
      font-weight: 700;
      margin-bottom: 8px;
    }

    .plan-card-price {
      font-size: 2rem;
      font-weight: 700;
      color: #818cf8;
    }

    .plan-card-price span {
      font-size: 0.9rem;
      color: #888;
      font-weight: 400;
    }

    .current-badge {
      position: absolute;
      top: 12px;
      right: 12px;
      background: #4f46e5;
      color: white;
      padding: 4px 10px;
      border-radius: 10px;
      font-size: 0.75rem;
      font-weight: 600;
    }

    .plan-features {
      list-style: none;
      padding: 0;
      margin: 0 0 20px 0;
    }

    .plan-features li {
      padding: 8px 0;
      color: #ccc;
      font-size: 0.9rem;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .plan-features li::before {
      content: "\\2713";
      color: #22c55e;
      font-weight: bold;
    }

    /* Invoice list */
    .invoice-list {
      margin-top: 16px;
    }

    .invoice-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 16px;
      background: rgba(255, 255, 255, 0.03);
      border-radius: 8px;
      margin-bottom: 8px;
    }

    .invoice-info {
      display: flex;
      align-items: center;
      gap: 24px;
    }

    .invoice-date {
      color: #ccc;
      min-width: 100px;
    }

    .invoice-amount {
      font-weight: 600;
      min-width: 80px;
    }

    .invoice-status {
      font-size: 0.85rem;
    }

    .invoice-status.paid {
      color: #22c55e;
    }

    .invoice-status.open {
      color: #eab308;
    }

    /* Buttons */
    .btn {
      padding: 10px 20px;
      border-radius: 8px;
      border: none;
      font-size: 0.9rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      text-decoration: none;
    }

    .btn-primary {
      background: #4f46e5;
      color: white;
    }

    .btn-primary:hover:not(:disabled) {
      background: #4338ca;
    }

    .btn-secondary {
      background: rgba(255, 255, 255, 0.1);
      color: #ccc;
    }

    .btn-secondary:hover:not(:disabled) {
      background: rgba(255, 255, 255, 0.15);
    }

    .btn-danger {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
    }

    .btn-danger:hover:not(:disabled) {
      background: rgba(239, 68, 68, 0.3);
    }

    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .btn-sm {
      padding: 6px 12px;
      font-size: 0.85rem;
    }

    .actions {
      display: flex;
      gap: 12px;
      margin-top: 16px;
      flex-wrap: wrap;
    }

    /* Loading & empty states */
    .loading {
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 60px;
    }

    .spinner {
      width: 32px;
      height: 32px;
      border: 3px solid rgba(255, 255, 255, 0.1);
      border-top-color: #4f46e5;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }

    @keyframes spin {
      to {
        transform: rotate(360deg);
      }
    }

    .empty-state {
      text-align: center;
      padding: 32px;
      color: #888;
    }

    /* Confirmation dialog */
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.7);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
    }

    .modal {
      background: #1a1a2e;
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 24px;
      max-width: 400px;
      width: 90%;
    }

    .modal h3 {
      margin-bottom: 16px;
    }

    .modal p {
      color: #888;
      margin-bottom: 24px;
    }

    .modal-actions {
      display: flex;
      gap: 12px;
      justify-content: flex-end;
    }

    /* Unlimited badge */
    .unlimited {
      color: #22c55e;
      font-weight: 500;
    }
  `;

  @property({ type: Object })
  user: User | null = null;

  @state() private loading = true;
  @state() private subscription: Subscription | null = null;
  @state() private usage: UsageData | null = null;
  @state() private plans: Plan[] = [];
  @state() private invoices: Invoice[] = [];
  @state() private showCancelConfirm = false;
  @state() private actionLoading = false;

  connectedCallback() {
    super.connectedCallback();
    this.loadBillingData();
  }

  private async loadBillingData() {
    this.loading = true;
    try {
      // Load all billing data in parallel
      const [subscriptionRes, usageRes, plansRes, invoicesRes] = await Promise.all([
        this.fetchSubscription(),
        this.fetchUsage(),
        this.fetchPlans(),
        this.fetchInvoices(),
      ]);

      this.subscription = subscriptionRes;
      this.usage = usageRes;
      this.plans = plansRes;
      this.invoices = invoicesRes;
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to load billing data");
    }
    this.loading = false;
  }

  private async fetchSubscription(): Promise<Subscription> {
    try {
      const response = await api["request"]<{ subscription: Subscription }>(
        "/api/billing/subscription",
      );
      return response.subscription;
    } catch {
      // Return default free plan if endpoint not implemented
      return {
        id: "default",
        plan: "free",
        status: "active",
        currentPeriodStart: new Date().toISOString(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
        cancelAtPeriodEnd: false,
      };
    }
  }

  private async fetchUsage(): Promise<UsageData> {
    try {
      const response = await api["request"]<{ usage: UsageData }>("/api/billing/usage");
      return response.usage;
    } catch {
      // Return mock usage data if endpoint not implemented
      return {
        users: { current: 1, limit: 3 },
        agents: { current: 1, limit: 1 },
        apiCalls: { current: 150, limit: 1000 },
        storage: { current: 25, limit: 100 },
        groups: { current: 0, limit: 1 },
      };
    }
  }

  private async fetchPlans(): Promise<Plan[]> {
    try {
      const response = await api["request"]<{ plans: Plan[] }>("/api/billing/plans");
      return response.plans;
    } catch {
      // Return default plans if endpoint not implemented
      return [
        {
          id: "free",
          name: "Free",
          price: 0,
          features: [
            "3 users",
            "1 agent",
            "1,000 API calls/month",
            "100 MB storage",
            "1 group",
            "Community support",
          ],
          limits: {
            users: 3,
            agents: 1,
            apiCalls: 1000,
            storage: 100,
            groups: 1,
          },
        },
        {
          id: "pro",
          name: "Pro",
          price: 2900, // $29/month
          yearlyPrice: 29000, // $290/year (save $58)
          features: [
            "25 users",
            "5 agents",
            "50,000 API calls/month",
            "5 GB storage",
            "10 groups",
            "Priority support",
            "Advanced analytics",
            "Custom integrations",
          ],
          limits: {
            users: 25,
            agents: 5,
            apiCalls: 50000,
            storage: 5000,
            groups: 10,
          },
        },
        {
          id: "enterprise",
          name: "Enterprise",
          price: 9900, // $99/month
          features: [
            "Unlimited users",
            "Unlimited agents",
            "Unlimited API calls",
            "Unlimited storage",
            "Unlimited groups",
            "24/7 dedicated support",
            "SAML SSO",
            "Custom SLA",
            "Data residency options",
          ],
          limits: {
            users: -1,
            agents: -1,
            apiCalls: -1,
            storage: -1,
            groups: -1,
          },
        },
      ];
    }
  }

  private async fetchInvoices(): Promise<Invoice[]> {
    try {
      const response = await api["request"]<{ invoices: Invoice[] }>("/api/billing/invoices");
      return response.invoices;
    } catch {
      // Return empty invoices if endpoint not implemented
      return [];
    }
  }

  private async handleUpgrade(planId: string) {
    this.actionLoading = true;
    try {
      const response = await api["request"]<{ url: string }>("/api/billing/checkout", {
        method: "POST",
        body: JSON.stringify({ planId }),
      });
      // Redirect to Stripe Checkout
      window.location.href = response.url;
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to start checkout");
    }
    this.actionLoading = false;
  }

  private async handleManageBilling() {
    this.actionLoading = true;
    try {
      const response = await api["request"]<{ url: string }>("/api/billing/portal", {
        method: "POST",
      });
      // Redirect to Stripe Customer Portal
      window.location.href = response.url;
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to open billing portal");
    }
    this.actionLoading = false;
  }

  private async handleCancelSubscription() {
    this.actionLoading = true;
    try {
      await api["request"]("/api/billing/cancel", {
        method: "POST",
      });
      toast.success("Subscription will be canceled at the end of the billing period");
      this.showCancelConfirm = false;
      await this.loadBillingData();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to cancel subscription");
    }
    this.actionLoading = false;
  }

  private getUsagePercentage(current: number, limit: number): number {
    if (limit === -1) {
      return 0;
    } // Unlimited
    return Math.min(100, Math.round((current / limit) * 100));
  }

  private getProgressColor(percentage: number): string {
    if (percentage >= 90) {
      return "progress-red";
    }
    if (percentage >= 70) {
      return "progress-yellow";
    }
    return "progress-green";
  }

  private formatPrice(cents: number): string {
    return `$${(cents / 100).toFixed(0)}`;
  }

  private formatDate(dateString: string): string {
    return new Date(dateString).toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  }

  private formatLimit(value: number): string {
    if (value === -1) {
      return "Unlimited";
    }
    if (value >= 1000000) {
      return `${(value / 1000000).toFixed(0)}M`;
    }
    if (value >= 1000) {
      return `${(value / 1000).toFixed(0)}K`;
    }
    return value.toString();
  }

  private getStatusBadgeClass(status: string): string {
    switch (status) {
      case "active":
        return "badge-active";
      case "past_due":
        return "badge-past-due";
      case "canceling":
        return "badge-canceling";
      case "trialing":
        return "badge-trialing";
      default:
        return "";
    }
  }

  private getStatusLabel(status: string): string {
    switch (status) {
      case "active":
        return "Active";
      case "past_due":
        return "Past Due";
      case "canceling":
        return "Canceling";
      case "canceled":
        return "Canceled";
      case "trialing":
        return "Trial";
      default:
        return status;
    }
  }

  render() {
    if (this.loading) {
      return html`
        <div class="loading">
          <div class="spinner"></div>
        </div>
      `;
    }

    return html`
      <h1>Billing</h1>
      <p class="subtitle">Manage your subscription and billing</p>

      ${this.renderCurrentPlan()} ${this.renderUsageOverview()} ${this.renderPlanComparison()}
      ${this.renderBillingHistory()} ${this.showCancelConfirm ? this.renderCancelConfirmDialog() : ""}
    `;
  }

  private renderCurrentPlan() {
    if (!this.subscription) {
      return "";
    }

    const currentPlan = this.plans.find((p) => p.id === this.subscription?.plan);
    const planName = currentPlan?.name || this.subscription.plan;

    return html`
      <div class="section">
        <h2>Current Plan</h2>
        <div class="card">
          <div class="card-header">
            <div class="plan-info">
              <span class="plan-name">${planName}</span>
              <span class="badge ${this.getStatusBadgeClass(this.subscription.status)}">
                ${this.getStatusLabel(this.subscription.status)}
              </span>
            </div>
          </div>

          <div class="plan-details">
            ${
              this.subscription.cancelAtPeriodEnd
                ? html`
                  <p style="color: #eab308; margin-bottom: 8px;">
                    Your subscription will be canceled on
                    ${this.formatDate(this.subscription.currentPeriodEnd)}
                  </p>
                `
                : html`
                  <p>
                    ${
                      this.subscription.plan === "free"
                        ? "Free plan - No billing"
                        : `Renews on ${this.formatDate(this.subscription.currentPeriodEnd)}`
                    }
                  </p>
                `
            }
          </div>

          <div class="actions">
            ${
              this.subscription.plan === "free"
                ? html`
                  <button
                    class="btn btn-primary"
                    @click=${() => this.handleUpgrade("pro")}
                    ?disabled=${this.actionLoading}
                  >
                    Upgrade to Pro
                  </button>
                `
                : html`
                  <button
                    class="btn btn-secondary"
                    @click=${this.handleManageBilling}
                    ?disabled=${this.actionLoading}
                  >
                    Manage Billing
                  </button>
                  ${
                    !this.subscription.cancelAtPeriodEnd
                      ? html`
                        <button
                          class="btn btn-danger"
                          @click=${() => (this.showCancelConfirm = true)}
                          ?disabled=${this.actionLoading}
                        >
                          Cancel Subscription
                        </button>
                      `
                      : ""
                  }
                `
            }
          </div>
        </div>
      </div>
    `;
  }

  private renderUsageOverview() {
    if (!this.usage) {
      return "";
    }

    const items = [
      { name: "Users", ...this.usage.users },
      { name: "Agents", ...this.usage.agents },
      { name: "API Calls", ...this.usage.apiCalls, suffix: "this month" },
      { name: "Storage", ...this.usage.storage, suffix: "MB" },
      { name: "Groups", ...this.usage.groups },
    ];

    return html`
      <div class="section">
        <h2>Usage Overview</h2>
        <div class="usage-grid">
          ${items.map((item) => {
            const percentage = this.getUsagePercentage(item.current, item.limit);
            const progressClass = this.getProgressColor(percentage);
            const isUnlimited = item.limit === -1;

            return html`
              <div class="usage-item">
                <div class="usage-label">
                  <span class="usage-name">${item.name}</span>
                  <span class="usage-value">
                    ${
                      isUnlimited
                        ? html`<span class="unlimited">${item.current} (Unlimited)</span>`
                        : html`${item.current} of ${this.formatLimit(item.limit)}
                          ${"suffix" in item ? item.suffix : ""}`
                    }
                  </span>
                </div>
                <div class="progress-bar">
                  <div
                    class="progress-fill ${progressClass}"
                    style="width: ${isUnlimited ? 0 : percentage}%"
                  ></div>
                </div>
              </div>
            `;
          })}
        </div>
      </div>
    `;
  }

  private renderPlanComparison() {
    return html`
      <div class="section">
        <h2>Available Plans</h2>
        <div class="plans-grid">
          ${this.plans.map((plan) => {
            const isCurrent = this.subscription?.plan === plan.id;
            const isDowngrade =
              this.subscription &&
              this.plans.findIndex((p) => p.id === this.subscription!.plan) >
                this.plans.findIndex((p) => p.id === plan.id);

            return html`
              <div class="plan-card ${isCurrent ? "current" : ""}">
                ${
                  isCurrent
                    ? html`
                        <span class="current-badge">Current Plan</span>
                      `
                    : ""
                }
                <div class="plan-card-header">
                  <div class="plan-card-name">${plan.name}</div>
                  <div class="plan-card-price">
                    ${
                      plan.price === 0
                        ? html`
                            Free
                          `
                        : html`${this.formatPrice(plan.price)}<span>/month</span>`
                    }
                  </div>
                </div>
                <ul class="plan-features">
                  ${plan.features.map((feature) => html`<li>${feature}</li>`)}
                </ul>
                ${
                  isCurrent
                    ? ""
                    : isDowngrade
                      ? html`
                        <button
                          class="btn btn-secondary"
                          style="width: 100%;"
                          @click=${this.handleManageBilling}
                          ?disabled=${this.actionLoading}
                        >
                          Downgrade
                        </button>
                      `
                      : html`
                        <button
                          class="btn btn-primary"
                          style="width: 100%;"
                          @click=${() => this.handleUpgrade(plan.id)}
                          ?disabled=${this.actionLoading}
                        >
                          ${plan.id === "enterprise" ? "Contact Sales" : "Upgrade"}
                        </button>
                      `
                }
              </div>
            `;
          })}
        </div>
      </div>
    `;
  }

  private renderBillingHistory() {
    return html`
      <div class="section">
        <h2>Billing History</h2>
        <div class="card">
          ${
            this.invoices.length > 0
              ? html`
                <div class="invoice-list">
                  ${this.invoices.map(
                    (invoice) => html`
                      <div class="invoice-item">
                        <div class="invoice-info">
                          <span class="invoice-date">${this.formatDate(invoice.date)}</span>
                          <span class="invoice-amount">${this.formatPrice(invoice.amount)}</span>
                          <span class="invoice-status ${invoice.status}">${invoice.status}</span>
                        </div>
                        ${
                          invoice.pdfUrl
                            ? html`
                              <a
                                href="${invoice.pdfUrl}"
                                target="_blank"
                                rel="noopener"
                                class="btn btn-sm btn-secondary"
                              >
                                Download PDF
                              </a>
                            `
                            : ""
                        }
                      </div>
                    `,
                  )}
                </div>
              `
              : html`
                  <div class="empty-state">
                    <p>No invoices yet</p>
                    <p style="font-size: 0.85rem; margin-top: 8px; color: #666">
                      Your billing history will appear here once you subscribe to a paid plan.
                    </p>
                  </div>
                `
          }
        </div>
      </div>
    `;
  }

  private renderCancelConfirmDialog() {
    return html`
      <div class="modal-overlay" @click=${() => (this.showCancelConfirm = false)}>
        <div class="modal" @click=${(e: Event) => e.stopPropagation()}>
          <h3>Cancel Subscription?</h3>
          <p>
            Your subscription will remain active until
            ${this.subscription ? this.formatDate(this.subscription.currentPeriodEnd) : "the end of your billing period"}.
            After that, you'll be downgraded to the Free plan.
          </p>
          <div class="modal-actions">
            <button class="btn btn-secondary" @click=${() => (this.showCancelConfirm = false)}>
              Keep Subscription
            </button>
            <button
              class="btn btn-danger"
              @click=${this.handleCancelSubscription}
              ?disabled=${this.actionLoading}
            >
              ${this.actionLoading ? "Canceling..." : "Yes, Cancel"}
            </button>
          </div>
        </div>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-billing": BillingPage;
  }
}

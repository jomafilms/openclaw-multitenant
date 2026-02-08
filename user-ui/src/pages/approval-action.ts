import { LitElement, html, css } from "lit";
import { customElement, state } from "lit/decorators.js";
import { toast } from "../components/toast.js";
import { api } from "../lib/api.js";

/**
 * Approval action page - handles approval links from push notifications.
 * URL format: /approval-action?token=xxx&action=approve|deny
 */
@customElement("ocmt-approval-action")
export class ApprovalActionPage extends LitElement {
  static styles = css`
    :host {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 24px;
      box-sizing: border-box;
    }

    .container {
      max-width: 500px;
      width: 100%;
      text-align: center;
    }

    .card {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      padding: 32px;
      margin-bottom: 24px;
    }

    .icon {
      font-size: 4rem;
      margin-bottom: 16px;
    }

    h1 {
      font-size: 1.5rem;
      margin-bottom: 8px;
    }

    .subtitle {
      color: #888;
      margin-bottom: 24px;
    }

    .approval-details {
      background: rgba(255, 255, 255, 0.05);
      border-radius: 8px;
      padding: 16px;
      margin: 24px 0;
      text-align: left;
    }

    .detail-row {
      display: flex;
      justify-content: space-between;
      padding: 8px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    }

    .detail-row:last-child {
      border-bottom: none;
    }

    .detail-label {
      color: #888;
    }

    .detail-value {
      color: white;
      font-weight: 500;
    }

    .scope-tags {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      justify-content: flex-end;
    }

    .scope-tag {
      background: rgba(79, 70, 229, 0.2);
      color: #818cf8;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.85rem;
    }

    .actions {
      display: flex;
      gap: 12px;
      justify-content: center;
      margin-top: 24px;
    }

    .btn {
      padding: 14px 28px;
      border-radius: 10px;
      border: none;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
      flex: 1;
      max-width: 180px;
    }

    .btn-approve {
      background: #22c55e;
      color: white;
    }

    .btn-approve:hover {
      background: #16a34a;
    }

    .btn-deny {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
    }

    .btn-deny:hover {
      background: rgba(239, 68, 68, 0.3);
    }

    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .loading {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 16px;
    }

    .spinner {
      width: 48px;
      height: 48px;
      border: 4px solid rgba(255, 255, 255, 0.1);
      border-top-color: #4f46e5;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }

    @keyframes spin {
      to {
        transform: rotate(360deg);
      }
    }

    .error-state {
      color: #ef4444;
    }

    .success-state {
      color: #22c55e;
    }

    .back-link {
      color: #888;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-top: 24px;
    }

    .back-link:hover {
      color: white;
    }

    .reason-box {
      background: rgba(245, 158, 11, 0.1);
      border: 1px solid rgba(245, 158, 11, 0.3);
      border-radius: 8px;
      padding: 12px;
      margin-top: 16px;
      text-align: left;
    }

    .reason-label {
      color: #f59e0b;
      font-size: 0.85rem;
      margin-bottom: 4px;
    }

    .reason-text {
      color: #ccc;
      font-style: italic;
    }
  `;

  @state()
  private loading = true;

  @state()
  private processing = false;

  @state()
  private error: string | null = null;

  @state()
  private success: string | null = null;

  @state()
  private approval: {
    id: string;
    status: string;
    resource: string;
    scope: string[];
    subjectEmail?: string;
    reason?: string;
    createdAt: string;
    expiresAt: string;
    userName: string;
  } | null = null;

  private token: string | null = null;

  connectedCallback() {
    super.connectedCallback();
    this.parseUrlAndLoad();
  }

  private async parseUrlAndLoad() {
    const params = new URLSearchParams(window.location.search);
    this.token = params.get("token");
    const action = params.get("action");

    if (!this.token) {
      this.error = "Missing approval token";
      this.loading = false;
      return;
    }

    // If action is specified in URL, perform it automatically
    if (action === "approve" || action === "deny") {
      await this.performAction(action);
      return;
    }

    // Otherwise, load approval details for user to decide
    await this.loadApprovalDetails();
  }

  private async loadApprovalDetails() {
    try {
      const result = await api.validateApprovalToken(this.token!);
      if (!result.valid) {
        this.error = "Invalid or expired approval token";
      } else {
        this.approval = result.approval;

        // Check if already decided
        if (this.approval.status !== "pending") {
          this.success = `This approval has already been ${this.approval.status}`;
        }
      }
    } catch (err) {
      this.error = err instanceof Error ? err.message : "Failed to load approval details";
    }
    this.loading = false;
  }

  private async performAction(action: "approve" | "deny") {
    this.processing = true;

    try {
      if (action === "approve") {
        await api.approveCapabilityByToken(this.token!);
        this.success = "Capability approved successfully!";
      } else {
        await api.denyCapabilityByToken(this.token!);
        this.success = "Capability denied.";
      }
    } catch (err) {
      this.error = err instanceof Error ? err.message : `Failed to ${action} capability`;
    }

    this.loading = false;
    this.processing = false;
  }

  private async handleApprove() {
    this.processing = true;
    try {
      await api.approveCapabilityByToken(this.token!);
      this.success = "Capability approved successfully!";
      toast.success("Capability approved");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to approve");
    }
    this.processing = false;
  }

  private async handleDeny() {
    this.processing = true;
    try {
      await api.denyCapabilityByToken(this.token!);
      this.success = "Capability denied.";
      toast.success("Capability denied");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to deny");
    }
    this.processing = false;
  }

  private formatDate(dateStr: string): string {
    return new Date(dateStr).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit",
    });
  }

  render() {
    if (this.loading) {
      return html`
        <div class="container">
          <div class="loading">
            <div class="spinner"></div>
            <p>Loading approval details...</p>
          </div>
        </div>
      `;
    }

    if (this.error) {
      return html`
        <div class="container">
          <div class="card error-state">
            <div class="icon">&#x26A0;</div>
            <h1>Error</h1>
            <p>${this.error}</p>
          </div>
          <a href="/approvals" class="back-link">
            &#x2190; Back to Approvals
          </a>
        </div>
      `;
    }

    if (this.success) {
      return html`
        <div class="container">
          <div class="card success-state">
            <div class="icon">&#x2713;</div>
            <h1>Done</h1>
            <p>${this.success}</p>
          </div>
          <a href="/approvals" class="back-link">
            &#x2190; View All Approvals
          </a>
        </div>
      `;
    }

    return html`
      <div class="container">
        <div class="card">
          <div class="icon">&#x1F510;</div>
          <h1>Approve Capability</h1>
          <p class="subtitle">Your agent is requesting permission to share access</p>

          ${
            this.approval
              ? html`
            <div class="approval-details">
              <div class="detail-row">
                <span class="detail-label">Resource</span>
                <span class="detail-value">${this.approval.resource}</span>
              </div>
              ${
                this.approval.subjectEmail
                  ? html`
                <div class="detail-row">
                  <span class="detail-label">Share with</span>
                  <span class="detail-value">${this.approval.subjectEmail}</span>
                </div>
              `
                  : ""
              }
              <div class="detail-row">
                <span class="detail-label">Permissions</span>
                <div class="scope-tags">
                  ${this.approval.scope.map((s) => html`<span class="scope-tag">${s}</span>`)}
                </div>
              </div>
              <div class="detail-row">
                <span class="detail-label">Requested</span>
                <span class="detail-value">${this.formatDate(this.approval.createdAt)}</span>
              </div>
              <div class="detail-row">
                <span class="detail-label">Expires</span>
                <span class="detail-value">${this.formatDate(this.approval.expiresAt)}</span>
              </div>
            </div>

            ${
              this.approval.reason
                ? html`
              <div class="reason-box">
                <div class="reason-label">Agent's reason:</div>
                <div class="reason-text">"${this.approval.reason}"</div>
              </div>
            `
                : ""
            }

            <div class="actions">
              <button
                class="btn btn-deny"
                @click=${this.handleDeny}
                ?disabled=${this.processing}
              >
                Deny
              </button>
              <button
                class="btn btn-approve"
                @click=${this.handleApprove}
                ?disabled=${this.processing}
              >
                ${this.processing ? "Processing..." : "Approve"}
              </button>
            </div>
          `
              : ""
          }
        </div>

        <a href="/approvals" class="back-link">
          &#x2190; View All Approvals
        </a>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-approval-action": ApprovalActionPage;
  }
}

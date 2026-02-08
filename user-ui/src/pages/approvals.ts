import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { toast } from "../components/toast.js";
import { api, User, CapabilityApproval } from "../lib/api.js";

// Permission levels from capability-ceiling
const PERMISSION_LEVELS = ["read", "list", "write", "delete", "admin", "share-further"] as const;
type PermissionLevel = (typeof PERMISSION_LEVELS)[number];

// Default agent ceiling (read and list only)
const DEFAULT_AGENT_CEILING: PermissionLevel[] = new Set(["read", "list"]);

interface ApprovalConstraints {
  timeLimit: string; // 'default' | '1h' | '4h' | '1d' | '1w' | 'custom'
  customHours?: number;
  scopeRestriction: string[]; // subset of original scope
  callLimit: number | null; // null = use default
}

@customElement("ocmt-approvals")
export class ApprovalsPage extends LitElement {
  static styles = css`
    :host {
      display: block;
      max-width: 900px;
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

    .badge {
      background: rgba(79, 70, 229, 0.2);
      color: #818cf8;
      padding: 2px 8px;
      border-radius: 10px;
      font-size: 0.75rem;
      text-transform: none;
      letter-spacing: 0;
    }

    .badge.pending {
      background: rgba(245, 158, 11, 0.2);
      color: #f59e0b;
    }

    .badge.approved {
      background: rgba(34, 197, 94, 0.2);
      color: #22c55e;
    }

    .badge.denied {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
    }

    .badge.expired {
      background: rgba(107, 114, 128, 0.2);
      color: #6b7280;
    }

    .approvals-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .approval-card {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 20px;
      transition: all 0.2s;
    }

    .approval-card:hover {
      background: rgba(255, 255, 255, 0.08);
    }

    .approval-card.pending {
      border-color: rgba(245, 158, 11, 0.3);
    }

    .approval-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      margin-bottom: 12px;
    }

    .approval-info {
      flex: 1;
    }

    .approval-title {
      font-weight: 600;
      font-size: 1.1rem;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .approval-resource {
      display: inline-block;
      background: rgba(79, 70, 229, 0.15);
      color: #818cf8;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 0.85rem;
      margin-top: 8px;
    }

    .approval-scope {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      margin-top: 8px;
    }

    .scope-tag {
      background: rgba(255, 255, 255, 0.1);
      color: #aaa;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.8rem;
    }

    .approval-reason {
      color: #aaa;
      font-size: 0.9rem;
      margin-top: 8px;
      font-style: italic;
    }

    .approval-meta {
      font-size: 0.85rem;
      color: #666;
      margin-top: 8px;
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
    }

    .approval-actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 16px;
    }

    .btn {
      padding: 10px 16px;
      border-radius: 8px;
      border: none;
      font-size: 0.9rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    .btn-primary {
      background: #4f46e5;
      color: white;
    }

    .btn-primary:hover {
      background: #4338ca;
    }

    .btn-secondary {
      background: rgba(255, 255, 255, 0.1);
      color: #ccc;
    }

    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.15);
    }

    .btn-danger {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
    }

    .btn-danger:hover {
      background: rgba(239, 68, 68, 0.3);
    }

    .btn-success {
      background: rgba(34, 197, 94, 0.2);
      color: #22c55e;
    }

    .btn-success:hover {
      background: rgba(34, 197, 94, 0.3);
    }

    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .empty-state {
      text-align: center;
      padding: 40px;
      color: #888;
    }

    .empty-state-icon {
      font-size: 3rem;
      margin-bottom: 16px;
    }

    .empty-state h3 {
      color: white;
      margin-bottom: 8px;
    }

    .loading {
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 40px;
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

    .tabs {
      display: flex;
      gap: 4px;
      margin-bottom: 24px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
      padding-bottom: 0;
    }

    .tab {
      padding: 12px 16px;
      background: none;
      border: none;
      color: #888;
      font-size: 0.95rem;
      cursor: pointer;
      transition: all 0.2s;
      border-bottom: 2px solid transparent;
      margin-bottom: -1px;
    }

    .tab:hover {
      color: white;
    }

    .tab.active {
      color: white;
      border-bottom-color: #4f46e5;
    }

    .warning-box {
      background: rgba(245, 158, 11, 0.1);
      border: 1px solid rgba(245, 158, 11, 0.3);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 24px;
    }

    .warning-box h3 {
      color: #f59e0b;
      margin-bottom: 8px;
      font-size: 1rem;
    }

    .warning-box p {
      color: #aaa;
      font-size: 0.9rem;
      margin: 0;
    }

    .agent-context {
      background: rgba(255, 255, 255, 0.05);
      border-radius: 8px;
      padding: 12px;
      margin-top: 12px;
      font-size: 0.85rem;
    }

    .agent-context-title {
      color: #888;
      margin-bottom: 8px;
      font-weight: 500;
    }

    .agent-context pre {
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      color: #ccc;
    }

    /* Constraints Panel */
    .constraints-panel {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 10px;
      padding: 16px;
      margin-top: 16px;
    }

    .constraints-title {
      font-size: 0.9rem;
      color: #aaa;
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .constraints-title svg {
      width: 16px;
      height: 16px;
    }

    .constraint-group {
      margin-bottom: 16px;
    }

    .constraint-group:last-child {
      margin-bottom: 0;
    }

    .constraint-label {
      font-size: 0.85rem;
      color: #888;
      margin-bottom: 8px;
      display: block;
    }

    .constraint-options {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }

    .constraint-option {
      padding: 8px 14px;
      border-radius: 8px;
      border: 1px solid rgba(255, 255, 255, 0.1);
      background: rgba(255, 255, 255, 0.05);
      color: #ccc;
      font-size: 0.85rem;
      cursor: pointer;
      transition: all 0.2s;
    }

    .constraint-option:hover {
      background: rgba(255, 255, 255, 0.08);
      border-color: rgba(255, 255, 255, 0.15);
    }

    .constraint-option.selected {
      background: rgba(79, 70, 229, 0.2);
      border-color: rgba(79, 70, 229, 0.4);
      color: #818cf8;
    }

    .constraint-option.exceeded {
      background: rgba(239, 68, 68, 0.1);
      border-color: rgba(239, 68, 68, 0.3);
      color: #ef4444;
      cursor: not-allowed;
    }

    .constraint-option.exceeded::after {
      content: " (exceeds ceiling)";
      font-size: 0.75rem;
      opacity: 0.7;
    }

    .constraint-input {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 8px;
      padding: 8px 12px;
      color: white;
      font-size: 0.9rem;
      width: 80px;
    }

    .constraint-input:focus {
      outline: none;
      border-color: rgba(79, 70, 229, 0.5);
    }

    .scope-checkboxes {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }

    .scope-checkbox {
      display: flex;
      align-items: center;
      gap: 6px;
      cursor: pointer;
    }

    .scope-checkbox input {
      cursor: pointer;
    }

    .scope-checkbox.disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .scope-checkbox.disabled input {
      cursor: not-allowed;
    }

    /* Ceiling Warning */
    .ceiling-warning {
      background: rgba(245, 158, 11, 0.1);
      border: 1px solid rgba(245, 158, 11, 0.3);
      border-radius: 8px;
      padding: 12px 16px;
      margin-bottom: 16px;
      display: flex;
      align-items: flex-start;
      gap: 10px;
    }

    .ceiling-warning-icon {
      color: #f59e0b;
      font-size: 1.2rem;
      flex-shrink: 0;
    }

    .ceiling-warning-content {
      flex: 1;
    }

    .ceiling-warning-title {
      font-weight: 600;
      color: #f59e0b;
      margin-bottom: 4px;
    }

    .ceiling-warning-text {
      color: #aaa;
      font-size: 0.85rem;
    }

    .ceiling-warning-permissions {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 8px;
    }

    .ceiling-permission-tag {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.8rem;
    }

    .toggle-constraints {
      background: none;
      border: none;
      color: #818cf8;
      cursor: pointer;
      font-size: 0.85rem;
      padding: 4px 8px;
      margin-top: 8px;
      display: inline-flex;
      align-items: center;
      gap: 4px;
    }

    .toggle-constraints:hover {
      text-decoration: underline;
    }
  `;

  @property({ type: Object })
  user: User | null = null;

  @state()
  private pendingApprovals: CapabilityApproval[] = [];

  @state()
  private historyApprovals: CapabilityApproval[] = [];

  @state()
  private loading = true;

  @state()
  private actionLoading: string | null = null;

  @state()
  private activeTab: "pending" | "history" = "pending";

  @state()
  private expandedConstraints: Set<string> = new Set();

  @state()
  private approvalConstraints: Map<string, ApprovalConstraints> = new Map();

  @state()
  private pendingCount = 0;

  @state()
  private pollInterval: ReturnType<typeof setInterval> | null = null;

  connectedCallback() {
    super.connectedCallback();
    this.loadData();

    // Listen for SSE events about new approvals
    window.addEventListener("capability_approval_requested", () => {
      this.loadData();
    });

    // Poll for new approvals every 30 seconds as fallback
    this.pollInterval = setInterval(() => {
      this.loadData();
    }, 30000);
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
  }

  private getDefaultConstraints(approval: CapabilityApproval): ApprovalConstraints {
    return {
      timeLimit: "default",
      scopeRestriction: [...approval.scope],
      callLimit: approval.max_calls ?? null,
    };
  }

  private getConstraints(approval: CapabilityApproval): ApprovalConstraints {
    if (!this.approvalConstraints.has(approval.id)) {
      this.approvalConstraints.set(approval.id, this.getDefaultConstraints(approval));
    }
    return this.approvalConstraints.get(approval.id)!;
  }

  private updateConstraint(approvalId: string, updates: Partial<ApprovalConstraints>) {
    const current = this.approvalConstraints.get(approvalId) ?? {
      timeLimit: "default",
      scopeRestriction: [],
      callLimit: null,
    };
    this.approvalConstraints.set(approvalId, { ...current, ...updates });
    this.requestUpdate();
  }

  private toggleExpandConstraints(approvalId: string) {
    if (this.expandedConstraints.has(approvalId)) {
      this.expandedConstraints.delete(approvalId);
    } else {
      this.expandedConstraints.add(approvalId);
    }
    this.requestUpdate();
  }

  private isPermissionExceedingCeiling(permission: string): boolean {
    // Check if permission exceeds default agent ceiling
    return !DEFAULT_AGENT_CEILING.has(permission as PermissionLevel);
  }

  private getExceedingPermissions(scope: string[]): string[] {
    return scope.filter((s) => this.isPermissionExceedingCeiling(s));
  }

  private calculateExpiresInSeconds(
    timeLimit: string,
    customHours?: number,
    defaultSeconds?: number,
  ): number {
    switch (timeLimit) {
      case "1h":
        return 3600;
      case "4h":
        return 4 * 3600;
      case "1d":
        return 24 * 3600;
      case "1w":
        return 7 * 24 * 3600;
      case "custom":
        return (customHours || 1) * 3600;
      case "default":
      default:
        return defaultSeconds || 3600;
    }
  }

  private async loadData() {
    this.loading = true;

    try {
      const [pending, history] = await Promise.all([
        api.listPendingApprovals(),
        api.listApprovalHistory(50),
      ]);

      this.pendingApprovals = pending.approvals;
      this.historyApprovals = history.approvals;
      this.pendingCount = this.pendingApprovals.length;

      // Dispatch event for nav badge update
      if (this.pendingCount > 0) {
        window.dispatchEvent(
          new CustomEvent("approval-count-changed", {
            detail: { count: this.pendingCount },
          }),
        );
      }

      // Initialize constraints for new approvals
      for (const approval of this.pendingApprovals) {
        if (!this.approvalConstraints.has(approval.id)) {
          this.approvalConstraints.set(approval.id, this.getDefaultConstraints(approval));
        }
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to load approvals");
    }

    this.loading = false;
  }

  private async handleApprove(approval: CapabilityApproval) {
    this.actionLoading = approval.id;

    try {
      const constraints = this.getConstraints(approval);

      // Calculate actual expiry based on time limit
      const expiresInSeconds = this.calculateExpiresInSeconds(
        constraints.timeLimit,
        constraints.customHours,
        approval.expires_in_seconds,
      );

      await api.approveCapabilityWithConstraints(approval.id, {
        expiresInSeconds,
        scope: constraints.scopeRestriction,
        maxCalls: constraints.callLimit,
      });

      toast.success(`Approved access to ${approval.resource}`);
      await this.loadData();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to approve");
    }

    this.actionLoading = null;
  }

  private async handleDeny(approval: CapabilityApproval) {
    this.actionLoading = approval.id;

    try {
      await api.denyCapability(approval.id);
      toast.success(`Denied access to ${approval.resource}`);
      await this.loadData();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to deny");
    }

    this.actionLoading = null;
  }

  private formatDate(dateStr: string): string {
    const date = new Date(dateStr);
    return date.toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit",
    });
  }

  private formatDuration(seconds: number): string {
    if (seconds < 60) {
      return `${seconds} seconds`;
    }
    if (seconds < 3600) {
      return `${Math.floor(seconds / 60)} minutes`;
    }
    if (seconds < 86400) {
      return `${Math.floor(seconds / 3600)} hours`;
    }
    return `${Math.floor(seconds / 86400)} days`;
  }

  private getResourceIcon(resource: string): string {
    if (resource.includes("calendar")) {
      return "📅";
    }
    if (resource.includes("email") || resource.includes("gmail")) {
      return "📧";
    }
    if (resource.includes("drive") || resource.includes("file")) {
      return "📁";
    }
    if (resource.includes("profile")) {
      return "👤";
    }
    if (resource.includes("slack")) {
      return "💬";
    }
    if (resource.includes("github")) {
      return "🐙";
    }
    return "🔑";
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
      <h1>Capability Approvals</h1>
      <p class="subtitle">Review and approve agent requests to share your data</p>

      ${
        this.pendingApprovals.length > 0
          ? html`
              <div class="warning-box">
                <h3>Action Required</h3>
                <p>
                  Your agent is waiting for your approval to share access to your resources. Review each request
                  carefully before approving.
                </p>
              </div>
            `
          : ""
      }

      <div class="tabs">
        <button
          class="tab ${this.activeTab === "pending" ? "active" : ""}"
          @click=${() => (this.activeTab = "pending")}
        >
          Pending
          ${
            this.pendingApprovals.length > 0
              ? html`
            <span class="badge pending">${this.pendingApprovals.length}</span>
          `
              : ""
          }
        </button>
        <button
          class="tab ${this.activeTab === "history" ? "active" : ""}"
          @click=${() => (this.activeTab = "history")}
        >
          History
        </button>
      </div>

      ${this.activeTab === "pending" ? this.renderPending() : this.renderHistory()}
    `;
  }

  private renderPending() {
    if (this.pendingApprovals.length === 0) {
      return html`
        <div class="empty-state">
          <div class="empty-state-icon">✅</div>
          <h3>No pending approvals</h3>
          <p>
            When your agent needs to share access to your resources, approval requests will appear here.
          </p>
        </div>
      `;
    }

    return html`
      <div class="approvals-list">
        ${this.pendingApprovals.map((approval) => this.renderPendingApproval(approval))}
      </div>
    `;
  }

  private renderPendingApproval(approval: CapabilityApproval) {
    const isLoading = this.actionLoading === approval.id;
    const isExpanded = this.expandedConstraints.has(approval.id);
    const constraints = this.getConstraints(approval);
    const exceedingPermissions = this.getExceedingPermissions(approval.scope);
    const hasCeilingWarning = exceedingPermissions.length > 0;

    return html`
      <div class="approval-card pending">
        <div class="approval-header">
          <div class="approval-info">
            <div class="approval-title">
              ${this.getResourceIcon(approval.resource)}
              Share access to ${approval.resource}
              <span class="badge pending">Pending</span>
            </div>
            ${
              approval.subject_email
                ? html`
              <p style="color: #aaa; margin-top: 4px;">
                Requested for: <strong style="color: white;">${approval.subject_email}</strong>
              </p>
            `
                : ""
            }
            <div class="approval-scope">
              ${approval.scope.map(
                (s) => html`
                <span class="scope-tag ${this.isPermissionExceedingCeiling(s) ? "ceiling-exceeded" : ""}">${s}</span>
              `,
              )}
            </div>
            ${
              approval.reason
                ? html`
              <div class="approval-reason">"${approval.reason}"</div>
            `
                : ""
            }
            <div class="approval-meta">
              <span>Requested ${this.formatDate(approval.created_at)}</span>
              <span>Duration: ${this.formatDuration(approval.expires_in_seconds)}</span>
              ${approval.max_calls ? html`<span>Max calls: ${approval.max_calls}</span>` : ""}
            </div>

            ${
              hasCeilingWarning
                ? html`
              <div class="ceiling-warning">
                <span class="ceiling-warning-icon">&#x26A0;</span>
                <div class="ceiling-warning-content">
                  <div class="ceiling-warning-title">Elevated Permissions Requested</div>
                  <div class="ceiling-warning-text">
                    This request includes permissions beyond the agent's default ceiling.
                    Consider restricting the scope below.
                  </div>
                  <div class="ceiling-warning-permissions">
                    ${exceedingPermissions.map(
                      (p) => html`
                      <span class="ceiling-permission-tag">${p}</span>
                    `,
                    )}
                  </div>
                </div>
              </div>
            `
                : ""
            }

            ${
              approval.agent_context && Object.keys(approval.agent_context).length > 0
                ? html`
              <div class="agent-context">
                <div class="agent-context-title">Agent Context</div>
                <pre>${JSON.stringify(approval.agent_context, null, 2)}</pre>
              </div>
            `
                : ""
            }

            <button class="toggle-constraints" @click=${() => this.toggleExpandConstraints(approval.id)}>
              ${isExpanded ? "- Hide options" : "+ Customize approval"}
            </button>

            ${isExpanded ? this.renderConstraintsPanel(approval, constraints) : ""}
          </div>
        </div>
        <div class="approval-actions">
          <button
            class="btn btn-success"
            @click=${() => this.handleApprove(approval)}
            ?disabled=${isLoading || constraints.scopeRestriction.length === 0}
          >
            ${isLoading ? "Processing..." : "Approve"}
          </button>
          <button
            class="btn btn-danger"
            @click=${() => this.handleDeny(approval)}
            ?disabled=${isLoading}
          >
            Deny
          </button>
        </div>
      </div>
    `;
  }

  private renderConstraintsPanel(approval: CapabilityApproval, constraints: ApprovalConstraints) {
    return html`
      <div class="constraints-panel">
        <div class="constraints-title">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
          </svg>
          Approval Constraints
        </div>

        <!-- Time Limit -->
        <div class="constraint-group">
          <label class="constraint-label">Time Limit</label>
          <div class="constraint-options">
            ${["1h", "4h", "1d", "1w", "default"].map(
              (option) => html`
              <button
                class="constraint-option ${constraints.timeLimit === option ? "selected" : ""}"
                @click=${() => this.updateConstraint(approval.id, { timeLimit: option })}
              >
                ${
                  option === "default"
                    ? `Default (${this.formatDuration(approval.expires_in_seconds)})`
                    : option === "1h"
                      ? "1 Hour"
                      : option === "4h"
                        ? "4 Hours"
                        : option === "1d"
                          ? "1 Day"
                          : option === "1w"
                            ? "1 Week"
                            : option
                }
              </button>
            `,
            )}
            <button
              class="constraint-option ${constraints.timeLimit === "custom" ? "selected" : ""}"
              @click=${() => this.updateConstraint(approval.id, { timeLimit: "custom", customHours: constraints.customHours || 1 })}
            >
              Custom
            </button>
            ${
              constraints.timeLimit === "custom"
                ? html`
              <input
                type="number"
                class="constraint-input"
                min="1"
                max="720"
                .value=${String(constraints.customHours || 1)}
                @input=${(e: Event) => {
                  const value = parseInt((e.target as HTMLInputElement).value) || 1;
                  this.updateConstraint(approval.id, {
                    customHours: Math.min(720, Math.max(1, value)),
                  });
                }}
              /> hours
            `
                : ""
            }
          </div>
        </div>

        <!-- Scope Restriction -->
        <div class="constraint-group">
          <label class="constraint-label">Permissions (uncheck to restrict)</label>
          <div class="scope-checkboxes">
            ${approval.scope.map((scope) => {
              const isExceeding = this.isPermissionExceedingCeiling(scope);
              const isChecked = constraints.scopeRestriction.includes(scope);
              return html`
                <label class="scope-checkbox ${isExceeding ? "warning" : ""}">
                  <input
                    type="checkbox"
                    .checked=${isChecked}
                    @change=${(e: Event) => {
                      const checked = (e.target as HTMLInputElement).checked;
                      const newScope = checked
                        ? [...constraints.scopeRestriction, scope]
                        : constraints.scopeRestriction.filter((s) => s !== scope);
                      this.updateConstraint(approval.id, { scopeRestriction: newScope });
                    }}
                  />
                  <span>${scope}</span>
                  ${
                    isExceeding
                      ? html`
                          <span style="color: #f59e0b; font-size: 0.75rem">(elevated)</span>
                        `
                      : ""
                  }
                </label>
              `;
            })}
          </div>
        </div>

        <!-- Call Limit -->
        <div class="constraint-group">
          <label class="constraint-label">Maximum API Calls</label>
          <div class="constraint-options">
            ${[null, 10, 50, 100, 500].map(
              (limit) => html`
              <button
                class="constraint-option ${constraints.callLimit === limit ? "selected" : ""}"
                @click=${() => this.updateConstraint(approval.id, { callLimit: limit })}
              >
                ${limit === null ? (approval.max_calls ? `Default (${approval.max_calls})` : "Unlimited") : limit}
              </button>
            `,
            )}
            <input
              type="number"
              class="constraint-input"
              placeholder="Custom"
              min="1"
              max="10000"
              .value=${constraints.callLimit && ![null, 10, 50, 100, 500].includes(constraints.callLimit) ? String(constraints.callLimit) : ""}
              @input=${(e: Event) => {
                const value = parseInt((e.target as HTMLInputElement).value);
                if (!isNaN(value) && value > 0) {
                  this.updateConstraint(approval.id, { callLimit: Math.min(10000, value) });
                }
              }}
            />
          </div>
        </div>
      </div>
    `;
  }

  private renderHistory() {
    if (this.historyApprovals.length === 0) {
      return html`
        <div class="empty-state">
          <div class="empty-state-icon">📜</div>
          <h3>No approval history</h3>
          <p>Past approval decisions will appear here.</p>
        </div>
      `;
    }

    return html`
      <div class="approvals-list">
        ${this.historyApprovals.map((approval) => this.renderHistoryApproval(approval))}
      </div>
    `;
  }

  private renderHistoryApproval(approval: CapabilityApproval) {
    const statusClass = approval.status;
    const statusLabel = approval.status.charAt(0).toUpperCase() + approval.status.slice(1);

    return html`
      <div class="approval-card">
        <div class="approval-header">
          <div class="approval-info">
            <div class="approval-title">
              ${this.getResourceIcon(approval.resource)}
              ${approval.resource}
              <span class="badge ${statusClass}">${statusLabel}</span>
            </div>
            ${
              approval.subject_email
                ? html`
              <p style="color: #888; margin-top: 4px; font-size: 0.9rem;">
                For: ${approval.subject_email}
              </p>
            `
                : ""
            }
            <div class="approval-scope">
              ${approval.scope.map((s) => html`<span class="scope-tag">${s}</span>`)}
            </div>
            <div class="approval-meta">
              <span>Requested ${this.formatDate(approval.created_at)}</span>
              ${
                approval.decided_at
                  ? html`
                <span>Decided ${this.formatDate(approval.decided_at)}</span>
              `
                  : ""
              }
            </div>
          </div>
        </div>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-approvals": ApprovalsPage;
  }
}

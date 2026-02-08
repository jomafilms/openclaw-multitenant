import { LitElement, html, css, TemplateResult } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { api, User, AuditLogEntry } from "../lib/api.js";

interface GroupedLogs {
  date: string;
  entries: AuditLogEntry[];
}

@customElement("ocmt-activity")
export class ActivityPage extends LitElement {
  static styles = css`
    :host {
      display: block;
      max-width: 800px;
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

    .day-group {
      margin-bottom: 32px;
    }

    .day-header {
      font-size: 0.9rem;
      color: #888;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 12px;
      padding-bottom: 8px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    }

    .activity-list {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .activity-item {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      padding: 12px 16px;
      background: rgba(255, 255, 255, 0.03);
      border-radius: 8px;
      transition: background 0.2s;
    }

    .activity-item:hover {
      background: rgba(255, 255, 255, 0.06);
    }

    .activity-icon {
      width: 32px;
      height: 32px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1rem;
      flex-shrink: 0;
    }

    .activity-icon.auth {
      background: rgba(79, 70, 229, 0.2);
    }

    .activity-icon.integration {
      background: rgba(34, 197, 94, 0.2);
    }

    .activity-icon.org {
      background: rgba(245, 158, 11, 0.2);
    }

    .activity-icon.peer {
      background: rgba(236, 72, 153, 0.2);
    }

    .activity-content {
      flex: 1;
      min-width: 0;
    }

    .activity-description {
      color: #ddd;
      font-size: 0.95rem;
      line-height: 1.4;
    }

    .activity-description strong {
      color: white;
    }

    .activity-meta {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-top: 4px;
      font-size: 0.8rem;
      color: #666;
    }

    .activity-time {
      color: #888;
    }

    .activity-details {
      color: #666;
      font-family: monospace;
      font-size: 0.75rem;
    }

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
      padding: 60px 20px;
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

    .error-banner {
      background: rgba(239, 68, 68, 0.2);
      border: 1px solid rgba(239, 68, 68, 0.3);
      padding: 12px 16px;
      border-radius: 8px;
      color: #ef4444;
      margin-bottom: 24px;
    }

    .filter-bar {
      display: flex;
      gap: 8px;
      margin-bottom: 24px;
      flex-wrap: wrap;
    }

    .filter-btn {
      padding: 8px 16px;
      border-radius: 20px;
      border: 1px solid rgba(255, 255, 255, 0.1);
      background: transparent;
      color: #888;
      font-size: 0.85rem;
      cursor: pointer;
      transition: all 0.2s;
    }

    .filter-btn:hover {
      border-color: rgba(255, 255, 255, 0.2);
      color: #ccc;
    }

    .filter-btn.active {
      background: rgba(79, 70, 229, 0.2);
      border-color: rgba(79, 70, 229, 0.3);
      color: #818cf8;
    }
  `;

  @property({ type: Object })
  user: User | null = null;

  @state()
  private logs: AuditLogEntry[] = [];

  @state()
  private loading = true;

  @state()
  private error = "";

  @state()
  private filter: "all" | "auth" | "integration" | "org" | "peer" = "all";

  connectedCallback() {
    super.connectedCallback();
    this.loadLogs();
  }

  private async loadLogs() {
    this.loading = true;
    this.error = "";
    console.log("Loading activity logs...");

    try {
      const result = await api.getAuditLog();
      console.log("Activity logs loaded:", result.logs?.length || 0);
      this.logs = result.logs || [];
    } catch (err) {
      console.error("Failed to load activity logs:", err);
      this.error = err instanceof Error ? err.message : "Failed to load activity";
    }

    this.loading = false;
  }

  private getFilteredLogs(): AuditLogEntry[] {
    if (this.filter === "all") {
      return this.logs;
    }

    return this.logs.filter((log) => {
      const action = log.action.toLowerCase();
      switch (this.filter) {
        case "auth":
          return action.includes("auth") || action.includes("login") || action.includes("logout");
        case "integration":
          return action.includes("integration") || action.includes("oauth");
        case "org":
          return action.includes("org") && !action.includes("peer");
        case "peer":
          return action.includes("peer");
        default:
          return true;
      }
    });
  }

  private groupByDate(logs: AuditLogEntry[]): GroupedLogs[] {
    const groups = new Map<string, AuditLogEntry[]>();

    for (const log of logs) {
      const date = new Date(log.timestamp).toLocaleDateString(undefined, {
        weekday: "long",
        month: "long",
        day: "numeric",
      });

      if (!groups.has(date)) {
        groups.set(date, []);
      }
      groups.get(date)!.push(log);
    }

    return Array.from(groups.entries()).map(([date, entries]) => ({
      date,
      entries,
    }));
  }

  private getActionIcon(action: string): { icon: string; category: string } {
    const a = action.toLowerCase();

    if (a.includes("login") || a.includes("auth") || a.includes("logout")) {
      return { icon: "🔐", category: "auth" };
    }
    if (a.includes("integration") || a.includes("oauth")) {
      return { icon: "🔌", category: "integration" };
    }
    if (a.includes("peer")) {
      return { icon: "🤝", category: "peer" };
    }
    if (a.includes("org")) {
      return { icon: "🏢", category: "org" };
    }

    return { icon: "📋", category: "auth" };
  }

  /**
   * Format an activity log entry as a Lit template.
   * Uses Lit's built-in auto-escaping for user-provided values to prevent XSS.
   * Returns TemplateResult instead of HTML strings for safe rendering.
   */
  private formatAction(log: AuditLogEntry): TemplateResult {
    const action = log.action;
    const details = log.details || {};

    // Auth actions
    if (action === "auth.magic_link_requested") {
      return html`
        You requested a login link
      `;
    }
    if (action === "auth.login") {
      return html`
        You logged in
      `;
    }
    if (action === "auth.logout") {
      return html`
        You logged out
      `;
    }

    // Integration actions - Lit auto-escapes all interpolated values
    if (action === "integration.api_key_added") {
      return html`You added <strong>${details.provider || "unknown"}</strong> API key`;
    }
    if (action === "integration.oauth_connected") {
      return html`You connected <strong>${details.provider || "unknown"}</strong>${details.email ? html` (${details.email})` : ""}`;
    }
    if (action === "integration.removed") {
      return html`You removed <strong>${details.provider || "unknown"}</strong> integration`;
    }

    // Group actions (legacy org.* actions still supported)
    if (action === "org.created" || action === "group.created") {
      return html`You created group <strong>${details.name || "unnamed"}</strong>`;
    }
    if (action === "org.resource.created" || action === "group.resource.created") {
      return html`You added resource <strong>${details.name || "unnamed"}</strong>`;
    }
    if (action === "org.resource.connected" || action === "group.resource.connected") {
      return html`
        You connected to a group resource
      `;
    }
    if (action === "org.resource.disconnected" || action === "group.resource.disconnected") {
      return html`
        You disconnected from a group resource
      `;
    }
    if (
      action === "org.grant.created" ||
      action === "group.share.created" ||
      action === "share.created"
    ) {
      return html`
        You granted resource access to a user
      `;
    }
    if (
      action === "org.grant.revoked" ||
      action === "group.share.revoked" ||
      action === "share.revoked"
    ) {
      return html`
        You revoked resource access from a user
      `;
    }
    if (action === "org.member.added" || action === "group.member.added") {
      return html`
        You added a member to the group
      `;
    }
    if (action === "org.member.removed" || action === "group.member.removed") {
      return html`
        You removed a member from the group
      `;
    }

    // Peer actions
    if (action === "peer.request.created") {
      const userName = log.target_user_name || "a user";
      return html`You requested access to <strong>${userName}</strong>'s ${details.capability || "resource"}`;
    }
    if (action === "peer.request.approved") {
      const userName = log.target_user_name || "a user";
      return html`You approved <strong>${userName}</strong>'s access to your ${details.capability || "resource"}`;
    }
    if (action === "peer.request.denied") {
      const userName = log.target_user_name || "a user";
      return html`You denied <strong>${userName}</strong>'s access request`;
    }
    if (action === "peer.grant.revoked") {
      const userName = log.target_user_name || "a user";
      return html`You revoked <strong>${userName}</strong>'s access to your ${details.capability || "resource"}`;
    }

    // Fallback - Lit auto-escapes the action string
    return html`${action.replace(/\./g, " ").replace(/_/g, " ")}`;
  }

  private formatTime(timestamp: string): string {
    return new Date(timestamp).toLocaleTimeString(undefined, {
      hour: "numeric",
      minute: "2-digit",
    });
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
      <h1>Activity Log</h1>
      <p class="subtitle">Your recent account activity</p>

      ${this.error ? html`<div class="error-banner">${this.error}</div>` : ""}

      ${this.renderFilterBar()}
      ${this.renderLogs()}
    `;
  }

  private renderFilterBar() {
    return html`
      <div class="filter-bar">
        <button
          class="filter-btn ${this.filter === "all" ? "active" : ""}"
          @click=${() => (this.filter = "all")}
        >
          All Activity
        </button>
        <button
          class="filter-btn ${this.filter === "auth" ? "active" : ""}"
          @click=${() => (this.filter = "auth")}
        >
          🔐 Auth
        </button>
        <button
          class="filter-btn ${this.filter === "integration" ? "active" : ""}"
          @click=${() => (this.filter = "integration")}
        >
          🔌 Integrations
        </button>
        <button
          class="filter-btn ${this.filter === "org" ? "active" : ""}"
          @click=${() => (this.filter = "org")}
        >
          👥 Groups
        </button>
        <button
          class="filter-btn ${this.filter === "peer" ? "active" : ""}"
          @click=${() => (this.filter = "peer")}
        >
          🤝 Sharing
        </button>
      </div>
    `;
  }

  private renderLogs() {
    const filtered = this.getFilteredLogs();

    if (filtered.length === 0) {
      return html`
        <div class="empty-state">
          <div class="empty-state-icon">📋</div>
          <h3>No activity yet</h3>
          <p>Your account activity will appear here</p>
        </div>
      `;
    }

    const grouped = this.groupByDate(filtered);

    return html`
      ${grouped.map(
        (group) => html`
        <div class="day-group">
          <div class="day-header">${group.date}</div>
          <div class="activity-list">
            ${group.entries.map((entry) => this.renderActivityItem(entry))}
          </div>
        </div>
      `,
      )}
    `;
  }

  private renderActivityItem(log: AuditLogEntry) {
    const { icon, category } = this.getActionIcon(log.action);

    return html`
      <div class="activity-item">
        <div class="activity-icon ${category}">${icon}</div>
        <div class="activity-content">
          <div class="activity-description">${this.formatAction(log)}</div>
          <div class="activity-meta">
            <span class="activity-time">${this.formatTime(log.timestamp)}</span>
          </div>
        </div>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-activity": ActivityPage;
  }
}

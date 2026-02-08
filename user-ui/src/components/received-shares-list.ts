import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { api } from "../lib/api.js";
import { toast } from "./toast.js";

export interface ReceivedShare {
  id: string;
  resourceId: string;
  resourceName: string;
  resourceType: string;
  ownerId: string;
  ownerName: string;
  ownerEmail: string;
  tier: "LIVE" | "CACHED" | "DELEGATED";
  permissions: string[] | Record<string, boolean>;
  status: "active" | "pending_approval" | "expired" | "revoked";
  ownerOnline?: boolean;
  lastSyncAt?: string;
  expiresAt?: string;
  sharedAt: string;
}

@customElement("received-shares-list")
export class ReceivedSharesList extends LitElement {
  static styles = css`
    :host {
      display: block;
    }

    .section-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 16px;
    }

    h2 {
      font-size: 1.1rem;
      color: #888;
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

    .share-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .share-card {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 20px;
      transition: all 0.2s;
    }

    .share-card:hover {
      background: rgba(255, 255, 255, 0.08);
    }

    .share-card.pending_approval {
      border-color: rgba(245, 158, 11, 0.3);
    }

    .share-card.expired,
    .share-card.revoked {
      opacity: 0.6;
    }

    .share-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
    }

    .share-info {
      flex: 1;
      min-width: 0;
    }

    .share-resource {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 4px;
    }

    .resource-icon {
      font-size: 1.2rem;
    }

    .resource-name {
      font-weight: 600;
      font-size: 1.05rem;
    }

    .share-owner {
      color: #aaa;
      font-size: 0.9rem;
      margin-bottom: 12px;
    }

    .share-owner strong {
      color: #fff;
    }

    .share-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 12px;
    }

    .meta-badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 0.8rem;
    }

    .tier-badge {
      background: rgba(79, 70, 229, 0.15);
      color: #818cf8;
    }

    .tier-badge.live {
      background: rgba(34, 197, 94, 0.15);
      color: #22c55e;
    }

    .tier-badge.delegated {
      background: rgba(245, 158, 11, 0.15);
      color: #f59e0b;
    }

    .permission-badge {
      background: rgba(255, 255, 255, 0.1);
      color: #ccc;
    }

    .access-status {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 12px 16px;
      background: rgba(255, 255, 255, 0.03);
      border-radius: 8px;
      margin-top: 12px;
    }

    .status-indicator {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 0.9rem;
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
    }

    .status-dot.online {
      background: #22c55e;
      box-shadow: 0 0 8px rgba(34, 197, 94, 0.5);
    }

    .status-dot.offline {
      background: #666;
    }

    .status-dot.pending {
      background: #f59e0b;
      animation: pulse 2s infinite;
    }

    @keyframes pulse {
      0%,
      100% {
        opacity: 1;
      }
      50% {
        opacity: 0.5;
      }
    }

    .status-text {
      color: #aaa;
    }

    .status-text.online {
      color: #22c55e;
    }

    .status-text.pending {
      color: #f59e0b;
    }

    .last-sync {
      color: #666;
      font-size: 0.85rem;
      margin-left: auto;
    }

    .pending-banner {
      background: rgba(245, 158, 11, 0.1);
      border: 1px solid rgba(245, 158, 11, 0.2);
      border-radius: 8px;
      padding: 12px 16px;
      margin-top: 12px;
      display: flex;
      align-items: center;
      gap: 10px;
      color: #f59e0b;
      font-size: 0.9rem;
    }

    .pending-icon {
      font-size: 1.2rem;
    }

    .empty-state {
      text-align: center;
      padding: 40px 20px;
      color: #888;
    }

    .empty-state-icon {
      font-size: 3rem;
      margin-bottom: 16px;
    }

    .empty-state h3 {
      color: white;
      margin-bottom: 8px;
      font-size: 1.1rem;
    }

    .empty-state p {
      font-size: 0.95rem;
      max-width: 300px;
      margin: 0 auto;
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

    /* Notification styling */
    .notification-item {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      padding: 16px;
      background: rgba(79, 70, 229, 0.1);
      border: 1px solid rgba(79, 70, 229, 0.2);
      border-radius: 12px;
      margin-bottom: 12px;
      animation: slideIn 0.3s ease-out;
    }

    @keyframes slideIn {
      from {
        opacity: 0;
        transform: translateY(-10px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    .notification-icon {
      font-size: 1.5rem;
    }

    .notification-content {
      flex: 1;
    }

    .notification-title {
      font-weight: 600;
      margin-bottom: 4px;
    }

    .notification-message {
      color: #aaa;
      font-size: 0.9rem;
    }

    .notification-actions {
      display: flex;
      gap: 8px;
      margin-top: 12px;
    }

    .btn {
      padding: 8px 16px;
      border-radius: 8px;
      border: none;
      font-size: 0.85rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
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

    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    @media (max-width: 600px) {
      .share-header {
        flex-direction: column;
        gap: 12px;
      }

      .access-status {
        flex-direction: column;
        align-items: flex-start;
        gap: 8px;
      }

      .last-sync {
        margin-left: 0;
      }

      .share-meta {
        flex-direction: column;
        gap: 6px;
      }

      .meta-badge {
        width: fit-content;
      }

      .notification-item {
        flex-direction: column;
      }

      .notification-actions {
        width: 100%;
      }

      .notification-actions .btn {
        flex: 1;
      }
    }
  `;

  @property({ type: Array })
  shares: ReceivedShare[] = [];

  @property({ type: Boolean })
  loading = false;

  @state()
  private actionLoading: string | null = null;

  private getResourceIcon(type: string): string {
    switch (type) {
      case "calendar":
        return "📅";
      case "email":
        return "📧";
      case "drive":
      case "files":
        return "📁";
      case "contacts":
        return "👥";
      case "api":
        return "🔌";
      case "mcp_server":
        return "🖥️";
      default:
        return "📦";
    }
  }

  private getTierLabel(tier: string): string {
    switch (tier) {
      case "LIVE":
        return "Real-time";
      case "CACHED":
        return "Offline";
      case "DELEGATED":
        return "Full access";
      default:
        return tier;
    }
  }

  private getAccessStatus(share: ReceivedShare): { dot: string; text: string; textClass: string } {
    if (share.status === "pending_approval") {
      return { dot: "pending", text: "Pending approval", textClass: "pending" };
    }
    if (share.status === "revoked") {
      return { dot: "offline", text: "Access revoked", textClass: "" };
    }
    if (share.status === "expired") {
      return { dot: "offline", text: "Expired", textClass: "" };
    }

    // For LIVE tier, check if owner is online
    if (share.tier === "LIVE") {
      if (share.ownerOnline) {
        return { dot: "online", text: "Available now", textClass: "online" };
      }
      return { dot: "offline", text: "Owner offline", textClass: "" };
    }

    // For CACHED and DELEGATED, always available
    return { dot: "online", text: "Available", textClass: "online" };
  }

  private formatLastSync(lastSyncAt: string | undefined): string {
    if (!lastSyncAt) return "";
    const date = new Date(lastSyncAt);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / (1000 * 60));
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));

    if (minutes < 1) return "Synced just now";
    if (minutes < 60) return `Synced ${minutes}m ago`;
    if (hours < 24) return `Synced ${hours}h ago`;
    if (days === 1) return "Synced yesterday";
    return `Synced ${days} days ago`;
  }

  private async handleAcceptShare(share: ReceivedShare) {
    this.actionLoading = share.id;

    try {
      await api.acceptReceivedShare(share.id);
      toast.success(`Connected to ${share.resourceName}`);
      this.dispatchEvent(
        new CustomEvent("share-accepted", {
          bubbles: true,
          composed: true,
          detail: { shareId: share.id },
        }),
      );
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to accept share");
    }

    this.actionLoading = null;
  }

  private async handleDeclineShare(share: ReceivedShare) {
    if (!confirm(`Decline access to ${share.resourceName} from ${share.ownerName}?`)) {
      return;
    }

    this.actionLoading = share.id;

    try {
      await api.declineReceivedShare(share.id);
      toast.info(`Declined share from ${share.ownerName}`);
      this.dispatchEvent(
        new CustomEvent("share-declined", {
          bubbles: true,
          composed: true,
          detail: { shareId: share.id },
        }),
      );
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to decline share");
    }

    this.actionLoading = null;
  }

  render() {
    if (this.loading) {
      return html`
        <div class="loading">
          <div class="spinner"></div>
        </div>
      `;
    }

    const pendingShares = this.shares.filter((s) => s.status === "pending_approval");
    const activeShares = this.shares.filter((s) => s.status === "active");
    const inactiveShares = this.shares.filter(
      (s) => s.status === "expired" || s.status === "revoked",
    );

    return html`
      ${pendingShares.length > 0 ? this.renderPendingNotifications(pendingShares) : ""}

      <div class="section-header">
        <h2>
          Shared With Me
          <span class="badge">${activeShares.length}</span>
          ${
            pendingShares.length > 0
              ? html`
            <span class="badge pending">${pendingShares.length} pending</span>
          `
              : ""
          }
        </h2>
      </div>

      ${
        this.shares.length === 0
          ? html`
              <div class="empty-state">
                <div class="empty-state-icon">🔗</div>
                <h3>No shared resources</h3>
                <p>When others share resources with you, they'll appear here.</p>
              </div>
            `
          : html`
        <div class="share-list">
          ${activeShares.map((share) => this.renderShareCard(share))}
          ${inactiveShares.map((share) => this.renderShareCard(share))}
        </div>
      `
      }
    `;
  }

  private renderPendingNotifications(pendingShares: ReceivedShare[]) {
    return html`
      ${pendingShares.map(
        (share) => html`
        <div class="notification-item">
          <span class="notification-icon">${this.getResourceIcon(share.resourceType)}</span>
          <div class="notification-content">
            <div class="notification-title">
              ${share.ownerName} shared their ${share.resourceType} with you
            </div>
            <div class="notification-message">
              ${share.resourceName} - ${this.getTierLabel(share.tier)} access with ${this.formatPermissions(share.permissions)} permissions
            </div>
            <div class="notification-actions">
              <button
                class="btn btn-primary"
                @click=${() => this.handleAcceptShare(share)}
                ?disabled=${this.actionLoading === share.id}
              >
                ${this.actionLoading === share.id ? "Accepting..." : "Accept"}
              </button>
              <button
                class="btn btn-secondary"
                @click=${() => this.handleDeclineShare(share)}
                ?disabled=${this.actionLoading === share.id}
              >
                Decline
              </button>
            </div>
          </div>
        </div>
      `,
      )}
    `;
  }

  private renderShareCard(share: ReceivedShare) {
    const status = this.getAccessStatus(share);
    const isActive = share.status === "active";

    return html`
      <div class="share-card ${share.status}">
        <div class="share-header">
          <div class="share-info">
            <div class="share-resource">
              <span class="resource-icon">${this.getResourceIcon(share.resourceType)}</span>
              <span class="resource-name">${share.resourceName}</span>
            </div>
            <div class="share-owner">
              From <strong>${share.ownerName}</strong>
              <span style="color: #666;">(${share.ownerEmail})</span>
            </div>
            <div class="share-meta">
              <span class="meta-badge tier-badge ${share.tier.toLowerCase()}">
                ${this.getTierLabel(share.tier)}
              </span>
              ${share.permissions.map(
                (p) => html`
                <span class="meta-badge permission-badge">${p}</span>
              `,
              )}
            </div>
          </div>
        </div>

        ${
          isActive
            ? html`
          <div class="access-status">
            <div class="status-indicator">
              <span class="status-dot ${status.dot}"></span>
              <span class="status-text ${status.textClass}">${status.text}</span>
            </div>
            ${
              share.tier === "CACHED" && share.lastSyncAt
                ? html`
              <span class="last-sync">${this.formatLastSync(share.lastSyncAt)}</span>
            `
                : ""
            }
          </div>
        `
            : ""
        }

        ${
          share.status === "pending_approval"
            ? html`
          <div class="pending-banner">
            <span class="pending-icon">!</span>
            <span>Waiting for ${share.ownerName} to approve your access request</span>
          </div>
        `
            : ""
        }
      </div>
    `;
  }

  // Helper to format permissions (handles both array and object formats)
  private formatPermissions(permissions: string[] | Record<string, boolean> | null): string {
    if (!permissions) return "none";
    if (Array.isArray(permissions)) {
      return permissions.join(", ");
    }
    // Object format: {read: true, write: false} -> "read"
    return (
      Object.entries(permissions)
        .filter(([_, enabled]) => enabled)
        .map(([perm]) => perm)
        .join(", ") || "none"
    );
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "received-shares-list": ReceivedSharesList;
  }
}

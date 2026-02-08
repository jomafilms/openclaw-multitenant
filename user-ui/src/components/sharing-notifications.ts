import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { api, ReceivedShareInfo, CapabilityApproval } from "../lib/api.js";
import { toast } from "./toast.js";

type NotificationType = "share_received" | "share_request" | "approval_needed";

interface SharingNotification {
  id: string;
  type: NotificationType;
  title: string;
  message: string;
  icon: string;
  data: ReceivedShareInfo | CapabilityApproval;
  createdAt: string;
}

@customElement("sharing-notifications")
export class SharingNotifications extends LitElement {
  static styles = css`
    :host {
      display: block;
    }

    .notifications-container {
      display: flex;
      flex-direction: column;
      gap: 12px;
      margin-bottom: 24px;
    }

    .notification-card {
      background: linear-gradient(135deg, rgba(79, 70, 229, 0.1) 0%, rgba(79, 70, 229, 0.05) 100%);
      border: 1px solid rgba(79, 70, 229, 0.2);
      border-radius: 12px;
      padding: 16px 20px;
      animation: slideIn 0.3s ease-out;
    }

    .notification-card.warning {
      background: linear-gradient(135deg, rgba(245, 158, 11, 0.1) 0%, rgba(245, 158, 11, 0.05) 100%);
      border-color: rgba(245, 158, 11, 0.2);
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

    .notification-header {
      display: flex;
      align-items: flex-start;
      gap: 12px;
    }

    .notification-icon {
      font-size: 1.6rem;
      flex-shrink: 0;
    }

    .notification-content {
      flex: 1;
      min-width: 0;
    }

    .notification-title {
      font-weight: 600;
      font-size: 1rem;
      margin-bottom: 4px;
      color: #fff;
    }

    .notification-message {
      color: #aaa;
      font-size: 0.9rem;
      line-height: 1.4;
      margin-bottom: 12px;
    }

    .notification-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 12px;
    }

    .meta-tag {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 0.8rem;
      background: rgba(255, 255, 255, 0.1);
      color: #ccc;
    }

    .meta-tag.tier {
      background: rgba(79, 70, 229, 0.2);
      color: #818cf8;
    }

    .meta-tag.tier.live {
      background: rgba(34, 197, 94, 0.2);
      color: #22c55e;
    }

    .meta-tag.tier.delegated {
      background: rgba(245, 158, 11, 0.2);
      color: #f59e0b;
    }

    .notification-actions {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }

    .btn {
      padding: 10px 18px;
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

    .btn-primary:hover:not(:disabled) {
      background: #4338ca;
    }

    .btn-success {
      background: rgba(34, 197, 94, 0.2);
      color: #22c55e;
    }

    .btn-success:hover:not(:disabled) {
      background: rgba(34, 197, 94, 0.3);
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

    .notification-time {
      font-size: 0.8rem;
      color: #666;
      margin-top: 8px;
    }

    .dismiss-btn {
      background: none;
      border: none;
      color: #666;
      cursor: pointer;
      padding: 4px;
      font-size: 1.2rem;
      line-height: 1;
      flex-shrink: 0;
    }

    .dismiss-btn:hover {
      color: #aaa;
    }

    .empty-state {
      text-align: center;
      padding: 24px;
      color: #666;
      font-size: 0.9rem;
    }

    @media (max-width: 600px) {
      .notification-card {
        padding: 14px 16px;
      }

      .notification-actions {
        flex-direction: column;
      }

      .btn {
        width: 100%;
        justify-content: center;
      }

      .notification-meta {
        flex-direction: column;
        gap: 6px;
      }

      .meta-tag {
        width: fit-content;
      }
    }
  `;

  @property({ type: Array })
  pendingShares: ReceivedShareInfo[] = [];

  @property({ type: Array })
  pendingApprovals: CapabilityApproval[] = [];

  @state()
  private actionLoading: string | null = null;

  @state()
  private dismissedIds: Set<string> = new Set();

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
        return "Real-time access";
      case "CACHED":
        return "Offline access";
      case "DELEGATED":
        return "Full access";
      default:
        return tier;
    }
  }

  private formatTimeAgo(dateStr: string): string {
    const date = new Date(dateStr);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / (1000 * 60));
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));

    if (minutes < 1) return "Just now";
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    if (days === 1) return "Yesterday";
    return `${days} days ago`;
  }

  private buildNotifications(): SharingNotification[] {
    const notifications: SharingNotification[] = [];

    // Add pending share notifications
    for (const share of this.pendingShares) {
      if (this.dismissedIds.has(share.id)) continue;
      if (share.status !== "pending_approval") continue;

      notifications.push({
        id: share.id,
        type: "share_received",
        title: `${share.ownerName} shared their ${share.resourceType} with you`,
        message: `${share.resourceName} - You've been granted ${this.formatPermissions(share.permissions)} access`,
        icon: this.getResourceIcon(share.resourceType),
        data: share,
        createdAt: share.sharedAt,
      });
    }

    // Add pending approval notifications
    for (const approval of this.pendingApprovals) {
      if (this.dismissedIds.has(approval.id)) continue;
      if (approval.status !== "pending") continue;

      notifications.push({
        id: approval.id,
        type: "approval_needed",
        title: "Your share request needs approval",
        message: approval.reason || `Requesting access to ${approval.resource}`,
        icon: "🔐",
        data: approval,
        createdAt: approval.created_at,
      });
    }

    // Sort by creation date (newest first)
    return notifications.sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
    );
  }

  private async handleAcceptShare(share: ReceivedShareInfo) {
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

  private async handleDeclineShare(share: ReceivedShareInfo) {
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

  private handleDismiss(id: string) {
    this.dismissedIds = new Set([...this.dismissedIds, id]);
    this.requestUpdate();
  }

  render() {
    const notifications = this.buildNotifications();

    if (notifications.length === 0) {
      return null;
    }

    return html`
      <div class="notifications-container">
        ${notifications.map((notification) => this.renderNotification(notification))}
      </div>
    `;
  }

  private renderNotification(notification: SharingNotification) {
    const isLoading = this.actionLoading === notification.id;

    if (notification.type === "share_received") {
      const share = notification.data as ReceivedShareInfo;
      return html`
        <div class="notification-card">
          <div class="notification-header">
            <span class="notification-icon">${notification.icon}</span>
            <div class="notification-content">
              <div class="notification-title">${notification.title}</div>
              <div class="notification-message">${notification.message}</div>
              <div class="notification-meta">
                <span class="meta-tag tier ${share.tier.toLowerCase()}">${this.getTierLabel(share.tier)}</span>
                ${share.permissions.map(
                  (p) => html`
                  <span class="meta-tag">${p}</span>
                `,
                )}
              </div>
              <div class="notification-actions">
                <button
                  class="btn btn-success"
                  @click=${() => this.handleAcceptShare(share)}
                  ?disabled=${isLoading}
                >
                  ${isLoading ? "Accepting..." : "Accept"}
                </button>
                <button
                  class="btn btn-secondary"
                  @click=${() => this.handleDeclineShare(share)}
                  ?disabled=${isLoading}
                >
                  Decline
                </button>
              </div>
              <div class="notification-time">${this.formatTimeAgo(notification.createdAt)}</div>
            </div>
            <button class="dismiss-btn" @click=${() => this.handleDismiss(notification.id)}>x</button>
          </div>
        </div>
      `;
    }

    if (notification.type === "approval_needed") {
      const approval = notification.data as CapabilityApproval;
      return html`
        <div class="notification-card warning">
          <div class="notification-header">
            <span class="notification-icon">${notification.icon}</span>
            <div class="notification-content">
              <div class="notification-title">${notification.title}</div>
              <div class="notification-message">${notification.message}</div>
              <div class="notification-meta">
                <span class="meta-tag">${approval.resource}</span>
                ${approval.scope.map(
                  (s) => html`
                  <span class="meta-tag">${s}</span>
                `,
                )}
              </div>
              <div class="notification-actions">
                <span style="color: #f59e0b; font-size: 0.9rem;">
                  Waiting for human approval...
                </span>
              </div>
              <div class="notification-time">${this.formatTimeAgo(notification.createdAt)}</div>
            </div>
            <button class="dismiss-btn" @click=${() => this.handleDismiss(notification.id)}>x</button>
          </div>
        </div>
      `;
    }

    return null;
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
    "sharing-notifications": SharingNotifications;
  }
}

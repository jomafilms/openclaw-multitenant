import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { toast } from "../components/toast.js";
import { api, User, GroupInvite } from "../lib/api.js";

@customElement("ocmt-group-invites")
export class GroupInvitesPage extends LitElement {
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

    .invites-list {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .invite-card {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 20px;
      transition: all 0.2s;
    }

    .invite-card:hover {
      background: rgba(255, 255, 255, 0.08);
    }

    .invite-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      margin-bottom: 12px;
    }

    .group-name {
      font-weight: 600;
      font-size: 1.2rem;
      color: #fff;
    }

    .group-slug {
      color: #888;
      font-size: 0.85rem;
      margin-top: 4px;
    }

    .badge {
      background: rgba(79, 70, 229, 0.2);
      color: #818cf8;
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 0.8rem;
      text-transform: capitalize;
    }

    .badge.admin {
      background: rgba(34, 197, 94, 0.2);
      color: #22c55e;
    }

    .invite-details {
      color: #aaa;
      font-size: 0.9rem;
      margin-bottom: 16px;
    }

    .invite-details p {
      margin: 4px 0;
    }

    .inviter {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .inviter-avatar {
      width: 24px;
      height: 24px;
      border-radius: 50%;
      background: rgba(79, 70, 229, 0.3);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 0.75rem;
      color: #818cf8;
    }

    .expiry {
      color: #f59e0b;
      font-size: 0.85rem;
    }

    .expiry.expired {
      color: #ef4444;
    }

    .actions {
      display: flex;
      gap: 12px;
    }

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

    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
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
      color: #ccc;
      margin-bottom: 8px;
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

    .success-message {
      background: rgba(34, 197, 94, 0.1);
      border: 1px solid rgba(34, 197, 94, 0.3);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 24px;
      color: #22c55e;
    }

    .back-link {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: #888;
      text-decoration: none;
      margin-bottom: 24px;
      font-size: 0.9rem;
    }

    .back-link:hover {
      color: #fff;
    }
  `;

  @property({ type: Object })
  user: User | null = null;

  @state() private invites: GroupInvite[] = [];
  @state() private loading = true;
  @state() private processingId: string | null = null;
  @state() private successMessage: string | null = null;

  connectedCallback() {
    super.connectedCallback();
    this.loadInvites();
  }

  private async loadInvites() {
    this.loading = true;
    try {
      const result = await api.listMyGroupInvites();
      this.invites = result.invites;
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to load invites");
    }
    this.loading = false;
  }

  private async handleAccept(invite: GroupInvite) {
    this.processingId = invite.id;
    try {
      const result = await api.acceptGroupInvite(invite.id);
      this.successMessage = result.message || `You are now a member of ${invite.groupName}`;
      toast.success(this.successMessage);
      await this.loadInvites();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to accept invite");
    }
    this.processingId = null;
  }

  private async handleDecline(invite: GroupInvite) {
    if (!confirm(`Are you sure you want to decline the invite to ${invite.groupName}?`)) {
      return;
    }

    this.processingId = invite.id;
    try {
      await api.declineGroupInvite(invite.id);
      toast.success("Invite declined");
      await this.loadInvites();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to decline invite");
    }
    this.processingId = null;
  }

  private formatDate(dateStr: string): string {
    return new Date(dateStr).toLocaleDateString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  }

  private formatTimeRemaining(expiresAt: string): string {
    const now = new Date();
    const expiry = new Date(expiresAt);
    const diffMs = expiry.getTime() - now.getTime();

    if (diffMs <= 0) {
      return "Expired";
    }

    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    const diffHours = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));

    if (diffDays > 0) {
      return `Expires in ${diffDays} day${diffDays === 1 ? "" : "s"}`;
    }
    if (diffHours > 0) {
      return `Expires in ${diffHours} hour${diffHours === 1 ? "" : "s"}`;
    }
    return "Expires soon";
  }

  private getInitials(name: string): string {
    if (!name) {
      return "??";
    }
    return name
      .split(" ")
      .map((n) => n[0])
      .join("")
      .toUpperCase()
      .slice(0, 2);
  }

  render() {
    return html`
      <a href="/groups" class="back-link">
        &larr; Back to Groups
      </a>

      <h1>Group Invites</h1>
      <p class="subtitle">Accept or decline pending invitations to join groups</p>

      ${
        this.successMessage
          ? html`
        <div class="success-message">
          ${this.successMessage}
        </div>
      `
          : ""
      }

      ${
        this.loading
          ? html`
              <div class="loading">
                <div class="spinner"></div>
              </div>
            `
          : this.invites.length > 0
            ? html`
        <div class="invites-list">
          ${this.invites.map((invite) => this.renderInviteCard(invite))}
        </div>
      `
            : html`
                <div class="empty-state">
                  <div class="empty-state-icon">&#x1F4EC;</div>
                  <h3>No pending invites</h3>
                  <p>You don't have any group invites at the moment.</p>
                </div>
              `
      }
    `;
  }

  private renderInviteCard(invite: GroupInvite) {
    const isProcessing = this.processingId === invite.id;
    const isExpired = invite.expiresAt && new Date(invite.expiresAt) < new Date();

    return html`
      <div class="invite-card">
        <div class="invite-header">
          <div>
            <div class="group-name">${invite.groupName}</div>
            <div class="group-slug">/${invite.groupSlug}</div>
          </div>
          <span class="badge ${invite.role === "admin" ? "admin" : ""}">${invite.role}</span>
        </div>

        <div class="invite-details">
          <div class="inviter">
            <span class="inviter-avatar">${this.getInitials(invite.inviterName || invite.inviterEmail)}</span>
            <span>Invited by ${invite.inviterName || invite.inviterEmail || "Unknown"}</span>
          </div>
          <p>Sent on ${invite.createdAt ? this.formatDate(invite.createdAt) : "Unknown date"}</p>
          ${
            invite.expiresAt
              ? html`
            <p class="expiry ${isExpired ? "expired" : ""}">
              ${isExpired ? "This invite has expired" : this.formatTimeRemaining(invite.expiresAt)}
            </p>
          `
              : ""
          }
        </div>

        ${
          !isExpired
            ? html`
          <div class="actions">
            <button
              class="btn btn-primary"
              @click=${() => this.handleAccept(invite)}
              ?disabled=${isProcessing}
            >
              ${isProcessing ? "Accepting..." : "Accept Invite"}
            </button>
            <button
              class="btn btn-secondary"
              @click=${() => this.handleDecline(invite)}
              ?disabled=${isProcessing}
            >
              Decline
            </button>
          </div>
        `
            : html`
                <div class="actions">
                  <span style="color: #888; font-size: 0.9rem">
                    This invite has expired. Ask the group admin to send a new invite.
                  </span>
                </div>
              `
        }
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-group-invites": GroupInvitesPage;
  }
}

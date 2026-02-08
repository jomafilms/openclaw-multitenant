import { LitElement, html, css } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { api } from '../lib/api.js';
import { toast } from './toast.js';

export interface SharedResource {
  id: string;
  resourceId: string;
  resourceName: string;
  resourceType: string;
  recipientId: string;
  recipientName: string;
  recipientEmail: string;
  tier: 'LIVE' | 'CACHED' | 'DELEGATED';
  permissions: string[];
  status: 'active' | 'pending' | 'expired' | 'revoked';
  expiresAt?: string;
  createdAt: string;
  approvedAt?: string;
}

@customElement('shared-resources-list')
export class SharedResourcesList extends LitElement {
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

    .share-card.pending {
      border-color: rgba(245, 158, 11, 0.3);
    }

    .share-card.expired {
      opacity: 0.6;
      border-color: rgba(239, 68, 68, 0.3);
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

    .share-recipient {
      color: #aaa;
      font-size: 0.9rem;
      margin-bottom: 12px;
    }

    .share-recipient strong {
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

    .status-badge {
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 0.8rem;
      font-weight: 500;
    }

    .status-badge.active {
      background: rgba(34, 197, 94, 0.15);
      color: #22c55e;
    }

    .status-badge.pending {
      background: rgba(245, 158, 11, 0.15);
      color: #f59e0b;
    }

    .status-badge.expired {
      background: rgba(239, 68, 68, 0.15);
      color: #ef4444;
    }

    .share-expiry {
      font-size: 0.85rem;
      color: #888;
    }

    .share-expiry.expiring-soon {
      color: #f59e0b;
    }

    .share-expiry.expired {
      color: #ef4444;
    }

    .share-actions {
      display: flex;
      flex-shrink: 0;
    }

    .btn {
      padding: 8px 16px;
      border-radius: 8px;
      border: none;
      font-size: 0.85rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    .btn-danger {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
    }

    .btn-danger:hover {
      background: rgba(239, 68, 68, 0.3);
    }

    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
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
      to { transform: rotate(360deg); }
    }

    @media (max-width: 600px) {
      .share-header {
        flex-direction: column;
        gap: 12px;
      }

      .share-actions {
        width: 100%;
      }

      .btn {
        width: 100%;
        justify-content: center;
      }

      .share-meta {
        flex-direction: column;
        gap: 6px;
      }

      .meta-badge {
        width: fit-content;
      }
    }
  `;

  @property({ type: Array })
  shares: SharedResource[] = [];

  @property({ type: Boolean })
  loading = false;

  @state()
  private actionLoading: string | null = null;

  private getResourceIcon(type: string): string {
    switch (type) {
      case 'calendar': return '📅';
      case 'email': return '📧';
      case 'drive':
      case 'files': return '📁';
      case 'contacts': return '👥';
      case 'api': return '🔌';
      case 'mcp_server': return '🖥️';
      default: return '📦';
    }
  }

  private getTierLabel(tier: string): string {
    switch (tier) {
      case 'LIVE': return 'Real-time';
      case 'CACHED': return 'Offline';
      case 'DELEGATED': return 'Full access';
      default: return tier;
    }
  }

  private formatExpiry(expiresAt: string | undefined, status: string): { text: string; class: string } {
    if (status === 'expired') {
      return { text: 'Expired', class: 'expired' };
    }
    if (!expiresAt) {
      return { text: 'No expiry', class: '' };
    }

    const date = new Date(expiresAt);
    const now = new Date();
    const diff = date.getTime() - now.getTime();
    const days = Math.ceil(diff / (1000 * 60 * 60 * 24));

    if (days < 0) return { text: 'Expired', class: 'expired' };
    if (days === 0) return { text: 'Expires today', class: 'expiring-soon' };
    if (days === 1) return { text: 'Expires tomorrow', class: 'expiring-soon' };
    if (days <= 3) return { text: `Expires in ${days} days`, class: 'expiring-soon' };
    if (days <= 7) return { text: `Expires in ${days} days`, class: '' };

    return {
      text: `Expires ${date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}`,
      class: ''
    };
  }

  private async handleRevoke(share: SharedResource) {
    if (!confirm(`Revoke ${share.recipientName}'s access to ${share.resourceName}? This action cannot be undone.`)) {
      return;
    }

    this.actionLoading = share.id;

    try {
      await api.revokeResourceShare(share.id);
      toast.success(`Revoked access for ${share.recipientName}`);
      this.dispatchEvent(new CustomEvent('share-revoked', {
        bubbles: true,
        composed: true,
        detail: { shareId: share.id }
      }));
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to revoke access');
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

    const activeShares = this.shares.filter(s => s.status === 'active');
    const pendingShares = this.shares.filter(s => s.status === 'pending');
    const expiredShares = this.shares.filter(s => s.status === 'expired');

    return html`
      <div class="section-header">
        <h2>
          What I've Shared
          <span class="badge">${activeShares.length + pendingShares.length}</span>
        </h2>
      </div>

      ${this.shares.length === 0 ? html`
        <div class="empty-state">
          <div class="empty-state-icon">🔒</div>
          <h3>No active shares</h3>
          <p>You haven't shared any resources yet. Share data with trusted contacts from your integrations.</p>
        </div>
      ` : html`
        <div class="share-list">
          ${pendingShares.map(share => this.renderShareCard(share))}
          ${activeShares.map(share => this.renderShareCard(share))}
          ${expiredShares.map(share => this.renderShareCard(share))}
        </div>
      `}
    `;
  }

  private renderShareCard(share: SharedResource) {
    const isLoading = this.actionLoading === share.id;
    const expiry = this.formatExpiry(share.expiresAt, share.status);
    const canRevoke = share.status === 'active' || share.status === 'pending';

    return html`
      <div class="share-card ${share.status}">
        <div class="share-header">
          <div class="share-info">
            <div class="share-resource">
              <span class="resource-icon">${this.getResourceIcon(share.resourceType)}</span>
              <span class="resource-name">${share.resourceName}</span>
            </div>
            <div class="share-recipient">
              Shared with <strong>${share.recipientName}</strong>
              <span style="color: #666;">(${share.recipientEmail})</span>
            </div>
            <div class="share-meta">
              <span class="meta-badge tier-badge ${share.tier.toLowerCase()}">
                ${this.getTierLabel(share.tier)}
              </span>
              ${share.permissions.map(p => html`
                <span class="meta-badge permission-badge">${p}</span>
              `)}
              <span class="status-badge ${share.status}">${share.status}</span>
            </div>
            <div class="share-expiry ${expiry.class}">
              ${expiry.text}
            </div>
          </div>
          ${canRevoke ? html`
            <div class="share-actions">
              <button
                class="btn btn-danger"
                @click=${() => this.handleRevoke(share)}
                ?disabled=${isLoading}
              >
                ${isLoading ? 'Revoking...' : 'Revoke'}
              </button>
            </div>
          ` : ''}
        </div>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'shared-resources-list': SharedResourcesList;
  }
}

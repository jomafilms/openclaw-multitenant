import { LitElement, html, css } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { api } from '../lib/api.js';
import { toast } from './toast.js';

export interface ShareableResource {
  id: string;
  name: string;
  type: string;
  icon?: string;
}

export type AccessTier = 'LIVE' | 'CACHED' | 'DELEGATED';
export type Permission = 'read' | 'write' | 'delete';
export type ExpiryOption = '1d' | '1w' | '1m' | 'custom' | 'never';

interface ShareConfig {
  resourceId: string;
  recipientEmail: string;
  tier: AccessTier;
  permissions: Permission[];
  expiresAt?: string;
}

@customElement('share-resource-modal')
export class ShareResourceModal extends LitElement {
  static styles = css`
    .overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.8);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      backdrop-filter: blur(4px);
      padding: 16px;
    }

    .modal {
      background: #1a1a2e;
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      padding: 32px;
      max-width: 520px;
      width: 100%;
      max-height: 90vh;
      overflow-y: auto;
      animation: slideUp 0.2s ease-out;
    }

    @keyframes slideUp {
      from {
        opacity: 0;
        transform: translateY(20px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    .modal-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 24px;
    }

    h2 {
      font-size: 1.4rem;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .close-btn {
      background: none;
      border: none;
      color: #666;
      font-size: 1.5rem;
      cursor: pointer;
      padding: 4px;
      line-height: 1;
    }

    .close-btn:hover {
      color: #aaa;
    }

    .resource-preview {
      background: rgba(79, 70, 229, 0.1);
      border: 1px solid rgba(79, 70, 229, 0.2);
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 24px;
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .resource-icon {
      font-size: 1.8rem;
    }

    .resource-info h3 {
      font-size: 1rem;
      margin-bottom: 2px;
    }

    .resource-info .type {
      font-size: 0.85rem;
      color: #888;
    }

    .form-group {
      margin-bottom: 24px;
    }

    label {
      display: block;
      font-size: 0.9rem;
      font-weight: 500;
      margin-bottom: 8px;
      color: #ccc;
    }

    .label-hint {
      font-weight: normal;
      color: #888;
      font-size: 0.85rem;
    }

    input[type="text"],
    input[type="email"],
    input[type="datetime-local"] {
      width: 100%;
      padding: 14px 16px;
      border-radius: 8px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: rgba(255, 255, 255, 0.1);
      color: white;
      font-size: 1rem;
      box-sizing: border-box;
    }

    input:focus {
      outline: none;
      border-color: #4f46e5;
    }

    input::placeholder {
      color: #666;
    }

    /* Access tier selection */
    .tier-options {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .tier-option {
      background: rgba(255, 255, 255, 0.05);
      border: 2px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 16px;
      cursor: pointer;
      transition: all 0.2s;
    }

    .tier-option:hover {
      background: rgba(255, 255, 255, 0.08);
    }

    .tier-option.selected {
      border-color: #4f46e5;
      background: rgba(79, 70, 229, 0.1);
    }

    .tier-option input {
      display: none;
    }

    .tier-header {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 6px;
    }

    .tier-icon {
      font-size: 1.2rem;
    }

    .tier-name {
      font-weight: 600;
      font-size: 1rem;
    }

    .tier-badge {
      font-size: 0.7rem;
      padding: 2px 8px;
      border-radius: 10px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .tier-badge.live {
      background: rgba(34, 197, 94, 0.2);
      color: #22c55e;
    }

    .tier-badge.cached {
      background: rgba(79, 70, 229, 0.2);
      color: #818cf8;
    }

    .tier-badge.delegated {
      background: rgba(245, 158, 11, 0.2);
      color: #f59e0b;
    }

    .tier-description {
      color: #aaa;
      font-size: 0.9rem;
      line-height: 1.4;
    }

    .tier-warning {
      margin-top: 8px;
      padding: 8px 12px;
      background: rgba(245, 158, 11, 0.1);
      border: 1px solid rgba(245, 158, 11, 0.2);
      border-radius: 8px;
      color: #f59e0b;
      font-size: 0.85rem;
      display: flex;
      align-items: flex-start;
      gap: 8px;
    }

    /* Permissions */
    .permissions-group {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
    }

    .permission-checkbox {
      display: flex;
      align-items: center;
      gap: 8px;
      cursor: pointer;
      padding: 10px 16px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 8px;
      transition: all 0.2s;
    }

    .permission-checkbox:hover {
      background: rgba(255, 255, 255, 0.08);
    }

    .permission-checkbox.checked {
      background: rgba(79, 70, 229, 0.15);
      border-color: rgba(79, 70, 229, 0.3);
    }

    .permission-checkbox input {
      display: none;
    }

    .checkbox-icon {
      width: 20px;
      height: 20px;
      border: 2px solid rgba(255, 255, 255, 0.3);
      border-radius: 4px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.2s;
    }

    .permission-checkbox.checked .checkbox-icon {
      background: #4f46e5;
      border-color: #4f46e5;
    }

    .checkbox-icon svg {
      width: 12px;
      height: 12px;
      color: white;
      opacity: 0;
      transition: opacity 0.2s;
    }

    .permission-checkbox.checked .checkbox-icon svg {
      opacity: 1;
    }

    .permission-label {
      font-size: 0.95rem;
    }

    /* Expiry options */
    .expiry-options {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 12px;
    }

    .expiry-btn {
      padding: 10px 16px;
      border-radius: 8px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: rgba(255, 255, 255, 0.05);
      color: #ccc;
      font-size: 0.9rem;
      cursor: pointer;
      transition: all 0.2s;
    }

    .expiry-btn:hover {
      background: rgba(255, 255, 255, 0.1);
    }

    .expiry-btn.selected {
      background: rgba(79, 70, 229, 0.2);
      border-color: #4f46e5;
      color: #818cf8;
    }

    .custom-expiry {
      margin-top: 12px;
    }

    /* Actions */
    .modal-actions {
      display: flex;
      gap: 12px;
      margin-top: 32px;
    }

    .btn {
      flex: 1;
      padding: 14px 24px;
      border-radius: 8px;
      border: none;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
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

    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.15);
    }

    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .error {
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.3);
      border-radius: 8px;
      padding: 12px 16px;
      color: #fca5a5;
      margin-bottom: 16px;
      font-size: 0.9rem;
    }

    @media (max-width: 480px) {
      .modal {
        padding: 24px 16px;
      }

      .tier-options {
        gap: 8px;
      }

      .tier-option {
        padding: 12px;
      }

      .permissions-group {
        flex-direction: column;
      }

      .permission-checkbox {
        width: 100%;
      }

      .expiry-options {
        flex-direction: column;
      }

      .expiry-btn {
        width: 100%;
        text-align: center;
      }

      .modal-actions {
        flex-direction: column;
      }
    }
  `;

  @property({ type: Boolean }) open = false;
  @property({ type: Object }) resource: ShareableResource | null = null;

  @state() private recipientEmail = '';
  @state() private selectedTier: AccessTier = 'CACHED';
  @state() private permissions: Set<Permission> = new Set(['read']);
  @state() private expiryOption: ExpiryOption = '1w';
  @state() private customExpiry = '';
  @state() private loading = false;
  @state() private error = '';

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

  private handleTierChange(tier: AccessTier) {
    this.selectedTier = tier;
  }

  private handlePermissionToggle(permission: Permission) {
    const newPermissions = new Set(this.permissions);
    if (newPermissions.has(permission)) {
      // Can't remove read permission
      if (permission !== 'read') {
        newPermissions.delete(permission);
      }
    } else {
      newPermissions.add(permission);
    }
    this.permissions = newPermissions;
  }

  private handleExpiryChange(option: ExpiryOption) {
    this.expiryOption = option;
    if (option !== 'custom') {
      this.customExpiry = '';
    }
  }

  private calculateExpiryDate(): string | undefined {
    const now = new Date();
    switch (this.expiryOption) {
      case '1d':
        now.setDate(now.getDate() + 1);
        return now.toISOString();
      case '1w':
        now.setDate(now.getDate() + 7);
        return now.toISOString();
      case '1m':
        now.setMonth(now.getMonth() + 1);
        return now.toISOString();
      case 'custom':
        return this.customExpiry ? new Date(this.customExpiry).toISOString() : undefined;
      case 'never':
        return undefined;
    }
  }

  private async handleShare() {
    if (!this.resource || !this.recipientEmail) return;

    this.loading = true;
    this.error = '';

    try {
      const config: ShareConfig = {
        resourceId: this.resource.id,
        recipientEmail: this.recipientEmail,
        tier: this.selectedTier,
        permissions: Array.from(this.permissions),
        expiresAt: this.calculateExpiryDate()
      };

      await api.createResourceShare(config);

      toast.success(`Shared ${this.resource.name} with ${this.recipientEmail}`);
      this.dispatchEvent(new CustomEvent('shared', {
        bubbles: true,
        composed: true,
        detail: config
      }));
      this.resetForm();
      this.dispatchEvent(new CustomEvent('close', { bubbles: true, composed: true }));
    } catch (err) {
      this.error = err instanceof Error ? err.message : 'Failed to share resource';
    }

    this.loading = false;
  }

  private resetForm() {
    this.recipientEmail = '';
    this.selectedTier = 'CACHED';
    this.permissions = new Set(['read']);
    this.expiryOption = '1w';
    this.customExpiry = '';
    this.error = '';
  }

  private handleClose() {
    this.resetForm();
    this.dispatchEvent(new CustomEvent('close', { bubbles: true, composed: true }));
  }

  private handleKeyDown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      this.handleClose();
    }
  }

  render() {
    if (!this.open || !this.resource) return null;

    return html`
      <div class="overlay" @click=${(e: Event) => {
        if (e.target === e.currentTarget) this.handleClose();
      }} @keydown=${this.handleKeyDown}>
        <div class="modal">
          <div class="modal-header">
            <h2>Share Resource</h2>
            <button class="close-btn" @click=${this.handleClose}>x</button>
          </div>

          <div class="resource-preview">
            <span class="resource-icon">${this.resource.icon || this.getResourceIcon(this.resource.type)}</span>
            <div class="resource-info">
              <h3>${this.resource.name}</h3>
              <span class="type">${this.resource.type}</span>
            </div>
          </div>

          ${this.error ? html`<div class="error">${this.error}</div>` : ''}

          <div class="form-group">
            <label for="recipient">Share with</label>
            <input
              id="recipient"
              type="email"
              placeholder="Enter email address"
              .value=${this.recipientEmail}
              @input=${(e: Event) => this.recipientEmail = (e.target as HTMLInputElement).value}
            />
          </div>

          <div class="form-group">
            <label>Access type <span class="label-hint">- How they can access your data</span></label>
            <div class="tier-options">
              <label class="tier-option ${this.selectedTier === 'LIVE' ? 'selected' : ''}">
                <input
                  type="radio"
                  name="tier"
                  value="LIVE"
                  .checked=${this.selectedTier === 'LIVE'}
                  @change=${() => this.handleTierChange('LIVE')}
                />
                <div class="tier-header">
                  <span class="tier-icon">🟢</span>
                  <span class="tier-name">Real-time access</span>
                  <span class="tier-badge live">Live</span>
                </div>
                <div class="tier-description">
                  They can access your data when you're online. Always up-to-date.
                </div>
              </label>

              <label class="tier-option ${this.selectedTier === 'CACHED' ? 'selected' : ''}">
                <input
                  type="radio"
                  name="tier"
                  value="CACHED"
                  .checked=${this.selectedTier === 'CACHED'}
                  @change=${() => this.handleTierChange('CACHED')}
                />
                <div class="tier-header">
                  <span class="tier-icon">📦</span>
                  <span class="tier-name">Offline access</span>
                  <span class="tier-badge cached">Cached</span>
                </div>
                <div class="tier-description">
                  They can access anytime, even when you're offline. Data may be slightly outdated.
                </div>
              </label>

              <label class="tier-option ${this.selectedTier === 'DELEGATED' ? 'selected' : ''}">
                <input
                  type="radio"
                  name="tier"
                  value="DELEGATED"
                  .checked=${this.selectedTier === 'DELEGATED'}
                  @change=${() => this.handleTierChange('DELEGATED')}
                />
                <div class="tier-header">
                  <span class="tier-icon">🔗</span>
                  <span class="tier-name">Full access</span>
                  <span class="tier-badge delegated">Delegated</span>
                </div>
                <div class="tier-description">
                  They get their own direct connection. Most powerful but grants significant access.
                </div>
                ${this.selectedTier === 'DELEGATED' ? html`
                  <div class="tier-warning">
                    <span>!</span>
                    <span>This grants significant access. The recipient can act on your behalf for this resource. Only use for highly trusted contacts.</span>
                  </div>
                ` : ''}
              </label>
            </div>
          </div>

          <div class="form-group">
            <label>Permissions</label>
            <div class="permissions-group">
              <label class="permission-checkbox checked">
                <input
                  type="checkbox"
                  checked
                  disabled
                />
                <span class="checkbox-icon">
                  <svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M2 6l3 3 5-6" />
                  </svg>
                </span>
                <span class="permission-label">Read</span>
              </label>

              <label class="permission-checkbox ${this.permissions.has('write') ? 'checked' : ''}"
                @click=${() => this.handlePermissionToggle('write')}>
                <input
                  type="checkbox"
                  .checked=${this.permissions.has('write')}
                />
                <span class="checkbox-icon">
                  <svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M2 6l3 3 5-6" />
                  </svg>
                </span>
                <span class="permission-label">Write</span>
              </label>

              <label class="permission-checkbox ${this.permissions.has('delete') ? 'checked' : ''}"
                @click=${() => this.handlePermissionToggle('delete')}>
                <input
                  type="checkbox"
                  .checked=${this.permissions.has('delete')}
                />
                <span class="checkbox-icon">
                  <svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M2 6l3 3 5-6" />
                  </svg>
                </span>
                <span class="permission-label">Delete</span>
              </label>
            </div>
          </div>

          <div class="form-group">
            <label>Expires</label>
            <div class="expiry-options">
              <button
                type="button"
                class="expiry-btn ${this.expiryOption === '1d' ? 'selected' : ''}"
                @click=${() => this.handleExpiryChange('1d')}
              >
                1 day
              </button>
              <button
                type="button"
                class="expiry-btn ${this.expiryOption === '1w' ? 'selected' : ''}"
                @click=${() => this.handleExpiryChange('1w')}
              >
                1 week
              </button>
              <button
                type="button"
                class="expiry-btn ${this.expiryOption === '1m' ? 'selected' : ''}"
                @click=${() => this.handleExpiryChange('1m')}
              >
                1 month
              </button>
              <button
                type="button"
                class="expiry-btn ${this.expiryOption === 'never' ? 'selected' : ''}"
                @click=${() => this.handleExpiryChange('never')}
              >
                Never
              </button>
              <button
                type="button"
                class="expiry-btn ${this.expiryOption === 'custom' ? 'selected' : ''}"
                @click=${() => this.handleExpiryChange('custom')}
              >
                Custom
              </button>
            </div>
            ${this.expiryOption === 'custom' ? html`
              <div class="custom-expiry">
                <input
                  type="datetime-local"
                  .value=${this.customExpiry}
                  @input=${(e: Event) => this.customExpiry = (e.target as HTMLInputElement).value}
                />
              </div>
            ` : ''}
          </div>

          <div class="modal-actions">
            <button class="btn btn-secondary" @click=${this.handleClose}>
              Cancel
            </button>
            <button
              class="btn btn-primary"
              @click=${this.handleShare}
              ?disabled=${!this.recipientEmail || this.loading}
            >
              ${this.loading ? 'Sharing...' : 'Share'}
            </button>
          </div>
        </div>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'share-resource-modal': ShareResourceModal;
  }
}

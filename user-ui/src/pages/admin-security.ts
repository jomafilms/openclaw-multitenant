/**
 * Admin Security Dashboard
 *
 * Provides admin-only UI for managing:
 * - IP Allowlist configuration
 * - Security settings
 * - Emergency access tokens
 */
import { LitElement, html, css, TemplateResult } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { api, User, IpAllowlistEntry, EmergencyToken } from "../lib/api.js";

@customElement("ocmt-admin-security")
export class AdminSecurityPage extends LitElement {
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

    .admin-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 12px;
      background: rgba(239, 68, 68, 0.2);
      border: 1px solid rgba(239, 68, 68, 0.3);
      border-radius: 6px;
      color: #ef4444;
      font-size: 0.85rem;
      font-weight: 500;
      margin-left: 12px;
    }

    .section {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
    }

    .section-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 20px;
    }

    .section-title {
      font-size: 1.2rem;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .section-icon {
      font-size: 1.3rem;
    }

    .toggle-container {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .toggle {
      position: relative;
      width: 48px;
      height: 26px;
      background: rgba(255, 255, 255, 0.1);
      border-radius: 13px;
      cursor: pointer;
      transition: background 0.2s;
    }

    .toggle.enabled {
      background: #22c55e;
    }

    .toggle::after {
      content: "";
      position: absolute;
      top: 3px;
      left: 3px;
      width: 20px;
      height: 20px;
      background: white;
      border-radius: 50%;
      transition: transform 0.2s;
    }

    .toggle.enabled::after {
      transform: translateX(22px);
    }

    .toggle-label {
      font-size: 0.9rem;
      color: #888;
    }

    /* Table styles */
    .data-table {
      width: 100%;
      border-collapse: collapse;
    }

    .data-table th {
      text-align: left;
      padding: 10px 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
      color: #888;
      font-weight: 500;
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .data-table td {
      padding: 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      vertical-align: middle;
    }

    .data-table tr:hover td {
      background: rgba(255, 255, 255, 0.02);
    }

    .ip-range {
      font-family: monospace;
      font-size: 0.95rem;
      color: #818cf8;
    }

    .description {
      color: #888;
      font-size: 0.9rem;
    }

    .meta {
      font-size: 0.8rem;
      color: #666;
    }

    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 3px 10px;
      border-radius: 10px;
      font-size: 0.75rem;
      font-weight: 500;
    }

    .status-badge.active {
      background: rgba(34, 197, 94, 0.2);
      color: #22c55e;
    }

    .status-badge.expired {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
    }

    .status-badge.used {
      background: rgba(251, 191, 36, 0.2);
      color: #fbbf24;
    }

    /* Form styles */
    .form-row {
      display: flex;
      gap: 12px;
      margin-bottom: 16px;
    }

    .form-group {
      flex: 1;
    }

    .form-group label {
      display: block;
      margin-bottom: 6px;
      font-size: 0.85rem;
      color: #888;
    }

    .input {
      width: 100%;
      padding: 10px 12px;
      border-radius: 8px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: rgba(255, 255, 255, 0.05);
      color: white;
      font-size: 0.95rem;
      box-sizing: border-box;
    }

    .input:focus {
      outline: none;
      border-color: #4f46e5;
    }

    .input::placeholder {
      color: #666;
    }

    .input.mono {
      font-family: monospace;
    }

    /* Button styles */
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

    .btn-icon {
      padding: 8px;
      background: none;
      border: none;
      color: #888;
      cursor: pointer;
      border-radius: 6px;
    }

    .btn-icon:hover {
      background: rgba(255, 255, 255, 0.1);
      color: white;
    }

    .btn-icon.danger:hover {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
    }

    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .action-buttons {
      display: flex;
      gap: 8px;
      margin-top: 16px;
    }

    /* Current IP display */
    .current-ip {
      display: flex;
      align-items: center;
      gap: 16px;
      padding: 12px 16px;
      background: rgba(79, 70, 229, 0.1);
      border: 1px solid rgba(79, 70, 229, 0.2);
      border-radius: 8px;
      margin-bottom: 16px;
    }

    .current-ip-label {
      color: #888;
      font-size: 0.9rem;
    }

    .current-ip-value {
      font-family: monospace;
      color: #818cf8;
      font-weight: 500;
    }

    /* Token display */
    .token-display {
      padding: 16px;
      background: rgba(251, 191, 36, 0.1);
      border: 1px solid rgba(251, 191, 36, 0.3);
      border-radius: 8px;
      margin-top: 16px;
    }

    .token-warning {
      display: flex;
      align-items: center;
      gap: 8px;
      color: #fbbf24;
      font-size: 0.9rem;
      margin-bottom: 12px;
    }

    .token-value {
      font-family: monospace;
      font-size: 1rem;
      padding: 12px;
      background: rgba(0, 0, 0, 0.3);
      border-radius: 6px;
      word-break: break-all;
      color: white;
    }

    .copy-btn {
      margin-top: 12px;
    }

    /* Settings list */
    .settings-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .setting-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 16px;
      background: rgba(255, 255, 255, 0.02);
      border-radius: 8px;
    }

    .setting-key {
      font-family: monospace;
      color: #818cf8;
    }

    .setting-value {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .env-badge {
      font-size: 0.75rem;
      padding: 2px 8px;
      background: rgba(100, 100, 100, 0.3);
      border-radius: 4px;
      color: #888;
    }

    /* Empty state */
    .empty-state {
      text-align: center;
      padding: 32px;
      color: #888;
    }

    .empty-state-icon {
      font-size: 2.5rem;
      margin-bottom: 12px;
    }

    /* Loading state */
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

    /* Error state */
    .error-banner {
      background: rgba(239, 68, 68, 0.2);
      border: 1px solid rgba(239, 68, 68, 0.3);
      padding: 16px;
      border-radius: 8px;
      color: #ef4444;
      margin-bottom: 24px;
    }

    .access-denied {
      text-align: center;
      padding: 60px 20px;
    }

    .access-denied-icon {
      font-size: 4rem;
      margin-bottom: 20px;
    }

    .access-denied h2 {
      margin-bottom: 12px;
    }

    .access-denied p {
      color: #888;
    }

    /* Modal */
    .modal-overlay {
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
    }

    .modal {
      background: #1a1a2e;
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      padding: 24px;
      max-width: 500px;
      width: 90%;
    }

    .modal h3 {
      margin-bottom: 16px;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .modal-buttons {
      display: flex;
      gap: 8px;
      margin-top: 20px;
    }

    .modal-buttons .btn {
      flex: 1;
    }

    .confirm-text {
      color: #888;
      margin-bottom: 16px;
      line-height: 1.5;
    }

    .confirm-warning {
      background: rgba(251, 191, 36, 0.1);
      border: 1px solid rgba(251, 191, 36, 0.3);
      padding: 12px;
      border-radius: 8px;
      color: #fbbf24;
      font-size: 0.9rem;
      margin-bottom: 16px;
    }
  `;

  @property({ type: Object })
  user: User | null = null;

  @state()
  private loading = true;

  @state()
  private isAdmin = false;

  @state()
  private error = "";

  // IP Allowlist state
  @state()
  private allowlistEnabled = false;

  @state()
  private ipEntries: IpAllowlistEntry[] = [];

  @state()
  private clientIp = "";

  @state()
  private newIpRange = "";

  @state()
  private newIpDescription = "";

  @state()
  private addingIp = false;

  // Settings state
  @state()
  private settings: Record<string, unknown> = {};

  @state()
  private envSettings: Record<string, number> = {};

  // Emergency tokens state
  @state()
  private emergencyTokens: EmergencyToken[] = [];

  @state()
  private newTokenReason = "";

  @state()
  private newTokenExpiry = 24;

  @state()
  private newTokenSingleUse = true;

  @state()
  private creatingToken = false;

  @state()
  private createdToken: string | null = null;

  // Modal state
  @state()
  private showConfirmModal = false;

  @state()
  private confirmAction: (() => Promise<void>) | null = null;

  @state()
  private confirmTitle = "";

  @state()
  private confirmMessage = "";

  @state()
  private confirmWarning = "";

  async connectedCallback() {
    super.connectedCallback();
    await this.checkAdminAccess();
  }

  private async checkAdminAccess() {
    this.loading = true;
    this.error = "";

    try {
      const result = await api.checkAdminStatus();
      this.isAdmin = result.isAdmin;

      if (this.isAdmin) {
        await this.loadAllData();
      }
    } catch (err) {
      console.error("Admin check failed:", err);
      this.isAdmin = false;
    }

    this.loading = false;
  }

  private async loadAllData() {
    try {
      const [allowlistData, settingsData, tokensData] = await Promise.all([
        api.getIpAllowlist(),
        api.getSecuritySettings(),
        api.listEmergencyTokens(),
      ]);

      this.allowlistEnabled = allowlistData.enabled;
      this.ipEntries = allowlistData.entries;
      this.clientIp = allowlistData.clientIp;

      this.settings = settingsData.settings;
      this.envSettings = settingsData.envSettings;

      this.emergencyTokens = tokensData.tokens;
    } catch (err) {
      console.error("Failed to load admin security data:", err);
      this.error = err instanceof Error ? err.message : "Failed to load data";
    }
  }

  private async handleToggleAllowlist() {
    const newState = !this.allowlistEnabled;

    // If disabling, show confirmation
    if (!newState) {
      this.confirmTitle = "Disable IP Allowlist";
      this.confirmMessage =
        "Disabling the IP allowlist will allow admin access from any IP address. This reduces security.";
      this.confirmWarning = "Are you sure you want to disable the IP allowlist?";
      this.confirmAction = async () => {
        await this.toggleAllowlist(false);
      };
      this.showConfirmModal = true;
      return;
    }

    await this.toggleAllowlist(true);
  }

  private async toggleAllowlist(enabled: boolean) {
    try {
      await api.toggleIpAllowlist(enabled);
      this.allowlistEnabled = enabled;
    } catch (err) {
      console.error("Failed to toggle allowlist:", err);
      this.error = err instanceof Error ? err.message : "Failed to update";
    }
  }

  private async handleAddIp() {
    if (!this.newIpRange.trim()) {
      return;
    }

    this.addingIp = true;
    this.error = "";

    try {
      const result = await api.addIpToAllowlist(
        this.newIpRange.trim(),
        this.newIpDescription.trim() || undefined,
      );
      this.ipEntries = [...this.ipEntries, result.entry];
      this.newIpRange = "";
      this.newIpDescription = "";
    } catch (err) {
      console.error("Failed to add IP:", err);
      this.error = err instanceof Error ? err.message : "Failed to add IP";
    }

    this.addingIp = false;
  }

  private async handleAddCurrentIp() {
    this.addingIp = true;
    this.error = "";

    try {
      const result = await api.addCurrentIpToAllowlist(`Added from admin dashboard`);
      this.ipEntries = [...this.ipEntries, result.entry];
    } catch (err) {
      console.error("Failed to add current IP:", err);
      this.error = err instanceof Error ? err.message : "Failed to add IP";
    }

    this.addingIp = false;
  }

  private async handleRemoveIp(entry: IpAllowlistEntry) {
    this.confirmTitle = "Remove IP from Allowlist";
    this.confirmMessage = `Remove ${entry.ipRange} from the allowlist?`;
    this.confirmWarning = entry.description || "";
    this.confirmAction = async () => {
      try {
        await api.removeIpFromAllowlist(entry.id);
        this.ipEntries = this.ipEntries.filter((e) => e.id !== entry.id);
      } catch (err) {
        console.error("Failed to remove IP:", err);
        this.error = err instanceof Error ? err.message : "Failed to remove IP";
      }
    };
    this.showConfirmModal = true;
  }

  private async handleCreateToken() {
    if (!this.newTokenReason.trim()) {
      return;
    }

    this.confirmTitle = "Create Emergency Access Token";
    this.confirmMessage =
      "This will create a token that bypasses normal admin authentication. Use with extreme caution.";
    this.confirmWarning = "Only create this token if you have a legitimate emergency access need.";
    this.confirmAction = async () => {
      this.creatingToken = true;
      try {
        const result = await api.createEmergencyToken(
          this.newTokenReason.trim(),
          this.newTokenExpiry,
          this.newTokenSingleUse,
        );
        this.createdToken = result.token;
        this.newTokenReason = "";

        // Refresh token list
        const tokensData = await api.listEmergencyTokens();
        this.emergencyTokens = tokensData.tokens;
      } catch (err) {
        console.error("Failed to create token:", err);
        this.error = err instanceof Error ? err.message : "Failed to create token";
      }
      this.creatingToken = false;
    };
    this.showConfirmModal = true;
  }

  private async handleRevokeToken(token: EmergencyToken) {
    this.confirmTitle = "Revoke Emergency Token";
    this.confirmMessage = `Revoke the emergency token created for: "${token.reason}"?`;
    this.confirmWarning = "This token will no longer be usable.";
    this.confirmAction = async () => {
      try {
        await api.revokeEmergencyToken(token.id);
        this.emergencyTokens = this.emergencyTokens.filter((t) => t.id !== token.id);
      } catch (err) {
        console.error("Failed to revoke token:", err);
        this.error = err instanceof Error ? err.message : "Failed to revoke token";
      }
    };
    this.showConfirmModal = true;
  }

  private async copyToken() {
    if (this.createdToken) {
      await navigator.clipboard.writeText(this.createdToken);
      // Could add a toast here
    }
  }

  private closeConfirmModal() {
    this.showConfirmModal = false;
    this.confirmAction = null;
    this.confirmTitle = "";
    this.confirmMessage = "";
    this.confirmWarning = "";
  }

  private async executeConfirmedAction() {
    if (this.confirmAction) {
      await this.confirmAction();
    }
    this.closeConfirmModal();
  }

  private formatDate(dateStr: string): string {
    return new Date(dateStr).toLocaleString();
  }

  private formatDuration(ms: number): string {
    const hours = Math.floor(ms / (1000 * 60 * 60));
    const minutes = Math.floor((ms % (1000 * 60 * 60)) / (1000 * 60));
    if (hours > 0) {
      return `${hours}h ${minutes}m`;
    }
    return `${minutes}m`;
  }

  private isExpired(dateStr: string): boolean {
    return new Date(dateStr) < new Date();
  }

  render(): TemplateResult {
    if (this.loading) {
      return html`
        <div class="loading">
          <div class="spinner"></div>
        </div>
      `;
    }

    if (!this.isAdmin) {
      return html`
        <div class="access-denied">
          <div class="access-denied-icon">🔒</div>
          <h2>Access Denied</h2>
          <p>You do not have admin privileges to access this page.</p>
        </div>
      `;
    }

    return html`
      <h1>
        Security Settings
        <span class="admin-badge">Admin Only</span>
      </h1>
      <p class="subtitle">Manage IP allowlists, security settings, and emergency access</p>

      ${this.error ? html`<div class="error-banner">${this.error}</div>` : ""}

      ${this.renderIpAllowlistSection()}
      ${this.renderSecuritySettingsSection()}
      ${this.renderEmergencyTokensSection()}
      ${this.showConfirmModal ? this.renderConfirmModal() : ""}
    `;
  }

  private renderIpAllowlistSection(): TemplateResult {
    return html`
      <div class="section">
        <div class="section-header">
          <div class="section-title">
            <span class="section-icon">🛡️</span>
            IP Allowlist
          </div>
          <div class="toggle-container">
            <span class="toggle-label">${this.allowlistEnabled ? "Enabled" : "Disabled"}</span>
            <div
              class="toggle ${this.allowlistEnabled ? "enabled" : ""}"
              @click=${this.handleToggleAllowlist}
            ></div>
          </div>
        </div>

        <div class="current-ip">
          <span class="current-ip-label">Your current IP:</span>
          <span class="current-ip-value">${this.clientIp || "Unknown"}</span>
          <button
            class="btn btn-secondary"
            @click=${this.handleAddCurrentIp}
            ?disabled=${this.addingIp}
          >
            Add My IP
          </button>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label>IP or CIDR Range</label>
            <input
              type="text"
              class="input mono"
              placeholder="192.168.1.0/24 or 10.0.0.1"
              .value=${this.newIpRange}
              @input=${(e: Event) => (this.newIpRange = (e.target as HTMLInputElement).value)}
            />
          </div>
          <div class="form-group">
            <label>Description (optional)</label>
            <input
              type="text"
              class="input"
              placeholder="e.g., Office network"
              .value=${this.newIpDescription}
              @input=${(e: Event) => (this.newIpDescription = (e.target as HTMLInputElement).value)}
            />
          </div>
        </div>

        <button
          class="btn btn-primary"
          @click=${this.handleAddIp}
          ?disabled=${!this.newIpRange.trim() || this.addingIp}
        >
          ${this.addingIp ? "Adding..." : "Add to Allowlist"}
        </button>

        ${
          this.ipEntries.length > 0
            ? html`
              <table class="data-table" style="margin-top: 20px;">
                <thead>
                  <tr>
                    <th>IP Range</th>
                    <th>Description</th>
                    <th>Added</th>
                    <th>Expires</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  ${this.ipEntries.map(
                    (entry) => html`
                      <tr>
                        <td><span class="ip-range">${entry.ipRange}</span></td>
                        <td class="description">${entry.description || "-"}</td>
                        <td class="meta">${this.formatDate(entry.createdAt)}</td>
                        <td>
                          ${
                            entry.expiresAt
                              ? html`
                                <span
                                  class="status-badge ${
                                    this.isExpired(entry.expiresAt) ? "expired" : "active"
                                  }"
                                >
                                  ${
                                    this.isExpired(entry.expiresAt)
                                      ? "Expired"
                                      : this.formatDate(entry.expiresAt)
                                  }
                                </span>
                              `
                              : html`
                                  <span class="meta">Never</span>
                                `
                          }
                        </td>
                        <td>
                          <button
                            class="btn-icon danger"
                            title="Remove"
                            @click=${() => this.handleRemoveIp(entry)}
                          >
                            &#x2715;
                          </button>
                        </td>
                      </tr>
                    `,
                  )}
                </tbody>
              </table>
            `
            : html`
                <div class="empty-state">
                  <div class="empty-state-icon">📋</div>
                  <p>No IP addresses in allowlist</p>
                </div>
              `
        }
      </div>
    `;
  }

  private renderSecuritySettingsSection(): TemplateResult {
    return html`
      <div class="section">
        <div class="section-header">
          <div class="section-title">
            <span class="section-icon">⚙️</span>
            Security Settings
          </div>
        </div>

        <div class="settings-list">
          <div class="setting-item">
            <span class="setting-key">Session Timeout</span>
            <div class="setting-value">
              <span>${this.formatDuration(this.envSettings.sessionTimeoutMs || 3600000)}</span>
              <span class="env-badge">ENV</span>
            </div>
          </div>
          <div class="setting-item">
            <span class="setting-key">Inactivity Timeout</span>
            <div class="setting-value">
              <span>${this.formatDuration(this.envSettings.inactivityTimeoutMs || 900000)}</span>
              <span class="env-badge">ENV</span>
            </div>
          </div>
          <div class="setting-item">
            <span class="setting-key">Reauth Interval</span>
            <div class="setting-value">
              <span>${this.formatDuration(this.envSettings.reauthIntervalMs || 300000)}</span>
              <span class="env-badge">ENV</span>
            </div>
          </div>
          ${Object.entries(this.settings).map(
            ([key, value]) => html`
              <div class="setting-item">
                <span class="setting-key">${key}</span>
                <div class="setting-value">
                  <span>${String(value)}</span>
                </div>
              </div>
            `,
          )}
        </div>
      </div>
    `;
  }

  private renderEmergencyTokensSection(): TemplateResult {
    return html`
      <div class="section">
        <div class="section-header">
          <div class="section-title">
            <span class="section-icon">🔑</span>
            Emergency Access Tokens
          </div>
        </div>

        <p class="confirm-text">
          Emergency tokens allow bypassing normal authentication in case of lockout.
          Use with extreme caution.
        </p>

        <div class="form-row">
          <div class="form-group" style="flex: 2;">
            <label>Reason for token</label>
            <input
              type="text"
              class="input"
              placeholder="e.g., Backup access for IT team"
              .value=${this.newTokenReason}
              @input=${(e: Event) => (this.newTokenReason = (e.target as HTMLInputElement).value)}
            />
          </div>
          <div class="form-group">
            <label>Expires in (hours)</label>
            <input
              type="number"
              class="input"
              min="1"
              max="720"
              .value=${String(this.newTokenExpiry)}
              @input=${(e: Event) =>
                (this.newTokenExpiry = parseInt((e.target as HTMLInputElement).value) || 24)}
            />
          </div>
        </div>

        <div style="display: flex; align-items: center; gap: 16px; margin-bottom: 16px;">
          <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
            <input
              type="checkbox"
              ?checked=${this.newTokenSingleUse}
              @change=${(e: Event) =>
                (this.newTokenSingleUse = (e.target as HTMLInputElement).checked)}
            />
            Single use only
          </label>
        </div>

        <button
          class="btn btn-danger"
          @click=${this.handleCreateToken}
          ?disabled=${!this.newTokenReason.trim() || this.creatingToken}
        >
          ${this.creatingToken ? "Creating..." : "Create Emergency Token"}
        </button>

        ${
          this.createdToken
            ? html`
              <div class="token-display">
                <div class="token-warning">
                  <span>Warning: This token will only be shown once. Save it securely!</span>
                </div>
                <div class="token-value">${this.createdToken}</div>
                <button class="btn btn-secondary copy-btn" @click=${this.copyToken}>
                  Copy Token
                </button>
                <button
                  class="btn btn-secondary"
                  style="margin-left: 8px;"
                  @click=${() => (this.createdToken = null)}
                >
                  Dismiss
                </button>
              </div>
            `
            : ""
        }

        ${
          this.emergencyTokens.length > 0
            ? html`
              <table class="data-table" style="margin-top: 20px;">
                <thead>
                  <tr>
                    <th>Reason</th>
                    <th>Created</th>
                    <th>Expires</th>
                    <th>Status</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  ${this.emergencyTokens.map(
                    (token) => html`
                      <tr>
                        <td>${token.reason}</td>
                        <td class="meta">${this.formatDate(token.createdAt)}</td>
                        <td class="meta">${this.formatDate(token.expiresAt)}</td>
                        <td>
                          ${
                            token.usedAt
                              ? html`
                                  <span class="status-badge used">Used</span>
                                `
                              : this.isExpired(token.expiresAt)
                                ? html`
                                    <span class="status-badge expired">Expired</span>
                                  `
                                : html`
                                    <span class="status-badge active">Active</span>
                                  `
                          }
                        </td>
                        <td>
                          ${
                            !token.usedAt && !this.isExpired(token.expiresAt)
                              ? html`
                                <button
                                  class="btn-icon danger"
                                  title="Revoke"
                                  @click=${() => this.handleRevokeToken(token)}
                                >
                                  &#x2715;
                                </button>
                              `
                              : ""
                          }
                        </td>
                      </tr>
                    `,
                  )}
                </tbody>
              </table>
            `
            : html`
                <div class="empty-state" style="margin-top: 20px">
                  <div class="empty-state-icon">🔒</div>
                  <p>No emergency tokens</p>
                </div>
              `
        }
      </div>
    `;
  }

  private renderConfirmModal(): TemplateResult {
    return html`
      <div
        class="modal-overlay"
        @click=${(e: Event) => {
          if (e.target === e.currentTarget) {
            this.closeConfirmModal();
          }
        }}
      >
        <div class="modal">
          <h3>${this.confirmTitle}</h3>
          <p class="confirm-text">${this.confirmMessage}</p>
          ${
            this.confirmWarning
              ? html`<div class="confirm-warning">${this.confirmWarning}</div>`
              : ""
          }
          <div class="modal-buttons">
            <button class="btn btn-secondary" @click=${this.closeConfirmModal}>
              Cancel
            </button>
            <button class="btn btn-danger" @click=${this.executeConfirmedAction}>
              Confirm
            </button>
          </div>
        </div>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-admin-security": AdminSecurityPage;
  }
}

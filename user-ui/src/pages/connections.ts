import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { api, User, Integration, VaultStatus } from "../lib/api.js";

type ConnectionType = "messaging" | "oauth" | "api_key";
type SetupType = "token" | "qr" | "oauth" | "api_key" | "coming_soon";

interface Connection {
  id: string;
  name: string;
  icon: string;
  description: string;
  type: ConnectionType;
  setupType: SetupType;
  helpText?: string;
  helpUrl?: string;
  oauthScope?: string;
  keyPlaceholder?: string;
  configKey?: string;
  hasScopeOptions?: boolean;
}

interface DriveScopeOption {
  level: string;
  name: string;
  description: string;
  capabilities: string[];
}

// Only show these connections for now
const CONNECTIONS: Connection[] = [
  // Messaging
  {
    id: "telegram",
    name: "Telegram",
    icon: "✈️",
    description: "Chat via Telegram bot",
    type: "messaging",
    setupType: "token",
    helpText: "Get token from @BotFather",
    helpUrl: "https://t.me/BotFather",
    configKey: "telegram.token",
  },
  {
    id: "whatsapp",
    name: "WhatsApp",
    icon: "💬",
    description: "Chat on WhatsApp",
    type: "messaging",
    setupType: "coming_soon",
    helpText: "Coming soon",
  },
  {
    id: "slack",
    name: "Slack",
    icon: "💼",
    description: "Chat in workspaces",
    type: "messaging",
    setupType: "coming_soon",
    helpText: "Coming soon",
  },
  // OAuth - Google Services
  {
    id: "google_calendar",
    name: "Google Calendar",
    icon: "📅",
    description: "Read your calendar events",
    type: "oauth",
    setupType: "oauth",
    oauthScope: "calendar",
  },
  {
    id: "google_gmail",
    name: "Gmail",
    icon: "✉️",
    description: "Read your emails",
    type: "oauth",
    setupType: "oauth",
    oauthScope: "gmail",
  },
  {
    id: "google_drive",
    name: "Google Drive",
    icon: "📁",
    description: "Access your files",
    type: "oauth",
    setupType: "oauth",
    oauthScope: "drive",
    hasScopeOptions: true,
  },
  {
    id: "github",
    name: "GitHub",
    icon: "🐙",
    description: "Access repositories",
    type: "api_key",
    setupType: "api_key",
    keyPlaceholder: "ghp_...",
  },
  // API Keys
  {
    id: "anthropic",
    name: "Anthropic",
    icon: "🤖",
    description: "Use your own Claude key",
    type: "api_key",
    setupType: "api_key",
    keyPlaceholder: "sk-ant-...",
  },
  {
    id: "openai",
    name: "OpenAI",
    icon: "🧠",
    description: "Use your own GPT key",
    type: "api_key",
    setupType: "api_key",
    keyPlaceholder: "sk-...",
  },
];

@customElement("ocmt-connections")
export class ConnectionsPage extends LitElement {
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

    .connections-table {
      width: 100%;
      border-collapse: collapse;
    }

    .connections-table th {
      text-align: left;
      padding: 12px 16px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
      color: #888;
      font-weight: 500;
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .connections-table td {
      padding: 16px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      vertical-align: middle;
    }

    .connections-table tr:hover td {
      background: rgba(255, 255, 255, 0.02);
    }

    .connection-info {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .connection-icon {
      font-size: 1.5rem;
      width: 40px;
      height: 40px;
      display: flex;
      align-items: center;
      justify-content: center;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 8px;
    }

    .connection-name {
      font-weight: 600;
    }

    .connection-desc {
      color: #888;
      font-size: 0.85rem;
    }

    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 0.8rem;
      font-weight: 500;
    }

    .status-badge.connected {
      background: rgba(34, 197, 94, 0.2);
      color: #22c55e;
    }

    .status-badge.disconnected {
      background: rgba(255, 255, 255, 0.1);
      color: #888;
    }

    .status-badge.coming-soon {
      background: rgba(251, 191, 36, 0.2);
      color: #fbbf24;
    }

    .btn {
      padding: 8px 16px;
      border-radius: 6px;
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
      max-width: 420px;
      width: 90%;
    }

    .modal h3 {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 16px;
    }

    .modal p {
      color: #888;
      font-size: 0.9rem;
      margin-bottom: 16px;
    }

    .form-group {
      margin-bottom: 16px;
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
      border-radius: 6px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: rgba(255, 255, 255, 0.1);
      color: white;
      font-size: 0.95rem;
      font-family: monospace;
      box-sizing: border-box;
    }

    .input:focus {
      outline: none;
      border-color: #4f46e5;
    }

    .modal-buttons {
      display: flex;
      gap: 8px;
      margin-top: 20px;
    }

    .modal-buttons .btn {
      flex: 1;
    }

    .error-message {
      background: rgba(239, 68, 68, 0.2);
      border: 1px solid rgba(239, 68, 68, 0.3);
      padding: 10px 12px;
      border-radius: 6px;
      color: #ef4444;
      margin-bottom: 12px;
      font-size: 0.9rem;
    }

    .success-banner {
      background: rgba(34, 197, 94, 0.2);
      border: 1px solid rgba(34, 197, 94, 0.3);
      padding: 14px 16px;
      border-radius: 10px;
      margin-bottom: 24px;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .help-link {
      color: #818cf8;
      font-size: 0.85rem;
    }

    .hint-box {
      margin-top: 32px;
      padding: 20px;
      background: rgba(79, 70, 229, 0.1);
      border: 1px solid rgba(79, 70, 229, 0.2);
      border-radius: 10px;
    }

    .hint-box strong {
      display: block;
      margin-bottom: 8px;
    }

    .hint-box p {
      color: #aaa;
      margin: 0;
      font-size: 0.9rem;
    }

    .spinner {
      width: 14px;
      height: 14px;
      border: 2px solid rgba(255, 255, 255, 0.3);
      border-top-color: white;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      display: inline-block;
    }

    @keyframes spin {
      to {
        transform: rotate(360deg);
      }
    }

    /* Scope selection modal */
    .scope-options {
      display: flex;
      flex-direction: column;
      gap: 12px;
      margin-bottom: 20px;
    }

    .scope-option {
      background: rgba(255, 255, 255, 0.05);
      border: 2px solid rgba(255, 255, 255, 0.1);
      border-radius: 10px;
      padding: 16px;
      cursor: pointer;
      transition: all 0.2s;
    }

    .scope-option:hover {
      background: rgba(255, 255, 255, 0.08);
      border-color: rgba(255, 255, 255, 0.2);
    }

    .scope-option.selected {
      border-color: #4f46e5;
      background: rgba(79, 70, 229, 0.1);
    }

    .scope-option-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 8px;
    }

    .scope-option-name {
      font-weight: 600;
      font-size: 1rem;
    }

    .scope-option-badge {
      font-size: 0.75rem;
      padding: 2px 8px;
      border-radius: 4px;
      background: rgba(255, 255, 255, 0.1);
    }

    .scope-option-badge.recommended {
      background: rgba(34, 197, 94, 0.2);
      color: #22c55e;
    }

    .scope-option-badge.warning {
      background: rgba(251, 191, 36, 0.2);
      color: #fbbf24;
    }

    .scope-option-description {
      color: #888;
      font-size: 0.9rem;
      margin-bottom: 10px;
    }

    .scope-option-capabilities {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }

    .scope-capability {
      font-size: 0.75rem;
      padding: 3px 8px;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 4px;
      color: #aaa;
    }

    .current-scope-badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      font-size: 0.75rem;
      padding: 2px 8px;
      background: rgba(79, 70, 229, 0.2);
      color: #818cf8;
      border-radius: 4px;
      margin-left: 8px;
    }

    .scope-warning {
      background: rgba(251, 191, 36, 0.1);
      border: 1px solid rgba(251, 191, 36, 0.3);
      border-radius: 8px;
      padding: 12px;
      margin-bottom: 16px;
      font-size: 0.85rem;
      color: #fbbf24;
    }

    /* Vault lock */
    .vault-notice {
      background: rgba(251, 191, 36, 0.1);
      border: 1px solid rgba(251, 191, 36, 0.3);
      padding: 14px 16px;
      border-radius: 10px;
      margin-bottom: 24px;
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .vault-notice-icon {
      font-size: 1.3rem;
    }

    .vault-notice-text {
      flex: 1;
    }

    .vault-notice-text strong {
      display: block;
      margin-bottom: 2px;
    }

    .vault-notice-text span {
      color: #888;
      font-size: 0.85rem;
    }
  `;

  @property({ type: Object })
  user: User | null = null;

  @state()
  private integrations: Integration[] = [];

  @state()
  private channelStatuses: Map<string, string> = new Map();

  @state()
  private loading = true;

  @state()
  private modalConnection: Connection | null = null;

  @state()
  private modalInput = "";

  @state()
  private modalLoading = false;

  @state()
  private modalError = "";

  @state()
  private successMessage = "";

  @state()
  private vaultStatus: VaultStatus | null = null;

  @state()
  private scopeModalConnection: Connection | null = null;

  @state()
  private scopeOptions: DriveScopeOption[] = [];

  @state()
  private selectedScopeLevel: string = "minimal";

  @state()
  private scopeModalLoading = false;

  connectedCallback() {
    super.connectedCallback();
    this.loadData();

    // Listen for vault status changes (e.g., when user unlocks vault)
    window.addEventListener("vault-status-changed", this.handleVaultStatusChange);

    // Check for OAuth callback
    const params = new URLSearchParams(window.location.search);
    const success = params.get("success");
    if (success) {
      this.successMessage = `${success} connected successfully!`;
      setTimeout(() => (this.successMessage = ""), 5000);
      // Clean URL
      window.history.replaceState({}, "", window.location.pathname);
    }
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    window.removeEventListener("vault-status-changed", this.handleVaultStatusChange);
  }

  private handleVaultStatusChange = async () => {
    // Refresh vault status when it changes
    try {
      this.vaultStatus = await api.getVaultStatus();
    } catch (err) {
      console.error("Failed to refresh vault status:", err);
    }
  };

  private async loadData() {
    this.loading = true;
    try {
      const [integResult, vaultResult] = await Promise.all([
        api.listIntegrations(),
        api.getVaultStatus(),
      ]);
      this.integrations = integResult.integrations;
      this.vaultStatus = vaultResult;
    } catch (err) {
      console.error("Failed to load data:", err);
    }
    this.loading = false;

    // Load channel status in background (don't block UI)
    this.loadChannelStatus();
  }

  private async loadChannelStatus() {
    try {
      const channelResult = await api.getChannelStatus();
      for (const ch of channelResult.channels || []) {
        this.channelStatuses.set(ch.id || ch.name, ch.status);
      }
      this.requestUpdate(); // Re-render with channel statuses
    } catch {
      // Ignore channel status errors - UI works without them
    }
  }

  private getStatus(conn: Connection): "connected" | "disconnected" | "coming_soon" {
    if (conn.setupType === "coming_soon") {
      return "coming_soon";
    }

    // Check integrations (OAuth + API keys)
    if (conn.type === "oauth" || conn.type === "api_key") {
      // For Google, check any google_* provider
      if (conn.id === "google") {
        return this.integrations.some(
          (i) => i.provider.startsWith("google") && i.status === "active",
        )
          ? "connected"
          : "disconnected";
      }
      return this.integrations.some((i) => i.provider === conn.id && i.status === "active")
        ? "connected"
        : "disconnected";
    }

    // Check messaging channels
    if (conn.type === "messaging") {
      const status = this.channelStatuses.get(conn.id);
      return status === "connected" ? "connected" : "disconnected";
    }

    return "disconnected";
  }

  private getConnectedEmail(conn: Connection): string | null {
    if (conn.id === "google") {
      const googleInt = this.integrations.find((i) => i.provider.startsWith("google"));
      return googleInt?.provider_email || null;
    }
    const int = this.integrations.find((i) => i.provider === conn.id);
    return int?.provider_email || null;
  }

  private async handleConnect(conn: Connection) {
    if (conn.setupType === "coming_soon") {
      return;
    }

    if (conn.setupType === "oauth") {
      // For connections with scope options (like Google Drive), show scope selection first
      if (conn.hasScopeOptions && conn.oauthScope === "drive") {
        await this.showScopeSelection(conn);
      } else {
        // Redirect to OAuth directly
        window.location.href = api.getOAuthUrl("google", conn.oauthScope);
      }
    } else {
      // Show modal for token/key input
      this.modalConnection = conn;
      this.modalInput = "";
      this.modalError = "";
    }
  }

  private async showScopeSelection(conn: Connection) {
    this.scopeModalConnection = conn;
    // Pre-select current scope level if changing, otherwise default to minimal
    const currentIntegration = this.getIntegrationForConnection(conn);
    const currentScopeLevel = currentIntegration?.metadata?.scopeLevel as string | undefined;
    this.selectedScopeLevel = currentScopeLevel || "minimal";
    this.scopeModalLoading = true;

    try {
      const data = await api.getDriveScopeOptions();
      this.scopeOptions = data.options || [];
    } catch {
      // Fallback scope options if API fails
      this.scopeOptions = [
        {
          level: "minimal",
          name: "Minimal",
          description: "Read-only access to files you select",
          capabilities: ["Read files you explicitly open"],
        },
        {
          level: "standard",
          name: "Standard",
          description: "Read and write access to Drive files",
          capabilities: ["Read all files", "Create and edit files", "Search Drive"],
        },
        {
          level: "full",
          name: "Full",
          description: "Full access to all Drive operations",
          capabilities: ["Full Drive access", "Manage permissions"],
        },
      ];
    }

    this.scopeModalLoading = false;
  }

  private handleScopeSelect(level: string) {
    this.selectedScopeLevel = level;
  }

  private handleScopeConfirm() {
    if (!this.scopeModalConnection) {
      return;
    }
    // Redirect to OAuth with selected scope level
    const url = new URL(api.getOAuthUrl("google", this.scopeModalConnection.oauthScope));
    url.searchParams.set("scopeLevel", this.selectedScopeLevel);
    window.location.href = url.toString();
  }

  private handleScopeModalClose() {
    this.scopeModalConnection = null;
    this.scopeOptions = [];
  }

  private async handleSaveModal() {
    if (!this.modalConnection || !this.modalInput.trim()) {
      return;
    }

    this.modalLoading = true;
    this.modalError = "";

    try {
      if (this.modalConnection.type === "messaging") {
        // Connect messaging channel
        await api.connectChannel(this.modalConnection.id, {
          token: this.modalInput.trim(),
        });
        this.channelStatuses.set(this.modalConnection.id, "connected");
      } else {
        // Save API key
        await api.addApiKey(this.modalConnection.id, this.modalInput.trim());
        await this.loadData();
      }

      this.successMessage = `${this.modalConnection.name} connected!`;
      setTimeout(() => (this.successMessage = ""), 4000);
      this.modalConnection = null;
    } catch (err) {
      this.modalError = err instanceof Error ? err.message : "Failed to connect";
    }

    this.modalLoading = false;
  }

  private async handleDisconnect(conn: Connection) {
    if (!confirm(`Disconnect ${conn.name}?`)) {
      return;
    }

    try {
      if (conn.type === "messaging") {
        await api.disconnectChannel(conn.id);
        this.channelStatuses.set(conn.id, "disconnected");
      } else {
        // For Google, disconnect all google_* integrations
        if (conn.id === "google") {
          for (const int of this.integrations.filter((i) => i.provider.startsWith("google"))) {
            await api.deleteIntegration(int.provider);
          }
        } else {
          await api.deleteIntegration(conn.id);
        }
        await this.loadData();
      }
    } catch (err) {
      console.error("Disconnect failed:", err);
    }
  }

  private handleUnlockVault() {
    window.dispatchEvent(
      new CustomEvent("request-vault-unlock", { bubbles: true, composed: true }),
    );
  }

  render() {
    if (this.loading) {
      return html`
        <div style="padding: 40px; text-align: center"><span class="spinner"></span></div>
      `;
    }

    return html`
      <h1>Connections</h1>
      <p class="subtitle">Connect messaging apps, services, and API keys</p>

      ${
        this.successMessage
          ? html`
        <div class="success-banner">
          <span>✅</span>
          <span>${this.successMessage}</span>
        </div>
      `
          : ""
      }

      ${
        this.vaultStatus?.hasVault && !this.vaultStatus?.isUnlocked
          ? html`
        <div class="vault-notice">
          <span class="vault-notice-icon">🔒</span>
          <div class="vault-notice-text">
            <strong>Vault locked</strong>
            <span>Unlock to manage OAuth connections</span>
          </div>
          <button class="btn btn-primary" @click=${this.handleUnlockVault}>Unlock</button>
        </div>
      `
          : ""
      }

      <table class="connections-table">
        <thead>
          <tr>
            <th>Service</th>
            <th>Status</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          ${CONNECTIONS.map((conn) => this.renderRow(conn))}
        </tbody>
      </table>

      <div class="hint-box">
        <strong>💡 Need something else?</strong>
        <p>Ask your AI assistant to connect other services. Just say: "Connect my Workflowy" or "Add my Notion API key"</p>
      </div>

      ${this.modalConnection ? this.renderModal() : ""}
      ${this.scopeModalConnection ? this.renderScopeModal() : ""}
    `;
  }

  private renderRow(conn: Connection) {
    const status = this.getStatus(conn);
    const email = this.getConnectedEmail(conn);
    const integration = this.getIntegrationForConnection(conn);
    const scopeLevel = integration?.metadata?.scopeLevelName as string | undefined;

    return html`
      <tr>
        <td>
          <div class="connection-info">
            <div class="connection-icon">${conn.icon}</div>
            <div>
              <div class="connection-name">
                ${conn.name}
                ${
                  status === "connected" && scopeLevel
                    ? html`
                  <span class="current-scope-badge">${scopeLevel}</span>
                `
                    : ""
                }
              </div>
              <div class="connection-desc">
                ${email || conn.description}
              </div>
            </div>
          </div>
        </td>
        <td>
          <span class="status-badge ${status}">
            ${
              status === "connected"
                ? "● Connected"
                : status === "coming_soon"
                  ? "◐ Coming soon"
                  : "○ Not connected"
            }
          </span>
        </td>
        <td style="text-align: right;">
          ${
            status === "connected"
              ? html`
            ${
              conn.hasScopeOptions
                ? html`
              <button class="btn" style="background: rgba(255,255,255,0.1); color: #ccc; margin-right: 8px;"
                @click=${() => this.showScopeSelection(conn)}>
                Change Access
              </button>
            `
                : ""
            }
            <button class="btn btn-danger" @click=${() => this.handleDisconnect(conn)}>
              Disconnect
            </button>
          `
              : status !== "coming_soon"
                ? html`
            <button class="btn btn-primary" @click=${() => this.handleConnect(conn)}>
              Connect
            </button>
          `
                : ""
          }
        </td>
      </tr>
    `;
  }

  private renderModal() {
    const conn = this.modalConnection!;
    const isMessaging = conn.type === "messaging";
    const label = isMessaging ? "Bot Token" : "API Key";

    return html`
      <div class="modal-overlay" @click=${(e: Event) => {
        if (e.target === e.currentTarget) {
          this.modalConnection = null;
        }
      }}>
        <div class="modal">
          <h3>${conn.icon} Connect ${conn.name}</h3>

          ${
            conn.helpText
              ? html`
            <p>
              ${conn.helpText}
              ${
                conn.helpUrl
                  ? html`
                <a href="${conn.helpUrl}" target="_blank" class="help-link">Open →</a>
              `
                  : ""
              }
            </p>
          `
              : ""
          }

          ${
            this.modalError
              ? html`
            <div class="error-message">${this.modalError}</div>
          `
              : ""
          }

          <div class="form-group">
            <label>${label}</label>
            <input
              type="password"
              class="input"
              placeholder=${conn.keyPlaceholder || `Enter ${label.toLowerCase()}`}
              .value=${this.modalInput}
              @input=${(e: Event) => (this.modalInput = (e.target as HTMLInputElement).value)}
              ?disabled=${this.modalLoading}
            />
          </div>

          <div class="modal-buttons">
            <button class="btn" style="background: rgba(255,255,255,0.1); color: #ccc;"
              @click=${() => (this.modalConnection = null)}>
              Cancel
            </button>
            <button class="btn btn-primary"
              ?disabled=${!this.modalInput.trim() || this.modalLoading}
              @click=${this.handleSaveModal}>
              ${
                this.modalLoading
                  ? html`
                      <span class="spinner"></span>
                    `
                  : "Connect"
              }
            </button>
          </div>
        </div>
      </div>
    `;
  }

  private renderScopeModal() {
    const conn = this.scopeModalConnection!;
    const currentIntegration = this.getIntegrationForConnection(conn);
    const currentScopeLevel = currentIntegration?.metadata?.scopeLevel as string | undefined;
    const isChangingScope = !!currentScopeLevel;

    return html`
      <div class="modal-overlay" @click=${(e: Event) => {
        if (e.target === e.currentTarget) {
          this.handleScopeModalClose();
        }
      }}>
        <div class="modal" style="max-width: 500px;">
          <h3>${conn.icon} ${isChangingScope ? "Change" : "Choose"} ${conn.name} Access Level</h3>

          <p style="color: #888; margin-bottom: 16px;">
            Select how much access your AI assistant should have to Google Drive.
            ${isChangingScope ? "Changing scope requires re-authorization." : ""}
          </p>

          ${
            isChangingScope && this.selectedScopeLevel !== currentScopeLevel
              ? html`
            <div class="scope-warning">
              ${
                this.getScopeLevelIndex(this.selectedScopeLevel) <
                this.getScopeLevelIndex(currentScopeLevel)
                  ? "Downgrading permissions may limit some Drive features."
                  : "Upgrading permissions will request additional access from Google."
              }
            </div>
          `
              : ""
          }

          ${
            this.scopeModalLoading
              ? html`
                  <div style="text-align: center; padding: 40px">
                    <span class="spinner"></span>
                  </div>
                `
              : html`
            <div class="scope-options">
              ${this.scopeOptions.map(
                (option) => html`
                <div
                  class="scope-option ${this.selectedScopeLevel === option.level ? "selected" : ""}"
                  @click=${() => this.handleScopeSelect(option.level)}
                >
                  <div class="scope-option-header">
                    <span class="scope-option-name">${option.name}</span>
                    ${
                      option.level === "minimal"
                        ? html`
                            <span class="scope-option-badge recommended">Recommended</span>
                          `
                        : option.level === "full"
                          ? html`
                              <span class="scope-option-badge warning">Full Access</span>
                            `
                          : ""
                    }
                    ${
                      currentScopeLevel === option.level
                        ? html`
                            <span class="current-scope-badge">Current</span>
                          `
                        : ""
                    }
                  </div>
                  <div class="scope-option-description">${option.description}</div>
                  <div class="scope-option-capabilities">
                    ${option.capabilities.map(
                      (cap) => html`
                      <span class="scope-capability">${cap}</span>
                    `,
                    )}
                  </div>
                </div>
              `,
              )}
            </div>
          `
          }

          <div class="modal-buttons">
            <button class="btn" style="background: rgba(255,255,255,0.1); color: #ccc;"
              @click=${this.handleScopeModalClose}>
              Cancel
            </button>
            <button class="btn btn-primary"
              ?disabled=${this.scopeModalLoading || (isChangingScope && this.selectedScopeLevel === currentScopeLevel)}
              @click=${this.handleScopeConfirm}>
              ${isChangingScope ? "Update Access" : "Continue"}
            </button>
          </div>
        </div>
      </div>
    `;
  }

  private getIntegrationForConnection(conn: Connection): Integration | undefined {
    return this.integrations.find((i) => i.provider === conn.id);
  }

  private getScopeLevelIndex(level: string | undefined): number {
    const levels = ["minimal", "standard", "full"];
    return level ? levels.indexOf(level) : -1;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-connections": ConnectionsPage;
  }
}

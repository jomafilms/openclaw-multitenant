import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { api, User, Integration, VaultStatus } from "../lib/api.js";

interface ProviderConfig {
  name: string;
  icon: string;
  description: string;
  type: "api_key" | "oauth";
  oauthScope?: string;
  keyPlaceholder?: string;
  keyLabel?: string;
}

const PROVIDERS: Record<string, ProviderConfig> = {
  anthropic: {
    name: "Anthropic",
    icon: "🤖",
    description: "Use your own Claude API key",
    type: "api_key",
    keyPlaceholder: "sk-ant-...",
    keyLabel: "API Key",
  },
  openai: {
    name: "OpenAI",
    icon: "🧠",
    description: "Use your own GPT API key",
    type: "api_key",
    keyPlaceholder: "sk-...",
    keyLabel: "API Key",
  },
  google_calendar: {
    name: "Google Calendar",
    icon: "📅",
    description: "View and manage your calendar",
    type: "oauth",
    oauthScope: "calendar",
  },
  google_gmail: {
    name: "Gmail",
    icon: "📧",
    description: "Read and search your emails",
    type: "oauth",
    oauthScope: "gmail",
  },
  google_drive: {
    name: "Google Drive",
    icon: "📁",
    description: "Access your documents",
    type: "oauth",
    oauthScope: "drive",
  },
  github: {
    name: "GitHub",
    icon: "💻",
    description: "Access your repositories",
    type: "api_key",
    keyPlaceholder: "ghp_...",
    keyLabel: "Personal Access Token",
  },
};

@customElement("ocmt-integrations")
export class IntegrationsPage extends LitElement {
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
    }

    .integrations-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
      gap: 16px;
    }

    .integration-card {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 20px;
      transition: all 0.2s;
    }

    .integration-card:hover {
      background: rgba(255, 255, 255, 0.08);
    }

    .integration-card.connected {
      border-color: rgba(34, 197, 94, 0.3);
    }

    .integration-header {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 12px;
    }

    .integration-icon {
      font-size: 2rem;
    }

    .integration-info {
      flex: 1;
    }

    .integration-name {
      font-weight: 600;
      font-size: 1rem;
    }

    .integration-status {
      font-size: 0.8rem;
      color: #888;
    }

    .integration-status.connected {
      color: #22c55e;
    }

    .integration-description {
      color: #888;
      font-size: 0.9rem;
      margin-bottom: 16px;
    }

    .integration-email {
      font-size: 0.85rem;
      color: #4f46e5;
      margin-bottom: 12px;
    }

    .integration-actions {
      display: flex;
      gap: 8px;
    }

    .btn {
      flex: 1;
      padding: 10px 16px;
      border-radius: 8px;
      border: none;
      font-size: 0.9rem;
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
      max-width: 450px;
      width: 90%;
    }

    .modal-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 20px;
    }

    .modal-header h3 {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 1.2rem;
    }

    .modal-close {
      background: none;
      border: none;
      color: #888;
      font-size: 1.5rem;
      cursor: pointer;
      padding: 0;
      line-height: 1;
    }

    .modal-close:hover {
      color: white;
    }

    .form-group {
      margin-bottom: 16px;
    }

    .form-group label {
      display: block;
      margin-bottom: 8px;
      font-size: 0.9rem;
      color: #888;
    }

    .input {
      width: 100%;
      padding: 12px 14px;
      border-radius: 8px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: rgba(255, 255, 255, 0.1);
      color: white;
      font-size: 1rem;
      font-family: monospace;
    }

    .input::placeholder {
      color: #666;
    }

    .input:focus {
      outline: none;
      border-color: #4f46e5;
    }

    .error-message {
      background: rgba(239, 68, 68, 0.2);
      border: 1px solid rgba(239, 68, 68, 0.3);
      padding: 12px;
      border-radius: 8px;
      color: #ef4444;
      margin-bottom: 16px;
    }

    .success-banner {
      background: rgba(34, 197, 94, 0.2);
      border: 1px solid rgba(34, 197, 94, 0.3);
      padding: 16px;
      border-radius: 12px;
      margin-bottom: 24px;
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .success-banner-icon {
      font-size: 1.5rem;
    }

    .spinner {
      width: 16px;
      height: 16px;
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

    /* Vault lock overlay */
    .vault-lock-overlay {
      background: rgba(15, 15, 26, 0.95);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      padding: 48px 32px;
      text-align: center;
      max-width: 450px;
      margin: 60px auto;
    }

    .vault-lock-icon {
      width: 80px;
      height: 80px;
      background: rgba(79, 70, 229, 0.2);
      border-radius: 20px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 40px;
      margin: 0 auto 24px;
    }

    .vault-lock-overlay h2 {
      margin-bottom: 12px;
    }

    .vault-lock-overlay p {
      color: #888;
      margin-bottom: 24px;
      line-height: 1.6;
    }

    .btn-unlock {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 14px 28px;
      background: #4f46e5;
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
    }

    .btn-unlock:hover {
      background: #4338ca;
    }
  `;

  @property({ type: Object })
  user: User | null = null;

  @state()
  private integrations: Integration[] = [];

  @state()
  private loading = true;

  @state()
  private modalProvider: string | null = null;

  @state()
  private modalApiKey = "";

  @state()
  private modalLoading = false;

  @state()
  private modalError = "";

  @state()
  private successProvider: string | null = null;

  @state()
  private vaultStatus: VaultStatus | null = null;

  connectedCallback() {
    super.connectedCallback();
    this.checkVaultStatus();
    this.loadIntegrations();

    // Listen for vault status changes
    window.addEventListener("vault-status-changed", this.handleVaultStatusChange);

    // Check for OAuth callback success/error
    const params = new URLSearchParams(window.location.search);
    const success = params.get("success");
    const error = params.get("error");

    if (success) {
      this.successProvider = success;
      setTimeout(() => (this.successProvider = null), 5000);
    }

    if (error) {
      // Handle OAuth error
      console.error("OAuth error:", error);
    }
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    window.removeEventListener("vault-status-changed", this.handleVaultStatusChange);
  }

  private handleVaultStatusChange = () => {
    this.checkVaultStatus();
  };

  private async checkVaultStatus() {
    try {
      this.vaultStatus = await api.getVaultStatus();
    } catch (err) {
      console.error("Failed to check vault status:", err);
    }
  }

  private handleUnlockVault() {
    // Dispatch event to open the vault unlock modal in the main app
    window.dispatchEvent(
      new CustomEvent("request-vault-unlock", { bubbles: true, composed: true }),
    );
  }

  private async loadIntegrations() {
    this.loading = true;
    try {
      const result = await api.listIntegrations();
      this.integrations = result.integrations;
    } catch (err) {
      console.error("Failed to load integrations:", err);
    }
    this.loading = false;
  }

  private isConnected(provider: string): boolean {
    return this.integrations.some((i) => i.provider === provider && i.status === "active");
  }

  private getIntegration(provider: string): Integration | undefined {
    return this.integrations.find((i) => i.provider === provider);
  }

  private handleConnect(provider: string) {
    const config = PROVIDERS[provider];
    if (!config) {
      return;
    }

    if (config.type === "oauth") {
      // Redirect to OAuth flow
      window.location.href = api.getOAuthUrl("google", config.oauthScope);
    } else {
      // Show API key modal
      this.modalProvider = provider;
      this.modalApiKey = "";
      this.modalError = "";
    }
  }

  private async handleSaveApiKey() {
    if (!this.modalProvider || !this.modalApiKey.trim()) {
      return;
    }

    this.modalLoading = true;
    this.modalError = "";

    try {
      await api.addApiKey(this.modalProvider, this.modalApiKey.trim());
      this.modalProvider = null;
      this.modalApiKey = "";
      await this.loadIntegrations();
    } catch (err) {
      this.modalError = err instanceof Error ? err.message : "Failed to save API key";
    }

    this.modalLoading = false;
  }

  private async handleDisconnect(provider: string) {
    if (!confirm(`Are you sure you want to disconnect ${PROVIDERS[provider]?.name || provider}?`)) {
      return;
    }

    try {
      await api.deleteIntegration(provider);
      await this.loadIntegrations();
    } catch (err) {
      console.error("Failed to disconnect:", err);
    }
  }

  private renderVaultLockOverlay() {
    return html`
      <h1>Integrations</h1>
      <p class="subtitle">Connect apps and services to enhance your AI assistant</p>

      <div class="vault-lock-overlay">
        <div class="vault-lock-icon">&#x1F512;</div>
        <h2>Vault Locked</h2>
        <p>
          Your integrations contain sensitive API keys and tokens.
          Please unlock your vault to view and manage them.
        </p>
        <button class="btn-unlock" @click=${this.handleUnlockVault}>
          <span>&#x1F513;</span> Unlock Vault
        </button>
      </div>
    `;
  }

  render() {
    // If user has a vault but it's locked, show the lock overlay
    if (this.vaultStatus?.hasVault && !this.vaultStatus?.isUnlocked) {
      return this.renderVaultLockOverlay();
    }

    return html`
      <h1>Integrations</h1>
      <p class="subtitle">Connect apps and services to enhance your AI assistant</p>

      ${
        this.successProvider
          ? html`
        <div class="success-banner">
          <span class="success-banner-icon">✅</span>
          <div>
            <strong>${PROVIDERS[this.successProvider]?.name || this.successProvider} connected!</strong>
            <div style="color: #888; font-size: 0.9rem;">Your AI can now access this service.</div>
          </div>
        </div>
      `
          : ""
      }

      <div class="section">
        <h2>AI Providers</h2>
        <div class="integrations-grid">
          ${this.renderProviderCard("anthropic")}
          ${this.renderProviderCard("openai")}
        </div>
      </div>

      <div class="section">
        <h2>Google Services</h2>
        <div class="integrations-grid">
          ${this.renderProviderCard("google_calendar")}
          ${this.renderProviderCard("google_gmail")}
          ${this.renderProviderCard("google_drive")}
        </div>
      </div>

      <div class="section">
        <h2>Developer Tools</h2>
        <div class="integrations-grid">
          ${this.renderProviderCard("github")}
        </div>
      </div>

      ${this.modalProvider ? this.renderModal() : ""}
    `;
  }

  private renderProviderCard(providerId: string) {
    const config = PROVIDERS[providerId];
    if (!config) {
      return "";
    }

    const connected = this.isConnected(providerId);
    const integration = this.getIntegration(providerId);
    const scopeLevelName = integration?.metadata?.scopeLevelName as string | undefined;

    return html`
      <div class="integration-card ${connected ? "connected" : ""}">
        <div class="integration-header">
          <span class="integration-icon">${config.icon}</span>
          <div class="integration-info">
            <div class="integration-name">${config.name}</div>
            <div class="integration-status ${connected ? "connected" : ""}">
              ${connected ? "Connected" : "Not connected"}
              ${
                connected && scopeLevelName
                  ? html`
                <span style="margin-left: 6px; font-size: 0.75rem; padding: 2px 6px; background: rgba(79, 70, 229, 0.2); color: #818cf8; border-radius: 4px;">
                  ${scopeLevelName}
                </span>
              `
                  : ""
              }
            </div>
          </div>
        </div>
        <p class="integration-description">${config.description}</p>
        ${
          integration?.provider_email
            ? html`
          <p class="integration-email">${integration.provider_email}</p>
        `
            : ""
        }
        <div class="integration-actions">
          ${
            connected
              ? html`
            <button class="btn btn-danger" @click=${() => this.handleDisconnect(providerId)}>
              Disconnect
            </button>
          `
              : html`
            <button class="btn btn-primary" @click=${() => this.handleConnect(providerId)}>
              Connect
            </button>
          `
          }
        </div>
      </div>
    `;
  }

  private renderModal() {
    const config = this.modalProvider ? PROVIDERS[this.modalProvider] : null;
    if (!config) {
      return "";
    }

    return html`
      <div class="modal-overlay" @click=${(e: Event) => {
        if (e.target === e.currentTarget) {
          this.modalProvider = null;
        }
      }}>
        <div class="modal">
          <div class="modal-header">
            <h3>${config.icon} Connect ${config.name}</h3>
            <button class="modal-close" @click=${() => (this.modalProvider = null)}>&times;</button>
          </div>

          ${
            this.modalError
              ? html`
            <div class="error-message">${this.modalError}</div>
          `
              : ""
          }

          <div class="form-group">
            <label>${config.keyLabel || "API Key"}</label>
            <input
              type="password"
              class="input"
              placeholder=${config.keyPlaceholder || "Enter your API key"}
              .value=${this.modalApiKey}
              @input=${(e: Event) => (this.modalApiKey = (e.target as HTMLInputElement).value)}
              ?disabled=${this.modalLoading}
            />
          </div>

          <p style="color: #888; font-size: 0.85rem; margin-bottom: 16px;">
            Your API key is encrypted and stored securely. It will never be shared or logged.
          </p>

          <button
            class="btn btn-primary"
            style="width: 100%;"
            @click=${this.handleSaveApiKey}
            ?disabled=${!this.modalApiKey.trim() || this.modalLoading}
          >
            ${
              this.modalLoading
                ? html`
                    <span class="spinner"></span>
                  `
                : "Save API Key"
            }
          </button>
        </div>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-integrations": IntegrationsPage;
  }
}

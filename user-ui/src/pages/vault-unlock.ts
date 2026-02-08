import { LitElement, html, css } from "lit";
import { customElement, state } from "lit/decorators.js";
import { api } from "../lib/api.js";
import { IContainerUnlockClient, createContainerUnlockClient } from "../lib/container-unlock.js";

/**
 * Vault unlock page - handles direct browser-to-container unlock
 *
 * SECURITY: Password derivation happens entirely in the browser.
 * The password NEVER leaves the browser - only a cryptographic proof
 * is sent to the container to verify the password is correct.
 *
 * Flow:
 * 1. Validate magic link token via management server (get userId, container info)
 * 2. Connect directly to container via WebSocket
 * 3. Get unlock challenge from container
 * 4. Derive key from password using Argon2id (in browser)
 * 5. Sign challenge with derived key (in browser)
 * 6. Send signed response to container for verification
 */
@customElement("ocmt-vault-unlock")
export class VaultUnlockPage extends LitElement {
  static styles = css`
    :host {
      display: block;
      min-height: 80vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .card {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      padding: 32px;
      max-width: 420px;
      width: 100%;
    }

    .icon {
      width: 64px;
      height: 64px;
      background: rgba(79, 70, 229, 0.2);
      border-radius: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 32px;
      margin: 0 auto 24px;
    }

    h1 {
      text-align: center;
      margin-bottom: 8px;
      font-size: 1.5rem;
    }

    .subtitle {
      text-align: center;
      color: #888;
      margin-bottom: 24px;
    }

    .user-info {
      background: rgba(255, 255, 255, 0.05);
      border-radius: 8px;
      padding: 12px 16px;
      margin-bottom: 24px;
      text-align: center;
    }

    .user-name {
      font-weight: 600;
      margin-bottom: 4px;
    }

    .user-email {
      color: #888;
      font-size: 0.9rem;
    }

    input {
      width: 100%;
      padding: 14px 16px;
      border-radius: 8px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: rgba(255, 255, 255, 0.1);
      color: white;
      font-size: 1rem;
      box-sizing: border-box;
      margin-bottom: 16px;
    }

    input:focus {
      outline: none;
      border-color: #4f46e5;
    }

    .btn {
      width: 100%;
      padding: 14px;
      border-radius: 8px;
      border: none;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
      font-size: 1rem;
    }

    .btn-primary {
      background: #4f46e5;
      color: white;
    }

    .btn-primary:hover:not(:disabled) {
      background: #4338ca;
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
      text-align: center;
    }

    .success {
      background: rgba(34, 197, 94, 0.1);
      border: 1px solid rgba(34, 197, 94, 0.3);
      border-radius: 8px;
      padding: 20px;
      text-align: center;
    }

    .success-icon {
      font-size: 48px;
      margin-bottom: 16px;
    }

    .success h2 {
      color: #22c55e;
      margin-bottom: 8px;
    }

    .success p {
      color: #888;
      margin-bottom: 16px;
    }

    .loading {
      text-align: center;
      padding: 40px;
    }

    .spinner {
      width: 40px;
      height: 40px;
      border: 3px solid rgba(255, 255, 255, 0.1);
      border-top-color: #4f46e5;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      margin: 0 auto 16px;
    }

    @keyframes spin {
      to {
        transform: rotate(360deg);
      }
    }

    .expires-notice {
      text-align: center;
      color: #888;
      font-size: 0.85rem;
      margin-top: 16px;
    }

    .security-badge {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      margin-top: 16px;
      padding: 8px 12px;
      background: rgba(34, 197, 94, 0.1);
      border-radius: 6px;
      font-size: 0.75rem;
      color: #86efac;
    }

    .security-badge svg {
      width: 14px;
      height: 14px;
    }

    .deriving-notice {
      text-align: center;
      color: #a5b4fc;
      font-size: 0.85rem;
      margin-top: 8px;
    }
  `;

  @state() private token: string | null = null;
  @state() private tokenData: {
    userId: string;
    userName: string;
    email: string;
    expiresIn: number;
    agentServerUrl?: string;
  } | null = null;
  @state() private loading = true;
  @state() private error = "";
  @state() private password = "";
  @state() private unlocking = false;
  @state() private deriving = false;
  @state() private unlocked = false;

  private unlockClient: IContainerUnlockClient | null = null;

  connectedCallback() {
    super.connectedCallback();
    this.handleTokenFromUrl();
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    // Clean up WebSocket connection
    this.unlockClient?.close();
  }

  private async handleTokenFromUrl() {
    const params = new URLSearchParams(window.location.search);
    this.token = params.get("t");
    const errorParam = params.get("error");

    if (errorParam === "missing_token") {
      this.error = "No unlock token provided. Please use the link sent by your AI.";
      this.loading = false;
      return;
    }

    if (errorParam === "invalid_token") {
      this.error = "This unlock link has expired or is invalid. Please ask your AI for a new one.";
      this.loading = false;
      return;
    }

    if (!this.token) {
      this.error = "No unlock token provided.";
      this.loading = false;
      return;
    }

    // Validate the token and get container connection info
    try {
      this.tokenData = await api.validateUnlockToken(this.token);

      // Create direct container connection client
      if (this.tokenData.agentServerUrl && this.tokenData.userId) {
        this.unlockClient = createContainerUnlockClient(
          this.tokenData.agentServerUrl,
          this.tokenData.userId,
        );
      }

      this.loading = false;
    } catch (err) {
      this.error = err instanceof Error ? err.message : "Invalid or expired unlock link";
      this.loading = false;
    }
  }

  private async handleUnlock() {
    if (!this.password) {
      return;
    }

    this.unlocking = true;
    this.deriving = false;
    this.error = "";

    try {
      // Use direct container connection if available
      if (this.unlockClient) {
        await this.handleDirectUnlock();
      } else {
        // Fallback to management server (legacy path)
        await this.handleLegacyUnlock();
      }
    } catch (err) {
      this.error = err instanceof Error ? err.message : "Failed to unlock vault";
      this.unlocking = false;
      this.deriving = false;
    }
  }

  /**
   * Direct browser-to-container unlock
   * Password derivation happens entirely in browser
   */
  private async handleDirectUnlock() {
    if (!this.unlockClient) {
      throw new Error("Container connection not available");
    }

    // Show deriving state (Argon2 can take a few seconds)
    this.deriving = true;

    // Unlock directly with container
    // Password is derived in browser, NEVER sent over network
    const result = await this.unlockClient.unlock(this.password);

    this.deriving = false;

    if (!result.success) {
      throw new Error(result.error || "Failed to unlock vault");
    }

    // Mark as unlocked
    this.unlocked = true;
    this.unlocking = false;

    // Notify app that vault is unlocked
    window.dispatchEvent(new CustomEvent("vault-status-changed"));

    // Redirect to dashboard after a moment
    setTimeout(() => {
      window.location.href = "/dashboard";
    }, 2000);
  }

  /**
   * Legacy unlock via management server
   * Used as fallback when direct connection is not available
   */
  private async handleLegacyUnlock() {
    if (!this.token) {
      return;
    }

    await api.unlockVaultWithToken(this.token, this.password);
    this.unlocked = true;
    this.unlocking = false;

    // Notify app that vault is unlocked
    window.dispatchEvent(new CustomEvent("vault-status-changed"));

    // Redirect to dashboard after a moment
    setTimeout(() => {
      window.location.href = "/dashboard";
    }, 2000);
  }

  private handleKeyDown(e: KeyboardEvent) {
    if (e.key === "Enter" && this.password) {
      this.handleUnlock();
    }
  }

  render() {
    if (this.loading) {
      return html`
        <div class="card">
          <div class="loading">
            <div class="spinner"></div>
            <p style="color: #888">Validating unlock link...</p>
          </div>
        </div>
      `;
    }

    if (this.unlocked) {
      return html`
        <div class="card">
          <div class="success">
            <div class="success-icon">&#x2705;</div>
            <h2>Vault Unlocked</h2>
            <p>Redirecting to your dashboard...</p>
          </div>
        </div>
      `;
    }

    if (this.error && !this.tokenData) {
      return html`
        <div class="card">
          <div class="icon">&#x1F512;</div>
          <h1>Unlock Failed</h1>
          <div class="error">${this.error}</div>
          <button class="btn btn-primary" @click=${() => (window.location.href = "/dashboard")}>
            Go to Dashboard
          </button>
        </div>
      `;
    }

    return html`
      <div class="card">
        <div class="icon">&#x1F513;</div>
        <h1>Unlock Your Vault</h1>
        <p class="subtitle">Your AI assistant needs access to your secure data</p>

        ${
          this.tokenData
            ? html`
          <div class="user-info">
            <div class="user-name">${this.tokenData.userName}</div>
            <div class="user-email">${this.tokenData.email}</div>
          </div>
        `
            : ""
        }

        ${this.error ? html`<div class="error">${this.error}</div>` : ""}

        <input
          type="password"
          placeholder="Enter your vault password"
          .value=${this.password}
          @input=${(e: Event) => (this.password = (e.target as HTMLInputElement).value)}
          @keydown=${this.handleKeyDown}
          ?disabled=${this.unlocking}
          autofocus
        />

        <button
          class="btn btn-primary"
          @click=${this.handleUnlock}
          ?disabled=${!this.password || this.unlocking}
        >
          ${this.deriving ? "Deriving key..." : this.unlocking ? "Unlocking..." : "Unlock Vault"}
        </button>

        ${
          this.deriving
            ? html`
                <p class="deriving-notice">Deriving encryption key from password (this may take a few seconds)</p>
              `
            : ""
        }

        ${
          this.tokenData
            ? html`
          <p class="expires-notice">
            This link expires in ${Math.floor(this.tokenData.expiresIn / 60)} minutes
          </p>
        `
            : ""
        }

        ${
          this.unlockClient
            ? html`
                <div class="security-badge">
                  <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                    />
                  </svg>
                  Password never leaves your browser
                </div>
              `
            : ""
        }
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-vault-unlock": VaultUnlockPage;
  }
}

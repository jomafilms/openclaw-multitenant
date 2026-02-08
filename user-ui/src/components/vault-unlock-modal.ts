import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { api, BiometricsStatus } from "../lib/api.js";

@customElement("vault-unlock-modal")
export class VaultUnlockModal extends LitElement {
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
    }

    .modal {
      background: #1a1a2e;
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      padding: 32px;
      max-width: 400px;
      width: 90%;
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

    h2 {
      margin-bottom: 8px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .subtitle {
      color: #888;
      margin-bottom: 24px;
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
    }

    .forgot-link {
      text-align: center;
      margin-top: 16px;
    }

    .forgot-link a {
      color: #818cf8;
      text-decoration: none;
      font-size: 0.9rem;
    }

    .forgot-link a:hover {
      text-decoration: underline;
    }

    .lock-icon {
      width: 48px;
      height: 48px;
      background: rgba(79, 70, 229, 0.2);
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 24px;
      margin: 0 auto 16px;
    }
  `;

  @property({ type: Boolean }) open = false;
  @state() private password = "";
  @state() private loading = false;
  @state() private error = "";
  @state() private biometricsStatus: BiometricsStatus | null = null;
  @state() private biometricsLoading = false;

  private async handleUnlock() {
    if (!this.password) {
      return;
    }

    this.loading = true;
    this.error = "";

    try {
      await api.unlockVault(this.password);
      this.password = "";
      this.dispatchEvent(new CustomEvent("unlocked", { bubbles: true, composed: true }));
    } catch (err) {
      this.error = err instanceof Error ? err.message : "Failed to unlock vault";
    }

    this.loading = false;
  }

  private handleKeyDown(e: KeyboardEvent) {
    if (e.key === "Enter" && this.password) {
      this.handleUnlock();
    }
    if (e.key === "Escape") {
      this.dispatchEvent(new CustomEvent("close", { bubbles: true, composed: true }));
    }
  }

  private handleForgotPassword(e: Event) {
    e.preventDefault();
    this.dispatchEvent(new CustomEvent("forgot-password", { bubbles: true, composed: true }));
  }

  updated(changedProperties: Map<string, unknown>) {
    if (changedProperties.has("open") && this.open) {
      // Check biometrics status when modal opens
      this.checkBiometrics();
      // Focus the password input when modal opens
      requestAnimationFrame(() => {
        const input = this.shadowRoot?.querySelector("input");
        input?.focus();
      });
    }
  }

  private async checkBiometrics() {
    try {
      const fingerprint = localStorage.getItem("ocmt_device_fingerprint");
      if (fingerprint) {
        this.biometricsStatus = await api.getBiometricsStatus(fingerprint);
      }
    } catch (err) {
      console.error("Failed to check biometrics:", err);
    }
  }

  private async handleBiometricUnlock() {
    const deviceKey = localStorage.getItem("ocmt_device_key");
    const deviceFingerprint = localStorage.getItem("ocmt_device_fingerprint");

    if (!deviceKey || !deviceFingerprint) {
      this.error = "Biometrics not set up on this device";
      return;
    }

    this.biometricsLoading = true;
    this.error = "";

    try {
      await api.unlockVaultWithBiometrics(deviceKey, deviceFingerprint);
      this.password = "";
      this.dispatchEvent(new CustomEvent("unlocked", { bubbles: true, composed: true }));
    } catch (err: unknown) {
      const error = err as { reason?: string; message?: string };
      if (error.reason === "biometrics_expired") {
        this.error = "Password required (14+ days since last password entry)";
      } else {
        this.error = error.message || "Biometric unlock failed";
      }
    }

    this.biometricsLoading = false;
  }

  private canUseBiometrics(): boolean {
    return (
      !!this.biometricsStatus?.biometricsEnabled &&
      !!this.biometricsStatus?.canUseBiometrics &&
      !!this.biometricsStatus?.deviceRegistered
    );
  }

  render() {
    if (!this.open) {
      return null;
    }

    return html`
      <div class="overlay" @click=${(e: Event) => {
        if (e.target === e.currentTarget) {
          this.dispatchEvent(new CustomEvent("close", { bubbles: true, composed: true }));
        }
      }}>
        <div class="modal">
          <div class="lock-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
            </svg>
          </div>
          <h2>Unlock Vault</h2>
          <p class="subtitle">Enter your vault password to continue</p>

          ${this.error ? html`<div class="error">${this.error}</div>` : ""}

          <input
            type="password"
            placeholder="Vault password"
            .value=${this.password}
            @input=${(e: Event) => (this.password = (e.target as HTMLInputElement).value)}
            @keydown=${this.handleKeyDown}
          />

          ${
            this.canUseBiometrics()
              ? html`
            <button
              class="btn btn-primary"
              ?disabled=${this.biometricsLoading}
              @click=${this.handleBiometricUnlock}
              style="margin-bottom: 12px;"
            >
              ${this.biometricsLoading ? "Verifying..." : "Unlock with Biometrics"}
            </button>

            <div style="text-align: center; color: #666; margin-bottom: 12px; font-size: 0.85rem;">
              or enter password
            </div>
          `
              : ""
          }

          <button
            class="btn btn-primary"
            ?disabled=${!this.password || this.loading}
            @click=${this.handleUnlock}
            style="${this.canUseBiometrics() ? "background: rgba(255, 255, 255, 0.1);" : ""}"
          >
            ${this.loading ? "Unlocking..." : "Unlock with Password"}
          </button>

          <div class="forgot-link">
            <a href="#" @click=${this.handleForgotPassword}>Forgot password?</a>
          </div>
        </div>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "vault-unlock-modal": VaultUnlockModal;
  }
}

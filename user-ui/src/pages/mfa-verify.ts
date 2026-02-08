import { LitElement, html, css } from "lit";
import { customElement, property, state, query } from "lit/decorators.js";
import type { MfaCodeInput } from "../components/mfa-code-input.js";
import { toast } from "../components/toast.js";
import "../components/mfa-code-input.js";
import { api, User } from "../lib/api.js";

type VerifyMode = "totp" | "backup";

/**
 * MFA verification page shown during login when user has MFA enabled.
 * Supports both TOTP codes and backup codes.
 */
@customElement("ocmt-mfa-verify")
export class MfaVerifyPage extends LitElement {
  static styles = css`
    :host {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 80vh;
    }

    .container {
      max-width: 400px;
      width: 100%;
      text-align: center;
    }

    .logo {
      font-size: 4rem;
      margin-bottom: 16px;
    }

    h1 {
      font-size: 1.8rem;
      margin-bottom: 8px;
    }

    .subtitle {
      color: #888;
      margin-bottom: 32px;
    }

    .card {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      padding: 32px;
    }

    .mode-toggle {
      margin-bottom: 24px;
    }

    .mode-link {
      color: #818cf8;
      text-decoration: none;
      cursor: pointer;
      font-size: 0.9rem;
    }

    .mode-link:hover {
      text-decoration: underline;
    }

    .verify-label {
      margin-bottom: 20px;
      color: #ccc;
      font-size: 0.95rem;
    }

    .backup-input-container {
      margin-bottom: 24px;
    }

    .backup-input {
      width: 100%;
      padding: 14px 16px;
      border-radius: 8px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: rgba(255, 255, 255, 0.1);
      color: white;
      font-size: 1.1rem;
      font-family: monospace;
      text-align: center;
      text-transform: uppercase;
      letter-spacing: 2px;
      box-sizing: border-box;
    }

    .backup-input::placeholder {
      color: #666;
      text-transform: none;
      letter-spacing: normal;
    }

    .backup-input:focus {
      outline: none;
      border-color: #4f46e5;
    }

    .backup-input.error {
      border-color: #ef4444;
      animation: shake 0.3s ease-in-out;
    }

    @keyframes shake {
      0%,
      100% {
        transform: translateX(0);
      }
      25% {
        transform: translateX(-4px);
      }
      75% {
        transform: translateX(4px);
      }
    }

    .btn {
      width: 100%;
      padding: 14px 28px;
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

    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .error-message {
      background: rgba(239, 68, 68, 0.2);
      border: 1px solid rgba(239, 68, 68, 0.3);
      padding: 12px;
      border-radius: 8px;
      margin-bottom: 16px;
      color: #ef4444;
    }

    .warning-message {
      background: rgba(245, 158, 11, 0.2);
      border: 1px solid rgba(245, 158, 11, 0.3);
      padding: 12px;
      border-radius: 8px;
      margin-top: 16px;
      color: #f59e0b;
      font-size: 0.9rem;
    }

    .spinner {
      width: 20px;
      height: 20px;
      border: 2px solid rgba(255, 255, 255, 0.3);
      border-top-color: white;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }

    @keyframes spin {
      to {
        transform: rotate(360deg);
      }
    }

    .help-text {
      margin-top: 24px;
      font-size: 0.85rem;
      color: #666;
    }

    .help-link {
      color: #818cf8;
      text-decoration: none;
    }

    .help-link:hover {
      text-decoration: underline;
    }

    .back-link {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: #888;
      text-decoration: none;
      margin-top: 24px;
      font-size: 0.9rem;
      cursor: pointer;
    }

    .back-link:hover {
      color: #fff;
    }
  `;

  /**
   * The pending MFA token received after magic link verification
   */
  @property({ type: String })
  pendingToken = "";

  /**
   * Callback when verification succeeds
   */
  @property({ attribute: false })
  onSuccess?: (user: User) => void;

  /**
   * Callback when user wants to cancel and go back to login
   */
  @property({ attribute: false })
  onCancel?: () => void;

  @state() private mode: VerifyMode = "totp";
  @state() private loading = false;
  @state() private error = "";
  @state() private warning = "";
  @state() private backupCode = "";
  @state() private backupInputError = false;

  @query("mfa-code-input")
  private codeInput!: MfaCodeInput;

  @query(".backup-input")
  private backupInput!: HTMLInputElement;

  connectedCallback() {
    super.connectedCallback();
    // Focus the input after render
    this.updateComplete.then(() => {
      if (this.mode === "totp" && this.codeInput) {
        this.codeInput.focus();
      } else if (this.mode === "backup" && this.backupInput) {
        this.backupInput.focus();
      }
    });
  }

  private switchMode(newMode: VerifyMode) {
    this.mode = newMode;
    this.error = "";
    this.warning = "";
    this.backupInputError = false;

    this.updateComplete.then(() => {
      if (newMode === "totp" && this.codeInput) {
        this.codeInput.clear();
        this.codeInput.focus();
      } else if (newMode === "backup" && this.backupInput) {
        this.backupCode = "";
        this.backupInput.focus();
      }
    });
  }

  private async handleCodeComplete(e: CustomEvent<{ code: string }>) {
    await this.verifyTotp(e.detail.code);
  }

  private async verifyTotp(code: string) {
    if (!this.pendingToken) {
      this.error = "Session expired. Please try logging in again.";
      return;
    }

    this.loading = true;
    this.error = "";

    try {
      const result = await api.verifyMfaLogin(this.pendingToken, code);

      if (result.success) {
        toast.success("Verification successful!");
        this.onSuccess?.(result.user);
      }
    } catch (err) {
      this.error = err instanceof Error ? err.message : "Invalid verification code";
      if (this.codeInput) {
        this.codeInput.error = true;
        setTimeout(() => {
          this.codeInput.clear();
        }, 500);
      }
    }

    this.loading = false;
  }

  private async verifyBackupCode() {
    if (!this.pendingToken) {
      this.error = "Session expired. Please try logging in again.";
      return;
    }

    const code = this.backupCode.trim();
    if (!code) {
      this.error = "Please enter a backup code";
      return;
    }

    this.loading = true;
    this.error = "";

    try {
      const result = await api.verifyMfaLoginWithBackupCode(this.pendingToken, code);

      if (result.success) {
        toast.success("Verification successful!");

        // Show warning if low on backup codes
        if (result.warning) {
          this.warning = result.warning;
        } else if (result.backupCodesRemaining < 3) {
          toast.warning(
            `You only have ${result.backupCodesRemaining} backup codes left. Consider regenerating them.`,
          );
        }

        this.onSuccess?.(result.user);
      }
    } catch (err) {
      this.error = err instanceof Error ? err.message : "Invalid backup code";
      this.backupInputError = true;
      setTimeout(() => {
        this.backupInputError = false;
        this.backupCode = "";
        this.backupInput?.focus();
      }, 500);
    }

    this.loading = false;
  }

  private handleBackupCodeInput(e: Event) {
    const input = e.target as HTMLInputElement;
    // Allow alphanumeric and dashes, uppercase everything
    this.backupCode = input.value.toUpperCase().replace(/[^A-Z0-9-]/g, "");
  }

  private handleBackupCodeKeydown(e: KeyboardEvent) {
    if (e.key === "Enter" && this.backupCode.length >= 8) {
      this.verifyBackupCode();
    }
  }

  private handleCancel() {
    this.onCancel?.();
  }

  render() {
    return html`
      <div class="container">
        <div class="logo">&#x1F512;</div>
        <h1>Two-Factor Authentication</h1>
        <p class="subtitle">Enter your verification code to continue</p>

        <div class="card">
          ${this.mode === "totp" ? this.renderTotpMode() : this.renderBackupMode()}
        </div>

        <a class="back-link" @click=${this.handleCancel}>
          &larr; Back to login
        </a>
      </div>
    `;
  }

  private renderTotpMode() {
    return html`
      <div class="mode-toggle">
        <a class="mode-link" @click=${() => this.switchMode("backup")}>
          Use a backup code instead
        </a>
      </div>

      ${this.error ? html`<div class="error-message">${this.error}</div>` : ""}

      <p class="verify-label">
        Enter the 6-digit code from your authenticator app:
      </p>

      <mfa-code-input
        ?disabled=${this.loading}
        @code-complete=${this.handleCodeComplete}
      ></mfa-code-input>

      ${this.warning ? html`<div class="warning-message">${this.warning}</div>` : ""}

      <p class="help-text">
        Open your authenticator app (Google Authenticator, Authy, etc.) to get your code.
      </p>
    `;
  }

  private renderBackupMode() {
    const canSubmit = this.backupCode.replace(/-/g, "").length >= 8;

    return html`
      <div class="mode-toggle">
        <a class="mode-link" @click=${() => this.switchMode("totp")}>
          Use authenticator app instead
        </a>
      </div>

      ${this.error ? html`<div class="error-message">${this.error}</div>` : ""}

      <p class="verify-label">
        Enter one of your backup codes:
      </p>

      <div class="backup-input-container">
        <input
          type="text"
          class="backup-input ${this.backupInputError ? "error" : ""}"
          placeholder="XXXX-XXXX"
          .value=${this.backupCode}
          @input=${this.handleBackupCodeInput}
          @keydown=${this.handleBackupCodeKeydown}
          ?disabled=${this.loading}
          autocomplete="off"
          spellcheck="false"
        />
      </div>

      <button
        class="btn btn-primary"
        ?disabled=${!canSubmit || this.loading}
        @click=${this.verifyBackupCode}
      >
        ${
          this.loading
            ? html`
                <div class="spinner"></div>
              `
            : ""
        }
        ${this.loading ? "Verifying..." : "Verify Backup Code"}
      </button>

      ${this.warning ? html`<div class="warning-message">${this.warning}</div>` : ""}

      <p class="help-text">
        Backup codes were provided when you set up two-factor authentication.
        Each code can only be used once.
      </p>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-mfa-verify": MfaVerifyPage;
  }
}

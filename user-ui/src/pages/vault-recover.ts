import { LitElement, html, css } from "lit";
import { customElement, state } from "lit/decorators.js";
import { api } from "../lib/api.js";

@customElement("ocmt-vault-recover")
export class VaultRecoverPage extends LitElement {
  static styles = css`
    :host {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 80vh;
    }

    .container {
      max-width: 500px;
      width: 100%;
      text-align: center;
    }

    .card {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      padding: 32px;
      margin-bottom: 24px;
    }

    h1 {
      font-size: 1.8rem;
      margin-bottom: 8px;
    }

    .subtitle {
      color: #888;
      margin-bottom: 32px;
    }

    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }

    label {
      display: block;
      margin-bottom: 8px;
      font-weight: 500;
    }

    input,
    textarea {
      width: 100%;
      padding: 14px 16px;
      border-radius: 8px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: rgba(255, 255, 255, 0.1);
      color: white;
      font-size: 1rem;
      box-sizing: border-box;
      font-family: inherit;
    }

    textarea {
      min-height: 100px;
      resize: vertical;
    }

    input:focus,
    textarea:focus {
      outline: none;
      border-color: #4f46e5;
    }

    .btn {
      width: 100%;
      padding: 16px;
      border-radius: 8px;
      border: none;
      background: #4f46e5;
      color: white;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s;
    }

    .btn:hover:not(:disabled) {
      background: #4338ca;
    }

    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .btn-secondary {
      background: rgba(255, 255, 255, 0.1);
      margin-top: 12px;
    }

    .btn-secondary:hover:not(:disabled) {
      background: rgba(255, 255, 255, 0.15);
    }

    .info-box {
      background: rgba(79, 70, 229, 0.1);
      border: 1px solid rgba(79, 70, 229, 0.3);
      border-radius: 8px;
      padding: 16px;
      text-align: left;
      font-size: 0.9rem;
      color: #a5b4fc;
      margin-bottom: 24px;
    }

    .error-box {
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.3);
      border-radius: 8px;
      padding: 12px 16px;
      color: #fca5a5;
      margin: 16px 0;
      text-align: left;
    }

    .success-box {
      background: rgba(34, 197, 94, 0.1);
      border: 1px solid rgba(34, 197, 94, 0.3);
      border-radius: 8px;
      padding: 16px;
      color: #86efac;
      margin: 16px 0;
    }

    .password-strength {
      margin-top: 8px;
      font-size: 0.85rem;
    }

    .strength-weak {
      color: #ef4444;
    }
    .strength-medium {
      color: #f59e0b;
    }
    .strength-strong {
      color: #22c55e;
    }
  `;

  @state() private step: "phrase" | "password" | "success" = "phrase";
  @state() private recoveryPhrase = "";
  @state() private newPassword = "";
  @state() private confirmPassword = "";
  @state() private loading = false;
  @state() private error = "";

  private getPasswordStrength(): { level: string; text: string } {
    const p = this.newPassword;
    if (p.length < 12) {
      return { level: "weak", text: "Too short (min 12 characters)" };
    }
    if (p.length < 16) {
      return { level: "medium", text: "Medium - consider longer" };
    }

    const hasUpper = /[A-Z]/.test(p);
    const hasLower = /[a-z]/.test(p);
    const hasNumber = /[0-9]/.test(p);
    const hasSymbol = /[^A-Za-z0-9]/.test(p);
    const variety = [hasUpper, hasLower, hasNumber, hasSymbol].filter(Boolean).length;

    if (variety >= 3 && p.length >= 16) {
      return { level: "strong", text: "Strong" };
    }
    if (variety >= 2) {
      return { level: "medium", text: "Medium" };
    }
    return { level: "weak", text: "Weak - add variety" };
  }

  private handlePhraseSubmit() {
    const words = this.recoveryPhrase.trim().split(/\s+/);
    if (words.length !== 12) {
      this.error = "Recovery phrase must be 12 words";
      return;
    }
    this.error = "";
    this.step = "password";
  }

  private async handleRecover() {
    if (this.newPassword !== this.confirmPassword) {
      this.error = "Passwords do not match";
      return;
    }

    if (this.newPassword.length < 12) {
      this.error = "Password must be at least 12 characters";
      return;
    }

    this.loading = true;
    this.error = "";

    try {
      await api.recoverVault(this.recoveryPhrase.trim(), this.newPassword);
      this.step = "success";
    } catch (err) {
      this.error = err instanceof Error ? err.message : "Failed to recover vault";
    }

    this.loading = false;
  }

  private handleComplete() {
    this.dispatchEvent(new CustomEvent("recovered", { bubbles: true, composed: true }));
  }

  private handleBack() {
    if (this.step === "password") {
      this.step = "phrase";
      this.error = "";
    } else {
      this.dispatchEvent(new CustomEvent("cancel", { bubbles: true, composed: true }));
    }
  }

  render() {
    if (this.step === "success") {
      return this.renderSuccessStep();
    }
    if (this.step === "password") {
      return this.renderPasswordStep();
    }
    return this.renderPhraseStep();
  }

  private renderPhraseStep() {
    const wordCount = this.recoveryPhrase
      .trim()
      .split(/\s+/)
      .filter((w) => w).length;
    const canSubmit = wordCount === 12;

    return html`
      <div class="container">
        <h1>Recover Vault</h1>
        <p class="subtitle">Enter your 12-word recovery phrase</p>

        <div class="card">
          <div class="info-box">
            Enter the recovery phrase you saved when you created your vault.
            This will allow you to set a new password.
          </div>

          ${
            this.error
              ? html`
            <div class="error-box">${this.error}</div>
          `
              : ""
          }

          <div class="form-group">
            <label>Recovery Phrase</label>
            <textarea
              .value=${this.recoveryPhrase}
              @input=${(e: Event) => (this.recoveryPhrase = (e.target as HTMLTextAreaElement).value)}
              placeholder="Enter your 12 words separated by spaces"
            ></textarea>
            <div style="margin-top: 8px; color: #888; font-size: 0.85rem;">
              Words entered: ${wordCount}/12
            </div>
          </div>

          <button
            class="btn"
            ?disabled=${!canSubmit}
            @click=${this.handlePhraseSubmit}
          >
            Continue
          </button>

          <button class="btn btn-secondary" @click=${this.handleBack}>
            Cancel
          </button>
        </div>
      </div>
    `;
  }

  private renderPasswordStep() {
    const strength = this.getPasswordStrength();
    const canSubmit = this.newPassword.length >= 12 && this.newPassword === this.confirmPassword;

    return html`
      <div class="container">
        <h1>Set New Password</h1>
        <p class="subtitle">Create a new vault password</p>

        <div class="card">
          ${
            this.error
              ? html`
            <div class="error-box">${this.error}</div>
          `
              : ""
          }

          <div class="form-group">
            <label>New Password</label>
            <input
              type="password"
              .value=${this.newPassword}
              @input=${(e: Event) => (this.newPassword = (e.target as HTMLInputElement).value)}
              placeholder="Enter a strong password"
            />
            ${
              this.newPassword
                ? html`
              <div class="password-strength strength-${strength.level}">
                ${strength.text}
              </div>
            `
                : ""
            }
          </div>

          <div class="form-group">
            <label>Confirm Password</label>
            <input
              type="password"
              .value=${this.confirmPassword}
              @input=${(e: Event) => (this.confirmPassword = (e.target as HTMLInputElement).value)}
              placeholder="Confirm your password"
            />
          </div>

          <button
            class="btn"
            ?disabled=${!canSubmit || this.loading}
            @click=${this.handleRecover}
          >
            ${this.loading ? "Recovering..." : "Reset Password"}
          </button>

          <button class="btn btn-secondary" @click=${this.handleBack}>
            Back
          </button>
        </div>
      </div>
    `;
  }

  private renderSuccessStep() {
    return html`
      <div class="container">
        <h1>Password Reset</h1>
        <p class="subtitle">Your vault password has been changed</p>

        <div class="card">
          <div class="success-box">
            Your vault has been recovered successfully. You can now sign in with your new password.
          </div>

          <button class="btn" @click=${this.handleComplete}>
            Continue to Sign In
          </button>
        </div>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-vault-recover": VaultRecoverPage;
  }
}

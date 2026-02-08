import { LitElement, html, css } from "lit";
import { customElement, state } from "lit/decorators.js";
import { api } from "../lib/api.js";

@customElement("ocmt-vault-setup")
export class VaultSetupPage extends LitElement {
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

    input {
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

    .info-box {
      background: rgba(79, 70, 229, 0.1);
      border: 1px solid rgba(79, 70, 229, 0.3);
      border-radius: 8px;
      padding: 16px;
      text-align: left;
      font-size: 0.9rem;
      color: #a5b4fc;
    }

    .info-box strong {
      color: white;
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

    /* Recovery phrase display */
    .recovery-phrase {
      background: #1a1a2e;
      border: 2px dashed rgba(79, 70, 229, 0.5);
      border-radius: 12px;
      padding: 24px;
      margin: 24px 0;
      font-family: monospace;
      font-size: 1.1rem;
      line-height: 2;
      word-spacing: 8px;
      user-select: all;
    }

    .warning-box {
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.3);
      border-radius: 8px;
      padding: 16px;
      margin: 24px 0;
      text-align: left;
    }

    .warning-box h4 {
      color: #ef4444;
      margin-bottom: 8px;
    }

    .warning-box ul {
      margin: 0;
      padding-left: 20px;
      color: #ccc;
    }

    .warning-box li {
      margin-bottom: 4px;
    }

    .download-btn {
      background: rgba(255, 255, 255, 0.1);
      border: 1px solid rgba(255, 255, 255, 0.2);
      margin-bottom: 16px;
    }

    .download-btn:hover:not(:disabled) {
      background: rgba(255, 255, 255, 0.15);
    }

    .checkbox-group {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      text-align: left;
      margin: 24px 0;
    }

    .checkbox-group input[type="checkbox"] {
      width: auto;
      margin-top: 4px;
      cursor: pointer;
    }

    .checkbox-group label {
      margin: 0;
      font-weight: normal;
      cursor: pointer;
    }

    .skip-link {
      display: block;
      margin-top: 24px;
      color: #888;
      text-decoration: none;
      font-size: 0.9rem;
    }

    .skip-link:hover {
      color: #aaa;
    }
  `;

  @state() private step: "password" | "recovery" = "password";
  @state() private password = "";
  @state() private confirmPassword = "";
  @state() private recoveryPhrase = "";
  @state() private savedPhrase = false;
  @state() private loading = false;
  @state() private error = "";

  private getPasswordStrength(): { level: string; text: string } {
    const p = this.password;
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

  private async handleCreateVault() {
    if (this.password !== this.confirmPassword) {
      this.error = "Passwords do not match";
      return;
    }

    if (this.password.length < 12) {
      this.error = "Password must be at least 12 characters";
      return;
    }

    this.loading = true;
    this.error = "";

    try {
      const result = await api.createVault(this.password);
      this.recoveryPhrase = result.recoveryPhrase;
      this.step = "recovery";
    } catch (err) {
      this.error = err instanceof Error ? err.message : "Failed to create vault";
    }

    this.loading = false;
  }

  private downloadRecoveryPhrase() {
    const blob = new Blob(
      [
        `OCMT Recovery Phrase\n`,
        `========================\n\n`,
        `${this.recoveryPhrase}\n\n`,
        `========================\n`,
        `Store this securely. If you forget your vault password,\n`,
        `this phrase is the ONLY way to recover your data.\n\n`,
        `Created: ${new Date().toISOString()}\n`,
      ],
      { type: "text/plain" },
    );

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "ocmt-recovery-phrase.txt";
    a.click();
    URL.revokeObjectURL(url);
  }

  private handleComplete() {
    this.dispatchEvent(new CustomEvent("vault-created", { bubbles: true, composed: true }));
  }

  private handleSkip() {
    this.dispatchEvent(new CustomEvent("vault-skipped", { bubbles: true, composed: true }));
  }

  render() {
    if (this.step === "recovery") {
      return this.renderRecoveryStep();
    }
    return this.renderPasswordStep();
  }

  private renderPasswordStep() {
    const strength = this.getPasswordStrength();
    const canSubmit = this.password.length >= 12 && this.password === this.confirmPassword;

    return html`
      <div class="container">
        <h1>Create Your Vault</h1>
        <p class="subtitle">Protect your data with zero-knowledge encryption</p>

        <div class="card">
          <div class="info-box">
            <strong>Your vault password encrypts all your data.</strong><br>
            Not even OCMT can access it without this password.
          </div>

          ${
            this.error
              ? html`
            <div class="error-box">
              ${this.error}
            </div>
          `
              : ""
          }

          <div class="form-group" style="margin-top: 24px;">
            <label>Vault Password</label>
            <input
              type="password"
              .value=${this.password}
              @input=${(e: Event) => (this.password = (e.target as HTMLInputElement).value)}
              placeholder="Enter a strong password"
            />
            ${
              this.password
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
            @click=${this.handleCreateVault}
          >
            ${this.loading ? "Creating Vault..." : "Create Vault"}
          </button>

          <a href="#" class="skip-link" @click=${(e: Event) => {
            e.preventDefault();
            this.handleSkip();
          }}>
            Skip for now (you can set this up later)
          </a>
        </div>
      </div>
    `;
  }

  private renderRecoveryStep() {
    return html`
      <div class="container">
        <h1>Your Recovery Phrase</h1>
        <p class="subtitle">Save this - it's shown only once</p>

        <div class="card">
          <div class="recovery-phrase">
            ${this.recoveryPhrase}
          </div>

          <button class="btn download-btn" @click=${this.downloadRecoveryPhrase}>
            Download as Text File
          </button>

          <div class="warning-box">
            <h4>Important</h4>
            <ul>
              <li>This phrase can recover your data if you forget your password</li>
              <li>Store it somewhere safe (password manager, safe deposit box)</li>
              <li>Never share it with anyone</li>
              <li>OCMT cannot recover your data without it</li>
            </ul>
          </div>

          <div class="checkbox-group">
            <input
              type="checkbox"
              id="saved"
              .checked=${this.savedPhrase}
              @change=${(e: Event) => (this.savedPhrase = (e.target as HTMLInputElement).checked)}
            />
            <label for="saved">
              I have saved my recovery phrase securely
            </label>
          </div>

          <button
            class="btn"
            ?disabled=${!this.savedPhrase}
            @click=${this.handleComplete}
          >
            Complete Setup
          </button>
        </div>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-vault-setup": VaultSetupPage;
  }
}

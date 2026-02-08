import { LitElement, html, css } from "lit";
import { customElement, property, state, query } from "lit/decorators.js";
import QRCode from "qrcode";
import type { MfaCodeInput } from "../components/mfa-code-input.js";
import { toast } from "../components/toast.js";
import "../components/mfa-code-input.js";
import { api, User, MfaStatusResponse } from "../lib/api.js";

type SetupStep =
  | "loading"
  | "already-enabled"
  | "start"
  | "scan"
  | "verify"
  | "backup-codes"
  | "complete";

@customElement("ocmt-mfa-setup")
export class MfaSetupPage extends LitElement {
  static styles = css`
    :host {
      display: block;
      max-width: 600px;
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

    .card {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      padding: 32px;
      margin-bottom: 24px;
    }

    .step-header {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 24px;
    }

    .step-number {
      width: 32px;
      height: 32px;
      background: #4f46e5;
      color: white;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 600;
      font-size: 0.9rem;
    }

    .step-title {
      font-size: 1.2rem;
      font-weight: 600;
    }

    .qr-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 24px;
      margin-bottom: 24px;
    }

    .qr-code {
      background: white;
      padding: 16px;
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .qr-code canvas,
    .qr-code svg,
    .qr-code img {
      display: block;
    }

    .manual-entry {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 8px;
      padding: 16px;
      text-align: center;
    }

    .manual-entry-label {
      font-size: 0.85rem;
      color: #888;
      margin-bottom: 8px;
    }

    .secret-key {
      font-family: monospace;
      font-size: 1rem;
      color: #22c55e;
      letter-spacing: 2px;
      word-break: break-all;
      user-select: all;
    }

    .copy-btn {
      background: none;
      border: none;
      color: #818cf8;
      cursor: pointer;
      padding: 4px 8px;
      margin-left: 8px;
      font-size: 0.85rem;
    }

    .copy-btn:hover {
      text-decoration: underline;
    }

    .verify-section {
      text-align: center;
    }

    .verify-label {
      margin-bottom: 16px;
      color: #ccc;
    }

    .backup-codes {
      background: #1a1a2e;
      border: 2px dashed rgba(79, 70, 229, 0.5);
      border-radius: 12px;
      padding: 24px;
      margin: 24px 0;
    }

    .backup-codes-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 12px;
      margin-top: 16px;
    }

    .backup-code {
      font-family: monospace;
      font-size: 1rem;
      color: #22c55e;
      text-align: center;
      padding: 8px;
      background: rgba(34, 197, 94, 0.1);
      border-radius: 6px;
      user-select: all;
    }

    .warning-box {
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.3);
      border-radius: 8px;
      padding: 16px;
      margin: 24px 0;
    }

    .warning-box h4 {
      color: #ef4444;
      margin-bottom: 8px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .warning-box ul {
      margin: 0;
      padding-left: 20px;
      color: #ccc;
    }

    .warning-box li {
      margin-bottom: 4px;
    }

    .info-box {
      background: rgba(79, 70, 229, 0.1);
      border: 1px solid rgba(79, 70, 229, 0.3);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 24px;
      color: #a5b4fc;
    }

    .btn {
      padding: 14px 28px;
      border-radius: 8px;
      border: none;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
      display: inline-flex;
      align-items: center;
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

    .btn-secondary:hover:not(:disabled) {
      background: rgba(255, 255, 255, 0.15);
    }

    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .btn-group {
      display: flex;
      gap: 12px;
      justify-content: center;
      margin-top: 24px;
    }

    .error-message {
      background: rgba(239, 68, 68, 0.2);
      border: 1px solid rgba(239, 68, 68, 0.3);
      padding: 12px;
      border-radius: 8px;
      margin-bottom: 16px;
      color: #ef4444;
      text-align: center;
    }

    .success-icon {
      font-size: 4rem;
      margin-bottom: 16px;
    }

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

    .back-link {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: #888;
      text-decoration: none;
      margin-bottom: 24px;
      font-size: 0.9rem;
    }

    .back-link:hover {
      color: #fff;
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
      color: #ccc;
    }

    .already-enabled {
      text-align: center;
      padding: 40px 20px;
    }

    .already-enabled-icon {
      font-size: 3rem;
      margin-bottom: 16px;
    }
  `;

  @property({ type: Object })
  user: User | null = null;

  @state() private step: SetupStep = "loading";
  @state() private mfaStatus: MfaStatusResponse | null = null;
  @state() private secret = "";
  @state() private qrUri = "";
  @state() private backupCodes: string[] = [];
  @state() private savedCodes = false;
  @state() private loading = false;
  @state() private error = "";

  @query("mfa-code-input")
  private codeInput!: MfaCodeInput;

  connectedCallback() {
    super.connectedCallback();
    this.checkMfaStatus();
  }

  private async checkMfaStatus() {
    try {
      this.mfaStatus = await api.getMfaStatus();
      if (this.mfaStatus.totpEnabled) {
        this.step = "already-enabled";
      } else {
        this.step = "start";
      }
    } catch (err) {
      // MFA status endpoint might not exist or fail, proceed to start
      this.step = "start";
    }
  }

  private async startSetup() {
    this.loading = true;
    this.error = "";

    try {
      const result = await api.setupMfa();
      this.secret = result.secret;
      this.qrUri = result.qrUri;
      this.step = "scan";

      // Generate QR code after render
      await this.updateComplete;
      this.generateQRCode();
    } catch (err) {
      this.error = err instanceof Error ? err.message : "Failed to start MFA setup";
    }

    this.loading = false;
  }

  private async generateQRCode() {
    const container = this.shadowRoot?.querySelector(".qr-code");
    if (!container || !this.qrUri) {
      return;
    }

    try {
      const size = 200;
      const canvas = document.createElement("canvas");
      canvas.width = size;
      canvas.height = size;
      // Clear container safely using DOM API
      while (container.firstChild) {
        container.removeChild(container.firstChild);
      }
      container.appendChild(canvas);

      // Generate QR code using the qrcode library
      await QRCode.toCanvas(canvas, this.qrUri, {
        width: size,
        margin: 2,
        color: { dark: "#000000", light: "#ffffff" },
      });
    } catch (err) {
      console.error("Failed to generate QR code:", err);
      // Fallback: show text indicating to use manual entry using safe DOM APIs
      const container = this.shadowRoot?.querySelector(".qr-code");
      if (container) {
        // Clear container safely
        while (container.firstChild) {
          container.removeChild(container.firstChild);
        }
        // Build fallback message using DOM APIs to prevent XSS
        const fallbackDiv = document.createElement("div");
        fallbackDiv.style.cssText =
          "width: 200px; height: 200px; display: flex; align-items: center; justify-content: center; text-align: center; color: #666; font-size: 14px;";
        fallbackDiv.textContent = "QR code unavailable. Use manual entry below.";
        container.appendChild(fallbackDiv);
      }
    }
  }

  private async handleCodeComplete(e: CustomEvent<{ code: string }>) {
    await this.verifyCode(e.detail.code);
  }

  private async verifyCode(code: string) {
    this.loading = true;
    this.error = "";

    try {
      const result = await api.verifyMfa(code);

      if (result.success) {
        this.backupCodes = result.backupCodes || [];
        this.step = "backup-codes";
        toast.success("MFA enabled successfully!");
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

  private copySecret() {
    navigator.clipboard.writeText(this.secret);
    toast.success("Secret key copied to clipboard");
  }

  private copyBackupCodes() {
    const codesText = this.backupCodes.join("\n");
    navigator.clipboard.writeText(codesText);
    toast.success("Backup codes copied to clipboard");
  }

  private downloadBackupCodes() {
    const content = [
      "OCMT MFA Backup Codes",
      "========================",
      "",
      "Store these codes securely. Each code can only be used once.",
      "",
      ...this.backupCodes,
      "",
      "========================",
      `Generated: ${new Date().toISOString()}`,
    ].join("\n");

    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "ocmt-backup-codes.txt";
    a.click();
    URL.revokeObjectURL(url);
  }

  private handleComplete() {
    this.step = "complete";
    this.dispatchEvent(new CustomEvent("mfa-enabled", { bubbles: true, composed: true }));
  }

  private navigateToSettings() {
    window.history.pushState({}, "", "/vault/settings");
    window.dispatchEvent(new PopStateEvent("popstate"));
  }

  render() {
    return html`
      <a href="/vault/settings" class="back-link" @click=${(e: Event) => {
        e.preventDefault();
        this.navigateToSettings();
      }}>
        &larr; Back to Security Settings
      </a>

      <h1>Two-Factor Authentication</h1>
      <p class="subtitle">Add an extra layer of security to your account</p>

      ${this.renderStep()}
    `;
  }

  private renderStep() {
    switch (this.step) {
      case "loading":
        return html`
          <div class="loading">
            <div class="spinner"></div>
          </div>
        `;

      case "already-enabled":
        return this.renderAlreadyEnabled();

      case "start":
        return this.renderStart();

      case "scan":
        return this.renderScan();

      case "verify":
        return this.renderVerify();

      case "backup-codes":
        return this.renderBackupCodes();

      case "complete":
        return this.renderComplete();
    }
  }

  private renderAlreadyEnabled() {
    return html`
      <div class="card">
        <div class="already-enabled">
          <div class="already-enabled-icon">&#x1F512;</div>
          <h2>MFA is Already Enabled</h2>
          <p style="color: #888; margin-bottom: 24px;">
            Two-factor authentication is currently active on your account.
          </p>
          <p style="color: #888; margin-bottom: 24px;">
            Backup codes remaining: <strong style="color: #22c55e;">${this.mfaStatus?.backupCodesRemaining ?? "?"}</strong>
          </p>
          <div class="btn-group">
            <button class="btn btn-secondary" @click=${this.navigateToSettings}>
              Back to Settings
            </button>
          </div>
        </div>
      </div>
    `;
  }

  private renderStart() {
    return html`
      <div class="card">
        <div class="info-box">
          <strong>What you'll need:</strong>
          <ul style="margin-top: 8px; padding-left: 20px;">
            <li>An authenticator app (Google Authenticator, Authy, 1Password, etc.)</li>
            <li>A safe place to store backup codes</li>
          </ul>
        </div>

        ${this.error ? html`<div class="error-message">${this.error}</div>` : ""}

        <div style="text-align: center;">
          <button class="btn btn-primary" @click=${this.startSetup} ?disabled=${this.loading}>
            ${this.loading ? "Setting up..." : "Begin Setup"}
          </button>
        </div>
      </div>
    `;
  }

  private renderScan() {
    return html`
      <div class="card">
        <div class="step-header">
          <div class="step-number">1</div>
          <div class="step-title">Scan QR Code</div>
        </div>

        <div class="qr-container">
          <div class="qr-code">
            <!-- QR code will be rendered here -->
          </div>

          <div class="manual-entry">
            <div class="manual-entry-label">Or enter this key manually:</div>
            <div>
              <span class="secret-key">${this.secret}</span>
              <button class="copy-btn" @click=${this.copySecret}>Copy</button>
            </div>
          </div>
        </div>

        <div class="step-header" style="margin-top: 32px;">
          <div class="step-number">2</div>
          <div class="step-title">Verify Code</div>
        </div>

        ${this.error ? html`<div class="error-message">${this.error}</div>` : ""}

        <div class="verify-section">
          <p class="verify-label">Enter the 6-digit code from your authenticator app:</p>
          <mfa-code-input
            ?disabled=${this.loading}
            @code-complete=${this.handleCodeComplete}
          ></mfa-code-input>
        </div>
      </div>
    `;
  }

  private renderVerify() {
    return html`
      <div class="card">
        <div class="step-header">
          <div class="step-number">2</div>
          <div class="step-title">Verify Code</div>
        </div>

        ${this.error ? html`<div class="error-message">${this.error}</div>` : ""}

        <div class="verify-section">
          <p class="verify-label">Enter the 6-digit code from your authenticator app:</p>
          <mfa-code-input
            ?disabled=${this.loading}
            @code-complete=${this.handleCodeComplete}
          ></mfa-code-input>
        </div>
      </div>
    `;
  }

  private renderBackupCodes() {
    return html`
      <div class="card">
        <div class="step-header">
          <div class="step-number">3</div>
          <div class="step-title">Save Backup Codes</div>
        </div>

        <p style="color: #ccc; margin-bottom: 16px;">
          Save these backup codes in a secure location. You can use them to access your account if you lose your authenticator device.
        </p>

        <div class="backup-codes">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <strong style="color: #22c55e;">Your Backup Codes</strong>
            <button class="copy-btn" @click=${this.copyBackupCodes}>Copy All</button>
          </div>
          <div class="backup-codes-grid">
            ${this.backupCodes.map((code) => html`<div class="backup-code">${code}</div>`)}
          </div>
        </div>

        <button class="btn btn-secondary" style="width: 100%; margin-bottom: 16px;" @click=${this.downloadBackupCodes}>
          Download as Text File
        </button>

        <div class="warning-box">
          <h4>&#x26A0; Important</h4>
          <ul>
            <li>Each backup code can only be used once</li>
            <li>Store them somewhere safe (password manager, safe deposit box)</li>
            <li>These codes will not be shown again</li>
            <li>If you lose both your authenticator and backup codes, you may lose access to your account</li>
          </ul>
        </div>

        <div class="checkbox-group">
          <input
            type="checkbox"
            id="saved-codes"
            .checked=${this.savedCodes}
            @change=${(e: Event) => (this.savedCodes = (e.target as HTMLInputElement).checked)}
          />
          <label for="saved-codes">
            I have saved my backup codes securely
          </label>
        </div>

        <div class="btn-group">
          <button
            class="btn btn-primary"
            ?disabled=${!this.savedCodes}
            @click=${this.handleComplete}
          >
            Complete Setup
          </button>
        </div>
      </div>
    `;
  }

  private renderComplete() {
    return html`
      <div class="card" style="text-align: center;">
        <div class="success-icon">&#x2705;</div>
        <h2>MFA Enabled Successfully!</h2>
        <p style="color: #888; margin-bottom: 24px;">
          Your account is now protected with two-factor authentication.
        </p>
        <button class="btn btn-primary" @click=${this.navigateToSettings}>
          Back to Settings
        </button>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-mfa-setup": MfaSetupPage;
  }
}

import { LitElement, html, css } from "lit";
import { customElement, state } from "lit/decorators.js";
import { api } from "../lib/api.js";

@customElement("ocmt-login")
export class LoginPage extends LitElement {
  static styles = css`
    :host {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 80vh;
    }

    .login-container {
      text-align: center;
      max-width: 400px;
      width: 100%;
    }

    .logo {
      font-size: 4rem;
      margin-bottom: 16px;
    }

    h1 {
      font-size: 2.5rem;
      margin-bottom: 8px;
    }

    .subtitle {
      color: #888;
      font-size: 1.1rem;
      margin-bottom: 40px;
    }

    .card {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      padding: 32px;
    }

    .form-group {
      margin-bottom: 16px;
    }

    .input {
      width: 100%;
      padding: 14px 16px;
      border-radius: 8px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: rgba(255, 255, 255, 0.1);
      color: white;
      font-size: 1rem;
      box-sizing: border-box;
    }

    .input::placeholder {
      color: #666;
    }

    .input:focus {
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
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }

    .btn:hover:not(:disabled) {
      background: #4338ca;
    }

    .btn:disabled {
      opacity: 0.7;
      cursor: not-allowed;
    }

    .oauth-buttons {
      display: flex;
      flex-direction: column;
      gap: 12px;
      margin-bottom: 24px;
    }

    .oauth-btn {
      width: 100%;
      padding: 14px 16px;
      border-radius: 8px;
      border: none;
      font-size: 1rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 12px;
    }

    .oauth-btn:disabled {
      opacity: 0.7;
      cursor: not-allowed;
    }

    .oauth-btn svg {
      width: 20px;
      height: 20px;
      flex-shrink: 0;
    }

    .oauth-btn-google {
      background: #ffffff;
      color: #3c4043;
      border: 1px solid #dadce0;
    }

    .oauth-btn-google:hover:not(:disabled) {
      background: #f8f9fa;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    }

    .oauth-btn-github {
      background: #24292f;
      color: #ffffff;
    }

    .oauth-btn-github:hover:not(:disabled) {
      background: #32383f;
    }

    .oauth-btn-microsoft {
      background: #2f2f2f;
      color: #ffffff;
    }

    .oauth-btn-microsoft:hover:not(:disabled) {
      background: #3d3d3d;
    }

    .divider {
      display: flex;
      align-items: center;
      margin: 24px 0;
      gap: 16px;
    }

    .divider-line {
      flex: 1;
      height: 1px;
      background: rgba(255, 255, 255, 0.1);
    }

    .divider-text {
      color: #666;
      font-size: 0.85rem;
      text-transform: lowercase;
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

    .success-message {
      background: rgba(34, 197, 94, 0.2);
      border: 1px solid rgba(34, 197, 94, 0.3);
      padding: 20px;
      border-radius: 12px;
      margin-bottom: 20px;
    }

    .success-message h3 {
      color: #22c55e;
      margin-bottom: 8px;
    }

    .success-message p {
      color: #888;
    }

    .error-message {
      background: rgba(239, 68, 68, 0.2);
      border: 1px solid rgba(239, 68, 68, 0.3);
      padding: 12px;
      border-radius: 8px;
      margin-bottom: 16px;
      color: #ef4444;
    }

    .dev-link {
      margin-top: 16px;
      padding: 12px;
      background: rgba(79, 70, 229, 0.2);
      border-radius: 8px;
      font-size: 0.85rem;
    }

    .dev-link a {
      color: #818cf8;
      word-break: break-all;
    }

    .features {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 16px;
      margin-top: 40px;
      text-align: left;
    }

    .feature {
      padding: 16px;
      background: rgba(255, 255, 255, 0.03);
      border-radius: 8px;
    }

    .feature-icon {
      font-size: 1.5rem;
      margin-bottom: 8px;
    }

    .feature h4 {
      font-size: 0.9rem;
      margin-bottom: 4px;
    }

    .feature p {
      color: #666;
      font-size: 0.8rem;
    }
  `;

  @state()
  private email = "";

  @state()
  private loading = false;

  @state()
  private oauthLoading: "google" | "github" | "microsoft" | null = null;

  @state()
  private sent = false;

  @state()
  private error = "";

  @state()
  private devVerifyUrl = "";

  connectedCallback() {
    super.connectedCallback();
    // Check for OAuth error from callback
    const urlParams = new URLSearchParams(window.location.search);
    const oauthError = urlParams.get("error");
    if (oauthError) {
      this.error = this.getOAuthErrorMessage(oauthError);
      // Clean up the URL
      window.history.replaceState({}, "", window.location.pathname);
    }
  }

  private getOAuthErrorMessage(error: string): string {
    const errorMessages: Record<string, string> = {
      access_denied: "Access was denied. Please try again.",
      invalid_request: "Invalid request. Please try again.",
      server_error: "Server error. Please try again later.",
      temporarily_unavailable: "Service temporarily unavailable. Please try again later.",
      oauth_failed: "OAuth authentication failed. Please try again.",
    };
    return errorMessages[error] || `Authentication failed: ${error}`;
  }

  private handleOAuthLogin(provider: "google" | "github" | "microsoft") {
    this.oauthLoading = provider;
    this.error = "";
    window.location.href = `/api/auth/${provider}`;
  }

  private async handleSubmit(e: Event) {
    e.preventDefault();

    if (!this.email || !this.email.includes("@")) {
      this.error = "Please enter a valid email address";
      return;
    }

    this.loading = true;
    this.error = "";

    try {
      const result = await api.login(this.email);

      if (result.success) {
        this.sent = true;
        // In dev mode, show the verify URL
        if (result._dev_verify_url) {
          this.devVerifyUrl = result._dev_verify_url;
        }
      }
    } catch (err) {
      this.error = err instanceof Error ? err.message : "Failed to send login link";
    }

    this.loading = false;
  }

  render() {
    return html`
      <div class="login-container">
        <div class="logo">🐾</div>
        <h1>OCMT</h1>
        <p class="subtitle">Your personal AI assistant</p>

        <div class="card">
          ${this.sent ? this.renderSentMessage() : this.renderForm()}
        </div>

        <div class="features">
          <div class="feature">
            <div class="feature-icon">🔒</div>
            <h4>Fully Isolated</h4>
            <p>Your own private AI container</p>
          </div>
          <div class="feature">
            <div class="feature-icon">🔗</div>
            <h4>Connect Apps</h4>
            <p>Calendar, email, and more</p>
          </div>
          <div class="feature">
            <div class="feature-icon">💬</div>
            <h4>Multi-Channel</h4>
            <p>Web, Telegram, WhatsApp</p>
          </div>
          <div class="feature">
            <div class="feature-icon">🧠</div>
            <h4>Remembers You</h4>
            <p>Learns your preferences</p>
          </div>
        </div>
      </div>
    `;
  }

  private renderForm() {
    const isAnyLoading = this.loading || this.oauthLoading !== null;

    return html`
      ${this.error ? html`<div class="error-message">${this.error}</div>` : ""}

      <div class="oauth-buttons">
        <button
          class="oauth-btn oauth-btn-google"
          @click=${() => this.handleOAuthLogin("google")}
          ?disabled=${isAnyLoading}
        >
          ${
            this.oauthLoading === "google"
              ? html`
                  <div class="spinner" style="border-color: rgba(0, 0, 0, 0.2); border-top-color: #3c4043"></div>
                `
              : html`
                  <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path
                      fill="#4285F4"
                      d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                    />
                    <path
                      fill="#34A853"
                      d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                    />
                    <path
                      fill="#FBBC05"
                      d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                    />
                    <path
                      fill="#EA4335"
                      d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                    />
                  </svg>
                `
          }
          ${this.oauthLoading === "google" ? "Connecting..." : "Continue with Google"}
        </button>

        <button
          class="oauth-btn oauth-btn-github"
          @click=${() => this.handleOAuthLogin("github")}
          ?disabled=${isAnyLoading}
        >
          ${
            this.oauthLoading === "github"
              ? html`
                  <div class="spinner"></div>
                `
              : html`
                  <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="currentColor">
                    <path
                      d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"
                    />
                  </svg>
                `
          }
          ${this.oauthLoading === "github" ? "Connecting..." : "Continue with GitHub"}
        </button>

        <button
          class="oauth-btn oauth-btn-microsoft"
          @click=${() => this.handleOAuthLogin("microsoft")}
          ?disabled=${isAnyLoading}
        >
          ${
            this.oauthLoading === "microsoft"
              ? html`
                  <div class="spinner"></div>
                `
              : html`
                  <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path fill="#F25022" d="M1 1h10v10H1z" />
                    <path fill="#00A4EF" d="M1 13h10v10H1z" />
                    <path fill="#7FBA00" d="M13 1h10v10H13z" />
                    <path fill="#FFB900" d="M13 13h10v10H13z" />
                  </svg>
                `
          }
          ${this.oauthLoading === "microsoft" ? "Connecting..." : "Continue with Microsoft"}
        </button>
      </div>

      <div class="divider">
        <div class="divider-line"></div>
        <span class="divider-text">or</span>
        <div class="divider-line"></div>
      </div>

      <form @submit=${this.handleSubmit}>
        <div class="form-group">
          <input
            type="email"
            class="input"
            placeholder="Enter your email"
            .value=${this.email}
            @input=${(e: Event) => (this.email = (e.target as HTMLInputElement).value)}
            ?disabled=${isAnyLoading}
            required
          />
        </div>
        <button type="submit" class="btn" ?disabled=${isAnyLoading}>
          ${
            this.loading
              ? html`
                  <div class="spinner"></div>
                `
              : ""
          }
          ${this.loading ? "Sending..." : "Continue with Email"}
        </button>
      </form>
    `;
  }

  private renderSentMessage() {
    return html`
      <div class="success-message">
        <h3>Check your email!</h3>
        <p>We sent a login link to <strong>${this.email}</strong></p>
      </div>
      <p style="color: #888; font-size: 0.9rem;">
        Click the link in the email to sign in. The link expires in 15 minutes.
      </p>

      ${
        this.devVerifyUrl
          ? html`
        <div class="dev-link">
          <strong>Dev mode:</strong><br>
          <a href="${this.devVerifyUrl}" target="_blank">Click here to verify</a>
        </div>
      `
          : ""
      }

      <button
        class="btn"
        style="margin-top: 20px; background: transparent; border: 1px solid rgba(255,255,255,0.2);"
        @click=${() => {
          this.sent = false;
          this.devVerifyUrl = "";
        }}
      >
        Try a different email
      </button>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-login": LoginPage;
  }
}

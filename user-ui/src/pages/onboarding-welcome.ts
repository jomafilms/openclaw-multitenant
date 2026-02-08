import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { User } from "../lib/api.js";

@customElement("ocmt-onboarding-welcome")
export class OnboardingWelcomePage extends LitElement {
  static styles = css`
    :host {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 80vh;
    }

    .container {
      text-align: center;
      max-width: 600px;
      width: 100%;
      padding: 0 24px;
    }

    .logo {
      font-size: 4rem;
      margin-bottom: 16px;
    }

    h1 {
      font-size: 2.5rem;
      margin-bottom: 12px;
    }

    .welcome-name {
      color: #818cf8;
    }

    .subtitle {
      color: #888;
      font-size: 1.1rem;
      margin-bottom: 48px;
    }

    .steps {
      display: flex;
      justify-content: center;
      gap: 32px;
      margin-bottom: 48px;
      flex-wrap: wrap;
    }

    .step {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 12px;
      min-width: 120px;
    }

    .step-icon {
      width: 64px;
      height: 64px;
      border-radius: 50%;
      background: rgba(79, 70, 229, 0.2);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.5rem;
    }

    .step-title {
      font-weight: 600;
      color: white;
    }

    .step-desc {
      font-size: 0.85rem;
      color: #888;
    }

    .connector {
      display: flex;
      align-items: center;
      color: #555;
      padding-top: 20px;
    }

    .btn {
      padding: 16px 48px;
      border-radius: 8px;
      border: none;
      font-size: 1.1rem;
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

    .btn-primary:hover {
      background: #4338ca;
    }

    .skip-link {
      display: block;
      margin-top: 24px;
      color: #888;
      text-decoration: none;
      font-size: 0.9rem;
      cursor: pointer;
    }

    .skip-link:hover {
      color: white;
    }

    @media (max-width: 600px) {
      .steps {
        flex-direction: column;
        gap: 24px;
      }

      .connector {
        display: none;
      }

      h1 {
        font-size: 1.8rem;
      }
    }
  `;

  @property({ type: Object })
  user: User | null = null;

  @state()
  private starting = false;

  private handleGetStarted() {
    this.starting = true;
    // Navigate to group creation
    this.dispatchEvent(
      new CustomEvent("navigate", {
        detail: { page: "onboarding-group" },
        bubbles: true,
        composed: true,
      }),
    );
  }

  private handleSkip() {
    // Skip to dashboard
    this.dispatchEvent(
      new CustomEvent("navigate", {
        detail: { page: "dashboard" },
        bubbles: true,
        composed: true,
      }),
    );
  }

  render() {
    const firstName = this.user?.name?.split(" ")[0] || "there";

    return html`
      <div class="container">
        <div class="logo">&#x1F44B;</div>
        <h1>Welcome, <span class="welcome-name">${firstName}</span>!</h1>
        <p class="subtitle">
          Let's get you set up with your own AI-powered workspace.
          This will only take a few minutes.
        </p>

        <div class="steps">
          <div class="step">
            <div class="step-icon">&#x1F3E2;</div>
            <div class="step-title">Create Group</div>
            <div class="step-desc">Your workspace</div>
          </div>

          <div class="connector">&#x2192;</div>

          <div class="step">
            <div class="step-icon">&#x1F465;</div>
            <div class="step-title">Invite Team</div>
            <div class="step-desc">Optional</div>
          </div>

          <div class="connector">&#x2192;</div>

          <div class="step">
            <div class="step-icon">&#x1F916;</div>
            <div class="step-title">Configure Agent</div>
            <div class="step-desc">Your AI assistant</div>
          </div>
        </div>

        <button class="btn btn-primary" @click=${this.handleGetStarted} ?disabled=${this.starting}>
          ${this.starting ? "Starting..." : "Get Started"}
        </button>

        <a class="skip-link" @click=${this.handleSkip}>
          I'll do this later - skip to dashboard
        </a>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-onboarding-welcome": OnboardingWelcomePage;
  }
}

import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { User } from "../lib/api.js";

@customElement("ocmt-onboarding-complete")
export class OnboardingCompletePage extends LitElement {
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

    .celebration {
      font-size: 5rem;
      margin-bottom: 24px;
      animation: bounce 1s ease infinite;
    }

    @keyframes bounce {
      0%,
      100% {
        transform: translateY(0);
      }
      50% {
        transform: translateY(-10px);
      }
    }

    h1 {
      font-size: 2.5rem;
      margin-bottom: 12px;
      color: #22c55e;
    }

    .subtitle {
      color: #888;
      font-size: 1.1rem;
      margin-bottom: 40px;
    }

    .summary {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      padding: 32px;
      margin-bottom: 32px;
      text-align: left;
    }

    .summary h3 {
      margin-bottom: 16px;
      font-size: 1.1rem;
    }

    .summary-item {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 12px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    }

    .summary-item:last-child {
      border-bottom: none;
    }

    .summary-icon {
      width: 40px;
      height: 40px;
      border-radius: 10px;
      background: rgba(34, 197, 94, 0.2);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.2rem;
      flex-shrink: 0;
    }

    .summary-content {
      flex: 1;
    }

    .summary-label {
      color: #888;
      font-size: 0.85rem;
    }

    .summary-value {
      color: white;
      font-weight: 500;
    }

    .quick-links {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 16px;
      margin-bottom: 32px;
    }

    .quick-link {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 20px;
      text-align: center;
      cursor: pointer;
      transition: all 0.2s;
      text-decoration: none;
      color: white;
    }

    .quick-link:hover {
      background: rgba(255, 255, 255, 0.08);
      border-color: rgba(79, 70, 229, 0.3);
    }

    .quick-link-icon {
      font-size: 2rem;
      margin-bottom: 8px;
    }

    .quick-link-title {
      font-weight: 500;
      margin-bottom: 4px;
    }

    .quick-link-desc {
      font-size: 0.8rem;
      color: #888;
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

    @media (max-width: 600px) {
      .quick-links {
        grid-template-columns: 1fr;
      }

      h1 {
        font-size: 1.8rem;
      }

      .celebration {
        font-size: 4rem;
      }
    }
  `;

  @property({ type: Object })
  user: User | null = null;

  @state()
  private summary = {
    groupName: "",
    agentName: "",
    invitesSent: 0,
  };

  connectedCallback() {
    super.connectedCallback();
    // Get summary info - in a real app this would come from the API or state
    this.summary = {
      groupName: sessionStorage.getItem("onboarding_group_name") || "Your Group",
      agentName: "AI Assistant",
      invitesSent: 0,
    };
  }

  private navigateTo(page: string) {
    this.dispatchEvent(
      new CustomEvent("navigate", {
        detail: { page },
        bubbles: true,
        composed: true,
      }),
    );
  }

  render() {
    return html`
      <div class="container">
        <div class="celebration">&#x1F389;</div>
        <h1>You're All Set!</h1>
        <p class="subtitle">
          Your workspace is ready. Let's explore what you can do.
        </p>

        <div class="summary">
          <h3>What we set up</h3>

          <div class="summary-item">
            <div class="summary-icon">&#x1F3E2;</div>
            <div class="summary-content">
              <div class="summary-label">Group</div>
              <div class="summary-value">${this.summary.groupName}</div>
            </div>
          </div>

          <div class="summary-item">
            <div class="summary-icon">&#x1F916;</div>
            <div class="summary-content">
              <div class="summary-label">AI Agent</div>
              <div class="summary-value">${this.summary.agentName}</div>
            </div>
          </div>

          <div class="summary-item">
            <div class="summary-icon">&#x2705;</div>
            <div class="summary-content">
              <div class="summary-label">Status</div>
              <div class="summary-value">Ready to go!</div>
            </div>
          </div>
        </div>

        <div class="quick-links">
          <div class="quick-link" @click=${() => this.navigateTo("dashboard")}>
            <div class="quick-link-icon">&#x1F4AC;</div>
            <div class="quick-link-title">Start Chatting</div>
            <div class="quick-link-desc">Talk to your AI</div>
          </div>

          <div class="quick-link" @click=${() => this.navigateTo("connections")}>
            <div class="quick-link-icon">&#x1F517;</div>
            <div class="quick-link-title">Connect Apps</div>
            <div class="quick-link-desc">Calendar, email, etc.</div>
          </div>

          <div class="quick-link" @click=${() => this.navigateTo("groups")}>
            <div class="quick-link-icon">&#x1F465;</div>
            <div class="quick-link-title">Invite Team</div>
            <div class="quick-link-desc">Add more people</div>
          </div>
        </div>

        <button class="btn btn-primary" @click=${() => this.navigateTo("dashboard")}>
          Go to Dashboard &#x2192;
        </button>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-onboarding-complete": OnboardingCompletePage;
  }
}

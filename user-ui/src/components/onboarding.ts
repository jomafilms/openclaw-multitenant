import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";

const ONBOARDING_KEY = "ocmt_onboarding_seen";

@customElement("ocmt-onboarding")
export class OnboardingModal extends LitElement {
  static styles = css`
    :host {
      display: block;
    }

    .overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.8);
      z-index: 1000;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      animation: fadeIn 0.3s ease-out;
    }

    @keyframes fadeIn {
      from {
        opacity: 0;
      }
      to {
        opacity: 1;
      }
    }

    .modal {
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 20px;
      max-width: 500px;
      width: 100%;
      max-height: 90vh;
      overflow-y: auto;
      animation: slideUp 0.3s ease-out;
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

    .modal-header {
      padding: 32px 32px 0;
      text-align: center;
    }

    .modal-header h2 {
      font-size: 1.75rem;
      margin-bottom: 8px;
    }

    .modal-header p {
      color: #888;
    }

    .steps {
      padding: 24px 32px;
    }

    .step {
      display: flex;
      gap: 16px;
      padding: 16px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }

    .step:last-child {
      border-bottom: none;
    }

    .step-icon {
      width: 48px;
      height: 48px;
      background: rgba(79, 70, 229, 0.2);
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.5rem;
      flex-shrink: 0;
    }

    .step-content h3 {
      font-size: 1rem;
      margin-bottom: 4px;
    }

    .step-content p {
      color: #888;
      font-size: 0.9rem;
      line-height: 1.5;
    }

    .modal-footer {
      padding: 16px 32px 32px;
      display: flex;
      gap: 12px;
    }

    .btn {
      flex: 1;
      padding: 14px 24px;
      border-radius: 10px;
      border: none;
      font-size: 1rem;
      font-weight: 600;
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

    .btn-secondary {
      background: rgba(255, 255, 255, 0.1);
      color: #ccc;
    }

    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.15);
    }

    .progress-dots {
      display: flex;
      justify-content: center;
      gap: 8px;
      padding: 16px;
    }

    .dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: rgba(255, 255, 255, 0.2);
      transition: all 0.2s;
    }

    .dot.active {
      background: #4f46e5;
      width: 24px;
      border-radius: 4px;
    }

    @media (max-width: 480px) {
      .modal {
        border-radius: 16px;
      }

      .modal-header {
        padding: 24px 20px 0;
      }

      .modal-header h2 {
        font-size: 1.5rem;
      }

      .steps {
        padding: 20px;
      }

      .step {
        gap: 12px;
        padding: 12px 0;
      }

      .step-icon {
        width: 40px;
        height: 40px;
        font-size: 1.25rem;
      }

      .modal-footer {
        padding: 12px 20px 24px;
        flex-direction: column;
      }
    }
  `;

  @property({ type: String })
  userId = "";

  @state()
  private visible = false;

  @state()
  private currentStep = 0;

  private steps = [
    {
      icon: "💬",
      title: "Chat with your AI",
      description:
        "Use the Chat page to talk to your personal AI assistant. It remembers your conversations and learns your preferences over time.",
    },
    {
      icon: "🔌",
      title: "Connect your services",
      description:
        "Add integrations like Google Calendar, Gmail, or custom APIs. Your AI can then help you manage emails, schedule meetings, and more.",
    },
    {
      icon: "👥",
      title: "Access group resources",
      description:
        "If you belong to a group, you can connect to shared resources like company APIs and databases from the Resources page.",
    },
    {
      icon: "🤝",
      title: "Share with peers",
      description:
        "Use the Sharing page to grant others access to your data (like calendar availability) with your explicit approval for each request.",
    },
  ];

  connectedCallback() {
    super.connectedCallback();
    this.checkOnboardingStatus();
  }

  private checkOnboardingStatus() {
    const seen = localStorage.getItem(`${ONBOARDING_KEY}_${this.userId}`);
    if (!seen && this.userId) {
      this.visible = true;
    }
  }

  private handleNext() {
    if (this.currentStep < this.steps.length - 1) {
      this.currentStep++;
    } else {
      this.handleDismiss();
    }
  }

  private handleSkip() {
    this.handleDismiss();
  }

  private handleDismiss() {
    if (this.userId) {
      localStorage.setItem(`${ONBOARDING_KEY}_${this.userId}`, "true");
    }
    this.visible = false;
  }

  render() {
    if (!this.visible) {
      return null;
    }

    const step = this.steps[this.currentStep];
    const isLastStep = this.currentStep === this.steps.length - 1;

    return html`
      <div class="overlay">
        <div class="modal">
          <div class="modal-header">
            <h2>Welcome to OCMT!</h2>
            <p>Let's get you started with your personal AI</p>
          </div>

          <div class="progress-dots">
            ${this.steps.map(
              (_, i) => html`
              <div class="dot ${i === this.currentStep ? "active" : ""}"></div>
            `,
            )}
          </div>

          <div class="steps">
            <div class="step">
              <div class="step-icon">${step.icon}</div>
              <div class="step-content">
                <h3>${step.title}</h3>
                <p>${step.description}</p>
              </div>
            </div>
          </div>

          <div class="modal-footer">
            <button class="btn btn-secondary" @click=${this.handleSkip}>
              Skip
            </button>
            <button class="btn btn-primary" @click=${this.handleNext}>
              ${isLastStep ? "Get Started" : "Next"}
            </button>
          </div>
        </div>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-onboarding": OnboardingModal;
  }
}

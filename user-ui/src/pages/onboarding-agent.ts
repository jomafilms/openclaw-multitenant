import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { toast } from "../components/toast.js";
import { api, User } from "../lib/api.js";

const DEFAULT_SYSTEM_PROMPT = `You are a helpful AI assistant. You are polite, professional, and focused on providing accurate and useful information. When you don't know something, you say so honestly. You can help with a wide range of tasks including writing, analysis, coding, and general questions.`;

const MODEL_OPTIONS = [
  {
    value: "claude-3-opus",
    name: "Claude 3 Opus",
    description: "Most capable, best for complex tasks",
  },
  {
    value: "claude-3-sonnet",
    name: "Claude 3 Sonnet",
    description: "Balanced performance and speed",
  },
  { value: "claude-3-haiku", name: "Claude 3 Haiku", description: "Fast and efficient" },
  { value: "gpt-4", name: "GPT-4", description: "OpenAI's most capable model" },
  { value: "gpt-4-turbo", name: "GPT-4 Turbo", description: "Faster GPT-4 variant" },
  { value: "gpt-3.5-turbo", name: "GPT-3.5 Turbo", description: "Fast and cost-effective" },
];

@customElement("ocmt-onboarding-agent")
export class OnboardingAgentPage extends LitElement {
  static styles = css`
    :host {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 80vh;
    }

    .container {
      max-width: 600px;
      width: 100%;
      padding: 0 24px;
    }

    .progress {
      display: flex;
      gap: 8px;
      margin-bottom: 32px;
      justify-content: center;
    }

    .progress-step {
      width: 40px;
      height: 4px;
      border-radius: 2px;
      background: rgba(255, 255, 255, 0.2);
    }

    .progress-step.active {
      background: #4f46e5;
    }

    .progress-step.completed {
      background: #22c55e;
    }

    h1 {
      font-size: 1.8rem;
      margin-bottom: 8px;
      text-align: center;
    }

    .subtitle {
      color: #888;
      text-align: center;
      margin-bottom: 32px;
    }

    .card {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      padding: 32px;
    }

    .form-group {
      margin-bottom: 24px;
    }

    .form-group label {
      display: block;
      font-size: 0.9rem;
      color: #888;
      margin-bottom: 8px;
    }

    .form-group label .required {
      color: #ef4444;
    }

    input,
    select,
    textarea {
      width: 100%;
      padding: 14px 16px;
      border-radius: 8px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: rgba(255, 255, 255, 0.1);
      color: white;
      font-size: 1rem;
      box-sizing: border-box;
    }

    input::placeholder,
    textarea::placeholder {
      color: #666;
    }

    input:focus,
    select:focus,
    textarea:focus {
      outline: none;
      border-color: #4f46e5;
    }

    select option {
      background: #1a1a2e;
      color: white;
    }

    textarea {
      min-height: 150px;
      resize: vertical;
      font-family: inherit;
      line-height: 1.5;
    }

    .model-option {
      padding: 12px;
    }

    .model-description {
      font-size: 0.8rem;
      color: #888;
      margin-top: 4px;
    }

    .preset-btn {
      background: rgba(79, 70, 229, 0.2);
      border: 1px solid rgba(79, 70, 229, 0.3);
      color: #818cf8;
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 0.8rem;
      cursor: pointer;
      margin-right: 8px;
      transition: all 0.2s;
    }

    .preset-btn:hover {
      background: rgba(79, 70, 229, 0.3);
    }

    .presets {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 12px;
    }

    .actions {
      display: flex;
      gap: 12px;
      margin-top: 24px;
    }

    .btn {
      flex: 1;
      padding: 14px 24px;
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

    .error-message {
      background: rgba(239, 68, 68, 0.2);
      border: 1px solid rgba(239, 68, 68, 0.3);
      padding: 12px;
      border-radius: 8px;
      margin-bottom: 16px;
      color: #ef4444;
    }

    .char-count {
      text-align: right;
      font-size: 0.8rem;
      color: #666;
      margin-top: 4px;
    }
  `;

  @property({ type: Object })
  user: User | null = null;

  @state()
  private agentName = "";

  @state()
  private model = "claude-3-sonnet";

  @state()
  private systemPrompt = DEFAULT_SYSTEM_PROMPT;

  @state()
  private creating = false;

  @state()
  private error = "";

  private setPreset(preset: "default" | "concise" | "creative" | "technical") {
    switch (preset) {
      case "default":
        this.systemPrompt = DEFAULT_SYSTEM_PROMPT;
        break;
      case "concise":
        this.systemPrompt = `You are a concise and efficient AI assistant. Keep responses brief and to the point. Use bullet points when appropriate. Avoid unnecessary elaboration.`;
        break;
      case "creative":
        this.systemPrompt = `You are a creative and imaginative AI assistant. Think outside the box and offer unique perspectives. Be engaging and enthusiastic while remaining helpful and accurate.`;
        break;
      case "technical":
        this.systemPrompt = `You are a technical AI assistant specializing in software development, system administration, and technology topics. Provide detailed, accurate technical information with code examples when helpful.`;
        break;
    }
  }

  private async handleSubmit(e: Event) {
    e.preventDefault();

    if (!this.agentName) {
      this.error = "Please enter a name for your agent";
      return;
    }

    this.creating = true;
    this.error = "";

    try {
      // Save agent configuration
      // In a real implementation, this would call an API to create/configure the agent
      await api.setAgentConfig("agent.name", this.agentName);
      await api.setAgentConfig("agent.model", this.model);
      await api.setAgentConfig("agent.system_prompt", this.systemPrompt);

      toast.success("Agent configured!");

      // Clear onboarding session data
      sessionStorage.removeItem("onboarding_group_id");
      sessionStorage.removeItem("onboarding_group_name");

      // Navigate to completion
      this.dispatchEvent(
        new CustomEvent("navigate", {
          detail: { page: "onboarding-complete" },
          bubbles: true,
          composed: true,
        }),
      );
    } catch (err) {
      this.error = err instanceof Error ? err.message : "Failed to configure agent";
    }

    this.creating = false;
  }

  private handleBack() {
    this.dispatchEvent(
      new CustomEvent("navigate", {
        detail: { page: "onboarding-team" },
        bubbles: true,
        composed: true,
      }),
    );
  }

  render() {
    return html`
      <div class="container">
        <div class="progress">
          <div class="progress-step completed"></div>
          <div class="progress-step completed"></div>
          <div class="progress-step active"></div>
        </div>

        <h1>Configure Your Agent</h1>
        <p class="subtitle">
          Set up your AI assistant. You can customize these settings anytime.
        </p>

        <div class="card">
          ${this.error ? html`<div class="error-message">${this.error}</div>` : ""}

          <form @submit=${this.handleSubmit}>
            <div class="form-group">
              <label>Agent Name <span class="required">*</span></label>
              <input
                type="text"
                placeholder="My AI Assistant"
                .value=${this.agentName}
                @input=${(e: Event) => (this.agentName = (e.target as HTMLInputElement).value)}
                ?disabled=${this.creating}
                required
              />
            </div>

            <div class="form-group">
              <label>AI Model</label>
              <select
                .value=${this.model}
                @change=${(e: Event) => (this.model = (e.target as HTMLSelectElement).value)}
                ?disabled=${this.creating}
              >
                ${MODEL_OPTIONS.map(
                  (opt) => html`
                    <option value="${opt.value}">${opt.name} - ${opt.description}</option>
                  `,
                )}
              </select>
            </div>

            <div class="form-group">
              <label>System Prompt</label>
              <div class="presets">
                <button type="button" class="preset-btn" @click=${() => this.setPreset("default")}>
                  Default
                </button>
                <button type="button" class="preset-btn" @click=${() => this.setPreset("concise")}>
                  Concise
                </button>
                <button type="button" class="preset-btn" @click=${() => this.setPreset("creative")}>
                  Creative
                </button>
                <button type="button" class="preset-btn" @click=${() => this.setPreset("technical")}>
                  Technical
                </button>
              </div>
              <textarea
                placeholder="Instructions for your AI assistant..."
                .value=${this.systemPrompt}
                @input=${(e: Event) => (this.systemPrompt = (e.target as HTMLTextAreaElement).value)}
                ?disabled=${this.creating}
              ></textarea>
              <div class="char-count">${this.systemPrompt.length} characters</div>
            </div>

            <div class="actions">
              <button type="button" class="btn btn-secondary" @click=${this.handleBack} ?disabled=${this.creating}>
                Back
              </button>
              <button type="submit" class="btn btn-primary" ?disabled=${this.creating || !this.agentName}>
                ${
                  this.creating
                    ? html`
                        <div class="spinner"></div>
                      `
                    : ""
                }
                ${this.creating ? "Creating..." : "Create Agent"}
              </button>
            </div>
          </form>
        </div>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-onboarding-agent": OnboardingAgentPage;
  }
}

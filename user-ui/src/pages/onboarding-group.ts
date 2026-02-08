import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { toast } from "../components/toast.js";
import { api, User } from "../lib/api.js";

@customElement("ocmt-onboarding-group")
export class OnboardingGroupPage extends LitElement {
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
      margin-bottom: 20px;
    }

    .form-group label {
      display: block;
      font-size: 0.9rem;
      color: #888;
      margin-bottom: 8px;
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
    }

    input::placeholder,
    textarea::placeholder {
      color: #666;
    }

    input:focus,
    textarea:focus {
      outline: none;
      border-color: #4f46e5;
    }

    textarea {
      min-height: 80px;
      resize: vertical;
    }

    .slug-preview {
      font-size: 0.85rem;
      color: #888;
      margin-top: 8px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .slug-preview .url {
      color: #818cf8;
      font-family: monospace;
    }

    .slug-status {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      font-size: 0.8rem;
      padding: 2px 8px;
      border-radius: 4px;
    }

    .slug-status.available {
      color: #22c55e;
      background: rgba(34, 197, 94, 0.2);
    }

    .slug-status.unavailable {
      color: #ef4444;
      background: rgba(239, 68, 68, 0.2);
    }

    .slug-status.checking {
      color: #eab308;
      background: rgba(234, 179, 8, 0.2);
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
  `;

  @property({ type: Object })
  user: User | null = null;

  @state()
  private groupName = "";

  @state()
  private slug = "";

  @state()
  private description = "";

  @state()
  private slugStatus: "idle" | "checking" | "available" | "unavailable" = "idle";

  @state()
  private creating = false;

  @state()
  private error = "";

  private slugCheckTimeout: ReturnType<typeof setTimeout> | null = null;

  private generateSlug(name: string): string {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "");
  }

  private handleNameInput(e: Event) {
    this.groupName = (e.target as HTMLInputElement).value;
    // Auto-generate slug from name if slug is empty or was auto-generated
    if (!this.slug || this.slug === this.generateSlug(this.groupName.slice(0, -1))) {
      this.slug = this.generateSlug(this.groupName);
      this.checkSlugAvailability();
    }
  }

  private handleSlugInput(e: Event) {
    // Only allow valid slug characters
    const input = (e.target as HTMLInputElement).value;
    this.slug = input.toLowerCase().replace(/[^a-z0-9-]/g, "");
    this.checkSlugAvailability();
  }

  private checkSlugAvailability() {
    // Debounce the check
    if (this.slugCheckTimeout) {
      clearTimeout(this.slugCheckTimeout);
    }

    if (!this.slug || this.slug.length < 2) {
      this.slugStatus = "idle";
      return;
    }

    this.slugStatus = "checking";

    this.slugCheckTimeout = setTimeout(async () => {
      try {
        // In a real implementation, we'd call an API to check availability
        // For now, simulate a check
        await new Promise((resolve) => setTimeout(resolve, 300));
        // Assume available if slug is valid
        this.slugStatus = this.slug.length >= 2 ? "available" : "idle";
      } catch {
        this.slugStatus = "unavailable";
      }
    }, 500);
  }

  private async handleSubmit(e: Event) {
    e.preventDefault();

    if (!this.groupName || !this.slug) {
      this.error = "Please fill in all required fields";
      return;
    }

    if (this.slug.length < 2) {
      this.error = "Slug must be at least 2 characters";
      return;
    }

    this.creating = true;
    this.error = "";

    try {
      const result = await api.createGroup(
        this.groupName,
        this.slug,
        this.description || undefined,
      );

      if (result.success) {
        toast.success("Group created!");
        // Store group ID for next steps
        sessionStorage.setItem("onboarding_group_id", result.group.id);
        sessionStorage.setItem("onboarding_group_name", result.group.name);

        // Navigate to team invite
        this.dispatchEvent(
          new CustomEvent("navigate", {
            detail: { page: "onboarding-team" },
            bubbles: true,
            composed: true,
          }),
        );
      }
    } catch (err) {
      this.error = err instanceof Error ? err.message : "Failed to create group";
    }

    this.creating = false;
  }

  private handleBack() {
    this.dispatchEvent(
      new CustomEvent("navigate", {
        detail: { page: "onboarding-welcome" },
        bubbles: true,
        composed: true,
      }),
    );
  }

  render() {
    return html`
      <div class="container">
        <div class="progress">
          <div class="progress-step active"></div>
          <div class="progress-step"></div>
          <div class="progress-step"></div>
        </div>

        <h1>Create Your Group</h1>
        <p class="subtitle">
          This is your workspace where you'll manage your team and resources.
        </p>

        <div class="card">
          ${this.error ? html`<div class="error-message">${this.error}</div>` : ""}

          <form @submit=${this.handleSubmit}>
            <div class="form-group">
              <label>Group Name *</label>
              <input
                type="text"
                placeholder="Acme Inc."
                .value=${this.groupName}
                @input=${this.handleNameInput}
                ?disabled=${this.creating}
                required
              />
            </div>

            <div class="form-group">
              <label>URL Slug *</label>
              <input
                type="text"
                placeholder="acme-inc"
                pattern="[a-z0-9-]+"
                .value=${this.slug}
                @input=${this.handleSlugInput}
                ?disabled=${this.creating}
                required
              />
              <div class="slug-preview">
                <span>Your URL:</span>
                <span class="url">${this.slug || "your-group"}.YOUR_DOMAIN</span>
                ${
                  this.slugStatus === "checking"
                    ? html`
                        <span class="slug-status checking">Checking...</span>
                      `
                    : this.slugStatus === "available"
                      ? html`
                          <span class="slug-status available">&#x2713; Available</span>
                        `
                      : this.slugStatus === "unavailable"
                        ? html`
                            <span class="slug-status unavailable">&#x2717; Taken</span>
                          `
                        : ""
                }
              </div>
            </div>

            <div class="form-group">
              <label>Description (optional)</label>
              <textarea
                placeholder="What is your group about?"
                .value=${this.description}
                @input=${(e: Event) => (this.description = (e.target as HTMLTextAreaElement).value)}
                ?disabled=${this.creating}
              ></textarea>
            </div>

            <div class="actions">
              <button type="button" class="btn btn-secondary" @click=${this.handleBack} ?disabled=${this.creating}>
                Back
              </button>
              <button
                type="submit"
                class="btn btn-primary"
                ?disabled=${this.creating || this.slugStatus === "unavailable" || !this.slug}
              >
                ${
                  this.creating
                    ? html`
                        <div class="spinner"></div>
                      `
                    : ""
                }
                ${this.creating ? "Creating..." : "Create Group"}
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
    "ocmt-onboarding-group": OnboardingGroupPage;
  }
}

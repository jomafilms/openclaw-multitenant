import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { toast } from "../components/toast.js";
import { api, User } from "../lib/api.js";

interface EmailRow {
  id: number;
  email: string;
  role: "member" | "admin";
}

@customElement("ocmt-onboarding-team")
export class OnboardingTeamPage extends LitElement {
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

    .group-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(79, 70, 229, 0.2);
      color: #818cf8;
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 0.85rem;
      margin-bottom: 24px;
    }

    .card {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      padding: 32px;
    }

    .email-row {
      display: flex;
      gap: 12px;
      margin-bottom: 12px;
      align-items: center;
    }

    .email-input {
      flex: 2;
    }

    .role-select {
      flex: 1;
    }

    input,
    select {
      width: 100%;
      padding: 12px 14px;
      border-radius: 8px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: rgba(255, 255, 255, 0.1);
      color: white;
      font-size: 0.95rem;
      box-sizing: border-box;
    }

    input::placeholder {
      color: #666;
    }

    input:focus,
    select:focus {
      outline: none;
      border-color: #4f46e5;
    }

    select option {
      background: #1a1a2e;
      color: white;
    }

    .remove-btn {
      background: rgba(239, 68, 68, 0.2);
      border: none;
      color: #ef4444;
      width: 36px;
      height: 36px;
      border-radius: 8px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .remove-btn:hover {
      background: rgba(239, 68, 68, 0.3);
    }

    .add-row-btn {
      background: none;
      border: 1px dashed rgba(255, 255, 255, 0.3);
      color: #888;
      padding: 12px;
      border-radius: 8px;
      cursor: pointer;
      width: 100%;
      font-size: 0.9rem;
      margin-top: 8px;
      transition: all 0.2s;
    }

    .add-row-btn:hover {
      border-color: #4f46e5;
      color: #818cf8;
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

    .skip-link {
      display: block;
      text-align: center;
      margin-top: 16px;
      color: #888;
      text-decoration: none;
      font-size: 0.9rem;
      cursor: pointer;
    }

    .skip-link:hover {
      color: white;
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

    .info-box {
      background: rgba(79, 70, 229, 0.1);
      border: 1px solid rgba(79, 70, 229, 0.2);
      padding: 16px;
      border-radius: 8px;
      margin-bottom: 24px;
      font-size: 0.9rem;
      color: #aaa;
    }

    .info-box strong {
      color: white;
    }
  `;

  @property({ type: Object })
  user: User | null = null;

  @state()
  private emailRows: EmailRow[] = [{ id: 1, email: "", role: "member" }];

  @state()
  private nextId = 2;

  @state()
  private sending = false;

  @state()
  private groupName = "";

  @state()
  private groupId = "";

  connectedCallback() {
    super.connectedCallback();
    // Get group info from session storage
    this.groupId = sessionStorage.getItem("onboarding_group_id") || "";
    this.groupName = sessionStorage.getItem("onboarding_group_name") || "your group";
  }

  private addRow() {
    this.emailRows = [...this.emailRows, { id: this.nextId++, email: "", role: "member" }];
  }

  private removeRow(id: number) {
    if (this.emailRows.length > 1) {
      this.emailRows = this.emailRows.filter((row) => row.id !== id);
    }
  }

  private updateEmail(id: number, email: string) {
    this.emailRows = this.emailRows.map((row) => (row.id === id ? { ...row, email } : row));
  }

  private updateRole(id: number, role: "member" | "admin") {
    this.emailRows = this.emailRows.map((row) => (row.id === id ? { ...row, role } : row));
  }

  private getValidEmails(): EmailRow[] {
    return this.emailRows.filter((row) => row.email && row.email.includes("@"));
  }

  private async handleSendInvites() {
    const validEmails = this.getValidEmails();

    if (validEmails.length === 0) {
      toast.error("Please enter at least one valid email address");
      return;
    }

    if (!this.groupId) {
      toast.error("Group not found. Please go back and create one.");
      return;
    }

    this.sending = true;

    try {
      let successCount = 0;
      let errorCount = 0;

      for (const row of validEmails) {
        try {
          await api.inviteToGroup(this.groupId, row.email, row.role);
          successCount++;
        } catch {
          errorCount++;
        }
      }

      if (successCount > 0) {
        toast.success(`Sent ${successCount} invite${successCount > 1 ? "s" : ""}`);
      }
      if (errorCount > 0) {
        toast.error(`Failed to send ${errorCount} invite${errorCount > 1 ? "s" : ""}`);
      }

      // Navigate to next step
      this.dispatchEvent(
        new CustomEvent("navigate", {
          detail: { page: "onboarding-agent" },
          bubbles: true,
          composed: true,
        }),
      );
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to send invites");
    }

    this.sending = false;
  }

  private handleSkip() {
    this.dispatchEvent(
      new CustomEvent("navigate", {
        detail: { page: "onboarding-agent" },
        bubbles: true,
        composed: true,
      }),
    );
  }

  private handleBack() {
    this.dispatchEvent(
      new CustomEvent("navigate", {
        detail: { page: "onboarding-group" },
        bubbles: true,
        composed: true,
      }),
    );
  }

  render() {
    const validEmails = this.getValidEmails();

    return html`
      <div class="container">
        <div class="progress">
          <div class="progress-step completed"></div>
          <div class="progress-step active"></div>
          <div class="progress-step"></div>
        </div>

        <h1>Invite Your Team</h1>
        <p class="subtitle">
          Add colleagues to collaborate in your group. You can always add more later.
        </p>

        <div style="text-align: center;">
          <span class="group-badge">
            &#x1F3E2; ${this.groupName}
          </span>
        </div>

        <div class="card">
          <div class="info-box">
            <strong>Team members</strong> can access shared resources and collaborate.
            <strong>Admins</strong> can also invite others and manage settings.
          </div>

          ${this.emailRows.map(
            (row) => html`
              <div class="email-row">
                <div class="email-input">
                  <input
                    type="email"
                    placeholder="colleague@example.com"
                    .value=${row.email}
                    @input=${(e: Event) => this.updateEmail(row.id, (e.target as HTMLInputElement).value)}
                    ?disabled=${this.sending}
                  />
                </div>
                <div class="role-select">
                  <select
                    .value=${row.role}
                    @change=${(e: Event) => this.updateRole(row.id, (e.target as HTMLSelectElement).value as "member" | "admin")}
                    ?disabled=${this.sending}
                  >
                    <option value="member">Member</option>
                    <option value="admin">Admin</option>
                  </select>
                </div>
                ${
                  this.emailRows.length > 1
                    ? html`
                      <button
                        class="remove-btn"
                        @click=${() => this.removeRow(row.id)}
                        ?disabled=${this.sending}
                        title="Remove"
                      >
                        &#x2715;
                      </button>
                    `
                    : html`
                        <div style="width: 36px"></div>
                      `
                }
              </div>
            `,
          )}

          <button class="add-row-btn" @click=${this.addRow} ?disabled=${this.sending}>
            + Add another email
          </button>

          <div class="actions">
            <button type="button" class="btn btn-secondary" @click=${this.handleBack} ?disabled=${this.sending}>
              Back
            </button>
            <button
              class="btn btn-primary"
              @click=${this.handleSendInvites}
              ?disabled=${this.sending || validEmails.length === 0}
            >
              ${
                this.sending
                  ? html`
                      <div class="spinner"></div>
                    `
                  : ""
              }
              ${
                this.sending
                  ? "Sending..."
                  : validEmails.length > 0
                    ? `Send ${validEmails.length} Invite${validEmails.length > 1 ? "s" : ""}`
                    : "Send Invites"
              }
            </button>
          </div>

          <a class="skip-link" @click=${this.handleSkip}>
            Skip for now - I'll invite people later
          </a>
        </div>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-onboarding-team": OnboardingTeamPage;
  }
}

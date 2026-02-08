import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { api, User, GroupResource } from "../lib/api.js";

@customElement("ocmt-group-resources")
export class GroupResourcesPage extends LitElement {
  static styles = css`
    :host {
      display: block;
      max-width: 900px;
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

    .section {
      margin-bottom: 40px;
    }

    .section h2 {
      font-size: 1.1rem;
      color: #888;
      margin-bottom: 16px;
      text-transform: uppercase;
      letter-spacing: 1px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .badge {
      background: rgba(79, 70, 229, 0.2);
      color: #818cf8;
      padding: 2px 8px;
      border-radius: 10px;
      font-size: 0.75rem;
      text-transform: none;
      letter-spacing: 0;
    }

    .resources-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .resource-card {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 20px;
      transition: all 0.2s;
    }

    .resource-card:hover {
      background: rgba(255, 255, 255, 0.08);
    }

    .resource-card.connected {
      border-color: rgba(34, 197, 94, 0.3);
    }

    .resource-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      margin-bottom: 12px;
    }

    .resource-info {
      flex: 1;
    }

    .resource-name {
      font-weight: 600;
      font-size: 1.1rem;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .resource-icon {
      font-size: 1.3rem;
    }

    .resource-group {
      font-size: 0.85rem;
      color: #888;
      margin-top: 4px;
    }

    .resource-description {
      color: #aaa;
      font-size: 0.9rem;
      margin-bottom: 12px;
    }

    .resource-permissions {
      display: flex;
      gap: 8px;
      margin-bottom: 16px;
    }

    .permission-badge {
      background: rgba(79, 70, 229, 0.15);
      color: #818cf8;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 0.8rem;
    }

    .resource-status {
      font-size: 0.85rem;
      color: #888;
    }

    .resource-status.connected {
      color: #22c55e;
    }

    .btn {
      padding: 10px 20px;
      border-radius: 8px;
      border: none;
      font-size: 0.9rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
      display: inline-flex;
      align-items: center;
      gap: 6px;
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

    .btn-danger {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
    }

    .btn-danger:hover {
      background: rgba(239, 68, 68, 0.3);
    }

    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .empty-state {
      text-align: center;
      padding: 40px;
      color: #888;
    }

    .empty-state-icon {
      font-size: 3rem;
      margin-bottom: 16px;
    }

    .empty-state h3 {
      color: white;
      margin-bottom: 8px;
    }

    .loading {
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 40px;
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

    .error-banner {
      background: rgba(239, 68, 68, 0.2);
      border: 1px solid rgba(239, 68, 68, 0.3);
      padding: 12px 16px;
      border-radius: 8px;
      color: #ef4444;
      margin-bottom: 24px;
    }

    .success-banner {
      background: rgba(34, 197, 94, 0.2);
      border: 1px solid rgba(34, 197, 94, 0.3);
      padding: 12px 16px;
      border-radius: 8px;
      color: #22c55e;
      margin-bottom: 24px;
    }
  `;

  @property({ type: Object })
  user: User | null = null;

  @state()
  private availableResources: GroupResource[] = [];

  @state()
  private connectedResources: GroupResource[] = [];

  @state()
  private loading = true;

  @state()
  private actionLoading: string | null = null;

  @state()
  private error = "";

  @state()
  private success = "";

  connectedCallback() {
    super.connectedCallback();
    this.loadResources();
  }

  private async loadResources() {
    this.loading = true;
    this.error = "";
    console.log("Loading resources...");

    try {
      const [available, connected] = await Promise.all([
        api.listAvailableResources(),
        api.listConnectedResources(),
      ]);
      console.log("Resources loaded:", {
        available: available.resources.length,
        connected: connected.resources.length,
      });

      this.availableResources = available.resources || [];
      this.connectedResources = connected.resources || [];
    } catch (err) {
      console.error("Failed to load resources:", err);
      this.error = err instanceof Error ? err.message : "Failed to load resources";
    }

    this.loading = false;
    console.log("Loading complete, loading:", this.loading);
  }

  private async handleConnect(resource: GroupResource) {
    this.actionLoading = resource.id;
    this.error = "";
    this.success = "";

    try {
      await api.connectResource(resource.id);
      this.success = `Connected to ${resource.resource_name}`;
      await this.loadResources();
    } catch (err) {
      this.error = err instanceof Error ? err.message : "Failed to connect";
    }

    this.actionLoading = null;
  }

  private async handleDisconnect(resource: GroupResource) {
    if (!confirm(`Disconnect from ${resource.resource_name}?`)) {
      return;
    }

    this.actionLoading = resource.id;
    this.error = "";
    this.success = "";

    try {
      await api.disconnectResource(resource.id);
      this.success = `Disconnected from ${resource.resource_name}`;
      await this.loadResources();
    } catch (err) {
      this.error = err instanceof Error ? err.message : "Failed to disconnect";
    }

    this.actionLoading = null;
  }

  private getResourceIcon(type: string): string {
    switch (type) {
      case "api":
        return "🔌";
      case "mcp_server":
        return "🖥️";
      case "webhook":
        return "🪝";
      default:
        return "📦";
    }
  }

  render() {
    if (this.loading) {
      return html`
        <div class="loading">
          <div class="spinner"></div>
        </div>
      `;
    }

    return html`
      <h1>Group Resources</h1>
      <p class="subtitle">Connect to shared resources from your groups</p>

      ${this.error ? html`<div class="error-banner">${this.error}</div>` : ""}
      ${this.success ? html`<div class="success-banner">${this.success}</div>` : ""}

      <div class="section">
        <h2>
          Connected
          <span class="badge">${this.connectedResources.length}</span>
        </h2>
        ${
          this.connectedResources.length > 0
            ? html`
          <div class="resources-list">
            ${this.connectedResources.map((resource) => this.renderConnectedResource(resource))}
          </div>
        `
            : html`
                <div class="empty-state">
                  <div class="empty-state-icon">🔗</div>
                  <h3>No connected resources</h3>
                  <p>Connect to available resources below to start using them</p>
                </div>
              `
        }
      </div>

      <div class="section">
        <h2>
          Available to Connect
          <span class="badge">${this.availableResources.length}</span>
        </h2>
        ${
          this.availableResources.length > 0
            ? html`
          <div class="resources-list">
            ${this.availableResources.map((resource) => this.renderAvailableResource(resource))}
          </div>
        `
            : html`
                <div class="empty-state">
                  <div class="empty-state-icon">📭</div>
                  <h3>No available resources</h3>
                  <p>Ask your group admin to grant you access to resources</p>
                </div>
              `
        }
      </div>
    `;
  }

  private renderConnectedResource(resource: GroupResource) {
    const isLoading = this.actionLoading === resource.id;

    return html`
      <div class="resource-card connected">
        <div class="resource-header">
          <div class="resource-info">
            <div class="resource-name">
              <span class="resource-icon">${this.getResourceIcon(resource.resource_type)}</span>
              ${resource.resource_name}
            </div>
            <div class="resource-group">${resource.group_name}</div>
          </div>
          <button
            class="btn btn-danger"
            @click=${() => this.handleDisconnect(resource)}
            ?disabled=${isLoading}
          >
            ${isLoading ? "Disconnecting..." : "Disconnect"}
          </button>
        </div>
        ${
          resource.resource_description
            ? html`
          <p class="resource-description">${resource.resource_description}</p>
        `
            : ""
        }
        <div class="resource-permissions">
          ${this.getPermissions(resource).map(
            (p) => html`
            <span class="permission-badge">${p}</span>
          `,
          )}
        </div>
        <div class="resource-status connected">
          Connected ${resource.connected_at ? this.formatDate(resource.connected_at) : ""}
        </div>
      </div>
    `;
  }

  private renderAvailableResource(resource: GroupResource) {
    const isLoading = this.actionLoading === resource.id;

    return html`
      <div class="resource-card">
        <div class="resource-header">
          <div class="resource-info">
            <div class="resource-name">
              <span class="resource-icon">${this.getResourceIcon(resource.resource_type)}</span>
              ${resource.resource_name}
            </div>
            <div class="resource-group">${resource.group_name}</div>
          </div>
          <button
            class="btn btn-primary"
            @click=${() => this.handleConnect(resource)}
            ?disabled=${isLoading}
          >
            ${isLoading ? "Connecting..." : "Connect"}
          </button>
        </div>
        ${
          resource.resource_description
            ? html`
          <p class="resource-description">${resource.resource_description}</p>
        `
            : ""
        }
        <div class="resource-permissions">
          ${this.getPermissions(resource).map(
            (p) => html`
            <span class="permission-badge">${p}</span>
          `,
          )}
        </div>
        <div class="resource-status">
          Granted by ${resource.group_name}
        </div>
      </div>
    `;
  }

  private getPermissions(resource: GroupResource): string[] {
    const perms = resource.permissions;
    if (!perms) {
      return [];
    }
    if (Array.isArray(perms)) {
      return perms;
    }
    if (typeof perms === "string") {
      return perms
        .split(",")
        .map((p) => p.trim())
        .filter(Boolean);
    }
    return [];
  }

  private formatDate(dateStr: string): string {
    const date = new Date(dateStr);
    return date.toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-group-resources": GroupResourcesPage;
  }
}

import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import type { ShareableResource } from "../components/share-resource-modal.js";
import { toast } from "../components/toast.js";
import {
  api,
  User,
  PeerGrant,
  SharedResourceInfo,
  ReceivedShareInfo,
  ShareableResourceInfo,
} from "../lib/api.js";
// Import new sharing components
import "../components/share-resource-modal.js";
import "../components/shared-resources-list.js";
import "../components/received-shares-list.js";
import "../components/sharing-notifications.js";

@customElement("ocmt-sharing")
export class SharingPage extends LitElement {
  static styles = css`
    :host {
      display: block;
      max-width: 900px;
      margin: 0 auto;
    }

    .page-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      margin-bottom: 32px;
      flex-wrap: wrap;
      gap: 16px;
    }

    .page-header-content {
      flex: 1;
      min-width: 200px;
    }

    h1 {
      font-size: 1.8rem;
      margin-bottom: 8px;
    }

    .subtitle {
      color: #888;
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

    .badge.pending {
      background: rgba(245, 158, 11, 0.2);
      color: #f59e0b;
    }

    .grants-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .grant-card {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 20px;
      transition: all 0.2s;
    }

    .grant-card:hover {
      background: rgba(255, 255, 255, 0.08);
    }

    .grant-card.pending {
      border-color: rgba(245, 158, 11, 0.3);
    }

    .grant-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      margin-bottom: 12px;
    }

    .grant-info {
      flex: 1;
    }

    .grant-user {
      font-weight: 600;
      font-size: 1.1rem;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .grant-email {
      font-size: 0.85rem;
      color: #888;
      margin-top: 4px;
    }

    .grant-capability {
      display: inline-block;
      background: rgba(79, 70, 229, 0.15);
      color: #818cf8;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 0.85rem;
      margin-top: 8px;
    }

    .grant-reason {
      color: #aaa;
      font-size: 0.9rem;
      margin-top: 8px;
      font-style: italic;
    }

    .grant-expiry {
      font-size: 0.85rem;
      color: #888;
      margin-top: 8px;
    }

    .grant-expiry.expiring-soon {
      color: #f59e0b;
    }

    .grant-actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }

    .btn {
      padding: 10px 16px;
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

    .btn-success {
      background: rgba(34, 197, 94, 0.2);
      color: #22c55e;
    }

    .btn-success:hover {
      background: rgba(34, 197, 94, 0.3);
    }

    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .btn-small {
      padding: 6px 12px;
      font-size: 0.8rem;
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

    .request-form {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
    }

    .request-form h3 {
      margin-bottom: 16px;
    }

    .form-row {
      display: flex;
      gap: 12px;
      margin-bottom: 12px;
    }

    .form-row input,
    .form-row select {
      flex: 1;
      padding: 12px;
      border-radius: 8px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: rgba(255, 255, 255, 0.1);
      color: white;
      font-size: 0.95rem;
    }

    .form-row input::placeholder {
      color: #666;
    }

    .form-row select option {
      background: #1a1a2e;
    }

    .duration-options {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }

    /* Share button dropdown */
    .share-dropdown {
      position: relative;
    }

    .share-menu {
      position: absolute;
      top: 100%;
      right: 0;
      margin-top: 8px;
      background: #1a1a2e;
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 8px;
      min-width: 280px;
      z-index: 100;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
      animation: fadeIn 0.15s ease-out;
    }

    @keyframes fadeIn {
      from {
        opacity: 0;
        transform: translateY(-8px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    .share-menu-item {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 12px 16px;
      border-radius: 8px;
      cursor: pointer;
      transition: background 0.2s;
    }

    .share-menu-item:hover {
      background: rgba(255, 255, 255, 0.08);
    }

    .share-menu-item-icon {
      font-size: 1.3rem;
    }

    .share-menu-item-info {
      flex: 1;
    }

    .share-menu-item-name {
      font-weight: 500;
      margin-bottom: 2px;
    }

    .share-menu-item-type {
      font-size: 0.8rem;
      color: #888;
    }

    .share-menu-empty {
      padding: 16px;
      text-align: center;
      color: #888;
      font-size: 0.9rem;
    }

    .share-menu-loading {
      padding: 16px;
      display: flex;
      justify-content: center;
    }

    /* Tabs */
    .tabs {
      display: flex;
      gap: 4px;
      margin-bottom: 24px;
      background: rgba(255, 255, 255, 0.05);
      padding: 4px;
      border-radius: 10px;
      width: fit-content;
    }

    .tab {
      padding: 10px 20px;
      border: none;
      background: transparent;
      color: #888;
      font-size: 0.95rem;
      font-weight: 500;
      cursor: pointer;
      border-radius: 8px;
      transition: all 0.2s;
    }

    .tab:hover {
      color: #ccc;
    }

    .tab.active {
      background: rgba(79, 70, 229, 0.2);
      color: #818cf8;
    }

    @media (max-width: 600px) {
      .page-header {
        flex-direction: column;
      }

      .tabs {
        width: 100%;
      }

      .tab {
        flex: 1;
        text-align: center;
        padding: 12px 8px;
        font-size: 0.85rem;
      }

      .share-menu {
        left: 0;
        right: auto;
        max-width: calc(100vw - 32px);
      }
    }
  `;

  @property({ type: Object })
  user: User | null = null;

  // Legacy peer grants (for backward compatibility)
  @state()
  private incomingRequests: PeerGrant[] = [];

  @state()
  private outgoingRequests: PeerGrant[] = [];

  @state()
  private grantsToMe: PeerGrant[] = [];

  @state()
  private grantsFromMe: PeerGrant[] = [];

  // New resource sharing
  @state()
  private myShares: SharedResourceInfo[] = [];

  @state()
  private receivedShares: ReceivedShareInfo[] = [];

  @state()
  private shareableResources: ShareableResourceInfo[] = [];

  @state()
  private loading = true;

  @state()
  private actionLoading: string | null = null;

  @state()
  private requestEmail = "";

  @state()
  private requestCapability = "calendar:freebusy";

  @state()
  private requestReason = "";

  // UI state
  @state()
  private activeTab: "overview" | "shared" | "received" = "overview";

  @state()
  private showShareMenu = false;

  @state()
  private showShareModal = false;

  @state()
  private selectedResource: ShareableResource | null = null;

  @state()
  private shareableLoading = false;

  connectedCallback() {
    super.connectedCallback();
    this.loadData();

    // Close share menu on outside click
    document.addEventListener("click", this.handleOutsideClick);
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    document.removeEventListener("click", this.handleOutsideClick);
  }

  private handleOutsideClick = (e: Event) => {
    const target = e.target as HTMLElement;
    if (!target.closest(".share-dropdown")) {
      this.showShareMenu = false;
    }
  };

  private async loadData() {
    this.loading = true;

    try {
      // Load both legacy peer grants and new resource shares in parallel
      const [incoming, outgoing, toMe, fromMe, mySharesResult, receivedResult] = await Promise.all([
        api.listIncomingRequests().catch(() => ({ requests: [] })),
        api.listOutgoingRequests().catch(() => ({ requests: [] })),
        api.listGrantsToMe().catch(() => ({ grants: [] })),
        api.listGrantsFromMe().catch(() => ({ grants: [] })),
        api.listMyShares().catch(() => ({ shares: [] })),
        api.listReceivedShares().catch(() => ({ shares: [] })),
      ]);

      this.incomingRequests = incoming.requests;
      this.outgoingRequests = outgoing.requests;
      this.grantsToMe = toMe.grants;
      this.grantsFromMe = fromMe.grants;
      this.myShares = mySharesResult.shares;
      this.receivedShares = receivedResult.shares;
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to load sharing data");
    }

    this.loading = false;
  }

  private async loadShareableResources() {
    if (this.shareableResources.length > 0) {
      return;
    }

    this.shareableLoading = true;
    try {
      const result = await api.listShareableResources();
      this.shareableResources = result.resources;
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to load resources");
    }
    this.shareableLoading = false;
  }

  private handleShareButtonClick(e: Event) {
    e.stopPropagation();
    this.showShareMenu = !this.showShareMenu;
    if (this.showShareMenu) {
      this.loadShareableResources();
    }
  }

  private handleSelectResource(resource: ShareableResourceInfo) {
    this.selectedResource = {
      id: resource.id,
      name: resource.name,
      type: resource.type,
      icon: resource.icon,
    };
    this.showShareMenu = false;
    this.showShareModal = true;
  }

  private handleShareModalClose() {
    this.showShareModal = false;
    this.selectedResource = null;
  }

  private async handleShareComplete() {
    this.showShareModal = false;
    this.selectedResource = null;
    await this.loadData();
  }

  private async handleShareRevoked() {
    await this.loadData();
  }

  private async handleShareAccepted() {
    await this.loadData();
  }

  private async handleCreateRequest(e: Event) {
    e.preventDefault();
    this.actionLoading = "create";

    try {
      await api.createPeerRequest(
        this.requestEmail,
        this.requestCapability,
        this.requestReason || undefined,
      );
      toast.success(`Access request sent to ${this.requestEmail}`);
      this.requestEmail = "";
      this.requestReason = "";
      await this.loadData();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to send request");
    }

    this.actionLoading = null;
  }

  private async handleApprove(grant: PeerGrant, duration: "day" | "week" | "month" | "always") {
    this.actionLoading = grant.id;

    try {
      await api.approvePeerRequest(grant.id, duration);
      toast.success(`Approved access for ${grant.grantee_name}`);
      await this.loadData();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to approve");
    }

    this.actionLoading = null;
  }

  private async handleDeny(grant: PeerGrant) {
    this.actionLoading = grant.id;

    try {
      await api.denyPeerRequest(grant.id);
      toast.success(`Denied access for ${grant.grantee_name}`);
      await this.loadData();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to deny");
    }

    this.actionLoading = null;
  }

  private async handleRevoke(grant: PeerGrant) {
    if (!confirm(`Revoke ${grant.grantee_name}'s access to ${grant.capability}?`)) {
      return;
    }

    this.actionLoading = grant.id;

    try {
      await api.revokePeerGrant(grant.id);
      toast.success(`Revoked access for ${grant.grantee_name}`);
      await this.loadData();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to revoke");
    }

    this.actionLoading = null;
  }

  private formatExpiry(expiresAt: string | undefined): string {
    if (!expiresAt) {
      return "No expiry";
    }
    const date = new Date(expiresAt);
    const now = new Date();
    const diff = date.getTime() - now.getTime();
    const days = Math.ceil(diff / (1000 * 60 * 60 * 24));

    if (days < 0) {
      return "Expired";
    }
    if (days === 0) {
      return "Expires today";
    }
    if (days === 1) {
      return "Expires tomorrow";
    }
    if (days <= 7) {
      return `Expires in ${days} days`;
    }

    return `Expires ${date.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })}`;
  }

  private isExpiringSoon(expiresAt: string | undefined): boolean {
    if (!expiresAt) {
      return false;
    }
    const date = new Date(expiresAt);
    const now = new Date();
    const diff = date.getTime() - now.getTime();
    const days = Math.ceil(diff / (1000 * 60 * 60 * 24));
    return days >= 0 && days <= 3;
  }

  private getCapabilityIcon(capability: string): string {
    if (capability.includes("calendar")) {
      return "📅";
    }
    if (capability.includes("email") || capability.includes("gmail")) {
      return "📧";
    }
    if (capability.includes("drive") || capability.includes("file")) {
      return "📁";
    }
    if (capability.includes("profile")) {
      return "👤";
    }
    return "🔑";
  }

  private getResourceIcon(type: string): string {
    switch (type) {
      case "calendar":
        return "📅";
      case "email":
        return "📧";
      case "drive":
      case "files":
        return "📁";
      case "contacts":
        return "👥";
      case "api":
        return "🔌";
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

    // Calculate pending items for notifications
    const pendingReceivedShares = this.receivedShares.filter(
      (s) => s.status === "pending_approval",
    );

    return html`
      <div class="page-header">
        <div class="page-header-content">
          <h1>Sharing</h1>
          <p class="subtitle">Share your data with trusted contacts and see what others have shared with you</p>
        </div>
        <div class="share-dropdown">
          <button class="btn btn-primary" @click=${this.handleShareButtonClick}>
            + Share Resource
          </button>
          ${this.showShareMenu ? this.renderShareMenu() : ""}
        </div>
      </div>

      <!-- Notifications for pending items -->
      <sharing-notifications
        .pendingShares=${pendingReceivedShares}
        .pendingApprovals=${[]}
        @share-accepted=${this.handleShareAccepted}
        @share-declined=${() => this.loadData()}
      ></sharing-notifications>

      <!-- Tabs -->
      <div class="tabs">
        <button
          class="tab ${this.activeTab === "overview" ? "active" : ""}"
          @click=${() => (this.activeTab = "overview")}
        >
          Overview
        </button>
        <button
          class="tab ${this.activeTab === "shared" ? "active" : ""}"
          @click=${() => (this.activeTab = "shared")}
        >
          My Shares (${this.myShares.length + this.grantsFromMe.length})
        </button>
        <button
          class="tab ${this.activeTab === "received" ? "active" : ""}"
          @click=${() => (this.activeTab = "received")}
        >
          Shared With Me (${this.receivedShares.length + this.grantsToMe.length})
        </button>
      </div>

      ${this.activeTab === "overview" ? this.renderOverviewTab() : ""}
      ${this.activeTab === "shared" ? this.renderSharedTab() : ""}
      ${this.activeTab === "received" ? this.renderReceivedTab() : ""}

      <!-- Share Modal -->
      <share-resource-modal
        .open=${this.showShareModal}
        .resource=${this.selectedResource}
        @close=${this.handleShareModalClose}
        @shared=${this.handleShareComplete}
      ></share-resource-modal>
    `;
  }

  private renderShareMenu() {
    return html`
      <div class="share-menu">
        ${
          this.shareableLoading
            ? html`
                <div class="share-menu-loading">
                  <div class="spinner"></div>
                </div>
              `
            : this.shareableResources.length === 0
              ? html`
                  <div class="share-menu-empty">No resources available to share. Connect integrations first.</div>
                `
              : html`
          ${this.shareableResources.map(
            (resource) => html`
            <div class="share-menu-item" @click=${() => this.handleSelectResource(resource)}>
              <span class="share-menu-item-icon">${resource.icon || this.getResourceIcon(resource.type)}</span>
              <div class="share-menu-item-info">
                <div class="share-menu-item-name">${resource.name}</div>
                <div class="share-menu-item-type">${resource.sourceName || resource.type}</div>
              </div>
            </div>
          `,
          )}
        `
        }
      </div>
    `;
  }

  private renderOverviewTab() {
    return html`
      ${this.renderRequestForm()}

      ${this.incomingRequests.length > 0 ? this.renderIncomingRequests() : ""}

      <!-- Quick summary sections -->
      <div class="section">
        <h2>
          What I've Shared
          <span class="badge">${this.myShares.length + this.grantsFromMe.length}</span>
        </h2>
        ${
          this.myShares.length > 0 || this.grantsFromMe.length > 0
            ? html`
          <div class="grants-list">
            ${this.grantsFromMe.slice(0, 3).map((grant) => this.renderGrantFromMe(grant))}
          </div>
          ${
            this.myShares.length + this.grantsFromMe.length > 3
              ? html`
            <button class="btn btn-secondary" style="margin-top: 16px;" @click=${() => (this.activeTab = "shared")}>
              View all shares
            </button>
          `
              : ""
          }
        `
            : html`
                <div class="empty-state">
                  <div class="empty-state-icon">🔒</div>
                  <h3>No active shares</h3>
                  <p>Click "Share Resource" to share your data with trusted contacts</p>
                </div>
              `
        }
      </div>

      <div class="section">
        <h2>
          What I Can Access
          <span class="badge">${this.receivedShares.length + this.grantsToMe.length}</span>
        </h2>
        ${
          this.receivedShares.length > 0 || this.grantsToMe.length > 0
            ? html`
          <div class="grants-list">
            ${this.grantsToMe.slice(0, 3).map((grant) => this.renderGrantToMe(grant))}
          </div>
          ${
            this.receivedShares.length + this.grantsToMe.length > 3
              ? html`
            <button class="btn btn-secondary" style="margin-top: 16px;" @click=${() => (this.activeTab = "received")}>
              View all access
            </button>
          `
              : ""
          }
        `
            : html`
                <div class="empty-state">
                  <div class="empty-state-icon">🔗</div>
                  <h3>No access granted</h3>
                  <p>When others share resources with you, they'll appear here</p>
                </div>
              `
        }
      </div>

      ${this.outgoingRequests.length > 0 ? this.renderOutgoingRequests() : ""}
    `;
  }

  private renderSharedTab() {
    // Convert legacy grants to the new format for display
    const legacyAsShared: SharedResourceInfo[] = this.grantsFromMe.map((g) => ({
      id: g.id,
      resourceId: g.id,
      resourceName: g.capability,
      resourceType: this.guessResourceType(g.capability),
      recipientId: g.grantee_id || "",
      recipientName: g.grantee_name || "Unknown",
      recipientEmail: g.grantee_email || "",
      tier: "LIVE" as const,
      permissions: ["read"],
      status: "active" as const,
      expiresAt: g.expires_at,
      createdAt: g.created_at,
    }));

    const allShares = [...this.myShares, ...legacyAsShared];

    return html`
      <shared-resources-list
        .shares=${allShares}
        @share-revoked=${this.handleShareRevoked}
      ></shared-resources-list>
    `;
  }

  private renderReceivedTab() {
    // Convert legacy grants to the new format for display
    const legacyAsReceived: ReceivedShareInfo[] = this.grantsToMe.map((g) => ({
      id: g.id,
      resourceId: g.id,
      resourceName: g.capability,
      resourceType: this.guessResourceType(g.capability),
      ownerId: g.grantor_id || "",
      ownerName: g.grantor_name || "Unknown",
      ownerEmail: g.grantor_email || "",
      tier: "LIVE" as const,
      permissions: ["read"],
      status: "active" as const,
      ownerOnline: true,
      sharedAt: g.created_at,
      expiresAt: g.expires_at,
    }));

    const allReceived = [...this.receivedShares, ...legacyAsReceived];

    return html`
      <received-shares-list
        .shares=${allReceived}
        @share-accepted=${this.handleShareAccepted}
        @share-declined=${() => this.loadData()}
      ></received-shares-list>
    `;
  }

  private guessResourceType(capability: string): string {
    if (capability.includes("calendar")) {
      return "calendar";
    }
    if (capability.includes("email") || capability.includes("gmail")) {
      return "email";
    }
    if (capability.includes("drive") || capability.includes("file")) {
      return "files";
    }
    if (capability.includes("contact")) {
      return "contacts";
    }
    return "api";
  }

  private renderRequestForm() {
    return html`
      <div class="request-form">
        <h3>Need to share or request access?</h3>
        <p style="color: #aaa; margin-bottom: 16px">Your agent can help you manage sharing. Just ask:</p>
        <div style="display: flex; flex-direction: column; gap: 8px; color: #888; font-style: italic">
          <span>"Share my calendar with bob@example.com"</span>
          <span>"Request access to Alice's calendar"</span>
          <span>"Show me who has access to my data"</span>
        </div>
      </div>
    `;
  }

  private renderIncomingRequests() {
    return html`
      <div class="section">
        <h2>
          Pending Requests
          <span class="badge pending">${this.incomingRequests.length}</span>
        </h2>
        <div class="grants-list">
          ${this.incomingRequests.map((grant) => this.renderIncomingRequest(grant))}
        </div>
      </div>
    `;
  }

  private renderIncomingRequest(grant: PeerGrant) {
    const isLoading = this.actionLoading === grant.id;

    return html`
      <div class="grant-card pending">
        <div class="grant-header">
          <div class="grant-info">
            <div class="grant-user">
              ${grant.grantee_name} wants access
            </div>
            <div class="grant-email">${grant.grantee_email}</div>
            <span class="grant-capability">
              ${this.getCapabilityIcon(grant.capability)} ${grant.capability}
            </span>
            ${
              grant.reason
                ? html`
              <div class="grant-reason">"${grant.reason}"</div>
            `
                : ""
            }
          </div>
        </div>
        <div class="grant-actions">
          <div class="duration-options">
            <button
              class="btn btn-success btn-small"
              @click=${() => this.handleApprove(grant, "day")}
              ?disabled=${isLoading}
            >
              1 Day
            </button>
            <button
              class="btn btn-success btn-small"
              @click=${() => this.handleApprove(grant, "week")}
              ?disabled=${isLoading}
            >
              1 Week
            </button>
            <button
              class="btn btn-success btn-small"
              @click=${() => this.handleApprove(grant, "month")}
              ?disabled=${isLoading}
            >
              1 Month
            </button>
            <button
              class="btn btn-success btn-small"
              @click=${() => this.handleApprove(grant, "always")}
              ?disabled=${isLoading}
            >
              Always
            </button>
          </div>
          <button
            class="btn btn-danger btn-small"
            @click=${() => this.handleDeny(grant)}
            ?disabled=${isLoading}
          >
            Deny
          </button>
        </div>
      </div>
    `;
  }

  private renderGrantFromMe(grant: PeerGrant) {
    const isLoading = this.actionLoading === grant.id;
    const expiringSoon = this.isExpiringSoon(grant.expires_at);

    return html`
      <div class="grant-card">
        <div class="grant-header">
          <div class="grant-info">
            <div class="grant-user">
              ${grant.grantee_name}
            </div>
            <div class="grant-email">${grant.grantee_email}</div>
            <span class="grant-capability">
              ${this.getCapabilityIcon(grant.capability)} ${grant.capability}
            </span>
            <div class="grant-expiry ${expiringSoon ? "expiring-soon" : ""}">
              ${this.formatExpiry(grant.expires_at)}
            </div>
          </div>
          <button
            class="btn btn-danger"
            @click=${() => this.handleRevoke(grant)}
            ?disabled=${isLoading}
          >
            ${isLoading ? "Revoking..." : "Revoke"}
          </button>
        </div>
      </div>
    `;
  }

  private renderGrantToMe(grant: PeerGrant) {
    const expiringSoon = this.isExpiringSoon(grant.expires_at);

    return html`
      <div class="grant-card">
        <div class="grant-header">
          <div class="grant-info">
            <div class="grant-user">
              ${grant.grantor_name}
            </div>
            <div class="grant-email">${grant.grantor_email}</div>
            <span class="grant-capability">
              ${this.getCapabilityIcon(grant.capability)} ${grant.capability}
            </span>
            <div class="grant-expiry ${expiringSoon ? "expiring-soon" : ""}">
              ${this.formatExpiry(grant.expires_at)}
            </div>
          </div>
        </div>
      </div>
    `;
  }

  private renderOutgoingRequests() {
    return html`
      <div class="section">
        <h2>
          My Pending Requests
          <span class="badge pending">${this.outgoingRequests.length}</span>
        </h2>
        <div class="grants-list">
          ${this.outgoingRequests.map(
            (grant) => html`
            <div class="grant-card pending">
              <div class="grant-header">
                <div class="grant-info">
                  <div class="grant-user">
                    Waiting for ${grant.grantor_name}
                  </div>
                  <div class="grant-email">${grant.grantor_email}</div>
                  <span class="grant-capability">
                    ${this.getCapabilityIcon(grant.capability)} ${grant.capability}
                  </span>
                </div>
                <span class="badge pending">Pending</span>
              </div>
            </div>
          `,
          )}
        </div>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-sharing": SharingPage;
  }
}

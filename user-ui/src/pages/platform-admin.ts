/**
 * Platform Admin Dashboard
 *
 * Provides platform-wide admin UI for managing:
 * - Tenants (organizations/workspaces)
 * - Users across all tenants
 * - Containers and resources
 * - Platform metrics and health
 *
 * Only accessible to users with is_platform_admin flag
 */
import { LitElement, html, css, TemplateResult } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { toast } from "../components/toast.js";
import {
  api,
  User,
  PlatformStats,
  TenantInfo,
  TenantDetails,
  PlatformUserInfo,
  ContainerInfo,
} from "../lib/api.js";

type Tab = "overview" | "tenants" | "users" | "containers" | "metrics";

@customElement("ocmt-platform-admin")
export class PlatformAdminPage extends LitElement {
  static styles = css`
    :host {
      display: block;
      max-width: 1400px;
      margin: 0 auto;
    }

    h1 {
      font-size: 1.8rem;
      margin-bottom: 8px;
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .subtitle {
      color: #888;
      margin-bottom: 24px;
    }

    .platform-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 12px;
      background: rgba(168, 85, 247, 0.2);
      border: 1px solid rgba(168, 85, 247, 0.3);
      border-radius: 6px;
      color: #a855f7;
      font-size: 0.85rem;
      font-weight: 500;
    }

    .impersonation-banner {
      background: rgba(251, 191, 36, 0.2);
      border: 1px solid rgba(251, 191, 36, 0.4);
      padding: 12px 16px;
      border-radius: 8px;
      margin-bottom: 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .impersonation-banner-text {
      color: #fbbf24;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    /* Tabs */
    .tabs {
      display: flex;
      gap: 4px;
      margin-bottom: 24px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
      padding-bottom: 0;
    }

    .tab {
      padding: 12px 20px;
      border: none;
      background: none;
      color: #888;
      font-size: 0.95rem;
      font-weight: 500;
      cursor: pointer;
      border-bottom: 2px solid transparent;
      margin-bottom: -1px;
      transition: all 0.2s;
    }

    .tab:hover {
      color: #ccc;
    }

    .tab.active {
      color: #a855f7;
      border-bottom-color: #a855f7;
    }

    .tab-badge {
      background: rgba(168, 85, 247, 0.2);
      color: #a855f7;
      padding: 2px 8px;
      border-radius: 10px;
      font-size: 0.75rem;
      margin-left: 6px;
    }

    /* Stats Grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }

    .stat-card {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 20px;
    }

    .stat-value {
      font-size: 2rem;
      font-weight: 700;
      color: white;
      margin-bottom: 4px;
    }

    .stat-label {
      color: #888;
      font-size: 0.9rem;
    }

    .stat-card.primary .stat-value {
      color: #a855f7;
    }

    .stat-card.success .stat-value {
      color: #22c55e;
    }

    .stat-card.warning .stat-value {
      color: #fbbf24;
    }

    .stat-card.info .stat-value {
      color: #3b82f6;
    }

    /* Section */
    .section {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
    }

    .section-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 20px;
    }

    .section-title {
      font-size: 1.2rem;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .section-icon {
      font-size: 1.3rem;
    }

    /* Search and Filter Bar */
    .filter-bar {
      display: flex;
      gap: 12px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }

    .search-input {
      flex: 1;
      min-width: 200px;
      padding: 10px 14px;
      border-radius: 8px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: rgba(255, 255, 255, 0.05);
      color: white;
      font-size: 0.95rem;
    }

    .search-input:focus {
      outline: none;
      border-color: #a855f7;
    }

    .search-input::placeholder {
      color: #666;
    }

    .filter-select {
      padding: 10px 14px;
      border-radius: 8px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: rgba(255, 255, 255, 0.05);
      color: white;
      font-size: 0.95rem;
      cursor: pointer;
    }

    .filter-select:focus {
      outline: none;
      border-color: #a855f7;
    }

    .filter-select option {
      background: #1a1a2e;
    }

    /* Data Table */
    .data-table {
      width: 100%;
      border-collapse: collapse;
    }

    .data-table th {
      text-align: left;
      padding: 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
      color: #888;
      font-weight: 500;
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .data-table td {
      padding: 14px 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      vertical-align: middle;
    }

    .data-table tr:hover td {
      background: rgba(255, 255, 255, 0.02);
    }

    .data-table .mono {
      font-family: monospace;
      font-size: 0.9rem;
      color: #a5b4fc;
    }

    /* Status Badges */
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 4px 10px;
      border-radius: 12px;
      font-size: 0.8rem;
      font-weight: 500;
    }

    .status-badge.active,
    .status-badge.running {
      background: rgba(34, 197, 94, 0.2);
      color: #22c55e;
    }

    .status-badge.pending {
      background: rgba(251, 191, 36, 0.2);
      color: #fbbf24;
    }

    .status-badge.suspended,
    .status-badge.paused {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
    }

    .status-badge.disabled,
    .status-badge.stopped {
      background: rgba(100, 100, 100, 0.3);
      color: #888;
    }

    .status-badge.error {
      background: rgba(239, 68, 68, 0.3);
      color: #ef4444;
    }

    /* Plan Badge */
    .plan-badge {
      display: inline-flex;
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
    }

    .plan-badge.free {
      background: rgba(100, 100, 100, 0.3);
      color: #888;
    }

    .plan-badge.starter {
      background: rgba(59, 130, 246, 0.2);
      color: #3b82f6;
    }

    .plan-badge.pro {
      background: rgba(168, 85, 247, 0.2);
      color: #a855f7;
    }

    .plan-badge.enterprise {
      background: rgba(251, 191, 36, 0.2);
      color: #fbbf24;
    }

    /* Buttons */
    .btn {
      padding: 8px 14px;
      border-radius: 6px;
      border: none;
      font-size: 0.85rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    .btn-primary {
      background: #a855f7;
      color: white;
    }

    .btn-primary:hover:not(:disabled) {
      background: #9333ea;
    }

    .btn-secondary {
      background: rgba(255, 255, 255, 0.1);
      color: #ccc;
    }

    .btn-secondary:hover:not(:disabled) {
      background: rgba(255, 255, 255, 0.15);
    }

    .btn-danger {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
    }

    .btn-danger:hover:not(:disabled) {
      background: rgba(239, 68, 68, 0.3);
    }

    .btn-warning {
      background: rgba(251, 191, 36, 0.2);
      color: #fbbf24;
    }

    .btn-warning:hover:not(:disabled) {
      background: rgba(251, 191, 36, 0.3);
    }

    .btn-success {
      background: rgba(34, 197, 94, 0.2);
      color: #22c55e;
    }

    .btn-success:hover:not(:disabled) {
      background: rgba(34, 197, 94, 0.3);
    }

    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .btn-sm {
      padding: 6px 10px;
      font-size: 0.8rem;
    }

    .action-buttons {
      display: flex;
      gap: 6px;
    }

    /* Loading and Empty States */
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
      border-top-color: #a855f7;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }

    @keyframes spin {
      to {
        transform: rotate(360deg);
      }
    }

    .empty-state {
      text-align: center;
      padding: 40px 20px;
      color: #888;
    }

    .empty-state-icon {
      font-size: 3rem;
      margin-bottom: 12px;
    }

    .empty-state h3 {
      color: white;
      margin-bottom: 8px;
    }

    /* Error */
    .error-banner {
      background: rgba(239, 68, 68, 0.2);
      border: 1px solid rgba(239, 68, 68, 0.3);
      padding: 12px 16px;
      border-radius: 8px;
      color: #ef4444;
      margin-bottom: 24px;
    }

    .access-denied {
      text-align: center;
      padding: 80px 20px;
    }

    .access-denied-icon {
      font-size: 4rem;
      margin-bottom: 20px;
    }

    .access-denied h2 {
      margin-bottom: 12px;
    }

    .access-denied p {
      color: #888;
    }

    /* Modal */
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.8);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      padding: 20px;
    }

    .modal {
      background: #1a1a2e;
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      padding: 24px;
      max-width: 600px;
      width: 100%;
      max-height: 80vh;
      overflow-y: auto;
    }

    .modal h3 {
      margin-bottom: 16px;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .modal-body {
      margin-bottom: 20px;
    }

    .modal-buttons {
      display: flex;
      gap: 12px;
      justify-content: flex-end;
    }

    .detail-row {
      display: flex;
      justify-content: space-between;
      padding: 10px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }

    .detail-label {
      color: #888;
    }

    .detail-value {
      color: white;
      font-weight: 500;
    }

    /* Charts placeholder */
    .chart-placeholder {
      background: rgba(255, 255, 255, 0.02);
      border: 1px dashed rgba(255, 255, 255, 0.1);
      border-radius: 8px;
      padding: 60px 20px;
      text-align: center;
      color: #666;
    }

    /* Subscription cards for overview */
    .subscription-cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 12px;
      margin-top: 16px;
    }

    .subscription-card {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 8px;
      padding: 16px;
      text-align: center;
    }

    .subscription-card-count {
      font-size: 1.5rem;
      font-weight: 700;
      margin-bottom: 4px;
    }

    .subscription-card-label {
      font-size: 0.85rem;
      color: #888;
      text-transform: capitalize;
    }

    /* Resource meters */
    .resource-meter {
      margin-top: 12px;
    }

    .resource-label {
      display: flex;
      justify-content: space-between;
      margin-bottom: 6px;
      font-size: 0.9rem;
    }

    .resource-bar {
      height: 8px;
      background: rgba(255, 255, 255, 0.1);
      border-radius: 4px;
      overflow: hidden;
    }

    .resource-bar-fill {
      height: 100%;
      background: #a855f7;
      border-radius: 4px;
      transition: width 0.3s;
    }

    .resource-bar-fill.warning {
      background: #fbbf24;
    }

    .resource-bar-fill.danger {
      background: #ef4444;
    }

    /* Responsive */
    @media (max-width: 768px) {
      h1 {
        font-size: 1.5rem;
        flex-direction: column;
        align-items: flex-start;
        gap: 8px;
      }

      .tabs {
        overflow-x: auto;
        padding-bottom: 4px;
      }

      .tab {
        padding: 10px 14px;
        white-space: nowrap;
      }

      .section {
        padding: 16px;
      }

      .filter-bar {
        flex-direction: column;
      }

      .data-table {
        display: block;
        overflow-x: auto;
      }

      .stats-grid {
        grid-template-columns: repeat(2, 1fr);
      }
    }
  `;

  @property({ type: Object })
  user: User | null = null;

  @state()
  private loading = true;

  @state()
  private isPlatformAdmin = false;

  @state()
  private error = "";

  @state()
  private activeTab: Tab = "overview";

  @state()
  private stats: PlatformStats | null = null;

  // Tenants state
  @state()
  private tenants: TenantInfo[] = [];

  @state()
  private tenantsTotal = 0;

  @state()
  private tenantSearch = "";

  @state()
  private tenantStatusFilter = "";

  @state()
  private selectedTenant: TenantDetails | null = null;

  @state()
  private showTenantModal = false;

  // Users state
  @state()
  private users: PlatformUserInfo[] = [];

  @state()
  private usersTotal = 0;

  @state()
  private userSearch = "";

  @state()
  private userStatusFilter = "";

  // Containers state
  @state()
  private containers: ContainerInfo[] = [];

  @state()
  private containersTotal = 0;

  @state()
  private containerStatusFilter = "";

  // Action state
  @state()
  private actionLoading = "";

  // Confirm dialog
  @state()
  private showConfirmDialog = false;

  @state()
  private confirmTitle = "";

  @state()
  private confirmMessage = "";

  @state()
  private confirmAction: (() => Promise<void>) | null = null;

  @state()
  private confirmDanger = false;

  async connectedCallback() {
    super.connectedCallback();
    await this.checkPlatformAdminAccess();
  }

  private async checkPlatformAdminAccess() {
    this.loading = true;
    this.error = "";

    try {
      const result = await api.checkPlatformAdminStatus();
      this.isPlatformAdmin = result.isPlatformAdmin;

      if (this.isPlatformAdmin) {
        await this.loadStats();
      }
    } catch (err) {
      console.error("Platform admin check failed:", err);
      this.isPlatformAdmin = false;
    }

    this.loading = false;
  }

  private async loadStats() {
    try {
      this.stats = await api.getPlatformStats();
    } catch (err) {
      console.error("Failed to load platform stats:", err);
      this.error = err instanceof Error ? err.message : "Failed to load stats";
    }
  }

  private async loadTenants() {
    try {
      const result = await api.listTenants({
        search: this.tenantSearch || undefined,
        status: this.tenantStatusFilter || undefined,
        limit: 50,
      });
      this.tenants = result.tenants;
      this.tenantsTotal = result.total;
    } catch (err) {
      console.error("Failed to load tenants:", err);
      toast.error("Failed to load tenants");
    }
  }

  private async loadUsers() {
    try {
      const result = await api.listAllUsers({
        search: this.userSearch || undefined,
        status: this.userStatusFilter || undefined,
        limit: 50,
      });
      this.users = result.users;
      this.usersTotal = result.total;
    } catch (err) {
      console.error("Failed to load users:", err);
      toast.error("Failed to load users");
    }
  }

  private async loadContainers() {
    try {
      const result = await api.listAllContainers({
        status: this.containerStatusFilter || undefined,
        limit: 50,
      });
      this.containers = result.containers;
      this.containersTotal = result.total;
    } catch (err) {
      console.error("Failed to load containers:", err);
      toast.error("Failed to load containers");
    }
  }

  private async handleTabChange(tab: Tab) {
    this.activeTab = tab;

    // Load data for the tab
    if (tab === "tenants" && this.tenants.length === 0) {
      await this.loadTenants();
    } else if (tab === "users" && this.users.length === 0) {
      await this.loadUsers();
    } else if (tab === "containers" && this.containers.length === 0) {
      await this.loadContainers();
    }
  }

  private async handleViewTenant(tenant: TenantInfo) {
    this.actionLoading = `view-${tenant.id}`;
    try {
      this.selectedTenant = await api.getTenantDetails(tenant.id);
      this.showTenantModal = true;
    } catch (err) {
      toast.error("Failed to load tenant details");
    }
    this.actionLoading = "";
  }

  private handleSuspendTenant(tenant: TenantInfo) {
    this.confirmTitle = "Suspend Tenant";
    this.confirmMessage = `Are you sure you want to suspend "${tenant.name}"? All users will lose access until unsuspended.`;
    this.confirmDanger = true;
    this.confirmAction = async () => {
      try {
        await api.suspendTenant(tenant.id);
        toast.success(`Tenant "${tenant.name}" suspended`);
        await this.loadTenants();
        await this.loadStats();
      } catch (err) {
        toast.error(err instanceof Error ? err.message : "Failed to suspend tenant");
      }
    };
    this.showConfirmDialog = true;
  }

  private handleUnsuspendTenant(tenant: TenantInfo) {
    this.confirmTitle = "Unsuspend Tenant";
    this.confirmMessage = `Restore access for "${tenant.name}"?`;
    this.confirmDanger = false;
    this.confirmAction = async () => {
      try {
        await api.unsuspendTenant(tenant.id);
        toast.success(`Tenant "${tenant.name}" unsuspended`);
        await this.loadTenants();
        await this.loadStats();
      } catch (err) {
        toast.error(err instanceof Error ? err.message : "Failed to unsuspend tenant");
      }
    };
    this.showConfirmDialog = true;
  }

  private async handleImpersonateUser(user: PlatformUserInfo) {
    this.confirmTitle = "Impersonate User";
    this.confirmMessage = `You will be logged in as "${user.name}" (${user.email}). You can return to your admin session at any time.`;
    this.confirmDanger = false;
    this.confirmAction = async () => {
      try {
        await api.impersonateUser(user.id);
        toast.success(`Now impersonating ${user.name}`);
        // Reload the page to reflect new session
        window.location.href = "/dashboard";
      } catch (err) {
        toast.error(err instanceof Error ? err.message : "Failed to impersonate user");
      }
    };
    this.showConfirmDialog = true;
  }

  private async handleStopImpersonation() {
    try {
      await api.stopImpersonation();
      toast.success("Returned to admin session");
      window.location.reload();
    } catch (err) {
      toast.error("Failed to stop impersonation");
    }
  }

  private async handleToggleUserStatus(user: PlatformUserInfo) {
    const newStatus = user.status === "active" ? "disabled" : "active";
    const action = newStatus === "disabled" ? "Disable" : "Enable";

    this.confirmTitle = `${action} User`;
    this.confirmMessage = `${action} user "${user.name}" (${user.email})?`;
    this.confirmDanger = newStatus === "disabled";
    this.confirmAction = async () => {
      try {
        await api.setUserStatus(user.id, newStatus);
        toast.success(`User ${newStatus === "disabled" ? "disabled" : "enabled"}`);
        await this.loadUsers();
      } catch (err) {
        toast.error(err instanceof Error ? err.message : `Failed to ${action.toLowerCase()} user`);
      }
    };
    this.showConfirmDialog = true;
  }

  private async handleRestartContainer(container: ContainerInfo) {
    this.actionLoading = `restart-${container.id}`;
    try {
      await api.restartContainer(container.id);
      toast.success("Container restarted");
      await this.loadContainers();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to restart container");
    }
    this.actionLoading = "";
  }

  private async handleStopContainer(container: ContainerInfo) {
    this.confirmTitle = "Stop Container";
    this.confirmMessage = `Stop the container for ${container.userName || container.userId}? The user will need to restart it.`;
    this.confirmDanger = true;
    this.confirmAction = async () => {
      try {
        await api.stopContainer(container.id);
        toast.success("Container stopped");
        await this.loadContainers();
      } catch (err) {
        toast.error(err instanceof Error ? err.message : "Failed to stop container");
      }
    };
    this.showConfirmDialog = true;
  }

  private closeConfirmDialog() {
    this.showConfirmDialog = false;
    this.confirmAction = null;
    this.confirmTitle = "";
    this.confirmMessage = "";
    this.confirmDanger = false;
  }

  private async executeConfirmedAction() {
    if (this.confirmAction) {
      await this.confirmAction();
    }
    this.closeConfirmDialog();
  }

  private formatDate(dateStr: string): string {
    return new Date(dateStr).toLocaleDateString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  }

  private formatDateTime(dateStr: string): string {
    return new Date(dateStr).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit",
    });
  }

  private formatRelativeTime(dateStr: string): string {
    const date = new Date(dateStr);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMinutes = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMinutes < 1) {
      return "Just now";
    }
    if (diffMinutes < 60) {
      return `${diffMinutes}m ago`;
    }
    if (diffHours < 24) {
      return `${diffHours}h ago`;
    }
    if (diffDays < 7) {
      return `${diffDays}d ago`;
    }
    return this.formatDate(dateStr);
  }

  render(): TemplateResult {
    if (this.loading) {
      return html`
        <div class="loading">
          <div class="spinner"></div>
        </div>
      `;
    }

    if (!this.isPlatformAdmin) {
      return html`
        <div class="access-denied">
          <div class="access-denied-icon">🔒</div>
          <h2>Access Denied</h2>
          <p>You do not have platform admin privileges to access this page.</p>
        </div>
      `;
    }

    return html`
      <h1>
        Platform Admin
        <span class="platform-badge">Platform Admin</span>
      </h1>
      <p class="subtitle">Manage tenants, users, and platform resources</p>

      ${api.isImpersonating() ? this.renderImpersonationBanner() : ""}
      ${this.error ? html`<div class="error-banner">${this.error}</div>` : ""}

      ${this.renderTabs()}

      <div class="tab-content">
        ${this.activeTab === "overview" ? this.renderOverview() : ""}
        ${this.activeTab === "tenants" ? this.renderTenantsTab() : ""}
        ${this.activeTab === "users" ? this.renderUsersTab() : ""}
        ${this.activeTab === "containers" ? this.renderContainersTab() : ""}
        ${this.activeTab === "metrics" ? this.renderMetricsTab() : ""}
      </div>

      ${this.showTenantModal ? this.renderTenantModal() : ""}
      ${this.showConfirmDialog ? this.renderConfirmDialog() : ""}
    `;
  }

  private renderImpersonationBanner(): TemplateResult {
    return html`
      <div class="impersonation-banner">
        <div class="impersonation-banner-text">
          <span>You are currently impersonating another user</span>
        </div>
        <button class="btn btn-warning" @click=${this.handleStopImpersonation}>
          Stop Impersonation
        </button>
      </div>
    `;
  }

  private renderTabs(): TemplateResult {
    return html`
      <div class="tabs">
        <button
          class="tab ${this.activeTab === "overview" ? "active" : ""}"
          @click=${() => this.handleTabChange("overview")}
        >
          Overview
        </button>
        <button
          class="tab ${this.activeTab === "tenants" ? "active" : ""}"
          @click=${() => this.handleTabChange("tenants")}
        >
          Tenants
          ${this.stats?.totalTenants ? html`<span class="tab-badge">${this.stats.totalTenants}</span>` : ""}
        </button>
        <button
          class="tab ${this.activeTab === "users" ? "active" : ""}"
          @click=${() => this.handleTabChange("users")}
        >
          Users
          ${this.stats?.totalUsers ? html`<span class="tab-badge">${this.stats.totalUsers}</span>` : ""}
        </button>
        <button
          class="tab ${this.activeTab === "containers" ? "active" : ""}"
          @click=${() => this.handleTabChange("containers")}
        >
          Containers
          ${this.stats?.runningContainers ? html`<span class="tab-badge">${this.stats.runningContainers}</span>` : ""}
        </button>
        <button
          class="tab ${this.activeTab === "metrics" ? "active" : ""}"
          @click=${() => this.handleTabChange("metrics")}
        >
          Metrics
        </button>
      </div>
    `;
  }

  private renderOverview(): TemplateResult {
    if (!this.stats) {
      return html`
        <div class="loading">
          <div class="spinner"></div>
        </div>
      `;
    }

    return html`
      <div class="stats-grid">
        <div class="stat-card primary">
          <div class="stat-value">${this.stats.totalTenants}</div>
          <div class="stat-label">Total Tenants</div>
        </div>
        <div class="stat-card success">
          <div class="stat-value">${this.stats.activeTenants}</div>
          <div class="stat-label">Active Tenants</div>
        </div>
        <div class="stat-card warning">
          <div class="stat-value">${this.stats.suspendedTenants}</div>
          <div class="stat-label">Suspended</div>
        </div>
        <div class="stat-card info">
          <div class="stat-value">${this.stats.totalUsers}</div>
          <div class="stat-label">Total Users</div>
        </div>
        <div class="stat-card success">
          <div class="stat-value">${this.stats.activeUsers}</div>
          <div class="stat-label">Active Users</div>
        </div>
        <div class="stat-card primary">
          <div class="stat-value">${this.stats.runningContainers}</div>
          <div class="stat-label">Running Containers</div>
        </div>
      </div>

      <div class="section">
        <div class="section-header">
          <div class="section-title">
            <span class="section-icon">💳</span>
            Subscriptions by Plan
          </div>
        </div>
        <div class="subscription-cards">
          ${Object.entries(this.stats.subscriptionsByPlan || {}).map(
            ([plan, count]) => html`
              <div class="subscription-card">
                <div class="subscription-card-count" style="color: ${this.getPlanColor(plan)}">${count}</div>
                <div class="subscription-card-label">${plan}</div>
              </div>
            `,
          )}
        </div>
      </div>

      <div class="section">
        <div class="section-header">
          <div class="section-title">
            <span class="section-icon">📊</span>
            Platform Health
          </div>
        </div>

        <div class="resource-meter">
          <div class="resource-label">
            <span>API Calls Today</span>
            <span>${this.stats.apiCallsToday.toLocaleString()}</span>
          </div>
          <div class="resource-bar">
            <div class="resource-bar-fill" style="width: ${Math.min(100, (this.stats.apiCallsToday / 100000) * 100)}%"></div>
          </div>
        </div>

        <div class="resource-meter">
          <div class="resource-label">
            <span>Storage Used</span>
            <span>${this.stats.storageUsedGB.toFixed(1)} GB</span>
          </div>
          <div class="resource-bar">
            <div
              class="resource-bar-fill ${this.stats.storageUsedGB > 80 ? "danger" : this.stats.storageUsedGB > 60 ? "warning" : ""}"
              style="width: ${Math.min(100, this.stats.storageUsedGB)}%"
            ></div>
          </div>
        </div>

        <div class="resource-meter">
          <div class="resource-label">
            <span>New Signups This Week</span>
            <span>${this.stats.newSignupsThisWeek}</span>
          </div>
          <div class="resource-bar">
            <div class="resource-bar-fill" style="width: ${Math.min(100, this.stats.newSignupsThisWeek * 2)}%"></div>
          </div>
        </div>
      </div>
    `;
  }

  private getPlanColor(plan: string): string {
    const colors: Record<string, string> = {
      free: "#888",
      starter: "#3b82f6",
      pro: "#a855f7",
      enterprise: "#fbbf24",
    };
    return colors[plan.toLowerCase()] || "#888";
  }

  private renderTenantsTab(): TemplateResult {
    return html`
      <div class="section">
        <div class="filter-bar">
          <input
            type="text"
            class="search-input"
            placeholder="Search tenants by name or slug..."
            .value=${this.tenantSearch}
            @input=${(e: Event) => {
              this.tenantSearch = (e.target as HTMLInputElement).value;
            }}
            @keyup=${(e: KeyboardEvent) => {
              if (e.key === "Enter") {
                this.loadTenants();
              }
            }}
          />
          <select
            class="filter-select"
            .value=${this.tenantStatusFilter}
            @change=${(e: Event) => {
              this.tenantStatusFilter = (e.target as HTMLSelectElement).value;
              this.loadTenants();
            }}
          >
            <option value="">All Status</option>
            <option value="active">Active</option>
            <option value="suspended">Suspended</option>
            <option value="deleted">Deleted</option>
          </select>
          <button class="btn btn-secondary" @click=${this.loadTenants}>Search</button>
        </div>

        ${
          this.tenants.length === 0
            ? html`
                <div class="empty-state">
                  <div class="empty-state-icon">🏢</div>
                  <h3>No tenants found</h3>
                  <p>Try adjusting your search or filters</p>
                </div>
              `
            : html`
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Slug</th>
                    <th>Owner</th>
                    <th>Users</th>
                    <th>Plan</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  ${this.tenants.map((tenant) => this.renderTenantRow(tenant))}
                </tbody>
              </table>
            `
        }
      </div>
    `;
  }

  private renderTenantRow(tenant: TenantInfo): TemplateResult {
    return html`
      <tr>
        <td><strong>${tenant.name}</strong></td>
        <td class="mono">${tenant.slug}</td>
        <td>
          <div>${tenant.ownerName}</div>
          <div style="font-size: 0.8rem; color: #888">${tenant.ownerEmail}</div>
        </td>
        <td>${tenant.userCount}</td>
        <td>
          <span class="plan-badge ${tenant.plan.toLowerCase()}">${tenant.plan}</span>
        </td>
        <td>
          <span class="status-badge ${tenant.status}">${tenant.status}</span>
        </td>
        <td>${this.formatDate(tenant.createdAt)}</td>
        <td>
          <div class="action-buttons">
            <button
              class="btn btn-sm btn-secondary"
              @click=${() => this.handleViewTenant(tenant)}
              ?disabled=${this.actionLoading === `view-${tenant.id}`}
            >
              View
            </button>
            ${
              tenant.status === "active"
                ? html`
                  <button class="btn btn-sm btn-warning" @click=${() => this.handleSuspendTenant(tenant)}>
                    Suspend
                  </button>
                `
                : tenant.status === "suspended"
                  ? html`
                    <button class="btn btn-sm btn-success" @click=${() => this.handleUnsuspendTenant(tenant)}>
                      Unsuspend
                    </button>
                  `
                  : ""
            }
          </div>
        </td>
      </tr>
    `;
  }

  private renderUsersTab(): TemplateResult {
    return html`
      <div class="section">
        <div class="filter-bar">
          <input
            type="text"
            class="search-input"
            placeholder="Search users by email or name..."
            .value=${this.userSearch}
            @input=${(e: Event) => {
              this.userSearch = (e.target as HTMLInputElement).value;
            }}
            @keyup=${(e: KeyboardEvent) => {
              if (e.key === "Enter") {
                this.loadUsers();
              }
            }}
          />
          <select
            class="filter-select"
            .value=${this.userStatusFilter}
            @change=${(e: Event) => {
              this.userStatusFilter = (e.target as HTMLSelectElement).value;
              this.loadUsers();
            }}
          >
            <option value="">All Status</option>
            <option value="active">Active</option>
            <option value="pending">Pending</option>
            <option value="disabled">Disabled</option>
          </select>
          <button class="btn btn-secondary" @click=${this.loadUsers}>Search</button>
        </div>

        ${
          this.users.length === 0
            ? html`
                <div class="empty-state">
                  <div class="empty-state-icon">👥</div>
                  <h3>No users found</h3>
                  <p>Try adjusting your search or filters</p>
                </div>
              `
            : html`
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Email</th>
                    <th>Name</th>
                    <th>Tenant</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Last Login</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  ${this.users.map((user) => this.renderUserRow(user))}
                </tbody>
              </table>
            `
        }
      </div>
    `;
  }

  private renderUserRow(user: PlatformUserInfo): TemplateResult {
    return html`
      <tr>
        <td class="mono">${user.email}</td>
        <td>${user.name}</td>
        <td>${user.tenantName || "-"}</td>
        <td>${user.role || "-"}</td>
        <td>
          <span class="status-badge ${user.status}">${user.status}</span>
        </td>
        <td>${user.lastLoginAt ? this.formatRelativeTime(user.lastLoginAt) : "Never"}</td>
        <td>
          <div class="action-buttons">
            <button class="btn btn-sm btn-primary" @click=${() => this.handleImpersonateUser(user)}>
              Impersonate
            </button>
            <button
              class="btn btn-sm ${user.status === "active" ? "btn-danger" : "btn-success"}"
              @click=${() => this.handleToggleUserStatus(user)}
            >
              ${user.status === "active" ? "Disable" : "Enable"}
            </button>
          </div>
        </td>
      </tr>
    `;
  }

  private renderContainersTab(): TemplateResult {
    return html`
      <div class="section">
        <div class="filter-bar">
          <select
            class="filter-select"
            .value=${this.containerStatusFilter}
            @change=${(e: Event) => {
              this.containerStatusFilter = (e.target as HTMLSelectElement).value;
              this.loadContainers();
            }}
          >
            <option value="">All Status</option>
            <option value="running">Running</option>
            <option value="paused">Paused</option>
            <option value="stopped">Stopped</option>
            <option value="error">Error</option>
          </select>
          <button class="btn btn-secondary" @click=${this.loadContainers}>Refresh</button>
        </div>

        ${
          this.containers.length === 0
            ? html`
                <div class="empty-state">
                  <div class="empty-state-icon">📦</div>
                  <h3>No containers found</h3>
                  <p>No containers match your filters</p>
                </div>
              `
            : html`
              <table class="data-table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Container ID</th>
                    <th>Status</th>
                    <th>Memory</th>
                    <th>CPU</th>
                    <th>Last Activity</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  ${this.containers.map((container) => this.renderContainerRow(container))}
                </tbody>
              </table>
            `
        }
      </div>
    `;
  }

  private renderContainerRow(container: ContainerInfo): TemplateResult {
    return html`
      <tr>
        <td>
          <div>${container.userName || "Unknown"}</div>
          <div style="font-size: 0.8rem; color: #888">${container.userEmail || container.userId}</div>
        </td>
        <td class="mono" style="font-size: 0.8rem">${container.containerId.substring(0, 12)}</td>
        <td>
          <span class="status-badge ${container.status}">${container.status}</span>
        </td>
        <td>${container.memoryUsageMB.toFixed(0)} MB</td>
        <td>${container.cpuPercent.toFixed(1)}%</td>
        <td>${container.lastActivityAt ? this.formatRelativeTime(container.lastActivityAt) : "-"}</td>
        <td>
          <div class="action-buttons">
            <button
              class="btn btn-sm btn-secondary"
              @click=${() => this.handleRestartContainer(container)}
              ?disabled=${this.actionLoading === `restart-${container.id}` || container.status === "stopped"}
            >
              ${this.actionLoading === `restart-${container.id}` ? "..." : "Restart"}
            </button>
            ${
              container.status === "running"
                ? html`
                  <button class="btn btn-sm btn-danger" @click=${() => this.handleStopContainer(container)}>
                    Stop
                  </button>
                `
                : ""
            }
          </div>
        </td>
      </tr>
    `;
  }

  private renderMetricsTab(): TemplateResult {
    return html`
      <div class="section">
        <div class="section-header">
          <div class="section-title">
            <span class="section-icon">📈</span>
            Platform Metrics
          </div>
        </div>

        <div class="chart-placeholder">
          <p>API Calls Over Time</p>
          <p style="font-size: 0.85rem; margin-top: 8px">Chart visualization coming soon</p>
        </div>
      </div>

      <div class="section">
        <div class="section-header">
          <div class="section-title">
            <span class="section-icon">💾</span>
            Storage Usage Trends
          </div>
        </div>

        <div class="chart-placeholder">
          <p>Storage Usage Over Time</p>
          <p style="font-size: 0.85rem; margin-top: 8px">Chart visualization coming soon</p>
        </div>
      </div>

      <div class="section">
        <div class="section-header">
          <div class="section-title">
            <span class="section-icon">👤</span>
            New Signups
          </div>
        </div>

        <div class="chart-placeholder">
          <p>New Signups Over Time</p>
          <p style="font-size: 0.85rem; margin-top: 8px">Chart visualization coming soon</p>
        </div>
      </div>
    `;
  }

  private renderTenantModal(): TemplateResult {
    if (!this.selectedTenant) {
      return html``;
    }

    const tenant = this.selectedTenant;

    return html`
      <div
        class="modal-overlay"
        @click=${(e: Event) => {
          if (e.target === e.currentTarget) {
            this.showTenantModal = false;
            this.selectedTenant = null;
          }
        }}
      >
        <div class="modal">
          <h3>
            <span class="section-icon">🏢</span>
            ${tenant.name}
          </h3>

          <div class="modal-body">
            <div class="detail-row">
              <span class="detail-label">Slug</span>
              <span class="detail-value mono">${tenant.slug}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Owner</span>
              <span class="detail-value">${tenant.ownerName} (${tenant.ownerEmail})</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Status</span>
              <span class="detail-value">
                <span class="status-badge ${tenant.status}">${tenant.status}</span>
              </span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Plan</span>
              <span class="detail-value">
                <span class="plan-badge ${tenant.plan.toLowerCase()}">${tenant.plan}</span>
              </span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Users</span>
              <span class="detail-value">${tenant.userCount}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Containers</span>
              <span class="detail-value">${tenant.containerCount}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Created</span>
              <span class="detail-value">${this.formatDateTime(tenant.createdAt)}</span>
            </div>
            ${
              tenant.usageStats
                ? html`
                  <div class="detail-row">
                    <span class="detail-label">API Calls</span>
                    <span class="detail-value">${tenant.usageStats.apiCalls.toLocaleString()}</span>
                  </div>
                  <div class="detail-row">
                    <span class="detail-label">Storage</span>
                    <span class="detail-value">${tenant.usageStats.storageUsedMB.toFixed(1)} MB</span>
                  </div>
                `
                : ""
            }
          </div>

          <div class="modal-buttons">
            <button
              class="btn btn-secondary"
              @click=${() => {
                this.showTenantModal = false;
                this.selectedTenant = null;
              }}
            >
              Close
            </button>
          </div>
        </div>
      </div>
    `;
  }

  private renderConfirmDialog(): TemplateResult {
    return html`
      <div class="modal-overlay" @click=${this.closeConfirmDialog}>
        <div class="modal" @click=${(e: Event) => e.stopPropagation()}>
          <h3>${this.confirmTitle}</h3>
          <div class="modal-body">
            <p style="color: #888; line-height: 1.6">${this.confirmMessage}</p>
          </div>
          <div class="modal-buttons">
            <button class="btn btn-secondary" @click=${this.closeConfirmDialog}>Cancel</button>
            <button
              class="btn ${this.confirmDanger ? "btn-danger" : "btn-primary"}"
              @click=${this.executeConfirmedAction}
            >
              Confirm
            </button>
          </div>
        </div>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-platform-admin": PlatformAdminPage;
  }
}

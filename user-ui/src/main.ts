import "./styles/global.css";
import { LitElement, html, css } from "lit";
import { customElement, state } from "lit/decorators.js";
import { api, User, VaultStatus } from "./lib/api.js";
// Import components
import "./components/toast.js";
import "./components/onboarding.js";
import "./components/vault-unlock-modal.js";
import "./components/share-resource-modal.js";
import "./components/shared-resources-list.js";
import "./components/received-shares-list.js";
import "./components/sharing-notifications.js";
// Import pages
import "./pages/login.js";
import "./pages/dashboard.js";
import "./pages/connections.js";
import "./pages/sharing.js";
import "./pages/activity.js";
import "./pages/vault-setup.js";
import "./pages/vault-recover.js";
import "./pages/vault-settings.js";
import "./pages/vault-unlock.js";
import "./pages/approvals.js";
import "./pages/approval-action.js";
// Groups (unified - replaces organizations)
import "./pages/groups.js";
import "./pages/group-invites.js";
import "./pages/group-resources.js";
// Billing
import "./pages/billing.js";
// Security
import "./pages/sessions.js";
import "./pages/admin-security.js";
// Platform Admin
import "./pages/platform-admin.js";
// MFA
import "./components/mfa-code-input.js";
import "./pages/mfa-setup.js";
import "./pages/mfa-verify.js";
// Onboarding
import "./pages/onboarding-welcome.js";
import "./pages/onboarding-group.js";
import "./pages/onboarding-team.js";
import "./pages/onboarding-agent.js";
import "./pages/onboarding-complete.js";

type Page =
  | "login"
  | "dashboard"
  | "connections"
  | "resources"
  | "sharing"
  | "activity"
  | "vault-setup"
  | "vault-recover"
  | "vault-settings"
  | "vault-unlock"
  | "approvals"
  | "approval-action"
  | "groups"
  | "group-invites"
  | "sessions"
  | "mfa-setup"
  | "mfa-verify"
  | "admin-security"
  | "billing"
  | "platform-admin"
  | "onboarding-welcome"
  | "onboarding-group"
  | "onboarding-team"
  | "onboarding-agent"
  | "onboarding-complete";

@customElement("ocmt-app")
export class OcmtApp extends LitElement {
  static styles = css`
    :host {
      display: block;
      min-height: 100vh;
    }

    .nav {
      background: rgba(255, 255, 255, 0.05);
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
      padding: 16px 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      position: relative;
    }

    .nav-brand {
      font-size: 1.25rem;
      font-weight: 700;
      color: white;
      text-decoration: none;
      display: flex;
      align-items: center;
      gap: 8px;
      z-index: 101;
    }

    .nav-links {
      display: flex;
      align-items: center;
      gap: 24px;
    }

    .nav-link {
      color: #888;
      text-decoration: none;
      font-weight: 500;
      transition: color 0.2s;
    }

    .nav-link:hover,
    .nav-link.active {
      color: white;
    }

    .nav-link-badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 18px;
      height: 18px;
      padding: 0 5px;
      margin-left: 6px;
      background: #ef4444;
      color: white;
      font-size: 0.7rem;
      font-weight: 600;
      border-radius: 9px;
    }

    .nav-user {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .nav-user-name {
      color: #888;
    }

    .nav-logout {
      background: none;
      border: none;
      color: #888;
      cursor: pointer;
      font-size: 0.9rem;
    }

    .nav-logout:hover {
      color: white;
    }

    .menu-toggle {
      display: none;
      background: none;
      border: none;
      color: white;
      font-size: 1.5rem;
      cursor: pointer;
      padding: 8px;
      z-index: 101;
    }

    main {
      padding: 40px 24px;
      max-width: 1200px;
      margin: 0 auto;
    }

    /* Mobile responsive navigation */
    @media (max-width: 768px) {
      .nav {
        padding: 12px 16px;
      }

      .menu-toggle {
        display: block;
      }

      .nav-links {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(15, 15, 26, 0.98);
        flex-direction: column;
        justify-content: center;
        gap: 32px;
        z-index: 100;
        opacity: 0;
        visibility: hidden;
        transition: all 0.3s;
      }

      .nav-links.open {
        opacity: 1;
        visibility: visible;
      }

      .nav-link {
        font-size: 1.25rem;
      }

      .nav-user {
        position: fixed;
        bottom: 32px;
        left: 0;
        right: 0;
        flex-direction: column;
        gap: 12px;
        z-index: 100;
        opacity: 0;
        visibility: hidden;
        transition: all 0.3s;
      }

      .nav-links.open ~ .nav-user,
      .nav-user.open {
        opacity: 1;
        visibility: visible;
      }

      .nav-user-name {
        font-size: 0.9rem;
      }

      .nav-logout {
        padding: 12px 24px;
        background: rgba(255, 255, 255, 0.1);
        border-radius: 8px;
      }

      main {
        padding: 24px 16px;
      }
    }

    @media (max-width: 480px) {
      .nav {
        padding: 10px 12px;
      }

      .nav-brand {
        font-size: 1.1rem;
      }

      main {
        padding: 16px 12px;
      }
    }
  `;

  @state()
  private currentPage: Page = "login";

  @state()
  private user: User | null = null;

  @state()
  private loading = true;

  @state()
  private menuOpen = false;

  @state()
  private vaultStatus: VaultStatus | null = null;

  @state()
  private showVaultUnlock = false;

  @state()
  private pendingApprovalCount = 0;

  @state()
  private sseEventSource: EventSource | null = null;

  @state()
  private pendingMfaToken = "";

  // Flag to prevent double magic link verification (race condition fix)
  private verifyingMagicLink = false;

  async connectedCallback() {
    super.connectedCallback();

    // Handle magic link verification immediately (before auth check)
    // This prevents the verify flow from being blocked by auth checks
    const params = new URLSearchParams(window.location.search);
    const verifyToken = params.get("token");
    if (window.location.pathname === "/verify" && verifyToken) {
      await this.verifyMagicLink(verifyToken);
      this.loading = false;
      return; // Skip rest of init - verifyMagicLink handles navigation
    }

    // Handle routing for non-verify pages
    this.handleRoute();
    window.addEventListener("popstate", () => this.handleRoute());

    // Auto-lock vault on browser close (if configured)
    window.addEventListener("beforeunload", this.handleBeforeUnload);

    // Set up vault session activity extension
    this.setupVaultSessionExtension();

    // Listen for vault unlock requests from components
    window.addEventListener("request-vault-unlock", () => {
      if (this.vaultStatus?.hasVault) {
        this.showVaultUnlock = true;
      }
    });

    // Listen for approval count changes
    window.addEventListener("approval-count-changed", ((e: CustomEvent) => {
      this.pendingApprovalCount = e.detail.count || 0;
    }) as EventListener);

    // Check if user is authenticated
    if (api.isAuthenticated()) {
      try {
        const { user } = await api.getMe();
        this.user = user;

        // Check vault status
        await this.checkVaultStatus();

        // Load initial approval count
        await this.loadPendingApprovalCount();

        // Set up SSE for real-time notifications
        this.setupSSENotifications();

        if (this.currentPage === "login") {
          this.navigateTo("dashboard");
        }
      } catch {
        // Session invalid, clear stale data and go to login
        console.log("Session invalid, clearing stale data");
        api.clearSession();
        this.user = null;
        this.currentPage = "login";
        window.history.replaceState({}, "", "/login");
      }
    } else {
      // No session token - ensure we're on login page if trying to access protected route
      const path = window.location.pathname;
      const isPublicPath = path === "/" || path === "/login" || path === "/verify";
      if (!isPublicPath) {
        this.currentPage = "login";
        window.history.replaceState({}, "", "/login");
      }
    }

    this.loading = false;
    // Re-run route handling now that we know auth state
    this.handleRoute();
  }

  private async checkVaultStatus() {
    if (!this.user) {
      return;
    }

    try {
      this.vaultStatus = await api.getVaultStatus();

      // If user has vault but it's locked, show unlock modal
      if (this.vaultStatus.hasVault && !this.vaultStatus.isUnlocked) {
        this.showVaultUnlock = true;
      }

      // Sync user settings to localStorage (for beforeunload handler)
      this.syncSettingsToLocal();
    } catch (err) {
      console.error("Failed to check vault status:", err);
    }
  }

  private async syncSettingsToLocal() {
    try {
      const { settings } = await api.getSettings();
      // Sync auto-lock setting to localStorage for beforeunload handler
      localStorage.setItem("ocmt_autolock", settings.vaultAutoLock ? "true" : "false");
    } catch (err) {
      console.error("Failed to sync settings:", err);
    }
  }

  private async loadPendingApprovalCount() {
    try {
      const { approvals } = await api.listPendingApprovals();
      this.pendingApprovalCount = approvals.length;
    } catch (err) {
      console.error("Failed to load pending approval count:", err);
    }
  }

  private setupSSENotifications() {
    // Close any existing connection
    if (this.sseEventSource) {
      this.sseEventSource.close();
    }

    // Create SSE connection for real-time notifications
    const sessionToken = localStorage.getItem("ocmt_session");
    if (!sessionToken) {
      return;
    }

    const baseUrl = import.meta.env.VITE_API_URL ?? "";
    const url = `${baseUrl || window.location.origin}/api/notifications/stream?token=${encodeURIComponent(sessionToken)}`;

    try {
      this.sseEventSource = new EventSource(url, { withCredentials: true });

      // Handle initial approval count
      this.sseEventSource.addEventListener("approval_count", (event) => {
        try {
          const data = JSON.parse(event.data);
          this.pendingApprovalCount = data.count || 0;
        } catch (err) {
          console.error("Failed to parse approval count:", err);
        }
      });

      this.sseEventSource.addEventListener("capability_approval_requested", (event) => {
        try {
          const data = JSON.parse(event.data);
          this.pendingApprovalCount++;

          // Show toast notification
          import("./components/toast.js").then(({ toast }) => {
            toast.info(`New approval request for ${data.resource}`, 5000);
          });

          // Dispatch global event for other components
          window.dispatchEvent(new CustomEvent("capability_approval_requested", { detail: data }));
        } catch (err) {
          console.error("Failed to parse SSE event:", err);
        }
      });

      this.sseEventSource.addEventListener("capability_approval_decided", (event) => {
        try {
          const data = JSON.parse(event.data);
          // Refresh count after a short delay to allow DB to update
          setTimeout(() => this.loadPendingApprovalCount(), 500);

          // Dispatch global event for other components
          window.dispatchEvent(new CustomEvent("capability_approval_decided", { detail: data }));
        } catch (err) {
          console.error("Failed to parse SSE event:", err);
        }
      });

      this.sseEventSource.addEventListener("connected", () => {
        console.log("Notifications SSE connected");
      });

      this.sseEventSource.onerror = () => {
        console.warn("SSE connection error, will attempt reconnect");
        // EventSource will automatically reconnect
      };
    } catch (err) {
      console.error("Failed to set up SSE notifications:", err);
    }
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    if (this.sseEventSource) {
      this.sseEventSource.close();
      this.sseEventSource = null;
    }
    if (this.vaultSessionInterval) {
      clearInterval(this.vaultSessionInterval);
    }
  }

  private handleRoute() {
    const path = window.location.pathname;
    const params = new URLSearchParams(window.location.search);

    // Handle magic link verification
    if (path === "/verify" || params.has("token")) {
      const token = params.get("token");
      if (token) {
        this.verifyMagicLink(token);
        return;
      }
    }

    // Handle OAuth callback
    if (path === "/connections" || path === "/integrations") {
      const success = params.get("success");
      const error = params.get("error");
      if (success || error) {
        // Show notification and clean URL
        window.history.replaceState({}, "", "/connections");
      }
    }

    // If not authenticated (no user loaded yet), show login for protected routes
    // This prevents showing stale data or errors while session is being validated
    const isAuthenticated = this.user !== null;
    const isPublicPath = path === "/" || path === "/login" || path === "/verify";

    if (!isAuthenticated && !isPublicPath && !this.loading) {
      // Not authenticated and trying to access protected route - show login
      this.currentPage = "login";
      window.history.replaceState({}, "", "/login");
      return;
    }

    // Regular routing
    if (path === "/dashboard") {
      this.currentPage = "dashboard";
    } else if (
      path === "/connections" ||
      path === "/integrations" ||
      path === "/messaging" ||
      path === "/channels"
    ) {
      this.currentPage = "connections";
    } else if (path === "/resources") {
      this.currentPage = "resources";
    } else if (path === "/sharing") {
      this.currentPage = "sharing";
    } else if (path === "/activity") {
      this.currentPage = "activity";
    } else if (path === "/organizations" || path === "/orgs" || path === "/groups") {
      // Redirect old /organizations and /orgs to /groups
      if (path !== "/groups") {
        window.history.replaceState({}, "", "/groups");
      }
      this.currentPage = "groups";
    } else if (path === "/invites" || path === "/org-invites" || path === "/group-invites") {
      // Redirect old /invites and /org-invites to /group-invites
      if (path !== "/group-invites") {
        window.history.replaceState({}, "", "/group-invites");
      }
      this.currentPage = "group-invites";
    } else if (path === "/approvals") {
      this.currentPage = "approvals";
    } else if (path === "/approval-action") {
      this.currentPage = "approval-action";
    } else if (path === "/vault/setup") {
      this.currentPage = "vault-setup";
    } else if (path === "/vault/recover") {
      this.currentPage = "vault-recover";
    } else if (path === "/vault/settings" || path === "/vault") {
      this.currentPage = "vault-settings";
    } else if (path === "/vault/unlock") {
      this.currentPage = "vault-unlock";
    } else if (path === "/sessions") {
      this.currentPage = "sessions";
    } else if (path === "/mfa/setup" || path === "/mfa-setup") {
      this.currentPage = "mfa-setup";
    } else if (path === "/mfa/verify" || path === "/mfa-verify") {
      this.currentPage = "mfa-verify";
    } else if (path === "/admin/security" || path === "/admin-security") {
      this.currentPage = "admin-security";
    } else if (path === "/billing") {
      this.currentPage = "billing";
    } else if (path === "/platform-admin" || path === "/admin/platform") {
      this.currentPage = "platform-admin";
    } else if (path === "/onboarding" || path === "/onboarding/welcome") {
      this.currentPage = "onboarding-welcome";
    } else if (path === "/onboarding/org" || path === "/onboarding/group") {
      this.currentPage = "onboarding-group";
    } else if (path === "/onboarding/team") {
      this.currentPage = "onboarding-team";
    } else if (path === "/onboarding/agent") {
      this.currentPage = "onboarding-agent";
    } else if (path === "/onboarding/complete") {
      this.currentPage = "onboarding-complete";
    } else if (path === "/login" || path === "/") {
      this.currentPage = this.user ? "dashboard" : "login";
    } else {
      this.currentPage = this.user ? "dashboard" : "login";
    }
  }

  private async verifyMagicLink(token: string) {
    // Prevent double verification (race condition when handleRoute is called twice)
    if (this.verifyingMagicLink) {
      return;
    }
    this.verifyingMagicLink = true;

    // Clear token from URL immediately to prevent re-verification on refresh
    window.history.replaceState({}, "", "/verify");

    this.loading = true;
    try {
      const result = await api.verifyToken(token);
      if (result.success) {
        this.user = result.user;

        // Check vault status after login
        await this.checkVaultStatus();

        this.navigateTo("dashboard");
      }
    } catch (err) {
      console.error("Magic link verification failed:", err);
      this.navigateTo("login");
    }
    this.loading = false;
    this.verifyingMagicLink = false;
  }

  private navigateTo(page: Page) {
    this.currentPage = page;
    const path = page === "login" ? "/" : `/${page}`;
    window.history.pushState({}, "", path);
  }

  private async handleLogout() {
    await api.logout();
    this.user = null;
    this.navigateTo("login");
  }

  private async handleLogin(e: CustomEvent<User>) {
    this.user = e.detail;

    // Check vault status after login
    await this.checkVaultStatus();

    this.navigateTo("dashboard");
  }

  private handleVaultUnlocked() {
    this.showVaultUnlock = false;
    // Refresh vault status
    this.checkVaultStatus();
    // Notify other components that vault status changed
    window.dispatchEvent(new CustomEvent("vault-status-changed"));
  }

  private handleVaultCreated() {
    // Refresh vault status and go to dashboard
    this.checkVaultStatus();
    this.navigateTo("dashboard");
  }

  private handleVaultSkipped() {
    // User chose to skip vault setup, go to dashboard
    this.navigateTo("dashboard");
  }

  private handleVaultRecovered() {
    // Vault recovered, show unlock modal
    this.showVaultUnlock = true;
    this.navigateTo("dashboard");
  }

  private handleForgotPassword() {
    this.showVaultUnlock = false;
    this.navigateTo("vault-recover");
  }

  private handleOnboardingNavigate(e: CustomEvent<{ page: Page }>) {
    this.navigateTo(e.detail.page);
  }

  private async handleMfaVerified(user: User) {
    this.user = user;
    this.pendingMfaToken = "";

    // Check vault status after MFA verification
    await this.checkVaultStatus();

    // Set up SSE notifications
    this.setupSSENotifications();

    // Load initial approval count
    await this.loadPendingApprovalCount();

    this.navigateTo("dashboard");
  }

  private handleBeforeUnload = () => {
    // Auto-lock vault on browser close if configured
    if (localStorage.getItem("ocmt_autolock") === "true") {
      // Use sendBeacon for reliable delivery on page unload
      const token = localStorage.getItem("ocmt_vault_session");
      if (token) {
        navigator.sendBeacon("/api/vault/lock", JSON.stringify({}));
      }
    }
  };

  private vaultSessionInterval: ReturnType<typeof setInterval> | null = null;

  private setupVaultSessionExtension() {
    // Extend vault session on user activity (every 5 minutes if active)
    let lastActivity = Date.now();

    const handleActivity = () => {
      lastActivity = Date.now();
    };

    // Track user activity
    window.addEventListener("mousemove", handleActivity, { passive: true });
    window.addEventListener("keydown", handleActivity, { passive: true });
    window.addEventListener("click", handleActivity, { passive: true });
    window.addEventListener("touchstart", handleActivity, { passive: true });

    // Check and extend session every 5 minutes
    this.vaultSessionInterval = setInterval(
      async () => {
        // Only extend if user was active in the last 5 minutes
        const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
        if (lastActivity > fiveMinutesAgo && this.vaultStatus?.isUnlocked) {
          try {
            await api.extendVaultSession();
            // Refresh vault status
            await this.checkVaultStatus();
          } catch {
            // Session may have expired, trigger unlock modal
            if (this.vaultStatus?.hasVault) {
              this.showVaultUnlock = true;
            }
          }
        }
      },
      5 * 60 * 1000,
    ); // Every 5 minutes
  }

  render() {
    if (this.loading) {
      return html`
        <div style="display: flex; align-items: center; justify-content: center; min-height: 100vh">
          <div class="spinner" style="width: 40px; height: 40px; border-width: 3px"></div>
        </div>
      `;
    }

    return html`
      ${this.user ? this.renderNav() : ""}
      <main>
        ${this.renderPage()}
      </main>
      <ocmt-toast-container></ocmt-toast-container>
      ${this.user ? html`<ocmt-onboarding .userId=${this.user.id}></ocmt-onboarding>` : ""}
      <vault-unlock-modal
        .open=${this.showVaultUnlock}
        @unlocked=${this.handleVaultUnlocked}
        @close=${() => (this.showVaultUnlock = false)}
        @forgot-password=${this.handleForgotPassword}
      ></vault-unlock-modal>
    `;
  }

  private toggleMenu() {
    this.menuOpen = !this.menuOpen;
  }

  private closeMenuAndNavigate(page: Page) {
    this.menuOpen = false;
    this.navigateTo(page);
  }

  private renderNav() {
    return html`
      <nav class="nav">
        <a href="/" class="nav-brand" @click=${(e: Event) => {
          e.preventDefault();
          this.closeMenuAndNavigate("dashboard");
        }}>
          OCMT
        </a>
        <button class="menu-toggle" @click=${this.toggleMenu} aria-label="Toggle menu">
          ${this.menuOpen ? "✕" : "☰"}
        </button>
        <div class="nav-links ${this.menuOpen ? "open" : ""}">
          <a
            href="/dashboard"
            class="nav-link ${this.currentPage === "dashboard" ? "active" : ""}"
            @click=${(e: Event) => {
              e.preventDefault();
              this.closeMenuAndNavigate("dashboard");
            }}
          >
            Chat
          </a>
          <a
            href="/connections"
            class="nav-link ${this.currentPage === "connections" ? "active" : ""}"
            @click=${(e: Event) => {
              e.preventDefault();
              this.closeMenuAndNavigate("connections");
            }}
          >
            Connections
          </a>
          <a
            href="/resources"
            class="nav-link ${this.currentPage === "resources" ? "active" : ""}"
            @click=${(e: Event) => {
              e.preventDefault();
              this.closeMenuAndNavigate("resources");
            }}
          >
            Resources
          </a>
          <a
            href="/groups"
            class="nav-link ${this.currentPage === "groups" ? "active" : ""}"
            @click=${(e: Event) => {
              e.preventDefault();
              this.closeMenuAndNavigate("groups");
            }}
          >
            Groups
          </a>
          <a
            href="/sharing"
            class="nav-link ${this.currentPage === "sharing" ? "active" : ""}"
            @click=${(e: Event) => {
              e.preventDefault();
              this.closeMenuAndNavigate("sharing");
            }}
          >
            Sharing
          </a>
          <a
            href="/approvals"
            class="nav-link ${this.currentPage === "approvals" ? "active" : ""}"
            @click=${(e: Event) => {
              e.preventDefault();
              this.closeMenuAndNavigate("approvals");
            }}
          >
            Approvals
            ${
              this.pendingApprovalCount > 0
                ? html`
              <span class="nav-link-badge">${this.pendingApprovalCount > 99 ? "99+" : this.pendingApprovalCount}</span>
            `
                : ""
            }
          </a>
          <a
            href="/activity"
            class="nav-link ${this.currentPage === "activity" ? "active" : ""}"
            @click=${(e: Event) => {
              e.preventDefault();
              this.closeMenuAndNavigate("activity");
            }}
          >
            Activity
          </a>
          <a
            href="/vault/settings"
            class="nav-link ${this.currentPage === "vault-settings" ? "active" : ""}"
            @click=${(e: Event) => {
              e.preventDefault();
              this.closeMenuAndNavigate("vault-settings");
            }}
          >
            Vault
          </a>
          <a
            href="/sessions"
            class="nav-link ${this.currentPage === "sessions" ? "active" : ""}"
            @click=${(e: Event) => {
              e.preventDefault();
              this.closeMenuAndNavigate("sessions");
            }}
          >
            Sessions
          </a>
          <a
            href="/billing"
            class="nav-link ${this.currentPage === "billing" ? "active" : ""}"
            @click=${(e: Event) => {
              e.preventDefault();
              this.closeMenuAndNavigate("billing");
            }}
          >
            Billing
          </a>
        </div>
        <div class="nav-user ${this.menuOpen ? "open" : ""}">
          <span class="nav-user-name">${this.user?.name || this.user?.email}</span>
          <button class="nav-logout" @click=${this.handleLogout}>Logout</button>
        </div>
      </nav>
    `;
  }

  private renderPage() {
    switch (this.currentPage) {
      case "login":
        return html`<ocmt-login @login=${this.handleLogin}></ocmt-login>`;
      case "dashboard":
        return html`<ocmt-dashboard .user=${this.user}></ocmt-dashboard>`;
      case "connections":
        return html`<ocmt-connections .user=${this.user}></ocmt-connections>`;
      case "resources":
        return html`<ocmt-group-resources .user=${this.user}></ocmt-group-resources>`;
      case "sharing":
        return html`<ocmt-sharing .user=${this.user}></ocmt-sharing>`;
      case "activity":
        return html`<ocmt-activity .user=${this.user}></ocmt-activity>`;
      case "vault-setup":
        return html`<ocmt-vault-setup
          @vault-created=${this.handleVaultCreated}
          @vault-skipped=${this.handleVaultSkipped}
        ></ocmt-vault-setup>`;
      case "vault-recover":
        return html`<ocmt-vault-recover
          @recovered=${this.handleVaultRecovered}
          @cancel=${() => this.navigateTo("dashboard")}
        ></ocmt-vault-recover>`;
      case "vault-settings":
        return html`
          <ocmt-vault-settings></ocmt-vault-settings>
        `;
      case "vault-unlock":
        return html`
          <ocmt-vault-unlock></ocmt-vault-unlock>
        `;
      case "approvals":
        return html`<ocmt-approvals .user=${this.user}></ocmt-approvals>`;
      case "approval-action":
        return html`
          <ocmt-approval-action></ocmt-approval-action>
        `;
      case "groups":
        return html`<ocmt-groups .user=${this.user}></ocmt-groups>`;
      case "group-invites":
        return html`<ocmt-group-invites .user=${this.user}></ocmt-group-invites>`;
      case "sessions":
        return html`<ocmt-sessions .user=${this.user}></ocmt-sessions>`;
      case "mfa-setup":
        return html`<ocmt-mfa-setup .user=${this.user}></ocmt-mfa-setup>`;
      case "mfa-verify":
        return html`<ocmt-mfa-verify
          .pendingToken=${this.pendingMfaToken}
          .onSuccess=${(user: User) => this.handleMfaVerified(user)}
          .onCancel=${() => this.navigateTo("login")}
        ></ocmt-mfa-verify>`;
      case "admin-security":
        return html`<ocmt-admin-security .user=${this.user}></ocmt-admin-security>`;
      case "billing":
        return html`<ocmt-billing .user=${this.user}></ocmt-billing>`;
      case "platform-admin":
        return html`<ocmt-platform-admin .user=${this.user}></ocmt-platform-admin>`;
      case "onboarding-welcome":
        return html`<ocmt-onboarding-welcome
          .user=${this.user}
          @navigate=${this.handleOnboardingNavigate}
        ></ocmt-onboarding-welcome>`;
      case "onboarding-group":
        return html`<ocmt-onboarding-group
          .user=${this.user}
          @navigate=${this.handleOnboardingNavigate}
        ></ocmt-onboarding-group>`;
      case "onboarding-team":
        return html`<ocmt-onboarding-team
          .user=${this.user}
          @navigate=${this.handleOnboardingNavigate}
        ></ocmt-onboarding-team>`;
      case "onboarding-agent":
        return html`<ocmt-onboarding-agent
          .user=${this.user}
          @navigate=${this.handleOnboardingNavigate}
        ></ocmt-onboarding-agent>`;
      case "onboarding-complete":
        return html`<ocmt-onboarding-complete
          .user=${this.user}
          @navigate=${this.handleOnboardingNavigate}
        ></ocmt-onboarding-complete>`;
      default:
        return html`<ocmt-login @login=${this.handleLogin}></ocmt-login>`;
    }
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-app": OcmtApp;
  }
}

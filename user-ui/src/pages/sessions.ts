import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { toast } from "../components/toast.js";
import { api, User, SessionInfo } from "../lib/api.js";

@customElement("ocmt-sessions")
export class SessionsPage extends LitElement {
  static styles = css`
    :host {
      display: block;
      max-width: 800px;
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
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      padding: 24px;
      margin-bottom: 24px;
    }

    .section h2 {
      font-size: 1.2rem;
      margin-bottom: 16px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .session-count {
      background: rgba(79, 70, 229, 0.2);
      color: #818cf8;
      padding: 2px 8px;
      border-radius: 10px;
      font-size: 0.8rem;
      font-weight: normal;
    }

    .session-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .session-card {
      display: flex;
      align-items: flex-start;
      gap: 16px;
      padding: 16px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 12px;
      transition: all 0.2s;
    }

    .session-card:hover {
      background: rgba(255, 255, 255, 0.05);
      border-color: rgba(255, 255, 255, 0.12);
    }

    .session-card.current {
      border-color: rgba(34, 197, 94, 0.3);
      background: rgba(34, 197, 94, 0.05);
    }

    .device-icon {
      width: 48px;
      height: 48px;
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.5rem;
      flex-shrink: 0;
      background: rgba(255, 255, 255, 0.1);
    }

    .session-card.current .device-icon {
      background: rgba(34, 197, 94, 0.2);
    }

    .session-info {
      flex: 1;
      min-width: 0;
    }

    .session-header {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 4px;
    }

    .session-name {
      font-weight: 600;
      font-size: 1rem;
      color: white;
    }

    .current-badge {
      background: rgba(34, 197, 94, 0.2);
      color: #22c55e;
      padding: 2px 8px;
      border-radius: 10px;
      font-size: 0.75rem;
      font-weight: 500;
    }

    .session-details {
      display: flex;
      flex-direction: column;
      gap: 4px;
      margin-top: 8px;
    }

    .session-detail {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 0.85rem;
      color: #888;
    }

    .session-detail-icon {
      width: 16px;
      text-align: center;
      flex-shrink: 0;
    }

    .session-actions {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-shrink: 0;
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

    .btn-danger {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
    }

    .btn-danger:hover:not(:disabled) {
      background: rgba(239, 68, 68, 0.3);
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

    .btn-row {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-top: 16px;
    }

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
      border-top-color: #4f46e5;
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
      padding: 60px 20px;
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

    .error-banner {
      background: rgba(239, 68, 68, 0.2);
      border: 1px solid rgba(239, 68, 68, 0.3);
      padding: 12px 16px;
      border-radius: 8px;
      color: #ef4444;
      margin-bottom: 24px;
    }

    .info-box {
      background: rgba(79, 70, 229, 0.1);
      border: 1px solid rgba(79, 70, 229, 0.3);
      border-radius: 8px;
      padding: 16px;
      font-size: 0.9rem;
      color: #a5b4fc;
      margin-bottom: 16px;
    }

    .warning-box {
      background: rgba(251, 191, 36, 0.1);
      border: 1px solid rgba(251, 191, 36, 0.3);
      border-radius: 8px;
      padding: 16px;
      font-size: 0.9rem;
      color: #fbbf24;
      margin-bottom: 16px;
    }

    /* Confirmation dialog */
    .dialog-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.7);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      padding: 20px;
    }

    .dialog {
      background: #1a1a2e;
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      padding: 24px;
      max-width: 400px;
      width: 100%;
    }

    .dialog h3 {
      margin-bottom: 12px;
      font-size: 1.2rem;
    }

    .dialog p {
      color: #888;
      margin-bottom: 20px;
      line-height: 1.5;
    }

    .dialog-actions {
      display: flex;
      gap: 12px;
      justify-content: flex-end;
    }

    /* Mobile responsive */
    @media (max-width: 768px) {
      h1 {
        font-size: 1.5rem;
      }

      .section {
        padding: 20px;
      }

      .session-card {
        flex-direction: column;
        gap: 12px;
      }

      .device-icon {
        width: 40px;
        height: 40px;
        font-size: 1.2rem;
      }

      .session-actions {
        width: 100%;
        justify-content: flex-end;
      }

      .btn-row {
        flex-direction: column;
      }

      .btn {
        width: 100%;
        justify-content: center;
      }
    }
  `;

  @property({ type: Object })
  user: User | null = null;

  @state()
  private sessions: SessionInfo[] = [];

  @state()
  private loading = true;

  @state()
  private error = "";

  @state()
  private actionLoading: string | null = null;

  @state()
  private showConfirmDialog = false;

  @state()
  private confirmAction: "revoke" | "revokeAll" | null = null;

  @state()
  private confirmSessionId: string | null = null;

  @state()
  private confirmSessionName: string | null = null;

  connectedCallback() {
    super.connectedCallback();
    this.loadSessions();
  }

  private async loadSessions() {
    this.loading = true;
    this.error = "";

    try {
      const result = await api.getSessions();
      this.sessions = result.sessions || [];
    } catch (err) {
      console.error("Failed to load sessions:", err);
      this.error = err instanceof Error ? err.message : "Failed to load sessions";
    }

    this.loading = false;
  }

  private getDeviceIcon(deviceInfo: SessionInfo["deviceInfo"]): string {
    const type = deviceInfo.type?.toLowerCase() || "";
    const os = deviceInfo.os?.toLowerCase() || "";

    if (type === "mobile" || os.includes("ios") || os.includes("android")) {
      return "📱";
    }
    if (type === "tablet" || os.includes("ipad")) {
      return "📲";
    }
    if (os.includes("mac") || os.includes("darwin")) {
      return "💻";
    }
    if (os.includes("windows")) {
      return "🖥️";
    }
    if (os.includes("linux")) {
      return "🐧";
    }
    return "🌐";
  }

  private formatDeviceName(session: SessionInfo): string {
    const { deviceInfo } = session;
    const parts: string[] = [];

    if (deviceInfo.browser) {
      parts.push(deviceInfo.browser);
    }
    if (deviceInfo.os) {
      parts.push(`on ${deviceInfo.os}`);
    }

    if (parts.length > 0) {
      return parts.join(" ");
    }

    return deviceInfo.name || "Unknown device";
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
      return `${diffMinutes} minute${diffMinutes === 1 ? "" : "s"} ago`;
    }
    if (diffHours < 24) {
      return `${diffHours} hour${diffHours === 1 ? "" : "s"} ago`;
    }
    if (diffDays < 7) {
      return `${diffDays} day${diffDays === 1 ? "" : "s"} ago`;
    }

    return date.toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      year: date.getFullYear() !== now.getFullYear() ? "numeric" : undefined,
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

  private showRevokeConfirm(session: SessionInfo) {
    this.confirmAction = "revoke";
    this.confirmSessionId = session.id;
    this.confirmSessionName = this.formatDeviceName(session);
    this.showConfirmDialog = true;
  }

  private showRevokeAllConfirm() {
    this.confirmAction = "revokeAll";
    this.confirmSessionId = null;
    this.confirmSessionName = null;
    this.showConfirmDialog = true;
  }

  private closeConfirmDialog() {
    this.showConfirmDialog = false;
    this.confirmAction = null;
    this.confirmSessionId = null;
    this.confirmSessionName = null;
  }

  private async handleConfirm() {
    if (this.confirmAction === "revoke" && this.confirmSessionId) {
      await this.revokeSession(this.confirmSessionId);
    } else if (this.confirmAction === "revokeAll") {
      await this.revokeAllSessions();
    }
    this.closeConfirmDialog();
  }

  private async revokeSession(sessionId: string) {
    this.actionLoading = sessionId;

    try {
      await api.revokeSession(sessionId);
      toast.success("Session revoked successfully");
      await this.loadSessions();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to revoke session");
    }

    this.actionLoading = null;
  }

  private async revokeAllSessions() {
    this.actionLoading = "all";

    try {
      const result = await api.revokeAllSessions();
      toast.success(
        `Revoked ${result.revokedCount} session${result.revokedCount === 1 ? "" : "s"}`,
      );
      await this.loadSessions();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to revoke sessions");
    }

    this.actionLoading = null;
  }

  render() {
    if (this.loading) {
      return html`
        <div class="loading">
          <div class="spinner"></div>
        </div>
      `;
    }

    const otherSessions = this.sessions.filter((s) => !s.isCurrent);
    const currentSession = this.sessions.find((s) => s.isCurrent);

    return html`
      <h1>Active Sessions</h1>
      <p class="subtitle">Manage your logged-in devices and sessions</p>

      ${this.error ? html`<div class="error-banner">${this.error}</div>` : ""}

      <div class="info-box">
        Review your active sessions and sign out from devices you no longer use or do not recognize.
        For security, we recommend revoking any suspicious sessions immediately.
      </div>

      ${currentSession ? this.renderCurrentSession(currentSession) : ""}
      ${this.renderOtherSessions(otherSessions)}
      ${this.showConfirmDialog ? this.renderConfirmDialog() : ""}
    `;
  }

  private renderCurrentSession(session: SessionInfo) {
    return html`
      <div class="section">
        <h2>Current Session</h2>
        <div class="session-card current">
          <div class="device-icon">${this.getDeviceIcon(session.deviceInfo)}</div>
          <div class="session-info">
            <div class="session-header">
              <span class="session-name">${this.formatDeviceName(session)}</span>
              <span class="current-badge">This device</span>
            </div>
            <div class="session-details">
              ${
                session.ipAddress
                  ? html`
                    <div class="session-detail">
                      <span class="session-detail-icon">🌐</span>
                      <span>IP: ${session.ipAddress}</span>
                    </div>
                  `
                  : ""
              }
              <div class="session-detail">
                <span class="session-detail-icon">🕐</span>
                <span>Last active: ${this.formatRelativeTime(session.lastActivityAt)}</span>
              </div>
              <div class="session-detail">
                <span class="session-detail-icon">📅</span>
                <span>Signed in: ${this.formatDateTime(session.createdAt)}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  private renderOtherSessions(sessions: SessionInfo[]) {
    return html`
      <div class="section">
        <h2>
          Other Sessions
          ${sessions.length > 0 ? html`<span class="session-count">${sessions.length}</span>` : ""}
        </h2>

        ${
          sessions.length === 0
            ? html`
                <div class="empty-state">
                  <div class="empty-state-icon">🔒</div>
                  <h3>No other sessions</h3>
                  <p>You are only logged in on this device</p>
                </div>
              `
            : html`
              <div class="session-list">
                ${sessions.map((session) => this.renderSessionCard(session))}
              </div>

              <div class="btn-row">
                <button
                  class="btn btn-danger"
                  ?disabled=${this.actionLoading === "all"}
                  @click=${this.showRevokeAllConfirm}
                >
                  ${this.actionLoading === "all" ? "Signing out..." : "Sign out everywhere else"}
                </button>
              </div>
            `
        }
      </div>
    `;
  }

  private renderSessionCard(session: SessionInfo) {
    const isLoading = this.actionLoading === session.id;

    return html`
      <div class="session-card">
        <div class="device-icon">${this.getDeviceIcon(session.deviceInfo)}</div>
        <div class="session-info">
          <div class="session-header">
            <span class="session-name">${this.formatDeviceName(session)}</span>
          </div>
          <div class="session-details">
            ${
              session.ipAddress
                ? html`
                  <div class="session-detail">
                    <span class="session-detail-icon">🌐</span>
                    <span>IP: ${session.ipAddress}</span>
                  </div>
                `
                : ""
            }
            <div class="session-detail">
              <span class="session-detail-icon">🕐</span>
              <span>Last active: ${this.formatRelativeTime(session.lastActivityAt)}</span>
            </div>
            <div class="session-detail">
              <span class="session-detail-icon">📅</span>
              <span>Signed in: ${this.formatDateTime(session.createdAt)}</span>
            </div>
          </div>
        </div>
        <div class="session-actions">
          <button
            class="btn btn-danger"
            ?disabled=${isLoading}
            @click=${() => this.showRevokeConfirm(session)}
          >
            ${isLoading ? "Revoking..." : "Revoke"}
          </button>
        </div>
      </div>
    `;
  }

  private renderConfirmDialog() {
    const isRevokeAll = this.confirmAction === "revokeAll";
    const otherCount = this.sessions.filter((s) => !s.isCurrent).length;

    return html`
      <div class="dialog-overlay" @click=${this.closeConfirmDialog}>
        <div class="dialog" @click=${(e: Event) => e.stopPropagation()}>
          <h3>${isRevokeAll ? "Sign out everywhere else?" : "Revoke session?"}</h3>
          <p>
            ${
              isRevokeAll
                ? html`This will sign out ${otherCount} other session${otherCount === 1 ? "" : "s"}.
                  You will remain logged in on this device.`
                : html`This will sign out the session on
                  <strong>${this.confirmSessionName}</strong>. Any unsaved work on that device will
                  be lost.`
            }
          </p>
          <div class="dialog-actions">
            <button class="btn btn-secondary" @click=${this.closeConfirmDialog}>Cancel</button>
            <button
              class="btn btn-danger"
              @click=${this.handleConfirm}
              ?disabled=${this.actionLoading !== null}
            >
              ${isRevokeAll ? "Sign out all" : "Revoke"}
            </button>
          </div>
        </div>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-sessions": SessionsPage;
  }
}

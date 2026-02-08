import { LitElement, html, css } from "lit";
import { customElement, state } from "lit/decorators.js";
import { toast } from "../components/toast.js";
import { api, VaultStatus, BiometricsStatus, DeviceInfo } from "../lib/api.js";

@customElement("ocmt-vault-settings")
export class VaultSettingsPage extends LitElement {
  static styles = css`
    :host {
      display: block;
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

    .section p {
      color: #888;
      margin-bottom: 16px;
      line-height: 1.6;
    }

    .status-row {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 12px 16px;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 8px;
      margin-bottom: 12px;
    }

    .status-icon {
      width: 32px;
      height: 32px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.2rem;
    }

    .status-icon.success {
      background: rgba(34, 197, 94, 0.2);
    }

    .status-icon.warning {
      background: rgba(251, 191, 36, 0.2);
    }

    .status-icon.error {
      background: rgba(239, 68, 68, 0.2);
    }

    .status-text {
      flex: 1;
    }

    .status-text strong {
      display: block;
      margin-bottom: 2px;
    }

    .status-text span {
      font-size: 0.85rem;
      color: #888;
    }

    .btn {
      padding: 12px 20px;
      border-radius: 8px;
      border: none;
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

    .btn-primary:hover:not(:disabled) {
      background: #4338ca;
    }

    .btn-secondary {
      background: rgba(255, 255, 255, 0.1);
      color: white;
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

    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .btn-row {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
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

    .form-group {
      margin-bottom: 16px;
    }

    .form-group label {
      display: block;
      margin-bottom: 8px;
      font-weight: 500;
    }

    input {
      width: 100%;
      padding: 12px 16px;
      border-radius: 8px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: rgba(255, 255, 255, 0.1);
      color: white;
      font-size: 1rem;
      box-sizing: border-box;
    }

    input:focus {
      outline: none;
      border-color: #4f46e5;
    }

    .no-vault {
      text-align: center;
      padding: 40px;
    }

    .no-vault-icon {
      font-size: 4rem;
      margin-bottom: 16px;
    }

    .no-vault h2 {
      margin-bottom: 8px;
    }

    .no-vault p {
      margin-bottom: 24px;
    }

    .spinner {
      width: 40px;
      height: 40px;
      border: 3px solid rgba(255, 255, 255, 0.2);
      border-top-color: #4f46e5;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }

    @keyframes spin {
      to {
        transform: rotate(360deg);
      }
    }

    .loading {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 300px;
    }

    /* Mobile responsive */
    @media (max-width: 768px) {
      h1 {
        font-size: 1.5rem;
      }

      .section {
        padding: 20px;
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

  @state() private loading = true;
  @state() private vaultStatus: VaultStatus | null = null;
  @state() private biometricsStatus: BiometricsStatus | null = null;
  @state() private devices: DeviceInfo[] = [];
  @state() private showChangePassword = false;
  @state() private currentPassword = "";
  @state() private newPassword = "";
  @state() private confirmPassword = "";
  @state() private changingPassword = false;
  @state() private error = "";
  @state() private autoLock = false;
  @state() private enablingBiometrics = false;
  @state() private loadingDevices = false;

  async connectedCallback() {
    super.connectedCallback();
    await this.loadSettings();
    await this.loadVaultStatus();
  }

  private async loadSettings() {
    try {
      const { settings } = await api.getSettings();
      this.autoLock = settings.vaultAutoLock ?? false;
      // Sync to localStorage for beforeunload handler
      localStorage.setItem("ocmt_autolock", this.autoLock ? "true" : "false");
    } catch (err) {
      console.error("Failed to load settings:", err);
      // Fallback to localStorage for backwards compatibility
      this.autoLock = localStorage.getItem("ocmt_autolock") === "true";
    }
  }

  private async toggleAutoLock() {
    const newValue = !this.autoLock;
    try {
      await api.updateSettings({ vaultAutoLock: newValue });
      this.autoLock = newValue;
      // Sync to localStorage for beforeunload handler
      localStorage.setItem("ocmt_autolock", this.autoLock ? "true" : "false");
      toast.success(this.autoLock ? "Auto-lock enabled" : "Auto-lock disabled");
    } catch (err) {
      console.error("Failed to save auto-lock setting:", err);
      toast.error("Failed to save setting");
    }
  }

  private async loadVaultStatus() {
    this.loading = true;
    try {
      this.vaultStatus = await api.getVaultStatus();

      // Load biometrics status
      const fingerprint = this.getDeviceFingerprint();
      this.biometricsStatus = await api.getBiometricsStatus(fingerprint);

      // Load devices if vault is unlocked
      if (this.vaultStatus.isUnlocked && this.biometricsStatus.biometricsEnabled) {
        await this.loadDevices();
      }
    } catch (err) {
      console.error("Failed to load vault status:", err);
    }
    this.loading = false;
  }

  private async loadDevices() {
    this.loadingDevices = true;
    try {
      const result = await api.listDevices();
      this.devices = result.devices;
    } catch (err) {
      console.error("Failed to load devices:", err);
    }
    this.loadingDevices = false;
  }

  private getDeviceFingerprint(): string {
    // Generate a simple device fingerprint
    let fingerprint = localStorage.getItem("ocmt_device_fingerprint");
    if (!fingerprint) {
      fingerprint = crypto.randomUUID();
      localStorage.setItem("ocmt_device_fingerprint", fingerprint);
    }
    return fingerprint;
  }

  private getDeviceName(): string {
    const ua = navigator.userAgent;
    if (ua.includes("iPhone")) {
      return "iPhone";
    }
    if (ua.includes("iPad")) {
      return "iPad";
    }
    if (ua.includes("Android")) {
      return "Android Device";
    }
    if (ua.includes("Mac")) {
      return "Mac";
    }
    if (ua.includes("Windows")) {
      return "Windows PC";
    }
    if (ua.includes("Linux")) {
      return "Linux PC";
    }
    return "Unknown Device";
  }

  private async enableBiometrics() {
    if (!this.vaultStatus?.isUnlocked) {
      toast.error("Please unlock your vault first");
      return;
    }

    this.enablingBiometrics = true;

    try {
      const deviceName = this.getDeviceName();
      const deviceFingerprint = this.getDeviceFingerprint();

      const result = await api.enableBiometrics(deviceName, deviceFingerprint);

      // Store device key securely in localStorage (in production, use credential storage)
      localStorage.setItem("ocmt_device_key", result.deviceKey);

      toast.success("Biometrics enabled for this device");
      await this.loadVaultStatus();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to enable biometrics");
    }

    this.enablingBiometrics = false;
  }

  private async disableBiometrics() {
    if (!this.vaultStatus?.isUnlocked) {
      toast.error("Please unlock your vault first");
      return;
    }

    try {
      await api.disableBiometrics();
      localStorage.removeItem("ocmt_device_key");
      toast.success("Biometrics disabled");
      await this.loadVaultStatus();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to disable biometrics");
    }
  }

  private async removeDevice(deviceId: string) {
    try {
      await api.removeDevice(deviceId);
      toast.success("Device removed");
      await this.loadDevices();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to remove device");
    }
  }

  private downloadBackup() {
    // Open backup URL in new window to trigger download
    window.open(api.getVaultBackupUrl(), "_blank");
    toast.success("Backup download started");
  }

  private navigateToSetup() {
    window.history.pushState({}, "", "/vault/setup");
    window.dispatchEvent(new PopStateEvent("popstate"));
  }

  private navigateToRecover() {
    window.history.pushState({}, "", "/vault/recover");
    window.dispatchEvent(new PopStateEvent("popstate"));
  }

  private async handleChangePassword() {
    if (this.newPassword !== this.confirmPassword) {
      this.error = "Passwords do not match";
      return;
    }

    if (this.newPassword.length < 12) {
      this.error = "New password must be at least 12 characters";
      return;
    }

    this.changingPassword = true;
    this.error = "";

    try {
      await api.changeVaultPassword(this.currentPassword, this.newPassword);
      toast.success("Password changed successfully");
      this.showChangePassword = false;
      this.currentPassword = "";
      this.newPassword = "";
      this.confirmPassword = "";
      // Refresh status
      await this.loadVaultStatus();
    } catch (err) {
      this.error = err instanceof Error ? err.message : "Failed to change password";
    }

    this.changingPassword = false;
  }

  render() {
    if (this.loading) {
      return html`
        <div class="loading">
          <div class="spinner"></div>
        </div>
      `;
    }

    if (!this.vaultStatus?.hasVault) {
      return this.renderNoVault();
    }

    return html`
      <h1>Vault Settings</h1>
      <p class="subtitle">Manage your encrypted vault</p>

      ${this.renderVaultStatus()}
      ${this.renderBiometricsSection()}
      ${this.renderBackupSection()}
      ${this.renderSecuritySection()}
    `;
  }

  private renderNoVault() {
    return html`
      <div class="section no-vault">
        <div class="no-vault-icon">🔐</div>
        <h2>No Vault Set Up</h2>
        <p>Create a vault to encrypt your credentials and data with zero-knowledge encryption.</p>
        <button class="btn btn-primary" @click=${this.navigateToSetup}>
          Create Vault
        </button>
      </div>
    `;
  }

  private renderVaultStatus() {
    const isUnlocked = this.vaultStatus?.isUnlocked;
    const expiresIn = this.vaultStatus?.expiresIn || 0;
    const expiresMinutes = Math.ceil(expiresIn / 60);

    return html`
      <div class="section">
        <h2>Vault Status</h2>

        <div class="status-row">
          <div class="status-icon ${isUnlocked ? "success" : "warning"}">
            ${isUnlocked ? "🔓" : "🔐"}
          </div>
          <div class="status-text">
            <strong>${isUnlocked ? "Unlocked" : "Locked"}</strong>
            <span>${isUnlocked ? `Session expires in ${expiresMinutes} minutes` : "Enter password to unlock"}</span>
          </div>
        </div>

        ${
          this.vaultStatus?.biometrics?.enabled
            ? html`
          <div class="status-row">
            <div class="status-icon ${this.vaultStatus.biometrics.canUse ? "success" : "warning"}">
              👆
            </div>
            <div class="status-text">
              <strong>Biometrics Enabled</strong>
              <span>${this.vaultStatus.biometrics.canUse ? "Touch ID / Face ID available" : "Password required (14+ days since last entry)"}</span>
            </div>
          </div>
        `
            : ""
        }
      </div>
    `;
  }

  private renderBiometricsSection() {
    const isEnabled = this.biometricsStatus?.biometricsEnabled;
    const canUse = this.biometricsStatus?.canUseBiometrics;

    return html`
      <div class="section">
        <h2>Biometric Unlock</h2>

        ${
          isEnabled
            ? html`
          <div class="status-row">
            <div class="status-icon ${canUse ? "success" : "warning"}">
              👆
            </div>
            <div class="status-text">
              <strong>${canUse ? "Active" : "Password Required"}</strong>
              <span>${
                canUse
                  ? "Touch ID / Face ID available for quick unlock"
                  : `Password required (${this.biometricsStatus?.passwordRequiredReason || "14+ days since last password entry"})`
              }</span>
            </div>
          </div>

          ${
            this.devices.length > 0
              ? html`
            <h3 style="margin-top: 20px; margin-bottom: 12px; font-size: 1rem;">Registered Devices</h3>
            ${this.devices.map(
              (device) => html`
              <div class="status-row">
                <div class="status-icon" style="background: rgba(255, 255, 255, 0.1);">
                  📱
                </div>
                <div class="status-text">
                  <strong>${device.device_name}</strong>
                  <span>Last used: ${device.last_used_at ? new Date(device.last_used_at).toLocaleDateString() : "Never"}</span>
                </div>
                <button
                  class="btn btn-danger"
                  style="padding: 8px 12px; font-size: 0.85rem;"
                  @click=${() => this.removeDevice(device.id)}
                >
                  Remove
                </button>
              </div>
            `,
            )}
          `
              : ""
          }

          <div class="btn-row" style="margin-top: 16px;">
            <button class="btn btn-danger" @click=${this.disableBiometrics}>
              Disable Biometrics
            </button>
          </div>
        `
            : html`
          <p>
            Enable biometric unlock for quick access on this device.
            You'll still need your password every 14 days and for sensitive actions.
          </p>

          <div class="info-box">
            When enabled, you can unlock your vault using Touch ID, Face ID, or other
            biometric authentication supported by your device.
          </div>

          ${
            !this.vaultStatus?.isUnlocked
              ? html`
                  <div class="warning-box">Unlock your vault first to enable biometrics.</div>
                `
              : html`
            <div class="btn-row">
              <button
                class="btn btn-primary"
                ?disabled=${this.enablingBiometrics}
                @click=${this.enableBiometrics}
              >
                ${this.enablingBiometrics ? "Enabling..." : "Enable Biometrics"}
              </button>
            </div>
          `
          }
        `
        }
      </div>
    `;
  }

  private renderBackupSection() {
    return html`
      <div class="section">
        <h2>Backup</h2>
        <p>
          Download an encrypted backup of your vault. This backup contains all your credentials
          and data, encrypted with your vault password.
        </p>

        <div class="info-box">
          Your backup is encrypted with your vault password. You'll need your password or
          recovery phrase to restore it.
        </div>

        <div class="btn-row">
          <button class="btn btn-secondary" @click=${this.downloadBackup}>
            Download Backup
          </button>
        </div>
      </div>
    `;
  }

  private renderSecuritySection() {
    return html`
      <div class="section">
        <h2>Security</h2>

        <div class="status-row" style="cursor: pointer;" @click=${this.toggleAutoLock}>
          <div class="status-icon ${this.autoLock ? "success" : "warning"}">
            ${this.autoLock ? "✓" : "○"}
          </div>
          <div class="status-text">
            <strong>Auto-lock on Close</strong>
            <span>${this.autoLock ? "Vault locks when you close the browser" : "Vault stays unlocked until session expires"}</span>
          </div>
        </div>

        ${
          this.showChangePassword
            ? this.renderChangePasswordForm()
            : html`
          <div class="btn-row" style="margin-top: 16px;">
            <button class="btn btn-secondary" @click=${() => (this.showChangePassword = true)}>
              Change Password
            </button>
            <button class="btn btn-secondary" @click=${this.navigateToRecover}>
              Recover with Phrase
            </button>
          </div>
        `
        }
      </div>
    `;
  }

  private renderChangePasswordForm() {
    return html`
      <div class="warning-box">
        Changing your password will invalidate any existing vault sessions and disable biometrics.
        You'll need to re-enable biometrics after changing your password.
      </div>

      ${
        this.error
          ? html`
        <div class="warning-box" style="background: rgba(239, 68, 68, 0.1); border-color: rgba(239, 68, 68, 0.3); color: #fca5a5;">
          ${this.error}
        </div>
      `
          : ""
      }

      <div class="form-group">
        <label>Current Password</label>
        <input
          type="password"
          .value=${this.currentPassword}
          @input=${(e: Event) => (this.currentPassword = (e.target as HTMLInputElement).value)}
          placeholder="Enter current password"
        />
      </div>

      <div class="form-group">
        <label>New Password</label>
        <input
          type="password"
          .value=${this.newPassword}
          @input=${(e: Event) => (this.newPassword = (e.target as HTMLInputElement).value)}
          placeholder="Enter new password (min 12 characters)"
        />
      </div>

      <div class="form-group">
        <label>Confirm New Password</label>
        <input
          type="password"
          .value=${this.confirmPassword}
          @input=${(e: Event) => (this.confirmPassword = (e.target as HTMLInputElement).value)}
          placeholder="Confirm new password"
        />
      </div>

      <div class="btn-row">
        <button
          class="btn btn-primary"
          ?disabled=${!this.currentPassword || !this.newPassword || !this.confirmPassword || this.changingPassword}
          @click=${this.handleChangePassword}
        >
          ${this.changingPassword ? "Changing..." : "Change Password"}
        </button>
        <button
          class="btn btn-secondary"
          @click=${() => {
            this.showChangePassword = false;
            this.error = "";
            this.currentPassword = "";
            this.newPassword = "";
            this.confirmPassword = "";
          }}
        >
          Cancel
        </button>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-vault-settings": VaultSettingsPage;
  }
}

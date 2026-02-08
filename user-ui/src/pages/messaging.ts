import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { api, User } from "../lib/api.js";

interface Channel {
  id: string;
  name: string;
  icon: string;
  description: string;
  status: "connected" | "disconnected" | "pending" | "coming_soon";
  configKey: string;
  setupType: "token" | "qr" | "phone" | "agent" | "coming_soon";
  helpUrl?: string;
  helpText?: string;
  agentPrompt?: string; // For 'agent' setup type
}

const CHANNELS: Channel[] = [
  {
    id: "telegram",
    name: "Telegram",
    icon: "✈️",
    description: "Chat with your AI via Telegram bot",
    status: "disconnected",
    configKey: "telegram.token",
    setupType: "token",
    helpText: "Get a bot token from @BotFather on Telegram",
    helpUrl: "https://t.me/BotFather",
  },
  {
    id: "whatsapp",
    name: "WhatsApp",
    icon: "💬",
    description: "One-click setup coming soon",
    status: "coming_soon",
    configKey: "whatsapp",
    setupType: "coming_soon",
    helpText: "Ask your agent to get connected now",
  },
  {
    id: "slack",
    name: "Slack",
    icon: "💼",
    description: "One-click setup coming soon",
    status: "coming_soon",
    configKey: "slack.token",
    setupType: "coming_soon",
    helpText: "Ask your agent to get connected now",
  },
  {
    id: "discord",
    name: "Discord",
    icon: "🎮",
    description: "Chat in Discord servers or DMs",
    status: "disconnected",
    configKey: "discord.token",
    setupType: "token",
    helpText: "Add your Discord bot token",
    helpUrl: "https://discord.com/developers/applications",
  },
  {
    id: "signal",
    name: "Signal",
    icon: "🔒",
    description: "Secure messaging via Signal",
    status: "disconnected",
    configKey: "signal.phone",
    setupType: "phone",
    helpText: "Link your Signal account",
  },
  {
    id: "imap",
    name: "Email (IMAP)",
    icon: "📧",
    description: "Receive and respond to emails",
    status: "disconnected",
    configKey: "imap.host",
    setupType: "agent",
    helpText: "Your agent can help set this up",
    agentPrompt: "Connect my email inbox via IMAP",
  },
];

@customElement("ocmt-messaging")
export class MessagingPage extends LitElement {
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

    .channels-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
      gap: 16px;
    }

    .channel-card {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 24px;
      transition: all 0.2s;
    }

    .channel-card:hover {
      background: rgba(255, 255, 255, 0.08);
    }

    .channel-card.connected {
      border-color: rgba(34, 197, 94, 0.4);
    }

    .channel-header {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 12px;
    }

    .channel-icon {
      font-size: 2rem;
    }

    .channel-name {
      font-size: 1.2rem;
      font-weight: 600;
    }

    .channel-status {
      margin-left: auto;
      font-size: 0.8rem;
      padding: 4px 10px;
      border-radius: 12px;
    }

    .channel-status.connected {
      background: rgba(34, 197, 94, 0.2);
      color: #22c55e;
    }

    .channel-status.disconnected {
      background: rgba(255, 255, 255, 0.1);
      color: #888;
    }

    .channel-status.pending {
      background: rgba(251, 191, 36, 0.2);
      color: #fbbf24;
    }

    .channel-status.coming_soon {
      background: rgba(251, 191, 36, 0.2);
      color: #fbbf24;
    }

    .channel-description {
      color: #aaa;
      font-size: 0.9rem;
      margin-bottom: 16px;
    }

    .btn {
      width: 100%;
      padding: 12px;
      border-radius: 8px;
      border: none;
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

    .btn-danger {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
    }

    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    /* Setup Modal */
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
    }

    .modal {
      background: #1a1a2e;
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      padding: 32px;
      max-width: 480px;
      width: 90%;
    }

    .modal h2 {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 8px;
    }

    .modal .subtitle {
      margin-bottom: 24px;
    }

    .form-group {
      margin-bottom: 20px;
    }

    .form-group label {
      display: block;
      margin-bottom: 8px;
      font-weight: 500;
    }

    .form-group input {
      width: 100%;
      padding: 12px 14px;
      border-radius: 8px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: rgba(255, 255, 255, 0.1);
      color: white;
      font-size: 1rem;
      box-sizing: border-box;
    }

    .form-group input:focus {
      outline: none;
      border-color: #4f46e5;
    }

    .help-box {
      background: rgba(79, 70, 229, 0.1);
      border: 1px solid rgba(79, 70, 229, 0.3);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 20px;
      font-size: 0.9rem;
    }

    .help-box a {
      color: #818cf8;
    }

    .help-steps {
      margin: 12px 0 0 0;
      padding-left: 20px;
      color: #aaa;
    }

    .help-steps li {
      margin-bottom: 8px;
    }

    .modal-buttons {
      display: flex;
      gap: 12px;
      margin-top: 24px;
    }

    .modal-buttons .btn {
      flex: 1;
    }

    .error-message {
      background: rgba(239, 68, 68, 0.2);
      border: 1px solid rgba(239, 68, 68, 0.3);
      padding: 12px;
      border-radius: 8px;
      color: #ef4444;
      margin-bottom: 16px;
    }

    .success-message {
      background: rgba(34, 197, 94, 0.2);
      border: 1px solid rgba(34, 197, 94, 0.3);
      padding: 12px;
      border-radius: 8px;
      color: #22c55e;
      margin-bottom: 16px;
    }

    .qr-container {
      background: white;
      padding: 20px;
      border-radius: 12px;
      text-align: center;
      margin-bottom: 20px;
    }

    .qr-placeholder {
      width: 200px;
      height: 200px;
      background: #f0f0f0;
      margin: 0 auto;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #666;
      border-radius: 8px;
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

    .custom-channel-hint {
      margin-top: 32px;
      padding: 24px;
      background: rgba(79, 70, 229, 0.1);
      border: 1px solid rgba(79, 70, 229, 0.2);
      border-radius: 12px;
      display: flex;
      gap: 16px;
      align-items: flex-start;
    }

    .hint-icon {
      font-size: 1.5rem;
    }

    .hint-content strong {
      display: block;
      margin-bottom: 8px;
    }

    .hint-content p {
      color: #aaa;
      margin: 0 0 12px 0;
      font-size: 0.9rem;
    }

    .hint-examples {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }

    .hint-example {
      background: rgba(255, 255, 255, 0.1);
      padding: 6px 12px;
      border-radius: 16px;
      font-size: 0.85rem;
      color: #ccc;
      font-family: monospace;
    }

    .channel-hint {
      color: #818cf8;
      font-size: 0.85rem;
      margin: -8px 0 16px 0;
      font-style: italic;
    }
  `;

  @property({ type: Object })
  user: User | null = null;

  @state()
  private channels: Channel[] = [...CHANNELS];

  @state()
  private loading = true;

  @state()
  private setupChannel: Channel | null = null;

  @state()
  private tokenInput = "";

  @state()
  private saving = false;

  @state()
  private error = "";

  @state()
  private success = "";

  connectedCallback() {
    super.connectedCallback();
    this.loadChannelStatus();
  }

  private async loadChannelStatus() {
    this.loading = true;
    try {
      const response = await api.getChannelStatus();
      const channelStatuses = response.channels || [];

      // Create a lookup map from channel name/id to status
      const statusMap = new Map<string, string>();
      for (const ch of channelStatuses) {
        // OpenClaw uses channel names like 'telegram', 'whatsapp', etc.
        const id = (ch.id || ch.name || "").toLowerCase();
        statusMap.set(id, ch.status);
      }

      // Update channel statuses
      this.channels = this.channels.map((channel) => ({
        ...channel,
        status: statusMap.get(channel.id) || "disconnected",
      }));
    } catch (err) {
      console.error("Failed to load channel status:", err);
    }
    this.loading = false;
  }

  private openSetup(channel: Channel) {
    this.setupChannel = channel;
    this.tokenInput = "";
    this.error = "";
    this.success = "";
  }

  private closeSetup() {
    this.setupChannel = null;
    this.tokenInput = "";
    this.error = "";
  }

  private async handleConnect() {
    if (!this.setupChannel || !this.tokenInput.trim()) {
      return;
    }

    this.saving = true;
    this.error = "";

    try {
      await api.connectChannel(this.setupChannel.id, {
        token: this.tokenInput.trim(),
      });

      this.success = `${this.setupChannel.name} connected successfully!`;

      // Update status
      this.channels = this.channels.map((ch) =>
        ch.id === this.setupChannel!.id ? { ...ch, status: "connected" as const } : ch,
      );

      // Close modal after brief delay
      setTimeout(() => {
        this.closeSetup();
        this.success = "";
      }, 1500);
    } catch (err) {
      this.error = err instanceof Error ? err.message : "Failed to connect";
    }

    this.saving = false;
  }

  private navigateToChat() {
    // Navigate to the chat page
    window.location.hash = "#/chat";
  }

  private async handleDisconnect(channel: Channel) {
    if (!confirm(`Disconnect ${channel.name}?`)) {
      return;
    }

    try {
      await api.disconnectChannel(channel.id);

      this.channels = this.channels.map((ch) =>
        ch.id === channel.id ? { ...ch, status: "disconnected" as const } : ch,
      );
    } catch (err) {
      console.error("Failed to disconnect:", err);
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
      <h1>Messaging Channels</h1>
      <p class="subtitle">Connect your AI assistant to messaging platforms</p>

      <div class="channels-grid">
        ${this.channels.map((channel) => this.renderChannel(channel))}
      </div>

      <div class="custom-channel-hint">
        <div class="hint-icon">💡</div>
        <div class="hint-content">
          <strong>Don't see what you need, or need help?</strong>
          <p>Your agent can help you connect other services. Just ask:</p>
          <div class="hint-examples">
            <span class="hint-example">"Connect me to Workflowy"</span>
            <span class="hint-example">"Set up Matrix chat"</span>
            <span class="hint-example">"Add Microsoft Teams"</span>
          </div>
        </div>
      </div>

      ${this.setupChannel ? this.renderSetupModal() : ""}
    `;
  }

  private renderChannel(channel: Channel) {
    return html`
      <div class="channel-card ${channel.status}">
        <div class="channel-header">
          <span class="channel-icon">${channel.icon}</span>
          <span class="channel-name">${channel.name}</span>
          <span class="channel-status ${channel.status}">
            ${
              channel.status === "connected"
                ? "● Connected"
                : channel.status === "pending"
                  ? "◐ Pending"
                  : channel.status === "coming_soon"
                    ? "◐ Coming soon"
                    : "○ Not connected"
            }
          </span>
        </div>
        <p class="channel-description">${channel.description}</p>
        ${channel.status === "coming_soon" && channel.helpText ? html`<p class="channel-hint">${channel.helpText}</p>` : ""}
        ${
          channel.status === "connected"
            ? html`
          <button class="btn btn-danger" @click=${() => this.handleDisconnect(channel)}>
            Disconnect
          </button>
        `
            : channel.status === "coming_soon"
              ? html`
                  <button class="btn btn-secondary" @click=${() => this.navigateToChat()}>Ask Agent</button>
                `
              : html`
          <button class="btn btn-primary" @click=${() => this.openSetup(channel)}>
            Connect
          </button>
        `
        }
      </div>
    `;
  }

  private renderSetupModal() {
    const channel = this.setupChannel!;

    return html`
      <div class="modal-overlay" @click=${(e: Event) => {
        if (e.target === e.currentTarget) {
          this.closeSetup();
        }
      }}>
        <div class="modal">
          <h2>
            <span>${channel.icon}</span>
            Connect ${channel.name}
          </h2>
          <p class="subtitle">${channel.description}</p>

          ${
            this.error
              ? html`
            <div class="error-message">${this.error}</div>
          `
              : ""
          }

          ${
            this.success
              ? html`
            <div class="success-message">${this.success}</div>
          `
              : ""
          }

          ${channel.setupType === "token" ? this.renderTokenSetup(channel) : ""}
          ${channel.setupType === "qr" ? this.renderQRSetup(channel) : ""}
          ${channel.setupType === "phone" ? this.renderPhoneSetup(channel) : ""}
          ${channel.setupType === "agent" ? this.renderAgentSetup(channel) : ""}

          <div class="modal-buttons">
            <button class="btn btn-secondary" @click=${this.closeSetup}>
              ${channel.setupType === "agent" ? "Close" : "Cancel"}
            </button>
            ${
              channel.setupType === "token"
                ? html`
              <button
                class="btn btn-primary"
                ?disabled=${!this.tokenInput.trim() || this.saving}
                @click=${this.handleConnect}
              >
                ${this.saving ? "Connecting..." : "Connect"}
              </button>
            `
                : ""
            }
          </div>
        </div>
      </div>
    `;
  }

  private renderTokenSetup(channel: Channel) {
    const steps = this.getSetupSteps(channel);

    return html`
      <div class="help-box">
        <strong>How to get your ${channel.name} bot token:</strong>
        <ol class="help-steps">
          ${steps.map((step) => html`<li>${step}</li>`)}
        </ol>
        ${
          channel.helpUrl
            ? html`
          <a href="${channel.helpUrl}" target="_blank">Open ${channel.name} setup →</a>
        `
            : ""
        }
      </div>

      <div class="form-group">
        <label>Bot Token</label>
        <input
          type="password"
          placeholder="Paste your bot token here"
          .value=${this.tokenInput}
          @input=${(e: Event) => (this.tokenInput = (e.target as HTMLInputElement).value)}
        />
      </div>
    `;
  }

  private renderQRSetup(channel: Channel) {
    return html`
      <div class="help-box">
        <strong>Scan with ${channel.name} on your phone:</strong>
        <ol class="help-steps">
          <li>Open ${channel.name} on your phone</li>
          <li>Go to Settings → Linked Devices</li>
          <li>Tap "Link a Device"</li>
          <li>Scan the QR code below</li>
        </ol>
      </div>

      <div class="qr-container">
        <div class="qr-placeholder">
          QR Code Loading...
        </div>
      </div>

      <p style="text-align: center; color: #888; font-size: 0.9rem;">
        Waiting for scan...
      </p>
    `;
  }

  private renderPhoneSetup(channel: Channel) {
    return html`
      <div class="help-box">
        <strong>Link your ${channel.name} account:</strong>
        <p style="margin-top: 8px; color: #aaa;">
          Enter the phone number associated with your ${channel.name} account.
        </p>
      </div>

      <div class="form-group">
        <label>Phone Number</label>
        <input
          type="tel"
          placeholder="+1 234 567 8900"
          .value=${this.tokenInput}
          @input=${(e: Event) => (this.tokenInput = (e.target as HTMLInputElement).value)}
        />
      </div>
    `;
  }

  private renderAgentSetup(channel: Channel) {
    return html`
      <div class="help-box" style="text-align: center;">
        <p style="font-size: 1.1rem; margin-bottom: 16px;">
          ${channel.name} requires multiple settings to configure.
        </p>
        <p style="color: #aaa; margin-bottom: 16px;">
          Your agent can help you set this up. Just ask:
        </p>
        <p style="font-style: italic; color: #818cf8; font-size: 1.1rem;">
          "${channel.agentPrompt || `Set up ${channel.name} for me`}"
        </p>
      </div>
    `;
  }

  private getSetupSteps(channel: Channel): string[] {
    switch (channel.id) {
      case "telegram":
        return [
          "Open Telegram and search for @BotFather",
          "Send /newbot and follow the prompts",
          "Choose a name and username for your bot",
          "Copy the token BotFather gives you",
        ];
      case "discord":
        return [
          "Go to Discord Developer Portal",
          "Create a new application",
          'Go to "Bot" section and create a bot',
          "Copy the bot token",
        ];
      case "slack":
        return [
          "Go to api.slack.com/apps and create a new app",
          "Add Bot Token Scopes (chat:write, channels:read, etc.)",
          "Install to your workspace",
          "Copy the Bot User OAuth Token (xoxb-...)",
        ];
      case "imap":
        return [
          "Get your email IMAP server settings",
          'For Gmail: imap.gmail.com (enable "Less secure apps" or use App Password)',
          "Enter your email and app password",
          "Your agent will monitor and respond to emails",
        ];
      default:
        return ["Follow the setup instructions"];
    }
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-messaging": MessagingPage;
  }
}

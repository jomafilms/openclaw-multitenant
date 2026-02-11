import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { unsafeHTML } from "lit/directives/unsafe-html.js";
import { api, User, ChatMessage, VaultStatus } from "../lib/api.js";
import { GatewayClient, ChatEvent, WakeStatus } from "../lib/gateway-client.js";
import { toSanitizedMarkdownHtml } from "../lib/markdown.js";

@customElement("ocmt-dashboard")
export class DashboardPage extends LitElement {
  static styles = css`
    :host {
      display: block;
      height: calc(100vh - 140px);
      max-width: 900px;
      margin: 0 auto;
    }

    .chat-container {
      display: flex;
      flex-direction: column;
      height: 100%;
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      overflow: hidden;
    }

    .chat-header {
      padding: 16px 20px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .chat-header h2 {
      font-size: 1.1rem;
      font-weight: 600;
    }

    .connection-status {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 0.85rem;
      color: #888;
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #888;
    }

    .status-dot.connected {
      background: #22c55e;
    }

    .status-dot.error {
      background: #ef4444;
    }

    .status-dot.provisioning {
      background: #a855f7;
      animation: pulse 1.5s ease-in-out infinite;
    }

    .status-dot.waking {
      background: #eab308;
      animation: pulse 1.5s ease-in-out infinite;
    }

    @keyframes pulse {
      0%, 100% {
        opacity: 1;
        transform: scale(1);
      }
      50% {
        opacity: 0.6;
        transform: scale(1.1);
      }
    }

    .connection-status-detail {
      font-size: 0.75rem;
      color: #666;
      margin-top: 2px;
    }

    .progress-bar {
      width: 100px;
      height: 3px;
      background: rgba(255, 255, 255, 0.1);
      border-radius: 2px;
      overflow: hidden;
      margin-left: 8px;
    }

    .progress-bar-fill {
      height: 100%;
      background: linear-gradient(90deg, #a855f7, #4f46e5);
      animation: progress-indeterminate 1.5s ease-in-out infinite;
    }

    @keyframes progress-indeterminate {
      0% {
        transform: translateX(-100%);
        width: 50%;
      }
      50% {
        transform: translateX(50%);
        width: 50%;
      }
      100% {
        transform: translateX(200%);
        width: 50%;
      }
    }

    .messages {
      flex: 1;
      overflow-y: auto;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .message {
      max-width: 80%;
      padding: 10px 14px;
      border-radius: 16px;
      line-height: 1.5;
      word-break: break-word;
    }

    /* Markdown content styles */
    .message-content :where(p, ul, ol, pre, blockquote, table) {
      margin: 0;
    }

    .message-content :where(p + p, p + ul, p + ol, p + pre, p + blockquote) {
      margin-top: 0.75em;
    }

    .message-content :where(ul, ol) {
      padding-left: 1.5em;
    }

    .message-content :where(li + li) {
      margin-top: 0.25em;
    }

    .message-content :where(a) {
      color: #818cf8;
      text-decoration: underline;
      text-underline-offset: 2px;
    }

    .message-content :where(a:hover) {
      opacity: 0.8;
    }

    .message-content :where(code) {
      font-family: "Monaco", "Menlo", monospace;
      font-size: 0.9em;
    }

    .message-content :where(:not(pre) > code) {
      background: rgba(0, 0, 0, 0.2);
      padding: 0.15em 0.4em;
      border-radius: 4px;
    }

    .message-content :where(pre) {
      background: rgba(0, 0, 0, 0.2);
      border-radius: 6px;
      padding: 10px 12px;
      overflow-x: auto;
    }

    .message-content :where(pre code) {
      background: none;
      padding: 0;
    }

    .message-content :where(blockquote) {
      border-left: 3px solid rgba(255, 255, 255, 0.3);
      padding-left: 12px;
      margin-left: 0;
      color: rgba(255, 255, 255, 0.7);
    }

    .message-content :where(strong, b) {
      font-weight: 600;
    }

    .message-content :where(em, i) {
      font-style: italic;
    }

    .message.user {
      background: #4f46e5;
      align-self: flex-end;
      border-bottom-right-radius: 4px;
    }

    .message.assistant {
      background: rgba(255, 255, 255, 0.1);
      align-self: flex-start;
      border-bottom-left-radius: 4px;
    }

    .message.system {
      background: rgba(251, 191, 36, 0.15);
      align-self: center;
      text-align: center;
      font-size: 0.9rem;
      color: #fbbf24;
      max-width: 100%;
    }

    .message.streaming {
      opacity: 0.8;
      border: 1px dashed rgba(255, 255, 255, 0.3);
    }

    .message-time {
      font-size: 0.7rem;
      color: rgba(255, 255, 255, 0.4);
      margin-top: 2px;
    }

    .typing-indicator {
      display: flex;
      gap: 4px;
      padding: 12px 16px;
      background: rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      border-bottom-left-radius: 4px;
      align-self: flex-start;
      max-width: 60px;
    }

    .typing-dot {
      width: 8px;
      height: 8px;
      background: #888;
      border-radius: 50%;
      animation: bounce 1.4s infinite ease-in-out;
    }

    .typing-dot:nth-child(1) {
      animation-delay: -0.32s;
    }
    .typing-dot:nth-child(2) {
      animation-delay: -0.16s;
    }

    @keyframes bounce {
      0%,
      80%,
      100% {
        transform: scale(0.8);
        opacity: 0.5;
      }
      40% {
        transform: scale(1);
        opacity: 1;
      }
    }

    .input-area {
      padding: 16px 20px;
      border-top: 1px solid rgba(255, 255, 255, 0.1);
      background: rgba(0, 0, 0, 0.2);
    }

    .input-row {
      display: flex;
      gap: 12px;
    }

    textarea {
      flex: 1;
      padding: 12px 16px;
      border-radius: 12px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: rgba(255, 255, 255, 0.1);
      color: white;
      font-size: 1rem;
      font-family: inherit;
      resize: none;
      min-height: 48px;
      max-height: 150px;
    }

    textarea::placeholder {
      color: #666;
    }

    textarea:focus {
      outline: none;
      border-color: #4f46e5;
    }

    .send-btn {
      padding: 12px 24px;
      border-radius: 12px;
      border: none;
      background: #4f46e5;
      color: white;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .send-btn:hover:not(:disabled) {
      background: #4338ca;
    }

    .send-btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .spinner {
      width: 16px;
      height: 16px;
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

    .empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      height: 100%;
      color: #888;
      text-align: center;
      padding: 40px;
    }

    .empty-state-icon {
      font-size: 4rem;
      margin-bottom: 16px;
    }

    .empty-state h3 {
      font-size: 1.2rem;
      color: white;
      margin-bottom: 8px;
    }

    /* Mobile responsive styles */
    @media (max-width: 768px) {
      :host {
        height: calc(100vh - 120px);
        height: calc(100dvh - 120px);
      }

      .chat-container {
        border-radius: 12px;
      }

      .chat-header {
        padding: 12px 16px;
      }

      .chat-header h2 {
        font-size: 1rem;
      }

      .messages {
        padding: 16px;
        gap: 10px;
      }

      .message {
        max-width: 85%;
        padding: 10px 14px;
        font-size: 0.95rem;
      }

      .input-area {
        padding: 12px 16px;
      }

      .input-row {
        gap: 8px;
      }

      textarea {
        padding: 12px 14px;
        font-size: 16px; /* Prevents iOS zoom */
      }

      .send-btn {
        padding: 12px 16px;
      }
    }

    @media (max-width: 480px) {
      :host {
        height: calc(100vh - 100px);
        height: calc(100dvh - 100px);
      }

      .chat-header {
        padding: 10px 12px;
      }

      .connection-status {
        font-size: 0.75rem;
      }

      .messages {
        padding: 12px;
      }

      .message {
        max-width: 90%;
        padding: 10px 12px;
      }

      .input-area {
        padding: 10px 12px;
      }

      .empty-state {
        padding: 24px;
      }

      .empty-state-icon {
        font-size: 3rem;
      }
    }

    /* Safe area for notched phones */
    @supports (padding: env(safe-area-inset-bottom)) {
      .input-area {
        padding-bottom: calc(16px + env(safe-area-inset-bottom));
      }

      @media (max-width: 768px) {
        .input-area {
          padding-bottom: calc(12px + env(safe-area-inset-bottom));
        }
      }
    }
  `;

  @property({ type: Object })
  user: User | null = null;

  @state()
  private messages: ChatMessage[] = [];

  @state()
  private inputText = "";

  @state()
  private sending = false;

  @state()
  private connected = false;

  @state()
  private connectionError = "";

  @state()
  private streamingText = "";

  @state()
  private vaultStatus: VaultStatus | null = null;

  @state()
  private vaultCheckComplete = false;

  @state()
  private wakeStatus: WakeStatus = {
    phase: 'idle',
    message: '',
    isProvisioning: false,
  };

  private gateway: GatewayClient | null = null;
  private messagesContainer: HTMLElement | null = null;
  private currentRunId: string | null = null;

  connectedCallback() {
    super.connectedCallback();
    this.loadMessages();
    this.checkVaultAndConnect();
    // Listen for vault status changes from parent
    window.addEventListener("vault-status-changed", this.handleVaultStatusChange);
    // Scroll to bottom after messages are loaded and rendered
    this.updateComplete.then(() => this.scrollToBottom());
  }

  private async checkVaultAndConnect() {
    try {
      this.vaultStatus = await api.getVaultStatus();
      this.vaultCheckComplete = true;

      // Only connect if:
      // 1. User doesn't have a vault (optional), OR
      // 2. User has a vault and it's unlocked
      if (!this.vaultStatus.hasVault || this.vaultStatus.isUnlocked) {
        await this.connectGateway();
      }
    } catch (err) {
      console.error("Failed to check vault status:", err);
      this.vaultCheckComplete = true;
      // On error, try to connect anyway
      await this.connectGateway();
    }
  }

  private requiresVaultUnlock(): boolean {
    return this.vaultStatus?.hasVault === true && !this.vaultStatus.isUnlocked;
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    this.gateway?.stop();
    window.removeEventListener("vault-status-changed", this.handleVaultStatusChange);
  }

  private handleVaultStatusChange = () => {
    this.checkVaultAndConnect();
  };

  // Public method to refresh vault status (called from parent when vault is unlocked)
  public async refreshVaultStatus() {
    await this.checkVaultAndConnect();
  }

  private loadMessages() {
    const saved = localStorage.getItem(`ocmt_messages_${this.user?.id}`);
    if (saved) {
      try {
        this.messages = JSON.parse(saved);
      } catch {
        this.messages = [];
      }
    }
  }

  private saveMessages() {
    if (this.user?.id) {
      const toSave = this.messages.slice(-100); // Keep last 100 messages
      localStorage.setItem(`ocmt_messages_${this.user.id}`, JSON.stringify(toSave));
    }
  }

  private async connectGateway() {
    let gatewayInfo = api.getGatewayInfo();

    // If no gateway info cached, try to refresh from server
    if (!gatewayInfo) {
      try {
        console.log("[dashboard] no cached gateway, fetching from server...");
        const { gateway } = await api.getMe();
        gatewayInfo = gateway || null;
      } catch (err) {
        console.error("[dashboard] failed to fetch gateway info:", err);
      }
    }

    if (!gatewayInfo) {
      this.connectionError = "No container available. Please try logging out and back in.";
      return;
    }

    this.gateway = new GatewayClient({
      host: gatewayInfo.host,
      port: gatewayInfo.port,
      token: gatewayInfo.token,
      onConnected: () => {
        this.connected = true;
        this.connectionError = "";
        this.wakeStatus = { phase: 'ready', message: '', isProvisioning: false };
        console.log("[dashboard] gateway connected");
      },
      onDisconnected: (reason) => {
        this.connected = false;
        // Make error messages user-friendly
        if (reason.includes("1006") || reason.includes("1005")) {
          this.connectionError = ""; // Will show "Connecting..." instead of error code
        } else {
          this.connectionError = reason || "Disconnected";
        }
        this.wakeStatus = { phase: 'idle', message: '', isProvisioning: false };
      },
      onChatEvent: (event) => this.handleChatEvent(event),
      onError: (error) => {
        this.connectionError = error;
        this.wakeStatus = { phase: 'error', message: error, isProvisioning: false };
      },
      onWakeStatus: (status) => {
        this.wakeStatus = status;
      },
    });

    this.gateway.start();
  }

  private handleChatEvent(event: ChatEvent) {
    console.log("[dashboard] chat event:", event.state, event);

    switch (event.state) {
      case "started":
        this.currentRunId = event.runId;
        this.streamingText = "";
        break;

      case "delta":
        if (event.runId === this.currentRunId) {
          // Extract text from message content (gateway sends full message in delta)
          if (event.message?.content) {
            const textContent = event.message.content.find((c) => c.type === "text");
            if (textContent?.text) {
              this.streamingText = textContent.text.trim();
            }
          } else if (event.delta) {
            // Fallback if delta is a string
            this.streamingText += event.delta;
          }
        }
        break;

      case "final":
        if (event.runId === this.currentRunId) {
          // Extract text from message
          let text = this.streamingText.trim();
          if (event.message?.content) {
            const textContent = event.message.content.find((c) => c.type === "text");
            if (textContent?.text) {
              text = textContent.text.trim();
            }
          }

          if (text) {
            const msg: ChatMessage = {
              role: "assistant",
              content: text,
              timestamp: new Date().toISOString(),
            };
            this.messages = [...this.messages, msg];
            this.saveMessages();
            this.scrollToBottom();
          }

          this.streamingText = "";
          this.currentRunId = null;
          this.sending = false;
        }
        break;

      case "error":
        if (event.runId === this.currentRunId) {
          const msg: ChatMessage = {
            role: "system",
            content: `Error: ${event.errorMessage || "Unknown error"}`,
            timestamp: new Date().toISOString(),
          };
          this.messages = [...this.messages, msg];
          this.saveMessages();
          this.scrollToBottom();
          this.streamingText = "";
          this.currentRunId = null;
          this.sending = false;
        }
        break;
    }
  }

  private scrollToBottom() {
    requestAnimationFrame(() => {
      const container = this.shadowRoot?.querySelector(".messages");
      if (container) {
        container.scrollTop = container.scrollHeight;
      }
    });
  }

  private async handleSend() {
    const text = this.inputText.trim();
    if (!text || this.sending || !this.gateway?.connected) {
      return;
    }

    this.inputText = "";
    this.sending = true;

    // Add user message immediately
    const userMsg: ChatMessage = {
      role: "user",
      content: text,
      timestamp: new Date().toISOString(),
    };
    this.messages = [...this.messages, userMsg];
    this.saveMessages();
    this.scrollToBottom();

    try {
      const result = await this.gateway.sendMessage(text);
      console.log("[dashboard] send result:", result);
      // Set currentRunId so we can match incoming delta/final events
      this.currentRunId = result.runId;
      this.streamingText = "";
    } catch (err) {
      console.error("Send error:", err);
      const errorMsg: ChatMessage = {
        role: "system",
        content: `Send failed: ${err instanceof Error ? err.message : String(err)}`,
        timestamp: new Date().toISOString(),
      };
      this.messages = [...this.messages, errorMsg];
      this.saveMessages();
      this.sending = false;
    }

    this.scrollToBottom();

    // Focus back on input
    const textarea = this.shadowRoot?.querySelector("textarea");
    textarea?.focus();
  }

  private handleKeyDown(e: KeyboardEvent) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      this.handleSend();
    }
  }

  private handleInput(e: Event) {
    const textarea = e.target as HTMLTextAreaElement;
    this.inputText = textarea.value;

    // Auto-resize textarea
    textarea.style.height = "auto";
    textarea.style.height = Math.min(textarea.scrollHeight, 150) + "px";
  }

  render() {
    // Show loading while checking vault status
    if (!this.vaultCheckComplete) {
      return html`
        <div class="chat-container">
          <div class="empty-state">
            <div class="spinner" style="width: 40px; height: 40px"></div>
            <p style="margin-top: 16px">Loading...</p>
          </div>
        </div>
      `;
    }

    // Show vault locked message if vault requires unlock
    if (this.requiresVaultUnlock()) {
      return html`
        <div class="chat-container">
          <div class="chat-header">
            <h2>Chat with your AI</h2>
            <div class="connection-status">
              <div class="status-dot"></div>
              Vault Locked
            </div>
          </div>
          <div class="empty-state">
            <div class="empty-state-icon">🔐</div>
            <h3>Vault is Locked</h3>
            <p>Please unlock your vault to chat with your AI assistant.</p>
            <p style="font-size: 0.9rem; color: #666; margin-top: 8px">
              Your credentials are encrypted and need to be unlocked.
            </p>
          </div>
        </div>
      `;
    }

    return html`
      <div class="chat-container">
        <div class="chat-header">
          <h2>Chat with your AI</h2>
          ${this.renderConnectionStatus()}
        </div>

        <div class="messages">
          ${this.messages.length === 0 && !this.streamingText ? this.renderEmptyState() : this.renderMessages()}
          ${this.streamingText ? html`<div class="message assistant streaming"><div class="message-content">${unsafeHTML(toSanitizedMarkdownHtml(this.streamingText))}</div></div>` : ""}
          ${
            this.sending && !this.streamingText
              ? html`
                  <div class="typing-indicator">
                    <div class="typing-dot"></div>
                    <div class="typing-dot"></div>
                    <div class="typing-dot"></div>
                  </div>
                `
              : ""
          }
        </div>

        <div class="input-area">
          <div class="input-row">
            <textarea
              placeholder="Type your message..."
              .value=${this.inputText}
              @input=${this.handleInput}
              @keydown=${this.handleKeyDown}
              ?disabled=${this.sending}
              rows="1"
            ></textarea>
            <button
              class="send-btn"
              @click=${this.handleSend}
              ?disabled=${!this.inputText.trim() || this.sending}
            >
              ${
                this.sending
                  ? html`
                      <div class="spinner"></div>
                    `
                  : "Send"
              }
            </button>
          </div>
        </div>
      </div>
    `;
  }

  private renderConnectionStatus() {
    // Connected state
    if (this.connected) {
      return html`
        <div class="connection-status">
          <div class="status-dot connected"></div>
          Connected
        </div>
      `;
    }

    // Error state
    if (this.connectionError) {
      return html`
        <div class="connection-status">
          <div class="status-dot error"></div>
          ${this.connectionError}
        </div>
      `;
    }

    // Provisioning state (first-time setup)
    if (this.wakeStatus.isProvisioning) {
      return html`
        <div class="connection-status">
          <div class="status-dot provisioning"></div>
          <div>
            <div>Setting up your environment...</div>
            <div class="connection-status-detail">This may take a minute or two</div>
          </div>
          <div class="progress-bar">
            <div class="progress-bar-fill"></div>
          </div>
        </div>
      `;
    }

    // Waking from hibernation
    if (this.wakeStatus.phase === 'waking') {
      return html`
        <div class="connection-status">
          <div class="status-dot waking"></div>
          <div>
            <div>Waking up container...</div>
            <div class="connection-status-detail">Just a moment</div>
          </div>
        </div>
      `;
    }

    // Connecting state
    if (this.wakeStatus.phase === 'connecting') {
      return html`
        <div class="connection-status">
          <div class="status-dot"></div>
          Connecting...
        </div>
      `;
    }

    // Default connecting state
    return html`
      <div class="connection-status">
        <div class="status-dot"></div>
        Connecting...
      </div>
    `;
  }

  private renderEmptyState() {
    return html`
      <div class="empty-state">
        <div class="empty-state-icon">💬</div>
        <h3>Start a conversation</h3>
        <p>Send a message to start chatting with your AI assistant.</p>
      </div>
    `;
  }

  private renderMessages() {
    return this.messages.map(
      (msg) => html`
      <div class="message ${msg.role}">
        <div class="message-content">${msg.role === "assistant" ? unsafeHTML(toSanitizedMarkdownHtml(msg.content)) : msg.content}</div>
        ${msg.timestamp ? html`<div class="message-time">${this.formatTime(msg.timestamp)}</div>` : ""}
      </div>
    `,
    );
  }

  private formatTime(timestamp: string): string {
    const date = new Date(timestamp);
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-dashboard": DashboardPage;
  }
}

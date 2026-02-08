import { LitElement, html, css } from "lit";
import { customElement, state } from "lit/decorators.js";

export interface ToastMessage {
  id: string;
  type: "success" | "error" | "info" | "warning";
  message: string;
  duration?: number;
}

// Global toast manager
class ToastManager {
  private static instance: ToastManager;
  private listeners: Set<(toasts: ToastMessage[]) => void> = new Set();
  private toasts: ToastMessage[] = [];

  static getInstance(): ToastManager {
    if (!ToastManager.instance) {
      ToastManager.instance = new ToastManager();
    }
    return ToastManager.instance;
  }

  show(type: ToastMessage["type"], message: string, duration = 5000): string {
    const id = Math.random().toString(36).substring(2);
    const toast: ToastMessage = { id, type, message, duration };

    this.toasts = [...this.toasts, toast];
    this.notify();

    if (duration > 0) {
      setTimeout(() => this.dismiss(id), duration);
    }

    return id;
  }

  dismiss(id: string) {
    this.toasts = this.toasts.filter((t) => t.id !== id);
    this.notify();
  }

  subscribe(listener: (toasts: ToastMessage[]) => void) {
    this.listeners.add(listener);
    listener(this.toasts);
    return () => this.listeners.delete(listener);
  }

  private notify() {
    this.listeners.forEach((listener) => listener(this.toasts));
  }
}

// Export toast helper functions
export const toast = {
  success: (message: string, duration?: number) =>
    ToastManager.getInstance().show("success", message, duration),
  error: (message: string, duration?: number) =>
    ToastManager.getInstance().show("error", message, duration ?? 8000),
  info: (message: string, duration?: number) =>
    ToastManager.getInstance().show("info", message, duration),
  warning: (message: string, duration?: number) =>
    ToastManager.getInstance().show("warning", message, duration ?? 6000),
  dismiss: (id: string) => ToastManager.getInstance().dismiss(id),
};

@customElement("ocmt-toast-container")
export class ToastContainer extends LitElement {
  static styles = css`
    :host {
      position: fixed;
      bottom: 24px;
      right: 24px;
      z-index: 9999;
      display: flex;
      flex-direction: column;
      gap: 8px;
      max-width: 400px;
      pointer-events: none;
    }

    @media (max-width: 480px) {
      :host {
        left: 16px;
        right: 16px;
        bottom: 16px;
        max-width: none;
      }
    }

    .toast {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      padding: 14px 16px;
      border-radius: 10px;
      background: #1e1e2e;
      border: 1px solid rgba(255, 255, 255, 0.1);
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
      animation: slideIn 0.3s ease-out;
      pointer-events: auto;
    }

    .toast.leaving {
      animation: slideOut 0.2s ease-in forwards;
    }

    @keyframes slideIn {
      from {
        opacity: 0;
        transform: translateX(100%);
      }
      to {
        opacity: 1;
        transform: translateX(0);
      }
    }

    @keyframes slideOut {
      from {
        opacity: 1;
        transform: translateX(0);
      }
      to {
        opacity: 0;
        transform: translateX(100%);
      }
    }

    .toast-icon {
      font-size: 1.2rem;
      flex-shrink: 0;
    }

    .toast-content {
      flex: 1;
      min-width: 0;
    }

    .toast-message {
      color: #e0e0e0;
      font-size: 0.9rem;
      line-height: 1.4;
    }

    .toast-close {
      background: none;
      border: none;
      color: #666;
      cursor: pointer;
      padding: 0;
      font-size: 1.2rem;
      line-height: 1;
      flex-shrink: 0;
    }

    .toast-close:hover {
      color: #aaa;
    }

    .toast.success {
      border-color: rgba(34, 197, 94, 0.3);
    }

    .toast.success .toast-icon {
      color: #22c55e;
    }

    .toast.error {
      border-color: rgba(239, 68, 68, 0.3);
    }

    .toast.error .toast-icon {
      color: #ef4444;
    }

    .toast.warning {
      border-color: rgba(245, 158, 11, 0.3);
    }

    .toast.warning .toast-icon {
      color: #f59e0b;
    }

    .toast.info {
      border-color: rgba(79, 70, 229, 0.3);
    }

    .toast.info .toast-icon {
      color: #818cf8;
    }
  `;

  @state()
  private toasts: ToastMessage[] = [];

  private unsubscribe?: () => void;

  connectedCallback() {
    super.connectedCallback();
    this.unsubscribe = ToastManager.getInstance().subscribe((toasts) => {
      this.toasts = toasts;
    });
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    this.unsubscribe?.();
  }

  private getIcon(type: ToastMessage["type"]): string {
    switch (type) {
      case "success":
        return "✓";
      case "error":
        return "✕";
      case "warning":
        return "⚠";
      case "info":
        return "ℹ";
    }
  }

  private handleDismiss(id: string) {
    toast.dismiss(id);
  }

  render() {
    return html`
      ${this.toasts.map(
        (t) => html`
        <div class="toast ${t.type}">
          <span class="toast-icon">${this.getIcon(t.type)}</span>
          <div class="toast-content">
            <div class="toast-message">${t.message}</div>
          </div>
          <button class="toast-close" @click=${() => this.handleDismiss(t.id)}>×</button>
        </div>
      `,
      )}
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-toast-container": ToastContainer;
  }
}

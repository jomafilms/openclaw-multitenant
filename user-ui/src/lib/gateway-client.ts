// Gateway client for direct WebSocket connection to user's container
// Based on OpenClaw's GatewayBrowserClient protocol

import { api } from './api.js';

export interface ChatEvent {
  runId: string;
  sessionKey: string;
  seq: number;
  state: 'started' | 'delta' | 'final' | 'error';
  delta?: string;
  message?: {
    role: string;
    content: Array<{ type: string; text?: string }>;
    timestamp?: number;
  };
  errorMessage?: string;
}

export interface WakeStatus {
  phase: 'idle' | 'waking' | 'connecting' | 'ready' | 'error';
  message: string;
  isProvisioning: boolean;
  previousState?: string;
}

export interface GatewayClientOptions {
  host: string;
  port: number;
  token: string;
  onConnected?: () => void;
  onDisconnected?: (reason: string) => void;
  onChatEvent?: (event: ChatEvent) => void;
  onError?: (error: string) => void;
  onWaking?: (waking: boolean, message?: string) => void;
  onWakeStatus?: (status: WakeStatus) => void;
}

type Pending = {
  resolve: (value: unknown) => void;
  reject: (err: unknown) => void;
};

export class GatewayClient {
  private ws: WebSocket | null = null;
  private pending = new Map<string, Pending>();
  private closed = false;
  private connectNonce: string | null = null;
  private connectSent = false;
  private backoffMs = 800;
  private sessionKey = 'main';
  private messageSeq = 0;

  constructor(private opts: GatewayClientOptions) {}

  async start() {
    this.closed = false;
    await this.wakeAndConnect();
  }

  private async wakeAndConnect() {
    // Wake container from hibernation before connecting
    try {
      console.log('[gateway] waking container...');

      // Determine initial message based on context
      this.opts.onWaking?.(true, 'Waking up container...');
      this.opts.onWakeStatus?.({
        phase: 'waking',
        message: 'Checking container status...',
        isProvisioning: false,
      });

      const result = await api.wakeContainer();
      console.log('[gateway] container awake in', result.wakeTime, 'ms, previousState:', result.previousState, 'isFirstWake:', result.isFirstWake);

      // Provide contextual feedback based on wake result
      if (result.isFirstWake) {
        // First time provisioning
        this.opts.onWakeStatus?.({
          phase: 'waking',
          message: 'Setting up your environment...',
          isProvisioning: true,
          previousState: result.previousState,
        });
        this.opts.onWaking?.(true, 'Setting up your environment...');
      } else if (result.previousState === 'paused' || result.previousState === 'stopped') {
        // Waking from hibernation
        this.opts.onWakeStatus?.({
          phase: 'waking',
          message: 'Waking up container...',
          isProvisioning: false,
          previousState: result.previousState,
        });
        this.opts.onWaking?.(true, 'Waking up container...');
      } else if (result.wakeTime > 0) {
        // Normal wake with some delay
        this.opts.onWakeStatus?.({
          phase: 'waking',
          message: `Container woke in ${Math.round(result.wakeTime / 1000)}s`,
          isProvisioning: false,
          previousState: result.previousState,
        });
        this.opts.onWaking?.(true, `Container woke in ${Math.round(result.wakeTime / 1000)}s`);
      }

      // Give gateway a moment to fully start after wake
      if (result.wakeTime > 1000) {
        await new Promise(r => setTimeout(r, 500));
      }

      // Transition to connecting phase
      this.opts.onWakeStatus?.({
        phase: 'connecting',
        message: 'Connecting...',
        isProvisioning: false,
      });
      this.opts.onWaking?.(false);
    } catch (err) {
      console.warn('[gateway] wake failed, will retry on reconnect:', err);
      this.opts.onWakeStatus?.({
        phase: 'error',
        message: 'Wake failed, retrying...',
        isProvisioning: false,
      });
      this.opts.onWaking?.(false, 'Wake failed, retrying...');
    }
    this.connect();
  }

  stop() {
    this.closed = true;
    this.ws?.close();
    this.ws = null;
    this.flushPending(new Error('gateway client stopped'));
  }

  get connected() {
    return this.ws?.readyState === WebSocket.OPEN && this.connectSent;
  }

  private connect() {
    if (this.closed) return;

    // Connect to container gateway
    // In production (HTTPS), use nginx proxy; in development, connect directly
    const isSecure = window.location.protocol === 'https:';
    const url = isSecure
      ? `wss://${window.location.host}/ws/${this.opts.port}/`
      : `ws://${this.opts.host}:${this.opts.port}`;
    console.log('[gateway] connecting to', url);

    this.ws = new WebSocket(url);

    this.ws.addEventListener('open', () => {
      console.log('[gateway] socket open, waiting for challenge');
      this.queueConnect();
    });

    this.ws.addEventListener('message', (ev) => {
      this.handleMessage(String(ev.data ?? ''));
    });

    this.ws.addEventListener('close', (ev) => {
      const reason = String(ev.reason || '');
      console.log('[gateway] closed:', ev.code, reason);
      this.ws = null;
      this.connectSent = false;
      this.flushPending(new Error(`gateway closed (${ev.code}): ${reason}`));
      this.opts.onDisconnected?.(reason || `Code ${ev.code}`);
      this.scheduleReconnect();
    });

    this.ws.addEventListener('error', (ev) => {
      console.error('[gateway] error:', ev);
    });
  }

  private scheduleReconnect() {
    if (this.closed) return;
    const delay = this.backoffMs;
    this.backoffMs = Math.min(this.backoffMs * 1.7, 15000);
    // Wake container on reconnect too (may have hibernated)
    setTimeout(() => this.wakeAndConnect(), delay);
  }

  private flushPending(err: Error) {
    for (const [, p] of this.pending) {
      p.reject(err);
    }
    this.pending.clear();
  }

  private queueConnect() {
    this.connectNonce = null;
    this.connectSent = false;
    // Wait briefly for challenge event
    setTimeout(() => {
      if (!this.connectSent && this.ws?.readyState === WebSocket.OPEN) {
        this.sendConnect();
      }
    }, 750);
  }

  private async sendConnect() {
    if (this.connectSent) return;
    this.connectSent = true;

    const params = {
      minProtocol: 3,
      maxProtocol: 3,
      client: {
        id: 'openclaw-control-ui',  // Must be a valid OpenClaw client ID
        version: '1.0.0',
        platform: navigator.platform || 'web',
        mode: 'webchat',
      },
      role: 'operator',
      scopes: ['operator.admin'],
      caps: [],
      auth: {
        token: this.opts.token,
      },
      userAgent: navigator.userAgent,
    };

    try {
      const hello = await this.request<{ protocol: number; features?: unknown }>('connect', params);
      console.log('[gateway] connected, protocol:', hello.protocol);
      this.backoffMs = 800;
      this.opts.onConnected?.();
    } catch (err) {
      console.error('[gateway] connect failed:', err);
      this.opts.onError?.(err instanceof Error ? err.message : String(err));
      this.ws?.close(4008, 'connect failed');
    }
  }

  private handleMessage(raw: string) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return;
    }

    const frame = parsed as { type?: string; event?: string; payload?: unknown; id?: string; ok?: boolean; error?: { message?: string } };

    // Event frame
    if (frame.type === 'event') {
      if (frame.event === 'connect.challenge') {
        const payload = frame.payload as { nonce?: string } | undefined;
        if (payload?.nonce) {
          this.connectNonce = payload.nonce;
          this.sendConnect();
        }
        return;
      }

      // Chat event
      if (frame.event === 'chat') {
        const chatEvent = frame.payload as ChatEvent;
        this.opts.onChatEvent?.(chatEvent);
      }
      return;
    }

    // Response frame
    if (frame.type === 'res' && frame.id) {
      const pending = this.pending.get(frame.id);
      if (!pending) return;
      this.pending.delete(frame.id);
      if (frame.ok) {
        pending.resolve(frame.payload);
      } else {
        pending.reject(new Error(frame.error?.message ?? 'request failed'));
      }
    }
  }

  private generateId(): string {
    return Math.random().toString(36).slice(2) + Date.now().toString(36);
  }

  request<T = unknown>(method: string, params?: unknown): Promise<T> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      return Promise.reject(new Error('gateway not connected'));
    }

    const id = this.generateId();
    const frame = { type: 'req', id, method, params };

    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, {
        resolve: (v) => resolve(v as T),
        reject
      });
      this.ws!.send(JSON.stringify(frame));
    });
  }

  // Send a chat message
  async sendMessage(message: string): Promise<{ runId: string; status: string }> {
    const idempotencyKey = this.generateId();

    return this.request('chat.send', {
      sessionKey: this.sessionKey,
      message,
      idempotencyKey,
    });
  }

  // Get chat history
  async getHistory(limit = 100): Promise<{ messages: unknown[]; sessionKey: string }> {
    return this.request('chat.history', {
      sessionKey: this.sessionKey,
      limit,
    });
  }
}

/**
 * Secure transcript writing with encrypted session support.
 *
 * This module provides a wrapper around session transcript writing that
 * uses encrypted storage when the vault is unlocked, falling back to
 * plaintext when the vault is locked (for backward compatibility).
 *
 * Security model:
 * - When vault is unlocked: All messages written to encrypted .jsonl.enc files
 * - When vault is locked: Falls back to plaintext (migration period only)
 * - New sessions always prefer encrypted when vault is unlocked
 */

import { CURRENT_SESSION_VERSION, SessionManager } from "@mariozechner/pi-coding-agent";
import fs from "node:fs";
import path from "node:path";
import type { SessionEntry } from "./types.js";
import { emitSessionTranscriptUpdate } from "../../sessions/transcript-events.js";
import { getSecureSessionStore, type Message as SecureMessage } from "./encrypted-store.js";
import { resolveDefaultSessionStorePath, resolveSessionTranscriptPath } from "./paths.js";
import { loadSessionStore, updateSessionStore } from "./store.js";

// ============================================================================
// Types
// ============================================================================

export interface SecureTranscriptResult {
  ok: boolean;
  sessionFile?: string;
  encrypted?: boolean;
  reason?: string;
}

export interface VaultStatusForTranscript {
  initialized: boolean;
  unlocked: boolean;
}

// ============================================================================
// Vault Status Check
// ============================================================================

/**
 * Get vault status for transcript writing.
 * Returns whether the vault is available and unlocked.
 */
export function getVaultStatusForTranscript(sessionDir?: string): VaultStatusForTranscript {
  const store = getSecureSessionStore(sessionDir);

  if (!store) {
    return { initialized: false, unlocked: false };
  }

  return {
    initialized: true,
    unlocked: store.isUnlocked(),
  };
}

// ============================================================================
// Secure Transcript Writing
// ============================================================================

/**
 * Append an assistant message to a session transcript.
 * Uses encrypted storage when vault is unlocked.
 *
 * @param params - Message parameters
 * @returns Result with success status and encryption info
 */
export async function appendSecureMessage(params: {
  agentId?: string;
  sessionKey: string;
  text?: string;
  mediaUrls?: string[];
  role?: "user" | "assistant" | "system";
  storePath?: string;
  /** If true, require encryption - fail if vault is locked */
  requireEncryption?: boolean;
}): Promise<SecureTranscriptResult> {
  const sessionKey = params.sessionKey.trim();
  if (!sessionKey) {
    return { ok: false, reason: "missing sessionKey" };
  }

  const mirrorText = resolveMirroredTranscriptText({
    text: params.text,
    mediaUrls: params.mediaUrls,
  });
  if (!mirrorText) {
    return { ok: false, reason: "empty text" };
  }

  const storePath = params.storePath ?? resolveDefaultSessionStorePath(params.agentId);
  const store = loadSessionStore(storePath, { skipCache: true });
  const entry = store[sessionKey] as SessionEntry | undefined;
  if (!entry?.sessionId) {
    return { ok: false, reason: `unknown sessionKey: ${sessionKey}` };
  }

  // Check if we can use encrypted storage
  const sessionDir = path.dirname(resolveSessionTranscriptPath(entry.sessionId, params.agentId));
  const secureStore = getSecureSessionStore(sessionDir);
  const useEncryption = secureStore?.isUnlocked() ?? false;

  // If encryption is required but vault is locked, fail
  if (params.requireEncryption && !useEncryption) {
    return { ok: false, reason: "Vault is locked - encryption required" };
  }

  if (useEncryption && secureStore) {
    // Use encrypted storage
    try {
      const message: SecureMessage = {
        role: params.role ?? "assistant",
        content: mirrorText,
      };

      await secureStore.appendMessage(entry.sessionId, message);

      // Update session entry if needed
      const encryptedFile = `${sessionDir}/${entry.sessionId}.jsonl.enc`;
      if (!entry.sessionFile || entry.sessionFile !== encryptedFile) {
        await updateSessionStore(storePath, (current) => {
          current[sessionKey] = {
            ...entry,
            sessionFile: encryptedFile,
          };
        });
      }

      emitSessionTranscriptUpdate(encryptedFile);
      return { ok: true, sessionFile: encryptedFile, encrypted: true };
    } catch (err) {
      console.error("Failed to write encrypted message:", err);
      // Fall back to plaintext if encryption fails
      if (params.requireEncryption) {
        return { ok: false, reason: `Encryption failed: ${(err as Error).message}` };
      }
    }
  }

  // Fall back to plaintext
  const sessionFile =
    entry.sessionFile?.trim() || resolveSessionTranscriptPath(entry.sessionId, params.agentId);

  await ensureSessionHeader({ sessionFile, sessionId: entry.sessionId });

  const sessionManager = SessionManager.open(sessionFile);
  // SessionManager uses specific role types
  const smRole = params.role === "system" ? "assistant" : (params.role ?? "assistant");
  sessionManager.appendMessage({
    role: smRole as "user" | "assistant",
    content: [{ type: "text", text: mirrorText }],
    api: "openai-responses",
    provider: "openclaw",
    model: "delivery-mirror",
    usage: {
      input: 0,
      output: 0,
      cacheRead: 0,
      cacheWrite: 0,
      totalTokens: 0,
      cost: {
        input: 0,
        output: 0,
        cacheRead: 0,
        cacheWrite: 0,
        total: 0,
      },
    },
    stopReason: "stop",
    timestamp: Date.now(),
  });

  if (!entry.sessionFile || entry.sessionFile !== sessionFile) {
    await updateSessionStore(storePath, (current) => {
      current[sessionKey] = {
        ...entry,
        sessionFile,
      };
    });
  }

  emitSessionTranscriptUpdate(sessionFile);
  return { ok: true, sessionFile, encrypted: false };
}

// ============================================================================
// Helper Functions
// ============================================================================

function resolveMirroredTranscriptText(params: {
  text?: string;
  mediaUrls?: string[];
}): string | null {
  const mediaUrls = params.mediaUrls?.filter((url) => url && url.trim()) ?? [];
  if (mediaUrls.length > 0) {
    const names = mediaUrls
      .map((url) => extractFileNameFromMediaUrl(url))
      .filter((name): name is string => Boolean(name && name.trim()));
    if (names.length > 0) {
      return names.join(", ");
    }
    return "media";
  }

  const text = params.text ?? "";
  const trimmed = text.trim();
  return trimmed ? trimmed : null;
}

function stripQuery(value: string): string {
  const noHash = value.split("#")[0] ?? value;
  return noHash.split("?")[0] ?? noHash;
}

function extractFileNameFromMediaUrl(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  const cleaned = stripQuery(trimmed);
  try {
    const parsed = new URL(cleaned);
    const base = path.basename(parsed.pathname);
    if (!base) {
      return null;
    }
    try {
      return decodeURIComponent(base);
    } catch {
      return base;
    }
  } catch {
    const base = path.basename(cleaned);
    if (!base || base === "/" || base === ".") {
      return null;
    }
    return base;
  }
}

async function ensureSessionHeader(params: {
  sessionFile: string;
  sessionId: string;
}): Promise<void> {
  if (fs.existsSync(params.sessionFile)) {
    return;
  }
  await fs.promises.mkdir(path.dirname(params.sessionFile), { recursive: true });
  const header = {
    type: "session",
    version: CURRENT_SESSION_VERSION,
    id: params.sessionId,
    timestamp: new Date().toISOString(),
    cwd: process.cwd(),
  };
  await fs.promises.writeFile(params.sessionFile, `${JSON.stringify(header)}\n`, "utf-8");
}

// ============================================================================
// Error Types
// ============================================================================

/**
 * Error thrown when vault is locked but encryption is required.
 */
export class VaultLockedError extends Error {
  constructor(
    message: string,
    public readonly unlockUrl?: string,
  ) {
    super(message);
    this.name = "VaultLockedError";
  }
}

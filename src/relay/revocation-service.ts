/**
 * Relay Revocation Service
 *
 * HTTP service for handling capability revocations at the relay level.
 * This provides instant revocation enforcement across the mesh network.
 *
 * Trust Model:
 * The relay gains enforcement power by maintaining a revocation blocklist.
 * This is a deliberate trust tradeoff:
 *
 * - PRO: Instant revocation - no waiting for capability expiry
 * - PRO: Network-wide enforcement - all relays can check revocations
 * - CON: Relay can deny service by falsely claiming revocation
 * - CON: Relay learns which capabilities are being used (metadata leakage)
 *
 * Mitigations:
 * 1. Revocations are signed by the issuer - relay cannot forge revocations
 * 2. Relays are operated by trusted parties (or self-hosted)
 * 3. Capabilities still work if relay is unavailable (degrade to expiry-only)
 * 4. Audit logging enables detection of malicious relay behavior
 *
 * @see docs/mesh/trust-model.md for full security analysis
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { verify as cryptoVerify, createPublicKey } from "crypto";
import { getRevocationStore, type RevocationStore } from "./revocation-store.js";

// Ed25519 SPKI prefix for DER-encoded public keys
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface RevocationRequest {
  /** The capability ID to revoke */
  capabilityId: string;
  /** Public key of the revoker (must match capability issuer) */
  revokedBy: string;
  /** Signature of the revocation (signed by issuer's private key) */
  signature: string;
  /** Optional reason for revocation */
  reason?: string;
  /** Original capability expiry (for cleanup scheduling) */
  originalExpiry?: string;
  /** Timestamp of the revocation request */
  timestamp: string;
}

export interface RevocationResponse {
  success: boolean;
  revocationId?: string;
  error?: string;
}

export interface RevocationCheckRequest {
  capabilityId: string;
}

export interface RevocationCheckResponse {
  revoked: boolean;
  revokedAt?: string;
  revokedBy?: string;
  reason?: string;
}

/**
 * Verify that a revocation request is properly signed by the issuer.
 */
function verifyRevocationSignature(request: RevocationRequest): boolean {
  try {
    const { capabilityId, revokedBy, signature, reason, originalExpiry, timestamp } = request;

    // Reconstruct the signed payload
    const payload = JSON.stringify({
      action: "revoke",
      capabilityId,
      revokedBy,
      reason,
      originalExpiry,
      timestamp,
    });

    // Reconstruct SPKI-encoded DER format for Ed25519 public key
    const rawKey = Buffer.from(revokedBy, "base64");
    if (rawKey.length !== 32) {
      console.warn("[RevocationService] Invalid public key length:", rawKey.length);
      return false;
    }

    const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX, rawKey]);
    const publicKey = createPublicKey({ key: spkiDer, type: "spki", format: "der" });

    // Verify Ed25519 signature (null algorithm for Ed25519)
    const signatureBuffer = Buffer.from(signature, "base64");

    // Ed25519 signatures are always 64 bytes
    if (signatureBuffer.length !== 64) {
      console.warn("[RevocationService] Invalid signature length:", signatureBuffer.length);
      return false;
    }

    return cryptoVerify(null, Buffer.from(payload, "utf-8"), publicKey, signatureBuffer);
  } catch (err) {
    console.error("[RevocationService] Signature verification failed:", err);
    return false;
  }
}

/**
 * Create the revocation service handler.
 */
export function createRevocationService(store?: RevocationStore) {
  const revocationStore = store ?? getRevocationStore();

  return {
    /**
     * Handle a revocation request.
     */
    async handleRevoke(request: RevocationRequest): Promise<RevocationResponse> {
      // Validate request
      if (!request.capabilityId || !request.revokedBy || !request.signature) {
        return {
          success: false,
          error: "Missing required fields: capabilityId, revokedBy, signature",
        };
      }

      // Verify timestamp is recent (within 5 minutes)
      const requestTime = new Date(request.timestamp).getTime();
      const now = Date.now();
      if (Math.abs(now - requestTime) > 5 * 60 * 1000) {
        return {
          success: false,
          error: "Revocation request timestamp is too old or in the future",
        };
      }

      // Verify signature
      if (!verifyRevocationSignature(request)) {
        return {
          success: false,
          error: "Invalid signature - revocation must be signed by capability issuer",
        };
      }

      // Record the revocation
      try {
        const record = await revocationStore.revoke(request.capabilityId, request.revokedBy, {
          reason: request.reason,
          originalExpiry: request.originalExpiry,
        });

        console.log(
          `[RevocationService] Revoked capability ${request.capabilityId} by ${request.revokedBy}`,
        );

        return {
          success: true,
          revocationId: record.capabilityId,
        };
      } catch (err) {
        return {
          success: false,
          error: `Failed to record revocation: ${(err as Error).message}`,
        };
      }
    },

    /**
     * Check if a capability is revoked.
     */
    checkRevocation(capabilityId: string): RevocationCheckResponse {
      const result = revocationStore.isRevoked(capabilityId);

      if (result.revoked && result.record) {
        return {
          revoked: true,
          revokedAt: result.record.revokedAt,
          revokedBy: result.record.revokedBy,
          reason: result.record.reason,
        };
      }

      return { revoked: false };
    },

    /**
     * Get revocation store statistics.
     */
    getStats() {
      return revocationStore.getStats();
    },

    /**
     * Run cleanup of expired revocations.
     */
    async cleanup(): Promise<number> {
      return revocationStore.cleanup();
    },
  };
}

/**
 * HTTP handler for revocation endpoints.
 * Integrates with the relay's HTTP server.
 */
export async function handleRevocationHttpRequest(
  req: IncomingMessage,
  res: ServerResponse,
  service: ReturnType<typeof createRevocationService>,
): Promise<boolean> {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);

  // POST /relay/revoke - Submit a revocation
  if (url.pathname === "/relay/revoke" && req.method === "POST") {
    try {
      const body = await readJsonBody(req);
      const result = await service.handleRevoke(body as RevocationRequest);

      res.writeHead(result.success ? 200 : 400, { "Content-Type": "application/json" });
      res.end(JSON.stringify(result));
      return true;
    } catch (err) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: false, error: (err as Error).message }));
      return true;
    }
  }

  // GET /relay/revocation/:capabilityId - Check revocation status
  const checkMatch = url.pathname.match(/^\/relay\/revocation\/([^/]+)$/);
  if (checkMatch && req.method === "GET") {
    const capabilityId = decodeURIComponent(checkMatch[1]);
    const result = service.checkRevocation(capabilityId);

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(result));
    return true;
  }

  // POST /relay/check-revocations - Batch check revocations
  if (url.pathname === "/relay/check-revocations" && req.method === "POST") {
    try {
      const body = await readJsonBody(req);
      const capabilityIds = (body as { capabilityIds: string[] }).capabilityIds ?? [];

      const results: Record<string, RevocationCheckResponse> = {};
      for (const id of capabilityIds) {
        results[id] = service.checkRevocation(id);
      }

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ results }));
      return true;
    } catch (err) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: (err as Error).message }));
      return true;
    }
  }

  // GET /relay/revocation-stats - Get revocation statistics
  if (url.pathname === "/relay/revocation-stats" && req.method === "GET") {
    const stats = service.getStats();

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(stats));
    return true;
  }

  return false; // Not handled
}

/**
 * Read JSON body from request.
 */
async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", (chunk: Buffer) => {
      body += chunk.toString();
      if (body.length > 64 * 1024) {
        reject(new Error("Request body too large"));
      }
    });

    req.on("end", () => {
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error("Invalid JSON body"));
      }
    });

    req.on("error", reject);
  });
}

/**
 * Middleware to check revocation before forwarding messages.
 * This is the critical path for instant revocation enforcement.
 */
export function createRevocationMiddleware(service: ReturnType<typeof createRevocationService>) {
  return {
    /**
     * Check if a capability should be blocked.
     * Call this before forwarding any message that uses a capability.
     */
    shouldBlock(capabilityId: string): { blocked: boolean; reason?: string } {
      const result = service.checkRevocation(capabilityId);

      if (result.revoked) {
        return {
          blocked: true,
          reason: result.reason ?? `Capability revoked at ${result.revokedAt}`,
        };
      }

      return { blocked: false };
    },

    /**
     * Check multiple capabilities at once (for batch operations).
     */
    shouldBlockAny(capabilityIds: string[]): {
      blocked: boolean;
      blockedId?: string;
      reason?: string;
    } {
      for (const id of capabilityIds) {
        const result = service.checkRevocation(id);
        if (result.revoked) {
          return {
            blocked: true,
            blockedId: id,
            reason: result.reason ?? `Capability ${id} revoked at ${result.revokedAt}`,
          };
        }
      }

      return { blocked: false };
    },
  };
}

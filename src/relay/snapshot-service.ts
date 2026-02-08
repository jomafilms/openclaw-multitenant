/**
 * Relay Snapshot Service
 *
 * HTTP service for handling cached snapshots at the relay level.
 * This enables offline access to CACHED tier capabilities.
 *
 * Security Model:
 * - Snapshots are encrypted end-to-end (issuer -> recipient)
 * - Relay stores encrypted blobs blindly, cannot read content
 * - Snapshots are signed by the issuer for authenticity
 * - Expiry is enforced to prevent stale data
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { verify as cryptoVerify, createPublicKey } from "crypto";
import type { CachedSnapshot } from "../container/secret-store.js";
import { getSnapshotStore, type SnapshotStore } from "./snapshot-store.js";

// Ed25519 SPKI prefix for DER-encoded public keys
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/**
 * Verify that a snapshot is properly signed by the issuer.
 */
function verifySnapshotSignature(snapshot: CachedSnapshot): boolean {
  try {
    const { capabilityId, encryptedData, ephemeralPublicKey, signature, issuerPublicKey } =
      snapshot;

    // Reconstruct the signed payload
    const payload = `${capabilityId}:${encryptedData}:${ephemeralPublicKey}`;

    // Reconstruct SPKI-encoded DER format for Ed25519 public key
    const rawKey = Buffer.from(issuerPublicKey, "base64");
    if (rawKey.length !== 32) {
      console.warn("[SnapshotService] Invalid public key length:", rawKey.length);
      return false;
    }

    const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX, rawKey]);
    const publicKey = createPublicKey({ key: spkiDer, type: "spki", format: "der" });

    // Verify Ed25519 signature
    const signatureBuffer = Buffer.from(signature, "base64");

    if (signatureBuffer.length !== 64) {
      console.warn("[SnapshotService] Invalid signature length:", signatureBuffer.length);
      return false;
    }

    return cryptoVerify(null, Buffer.from(payload, "utf-8"), publicKey, signatureBuffer);
  } catch (err) {
    console.error("[SnapshotService] Signature verification failed:", err);
    return false;
  }
}

/**
 * Create the snapshot service handler.
 */
export function createSnapshotService(store?: SnapshotStore) {
  const snapshotStore = store ?? getSnapshotStore();

  return {
    /**
     * Store a snapshot.
     */
    async storeSnapshot(snapshot: CachedSnapshot): Promise<{ success: boolean; error?: string }> {
      // Validate required fields
      if (
        !snapshot.capabilityId ||
        !snapshot.encryptedData ||
        !snapshot.ephemeralPublicKey ||
        !snapshot.nonce ||
        !snapshot.tag ||
        !snapshot.signature ||
        !snapshot.issuerPublicKey
      ) {
        return { success: false, error: "Missing required snapshot fields" };
      }

      // Verify the signature
      if (!verifySnapshotSignature(snapshot)) {
        return { success: false, error: "Invalid snapshot signature" };
      }

      // Check expiry
      if (new Date(snapshot.expiresAt).getTime() < Date.now()) {
        return { success: false, error: "Snapshot has already expired" };
      }

      try {
        await snapshotStore.store(snapshot);
        console.log(`[SnapshotService] Stored snapshot for capability ${snapshot.capabilityId}`);
        return { success: true };
      } catch (err) {
        return { success: false, error: (err as Error).message };
      }
    },

    /**
     * Retrieve a snapshot.
     */
    getSnapshot(capabilityId: string): CachedSnapshot | null {
      return snapshotStore.get(capabilityId);
    },

    /**
     * Delete a snapshot.
     */
    async deleteSnapshot(capabilityId: string): Promise<boolean> {
      return snapshotStore.delete(capabilityId);
    },

    /**
     * Get snapshot store statistics.
     */
    getStats() {
      return snapshotStore.getStats();
    },

    /**
     * Run cleanup of expired snapshots.
     */
    async cleanup(): Promise<number> {
      return snapshotStore.cleanup();
    },
  };
}

/**
 * HTTP handler for snapshot endpoints.
 * Integrates with the relay's HTTP server.
 */
export async function handleSnapshotHttpRequest(
  req: IncomingMessage,
  res: ServerResponse,
  service: ReturnType<typeof createSnapshotService>,
): Promise<boolean> {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);

  // POST /relay/snapshots - Store a snapshot
  if (url.pathname === "/relay/snapshots" && req.method === "POST") {
    try {
      const body = await readJsonBody(req);
      const result = await service.storeSnapshot(body as CachedSnapshot);

      res.writeHead(result.success ? 200 : 400, { "Content-Type": "application/json" });
      res.end(JSON.stringify(result));
      return true;
    } catch (err) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: false, error: (err as Error).message }));
      return true;
    }
  }

  // GET /relay/snapshots/:capabilityId - Retrieve a snapshot
  const getMatch = url.pathname.match(/^\/relay\/snapshots\/([^/]+)$/);
  if (getMatch && req.method === "GET") {
    const capabilityId = decodeURIComponent(getMatch[1]);
    const snapshot = service.getSnapshot(capabilityId);

    if (snapshot) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(snapshot));
    } else {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Snapshot not found" }));
    }
    return true;
  }

  // DELETE /relay/snapshots/:capabilityId - Delete a snapshot
  if (getMatch && req.method === "DELETE") {
    const capabilityId = decodeURIComponent(getMatch[1]);
    await service.deleteSnapshot(capabilityId);

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ success: true }));
    return true;
  }

  // GET /relay/snapshot-stats - Get snapshot statistics
  if (url.pathname === "/relay/snapshot-stats" && req.method === "GET") {
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
      // Allow larger bodies for snapshots (up to 1MB)
      if (body.length > 1024 * 1024) {
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

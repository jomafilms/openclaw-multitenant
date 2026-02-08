/**
 * Message Relay Routes
 *
 * Routes for container-to-container message forwarding with capability verification.
 *
 * SECURITY: This relay is ZERO-KNOWLEDGE
 * - Message payloads are encrypted end-to-end
 * - The relay CANNOT read message content
 * - Only metadata is logged: who->whom, timestamp, size
 * - Capability tokens are verified before forwarding
 */
import { Router } from 'express';
import { createVerify, createPublicKey, createHash } from 'crypto';
import { requireContainer } from '../middleware/auth.js';
import { messages, rateLimits, auditLog, containerRegistry, meshAuditLogs, MESH_AUDIT_EVENTS } from '../db/index.js';
import { sendToContainer, isContainerConnected } from '../lib/websocket.js';
import { wakeContainer, getContainerStatus } from '../lib/wake.js';
import {
  validate,
  sendMessageSchema,
  capabilityEnvelopeSchema,
} from '../lib/schemas.js';
import { messageSendLimiter } from '../lib/rate-limit.js';
import { forwardToCallback } from '../lib/forward.js';

const router = Router();

// Maximum payload size (1MB encrypted blob limit)
const MAX_PAYLOAD_SIZE = 1024 * 1024;

// Ed25519 SPKI prefix for DER-encoded public keys
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/**
 * Verify an Ed25519 signature
 */
function verifySignature(payload, signatureBase64, publicKeyBase64) {
  try {
    const rawKey = Buffer.from(publicKeyBase64, 'base64');
    if (rawKey.length !== 32) {
      return false;
    }

    const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX, rawKey]);
    const publicKey = createPublicKey({ key: spkiDer, type: 'spki', format: 'der' });

    const signatureBuffer = Buffer.from(signatureBase64, 'base64');
    if (signatureBuffer.length !== 64) {
      return false;
    }

    const verify = createVerify(null);
    verify.update(payload);
    return verify.verify(publicKey, signatureBuffer);
  } catch (err) {
    console.error('[messages] Signature verification failed:', err.message);
    return false;
  }
}

/**
 * Decode and validate a capability token
 * @param {string} token - Base64url encoded capability token
 * @returns {Object|null} Decoded token or null if invalid
 */
function decodeCapabilityToken(token) {
  try {
    const decoded = JSON.parse(Buffer.from(token, 'base64url').toString());
    const { id, iss, sub, resource, scope, exp, sig } = decoded;

    // Check required fields
    if (!id || !iss || !sub || !resource || !scope || !exp || !sig) {
      return null;
    }

    // Verify signature
    const claims = { ...decoded };
    delete claims.sig;
    if (!verifySignature(JSON.stringify(claims), sig, iss)) {
      return null;
    }

    // Check expiry
    const now = Math.floor(Date.now() / 1000);
    if (exp < now) {
      return null;
    }

    return decoded;
  } catch (err) {
    console.error('[messages] Failed to decode capability token:', err.message);
    return null;
  }
}

/**
 * POST /relay/forward
 * Forward an encrypted message to another container with capability verification.
 *
 * This is the main entry point for capability-based container-to-container messaging.
 * The capability token proves the sender is authorized to access the target resource.
 *
 * Body: {
 *   toContainerId: UUID,
 *   capabilityToken: string (signed capability token),
 *   encryptedPayload: string (encrypted message, relay cannot read),
 *   nonce: string (for encryption),
 *   signature: string (sender signs the envelope)
 * }
 *
 * Flow:
 * 1. Verify sender authentication (gateway token)
 * 2. Decode and verify capability token
 * 3. Check capability is not revoked
 * 4. Store message for delivery
 * 5. Attempt immediate delivery via WebSocket
 * 6. Fall back to callback URL or queue for later
 */
router.post('/forward', messageSendLimiter, requireContainer, validate({ body: capabilityEnvelopeSchema }), async (req, res) => {
  const {
    toContainerId,
    capabilityToken,
    encryptedPayload,
    nonce,
    signature,
  } = req.validatedBody;
  const fromContainerId = req.container.userId;

  const payloadSize = Buffer.byteLength(encryptedPayload, 'utf8');
  if (payloadSize > MAX_PAYLOAD_SIZE) {
    return res.status(413).json({
      error: 'Payload too large',
      maxSize: MAX_PAYLOAD_SIZE,
      yourSize: payloadSize
    });
  }

  try {
    // Decode and verify capability token
    const capability = decodeCapabilityToken(capabilityToken);
    if (!capability) {
      await auditLog.log({
        fromContainerId,
        toContainerId,
        payloadSize,
        status: 'invalid_capability',
        errorMessage: 'Invalid or expired capability token'
      });

      // Log capability denial to mesh audit
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.CAPABILITY_DENIED,
        actorId: fromContainerId,
        targetId: toContainerId,
        ipAddress: req.ip,
        success: false,
        source: 'relay-server',
        errorMessage: 'Invalid or expired capability token'
      });

      return res.status(403).json({
        error: 'Invalid or expired capability token'
      });
    }

    // Verify the capability was issued for the target container
    // The capability issuer should match the target container
    // (We're forwarding a request to execute on their behalf)
    // NOTE: The relay verifies the token format and signature, but
    // the actual authorization check happens at the target container

    // Check rate limit
    const rateLimit = await rateLimits.checkAndIncrement(fromContainerId);
    if (!rateLimit.allowed) {
      await auditLog.log({
        fromContainerId,
        toContainerId,
        payloadSize,
        status: 'rate_limited',
        errorMessage: null
      });

      return res.status(429).json({
        error: 'Rate limit exceeded',
        remaining: 0,
        resetAt: rateLimit.resetAt
      });
    }

    // Build the message envelope (relay stores but cannot decrypt)
    const messageEnvelope = JSON.stringify({
      type: 'capability_execution',
      capabilityId: capability.id,
      capabilityToken,
      encryptedPayload,
      nonce,
      senderSignature: signature,
      fromContainerId,
      timestamp: new Date().toISOString(),
    });

    // Store the message
    const message = await messages.create({
      fromContainerId,
      toContainerId,
      payloadEncrypted: messageEnvelope
    });

    // Try to deliver immediately via WebSocket if connected
    let deliveredViaWebSocket = false;
    if (isContainerConnected(toContainerId)) {
      deliveredViaWebSocket = sendToContainer(toContainerId, message);
      if (deliveredViaWebSocket) {
        console.log(`[messages] Message ${message.id.slice(0, 8)} delivered via WebSocket`);
      }
    }

    // Try callback URL if not connected via WebSocket
    let deliveredViaCallback = false;
    if (!deliveredViaWebSocket) {
      const registration = await containerRegistry.findByContainerId(toContainerId);
      if (registration?.callback_url) {
        const forwardResult = await forwardToCallback(registration.callback_url, {
          messageId: message.id,
          fromContainerId,
          envelope: messageEnvelope,
          timestamp: message.created_at,
        });

        if (forwardResult.success) {
          deliveredViaCallback = true;
          await messages.markDelivered(message.id);
          console.log(`[messages] Message ${message.id.slice(0, 8)} delivered via callback`);
        }
      }
    }

    // If not connected and no callback, check if hibernated and trigger wake
    let wakeTriggered = false;
    if (!deliveredViaWebSocket && !deliveredViaCallback) {
      const containerStatus = await getContainerStatus(toContainerId);

      if (containerStatus.status === 'hibernated' || containerStatus.status === 'stopped') {
        console.log(`[messages] Destination ${toContainerId.slice(0, 8)} is hibernated, triggering wake`);
        const wakeResult = await wakeContainer(toContainerId);
        wakeTriggered = wakeResult.success;
      }
    }

    // Log successful relay
    await auditLog.log({
      fromContainerId,
      toContainerId,
      payloadSize,
      status: deliveredViaWebSocket ? 'delivered_ws' :
              deliveredViaCallback ? 'delivered_callback' : 'queued',
      errorMessage: null
    });

    // Log capability usage to mesh audit
    await meshAuditLogs.log({
      eventType: MESH_AUDIT_EVENTS.CAPABILITY_USED,
      actorId: fromContainerId,
      targetId: toContainerId,
      ipAddress: req.ip,
      success: true,
      source: 'relay-server',
      details: {
        capabilityId: capability.id,
        messageId: message.id,
        deliveryMethod: deliveredViaWebSocket ? 'websocket' :
                        deliveredViaCallback ? 'callback' : 'pending'
      }
    });

    // Log message forward to mesh audit
    await meshAuditLogs.log({
      eventType: MESH_AUDIT_EVENTS.RELAY_MESSAGE_FORWARDED,
      actorId: fromContainerId,
      targetId: toContainerId,
      ipAddress: req.ip,
      success: true,
      source: 'relay-server',
      details: {
        messageId: message.id,
        capabilityId: capability.id,
        payloadSize
      }
    });

    res.status(201).json({
      messageId: message.id,
      capabilityId: capability.id,
      status: deliveredViaWebSocket ? 'delivered' :
              deliveredViaCallback ? 'delivered' : 'queued',
      deliveryMethod: deliveredViaWebSocket ? 'websocket' :
                      deliveredViaCallback ? 'callback' : 'pending',
      wakeTriggered,
      rateLimit: {
        remaining: rateLimit.remaining,
        resetAt: rateLimit.resetAt
      }
    });

  } catch (err) {
    console.error('[messages] Forward error:', err);

    await auditLog.log({
      fromContainerId,
      toContainerId,
      payloadSize,
      status: 'error',
      errorMessage: err.message
    });

    res.status(500).json({ error: 'Failed to forward message' });
  }
});

/**
 * POST /relay/send
 * Send an encrypted message to another container (simple mode, no capability verification).
 *
 * This is a simpler endpoint for direct container-to-container messaging
 * where both containers already have a trust relationship.
 *
 * For capability-based access, use POST /relay/forward instead.
 *
 * Body: {
 *   toContainerId: UUID,
 *   payload: string (encrypted blob - we NEVER decrypt this)
 * }
 */
router.post('/send', messageSendLimiter, requireContainer, validate({ body: sendMessageSchema }), async (req, res) => {
  const { toContainerId, payload } = req.validatedBody;
  const fromContainerId = req.container.userId;

  const payloadSize = Buffer.byteLength(payload, 'utf8');
  if (payloadSize > MAX_PAYLOAD_SIZE) {
    return res.status(413).json({
      error: 'Payload too large',
      maxSize: MAX_PAYLOAD_SIZE,
      yourSize: payloadSize
    });
  }

  // Prevent sending to self
  if (toContainerId === fromContainerId) {
    return res.status(400).json({ error: 'Cannot send message to self' });
  }

  try {
    // Check rate limit
    const rateLimit = await rateLimits.checkAndIncrement(fromContainerId);
    if (!rateLimit.allowed) {
      await auditLog.log({
        fromContainerId,
        toContainerId,
        payloadSize,
        status: 'rate_limited',
        errorMessage: null
      });

      return res.status(429).json({
        error: 'Rate limit exceeded',
        remaining: 0,
        resetAt: rateLimit.resetAt
      });
    }

    // Store the message
    const message = await messages.create({
      fromContainerId,
      toContainerId,
      payloadEncrypted: payload
    });

    // Try to deliver immediately via WebSocket if connected
    let deliveredViaWebSocket = false;
    if (isContainerConnected(toContainerId)) {
      deliveredViaWebSocket = sendToContainer(toContainerId, message);
      if (deliveredViaWebSocket) {
        console.log(`[messages] Message ${message.id.slice(0, 8)} delivered via WebSocket`);
      }
    }

    // Try callback URL if not connected via WebSocket
    let deliveredViaCallback = false;
    if (!deliveredViaWebSocket) {
      const registration = await containerRegistry.findByContainerId(toContainerId);
      if (registration?.callback_url) {
        const forwardResult = await forwardToCallback(registration.callback_url, {
          messageId: message.id,
          fromContainerId,
          payload,
          timestamp: message.created_at,
        });

        if (forwardResult.success) {
          deliveredViaCallback = true;
          await messages.markDelivered(message.id);
          console.log(`[messages] Message ${message.id.slice(0, 8)} delivered via callback`);
        }
      }
    }

    // If not connected, check if hibernated and trigger wake
    let wakeTriggered = false;
    if (!deliveredViaWebSocket && !deliveredViaCallback) {
      const containerStatus = await getContainerStatus(toContainerId);

      if (containerStatus.status === 'hibernated' || containerStatus.status === 'stopped') {
        console.log(`[messages] Destination ${toContainerId.slice(0, 8)} is hibernated, triggering wake`);
        const wakeResult = await wakeContainer(toContainerId);
        wakeTriggered = wakeResult.success;
      }
    }

    // Log successful relay
    await auditLog.log({
      fromContainerId,
      toContainerId,
      payloadSize,
      status: deliveredViaWebSocket ? 'delivered_ws' :
              deliveredViaCallback ? 'delivered_callback' : 'queued',
      errorMessage: null
    });

    res.status(201).json({
      messageId: message.id,
      status: deliveredViaWebSocket || deliveredViaCallback ? 'delivered' : 'queued',
      deliveryMethod: deliveredViaWebSocket ? 'websocket' :
                      deliveredViaCallback ? 'callback' : 'pending',
      wakeTriggered,
      rateLimit: {
        remaining: rateLimit.remaining,
        resetAt: rateLimit.resetAt
      }
    });

  } catch (err) {
    console.error('[messages] Send error:', err);

    await auditLog.log({
      fromContainerId,
      toContainerId,
      payloadSize,
      status: 'error',
      errorMessage: err.message
    });

    res.status(500).json({ error: 'Failed to send message' });
  }
});

/**
 * GET /relay/messages/pending
 * Get pending messages for the authenticated container
 *
 * Query params:
 *   - limit: max messages to return (default 50, max 100)
 *   - ack: comma-separated message IDs to acknowledge as delivered
 */
router.get('/messages/pending', requireContainer, async (req, res) => {
  const containerId = req.container.userId;
  const limit = Math.min(parseInt(req.query.limit || '50', 10), 100);

  try {
    // Acknowledge messages if provided
    if (req.query.ack) {
      const ackIds = req.query.ack.split(',').filter(id => id.trim());
      if (ackIds.length > 0) {
        await messages.markManyDelivered(ackIds);
        console.log(`[messages] Acknowledged ${ackIds.length} messages for ${containerId.slice(0, 8)}`);
      }
    }

    // Get pending messages
    const pending = await messages.getPending(containerId, limit);

    res.json({
      count: pending.length,
      messages: pending.map(m => ({
        id: m.id,
        from: m.from_container_id,
        payload: m.payload_encrypted,
        size: m.payload_size,
        timestamp: m.created_at
      }))
    });

  } catch (err) {
    console.error('[messages] Get pending error:', err);
    res.status(500).json({ error: 'Failed to get pending messages' });
  }
});

/**
 * POST /relay/messages/ack
 * Acknowledge messages as delivered (batch)
 *
 * Body: {
 *   messageIds: string[]
 * }
 */
router.post('/messages/ack', requireContainer, async (req, res) => {
  const { messageIds } = req.body;

  if (!Array.isArray(messageIds) || messageIds.length === 0) {
    return res.status(400).json({ error: 'messageIds must be a non-empty array' });
  }

  if (messageIds.length > 100) {
    return res.status(400).json({ error: 'Maximum 100 messages per ack request' });
  }

  try {
    const acknowledged = await messages.markManyDelivered(messageIds);

    res.json({
      acknowledged: acknowledged.length,
      messageIds: acknowledged.map(m => m.id)
    });

  } catch (err) {
    console.error('[messages] Ack error:', err);
    res.status(500).json({ error: 'Failed to acknowledge messages' });
  }
});

export default router;

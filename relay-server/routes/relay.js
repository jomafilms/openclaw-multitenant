import { Router } from 'express';
import { requireContainer } from '../middleware/auth.js';
import { messages, rateLimits, auditLog, containers } from '../db/index.js';
import { sendToContainer, isContainerConnected } from '../lib/websocket.js';
import { wakeContainer, getContainerStatus } from '../lib/wake.js';
import { messageSendLimiter } from '../lib/rate-limit.js';

const router = Router();

// Maximum payload size (1MB encrypted blob limit)
const MAX_PAYLOAD_SIZE = 1024 * 1024;

/**
 * POST /relay/send
 * Send an encrypted message to another container
 *
 * Body: {
 *   toContainerId: UUID,
 *   payload: string (encrypted blob - we NEVER decrypt this)
 * }
 *
 * SECURITY: This relay is ZERO-KNOWLEDGE
 * - We store and route encrypted payloads
 * - We CANNOT and DO NOT read message content
 * - We only log: who -> whom, timestamp, payload size
 *
 * Rate limited: 100 messages per minute per container
 */
router.post('/send', messageSendLimiter, requireContainer, async (req, res) => {
  const { toContainerId, payload } = req.body;
  const fromContainerId = req.container.userId;

  // Validate request
  if (!toContainerId) {
    return res.status(400).json({ error: 'Missing toContainerId' });
  }

  if (!payload || typeof payload !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid payload' });
  }

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

    // Verify destination container exists
    const destContainer = await containers.findByUserId(toContainerId);
    if (!destContainer) {
      await auditLog.log({
        fromContainerId,
        toContainerId,
        payloadSize,
        status: 'invalid_destination',
        errorMessage: 'Destination container not found'
      });

      return res.status(404).json({ error: 'Destination container not found' });
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
        console.log(`[relay] Message ${message.id.slice(0, 8)} delivered via WebSocket`);
      }
    }

    // If not connected, check if hibernated and trigger wake
    let wakeTriggered = false;
    if (!deliveredViaWebSocket) {
      const containerStatus = await getContainerStatus(toContainerId);

      if (containerStatus.status === 'hibernated' || containerStatus.status === 'stopped') {
        console.log(`[relay] Destination ${toContainerId.slice(0, 8)} is hibernated, triggering wake`);
        const wakeResult = await wakeContainer(toContainerId);
        wakeTriggered = wakeResult.success;
      }
    }

    // Log successful relay
    await auditLog.log({
      fromContainerId,
      toContainerId,
      payloadSize,
      status: deliveredViaWebSocket ? 'delivered' : 'queued',
      errorMessage: null
    });

    res.status(201).json({
      messageId: message.id,
      status: deliveredViaWebSocket ? 'delivered' : 'queued',
      wakeTriggered,
      rateLimit: {
        remaining: rateLimit.remaining,
        resetAt: rateLimit.resetAt
      }
    });

  } catch (err) {
    console.error('[relay] Send error:', err);

    await auditLog.log({
      fromContainerId,
      toContainerId,
      payloadSize,
      status: 'error',
      errorMessage: err.message
    });

    res.status(500).json({ error: 'Failed to relay message' });
  }
});

/**
 * GET /relay/pending
 * Get pending messages for the authenticated container
 *
 * Query params:
 *   - limit: max messages to return (default 50, max 100)
 *   - ack: comma-separated message IDs to acknowledge as delivered
 */
router.get('/pending', requireContainer, async (req, res) => {
  const containerId = req.container.userId;
  const limit = Math.min(parseInt(req.query.limit || '50', 10), 100);

  try {
    // Acknowledge messages if provided
    if (req.query.ack) {
      const ackIds = req.query.ack.split(',').filter(id => id.trim());
      if (ackIds.length > 0) {
        await messages.markManyDelivered(ackIds);
        console.log(`[relay] Acknowledged ${ackIds.length} messages for ${containerId.slice(0, 8)}`);
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
    console.error('[relay] Get pending error:', err);
    res.status(500).json({ error: 'Failed to get pending messages' });
  }
});

/**
 * POST /relay/ack
 * Acknowledge messages as delivered (batch)
 *
 * Body: {
 *   messageIds: string[]
 * }
 */
router.post('/ack', requireContainer, async (req, res) => {
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
    console.error('[relay] Ack error:', err);
    res.status(500).json({ error: 'Failed to acknowledge messages' });
  }
});

/**
 * GET /relay/status
 * Get relay status for the authenticated container
 */
router.get('/status', requireContainer, async (req, res) => {
  const containerId = req.container.userId;

  try {
    const [pendingCount, rateStatus] = await Promise.all([
      messages.countPending(containerId),
      rateLimits.getStatus(containerId)
    ]);

    res.json({
      containerId,
      pendingMessages: pendingCount,
      rateLimit: rateStatus,
      connected: isContainerConnected(containerId)
    });

  } catch (err) {
    console.error('[relay] Status error:', err);
    res.status(500).json({ error: 'Failed to get status' });
  }
});

export default router;

/**
 * Message Forwarding Utilities
 *
 * Handles forwarding messages to container callback URLs.
 * Used when containers are not connected via WebSocket.
 */
import axios from "axios";

const FORWARD_TIMEOUT_MS = parseInt(process.env.FORWARD_TIMEOUT_MS || "10000", 10);
const MAX_RETRIES = parseInt(process.env.FORWARD_MAX_RETRIES || "2", 10);

/**
 * Forward a message to a container's callback URL.
 *
 * @param {string} callbackUrl - The container's callback URL
 * @param {Object} message - The message to forward
 * @param {string} message.messageId - Unique message ID
 * @param {string} message.fromContainerId - Sender's container ID
 * @param {string} message.payload - Encrypted message payload (or envelope)
 * @param {string} message.timestamp - Message timestamp
 * @returns {Promise<{success: boolean, statusCode?: number, error?: string}>}
 */
export async function forwardToCallback(callbackUrl, message) {
  let lastError = null;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      const response = await axios.post(
        callbackUrl,
        {
          type: "message",
          messageId: message.messageId,
          from: message.fromContainerId,
          payload: message.payload || message.envelope,
          timestamp: message.timestamp,
        },
        {
          timeout: FORWARD_TIMEOUT_MS,
          headers: {
            "Content-Type": "application/json",
            "X-OCMT-Message-Id": message.messageId,
            "X-OCMT-From": message.fromContainerId,
          },
          // Don't throw on non-2xx (we handle it below)
          validateStatus: () => true,
        },
      );

      // Check for success (2xx status)
      if (response.status >= 200 && response.status < 300) {
        return { success: true, statusCode: response.status };
      }

      // Non-2xx is an error
      lastError = `HTTP ${response.status}`;

      // Don't retry on 4xx (client errors)
      if (response.status >= 400 && response.status < 500) {
        console.warn(
          `[forward] Callback returned ${response.status} for message ${message.messageId.slice(0, 8)}`,
        );
        return { success: false, statusCode: response.status, error: lastError };
      }

      // Retry on 5xx
      console.warn(
        `[forward] Callback returned ${response.status}, will retry (attempt ${attempt + 1}/${MAX_RETRIES + 1})`,
      );
    } catch (err) {
      lastError = err.message;
      console.warn(
        `[forward] Callback failed: ${err.message} (attempt ${attempt + 1}/${MAX_RETRIES + 1})`,
      );
    }

    // Wait before retry with exponential backoff
    if (attempt < MAX_RETRIES) {
      await new Promise((resolve) => setTimeout(resolve, 100 * Math.pow(2, attempt)));
    }
  }

  // All retries exhausted
  console.error(`[forward] All retries exhausted for message ${message.messageId?.slice(0, 8)}`);
  return { success: false, error: lastError || "Max retries exceeded" };
}

/**
 * Batch forward multiple messages to a callback URL.
 * Useful for delivering queued messages when a container comes online.
 *
 * @param {string} callbackUrl - The container's callback URL
 * @param {Array<Object>} messages - Array of messages to forward
 * @returns {Promise<{success: number, failed: number, errors: string[]}>}
 */
export async function forwardBatch(callbackUrl, messages) {
  let success = 0;
  let failed = 0;
  const errors = [];

  for (const message of messages) {
    const result = await forwardToCallback(callbackUrl, message);
    if (result.success) {
      success++;
    } else {
      failed++;
      errors.push(`${message.messageId}: ${result.error}`);
    }
  }

  return { success, failed, errors };
}

export default {
  forwardToCallback,
  forwardBatch,
};

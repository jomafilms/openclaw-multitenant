// SSE (Server-Sent Events) connection management
// Active SSE connections by user ID
export const sseConnections = new Map();

/**
 * Broadcast event to all of a user's SSE connections
 * @param {string} userId - User ID to broadcast to
 * @param {string} event - Event name
 * @param {object} data - Event data
 */
export function broadcastToUser(userId, event, data) {
  const connections = sseConnections.get(userId);
  if (connections) {
    const message = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    connections.forEach(res => {
      try {
        res.write(message);
      } catch (e) {
        // Connection closed, will be cleaned up
      }
    });
  }
}

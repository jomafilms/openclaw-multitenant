/**
 * WebSocket proxy for direct browser-to-container vault unlock
 *
 * This proxies WebSocket connections from the browser directly to the
 * container's secret API, keeping the management server out of the
 * unlock path. The password never touches the management server.
 */

import crypto from "crypto";
import { WebSocketServer, WebSocket } from "ws";
import { containers, ensureAwake, touchActivity } from "./containers.js";

/**
 * Set up WebSocket upgrade handler for unlock endpoints
 */
export function setupUnlockProxy(server, authToken) {
  const wss = new WebSocketServer({ noServer: true });

  // Handle upgrade requests
  server.on("upgrade", async (request, socket, head) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    const match = url.pathname.match(/^\/api\/containers\/([^/]+)\/unlock$/);

    if (!match) {
      socket.destroy();
      return;
    }

    // Verify auth token from query string or header - timing-safe comparison
    const token = url.searchParams.get("token") || request.headers["x-auth-token"];
    if (!token || typeof token !== "string") {
      socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
      socket.destroy();
      return;
    }
    const tokenBuf = Buffer.from(token);
    const authBuf = Buffer.from(authToken);
    if (tokenBuf.length !== authBuf.length || !crypto.timingSafeEqual(tokenBuf, authBuf)) {
      socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
      socket.destroy();
      return;
    }

    const userId = match[1];
    const containerInfo = containers.get(userId);

    if (!containerInfo) {
      socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
      socket.destroy();
      return;
    }

    // Wake container if needed
    const awoke = await ensureAwake(userId);
    if (!awoke) {
      socket.write("HTTP/1.1 503 Service Unavailable\r\n\r\n");
      socket.destroy();
      return;
    }

    // Accept the WebSocket connection
    wss.handleUpgrade(request, socket, head, (ws) => {
      handleUnlockConnection(ws, userId, containerInfo);
    });
  });

  console.log("[unlock-proxy] WebSocket proxy initialized");
}

/**
 * Handle an unlock WebSocket connection
 * Proxies messages between browser and container
 */
function handleUnlockConnection(browserWs, userId, containerInfo) {
  console.log(`[unlock-proxy] Client connected for ${userId.slice(0, 8)}...`);

  // Connect to container's secret API
  const containerUrl = `ws://localhost:${containerInfo.port}/vault/ws`;
  let containerWs = null;
  let messageQueue = [];

  const connectToContainer = () => {
    containerWs = new WebSocket(containerUrl);

    containerWs.on("open", () => {
      console.log(`[unlock-proxy] Connected to container for ${userId.slice(0, 8)}...`);
      // Flush queued messages
      for (const msg of messageQueue) {
        containerWs.send(msg);
      }
      messageQueue = [];
    });

    containerWs.on("message", (data) => {
      if (browserWs.readyState === WebSocket.OPEN) {
        browserWs.send(data.toString());
        touchActivity(userId);
      }
    });

    containerWs.on("error", (err) => {
      console.error(`[unlock-proxy] Container connection error:`, err.message);
      if (browserWs.readyState === WebSocket.OPEN) {
        browserWs.send(JSON.stringify({ error: "Container connection failed" }));
      }
    });

    containerWs.on("close", () => {
      console.log(`[unlock-proxy] Container connection closed for ${userId.slice(0, 8)}...`);
    });
  };

  // Handle messages from browser
  browserWs.on("message", (data) => {
    const message = data.toString();

    if (containerWs?.readyState === WebSocket.OPEN) {
      containerWs.send(message);
    } else {
      // Queue message while connecting
      messageQueue.push(message);
      if (!containerWs || containerWs.readyState === WebSocket.CLOSED) {
        connectToContainer();
      }
    }
  });

  browserWs.on("close", () => {
    console.log(`[unlock-proxy] Client disconnected for ${userId.slice(0, 8)}...`);
    if (containerWs) {
      containerWs.close();
    }
  });

  browserWs.on("error", (err) => {
    console.error(`[unlock-proxy] Browser connection error:`, err.message);
    if (containerWs) {
      containerWs.close();
    }
  });

  // Start connection to container
  connectToContainer();
}

/**
 * Proxy HTTP request to container
 */
export async function proxyToContainer(userId, method, path, body = null) {
  const containerInfo = containers.get(userId);

  if (!containerInfo) {
    return { error: "Container not found" };
  }

  const awoke = await ensureAwake(userId);
  if (!awoke) {
    return { error: "Failed to wake container" };
  }

  const url = `http://localhost:${containerInfo.port}${path}`;

  try {
    const options = {
      method,
      headers: {
        "Content-Type": "application/json",
        "X-Gateway-Token": containerInfo.gatewayToken,
      },
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    const response = await fetch(url, options);
    const data = await response.json();

    touchActivity(userId);
    return data;
  } catch (error) {
    console.error(`[unlock-proxy] HTTP proxy error:`, error.message);
    return { error: "Container communication failed" };
  }
}

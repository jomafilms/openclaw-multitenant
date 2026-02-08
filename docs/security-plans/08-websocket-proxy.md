# Security Plan 08: WebSocket Proxy for Gateway Token Isolation

## Overview

**Problem**: The frontend currently receives gateway tokens via API responses. These tokens provide direct access to user containers and should never be exposed to client-side JavaScript.

**Solution**: Implement a WebSocket proxy in the management server that:

1. Authenticates clients using httpOnly session cookies
2. Maintains gateway tokens server-side only
3. Proxies WebSocket connections to containers transparently

---

## Current Architecture (Insecure)

```
Browser ──────► API ──────► Returns gateway token in response
   │
   └──────────► Container (using exposed token)
```

**Risk**: XSS can steal gateway tokens from JavaScript memory/localStorage.

---

## Target Architecture (Secure)

```
Browser ──────► Management Server (cookie auth)
                      │
                      └──────► Container (server holds token)
```

**Benefit**: Gateway tokens never reach the browser.

---

## Implementation

### 1. WebSocket Proxy Route

**Create `management-server/routes/ws-proxy.js`:**

```javascript
import { WebSocketServer } from "ws";
import { WebSocket } from "ws";
import { sessions } from "../db/index.js";
import cookie from "cookie";

const SESSION_COOKIE = "ocmt_session";

/**
 * Upgrade HTTP connection to WebSocket with cookie authentication
 */
export function setupWebSocketProxy(server) {
  const wss = new WebSocketServer({ noServer: true });

  server.on("upgrade", async (request, socket, head) => {
    // Only handle /api/ws/* paths
    if (!request.url?.startsWith("/api/ws/")) {
      socket.destroy();
      return;
    }

    try {
      // Parse session cookie
      const cookies = cookie.parse(request.headers.cookie || "");
      const sessionToken = cookies[SESSION_COOKIE];

      if (!sessionToken) {
        socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
        socket.destroy();
        return;
      }

      // Validate session
      const session = await sessions.findByToken(sessionToken);
      if (!session) {
        socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
        socket.destroy();
        return;
      }

      // Check container assignment
      if (!session.container_id || !session.gateway_token) {
        socket.write("HTTP/1.1 503 Service Unavailable\r\n\r\n");
        socket.destroy();
        return;
      }

      // Upgrade connection
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit("connection", ws, request, session);
      });
    } catch (err) {
      console.error("WebSocket upgrade error:", err);
      socket.write("HTTP/1.1 500 Internal Server Error\r\n\r\n");
      socket.destroy();
    }
  });

  wss.on("connection", (clientWs, request, session) => {
    // Connect to container using server-side token
    const containerUrl = `ws://localhost:${session.container_port}/ws`;
    const containerWs = new WebSocket(containerUrl, {
      headers: {
        Authorization: `Bearer ${session.gateway_token}`,
      },
    });

    // Track connection state
    let containerConnected = false;

    containerWs.on("open", () => {
      containerConnected = true;
      console.log(`Proxying WS for user ${session.user_id} to container ${session.container_id}`);
    });

    containerWs.on("error", (err) => {
      console.error("Container WS error:", err);
      clientWs.close(1011, "Container connection error");
    });

    containerWs.on("close", () => {
      if (clientWs.readyState === WebSocket.OPEN) {
        clientWs.close(1000, "Container disconnected");
      }
    });

    // Proxy messages bidirectionally
    clientWs.on("message", (data) => {
      if (containerConnected && containerWs.readyState === WebSocket.OPEN) {
        containerWs.send(data);
      }
    });

    containerWs.on("message", (data) => {
      if (clientWs.readyState === WebSocket.OPEN) {
        clientWs.send(data);
      }
    });

    clientWs.on("close", () => {
      if (containerWs.readyState === WebSocket.OPEN) {
        containerWs.close();
      }
    });

    clientWs.on("error", (err) => {
      console.error("Client WS error:", err);
      containerWs.close();
    });
  });

  return wss;
}
```

### 2. Server Integration

**Update `management-server/server.js`:**

```javascript
import { createServer } from "http";
import { setupWebSocketProxy } from "./routes/ws-proxy.js";

// Create HTTP server from Express app
const server = createServer(app);

// Setup WebSocket proxy
setupWebSocketProxy(server);

// Use server.listen instead of app.listen
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
```

### 3. Remove Gateway Token from API Responses

**Audit and update these endpoints:**

```javascript
// BEFORE (insecure)
res.json({
  user: session.email,
  containerId: session.container_id,
  gatewayToken: session.gateway_token, // REMOVE THIS
});

// AFTER (secure)
res.json({
  user: session.email,
  containerId: session.container_id,
  wsEndpoint: "/api/ws/container", // Client uses this instead
});
```

**Files to audit:**

- `routes/auth.js` - Login response
- `routes/user.js` - User info endpoint
- `middleware/auth.js` - req.user object

### 4. Update Frontend

**Update `user-ui/src/lib/api.ts`:**

```typescript
// BEFORE (insecure)
class ContainerConnection {
  constructor(gatewayToken: string, containerPort: number) {
    this.ws = new WebSocket(`ws://localhost:${containerPort}/ws`, {
      headers: { Authorization: `Bearer ${gatewayToken}` },
    });
  }
}

// AFTER (secure)
class ContainerConnection {
  constructor() {
    // WebSocket uses cookies automatically
    // No token needed - proxy handles auth
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    this.ws = new WebSocket(`${protocol}//${window.location.host}/api/ws/container`);
  }
}
```

### 5. SSE Proxy (Same Pattern)

For Server-Sent Events, apply the same proxy pattern:

**Create `management-server/routes/sse-proxy.js`:**

```javascript
import { sessions } from "../db/index.js";

export async function sseProxyHandler(req, res) {
  // Cookie auth already validated by middleware
  const session = req.session;

  if (!session.container_id || !session.gateway_token) {
    return res.status(503).json({ error: "Container not available" });
  }

  // Proxy SSE from container
  const containerUrl = `http://localhost:${session.container_port}/events`;

  const response = await fetch(containerUrl, {
    headers: {
      Authorization: `Bearer ${session.gateway_token}`,
      Accept: "text/event-stream",
    },
  });

  // Set SSE headers
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");

  // Pipe container response to client
  response.body.pipe(res);

  req.on("close", () => {
    response.body.destroy();
  });
}
```

---

## Database Changes

No schema changes required. Gateway tokens remain in sessions table but are never exposed to clients.

---

## Migration Steps

1. **Phase 1**: Deploy WebSocket proxy alongside existing direct connections
2. **Phase 2**: Update frontend to use proxy endpoints
3. **Phase 3**: Remove gateway token from all API responses
4. **Phase 4**: Remove direct container WebSocket code from frontend

---

## Security Considerations

1. **Rate Limiting**: Apply rate limits to WebSocket upgrade requests
2. **Connection Limits**: Max connections per user (prevent resource exhaustion)
3. **Heartbeat**: Implement ping/pong to detect stale connections
4. **Logging**: Log proxy connections for audit trail

---

## Testing

```bash
# Test WebSocket proxy authentication
wscat -c ws://localhost:3000/api/ws/container
# Should fail without cookie

# Test with cookie
wscat -c ws://localhost:3000/api/ws/container \
  -H "Cookie: ocmt_session=<valid-token>"
# Should connect

# Verify no gateway token in API responses
curl http://localhost:3000/api/user -H "Cookie: ..." | grep -i gateway
# Should return nothing
```

---

## Files to Create

| File                  | Purpose                 |
| --------------------- | ----------------------- |
| `routes/ws-proxy.js`  | WebSocket proxy handler |
| `routes/sse-proxy.js` | SSE proxy handler       |

## Files to Modify

| File                     | Changes                                |
| ------------------------ | -------------------------------------- |
| `server.js`              | Setup WebSocket upgrade handling       |
| `routes/auth.js`         | Remove gateway token from responses    |
| `routes/user.js`         | Remove gateway token from responses    |
| `middleware/auth.js`     | Don't attach gateway token to req.user |
| `user-ui/src/lib/api.ts` | Use proxy endpoints                    |

---

## Priority

**CRITICAL** - Gateway token exposure enables full container access if XSS occurs.

## Estimated Effort

3-4 hours for proxy implementation + 2 hours for frontend migration.

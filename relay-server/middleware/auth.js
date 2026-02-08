import { containers } from "../db/index.js";

/**
 * Middleware to authenticate containers by their gateway token
 * Expects:
 *   - Header: Authorization: Bearer <gateway_token>
 *   - Header: X-Container-Id: <user_id> (the user's UUID)
 *
 * Sets req.container if valid
 */
export async function requireContainer(req, res, next) {
  const authHeader = req.headers.authorization;
  const containerId = req.headers["x-container-id"];

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or invalid Authorization header" });
  }

  if (!containerId) {
    return res.status(401).json({ error: "Missing X-Container-Id header" });
  }

  const gatewayToken = authHeader.slice(7); // Remove 'Bearer '

  try {
    const container = await containers.verifyGatewayToken(containerId, gatewayToken);

    if (!container) {
      return res.status(401).json({ error: "Invalid container credentials" });
    }

    if (container.status === "suspended") {
      return res.status(403).json({ error: "Container is suspended" });
    }

    req.container = {
      userId: container.id,
      containerId: container.container_id,
      status: container.status,
    };

    next();
  } catch (err) {
    console.error("Container auth error:", err);
    res.status(500).json({ error: "Authentication failed" });
  }
}

/**
 * Middleware for WebSocket authentication
 * Returns container info if valid, null otherwise
 *
 * Authentication methods (in order of preference):
 * 1. Sec-WebSocket-Protocol header: "token.<base64-encoded-token>, ocmt-relay"
 *    - Token format: base64(containerId:gatewayToken)
 *    - Server echoes back "ocmt-relay" as the accepted subprotocol
 * 2. Query parameters (DEPRECATED): ?token=<token>&containerId=<id>
 *    - Logs deprecation warning; will be removed in future version
 */
export async function authenticateWebSocket(request) {
  let gatewayToken = null;
  let containerId = null;
  let acceptedProtocol = null;
  let authMethod = null;

  // Method 1: Try Sec-WebSocket-Protocol header first (secure method)
  const protocolHeader = request.headers["sec-websocket-protocol"];
  if (protocolHeader) {
    // Parse protocols: "token.<base64>, ocmt-relay" or similar
    const protocols = protocolHeader.split(",").map((p) => p.trim());

    for (const protocol of protocols) {
      if (protocol.startsWith("token.")) {
        try {
          // Extract and decode the token
          // Format: token.<base64(containerId:gatewayToken)>
          const encodedToken = protocol.substring(6); // Remove 'token.' prefix
          const decodedToken = Buffer.from(encodedToken, "base64").toString("utf-8");

          // Parse containerId:gatewayToken
          const colonIndex = decodedToken.indexOf(":");
          if (colonIndex > 0) {
            containerId = decodedToken.substring(0, colonIndex);
            gatewayToken = decodedToken.substring(colonIndex + 1);
            authMethod = "header";
          }
        } catch (err) {
          console.warn("WebSocket auth: failed to decode token from protocol header:", err.message);
        }
        break;
      }
    }

    // Find a non-token protocol to echo back (e.g., "ocmt-relay")
    const nonTokenProtocol = protocols.find((p) => !p.startsWith("token."));
    if (nonTokenProtocol) {
      acceptedProtocol = nonTokenProtocol;
    }
  }

  // Method 2: Fall back to query parameters (deprecated)
  if (!gatewayToken || !containerId) {
    const url = new URL(request.url, `http://${request.headers.host}`);
    const params = url.searchParams;
    const queryToken = params.get("token");
    const queryContainerId = params.get("containerId");

    if (queryToken && queryContainerId) {
      // Log deprecation warning (rate-limited to avoid log spam)
      if (!authenticateWebSocket._deprecationLogged) {
        console.warn(
          "DEPRECATED: WebSocket authentication via query parameters is deprecated and will be removed. " +
            'Use Sec-WebSocket-Protocol header instead: "token.<base64(containerId:token)>, ocmt-relay"',
        );
        authenticateWebSocket._deprecationLogged = true;
        // Reset the flag after 1 hour to log again if still being used
        setTimeout(() => {
          authenticateWebSocket._deprecationLogged = false;
        }, 3600000);
      }

      gatewayToken = queryToken;
      containerId = queryContainerId;
      authMethod = "query-param";
    }
  }

  if (!gatewayToken || !containerId) {
    return { container: null, acceptedProtocol: null };
  }

  try {
    const container = await containers.verifyGatewayToken(containerId, gatewayToken);

    if (!container || container.status === "suspended") {
      return { container: null, acceptedProtocol: null };
    }

    return {
      container: {
        userId: container.id,
        containerId: container.container_id,
        status: container.status,
      },
      acceptedProtocol,
      authMethod,
    };
  } catch (err) {
    console.error("WebSocket auth error:", err);
    return { container: null, acceptedProtocol: null };
  }
}

export default { requireContainer, authenticateWebSocket };

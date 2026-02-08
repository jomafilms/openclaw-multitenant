// SSE-specific authentication middleware
// Allows query param tokens ONLY for EventSource connections
// which cannot set custom headers

import { sessions } from "../db/index.js";
import { getClientIp } from "../lib/rate-limit.js";

const SESSION_COOKIE = "ocmt_session";

// Configurable session timeout for regular users
const USER_SESSION_TIMEOUT_MS =
  parseInt(process.env.USER_SESSION_TIMEOUT_MS) || 7 * 24 * 60 * 60 * 1000; // 7 days default

/**
 * SSE-specific auth that allows query param tokens
 * ONLY for EventSource connections (which cannot set custom headers)
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export function requireUserSSE(req, res, next) {
  const isSSE = req.headers.accept?.includes("text/event-stream");

  let token;
  if (isSSE) {
    // For SSE, allow query param as fallback (EventSource limitation)
    // Priority: cookie > header > query param
    token = req.cookies?.[SESSION_COOKIE] || req.headers["x-session-token"] || req.query.token;
  } else {
    // Non-SSE: Never allow query param tokens
    token = req.cookies?.[SESSION_COOKIE] || req.headers["x-session-token"];
  }

  if (!token) {
    return res.status(401).json({ error: "Authentication required" });
  }

  sessions
    .findByToken(token)
    .then(async (session) => {
      if (!session) {
        return res.status(401).json({ error: "Invalid or expired session" });
      }

      // Check session age against timeout
      const sessionAge = Date.now() - new Date(session.created_at).getTime();
      if (sessionAge > USER_SESSION_TIMEOUT_MS) {
        return res.status(401).json({
          error: "Session expired",
          code: "SESSION_EXPIRED",
        });
      }

      req.user = {
        id: session.user_id,
        email: session.email,
        name: session.name,
        status: session.status,
        containerId: session.container_id,
        containerPort: session.container_port,
        gatewayToken: session.gateway_token,
      };
      req.sessionId = session.id;
      req.sessionToken = token;

      // Update last activity asynchronously (don't block request)
      const clientIp = getClientIp(req);
      sessions.updateLastActivity(session.id, clientIp).catch((err) => {
        console.error("Failed to update session activity:", err);
      });

      next();
    })
    .catch((err) => {
      console.error("SSE Auth error:", err);
      res.status(500).json({ error: "Authentication failed" });
    });
}

export default { requireUserSSE };

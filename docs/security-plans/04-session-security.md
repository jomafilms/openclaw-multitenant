# Security Plan 04: Session Security Improvements

## Overview

This plan addresses four session security issues:

1. Session token allowed in query params (leaks to logs/referrer)
2. IP header trust without validation
3. No session management UI (view/revoke sessions)
4. No "sign out everywhere" feature

---

## 1. Remove Query Param Token Support

### Current Issue

In `management-server/middleware/auth.js` line 27:

```javascript
const token = req.cookies?.[SESSION_COOKIE] || req.headers["x-session-token"] || req.query.token;
```

Query param tokens leak to server logs, browser history, referrer headers, and shared URLs.

### Implementation

#### 1.1 Create SSE-Only Auth Middleware

Create `management-server/middleware/sse-auth.js`:

```javascript
import { sessions } from "../db/index.js";

const SESSION_COOKIE = "ocmt_session";

/**
 * SSE-specific auth that allows query param tokens
 * ONLY for EventSource connections (which cannot set custom headers)
 */
export function requireUserSSE(req, res, next) {
  const isSSE = req.headers.accept?.includes("text/event-stream");

  let token;
  if (isSSE) {
    // For SSE, allow query param as fallback (EventSource limitation)
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
    .then((session) => {
      if (!session) {
        return res.status(401).json({ error: "Invalid or expired session" });
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
      next();
    })
    .catch((err) => {
      console.error("Auth error:", err);
      res.status(500).json({ error: "Authentication failed" });
    });
}
```

#### 1.2 Update Main Auth Middleware

Modify `management-server/middleware/auth.js`:

```javascript
export function requireUser(req, res, next) {
  // SECURITY: Never accept tokens from query params
  // SSE endpoints must use requireUserSSE middleware instead
  const token = req.cookies?.[SESSION_COOKIE] || req.headers["x-session-token"];

  if (!token) {
    return res.status(401).json({ error: "Authentication required" });
  }

  // ... rest unchanged
}
```

#### 1.3 Update SSE Routes

Update `routes/chat.js` and `routes/notifications.js`:

```javascript
import { requireUserSSE } from "../middleware/sse-auth.js";

router.get("/stream", requireUserSSE, (req, res) => {
  // ... SSE code
});
```

---

## 2. Proper Trust Proxy Configuration

### Current Issue

`getClientIp()` blindly trusts `X-Forwarded-For`, allowing IP spoofing.

### Implementation

#### 2.1 Configure Express Trust Proxy

Update `management-server/server.js`:

```javascript
const app = express();

// Trust proxy configuration
const TRUST_PROXY = process.env.TRUST_PROXY || "loopback";

if (TRUST_PROXY === "true" || TRUST_PROXY === "1") {
  app.set("trust proxy", true);
} else if (TRUST_PROXY === "false" || TRUST_PROXY === "0") {
  app.set("trust proxy", false);
} else if (/^\d+$/.test(TRUST_PROXY)) {
  app.set("trust proxy", parseInt(TRUST_PROXY, 10));
} else {
  app.set("trust proxy", TRUST_PROXY);
}
```

#### 2.2 Create Validated IP Extraction

Update `management-server/lib/rate-limit.js`:

```javascript
import { isIP } from "net";

const TRUSTED_PROXY_RANGES = [
  "127.0.0.0/8",
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "::1/128",
  "fc00::/7",
];

function isTrustedProxy(ip) {
  const trustedEnv = process.env.TRUSTED_PROXIES;
  const trustedRanges = trustedEnv
    ? trustedEnv.split(",").map((s) => s.trim())
    : TRUSTED_PROXY_RANGES;

  return trustedRanges.some((range) => ipInRange(ip, range));
}

export function getClientIp(req) {
  // If Express trust proxy is configured, use req.ip
  if (req.app.get("trust proxy")) {
    return req.ip || req.socket?.remoteAddress || "unknown";
  }

  const socketIp = req.socket?.remoteAddress;

  // Only process forwarded headers if from trusted proxy
  if (socketIp && isTrustedProxy(socketIp)) {
    const forwardedFor = req.headers["x-forwarded-for"];
    if (forwardedFor) {
      const ips = forwardedFor.split(",").map((ip) => ip.trim());
      for (const ip of ips) {
        if (isIP(ip)) return ip;
      }
    }

    const realIp = req.headers["x-real-ip"];
    if (realIp && isIP(realIp)) return realIp;
  }

  return socketIp || "unknown";
}
```

#### 2.3 Environment Variables

Add to `.env.example`:

```bash
# Trust proxy: number (1, 2), 'true', 'false', or 'loopback, 10.0.0.0/8'
TRUST_PROXY=loopback

# Trusted proxy IP ranges (comma-separated CIDR)
TRUSTED_PROXIES=127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

---

## 3. Database Schema for Session Tracking

### Migration

Add to `management-server/db/migrate.js`:

```javascript
// Session metadata for security tracking
`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip_address INET`,
`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_agent TEXT`,
`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_info JSONB DEFAULT '{}'`,
`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_activity_at TIMESTAMP DEFAULT NOW()`,
`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP`,
`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoke_reason VARCHAR(50)`,

// Indexes
`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`,
`CREATE INDEX IF NOT EXISTS idx_sessions_user_active ON sessions(user_id, expires_at) WHERE revoked_at IS NULL`,
```

---

## 4. Session Management API

### 4.1 Update Session Database Operations

Add to `management-server/db/index.js`:

```javascript
export const sessions = {
  async create(userId, token, expiresAt, metadata = {}) {
    const { ipAddress, userAgent, deviceInfo } = metadata;
    const res = await query(
      `INSERT INTO sessions (user_id, token, expires_at, ip_address, user_agent, device_info, last_activity_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW())
       RETURNING *`,
      [
        userId,
        token,
        expiresAt,
        ipAddress,
        userAgent,
        deviceInfo ? JSON.stringify(deviceInfo) : "{}",
      ],
    );
    return res.rows[0];
  },

  async findByToken(token) {
    const res = await query(
      `SELECT s.*, u.* FROM sessions s
       JOIN users u ON s.user_id = u.id
       WHERE s.token = $1
         AND s.expires_at > NOW()
         AND s.revoked_at IS NULL`,
      [token],
    );
    return res.rows[0];
  },

  async listActiveForUser(userId) {
    const res = await query(
      `SELECT id, created_at, expires_at, ip_address, user_agent, device_info, last_activity_at
       FROM sessions
       WHERE user_id = $1
         AND expires_at > NOW()
         AND revoked_at IS NULL
       ORDER BY last_activity_at DESC`,
      [userId],
    );
    return res.rows;
  },

  async updateLastActivity(sessionId, ipAddress) {
    await query(
      `UPDATE sessions
       SET last_activity_at = NOW(), ip_address = COALESCE($2, ip_address)
       WHERE id = $1`,
      [sessionId, ipAddress],
    );
  },

  async revokeById(sessionId, reason = "user_action") {
    const res = await query(
      `UPDATE sessions
       SET revoked_at = NOW(), revoke_reason = $2
       WHERE id = $1 AND revoked_at IS NULL
       RETURNING *`,
      [sessionId, reason],
    );
    return res.rows[0];
  },

  async revokeAllForUser(userId, exceptSessionId = null, reason = "user_action") {
    let queryText = `UPDATE sessions
                     SET revoked_at = NOW(), revoke_reason = $2
                     WHERE user_id = $1
                       AND revoked_at IS NULL
                       AND expires_at > NOW()`;
    const params = [userId, reason];

    if (exceptSessionId) {
      queryText += ` AND id != $3`;
      params.push(exceptSessionId);
    }

    queryText += ` RETURNING id`;
    const res = await query(queryText, params);
    return res.rows.length;
  },
};
```

### 4.2 Create Session Routes

Create `management-server/routes/sessions.js`:

```javascript
import { Router } from "express";
import { sessions, audit } from "../db/index.js";
import { requireUser } from "../middleware/auth.js";
import { getClientIp } from "../lib/rate-limit.js";

const router = Router();

// GET /api/auth/sessions - List active sessions
router.get("/", requireUser, async (req, res) => {
  try {
    const activeSessions = await sessions.listActiveForUser(req.user.id);

    const sessionsWithCurrent = activeSessions.map((session) => ({
      id: session.id,
      createdAt: session.created_at,
      expiresAt: session.expires_at,
      lastActivityAt: session.last_activity_at,
      ipAddress: session.ip_address,
      deviceInfo: session.device_info,
      isCurrent: session.id === req.sessionId,
    }));

    res.json({ sessions: sessionsWithCurrent, count: sessionsWithCurrent.length });
  } catch (err) {
    console.error("List sessions error:", err);
    res.status(500).json({ error: "Failed to list sessions" });
  }
});

// DELETE /api/auth/sessions/:id - Revoke specific session
router.delete("/:id", requireUser, async (req, res) => {
  try {
    const { id } = req.params;

    const session = await sessions.findById(id);
    if (!session || session.user_id !== req.user.id) {
      return res.status(404).json({ error: "Session not found" });
    }

    if (id === req.sessionId) {
      return res.status(400).json({
        error: "Cannot revoke current session. Use logout instead.",
        code: "CANNOT_REVOKE_CURRENT",
      });
    }

    await sessions.revokeById(id, "user_revoked");
    await audit.log(req.user.id, "session.revoked", { sessionId: id }, getClientIp(req));

    res.json({ success: true, message: "Session revoked" });
  } catch (err) {
    console.error("Revoke session error:", err);
    res.status(500).json({ error: "Failed to revoke session" });
  }
});

// DELETE /api/auth/sessions - Sign out everywhere (except current)
router.delete("/", requireUser, async (req, res) => {
  try {
    const revokedCount = await sessions.revokeAllForUser(
      req.user.id,
      req.sessionId,
      "sign_out_everywhere",
    );

    await audit.log(
      req.user.id,
      "session.revoked_all",
      {
        count: revokedCount,
        exceptCurrent: true,
      },
      getClientIp(req),
    );

    res.json({
      success: true,
      message: `Revoked ${revokedCount} session(s)`,
      revokedCount,
    });
  } catch (err) {
    console.error("Revoke all sessions error:", err);
    res.status(500).json({ error: "Failed to revoke sessions" });
  }
});

export default router;
```

### 4.3 Register Routes

Update `management-server/server.js`:

```javascript
import sessionsRouter from "./routes/sessions.js";

app.use("/api/auth/sessions", sessionsRouter);
```

---

## 5. UI Components

### 5.1 API Client Methods

Add to `user-ui/src/lib/api.ts`:

```typescript
interface SessionInfo {
  id: string;
  createdAt: string;
  expiresAt: string;
  lastActivityAt: string;
  ipAddress: string | null;
  deviceInfo: {
    type: string;
    name: string;
    browser?: string;
    os?: string;
  };
  isCurrent: boolean;
}

class ApiClient {
  async listSessions(): Promise<{ sessions: SessionInfo[]; count: number }> {
    return this.request("/api/auth/sessions");
  }

  async revokeSession(sessionId: string): Promise<{ success: boolean }> {
    return this.request(`/api/auth/sessions/${sessionId}`, { method: "DELETE" });
  }

  async revokeAllSessions(): Promise<{ success: boolean; revokedCount: number }> {
    return this.request("/api/auth/sessions", { method: "DELETE" });
  }
}
```

### 5.2 Sessions Page

Create `user-ui/src/pages/sessions.ts` with:

- List of active sessions with device info and IP
- "This device" badge for current session
- Revoke button for each non-current session
- "Sign Out Everywhere" button
- Device icons (mobile/tablet/desktop)
- Relative time display for last activity

---

## 6. Dependencies

Add to `management-server/package.json`:

```json
{
  "dependencies": {
    "ua-parser-js": "^1.0.0"
  }
}
```

For user agent parsing into device info.

---

## 7. Security Considerations

### Session Token Security

- 32 random bytes (256 bits), cryptographically secure
- httpOnly cookies as primary transport
- Query params only for SSE with Accept header validation

### IP Tracking Privacy

- IP stored for security purposes only
- Consider anonymizing after 30 days
- Add data retention policy (delete after 90 days)

### Rate Limiting

```javascript
const sessionMgmtLimiter = createRateLimiter({
  name: "session-management",
  windowMs: 15 * 60 * 1000,
  maxRequests: 20,
});

router.use(sessionMgmtLimiter);
```

### New Device Notification (Optional)

Email user when new device signs in:

```javascript
async function notifyNewSession(user, session) {
  await resend.emails.send({
    to: user.email,
    subject: "New sign-in to OCMT",
    html: `
      <p>New device signed in:</p>
      <ul>
        <li>Device: ${session.deviceInfo.name}</li>
        <li>IP: ${session.ipAddress}</li>
        <li>Time: ${new Date().toISOString()}</li>
      </ul>
      <p>If this wasn't you, <a href="${USER_UI_URL}/sessions">review your sessions</a>.</p>
    `,
  });
}
```

---

## 8. Session Timeout Configuration

### 8.1 Regular User Session Timeout

Make session timeout configurable via environment variable:

**Update `management-server/middleware/auth.js`:**

```javascript
// Configurable session timeout for regular users
const USER_SESSION_TIMEOUT_MS =
  parseInt(process.env.USER_SESSION_TIMEOUT_MS) || 7 * 24 * 60 * 60 * 1000; // 7 days default

export function requireUser(req, res, next) {
  // ... token extraction ...

  sessions.findByToken(token).then((session) => {
    if (!session) {
      return res.status(401).json({ error: "Invalid or expired session" });
    }

    // Check session age
    const sessionAge = Date.now() - new Date(session.created_at).getTime();
    if (sessionAge > USER_SESSION_TIMEOUT_MS) {
      return res.status(401).json({
        error: "Session expired",
        code: "SESSION_EXPIRED",
      });
    }

    // ... rest of auth logic ...
  });
}
```

**Environment variables:**

```bash
# Regular user session timeout (default: 7 days)
USER_SESSION_TIMEOUT_MS=604800000

# Admin session timeout (default: 1 hour) - defined in Plan 07
ADMIN_SESSION_TIMEOUT_MS=3600000
```

### 8.2 Concurrent Session Limits

Limit the number of active sessions per user to prevent abuse:

**Add to `management-server/db/index.js`:**

```javascript
const MAX_SESSIONS_PER_USER = parseInt(process.env.MAX_SESSIONS_PER_USER) || 5;

export const sessions = {
  // ... existing methods ...

  async enforceSessionLimit(userId) {
    const activeSessions = await this.listActiveForUser(userId);

    if (activeSessions.length >= MAX_SESSIONS_PER_USER) {
      // Revoke oldest session(s) to make room
      const sessionsToRevoke = activeSessions
        .sort((a, b) => new Date(a.last_activity_at) - new Date(b.last_activity_at))
        .slice(0, activeSessions.length - MAX_SESSIONS_PER_USER + 1);

      for (const session of sessionsToRevoke) {
        await this.revokeById(session.id, "session_limit_exceeded");
      }

      return sessionsToRevoke.length;
    }

    return 0;
  },

  async create(userId, token, ipAddress, userAgent) {
    // Enforce session limit before creating new session
    await this.enforceSessionLimit(userId);

    // Create new session
    const res = await query(
      `INSERT INTO sessions (user_id, token, ip_address, user_agent, expires_at)
       VALUES ($1, $2, $3, $4, NOW() + INTERVAL '7 days')
       RETURNING *`,
      [userId, token, ipAddress, userAgent],
    );
    return res.rows[0];
  },
};
```

**Environment variable:**

```bash
# Maximum concurrent sessions per user (default: 5)
MAX_SESSIONS_PER_USER=5
```

---

## Files to Modify

| File                     | Changes                                                      |
| ------------------------ | ------------------------------------------------------------ |
| `middleware/auth.js`     | Remove query param, add session ID to req, add timeout check |
| `lib/rate-limit.js`      | Validate trusted proxies                                     |
| `db/migrate.js`          | Add session metadata columns                                 |
| `db/index.js`            | Add session CRUD operations                                  |
| `server.js`              | Add trust proxy config, register routes                      |
| `user-ui/src/lib/api.ts` | Add session management methods                               |

## Files to Create

| File                            | Purpose                            |
| ------------------------------- | ---------------------------------- |
| `middleware/sse-auth.js`        | SSE-specific auth with query param |
| `routes/sessions.js`            | Session management endpoints       |
| `user-ui/src/pages/sessions.ts` | Session management UI              |

---

## Migration Steps

1. Run database migrations (add columns)
2. Deploy updated auth middleware
3. Deploy trust proxy configuration
4. Deploy session management routes
5. Deploy UI changes
6. Monitor for auth issues

## Rollback Plan

- Revert auth middleware to accept query params
- Disable trust proxy setting
- Session management routes are additive, can remain

---

## Priority

**High** - Addresses active security vulnerabilities.

## Estimated Effort

- Query param removal: 2 hours
- Trust proxy config: 2 hours
- Session management API: 4 hours
- UI components: 4 hours
- Testing: 3 hours

**Total: ~2 days**

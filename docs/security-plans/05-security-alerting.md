# Security Plan 05: Security Alerting and Monitoring

## Overview

Implement a comprehensive security alerting system that detects security events, applies configurable thresholds, routes alerts through multiple channels (email, webhooks, in-app), and provides deduplication and throttling.

## Current State

### Existing Components

- **Audit logging** - `db/index.js` (audit, meshAuditLogs, orgVaultAudit)
- **Anomaly detection** - `lib/anomaly-detection.js` (thresholds, baselines)
- **Rate limiting** - `lib/rate-limit.js` (with `onLimitReached` callbacks)
- **Email** - `lib/email.js` (Resend integration)
- **In-app notifications** - `db/index.js` (notifications table)
- **SSE** - `lib/sse.js` (real-time updates)

### Gaps

- No external alerting (email/webhook) for security events
- No configurable alert rules or thresholds
- No webhook support for Slack/Discord/PagerDuty
- No alert deduplication or throttling
- No alert configuration UI

---

## Implementation Plan

### Phase 1: Database Schema

Add to `management-server/db/migrate.js`:

```sql
-- Alert rules configuration
CREATE TABLE IF NOT EXISTS alert_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  event_type VARCHAR(100) NOT NULL,
  severity_threshold VARCHAR(20) DEFAULT 'warning',
  threshold_count INTEGER DEFAULT 1,
  threshold_window_minutes INTEGER DEFAULT 15,
  enabled BOOLEAN DEFAULT true,
  cooldown_minutes INTEGER DEFAULT 60,
  channels JSONB DEFAULT '["in_app"]'::jsonb,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Webhook channel configurations
CREATE TABLE IF NOT EXISTS alert_channels (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  channel_type VARCHAR(50) NOT NULL,
  name VARCHAR(255) NOT NULL,
  config_encrypted TEXT NOT NULL,
  enabled BOOLEAN DEFAULT true,
  last_success_at TIMESTAMP,
  last_failure_at TIMESTAMP,
  failure_count INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Alert history for deduplication
CREATE TABLE IF NOT EXISTS alert_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_id UUID REFERENCES alert_rules(id) ON DELETE SET NULL,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  event_type VARCHAR(100) NOT NULL,
  severity VARCHAR(20) NOT NULL,
  title VARCHAR(255) NOT NULL,
  message TEXT,
  metadata JSONB DEFAULT '{}',
  dedup_key VARCHAR(255),
  channels_sent JSONB DEFAULT '[]'::jsonb,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Alert cooldowns (throttling)
CREATE TABLE IF NOT EXISTS alert_cooldowns (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  dedup_key VARCHAR(255) NOT NULL UNIQUE,
  last_alerted_at TIMESTAMP NOT NULL,
  alert_count INTEGER DEFAULT 1,
  expires_at TIMESTAMP NOT NULL
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_alert_rules_user ON alert_rules(user_id);
CREATE INDEX IF NOT EXISTS idx_alert_rules_event ON alert_rules(event_type);
CREATE INDEX IF NOT EXISTS idx_alert_history_dedup ON alert_history(dedup_key);
CREATE INDEX IF NOT EXISTS idx_alert_cooldowns_expires ON alert_cooldowns(expires_at);
```

---

### Phase 2: Alert Service Core

Create `management-server/lib/alerting.js`:

```javascript
import crypto from "crypto";
import {
  alertRules,
  alertChannels,
  alertHistory,
  alertCooldowns,
  notifications,
  users,
} from "../db/index.js";
import { sendSecurityAlertEmail } from "./email.js";
import { broadcastToUser } from "./sse.js";

// Security event types
export const ALERT_EVENTS = {
  // Authentication
  AUTH_FAILED_THRESHOLD: "auth.failed_threshold",
  AUTH_NEW_DEVICE: "auth.new_device",
  AUTH_UNUSUAL_LOCATION: "auth.unusual_location",

  // Vault
  VAULT_UNLOCK_FAILED_THRESHOLD: "vault.unlock_failed_threshold",
  VAULT_LOCKED_BY_ANOMALY: "vault.locked_by_anomaly",
  VAULT_PASSWORD_CHANGED: "vault.password_changed",

  // Rate Limits
  RATE_LIMIT_AUTH: "rate_limit.auth",
  RATE_LIMIT_VAULT: "rate_limit.vault",
  RATE_LIMIT_API: "rate_limit.api",

  // Anomaly Detection
  ANOMALY_DETECTED: "anomaly.detected",
  ANOMALY_CRITICAL: "anomaly.critical",

  // Admin Actions
  ADMIN_USER_DELETED: "admin.user_deleted",
  ADMIN_SETTINGS_CHANGED: "admin.settings_changed",

  // Group Security
  GROUP_ADMIN_CHANGED: "group.admin_changed",
  GROUP_VAULT_UNLOCKED: "group.vault_unlocked",

  // Tokens
  TOKEN_REVOKED_ALL: "token.revoked_all",
};

// Default severity levels
const DEFAULT_SEVERITY = {
  [ALERT_EVENTS.AUTH_FAILED_THRESHOLD]: "warning",
  [ALERT_EVENTS.AUTH_NEW_DEVICE]: "info",
  [ALERT_EVENTS.VAULT_UNLOCK_FAILED_THRESHOLD]: "critical",
  [ALERT_EVENTS.VAULT_LOCKED_BY_ANOMALY]: "critical",
  [ALERT_EVENTS.RATE_LIMIT_AUTH]: "warning",
  [ALERT_EVENTS.RATE_LIMIT_VAULT]: "critical",
  [ALERT_EVENTS.ANOMALY_CRITICAL]: "critical",
  [ALERT_EVENTS.TOKEN_REVOKED_ALL]: "critical",
};

function generateDedupKey(eventType, userId, orgId, metadata = {}) {
  const components = [eventType, userId || "system", orgId || "none", metadata.ipAddress || ""];
  return crypto.createHash("sha256").update(components.join(":")).digest("hex").slice(0, 32);
}

async function isInCooldown(dedupKey, cooldownMinutes) {
  const cooldown = await alertCooldowns.findByKey(dedupKey);
  if (!cooldown) return false;
  return new Date() < new Date(cooldown.expires_at);
}

async function updateCooldown(dedupKey, cooldownMinutes) {
  const expiresAt = new Date(Date.now() + cooldownMinutes * 60 * 1000);
  await alertCooldowns.upsert(dedupKey, expiresAt);
}

/**
 * Main alert dispatch function
 */
export async function triggerAlert({
  eventType,
  userId,
  orgId,
  title,
  message,
  severity,
  metadata = {},
}) {
  try {
    const effectiveSeverity = severity || DEFAULT_SEVERITY[eventType] || "info";
    const dedupKey = generateDedupKey(eventType, userId, orgId, metadata);

    // Get applicable rules (or use defaults)
    let rules = await alertRules.findApplicable(userId, orgId, eventType);
    if (rules.length === 0) {
      rules = [
        {
          id: null,
          threshold_count: 1,
          threshold_window_minutes: 15,
          cooldown_minutes: 60,
          channels: ["in_app", "email"],
        },
      ];
    }

    for (const rule of rules) {
      // Check severity threshold
      if (!meetsThreshold(effectiveSeverity, rule.severity_threshold)) continue;

      // Check cooldown
      if (await isInCooldown(dedupKey, rule.cooldown_minutes)) {
        console.log(`[alerting] Suppressed by cooldown: ${eventType}`);
        continue;
      }

      // Check threshold count
      const recentCount = await alertHistory.countRecent(dedupKey, rule.threshold_window_minutes);
      if (recentCount + 1 < rule.threshold_count) {
        await alertHistory.create({
          ruleId: rule.id,
          userId,
          orgId,
          eventType,
          severity: effectiveSeverity,
          title,
          message,
          metadata,
          dedupKey,
          channelsSent: [],
        });
        continue;
      }

      // Send to channels
      const channelsSent = [];
      for (const channel of rule.channels) {
        try {
          await sendToChannel(channel, {
            userId,
            orgId,
            eventType,
            title,
            message,
            severity: effectiveSeverity,
            metadata,
          });
          channelsSent.push(channel);
        } catch (err) {
          console.error(`[alerting] Failed ${channel}:`, err.message);
        }
      }

      await alertHistory.create({
        ruleId: rule.id,
        userId,
        orgId,
        eventType,
        severity: effectiveSeverity,
        title,
        message,
        metadata,
        dedupKey,
        channelsSent,
      });
      await updateCooldown(dedupKey, rule.cooldown_minutes);
    }
  } catch (err) {
    console.error("[alerting] Error:", err);
  }
}

function meetsThreshold(severity, threshold) {
  const levels = { debug: 0, info: 1, warning: 2, critical: 3 };
  return (levels[severity] || 0) >= (levels[threshold] || 0);
}

async function sendToChannel(channel, alert) {
  switch (channel) {
    case "in_app":
      return sendInAppNotification(alert);
    case "email":
      return sendEmailAlert(alert);
    case "slack":
    case "discord":
    case "pagerduty":
    case "webhook":
      return sendWebhookAlert(channel, alert);
  }
}

async function sendInAppNotification({ userId, title, message, severity, metadata, eventType }) {
  if (!userId) return;
  const notification = await notifications.create({
    userId,
    type: "security_alert",
    title,
    message,
    severity,
    metadata: { ...metadata, eventType },
  });
  broadcastToUser(userId, "security_alert", {
    id: notification.id,
    title,
    message,
    severity,
    eventType,
    timestamp: new Date().toISOString(),
  });
}

async function sendEmailAlert({ userId, title, message, severity, metadata, eventType }) {
  if (!userId) return;
  const user = await users.findById(userId);
  if (user?.email) {
    await sendSecurityAlertEmail({
      to: user.email,
      subject: title,
      eventType,
      severity,
      message,
      metadata,
      actionUrl: `${process.env.USER_UI_URL}/activity`,
    });
  }
}

async function sendWebhookAlert(channelType, alert) {
  const { userId, orgId, title, message, severity, metadata, eventType } = alert;
  const channels = await alertChannels.findByType(userId, orgId, channelType);

  for (const channel of channels) {
    if (!channel.enabled) continue;
    try {
      const config = await alertChannels.getDecryptedConfig(channel.id);
      const payload = formatWebhookPayload(channelType, {
        title,
        message,
        severity,
        metadata,
        eventType,
      });

      const response = await fetch(config.webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(config.headers || {}) },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(10000),
      });

      if (!response.ok) throw new Error(`Webhook returned ${response.status}`);
      await alertChannels.recordSuccess(channel.id);
    } catch (err) {
      console.error(`[alerting] Webhook failed:`, err.message);
      await alertChannels.recordFailure(channel.id, err.message);
    }
  }
}

function formatWebhookPayload(channelType, alert) {
  const { title, message, severity, metadata, eventType } = alert;
  const timestamp = new Date().toISOString();

  switch (channelType) {
    case "slack":
      return {
        blocks: [
          { type: "header", text: { type: "plain_text", text: `🔒 ${title}` } },
          { type: "section", text: { type: "mrkdwn", text: message } },
          {
            type: "context",
            elements: [
              { type: "mrkdwn", text: `*Severity:* ${severity}` },
              { type: "mrkdwn", text: `*Event:* ${eventType}` },
            ],
          },
        ],
        attachments: [
          {
            color:
              severity === "critical" ? "#dc2626" : severity === "warning" ? "#f59e0b" : "#6366f1",
          },
        ],
      };

    case "discord":
      return {
        embeds: [
          {
            title: `🔒 ${title}`,
            description: message,
            color:
              severity === "critical" ? 0xdc2626 : severity === "warning" ? 0xf59e0b : 0x6366f1,
            fields: [
              { name: "Severity", value: severity, inline: true },
              { name: "Event", value: eventType, inline: true },
            ],
            timestamp,
          },
        ],
      };

    case "pagerduty":
      return {
        routing_key: metadata.routingKey,
        event_action: severity === "critical" ? "trigger" : "change",
        payload: {
          summary: title,
          severity: severity === "critical" ? "critical" : "warning",
          source: "OCMT",
          custom_details: { message, ...metadata },
        },
      };

    default:
      return { event: eventType, title, message, severity, metadata, timestamp };
  }
}

export async function cleanupExpiredCooldowns() {
  return await alertCooldowns.deleteExpired();
}
```

---

### Phase 3: Email Templates

Extend `management-server/lib/email.js`:

```javascript
export async function sendSecurityAlertEmail({
  to,
  subject,
  eventType,
  severity,
  message,
  metadata,
  actionUrl,
}) {
  if (!resend) return false;

  const colors = {
    critical: { bg: "#fef2f2", border: "#dc2626", text: "#991b1b" },
    warning: { bg: "#fffbeb", border: "#f59e0b", text: "#92400e" },
    info: { bg: "#eff6ff", border: "#3b82f6", text: "#1e40af" },
  };
  const c = colors[severity] || colors.info;

  await resend.emails.send({
    from: EMAIL_FROM,
    to,
    subject: `🔒 ${subject}`,
    html: `
      <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 40px 20px;">
        <div style="background: ${c.bg}; border-left: 4px solid ${c.border}; padding: 20px; border-radius: 8px;">
          <h2 style="color: ${c.text}; margin: 0 0 12px;">${subject}</h2>
          <p style="color: ${c.text}; margin: 0;">${message}</p>
        </div>
        <div style="background: #f9fafb; padding: 16px; border-radius: 8px; margin: 24px 0;">
          <p style="color: #6b7280; margin: 0; font-size: 13px;"><strong>Event:</strong> ${eventType}</p>
          ${metadata.ipAddress ? `<p style="color: #6b7280; margin: 8px 0 0; font-size: 13px;"><strong>IP:</strong> ${metadata.ipAddress}</p>` : ""}
        </div>
        ${actionUrl ? `<a href="${actionUrl}" style="display: inline-block; background: #4f46e5; color: white; padding: 14px 28px; border-radius: 8px; text-decoration: none;">View Activity Log →</a>` : ""}
      </div>
    `,
  });
  return true;
}
```

---

### Phase 4: Integration Points

#### Rate Limit Integration

Update `lib/rate-limit.js`:

```javascript
import { triggerAlert, ALERT_EVENTS } from "./alerting.js";

export const strictAuthLimiter = createRateLimiter({
  name: "strict-auth",
  windowMs: 15 * 60 * 1000,
  maxRequests: 5,
  onLimitReached: async (req, key) => {
    await triggerAlert({
      eventType: ALERT_EVENTS.RATE_LIMIT_AUTH,
      userId: req.user?.id,
      title: "Authentication Rate Limit Exceeded",
      message: `Too many auth attempts from IP ${key}`,
      metadata: { ipAddress: key, endpoint: req.path },
    });
  },
});

export const vaultUnlockLimiter = createRateLimiter({
  name: "vault-unlock",
  windowMs: 15 * 60 * 1000,
  maxRequests: 5,
  onLimitReached: async (req, key) => {
    await triggerAlert({
      eventType: ALERT_EVENTS.RATE_LIMIT_VAULT,
      userId: req.user?.id,
      title: "Vault Unlock Rate Limit Exceeded",
      message: "Multiple failed vault unlock attempts detected",
      severity: "critical",
      metadata: { ipAddress: key },
    });
  },
});
```

#### Anomaly Detection Integration

Update `lib/anomaly-detection.js`:

```javascript
import { triggerAlert, ALERT_EVENTS } from "./alerting.js";

async function handleAnomaly(userId, anomaly) {
  // Existing alert record creation...

  await triggerAlert({
    eventType:
      anomaly.severity === "critical"
        ? ALERT_EVENTS.ANOMALY_CRITICAL
        : ALERT_EVENTS.ANOMALY_DETECTED,
    userId,
    title: anomaly.severity === "critical" ? "Critical: Vault Locked" : "Unusual Activity Detected",
    message: anomaly.description,
    severity: anomaly.severity,
    metadata: { type: anomaly.type, metric: anomaly.metricName },
  });

  if (anomaly.severity === "critical") {
    await lockVaultForAnomaly(userId, alert.id);
  }
}
```

---

### Phase 5: Configuration API

Create `management-server/routes/alerts.js`:

```javascript
import { Router } from "express";
import { requireUser } from "../middleware/auth.js";
import { alertRules, alertChannels, alertHistory } from "../db/index.js";
import { ALERT_EVENTS } from "../lib/alerting.js";

const router = Router();

// List event types
router.get("/events", requireUser, (req, res) => {
  res.json({
    events: Object.entries(ALERT_EVENTS).map(([key, value]) => ({
      key,
      value,
      category: value.split(".")[0],
    })),
  });
});

// Get rules
router.get("/rules", requireUser, async (req, res) => {
  const rules = await alertRules.listForUser(req.user.id);
  res.json({ rules });
});

// Create/update rule
router.post("/rules", requireUser, async (req, res) => {
  const rule = await alertRules.upsert({ userId: req.user.id, ...req.body });
  res.json({ rule });
});

// Delete rule
router.delete("/rules/:id", requireUser, async (req, res) => {
  await alertRules.delete(req.params.id, req.user.id);
  res.json({ success: true });
});

// Get channels
router.get("/channels", requireUser, async (req, res) => {
  const channels = await alertChannels.listForUser(req.user.id);
  res.json({
    channels: channels.map((c) => ({
      id: c.id,
      channelType: c.channel_type,
      name: c.name,
      enabled: c.enabled,
      failureCount: c.failure_count,
    })),
  });
});

// Create webhook
router.post("/channels", requireUser, async (req, res) => {
  const channel = await alertChannels.create({ userId: req.user.id, ...req.body });
  res.json({ channel });
});

// Test webhook
router.post("/channels/:id/test", requireUser, async (req, res) => {
  // Send test alert to webhook
  res.json({ success: true });
});

// Get history
router.get("/history", requireUser, async (req, res) => {
  const { limit = 50 } = req.query;
  const history = await alertHistory.listForUser(req.user.id, parseInt(limit));
  res.json({ history });
});

export default router;
```

Register in `server.js`:

```javascript
import alertsRouter from "./routes/alerts.js";
app.use("/api/alerts", alertsRouter);
```

---

### Phase 6: UI Components

Create `user-ui/src/pages/alert-settings.ts`:

- Channel management (add/remove webhooks)
- Rule configuration (thresholds, severity, channels)
- Alert history view
- Test webhook functionality

---

## Security Events to Alert On

| Event                   | Default Severity | Default Channels       |
| ----------------------- | ---------------- | ---------------------- |
| Auth failed threshold   | Warning          | in_app, email          |
| New device login        | Info             | email                  |
| Unusual location        | Warning          | email                  |
| Vault unlock failed     | Critical         | in_app, email          |
| Vault locked by anomaly | Critical         | in_app, email, webhook |
| Rate limit exceeded     | Warning          | in_app                 |
| Admin actions           | Warning          | email                  |
| Group admin changed     | Warning          | email                  |

---

## Files to Modify

| File                       | Changes                     |
| -------------------------- | --------------------------- |
| `db/migrate.js`            | Add alert tables            |
| `db/index.js`              | Add alert CRUD operations   |
| `lib/rate-limit.js`        | Add alerting calls          |
| `lib/anomaly-detection.js` | Add alerting calls          |
| `lib/email.js`             | Add security email template |
| `server.js`                | Register alerts routes      |

## Files to Create

| File                                  | Purpose                 |
| ------------------------------------- | ----------------------- |
| `lib/alerting.js`                     | Core alerting service   |
| `routes/alerts.js`                    | Alert configuration API |
| `user-ui/src/pages/alert-settings.ts` | Settings UI             |

---

## Testing

### Unit Tests

```javascript
describe("Alerting Service", () => {
  it("generates consistent dedup keys");
  it("respects cooldown periods");
  it("respects threshold counts");
  it("formats Slack payloads correctly");
  it("formats Discord payloads correctly");
});
```

### Integration Tests

```javascript
describe("Alerting Integration", () => {
  it("rate limit triggers alert");
  it("anomaly detection triggers alert");
  it("webhook delivery works");
  it("deduplication prevents spam");
});
```

---

## Priority

**Medium-High** - Important for production security monitoring but can be phased in after foundational security fixes.

## Estimated Effort

- Phase 1 (Schema): 1 day
- Phase 2-3 (Core service + email): 2 days
- Phase 4 (Integrations): 2 days
- Phase 5 (API): 1 day
- Phase 6 (UI): 2 days
- Testing: 2 days

**Total: ~10 days**

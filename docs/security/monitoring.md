# Security Monitoring

Guidelines for monitoring OCMT deployments for security events.

## What to Log

### Authentication Events

| Event                  | Severity | Log Fields                                             |
| ---------------------- | -------- | ------------------------------------------------------ |
| Successful login       | INFO     | user_id, ip_address, user_agent, timestamp             |
| Failed login           | WARN     | email_attempted, ip_address, failure_reason, timestamp |
| Password reset request | INFO     | email, ip_address, timestamp                           |
| Session created        | INFO     | user_id, session_id_prefix, ip_address                 |
| Session invalidated    | INFO     | user_id, reason (logout/timeout/revoked)               |
| MFA success            | INFO     | user_id, method (totp/backup_code)                     |
| MFA failure            | WARN     | user_id, method, failure_reason                        |

### Authorization Events

| Event             | Severity | Log Fields                               |
| ----------------- | -------- | ---------------------------------------- |
| Access denied     | WARN     | user_id, resource, action, reason        |
| Admin action      | INFO     | admin_id, action, target, details        |
| Permission change | INFO     | user_id, target_user, permission, change |
| API key created   | INFO     | user_id, key_prefix, scopes              |
| API key revoked   | INFO     | user_id, key_prefix, reason              |

### Rate Limiting Events

| Event                    | Severity | Log Fields                                      |
| ------------------------ | -------- | ----------------------------------------------- |
| Rate limit warning (80%) | INFO     | identifier, endpoint, count, limit              |
| Rate limit exceeded      | WARN     | identifier, endpoint, count, limit, retry_after |
| Rate limit burst         | ERROR    | identifier, endpoint, requests_in_window        |

### Vault and Encryption Events

| Event                   | Severity | Log Fields                               |
| ----------------------- | -------- | ---------------------------------------- |
| Vault unlock success    | INFO     | user_id, method (password/biometric)     |
| Vault unlock failure    | WARN     | user_id, method, attempt_count           |
| Vault locked (timeout)  | INFO     | user_id, idle_duration                   |
| Encryption key rotation | INFO     | old_version, new_version, migrated_count |
| Decryption failure      | ERROR    | context, error_type                      |

### Container Events

| Event                | Severity | Log Fields                                   |
| -------------------- | -------- | -------------------------------------------- |
| Container created    | INFO     | user_id, container_id                        |
| Container started    | INFO     | user_id, container_id, wake_reason           |
| Container hibernated | INFO     | user_id, container_id, mode (pause/stop)     |
| Container error      | ERROR    | user_id, container_id, error                 |
| Resource limit hit   | WARN     | user_id, container_id, resource (memory/cpu) |

---

## Log Format

Use structured JSON logging for easy parsing:

```json
{
  "timestamp": "2024-01-15T10:30:00.000Z",
  "level": "WARN",
  "event": "auth.login_failed",
  "service": "management-server",
  "fields": {
    "email": "user@example.com",
    "ip": "192.168.1.100",
    "reason": "invalid_password",
    "attempt": 3
  },
  "trace_id": "abc123"
}
```

### Log Levels

| Level | Use For                                     |
| ----- | ------------------------------------------- |
| DEBUG | Detailed debugging (disabled in production) |
| INFO  | Normal operations, audit trail              |
| WARN  | Potential security issues, failed attempts  |
| ERROR | Security violations, system failures        |
| FATAL | Critical security breaches, data loss       |

---

## Alert Thresholds

### High Priority (Immediate Response)

| Condition                 | Threshold           | Action                      |
| ------------------------- | ------------------- | --------------------------- |
| Failed logins (same IP)   | 10 in 5 min         | Block IP, notify security   |
| Failed logins (same user) | 5 in 15 min         | Lock account, notify user   |
| Vault unlock failures     | 5 in 15 min         | Lock vault, notify user     |
| Admin auth failures       | 3 in 5 min          | Lock admin, notify security |
| Rate limit burst          | 100x limit in 1 min | Block IP, investigate       |

### Medium Priority (Review Within Hours)

| Condition            | Threshold         | Action                 |
| -------------------- | ----------------- | ---------------------- |
| Rate limit hits      | 50 in 1 hour      | Review traffic pattern |
| Access denied events | 20 in 1 hour      | Review permissions     |
| New admin actions    | Any               | Review in daily digest |
| Unusual API patterns | Anomaly detection | Manual review          |

### Low Priority (Weekly Review)

| Condition                   | Notes                     |
| --------------------------- | ------------------------- |
| Session timeout patterns    | Optimize timeout settings |
| Container hibernation stats | Capacity planning         |
| Resource utilization trends | Infrastructure scaling    |

---

## Alerting Configuration

### Slack/Discord Integration

```javascript
// Example alert payload
{
  "channel": "#security-alerts",
  "attachments": [{
    "color": "danger",
    "title": "Security Alert: Multiple Failed Logins",
    "fields": [
      { "title": "IP Address", "value": "192.168.1.100", "short": true },
      { "title": "Attempts", "value": "10", "short": true },
      { "title": "Time Window", "value": "5 minutes", "short": true },
      { "title": "Action Taken", "value": "IP blocked for 1 hour", "short": true }
    ],
    "footer": "OCMT Security | Production",
    "ts": 1705312200
  }]
}
```

### PagerDuty Integration

```javascript
// High-priority alert
{
  "routing_key": "your-pagerduty-key",
  "event_action": "trigger",
  "payload": {
    "summary": "CRITICAL: Admin authentication brute force detected",
    "source": "ocmt-management-server",
    "severity": "critical",
    "custom_details": {
      "ip_address": "192.168.1.100",
      "attempts": 10,
      "action": "Admin endpoint locked"
    }
  }
}
```

### Email Alerts

For critical events that require documented notification:

- Account lockouts
- Admin privilege changes
- Encryption key rotations
- Security policy changes

---

## Incident Response

### Classification

| Level         | Description                         | Response Time | Examples                                      |
| ------------- | ----------------------------------- | ------------- | --------------------------------------------- |
| P1 - Critical | Active breach, data exposure        | 15 minutes    | Unauthorized data access, admin compromise    |
| P2 - High     | Attempted breach, system compromise | 1 hour        | Brute force attack, suspicious admin activity |
| P3 - Medium   | Policy violations, anomalies        | 4 hours       | Rate limit abuse, unusual access patterns     |
| P4 - Low      | Minor issues, warnings              | 24 hours      | Configuration warnings, audit findings        |

### Response Steps

**P1 - Critical**

1. Acknowledge alert immediately
2. Isolate affected systems
3. Preserve logs and evidence
4. Notify security team lead
5. Begin incident investigation
6. Communicate to affected users (if applicable)
7. Document timeline and actions

**P2 - High**

1. Acknowledge alert within 15 minutes
2. Assess scope and impact
3. Apply immediate mitigations (block IP, lock account)
4. Investigate root cause
5. Document findings
6. Schedule post-incident review

**P3/P4 - Medium/Low**

1. Review during business hours
2. Document in security log
3. Apply fixes if needed
4. Include in weekly security review

---

## Log Retention

### Retention Policy

| Log Type            | Retention Period | Storage              |
| ------------------- | ---------------- | -------------------- |
| Security events     | 1 year           | Encrypted, immutable |
| Authentication logs | 90 days          | Standard storage     |
| Access logs         | 30 days          | Standard storage     |
| Debug logs          | 7 days           | Ephemeral            |

### Compliance Considerations

- GDPR: Right to erasure may require log anonymization
- SOC 2: Audit logs must be retained and protected
- HIPAA: Access logs required for 6 years

### Log Protection

- [ ] Logs stored in append-only storage
- [ ] Log integrity verification (checksums)
- [ ] Separate log storage from application
- [ ] Encrypted at rest
- [ ] Access logging for log access

---

## Monitoring Tools

### Recommended Stack

| Component       | Options                                |
| --------------- | -------------------------------------- |
| Log aggregation | ELK Stack, Loki, CloudWatch Logs       |
| Metrics         | Prometheus, DataDog, CloudWatch        |
| Alerting        | PagerDuty, Opsgenie, VictorOps         |
| Dashboards      | Grafana, Kibana, DataDog               |
| SIEM            | Splunk, Elastic SIEM, AWS Security Hub |

### Example Grafana Dashboard

Key panels to include:

1. **Authentication Overview**
   - Login success/failure rate
   - Failed login heatmap by IP
   - Active sessions count

2. **Rate Limiting**
   - Rate limit hits over time
   - Top limited endpoints
   - Blocked IPs

3. **Container Health**
   - Active vs hibernated containers
   - Container errors
   - Resource utilization

4. **Security Events**
   - Event timeline
   - Alert count by severity
   - Top security events

---

## Health Check Monitoring

### Endpoints to Monitor

```bash
# Management Server
GET /health
# Expected: {"status":"ok","relay":{"healthy":true},"redis":{"connected":true}}

# Agent Server
GET /health
# Expected: {"status":"ok","containers":N,"hibernation":{...}}

# Relay Server
GET /health
# Expected: {"status":"ok"}
```

### Health Check Alerts

| Condition             | Alert                 |
| --------------------- | --------------------- |
| Health check fails    | P2 - Service degraded |
| Health check fails 3x | P1 - Service down     |
| Redis disconnected    | P3 - Fallback active  |
| Database unreachable  | P1 - Critical failure |

---

## See Also

- [Deployment Security](/security/deployment)
- [Production Hardening](/security/hardening)
- [Secrets Management](/security/secrets)
- [Security Alerting Plan](/security-plans/05-security-alerting)

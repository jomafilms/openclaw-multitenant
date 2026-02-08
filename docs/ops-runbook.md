# Operations Runbook

This runbook provides incident response procedures and troubleshooting guidance for production OCMT deployments.

## On-Call Quick Reference

### Critical Alerts - Immediate Action Required

| Alert                      | First Response                      | Escalation    |
| -------------------------- | ----------------------------------- | ------------- |
| Database unreachable       | Check connection, restart if needed | DBA on-call   |
| Vault compromise suspected | Lock all vaults, rotate keys        | Security lead |
| Rate limit exhaustion      | Check for attack, adjust limits     | Platform team |
| Memory exhaustion          | Restart service, check for leaks    | Platform team |
| Certificate expiry         | Renew immediately                   | DevOps        |

### Service Health Endpoints

```bash
# Quick health check all services
curl -s http://localhost:18789/health          # Gateway
curl -s http://localhost:8080/health           # Management server
curl -s http://localhost:8081/health           # Agent server
curl -s http://localhost:8082/health           # Relay server
curl -s http://localhost:8083/health           # Group vault
```

## Incident Response Procedures

### INC-001: Authentication Failures Spike

**Symptoms:**

- High rate of 401 responses
- Rate limiter triggering frequently
- User reports of login failures

**Immediate Actions:**

1. Check if this is a targeted attack vs widespread issue:

   ```bash
   # Check rate limit hits by IP
   grep "rate limit" /var/log/openclaw/*.log | awk '{print $NF}' | sort | uniq -c | sort -rn | head -20
   ```

2. If attack - block offending IPs at load balancer level

3. If legitimate - check auth service health:

   ```bash
   # Verify database connectivity
   psql $DATABASE_URL -c "SELECT 1"

   # Check session store
   curl -s http://localhost:8080/health | jq .sessions
   ```

**Resolution:**

- If credential stuffing: Enable additional rate limiting, notify affected users
- If service issue: Restart auth service, verify database connections
- If token issues: Check SESSION_SECRET hasn't changed, verify cookie settings

---

### INC-002: Token Compromise Suspected

**Symptoms:**

- Unusual API activity from a user/container
- Audit log shows unauthorized operations
- User reports activity they didn't perform

**Immediate Actions:**

1. **Revoke all tokens for affected entity:**

   ```bash
   # Revoke user's capability tokens
   curl -X POST -H "X-Auth-Token: $ADMIN_TOKEN" \
     https://api.yourdomain.com/admin/users/{userId}/revoke-all

   # Revoke specific container tokens
   curl -X DELETE -H "X-Auth-Token: $VAULT_TOKEN" \
     https://group-vault/tokens/{tokenId}
   ```

2. **Lock affected vault if group-level compromise:**

   ```bash
   curl -X POST -H "X-Auth-Token: $ADMIN_TOKEN" \
     https://group-vault/groups/{groupId}/lock
   ```

3. **Collect evidence:**
   ```bash
   # Export relevant audit logs
   psql $DATABASE_URL -c "COPY (SELECT * FROM audit_logs WHERE user_id = '{userId}' AND created_at > NOW() - INTERVAL '24 hours') TO STDOUT WITH CSV HEADER" > incident_logs.csv
   ```

**Investigation:**

- Check how token was obtained (phishing, API leak, session hijack)
- Review all actions taken with compromised token
- Identify any data exfiltration

**Resolution:**

- Force password reset for affected users
- Rotate any secrets the token had access to
- Review and tighten token scopes if needed

---

### INC-003: Database Connection Exhaustion

**Symptoms:**

- Services returning 500 errors
- "too many connections" in logs
- Slow response times

**Immediate Actions:**

1. **Check current connections:**

   ```bash
   psql $DATABASE_URL -c "SELECT count(*) FROM pg_stat_activity"
   psql $DATABASE_URL -c "SELECT usename, application_name, count(*) FROM pg_stat_activity GROUP BY 1,2 ORDER BY 3 DESC"
   ```

2. **Kill idle connections if needed:**

   ```bash
   psql $DATABASE_URL -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'idle' AND query_start < NOW() - INTERVAL '10 minutes'"
   ```

3. **Restart affected services** to reset connection pools

**Prevention:**

- Ensure connection pooling is configured (PgBouncer recommended)
- Set appropriate `max_connections` in PostgreSQL
- Configure connection timeouts in application

---

### INC-004: Memory Exhaustion / OOM

**Symptoms:**

- Service crashes with OOM killer
- Kubernetes pod evictions
- Gradual memory increase over time

**Immediate Actions:**

1. **Restart affected service** to restore functionality

2. **Capture heap dump before restart if possible:**

   ```bash
   # For Node.js
   kill -USR2 <pid>  # Triggers heap dump if --heapsnapshot-signal enabled
   ```

3. **Check for obvious leaks:**
   ```bash
   # Monitor memory usage
   watch -n 5 'ps aux --sort=-%mem | head -10'
   ```

**Investigation:**

- Check if memory correlates with request volume
- Look for unbounded caches or collections
- Review recent deployments for memory-intensive changes

**Common Causes:**

- WebSocket connections not being cleaned up (check `MAX_WEBSOCKET_CONNECTIONS`)
- Large file uploads held in memory
- Unbounded session/cache storage

---

### INC-005: Relay Message Backlog

**Symptoms:**

- Messages taking long to deliver
- Queue depth increasing
- Timeout errors on send

**Immediate Actions:**

1. **Check queue depth:**

   ```bash
   curl -s http://localhost:8082/health | jq .queueDepth
   ```

2. **Check for stuck consumers:**

   ```bash
   curl -s http://localhost:8082/health | jq .consumers
   ```

3. **If consumer is stuck, restart it:**
   ```bash
   # Restart specific consumer
   docker restart relay-consumer-1
   ```

**Investigation:**

- Check if specific destination is unreachable
- Look for message size anomalies
- Verify downstream services are healthy

---

### INC-006: Certificate Expiry

**Symptoms:**

- SSL/TLS errors in logs
- Browsers showing certificate warnings
- Service-to-service calls failing

**Immediate Actions:**

1. **Check certificate expiry:**

   ```bash
   echo | openssl s_client -connect yourdomain.com:443 2>/dev/null | openssl x509 -noout -dates
   ```

2. **Renew certificate:**

   ```bash
   # Using certbot
   certbot renew --force-renewal

   # Or manually with Let's Encrypt
   certbot certonly --webroot -w /var/www/html -d yourdomain.com
   ```

3. **Reload services to pick up new cert:**
   ```bash
   nginx -s reload
   # or
   docker restart reverse-proxy
   ```

---

## Troubleshooting Guide

### Gateway Won't Start

**Check configuration:**

```bash
openclaw doctor
openclaw config get gateway.mode
```

**Common issues:**

- Port already in use: `lsof -i :18789`
- Missing required config: Check error message for missing keys
- Database not accessible: Verify `DATABASE_URL`

### WebSocket Connections Dropping

**Check limits:**

```bash
# Current connection count
curl -s http://localhost:18789/health | jq .wsConnections

# System limits
ulimit -n
sysctl net.core.somaxconn
```

**Increase limits if needed:**

```bash
# In /etc/sysctl.conf
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535

# In /etc/security/limits.conf
* soft nofile 65535
* hard nofile 65535
```

### Slow API Responses

**Check database query performance:**

```bash
psql $DATABASE_URL -c "SELECT query, calls, mean_time, total_time FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10"
```

**Check for missing indexes:**

```bash
psql $DATABASE_URL -c "SELECT schemaname, tablename, indexname FROM pg_indexes WHERE indexname IS NULL"
```

**Check connection pool:**

```bash
# If using PgBouncer
psql -p 6432 pgbouncer -c "SHOW POOLS"
```

### Container Secret Store Issues

**Verify encryption:**

```bash
# Check if secrets are properly encrypted
openclaw security audit --container <id>
```

**Re-initialize if corrupted:**

```bash
# Backup first!
cp ~/.openclaw/containers/<id>/secrets.enc ~/.openclaw/containers/<id>/secrets.enc.bak

# Re-initialize
openclaw containers init <id> --force
```

## Recovery Procedures

### Full Database Restore

```bash
# Stop all services
systemctl stop openclaw-*

# Restore from backup
pg_restore -d $DATABASE_URL backup.sql

# Run any pending migrations
pnpm db:migrate

# Restart services
systemctl start openclaw-*

# Verify
openclaw doctor
```

### Vault Key Rotation

```bash
# 1. Generate new signing key
NEW_KEY=$(openssl rand -hex 32)

# 2. Update group-vault configuration
export GROUP_VAULT_SIGNING_KEY=$NEW_KEY

# 3. Restart group-vault service
docker restart group-vault

# 4. All existing tokens will be invalidated
# Users will need to re-authenticate
```

### Emergency Shutdown

If a critical security incident requires immediate shutdown:

```bash
# Stop all external traffic
iptables -I INPUT -p tcp --dport 443 -j DROP
iptables -I INPUT -p tcp --dport 80 -j DROP

# Stop services gracefully
systemctl stop openclaw-gateway
systemctl stop openclaw-management
systemctl stop openclaw-relay
systemctl stop openclaw-vault

# Lock all vaults
for group in $(psql $DATABASE_URL -t -c "SELECT id FROM groups"); do
  curl -X POST -H "X-Auth-Token: $ADMIN_TOKEN" \
    https://group-vault/groups/$group/lock
done
```

## Monitoring Setup

### Key Metrics to Track

| Metric           | Warning    | Critical   | Action                           |
| ---------------- | ---------- | ---------- | -------------------------------- |
| Error rate (5xx) | > 1%       | > 5%       | Check logs, restart if needed    |
| P99 latency      | > 500ms    | > 2000ms   | Check database, optimize queries |
| Memory usage     | > 80%      | > 95%      | Investigate leaks, scale up      |
| CPU usage        | > 70%      | > 90%      | Scale horizontally               |
| DB connections   | > 80% pool | > 95% pool | Increase pool, check leaks       |
| Queue depth      | > 1000     | > 10000    | Scale consumers                  |
| Rate limit hits  | > 100/min  | > 1000/min | Check for attack                 |

### Log Aggregation Queries

```bash
# Errors in last hour
grep -E "error|ERROR" /var/log/openclaw/*.log | grep "$(date -d '1 hour ago' +'%Y-%m-%d %H')"

# Auth failures
grep "401\|Unauthorized\|auth failed" /var/log/openclaw/*.log | tail -100

# Slow requests (> 1s)
grep "duration.*[0-9]{4,}ms" /var/log/openclaw/*.log
```

## Cleanup Job Monitoring

OCMT has several background cleanup jobs that must run regularly to prevent resource exhaustion.

### Cleanup Jobs Overview

| Job                | Location     | Frequency  | Purpose                           |
| ------------------ | ------------ | ---------- | --------------------------------- |
| Revocation cleanup | Relay server | Hourly     | Remove expired revocation records |
| Snapshot cleanup   | Relay server | Hourly     | Purge stale capability snapshots  |
| Session cleanup    | Secret store | On expiry  | Clear expired vault sessions      |
| Rate limit cleanup | Gateway      | Continuous | Clear stale rate limit entries    |

### Monitoring Cleanup Health

**Check revocation store size:**

```bash
# Query revocation count (should not grow unbounded)
curl -s http://localhost:8082/health | jq .revocationCount

# Expected: Should plateau based on retention policy
# Alert if: Growing > 10% per day without corresponding traffic increase
```

**Check snapshot store:**

```bash
# Query pending snapshots
curl -s http://localhost:8082/health | jq .pendingSnapshots

# Expected: < 100 pending at any time
# Alert if: > 1000 pending (indicates push failures)
```

**Monitor cleanup execution:**

```bash
# Check cleanup logs
grep "cleanup" /var/log/openclaw/*.log | tail -20

# Should see regular entries like:
# [relay] Cleaned up 42 expired revocations
# [snapshot] Removed 15 stale snapshots
```

### Troubleshooting Cleanup Failures

1. **Cleanup not running:**
   - Check if relay service is healthy
   - Verify cron/scheduler is running
   - Check for error logs

2. **Cleanup taking too long:**
   - Database may need indexing
   - Consider batch size adjustment
   - Check for lock contention

3. **Resources still growing:**
   - Retention policy may be too long
   - Check for cleanup errors
   - Verify expiry timestamps are set correctly

## Database Backup Procedures

### Automated Backup Setup

**Daily backup script (`/etc/cron.daily/openclaw-backup`):**

```bash
#!/bin/bash
set -euo pipefail

BACKUP_DIR="/var/backups/openclaw"
RETENTION_DAYS=30
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Dump database
pg_dump "$DATABASE_URL" | gzip > "$BACKUP_DIR/openclaw_$DATE.sql.gz"

# Backup config (exclude secrets)
tar czf "$BACKUP_DIR/config_$DATE.tar.gz" \
  --exclude='*.enc' \
  --exclude='auth-profiles.json' \
  /home/node/.openclaw/

# Cleanup old backups
find "$BACKUP_DIR" -name "*.gz" -mtime +$RETENTION_DAYS -delete

# Log success
echo "[$(date)] Backup completed: openclaw_$DATE.sql.gz" >> /var/log/openclaw-backup.log
```

### Backup Verification

**Weekly verification script:**

```bash
#!/bin/bash
# Verify backup integrity

LATEST=$(ls -t /var/backups/openclaw/openclaw_*.sql.gz | head -1)

# Check file exists and is not empty
if [[ ! -s "$LATEST" ]]; then
  echo "ALERT: Latest backup is missing or empty" | mail -s "Backup Alert" ops@company.com
  exit 1
fi

# Test decompression
if ! gunzip -t "$LATEST"; then
  echo "ALERT: Latest backup is corrupted" | mail -s "Backup Alert" ops@company.com
  exit 1
fi

# Optionally: Restore to test database
# pg_restore -d openclaw_test < "$LATEST"

echo "Backup verified: $LATEST"
```

### Critical Tables to Monitor

| Table             | Purpose                  | Backup Priority         |
| ----------------- | ------------------------ | ----------------------- |
| `revocations`     | Token revocation records | Critical                |
| `audit_logs`      | Security audit trail     | Critical                |
| `mesh_audit_logs` | Mesh security events     | Critical                |
| `groups`          | Group configuration      | High                    |
| `users`           | User accounts            | High                    |
| `sessions`        | Active sessions          | Medium (can regenerate) |

### Restore Procedures

**Point-in-time restore:**

```bash
# 1. Stop services
systemctl stop openclaw-*

# 2. Identify target backup
ls -la /var/backups/openclaw/

# 3. Restore database
gunzip -c /var/backups/openclaw/openclaw_20240101_120000.sql.gz | psql $DATABASE_URL

# 4. Verify data integrity
psql $DATABASE_URL -c "SELECT COUNT(*) FROM users"
psql $DATABASE_URL -c "SELECT COUNT(*) FROM revocations"

# 5. Restart services
systemctl start openclaw-*

# 6. Verify functionality
openclaw doctor
```

### Backup Monitoring Alerts

Set up alerts for:

- Backup job failures (no new backup in 25 hours)
- Backup size anomalies (> 50% change from previous)
- Disk space for backup volume (> 80% full)
- Backup verification failures

## Contact Escalation

| Level | Timeframe | Who              | Contact              |
| ----- | --------- | ---------------- | -------------------- |
| L1    | 0-15 min  | On-call engineer | PagerDuty            |
| L2    | 15-30 min | Platform lead    | Slack #incidents     |
| L3    | 30-60 min | Security team    | security@company.com |
| L4    | 60+ min   | VP Engineering   | Phone                |

---

_Last updated: 2026-02-06_

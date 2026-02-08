# Production Hardening Checklist

Step-by-step checklist for hardening OCMT deployments.

## Pre-Production Checklist

### Authentication and Authorization

- [ ] **Set ADMIN_TOKEN environment variable**

  ```bash
  ADMIN_TOKEN=$(node -e "console.log(require('crypto').randomBytes(24).toString('base64'))")
  ```

  Without this, admin endpoints return 500 errors. With a weak token, attackers can access administrative functions.

- [ ] **Set AGENT_SERVER_TOKEN**

  ```bash
  AGENT_SERVER_TOKEN=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
  ```

  Must match `AUTH_TOKEN` on agent server.

- [ ] **Configure session timeouts**

  ```bash
  USER_SESSION_TIMEOUT_MS=604800000  # 7 days (adjust based on security requirements)
  MAX_SESSIONS_PER_USER=5
  ```

- [ ] **Enable pairing mode for unknown senders**
  ```json
  {
    "gateway": {
      "dmPolicy": "pairing"
    }
  }
  ```

---

### Encryption and Secrets

- [ ] **Generate and store ENCRYPTION_KEY**

  ```bash
  ENCRYPTION_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
  ```

  - Store in secrets manager
  - Create offline backup
  - Document recovery procedure

- [ ] **Verify encryption key format**
  - Exactly 64 hex characters
  - Cryptographically random (not derived from password)

---

### Redis Configuration

- [ ] **Configure Redis for distributed rate limiting**

  ```bash
  REDIS_URL=redis://:password@redis-host:6379
  ```

- [ ] **Set Redis authentication**

  ```bash
  # In Redis config or docker-compose
  requirepass your-secure-redis-password
  ```

- [ ] **Configure memory limits**

  ```bash
  maxmemory 256mb
  maxmemory-policy volatile-lru
  ```

- [ ] **Enable persistence for recovery**
  ```bash
  appendonly yes
  ```

---

### TLS/HTTPS

- [ ] **Enable HTTPS/TLS termination**
  - Use reverse proxy (Caddy, nginx) or cloud load balancer
  - Valid certificate from trusted CA

- [ ] **Configure HSTS** (after testing)

  ```
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  ```

- [ ] **Redirect HTTP to HTTPS**

  ```nginx
  server {
      listen 80;
      return 301 https://$host$request_uri;
  }
  ```

- [ ] **Disable weak TLS versions and ciphers**
  - Minimum TLS 1.2
  - Prefer TLS 1.3
  - Disable CBC mode ciphers

---

### Rate Limiting

- [ ] **Verify rate limits are configured**

  | Endpoint       | Limit        | Window                |
  | -------------- | ------------ | --------------------- |
  | Authentication | 5 attempts   | 15 min                |
  | Vault unlock   | 5 attempts   | 15 min (with backoff) |
  | API general    | 100 requests | 15 min                |
  | Password reset | 3 requests   | 1 hour                |

- [ ] **Test rate limiting is working**
  ```bash
  # Should return 429 after limit exceeded
  for i in {1..10}; do curl -X POST https://api.example.com/auth/login; done
  ```

---

### IP Allowlists

- [ ] **Configure admin IP allowlist** (if applicable)

  ```bash
  ADMIN_ALLOWED_IPS=10.0.0.0/8,192.168.1.0/24
  ```

- [ ] **Configure trusted proxy IPs**
  ```bash
  TRUST_PROXY=1
  TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
  ```

---

### Security Headers

- [ ] **Verify security headers are set**

  ```bash
  curl -I https://api.example.com/health | grep -E "(Content-Security|Strict-Transport|X-Frame|X-Content-Type)"
  ```

  Expected headers:
  - `Content-Security-Policy`
  - `Strict-Transport-Security`
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: strict-origin-when-cross-origin`

- [ ] **Test CSP is not blocking legitimate resources**
  - Check browser console for CSP violations
  - Verify WebSocket connections work
  - Verify Google Fonts load

---

### Container Security

- [ ] **Run containers as non-root**

  ```yaml
  user: "1000:1000"
  ```

- [ ] **Set resource limits**

  ```yaml
  deploy:
    resources:
      limits:
        memory: 2G
        cpus: "2.0"
  ```

- [ ] **Enable health checks**

  ```yaml
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
    interval: 30s
    timeout: 10s
    retries: 3
  ```

- [ ] **Configure log rotation**
  ```yaml
  logging:
    driver: json-file
    options:
      max-size: "100m"
      max-file: "3"
  ```

---

### Database Security

- [ ] **Use strong database password**

  ```bash
  DATABASE_URL=postgresql://user:strong-random-password@host:5432/ocmt
  ```

- [ ] **Database on private network only**
  - No public IP
  - Firewall rules restrict access

- [ ] **Enable SSL for database connections** (if supported)

  ```bash
  DATABASE_URL=postgresql://user:pass@host:5432/ocmt?sslmode=require
  ```

- [ ] **Regular database backups**
  - Automated daily backups
  - Test restore procedure
  - Encrypt backup files

---

### Monitoring and Alerting

- [ ] **Configure security event logging**
  - Failed authentication attempts
  - Rate limit violations
  - Unusual API patterns

- [ ] **Set up alerting**
  - PagerDuty, Slack, or Discord integration
  - Alert on multiple failed logins
  - Alert on rate limit bursts

- [ ] **Enable audit logging**
  - User actions logged
  - API calls logged
  - Container operations logged

---

## Post-Deployment Verification

### Security Scanning

- [ ] **Run security header scan**
  - https://securityheaders.com
  - Target grade: A or A+

- [ ] **Run SSL/TLS scan**
  - https://www.ssllabs.com/ssltest/
  - Target grade: A or A+

- [ ] **Run dependency audit**
  ```bash
  npm audit
  ```

### Functional Testing

- [ ] **Test authentication flow**
  - Magic link login works
  - Session timeout enforced
  - Invalid tokens rejected

- [ ] **Test rate limiting**
  - Limits enforced correctly
  - Legitimate users not blocked

- [ ] **Test encryption**
  - Secrets stored encrypted
  - Decryption works correctly

---

## Ongoing Maintenance

### Weekly

- [ ] Review security alerts
- [ ] Check for failed login patterns
- [ ] Review rate limit logs

### Monthly

- [ ] Update dependencies (`npm update`)
- [ ] Review and rotate ADMIN_TOKEN if needed
- [ ] Check certificate expiration dates

### Quarterly

- [ ] Rotate all service tokens
- [ ] Review user access and permissions
- [ ] Security audit of configuration
- [ ] Test backup restoration

### Annually

- [ ] Full security assessment
- [ ] Review and update security policies
- [ ] ENCRYPTION_KEY rotation (with migration)
- [ ] Update TLS configuration

---

## Quick Reference Commands

```bash
# Generate secure token
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Test health endpoint
curl https://api.example.com/health

# Check security headers
curl -I https://api.example.com/health

# Verify TLS configuration
openssl s_client -connect api.example.com:443 -tls1_3

# Check Redis connection
redis-cli -h redis-host -a password ping

# View recent security events
tail -f /var/log/ocmt/security.log
```

---

## See Also

- [Deployment Security](/security/deployment)
- [Secrets Management](/security/secrets)
- [Security Monitoring](/security/monitoring)
- [SECURITY_ARCHITECTURE.md](/SECURITY_ARCHITECTURE.md)

# Deployment Security Checklist

Security requirements for deploying OCMT in production environments.

## TLS/HTTPS Requirements

Production deployments **must** use TLS for all external traffic.

### Required Configuration

| Endpoint          | Protocol    | Notes                                        |
| ----------------- | ----------- | -------------------------------------------- |
| Management Server | HTTPS (443) | User-facing API and UI                       |
| User UI           | HTTPS (443) | Static assets and SPA                        |
| WebSocket         | WSS         | Secure WebSocket for real-time communication |
| Admin UI          | HTTPS (443) | Administrative dashboard                     |

### TLS Termination Options

**Option A: Reverse Proxy (Recommended)**

Use Caddy, nginx, or a cloud load balancer for TLS termination:

```
# Caddyfile example
api.yourdomain.com {
    reverse_proxy management-server:3000
}

app.yourdomain.com {
    reverse_proxy user-ui:80
}
```

**Option B: Cloud Load Balancer**

- AWS Application Load Balancer with ACM certificate
- GCP Cloud Load Balancing with managed certificates
- DigitalOcean Load Balancer with Let's Encrypt

### Certificate Requirements

- Use certificates from a trusted CA (Let's Encrypt is acceptable)
- Enable automatic renewal
- Minimum TLS 1.2; prefer TLS 1.3
- Disable weak cipher suites

---

## Network Isolation

### Component Communication

```
                    ┌─────────────────────────────────────┐
                    │           Public Internet            │
                    └────────────────┬────────────────────┘
                                     │
                              (HTTPS/WSS)
                                     │
                    ┌────────────────▼────────────────────┐
                    │       Load Balancer / Reverse Proxy  │
                    │       (TLS Termination)              │
                    └────────────────┬────────────────────┘
                                     │
                              (HTTP/WS)
                                     │
┌────────────────────────────────────┼────────────────────────────────────┐
│                            Private Network                               │
│                                    │                                     │
│    ┌───────────────┐    ┌─────────▼─────────┐    ┌───────────────┐     │
│    │ Management    │◄───│    Relay Server    │───►│ Agent Server  │     │
│    │ Server        │    │                    │    │               │     │
│    │ :3000         │    │    :5000           │    │   :4000       │     │
│    └───────────────┘    └────────────────────┘    └───────┬───────┘     │
│            │                                              │              │
│            ▼                                              ▼              │
│    ┌───────────────┐                            ┌─────────────────┐     │
│    │  PostgreSQL   │                            │ User Containers │     │
│    │    :5432      │                            │ (Isolated)      │     │
│    └───────────────┘                            └─────────────────┘     │
└──────────────────────────────────────────────────────────────────────────┘
```

### Isolation Requirements

- [ ] Database (PostgreSQL) on private network only
- [ ] Inter-service communication over private network
- [ ] User containers isolated from each other
- [ ] No direct public access to internal services

---

## Firewall Rules

### Inbound (Public)

| Port | Protocol | Source   | Destination   | Purpose                |
| ---- | -------- | -------- | ------------- | ---------------------- |
| 443  | TCP      | Internet | Load Balancer | HTTPS traffic          |
| 80   | TCP      | Internet | Load Balancer | HTTP redirect to HTTPS |

### Internal (Private Network)

| Port  | Protocol | Source                          | Destination       | Purpose                 |
| ----- | -------- | ------------------------------- | ----------------- | ----------------------- |
| 3000  | TCP      | Load Balancer                   | Management Server | API requests            |
| 5000  | TCP      | Management Server               | Relay Server      | Message relay           |
| 4000  | TCP      | Management Server               | Agent Server      | Container management    |
| 5432  | TCP      | Management Server, Relay Server | PostgreSQL        | Database                |
| 6379  | TCP      | All services                    | Redis             | Rate limiting, sessions |
| 18789 | TCP      | Relay Server                    | User Containers   | Gateway communication   |

### Outbound

| Port | Protocol | Source            | Destination         | Purpose              |
| ---- | -------- | ----------------- | ------------------- | -------------------- |
| 443  | TCP      | Management Server | OAuth providers     | OAuth callbacks      |
| 443  | TCP      | User Containers   | AI providers        | API calls            |
| 443  | TCP      | User Containers   | Messaging platforms | Channel integrations |

---

## Load Balancer Configuration

### Health Check Endpoints

```bash
# Management Server
GET /health
# Expected: {"status":"ok","relay":{...},"redis":{...}}

# Agent Server
GET /health
# Expected: {"status":"ok","containers":N,"hibernation":{...}}

# Relay Server
GET /health
# Expected: {"status":"ok"}
```

### Recommended Settings

| Setting               | Value | Notes                            |
| --------------------- | ----- | -------------------------------- |
| Health check interval | 30s   | Balance responsiveness vs load   |
| Health check timeout  | 10s   | Allow for slow database queries  |
| Unhealthy threshold   | 3     | Mark unhealthy after 3 failures  |
| Connection timeout    | 60s   | Allow for long-running requests  |
| Idle timeout          | 300s  | Keep WebSocket connections alive |
| Max request body size | 10MB  | Prevent large payload DoS        |

### WebSocket Support

Ensure load balancer supports WebSocket upgrades:

```nginx
# nginx example
location /ws {
    proxy_pass http://management-server:3000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 86400;
}
```

---

## Required Environment Variables

### Management Server

```bash
# Required
DATABASE_URL=postgresql://user:pass@host:5432/ocmt
ENCRYPTION_KEY=<64-hex-chars>          # See secrets.md
ADMIN_PASSWORD=<secure-password>       # Admin authentication
BASE_URL=https://api.yourdomain.com    # Public API URL
USER_UI_URL=https://app.yourdomain.com # Frontend URL
NODE_ENV=production

# Security
TRUST_PROXY=1                          # Behind load balancer
TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16

# Optional (recommended)
REDIS_URL=redis://redis:6379           # Distributed rate limiting
AGENT_SERVER_URL=http://agent-server:4000
AGENT_SERVER_TOKEN=<secure-token>
```

### Relay Server

```bash
DATABASE_URL=postgresql://user:pass@host:5432/ocmt
AGENT_SERVER_URL=http://agent-server:4000
AGENT_SERVER_TOKEN=<secure-token>
NODE_ENV=production
```

### Agent Server

```bash
AUTH_TOKEN=<secure-token>              # Must match AGENT_SERVER_TOKEN
DATA_DIR=/opt/ocmt/data
NODE_ENV=production
```

### Admin UI

```bash
ADMIN_TOKEN=<secure-token>             # See secrets.md
OPENCLAW_CONFIG=/root/.openclaw/openclaw.json
```

---

## Pre-Deployment Checklist

### TLS/HTTPS

- [ ] TLS certificate installed and valid
- [ ] HTTP redirects to HTTPS
- [ ] HSTS header enabled (after testing)
- [ ] TLS 1.2+ only; weak ciphers disabled

### Network

- [ ] Database not exposed to public internet
- [ ] Internal services on private network
- [ ] Firewall rules configured per above
- [ ] User containers network-isolated

### Secrets

- [ ] ENCRYPTION_KEY generated and backed up
- [ ] ADMIN_TOKEN set (not default)
- [ ] AGENT_SERVER_TOKEN set (not default)
- [ ] Database password not default
- [ ] All secrets in environment variables (not in code)

### Infrastructure

- [ ] Health checks configured
- [ ] Resource limits set on containers
- [ ] Log rotation configured
- [ ] Backups scheduled for database

---

## Cloud-Specific Notes

### AWS

- Use VPC with private subnets for internal services
- Security Groups for firewall rules
- ALB with ACM for TLS
- RDS in private subnet with security group

### GCP

- Use VPC with private subnet
- Cloud Armor for WAF/DDoS protection
- Cloud Load Balancing with managed certificates
- Cloud SQL with private IP

### DigitalOcean

- Use VPC for private networking
- Managed Load Balancer with Let's Encrypt
- Managed Database with private network
- Droplet firewall rules

---

## See Also

- [Secrets Management](/security/secrets)
- [Production Hardening](/security/hardening)
- [Security Monitoring](/security/monitoring)

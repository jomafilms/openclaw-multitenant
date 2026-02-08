# OCMT on Google Cloud Run - Future Architecture

> **Status:** Draft for future migration. Current production runs on DigitalOcean.
> **Trigger to migrate:** 50+ users, enterprise customer inquiry, or DO capacity limits.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Google Cloud Platform                                │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      Cloud Load Balancer                             │    │
│  │                    (Global, HTTPS, SSL managed)                      │    │
│  └──────────────┬─────────────────┬─────────────────┬──────────────────┘    │
│                 │                 │                 │                        │
│                 ▼                 ▼                 ▼                        │
│  ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────────────┐    │
│  │  Management API  │ │    User UI       │ │    Agent Orchestrator    │    │
│  │  (Cloud Run)     │ │  (Cloud Storage  │ │    (Cloud Run)           │    │
│  │                  │ │   + CDN)         │ │                          │    │
│  │  - Auth/JWT      │ │                  │ │  - Container management  │    │
│  │  - Vault         │ │  Static hosting  │ │  - Hibernation logic     │    │
│  │  - User mgmt     │ │  ~$0/mo          │ │  - WebSocket proxy       │    │
│  │                  │ │                  │ │                          │    │
│  │  Min: 0 (scale   │ └──────────────────┘ │  Min: 1 (always-on for   │    │
│  │       to zero)   │                      │       webhook receiving) │    │
│  └──────────────────┘                      └────────────┬─────────────┘    │
│           │                                             │                   │
│           │                                             │                   │
│           ▼                                             ▼                   │
│  ┌──────────────────┐                      ┌──────────────────────────┐    │
│  │  Cloud SQL       │                      │  User Agent Containers   │    │
│  │  (PostgreSQL)    │                      │  (Cloud Run Jobs or      │    │
│  │                  │                      │   Cloud Run Services)    │    │
│  │  - Users         │                      │                          │    │
│  │  - Sessions      │                      │  ┌─────┐ ┌─────┐ ┌─────┐ │    │
│  │  - Vault data    │                      │  │User1│ │User2│ │UserN│ │    │
│  │                  │                      │  │Agent│ │Agent│ │Agent│ │    │
│  │  ~$10-30/mo      │                      │  └─────┘ └─────┘ └─────┘ │    │
│  └──────────────────┘                      │                          │    │
│                                            │  Scale: 0 to 1000+       │    │
│           │                                │  Per-container billing   │    │
│           ▼                                └────────────┬─────────────┘    │
│  ┌──────────────────┐                                   │                   │
│  │  Secret Manager  │                                   ▼                   │
│  │                  │                      ┌──────────────────────────┐    │
│  │  - API keys      │                      │  Cloud Storage           │    │
│  │  - JWT secrets   │                      │  (User workspaces)       │    │
│  │  - Env vars      │                      │                          │    │
│  │                  │                      │  /users/{userId}/        │    │
│  │  ~$0.06/10k ops  │                      │    - workspace/          │    │
│  └──────────────────┘                      │    - sessions/           │    │
│                                            │    - config/             │    │
│                                            │                          │    │
│                                            │  ~$0.02/GB/mo            │    │
│                                            └──────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Management API (Cloud Run Service)

```yaml
# management-service.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: ocmt-management
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/minScale: "0"
        autoscaling.knative.dev/maxScale: "10"
    spec:
      containerConcurrency: 80
      timeoutSeconds: 300
      containers:
        - image: gcr.io/ocmt/management:latest
          resources:
            limits:
              memory: 512Mi
              cpu: "1"
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: db-credentials
                  key: url
```

**Estimated cost:** $5-15/mo (scales to zero when idle)

### 2. User UI (Cloud Storage + CDN)

Static hosting - no Cloud Run needed.

```bash
# Deploy UI
gsutil -m rsync -r -d user-ui/dist gs://ocmt-ui/
# Enable CDN via Cloud CDN or use Firebase Hosting
```

**Estimated cost:** ~$1-5/mo (bandwidth only)

### 3. Agent Orchestrator (Cloud Run Service)

This replaces `agent-server/server.js`. Manages user containers.

```yaml
# orchestrator-service.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: ocmt-orchestrator
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/minScale: "1" # Always on for webhooks
        autoscaling.knative.dev/maxScale: "5"
    spec:
      containerConcurrency: 100
      timeoutSeconds: 900 # 15min for long agent tasks
      containers:
        - image: gcr.io/ocmt/orchestrator:latest
          resources:
            limits:
              memory: 1Gi
              cpu: "2"
```

**Estimated cost:** $20-40/mo (always-on minimum)

### 4. User Agent Containers (Cloud Run Services - Dynamic)

Each user gets their own Cloud Run service, created on-demand.

```javascript
// orchestrator pseudo-code
async function provisionUserAgent(userId) {
  const serviceName = `agent-${userId.slice(0, 8)}`;

  // Create Cloud Run service via API
  await cloudRun.services.create({
    parent: `projects/ocmt/locations/us-central1`,
    service: {
      name: serviceName,
      template: {
        containers: [
          {
            image: "gcr.io/ocmt/openclaw:latest",
            resources: { limits: { memory: "1Gi", cpu: "1" } },
            env: [
              { name: "OCMT_USER_ID", value: userId },
              {
                name: "ANTHROPIC_API_KEY",
                valueFrom: { secretKeyRef: { name: `user-${userId}-anthropic` } },
              },
            ],
          },
        ],
        scaling: {
          minInstanceCount: 0, // Scale to zero!
          maxInstanceCount: 1, // One instance per user
        },
      },
    },
  });
}
```

**Key advantage:** Each user container scales to zero independently.

**Estimated cost per user:**

- Active (chatting): ~$0.05-0.10/hour
- Idle (scaled to zero): ~$0/hour
- Storage: ~$0.02/GB/mo

### 5. Cloud SQL (PostgreSQL)

```bash
# Create instance
gcloud sql instances create ocmt-db \
  --database-version=POSTGRES_15 \
  --tier=db-f1-micro \
  --region=us-central1
```

**Estimated cost:** $10-30/mo (can start with smallest tier)

### 6. Cloud Storage (User Data)

```
gs://ocmt-user-data/
  └── users/
      └── {userId}/
          ├── workspace/      # User's agent workspace
          ├── sessions/       # Chat sessions (JSONL)
          └── config/         # Agent configuration
```

**Estimated cost:** ~$0.02/GB/mo

## Migration Steps

### Phase 1: Prepare (While on DO)

1. Containerize management server (already done)
2. Containerize agent orchestrator (already done)
3. Set up GCP project and enable APIs
4. Create Cloud SQL instance
5. Set up Secret Manager

### Phase 2: Deploy Infrastructure

```bash
# 1. Create GCP project
gcloud projects create ocmt-prod

# 2. Enable APIs
gcloud services enable \
  run.googleapis.com \
  sql-component.googleapis.com \
  secretmanager.googleapis.com \
  storage.googleapis.com

# 3. Create Cloud SQL
gcloud sql instances create ocmt-db \
  --database-version=POSTGRES_15 \
  --tier=db-f1-micro \
  --region=us-central1

# 4. Create storage bucket
gsutil mb -l us-central1 gs://ocmt-user-data

# 5. Deploy management API
gcloud run deploy ocmt-management \
  --image gcr.io/ocmt/management:latest \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated

# 6. Deploy orchestrator
gcloud run deploy ocmt-orchestrator \
  --image gcr.io/ocmt/orchestrator:latest \
  --platform managed \
  --region us-central1 \
  --min-instances 1
```

### Phase 3: Migrate Data

```bash
# Export from DO PostgreSQL
pg_dump -h YOUR_MGMT_SERVER_IP -U ocmt ocmt > backup.sql

# Import to Cloud SQL
gcloud sql import sql ocmt-db gs://ocmt-backups/backup.sql

# Sync user data
gsutil -m rsync -r /opt/ocmt/data gs://ocmt-user-data/users/
```

### Phase 4: Switch Traffic

1. Update DNS to point to Cloud Run URLs
2. Monitor for errors
3. Keep DO running for 24-48h as fallback
4. Decommission DO droplets

## Cost Estimates

### Small Scale (50 users, 10% concurrent)

| Component                      | Monthly Cost |
| ------------------------------ | ------------ |
| Management API                 | $5           |
| Orchestrator                   | $25          |
| User containers (5 active avg) | $20          |
| Cloud SQL                      | $15          |
| Storage (10GB)                 | $1           |
| Bandwidth                      | $5           |
| **Total**                      | **~$70/mo**  |

### Medium Scale (200 users, 10% concurrent)

| Component                       | Monthly Cost |
| ------------------------------- | ------------ |
| Management API                  | $10          |
| Orchestrator                    | $30          |
| User containers (20 active avg) | $80          |
| Cloud SQL                       | $30          |
| Storage (50GB)                  | $2           |
| Bandwidth                       | $15          |
| **Total**                       | **~$170/mo** |

### Large Scale (1000 users, 10% concurrent)

| Component                        | Monthly Cost |
| -------------------------------- | ------------ |
| Management API                   | $20          |
| Orchestrator                     | $50          |
| User containers (100 active avg) | $350         |
| Cloud SQL                        | $50          |
| Storage (200GB)                  | $5           |
| Bandwidth                        | $50          |
| **Total**                        | **~$525/mo** |

## Comparison: DO vs Cloud Run

| Metric        | DigitalOcean (Current)         | Google Cloud Run |
| ------------- | ------------------------------ | ---------------- |
| 50 users      | $36-48/mo (need upgrade)       | ~$70/mo          |
| 200 users     | $96-200/mo (multiple droplets) | ~$170/mo         |
| 1000 users    | Complex multi-droplet          | ~$525/mo         |
| Scale-to-zero | Manual (hibernation)           | Automatic        |
| SLA           | None                           | 99.95%           |
| Compliance    | None                           | SOC2, HIPAA, ISO |
| Ops burden    | Manual scaling                 | Fully managed    |

**Crossover point:** Cloud Run becomes cost-effective at ~100+ users, but provides enterprise features immediately.

## Key Differences from Current Architecture

1. **No Docker-in-Docker:** Cloud Run manages containers natively
2. **No hibernation code needed:** Scale-to-zero is built-in
3. **No port management:** Each service gets its own URL
4. **Stateless orchestrator:** User data in Cloud Storage, not local disk
5. **Managed database:** Cloud SQL instead of SQLite/local PostgreSQL

## Files to Modify for Migration

```
agent-server/server.js     → orchestrator/   (rewrite for Cloud Run API)
management-server/         → Keep mostly same, update DB connection
user-ui/                   → No changes, just deploy to Cloud Storage
```

## When to Migrate

Trigger any of these:

- [ ] 50+ total users
- [ ] Enterprise customer requires SLA/compliance
- [ ] DO capacity hits 70% warning
- [ ] Need multi-region deployment
- [ ] Want to eliminate ops burden

## Resources

- [Cloud Run Documentation](https://cloud.google.com/run/docs)
- [Cloud Run Pricing](https://cloud.google.com/run/pricing)
- [Cloud SQL Documentation](https://cloud.google.com/sql/docs)
- [Migrating to Cloud Run](https://cloud.google.com/run/docs/migrating)

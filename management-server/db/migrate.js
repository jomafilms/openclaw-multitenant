import dotenv from "dotenv";
import pg from "pg";

dotenv.config();

const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgresql://localhost:5432/ocmt",
});

const migrations = [
  // Users table
  `CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE,
    name VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    status VARCHAR(50) DEFAULT 'pending',

    -- Container info
    container_id VARCHAR(255),
    container_port INTEGER,
    gateway_token VARCHAR(255) NOT NULL,

    -- Telegram
    telegram_bot_token VARCHAR(255),
    telegram_bot_username VARCHAR(255),
    telegram_chat_id BIGINT,

    -- Settings
    settings JSONB DEFAULT '{}'
  )`,

  // Usage tracking
  `CREATE TABLE IF NOT EXISTS usage (
    id SERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    api_calls INTEGER DEFAULT 0,
    UNIQUE(user_id, date)
  )`,

  // Audit log
  `CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT NOW(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    details JSONB,
    ip_address INET
  )`,

  // Sessions (for login)
  `CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL
  )`,

  // Secrets vault (encrypted API keys)
  `CREATE TABLE IF NOT EXISTS secrets (
    key VARCHAR(100) PRIMARY KEY,
    value_encrypted TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    rotated_at TIMESTAMP
  )`,

  // User integrations (OAuth tokens, API keys)
  `CREATE TABLE IF NOT EXISTS user_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    integration_type VARCHAR(20) NOT NULL,
    access_token_encrypted TEXT,
    refresh_token_encrypted TEXT,
    token_expires_at TIMESTAMP,
    api_key_encrypted TEXT,
    provider_email VARCHAR(255),
    metadata JSONB DEFAULT '{}',
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, provider)
  )`,

  // Magic link tokens for passwordless auth
  `CREATE TABLE IF NOT EXISTS magic_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP
  )`,

  // Organizations
  `CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
  )`,

  // Org memberships (who belongs to which org)
  `CREATE TABLE IF NOT EXISTS org_memberships (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    role VARCHAR(20) DEFAULT 'member',
    joined_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (user_id, org_id)
  )`,

  // Org resources (MCP servers/APIs the org exposes)
  `CREATE TABLE IF NOT EXISTS org_resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    resource_type VARCHAR(50) DEFAULT 'mcp_server',
    endpoint VARCHAR(500) NOT NULL,
    auth_config_encrypted TEXT,
    metadata JSONB DEFAULT '{}',
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
  )`,

  // Org grants (who can access which resources)
  // Note: permissions is JSONB for granular control
  // Permissions: read, list, write, delete, admin, share
  `CREATE TABLE IF NOT EXISTS org_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    resource_id UUID REFERENCES org_resources(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    permissions JSONB NOT NULL DEFAULT '{"read": true, "list": false, "write": false, "delete": false, "admin": false, "share": false}'::jsonb,
    status VARCHAR(20) DEFAULT 'granted',
    granted_by UUID REFERENCES users(id),
    granted_at TIMESTAMP DEFAULT NOW(),
    connected_at TIMESTAMP,
    revoked_at TIMESTAMP,
    UNIQUE (resource_id, user_id)
  )`,

  // Peer grants (user-to-user sharing with approval handshake)
  `CREATE TABLE IF NOT EXISTS peer_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    grantor_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    grantee_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    capability VARCHAR(100) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    reason TEXT,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    decided_at TIMESTAMP,
    UNIQUE (grantor_id, grantee_id, capability)
  )`,

  // Add target_user_id to audit_log if not exists (for peer sharing audit)
  `ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS target_user_id UUID REFERENCES users(id) ON DELETE SET NULL`,

  // Vault columns for zero-knowledge encryption
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS vault JSONB`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS vault_created_at TIMESTAMP`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS vault_unlocked_until TIMESTAMP`,

  // Device keys table (for biometric/WebAuthn multi-device support)
  `CREATE TABLE IF NOT EXISTS device_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    device_name VARCHAR(255),
    device_fingerprint VARCHAR(255),
    encrypted_device_key TEXT,
    webauthn_credential_id TEXT,
    webauthn_public_key TEXT,
    webauthn_counter INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    last_used_at TIMESTAMP,
    UNIQUE(user_id, device_fingerprint)
  )`,

  // Biometrics settings on users
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS biometrics_enabled BOOLEAN DEFAULT false`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS biometrics_last_password_at TIMESTAMP`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS biometrics_max_age_days INTEGER DEFAULT 14`,

  // Indexes
  `CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`,
  `CREATE INDEX IF NOT EXISTS idx_users_telegram_chat_id ON users(telegram_chat_id)`,
  `CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)`,
  `CREATE INDEX IF NOT EXISTS idx_usage_user_date ON usage(user_id, date)`,
  `CREATE INDEX IF NOT EXISTS idx_user_integrations_user_id ON user_integrations(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_magic_links_token ON magic_links(token)`,
  `CREATE INDEX IF NOT EXISTS idx_magic_links_email ON magic_links(email)`,
  `CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug)`,
  `CREATE INDEX IF NOT EXISTS idx_org_memberships_user ON org_memberships(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_org_memberships_org ON org_memberships(org_id)`,
  `CREATE INDEX IF NOT EXISTS idx_org_resources_org ON org_resources(org_id)`,
  `CREATE INDEX IF NOT EXISTS idx_org_grants_user ON org_grants(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_org_grants_resource ON org_grants(resource_id)`,
  `CREATE INDEX IF NOT EXISTS idx_org_grants_org ON org_grants(org_id)`,
  `CREATE INDEX IF NOT EXISTS idx_peer_grants_grantor ON peer_grants(grantor_id)`,
  `CREATE INDEX IF NOT EXISTS idx_peer_grants_grantee ON peer_grants(grantee_id)`,
  `CREATE INDEX IF NOT EXISTS idx_peer_grants_status ON peer_grants(status)`,
  `CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log(target_user_id)`,

  // Device keys indexes
  `CREATE INDEX IF NOT EXISTS idx_device_keys_user ON device_keys(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_device_keys_fingerprint ON device_keys(device_fingerprint)`,

  // Org invites (consent-based membership)
  `CREATE TABLE IF NOT EXISTS org_invites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    inviter_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    invitee_email VARCHAR(255) NOT NULL,
    invitee_id UUID REFERENCES users(id) ON DELETE SET NULL,
    role VARCHAR(20) DEFAULT 'member',
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT NOW(),
    decided_at TIMESTAMP
  )`,

  // Org invites indexes
  `CREATE INDEX IF NOT EXISTS idx_org_invites_org ON org_invites(org_id)`,
  `CREATE INDEX IF NOT EXISTS idx_org_invites_invitee_email ON org_invites(invitee_email)`,
  `CREATE INDEX IF NOT EXISTS idx_org_invites_invitee_id ON org_invites(invitee_id)`,
  `CREATE INDEX IF NOT EXISTS idx_org_invites_status ON org_invites(status)`,
  // Partial unique index: only one pending invite per org+email
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_org_invites_pending_unique ON org_invites(org_id, invitee_email) WHERE status = 'pending'`,

  // Org invites token and expiration columns (for secure invite links)
  `ALTER TABLE org_invites ADD COLUMN IF NOT EXISTS token VARCHAR(64) UNIQUE`,
  `ALTER TABLE org_invites ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP`,
  `CREATE INDEX IF NOT EXISTS idx_org_invites_token ON org_invites(token)`,
  `CREATE INDEX IF NOT EXISTS idx_org_invites_expires ON org_invites(expires_at)`,

  // Capability approvals (human-in-the-loop for sensitive agent operations)
  `CREATE TABLE IF NOT EXISTS capability_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    operation_type VARCHAR(50) NOT NULL,
    subject_public_key VARCHAR(255) NOT NULL,
    subject_email VARCHAR(255),
    resource VARCHAR(100) NOT NULL,
    scope TEXT[] NOT NULL,
    expires_in_seconds INTEGER NOT NULL,
    max_calls INTEGER,
    reason TEXT,
    agent_context JSONB DEFAULT '{}',
    status VARCHAR(20) DEFAULT 'pending',
    token VARCHAR(255) UNIQUE,
    created_at TIMESTAMP DEFAULT NOW(),
    decided_at TIMESTAMP,
    expires_at TIMESTAMP
  )`,

  // Capability approvals indexes
  `CREATE INDEX IF NOT EXISTS idx_capability_approvals_user ON capability_approvals(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_capability_approvals_status ON capability_approvals(status)`,
  `CREATE INDEX IF NOT EXISTS idx_capability_approvals_token ON capability_approvals(token)`,

  // Agent activity log (for behavioral anomaly detection)
  `CREATE TABLE IF NOT EXISTS agent_activity_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action_type VARCHAR(100) NOT NULL,
    resource VARCHAR(255),
    timestamp TIMESTAMP DEFAULT NOW(),
    hour_of_day INTEGER GENERATED ALWAYS AS (EXTRACT(HOUR FROM timestamp)) STORED,
    day_of_week INTEGER GENERATED ALWAYS AS (EXTRACT(DOW FROM timestamp)) STORED,
    metadata JSONB DEFAULT '{}'
  )`,

  // Agent activity baselines (rolling averages for anomaly detection)
  `CREATE TABLE IF NOT EXISTS agent_baselines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    metric_name VARCHAR(100) NOT NULL,
    baseline_value NUMERIC NOT NULL,
    stddev_value NUMERIC DEFAULT 0,
    sample_count INTEGER DEFAULT 0,
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, metric_name)
  )`,

  // Anomaly alerts (detected anomalies)
  `CREATE TABLE IF NOT EXISTS anomaly_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    alert_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) DEFAULT 'warning',
    metric_name VARCHAR(100),
    expected_value NUMERIC,
    actual_value NUMERIC,
    deviation_factor NUMERIC,
    description TEXT,
    metadata JSONB DEFAULT '{}',
    action_taken VARCHAR(50),
    acknowledged_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
  )`,

  // User notifications (for alerting users about anomalies)
  `CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT,
    severity VARCHAR(20) DEFAULT 'info',
    metadata JSONB DEFAULT '{}',
    read_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
  )`,

  // Agent activity log indexes
  `CREATE INDEX IF NOT EXISTS idx_agent_activity_user ON agent_activity_log(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_agent_activity_timestamp ON agent_activity_log(timestamp)`,
  `CREATE INDEX IF NOT EXISTS idx_agent_activity_action ON agent_activity_log(action_type)`,
  `CREATE INDEX IF NOT EXISTS idx_agent_activity_user_action_ts ON agent_activity_log(user_id, action_type, timestamp)`,

  // Agent baselines indexes
  `CREATE INDEX IF NOT EXISTS idx_agent_baselines_user ON agent_baselines(user_id)`,

  // Anomaly alerts indexes
  `CREATE INDEX IF NOT EXISTS idx_anomaly_alerts_user ON anomaly_alerts(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_anomaly_alerts_created ON anomaly_alerts(created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_anomaly_alerts_unack ON anomaly_alerts(user_id, acknowledged_at) WHERE acknowledged_at IS NULL`,

  // Notifications indexes
  `CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(user_id, read_at) WHERE read_at IS NULL`,

  // Vault lock status for anomaly response
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS vault_locked_by_anomaly BOOLEAN DEFAULT false`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS vault_locked_at TIMESTAMP`,

  // ============================================================
  // RECOVERY METHODS (Social Recovery + Hardware Backup)
  // ============================================================

  // Recovery methods enabled for each user
  `CREATE TABLE IF NOT EXISTS recovery_methods (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method_type VARCHAR(20) NOT NULL,
    config_encrypted TEXT,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, method_type)
  )`,

  // Recovery contacts for social recovery (Shamir shards)
  `CREATE TABLE IF NOT EXISTS recovery_contacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recovery_id VARCHAR(64) NOT NULL,
    contact_email VARCHAR(255) NOT NULL,
    contact_name VARCHAR(255),
    share_index INTEGER NOT NULL,
    shard_encrypted TEXT NOT NULL,
    notified_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, contact_email)
  )`,

  // Active recovery requests (when user initiates social recovery)
  `CREATE TABLE IF NOT EXISTS recovery_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recovery_id VARCHAR(64) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    threshold INTEGER NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    shards_collected INTEGER DEFAULT 0,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP
  )`,

  // Submitted shards during recovery process
  `CREATE TABLE IF NOT EXISTS recovery_shards (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES recovery_requests(id) ON DELETE CASCADE,
    contact_email VARCHAR(255) NOT NULL,
    shard TEXT NOT NULL,
    submitted_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(request_id, contact_email)
  )`,

  // Recovery methods indexes
  `CREATE INDEX IF NOT EXISTS idx_recovery_methods_user ON recovery_methods(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_recovery_contacts_user ON recovery_contacts(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_recovery_contacts_email ON recovery_contacts(contact_email)`,
  `CREATE INDEX IF NOT EXISTS idx_recovery_requests_user ON recovery_requests(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_recovery_requests_token ON recovery_requests(token_hash)`,
  `CREATE INDEX IF NOT EXISTS idx_recovery_shards_request ON recovery_shards(request_id)`,

  // ============================================================
  // GRANULAR RESOURCE PERMISSIONS MIGRATION
  // ============================================================
  // Migrate org_grants.permissions from TEXT[] to JSONB
  // This handles existing data by converting array to JSONB format
  `DO $$
  BEGIN
    -- Check if permissions column is still TEXT[] type
    IF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_name = 'org_grants'
        AND column_name = 'permissions'
        AND data_type = 'ARRAY'
    ) THEN
      -- Add new JSONB column
      ALTER TABLE org_grants ADD COLUMN IF NOT EXISTS permissions_jsonb JSONB;

      -- Convert existing TEXT[] to JSONB
      UPDATE org_grants SET permissions_jsonb = jsonb_build_object(
        'read', 'read' = ANY(permissions::text[]),
        'list', 'list' = ANY(permissions::text[]),
        'write', 'write' = ANY(permissions::text[]),
        'delete', 'delete' = ANY(permissions::text[]),
        'admin', 'admin' = ANY(permissions::text[]),
        'share', 'share' = ANY(permissions::text[])
      );

      -- Drop old column and rename new one
      ALTER TABLE org_grants DROP COLUMN permissions;
      ALTER TABLE org_grants RENAME COLUMN permissions_jsonb TO permissions;

      -- Set default and not null
      ALTER TABLE org_grants ALTER COLUMN permissions SET DEFAULT '{"read": true, "list": false, "write": false, "delete": false, "admin": false, "share": false}'::jsonb;
      ALTER TABLE org_grants ALTER COLUMN permissions SET NOT NULL;
    END IF;
  END $$`,

  // ============================================================
  // ORG VAULT THRESHOLD UNLOCK (2 of N admins)
  // ============================================================

  // Org vault threshold unlock configuration
  `ALTER TABLE organizations ADD COLUMN IF NOT EXISTS unlock_threshold INTEGER DEFAULT 2`,
  `ALTER TABLE organizations ADD COLUMN IF NOT EXISTS vault_config JSONB DEFAULT '{}'`,

  // Org unlock requests (for threshold-based vault access)
  `CREATE TABLE IF NOT EXISTS org_unlock_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    requested_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason TEXT,
    status VARCHAR(20) DEFAULT 'pending',
    required_approvals INTEGER NOT NULL,
    session_key_encrypted TEXT,
    expires_at TIMESTAMP NOT NULL,
    unlocked_at TIMESTAMP,
    locked_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
  )`,

  // Org unlock approvals
  `CREATE TABLE IF NOT EXISTS org_unlock_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES org_unlock_requests(id) ON DELETE CASCADE,
    approved_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    approved_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(request_id, approved_by)
  )`,

  // Org unlock request indexes
  `CREATE INDEX IF NOT EXISTS idx_org_unlock_requests_org ON org_unlock_requests(org_id)`,
  `CREATE INDEX IF NOT EXISTS idx_org_unlock_requests_status ON org_unlock_requests(status)`,
  `CREATE INDEX IF NOT EXISTS idx_org_unlock_requests_expires ON org_unlock_requests(expires_at)`,
  `CREATE INDEX IF NOT EXISTS idx_org_unlock_approvals_request ON org_unlock_approvals(request_id)`,

  // ============================================================
  // ORG VAULTS (Dedicated container-based secret storage)
  // ============================================================

  // Org vaults table - stores encrypted vault data per org
  `CREATE TABLE IF NOT EXISTS org_vaults (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE UNIQUE,
    container_id VARCHAR(255),
    container_port INTEGER,
    vault_encrypted JSONB,
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
  )`,

  // Org vault audit log (separate from main audit log for container isolation)
  `CREATE TABLE IF NOT EXISTS org_vault_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    secret_key VARCHAR(255),
    ip_address INET,
    success BOOLEAN DEFAULT true,
    error_message TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW()
  )`,

  // Org vault capability tokens (for scoped secret access)
  `CREATE TABLE IF NOT EXISTS org_vault_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    allowed_secrets TEXT[] DEFAULT ARRAY['*'],
    permissions TEXT[] DEFAULT ARRAY['read'],
    issued_by UUID REFERENCES users(id),
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
  )`,

  // Org vault indexes
  `CREATE INDEX IF NOT EXISTS idx_org_vaults_org ON org_vaults(org_id)`,
  `CREATE INDEX IF NOT EXISTS idx_org_vaults_status ON org_vaults(status)`,
  `CREATE INDEX IF NOT EXISTS idx_org_vault_audit_org ON org_vault_audit(org_id)`,
  `CREATE INDEX IF NOT EXISTS idx_org_vault_audit_user ON org_vault_audit(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_org_vault_audit_action ON org_vault_audit(action)`,
  `CREATE INDEX IF NOT EXISTS idx_org_vault_audit_created ON org_vault_audit(created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_org_vault_tokens_org ON org_vault_tokens(org_id)`,
  `CREATE INDEX IF NOT EXISTS idx_org_vault_tokens_user ON org_vault_tokens(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_org_vault_tokens_hash ON org_vault_tokens(token_hash)`,

  // ============================================================
  // CAPABILITY REVOCATIONS (Persistent revocation storage)
  // Critical security: Revocations must survive server restarts
  // ============================================================

  // Revoked capabilities table
  `CREATE TABLE IF NOT EXISTS capability_revocations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    capability_id VARCHAR(255) NOT NULL UNIQUE,
    revoked_at TIMESTAMP NOT NULL DEFAULT NOW(),
    issuer_public_key VARCHAR(255) NOT NULL,
    reason TEXT,
    original_expiry TIMESTAMP,
    signature TEXT,
    metadata JSONB DEFAULT '{}'
  )`,

  // Capability revocations indexes
  `CREATE INDEX IF NOT EXISTS idx_capability_revocations_capability ON capability_revocations(capability_id)`,
  `CREATE INDEX IF NOT EXISTS idx_capability_revocations_issuer ON capability_revocations(issuer_public_key)`,
  `CREATE INDEX IF NOT EXISTS idx_capability_revocations_revoked ON capability_revocations(revoked_at)`,
  `CREATE INDEX IF NOT EXISTS idx_capability_revocations_expiry ON capability_revocations(original_expiry)`,

  // Org-scoped token revocations (for org-vault tokens)
  `CREATE TABLE IF NOT EXISTS org_token_revocations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    token_id VARCHAR(255) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    revoked_at TIMESTAMP NOT NULL DEFAULT NOW(),
    revoked_by UUID REFERENCES users(id) ON DELETE SET NULL,
    reason TEXT,
    UNIQUE(org_id, token_id)
  )`,

  // Org token revocations indexes
  `CREATE INDEX IF NOT EXISTS idx_org_token_revocations_org ON org_token_revocations(org_id)`,
  `CREATE INDEX IF NOT EXISTS idx_org_token_revocations_token ON org_token_revocations(token_id)`,
  `CREATE INDEX IF NOT EXISTS idx_org_token_revocations_user ON org_token_revocations(user_id)`,

  // ============================================================
  // MESH AUDIT LOGS (Persistent audit trail for security events)
  // ============================================================

  // Main mesh audit log table for security-critical events
  `CREATE TABLE IF NOT EXISTS mesh_audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    event_type VARCHAR(64) NOT NULL,
    actor_id VARCHAR(128),
    target_id VARCHAR(128),
    org_id VARCHAR(128),
    details JSONB,
    ip_address VARCHAR(45),
    success BOOLEAN DEFAULT true,
    error_message TEXT,
    source VARCHAR(32) DEFAULT 'management-server'
  )`,

  // Mesh audit log indexes
  `CREATE INDEX IF NOT EXISTS idx_mesh_audit_logs_timestamp ON mesh_audit_logs(timestamp)`,
  `CREATE INDEX IF NOT EXISTS idx_mesh_audit_logs_actor ON mesh_audit_logs(actor_id)`,
  `CREATE INDEX IF NOT EXISTS idx_mesh_audit_logs_org ON mesh_audit_logs(org_id)`,
  `CREATE INDEX IF NOT EXISTS idx_mesh_audit_logs_event_type ON mesh_audit_logs(event_type)`,
  `CREATE INDEX IF NOT EXISTS idx_mesh_audit_logs_target ON mesh_audit_logs(target_id)`,
  `CREATE INDEX IF NOT EXISTS idx_mesh_audit_logs_success ON mesh_audit_logs(success) WHERE success = false`,

  // Composite index for common query patterns
  `CREATE INDEX IF NOT EXISTS idx_mesh_audit_logs_org_time ON mesh_audit_logs(org_id, timestamp DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_mesh_audit_logs_actor_time ON mesh_audit_logs(actor_id, timestamp DESC)`,

  // ============================================================
  // ORGANIZATIONS → GROUPS REFACTOR
  // Rename tables and columns from org_* to group_* naming
  // ============================================================

  // Rename organizations → groups
  `DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'organizations') THEN
      ALTER TABLE organizations RENAME TO groups;
    END IF;
  END $$`,

  // Rename org_memberships → group_memberships
  `DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'org_memberships') THEN
      ALTER TABLE org_memberships RENAME TO group_memberships;
      ALTER TABLE group_memberships RENAME COLUMN org_id TO group_id;
    END IF;
  END $$`,

  // Rename org_resources → group_resources
  `DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'org_resources') THEN
      ALTER TABLE org_resources RENAME TO group_resources;
      ALTER TABLE group_resources RENAME COLUMN org_id TO group_id;
    END IF;
  END $$`,

  // Rename org_grants → shares
  `DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'org_grants') THEN
      ALTER TABLE org_grants RENAME TO shares;
      ALTER TABLE shares RENAME COLUMN org_id TO group_id;
    END IF;
  END $$`,

  // Rename org_invites → group_invites
  `DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'org_invites') THEN
      ALTER TABLE org_invites RENAME TO group_invites;
      ALTER TABLE group_invites RENAME COLUMN org_id TO group_id;
    END IF;
  END $$`,

  // Rename org_unlock_requests → group_unlock_requests
  `DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'org_unlock_requests') THEN
      ALTER TABLE org_unlock_requests RENAME TO group_unlock_requests;
      ALTER TABLE group_unlock_requests RENAME COLUMN org_id TO group_id;
    END IF;
  END $$`,

  // Rename org_unlock_approvals → group_unlock_approvals
  `DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'org_unlock_approvals') THEN
      ALTER TABLE org_unlock_approvals RENAME TO group_unlock_approvals;
    END IF;
  END $$`,

  // Rename org_vaults → group_vaults
  `DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'org_vaults') THEN
      ALTER TABLE org_vaults RENAME TO group_vaults;
      ALTER TABLE group_vaults RENAME COLUMN org_id TO group_id;
    END IF;
  END $$`,

  // Rename org_vault_audit → group_vault_audit
  `DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'org_vault_audit') THEN
      ALTER TABLE org_vault_audit RENAME TO group_vault_audit;
      ALTER TABLE group_vault_audit RENAME COLUMN org_id TO group_id;
    END IF;
  END $$`,

  // Rename org_vault_tokens → group_vault_tokens
  `DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'org_vault_tokens') THEN
      ALTER TABLE org_vault_tokens RENAME TO group_vault_tokens;
      ALTER TABLE group_vault_tokens RENAME COLUMN org_id TO group_id;
    END IF;
  END $$`,

  // Rename org_token_revocations → group_token_revocations
  `DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'org_token_revocations') THEN
      ALTER TABLE org_token_revocations RENAME TO group_token_revocations;
      ALTER TABLE group_token_revocations RENAME COLUMN org_id TO group_id;
    END IF;
  END $$`,

  // Rename mesh_audit_logs org_id → group_id
  `DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'mesh_audit_logs' AND column_name = 'org_id') THEN
      ALTER TABLE mesh_audit_logs RENAME COLUMN org_id TO group_id;
    END IF;
  END $$`,

  // Create new group indexes (since old org_* indexes point to renamed tables)
  `CREATE INDEX IF NOT EXISTS idx_groups_slug ON groups(slug)`,
  `CREATE INDEX IF NOT EXISTS idx_group_memberships_user ON group_memberships(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_group_memberships_group ON group_memberships(group_id)`,
  `CREATE INDEX IF NOT EXISTS idx_group_resources_group ON group_resources(group_id)`,
  `CREATE INDEX IF NOT EXISTS idx_shares_user ON shares(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_shares_resource ON shares(resource_id)`,
  `CREATE INDEX IF NOT EXISTS idx_shares_group ON shares(group_id)`,
  `CREATE INDEX IF NOT EXISTS idx_group_invites_group ON group_invites(group_id)`,
  `CREATE INDEX IF NOT EXISTS idx_group_unlock_requests_group ON group_unlock_requests(group_id)`,
  `CREATE INDEX IF NOT EXISTS idx_group_vaults_group ON group_vaults(group_id)`,
  `CREATE INDEX IF NOT EXISTS idx_group_vault_audit_group ON group_vault_audit(group_id)`,
  `CREATE INDEX IF NOT EXISTS idx_group_vault_tokens_group ON group_vault_tokens(group_id)`,
  `CREATE INDEX IF NOT EXISTS idx_group_token_revocations_group ON group_token_revocations(group_id)`,
  `CREATE INDEX IF NOT EXISTS idx_mesh_audit_logs_group ON mesh_audit_logs(group_id)`,
  `CREATE INDEX IF NOT EXISTS idx_mesh_audit_logs_group_time ON mesh_audit_logs(group_id, timestamp DESC)`,

  // ============================================================
  // ADMIN SECURITY (IP Allowlist, Security Settings, Emergency Access)
  // ============================================================

  // Admin IP Allowlist - stores CIDR ranges allowed to access admin routes
  `CREATE TABLE IF NOT EXISTS admin_ip_allowlist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_range CIDR NOT NULL,
    description TEXT,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    last_used_at TIMESTAMP,
    hit_count INTEGER DEFAULT 0,
    enabled BOOLEAN DEFAULT true
  )`,

  // Index for efficient lookups of enabled, non-expired entries
  `CREATE INDEX IF NOT EXISTS idx_admin_ip_allowlist_enabled ON admin_ip_allowlist(enabled) WHERE enabled = true`,

  // Admin Security Settings - key/value store for admin security configuration
  `CREATE TABLE IF NOT EXISTS admin_security_settings (
    key VARCHAR(100) PRIMARY KEY,
    value JSONB NOT NULL,
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMP DEFAULT NOW()
  )`,

  // Admin Action Confirmations - 2-step confirmation for dangerous operations
  `CREATE TABLE IF NOT EXISTS admin_action_confirmations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action_type VARCHAR(100) NOT NULL,
    action_details JSONB NOT NULL,
    token VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    confirmed_at TIMESTAMP,
    ip_address INET
  )`,

  // Index for finding valid (unexpired, unconfirmed) tokens
  `CREATE INDEX IF NOT EXISTS idx_admin_confirmations_token ON admin_action_confirmations(token) WHERE confirmed_at IS NULL`,

  // Emergency Access Tokens - for lockout recovery
  `CREATE TABLE IF NOT EXISTS emergency_access_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    reason TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    used_by_ip INET,
    single_use BOOLEAN DEFAULT true
  )`,

  // Index for validating emergency tokens
  `CREATE INDEX IF NOT EXISTS idx_emergency_tokens_hash ON emergency_access_tokens(token_hash)`,
  `CREATE INDEX IF NOT EXISTS idx_emergency_tokens_expires ON emergency_access_tokens(expires_at)`,

  // Add session activity tracking columns for admin timeout
  `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_activity_at TIMESTAMP`,
  `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_ip INET`,

  // Index for session activity queries
  `CREATE INDEX IF NOT EXISTS idx_sessions_last_activity ON sessions(last_activity_at)`,

  // ============================================================
  // SESSION SECURITY IMPROVEMENTS (Plan 04)
  // ============================================================

  // Session metadata columns for security tracking
  `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip_address INET`,
  `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_agent TEXT`,
  `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_info JSONB DEFAULT '{}'`,
  `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP`,
  `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoke_reason VARCHAR(50)`,

  // Set default for last_activity_at if NULL
  `UPDATE sessions SET last_activity_at = created_at WHERE last_activity_at IS NULL`,
  `ALTER TABLE sessions ALTER COLUMN last_activity_at SET DEFAULT NOW()`,

  // Index for finding active sessions per user (for session management UI)
  `CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_sessions_user_active ON sessions(user_id, expires_at) WHERE revoked_at IS NULL`,

  // ============================================================
  // SECURITY EVENTS AND ALERTING
  // ============================================================

  // Security events log - stores all security-relevant events
  `CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(100) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    group_id UUID REFERENCES groups(id) ON DELETE SET NULL,
    severity VARCHAR(20) DEFAULT 'info',
    details JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW()
  )`,

  // Security events indexes
  `CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type)`,
  `CREATE INDEX IF NOT EXISTS idx_security_events_user ON security_events(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_security_events_group ON security_events(group_id)`,
  `CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity)`,
  `CREATE INDEX IF NOT EXISTS idx_security_events_created ON security_events(created_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_security_events_user_type ON security_events(user_id, event_type, created_at)`,

  // Alert rules configuration - per-user/group alert preferences
  `CREATE TABLE IF NOT EXISTS alert_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
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
  )`,

  // Alert rules indexes
  `CREATE INDEX IF NOT EXISTS idx_alert_rules_user ON alert_rules(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_alert_rules_group ON alert_rules(group_id)`,
  `CREATE INDEX IF NOT EXISTS idx_alert_rules_event ON alert_rules(event_type)`,
  `CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled ON alert_rules(enabled) WHERE enabled = true`,

  // Webhook channel configurations - stores encrypted webhook URLs
  `CREATE TABLE IF NOT EXISTS alert_channels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    channel_type VARCHAR(50) NOT NULL,
    name VARCHAR(255) NOT NULL,
    config_encrypted TEXT NOT NULL,
    enabled BOOLEAN DEFAULT true,
    last_success_at TIMESTAMP,
    last_failure_at TIMESTAMP,
    failure_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
  )`,

  // Alert channels indexes
  `CREATE INDEX IF NOT EXISTS idx_alert_channels_user ON alert_channels(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_alert_channels_group ON alert_channels(group_id)`,
  `CREATE INDEX IF NOT EXISTS idx_alert_channels_type ON alert_channels(channel_type)`,

  // Alert history for deduplication and tracking
  `CREATE TABLE IF NOT EXISTS alert_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID REFERENCES alert_rules(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT,
    metadata JSONB DEFAULT '{}',
    dedup_key VARCHAR(255),
    channels_sent JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMP DEFAULT NOW()
  )`,

  // Alert history indexes
  `CREATE INDEX IF NOT EXISTS idx_alert_history_user ON alert_history(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_alert_history_dedup ON alert_history(dedup_key)`,
  `CREATE INDEX IF NOT EXISTS idx_alert_history_created ON alert_history(created_at DESC)`,

  // Alert cooldowns (throttling) - prevents alert spam
  `CREATE TABLE IF NOT EXISTS alert_cooldowns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dedup_key VARCHAR(255) NOT NULL UNIQUE,
    last_alerted_at TIMESTAMP NOT NULL,
    alert_count INTEGER DEFAULT 1,
    expires_at TIMESTAMP NOT NULL
  )`,

  // Alert cooldowns indexes
  `CREATE INDEX IF NOT EXISTS idx_alert_cooldowns_key ON alert_cooldowns(dedup_key)`,
  `CREATE INDEX IF NOT EXISTS idx_alert_cooldowns_expires ON alert_cooldowns(expires_at)`,

  // ============================================================
  // RESOURCE SHARES (Peer-to-peer integration sharing)
  // Allows users to share their integrations directly with other users
  // ============================================================

  `CREATE TABLE IF NOT EXISTS resource_shares (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id UUID NOT NULL REFERENCES user_integrations(id) ON DELETE CASCADE,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id UUID REFERENCES users(id) ON DELETE SET NULL,
    recipient_email VARCHAR(255) NOT NULL,
    tier VARCHAR(20) DEFAULT 'LIVE',
    permissions JSONB DEFAULT '{"read": true}'::jsonb,
    status VARCHAR(20) DEFAULT 'pending',
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    accepted_at TIMESTAMP,
    revoked_at TIMESTAMP,
    UNIQUE(integration_id, recipient_email)
  )`,

  // Resource shares indexes
  `CREATE INDEX IF NOT EXISTS idx_resource_shares_owner ON resource_shares(owner_id)`,
  `CREATE INDEX IF NOT EXISTS idx_resource_shares_recipient ON resource_shares(recipient_id)`,
  `CREATE INDEX IF NOT EXISTS idx_resource_shares_recipient_email ON resource_shares(recipient_email)`,
  `CREATE INDEX IF NOT EXISTS idx_resource_shares_integration ON resource_shares(integration_id)`,
  `CREATE INDEX IF NOT EXISTS idx_resource_shares_status ON resource_shares(status)`,

  // ============================================================
  // PLATFORM ADMIN FLAG (Multi-tenant SaaS)
  // Indicates platform-level admin privileges (not tenant-scoped)
  // ============================================================

  `ALTER TABLE users ADD COLUMN IF NOT EXISTS is_platform_admin BOOLEAN DEFAULT false`,
  `CREATE INDEX IF NOT EXISTS idx_users_platform_admin ON users(is_platform_admin) WHERE is_platform_admin = true`,

  // ============================================================
  // AUDIT EXPORT TABLES (SIEM Integration)
  // Wave 5.4 Enterprise Feature
  // ============================================================

  // Audit webhooks for SIEM delivery
  `CREATE TABLE IF NOT EXISTS audit_webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    secret_hash VARCHAR(64),
    format VARCHAR(20) DEFAULT 'json' CHECK (format IN ('json', 'csv', 'cef', 'syslog')),
    siem_type VARCHAR(20) DEFAULT 'custom' CHECK (siem_type IN ('splunk', 'datadog', 'elastic', 'custom')),
    events JSONB DEFAULT '[]',
    headers JSONB DEFAULT '{}',
    enabled BOOLEAN DEFAULT true,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT unique_tenant_webhook UNIQUE (tenant_id)
  )`,

  // Audit webhooks indexes
  `CREATE INDEX IF NOT EXISTS idx_audit_webhooks_tenant ON audit_webhooks(tenant_id)`,
  `CREATE INDEX IF NOT EXISTS idx_audit_webhooks_enabled ON audit_webhooks(tenant_id) WHERE enabled = true`,

  // Batch export jobs table
  `CREATE TABLE IF NOT EXISTS audit_export_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    start_date TIMESTAMPTZ NOT NULL,
    end_date TIMESTAMPTZ NOT NULL,
    format VARCHAR(20) DEFAULT 'json' CHECK (format IN ('json', 'csv', 'cef', 'syslog')),
    actions JSONB DEFAULT '[]',
    chunk_size INTEGER DEFAULT 10000,
    email VARCHAR(255),
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'expired')),
    progress INTEGER DEFAULT 0,
    error_message TEXT,
    download_url TEXT,
    file_size_bytes BIGINT,
    record_count INTEGER,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
  )`,

  // Export jobs indexes
  `CREATE INDEX IF NOT EXISTS idx_audit_export_jobs_tenant ON audit_export_jobs(tenant_id)`,
  `CREATE INDEX IF NOT EXISTS idx_audit_export_jobs_status ON audit_export_jobs(status)`,
  `CREATE INDEX IF NOT EXISTS idx_audit_export_jobs_user ON audit_export_jobs(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_audit_export_jobs_created ON audit_export_jobs(created_at DESC)`,

  // Webhook delivery tracking
  `CREATE TABLE IF NOT EXISTS audit_webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id UUID NOT NULL REFERENCES audit_webhooks(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type VARCHAR(64) NOT NULL,
    event_id UUID,
    success BOOLEAN NOT NULL,
    status_code INTEGER,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    payload_size_bytes INTEGER,
    duration_ms INTEGER,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`,

  // Webhook deliveries indexes
  `CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook ON audit_webhook_deliveries(webhook_id)`,
  `CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_tenant ON audit_webhook_deliveries(tenant_id)`,
  `CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_created ON audit_webhook_deliveries(created_at DESC)`,

  // Export usage tracking for rate limiting
  `CREATE TABLE IF NOT EXISTS audit_export_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    export_count INTEGER DEFAULT 0,
    record_count BIGINT DEFAULT 0,
    CONSTRAINT unique_tenant_window UNIQUE (tenant_id, window_start)
  )`,

  `CREATE INDEX IF NOT EXISTS idx_export_usage_tenant_window ON audit_export_usage(tenant_id, window_start DESC)`,
];

async function migrate() {
  console.log("Running migrations...");

  for (const sql of migrations) {
    try {
      await pool.query(sql);
      console.log("✓", sql.slice(0, 50) + "...");
    } catch (err) {
      console.error("✗ Migration failed:", err.message);
      console.error("  SQL:", sql.slice(0, 100));
    }
  }

  console.log("Migrations complete.");
  await pool.end();
}

migrate().catch(console.error);

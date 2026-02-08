-- ============================================================
-- OCMT Security Tables Migration
-- Wave 1.4: Comprehensive Security Schema
--
-- This migration adds all security-related tables for:
-- - Multi-Factor Authentication (Plan 03)
-- - Session Security (Plan 04)
-- - Security Alerting (Plan 05)
-- - Admin Security (Plan 07)
-- - Encryption Key Rotation (Plan 11)
--
-- Run with: psql -d ocmt -f 001_security_tables.sql
-- ============================================================

BEGIN;

-- ============================================================
-- PLAN 03: MULTI-FACTOR AUTHENTICATION
-- ============================================================

-- MFA configuration per user
CREATE TABLE IF NOT EXISTS user_mfa (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  totp_secret_encrypted TEXT,
  totp_enabled BOOLEAN DEFAULT FALSE,
  totp_verified_at TIMESTAMPTZ,
  mfa_enforced BOOLEAN DEFAULT FALSE,
  preferred_method VARCHAR(20) DEFAULT 'totp',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id)
);

-- Backup codes for MFA recovery
CREATE TABLE IF NOT EXISTS mfa_backup_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- MFA verification attempts (for rate limiting and auditing)
CREATE TABLE IF NOT EXISTS mfa_attempts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  attempt_type VARCHAR(20) NOT NULL,
  success BOOLEAN NOT NULL,
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Pending MFA sessions (between magic link and MFA verification)
CREATE TABLE IF NOT EXISTS pending_mfa_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_token TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Add MFA columns to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_required BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_last_verified_at TIMESTAMPTZ;

-- MFA indexes
CREATE INDEX IF NOT EXISTS idx_user_mfa_user ON user_mfa(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_user ON mfa_backup_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_unused ON mfa_backup_codes(user_id) WHERE used_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_mfa_attempts_user ON mfa_attempts(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_attempts_created ON mfa_attempts(created_at);
CREATE INDEX IF NOT EXISTS idx_pending_mfa_token ON pending_mfa_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_pending_mfa_expires ON pending_mfa_sessions(expires_at);


-- ============================================================
-- PLAN 04: SESSION SECURITY IMPROVEMENTS
-- ============================================================

-- Add session metadata columns for security tracking
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip_address INET;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_agent TEXT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_info JSONB DEFAULT '{}';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_activity_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoke_reason VARCHAR(50);

-- Session indexes
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user_active ON sessions(user_id, expires_at)
  WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_last_activity ON sessions(last_activity_at);


-- ============================================================
-- PLAN 05: SECURITY ALERTING AND MONITORING
-- ============================================================

-- Security events table (centralized security event log)
CREATE TABLE IF NOT EXISTS security_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type VARCHAR(100) NOT NULL,
  severity VARCHAR(20) NOT NULL DEFAULT 'info',
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  group_id UUID REFERENCES groups(id) ON DELETE SET NULL,
  ip_address INET,
  user_agent TEXT,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Alert rules configuration
CREATE TABLE IF NOT EXISTS alert_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
  event_type VARCHAR(100) NOT NULL,
  severity_threshold VARCHAR(20) DEFAULT 'warning',
  threshold_count INTEGER DEFAULT 1,
  threshold_window_minutes INTEGER DEFAULT 15,
  enabled BOOLEAN DEFAULT TRUE,
  cooldown_minutes INTEGER DEFAULT 60,
  channels JSONB DEFAULT '["in_app"]'::jsonb,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Webhook channel configurations for alerts
CREATE TABLE IF NOT EXISTS alert_channels (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
  channel_type VARCHAR(50) NOT NULL,
  name VARCHAR(255) NOT NULL,
  config_encrypted TEXT NOT NULL,
  enabled BOOLEAN DEFAULT TRUE,
  last_success_at TIMESTAMPTZ,
  last_failure_at TIMESTAMPTZ,
  failure_count INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Alert history for deduplication and auditing
CREATE TABLE IF NOT EXISTS alert_history (
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
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Alert cooldowns (throttling to prevent spam)
CREATE TABLE IF NOT EXISTS alert_cooldowns (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  dedup_key VARCHAR(255) NOT NULL UNIQUE,
  last_alerted_at TIMESTAMPTZ NOT NULL,
  alert_count INTEGER DEFAULT 1,
  expires_at TIMESTAMPTZ NOT NULL
);

-- Security alerting indexes
CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_user ON security_events(user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_group ON security_events(group_id);
CREATE INDEX IF NOT EXISTS idx_security_events_created ON security_events(created_at);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);

CREATE INDEX IF NOT EXISTS idx_alert_rules_user ON alert_rules(user_id);
CREATE INDEX IF NOT EXISTS idx_alert_rules_group ON alert_rules(group_id);
CREATE INDEX IF NOT EXISTS idx_alert_rules_event ON alert_rules(event_type);
CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled ON alert_rules(enabled) WHERE enabled = TRUE;

CREATE INDEX IF NOT EXISTS idx_alert_channels_user ON alert_channels(user_id);
CREATE INDEX IF NOT EXISTS idx_alert_channels_group ON alert_channels(group_id);
CREATE INDEX IF NOT EXISTS idx_alert_channels_type ON alert_channels(channel_type);

CREATE INDEX IF NOT EXISTS idx_alert_history_user ON alert_history(user_id);
CREATE INDEX IF NOT EXISTS idx_alert_history_group ON alert_history(group_id);
CREATE INDEX IF NOT EXISTS idx_alert_history_dedup ON alert_history(dedup_key);
CREATE INDEX IF NOT EXISTS idx_alert_history_created ON alert_history(created_at);

CREATE INDEX IF NOT EXISTS idx_alert_cooldowns_key ON alert_cooldowns(dedup_key);
CREATE INDEX IF NOT EXISTS idx_alert_cooldowns_expires ON alert_cooldowns(expires_at);


-- ============================================================
-- PLAN 07: ADMIN SECURITY HARDENING
-- ============================================================

-- Admin IP allowlist (CIDR-based access control)
CREATE TABLE IF NOT EXISTS admin_ip_allowlist (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ip_range CIDR NOT NULL,
  description TEXT,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  hit_count INTEGER DEFAULT 0,
  enabled BOOLEAN DEFAULT TRUE
);

-- Admin security settings (key-value configuration store)
CREATE TABLE IF NOT EXISTS admin_security_settings (
  key VARCHAR(100) PRIMARY KEY,
  value JSONB NOT NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Admin action confirmations (for dangerous operations)
CREATE TABLE IF NOT EXISTS admin_action_confirmations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  action_type VARCHAR(100) NOT NULL,
  action_details JSONB NOT NULL,
  token VARCHAR(64) NOT NULL UNIQUE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  confirmed_at TIMESTAMPTZ,
  ip_address INET
);

-- Emergency access tokens (for lockout recovery)
CREATE TABLE IF NOT EXISTS emergency_access_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash VARCHAR(64) NOT NULL UNIQUE,
  reason TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  used_by_ip INET,
  single_use BOOLEAN DEFAULT TRUE
);

-- Admin security indexes
CREATE INDEX IF NOT EXISTS idx_admin_ip_allowlist_enabled ON admin_ip_allowlist(enabled)
  WHERE enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_admin_ip_allowlist_expires ON admin_ip_allowlist(expires_at);

CREATE INDEX IF NOT EXISTS idx_admin_confirmations_token ON admin_action_confirmations(token)
  WHERE confirmed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_admin_confirmations_admin ON admin_action_confirmations(admin_id);
CREATE INDEX IF NOT EXISTS idx_admin_confirmations_expires ON admin_action_confirmations(expires_at);

CREATE INDEX IF NOT EXISTS idx_emergency_access_token ON emergency_access_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_emergency_access_expires ON emergency_access_tokens(expires_at);


-- ============================================================
-- PLAN 11: ENCRYPTION KEY VERSIONING & ROTATION
-- ============================================================

-- Encryption key metadata (tracks key versions and rotation history)
CREATE TABLE IF NOT EXISTS encryption_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  version INTEGER NOT NULL UNIQUE,
  key_id VARCHAR(64) NOT NULL UNIQUE,
  algorithm VARCHAR(50) DEFAULT 'aes-256-gcm',
  status VARCHAR(20) DEFAULT 'active',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  rotated_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  metadata JSONB DEFAULT '{}'
);

-- Encryption migrations tracking (for key rotation progress)
CREATE TABLE IF NOT EXISTS encryption_migrations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  table_name VARCHAR(100) NOT NULL,
  column_name VARCHAR(100) NOT NULL,
  from_version INTEGER NOT NULL,
  to_version INTEGER NOT NULL,
  rows_total INTEGER DEFAULT 0,
  rows_migrated INTEGER DEFAULT 0,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  status VARCHAR(20) DEFAULT 'running',
  error_message TEXT
);

-- Encryption key indexes
CREATE INDEX IF NOT EXISTS idx_encryption_keys_version ON encryption_keys(version);
CREATE INDEX IF NOT EXISTS idx_encryption_keys_status ON encryption_keys(status);

CREATE INDEX IF NOT EXISTS idx_encryption_migrations_status ON encryption_migrations(status);
CREATE INDEX IF NOT EXISTS idx_encryption_migrations_table ON encryption_migrations(table_name, column_name);


-- ============================================================
-- ADDITIONAL SECURITY INDEXES
-- ============================================================

-- Composite indexes for common security queries
CREATE INDEX IF NOT EXISTS idx_mfa_attempts_user_time ON mfa_attempts(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_user_time ON security_events(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_group_time ON security_events(group_id, created_at DESC);


-- ============================================================
-- CLEANUP: Remove expired data (can be run periodically)
-- ============================================================

-- Function to clean up expired security data
CREATE OR REPLACE FUNCTION cleanup_expired_security_data()
RETURNS void AS $$
BEGIN
  -- Delete expired pending MFA sessions
  DELETE FROM pending_mfa_sessions WHERE expires_at < NOW();

  -- Delete expired admin confirmations
  DELETE FROM admin_action_confirmations
  WHERE expires_at < NOW() AND confirmed_at IS NULL;

  -- Delete expired emergency tokens
  DELETE FROM emergency_access_tokens WHERE expires_at < NOW();

  -- Delete expired alert cooldowns
  DELETE FROM alert_cooldowns WHERE expires_at < NOW();

  -- Delete old MFA attempts (keep 30 days)
  DELETE FROM mfa_attempts WHERE created_at < NOW() - INTERVAL '30 days';

  -- Delete old security events (keep 90 days)
  DELETE FROM security_events WHERE created_at < NOW() - INTERVAL '90 days';

  -- Delete old alert history (keep 90 days)
  DELETE FROM alert_history WHERE created_at < NOW() - INTERVAL '90 days';
END;
$$ LANGUAGE plpgsql;

-- Comment on cleanup function
COMMENT ON FUNCTION cleanup_expired_security_data() IS
  'Removes expired security data. Run periodically via cron or scheduled job.';


COMMIT;

-- ============================================================
-- VERIFICATION QUERIES (run after migration to verify)
-- ============================================================
-- SELECT table_name FROM information_schema.tables
--   WHERE table_schema = 'public'
--   AND table_name IN (
--     'user_mfa', 'mfa_backup_codes', 'mfa_attempts', 'pending_mfa_sessions',
--     'security_events', 'alert_rules', 'alert_channels', 'alert_history', 'alert_cooldowns',
--     'admin_ip_allowlist', 'admin_security_settings', 'admin_action_confirmations', 'emergency_access_tokens',
--     'encryption_keys', 'encryption_migrations'
--   );

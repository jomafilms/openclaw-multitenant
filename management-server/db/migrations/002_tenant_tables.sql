-- ============================================================
-- OCMT Multi-Tenant Tables Migration
-- Wave 1.1: Database Migrations for Multi-Tenant Support
--
-- This migration adds multi-tenant infrastructure:
-- - Tenants table (organizations/workspaces)
-- - API keys for programmatic access
-- - Subscriptions and billing tracking
-- - tenant_id foreign keys on existing tables
--
-- Run with: psql -d ocmt -f 002_tenant_tables.sql
-- ============================================================

BEGIN;

-- ============================================================
-- TENANTS TABLE
-- Core multi-tenant entity representing organizations/workspaces
-- ============================================================

CREATE TABLE IF NOT EXISTS tenants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  slug VARCHAR(100) UNIQUE NOT NULL,
  owner_id UUID REFERENCES users(id) ON DELETE SET NULL,
  settings JSONB DEFAULT '{}',
  status VARCHAR(50) DEFAULT 'active',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Tenants indexes
CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);
CREATE INDEX IF NOT EXISTS idx_tenants_owner ON tenants(owner_id);
CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants(status);
CREATE INDEX IF NOT EXISTS idx_tenants_created ON tenants(created_at);

COMMENT ON TABLE tenants IS 'Multi-tenant organizations/workspaces';
COMMENT ON COLUMN tenants.slug IS 'URL-safe unique identifier for subdomain routing';
COMMENT ON COLUMN tenants.settings IS 'Tenant-specific configuration (branding, features, etc.)';
COMMENT ON COLUMN tenants.status IS 'active, suspended, deleted';


-- ============================================================
-- API KEYS TABLE
-- Programmatic access tokens for API authentication
-- ============================================================

CREATE TABLE IF NOT EXISTS api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  name VARCHAR(255) NOT NULL,
  key_hash VARCHAR(64) NOT NULL,
  key_prefix VARCHAR(12) NOT NULL,
  scopes JSONB DEFAULT '["read"]',
  rate_limit_override INTEGER,
  last_used_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- API keys indexes
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
-- Note: Can't use NOW() in partial index predicate, so just filter by revoked_at
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(tenant_id)
  WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_api_keys_last_used ON api_keys(last_used_at);

COMMENT ON TABLE api_keys IS 'API keys for programmatic access';
COMMENT ON COLUMN api_keys.key_hash IS 'SHA-256 hash of the full API key';
COMMENT ON COLUMN api_keys.key_prefix IS 'First 12 chars for display (e.g., opw_live_xxx)';
COMMENT ON COLUMN api_keys.scopes IS 'Array of permission scopes: read, write, admin, etc.';
COMMENT ON COLUMN api_keys.rate_limit_override IS 'Custom rate limit, NULL uses plan default';


-- ============================================================
-- SUBSCRIPTIONS TABLE
-- Stripe billing and plan management
-- ============================================================

CREATE TABLE IF NOT EXISTS subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID UNIQUE NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  stripe_customer_id VARCHAR(255),
  stripe_subscription_id VARCHAR(255),
  plan VARCHAR(50) DEFAULT 'free',
  status VARCHAR(50) DEFAULT 'active',
  current_period_start TIMESTAMPTZ,
  current_period_end TIMESTAMPTZ,
  cancel_at_period_end BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Subscriptions indexes
CREATE INDEX IF NOT EXISTS idx_subscriptions_tenant ON subscriptions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe_customer ON subscriptions(stripe_customer_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe_sub ON subscriptions(stripe_subscription_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_plan ON subscriptions(plan);
CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_subscriptions_period_end ON subscriptions(current_period_end);

COMMENT ON TABLE subscriptions IS 'Tenant subscription and billing information';
COMMENT ON COLUMN subscriptions.plan IS 'free, pro, enterprise';
COMMENT ON COLUMN subscriptions.status IS 'active, past_due, canceled, trialing';


-- ============================================================
-- ADD TENANT_ID TO EXISTING TABLES
-- NULL allowed for backwards compatibility during migration
-- ============================================================

-- Users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_platform_admin BOOLEAN DEFAULT false;
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_platform_admin ON users(is_platform_admin) WHERE is_platform_admin = true;

COMMENT ON COLUMN users.is_platform_admin IS 'Platform-wide admin privileges (not tenant-scoped)';

-- Groups table
ALTER TABLE groups ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_groups_tenant ON groups(tenant_id);

-- Group resources table
ALTER TABLE group_resources ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_group_resources_tenant ON group_resources(tenant_id);

-- Group memberships table
ALTER TABLE group_memberships ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_group_memberships_tenant ON group_memberships(tenant_id);

-- Audit log table
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant ON audit_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_time ON audit_log(tenant_id, timestamp DESC);

-- Usage table (for quota tracking per tenant)
ALTER TABLE usage ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_usage_tenant ON usage(tenant_id);
CREATE INDEX IF NOT EXISTS idx_usage_tenant_date ON usage(tenant_id, date);


-- ============================================================
-- COMPOSITE INDEXES FOR COMMON QUERIES
-- ============================================================

-- Tenant-scoped lookups for groups
CREATE INDEX IF NOT EXISTS idx_groups_tenant_slug ON groups(tenant_id, slug);
CREATE INDEX IF NOT EXISTS idx_groups_tenant_name ON groups(tenant_id, name);

-- Tenant-scoped lookups for users
CREATE INDEX IF NOT EXISTS idx_users_tenant_email ON users(tenant_id, email);

-- API key validation (hot path)
CREATE INDEX IF NOT EXISTS idx_api_keys_validation ON api_keys(key_hash, tenant_id)
  WHERE revoked_at IS NULL;


-- ============================================================
-- TRIGGER: AUTO-UPDATE updated_at
-- ============================================================

-- Create trigger function if not exists
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Add triggers for new tables
DROP TRIGGER IF EXISTS tenants_updated_at ON tenants;
CREATE TRIGGER tenants_updated_at
  BEFORE UPDATE ON tenants
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS subscriptions_updated_at ON subscriptions;
CREATE TRIGGER subscriptions_updated_at
  BEFORE UPDATE ON subscriptions
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();


-- ============================================================
-- HELPER FUNCTIONS
-- ============================================================

-- Function to get tenant by API key hash
CREATE OR REPLACE FUNCTION get_tenant_by_api_key(p_key_hash VARCHAR)
RETURNS TABLE (
  tenant_id UUID,
  api_key_id UUID,
  scopes JSONB,
  rate_limit_override INTEGER
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    ak.tenant_id,
    ak.id as api_key_id,
    ak.scopes,
    ak.rate_limit_override
  FROM api_keys ak
  WHERE ak.key_hash = p_key_hash
    AND ak.revoked_at IS NULL
    AND (ak.expires_at IS NULL OR ak.expires_at > NOW());
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_tenant_by_api_key(VARCHAR) IS
  'Validates API key and returns tenant context. Updates last_used_at separately for performance.';


-- Function to check if user belongs to tenant
CREATE OR REPLACE FUNCTION user_in_tenant(p_user_id UUID, p_tenant_id UUID)
RETURNS BOOLEAN AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM users
    WHERE id = p_user_id AND tenant_id = p_tenant_id
  );
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION user_in_tenant(UUID, UUID) IS
  'Checks if a user belongs to a specific tenant.';


COMMIT;

-- ============================================================
-- VERIFICATION QUERIES (run after migration to verify)
-- ============================================================
-- SELECT table_name FROM information_schema.tables
--   WHERE table_schema = 'public'
--   AND table_name IN ('tenants', 'api_keys', 'subscriptions');
--
-- SELECT column_name, table_name
--   FROM information_schema.columns
--   WHERE column_name = 'tenant_id'
--   AND table_schema = 'public';
--
-- SELECT indexname FROM pg_indexes
--   WHERE indexname LIKE '%tenant%';

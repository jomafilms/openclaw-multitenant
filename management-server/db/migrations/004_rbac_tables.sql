-- ============================================================
-- OCMT RBAC Tables Migration
-- Wave 5.2: Advanced Role-Based Access Control
--
-- This migration adds RBAC infrastructure:
-- - Custom roles per tenant (enterprise feature)
-- - User-role assignments
-- - Resource-level permissions on users table
--
-- Run with: psql -d ocmt -f 004_rbac_tables.sql
-- ============================================================

BEGIN;

-- ============================================================
-- TENANT_ROLES TABLE
-- Custom roles defined per tenant (enterprise feature)
-- ============================================================

CREATE TABLE IF NOT EXISTS tenant_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name VARCHAR(50) NOT NULL,
  description TEXT,
  permissions JSONB DEFAULT '[]',
  inherits JSONB DEFAULT '[]',
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  deleted_at TIMESTAMPTZ,
  UNIQUE(tenant_id, name)
);

-- Indexes for tenant_roles
CREATE INDEX IF NOT EXISTS idx_tenant_roles_tenant ON tenant_roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_roles_tenant_name ON tenant_roles(tenant_id, name) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_tenant_roles_deleted ON tenant_roles(tenant_id) WHERE deleted_at IS NULL;

COMMENT ON TABLE tenant_roles IS 'Custom roles defined per tenant for enterprise RBAC';
COMMENT ON COLUMN tenant_roles.name IS 'Role name (unique per tenant, lowercase alphanumeric)';
COMMENT ON COLUMN tenant_roles.permissions IS 'JSON array of permission strings (e.g., ["users.manage", "groups.view"])';
COMMENT ON COLUMN tenant_roles.inherits IS 'JSON array of role names to inherit permissions from';
COMMENT ON COLUMN tenant_roles.deleted_at IS 'Soft delete timestamp';


-- ============================================================
-- TENANT_USER_ROLES TABLE
-- Track custom role assignments (for audit trail)
-- ============================================================

CREATE TABLE IF NOT EXISTS tenant_user_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id UUID REFERENCES tenant_roles(id) ON DELETE SET NULL,
  role_name VARCHAR(50) NOT NULL,
  assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
  assigned_at TIMESTAMPTZ DEFAULT NOW(),
  revoked_at TIMESTAMPTZ,
  UNIQUE(tenant_id, user_id, role_name)
);

-- Indexes for tenant_user_roles
CREATE INDEX IF NOT EXISTS idx_tenant_user_roles_tenant ON tenant_user_roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_user_roles_user ON tenant_user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_tenant_user_roles_role ON tenant_user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_tenant_user_roles_active ON tenant_user_roles(tenant_id, user_id) WHERE revoked_at IS NULL;

COMMENT ON TABLE tenant_user_roles IS 'Tracks custom role assignments for audit trail';
COMMENT ON COLUMN tenant_user_roles.role_name IS 'Role name (built-in or custom) - kept for audit after role deletion';


-- ============================================================
-- ADD RBAC COLUMNS TO USERS TABLE
-- ============================================================

-- Add tenant_role column for user's role within their tenant
ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_role VARCHAR(50) DEFAULT 'member';

-- Add resource_permissions column for resource-level permission overrides
ALTER TABLE users ADD COLUMN IF NOT EXISTS resource_permissions JSONB DEFAULT '{}';

-- Indexes for RBAC columns
CREATE INDEX IF NOT EXISTS idx_users_tenant_role ON users(tenant_id, tenant_role);

COMMENT ON COLUMN users.tenant_role IS 'User role within their tenant (owner, admin, member, observer, or custom)';
COMMENT ON COLUMN users.resource_permissions IS 'Resource-level permission overrides: { [resourceId]: ["read", "write"] }';


-- ============================================================
-- TRIGGER: AUTO-UPDATE updated_at FOR TENANT_ROLES
-- ============================================================

DROP TRIGGER IF EXISTS tenant_roles_updated_at ON tenant_roles;
CREATE TRIGGER tenant_roles_updated_at
  BEFORE UPDATE ON tenant_roles
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();


-- ============================================================
-- HELPER FUNCTIONS
-- ============================================================

-- Function to get a user's effective role in a tenant
CREATE OR REPLACE FUNCTION get_user_tenant_role(p_user_id UUID, p_tenant_id UUID)
RETURNS VARCHAR AS $$
DECLARE
  v_role VARCHAR;
  v_is_owner BOOLEAN;
BEGIN
  -- Check if user is the tenant owner
  SELECT EXISTS (
    SELECT 1 FROM tenants WHERE id = p_tenant_id AND owner_id = p_user_id
  ) INTO v_is_owner;

  IF v_is_owner THEN
    RETURN 'owner';
  END IF;

  -- Get the user's assigned role
  SELECT tenant_role INTO v_role
  FROM users
  WHERE id = p_user_id AND tenant_id = p_tenant_id;

  -- Default to 'member' if no role assigned
  RETURN COALESCE(v_role, 'member');
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_user_tenant_role(UUID, UUID) IS
  'Gets user effective role in tenant, returning owner if they own the tenant';


-- Function to check if a user has a specific permission
-- Note: This is a simplified check - full permission resolution with inheritance
-- is done in application code for performance
CREATE OR REPLACE FUNCTION user_has_permission(
  p_user_id UUID,
  p_tenant_id UUID,
  p_permission VARCHAR
)
RETURNS BOOLEAN AS $$
DECLARE
  v_role VARCHAR;
  v_is_platform_admin BOOLEAN;
BEGIN
  -- Check if platform admin (has all permissions)
  SELECT is_platform_admin INTO v_is_platform_admin
  FROM users WHERE id = p_user_id;

  IF v_is_platform_admin THEN
    RETURN TRUE;
  END IF;

  -- Get user's role
  v_role := get_user_tenant_role(p_user_id, p_tenant_id);

  -- Owner has all permissions
  IF v_role = 'owner' THEN
    RETURN TRUE;
  END IF;

  -- For other roles, check resource_permissions for resource-specific perms
  -- This is a simplified check - full resolution is in application code
  RETURN FALSE;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION user_has_permission(UUID, UUID, VARCHAR) IS
  'Simplified permission check - use application code for full inheritance resolution';


-- ============================================================
-- SET DEFAULT ROLE FOR TENANT OWNERS
-- Update existing tenant owners to have 'owner' role
-- ============================================================

UPDATE users u
SET tenant_role = 'owner'
FROM tenants t
WHERE u.id = t.owner_id
  AND u.tenant_id = t.id
  AND (u.tenant_role IS NULL OR u.tenant_role = 'member');


COMMIT;

-- ============================================================
-- VERIFICATION QUERIES (run after migration to verify)
-- ============================================================
-- SELECT table_name FROM information_schema.tables
--   WHERE table_schema = 'public'
--   AND table_name IN ('tenant_roles', 'tenant_user_roles');
--
-- SELECT column_name, table_name, data_type
--   FROM information_schema.columns
--   WHERE column_name IN ('tenant_role', 'resource_permissions')
--   AND table_schema = 'public';
--
-- SELECT indexname FROM pg_indexes
--   WHERE indexname LIKE '%role%';

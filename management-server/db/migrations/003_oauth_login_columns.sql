-- ============================================================
-- OCMT OAuth Login Columns Migration
-- Wave 4.1: OAuth2 Login Support
--
-- This migration adds OAuth login columns to users table for:
-- - Google OAuth login
-- - GitHub OAuth login (future)
-- - Microsoft OAuth login (future)
--
-- Run with: psql -d ocmt -f 003_oauth_login_columns.sql
-- ============================================================

BEGIN;

-- ============================================================
-- OAUTH COLUMNS ON USERS TABLE
-- ============================================================

-- Google OAuth ID (sub claim from Google ID token)
ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS google_email VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS google_picture TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS google_linked_at TIMESTAMPTZ;

-- GitHub OAuth ID
ALTER TABLE users ADD COLUMN IF NOT EXISTS github_id VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS github_username VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS github_avatar_url TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS github_linked_at TIMESTAMPTZ;

-- Microsoft OAuth ID
ALTER TABLE users ADD COLUMN IF NOT EXISTS microsoft_id VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS microsoft_email VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS microsoft_picture TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS microsoft_linked_at TIMESTAMPTZ;

-- Profile picture (from any OAuth provider or uploaded)
ALTER TABLE users ADD COLUMN IF NOT EXISTS picture TEXT;

-- Onboarding status (for new OAuth users who need to complete setup)
ALTER TABLE users ADD COLUMN IF NOT EXISTS needs_onboarding BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarding_completed_at TIMESTAMPTZ;

-- Last login metadata
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_method VARCHAR(50);
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_ip INET;

-- ============================================================
-- OAUTH STATE TABLE (for CSRF protection during OAuth flow)
-- ============================================================

CREATE TABLE IF NOT EXISTS oauth_states (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  state VARCHAR(64) NOT NULL UNIQUE,
  provider VARCHAR(50) NOT NULL,
  redirect_url TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ
);

-- OAuth state indexes
CREATE INDEX IF NOT EXISTS idx_oauth_states_state ON oauth_states(state);
CREATE INDEX IF NOT EXISTS idx_oauth_states_expires ON oauth_states(expires_at);

COMMENT ON TABLE oauth_states IS 'CSRF protection state tokens for OAuth flows';
COMMENT ON COLUMN oauth_states.state IS 'Random state token sent with OAuth redirect';
COMMENT ON COLUMN oauth_states.redirect_url IS 'URL to redirect after successful login';

-- ============================================================
-- INDEXES FOR OAUTH LOOKUPS
-- ============================================================

-- Google login lookups
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id) WHERE google_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_google_email ON users(google_email) WHERE google_email IS NOT NULL;

-- GitHub login lookups
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_github_id ON users(github_id) WHERE github_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_github_username ON users(github_username) WHERE github_username IS NOT NULL;

-- Microsoft login lookups
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_microsoft_id ON users(microsoft_id) WHERE microsoft_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_microsoft_email ON users(microsoft_email) WHERE microsoft_email IS NOT NULL;

-- ============================================================
-- CLEANUP FUNCTION
-- ============================================================

-- Add to cleanup function
CREATE OR REPLACE FUNCTION cleanup_expired_oauth_states()
RETURNS void AS $$
BEGIN
  DELETE FROM oauth_states WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_expired_oauth_states() IS
  'Removes expired OAuth state tokens. Run periodically via cron.';

COMMIT;

-- ============================================================
-- VERIFICATION QUERIES
-- ============================================================
-- SELECT column_name, data_type FROM information_schema.columns
--   WHERE table_name = 'users'
--   AND column_name IN ('google_id', 'github_id', 'microsoft_id', 'needs_onboarding');
--
-- SELECT table_name FROM information_schema.tables
--   WHERE table_name = 'oauth_states';

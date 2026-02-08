-- Migration: 005_audit_export_tables.sql
-- Audit Log Export and SIEM Integration Tables
-- Wave 5.4 Enterprise Feature

-- ============================================================
-- AUDIT WEBHOOKS TABLE
-- ============================================================

-- Stores webhook configurations for SIEM delivery
CREATE TABLE IF NOT EXISTS audit_webhooks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

  -- Webhook configuration
  url TEXT NOT NULL,
  secret_hash VARCHAR(64), -- SHA-256 hash of the signing secret
  format VARCHAR(20) DEFAULT 'json' CHECK (format IN ('json', 'csv', 'cef', 'syslog')),
  siem_type VARCHAR(20) DEFAULT 'custom' CHECK (siem_type IN ('splunk', 'datadog', 'elastic', 'custom')),

  -- Event filtering
  events JSONB DEFAULT '[]', -- Array of event types to forward (empty = all)

  -- Custom headers (e.g., API keys for SIEM)
  headers JSONB DEFAULT '{}',

  -- Status
  enabled BOOLEAN DEFAULT true,

  -- Audit fields
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),

  -- Unique constraint: one webhook per tenant
  CONSTRAINT unique_tenant_webhook UNIQUE (tenant_id)
);

-- Index for quick lookups
CREATE INDEX IF NOT EXISTS idx_audit_webhooks_tenant ON audit_webhooks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_webhooks_enabled ON audit_webhooks(tenant_id) WHERE enabled = true;

-- ============================================================
-- AUDIT EXPORT JOBS TABLE
-- ============================================================

-- Tracks batch export jobs for large date ranges
CREATE TABLE IF NOT EXISTS audit_export_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id),

  -- Export parameters
  start_date TIMESTAMPTZ NOT NULL,
  end_date TIMESTAMPTZ NOT NULL,
  format VARCHAR(20) DEFAULT 'json' CHECK (format IN ('json', 'csv', 'cef', 'syslog')),
  actions JSONB DEFAULT '[]', -- Event type filter
  chunk_size INTEGER DEFAULT 10000,

  -- Notification
  email VARCHAR(255), -- Email to notify when complete

  -- Job status
  status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'expired')),
  progress INTEGER DEFAULT 0, -- Percentage 0-100
  error_message TEXT,

  -- Result
  download_url TEXT, -- Pre-signed URL when completed
  file_size_bytes BIGINT,
  record_count INTEGER,
  expires_at TIMESTAMPTZ, -- When the download link expires

  -- Timestamps
  created_at TIMESTAMPTZ DEFAULT NOW(),
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ
);

-- Indexes for job management
CREATE INDEX IF NOT EXISTS idx_audit_export_jobs_tenant ON audit_export_jobs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_export_jobs_status ON audit_export_jobs(status);
CREATE INDEX IF NOT EXISTS idx_audit_export_jobs_user ON audit_export_jobs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_export_jobs_created ON audit_export_jobs(created_at DESC);

-- ============================================================
-- WEBHOOK DELIVERY LOG TABLE
-- ============================================================

-- Tracks webhook delivery attempts for debugging
CREATE TABLE IF NOT EXISTS audit_webhook_deliveries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  webhook_id UUID NOT NULL REFERENCES audit_webhooks(id) ON DELETE CASCADE,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

  -- Event details
  event_type VARCHAR(64) NOT NULL,
  event_id UUID, -- Reference to original audit event if available

  -- Delivery status
  success BOOLEAN NOT NULL,
  status_code INTEGER,
  error_message TEXT,
  retry_count INTEGER DEFAULT 0,

  -- Payload info (for debugging, don't store full payload)
  payload_size_bytes INTEGER,

  -- Timing
  duration_ms INTEGER,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for delivery tracking
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook ON audit_webhook_deliveries(webhook_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_tenant ON audit_webhook_deliveries(tenant_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_created ON audit_webhook_deliveries(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_success ON audit_webhook_deliveries(webhook_id, success);

-- ============================================================
-- EXPORT USAGE TRACKING TABLE
-- ============================================================

-- Tracks export rate limiting per tenant
CREATE TABLE IF NOT EXISTS audit_export_usage (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

  -- Usage window
  window_start TIMESTAMPTZ NOT NULL,
  window_end TIMESTAMPTZ NOT NULL,

  -- Counts
  export_count INTEGER DEFAULT 0,
  record_count BIGINT DEFAULT 0, -- Total records exported

  -- Unique constraint per tenant per window
  CONSTRAINT unique_tenant_window UNIQUE (tenant_id, window_start)
);

-- Index for quick lookups
CREATE INDEX IF NOT EXISTS idx_export_usage_tenant_window ON audit_export_usage(tenant_id, window_start DESC);

-- ============================================================
-- HELPER FUNCTIONS
-- ============================================================

-- Function to update webhook updated_at timestamp
CREATE OR REPLACE FUNCTION update_audit_webhook_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for auto-updating timestamp
DROP TRIGGER IF EXISTS audit_webhooks_updated_at ON audit_webhooks;
CREATE TRIGGER audit_webhooks_updated_at
  BEFORE UPDATE ON audit_webhooks
  FOR EACH ROW
  EXECUTE FUNCTION update_audit_webhook_timestamp();

-- ============================================================
-- CLEANUP POLICIES
-- ============================================================

-- Function to cleanup old export jobs and delivery logs
CREATE OR REPLACE FUNCTION cleanup_audit_export_data(retention_days INTEGER DEFAULT 30)
RETURNS TABLE(jobs_deleted INTEGER, deliveries_deleted INTEGER) AS $$
DECLARE
  job_count INTEGER;
  delivery_count INTEGER;
BEGIN
  -- Delete old completed/failed/expired export jobs
  DELETE FROM audit_export_jobs
  WHERE created_at < NOW() - (retention_days * INTERVAL '1 day')
    AND status IN ('completed', 'failed', 'expired');
  GET DIAGNOSTICS job_count = ROW_COUNT;

  -- Delete old webhook delivery logs
  DELETE FROM audit_webhook_deliveries
  WHERE created_at < NOW() - (retention_days * INTERVAL '1 day');
  GET DIAGNOSTICS delivery_count = ROW_COUNT;

  -- Delete old export usage records
  DELETE FROM audit_export_usage
  WHERE window_end < NOW() - (retention_days * INTERVAL '1 day');

  RETURN QUERY SELECT job_count, delivery_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================
-- COMMENTS
-- ============================================================

COMMENT ON TABLE audit_webhooks IS 'Webhook configurations for SIEM audit log delivery';
COMMENT ON TABLE audit_export_jobs IS 'Batch export jobs for large audit log exports';
COMMENT ON TABLE audit_webhook_deliveries IS 'Webhook delivery attempt history for debugging';
COMMENT ON TABLE audit_export_usage IS 'Rate limiting tracking for audit exports';

COMMENT ON COLUMN audit_webhooks.secret_hash IS 'SHA-256 hash of webhook signing secret';
COMMENT ON COLUMN audit_webhooks.events IS 'Array of event types to forward, empty means all';
COMMENT ON COLUMN audit_webhooks.headers IS 'Custom HTTP headers for SIEM authentication';

COMMENT ON COLUMN audit_export_jobs.progress IS 'Export progress percentage 0-100';
COMMENT ON COLUMN audit_export_jobs.download_url IS 'Pre-signed URL for downloading completed export';

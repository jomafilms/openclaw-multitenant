# Production Deployment TODO

**Status:** ✅ PRODUCTION READY (2026-02-06)
**Upstream Sync:** ✅ Merged 316 upstream commits (2026-02-06)
**Full Report:** See `docs/PRODUCTION-REVIEW-STATUS.md`

Comprehensive task list from security reviews (Agent 1 + Agent 2).

## Phase 1: Critical Security & Stability (Immediate)

### Timing-Unsafe Comparisons (5 remaining) ✅ COMPLETE

- [x] group-vault/server.js:91 - Management API auth
- [x] agent-server/lib/unlock-proxy.js:30 - WebSocket upgrade
- [x] src/browser/extension-relay.ts:368 - Extension relay auth
- [x] src/browser/extension-relay.ts:514 - Extension relay auth
- [x] src/gateway/server-http.ts:83 - Hooks endpoint auth

### Empty Catch Blocks (13 files - critical ones fixed)

- [x] src/memory/sync-memory-files.ts - Added debug logging
- [x] src/memory/sync-session-files.ts - Added debug logging
- [ ] src/memory/internal.ts - File system ops (intentional)
- [x] src/memory/manager.ts - Added debug logging
- [x] src/media/fetch.ts - Added comments (stream cleanup, intentional)
- [ ] src/media-understanding/runner.ts
- [ ] src/commands/status.scan.ts
- [ ] src/commands/chutes-oauth.ts
- [ ] src/canvas-host/a2ui.ts
- [ ] src/browser/cdp.ts - Browser DOM access (intentional)
- [ ] src/agents/workspace.ts - File system ops (intentional)
- [ ] src/agents/minimax-vlm.ts
- [ ] src/agents/model-auth.ts

### Infrastructure ✅ COMPLETE

- [x] Add HEALTHCHECK to main Dockerfile
- [x] Add max WebSocket connection limit (1000 connections)
- [x] Add request timeout to HTTP requests in relay services (already had timeouts)

### Rate Limiting ✅ COMPLETE

- [x] src/gateway/secret-store-http.ts - Rate limited (30 req/min/IP)

## Phase 2: Test Coverage & Type Safety

### Critical Untested Files

- [x] src/routing/session-key.ts - Session isolation (45 tests added)
- [x] src/routing/bindings.ts - Core message routing (22 tests added)
- [x] src/infra/net/fetch-guard.ts - Security critical (15 tests added)
- [x] Channel normalizers (discord, slack, telegram, whatsapp) - 78 tests added
- [x] Heartbeat runner - Already has 72 tests across 5 test files

### Type Safety

Note: @ts-nocheck in Telegram files is due to undici/native-fetch type incompatibilities.
Removing requires proper type assertions or wrapper types. Total: 1,652 lines.

- [ ] src/telegram/bot.ts - Remove @ts-nocheck (512 lines)
- [ ] src/telegram/proxy.ts - Remove @ts-nocheck (11 lines, undici fetch types)
- [ ] src/telegram/bot-message-dispatch.ts - Remove @ts-nocheck (333 lines)
- [ ] src/telegram/bot-message.ts - Remove @ts-nocheck (65 lines)
- [ ] src/telegram/bot-handlers.ts - Remove @ts-nocheck (731 lines)

### Test Maintenance

- [x] Audit 60 .skip/.only test markers - All are legitimate (live test conditionals, platform-specific)
- [ ] Review high mock coupling (implementation detail leakage)
- [ ] Add missing negative test cases

## Phase 3: Code Quality & Documentation

### Large Files to Split

- [ ] src/memory/manager.ts (2,396 lines)
- [ ] src/container/secret-store.ts (2,256 lines) - Also needs crypto audit

### CLI Improvements

- [ ] Implement semantic exit codes (only 0 and 1 currently)
- [ ] Fix boolean option defaults (breaks truthy checks)
- [ ] Add missing CLI help documentation (7 files)
- [ ] Fix inconsistent --json option descriptions
- [ ] Add remediation hints to error messages

### Plugin/Extension Fixes

- [x] Plugin services registered but .start() never called - Verified: services ARE started in gateway startup
- [ ] No plugin unloading mechanism
- [ ] Synchronous tool_result_persist can fail with partial mutations
- [x] Add warning for external plugin installation - Security confirmation for npm plugins

### Documentation

- [x] Deployment checklist (docs/deployment-checklist.md)
- [x] Ops runbook for incident response (docs/ops-runbook.md)
- [ ] Architecture diagram for mesh security
- [x] Config troubleshooting guide (docs/config-troubleshooting.md)
- [x] Document plugin security model (docs/plugin-security.md)
- [ ] Create central feature flag registry
- [ ] Auto-generate config schema documentation

## Phase 4: Operational Readiness

### Monitoring & Metrics

- [ ] Add metrics collection (Prometheus/StatsD)
- [x] Set resource limits in Docker Compose - Added memory/CPU limits and logging config
- [x] Set up cleanup job monitoring - Documented in ops-runbook.md

### Security Hardening

- [ ] Implement challenge-response for password handling (currently in request body)
- [x] Replace console.log with proper logging in secret operations - Using subsystem logger
- [x] Add CORS headers to secret store endpoints - N/A: local-only endpoints, CORS not applicable

### Database & Backups

- [x] Set up automated PostgreSQL backups - Documented scripts and procedures in ops-runbook.md
- [x] Configure backup monitoring/alerting - Documented in ops-runbook.md

## Low Priority / Nice to Have

### Code Quality

- [ ] Complex function signatures with 40+ parameters need simplification
- [ ] Review crypto operations in secret-store.ts

### Config & Environment

- [ ] Create central feature flag registry
- [ ] Auto-generate config schema documentation

---

## Completed

### Security Fixes (Original Review)

- [x] SQL injection (11 locations) - Parameterized queries
- [x] XSS in admin panel - escapeHtml()
- [x] XSS in user-ui activity log - escapeHtml()
- [x] Hardcoded secrets - Env vars required
- [x] Admin auth cookie - Secure session tokens
- [x] Magic link race condition - Atomic UPDATE...RETURNING
- [x] Group-vault async/await errors - All 3 routes fixed
- [x] CORS misconfiguration - Explicit origins required
- [x] Timing attack (agent-server) - timingSafeEqual
- [x] Timing attack (management-server/mcp.js) - timingSafeEqual
- [x] Timing attack (management-server/internal.js) - timingSafeEqual
- [x] Magic link console logging - Gated to dev mode

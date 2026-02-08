# Configuration Troubleshooting Guide

This guide helps diagnose and resolve common configuration issues in OCMT.

## Quick Diagnostics

Run the built-in doctor command first:

```bash
openclaw doctor
```

This will check for common issues including:

- Missing required configuration
- Invalid values
- Deprecated settings
- Service connectivity

## Common Configuration Issues

### Issue: Gateway Won't Start

**Symptoms:**

- Error: "Missing required configuration"
- Gateway exits immediately after starting

**Solution:**

1. Check required configuration is set:

   ```bash
   openclaw config get gateway.mode
   openclaw config get gateway.port
   ```

2. If missing, set defaults:

   ```bash
   openclaw config set gateway.mode local
   openclaw config set gateway.port 18789
   ```

3. Verify environment variables:
   ```bash
   # Required for production
   echo $SESSION_SECRET
   echo $DATABASE_URL
   ```

---

### Issue: Channel Not Connecting

**Symptoms:**

- Channel shows as "disconnected" in status
- Messages not being received/sent

**Solution:**

1. Check channel status:

   ```bash
   openclaw channels status --probe
   ```

2. Verify channel credentials:

   ```bash
   # For Telegram
   openclaw config get telegram.token

   # For Discord
   openclaw config get discord.token

   # For WhatsApp
   openclaw channels whatsapp status
   ```

3. Common fixes:
   - **Telegram**: Ensure bot token is valid (get new one from @BotFather)
   - **Discord**: Ensure bot has proper intents enabled in Discord Developer Portal
   - **WhatsApp**: Re-link with `openclaw channels whatsapp link`
   - **Slack**: Re-authorize with `openclaw channels slack auth`

---

### Issue: Model API Errors

**Symptoms:**

- "No API key found for provider"
- Model requests failing with 401

**Solution:**

1. Check configured auth profiles:

   ```bash
   openclaw models list
   ```

2. Verify API key is set:

   ```bash
   # Check if key exists (won't show actual value)
   openclaw config get models.openai.apiKey
   ```

3. Add or update API key:

   ```bash
   openclaw models add openai
   # Follow prompts to enter API key
   ```

4. Test the connection:
   ```bash
   openclaw models test openai
   ```

---

### Issue: Memory/Sessions Not Persisting

**Symptoms:**

- Conversation context lost between restarts
- "Session not found" errors

**Solution:**

1. Check session storage location:

   ```bash
   openclaw config get storage.sessionsDir
   ls -la ~/.openclaw/sessions/
   ```

2. Verify disk space:

   ```bash
   df -h ~/.openclaw
   ```

3. Check file permissions:

   ```bash
   ls -la ~/.openclaw/
   # Should be readable/writable by current user
   ```

4. If using custom storage, verify configuration:
   ```bash
   openclaw config get storage
   ```

---

### Issue: CORS Errors in Browser

**Symptoms:**

- Browser console shows "CORS" errors
- WebSocket connections blocked

**Solution:**

1. Set allowed origins explicitly:

   ```bash
   # For relay server
   export ALLOWED_ORIGINS=https://app.yourdomain.com
   ```

2. For development, allow localhost:

   ```bash
   export ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
   ```

3. **Never use** `*` for ALLOWED_ORIGINS in production

---

### Issue: Rate Limiting Too Aggressive

**Symptoms:**

- Legitimate requests being blocked
- "Too many requests" errors

**Solution:**

1. Check current rate limit settings:

   ```bash
   openclaw config get rateLimit
   ```

2. Adjust limits (with caution):

   ```bash
   openclaw config set rateLimit.requestsPerMinute 100
   ```

3. If using behind a proxy, ensure X-Forwarded-For is trusted:
   ```bash
   openclaw config set server.trustProxy true
   ```

---

### Issue: Webhook Not Receiving Events

**Symptoms:**

- Webhook endpoint not being called
- Events missing in logs

**Solution:**

1. Verify webhook is registered:

   ```bash
   openclaw webhooks list
   ```

2. Test webhook endpoint:

   ```bash
   curl -X POST https://your-webhook-url/path \
     -H "Content-Type: application/json" \
     -d '{"test": true}'
   ```

3. Check webhook secret matches:

   ```bash
   openclaw config get webhooks.secret
   ```

4. Review webhook logs:
   ```bash
   openclaw logs --follow --filter webhook
   ```

---

### Issue: Plugin Not Loading

**Symptoms:**

- Plugin commands not available
- "Plugin not found" errors

**Solution:**

1. List installed plugins:

   ```bash
   openclaw plugins list
   ```

2. Verify plugin installation:

   ```bash
   openclaw plugins install <plugin-name>
   ```

3. Check for version compatibility:

   ```bash
   openclaw plugins info <plugin-name>
   ```

4. Enable plugin if disabled:
   ```bash
   openclaw plugins enable <plugin-name>
   ```

---

## Configuration Reference

### Config File Locations

| Platform    | Location                         |
| ----------- | -------------------------------- |
| Linux/macOS | `~/.openclaw/config.json`        |
| Windows     | `%APPDATA%\openclaw\config.json` |
| Docker      | `/app/.openclaw/config.json`     |

### Environment Variable Precedence

Environment variables override config file values:

```bash
# Environment variable naming convention
OPENCLAW_<SECTION>_<KEY>=value

# Examples
OPENCLAW_GATEWAY_PORT=8080
OPENCLAW_MODELS_DEFAULT=anthropic/claude-3-opus
```

### Viewing Effective Configuration

```bash
# Show all config values
openclaw config list

# Show config with sources (file vs env)
openclaw config list --show-source

# Export current config
openclaw config export > config-backup.json
```

### Resetting Configuration

```bash
# Reset single value to default
openclaw config unset gateway.port

# Reset entire section
openclaw config reset gateway

# Factory reset (caution!)
openclaw config reset --all
```

## Validation Tools

### Config Validation

```bash
# Validate configuration
openclaw config validate

# Check specific section
openclaw config validate --section models
```

### Network Connectivity Test

```bash
# Test all external services
openclaw doctor --network

# Test specific service
openclaw doctor --network --service openai
```

### Debug Mode

For detailed debugging information:

```bash
# Enable debug logging
DEBUG=openclaw:* openclaw gateway run

# Log to file
openclaw gateway run --log-file /tmp/openclaw-debug.log --log-level debug
```

## Getting Help

If you're still stuck:

1. Check the logs:

   ```bash
   openclaw logs --lines 100
   ```

2. Run diagnostics:

   ```bash
   openclaw doctor --verbose > diagnostics.txt
   ```

3. File an issue with the diagnostics output at:
   https://github.com/anthropics/claude-code/issues

---

_Last updated: 2026-02-06_

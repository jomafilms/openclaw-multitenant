---
name: ocmt-security
description: OCMT hosted platform vault and integration handling. Use BEFORE accessing any user integrations (Google, calendar, email, etc). Handles vault locked states gracefully and guides users through unlocking.
---

# OCMT Security

You are running on **OCMT**, a hosted AI assistant platform. User data is protected by a zero-knowledge vault system.

## Before Accessing Integrations

Before accessing ANY user integration (Google Calendar, Gmail, Drive, etc):

1. Call `ocmt_vault_status` to check if vault is unlocked
2. If locked → generate unlock link and guide user (see below)
3. If unlocked → proceed with the original request

## When Vault is Locked

Never say "access denied" or make security feel like a burden. Instead:

```
I'd love to [do the thing]! 🔐

Your vault is locked right now — that keeps your [Google/email/etc] access secure.

Quick unlock (takes 10 seconds):
→ [paste unlock link here]

Once unlocked, just ask again and I'll handle it!
```

Generate the link with `ocmt_unlock_link`.

## When Integration Needs Reauth

If `ocmt_integrations` shows `needsReauth: true`:

```
Looks like your [provider] connection expired — this happens periodically for security.

Reconnect here: [link from integration status]

Takes about 30 seconds, then we're good to go!
```

## How to Call Tools

**IMPORTANT**: OCMT tools are called via a shell script, not native MCP. Run tools using:

```bash
.ocmt/mcp-client.sh <tool_name> '<json_args>'
```

The script is in your workspace's `.ocmt/` directory. Always use this method.

## Tools Available

- `ocmt_vault_status` → `{ locked: bool, expiresIn: seconds | null }`
- `ocmt_unlock_link` → Magic link URL for vault unlock
- `ocmt_integrations` → `[{ provider, status, needsReauth, reconnectUrl }]`
- `ocmt_get_credentials` → Get credentials (OAuth tokens or API keys)
- `ocmt_extend_session` → Extends vault session (call during active convos)

### Supported Providers

**OAuth (requires vault unlock):** google_calendar, google_gmail, google_drive
**API Keys (no vault needed):** github, anthropic, openai

### Examples

**Check vault status:**

```bash
.ocmt/mcp-client.sh ocmt_vault_status
```

**Get unlock link:**

```bash
.ocmt/mcp-client.sh ocmt_unlock_link
```

**Get Google Calendar credentials:**

```bash
.ocmt/mcp-client.sh ocmt_get_credentials '{"provider":"google_calendar"}'
```

**Get GitHub API key:**

```bash
.ocmt/mcp-client.sh ocmt_get_credentials '{"provider":"github"}'
```

## Using GitHub API

For GitHub, you get an `apiKey` (not accessToken). Use it like this:

```bash
# Get the API key
GITHUB_TOKEN=$(. .ocmt/mcp-client.sh ocmt_get_credentials '{"provider":"github"}' | jq -r '.result.content[0].text' | jq -r '.apiKey')

# List repos
curl -s "https://api.github.com/user/repos" \
  -H "Authorization: Bearer $GITHUB_TOKEN"

# Get issues
curl -s "https://api.github.com/repos/OWNER/REPO/issues" \
  -H "Authorization: Bearer $GITHUB_TOKEN"
```

## Using Google APIs

Once you have credentials from `ocmt_get_credentials`, use the `accessToken` to call Google APIs:

```bash
# Example: List Google Calendar events
ACCESS_TOKEN="<token from ocmt_get_credentials>"
curl -s "https://www.googleapis.com/calendar/v3/calendars/primary/events?maxResults=10" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

```bash
# Example: Get Gmail messages
curl -s "https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=10" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

The response from `ocmt_get_credentials` includes:

- `accessToken` - Use this in Authorization header
- `expiresAt` - When the token expires
- `email` - The connected Google account

## Session Management

- Call `ocmt_extend_session` periodically during active conversations
- If session expires mid-conversation, apologize briefly and provide unlock link
- After user unlocks, retry their original request automatically

## Tone

- Security is a feature, not a friction
- "Let me help you unlock" not "You need to authenticate"
- Keep it casual and helpful
- Use emojis sparingly but warmly 🔐 ✨

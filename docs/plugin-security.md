# Plugin Security Model

This document describes the security model for OCMT plugins, including isolation, permissions, and best practices.

## Overview

OCMT plugins are powerful extensions that can:

- Add new tools for the AI agent
- Register hooks for lifecycle events
- Provide gateway RPC methods
- Add CLI commands
- Run background services

With this power comes risk. Plugins run with the same permissions as the OCMT process and can access configuration, secrets, and make network requests.

## Trust Model

### Plugin Sources

| Source                | Trust Level       | Installation                   |
| --------------------- | ----------------- | ------------------------------ |
| Built-in extensions   | Fully trusted     | Bundled with OCMT              |
| Verified plugins      | High trust        | Curated list, code reviewed    |
| npm packages          | **User verified** | Requires explicit confirmation |
| Local paths           | User controlled   | No confirmation needed         |
| Archives (.zip, .tgz) | **User verified** | Requires manual download       |

### Installation Confirmation

When installing plugins from npm, users see a security warning:

```
Security Warning:
You are about to install an external plugin from npm: some-plugin

External plugins can:
  - Execute arbitrary code on your system
  - Access your configuration and secrets
  - Make network requests on your behalf

Only install plugins from sources you trust.

Do you want to continue with the installation? (y/N)
```

Use `--yes` to skip this confirmation in scripts (with caution).

## Plugin Isolation

### Current Model (v1)

Plugins currently run in the same process as OCMT with full access to:

- Configuration (`OpenClawConfig`)
- File system (via Node.js APIs)
- Network (via Node.js APIs)
- Environment variables
- Child process spawning

### What Plugins CAN Access

1. **Configuration**
   - All config values via `config` parameter
   - Auth profiles and API keys
   - Channel credentials

2. **File System**
   - Agent directories (`~/.openclaw/agents/`)
   - Session data
   - Memory files

3. **Network**
   - Outbound HTTP/HTTPS requests
   - WebSocket connections
   - Any network accessible to the host

4. **Process**
   - Spawn child processes
   - Access environment variables
   - Signal handling

### What Plugins CANNOT Do

1. **Break sandbox isolation** (when enabled)
   - Container sandboxes still apply
   - Agent execution isolation remains

2. **Bypass rate limits**
   - API rate limits are enforced at the provider level

3. **Access other users' data** (in multi-tenant setups)
   - Each user runs their own OCMT instance

## Plugin Capabilities

### Tools

Plugins can register tools that the AI agent can invoke:

```typescript
export const tools: Tool[] = [
  {
    name: "my_tool",
    description: "Does something",
    parameters: {
      /* JSON schema */
    },
    execute: async (params, context) => {
      // Has access to context.config, context.agentId, etc.
      return { result: "done" };
    },
  },
];
```

**Security considerations:**

- Tools execute with full process permissions
- Input validation is the plugin's responsibility
- Output is returned to the AI agent

### Hooks

Hooks intercept lifecycle events:

```typescript
export const hooks: Hook[] = [
  {
    event: "agent:message:before",
    handler: async (payload, context) => {
      // Can modify or block messages
    },
  },
];
```

**Security considerations:**

- Hooks can see/modify all message content
- Can block message processing
- Run synchronously in the message pipeline

### Services

Background services run alongside the gateway:

```typescript
export const services: Service[] = [
  {
    id: "my-service",
    start: async (context) => {
      // Runs when gateway starts
    },
    stop: async (context) => {
      // Called on shutdown
    },
  },
];
```

**Security considerations:**

- Services run continuously
- Can hold open connections
- Not automatically restarted on crash

## Best Practices

### For Plugin Authors

1. **Minimize permissions**
   - Only access what you need
   - Don't store secrets unnecessarily

2. **Validate all input**
   - Sanitize user-provided data
   - Validate tool parameters

3. **Handle errors gracefully**
   - Don't crash the host process
   - Log errors for debugging

4. **Document security implications**
   - List what data you access
   - Explain network calls made

5. **Keep dependencies minimal**
   - Fewer dependencies = smaller attack surface
   - Audit dependencies regularly

### For Plugin Users

1. **Only install trusted plugins**
   - Check the source and author
   - Review the code if possible

2. **Monitor plugin behavior**
   - Check logs for unusual activity
   - Monitor network connections

3. **Keep plugins updated**
   - Security patches may be released
   - Use `openclaw plugins update`

4. **Remove unused plugins**
   - Reduces attack surface
   - Use `openclaw plugins disable <id>`

5. **Use local plugins for sensitive operations**
   - You can audit the code
   - No external dependencies

## Future Improvements

### Planned Security Enhancements

1. **Permission system**
   - Plugins declare required permissions
   - Users approve on install
   - Runtime enforcement

2. **Sandboxed execution**
   - Plugins run in isolated contexts
   - Limited file system access
   - Controlled network access

3. **Signature verification**
   - Signed plugin packages
   - Author identity verification
   - Tamper detection

4. **Audit logging**
   - Track plugin actions
   - Security-relevant events
   - Exportable logs

### Roadmap

- v1.x: Current model (process-level trust)
- v2.0: Permission declarations
- v2.x: Runtime permission enforcement
- v3.0: Full sandbox isolation

## Reporting Security Issues

If you discover a security vulnerability in a plugin:

1. **Do not disclose publicly** until fixed
2. **Contact the plugin author** directly
3. **Report to OCMT** if it's a platform issue

For core OCMT issues:

- Email: security@YOUR_DOMAIN (hypothetical)
- Use GitHub security advisories

## Reference

### Plugin API Types

```typescript
interface PluginContext {
  config: OpenClawConfig;
  agentId: string;
  stateDir: string;
  workspaceDir?: string;
  logger: Logger;
}

interface Tool {
  name: string;
  description: string;
  parameters: JSONSchema;
  execute: (params: unknown, context: PluginContext) => Promise<unknown>;
}

interface Hook {
  event: HookEvent;
  handler: (payload: unknown, context: PluginContext) => Promise<void>;
}

interface Service {
  id: string;
  start: (context: PluginContext) => Promise<void>;
  stop?: (context: PluginContext) => Promise<void>;
}
```

### Configuration

Plugin configuration in `~/.openclaw/config.json`:

```json
{
  "plugins": {
    "entries": {
      "my-plugin": {
        "enabled": true,
        "config": {
          "customOption": "value"
        }
      }
    },
    "installs": {
      "my-plugin": {
        "source": "npm",
        "spec": "my-plugin@1.0.0",
        "installedAt": "2024-01-01T00:00:00Z"
      }
    }
  }
}
```

---

_Last updated: 2026-02-06_

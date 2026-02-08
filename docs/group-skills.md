# Group Skills

Group skills are markdown documents that teach AI agents how to use group-shared API resources. When a user has connected access to a group resource with a skill doc, that document is automatically synced to their agent's workspace.

## How It Works

1. **Group admin creates a resource** with a skill doc in the metadata
2. **User is granted access** to the resource and connects it
3. **Context sync** writes the skill doc to `.ocmt/skills/<group>-<resource>.md`
4. **Agent reads the skill doc** and learns how to use the API
5. **Agent calls the API** via `ocmt_call_resource` with the resource ID

## Creating a Skill Doc

Skill docs are markdown files that explain:

- What the API does
- How to authenticate (handled automatically via `ocmt_call_resource`)
- Available endpoints and their parameters
- Common use cases and examples

### Example: Events API Skill

````markdown
# Events API - Agent Skill

You have access to the Events API for querying local events.

## Base URL

All requests go through ocmt_call_resource, so you only need paths:

- Use `method: "GET"` and `path: "/events"`

## How to Find Events

### Search by keyword

```json
{ "resourceId": "xxx", "method": "GET", "path": "/events?search=jazz&limit=20" }
```
````

### Filter by date range

```json
{ "resourceId": "xxx", "method": "GET", "path": "/events?startsAfter=2025-03-01T00:00:00Z" }
```

### Get event details

```json
{ "resourceId": "xxx", "method": "GET", "path": "/events/event-slug" }
```

````

## Adding a Skill Doc to a Resource

### Via MCP Tool

Group admins can add skill docs when creating or updating resources:

```bash
.ocmt/mcp-client.sh ocmt_create_resource '{
  "groupId": "group-uuid",
  "name": "Events API",
  "endpoint": "https://api.example.com",
  "authConfig": {
    "type": "api_key",
    "header": "x-api-key",
    "value": "secret-key"
  },
  "metadata": {
    "skillDoc": "# Events API\\n\\nYou have access to..."
  }
}'
````

### Via Database

For existing resources, update the metadata JSONB field:

```sql
UPDATE group_resources
SET metadata = jsonb_set(
  COALESCE(metadata, '{}'),
  '{skillDoc}',
  '"# Events API\n\nYou have access to..."'::jsonb
)
WHERE id = 'resource-uuid';
```

## Skill Doc Sync

Skill docs are synced during:

1. **Container provisioning** - initial setup
2. **Context update** - when integrations or groups change
3. **Container repair** - manual refresh

The sync writes skill docs to:

```
/home/node/.openclaw/workspace/.ocmt/skills/<group-slug>-<resource-slug>.md
```

Each skill doc includes a header comment with resource context:

```markdown
<!--
  Group Skill: Events API
  Group: Acme Corp
  Resource ID: abc-123-def
  Resource Type: api

  To call this API, use ocmt_call_resource with resourceId: "abc-123-def"
-->

# Events API - Agent Skill

...
```

## Permission Model

Skill docs are only synced for resources where:

1. User has a `group_grant` with `status = 'connected'`
2. Resource has `status = 'active'`
3. Resource metadata contains a `skillDoc` field

The agent can only call APIs the user has permission for. The `ocmt_call_resource` tool validates permissions based on HTTP method:

| HTTP Method    | Required Permission |
| -------------- | ------------------- |
| GET            | `read`              |
| POST/PUT/PATCH | `write`             |
| DELETE         | `delete`            |

## Best Practices

### For Skill Doc Authors

1. **Be specific** - Include exact paths, parameters, and response formats
2. **Show examples** - Provide copy-paste JSON for common operations
3. **Explain the domain** - Help the agent understand what the API is for
4. **Keep it focused** - One skill doc per resource/API
5. **Use consistent formatting** - Markdown with code blocks

### For Group Admins

1. **Test the skill** - Try the API calls before sharing
2. **Grant minimal permissions** - Use read-only for query-only APIs
3. **Document auth** - Note if API has special rate limits
4. **Update when API changes** - Keep skill docs current

## Troubleshooting

### Skill doc not appearing

1. Check user has connected the resource: `ocmt_group_resources '{"status":"connected"}'`
2. Trigger a context sync by updating integrations or running repair
3. Verify resource has `skillDoc` in metadata

### Agent can't call the API

1. Check permissions in the grant
2. Verify resource status is 'active'
3. Check API endpoint is correct and accessible
4. Review rate limits (100 calls/hour per resource per user)

## Related

- [ZERO-KNOWLEDGE-INTEGRATIONS.md](./ZERO-KNOWLEDGE-INTEGRATIONS.md) - MCP config injection
- [group-resources via MCP](./index.md) - Group resource management

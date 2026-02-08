#!/bin/bash
# Repair all existing containers to add MCP config
# Run from agent server or with SSH access

AGENT_SERVER="${AGENT_SERVER_URL:-http://localhost:4000}"
AUTH_TOKEN="${AUTH_TOKEN:-}"

if [ -z "$AUTH_TOKEN" ]; then
  echo "ERROR: AUTH_TOKEN environment variable required"
  echo "Usage: AUTH_TOKEN=xxx ./repair-containers.sh"
  exit 1
fi

echo "Fetching container list from $AGENT_SERVER..."
CONTAINERS=$(curl -s -H "X-Auth-Token: $AUTH_TOKEN" "$AGENT_SERVER/api/containers")

if [ -z "$CONTAINERS" ] || [ "$CONTAINERS" = "[]" ]; then
  echo "No containers found or failed to fetch list"
  exit 1
fi

echo "Found containers:"
echo "$CONTAINERS" | jq -r '.[] | "  - \(.userId[0:8])... (port \(.port), state: \(.hibernationState))"'

echo ""
echo "Repairing containers..."

for USER_ID in $(echo "$CONTAINERS" | jq -r '.[].userId'); do
  echo -n "  Repairing $USER_ID... "
  RESULT=$(curl -s -X POST \
    -H "X-Auth-Token: $AUTH_TOKEN" \
    -H "Content-Type: application/json" \
    "$AGENT_SERVER/api/containers/$USER_ID/repair")
  
  STATUS=$(echo "$RESULT" | jq -r '.status // .error')
  MCP=$(echo "$RESULT" | jq -r '.mcpConfigured // "unknown"')
  
  if [ "$STATUS" = "repaired" ]; then
    echo "✓ (mcpConfigured: $MCP)"
  else
    echo "✗ ($STATUS)"
  fi
done

echo ""
echo "Done!"

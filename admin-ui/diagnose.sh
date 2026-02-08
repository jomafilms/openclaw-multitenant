#!/bin/bash
# OCMT Diagnostic Script
# Run this on the server to identify issues

echo "OCMT Diagnostics"
echo "======================"
echo ""

# 1. Check OpenClaw installation
echo "1. OpenClaw Installation"
echo "------------------------"
which openclaw && openclaw --version || echo "ERROR: openclaw not found"
echo ""

# 2. Check config
echo "2. Configuration"
echo "----------------"
CONFIG_PATH="/root/.openclaw/openclaw.json"
if [ -f "$CONFIG_PATH" ]; then
    echo "Config exists: $CONFIG_PATH"
    echo "Contents:"
    cat "$CONFIG_PATH" | head -50
else
    echo "ERROR: Config not found at $CONFIG_PATH"
fi
echo ""

# 3. Check default workspace
echo "3. Default Workspace"
echo "--------------------"
WORKSPACE="/root/.openclaw/workspace"
if [ -d "$WORKSPACE" ]; then
    echo "Workspace exists: $WORKSPACE"
    echo "Files:"
    ls -la "$WORKSPACE"
else
    echo "ERROR: Default workspace not found"
    echo "Creating with template files..."
fi
echo ""

# 4. Check user workspaces
echo "4. User Workspaces"
echo "------------------"
WORKSPACES_DIR="/root/.openclaw/workspaces"
if [ -d "$WORKSPACES_DIR" ]; then
    echo "Workspaces directory exists"
    for ws in "$WORKSPACES_DIR"/*; do
        if [ -d "$ws" ]; then
            echo "  - $(basename $ws):"
            ls -la "$ws" | head -10
            echo "    Permissions:"
            stat -c '%a %U:%G' "$ws" 2>/dev/null || stat -f '%Lp %Su:%Sg' "$ws"
        fi
    done
else
    echo "No user workspaces yet"
fi
echo ""

# 5. Check gateway process
echo "5. Gateway Process"
echo "------------------"
ps aux | grep -E "openclaw.*gateway|clawdbot" | grep -v grep || echo "Gateway not running"
echo ""

# 6. Check agents directory
echo "6. Agents Directory"
echo "-------------------"
AGENTS_DIR="/root/.openclaw/agents"
if [ -d "$AGENTS_DIR" ]; then
    echo "Agents:"
    ls -la "$AGENTS_DIR"
else
    echo "No agents directory"
fi
echo ""

# 7. Check auth profiles
echo "7. Auth Profiles"
echo "----------------"
AUTH_PATH="/root/.openclaw/agents/main/agent/auth-profiles.json"
if [ -f "$AUTH_PATH" ]; then
    echo "Auth profiles exist"
    cat "$AUTH_PATH" | grep -o '"provider":"[^"]*"' | head -5
else
    echo "No auth profiles found - AI won't work!"
fi
echo ""

# 8. Test write permissions
echo "8. Write Permissions Test"
echo "-------------------------"
TEST_FILE="/root/.openclaw/workspace/test-write-$(date +%s).tmp"
if touch "$TEST_FILE" 2>/dev/null; then
    echo "Can write to workspace"
    rm "$TEST_FILE"
else
    echo "ERROR: Cannot write to workspace!"
    ls -la "/root/.openclaw/workspace"
fi
echo ""

# 9. Check if template files exist in default workspace
echo "9. Template Files"
echo "-----------------"
TEMPLATES=("AGENTS.md" "SOUL.md" "USER.md" "IDENTITY.md" "BOOTSTRAP.md")
for tmpl in "${TEMPLATES[@]}"; do
    if [ -f "/root/.openclaw/workspace/$tmpl" ]; then
        echo "  ✓ $tmpl exists"
    else
        echo "  ✗ $tmpl MISSING"
    fi
done
echo ""

echo "Diagnostics complete."

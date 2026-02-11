import { spawnSync } from "child_process";
import crypto from "crypto";
import express from "express";
import fs from "fs-extra";
import path from "path";
import cookieParser from "cookie-parser";
import { createSession, validateSession, destroySession } from "./lib/session.js";
import { proxyToManagement } from "./lib/management-proxy.js";

// HTML escaping helper to prevent XSS
function escapeHtml(str) {
  if (str == null) {
    return "";
  }
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Input validation helpers
function isValidAgentId(id) {
  // Only allow alphanumeric characters, hyphens, and underscores
  return typeof id === "string" && /^[a-zA-Z0-9_-]+$/.test(id) && id.length <= 100;
}

function isValidPairingCode(code) {
  // Pairing codes should be alphanumeric only
  return typeof code === "string" && /^[a-zA-Z0-9]+$/.test(code) && code.length <= 20;
}

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const CONFIG_PATH = process.env.OPENCLAW_CONFIG || "/root/.openclaw/openclaw.json";
const OPENCLAW_DIR = "/root/.openclaw";
const AGENTS_DIR = path.join(OPENCLAW_DIR, "agents");
const WORKSPACES_DIR = path.join(OPENCLAW_DIR, "workspaces");

// Authentication middleware for sensitive endpoints
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;

function requireAuth(req, res, next) {
  if (!ADMIN_TOKEN) {
    return res
      .status(500)
      .send("ADMIN_TOKEN environment variable not set. Set it to protect admin endpoints.");
  }

  // 1. First check Authorization header (for API clients)
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.slice(7); // Remove 'Bearer ' prefix
    // Use timing-safe comparison to prevent timing attacks
    const tokenBuffer = Buffer.from(token);
    const adminTokenBuffer = Buffer.from(ADMIN_TOKEN);
    // timingSafeEqual requires same length buffers
    if (
      tokenBuffer.length === adminTokenBuffer.length &&
      crypto.timingSafeEqual(tokenBuffer, adminTokenBuffer)
    ) {
      return next();
    }
  }

  // 2. Check admin_session cookie (for browser sessions)
  const sessionToken = req.cookies.admin_session;
  if (sessionToken) {
    const session = validateSession(sessionToken);
    if (session) {
      return next();
    }
  }

  // 3. Neither valid - return appropriate response
  if (req.accepts("html")) {
    // HTML request: redirect to login page
    return res.redirect("/login");
  } else {
    // API request: return 401 JSON error
    return res.status(401).json({ error: "Unauthorized" });
  }
}

// GET /login - render login form
app.get("/login", (req, res) => {
  const error = req.query.error === "1";
  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Login - OCMT Admin</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); min-height: 100vh; color: #fff; display: flex; align-items: center; justify-content: center; }
    .login-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 40px; width: 100%; max-width: 400px; }
    h1 { font-size: 1.5rem; margin-bottom: 10px; text-align: center; }
    .subtitle { color: #888; font-size: 0.9rem; margin-bottom: 30px; text-align: center; }
    .error { background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.3); color: #ef4444; padding: 12px; border-radius: 8px; margin-bottom: 20px; text-align: center; font-size: 0.9rem; }
    label { display: block; color: #888; font-size: 0.85rem; margin-bottom: 8px; }
    input { width: 100%; padding: 12px 15px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.2); background: rgba(255,255,255,0.1); color: white; font-size: 1rem; margin-bottom: 20px; }
    input::placeholder { color: #666; }
    input:focus { outline: none; border-color: #4f46e5; }
    button { width: 100%; padding: 12px 15px; border-radius: 8px; border: none; background: #4f46e5; color: white; font-size: 1rem; font-weight: 600; cursor: pointer; }
    button:hover { background: #4338ca; }
  </style>
</head>
<body>
  <div class="login-card">
    <h1>OCMT Admin</h1>
    <p class="subtitle">Enter your admin token to continue</p>
    ${error ? '<div class="error">Invalid token. Please try again.</div>' : ""}
    <form action="/login" method="POST">
      <label for="token">Admin Token</label>
      <input type="password" id="token" name="token" placeholder="Enter admin token" required autofocus>
      <button type="submit">Login</button>
    </form>
  </div>
</body>
</html>`);
});

// POST /login - handle login form submission
app.post("/login", (req, res) => {
  const { token } = req.body;

  if (!ADMIN_TOKEN) {
    return res.status(500).send("ADMIN_TOKEN environment variable not set.");
  }

  if (!token) {
    return res.redirect("/login?error=1");
  }

  // Use timing-safe comparison to prevent timing attacks
  const tokenBuffer = Buffer.from(String(token));
  const adminTokenBuffer = Buffer.from(ADMIN_TOKEN);

  let isValid = false;
  if (tokenBuffer.length === adminTokenBuffer.length) {
    isValid = crypto.timingSafeEqual(tokenBuffer, adminTokenBuffer);
  }

  if (isValid) {
    // Create session and set cookie
    const sessionId = createSession();
    res.cookie("admin_session", sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      sameSite: "lax",
    });
    return res.redirect("/admin");
  } else {
    return res.redirect("/login?error=1");
  }
});

function getConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
  } catch (e) {
    return null;
  }
}

// Read actual agents from openclaw's internal structure
function getAgentsFromDirectory() {
  const agents = [];
  try {
    if (!fs.existsSync(AGENTS_DIR)) {
      return agents;
    }
    const dirs = fs.readdirSync(AGENTS_DIR, { withFileTypes: true });
    for (const dir of dirs) {
      if (!dir.isDirectory()) {
        continue;
      }
      const agentId = dir.name;
      const agentPath = path.join(AGENTS_DIR, agentId);
      const sessionsPath = path.join(agentPath, "sessions", "sessions.json");

      let connections = [];
      let lastActivity = null;
      let ownerName = null;

      // Read session data for connections
      if (fs.existsSync(sessionsPath)) {
        try {
          const sessions = JSON.parse(fs.readFileSync(sessionsPath, "utf8"));
          for (const [key, session] of Object.entries(sessions)) {
            // Track last activity regardless of origin
            if (session.updatedAt && (!lastActivity || session.updatedAt > lastActivity)) {
              lastActivity = session.updatedAt;
            }

            if (session.origin) {
              // Channel-based session (Telegram, WhatsApp, etc.)
              connections.push({
                channel: session.origin.provider || session.lastChannel,
                label: session.origin.label,
                chatType: session.origin.chatType,
                lastActivity: session.updatedAt,
              });
              // Extract owner name from label
              if (session.origin.label && !ownerName) {
                ownerName = session.origin.label.split(" id:")[0];
              }
            } else if (session.sessionId) {
              // CLI/Web session (no origin)
              connections.push({
                channel: "web",
                label: "Web Chat",
                chatType: "direct",
                lastActivity: session.updatedAt,
              });
            }
          }
        } catch (e) {}
      }

      // Try to get owner name from workspace if not found in sessions
      if (!ownerName) {
        const workspacePath = path.join(WORKSPACES_DIR, agentId);
        const userMdPath = path.join(workspacePath, "USER.md");
        if (fs.existsSync(userMdPath)) {
          try {
            const userMd = fs.readFileSync(userMdPath, "utf8");
            const nameMatch = userMd.match(/\*\*Name:\*\*\s*(.+)/);
            if (nameMatch) {
              ownerName = nameMatch[1].trim();
            }
          } catch (e) {}
        }
      }

      agents.push({
        id: agentId,
        path: agentPath,
        connections,
        ownerName,
        lastActivity,
        hasWorkspace:
          fs.existsSync(path.join(OPENCLAW_DIR, "workspace")) ||
          fs.existsSync(path.join(WORKSPACES_DIR, agentId)),
      });
    }
  } catch (e) {
    console.error("Error reading agents:", e);
  }
  return agents;
}

// Root route - redirect based on authentication status
app.get("/", (req, res) => {
  const sessionToken = req.cookies.admin_session;
  if (sessionToken && validateSession(sessionToken)) {
    return res.redirect("/admin");
  }
  return res.redirect("/login");
});

// Signup routes - disabled for multi-tenant (users are provisioned via admin)
app.get("/signup", (req, res) => {
  res.redirect("/login");
});

app.post("/signup", (req, res) => {
  res.redirect("/login");
});

// Connect page - disabled for multi-tenant
app.get("/connect", (req, res) => {
  res.redirect("/login");
});

// Chat page - disabled for multi-tenant
app.get("/chat", (req, res) => {
  res.redirect("/login");
});

// Logout route (public - destroys session and redirects to login)
app.get("/logout", (req, res) => {
  const token = req.cookies.admin_session;
  destroySession(token);
  res.clearCookie("admin_session");
  res.redirect("/login");
});

// Chat API (protected - requires ADMIN_TOKEN)
app.post("/api/chat", requireAuth, async (req, res) => {
  const { message, user } = req.body;
  try {
    const agentId = user || "main";

    // Validate agentId to prevent command injection
    if (!isValidAgentId(agentId)) {
      console.error("Invalid agent ID:", agentId);
      return res.status(400).json({ response: "Invalid user ID." });
    }

    // Validate message exists and is a string
    if (typeof message !== "string" || message.length === 0) {
      return res.status(400).json({ response: "Message is required." });
    }

    // Use spawnSync with argument array to prevent command injection
    const result = spawnSync("openclaw", ["agent", "--agent", agentId, "--message", message], {
      encoding: "utf8",
      timeout: 120000,
    });

    // Filter out gateway/config lines from output
    const output = (result.stdout || "")
      .split("\n")
      .filter((line) => !/^gateway|^Gateway|^Source:|^Config:|^Bind:|^\[agents/.test(line))
      .join("\n")
      .trim();

    if (result.error) {
      console.error("Chat spawn error:", result.error.message);
      res.json({ response: "I'm having trouble connecting. Please try again." });
    } else {
      res.json({ response: output || "No response received." });
    }
  } catch (error) {
    console.error("Chat error:", error.message);
    res.json({ response: "I'm having trouble connecting. Please try again." });
  }
});

// Admin dashboard (protected - requires ADMIN_TOKEN)
app.get("/admin", requireAuth, async (req, res) => {
  const agents = getAgentsFromDirectory();
  const activeUsersCount = agents.filter((a) => a.connections.length > 0).length;

  // Fetch stats from management server
  let allowlistData = null;
  let pendingUsersData = null;
  let allowlistError = false;
  let pendingError = false;

  try {
    allowlistData = await proxyToManagement("/api/admin/user-allowlist");
  } catch (error) {
    console.error("Failed to fetch allowlist:", error.message);
    allowlistError = true;
  }

  try {
    pendingUsersData = await proxyToManagement("/api/admin/pending-users");
  } catch (error) {
    console.error("Failed to fetch pending users:", error.message);
    pendingError = true;
  }

  // Calculate stats
  const totalUsers = allowlistError ? null : (allowlistData?.entries?.length || 0);
  const pendingCount = pendingError ? null : (pendingUsersData?.pending?.length || 0);
  const runningContainers = activeUsersCount; // Users with active connections have containers
  const managementConnected = !allowlistError || !pendingError;
  const lastRefreshed = new Date().toISOString();

  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>OCMT Admin Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      min-height: 100vh;
      color: #fff;
    }
    .container { max-width: 900px; margin: 0 auto; padding: 40px 20px; }

    /* Header */
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 40px;
    }
    .header h1 { font-size: 1.75rem; font-weight: 600; }
    .header a {
      color: #a78bfa;
      text-decoration: none;
      font-size: 0.9rem;
      padding: 8px 16px;
      border: 1px solid rgba(167, 139, 250, 0.3);
      border-radius: 8px;
      transition: all 0.2s;
    }
    .header a:hover {
      background: rgba(167, 139, 250, 0.1);
      border-color: rgba(167, 139, 250, 0.5);
    }

    /* Stats Grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 30px;
    }
    @media (max-width: 768px) {
      .stats-grid { grid-template-columns: repeat(2, 1fr); }
    }
    .stat-card {
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 12px;
      padding: 24px 20px;
      text-align: center;
      transition: all 0.2s;
    }
    .stat-card:hover {
      background: rgba(255,255,255,0.08);
      border-color: rgba(255,255,255,0.15);
    }
    .stat-value {
      font-size: 2.5rem;
      font-weight: 700;
      color: #a78bfa;
      line-height: 1;
      margin-bottom: 8px;
    }
    .stat-value.error { color: #ef4444; font-size: 1rem; }
    .stat-label {
      color: #888;
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    /* Cards */
    .card {
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 16px;
      padding: 24px;
      margin-bottom: 20px;
    }
    .card h2 {
      font-size: 1.1rem;
      font-weight: 600;
      margin-bottom: 20px;
      color: #e0e0e0;
    }

    /* Quick Actions */
    .actions-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
    }
    @media (max-width: 768px) {
      .actions-grid { grid-template-columns: repeat(2, 1fr); }
    }
    .action-link {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 20px 16px;
      background: rgba(79, 70, 229, 0.1);
      border: 1px solid rgba(79, 70, 229, 0.2);
      border-radius: 12px;
      color: #a78bfa;
      text-decoration: none;
      font-size: 0.9rem;
      font-weight: 500;
      transition: all 0.2s;
      text-align: center;
    }
    .action-link:hover {
      background: rgba(79, 70, 229, 0.2);
      border-color: rgba(79, 70, 229, 0.4);
      transform: translateY(-2px);
    }
    .action-icon {
      font-size: 1.5rem;
      margin-bottom: 8px;
    }

    /* System Status */
    .status-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px 0;
      border-bottom: 1px solid rgba(255,255,255,0.05);
    }
    .status-row:last-child { border-bottom: none; }
    .status-label { color: #888; font-size: 0.9rem; }
    .status-value { font-size: 0.9rem; }
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 0.8rem;
      font-weight: 500;
    }
    .status-badge.connected {
      background: rgba(34, 197, 94, 0.2);
      color: #22c55e;
    }
    .status-badge.disconnected {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
    }
    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: currentColor;
    }
    .timestamp {
      color: #666;
      font-family: monospace;
      font-size: 0.85rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>OCMT Admin Dashboard</h1>
      <a href="/logout">Logout</a>
    </div>

    <!-- Overview Stats Cards -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-value ${totalUsers === null ? 'error' : ''}">${totalUsers === null ? 'Error' : totalUsers}</div>
        <div class="stat-label">Total Users</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${activeUsersCount}</div>
        <div class="stat-label">Active Users</div>
      </div>
      <div class="stat-card">
        <div class="stat-value ${pendingCount === null ? 'error' : ''}">${pendingCount === null ? 'Error' : pendingCount}</div>
        <div class="stat-label">Pending Approval</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${runningContainers}</div>
        <div class="stat-label">Running Containers</div>
      </div>
    </div>

    <!-- Quick Action Links -->
    <div class="card">
      <h2>Quick Actions</h2>
      <div class="actions-grid">
        <a href="/admin/allowlist" class="action-link">
          <span class="action-icon">&#128221;</span>
          Manage Allowlist
        </a>
        <a href="/admin/pending" class="action-link">
          <span class="action-icon">&#128101;</span>
          Pending Users
        </a>
        <a href="/admin/users" class="action-link">
          <span class="action-icon">&#128100;</span>
          All Users
        </a>
        <a href="/admin/containers" class="action-link">
          <span class="action-icon">&#128230;</span>
          Containers
        </a>
      </div>
    </div>

    <!-- System Status -->
    <div class="card">
      <h2>System Status</h2>
      <div class="status-row">
        <span class="status-label">Management Server</span>
        <span class="status-badge ${managementConnected ? 'connected' : 'disconnected'}">
          <span class="status-dot"></span>
          ${managementConnected ? 'Connected' : 'Disconnected'}
        </span>
      </div>
      <div class="status-row">
        <span class="status-label">Last Refreshed</span>
        <span class="timestamp">${escapeHtml(lastRefreshed)}</span>
      </div>
    </div>
  </div>
</body>
</html>`);
});

// Pending user approvals page (protected - requires ADMIN_TOKEN)
app.get("/admin/pending", requireAuth, async (req, res) => {
  // Fetch pending users from management server
  let pendingUsers = [];
  let fetchError = null;
  try {
    const data = await proxyToManagement("/api/admin/pending-users");
    pendingUsers = data.pending || data.users || data || [];
    // Ensure we have an array
    if (!Array.isArray(pendingUsers)) {
      pendingUsers = [];
    }
  } catch (error) {
    fetchError = error.message;
  }

  const pendingCount = pendingUsers.length;

  // Build pending users list HTML
  const pendingUsersHtml = pendingUsers
    .map((user) => {
      const signupDate = user.createdAt
        ? new Date(user.createdAt).toLocaleString()
        : user.signupDate
          ? new Date(user.signupDate).toLocaleString()
          : "Unknown";
      const userId = user.id || user.userId || user.email;
      return `<div class="pending-user-card" data-user-id="${escapeHtml(userId)}">
        <div class="user-info">
          <div class="user-email">${escapeHtml(user.email || "No email")}</div>
          <div class="user-meta">Signed up: ${escapeHtml(signupDate)}</div>
        </div>
        <div class="user-actions">
          <button class="btn btn-approve" onclick="approveUser('${escapeHtml(userId)}')">Approve</button>
          <button class="btn btn-reject" onclick="rejectUser('${escapeHtml(userId)}', '${escapeHtml(user.email || userId)}')">Reject</button>
        </div>
      </div>`;
    })
    .join("");

  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Pending Approvals - OCMT Admin</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      min-height: 100vh;
      color: #fff;
    }
    .container { max-width: 900px; margin: 0 auto; padding: 40px 20px; }

    /* Header */
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 30px;
    }
    .header-left {
      display: flex;
      align-items: center;
      gap: 20px;
    }
    .back-link {
      color: #a78bfa;
      text-decoration: none;
      font-size: 0.9rem;
      padding: 8px 16px;
      border: 1px solid rgba(167, 139, 250, 0.3);
      border-radius: 8px;
      transition: all 0.2s;
    }
    .back-link:hover {
      background: rgba(167, 139, 250, 0.1);
      border-color: rgba(167, 139, 250, 0.5);
    }
    h1 { font-size: 1.75rem; font-weight: 600; }
    .logout-link {
      color: #a78bfa;
      text-decoration: none;
      font-size: 0.9rem;
      padding: 8px 16px;
      border: 1px solid rgba(167, 139, 250, 0.3);
      border-radius: 8px;
      transition: all 0.2s;
    }
    .logout-link:hover {
      background: rgba(167, 139, 250, 0.1);
      border-color: rgba(167, 139, 250, 0.5);
    }

    /* Stats Bar */
    .stats-bar {
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 12px;
      padding: 20px 24px;
      margin-bottom: 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .stats-text { color: #888; font-size: 1rem; }
    .stats-text strong { color: #fff; font-size: 1.25rem; }

    /* Buttons */
    .btn {
      padding: 10px 20px;
      border-radius: 8px;
      border: none;
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-approve {
      background: #22c55e;
      color: #fff;
    }
    .btn-approve:hover:not(:disabled) { background: #16a34a; }
    .btn-reject {
      background: #ef4444;
      color: #fff;
      margin-left: 10px;
    }
    .btn-reject:hover:not(:disabled) { background: #dc2626; }
    .btn-bulk {
      background: #4f46e5;
      color: #fff;
    }
    .btn-bulk:hover:not(:disabled) { background: #4338ca; }

    /* Cards */
    .card {
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 16px;
      padding: 24px;
    }

    /* Pending User Cards */
    .pending-user-card {
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(255,255,255,0.08);
      padding: 20px;
      border-radius: 12px;
      margin-bottom: 12px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 15px;
      transition: all 0.3s ease;
    }
    .pending-user-card:last-child { margin-bottom: 0; }
    .pending-user-card:hover {
      background: rgba(255,255,255,0.08);
      border-color: rgba(255,255,255,0.15);
    }
    .user-info { flex: 1; min-width: 200px; }
    .user-email {
      font-weight: 600;
      font-size: 1.1rem;
      margin-bottom: 6px;
      color: #e0e0e0;
    }
    .user-meta { color: #888; font-size: 0.85rem; }
    .user-actions { display: flex; align-items: center; }

    /* Empty State */
    .empty-state {
      text-align: center;
      padding: 60px 20px;
    }
    .empty-state-icon {
      font-size: 4rem;
      margin-bottom: 20px;
      color: #22c55e;
    }
    .empty-state-text {
      color: #888;
      font-size: 1.1rem;
      line-height: 1.5;
    }

    /* Messages */
    .error-message {
      background: rgba(239, 68, 68, 0.2);
      border: 1px solid rgba(239, 68, 68, 0.3);
      color: #ef4444;
      padding: 15px 20px;
      border-radius: 12px;
      margin-bottom: 20px;
    }
    .success-message {
      background: rgba(34, 197, 94, 0.2);
      border: 1px solid rgba(34, 197, 94, 0.3);
      color: #22c55e;
      padding: 15px 20px;
      border-radius: 12px;
      margin-bottom: 20px;
      display: none;
    }

    /* Confirmation Dialog */
    .dialog-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0,0,0,0.7);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 1000;
    }
    .dialog-overlay.active { display: flex; }
    .dialog {
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      border: 1px solid rgba(255,255,255,0.2);
      border-radius: 16px;
      padding: 30px;
      max-width: 420px;
      width: 90%;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
    }
    .dialog h3 {
      margin-bottom: 15px;
      color: #ef4444;
      font-size: 1.25rem;
    }
    .dialog p {
      color: #888;
      margin-bottom: 25px;
      line-height: 1.6;
    }
    .dialog-actions {
      display: flex;
      justify-content: flex-end;
      gap: 12px;
    }
    .btn-cancel {
      background: rgba(255,255,255,0.1);
      color: #fff;
      border: 1px solid rgba(255,255,255,0.2);
    }
    .btn-cancel:hover {
      background: rgba(255,255,255,0.15);
      border-color: rgba(255,255,255,0.3);
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="header-left">
        <a href="/admin" class="back-link">&larr; Back</a>
        <h1>Pending User Approvals</h1>
      </div>
      <a href="/logout" class="logout-link">Logout</a>
    </div>

    <div id="successMessage" class="success-message"></div>

    ${fetchError ? `<div class="error-message">Error loading pending users: ${escapeHtml(fetchError)}</div>` : ""}

    <div class="stats-bar">
      <div class="stats-text"><strong>${pendingCount}</strong> user${pendingCount !== 1 ? "s" : ""} awaiting approval</div>
      ${pendingCount > 0 ? `<button class="btn btn-bulk" onclick="approveAll()">Approve All</button>` : ""}
    </div>

    <div class="card">
      ${
        pendingCount > 0
          ? pendingUsersHtml
          : `<div class="empty-state">
              <div class="empty-state-icon">&#10003;</div>
              <div class="empty-state-text">No users pending approval.<br>All caught up!</div>
            </div>`
      }
    </div>
  </div>

  <!-- Confirmation Dialog -->
  <div class="dialog-overlay" id="confirmDialog">
    <div class="dialog">
      <h3>Confirm Rejection</h3>
      <p id="dialogMessage">Are you sure you want to reject this user?</p>
      <div class="dialog-actions">
        <button class="btn btn-cancel" onclick="closeDialog()">Cancel</button>
        <button class="btn btn-reject" id="confirmRejectBtn">Reject</button>
      </div>
    </div>
  </div>

  <script>
    let pendingRejectUserId = null;

    function showSuccess(message) {
      const el = document.getElementById('successMessage');
      el.textContent = message;
      el.style.display = 'block';
      setTimeout(() => { el.style.display = 'none'; }, 3000);
    }

    function removeUserCard(userId) {
      const card = document.querySelector('[data-user-id="' + userId + '"]');
      if (card) {
        card.style.opacity = '0';
        card.style.transform = 'translateX(20px)';
        setTimeout(() => {
          card.remove();
          updateStats();
        }, 300);
      }
    }

    function updateStats() {
      const cards = document.querySelectorAll('.pending-user-card');
      const count = cards.length;
      const statsText = document.querySelector('.stats-text');
      if (statsText) {
        statsText.innerHTML = '<strong>' + count + '</strong> user' + (count !== 1 ? 's' : '') + ' awaiting approval';
      }
      // Hide bulk approve button if no more pending users
      const bulkBtn = document.querySelector('.btn-bulk');
      if (bulkBtn && count === 0) {
        bulkBtn.style.display = 'none';
      }
      // Show empty state if no more pending users
      if (count === 0) {
        const cardContainer = document.querySelector('.card');
        if (cardContainer) {
          cardContainer.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10003;</div><div class="empty-state-text">No users pending approval.<br>All caught up!</div></div>';
        }
      }
    }

    async function approveUser(userId) {
      const btn = event.target;
      btn.disabled = true;
      btn.textContent = 'Approving...';

      try {
        const response = await fetch('/api/pending-users/approve', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ userId: userId })
        });

        if (response.ok) {
          showSuccess('User approved successfully');
          removeUserCard(userId);
        } else {
          const data = await response.json();
          alert('Error: ' + (data.error || 'Failed to approve user'));
          btn.disabled = false;
          btn.textContent = 'Approve';
        }
      } catch (error) {
        alert('Error: ' + error.message);
        btn.disabled = false;
        btn.textContent = 'Approve';
      }
    }

    function rejectUser(userId, email) {
      pendingRejectUserId = userId;
      document.getElementById('dialogMessage').textContent = 'Are you sure you want to reject ' + email + '? This action cannot be undone.';
      document.getElementById('confirmDialog').classList.add('active');
    }

    function closeDialog() {
      document.getElementById('confirmDialog').classList.remove('active');
      pendingRejectUserId = null;
    }

    document.getElementById('confirmRejectBtn').addEventListener('click', async function() {
      if (!pendingRejectUserId) return;

      const userId = pendingRejectUserId;
      const btn = this;
      btn.disabled = true;
      btn.textContent = 'Rejecting...';

      try {
        const response = await fetch('/api/pending-users/reject', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ userId: userId })
        });

        closeDialog();

        if (response.ok) {
          showSuccess('User rejected');
          removeUserCard(userId);
        } else {
          const data = await response.json();
          alert('Error: ' + (data.error || 'Failed to reject user'));
        }
      } catch (error) {
        closeDialog();
        alert('Error: ' + error.message);
      }

      btn.disabled = false;
      btn.textContent = 'Reject';
    });

    async function approveAll() {
      if (!confirm('Are you sure you want to approve all pending users?')) return;

      const cards = document.querySelectorAll('.pending-user-card');
      const btn = document.querySelector('.btn-bulk');
      if (btn) {
        btn.disabled = true;
        btn.textContent = 'Approving...';
      }

      let successCount = 0;
      let errorCount = 0;

      for (const card of cards) {
        const userId = card.dataset.userId;
        try {
          const response = await fetch('/api/pending-users/approve', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ userId: userId })
          });

          if (response.ok) {
            successCount++;
            removeUserCard(userId);
          } else {
            errorCount++;
          }
        } catch (error) {
          errorCount++;
        }
      }

      if (btn) {
        btn.disabled = false;
        btn.textContent = 'Approve All';
      }

      if (errorCount > 0) {
        alert('Approved ' + successCount + ' users. ' + errorCount + ' failed.');
      } else if (successCount > 0) {
        showSuccess('All ' + successCount + ' users approved');
      }
    }

    // Close dialog on Escape key
    document.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') closeDialog();
    });

    // Close dialog on overlay click
    document.getElementById('confirmDialog').addEventListener('click', function(e) {
      if (e.target === this) closeDialog();
    });
  </script>
</body>
</html>`);
});

// Approve pairing (protected - requires ADMIN_TOKEN)
app.post("/admin/approve", requireAuth, (req, res) => {
  const { code } = req.body;

  // Validate pairing code to prevent command injection
  if (!isValidPairingCode(code)) {
    console.error("Invalid pairing code:", code);
    return res.redirect("/admin?error=" + encodeURIComponent("Invalid pairing code format"));
  }

  try {
    // Use spawnSync with argument array to prevent command injection
    const result = spawnSync("openclaw", ["pairing", "approve", "telegram", code], {
      encoding: "utf8",
      timeout: 30000,
    });

    if (result.error || result.status !== 0) {
      const errorMsg = result.stderr || result.error?.message || "Pairing approval failed";
      res.redirect("/admin?error=" + encodeURIComponent(errorMsg));
    } else {
      res.redirect("/admin?success=1");
    }
  } catch (e) {
    res.redirect("/admin?error=" + encodeURIComponent(e.message));
  }
});

// Dev dashboard - raw files viewer (protected - requires ADMIN_TOKEN)
app.get("/dev", requireAuth, (req, res) => {
  const config = getConfig();
  const configRaw = fs.existsSync(CONFIG_PATH)
    ? fs.readFileSync(CONFIG_PATH, "utf8")
    : "Config not found";

  // Get actual agents from directory
  const agents = getAgentsFromDirectory();

  // Get user workspaces (from /workspaces for new users)
  let workspaces = [];
  try {
    if (fs.existsSync(WORKSPACES_DIR)) {
      workspaces = fs.readdirSync(WORKSPACES_DIR);
    }
  } catch (e) {}

  let authProfiles = "Not found";
  const authPath = "/root/.openclaw/agents/main/agent/auth-profiles.json";
  try {
    if (fs.existsSync(authPath)) {
      const auth = JSON.parse(fs.readFileSync(authPath, "utf8"));
      authProfiles = JSON.stringify(
        auth,
        (k, v) =>
          k === "apiKey" || k === "token" || k === "accessToken" || k === "refreshToken"
            ? "***REDACTED***"
            : v,
        2,
      );
    }
  } catch (e) {
    authProfiles = "Error: " + e.message;
  }

  const wsHtml = workspaces.length
    ? workspaces.map((w) => '<div class="workspace-item">📁 ' + escapeHtml(w) + "</div>").join("")
    : '<p style="color:#8b949e;">No workspaces yet</p>';

  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Dev Dashboard - OCMT</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0d1117; min-height: 100vh; color: #c9d1d9; }
    .container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
    h1 { font-size: 1.8rem; margin-bottom: 10px; color: #58a6ff; }
    .subtitle { color: #8b949e; margin-bottom: 30px; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
    .card h2 { font-size: 1rem; color: #58a6ff; margin-bottom: 15px; }
    pre { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 15px; overflow-x: auto; font-size: 0.85rem; line-height: 1.5; color: #e6edf3; white-space: pre-wrap; word-break: break-all; }
    .file-path { color: #8b949e; font-size: 0.8rem; margin-bottom: 10px; font-family: monospace; }
    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 10px; }
    .workspace-item { background: #21262d; padding: 10px 15px; border-radius: 6px; border: 1px solid #30363d; font-family: monospace; font-size: 0.85rem; }
    a { color: #58a6ff; text-decoration: none; }
    .nav { margin-bottom: 20px; display: flex; gap: 15px; }
    .badge { background: #238636; color: white; padding: 2px 8px; border-radius: 10px; font-size: 0.75rem; margin-left: 10px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="nav">
      <a href="/admin">Admin</a>
      <a href="/dev"><strong>Dev</strong></a>
      <a href="/dev/browse">Browse Files</a>
      <a href="/logout">Logout</a>
    </div>
    <h1>🔧 Dev Dashboard</h1>
    <p class="subtitle">Raw configuration and files on the droplet</p>

    <div class="card">
      <h2>OpenClaw Config</h2>
      <div class="file-path">${CONFIG_PATH}</div>
      <pre>${escapeHtml(configRaw)}</pre>
    </div>

    <div class="card">
      <h2>Active Agents <span class="badge">${agents.length}</span></h2>
      <div class="file-path">${AGENTS_DIR}</div>
      <pre>${escapeHtml(JSON.stringify(agents, null, 2))}</pre>
    </div>

    <div class="card">
      <h2>User Workspaces <span class="badge">${workspaces.length}</span></h2>
      <div class="file-path">${WORKSPACES_DIR}</div>
      <div class="grid">${wsHtml}</div>
    </div>

    <div class="card">
      <h2>Auth Profiles (redacted)</h2>
      <div class="file-path">${authPath}</div>
      <pre>${escapeHtml(authProfiles)}</pre>
    </div>

    <div class="card">
      <h2>File Paths</h2>
      <pre>Config:     /root/.openclaw/openclaw.json
Workspaces: /root/.openclaw/workspaces/
Auth:       /root/.openclaw/agents/main/agent/auth-profiles.json
Logs:       /var/log/openclaw.log</pre>
    </div>
  </div>
</body>
</html>`);
});

// File browser - VS Code style (protected - requires ADMIN_TOKEN)
app.get("/dev/browse", requireAuth, (req, res) => {
  const selectedFile = req.query.file || "";

  // Security: validate no null bytes in path
  if (selectedFile.includes("\0")) {
    return res.status(400).send("Invalid file path");
  }

  const baseDir = path.resolve(OPENCLAW_DIR);

  // Get all files recursively
  function getFiles(dir, prefix = "") {
    let results = [];
    try {
      const items = fs.readdirSync(dir, { withFileTypes: true });
      for (const item of items) {
        if (item.name.startsWith(".")) {
          continue;
        } // skip hidden
        const fullPath = path.join(dir, item.name);
        const relativePath = prefix ? `${prefix}/${item.name}` : item.name;
        if (item.isDirectory()) {
          results.push({ name: item.name, path: relativePath, type: "dir" });
          results = results.concat(getFiles(fullPath, relativePath));
        } else {
          results.push({ name: item.name, path: relativePath, type: "file" });
        }
      }
    } catch (e) {}
    return results;
  }

  const files = getFiles(baseDir);

  // Read selected file content
  let fileContent = "";
  let filePath = "";
  if (selectedFile) {
    // Security: resolve to absolute path and validate it stays within baseDir
    filePath = path.resolve(baseDir, selectedFile);

    // Prevent path traversal attacks (e.g., ?file=../../../etc/passwd)
    if (!filePath.startsWith(baseDir + path.sep) && filePath !== baseDir) {
      return res.status(403).send("Access denied - path traversal detected");
    }

    try {
      if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
        fileContent = fs.readFileSync(filePath, "utf8");
      }
    } catch (e) {
      fileContent = "Error reading file: " + e.message;
    }
  }

  // Build file tree HTML
  const fileListHtml = files
    .map((f) => {
      const indent = (f.path.match(/\//g) || []).length * 16;
      const icon = f.type === "dir" ? "📁" : "📄";
      const isSelected = f.path === selectedFile ? "selected" : "";
      if (f.type === "dir") {
        return `<div class="file-item dir" style="padding-left:${indent}px">${icon} ${escapeHtml(f.name)}/</div>`;
      }
      return `<a href="/dev/browse?file=${encodeURIComponent(f.path)}" class="file-item ${isSelected}" style="padding-left:${indent}px">${icon} ${escapeHtml(f.name)}</a>`;
    })
    .join("");

  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>File Browser - OCMT</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Menlo', monospace; background: #1e1e1e; height: 100vh; color: #d4d4d4; display: flex; flex-direction: column; }
    .header { background: #323233; padding: 10px 20px; border-bottom: 1px solid #3c3c3c; display: flex; align-items: center; gap: 20px; }
    .header h1 { font-size: 1rem; font-weight: normal; color: #cccccc; }
    .header a { color: #569cd6; text-decoration: none; font-size: 0.9rem; }
    .main { display: flex; flex: 1; overflow: hidden; }
    .sidebar { width: 280px; background: #252526; border-right: 1px solid #3c3c3c; overflow-y: auto; }
    .sidebar-header { padding: 10px 15px; font-size: 0.75rem; text-transform: uppercase; color: #888; border-bottom: 1px solid #3c3c3c; }
    .file-item { display: block; padding: 4px 15px; font-size: 0.85rem; color: #cccccc; text-decoration: none; cursor: pointer; white-space: nowrap; }
    .file-item:hover { background: #2a2d2e; }
    .file-item.selected { background: #094771; color: #fff; }
    .file-item.dir { color: #888; cursor: default; }
    .content { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
    .content-header { padding: 8px 15px; background: #2d2d2d; border-bottom: 1px solid #3c3c3c; font-size: 0.85rem; color: #888; }
    .content-body { flex: 1; overflow: auto; }
    pre { padding: 15px; font-size: 0.85rem; line-height: 1.6; white-space: pre-wrap; word-break: break-all; }
    .empty { padding: 40px; text-align: center; color: #666; }
    .line-numbers { position: absolute; left: 0; top: 0; padding: 15px 10px; text-align: right; color: #5a5a5a; user-select: none; border-right: 1px solid #3c3c3c; background: #1e1e1e; }
    .code-container { position: relative; padding-left: 50px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>File Browser</h1>
    <a href="/dev">Dev Dashboard</a>
    <a href="/admin">Admin</a>
    <a href="/logout">Logout</a>
  </div>
  <div class="main">
    <div class="sidebar">
      <div class="sidebar-header">~/.openclaw</div>
      ${fileListHtml}
    </div>
    <div class="content">
      ${
        selectedFile
          ? `
        <div class="content-header">${escapeHtml(selectedFile)}</div>
        <div class="content-body">
          <pre>${escapeHtml(fileContent)}</pre>
        </div>
      `
          : `
        <div class="empty">Select a file to view its contents</div>
      `
      }
    </div>
  </div>
</body>
</html>`);
});

// ============================================================================
// Management Server Proxy Routes
// ============================================================================

// GET /api/allowlist - Get allowlist entries
app.get("/api/allowlist", requireAuth, async (req, res) => {
  try {
    const data = await proxyToManagement("/api/admin/user-allowlist");
    res.json(data);
  } catch (error) {
    console.error("Proxy error (GET /api/allowlist):", error.message);
    res.status(500).json({ error: error.message });
  }
});

// POST /api/allowlist - Add allowlist entry
app.post("/api/allowlist", requireAuth, async (req, res) => {
  try {
    const data = await proxyToManagement("/api/admin/user-allowlist", {
      method: "POST",
      body: JSON.stringify(req.body),
    });
    res.json(data);
  } catch (error) {
    console.error("Proxy error (POST /api/allowlist):", error.message);
    res.status(500).json({ error: error.message });
  }
});

// POST /api/allowlist/toggle - Toggle allowlist enabled/disabled
app.post("/api/allowlist/toggle", requireAuth, async (req, res) => {
  try {
    const data = await proxyToManagement("/api/admin/user-allowlist/toggle", {
      method: "POST",
      body: JSON.stringify(req.body),
    });
    res.json(data);
  } catch (error) {
    console.error("Proxy error (POST /api/allowlist/toggle):", error.message);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/pending-users - Get pending user requests
app.get("/api/pending-users", requireAuth, async (req, res) => {
  try {
    const data = await proxyToManagement("/api/admin/pending-users");
    res.json(data);
  } catch (error) {
    console.error("Proxy error (GET /api/pending-users):", error.message);
    res.status(500).json({ error: error.message });
  }
});

// POST /api/pending-users/approve - Approve a pending user
app.post("/api/pending-users/approve", requireAuth, async (req, res) => {
  try {
    const data = await proxyToManagement("/api/admin/pending-users/approve", {
      method: "POST",
      body: JSON.stringify(req.body),
    });
    res.json(data);
  } catch (error) {
    console.error("Proxy error (POST /api/pending-users/approve):", error.message);
    res.status(500).json({ error: error.message });
  }
});

// POST /api/pending-users/reject - Reject a pending user
app.post("/api/pending-users/reject", requireAuth, async (req, res) => {
  try {
    const data = await proxyToManagement("/api/admin/pending-users/reject", {
      method: "POST",
      body: JSON.stringify(req.body),
    });
    res.json(data);
  } catch (error) {
    console.error("Proxy error (POST /api/pending-users/reject):", error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// User Management Page
// ============================================================================

// GET /admin/users - User management page (protected)
app.get("/admin/users", requireAuth, async (req, res) => {
  // Get query parameters for filtering
  const statusFilter = req.query.status || "all";
  const searchQuery = req.query.search || "";
  const page = parseInt(req.query.page) || 1;

  // Placeholder users data - will be replaced when API is available
  let users = [];
  let totalUsers = 0;
  let apiAvailable = false;
  let errorMessage = "";

  // Try to fetch users from management server
  try {
    const data = await proxyToManagement("/api/admin/users");
    if (data && Array.isArray(data.users)) {
      users = data.users;
      totalUsers = data.total || users.length;
      apiAvailable = true;
    }
  } catch (error) {
    // API not available yet - show placeholder message
    errorMessage = "User list API coming soon. Use database directly for now.";
  }

  // Apply client-side filtering if we have data
  if (apiAvailable && users.length > 0) {
    if (statusFilter !== "all") {
      users = users.filter((u) => u.status === statusFilter);
    }
    if (searchQuery) {
      const search = searchQuery.toLowerCase();
      users = users.filter((u) => u.email && u.email.toLowerCase().includes(search));
    }
  }

  // Pagination
  const perPage = 20;
  const totalPages = Math.ceil(users.length / perPage);
  const paginatedUsers = users.slice((page - 1) * perPage, page * perPage);

  // Build user rows HTML
  const userRowsHtml = paginatedUsers
    .map((u) => {
      // Status badge colors
      let statusBg, statusColor;
      switch (u.status) {
        case "active":
          statusBg = "rgba(34,197,94,0.2)";
          statusColor = "#22c55e";
          break;
        case "pending":
          statusBg = "rgba(234,179,8,0.2)";
          statusColor = "#eab308";
          break;
        case "pending_approval":
          statusBg = "rgba(249,115,22,0.2)";
          statusColor = "#f97316";
          break;
        case "suspended":
          statusBg = "rgba(239,68,68,0.2)";
          statusColor = "#ef4444";
          break;
        default:
          statusBg = "rgba(156,163,175,0.2)";
          statusColor = "#9ca3af";
      }

      // Container status
      let containerStatus = "None";
      let containerColor = "#6b7280";
      if (u.container) {
        if (u.container.running) {
          containerStatus = "Running";
          containerColor = "#22c55e";
        } else {
          containerStatus = "Hibernated";
          containerColor = "#f59e0b";
        }
      }

      const createdAt = u.createdAt ? new Date(u.createdAt).toLocaleDateString() : "-";
      const lastLogin = u.lastLogin ? new Date(u.lastLogin).toLocaleString() : "Never";

      return `<tr>
        <td style="padding:12px 15px;border-bottom:1px solid rgba(255,255,255,0.1);">${escapeHtml(u.email || "-")}</td>
        <td style="padding:12px 15px;border-bottom:1px solid rgba(255,255,255,0.1);">
          <span style="background:${statusBg};color:${statusColor};padding:4px 10px;border-radius:12px;font-size:0.8rem;">${escapeHtml(u.status || "unknown")}</span>
        </td>
        <td style="padding:12px 15px;border-bottom:1px solid rgba(255,255,255,0.1);color:${containerColor};">${escapeHtml(containerStatus)}</td>
        <td style="padding:12px 15px;border-bottom:1px solid rgba(255,255,255,0.1);color:#888;">${escapeHtml(createdAt)}</td>
        <td style="padding:12px 15px;border-bottom:1px solid rgba(255,255,255,0.1);color:#888;">${escapeHtml(lastLogin)}</td>
        <td style="padding:12px 15px;border-bottom:1px solid rgba(255,255,255,0.1);">
          <a href="/admin/users/${escapeHtml(u.id || "")}" style="color:#4f46e5;text-decoration:none;">View details</a>
        </td>
      </tr>`;
    })
    .join("");

  // Placeholder message when no data
  const placeholderHtml = `
    <div style="background:rgba(249,115,22,0.1);border:1px solid rgba(249,115,22,0.3);border-radius:12px;padding:30px;text-align:center;margin-top:20px;">
      <div style="font-size:2rem;margin-bottom:15px;">&#128679;</div>
      <h3 style="color:#f97316;margin-bottom:10px;">Coming Soon</h3>
      <p style="color:#888;">${escapeHtml(errorMessage)}</p>
    </div>
  `;

  // Pagination HTML
  const paginationHtml =
    totalPages > 1
      ? `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-top:20px;padding:15px 0;">
      <div style="color:#888;font-size:0.9rem;">
        Showing ${(page - 1) * perPage + 1}-${Math.min(page * perPage, users.length)} of ${users.length} users
      </div>
      <div style="display:flex;gap:10px;">
        ${page > 1 ? `<a href="/admin/users?status=${encodeURIComponent(statusFilter)}&search=${encodeURIComponent(searchQuery)}&page=${page - 1}" style="padding:8px 16px;background:rgba(255,255,255,0.1);border-radius:6px;color:#fff;text-decoration:none;">Previous</a>` : `<span style="padding:8px 16px;background:rgba(255,255,255,0.05);border-radius:6px;color:#555;">Previous</span>`}
        ${page < totalPages ? `<a href="/admin/users?status=${encodeURIComponent(statusFilter)}&search=${encodeURIComponent(searchQuery)}&page=${page + 1}" style="padding:8px 16px;background:rgba(255,255,255,0.1);border-radius:6px;color:#fff;text-decoration:none;">Next</a>` : `<span style="padding:8px 16px;background:rgba(255,255,255,0.05);border-radius:6px;color:#555;">Next</span>`}
      </div>
    </div>
  `
      : "";

  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>User Management - OCMT Admin</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); min-height: 100vh; color: #fff; }
    .container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
    .header h1 { font-size: 1.8rem; }
    .header-links { display: flex; gap: 20px; }
    .header-links a { color: #a78bfa; text-decoration: none; }
    .header-links a:hover { text-decoration: underline; }
    .card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 25px; margin-bottom: 20px; }
    .filters { display: flex; gap: 15px; flex-wrap: wrap; align-items: center; }
    .filters select, .filters input { padding: 10px 15px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.2); background: rgba(255,255,255,0.1); color: white; font-size: 0.95rem; }
    .filters select { min-width: 180px; cursor: pointer; }
    .filters select option { background: #1a1a2e; color: white; }
    .filters input { flex: 1; min-width: 200px; }
    .filters input::placeholder { color: #666; }
    .filters button { padding: 10px 20px; border-radius: 8px; border: none; background: #4f46e5; color: white; font-size: 0.95rem; font-weight: 600; cursor: pointer; }
    .filters button:hover { background: #4338ca; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th { text-align: left; padding: 12px 15px; border-bottom: 2px solid rgba(255,255,255,0.1); color: #888; font-weight: 600; font-size: 0.85rem; text-transform: uppercase; }
    .empty-state { text-align: center; padding: 40px; color: #666; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>User Management</h1>
      <div class="header-links">
        <a href="/admin">Back to Dashboard</a>
        <a href="/logout">Logout</a>
      </div>
    </div>

    <div class="card">
      <form method="GET" action="/admin/users" class="filters">
        <select name="status">
          <option value="all" ${statusFilter === "all" ? "selected" : ""}>All Statuses</option>
          <option value="active" ${statusFilter === "active" ? "selected" : ""}>Active</option>
          <option value="pending" ${statusFilter === "pending" ? "selected" : ""}>Pending</option>
          <option value="pending_approval" ${statusFilter === "pending_approval" ? "selected" : ""}>Pending Approval</option>
          <option value="suspended" ${statusFilter === "suspended" ? "selected" : ""}>Suspended</option>
        </select>
        <input type="text" name="search" placeholder="Search by email..." value="${escapeHtml(searchQuery)}">
        <button type="submit">Filter</button>
      </form>
    </div>

    <div class="card">
      ${
        !apiAvailable
          ? placeholderHtml
          : users.length === 0
            ? '<div class="empty-state">No users found matching your criteria.</div>'
            : `
        <table>
          <thead>
            <tr>
              <th>Email</th>
              <th>Status</th>
              <th>Container</th>
              <th>Created</th>
              <th>Last Login</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${userRowsHtml}
          </tbody>
        </table>
        ${paginationHtml}
      `
      }
    </div>
  </div>
</body>
</html>`);
});

// GET /api/allowlist/check - Check if a user is allowlisted
app.get("/api/allowlist/check", requireAuth, async (req, res) => {
  try {
    const { identifier } = req.query;
    const data = await proxyToManagement(
      `/api/admin/user-allowlist/check?identifier=${encodeURIComponent(identifier || "")}`
    );
    res.json(data);
  } catch (error) {
    console.error("Proxy error (GET /api/allowlist/check):", error.message);
    res.status(500).json({ error: error.message });
  }
});

// PATCH /api/allowlist/:id - Update allowlist entry
app.patch("/api/allowlist/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const data = await proxyToManagement(`/api/admin/user-allowlist/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(req.body),
    });
    res.json(data);
  } catch (error) {
    console.error("Proxy error (PATCH /api/allowlist/:id):", error.message);
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/allowlist/:id - Delete allowlist entry
app.delete("/api/allowlist/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const data = await proxyToManagement(`/api/admin/user-allowlist/${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
    res.json(data);
  } catch (error) {
    console.error("Proxy error (DELETE /api/allowlist/:id):", error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// Allowlist Management Page
// ============================================================================

// GET /admin/allowlist - Allowlist management page
app.get("/admin/allowlist", requireAuth, async (req, res) => {
  // Fetch current allowlist data
  let entries = [];
  let settings = { enabled: false };
  let error = req.query.error || null;
  let success = req.query.success || null;

  try {
    const response = await proxyToManagement("/api/admin/user-allowlist");
    entries = response.entries || [];
    settings = response.settings || { enabled: false };
  } catch (e) {
    error = error || "Failed to load allowlist data: " + e.message;
  }

  const entriesHtml =
    entries.length > 0
      ? entries
          .map((entry) => {
            const statusBadge = entry.enabled
              ? '<span style="background:#22c55e;color:#fff;padding:2px 8px;border-radius:10px;font-size:0.75rem;">Enabled</span>'
              : '<span style="background:#6b7280;color:#fff;padding:2px 8px;border-radius:10px;font-size:0.75rem;">Disabled</span>';
            const typeBadge =
              entry.type === "domain"
                ? '<span style="background:#8b5cf6;color:#fff;padding:2px 8px;border-radius:10px;font-size:0.75rem;">Domain</span>'
                : '<span style="background:#3b82f6;color:#fff;padding:2px 8px;border-radius:10px;font-size:0.75rem;">Email</span>';
            return `<tr>
          <td style="padding:12px 15px;">${typeBadge}</td>
          <td style="padding:12px 15px;font-family:monospace;">${escapeHtml(entry.value)}</td>
          <td style="padding:12px 15px;color:#888;">${escapeHtml(entry.description || "-")}</td>
          <td style="padding:12px 15px;">${statusBadge}</td>
          <td style="padding:12px 15px;">
            <button onclick="toggleEntry('${escapeHtml(entry.id)}', ${!entry.enabled})" style="background:${entry.enabled ? "#6b7280" : "#22c55e"};color:#fff;border:none;padding:6px 12px;border-radius:6px;cursor:pointer;margin-right:5px;font-size:0.8rem;">${entry.enabled ? "Disable" : "Enable"}</button>
            <button onclick="deleteEntry('${escapeHtml(entry.id)}')" style="background:#ef4444;color:#fff;border:none;padding:6px 12px;border-radius:6px;cursor:pointer;font-size:0.8rem;">Delete</button>
          </td>
        </tr>`;
          })
          .join("")
      : '<tr><td colspan="5" style="padding:20px;text-align:center;color:#666;">No allowlist entries yet</td></tr>';

  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Allowlist Management - OCMT Admin</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); min-height: 100vh; color: #fff; }
    .container { max-width: 900px; margin: 0 auto; padding: 40px 20px; }
    h1 { font-size: 2rem; margin-bottom: 30px; }
    .card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 30px; margin-bottom: 20px; }
    .card h2 { margin-bottom: 20px; font-size: 1.2rem; }
    input, select, textarea, button { padding: 12px 15px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.2); font-size: 1rem; }
    input, select, textarea { background: rgba(255,255,255,0.1); color: white; }
    input::placeholder, textarea::placeholder { color: #666; }
    button { background: #4f46e5; color: white; border: none; cursor: pointer; }
    button:hover { background: #4338ca; }
    button:disabled { background: #6b7280; cursor: not-allowed; }
    a { color: #4f46e5; text-decoration: none; }
    .nav { margin-bottom: 20px; display: flex; gap: 15px; }
    .error { background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.3); color: #ef4444; padding: 12px; border-radius: 8px; margin-bottom: 20px; }
    .success { background: rgba(34, 197, 94, 0.2); border: 1px solid rgba(34, 197, 94, 0.3); color: #22c55e; padding: 12px; border-radius: 8px; margin-bottom: 20px; }
    table { width: 100%; border-collapse: collapse; }
    th { text-align: left; padding: 12px 15px; border-bottom: 1px solid rgba(255,255,255,0.1); color: #888; font-weight: 500; }
    tr { border-bottom: 1px solid rgba(255,255,255,0.05); }
    tr:last-child { border-bottom: none; }
    .toggle-container { display: flex; align-items: center; gap: 15px; }
    .toggle { position: relative; width: 50px; height: 26px; }
    .toggle input { opacity: 0; width: 0; height: 0; }
    .toggle-slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background: #374151; border-radius: 26px; transition: 0.3s; }
    .toggle-slider:before { position: absolute; content: ""; height: 20px; width: 20px; left: 3px; bottom: 3px; background: white; border-radius: 50%; transition: 0.3s; }
    .toggle input:checked + .toggle-slider { background: #22c55e; }
    .toggle input:checked + .toggle-slider:before { transform: translateX(24px); }
    .toggle-text { color: #888; font-size: 0.9rem; }
    .form-row { display: flex; gap: 10px; margin-bottom: 15px; }
    .form-row > * { flex: 1; }
    .form-row select { flex: 0 0 120px; }
    .test-section { display: flex; gap: 10px; align-items: flex-start; }
    .test-section input { flex: 1; }
    #test-result { margin-top: 15px; padding: 12px; border-radius: 8px; display: none; }
    #test-result.allowed { background: rgba(34, 197, 94, 0.2); border: 1px solid rgba(34, 197, 94, 0.3); color: #22c55e; display: block; }
    #test-result.denied { background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.3); color: #ef4444; display: block; }
    #test-result.error { background: rgba(251, 191, 36, 0.2); border: 1px solid rgba(251, 191, 36, 0.3); color: #fbbf24; display: block; }
  </style>
</head>
<body>
  <div class="container">
    <div class="nav">
      <a href="/admin">&larr; Back to Admin</a>
      <a href="/logout" style="margin-left:auto;">Logout</a>
    </div>
    <h1>Allowlist Management</h1>

    ${error ? `<div class="error">${escapeHtml(error)}</div>` : ""}
    ${success ? '<div class="success">Operation completed successfully</div>' : ""}

    <div class="card">
      <h2>Allowlist Status</h2>
      <div class="toggle-container">
        <label class="toggle">
          <input type="checkbox" id="allowlist-toggle" ${settings.enabled ? "checked" : ""} onchange="toggleAllowlist(this.checked)">
          <span class="toggle-slider"></span>
        </label>
        <span class="toggle-text" id="toggle-status">
          ${
            settings.enabled
              ? 'Allowlist is <strong style="color:#22c55e;">enabled</strong>. Only users matching an entry can access the system.'
              : 'Allowlist is <strong style="color:#ef4444;">disabled</strong>. All users can access the system.'
          }
        </span>
      </div>
    </div>

    <div class="card">
      <h2>Add Entry</h2>
      <form action="/api/allowlist" method="POST" id="add-form">
        <div class="form-row">
          <select name="type" id="entry-type" required>
            <option value="email">Email</option>
            <option value="domain">Domain</option>
          </select>
          <input type="text" name="value" id="entry-value" placeholder="user@example.com or example.com" required>
        </div>
        <div class="form-row">
          <textarea name="description" placeholder="Description (optional)" rows="2" style="resize:vertical;"></textarea>
        </div>
        <button type="submit">Add Entry</button>
      </form>
    </div>

    <div class="card">
      <h2>Allowlist Entries</h2>
      <table>
        <thead>
          <tr>
            <th>Type</th>
            <th>Value</th>
            <th>Description</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${entriesHtml}
        </tbody>
      </table>
    </div>

    <div class="card">
      <h2>Test Email</h2>
      <p style="color:#888;margin-bottom:15px;font-size:0.9rem;">Check if an email address would be allowed access.</p>
      <div class="test-section">
        <input type="email" id="test-email" placeholder="test@example.com">
        <button onclick="testEmail()" id="test-btn">Test</button>
      </div>
      <div id="test-result"></div>
    </div>
  </div>

  <script>
    // Toggle allowlist enabled/disabled
    async function toggleAllowlist(enabled) {
      try {
        const response = await fetch('/api/allowlist/toggle', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled })
        });
        const data = await response.json();
        if (data.error) {
          alert('Error: ' + data.error);
          document.getElementById('allowlist-toggle').checked = !enabled;
        } else {
          const statusEl = document.getElementById('toggle-status');
          if (enabled) {
            statusEl.innerHTML = 'Allowlist is <strong style="color:#22c55e;">enabled</strong>. Only users matching an entry can access the system.';
          } else {
            statusEl.innerHTML = 'Allowlist is <strong style="color:#ef4444;">disabled</strong>. All users can access the system.';
          }
        }
      } catch (e) {
        alert('Error toggling allowlist: ' + e.message);
        document.getElementById('allowlist-toggle').checked = !enabled;
      }
    }

    // Toggle individual entry enabled/disabled
    async function toggleEntry(id, enabled) {
      try {
        const response = await fetch('/api/allowlist/' + id, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled })
        });
        const data = await response.json();
        if (data.error) {
          alert('Error: ' + data.error);
        } else {
          window.location.reload();
        }
      } catch (e) {
        alert('Error updating entry: ' + e.message);
      }
    }

    // Delete entry
    async function deleteEntry(id) {
      if (!confirm('Are you sure you want to delete this entry?')) return;
      try {
        const response = await fetch('/api/allowlist/' + id, {
          method: 'DELETE'
        });
        const data = await response.json();
        if (data.error) {
          alert('Error: ' + data.error);
        } else {
          window.location.reload();
        }
      } catch (e) {
        alert('Error deleting entry: ' + e.message);
      }
    }

    // Test email
    async function testEmail() {
      const email = document.getElementById('test-email').value;
      const resultEl = document.getElementById('test-result');
      const btn = document.getElementById('test-btn');

      if (!email) {
        resultEl.className = 'error';
        resultEl.textContent = 'Please enter an email address';
        resultEl.style.display = 'block';
        return;
      }

      btn.disabled = true;
      btn.textContent = 'Testing...';

      try {
        const response = await fetch('/api/allowlist/check?identifier=' + encodeURIComponent(email));
        const data = await response.json();

        if (data.error) {
          resultEl.className = 'error';
          resultEl.textContent = 'Error: ' + data.error;
        } else if (data.allowed) {
          resultEl.className = 'allowed';
          resultEl.innerHTML = '<strong>' + escapeHtml(email) + '</strong> is allowed' + (data.matchedBy ? ' (matched by: ' + escapeHtml(data.matchedBy) + ')' : '');
        } else {
          resultEl.className = 'denied';
          resultEl.innerHTML = '<strong>' + escapeHtml(email) + '</strong> would be denied access';
        }
        resultEl.style.display = 'block';
      } catch (e) {
        resultEl.className = 'error';
        resultEl.textContent = 'Error testing email: ' + e.message;
        resultEl.style.display = 'block';
      } finally {
        btn.disabled = false;
        btn.textContent = 'Test';
      }
    }

    // Simple HTML escape for JS
    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    // Handle form submission via AJAX
    document.getElementById('add-form').addEventListener('submit', async function(e) {
      e.preventDefault();
      const formData = new FormData(this);
      const data = Object.fromEntries(formData.entries());

      try {
        const response = await fetch('/api/allowlist', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data)
        });
        const result = await response.json();
        if (result.error) {
          alert('Error: ' + result.error);
        } else {
          window.location.href = '/admin/allowlist?success=1';
        }
      } catch (e) {
        alert('Error adding entry: ' + e.message);
      }
    });

    // Update placeholder based on type selection
    document.getElementById('entry-type').addEventListener('change', function() {
      const valueInput = document.getElementById('entry-value');
      if (this.value === 'domain') {
        valueInput.placeholder = 'example.com';
      } else {
        valueInput.placeholder = 'user@example.com';
      }
    });
  </script>
</body>
</html>`);
});

// ============================================================================
// Container Status Page (placeholder for agent-server integration)
// ============================================================================

app.get("/admin/containers", requireAuth, (req, res) => {
  // Placeholder data - in production, this would come from agent-server API
  const agentServerUrl = process.env.AGENT_SERVER_URL || null;

  // Mock container data for UI demonstration
  const containers = [
    { id: "cnt-abc123", user: "alice", status: "running", memory: "256MB", cpu: "2.3%", lastActivity: new Date(Date.now() - 5 * 60 * 1000).toISOString() },
    { id: "cnt-def456", user: "bob", status: "hibernated", memory: "0MB", cpu: "0%", lastActivity: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString() },
    { id: "cnt-ghi789", user: "carol", status: "running", memory: "512MB", cpu: "8.1%", lastActivity: new Date(Date.now() - 30 * 1000).toISOString() },
    { id: "cnt-jkl012", user: "dave", status: "stopped", memory: "0MB", cpu: "0%", lastActivity: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString() },
  ];

  // Calculate stats
  const stats = {
    total: containers.length,
    running: containers.filter((c) => c.status === "running").length,
    hibernated: containers.filter((c) => c.status === "hibernated").length,
    stopped: containers.filter((c) => c.status === "stopped").length,
  };

  // Status badge colors
  const statusColors = {
    running: { bg: "rgba(34, 197, 94, 0.2)", color: "#22c55e", text: "Running" },
    hibernated: { bg: "rgba(234, 179, 8, 0.2)", color: "#eab308", text: "Hibernated" },
    stopped: { bg: "rgba(239, 68, 68, 0.2)", color: "#ef4444", text: "Stopped" },
  };

  // Generate table rows
  const tableRows = containers
    .map((c) => {
      const statusStyle = statusColors[c.status] || statusColors.stopped;
      const lastActive = new Date(c.lastActivity).toLocaleString();

      // Action buttons based on status
      let actions = "";
      if (c.status === "hibernated") {
        actions = `<button class="action-btn wake" disabled title="Wake container">Wake</button>`;
      } else if (c.status === "running") {
        actions = `<button class="action-btn hibernate" disabled title="Hibernate container">Hibernate</button>`;
      } else {
        actions = `<button class="action-btn restart" disabled title="Restart container">Restart</button>`;
      }

      return `<tr>
      <td><code>${escapeHtml(c.id)}</code></td>
      <td>${escapeHtml(c.user)}</td>
      <td><span class="status-badge" style="background:${statusStyle.bg};color:${statusStyle.color};">${statusStyle.text}</span></td>
      <td>${escapeHtml(c.memory)}</td>
      <td>${escapeHtml(c.cpu)}</td>
      <td>${escapeHtml(lastActive)}</td>
      <td>${actions}</td>
    </tr>`;
    })
    .join("");

  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Container Status - OCMT Admin</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); min-height: 100vh; color: #fff; }
    .container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
    .header-left { display: flex; align-items: center; gap: 20px; }
    .header-right { display: flex; gap: 15px; }
    h1 { font-size: 1.8rem; }
    a { color: #a78bfa; text-decoration: none; }
    a:hover { text-decoration: underline; }

    /* Stats Grid */
    .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }
    .stat { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); padding: 20px; border-radius: 12px; text-align: center; }
    .stat-num { font-size: 2rem; font-weight: bold; }
    .stat-num.total { color: #a78bfa; }
    .stat-num.running { color: #22c55e; }
    .stat-num.hibernated { color: #eab308; }
    .stat-num.stopped { color: #ef4444; }
    .stat-label { color: #888; font-size: 0.9rem; margin-top: 5px; }

    /* Filters */
    .filters { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 20px; margin-bottom: 20px; display: flex; gap: 15px; align-items: center; }
    .filters label { color: #888; font-size: 0.9rem; }
    .filters select { padding: 8px 12px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.2); background: rgba(255,255,255,0.1); color: white; font-size: 0.9rem; cursor: pointer; }
    .filters select option { background: #1a1a2e; color: white; }
    .btn { padding: 8px 16px; border-radius: 6px; border: none; font-size: 0.9rem; cursor: pointer; font-weight: 500; }
    .btn-primary { background: #4f46e5; color: white; }
    .btn-primary:hover { background: #4338ca; }
    .btn-primary:disabled { background: #4f46e580; cursor: not-allowed; }

    /* Table */
    .card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 25px; margin-bottom: 20px; overflow-x: auto; }
    .card h2 { margin-bottom: 20px; font-size: 1.2rem; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1); }
    th { color: #888; font-weight: 500; font-size: 0.85rem; text-transform: uppercase; }
    td { font-size: 0.9rem; }
    code { background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 4px; font-family: 'Menlo', monospace; font-size: 0.85rem; }
    .status-badge { padding: 4px 10px; border-radius: 20px; font-size: 0.8rem; font-weight: 500; }
    .action-btn { padding: 5px 12px; border-radius: 4px; border: 1px solid rgba(255,255,255,0.2); background: transparent; color: #888; font-size: 0.8rem; cursor: pointer; margin-right: 5px; }
    .action-btn:hover:not(:disabled) { background: rgba(255,255,255,0.1); color: white; }
    .action-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .action-btn.wake { border-color: rgba(34, 197, 94, 0.5); color: #22c55e; }
    .action-btn.hibernate { border-color: rgba(234, 179, 8, 0.5); color: #eab308; }
    .action-btn.restart { border-color: rgba(79, 70, 229, 0.5); color: #a78bfa; }

    /* Placeholder Message */
    .placeholder { background: rgba(234, 179, 8, 0.1); border: 1px solid rgba(234, 179, 8, 0.3); border-radius: 12px; padding: 25px; margin-bottom: 20px; }
    .placeholder h3 { color: #eab308; margin-bottom: 15px; font-size: 1rem; }
    .placeholder p { color: #888; margin-bottom: 10px; font-size: 0.9rem; }
    .placeholder code { color: #eab308; }
    .placeholder ul { margin-left: 20px; margin-top: 10px; }
    .placeholder li { color: #888; margin-bottom: 8px; font-size: 0.9rem; }

    @media (max-width: 768px) {
      .stats { grid-template-columns: repeat(2, 1fr); }
      .filters { flex-wrap: wrap; }
      .header { flex-direction: column; gap: 15px; align-items: flex-start; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="header-left">
        <a href="/admin">Back to Admin</a>
        <h1>Container Status</h1>
      </div>
      <div class="header-right">
        <a href="/logout">Logout</a>
      </div>
    </div>

    <!-- Placeholder Message -->
    <div class="placeholder">
      <h3>Agent Server Integration Required</h3>
      <p>Container management requires agent-server integration. The data shown below is placeholder data for UI demonstration.</p>
      <ul>
        <li>Direct Docker commands: <code>docker ps</code>, <code>docker stats</code></li>
        <li>Environment variable needed: <code>AGENT_SERVER_URL</code> ${agentServerUrl ? `(currently set to: ${escapeHtml(agentServerUrl)})` : "(not set)"}</li>
      </ul>
    </div>

    <!-- Summary Stats -->
    <div class="stats">
      <div class="stat">
        <div class="stat-num total">${stats.total}</div>
        <div class="stat-label">Total Containers</div>
      </div>
      <div class="stat">
        <div class="stat-num running">${stats.running}</div>
        <div class="stat-label">Running</div>
      </div>
      <div class="stat">
        <div class="stat-num hibernated">${stats.hibernated}</div>
        <div class="stat-label">Hibernated</div>
      </div>
      <div class="stat">
        <div class="stat-num stopped">${stats.stopped}</div>
        <div class="stat-label">Stopped</div>
      </div>
    </div>

    <!-- Filters -->
    <div class="filters">
      <label for="status-filter">Status:</label>
      <select id="status-filter" disabled>
        <option value="all">All</option>
        <option value="running">Running</option>
        <option value="hibernated">Hibernated</option>
        <option value="stopped">Stopped</option>
      </select>
      <button class="btn btn-primary" disabled>Refresh</button>
    </div>

    <!-- Containers Table -->
    <div class="card">
      <h2>Containers</h2>
      <table>
        <thead>
          <tr>
            <th>Container ID</th>
            <th>User</th>
            <th>Status</th>
            <th>Memory</th>
            <th>CPU</th>
            <th>Last Activity</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${tableRows}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>`);
});

const PORT = process.env.PORT || 3000;
// SECURITY: Admin UI should only be accessible from internal network
// Set ADMIN_BIND to '127.0.0.1' or internal IP (e.g., '10.x.x.x') for production
// Set to '0.0.0.0' only for local development
const ADMIN_BIND = process.env.ADMIN_BIND || "127.0.0.1";

if (ADMIN_BIND === "0.0.0.0") {
  console.warn(
    "⚠️  WARNING: Admin UI is binding to 0.0.0.0 - this exposes it to the public internet!",
  );
  console.warn("   Set ADMIN_BIND=127.0.0.1 for production use.");
}

app.listen(PORT, ADMIN_BIND, () => {
  console.log(`OCMT Admin UI running on http://${ADMIN_BIND}:${PORT}`);
  if (ADMIN_BIND === "127.0.0.1") {
    console.log("   Access via SSH tunnel: ssh -L 3000:localhost:3000 user@server");
  }
});

import crypto from "crypto";
// Admin routes (internal only - access via SSH tunnel)
import { Router } from "express";
import { users, audit } from "../db/index.js";

const router = Router();

// XSS protection: escape HTML entities in user-controlled data
function escapeHtml(str) {
  if (!str) {
    return "";
  }
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Allowed status values for CSS class names
const ALLOWED_STATUSES = new Set(["active", "pending", "inactive", "suspended"]);

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!ADMIN_PASSWORD) {
  throw new Error(
    "ADMIN_PASSWORD environment variable is required for admin routes. " +
      "Set a strong password in your environment.",
  );
}

// Session store for admin sessions
// Key: session token, Value: { expiresAt: timestamp }
const adminSessions = new Map();

// Session duration: 24 hours
const SESSION_DURATION_MS = 24 * 60 * 60 * 1000;

// Clean up expired sessions periodically
setInterval(
  () => {
    const now = Date.now();
    for (const [token, session] of adminSessions.entries()) {
      if (session.expiresAt <= now) {
        adminSessions.delete(token);
      }
    }
  },
  60 * 60 * 1000,
); // Run every hour

// Generate a cryptographically secure session token
function generateSessionToken() {
  return crypto.randomBytes(32).toString("hex");
}

// Validate session token
function validateSession(token) {
  if (!token) {
    return false;
  }
  const session = adminSessions.get(token);
  if (!session) {
    return false;
  }
  if (session.expiresAt <= Date.now()) {
    adminSessions.delete(token);
    return false;
  }
  return true;
}

// Auth middleware for admin
function requireAdmin(req, res, next) {
  const sessionToken = req.cookies.admin_session;
  if (validateSession(sessionToken)) {
    return next();
  }
  res.redirect("/admin/login");
}

// Admin login page
router.get("/login", (req, res) => {
  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Admin Login - OCMT</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0d1117; min-height: 100vh; color: #c9d1d9; display: flex; align-items: center; justify-content: center; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 30px; width: 100%; max-width: 400px; }
    h1 { font-size: 1.5rem; margin-bottom: 20px; }
    input { width: 100%; padding: 12px; border-radius: 6px; border: 1px solid #30363d; background: #0d1117; color: #c9d1d9; font-size: 1rem; margin-bottom: 15px; }
    button { width: 100%; padding: 12px; border-radius: 6px; border: none; background: #238636; color: white; font-size: 1rem; cursor: pointer; }
    button:hover { background: #2ea043; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Admin Login</h1>
    <form action="/admin/login" method="POST">
      <input type="password" name="password" placeholder="Admin password" required>
      <button type="submit">Login</button>
    </form>
  </div>
</body>
</html>`);
});

// Admin login POST
router.post("/login", (req, res) => {
  const { password } = req.body;
  // Use timing-safe comparison to prevent timing attacks
  const passwordBuffer = Buffer.from(password || "");
  const adminPasswordBuffer = Buffer.from(ADMIN_PASSWORD);

  // Pad to same length for timing-safe comparison
  const maxLen = Math.max(passwordBuffer.length, adminPasswordBuffer.length);
  const paddedPassword = Buffer.alloc(maxLen);
  const paddedAdminPassword = Buffer.alloc(maxLen);
  passwordBuffer.copy(paddedPassword);
  adminPasswordBuffer.copy(paddedAdminPassword);

  if (
    passwordBuffer.length === adminPasswordBuffer.length &&
    crypto.timingSafeEqual(paddedPassword, paddedAdminPassword)
  ) {
    // Generate a secure session token instead of storing the password
    const sessionToken = generateSessionToken();
    adminSessions.set(sessionToken, {
      expiresAt: Date.now() + SESSION_DURATION_MS,
    });
    res.cookie("admin_session", sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: SESSION_DURATION_MS,
    });
    res.redirect("/admin");
  } else {
    res.redirect("/admin/login?error=1");
  }
});

// Admin dashboard
router.get("/", requireAdmin, async (req, res) => {
  const allUsers = await users.list();
  const userCount = allUsers.length;
  const activeCount = allUsers.filter((u) => u.status === "active").length;
  const recentLogs = await audit.getRecent(20);

  const userRows = allUsers
    .map((u) => {
      // Validate status for CSS class - only allow known values
      const statusClass = ALLOWED_STATUSES.has(u.status) ? u.status : "unknown";
      return `
    <tr>
      <td>${escapeHtml(u.name)}</td>
      <td>${escapeHtml(u.email)}</td>
      <td><span class="status ${statusClass}">${escapeHtml(u.status)}</span></td>
      <td>@${escapeHtml(u.telegram_bot_username) || "N/A"}</td>
      <td>${new Date(u.created_at).toLocaleDateString()}</td>
      <td><a href="/admin/user/${encodeURIComponent(u.id)}">View</a></td>
    </tr>
  `;
    })
    .join("");

  const logRows = recentLogs
    .map(
      (l) => `
    <tr>
      <td>${new Date(l.timestamp).toLocaleString()}</td>
      <td>${escapeHtml(l.user_name) || "System"}</td>
      <td>${escapeHtml(l.action)}</td>
    </tr>
  `,
    )
    .join("");

  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Admin - OCMT</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0d1117; min-height: 100vh; color: #c9d1d9; }
    .container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
    h1 { font-size: 1.8rem; margin-bottom: 30px; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 30px; }
    .stat { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; }
    .stat-num { font-size: 2rem; font-weight: bold; color: #58a6ff; }
    .stat-label { color: #8b949e; font-size: 0.9rem; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
    .card h2 { font-size: 1.1rem; margin-bottom: 15px; color: #58a6ff; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #30363d; }
    th { color: #8b949e; font-weight: normal; }
    .status { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.8rem; }
    .status.active { background: #238636; color: white; }
    .status.pending { background: #9e6a03; color: white; }
    a { color: #58a6ff; text-decoration: none; }
    .nav { margin-bottom: 20px; }
    .nav a { margin-right: 15px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="nav">
      <a href="/">Public Site</a>
      <a href="/admin">Dashboard</a>
      <a href="/admin/logs">Logs</a>
    </div>
    <h1>OCMT Admin</h1>
    <div class="stats">
      <div class="stat">
        <div class="stat-num">${userCount}</div>
        <div class="stat-label">Total Users</div>
      </div>
      <div class="stat">
        <div class="stat-num">${activeCount}</div>
        <div class="stat-label">Active</div>
      </div>
      <div class="stat">
        <div class="stat-num">${userCount - activeCount}</div>
        <div class="stat-label">Pending</div>
      </div>
    </div>
    <div class="card">
      <h2>Users</h2>
      <table>
        <thead>
          <tr><th>Name</th><th>Email</th><th>Status</th><th>Bot</th><th>Created</th><th></th></tr>
        </thead>
        <tbody>
          ${userRows || '<tr><td colspan="6">No users yet</td></tr>'}
        </tbody>
      </table>
    </div>
    <div class="card">
      <h2>Recent Activity</h2>
      <table>
        <thead>
          <tr><th>Time</th><th>User</th><th>Action</th></tr>
        </thead>
        <tbody>
          ${logRows || '<tr><td colspan="3">No activity yet</td></tr>'}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>`);
});

// Admin logs page
router.get("/logs", requireAdmin, async (req, res) => {
  const logs = await audit.getRecent(100);

  const logRows = logs
    .map(
      (l) => `
    <tr>
      <td>${new Date(l.timestamp).toLocaleString()}</td>
      <td>${escapeHtml(l.user_name) || "System"}</td>
      <td><code>${escapeHtml(l.action)}</code></td>
      <td><pre style="margin:0;max-width:300px;overflow:auto;font-size:0.75rem;">${l.details ? escapeHtml(JSON.stringify(l.details, null, 2)) : "-"}</pre></td>
      <td>${escapeHtml(l.ip_address) || "-"}</td>
    </tr>
  `,
    )
    .join("");

  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Logs - OCMT Admin</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0d1117; min-height: 100vh; color: #c9d1d9; }
    .container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
    h1 { font-size: 1.8rem; margin-bottom: 30px; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #30363d; }
    th { color: #8b949e; font-weight: normal; }
    code { background: #21262d; padding: 2px 6px; border-radius: 4px; font-size: 0.85rem; }
    pre { background: #21262d; padding: 8px; border-radius: 4px; }
    a { color: #58a6ff; text-decoration: none; }
    .nav { margin-bottom: 20px; }
    .nav a { margin-right: 15px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="nav">
      <a href="/">Public Site</a>
      <a href="/admin">Dashboard</a>
      <a href="/admin/logs">Logs</a>
    </div>
    <h1>Audit Logs</h1>
    <div class="card">
      <table>
        <thead>
          <tr><th>Time</th><th>User</th><th>Action</th><th>Details</th><th>IP</th></tr>
        </thead>
        <tbody>
          ${logRows || '<tr><td colspan="5">No logs yet</td></tr>'}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>`);
});

export default router;

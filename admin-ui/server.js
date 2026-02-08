import { spawnSync } from "child_process";
import crypto from "crypto";
import express from "express";
import fs from "fs-extra";
import path from "path";

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
  // Only accept token from Authorization header - never from query params
  // Query params leak to logs, browser history, and referrer headers
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (!token) {
    return res.status(401).send("Unauthorized - provide ADMIN_TOKEN via Authorization header");
  }
  // Use timing-safe comparison to prevent timing attacks
  const tokenBuffer = Buffer.from(token);
  const adminTokenBuffer = Buffer.from(ADMIN_TOKEN);
  if (
    tokenBuffer.length !== adminTokenBuffer.length ||
    !crypto.timingSafeEqual(tokenBuffer, adminTokenBuffer)
  ) {
    return res.status(401).send("Unauthorized - invalid token");
  }
  next();
}

function getConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
  } catch (e) {
    return null;
  }
}

function saveConfig(config) {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
}

function generateUserId(name) {
  return (
    name
      .toLowerCase()
      .replace(/[^a-z0-9]/g, "-")
      .slice(0, 20) +
    "-" +
    Date.now().toString(36).slice(-4)
  );
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

// Landing page
app.get("/", (req, res) => {
  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>OCMT - Your AI Assistant</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); min-height: 100vh; color: #fff; }
    .container { max-width: 600px; margin: 0 auto; padding: 40px 20px; }
    h1 { font-size: 3rem; margin-bottom: 10px; }
    h1 span { font-size: 4rem; }
    .subtitle { color: #888; font-size: 1.2rem; margin-bottom: 40px; }
    .card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 30px; margin-bottom: 20px; }
    .step { display: flex; align-items: flex-start; margin-bottom: 20px; opacity: 0.7; }
    .step.active { opacity: 1; }
    .step-num { background: #4f46e5; color: white; width: 32px; height: 32px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; margin-right: 15px; flex-shrink: 0; }
    .step h3 { margin-bottom: 5px; }
    .step p { color: #888; font-size: 0.9rem; }
    input, button { width: 100%; padding: 15px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.2); font-size: 1rem; margin-bottom: 15px; }
    input { background: rgba(255,255,255,0.1); color: white; }
    input::placeholder { color: #666; }
    button { background: #4f46e5; color: white; border: none; cursor: pointer; font-weight: 600; }
    button:hover { background: #4338ca; }
    .admin-link { color: #4f46e5; text-decoration: none; font-size: 0.9rem; display: block; text-align: center; margin-top: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>OCMT</h1>
    <p class="subtitle">Your personal AI assistant in 3 easy steps</p>
    <div class="card">
      <form action="/signup" method="POST">
        <div class="step active">
          <div class="step-num">1</div>
          <div><h3>What's your name?</h3><p>We'll create your personal AI assistant</p></div>
        </div>
        <input type="text" name="name" placeholder="Enter your first name" required>
        <div class="step">
          <div class="step-num">2</div>
          <div><h3>Meet your AI</h3><p>Your AI will introduce itself and you'll set it up together</p></div>
        </div>
        <button type="submit">Get My AI Assistant →</button>
      </form>
    </div>
    <a href="/admin" class="admin-link">Admin Dashboard →</a>
  </div>
</body>
</html>`);
});

// Signup handler
app.post("/signup", async (req, res) => {
  const { name, botName } = req.body;
  if (!name) {
    return res.redirect("/");
  }

  const userId = generateUserId(name);
  const workspacePath = path.join(WORKSPACES_DIR, userId);

  // Copy ENTIRE default workspace to new user workspace (excluding .git)
  const defaultWorkspace = path.join(OPENCLAW_DIR, "workspace");
  await fs.copy(defaultWorkspace, workspacePath, {
    filter: (src) => !src.includes(".git"),
  });

  // The AI will handle personalization through the BOOTSTRAP.md conversation
  // User tells AI their name and picks AI name during onboarding chat

  // Update config with new agent
  const config = getConfig();
  if (!config) {
    return res.status(500).send("Could not read OpenClaw config");
  }

  if (!config.agents) {
    config.agents = {};
  }
  if (!config.agents.list) {
    config.agents.list = [];
  }

  config.agents.list.push({
    id: userId,
    workspace: workspacePath,
  });

  saveConfig(config);

  // Signal gateway to reload config (SIGUSR1)
  // Using spawnSync with array arguments to avoid command injection vulnerabilities
  // Try first pattern, ignore errors
  spawnSync("pkill", ["-USR1", "-f", "openclaw gateway"], { stdio: "ignore" });
  // Try second pattern, ignore errors
  spawnSync("pkill", ["-USR1", "-f", "clawdbot"], { stdio: "ignore" });

  // Go directly to chat - the AI will introduce itself via BOOTSTRAP.md
  res.redirect("/chat?user=" + encodeURIComponent(userId) + "&name=" + encodeURIComponent(name));
});

// Connect page
app.get("/connect", (req, res) => {
  const { user, name, botName } = req.query;
  const aiName = botName || "Assistant";
  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Connect Your AI - OCMT</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); min-height: 100vh; color: #fff; }
    .container { max-width: 700px; margin: 0 auto; padding: 40px 20px; }
    h1 { font-size: 2rem; margin-bottom: 10px; }
    .subtitle { color: #888; font-size: 1.1rem; margin-bottom: 30px; }
    .success { background: rgba(34, 197, 94, 0.2); border: 1px solid rgba(34, 197, 94, 0.3); padding: 20px; border-radius: 8px; text-align: center; margin-bottom: 30px; }
    .success h2 { color: #22c55e; margin-bottom: 5px; }
    .section-title { font-size: 1.1rem; color: #888; margin: 30px 0 15px; text-transform: uppercase; letter-spacing: 1px; }
    .integrations { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 15px; }
    .integration { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 20px; text-align: center; cursor: pointer; transition: all 0.2s; }
    .integration:hover { background: rgba(255,255,255,0.1); }
    .integration.soon { opacity: 0.5; cursor: not-allowed; }
    .integration-icon { font-size: 2.5rem; margin-bottom: 10px; }
    .integration h3 { font-size: 1rem; margin-bottom: 5px; }
    .integration p { color: #666; font-size: 0.8rem; }
    .badge { display: inline-block; background: #4f46e5; color: white; padding: 2px 8px; border-radius: 10px; font-size: 0.7rem; margin-top: 8px; }
    .badge.gray { background: #666; }
    .chat-now { display: block; background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%); color: white; padding: 20px 30px; border-radius: 12px; text-decoration: none; font-weight: 600; font-size: 1.1rem; text-align: center; margin-bottom: 20px; }
    .note { background: rgba(79, 70, 229, 0.2); border: 1px solid rgba(79, 70, 229, 0.3); padding: 15px; border-radius: 8px; margin-top: 30px; font-size: 0.9rem; }
    .user-id { font-family: monospace; background: rgba(0,0,0,0.3); padding: 2px 8px; border-radius: 4px; }
    .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; align-items: center; justify-content: center; }
    .modal.active { display: flex; }
    .modal-content { background: #1a1a2e; border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 30px; max-width: 500px; width: 90%; }
    .modal-close { float: right; background: none; border: none; color: #888; font-size: 1.5rem; cursor: pointer; width: auto; }
    .modal h2 { margin-bottom: 20px; }
    .modal ol { padding-left: 20px; line-height: 2; color: #aaa; }
    .modal .btn { display: inline-block; background: #0088cc; color: white; padding: 12px 25px; border-radius: 8px; text-decoration: none; font-weight: 600; margin-top: 15px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="success">
      <h2>✓ Meet ${escapeHtml(aiName)}!</h2>
      <p>Welcome, ${escapeHtml(name || "friend")}! Your AI assistant <strong>${escapeHtml(aiName)}</strong> is ready.</p>
    </div>
    <h1>Connect with ${escapeHtml(aiName)}</h1>
    <p class="subtitle">Choose how you want to chat with ${escapeHtml(aiName)}</p>
    <a href="/chat?user=${encodeURIComponent(user || "")}&botName=${encodeURIComponent(aiName)}" class="chat-now">💬 Start Chatting with ${escapeHtml(aiName)} →</a>
    <div class="section-title">📱 Messaging Apps</div>
    <div class="integrations">
      <div class="integration" onclick="showModal('telegram')">
        <div class="integration-icon">✈️</div>
        <h3>Telegram</h3>
        <p>Chat on mobile</p>
        <span class="badge">Ready</span>
      </div>
      <div class="integration" onclick="showModal('whatsapp')">
        <div class="integration-icon">💬</div>
        <h3>WhatsApp</h3>
        <p>Use your number</p>
        <span class="badge">Ready</span>
      </div>
      <div class="integration" onclick="showModal('slack')">
        <div class="integration-icon">💼</div>
        <h3>Slack</h3>
        <p>Work chat</p>
        <span class="badge">Ready</span>
      </div>
      <div class="integration soon">
        <div class="integration-icon">💬</div>
        <h3>iMessage</h3>
        <p>Apple users</p>
        <span class="badge gray">Coming Soon</span>
      </div>
    </div>
    <div class="section-title">📅 Productivity</div>
    <div class="integrations">
      <div class="integration" onclick="showModal('gcal')">
        <div class="integration-icon">📅</div>
        <h3>Google Calendar</h3>
        <p>Manage events</p>
        <span class="badge">Ready</span>
      </div>
      <div class="integration" onclick="showModal('gmail')">
        <div class="integration-icon">📧</div>
        <h3>Gmail</h3>
        <p>Email assistant</p>
        <span class="badge">Ready</span>
      </div>
      <div class="integration soon">
        <div class="integration-icon">📝</div>
        <h3>Notion</h3>
        <p>Notes & docs</p>
        <span class="badge gray">Coming Soon</span>
      </div>
    </div>
    <div class="note">
      <strong>Your Agent ID:</strong> <span class="user-id">${escapeHtml(user)}</span><br>
      <small>You can connect multiple apps to the same AI assistant</small>
    </div>
  </div>
  <div class="modal" id="modal-telegram">
    <div class="modal-content">
      <button class="modal-close" onclick="closeModal('telegram')">×</button>
      <h2>✈️ Connect Telegram</h2>
      <ol>
        <li>Open Telegram on your phone</li>
        <li>Search for <strong>@OCMTBot</strong></li>
        <li>Tap <strong>Start</strong> or send /start</li>
        <li>You'll get a pairing code - give it to the admin</li>
      </ol>
      <a href="https://t.me/OCMTBot" class="btn" target="_blank">Open Telegram →</a>
    </div>
  </div>
  <div class="modal" id="modal-whatsapp">
    <div class="modal-content">
      <button class="modal-close" onclick="closeModal('whatsapp')">×</button>
      <h2>💬 Connect WhatsApp</h2>
      <ol>
        <li>Contact the admin for the WhatsApp number</li>
        <li>Save the number to your contacts</li>
        <li>Send "Hi" to start</li>
      </ol>
      <p style="color: #888; margin-top: 15px;">Note: WhatsApp requires setup. Contact admin.</p>
    </div>
  </div>
  <div class="modal" id="modal-slack">
    <div class="modal-content">
      <button class="modal-close" onclick="closeModal('slack')">×</button>
      <h2>💼 Connect Slack</h2>
      <ol>
        <li>Ask admin to add OCMT to your workspace</li>
        <li>Find the OCMT app in Slack</li>
        <li>Send a direct message to start</li>
      </ol>
    </div>
  </div>
  <div class="modal" id="modal-gcal">
    <div class="modal-content">
      <button class="modal-close" onclick="closeModal('gcal')">×</button>
      <h2>📅 Connect Google Calendar</h2>
      <ol>
        <li>Click the button below to authorize</li>
        <li>Sign in with your Google account</li>
        <li>Allow OCMT to view your calendar</li>
      </ol>
      <a href="/auth/google?user=${encodeURIComponent(user || "")}&scope=calendar" class="btn">Connect Google Calendar →</a>
    </div>
  </div>
  <div class="modal" id="modal-gmail">
    <div class="modal-content">
      <button class="modal-close" onclick="closeModal('gmail')">×</button>
      <h2>📧 Connect Gmail</h2>
      <ol>
        <li>Click the button below to authorize</li>
        <li>Sign in with your Google account</li>
        <li>Allow OCMT to read your emails</li>
      </ol>
      <a href="/auth/google?user=${encodeURIComponent(user || "")}&scope=gmail" class="btn">Connect Gmail →</a>
    </div>
  </div>
  <script>
    function showModal(id) { document.getElementById('modal-' + id).classList.add('active'); }
    function closeModal(id) { document.getElementById('modal-' + id).classList.remove('active'); }
    document.querySelectorAll('.modal').forEach(m => m.addEventListener('click', e => { if (e.target === m) m.classList.remove('active'); }));
  </script>
</body>
</html>`);
});

// Chat page
app.get("/chat", (req, res) => {
  const { user, name, botName } = req.query;
  const aiName = botName || "your AI";
  const userName = name || "friend";
  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Chat - OCMT</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; height: 100vh; display: flex; flex-direction: column; color: #fff; }
    .header { background: rgba(255,255,255,0.05); padding: 15px 20px; border-bottom: 1px solid rgba(255,255,255,0.1); display: flex; align-items: center; justify-content: space-between; }
    .header h1 { font-size: 1.2rem; }
    .header a { color: #4f46e5; text-decoration: none; }
    .messages { flex: 1; overflow-y: auto; padding: 20px; }
    .message { max-width: 80%; margin-bottom: 15px; padding: 12px 16px; border-radius: 16px; line-height: 1.5; white-space: pre-wrap; }
    .message.user { background: #4f46e5; margin-left: auto; border-bottom-right-radius: 4px; }
    .message.assistant { background: rgba(255,255,255,0.1); border-bottom-left-radius: 4px; }
    .message.system { background: rgba(251, 191, 36, 0.2); text-align: center; max-width: 100%; font-size: 0.9rem; }
    .input-area { padding: 15px 20px; background: rgba(255,255,255,0.05); border-top: 1px solid rgba(255,255,255,0.1); }
    .input-row { display: flex; gap: 10px; max-width: 800px; margin: 0 auto; }
    textarea { flex: 1; padding: 12px 15px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.2); background: rgba(255,255,255,0.1); color: white; font-size: 1rem; resize: none; font-family: inherit; }
    textarea::placeholder { color: #666; }
    button { padding: 12px 25px; border-radius: 12px; border: none; background: #4f46e5; color: white; font-weight: 600; cursor: pointer; }
    button:disabled { opacity: 0.5; }
    .typing { display: none; margin: 10px 20px; color: #888; }
    .typing.active { display: block; }
  </style>
</head>
<body>
  <div class="header">
    <h1>OCMT</h1>
    <div style="display:flex;gap:15px;">
      <a href="/connect?user=${encodeURIComponent(user || "")}&name=${encodeURIComponent(userName)}">⚙️ Settings</a>
      <a href="/">← Home</a>
    </div>
  </div>
  <div class="messages" id="messages">
    <div class="message system">Welcome ${escapeHtml(userName)}! Say hello to meet your new AI assistant.</div>
  </div>
  <div class="typing" id="typing">Thinking...</div>
  <div class="input-area">
    <div class="input-row">
      <textarea id="input" rows="1" placeholder="Type your message..." onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendMessage();}"></textarea>
      <button onclick="sendMessage()" id="sendBtn">Send</button>
    </div>
  </div>
  <script>
    const messagesEl = document.getElementById('messages');
    const input = document.getElementById('input');
    const typing = document.getElementById('typing');
    const sendBtn = document.getElementById('sendBtn');
    const user = ${JSON.stringify(user || "main")};
    const storageKey = 'ocmt_chat_' + user;

    // Load saved messages on page load
    function loadMessages() {
      const saved = localStorage.getItem(storageKey);
      if (saved) {
        try {
          const msgs = JSON.parse(saved);
          msgs.forEach(m => addMessageToDOM(m.text, m.role, false));
        } catch (e) {}
      }
    }

    function saveMessages() {
      const msgs = [];
      messagesEl.querySelectorAll('.message:not(.system)').forEach(el => {
        msgs.push({
          text: el.textContent,
          role: el.classList.contains('user') ? 'user' : 'assistant'
        });
      });
      // Keep last 100 messages
      const toSave = msgs.slice(-100);
      localStorage.setItem(storageKey, JSON.stringify(toSave));
    }

    function addMessageToDOM(text, role, save = true) {
      const div = document.createElement('div');
      div.className = 'message ' + role;
      div.textContent = text;
      messagesEl.appendChild(div);
      messagesEl.scrollTop = messagesEl.scrollHeight;
      if (save) saveMessages();
    }

    function addMessage(text, role) {
      addMessageToDOM(text, role, true);
    }

    async function sendMessage() {
      const text = input.value.trim();
      if (!text) return;
      addMessage(text, 'user');
      input.value = '';
      typing.classList.add('active');
      sendBtn.disabled = true;
      try {
        const res = await fetch('/api/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: text, user: user })
        });
        const data = await res.json();
        addMessage(data.response || 'No response', 'assistant');
      } catch (err) {
        addMessage('Error: ' + err.message, 'system');
      }
      typing.classList.remove('active');
      sendBtn.disabled = false;
      input.focus();
    }

    // Load messages on page load
    loadMessages();
  </script>
</body>
</html>`);
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
app.get("/admin", requireAuth, (req, res) => {
  const agents = getAgentsFromDirectory();
  const connectedCount = agents.filter((a) => a.connections.length > 0).length;

  const agentRows = agents
    .map((a) => {
      const isConnected = a.connections.length > 0;
      const connectionBadges = a.connections
        .map((c) => {
          const icon = c.channel === "telegram" ? "✈️" : c.channel === "web" ? "🌐" : "💬";
          return `<span style="background:rgba(34,197,94,0.2);color:#22c55e;padding:2px 8px;border-radius:10px;font-size:0.75rem;margin-right:5px;">${icon} ${escapeHtml(c.channel)}</span>`;
        })
        .join("");
      const lastActive = a.lastActivity ? new Date(a.lastActivity).toLocaleString() : "Never";
      return `<div style="background:rgba(255,255,255,0.05);padding:15px;border-radius:8px;margin-bottom:10px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <strong>${escapeHtml(a.ownerName || a.id)}</strong>
        <span style="padding:4px 12px;border-radius:20px;font-size:0.8rem;background:${isConnected ? "#22c55e" : "#f59e0b"};color:${isConnected ? "#fff" : "#000"};">${isConnected ? "active" : "pending"}</span>
      </div>
      <div style="color:#666;font-size:0.85rem;margin-bottom:5px;">Agent: ${escapeHtml(a.id)}</div>
      <div style="margin-bottom:5px;">${connectionBadges || '<span style="color:#666;font-size:0.8rem;">No connections</span>'}</div>
      <div style="color:#555;font-size:0.75rem;">Last active: ${escapeHtml(lastActive)}</div>
    </div>`;
    })
    .join("");

  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Admin - OCMT</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); min-height: 100vh; color: #fff; }
    .container { max-width: 800px; margin: 0 auto; padding: 40px 20px; }
    h1 { font-size: 2rem; margin-bottom: 30px; }
    .card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 30px; margin-bottom: 20px; }
    .card h2 { margin-bottom: 20px; }
    input, button { padding: 12px 15px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.2); font-size: 1rem; }
    input { background: rgba(255,255,255,0.1); color: white; margin-right: 10px; }
    button { background: #4f46e5; color: white; border: none; cursor: pointer; }
    .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 30px; }
    .stat { background: rgba(255,255,255,0.05); padding: 20px; border-radius: 12px; text-align: center; }
    .stat-num { font-size: 2rem; font-weight: bold; color: #4f46e5; }
    .stat-label { color: #888; }
    a { color: #4f46e5; text-decoration: none; }
  </style>
</head>
<body>
  <div class="container">
    <a href="/">← Back to signup</a>
    <h1>OCMT Admin</h1>
    <div class="stats">
      <div class="stat"><div class="stat-num">${agents.length}</div><div class="stat-label">Agents</div></div>
      <div class="stat"><div class="stat-num">${connectedCount}</div><div class="stat-label">Connected</div></div>
      <div class="stat"><div class="stat-num">${agents.length - connectedCount}</div><div class="stat-label">Pending</div></div>
    </div>
    <div class="card">
      <h2>Approve Pairing</h2>
      <p style="color:#888;margin-bottom:15px;">Enter the code from Telegram:</p>
      <form action="/admin/approve" method="POST" style="display:flex;gap:10px;">
        <input type="text" name="code" placeholder="Code (e.g. ALPKLRP5)" required style="flex:1;">
        <button type="submit">Approve</button>
      </form>
    </div>
    <div class="card">
      <h2>Agents</h2>
      ${agentRows || '<p style="color:#666;">No agents yet</p>'}
    </div>
  </div>
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
      <a href="/">← Signup</a>
      <a href="/admin">Admin</a>
      <a href="/dev"><strong>Dev</strong></a>
      <a href="/dev/browse">📂 Browse Files</a>
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
    <h1>📂 File Browser</h1>
    <a href="/dev">← Dev Dashboard</a>
    <a href="/admin">Admin</a>
    <a href="/">Home</a>
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

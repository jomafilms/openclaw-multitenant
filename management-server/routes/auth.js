import axios from "axios";
// Authentication routes - login, logout, magic links
import { Router } from "express";
import { users, audit, integrations, meshAuditLogs, MESH_AUDIT_EVENTS } from "../db/index.js";
import { updateAgentContext, AGENT_SERVER_URL, AGENT_SERVER_TOKEN } from "../lib/context.js";
import { decryptGatewayToken, generateEphemeralToken } from "../lib/gateway-tokens.js";
import { loginLimiter, strictAuthLimiter } from "../lib/rate-limit.js";
import { closeUserConnections } from "../lib/ws-proxy.js";
import {
  requireUser,
  generateMagicLink,
  verifyMagicLink,
  setSessionCookie,
  clearSessionCookie,
  logout,
} from "../middleware/auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

const USER_UI_URL = process.env.USER_UI_URL || "http://localhost:5173";
const AGENT_SERVER_HOST = process.env.AGENT_SERVER_HOST || "localhost";
const EMAIL_FROM = process.env.RESEND_FROM || "OCMT <noreply@YOUR_DOMAIN>";

// Will be injected from server.js
let resend = null;
export function setResend(r) {
  resend = r;
}

// Helper: Get effective API key (user's own or business default)
async function getEffectiveApiKey(userId, provider) {
  const userIntegration = await integrations.getDecryptedTokens(userId, provider);
  if (userIntegration?.apiKey) {
    return { key: userIntegration.apiKey, source: "user" };
  }

  if (provider === "anthropic" && process.env.ANTHROPIC_API_KEY) {
    return { key: process.env.ANTHROPIC_API_KEY, source: "business" };
  }
  if (provider === "openai" && process.env.OPENAI_API_KEY) {
    return { key: process.env.OPENAI_API_KEY, source: "business" };
  }

  return null;
}

// Request magic link login
// Rate limited: 10 attempts per 15 minutes per IP to prevent email spam
router.post("/login", loginLimiter, async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !email.includes("@")) {
      return res.status(400).json({ error: "Valid email required" });
    }

    const token = await generateMagicLink(email);
    const verifyUrl = `${USER_UI_URL}/verify?token=${token}`;

    const existingUser = await users.findByEmail(email);
    if (existingUser) {
      await audit.log(existingUser.id, "auth.magic_link_requested", { email }, req.ip);
    }

    // Send magic link email
    if (resend) {
      try {
        await resend.emails.send({
          from: EMAIL_FROM,
          to: email,
          subject: "Sign in to OCMT",
          html: `
            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 500px; margin: 0 auto; padding: 40px 20px;">
              <h1 style="color: #1a1a2e; margin-bottom: 24px;">Sign in to OCMT</h1>
              <p style="color: #666; font-size: 16px; line-height: 1.6;">
                Click the button below to sign in. This link expires in 15 minutes.
              </p>
              <a href="${verifyUrl}" style="display: inline-block; background: #4f46e5; color: white; padding: 14px 28px; border-radius: 8px; text-decoration: none; font-weight: 600; margin: 24px 0;">
                Sign In →
              </a>
              <p style="color: #999; font-size: 14px; margin-top: 32px;">
                If you didn't request this email, you can safely ignore it.
              </p>
            </div>
          `,
        });
        console.log(`Magic link email sent to ${email}`);
      } catch (emailErr) {
        console.error("Failed to send email:", emailErr);
      }
    } else if (process.env.NODE_ENV !== "production") {
      // Only log magic links in development mode for testing
      console.log(`[DEV] Magic link for ${email}: ${verifyUrl}`);
    } else {
      console.warn(`No email service configured - cannot send magic link to ${email}`);
    }

    res.json({ success: true, message: "Check your email for a login link" });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Failed to send login link" });
  }
});

// Verify magic link and create session
// Rate limited: strict auth limit to prevent token brute force
router.get("/verify", strictAuthLimiter, async (req, res) => {
  try {
    const { token } = req.query;

    if (!token) {
      return res.status(400).json({ error: "Token required" });
    }

    const result = await verifyMagicLink(token, req.ip, req.headers["user-agent"]);

    if (!result.success) {
      // Log failed auth attempt to mesh audit
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: result.error,
        details: { method: "magic_link" },
      });
      return res.status(400).json({ error: result.error });
    }

    // Provision container if user doesn't have one
    if (!result.user.container_id) {
      try {
        console.log(`Provisioning container for user ${result.user.id}...`);

        const anthropicKey = await getEffectiveApiKey(result.user.id, "anthropic");
        const openaiKey = await getEffectiveApiKey(result.user.id, "openai");

        const provisionBody = {
          userId: result.user.id,
          userName: result.user.name,
        };

        if (anthropicKey?.key) {
          provisionBody.anthropicApiKey = anthropicKey.key;
        } else if (process.env.ANTHROPIC_SETUP_TOKEN) {
          provisionBody.anthropicSetupToken = process.env.ANTHROPIC_SETUP_TOKEN;
        }

        if (openaiKey?.key) {
          provisionBody.openaiApiKey = openaiKey.key;
        }

        const containerRes = await axios.post(`${AGENT_SERVER_URL}/api/provision`, provisionBody, {
          headers: { "x-auth-token": AGENT_SERVER_TOKEN },
          timeout: 60000,
        });

        if (containerRes.data.containerId) {
          await users.updateContainer(result.user.id, {
            containerId: containerRes.data.containerId,
            containerPort: containerRes.data.port,
          });
          if (containerRes.data.gatewayToken) {
            await users.updateGatewayToken(result.user.id, containerRes.data.gatewayToken);
          }
          console.log(`Container provisioned: ${containerRes.data.containerId}`);

          updateAgentContext(result.user.id).catch((err) => {
            console.error("Failed to initialize agent context:", err.message);
          });
        }
      } catch (containerErr) {
        console.error("Failed to provision container:", containerErr.message);
      }
    } else {
      updateAgentContext(result.user.id).catch((err) => {
        console.error("Failed to refresh agent context:", err.message);
      });
    }

    setSessionCookie(res, result.sessionToken, result.sessionExpiresAt);

    // Log successful auth to mesh audit
    await meshAuditLogs.log({
      eventType: MESH_AUDIT_EVENTS.AUTH_LOGIN,
      actorId: result.user.id,
      ipAddress: req.ip,
      success: true,
      details: { method: "magic_link" },
    });

    const updatedUser = await users.findById(result.user.id);

    // Return raw gateway token for direct container WebSocket connection
    // Note: WebSocket goes directly to container which expects permanent token
    let gateway = null;
    if (updatedUser.container_port && updatedUser.gateway_token) {
      let rawToken;
      try {
        rawToken = decryptGatewayToken(updatedUser.gateway_token);
      } catch {
        // Legacy unencrypted token
        rawToken = updatedUser.gateway_token;
      }
      gateway = {
        host: AGENT_SERVER_HOST,
        port: updatedUser.container_port,
        token: rawToken,
      };
    }

    if (req.accepts("html")) {
      return res.redirect(`${USER_UI_URL}/dashboard`);
    }

    res.json({
      success: true,
      user: {
        id: result.user.id,
        name: result.user.name,
        email: result.user.email,
        status: result.user.status,
      },
      sessionToken: result.sessionToken,
      gateway,
    });
  } catch (err) {
    console.error("Verify error:", err);
    res.status(500).json({ error: "Verification failed" });
  }
});

// Get current user
router.get("/me", requireUser, detectTenant, async (req, res) => {
  let gateway = null;

  if (req.user.containerPort && req.user.gatewayToken) {
    // Return raw token for direct container WebSocket connection
    let rawToken;
    try {
      rawToken = decryptGatewayToken(req.user.gatewayToken);
    } catch {
      // Legacy unencrypted token
      rawToken = req.user.gatewayToken;
    }

    gateway = {
      host: AGENT_SERVER_HOST,
      port: req.user.containerPort,
      token: rawToken,
    };
  }

  res.json({
    user: {
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
      status: req.user.status,
    },
    gateway,
  });
});

// Logout
router.post("/logout", requireUser, detectTenant, async (req, res) => {
  // Log logout to mesh audit
  await meshAuditLogs.log({
    eventType: MESH_AUDIT_EVENTS.AUTH_LOGOUT,
    actorId: req.user.id,
    ipAddress: req.ip,
    success: true,
  });

  // Close all WebSocket connections for this user
  closeUserConnections(req.user.id);

  await logout(req, res);
  res.json({ success: true });
});

export default router;

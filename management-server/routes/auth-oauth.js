import axios from "axios";
import crypto from "crypto";
// OAuth authentication routes - Google, GitHub, and Microsoft OAuth flows for login/signup
import { Router } from "express";
import { users, sessions, audit, meshAuditLogs, MESH_AUDIT_EVENTS } from "../db/index.js";
import { updateAgentContext, AGENT_SERVER_URL, AGENT_SERVER_TOKEN } from "../lib/context.js";
import { generatePermanentToken, encryptGatewayToken } from "../lib/gateway-tokens.js";
import { strictAuthLimiter, loginLimiter } from "../lib/rate-limit.js";
import { getRedisClient, isRedisConnected } from "../lib/redis.js";
import { setSessionCookie } from "../middleware/auth.js";

const router = Router();

const USER_UI_URL = process.env.USER_UI_URL || "http://localhost:5173";
const BASE_URL = process.env.BASE_URL || "http://localhost:3000";
const SESSION_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 days
const AGENT_SERVER_HOST = process.env.AGENT_SERVER_HOST || "localhost";

// Google OAuth configuration
// Support GOOGLE_LOGIN_CLIENT_ID for login-specific credentials,
// falling back to GOOGLE_CLIENT_ID for shared credentials
const GOOGLE_LOGIN_CLIENT_ID = process.env.GOOGLE_LOGIN_CLIENT_ID || process.env.GOOGLE_CLIENT_ID;
const GOOGLE_LOGIN_CLIENT_SECRET =
  process.env.GOOGLE_LOGIN_CLIENT_SECRET || process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI = `${BASE_URL}/api/auth/google/callback`;

// GitHub OAuth configuration
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const GITHUB_REDIRECT_URI = `${BASE_URL}/api/auth/github/callback`;

// Microsoft OAuth configuration
const MICROSOFT_CLIENT_ID = process.env.MICROSOFT_CLIENT_ID;
const MICROSOFT_CLIENT_SECRET = process.env.MICROSOFT_CLIENT_SECRET;
const MICROSOFT_REDIRECT_URI = `${BASE_URL}/api/auth/microsoft/callback`;
const MICROSOFT_TENANT = "common"; // Allows any Microsoft account (personal + work/school)

// Microsoft OAuth endpoints
const MICROSOFT_AUTH_URL = `https://login.microsoftonline.com/${MICROSOFT_TENANT}/oauth2/v2.0/authorize`;
const MICROSOFT_TOKEN_URL = `https://login.microsoftonline.com/${MICROSOFT_TENANT}/oauth2/v2.0/token`;
const MICROSOFT_GRAPH_URL = "https://graph.microsoft.com/v1.0/me";

// OAuth state storage with Redis fallback to in-memory for local development
const STATE_TTL_SECONDS = 600; // 10 minutes
const OAUTH_STATE_PREFIX = "oauth:state:";

// In-memory fallback when Redis is not configured
const memoryOauthStates = new Map();

// Cleanup expired states periodically (only needed for in-memory fallback)
setInterval(() => {
  if (isRedisConnected()) {
    return;
  } // Redis handles expiry via TTL
  const now = Date.now();
  for (const [state, data] of memoryOauthStates.entries()) {
    if (data.expiresAt < now) {
      memoryOauthStates.delete(state);
    }
  }
}, 60 * 1000); // Every minute

/**
 * Store OAuth state data in Redis or memory
 */
async function setOAuthState(state, data) {
  const redis = getRedisClient();
  if (redis && isRedisConnected()) {
    try {
      await redis.setex(`${OAUTH_STATE_PREFIX}${state}`, STATE_TTL_SECONDS, JSON.stringify(data));
      return;
    } catch (err) {
      console.warn("[auth-oauth] Redis setex failed, falling back to memory:", err.message);
    }
  }
  // Fallback to in-memory
  memoryOauthStates.set(state, {
    ...data,
    expiresAt: Date.now() + STATE_TTL_SECONDS * 1000,
  });
}

/**
 * Get and delete OAuth state data (consume the token)
 */
async function getAndDeleteOAuthState(state) {
  const redis = getRedisClient();
  if (redis && isRedisConnected()) {
    try {
      const key = `${OAUTH_STATE_PREFIX}${state}`;
      // Use GETDEL for atomic get-and-delete (Redis 6.2+)
      // Fall back to GET + DEL for older versions
      let dataStr;
      try {
        dataStr = await redis.getdel(key);
      } catch {
        // GETDEL not available, use GET + DEL
        dataStr = await redis.get(key);
        if (dataStr) {
          await redis.del(key);
        }
      }
      if (dataStr) {
        return JSON.parse(dataStr);
      }
      return null;
    } catch (err) {
      console.warn("[auth-oauth] Redis get failed, checking memory fallback:", err.message);
    }
  }
  // Fallback to in-memory
  const data = memoryOauthStates.get(state);
  if (!data) {
    return null;
  }
  memoryOauthStates.delete(state);
  if (Date.now() > data.expiresAt) {
    return null;
  }
  return data;
}

/**
 * Generate a secure state token and store it with metadata
 */
async function generateState(metadata = {}) {
  const state = crypto.randomBytes(32).toString("hex");
  const data = {
    ...metadata,
    createdAt: Date.now(),
  };
  await setOAuthState(state, data);
  return state;
}

/**
 * Verify and consume a state token
 */
async function verifyState(state) {
  return await getAndDeleteOAuthState(state);
}

/**
 * Helper: Get effective API key for container provisioning
 */
async function getEffectiveApiKey(provider) {
  if (provider === "anthropic" && process.env.ANTHROPIC_API_KEY) {
    return { key: process.env.ANTHROPIC_API_KEY, source: "business" };
  }
  if (provider === "openai" && process.env.OPENAI_API_KEY) {
    return { key: process.env.OPENAI_API_KEY, source: "business" };
  }
  return null;
}

/**
 * Helper: Provision container for new user
 */
async function provisionContainerForUser(user) {
  try {
    console.log(`Provisioning container for user ${user.id}...`);

    const anthropicKey = await getEffectiveApiKey("anthropic");
    const openaiKey = await getEffectiveApiKey("openai");

    const provisionBody = {
      userId: user.id,
      userName: user.name,
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
      await users.updateContainer(user.id, {
        containerId: containerRes.data.containerId,
        containerPort: containerRes.data.port,
      });
      if (containerRes.data.gatewayToken) {
        await users.updateGatewayToken(user.id, containerRes.data.gatewayToken);
      }
      console.log(`Container provisioned: ${containerRes.data.containerId}`);

      updateAgentContext(user.id).catch((err) => {
        console.error("Failed to initialize agent context:", err.message);
      });

      return true;
    }
  } catch (containerErr) {
    console.error("Failed to provision container:", containerErr.message);
  }
  return false;
}

/**
 * Helper: Create session and set cookie
 */
async function createSessionForUser(user, req, res) {
  const sessionToken = crypto.randomBytes(32).toString("hex");
  const sessionExpiresAt = new Date(Date.now() + SESSION_MAX_AGE);

  await sessions.create(user.id, sessionToken, sessionExpiresAt, {
    ipAddress: req.ip,
    userAgent: req.headers["user-agent"],
  });

  setSessionCookie(res, sessionToken, sessionExpiresAt);

  return { sessionToken, sessionExpiresAt };
}

// ============================================================
// GOOGLE OAUTH LOGIN
// ============================================================

/**
 * GET /auth/google - Start Google OAuth login flow
 *
 * Query params:
 * - redirect: URL to redirect after login (optional, must be same origin)
 */
router.get("/google", loginLimiter, async (req, res) => {
  if (!GOOGLE_LOGIN_CLIENT_ID) {
    return res.status(503).json({
      error: "Google OAuth not configured",
      code: "OAUTH_NOT_CONFIGURED",
      message: "Google login is not available. Please use magic link or contact support.",
    });
  }

  // Validate redirect URL if provided (must be same origin for security)
  let redirectUrl = null;
  const { redirect } = req.query;
  if (redirect) {
    try {
      const url = new URL(redirect, USER_UI_URL);
      if (url.origin === new URL(USER_UI_URL).origin) {
        redirectUrl = redirect;
      }
    } catch (e) {
      // Invalid URL, ignore
    }
  }

  const state = await generateState({ provider: "google", ip: req.ip, redirectUrl });

  const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  authUrl.searchParams.set("client_id", GOOGLE_LOGIN_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", GOOGLE_REDIRECT_URI);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", "openid email profile");
  authUrl.searchParams.set("access_type", "online"); // No refresh token needed for login
  authUrl.searchParams.set("state", state);
  // Use 'select_account' to let user choose which Google account
  authUrl.searchParams.set("prompt", "select_account");

  res.redirect(authUrl.toString());
});

/**
 * GET /auth/google/callback - Handle Google OAuth callback
 */
router.get("/google/callback", strictAuthLimiter, async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      console.error("Google OAuth error:", error);
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: `Google OAuth error: ${error}`,
        details: { method: "google_oauth" },
      });
      return res.redirect(`${USER_UI_URL}/login?error=${encodeURIComponent(error)}`);
    }

    if (!code || !state) {
      return res.redirect(`${USER_UI_URL}/login?error=missing_params`);
    }

    // Verify state
    const stateData = await verifyState(state);
    if (!stateData || stateData.provider !== "google") {
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: "Invalid OAuth state",
        details: { method: "google_oauth" },
      });
      return res.redirect(`${USER_UI_URL}/login?error=invalid_state`);
    }

    // Exchange code for tokens
    let tokenResponse;
    try {
      tokenResponse = await axios.post(
        "https://oauth2.googleapis.com/token",
        {
          code,
          client_id: GOOGLE_LOGIN_CLIENT_ID,
          client_secret: GOOGLE_LOGIN_CLIENT_SECRET,
          redirect_uri: GOOGLE_REDIRECT_URI,
          grant_type: "authorization_code",
        },
        { timeout: 10000 },
      );
    } catch (tokenErr) {
      console.error("Google token exchange error:", tokenErr.response?.data || tokenErr.message);
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: "Failed to exchange OAuth code for tokens",
        details: { method: "google_oauth" },
      });
      return res.redirect(`${USER_UI_URL}/login?error=token_exchange_failed`);
    }

    const { access_token } = tokenResponse.data;

    // Get user info
    let userInfo;
    try {
      const userInfoResponse = await axios.get("https://www.googleapis.com/oauth2/v2/userinfo", {
        headers: { Authorization: `Bearer ${access_token}` },
        timeout: 10000,
      });
      userInfo = userInfoResponse.data;
    } catch (graphErr) {
      console.error("Google userinfo error:", graphErr.response?.data || graphErr.message);
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: "Failed to get user info from Google",
        details: { method: "google_oauth" },
      });
      return res.redirect(`${USER_UI_URL}/login?error=user_info_failed`);
    }

    const { id: googleId, email, name: displayName } = userInfo;

    if (!email) {
      console.error("Google account has no email:", userInfo);
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: "Google account has no email",
        details: { method: "google_oauth", googleId },
      });
      return res.redirect(`${USER_UI_URL}/login?error=no_email`);
    }

    // Find or create user
    let user = await users.findByEmail(email);
    let isNewUser = false;

    if (!user) {
      // Create new user
      isNewUser = true;
      // Generate and encrypt gateway token for secure storage
      const rawToken = generatePermanentToken();
      const encryptedToken = encryptGatewayToken(rawToken);
      user = await users.create({
        name: displayName || email.split("@")[0],
        email,
        gatewayToken: encryptedToken,
      });

      // Store Google ID in user settings
      await users.updateSettings(user.id, {
        google_id: googleId,
        oauth_provider: "google",
      });

      await audit.log(
        user.id,
        "user.created",
        {
          email,
          method: "google_oauth",
          google_id: googleId,
        },
        req.ip,
      );

      console.log(`New user created via Google OAuth: ${email.split("@")[0]}@***`);
    } else {
      // Link Google account if not already linked
      const settings = await users.getSettings(user.id);
      if (!settings.google_id) {
        await users.updateSettings(user.id, {
          google_id: googleId,
          oauth_provider: settings.oauth_provider || "google",
        });
        await audit.log(user.id, "user.google_linked", { google_id: googleId }, req.ip);
      }
    }

    // Provision container if needed
    if (!user.container_id) {
      await provisionContainerForUser(user);
      user = await users.findById(user.id);
    } else {
      updateAgentContext(user.id).catch((err) => {
        console.error("Failed to refresh agent context:", err.message);
      });
    }

    // Create session
    await createSessionForUser(user, req, res);
    await audit.log(user.id, "user.login", { method: "google_oauth" }, req.ip);

    // Log successful auth
    await meshAuditLogs.log({
      eventType: MESH_AUDIT_EVENTS.AUTH_LOGIN,
      actorId: user.id,
      ipAddress: req.ip,
      success: true,
      details: { method: "google_oauth", isNewUser, google_email: email },
    });

    // Redirect to custom URL, onboarding (for new users), or dashboard
    let redirectTo = stateData.redirectUrl || "/dashboard";
    if (isNewUser) {
      // New users may need onboarding
      redirectTo = "/dashboard"; // or '/onboarding' if you have an onboarding flow
    }
    res.redirect(`${USER_UI_URL}${redirectTo.startsWith("/") ? redirectTo : "/" + redirectTo}`);
  } catch (err) {
    console.error("Google OAuth callback error:", err);
    await meshAuditLogs.log({
      eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
      ipAddress: req.ip,
      success: false,
      errorMessage: err.message,
      details: { method: "google_oauth" },
    });
    res.redirect(`${USER_UI_URL}/login?error=oauth_failed`);
  }
});

// ============================================================
// GITHUB OAUTH LOGIN
// ============================================================

/**
 * GET /auth/github - Start GitHub OAuth login flow
 */
router.get("/github", loginLimiter, async (req, res) => {
  if (!GITHUB_CLIENT_ID) {
    return res.status(503).json({ error: "GitHub OAuth not configured" });
  }

  const state = await generateState({ provider: "github", ip: req.ip });

  const authUrl = new URL("https://github.com/login/oauth/authorize");
  authUrl.searchParams.set("client_id", GITHUB_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", GITHUB_REDIRECT_URI);
  authUrl.searchParams.set("scope", "read:user user:email");
  authUrl.searchParams.set("state", state);

  res.redirect(authUrl.toString());
});

/**
 * GET /auth/github/callback - Handle GitHub OAuth callback
 */
router.get("/github/callback", strictAuthLimiter, async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;

    if (error) {
      console.error("GitHub OAuth error:", error, error_description);
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: `GitHub OAuth error: ${error}`,
        details: { method: "github_oauth" },
      });
      return res.redirect(`${USER_UI_URL}/login?error=${encodeURIComponent(error)}`);
    }

    if (!code || !state) {
      return res.redirect(`${USER_UI_URL}/login?error=missing_params`);
    }

    // Verify state
    const stateData = await verifyState(state);
    if (!stateData || stateData.provider !== "github") {
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: "Invalid OAuth state",
        details: { method: "github_oauth" },
      });
      return res.redirect(`${USER_UI_URL}/login?error=invalid_state`);
    }

    // Exchange code for access token
    let tokenResponse;
    try {
      tokenResponse = await axios.post(
        "https://github.com/login/oauth/access_token",
        {
          client_id: GITHUB_CLIENT_ID,
          client_secret: GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: GITHUB_REDIRECT_URI,
        },
        {
          headers: { Accept: "application/json" },
        },
      );
    } catch (tokenErr) {
      console.error("GitHub token exchange error:", tokenErr.response?.data || tokenErr.message);
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: "Failed to exchange OAuth code for tokens",
        details: { method: "github_oauth" },
      });
      return res.redirect(`${USER_UI_URL}/login?error=token_exchange_failed`);
    }

    const {
      access_token,
      error: tokenError,
      error_description: tokenErrorDesc,
    } = tokenResponse.data;

    if (tokenError || !access_token) {
      console.error("GitHub token exchange error:", tokenError, tokenErrorDesc);
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: `GitHub token error: ${tokenError || "no access_token"}`,
        details: { method: "github_oauth" },
      });
      return res.redirect(`${USER_UI_URL}/login?error=token_exchange_failed`);
    }

    // Get user info from GitHub
    let userInfo;
    try {
      const userResponse = await axios.get("https://api.github.com/user", {
        headers: {
          Authorization: `Bearer ${access_token}`,
          Accept: "application/vnd.github+json",
          "User-Agent": "OCMT-OAuth",
        },
      });
      userInfo = userResponse.data;
    } catch (apiErr) {
      console.error("GitHub user API error:", apiErr.response?.data || apiErr.message);
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: "Failed to get user info from GitHub",
        details: { method: "github_oauth" },
      });
      return res.redirect(`${USER_UI_URL}/login?error=user_info_failed`);
    }

    const { id: githubId, login: githubLogin, name: githubName } = userInfo;

    // Get user's primary email
    // GitHub may not return email directly if user has it set to private
    let email = userInfo.email;

    if (!email) {
      // Fetch from /user/emails endpoint
      try {
        const emailsResponse = await axios.get("https://api.github.com/user/emails", {
          headers: {
            Authorization: `Bearer ${access_token}`,
            Accept: "application/vnd.github+json",
            "User-Agent": "OCMT-OAuth",
          },
        });

        // Find primary email, or first verified email, or any email
        const emails = emailsResponse.data;
        const primaryEmail = emails.find((e) => e.primary && e.verified);
        const verifiedEmail = emails.find((e) => e.verified);
        const anyEmail = emails[0];

        email = (primaryEmail || verifiedEmail || anyEmail)?.email;
      } catch (emailErr) {
        console.error("Failed to fetch GitHub emails:", emailErr.message);
      }
    }

    if (!email) {
      console.error("GitHub OAuth: No email available for user", githubLogin);
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: "No email available from GitHub",
        details: { method: "github_oauth", githubLogin },
      });
      return res.redirect(`${USER_UI_URL}/login?error=no_email`);
    }

    // Find or create user
    let user = await users.findByEmail(email);
    let isNewUser = false;

    if (!user) {
      // Create new user
      isNewUser = true;
      // Generate and encrypt gateway token for secure storage
      const rawToken = generatePermanentToken();
      const encryptedToken = encryptGatewayToken(rawToken);
      user = await users.create({
        name: githubName || githubLogin,
        email,
        gatewayToken: encryptedToken,
      });

      // Store GitHub ID in user settings
      await users.updateSettings(user.id, {
        github_id: githubId,
        github_login: githubLogin,
        oauth_provider: "github",
      });

      await audit.log(
        user.id,
        "user.created",
        {
          email,
          method: "github_oauth",
          github_id: githubId,
          github_login: githubLogin,
        },
        req.ip,
      );

      console.log(`New user created via GitHub OAuth: ${email.split("@")[0]}@*** (${githubLogin})`);
    } else {
      // Link GitHub account if not already linked
      const settings = await users.getSettings(user.id);
      if (!settings.github_id) {
        await users.updateSettings(user.id, {
          github_id: githubId,
          github_login: githubLogin,
          oauth_provider: settings.oauth_provider || "github",
        });
        await audit.log(
          user.id,
          "user.github_linked",
          {
            github_id: githubId,
            github_login: githubLogin,
          },
          req.ip,
        );
      }
    }

    // Provision container if needed
    if (!user.container_id) {
      await provisionContainerForUser(user);
      user = await users.findById(user.id);
    } else {
      updateAgentContext(user.id).catch((err) => {
        console.error("Failed to refresh agent context:", err.message);
      });
    }

    // Create session
    await createSessionForUser(user, req, res);
    await audit.log(user.id, "user.login", { method: "github_oauth" }, req.ip);

    // Log successful auth
    await meshAuditLogs.log({
      eventType: MESH_AUDIT_EVENTS.AUTH_LOGIN,
      actorId: user.id,
      ipAddress: req.ip,
      success: true,
      details: { method: "github_oauth", githubId, githubLogin, isNewUser },
    });

    res.redirect(`${USER_UI_URL}/dashboard`);
  } catch (err) {
    console.error("GitHub OAuth callback error:", err);
    await meshAuditLogs.log({
      eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
      ipAddress: req.ip,
      success: false,
      errorMessage: err.message,
      details: { method: "github_oauth" },
    });
    res.redirect(`${USER_UI_URL}/login?error=oauth_failed`);
  }
});

// ============================================================
// MICROSOFT OAUTH
// ============================================================

/**
 * GET /auth/microsoft - Start Microsoft OAuth flow
 * Generates state token and redirects to Microsoft login
 */
router.get("/microsoft", loginLimiter, async (req, res) => {
  if (!MICROSOFT_CLIENT_ID) {
    return res.status(503).json({ error: "Microsoft OAuth not configured" });
  }

  const state = await generateState({ provider: "microsoft", ip: req.ip });

  // Build Microsoft OAuth authorization URL
  const authUrl = new URL(MICROSOFT_AUTH_URL);
  authUrl.searchParams.set("client_id", MICROSOFT_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", MICROSOFT_REDIRECT_URI);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", "openid email profile User.Read");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("response_mode", "query");

  res.redirect(authUrl.toString());
});

/**
 * GET /auth/microsoft/callback - Handle Microsoft OAuth callback
 * Exchanges code for tokens, gets user info, creates/links account
 */
router.get("/microsoft/callback", strictAuthLimiter, async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;

    // Handle OAuth errors from Microsoft
    if (error) {
      console.error("Microsoft OAuth error:", error, error_description);
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: `Microsoft OAuth error: ${error}`,
        details: { method: "microsoft_oauth", error, error_description },
      });
      return res.redirect(
        `${USER_UI_URL}/login?error=${encodeURIComponent(error_description || error)}`,
      );
    }

    // Verify required parameters
    if (!code || !state) {
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: "Missing OAuth parameters",
        details: { method: "microsoft_oauth" },
      });
      return res.redirect(`${USER_UI_URL}/login?error=missing_params`);
    }

    // Verify state token (CSRF protection)
    const stateData = await verifyState(state);
    if (!stateData || stateData.provider !== "microsoft") {
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: "Invalid or expired OAuth state",
        details: { method: "microsoft_oauth" },
      });
      return res.redirect(`${USER_UI_URL}/login?error=invalid_state`);
    }

    // Exchange authorization code for tokens
    let tokenResponse;
    try {
      tokenResponse = await axios.post(
        MICROSOFT_TOKEN_URL,
        new URLSearchParams({
          client_id: MICROSOFT_CLIENT_ID,
          client_secret: MICROSOFT_CLIENT_SECRET,
          code,
          redirect_uri: MICROSOFT_REDIRECT_URI,
          grant_type: "authorization_code",
        }),
        {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
        },
      );
    } catch (tokenErr) {
      console.error("Microsoft token exchange error:", tokenErr.response?.data || tokenErr.message);
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: "Failed to exchange OAuth code for tokens",
        details: { method: "microsoft_oauth" },
      });
      return res.redirect(`${USER_UI_URL}/login?error=token_exchange_failed`);
    }

    const { access_token } = tokenResponse.data;

    // Get user info from Microsoft Graph API
    let userInfo;
    try {
      const graphResponse = await axios.get(MICROSOFT_GRAPH_URL, {
        headers: {
          Authorization: `Bearer ${access_token}`,
        },
      });
      userInfo = graphResponse.data;
    } catch (graphErr) {
      console.error("Microsoft Graph API error:", graphErr.response?.data || graphErr.message);
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: "Failed to get user info from Microsoft",
        details: { method: "microsoft_oauth" },
      });
      return res.redirect(`${USER_UI_URL}/login?error=user_info_failed`);
    }

    // Microsoft Graph returns: id, displayName, mail, userPrincipalName
    const microsoftId = userInfo.id;
    const email = userInfo.mail || userInfo.userPrincipalName;
    const displayName = userInfo.displayName || email?.split("@")[0] || "User";

    if (!email) {
      console.error("Microsoft account has no email:", userInfo);
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: "Microsoft account has no email",
        details: { method: "microsoft_oauth", microsoftId },
      });
      return res.redirect(`${USER_UI_URL}/login?error=no_email`);
    }

    // Find existing user by email
    let user = await users.findByEmail(email);
    let isNewUser = false;

    if (!user) {
      // Create new user with Microsoft ID
      isNewUser = true;
      // Generate and encrypt gateway token for secure storage
      const rawToken = generatePermanentToken();
      const encryptedToken = encryptGatewayToken(rawToken);
      user = await users.create({
        name: displayName,
        email: email,
        gatewayToken: encryptedToken,
      });

      // Store Microsoft ID in user settings for future logins
      await users.updateSettings(user.id, {
        microsoft_id: microsoftId,
        oauth_provider: "microsoft",
      });

      await audit.log(
        user.id,
        "user.created",
        {
          email,
          method: "microsoft_oauth",
          microsoft_id: microsoftId,
        },
        req.ip,
      );

      console.log(`New user created via Microsoft OAuth: ${email.split("@")[0]}@***`);
    } else {
      // Existing user - link Microsoft account if not already linked
      const settings = await users.getSettings(user.id);
      if (!settings.microsoft_id) {
        await users.updateSettings(user.id, {
          microsoft_id: microsoftId,
          oauth_provider: settings.oauth_provider || "microsoft",
        });
        await audit.log(
          user.id,
          "user.microsoft_linked",
          {
            microsoft_id: microsoftId,
          },
          req.ip,
        );
      }
    }

    // Provision container if user doesn't have one
    if (!user.container_id) {
      await provisionContainerForUser(user);
      // Refresh user to get updated container info
      user = await users.findById(user.id);
    } else {
      // Update agent context for existing users
      updateAgentContext(user.id).catch((err) => {
        console.error("Failed to refresh agent context:", err.message);
      });
    }

    // Create session
    await createSessionForUser(user, req, res);
    await audit.log(user.id, "user.login", { method: "microsoft_oauth" }, req.ip);

    // Log successful auth to mesh audit
    await meshAuditLogs.log({
      eventType: MESH_AUDIT_EVENTS.AUTH_LOGIN,
      actorId: user.id,
      ipAddress: req.ip,
      success: true,
      details: { method: "microsoft_oauth", isNewUser },
    });

    // Redirect to dashboard
    res.redirect(`${USER_UI_URL}/dashboard`);
  } catch (err) {
    console.error("Microsoft OAuth callback error:", err);
    await meshAuditLogs.log({
      eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
      ipAddress: req.ip,
      success: false,
      errorMessage: err.message,
      details: { method: "microsoft_oauth" },
    });
    res.redirect(`${USER_UI_URL}/login?error=oauth_failed`);
  }
});

// ============================================================
// OAUTH PROVIDERS STATUS
// ============================================================

/**
 * GET /auth/providers - List available OAuth providers
 * Returns list of configured OAuth providers for the login page
 */
router.get("/providers", (req, res) => {
  const providers = [];

  if (GOOGLE_LOGIN_CLIENT_ID) {
    providers.push({
      id: "google",
      name: "Google",
      enabled: true,
      loginUrl: `${BASE_URL}/api/auth/google`,
    });
  }

  if (GITHUB_CLIENT_ID) {
    providers.push({
      id: "github",
      name: "GitHub",
      enabled: true,
      loginUrl: `${BASE_URL}/api/auth/github`,
    });
  }

  if (MICROSOFT_CLIENT_ID) {
    providers.push({
      id: "microsoft",
      name: "Microsoft",
      enabled: true,
      loginUrl: `${BASE_URL}/api/auth/microsoft`,
    });
  }

  res.json({ providers });
});

export default router;

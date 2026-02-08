// Self-service onboarding routes
// Provides a streamlined flow for new users to set up their organization
import axios from "axios";
import crypto from "crypto";
import { Router } from "express";
import { z } from "zod";
import {
  users,
  audit,
  tenants,
  tenantMemberships,
  subscriptions,
  groupInvites,
  integrations,
} from "../db/index.js";
import { updateAgentContext, AGENT_SERVER_URL, AGENT_SERVER_TOKEN } from "../lib/context.js";
import { sendGroupInviteEmail } from "../lib/email.js";
import { validate, emailSchema, slugSchema, nonEmptyStringSchema } from "../lib/schemas.js";
import { requireUser } from "../middleware/auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

const EMAIL_FROM = process.env.RESEND_FROM || "OCMT <noreply@YOUR_DOMAIN>";
const USER_UI_URL = process.env.USER_UI_URL || "http://localhost:5173";

// Will be injected from server.js
let resend = null;
export function setResend(r) {
  resend = r;
}

// ============================================================
// SCHEMAS
// ============================================================

/**
 * Slug validation - lowercase, alphanumeric, hyphens, 3-50 chars
 */
const onboardingSlugSchema = z
  .string()
  .min(3, "Slug must be at least 3 characters")
  .max(50, "Slug must be less than 50 characters")
  .regex(
    /^[a-z][a-z0-9-]*[a-z0-9]$/,
    "Slug must start with a letter, end with a letter or number, and contain only lowercase letters, numbers, and hyphens",
  )
  .regex(/^(?!.*--)/, "Slug cannot contain consecutive hyphens");

const createGroupSchema = z.object({
  name: nonEmptyStringSchema(100),
  slug: onboardingSlugSchema,
});

const inviteTeamSchema = z.object({
  emails: z
    .array(emailSchema)
    .min(1, "At least one email required")
    .max(20, "Maximum 20 invites at once"),
});

const configureAgentSchema = z.object({
  name: nonEmptyStringSchema(100).optional(),
  model: z
    .enum(["claude-3-5-sonnet", "claude-3-5-haiku", "claude-3-opus", "gpt-4", "gpt-4-turbo"])
    .optional(),
  systemPrompt: z.string().max(10000).optional(),
});

// In-memory onboarding sessions (could be moved to Redis for production)
const onboardingSessions = new Map();
const ONBOARDING_SESSION_TTL = 60 * 60 * 1000; // 1 hour

// ============================================================
// HELPER FUNCTIONS
// ============================================================

/**
 * Create an onboarding session
 */
function createOnboardingSession(userId) {
  const sessionId = crypto.randomBytes(32).toString("hex");
  const session = {
    id: sessionId,
    userId,
    steps: {
      org: { completed: false, data: null },
      invite: { completed: false, data: null },
      agent: { completed: false, data: null },
    },
    createdAt: Date.now(),
    expiresAt: Date.now() + ONBOARDING_SESSION_TTL,
  };
  onboardingSessions.set(sessionId, session);
  return session;
}

/**
 * Get onboarding session
 */
function getOnboardingSession(sessionId, userId) {
  const session = onboardingSessions.get(sessionId);
  if (!session) {
    return null;
  }
  if (session.userId !== userId) {
    return null;
  }
  if (session.expiresAt < Date.now()) {
    onboardingSessions.delete(sessionId);
    return null;
  }
  return session;
}

/**
 * Update onboarding session
 */
function updateOnboardingSession(sessionId, step, data) {
  const session = onboardingSessions.get(sessionId);
  if (!session) {
    return null;
  }
  session.steps[step] = { completed: true, data };
  return session;
}

/**
 * Clean up expired sessions periodically
 */
setInterval(
  () => {
    const now = Date.now();
    for (const [sessionId, session] of onboardingSessions) {
      if (session.expiresAt < now) {
        onboardingSessions.delete(sessionId);
      }
    }
  },
  5 * 60 * 1000,
); // Every 5 minutes

/**
 * Get effective API key (user's own or business default)
 */
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

// ============================================================
// ROUTES
// ============================================================

/**
 * POST /api/onboarding/start
 * Initialize a new onboarding session
 */
router.post("/start", requireUser, detectTenant, async (req, res) => {
  try {
    // Check if user already has a tenant
    const existingTenant = await tenantMemberships.getTenantForUser(req.user.id);

    const session = createOnboardingSession(req.user.id);

    await audit.log(
      req.user.id,
      "onboarding.started",
      { sessionId: session.id, hasTenant: !!existingTenant },
      req.ip,
    );

    res.json({
      success: true,
      sessionId: session.id,
      expiresAt: new Date(session.expiresAt).toISOString(),
      existingTenant: existingTenant
        ? {
            id: existingTenant.id,
            name: existingTenant.name,
            slug: existingTenant.slug,
          }
        : null,
    });
  } catch (err) {
    console.error("Onboarding start error:", err);
    res.status(500).json({ error: "Failed to start onboarding" });
  }
});

/**
 * POST /api/onboarding/org
 * Create the group (tenant)
 */
router.post(
  "/org",
  requireUser,
  detectTenant,
  validate({ body: createGroupSchema }),
  async (req, res) => {
    try {
      const { name, slug } = req.validatedBody;
      const sessionId = req.headers["x-onboarding-session"];

      // Check if user already has a tenant
      const existingTenant = await tenantMemberships.getTenantForUser(req.user.id);
      if (existingTenant) {
        return res.status(400).json({
          error: "You already belong to an organization",
          tenant: {
            id: existingTenant.id,
            name: existingTenant.name,
            slug: existingTenant.slug,
          },
        });
      }

      // Validate slug uniqueness
      const existingSlug = await tenants.findBySlug(slug.toLowerCase());
      if (existingSlug) {
        return res.status(409).json({
          error: "This slug is already taken",
          code: "SLUG_TAKEN",
          suggestion: `${slug}-${Math.floor(Math.random() * 1000)}`,
        });
      }

      // Create the tenant
      const tenant = await tenants.create(name, slug.toLowerCase(), req.user.id, {
        onboarding: { completedAt: null },
      });

      // Add user to tenant
      await tenantMemberships.addMember(tenant.id, req.user.id);

      // Create free subscription
      const subscription = await subscriptions.create(tenant.id, "free");

      // Update onboarding session if provided
      if (sessionId) {
        updateOnboardingSession(sessionId, "org", { tenantId: tenant.id });
      }

      await audit.log(
        req.user.id,
        "onboarding.org.created",
        {
          tenantId: tenant.id,
          name,
          slug: tenant.slug,
          subscriptionId: subscription.id,
        },
        req.ip,
      );

      res.json({
        success: true,
        tenant: {
          id: tenant.id,
          name: tenant.name,
          slug: tenant.slug,
          status: tenant.status,
          createdAt: tenant.created_at,
        },
        subscription: {
          id: subscription.id,
          plan: subscription.plan,
          status: subscription.status,
        },
      });
    } catch (err) {
      console.error("Onboarding org error:", err);
      res.status(500).json({ error: "Failed to create organization" });
    }
  },
);

/**
 * POST /api/onboarding/invite
 * Invite team members to the new organization
 */
router.post(
  "/invite",
  requireUser,
  detectTenant,
  validate({ body: inviteTeamSchema }),
  async (req, res) => {
    try {
      const { emails } = req.validatedBody;
      const sessionId = req.headers["x-onboarding-session"];

      // Get user's tenant
      const tenant = await tenantMemberships.getTenantForUser(req.user.id);
      if (!tenant) {
        return res.status(400).json({
          error: "You must create an organization first",
          code: "NO_ORG",
        });
      }

      // Check if user is the owner
      const isOwner = await tenantMemberships.isOwner(tenant.id, req.user.id);
      if (!isOwner) {
        return res.status(403).json({
          error: "Only the organization owner can invite members during onboarding",
        });
      }

      const results = [];
      const successfulInvites = [];

      for (const email of emails) {
        const normalizedEmail = email.toLowerCase().trim();

        // Skip if it's the current user's email
        if (normalizedEmail === req.user.email.toLowerCase()) {
          results.push({
            email: normalizedEmail,
            status: "skipped",
            reason: "Cannot invite yourself",
          });
          continue;
        }

        try {
          // Check if user exists and is already a member
          const existingUser = await users.findByEmail(normalizedEmail);
          if (existingUser) {
            const isMember = await tenantMemberships.isMember(tenant.id, existingUser.id);
            if (isMember) {
              results.push({
                email: normalizedEmail,
                status: "skipped",
                reason: "Already a member",
              });
              continue;
            }
          }

          // Create invite using the group invites system (tenant as group)
          // For now, we create a simple pending invite record
          const token = crypto.randomBytes(32).toString("hex");
          const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

          // Store invite in tenant settings or a dedicated table
          // Using a lightweight approach for onboarding invites
          const invite = {
            id: crypto.randomUUID(),
            tenantId: tenant.id,
            inviterId: req.user.id,
            inviteeEmail: normalizedEmail,
            inviteeId: existingUser?.id || null,
            role: "member",
            token,
            expiresAt: expiresAt.toISOString(),
            status: "pending",
            createdAt: new Date().toISOString(),
          };

          // Send invite email
          const emailSent = await sendTenantInviteEmail({
            to: normalizedEmail,
            tenantName: tenant.name,
            inviterName: req.user.name || req.user.email,
            inviteToken: token,
          });

          results.push({
            email: normalizedEmail,
            status: emailSent ? "sent" : "pending",
            inviteId: invite.id,
          });

          if (emailSent) {
            successfulInvites.push(normalizedEmail);
          }

          await audit.log(
            req.user.id,
            "onboarding.invite.sent",
            {
              tenantId: tenant.id,
              inviteeEmail: normalizedEmail,
              emailSent,
            },
            req.ip,
          );
        } catch (inviteErr) {
          console.error(`Failed to invite ${normalizedEmail}:`, inviteErr);
          results.push({
            email: normalizedEmail,
            status: "failed",
            reason: "Failed to send invite",
          });
        }
      }

      // Update onboarding session if provided
      if (sessionId) {
        updateOnboardingSession(sessionId, "invite", {
          invitesSent: successfulInvites.length,
          invitedEmails: successfulInvites,
        });
      }

      res.json({
        success: true,
        results,
        summary: {
          total: emails.length,
          sent: results.filter((r) => r.status === "sent").length,
          skipped: results.filter((r) => r.status === "skipped").length,
          failed: results.filter((r) => r.status === "failed").length,
        },
      });
    } catch (err) {
      console.error("Onboarding invite error:", err);
      res.status(500).json({ error: "Failed to send invites" });
    }
  },
);

/**
 * Helper: Send tenant invite email
 */
async function sendTenantInviteEmail({ to, tenantName, inviterName, inviteToken }) {
  if (!resend) {
    console.warn(`[onboarding] No email service configured - cannot send invite to ${to}`);
    return false;
  }

  const inviteUrl = `${USER_UI_URL}/invite?token=${inviteToken}&type=tenant`;

  try {
    await resend.emails.send({
      from: EMAIL_FROM,
      to,
      subject: `You've been invited to join ${tenantName} on OCMT`,
      html: `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 500px; margin: 0 auto; padding: 40px 20px;">
          <h1 style="color: #1a1a2e; margin-bottom: 24px;">You're invited to ${escapeHtml(tenantName)}</h1>
          <p style="color: #666; font-size: 16px; line-height: 1.6;">
            ${escapeHtml(inviterName)} has invited you to join <strong>${escapeHtml(tenantName)}</strong> on OCMT.
          </p>
          <p style="color: #666; font-size: 16px; line-height: 1.6;">
            OCMT helps teams work together with AI-powered agents. Click below to accept the invitation and get started:
          </p>
          <a href="${inviteUrl}" style="display: inline-block; background: #6366f1; color: white; padding: 14px 28px; text-decoration: none; border-radius: 8px; font-weight: 600; margin: 16px 0;">
            Accept Invitation
          </a>
          <p style="color: #999; font-size: 14px; margin-top: 32px;">
            Or copy this link: ${inviteUrl}
          </p>
          <p style="color: #999; font-size: 14px;">
            This invitation expires in 7 days. If you didn't expect this email, you can safely ignore it.
          </p>
        </div>
      `,
    });
    console.log(`[onboarding] Tenant invite sent to ${to} for ${tenantName}`);
    return true;
  } catch (err) {
    console.error(`[onboarding] Failed to send invite email to ${to}:`, err.message);
    return false;
  }
}

/**
 * Escape HTML entities for safe email content
 */
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

/**
 * POST /api/onboarding/agent
 * Configure and provision the first agent
 */
router.post(
  "/agent",
  requireUser,
  detectTenant,
  validate({ body: configureAgentSchema }),
  async (req, res) => {
    try {
      const { name, model, systemPrompt } = req.validatedBody || {};
      const sessionId = req.headers["x-onboarding-session"];

      // Get user's tenant
      const tenant = await tenantMemberships.getTenantForUser(req.user.id);
      if (!tenant) {
        return res.status(400).json({
          error: "You must create an organization first",
          code: "NO_ORG",
        });
      }

      // Check if user already has a container
      const user = await users.findById(req.user.id);
      if (user.container_id) {
        // Container already exists, just update config if provided
        if (name || model || systemPrompt) {
          // Could update agent config here
          await audit.log(
            req.user.id,
            "onboarding.agent.configured",
            { tenantId: tenant.id, hasExisting: true, name, model },
            req.ip,
          );
        }

        if (sessionId) {
          updateOnboardingSession(sessionId, "agent", {
            containerId: user.container_id,
            port: user.container_port,
            existing: true,
          });
        }

        return res.json({
          success: true,
          agent: {
            containerId: user.container_id,
            port: user.container_port,
            status: "active",
            existing: true,
          },
        });
      }

      // Provision new container
      console.log(`[onboarding] Provisioning container for user ${req.user.id}...`);

      const anthropicKey = await getEffectiveApiKey(req.user.id, "anthropic");
      const openaiKey = await getEffectiveApiKey(req.user.id, "openai");

      const provisionBody = {
        userId: req.user.id,
        userName: user.name || name || "Agent",
      };

      if (anthropicKey?.key) {
        provisionBody.anthropicApiKey = anthropicKey.key;
      } else if (process.env.ANTHROPIC_SETUP_TOKEN) {
        provisionBody.anthropicSetupToken = process.env.ANTHROPIC_SETUP_TOKEN;
      }

      if (openaiKey?.key) {
        provisionBody.openaiApiKey = openaiKey.key;
      }

      try {
        const containerRes = await axios.post(`${AGENT_SERVER_URL}/api/provision`, provisionBody, {
          headers: { "x-auth-token": AGENT_SERVER_TOKEN },
          timeout: 60000,
        });

        if (containerRes.data.containerId) {
          await users.updateContainer(req.user.id, {
            containerId: containerRes.data.containerId,
            containerPort: containerRes.data.port,
          });

          if (containerRes.data.gatewayToken) {
            await users.updateGatewayToken(req.user.id, containerRes.data.gatewayToken);
          }

          console.log(`[onboarding] Container provisioned: ${containerRes.data.containerId}`);

          // Initialize agent context
          updateAgentContext(req.user.id).catch((err) => {
            console.error("Failed to initialize agent context:", err.message);
          });

          if (sessionId) {
            updateOnboardingSession(sessionId, "agent", {
              containerId: containerRes.data.containerId,
              port: containerRes.data.port,
              existing: false,
            });
          }

          await audit.log(
            req.user.id,
            "onboarding.agent.provisioned",
            {
              tenantId: tenant.id,
              containerId: containerRes.data.containerId,
              port: containerRes.data.port,
            },
            req.ip,
          );

          res.json({
            success: true,
            agent: {
              containerId: containerRes.data.containerId,
              port: containerRes.data.port,
              status: "provisioned",
              existing: false,
            },
          });
        } else {
          throw new Error("No container ID returned from provisioning");
        }
      } catch (provisionErr) {
        console.error("Container provisioning failed:", provisionErr.message);
        res.status(503).json({
          error: "Failed to provision agent container",
          message: "Please try again or contact support",
        });
      }
    } catch (err) {
      console.error("Onboarding agent error:", err);
      res.status(500).json({ error: "Failed to configure agent" });
    }
  },
);

/**
 * POST /api/onboarding/complete
 * Mark onboarding as complete
 */
router.post("/complete", requireUser, detectTenant, async (req, res) => {
  try {
    const sessionId = req.headers["x-onboarding-session"];

    // Get user's tenant
    const tenant = await tenantMemberships.getTenantForUser(req.user.id);
    if (!tenant) {
      return res.status(400).json({
        error: "You must create an organization first",
        code: "NO_ORG",
      });
    }

    // Update tenant settings to mark onboarding complete
    await tenants.updateSettings(tenant.id, {
      onboarding: {
        completedAt: new Date().toISOString(),
        completedBy: req.user.id,
      },
    });

    // Update user settings to mark personal onboarding complete
    await users.updateSettings(req.user.id, {
      onboarding_completed: true,
      onboarding_completed_at: new Date().toISOString(),
    });

    // Clean up onboarding session
    if (sessionId) {
      onboardingSessions.delete(sessionId);
    }

    // Send welcome email
    await sendWelcomeEmail(req.user.email, req.user.name, tenant.name);

    await audit.log(req.user.id, "onboarding.completed", { tenantId: tenant.id }, req.ip);

    res.json({
      success: true,
      message: "Onboarding complete! Welcome to OCMT.",
      nextSteps: [
        {
          title: "Explore your dashboard",
          url: "/dashboard",
          description: "See an overview of your organization",
        },
        {
          title: "Connect integrations",
          url: "/settings/integrations",
          description: "Connect Google, GitHub, and other services",
        },
        {
          title: "Start chatting with your agent",
          url: "/chat",
          description: "Your AI agent is ready to help",
        },
      ],
    });
  } catch (err) {
    console.error("Onboarding complete error:", err);
    res.status(500).json({ error: "Failed to complete onboarding" });
  }
});

/**
 * Helper: Send welcome email
 */
async function sendWelcomeEmail(email, userName, tenantName) {
  if (!resend) {
    console.warn(
      `[onboarding] No email service configured - cannot send welcome email to ${email}`,
    );
    return false;
  }

  try {
    await resend.emails.send({
      from: EMAIL_FROM,
      to: email,
      subject: `Welcome to OCMT!`,
      html: `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 500px; margin: 0 auto; padding: 40px 20px;">
          <h1 style="color: #1a1a2e; margin-bottom: 24px;">Welcome to OCMT!</h1>
          <p style="color: #666; font-size: 16px; line-height: 1.6;">
            Hi ${escapeHtml(userName || "there")},
          </p>
          <p style="color: #666; font-size: 16px; line-height: 1.6;">
            Congratulations on setting up <strong>${escapeHtml(tenantName)}</strong>! Your organization is ready to go.
          </p>
          <h2 style="color: #1a1a2e; font-size: 18px; margin-top: 32px;">Here's what you can do next:</h2>
          <ul style="color: #666; font-size: 16px; line-height: 1.8;">
            <li><strong>Chat with your agent</strong> - Start a conversation and let AI help you get things done</li>
            <li><strong>Connect integrations</strong> - Link Google, GitHub, and other services</li>
            <li><strong>Invite your team</strong> - Collaborate with colleagues</li>
            <li><strong>Explore settings</strong> - Customize your experience</li>
          </ul>
          <a href="${USER_UI_URL}/dashboard" style="display: inline-block; background: #6366f1; color: white; padding: 14px 28px; text-decoration: none; border-radius: 8px; font-weight: 600; margin: 24px 0;">
            Go to Dashboard
          </a>
          <p style="color: #999; font-size: 14px; margin-top: 32px;">
            Questions? Reply to this email or visit our documentation.
          </p>
        </div>
      `,
    });
    console.log(`[onboarding] Welcome email sent to ${email}`);
    return true;
  } catch (err) {
    console.error(`[onboarding] Failed to send welcome email to ${email}:`, err.message);
    return false;
  }
}

/**
 * GET /api/onboarding/status
 * Get current onboarding progress
 */
router.get("/status", requireUser, detectTenant, async (req, res) => {
  try {
    const sessionId = req.headers["x-onboarding-session"];
    const user = await users.findById(req.user.id);
    const userSettings = await users.getSettings(req.user.id);

    // Check if onboarding is already complete
    if (userSettings?.onboarding_completed) {
      return res.json({
        completed: true,
        completedAt: userSettings.onboarding_completed_at,
        steps: {
          org: { completed: true, required: true },
          invite: { completed: true, required: false },
          agent: { completed: true, required: true },
        },
        nextStep: null,
      });
    }

    // Get tenant info
    const tenant = await tenantMemberships.getTenantForUser(req.user.id);

    // Determine step completion status
    const steps = {
      org: {
        completed: !!tenant,
        required: true,
        data: tenant ? { id: tenant.id, name: tenant.name, slug: tenant.slug } : null,
      },
      invite: {
        completed: false, // Optional step
        required: false,
        skippable: true,
      },
      agent: {
        completed: !!user.container_id,
        required: true,
        data: user.container_id
          ? { containerId: user.container_id, port: user.container_port }
          : null,
      },
    };

    // Get onboarding session if provided
    let session = null;
    if (sessionId) {
      session = getOnboardingSession(sessionId, req.user.id);
      if (session) {
        // Merge session data with step status
        if (session.steps.invite.completed) {
          steps.invite.completed = true;
          steps.invite.data = session.steps.invite.data;
        }
      }
    }

    // Determine next required step
    let nextStep = null;
    if (!steps.org.completed) {
      nextStep = "org";
    } else if (!steps.agent.completed) {
      nextStep = "agent";
    }

    res.json({
      completed: !nextStep,
      steps,
      nextStep,
      session: session
        ? {
            id: session.id,
            expiresAt: new Date(session.expiresAt).toISOString(),
          }
        : null,
    });
  } catch (err) {
    console.error("Onboarding status error:", err);
    res.status(500).json({ error: "Failed to get onboarding status" });
  }
});

/**
 * GET /api/onboarding/check-slug
 * Check if a slug is available
 */
router.get("/check-slug", requireUser, detectTenant, async (req, res) => {
  try {
    const { slug } = req.query;

    if (!slug || typeof slug !== "string") {
      return res.status(400).json({ error: "Slug parameter required" });
    }

    const normalizedSlug = slug.toLowerCase().trim();

    // Validate format
    const formatResult = onboardingSlugSchema.safeParse(normalizedSlug);
    if (!formatResult.success) {
      return res.json({
        available: false,
        valid: false,
        reason: formatResult.error.errors[0]?.message || "Invalid slug format",
      });
    }

    // Check availability
    const existing = await tenants.findBySlug(normalizedSlug);
    if (existing) {
      // Generate suggestions
      const suggestions = [
        `${normalizedSlug}-${Math.floor(Math.random() * 100)}`,
        `${normalizedSlug}-team`,
        `${normalizedSlug}-org`,
      ];

      return res.json({
        available: false,
        valid: true,
        reason: "Slug is already taken",
        suggestions,
      });
    }

    res.json({
      available: true,
      valid: true,
      slug: normalizedSlug,
    });
  } catch (err) {
    console.error("Check slug error:", err);
    res.status(500).json({ error: "Failed to check slug availability" });
  }
});

export default router;

// Email service for sending notifications
// Uses Resend for transactional emails

import { Resend } from "resend";

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const EMAIL_FROM = process.env.RESEND_FROM || "OCMT <noreply@YOUR_DOMAIN>";
const USER_UI_URL = process.env.USER_UI_URL || "https://YOUR_DOMAIN";

const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;

/**
 * Send a group invite email
 */
export async function sendGroupInviteEmail({ to, groupName, inviterName, inviteToken, role }) {
  if (!resend) {
    console.warn(`[email] No email service configured - cannot send invite to ${to}`);
    return false;
  }

  const inviteUrl = `${USER_UI_URL}/invite?token=${inviteToken}`;

  try {
    await resend.emails.send({
      from: EMAIL_FROM,
      to,
      subject: `You've been invited to join ${groupName} on OCMT`,
      html: `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 500px; margin: 0 auto; padding: 40px 20px;">
          <h1 style="color: #1a1a2e; margin-bottom: 24px;">You're invited to ${groupName}</h1>
          <p style="color: #666; font-size: 16px; line-height: 1.6;">
            ${inviterName} has invited you to join <strong>${groupName}</strong> as a ${role} on OCMT.
          </p>
          <p style="color: #666; font-size: 16px; line-height: 1.6;">
            Click the button below to accept the invitation:
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
    console.log(`[email] Group invite sent to ${to} for ${groupName}`);
    return true;
  } catch (err) {
    console.error(`[email] Failed to send invite email to ${to}:`, err.message);
    return false;
  }
}

/**
 * Send a security alert email
 */
export async function sendSecurityAlertEmail({
  to,
  subject,
  eventType,
  severity,
  message,
  metadata = {},
  actionUrl,
}) {
  if (!resend) {
    console.warn(`[email] No email service configured - cannot send security alert to ${to}`);
    return false;
  }

  // Color schemes by severity
  const colors = {
    critical: { bg: "#fef2f2", border: "#dc2626", text: "#991b1b", badge: "#dc2626" },
    warning: { bg: "#fffbeb", border: "#f59e0b", text: "#92400e", badge: "#f59e0b" },
    info: { bg: "#eff6ff", border: "#3b82f6", text: "#1e40af", badge: "#3b82f6" },
    debug: { bg: "#f9fafb", border: "#6b7280", text: "#374151", badge: "#6b7280" },
  };
  const c = colors[severity] || colors.info;

  // Format metadata for display (excluding sensitive fields)
  const safeMetadata = { ...metadata };
  delete safeMetadata.password;
  delete safeMetadata.token;
  delete safeMetadata.secret;

  const metadataHtml = Object.entries(safeMetadata)
    .filter(([key, value]) => value !== undefined && value !== null && key !== "securityEventId")
    .map(
      ([key, value]) =>
        `<p style="color: #6b7280; margin: 4px 0 0; font-size: 13px;"><strong>${escapeHtml(key)}:</strong> ${escapeHtml(String(value))}</p>`,
    )
    .join("");

  try {
    await resend.emails.send({
      from: EMAIL_FROM,
      to,
      subject: `Security Alert: ${subject}`,
      html: `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 40px 20px;">
          <div style="background: ${c.bg}; border-left: 4px solid ${c.border}; padding: 20px; border-radius: 8px;">
            <div style="display: flex; align-items: center; margin-bottom: 12px;">
              <span style="background: ${c.badge}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; text-transform: uppercase;">${escapeHtml(severity)}</span>
            </div>
            <h2 style="color: ${c.text}; margin: 0 0 12px; font-size: 18px;">${escapeHtml(subject)}</h2>
            <p style="color: ${c.text}; margin: 0; line-height: 1.6;">${escapeHtml(message)}</p>
          </div>
          <div style="background: #f9fafb; padding: 16px; border-radius: 8px; margin: 24px 0;">
            <p style="color: #6b7280; margin: 0; font-size: 13px;"><strong>Event Type:</strong> ${escapeHtml(eventType)}</p>
            <p style="color: #6b7280; margin: 4px 0 0; font-size: 13px;"><strong>Time:</strong> ${new Date().toISOString()}</p>
            ${metadataHtml}
          </div>
          ${
            actionUrl
              ? `<a href="${escapeHtml(actionUrl)}" style="display: inline-block; background: #4f46e5; color: white; padding: 14px 28px; border-radius: 8px; text-decoration: none; font-weight: 600;">View Activity Log</a>`
              : ""
          }
          <p style="color: #9ca3af; font-size: 12px; margin-top: 32px; line-height: 1.5;">
            This is an automated security notification from OCMT. If you did not expect this alert or believe it to be in error, please review your account security settings.
          </p>
        </div>
      `,
    });
    console.log(`[email] Security alert sent to ${to}: ${subject}`);
    return true;
  } catch (err) {
    console.error(`[email] Failed to send security alert to ${to}:`, err.message);
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
 * Check if email service is configured
 */
export function isEmailConfigured() {
  return !!resend;
}

export { EMAIL_FROM, USER_UI_URL };

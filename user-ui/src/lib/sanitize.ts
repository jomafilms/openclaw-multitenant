// XSS sanitization utilities using DOMPurify
import DOMPurify from "dompurify";

// Allowed tags for strict HTML sanitization
const STRICT_ALLOWED_TAGS = [
  "h1",
  "h2",
  "h3",
  "h4",
  "h5",
  "h6",
  "p",
  "br",
  "hr",
  "ul",
  "ol",
  "li",
  "blockquote",
  "pre",
  "code",
  "strong",
  "em",
  "b",
  "i",
  "u",
  "s",
  "a",
  "img",
  "table",
  "thead",
  "tbody",
  "tr",
  "th",
  "td",
  "div",
  "span",
];

// Allowed attributes for strict sanitization
const STRICT_ALLOWED_ATTR = ["href", "src", "alt", "title", "class", "target", "rel"];

// Forbidden tags that should never be allowed
const FORBIDDEN_TAGS = ["script", "style", "iframe", "frame", "object", "embed", "form", "input"];

// Forbidden attributes (event handlers)
const FORBIDDEN_ATTR = ["onerror", "onload", "onclick", "onmouseover", "onfocus", "onblur"];

// Track whether hooks have been installed
let hooksInstalled = false;

/**
 * Install DOMPurify hooks for additional safety.
 * Forces all links to open safely with target=_blank and rel=noopener noreferrer.
 * Removes any remaining javascript: URLs from href/src/action attributes.
 */
function installHooks(): void {
  if (hooksInstalled) {
    return;
  }
  hooksInstalled = true;

  DOMPurify.addHook("afterSanitizeAttributes", (node) => {
    // Force all links to open in new tab with noopener
    if (node.tagName === "A") {
      node.setAttribute("target", "_blank");
      node.setAttribute("rel", "noopener noreferrer");
    }

    // Remove any remaining javascript: in href/src/action
    const dangerousAttrs = ["href", "src", "action"];
    for (const attr of dangerousAttrs) {
      const value = node.getAttribute(attr);
      if (value && value.toLowerCase().trim().startsWith("javascript:")) {
        node.removeAttribute(attr);
      }
    }
  });
}

// Install hooks on module load
installHooks();

/**
 * Sanitize HTML to prevent XSS.
 * Uses strict allowlist of tags and attributes.
 * Suitable for user-generated content that needs formatting.
 *
 * @param dirty - The potentially unsafe HTML string
 * @returns Sanitized HTML string
 */
export function sanitizeHtml(dirty: string): string {
  if (!dirty) {
    return "";
  }

  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: STRICT_ALLOWED_TAGS,
    ALLOWED_ATTR: STRICT_ALLOWED_ATTR,
    // Prevent javascript: URLs
    ALLOWED_URI_REGEXP: /^(?:(?:https?|mailto|tel):|[^a-z]|[a-z+.-]+(?:[^a-z+.\-:]|$))/i,
    FORBID_TAGS: FORBIDDEN_TAGS,
    FORBID_ATTR: FORBIDDEN_ATTR,
  });
}

/**
 * Sanitize markdown-rendered HTML.
 * More permissive than sanitizeHtml to allow code blocks and other markdown features.
 * Should be used after converting markdown to HTML.
 *
 * @param dirty - The potentially unsafe HTML string (typically from marked.parse())
 * @returns Sanitized HTML string
 */
export function sanitizeMarkdown(dirty: string): string {
  if (!dirty) {
    return "";
  }

  return DOMPurify.sanitize(dirty, {
    USE_PROFILES: { html: true },
    FORBID_TAGS: FORBIDDEN_TAGS,
    FORBID_ATTR: FORBIDDEN_ATTR,
    // Prevent javascript: URLs
    ALLOWED_URI_REGEXP: /^(?:(?:https?|mailto|tel):|[^a-z]|[a-z+.-]+(?:[^a-z+.\-:]|$))/i,
  });
}

/**
 * Strip all HTML tags, returning plain text only.
 * Useful for displaying user content in contexts where no HTML is allowed.
 *
 * @param dirty - The potentially unsafe HTML string
 * @returns Plain text with all HTML removed
 */
export function stripHtml(dirty: string): string {
  if (!dirty) {
    return "";
  }

  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: [],
    ALLOWED_ATTR: [],
  });
}

/**
 * Escape HTML special characters without using DOMPurify.
 * Useful for simple text escaping in templates.
 *
 * @param text - Plain text to escape
 * @returns HTML-escaped string
 */
export function escapeHtml(text: string): string {
  if (!text) {
    return "";
  }

  const escapeMap: Record<string, string> = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  };

  return text.replace(/[&<>"']/g, (char) => escapeMap[char]);
}

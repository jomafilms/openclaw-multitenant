# Security Plan 09: XSS Mitigation

## Overview

**Problem**: The frontend uses `innerHTML` and similar patterns that can lead to XSS vulnerabilities when rendering user-controlled content, particularly markdown.

**Solution**:

1. Audit and replace unsafe DOM manipulation patterns
2. Integrate DOMPurify for HTML sanitization
3. Use Lit's safe templating exclusively
4. Add CSP to block inline scripts as defense-in-depth

---

## Current Vulnerabilities

### Known Unsafe Patterns

**`user-ui/src/pages/group-resources.ts`** - Markdown rendering:

```typescript
// UNSAFE - renders markdown to HTML without sanitization
this.shadowRoot.innerHTML = marked(userContent);
```

**General patterns to find:**

```typescript
// All of these are potentially unsafe with user content
element.innerHTML = userContent;
element.outerHTML = userContent;
document.write(userContent);
insertAdjacentHTML("beforeend", userContent);
```

---

## Implementation

### 1. Install DOMPurify

```bash
cd user-ui
pnpm add dompurify
pnpm add -D @types/dompurify
```

### 2. Create Sanitization Utility

**Create `user-ui/src/lib/sanitize.ts`:**

```typescript
import DOMPurify from "dompurify";

/**
 * Sanitize HTML to prevent XSS
 * Allows safe HTML tags and attributes only
 */
export function sanitizeHtml(dirty: string): string {
  return DOMPurify.sanitize(dirty, {
    // Allow common formatting tags
    ALLOWED_TAGS: [
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
    ],
    // Allow safe attributes
    ALLOWED_ATTR: ["href", "src", "alt", "title", "class", "target", "rel"],
    // Force links to open safely
    ADD_ATTR: ["target", "rel"],
    // Prevent javascript: URLs
    ALLOWED_URI_REGEXP: /^(?:(?:https?|mailto|tel):|[^a-z]|[a-z+.-]+(?:[^a-z+.\-:]|$))/i,
    // Remove data: URLs for images (can contain scripts)
    FORBID_ATTR: ["onerror", "onload", "onclick", "onmouseover"],
    FORBID_TAGS: ["script", "style", "iframe", "frame", "object", "embed", "form", "input"],
  });
}

/**
 * Sanitize markdown-rendered HTML
 * More permissive for code blocks
 */
export function sanitizeMarkdown(dirty: string): string {
  return DOMPurify.sanitize(dirty, {
    USE_PROFILES: { html: true },
    ADD_ATTR: ["target"],
    FORBID_TAGS: ["script", "style", "iframe"],
    FORBID_ATTR: ["onerror", "onload", "onclick"],
  });
}

/**
 * Strip all HTML, return plain text only
 */
export function stripHtml(dirty: string): string {
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: [],
    ALLOWED_ATTR: [],
  });
}

/**
 * Configure DOMPurify hooks for additional safety
 */
DOMPurify.addHook("afterSanitizeAttributes", (node) => {
  // Force all links to open in new tab with noopener
  if (node.tagName === "A") {
    node.setAttribute("target", "_blank");
    node.setAttribute("rel", "noopener noreferrer");
  }

  // Remove any remaining javascript: in href/src
  ["href", "src", "action"].forEach((attr) => {
    const value = node.getAttribute(attr);
    if (value && value.toLowerCase().includes("javascript:")) {
      node.removeAttribute(attr);
    }
  });
});
```

### 3. Create Safe Markdown Component

**Create `user-ui/src/components/safe-markdown.ts`:**

```typescript
import { LitElement, html, css } from "lit";
import { customElement, property } from "lit/decorators.js";
import { unsafeHTML } from "lit/directives/unsafe-html.js";
import { marked } from "marked";
import { sanitizeMarkdown } from "../lib/sanitize.js";

@customElement("safe-markdown")
export class SafeMarkdown extends LitElement {
  @property({ type: String })
  content = "";

  static styles = css`
    :host {
      display: block;
    }

    /* Markdown styling */
    pre {
      background: var(--code-bg, #f5f5f5);
      padding: 1em;
      overflow-x: auto;
      border-radius: 4px;
    }

    code {
      font-family: monospace;
    }

    a {
      color: var(--link-color, #0066cc);
    }

    img {
      max-width: 100%;
      height: auto;
    }
  `;

  render() {
    if (!this.content) {
      return html``;
    }

    // Parse markdown, then sanitize the resulting HTML
    const rawHtml = marked.parse(this.content, {
      breaks: true,
      gfm: true,
    });
    const safeHtml = sanitizeMarkdown(rawHtml);

    // unsafeHTML is safe here because we've sanitized
    return html`${unsafeHTML(safeHtml)}`;
  }
}
```

### 4. Fix Known Vulnerable Files

#### 4.1 `user-ui/src/pages/group-resources.ts`

```typescript
// BEFORE
import { html } from 'lit';

render() {
  // UNSAFE
  return html`<div .innerHTML=${marked(this.resource.content)}></div>`;
}

// AFTER
import { html } from 'lit';
import '../components/safe-markdown.js';

render() {
  // SAFE - uses sanitized component
  return html`<safe-markdown .content=${this.resource.content}></safe-markdown>`;
}
```

#### 4.2 `user-ui/src/pages/activity.ts` (CRITICAL - Groups Refactor)

**Location**: Line 476

```typescript
// BEFORE (UNSAFE)
<div class="activity-description" .innerHTML=${this.formatAction(log)}></div>

// AFTER (SAFE)
import { unsafeHTML } from 'lit/directives/unsafe-html.js';
import { sanitizeHtml } from '../lib/sanitize.js';

// In render method:
<div class="activity-description">
  ${unsafeHTML(sanitizeHtml(this.formatAction(log)))}
</div>
```

**Why this is critical**: The `formatAction()` method formats user-controlled data (usernames, group names, action descriptions). Without sanitization, malicious group names could execute XSS.

**Alternative approach** - Refactor `formatAction()` to return Lit templates instead of HTML strings:

```typescript
// Better approach - avoid HTML strings entirely
formatAction(log: ActivityLog) {
  const userName = log.user_name || 'Unknown';
  const groupName = log.group_name || '';

  switch (log.action) {
    case 'group.join':
      return html`<strong>${userName}</strong> joined <strong>${groupName}</strong>`;
    case 'invite.accept':
      return html`<strong>${userName}</strong> accepted invite to <strong>${groupName}</strong>`;
    // ... etc
    default:
      return html`${log.action}`;
  }
}

// In render:
<div class="activity-description">${this.formatAction(log)}</div>
```

### 5. ESLint Rules for Prevention

**Add to `user-ui/.eslintrc.js`:**

```javascript
module.exports = {
  rules: {
    // Warn on innerHTML usage
    "no-restricted-properties": [
      "error",
      {
        object: "element",
        property: "innerHTML",
        message: "Use Lit templates or SafeMarkdown component instead of innerHTML",
      },
      {
        object: "this",
        property: "innerHTML",
        message: "Use Lit templates or SafeMarkdown component instead of innerHTML",
      },
    ],
    // Warn on document.write
    "no-restricted-globals": [
      "error",
      {
        name: "document.write",
        message: "document.write is unsafe, use DOM methods",
      },
    ],
  },
};
```

### 6. Lit-Specific Safe Patterns

**Safe patterns to use:**

```typescript
import { html } from "lit";
import { unsafeHTML } from "lit/directives/unsafe-html.js";
import { sanitizeHtml } from "../lib/sanitize.js";

// SAFE: Lit auto-escapes expressions
html`<div>${userContent}</div>`; // Content is escaped

// SAFE: Sanitized before unsafeHTML
html`<div>${unsafeHTML(sanitizeHtml(userContent))}</div>`;

// SAFE: Attribute binding (Lit escapes)
html`<div title=${userContent}></div>`;

// UNSAFE: Never do this
html`<div>${unsafeHTML(userContent)}</div>`; // XSS!
```

### 7. Audit Script

**Create `scripts/audit-xss.sh`:**

```bash
#!/bin/bash
# Find potentially unsafe DOM patterns

echo "=== Searching for innerHTML usage ==="
grep -rn "innerHTML" user-ui/src --include="*.ts" --include="*.js"

echo ""
echo "=== Searching for unsafeHTML without sanitize ==="
grep -rn "unsafeHTML" user-ui/src --include="*.ts" | grep -v "sanitize"

echo ""
echo "=== Searching for document.write ==="
grep -rn "document.write" user-ui/src --include="*.ts" --include="*.js"

echo ""
echo "=== Searching for eval ==="
grep -rn "eval(" user-ui/src --include="*.ts" --include="*.js"

echo ""
echo "=== Searching for insertAdjacentHTML ==="
grep -rn "insertAdjacentHTML" user-ui/src --include="*.ts" --include="*.js"
```

---

## CSP Defense-in-Depth

Even with sanitization, add CSP as a second layer of defense.

**In Plan 01 security headers, ensure:**

```javascript
contentSecurityPolicy: {
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],  // No 'unsafe-inline'!
    styleSrc: ["'self'", "'unsafe-inline'"],  // Lit needs this
    imgSrc: ["'self'", "data:", "https:"],
    connectSrc: ["'self'", "wss:"],
    frameAncestors: ["'none'"]
  }
}
```

---

## Files to Create

| File                                      | Purpose                              |
| ----------------------------------------- | ------------------------------------ |
| `user-ui/src/lib/sanitize.ts`             | DOMPurify wrapper with safe defaults |
| `user-ui/src/components/safe-markdown.ts` | Sanitized markdown renderer          |
| `scripts/audit-xss.sh`                    | Find unsafe patterns                 |

## Files to Modify

| File                                   | Changes                     |
| -------------------------------------- | --------------------------- |
| `user-ui/package.json`                 | Add dompurify dependency    |
| `user-ui/src/pages/group-resources.ts` | Use safe-markdown component |
| `user-ui/.eslintrc.js`                 | Add innerHTML warnings      |
| Any file using innerHTML               | Migrate to Lit templates    |

---

## Testing

```bash
# Run audit script
./scripts/audit-xss.sh

# Test sanitization
node -e "
const { sanitizeHtml } = require('./user-ui/dist/lib/sanitize.js');
console.log(sanitizeHtml('<script>alert(1)</script>'));  // Should be empty
console.log(sanitizeHtml('<img src=x onerror=alert(1)>'));  // Should remove onerror
console.log(sanitizeHtml('<a href=\"javascript:alert(1)\">click</a>'));  // Should remove href
"

# Manual XSS test in browser
# Enter these in any markdown/text field:
# <script>alert('XSS')</script>
# <img src=x onerror=alert('XSS')>
# <a href="javascript:alert('XSS')">click</a>
# None should execute
```

---

## Priority

**HIGH** - XSS can steal session tokens, gateway tokens, and user data.

## Estimated Effort

- Sanitization library: 1 hour
- Safe markdown component: 1 hour
- Audit and fix existing code: 2-3 hours
- ESLint rules: 30 minutes
- Testing: 1 hour

**Total: ~6 hours**

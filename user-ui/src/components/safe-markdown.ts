// Safe markdown rendering component using marked + DOMPurify
import { LitElement, html, css } from "lit";
import { customElement, property } from "lit/decorators.js";
import { unsafeHTML } from "lit/directives/unsafe-html.js";
import { marked } from "marked";
import { sanitizeMarkdown } from "../lib/sanitize.js";

// Configure marked for GFM (GitHub Flavored Markdown)
marked.setOptions({
  gfm: true,
  breaks: true,
});

/**
 * Safe markdown rendering component.
 * Parses markdown with `marked` and sanitizes the output with DOMPurify.
 *
 * Usage:
 * ```html
 * <safe-markdown .content=${markdownString}></safe-markdown>
 * ```
 *
 * The component automatically:
 * - Converts markdown to HTML
 * - Sanitizes all HTML to prevent XSS
 * - Forces links to open in new tabs with noopener
 * - Applies consistent styling for code blocks, links, etc.
 */
@customElement("safe-markdown")
export class SafeMarkdown extends LitElement {
  /**
   * The markdown content to render.
   */
  @property({ type: String })
  content = "";

  static styles = css`
    :host {
      display: block;
      line-height: 1.6;
      color: inherit;
    }

    /* Headings */
    h1,
    h2,
    h3,
    h4,
    h5,
    h6 {
      margin-top: 1.5em;
      margin-bottom: 0.5em;
      font-weight: 600;
      line-height: 1.3;
    }

    h1 {
      font-size: 1.75em;
    }
    h2 {
      font-size: 1.5em;
    }
    h3 {
      font-size: 1.25em;
    }
    h4 {
      font-size: 1.1em;
    }
    h5,
    h6 {
      font-size: 1em;
    }

    h1:first-child,
    h2:first-child,
    h3:first-child,
    h4:first-child,
    h5:first-child,
    h6:first-child {
      margin-top: 0;
    }

    /* Paragraphs */
    p {
      margin: 0.75em 0;
    }

    p:first-child {
      margin-top: 0;
    }

    p:last-child {
      margin-bottom: 0;
    }

    /* Links */
    a {
      color: var(--link-color, #6366f1);
      text-decoration: none;
      transition: color 0.15s ease;
    }

    a:hover {
      color: var(--link-hover-color, #818cf8);
      text-decoration: underline;
    }

    a:visited {
      color: var(--link-visited-color, #a78bfa);
    }

    /* Code blocks */
    pre {
      background: var(--code-bg, #1e1e2e);
      border: 1px solid var(--code-border, rgba(255, 255, 255, 0.1));
      border-radius: 8px;
      padding: 1em;
      overflow-x: auto;
      margin: 1em 0;
    }

    pre code {
      background: none;
      padding: 0;
      border-radius: 0;
      font-size: 0.9em;
    }

    /* Inline code */
    code {
      font-family: "SF Mono", Monaco, "Cascadia Code", "Roboto Mono", Consolas, monospace;
      background: var(--inline-code-bg, rgba(255, 255, 255, 0.1));
      padding: 0.2em 0.4em;
      border-radius: 4px;
      font-size: 0.9em;
    }

    /* Blockquotes */
    blockquote {
      margin: 1em 0;
      padding: 0.5em 1em;
      border-left: 4px solid var(--blockquote-border, #6366f1);
      background: var(--blockquote-bg, rgba(99, 102, 241, 0.1));
      border-radius: 0 4px 4px 0;
    }

    blockquote p {
      margin: 0;
    }

    /* Lists */
    ul,
    ol {
      margin: 0.75em 0;
      padding-left: 1.5em;
    }

    li {
      margin: 0.25em 0;
    }

    li > ul,
    li > ol {
      margin: 0.25em 0;
    }

    /* Horizontal rules */
    hr {
      border: none;
      border-top: 1px solid var(--hr-color, rgba(255, 255, 255, 0.1));
      margin: 1.5em 0;
    }

    /* Tables */
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 1em 0;
    }

    th,
    td {
      padding: 0.5em 0.75em;
      text-align: left;
      border: 1px solid var(--table-border, rgba(255, 255, 255, 0.1));
    }

    th {
      background: var(--table-header-bg, rgba(255, 255, 255, 0.05));
      font-weight: 600;
    }

    tr:nth-child(even) {
      background: var(--table-stripe-bg, rgba(255, 255, 255, 0.02));
    }

    /* Images */
    img {
      max-width: 100%;
      height: auto;
      border-radius: 4px;
    }

    /* Strong and emphasis */
    strong,
    b {
      font-weight: 600;
    }

    em,
    i {
      font-style: italic;
    }

    /* Strikethrough */
    del,
    s {
      text-decoration: line-through;
      opacity: 0.7;
    }
  `;

  render() {
    if (!this.content) {
      return html``;
    }

    // Parse markdown to HTML
    const rawHtml = marked.parse(this.content, {
      async: false,
    }) as string;

    // Sanitize the HTML to prevent XSS
    const safeHtml = sanitizeMarkdown(rawHtml);

    // unsafeHTML is safe here because we've sanitized the content
    return html`${unsafeHTML(safeHtml)}`;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "safe-markdown": SafeMarkdown;
  }
}

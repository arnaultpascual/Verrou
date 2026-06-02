/**
 * Zero-dependency lightweight markdown renderer.
 *
 * Converts a subset of markdown to sanitized HTML for secure note display.
 * Supports: headings, bold, italic, inline code, fenced code blocks,
 * unordered lists, ordered lists, and safe links.
 *
 * SECURITY MODEL
 * --------------
 * The output of this function is injected via `innerHTML` inside the
 * (untrusted) WebView, on DECRYPTED user-controlled content. It must never
 * allow attacker-controlled markup or script-bearing URLs to survive.
 *
 * Defenses:
 * 1. ALL input text is HTML-escaped FIRST. Any raw `<script>`,
 *    `<img onerror=...>`, etc. in the note body becomes inert text. No code
 *    path ever copies un-escaped source into the output.
 * 2. Only a fixed ALLOWLIST of tags is emitted: <h1>-<h3>, <strong>, <em>,
 *    <code>, <pre>, <ul>, <ol>, <li>, <p>, and <a>. No attributes are ever
 *    emitted except `href`/`rel`/`target` on anchors.
 * 3. Anchor URLs are validated against a scheme allowlist (http, https,
 *    mailto) plus same-document/relative references. Everything else
 *    (javascript:, data:, vbscript:, file:, etc.) is neutralized — the
 *    original markdown is left as plain (escaped) text with no anchor.
 * 4. The validated href is re-escaped for the attribute context, so it cannot
 *    break out of the quoted attribute.
 */

/**
 * Escape HTML entities to prevent injection.
 *
 * Escapes the five characters that are dangerous in both text and
 * double-quoted attribute contexts. `&` MUST be escaped first.
 */
function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * URL schemes permitted in links. Anything not matching one of these (and not
 * a relative / same-document reference) is rejected and the link is dropped.
 */
const ALLOWED_URL_SCHEMES = new Set(["http", "https", "mailto"]);

/**
 * Matches ASCII control characters (0x00-0x1F), DEL (0x7F), and the space
 * character. Browsers ignore these when resolving a URL scheme, so they must be
 * stripped before the scheme is examined — otherwise `javascript:` could be
 * smuggled as `java\tscript:`, `\njavascript:`, or `  javascript:`.
 *
 * Built via `new RegExp` so no raw control bytes appear in this source file.
 */
const URL_STRIP_CHARS = new RegExp("[\\x00-\\x20\\x7f]", "g");

/**
 * Validate and normalize a link target extracted from `[text](url)`.
 *
 * The incoming `raw` value has already been HTML-escaped by `escapeHtml`, so
 * we first decode the handful of entities that can appear inside a URL token,
 * then strip control/whitespace characters, then test the scheme.
 *
 * Returns a safe, attribute-escaped href string, or `null` if the URL is not
 * allowed (caller then renders the original markdown as plain text).
 */
function sanitizeUrl(raw: string): string | null {
  // Undo the entity-escaping applied by escapeHtml so we can inspect the
  // true characters of the URL (e.g. an `&` in a query string is `&amp;`).
  const decoded = raw
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");

  // Strip control characters and spaces (see URL_STRIP_CHARS) so the scheme
  // check below is authoritative and cannot be bypassed by obfuscation.
  const cleaned = decoded.replace(URL_STRIP_CHARS, "");

  if (cleaned === "") {
    return null;
  }

  // Detect an explicit scheme: a leading run of scheme chars followed by ":".
  // Per RFC 3986 a scheme is ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ). The
  // charset excludes "/", "?" and "#", so a colon appearing only inside a path
  // (e.g. "foo/bar:baz") is correctly treated as a relative reference.
  const schemeMatch = cleaned.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase();
    if (!ALLOWED_URL_SCHEMES.has(scheme)) {
      return null;
    }
  }
  // No scheme → relative path, fragment (#...), or protocol-relative; allowed.

  // Re-escape the cleaned value for the double-quoted attribute context so it
  // cannot terminate the attribute or the tag.
  return escapeHtml(cleaned);
}

/**
 * Render a markdown string to sanitized HTML.
 *
 * Processing order:
 * 1. Escape all HTML entities
 * 2. Extract fenced code blocks (``` ... ```)
 * 3. Process block-level elements (headings, lists)
 * 4. Process inline elements (bold, italic, inline code, safe links)
 */
export function renderMarkdown(source: string): string {
  const escaped = escapeHtml(source);
  const lines = escaped.split("\n");
  const output: string[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block. Contents are emitted verbatim (already escaped) and
    // are NOT run through inline processing, so no markup is interpreted.
    if (line.startsWith("```")) {
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("```")) {
        codeLines.push(lines[i]);
        i++;
      }
      if (i < lines.length) i++; // skip closing ```
      output.push(`<pre><code>${codeLines.join("\n")}</code></pre>`);
      continue;
    }

    // Headings
    const headingMatch = line.match(/^(#{1,3})\s+(.+)$/);
    if (headingMatch) {
      const level = headingMatch[1].length;
      const text = processInline(headingMatch[2]);
      output.push(`<h${level}>${text}</h${level}>`);
      i++;
      continue;
    }

    // Unordered list
    if (line.match(/^[-*]\s+/)) {
      const items: string[] = [];
      while (i < lines.length && lines[i].match(/^[-*]\s+/)) {
        items.push(processInline(lines[i].replace(/^[-*]\s+/, "")));
        i++;
      }
      output.push(`<ul>${items.map((item) => `<li>${item}</li>`).join("")}</ul>`);
      continue;
    }

    // Ordered list
    if (line.match(/^\d+\.\s+/)) {
      const items: string[] = [];
      while (i < lines.length && lines[i].match(/^\d+\.\s+/)) {
        items.push(processInline(lines[i].replace(/^\d+\.\s+/, "")));
        i++;
      }
      output.push(`<ol>${items.map((item) => `<li>${item}</li>`).join("")}</ol>`);
      continue;
    }

    // Empty line → paragraph break
    if (line.trim() === "") {
      i++;
      continue;
    }

    // Regular paragraph
    output.push(`<p>${processInline(line)}</p>`);
    i++;
  }

  return output.join("\n");
}

/**
 * Process inline markdown elements within already-escaped text.
 *
 * The input is guaranteed HTML-escaped by `renderMarkdown`. Every replacement
 * below either wraps already-escaped text in a fixed safe tag or, for links,
 * routes the URL through `sanitizeUrl`. No replacement reintroduces raw markup.
 */
function processInline(text: string): string {
  // Links: [label](url). Resolved before emphasis so emphasis inside the label
  // still renders, but the URL itself is taken literally and validated. The
  // label is non-greedy and may not contain "]"; the URL may not contain
  // whitespace or ")".
  const withLinks = text.replace(
    /\[([^\]]*)\]\(([^)\s]*)\)/g,
    (match, label: string, url: string) => {
      const href = sanitizeUrl(url);
      if (href === null) {
        // Disallowed scheme (javascript:, data:, vbscript:, ...). Drop the link
        // and leave the original markdown as inert, already-escaped text.
        return match;
      }
      // `label` is already escaped; allow emphasis/code inside it.
      const safeLabel = processInlineEmphasis(label);
      return `<a href="${href}" rel="noopener noreferrer nofollow" target="_blank">${safeLabel}</a>`;
    },
  );

  return processInlineEmphasis(withLinks);
}

/**
 * Apply inline code / bold / italic to already-escaped text. Split out so it
 * can be reused for link labels without re-running link parsing.
 */
function processInlineEmphasis(text: string): string {
  let result = text;

  // Inline code (must come first to avoid bold/italic inside code)
  result = result.replace(/`([^`]+)`/g, "<code>$1</code>");

  // Bold (**text** or __text__)
  result = result.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  result = result.replace(/__(.+?)__/g, "<strong>$1</strong>");

  // Italic (*text* or _text_)
  result = result.replace(/\*(.+?)\*/g, "<em>$1</em>");
  result = result.replace(/_(.+?)_/g, "<em>$1</em>");

  return result;
}

/**
 * Zero-dependency lightweight markdown renderer.
 *
 * Converts a subset of markdown to sanitized HTML for secure note display.
 * Supports: headings, bold, italic, inline code, fenced code blocks,
 * unordered lists, and ordered lists.
 *
 * HTML entities are escaped first to prevent XSS.
 */

/** Escape HTML entities to prevent injection. */
function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Render a markdown string to sanitized HTML.
 *
 * Processing order:
 * 1. Escape all HTML entities
 * 2. Extract fenced code blocks (``` ... ```)
 * 3. Process block-level elements (headings, lists)
 * 4. Process inline elements (bold, italic, inline code)
 */
export function renderMarkdown(source: string): string {
  const escaped = escapeHtml(source);
  const lines = escaped.split("\n");
  const output: string[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block
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

/** Process inline markdown elements within already-escaped text. */
function processInline(text: string): string {
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

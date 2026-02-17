/**
 * URL utilities for credential entry forms.
 *
 * - extractDomain: parse hostname from URL string
 * - validateUrl: check if string is a valid URL or domain
 */

/**
 * Extract the domain (hostname without www.) from a URL string.
 * Accepts full URLs or bare domains (e.g. "github.com").
 * Returns empty string if parsing fails.
 */
export function extractDomain(url: string): string {
  const trimmed = url.trim();
  if (!trimmed) return "";
  try {
    const normalized = trimmed.match(/^https?:\/\//) ? trimmed : `https://${trimmed}`;
    const u = new URL(normalized);
    return u.hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
}

/**
 * Validate that a string is a plausible URL.
 * Accepts `http://`, `https://`, or a bare domain that parses via `new URL`.
 * Returns an error message or empty string if valid.
 */
export function validateUrl(url: string): string {
  const trimmed = url.trim();
  if (!trimmed) return ""; // empty is valid (optional field)
  try {
    const normalized = trimmed.match(/^https?:\/\//) ? trimmed : `https://${trimmed}`;
    const u = new URL(normalized);
    // Must have a dot in hostname (reject "localhost"-style unless explicit)
    if (!u.hostname.includes(".") && !trimmed.match(/^https?:\/\//)) {
      return "Enter a valid URL (e.g. example.com or https://example.com).";
    }
    return "";
  } catch {
    return "Enter a valid URL (e.g. example.com or https://example.com).";
  }
}

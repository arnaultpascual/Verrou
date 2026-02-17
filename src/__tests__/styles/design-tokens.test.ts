/**
 * Design Token System tests — Story 2.4
 *
 * Validates that variables.css, reset.css, and global.css define the
 * complete token set matching the UX specification.
 *
 * Strategy: Parse CSS file contents as text (token existence/correctness)
 * and test DOM behaviors (theme switching, reduced motion).
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it } from "vitest";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/** Read a CSS file relative to src/styles/ */
function readCss(filename: string): string {
  return readFileSync(
    resolve(__dirname, "../../styles", filename),
    "utf-8",
  );
}

/** Extract all CSS custom property declarations (--name: value) from text */
function extractTokens(css: string): Map<string, string> {
  const tokens = new Map<string, string>();
  // Match --property-name: value; (possibly multiline for font stacks)
  const regex = /--([\w-]+)\s*:\s*([^;]+);/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(css)) !== null) {
    tokens.set(`--${match[1]}`, match[2].trim());
  }
  return tokens;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Design Token System", () => {
  let variablesCss: string;
  let resetCss: string;
  let globalCss: string;

  beforeEach(() => {
    variablesCss = readCss("variables.css");
    resetCss = readCss("reset.css");
    globalCss = readCss("global.css");
  });

  // ── Task 7.1: CSS files are parseable ──

  describe("CSS file syntax", () => {
    it("variables.css is readable and non-empty", () => {
      expect(variablesCss.length).toBeGreaterThan(100);
    });

    it("reset.css is readable and non-empty", () => {
      expect(resetCss.length).toBeGreaterThan(50);
    });

    it("global.css is readable and non-empty", () => {
      expect(globalCss.length).toBeGreaterThan(50);
    });
  });

  // ── Task 7.2: All required token categories exist ──

  describe("Token categories in :root", () => {
    let rootTokens: Map<string, string>;

    beforeEach(() => {
      // Extract tokens from the :root block (before any theme selector)
      const rootMatch = variablesCss.match(/:root\s*\{([^}]+)\}/);
      expect(rootMatch).not.toBeNull();
      rootTokens = extractTokens(rootMatch![1]);
    });

    it("defines surface hierarchy tokens", () => {
      expect(rootTokens.has("--color-surface-0")).toBe(true);
      expect(rootTokens.has("--color-surface-1")).toBe(true);
      expect(rootTokens.has("--color-surface-2")).toBe(true);
      expect(rootTokens.has("--color-surface-3")).toBe(true);
    });

    it("defines text hierarchy tokens with UX spec names", () => {
      expect(rootTokens.has("--color-text-primary")).toBe(true);
      expect(rootTokens.has("--color-text-secondary")).toBe(true);
      expect(rootTokens.has("--color-text-muted")).toBe(true);
      expect(rootTokens.has("--color-text-inverse")).toBe(true);
    });

    it("does NOT define old --color-text-tertiary name", () => {
      expect(rootTokens.has("--color-text-tertiary")).toBe(false);
    });

    it("defines semantic color tokens with UX spec names", () => {
      expect(rootTokens.has("--color-primary")).toBe(true);
      expect(rootTokens.has("--color-primary-hover")).toBe(true);
      expect(rootTokens.has("--color-danger")).toBe(true);
      expect(rootTokens.has("--color-success")).toBe(true);
      expect(rootTokens.has("--color-warning")).toBe(true);
    });

    it("does NOT define old --color-interactive naming", () => {
      expect(rootTokens.has("--color-interactive")).toBe(false);
      expect(rootTokens.has("--color-interactive-hover")).toBe(false);
    });

    it("defines entry type accent tokens with --color-type-* naming", () => {
      expect(rootTokens.has("--color-type-totp")).toBe(true);
      expect(rootTokens.has("--color-type-seed")).toBe(true);
      expect(rootTokens.has("--color-type-recovery")).toBe(true);
      expect(rootTokens.has("--color-type-note")).toBe(true);
      expect(rootTokens.has("--color-type-credential")).toBe(true);
    });

    it("does NOT define old --color-accent-* naming", () => {
      expect(rootTokens.has("--color-accent-totp")).toBe(false);
    });

    it("defines border color tokens for composability", () => {
      expect(rootTokens.has("--border-color-subtle")).toBe(true);
      expect(rootTokens.has("--border-color-default")).toBe(true);
      expect(rootTokens.has("--border-color-strong")).toBe(true);
    });

    it("defines border shorthand tokens", () => {
      expect(rootTokens.has("--border-subtle")).toBe(true);
      expect(rootTokens.has("--border-default")).toBe(true);
      expect(rootTokens.has("--border-strong")).toBe(true);
      expect(rootTokens.has("--border-radius-sm")).toBe(true);
      expect(rootTokens.has("--border-radius-md")).toBe(true);
      expect(rootTokens.has("--border-radius-lg")).toBe(true);
    });

    it("does NOT define old --color-border-* or --radius-* naming", () => {
      expect(rootTokens.has("--color-border-subtle")).toBe(false);
      expect(rootTokens.has("--radius-sm")).toBe(false);
    });

    it("defines spacing scale on 4/8px grid", () => {
      expect(rootTokens.get("--spacing-xs")).toBe("4px");
      expect(rootTokens.get("--spacing-sm")).toBe("8px");
      expect(rootTokens.get("--spacing-md")).toBe("12px");
      expect(rootTokens.get("--spacing-lg")).toBe("16px");
      expect(rootTokens.get("--spacing-xl")).toBe("24px");
      expect(rootTokens.get("--spacing-2xl")).toBe("32px");
      expect(rootTokens.get("--spacing-3xl")).toBe("48px");
    });

    it("defines typography tokens with UX spec names", () => {
      expect(rootTokens.has("--font-family")).toBe(true);
      expect(rootTokens.has("--font-family-mono")).toBe(true);
      expect(rootTokens.has("--font-size-xs")).toBe(true);
      expect(rootTokens.has("--font-size-sm")).toBe(true);
      expect(rootTokens.has("--font-size-md")).toBe(true);
      expect(rootTokens.has("--font-size-lg")).toBe(true);
      expect(rootTokens.has("--font-size-xl")).toBe(true);
      expect(rootTokens.has("--font-size-2xl")).toBe(true);
      expect(rootTokens.has("--font-weight-normal")).toBe(true);
      expect(rootTokens.has("--font-weight-medium")).toBe(true);
      expect(rootTokens.has("--font-weight-semibold")).toBe(true);
    });

    it("does NOT define old --font-family-sans or --font-weight-regular", () => {
      expect(rootTokens.has("--font-family-sans")).toBe(false);
      expect(rootTokens.has("--font-weight-regular")).toBe(false);
    });

    it("defines OTP typography tokens", () => {
      expect(rootTokens.get("--letter-spacing-otp")).toBe("0.15em");
      expect(rootTokens.get("--font-size-otp")).toBe("1.25rem");
      expect(rootTokens.get("--font-weight-otp")).toBe("600");
    });

    it("defines shadow tokens matching UX spec", () => {
      expect(rootTokens.get("--shadow-none")).toBe("none");
      expect(rootTokens.has("--shadow-sm")).toBe(true);
      expect(rootTokens.has("--shadow-popup")).toBe(true);
    });

    it("does NOT define old --shadow-md", () => {
      expect(rootTokens.has("--shadow-md")).toBe(false);
    });

    it("defines animation tokens with correct values", () => {
      expect(rootTokens.get("--duration-instant")).toBe("50ms");
      expect(rootTokens.get("--duration-fast")).toBe("100ms");
      expect(rootTokens.get("--duration-normal")).toBe("200ms");
      expect(rootTokens.get("--duration-slow")).toBe("400ms");
      expect(rootTokens.get("--duration-ceremony")).toBe("3000ms");
      expect(rootTokens.get("--easing-default")).toBe("cubic-bezier(0.4, 0, 0.2, 1)");
    });

    it("defines opacity tokens", () => {
      expect(rootTokens.get("--opacity-disabled")).toBe("0.5");
      expect(rootTokens.get("--opacity-muted")).toBe("0.7");
    });

    it("defines component size tokens", () => {
      expect(rootTokens.get("--size-checkbox")).toBe("16px");
      expect(rootTokens.get("--size-dot-indicator")).toBe("10px");
    });

    it("defines letter-spacing-wide token", () => {
      expect(rootTokens.get("--letter-spacing-wide")).toBe("0.05em");
    });

    it("defines z-index scale matching UX spec", () => {
      expect(rootTokens.get("--z-base")).toBe("0");
      expect(rootTokens.get("--z-dropdown")).toBe("100");
      expect(rootTokens.get("--z-modal")).toBe("200");
      expect(rootTokens.get("--z-popup")).toBe("300");
      expect(rootTokens.get("--z-toast")).toBe("400");
    });

    it("does NOT define old --z-sticky, --z-overlay", () => {
      expect(rootTokens.has("--z-sticky")).toBe(false);
      expect(rootTokens.has("--z-overlay")).toBe(false);
    });

    it("defines focus ring token", () => {
      expect(rootTokens.has("--color-focus-ring")).toBe(true);
    });
  });

  // ── Task 7.3: Dark theme is the default ──

  describe("Dark theme defaults in :root", () => {
    it("dark surface-0 matches UX spec #0F0F14", () => {
      const rootMatch = variablesCss.match(/:root\s*\{([^}]+)\}/);
      const tokens = extractTokens(rootMatch![1]);
      expect(tokens.get("--color-surface-0")).toBe("#0F0F14");
    });

    it("dark text-primary matches UX spec #E8E8F0", () => {
      const rootMatch = variablesCss.match(/:root\s*\{([^}]+)\}/);
      const tokens = extractTokens(rootMatch![1]);
      expect(tokens.get("--color-text-primary")).toBe("#E8E8F0");
    });

    it("dark primary color matches UX spec #7B8CA8", () => {
      const rootMatch = variablesCss.match(/:root\s*\{([^}]+)\}/);
      const tokens = extractTokens(rootMatch![1]);
      expect(tokens.get("--color-primary")).toBe("#7B8CA8");
    });
  });

  // ── Task 7.4: Light theme via [data-theme="light"] ──

  describe("Light theme via [data-theme=\"light\"]", () => {
    it("contains [data-theme=\"light\"] selector", () => {
      expect(variablesCss).toContain('[data-theme="light"]');
    });

    it("light theme defines surface-0 as #F8F8FA", () => {
      const lightMatch = variablesCss.match(
        /\[data-theme="light"\]\s*\{([^}]+)\}/,
      );
      expect(lightMatch).not.toBeNull();
      const tokens = extractTokens(lightMatch![1]);
      expect(tokens.get("--color-surface-0")).toBe("#F8F8FA");
    });

    it("light theme defines text-primary as #1A1A2E", () => {
      const lightMatch = variablesCss.match(
        /\[data-theme="light"\]\s*\{([^}]+)\}/,
      );
      const tokens = extractTokens(lightMatch![1]);
      expect(tokens.get("--color-text-primary")).toBe("#1A1A2E");
    });

    it("light theme defines primary color as #4A5568", () => {
      const lightMatch = variablesCss.match(
        /\[data-theme="light"\]\s*\{([^}]+)\}/,
      );
      const tokens = extractTokens(lightMatch![1]);
      expect(tokens.get("--color-primary")).toBe("#4A5568");
    });

    it("light theme defines all entry type accents", () => {
      const lightMatch = variablesCss.match(
        /\[data-theme="light"\]\s*\{([^}]+)\}/,
      );
      const tokens = extractTokens(lightMatch![1]);
      expect(tokens.get("--color-type-totp")).toBe("#4A7C9B");
      expect(tokens.get("--color-type-seed")).toBe("#7B6B8A");
      expect(tokens.get("--color-type-recovery")).toBe("#8B7355");
      expect(tokens.get("--color-type-note")).toBe("#5B7B6B");
      expect(tokens.get("--color-type-credential")).toBe("#6B7B8B");
    });
  });

  // ── Task 7.4 (cont): System preference fallback ──

  describe("System preference fallback", () => {
    it("contains prefers-color-scheme media query fallback", () => {
      expect(variablesCss).toContain("prefers-color-scheme: light");
    });

    it("uses :root:not([data-theme]) so explicit attribute wins", () => {
      expect(variablesCss).toContain(":root:not([data-theme])");
    });
  });

  // ── Task 7.5: Reduced motion ──

  describe("Reduced motion support", () => {
    it("global.css contains prefers-reduced-motion media query", () => {
      expect(globalCss).toContain("prefers-reduced-motion: reduce");
    });

    it("reduced motion block sets all durations to 0ms", () => {
      const reducedBlock = globalCss.match(
        /@media\s*\(prefers-reduced-motion:\s*reduce\)\s*\{([^}]*\{[^}]*\}[^}]*)\}/,
      );
      expect(reducedBlock).not.toBeNull();
      const content = reducedBlock![1];
      expect(content).toContain("--duration-instant: 0ms");
      expect(content).toContain("--duration-fast: 0ms");
      expect(content).toContain("--duration-normal: 0ms");
      expect(content).toContain("--duration-slow: 0ms");
      expect(content).toContain("--duration-ceremony: 0ms");
    });
  });

  // ── Task 7.6: Focus ring ──

  describe("Focus ring styling", () => {
    it("global.css defines :focus-visible with color-focus-ring", () => {
      expect(globalCss).toContain(":focus-visible");
      expect(globalCss).toContain("var(--color-focus-ring)");
    });
  });

  // ── Task 7.7: Body uses system font stack ──

  describe("Body font configuration", () => {
    it("reset.css applies --font-family to body", () => {
      expect(resetCss).toContain("var(--font-family)");
    });

    it("reset.css does NOT reference old --font-family-sans", () => {
      expect(resetCss).not.toContain("--font-family-sans");
    });

    it("reset.css applies --font-weight-normal to body", () => {
      expect(resetCss).toContain("var(--font-weight-normal)");
    });

    it("reset.css does NOT reference old --font-weight-regular", () => {
      expect(resetCss).not.toContain("--font-weight-regular");
    });

    it("html uses font-size: 100% for system preference (NFR49)", () => {
      expect(resetCss).toContain("font-size: 100%");
      expect(resetCss).not.toContain("font-size: 16px");
    });

    it("body sets user-select: none for desktop app", () => {
      expect(resetCss).toContain("user-select: none");
    });
  });

  // ── Task 7.8: Heading hierarchy ──

  describe("Heading hierarchy", () => {
    it("h1 uses --font-size-xl", () => {
      expect(globalCss).toContain("--font-size-xl");
    });

    it("h2 uses --font-size-lg", () => {
      expect(globalCss).toContain("--font-size-lg");
    });

    it("h3 uses --font-size-md", () => {
      expect(globalCss).toContain("--font-size-md");
    });

    it("headings use --font-weight-semibold", () => {
      expect(globalCss).toContain("var(--font-weight-semibold)");
    });

    it("monospace elements use --font-family-mono", () => {
      expect(globalCss).toContain("var(--font-family-mono)");
    });
  });

  // ── Selection and scrollbar styling ──

  describe("Additional global styles", () => {
    it("global.css defines ::selection styling", () => {
      expect(globalCss).toContain("::selection");
      expect(globalCss).toContain("var(--color-primary)");
    });

    it("global.css defines scrollbar styling", () => {
      expect(globalCss).toContain("::-webkit-scrollbar");
    });
  });
});

describe("Token completeness cross-check", () => {
  it("no references to removed tokens in any style file", () => {
    const allCss = readCss("variables.css") + readCss("reset.css") + readCss("global.css");

    // Old token names that should NOT appear anywhere
    const removedTokens = [
      "--color-text-tertiary",
      "--color-interactive:",     // colon to avoid matching comments
      "--color-accent-totp",
      "--color-border-subtle",
      "--font-family-sans:",
      "--font-weight-regular:",
      "--shadow-md:",
      "--z-sticky",
      "--z-overlay",
      "--radius-sm:",
      "--color-error:",
      "--color-info:",
    ];

    for (const token of removedTokens) {
      // Check token is not defined (var() references excluded — only definitions)
      const defPattern = new RegExp(`^\\s*${token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, "m");
      expect(
        defPattern.test(allCss),
        `Found removed token definition: ${token}`,
      ).toBe(false);
    }
  });
});

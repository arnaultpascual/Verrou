import { describe, it, expect } from "vitest";
import { renderMarkdown } from "../../../features/notes/renderMarkdown";

/**
 * The output of renderMarkdown is injected via innerHTML into the untrusted
 * WebView, on decrypted user content. These tests assert that no path lets
 * script-bearing markup or dangerous URL schemes survive, while ordinary
 * markdown still renders to the safe tag allowlist.
 */
describe("renderMarkdown — XSS hardening", () => {
  it("neutralizes a raw <script> tag in the body", () => {
    const html = renderMarkdown("<script>alert(1)</script>");
    expect(html).not.toContain("<script");
    expect(html).not.toContain("</script>");
    // The angle brackets must be escaped to entities.
    expect(html).toContain("&lt;script&gt;");
  });

  it("neutralizes <img src=x onerror=alert(1)>", () => {
    const html = renderMarkdown("<img src=x onerror=alert(1)>");
    // No live <img> tag is emitted; the angle brackets are escaped, so the
    // `onerror` text is inert content of a <p>, not an attribute.
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
  });

  it("does not emit an onclick (or any event-handler) attribute", () => {
    const html = renderMarkdown('<a href="#" onclick="alert(1)">x</a>');
    // The raw anchor is fully escaped — no live <a> tag and no live handler.
    expect(html).not.toContain('<a href="#"');
    expect(html).not.toContain("<a ");
    expect(html).toContain("&lt;a href=&quot;#&quot; onclick=&quot;alert(1)&quot;&gt;");
  });

  it("strips a javascript: scheme from a markdown link", () => {
    const html = renderMarkdown("[click me](javascript:alert(1))");
    // No anchor and no live href are emitted; the markdown is left as text.
    expect(html).not.toContain("<a ");
    expect(html).not.toContain("href=");
    expect(html).toContain("<p>[click me](javascript:alert(1))</p>");
  });

  it("strips an obfuscated javascript: scheme (embedded whitespace/controls)", () => {
    // Browsers ignore the tab inside the scheme; sanitizeUrl must too.
    const html = renderMarkdown("[x](java\tscript:alert(1))");
    expect(html).not.toContain("<a ");
    expect(html).not.toContain("href=");
    // Leading whitespace before the scheme must not bypass the check either.
    const html2 = renderMarkdown("[x](  javascript:alert(1))");
    expect(html2).not.toContain("<a ");
    expect(html2).not.toContain("href=");
  });

  it("strips a data: URL from a markdown link", () => {
    const html = renderMarkdown(
      "[evil](data:text/html,<script>alert(1)</script>)",
    );
    // No anchor, no live href, and the embedded <script> stays escaped text.
    expect(html).not.toContain("<a ");
    expect(html).not.toContain("href=");
    expect(html).not.toContain("<script");
    expect(html).toContain("&lt;script&gt;");
  });

  it("strips a vbscript: URL from a markdown link", () => {
    const html = renderMarkdown("[x](vbscript:msgbox(1))");
    expect(html).not.toContain("<a ");
    expect(html).not.toContain("href=");
    expect(html).toContain("<p>[x](vbscript:msgbox(1))</p>");
  });

  it("strips a file: URL from a markdown link", () => {
    const html = renderMarkdown("[x](file:///etc/passwd)");
    expect(html).not.toContain("<a ");
    expect(html).not.toContain("href=");
  });

  it("does not allow a quote to break out of the href attribute", () => {
    // Attempt to inject an event handler by closing the href quote early. The
    // URL contains a space, so the link pattern does not match; even so, the
    // double-quote is escaped to &quot; and no anchor/handler is emitted.
    const html = renderMarkdown('[x](https://e.com" onmouseover="alert(1))');
    expect(html).not.toContain("<a ");
    expect(html).not.toContain('"https://e.com"');
    // The stray quote from the payload is escaped, not live.
    expect(html).toContain("&quot;");
  });

  it("does not interpret markup smuggled through a code fence", () => {
    const html = renderMarkdown("```\n<script>alert(1)</script>\n```");
    expect(html).toContain("<pre><code>");
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
  });
});

describe("renderMarkdown — legitimate markdown still renders", () => {
  it("renders bold text", () => {
    expect(renderMarkdown("**bold**")).toContain("<strong>bold</strong>");
  });

  it("renders italic text", () => {
    expect(renderMarkdown("*italic*")).toContain("<em>italic</em>");
  });

  it("renders inline code", () => {
    expect(renderMarkdown("`code`")).toContain("<code>code</code>");
  });

  it("renders a fenced code block", () => {
    const html = renderMarkdown("```\nconst x = 1;\n```");
    expect(html).toContain("<pre><code>const x = 1;</code></pre>");
  });

  it("renders headings h1-h3", () => {
    expect(renderMarkdown("# Title")).toContain("<h1>Title</h1>");
    expect(renderMarkdown("## Sub")).toContain("<h2>Sub</h2>");
    expect(renderMarkdown("### Small")).toContain("<h3>Small</h3>");
  });

  it("renders an unordered list", () => {
    const html = renderMarkdown("- one\n- two");
    expect(html).toBe("<ul><li>one</li><li>two</li></ul>");
  });

  it("renders an ordered list", () => {
    const html = renderMarkdown("1. first\n2. second");
    expect(html).toBe("<ol><li>first</li><li>second</li></ol>");
  });

  it("renders a paragraph", () => {
    expect(renderMarkdown("hello world")).toBe("<p>hello world</p>");
  });

  it("renders a safe https link with hardened anchor attributes", () => {
    const html = renderMarkdown("[Verrou](https://example.com/path?a=1)");
    expect(html).toContain('href="https://example.com/path?a=1"');
    expect(html).toContain(">Verrou</a>");
    // Defense-in-depth attributes on every emitted anchor.
    expect(html).toContain('rel="noopener noreferrer nofollow"');
    expect(html).toContain('target="_blank"');
  });

  it("renders a safe http link", () => {
    const html = renderMarkdown("[site](http://example.com)");
    expect(html).toContain('href="http://example.com"');
    expect(html).toContain(">site</a>");
  });

  it("renders a mailto link", () => {
    const html = renderMarkdown("[mail](mailto:a@b.com)");
    expect(html).toContain('href="mailto:a@b.com"');
    expect(html).toContain(">mail</a>");
  });

  it("allows emphasis inside a link label", () => {
    const html = renderMarkdown("[**bold link**](https://example.com)");
    expect(html).toContain('href="https://example.com"');
    expect(html).toContain("<strong>bold link</strong>");
  });

  it("escapes & in a query string but keeps the link", () => {
    const html = renderMarkdown("[q](https://example.com/?a=1&b=2)");
    // The href value lives in an attribute, so & is rendered as &amp;.
    expect(html).toContain('href="https://example.com/?a=1&amp;b=2"');
    expect(html).toContain(">q</a>");
  });
});

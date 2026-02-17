import { describe, expect, it } from "vitest";
import { extractDomain, validateUrl } from "../../../features/credentials/url-utils";

describe("extractDomain", () => {
  it("extracts domain from full https URL", () => {
    expect(extractDomain("https://github.com/login")).toBe("github.com");
  });

  it("extracts domain from http URL", () => {
    expect(extractDomain("http://example.org/path")).toBe("example.org");
  });

  it("strips www prefix", () => {
    expect(extractDomain("https://www.google.com")).toBe("google.com");
  });

  it("handles bare domain without protocol", () => {
    expect(extractDomain("github.com")).toBe("github.com");
  });

  it("handles bare domain with path", () => {
    expect(extractDomain("gitlab.com/users/sign_in")).toBe("gitlab.com");
  });

  it("returns empty string for empty input", () => {
    expect(extractDomain("")).toBe("");
  });

  it("returns empty string for whitespace-only input", () => {
    expect(extractDomain("   ")).toBe("");
  });

  it("returns empty string for garbage input", () => {
    expect(extractDomain("not a url at all!!")).toBe("");
  });

  it("handles subdomain URLs", () => {
    expect(extractDomain("https://mail.google.com")).toBe("mail.google.com");
  });

  it("handles URL with port", () => {
    expect(extractDomain("https://localhost:8080/api")).toBe("localhost");
  });

  it("trims whitespace", () => {
    expect(extractDomain("  https://github.com  ")).toBe("github.com");
  });
});

describe("validateUrl", () => {
  it("returns empty for valid https URL", () => {
    expect(validateUrl("https://github.com")).toBe("");
  });

  it("returns empty for valid http URL", () => {
    expect(validateUrl("http://example.org")).toBe("");
  });

  it("returns empty for bare domain with dot", () => {
    expect(validateUrl("github.com")).toBe("");
  });

  it("returns empty for empty string (optional field)", () => {
    expect(validateUrl("")).toBe("");
  });

  it("returns empty for whitespace-only (optional)", () => {
    expect(validateUrl("   ")).toBe("");
  });

  it("returns error for bare word without dot and no protocol", () => {
    expect(validateUrl("foobar")).not.toBe("");
  });

  it("accepts localhost with explicit protocol", () => {
    expect(validateUrl("http://localhost")).toBe("");
  });

  it("returns error for garbage", () => {
    expect(validateUrl("not a url!!")).not.toBe("");
  });

  it("accepts URL with path", () => {
    expect(validateUrl("https://example.com/login?redirect=true")).toBe("");
  });
});

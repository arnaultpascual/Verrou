import { describe, it, expect } from "vitest";
import { parseOtpAuthUri, buildOtpAuthUri } from "../../../features/entries/otpauth";

describe("parseOtpAuthUri", () => {
  describe("valid full URIs", () => {
    it("parses a complete TOTP URI with all parameters", () => {
      const uri =
        "otpauth://totp/GitHub:user%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30";
      const result = parseOtpAuthUri(uri);

      expect(result).not.toBeNull();
      expect(result!.type).toBe("totp");
      expect(result!.name).toBe("user@example.com");
      expect(result!.issuer).toBe("GitHub");
      expect(result!.secret).toBe("JBSWY3DPEHPK3PXP");
      expect(result!.algorithm).toBe("SHA1");
      expect(result!.digits).toBe(6);
      expect(result!.period).toBe(30);
    });

    it("parses a HOTP URI with counter", () => {
      const uri =
        "otpauth://hotp/Service:admin?secret=GEZDGNBVGY3TQOJQ&issuer=Service&counter=42";
      const result = parseOtpAuthUri(uri);

      expect(result).not.toBeNull();
      expect(result!.type).toBe("hotp");
      expect(result!.name).toBe("admin");
      expect(result!.issuer).toBe("Service");
      expect(result!.secret).toBe("GEZDGNBVGY3TQOJQ");
      expect(result!.counter).toBe(42);
    });

    it("parses URI with SHA256 algorithm and 8 digits", () => {
      const uri =
        "otpauth://totp/AWS:root?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&algorithm=SHA256&digits=8&period=30&issuer=AWS";
      const result = parseOtpAuthUri(uri);

      expect(result!.algorithm).toBe("SHA256");
      expect(result!.digits).toBe(8);
    });

    it("parses URI with SHA512 algorithm", () => {
      const uri =
        "otpauth://totp/Corp:user?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512&issuer=Corp";
      const result = parseOtpAuthUri(uri);

      expect(result!.algorithm).toBe("SHA512");
    });

    it("parses URI with period 15", () => {
      const uri =
        "otpauth://totp/Steam:user?secret=JBSWY3DPEHPK3PXP&period=15&issuer=Steam";
      const result = parseOtpAuthUri(uri);

      expect(result!.period).toBe(15);
    });

    it("parses URI with period 60", () => {
      const uri =
        "otpauth://totp/Bank:user?secret=JBSWY3DPEHPK3PXP&period=60&issuer=Bank";
      const result = parseOtpAuthUri(uri);

      expect(result!.period).toBe(60);
    });
  });

  describe("minimal URIs (defaults applied)", () => {
    it("parses URI with only secret param", () => {
      const uri = "otpauth://totp/MyAccount?secret=JBSWY3DPEHPK3PXP";
      const result = parseOtpAuthUri(uri);

      expect(result).not.toBeNull();
      expect(result!.type).toBe("totp");
      expect(result!.name).toBe("MyAccount");
      expect(result!.issuer).toBe("");
      expect(result!.secret).toBe("JBSWY3DPEHPK3PXP");
      expect(result!.algorithm).toBe("SHA1");
      expect(result!.digits).toBe(6);
      expect(result!.period).toBe(30);
      expect(result!.counter).toBe(0);
    });

    it("uses issuer from label when param missing", () => {
      const uri = "otpauth://totp/Acme:john?secret=JBSWY3DPEHPK3PXP";
      const result = parseOtpAuthUri(uri);

      expect(result!.issuer).toBe("Acme");
      expect(result!.name).toBe("john");
    });
  });

  describe("issuer precedence", () => {
    it("param issuer takes precedence over label issuer", () => {
      const uri =
        "otpauth://totp/LabelIssuer:user?secret=JBSWY3DPEHPK3PXP&issuer=ParamIssuer";
      const result = parseOtpAuthUri(uri);

      expect(result!.issuer).toBe("ParamIssuer");
      expect(result!.name).toBe("user");
    });
  });

  describe("URL-encoded special characters", () => {
    it("decodes URL-encoded label", () => {
      const uri =
        "otpauth://totp/My%20Company%3Auser%40email.com?secret=JBSWY3DPEHPK3PXP&issuer=My%20Company";
      const result = parseOtpAuthUri(uri);

      expect(result!.name).toBe("user@email.com");
      expect(result!.issuer).toBe("My Company");
    });

    it("handles plus signs in labels", () => {
      const uri =
        "otpauth://totp/user%2Btag%40mail.com?secret=JBSWY3DPEHPK3PXP";
      const result = parseOtpAuthUri(uri);

      expect(result!.name).toBe("user+tag@mail.com");
    });

    it("handles encoded colon in issuer", () => {
      const uri =
        "otpauth://totp/Corp%3A%3ADiv:user?secret=JBSWY3DPEHPK3PXP";
      const result = parseOtpAuthUri(uri);

      // First colon not encoded is the separator
      expect(result!.issuer).toBe("Corp::Div");
      expect(result!.name).toBe("user");
    });
  });

  describe("invalid URIs", () => {
    it("returns null for empty string", () => {
      expect(parseOtpAuthUri("")).toBeNull();
    });

    it("returns null for non-otpauth URI", () => {
      expect(parseOtpAuthUri("https://example.com")).toBeNull();
    });

    it("returns null for missing secret", () => {
      expect(parseOtpAuthUri("otpauth://totp/Test?issuer=Test")).toBeNull();
    });

    it("returns null for empty secret", () => {
      expect(parseOtpAuthUri("otpauth://totp/Test?secret=")).toBeNull();
    });

    it("returns null for unknown type", () => {
      expect(
        parseOtpAuthUri("otpauth://steam/Test?secret=JBSWY3DPEHPK3PXP"),
      ).toBeNull();
    });

    it("returns null for malformed URI", () => {
      expect(parseOtpAuthUri("otpauth://")).toBeNull();
    });

    it("returns null for plain text", () => {
      expect(parseOtpAuthUri("just some random text")).toBeNull();
    });

    it("returns null for otpauth with no path", () => {
      expect(parseOtpAuthUri("otpauth://totp?secret=ABC")).toBeNull();
    });
  });

  describe("case handling", () => {
    it("normalizes secret to uppercase", () => {
      const uri = "otpauth://totp/Test?secret=jbswy3dpehpk3pxp";
      const result = parseOtpAuthUri(uri);

      expect(result!.secret).toBe("JBSWY3DPEHPK3PXP");
    });

    it("accepts case-insensitive algorithm", () => {
      const uri =
        "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&algorithm=sha256";
      const result = parseOtpAuthUri(uri);

      expect(result!.algorithm).toBe("SHA256");
    });
  });

  describe("edge cases", () => {
    it("handles label with no account (just issuer prefix)", () => {
      const uri = "otpauth://totp/Issuer:?secret=JBSWY3DPEHPK3PXP";
      const result = parseOtpAuthUri(uri);

      expect(result!.issuer).toBe("Issuer");
      expect(result!.name).toBe("");
    });

    it("handles trailing spaces in secret", () => {
      const uri = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP%20";
      const result = parseOtpAuthUri(uri);

      expect(result!.secret).toBe("JBSWY3DPEHPK3PXP");
    });

    it("ignores unsupported digits values (falls back to default)", () => {
      const uri = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=7";
      const result = parseOtpAuthUri(uri);

      expect(result!.digits).toBe(6);
    });

    it("ignores unsupported period values (falls back to default)", () => {
      const uri = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&period=45";
      const result = parseOtpAuthUri(uri);

      expect(result!.period).toBe(30);
    });

    it("handles secret with padding characters", () => {
      const uri = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP====";
      const result = parseOtpAuthUri(uri);

      expect(result!.secret).toBe("JBSWY3DPEHPK3PXP====");
    });

    it("does not double-decode issuer param (handles % in issuer)", () => {
      const uri =
        "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&issuer=100%25%20Corp";
      const result = parseOtpAuthUri(uri);

      // URLSearchParams decodes to "100% Corp" — no double-decode
      expect(result!.issuer).toBe("100% Corp");
    });
  });
});

describe("buildOtpAuthUri", () => {
  it("builds a basic TOTP URI with issuer", () => {
    const uri = buildOtpAuthUri({
      type: "totp",
      name: "user@example.com",
      issuer: "GitHub",
      secret: "JBSWY3DPEHPK3PXP",
    });

    expect(uri).toContain("otpauth://totp/");
    expect(uri).toContain("GitHub");
    expect(uri).toContain("user%40example.com");
    expect(uri).toContain("secret=JBSWY3DPEHPK3PXP");
    expect(uri).toContain("issuer=GitHub");
    // Defaults omitted
    expect(uri).not.toContain("algorithm=");
    expect(uri).not.toContain("digits=");
    expect(uri).not.toContain("period=");
  });

  it("builds a minimal TOTP URI without issuer", () => {
    const uri = buildOtpAuthUri({
      type: "totp",
      name: "MyAccount",
      secret: "ABCDEFGH",
    });

    expect(uri).toBe("otpauth://totp/MyAccount?secret=ABCDEFGH");
  });

  it("includes non-default algorithm", () => {
    const uri = buildOtpAuthUri({
      type: "totp",
      name: "Test",
      secret: "ABC",
      algorithm: "SHA256",
    });

    expect(uri).toContain("algorithm=SHA256");
  });

  it("includes non-default digits", () => {
    const uri = buildOtpAuthUri({
      type: "totp",
      name: "Test",
      secret: "ABC",
      digits: 8,
    });

    expect(uri).toContain("digits=8");
  });

  it("includes non-default period for TOTP", () => {
    const uri = buildOtpAuthUri({
      type: "totp",
      name: "Test",
      secret: "ABC",
      period: 60,
    });

    expect(uri).toContain("period=60");
  });

  it("includes counter for HOTP", () => {
    const uri = buildOtpAuthUri({
      type: "hotp",
      name: "Test",
      secret: "ABC",
      counter: 42,
    });

    expect(uri).toContain("otpauth://hotp/");
    expect(uri).toContain("counter=42");
  });

  it("omits period for TOTP when it equals default (30)", () => {
    const uri = buildOtpAuthUri({
      type: "totp",
      name: "Test",
      secret: "ABC",
      period: 30,
    });

    expect(uri).not.toContain("period=");
  });

  it("roundtrips with parseOtpAuthUri", () => {
    const input = {
      type: "totp" as const,
      name: "user@example.com",
      issuer: "GitHub",
      secret: "JBSWY3DPEHPK3PXP",
      algorithm: "SHA256",
      digits: 8,
      period: 60,
    };

    const uri = buildOtpAuthUri(input);
    const parsed = parseOtpAuthUri(uri);

    expect(parsed).not.toBeNull();
    expect(parsed!.type).toBe(input.type);
    expect(parsed!.name).toBe(input.name);
    expect(parsed!.issuer).toBe(input.issuer);
    expect(parsed!.secret).toBe(input.secret);
    expect(parsed!.algorithm).toBe(input.algorithm);
    expect(parsed!.digits).toBe(input.digits);
    expect(parsed!.period).toBe(input.period);
  });

  it("encodes special characters in name and issuer", () => {
    const uri = buildOtpAuthUri({
      type: "totp",
      name: "user+tag@mail.com",
      issuer: "My Company",
      secret: "ABC",
    });

    // Name and issuer should be encoded in label
    expect(uri).toContain("My%20Company");
    expect(uri).toContain("user%2Btag%40mail.com");
    // issuer param is unencoded (URLSearchParams handles it)
    expect(uri).toContain("issuer=My+Company");
  });
});

/**
 * otpauth:// URI parser and builder.
 *
 * Standard format (RFC 6238 de facto):
 *   otpauth://totp/Issuer:Account?secret=BASE32&issuer=Issuer&algorithm=SHA1&digits=6&period=30
 *
 * parseOtpAuthUri: Returns ParsedOtpAuth on success, null on invalid input.
 * buildOtpAuthUri: Returns a well-formed otpauth:// URI string.
 */

export type OtpType = "totp" | "hotp";
export type OtpAlgorithm = "SHA1" | "SHA256" | "SHA512";
export type OtpDigits = 6 | 8;
export type OtpPeriod = 15 | 30 | 60;

export interface ParsedOtpAuth {
  type: OtpType;
  name: string;
  issuer: string;
  secret: string;
  algorithm: OtpAlgorithm;
  digits: OtpDigits;
  period: OtpPeriod;
  counter: number;
}

const VALID_TYPES = new Set<string>(["totp", "hotp"]);
const VALID_ALGORITHMS: Record<string, OtpAlgorithm> = {
  sha1: "SHA1",
  sha256: "SHA256",
  sha512: "SHA512",
};
const VALID_DIGITS = new Set<number>([6, 8]);
const VALID_PERIODS = new Set<number>([15, 30, 60]);

/** Parse an otpauth:// URI into structured fields. Returns null if invalid. */
export function parseOtpAuthUri(uri: string): ParsedOtpAuth | null {
  if (!uri || !uri.startsWith("otpauth://")) {
    return null;
  }

  // Split scheme from the rest: "totp/Label?params"
  const afterScheme = uri.slice("otpauth://".length);
  const slashIndex = afterScheme.indexOf("/");
  if (slashIndex === -1) {
    return null;
  }

  const type = afterScheme.slice(0, slashIndex).toLowerCase();
  if (!VALID_TYPES.has(type)) {
    return null;
  }

  // Split path from query
  const rest = afterScheme.slice(slashIndex + 1);
  if (!rest) {
    return null;
  }

  const questionIndex = rest.indexOf("?");
  if (questionIndex === -1) {
    return null;
  }

  const labelRaw = rest.slice(0, questionIndex);
  const queryString = rest.slice(questionIndex + 1);

  // Parse label: "Issuer:Account" or just "Account"
  // Strategy: try literal colon first (preserves encoded colons in issuer),
  // then fall back to decoded colon splitting.
  const colonIndex = labelRaw.indexOf(":");
  let labelIssuer = "";
  let name: string;

  if (colonIndex !== -1) {
    labelIssuer = decodeURIComponent(labelRaw.slice(0, colonIndex));
    name = decodeURIComponent(labelRaw.slice(colonIndex + 1));
  } else {
    const decoded = decodeURIComponent(labelRaw);
    const decodedColon = decoded.indexOf(":");
    if (decodedColon !== -1) {
      labelIssuer = decoded.slice(0, decodedColon);
      name = decoded.slice(decodedColon + 1);
    } else {
      name = decoded;
    }
  }

  // Parse query parameters
  const params = new URLSearchParams(queryString);

  const secret = (params.get("secret") ?? "").trim().toUpperCase();
  if (!secret) {
    return null;
  }

  // URLSearchParams.get() already returns decoded values — do NOT double-decode
  const paramIssuer = params.get("issuer");
  const issuer = paramIssuer ?? labelIssuer;

  const algorithmRaw = (params.get("algorithm") ?? "sha1").toLowerCase();
  const algorithm = VALID_ALGORITHMS[algorithmRaw] ?? "SHA1";

  const digitsRaw = parseInt(params.get("digits") ?? "6", 10);
  const digits: OtpDigits = VALID_DIGITS.has(digitsRaw)
    ? (digitsRaw as OtpDigits)
    : 6;

  const periodRaw = parseInt(params.get("period") ?? "30", 10);
  const period: OtpPeriod = VALID_PERIODS.has(periodRaw)
    ? (periodRaw as OtpPeriod)
    : 30;

  const counter = parseInt(params.get("counter") ?? "0", 10) || 0;

  return {
    type: type as OtpType,
    name,
    issuer,
    secret,
    algorithm,
    digits,
    period,
    counter,
  };
}

/** Input for building an otpauth:// URI. */
export interface OtpAuthBuildInput {
  type: OtpType;
  name: string;
  issuer?: string;
  secret: string;
  algorithm?: string;
  digits?: number;
  period?: number;
  counter?: number;
}

/** Build a standard otpauth:// URI from structured fields. */
export function buildOtpAuthUri(input: OtpAuthBuildInput): string {
  const { type, name, secret, issuer } = input;
  const algorithm = input.algorithm ?? "SHA1";
  const digits = input.digits ?? 6;
  const period = input.period ?? 30;
  const counter = input.counter ?? 0;

  // Build label: "Issuer:Name" or just "Name"
  const label = issuer
    ? `${encodeURIComponent(issuer)}:${encodeURIComponent(name)}`
    : encodeURIComponent(name);

  // Build query params — omit defaults to keep URI compact
  const params = new URLSearchParams();
  params.set("secret", secret);
  if (issuer) params.set("issuer", issuer);
  if (algorithm !== "SHA1") params.set("algorithm", algorithm);
  if (digits !== 6) params.set("digits", String(digits));
  if (type === "totp" && period !== 30) params.set("period", String(period));
  if (type === "hotp") params.set("counter", String(counter));

  return `otpauth://${type}/${label}?${params.toString()}`;
}

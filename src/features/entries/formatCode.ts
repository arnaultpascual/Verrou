/** Format a TOTP/HOTP code string with digit grouping for display. */
export function formatTotpCode(code: string, digits: number): string {
  if (code.length !== digits) return code;
  const split = digits === 8 ? 4 : 3;
  return code.slice(0, split) + " " + code.slice(split);
}

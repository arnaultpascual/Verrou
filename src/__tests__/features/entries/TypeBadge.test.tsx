import { render } from "@solidjs/testing-library";
import { describe, expect, it } from "vitest";
import { TypeBadge } from "../../../features/entries/TypeBadge";

describe("TypeBadge", () => {
  describe("renders correct label for each entry type", () => {
    it("renders TOTP badge", () => {
      render(() => <TypeBadge entryType="totp" />);
      expect(document.body.textContent).toContain("TOTP");
    });

    it("renders HOTP badge", () => {
      render(() => <TypeBadge entryType="hotp" />);
      expect(document.body.textContent).toContain("HOTP");
    });

    it("renders Seed Phrase badge", () => {
      render(() => <TypeBadge entryType="seed_phrase" />);
      expect(document.body.textContent).toContain("Seed");
    });

    it("renders Recovery Code badge", () => {
      render(() => <TypeBadge entryType="recovery_code" />);
      expect(document.body.textContent).toContain("Recovery");
    });

    it("renders Secure Note badge", () => {
      render(() => <TypeBadge entryType="secure_note" />);
      expect(document.body.textContent).toContain("Note");
    });
  });

  describe("renders correct icon for each entry type", () => {
    it("renders lock icon for TOTP", () => {
      render(() => <TypeBadge entryType="totp" />);
      const svg = document.querySelector("svg");
      expect(svg).toBeTruthy();
      expect(svg?.getAttribute("aria-hidden")).toBe("true");
    });

    it("renders lock icon for HOTP", () => {
      render(() => <TypeBadge entryType="hotp" />);
      const svg = document.querySelector("svg");
      expect(svg).toBeTruthy();
    });

    it("renders shield icon for seed_phrase", () => {
      render(() => <TypeBadge entryType="seed_phrase" />);
      const svg = document.querySelector("svg");
      expect(svg).toBeTruthy();
    });
  });

  describe("applies type-specific accent color", () => {
    it("applies totp accent via CSS variable", () => {
      render(() => <TypeBadge entryType="totp" />);
      const badge = document.querySelector("[data-type='totp']");
      expect(badge).toBeTruthy();
    });

    it("applies seed accent via data attribute", () => {
      render(() => <TypeBadge entryType="seed_phrase" />);
      const badge = document.querySelector("[data-type='seed_phrase']");
      expect(badge).toBeTruthy();
    });

    it("applies recovery accent via data attribute", () => {
      render(() => <TypeBadge entryType="recovery_code" />);
      const badge = document.querySelector("[data-type='recovery_code']");
      expect(badge).toBeTruthy();
    });

    it("applies note accent via data attribute", () => {
      render(() => <TypeBadge entryType="secure_note" />);
      const badge = document.querySelector("[data-type='secure_note']");
      expect(badge).toBeTruthy();
    });
  });

  describe("handles unknown types gracefully", () => {
    it("renders fallback for unknown type", () => {
      render(() => <TypeBadge entryType="unknown_type" />);
      expect(document.body.textContent).toContain("Other");
    });
  });
});

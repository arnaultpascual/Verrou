import { render, fireEvent, screen } from "@solidjs/testing-library";
import { describe, expect, it, vi } from "vitest";
import { PasswordGenerator } from "../../../features/credentials/PasswordGenerator";

describe("PasswordGenerator", () => {
  const defaultProps = {
    onUse: vi.fn(),
  };

  describe("rendering", () => {
    it("renders collapsed by default", () => {
      render(() => <PasswordGenerator {...defaultProps} />);
      const header = screen.getByRole("button", { name: /password generator/i });
      expect(header).toBeDefined();
      expect(header.getAttribute("aria-expanded")).toBe("false");
      // Body should not be visible
      expect(screen.queryByText("Random")).toBeNull();
    });

    it("renders expanded when defaultExpanded is true", () => {
      render(() => <PasswordGenerator {...defaultProps} defaultExpanded />);
      const header = screen.getByRole("button", { name: /password generator/i });
      expect(header.getAttribute("aria-expanded")).toBe("true");
      // Body should be visible
      expect(screen.getByText("Random")).toBeDefined();
      expect(screen.getByText("Passphrase")).toBeDefined();
    });
  });

  describe("expand/collapse", () => {
    it("expands on header click", async () => {
      render(() => <PasswordGenerator {...defaultProps} />);
      const header = screen.getByRole("button", { name: /password generator/i });

      await fireEvent.click(header);
      expect(header.getAttribute("aria-expanded")).toBe("true");
      expect(screen.getByText("Random")).toBeDefined();
    });

    it("collapses on second header click", async () => {
      render(() => <PasswordGenerator {...defaultProps} defaultExpanded />);
      const header = screen.getByRole("button", { name: /password generator/i });

      await fireEvent.click(header);
      expect(header.getAttribute("aria-expanded")).toBe("false");
      expect(screen.queryByText("Random")).toBeNull();
    });
  });

  describe("mode toggle", () => {
    it("defaults to random mode", () => {
      render(() => <PasswordGenerator {...defaultProps} defaultExpanded />);
      const randomBtn = screen.getByRole("radio", { name: "Random" });
      expect(randomBtn.getAttribute("aria-checked")).toBe("true");
    });

    it("switches to passphrase mode", async () => {
      render(() => <PasswordGenerator {...defaultProps} defaultExpanded />);
      const passphraseBtn = screen.getByRole("radio", { name: "Passphrase" });
      await fireEvent.click(passphraseBtn);
      expect(passphraseBtn.getAttribute("aria-checked")).toBe("true");
      // Passphrase options should be visible
      expect(screen.getByText("Words")).toBeDefined();
      expect(screen.getByText("Separator")).toBeDefined();
    });

    it("shows length slider in random mode", () => {
      render(() => <PasswordGenerator {...defaultProps} defaultExpanded />);
      expect(screen.getByText("Length")).toBeDefined();
    });

    it("shows charset checkboxes in random mode", () => {
      render(() => <PasswordGenerator {...defaultProps} defaultExpanded />);
      expect(screen.getByText("A-Z")).toBeDefined();
      expect(screen.getByText("a-z")).toBeDefined();
      expect(screen.getByText("0-9")).toBeDefined();
      expect(screen.getByText("!@#$")).toBeDefined();
    });
  });

  describe("charset guard (H3 fix)", () => {
    it("all 4 checkboxes start enabled", () => {
      render(() => <PasswordGenerator {...defaultProps} defaultExpanded />);
      const checkboxes = document.querySelectorAll("input[type='checkbox']");
      // In random mode there are 4 charset checkboxes
      const charsetBoxes = Array.from(checkboxes).slice(0, 4);
      for (const cb of charsetBoxes) {
        expect((cb as HTMLInputElement).checked).toBe(true);
      }
    });

    it("disables last remaining checkbox", async () => {
      render(() => <PasswordGenerator {...defaultProps} defaultExpanded />);
      const checkboxes = Array.from(
        document.querySelectorAll("input[type='checkbox']"),
      ) as HTMLInputElement[];

      // Uncheck first 3 (A-Z, a-z, 0-9), leaving !@#$ as last
      await fireEvent.click(checkboxes[0]); // uncheck A-Z
      await fireEvent.click(checkboxes[1]); // uncheck a-z
      await fireEvent.click(checkboxes[2]); // uncheck 0-9

      // The last checkbox (!@#$) should be disabled
      expect(checkboxes[3].disabled).toBe(true);
    });
  });

  describe("actions", () => {
    it("has a regenerate button", () => {
      render(() => <PasswordGenerator {...defaultProps} defaultExpanded />);
      expect(screen.getByLabelText("Regenerate")).toBeDefined();
    });

    it("has a copy button", () => {
      render(() => <PasswordGenerator {...defaultProps} defaultExpanded />);
      expect(screen.getByLabelText("Copy to clipboard")).toBeDefined();
    });

    it("has a use button", () => {
      render(() => <PasswordGenerator {...defaultProps} defaultExpanded />);
      expect(screen.getByText("Use this password")).toBeDefined();
    });

    it("calls onUse when use button is clicked with a generated value", async () => {
      const onUse = vi.fn();
      render(() => <PasswordGenerator onUse={onUse} defaultExpanded />);

      // Wait for the auto-generate effect to fire
      await new Promise((r) => setTimeout(r, 100));

      const useBtn = screen.getByText("Use this password");
      await fireEvent.click(useBtn);

      expect(onUse).toHaveBeenCalledTimes(1);
      expect(typeof onUse.mock.calls[0][0]).toBe("string");
      expect(onUse.mock.calls[0][0].length).toBeGreaterThan(0);
    });
  });

  describe("strength meter", () => {
    it("shows strength label when expanded", () => {
      render(() => <PasswordGenerator {...defaultProps} defaultExpanded />);
      // One of the strength labels should be present
      const labels = ["Weak", "Fair", "Good", "Excellent"];
      const found = labels.some((label) => screen.queryByText(label) !== null);
      expect(found).toBe(true);
    });

    it("has a progressbar for strength", () => {
      render(() => <PasswordGenerator {...defaultProps} defaultExpanded />);
      const progressbar = document.querySelector("[role='progressbar']");
      expect(progressbar).not.toBeNull();
    });
  });

  describe("passphrase mode options", () => {
    it("shows capitalize and append digit checkboxes", async () => {
      render(() => <PasswordGenerator {...defaultProps} defaultExpanded />);
      const passphraseBtn = screen.getByRole("radio", { name: "Passphrase" });
      await fireEvent.click(passphraseBtn);

      expect(screen.getByText("Capitalize")).toBeDefined();
      expect(screen.getByText("Append digit")).toBeDefined();
    });

    it("shows separator dropdown with all options", async () => {
      render(() => <PasswordGenerator {...defaultProps} defaultExpanded />);
      const passphraseBtn = screen.getByRole("radio", { name: "Passphrase" });
      await fireEvent.click(passphraseBtn);

      const select = document.querySelector("select") as HTMLSelectElement;
      expect(select).not.toBeNull();
      expect(select.options.length).toBe(5); // hyphen, space, dot, underscore, none
    });
  });

  describe("accessibility", () => {
    it("header has aria-expanded attribute", () => {
      render(() => <PasswordGenerator {...defaultProps} />);
      const header = screen.getByRole("button", { name: /password generator/i });
      expect(header.hasAttribute("aria-expanded")).toBe(true);
    });

    it("mode toggle has radiogroup role", () => {
      render(() => <PasswordGenerator {...defaultProps} defaultExpanded />);
      const radiogroup = document.querySelector("[role='radiogroup']");
      expect(radiogroup).not.toBeNull();
    });

    it("mode buttons have radio role", () => {
      render(() => <PasswordGenerator {...defaultProps} defaultExpanded />);
      const radios = screen.getAllByRole("radio");
      expect(radios.length).toBe(2);
    });

    it("sliders have associated labels", () => {
      render(() => <PasswordGenerator {...defaultProps} defaultExpanded />);
      const lengthSlider = document.getElementById("pw-length");
      expect(lengthSlider).not.toBeNull();
      const label = document.querySelector("label[for='pw-length']");
      expect(label).not.toBeNull();
    });
  });
});

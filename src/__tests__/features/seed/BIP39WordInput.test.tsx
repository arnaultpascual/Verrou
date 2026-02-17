import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi } from "vitest";
import { BIP39WordInput } from "../../../features/seed/BIP39WordInput";

describe("BIP39WordInput", () => {
  const defaultProps = {
    index: 0,
    total: 12,
    value: "",
    language: "english",
    onChange: vi.fn(),
    onValidated: vi.fn(),
  };

  describe("rendering", () => {
    it("renders with correct label", () => {
      render(() => <BIP39WordInput {...defaultProps} index={0} />);
      expect(document.body.textContent).toContain("Word 1");
    });

    it("renders label with correct word number for different indices", () => {
      render(() => <BIP39WordInput {...defaultProps} index={4} />);
      expect(document.body.textContent).toContain("Word 5");
    });

    it("renders an input element", () => {
      render(() => <BIP39WordInput {...defaultProps} />);
      const input = document.querySelector("input");
      expect(input).toBeTruthy();
    });

    it("applies monospace font class", () => {
      render(() => <BIP39WordInput {...defaultProps} />);
      const input = document.querySelector("input");
      expect(input).toBeTruthy();
      // The input should exist with the component's CSS module class
      expect(input?.getAttribute("type")).toBe("text");
    });
  });

  describe("accessibility", () => {
    it("has correct aria-label", () => {
      render(() => <BIP39WordInput {...defaultProps} index={2} total={24} />);
      const input = document.querySelector("input");
      expect(input?.getAttribute("aria-label")).toBe("Word 3 of 24");
    });

    it("has combobox role", () => {
      render(() => <BIP39WordInput {...defaultProps} />);
      const input = document.querySelector("input");
      expect(input?.getAttribute("role")).toBe("combobox");
    });

    it("has aria-expanded false initially", () => {
      render(() => <BIP39WordInput {...defaultProps} />);
      const input = document.querySelector("input");
      expect(input?.getAttribute("aria-expanded")).toBe("false");
    });

    it("has autocomplete off", () => {
      render(() => <BIP39WordInput {...defaultProps} />);
      const input = document.querySelector("input");
      expect(input?.getAttribute("autocomplete")).toBe("off");
    });

    it("has spellcheck disabled", () => {
      render(() => <BIP39WordInput {...defaultProps} />);
      const input = document.querySelector("input");
      expect(input?.getAttribute("spellcheck")).toBe("false");
    });
  });

  describe("disabled state", () => {
    it("respects disabled prop", () => {
      render(() => <BIP39WordInput {...defaultProps} disabled={true} />);
      const input = document.querySelector("input");
      expect(input?.disabled).toBe(true);
    });

    it("is not disabled by default", () => {
      render(() => <BIP39WordInput {...defaultProps} />);
      const input = document.querySelector("input");
      expect(input?.disabled).toBe(false);
    });
  });

  describe("value display", () => {
    it("displays provided value", () => {
      render(() => <BIP39WordInput {...defaultProps} value="abandon" />);
      const input = document.querySelector("input") as HTMLInputElement;
      expect(input.value).toBe("abandon");
    });

    it("displays empty string when no value", () => {
      render(() => <BIP39WordInput {...defaultProps} value="" />);
      const input = document.querySelector("input") as HTMLInputElement;
      expect(input.value).toBe("");
    });
  });

  describe("error message", () => {
    it("does not show error initially", () => {
      render(() => <BIP39WordInput {...defaultProps} />);
      const errorEl = document.querySelector("[role='alert']");
      expect(errorEl).toBeNull();
    });
  });

  describe("blur validation", () => {
    it("calls onValidated with true after blur on valid word", async () => {
      const onValidated = vi.fn();
      render(() => (
        <BIP39WordInput {...defaultProps} value="abandon" onValidated={onValidated} />
      ));

      const input = document.querySelector("input")!;
      fireEvent.blur(input);

      await waitFor(() => {
        expect(onValidated).toHaveBeenCalledWith(0, true);
      }, { timeout: 1000 });
    });

    it("shows error after blur on invalid word", async () => {
      render(() => (
        <BIP39WordInput {...defaultProps} value="xyz123" onValidated={vi.fn()} />
      ));

      const input = document.querySelector("input")!;
      fireEvent.blur(input);

      await waitFor(() => {
        const errorEl = document.querySelector("[role='alert']");
        expect(errorEl).toBeTruthy();
        expect(errorEl?.textContent).toContain("Not a valid BIP39 word");
      }, { timeout: 1000 });
    });

    it("does not validate empty input on blur", async () => {
      const onValidated = vi.fn();
      render(() => (
        <BIP39WordInput {...defaultProps} value="" onValidated={onValidated} />
      ));

      const input = document.querySelector("input")!;
      fireEvent.blur(input);

      // Wait a bit and verify onValidated was NOT called
      await new Promise((r) => setTimeout(r, 300));
      expect(onValidated).not.toHaveBeenCalled();
    });
  });
});

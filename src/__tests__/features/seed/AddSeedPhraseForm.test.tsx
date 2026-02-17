import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi } from "vitest";
import { AddSeedPhraseForm } from "../../../features/seed/AddSeedPhraseForm";

// Mock the toast hook
vi.mock("../../../components/useToast", () => ({
  useToast: () => ({
    success: vi.fn(),
    error: vi.fn(),
  }),
}));

describe("AddSeedPhraseForm", () => {
  const defaultProps = {
    open: true,
    onClose: vi.fn(),
    onSuccess: vi.fn(),
  };

  describe("rendering", () => {
    it("renders modal title", () => {
      render(() => <AddSeedPhraseForm {...defaultProps} />);
      expect(document.body.textContent).toContain("Add Seed Phrase");
    });

    it("renders word count selector", () => {
      render(() => <AddSeedPhraseForm {...defaultProps} />);
      const selects = document.querySelectorAll("select");
      const wordCountSelect = Array.from(selects).find((s) =>
        s.id?.includes("word-count"),
      );
      expect(wordCountSelect).toBeTruthy();
    });

    it("renders language selector", () => {
      render(() => <AddSeedPhraseForm {...defaultProps} />);
      const selects = document.querySelectorAll("select");
      const langSelect = Array.from(selects).find((s) =>
        s.id?.includes("language"),
      );
      expect(langSelect).toBeTruthy();
    });

    it("renders word count selector with 5 options", () => {
      render(() => <AddSeedPhraseForm {...defaultProps} />);
      const selects = document.querySelectorAll("select");
      const wordCountSelect = Array.from(selects).find((s) =>
        s.id?.includes("word-count"),
      );
      const options = wordCountSelect?.querySelectorAll("option");
      expect(options?.length).toBe(5);
    });

    it("renders language selector with 10 options", () => {
      render(() => <AddSeedPhraseForm {...defaultProps} />);
      const selects = document.querySelectorAll("select");
      const langSelect = Array.from(selects).find((s) =>
        s.id?.includes("language"),
      );
      const options = langSelect?.querySelectorAll("option");
      expect(options?.length).toBe(10);
    });

    it("renders 12 word inputs by default", () => {
      render(() => <AddSeedPhraseForm {...defaultProps} />);
      // 12 BIP39 word inputs + 2 metadata inputs (name, issuer) = 14 text inputs total
      // Use combobox role to identify just the BIP39 word inputs
      const wordInputs = document.querySelectorAll("input[role='combobox']");
      expect(wordInputs.length).toBe(12);
    });

    it("renders wallet name input", () => {
      render(() => <AddSeedPhraseForm {...defaultProps} />);
      expect(document.body.textContent).toContain("Wallet Name");
    });

    it("renders issuer input", () => {
      render(() => <AddSeedPhraseForm {...defaultProps} />);
      expect(document.body.textContent).toContain("Issuer");
    });
  });

  describe("passphrase toggle", () => {
    it("renders passphrase checkbox", () => {
      render(() => <AddSeedPhraseForm {...defaultProps} />);
      expect(document.body.textContent).toContain("BIP39 passphrase");
    });

    it("does not show passphrase input by default", () => {
      render(() => <AddSeedPhraseForm {...defaultProps} />);
      expect(document.body.textContent).not.toContain("BIP39 Passphrase");
    });
  });

  describe("buttons", () => {
    it("renders save button", () => {
      render(() => <AddSeedPhraseForm {...defaultProps} />);
      expect(document.body.textContent).toContain("Save Seed Phrase");
    });

    it("renders cancel button", () => {
      render(() => <AddSeedPhraseForm {...defaultProps} />);
      expect(document.body.textContent).toContain("Cancel");
    });
  });

  describe("closed state", () => {
    it("does not render content when closed", () => {
      render(() => (
        <AddSeedPhraseForm {...defaultProps} open={false} />
      ));
      // Modal should not render its content when closed
      const selects = document.querySelectorAll("select");
      expect(selects.length).toBe(0);
    });
  });

  describe("interaction", () => {
    it("updates word inputs when word count changes to 24", async () => {
      render(() => <AddSeedPhraseForm {...defaultProps} />);

      // Initially 12 word inputs
      expect(document.querySelectorAll("input[role='combobox']").length).toBe(12);

      // Change word count to 24
      const wordCountSelect = Array.from(document.querySelectorAll("select"))
        .find((s) => s.id?.includes("word-count"));
      fireEvent.change(wordCountSelect!, { target: { value: "24" } });

      await waitFor(() => {
        expect(document.querySelectorAll("input[role='combobox']").length).toBe(24);
      });
    });

    it("updates word inputs when word count changes to 15", async () => {
      render(() => <AddSeedPhraseForm {...defaultProps} />);

      const wordCountSelect = Array.from(document.querySelectorAll("select"))
        .find((s) => s.id?.includes("word-count"));
      fireEvent.change(wordCountSelect!, { target: { value: "15" } });

      await waitFor(() => {
        expect(document.querySelectorAll("input[role='combobox']").length).toBe(15);
      });
    });
  });
});

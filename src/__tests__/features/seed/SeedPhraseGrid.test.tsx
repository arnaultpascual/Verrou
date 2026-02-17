import { render } from "@solidjs/testing-library";
import { describe, expect, it, vi } from "vitest";
import { SeedPhraseGrid } from "../../../features/seed/SeedPhraseGrid";

describe("SeedPhraseGrid", () => {
  const defaultProps = {
    wordCount: 12,
    language: "english",
    words: Array(12).fill(""),
    onWordsChange: vi.fn(),
    validationStates: Array(12).fill(false),
    onWordValidated: vi.fn(),
  };

  describe("renders correct number of inputs", () => {
    it("renders 12 inputs for 12-word count", () => {
      render(() => <SeedPhraseGrid {...defaultProps} wordCount={12} />);
      const inputs = document.querySelectorAll("input[type='text']");
      expect(inputs.length).toBe(12);
    });

    it("renders 15 inputs for 15-word count", () => {
      const words = Array(15).fill("");
      const states = Array(15).fill(false);
      render(() => (
        <SeedPhraseGrid
          {...defaultProps}
          wordCount={15}
          words={words}
          validationStates={states}
        />
      ));
      const inputs = document.querySelectorAll("input[type='text']");
      expect(inputs.length).toBe(15);
    });

    it("renders 24 inputs for 24-word count", () => {
      const words = Array(24).fill("");
      const states = Array(24).fill(false);
      render(() => (
        <SeedPhraseGrid
          {...defaultProps}
          wordCount={24}
          words={words}
          validationStates={states}
        />
      ));
      const inputs = document.querySelectorAll("input[type='text']");
      expect(inputs.length).toBe(24);
    });
  });

  describe("completion indicator", () => {
    it("shows 0 of N words entered when empty", () => {
      render(() => <SeedPhraseGrid {...defaultProps} />);
      expect(document.body.textContent).toContain("0 of 12 words entered");
    });

    it("shows correct count when some words entered", () => {
      const words = ["abandon", "ability", "", "", "", "", "", "", "", "", "", ""];
      render(() => (
        <SeedPhraseGrid {...defaultProps} words={words} />
      ));
      expect(document.body.textContent).toContain("2 of 12 words entered");
    });

    it("shows all words entered when complete", () => {
      const words = Array(12).fill("abandon");
      render(() => (
        <SeedPhraseGrid {...defaultProps} words={words} />
      ));
      expect(document.body.textContent).toContain("12 of 12 words entered");
    });
  });

  describe("layout", () => {
    it("renders a grid container", () => {
      render(() => <SeedPhraseGrid {...defaultProps} />);
      // The grid container should have the grid class applied
      const gridDiv = document.querySelector("div > div");
      expect(gridDiv).toBeTruthy();
    });
  });

  describe("word labels", () => {
    it("renders sequential word labels", () => {
      render(() => <SeedPhraseGrid {...defaultProps} wordCount={4} words={Array(4).fill("")} validationStates={Array(4).fill(false)} />);
      expect(document.body.textContent).toContain("Word 1");
      expect(document.body.textContent).toContain("Word 2");
      expect(document.body.textContent).toContain("Word 3");
      expect(document.body.textContent).toContain("Word 4");
    });
  });

  describe("disabled state", () => {
    it("passes disabled to all inputs", () => {
      render(() => <SeedPhraseGrid {...defaultProps} disabled={true} />);
      const inputs = document.querySelectorAll("input[type='text']");
      for (const input of inputs) {
        expect((input as HTMLInputElement).disabled).toBe(true);
      }
    });
  });
});

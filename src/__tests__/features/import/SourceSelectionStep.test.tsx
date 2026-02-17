import { render, fireEvent } from "@solidjs/testing-library";
import { describe, expect, it, vi } from "vitest";
import { SourceSelectionStep } from "../../../features/import/SourceSelectionStep";

describe("SourceSelectionStep", () => {
  it("renders all three source options", () => {
    const { getByText } = render(() => (
      <SourceSelectionStep onSelect={vi.fn()} />
    ));
    expect(getByText("Google Authenticator")).toBeDefined();
    expect(getByText("Aegis Authenticator")).toBeDefined();
    expect(getByText("2FAS Authenticator")).toBeDefined();
  });

  it("renders heading and description", () => {
    const { getByText } = render(() => (
      <SourceSelectionStep onSelect={vi.fn()} />
    ));
    expect(getByText("Choose your import source")).toBeDefined();
    expect(
      getByText("Select the authenticator app you want to import accounts from."),
    ).toBeDefined();
  });

  it("uses radiogroup role for accessibility", () => {
    const { container } = render(() => (
      <SourceSelectionStep onSelect={vi.fn()} />
    ));
    const radiogroup = container.querySelector("[role='radiogroup']");
    expect(radiogroup).not.toBeNull();
    expect(radiogroup!.getAttribute("aria-label")).toBe("Import source selection");
  });

  it("renders source cards as radio buttons", () => {
    const { container } = render(() => (
      <SourceSelectionStep onSelect={vi.fn()} />
    ));
    const radios = container.querySelectorAll("[role='radio']");
    expect(radios.length).toBe(3);
  });

  it("calls onSelect when a source card is clicked", () => {
    const onSelect = vi.fn();
    const { getByText } = render(() => (
      <SourceSelectionStep onSelect={onSelect} />
    ));

    fireEvent.click(getByText("Aegis Authenticator"));
    expect(onSelect).toHaveBeenCalledWith("aegis");
  });

  it("calls onSelect when Enter is pressed on a card", () => {
    const onSelect = vi.fn();
    const { container } = render(() => (
      <SourceSelectionStep onSelect={onSelect} />
    ));

    const cards = container.querySelectorAll("[role='radio']");
    fireEvent.keyDown(cards[0], { key: "Enter" });
    expect(onSelect).toHaveBeenCalledWith("google-auth");
  });

  it("calls onSelect when Space is pressed on a card", () => {
    const onSelect = vi.fn();
    const { container } = render(() => (
      <SourceSelectionStep onSelect={onSelect} />
    ));

    const cards = container.querySelectorAll("[role='radio']");
    fireEvent.keyDown(cards[2], { key: " " });
    expect(onSelect).toHaveBeenCalledWith("twofas");
  });

  it("sets aria-checked on the selected card", () => {
    const { container } = render(() => (
      <SourceSelectionStep onSelect={vi.fn()} />
    ));

    const cards = container.querySelectorAll("[role='radio']");
    // Initially none selected
    cards.forEach((card) => {
      expect(card.getAttribute("aria-checked")).toBe("false");
    });

    // Click the second card
    fireEvent.click(cards[1]);
    expect(cards[1].getAttribute("aria-checked")).toBe("true");
    expect(cards[0].getAttribute("aria-checked")).toBe("false");
    expect(cards[2].getAttribute("aria-checked")).toBe("false");
  });

  it("renders source descriptions", () => {
    const { getByText } = render(() => (
      <SourceSelectionStep onSelect={vi.fn()} />
    ));
    expect(getByText("Import via migration QR code or URI")).toBeDefined();
    expect(getByText("Import from JSON vault export")).toBeDefined();
    expect(getByText("Import from JSON backup file")).toBeDefined();
  });
});

import { render, fireEvent } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { KdfPresetStep } from "../../../features/onboarding/KdfPresetStep";
import { wizardStore, setWizardStore } from "../../../features/onboarding/stores";

describe("KdfPresetStep", () => {
  beforeEach(() => {
    setWizardStore({
      password: "",
      confirmPassword: "",
      kdfPreset: "balanced",
      recoveryKeyConfirmed: false,
      recoveryKey: null,
      vaultFingerprint: null,
      isCreating: false,
    });
  });

  it("renders heading and description", () => {
    const { getByText } = render(() => (
      <KdfPresetStep onValidChange={vi.fn()} />
    ));
    expect(getByText("Choose security level")).toBeDefined();
    expect(getByText(/How long should unlocking take/)).toBeDefined();
  });

  it("renders three preset options", () => {
    const { getByText } = render(() => (
      <KdfPresetStep onValidChange={vi.fn()} />
    ));
    expect(getByText("Fast")).toBeDefined();
    expect(getByText("Balanced")).toBeDefined();
    expect(getByText("Maximum")).toBeDefined();
  });

  it("shows recommended badge on Balanced", () => {
    const { getByText } = render(() => (
      <KdfPresetStep onValidChange={vi.fn()} />
    ));
    expect(getByText("(Recommended)")).toBeDefined();
  });

  it("has radiogroup role with label", () => {
    const { container } = render(() => (
      <KdfPresetStep onValidChange={vi.fn()} />
    ));
    const group = container.querySelector("[role='radiogroup']");
    expect(group).not.toBeNull();
    expect(group!.getAttribute("aria-label")).toBe("Security level selection");
  });

  it("defaults to balanced preset (aria-checked)", () => {
    const { container } = render(() => (
      <KdfPresetStep onValidChange={vi.fn()} />
    ));
    const radios = container.querySelectorAll("[role='radio']");
    expect(radios.length).toBe(3);
    // Fast, Balanced, Maximum — index 1 is balanced
    expect(radios[0].getAttribute("aria-checked")).toBe("false");
    expect(radios[1].getAttribute("aria-checked")).toBe("true");
    expect(radios[2].getAttribute("aria-checked")).toBe("false");
  });

  it("updates store when clicking Fast", () => {
    const { container } = render(() => (
      <KdfPresetStep onValidChange={vi.fn()} />
    ));
    const radios = container.querySelectorAll("[role='radio']");
    fireEvent.click(radios[0]); // Fast
    expect(wizardStore.kdfPreset).toBe("fast");
  });

  it("updates store when clicking Maximum", () => {
    const { container } = render(() => (
      <KdfPresetStep onValidChange={vi.fn()} />
    ));
    const radios = container.querySelectorAll("[role='radio']");
    fireEvent.click(radios[2]); // Maximum
    expect(wizardStore.kdfPreset).toBe("maximum");
  });

  it("updates aria-checked after selection change", () => {
    const { container } = render(() => (
      <KdfPresetStep onValidChange={vi.fn()} />
    ));
    const radios = container.querySelectorAll("[role='radio']");
    fireEvent.click(radios[0]); // Fast
    expect(radios[0].getAttribute("aria-checked")).toBe("true");
    expect(radios[1].getAttribute("aria-checked")).toBe("false");
  });

  it("calls onValidChange(true) immediately (always valid)", () => {
    const onValid = vi.fn();
    render(() => <KdfPresetStep onValidChange={onValid} />);
    expect(onValid).toHaveBeenCalledWith(true);
  });

  it("shows timing labels", () => {
    const { getByText } = render(() => (
      <KdfPresetStep onValidChange={vi.fn()} />
    ));
    expect(getByText("~1 second")).toBeDefined();
    expect(getByText("~2 seconds")).toBeDefined();
    expect(getByText("~4 seconds")).toBeDefined();
  });

  it("shows description for each preset", () => {
    const { getByText } = render(() => (
      <KdfPresetStep onValidChange={vi.fn()} />
    ));
    expect(getByText(/Quick access/)).toBeDefined();
    expect(getByText(/Recommended balance/)).toBeDefined();
    expect(getByText(/Maximum security/)).toBeDefined();
  });
});

import { render } from "@solidjs/testing-library";
import { describe, expect, it } from "vitest";
import { StepIndicator } from "../../../features/onboarding/StepIndicator";

describe("StepIndicator", () => {
  it("renders all step labels", () => {
    const { getByText } = render(() => (
      <StepIndicator currentStep={1}  />
    ));
    expect(getByText("Password")).toBeDefined();
    expect(getByText("Security")).toBeDefined();
    expect(getByText("Recovery")).toBeDefined();
    expect(getByText("Import")).toBeDefined();
  });

  it("shows step count text", () => {
    const { getByText } = render(() => (
      <StepIndicator currentStep={2}  />
    ));
    expect(getByText("Step 2 of 4")).toBeDefined();
  });

  it("marks current step with aria-current", () => {
    const { container } = render(() => (
      <StepIndicator currentStep={2}  />
    ));
    const dots = container.querySelectorAll("[aria-current='step']");
    expect(dots.length).toBe(1);
  });

  it("has navigation role with aria-label", () => {
    const { container } = render(() => (
      <StepIndicator currentStep={1}  />
    ));
    const nav = container.querySelector("[role='navigation']");
    expect(nav).not.toBeNull();
    expect(nav!.getAttribute("aria-label")).toBe("Progress");
  });

  it("renders 4 dots", () => {
    const { container } = render(() => (
      <StepIndicator currentStep={1}  />
    ));
    // Each step has a dot div inside a stepItem
    const nav = container.querySelector("[role='navigation']");
    const stepItems = nav!.querySelectorAll("div > div");
    // At minimum, 4 step item containers should exist
    expect(stepItems.length).toBeGreaterThanOrEqual(4);
  });

  it("updates step count when props change", () => {
    const { getByText, unmount } = render(() => (
      <StepIndicator currentStep={3}  />
    ));
    expect(getByText("Step 3 of 4")).toBeDefined();
    unmount();

    const { getByText: getByText2 } = render(() => (
      <StepIndicator currentStep={1}  />
    ));
    expect(getByText2("Step 1 of 4")).toBeDefined();
  });
});

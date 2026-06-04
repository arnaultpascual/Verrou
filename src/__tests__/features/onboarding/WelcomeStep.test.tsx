import { render, fireEvent } from "@solidjs/testing-library";
import { describe, expect, it, vi } from "vitest";
import { WelcomeStep } from "../../../features/onboarding/WelcomeStep";

describe("WelcomeStep", () => {
  it("renders the value proposition", () => {
    const { getByText } = render(() => <WelcomeStep onStart={vi.fn()} />);
    expect(getByText("Your vault, and only yours")).toBeDefined();
    expect(getByText("Offline by design — no servers, ever")).toBeDefined();
    expect(getByText("No account, no email, no tracking")).toBeDefined();
    expect(getByText("Post-quantum encryption built in")).toBeDefined();
  });

  it("calls onStart when Get started is clicked", () => {
    const onStart = vi.fn();
    const { getByText } = render(() => <WelcomeStep onStart={onStart} />);
    fireEvent.click(getByText("Get started"));
    expect(onStart).toHaveBeenCalled();
  });
});

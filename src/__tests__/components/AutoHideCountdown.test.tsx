import { render, fireEvent } from "@solidjs/testing-library";
import { describe, expect, it, vi } from "vitest";
import { createSignal as solidSignal } from "solid-js";
import { AutoHideCountdown } from "../../components/AutoHideCountdown";

describe("AutoHideCountdown", () => {
  it("renders the timer bar with a Hide button", () => {
    render(() => <AutoHideCountdown remainingMs={30_000} onHide={vi.fn()} />);

    expect(document.querySelector("[data-testid='auto-hide-countdown']")).toBeTruthy();
    expect(document.querySelector("[data-testid='auto-hide-hide-btn']")).toBeTruthy();
  });

  it("shows '{n}s' under a minute", () => {
    render(() => <AutoHideCountdown remainingMs={30_000} onHide={vi.fn()} />);
    expect(document.body.textContent).toContain("Hiding in 30s");
  });

  it("rounds up partial seconds", () => {
    render(() => <AutoHideCountdown remainingMs={29_400} onHide={vi.fn()} />);
    // ceil(29.4) = 30
    expect(document.body.textContent).toContain("Hiding in 30s");
  });

  it("shows mm:ss at a minute or more", () => {
    render(() => <AutoHideCountdown remainingMs={60_000} onHide={vi.fn()} />);
    expect(document.body.textContent).toContain("Hiding in 1:00");
  });

  it("pads the seconds in mm:ss", () => {
    render(() => <AutoHideCountdown remainingMs={65_000} onHide={vi.fn()} />);
    expect(document.body.textContent).toContain("Hiding in 1:05");
  });

  it("clamps negative time to 0s", () => {
    render(() => <AutoHideCountdown remainingMs={-500} onHide={vi.fn()} />);
    expect(document.body.textContent).toContain("Hiding in 0s");
  });

  it("announces the remaining time politely (aria-live)", () => {
    render(() => <AutoHideCountdown remainingMs={10_000} onHide={vi.fn()} />);
    const live = document.querySelector("[aria-live='polite']");
    expect(live).toBeTruthy();
    expect(live!.textContent).toContain("Hiding in 10s");
  });

  it("fires onHide when the Hide button is clicked", () => {
    const onHide = vi.fn();
    render(() => <AutoHideCountdown remainingMs={10_000} onHide={onHide} />);

    fireEvent.click(document.querySelector("[data-testid='auto-hide-hide-btn']")!);
    expect(onHide).toHaveBeenCalledTimes(1);
  });

  it("reactively updates the label when remainingMs changes", () => {
    const [ms, setMs] = solidSignal(20_000);
    render(() => <AutoHideCountdown remainingMs={ms()} onHide={vi.fn()} />);

    expect(document.body.textContent).toContain("Hiding in 20s");
    setMs(5_000);
    expect(document.body.textContent).toContain("Hiding in 5s");
  });
});

import { render } from "@solidjs/testing-library";
import { SecurityCeremony } from "../../components/SecurityCeremony";

describe("SecurityCeremony", () => {
  it("renders with progressbar role", () => {
    const { container } = render(() => <SecurityCeremony progress={50} />);
    const bar = container.querySelector("[role='progressbar']");
    expect(bar).toBeTruthy();
  });

  it("sets aria-valuenow to progress value", () => {
    const { container } = render(() => <SecurityCeremony progress={67} />);
    const bar = container.querySelector("[role='progressbar']")!;
    expect(bar.getAttribute("aria-valuenow")).toBe("67");
  });

  it("sets aria-valuemin and aria-valuemax", () => {
    const { container } = render(() => <SecurityCeremony progress={0} />);
    const bar = container.querySelector("[role='progressbar']")!;
    expect(bar.getAttribute("aria-valuemin")).toBe("0");
    expect(bar.getAttribute("aria-valuemax")).toBe("100");
  });

  it("has aria-label for accessibility", () => {
    const { container } = render(() => <SecurityCeremony progress={50} />);
    const bar = container.querySelector("[role='progressbar']")!;
    expect(bar.getAttribute("aria-label")).toBe("Verifying identity");
  });

  it("shows 'Verifying your identity...' when in progress", () => {
    const { container } = render(() => <SecurityCeremony progress={50} />);
    expect(container.textContent).toContain("Verifying your identity...");
  });

  it("shows 'Verified' when complete", () => {
    const { container } = render(() => <SecurityCeremony progress={100} />);
    expect(container.textContent).toContain("Verified");
  });

  it("shows explanation text during progress", () => {
    const { container } = render(() => <SecurityCeremony progress={50} />);
    expect(container.textContent).toContain("extra verification");
  });

  it("hides explanation text when complete", () => {
    const { container } = render(() => <SecurityCeremony progress={100} />);
    expect(container.textContent).not.toContain("extra verification");
  });

  it("shows shield icon during progress", () => {
    const { container } = render(() => <SecurityCeremony progress={50} />);
    const svg = container.querySelector("svg");
    expect(svg).toBeTruthy();
  });

  it("shows check icon when complete", () => {
    const { container } = render(() => <SecurityCeremony progress={100} />);
    const svg = container.querySelector("svg");
    expect(svg).toBeTruthy();
  });

  it("calls onComplete when progress reaches 100", () => {
    const onComplete = vi.fn();
    render(() => <SecurityCeremony progress={100} onComplete={onComplete} />);
    expect(onComplete).toHaveBeenCalled();
  });

  it("does not call onComplete when progress < 100", () => {
    const onComplete = vi.fn();
    render(() => <SecurityCeremony progress={99} onComplete={onComplete} />);
    expect(onComplete).not.toHaveBeenCalled();
  });

  it("clamps progress to 0-100 range", () => {
    const { container } = render(() => <SecurityCeremony progress={150} />);
    const bar = container.querySelector("[role='progressbar']")!;
    expect(bar.getAttribute("aria-valuenow")).toBe("100");
  });

  it("clamps negative progress to 0", () => {
    const { container } = render(() => <SecurityCeremony progress={-10} />);
    const bar = container.querySelector("[role='progressbar']")!;
    expect(bar.getAttribute("aria-valuenow")).toBe("0");
  });
});

import { render } from "@solidjs/testing-library";
import { Spinner } from "../../components/Spinner";

describe("Spinner", () => {
  it("renders with role=status", () => {
    const { container } = render(() => <Spinner />);
    const spinner = container.querySelector("[role='status']");
    expect(spinner).toBeTruthy();
  });

  it("has aria-label='Loading'", () => {
    const { container } = render(() => <Spinner />);
    const spinner = container.querySelector("[role='status']")!;
    expect(spinner.getAttribute("aria-label")).toBe("Loading");
  });

  it("defaults to 16px size", () => {
    const { container } = render(() => <Spinner />);
    const spinner = container.querySelector("[role='status']") as HTMLElement;
    expect(spinner.style.width).toBe("16px");
    expect(spinner.style.height).toBe("16px");
  });

  it("supports custom size", () => {
    const { container } = render(() => <Spinner size={32} />);
    const spinner = container.querySelector("[role='status']") as HTMLElement;
    expect(spinner.style.width).toBe("32px");
    expect(spinner.style.height).toBe("32px");
  });

  it("renders an SVG with track and arc", () => {
    const { container } = render(() => <Spinner />);
    const svg = container.querySelector("svg");
    expect(svg).toBeTruthy();
    const circle = container.querySelector("circle");
    expect(circle).toBeTruthy();
    const path = container.querySelector("path");
    expect(path).toBeTruthy();
  });

  it("SVG is aria-hidden (decorative)", () => {
    const { container } = render(() => <Spinner />);
    const svg = container.querySelector("svg")!;
    expect(svg.getAttribute("aria-hidden")).toBe("true");
  });

  it("contains 'Loading...' screen reader text", () => {
    const { container } = render(() => <Spinner />);
    expect(container.textContent).toContain("Loading...");
  });

  it("applies custom class", () => {
    const { container } = render(() => <Spinner class="my-spinner" />);
    const spinner = container.querySelector("[role='status']")!;
    expect(spinner.className).toContain("my-spinner");
  });
});

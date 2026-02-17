import { render } from "@solidjs/testing-library";
import { Icon } from "../../components/Icon";

describe("Icon", () => {
  it("renders an SVG element", () => {
    const { container } = render(() => <Icon name="shield" />);
    const svg = container.querySelector("svg");
    expect(svg).toBeTruthy();
  });

  it("defaults to 16px size", () => {
    const { container } = render(() => <Icon name="shield" />);
    const svg = container.querySelector("svg")!;
    expect(svg.getAttribute("width")).toBe("16");
    expect(svg.getAttribute("height")).toBe("16");
  });

  it("supports custom size", () => {
    const { container } = render(() => <Icon name="shield" size={24} />);
    const svg = container.querySelector("svg")!;
    expect(svg.getAttribute("width")).toBe("24");
    expect(svg.getAttribute("height")).toBe("24");
  });

  it("renders correct SVG path for each icon", () => {
    const icons = [
      "shield", "eye", "eye-off", "check", "alert", "info",
      "copy", "lock", "spinner", "chevron-right", "plus", "x",
    ] as const;

    for (const name of icons) {
      const { container, unmount } = render(() => <Icon name={name} />);
      const path = container.querySelector("path");
      expect(path).toBeTruthy();
      expect(path!.getAttribute("d")).toBeTruthy();
      unmount();
    }
  });

  it("is decorative (aria-hidden) when no label provided", () => {
    const { container } = render(() => <Icon name="shield" />);
    const svg = container.querySelector("svg")!;
    expect(svg.getAttribute("aria-hidden")).toBe("true");
    expect(svg.getAttribute("aria-label")).toBeNull();
  });

  it("is accessible (aria-label + role=img) when label provided", () => {
    const { container } = render(() => (
      <Icon name="shield" label="Security shield" />
    ));
    const svg = container.querySelector("svg")!;
    expect(svg.getAttribute("aria-label")).toBe("Security shield");
    expect(svg.getAttribute("role")).toBe("img");
    expect(svg.getAttribute("aria-hidden")).toBeNull();
  });

  it("uses 24x24 viewBox", () => {
    const { container } = render(() => <Icon name="check" />);
    const svg = container.querySelector("svg")!;
    expect(svg.getAttribute("viewBox")).toBe("0 0 24 24");
  });

  it("inherits color via fill=currentColor", () => {
    const { container } = render(() => <Icon name="check" />);
    const svg = container.querySelector("svg")!;
    expect(svg.getAttribute("fill")).toBe("currentColor");
  });

  it("applies custom class", () => {
    const { container } = render(() => <Icon name="check" class="my-icon" />);
    const svg = container.querySelector("svg")!;
    expect(svg.className.baseVal).toContain("my-icon");
  });
});

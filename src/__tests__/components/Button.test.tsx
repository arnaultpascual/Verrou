import { render, fireEvent } from "@solidjs/testing-library";
import { Button } from "../../components/Button";

describe("Button", () => {
  it("renders with children", () => {
    const { getByText } = render(() => <Button>Click me</Button>);
    expect(getByText("Click me")).toBeTruthy();
  });

  it("defaults to primary variant", () => {
    const { container } = render(() => <Button>OK</Button>);
    const btn = container.querySelector("button")!;
    expect(btn.className).toContain("primary");
  });

  it("renders secondary variant", () => {
    const { container } = render(() => <Button variant="secondary">More</Button>);
    const btn = container.querySelector("button")!;
    expect(btn.className).toContain("secondary");
  });

  it("renders ghost variant", () => {
    const { container } = render(() => <Button variant="ghost">Cancel</Button>);
    const btn = container.querySelector("button")!;
    expect(btn.className).toContain("ghost");
  });

  it("renders danger variant", () => {
    const { container } = render(() => <Button variant="danger">Delete</Button>);
    const btn = container.querySelector("button")!;
    expect(btn.className).toContain("danger");
  });

  it("defaults to md size", () => {
    const { container } = render(() => <Button>OK</Button>);
    const btn = container.querySelector("button")!;
    expect(btn.className).toContain("md");
  });

  it("renders sm size", () => {
    const { container } = render(() => <Button size="sm">OK</Button>);
    const btn = container.querySelector("button")!;
    expect(btn.className).toContain("sm");
    expect(btn.className).not.toContain("md");
  });

  it("renders lg size", () => {
    const { container } = render(() => <Button size="lg">OK</Button>);
    const btn = container.querySelector("button")!;
    expect(btn.className).toContain("lg");
    expect(btn.className).not.toContain("md");
  });

  it("applies iconOnly modifier", () => {
    const { container } = render(() => (
      <Button iconOnly aria-label="settings">
        <svg />
      </Button>
    ));
    const btn = container.querySelector("button")!;
    expect(btn.className).toContain("iconOnly");
  });

  it("does not apply iconOnly by default", () => {
    const { container } = render(() => <Button>OK</Button>);
    const btn = container.querySelector("button")!;
    expect(btn.className).not.toContain("iconOnly");
  });

  it("applies fullWidth modifier", () => {
    const { container } = render(() => <Button fullWidth>OK</Button>);
    const btn = container.querySelector("button")!;
    expect(btn.className).toContain("fullWidth");
  });

  it("does not apply fullWidth by default", () => {
    const { container } = render(() => <Button>OK</Button>);
    const btn = container.querySelector("button")!;
    expect(btn.className).not.toContain("fullWidth");
  });

  it("defaults to type=button", () => {
    const { container } = render(() => <Button>OK</Button>);
    const btn = container.querySelector("button")!;
    expect(btn.getAttribute("type")).toBe("button");
  });

  it("supports type=submit", () => {
    const { container } = render(() => <Button type="submit">OK</Button>);
    const btn = container.querySelector("button")!;
    expect(btn.getAttribute("type")).toBe("submit");
  });

  it("calls onClick on click", () => {
    const onClick = vi.fn();
    const { getByText } = render(() => <Button onClick={onClick}>OK</Button>);
    fireEvent.click(getByText("OK"));
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it("sets aria-disabled when disabled", () => {
    const { container } = render(() => <Button disabled>OK</Button>);
    const btn = container.querySelector("button")!;
    expect(btn.getAttribute("aria-disabled")).toBe("true");
  });

  it("does not call onClick when disabled", () => {
    const onClick = vi.fn();
    const { container } = render(() => (
      <Button disabled onClick={onClick}>OK</Button>
    ));
    const btn = container.querySelector("button")!;
    fireEvent.click(btn);
    expect(onClick).not.toHaveBeenCalled();
  });

  it("shows spinner-only when loading without loadingText", () => {
    const { container, queryByText } = render(() => (
      <Button loading>Submit</Button>
    ));
    // The spinner renders, but the children label is replaced and no loadingText is shown.
    expect(container.querySelector("[role='status']")).toBeTruthy();
    expect(queryByText("Submit")).toBeNull();
    expect(queryByText("Saving...")).toBeNull();
    expect(
      container.querySelector("button")!.getAttribute("aria-busy"),
    ).toBe("true");
  });

  it("shows loadingText next to the spinner when provided", () => {
    const { container, getByText } = render(() => (
      <Button loading loadingText="Saving changes">
        Submit
      </Button>
    ));
    expect(getByText("Saving changes")).toBeTruthy();
    expect(container.querySelector("[role='status']")).toBeTruthy();
  });

  it("does not render loadingText when not loading", () => {
    const { queryByText, getByText } = render(() => (
      <Button loadingText="Saving changes">Submit</Button>
    ));
    expect(getByText("Submit")).toBeTruthy();
    expect(queryByText("Saving changes")).toBeNull();
  });

  it("sets aria-disabled when loading", () => {
    const { container } = render(() => <Button loading>OK</Button>);
    const btn = container.querySelector("button")!;
    expect(btn.getAttribute("aria-disabled")).toBe("true");
  });

  it("does not call onClick when loading", () => {
    const onClick = vi.fn();
    const { container } = render(() => (
      <Button loading onClick={onClick}>OK</Button>
    ));
    fireEvent.click(container.querySelector("button")!);
    expect(onClick).not.toHaveBeenCalled();
  });

  it("applies custom class", () => {
    const { container } = render(() => <Button class="custom">OK</Button>);
    const btn = container.querySelector("button")!;
    expect(btn.className).toContain("custom");
  });

  it("combines variant, size, and modifiers", () => {
    const { container } = render(() => (
      <Button variant="secondary" size="lg" fullWidth>
        OK
      </Button>
    ));
    const btn = container.querySelector("button")!;
    expect(btn.className).toContain("secondary");
    expect(btn.className).toContain("lg");
    expect(btn.className).toContain("fullWidth");
  });
});

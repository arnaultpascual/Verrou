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

  it("shows loading state with Spinner and 'Saving...'", () => {
    const { container, getByText } = render(() => (
      <Button loading>Submit</Button>
    ));
    expect(getByText("Saving...")).toBeTruthy();
    expect(container.querySelector("[role='status']")).toBeTruthy();
    expect(container.querySelector("button")!.getAttribute("aria-busy")).toBe("true");
  });

  it("sets aria-disabled when loading", () => {
    const { container } = render(() => <Button loading>OK</Button>);
    const btn = container.querySelector("button")!;
    expect(btn.getAttribute("aria-disabled")).toBe("true");
  });

  it("applies custom class", () => {
    const { container } = render(() => <Button class="custom">OK</Button>);
    const btn = container.querySelector("button")!;
    expect(btn.className).toContain("custom");
  });
});

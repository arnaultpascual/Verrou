import { render, fireEvent } from "@solidjs/testing-library";
import { Input } from "../../components/Input";

describe("Input", () => {
  it("renders with label", () => {
    const { getByText } = render(() => <Input label="Username" />);
    expect(getByText("Username")).toBeTruthy();
  });

  it("associates label with input via for/id", () => {
    const { container } = render(() => <Input label="Email" id="email-input" />);
    const label = container.querySelector("label")!;
    const input = container.querySelector("input")!;
    expect(label.getAttribute("for")).toBe("email-input");
    expect(input.id).toBe("email-input");
  });

  it("auto-generates id when not provided", () => {
    const { container } = render(() => <Input label="Name" />);
    const label = container.querySelector("label")!;
    const input = container.querySelector("input")!;
    expect(label.getAttribute("for")).toBeTruthy();
    expect(input.id).toBe(label.getAttribute("for"));
  });

  it("displays value", () => {
    const { container } = render(() => <Input label="Name" value="John" />);
    const input = container.querySelector("input")!;
    expect(input.value).toBe("John");
  });

  it("calls onInput with new value", () => {
    const onInput = vi.fn();
    const { container } = render(() => (
      <Input label="Name" onInput={onInput} />
    ));
    const input = container.querySelector("input")!;
    fireEvent.input(input, { target: { value: "test" } });
    expect(onInput).toHaveBeenCalledWith("test");
  });

  it("shows error message", () => {
    const { getByText, container } = render(() => (
      <Input label="Email" error="Invalid email" />
    ));
    expect(getByText("Invalid email")).toBeTruthy();
    const errorEl = container.querySelector("[role='alert']")!;
    expect(errorEl.textContent).toBe("Invalid email");
  });

  it("sets aria-invalid on error", () => {
    const { container } = render(() => (
      <Input label="Email" error="Required" />
    ));
    const input = container.querySelector("input")!;
    expect(input.getAttribute("aria-invalid")).toBe("true");
  });

  it("links input to error via aria-describedby", () => {
    const { container } = render(() => (
      <Input label="Email" id="email" error="Required" />
    ));
    const input = container.querySelector("input")!;
    const errorEl = container.querySelector("[role='alert']")!;
    expect(input.getAttribute("aria-describedby")).toBe(errorEl.id);
  });

  it("does not show error when no error prop", () => {
    const { container } = render(() => <Input label="Name" />);
    const errorEl = container.querySelector("[role='alert']");
    expect(errorEl).toBeNull();
    const input = container.querySelector("input")!;
    expect(input.getAttribute("aria-invalid")).toBeNull();
  });

  it("supports disabled state", () => {
    const { container } = render(() => <Input label="Name" disabled />);
    const input = container.querySelector("input")!;
    expect(input.disabled).toBe(true);
  });

  it("sets placeholder", () => {
    const { container } = render(() => (
      <Input label="Name" placeholder="Enter name" />
    ));
    const input = container.querySelector("input")!;
    expect(input.placeholder).toBe("Enter name");
  });

  it("defaults to type=text", () => {
    const { container } = render(() => <Input label="Name" />);
    const input = container.querySelector("input")!;
    expect(input.type).toBe("text");
  });

  it("supports type=email", () => {
    const { container } = render(() => <Input label="Email" type="email" />);
    const input = container.querySelector("input")!;
    expect(input.type).toBe("email");
  });

  it("applies error CSS class on error", () => {
    const { container } = render(() => (
      <Input label="Name" error="Error" />
    ));
    const input = container.querySelector("input")!;
    expect(input.className).toContain("inputError");
  });
});

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

  describe("hint", () => {
    it("renders hint text under the field", () => {
      const { getByText } = render(() => (
        <Input label="Email" hint="We never share this" />
      ));
      expect(getByText("We never share this")).toBeTruthy();
    });

    it("links hint to input via aria-describedby", () => {
      const { container } = render(() => (
        <Input label="Email" id="email" hint="Helper" />
      ));
      const input = container.querySelector("input")!;
      const hintEl = container.querySelector("#email-hint")!;
      expect(hintEl).toBeTruthy();
      expect(hintEl.textContent).toBe("Helper");
      expect(input.getAttribute("aria-describedby")).toBe(hintEl.id);
    });

    it("does not render hint when not provided", () => {
      const { container } = render(() => <Input label="Email" id="email" />);
      expect(container.querySelector("#email-hint")).toBeNull();
      const input = container.querySelector("input")!;
      expect(input.getAttribute("aria-describedby")).toBeNull();
    });

    it("describes input by both hint and error when both present", () => {
      const { container } = render(() => (
        <Input label="Email" id="email" hint="Helper" error="Required" />
      ));
      const input = container.querySelector("input")!;
      const describedBy = input.getAttribute("aria-describedby")!;
      expect(describedBy).toContain("email-error");
      expect(describedBy).toContain("email-hint");
    });
  });

  describe("required", () => {
    it("shows a required indicator on the label", () => {
      const { container } = render(() => (
        <Input label="Name" required />
      ));
      const label = container.querySelector("label")!;
      expect(label.textContent).toContain("*");
    });

    it("sets the native required attribute on the input", () => {
      const { container } = render(() => (
        <Input label="Name" required />
      ));
      const input = container.querySelector("input")!;
      expect(input.required).toBe(true);
    });

    it("required indicator is hidden from assistive tech", () => {
      const { container } = render(() => (
        <Input label="Name" required />
      ));
      const indicator = container.querySelector("label span")!;
      expect(indicator.getAttribute("aria-hidden")).toBe("true");
    });

    it("is not required by default", () => {
      const { container } = render(() => <Input label="Name" />);
      const input = container.querySelector("input")!;
      expect(input.required).toBe(false);
      expect(container.querySelector("label span")).toBeNull();
    });
  });
});

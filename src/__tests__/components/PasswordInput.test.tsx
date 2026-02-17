import { render, fireEvent } from "@solidjs/testing-library";
import { PasswordInput } from "../../components/PasswordInput";

describe("PasswordInput", () => {
  describe("common behavior", () => {
    it("renders with label", () => {
      const { getByText } = render(() => (
        <PasswordInput label="Master Password" mode="unlock" />
      ));
      expect(getByText("Master Password")).toBeTruthy();
    });

    it("associates label with input", () => {
      const { container } = render(() => (
        <PasswordInput label="Password" mode="unlock" id="pw" />
      ));
      const label = container.querySelector("label")!;
      const input = container.querySelector("input")!;
      expect(label.getAttribute("for")).toBe("pw");
      expect(input.id).toBe("pw");
    });

    it("defaults to password type (masked)", () => {
      const { container } = render(() => (
        <PasswordInput label="Password" mode="unlock" />
      ));
      const input = container.querySelector("input")!;
      expect(input.type).toBe("password");
    });

    it("calls onInput with value", () => {
      const onInput = vi.fn();
      const { container } = render(() => (
        <PasswordInput label="Password" mode="unlock" onInput={onInput} />
      ));
      const input = container.querySelector("input")!;
      fireEvent.input(input, { target: { value: "secret" } });
      expect(onInput).toHaveBeenCalledWith("secret");
    });

    it("shows error message", () => {
      const { getByText } = render(() => (
        <PasswordInput label="Password" mode="unlock" error="Wrong password" />
      ));
      expect(getByText("Wrong password")).toBeTruthy();
    });

    it("sets aria-invalid on error", () => {
      const { container } = render(() => (
        <PasswordInput label="Password" mode="unlock" error="Required" />
      ));
      const input = container.querySelector("input")!;
      expect(input.getAttribute("aria-invalid")).toBe("true");
    });
  });

  describe("visibility toggle", () => {
    it("renders toggle button with 'Show password' label", () => {
      const { container } = render(() => (
        <PasswordInput label="Password" mode="unlock" />
      ));
      const btn = container.querySelector("button")!;
      expect(btn.getAttribute("aria-label")).toBe("Show password");
    });

    it("toggles to text type on click", () => {
      const { container } = render(() => (
        <PasswordInput label="Password" mode="unlock" />
      ));
      const input = container.querySelector("input")!;
      const btn = container.querySelector("button")!;

      expect(input.type).toBe("password");
      fireEvent.click(btn);
      expect(input.type).toBe("text");
      expect(btn.getAttribute("aria-label")).toBe("Hide password");
    });

    it("toggles back to password on second click", () => {
      const { container } = render(() => (
        <PasswordInput label="Password" mode="unlock" />
      ));
      const input = container.querySelector("input")!;
      const btn = container.querySelector("button")!;

      fireEvent.click(btn);
      fireEvent.click(btn);
      expect(input.type).toBe("password");
      expect(btn.getAttribute("aria-label")).toBe("Show password");
    });
  });

  describe("unlock mode", () => {
    it("does not show strength meter", () => {
      const { container } = render(() => (
        <PasswordInput label="Password" mode="unlock" value="test123" />
      ));
      expect(container.querySelector("[role='progressbar']")).toBeNull();
    });

    it("does not show guidance text", () => {
      const { container } = render(() => (
        <PasswordInput label="Password" mode="unlock" value="ab" />
      ));
      expect(container.textContent).not.toContain("memorable phrase");
    });

    it("has autocomplete=current-password", () => {
      const { container } = render(() => (
        <PasswordInput label="Password" mode="unlock" />
      ));
      const input = container.querySelector("input")!;
      expect(input.getAttribute("autocomplete")).toBe("current-password");
    });
  });

  describe("create mode — strength meter", () => {
    it("shows strength meter", () => {
      const { container } = render(() => (
        <PasswordInput label="Password" mode="create" value="test" />
      ));
      expect(container.querySelector("[role='progressbar']")).toBeTruthy();
    });

    it("shows 'Weak' for short passwords", () => {
      const { getByText } = render(() => (
        <PasswordInput label="Password" mode="create" value="ab" />
      ));
      expect(getByText("Weak")).toBeTruthy();
    });

    it("shows 'Good' for strong passwords", () => {
      const { getByText } = render(() => (
        <PasswordInput label="Password" mode="create" value="MyStr0ng!Pass" />
      ));
      expect(getByText("Good")).toBeTruthy();
    });

    it("shows 'Excellent' for passphrase-like input", () => {
      const { getByText } = render(() => (
        <PasswordInput label="Password" mode="create" value="correct horse battery staple" />
      ));
      expect(getByText("Excellent")).toBeTruthy();
    });

    it("shows guidance for weak passwords (FR26)", () => {
      const { container } = render(() => (
        <PasswordInput label="Password" mode="create" value="ab" />
      ));
      expect(container.textContent).toContain("memorable phrase");
    });

    it("hides guidance for good passwords", () => {
      const { container } = render(() => (
        <PasswordInput label="Password" mode="create" value="MyStr0ng!Pass" />
      ));
      expect(container.textContent).not.toContain("memorable phrase");
    });

    it("has autocomplete=new-password", () => {
      const { container } = render(() => (
        <PasswordInput label="Password" mode="create" />
      ));
      const input = container.querySelector("input")!;
      expect(input.getAttribute("autocomplete")).toBe("new-password");
    });

    it("strength progressbar has aria attributes", () => {
      const { container } = render(() => (
        <PasswordInput label="Password" mode="create" value="test" />
      ));
      const bar = container.querySelector("[role='progressbar']")!;
      expect(bar.getAttribute("aria-valuenow")).toBeTruthy();
      expect(bar.getAttribute("aria-valuemin")).toBe("0");
      expect(bar.getAttribute("aria-valuemax")).toBe("100");
      expect(bar.getAttribute("aria-label")).toContain("Password strength");
    });
  });

  describe("no DOM value leakage", () => {
    it("does not expose value as DOM attribute when masked", () => {
      const { container } = render(() => (
        <PasswordInput label="Password" mode="unlock" value="secret123" />
      ));
      const input = container.querySelector("input")!;
      // The value property is set but the HTML attribute should not leak
      // In password type, the value is not visible as text content
      expect(input.type).toBe("password");
      // Ensure value doesn't appear in outer HTML as an attribute
      const outerHtml = container.innerHTML;
      expect(outerHtml).not.toContain("secret123");
    });
  });
});

import { render, fireEvent } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { PasswordStep } from "../../../features/onboarding/PasswordStep";
import { wizardStore, setWizardStore } from "../../../features/onboarding/stores";

describe("PasswordStep", () => {
  beforeEach(() => {
    setWizardStore({
      password: "",
      confirmPassword: "",
      kdfPreset: "balanced",
      recoveryKeyConfirmed: false,
      recoveryKey: null,
      vaultFingerprint: null,
      isCreating: false,
    });
  });

  it("renders heading and description", () => {
    const { getByText } = render(() => (
      <PasswordStep onValidChange={vi.fn()} />
    ));
    expect(getByText("Create your password")).toBeDefined();
    expect(getByText(/Choose a strong master password/)).toBeDefined();
  });

  it("renders two password inputs", () => {
    const { getByText } = render(() => (
      <PasswordStep onValidChange={vi.fn()} />
    ));
    expect(getByText("Master password")).toBeDefined();
    expect(getByText("Confirm password")).toBeDefined();
  });

  it("renders passphrase guidance", () => {
    const { container } = render(() => (
      <PasswordStep onValidChange={vi.fn()} />
    ));
    expect(container.textContent).toContain("correct horse battery staple");
  });

  it("calls onValidChange(false) when passwords are empty", () => {
    const onValid = vi.fn();
    render(() => <PasswordStep onValidChange={onValid} />);
    expect(onValid).toHaveBeenCalledWith(false);
  });

  it("calls onValidChange(false) when passwords do not match", () => {
    const onValid = vi.fn();
    setWizardStore("password", "correct horse battery staple");
    setWizardStore("confirmPassword", "different passphrase here");
    render(() => <PasswordStep onValidChange={onValid} />);
    expect(onValid).toHaveBeenCalledWith(false);
  });

  it("calls onValidChange(true) when passwords match and strength is good", () => {
    const onValid = vi.fn();
    const strongPass = "correct horse battery staple";
    setWizardStore("password", strongPass);
    setWizardStore("confirmPassword", strongPass);
    render(() => <PasswordStep onValidChange={onValid} />);
    expect(onValid).toHaveBeenCalledWith(true);
  });

  it("calls onValidChange(false) for weak matching passwords", () => {
    const onValid = vi.fn();
    setWizardStore("password", "abc");
    setWizardStore("confirmPassword", "abc");
    render(() => <PasswordStep onValidChange={onValid} />);
    expect(onValid).toHaveBeenCalledWith(false);
  });

  it("shows mismatch error when confirm differs from password", () => {
    setWizardStore("password", "MyStr0ngP@ss");
    setWizardStore("confirmPassword", "different");
    const { getByText } = render(() => (
      <PasswordStep onValidChange={vi.fn()} />
    ));
    expect(getByText("Passwords do not match")).toBeDefined();
  });

  it("does not show mismatch error when confirm is empty", () => {
    setWizardStore("password", "MyStr0ngP@ss");
    setWizardStore("confirmPassword", "");
    const { queryByText } = render(() => (
      <PasswordStep onValidChange={vi.fn()} />
    ));
    expect(queryByText("Passwords do not match")).toBeNull();
  });

  it("updates store on password input", () => {
    const { container } = render(() => (
      <PasswordStep onValidChange={vi.fn()} />
    ));
    const inputs = container.querySelectorAll("input");
    fireEvent.input(inputs[0], { target: { value: "newpassword" } });
    expect(wizardStore.password).toBe("newpassword");
  });

  it("first input uses mode=create (shows strength meter)", () => {
    setWizardStore("password", "test1234");
    const { container } = render(() => (
      <PasswordStep onValidChange={vi.fn()} />
    ));
    // create mode shows a progressbar for strength
    const progressbar = container.querySelector("[role='progressbar']");
    expect(progressbar).not.toBeNull();
  });
});

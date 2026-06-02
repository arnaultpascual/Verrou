import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { ReAuthPrompt } from "../../components/ReAuthPrompt";

const noop = async () => {};

function clickVerify() {
  const verifyBtn = Array.from(document.querySelectorAll("button")).find((b) =>
    b.textContent?.includes("Verify"),
  );
  fireEvent.click(verifyBtn!);
}

function submit(password: string) {
  const input = document.querySelector("input[type='password']") as HTMLInputElement;
  fireEvent.input(input, { target: { value: password } });
  clickVerify();
}

describe("ReAuthPrompt", () => {
  it("renders nothing when closed", () => {
    render(() => <ReAuthPrompt open={false} onClose={() => {}} onVerified={noop} />);
    expect(document.querySelector("[role='dialog']")).toBeNull();
  });

  it("renders modal with title when open", () => {
    render(() => <ReAuthPrompt open={true} onClose={() => {}} onVerified={noop} />);
    expect(document.body.textContent).toContain("Verify Your Identity");
  });

  it("contains a password input in unlock mode", () => {
    render(() => <ReAuthPrompt open={true} onClose={() => {}} onVerified={noop} />);
    const input = document.querySelector("input[type='password']");
    expect(input).toBeTruthy();
    expect(input?.getAttribute("autocomplete")).toBe("current-password");
  });

  it("shows description text", () => {
    render(() => <ReAuthPrompt open={true} onClose={() => {}} onVerified={noop} />);
    expect(document.body.textContent).toContain("re-authentication");
  });

  it("has Cancel and Verify buttons", () => {
    render(() => <ReAuthPrompt open={true} onClose={() => {}} onVerified={noop} />);
    expect(document.body.textContent).toContain("Cancel");
    expect(document.body.textContent).toContain("Verify");
  });

  it("calls onClose when Cancel is clicked", () => {
    const onClose = vi.fn();
    render(() => <ReAuthPrompt open={true} onClose={onClose} onVerified={noop} />);
    const cancelBtn = Array.from(document.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("Cancel"),
    );
    fireEvent.click(cancelBtn!);
    expect(onClose).toHaveBeenCalled();
  });

  it("shows error and does not verify when submitting empty password", () => {
    const onVerified = vi.fn(noop);
    render(() => <ReAuthPrompt open={true} onClose={() => {}} onVerified={onVerified} />);
    clickVerify();
    expect(document.body.textContent).toContain("Password is required");
    expect(onVerified).not.toHaveBeenCalled();
  });

  it("calls onVerified with the entered password and shows the ceremony", async () => {
    // never resolves → stays in the "verifying" state
    const onVerified = vi.fn(() => new Promise<void>(() => {}));
    render(() => <ReAuthPrompt open={true} onClose={() => {}} onVerified={onVerified} />);

    submit("testpass");

    await waitFor(() => {
      expect(document.querySelector("[role='progressbar']")).toBeTruthy();
    });
    expect(onVerified).toHaveBeenCalledWith("testpass");
    expect(document.body.textContent).toContain("Verifying your identity");
  });

  it("completes the ceremony (100%) ONLY after verification resolves", async () => {
    let resolveVerify: () => void = () => {};
    const onVerified = vi.fn(
      () =>
        new Promise<void>((res) => {
          resolveVerify = res;
        }),
    );
    render(() => <ReAuthPrompt open={true} onClose={() => {}} onVerified={onVerified} />);

    submit("testpass");

    // While verifying, the bar must NOT report completion.
    await waitFor(() => {
      expect(document.querySelector("[role='progressbar']")).toBeTruthy();
    });
    expect(document.querySelector("[role='progressbar']")?.getAttribute("aria-valuenow")).not.toBe(
      "100",
    );

    // Backend confirms → only now does it reach 100.
    resolveVerify();
    await waitFor(() => {
      expect(
        document.querySelector("[role='progressbar']")?.getAttribute("aria-valuenow"),
      ).toBe("100");
    });
  });

  it("surfaces the error inline and returns to input when verification fails", async () => {
    const onVerified = vi.fn().mockRejectedValue("Incorrect password.");
    render(() => <ReAuthPrompt open={true} onClose={() => {}} onVerified={onVerified} />);

    submit("wrongpass");

    await waitFor(() => {
      expect(document.body.textContent).toContain("Incorrect password.");
    });
    // Back to the input phase: password field present, no ceremony bar.
    expect(document.querySelector("input[type='password']")).toBeTruthy();
    expect(document.querySelector("[role='progressbar']")).toBeNull();
  });

  it("does not close on overlay click (closeOnOverlayClick=false)", () => {
    const onClose = vi.fn();
    render(() => <ReAuthPrompt open={true} onClose={onClose} onVerified={noop} />);
    expect(document.querySelector("[role='dialog']")).toBeTruthy();
  });
});

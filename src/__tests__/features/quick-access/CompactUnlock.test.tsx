import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";

// Mock vault IPC
vi.mock("../../../features/vault/ipc", () => ({
  unlockVault: vi.fn(),
  parseUnlockError: vi.fn().mockReturnValue({
    code: "INVALID_PASSWORD",
    message: "Incorrect password. Please try again.",
  }),
}));

import { unlockVault, parseUnlockError } from "../../../features/vault/ipc";
import { CompactUnlock } from "../../../features/quick-access/CompactUnlock";

describe("CompactUnlock", () => {
  const onSuccess = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders password input and unlock button", () => {
    const { getByText, container } = render(() => (
      <CompactUnlock onSuccess={onSuccess} />
    ));

    expect(getByText("Master Password")).toBeDefined();
    expect(getByText("Unlock")).toBeDefined();
    expect(container.querySelector("input")).not.toBeNull();
  });

  it("submit button is disabled when password is empty", () => {
    const { container } = render(() => (
      <CompactUnlock onSuccess={onSuccess} />
    ));

    const button = container.querySelector("button[type='submit']") as HTMLButtonElement;
    expect(button.disabled).toBe(true);
  });

  it("enables submit button when password is entered", async () => {
    const { container } = render(() => (
      <CompactUnlock onSuccess={onSuccess} />
    ));

    const input = container.querySelector("input") as HTMLInputElement;
    const button = container.querySelector("button[type='submit']") as HTMLButtonElement;

    fireEvent.input(input, { target: { value: "test-password" } });

    await waitFor(() => {
      expect(button.disabled).toBe(false);
    });
  });

  it("calls unlockVault on submit", async () => {
    (unlockVault as ReturnType<typeof vi.fn>).mockResolvedValue({ unlockCount: 1 });

    const { container } = render(() => (
      <CompactUnlock onSuccess={onSuccess} />
    ));

    const input = container.querySelector("input") as HTMLInputElement;
    fireEvent.input(input, { target: { value: "my-password" } });

    const form = container.querySelector("form") as HTMLFormElement;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(unlockVault).toHaveBeenCalledWith("my-password");
    });
  });

  it("calls onSuccess after successful unlock", async () => {
    (unlockVault as ReturnType<typeof vi.fn>).mockResolvedValue({ unlockCount: 1 });

    const { container } = render(() => (
      <CompactUnlock onSuccess={onSuccess} />
    ));

    const input = container.querySelector("input") as HTMLInputElement;
    fireEvent.input(input, { target: { value: "correct-password" } });

    const form = container.querySelector("form") as HTMLFormElement;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(onSuccess).toHaveBeenCalled();
    });
  });

  it("shows error message on failed unlock", async () => {
    (unlockVault as ReturnType<typeof vi.fn>).mockRejectedValue("Invalid password");
    (parseUnlockError as ReturnType<typeof vi.fn>).mockReturnValue({
      code: "INVALID_PASSWORD",
      message: "Incorrect password. Please try again.",
    });

    const { container, findByText } = render(() => (
      <CompactUnlock onSuccess={onSuccess} />
    ));

    const input = container.querySelector("input") as HTMLInputElement;
    fireEvent.input(input, { target: { value: "wrong-password" } });

    const form = container.querySelector("form") as HTMLFormElement;
    fireEvent.submit(form);

    const errorMsg = await findByText("Incorrect password. Please try again.");
    expect(errorMsg).toBeDefined();
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it("clears password field on error", async () => {
    (unlockVault as ReturnType<typeof vi.fn>).mockRejectedValue("Invalid password");

    const { container } = render(() => (
      <CompactUnlock onSuccess={onSuccess} />
    ));

    const input = container.querySelector("input") as HTMLInputElement;
    fireEvent.input(input, { target: { value: "wrong-password" } });

    const form = container.querySelector("form") as HTMLFormElement;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(input.value).toBe("");
    });
  });
});

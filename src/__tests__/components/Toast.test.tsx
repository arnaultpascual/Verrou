import { render } from "@solidjs/testing-library";
import { type ToastVariant } from "../../components/Toast";
import { ToastProvider } from "../../components/ToastProvider";

// Note: ToastContent renders inside Kobalte Toast.Root which requires
// Toast.Region context. Full toast rendering tests must be done within
// a ToastProvider context using the toaster.show() API (integration).
// These tests verify provider setup, variant types, and hook exports.

describe("ToastVariant types", () => {
  it("supports 3 variants: success, error, info", () => {
    const variants: ToastVariant[] = ["success", "error", "info"];
    expect(variants).toHaveLength(3);
    expect(variants).toContain("success");
    expect(variants).toContain("error");
    expect(variants).toContain("info");
  });
});

describe("ToastProvider", () => {
  it("renders children", () => {
    const { getByText } = render(() => (
      <ToastProvider>
        <p>App content</p>
      </ToastProvider>
    ));
    expect(getByText("App content")).toBeTruthy();
  });

  it("renders Toast.Region with role=region", () => {
    render(() => (
      <ToastProvider>
        <div />
      </ToastProvider>
    ));
    const region = document.querySelector("[role='region']");
    expect(region).toBeTruthy();
  });

  it("renders Toast.List as an ordered list inside Region", () => {
    render(() => (
      <ToastProvider>
        <div />
      </ToastProvider>
    ));
    const list = document.querySelector("ol");
    expect(list).toBeTruthy();
  });

  it("region has aria-label for accessibility", () => {
    render(() => (
      <ToastProvider>
        <div />
      </ToastProvider>
    ));
    const region = document.querySelector("[role='region']");
    expect(region).toBeTruthy();
    // Kobalte adds aria-label="Notifications" by default
    expect(region!.getAttribute("aria-label")).toBeTruthy();
  });
});

describe("useToast", () => {
  it("module exports correctly with all variant methods", async () => {
    const { useToast } = await import("../../components/useToast");
    expect(typeof useToast).toBe("function");
    const toast = useToast();
    expect(typeof toast.success).toBe("function");
    expect(typeof toast.error).toBe("function");
    expect(typeof toast.info).toBe("function");
    expect(typeof toast.dismiss).toBe("function");
    expect(typeof toast.clear).toBe("function");
  });

  it("returns distinct methods for each variant", async () => {
    const { useToast } = await import("../../components/useToast");
    const toast = useToast();
    // Each method should be unique (not aliased)
    expect(toast.success).not.toBe(toast.error);
    expect(toast.error).not.toBe(toast.info);
    expect(toast.success).not.toBe(toast.info);
  });

  it("dismiss and clear are utility methods", async () => {
    const { useToast } = await import("../../components/useToast");
    const toast = useToast();
    expect(typeof toast.dismiss).toBe("function");
    expect(typeof toast.clear).toBe("function");
    expect(toast.dismiss).not.toBe(toast.clear);
  });
});

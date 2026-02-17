import { toaster } from "@kobalte/core/toast";
import { ToastContent, type ToastVariant } from "./Toast";

/**
 * Shows a toast notification.
 *
 * Duration is set per-variant on Toast.Root (in Toast.tsx):
 *   success: 1000ms, info: 3000ms, error: persistent
 *
 * Usage:
 *   const toast = useToast();
 *   toast.success("Copied to clipboard");
 *   toast.error("Failed to save");
 *   toast.info("Vault locked");
 */
export function useToast() {
  function showToast(variant: ToastVariant, message: string) {
    return toaster.show((props) =>
      ToastContent({
        toastId: props.toastId,
        variant,
        message,
      })
    );
  }

  return {
    success: (message: string) => showToast("success", message),
    error: (message: string) => showToast("error", message),
    info: (message: string) => showToast("info", message),
    dismiss: (id: number) => toaster.dismiss(id),
    clear: () => toaster.clear(),
  };
}

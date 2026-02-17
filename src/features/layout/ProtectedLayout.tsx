import type { Component, JSX } from "solid-js";
import { Show, createEffect, onMount, onCleanup } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { vaultState, setVaultState } from "../../stores/vaultStore";
import { lockVault, heartbeat, onVaultLocked } from "../vault/ipc";
import { AppLayout } from "./AppLayout";

/** Minimum interval between heartbeat IPC calls (ms). */
const HEARTBEAT_DEBOUNCE_MS = 30_000;

export const ProtectedLayout: Component<{ children?: JSX.Element }> = (props) => {
  const navigate = useNavigate();
  let lastHeartbeat = 0;

  createEffect(() => {
    const state = vaultState();
    if (state === "locked") {
      navigate("/unlock", { replace: true });
    } else if (state === "no-vault") {
      navigate("/onboarding", { replace: true });
    }
  });

  // -- Manual lock: Cmd+L / Ctrl+L ------------------------------------
  const handleKeydown = (e: KeyboardEvent) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "l") {
      e.preventDefault();
      if (vaultState() === "unlocked") {
        lockVault().then(() => {
          setVaultState("locked");
        }).catch(() => {
          // Lock failed — rare edge case
        });
      }
    }
  };

  // -- System event detection: lock on visibility hidden ---------------
  const handleVisibilityChange = () => {
    if (document.visibilityState === "hidden" && vaultState() === "unlocked") {
      lockVault().then(() => {
        setVaultState("locked");
      }).catch(() => {
        // Lock failed — backend timer will catch it
      });
    }
  };

  // -- Activity heartbeat (debounced) ----------------------------------
  const sendHeartbeat = () => {
    const now = Date.now();
    if (now - lastHeartbeat > HEARTBEAT_DEBOUNCE_MS) {
      lastHeartbeat = now;
      heartbeat().catch(() => {
        // Heartbeat failed — non-critical
      });
    }
  };

  onMount(() => {
    document.addEventListener("keydown", handleKeydown);
    document.addEventListener("visibilitychange", handleVisibilityChange);
    document.addEventListener("click", sendHeartbeat);
    document.addEventListener("keydown", sendHeartbeat);
    document.addEventListener("mousemove", sendHeartbeat);
  });

  // -- Backend event: verrou://vault-locked ----------------------------
  const unlistenLocked = onVaultLocked(() => {
    setVaultState("locked");
  });

  onCleanup(() => {
    document.removeEventListener("keydown", handleKeydown);
    document.removeEventListener("visibilitychange", handleVisibilityChange);
    document.removeEventListener("click", sendHeartbeat);
    document.removeEventListener("keydown", sendHeartbeat);
    document.removeEventListener("mousemove", sendHeartbeat);
    unlistenLocked();
  });

  return (
    <Show when={vaultState() === "unlocked"}>
      <AppLayout>{props.children}</AppLayout>
    </Show>
  );
};

import { createSignal } from "solid-js";
import { checkVaultStatus, setVaultDir } from "../features/vault/ipc";

export type VaultState = "no-vault" | "locked" | "unlocked";

const [state, setState] = createSignal<VaultState>("locked");
const [initialized, setInitialized] = createSignal(false);

export function vaultState(): VaultState {
  return state();
}

export function setVaultState(value: VaultState): void {
  setState(value);
}

/** Whether the initial vault status check has completed. */
export function isVaultInitialized(): boolean {
  return initialized();
}

/**
 * Query the backend for vault existence and lock state.
 * Must be called once at startup (e.g. in AppRoot onMount).
 * Stores the vault directory path and sets the initial state.
 */
export async function initVaultState(): Promise<void> {
  try {
    const status = await checkVaultStatus();
    setVaultDir(status.vaultDir);
    setState(status.state);
  } catch {
    // If the check fails (e.g. browser dev mode mock), default to "locked".
    setState("locked");
  } finally {
    setInitialized(true);
  }
}

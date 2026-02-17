import { createSignal } from "solid-js";

const STORAGE_KEY = "verrou:sidebar-collapsed";

function readPersistedState(): boolean {
  try {
    return localStorage.getItem(STORAGE_KEY) === "true";
  } catch {
    return false;
  }
}

const [collapsed, setCollapsed] = createSignal<boolean>(readPersistedState());

export function sidebarCollapsed(): boolean {
  return collapsed();
}

export function setSidebarCollapsed(value: boolean): void {
  setCollapsed(value);
  try {
    localStorage.setItem(STORAGE_KEY, String(value));
  } catch {
    // localStorage unavailable — silently ignore
  }
}

export function toggleSidebar(): void {
  setSidebarCollapsed(!collapsed());
}

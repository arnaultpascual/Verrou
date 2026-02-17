import type { Component } from "solid-js";
import { createSignal, createResource, Show, For } from "solid-js";
import { Button, useToast } from "../../components";
import {
  updateHotkeyBinding,
  resetHotkeyBinding,
  getPreferences,
  DEFAULT_HOTKEYS,
} from "./preferencesIpc";
import type { HotkeyBindingsDto } from "./preferencesIpc";
import { t } from "../../stores/i18nStore";
import styles from "./KeyboardShortcuts.module.css";

// ── Platform detection (navigator.userAgentData preferred over deprecated navigator.platform) ──

type Platform = "mac" | "win" | "linux";

function detectPlatform(): Platform {
  const ua = (navigator as { userAgentData?: { platform?: string } }).userAgentData;
  const hint = (ua?.platform ?? navigator.platform ?? "").toLowerCase();
  if (hint.includes("mac")) return "mac";
  if (hint.includes("win")) return "win";
  return "linux";
}

// ── System shortcut blocklist (warn, don't block) ─────────────────

const SYSTEM_BLOCKLIST: Record<Platform, string[]> = {
  mac: [
    "Cmd+Q", "Cmd+Tab", "Cmd+Space", "Cmd+H", "Cmd+M", "Cmd+W",
    "Ctrl+Up", "Ctrl+Down",
  ],
  win: [
    "Ctrl+Alt+Delete", "Alt+Tab", "Alt+F4", "Win+L", "Win+D", "Win+E",
  ],
  linux: ["Ctrl+Alt+T", "Super"],
};

function isSystemShortcut(combo: string): string | undefined {
  const platform = detectPlatform();
  const shortcuts = SYSTEM_BLOCKLIST[platform];

  const normalized = combo.replace("CmdOrCtrl", platform === "mac" ? "Cmd" : "Ctrl");
  const match = shortcuts.find(
    (s) => s.toLowerCase() === normalized.toLowerCase(),
  );
  return match
    ? t("settings.shortcuts.systemWarning", { shortcut: match })
    : undefined;
}

// ── Key Recorder ──────────────────────────────────────────────────

interface KeyRecorderProps {
  currentCombo: string;
  onConfirm: (combo: string) => void;
  onCancel: () => void;
}

const KeyRecorderInput: Component<KeyRecorderProps> = (props) => {
  const [captured, setCaptured] = createSignal("");
  const [warning, setWarning] = createSignal("");

  const handleKeyDown = (e: KeyboardEvent) => {
    e.preventDefault();
    e.stopPropagation();

    // Escape cancels
    if (e.key === "Escape") {
      props.onCancel();
      return;
    }

    const parts: string[] = [];
    if (e.metaKey) parts.push("Cmd");
    else if (e.ctrlKey) parts.push("Ctrl");
    if (e.altKey) parts.push("Alt");
    if (e.shiftKey) parts.push("Shift");

    // Only accept if at least one modifier + one non-modifier key
    const modifierKeys = new Set(["Control", "Shift", "Alt", "Meta"]);
    if (parts.length > 0 && !modifierKeys.has(e.key)) {
      const keyName = e.key.length === 1 ? e.key.toUpperCase() : e.key;
      parts.push(keyName);
      const combo = parts.join("+");
      setCaptured(combo);

      // Check for system shortcut warnings
      const sysWarning = isSystemShortcut(combo);
      setWarning(sysWarning || "");
    }
  };

  const handleConfirm = () => {
    if (captured()) {
      // Convert to portable CmdOrCtrl format for storage
      const portable = captured().replace(/^Cmd\+/, "CmdOrCtrl+").replace(/^Ctrl\+/, "CmdOrCtrl+");
      props.onConfirm(portable);
    }
  };

  return (
    <div class={styles.recorder}>
      <div
        class={styles.recorderInput}
        tabIndex={0}
        role="textbox"
        aria-label={t("settings.shortcuts.recorderPlaceholder")}
        onKeyDown={handleKeyDown}
      >
        <Show
          when={captured()}
          fallback={
            <span class={styles.recorderPlaceholder}>
              {t("settings.shortcuts.recorderPlaceholder")}
            </span>
          }
        >
          <kbd class={styles.kbd}>{captured()}</kbd>
        </Show>
      </div>

      <Show when={warning()}>
        <p class={styles.warning} role="alert">{warning()}</p>
      </Show>

      <div class={styles.recorderActions}>
        <Button variant="ghost" onClick={props.onCancel}>
          {t("settings.shortcuts.cancel")}
        </Button>
        <Button
          onClick={handleConfirm}
          disabled={!captured()}
        >
          {t("settings.shortcuts.confirm")}
        </Button>
      </div>
    </div>
  );
};

// ── Shortcut row config ───────────────────────────────────────────

interface ShortcutRow {
  name: keyof HotkeyBindingsDto;
  label: string;
}

const SHORTCUT_ROWS: ShortcutRow[] = [
  { name: "quickAccess", label: "settings.shortcuts.quickAccess" },
  { name: "lockVault", label: "settings.shortcuts.lockVault" },
];

// ── Main component ────────────────────────────────────────────────

export const KeyboardShortcuts: Component = () => {
  const toast = useToast();
  const [bindings, { mutate }] = createResource(
    async () => {
      const prefs = await getPreferences();
      return prefs.hotkeys;
    },
  );

  const [recording, setRecording] = createSignal<string | null>(null);
  const [error, setError] = createSignal<Record<string, string>>({});

  const displayCombo = (combo: string): string => {
    const platform = detectPlatform();
    if (platform === "mac") {
      return combo.replace("CmdOrCtrl", "\u2318").replace("Shift", "\u21E7").replace("Alt", "\u2325");
    }
    return combo.replace("CmdOrCtrl", "Ctrl");
  };

  const handleStartRecording = (name: string) => {
    setRecording(name);
    setError((prev) => ({ ...prev, [name]: "" }));
  };

  const handleConfirm = async (name: string, combo: string) => {
    setRecording(null);
    try {
      const updated = await updateHotkeyBinding(name, combo);
      mutate(updated);
      setError((prev) => ({ ...prev, [name]: "" }));
      toast.success(t("settings.shortcuts.success", { shortcut: displayCombo(combo) }));
    } catch (err) {
      const msg = typeof err === "string" ? err : String(err);
      setError((prev) => ({ ...prev, [name]: msg }));
      toast.error(msg);
    }
  };

  const handleReset = async (name: string) => {
    try {
      const updated = await resetHotkeyBinding(name);
      mutate(updated);
      setError((prev) => ({ ...prev, [name]: "" }));
      const defaultCombo = DEFAULT_HOTKEYS[name as keyof HotkeyBindingsDto];
      toast.success(t("settings.shortcuts.resetSuccess", { shortcut: displayCombo(defaultCombo) }));
    } catch (err) {
      const msg = typeof err === "string" ? err : String(err);
      toast.error(msg);
    }
  };

  const handleCancel = () => {
    setRecording(null);
  };

  return (
    <div class={styles.section}>
      <h2 class={styles.sectionTitle}>{t("settings.keyboardShortcuts")}</h2>
      <p class={styles.sectionDescription}>
        {t("settings.shortcuts.description")}
      </p>

      <Show when={bindings()}>
        <table class={styles.table} role="grid">
          <thead>
            <tr>
              <th class={styles.th}>{t("settings.shortcuts.action")}</th>
              <th class={styles.th}>{t("settings.shortcuts.shortcut")}</th>
              <th class={styles.th}>
                <span class={styles.srOnly}>{t("settings.shortcuts.actions")}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            <For each={SHORTCUT_ROWS}>
              {(row) => (
                <tr class={styles.row}>
                  <td class={styles.labelCell}>{t(row.label)}</td>
                  <td class={styles.comboCell}>
                    <Show
                      when={recording() === row.name}
                      fallback={
                        <>
                          <kbd class={styles.kbd}>
                            {displayCombo(bindings()![row.name])}
                          </kbd>
                          <Show when={error()[row.name]}>
                            <span class={styles.errorBadge} title={error()[row.name]}>
                              !
                            </span>
                          </Show>
                        </>
                      }
                    >
                      <KeyRecorderInput
                        currentCombo={bindings()![row.name]}
                        onConfirm={(combo) => handleConfirm(row.name, combo)}
                        onCancel={handleCancel}
                      />
                    </Show>
                  </td>
                  <td class={styles.actionsCell}>
                    <Show when={recording() !== row.name}>
                      <Button
                        variant="ghost"
                        onClick={() => handleStartRecording(row.name)}
                        data-testid={`change-${row.name}`}
                      >
                        {t("settings.shortcuts.changeButton")}
                      </Button>
                      <Show when={bindings()![row.name] !== DEFAULT_HOTKEYS[row.name]}>
                        <Button
                          variant="ghost"
                          onClick={() => handleReset(row.name)}
                          data-testid={`reset-${row.name}`}
                        >
                          {t("settings.shortcuts.resetButton")}
                        </Button>
                      </Show>
                    </Show>
                  </td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </Show>

      <Show when={bindings.error}>
        <p class={styles.errorMessage} role="alert">
          {t("settings.shortcuts.loadError")}
        </p>
      </Show>

      <p class={styles.platformNote}>
        <Show when={typeof navigator !== "undefined" && detectPlatform() === "linux"}>
          {t("settings.shortcuts.waylandNote")}{" "}
          <code>{t("settings.shortcuts.waylandEnv")}</code>
        </Show>
      </p>
    </div>
  );
};

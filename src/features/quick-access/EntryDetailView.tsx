import type { Component } from "solid-js";
import { createSignal, Show, Switch, Match, onCleanup, onMount } from "solid-js";
import type { EntryMetadataDto } from "../entries/ipc";
import { revealPassword, copyToClipboard, generateHotpCode } from "../entries/ipc";
import { useTotpCode } from "../entries/useTotpCode";
import { formatTotpCode } from "../entries/formatCode";
import { CountdownRing } from "../entries/CountdownRing";
import { TypeBadge } from "../entries/TypeBadge";
import { Icon } from "../../components/Icon";
import { useToast } from "../../components/useToast";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { t } from "../../stores/i18nStore";
import styles from "./EntryDetailView.module.css";

export interface EntryDetailViewProps {
  entry: EntryMetadataDto;
  onBack: () => void;
}

/**
 * Detail view for a single entry in the quick-access popup.
 * Renders per-type content: credential, totp/hotp, or generic message.
 */
export const EntryDetailView: Component<EntryDetailViewProps> = (props) => {
  let containerRef: HTMLDivElement | undefined;

  onMount(() => {
    containerRef?.focus();
  });

  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      props.onBack();
    }
  };

  return (
    <div
      ref={containerRef}
      class={styles.container}
      onKeyDown={handleKeyDown}
      tabindex={-1}
    >
      <div class={styles.header}>
        <button
          class={styles.backBtn}
          onClick={props.onBack}
          aria-label={t("quickAccess.detail.back")}
        >
          <Icon name="chevron-left" size={16} />
        </button>
        <span class={styles.headerName}>{props.entry.name}</span>
        <TypeBadge entryType={props.entry.entryType} />
      </div>

      <div class={styles.body}>
        <Switch>
          <Match when={props.entry.entryType === "credential"}>
            <CredentialDetail entry={props.entry} />
          </Match>
          <Match when={props.entry.entryType === "totp" || props.entry.entryType === "hotp"}>
            <TotpDetail entry={props.entry} />
          </Match>
          <Match when={true}>
            <GenericDetail />
          </Match>
        </Switch>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Credential detail — username + password reveal with inline re-auth
// ---------------------------------------------------------------------------

const CredentialDetail: Component<{ entry: EntryMetadataDto }> = (props) => {
  const toast = useToast();
  const [password, setPassword] = createSignal("");
  const [revealedPassword, setRevealedPassword] = createSignal<string | null>(null);
  const [reAuthError, setReAuthError] = createSignal("");
  const [showReAuth, setShowReAuth] = createSignal(false);
  const [isRevealing, setIsRevealing] = createSignal(false);
  const [hideTimer, setHideTimer] = createSignal(0);

  let timerRef: ReturnType<typeof setInterval> | undefined;

  const clearSecret = () => {
    if (timerRef) { clearInterval(timerRef); timerRef = undefined; }
    setRevealedPassword(null);
    setShowReAuth(false);
    setPassword("");
    setHideTimer(0);
  };

  onMount(async () => {
    const unlisten = await getCurrentWindow().onFocusChanged(({ payload: focused }) => {
      if (!focused) clearSecret();
    });
    onCleanup(unlisten);
  });

  onCleanup(() => {
    if (timerRef) clearInterval(timerRef);
    setRevealedPassword(null);
    setPassword("");
  });

  const startHideTimer = () => {
    setHideTimer(30);
    timerRef = setInterval(() => {
      setHideTimer((s) => {
        if (s <= 1) {
          clearInterval(timerRef);
          timerRef = undefined;
          setRevealedPassword(null);
          setShowReAuth(false);
          setPassword("");
          return 0;
        }
        return s - 1;
      });
    }, 1000);
  };

  const handleRevealClick = () => {
    setShowReAuth(true);
    setReAuthError("");
  };

  const handleHideClick = () => { clearSecret(); };

  const handleReAuthSubmit = async (e: Event) => {
    e.preventDefault();
    if (!password()) {
      setReAuthError(t("quickAccess.detail.passwordRequired"));
      return;
    }
    setIsRevealing(true);
    setReAuthError("");
    try {
      const result = await revealPassword(props.entry.id, password());
      setRevealedPassword(result.password);
      setShowReAuth(false);
      setPassword("");
      startHideTimer();
    } catch {
      setReAuthError(t("quickAccess.detail.revealError"));
    } finally {
      setIsRevealing(false);
    }
  };

  const copyUsername = async () => {
    if (!props.entry.username) return;
    try {
      await copyToClipboard(props.entry.username);
      toast.success(t("quickAccess.detail.usernameCopied"));
      setTimeout(async () => {
        await getCurrentWindow().hide();
      }, 500);
    } catch {
      // silent
    }
  };

  const copyPasswordToClipboard = async () => {
    const pw = revealedPassword();
    if (!pw) return;
    try {
      await copyToClipboard(pw);
      toast.success(t("quickAccess.detail.passwordCopied"));
      setTimeout(async () => {
        await getCurrentWindow().hide();
      }, 500);
    } catch {
      // silent
    }
  };

  return (
    <>
      {/* Username row */}
      <Show when={props.entry.username}>
        <div class={styles.section}>
          <span class={styles.sectionLabel}>{t("quickAccess.detail.username")}</span>
          <div class={styles.secretRow}>
            <span class={styles.fieldValue}>{props.entry.username}</span>
            <button
              class={styles.copyBtn}
              onClick={copyUsername}
              aria-label={t("quickAccess.detail.usernameCopied")}
            >
              <Icon name="copy" size={14} />
            </button>
          </div>
        </div>
      </Show>

      {/* Password row */}
      <div class={styles.section}>
        <span class={styles.sectionLabel}>{t("quickAccess.detail.password")}</span>

        <Show when={revealedPassword()} fallback={
          <Show when={showReAuth()} fallback={
            <div class={styles.secretRow}>
              <span class={styles.masked}>&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;</span>
              <button
                class={styles.revealBtn}
                onClick={handleRevealClick}
              >
                <Icon name="eye" size={14} />
                <span>{t("quickAccess.detail.reveal")}</span>
              </button>
            </div>
          }>
            {/* Inline re-auth form */}
            <form class={styles.reAuthForm} onSubmit={handleReAuthSubmit}>
              <input
                class={styles.reAuthInput}
                type="password"
                value={password()}
                onInput={(e) => setPassword(e.currentTarget.value)}
                placeholder={t("quickAccess.passwordPlaceholder")}
                autocomplete="current-password"
                disabled={isRevealing()}
                autofocus
              />
              <button
                type="submit"
                class={styles.reAuthSubmit}
                disabled={isRevealing()}
              >
                {isRevealing() ? (
                  <Icon name="spinner" size={14} />
                ) : (
                  <Icon name="check" size={14} />
                )}
              </button>
            </form>
            <Show when={reAuthError()}>
              <span class={styles.reAuthError}>{reAuthError()}</span>
            </Show>
          </Show>
        }>
          {/* Revealed password */}
          <div class={styles.secretRow}>
            <span class={styles.revealedValue}>{revealedPassword()}</span>
            <button
              class={styles.copyBtn}
              onClick={copyPasswordToClipboard}
              aria-label={t("quickAccess.detail.passwordCopied")}
            >
              <Icon name="copy" size={14} />
            </button>
            <button
              class={styles.hideBtn}
              onClick={handleHideClick}
            >
              <Icon name="eye-off" size={14} />
            </button>
          </div>
          <Show when={hideTimer() > 0}>
            <span class={styles.timer}>
              {t("quickAccess.detail.hidingIn", { seconds: String(hideTimer()) })}
            </span>
          </Show>
        </Show>
      </div>
    </>
  );
};

// ---------------------------------------------------------------------------
// TOTP/HOTP detail — live code + countdown + copy
// ---------------------------------------------------------------------------

const TotpDetail: Component<{ entry: EntryMetadataDto }> = (props) => {
  const toast = useToast();
  const isTotp = () => props.entry.entryType === "totp";

  return (
    <Show when={isTotp()} fallback={<HotpDetail entry={props.entry} />}>
      <TotpLiveDetail entry={props.entry} toast={toast} />
    </Show>
  );
};

const TotpLiveDetail: Component<{ entry: EntryMetadataDto; toast: ReturnType<typeof useToast> }> = (props) => {
  const { code, remainingSeconds } = useTotpCode(props.entry.id, props.entry.period);

  const copyCode = async () => {
    const c = code();
    if (!c) return;
    try {
      await copyToClipboard(c);
      props.toast.success(t("quickAccess.detail.codeCopied"));
      setTimeout(async () => {
        await getCurrentWindow().hide();
      }, 500);
    } catch {
      // silent
    }
  };

  return (
    <div class={styles.totpDisplay}>
      <Show when={props.entry.issuer}>
        <span class={styles.totpIssuer}>{props.entry.issuer}</span>
      </Show>
      <div class={styles.totpCodeRow}>
        <span class={styles.totpCode}>
          {formatTotpCode(code(), props.entry.digits)}
        </span>
        <CountdownRing remaining={remainingSeconds()} period={props.entry.period} />
      </div>
      <button class={styles.totpCopyBtn} onClick={copyCode}>
        <Icon name="copy" size={14} />
        <span>{t("quickAccess.detail.copyCode")}</span>
      </button>
    </div>
  );
};

/**
 * HOTP is counter-based, so unlike TOTP there is no live code to show on mount.
 * The user explicitly generates the next code; generating advances + persists
 * the counter, copies the code to the concealed clipboard, and hides the popup.
 * The code is cleared on focus loss / unmount so it never lingers in the DOM.
 */
const HotpDetail: Component<{ entry: EntryMetadataDto }> = (props) => {
  const toast = useToast();
  const [code, setCode] = createSignal("");
  const [counter, setCounter] = createSignal<number | null>(null);
  const [isGenerating, setIsGenerating] = createSignal(false);

  onMount(async () => {
    const unlisten = await getCurrentWindow().onFocusChanged(({ payload: focused }) => {
      if (!focused) {
        setCode("");
        setCounter(null);
      }
    });
    onCleanup(unlisten);
  });

  onCleanup(() => {
    setCode("");
    setCounter(null);
  });

  const generateAndCopy = async () => {
    if (isGenerating()) return;
    setIsGenerating(true);
    try {
      const result = await generateHotpCode(props.entry.id);
      setCode(result.code);
      setCounter(result.counter + 1);
      await copyToClipboard(result.code);
      toast.success(t("quickAccess.detail.codeCopied"));
      setTimeout(async () => {
        await getCurrentWindow().hide();
      }, 500);
    } catch {
      // silent
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div class={styles.totpDisplay}>
      <Show when={props.entry.issuer}>
        <span class={styles.totpIssuer}>{props.entry.issuer}</span>
      </Show>
      <Show when={code()}>
        <div class={styles.totpCodeRow}>
          <span class={styles.totpCode}>
            {formatTotpCode(code(), props.entry.digits)}
          </span>
        </div>
        <Show when={counter() !== null}>
          <span class={styles.totpIssuer}>
            {t("quickAccess.detail.counterValue", { counter: String(counter()) })}
          </span>
        </Show>
      </Show>
      <button class={styles.totpCopyBtn} onClick={generateAndCopy} disabled={isGenerating()}>
        <Icon name="refresh" size={14} />
        <span>{t("quickAccess.detail.generateCode")}</span>
      </button>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Generic detail — "open main vault" message
// ---------------------------------------------------------------------------

const GenericDetail: Component = () => {
  return (
    <div class={styles.infoMessage}>
      <Icon name="lock" size={20} />
      <span>{t("quickAccess.detail.openMainVault")}</span>
    </div>
  );
};

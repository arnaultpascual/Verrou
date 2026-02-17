import type { Component } from "solid-js";
import {
  Show,
  For,
  createSignal,
  createEffect,
  on,
  onCleanup,
} from "solid-js";
import { Modal } from "../../components/Modal";
import { PasswordInput } from "../../components/PasswordInput";
import { SecurityCeremony } from "../../components/SecurityCeremony";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import { useToast } from "../../components/useToast";
import { QrCode } from "../entries/QrCode";
import { listEntries, type EntryMetadataDto } from "../entries/ipc";
import { parseUnlockError } from "../vault/ipc";
import { t } from "../../stores/i18nStore";
import { prepareQrTransfer, setScreenCaptureProtection, saveTransferFile } from "./qrTransferIpc";
import styles from "./QrTransferSendModal.module.css";

export interface QrTransferSendModalProps {
  open: boolean;
  onClose: () => void;
}

type Phase = "select" | "auth" | "preparing" | "transfer" | "error";

/** Sensitive entry types that require re-authentication. */
const SENSITIVE_TYPES = new Set(["seed_phrase", "recovery_code"]);

/** QR animation interval in ms (~2-3 FPS). */
const QR_FRAME_MS = 400;

export const QrTransferSendModal: Component<QrTransferSendModalProps> = (
  props,
) => {
  const toast = useToast();

  // Shared state
  const [phase, setPhase] = createSignal<Phase>("select");
  const [errorMessage, setErrorMessage] = createSignal("");
  const [shake, setShake] = createSignal(false);

  // Select phase
  const [entries, setEntries] = createSignal<EntryMetadataDto[]>([]);
  const [selected, setSelected] = createSignal<Set<string>>(new Set());

  // Auth phase
  const [password, setPassword] = createSignal("");

  // Preparing phase
  const [progress, setProgress] = createSignal(0);

  // Transfer phase
  const [chunks, setChunks] = createSignal<string[]>([]);
  const [verificationCode, setVerificationCode] = createSignal("");
  const [currentChunk, setCurrentChunk] = createSignal(0);
  const [captureProtected, setCaptureProtected] = createSignal(false);

  let progressInterval: ReturnType<typeof setInterval> | undefined;
  let qrInterval: ReturnType<typeof setInterval> | undefined;

  // Load entries when modal opens
  createEffect(
    on(
      () => props.open,
      async (open) => {
        if (open) {
          resetState();
          try {
            const all = await listEntries();
            setEntries(all);
          } catch {
            setEntries([]);
          }
        }
      },
    ),
  );

  // Animate QR codes in transfer phase
  createEffect(
    on(
      () => phase() === "transfer" && chunks().length > 0,
      (active) => {
        if (qrInterval) clearInterval(qrInterval);
        if (active && chunks().length > 1) {
          qrInterval = setInterval(() => {
            setCurrentChunk((prev) => (prev + 1) % chunks().length);
          }, QR_FRAME_MS);
        }
      },
    ),
  );

  onCleanup(() => {
    cleanup();
  });

  function resetState() {
    setPhase("select");
    setErrorMessage("");
    setShake(false);
    setSelected(new Set<string>());
    setPassword("");
    setProgress(0);
    setChunks([]);
    setVerificationCode("");
    setCurrentChunk(0);
    setCaptureProtected(false);
    if (progressInterval) clearInterval(progressInterval);
    if (qrInterval) clearInterval(qrInterval);
  }

  async function cleanup() {
    if (progressInterval) clearInterval(progressInterval);
    if (qrInterval) clearInterval(qrInterval);
    setPassword("");
    setChunks([]);
    setVerificationCode("");
    if (captureProtected()) {
      await setScreenCaptureProtection(false).catch(() => {});
      setCaptureProtected(false);
    }
  }

  function handleClose() {
    cleanup();
    props.onClose();
  }

  function hasSensitiveSelected(): boolean {
    const sel = selected();
    return entries().some((e) => sel.has(e.id) && SENSITIVE_TYPES.has(e.entryType));
  }

  function toggleEntry(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleAll() {
    const all = entries();
    if (selected().size === all.length) {
      setSelected(new Set<string>());
    } else {
      setSelected(new Set(all.map((e) => e.id)));
    }
  }

  function handleContinue() {
    if (selected().size === 0) return;
    if (hasSensitiveSelected()) {
      setPhase("auth");
    } else {
      startPrepare();
    }
  }

  function handleAuthSubmit(e: Event) {
    e.preventDefault();
    if (!password()) return;
    startPrepare();
  }

  async function startPrepare() {
    setPhase("preparing");
    setProgress(0);

    progressInterval = setInterval(() => {
      setProgress((prev) => (prev >= 90 ? prev : prev + 5));
    }, 100);

    try {
      const result = await prepareQrTransfer({
        entryIds: [...selected()],
        password: hasSensitiveSelected() ? password() : undefined,
      });

      if (progressInterval) clearInterval(progressInterval);
      setProgress(100);
      await new Promise((r) => setTimeout(r, 300));

      setChunks(result.chunks);
      setVerificationCode(result.verificationCode);
      setCurrentChunk(0);

      // Enable screen capture protection
      try {
        const applied = await setScreenCaptureProtection(true);
        setCaptureProtected(applied);
      } catch {
        setCaptureProtected(false);
      }

      setPhase("transfer");
      setPassword("");
    } catch (err) {
      if (progressInterval) clearInterval(progressInterval);
      setProgress(0);
      setPassword("");

      const errorStr = typeof err === "string" ? err : String(err);
      const parsed = parseUnlockError(errorStr);
      setErrorMessage(parsed.message);
      setPhase("error");
      setShake(true);
      setTimeout(() => setShake(false), 200);
    }
  }

  function handleRetry() {
    setErrorMessage("");
    setPhase("select");
  }

  async function handleSaveToFile() {
    try {
      const path = await saveTransferFile(chunks());
      if (path) {
        toast.success(t("export.qrTransfer.send.toastFileSaved"));
      }
    } catch (err) {
      toast.error(t("export.qrTransfer.send.toastFileFailed"));
    }
  }

  return (
    <Modal
      open={props.open}
      onClose={handleClose}
      title={t("export.qrTransfer.send.title")}
      closeOnOverlayClick={false}
    >
      {/* Phase: Entry selection */}
      <Show when={phase() === "select"}>
        <p class={styles.description}>
          {t("export.qrTransfer.send.selectDescription")}
        </p>

        <Show when={entries().length > 0}>
          <label class={styles.selectAll}>
            <input
              type="checkbox"
              checked={selected().size === entries().length && entries().length > 0}
              onChange={toggleAll}
            />
            {t("export.qrTransfer.send.selectAll", { count: String(entries().length) })}
          </label>

          <div class={styles.entryList}>
            <For each={entries()}>
              {(entry) => (
                <label class={styles.entryItem}>
                  <input
                    type="checkbox"
                    checked={selected().has(entry.id)}
                    onChange={() => toggleEntry(entry.id)}
                  />
                  <span class={styles.entryName}>
                    {entry.name}
                    <Show when={entry.issuer}>
                      <span class={styles.entryIssuer}>
                        {" "}
                        ({entry.issuer})
                      </span>
                    </Show>
                  </span>
                  <span class={styles.entryType}>{entry.entryType}</span>
                </label>
              )}
            </For>
          </div>

          <p class={styles.selectionCount}>
            {t("export.qrTransfer.send.selectionCount", { selected: String(selected().size), total: String(entries().length) })}
          </p>
        </Show>

        <Show when={entries().length === 0}>
          <p class={styles.description}>{t("export.qrTransfer.send.noEntries")}</p>
        </Show>

        <div class={styles.actions}>
          <Button variant="ghost" onClick={handleClose}>
            {t("common.cancel")}
          </Button>
          <Button
            disabled={selected().size === 0}
            onClick={handleContinue}
            data-testid="qr-send-continue"
          >
            {t("common.continue")}
          </Button>
        </div>
      </Show>

      {/* Phase: Re-authentication for sensitive entries */}
      <Show when={phase() === "auth"}>
        <form onSubmit={handleAuthSubmit} class={styles.authForm}>
          <p class={styles.sensitiveWarning}>
            {t("export.qrTransfer.send.sensitiveWarning")}
          </p>
          <PasswordInput
            label={t("export.qrTransfer.send.passwordLabel")}
            mode="unlock"
            value={password()}
            onInput={setPassword}
            placeholder={t("export.qrTransfer.send.passwordPlaceholder")}
          />
          <div class={styles.actions}>
            <Button variant="ghost" onClick={() => setPhase("select")}>
              {t("common.back")}
            </Button>
            <Button
              type="submit"
              disabled={!password()}
              data-testid="qr-send-auth"
            >
              {t("export.qrTransfer.send.authenticate")}
            </Button>
          </div>
        </form>
      </Show>

      {/* Phase: Preparing with ceremony */}
      <Show when={phase() === "preparing"}>
        <div class={styles.ceremonyWrapper}>
          <SecurityCeremony
            progress={progress()}
            onComplete={() => {}}
          />
        </div>
      </Show>

      {/* Phase: Transfer — QR display */}
      <Show when={phase() === "transfer"}>
        <div class={styles.transferContent}>
          <p class={styles.description}>
            {t("export.qrTransfer.send.verificationPrompt")}
          </p>
          <div class={styles.verificationCode} aria-live="polite">{verificationCode()}</div>

          <div class={styles.qrWrapper} aria-label={t("export.qrTransfer.send.ariaQrCode", { current: String(currentChunk() + 1), total: String(chunks().length) })}>
            <Show when={chunks().length > 0}>
              <QrCode data={chunks()[currentChunk()]} size={200} />
            </Show>
          </div>

          <p class={styles.chunkProgress} aria-live="polite">
            {t("export.qrTransfer.send.chunkProgress", { current: String(currentChunk() + 1), total: String(chunks().length) })}
          </p>

          <Show when={captureProtected()}>
            <p class={styles.captureWarning}>
              {t("export.qrTransfer.send.captureDisabled")}
            </p>
          </Show>
          <Show when={!captureProtected()}>
            <p class={styles.captureWarning}>
              {t("export.qrTransfer.send.captureUnavailable")}
            </p>
          </Show>

          <div class={styles.actions}>
            <Button
              variant="ghost"
              onClick={handleSaveToFile}
              data-testid="qr-send-save-file"
            >
              <Icon name="download" size={16} /> {t("export.qrTransfer.send.saveToFile")}
            </Button>
            <Button onClick={handleClose} data-testid="qr-send-done">
              {t("common.done")}
            </Button>
          </div>
        </div>
      </Show>

      {/* Phase: Error */}
      <Show when={phase() === "error"}>
        <div
          class={`${styles.errorContent} ${shake() ? styles.shake : ""}`}
        >
          <p class={styles.error} role="alert" data-testid="qr-send-error">
            {errorMessage()}
          </p>
          <div class={styles.actions}>
            <Button variant="ghost" onClick={handleClose}>
              {t("common.cancel")}
            </Button>
            <Button onClick={handleRetry} data-testid="qr-send-retry">
              {t("common.tryAgain")}
            </Button>
          </div>
        </div>
      </Show>
    </Modal>
  );
};

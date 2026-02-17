import type { Component } from "solid-js";
import { Show, createSignal, createEffect, on, onCleanup } from "solid-js";
import { Modal } from "../../components/Modal";
import { PasswordInput } from "../../components/PasswordInput";
import { SecurityCeremony } from "../../components/SecurityCeremony";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import { useToast } from "../../components/useToast";
import { parseUnlockError } from "../vault/ipc";
import { t } from "../../stores/i18nStore";
import { generatePaperBackupData } from "./paperBackupIpc";
import type { PaperBackupData } from "./paperBackupIpc";
import { PaperBackupDocument } from "./PaperBackupDocument";
import styles from "./PaperBackupModal.module.css";

export interface PaperBackupModalProps {
  open: boolean;
  onClose: () => void;
}

type Phase = "input" | "generating" | "preview" | "error";

export const PaperBackupModal: Component<PaperBackupModalProps> = (props) => {
  const toast = useToast();

  const [password, setPassword] = createSignal("");
  const [phase, setPhase] = createSignal<Phase>("input");
  const [progress, setProgress] = createSignal(0);
  const [errorMessage, setErrorMessage] = createSignal("");
  const [backupData, setBackupData] = createSignal<PaperBackupData | null>(
    null,
  );
  const [shake, setShake] = createSignal(false);

  let progressInterval: ReturnType<typeof setInterval> | undefined;

  // Reset state when modal opens/closes
  createEffect(
    on(
      () => props.open,
      (open) => {
        if (open) {
          setPassword("");
          setPhase("input");
          setProgress(0);
          setErrorMessage("");
          setBackupData(null);
          setShake(false);
        } else {
          // Clear sensitive data on close (AC #4)
          setBackupData(null);
          setPassword("");
        }
      },
    ),
  );

  onCleanup(() => {
    if (progressInterval) clearInterval(progressInterval);
    setPassword("");
    setBackupData(null);
  });

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    if (!password() || phase() === "generating") return;

    setPhase("generating");
    setProgress(0);

    progressInterval = setInterval(() => {
      setProgress((prev) => (prev >= 90 ? prev : prev + 5));
    }, 100);

    try {
      const data = await generatePaperBackupData(password());

      if (progressInterval) clearInterval(progressInterval);
      setProgress(100);
      await new Promise((resolve) => setTimeout(resolve, 300));

      setBackupData(data);
      setPhase("preview");
    } catch (err) {
      if (progressInterval) clearInterval(progressInterval);
      setProgress(0);

      const errorStr = typeof err === "string" ? err : String(err);
      const parsed = parseUnlockError(errorStr);
      setErrorMessage(parsed.message);
      setPhase("error");
      setShake(true);
      setTimeout(() => setShake(false), 200);
    }
  };

  const handleRetry = () => {
    setPassword("");
    setErrorMessage("");
    setPhase("input");
  };

  const handlePrint = () => {
    window.print();
  };

  const handleClose = () => {
    setBackupData(null);
    setPassword("");
    props.onClose();
  };

  return (
    <Modal
      open={props.open}
      onClose={handleClose}
      title={t("export.paperBackup.title")}
      closeOnOverlayClick={false}
    >
      {/* Phase: Password input */}
      <Show when={phase() === "input"}>
        <form onSubmit={handleSubmit} class={styles.form}>
          <div class={styles.warning}>
            <Icon name="alert" size={18} class={styles.warningIcon} />
            <p class={styles.warningText}>
              {t("export.paperBackup.warningInput")}
            </p>
          </div>
          <p class={styles.description}>
            {t("export.paperBackup.description")}
          </p>
          <PasswordInput
            label={t("export.paperBackup.passwordLabel")}
            mode="unlock"
            value={password()}
            onInput={setPassword}
            placeholder={t("export.paperBackup.passwordPlaceholder")}
          />
          <div class={styles.actions}>
            <Button variant="ghost" onClick={handleClose}>
              {t("common.cancel")}
            </Button>
            <Button
              type="submit"
              disabled={!password()}
              data-testid="paper-backup-submit"
            >
              {t("export.paperBackup.generateButton")}
            </Button>
          </div>
        </form>
      </Show>

      {/* Phase: Generating with ceremony */}
      <Show when={phase() === "generating"}>
        <div class={styles.ceremonyWrapper}>
          <SecurityCeremony
            progress={progress()}
            onComplete={() => {
              /* handled in async flow */
            }}
          />
        </div>
      </Show>

      {/* Phase: Preview with print */}
      <Show when={phase() === "preview" && backupData()}>
        <div class={styles.warning}>
          <Icon name="alert" size={18} class={styles.warningIcon} />
          <p class={styles.warningText}>
            {t("export.paperBackup.warningPreview")}
          </p>
        </div>
        <div class={styles.previewWrapper}>
          <PaperBackupDocument data={backupData()!} />
        </div>
        <div class={styles.actions}>
          <Button variant="ghost" onClick={handleClose} data-testid="paper-backup-close">
            {t("common.close")}
          </Button>
          <Button onClick={handlePrint} data-testid="paper-backup-print">
            <Icon name="print" size={16} /> {t("export.paperBackup.printButton")}
          </Button>
        </div>
      </Show>

      {/* Phase: Error */}
      <Show when={phase() === "error"}>
        <div
          class={`${styles.errorContent} ${shake() ? styles.shake : ""}`}
        >
          <p class={styles.error} role="alert" data-testid="paper-backup-error">
            {errorMessage()}
          </p>
          <div class={styles.actions}>
            <Button variant="ghost" onClick={handleClose}>
              {t("common.cancel")}
            </Button>
            <Button onClick={handleRetry} data-testid="paper-backup-retry">
              {t("common.tryAgain")}
            </Button>
          </div>
        </div>
      </Show>
    </Modal>
  );
};

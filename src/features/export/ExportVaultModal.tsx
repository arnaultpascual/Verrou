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
import { exportVault, pickExportLocation } from "./ipc";
import type { ExportVaultResponse } from "./ipc";
import styles from "./ExportVaultModal.module.css";

export interface ExportVaultModalProps {
  open: boolean;
  onClose: () => void;
}

type Phase = "location" | "input" | "exporting" | "success" | "error";

export const ExportVaultModal: Component<ExportVaultModalProps> = (props) => {
  const toast = useToast();

  const [password, setPassword] = createSignal("");
  const [phase, setPhase] = createSignal<Phase>("location");
  const [progress, setProgress] = createSignal(0);
  const [errorMessage, setErrorMessage] = createSignal("");
  const [result, setResult] = createSignal<ExportVaultResponse | null>(null);
  const [shake, setShake] = createSignal(false);
  const [savePath, setSavePath] = createSignal("");
  const [exportFilename, setExportFilename] = createSignal("");

  let progressInterval: ReturnType<typeof setInterval> | undefined;

  const basename = (p: string) => p.split(/[\\/]/).pop() || "vault-export.verrou";

  // Reset state when the modal opens.
  createEffect(
    on(
      () => props.open,
      (open) => {
        if (open) {
          setPassword("");
          setPhase("location");
          setProgress(0);
          setErrorMessage("");
          setResult(null);
          setShake(false);
          setSavePath("");
          setExportFilename("");
        }
      },
    ),
  );

  onCleanup(() => {
    if (progressInterval) clearInterval(progressInterval);
    setPassword("");
  });

  // Step 1 (low-stakes): choose the destination BEFORE asking for the password,
  // so cancelling the native save dialog never costs a typed master password.
  const handleChooseLocation = async () => {
    const path = await pickExportLocation();
    if (!path) return; // cancelled — stay on the location step
    setSavePath(path);
    setExportFilename(basename(path));
    setPhase("input");
  };

  // Step 2 (high-stakes): authenticate, then export to the already-chosen path.
  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    if (!password() || phase() === "exporting" || !savePath()) return;

    setPhase("exporting");
    setProgress(0);
    progressInterval = setInterval(() => {
      setProgress((prev) => (prev >= 90 ? prev : prev + 5));
    }, 100);

    try {
      const exportResult = await exportVault(password(), savePath());

      if (progressInterval) clearInterval(progressInterval);
      setProgress(100);
      await new Promise((resolve) => setTimeout(resolve, 300));

      setResult(exportResult);
      setPhase("success");
      toast.success(t("export.vault.toastSuccess", { filename: exportFilename() }));
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
    setPhase("input"); // keep the already-chosen location
  };

  return (
    <Modal
      open={props.open}
      onClose={props.onClose}
      title={t("export.vault.title")}
      closeOnOverlayClick={false}
    >
      {/* Phase: choose the destination first */}
      <Show when={phase() === "location"}>
        <div class={styles.form}>
          <p class={styles.description}>{t("export.vault.description")}</p>
          <p class={styles.trust}>
            <Icon name="lock" size={14} class={styles.trustIcon} />
            <span>{t("export.vault.trust")}</span>
          </p>
          <div class={styles.actions}>
            <Button variant="ghost" onClick={props.onClose}>
              {t("common.cancel")}
            </Button>
            <Button onClick={handleChooseLocation} data-testid="export-choose-location">
              {t("export.vault.chooseLocationButton")}
            </Button>
          </div>
        </div>
      </Show>

      {/* Phase: authenticate (destination already chosen) */}
      <Show when={phase() === "input"}>
        <form onSubmit={handleSubmit} class={styles.form}>
          <p class={styles.savingTo}>
            {t("export.vault.savingTo", { filename: exportFilename() })}{" "}
            <button
              type="button"
              class={styles.changeBtn}
              onClick={() => setPhase("location")}
              data-testid="export-change-location"
            >
              {t("export.vault.changeLocation")}
            </button>
          </p>
          <PasswordInput
            label={t("export.vault.passwordLabel")}
            mode="unlock"
            value={password()}
            onInput={setPassword}
            placeholder={t("export.vault.passwordPlaceholder")}
          />
          <div class={styles.actions}>
            <Button variant="ghost" onClick={props.onClose}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" disabled={!password()} data-testid="export-vault-submit">
              {t("export.vault.submitButton")}
            </Button>
          </div>
        </form>
      </Show>

      {/* Phase: exporting */}
      <Show when={phase() === "exporting"}>
        <div class={styles.ceremonyWrapper}>
          <SecurityCeremony
            progress={progress()}
            onComplete={() => {
              /* handled in async flow */
            }}
          />
        </div>
      </Show>

      {/* Phase: success */}
      <Show when={phase() === "success" && result()}>
        <div class={styles.successContent}>
          <div class={styles.successIcon}>
            <Icon name="check" size={48} />
          </div>
          <h3 class={styles.successHeading}>{t("export.vault.successHeading")}</h3>
          <ul class={styles.statList}>
            <li class={styles.statItem}>
              <span class={styles.statLabel}>{t("export.vault.entries")}</span>
              <span class={styles.statValue}>{result()!.entryCount}</span>
            </li>
            <li class={styles.statItem}>
              <span class={styles.statLabel}>{t("export.vault.folders")}</span>
              <span class={styles.statValue}>{result()!.folderCount}</span>
            </li>
            <li class={styles.statItem}>
              <span class={styles.statLabel}>{t("export.vault.attachments")}</span>
              <span class={styles.statValue}>{result()!.attachmentCount}</span>
            </li>
          </ul>
          <div class={styles.actions}>
            <Button onClick={props.onClose} data-testid="export-vault-done">
              {t("common.done")}
            </Button>
          </div>
        </div>
      </Show>

      {/* Phase: error */}
      <Show when={phase() === "error"}>
        <div class={`${styles.errorContent} ${shake() ? styles.shake : ""}`}>
          <p class={styles.error} role="alert" data-testid="export-error">
            {errorMessage()}
          </p>
          <div class={styles.actions}>
            <Button variant="ghost" onClick={props.onClose}>
              {t("common.cancel")}
            </Button>
            <Button onClick={handleRetry} data-testid="export-retry">
              {t("common.tryAgain")}
            </Button>
          </div>
        </div>
      </Show>
    </Modal>
  );
};

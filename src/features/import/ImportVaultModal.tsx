import type { Component } from "solid-js";
import { Show, createSignal, createEffect, on, onCleanup } from "solid-js";
import { Modal } from "../../components/Modal";
import { PasswordInput } from "../../components/PasswordInput";
import { SecurityCeremony } from "../../components/SecurityCeremony";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import { useToast } from "../../components/useToast";
import { parseUnlockError } from "../vault/ipc";
import {
  pickVerrouImportFile,
  validateVerrouImport,
  confirmVerrouImport,
} from "./verrou-ipc";
import type {
  DuplicateMode,
  VerrouImportPreviewDto,
  VerrouImportResultDto,
} from "./verrou-ipc";
import { t } from "../../stores/i18nStore";
import styles from "./ImportVaultModal.module.css";

export interface ImportVaultModalProps {
  open: boolean;
  onClose: () => void;
}

type Phase = "input" | "validating" | "preview" | "importing" | "success" | "error";

export const ImportVaultModal: Component<ImportVaultModalProps> = (props) => {
  const toast = useToast();

  const [filePath, setFilePath] = createSignal("");
  const [password, setPassword] = createSignal("");
  const [phase, setPhase] = createSignal<Phase>("input");
  const [progress, setProgress] = createSignal(0);
  const [errorMessage, setErrorMessage] = createSignal("");
  const [preview, setPreview] = createSignal<VerrouImportPreviewDto | null>(null);
  const [result, setResult] = createSignal<VerrouImportResultDto | null>(null);
  const [duplicateMode, setDuplicateMode] = createSignal<DuplicateMode>("skip");
  const [shake, setShake] = createSignal(false);

  let progressInterval: ReturnType<typeof setInterval> | undefined;

  // Reset state when modal opens/closes
  createEffect(
    on(
      () => props.open,
      (open) => {
        if (open) {
          setFilePath("");
          setPassword("");
          setPhase("input");
          setProgress(0);
          setErrorMessage("");
          setPreview(null);
          setResult(null);
          setDuplicateMode("skip");
          setShake(false);
        }
      },
    ),
  );

  onCleanup(() => {
    if (progressInterval) clearInterval(progressInterval);
    setPassword("");
  });

  const handlePickFile = async () => {
    const path = await pickVerrouImportFile();
    if (path) setFilePath(path);
  };

  const displayFileName = () => {
    const p = filePath();
    if (!p) return "";
    const parts = p.split(/[\\/]/);
    return parts[parts.length - 1] || p;
  };

  const handleValidate = async (e: Event) => {
    e.preventDefault();
    if (!filePath() || !password() || phase() === "validating") return;

    setPhase("validating");
    setProgress(0);

    progressInterval = setInterval(() => {
      setProgress((prev) => (prev >= 90 ? prev : prev + 5));
    }, 100);

    try {
      const result = await validateVerrouImport(filePath(), password());

      if (progressInterval) clearInterval(progressInterval);
      setProgress(100);
      await new Promise((resolve) => setTimeout(resolve, 300));

      setPreview(result);
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

  const handleImport = async () => {
    if (!filePath() || !password() || phase() === "importing") return;

    setPhase("importing");
    setProgress(0);

    progressInterval = setInterval(() => {
      setProgress((prev) => (prev >= 90 ? prev : prev + 3));
    }, 100);

    try {
      const importResult = await confirmVerrouImport(
        filePath(),
        password(),
        duplicateMode(),
      );

      if (progressInterval) clearInterval(progressInterval);
      setProgress(100);
      await new Promise((resolve) => setTimeout(resolve, 300));

      setResult(importResult);
      setPhase("success");
      toast.success(
        t("import.vault.toastSuccess", { count: importResult.importedEntries }),
      );
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

  const handleBackToInput = () => {
    setPassword("");
    setErrorMessage("");
    setPreview(null);
    setPhase("input");
  };

  return (
    <Modal
      open={props.open}
      onClose={props.onClose}
      title={t("import.vault.title")}
      closeOnOverlayClick={false}
    >
      {/* Phase: File + password input */}
      <Show when={phase() === "input"}>
        <form onSubmit={handleValidate} class={styles.form}>
          <p class={styles.description}>
            {t("import.vault.description")}
          </p>

          <div class={styles.fileSection}>
            <span class={styles.fileLabel}>{t("import.vault.fileLabel")}</span>
            <div class={styles.fileRow}>
              <span
                class={filePath() ? styles.filePath : styles.filePathEmpty}
                title={filePath()}
              >
                {displayFileName() || t("import.vault.noFile")}
              </span>
              <Button
                variant="ghost"
                onClick={handlePickFile}
                data-testid="pick-import-file"
              >
                {t("import.vault.browse")}
              </Button>
            </div>
          </div>

          <PasswordInput
            label={t("import.vault.passwordLabel")}
            mode="unlock"
            value={password()}
            onInput={setPassword}
            placeholder={t("import.vault.passwordPlaceholder")}
          />

          <div class={styles.actions}>
            <Button variant="ghost" onClick={props.onClose}>
              {t("common.cancel")}
            </Button>
            <Button
              type="submit"
              disabled={!filePath() || !password()}
              data-testid="validate-import-submit"
            >
              {t("import.vault.validate")}
            </Button>
          </div>
        </form>
      </Show>

      {/* Phase: Validating with ceremony */}
      <Show when={phase() === "validating"}>
        <div class={styles.ceremonyWrapper}>
          <SecurityCeremony
            progress={progress()}
            onComplete={() => {/* handled in async flow */}}
          />
        </div>
      </Show>

      {/* Phase: Preview — show what will be imported */}
      <Show when={phase() === "preview" && preview()}>
        <div class={styles.previewContent}>
          <div class={styles.previewSummary}>
            <div class={styles.previewStat}>
              <span class={styles.previewStatLabel}>{t("import.vault.entries")}</span>
              <span class={styles.previewStatValue}>{preview()!.totalEntries}</span>
            </div>
            <div class={styles.previewStat}>
              <span class={styles.previewStatLabel}>{t("import.vault.folders")}</span>
              <span class={styles.previewStatValue}>{preview()!.totalFolders}</span>
            </div>
            <div class={styles.previewStat}>
              <span class={styles.previewStatLabel}>{t("import.vault.attachments")}</span>
              <span class={styles.previewStatValue}>{preview()!.totalAttachments}</span>
            </div>
          </div>

          <p class={styles.description}>
            {t("import.vault.mergeDescription")}
          </p>

          <Show when={preview()!.duplicateCount > 0}>
            <div class={styles.duplicateWarning}>
              <Icon name="alert" size={16} class={styles.duplicateIcon} />
              <div>
                <p class={styles.duplicateText}>
                  {t("import.vault.duplicatesFound", { count: preview()!.duplicateCount })}
                </p>
                <div class={styles.duplicateMode}>
                  <label class={styles.modeOption}>
                    <input
                      type="radio"
                      name="duplicateMode"
                      value="skip"
                      checked={duplicateMode() === "skip"}
                      onChange={() => setDuplicateMode("skip")}
                    />
                    {t("import.vault.skipDuplicates")}
                  </label>
                  <label class={styles.modeOption}>
                    <input
                      type="radio"
                      name="duplicateMode"
                      value="replace"
                      checked={duplicateMode() === "replace"}
                      onChange={() => setDuplicateMode("replace")}
                    />
                    {t("import.vault.replaceDuplicates")}
                  </label>
                </div>
              </div>
            </div>
          </Show>

          <div class={styles.actions}>
            <Button variant="ghost" onClick={handleBackToInput}>
              {t("common.back")}
            </Button>
            <Button
              onClick={handleImport}
              data-testid="confirm-import-submit"
            >
              {t("import.vault.importEntries", { count: preview()!.totalEntries })}
            </Button>
          </div>
        </div>
      </Show>

      {/* Phase: Importing with ceremony */}
      <Show when={phase() === "importing"}>
        <div class={styles.ceremonyWrapper}>
          <SecurityCeremony
            progress={progress()}
            onComplete={() => {/* handled in async flow */}}
          />
        </div>
      </Show>

      {/* Phase: Success */}
      <Show when={phase() === "success" && result()}>
        <div class={styles.successContent}>
          <div class={styles.successIcon}>
            <Icon name="check" size={48} />
          </div>
          <h3 class={styles.successHeading}>{t("import.vault.importComplete")}</h3>
          <ul class={styles.statList}>
            <li class={styles.statItem}>
              <span class={styles.statLabel}>{t("import.vault.entriesImported")}</span>
              <span class={styles.statValue}>{result()!.importedEntries}</span>
            </li>
            <li class={styles.statItem}>
              <span class={styles.statLabel}>{t("import.vault.foldersCreated")}</span>
              <span class={styles.statValue}>{result()!.importedFolders}</span>
            </li>
            <li class={styles.statItem}>
              <span class={styles.statLabel}>{t("import.vault.attachmentsImported")}</span>
              <span class={styles.statValue}>{result()!.importedAttachments}</span>
            </li>
            <Show when={result()!.skippedDuplicates > 0}>
              <li class={styles.statItem}>
                <span class={styles.statLabel}>{t("import.vault.duplicatesSkipped")}</span>
                <span class={styles.statValue}>{result()!.skippedDuplicates}</span>
              </li>
            </Show>
            <Show when={result()!.replacedEntries > 0}>
              <li class={styles.statItem}>
                <span class={styles.statLabel}>{t("import.vault.entriesReplaced")}</span>
                <span class={styles.statValue}>{result()!.replacedEntries}</span>
              </li>
            </Show>
          </ul>
          <div class={styles.actions}>
            <Button onClick={props.onClose} data-testid="import-vault-done">
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
          <p class={styles.error} role="alert" data-testid="import-error">
            {errorMessage()}
          </p>
          <div class={styles.actions}>
            <Button variant="ghost" onClick={props.onClose}>
              {t("common.cancel")}
            </Button>
            <Button onClick={handleRetry} data-testid="import-retry">
              {t("common.tryAgain")}
            </Button>
          </div>
        </div>
      </Show>
    </Modal>
  );
};

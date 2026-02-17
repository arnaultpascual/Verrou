import type { Component } from "solid-js";
import { onMount, Show, For } from "solid-js";
import { Button, Icon, SecurityCeremony } from "../../components";
import {
  confirmGoogleAuthImport,
  confirmAegisImport,
  confirmTwofasImport,
} from "./ipc";
import type { ImportSource, ImportSummaryDto, ValidationReportDto } from "./types";
import { t } from "../../stores/i18nStore";
import styles from "./ImportProgressStep.module.css";

export interface ImportProgressStepProps {
  source: ImportSource;
  fileData: string;
  password: string | null;
  skipIndices: number[];
  report: ValidationReportDto;
  onComplete: (summary: ImportSummaryDto) => void;
  onError: (error: string) => void;
  onRetry: () => void;
  onDone: () => void;
  summary: ImportSummaryDto | null;
  error: string | null;
}

export const ImportProgressStep: Component<ImportProgressStepProps> = (props) => {
  onMount(async () => {
    // Skip if already have result
    if (props.summary || props.error) return;

    try {
      let result: ImportSummaryDto;

      if (props.source === "google-auth") {
        result = await confirmGoogleAuthImport(
          props.fileData,
          props.skipIndices,
        );
      } else if (props.source === "aegis") {
        result = await confirmAegisImport(
          props.fileData,
          props.password ?? undefined,
          props.skipIndices,
        );
      } else {
        result = await confirmTwofasImport(
          props.fileData,
          props.password ?? undefined,
          props.skipIndices,
        );
      }

      props.onComplete(result);
    } catch (err) {
      const message =
        typeof err === "string"
          ? err
          : t("import.progress.unexpectedError");
      props.onError(message);
    }
  });

  const isLoading = () => !props.summary && !props.error;
  const isSuccess = () => props.summary !== null;
  const isError = () => props.error !== null;

  const importedNames = () => {
    if (!props.report) return [];
    const skip = new Set(props.skipIndices);
    // Valid entries that were not skipped
    const validNames = props.report.validEntries
      .filter((e) => !skip.has(e.index))
      .map((e) => e.name);
    // Duplicates that were force-imported (not in skipIndices)
    const dupNames = props.report.duplicates
      .filter((d) => !skip.has(d.index))
      .map((d) => d.name);
    return [...validNames, ...dupNames];
  };

  return (
    <div class={styles.step} aria-live="polite">
      {/* Loading state */}
      <Show when={isLoading()}>
        <SecurityCeremony progress={50} />
        <p class={styles.resultTitle}>{t("import.progress.importing")}</p>
        <p class={styles.resultDetail}>
          {t("import.progress.doNotClose")}
        </p>
      </Show>

      {/* Success state */}
      <Show when={isSuccess()}>
        <div class={`${styles.resultIcon} ${styles.successIcon}`}>
          <Icon name="check" size={32} />
        </div>
        <p class={styles.resultTitle}>
          {t("import.progress.successCount", { count: String(props.summary!.imported) })}
        </p>
        <Show when={props.summary!.skipped > 0}>
          <p class={styles.resultDetailMuted}>
            {t("import.progress.skippedCount", { count: String(props.summary!.skipped) })}
          </p>
        </Show>
        <Show when={importedNames().length > 0}>
          <div class={styles.importedList}>
            <For each={importedNames()}>
              {(name) => (
                <span class={styles.importedEntry}>
                  <Icon name="check" size={12} /> {name}
                </span>
              )}
            </For>
          </div>
        </Show>
        <div class={styles.actions}>
          <Button variant="primary" onClick={props.onDone}>
            {t("import.progress.goToVault")}
          </Button>
        </div>
      </Show>

      {/* Error state */}
      <Show when={isError()}>
        <div class={`${styles.resultIcon} ${styles.errorIcon}`}>
          <Icon name="alert" size={32} />
        </div>
        <p class={styles.resultTitle}>{t("import.progress.failed")}</p>
        <p class={styles.resultDetail}>
          {t("import.progress.noChanges")}
        </p>
        <p class={styles.errorAction}>
          {t("import.progress.tryAgainHint")}
        </p>
        <p class={styles.errorMessage}>{props.error}</p>
        <div class={styles.actions}>
          <Button variant="ghost" onClick={props.onRetry}>
            {t("import.progress.tryAgain")}
          </Button>
        </div>
      </Show>
    </div>
  );
};

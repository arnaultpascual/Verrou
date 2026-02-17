import type { Component } from "solid-js";
import { createSignal, Show, For } from "solid-js";
import { Button, Icon } from "../../components";
import { useToast } from "../../components/useToast";
import { AddEntryModal } from "../entries/AddEntryModal";
import { TypeBadge } from "../entries/TypeBadge";
import type { ValidationReportDto } from "./types";
import { t } from "../../stores/i18nStore";
import styles from "./ValidationReportStep.module.css";

export interface ValidationReportStepProps {
  report: ValidationReportDto;
  onConfirm: (skipIndices: number[]) => void;
}

export const ValidationReportStep: Component<ValidationReportStepProps> = (props) => {
  const toast = useToast();

  // Track which valid entries are checked (all checked by default)
  const [checked, setChecked] = createSignal<Set<number>>(
    new Set(props.report.validEntries.map((e) => e.index)),
  );

  // Manual entry modal state
  const [manualEntry, setManualEntry] = createSignal<{ name?: string; issuer?: string } | null>(null);

  // Duplicate force-import state
  const [importDuplicates, setImportDuplicates] = createSignal<Set<number>>(new Set());

  // Collapsible sections
  const [showDuplicates, setShowDuplicates] = createSignal(false);
  const [showUnsupported, setShowUnsupported] = createSignal(false);
  const [showMalformed, setShowMalformed] = createSignal(false);

  const toggleEntry = (index: number) => {
    setChecked((prev) => {
      const next = new Set(prev);
      if (next.has(index)) {
        next.delete(index);
      } else {
        next.add(index);
      }
      return next;
    });
  };

  const importCount = () => checked().size + importDuplicates().size;

  const skipIndices = () => {
    const selected = checked();
    const forcedDups = importDuplicates();

    // Unchecked valid entries should be skipped
    const skippedValid = props.report.validEntries
      .filter((e) => !selected.has(e.index))
      .map((e) => e.index);

    // All duplicate indices that are NOT force-imported should be skipped
    const skippedDuplicates = props.report.duplicates
      .filter((d) => !forcedDups.has(d.index))
      .map((d) => d.index);

    return [...skippedValid, ...skippedDuplicates];
  };

  const handleConfirm = () => {
    props.onConfirm(skipIndices());
  };

  const toggleDuplicateImport = (index: number) => {
    setImportDuplicates((prev) => {
      const next = new Set(prev);
      if (next.has(index)) {
        next.delete(index);
      } else {
        next.add(index);
      }
      return next;
    });
  };

  const handleManualSuccess = () => {
    toast.success(t("import.validationReport.toastManualAdded"));
    setManualEntry(null);
  };

  const hasNoValid = () => props.report.validCount === 0;

  return (
    <div class={styles.step}>
      <h2 class={styles.heading}>{t("import.validationReport.heading")}</h2>

      {/* Summary counts */}
      <div class={styles.summary}>
        <div class={styles.summaryItem}>
          <span class={styles.summaryCount}>{props.report.totalParsed}</span>
          <span class={styles.summaryLabel}>{t("import.validationReport.found")}</span>
        </div>
        <div class={styles.summaryItem}>
          <span class={styles.summaryCount}>{props.report.validCount}</span>
          <span class={styles.summaryLabel}>{t("import.validationReport.valid")}</span>
        </div>
        <Show when={props.report.duplicateCount > 0}>
          <div class={styles.summaryItem}>
            <span class={styles.summaryCount}>{props.report.duplicateCount}</span>
            <span class={styles.summaryLabel}>{t("import.validationReport.duplicates")}</span>
          </div>
        </Show>
        <Show when={props.report.unsupportedCount > 0}>
          <div class={styles.summaryItem}>
            <span class={styles.summaryCount}>{props.report.unsupportedCount}</span>
            <span class={styles.summaryLabel}>{t("import.validationReport.unsupported")}</span>
          </div>
        </Show>
        <Show when={props.report.malformedCount > 0}>
          <div class={styles.summaryItem}>
            <span class={styles.summaryCount}>{props.report.malformedCount}</span>
            <span class={styles.summaryLabel}>{t("import.validationReport.malformed")}</span>
          </div>
        </Show>
      </div>

      {/* Empty state */}
      <Show when={hasNoValid()}>
        <div class={styles.emptyState}>
          <Icon name="alert" size={32} />
          <span class={styles.emptyTitle}>{t("import.validationReport.emptyTitle")}</span>
          <span class={styles.emptyDescription}>
            {t("import.validationReport.emptyDescription")}
          </span>
        </div>
      </Show>

      {/* Valid entries section */}
      <Show when={!hasNoValid()}>
        <div class={styles.section}>
          <button
            type="button"
            class={styles.sectionHeader}
            onClick={() => {}}
            aria-expanded="true"
          >
            <Icon name="check" size={16} />
            {t("import.validationReport.validEntries")}
            <span class={styles.sectionCount}>({props.report.validCount})</span>
          </button>
          <div class={styles.entryList}>
            <For each={props.report.validEntries}>
              {(entry) => (
                <label class={styles.entryRow}>
                  <input
                    type="checkbox"
                    class={styles.entryCheckbox}
                    checked={checked().has(entry.index)}
                    onChange={() => toggleEntry(entry.index)}
                  />
                  <span class={styles.entryName}>{entry.name}</span>
                  <Show when={entry.issuer}>
                    <span class={styles.entryIssuer}>{entry.issuer}</span>
                  </Show>
                  <TypeBadge entryType={entry.entryType} />
                </label>
              )}
            </For>
          </div>
        </div>
      </Show>

      {/* Duplicates section */}
      <Show when={props.report.duplicates.length > 0}>
        <div class={styles.section}>
          <button
            type="button"
            class={styles.sectionHeader}
            onClick={() => setShowDuplicates(!showDuplicates())}
            aria-expanded={showDuplicates()}
          >
            <Icon name="alert" size={16} />
            {t("import.validationReport.duplicates")}
            <span class={styles.sectionCount}>({props.report.duplicateCount})</span>
          </button>
          <Show when={showDuplicates()}>
            <div class={styles.entryList}>
              <For each={props.report.duplicates}>
                {(dup) => (
                  <div class={styles.entryRow}>
                    <span class={styles.entryName}>{dup.name}</span>
                    <Show when={dup.issuer}>
                      <span class={styles.entryIssuer}>{dup.issuer}</span>
                    </Show>
                    <span class={styles.duplicateMatch}>
                      {t("import.validationReport.alreadyExists", { name: dup.existingName })}
                    </span>
                    <div class={styles.duplicateActions}>
                      <button
                        type="button"
                        class={`${styles.duplicateToggle} ${!importDuplicates().has(dup.index) ? styles.duplicateToggleActive : ""}`}
                        onClick={(e) => {
                          e.stopPropagation();
                          const s = importDuplicates();
                          if (s.has(dup.index)) {
                            toggleDuplicateImport(dup.index);
                          }
                        }}
                        onKeyDown={(e) => e.stopPropagation()}
                      >
                        {t("import.validationReport.skip")}
                      </button>
                      <button
                        type="button"
                        class={`${styles.duplicateToggle} ${importDuplicates().has(dup.index) ? styles.duplicateToggleActive : ""}`}
                        onClick={(e) => {
                          e.stopPropagation();
                          const s = importDuplicates();
                          if (!s.has(dup.index)) {
                            toggleDuplicateImport(dup.index);
                          }
                        }}
                        onKeyDown={(e) => e.stopPropagation()}
                      >
                        {t("import.validationReport.importAnyway")}
                      </button>
                    </div>
                  </div>
                )}
              </For>
            </div>
          </Show>
        </div>
      </Show>

      {/* Unsupported section */}
      <Show when={props.report.unsupported.length > 0}>
        <div class={styles.section}>
          <button
            type="button"
            class={styles.sectionHeader}
            onClick={() => setShowUnsupported(!showUnsupported())}
            aria-expanded={showUnsupported()}
          >
            <Icon name="info" size={16} />
            {t("import.validationReport.unsupported")}
            <span class={styles.sectionCount}>({props.report.unsupportedCount})</span>
          </button>
          <Show when={showUnsupported()}>
            <div class={styles.entryList}>
              <For each={props.report.unsupported}>
                {(entry) => (
                  <div class={styles.entryRow}>
                    <span class={styles.entryName}>{entry.name}</span>
                    <span class={`${styles.entryReason} ${styles.unsupportedReason}`}>
                      {entry.reason}
                    </span>
                    <button
                      type="button"
                      class={styles.addManuallyLink}
                      onClick={(e) => {
                        e.stopPropagation();
                        setManualEntry({ name: entry.name, issuer: entry.issuer });
                      }}
                      onKeyDown={(e) => e.stopPropagation()}
                    >
                      {t("import.validationReport.addManually")}
                    </button>
                  </div>
                )}
              </For>
            </div>
          </Show>
        </div>
      </Show>

      {/* Malformed section */}
      <Show when={props.report.malformed.length > 0}>
        <div class={styles.section}>
          <button
            type="button"
            class={styles.sectionHeader}
            onClick={() => setShowMalformed(!showMalformed())}
            aria-expanded={showMalformed()}
          >
            <Icon name="alert" size={16} />
            {t("import.validationReport.malformed")}
            <span class={styles.sectionCount}>({props.report.malformedCount})</span>
          </button>
          <Show when={showMalformed()}>
            <div class={styles.entryList}>
              <For each={props.report.malformed}>
                {(entry) => (
                  <div class={styles.entryRow}>
                    <span class={styles.entryName}>{t("import.validationReport.entryNumber", { number: String(entry.index + 1) })}</span>
                    <span class={`${styles.entryReason} ${styles.malformedReason}`}>
                      {entry.reason}
                    </span>
                    <button
                      type="button"
                      class={styles.addManuallyLink}
                      onClick={(e) => {
                        e.stopPropagation();
                        setManualEntry({});
                      }}
                      onKeyDown={(e) => e.stopPropagation()}
                    >
                      {t("import.validationReport.addManually")}
                    </button>
                  </div>
                )}
              </For>
            </div>
          </Show>
        </div>
      </Show>

      {/* Footer with import button */}
      <Show when={!hasNoValid()}>
        <div class={styles.footer}>
          <span class={styles.importCount}>
            {t("import.validationReport.selectedCount", { count: String(importCount()) })}
          </span>
          <Button
            variant="primary"
            onClick={handleConfirm}
            disabled={importCount() === 0}
          >
            {t("import.validationReport.importButton", { count: String(importCount()) })}
          </Button>
        </div>
      </Show>

      {/* Add manually modal */}
      <AddEntryModal
        open={manualEntry() !== null}
        onClose={() => setManualEntry(null)}
        onSuccess={handleManualSuccess}
        initialData={manualEntry() ?? undefined}
      />
    </div>
  );
};

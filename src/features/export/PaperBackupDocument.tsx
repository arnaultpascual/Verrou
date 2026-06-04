import type { Component } from "solid-js";
import { For, Show } from "solid-js";
import { t } from "../../stores/i18nStore";
import type { PaperBackupData } from "./paperBackupIpc";
import styles from "./PaperBackupDocument.module.css";

export interface PaperBackupDocumentProps {
  data: PaperBackupData;
}

export const PaperBackupDocument: Component<PaperBackupDocumentProps> = (
  props,
) => {
  const hasSeeds = () => props.data.seeds.length > 0;
  const hasRecovery = () => props.data.recoveryCodes.length > 0;

  return (
    <div class={styles.document} data-testid="paper-backup-document">
      {/* Header */}
      <div class={styles.header}>
        <p class={styles.confidential}>{t("export.paperBackup.doc.confidential")}</p>
        <h2 class={styles.title}>{t("export.paperBackup.doc.title")}</h2>
        <p class={styles.meta}>
          {t("export.paperBackup.doc.generated", { date: props.data.generatedAt })}
          <br />
          {t("export.paperBackup.doc.fingerprint", {
            fingerprint: props.data.vaultFingerprint,
          })}
        </p>
      </div>

      <Show when={!hasSeeds() && !hasRecovery()}>
        <p class={styles.emptyState}>{t("export.paperBackup.doc.empty")}</p>
      </Show>

      {/* Seed Phrases Section */}
      <Show when={hasSeeds()}>
        <div class={styles.section} data-testid="seeds-section">
          <h3 class={styles.sectionTitle}>{t("export.paperBackup.doc.seedsTitle")}</h3>
          <For each={props.data.seeds}>
            {(seed) => {
              return (
                <div class={styles.entryBlock}>
                  <p class={styles.entryName}>
                    {seed.name}
                    <Show when={seed.issuer}>
                      <span class={styles.entryIssuer}> ({seed.issuer})</span>
                    </Show>
                  </p>
                  <div class={styles.wordGrid}>
                    <For each={seed.words}>
                      {(word, i) => (
                        <div class={styles.wordItem}>
                          <span class={styles.wordIndex}>{i() + 1}.</span>
                          <span class={styles.wordText}>{word}</span>
                        </div>
                      )}
                    </For>
                  </div>
                  <Show when={seed.hasPassphrase}>
                    <p class={styles.passphraseWarning}>
                      {t("export.paperBackup.doc.passphraseNote")}
                    </p>
                  </Show>
                </div>
              );
            }}
          </For>
        </div>
      </Show>

      {/* Recovery Codes Section */}
      <Show when={hasRecovery()}>
        <div class={styles.section} data-testid="recovery-section">
          <h3 class={styles.sectionTitle}>{t("export.paperBackup.doc.recoveryTitle")}</h3>
          <For each={props.data.recoveryCodes}>
            {(entry) => (
              <div class={styles.entryBlock}>
                <p class={styles.entryName}>
                  {entry.name}
                  <Show when={entry.issuer}>
                    <span class={styles.entryIssuer}> ({entry.issuer})</span>
                  </Show>
                </p>
                <div class={styles.codeGrid}>
                  <For each={entry.codes}>
                    {(code, i) => {
                      const isUsed = () => entry.used.includes(i());
                      return (
                        <div
                          class={`${styles.codeItem} ${isUsed() ? styles.codeUsed : ""}`}
                        >
                          <span class={styles.statusIcon}>
                            {isUsed() ? "✗" : "✓"}
                          </span>
                          <span>{code}</span>
                        </div>
                      );
                    }}
                  </For>
                </div>
                <p class={styles.remainingNote}>
                  {t("export.paperBackup.doc.remaining", {
                    remaining: String(entry.remainingCodes),
                    total: String(entry.totalCodes),
                  })}
                </p>
              </div>
            )}
          </For>
        </div>
      </Show>

      {/* Footer */}
      <div class={styles.footer}>
        <p class={styles.checksum}>
          <span class={styles.checksumLabel}>
            {t("export.paperBackup.doc.checksumLabel")}
          </span>
          {props.data.contentChecksum}
        </p>
        <p class={styles.footerWarning}>{t("export.paperBackup.doc.storeWarning")}</p>
      </div>
    </div>
  );
};

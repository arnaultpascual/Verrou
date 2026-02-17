import type { Component } from "solid-js";
import { For, Show } from "solid-js";
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
        <p class={styles.confidential}>CONFIDENTIAL</p>
        <h2 class={styles.title}>VERROU Paper Backup</h2>
        <p class={styles.meta}>
          Generated: {props.data.generatedAt}
          <br />
          Vault Fingerprint: {props.data.vaultFingerprint}
        </p>
      </div>

      <Show when={!hasSeeds() && !hasRecovery()}>
        <p class={styles.emptyState}>
          No seed phrases or recovery codes found in this vault.
        </p>
      </Show>

      {/* Seed Phrases Section */}
      <Show when={hasSeeds()}>
        <div class={styles.section} data-testid="seeds-section">
          <h3 class={styles.sectionTitle}>Seed Phrases</h3>
          <For each={props.data.seeds}>
            {(seed) => {
              return (
                <div class={styles.entryBlock}>
                  <p class={styles.entryName}>
                    {seed.name}
                    <Show when={seed.issuer}>
                      <span class={styles.entryIssuer}>
                        {" "}
                        ({seed.issuer})
                      </span>
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
                      Passphrase protected (25th word not included in this
                      backup)
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
          <h3 class={styles.sectionTitle}>Recovery Codes</h3>
          <For each={props.data.recoveryCodes}>
            {(entry) => (
              <div class={styles.entryBlock}>
                <p class={styles.entryName}>
                  {entry.name}
                  <Show when={entry.issuer}>
                    <span class={styles.entryIssuer}>
                      {" "}
                      ({entry.issuer})
                    </span>
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
                            {isUsed() ? "\u2717" : "\u2713"}
                          </span>
                          <span>{code}</span>
                        </div>
                      );
                    }}
                  </For>
                </div>
                <p class={styles.remainingNote}>
                  {entry.remainingCodes} of {entry.totalCodes} remaining
                </p>
              </div>
            )}
          </For>
        </div>
      </Show>

      {/* Footer */}
      <div class={styles.footer}>
        <p class={styles.checksum}>
          <span class={styles.checksumLabel}>Content Checksum (BLAKE3): </span>
          {props.data.contentChecksum}
        </p>
        <p class={styles.footerWarning}>
          Store this document in a secure physical location. Do NOT photograph
          or digitize this backup.
        </p>
      </div>
    </div>
  );
};

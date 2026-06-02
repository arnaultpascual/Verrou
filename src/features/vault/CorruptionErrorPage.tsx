import type { Component } from "solid-js";
import { createSignal, createResource, Show, For } from "solid-js";
import { Button, Icon, Modal, useToast } from "../../components";
import {
  listVaultBackups,
  restoreVaultBackup,
  parseUnlockError,
} from "./ipc";
import type { BackupInfoDto } from "./ipc";
import { t } from "../../stores/i18nStore";
import styles from "./CorruptionErrorPage.module.css";

export interface CorruptionErrorPageProps {
  /** The error message from the integrity check. */
  message: string;
  /** Called after successful restore to retry unlock. */
  onRestored: () => void;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  const mb = kb / 1024;
  return `${mb.toFixed(1)} MB`;
}

export const CorruptionErrorPage: Component<CorruptionErrorPageProps> = (props) => {
  const toast = useToast();

  const [showBackups, setShowBackups] = createSignal(false);
  const [selectedBackup, setSelectedBackup] = createSignal<BackupInfoDto | null>(null);
  const [confirmOpen, setConfirmOpen] = createSignal(false);
  const [restoring, setRestoring] = createSignal(false);
  const [restorePassword, setRestorePassword] = createSignal("");
  const [restorePasswordError, setRestorePasswordError] = createSignal("");

  const [backups] = createResource(showBackups, async (show) => {
    if (!show) return [];
    return listVaultBackups();
  });

  const handleShowBackups = () => {
    setShowBackups(true);
  };

  const handleSelectBackup = (backup: BackupInfoDto) => {
    setSelectedBackup(backup);
  };

  const handleRestoreClick = () => {
    if (!selectedBackup()) return;
    setRestorePassword("");
    setRestorePasswordError("");
    setConfirmOpen(true);
  };

  const handleModalClose = () => {
    setConfirmOpen(false);
    setRestorePassword("");
    setRestorePasswordError("");
  };

  const handleConfirmRestore = async () => {
    const backup = selectedBackup();
    if (!backup) return;

    const password = restorePassword();
    if (!password) {
      setRestorePasswordError(t("vault.corruption.passwordRequired"));
      return;
    }

    setRestorePasswordError("");
    setConfirmOpen(false);
    setRestoring(true);

    try {
      await restoreVaultBackup(backup.path, password);
      toast.success(t("vault.corruption.restoreSuccess"));
      props.onRestored();
    } catch (err) {
      setRestoring(false);
      const errorStr = typeof err === "string" ? err : String(err);
      const parsed = parseUnlockError(errorStr);
      if (parsed.code === "INVALID_PASSWORD") {
        setRestorePassword("");
        setRestorePasswordError(t("vault.corruption.invalidPassword"));
        setConfirmOpen(true);
      } else if (parsed.code === "RATE_LIMITED") {
        setRestorePassword("");
        setRestorePasswordError(t("vault.corruption.rateLimited"));
        setConfirmOpen(true);
      } else {
        toast.error(t("vault.corruption.restoreError"));
      }
    }
  };

  return (
    <div class={styles.container}>
      <div class={styles.content}>
        <Icon name="alert" size={48} class={styles.errorIcon} />

        <h1 class={styles.heading} data-testid="corruption-heading">
          {t("vault.corruption.heading")}
        </h1>

        <p class={styles.message} data-testid="corruption-message">
          {props.message}
        </p>

        <p class={styles.message}>
          {t("vault.corruption.backupHint")}
        </p>

        <Show when={!showBackups()}>
          <div class={styles.actions}>
            <Button
              onClick={handleShowBackups}
              data-testid="show-backups-btn"
            >
              {t("vault.corruption.restoreFromBackup")}
            </Button>
          </div>
        </Show>

        <Show when={showBackups()}>
          <div class={styles.backupSection}>
            <Show
              when={backups() && backups()!.length > 0}
              fallback={
                <p class={styles.emptyBackups} data-testid="no-backups">
                  {t("vault.corruption.noBackups")}
                </p>
              }
            >
              <div class={styles.backupList} data-testid="backup-list">
                <For each={backups()}>
                  {(backup) => (
                    <div
                      class={`${styles.backupItem} ${
                        selectedBackup()?.path === backup.path ? styles.selected : ""
                      }`}
                      onClick={() => handleSelectBackup(backup)}
                      data-testid="backup-item"
                    >
                      <input
                        type="radio"
                        name="backup"
                        checked={selectedBackup()?.path === backup.path}
                        onChange={() => handleSelectBackup(backup)}
                      />
                      <div class={styles.backupDetails}>
                        <span class={styles.backupTimestamp}>{backup.timestamp}</span>
                        <span class={styles.backupSize}>{formatBytes(backup.sizeBytes)}</span>
                      </div>
                    </div>
                  )}
                </For>
              </div>
            </Show>

            <div class={styles.actions}>
              <Button
                onClick={handleRestoreClick}
                disabled={!selectedBackup() || restoring()}
                data-testid="restore-btn"
              >
                {restoring() ? t("vault.corruption.restoring") : t("vault.corruption.restoreSelected")}
              </Button>
            </div>
          </div>
        </Show>
      </div>

      {/* Confirmation modal with password re-authentication */}
      <Modal
        open={confirmOpen()}
        onClose={handleModalClose}
        title={t("vault.corruption.confirmTitle")}
        actions={
          <>
            <Button variant="ghost" onClick={handleModalClose}>
              {t("vault.corruption.cancel")}
            </Button>
            <Button onClick={handleConfirmRestore} data-testid="confirm-restore-btn">
              {t("vault.corruption.restore")}
            </Button>
          </>
        }
      >
        <p>{t("vault.corruption.confirmMessage")}</p>
        <div class={styles.passwordField}>
          <label for="restore-password-input">{t("vault.corruption.passwordLabel")}</label>
          <input
            id="restore-password-input"
            type="password"
            value={restorePassword()}
            onInput={(e) => {
              setRestorePassword(e.currentTarget.value);
              setRestorePasswordError("");
            }}
            placeholder={t("vault.corruption.passwordPlaceholder")}
            autocomplete="current-password"
            data-testid="restore-password-input"
          />
          <Show when={restorePasswordError()}>
            <p class={styles.passwordError} data-testid="restore-password-error" role="alert">
              {restorePasswordError()}
            </p>
          </Show>
        </div>
      </Modal>
    </div>
  );
};

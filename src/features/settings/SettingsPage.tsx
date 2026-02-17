import type { Component } from "solid-js";
import { createSignal, Show, onCleanup } from "solid-js";
import { useNavigate } from "@solidjs/router";
import {
  PasswordInput,
  SecurityCeremony,
  Button,
  Icon,
  Spinner,
  useToast,
} from "../../components";
import {
  changeMasterPassword,
  deleteVault,
  parseUnlockError,
} from "../vault/ipc";
import type { PasswordChangeResponse } from "../vault/ipc";
import { setVaultState } from "../../stores/vaultStore";
import { KeyboardShortcuts } from "./KeyboardShortcuts";
import { BiometricSettings } from "./BiometricSettings";
import { HardwareSecurityStatus } from "./HardwareSecurityStatus";
import { PreferencesSection } from "./PreferencesSection";
import { SecurityInfoSection } from "./SecurityInfoSection";
import { AboutSection } from "./AboutSection";
import { ExportVaultModal } from "../export/ExportVaultModal";
import { PaperBackupModal } from "../export/PaperBackupModal";
import { QrTransferSendModal } from "../export/QrTransferSendModal";
import { QrTransferReceiveModal } from "../export/QrTransferReceiveModal";
import { ImportVaultModal } from "../import/ImportVaultModal";
import { t } from "../../stores/i18nStore";
import styles from "./SettingsPage.module.css";

type PasswordChangePhase =
  | "idle"       // Settings view, "Change Master Password" button
  | "reauth"     // Enter current password
  | "newpass"    // Enter new password + confirm
  | "changing"   // SecurityCeremony during re-auth + slot re-wrapping (single backend call)
  | "newkey"     // Display new recovery key
  | "error";     // Error state — show error in reauth form

export const SettingsPage: Component = () => {
  const toast = useToast();
  const navigate = useNavigate();

  const [phase, setPhase] = createSignal<PasswordChangePhase>("idle");
  const [currentPassword, setCurrentPassword] = createSignal("");
  const [newPassword, setNewPassword] = createSignal("");
  const [confirmPassword, setConfirmPassword] = createSignal("");
  const [errorMessage, setErrorMessage] = createSignal("");
  const [progress, setProgress] = createSignal(0);
  const [newRecoveryKey, setNewRecoveryKey] = createSignal<PasswordChangeResponse | null>(null);
  const [keySaved, setKeySaved] = createSignal(false);
  const [shake, setShake] = createSignal(false);

  // Export/Import vault state
  const [showExport, setShowExport] = createSignal(false);
  const [showPaperBackup, setShowPaperBackup] = createSignal(false);
  const [showImportVault, setShowImportVault] = createSignal(false);
  const [showQrSend, setShowQrSend] = createSignal(false);
  const [showQrReceive, setShowQrReceive] = createSignal(false);

  // Delete vault state
  type DeletePhase = "idle" | "confirm" | "auth" | "deleting" | "error";
  const [deletePhase, setDeletePhase] = createSignal<DeletePhase>("idle");
  const [deletePassword, setDeletePassword] = createSignal("");
  const [deleteError, setDeleteError] = createSignal("");
  const [deleteShake, setDeleteShake] = createSignal(false);

  let progressInterval: ReturnType<typeof setInterval> | undefined;

  onCleanup(() => {
    if (progressInterval) clearInterval(progressInterval);
    // Defense-in-depth: clear password values from SolidJS signals on unmount
    // so they don't linger in memory if the user navigates away mid-flow.
    setCurrentPassword("");
    setNewPassword("");
    setConfirmPassword("");
    setDeletePassword("");
  });

  const resetFlow = () => {
    setPhase("idle");
    setCurrentPassword("");
    setNewPassword("");
    setConfirmPassword("");
    setErrorMessage("");
    setProgress(0);
    setNewRecoveryKey(null);
    setKeySaved(false);
    if (progressInterval) clearInterval(progressInterval);
  };

  const triggerShake = () => {
    setShake(true);
    setTimeout(() => setShake(false), 200);
  };

  const handleStartChange = () => {
    setPhase("reauth");
    setCurrentPassword("");
    setErrorMessage("");
  };

  const handleCancel = () => {
    resetFlow();
  };

  const passwordsMatch = () =>
    newPassword().length > 0 && newPassword() === confirmPassword();

  const handleReAuthSubmit = (e: Event) => {
    e.preventDefault();
    if (!currentPassword()) return;

    // Re-auth is a UI gate — the actual password verification happens atomically
    // on the backend when changeMasterPassword is called during the "changing" phase.
    setErrorMessage("");
    setPhase("newpass");
  };

  const handlePasswordChange = async (e: Event) => {
    e.preventDefault();
    if (!passwordsMatch() || phase() === "changing") return;

    setPhase("changing");
    setProgress(0);

    progressInterval = setInterval(() => {
      setProgress((prev) => (prev >= 90 ? prev : prev + 5));
    }, 100);

    try {
      const result = await changeMasterPassword(
        currentPassword(),
        newPassword(),
      );

      if (progressInterval) clearInterval(progressInterval);
      setProgress(100);
      await new Promise((resolve) => setTimeout(resolve, 300));

      setNewRecoveryKey(result);
      setPhase("newkey");
    } catch (err) {
      if (progressInterval) clearInterval(progressInterval);
      setProgress(0);

      const errorStr = typeof err === "string" ? err : String(err);
      const parsed = parseUnlockError(errorStr);
      setErrorMessage(parsed.message);

      if (parsed.code === "INVALID_PASSWORD") {
        // Wrong current password — go back to re-auth with error
        setPhase("error");
        triggerShake();
      } else {
        setPhase("newpass");
        toast.error(t("settings.passwordChange.changeFailed"));
      }
    }
  };

  const handleFinish = () => {
    toast.success(t("settings.passwordChange.changeSuccess"));
    resetFlow();
  };

  // ── Delete vault handlers ──────────────────────────────────

  const resetDelete = () => {
    setDeletePhase("idle");
    setDeletePassword("");
    setDeleteError("");
  };

  const handleDeleteConfirm = async (e: Event) => {
    e.preventDefault();
    if (!deletePassword() || deletePhase() === "deleting") return;

    setDeletePhase("deleting");
    setDeleteError("");

    try {
      await deleteVault(deletePassword());
      setDeletePassword("");
      setVaultState("no-vault");
      navigate("/onboarding");
    } catch (err) {
      const errorStr = typeof err === "string" ? err : String(err);
      const parsed = parseUnlockError(errorStr);
      setDeleteError(parsed.message);
      setDeletePhase("error");
      setDeleteShake(true);
      setTimeout(() => setDeleteShake(false), 200);
    }
  };

  return (
    <div class={styles.page}>
      <h1 class={styles.pageTitle}>{t("settings.title")}</h1>

      {/* Preferences section — theme, timeout, startup */}
      <PreferencesSection />

      {/* Security section */}
      <div class={styles.section}>
        <h2 class={styles.sectionTitle}>{t("settings.security")}</h2>

        <BiometricSettings />
        <HardwareSecurityStatus />

        <Show when={phase() === "idle"}>
          <p class={styles.sectionDescription}>
            {t("settings.securityDescription")}
          </p>
          <div>
            <Button
              onClick={handleStartChange}
              data-testid="change-password-start"
            >
              {t("settings.changePasswordButton")}
            </Button>
          </div>
        </Show>

        {/* Phase: Re-authentication */}
        <Show when={phase() === "reauth" || phase() === "error"}>
          <div class={`${styles.changeFlow} ${shake() ? styles.shake : ""}`}>
            <h3 class={styles.flowHeading}>{t("settings.passwordChange.verifyHeading")}</h3>
            <p class={styles.flowDescription}>
              {t("settings.passwordChange.verifyDescription")}
            </p>

            <form class={styles.form} onSubmit={handleReAuthSubmit}>
              <PasswordInput
                label={t("settings.passwordChange.currentPasswordLabel")}
                mode="unlock"
                value={currentPassword()}
                onInput={setCurrentPassword}
                placeholder={t("settings.passwordChange.currentPasswordPlaceholder")}
                id="settings-current-password"
              />

              <Show when={phase() === "error"}>
                <p class={styles.error} role="alert" data-testid="reauth-error">
                  {errorMessage()}
                </p>
              </Show>

              <div class={styles.formActions}>
                <Button variant="ghost" onClick={handleCancel}>
                  {t("settings.passwordChange.cancel")}
                </Button>
                <Button
                  type="submit"
                  disabled={!currentPassword()}
                  data-testid="verify-password-btn"
                >
                  {t("settings.passwordChange.verifyButton")}
                </Button>
              </div>
            </form>
          </div>
        </Show>

        {/* Phase: New password */}
        <Show when={phase() === "newpass"}>
          <div class={styles.changeFlow}>
            <h3 class={styles.flowHeading}>{t("settings.passwordChange.newPasswordHeading")}</h3>
            <p class={styles.flowDescription}>
              {t("settings.passwordChange.newPasswordDescription")}
            </p>

            <form class={styles.form} onSubmit={handlePasswordChange}>
              <div class={styles.passwordSection}>
                <PasswordInput
                  label={t("settings.passwordChange.newPasswordLabel")}
                  mode="create"
                  value={newPassword()}
                  onInput={setNewPassword}
                  placeholder={t("settings.passwordChange.newPasswordPlaceholder")}
                  id="settings-new-password"
                />

                <PasswordInput
                  label={t("settings.passwordChange.confirmPasswordLabel")}
                  mode="unlock"
                  value={confirmPassword()}
                  onInput={setConfirmPassword}
                  error={
                    confirmPassword().length > 0 && !passwordsMatch()
                      ? t("settings.passwordChange.confirmPasswordError")
                      : undefined
                  }
                  placeholder={t("settings.passwordChange.confirmPasswordPlaceholder")}
                  id="settings-confirm-password"
                />
              </div>

              <div class={styles.formActions}>
                <Button variant="ghost" onClick={handleCancel}>
                  {t("settings.passwordChange.cancel")}
                </Button>
                <Button
                  type="submit"
                  disabled={!passwordsMatch()}
                  data-testid="change-password-btn"
                >
                  {t("settings.passwordChange.changeButton")}
                </Button>
              </div>
            </form>
          </div>
        </Show>

        {/* Phase: SecurityCeremony during slot re-wrapping */}
        <Show when={phase() === "changing"}>
          <div class={styles.changeFlow}>
            <div class={styles.ceremonyWrapper}>
              <SecurityCeremony
                progress={progress()}
                onComplete={() => {/* handled in async flow */}}
              />
            </div>
          </div>
        </Show>

        {/* Phase: New recovery key display */}
        <Show when={phase() === "newkey" && newRecoveryKey()}>
          <div class={styles.changeFlow}>
            <div style={{ "text-align": "center" }}>
              <Icon name="shield" size={36} />
            </div>

            <h3 class={styles.flowHeading} style={{ "text-align": "center" }}>
              {t("settings.passwordChange.newKeyHeading")}
            </h3>

            <p class={styles.flowDescription} style={{ "text-align": "center" }}>
              {t("settings.passwordChange.newKeyDescription")}
            </p>

            <div class={styles.keyDisplay}>
              <code class={styles.keyText} data-testid="new-recovery-key">
                {newRecoveryKey()!.formattedKey}
              </code>
            </div>

            <Show when={newRecoveryKey()!.vaultFingerprint}>
              <p class={styles.fingerprint}>
                {t("settings.vaultFingerprint")} <code>{newRecoveryKey()!.vaultFingerprint}</code>
              </p>
            </Show>

            <div class={styles.printActions}>
              <Button variant="ghost" onClick={() => window.print()} data-testid="print-btn">
                {t("settings.passwordChange.printButton")}
              </Button>
            </div>

            <label class={styles.confirmLabel}>
              <input
                type="checkbox"
                checked={keySaved()}
                onChange={(e) => setKeySaved(e.currentTarget.checked)}
                data-testid="confirm-saved-checkbox"
              />
              <span>{t("settings.passwordChange.keySaved")}</span>
            </label>

            <button
              class={styles.submitBtn}
              disabled={!keySaved()}
              onClick={handleFinish}
              data-testid="finish-btn"
            >
              {t("settings.passwordChange.doneButton")}
            </button>
          </div>
        </Show>
      </div>

      {/* Keyboard Shortcuts section */}
      <KeyboardShortcuts />

      {/* Import section */}
      <div class={styles.section}>
        <h2 class={styles.sectionTitle}>{t("settings.importSection")}</h2>
        <p class={styles.sectionDescription}>
          {t("settings.importDescription")}
        </p>
        <div>
          <Button onClick={() => navigate("/import")}>
            {t("settings.importButton")}
          </Button>
        </div>
      </div>

      {/* Export & Backup section */}
      <div class={styles.section}>
        <h2 class={styles.sectionTitle}>{t("settings.exportSection")}</h2>
        <p class={styles.sectionDescription}>
          {t("settings.exportDescription")}
        </p>
        <div class={styles.buttonGroup}>
          <Button
            onClick={() => setShowExport(true)}
            data-testid="export-vault-btn"
          >
            {t("settings.exportButton")}
          </Button>
          <Button
            variant="ghost"
            onClick={() => setShowPaperBackup(true)}
            data-testid="paper-backup-btn"
          >
            <Icon name="print" size={16} /> {t("settings.paperBackupButton")}
          </Button>
          <Button
            variant="ghost"
            onClick={() => setShowImportVault(true)}
            data-testid="import-vault-btn"
          >
            {t("settings.restoreButton")}
          </Button>
        </div>
      </div>
      <ExportVaultModal
        open={showExport()}
        onClose={() => setShowExport(false)}
      />
      <PaperBackupModal
        open={showPaperBackup()}
        onClose={() => setShowPaperBackup(false)}
      />
      <ImportVaultModal
        open={showImportVault()}
        onClose={() => setShowImportVault(false)}
      />

      {/* Device Transfer section */}
      <div class={styles.section}>
        <h2 class={styles.sectionTitle}>{t("settings.deviceTransfer")}</h2>
        <p class={styles.sectionDescription}>
          {t("settings.deviceTransferDescription")}
        </p>
        <div class={styles.buttonGroup}>
          <Button
            onClick={() => setShowQrSend(true)}
            data-testid="qr-send-btn"
          >
            <Icon name="share" size={16} /> {t("settings.sendEntriesButton")}
          </Button>
          <Button
            variant="ghost"
            onClick={() => setShowQrReceive(true)}
            data-testid="qr-receive-btn"
          >
            <Icon name="download" size={16} /> {t("settings.receiveEntriesButton")}
          </Button>
        </div>
      </div>
      <QrTransferSendModal
        open={showQrSend()}
        onClose={() => setShowQrSend(false)}
      />
      <QrTransferReceiveModal
        open={showQrReceive()}
        onClose={() => setShowQrReceive(false)}
      />

      {/* Clipboard section */}
      <div class={styles.section}>
        <h2 class={styles.sectionTitle}>{t("settings.clipboard")}</h2>
        <p class={styles.sectionDescription}>
          {t("settings.clipboardDescription")}
        </p>
        <div class={styles.infoNote} data-testid="clipboard-info-note">
          <Icon name="info" size={14} class={styles.infoNoteIcon} />
          <span>
            {t("settings.clipboardInfo")}
          </span>
        </div>
      </div>

      {/* Danger Zone section */}
      <div class={`${styles.section} ${styles.dangerSection}`}>
        <h2 class={`${styles.sectionTitle} ${styles.dangerTitle}`}>{t("settings.dangerZone")}</h2>

        <Show when={deletePhase() === "idle"}>
          <p class={styles.sectionDescription}>
            {t("settings.deleteVaultDescription")}
          </p>
          <div>
            <Button
              variant="ghost"
              class={styles.dangerBtn}
              onClick={() => setDeletePhase("confirm")}
              data-testid="delete-vault-start"
            >
              {t("settings.deleteVaultButton")}
            </Button>
          </div>
        </Show>

        <Show when={deletePhase() === "confirm"}>
          <div class={styles.changeFlow}>
            <div class={styles.dangerWarning}>
              <Icon name="info" size={18} />
              <div>
                <p class={styles.dangerWarningTitle}>
                  {t("settings.deleteFlow.warningTitle")}
                </p>
                <ul class={styles.dangerWarningList}>
                  <li>{t("settings.deleteFlow.warningEntries")}</li>
                  <li>{t("settings.deleteFlow.warningBackups")}</li>
                  <li>{t("settings.deleteFlow.warningRecoveryKey")}</li>
                </ul>
              </div>
            </div>

            <p class={styles.flowDescription}>
              {t("settings.deleteFlow.confirmQuestion")}
            </p>

            <div class={styles.formActions}>
              <Button variant="ghost" onClick={resetDelete}>
                {t("settings.deleteFlow.cancel")}
              </Button>
              <Button
                variant="ghost"
                class={styles.dangerBtn}
                onClick={() => setDeletePhase("auth")}
                data-testid="delete-vault-confirm"
              >
                {t("settings.deleteFlow.confirmButton")}
              </Button>
            </div>
          </div>
        </Show>

        <Show when={deletePhase() === "auth" || deletePhase() === "error"}>
          <div class={`${styles.changeFlow} ${deleteShake() ? styles.shake : ""}`}>
            <h3 class={styles.flowHeading}>{t("settings.deleteFlow.authHeading")}</h3>
            <p class={styles.flowDescription}>
              {t("settings.deleteFlow.authDescription")}
            </p>

            <form class={styles.form} onSubmit={handleDeleteConfirm}>
              <PasswordInput
                label={t("settings.deleteFlow.passwordLabel")}
                mode="unlock"
                value={deletePassword()}
                onInput={setDeletePassword}
                placeholder={t("settings.deleteFlow.passwordPlaceholder")}
                id="settings-delete-password"
              />

              <Show when={deletePhase() === "error"}>
                <p class={styles.error} role="alert" data-testid="delete-error">
                  {deleteError()}
                </p>
              </Show>

              <div class={styles.formActions}>
                <Button variant="ghost" onClick={resetDelete}>
                  {t("settings.deleteFlow.cancel")}
                </Button>
                <Button
                  type="submit"
                  variant="ghost"
                  class={styles.dangerBtn}
                  disabled={!deletePassword()}
                  data-testid="delete-vault-submit"
                >
                  {t("settings.deleteFlow.deleteButton")}
                </Button>
              </div>
            </form>
          </div>
        </Show>

        <Show when={deletePhase() === "deleting"}>
          <div class={styles.changeFlow}>
            <div class={styles.ceremonyWrapper}>
              <Spinner size={32} />
              <p class={styles.flowDescription}>{t("settings.deleteFlow.deleting")}</p>
            </div>
          </div>
        </Show>
      </div>

      {/* Security information section */}
      <SecurityInfoSection />

      {/* About section */}
      <AboutSection />
    </div>
  );
};

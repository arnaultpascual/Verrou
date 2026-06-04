import type { Component } from "solid-js";
import { createSignal, createEffect, on, onCleanup } from "solid-js";
import { Modal } from "../../components/Modal";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import { ReAuthPrompt } from "../../components/ReAuthPrompt";
import { useToast } from "../../components/useToast";
import { getEntry, revealOtpSecret, copyToClipboard } from "./ipc";
import { buildOtpAuthUri } from "./otpauth";
import { QrCode } from "./QrCode";
import { t } from "../../stores/i18nStore";
import styles from "./ExportUriModal.module.css";

export interface ExportUriModalProps {
  open: boolean;
  onClose: () => void;
  entryId: string;
  name: string;
  issuer?: string;
  entryType: string;
}

/**
 * Export an OTP account as an `otpauth://` URI + QR code.
 *
 * The raw secret never comes from `get_entry` (which withholds it). It is
 * fetched only through the re-authenticated `revealOtpSecret` path, so the
 * modal opens on a {@link ReAuthPrompt} gate and reveals the URI/QR only after
 * the master password is confirmed.
 */
export const ExportUriModal: Component<ExportUriModalProps> = (props) => {
  const toast = useToast();
  const [uri, setUri] = createSignal("");

  // AC #4: never leave a revealed secret in the DOM once the modal closes.
  createEffect(
    on(
      () => props.open,
      (open) => {
        if (!open) setUri("");
      },
    ),
  );

  onCleanup(() => setUri(""));

  // Re-authenticate, fetch the raw secret, and build the otpauth:// URI.
  // Rejects on a wrong password so ReAuthPrompt surfaces the error inline and
  // keeps itself open for retry — the URI is only set on real success.
  const handleVerified = async (password: string) => {
    const [detail, secret] = await Promise.all([
      getEntry(props.entryId),
      revealOtpSecret(props.entryId, password),
    ]);
    setUri(
      buildOtpAuthUri({
        type: detail.entryType as "totp" | "hotp",
        name: detail.name,
        issuer: detail.issuer,
        secret,
        algorithm: detail.algorithm,
        digits: detail.digits,
        period: detail.period,
        counter: detail.counter,
      }),
    );
  };

  const handleCopy = async () => {
    const currentUri = uri();
    if (!currentUri) return;
    try {
      await copyToClipboard(currentUri);
      toast.success(t("entries.exportUri.uriCopied"));
    } catch {
      toast.error(t("entries.exportUri.uriCopyError"));
    }
  };

  return (
    <>
      {/* Re-auth gate — the raw secret is re-auth-protected (export tier). */}
      <ReAuthPrompt
        open={props.open && !uri()}
        onClose={props.onClose}
        onVerified={handleVerified}
      />

      {/* Export content — rendered only after the secret has been revealed. */}
      <Modal
        open={props.open && Boolean(uri())}
        onClose={props.onClose}
        title={t("entries.exportUri.title")}
        closeOnOverlayClick={false}
      >
        {/* Warning (AC #2) */}
        <div class={styles.warning}>
          <Icon name="alert" size={16} class={styles.warningIcon} />
          <p class={styles.warningText}>
            {t("entries.exportUri.warning", { name: props.name })}
          </p>
        </div>

        <div class={styles.content}>
          {/* URI display */}
          <div class={styles.uriSection}>
            <label class={styles.uriLabel}>{t("entries.exportUri.uriLabel")}</label>
            <div class={styles.uriRow}>
              <code class={styles.uriText} data-testid="export-uri-text">
                {uri()}
              </code>
            </div>
            <Button variant="ghost" onClick={handleCopy} data-testid="copy-uri-btn">
              <Icon name="copy" size={16} /> {t("entries.exportUri.copyUri")}
            </Button>
          </div>

          {/* QR code (AC #3) */}
          <div class={styles.qrSection}>
            <label class={styles.qrLabel}>{t("entries.exportUri.qrLabel")}</label>
            <div class={styles.qrWrapper}>
              <QrCode data={uri()} size={200} />
            </div>
          </div>
        </div>

        <div class={styles.actions}>
          <Button onClick={props.onClose} data-testid="export-uri-close">
            {t("common.close")}
          </Button>
        </div>
      </Modal>
    </>
  );
};

import type { Component } from "solid-js";
import { Show, createSignal, createEffect, on, onCleanup } from "solid-js";
import { Modal } from "../../components/Modal";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import { useToast } from "../../components/useToast";
import { getEntry, copyToClipboard } from "./ipc";
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

export const ExportUriModal: Component<ExportUriModalProps> = (props) => {
  const toast = useToast();
  const [uri, setUri] = createSignal("");
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal("");

  // Fetch entry detail and build URI when modal opens
  createEffect(
    on(
      () => props.open,
      async (open) => {
        if (!open) {
          // AC #4: Clear URI from DOM on close
          setUri("");
          setError("");
          return;
        }

        setLoading(true);
        setError("");
        try {
          const detail = await getEntry(props.entryId);
          const otpauthUri = buildOtpAuthUri({
            type: detail.entryType as "totp" | "hotp",
            name: detail.name,
            issuer: detail.issuer,
            secret: detail.secret,
            algorithm: detail.algorithm,
            digits: detail.digits,
            period: detail.period,
            counter: detail.counter,
          });
          setUri(otpauthUri);
        } catch (err) {
          setError(typeof err === "string" ? err : t("entries.exportUri.loadError"));
        } finally {
          setLoading(false);
        }
      },
    ),
  );

  onCleanup(() => {
    setUri("");
  });

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
    <Modal
      open={props.open}
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

      <Show when={loading()}>
        <div class={styles.loading}>
          <Icon name="spinner" size={24} />
          <span>{t("entries.exportUri.loading")}</span>
        </div>
      </Show>

      <Show when={error()}>
        <p class={styles.error} role="alert">
          {error()}
        </p>
      </Show>

      <Show when={uri()}>
        <div class={styles.content}>
          {/* URI display */}
          <div class={styles.uriSection}>
            <label class={styles.uriLabel}>{t("entries.exportUri.uriLabel")}</label>
            <div class={styles.uriRow}>
              <code class={styles.uriText} data-testid="export-uri-text">
                {uri()}
              </code>
            </div>
            <Button
              variant="ghost"
              onClick={handleCopy}
              data-testid="copy-uri-btn"
            >
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
      </Show>

      <div class={styles.actions}>
        <Button onClick={props.onClose} data-testid="export-uri-close">
          {t("common.close")}
        </Button>
      </div>
    </Modal>
  );
};

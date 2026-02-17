import type { Component } from "solid-js";
import { Show, createSignal } from "solid-js";
import { Modal } from "../../components/Modal";
import { Button } from "../../components/Button";
import { ReAuthPrompt } from "../../components/ReAuthPrompt";
import { useToast } from "../../components/useToast";
import { Icon } from "../../components/Icon";
import { SeedViewer } from "./SeedViewer";
import { revealSeedPhrase } from "./ipc";
import type { SeedDisplay } from "./ipc";
import { AttachmentsSection } from "../attachments/AttachmentsSection";
import { t } from "../../stores/i18nStore";
import styles from "./SeedPhraseDetailModal.module.css";

export interface SeedPhraseDetailModalProps {
  /** Controlled open state. */
  open: boolean;
  /** Called when dialog should close. */
  onClose: () => void;
  /** Entry ID of the seed phrase. */
  entryId: string;
  /** Wallet name / display name. */
  name: string;
  /** Issuer (optional). */
  issuer?: string;
  /** Word count (12, 15, 18, 21, or 24). Shown after reveal if not provided. */
  wordCount?: number;
  /** ISO 8601 creation timestamp. */
  createdAt: string;
  /** Called when the user wants to edit this entry. */
  onEdit?: (entryId: string) => void;
  /** Called when the user wants to delete this entry. */
  onDelete?: (entryId: string, entryName: string) => void;
}

export const SeedPhraseDetailModal: Component<SeedPhraseDetailModalProps> = (props) => {
  const toast = useToast();
  const [revealedData, setRevealedData] = createSignal<SeedDisplay | null>(null);
  const [showReAuth, setShowReAuth] = createSignal(false);

  const handleRevealRequest = () => {
    setShowReAuth(true);
  };

  const handleVerified = async (password: string) => {
    setShowReAuth(false);
    try {
      const data = await revealSeedPhrase(props.entryId, password);
      setRevealedData(data);
    } catch (err) {
      const msg = typeof err === "string" ? err : t("seed.detail.incorrectPassword");
      toast.error(msg);
    }
  };

  const handleClear = () => {
    setRevealedData(null);
  };

  const handleClose = () => {
    // Clear any revealed data before closing
    setRevealedData(null);
    setShowReAuth(false);
    props.onClose();
  };

  const formatDate = (iso: string) => {
    try {
      return new Date(iso).toLocaleDateString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
      });
    } catch {
      return iso;
    }
  };

  return (
    <>
      <Modal
        open={props.open}
        onClose={handleClose}
        title={t("seed.detail.title")}
        closeOnOverlayClick={false}
        actions={
          <>
            <Show when={props.onDelete}>
              <Button
                variant="danger"
                onClick={() => props.onDelete?.(props.entryId, props.name)}
                class={styles.deleteBtn}
                data-testid="seed-detail-delete-btn"
              >
                {t("common.delete")}
              </Button>
            </Show>
            <Show when={props.onEdit}>
              <Button
                variant="ghost"
                onClick={() => props.onEdit?.(props.entryId)}
                data-testid="seed-detail-edit-btn"
              >
                <Icon name="edit" size={14} />
                {t("common.edit")}
              </Button>
            </Show>
            <Button variant="ghost" onClick={handleClose}>
              {t("common.close")}
            </Button>
          </>
        }
      >
        <div class={styles.container}>
          {/* Metadata section */}
          <div class={styles.metadata}>
            <div class={styles.metaRow}>
              <span class={styles.metaLabel}>{t("seed.detail.wallet")}</span>
              <span class={styles.metaValue} data-testid="seed-detail-name">{props.name}</span>
            </div>
            <Show when={props.issuer}>
              <div class={styles.metaRow}>
                <span class={styles.metaLabel}>{t("seed.detail.issuer")}</span>
                <span class={styles.metaValue} data-testid="seed-detail-issuer">{props.issuer}</span>
              </div>
            </Show>
            <Show when={revealedData()?.wordCount ?? props.wordCount}>
              <div class={styles.metaRow}>
                <span class={styles.metaLabel}>{t("seed.detail.words")}</span>
                <span class={styles.metaValue} data-testid="seed-detail-word-count">
                  {t("seed.detail.wordCount", { count: revealedData()?.wordCount ?? props.wordCount })}
                </span>
              </div>
            </Show>
            <div class={styles.metaRow}>
              <span class={styles.metaLabel}>{t("seed.detail.added")}</span>
              <span class={styles.metaValue}>{formatDate(props.createdAt)}</span>
            </div>
            <Show when={revealedData()?.hasPassphrase}>
              <div class={styles.metaRow}>
                <span class={styles.metaLabel}>{t("seed.detail.passphrase")}</span>
                <span class={styles.metaValue}>
                  <Icon name="key" size={14} />
                  {t("seed.detail.passphraseSet")}
                </span>
              </div>
            </Show>
          </div>

          <hr class={styles.separator} />

          {/* Seed phrase viewer */}
          <SeedViewer
            wordCount={revealedData()?.wordCount ?? props.wordCount ?? 12}
            hasPassphrase={revealedData()?.hasPassphrase ?? false}
            revealedData={revealedData()}
            onRevealRequest={handleRevealRequest}
            onClear={handleClear}
          />
          <AttachmentsSection entryId={props.entryId} />
        </div>
      </Modal>

      {/* Re-auth modal (stacks on top of detail modal) */}
      <ReAuthPrompt
        open={showReAuth()}
        onClose={() => setShowReAuth(false)}
        onVerified={handleVerified}
      />
    </>
  );
};

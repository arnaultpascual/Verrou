import type { Component } from "solid-js";
import { Show } from "solid-js";
import { Modal } from "../../components/Modal";
import { Button } from "../../components/Button";
import { ReAuthPrompt } from "../../components/ReAuthPrompt";
import { AutoHideCountdown } from "../../components/AutoHideCountdown";
import { Icon } from "../../components/Icon";
import { SeedViewer } from "./SeedViewer";
import { revealSeedPhrase } from "./ipc";
import type { SeedDisplay } from "./ipc";
import { useReveal } from "../entries/useReveal";
import { useRevealCopy } from "../entries/useRevealCopy";
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
  const copyReveal = useRevealCopy();

  // Shared reveal grammar: re-auth gate, unified 60s auto-hide, clear-on-lock,
  // clear-on-cleanup. The seed phrase is never copied across IPC except as the
  // display-safe word list returned by revealSeedPhrase.
  const reveal = useReveal<SeedDisplay>({
    revealFn: (password) => revealSeedPhrase(props.entryId, password),
  });

  const handleCopyAll = () => {
    const data = reveal.revealed();
    if (!data) return;
    void copyReveal(data.words.join(" "), t("seed.viewer.copyAllLabel"));
  };

  const handleClose = () => {
    // Clear any revealed secret + close the re-auth prompt before closing.
    reveal.hide();
    reveal.cancelReAuth();
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
            <Show when={reveal.revealed()?.wordCount ?? props.wordCount}>
              <div class={styles.metaRow}>
                <span class={styles.metaLabel}>{t("seed.detail.words")}</span>
                <span class={styles.metaValue} data-testid="seed-detail-word-count">
                  {t("seed.detail.wordCount", { count: reveal.revealed()?.wordCount ?? props.wordCount })}
                </span>
              </div>
            </Show>
            <div class={styles.metaRow}>
              <span class={styles.metaLabel}>{t("seed.detail.added")}</span>
              <span class={styles.metaValue}>{formatDate(props.createdAt)}</span>
            </div>
            <Show when={reveal.revealed()?.hasPassphrase}>
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
            wordCount={reveal.revealed()?.wordCount ?? props.wordCount ?? 12}
            hasPassphrase={reveal.revealed()?.hasPassphrase ?? false}
            revealedData={reveal.revealed()}
            onRevealRequest={reveal.request}
            onCopyAll={handleCopyAll}
            onHide={reveal.hide}
            countdown={
              <AutoHideCountdown
                remainingMs={reveal.remainingMs()}
                onHide={reveal.hide}
              />
            }
          />
          <AttachmentsSection entryId={props.entryId} />
        </div>
      </Modal>

      {/* Re-auth modal (stacks on top of detail modal) */}
      <ReAuthPrompt
        open={reveal.showReAuth()}
        onClose={reveal.cancelReAuth}
        onVerified={reveal.onVerified}
      />
    </>
  );
};

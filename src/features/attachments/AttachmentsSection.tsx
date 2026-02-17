import type { Component } from "solid-js";
import { createResource, createSignal, Show, For } from "solid-js";
import { Icon, Button, useToast } from "../../components";
import {
  listAttachments,
  addAttachment,
  exportAttachment,
  deleteAttachment,
  pickFile,
  pickSaveLocation,
  formatBytes,
} from "./ipc";
import type { AttachmentMetadataDto } from "./ipc";
import { t } from "../../stores/i18nStore";
import styles from "./AttachmentsSection.module.css";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_ATTACHMENTS = 10;

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export const AttachmentsSection: Component<{ entryId: string }> = (props) => {
  const toast = useToast();
  const [attachments, { refetch }] = createResource(
    () => props.entryId,
    listAttachments,
  );
  const [adding, setAdding] = createSignal(false);
  const [confirmDeleteId, setConfirmDeleteId] = createSignal<string | null>(
    null,
  );

  const count = () => attachments()?.length ?? 0;
  const atLimit = () => count() >= MAX_ATTACHMENTS;

  const handleAdd = async () => {
    setAdding(true);
    try {
      const filePath = await pickFile();
      if (!filePath) return;

      await addAttachment(props.entryId, filePath);
      toast.success(t("attachments.toastAdded"));
      refetch();
    } catch (err) {
      const msg = typeof err === "string" ? err : t("attachments.addFailed");
      toast.error(msg);
    } finally {
      setAdding(false);
    }
  };

  const handleExport = async (attachment: AttachmentMetadataDto) => {
    try {
      const savePath = await pickSaveLocation(attachment.filename);
      if (!savePath) return;

      await exportAttachment(attachment.id, savePath);
      toast.success(t("attachments.toastSaved", { filename: attachment.filename }));
    } catch (err) {
      const msg = typeof err === "string" ? err : t("attachments.exportFailed");
      toast.error(msg);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteAttachment(id);
      setConfirmDeleteId(null);
      toast.success(t("attachments.toastDeleted"));
      refetch();
    } catch (err) {
      const msg =
        typeof err === "string" ? err : t("attachments.deleteFailed");
      toast.error(msg);
    }
  };

  return (
    <div class={styles.section}>
      <div class={styles.header}>
        <span class={styles.title}>{t("attachments.title")}</span>
        <Button
          variant="ghost"
          class={styles.addBtn}
          onClick={(e: MouseEvent) => {
            e.stopPropagation();
            handleAdd();
          }}
          disabled={adding() || atLimit()}
          aria-label={t("attachments.ariaAdd")}
        >
          <Icon name="plus" size={14} />
          <span>{t("attachments.add")}</span>
        </Button>
      </div>

      <Show
        when={count() > 0}
        fallback={
          <div class={styles.emptyState}>{t("attachments.empty")}</div>
        }
      >
        <div class={styles.list}>
          <For each={attachments()}>
            {(att) => (
              <Show
                when={confirmDeleteId() !== att.id}
                fallback={
                  <div class={styles.confirmOverlay}>
                    <span class={styles.confirmText}>
                      {t("attachments.confirmDelete", { filename: att.filename })}
                    </span>
                    <div class={styles.confirmActions}>
                      <Button
                        variant="danger"
                        onClick={(e: MouseEvent) => {
                          e.stopPropagation();
                          handleDelete(att.id);
                        }}
                      >
                        {t("common.delete")}
                      </Button>
                      <Button
                        variant="ghost"
                        onClick={(e: MouseEvent) => {
                          e.stopPropagation();
                          setConfirmDeleteId(null);
                        }}
                      >
                        {t("common.cancel")}
                      </Button>
                    </div>
                  </div>
                }
              >
                <div class={styles.item}>
                  <div class={styles.itemInfo}>
                    <Icon
                      name="paperclip"
                      size={14}
                      class={styles.itemIcon}
                    />
                    <span class={styles.filename}>{att.filename}</span>
                    <span class={styles.filesize}>
                      {formatBytes(att.sizeBytes)}
                    </span>
                  </div>
                  <div class={styles.actions}>
                    <button
                      class={styles.actionBtn}
                      title={t("attachments.download")}
                      aria-label={t("attachments.ariaDownload", { filename: att.filename })}
                      onClick={(e) => {
                        e.stopPropagation();
                        handleExport(att);
                      }}
                    >
                      <Icon name="download" size={14} />
                    </button>
                    <button
                      class={`${styles.actionBtn} ${styles.actionBtnDanger}`}
                      title={t("attachments.deleteTitle")}
                      aria-label={t("attachments.ariaDelete", { filename: att.filename })}
                      onClick={(e) => {
                        e.stopPropagation();
                        setConfirmDeleteId(att.id);
                      }}
                    >
                      <Icon name="trash" size={14} />
                    </button>
                  </div>
                </div>
              </Show>
            )}
          </For>
        </div>
        <Show when={atLimit()}>
          <div class={styles.limitNote}>
            {t("attachments.limitReached", { max: String(MAX_ATTACHMENTS) })}
          </div>
        </Show>
      </Show>
    </div>
  );
};

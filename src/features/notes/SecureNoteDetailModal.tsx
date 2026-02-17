/**
 * SecureNoteDetailModal — view and edit a secure note entry.
 *
 * View mode renders body with lightweight markdown.
 * Edit mode shows raw textarea. No re-auth required
 * (notes are not high-sensitivity like seeds).
 */

import type { Component } from "solid-js";
import { Show, For, createSignal, createResource, createEffect } from "solid-js";
import { Modal } from "../../components/Modal";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import { TagInput } from "../../components/TagInput";
import { useToast } from "../../components/useToast";
import { getEntry, updateEntry, deleteEntry } from "../entries/ipc";
import { renderMarkdown } from "./renderMarkdown";
import { AttachmentsSection } from "../attachments/AttachmentsSection";
import { t } from "../../stores/i18nStore";
import styles from "./SecureNoteDetailModal.module.css";

export interface SecureNoteDetailModalProps {
  open: boolean;
  onClose: () => void;
  entryId: string;
  name: string;
  createdAt: string;
  onDeleted?: () => void;
  onEdited?: () => void;
}

export const SecureNoteDetailModal: Component<SecureNoteDetailModalProps> = (props) => {
  const toast = useToast();
  const [editing, setEditing] = createSignal(false);
  const [editBody, setEditBody] = createSignal("");
  const [editTags, setEditTags] = createSignal<string[]>([]);
  const [saving, setSaving] = createSignal(false);
  const [deleting, setDeleting] = createSignal(false);
  const [confirmDelete, setConfirmDelete] = createSignal(false);

  const [entry, { refetch }] = createResource(
    () => (props.open ? props.entryId : undefined),
    (id) => getEntry(id),
  );

  // Initialize edit body and tags when switching to edit mode
  createEffect(() => {
    if (editing()) {
      const data = entry();
      if (data) {
        setEditBody(data.secret);
        setEditTags(data.tags ?? []);
      }
    }
  });

  const tags = () => entry()?.tags ?? [];

  const handleEdit = () => {
    setEditing(true);
  };

  const handleCancelEdit = () => {
    setEditing(false);
  };

  const handleSave = async () => {
    if (saving()) return;
    setSaving(true);
    try {
      await updateEntry({
        id: props.entryId,
        secret: editBody(),
        tags: editTags(),
      });
      toast.success(t("notes.detail.updated"));
      setEditing(false);
      refetch();
      props.onEdited?.();
    } catch (err) {
      toast.error(typeof err === "string" ? err : t("notes.detail.saveError"));
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (deleting()) return;
    setDeleting(true);
    try {
      await deleteEntry(props.entryId);
      toast.success(t("notes.detail.deleted"));
      setConfirmDelete(false);
      props.onDeleted?.();
    } catch (err) {
      toast.error(typeof err === "string" ? err : t("notes.detail.deleteError"));
    } finally {
      setDeleting(false);
    }
  };

  const handleClose = () => {
    setEditing(false);
    setConfirmDelete(false);
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
    <Modal
      open={props.open}
      onClose={handleClose}
      title={props.name}
      closeOnOverlayClick={!editing()}
      actions={
        <Show
          when={!confirmDelete()}
          fallback={
            <>
              <Button variant="ghost" onClick={() => setConfirmDelete(false)}>
                {t("notes.detail.cancel")}
              </Button>
              <Button variant="danger" onClick={handleDelete} loading={deleting()}>
                {t("notes.detail.confirmDelete")}
              </Button>
            </>
          }
        >
          <Button
            variant="danger"
            onClick={() => setConfirmDelete(true)}
            class={styles.deleteBtn}
          >
            {t("notes.detail.delete")}
          </Button>
          <Show
            when={editing()}
            fallback={
              <Button variant="primary" onClick={handleEdit}>
                <Icon name="edit" size={14} /> {t("notes.detail.edit")}
              </Button>
            }
          >
            <Button variant="ghost" onClick={handleCancelEdit}>
              {t("notes.detail.cancel")}
            </Button>
            <Button variant="primary" onClick={handleSave} loading={saving()}>
              {t("notes.detail.save")}
            </Button>
          </Show>
        </Show>
      }
    >
      <div class={styles.container}>
        {/* Metadata */}
        <div class={styles.metadata}>
          <div class={styles.metaRow}>
            <span class={styles.metaLabel}>{t("notes.detail.created")}</span>
            <span class={styles.metaValue}>{formatDate(props.createdAt)}</span>
          </div>
        </div>

        {/* Tags */}
        <Show when={tags().length > 0}>
          <div class={styles.tags}>
            <For each={tags()}>
              {(tag) => <span class={styles.tag}>{tag}</span>}
            </For>
          </div>
        </Show>

        <hr class={styles.separator} />

        {/* Body: view or edit */}
        <Show
          when={!editing()}
          fallback={
            <div class={styles.editSection}>
              <textarea
                class={styles.editTextarea}
                value={editBody()}
                onInput={(e) => setEditBody(e.currentTarget.value)}
                rows={12}
              />
              <div class={styles.editTagsWrapper}>
                <label class={styles.editTagsLabel}>{t("notes.detail.tags")}</label>
                <TagInput
                  tags={editTags()}
                  onChange={setEditTags}
                  placeholder={t("notes.detail.tagsPlaceholder")}
                  disabled={saving()}
                />
              </div>
            </div>
          }
        >
          <Show when={entry()} fallback={<p>{t("notes.detail.loading")}</p>}>
            {(data) => (
              <div
                class={styles.body}
                innerHTML={renderMarkdown(data().secret)}
              />
            )}
          </Show>
        </Show>
        <AttachmentsSection entryId={props.entryId} />
      </div>
    </Modal>
  );
};

/**
 * FolderSection — sidebar folder list with inline CRUD.
 *
 * Renders inside the sidebar. Supports:
 * - "All Entries" item (clears folder filter)
 * - Folder list with entry counts
 * - "New Folder" inline input (Enter to create)
 * - Hover/focus actions: rename (inline edit), delete (inline confirm)
 *
 * Failures surface via toast; deletes require an inline confirmation
 * (entries inside the folder are moved to "All", never deleted).
 */

import type { Component } from "solid-js";
import { For, Show, createSignal, createResource } from "solid-js";
import { Icon } from "../../components/Icon";
import { useToast } from "../../components/useToast";
import { listFolders, createFolder, renameFolder, deleteFolder, type FolderWithCountDto } from "./ipc";
import { t } from "../../stores/i18nStore";
import styles from "./FolderSection.module.css";

export interface FolderSectionProps {
  selectedFolderId: string | null;
  onSelectFolder: (folderId: string | null) => void;
  collapsed?: boolean;
}

export const FolderSection: Component<FolderSectionProps> = (props) => {
  const toast = useToast();
  const [folders, { refetch }] = createResource(listFolders);
  const [creating, setCreating] = createSignal(false);
  const [newName, setNewName] = createSignal("");
  const [renamingId, setRenamingId] = createSignal<string | null>(null);
  const [renameValue, setRenameValue] = createSignal("");
  const [confirmDeleteId, setConfirmDeleteId] = createSignal<string | null>(null);

  const handleCreateStart = () => {
    setCreating(true);
    setNewName("");
  };

  const handleCreateSubmit = async () => {
    const name = newName().trim();
    if (!name) {
      setCreating(false);
      return;
    }
    try {
      await createFolder(name);
      refetch();
    } catch (err) {
      const msg = typeof err === "string" ? err : t("folders.createError");
      toast.error(msg);
    }
    setCreating(false);
    setNewName("");
  };

  const handleCreateKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleCreateSubmit();
    } else if (e.key === "Escape") {
      setCreating(false);
    }
  };

  const handleRenameStart = (folder: FolderWithCountDto) => {
    setRenamingId(folder.id);
    setRenameValue(folder.name);
  };

  const handleRenameSubmit = async () => {
    const id = renamingId();
    const name = renameValue().trim();
    if (!id || !name) {
      setRenamingId(null);
      return;
    }
    try {
      await renameFolder(id, name);
      refetch();
    } catch (err) {
      const msg = typeof err === "string" ? err : t("folders.renameError");
      toast.error(msg);
    }
    setRenamingId(null);
  };

  const handleRenameKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleRenameSubmit();
    } else if (e.key === "Escape") {
      setRenamingId(null);
    }
  };

  const handleDelete = async (folderId: string) => {
    try {
      await deleteFolder(folderId);
      setConfirmDeleteId(null);
      if (props.selectedFolderId === folderId) {
        props.onSelectFolder(null);
      }
      refetch();
    } catch (err) {
      const msg = typeof err === "string" ? err : t("folders.deleteError");
      toast.error(msg);
    }
  };

  return (
    <div class={styles.section}>
      {/* All Entries */}
      <div
        class={`${styles.allItem} ${props.selectedFolderId === null ? styles.active : ""}`}
        onClick={() => props.onSelectFolder(null)}
        role="button"
        tabindex={0}
        onKeyDown={(e) => { if (e.key === "Enter") props.onSelectFolder(null); }}
      >
        <Icon name="list" size={14} />
        <Show when={!props.collapsed}>
          <span class={styles.folderName}>{t("folders.allEntries")}</span>
        </Show>
      </div>

      {/* Folder List */}
      <Show when={!props.collapsed}>
        <ul class={styles.folderList} role="list">
          <For each={folders() ?? []}>
            {(folder) => (
              <li>
                <Show
                  when={renamingId() !== folder.id}
                  fallback={
                    <input
                      class={styles.inlineInput}
                      value={renameValue()}
                      onInput={(e) => setRenameValue(e.currentTarget.value)}
                      onBlur={() => handleRenameSubmit()}
                      onKeyDown={handleRenameKeyDown}
                      ref={(el) => setTimeout(() => el.focus(), 0)}
                    />
                  }
                >
                  <Show
                    when={confirmDeleteId() !== folder.id}
                    fallback={
                      <div class={styles.confirmOverlay}>
                        <span class={styles.confirmText}>
                          {t("folders.confirmDelete", { name: folder.name })}
                        </span>
                        <div class={styles.confirmActions}>
                          <button
                            class={`${styles.confirmBtn} ${styles.confirmBtnDanger}`}
                            onClick={(e) => { e.stopPropagation(); handleDelete(folder.id); }}
                          >
                            {t("common.delete")}
                          </button>
                          <button
                            class={styles.confirmBtn}
                            onClick={(e) => { e.stopPropagation(); setConfirmDeleteId(null); }}
                          >
                            {t("common.cancel")}
                          </button>
                        </div>
                      </div>
                    }
                  >
                    <div
                      class={`${styles.folderItem} ${props.selectedFolderId === folder.id ? styles.active : ""}`}
                      onClick={() => props.onSelectFolder(folder.id)}
                      role="button"
                      tabindex={0}
                      onKeyDown={(e) => { if (e.key === "Enter") props.onSelectFolder(folder.id); }}
                    >
                      <Icon name="folder" size={14} />
                      <span class={styles.folderName}>{folder.name}</span>
                      <span class={styles.folderCount}>{folder.entryCount}</span>
                      <div class={styles.hoverActions}>
                        <button
                          class={styles.actionBtn}
                          title={t("folders.rename")}
                          aria-label={t("folders.renameAria", { name: folder.name })}
                          onClick={(e) => { e.stopPropagation(); handleRenameStart(folder); }}
                          onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") e.stopPropagation(); }}
                        >
                          <Icon name="edit" size={12} />
                        </button>
                        <button
                          class={styles.actionBtn}
                          title={t("folders.delete")}
                          aria-label={t("folders.deleteAria", { name: folder.name })}
                          onClick={(e) => { e.stopPropagation(); setConfirmDeleteId(folder.id); }}
                          onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") e.stopPropagation(); }}
                        >
                          <Icon name="x" size={12} />
                        </button>
                      </div>
                    </div>
                  </Show>
                </Show>
              </li>
            )}
          </For>
        </ul>

        {/* New Folder */}
        <Show
          when={!creating()}
          fallback={
            <input
              class={styles.inlineInput}
              value={newName()}
              onInput={(e) => setNewName(e.currentTarget.value)}
              onBlur={() => handleCreateSubmit()}
              onKeyDown={handleCreateKeyDown}
              placeholder={t("folders.namePlaceholder")}
              ref={(el) => setTimeout(() => el.focus(), 0)}
            />
          }
        >
          <button class={styles.newFolderBtn} onClick={handleCreateStart}>
            <Icon name="plus" size={12} />
            {t("folders.newFolder")}
          </button>
        </Show>
      </Show>
    </div>
  );
};

/**
 * FolderSection — sidebar folder tree with inline CRUD, nesting, and reordering.
 *
 * Renders inside the sidebar. Supports:
 * - "All Entries" item (clears the folder filter; also a drop target → root)
 * - A nested folder tree with expand/collapse and entry counts
 * - Create (root or subfolder), rename (inline), delete (inline confirm)
 * - Reorder within siblings (↑/↓ buttons) and reparent (drag onto a folder,
 *   or Alt+←/→ to outdent/indent) — all backed by the cycle-safe `moveFolder`
 *
 * Failures surface via toast; deletes require an inline confirmation (entries
 * inside the folder are moved to "All", never deleted).
 */

import type { Component, JSX } from "solid-js";
import { For, Show, createSignal, createMemo, createResource } from "solid-js";
import { Icon } from "../../components/Icon";
import { useToast } from "../../components/useToast";
import {
  listFolders,
  createFolder,
  renameFolder,
  deleteFolder,
  moveFolder,
  type FolderWithCountDto,
} from "./ipc";
import { t } from "../../stores/i18nStore";
import styles from "./FolderSection.module.css";

export interface FolderSectionProps {
  selectedFolderId: string | null;
  onSelectFolder: (folderId: string | null) => void;
  collapsed?: boolean;
}

interface TreeNode {
  folder: FolderWithCountDto;
  children: TreeNode[];
  depth: number;
}

/** Build a nested tree from the flat folder list (orphans surface at root). */
function buildTree(folders: FolderWithCountDto[]): TreeNode[] {
  const ids = new Set(folders.map((f) => f.id));
  const byParent = new Map<string | undefined, FolderWithCountDto[]>();
  for (const f of folders) {
    const key = f.parentId && ids.has(f.parentId) ? f.parentId : undefined;
    const group = byParent.get(key);
    if (group) group.push(f);
    else byParent.set(key, [f]);
  }
  for (const group of byParent.values()) {
    group.sort((a, b) => a.sortOrder - b.sortOrder || a.name.localeCompare(b.name));
  }
  const seen = new Set<string>();
  const build = (parentKey: string | undefined, depth: number): TreeNode[] =>
    (byParent.get(parentKey) ?? [])
      .filter((f) => !seen.has(f.id))
      .map((f) => {
        seen.add(f.id);
        return { folder: f, children: build(f.id, depth + 1), depth };
      });
  return build(undefined, 0);
}

// `null` = creating at root, a string = creating under that folder id.
type CreateTarget = string | null | undefined;

export const FolderSection: Component<FolderSectionProps> = (props) => {
  const toast = useToast();
  const [folders, { refetch }] = createResource(listFolders);
  const tree = createMemo(() => buildTree(folders() ?? []));

  const [createTarget, setCreateTarget] = createSignal<CreateTarget>(undefined);
  const [newName, setNewName] = createSignal("");
  const [renamingId, setRenamingId] = createSignal<string | null>(null);
  const [renameValue, setRenameValue] = createSignal("");
  const [confirmDeleteId, setConfirmDeleteId] = createSignal<string | null>(null);
  const [collapsedIds, setCollapsedIds] = createSignal<Set<string>>(new Set());
  const [draggingId, setDraggingId] = createSignal<string | null>(null);
  const [dragOverId, setDragOverId] = createSignal<string | null>(null);

  const flat = () => folders() ?? [];
  const siblingsOf = (parentId: string | undefined): FolderWithCountDto[] =>
    flat()
      .filter((f) => (f.parentId ?? undefined) === (parentId ?? undefined))
      .sort((a, b) => a.sortOrder - b.sortOrder || a.name.localeCompare(b.name));

  const isExpanded = (id: string) => !collapsedIds().has(id);
  const toggleExpanded = (id: string) =>
    setCollapsedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const expand = (id: string) =>
    setCollapsedIds((prev) => {
      if (!prev.has(id)) return prev;
      const next = new Set(prev);
      next.delete(id);
      return next;
    });

  // ── Create ──

  const startCreate = (target: string | null) => {
    setCreateTarget(target);
    setNewName("");
    if (typeof target === "string") expand(target);
  };

  const submitCreate = async () => {
    const name = newName().trim();
    const target = createTarget();
    if (!name || target === undefined) {
      setCreateTarget(undefined);
      return;
    }
    try {
      await createFolder(name, target === null ? undefined : target);
      refetch();
    } catch (err) {
      toast.error(typeof err === "string" ? err : t("folders.createError"));
    }
    setCreateTarget(undefined);
    setNewName("");
  };

  const createKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      submitCreate();
    } else if (e.key === "Escape") {
      setCreateTarget(undefined);
    }
  };

  // ── Rename ──

  const startRename = (folder: FolderWithCountDto) => {
    setRenamingId(folder.id);
    setRenameValue(folder.name);
  };

  const submitRename = async () => {
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
      toast.error(typeof err === "string" ? err : t("folders.renameError"));
    }
    setRenamingId(null);
  };

  const renameKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      submitRename();
    } else if (e.key === "Escape") {
      setRenamingId(null);
    }
  };

  // ── Delete ──

  const handleDelete = async (folderId: string) => {
    try {
      await deleteFolder(folderId);
      setConfirmDeleteId(null);
      if (props.selectedFolderId === folderId) props.onSelectFolder(null);
      refetch();
    } catch (err) {
      toast.error(typeof err === "string" ? err : t("folders.deleteError"));
    }
  };

  // ── Move (reorder + reparent) ──

  const doMove = async (
    folderId: string,
    parentId: string | undefined,
    position: number,
  ) => {
    try {
      await moveFolder(folderId, parentId, position);
      refetch();
    } catch (err) {
      toast.error(typeof err === "string" ? err : t("folders.moveError"));
    }
  };

  const moveUp = (f: FolderWithCountDto) => {
    const sibs = siblingsOf(f.parentId ?? undefined);
    const i = sibs.findIndex((s) => s.id === f.id);
    if (i > 0) doMove(f.id, f.parentId ?? undefined, i - 1);
  };
  const moveDown = (f: FolderWithCountDto) => {
    const sibs = siblingsOf(f.parentId ?? undefined);
    const i = sibs.findIndex((s) => s.id === f.id);
    if (i >= 0 && i < sibs.length - 1) doMove(f.id, f.parentId ?? undefined, i + 1);
  };
  const indent = (f: FolderWithCountDto) => {
    const sibs = siblingsOf(f.parentId ?? undefined);
    const i = sibs.findIndex((s) => s.id === f.id);
    if (i > 0) doMove(f.id, sibs[i - 1].id, Number.MAX_SAFE_INTEGER);
  };
  const outdent = (f: FolderWithCountDto) => {
    if (!f.parentId) return;
    const parent = flat().find((p) => p.id === f.parentId);
    const grand = parent?.parentId ?? undefined;
    const gsibs = siblingsOf(grand);
    const pi = gsibs.findIndex((s) => s.id === f.parentId);
    doMove(f.id, grand, pi + 1);
  };

  const rowKeyDown = (e: KeyboardEvent, f: FolderWithCountDto) => {
    if (e.key === "Enter") {
      props.onSelectFolder(f.id);
    } else if (e.altKey && e.key === "ArrowLeft") {
      e.preventDefault();
      outdent(f);
    } else if (e.altKey && e.key === "ArrowRight") {
      e.preventDefault();
      indent(f);
    }
  };

  // ── Drag & drop (reparent) ──

  const onDrop = (targetParentId: string | undefined) => {
    const id = draggingId();
    setDragOverId(null);
    setDraggingId(null);
    if (!id || id === targetParentId) return;
    doMove(id, targetParentId, Number.MAX_SAFE_INTEGER);
  };

  // ── Inline input (shared markup for create/rename) ──

  const inlineInput = (
    value: () => string,
    onInput: (v: string) => void,
    onBlur: () => void,
    onKeyDown: (e: KeyboardEvent) => void,
    placeholder?: string,
  ): JSX.Element => (
    <input
      class={styles.inlineInput}
      value={value()}
      onInput={(e) => onInput(e.currentTarget.value)}
      onBlur={onBlur}
      onKeyDown={onKeyDown}
      placeholder={placeholder}
      ref={(el) => setTimeout(() => el.focus(), 0)}
    />
  );

  // ── Recursive node render ──

  const renderNode = (node: TreeNode): JSX.Element => {
    const f = node.folder;
    const hasChildren = () => node.children.length > 0;

    return (
      <li>
        <Show
          when={renamingId() !== f.id}
          fallback={inlineInput(renameValue, setRenameValue, submitRename, renameKeyDown)}
        >
          <Show
            when={confirmDeleteId() !== f.id}
            fallback={
              <div class={styles.confirmOverlay} style={{ "--depth": String(node.depth) }}>
                <span class={styles.confirmText}>
                  {t("folders.confirmDelete", { name: f.name })}
                </span>
                <div class={styles.confirmActions}>
                  <button
                    class={`${styles.confirmBtn} ${styles.confirmBtnDanger}`}
                    onClick={(e) => {
                      e.stopPropagation();
                      handleDelete(f.id);
                    }}
                  >
                    {t("common.delete")}
                  </button>
                  <button
                    class={styles.confirmBtn}
                    onClick={(e) => {
                      e.stopPropagation();
                      setConfirmDeleteId(null);
                    }}
                  >
                    {t("common.cancel")}
                  </button>
                </div>
              </div>
            }
          >
            <div
              class={`${styles.folderItem} ${
                props.selectedFolderId === f.id ? styles.active : ""
              } ${dragOverId() === f.id ? styles.dragOver : ""} ${
                draggingId() === f.id ? styles.dragging : ""
              }`}
              style={{ "--depth": String(node.depth) }}
              role="button"
              tabindex={0}
              draggable={true}
              aria-label={f.name}
              onClick={() => props.onSelectFolder(f.id)}
              onKeyDown={(e) => rowKeyDown(e, f)}
              onDragStart={() => setDraggingId(f.id)}
              onDragEnd={() => {
                setDraggingId(null);
                setDragOverId(null);
              }}
              onDragOver={(e) => {
                if (draggingId() && draggingId() !== f.id) {
                  e.preventDefault();
                  setDragOverId(f.id);
                }
              }}
              onDragLeave={() => dragOverId() === f.id && setDragOverId(null)}
              onDrop={(e) => {
                e.preventDefault();
                e.stopPropagation();
                onDrop(f.id);
              }}
            >
              <Show
                when={hasChildren()}
                fallback={<span class={styles.chevronSpacer} aria-hidden="true" />}
              >
                <button
                  class={styles.chevronBtn}
                  aria-label={
                    isExpanded(f.id)
                      ? t("folders.collapseAria", { name: f.name })
                      : t("folders.expandAria", { name: f.name })
                  }
                  aria-expanded={isExpanded(f.id)}
                  onClick={(e) => {
                    e.stopPropagation();
                    toggleExpanded(f.id);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") e.stopPropagation();
                  }}
                >
                  <Icon
                    name="chevron-right"
                    size={12}
                    class={`${styles.chevron} ${isExpanded(f.id) ? styles.chevronOpen : ""}`}
                  />
                </button>
              </Show>

              <Icon name="folder" size={14} />
              <span class={styles.folderName}>{f.name}</span>
              <span class={styles.folderCount}>{f.entryCount}</span>

              <div class={styles.hoverActions}>
                <button
                  class={styles.actionBtn}
                  title={t("folders.newSubfolder")}
                  aria-label={t("folders.newSubfolderAria", { name: f.name })}
                  onClick={(e) => {
                    e.stopPropagation();
                    startCreate(f.id);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") e.stopPropagation();
                  }}
                >
                  <Icon name="plus" size={12} />
                </button>
                <button
                  class={styles.actionBtn}
                  title={t("folders.moveUp")}
                  aria-label={t("folders.moveUpAria", { name: f.name })}
                  onClick={(e) => {
                    e.stopPropagation();
                    moveUp(f);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") e.stopPropagation();
                  }}
                >
                  <Icon name="chevron-right" size={12} class={styles.iconUp} />
                </button>
                <button
                  class={styles.actionBtn}
                  title={t("folders.moveDown")}
                  aria-label={t("folders.moveDownAria", { name: f.name })}
                  onClick={(e) => {
                    e.stopPropagation();
                    moveDown(f);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") e.stopPropagation();
                  }}
                >
                  <Icon name="chevron-right" size={12} class={styles.iconDown} />
                </button>
                <button
                  class={styles.actionBtn}
                  title={t("folders.rename")}
                  aria-label={t("folders.renameAria", { name: f.name })}
                  onClick={(e) => {
                    e.stopPropagation();
                    startRename(f);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") e.stopPropagation();
                  }}
                >
                  <Icon name="edit" size={12} />
                </button>
                <button
                  class={styles.actionBtn}
                  title={t("folders.delete")}
                  aria-label={t("folders.deleteAria", { name: f.name })}
                  onClick={(e) => {
                    e.stopPropagation();
                    setConfirmDeleteId(f.id);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") e.stopPropagation();
                  }}
                >
                  <Icon name="x" size={12} />
                </button>
              </div>
            </div>
          </Show>
        </Show>

        {/* Subfolder creation input */}
        <Show when={createTarget() === f.id}>
          <ul class={styles.childList} role="list">
            <li style={{ "--depth": String(node.depth + 1) }} class={styles.inlineInputRow}>
              {inlineInput(
                newName,
                setNewName,
                submitCreate,
                createKeyDown,
                t("folders.namePlaceholder"),
              )}
            </li>
          </ul>
        </Show>

        {/* Children */}
        <Show when={hasChildren() && isExpanded(f.id)}>
          <ul class={styles.childList} role="list">
            <For each={node.children}>{renderNode}</For>
          </ul>
        </Show>
      </li>
    );
  };

  return (
    <div class={styles.section}>
      {/* All Entries (also a drop target → move to root) */}
      <div
        class={`${styles.allItem} ${props.selectedFolderId === null ? styles.active : ""} ${
          dragOverId() === "__root__" ? styles.dragOver : ""
        }`}
        onClick={() => props.onSelectFolder(null)}
        role="button"
        tabindex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter") props.onSelectFolder(null);
        }}
        onDragOver={(e) => {
          if (draggingId()) {
            e.preventDefault();
            setDragOverId("__root__");
          }
        }}
        onDragLeave={() => dragOverId() === "__root__" && setDragOverId(null)}
        onDrop={(e) => {
          e.preventDefault();
          onDrop(undefined);
        }}
      >
        <Icon name="list" size={14} />
        <Show when={!props.collapsed}>
          <span class={styles.folderName}>{t("folders.allEntries")}</span>
        </Show>
      </div>

      <Show when={!props.collapsed}>
        <ul class={styles.folderList} role="list">
          <For each={tree()}>{renderNode}</For>
        </ul>

        {/* New top-level folder */}
        <Show
          when={createTarget() !== null}
          fallback={inlineInput(
            newName,
            setNewName,
            submitCreate,
            createKeyDown,
            t("folders.namePlaceholder"),
          )}
        >
          <button class={styles.newFolderBtn} onClick={() => startCreate(null)}>
            <Icon name="plus" size={12} />
            {t("folders.newFolder")}
          </button>
        </Show>
      </Show>
    </div>
  );
};

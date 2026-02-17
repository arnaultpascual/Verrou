import type { Component } from "solid-js";
import { Show, createSignal, createResource, createEffect, onCleanup } from "solid-js";
import { useLocation } from "@solidjs/router";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import { useToast } from "../../components/useToast";
import { searchQuery } from "../../stores/searchStore";
import { t } from "../../stores/i18nStore";
import { selectedFolderId } from "../../stores/folderStore";
import { listEntries, deleteEntry, updateEntry, type EntryMetadataDto } from "./ipc";
import { filterEntries, sortEntries, type SortMode } from "./filterEntries";
import { EntryList } from "./EntryList";
import { AddEntryModal } from "./AddEntryModal";
import { AddSeedPhraseForm } from "../seed/AddSeedPhraseForm";
import { SeedPhraseDetailModal } from "../seed/SeedPhraseDetailModal";
import { EditSeedPhraseModal } from "../seed/EditSeedPhraseModal";
import { ConfirmDeleteSeedModal } from "../seed/ConfirmDeleteSeedModal";
import { AddRecoveryCodeForm } from "../recovery/AddRecoveryCodeForm";
import { RecoveryCodeDetailModal } from "../recovery/RecoveryCodeDetailModal";
import { EditRecoveryCodeModal } from "../recovery/EditRecoveryCodeModal";
import { getAllRecoveryStats, getLinkedRecoveryCount } from "../recovery/ipc";
import { AddSecureNoteForm } from "../notes/AddSecureNoteForm";
import { SecureNoteDetailModal } from "../notes/SecureNoteDetailModal";
import { AddCredentialModal } from "../credentials/AddCredentialModal";
import { CredentialDetailModal } from "../credentials/CredentialDetailModal";
import { EditCredentialModal } from "../credentials/EditCredentialModal";
import { EditEntryModal } from "./EditEntryModal";
import { ExportUriModal } from "./ExportUriModal";
import { ConfirmDeleteModal } from "./ConfirmDeleteModal";
import styles from "./EntriesPage.module.css";

const ARIA_ANNOUNCE_DELAY_MS = 300;

/** Map sidebar URL ?type= param to backend entryType values. */
const TYPE_FILTER_MAP: Record<string, string[]> = {
  totp: ["totp", "hotp"],
  seed: ["seed_phrase"],
  recovery: ["recovery_code"],
  note: ["secure_note"],
  credential: ["credential"],
};

export const EntriesPage: Component = () => {
  const location = useLocation();
  const toast = useToast();
  const [modalOpen, setModalOpen] = createSignal(false);
  const [seedModalOpen, setSeedModalOpen] = createSignal(false);
  const [recoveryModalOpen, setRecoveryModalOpen] = createSignal(false);
  const [noteModalOpen, setNoteModalOpen] = createSignal(false);
  const [credentialModalOpen, setCredentialModalOpen] = createSignal(false);
  const [noteDetailEntry, setNoteDetailEntry] = createSignal<EntryMetadataDto | null>(null);
  const [addMenuOpen, setAddMenuOpen] = createSignal(false);
  const [editEntryId, setEditEntryId] = createSignal<string | null>(null);
  const [seedDetailEntry, setSeedDetailEntry] = createSignal<EntryMetadataDto | null>(null);
  const [editSeedEntryId, setEditSeedEntryId] = createSignal<string | null>(null);
  const [recoveryDetailEntry, setRecoveryDetailEntry] = createSignal<EntryMetadataDto | null>(null);
  const [editRecoveryEntryId, setEditRecoveryEntryId] = createSignal<string | null>(null);
  const [deleteSeedTarget, setDeleteSeedTarget] = createSignal<{ id: string; name: string } | null>(null);
  const [deleteTarget, setDeleteTarget] = createSignal<{ id: string; name: string } | null>(null);
  const [linkedRecoveryCount, setLinkedRecoveryCount] = createSignal(0);
  const [isDeleting, setIsDeleting] = createSignal(false);
  const [pendingSeedRefresh, setPendingSeedRefresh] = createSignal<string | null>(null);
  const [pendingRecoveryRefresh, setPendingRecoveryRefresh] = createSignal<string | null>(null);
  const [credentialDetailEntry, setCredentialDetailEntry] = createSignal<EntryMetadataDto | null>(null);
  const [editCredentialEntryId, setEditCredentialEntryId] = createSignal<string | null>(null);
  const [pendingCredentialRefresh, setPendingCredentialRefresh] = createSignal<string | null>(null);
  const [exportUriEntry, setExportUriEntry] = createSignal<{ id: string; name: string; issuer?: string; entryType: string } | null>(null);
  const [sortMode, setSortMode] = createSignal<SortMode>("alpha-asc");
  const [entries, { refetch }] = createResource(listEntries);
  const [recoveryStats, { refetch: refetchStats }] = createResource(getAllRecoveryStats);
  const [announcement, setAnnouncement] = createSignal("");

  const filteredEntries = () => {
    let result = entries() ?? [];
    const folderId = selectedFolderId();
    if (folderId) {
      result = result.filter((e) => e.folderId === folderId);
    }
    const typeParam = new URLSearchParams(location.search).get("type");
    if (typeParam && TYPE_FILTER_MAP[typeParam]) {
      const allowed = TYPE_FILTER_MAP[typeParam];
      result = result.filter((e) => allowed.includes(e.entryType));
    }
    const filtered = filterEntries(result, searchQuery());
    return sortEntries(filtered, sortMode());
  };

  // Debounce the aria-live announcement to avoid per-keystroke screen reader noise
  createEffect(() => {
    const query = searchQuery();
    const count = filteredEntries().length;
    const text = query ? t("entries.searchResultCount", { count: String(count) }) : "";

    const timer = setTimeout(() => setAnnouncement(text), ARIA_ANNOUNCE_DELAY_MS);
    onCleanup(() => clearTimeout(timer));
  });

  // Close add menu when clicking outside
  createEffect(() => {
    if (!addMenuOpen()) return;
    const handler = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (!target.closest(`.${styles.addMenu}`)) {
        setAddMenuOpen(false);
      }
    };
    document.addEventListener("click", handler, { capture: true });
    onCleanup(() => document.removeEventListener("click", handler, { capture: true }));
  });

  // After a seed phrase edit, re-open the detail modal with fresh data once refetch completes.
  createEffect(() => {
    const pendingId = pendingSeedRefresh();
    if (!pendingId) return;
    if (entries.loading) return;
    const all = entries() ?? [];
    const fresh = all.find((e) => e.id === pendingId);
    if (fresh) {
      setSeedDetailEntry(fresh);
    }
    setPendingSeedRefresh(null);
  });

  // After a recovery code edit, re-open the detail modal with fresh data once refetch completes.
  createEffect(() => {
    const pendingId = pendingRecoveryRefresh();
    if (!pendingId) return;
    if (entries.loading) return;
    const all = entries() ?? [];
    const fresh = all.find((e) => e.id === pendingId);
    if (fresh) {
      setRecoveryDetailEntry(fresh);
    }
    setPendingRecoveryRefresh(null);
  });

  // After a credential edit, re-open the detail modal with fresh data once refetch completes.
  createEffect(() => {
    const pendingId = pendingCredentialRefresh();
    if (!pendingId) return;
    if (entries.loading) return;
    const all = entries() ?? [];
    const fresh = all.find((e) => e.id === pendingId);
    if (fresh) {
      setCredentialDetailEntry(fresh);
    }
    setPendingCredentialRefresh(null);
  });

  const handleSuccess = () => {
    refetch();
    refetchStats();
  };

  const handleDeleteRequest = async (entryId: string, entryName: string) => {
    // Check for linked recovery codes (cascade warning for TOTP/HOTP)
    const all = entries() ?? [];
    const entry = all.find((e) => e.id === entryId);
    if (entry?.entryType === "totp" || entry?.entryType === "hotp") {
      try {
        const count = await getLinkedRecoveryCount(entryId);
        setLinkedRecoveryCount(count);
      } catch {
        setLinkedRecoveryCount(0);
      }
    } else {
      setLinkedRecoveryCount(0);
    }
    setDeleteTarget({ id: entryId, name: entryName });
  };

  const handleConfirmDelete = async () => {
    const target = deleteTarget();
    if (!target || isDeleting()) return;
    setIsDeleting(true);
    try {
      await deleteEntry(target.id);
      toast.success(t("entries.delete.success"));
      setDeleteTarget(null);
      setEditEntryId(null);
      setEditCredentialEntryId(null);
      setCredentialDetailEntry(null);
      refetch();
      refetchStats();
    } catch (err) {
      toast.error(typeof err === "string" ? err : t("entries.delete.error"));
    } finally {
      setIsDeleting(false);
    }
  };

  const handleCancelDelete = () => {
    setDeleteTarget(null);
  };

  const handleTogglePin = async (entryId: string, pinned: boolean) => {
    try {
      const all = entries() ?? [];
      const entry = all.find((e) => e.id === entryId);
      const name = entry?.name ?? "Entry";
      await updateEntry({ id: entryId, pinned });
      toast.success(pinned ? t("entries.card.pinSuccess", { name }) : t("entries.card.unpinSuccess", { name }));
      refetch();
    } catch {
      toast.error(t("entries.card.pinError"));
    }
  };

  // Seed phrase edit: opens EditSeedPhraseModal from detail modal
  const handleSeedEdit = (entryId: string) => {
    setEditSeedEntryId(entryId);
  };

  // Seed phrase delete: opens ConfirmDeleteSeedModal from detail modal
  const handleSeedDeleteRequest = (entryId: string, entryName: string) => {
    setDeleteSeedTarget({ id: entryId, name: entryName });
  };

  // Seed phrase deleted: close all seed modals and refetch
  const handleSeedDeleted = () => {
    setDeleteSeedTarget(null);
    setSeedDetailEntry(null);
    refetch();
  };

  // Recovery code edit: opens EditRecoveryCodeModal from detail modal
  const handleRecoveryEdit = (entryId: string) => {
    setEditRecoveryEntryId(entryId);
  };

  // Recovery code edit saved: close edit modal, refresh detail.
  // The createEffect above will reopen the detail modal with fresh data once refetch completes.
  const handleRecoveryEditSuccess = () => {
    setEditRecoveryEntryId(null);
    const currentDetail = recoveryDetailEntry();
    if (currentDetail) {
      setPendingRecoveryRefresh(currentDetail.id);
      setRecoveryDetailEntry(null);
    }
    refetch();
    refetchStats();
  };

  // Credential edit: opens EditCredentialModal from detail modal
  const handleCredentialEdit = (entryId: string) => {
    setEditCredentialEntryId(entryId);
  };

  // Credential edit saved: close edit modal, refresh detail.
  const handleCredentialEditSuccess = () => {
    setEditCredentialEntryId(null);
    const currentDetail = credentialDetailEntry();
    if (currentDetail) {
      setPendingCredentialRefresh(currentDetail.id);
      setCredentialDetailEntry(null);
    }
    refetch();
  };

  // Credential deleted: close all credential modals and refetch
  const handleCredentialDeleted = () => {
    setCredentialDetailEntry(null);
    setEditCredentialEntryId(null);
    refetch();
  };

  // Credential delete request from edit modal: route to standard ConfirmDeleteModal
  const handleCredentialDeleteRequest = (entryId: string, entryName: string) => {
    setDeleteTarget({ id: entryId, name: entryName });
  };

  // Export URI: open ExportUriModal from EditEntryModal
  const handleExportUri = (entryId: string, name: string, issuer: string | undefined, entryType: string) => {
    setEditEntryId(null);
    setExportUriEntry({ id: entryId, name, issuer, entryType });
  };

  // Seed phrase edit saved: close edit modal, refresh detail.
  // The createEffect above will reopen the detail modal with fresh data once refetch completes.
  const handleSeedEditSuccess = () => {
    setEditSeedEntryId(null);
    const currentDetail = seedDetailEntry();
    if (currentDetail) {
      setPendingSeedRefresh(currentDetail.id);
      setSeedDetailEntry(null);
    }
    refetch();
  };

  return (
    <div class={styles.page}>
      <div class={styles.header}>
        <h2 class={styles.title}>{t("entries.title")}</h2>
        <select
          class={styles.sortSelect}
          value={sortMode()}
          onChange={(e) => setSortMode(e.currentTarget.value as SortMode)}
          aria-label={t("entries.sort.label")}
        >
          <option value="alpha-asc">{t("entries.sort.alphaAsc")}</option>
          <option value="alpha-desc">{t("entries.sort.alphaDesc")}</option>
          <option value="newest">{t("entries.sort.newest")}</option>
          <option value="oldest">{t("entries.sort.oldest")}</option>
        </select>
        <div class={styles.addMenu}>
          <Button
            variant="primary"
            onClick={() => setAddMenuOpen((prev) => !prev)}
          >
            <Icon name="plus" size={16} /> {t("entries.addButton")}
          </Button>
          <Show when={addMenuOpen()}>
            <div class={styles.addDropdown}>
              <button
                class={styles.addOption}
                onClick={() => {
                  setAddMenuOpen(false);
                  setModalOpen(true);
                }}
              >
                <Icon name="lock" size={16} />
                {t("entries.addMenu.totp")}
              </button>
              <button
                class={styles.addOption}
                onClick={() => {
                  setAddMenuOpen(false);
                  setSeedModalOpen(true);
                }}
              >
                <Icon name="shield" size={16} />
                {t("entries.addMenu.seed")}
              </button>
              <button
                class={styles.addOption}
                onClick={() => {
                  setAddMenuOpen(false);
                  setRecoveryModalOpen(true);
                }}
              >
                <Icon name="key" size={16} />
                {t("entries.addMenu.recovery")}
              </button>
              <button
                class={styles.addOption}
                onClick={() => {
                  setAddMenuOpen(false);
                  setNoteModalOpen(true);
                }}
              >
                <Icon name="list" size={16} />
                {t("entries.addMenu.note")}
              </button>
              <button
                class={styles.addOption}
                onClick={() => {
                  setAddMenuOpen(false);
                  setCredentialModalOpen(true);
                }}
              >
                <Icon name="key" size={16} />
                {t("entries.addMenu.credential")}
              </button>
            </div>
          </Show>
        </div>
      </div>

      <Show when={entries.loading}>
        <p class={styles.loading}>{t("entries.loading")}</p>
      </Show>

      <Show when={entries.error}>
        <p class={styles.error}>{t("entries.error")}</p>
      </Show>

      <Show when={entries() && !entries.loading}>
        <EntryList
          entries={filteredEntries()}
          searchQuery={searchQuery()}
          recoveryStats={recoveryStats()}
          onAdd={() => setAddMenuOpen(true)}
          onSelect={(id) => {
            const all = entries() ?? [];
            const entry = all.find((e) => e.id === id);
            if (entry?.entryType === "seed_phrase") {
              setSeedDetailEntry(entry);
            } else if (entry?.entryType === "recovery_code") {
              setRecoveryDetailEntry(entry);
            } else if (entry?.entryType === "secure_note") {
              setNoteDetailEntry(entry);
            } else if (entry?.entryType === "credential") {
              setCredentialDetailEntry(entry);
            } else {
              setEditEntryId(id);
            }
          }}
          onTogglePin={handleTogglePin}
        />
      </Show>

      {/* Screen reader result count announcement (debounced to avoid per-keystroke noise) */}
      <span class={styles.srOnly} aria-live="polite" role="status">
        {announcement()}
      </span>

      <AddEntryModal
        open={modalOpen()}
        onClose={() => setModalOpen(false)}
        onSuccess={handleSuccess}
      />

      <AddSeedPhraseForm
        open={seedModalOpen()}
        onClose={() => setSeedModalOpen(false)}
        onSuccess={handleSuccess}
      />

      <AddRecoveryCodeForm
        open={recoveryModalOpen()}
        onClose={() => setRecoveryModalOpen(false)}
        onSuccess={handleSuccess}
      />

      <AddSecureNoteForm
        open={noteModalOpen()}
        onClose={() => setNoteModalOpen(false)}
        onSuccess={handleSuccess}
      />

      <AddCredentialModal
        open={credentialModalOpen()}
        onClose={() => setCredentialModalOpen(false)}
        onSuccess={handleSuccess}
      />

      <Show when={credentialDetailEntry()}>
        {(entry) => (
          <CredentialDetailModal
            open={true}
            onClose={() => setCredentialDetailEntry(null)}
            entryId={entry().id}
            name={entry().name}
            issuer={entry().issuer}
            tags={entry().tags}
            folderId={entry().folderId}
            createdAt={entry().createdAt}
            onEdit={handleCredentialEdit}
            onDeleted={handleCredentialDeleted}
          />
        )}
      </Show>

      <Show when={editCredentialEntryId()}>
        {(id) => (
          <EditCredentialModal
            open={true}
            entryId={id()}
            onClose={() => setEditCredentialEntryId(null)}
            onSuccess={handleCredentialEditSuccess}
            onDelete={handleCredentialDeleteRequest}
          />
        )}
      </Show>

      <Show when={noteDetailEntry()}>
        {(entry) => (
          <SecureNoteDetailModal
            open={true}
            onClose={() => setNoteDetailEntry(null)}
            entryId={entry().id}
            name={entry().name}
            createdAt={entry().createdAt}
            onDeleted={() => {
              setNoteDetailEntry(null);
              refetch();
            }}
            onEdited={() => refetch()}
          />
        )}
      </Show>

      <Show when={recoveryDetailEntry()}>
        {(entry) => (
          <RecoveryCodeDetailModal
            open={true}
            onClose={() => setRecoveryDetailEntry(null)}
            entryId={entry().id}
            name={entry().name}
            issuer={entry().issuer}
            createdAt={entry().createdAt}
            onDeleted={() => {
              setRecoveryDetailEntry(null);
              refetch();
              refetchStats();
            }}
            onStatsChanged={() => refetchStats()}
            onEdit={handleRecoveryEdit}
          />
        )}
      </Show>

      <Show when={editRecoveryEntryId()}>
        {(id) => (
          <EditRecoveryCodeModal
            open={true}
            entryId={id()}
            onClose={() => setEditRecoveryEntryId(null)}
            onSuccess={handleRecoveryEditSuccess}
          />
        )}
      </Show>

      <Show when={seedDetailEntry()}>
        {(entry) => (
          <SeedPhraseDetailModal
            open={true}
            onClose={() => setSeedDetailEntry(null)}
            entryId={entry().id}
            name={entry().name}
            issuer={entry().issuer}
            createdAt={entry().createdAt}
            onEdit={handleSeedEdit}
            onDelete={handleSeedDeleteRequest}
          />
        )}
      </Show>

      <Show when={editSeedEntryId()}>
        {(id) => (
          <EditSeedPhraseModal
            open={true}
            entryId={id()}
            onClose={() => setEditSeedEntryId(null)}
            onSuccess={handleSeedEditSuccess}
            onDelete={handleSeedDeleteRequest}
          />
        )}
      </Show>

      <Show when={deleteSeedTarget()}>
        {(target) => (
          <ConfirmDeleteSeedModal
            open={true}
            entryId={target().id}
            walletName={target().name}
            onDeleted={handleSeedDeleted}
            onCancel={() => setDeleteSeedTarget(null)}
          />
        )}
      </Show>

      <Show when={editEntryId()}>
        {(id) => (
          <EditEntryModal
            open={true}
            entryId={id()}
            onClose={() => setEditEntryId(null)}
            onSuccess={handleSuccess}
            onDelete={handleDeleteRequest}
            onExport={handleExportUri}
          />
        )}
      </Show>

      <Show when={exportUriEntry()}>
        {(entry) => (
          <ExportUriModal
            open={true}
            onClose={() => setExportUriEntry(null)}
            entryId={entry().id}
            name={entry().name}
            issuer={entry().issuer}
            entryType={entry().entryType}
          />
        )}
      </Show>

      <Show when={deleteTarget()}>
        {(target) => (
          <ConfirmDeleteModal
            open={true}
            entryName={target().name}
            loading={isDeleting()}
            linkedRecoveryCount={linkedRecoveryCount()}
            onConfirm={handleConfirmDelete}
            onCancel={handleCancelDelete}
          />
        )}
      </Show>
    </div>
  );
};

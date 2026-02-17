/**
 * IPC service for entry CRUD commands.
 * When running inside Tauri, invokes Rust backend commands.
 * Falls back to in-memory mock store for browser dev mode.
 */

import { filterEntries } from "./filterEntries";

// ---------------------------------------------------------------------------
// DTOs — mirror Rust camelCase DTOs exactly
// ---------------------------------------------------------------------------

/** Display-safe entry metadata. Never includes secret data. */
export interface EntryMetadataDto {
  id: string;
  entryType: string;
  name: string;
  issuer?: string;
  folderId?: string;
  algorithm: string;
  digits: number;
  period: number;
  pinned: boolean;
  tags?: string[];
  /** Username (plaintext, credential entries only). */
  username?: string;
  /** Template identifier (plaintext, credential entries only). */
  template?: string;
  createdAt: string;
  updatedAt: string;
}

/** Full entry detail including decrypted secret. */
export interface EntryDetailDto extends EntryMetadataDto {
  secret: string;
  counter: number;
  /** Tags (only populated for secure_note entries). */
  tags?: string[];
}

/** Request DTO for adding a new entry. */
export interface AddEntryRequest {
  entryType: string;
  name: string;
  issuer?: string;
  folderId?: string;
  algorithm?: string;
  digits?: number;
  period?: number;
  counter?: number;
  pinned?: boolean;
  secret: string;
  passphrase?: string;
  language?: string;
  /** Parent TOTP/HOTP entry ID for recovery code linking (FR14). */
  linkedEntryId?: string;
  /** Tags for secure_note entries. */
  tags?: string[];
  /** Username for credential entries. */
  username?: string;
  /** URLs for credential entries. */
  urls?: string[];
  /** Notes for credential entries. */
  notes?: string;
  /** Linked TOTP entry ID for credential entries. */
  linkedTotpId?: string;
  /** Custom fields for credential entries. */
  customFields?: CustomFieldDto[];
  /** Template identifier for credential entries (e.g., "credit_card", "ssh_key"). */
  template?: string;
}

/** Request DTO for updating an entry. */
export interface UpdateEntryRequest {
  id: string;
  name?: string;
  issuer?: string | null;
  folderId?: string | null;
  algorithm?: string;
  digits?: number;
  period?: number;
  counter?: number;
  pinned?: boolean;
  secret?: string;
  /** BIP39 passphrase tri-state: undefined = no change, null = remove, string = set new */
  passphrase?: string | null;
  /** Tags for secure_note entries. */
  tags?: string[];
  /** New username for credential entries. */
  username?: string | null;
  /** New URLs for credential entries. */
  urls?: string[];
  /** New notes for credential entries. */
  notes?: string | null;
  /** New linked TOTP ID for credential entries. */
  linkedTotpId?: string | null;
  /** New custom fields for credential entries. */
  customFields?: CustomFieldDto[];
}

/** TOTP code display result. Mirrors future Rust TotpDisplay DTO. */
export interface TotpCodeDto {
  code: string;
  remainingSeconds: number;
}

/** Note content search result. */
export interface NoteSearchResult {
  entryId: string;
  name: string;
  snippet: string;
}

/** Custom field for credential entries. */
export interface CustomFieldDto {
  label: string;
  value: string;
  /** Field type: `text`, `hidden`, `url`, `date`. */
  fieldType: string;
}

/** Password history entry for credential entries. */
export interface PasswordHistoryEntryDto {
  password: string;
  changedAt: string;
}

/** Credential display DTO returned after re-authentication. */
export interface CredentialDisplay {
  password: string;
  username?: string;
  urls: string[];
  notes?: string;
  linkedTotpId?: string;
  customFields: CustomFieldDto[];
  passwordHistory: PasswordHistoryEntryDto[];
  /** Template identifier (e.g., "credit_card", "ssh_key"). */
  template?: string;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const VALID_ENTRY_TYPES = new Set([
  "totp",
  "hotp",
  "seed_phrase",
  "recovery_code",
  "secure_note",
  "credential",
]);

// ---------------------------------------------------------------------------
// Mock data store
// ---------------------------------------------------------------------------

const MOCK_ENTRIES: EntryDetailDto[] = [
  {
    id: "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    entryType: "totp",
    name: "GitHub",
    issuer: "github.com",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    counter: 0,
    pinned: true,
    createdAt: "2026-02-05T10:00:00Z",
    updatedAt: "2026-02-05T10:00:00Z",
    secret: "JBSWY3DPEHPK3PXP",
  },
  {
    id: "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
    entryType: "totp",
    name: "Google",
    issuer: "google.com",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    counter: 0,
    pinned: false,
    createdAt: "2026-02-05T11:00:00Z",
    updatedAt: "2026-02-05T11:00:00Z",
    secret: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
  },
  {
    id: "c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f",
    entryType: "totp",
    name: "AWS Console",
    issuer: "amazon.com",
    algorithm: "SHA256",
    digits: 8,
    period: 30,
    counter: 0,
    pinned: false,
    createdAt: "2026-02-06T09:30:00Z",
    updatedAt: "2026-02-06T09:30:00Z",
    secret: "GEZDGNBVGY3TQOJQ",
  },
  {
    id: "d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f80",
    entryType: "hotp",
    name: "Legacy VPN",
    issuer: "vpn.corp.example.com",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    counter: 42,
    pinned: false,
    createdAt: "2026-02-04T14:00:00Z",
    updatedAt: "2026-02-06T08:00:00Z",
    secret: "IFBEGRCFIZDUQMJQ",
  },
  {
    id: "e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8091",
    entryType: "seed_phrase",
    name: "Bitcoin Wallet",
    issuer: "ledger.com",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    counter: 0,
    pinned: false,
    createdAt: "2026-02-05T12:00:00Z",
    updatedAt: "2026-02-05T12:00:00Z",
    secret: "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual adapt",
  },
  {
    id: "f6a7b8c9-d0e1-4f2a-3b4c-5d6e7f809102",
    entryType: "recovery_code",
    name: "Google Account",
    issuer: "google.com",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    counter: 0,
    pinned: false,
    createdAt: "2026-02-05T13:00:00Z",
    updatedAt: "2026-02-05T13:00:00Z",
    secret: "abcd-1234-efgh-5678\nijkl-9012-mnop-3456\nqrst-7890-uvwx-1234",
  },
  {
    id: "a7b8c9d0-e1f2-4a3b-4c5d-6e7f80910213",
    entryType: "secure_note",
    name: "Server Credentials",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    counter: 0,
    pinned: false,
    createdAt: "2026-02-05T14:00:00Z",
    updatedAt: "2026-02-05T14:00:00Z",
    secret: "Production DB: host=db.example.com user=admin pass=s3cur3",
    tags: ["server", "production", "database"],
  },
  {
    id: "b8c9d0e1-f2a3-4b4c-5d6e-7f8091021324",
    entryType: "credential",
    name: "GitHub Login",
    issuer: "github.com",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    counter: 0,
    pinned: false,
    createdAt: "2026-02-10T09:00:00Z",
    updatedAt: "2026-02-10T09:00:00Z",
    secret: "s3cur3P@ss!",
    username: "admin@github.com",
  },
];

let mockStore = [...MOCK_ENTRIES];
let nextIdCounter = 100;

/** Whether we're running inside a Tauri webview (vs. test/browser). */
const IS_TAURI = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

// ---------------------------------------------------------------------------
// IPC functions (Tauri → Rust backend, fallback → mock store)
// ---------------------------------------------------------------------------

/** List all entries (metadata only — no secret data). */
export async function listEntries(): Promise<EntryMetadataDto[]> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<EntryMetadataDto[]>("list_entries");
  }
  await delay(50);
  return mockStore
    .map(stripSecret)
    .sort((a, b) => {
      if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
}

/** Add a new entry to the vault. */
export async function addEntry(
  request: AddEntryRequest,
): Promise<EntryMetadataDto> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<EntryMetadataDto>("add_entry", { request });
  }
  await delay(100);

  if (!VALID_ENTRY_TYPES.has(request.entryType)) {
    throw `Invalid entry type: ${request.entryType}`;
  }

  const now = new Date().toISOString();
  nextIdCounter += 1;
  const id = `mock-${nextIdCounter.toString(16).padStart(8, "0")}-0000-4000-8000-000000000000`;

  const entry: EntryDetailDto = {
    id,
    entryType: request.entryType,
    name: request.name,
    issuer: request.issuer,
    folderId: request.folderId,
    algorithm: request.algorithm ?? "SHA1",
    digits: request.digits ?? 6,
    period: request.period ?? 30,
    counter: request.counter ?? 0,
    pinned: request.pinned ?? false,
    createdAt: now,
    updatedAt: now,
    secret: request.secret,
  };

  mockStore.push(entry);
  return stripSecret(entry);
}

/** Get a single entry with decrypted secret. */
export async function getEntry(entryId: string): Promise<EntryDetailDto> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<EntryDetailDto>("get_entry", { entryId });
  }
  await delay(50);

  const entry = mockStore.find((e) => e.id === entryId);
  if (!entry) {
    throw "Entry not found. It may have been deleted.";
  }

  // Credential passwords are NEVER returned via getEntry.
  // Use revealPassword (with re-auth) to access the password.
  if (entry.entryType === "credential") {
    return { ...entry, secret: "" };
  }

  return { ...entry };
}

/** Update an existing entry. */
export async function updateEntry(
  request: UpdateEntryRequest,
): Promise<EntryMetadataDto> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<EntryMetadataDto>("update_entry", { request });
  }
  await delay(100);

  const idx = mockStore.findIndex((e) => e.id === request.id);
  if (idx === -1) {
    throw "Entry not found. It may have been deleted.";
  }

  const existing = mockStore[idx];
  const now = new Date().toISOString();

  const updated: EntryDetailDto = {
    ...existing,
    name: request.name ?? existing.name,
    issuer: request.issuer !== undefined ? (request.issuer ?? undefined) : existing.issuer,
    folderId: request.folderId !== undefined ? (request.folderId ?? undefined) : existing.folderId,
    algorithm: request.algorithm ?? existing.algorithm,
    digits: request.digits ?? existing.digits,
    period: request.period ?? existing.period,
    counter: request.counter ?? existing.counter,
    pinned: request.pinned ?? existing.pinned,
    secret: request.secret ?? existing.secret,
    updatedAt: now,
  };

  mockStore[idx] = updated;
  return stripSecret(updated);
}

/** Delete an entry by ID. */
export async function deleteEntry(entryId: string): Promise<void> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("delete_entry", { entryId });
    return;
  }
  await delay(50);

  const idx = mockStore.findIndex((e) => e.id === entryId);
  if (idx === -1) {
    throw "Entry not found. It may have been deleted.";
  }

  mockStore.splice(idx, 1);
}

/** Generate a TOTP code for the given entry. Uses getEntry() (Rust-backed when in Tauri). */
export async function generateTotpCode(entryId: string): Promise<TotpCodeDto> {
  const entry = await getEntry(entryId);
  if (entry.entryType !== "totp") {
    throw "Entry is not a TOTP entry.";
  }

  const period = entry.period || 30;
  const now = Math.floor(Date.now() / 1000);
  const remainingSeconds = period - (now % period);
  const counter = Math.floor(now / period);
  const secretBytes = decodeBase32(entry.secret);
  const algo = entry.algorithm?.toUpperCase() === "SHA256" ? "SHA-256"
    : entry.algorithm?.toUpperCase() === "SHA512" ? "SHA-512"
    : "SHA-1";
  const digits = entry.digits || 6;

  const code = await computeHotp(secretBytes, counter, algo, digits);
  return { code, remainingSeconds };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Strip secret data from a detail DTO to produce a metadata DTO. */
function stripSecret(entry: EntryDetailDto): EntryMetadataDto {
  const { secret: _, counter: __, tags: _tags, ...metadata } = entry;
  // Preserve tags on metadata for search (they're plaintext organizational data).
  return { ...metadata, tags: entry.tags };
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Base32 & TOTP (mock-only, mirrors Rust verrou-crypto-core)
// ---------------------------------------------------------------------------

const BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Decode a Base32-encoded string to Uint8Array (RFC 4648). */
function decodeBase32(input: string): Uint8Array {
  const cleaned = input.replace(/[\s=]/g, "").toUpperCase();
  const bits: number[] = [];
  for (const ch of cleaned) {
    const val = BASE32_CHARS.indexOf(ch);
    if (val === -1) continue;
    for (let j = 4; j >= 0; j--) {
      bits.push((val >> j) & 1);
    }
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) {
      byte = (byte << 1) | bits[i * 8 + b];
    }
    bytes[i] = byte;
  }
  return bytes;
}

/** Compute HOTP code using Web Crypto API (RFC 4226). */
async function computeHotp(
  secret: Uint8Array,
  counter: number,
  algorithm: string,
  digits: number,
): Promise<string> {
  const counterBytes = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = c & 0xff;
    c = Math.floor(c / 256);
  }

  const key = await crypto.subtle.importKey(
    "raw",
    secret as BufferSource,
    { name: "HMAC", hash: algorithm },
    false,
    ["sign"],
  );

  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
  const offset = sig[sig.length - 1] & 0x0f;
  const binary =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);

  const modulus = digits === 8 ? 100_000_000 : 1_000_000;
  return (binary % modulus).toString().padStart(digits, "0");
}

// ---------------------------------------------------------------------------
// Search (mock layer — will swap to Rust trigram backend)
// ---------------------------------------------------------------------------

/** Search entries by query. Uses listEntries() (Rust-backed when in Tauri) + client-side filter. */
export async function searchEntries(query: string): Promise<EntryMetadataDto[]> {
  const all = await listEntries();
  return filterEntries(all, query);
}

// ---------------------------------------------------------------------------
// Clipboard — production uses Rust IPC with concealment + auto-clear;
//             test/dev uses navigator.clipboard mock
// ---------------------------------------------------------------------------

/**
 * Copy text to clipboard with platform-specific concealment.
 *
 * In production (Tauri): invokes `clipboard_write_concealed` which uses
 * NSPasteboard concealed type (macOS) or clipboard history exclusion (Windows),
 * and schedules a Rust-side auto-clear timer using the configured preference timeout.
 *
 * In tests: uses navigator.clipboard.writeText (no concealment, no auto-clear).
 */
export async function copyToClipboard(text: string): Promise<void> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("clipboard_write_concealed", { text });
  } else {
    await navigator.clipboard.writeText(text);
  }
}

/**
 * Clear clipboard contents.
 *
 * In production (Tauri): invokes `clipboard_clear` which cancels any
 * pending auto-clear timer and clears the system clipboard.
 *
 * In tests: writes empty string via navigator.clipboard.
 */
export async function clearClipboard(): Promise<void> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("clipboard_clear");
  } else {
    await navigator.clipboard.writeText("");
  }
}

// ---------------------------------------------------------------------------
// Note Content Search
// ---------------------------------------------------------------------------

/**
 * Server-side search of secure note content.
 *
 * Decrypts all `secure_note` entries in Rust, searches bodies for `query`,
 * and returns matching entry IDs with contextual snippets.
 * Note content stays in Rust memory — never sent to the frontend search index.
 */
export async function searchNoteContent(query: string): Promise<NoteSearchResult[]> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<NoteSearchResult[]>("search_note_content", { query });
  }
  // Mock: search through mock store note bodies
  const results: NoteSearchResult[] = [];
  for (const entry of mockStore) {
    if (entry.entryType !== "secure_note") continue;
    const lower = entry.secret.toLowerCase();
    const pos = lower.indexOf(query.toLowerCase());
    if (pos >= 0) {
      const start = Math.max(0, pos - 40);
      const end = Math.min(entry.secret.length, pos + query.length + 40);
      let snippet = "";
      if (start > 0) snippet += "...";
      snippet += entry.secret.slice(start, end);
      if (end < entry.secret.length) snippet += "...";
      results.push({ entryId: entry.id, name: entry.name, snippet });
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// Credential Reveal
// ---------------------------------------------------------------------------

/**
 * Reveal a credential's password and details after re-authentication.
 *
 * Requires master password re-entry. Returns full credential data
 * including password, username, URLs, custom fields, and password history.
 */
export async function revealPassword(
  entryId: string,
  password: string,
): Promise<CredentialDisplay> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<CredentialDisplay>("reveal_password", { entryId, password });
  }
  // Mock: find credential entry and return its data
  await delay(500); // Simulate KDF delay
  const entry = mockStore.find((e) => e.id === entryId);
  if (!entry) throw "Entry not found.";
  if (entry.entryType !== "credential") throw "Entry is not a credential.";
  return {
    password: entry.secret,
    username: "admin@example.com",
    urls: ["https://example.com"],
    notes: "Mock credential notes",
    customFields: [],
    passwordHistory: [],
    template: (entry as any).template,
  };
}

/** Reset mock store to initial state (for testing). */
export function _resetMockStore(): void {
  mockStore = [...MOCK_ENTRIES];
  nextIdCounter = 100;
}

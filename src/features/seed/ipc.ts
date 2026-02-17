/**
 * BIP39 seed phrase IPC service.
 * Wraps Tauri invoke() calls for BIP39 word validation, autocomplete,
 * and phrase checksum verification. NEVER sends full wordlists to the
 * frontend (NFR22).
 */

// ---------------------------------------------------------------------------
// DTOs — mirror Rust camelCase DTOs exactly
// ---------------------------------------------------------------------------

/** Result of validating a single BIP39 word. */
export interface Bip39WordResult {
  valid: boolean;
}

/** Result of validating a complete BIP39 phrase (checksum verification). */
export interface Bip39PhraseResult {
  valid: boolean;
  error?: string;
}

// ---------------------------------------------------------------------------
// Tauri detection
// ---------------------------------------------------------------------------

const IS_TAURI =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

// ---------------------------------------------------------------------------
// Mock BIP39 wordlist subset (for dev/test only — NOT the full list)
// ---------------------------------------------------------------------------

const MOCK_WORDS = [
  "abandon", "ability", "able", "about", "above", "absent", "absorb",
  "abstract", "absurd", "abuse", "access", "accident", "account", "accuse",
  "achieve", "acid", "acoustic", "acquire", "across", "act", "action",
  "actor", "actress", "actual", "adapt", "add", "addict", "address",
  "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair",
  "afford", "afraid", "again", "age", "agent", "agree", "ahead", "aim",
  "air", "airport", "aisle", "alarm", "album", "alcohol", "alert", "zoo",
];

// ---------------------------------------------------------------------------
// IPC functions
// ---------------------------------------------------------------------------

/**
 * Validate a single word against a BIP39 wordlist.
 * Returns `{ valid: true }` if the word exists in the wordlist.
 */
export async function validateWord(
  word: string,
  language: string,
): Promise<Bip39WordResult> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<Bip39WordResult>("bip39_validate_word", { word, language });
  }

  // Mock: check against subset
  await delay(20);
  return { valid: MOCK_WORDS.includes(word.toLowerCase()) };
}

/**
 * Get autocomplete suggestions for a BIP39 word prefix.
 * Returns up to `max` words (default 5) matching the prefix.
 */
export async function suggestWords(
  prefix: string,
  language: string,
  max?: number,
): Promise<string[]> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<string[]>("bip39_suggest_words", { prefix, language, max });
  }

  // Mock: filter subset by prefix
  await delay(15);
  const limit = max ?? 5;
  const lower = prefix.toLowerCase();
  return MOCK_WORDS.filter((w) => w.startsWith(lower)).slice(0, limit);
}

/**
 * Validate a complete BIP39 mnemonic phrase (word count + checksum).
 * Returns `{ valid: true }` if the phrase passes all checks.
 */
export async function validatePhrase(
  words: string[],
  language: string,
): Promise<Bip39PhraseResult> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<Bip39PhraseResult>("bip39_validate_phrase", {
      words,
      language,
    });
  }

  // Mock: check word count and that all words are in subset
  await delay(30);
  const validCounts = [12, 15, 18, 21, 24];
  if (!validCounts.includes(words.length)) {
    return {
      valid: false,
      error: `Invalid word count: ${words.length}. Expected 12, 15, 18, 21, or 24.`,
    };
  }

  const invalidWord = words.find((w) => !MOCK_WORDS.includes(w.toLowerCase()));
  if (invalidWord) {
    return {
      valid: false,
      error: `Unknown word not found in wordlist: "${invalidWord}".`,
    };
  }

  return { valid: true };
}

// ---------------------------------------------------------------------------
// Seed phrase reveal
// ---------------------------------------------------------------------------

/** Seed phrase display DTO — individual BIP39 words (never raw entropy). */
export interface SeedDisplay {
  words: string[];
  wordCount: number;
  hasPassphrase: boolean;
}

/**
 * Reveal a seed phrase after re-authenticating with the master password.
 * Requires the vault to be unlocked. The password is verified server-side
 * via KDF re-derivation and slot unwrapping.
 *
 * The vault directory is resolved on the Rust side via AppHandle — the
 * frontend does not need to supply it.
 */
export async function revealSeedPhrase(
  entryId: string,
  password: string,
): Promise<SeedDisplay> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<SeedDisplay>("reveal_seed_phrase", {
      entryId,
      password,
    });
  }

  // Mock: return a 12-word test seed after simulated delay
  await delay(50);
  return {
    words: [
      "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
      "abandon", "abandon", "abandon", "abandon", "abandon", "about",
    ],
    wordCount: 12,
    hasPassphrase: false,
  };
}

// ---------------------------------------------------------------------------
// Authenticated delete
// ---------------------------------------------------------------------------

/**
 * Delete a seed phrase entry after re-authenticating with the master password.
 * Wraps the generalized `delete_entry_with_auth` Rust command which checks
 * entry type internally — SeedPhrase/RecoveryCode require re-auth,
 * Totp/Note skip it. Forward-compatible for Story 6.6.
 */
export async function deleteSeedPhrase(
  entryId: string,
  password: string,
): Promise<void> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<void>("delete_entry_with_auth", { entryId, password });
  }

  // Mock: simulate authenticated deletion with delay
  await delay(50);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

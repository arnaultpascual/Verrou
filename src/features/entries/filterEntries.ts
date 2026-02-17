import type { EntryMetadataDto } from "./ipc";

// ---------------------------------------------------------------------------
// Sort modes
// ---------------------------------------------------------------------------

export type SortMode = "alpha-asc" | "alpha-desc" | "newest" | "oldest";

/**
 * Sort entries by the given mode.
 * Pinned entries always come first, then sorted within groups.
 */
export function sortEntries(
  entries: EntryMetadataDto[],
  mode: SortMode,
): EntryMetadataDto[] {
  return [...entries].sort((a, b) => {
    // Pinned always first
    if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;

    switch (mode) {
      case "alpha-asc":
        return a.name.localeCompare(b.name);
      case "alpha-desc":
        return b.name.localeCompare(a.name);
      case "newest":
        return b.createdAt.localeCompare(a.createdAt);
      case "oldest":
        return a.createdAt.localeCompare(b.createdAt);
      default:
        return a.name.localeCompare(b.name);
    }
  });
}

// ---------------------------------------------------------------------------
// Search / filter
// ---------------------------------------------------------------------------

/** Score tiers for search result ranking. */
const SCORE_PREFIX = 3;
const SCORE_CONTAINS = 2;
const SCORE_SUBSEQUENCE = 1;

/**
 * Check if `query` is a subsequence of `text` (chars appear in order).
 * Returns true if every character of query appears in text in order.
 */
function isSubsequence(text: string, query: string): boolean {
  let qi = 0;
  for (let ti = 0; ti < text.length && qi < query.length; ti++) {
    if (text[ti] === query[qi]) qi++;
  }
  return qi === query.length;
}

/**
 * Score an entry against a lowercase query.
 * Returns 0 if no match, 1-3 based on match quality.
 */
function scoreEntry(entry: EntryMetadataDto, lowerQuery: string): number {
  const name = entry.name.toLowerCase();
  const issuer = (entry.issuer ?? "").toLowerCase();
  const username = (entry.username ?? "").toLowerCase();

  // Prefix match (best)
  if (name.startsWith(lowerQuery) || issuer.startsWith(lowerQuery) || username.startsWith(lowerQuery)) {
    return SCORE_PREFIX;
  }

  // Contains match
  if (name.includes(lowerQuery) || issuer.includes(lowerQuery) || username.includes(lowerQuery)) {
    return SCORE_CONTAINS;
  }

  // Tag exact match (treated as contains-tier)
  const tags = entry.tags ?? [];
  if (tags.some((t) => t.toLowerCase() === lowerQuery)) {
    return SCORE_CONTAINS;
  }

  // Tag prefix match
  if (tags.some((t) => t.toLowerCase().startsWith(lowerQuery))) {
    return SCORE_CONTAINS;
  }

  // Subsequence match (weakest)
  if (isSubsequence(name, lowerQuery) || isSubsequence(issuer, lowerQuery) || isSubsequence(username, lowerQuery)) {
    return SCORE_SUBSEQUENCE;
  }

  return 0;
}

/**
 * Filter and rank entries by fuzzy match against query.
 *
 * Searches `name`, `issuer`, `username`, and `tags` — no secret material.
 * Returns full list when query is empty.
 *
 * Result ordering: pinned first → higher score → alphabetical tie-break.
 */
export function filterEntries(
  entries: EntryMetadataDto[],
  query: string,
): EntryMetadataDto[] {
  const trimmed = query.trim().toLowerCase();

  if (trimmed === "") {
    // Return all entries with default ordering: pinned first, then alphabetical
    return [...entries].sort((a, b) => {
      if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
  }

  // Score and filter
  const scored = entries
    .map((entry) => ({ entry, score: scoreEntry(entry, trimmed) }))
    .filter(({ score }) => score > 0);

  // Sort: pinned first → higher score → alphabetical
  scored.sort((a, b) => {
    if (a.entry.pinned !== b.entry.pinned) return a.entry.pinned ? -1 : 1;
    if (a.score !== b.score) return b.score - a.score;
    return a.entry.name.localeCompare(b.entry.name);
  });

  return scored.map(({ entry }) => entry);
}

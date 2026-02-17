/**
 * Global i18n store — reactive translations powered by @solid-primitives/i18n.
 *
 * Locale is determined by: saved preference > OS locale > "en" fallback.
 * Switching locale reactively updates all t() calls without app restart.
 * Missing keys fall back to the English dictionary with dev-mode warnings.
 */

import { createSignal, createMemo } from "solid-js";
import { flatten, translator, resolveTemplate } from "@solid-primitives/i18n";
import type { Flatten } from "@solid-primitives/i18n";

import en from "../i18n/en.json";
import fr from "../i18n/fr.json";
import de from "../i18n/de.json";
import es from "../i18n/es.json";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type RawDictionary = typeof en;
type FlatDictionary = Flatten<RawDictionary>;

/** Supported locale codes. */
export type Locale = "en" | "fr" | "de" | "es";

/** Metadata for a supported locale. */
export interface LocaleInfo {
  code: Locale;
  /** Native name (displayed in language selector). */
  name: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** All available locales with display names. */
export const AVAILABLE_LOCALES: readonly LocaleInfo[] = [
  { code: "en", name: "English" },
  { code: "fr", name: "Fran\u00e7ais" },
  { code: "de", name: "Deutsch" },
  { code: "es", name: "Espa\u00f1ol" },
] as const;

// fr, de, and es may lag behind en.json — missing keys fall back to English at runtime.
// Cast to RawDictionary to satisfy the type system; the fallback translator handles gaps.
const dictionaries: Record<Locale, RawDictionary> = {
  en,
  fr: fr as unknown as RawDictionary,
  de: de as unknown as RawDictionary,
  es: es as unknown as RawDictionary,
};

// ---------------------------------------------------------------------------
// Locale signal
// ---------------------------------------------------------------------------

const [locale, setLocaleSignal] = createSignal<Locale>("en");

/** Current active locale. */
export { locale };

/** Set the active locale. Updates all t() calls reactively. */
export function setLocale(code: Locale): void {
  setLocaleSignal(code);
}

// ---------------------------------------------------------------------------
// Translator with English fallback
// ---------------------------------------------------------------------------

const flatEn = flatten(en) as FlatDictionary;

const currentDict = createMemo<FlatDictionary>(() => {
  const loc = locale();
  const raw = dictionaries[loc] ?? en;
  return flatten(raw) as FlatDictionary;
});

const primaryTranslator = translator(currentDict, resolveTemplate);
const fallbackTranslator = translator(() => flatEn, resolveTemplate);

/**
 * Translate a key using the current locale.
 *
 * Falls back to English if the key is missing in the current locale.
 * In development mode, logs a console warning for missing keys.
 */
export function t(key: string, ...args: unknown[]): string {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const result = (primaryTranslator as any)(key, ...args);
  if (result !== undefined && result !== null) return String(result);

  // Fallback to English
  if (import.meta.env.DEV && locale() !== "en") {
    console.warn(`[i18n] Missing key "${key}" for locale "${locale()}"`);
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const fallback = (fallbackTranslator as any)(key, ...args);
  if (fallback !== undefined && fallback !== null) return String(fallback);

  // Last resort: return the key itself
  return key;
}

// ---------------------------------------------------------------------------
// Date / time formatting
// ---------------------------------------------------------------------------

/**
 * Format a date using `Intl.DateTimeFormat` with the current locale.
 * Uses "medium" date style (e.g., "Feb 16, 2026" / "16 f\u00e9vr. 2026").
 */
export function formatDate(date: Date | string | number): string {
  const d = date instanceof Date ? date : new Date(date);
  return new Intl.DateTimeFormat(locale(), { dateStyle: "medium" }).format(d);
}

/**
 * Format a time using `Intl.DateTimeFormat` with the current locale.
 * Uses "short" time style (e.g., "2:30 PM" / "14:30").
 */
export function formatTime(date: Date | string | number): string {
  const d = date instanceof Date ? date : new Date(date);
  return new Intl.DateTimeFormat(locale(), { timeStyle: "short" }).format(d);
}

/**
 * Format a date+time using `Intl.DateTimeFormat` with the current locale.
 */
export function formatDateTime(date: Date | string | number): string {
  const d = date instanceof Date ? date : new Date(date);
  return new Intl.DateTimeFormat(locale(), {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(d);
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/**
 * Detect the best initial locale from OS settings.
 * Only returns a locale if it matches one of our supported locales.
 */
function detectOsLocale(): Locale | null {
  if (typeof navigator === "undefined") return null;

  const langs = navigator.languages ?? [navigator.language];
  for (const lang of langs) {
    const code = lang.split("-")[0].toLowerCase();
    if (code in dictionaries) return code as Locale;
  }
  return null;
}

/**
 * Initialize the i18n system.
 *
 * @param savedLanguage — language code from saved preferences (if any)
 */
export function initI18n(savedLanguage?: string): void {
  // Priority: saved preference > OS locale > "en"
  if (savedLanguage && savedLanguage in dictionaries) {
    setLocaleSignal(savedLanguage as Locale);
  } else {
    const osLocale = detectOsLocale();
    setLocaleSignal(osLocale ?? "en");
  }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** Reset the i18n store to defaults (for testing only). @internal */
export function _resetI18nStore(): void {
  setLocaleSignal("en");
}

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  t,
  locale,
  setLocale,
  initI18n,
  formatDate,
  formatTime,
  formatDateTime,
  AVAILABLE_LOCALES,
  _resetI18nStore,
} from "../../stores/i18nStore";

describe("i18nStore", () => {
  beforeEach(() => {
    _resetI18nStore();
  });

  // ---------------------------------------------------------------------------
  // Locale signal
  // ---------------------------------------------------------------------------

  it("defaults to English locale", () => {
    expect(locale()).toBe("en");
  });

  it("changes locale via setLocale()", () => {
    setLocale("fr");
    expect(locale()).toBe("fr");
  });

  it("exposes all four supported locales", () => {
    expect(AVAILABLE_LOCALES).toHaveLength(4);
    const codes = AVAILABLE_LOCALES.map((l) => l.code);
    expect(codes).toEqual(["en", "fr", "de", "es"]);
  });

  // ---------------------------------------------------------------------------
  // Translation function t()
  // ---------------------------------------------------------------------------

  it("translates a simple key in English", () => {
    expect(t("common.save")).toBe("Save");
    expect(t("common.cancel")).toBe("Cancel");
  });

  it("translates nested keys", () => {
    expect(t("sidebar.navigation")).toBe("Navigation");
    expect(t("header.title")).toBe("VERROU");
  });

  it("translates in French when locale is fr", () => {
    setLocale("fr");
    expect(t("common.save")).toBe("Enregistrer");
    expect(t("common.cancel")).toBe("Annuler");
  });

  it("translates in German when locale is de", () => {
    setLocale("de");
    expect(t("common.save")).toBe("Speichern");
    expect(t("common.cancel")).toBe("Abbrechen");
  });

  it("translates in Spanish when locale is es", () => {
    setLocale("es");
    expect(t("common.save")).toBe("Guardar");
    expect(t("common.cancel")).toBe("Cancelar");
  });

  // ---------------------------------------------------------------------------
  // Fallback behavior
  // ---------------------------------------------------------------------------

  it("falls back to English for missing keys in non-en locale", () => {
    setLocale("de");
    // de.json is a core subset — many keys only exist in en.json
    // The fallback should return the English value
    const result = t("header.title");
    expect(result).toBe("VERROU");
  });

  it("returns key itself when not found in any dictionary", () => {
    const result = t("nonexistent.key.that.does.not.exist");
    expect(result).toBe("nonexistent.key.that.does.not.exist");
  });

  it("logs console.warn for missing keys in dev mode (non-en locale)", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    setLocale("de");
    // Access a key that exists in en but not de
    t("credentials.add.title");
    // import.meta.env.DEV is true in vitest — verify warning fires
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('[i18n] Missing key "credentials.add.title"'),
    );
    warnSpy.mockRestore();
  });

  // ---------------------------------------------------------------------------
  // Template resolution
  // ---------------------------------------------------------------------------

  it("resolves template variables", () => {
    const result = t("footer.entryCount", { count: 42 });
    expect(result).toBe("42 entries");
  });

  it("resolves template variables in French", () => {
    setLocale("fr");
    const result = t("footer.entryCount", { count: 42 });
    expect(result).toBe("42 entrées");
  });

  // ---------------------------------------------------------------------------
  // initI18n()
  // ---------------------------------------------------------------------------

  it("uses saved language when provided", () => {
    initI18n("fr");
    expect(locale()).toBe("fr");
  });

  it("ignores invalid saved language", () => {
    initI18n("xx");
    // Should fall back to OS locale or "en"
    expect(["en", "fr", "de", "es"]).toContain(locale());
  });

  it("uses OS locale when no saved language", () => {
    // navigator.languages is available in jsdom
    const originalLanguages = navigator.languages;
    Object.defineProperty(navigator, "languages", {
      value: ["de-DE", "en-US"],
      configurable: true,
    });

    initI18n();
    expect(locale()).toBe("de");

    Object.defineProperty(navigator, "languages", {
      value: originalLanguages,
      configurable: true,
    });
  });

  it("falls back to en when OS locale is unsupported", () => {
    const originalLanguages = navigator.languages;
    Object.defineProperty(navigator, "languages", {
      value: ["ja-JP", "zh-CN"],
      configurable: true,
    });

    initI18n();
    expect(locale()).toBe("en");

    Object.defineProperty(navigator, "languages", {
      value: originalLanguages,
      configurable: true,
    });
  });

  // ---------------------------------------------------------------------------
  // Date/time formatting
  // ---------------------------------------------------------------------------

  it("formats date with current locale", () => {
    const date = new Date(2026, 1, 16); // Feb 16, 2026
    const result = formatDate(date);
    expect(result).toBeTruthy();
    expect(typeof result).toBe("string");
  });

  it("formats time with current locale", () => {
    const date = new Date(2026, 1, 16, 14, 30);
    const result = formatTime(date);
    expect(result).toBeTruthy();
    expect(typeof result).toBe("string");
  });

  it("formats date+time with current locale", () => {
    const date = new Date(2026, 1, 16, 14, 30);
    const result = formatDateTime(date);
    expect(result).toBeTruthy();
    expect(typeof result).toBe("string");
  });

  it("accepts string and number date inputs", () => {
    const iso = "2026-02-16T14:30:00Z";
    const ts = new Date(iso).getTime();
    expect(formatDate(iso)).toBeTruthy();
    expect(formatDate(ts)).toBeTruthy();
  });

  // ---------------------------------------------------------------------------
  // _resetI18nStore()
  // ---------------------------------------------------------------------------

  it("resets locale to en", () => {
    setLocale("fr");
    expect(locale()).toBe("fr");
    _resetI18nStore();
    expect(locale()).toBe("en");
  });
});

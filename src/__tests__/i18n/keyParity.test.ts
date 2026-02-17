import { describe, it, expect } from "vitest";
import en from "../../i18n/en.json";
import fr from "../../i18n/fr.json";
import de from "../../i18n/de.json";
import es from "../../i18n/es.json";

/** Recursively extract all leaf keys from a nested object. */
function getLeafKeys(obj: Record<string, unknown>, prefix = ""): string[] {
  const keys: string[] = [];
  for (const [k, v] of Object.entries(obj)) {
    const full = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      keys.push(...getLeafKeys(v as Record<string, unknown>, full));
    } else {
      keys.push(full);
    }
  }
  return keys;
}

describe("i18n key parity", () => {
  const enKeys = new Set(getLeafKeys(en));

  it("en.json has a reasonable number of keys", () => {
    expect(enKeys.size).toBeGreaterThan(100);
  });

  it("fr.json has exact parity with en.json", () => {
    const frKeys = new Set(getLeafKeys(fr));
    const missingInFr = [...enKeys].filter((k) => !frKeys.has(k));
    const extraInFr = [...frKeys].filter((k) => !enKeys.has(k));

    expect(missingInFr).toEqual([]);
    expect(extraInFr).toEqual([]);
  });

  it("de.json keys are a subset of en.json", () => {
    const deKeys = getLeafKeys(de);
    const extraInDe = deKeys.filter((k) => !enKeys.has(k));
    expect(extraInDe).toEqual([]);
  });

  it("es.json keys are a subset of en.json", () => {
    const esKeys = getLeafKeys(es);
    const extraInEs = esKeys.filter((k) => !enKeys.has(k));
    expect(extraInEs).toEqual([]);
  });

  it("de.json covers core UI sections", () => {
    const deKeys = new Set(getLeafKeys(de));
    // Core sections that should be translated
    expect(deKeys.has("common.save")).toBe(true);
    expect(deKeys.has("sidebar.navigation")).toBe(true);
    expect(deKeys.has("header.title")).toBe(true);
    expect(deKeys.has("settings.title")).toBe(true);
  });

  it("es.json covers core UI sections", () => {
    const esKeys = new Set(getLeafKeys(es));
    expect(esKeys.has("common.save")).toBe(true);
    expect(esKeys.has("sidebar.navigation")).toBe(true);
    expect(esKeys.has("header.title")).toBe(true);
    expect(esKeys.has("settings.title")).toBe(true);
  });

  it("no translation values are empty strings", () => {
    const checkEmpty = (obj: Record<string, unknown>, file: string, prefix = "") => {
      for (const [k, v] of Object.entries(obj)) {
        const full = prefix ? `${prefix}.${k}` : k;
        if (v !== null && typeof v === "object" && !Array.isArray(v)) {
          checkEmpty(v as Record<string, unknown>, file, full);
        } else if (typeof v === "string" && v.trim() === "") {
          throw new Error(`Empty translation: ${file}:${full}`);
        }
      }
    };

    checkEmpty(en, "en.json");
    checkEmpty(fr, "fr.json");
    checkEmpty(de, "de.json");
    checkEmpty(es, "es.json");
  });

  it("template variables in fr.json match en.json", () => {
    const enFlat = Object.fromEntries(
      getLeafKeys(en).map((k) => {
        let val: unknown = en;
        for (const part of k.split(".")) val = (val as Record<string, unknown>)[part];
        return [k, val as string];
      }),
    );
    const frFlat = Object.fromEntries(
      getLeafKeys(fr).map((k) => {
        let val: unknown = fr;
        for (const part of k.split(".")) val = (val as Record<string, unknown>)[part];
        return [k, val as string];
      }),
    );

    const templateVar = /\{\{(\w+)\}\}/g;
    for (const key of Object.keys(enFlat)) {
      const enVars = [...enFlat[key].matchAll(templateVar)].map((m) => m[1]).sort();
      if (enVars.length === 0) continue;
      if (!(key in frFlat)) continue;
      const frVars = [...frFlat[key].matchAll(templateVar)].map((m) => m[1]).sort();
      expect(frVars, `Template vars mismatch for key "${key}"`).toEqual(enVars);
    }
  });

  it("all t() keys used in source code exist in en.json", async () => {
    const { readFileSync, readdirSync, statSync } = await import("fs");
    const { join } = await import("path");
    const srcRoot = join(__dirname, "..", "..");

    // Recursively collect .tsx files
    const tsxFiles: string[] = [];
    function walk(dir: string) {
      for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        if (entry === "__tests__" || entry === "node_modules") continue;
        if (statSync(full).isDirectory()) walk(full);
        else if (entry.endsWith(".tsx")) tsxFiles.push(full);
      }
    }
    walk(srcRoot);

    // Extract all t("...") calls
    const tKeyPattern = /\bt\(\s*["'`]([^"'`]+)["'`]/g;
    const usedKeys = new Set<string>();
    for (const file of tsxFiles) {
      const content = readFileSync(file, "utf-8");
      for (const match of content.matchAll(tKeyPattern)) {
        const key = match[1];
        // Skip dynamic keys with template literals
        if (key.includes("${") || key.includes("{{")) continue;
        usedKeys.add(key);
      }
    }

    expect(usedKeys.size).toBeGreaterThan(50);

    const missing = [...usedKeys].filter((k) => !enKeys.has(k));
    expect(missing, `Keys used in t() but missing from en.json: ${missing.join(", ")}`).toEqual([]);
  });
});

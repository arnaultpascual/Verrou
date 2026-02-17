import { describe, it, expect } from "vitest";
import {
  CREDENTIAL_TEMPLATES,
  getTemplateById,
} from "../../../features/credentials/templates";
import type { TemplateDefinition } from "../../../features/credentials/templates";

describe("CREDENTIAL_TEMPLATES", () => {
  it("contains exactly 5 built-in templates", () => {
    expect(CREDENTIAL_TEMPLATES).toHaveLength(5);
  });

  it("has unique IDs", () => {
    const ids = CREDENTIAL_TEMPLATES.map((t) => t.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("has non-empty names, icons, and descriptions for all templates", () => {
    for (const tmpl of CREDENTIAL_TEMPLATES) {
      expect(tmpl.name).toBeTruthy();
      expect(tmpl.icon).toBeTruthy();
      expect(tmpl.description).toBeTruthy();
    }
  });

  describe("Login template", () => {
    let tmpl: TemplateDefinition;
    it("exists with id 'login'", () => {
      tmpl = CREDENTIAL_TEMPLATES.find((t) => t.id === "login")!;
      expect(tmpl).toBeDefined();
    });
    it("has no custom fields (base credential is sufficient)", () => {
      const t = CREDENTIAL_TEMPLATES.find((t) => t.id === "login")!;
      expect(t.customFields).toHaveLength(0);
    });
  });

  describe("Credit Card template", () => {
    it("has 4 custom fields with correct types", () => {
      const tmpl = CREDENTIAL_TEMPLATES.find((t) => t.id === "credit_card")!;
      expect(tmpl).toBeDefined();
      expect(tmpl.customFields).toHaveLength(4);

      const [cardNumber, expiry, cvv, cardholder] = tmpl.customFields;
      expect(cardNumber.label).toBe("Card Number");
      expect(cardNumber.fieldType).toBe("hidden");
      expect(expiry.label).toBe("Expiry Date");
      expect(expiry.fieldType).toBe("date");
      expect(cvv.label).toBe("CVV");
      expect(cvv.fieldType).toBe("hidden");
      expect(cardholder.label).toBe("Cardholder Name");
      expect(cardholder.fieldType).toBe("text");
    });
  });

  describe("Identity template", () => {
    it("has 5 custom fields with correct types", () => {
      const tmpl = CREDENTIAL_TEMPLATES.find((t) => t.id === "identity")!;
      expect(tmpl).toBeDefined();
      expect(tmpl.customFields).toHaveLength(5);

      expect(tmpl.customFields[0].label).toBe("Full Name");
      expect(tmpl.customFields[0].fieldType).toBe("text");
      expect(tmpl.customFields[4].label).toBe("Date of Birth");
      expect(tmpl.customFields[4].fieldType).toBe("date");
    });
  });

  describe("SSH Key template", () => {
    it("has 4 custom fields with correct types", () => {
      const tmpl = CREDENTIAL_TEMPLATES.find((t) => t.id === "ssh_key")!;
      expect(tmpl).toBeDefined();
      expect(tmpl.customFields).toHaveLength(4);

      const [privKey, pubKey, fingerprint, passphrase] = tmpl.customFields;
      expect(privKey.label).toBe("Private Key");
      expect(privKey.fieldType).toBe("hidden");
      expect(pubKey.label).toBe("Public Key");
      expect(pubKey.fieldType).toBe("text");
      expect(fingerprint.label).toBe("Fingerprint");
      expect(fingerprint.fieldType).toBe("text");
      expect(passphrase.label).toBe("Passphrase");
      expect(passphrase.fieldType).toBe("hidden");
    });
  });

  describe("Software License template", () => {
    it("has 4 custom fields with correct types", () => {
      const tmpl = CREDENTIAL_TEMPLATES.find((t) => t.id === "software_license")!;
      expect(tmpl).toBeDefined();
      expect(tmpl.customFields).toHaveLength(4);

      const [licenseKey, email, date, seats] = tmpl.customFields;
      expect(licenseKey.label).toBe("License Key");
      expect(licenseKey.fieldType).toBe("hidden");
      expect(email.label).toBe("Registered Email");
      expect(email.fieldType).toBe("text");
      expect(date.label).toBe("Purchase Date");
      expect(date.fieldType).toBe("date");
      expect(seats.label).toBe("Seats");
      expect(seats.fieldType).toBe("text");
    });
  });

  it("all custom field values are empty strings", () => {
    for (const tmpl of CREDENTIAL_TEMPLATES) {
      for (const field of tmpl.customFields) {
        expect(field.value).toBe("");
      }
    }
  });

  it("all field types are valid CustomFieldType values", () => {
    const validTypes = new Set(["text", "hidden", "url", "date"]);
    for (const tmpl of CREDENTIAL_TEMPLATES) {
      for (const field of tmpl.customFields) {
        expect(validTypes.has(field.fieldType)).toBe(true);
      }
    }
  });
});

describe("getTemplateById", () => {
  it("returns the correct template for each ID", () => {
    for (const tmpl of CREDENTIAL_TEMPLATES) {
      const found = getTemplateById(tmpl.id);
      expect(found).toBe(tmpl);
    }
  });

  it("returns undefined for unknown ID", () => {
    expect(getTemplateById("nonexistent")).toBeUndefined();
  });

  it("returns undefined for empty string", () => {
    expect(getTemplateById("")).toBeUndefined();
  });
});

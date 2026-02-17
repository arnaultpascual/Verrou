/**
 * Built-in credential templates.
 *
 * Templates pre-populate custom fields for common credential types.
 * They are frontend-only static data — no backend storage needed.
 * The `template` field on the credential is a simple string identifier.
 */

import type { IconName } from "../../components/Icon";
import type { CustomFieldDto } from "../entries/ipc";

/** Template definition for a credential type. */
export interface TemplateDefinition {
  /** Unique identifier stored in the credential's `template` field. */
  id: string;
  /** Human-readable name shown in the dropdown. */
  name: string;
  /** Icon name from the Icon component. */
  icon: IconName;
  /** Short description for the dropdown. */
  description: string;
  /** Custom fields pre-populated when this template is selected. */
  customFields: CustomFieldDto[];
}

/** All built-in credential templates. */
export const CREDENTIAL_TEMPLATES: TemplateDefinition[] = [
  {
    id: "login",
    name: "Login",
    icon: "key",
    description: "Website or app login",
    customFields: [],
  },
  {
    id: "credit_card",
    name: "Credit Card",
    icon: "credit-card",
    description: "Payment card details",
    customFields: [
      { label: "Card Number", value: "", fieldType: "hidden" },
      { label: "Expiry Date", value: "", fieldType: "date" },
      { label: "CVV", value: "", fieldType: "hidden" },
      { label: "Cardholder Name", value: "", fieldType: "text" },
    ],
  },
  {
    id: "identity",
    name: "Identity",
    icon: "user",
    description: "Personal identity document",
    customFields: [
      { label: "Full Name", value: "", fieldType: "text" },
      { label: "Email", value: "", fieldType: "text" },
      { label: "Phone", value: "", fieldType: "text" },
      { label: "Address", value: "", fieldType: "text" },
      { label: "Date of Birth", value: "", fieldType: "date" },
    ],
  },
  {
    id: "ssh_key",
    name: "SSH Key",
    icon: "terminal",
    description: "SSH key pair",
    customFields: [
      { label: "Private Key", value: "", fieldType: "hidden" },
      { label: "Public Key", value: "", fieldType: "text" },
      { label: "Fingerprint", value: "", fieldType: "text" },
      { label: "Passphrase", value: "", fieldType: "hidden" },
    ],
  },
  {
    id: "software_license",
    name: "Software License",
    icon: "file-text",
    description: "Software license key",
    customFields: [
      { label: "License Key", value: "", fieldType: "hidden" },
      { label: "Registered Email", value: "", fieldType: "text" },
      { label: "Purchase Date", value: "", fieldType: "date" },
      { label: "Seats", value: "", fieldType: "text" },
    ],
  },
];

/** Look up a template by its ID. */
export function getTemplateById(id: string): TemplateDefinition | undefined {
  return CREDENTIAL_TEMPLATES.find((t) => t.id === id);
}

-- 007_add_template_column.sql
-- Adds unencrypted template column for credential entries (EntryCard display).
-- Same Layer 1 (SQLCipher) protection as username column.
-- Stores template identifier (e.g., "credit_card", "ssh_key") — non-secret metadata.
-- Existing credentials will show NULL until next edit.

ALTER TABLE entries ADD COLUMN template TEXT;

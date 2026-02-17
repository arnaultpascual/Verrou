-- 005_add_username_column.sql
-- Adds unencrypted username column for credential entries (EntryCard display).
-- Same Layer 1 (SQLCipher) protection as name/issuer columns.
-- Existing credentials will show NULL until next edit.

ALTER TABLE entries ADD COLUMN username TEXT;

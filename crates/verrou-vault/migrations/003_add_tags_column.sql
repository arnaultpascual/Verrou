-- 003_add_tags_column.sql
-- Adds a plaintext `tags` column to entries for search without decryption.
-- Tags are stored as JSON arrays (e.g. '["server","production"]').
-- The authoritative copy remains inside the encrypted blob; this column
-- is a search-friendly duplicate kept in sync by add/update operations.

ALTER TABLE entries ADD COLUMN tags TEXT NOT NULL DEFAULT '[]';

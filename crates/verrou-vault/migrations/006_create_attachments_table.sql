-- 006_create_attachments_table.sql
-- Secure file attachments stored as AES-256-GCM encrypted BLOBs.
-- Metadata (filename, mime_type, size_bytes) is plaintext under Layer 1 (SQLCipher).
-- File content (encrypted_data) is Layer 2 encrypted with an entry-specific derived key.
-- ON DELETE CASCADE ensures attachments are removed when the parent entry is deleted.

CREATE TABLE attachments (
    id             TEXT PRIMARY KEY NOT NULL,
    entry_id       TEXT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    filename       TEXT NOT NULL,
    mime_type      TEXT NOT NULL,
    size_bytes     INTEGER NOT NULL,
    encrypted_data BLOB NOT NULL,
    created_at     TEXT NOT NULL
);

CREATE INDEX idx_attachments_entry_id ON attachments(entry_id);

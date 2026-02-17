-- 001_initial_schema.sql
-- Creates the core vault tables: entries, folders, key_slots.
-- Convention: snake_case plural tables, snake_case columns,
--            idx_{table}_{column} indexes, {ref_singular}_id FKs.

CREATE TABLE IF NOT EXISTS folders (
    id         TEXT    PRIMARY KEY NOT NULL,
    name       TEXT    NOT NULL,
    parent_id  TEXT    REFERENCES folders(id) ON DELETE SET NULL,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_folders_parent_id ON folders(parent_id);

CREATE TABLE IF NOT EXISTS entries (
    id             TEXT PRIMARY KEY NOT NULL,
    entry_type     TEXT NOT NULL CHECK(entry_type IN ('totp', 'seed_phrase', 'recovery_code', 'secure_note')),
    name           TEXT NOT NULL,
    issuer         TEXT,
    folder_id      TEXT REFERENCES folders(id) ON DELETE SET NULL,
    encrypted_data BLOB NOT NULL,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entries_folder_id  ON entries(folder_id);
CREATE INDEX IF NOT EXISTS idx_entries_entry_type ON entries(entry_type);
CREATE INDEX IF NOT EXISTS idx_entries_issuer     ON entries(issuer);

CREATE TABLE IF NOT EXISTS key_slots (
    id          TEXT PRIMARY KEY NOT NULL,
    slot_type   TEXT NOT NULL,
    wrapped_key BLOB NOT NULL,
    salt        BLOB,
    kdf_params  TEXT,
    created_at  TEXT NOT NULL
);

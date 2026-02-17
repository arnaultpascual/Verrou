-- 004_add_credential_type.sql
-- Adds 'credential' to the entry_type CHECK constraint.
-- SQLite cannot ALTER CHECK constraints, so we recreate the entries table.

-- Step 1: Create new table with updated CHECK constraint.
CREATE TABLE entries_new (
    id             TEXT PRIMARY KEY NOT NULL,
    entry_type     TEXT NOT NULL CHECK(entry_type IN ('totp', 'hotp', 'seed_phrase', 'recovery_code', 'secure_note', 'credential')),
    name           TEXT NOT NULL,
    issuer         TEXT,
    folder_id      TEXT REFERENCES folders(id) ON DELETE SET NULL,
    encrypted_data BLOB NOT NULL,
    algorithm      TEXT NOT NULL DEFAULT 'SHA1',
    digits         INTEGER NOT NULL DEFAULT 6 CHECK(digits IN (6, 8)),
    period         INTEGER NOT NULL DEFAULT 30 CHECK(period IN (15, 30, 60)),
    counter        INTEGER NOT NULL DEFAULT 0,
    pinned         INTEGER NOT NULL DEFAULT 0 CHECK(pinned IN (0, 1)),
    tags           TEXT NOT NULL DEFAULT '[]',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

-- Step 2: Copy existing data.
INSERT INTO entries_new (id, entry_type, name, issuer, folder_id, encrypted_data,
    algorithm, digits, period, counter, pinned, tags, created_at, updated_at)
SELECT id, entry_type, name, issuer, folder_id, encrypted_data,
    algorithm, digits, period, counter, pinned, tags, created_at, updated_at
FROM entries;

-- Step 3: Drop old table and rename new one.
DROP TABLE entries;
ALTER TABLE entries_new RENAME TO entries;

-- Step 4: Recreate indexes.
CREATE INDEX IF NOT EXISTS idx_entries_folder_id  ON entries(folder_id);
CREATE INDEX IF NOT EXISTS idx_entries_entry_type ON entries(entry_type);
CREATE INDEX IF NOT EXISTS idx_entries_issuer     ON entries(issuer);
CREATE INDEX IF NOT EXISTS idx_entries_pinned     ON entries(pinned);

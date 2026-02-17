//! Folder management for vault entry organization.
//!
//! Folders provide a simple flat (with optional nesting) organizational
//! structure for vault entries. Each folder has a name, optional parent,
//! and sort order.

use rusqlite::params;

use crate::error::VaultError;
use crate::lifecycle::{generate_uuid, now_iso8601};

/// A folder in the vault.
#[derive(Debug, Clone)]
pub struct Folder {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub sort_order: i32,
    pub created_at: String,
    pub updated_at: String,
}

/// A folder with its entry count for list display.
#[derive(Debug, Clone)]
pub struct FolderListItem {
    pub folder: Folder,
    pub entry_count: u32,
}

/// Create a new folder.
///
/// # Errors
///
/// Returns [`VaultError::Database`] if the SQL INSERT fails.
pub fn create_folder(conn: &rusqlite::Connection, name: &str) -> Result<Folder, VaultError> {
    let id = generate_uuid();
    let now = now_iso8601();

    conn.execute(
        "INSERT INTO folders (id, name, parent_id, sort_order, created_at, updated_at) \
         VALUES (?1, ?2, NULL, 0, ?3, ?4)",
        params![id, name, now, now],
    )
    .map_err(|e| VaultError::Database(format!("failed to create folder: {e}")))?;

    Ok(Folder {
        id,
        name: name.to_string(),
        parent_id: None,
        sort_order: 0,
        created_at: now.clone(),
        updated_at: now,
    })
}

/// List all folders with their entry counts.
///
/// Returns folders sorted by `sort_order`, then name.
///
/// # Errors
///
/// Returns [`VaultError::Database`] if the query fails.
pub fn list_folders_with_counts(
    conn: &rusqlite::Connection,
) -> Result<Vec<FolderListItem>, VaultError> {
    let mut stmt = conn
        .prepare(
            "SELECT f.id, f.name, f.parent_id, f.sort_order, f.created_at, f.updated_at, \
             COUNT(e.id) AS entry_count \
             FROM folders f \
             LEFT JOIN entries e ON e.folder_id = f.id \
             GROUP BY f.id \
             ORDER BY f.sort_order ASC, f.name ASC",
        )
        .map_err(|e| VaultError::Database(format!("failed to prepare folder query: {e}")))?;

    let rows = stmt
        .query_map([], |row| {
            Ok(FolderListItem {
                folder: Folder {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    parent_id: row.get(2)?,
                    sort_order: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                },
                entry_count: row.get::<_, u32>(6)?,
            })
        })
        .map_err(|e| VaultError::Database(format!("failed to query folders: {e}")))?;

    let mut items = Vec::new();
    for row in rows {
        items.push(
            row.map_err(|e| VaultError::Database(format!("failed to read folder row: {e}")))?,
        );
    }

    Ok(items)
}

/// Rename a folder.
///
/// # Errors
///
/// Returns [`VaultError::Database`] if the UPDATE fails or folder is not found.
pub fn rename_folder(
    conn: &rusqlite::Connection,
    folder_id: &str,
    new_name: &str,
) -> Result<Folder, VaultError> {
    let now = now_iso8601();

    let updated = conn
        .execute(
            "UPDATE folders SET name = ?1, updated_at = ?2 WHERE id = ?3",
            params![new_name, now, folder_id],
        )
        .map_err(|e| VaultError::Database(format!("failed to rename folder: {e}")))?;

    if updated == 0 {
        return Err(VaultError::Database("Folder not found.".to_string()));
    }

    // Fetch the updated folder.
    conn.query_row(
        "SELECT id, name, parent_id, sort_order, created_at, updated_at \
         FROM folders WHERE id = ?1",
        params![folder_id],
        |row| {
            Ok(Folder {
                id: row.get(0)?,
                name: row.get(1)?,
                parent_id: row.get(2)?,
                sort_order: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
            })
        },
    )
    .map_err(|e| VaultError::Database(format!("failed to fetch renamed folder: {e}")))
}

/// Delete a folder.
///
/// Entries in this folder have their `folder_id` set to NULL (moved to "All").
/// The folder is then deleted.
///
/// # Errors
///
/// Returns [`VaultError::Database`] if the queries fail.
pub fn delete_folder(conn: &rusqlite::Connection, folder_id: &str) -> Result<(), VaultError> {
    // Unlink entries from this folder.
    conn.execute(
        "UPDATE entries SET folder_id = NULL WHERE folder_id = ?1",
        params![folder_id],
    )
    .map_err(|e| VaultError::Database(format!("failed to unlink entries from folder: {e}")))?;

    // Delete the folder.
    let deleted = conn
        .execute("DELETE FROM folders WHERE id = ?1", params![folder_id])
        .map_err(|e| VaultError::Database(format!("failed to delete folder: {e}")))?;

    if deleted == 0 {
        return Err(VaultError::Database("Folder not found.".to_string()));
    }

    Ok(())
}

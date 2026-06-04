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

/// Create a new top-level folder.
///
/// # Errors
///
/// Returns [`VaultError::Database`] if the SQL INSERT fails.
pub fn create_folder(conn: &rusqlite::Connection, name: &str) -> Result<Folder, VaultError> {
    create_folder_under(conn, name, None)
}

/// Create a new folder, optionally nested under `parent_id`.
///
/// The folder is appended after its existing siblings (sort order = current
/// sibling max + 1), so newly created folders sort last within their parent
/// until the user reorders them.
///
/// # Errors
///
/// Returns [`VaultError::Database`] if the SQL INSERT fails.
pub fn create_folder_under(
    conn: &rusqlite::Connection,
    name: &str,
    parent_id: Option<&str>,
) -> Result<Folder, VaultError> {
    let id = generate_uuid();
    let now = now_iso8601();
    let sort_order = next_sort_order(conn, parent_id)?;

    conn.execute(
        "INSERT INTO folders (id, name, parent_id, sort_order, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![id, name, parent_id, sort_order, now, now],
    )
    .map_err(|e| VaultError::Database(format!("failed to create folder: {e}")))?;

    Ok(Folder {
        id,
        name: name.to_string(),
        parent_id: parent_id.map(str::to_string),
        sort_order,
        created_at: now.clone(),
        updated_at: now,
    })
}

/// Next sort order for a new folder within `parent_id` (sibling max + 1, or 0).
///
/// `parent_id IS ?1` matches NULL correctly, so top-level folders (NULL parent)
/// share one sibling group.
fn next_sort_order(
    conn: &rusqlite::Connection,
    parent_id: Option<&str>,
) -> Result<i32, VaultError> {
    let max: Option<i32> = conn
        .query_row(
            "SELECT MAX(sort_order) FROM folders WHERE parent_id IS ?1",
            params![parent_id],
            |row| row.get(0),
        )
        .map_err(|e| VaultError::Database(format!("failed to read sort order: {e}")))?;
    Ok(max.map_or(0, |m| m.saturating_add(1)))
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

/// Return the `parent_id` of a folder, or `None` if it has no parent (or does
/// not exist — treated as the end of an ancestry walk).
fn parent_of(conn: &rusqlite::Connection, folder_id: &str) -> Result<Option<String>, VaultError> {
    match conn.query_row(
        "SELECT parent_id FROM folders WHERE id = ?1",
        params![folder_id],
        |row| row.get::<_, Option<String>>(0),
    ) {
        Ok(parent) => Ok(parent),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(VaultError::Database(format!(
            "failed to read folder parent: {e}"
        ))),
    }
}

/// Move a folder under `new_parent_id` (or to the top level when `None`) and
/// place it at `position` among its new siblings.
///
/// Both reparenting and reordering go through this one operation. All siblings
/// in the destination group are renumbered `0..n` in a single transaction so
/// `sort_order` stays dense and stable. `position` is clamped to a valid index.
///
/// Moving a folder into itself or one of its own descendants is rejected — that
/// would create a cycle in the tree.
///
/// # Errors
///
/// Returns [`VaultError::Database`] if the folder does not exist, the move would
/// create a cycle, or a query fails.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
pub fn move_folder(
    conn: &rusqlite::Connection,
    folder_id: &str,
    new_parent_id: Option<&str>,
    position: i32,
) -> Result<Folder, VaultError> {
    // Cycle prevention: the destination parent must not be the folder itself
    // nor any of its descendants. Walk up from the destination to the root.
    if let Some(parent) = new_parent_id {
        if parent == folder_id {
            return Err(VaultError::Database(
                "A folder cannot be moved into itself.".to_string(),
            ));
        }
        let mut ancestor = parent_of(conn, parent)?;
        while let Some(current) = ancestor {
            if current == folder_id {
                return Err(VaultError::Database(
                    "A folder cannot be moved into one of its own subfolders.".to_string(),
                ));
            }
            ancestor = parent_of(conn, &current)?;
        }
    }

    let now = now_iso8601();
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| VaultError::Database(format!("failed to begin transaction: {e}")))?;

    // The folder being moved must exist.
    let exists = tx
        .query_row(
            "SELECT 1 FROM folders WHERE id = ?1",
            params![folder_id],
            |_| Ok(()),
        )
        .is_ok();
    if !exists {
        return Err(VaultError::Database("Folder not found.".to_string()));
    }

    // Ordered sibling ids in the destination group, excluding the mover itself.
    let mut sibling_ids: Vec<String> = {
        let mut stmt = tx
            .prepare(
                "SELECT id FROM folders \
                 WHERE parent_id IS ?1 AND id != ?2 \
                 ORDER BY sort_order ASC, name ASC",
            )
            .map_err(|e| VaultError::Database(format!("failed to prepare sibling query: {e}")))?;
        let rows = stmt
            .query_map(params![new_parent_id, folder_id], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|e| VaultError::Database(format!("failed to query siblings: {e}")))?;
        let mut ids = Vec::new();
        for row in rows {
            ids.push(
                row.map_err(|e| VaultError::Database(format!("failed to read sibling: {e}")))?,
            );
        }
        ids
    };

    // Clamp the insertion index, then splice the mover into the ordered group.
    let clamped = position.max(0).min(sibling_ids.len() as i32) as usize;
    sibling_ids.insert(clamped, folder_id.to_string());

    // Renumber the whole group densely; the mover also gets its new parent.
    for (index, id) in sibling_ids.iter().enumerate() {
        let order = index as i32;
        if id == folder_id {
            tx.execute(
                "UPDATE folders SET parent_id = ?1, sort_order = ?2, updated_at = ?3 \
                 WHERE id = ?4",
                params![new_parent_id, order, now, id],
            )
        } else {
            tx.execute(
                "UPDATE folders SET sort_order = ?1 WHERE id = ?2",
                params![order, id],
            )
        }
        .map_err(|e| VaultError::Database(format!("failed to renumber folders: {e}")))?;
    }

    tx.commit()
        .map_err(|e| VaultError::Database(format!("failed to commit folder move: {e}")))?;

    // Return the moved folder in its new position.
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
    .map_err(|e| VaultError::Database(format!("failed to fetch moved folder: {e}")))
}

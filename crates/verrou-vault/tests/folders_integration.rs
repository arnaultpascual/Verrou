//! Integration tests for folder hierarchy operations.
//!
//! Exercises the nesting-aware create path and the cycle-safe `move_folder`
//! (reorder + reparent) against a real SQLCipher-backed vault.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::path::Path;

use verrou_crypto_core::kdf::{Argon2idParams, CalibratedPresets, KdfPreset};
use verrou_crypto_core::memory::SecretBytes;
use verrou_vault::lifecycle::{CreateVaultRequest, UnlockVaultRequest};
use verrou_vault::{create_folder, create_folder_under, list_folders_with_counts, move_folder};

/// Minimal Argon2id params for fast tests (not secure — test only).
const fn test_calibrated() -> CalibratedPresets {
    CalibratedPresets {
        fast: Argon2idParams {
            m_cost: 32,
            t_cost: 1,
            p_cost: 1,
        },
        balanced: Argon2idParams {
            m_cost: 64,
            t_cost: 2,
            p_cost: 1,
        },
        maximum: Argon2idParams {
            m_cost: 128,
            t_cost: 3,
            p_cost: 1,
        },
    }
}

/// Create + unlock a vault in `dir`, returning the open database.
fn setup_vault(dir: &Path) -> (verrou_vault::VaultDb, SecretBytes<32>) {
    let calibrated = test_calibrated();
    let password = b"folder-tests-password";
    verrou_vault::lifecycle::create_vault(&CreateVaultRequest {
        password,
        preset: KdfPreset::Fast,
        vault_dir: dir,
        calibrated: &calibrated,
    })
    .expect("vault creation should succeed in test");

    let session = verrou_vault::lifecycle::unlock_vault(&UnlockVaultRequest {
        password,
        vault_dir: dir,
    })
    .expect("vault unlock should succeed in test");

    (session.db, session.master_key)
}

/// Map of folder id to `sort_order` across the whole vault.
fn sort_orders(db: &verrou_vault::VaultDb) -> HashMap<String, i32> {
    list_folders_with_counts(db.connection())
        .unwrap()
        .into_iter()
        .map(|item| (item.folder.id, item.folder.sort_order))
        .collect()
}

/// Map of folder id to `parent_id` across the whole vault.
fn parents(db: &verrou_vault::VaultDb) -> HashMap<String, Option<String>> {
    list_folders_with_counts(db.connection())
        .unwrap()
        .into_iter()
        .map(|item| (item.folder.id, item.folder.parent_id))
        .collect()
}

#[test]
fn create_appends_after_siblings_at_root() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _key) = setup_vault(dir.path());

    let a = create_folder(db.connection(), "A").unwrap();
    let b = create_folder(db.connection(), "B").unwrap();

    assert!(a.parent_id.is_none());
    assert_eq!(a.sort_order, 0);
    assert_eq!(
        b.sort_order, 1,
        "second root folder appends after the first"
    );
}

#[test]
fn create_under_parent_sets_parent_and_orders_children() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _key) = setup_vault(dir.path());

    let parent = create_folder(db.connection(), "Parent").unwrap();
    let c1 = create_folder_under(db.connection(), "C1", Some(&parent.id)).unwrap();
    let c2 = create_folder_under(db.connection(), "C2", Some(&parent.id)).unwrap();

    assert_eq!(c1.parent_id.as_deref(), Some(parent.id.as_str()));
    assert_eq!(c2.parent_id.as_deref(), Some(parent.id.as_str()));
    // Children form their own sibling group, independent of root ordering.
    assert_eq!(c1.sort_order, 0);
    assert_eq!(c2.sort_order, 1);
}

#[test]
fn move_reorders_within_the_same_parent() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _key) = setup_vault(dir.path());

    let a = create_folder(db.connection(), "A").unwrap();
    let b = create_folder(db.connection(), "B").unwrap();
    let c = create_folder(db.connection(), "C").unwrap();

    // Move C to the front.
    let moved = move_folder(db.connection(), &c.id, None, 0).unwrap();
    assert_eq!(moved.sort_order, 0);

    // Group is renumbered densely: C(0), A(1), B(2).
    let orders = sort_orders(&db);
    assert_eq!(orders[&c.id], 0);
    assert_eq!(orders[&a.id], 1);
    assert_eq!(orders[&b.id], 2);
}

#[test]
fn move_reparents_into_another_folder() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _key) = setup_vault(dir.path());

    let a = create_folder(db.connection(), "A").unwrap();
    let b = create_folder(db.connection(), "B").unwrap();

    let moved = move_folder(db.connection(), &b.id, Some(&a.id), 0).unwrap();
    assert_eq!(moved.parent_id.as_deref(), Some(a.id.as_str()));
    assert_eq!(moved.sort_order, 0);

    let parents = parents(&db);
    assert_eq!(parents[&b.id].as_deref(), Some(a.id.as_str()));
    assert!(parents[&a.id].is_none());
}

#[test]
fn move_into_self_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _key) = setup_vault(dir.path());

    let a = create_folder(db.connection(), "A").unwrap();
    let result = move_folder(db.connection(), &a.id, Some(&a.id), 0);
    assert!(
        result.is_err(),
        "moving a folder into itself must be rejected"
    );
}

#[test]
fn move_into_own_descendant_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _key) = setup_vault(dir.path());

    let a = create_folder(db.connection(), "A").unwrap();
    let b = create_folder_under(db.connection(), "B", Some(&a.id)).unwrap();

    // A is B's parent; moving A under B would create a cycle.
    let result = move_folder(db.connection(), &a.id, Some(&b.id), 0);
    assert!(
        result.is_err(),
        "moving a folder into its own descendant must be rejected"
    );

    // The tree is unchanged: B still under A, A still at root.
    let parents = parents(&db);
    assert_eq!(parents[&b.id].as_deref(), Some(a.id.as_str()));
    assert!(parents[&a.id].is_none());
}

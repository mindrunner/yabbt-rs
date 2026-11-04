//! Probes pinning the behaviour of the `keepass` crate that the yabbt
//! KeePass backend depends on: KDBX4 saving, id stability across
//! save/reopen, protected fields, attachment persistence, and the
//! recycle-bin metadata. If a crate update breaks one of these, the
//! failure surfaces here instead of deep inside the adapter.

use keepass::config::{DatabaseConfig, KdfConfig};
use keepass::db::Value;
use keepass::{Database, DatabaseKey};
use std::fs;
use std::path::Path;

const PASSWORD: &str = "spike-test-password";

/// Cheap KDF so each save costs milliseconds instead of ~1s of Argon2.
fn cheap_config() -> DatabaseConfig {
    let mut config = DatabaseConfig::default();
    config.kdf_config = KdfConfig::Aes { rounds: 10 };
    config
}

fn key() -> DatabaseKey {
    DatabaseKey::new().with_password(PASSWORD)
}

fn save(db: &Database, path: &Path) {
    let mut file = fs::File::create(path).expect("create kdbx file");
    db.save(&mut file, key()).expect("save kdbx");
}

fn reopen(path: &Path) -> Database {
    let mut file = fs::File::open(path).expect("open kdbx file");
    Database::open(&mut file, key()).expect("reopen kdbx")
}

#[test]
fn kdbx_round_trips_groups_entries_fields_tags_and_ids() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("spike.kdbx");

    let mut db = Database::with_config(cheap_config());
    let mut root = db.root_mut();
    let mut group = root.add_group();
    group.name = "Infrastructure".to_string();
    let group_id = group.as_ref().id();

    let mut entry = group.add_entry();
    entry.set_unprotected("Title", "Example Login");
    entry.set_unprotected("UserName", "admin");
    entry.set_protected("Password", "hunter2");
    entry.set_protected("yabbt.marker", "marker-value");
    entry.tags.push("favorite".to_string());
    let entry_id = entry.as_ref().id();

    save(&db, &path);
    let db = reopen(&path);

    let group = db.group(group_id).expect("group survives reopen by id");
    assert_eq!(group.name, "Infrastructure");

    let entry = db.entry(entry_id).expect("entry survives reopen by id");
    assert_eq!(entry.get_title(), Some("Example Login"));
    assert_eq!(entry.get_username(), Some("admin"));
    assert_eq!(entry.get_password(), Some("hunter2"));
    assert_eq!(entry.get("yabbt.marker"), Some("marker-value"));
    assert!(
        entry
            .fields
            .get("Password")
            .expect("password field")
            .is_protected()
    );
    assert!(
        entry
            .fields
            .get("yabbt.marker")
            .expect("marker field")
            .is_protected()
    );
    assert_eq!(entry.tags, vec!["favorite".to_string()]);
}

#[test]
fn kdbx_attachment_bytes_round_trip_through_save() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("spike.kdbx");

    let mut db = Database::with_config(cheap_config());
    let mut root = db.root_mut();
    let mut entry = root.add_entry();
    entry.set_unprotected("Title", "With Attachment");
    entry.add_attachment("recovery.txt", Value::protected(b"recovery-code".to_vec()));
    let entry_id = entry.as_ref().id();

    save(&db, &path);
    let db = reopen(&path);

    let entry = db.entry(entry_id).expect("entry survives reopen");
    let attachments = entry
        .attachments_named()
        .map(|(name, attachment)| (name.to_string(), attachment.data.get().clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        attachments,
        vec![("recovery.txt".to_string(), b"recovery-code".to_vec())]
    );
}

#[test]
fn kdbx_wrong_password_fails_to_open() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("spike.kdbx");

    let db = Database::with_config(cheap_config());
    save(&db, &path);

    let mut file = fs::File::open(&path).expect("open kdbx file");
    let result = Database::open(
        &mut file,
        DatabaseKey::new().with_password("wrong-password"),
    );
    assert!(result.is_err());
}

#[test]
fn kdbx_recycle_bin_metadata_round_trips() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("spike.kdbx");

    let mut db = Database::with_config(cheap_config());
    let mut root = db.root_mut();
    let mut bin = root.add_group();
    bin.name = "Recycle Bin".to_string();
    let bin_id = bin.as_ref().id();
    db.meta.recyclebin_uuid = Some(bin_id.uuid());

    save(&db, &path);
    let db = reopen(&path);

    let bin = db.recycle_bin().expect("recycle bin recognized");
    assert_eq!(bin.name, "Recycle Bin");
}

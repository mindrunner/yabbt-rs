//! KeePass source adapter tests against real kdbx files in tempdirs.

use keepass::config::{DatabaseConfig, KdfConfig};
use keepass::db::Value as KdbxValue;
use keepass::{Database, DatabaseKey};
use std::fs;
use std::path::Path;
use yabbt::adapters::VaultSource;
use yabbt::adapters::keepass::{KEEPASS_FAVORITE_TAG, KeepassVault, KeepassVaultOptions};
use yabbt::diff::stable_fingerprint;
use yabbt::model::ItemKind;

const PASSWORD: &str = "kdbx-test-password";

fn cheap_config() -> DatabaseConfig {
    let mut config = DatabaseConfig::default();
    config.kdf_config = KdfConfig::Aes { rounds: 10 };
    config
}

fn save(db: &Database, path: &Path) {
    let mut file = fs::File::create(path).expect("create kdbx file");
    db.save(&mut file, DatabaseKey::new().with_password(PASSWORD))
        .expect("save kdbx");
}

fn open_vault(path: &Path) -> KeepassVault {
    KeepassVault::open(KeepassVaultOptions {
        path: path.to_path_buf(),
        passphrase: PASSWORD.to_string(),
        create_if_missing: false,
    })
    .expect("open keepass vault")
}

/// A KeePassXC-style database authored without yabbt: a login entry inside
/// a group (with an attachment and a custom field), and a note in the root.
fn write_foreign_kdbx(path: &Path) -> (String, String, String) {
    let mut db = Database::with_config(cheap_config());

    let mut root = db.root_mut();
    let mut group = root.add_group();
    group.name = "Infrastructure".to_string();
    let group_id = group.as_ref().id().uuid().to_string();

    let mut login = group.add_entry();
    login.set_unprotected("Title", "Example Login");
    login.set_unprotected("UserName", "admin");
    login.set_protected("Password", "hunter2");
    login.set_unprotected("URL", "https://vault.example.test");
    login.set_protected("recovery", "code");
    login.tags.push(KEEPASS_FAVORITE_TAG.to_string());
    login.add_attachment(
        "recovery.txt",
        KdbxValue::protected(b"recovery-code".to_vec()),
    );
    let login_id = login.as_ref().id().uuid().to_string();

    let mut root = db.root_mut();
    let mut note = root.add_entry();
    note.set_unprotected("Title", "Example Note");
    note.set_unprotected("Notes", "note body");
    let note_id = note.as_ref().id().uuid().to_string();

    save(&db, path);
    (group_id, login_id, note_id)
}

#[test]
fn keepass_export_renders_groups_entries_and_attachments() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    let (group_id, login_id, note_id) = write_foreign_kdbx(&path);

    let vault = open_vault(&path);
    let export = vault.export().expect("export keepass vault");

    assert_eq!(export.vault.metadata.source_backend, "keepass");
    assert_eq!(export.vault.folders.len(), 1);
    assert_eq!(export.vault.folders[0].id, group_id);
    assert_eq!(export.vault.folders[0].name, "Infrastructure");

    let login = export
        .vault
        .items
        .iter()
        .find(|item| item.id == login_id)
        .expect("login item rendered");
    assert_eq!(login.name, "Example Login");
    assert_eq!(login.folder_id.as_deref(), Some(group_id.as_str()));
    assert!(login.favorite);
    match &login.kind {
        ItemKind::Login {
            username,
            password,
            uris,
            ..
        } => {
            assert_eq!(username, "admin");
            assert_eq!(password, "hunter2");
            assert_eq!(uris, &vec!["https://vault.example.test".to_string()]);
        }
        other => panic!("expected login kind, got {other:?}"),
    }
    let recovery_field = login
        .fields
        .iter()
        .find(|field| field.name == "recovery")
        .expect("custom field rendered");
    assert_eq!(recovery_field.value, "code");
    assert!(recovery_field.hidden);

    // Attachment metadata and bytes round-trip with the archive path scheme.
    assert_eq!(login.attachments.len(), 1);
    let attachment = &login.attachments[0];
    assert_eq!(attachment.file_name, "recovery.txt");
    assert_eq!(attachment.size, b"recovery-code".len() as u64);
    assert_eq!(attachment.sha256, stable_fingerprint(b"recovery-code"));
    assert_eq!(
        attachment.path,
        format!("attachments/{login_id}/{}.bin", attachment.id)
    );
    assert_eq!(export.attachments.len(), 1);
    assert_eq!(export.attachments[0].path, attachment.path);
    assert_eq!(export.attachments[0].bytes, b"recovery-code");

    let note = export
        .vault
        .items
        .iter()
        .find(|item| item.id == note_id)
        .expect("note item rendered");
    assert_eq!(note.kind, ItemKind::SecureNote);
    assert_eq!(note.notes.as_deref(), Some("note body"));
    assert!(note.folder_id.is_none());
}

#[test]
fn keepass_export_excludes_recycle_bin_entries_and_group() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");

    let mut db = Database::with_config(cheap_config());
    let mut root = db.root_mut();
    let mut bin = root.add_group();
    bin.name = "Recycle Bin".to_string();
    let mut trashed = bin.add_entry();
    trashed.set_unprotected("Title", "Trashed Entry");
    let bin_id = bin.as_ref().id();
    db.meta.recyclebin_uuid = Some(bin_id.uuid());
    let mut root = db.root_mut();
    let mut kept = root.add_entry();
    kept.set_unprotected("Title", "Kept Entry");
    save(&db, &path);

    let vault = open_vault(&path);
    let scanned = vault.scan_vault().expect("scan keepass vault");

    assert!(scanned.folders.is_empty(), "recycle bin is not a folder");
    assert_eq!(scanned.items.len(), 1);
    assert_eq!(scanned.items[0].name, "Kept Entry");
}

#[test]
fn keepass_export_renders_nested_groups_as_slash_joined_folders() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");

    let mut db = Database::with_config(cheap_config());
    let mut root = db.root_mut();
    let mut work = root.add_group();
    work.name = "Work".to_string();
    let work_id = work.as_ref().id().uuid().to_string();
    let mut sub = work.add_group();
    sub.name = "Sub".to_string();
    let sub_id = sub.as_ref().id().uuid().to_string();
    let mut nested = sub.add_entry();
    nested.set_unprotected("Title", "Nested Entry");
    save(&db, &path);

    let scanned = open_vault(&path).scan_vault().expect("scan keepass vault");

    let mut folders = scanned
        .folders
        .iter()
        .map(|folder| (folder.id.clone(), folder.name.clone()))
        .collect::<Vec<_>>();
    folders.sort_by(|left, right| left.1.cmp(&right.1));
    assert_eq!(
        folders,
        vec![
            (work_id, "Work".to_string()),
            (sub_id.clone(), "Work/Sub".to_string())
        ]
    );
    assert_eq!(scanned.items.len(), 1);
    assert_eq!(scanned.items[0].folder_id.as_deref(), Some(sub_id.as_str()));
}

#[test]
fn keepass_export_excludes_entries_and_groups_nested_in_recycle_bin() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");

    let mut db = Database::with_config(cheap_config());
    let mut root = db.root_mut();
    let mut bin = root.add_group();
    bin.name = "Recycle Bin".to_string();
    let bin_id = bin.as_ref().id();
    let mut deleted_group = bin.add_group();
    deleted_group.name = "Deleted Group".to_string();
    let mut trashed = deleted_group.add_entry();
    trashed.set_unprotected("Title", "Trashed In Subgroup");
    trashed.set_protected("Password", "trashed-secret");
    db.meta.recyclebin_uuid = Some(bin_id.uuid());
    let mut root = db.root_mut();
    let mut kept = root.add_entry();
    kept.set_unprotected("Title", "Kept Entry");
    save(&db, &path);

    let scanned = open_vault(&path).scan_vault().expect("scan keepass vault");

    assert!(
        scanned.folders.is_empty(),
        "recycle bin subgroups are not folders: {:?}",
        scanned.folders
    );
    assert_eq!(scanned.items.len(), 1);
    assert_eq!(scanned.items[0].name, "Kept Entry");
}

#[test]
fn keepass_open_missing_file_errors_without_create_flag() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("missing.kdbx");

    let error = KeepassVault::open(KeepassVaultOptions {
        path: path.clone(),
        passphrase: PASSWORD.to_string(),
        create_if_missing: false,
    })
    .expect_err("missing file errors");
    assert!(error.to_string().contains("does not exist"));
    assert!(!path.exists());
}

#[test]
fn keepass_open_wrong_passphrase_errors() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_foreign_kdbx(&path);

    let error = KeepassVault::open(KeepassVaultOptions {
        path,
        passphrase: "wrong".to_string(),
        create_if_missing: false,
    })
    .expect_err("wrong passphrase errors");
    assert!(
        error
            .to_string()
            .contains("failed to open keepass database")
    );
}

#[test]
fn keepass_export_does_not_panic_on_hostile_bitwarden_raw() {
    // A hostile/corrupted kdbx whose `yabbt.bitwarden_raw` claims to be a login
    // (`type:1`) but stores non-object `login`/`uris` values must not panic
    // `render_entry` during export (regression for the serde_json index-assign
    // panic on attacker-controlled nested values).
    for raw in [
        r#"{"type":1,"login":0}"#,
        r#"{"type":1,"login":"oops"}"#,
        r#"{"type":1,"login":{"uris":["x"]}}"#,
        r#"{"type":1,"login":{"uris":42}}"#,
    ] {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("hostile.kdbx");

        let mut db = Database::with_config(cheap_config());
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected("Title", "Hostile");
        entry.set_unprotected("UserName", "victim");
        entry.set_unprotected("URL", "https://example.test");
        entry.set_unprotected("yabbt.bitwarden_raw", raw);
        save(&db, &path);

        let vault = open_vault(&path);
        let export = vault
            .export()
            .expect("export must not panic on hostile raw");
        assert_eq!(export.vault.items.len(), 1, "raw payload `{raw}`");
    }
}

#[test]
fn keepass_create_if_missing_scans_empty_without_touching_disk() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("new.kdbx");

    let vault = KeepassVault::open(KeepassVaultOptions {
        path: path.clone(),
        passphrase: PASSWORD.to_string(),
        create_if_missing: true,
    })
    .expect("open with create_if_missing");
    let scanned = vault.scan_vault().expect("scan empty vault");

    assert!(scanned.items.is_empty());
    assert!(scanned.folders.is_empty());
    assert!(!path.exists(), "no file created without a write");
}

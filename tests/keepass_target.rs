//! Restore-apply behaviour tests against a real KeePass database in a
//! tempdir: full restore, restore-map idempotency, update-existing, prune
//! via the recycle bin, verify-after, and the save-safety machinery.

use keepass::config::{DatabaseConfig, KdfConfig};
use keepass::{Database, DatabaseKey};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use yabbt::adapters::AdapterError;
use yabbt::adapters::keepass::{KeepassVault, KeepassVaultOptions};
use yabbt::archive::{ArchiveAttachment, OpenedArchive};
use yabbt::diff::stable_fingerprint;
use yabbt::model::{
    AttachmentRef, CompletenessReport, Field, Folder, ItemKind, Vault, VaultItem, VaultMetadata,
};
use yabbt::progress::NoopProgress;
use yabbt::restore_apply::{
    ApplyOptions, AttachmentUpload, RestoreError, RestoreOutcome, UploadedAttachment,
    VaultTargetOps, VisibleItem, apply_restore_plan,
};
use yabbt::restore_map::restore_map_state;
use yabbt::restore_plan::{RestorePlanOptions, RestorePlanStatus, plan_restore_with_options};

const PASSWORD: &str = "kdbx-test-password";
const ATTACHMENT_BYTES: &[u8] = b"recovery-code";

fn cheap_config() -> DatabaseConfig {
    let mut config = DatabaseConfig::default();
    config.kdf_config = KdfConfig::Aes { rounds: 10 };
    config
}

fn key() -> DatabaseKey {
    DatabaseKey::new().with_password(PASSWORD)
}

fn save_db(db: &Database, path: &Path) {
    let mut file = fs::File::create(path).expect("create kdbx file");
    db.save(&mut file, key()).expect("save kdbx");
}

fn reopen_db(path: &Path) -> Database {
    let mut file = fs::File::open(path).expect("open kdbx file");
    Database::open(&mut file, key()).expect("reopen kdbx")
}

/// Empty database saved with a cheap KDF, so every adapter save stays fast.
fn write_empty_kdbx(path: &Path) {
    save_db(&Database::with_config(cheap_config()), path);
}

fn open_target(path: &Path) -> KeepassVault {
    KeepassVault::open(KeepassVaultOptions {
        path: path.to_path_buf(),
        passphrase: PASSWORD.to_string(),
        create_if_missing: false,
    })
    .expect("open keepass target")
}

fn archive_vault() -> Vault {
    Vault {
        metadata: VaultMetadata {
            archive_version: 1,
            source_backend: "bw".to_string(),
            source_server: None,
            created_at: "2026-06-01T12:00:00Z".to_string(),
            tool_version: "0.1.0".to_string(),
        },
        folders: vec![Folder {
            id: "source-folder-1".to_string(),
            name: "Infrastructure".to_string(),
        }],
        items: vec![
            VaultItem {
                id: "source-item-1".to_string(),
                kind: ItemKind::Login {
                    username: "admin".to_string(),
                    password: "hunter2".to_string(),
                    uris: vec!["https://vault.example.test".to_string()],
                    totp: None,
                },
                name: "Example Login".to_string(),
                notes: Some("login note".to_string()),
                folder_id: Some("source-folder-1".to_string()),
                favorite: true,
                fields: vec![Field {
                    name: "recovery".to_string(),
                    value: "code".to_string(),
                    hidden: true,
                }],
                attachments: vec![AttachmentRef {
                    id: "source-attachment-1".to_string(),
                    file_name: "recovery.txt".to_string(),
                    size: ATTACHMENT_BYTES.len() as u64,
                    sha256: stable_fingerprint(ATTACHMENT_BYTES),
                    path: "attachments/source-item-1/source-attachment-1.bin".to_string(),
                }],
                backend_metadata: Vec::new(),
            },
            VaultItem {
                id: "source-item-2".to_string(),
                kind: ItemKind::SecureNote,
                name: "Example Note".to_string(),
                notes: Some("note body".to_string()),
                folder_id: None,
                favorite: false,
                fields: Vec::new(),
                attachments: Vec::new(),
                backend_metadata: Vec::new(),
            },
        ],
        report: CompletenessReport {
            complete: true,
            warnings: Vec::new(),
        },
    }
}

fn opened_archive() -> OpenedArchive {
    OpenedArchive {
        vault: archive_vault(),
        attachments: vec![ArchiveAttachment {
            path: "attachments/source-item-1/source-attachment-1.bin".to_string(),
            bytes: ATTACHMENT_BYTES.to_vec(),
        }],
    }
}

fn apply_options() -> ApplyOptions {
    ApplyOptions {
        mark_restored: true,
        restore_map: true,
        update_existing: false,
        verify_after: false,
    }
}

fn apply(target: &KeepassVault, options: ApplyOptions) -> RestoreOutcome {
    apply_with_prune(target, options, false, false)
}

fn apply_with_prune(
    target: &KeepassVault,
    options: ApplyOptions,
    prune: bool,
    prune_permanent: bool,
) -> RestoreOutcome {
    apply_archive(target, &opened_archive(), options, prune, prune_permanent)
}

fn apply_archive(
    target: &KeepassVault,
    opened: &OpenedArchive,
    options: ApplyOptions,
    prune: bool,
    prune_permanent: bool,
) -> RestoreOutcome {
    let target_vault = target.scan_vault().expect("scan keepass target");
    let plan = plan_restore_with_options(
        &opened.vault,
        Some(&target_vault),
        "keepass",
        RestorePlanOptions {
            target_organization_id: None,
            prune,
            prune_permanent,
            ..RestorePlanOptions::default()
        },
    );
    assert_eq!(
        plan.status(),
        RestorePlanStatus::Ready,
        "plan blocked: {:?}",
        plan.blockers
    );
    apply_restore_plan(
        target,
        opened,
        &plan,
        &target_vault,
        None,
        options,
        &NoopProgress,
    )
    .expect("apply restore plan")
}

#[test]
fn restore_into_empty_kdbx_creates_groups_entries_attachments_and_restore_map() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);

    let outcome = apply(&target, apply_options());

    let summary = &outcome.summary;
    assert_eq!(summary.folders_created, 1);
    assert_eq!(summary.items_created, 2);
    assert_eq!(summary.attachments_uploaded, 1);
    assert!(summary.restore_map_updated);

    // Inspect the kdbx FILE through the keepass crate, independent of the
    // adapter: groups, credentials, markers, and attachment bytes persisted.
    let db = reopen_db(&path);
    let root = db.root();
    let group = root
        .groups()
        .find(|group| group.name == "Infrastructure")
        .expect("group created");
    let login = group
        .entries()
        .find(|entry| entry.get_title() == Some("Example Login"))
        .expect("login entry in group");
    assert_eq!(login.get_username(), Some("admin"));
    assert_eq!(login.get_password(), Some("hunter2"));
    assert_eq!(login.get_url(), Some("https://vault.example.test"));
    assert_eq!(login.get("yabbt.source_item_id"), Some("source-item-1"));
    assert_eq!(login.get("recovery"), Some("code"));
    assert!(login.tags.iter().any(|tag| tag == "favorite"));
    let attachments = login
        .attachments_named()
        .map(|(name, attachment)| (name.to_string(), attachment.data.get().clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        attachments,
        vec![("recovery.txt".to_string(), ATTACHMENT_BYTES.to_vec())]
    );

    // The restore map is readable back through the scan path.
    let state = restore_map_state(&target.scan_vault().expect("scan"))
        .expect("restore map parses")
        .expect("restore map present");
    assert_eq!(state.map.entries.len(), 2);
    assert!(state.map.entries.contains_key("source-item-1"));
    assert!(state.map.entries.contains_key("source-item-2"));
}

#[test]
fn restore_again_is_idempotent_via_restore_map_in_kdbx() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);

    let first = apply(&target, apply_options());
    assert_eq!(first.summary.items_created, 2);

    let second = apply(&target, apply_options());
    assert_eq!(second.summary.folders_created, 0);
    assert_eq!(second.summary.items_created, 0);
    assert_eq!(second.summary.items_updated, 0);
    assert_eq!(second.summary.attachments_uploaded, 0);

    // And again through a completely fresh adapter on the saved file.
    let reopened = open_target(&path);
    let third = apply(&reopened, apply_options());
    assert_eq!(third.summary.items_created, 0);
    assert_eq!(third.summary.attachments_uploaded, 0);
}

#[test]
fn update_existing_edits_drifted_kdbx_entry() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);
    apply(&target, apply_options());

    // Drift the note entry as a KeePass user would, outside the adapter.
    let mut db = reopen_db(&path);
    let note_id = db
        .iter_all_entries()
        .find(|entry| entry.get_title() == Some("Example Note"))
        .expect("note entry")
        .id();
    db.entry_mut(note_id)
        .expect("note entry mut")
        .set_unprotected("Notes", "drifted note body");
    save_db(&db, &path);
    target.sync().expect("reload after external edit");

    let without_update = apply(&target, apply_options());
    assert_eq!(without_update.summary.items_updated, 0);

    let with_update = apply(
        &target,
        ApplyOptions {
            update_existing: true,
            ..apply_options()
        },
    );
    assert_eq!(with_update.summary.items_updated, 1);

    let scanned = target.scan_vault().expect("scan");
    let note = scanned
        .items
        .iter()
        .find(|item| item.name == "Example Note")
        .expect("note item");
    assert_eq!(note.notes.as_deref(), Some("note body"));
}

#[test]
fn prune_moves_target_only_entry_to_recycle_bin_and_deletes_extras() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);
    let first = apply(&target, apply_options());
    let login_target_id = first.summary.created_item_ids[0].clone();

    // Seed target-only data as a KeePass user would.
    let mut db = reopen_db(&path);
    let mut root = db.root_mut();
    let mut extra_group = root.add_group();
    extra_group.name = "Target Only Group".to_string();
    let mut extra_entry = root.add_entry();
    extra_entry.set_unprotected("Title", "Target Only Note");
    extra_entry.set_unprotected("Notes", "target only body");
    let extra_entry_id = extra_entry.as_ref().id().uuid().to_string();
    let login_uuid = uuid::Uuid::parse_str(&login_target_id).expect("login uuid");
    db.entry_mut(keepass::db::EntryId::from_uuid(login_uuid))
        .expect("login entry")
        .add_attachment(
            "extra.bin",
            keepass::db::Value::protected(b"target-only-bytes".to_vec()),
        );
    save_db(&db, &path);
    target.sync().expect("reload after seeding");

    let outcome = apply_with_prune(
        &target,
        ApplyOptions {
            verify_after: true,
            ..apply_options()
        },
        true,
        false,
    );

    let summary = &outcome.summary;
    assert_eq!(summary.items_deleted, 1);
    assert_eq!(summary.deleted_item_ids, vec![extra_entry_id.clone()]);
    assert_eq!(summary.attachments_deleted, 1);
    assert_eq!(summary.folders_deleted, 1);

    let verification = outcome.verification.expect("verification ran");
    assert_eq!(verification.deleted_items, 1);
    assert_eq!(verification.deleted_attachments, 1);
    assert_eq!(verification.deleted_folders, 1);

    // The pruned entry sits in the KeePassXC-recognized recycle bin.
    let db = reopen_db(&path);
    let bin = db.recycle_bin().expect("recycle bin exists");
    assert!(
        bin.entries()
            .any(|entry| entry.get_title() == Some("Target Only Note")),
        "pruned entry is in the recycle bin"
    );
    assert!(
        !db.root()
            .groups()
            .any(|group| group.name == "Target Only Group"),
        "target-only group deleted"
    );
    let login = db
        .entry(keepass::db::EntryId::from_uuid(login_uuid))
        .expect("login entry");
    assert!(
        login
            .attachments_named()
            .all(|(name, _)| name != "extra.bin"),
        "target-only attachment deleted"
    );
}

#[test]
fn prune_permanent_removes_entry_from_kdbx_entirely() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);
    apply(&target, apply_options());

    let mut db = reopen_db(&path);
    let mut root = db.root_mut();
    let mut extra_entry = root.add_entry();
    extra_entry.set_unprotected("Title", "Target Only Note");
    let extra_uuid = extra_entry.as_ref().id().uuid();
    save_db(&db, &path);
    target.sync().expect("reload after seeding");

    apply_with_prune(&target, apply_options(), true, true);

    let db = reopen_db(&path);
    assert!(
        db.entry(keepass::db::EntryId::from_uuid(extra_uuid))
            .is_none(),
        "permanently pruned entry is gone"
    );
}

#[test]
fn verify_after_reports_counts_and_survives_disk_reload() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);

    // verify-after calls sync(), which reloads from disk — so passing
    // verification proves the mutations were persisted, not just in memory.
    let outcome = apply(
        &target,
        ApplyOptions {
            verify_after: true,
            ..apply_options()
        },
    );

    let verification = outcome.verification.expect("verification ran");
    assert_eq!(verification.created_items, 2);
    assert_eq!(verification.attachments, 1);
    assert_eq!(verification.deleted_items, 0);
}

#[test]
fn existing_kdbx_gets_one_bak_copy_before_first_write() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");

    // Pre-existing database with user content.
    let mut db = Database::with_config(cheap_config());
    let mut root = db.root_mut();
    let mut existing = root.add_entry();
    existing.set_unprotected("Title", "Pre Existing");
    save_db(&db, &path);

    let target = open_target(&path);
    apply(&target, apply_options());

    let baks = bak_files(temp.path());
    assert_eq!(baks.len(), 1, "one .bak copy created: {baks:?}");
    let bak = reopen_db(&baks[0]);
    assert!(
        bak.iter_all_entries()
            .any(|entry| entry.get_title() == Some("Pre Existing")),
        ".bak holds the pre-write state"
    );
    assert!(
        !bak.iter_all_entries()
            .any(|entry| entry.get_title() == Some("Example Login")),
        ".bak predates yabbt's writes"
    );

    let live = reopen_db(&path);
    assert!(
        live.iter_all_entries()
            .any(|entry| entry.get_title() == Some("Pre Existing")),
        "pre-existing entry survives in the live database"
    );
}

/// Every `vault.kdbx.<timestamp>.bak` copy in `dir`, sorted by name.
fn bak_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut baks = fs::read_dir(dir)
        .expect("read dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            name.starts_with("vault.kdbx.") && name.ends_with(".bak")
        })
        .collect::<Vec<_>>();
    baks.sort();
    baks
}

#[test]
fn later_runs_never_overwrite_an_earlier_bak_copy() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    let mut db = Database::with_config(cheap_config());
    db.root_mut()
        .add_entry()
        .set_unprotected("Title", "Pre Existing");
    save_db(&db, &path);

    // Run 1 restores the archive; run 2 (a fresh process) writes again.
    apply(&open_target(&path), apply_options());
    let second_run = open_target(&path);
    second_run
        .create_folder(&serde_json::json!({ "name": "Run Two" }))
        .expect("second run writes");
    second_run.commit().expect("second run commits");

    let baks = bak_files(temp.path());
    assert_eq!(baks.len(), 2, "one .bak per run: {baks:?}");
    let originals = baks
        .iter()
        .map(|bak| reopen_db(bak))
        .filter(|bak| {
            !bak.iter_all_entries()
                .any(|entry| entry.get_title() == Some("Example Login"))
        })
        .count();
    assert_eq!(originals, 1, "the pre-yabbt original is still kept");
}

#[test]
fn no_stray_temp_files_after_apply() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);

    apply(&target, apply_options());

    let leftovers = fs::read_dir(temp.path())
        .expect("read tempdir")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains("tmp-yabbt"))
        .collect::<Vec<_>>();
    assert!(leftovers.is_empty(), "stray temp files: {leftovers:?}");
}

fn raw_item(id: &str, kind: ItemKind, name: &str, raw: serde_json::Value) -> VaultItem {
    VaultItem {
        id: id.to_string(),
        kind,
        name: name.to_string(),
        notes: None,
        folder_id: None,
        favorite: false,
        fields: vec![Field {
            name: "flag".to_string(),
            value: "true".to_string(),
            hidden: false,
        }],
        attachments: Vec::new(),
        backend_metadata: vec![("bitwarden.raw".to_string(), raw.to_string())],
    }
}

/// Items whose data lives mostly in the raw Bitwarden payload (cards,
/// identities, passkeys, URI match types) must round-trip through a kdbx
/// target without being reported as changed on the next run, while
/// tampering with that raw-only data is still detected.
#[test]
fn raw_only_item_data_round_trips_without_spurious_changes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);

    let mut opened = opened_archive();
    opened.vault.folders.clear();
    opened.attachments.clear();
    opened.vault.items = vec![
        raw_item(
            "card",
            ItemKind::Card,
            "Visa",
            serde_json::json!({
                "id": "card", "type": 3, "name": "Visa", "notes": null, "favorite": false,
                "folderId": null, "organizationId": null, "collectionIds": null,
                "revisionDate": "2026-06-01T12:00:00Z", "reprompt": 1,
                "passwordHistory": null,
                "fields": [{ "name": "flag", "value": "true", "type": 2, "linkedId": null }],
                "card": { "cardholderName": "A", "number": "4111111111111111", "code": "123" },
            }),
        ),
        raw_item(
            "identity",
            ItemKind::Identity,
            "Me",
            serde_json::json!({
                "id": "identity", "type": 4, "name": "Me", "notes": null, "favorite": false,
                "folderId": null, "reprompt": 0,
                "fields": [{ "name": "flag", "value": "true", "type": 0 }],
                "identity": { "firstName": "Ada", "ssn": "000-00-0000", "passportNumber": null },
            }),
        ),
        raw_item(
            "login",
            ItemKind::Login {
                username: "admin".to_string(),
                password: "hunter2".to_string(),
                uris: vec![
                    "https://a.example.test".to_string(),
                    "https://b.example.test".to_string(),
                ],
                totp: None,
            },
            "Login",
            serde_json::json!({
                "id": "login", "type": 1, "name": "Login", "notes": null, "favorite": false,
                "folderId": null, "reprompt": 0,
                "passwordHistory": [{ "password": "old", "lastUsedDate": "2026-01-01T00:00:00Z" }],
                "fields": [{ "name": "flag", "value": "true", "type": 0 }],
                "login": {
                    "username": "admin", "password": "hunter2", "totp": null,
                    "passwordRevisionDate": "2026-01-01T00:00:00Z",
                    "uris": [
                        { "uri": "https://a.example.test", "match": 3 },
                        { "uri": "https://b.example.test", "match": null },
                    ],
                    "fido2Credentials": [{ "credentialId": "cred-1", "rpId": "a.example.test" }],
                },
            }),
        ),
    ];

    let plan_against = |target: &KeepassVault| {
        let target_vault = target.scan_vault().expect("scan keepass target");
        let plan = plan_restore_with_options(
            &opened.vault,
            Some(&target_vault),
            "keepass",
            RestorePlanOptions::default(),
        );
        (target_vault, plan)
    };

    let (target_vault, plan) = plan_against(&target);
    assert_eq!(plan.items_to_create, 3);
    apply_restore_plan(
        &target,
        &opened,
        &plan,
        &target_vault,
        None,
        apply_options(),
        &NoopProgress,
    )
    .expect("apply");

    let (_, plan) = plan_against(&open_target(&path));
    assert!(
        plan.update_item_ids.is_empty(),
        "spurious updates: {:?}",
        plan.update_item_ids
    );
    assert!(plan.create_item_ids.is_empty());
    assert_eq!(plan.items_unchanged, 3);

    // Tampering with raw-only data inside the kdbx is detected.
    let mut db = reopen_db(&path);
    let card_id = db
        .iter_all_entries()
        .find(|entry| entry.get_title() == Some("Visa"))
        .expect("card entry")
        .id();
    let raw = db
        .entry(card_id)
        .expect("card")
        .get("yabbt.bitwarden_raw")
        .expect("raw field")
        .replace("4111111111111111", "5500000000000004");
    db.entry_mut(card_id)
        .expect("card mut")
        .set_protected("yabbt.bitwarden_raw", raw);
    save_db(&db, &path);
    let (_, plan) = plan_against(&open_target(&path));
    assert_eq!(plan.update_item_ids, vec!["card".to_string()]);
}

/// Seed a kdbx with three root entries, each holding one distinct attachment.
/// Returns the entry uuids in order A, B, C.
fn seed_three_entries_with_attachments(path: &Path) -> Vec<uuid::Uuid> {
    let mut db = Database::with_config(cheap_config());
    let mut ids = Vec::new();
    for (title, bytes) in [("A", b"bytes-a"), ("B", b"bytes-b"), ("C", b"bytes-c")] {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected("Title", title);
        entry.add_attachment(
            format!("{title}.bin"),
            keepass::db::Value::protected(bytes.to_vec()),
        );
        ids.push(entry.as_ref().id().uuid());
    }
    save_db(&db, path);
    ids
}

fn attachments_on_disk(path: &Path, uuid: uuid::Uuid) -> Vec<(String, Vec<u8>)> {
    let db = reopen_db(path);
    let entry = db
        .entry(keepass::db::EntryId::from_uuid(uuid))
        .expect("entry present");
    let mut attachments = entry
        .attachments_named()
        .map(|(name, attachment)| (name.to_string(), attachment.data.get().clone()))
        .collect::<Vec<_>>();
    attachments.sort();
    attachments
}

#[test]
fn deleting_one_attachment_keeps_other_entries_attachments_intact_on_disk() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    let ids = seed_three_entries_with_attachments(&path);
    let target = open_target(&path);

    let a_id = ids[0].to_string();
    let a_attachment = target
        .list_visible_items()
        .expect("list items")
        .into_iter()
        .find(|item| item.id == a_id)
        .expect("entry A visible")
        .attachment_ids[0]
        .clone();
    target
        .delete_attachment(&a_id, &a_attachment)
        .expect("delete A's attachment");
    target.commit().expect("commit");

    assert_eq!(attachments_on_disk(&path, ids[0]), vec![]);
    assert_eq!(
        attachments_on_disk(&path, ids[1]),
        vec![("B.bin".to_string(), b"bytes-b".to_vec())]
    );
    assert_eq!(
        attachments_on_disk(&path, ids[2]),
        vec![("C.bin".to_string(), b"bytes-c".to_vec())]
    );
}

#[test]
fn deleting_attachments_repeatedly_keeps_every_survivor_intact_across_reopens() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    let ids = seed_three_entries_with_attachments(&path);

    // Delete B's attachment, then reopen and delete A's: each step must leave
    // the remaining attachments on the right entries.
    for (deleted, survivors) in [(1usize, vec![0usize, 2]), (0, vec![2])] {
        let target = open_target(&path);
        let entry_id = ids[deleted].to_string();
        let attachment_id = target
            .list_visible_items()
            .expect("list items")
            .into_iter()
            .find(|item| item.id == entry_id)
            .expect("entry visible")
            .attachment_ids[0]
            .clone();
        target
            .delete_attachment(&entry_id, &attachment_id)
            .expect("delete attachment");
        target.commit().expect("commit");
        for survivor in survivors {
            let title = ["A", "B", "C"][survivor];
            assert_eq!(
                attachments_on_disk(&path, ids[survivor]),
                vec![(
                    format!("{title}.bin"),
                    format!("bytes-{}", title.to_lowercase()).into_bytes()
                )],
                "entry {title} after deleting entry {deleted}'s attachment"
            );
        }
    }
}

#[test]
fn removing_an_attachment_shared_with_entry_history_fails_closed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    let mut db = Database::with_config(cheap_config());
    let entry_uuid = {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected("Title", "With History");
        entry.add_attachment(
            "doc.bin",
            keepass::db::Value::protected(b"doc-bytes".to_vec()),
        );
        // KeePassXC-style edit: the previous version, including its
        // reference to the same binary, moves into the entry's history.
        entry.edit_tracking(|tracked| tracked.set_unprotected("Notes", "edited"));
        entry.as_ref().id().uuid()
    };
    save_db(&db, &path);
    let before = fs::read(&path).expect("read kdbx");

    let target = open_target(&path);
    let entry_id = entry_uuid.to_string();
    let attachment_id = target
        .list_visible_items()
        .expect("list items")
        .into_iter()
        .find(|item| item.id == entry_id)
        .expect("entry visible")
        .attachment_ids[0]
        .clone();
    let error = target
        .delete_attachment(&entry_id, &attachment_id)
        .expect_err("removing a history-shared binary must fail closed");
    assert!(
        error.to_string().contains("history"),
        "error names the cause: {error}"
    );
    assert_eq!(
        fs::read(&path).expect("read kdbx"),
        before,
        "file untouched"
    );
    // The in-memory database still holds the attachment.
    assert_eq!(
        target
            .download_attachment(&entry_id, &attachment_id)
            .expect("attachment still present"),
        b"doc-bytes".to_vec()
    );
}

#[test]
fn permanently_deleting_an_entry_keeps_other_entries_attachments_intact_on_disk() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    let ids = seed_three_entries_with_attachments(&path);
    let target = open_target(&path);

    target
        .delete_item(&ids[0].to_string(), true)
        .expect("permanently delete A");
    target.commit().expect("commit");

    assert_eq!(
        attachments_on_disk(&path, ids[1]),
        vec![("B.bin".to_string(), b"bytes-b".to_vec())]
    );
    assert_eq!(
        attachments_on_disk(&path, ids[2]),
        vec![("C.bin".to_string(), b"bytes-c".to_vec())]
    );
}

#[test]
fn prune_keeps_matched_entry_moved_into_a_nested_target_group() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);
    apply(&target, apply_options());

    // As a KeePassXC user: file the restored note under Personal/Sub.
    let mut db = reopen_db(&path);
    let note_id = db
        .iter_all_entries()
        .find(|entry| entry.get_title() == Some("Example Note"))
        .expect("note entry")
        .id();
    let sub_id = {
        let mut root = db.root_mut();
        let mut personal = root.add_group();
        personal.name = "Personal".to_string();
        let mut sub = personal.add_group();
        sub.name = "Sub".to_string();
        sub.as_ref().id()
    };
    db.entry_mut(note_id)
        .expect("note entry mut")
        .move_to(sub_id)
        .expect("move note");
    save_db(&db, &path);
    target.sync().expect("reload after external edit");

    let outcome = apply_with_prune(&target, apply_options(), true, false);
    assert_eq!(outcome.summary.items_deleted, 0);
    assert_eq!(outcome.summary.folders_deleted, 0);

    let db = reopen_db(&path);
    let root = db.root();
    let sub = root
        .group_by_path(&["Personal", "Sub"])
        .expect("nested group survives prune");
    assert!(
        sub.entries()
            .any(|entry| entry.get_title() == Some("Example Note")),
        "matched entry survives in its nested group"
    );
}

#[test]
fn prune_moves_entries_from_target_only_nested_groups_to_recycle_bin() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);
    apply(&target, apply_options());

    let mut db = reopen_db(&path);
    {
        let mut root = db.root_mut();
        let mut other = root.add_group();
        other.name = "Other".to_string();
        let mut deep = other.add_group();
        deep.name = "Deep".to_string();
        let mut entry = deep.add_entry();
        entry.set_unprotected("Title", "Deep Note");
    }
    save_db(&db, &path);
    target.sync().expect("reload after seeding");

    let outcome = apply_with_prune(
        &target,
        ApplyOptions {
            verify_after: true,
            ..apply_options()
        },
        true,
        false,
    );
    assert_eq!(outcome.summary.items_deleted, 1);
    assert_eq!(outcome.summary.folders_deleted, 2);

    let db = reopen_db(&path);
    let bin = db.recycle_bin().expect("recycle bin exists");
    assert!(
        bin.entries()
            .any(|entry| entry.get_title() == Some("Deep Note")),
        "target-only nested entry is recoverable from the recycle bin"
    );
    assert!(db.root().group_by_name("Other").is_none());
}

#[test]
fn delete_folder_refuses_groups_with_entries_or_subgroups() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    let mut db = Database::with_config(cheap_config());
    let (holder_id, parent_id) = {
        let mut root = db.root_mut();
        let mut holder = root.add_group();
        holder.name = "Holder".to_string();
        holder.add_entry().set_unprotected("Title", "Inside");
        let holder_id = holder.as_ref().id().uuid().to_string();
        let mut root = db.root_mut();
        let mut parent = root.add_group();
        parent.name = "Parent".to_string();
        parent.add_group().name = "Child".to_string();
        (holder_id, parent.as_ref().id().uuid().to_string())
    };
    save_db(&db, &path);
    let target = open_target(&path);

    target
        .delete_folder(&holder_id)
        .expect_err("group with an entry is not deleted");
    target
        .delete_folder(&parent_id)
        .expect_err("group with a subgroup is not deleted");

    let db = reopen_db(&path);
    let root = db.root();
    let holder = root.group_by_name("Holder").expect("holder kept");
    assert!(
        holder
            .entries()
            .any(|entry| entry.get_title() == Some("Inside"))
    );
    assert!(db.root().group_by_path(&["Parent", "Child"]).is_some());
}

#[test]
fn restore_creates_nested_groups_for_slash_separated_folder_names() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);

    // Bitwarden names nested folders "Parent/Child"; the child comes first
    // here so the parent group is created implicitly, then reused.
    let mut opened = opened_archive();
    opened.vault.folders[0].name = "Work/Sub".to_string();
    opened.vault.folders.push(Folder {
        id: "source-folder-parent".to_string(),
        name: "Work".to_string(),
    });

    let first = apply_archive(&target, &opened, apply_options(), false, false);
    assert_eq!(first.summary.folders_created, 2);

    let db = reopen_db(&path);
    assert_eq!(
        db.root()
            .groups()
            .filter(|group| group.name == "Work")
            .count(),
        1,
        "one Work group"
    );
    let root = db.root();
    let sub = root
        .group_by_path(&["Work", "Sub"])
        .expect("nested group created");
    assert!(
        sub.entries()
            .any(|entry| entry.get_title() == Some("Example Login"))
    );

    // A pruning re-run matches both folders and changes nothing.
    let second = apply_archive(&target, &opened, apply_options(), true, false);
    assert_eq!(second.summary.folders_created, 0);
    assert_eq!(second.summary.folders_deleted, 0);
    assert_eq!(second.summary.items_created, 0);
    assert_eq!(second.summary.items_deleted, 0);
}

#[test]
fn restore_keeps_both_attachments_with_the_same_file_name() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);

    let second_bytes = b"second-recovery-code".to_vec();
    let mut opened = opened_archive();
    opened.vault.items[0].attachments.push(AttachmentRef {
        id: "source-attachment-2".to_string(),
        file_name: "recovery.txt".to_string(),
        size: second_bytes.len() as u64,
        sha256: stable_fingerprint(&second_bytes),
        path: "attachments/source-item-1/source-attachment-2.bin".to_string(),
    });
    opened.attachments.push(ArchiveAttachment {
        path: "attachments/source-item-1/source-attachment-2.bin".to_string(),
        bytes: second_bytes.clone(),
    });

    let first = apply_archive(
        &target,
        &opened,
        ApplyOptions {
            verify_after: true,
            ..apply_options()
        },
        false,
        false,
    );
    assert_eq!(first.summary.attachments_uploaded, 2);
    assert_eq!(first.verification.expect("verification ran").attachments, 2);

    let db = reopen_db(&path);
    let login = db
        .iter_all_entries()
        .find(|entry| entry.get_title() == Some("Example Login"))
        .expect("login entry");
    let mut attachments = login
        .attachments_named()
        .map(|(name, attachment)| (name.to_string(), attachment.data.get().clone()))
        .collect::<Vec<_>>();
    attachments.sort();
    assert_eq!(
        attachments,
        vec![
            ("recovery (2).txt".to_string(), second_bytes),
            ("recovery.txt".to_string(), ATTACHMENT_BYTES.to_vec()),
        ]
    );

    // A pruning re-run recognizes both by content: nothing uploaded or deleted.
    let second = apply_archive(&target, &opened, apply_options(), true, false);
    assert_eq!(second.summary.attachments_uploaded, 0);
    assert_eq!(second.summary.attachments_deleted, 0);
}

#[test]
fn uploading_an_attachment_never_replaces_an_existing_one_with_the_same_name() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    let mut db = Database::with_config(cheap_config());
    let entry_id = {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected("Title", "User Entry");
        entry.add_attachment(
            "notes.txt",
            keepass::db::Value::protected(b"user-notes".to_vec()),
        );
        entry.as_ref().id().uuid().to_string()
    };
    save_db(&db, &path);
    let target = open_target(&path);

    let archive_bytes = b"archive-notes".to_vec();
    let uploaded = target
        .upload_attachments(
            &[yabbt::restore_apply::AttachmentUpload {
                target_item_id: entry_id.clone(),
                file_name: "notes.txt".to_string(),
                bytes: archive_bytes.clone(),
                size: archive_bytes.len() as u64,
                sha256: stable_fingerprint(&archive_bytes),
            }],
            &NoopProgress,
            1,
        )
        .expect("upload attachment");
    assert_eq!(uploaded.len(), 1);
    assert_eq!(uploaded[0].file_name, "notes (2).txt");

    target.commit().expect("commit");
    let uuid = uuid::Uuid::parse_str(&entry_id).expect("uuid");
    assert_eq!(
        attachments_on_disk(&path, uuid),
        vec![
            ("notes (2).txt".to_string(), archive_bytes),
            ("notes.txt".to_string(), b"user-notes".to_vec()),
        ]
    );
}

// ------------------------------------------------- attachment identity (N1)

/// Two root entries L < H (uuid order). L holds x (pool slot 0); H holds p
/// (slot 1) and q (slot 2). Returns (L uuid, H uuid).
fn seed_low_high_pool(path: &Path) -> (String, String) {
    let mut db = Database::with_config(cheap_config());
    let mut ids = Vec::new();
    for title in ["E1", "E2"] {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected("Title", title);
        ids.push(entry.as_ref().id());
    }
    ids.sort_by_key(|id| id.uuid().to_string());
    let (low, high) = (ids[0], ids[1]);
    db.entry_mut(low).unwrap().set_unprotected("Title", "L");
    db.entry_mut(high).unwrap().set_unprotected("Title", "H");
    db.entry_mut(low)
        .unwrap()
        .add_attachment("x.bin", keepass::db::Value::protected(b"x-bytes".to_vec()));
    db.entry_mut(high)
        .unwrap()
        .add_attachment("p.bin", keepass::db::Value::protected(b"p-bytes".to_vec()));
    db.entry_mut(high)
        .unwrap()
        .add_attachment("q.bin", keepass::db::Value::protected(b"q-bytes".to_vec()));
    save_db(&db, path);
    (low.uuid().to_string(), high.uuid().to_string())
}

fn note_item(id: &str, title: &str, attachments: Vec<AttachmentRef>) -> VaultItem {
    VaultItem {
        id: id.to_string(),
        kind: ItemKind::SecureNote,
        name: title.to_string(),
        notes: None,
        folder_id: None,
        favorite: false,
        fields: Vec::new(),
        attachments,
        backend_metadata: Vec::new(),
    }
}

fn archived_attachment(
    item: &str,
    n: usize,
    name: &str,
    bytes: &[u8],
) -> (AttachmentRef, ArchiveAttachment) {
    let path = format!("attachments/{item}/{n}.bin");
    (
        AttachmentRef {
            id: format!("{item}-att-{n}"),
            file_name: name.to_string(),
            size: bytes.len() as u64,
            sha256: stable_fingerprint(bytes),
            path: path.clone(),
        },
        ArchiveAttachment {
            path,
            bytes: bytes.to_vec(),
        },
    )
}

fn archive_of(items: Vec<VaultItem>, attachments: Vec<ArchiveAttachment>) -> OpenedArchive {
    let mut vault = archive_vault();
    vault.folders.clear();
    vault.items = items;
    OpenedArchive { vault, attachments }
}

fn titled_attachments_on_disk(path: &Path, title: &str) -> Vec<(String, Vec<u8>)> {
    let db = reopen_db(path);
    let entry = db
        .iter_all_entries()
        .find(|entry| entry.get_title() == Some(title))
        .expect("entry present");
    let mut attachments = entry
        .attachments_named()
        .map(|(name, attachment)| (name.to_string(), attachment.data.get().clone()))
        .collect::<Vec<_>>();
    attachments.sort();
    attachments
}

fn no_markers() -> ApplyOptions {
    ApplyOptions {
        mark_restored: false,
        restore_map: false,
        update_existing: false,
        verify_after: true,
    }
}

/// The plan records attachment deletes at scan time; deleting the first one
/// must not make a later planned delete hit a different (kept) attachment.
#[test]
fn prune_deletes_exactly_the_planned_attachments_across_entries() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    let (low, high) = seed_low_high_pool(&path);
    let target = open_target(&path);

    let (q_ref, q_payload) = archived_attachment(&high, 1, "q.bin", b"q-bytes");
    let opened = archive_of(
        vec![
            note_item(&low, "L", vec![]),
            note_item(&high, "H", vec![q_ref]),
        ],
        vec![q_payload],
    );
    let outcome = apply_archive(&target, &opened, no_markers(), true, false);
    assert_eq!(outcome.summary.attachments_deleted, 2);
    assert_eq!(titled_attachments_on_disk(&path, "L"), vec![]);
    assert_eq!(
        titled_attachments_on_disk(&path, "H"),
        vec![("q.bin".to_string(), b"q-bytes".to_vec())],
        "q is kept by the archive, p is pruned"
    );
}

/// Pruning a non-last pool slot renumbers the pool; verify-after must not
/// mistake a surviving attachment for the deleted one.
#[test]
fn verify_after_passes_after_pruning_a_non_last_pool_slot() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    let (low, high) = seed_low_high_pool(&path);
    let target = open_target(&path);

    let (p_ref, p_payload) = archived_attachment(&high, 1, "p.bin", b"p-bytes");
    let (q_ref, q_payload) = archived_attachment(&high, 2, "q.bin", b"q-bytes");
    let opened = archive_of(
        vec![
            note_item(&low, "L", vec![]),
            note_item(&high, "H", vec![p_ref, q_ref]),
        ],
        vec![p_payload, q_payload],
    );
    let outcome = apply_archive(&target, &opened, no_markers(), true, false);
    assert_eq!(outcome.summary.attachments_deleted, 1);
    assert_eq!(
        outcome
            .verification
            .expect("verification ran")
            .deleted_attachments,
        1
    );
    assert_eq!(titled_attachments_on_disk(&path, "L"), vec![]);
    assert_eq!(
        titled_attachments_on_disk(&path, "H"),
        vec![
            ("p.bin".to_string(), b"p-bytes".to_vec()),
            ("q.bin".to_string(), b"q-bytes".to_vec()),
        ]
    );
}

#[test]
fn attachment_ids_are_stable_across_pool_renumbering_and_reopens() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    let (low, high) = seed_low_high_pool(&path);
    let target = open_target(&path);
    let ids_of = |target: &KeepassVault, entry: &str| {
        let mut ids = target
            .list_visible_items()
            .expect("list items")
            .into_iter()
            .find(|item| item.id == entry)
            .expect("entry visible")
            .attachment_ids;
        ids.sort();
        ids
    };
    let high_before = ids_of(&target, &high);
    assert_eq!(high_before.len(), 2);
    let x_id = ids_of(&target, &low)[0].clone();
    assert!(
        !high_before.contains(&x_id),
        "attachment ids are unique across entries"
    );

    target.delete_attachment(&low, &x_id).expect("delete x");
    target.commit().expect("commit");
    assert_eq!(
        ids_of(&target, &high),
        high_before,
        "same ids after removal"
    );
    assert_eq!(
        ids_of(&open_target(&path), &high),
        high_before,
        "same ids after reopen"
    );
    // Deleting an id that no longer exists fails instead of hitting another.
    target
        .delete_attachment(&low, &x_id)
        .expect_err("x is already gone");
}

// ------------------------------------------- attachment content change (N2)

#[test]
fn changed_attachment_content_replaces_the_old_version_with_update_existing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);

    let (r1, p1) = archived_attachment("a", 1, "doc.txt", b"version-1");
    let v1 = archive_of(vec![note_item("a", "Note a", vec![r1])], vec![p1]);
    apply_archive(&target, &v1, apply_options(), false, false);

    let (r2, p2) = archived_attachment("a", 1, "doc.txt", b"version-2");
    let v2 = archive_of(vec![note_item("a", "Note a", vec![r2])], vec![p2]);

    // Without --update-existing the changed item is reported but left alone:
    // prune must not delete the old version when the new one is not uploaded.
    let without_update = apply_archive(&target, &v2, apply_options(), true, false);
    assert_eq!(without_update.summary.attachments_uploaded, 0);
    assert_eq!(without_update.summary.attachments_deleted, 0);
    assert_eq!(
        titled_attachments_on_disk(&path, "Note a"),
        vec![("doc.txt".to_string(), b"version-1".to_vec())]
    );

    let with_update = apply_archive(
        &target,
        &v2,
        ApplyOptions {
            update_existing: true,
            verify_after: true,
            ..apply_options()
        },
        true,
        false,
    );
    assert_eq!(with_update.summary.items_updated, 1);
    assert_eq!(with_update.summary.attachments_uploaded, 1);
    assert_eq!(with_update.summary.attachments_deleted, 1);
    assert!(with_update.verification.is_some());
    // The new content keeps the original name (the old version is removed
    // first; both happen in the same save).
    assert_eq!(
        titled_attachments_on_disk(&path, "Note a"),
        vec![("doc.txt".to_string(), b"version-2".to_vec())]
    );

    // Converged: the next run plans nothing.
    let target_vault = target.scan_vault().expect("scan");
    let plan = plan_restore_with_options(
        &v2.vault,
        Some(&target_vault),
        "keepass",
        RestorePlanOptions {
            prune: true,
            ..RestorePlanOptions::default()
        },
    );
    assert!(
        plan.update_item_ids.is_empty(),
        "{:?}",
        plan.update_item_ids
    );
    assert_eq!(plan.attachments_to_upload, 0);
    assert_eq!(plan.attachments_to_delete, 0);
}

/// `--update-existing` without `--prune` keeps the old version next to the
/// changed one; after that the item is converged instead of being planned
/// (and saved) as an update on every run.
#[test]
fn changed_attachment_with_update_but_no_prune_converges() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);
    let (r1, p1) = archived_attachment("a", 1, "doc.txt", b"version-1");
    let v1 = archive_of(vec![note_item("a", "Note a", vec![r1])], vec![p1]);
    apply_archive(&target, &v1, apply_options(), false, false);
    let (r2, p2) = archived_attachment("a", 1, "doc.txt", b"version-2");
    let v2 = archive_of(vec![note_item("a", "Note a", vec![r2])], vec![p2]);
    let update = ApplyOptions {
        update_existing: true,
        ..apply_options()
    };

    let first = apply_archive(&target, &v2, update, false, false);
    assert_eq!(first.summary.items_updated, 1);
    assert_eq!(
        titled_attachments_on_disk(&path, "Note a"),
        vec![
            ("doc (2).txt".to_string(), b"version-2".to_vec()),
            ("doc.txt".to_string(), b"version-1".to_vec()),
        ],
        "without --prune both versions are kept"
    );
    let saves = target.saves_written();
    for run in 0..3 {
        let outcome = apply_archive(&target, &v2, update, false, false);
        assert_eq!(outcome.summary.items_updated, 0, "run {run}");
        assert!(!outcome.summary.has_mutations(), "run {run}");
    }
    assert_eq!(target.saves_written(), saves, "converged runs do not save");

    // A later --prune removes the old version without another update.
    let pruned = apply_archive(&target, &v2, update, true, false);
    assert_eq!(pruned.summary.items_updated, 0);
    assert_eq!(pruned.summary.attachments_deleted, 1);
    assert_eq!(
        titled_attachments_on_disk(&path, "Note a"),
        vec![("doc (2).txt".to_string(), b"version-2".to_vec())]
    );
}

/// Delegates to a KeePass target but fails every attachment upload.
struct FailingUploads<'a>(&'a KeepassVault);

impl VaultTargetOps for FailingUploads<'_> {
    fn create_folder(&self, payload: &serde_json::Value) -> Result<String, AdapterError> {
        self.0.create_folder(payload)
    }
    fn create_item(&self, payload: &serde_json::Value) -> Result<String, AdapterError> {
        self.0.create_item(payload)
    }
    fn edit_item(&self, item_id: &str, payload: &serde_json::Value) -> Result<(), AdapterError> {
        self.0.edit_item(item_id, payload)
    }
    fn upload_attachments(
        &self,
        jobs: &[AttachmentUpload],
        _progress: &dyn yabbt::progress::ProgressReporter,
        _total: u64,
    ) -> Result<Vec<UploadedAttachment>, AdapterError> {
        if jobs.is_empty() {
            return Ok(Vec::new());
        }
        Err(AdapterError::new("injected upload failure"))
    }
    fn delete_attachment(&self, item_id: &str, attachment_id: &str) -> Result<(), AdapterError> {
        self.0.delete_attachment(item_id, attachment_id)
    }
    fn delete_item(&self, item_id: &str, permanent: bool) -> Result<(), AdapterError> {
        self.0.delete_item(item_id, permanent)
    }
    fn delete_folder(&self, folder_id: &str) -> Result<(), AdapterError> {
        self.0.delete_folder(folder_id)
    }
    fn sync(&self) -> Result<(), AdapterError> {
        self.0.sync()
    }
    fn get_item(&self, item_id: &str) -> Result<String, AdapterError> {
        self.0.get_item(item_id)
    }
    fn download_attachment(
        &self,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<Vec<u8>, AdapterError> {
        self.0.download_attachment(item_id, attachment_id)
    }
    fn list_visible_items(&self) -> Result<Vec<VisibleItem>, AdapterError> {
        self.0.list_visible_items()
    }
    fn list_folder_ids(&self) -> Result<Vec<String>, AdapterError> {
        self.0.list_folder_ids()
    }
    fn commit(&self) -> Result<(), AdapterError> {
        self.0.commit()
    }
    fn batches_writes(&self) -> bool {
        self.0.batches_writes()
    }
    fn discard(&self) {
        self.0.discard()
    }
}

/// The old version of a replaced attachment is removed before its successor
/// is uploaded, so a failing upload must not let the apply save the removal:
/// the database never ends up with neither version.
#[test]
fn failed_upload_after_replacing_an_attachment_saves_nothing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);
    let (r1, p1) = archived_attachment("a", 1, "doc.txt", b"version-1");
    let v1 = archive_of(vec![note_item("a", "Note a", vec![r1])], vec![p1]);
    apply_archive(&target, &v1, apply_options(), false, false);
    let before = fs::read(&path).expect("read kdbx");
    let saves = target.saves_written();

    let (r2, p2) = archived_attachment("a", 1, "doc.txt", b"version-2");
    let mut v2 = archive_of(vec![note_item("a", "Note a", vec![r2])], vec![p2]);
    // Also a new item, created before the uploads.
    v2.vault.items.push(note_item("b", "Note b", vec![]));
    let target_vault = target.scan_vault().expect("scan");
    let plan = plan_restore_with_options(
        &v2.vault,
        Some(&target_vault),
        "keepass",
        RestorePlanOptions {
            prune: true,
            ..RestorePlanOptions::default()
        },
    );
    assert!(plan.delete_attachments[0].requires_item_update, "{plan:?}");
    let error = apply_restore_plan(
        &FailingUploads(&target),
        &v2,
        &plan,
        &target_vault,
        None,
        ApplyOptions {
            update_existing: true,
            ..apply_options()
        },
        &NoopProgress,
    )
    .expect_err("upload fails");
    match error {
        RestoreError::Apply { summary, error } => {
            assert!(!summary.has_mutations(), "{summary:?}");
            assert!(!summary.restore_map_updated);
            let message = error.to_string();
            assert!(message.contains("injected upload failure"), "{message}");
            assert!(message.contains("nothing"), "{message}");
        }
        other => panic!("expected apply error, got {other:?}"),
    }
    assert_eq!(fs::read(&path).expect("read kdbx"), before, "nothing saved");
    assert_eq!(target.saves_written(), saves);
    assert_eq!(
        titled_attachments_on_disk(&path, "Note a"),
        vec![("doc.txt".to_string(), b"version-1".to_vec())]
    );
    // Memory was reset to the file as well.
    let rescanned = target.scan_vault().expect("scan");
    assert!(!rescanned.items.iter().any(|item| item.name == "Note b"));
}

/// A replacement delete that fails after an earlier one already removed an
/// old version (before its successor was uploaded) must not let the apply
/// save that removal either.
#[test]
fn failed_replacement_after_an_earlier_one_saves_nothing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);
    let (a1, pa1) = archived_attachment("a", 1, "a.txt", b"a-version-1");
    let (b1, pb1) = archived_attachment("a", 2, "b.txt", b"b-version-1");
    let v1 = archive_of(vec![note_item("a", "Note a", vec![a1, b1])], vec![pa1, pb1]);
    apply_archive(&target, &v1, apply_options(), false, false);
    let before = fs::read(&path).expect("read kdbx");

    let (a2, pa2) = archived_attachment("a", 1, "a.txt", b"a-version-2");
    let (b2, pb2) = archived_attachment("a", 2, "b.txt", b"b-version-2");
    let v2 = archive_of(vec![note_item("a", "Note a", vec![a2, b2])], vec![pa2, pb2]);
    let target_vault = target.scan_vault().expect("scan");
    let plan = plan_restore_with_options(
        &v2.vault,
        Some(&target_vault),
        "keepass",
        RestorePlanOptions {
            prune: true,
            ..RestorePlanOptions::default()
        },
    );
    assert_eq!(plan.delete_attachments.len(), 2, "{plan:?}");
    // The second planned delete will fail: its attachment is already gone.
    let second = &plan.delete_attachments[1];
    target
        .delete_attachment(&second.target_item_id, &second.attachment_id)
        .expect("remove ahead of the apply");

    let error = apply_restore_plan(
        &target,
        &v2,
        &plan,
        &target_vault,
        None,
        ApplyOptions {
            update_existing: true,
            ..apply_options()
        },
        &NoopProgress,
    )
    .expect_err("second replacement fails");
    match error {
        RestoreError::Apply { summary, error } => {
            assert!(!summary.has_mutations(), "{summary:?}");
            assert!(error.to_string().contains("nothing was saved"), "{error}");
        }
        other => panic!("expected apply error, got {other:?}"),
    }
    assert_eq!(fs::read(&path).expect("read kdbx"), before, "nothing saved");
}

// --------------------------------- duplicate attachment names converge (N5)

#[test]
fn renamed_duplicate_attachments_are_not_reported_as_changed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);

    let (r1, p1) = archived_attachment("a", 1, "x.txt", b"one");
    let (r2, p2) = archived_attachment("a", 2, "x.txt", b"two");
    let opened = archive_of(vec![note_item("a", "Note a", vec![r1, r2])], vec![p1, p2]);
    apply_archive(&target, &opened, apply_options(), false, false);

    for run in 0..2 {
        let outcome = apply_archive(
            &target,
            &opened,
            ApplyOptions {
                update_existing: true,
                ..apply_options()
            },
            true,
            false,
        );
        assert_eq!(outcome.summary.items_updated, 0, "run {run}");
        assert_eq!(outcome.summary.attachments_uploaded, 0, "run {run}");
        assert_eq!(outcome.summary.attachments_deleted, 0, "run {run}");
    }
}

// ------------------------------------------ history-pinned pool slots (N4)

/// A has a.bin (slot 0); B has b.bin (slot 1) and a KeePassXC-style history
/// version that shares slot 1. Returns (A uuid, B uuid).
fn seed_history_pinned_last_slot(path: &Path) -> (uuid::Uuid, uuid::Uuid) {
    let mut db = Database::with_config(cheap_config());
    let a = {
        let mut root = db.root_mut();
        let mut a = root.add_entry();
        a.set_unprotected("Title", "A");
        a.add_attachment("a.bin", keepass::db::Value::protected(b"a".to_vec()));
        a.as_ref().id().uuid()
    };
    let b = {
        let mut root = db.root_mut();
        let mut b = root.add_entry();
        b.set_unprotected("Title", "B");
        b.add_attachment("b.bin", keepass::db::Value::protected(b"b".to_vec()));
        b.edit_tracking(|tracked| tracked.set_unprotected("Notes", "edited once in KeePassXC"));
        b.as_ref().id().uuid()
    };
    save_db(&db, path);
    (a, b)
}

/// Every version of `uuid` (current first, then history) as sorted
/// `(name, bytes)` lists, read from the file.
fn all_versions_on_disk(path: &Path, uuid: uuid::Uuid) -> Vec<Vec<(String, Vec<u8>)>> {
    let db = reopen_db(path);
    let entry = db
        .entry(keepass::db::EntryId::from_uuid(uuid))
        .expect("entry present");
    let list = |version: &keepass::db::EntryRef<'_>| {
        let mut list = version
            .attachments_named()
            .map(|(name, attachment)| (name.to_string(), attachment.data.get().clone()))
            .collect::<Vec<_>>();
        list.sort();
        list
    };
    let mut versions = vec![list(&entry)];
    let count = entry
        .history
        .as_ref()
        .map_or(0, |history| history.get_entries().len());
    for index in 0..count {
        versions.push(list(&entry.historical(index).expect("history version")));
    }
    versions
}

fn first_attachment_id(target: &KeepassVault, entry: &str) -> String {
    target
        .list_visible_items()
        .expect("list")
        .into_iter()
        .find(|item| item.id == entry)
        .expect("entry visible")
        .attachment_ids[0]
        .clone()
}

#[test]
fn removing_an_attachment_below_a_history_pinned_slot_succeeds() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    let (a, b) = seed_history_pinned_last_slot(&path);
    let b_before = all_versions_on_disk(&path, b);
    assert_eq!(b_before.len(), 2, "B has one history version");

    let target = open_target(&path);
    let a_id = a.to_string();
    let a_attachment = first_attachment_id(&target, &a_id);
    target
        .delete_attachment(&a_id, &a_attachment)
        .expect("unrelated removal succeeds");
    target.commit().expect("commit");

    assert_eq!(all_versions_on_disk(&path, a), vec![vec![]]);
    assert_eq!(
        all_versions_on_disk(&path, b),
        b_before,
        "B's current and history attachments intact"
    );
    let db = reopen_db(&path);
    let entry = db
        .entry(keepass::db::EntryId::from_uuid(b))
        .expect("B present");
    assert_eq!(entry.get("Notes"), Some("edited once in KeePassXC"));
    assert_eq!(
        entry.historical(0).expect("history version").get("Notes"),
        None,
        "the history version keeps its own fields"
    );
}

#[test]
fn permanently_deleting_an_entry_below_a_history_pinned_slot_succeeds() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    let (a, b) = seed_history_pinned_last_slot(&path);
    let b_before = all_versions_on_disk(&path, b);

    let target = open_target(&path);
    target
        .delete_item(&a.to_string(), true)
        .expect("unrelated permanent delete succeeds");
    target.commit().expect("commit");

    let db = reopen_db(&path);
    assert!(db.entry(keepass::db::EntryId::from_uuid(a)).is_none());
    assert_eq!(all_versions_on_disk(&path, b), b_before);
}

// ------------------------------------------------------ folder names (N10)

#[test]
fn group_name_containing_a_slash_does_not_collide_with_nested_groups() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    let mut db = Database::with_config(cheap_config());
    {
        let mut root = db.root_mut();
        root.add_group().name = "a/b".to_string();
        let mut root = db.root_mut();
        let mut a = root.add_group();
        a.name = "a".to_string();
        a.add_group().name = "b".to_string();
    }
    save_db(&db, &path);

    let scanned = open_target(&path).scan_vault().expect("scan");
    let mut names = scanned
        .folders
        .iter()
        .map(|folder| folder.name.clone())
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 3, "distinct folder names: {names:?}");

    // Restoring the scanned folders into a fresh database reproduces a
    // distinct group per folder, and a pruning re-run matches every folder.
    let fresh_path = temp.path().join("fresh.kdbx");
    write_empty_kdbx(&fresh_path);
    let fresh = open_target(&fresh_path);
    let mut opened = archive_of(Vec::new(), Vec::new());
    opened.vault.folders = scanned.folders.clone();
    let first = apply_archive(&fresh, &opened, apply_options(), false, false);
    assert_eq!(first.summary.folders_created, 3);
    assert!(
        reopen_db(&fresh_path)
            .root()
            .group_by_path(&["a", "b"])
            .is_some()
    );
    let second = apply_archive(&fresh, &opened, apply_options(), true, false);
    assert_eq!(second.summary.folders_created, 0);
    assert_eq!(second.summary.folders_deleted, 0);
}

// ---------------------------------------------- deterministic rendering (h9)

#[test]
fn foreign_entry_renders_identically_across_opens() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    let mut db = Database::with_config(cheap_config());
    {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected("Title", "Foreign");
        for index in 0..8 {
            entry.set_unprotected(format!("custom{index}"), format!("value{index}"));
            entry.add_attachment(
                format!("file{index}.bin"),
                keepass::db::Value::protected(format!("bytes{index}").into_bytes()),
            );
        }
    }
    save_db(&db, &path);

    let mut fingerprints = std::collections::BTreeSet::new();
    for _ in 0..10 {
        let scanned = open_target(&path).scan_vault().expect("scan");
        fingerprints.insert(yabbt::diff::item_fingerprint(&scanned.items[0]));
    }
    assert_eq!(fingerprints.len(), 1, "rendering is deterministic");
}

// ---------------------------------------------------- batched writes (N7)

#[test]
fn mutations_are_written_only_on_commit() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let before = fs::read(&path).expect("read kdbx");
    let target = open_target(&path);

    let item_id = target
        .create_item(&serde_json::json!({ "type": 2, "name": "Pending", "fields": [] }))
        .expect("create");
    assert_eq!(
        fs::read(&path).expect("read kdbx"),
        before,
        "not yet written"
    );
    assert!(target.get_item(&item_id).is_ok(), "visible in memory");

    target.commit().expect("commit");
    assert!(
        reopen_db(&path)
            .iter_all_entries()
            .any(|entry| entry.get_title() == Some("Pending"))
    );
}

#[test]
fn apply_writes_the_kdbx_once() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);

    let outcome = apply(&target, apply_options());
    assert_eq!(outcome.summary.items_created, 2);
    assert!(outcome.summary.restore_map_updated);
    assert_eq!(target.saves_written(), 1);
}

/// Re-applying an unchanged archive (as every no-op `sync` does) must not
/// rewrite the kdbx or leave another full `.bak` copy behind, neither in
/// the same process nor in fresh ones.
#[test]
fn no_op_reapply_never_rewrites_the_kdbx_or_adds_bak_copies() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);
    apply(&target, apply_options());
    assert_eq!(target.saves_written(), 1);
    let baks = bak_files(temp.path()).len();
    let bytes = fs::read(&path).expect("read kdbx");

    let options = ApplyOptions {
        update_existing: true,
        verify_after: true,
        ..apply_options()
    };
    for run in 0..3 {
        let outcome = apply_with_prune(&target, options, true, false);
        assert!(!outcome.summary.has_mutations(), "run {run}");
        assert!(!outcome.summary.restore_map_updated, "run {run}");
        let fresh = open_target(&path);
        let outcome = apply_with_prune(&fresh, options, true, false);
        assert!(!outcome.summary.restore_map_updated, "fresh run {run}");
        assert_eq!(fresh.saves_written(), 0, "fresh run {run}");
    }
    assert_eq!(target.saves_written(), 1, "no further saves");
    assert_eq!(bak_files(temp.path()).len(), baks, "no further .bak copies");
    assert_eq!(fs::read(&path).expect("read kdbx"), bytes, "kdbx unchanged");
}

/// Editing an entry to exactly what it already holds is not a change.
#[test]
fn editing_an_entry_to_identical_content_does_not_save() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);
    let payload = serde_json::json!({
        "type": 1,
        "name": "Same",
        "notes": "body",
        "favorite": true,
        "login": { "username": "u", "password": "p", "uris": [{ "uri": "https://a.test" }] },
        "fields": [{ "name": "f", "value": "v", "type": 0 }],
    });
    let id = target.create_item(&payload).expect("create");
    target.commit().expect("commit");
    let bytes = fs::read(&path).expect("read kdbx");

    target.edit_item(&id, &payload).expect("edit");
    target.commit().expect("commit");
    assert_eq!(target.saves_written(), 1, "identical edit is not saved");
    assert_eq!(fs::read(&path).expect("read kdbx"), bytes);

    let mut changed = payload.clone();
    changed["notes"] = serde_json::json!("other body");
    target.edit_item(&id, &changed).expect("edit");
    target.commit().expect("commit");
    assert_eq!(target.saves_written(), 2, "a real change is saved");
}

/// Another program (e.g. KeePassXC) saving the database between yabbt's
/// read and its commit must never be overwritten: the commit refuses,
/// leaves the external version on disk, and reports nothing as applied.
#[test]
fn external_save_between_open_and_commit_is_never_overwritten() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);
    let opened = opened_archive();
    let target_vault = target.scan_vault().expect("scan");
    let plan = plan_restore_with_options(
        &opened.vault,
        Some(&target_vault),
        "keepass",
        RestorePlanOptions::default(),
    );

    let mut db = reopen_db(&path);
    db.root_mut()
        .add_entry()
        .set_unprotected("Title", "External Edit");
    save_db(&db, &path);
    let external = fs::read(&path).expect("read kdbx");

    let error = apply_restore_plan(
        &target,
        &opened,
        &plan,
        &target_vault,
        None,
        apply_options(),
        &NoopProgress,
    )
    .expect_err("external modification must abort the save");
    match error {
        RestoreError::Apply { summary, error } => {
            assert!(!summary.has_mutations(), "{summary:?}");
            assert!(!summary.restore_map_updated);
            let message = error.to_string();
            assert!(message.contains("modified by another program"), "{message}");
            assert!(message.contains("re-run"), "{message}");
            assert!(message.contains("nothing was written"), "{message}");
        }
        other => panic!("expected apply error, got {other:?}"),
    }
    assert_eq!(
        fs::read(&path).expect("read kdbx"),
        external,
        "external save kept"
    );
    assert!(
        bak_files(temp.path()).is_empty(),
        "no .bak for a refused save"
    );
    assert_eq!(target.saves_written(), 0);

    // The adapter now holds the external version; a re-run keeps it.
    apply(&target, apply_options());
    let titles = reopen_db(&path)
        .iter_all_entries()
        .filter_map(|entry| entry.get_title().map(str::to_string))
        .collect::<Vec<_>>();
    assert!(titles.contains(&"External Edit".to_string()), "{titles:?}");
    assert!(titles.contains(&"Example Login".to_string()), "{titles:?}");
}

/// A database file that appears at the path after a run started from a
/// missing file is not replaced either.
#[test]
fn database_created_externally_during_the_run_is_never_replaced() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    let target = KeepassVault::open(KeepassVaultOptions {
        path: path.clone(),
        passphrase: PASSWORD.to_string(),
        create_if_missing: true,
    })
    .expect("open missing target");
    target
        .create_folder(&serde_json::json!({ "name": "Pending" }))
        .expect("create folder");
    write_empty_kdbx(&path);
    let external = fs::read(&path).expect("read kdbx");

    let error = target.commit().expect_err("must not replace the new file");
    assert!(
        error.to_string().contains("modified by another program"),
        "{error}"
    );
    assert_eq!(fs::read(&path).expect("read kdbx"), external);
}

#[test]
fn failed_save_writes_nothing_and_reports_no_applied_changes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let before = fs::read(&path).expect("read kdbx");
    let target = open_target(&path);
    // A directory squatting on the temp-file name makes the save fail.
    fs::create_dir(temp.path().join("vault.kdbx.tmp-yabbt")).expect("squat temp name");

    let opened = opened_archive();
    let target_vault = target.scan_vault().expect("scan");
    let plan = plan_restore_with_options(
        &opened.vault,
        Some(&target_vault),
        "keepass",
        RestorePlanOptions::default(),
    );
    let error = apply_restore_plan(
        &target,
        &opened,
        &plan,
        &target_vault,
        None,
        apply_options(),
        &NoopProgress,
    )
    .expect_err("save fails");
    match error {
        RestoreError::Apply { summary, error } => {
            assert!(
                !summary.has_mutations(),
                "nothing reported as applied: {summary:?}"
            );
            assert!(!summary.restore_map_updated);
            assert!(
                error.to_string().contains("nothing was written"),
                "error says nothing was written: {error}"
            );
        }
        other => panic!("expected apply error, got {other:?}"),
    }
    assert_eq!(
        fs::read(&path).expect("read kdbx"),
        before,
        "file untouched"
    );
    // The discarded changes are gone from memory too.
    assert!(target.scan_vault().expect("scan").items.is_empty());
}

/// An entry whose only attachment is shared with its own history (what
/// KeePassXC leaves after any edit): the keepass crate cannot remove that
/// file. Returns the entry uuid.
fn seed_history_pinned_entry(path: &Path) -> uuid::Uuid {
    let mut db = Database::with_config(cheap_config());
    let pinned = {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected("Title", "Example Note");
        entry.set_unprotected("Notes", "note body");
        entry.add_attachment(
            "doc.bin",
            keepass::db::Value::protected(b"doc-bytes".to_vec()),
        );
        entry.edit_tracking(|tracked| tracked.set_unprotected("Notes", "note body"));
        entry.as_ref().id().uuid()
    };
    save_db(&db, path);
    pinned
}

/// A prune delete the keepass library has to refuse because entry history
/// still references the file is skipped with a report; the rest of the
/// apply goes ahead and succeeds.
#[test]
fn history_pinned_attachment_delete_is_skipped_and_the_apply_succeeds() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    let pinned = seed_history_pinned_entry(&path);
    let target = open_target(&path);

    let mut opened = opened_archive();
    opened.vault.items[1].id = pinned.to_string();
    let outcome = apply_archive(
        &target,
        &opened,
        ApplyOptions {
            verify_after: true,
            ..apply_options()
        },
        true,
        false,
    );
    let summary = &outcome.summary;
    assert_eq!(summary.items_created, 1);
    assert_eq!(summary.attachments_deleted, 0);
    assert_eq!(
        summary.attachment_deletes_kept_by_history,
        vec![pinned.to_string()]
    );
    assert!(summary.restore_map_updated);
    assert!(outcome.verification.is_some());
    assert!(
        reopen_db(&path)
            .iter_all_entries()
            .any(|entry| entry.get_title() == Some("Example Login")),
        "the create was persisted"
    );
    assert_eq!(
        all_versions_on_disk(&path, pinned),
        vec![
            vec![("doc.bin".to_string(), b"doc-bytes".to_vec())],
            vec![("doc.bin".to_string(), b"doc-bytes".to_vec())],
        ],
        "the pinned attachment is untouched"
    );
}

#[test]
fn mid_apply_failure_still_writes_the_completed_mutations() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.kdbx");
    write_empty_kdbx(&path);
    let target = open_target(&path);

    let opened = opened_archive();
    let target_vault = target.scan_vault().expect("scan");
    let mut plan = plan_restore_with_options(
        &opened.vault,
        Some(&target_vault),
        "keepass",
        RestorePlanOptions::default(),
    );
    // A delete of an attachment that does not exist fails after the creates.
    plan.delete_attachments
        .push(yabbt::restore_plan::RestoreAttachmentDelete {
            target_item_id: "00000000-0000-0000-0000-000000000001".to_string(),
            attachment_id: "kdbx-missing".to_string(),
            requires_item_update: false,
        });
    let error = apply_restore_plan(
        &target,
        &opened,
        &plan,
        &target_vault,
        None,
        apply_options(),
        &NoopProgress,
    )
    .expect_err("missing attachment cannot be deleted");
    match error {
        RestoreError::Apply { summary, error } => {
            assert!(error.to_string().contains("not found"), "{error}");
            assert_eq!(summary.items_created, 2);
            assert_eq!(summary.attachments_deleted, 0);
            assert!(summary.restore_map_updated);
        }
        other => panic!("expected apply error, got {other:?}"),
    }
    assert!(
        reopen_db(&path)
            .iter_all_entries()
            .any(|entry| entry.get_title() == Some("Example Login")),
        "the completed create was persisted"
    );
    assert!(
        restore_map_state(&open_target(&path).scan_vault().expect("scan"))
            .expect("map parses")
            .is_some(),
        "the restore map was persisted"
    );
}

// ------------------------------------- randomized attachment removal check

/// Tiny deterministic xorshift generator (no extra dependency).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

/// One entry version: its Notes field and sorted `(name, bytes)` attachments.
type VersionModel = (Option<String>, Vec<(String, Vec<u8>)>);

/// Every entry's versions (current first, then history), read from disk.
fn every_entry_on_disk(path: &Path) -> BTreeMap<uuid::Uuid, Vec<VersionModel>> {
    let db = reopen_db(path);
    let version_model = |version: &keepass::db::EntryRef<'_>| {
        let mut attachments = version
            .attachments_named()
            .map(|(name, attachment)| (name.to_string(), attachment.data.get().clone()))
            .collect::<Vec<_>>();
        attachments.sort();
        (version.get("Notes").map(str::to_string), attachments)
    };
    db.iter_all_entries()
        .map(|entry| {
            let count = entry
                .history
                .as_ref()
                .map_or(0, |history| history.get_entries().len());
            let versions =
                std::iter::once(version_model(&entry))
                    .chain((0..count).map(|index| {
                        version_model(&entry.historical(index).expect("history version"))
                    }))
                    .collect();
            (entry.id().uuid(), versions)
        })
        .collect()
}

/// Random databases (attachments, KeePassXC-style history versions that
/// share binaries with the current version, later additions, a recycle
/// bin) and random attachment / permanent entry removals: every removal
/// either succeeds and leaves every other version (attachments and fields)
/// intact on disk, or is refused because the file is still needed by the
/// entry's own history, and changes nothing.
#[test]
fn random_attachment_removals_keep_every_other_version_intact() {
    let (mut succeeded, mut refused) = (0, 0);
    for seed in 1..=40u64 {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ seed);
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("vault.kdbx");
        let mut db = Database::with_config(cheap_config());
        let bin_id = {
            let mut root = db.root_mut();
            let mut bin = root.add_group();
            bin.name = "Recycle Bin".to_string();
            bin.as_ref().id()
        };
        db.meta.recyclebin_uuid = Some(bin_id.uuid());
        let mut counter = 0;
        for index in 0..(4 + rng.below(5)) {
            let in_bin = rng.below(5) == 0;
            let mut parent = if in_bin {
                db.group_mut(bin_id).expect("bin")
            } else {
                db.root_mut()
            };
            let mut entry = parent.add_entry();
            entry.set_unprotected("Title", format!("E{index}"));
            for _ in 0..rng.below(4) {
                counter += 1;
                entry.add_attachment(
                    format!("f{counter}.bin"),
                    keepass::db::Value::protected(format!("bytes-{counter}").into_bytes()),
                );
            }
            for edit in 0..rng.below(3) {
                entry.edit_tracking(|tracked| {
                    tracked.set_unprotected("Notes", format!("edit {edit}"))
                });
                if rng.below(2) == 0 {
                    counter += 1;
                    entry.add_attachment(
                        format!("f{counter}.bin"),
                        keepass::db::Value::protected(format!("bytes-{counter}").into_bytes()),
                    );
                }
            }
        }
        save_db(&db, &path);

        let target = open_target(&path);
        let mut expected = every_entry_on_disk(&path);
        for _ in 0..6 {
            let candidates = expected
                .iter()
                .flat_map(|(uuid, versions)| {
                    versions[0]
                        .1
                        .iter()
                        .map(move |(name, _)| (*uuid, Some(name.clone())))
                        .chain(std::iter::once((*uuid, None)))
                })
                .collect::<Vec<_>>();
            if candidates.is_empty() {
                break;
            }
            let (uuid, name) = candidates[rng.below(candidates.len())].clone();
            let result = match &name {
                Some(name) => target.delete_attachment(
                    &uuid.to_string(),
                    &yabbt::adapters::keepass::keepass_attachment_id(uuid, name),
                ),
                None => target.delete_item(&uuid.to_string(), true),
            };
            match result {
                Ok(()) => {
                    succeeded += 1;
                    match &name {
                        Some(name) => expected.get_mut(&uuid).expect("entry")[0]
                            .1
                            .retain(|(candidate, _)| candidate != name),
                        None => {
                            expected.remove(&uuid);
                        }
                    }
                }
                Err(error) => {
                    refused += 1;
                    assert!(
                        error.to_string().contains("kept in the history"),
                        "seed {seed}: unexpected refusal: {error}"
                    );
                }
            }
            target.commit().expect("commit");
            assert_eq!(
                every_entry_on_disk(&path),
                expected,
                "seed {seed}: on-disk entries after removing {name:?} from {uuid}"
            );
        }
    }
    assert!(succeeded > 50, "removals exercised: {succeeded}");
    assert!(refused > 0, "history refusals exercised: {refused}");
}

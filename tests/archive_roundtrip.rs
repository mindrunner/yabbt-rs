use std::fs;
use std::path::PathBuf;

use yabbt::archive::{
    ArchiveAttachment, ArchiveBuilder, ArchiveError, WriteMode, open_archive, verify_archive,
};
use yabbt::model::{
    AttachmentRef, CompletenessReport, Folder, ItemKind, Vault, VaultItem, VaultMetadata,
};

const RECOVERY_SHA256: &str = "7b3ab6aba8e82522c98468aa813ae3d894b485b9fe936d275e8ff169159d13a0";
const STRONG_PASSPHRASE: &str = "correct horse battery staple archive vault";

fn sample_vault() -> Vault {
    Vault {
        metadata: VaultMetadata {
            archive_version: 1,
            source_backend: "fixture".to_string(),
            source_server: None,
            created_at: "2026-05-03T11:45:00Z".to_string(),
            tool_version: "0.1.0".to_string(),
        },
        folders: vec![Folder {
            id: "folder-1".to_string(),
            name: "Recovery".to_string(),
        }],
        items: vec![VaultItem {
            id: "item-1".to_string(),
            kind: ItemKind::SecureNote,
            name: "Recovery Codes".to_string(),
            notes: Some("secret note".to_string()),
            folder_id: Some("folder-1".to_string()),
            favorite: false,
            fields: Vec::new(),
            attachments: vec![AttachmentRef {
                id: "attachment-1".to_string(),
                file_name: "codes.txt".to_string(),
                size: 13,
                sha256: RECOVERY_SHA256.to_string(),
                path: "attachments/item-1/attachment-1.bin".to_string(),
            }],
            backend_metadata: Vec::new(),
        }],
        report: CompletenessReport {
            complete: true,
            warnings: Vec::new(),
        },
    }
}

fn archive_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("yabbt-{name}-{}.archive", std::process::id()));
    let _ = fs::remove_file(&path);
    path
}

#[test]
fn archive_write_is_atomic_and_leaves_no_temp_files() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("atomic.yabbt");

    ArchiveBuilder::new(sample_vault())
        .attachment(ArchiveAttachment {
            path: "attachments/item-1/attachment-1.bin".to_string(),
            bytes: b"recovery-code".to_vec(),
        })
        .write(&path, STRONG_PASSPHRASE, WriteMode::CreateNew)
        .expect("write archive");
    open_archive(&path, STRONG_PASSPHRASE).expect("archive opens");

    let leftovers = fs::read_dir(temp.path())
        .expect("read tempdir")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains("tmp-yabbt"))
        .collect::<Vec<_>>();
    assert!(leftovers.is_empty(), "stray temp files: {leftovers:?}");

    // A failed write (missing parent directory) leaves nothing behind.
    let missing_parent = temp.path().join("missing").join("archive.yabbt");
    ArchiveBuilder::new(sample_vault())
        .write(&missing_parent, STRONG_PASSPHRASE, WriteMode::CreateNew)
        .expect_err("write into missing directory fails");
    assert!(!missing_parent.exists());
}

fn temp_leftovers(dir: &std::path::Path) -> Vec<String> {
    fs::read_dir(dir)
        .expect("read dir")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains("tmp-yabbt"))
        .collect()
}

fn sample_builder() -> ArchiveBuilder {
    ArchiveBuilder::new(sample_vault()).attachment(ArchiveAttachment {
        path: "attachments/item-1/attachment-1.bin".to_string(),
        bytes: b"recovery-code".to_vec(),
    })
}

#[test]
fn archive_write_create_new_never_replaces_an_existing_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("existing.yabbt");
    fs::write(&path, b"previous good backup").expect("seed existing file");

    let error = sample_builder()
        .write(&path, STRONG_PASSPHRASE, WriteMode::CreateNew)
        .expect_err("create-new write must not replace");
    assert!(
        matches!(&error, ArchiveError::Io(io) if io.kind() == std::io::ErrorKind::AlreadyExists),
        "{error:?}"
    );
    assert_eq!(fs::read(&path).expect("read"), b"previous good backup");
    assert!(temp_leftovers(temp.path()).is_empty());
}

#[test]
fn archive_write_overwrite_replaces_an_existing_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("existing.yabbt");
    fs::write(&path, b"previous good backup").expect("seed existing file");

    sample_builder()
        .write(&path, STRONG_PASSPHRASE, WriteMode::Overwrite)
        .expect("overwrite");
    verify_archive(&path, STRONG_PASSPHRASE).expect("replaced archive verifies");
    assert!(temp_leftovers(temp.path()).is_empty());
}

#[test]
fn archive_write_ignores_a_stale_temp_file_and_is_owner_only() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("archive.yabbt");
    // The fixed temp name older versions used, left behind by a crash.
    let stale = temp.path().join("archive.yabbt.tmp-yabbt");
    fs::write(&stale, b"stale").expect("seed stale temp");

    sample_builder()
        .write(&path, STRONG_PASSPHRASE, WriteMode::CreateNew)
        .expect("stale temp does not block the write");
    verify_archive(&path, STRONG_PASSPHRASE).expect("archive verifies");
    assert_eq!(fs::read(&stale).expect("read stale"), b"stale");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn dropping_a_staged_archive_leaves_nothing_behind() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("staged.yabbt");

    let staged = sample_builder()
        .stage_with_progress(&path, STRONG_PASSPHRASE, &yabbt::progress::NoopProgress)
        .expect("stage");
    assert!(!path.exists(), "staging must not touch the destination");
    verify_archive(staged.path(), STRONG_PASSPHRASE).expect("staged archive verifies");
    drop(staged);
    assert!(!path.exists());
    assert!(temp_leftovers(temp.path()).is_empty());
}

#[test]
fn archive_round_trips_vault_and_attachments() {
    let path = archive_path("roundtrip");
    let vault = sample_vault();
    let attachment = ArchiveAttachment {
        path: "attachments/item-1/attachment-1.bin".to_string(),
        bytes: b"recovery-code".to_vec(),
    };

    ArchiveBuilder::new(vault.clone())
        .attachment(attachment.clone())
        .write(&path, STRONG_PASSPHRASE, WriteMode::CreateNew)
        .expect("write archive");

    let opened = open_archive(&path, STRONG_PASSPHRASE).expect("open archive");
    assert_eq!(opened.vault, vault);
    assert_eq!(opened.attachments, vec![attachment]);
    verify_archive(&path, STRONG_PASSPHRASE).expect("verify archive");
}

#[test]
fn archive_verifies_attachments_written_out_of_path_order() {
    let path = archive_path("unsorted-attachments");
    let mut vault = sample_vault();
    vault.items[0].attachments.push(AttachmentRef {
        id: "attachment-0".to_string(),
        file_name: "extra-codes.txt".to_string(),
        size: 10,
        sha256: String::new(),
        path: "attachments/item-1/attachment-0.bin".to_string(),
    });

    ArchiveBuilder::new(vault)
        .attachment(ArchiveAttachment {
            path: "attachments/item-1/attachment-1.bin".to_string(),
            bytes: b"recovery-code".to_vec(),
        })
        .attachment(ArchiveAttachment {
            path: "attachments/item-1/attachment-0.bin".to_string(),
            bytes: b"extra-code".to_vec(),
        })
        .write(&path, STRONG_PASSPHRASE, WriteMode::CreateNew)
        .expect("write archive");

    verify_archive(&path, STRONG_PASSPHRASE).expect("verify archive");
}

#[test]
fn archive_rejects_weak_passphrase_by_default() {
    let path = archive_path("weak-passphrase");

    let error = ArchiveBuilder::new(sample_vault())
        .write(&path, "password", WriteMode::CreateNew)
        .expect_err("weak passphrase fails");

    assert!(error.to_string().contains("weak passphrase"));
}

#[test]
fn archive_allows_weak_passphrase_with_explicit_override() {
    let path = archive_path("weak-passphrase-yolo");

    ArchiveBuilder::new(sample_vault())
        .allow_weak_passphrase()
        .write(&path, "password", WriteMode::CreateNew)
        .expect("explicit override writes archive");

    open_archive(&path, "password").expect("open weak archive with override");
}

#[test]
fn archive_bytes_do_not_expose_plaintext_payloads() {
    let path = archive_path("ciphertext");

    ArchiveBuilder::new(sample_vault())
        .attachment(ArchiveAttachment {
            path: "attachments/item-1/attachment-1.bin".to_string(),
            bytes: b"recovery-code".to_vec(),
        })
        .write(&path, STRONG_PASSPHRASE, WriteMode::CreateNew)
        .expect("write archive");

    let archive = fs::read(&path).expect("read archive");
    let archive_text = String::from_utf8_lossy(&archive);

    assert!(!archive_text.contains("Recovery Codes"));
    assert!(!archive_text.contains("secret note"));
    assert!(!archive_text.contains("recovery-code"));
}

#[test]
fn archive_rejects_wrong_passphrase() {
    let path = archive_path("wrong-passphrase");

    ArchiveBuilder::new(sample_vault())
        .write(
            &path,
            "right horse battery staple archive vault",
            WriteMode::CreateNew,
        )
        .expect("write archive");

    let error = open_archive(&path, "wrong passphrase").expect_err("wrong passphrase fails");
    assert!(error.to_string().contains("passphrase"));
}

#[test]
fn archive_rejects_tampered_bytes() {
    let path = archive_path("tampered");

    ArchiveBuilder::new(sample_vault())
        .write(&path, STRONG_PASSPHRASE, WriteMode::CreateNew)
        .expect("write archive");

    let mut bytes = fs::read(&path).expect("read archive");
    let last = bytes.last_mut().expect("archive has bytes");
    *last ^= 0x01;
    fs::write(&path, bytes).expect("write tampered archive");

    let error = verify_archive(&path, STRONG_PASSPHRASE).expect_err("tamper fails");
    assert!(error.to_string().contains("integrity"));
}

#[test]
fn verify_rejects_incomplete_backup_report() {
    let path = archive_path("incomplete");
    let mut vault = sample_vault();
    vault.report.complete = false;

    ArchiveBuilder::new(vault)
        .attachment(ArchiveAttachment {
            path: "attachments/item-1/attachment-1.bin".to_string(),
            bytes: b"recovery-code".to_vec(),
        })
        .write(&path, STRONG_PASSPHRASE, WriteMode::CreateNew)
        .expect("write archive");

    let error =
        verify_archive(&path, STRONG_PASSPHRASE).expect_err("incomplete backup fails verify");
    assert!(error.to_string().contains("incomplete"));
}

#[test]
fn verify_rejects_missing_attachment_payload() {
    let path = archive_path("missing-attachment");

    ArchiveBuilder::new(sample_vault())
        .write(&path, STRONG_PASSPHRASE, WriteMode::CreateNew)
        .expect("write archive");

    let error =
        verify_archive(&path, STRONG_PASSPHRASE).expect_err("missing attachment fails verify");
    assert!(error.to_string().contains("missing attachment"));
}

#[test]
fn verify_rejects_orphan_attachment_payload() {
    let path = archive_path("orphan-attachment");
    let mut vault = sample_vault();
    vault.items[0].attachments.clear();

    ArchiveBuilder::new(vault)
        .attachment(ArchiveAttachment {
            path: "attachments/item-1/attachment-1.bin".to_string(),
            bytes: b"recovery-code".to_vec(),
        })
        .write(&path, STRONG_PASSPHRASE, WriteMode::CreateNew)
        .expect("write archive");

    let error =
        verify_archive(&path, STRONG_PASSPHRASE).expect_err("orphan attachment fails verify");
    assert!(error.to_string().contains("orphan attachment"));
}

#[test]
fn verify_rejects_attachment_size_mismatch() {
    let path = archive_path("size-mismatch");
    let mut vault = sample_vault();
    vault.items[0].attachments[0].size = 999;

    ArchiveBuilder::new(vault)
        .attachment(ArchiveAttachment {
            path: "attachments/item-1/attachment-1.bin".to_string(),
            bytes: b"recovery-code".to_vec(),
        })
        .write(&path, STRONG_PASSPHRASE, WriteMode::CreateNew)
        .expect("write archive");

    let error = verify_archive(&path, STRONG_PASSPHRASE).expect_err("size mismatch fails verify");
    assert!(error.to_string().contains("size mismatch"));
}

#[test]
fn verify_rejects_attachment_sha_mismatch() {
    let path = archive_path("sha-mismatch");
    let mut vault = sample_vault();
    vault.items[0].attachments[0].sha256 = "not-the-real-sha".to_string();

    ArchiveBuilder::new(vault)
        .attachment(ArchiveAttachment {
            path: "attachments/item-1/attachment-1.bin".to_string(),
            bytes: b"recovery-code".to_vec(),
        })
        .write(&path, STRONG_PASSPHRASE, WriteMode::CreateNew)
        .expect("write archive");

    let error = verify_archive(&path, STRONG_PASSPHRASE).expect_err("sha mismatch fails verify");
    assert!(error.to_string().contains("sha256 mismatch"));
}

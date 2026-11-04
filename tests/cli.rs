use assert_cmd::Command;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use predicates::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};

use yabbt::archive::{ArchiveAttachment, ArchiveBuilder, WriteMode, open_archive};
use yabbt::model::{
    AttachmentRef, CompletenessReport, Field, Folder, ItemKind, Vault, VaultItem, VaultMetadata,
};

const STRONG_TEST_PASSPHRASE: &str = "correct horse battery staple archive vault";
const STRONG_KDBX_PASSPHRASE: &str = "correct horse battery staple kdbx vault";

#[test]
fn doctor_command_reports_stage_scope() {
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");

    cmd.arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("yabbt doctor"))
        .stdout(predicate::str::contains("archive core"))
        .stdout(predicate::str::contains(
            "bw backup, diff, restore dry-run, and restore apply available",
        ));
}

#[test]
fn help_lists_planned_command_surface() {
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");

    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("backup"))
        .stdout(predicate::str::contains("inspect"))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("diff"))
        .stdout(predicate::str::contains("restore"))
        .stdout(predicate::str::contains("sync"));
}

#[test]
fn transfer_commands_list_attachment_jobs_option() {
    for subcommand in ["backup", "diff", "restore"] {
        let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");

        cmd.args([subcommand, "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("--attachment-jobs"));
    }
}

#[test]
fn transfer_commands_reject_zero_attachment_jobs() {
    let commands = [
        vec![
            "backup",
            "--source",
            "bw",
            "--out",
            "backup.yabbt",
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
            "--attachment-jobs",
            "0",
        ],
        vec![
            "diff",
            "--source",
            "bw",
            "--archive",
            "backup.yabbt",
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
            "--attachment-jobs",
            "0",
        ],
        vec![
            "restore",
            "--target",
            "bw",
            "backup.yabbt",
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
            "--dry-run",
            "--attachment-jobs",
            "0",
        ],
    ];

    for args in commands {
        let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");

        cmd.args(args)
            .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "attachment jobs must be at least 1",
            ));
    }
}

#[test]
fn stage_later_commands_fail_with_clear_message() {
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");

    cmd.args(["backup", "--source", "unknown", "--out", "backup.yabbt"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported backup source"));
}

#[test]
fn backup_source_bw_writes_archive_with_fake_bw_cli() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);

    let archive_path = temp.path().join("backup.yabbt");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "bw",
        "--out",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .assert()
    .success()
    .stdout(predicate::str::contains("wrote backup archive"));

    let opened = open_archive(&archive_path, STRONG_TEST_PASSPHRASE).expect("open backup archive");
    assert_eq!(opened.vault.items[0].name, "Example Login");
    assert_eq!(opened.attachments[0].bytes, b"recovery-code");
}

#[test]
fn backup_parallel_attachment_jobs_overlap_downloads() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let (export_path, items_path) = write_multi_attachment_bitwarden_files(temp.path());
    let transfer_log = temp.path().join("attachment-transfers.log");

    let archive_path = temp.path().join("backup.yabbt");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "bw",
        "--out",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--attachment-jobs",
        "4",
        "--progress",
        "never",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_EXPORT", export_path)
    .env("YABBT_FAKE_BW_ITEMS", items_path)
    .env("YABBT_FAKE_BW_ATTACHMENT_TRANSFER_LOG", &transfer_log)
    .env("YABBT_FAKE_BW_ATTACHMENT_SLEEP", "0.2")
    .assert()
    .success();

    let opened = open_archive(&archive_path, STRONG_TEST_PASSPHRASE).expect("open backup archive");
    let attachment_paths = opened
        .attachments
        .iter()
        .map(|attachment| attachment.path.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        attachment_paths,
        [
            "attachments/item-1/attachment-1.bin",
            "attachments/item-1/attachment-2.bin",
            "attachments/item-1/attachment-3.bin",
            "attachments/item-1/attachment-4.bin",
        ]
    );

    let log = fs::read_to_string(transfer_log).expect("read transfer log");
    let lines = log.lines().collect::<Vec<_>>();
    let first_end = lines
        .iter()
        .position(|line| line.starts_with("end "))
        .expect("at least one attachment finished");
    let starts_before_first_end = lines[..first_end]
        .iter()
        .filter(|line| line.starts_with("start "))
        .count();

    assert!(
        starts_before_first_end > 1,
        "expected overlapping downloads, got log:\n{log}"
    );
}

#[test]
fn backup_attachment_jobs_one_downloads_serially() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let (export_path, items_path) = write_multi_attachment_bitwarden_files(temp.path());
    let transfer_log = temp.path().join("attachment-transfers.log");

    let archive_path = temp.path().join("backup.yabbt");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "bw",
        "--out",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--attachment-jobs",
        "1",
        "--progress",
        "never",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_EXPORT", export_path)
    .env("YABBT_FAKE_BW_ITEMS", items_path)
    .env("YABBT_FAKE_BW_ATTACHMENT_TRANSFER_LOG", &transfer_log)
    .env("YABBT_FAKE_BW_ATTACHMENT_SLEEP", "0.05")
    .assert()
    .success();

    let log = fs::read_to_string(transfer_log).expect("read transfer log");
    let lines = log.lines().collect::<Vec<_>>();
    let first_end = lines
        .iter()
        .position(|line| line.starts_with("end "))
        .expect("at least one attachment finished");
    let starts_before_first_end = lines[..first_end]
        .iter()
        .filter(|line| line.starts_with("start "))
        .count();

    assert_eq!(
        starts_before_first_end, 1,
        "expected serial downloads with one job, got log:\n{log}"
    );
}

#[test]
fn backup_source_bw_fails_before_export_when_vault_is_locked() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);

    let archive_path = temp.path().join("backup.yabbt");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "bw",
        "--out",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--progress",
        "plain",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_STATUS", "locked")
    .assert()
    .failure()
    .stderr(predicate::str::contains("bw vault is locked"))
    .stderr(predicate::str::contains("BW_SESSION"))
    .stderr(predicate::str::contains("EOF while parsing").not());
}

#[test]
fn backup_plain_progress_reports_secret_safe_phases_on_stderr() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);

    let archive_path = temp.path().join("backup.yabbt");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    let output = cmd
        .args([
            "backup",
            "--source",
            "bw",
            "--out",
            archive_path.to_str().expect("archive path"),
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
            "--progress",
            "plain",
        ])
        .env("PATH", path)
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .output()
        .expect("run backup with progress");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("wrote backup archive"));
    assert!(stderr.contains("progress phase: backup source"));
    assert!(stderr.contains("progress step: bw sync done"));
    assert!(stderr.contains("progress count: downloading attachments 1/1"));
    assert!(stderr.contains("progress step: encrypt archive done"));
    assert!(!stderr.contains("Example Login"));
    assert!(!stderr.contains("secret note"));
    assert!(!stderr.contains("hunter2"));
    assert!(!stderr.contains("recovery.txt"));
    assert!(!stderr.contains("recovery-code"));
}

#[test]
fn backup_progress_never_suppresses_progress_stderr() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);

    let archive_path = temp.path().join("backup.yabbt");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    let output = cmd
        .args([
            "backup",
            "--source",
            "bw",
            "--out",
            archive_path.to_str().expect("archive path"),
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
            "--progress",
            "never",
        ])
        .env("PATH", path)
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .output()
        .expect("run backup without progress");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("wrote backup archive"));
    assert!(stderr.is_empty());
}

#[test]
fn backup_progress_always_emits_progress_when_stderr_is_captured() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);

    let archive_path = temp.path().join("backup.yabbt");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    let output = cmd
        .args([
            "backup",
            "--source",
            "bw",
            "--out",
            archive_path.to_str().expect("archive path"),
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
            "--progress",
            "always",
        ])
        .env("PATH", path)
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .output()
        .expect("run backup with forced progress");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("wrote backup archive"));
    assert!(stderr.contains("bw sync done"));
    assert!(stderr.contains("encrypt archive done"));
    assert!(!stderr.contains("Example Login"));
    assert!(!stderr.contains("recovery.txt"));
    assert!(!stderr.contains("recovery-code"));
}

#[test]
fn backup_permissive_plain_progress_completes_missing_attachment_attempts() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);

    let archive_path = temp.path().join("backup.yabbt");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    let output = cmd
        .args([
            "backup",
            "--source",
            "bw",
            "--out",
            archive_path.to_str().expect("archive path"),
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
            "--permissive",
            "--progress",
            "plain",
        ])
        .env("PATH", path)
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .env("YABBT_FAKE_BW_SKIP_ATTACHMENT_WRITE", "1")
        .output()
        .expect("run permissive backup with progress");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("wrote backup archive"));
    assert!(stderr.contains("progress count: downloading attachments 0/1"));
    assert!(stderr.contains("progress count: downloading attachments 1/1"));
    assert!(stderr.contains("complete: false"), "{stderr}");
    assert!(stderr.contains("attachment-download-failed x1"), "{stderr}");
    assert!(!stderr.contains("Example Login"));
    assert!(!stderr.contains("recovery.txt"));
}

/// Run `backup --source bw` against the fake bw with an account that can see
/// organization items, plus any extra flags.
fn run_org_visible_backup(
    temp: &Path,
    archive_path: &Path,
    extra_args: &[&str],
) -> std::process::Output {
    let bin_dir = temp.join("bin");
    fs::create_dir_all(&bin_dir).expect("bin dir");
    write_fake_bw(&bin_dir.join("bw"));
    let items_path = write_org_visible_items(temp);
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "bw",
        "--out",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--progress",
        "never",
    ])
    .args(extra_args)
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_ITEMS", items_path)
    .output()
    .expect("run backup")
}

#[test]
fn backup_with_unexported_org_items_is_incomplete_and_says_so() {
    let temp = tempfile::tempdir().expect("tempdir");
    let archive_path = temp.path().join("backup.yabbt");

    let output = run_org_visible_backup(temp.path(), &archive_path, &[]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr:\n{stderr}");
    assert!(stdout.contains("wrote backup archive"));
    assert!(stderr.contains("complete: false"), "{stderr}");
    assert!(stderr.contains("org-items-not-exported x1"), "{stderr}");
    assert!(stderr.contains("2 organization item(s)"), "{stderr}");
    assert!(stderr.contains("--personal-only"), "{stderr}");
    assert!(!stderr.contains("Example Login"));
    assert_no_org_details(&stdout);
    assert_no_org_details(&stderr);

    let opened = open_archive(&archive_path, STRONG_TEST_PASSPHRASE).expect("open backup archive");
    assert!(!opened.vault.report.complete);
    assert_eq!(opened.vault.report.warnings.len(), 1);
    assert_eq!(
        opened.vault.report.warnings[0].code,
        "org-items-not-exported"
    );
}

#[test]
fn backup_personal_only_keeps_archive_complete_and_reports_excluded_org_items() {
    let temp = tempfile::tempdir().expect("tempdir");
    let archive_path = temp.path().join("backup.yabbt");

    let output = run_org_visible_backup(temp.path(), &archive_path, &["--personal-only"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr:\n{stderr}");
    assert!(stdout.contains("wrote backup archive"));
    assert!(stderr.contains("complete: true"), "{stderr}");
    assert!(
        stderr.contains("org-items-excluded-by-scope x1"),
        "{stderr}"
    );
    assert!(stderr.contains("2 organization item(s)"), "{stderr}");
    assert_no_org_details(&stdout);
    assert_no_org_details(&stderr);

    let opened = open_archive(&archive_path, STRONG_TEST_PASSPHRASE).expect("open backup archive");
    assert!(opened.vault.report.complete);
    assert_eq!(opened.vault.items.len(), 1);
    let warning = &opened.vault.report.warnings[0];
    assert_eq!(warning.code, "org-items-excluded-by-scope");
    assert!(warning.message.contains("2 organization item(s)"));
    assert_no_org_details(&warning.message);

    // The archive is a complete personal-vault backup: verify accepts it.
    let mut verify = Command::cargo_bin("yabbt").expect("binary exists");
    verify
        .args([
            "verify",
            archive_path.to_str().expect("archive path"),
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
        ])
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .assert()
        .success()
        .stdout(predicate::str::contains("complete: true"))
        .stdout(predicate::str::contains("warnings: 1"));
}

#[test]
fn backup_personal_only_conflicts_with_organization_id() {
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "bw",
        "--out",
        "backup.yabbt",
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--personal-only",
        "--organization-id",
        "org-1",
    ])
    .assert()
    .code(2)
    .stderr(predicate::str::contains("--personal-only"))
    .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn backup_source_keepass_rejects_personal_only() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "keepass",
        "--keepass-file",
        temp.path().join("source.kdbx").to_str().expect("kdbx path"),
        "--keepass-passphrase-env",
        "YABBT_TEST_KDBX_PASSPHRASE",
        "--out",
        temp.path()
            .join("backup.yabbt")
            .to_str()
            .expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--personal-only",
    ])
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_TEST_KDBX_PASSPHRASE", STRONG_KDBX_PASSPHRASE)
    .assert()
    .code(2)
    .stderr(predicate::str::contains(
        "backup --personal-only is only valid with a bw backend",
    ));
}

#[test]
fn backup_rejects_weak_passphrase_without_yolo() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);

    let archive_path = temp.path().join("backup.yabbt");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "bw",
        "--out",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", "password")
    .assert()
    .failure()
    .stderr(predicate::str::contains("weak passphrase"));
}

#[test]
fn backup_allows_weak_passphrase_with_yolo() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);

    let archive_path = temp.path().join("backup.yabbt");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "bw",
        "--out",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--yolo",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", "password")
    .assert()
    .success()
    .stdout(predicate::str::contains("wrote backup archive"));

    open_archive(&archive_path, "password").expect("open yolo archive");
}

#[test]
fn verify_archive_command_reports_safe_counts() {
    let temp = tempfile::tempdir().expect("tempdir");
    let archive_path = temp.path().join("backup.yabbt");
    write_sample_archive(&archive_path);

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "verify",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .assert()
    .success()
    .stdout(predicate::str::contains("archive verified"))
    .stdout(predicate::str::contains("items: 1"))
    .stdout(predicate::str::contains("attachments: 1"))
    .stdout(predicate::str::contains("complete: true"));
}

#[test]
fn inspect_archive_command_does_not_print_secrets() {
    let temp = tempfile::tempdir().expect("tempdir");
    let archive_path = temp.path().join("backup.yabbt");
    write_sample_archive(&archive_path);

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "inspect",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .assert()
    .success()
    .stdout(predicate::str::contains("source: fixture"))
    .stdout(predicate::str::contains("folders: 1"))
    .stdout(predicate::str::contains("items: 1"))
    .stdout(predicate::str::contains("attachments: 1"))
    .stdout(predicate::str::contains("Secret Login").not())
    .stdout(predicate::str::contains("secret note").not())
    .stdout(predicate::str::contains("hunter2").not())
    .stdout(predicate::str::contains("otpauth").not())
    .stdout(predicate::str::contains("recovery.txt").not());
}

#[test]
fn verify_fails_but_inspect_succeeds_for_incomplete_archive() {
    let temp = tempfile::tempdir().expect("tempdir");
    let archive_path = temp.path().join("incomplete.yabbt");
    let mut vault = sample_vault();
    vault.report.complete = false;
    write_archive(&archive_path, vault);

    let mut verify = Command::cargo_bin("yabbt").expect("binary exists");
    verify
        .args([
            "verify",
            archive_path.to_str().expect("archive path"),
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
        ])
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .assert()
        .failure()
        .stderr(predicate::str::contains("incomplete"));

    let mut inspect = Command::cargo_bin("yabbt").expect("binary exists");
    inspect
        .args([
            "inspect",
            archive_path.to_str().expect("archive path"),
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
        ])
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .assert()
        .success()
        .stdout(predicate::str::contains("complete: false"));
}

#[test]
fn diff_source_bw_reports_secret_safe_item_id_changes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);

    let mut baseline = sample_vault();
    baseline.items[0].notes = Some("older secret note".to_string());
    baseline.items.push(VaultItem {
        id: "removed-item".to_string(),
        kind: ItemKind::SecureNote,
        name: "Removed Secret".to_string(),
        notes: Some("removed secret note".to_string()),
        folder_id: None,
        favorite: false,
        fields: Vec::new(),
        attachments: Vec::new(),
        backend_metadata: Vec::new(),
    });
    let archive_path = temp.path().join("baseline.yabbt");
    write_archive(&archive_path, baseline);

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "diff",
        "--source",
        "bw",
        "--archive",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .assert()
    .success()
    .stdout(predicate::str::contains("added: 0"))
    .stdout(predicate::str::contains("removed: 1"))
    .stdout(predicate::str::contains("changed: 1"))
    .stdout(predicate::str::contains("unchanged: 0"))
    .stdout(predicate::str::contains("removed-item"))
    .stdout(predicate::str::contains("item-1"))
    .stdout(predicate::str::contains("Example Login").not())
    .stdout(predicate::str::contains("Removed Secret").not())
    .stdout(predicate::str::contains("secret note").not())
    .stdout(predicate::str::contains("hunter2").not())
    .stdout(predicate::str::contains("recovery-code").not());
}

#[test]
fn restore_dry_run_reports_secret_safe_human_plan() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let archive_path = temp.path().join("backup.yabbt");
    write_sample_archive(&archive_path);
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--dry-run",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .assert()
    .success()
    .stdout(predicate::str::contains("restore plan"))
    .stdout(predicate::str::contains("target: bw"))
    .stdout(predicate::str::contains("dry_run: true"))
    .stdout(predicate::str::contains("archive_items: 1"))
    .stdout(predicate::str::contains("target_items_scanned: 1"))
    .stdout(predicate::str::contains("items_to_create: 0"))
    .stdout(predicate::str::contains("items_to_update: 1"))
    .stdout(predicate::str::contains("items_unchanged: 0"))
    .stdout(predicate::str::contains("items_to_skip: 0"))
    .stdout(predicate::str::contains("attachments_to_upload: 1"))
    .stdout(predicate::str::contains("item-1"))
    .stdout(predicate::str::contains("Secret Login").not())
    .stdout(predicate::str::contains("secret note").not())
    .stdout(predicate::str::contains("hunter2").not())
    .stdout(predicate::str::contains("otpauth").not())
    .stdout(predicate::str::contains("recovery.txt").not())
    .stdout(predicate::str::contains("recovery-code").not());
}

#[test]
fn restore_dry_run_scans_target_without_downloading_attachment_bytes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let archive_path = temp.path().join("backup.yabbt");
    write_sample_archive(&archive_path);
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--dry-run",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_SKIP_ATTACHMENT_WRITE", "1")
    .assert()
    .success()
    .stdout(predicate::str::contains("restore plan"))
    .stdout(predicate::str::contains("target_items_scanned: 1"));
}

#[test]
fn restore_dry_run_reports_secret_safe_json_plan() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let archive_path = temp.path().join("backup.yabbt");
    write_sample_archive(&archive_path);
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    let output = cmd
        .args([
            "restore",
            "--target",
            "bw",
            archive_path.to_str().expect("archive path"),
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
            "--dry-run",
            "--format",
            "json",
        ])
        .env("PATH", path)
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).expect("stdout is utf-8");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid json plan");
    assert_eq!(json["target_backend"], "bw");
    assert_eq!(json["dry_run"], true);
    assert_eq!(json["archive_items"], 1);
    assert_eq!(json["target_items_scanned"], 1);
    assert_eq!(json["items_to_create"], 0);
    assert_eq!(json["items_to_update"], 1);
    assert_eq!(json["items_unchanged"], 0);
    assert_eq!(json["items_to_skip"], 0);
    assert_eq!(json["attachments_to_upload"], 1);
    assert_eq!(json["create_item_ids"], serde_json::json!([]));
    assert_eq!(json["update_item_ids"], serde_json::json!(["item-1"]));
    assert!(!stdout.contains("Secret Login"));
    assert!(!stdout.contains("secret note"));
    assert!(!stdout.contains("hunter2"));
    assert!(!stdout.contains("otpauth"));
    assert!(!stdout.contains("recovery.txt"));
    assert!(!stdout.contains("recovery-code"));
}

#[test]
fn restore_requires_dry_run_until_apply_exists() {
    let temp = tempfile::tempdir().expect("tempdir");
    let archive_path = temp.path().join("backup.yabbt");
    write_sample_archive(&archive_path);

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .assert()
    .failure()
    .stderr(predicate::str::contains(
        "restore requires either --dry-run or --apply",
    ));
}

#[test]
fn restore_prune_permanent_requires_prune_apply() {
    let temp = tempfile::tempdir().expect("tempdir");
    let archive_path = temp.path().join("backup.yabbt");
    write_sample_archive(&archive_path);

    let mut without_prune = Command::cargo_bin("yabbt").expect("binary exists");
    without_prune
        .args([
            "restore",
            "--target",
            "bw",
            archive_path.to_str().expect("archive path"),
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
            "--apply",
            "--prune-permanent",
        ])
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "restore --prune-permanent requires --apply --prune",
        ));

    let mut dry_run = Command::cargo_bin("yabbt").expect("binary exists");
    dry_run
        .args([
            "restore",
            "--target",
            "bw",
            archive_path.to_str().expect("archive path"),
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
            "--dry-run",
            "--prune",
            "--prune-permanent",
        ])
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "restore --prune-permanent requires --apply --prune",
        ));
}

#[test]
fn restore_dry_run_prune_reports_delete_counts_and_ids_secret_safely() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let (target_export, target_items) = write_prune_target_files(temp.path());
    let archive_path = temp.path().join("backup.yabbt");
    write_sample_archive(&archive_path);

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--dry-run",
        "--prune",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_EXPORT", &target_export)
    .env("YABBT_FAKE_BW_ITEMS", &target_items)
    .assert()
    .success()
    .stdout(predicate::str::contains("items_to_delete: 1"))
    .stdout(predicate::str::contains("target-only-item"))
    .stdout(predicate::str::contains("attachments_to_delete: 1"))
    .stdout(predicate::str::contains("target-extra-attachment"))
    .stdout(predicate::str::contains("folders_to_delete: 1"))
    .stdout(predicate::str::contains("extra-folder"))
    .stdout(predicate::str::contains("prune_permanent: false"))
    .stdout(predicate::str::contains("Secret Login").not())
    .stdout(predicate::str::contains("secret note").not())
    .stdout(predicate::str::contains("hunter2").not())
    .stdout(predicate::str::contains("extra.txt").not())
    .stdout(predicate::str::contains("Extra Folder").not());
}

#[test]
fn restore_prune_with_empty_archive_is_blocked_without_allow_mass_delete() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    write_fake_bw(&bin_dir.join("bw"));
    let call_log = temp.path().join("bw-calls.log");
    let (target_export, target_items) = write_prune_target_files(temp.path());
    let archive_path = temp.path().join("empty.yabbt");
    let mut empty = sample_vault();
    empty.items.clear();
    empty.folders.clear();
    ArchiveBuilder::new(empty)
        .write(&archive_path, STRONG_TEST_PASSPHRASE, WriteMode::Overwrite)
        .expect("write empty archive");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let restore = |extra: &[&str]| {
        let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
        cmd.args([
            "restore",
            "--target",
            "bw",
            archive_path.to_str().expect("archive path"),
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
        ])
        .args(extra)
        .env("PATH", &path)
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .env("YABBT_FAKE_BW_EXPORT", &target_export)
        .env("YABBT_FAKE_BW_ITEMS", &target_items)
        .env("YABBT_FAKE_BW_LOG", &call_log);
        cmd
    };

    restore(&["--dry-run", "--prune"])
        .assert()
        .code(3)
        .stdout(predicate::str::contains("status: blocked"))
        .stdout(predicate::str::contains("archive contains no items"))
        .stdout(predicate::str::contains("--allow-mass-delete"));
    restore(&["--apply", "--prune"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("archive contains no items"));
    let calls = fs::read_to_string(&call_log).unwrap_or_default();
    assert!(
        !calls.contains("delete "),
        "deleted despite guard:\n{calls}"
    );

    restore(&["--dry-run", "--prune", "--allow-mass-delete"])
        .assert()
        .success()
        .stdout(predicate::str::contains("status: ready"));
    restore(&["--dry-run", "--allow-mass-delete"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "--allow-mass-delete requires --prune",
        ));
}

#[test]
fn restore_dry_run_prune_json_reports_attachment_ids_without_internal_delete_jobs() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let (target_export, target_items) = write_prune_target_files(temp.path());
    let archive_path = temp.path().join("backup.yabbt");
    write_sample_archive(&archive_path);

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    let output = cmd
        .args([
            "restore",
            "--target",
            "bw",
            archive_path.to_str().expect("archive path"),
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
            "--dry-run",
            "--prune",
            "--format",
            "json",
        ])
        .env("PATH", path)
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .env("YABBT_FAKE_BW_EXPORT", &target_export)
        .env("YABBT_FAKE_BW_ITEMS", &target_items)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).expect("stdout is utf-8");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid json plan");
    assert_eq!(
        json["delete_attachment_ids"],
        serde_json::json!(["target-extra-attachment"])
    );
    assert!(json.get("delete_attachments").is_none());
}

#[test]
fn restore_apply_creates_missing_items_and_attachments_only() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let call_log = temp.path().join("bw-calls.log");

    let mut archive_vault = sample_vault();
    archive_vault.items[0].id = "new-item".to_string();
    archive_vault.items[0].attachments[0].path =
        "attachments/new-item/attachment-1.bin".to_string();
    let archive_path = temp.path().join("restore-apply.yabbt");
    ArchiveBuilder::new(archive_vault)
        .attachment(ArchiveAttachment {
            path: "attachments/new-item/attachment-1.bin".to_string(),
            bytes: b"recovery-code".to_vec(),
        })
        .write(&archive_path, STRONG_TEST_PASSPHRASE, WriteMode::Overwrite)
        .expect("write apply archive");

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_LOG", &call_log)
    .assert()
    .success()
    .stdout(predicate::str::contains("restore applied"))
    .stdout(predicate::str::contains("items_created: 1"))
    .stdout(predicate::str::contains("attachments_uploaded: 1"))
    .stdout(predicate::str::contains("items_update_skipped: 0"))
    .stdout(predicate::str::contains("items_delete_skipped: 1"))
    .stdout(predicate::str::contains("restore_map_updated: true"))
    .stdout(predicate::str::contains("Secret Login").not())
    .stdout(predicate::str::contains("secret note").not())
    .stdout(predicate::str::contains("hunter2").not())
    .stdout(predicate::str::contains("otpauth").not())
    .stdout(predicate::str::contains("recovery.txt").not())
    .stdout(predicate::str::contains("recovery-code").not());

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    assert!(calls.contains("create item "));
    assert!(calls.contains("create attachment --file "));
    assert!(calls.contains("--itemid created-new-item"));
    assert!(!calls.contains("edit item"));
    assert!(!calls.contains("delete item"));
}

#[test]
fn restore_apply_parallel_attachment_jobs_overlap_uploads() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let transfer_log = temp.path().join("attachment-uploads.log");
    let archive_path = write_new_item_multi_attachment_archive(temp.path());

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
        "--attachment-jobs",
        "4",
        "--progress",
        "never",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_ATTACHMENT_TRANSFER_LOG", &transfer_log)
    .env("YABBT_FAKE_BW_ATTACHMENT_SLEEP", "0.2")
    .assert()
    .success()
    .stdout(predicate::str::contains("attachments_uploaded: 4"));

    let log = fs::read_to_string(transfer_log).expect("read upload log");
    let lines = log.lines().collect::<Vec<_>>();
    let first_end = lines
        .iter()
        .position(|line| line.starts_with("end upload "))
        .expect("at least one attachment upload finished");
    let starts_before_first_end = lines[..first_end]
        .iter()
        .filter(|line| line.starts_with("start upload "))
        .count();

    assert!(
        starts_before_first_end > 1,
        "expected overlapping uploads, got log:\n{log}"
    );
}

#[test]
fn restore_apply_stops_claiming_upload_jobs_after_first_upload_failure() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let transfer_log = temp.path().join("attachment-uploads.log");
    let fail_marker = temp.path().join("fail-first-upload.marker");
    let archive_path = write_new_item_multi_attachment_archive(temp.path());

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
        "--attachment-jobs",
        "1",
        "--progress",
        "never",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_ATTACHMENT_TRANSFER_LOG", &transfer_log)
    .env("YABBT_FAKE_BW_FAIL_UPLOAD_MARKER", &fail_marker)
    .assert()
    .failure()
    .stderr(predicate::str::contains("restore failed"));

    let log = fs::read_to_string(transfer_log).expect("read upload log");
    let upload_starts = log
        .lines()
        .filter(|line| line.starts_with("start upload "))
        .count();
    assert_eq!(
        upload_starts, 1,
        "expected upload worker to stop after first failure, got log:\n{log}"
    );
}

#[test]
fn restore_apply_failure_reports_partial_mutations_and_writes_restore_map() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let call_log = temp.path().join("bw-calls.log");
    let fail_marker = temp.path().join("fail-first-upload.marker");
    let archive_path = write_new_item_multi_attachment_archive(temp.path());

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
        "--attachment-jobs",
        "1",
        "--progress",
        "never",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_LOG", &call_log)
    .env("YABBT_FAKE_BW_FAIL_UPLOAD_MARKER", &fail_marker)
    .assert()
    .code(1)
    .stdout(predicate::str::contains("restore partially applied"))
    .stdout(predicate::str::contains("items_created: 1"))
    .stdout(predicate::str::contains("created item ids:"))
    .stdout(predicate::str::contains("created-new-item"))
    .stdout(predicate::str::contains("restore_map_updated: true"))
    .stdout(predicate::str::contains(
        "attachment_upload_incomplete: true",
    ))
    .stdout(predicate::str::contains("hunter2").not())
    .stderr(predicate::str::contains("restore failed"))
    .stderr(predicate::str::contains("partially modified"))
    .stderr(predicate::str::contains("--update-existing"));

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    let item_creates = calls
        .lines()
        .filter(|line| line.starts_with("create item "))
        .count();
    assert_eq!(
        item_creates, 2,
        "item create plus restore map create:\n{calls}"
    );
}

#[test]
fn restore_json_progress_reports_secret_safe_apply_counts_on_stderr() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);

    let archive_path = write_new_item_archive(temp.path());
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    let output = cmd
        .args([
            "restore",
            "--target",
            "bw",
            archive_path.to_str().expect("archive path"),
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
            "--apply",
            "--progress",
            "json",
        ])
        .env("PATH", path)
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .output()
        .expect("run restore with progress");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let events = stderr
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("progress json"))
        .collect::<Vec<_>>();
    assert!(stdout.contains("restore applied"));
    assert!(events.iter().any(|event| {
        event.get("kind").and_then(serde_json::Value::as_str) == Some("phase")
            && event.get("label").and_then(serde_json::Value::as_str) == Some("restore archive")
    }));
    assert!(events.iter().any(|event| {
        event.get("kind").and_then(serde_json::Value::as_str) == Some("count")
            && event.get("label").and_then(serde_json::Value::as_str) == Some("creating items")
            && event.get("completed").and_then(serde_json::Value::as_u64) == Some(1)
            && event.get("total").and_then(serde_json::Value::as_u64) == Some(1)
    }));
    assert!(events.iter().any(|event| {
        event.get("kind").and_then(serde_json::Value::as_str) == Some("count")
            && event.get("label").and_then(serde_json::Value::as_str)
                == Some("uploading attachments")
            && event.get("completed").and_then(serde_json::Value::as_u64) == Some(1)
            && event.get("total").and_then(serde_json::Value::as_u64) == Some(1)
    }));
    assert!(!stderr.contains("Secret Login"));
    assert!(!stderr.contains("secret note"));
    assert!(!stderr.contains("hunter2"));
    assert!(!stderr.contains("recovery.txt"));
    assert!(!stderr.contains("recovery-code"));
}

#[test]
fn restore_apply_creates_missing_folders_and_rewrites_item_folder_ids() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let call_log = temp.path().join("bw-calls.log");
    let archive_path = write_new_item_archive(temp.path());

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_LOG", &call_log)
    .assert()
    .success()
    .stdout(predicate::str::contains("restore applied"))
    .stdout(predicate::str::contains("folders_created: 1"))
    .stdout(predicate::str::contains("items_created: 1"))
    .stdout(predicate::str::contains("Sensitive Folder").not());

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    assert!(calls.contains("create folder "));
    let create_item_call = calls
        .lines()
        .find(|line| line.starts_with("create item "))
        .expect("create item call");
    let payload = decode_create_item_payload(create_item_call);
    assert_eq!(payload["folderId"], "created-folder");
}

#[test]
fn restore_dry_run_exits_with_blocked_code_when_plan_is_blocked() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let archive_path = temp.path().join("org-item.yabbt");
    write_organization_item_archive(&archive_path);

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    for format in ["human", "json"] {
        let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
        cmd.args([
            "restore",
            "--target",
            "bw",
            archive_path.to_str().expect("archive path"),
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
            "--dry-run",
            "--format",
            format,
        ])
        .env("PATH", &path)
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .assert()
        .code(3)
        .stdout(predicate::str::contains(
            "organization or collection scoped",
        ));
    }
}

#[test]
fn restore_apply_blocks_organization_scoped_items_before_mutation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let call_log = temp.path().join("bw-calls.log");
    let archive_path = temp.path().join("org-item.yabbt");
    write_organization_item_archive(&archive_path);

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_LOG", &call_log)
    .assert()
    .code(3)
    .stderr(predicate::str::contains(
        "restore failed: plan has blockers",
    ))
    .stderr(predicate::str::contains("blockers:"))
    .stderr(predicate::str::contains(
        "unsupported organization item ids:",
    ))
    .stderr(predicate::str::contains("item-1"))
    .stderr(predicate::str::contains("unsupported collection item ids:"))
    .stderr(predicate::str::contains("source-org").not())
    .stderr(predicate::str::contains("source-collection").not());

    let calls = fs::read_to_string(call_log).unwrap_or_default();
    assert!(!calls.contains("create item "));
    assert!(!calls.contains("create folder "));
    assert!(!calls.contains("create attachment "));
}

#[test]
fn restore_of_archive_failing_verification_exits_blocked_for_dry_run_and_apply() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    write_fake_bw(&bin_dir.join("bw"));
    let call_log = temp.path().join("bw-calls.log");
    let archive_path = temp.path().join("incomplete.yabbt");
    let mut vault = sample_vault();
    vault.report.complete = false;
    write_archive(&archive_path, vault);

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    // The same blocked situation must exit the same way whether it was only
    // planned or refused at --apply.
    for mode in ["--dry-run", "--apply"] {
        let output = Command::cargo_bin("yabbt")
            .expect("binary exists")
            .args([
                "restore",
                "--target",
                "bw",
                archive_path.to_str().expect("archive path"),
                "--passphrase-env",
                "YABBT_TEST_PASSPHRASE",
                mode,
            ])
            .env("PATH", &path)
            .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
            .env("YABBT_FAKE_BW_LOG", &call_log)
            .output()
            .expect("run restore");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(3),
            "{mode}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(
            stdout.contains("backup is marked incomplete")
                || stderr.contains("backup is marked incomplete"),
            "{mode}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    let calls = fs::read_to_string(call_log).unwrap_or_default();
    assert!(!calls.contains("create "), "nothing applied:\n{calls}");
}

#[test]
fn restore_apply_with_organization_id_rewrites_item_organization_id() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let call_log = temp.path().join("bw-calls.log");
    let archive_path = temp.path().join("org-item-no-collections.yabbt");
    write_organization_item_without_collections_archive(&archive_path);

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--organization-id",
        "target-org",
        "--apply",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_LOG", &call_log)
    .assert()
    .success()
    .stdout(predicate::str::contains("restore applied"))
    .stdout(predicate::str::contains("items_created: 1"))
    .stdout(predicate::str::contains("source-org").not());

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    let create_item_call = calls
        .lines()
        .filter(|line| line.starts_with("create item "))
        .find(|line| decode_create_item_payload(line)["name"] == "Secret Login")
        .expect("restored item create call");
    let payload = decode_create_item_payload(create_item_call);
    assert_eq!(payload["organizationId"], "target-org");
    assert_eq!(payload["collectionIds"].as_array().map(Vec::len), Some(0));
    assert_eq!(payload["folderId"], "created-folder");
}

#[test]
fn restore_apply_verify_after_checks_created_item_ids() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let call_log = temp.path().join("bw-calls.log");
    let verify_items = temp.path().join("verify-items.json");
    fs::write(
        &verify_items,
        r#"[{"id":"created-new-item","attachments":[{"id":"verified-attachment","fileName":"recovery.txt","size":13}]}]"#,
    )
    .expect("write verify items");
    let archive_path = write_new_item_archive(temp.path());

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
        "--verify-after",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_LOG", &call_log)
    .env("YABBT_FAKE_BW_VERIFY_ITEMS", &verify_items)
    .env(
        "YABBT_FAKE_BW_AFTER_APPLY_MARKER",
        temp.path()
            .join("after-apply")
            .to_str()
            .expect("marker path"),
    )
    .assert()
    .success()
    .stdout(predicate::str::contains("restore applied"))
    .stdout(predicate::str::contains("post_apply_verified: true"))
    .stdout(predicate::str::contains("created_items_verified: 1"))
    .stdout(predicate::str::contains("attachments_verified: 1"))
    .stdout(predicate::str::contains("Secret Login").not())
    .stdout(predicate::str::contains("secret note").not())
    .stdout(predicate::str::contains("hunter2").not())
    .stdout(predicate::str::contains("recovery.txt").not());

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    assert!(calls.contains("get item created-new-item"));
}

#[test]
fn restore_apply_verify_after_checks_uploaded_attachments() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let call_log = temp.path().join("bw-calls.log");
    let verify_items = temp.path().join("verify-items.json");
    fs::write(
        &verify_items,
        r#"[{"id":"created-new-item","attachments":[{"id":"verified-attachment","fileName":"recovery.txt","size":13}]}]"#,
    )
    .expect("write verify items");
    let archive_path = write_new_item_archive(temp.path());

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
        "--verify-after",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_LOG", &call_log)
    .env("YABBT_FAKE_BW_VERIFY_ITEMS", &verify_items)
    .env(
        "YABBT_FAKE_BW_AFTER_APPLY_MARKER",
        temp.path()
            .join("after-apply")
            .to_str()
            .expect("marker path"),
    )
    .assert()
    .success()
    .stdout(predicate::str::contains("post_apply_verified: true"))
    .stdout(predicate::str::contains("attachments_verified: 1"))
    .stdout(predicate::str::contains("recovery.txt").not());
}

#[test]
fn restore_apply_verify_after_fails_when_uploaded_attachment_is_missing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let verify_items = temp.path().join("verify-items-missing.json");
    fs::write(
        &verify_items,
        r#"[{"id":"created-new-item","attachments":[]}]"#,
    )
    .expect("write verify items");
    let archive_path = write_new_item_archive(temp.path());

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
        "--verify-after",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_VERIFY_ITEMS", &verify_items)
    .env(
        "YABBT_FAKE_BW_AFTER_APPLY_MARKER",
        temp.path()
            .join("after-apply")
            .to_str()
            .expect("marker path"),
    )
    .assert()
    .failure()
    .stdout(predicate::str::contains("restore applied"))
    .stderr(predicate::str::contains(
        "post-apply attachment verification failed",
    ))
    .stderr(predicate::str::contains("recovery.txt").not());
}

#[test]
fn restore_apply_update_existing_edits_changed_matched_items() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let call_log = temp.path().join("bw-calls.log");
    let archive_path = temp.path().join("existing-item.yabbt");
    write_sample_archive(&archive_path);

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
        "--update-existing",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_LOG", &call_log)
    .assert()
    .success()
    .stdout(predicate::str::contains("restore applied"))
    .stdout(predicate::str::contains("mode: create-and-update"))
    .stdout(predicate::str::contains("items_created: 0"))
    .stdout(predicate::str::contains("items_updated: 1"))
    .stdout(predicate::str::contains("items_update_skipped: 0"))
    .stdout(predicate::str::contains("Secret Login").not())
    .stdout(predicate::str::contains("secret note").not())
    .stdout(predicate::str::contains("hunter2").not());

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    let edit_item_call = calls
        .lines()
        .find(|line| line.starts_with("edit item item-1 "))
        .expect("edit item call");
    let payload = decode_item_payload_arg(edit_item_call, 3);
    assert_eq!(payload["name"], "Secret Login");
    assert!(!calls.contains("delete item"));
}

#[test]
fn restore_apply_prune_deletes_target_only_data_to_trash_by_default() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let call_log = temp.path().join("bw-calls.log");
    let (target_export, target_items) = write_prune_target_files(temp.path());
    let archive_path = temp.path().join("backup.yabbt");
    write_sample_archive(&archive_path);

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
        "--prune",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_LOG", &call_log)
    .env("YABBT_FAKE_BW_EXPORT", &target_export)
    .env("YABBT_FAKE_BW_ITEMS", &target_items)
    .assert()
    .success()
    .stdout(predicate::str::contains("restore applied"))
    .stdout(predicate::str::contains("items_updated: 0"))
    // The matched item only has a target-only extra attachment, which prune
    // removes; it is not an item update.
    .stdout(predicate::str::contains("items_update_skipped: 0"))
    .stdout(predicate::str::contains("items_unchanged: 1"))
    .stdout(predicate::str::contains("items_deleted: 1"))
    .stdout(predicate::str::contains("attachments_deleted: 1"))
    .stdout(predicate::str::contains("folders_deleted: 1"))
    .stdout(predicate::str::contains("items_delete_skipped: 0"))
    .stdout(predicate::str::contains("prune_permanent: false"))
    .stdout(predicate::str::contains("target-only-item"))
    .stdout(predicate::str::contains("target-extra-attachment"))
    .stdout(predicate::str::contains("extra-folder"))
    .stdout(predicate::str::contains("Target Only Secret").not())
    .stdout(predicate::str::contains("extra.txt").not());

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    assert!(calls.contains("delete attachment target-extra-attachment --itemid item-1"));
    assert!(calls.contains("delete item target-only-item"));
    assert!(!calls.contains("delete item target-only-item --permanent"));
    assert!(calls.contains("delete folder extra-folder"));
    assert!(!calls.contains("edit item item-1 "));
}

#[test]
fn restore_apply_prune_permanent_passes_permanent_for_item_deletes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let call_log = temp.path().join("bw-calls.log");
    let (target_export, target_items) = write_prune_target_files(temp.path());
    let archive_path = temp.path().join("backup.yabbt");
    write_sample_archive(&archive_path);

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
        "--prune",
        "--prune-permanent",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_LOG", &call_log)
    .env("YABBT_FAKE_BW_EXPORT", &target_export)
    .env("YABBT_FAKE_BW_ITEMS", &target_items)
    .assert()
    .success()
    .stdout(predicate::str::contains("items_deleted: 1"))
    .stdout(predicate::str::contains("prune_permanent: true"));

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    assert!(calls.contains("delete item target-only-item --permanent"));
}

#[test]
fn restore_apply_verify_after_checks_updated_item_ids() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let call_log = temp.path().join("bw-calls.log");
    let archive_path = temp.path().join("existing-item.yabbt");
    write_sample_archive(&archive_path);

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
        "--update-existing",
        "--verify-after",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_LOG", &call_log)
    .assert()
    .success()
    .stdout(predicate::str::contains("post_apply_verified: true"))
    .stdout(predicate::str::contains("created_items_verified: 0"))
    .stdout(predicate::str::contains("updated_items_verified: 1"));

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    assert!(calls.contains("get item item-1"));
}

#[test]
fn restore_apply_update_existing_uploads_missing_attachments_only() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let call_log = temp.path().join("bw-calls.log");
    let archive_path = temp.path().join("existing-item-extra-attachment.yabbt");
    write_existing_item_extra_attachment_archive(&archive_path);

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    let output = cmd
        .args([
            "restore",
            "--target",
            "bw",
            archive_path.to_str().expect("archive path"),
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
            "--apply",
            "--update-existing",
            "--progress",
            "json",
        ])
        .env("PATH", path)
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .env("YABBT_FAKE_BW_LOG", &call_log)
        .output()
        .expect("run update-existing restore with progress");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let events = stderr
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("progress json"))
        .collect::<Vec<_>>();
    assert!(stdout.contains("restore applied"));
    assert!(stdout.contains("items_updated: 1"));
    assert!(stdout.contains("attachments_uploaded: 1"));
    assert!(!stdout.contains("existing-extra.txt"));
    assert!(!stdout.contains("existing-extra-code"));
    assert!(events.iter().any(|event| {
        event.get("kind").and_then(serde_json::Value::as_str) == Some("count")
            && event.get("label").and_then(serde_json::Value::as_str)
                == Some("uploading attachments")
            && event.get("completed").and_then(serde_json::Value::as_u64) == Some(1)
            && event.get("total").and_then(serde_json::Value::as_u64) == Some(1)
    }));

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    let attachment_uploads = calls
        .lines()
        .filter(|line| line.starts_with("create attachment "))
        .collect::<Vec<_>>();
    assert_eq!(attachment_uploads.len(), 1);
    assert!(attachment_uploads[0].contains("--itemid item-1"));
    assert!(calls.contains("edit item item-1 "));
}

#[test]
fn restore_apply_update_existing_does_not_duplicate_attachment_with_unreliable_target_size() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let call_log = temp.path().join("bw-calls.log");
    let target_items = temp
        .path()
        .join("target-items-unreliable-attachment-size.json");
    fs::write(
        &target_items,
        r#"[
  {
    "id": "item-1",
    "attachments": [
      {"id":"attachment-1","fileName":"recovery.txt","size":999}
    ]
  }
]"#,
    )
    .expect("write target items");
    let archive_path = temp.path().join("backup.yabbt");
    write_sample_archive(&archive_path);

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
        "--update-existing",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_LOG", &call_log)
    .env("YABBT_FAKE_BW_ITEMS", &target_items)
    .assert()
    .success()
    .stdout(predicate::str::contains("restore applied"))
    .stdout(predicate::str::contains("attachments_uploaded: 0"));

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    assert!(!calls.contains("create attachment "));
}

#[test]
fn restore_apply_verify_after_fails_when_created_item_is_missing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let archive_path = write_new_item_archive(temp.path());

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
        "--verify-after",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_GET_CREATED_FAIL", "1")
    .assert()
    .failure()
    .stdout(predicate::str::contains("restore applied"))
    .stderr(predicate::str::contains("post-apply verification failed"))
    .stderr(predicate::str::contains("Secret Login").not())
    .stderr(predicate::str::contains("secret note").not())
    .stderr(predicate::str::contains("hunter2").not());
}

#[test]
fn restore_apply_mark_restored_writes_hidden_yabbt_marker_fields() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let call_log = temp.path().join("bw-calls.log");
    let archive_path = write_new_item_archive(temp.path());

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
        "--mark-restored",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_LOG", &call_log)
    .assert()
    .success()
    .stdout(predicate::str::contains("restore applied"))
    .stdout(predicate::str::contains("marked_restored: true"));

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    let create_item_call = calls
        .lines()
        .find(|line| line.starts_with("create item "))
        .expect("create item call logged");
    let encoded = create_item_call
        .split_whitespace()
        .nth(2)
        .expect("encoded item payload");
    let decoded = BASE64.decode(encoded).expect("decode item payload");
    let payload: serde_json::Value = serde_json::from_slice(&decoded).expect("json payload");
    let fields = payload["fields"].as_array().expect("fields array");

    assert!(fields.iter().any(|field| {
        field["name"] == "yabbt.source_item_id"
            && field["value"] == "new-item"
            && field["type"] == 1
    }));
    assert!(fields.iter().any(|field| {
        field["name"] == "yabbt.source_fingerprint"
            && field["value"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
            && field["type"] == 1
    }));
    assert!(fields.iter().any(|field| {
        field["name"] == "yabbt.archive_version" && field["value"] == "1" && field["type"] == 1
    }));
}

#[test]
fn restore_apply_writes_single_yabbt_map_item_by_default() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let call_log = temp.path().join("bw-calls.log");
    let archive_path = write_new_item_archive(temp.path());

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_LOG", &call_log)
    .assert()
    .success()
    .stdout(predicate::str::contains("restore applied"))
    .stdout(predicate::str::contains("restore_map_updated: true"))
    .stdout(predicate::str::contains("marked_restored: false"));

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    let payloads = calls
        .lines()
        .filter(|line| line.starts_with("create item "))
        .map(decode_create_item_payload)
        .collect::<Vec<_>>();
    assert_eq!(payloads.len(), 2);

    let map_payload = payloads
        .iter()
        .find(|payload| payload["name"] == "yabbt restore map - do not edit")
        .expect("restore map item payload");
    assert_eq!(map_payload["type"], 2);
    assert_eq!(map_payload["secureNote"]["type"], 0);
    let fields = map_payload["fields"].as_array().expect("fields array");
    let map_field = fields
        .iter()
        .find(|field| field["name"] == "yabbt.restore_map" && field["type"] == 1)
        .expect("hidden restore map field");
    let map: serde_json::Value =
        serde_json::from_str(map_field["value"].as_str().expect("map field value"))
            .expect("restore map json");
    assert_eq!(map["version"], 1);
    assert_eq!(
        map["entries"]["new-item"]["target_item_id"],
        "created-new-item"
    );
    assert!(
        map["entries"]["new-item"]["source_fingerprint"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );

    let restored_item_payload = payloads
        .iter()
        .find(|payload| payload["name"] == "Secret Login")
        .expect("restored item payload");
    assert!(
        restored_item_payload["fields"]
            .as_array()
            .expect("restored item fields")
            .iter()
            .all(|field| field["name"] != "yabbt.source_item_id")
    );
}

#[test]
fn restore_apply_backfills_restore_map_for_existing_target_items() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let call_log = temp.path().join("bw-calls.log");
    let archive_path = temp.path().join("existing-item.yabbt");
    write_sample_archive(&archive_path);

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_LOG", &call_log)
    .assert()
    .success()
    .stdout(predicate::str::contains("restore applied"))
    .stdout(predicate::str::contains("items_created: 0"))
    .stdout(predicate::str::contains("items_update_skipped: 1"))
    .stdout(predicate::str::contains("restore_map_updated: true"));

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    let payloads = calls
        .lines()
        .filter(|line| line.starts_with("create item "))
        .map(decode_create_item_payload)
        .collect::<Vec<_>>();
    assert_eq!(payloads.len(), 1);

    let map_payload = payloads
        .iter()
        .find(|payload| payload["name"] == "yabbt restore map - do not edit")
        .expect("restore map item payload");
    let fields = map_payload["fields"].as_array().expect("fields array");
    let map_field = fields
        .iter()
        .find(|field| field["name"] == "yabbt.restore_map" && field["type"] == 1)
        .expect("hidden restore map field");
    let map: serde_json::Value =
        serde_json::from_str(map_field["value"].as_str().expect("map field value"))
            .expect("restore map json");
    assert_eq!(map["entries"]["item-1"]["target_item_id"], "item-1");
    assert!(
        map["entries"]["item-1"]["source_fingerprint"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
}

#[test]
fn restore_apply_repairs_stale_restore_map_entries() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let call_log = temp.path().join("bw-calls.log");
    let archive_path = write_new_item_archive(temp.path());
    let target_export = temp.path().join("target-with-stale-map.json");
    fs::write(
        &target_export,
        r#"{
  "encrypted": false,
  "folders": [],
  "items": [
    {
      "id": "restore-map-id",
      "folderId": null,
      "type": 2,
      "name": "yabbt restore map - do not edit",
      "notes": "Managed by yabbt. Do not edit.",
      "favorite": false,
      "secureNote": { "type": 0 },
      "fields": [
        {
          "name": "yabbt.restore_map",
          "value": "{\"version\":1,\"entries\":{\"stale-item\":{\"target_item_id\":\"missing-target-id\",\"source_fingerprint\":\"old\"}}}",
          "type": 1
        }
      ]
    }
  ]
}"#,
    )
    .expect("write target export");

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_LOG", &call_log)
    .env("YABBT_FAKE_BW_EXPORT", &target_export)
    .assert()
    .success()
    .stdout(predicate::str::contains("restore applied"))
    .stdout(predicate::str::contains("restore_map_updated: true"));

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    let edit_map_call = calls
        .lines()
        .find(|line| line.starts_with("edit item restore-map-id "))
        .expect("restore map edit call");
    let map_payload = decode_item_payload_arg(edit_map_call, 3);
    let fields = map_payload["fields"].as_array().expect("fields array");
    let map_field = fields
        .iter()
        .find(|field| field["name"] == "yabbt.restore_map" && field["type"] == 1)
        .expect("hidden restore map field");
    let map: serde_json::Value =
        serde_json::from_str(map_field["value"].as_str().expect("map field value"))
            .expect("restore map json");
    assert!(map["entries"]["stale-item"].is_null());
    assert_eq!(
        map["entries"]["new-item"]["target_item_id"],
        "created-new-item"
    );
}

#[test]
fn restore_apply_no_restore_map_skips_yabbt_map_item() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    write_fake_bw(&bw_path);
    let call_log = temp.path().join("bw-calls.log");
    let archive_path = write_new_item_archive(temp.path());

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
        "--no-restore-map",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_LOG", &call_log)
    .assert()
    .success()
    .stdout(predicate::str::contains("restore applied"))
    .stdout(predicate::str::contains("restore_map_updated: false"));

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    let payloads = calls
        .lines()
        .filter(|line| line.starts_with("create item "))
        .map(decode_create_item_payload)
        .collect::<Vec<_>>();
    assert_eq!(payloads.len(), 1);
    assert!(
        payloads
            .iter()
            .all(|payload| { payload["name"] != "yabbt restore map - do not edit" })
    );
}

#[test]
fn restore_apply_twice_with_stateful_fake_bw_does_not_duplicate_items() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    let state_path = temp.path().join("bw-state.json");
    write_stateful_fake_bw(&bw_path, &state_path);
    let call_log = temp.path().join("bw-calls.log");
    let archive_path = write_new_item_archive(temp.path());

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let restore_args = [
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
    ];

    let mut first = Command::cargo_bin("yabbt").expect("binary exists");
    first
        .args(restore_args)
        .env("PATH", &path)
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .env("YABBT_STATEFUL_BW_STATE", &state_path)
        .env("YABBT_FAKE_BW_LOG", &call_log)
        .assert()
        .success()
        .stdout(predicate::str::contains("items_created: 1"))
        .stdout(predicate::str::contains("folders_created: 1"));

    let mut second = Command::cargo_bin("yabbt").expect("binary exists");
    second
        .args(restore_args)
        .env("PATH", path)
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .env("YABBT_STATEFUL_BW_STATE", &state_path)
        .env("YABBT_FAKE_BW_LOG", &call_log)
        .assert()
        .success()
        .stdout(predicate::str::contains("items_created: 0"))
        .stdout(predicate::str::contains("folders_created: 0"))
        .stdout(predicate::str::contains("items_unchanged: 1"));

    let state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(state_path).expect("read state"))
            .expect("state json");
    let items = state["items"].as_array().expect("items array");
    let restored_items = items
        .iter()
        .filter(|item| item["name"] == "Secret Login")
        .count();
    let restore_map_items = items
        .iter()
        .filter(|item| item["name"] == "yabbt restore map - do not edit")
        .count();
    assert_eq!(restored_items, 1);
    assert_eq!(restore_map_items, 1);

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    let restored_creates = calls
        .lines()
        .filter(|line| line.starts_with("create item "))
        .map(decode_create_item_payload)
        .filter(|payload| payload["name"] == "Secret Login")
        .count();
    assert_eq!(restored_creates, 1);
}

#[test]
fn restore_apply_update_existing_twice_with_stateful_fake_bw_is_idempotent() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    let state_path = temp.path().join("bw-state.json");
    write_stateful_fake_bw(&bw_path, &state_path);
    fs::write(
        &state_path,
        r#"{
  "encrypted": false,
  "folders": [
    {
      "id": "folder-1",
      "name": "Sensitive Folder"
    }
  ],
  "items": [
    {
      "id": "item-1",
      "folderId": "folder-1",
      "type": 1,
      "name": "Secret Login",
      "notes": "old note",
      "favorite": false,
      "login": {
        "username": "alice",
        "password": "hunter2",
        "totp": "otpauth://totp/example",
        "uris": [
          {
            "uri": "https://example.test"
          }
        ]
      },
      "fields": [
        {
          "name": "pin",
          "value": "1234",
          "type": 1
        }
      ],
      "attachments": []
    }
  ]
}"#,
    )
    .expect("seed stateful fake bw state");
    let call_log = temp.path().join("bw-calls.log");
    let archive_path = temp.path().join("existing-item.yabbt");
    write_sample_archive(&archive_path);

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let restore_args = [
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
        "--update-existing",
    ];

    let mut first = Command::cargo_bin("yabbt").expect("binary exists");
    first
        .args(restore_args)
        .env("PATH", &path)
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .env("YABBT_STATEFUL_BW_STATE", &state_path)
        .env("YABBT_FAKE_BW_LOG", &call_log)
        .assert()
        .success()
        .stdout(predicate::str::contains("items_created: 0"))
        .stdout(predicate::str::contains("items_updated: 1"))
        .stdout(predicate::str::contains("attachments_uploaded: 1"));

    let mut second = Command::cargo_bin("yabbt").expect("binary exists");
    second
        .args(restore_args)
        .env("PATH", path)
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .env("YABBT_STATEFUL_BW_STATE", &state_path)
        .env("YABBT_FAKE_BW_LOG", &call_log)
        .assert()
        .success()
        .stdout(predicate::str::contains("items_created: 0"))
        .stdout(predicate::str::contains("items_updated: 0"))
        .stdout(predicate::str::contains("attachments_uploaded: 0"))
        .stdout(predicate::str::contains("items_unchanged: 1"));

    let state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(state_path).expect("read state"))
            .expect("state json");
    let items = state["items"].as_array().expect("items array");
    let restored_item = items
        .iter()
        .find(|item| item["id"] == "item-1")
        .expect("restored item");
    assert_eq!(restored_item["notes"], "secret note");
    assert_eq!(
        restored_item["attachments"]
            .as_array()
            .expect("attachments array")
            .len(),
        1
    );
    let restore_map_items = items
        .iter()
        .filter(|item| item["name"] == "yabbt restore map - do not edit")
        .count();
    assert_eq!(restore_map_items, 1);

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    let item_edits = calls
        .lines()
        .filter(|line| line.starts_with("edit item item-1 "))
        .count();
    let attachment_uploads = calls
        .lines()
        .filter(|line| line.starts_with("create attachment "))
        .count();
    assert_eq!(item_edits, 1);
    assert_eq!(attachment_uploads, 1);
}

#[test]
fn restore_apply_repairs_stale_restore_map_with_stateful_fake_bw() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    let state_path = temp.path().join("bw-state.json");
    write_stateful_fake_bw(&bw_path, &state_path);
    fs::write(
        &state_path,
        r#"{
  "encrypted": false,
  "folders": [],
  "items": [
    {
      "id": "restore-map-id",
      "folderId": null,
      "type": 2,
      "name": "yabbt restore map - do not edit",
      "notes": "Managed by yabbt. Do not edit.",
      "favorite": false,
      "secureNote": { "type": 0 },
      "fields": [
        {
          "name": "yabbt.restore_map",
          "value": "{\"version\":1,\"entries\":{\"stale-item\":{\"target_item_id\":\"missing-target-id\",\"source_fingerprint\":\"old\"}}}",
          "type": 1
        }
      ]
    }
  ]
}"#,
    )
    .expect("seed stale restore map state");
    let call_log = temp.path().join("bw-calls.log");
    let archive_path = write_new_item_archive(temp.path());

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let restore_args = [
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
    ];

    let mut first = Command::cargo_bin("yabbt").expect("binary exists");
    first
        .args(restore_args)
        .env("PATH", &path)
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .env("YABBT_STATEFUL_BW_STATE", &state_path)
        .env("YABBT_FAKE_BW_LOG", &call_log)
        .assert()
        .success()
        .stdout(predicate::str::contains("items_created: 1"))
        .stdout(predicate::str::contains("restore_map_updated: true"));

    let mut second = Command::cargo_bin("yabbt").expect("binary exists");
    second
        .args(restore_args)
        .env("PATH", path)
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .env("YABBT_STATEFUL_BW_STATE", &state_path)
        .env("YABBT_FAKE_BW_LOG", &call_log)
        .assert()
        .success()
        .stdout(predicate::str::contains("items_created: 0"))
        .stdout(predicate::str::contains("items_unchanged: 1"));

    let state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(state_path).expect("read state"))
            .expect("state json");
    let items = state["items"].as_array().expect("items array");
    let restored_items = items
        .iter()
        .filter(|item| item["name"] == "Secret Login")
        .count();
    let restore_map_items = items
        .iter()
        .filter(|item| item["name"] == "yabbt restore map - do not edit")
        .collect::<Vec<_>>();
    assert_eq!(restored_items, 1);
    assert_eq!(restore_map_items.len(), 1);

    let map_field = restore_map_items[0]["fields"]
        .as_array()
        .expect("map fields")
        .iter()
        .find(|field| field["name"] == "yabbt.restore_map")
        .expect("restore map field");
    let map: serde_json::Value =
        serde_json::from_str(map_field["value"].as_str().expect("restore map json"))
            .expect("parse restore map");
    assert!(map["entries"]["stale-item"].is_null());
    assert!(
        map["entries"]["new-item"]["target_item_id"]
            .as_str()
            .is_some_and(|target_id| !target_id.is_empty())
    );
    assert!(
        map["entries"]["new-item"]["source_fingerprint"]
            .as_str()
            .is_some_and(|fingerprint| !fingerprint.is_empty())
    );

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    let restored_creates = calls
        .lines()
        .filter(|line| line.starts_with("create item "))
        .map(decode_create_item_payload)
        .filter(|payload| payload["name"] == "Secret Login")
        .count();
    assert_eq!(restored_creates, 1);
}

#[test]
fn restore_apply_no_restore_map_twice_with_stateful_fake_bw_uses_fingerprint_fallback() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    let state_path = temp.path().join("bw-state.json");
    write_stateful_fake_bw(&bw_path, &state_path);
    let call_log = temp.path().join("bw-calls.log");
    let archive_path = write_new_item_archive(temp.path());

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let restore_args = [
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
        "--no-restore-map",
    ];

    let mut first = Command::cargo_bin("yabbt").expect("binary exists");
    first
        .args(restore_args)
        .env("PATH", &path)
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .env("YABBT_STATEFUL_BW_STATE", &state_path)
        .env("YABBT_FAKE_BW_LOG", &call_log)
        .assert()
        .success()
        .stdout(predicate::str::contains("items_created: 1"))
        .stdout(predicate::str::contains("restore_map_updated: false"));

    let mut second = Command::cargo_bin("yabbt").expect("binary exists");
    second
        .args(restore_args)
        .env("PATH", path)
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .env("YABBT_STATEFUL_BW_STATE", &state_path)
        .env("YABBT_FAKE_BW_LOG", &call_log)
        .assert()
        .success()
        .stdout(predicate::str::contains("items_created: 0"))
        .stdout(predicate::str::contains("restore_map_updated: false"))
        .stdout(predicate::str::contains("items_unchanged: 1"));

    let state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(state_path).expect("read state"))
            .expect("state json");
    let items = state["items"].as_array().expect("items array");
    let restored_items = items
        .iter()
        .filter(|item| item["name"] == "Secret Login")
        .count();
    let restore_map_items = items
        .iter()
        .filter(|item| item["name"] == "yabbt restore map - do not edit")
        .count();
    assert_eq!(restored_items, 1);
    assert_eq!(restore_map_items, 0);

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    let restored_creates = calls
        .lines()
        .filter(|line| line.starts_with("create item "))
        .map(decode_create_item_payload)
        .filter(|payload| payload["name"] == "Secret Login")
        .count();
    assert_eq!(restored_creates, 1);
}

#[test]
fn restore_apply_prune_twice_with_stateful_fake_bw_is_idempotent() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    let state_path = temp.path().join("bw-state.json");
    write_stateful_fake_bw(&bw_path, &state_path);
    fs::write(
        &state_path,
        r#"{
  "encrypted": false,
  "folders": [
    {"id":"folder-1","name":"Sensitive Folder"},
    {"id":"extra-folder","name":"Extra Folder"}
  ],
  "items": [
    {
      "id":"item-1",
      "folderId":"folder-1",
      "type":1,
      "name":"Secret Login",
      "notes":"secret note",
      "favorite":false,
      "login":{
        "username":"alice",
        "password":"hunter2",
        "totp":"otpauth://totp/example",
        "uris":[{"uri":"https://example.test"}]
      },
      "fields":[{"name":"pin","value":"1234","type":1}],
      "attachments":[
        {"id":"attachment-1","fileName":"recovery.txt","size":13},
        {"id":"extra-attachment","fileName":"extra.txt","size":9}
      ]
    },
    {
      "id":"target-only-item",
      "folderId":"extra-folder",
      "type":2,
      "name":"Target Only Secret",
      "notes":"delete me",
      "favorite":false,
      "secureNote":{"type":0},
      "fields":[],
      "attachments":[]
    }
  ]
}"#,
    )
    .expect("seed stateful prune state");
    let call_log = temp.path().join("bw-calls.log");
    let archive_path = temp.path().join("existing-item.yabbt");
    write_sample_archive(&archive_path);

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let restore_args = [
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
        "--prune",
    ];

    let mut first = Command::cargo_bin("yabbt").expect("binary exists");
    first
        .args(restore_args)
        .env("PATH", &path)
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .env("YABBT_STATEFUL_BW_STATE", &state_path)
        .env("YABBT_FAKE_BW_LOG", &call_log)
        .assert()
        .success()
        .stdout(predicate::str::contains("items_deleted: 1"))
        .stdout(predicate::str::contains("attachments_deleted: 1"))
        .stdout(predicate::str::contains("folders_deleted: 1"));

    let mut second = Command::cargo_bin("yabbt").expect("binary exists");
    second
        .args(restore_args)
        .env("PATH", path)
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .env("YABBT_STATEFUL_BW_STATE", &state_path)
        .env("YABBT_FAKE_BW_LOG", &call_log)
        .assert()
        .success()
        .stdout(predicate::str::contains("items_deleted: 0"))
        .stdout(predicate::str::contains("attachments_deleted: 0"))
        .stdout(predicate::str::contains("folders_deleted: 0"))
        .stdout(predicate::str::contains("items_unchanged: 1"));

    let state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(state_path).expect("read state"))
            .expect("state json");
    let items = state["items"].as_array().expect("items array");
    assert!(items.iter().all(|item| item["id"] != "target-only-item"));
    let folders = state["folders"].as_array().expect("folders array");
    assert!(folders.iter().all(|folder| folder["id"] != "extra-folder"));
    let restored_item = items
        .iter()
        .find(|item| item["id"] == "item-1")
        .expect("matched item remains");
    assert!(
        restored_item["attachments"]
            .as_array()
            .expect("attachments array")
            .iter()
            .all(|attachment| attachment["id"] != "extra-attachment")
    );

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    assert_eq!(
        calls
            .lines()
            .filter(|line| line.starts_with("delete item target-only-item"))
            .count(),
        1
    );
    assert_eq!(
        calls
            .lines()
            .filter(|line| line.starts_with("delete attachment extra-attachment --itemid item-1"))
            .count(),
        1
    );
    assert_eq!(
        calls
            .lines()
            .filter(|line| line.starts_with("delete folder extra-folder"))
            .count(),
        1
    );
}

#[test]
fn restore_apply_prune_verify_after_checks_deleted_objects() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let bw_path = bin_dir.join("bw");
    let state_path = temp.path().join("bw-state.json");
    write_stateful_fake_bw(&bw_path, &state_path);
    fs::write(
        &state_path,
        r#"{
  "encrypted": false,
  "folders": [
    {"id":"folder-1","name":"Sensitive Folder"},
    {"id":"extra-folder","name":"Extra Folder"}
  ],
  "items": [
    {
      "id":"item-1",
      "folderId":"folder-1",
      "type":1,
      "name":"Secret Login",
      "notes":"secret note",
      "favorite":false,
      "login":{
        "username":"alice",
        "password":"hunter2",
        "totp":"otpauth://totp/example",
        "uris":[{"uri":"https://example.test"}]
      },
      "fields":[{"name":"pin","value":"1234","type":1}],
      "attachments":[
        {"id":"attachment-1","fileName":"recovery.txt","size":13},
        {"id":"extra-attachment","fileName":"extra.txt","size":9}
      ]
    },
    {
      "id":"target-only-item",
      "folderId":"extra-folder",
      "type":2,
      "name":"Target Only Secret",
      "notes":"delete me",
      "favorite":false,
      "secureNote":{"type":0},
      "fields":[],
      "attachments":[]
    }
  ]
}"#,
    )
    .expect("seed stateful prune verification state");
    let call_log = temp.path().join("bw-calls.log");
    let archive_path = temp.path().join("existing-item.yabbt");
    write_sample_archive(&archive_path);

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--apply",
        "--prune",
        "--verify-after",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_STATEFUL_BW_STATE", &state_path)
    .env("YABBT_FAKE_BW_LOG", &call_log)
    .assert()
    .success()
    .stdout(predicate::str::contains("post_apply_verified: true"))
    .stdout(predicate::str::contains("deleted_items_verified: 1"))
    .stdout(predicate::str::contains("deleted_attachments_verified: 1"))
    .stdout(predicate::str::contains("deleted_folders_verified: 1"))
    .stdout(predicate::str::contains("Target Only Secret").not())
    .stdout(predicate::str::contains("extra.txt").not())
    .stdout(predicate::str::contains("Extra Folder").not());

    let calls = fs::read_to_string(call_log).expect("read fake bw call log");
    assert!(calls.contains("delete item target-only-item"));
    assert!(calls.contains("delete attachment extra-attachment --itemid item-1"));
    assert!(calls.contains("delete folder extra-folder"));
}

#[cfg(unix)]
#[test]
fn bw_login_creates_profile_dir_and_runs_config_and_login() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    write_fake_bw(&bin_dir.join("bw"));
    let data_home = temp.path().join("data");
    let call_log = temp.path().join("bw-calls.log");
    let env_log = temp.path().join("bw-env.log");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "bw-login",
        "--profile",
        "prod",
        "--server-url",
        "https://vault.example.test",
    ])
    .env("PATH", path)
    .env("XDG_DATA_HOME", &data_home)
    .env("YABBT_FAKE_BW_STATUS", "unauthenticated")
    .env("YABBT_FAKE_BW_LOG", &call_log)
    .env("YABBT_FAKE_BW_ENV_LOG", &env_log)
    .assert()
    .success()
    .stdout(predicate::str::contains("bw profile `prod` logged in"));

    let profile_dir = data_home.join("yabbt").join("bw-profiles").join("prod");
    assert!(profile_dir.is_dir(), "profile dir created");

    let calls = fs::read_to_string(&call_log).expect("call log");
    assert!(calls.contains("config server https://vault.example.test"));
    assert!(calls.lines().any(|line| line == "login"));

    let env_lines = fs::read_to_string(&env_log).expect("env log");
    let expected = format!("appdata={}", profile_dir.display());
    for line in env_lines.lines() {
        assert!(
            line.contains(&expected),
            "bw call ran outside the profile dir: {line}"
        );
    }
}

#[test]
fn bw_login_rejects_invalid_profile_name() {
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args(["bw-login", "--profile", "../escape"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid profile name"));
}

#[test]
fn bw_login_reports_already_logged_in_profile() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    write_fake_bw(&bin_dir.join("bw"));
    let data_home = temp.path().join("data");
    let call_log = temp.path().join("bw-calls.log");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args(["bw-login", "--profile", "prod"])
        .env("PATH", path)
        .env("XDG_DATA_HOME", &data_home)
        .env("YABBT_FAKE_BW_STATUS", "locked")
        .env("YABBT_FAKE_BW_LOG", &call_log)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "bw profile `prod` is already logged in",
        ));

    assert!(!call_log.exists(), "no login or config calls were made");
}

#[test]
fn backup_with_bw_profile_runs_bw_inside_profile_dir() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    write_fake_bw(&bin_dir.join("bw"));
    let data_home = temp.path().join("data");
    let env_log = temp.path().join("bw-env.log");
    let archive_path = temp.path().join("backup.yabbt");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "bw",
        "--bw-profile",
        "prod",
        "--out",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("PATH", path)
    .env("XDG_DATA_HOME", &data_home)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_ENV_LOG", &env_log)
    .assert()
    .success()
    .stdout(predicate::str::contains("wrote backup archive"));

    let profile_dir = data_home.join("yabbt").join("bw-profiles").join("prod");
    let env_lines = fs::read_to_string(&env_log).expect("env log");
    assert!(!env_lines.is_empty());
    let expected = format!("appdata={}", profile_dir.display());
    for line in env_lines.lines() {
        assert!(
            line.contains(&expected),
            "bw call ran outside the profile dir: {line}"
        );
    }
}

#[test]
fn backup_with_locked_profile_unlocks_interactively_and_uses_session() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    write_fake_bw(&bin_dir.join("bw"));
    let data_home = temp.path().join("data");
    let env_log = temp.path().join("bw-env.log");
    let archive_path = temp.path().join("backup.yabbt");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "bw",
        "--bw-profile",
        "prod",
        "--out",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("PATH", path)
    .env("XDG_DATA_HOME", &data_home)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_STATUS", "locked")
    .env("YABBT_FAKE_BW_SESSION", "fake-session-key")
    .env("YABBT_FAKE_BW_ENV_LOG", &env_log)
    .assert()
    .success()
    .stderr(predicate::str::contains("unlocking bw profile `prod`"))
    .stdout(predicate::str::contains("wrote backup archive"));

    let env_lines = fs::read_to_string(&env_log).expect("env log");
    let lines = env_lines.lines().collect::<Vec<_>>();
    assert!(lines[0].starts_with("status "), "first call checks status");
    assert!(lines.iter().any(|line| line.starts_with("unlock ")));
    let after_unlock = lines
        .iter()
        .skip_while(|line| !line.starts_with("unlock "))
        .skip(1)
        .collect::<Vec<_>>();
    assert!(!after_unlock.is_empty());
    for line in after_unlock {
        assert!(
            line.contains("session=fake-session-key"),
            "post-unlock bw call is missing the captured session: {line}"
        );
    }
}

#[test]
fn backup_with_unauthenticated_profile_points_at_bw_login() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    write_fake_bw(&bin_dir.join("bw"));
    let data_home = temp.path().join("data");
    let archive_path = temp.path().join("backup.yabbt");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "bw",
        "--bw-profile",
        "prod",
        "--out",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("PATH", path)
    .env("XDG_DATA_HOME", &data_home)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_STATUS", "unauthenticated")
    .assert()
    .failure()
    .stderr(predicate::str::contains(
        "run `yabbt bw-login --profile prod`",
    ));

    assert!(!archive_path.exists(), "no archive written");
}

/// Wrap the regular fake `bw` so every invocation appends its full
/// environment (`NAME=value` per line, then a `--` separator) to `env_dump`.
/// The dump path is baked into the script so it does not depend on any
/// variable reaching the child.
#[cfg(unix)]
fn write_env_dumping_fake_bw(bin_dir: &Path, env_dump: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let inner = bin_dir.join("bw-impl");
    write_fake_bw(&inner);
    let wrapper = bin_dir.join("bw");
    fs::write(
        &wrapper,
        format!(
            "#!/usr/bin/env bash\nset -euo pipefail\nenv >> '{}'\nprintf -- '--\\n' >> '{}'\nexec '{}' \"$@\"\n",
            env_dump.display(),
            env_dump.display(),
            inner.display()
        ),
    )
    .expect("write env-dumping bw");
    let mut permissions = fs::metadata(&wrapper).expect("metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&wrapper, permissions).expect("chmod env-dumping bw");
}

/// Env var names seen by each `bw` invocation recorded by
/// `write_env_dumping_fake_bw`.
fn bw_invocation_envs(env_dump: &Path) -> Vec<Vec<(String, String)>> {
    let dump = fs::read_to_string(env_dump).expect("env dump");
    dump.split("--\n")
        .filter(|block| !block.trim().is_empty())
        .map(|block| {
            block
                .lines()
                .filter_map(|line| line.split_once('='))
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect()
        })
        .collect()
}

/// Variables that change `bw`'s exit-status/output contract or disable TLS
/// verification. None of them may leak from yabbt's environment into `bw`.
const HOSTILE_BW_ENV: &[(&str, &str)] = &[
    ("BW_CLEANEXIT", "1"),
    ("BW_RESPONSE", "true"),
    ("BW_QUIET", "true"),
    ("BW_PRETTY", "true"),
    ("BW_RAW", "true"),
    ("BW_NOINTERACTION", "false"),
    ("NODE_TLS_REJECT_UNAUTHORIZED", "0"),
    ("NODE_OPTIONS", "--require /tmp/evil.js"),
];

#[cfg(unix)]
#[test]
fn backup_runs_bw_with_a_sanitized_environment() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let env_dump = temp.path().join("bw-env.dump");
    write_env_dumping_fake_bw(&bin_dir, &env_dump);
    let archive_path = temp.path().join("backup.yabbt");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "bw",
        "--out",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    // Ambient (non-profile) mode: the user's own bw session must reach bw.
    .env("BW_SESSION", "ambient-session-key")
    .env("NODE_EXTRA_CA_CERTS", "/etc/ssl/private-ca.pem")
    .env("HTTPS_PROXY", "http://proxy.example.test:3128")
    .env("LC_ALL", "C.UTF-8")
    .env("UNRELATED_SECRET", "must-not-leak")
    // Even an explicit passthrough request cannot re-admit hostile vars.
    .env(
        "YABBT_BW_ENV_PASSTHROUGH",
        "BW_CLEANEXIT,NODE_TLS_REJECT_UNAUTHORIZED,YABBT_FAKE_BW_*",
    );
    for (name, value) in HOSTILE_BW_ENV {
        cmd.env(name, value);
    }
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("wrote backup archive"));

    let invocations = bw_invocation_envs(&env_dump);
    assert!(!invocations.is_empty(), "bw was invoked");
    for env in invocations {
        let get = |name: &str| {
            env.iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        };
        for (name, _) in HOSTILE_BW_ENV {
            if *name == "BW_NOINTERACTION" {
                // yabbt sets this itself; the parent's value must not win.
                assert_eq!(get(name), Some("true"), "BW_NOINTERACTION override leaked");
            } else {
                assert_eq!(get(name), None, "{name} leaked into bw");
            }
        }
        assert_eq!(get("UNRELATED_SECRET"), None);
        assert_eq!(
            get("YABBT_TEST_PASSPHRASE"),
            None,
            "archive passphrase leaked"
        );
        assert_eq!(get("BW_SESSION"), Some("ambient-session-key"));
        assert_eq!(get("NODE_EXTRA_CA_CERTS"), Some("/etc/ssl/private-ca.pem"));
        assert_eq!(get("HTTPS_PROXY"), Some("http://proxy.example.test:3128"));
        assert_eq!(get("LC_ALL"), Some("C.UTF-8"));
        assert!(get("PATH").is_some());
    }
}

#[cfg(unix)]
#[test]
fn profile_bw_calls_ignore_ambient_session_and_hostile_env() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let env_dump = temp.path().join("bw-env.dump");
    write_env_dumping_fake_bw(&bin_dir, &env_dump);
    let data_home = temp.path().join("data");
    let archive_path = temp.path().join("backup.yabbt");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "bw",
        "--bw-profile",
        "prod",
        "--out",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("PATH", path)
    .env("XDG_DATA_HOME", &data_home)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("BW_SESSION", "other-account-session")
    .env("BITWARDENCLI_APPDATA_DIR", "/tmp/other-account")
    .env("BW_CLIENTSECRET", "other-account-api-secret")
    .env("NODE_EXTRA_CA_CERTS", "/etc/ssl/private-ca.pem");
    for (name, value) in HOSTILE_BW_ENV {
        cmd.env(name, value);
    }
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("wrote backup archive"));

    let profile_dir = data_home.join("yabbt").join("bw-profiles").join("prod");
    let invocations = bw_invocation_envs(&env_dump);
    assert!(!invocations.is_empty(), "bw was invoked");
    for env in invocations {
        let get = |name: &str| {
            env.iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(get("BW_CLEANEXIT"), None);
        assert_eq!(get("NODE_TLS_REJECT_UNAUTHORIZED"), None);
        assert_eq!(get("NODE_OPTIONS"), None);
        assert_eq!(get("BW_RESPONSE"), None);
        assert_eq!(
            get("BW_SESSION"),
            None,
            "ambient session leaked into profile"
        );
        assert_eq!(get("BW_CLIENTSECRET"), None);
        assert_eq!(
            get("BITWARDENCLI_APPDATA_DIR"),
            Some(profile_dir.to_str().expect("utf-8 profile dir"))
        );
        // Self-hosted servers with a private CA need this to keep working.
        assert_eq!(get("NODE_EXTRA_CA_CERTS"), Some("/etc/ssl/private-ca.pem"));
    }
}

/// Two-profile sync harness: a router `bw` dispatches by
/// BITWARDENCLI_APPDATA_DIR to a read-only source impl (which hard-fails on
/// any mutation) or the stateful target impl, logging every call per side.
struct SyncFixture {
    temp: tempfile::TempDir,
    path_env: String,
    data_home: PathBuf,
    source_log: PathBuf,
    target_log: PathBuf,
    target_state: PathBuf,
    archive_path: PathBuf,
}

fn setup_sync_fixture() -> SyncFixture {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    let source_impl = bin_dir.join("bw-source-impl");
    let target_impl = bin_dir.join("bw-target-impl");
    let target_state = temp.path().join("target-state.json");
    write_fake_bw(&source_impl);
    write_stateful_fake_bw(&target_impl, &target_state);

    let router = bin_dir.join("bw");
    fs::write(
        &router,
        r#"#!/usr/bin/env bash
set -euo pipefail
appdata="${BITWARDENCLI_APPDATA_DIR:-}"
if [ "$appdata" = "${YABBT_SYNC_SOURCE_DIR:?}" ]; then
  printf '%s\n' "$*" >> "${YABBT_SYNC_SOURCE_LOG:?}"
  case "$1" in
    create|edit|delete)
      echo "source profile must never be mutated: $*" >&2
      exit 1
      ;;
  esac
  exec "${YABBT_SYNC_SOURCE_IMPL:?}" "$@"
elif [ "$appdata" = "${YABBT_SYNC_TARGET_DIR:?}" ]; then
  printf '%s\n' "$*" >> "${YABBT_SYNC_TARGET_LOG:?}"
  exec "${YABBT_SYNC_TARGET_IMPL:?}" "$@"
else
  echo "bw ran outside a sync profile: appdata=$appdata" >&2
  exit 1
fi
"#,
    )
    .expect("write router bw");
    let mut permissions = fs::metadata(&router).expect("metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&router, permissions).expect("chmod router bw");

    SyncFixture {
        path_env: format!(
            "{}:{}",
            bin_dir.display(),
            std::env::var("PATH").unwrap_or_default()
        ),
        data_home: temp.path().join("data"),
        source_log: temp.path().join("source-calls.log"),
        target_log: temp.path().join("target-calls.log"),
        target_state,
        archive_path: temp.path().join("sync.yabbt"),
        temp,
    }
}

impl SyncFixture {
    fn profile_dir(&self, name: &str) -> PathBuf {
        self.data_home.join("yabbt").join("bw-profiles").join(name)
    }

    fn sync_command(&self, extra_args: &[&str]) -> Command {
        let bin_dir = self.temp.path().join("bin");
        let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
        cmd.args([
            "sync",
            "--source",
            "bw",
            "--target",
            "bw",
            "--source-profile",
            "src",
            "--target-profile",
            "tgt",
            "--out",
            self.archive_path.to_str().expect("archive path"),
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
        ])
        .args(extra_args)
        .env("PATH", &self.path_env)
        .env("XDG_DATA_HOME", &self.data_home)
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .env("YABBT_SYNC_SOURCE_DIR", self.profile_dir("src"))
        .env("YABBT_SYNC_TARGET_DIR", self.profile_dir("tgt"))
        .env("YABBT_SYNC_SOURCE_IMPL", bin_dir.join("bw-source-impl"))
        .env("YABBT_SYNC_TARGET_IMPL", bin_dir.join("bw-target-impl"))
        .env("YABBT_SYNC_SOURCE_LOG", &self.source_log)
        .env("YABBT_SYNC_TARGET_LOG", &self.target_log)
        .env("YABBT_STATEFUL_BW_STATE", &self.target_state);
        cmd
    }

    fn assert_source_was_never_mutated(&self) {
        let calls = fs::read_to_string(&self.source_log).expect("source call log");
        for line in calls.lines() {
            let operation = line.split_whitespace().next().unwrap_or_default();
            assert!(
                matches!(
                    operation,
                    "status" | "sync" | "--raw" | "export" | "list" | "get"
                ),
                "source profile saw a non-read operation: {line}"
            );
        }
    }
}

#[test]
fn sync_requires_both_profiles() {
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "sync",
        "--source",
        "bw",
        "--target",
        "bw",
        "--out",
        "sync.yabbt",
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .assert()
    .failure()
    .stderr(predicate::str::contains("sync requires --source-profile"));
}

#[test]
fn sync_rejects_same_source_and_target_profile() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "sync",
        "--source",
        "bw",
        "--target",
        "bw",
        "--source-profile",
        "prod",
        "--target-profile",
        "prod",
        "--out",
        "sync.yabbt",
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("XDG_DATA_HOME", temp.path())
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .assert()
    .failure()
    .stderr(predicate::str::contains(
        "sync source and target profiles must differ",
    ));
}

#[test]
fn sync_rejects_dry_run_with_apply() {
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "sync",
        "--source",
        "bw",
        "--target",
        "bw",
        "--dry-run",
        "--apply",
    ])
    .assert()
    .failure()
    .stderr(predicate::str::contains(
        "sync cannot combine --dry-run with --apply",
    ));
}

#[test]
fn sync_apply_only_flags_require_apply() {
    for flag in ["--verify-after", "--mark-restored", "--update-existing"] {
        let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
        cmd.args(["sync", "--source", "bw", "--target", "bw", flag])
            .assert()
            .failure()
            .stderr(predicate::str::contains(format!(
                "sync {flag} requires --apply"
            )));
    }
}

#[test]
fn sync_dry_run_writes_archive_and_prints_plan_without_mutations() {
    let fixture = setup_sync_fixture();

    fixture
        .sync_command(&[])
        .assert()
        .success()
        .stdout(predicate::str::contains("sync source bw -> target bw"))
        .stdout(predicate::str::contains("wrote backup archive"))
        .stdout(predicate::str::contains("restore plan"))
        .stdout(predicate::str::contains("items_to_create: 1"));

    let opened =
        open_archive(&fixture.archive_path, STRONG_TEST_PASSPHRASE).expect("open sync archive");
    assert_eq!(opened.vault.items[0].name, "Example Login");

    fixture.assert_source_was_never_mutated();
    let target_state = fs::read_to_string(&fixture.target_state).expect("target state");
    assert_eq!(
        target_state, r#"{"encrypted":false,"folders":[],"items":[]}"#,
        "dry-run must not mutate the target"
    );
}

#[test]
fn sync_apply_creates_items_in_target_profile_and_is_idempotent() {
    let fixture = setup_sync_fixture();

    fixture
        .sync_command(&["--apply"])
        .assert()
        .success()
        .stdout(predicate::str::contains("restore applied"))
        .stdout(predicate::str::contains("items_created: 1"));

    let target_state = fs::read_to_string(&fixture.target_state).expect("target state");
    assert!(target_state.contains("Example Login"));
    assert!(target_state.contains("yabbt restore map - do not edit"));

    // Second run matches via the restore map and creates nothing new.
    fixture
        .sync_command(&["--apply", "--overwrite"])
        .assert()
        .success()
        .stdout(predicate::str::contains("items_created: 0"));

    let target_state = fs::read_to_string(&fixture.target_state).expect("target state");
    assert_eq!(
        target_state.matches("Example Login").count(),
        1,
        "rerun must not duplicate items"
    );
    fixture.assert_source_was_never_mutated();
}

#[test]
fn sync_is_blocked_by_unacknowledged_org_items_and_points_at_personal_only() {
    let fixture = setup_sync_fixture();
    let items_path = write_org_visible_items(fixture.temp.path());

    let output = fixture
        .sync_command(&[])
        .env("YABBT_FAKE_BW_ITEMS", &items_path)
        .output()
        .expect("run sync");

    assert_eq!(output.status.code(), Some(3), "plan must be blocked");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("status: blocked"), "{stdout}");
    assert!(stdout.contains("archive is marked incomplete"), "{stdout}");
    assert!(stdout.contains("--personal-only"), "{stdout}");
    assert!(stderr.contains("complete: false"), "{stderr}");
    assert!(stderr.contains("org-items-not-exported"), "{stderr}");
    assert_no_org_details(&stdout);
    assert_no_org_details(&stderr);
    // An incomplete export is never published as sync's backup.
    assert!(!fixture.archive_path.exists(), "incomplete archive written");
    assert!(
        archive_temp_files(fixture.temp.path()).is_empty(),
        "stray temp files: {:?}",
        archive_temp_files(fixture.temp.path())
    );
}

#[test]
fn sync_overwrite_keeps_the_previous_archive_when_the_new_export_is_incomplete() {
    let fixture = setup_sync_fixture();
    fixture.sync_command(&[]).assert().success();
    let previous = fs::read(&fixture.archive_path).expect("previous archive");
    let items_path = write_org_visible_items(fixture.temp.path());

    for extra in [&["--overwrite"][..], &["--overwrite", "--apply"][..]] {
        let output = fixture
            .sync_command(extra)
            .env("YABBT_FAKE_BW_ITEMS", &items_path)
            .output()
            .expect("run sync");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(3),
            "{extra:?}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(
            stderr.contains("failed verification") && stderr.contains("left unchanged"),
            "{extra:?}\nstderr:\n{stderr}"
        );
        assert!(!stdout.contains("wrote backup archive"), "{stdout}");
        assert_eq!(
            fs::read(&fixture.archive_path).expect("read out"),
            previous,
            "{extra:?}: the last good archive must survive an incomplete export"
        );
        assert!(
            archive_temp_files(fixture.temp.path()).is_empty(),
            "stray temp files: {:?}",
            archive_temp_files(fixture.temp.path())
        );
    }
    let target_state = fs::read_to_string(&fixture.target_state).expect("target state");
    assert_eq!(
        target_state, r#"{"encrypted":false,"folders":[],"items":[]}"#,
        "a blocked sync must not mutate the target"
    );
}

#[test]
fn sync_personal_only_proceeds_when_source_sees_org_items() {
    let fixture = setup_sync_fixture();
    let items_path = write_org_visible_items(fixture.temp.path());

    let output = fixture
        .sync_command(&["--personal-only", "--apply"])
        .env("YABBT_FAKE_BW_ITEMS", &items_path)
        .output()
        .expect("run sync");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("items_created: 1"), "{stdout}");
    assert!(stderr.contains("complete: true"), "{stderr}");
    assert!(stderr.contains("org-items-excluded-by-scope"), "{stderr}");
    assert_no_org_details(&stdout);
    assert_no_org_details(&stderr);

    let opened =
        open_archive(&fixture.archive_path, STRONG_TEST_PASSPHRASE).expect("open sync archive");
    assert!(opened.vault.report.complete);
    let target_state = fs::read_to_string(&fixture.target_state).expect("target state");
    assert!(target_state.contains("Example Login"));
    fixture.assert_source_was_never_mutated();
}

#[test]
fn sync_rejects_personal_only_without_bw_source() {
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "sync",
        "--source",
        "keepass",
        "--target",
        "bw",
        "--target-profile",
        "tgt",
        "--personal-only",
    ])
    .assert()
    .code(2)
    .stderr(predicate::str::contains(
        "sync --personal-only is only valid with --source bw",
    ));
}

fn keepass_restore_command(archive: &Path, kdbx: &Path, extra_args: &[&str]) -> Command {
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "keepass",
        archive.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--keepass-file",
        kdbx.to_str().expect("kdbx path"),
        "--keepass-passphrase-env",
        "KDBX_TEST_PASSPHRASE",
    ])
    .args(extra_args)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("KDBX_TEST_PASSPHRASE", STRONG_KDBX_PASSPHRASE)
    .env("YABBT_KEEPASS_KDF", "insecure-fast");
    cmd
}

#[test]
fn restore_target_keepass_requires_keepass_flags() {
    let temp = tempfile::tempdir().expect("tempdir");
    let archive = write_new_item_archive(temp.path());

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "keepass",
        archive.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--dry-run",
    ])
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .assert()
    .failure()
    .stderr(predicate::str::contains(
        "restore requires --keepass-file <path>",
    ));
}

#[test]
fn restore_target_keepass_rejects_bw_only_flags() {
    let temp = tempfile::tempdir().expect("tempdir");
    let archive = write_new_item_archive(temp.path());
    let kdbx = temp.path().join("vault.kdbx");

    keepass_restore_command(&archive, &kdbx, &["--dry-run", "--bw-profile", "prod"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "restore --bw-profile is only valid with --target bw",
        ));

    keepass_restore_command(
        &archive,
        &kdbx,
        &["--dry-run", "--organization-id", "org-1"],
    )
    .assert()
    .failure()
    .stderr(predicate::str::contains(
        "restore --organization-id is only valid with --target bw",
    ));
}

#[test]
fn restore_keepass_flags_rejected_for_bw_target() {
    let temp = tempfile::tempdir().expect("tempdir");
    let archive = write_new_item_archive(temp.path());

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "restore",
        "--target",
        "bw",
        archive.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--dry-run",
        "--keepass-file",
        "vault.kdbx",
    ])
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .assert()
    .failure()
    .stderr(predicate::str::contains(
        "restore --keepass-file is only valid with --target keepass",
    ));
}

#[test]
fn restore_target_keepass_dry_run_plans_without_creating_the_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    let archive = write_new_item_archive(temp.path());
    let kdbx = temp.path().join("vault.kdbx");

    keepass_restore_command(&archive, &kdbx, &["--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("restore plan"))
        .stdout(predicate::str::contains("target: keepass"))
        .stdout(predicate::str::contains("items_to_create: 1"));

    assert!(!kdbx.exists(), "dry run must not create the database");
}

#[test]
fn restore_target_keepass_apply_rejects_weak_passphrase_for_new_database() {
    let temp = tempfile::tempdir().expect("tempdir");
    let archive = write_new_item_archive(temp.path());
    let kdbx = temp.path().join("vault.kdbx");

    // A weak kdbx passphrase must be refused when creating a brand-new
    // database, and the database must not be written.
    let mut cmd = keepass_restore_command(&archive, &kdbx, &["--apply"]);
    cmd.env("KDBX_TEST_PASSPHRASE", "weak")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "refuses to create keepass database",
        ));
    assert!(
        !kdbx.exists(),
        "weak passphrase must not create the database"
    );

    // --yolo overrides the strength check.
    let mut yolo = keepass_restore_command(&archive, &kdbx, &["--apply", "--yolo"]);
    yolo.env("KDBX_TEST_PASSPHRASE", "weak")
        .assert()
        .success()
        .stderr(predicate::str::contains("--yolo set"));
    assert!(kdbx.exists(), "yolo override creates the database");
}

#[test]
fn restore_target_keepass_apply_creates_database_and_is_idempotent() {
    let temp = tempfile::tempdir().expect("tempdir");
    let archive = write_new_item_archive(temp.path());
    let kdbx = temp.path().join("vault.kdbx");

    keepass_restore_command(&archive, &kdbx, &["--apply", "--verify-after"])
        .assert()
        .success()
        .stderr(predicate::str::contains("created new keepass database"))
        .stdout(predicate::str::contains("restore applied"))
        .stdout(predicate::str::contains("items_created: 1"))
        .stdout(predicate::str::contains("attachments_uploaded: 1"))
        .stdout(predicate::str::contains("post_apply_verified: true"));
    assert!(kdbx.exists(), "database created on apply");

    keepass_restore_command(&archive, &kdbx, &["--apply"])
        .assert()
        .success()
        .stdout(predicate::str::contains("items_created: 0"))
        .stdout(predicate::str::contains("attachments_uploaded: 0"));
}

#[test]
fn restore_target_keepass_apply_backs_up_existing_database() {
    let temp = tempfile::tempdir().expect("tempdir");
    let archive = write_new_item_archive(temp.path());
    let kdbx = temp.path().join("vault.kdbx");

    // First apply creates the database, second mutating run must back it up.
    keepass_restore_command(&archive, &kdbx, &["--apply"])
        .assert()
        .success();
    let second_archive = write_existing_only_note_archive(temp.path());
    keepass_restore_command(&second_archive, &kdbx, &["--apply"])
        .assert()
        .success()
        .stderr(predicate::str::contains("before first write"));

    let baks = fs::read_dir(temp.path())
        .expect("read tempdir")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("vault.kdbx.") && name.ends_with(".bak"))
        .count();
    assert_eq!(
        baks, 1,
        "timestamped .bak copy created before mutating an existing database"
    );
}

fn kdbx_bak_count(dir: &Path) -> usize {
    fs::read_dir(dir)
        .expect("read dir")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".bak"))
        .count()
}

/// No-op re-runs must not rewrite the kdbx: no new `.bak` copy, identical
/// bytes, and the restore map reported as not updated.
#[test]
fn restore_target_keepass_no_op_reruns_leave_the_database_untouched() {
    let temp = tempfile::tempdir().expect("tempdir");
    let archive = write_new_item_archive(temp.path());
    let kdbx = temp.path().join("vault.kdbx");
    keepass_restore_command(&archive, &kdbx, &["--apply"])
        .assert()
        .success()
        .stdout(predicate::str::contains("restore_map_updated: true"));
    let bytes = fs::read(&kdbx).expect("read kdbx");

    for run in 0..3 {
        keepass_restore_command(
            &archive,
            &kdbx,
            &["--apply", "--update-existing", "--prune", "--verify-after"],
        )
        .assert()
        .success()
        .stdout(predicate::str::contains("items_updated: 0"))
        .stdout(predicate::str::contains("restore_map_updated: false"))
        .stderr(predicate::str::contains("before first write").not());
        assert_eq!(kdbx_bak_count(temp.path()), 0, "run {run}: no .bak copy");
        assert_eq!(fs::read(&kdbx).expect("read kdbx"), bytes, "run {run}");
    }
}

fn keepass_sync_command(temp: &Path, kdbx: &Path, archive: &Path, extra: &[&str]) -> Command {
    let bin_dir = temp.join("bin");
    if !bin_dir.exists() {
        fs::create_dir(&bin_dir).expect("bin dir");
        write_fake_bw(&bin_dir.join("bw"));
    }
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "sync",
        "--source",
        "bw",
        "--target",
        "keepass",
        "--source-profile",
        "src",
        "--keepass-file",
        kdbx.to_str().expect("kdbx path"),
        "--keepass-passphrase-env",
        "KDBX_TEST_PASSPHRASE",
        "--out",
        archive.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .args(extra)
    .env("PATH", &path)
    .env("XDG_DATA_HOME", temp.join("data"))
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("KDBX_TEST_PASSPHRASE", STRONG_KDBX_PASSPHRASE)
    .env("YABBT_KEEPASS_KDF", "insecure-fast");
    cmd
}

/// Repeated `sync --apply` runs with an unchanged source must not rewrite
/// the kdbx or accumulate `.bak` copies.
#[test]
fn sync_to_keepass_no_op_runs_do_not_rewrite_the_database() {
    let temp = tempfile::tempdir().expect("tempdir");
    let kdbx = temp.path().join("t.kdbx");
    keepass_sync_command(
        temp.path(),
        &kdbx,
        &temp.path().join("a0.yabbt"),
        &["--apply"],
    )
    .assert()
    .success();
    let bytes = fs::read(&kdbx).expect("read kdbx");
    for run in 1..4 {
        let archive = temp.path().join(format!("a{run}.yabbt"));
        keepass_sync_command(temp.path(), &kdbx, &archive, &["--apply"])
            .assert()
            .success()
            .stdout(predicate::str::contains("restore_map_updated: false"));
        assert_eq!(kdbx_bak_count(temp.path()), 0, "run {run}: no .bak copy");
        assert_eq!(fs::read(&kdbx).expect("read kdbx"), bytes, "run {run}");
    }
}

#[test]
fn restore_target_keepass_output_is_secret_safe() {
    let temp = tempfile::tempdir().expect("tempdir");
    let archive = write_new_item_archive(temp.path());
    let kdbx = temp.path().join("vault.kdbx");

    let assert = keepass_restore_command(&archive, &kdbx, &["--apply"])
        .assert()
        .success();
    let output = assert.get_output();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for secret in ["Secret Login", "hunter2", "recovery.txt", "secret note"] {
        assert!(!combined.contains(secret), "output leaked `{secret}`");
    }
}

/// Archive containing only a secure note, used to force a second mutating
/// run against an already-existing keepass database.
fn write_existing_only_note_archive(temp_path: &Path) -> PathBuf {
    let mut vault = sample_vault();
    vault.items = vec![VaultItem {
        id: "second-note".to_string(),
        kind: ItemKind::SecureNote,
        name: "Second Note".to_string(),
        notes: Some("second body".to_string()),
        folder_id: None,
        favorite: false,
        fields: Vec::new(),
        attachments: Vec::new(),
        backend_metadata: Vec::new(),
    }];
    let archive_path = temp_path.join("second-note.yabbt");
    ArchiveBuilder::new(vault)
        .write(&archive_path, STRONG_TEST_PASSPHRASE, WriteMode::Overwrite)
        .expect("write second note archive");
    archive_path
}

/// Build a kdbx (cheap KDF) with one login entry + attachment, used as a
/// backup/diff/sync source.
fn write_source_kdbx(path: &Path) {
    use keepass::config::{DatabaseConfig, KdfConfig};
    use keepass::db::Value as KdbxValue;
    use keepass::{Database, DatabaseKey};

    let mut config = DatabaseConfig::default();
    config.kdf_config = KdfConfig::Aes { rounds: 10 };
    let mut db = Database::with_config(config);
    let mut root = db.root_mut();
    let mut group = root.add_group();
    group.name = "Infrastructure".to_string();
    let mut login = group.add_entry();
    login.set_unprotected("Title", "Kdbx Login");
    login.set_unprotected("UserName", "admin");
    login.set_protected("Password", "kdbx-hunter2");
    login.add_attachment(
        "recovery.txt",
        KdbxValue::protected(b"recovery-code".to_vec()),
    );

    let mut file = fs::File::create(path).expect("create source kdbx");
    db.save(
        &mut file,
        DatabaseKey::new().with_password(STRONG_KDBX_PASSPHRASE),
    )
    .expect("save source kdbx");
}

/// Prune of an attachment the keepass library cannot remove (it is shared
/// with the entry's history) is skipped with a warning naming only the
/// item id; the rest of the restore is applied and the run succeeds.
#[test]
fn restore_target_keepass_skips_history_pinned_attachment_delete() {
    use keepass::config::{DatabaseConfig, KdfConfig};
    use keepass::db::Value as KdbxValue;
    use keepass::{Database, DatabaseKey};

    let temp = tempfile::tempdir().expect("tempdir");
    let kdbx = temp.path().join("vault.kdbx");
    let mut config = DatabaseConfig::default();
    config.kdf_config = KdfConfig::Aes { rounds: 10 };
    let mut db = Database::with_config(config);
    let pinned = {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected("Title", "Pinned Note");
        entry.add_attachment(
            "pinned-secret-name.bin",
            KdbxValue::protected(b"doc".to_vec()),
        );
        entry.edit_tracking(|tracked| tracked.set_unprotected("Notes", "edited"));
        entry.as_ref().id().uuid().to_string()
    };
    let mut file = fs::File::create(&kdbx).expect("create kdbx");
    db.save(
        &mut file,
        DatabaseKey::new().with_password(STRONG_KDBX_PASSPHRASE),
    )
    .expect("save kdbx");
    drop(file);

    let mut vault = sample_vault();
    vault.folders.clear();
    vault.items[0].folder_id = None;
    vault.items.push(VaultItem {
        id: pinned.clone(),
        kind: ItemKind::SecureNote,
        name: "Pinned Note".to_string(),
        notes: Some("edited".to_string()),
        folder_id: None,
        favorite: false,
        fields: Vec::new(),
        attachments: Vec::new(),
        backend_metadata: Vec::new(),
    });
    let archive = temp.path().join("pinned.yabbt");
    ArchiveBuilder::new(vault)
        .attachment(ArchiveAttachment {
            path: "attachments/item-1/attachment-1.bin".to_string(),
            bytes: b"recovery-code".to_vec(),
        })
        .write(&archive, STRONG_TEST_PASSPHRASE, WriteMode::Overwrite)
        .expect("write archive");

    let output =
        keepass_restore_command(&archive, &kdbx, &["--apply", "--prune", "--verify-after"])
            .output()
            .expect("run restore");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("items_created: 1"), "{stdout}");
    assert!(stdout.contains("attachments_deleted: 0"), "{stdout}");
    assert!(stdout.contains("attachments_delete_skipped: 1"), "{stdout}");
    assert!(stderr.contains("warning: kept 1 attachment"), "{stderr}");
    assert!(stderr.contains(&pinned), "{stderr}");
    assert!(!stdout.contains("pinned-secret-name"), "{stdout}");
    assert!(!stderr.contains("pinned-secret-name"), "{stderr}");
}

#[test]
fn backup_source_keepass_writes_archive_from_kdbx() {
    let temp = tempfile::tempdir().expect("tempdir");
    let kdbx = temp.path().join("source.kdbx");
    write_source_kdbx(&kdbx);
    let archive_path = temp.path().join("backup.yabbt");

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "keepass",
        "--keepass-file",
        kdbx.to_str().expect("kdbx path"),
        "--keepass-passphrase-env",
        "KDBX_TEST_PASSPHRASE",
        "--out",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("KDBX_TEST_PASSPHRASE", STRONG_KDBX_PASSPHRASE)
    .assert()
    .success()
    .stdout(predicate::str::contains("wrote backup archive"));

    let opened = open_archive(&archive_path, STRONG_TEST_PASSPHRASE).expect("open archive");
    assert_eq!(opened.vault.metadata.source_backend, "keepass");
    assert_eq!(opened.vault.items.len(), 1);
    assert_eq!(opened.vault.items[0].name, "Kdbx Login");
    assert_eq!(opened.vault.folders[0].name, "Infrastructure");
    assert_eq!(opened.attachments.len(), 1);
    assert_eq!(opened.attachments[0].bytes, b"recovery-code");
}

#[test]
fn backup_source_keepass_missing_file_fails_without_creating_it() {
    let temp = tempfile::tempdir().expect("tempdir");
    let kdbx = temp.path().join("missing.kdbx");

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "keepass",
        "--keepass-file",
        kdbx.to_str().expect("kdbx path"),
        "--keepass-passphrase-env",
        "KDBX_TEST_PASSPHRASE",
        "--out",
        temp.path().join("backup.yabbt").to_str().expect("path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("KDBX_TEST_PASSPHRASE", STRONG_KDBX_PASSPHRASE)
    .assert()
    .failure()
    .stderr(predicate::str::contains("does not exist"));

    assert!(!kdbx.exists(), "source file must never be auto-created");
}

#[test]
fn backup_source_keepass_rejects_bw_only_flags() {
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "keepass",
        "--bw-profile",
        "prod",
        "--out",
        "backup.yabbt",
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .assert()
    .failure()
    .stderr(predicate::str::contains(
        "backup --bw-profile is only valid with a bw backend",
    ));
}

#[test]
fn restore_to_keepass_then_backup_from_keepass_diffs_clean() {
    let temp = tempfile::tempdir().expect("tempdir");
    let archive = write_new_item_archive(temp.path());
    let kdbx = temp.path().join("vault.kdbx");

    // Restore the archive into a fresh kdbx.
    keepass_restore_command(&archive, &kdbx, &["--apply"])
        .assert()
        .success();

    // Back the kdbx up into a second archive.
    let roundtrip_archive = temp.path().join("roundtrip.yabbt");
    let mut backup = Command::cargo_bin("yabbt").expect("binary exists");
    backup
        .args([
            "backup",
            "--source",
            "keepass",
            "--keepass-file",
            kdbx.to_str().expect("kdbx path"),
            "--keepass-passphrase-env",
            "KDBX_TEST_PASSPHRASE",
            "--out",
            roundtrip_archive.to_str().expect("archive path"),
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
        ])
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .env("KDBX_TEST_PASSPHRASE", STRONG_KDBX_PASSPHRASE)
        .assert()
        .success();

    // Diff that archive against the live kdbx: nothing changed.
    let mut diff = Command::cargo_bin("yabbt").expect("binary exists");
    diff.args([
        "diff",
        "--source",
        "keepass",
        "--keepass-file",
        kdbx.to_str().expect("kdbx path"),
        "--keepass-passphrase-env",
        "KDBX_TEST_PASSPHRASE",
        "--archive",
        roundtrip_archive.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("KDBX_TEST_PASSPHRASE", STRONG_KDBX_PASSPHRASE)
    .assert()
    .success()
    .stdout(predicate::str::contains("against source keepass"))
    .stdout(predicate::str::contains("added: 0"))
    .stdout(predicate::str::contains("removed: 0"))
    .stdout(predicate::str::contains("changed: 0"));
}

#[test]
fn sync_rejects_keepass_on_both_sides() {
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args(["sync", "--source", "keepass", "--target", "keepass"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "sync from keepass to keepass is not supported yet",
        ));
}

#[test]
fn sync_target_keepass_rejects_target_profile() {
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "sync",
        "--source",
        "bw",
        "--target",
        "keepass",
        "--source-profile",
        "src",
        "--target-profile",
        "tgt",
    ])
    .assert()
    .failure()
    .stderr(predicate::str::contains(
        "sync --target-profile is only valid with --target bw",
    ));
}

#[test]
fn sync_source_keepass_requires_keepass_flags() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    write_fake_bw(&bin_dir.join("bw"));
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "sync",
        "--source",
        "keepass",
        "--target",
        "bw",
        "--target-profile",
        "tgt",
        "--out",
        temp.path().join("sync.yabbt").to_str().expect("path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("PATH", path)
    .env("XDG_DATA_HOME", temp.path().join("data"))
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .assert()
    .failure()
    .stderr(predicate::str::contains(
        "sync requires --keepass-file <path>",
    ));
}

#[test]
fn sync_source_bw_target_keepass_apply_creates_entries_and_is_idempotent() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    write_fake_bw(&bin_dir.join("bw"));
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let kdbx = temp.path().join("target.kdbx");
    let archive = temp.path().join("sync.yabbt");

    let sync = |label: &str| {
        let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
        cmd.args([
            "sync",
            "--source",
            "bw",
            "--target",
            "keepass",
            "--source-profile",
            "src",
            "--keepass-file",
            kdbx.to_str().expect("kdbx path"),
            "--keepass-passphrase-env",
            "KDBX_TEST_PASSPHRASE",
            "--out",
            archive.to_str().expect("archive path"),
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
            "--apply",
            "--overwrite",
        ])
        .env("PATH", &path)
        .env("XDG_DATA_HOME", temp.path().join("data"))
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .env("KDBX_TEST_PASSPHRASE", STRONG_KDBX_PASSPHRASE)
        .env("YABBT_KEEPASS_KDF", "insecure-fast");
        let assert = cmd.assert().success();
        let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
        assert!(
            stdout.contains("sync source bw -> target keepass"),
            "{label}: missing sync header: {stdout}"
        );
        stdout
    };

    let first = sync("first run");
    assert!(first.contains("items_created: 1"), "first run: {first}");
    assert!(
        first.contains("attachments_uploaded: 1"),
        "first run: {first}"
    );
    assert!(kdbx.exists(), "target database created");

    let second = sync("second run");
    assert!(second.contains("items_created: 0"), "second run: {second}");
    assert!(
        second.contains("attachments_uploaded: 0"),
        "second run: {second}"
    );

    // The synced login is present exactly once in the kdbx.
    let mut file = fs::File::open(&kdbx).expect("open kdbx");
    let db = keepass::Database::open(
        &mut file,
        keepass::DatabaseKey::new().with_password(STRONG_KDBX_PASSPHRASE),
    )
    .expect("open target database");
    let logins = db
        .iter_all_entries()
        .filter(|entry| entry.get_title() == Some("Example Login"))
        .count();
    assert_eq!(logins, 1, "no duplicate entries after rerun");
}

#[test]
fn sync_source_keepass_target_bw_dry_run_plans_creates() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    write_fake_bw(&bin_dir.join("bw"));
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let kdbx = temp.path().join("source.kdbx");
    write_source_kdbx(&kdbx);
    let archive = temp.path().join("sync.yabbt");
    // The fake bw target reports the fixture vault; give it empty fixtures so
    // the plan creates everything from the kdbx.
    let empty_export = temp.path().join("empty-export.json");
    fs::write(&empty_export, r#"{"folders":[],"items":[]}"#).expect("write empty export");
    let empty_items = temp.path().join("empty-items.json");
    fs::write(&empty_items, "[]").expect("write empty items");

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "sync",
        "--source",
        "keepass",
        "--target",
        "bw",
        "--target-profile",
        "tgt",
        "--keepass-file",
        kdbx.to_str().expect("kdbx path"),
        "--keepass-passphrase-env",
        "KDBX_TEST_PASSPHRASE",
        "--out",
        archive.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("PATH", path)
    .env("XDG_DATA_HOME", temp.path().join("data"))
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("KDBX_TEST_PASSPHRASE", STRONG_KDBX_PASSPHRASE)
    .env("YABBT_FAKE_BW_EXPORT", &empty_export)
    .env("YABBT_FAKE_BW_ITEMS", &empty_items)
    .assert()
    .success()
    .stdout(predicate::str::contains("sync source keepass -> target bw"))
    .stdout(predicate::str::contains("wrote backup archive"))
    .stdout(predicate::str::contains("restore plan"))
    .stdout(predicate::str::contains("items_to_create: 1"));

    let opened = open_archive(&archive, STRONG_TEST_PASSPHRASE).expect("open sync archive");
    assert_eq!(opened.vault.metadata.source_backend, "keepass");
    assert_eq!(opened.vault.items[0].name, "Kdbx Login");
}

/// `sync --source bw --target keepass` with a fake bw on PATH that logs calls.
struct KeepassSyncFixture {
    temp: tempfile::TempDir,
    path_env: String,
    call_log: PathBuf,
    kdbx: PathBuf,
}

impl KeepassSyncFixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let bin_dir = temp.path().join("bin");
        fs::create_dir(&bin_dir).expect("bin dir");
        write_fake_bw(&bin_dir.join("bw"));
        let kdbx = temp.path().join("target.kdbx");
        write_source_kdbx(&kdbx);
        Self {
            path_env: format!(
                "{}:{}",
                bin_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
            call_log: temp.path().join("bw-calls.log"),
            kdbx,
            temp,
        }
    }

    fn sync(&self, out: &Path, extra: &[&str]) -> Command {
        let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
        cmd.args([
            "sync",
            "--source",
            "bw",
            "--target",
            "keepass",
            "--source-profile",
            "src",
            "--keepass-file",
            self.kdbx.to_str().expect("kdbx path"),
            "--out",
            out.to_str().expect("out path"),
            "--passphrase-env",
            "YABBT_TEST_PASSPHRASE",
        ])
        .args(extra)
        .env("PATH", &self.path_env)
        .env("XDG_DATA_HOME", self.temp.path().join("data"))
        .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
        .env("KDBX_TEST_PASSPHRASE", STRONG_KDBX_PASSPHRASE)
        .env("YABBT_FAKE_BW_LOG", &self.call_log);
        cmd
    }

    fn assert_not_exported(&self) {
        let calls = fs::read_to_string(&self.call_log).unwrap_or_default();
        assert!(
            !calls.contains("export"),
            "source exported before the refusal:\n{calls}"
        );
    }
}

#[test]
fn sync_refuses_out_that_aliases_the_keepass_file_or_its_siblings() {
    let fixture = KeepassSyncFixture::new();
    let original = fs::read(&fixture.kdbx).expect("read kdbx");
    // KeePass backups are `<kdbx>.<UTC timestamp>[-n].bak`.
    let bak = fixture.temp.path().join("target.kdbx.20261011T120000Z.bak");
    let bak_n = fixture
        .temp
        .path()
        .join("target.kdbx.20261011T120000Z-2.bak");
    let tmp = fixture.temp.path().join("target.kdbx.tmp-yabbt");
    // Same file through a different spelling must be caught too.
    let dotted = fixture.temp.path().join(".").join("target.kdbx");
    let dotted_bak = fixture
        .temp
        .path()
        .join(".")
        .join("target.kdbx.20250101T000000Z.bak");

    for out in [&fixture.kdbx, &bak, &bak_n, &tmp, &dotted, &dotted_bak] {
        fixture
            .sync(
                out,
                &[
                    "--keepass-passphrase-env",
                    "KDBX_TEST_PASSPHRASE",
                    "--overwrite",
                ],
            )
            .assert()
            .code(2)
            .stderr(predicate::str::contains("--keepass-file"));
    }
    assert_eq!(fs::read(&fixture.kdbx).expect("read kdbx"), original);
    assert!(!bak.exists());
    fixture.assert_not_exported();
}

#[test]
fn backup_source_keepass_refuses_out_equal_to_keepass_file() {
    let fixture = KeepassSyncFixture::new();
    let original = fs::read(&fixture.kdbx).expect("read kdbx");
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "keepass",
        "--keepass-file",
        fixture.kdbx.to_str().expect("kdbx path"),
        "--keepass-passphrase-env",
        "KDBX_TEST_PASSPHRASE",
        "--out",
        fixture.kdbx.to_str().expect("kdbx path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--overwrite",
    ])
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("KDBX_TEST_PASSPHRASE", STRONG_KDBX_PASSPHRASE)
    .assert()
    .code(2)
    .stderr(predicate::str::contains("--keepass-file"));
    assert_eq!(fs::read(&fixture.kdbx).expect("read kdbx"), original);
}

#[test]
fn sync_validates_keepass_target_before_exporting_source() {
    let fixture = KeepassSyncFixture::new();
    let out = fixture.temp.path().join("sync.yabbt");

    // Missing passphrase env flag.
    fixture
        .sync(&out, &[])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--keepass-passphrase-env"));
    // Wrong passphrase for the existing database.
    fixture
        .sync(&out, &["--keepass-passphrase-env", "WRONG_KDBX_PASSPHRASE"])
        .env(
            "WRONG_KDBX_PASSPHRASE",
            "not the database passphrase at all",
        )
        .assert()
        .failure()
        .stderr(predicate::str::contains("keepass"));

    fixture.assert_not_exported();
    assert!(!out.exists(), "no archive written");
}

#[test]
fn backup_creates_missing_out_directory() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    write_fake_bw(&bin_dir.join("bw"));
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let archive_path = temp.path().join("nested").join("dir").join("backup.yabbt");

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "bw",
        "--out",
        archive_path.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .assert()
    .success()
    .stderr(predicate::str::contains("notice: created output directory"))
    .stdout(predicate::str::contains("wrote backup archive"));

    open_archive(&archive_path, STRONG_TEST_PASSPHRASE).expect("archive opens");
}

#[test]
fn backup_out_pointing_at_directory_errors_before_export() {
    let temp = tempfile::tempdir().expect("tempdir");

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "bw",
        "--out",
        temp.path().to_str().expect("dir path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .assert()
    .failure()
    .stderr(predicate::str::contains("is a directory; pass a file path"));
}

#[test]
fn backup_refuses_to_overwrite_existing_out_before_export() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    write_fake_bw(&bin_dir.join("bw"));
    let call_log = temp.path().join("bw-calls.log");
    let out = temp.path().join("existing.yabbt");
    fs::write(&out, b"previous good backup").expect("seed existing archive");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "bw",
        "--out",
        out.to_str().expect("out path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("PATH", &path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_FAKE_BW_LOG", &call_log)
    .assert()
    .code(2)
    .stderr(predicate::str::contains("already exists"))
    .stderr(predicate::str::contains("--overwrite"));
    assert_eq!(fs::read(&out).expect("read out"), b"previous good backup");
    assert!(!call_log.exists(), "bw must not run before the refusal");

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "bw",
        "--out",
        out.to_str().expect("out path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
        "--overwrite",
    ])
    .env("PATH", &path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .assert()
    .success();
    open_archive(&out, STRONG_TEST_PASSPHRASE).expect("overwritten archive opens");
}

/// Files in `dir` whose name marks them as an archive write temp file.
fn archive_temp_files(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .expect("read dir")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains("tmp-yabbt"))
        .collect()
}

fn backup_command(bin_dir: &Path, out: &Path, extra_args: &[&str]) -> Command {
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "bw",
        "--out",
        out.to_str().expect("out path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .args(extra_args)
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE);
    cmd
}

#[test]
fn backup_never_replaces_an_out_created_while_the_export_ran() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    write_fake_bw(&bin_dir.join("bw"));
    let out_dir = temp.path().join("out");
    fs::create_dir(&out_dir).expect("out dir");
    let out = out_dir.join("backup.yabbt");

    // --out does not exist when yabbt checks it, but the (fake) export
    // creates it: without --overwrite the write must not replace it.
    backup_command(&bin_dir, &out, &[])
        .env("YABBT_FAKE_BW_EXPORT_CREATES", &out)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("already exists"))
        .stdout(predicate::str::contains("wrote backup archive").not());
    assert_eq!(fs::read(&out).expect("read out"), b"appeared during export");
    assert!(
        archive_temp_files(&out_dir).is_empty(),
        "stray temp files: {:?}",
        archive_temp_files(&out_dir)
    );
}

#[test]
fn backup_is_not_blocked_by_a_stale_temp_file_from_a_crashed_run() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    write_fake_bw(&bin_dir.join("bw"));
    let out = temp.path().join("backup.yabbt");
    let stale = temp.path().join("backup.yabbt.tmp-yabbt");
    fs::write(&stale, b"left behind by a crash").expect("seed stale temp");

    backup_command(&bin_dir, &out, &[])
        .assert()
        .success()
        .stdout(predicate::str::contains("wrote backup archive"));
    open_archive(&out, STRONG_TEST_PASSPHRASE).expect("archive opens");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&out).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "archive is owner-only");
    }
}

#[test]
fn sync_refuses_to_overwrite_existing_out_even_on_dry_run() {
    let fixture = setup_sync_fixture();
    fs::write(&fixture.archive_path, b"previous good backup").expect("seed existing archive");

    fixture
        .sync_command(&[])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("already exists"))
        .stderr(predicate::str::contains("--overwrite"));
    assert_eq!(
        fs::read(&fixture.archive_path).expect("read out"),
        b"previous good backup"
    );
    let source_calls = fs::read_to_string(&fixture.source_log).unwrap_or_default();
    assert!(
        !source_calls.contains("export"),
        "source exported before the refusal:\n{source_calls}"
    );

    fixture
        .sync_command(&["--overwrite"])
        .assert()
        .success()
        .stdout(predicate::str::contains("wrote backup archive"));
    open_archive(&fixture.archive_path, STRONG_TEST_PASSPHRASE).expect("overwritten archive");
}

#[test]
fn backup_rejects_weak_passphrase_before_any_export_work() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("bin dir");
    write_fake_bw(&bin_dir.join("bw"));
    let env_log = temp.path().join("bw-env.log");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "backup",
        "--source",
        "bw",
        "--out",
        temp.path().join("backup.yabbt").to_str().expect("path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("PATH", path)
    .env("YABBT_TEST_PASSPHRASE", "password")
    .env("YABBT_FAKE_BW_ENV_LOG", &env_log)
    .assert()
    .code(2)
    .stderr(predicate::str::contains("weak passphrase"));

    assert!(
        !env_log.exists(),
        "weak passphrase must fail before any bw call"
    );
}

#[test]
fn sync_rejects_weak_passphrase_as_usage_error_before_export() {
    let fixture = setup_sync_fixture();

    fixture
        .sync_command(&[])
        .env("YABBT_TEST_PASSPHRASE", "password")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("weak passphrase"));
    let source_calls = fs::read_to_string(&fixture.source_log).unwrap_or_default();
    assert!(
        !source_calls.contains("export"),
        "source exported before the refusal:\n{source_calls}"
    );
    assert!(!fixture.archive_path.exists());
}

#[test]
fn sync_creates_missing_out_directory() {
    let fixture = setup_sync_fixture();
    let nested_out = fixture.temp.path().join("nested").join("sync.yabbt");

    let bin_dir = fixture.temp.path().join("bin");
    let mut cmd = Command::cargo_bin("yabbt").expect("binary exists");
    cmd.args([
        "sync",
        "--source",
        "bw",
        "--target",
        "bw",
        "--source-profile",
        "src",
        "--target-profile",
        "tgt",
        "--out",
        nested_out.to_str().expect("archive path"),
        "--passphrase-env",
        "YABBT_TEST_PASSPHRASE",
    ])
    .env("PATH", &fixture.path_env)
    .env("XDG_DATA_HOME", &fixture.data_home)
    .env("YABBT_TEST_PASSPHRASE", STRONG_TEST_PASSPHRASE)
    .env("YABBT_SYNC_SOURCE_DIR", fixture.profile_dir("src"))
    .env("YABBT_SYNC_TARGET_DIR", fixture.profile_dir("tgt"))
    .env("YABBT_SYNC_SOURCE_IMPL", bin_dir.join("bw-source-impl"))
    .env("YABBT_SYNC_TARGET_IMPL", bin_dir.join("bw-target-impl"))
    .env("YABBT_SYNC_SOURCE_LOG", &fixture.source_log)
    .env("YABBT_SYNC_TARGET_LOG", &fixture.target_log)
    .env("YABBT_STATEFUL_BW_STATE", &fixture.target_state)
    .assert()
    .success()
    .stderr(predicate::str::contains("notice: created output directory"));

    assert!(
        nested_out.exists(),
        "archive written into created directory"
    );
}

/// yabbt starts every `bw` child from a cleared, allowlisted environment.
/// The fake `bw` scripts are steered by `YABBT_FAKE_BW_*` / `YABBT_SYNC_*` /
/// `YABBT_STATEFUL_BW_*` variables set on the yabbt command, so admit them via
/// the documented passthrough. Set once for the whole test process; every
/// fake-bw writer calls this before any yabbt command is spawned.
fn allow_fake_bw_control_env() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: the value is constant and only Rust code (which serializes
        // environment access through std's env lock) reads the environment in
        // this test binary.
        unsafe {
            std::env::set_var(
                "YABBT_BW_ENV_PASSTHROUGH",
                "YABBT_FAKE_BW_*,YABBT_SYNC_*,YABBT_STATEFUL_BW_*",
            )
        };
    });
}

fn write_fake_bw(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    allow_fake_bw_control_env();

    fs::write(
        path,
        format!(
            r#"#!/usr/bin/env bash
set -euo pipefail
if [ -n "${{YABBT_FAKE_BW_ENV_LOG:-}}" ]; then
  printf '%s appdata=%s session=%s\n' "$1" "${{BITWARDENCLI_APPDATA_DIR:-}}" "${{BW_SESSION:-}}" >> "$YABBT_FAKE_BW_ENV_LOG"
fi
case "$1" in
  status)
    if [ -n "${{YABBT_FAKE_BW_SESSION:-}}" ] && [ "${{BW_SESSION:-}}" = "$YABBT_FAKE_BW_SESSION" ]; then
      printf '{{"status":"unlocked"}}'
    else
      printf '{{"status":"%s"}}' "${{YABBT_FAKE_BW_STATUS:-unlocked}}"
    fi
    ;;
  unlock)
    printf '%s' "${{YABBT_FAKE_BW_SESSION:-fake-session-key}}"
    ;;
  login)
    if [ -n "${{YABBT_FAKE_BW_LOG:-}}" ]; then
      printf '%s\n' "$*" >> "$YABBT_FAKE_BW_LOG"
    fi
    exit 0
    ;;
  config)
    if [ -n "${{YABBT_FAKE_BW_LOG:-}}" ]; then
      printf '%s\n' "$*" >> "$YABBT_FAKE_BW_LOG"
    fi
    exit 0
    ;;
  create)
    # item/folder payloads now arrive on stdin (kept off argv); fold them back
    # into the logged command so assertions see the original "create item <b64>".
    payload=""
    if [ "$2" = "item" ] || [ "$2" = "folder" ]; then
      payload=$(cat)
    fi
    if [ -n "${{YABBT_FAKE_BW_LOG:-}}" ]; then
      if [ -n "$payload" ]; then
        printf '%s %s\n' "$*" "$payload" >> "$YABBT_FAKE_BW_LOG"
      else
        printf '%s\n' "$*" >> "$YABBT_FAKE_BW_LOG"
      fi
    fi
    if [ "$2" = "item" ]; then
      printf '{{"id":"created-new-item"}}'
    elif [ "$2" = "folder" ]; then
      printf '{{"id":"created-folder"}}'
    elif [ "$2" = "attachment" ]; then
      if [ -n "${{YABBT_FAKE_BW_ATTACHMENT_TRANSFER_LOG:-}}" ]; then
        printf 'start upload %s\n' "$*" >> "$YABBT_FAKE_BW_ATTACHMENT_TRANSFER_LOG"
      fi
      if [ -n "${{YABBT_FAKE_BW_ATTACHMENT_SLEEP:-}}" ]; then
        sleep "$YABBT_FAKE_BW_ATTACHMENT_SLEEP"
      fi
      if [ -n "${{YABBT_FAKE_BW_AFTER_APPLY_MARKER:-}}" ]; then
        : > "$YABBT_FAKE_BW_AFTER_APPLY_MARKER"
      fi
      if [ -n "${{YABBT_FAKE_BW_FAIL_UPLOAD_MARKER:-}}" ] && [ ! -e "$YABBT_FAKE_BW_FAIL_UPLOAD_MARKER" ]; then
        : > "$YABBT_FAKE_BW_FAIL_UPLOAD_MARKER"
        echo "simulated upload failure" >&2
        exit 1
      fi
      if [ -n "${{YABBT_FAKE_BW_ATTACHMENT_TRANSFER_LOG:-}}" ]; then
        printf 'end upload %s\n' "$*" >> "$YABBT_FAKE_BW_ATTACHMENT_TRANSFER_LOG"
      fi
      exit 0
    else
      echo "unexpected bw create command: $*" >&2
      exit 1
    fi
    ;;
  edit)
    # The item id stays in argv ($3); the payload arrives on stdin.
    payload=$(cat)
    if [ -n "${{YABBT_FAKE_BW_LOG:-}}" ]; then
      printf '%s %s\n' "$*" "$payload" >> "$YABBT_FAKE_BW_LOG"
    fi
    if [ "$2" = "item" ]; then
      printf '{{"id":"%s"}}' "$3"
    else
      echo "unexpected bw edit command: $*" >&2
      exit 1
    fi
    ;;
  delete)
    if [ -n "${{YABBT_FAKE_BW_LOG:-}}" ]; then
      printf '%s\n' "$*" >> "$YABBT_FAKE_BW_LOG"
    fi
    if [ "$2" = "attachment" ]; then
      has_itemid=0
      for arg in "$@"; do
        if [ "$arg" = "--itemid" ]; then
          has_itemid=1
        fi
      done
      if [ "$has_itemid" -ne 1 ]; then
        echo "\`itemid\` option is required." >&2
        exit 1
      fi
    fi
    exit 0
    ;;
  sync)
    exit 0
    ;;
  --raw)
    shift
    if [ "$1" = "export" ]; then
      if [ -n "${{YABBT_FAKE_BW_EXPORT_CREATES:-}}" ]; then
        printf 'appeared during export' > "$YABBT_FAKE_BW_EXPORT_CREATES"
      fi
      cat "${{YABBT_FAKE_BW_EXPORT:-{export_path}}}"
    else
      echo "unexpected bw command: --raw $*" >&2
      exit 1
    fi
    ;;
  export)
    if [ -n "${{YABBT_FAKE_BW_EXPORT_CREATES:-}}" ]; then
      printf 'appeared during export' > "$YABBT_FAKE_BW_EXPORT_CREATES"
    fi
    cat "${{YABBT_FAKE_BW_EXPORT:-{export_path}}}"
    ;;
  list)
    if [ -n "${{YABBT_FAKE_BW_VERIFY_ITEMS:-}}" ] && [ -n "${{YABBT_FAKE_BW_AFTER_APPLY_MARKER:-}}" ] && [ -e "$YABBT_FAKE_BW_AFTER_APPLY_MARKER" ]; then
      cat "$YABBT_FAKE_BW_VERIFY_ITEMS"
    else
      cat "${{YABBT_FAKE_BW_ITEMS:-{items_path}}}"
    fi
    ;;
  get)
    if [ "${{2:-}}" = "item" ]; then
      if [ -n "${{YABBT_FAKE_BW_LOG:-}}" ]; then
        printf '%s\n' "$*" >> "$YABBT_FAKE_BW_LOG"
      fi
      if [ -n "${{YABBT_FAKE_BW_GET_CREATED_FAIL:-}}" ]; then
        echo "not found" >&2
        exit 1
      fi
      if [ -n "${{YABBT_FAKE_BW_VERIFY_ITEMS:-}}" ] && [ -n "${{YABBT_FAKE_BW_AFTER_APPLY_MARKER:-}}" ] && [ -e "$YABBT_FAKE_BW_AFTER_APPLY_MARKER" ]; then
        python - "$YABBT_FAKE_BW_VERIFY_ITEMS" "$3" <<'PY'
import json
import sys

items = json.load(open(sys.argv[1]))
target_id = sys.argv[2]
for item in items:
    if item.get("id") == target_id:
        print(json.dumps(item))
        raise SystemExit(0)
print(json.dumps({{"id": target_id}}))
PY
        exit 0
      fi
      printf '{{"id":"%s"}}' "$3"
      exit 0
    fi
    out=""
    prev=""
    for arg in "$@"; do
      if [ "$prev" = "--output" ]; then
        out="$arg"
      fi
      prev="$arg"
    done
    if [ -n "${{YABBT_FAKE_BW_ATTACHMENT_TRANSFER_LOG:-}}" ]; then
      printf 'start %s\n' "${{3:-}}" >> "$YABBT_FAKE_BW_ATTACHMENT_TRANSFER_LOG"
    fi
    if [ -n "${{YABBT_FAKE_BW_ATTACHMENT_SLEEP:-}}" ]; then
      sleep "$YABBT_FAKE_BW_ATTACHMENT_SLEEP"
    fi
    if [ -n "${{YABBT_FAKE_BW_SKIP_ATTACHMENT_WRITE:-}}" ]; then
      exit 0
    fi
    if [ "${{3:-}}" = "target-extra-attachment" ]; then
      printf 'extra-code' > "$out"
    else
      printf 'recovery-code' > "$out"
    fi
    if [ -n "${{YABBT_FAKE_BW_ATTACHMENT_TRANSFER_LOG:-}}" ]; then
      printf 'end %s\n' "${{3:-}}" >> "$YABBT_FAKE_BW_ATTACHMENT_TRANSFER_LOG"
    fi
    ;;
  *)
    echo "unexpected bw command: $*" >&2
    exit 1
    ;;
esac
"#,
            export_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/bitwarden/export.json")
                .display(),
            items_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/bitwarden/items.json")
                .display()
        ),
    )
    .expect("write fake bw");
    let mut permissions = fs::metadata(path).expect("metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("chmod fake bw");
}

#[cfg(unix)]
fn write_stateful_fake_bw(path: &Path, state_path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    allow_fake_bw_control_env();

    fs::write(state_path, r#"{"encrypted":false,"folders":[],"items":[]}"#)
        .expect("write initial stateful fake bw state");
    fs::write(
        path,
        r#"#!/usr/bin/env bash
set -euo pipefail

state="${YABBT_STATEFUL_BW_STATE:?}"

log_call() {
  if [ -n "${YABBT_FAKE_BW_LOG:-}" ]; then
    printf '%s\n' "$*" >> "$YABBT_FAKE_BW_LOG"
  fi
}

case "$1" in
  status)
    printf '{"status":"unlocked"}'
    ;;
  sync)
    exit 0
    ;;
  --raw)
    shift
    if [ "$1" = "export" ]; then
      cat "$state"
    else
      echo "unexpected bw command: --raw $*" >&2
      exit 1
    fi
    ;;
  export)
    cat "$state"
    ;;
  list)
    if [ "$2" = "items" ]; then
      python3 - "$state" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as handle:
    state = json.load(handle)
items = [
    {"id": item["id"], "attachments": item.get("attachments", [])}
    for item in state.get("items", [])
]
print(json.dumps(items, separators=(",", ":")))
PY
    else
      echo "unexpected bw list command: $*" >&2
      exit 1
    fi
    ;;
  create)
    # item/folder payloads now arrive on stdin (kept off argv).
    if [ "$2" = "folder" ] || [ "$2" = "item" ]; then
      encoded=$(cat)
      log_call "$@" "$encoded"
    else
      log_call "$@"
    fi
    if [ "$2" = "folder" ]; then
      python3 - "$state" "$encoded" <<'PY'
import base64, json, sys
state_path, encoded = sys.argv[1], sys.argv[2]
with open(state_path, "r", encoding="utf-8") as handle:
    state = json.load(handle)
payload = json.loads(base64.b64decode(encoded))
folder_id = f"folder-{len(state.get('folders', [])) + 1}"
payload["id"] = folder_id
state.setdefault("folders", []).append(payload)
with open(state_path, "w", encoding="utf-8") as handle:
    json.dump(state, handle, separators=(",", ":"))
print(json.dumps({"id": folder_id}, separators=(",", ":")))
PY
    elif [ "$2" = "item" ]; then
      python3 - "$state" "$encoded" <<'PY'
import base64, json, sys
state_path, encoded = sys.argv[1], sys.argv[2]
with open(state_path, "r", encoding="utf-8") as handle:
    state = json.load(handle)
payload = json.loads(base64.b64decode(encoded))
item_id = f"item-{len(state.get('items', [])) + 1}"
payload["id"] = item_id
state.setdefault("items", []).append(payload)
with open(state_path, "w", encoding="utf-8") as handle:
    json.dump(state, handle, separators=(",", ":"))
print(json.dumps({"id": item_id}, separators=(",", ":")))
PY
    elif [ "$2" = "attachment" ]; then
      python3 - "$state" "$@" <<'PY'
import json, os, sys
state_path = sys.argv[1]
args = sys.argv[2:]
item_id = args[args.index("--itemid") + 1]
file_path = args[args.index("--file") + 1]
with open(state_path, "r", encoding="utf-8") as handle:
    state = json.load(handle)
for item in state.get("items", []):
    if item.get("id") == item_id:
        attachments = item.setdefault("attachments", [])
        attachment_id = f"attachment-{len(attachments) + 1}"
        attachments.append({
            "id": attachment_id,
            "fileName": os.path.basename(file_path),
            "size": os.path.getsize(file_path),
        })
        break
else:
    raise SystemExit(f"item {item_id} not found")
with open(state_path, "w", encoding="utf-8") as handle:
    json.dump(state, handle, separators=(",", ":"))
print(json.dumps({"id": attachment_id}, separators=(",", ":")))
PY
    else
      echo "unexpected bw create command: $*" >&2
      exit 1
    fi
    ;;
  edit)
    # The item id stays in argv ($3); the payload arrives on stdin.
    encoded=$(cat)
    log_call "$@" "$encoded"
    if [ "$2" = "item" ]; then
      python3 - "$state" "$3" "$encoded" <<'PY'
import base64, json, sys
state_path, item_id, encoded = sys.argv[1], sys.argv[2], sys.argv[3]
with open(state_path, "r", encoding="utf-8") as handle:
    state = json.load(handle)
payload = json.loads(base64.b64decode(encoded))
payload["id"] = item_id
items = state.setdefault("items", [])
for index, item in enumerate(items):
    if item.get("id") == item_id:
        if "attachments" not in payload and "attachments" in item:
            payload["attachments"] = item["attachments"]
        items[index] = payload
        break
else:
    items.append(payload)
with open(state_path, "w", encoding="utf-8") as handle:
    json.dump(state, handle, separators=(",", ":"))
print(json.dumps({"id": item_id}, separators=(",", ":")))
PY
    else
      echo "unexpected bw edit command: $*" >&2
      exit 1
    fi
    ;;
  delete)
    log_call "$@"
    if [ "$2" = "item" ]; then
      python3 - "$state" "$3" <<'PY'
import json, sys
state_path, item_id = sys.argv[1], sys.argv[2]
with open(state_path, "r", encoding="utf-8") as handle:
    state = json.load(handle)
state["items"] = [
    item for item in state.get("items", [])
    if item.get("id") != item_id
]
with open(state_path, "w", encoding="utf-8") as handle:
    json.dump(state, handle, separators=(",", ":"))
PY
    elif [ "$2" = "attachment" ]; then
      python3 - "$state" "$@" <<'PY'
import json, sys
state_path = sys.argv[1]
args = sys.argv[2:]
attachment_id = args[2]
if "--itemid" not in args:
    raise SystemExit("`itemid` option is required.")
item_id = args[args.index("--itemid") + 1]
with open(state_path, "r", encoding="utf-8") as handle:
    state = json.load(handle)
for item in state.get("items", []):
    if item.get("id") != item_id:
        continue
    item["attachments"] = [
        attachment for attachment in item.get("attachments", [])
        if attachment.get("id") != attachment_id
    ]
with open(state_path, "w", encoding="utf-8") as handle:
    json.dump(state, handle, separators=(",", ":"))
PY
    elif [ "$2" = "folder" ]; then
      python3 - "$state" "$3" <<'PY'
import json, sys
state_path, folder_id = sys.argv[1], sys.argv[2]
with open(state_path, "r", encoding="utf-8") as handle:
    state = json.load(handle)
state["folders"] = [
    folder for folder in state.get("folders", [])
    if folder.get("id") != folder_id
]
with open(state_path, "w", encoding="utf-8") as handle:
    json.dump(state, handle, separators=(",", ":"))
PY
    else
      echo "unexpected bw delete command: $*" >&2
      exit 1
    fi
    ;;
  get)
    if [ "${2:-}" = "item" ]; then
      log_call "$@"
      python3 - "$state" "$3" <<'PY'
import json, sys
state_path, item_id = sys.argv[1], sys.argv[2]
with open(state_path, "r", encoding="utf-8") as handle:
    state = json.load(handle)
for item in state.get("items", []):
    if item.get("id") == item_id:
        print(json.dumps(item, separators=(",", ":")))
        break
else:
    raise SystemExit(1)
PY
      exit 0
    fi
    out=""
    prev=""
    for arg in "$@"; do
      if [ "$prev" = "--output" ]; then
        out="$arg"
      fi
      prev="$arg"
    done
    if [ "${3:-}" = "extra-attachment" ]; then
      printf 'extra-code' > "$out"
    else
      printf 'recovery-code' > "$out"
    fi
    ;;
  *)
    echo "unexpected bw command: $*" >&2
    exit 1
    ;;
esac
"#,
    )
    .expect("write stateful fake bw");
    let mut permissions = fs::metadata(path).expect("metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("chmod stateful fake bw");
}

fn decode_create_item_payload(line: &str) -> serde_json::Value {
    decode_item_payload_arg(line, 2)
}

fn decode_item_payload_arg(line: &str, index: usize) -> serde_json::Value {
    let encoded = line
        .split_whitespace()
        .nth(index)
        .expect("encoded item payload");
    let decoded = BASE64.decode(encoded).expect("decode item payload");
    serde_json::from_slice(&decoded).expect("json payload")
}

fn write_sample_archive(path: &Path) {
    write_archive(path, sample_vault());
}

fn write_multi_attachment_bitwarden_files(temp_path: &Path) -> (PathBuf, PathBuf) {
    let export_path = temp_path.join("multi-attachment-export.json");
    fs::write(
        &export_path,
        r#"{
  "encrypted": false,
  "folders": [],
  "items": [
    {
      "id": "item-1",
      "type": 1,
      "name": "Example Login",
      "notes": null,
      "favorite": false,
      "login": {
        "username": "alice",
        "password": "correct horse battery staple",
        "uris": []
      },
      "fields": []
    }
  ]
}"#,
    )
    .expect("write multi attachment export");
    let items_path = temp_path.join("multi-attachment-items.json");
    fs::write(
        &items_path,
        r#"[
  {
    "id": "item-1",
    "attachments": [
      {"id":"attachment-1","fileName":"one.txt","size":13},
      {"id":"attachment-2","fileName":"two.txt","size":13},
      {"id":"attachment-3","fileName":"three.txt","size":13},
      {"id":"attachment-4","fileName":"four.txt","size":13}
    ]
  }
]"#,
    )
    .expect("write multi attachment items");

    (export_path, items_path)
}

/// `bw list items` output for an account that can also see organization
/// items: the default export fixture covers `item-1` only, so the two org
/// items are listed but not exported (the personal-scope situation).
fn write_org_visible_items(temp_path: &Path) -> PathBuf {
    let items_path = temp_path.join("org-visible-items.json");
    fs::write(
        &items_path,
        r#"[
  {
    "id": "item-1",
    "organizationId": null,
    "attachments": [
      {"id":"attachment-1","fileName":"recovery.txt","size":13}
    ]
  },
  {"id":"org-item-1","organizationId":"org-secret-id","name":"Org Secret Name","attachments":[]},
  {"id":"org-item-2","organizationId":"org-secret-id","name":"Other Org Item","attachments":[]}
]"#,
    )
    .expect("write org-visible items");
    items_path
}

fn assert_no_org_details(output: &str) {
    for secret in [
        "Org Secret Name",
        "Other Org Item",
        "org-secret-id",
        "org-item-1",
    ] {
        assert!(!output.contains(secret), "leaked `{secret}`:\n{output}");
    }
}

fn write_new_item_archive(temp_path: &Path) -> std::path::PathBuf {
    let mut archive_vault = sample_vault();
    archive_vault.items[0].id = "new-item".to_string();
    archive_vault.items[0].attachments[0].path =
        "attachments/new-item/attachment-1.bin".to_string();
    let archive_path = temp_path.join("restore-apply.yabbt");
    ArchiveBuilder::new(archive_vault)
        .attachment(ArchiveAttachment {
            path: "attachments/new-item/attachment-1.bin".to_string(),
            bytes: b"recovery-code".to_vec(),
        })
        .write(&archive_path, STRONG_TEST_PASSPHRASE, WriteMode::Overwrite)
        .expect("write apply archive");
    archive_path
}

fn write_new_item_multi_attachment_archive(temp_path: &Path) -> std::path::PathBuf {
    let mut archive_vault = sample_vault();
    archive_vault.items[0].id = "new-item".to_string();
    archive_vault.items[0].attachments = (1..=4)
        .map(|index| AttachmentRef {
            id: format!("attachment-{index}"),
            file_name: format!("recovery-{index}.txt"),
            size: 13,
            sha256: "7b3ab6aba8e82522c98468aa813ae3d894b485b9fe936d275e8ff169159d13a0".to_string(),
            path: format!("attachments/new-item/attachment-{index}.bin"),
        })
        .collect();
    let archive_path = temp_path.join("restore-apply-multi-attachment.yabbt");
    let mut archive = ArchiveBuilder::new(archive_vault);
    for index in 1..=4 {
        archive = archive.attachment(ArchiveAttachment {
            path: format!("attachments/new-item/attachment-{index}.bin"),
            bytes: b"recovery-code".to_vec(),
        });
    }
    archive
        .write(&archive_path, STRONG_TEST_PASSPHRASE, WriteMode::Overwrite)
        .expect("write multi attachment apply archive");
    archive_path
}

fn write_prune_target_files(temp_path: &Path) -> (PathBuf, PathBuf) {
    let export_path = temp_path.join("target-prune-export.json");
    fs::write(
        &export_path,
        r#"{
  "encrypted": false,
  "folders": [
    {"id":"folder-1","name":"Sensitive Folder"},
    {"id":"extra-folder","name":"Extra Folder"}
  ],
  "items": [
    {
      "id":"item-1",
      "folderId":"folder-1",
      "type":1,
      "name":"Secret Login",
      "notes":"secret note",
      "favorite":false,
      "login":{
        "username":"alice",
        "password":"hunter2",
        "totp":"otpauth://totp/example",
        "uris":[{"uri":"https://example.test"}]
      },
      "fields":[{"name":"pin","value":"1234","type":1}]
    },
    {
      "id":"target-only-item",
      "folderId":"extra-folder",
      "type":2,
      "name":"Target Only Secret",
      "notes":"delete me",
      "favorite":false,
      "secureNote":{"type":0},
      "fields":[]
    }
  ]
}"#,
    )
    .expect("write prune target export");
    let items_path = temp_path.join("target-prune-items.json");
    fs::write(
        &items_path,
        r#"[{"id":"item-1","attachments":[{"id":"attachment-1","fileName":"recovery.txt","size":13},{"id":"target-extra-attachment","fileName":"extra.txt","size":9}]},{"id":"target-only-item","attachments":[]}]"#,
    )
    .expect("write prune target items");
    (export_path, items_path)
}

fn write_archive(path: &Path, vault: Vault) {
    ArchiveBuilder::new(vault)
        .attachment(ArchiveAttachment {
            path: "attachments/item-1/attachment-1.bin".to_string(),
            bytes: b"recovery-code".to_vec(),
        })
        .write(path, STRONG_TEST_PASSPHRASE, WriteMode::Overwrite)
        .expect("write sample archive");
}

fn write_existing_item_extra_attachment_archive(path: &Path) {
    let mut vault = sample_vault();
    vault.items[0].attachments.push(AttachmentRef {
        id: "attachment-extra".to_string(),
        file_name: "existing-extra.txt".to_string(),
        size: 19,
        sha256: "90889bde6bc2d3518bea33a67f1f9e6b68246f122b0c87fdd5fd6420e451e6a5".to_string(),
        path: "attachments/item-1/attachment-extra.bin".to_string(),
    });

    ArchiveBuilder::new(vault)
        .attachment(ArchiveAttachment {
            path: "attachments/item-1/attachment-1.bin".to_string(),
            bytes: b"recovery-code".to_vec(),
        })
        .attachment(ArchiveAttachment {
            path: "attachments/item-1/attachment-extra.bin".to_string(),
            bytes: b"existing-extra-code".to_vec(),
        })
        .write(path, STRONG_TEST_PASSPHRASE, WriteMode::Overwrite)
        .expect("write extra attachment archive");
}

fn write_organization_item_archive(path: &Path) {
    let mut vault = sample_vault();
    vault.items[0].backend_metadata.push((
        "bitwarden.raw".to_string(),
        r#"{
  "id": "item-1",
  "organizationId": "source-org",
  "collectionIds": ["source-collection"],
  "folderId": "folder-1",
  "type": 1,
  "name": "Secret Login",
  "notes": "secret note",
  "favorite": false,
  "login": {
    "username": "alice",
    "password": "hunter2",
    "uris": [{"uri": "https://example.test"}]
  },
  "fields": []
}"#
        .to_string(),
    ));
    write_archive(path, vault);
}

fn write_organization_item_without_collections_archive(path: &Path) {
    let mut vault = sample_vault();
    vault.items[0].id = "org-new-item".to_string();
    vault.items[0].attachments[0].path = "attachments/org-new-item/attachment-1.bin".to_string();
    vault.items[0].backend_metadata.push((
        "bitwarden.raw".to_string(),
        r#"{
  "id": "org-new-item",
  "organizationId": "source-org",
  "collectionIds": [],
  "folderId": "folder-1",
  "type": 1,
  "name": "Secret Login",
  "notes": "secret note",
  "favorite": false,
  "login": {
    "username": "alice",
    "password": "hunter2",
    "uris": [{"uri": "https://example.test"}]
  },
  "fields": []
}"#
        .to_string(),
    ));
    ArchiveBuilder::new(vault)
        .attachment(ArchiveAttachment {
            path: "attachments/org-new-item/attachment-1.bin".to_string(),
            bytes: b"recovery-code".to_vec(),
        })
        .write(path, STRONG_TEST_PASSPHRASE, WriteMode::Overwrite)
        .expect("write organization archive");
}

fn sample_vault() -> Vault {
    Vault {
        metadata: VaultMetadata {
            archive_version: 1,
            source_backend: "fixture".to_string(),
            source_server: Some("https://vault.example.test".to_string()),
            created_at: "2026-05-03T12:00:00Z".to_string(),
            tool_version: "0.1.0".to_string(),
        },
        folders: vec![Folder {
            id: "folder-1".to_string(),
            name: "Sensitive Folder".to_string(),
        }],
        items: vec![VaultItem {
            id: "item-1".to_string(),
            kind: ItemKind::Login {
                username: "alice".to_string(),
                password: "hunter2".to_string(),
                uris: vec!["https://example.test".to_string()],
                totp: Some("otpauth://totp/example".to_string()),
            },
            name: "Secret Login".to_string(),
            notes: Some("secret note".to_string()),
            folder_id: Some("folder-1".to_string()),
            favorite: false,
            fields: vec![Field {
                name: "pin".to_string(),
                value: "1234".to_string(),
                hidden: true,
            }],
            attachments: vec![AttachmentRef {
                id: "attachment-1".to_string(),
                file_name: "recovery.txt".to_string(),
                size: 13,
                sha256: "7b3ab6aba8e82522c98468aa813ae3d894b485b9fe936d275e8ff169159d13a0"
                    .to_string(),
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

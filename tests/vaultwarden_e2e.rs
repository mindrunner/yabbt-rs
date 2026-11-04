mod support;

use assert_cmd::Command;
use predicates::prelude::*;
use support::E2eResult;
use support::bw_live::write_attachment_file;
use support::bw_live::{BwAccount, apply_yabbt_bw_env};
use support::e2e_seed::{seed_source_account, semantic_shape};
use support::vaultwarden::VaultwardenConfig;

const E2E_PASSPHRASE_ENV: &str = "YABBT_E2E_ARCHIVE_PASSPHRASE";
const E2E_PASSPHRASE: &str = "correct horse battery staple archive vault e2e";

#[test]
#[ignore = "requires a live Vaultwarden instance and dedicated test accounts"]
fn vaultwarden_backup_restore_round_trip_across_accounts() -> E2eResult<()> {
    if !support::live_e2e_enabled() {
        eprintln!("skipping Vaultwarden E2E; set YABBT_E2E_VAULTWARDEN=1 to run it");
        return Ok(());
    }

    let config = VaultwardenConfig::from_env()?;
    if let Some(admin) = config.admin_client()? {
        admin.ensure_ready()?;
        admin.reset_accounts_if_requested(&config)?;
    } else if config.reset_accounts {
        return Err("YABBT_E2E_RESET_ACCOUNTS=1 requires YABBT_E2E_VAULTWARDEN_ADMIN_TOKEN".into());
    }

    let temp = tempfile::tempdir()?;
    let archive_path = temp.path().join("vaultwarden-e2e.yabbt");

    let mut source = BwAccount::new(
        &config.base_url,
        &config.source.email,
        &config.source.password,
    )?;
    source.login().map_err(|error| {
        format!(
            "failed to login to source test account; ensure it is registered with the configured password, or reset/create it before running the E2E: {error}"
        )
    })?;
    let mut target = BwAccount::new(
        &config.base_url,
        &config.target.email,
        &config.target.password,
    )?;
    target.login().map_err(|error| {
        format!(
            "failed to login to target test account; ensure it is registered with the configured password, or reset/create it before running the E2E: {error}"
        )
    })?;

    source.cleanup_yabbt_e2e_data()?;
    target.cleanup_yabbt_e2e_data()?;

    let initial_source_shape = semantic_shape(&source.export_vault()?)?;
    if initial_source_shape.items != 0 || initial_source_shape.folders != 0 {
        return Err(format!(
            "source test account is not empty: {} items, {} folders; use a clean disposable source account before running",
            initial_source_shape.items, initial_source_shape.folders
        )
        .into());
    }
    let initial_target_shape = semantic_shape(&target.export_vault()?)?;
    if initial_target_shape.items != 0 || initial_target_shape.folders != 0 {
        return Err(format!(
            "target test account is not empty: {} items, {} folders; use a disposable target account or reset it before running",
            initial_target_shape.items, initial_target_shape.folders
        )
        .into());
    }

    let expected_shape = seed_source_account(&source, temp.path())?;

    let mut backup = Command::cargo_bin("yabbt")?;
    backup.args([
        "backup",
        "--source",
        "bw",
        "--server-url",
        source.server_url(),
        "--out",
        archive_path.to_str().ok_or("archive path must be UTF-8")?,
        "--passphrase-env",
        E2E_PASSPHRASE_ENV,
    ]);
    apply_yabbt_bw_env(&source, &mut backup);
    backup
        .env(E2E_PASSPHRASE_ENV, E2E_PASSPHRASE)
        .assert()
        .success()
        .stdout(predicate::str::contains("wrote backup archive"));

    let mut verify = Command::cargo_bin("yabbt")?;
    verify
        .args([
            "verify",
            archive_path.to_str().ok_or("archive path must be UTF-8")?,
            "--passphrase-env",
            E2E_PASSPHRASE_ENV,
        ])
        .env(E2E_PASSPHRASE_ENV, E2E_PASSPHRASE)
        .assert()
        .success()
        .stdout(predicate::str::contains("archive verified"))
        .stdout(predicate::str::contains(format!(
            "items: {}",
            expected_shape.items
        )))
        .stdout(predicate::str::contains(format!(
            "attachments: {}",
            expected_shape.attachments
        )));

    let mut inspect = Command::cargo_bin("yabbt")?;
    inspect
        .args([
            "inspect",
            archive_path.to_str().ok_or("archive path must be UTF-8")?,
            "--passphrase-env",
            E2E_PASSPHRASE_ENV,
        ])
        .env(E2E_PASSPHRASE_ENV, E2E_PASSPHRASE)
        .assert()
        .success()
        .stdout(predicate::str::contains("complete: true"))
        .stdout(predicate::str::contains("synthetic-password-primary").not())
        .stdout(predicate::str::contains("synthetic secure note body").not())
        .stdout(predicate::str::contains("synthetic-recovery-code").not());

    let mut restore = Command::cargo_bin("yabbt")?;
    restore.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().ok_or("archive path must be UTF-8")?,
        "--passphrase-env",
        E2E_PASSPHRASE_ENV,
        "--apply",
        "--verify-after",
    ]);
    apply_yabbt_bw_env(&target, &mut restore);
    restore
        .env(E2E_PASSPHRASE_ENV, E2E_PASSPHRASE)
        .assert()
        .success()
        .stdout(predicate::str::contains("restore applied"))
        .stdout(predicate::str::contains(format!(
            "items_created: {}",
            expected_shape.items
        )))
        .stdout(predicate::str::contains(format!(
            "attachments_uploaded: {}",
            expected_shape.attachments
        )))
        .stdout(predicate::str::contains("post_apply_verified: true"));

    let mut second_restore = Command::cargo_bin("yabbt")?;
    second_restore.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().ok_or("archive path must be UTF-8")?,
        "--passphrase-env",
        E2E_PASSPHRASE_ENV,
        "--apply",
        "--verify-after",
    ]);
    apply_yabbt_bw_env(&target, &mut second_restore);
    second_restore
        .env(E2E_PASSPHRASE_ENV, E2E_PASSPHRASE)
        .assert()
        .success()
        .stdout(predicate::str::contains("restore applied"))
        .stdout(predicate::str::contains("items_created: 0"))
        // A server round trip must not make restored items look changed.
        .stdout(predicate::str::contains("items_update_skipped: 0"))
        .stdout(predicate::str::contains("attachments_uploaded: 0"))
        .stdout(predicate::str::contains("post_apply_verified: true"));

    let target_vault_with_restored_items = target.export_vault()?;
    let restored_item_id = target_vault_with_restored_items
        .items
        .iter()
        .find(|item| item.name == "YABBT E2E Login Primary")
        .map(|item| item.id.clone())
        .ok_or("restored primary login item not found")?;
    let extra_attachment_path = write_attachment_file(
        temp.path(),
        "yabbt-e2e-target-only-extra.txt",
        b"synthetic target-only attachment\n",
    )?;
    target.create_attachment(&restored_item_id, &extra_attachment_path)?;

    let mut prune_restore = Command::cargo_bin("yabbt")?;
    prune_restore.args([
        "restore",
        "--target",
        "bw",
        archive_path.to_str().ok_or("archive path must be UTF-8")?,
        "--passphrase-env",
        E2E_PASSPHRASE_ENV,
        "--apply",
        "--verify-after",
        "--prune",
    ]);
    apply_yabbt_bw_env(&target, &mut prune_restore);
    prune_restore
        .env(E2E_PASSPHRASE_ENV, E2E_PASSPHRASE)
        .assert()
        .success()
        .stdout(predicate::str::contains("restore applied"))
        .stdout(predicate::str::contains("items_created: 0"))
        .stdout(predicate::str::contains("attachments_uploaded: 0"))
        .stdout(predicate::str::contains("attachments_deleted: 1"))
        .stdout(predicate::str::contains("post_apply_verified: true"))
        .stdout(predicate::str::contains("deleted_attachments_verified: 1"));

    let actual_shape = semantic_shape(&target.export_vault()?)?;
    assert_eq!(actual_shape, expected_shape);

    Ok(())
}

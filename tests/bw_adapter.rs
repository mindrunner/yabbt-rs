use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use yabbt::adapters::bitwarden_json::normalize_export;
use yabbt::adapters::bw::{BwAttachmentMode, BwProfileEnv, BwSourceAdapter, BwSourceOptions};
use yabbt::adapters::command::{CommandOutput, CommandRequest, CommandRunner};
use yabbt::archive::OpenedArchive;
use yabbt::model::{CompletenessReport, Field, ItemKind, Vault, VaultItem, VaultMetadata};
use yabbt::progress::NoopProgress;
use yabbt::restore_apply::{
    ApplyOptions, ApplySummary, AttachmentUpload, UploadedAttachment, VaultTargetOps,
    apply_restore_plan, verify_applied_restore,
};
use yabbt::restore_map::RESTORE_MAP_FIELD_NAME;
use yabbt::restore_plan::{RestorePlan, plan_restore};

const EXPORT_JSON: &str = include_str!("fixtures/bitwarden/export.json");
const ITEMS_JSON: &str = include_str!("fixtures/bitwarden/items.json");

#[derive(Debug)]
struct FakeRunner {
    calls: Mutex<Vec<CommandRequest>>,
    responses: Mutex<VecDeque<FakeResponse>>,
}

#[derive(Debug)]
struct FakeResponse {
    output: CommandOutput,
    write_attachment: Option<Vec<u8>>,
}

impl FakeRunner {
    fn new(responses: Vec<FakeResponse>) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            responses: Mutex::new(responses.into()),
        }
    }

    fn calls(&self) -> Vec<CommandRequest> {
        self.calls.lock().expect("calls mutex poisoned").clone()
    }
}

impl CommandRunner for FakeRunner {
    fn run(&self, request: CommandRequest) -> Result<CommandOutput, yabbt::adapters::AdapterError> {
        self.calls
            .lock()
            .expect("calls mutex poisoned")
            .push(request.clone());
        let response = self
            .responses
            .lock()
            .expect("responses mutex poisoned")
            .pop_front()
            .expect("fake response exists");
        if let Some(bytes) = response.write_attachment {
            let output_path = request
                .args
                .windows(2)
                .find_map(|args| (args[0] == "--output").then(|| PathBuf::from(&args[1])))
                .expect("attachment command has --output");
            fs::write(output_path, bytes).expect("write fake attachment");
        }
        Ok(response.output)
    }
}

fn summary_with_uploaded(uploaded_attachments: Vec<UploadedAttachment>) -> ApplySummary {
    ApplySummary {
        attachments_uploaded: uploaded_attachments.len(),
        uploaded_attachments,
        ..ApplySummary::default()
    }
}

fn success(stdout: impl Into<Vec<u8>>) -> FakeResponse {
    FakeResponse {
        output: CommandOutput {
            status: 0,
            stdout: stdout.into(),
            stderr: Vec::new(),
        },
        write_attachment: None,
    }
}

fn unlocked() -> FakeResponse {
    success(r#"{"status":"unlocked"}"#)
}

fn locked() -> FakeResponse {
    success(r#"{"status":"locked"}"#)
}

fn unauthenticated() -> FakeResponse {
    success(r#"{"status":"unauthenticated"}"#)
}

fn failure(stderr: impl Into<Vec<u8>>) -> FakeResponse {
    FakeResponse {
        output: CommandOutput {
            status: 1,
            stdout: Vec::new(),
            stderr: stderr.into(),
        },
        write_attachment: None,
    }
}

#[test]
fn command_runner_keeps_arguments_structured() {
    let runner = FakeRunner::new(vec![success(Vec::new())]);

    runner
        .run(CommandRequest::new(
            "bw",
            vec![
                "get".to_string(),
                "attachment".to_string(),
                "semi;colon".to_string(),
                "--output".to_string(),
                "/tmp/file with spaces".to_string(),
            ],
        ))
        .expect("fake command succeeds");

    let calls = runner.calls();
    assert_eq!(calls[0].program, "bw");
    assert_eq!(calls[0].args[2], "semi;colon");
    assert_eq!(calls[0].args[4], "/tmp/file with spaces");
}

fn env_value<'a>(call: &'a CommandRequest, name: &str) -> Option<&'a str> {
    call.env
        .iter()
        .rev()
        .find(|(key, _)| key == name)
        .and_then(|(_, value)| value.to_str())
}

#[test]
fn bw_adapter_injects_profile_env_into_every_command() {
    let runner = FakeRunner::new(vec![
        unlocked(),
        success(Vec::new()),
        success(EXPORT_JSON.as_bytes().to_vec()),
        success("[]".as_bytes().to_vec()),
    ]);
    let adapter = BwSourceAdapter::new(
        runner,
        BwSourceOptions {
            attachment_mode: BwAttachmentMode::MetadataOnly,
            profile: Some(BwProfileEnv {
                appdata_dir: PathBuf::from("/tmp/yabbt-profile-prod"),
                session: Some("profile-session-key".to_string()),
            }),
            ..BwSourceOptions::default()
        },
    );

    adapter
        .export_with_progress(&NoopProgress)
        .expect("export fixture");

    let calls = adapter.runner().calls();
    assert!(!calls.is_empty());
    for call in &calls {
        assert!(call.env_clear, "bw must not inherit the parent environment");
        assert_eq!(
            env_value(call, "BITWARDENCLI_APPDATA_DIR"),
            Some("/tmp/yabbt-profile-prod")
        );
        assert_eq!(env_value(call, "BW_SESSION"), Some("profile-session-key"));
        assert_eq!(
            call.env
                .iter()
                .filter(|(name, _)| name == "BW_SESSION")
                .count(),
            1
        );
        assert_eq!(env_value(call, "BW_NOINTERACTION"), Some("true"));
    }
}

#[test]
fn bw_adapter_builds_a_cleared_allowlisted_env_without_profile() {
    let runner = FakeRunner::new(vec![
        unlocked(),
        success(Vec::new()),
        success(EXPORT_JSON.as_bytes().to_vec()),
        success("[]".as_bytes().to_vec()),
    ]);
    let adapter = BwSourceAdapter::new(
        runner,
        BwSourceOptions {
            attachment_mode: BwAttachmentMode::MetadataOnly,
            ..BwSourceOptions::default()
        },
    );

    adapter
        .export_with_progress(&NoopProgress)
        .expect("export fixture");

    for call in adapter.runner().calls() {
        assert!(call.env_clear, "bw must not inherit the parent environment");
        assert_eq!(env_value(&call, "BW_NOINTERACTION"), Some("true"));
        for denied in yabbt::bw_env::DENIED_ENV_VARS {
            if *denied != "BW_NOINTERACTION" {
                assert_eq!(env_value(&call, denied), None, "{denied} reached bw");
            }
        }
    }
}

#[test]
fn bitwarden_json_normalizes_items_folders_fields_and_attachments() {
    let vault = normalize_export(
        EXPORT_JSON,
        ITEMS_JSON,
        "bw",
        Some("https://vault.example.test"),
    )
    .expect("normalize fixture");

    assert_eq!(vault.metadata.source_backend, "bw");
    assert_eq!(
        vault.metadata.source_server.as_deref(),
        Some("https://vault.example.test")
    );
    assert_eq!(vault.folders[0].name, "Infrastructure");
    assert_eq!(vault.items[0].name, "Example Login");
    assert_eq!(vault.items[0].attachments[0].id, "attachment-1");
    assert_eq!(
        vault.items[0].attachments[0].path,
        "attachments/item-1/attachment-1.bin"
    );
    assert!(
        vault.items[0]
            .backend_metadata
            .iter()
            .any(|(key, _)| key == "bitwarden.raw")
    );
}

#[test]
fn personal_backup_marks_listed_but_unexported_org_items_incomplete() {
    // `bw export` without --organizationid covers only the personal vault,
    // while `bw list items` also returns organization items.
    let listed_items = r#"[
        { "id": "item-1", "organizationId": null, "attachments": [] },
        { "id": "org-item-1", "organizationId": "org-secret-id", "name": "Org Secret Name" },
        { "id": "org-item-2", "organizationId": "org-secret-id", "name": "Other Org Item" }
    ]"#;
    let runner = FakeRunner::new(vec![
        unlocked(),
        success(Vec::new()),
        success(EXPORT_JSON.as_bytes().to_vec()),
        success(listed_items.as_bytes().to_vec()),
    ]);
    let adapter = BwSourceAdapter::new(
        runner,
        BwSourceOptions {
            attachment_mode: BwAttachmentMode::MetadataOnly,
            ..BwSourceOptions::default()
        },
    );

    let vault = adapter
        .export_with_progress(&NoopProgress)
        .expect("export succeeds with a warning")
        .vault;

    assert_eq!(vault.items.len(), 1);
    assert!(!vault.report.complete, "org items were silently dropped");
    let warning = vault
        .report
        .warnings
        .iter()
        .find(|warning| warning.code == "org-items-not-exported")
        .expect("org-items-not-exported warning");
    assert!(warning.message.contains('2'), "{}", warning.message);
    assert!(warning.message.contains("--organization-id"));
    assert!(warning.message.contains("--personal-only"));
    assert!(!warning.message.contains("Org Secret Name"));
    assert!(!warning.message.contains("org-secret-id"));
    assert!(!warning.message.contains("org-item-1"));
}

#[test]
fn personal_only_backup_accepts_scope_and_keeps_count_only_warning() {
    let listed_items = r#"[
        { "id": "item-1", "organizationId": null, "attachments": [] },
        { "id": "org-item-1", "organizationId": "org-secret-id", "name": "Org Secret Name" },
        { "id": "org-item-2", "organizationId": "org-secret-id", "name": "Other Org Item" }
    ]"#;
    let runner = FakeRunner::new(vec![
        unlocked(),
        success(Vec::new()),
        success(EXPORT_JSON.as_bytes().to_vec()),
        success(listed_items.as_bytes().to_vec()),
    ]);
    let adapter = BwSourceAdapter::new(
        runner,
        BwSourceOptions {
            attachment_mode: BwAttachmentMode::MetadataOnly,
            personal_only: true,
            ..BwSourceOptions::default()
        },
    );

    let vault = adapter
        .export_with_progress(&NoopProgress)
        .expect("export succeeds")
        .vault;

    assert!(vault.report.complete, "scope was explicitly acknowledged");
    assert_eq!(vault.report.warnings.len(), 1);
    let warning = &vault.report.warnings[0];
    assert_eq!(warning.code, "org-items-excluded-by-scope");
    assert!(
        warning.message.contains("2 organization item(s)"),
        "{}",
        warning.message
    );
    assert!(!warning.message.contains("Org Secret Name"));
    assert!(!warning.message.contains("org-secret-id"));
    assert!(!warning.message.contains("org-item-1"));
}

#[test]
fn personal_only_backup_without_org_items_adds_no_warning() {
    let runner = FakeRunner::new(vec![
        unlocked(),
        success(Vec::new()),
        success(EXPORT_JSON.as_bytes().to_vec()),
        success(br#"[{ "id": "item-1", "organizationId": null, "attachments": [] }]"#.to_vec()),
    ]);
    let adapter = BwSourceAdapter::new(
        runner,
        BwSourceOptions {
            attachment_mode: BwAttachmentMode::MetadataOnly,
            personal_only: true,
            ..BwSourceOptions::default()
        },
    );

    let vault = adapter
        .export_with_progress(&NoopProgress)
        .expect("export succeeds")
        .vault;

    assert!(vault.report.complete);
    assert!(vault.report.warnings.is_empty());
}

#[test]
fn personal_backup_without_org_items_stays_complete() {
    let listed_items = r#"[{ "id": "item-1", "organizationId": null, "attachments": [] }]"#;

    let vault = normalize_export(EXPORT_JSON, listed_items, "bw", None).expect("normalize");

    assert!(vault.report.complete);
    assert!(vault.report.warnings.is_empty());
}

#[test]
fn bitwarden_json_maps_ssh_key_and_tolerates_unknown_or_missing_item_types() {
    let export = r#"{
        "encrypted": false,
        "folders": [],
        "items": [
            { "id": "ssh", "type": 5, "name": "Deploy key", "sshKey": { "keyFingerprint": "SHA256:x" } },
            { "id": "future", "type": 7, "name": "Future item" },
            { "id": "untyped", "name": "No type" }
        ]
    }"#;

    let vault = normalize_export(export, "[]", "bw", None).expect("normalize mixed item types");

    assert_eq!(vault.items[0].kind, ItemKind::SshKey);
    assert_eq!(
        vault.items[1].kind,
        ItemKind::Unknown {
            kind: "bitwarden-type-7".to_string()
        }
    );
    assert_eq!(
        vault.items[2].kind,
        ItemKind::Unknown {
            kind: "bitwarden-type-0".to_string()
        }
    );

    // A vault holding such items must serialize (backup writes vault.json) and
    // fingerprint (diff/restore planning) without panicking.
    let restored = Vault::from_json(&vault.to_json()).expect("vault round-trips");
    assert_eq!(restored, vault);
    for item in &vault.items {
        let _ = yabbt::diff::item_fingerprint(item);
    }
}

#[test]
fn bitwarden_json_accepts_string_attachment_sizes_from_live_bw() {
    let listed_items = r#"
        [
          {
            "id": "item-1",
            "attachments": [
              { "id": "attachment-1", "fileName": "recovery.txt", "size": "13" }
            ]
          }
        ]
    "#;

    let vault = normalize_export(
        EXPORT_JSON,
        listed_items,
        "bw",
        Some("https://vault.example.test"),
    )
    .expect("normalize live-style attachment size");

    assert_eq!(vault.items[0].attachments[0].size, 13);
}

#[test]
fn bw_adapter_runs_expected_commands_and_collects_attachment_bytes() {
    let runner = FakeRunner::new(vec![
        unlocked(),
        success(Vec::new()),
        success(EXPORT_JSON.as_bytes().to_vec()),
        success(ITEMS_JSON.as_bytes().to_vec()),
        FakeResponse {
            output: CommandOutput {
                status: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
            write_attachment: Some(b"recovery-code".to_vec()),
        },
    ]);
    let adapter = BwSourceAdapter::new(
        runner,
        BwSourceOptions {
            server_url: None,
            organization_id: None,
            strict: true,
            attachment_jobs: 4,
            attachment_mode: BwAttachmentMode::Download,
            profile: None,
            personal_only: false,
        },
    );

    let export = adapter
        .export_with_progress(&NoopProgress)
        .expect("export fixture");

    assert_eq!(export.vault.items.len(), 1);
    assert_eq!(export.attachments[0].bytes, b"recovery-code");
    assert_eq!(export.vault.items[0].attachments[0].size, 13);
    assert_eq!(
        export.vault.items[0].attachments[0].sha256,
        "7b3ab6aba8e82522c98468aa813ae3d894b485b9fe936d275e8ff169159d13a0"
    );

    let calls = adapter.runner().calls();
    assert_eq!(calls[0].args, ["status"]);
    assert_eq!(calls[1].args, ["sync"]);
    assert_eq!(calls[2].args, ["--raw", "export", "--format", "json"]);
    assert_eq!(calls[3].args, ["list", "items"]);
    assert_eq!(calls[4].args[0..3], ["get", "attachment", "attachment-1"]);
    assert!(calls[4].args.contains(&"--itemid".to_string()));
    assert!(calls[4].args.contains(&"item-1".to_string()));
}

#[test]
fn bw_adapter_supports_organization_scope() {
    let runner = FakeRunner::new(vec![
        unlocked(),
        success(Vec::new()),
        success(EXPORT_JSON.as_bytes().to_vec()),
        success("[]".as_bytes().to_vec()),
    ]);
    let adapter = BwSourceAdapter::new(
        runner,
        BwSourceOptions {
            server_url: None,
            organization_id: Some("org-1".to_string()),
            strict: true,
            attachment_jobs: 4,
            attachment_mode: BwAttachmentMode::Download,
            profile: None,
            personal_only: false,
        },
    );

    adapter
        .export_with_progress(&NoopProgress)
        .expect("export fixture");

    let calls = adapter.runner().calls();
    assert_eq!(
        calls[2].args,
        [
            "--raw",
            "export",
            "--format",
            "json",
            "--organizationid",
            "org-1"
        ]
    );
    assert_eq!(
        calls[3].args,
        ["list", "items", "--organizationid", "org-1"]
    );
}

#[test]
fn bw_adapter_fails_before_sync_when_vault_is_locked() {
    let runner = FakeRunner::new(vec![locked()]);
    let adapter = BwSourceAdapter::new(runner, BwSourceOptions::default());

    let error = adapter
        .export_with_progress(&NoopProgress)
        .expect_err("locked vault fails early");

    assert!(error.to_string().contains("bw vault is locked"));
    let calls = adapter.runner().calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].args, ["status"]);
}

#[test]
fn bw_adapter_fails_before_sync_when_bw_is_unauthenticated() {
    let runner = FakeRunner::new(vec![unauthenticated()]);
    let adapter = BwSourceAdapter::new(runner, BwSourceOptions::default());

    let error = adapter
        .export_with_progress(&NoopProgress)
        .expect_err("unauthenticated bw fails early");

    assert!(error.to_string().contains("bw is not logged in"));
    let calls = adapter.runner().calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].args, ["status"]);
}

#[test]
fn bw_adapter_profile_mode_errors_point_at_bw_login_not_bw_session() {
    for (status, expected) in [
        (locked(), "is locked"),
        (unauthenticated(), "is not logged in"),
    ] {
        let runner = FakeRunner::new(vec![status]);
        let adapter = BwSourceAdapter::new(
            runner,
            BwSourceOptions {
                profile: Some(BwProfileEnv {
                    appdata_dir: PathBuf::from("/data/yabbt/bw-profiles/prod"),
                    session: None,
                }),
                ..BwSourceOptions::default()
            },
        );

        let error = adapter
            .export_with_progress(&NoopProgress)
            .expect_err("profile not unlocked")
            .to_string();

        assert!(error.contains(expected), "{error}");
        assert!(error.contains("yabbt bw-login --profile prod"), "{error}");
        assert!(!error.contains("BW_SESSION"), "{error}");
    }
}

#[test]
fn bw_adapter_allows_server_url_when_logged_into_that_server() {
    let runner = FakeRunner::new(vec![
        failure("Logout required before server config update."),
        success("https://vault.example.test\n"),
        unlocked(),
        success(Vec::new()),
        success(EXPORT_JSON.as_bytes().to_vec()),
        success(ITEMS_JSON.as_bytes().to_vec()),
        FakeResponse {
            output: CommandOutput {
                status: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
            write_attachment: Some(b"recovery-code".to_vec()),
        },
    ]);
    let adapter = BwSourceAdapter::new(
        runner,
        BwSourceOptions {
            server_url: Some("https://vault.example.test".to_string()),
            organization_id: None,
            strict: true,
            attachment_jobs: 4,
            attachment_mode: BwAttachmentMode::Download,
            profile: None,
            personal_only: false,
        },
    );

    let export = adapter
        .export_with_progress(&NoopProgress)
        .expect("export from already-configured server");

    assert_eq!(
        export.vault.metadata.source_server.as_deref(),
        Some("https://vault.example.test")
    );
    let calls = adapter.runner().calls();
    assert_eq!(
        calls[0].args,
        ["config", "server", "https://vault.example.test"]
    );
    assert_eq!(calls[1].args, ["config", "server"]);
    assert_eq!(calls[2].args, ["status"]);
    assert_eq!(calls[3].args, ["sync"]);
}

#[test]
fn bw_adapter_verify_uploaded_attachments_accepts_string_sizes_from_live_bw() {
    let runner = FakeRunner::new(vec![
        success(Vec::new()),
        success(
            r#"{
            "id": "item-1",
            "attachments": [{
                "id": "attachment-1",
                "fileName": "recovery.txt",
                "size": "13"
            }]
        }"#,
        ),
        FakeResponse {
            output: CommandOutput {
                status: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
            write_attachment: Some(b"recovery-code".to_vec()),
        },
    ]);
    let adapter = BwSourceAdapter::new(runner, BwSourceOptions::default());

    let verification = verify_applied_restore(
        &adapter,
        &summary_with_uploaded(vec![UploadedAttachment {
            target_item_id: "item-1".to_string(),
            file_name: "recovery.txt".to_string(),
            size: 13,
            sha256: "7b3ab6aba8e82522c98468aa813ae3d894b485b9fe936d275e8ff169159d13a0".to_string(),
        }]),
        &NoopProgress,
    )
    .expect("verify live-style attachment size");

    assert_eq!(verification.attachments, 1);
    let calls = adapter.runner().calls();
    assert_eq!(calls[0].args, ["sync"]);
    assert_eq!(calls[1].args, ["get", "item", "item-1"]);
    assert_eq!(calls[2].args[0..3], ["get", "attachment", "attachment-1"]);
}

#[test]
fn bw_adapter_verify_uploaded_attachments_retries_stale_metadata() {
    let runner = FakeRunner::new(vec![
        success(Vec::new()),
        success(r#"{ "id": "item-1", "attachments": [] }"#),
        success(Vec::new()),
        success(
            r#"{
            "id": "item-1",
            "attachments": [{
                "id": "attachment-1",
                "fileName": "recovery.txt",
                "size": 13
            }]
        }"#,
        ),
        FakeResponse {
            output: CommandOutput {
                status: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
            write_attachment: Some(b"recovery-code".to_vec()),
        },
    ]);
    let adapter = BwSourceAdapter::new(runner, BwSourceOptions::default());

    let verification = verify_applied_restore(
        &adapter,
        &summary_with_uploaded(vec![UploadedAttachment {
            target_item_id: "item-1".to_string(),
            file_name: "recovery.txt".to_string(),
            size: 13,
            sha256: "7b3ab6aba8e82522c98468aa813ae3d894b485b9fe936d275e8ff169159d13a0".to_string(),
        }]),
        &NoopProgress,
    )
    .expect("verify after stale metadata refresh");

    assert_eq!(verification.attachments, 1);
    let calls = adapter.runner().calls();
    assert_eq!(calls[0].args, ["sync"]);
    assert_eq!(calls[1].args, ["get", "item", "item-1"]);
    assert_eq!(calls[2].args, ["sync"]);
    assert_eq!(calls[3].args, ["get", "item", "item-1"]);
    assert_eq!(calls[4].args[0..3], ["get", "attachment", "attachment-1"]);
}

#[test]
fn bw_adapter_fails_when_strict_attachment_download_is_missing() {
    let runner = FakeRunner::new(vec![
        unlocked(),
        success(Vec::new()),
        success(EXPORT_JSON.as_bytes().to_vec()),
        success(ITEMS_JSON.as_bytes().to_vec()),
        success(Vec::new()),
    ]);
    let adapter = BwSourceAdapter::new(runner, BwSourceOptions::default());

    let error = adapter
        .export_with_progress(&NoopProgress)
        .expect_err("missing attachment fails");

    assert!(error.to_string().contains("attachment"));
}

#[test]
fn bw_adapter_permissive_tolerates_failed_attachment_download() {
    let runner = FakeRunner::new(vec![
        unlocked(),
        success(Vec::new()),
        success(EXPORT_JSON.as_bytes().to_vec()),
        success(ITEMS_JSON.as_bytes().to_vec()),
        failure("Attachment not found."),
    ]);
    let adapter = BwSourceAdapter::new(
        runner,
        BwSourceOptions {
            strict: false,
            ..BwSourceOptions::default()
        },
    );

    let export = adapter
        .export_with_progress(&NoopProgress)
        .expect("permissive export tolerates a failed attachment download");

    assert_eq!(export.vault.items.len(), 1);
    assert!(export.attachments.is_empty());
    assert!(!export.vault.report.complete);
    let warning = export
        .vault
        .report
        .warnings
        .iter()
        .find(|warning| warning.code == "attachment-download-failed")
        .expect("attachment-download-failed warning");
    assert!(warning.message.contains("attachment-1"));
}

#[test]
fn bw_adapter_strict_fails_on_failed_attachment_download() {
    let runner = FakeRunner::new(vec![
        unlocked(),
        success(Vec::new()),
        success(EXPORT_JSON.as_bytes().to_vec()),
        success(ITEMS_JSON.as_bytes().to_vec()),
        failure("Attachment not found."),
    ]);
    let adapter = BwSourceAdapter::new(runner, BwSourceOptions::default());

    let error = adapter
        .export_with_progress(&NoopProgress)
        .expect_err("strict export fails");

    assert!(error.to_string().contains("Attachment not found"));
}

#[test]
fn bw_adapter_splits_large_restore_map_into_bounded_notes() {
    let item_count = 1_800;
    let archive = vault(
        (0..item_count)
            .map(|index| test_item(&format!("source-item-{index:04}"), index))
            .collect(),
    );
    let target = vault(
        archive
            .items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                let mut target_item = item.clone();
                target_item.id = format!("target-item-{index:04}");
                target_item
            })
            .collect(),
    );
    let plan = plan_restore(&archive, Some(&target), "bw");
    let runner = FakeRunner::new(
        (0..8)
            .map(|index| success(format!(r#"{{"id":"map-chunk-{index}"}}"#)))
            .collect(),
    );
    let adapter = BwSourceAdapter::new(runner, BwSourceOptions::default());

    let outcome = apply_restore_plan(
        &adapter,
        &OpenedArchive {
            vault: archive,
            attachments: Vec::new(),
        },
        &plan,
        &target,
        None,
        ApplyOptions {
            mark_restored: false,
            restore_map: true,
            update_existing: false,
            verify_after: false,
        },
        &NoopProgress,
    )
    .expect("apply restore map");

    assert!(outcome.summary.restore_map_updated);
    let calls = adapter.runner().calls();
    let map_create_calls = calls
        .iter()
        .filter(|call| call.args[0] == "create" && call.args[1] == "item")
        .collect::<Vec<_>>();
    assert!(
        map_create_calls.len() > 1,
        "large restore map should be split"
    );
    let mut total_entries = 0;
    for (index, call) in map_create_calls.iter().enumerate() {
        assert_eq!(
            call.args.len(),
            2,
            "create item payload must travel on stdin, not argv"
        );
        let encoded = call
            .stdin
            .as_ref()
            .expect("create item sends payload on stdin");
        assert!(
            encoded.len() <= 96 * 1024,
            "restore map chunk exceeded conservative per-argument budget"
        );
        let payload = decode_item_payload(encoded);
        assert_eq!(payload["type"], 2);
        let expected_name = if index == 0 {
            "yabbt restore map - do not edit".to_string()
        } else {
            format!("yabbt restore map - do not edit {}", index + 1)
        };
        assert_eq!(payload["name"], expected_name);
        let map_field = payload["fields"]
            .as_array()
            .expect("fields array")
            .iter()
            .find(|field| field["name"] == RESTORE_MAP_FIELD_NAME && field["type"] == 1)
            .expect("restore map field");
        let map: serde_json::Value =
            serde_json::from_str(map_field["value"].as_str().expect("map JSON"))
                .expect("valid map JSON");
        total_entries += map["entries"].as_object().expect("entries object").len();
    }
    assert_eq!(total_entries, item_count);
}

#[test]
fn bw_adapter_deletes_stale_restore_map_chunks_after_rechunking_smaller() {
    let archive_item = test_item("source-current", 0);
    let mut target_item = archive_item.clone();
    target_item.id = "target-current".to_string();
    let stale_entries = (0..12)
        .map(|index| format!("stale-source-{index:02}"))
        .collect::<Vec<_>>();
    let mut stale_plan_ids = stale_entries.clone();
    let chunk_one = restore_map_item(
        "restore-map-1",
        "yabbt restore map - do not edit",
        &[
            ("source-current", "target-current"),
            ("stale-source-00", "missing-target-00"),
        ],
    );
    let chunk_two = restore_map_item(
        "restore-map-2",
        "yabbt restore map - do not edit 2",
        &[
            ("stale-source-01", "missing-target-01"),
            ("stale-source-02", "missing-target-02"),
        ],
    );
    let chunk_three = restore_map_item(
        "restore-map-3",
        "yabbt restore map - do not edit 3",
        &[
            ("stale-source-03", "missing-target-03"),
            ("stale-source-04", "missing-target-04"),
        ],
    );
    let archive = vault(vec![archive_item]);
    let target = vault(vec![target_item, chunk_one, chunk_two, chunk_three]);
    let runner = FakeRunner::new(vec![
        success(Vec::new()),
        success(Vec::new()),
        success(Vec::new()),
    ]);
    let adapter = BwSourceAdapter::new(runner, BwSourceOptions::default());
    let mut matched_target_item_ids = BTreeMap::new();
    matched_target_item_ids.insert("source-current".to_string(), "target-current".to_string());
    stale_plan_ids.sort();

    apply_restore_plan(
        &adapter,
        &OpenedArchive {
            vault: archive,
            attachments: Vec::new(),
        },
        &RestorePlan {
            target_backend: "bw".to_string(),
            dry_run: false,
            archive_scope: "personal".to_string(),
            archive_items: 1,
            target_items_scanned: Some(1),
            folders_to_create: 0,
            folders_to_delete: 0,
            items_to_create: 0,
            items_to_update: 0,
            items_unchanged: 1,
            items_to_skip: 0,
            items_to_delete: 0,
            attachments_to_upload: 0,
            attachments_to_delete: 0,
            warning_count: 0,
            create_item_ids: Vec::new(),
            create_folder_ids: Vec::new(),
            delete_folder_ids: Vec::new(),
            update_item_ids: Vec::new(),
            unchanged_item_ids: vec!["source-current".to_string()],
            skip_item_ids: Vec::new(),
            delete_item_ids: Vec::new(),
            delete_attachment_ids: Vec::new(),
            delete_attachments: Vec::new(),
            matched_target_folder_ids: BTreeMap::new(),
            matched_target_item_ids,
            restore_folder_ambiguous_ids: Vec::new(),
            invalid_scope_item_ids: Vec::new(),
            unsupported_organization_item_ids: Vec::new(),
            unsupported_collection_item_ids: Vec::new(),
            restore_map_stale_item_ids: stale_plan_ids,
            restore_fingerprint_ambiguous_item_ids: Vec::new(),
            prune_permanent: false,
            blockers: Vec::new(),
        },
        &target,
        None,
        ApplyOptions {
            mark_restored: false,
            restore_map: true,
            update_existing: false,
            verify_after: false,
        },
        &NoopProgress,
    )
    .expect("apply smaller restore map");

    let calls = adapter.runner().calls();
    assert_eq!(calls[0].args[0..3], ["edit", "item", "restore-map-1"]);
    assert_eq!(calls[1].args, ["delete", "item", "restore-map-2"]);
    assert_eq!(calls[2].args, ["delete", "item", "restore-map-3"]);
}

#[test]
fn bw_adapter_updates_restore_map_when_only_stale_entries_need_cleanup() {
    let chunk = restore_map_item(
        "restore-map-1",
        "yabbt restore map - do not edit",
        &[("stale-source", "missing-target")],
    );
    let target = vault(vec![chunk]);
    let archive = vault(Vec::new());
    let runner = FakeRunner::new(vec![success(Vec::new())]);
    let adapter = BwSourceAdapter::new(runner, BwSourceOptions::default());

    let outcome = apply_restore_plan(
        &adapter,
        &OpenedArchive {
            vault: archive,
            attachments: Vec::new(),
        },
        &RestorePlan {
            target_backend: "bw".to_string(),
            dry_run: false,
            archive_scope: "personal".to_string(),
            archive_items: 0,
            target_items_scanned: Some(0),
            folders_to_create: 0,
            folders_to_delete: 0,
            items_to_create: 0,
            items_to_update: 0,
            items_unchanged: 0,
            items_to_skip: 0,
            items_to_delete: 0,
            attachments_to_upload: 0,
            attachments_to_delete: 0,
            warning_count: 1,
            create_item_ids: Vec::new(),
            create_folder_ids: Vec::new(),
            delete_folder_ids: Vec::new(),
            update_item_ids: Vec::new(),
            unchanged_item_ids: Vec::new(),
            skip_item_ids: Vec::new(),
            delete_item_ids: Vec::new(),
            delete_attachment_ids: Vec::new(),
            delete_attachments: Vec::new(),
            matched_target_folder_ids: BTreeMap::new(),
            matched_target_item_ids: BTreeMap::new(),
            restore_folder_ambiguous_ids: Vec::new(),
            invalid_scope_item_ids: Vec::new(),
            unsupported_organization_item_ids: Vec::new(),
            unsupported_collection_item_ids: Vec::new(),
            restore_map_stale_item_ids: vec!["stale-source".to_string()],
            restore_fingerprint_ambiguous_item_ids: Vec::new(),
            prune_permanent: false,
            blockers: Vec::new(),
        },
        &target,
        None,
        ApplyOptions {
            mark_restored: false,
            restore_map: true,
            update_existing: false,
            verify_after: false,
        },
        &NoopProgress,
    )
    .expect("cleanup stale-only restore map");

    assert!(outcome.summary.restore_map_updated);
    let calls = adapter.runner().calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].args, ["delete", "item", "restore-map-1"]);
}

#[test]
fn bw_adapter_deletes_duplicate_restore_map_chunks_with_same_index() {
    let archive_item = test_item("source-current", 0);
    let mut target_item = archive_item.clone();
    target_item.id = "target-current".to_string();
    let primary_chunk = restore_map_item(
        "restore-map-primary",
        "yabbt restore map - do not edit",
        &[("source-current", "target-current")],
    );
    let duplicate_chunk = restore_map_item(
        "restore-map-duplicate",
        "yabbt restore map - do not edit",
        &[("duplicate-source", "duplicate-target")],
    );
    let archive = vault(vec![archive_item]);
    let target = vault(vec![target_item, primary_chunk, duplicate_chunk]);
    let runner = FakeRunner::new(vec![success(Vec::new()), success(Vec::new())]);
    let adapter = BwSourceAdapter::new(runner, BwSourceOptions::default());
    let mut matched_target_item_ids = BTreeMap::new();
    matched_target_item_ids.insert("source-current".to_string(), "target-current".to_string());

    apply_restore_plan(
        &adapter,
        &OpenedArchive {
            vault: archive,
            attachments: Vec::new(),
        },
        &RestorePlan {
            target_backend: "bw".to_string(),
            dry_run: false,
            archive_scope: "personal".to_string(),
            archive_items: 1,
            target_items_scanned: Some(1),
            folders_to_create: 0,
            folders_to_delete: 0,
            items_to_create: 0,
            items_to_update: 0,
            items_unchanged: 1,
            items_to_skip: 0,
            items_to_delete: 0,
            attachments_to_upload: 0,
            attachments_to_delete: 0,
            warning_count: 0,
            create_item_ids: Vec::new(),
            create_folder_ids: Vec::new(),
            delete_folder_ids: Vec::new(),
            update_item_ids: Vec::new(),
            unchanged_item_ids: vec!["source-current".to_string()],
            skip_item_ids: Vec::new(),
            delete_item_ids: Vec::new(),
            delete_attachment_ids: Vec::new(),
            delete_attachments: Vec::new(),
            matched_target_folder_ids: BTreeMap::new(),
            matched_target_item_ids,
            restore_folder_ambiguous_ids: Vec::new(),
            invalid_scope_item_ids: Vec::new(),
            unsupported_organization_item_ids: Vec::new(),
            unsupported_collection_item_ids: Vec::new(),
            restore_map_stale_item_ids: Vec::new(),
            restore_fingerprint_ambiguous_item_ids: Vec::new(),
            prune_permanent: false,
            blockers: Vec::new(),
        },
        &target,
        None,
        ApplyOptions {
            mark_restored: false,
            restore_map: true,
            update_existing: false,
            verify_after: false,
        },
        &NoopProgress,
    )
    .expect("apply restore map with duplicate chunks");

    let calls = adapter.runner().calls();
    assert_eq!(calls[0].args[0..3], ["edit", "item", "restore-map-primary"]);
    assert_eq!(calls[1].args, ["delete", "item", "restore-map-duplicate"]);
}

#[test]
fn bw_adapter_rejects_hostile_ids_returned_by_create() {
    for hostile in ["/home/u/.config/x", "../../escape", "--permanent", ""] {
        let response = serde_json::json!({ "id": hostile }).to_string();
        let runner = FakeRunner::new(vec![success(response.clone()), success(response)]);
        let adapter = BwSourceAdapter::new(runner, BwSourceOptions::default());

        assert!(
            adapter.create_item(&serde_json::json!({})).is_err(),
            "created item id {hostile:?} accepted"
        );
        assert!(
            adapter.create_folder(&serde_json::json!({})).is_err(),
            "created folder id {hostile:?} accepted"
        );
    }
}

#[test]
fn bw_adapter_upload_never_writes_outside_its_private_temp_dir() {
    let outside = tempfile::tempdir().expect("tempdir");
    let hostile_item_id = format!("{}/escape", outside.path().display());
    let runner = FakeRunner::new(vec![success(Vec::new())]);
    let adapter = BwSourceAdapter::new(runner, BwSourceOptions::default());

    let result = adapter.upload_attachments(
        &[AttachmentUpload {
            target_item_id: hostile_item_id,
            file_name: "secret.txt".to_string(),
            bytes: b"plaintext attachment".to_vec(),
            size: 20,
            sha256: String::new(),
        }],
        &NoopProgress,
        1,
    );

    assert!(result.is_err(), "hostile target item id accepted");
    assert_eq!(
        fs::read_dir(outside.path())
            .expect("read outside dir")
            .count(),
        0,
        "plaintext attachment written outside the private temp dir"
    );
    assert!(adapter.runner().calls().is_empty(), "bw was invoked");
}

fn decode_item_payload(encoded: &[u8]) -> serde_json::Value {
    let decoded = BASE64.decode(encoded).expect("decode item payload");
    serde_json::from_slice(&decoded).expect("json payload")
}

fn vault(items: Vec<VaultItem>) -> Vault {
    Vault {
        metadata: VaultMetadata {
            archive_version: 1,
            source_backend: "fixture".to_string(),
            source_server: Some("https://vault.example.test".to_string()),
            created_at: "2026-05-03T12:00:00Z".to_string(),
            tool_version: "0.1.0".to_string(),
        },
        folders: Vec::new(),
        items,
        report: CompletenessReport {
            complete: true,
            warnings: Vec::new(),
        },
    }
}

fn test_item(id: &str, index: usize) -> VaultItem {
    VaultItem {
        id: id.to_string(),
        kind: ItemKind::SecureNote,
        name: format!("Restore map split item {index:04}"),
        notes: Some(format!("restore map split note {index:04}")),
        folder_id: None,
        favorite: false,
        fields: vec![Field {
            name: "secret".to_string(),
            value: format!("hidden value {index:04}"),
            hidden: true,
        }],
        attachments: Vec::new(),
        backend_metadata: Vec::new(),
    }
}

fn restore_map_item(id: &str, name: &str, entries: &[(&str, &str)]) -> VaultItem {
    let entries = entries
        .iter()
        .map(|(source_item_id, target_item_id)| {
            (
                (*source_item_id).to_string(),
                serde_json::json!({
                    "target_item_id": target_item_id,
                    "source_fingerprint": "old-fingerprint",
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    VaultItem {
        id: id.to_string(),
        kind: ItemKind::SecureNote,
        name: name.to_string(),
        notes: Some("Managed by yabbt. Do not edit.".to_string()),
        folder_id: None,
        favorite: false,
        fields: vec![Field {
            name: RESTORE_MAP_FIELD_NAME.to_string(),
            value: serde_json::json!({
                "version": 1,
                "entries": entries,
            })
            .to_string(),
            hidden: true,
        }],
        attachments: Vec::new(),
        backend_metadata: Vec::new(),
    }
}

//! In-process restore apply tests against an in-memory fake vault target.
//! These cover the behaviours that previously only the ignored live
//! Vaultwarden e2e test exercised: full apply, restore-map round-trips,
//! idempotent re-apply, update-existing, prune, and verify-after.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use serde_json::{Value, json};
use yabbt::adapters::AdapterError;
use yabbt::adapters::bitwarden_json::normalize_export;
use yabbt::archive::{ArchiveAttachment, OpenedArchive};
use yabbt::diff::stable_fingerprint;
use yabbt::model::{
    AttachmentRef, CompletenessReport, Field, Folder, ItemKind, Vault, VaultItem, VaultMetadata,
};
use yabbt::progress::{NoopProgress, ProgressReporter};
use yabbt::restore_apply::{
    ApplyOptions, AttachmentUpload, RestoreError, RestoreOutcome, UploadedAttachment,
    VaultTargetOps, VisibleItem, apply_restore_plan,
};
use yabbt::restore_map::restore_map_state;
use yabbt::restore_plan::{RestorePlanOptions, RestorePlanStatus};

#[derive(Debug, Default)]
struct FakeState {
    folders: BTreeMap<String, String>,
    items: BTreeMap<String, Value>,
    trash: BTreeSet<String>,
    attachments: BTreeMap<(String, String), (String, Vec<u8>)>,
    hidden_item_ids: BTreeSet<String>,
    hide_created_items: bool,
    next_id: usize,
    edit_calls: usize,
    /// "upload" / "delete" per attachment mutation, in call order.
    attachment_ops: Vec<&'static str>,
}

/// Stateful in-memory vault satisfying the VaultTargetOps seam. It stores
/// the exact Bitwarden-wire payloads the orchestrator produces and renders
/// them back through `normalize_export`, so its `vault()` view is parsed the
/// same way real `bw` output would be.
#[derive(Debug, Default)]
struct FakeVault {
    state: Mutex<FakeState>,
}

impl FakeVault {
    fn new() -> Self {
        Self::default()
    }

    fn next_id(state: &mut FakeState, kind: &str) -> String {
        state.next_id += 1;
        format!("fake-{kind}-{}", state.next_id)
    }

    /// Seed a target-only folder, bypassing the seam.
    fn insert_folder(&self, name: &str) -> String {
        let mut state = self.state.lock().expect("state lock");
        let id = Self::next_id(&mut state, "folder");
        state.folders.insert(id.clone(), name.to_string());
        id
    }

    /// Seed a target-only item, bypassing the seam.
    fn insert_item(&self, payload: Value) -> String {
        let mut state = self.state.lock().expect("state lock");
        let id = Self::next_id(&mut state, "item");
        let mut payload = payload;
        payload["id"] = json!(id);
        state.items.insert(id.clone(), payload);
        id
    }

    /// Seed a target-only attachment, bypassing the seam.
    fn insert_attachment(&self, item_id: &str, file_name: &str, bytes: &[u8]) -> String {
        let mut state = self.state.lock().expect("state lock");
        assert!(state.items.contains_key(item_id), "item exists");
        let id = Self::next_id(&mut state, "attachment");
        state.attachments.insert(
            (item_id.to_string(), id.clone()),
            (file_name.to_string(), bytes.to_vec()),
        );
        id
    }

    /// Make `get_item` fail for every item created from now on, to inject
    /// verify-after failures.
    fn hide_future_created_items(&self) {
        let mut state = self.state.lock().expect("state lock");
        state.hide_created_items = true;
    }

    /// Mutate a stored item's notes, bypassing the seam.
    fn set_item_notes(&self, item_id: &str, notes: &str) {
        let mut state = self.state.lock().expect("state lock");
        let payload = state.items.get_mut(item_id).expect("item exists");
        payload["notes"] = json!(notes);
    }

    /// Mutate a stored item's raw payload, bypassing the seam.
    fn edit_payload(&self, item_id: &str, edit: impl FnOnce(&mut Value)) {
        let mut state = self.state.lock().expect("state lock");
        edit(state.items.get_mut(item_id).expect("item exists"));
    }

    fn has_item(&self, item_id: &str) -> bool {
        let state = self.state.lock().expect("state lock");
        state.items.contains_key(item_id)
    }

    fn item_payload(&self, item_id: &str) -> Value {
        let state = self.state.lock().expect("state lock");
        state.items.get(item_id).expect("item exists").clone()
    }

    fn attachment_bytes(&self, item_id: &str) -> Vec<Vec<u8>> {
        let state = self.state.lock().expect("state lock");
        state
            .attachments
            .iter()
            .filter(|((owner, _), _)| owner == item_id)
            .map(|(_, (_, bytes))| bytes.clone())
            .collect()
    }

    fn edit_calls(&self) -> usize {
        self.state.lock().expect("state lock").edit_calls
    }

    fn folder_names(&self) -> Vec<String> {
        let state = self.state.lock().expect("state lock");
        state.folders.values().cloned().collect()
    }

    fn trashed_item_ids(&self) -> Vec<String> {
        let state = self.state.lock().expect("state lock");
        state.trash.iter().cloned().collect()
    }

    fn rendered_item(state: &FakeState, id: &str, payload: &Value) -> Value {
        let mut rendered = payload.clone();
        rendered["id"] = json!(id);
        rendered["attachments"] = json!(
            state
                .attachments
                .iter()
                .filter(|((owner, _), _)| owner == id)
                .map(|((_, attachment_id), (file_name, bytes))| {
                    json!({
                        "id": attachment_id,
                        "fileName": file_name,
                        "size": bytes.len(),
                    })
                })
                .collect::<Vec<_>>()
        );
        rendered
    }

    /// Render current target state as a canonical [`Vault`], parsed through
    /// the same `normalize_export` as real `bw` export output.
    fn vault(&self) -> Vault {
        let state = self.state.lock().expect("state lock");
        let folders = state
            .folders
            .iter()
            .map(|(id, name)| json!({ "id": id, "name": name }))
            .collect::<Vec<_>>();
        let visible_items = state
            .items
            .iter()
            .filter(|(id, _)| !state.trash.contains(*id))
            .collect::<Vec<_>>();
        let export_items = visible_items
            .iter()
            .map(|(id, payload)| Self::rendered_item(&state, id, payload))
            .collect::<Vec<_>>();
        let export_json = json!({ "folders": folders, "items": export_items }).to_string();
        let listed_json = json!(
            visible_items
                .iter()
                .map(|(id, payload)| {
                    let rendered = Self::rendered_item(&state, id, payload);
                    json!({ "id": id, "attachments": rendered["attachments"] })
                })
                .collect::<Vec<_>>()
        )
        .to_string();
        normalize_export(&export_json, &listed_json, "bw", None).expect("fake vault normalizes")
    }
}

impl VaultTargetOps for FakeVault {
    fn create_folder(&self, payload: &Value) -> Result<String, AdapterError> {
        let name = payload
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| AdapterError::new("folder payload missing name"))?
            .to_string();
        let mut state = self.state.lock().expect("state lock");
        let id = Self::next_id(&mut state, "folder");
        state.folders.insert(id.clone(), name);
        Ok(id)
    }

    fn create_item(&self, payload: &Value) -> Result<String, AdapterError> {
        let mut state = self.state.lock().expect("state lock");
        let id = Self::next_id(&mut state, "item");
        let mut payload = payload.clone();
        payload["id"] = json!(id);
        state.items.insert(id.clone(), payload);
        if state.hide_created_items {
            state.hidden_item_ids.insert(id.clone());
        }
        Ok(id)
    }

    fn edit_item(&self, item_id: &str, payload: &Value) -> Result<(), AdapterError> {
        let mut state = self.state.lock().expect("state lock");
        if !state.items.contains_key(item_id) || state.trash.contains(item_id) {
            return Err(AdapterError::new(format!(
                "edit target item `{item_id}` not found"
            )));
        }
        state.edit_calls += 1;
        let mut payload = payload.clone();
        payload["id"] = json!(item_id);
        state.items.insert(item_id.to_string(), payload);
        Ok(())
    }

    fn upload_attachments(
        &self,
        jobs: &[AttachmentUpload],
        progress: &dyn ProgressReporter,
        total: u64,
    ) -> Result<Vec<UploadedAttachment>, AdapterError> {
        let mut uploaded = Vec::with_capacity(jobs.len());
        for (index, job) in jobs.iter().enumerate() {
            let mut state = self.state.lock().expect("state lock");
            if !state.items.contains_key(&job.target_item_id) {
                return Err(AdapterError::new(format!(
                    "attachment target item `{}` not found",
                    job.target_item_id
                )));
            }
            let id = Self::next_id(&mut state, "attachment");
            state.attachment_ops.push("upload");
            state.attachments.insert(
                (job.target_item_id.clone(), id),
                (job.file_name.clone(), job.bytes.clone()),
            );
            uploaded.push(UploadedAttachment {
                target_item_id: job.target_item_id.clone(),
                file_name: job.file_name.clone(),
                size: job.size,
                sha256: job.sha256.clone(),
            });
            progress.counted("uploading attachments", (index + 1) as u64, total);
        }
        Ok(uploaded)
    }

    fn delete_attachment(&self, item_id: &str, attachment_id: &str) -> Result<(), AdapterError> {
        let mut state = self.state.lock().expect("state lock");
        state.attachment_ops.push("delete");
        state
            .attachments
            .remove(&(item_id.to_string(), attachment_id.to_string()))
            .map(|_| ())
            .ok_or_else(|| {
                AdapterError::new(format!(
                    "attachment `{attachment_id}` not found on item `{item_id}`"
                ))
            })
    }

    fn delete_item(&self, item_id: &str, permanent: bool) -> Result<(), AdapterError> {
        let mut state = self.state.lock().expect("state lock");
        if !state.items.contains_key(item_id) {
            return Err(AdapterError::new(format!(
                "delete target item `{item_id}` not found"
            )));
        }
        if permanent {
            state.items.remove(item_id);
            state.trash.remove(item_id);
            state.attachments.retain(|(owner, _), _| owner != item_id);
        } else {
            state.trash.insert(item_id.to_string());
        }
        Ok(())
    }

    fn delete_folder(&self, folder_id: &str) -> Result<(), AdapterError> {
        let mut state = self.state.lock().expect("state lock");
        state
            .folders
            .remove(folder_id)
            .map(|_| ())
            .ok_or_else(|| AdapterError::new(format!("folder `{folder_id}` not found")))
    }

    fn sync(&self) -> Result<(), AdapterError> {
        Ok(())
    }

    fn get_item(&self, item_id: &str) -> Result<String, AdapterError> {
        let state = self.state.lock().expect("state lock");
        if state.hidden_item_ids.contains(item_id) || state.trash.contains(item_id) {
            return Err(AdapterError::new(format!("item `{item_id}` not found")));
        }
        let payload = state
            .items
            .get(item_id)
            .ok_or_else(|| AdapterError::new(format!("item `{item_id}` not found")))?;
        Ok(Self::rendered_item(&state, item_id, payload).to_string())
    }

    fn download_attachment(
        &self,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<Vec<u8>, AdapterError> {
        let state = self.state.lock().expect("state lock");
        state
            .attachments
            .get(&(item_id.to_string(), attachment_id.to_string()))
            .map(|(_, bytes)| bytes.clone())
            .ok_or_else(|| {
                AdapterError::new(format!(
                    "attachment `{attachment_id}` not found on item `{item_id}`"
                ))
            })
    }

    fn list_visible_items(&self) -> Result<Vec<VisibleItem>, AdapterError> {
        let state = self.state.lock().expect("state lock");
        Ok(state
            .items
            .keys()
            .filter(|id| !state.trash.contains(*id))
            .map(|id| VisibleItem {
                id: id.clone(),
                attachment_ids: state
                    .attachments
                    .keys()
                    .filter(|(owner, _)| owner == id)
                    .map(|(_, attachment_id)| attachment_id.clone())
                    .collect(),
            })
            .collect())
    }

    fn list_folder_ids(&self) -> Result<Vec<String>, AdapterError> {
        let state = self.state.lock().expect("state lock");
        Ok(state.folders.keys().cloned().collect())
    }
}

const ATTACHMENT_BYTES: &[u8] = b"recovery-code";

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

fn apply(fake: &FakeVault, options: ApplyOptions) -> RestoreOutcome {
    apply_with_prune(fake, options, false, false)
}

fn apply_with_prune(
    fake: &FakeVault,
    options: ApplyOptions,
    prune: bool,
    prune_permanent: bool,
) -> RestoreOutcome {
    try_apply_with_prune(fake, options, prune, prune_permanent).expect("apply restore plan")
}

fn try_apply_with_prune(
    fake: &FakeVault,
    options: ApplyOptions,
    prune: bool,
    prune_permanent: bool,
) -> Result<RestoreOutcome, RestoreError> {
    let opened = opened_archive();
    let target_vault = fake.vault();
    let plan = yabbt::restore_plan::plan_restore_with_options(
        &opened.vault,
        Some(&target_vault),
        "bw",
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
        fake,
        &opened,
        &plan,
        &target_vault,
        None,
        options,
        &NoopProgress,
    )
}

#[test]
fn restore_into_empty_target_creates_everything_and_writes_restore_map() {
    let fake = FakeVault::new();

    let outcome = apply(&fake, apply_options());

    let summary = &outcome.summary;
    assert_eq!(summary.folders_created, 1);
    assert_eq!(summary.items_created, 2);
    assert_eq!(summary.attachments_uploaded, 1);
    assert!(summary.restore_map_updated);
    assert_eq!(fake.folder_names(), vec!["Infrastructure".to_string()]);

    // Created items carry the mark-restored marker fields.
    let login_id = &summary.created_item_ids[0];
    let login_payload = fake.item_payload(login_id);
    let fields = login_payload["fields"].as_array().expect("fields array");
    let marker = fields
        .iter()
        .find(|field| field["name"] == "yabbt.source_item_id")
        .expect("source item id marker");
    assert_eq!(marker["value"], "source-item-1");

    // The created login lands in the created target folder.
    let target_vault = fake.vault();
    let folder_id = target_vault.folders[0].id.clone();
    assert_eq!(login_payload["folderId"].as_str(), Some(folder_id.as_str()));

    // Attachment bytes round-tripped.
    assert_eq!(
        fake.attachment_bytes(login_id),
        vec![ATTACHMENT_BYTES.to_vec()]
    );

    // The restore map is readable back from the target vault and maps both
    // source items to their fake target ids.
    let state = restore_map_state(&target_vault)
        .expect("restore map parses")
        .expect("restore map present");
    assert_eq!(state.map.entries.len(), 2);
    assert_eq!(state.map.entries["source-item-1"].target_item_id, *login_id);
    assert!(state.map.entries.contains_key("source-item-2"));
}

#[test]
fn restore_again_is_idempotent_via_restore_map() {
    let fake = FakeVault::new();
    let first = apply(&fake, apply_options());
    assert_eq!(first.summary.items_created, 2);

    // The second plan reads the restore map back from the target vault and
    // matches both archive items, so nothing is created or uploaded again.
    let second = apply(&fake, apply_options());
    assert_eq!(second.summary.folders_created, 0);
    assert_eq!(second.summary.items_created, 0);
    assert_eq!(second.summary.items_updated, 0);
    assert_eq!(second.summary.attachments_uploaded, 0);

    let state = restore_map_state(&fake.vault())
        .expect("restore map parses")
        .expect("restore map present");
    assert_eq!(state.map.entries.len(), 2);
}

/// A re-run that changes nothing must not rewrite the restore map either:
/// no `bw edit` of the map item, and the summary says it was not updated.
#[test]
fn no_op_rerun_does_not_rewrite_the_restore_map() {
    let fake = FakeVault::new();
    apply(&fake, apply_options());
    let map_before = restore_map_state(&fake.vault())
        .expect("restore map parses")
        .expect("restore map present");

    for run in 0..3 {
        let rerun = apply(&fake, apply_options());
        assert!(!rerun.summary.has_mutations(), "run {run}");
        assert!(!rerun.summary.restore_map_updated, "run {run}");
        assert_eq!(fake.edit_calls(), 0, "run {run}: no item was edited");
    }
    let map_after = restore_map_state(&fake.vault())
        .expect("restore map parses")
        .expect("restore map present");
    assert_eq!(map_after, map_before);
}

#[test]
fn update_existing_edits_changed_matched_item() {
    let fake = FakeVault::new();
    let first = apply(&fake, apply_options());
    let note_target_id = first.summary.created_item_ids[1].clone();

    // Drift the target item so the archive version differs.
    fake.set_item_notes(&note_target_id, "drifted note body");

    let without_update = apply(&fake, apply_options());
    assert_eq!(without_update.summary.items_updated, 0);

    let with_update = apply(
        &fake,
        ApplyOptions {
            update_existing: true,
            ..apply_options()
        },
    );
    assert_eq!(with_update.summary.items_updated, 1);
    assert_eq!(
        with_update.summary.updated_item_ids,
        vec![note_target_id.clone()]
    );
    assert_eq!(
        fake.item_payload(&note_target_id)["notes"],
        json!("note body")
    );
}

#[test]
fn prune_deletes_target_only_data_and_verifies_deletions() {
    let fake = FakeVault::new();
    let first = apply(&fake, apply_options());
    let login_target_id = first.summary.created_item_ids[0].clone();

    let extra_folder_id = fake.insert_folder("Target Only Folder");
    let extra_item_id = fake.insert_item(json!({
        "folderId": null,
        "type": 2,
        "name": "Target Only Note",
        "notes": "target only body",
        "favorite": false,
        "fields": [],
    }));
    let extra_attachment_id =
        fake.insert_attachment(&login_target_id, "extra.bin", b"target-only-bytes");

    let outcome = apply_with_prune(
        &fake,
        ApplyOptions {
            verify_after: true,
            ..apply_options()
        },
        true,
        false,
    );

    let summary = &outcome.summary;
    assert_eq!(summary.items_deleted, 1);
    assert_eq!(summary.deleted_item_ids, vec![extra_item_id.clone()]);
    assert_eq!(summary.attachments_deleted, 1);
    assert_eq!(summary.deleted_attachment_ids, vec![extra_attachment_id]);
    assert_eq!(summary.folders_deleted, 1);
    assert_eq!(summary.deleted_folder_ids, vec![extra_folder_id]);

    // Non-permanent prune sends the item to trash, not oblivion.
    assert_eq!(fake.trashed_item_ids(), vec![extra_item_id.clone()]);
    assert!(fake.has_item(&extra_item_id));
    assert_eq!(
        fake.attachment_bytes(&login_target_id),
        vec![ATTACHMENT_BYTES.to_vec()]
    );
    assert!(
        !fake
            .folder_names()
            .contains(&"Target Only Folder".to_string())
    );

    let verification = outcome.verification.expect("verification ran");
    assert_eq!(verification.deleted_items, 1);
    assert_eq!(verification.deleted_attachments, 1);
    assert_eq!(verification.deleted_folders, 1);
}

#[test]
fn prune_permanent_removes_items_entirely() {
    let fake = FakeVault::new();
    apply(&fake, apply_options());
    let extra_item_id = fake.insert_item(json!({
        "folderId": null,
        "type": 2,
        "name": "Target Only Note",
        "notes": "target only body",
        "favorite": false,
        "fields": [],
    }));

    apply_with_prune(&fake, apply_options(), true, true);

    assert!(!fake.has_item(&extra_item_id));
    assert!(fake.trashed_item_ids().is_empty());
}

#[test]
fn verify_after_reports_counts_for_created_data() {
    let fake = FakeVault::new();

    let outcome = apply(
        &fake,
        ApplyOptions {
            verify_after: true,
            ..apply_options()
        },
    );

    let verification = outcome.verification.expect("verification ran");
    assert_eq!(verification.created_items, 2);
    assert_eq!(verification.updated_items, 0);
    assert_eq!(verification.attachments, 1);
    assert_eq!(verification.deleted_items, 0);
}

#[test]
fn verify_after_failure_carries_apply_summary() {
    let fake = FakeVault::new();
    fake.hide_future_created_items();

    let error = try_apply_with_prune(
        &fake,
        ApplyOptions {
            verify_after: true,
            ..apply_options()
        },
        false,
        false,
    )
    .expect_err("verification fails");

    match error {
        RestoreError::Verify { summary, error } => {
            assert_eq!(summary.items_created, 2);
            assert!(
                error
                    .to_string()
                    .starts_with("post-apply verification failed:"),
                "unexpected error: {error}"
            );
        }
        RestoreError::Apply { error, .. } => panic!("apply should succeed, got: {error}"),
    }
}

// ------------------------------------------------- regression helpers

/// Plan and apply `opened` against the fake's current state.
fn apply_archive(
    target: &dyn VaultTargetOps,
    target_vault: Vault,
    opened: &OpenedArchive,
    options: ApplyOptions,
    prune: bool,
) -> Result<(yabbt::restore_plan::RestorePlan, RestoreOutcome), RestoreError> {
    let plan = yabbt::restore_plan::plan_restore_with_options(
        &opened.vault,
        Some(&target_vault),
        "bw",
        RestorePlanOptions {
            prune,
            ..RestorePlanOptions::default()
        },
    );
    assert_eq!(
        plan.status(),
        RestorePlanStatus::Ready,
        "{:?}",
        plan.blockers
    );
    let outcome = apply_restore_plan(
        target,
        opened,
        &plan,
        &target_vault,
        None,
        options,
        &NoopProgress,
    )?;
    Ok((plan, outcome))
}

/// A Bitwarden card item whose card data lives only in `bitwarden.raw`,
/// exactly as `normalize_export` produces it.
fn card_item(id: &str, number: &str) -> VaultItem {
    VaultItem {
        id: id.to_string(),
        kind: ItemKind::Card,
        name: "Visa".to_string(),
        notes: None,
        folder_id: None,
        favorite: false,
        fields: Vec::new(),
        attachments: Vec::new(),
        backend_metadata: vec![(
            "bitwarden.raw".to_string(),
            json!({
                "id": id,
                "type": 3,
                "name": "Visa",
                "notes": null,
                "favorite": false,
                "folderId": null,
                "organizationId": null,
                "collectionIds": null,
                "reprompt": 0,
                "revisionDate": "2026-06-01T12:00:00Z",
                "creationDate": "2026-06-01T12:00:00Z",
                "deletedDate": null,
                "passwordHistory": null,
                "fields": [],
                "card": {
                    "cardholderName": "A. Admin",
                    "brand": "Visa",
                    "number": number,
                    "expMonth": "1",
                    "expYear": "2030",
                    "code": "123"
                }
            })
            .to_string(),
        )],
    }
}

fn card_archive(number: &str) -> OpenedArchive {
    let mut vault = archive_vault();
    vault.folders.clear();
    vault.items = vec![card_item("source-card", number)];
    OpenedArchive {
        vault,
        attachments: Vec::new(),
    }
}

// ------------------------------------------- regression: raw-only fields

/// Card numbers live only in the raw payload. A tampered target card must
/// be planned as an update and restored by --update-existing; afterwards the
/// item must be stable (no perpetual churn).
#[test]
fn update_existing_restores_tampered_card_number() {
    let fake = FakeVault::new();
    let archive = card_archive("4111111111111111");
    let (_, first) =
        apply_archive(&fake, fake.vault(), &archive, apply_options(), false).expect("first apply");
    let card_target_id = first.summary.created_item_ids[0].clone();

    // Re-running against the unmodified target is a no-op.
    let (plan, _) = apply_archive(&fake, fake.vault(), &archive, apply_options(), false)
        .expect("idempotent apply");
    assert_eq!(plan.unchanged_item_ids, vec!["source-card".to_string()]);

    fake.edit_payload(&card_target_id, |payload| {
        payload["card"]["number"] = json!("5500000000000004");
    });

    let (plan, outcome) = apply_archive(
        &fake,
        fake.vault(),
        &archive,
        ApplyOptions {
            update_existing: true,
            ..apply_options()
        },
        false,
    )
    .expect("update apply");
    assert_eq!(plan.update_item_ids, vec!["source-card".to_string()]);
    assert_eq!(
        outcome.summary.updated_item_ids,
        vec![card_target_id.clone()]
    );
    assert_eq!(
        fake.item_payload(&card_target_id)["card"]["number"],
        json!("4111111111111111")
    );

    let (plan, _) = apply_archive(&fake, fake.vault(), &archive, apply_options(), false)
        .expect("post-update apply");
    assert_eq!(plan.unchanged_item_ids, vec!["source-card".to_string()]);
    assert!(plan.update_item_ids.is_empty());
}

/// Target-assigned or Bitwarden-maintained keys (ids, dates, password
/// history, folder/org ids) must not make an item look changed.
#[test]
fn volatile_raw_keys_do_not_mark_card_changed() {
    let fake = FakeVault::new();
    let archive = card_archive("4111111111111111");
    let (_, first) =
        apply_archive(&fake, fake.vault(), &archive, apply_options(), false).expect("first apply");
    let card_target_id = first.summary.created_item_ids[0].clone();

    fake.edit_payload(&card_target_id, |payload| {
        payload["revisionDate"] = json!("2026-09-09T09:09:09Z");
        payload["creationDate"] = json!("2026-09-09T09:09:09Z");
        payload["passwordHistory"] = json!([{ "password": "old", "lastUsedDate": "x" }]);
        payload["collectionIds"] = json!([]);
        payload["object"] = json!("item");
        payload["edit"] = json!(true);
        payload["viewPassword"] = json!(true);
    });

    let (plan, _) =
        apply_archive(&fake, fake.vault(), &archive, apply_options(), false).expect("apply");
    assert_eq!(plan.unchanged_item_ids, vec!["source-card".to_string()]);
    assert!(plan.update_item_ids.is_empty());
}

// ------------------------------------------- regression: double binding

/// Source gains a clone (identical content, new id sorting before the
/// original). The clone must be created in the target instead of binding
/// to the original's already-mapped target item.
#[test]
fn source_clone_is_created_not_double_mapped() {
    let fake = FakeVault::new();
    apply_archive(
        &fake,
        fake.vault(),
        &opened_archive(),
        apply_options(),
        false,
    )
    .expect("first apply");

    let mut v2 = opened_archive();
    let mut clone = v2.vault.items[1].clone();
    clone.id = "aaa-clone-of-note".to_string();
    v2.vault.items.push(clone);
    let (plan, outcome) =
        apply_archive(&fake, fake.vault(), &v2, apply_options(), false).expect("clone apply");

    assert_eq!(plan.create_item_ids, vec!["aaa-clone-of-note".to_string()]);
    assert_eq!(outcome.summary.items_created, 1);
    let notes = fake
        .vault()
        .items
        .iter()
        .filter(|item| item.name == "Example Note")
        .count();
    assert_eq!(notes, 2, "clone missing from target");

    // Converged: a further run creates nothing.
    let (plan, _) =
        apply_archive(&fake, fake.vault(), &v2, apply_options(), false).expect("third apply");
    assert!(plan.create_item_ids.is_empty());
}

// ------------------------------- regression: upstream restore map in archive

/// An archive taken from a vault that was itself a restore target contains
/// that vault's restore-map note. It must not be restored as a regular item
/// (which churned: created, then trashed as a duplicate map chunk, forever).
#[test]
fn archive_restore_map_item_is_not_restored() {
    let fake = FakeVault::new();
    let mut opened = opened_archive();
    opened.vault.items.push(VaultItem {
        id: "upstream-map".to_string(),
        kind: ItemKind::SecureNote,
        name: yabbt::restore_map::RESTORE_MAP_ITEM_NAME.to_string(),
        notes: Some("Managed by yabbt. Do not edit.".to_string()),
        folder_id: None,
        favorite: false,
        fields: vec![Field {
            name: yabbt::restore_map::RESTORE_MAP_FIELD_NAME.to_string(),
            value: r#"{"version":1,"entries":{}}"#.to_string(),
            hidden: true,
        }],
        attachments: Vec::new(),
        backend_metadata: Vec::new(),
    });
    for run in 1..=3 {
        let (plan, outcome) =
            apply_archive(&fake, fake.vault(), &opened, apply_options(), false).expect("apply");
        assert!(
            !plan.create_item_ids.contains(&"upstream-map".to_string()),
            "run {run} restores the upstream map"
        );
        assert_eq!(plan.archive_items, 2, "run {run}");
        if run > 1 {
            assert_eq!(outcome.summary.items_created, 0, "run {run}");
        }
    }
    assert!(fake.trashed_item_ids().is_empty(), "churn");
    let state = restore_map_state(&fake.vault())
        .expect("restore map parses")
        .expect("restore map present");
    assert!(!state.map.entries.contains_key("upstream-map"));
}

// ------------------------------------------ regression: mid-apply failure

/// Wraps the fake and injects failures: every attachment upload, and/or the
/// Nth `create_item` call (1-based, one-shot).
struct FailingTarget<'a> {
    inner: &'a FakeVault,
    fail_uploads: bool,
    fail_create_call: Option<usize>,
    create_calls: Mutex<usize>,
    fail_commits: bool,
    commit_calls: Mutex<usize>,
}

impl<'a> FailingTarget<'a> {
    fn new(inner: &'a FakeVault) -> Self {
        Self {
            inner,
            fail_uploads: false,
            fail_create_call: None,
            create_calls: Mutex::new(0),
            fail_commits: false,
            commit_calls: Mutex::new(0),
        }
    }

    fn uploads(inner: &'a FakeVault) -> Self {
        Self {
            fail_uploads: true,
            ..Self::new(inner)
        }
    }

    fn nth_create(inner: &'a FakeVault, call: usize) -> Self {
        Self {
            fail_create_call: Some(call),
            ..Self::new(inner)
        }
    }

    fn commits(&self) -> usize {
        *self.commit_calls.lock().expect("commit lock")
    }
}

impl VaultTargetOps for FailingTarget<'_> {
    fn commit(&self) -> Result<(), AdapterError> {
        *self.commit_calls.lock().expect("commit lock") += 1;
        if self.fail_commits {
            return Err(AdapterError::new("injected commit failure"));
        }
        Ok(())
    }
    fn create_folder(&self, payload: &Value) -> Result<String, AdapterError> {
        self.inner.create_folder(payload)
    }
    fn create_item(&self, payload: &Value) -> Result<String, AdapterError> {
        let mut calls = self.create_calls.lock().expect("calls lock");
        *calls += 1;
        if self.fail_create_call == Some(*calls) {
            return Err(AdapterError::new("injected create failure"));
        }
        self.inner.create_item(payload)
    }
    fn edit_item(&self, item_id: &str, payload: &Value) -> Result<(), AdapterError> {
        self.inner.edit_item(item_id, payload)
    }
    fn upload_attachments(
        &self,
        jobs: &[AttachmentUpload],
        progress: &dyn ProgressReporter,
        total: u64,
    ) -> Result<Vec<UploadedAttachment>, AdapterError> {
        if self.fail_uploads && !jobs.is_empty() {
            return Err(AdapterError::new("injected upload failure"));
        }
        self.inner.upload_attachments(jobs, progress, total)
    }
    fn delete_attachment(&self, item_id: &str, attachment_id: &str) -> Result<(), AdapterError> {
        self.inner.delete_attachment(item_id, attachment_id)
    }
    fn delete_item(&self, item_id: &str, permanent: bool) -> Result<(), AdapterError> {
        self.inner.delete_item(item_id, permanent)
    }
    fn delete_folder(&self, folder_id: &str) -> Result<(), AdapterError> {
        self.inner.delete_folder(folder_id)
    }
    fn sync(&self) -> Result<(), AdapterError> {
        self.inner.sync()
    }
    fn get_item(&self, item_id: &str) -> Result<String, AdapterError> {
        self.inner.get_item(item_id)
    }
    fn download_attachment(
        &self,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<Vec<u8>, AdapterError> {
        self.inner.download_attachment(item_id, attachment_id)
    }
    fn list_visible_items(&self) -> Result<Vec<VisibleItem>, AdapterError> {
        self.inner.list_visible_items()
    }
    fn list_folder_ids(&self) -> Result<Vec<String>, AdapterError> {
        self.inner.list_folder_ids()
    }
}

fn count_named(fake: &FakeVault, name: &str) -> usize {
    fake.vault()
        .items
        .iter()
        .filter(|item| item.name == name)
        .count()
}

/// Attachment upload fails after both items were created. The error must
/// carry the partial summary, the restore map must still record the created
/// items, and a re-run with default flags must not duplicate them.
#[test]
fn failed_upload_keeps_restore_map_and_rerun_does_not_duplicate() {
    let fake = FakeVault::new();
    let options = ApplyOptions {
        mark_restored: false,
        ..apply_options()
    };
    let error = apply_archive(
        &FailingTarget::uploads(&fake),
        fake.vault(),
        &opened_archive(),
        options,
        false,
    )
    .expect_err("upload fails");
    let RestoreError::Apply { summary, error } = error else {
        panic!("expected apply error");
    };
    assert!(
        error.to_string().contains("injected upload failure"),
        "{error}"
    );
    assert_eq!(summary.folders_created, 1);
    assert_eq!(summary.items_created, 2);
    assert_eq!(summary.created_item_ids.len(), 2);
    assert_eq!(summary.attachments_uploaded, 0);
    assert!(summary.restore_map_updated);

    let state = restore_map_state(&fake.vault())
        .expect("restore map parses")
        .expect("restore map present");
    assert_eq!(state.map.entries.len(), 2);

    let (plan, rerun) = apply_archive(&fake, fake.vault(), &opened_archive(), options, false)
        .expect("rerun succeeds");
    assert!(
        plan.create_item_ids.is_empty(),
        "{:?}",
        plan.create_item_ids
    );
    assert_eq!(rerun.summary.items_created, 0);
    assert_eq!(count_named(&fake, "Example Login"), 1);
    assert_eq!(count_named(&fake, "Example Note"), 1);

    // The missing attachment is reported as a pending update and
    // --update-existing uploads it.
    assert_eq!(plan.update_item_ids, vec!["source-item-1".to_string()]);
    let (_, update) = apply_archive(
        &fake,
        fake.vault(),
        &opened_archive(),
        ApplyOptions {
            update_existing: true,
            ..options
        },
        false,
    )
    .expect("update succeeds");
    assert_eq!(update.summary.attachments_uploaded, 1);
}

/// The second item create fails: the first item is already in the target
/// and must be in the summary and the restore map.
#[test]
fn failed_create_reports_items_created_so_far() {
    let fake = FakeVault::new();
    let options = ApplyOptions {
        mark_restored: false,
        ..apply_options()
    };
    let error = apply_archive(
        &FailingTarget::nth_create(&fake, 2),
        fake.vault(),
        &opened_archive(),
        options,
        false,
    )
    .expect_err("second create fails");
    let RestoreError::Apply { summary, error } = error else {
        panic!("expected apply error");
    };
    assert!(
        error.to_string().contains("injected create failure"),
        "{error}"
    );
    assert_eq!(summary.items_created, 1);
    assert!(summary.restore_map_updated);
    let created = summary.created_item_ids[0].clone();

    let state = restore_map_state(&fake.vault())
        .expect("restore map parses")
        .expect("restore map present");
    assert_eq!(state.map.entries["source-item-1"].target_item_id, created);

    let (plan, _) = apply_archive(&fake, fake.vault(), &opened_archive(), options, false)
        .expect("rerun succeeds");
    assert_eq!(plan.create_item_ids, vec!["source-item-2".to_string()]);
    assert_eq!(count_named(&fake, "Example Login"), 1);
}

/// A successful apply commits once, after the restore map; a mid-apply
/// failure commits the completed mutations before the best-effort map write.
#[test]
fn apply_commits_once_on_success_and_before_the_map_after_a_failure() {
    let fake = FakeVault::new();
    let target = FailingTarget::new(&fake);
    apply_archive(
        &target,
        fake.vault(),
        &opened_archive(),
        apply_options(),
        false,
    )
    .expect("apply succeeds");
    assert_eq!(target.commits(), 1);

    let fake = FakeVault::new();
    let target = FailingTarget::nth_create(&fake, 2);
    apply_archive(
        &target,
        fake.vault(),
        &opened_archive(),
        apply_options(),
        false,
    )
    .expect_err("second create fails");
    assert_eq!(target.commits(), 2);
}

/// When the final commit fails, nothing of the run is reported as applied
/// and the error says nothing was written.
#[test]
fn failed_commit_reports_no_applied_changes() {
    let fake = FakeVault::new();
    let target = FailingTarget {
        fail_commits: true,
        ..FailingTarget::new(&fake)
    };
    let error = apply_archive(
        &target,
        fake.vault(),
        &opened_archive(),
        apply_options(),
        false,
    )
    .expect_err("commit fails");
    let RestoreError::Apply { summary, error } = error else {
        panic!("expected apply error");
    };
    assert!(!summary.has_mutations(), "{summary:?}");
    assert!(!summary.restore_map_updated);
    assert!(summary.created_item_ids.is_empty());
    let message = error.to_string();
    assert!(message.contains("injected commit failure"), "{message}");
    assert!(message.contains("nothing was written"), "{message}");
}

/// Prune must not delete the target's version of an attachment while the
/// archive's replacement is not uploaded (an item update not applied
/// without --update-existing).
#[test]
fn prune_keeps_replaced_attachment_until_the_item_update_uploads_its_successor() {
    let fake = FakeVault::new();
    let first = apply(&fake, apply_options());
    let login = first.summary.created_item_ids[0].clone();
    // The target's attachment now has a different name than the archive's.
    let original = fake
        .vault()
        .items
        .iter()
        .find(|item| item.id == login)
        .expect("login")
        .attachments[0]
        .id
        .clone();
    fake.delete_attachment(&login, &original)
        .expect("drop original");
    fake.insert_attachment(&login, "old-recovery.txt", b"old-bytes");

    let without_update = apply_with_prune(&fake, apply_options(), true, false);
    assert_eq!(without_update.summary.attachments_deleted, 0);
    assert_eq!(without_update.summary.attachments_uploaded, 0);
    assert_eq!(fake.attachment_bytes(&login), vec![b"old-bytes".to_vec()]);

    let with_update = apply_with_prune(
        &fake,
        ApplyOptions {
            update_existing: true,
            ..apply_options()
        },
        true,
        false,
    );
    assert_eq!(with_update.summary.attachments_uploaded, 1);
    assert_eq!(with_update.summary.attachments_deleted, 1);
    assert_eq!(
        fake.attachment_bytes(&login),
        vec![ATTACHMENT_BYTES.to_vec()]
    );
    // A write-through target (bw) always gets the successor before the old
    // version is removed.
    let ops = fake
        .state
        .lock()
        .expect("state lock")
        .attachment_ops
        .clone();
    assert_eq!(&ops[ops.len() - 2..], ["upload", "delete"]);
}

/// When nothing was mutated before the failure, the target is left alone:
/// no restore map is written.
#[test]
fn failure_before_any_mutation_writes_nothing() {
    let fake = FakeVault::new();
    let mut opened = opened_archive();
    opened.vault.folders.clear();
    opened.vault.items[0].folder_id = None;
    let error = apply_archive(
        &FailingTarget::nth_create(&fake, 1),
        fake.vault(),
        &opened,
        apply_options(),
        false,
    )
    .expect_err("first create fails");
    let RestoreError::Apply { summary, .. } = error else {
        panic!("expected apply error");
    };
    assert_eq!(summary.items_created, 0);
    assert!(!summary.restore_map_updated);
    assert!(fake.vault().items.is_empty());
}

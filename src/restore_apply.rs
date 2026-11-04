//! Restore apply orchestration: turns a [`RestorePlan`] into mutations on a
//! target vault through the [`VaultTargetOps`] seam, then optionally verifies
//! the applied state. The mutation order is folders -> item creates -> item
//! updates -> attachment uploads -> attachment/item/folder deletes ->
//! restore-map upsert -> commit. Targets that batch writes (KeePass) persist
//! everything at the commit; after a mid-apply failure the completed
//! mutations are committed before the best-effort restore-map write.

use crate::adapters::AdapterError;
use crate::archive::OpenedArchive;
use crate::diff::{item_fingerprint, stable_fingerprint};
use crate::model::{Field, Folder, ItemKind, Vault, VaultItem};
use crate::progress::ProgressReporter;
use crate::restore_map::{
    RESTORE_MAP_FIELD_NAME, RESTORE_MAP_NOTE, RestoreMap, RestoreMapEntry, is_restore_map_item,
    restore_map_chunk_index, restore_map_field, restore_map_item_name, restore_map_state,
};
use crate::restore_plan::{
    RestoreAttachmentDelete, RestorePlan, YABBT_ARCHIVE_VERSION_FIELD,
    YABBT_SOURCE_FINGERPRINT_FIELD, YABBT_SOURCE_ITEM_ID_FIELD, pair_attachments,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::Duration;

const ATTACHMENT_VERIFY_ATTEMPTS: usize = 8;
const ATTACHMENT_VERIFY_RETRY_DELAY: Duration = Duration::from_secs(2);
// Linux also enforces MAX_ARG_STRLEN (~128 KiB) for each individual argv entry,
// so keep the base64 payload well below that rather than only below ARG_MAX.
const RESTORE_MAP_MAX_ENCODED_ARG_BYTES: usize = 96 * 1024;
const RESTORE_MAP_CHUNK_TARGET_ENCODED_BYTES: usize = RESTORE_MAP_MAX_ENCODED_ARG_BYTES - 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyOptions {
    pub mark_restored: bool,
    pub restore_map: bool,
    pub update_existing: bool,
    pub verify_after: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplySummary {
    pub folders_created: usize,
    pub items_created: usize,
    pub items_updated: usize,
    pub attachments_uploaded: usize,
    pub folders_deleted: usize,
    pub items_deleted: usize,
    pub attachments_deleted: usize,
    pub created_folder_ids: Vec<String>,
    pub created_item_ids: Vec<String>,
    pub updated_item_ids: Vec<String>,
    pub deleted_folder_ids: Vec<String>,
    pub deleted_item_ids: Vec<String>,
    pub deleted_attachment_ids: Vec<String>,
    pub uploaded_attachments: Vec<UploadedAttachment>,
    pub restore_map_updated: bool,
    /// The attachment upload batch failed; some of its uploads may have
    /// landed in the target even though `attachments_uploaded` is 0.
    pub attachment_upload_incomplete: bool,
    /// One target item id per planned attachment delete that was skipped
    /// because the target cannot remove the file while entry history still
    /// references it (KeePass); the attachment was left in place.
    pub attachment_deletes_kept_by_history: Vec<String>,
    /// Attachment deletes (also counted in `attachments_deleted`) that removed
    /// the old version of a changed attachment right before its successor
    /// was uploaded under the same name, on a target that saves both in one
    /// commit. Their ids may be reused by the successor, so post-apply
    /// verification checks the upload instead of the id's absence.
    pub replaced_attachment_ids: Vec<String>,
}

impl ApplySummary {
    /// Whether any target mutation was (or, for a failed upload batch, may
    /// have been) performed.
    pub fn has_mutations(&self) -> bool {
        self.folders_created > 0
            || self.items_created > 0
            || self.items_updated > 0
            || self.attachments_uploaded > 0
            || self.attachment_upload_incomplete
            || self.folders_deleted > 0
            || self.items_deleted > 0
            || self.attachments_deleted > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreVerification {
    pub created_items: usize,
    pub updated_items: usize,
    pub attachments: usize,
    pub deleted_items: usize,
    pub deleted_attachments: usize,
    pub deleted_folders: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOutcome {
    pub summary: ApplySummary,
    pub verification: Option<RestoreVerification>,
}

#[derive(Debug)]
pub enum RestoreError {
    /// Apply stopped part-way. `summary` records every mutation that
    /// completed before the failure, and whether the restore map was still
    /// written for them, so callers can tell the user what changed.
    Apply {
        summary: Box<ApplySummary>,
        error: AdapterError,
    },
    Verify {
        summary: Box<ApplySummary>,
        error: AdapterError,
    },
}

/// One attachment payload to upload to a target item.
#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentUpload {
    pub target_item_id: String,
    pub file_name: String,
    pub bytes: Vec<u8>,
    pub size: u64,
    pub sha256: String,
}

// `bytes` is plaintext attachment content; show only its length.
impl std::fmt::Debug for AttachmentUpload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentUpload")
            .field("target_item_id", &self.target_item_id)
            .field("file_name", &self.file_name)
            .field("bytes", &format_args!("<{} bytes>", self.bytes.len()))
            .field("size", &self.size)
            .field("sha256", &self.sha256)
            .finish()
    }
}

/// One attachment confirmed uploaded to a target item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadedAttachment {
    pub target_item_id: String,
    pub file_name: String,
    pub size: u64,
    pub sha256: String,
}

/// Target-visible item metadata used to verify deletions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VisibleItem {
    pub id: String,
    pub attachment_ids: Vec<String>,
}

/// The operations restore apply and post-apply verification need from a
/// target vault. Payloads are Bitwarden-wire JSON: the seam exists so the
/// apply sequence can be exercised against an in-memory fake, not to
/// abstract over backends, so adapters see the exact payloads `bw` would.
pub trait VaultTargetOps {
    /// Create a folder, returning the target-assigned folder id.
    fn create_folder(&self, payload: &Value) -> Result<String, AdapterError>;
    /// Create an item, returning the target-assigned item id.
    fn create_item(&self, payload: &Value) -> Result<String, AdapterError>;
    fn edit_item(&self, item_id: &str, payload: &Value) -> Result<(), AdapterError>;
    /// Upload a batch of attachments. Implementations may parallelize;
    /// `total` is the progress denominator (it can exceed `jobs.len()` when
    /// a caller splits one logical batch across calls).
    fn upload_attachments(
        &self,
        jobs: &[AttachmentUpload],
        progress: &dyn ProgressReporter,
        total: u64,
    ) -> Result<Vec<UploadedAttachment>, AdapterError>;
    fn delete_attachment(&self, item_id: &str, attachment_id: &str) -> Result<(), AdapterError>;
    fn delete_item(&self, item_id: &str, permanent: bool) -> Result<(), AdapterError>;
    fn delete_folder(&self, folder_id: &str) -> Result<(), AdapterError>;
    /// Refresh target state so subsequent reads see recent writes.
    fn sync(&self) -> Result<(), AdapterError>;
    /// Fetch one item as raw target JSON; errors if the item is not visible.
    fn get_item(&self, item_id: &str) -> Result<String, AdapterError>;
    fn download_attachment(
        &self,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<Vec<u8>, AdapterError>;
    fn list_visible_items(&self) -> Result<Vec<VisibleItem>, AdapterError>;
    fn list_folder_ids(&self) -> Result<Vec<String>, AdapterError>;
    /// Persist every mutation made so far. Targets that write through on
    /// each call (`bw`) need nothing here; targets that batch writes in
    /// memory (KeePass) save them now. On error nothing pending was
    /// persisted and the pending mutations are discarded.
    fn commit(&self) -> Result<(), AdapterError> {
        Ok(())
    }
    /// Whether mutations stay pending until [`commit`](Self::commit) and are
    /// persisted all together (or not at all), so they can still be dropped
    /// with [`discard`](Self::discard). False for write-through targets.
    fn batches_writes(&self) -> bool {
        false
    }
    /// Drop every mutation made since the last commit. Only meaningful when
    /// [`batches_writes`](Self::batches_writes) is true.
    fn discard(&self) {}
}

/// A restore target a backend exposes to the CLI: the mutation seam plus a
/// read-only scan of the current target state for planning.
pub trait RestoreTarget: VaultTargetOps {
    fn backend_name(&self) -> &'static str;
    fn scan(&self, progress: &dyn ProgressReporter) -> Result<Vault, AdapterError>;
}

pub fn apply_restore_plan(
    target: &dyn VaultTargetOps,
    opened: &OpenedArchive,
    plan: &RestorePlan,
    target_vault: &Vault,
    target_organization_id: Option<&str>,
    options: ApplyOptions,
    progress: &dyn ProgressReporter,
) -> Result<RestoreOutcome, RestoreError> {
    let mut summary = ApplySummary::default();
    // What the target has durably saved; see `commit_or_discard`.
    let mut committed = ApplySummary::default();
    let mut restore_map_entries = Vec::new();
    let mut failure = run_apply(
        target,
        opened,
        plan,
        target_vault,
        target_organization_id,
        options,
        progress,
        &mut summary,
        &mut restore_map_entries,
    )
    .err();

    // After a mid-apply failure, persist what completed before attempting
    // the best-effort restore-map write, so a failing map write cannot cost
    // the completed mutations.
    if let Some(error) = failure.take() {
        failure = Some(
            match commit_or_discard(target, &mut summary, &mut committed) {
                Ok(()) => error,
                Err(commit_error) => AdapterError::new(format!("{error}; {commit_error}")),
            },
        );
    }

    // The restore map is written on success, and best-effort after a
    // mid-apply failure once anything was mutated: without it a re-run would
    // not recognize the items this run already created and would duplicate
    // them. A failure before the first mutation leaves the target untouched.
    if options.restore_map && (failure.is_none() || summary.has_mutations()) {
        let map_result = matched_restore_map_entries(opened, plan).and_then(|matched| {
            restore_map_entries.extend(matched);
            if restore_map_entries.is_empty() && plan.restore_map_stale_item_ids.is_empty() {
                return Ok(false);
            }
            progress.step_start("write restore map");
            let written = upsert_restore_map(
                target,
                target_vault,
                std::mem::take(&mut restore_map_entries),
                &plan.restore_map_stale_item_ids,
                target_organization_id,
            )?;
            progress.step_finish("write restore map");
            Ok(written)
        });
        match map_result {
            Ok(updated) => summary.restore_map_updated = updated,
            Err(map_error) => {
                failure = Some(match failure {
                    None => map_error,
                    Some(error) => AdapterError::new(format!(
                        "{error}; the restore map could not be updated either: {map_error}"
                    )),
                });
            }
        }
    }
    if let Err(commit_error) = commit_or_discard(target, &mut summary, &mut committed) {
        failure = Some(match failure {
            None => commit_error,
            Some(error) => AdapterError::new(format!("{error}; {commit_error}")),
        });
    }
    if let Some(error) = failure {
        return Err(RestoreError::Apply {
            summary: Box::new(summary),
            error,
        });
    }

    if !options.verify_after {
        return Ok(RestoreOutcome {
            summary,
            verification: None,
        });
    }
    match verify_applied_restore(target, &summary, progress) {
        Ok(verification) => Ok(RestoreOutcome {
            summary,
            verification: Some(verification),
        }),
        Err(error) => Err(RestoreError::Verify {
            summary: Box::new(summary),
            error,
        }),
    }
}

/// Ask the target to persist its pending mutations. On success `committed`
/// catches up with `summary`. On failure the target discarded everything
/// since its last save, so `summary` is rolled back to `committed`: nothing
/// unsaved is ever reported as applied.
fn commit_or_discard(
    target: &dyn VaultTargetOps,
    summary: &mut ApplySummary,
    committed: &mut ApplySummary,
) -> Result<(), AdapterError> {
    match target.commit() {
        Ok(()) => {
            *committed = summary.clone();
            Ok(())
        }
        Err(error) => {
            let pending = summary.has_mutations() || summary.restore_map_updated;
            *summary = committed.clone();
            Err(AdapterError::new(if pending {
                format!(
                    "saving the target failed: {error}; nothing was written for the changes \
                     since the last save, and they are not counted as applied"
                )
            } else {
                format!("saving the target failed: {error}; nothing was written")
            }))
        }
    }
}

/// Perform the planned mutations, recording each completed one in `summary`
/// (and its restore-map entry in `restore_map_entries`) as it happens, so the
/// caller still knows what changed when a later step fails.
#[allow(clippy::too_many_arguments)]
fn run_apply(
    target: &dyn VaultTargetOps,
    opened: &OpenedArchive,
    plan: &RestorePlan,
    target_vault: &Vault,
    target_organization_id: Option<&str>,
    options: ApplyOptions,
    progress: &dyn ProgressReporter,
    summary: &mut ApplySummary,
    restore_map_entries: &mut Vec<(String, RestoreMapEntry)>,
) -> Result<(), AdapterError> {
    let ApplyOptions {
        mark_restored,
        restore_map: _,
        update_existing,
        verify_after: _,
    } = options;
    progress.phase("apply restore");
    let archive_items = opened
        .vault
        .items
        .iter()
        .map(|item| (item.id.clone(), item))
        .collect::<BTreeMap<_, _>>();
    let archive_folders = opened
        .vault
        .folders
        .iter()
        .map(|folder| (folder.id.clone(), folder))
        .collect::<BTreeMap<_, _>>();
    let target_items = target_vault
        .items
        .iter()
        .map(|item| (item.id.clone(), item))
        .collect::<BTreeMap<_, _>>();
    let attachments = opened
        .attachments
        .iter()
        .map(|attachment| (attachment.path.clone(), attachment))
        .collect::<BTreeMap<_, _>>();
    let mut attachment_upload_jobs = Vec::new();
    let mut folder_id_map = plan.matched_target_folder_ids.clone();

    let folders_to_create = plan.create_folder_ids.len() as u64;
    if folders_to_create > 0 {
        progress.counted("creating folders", 0, folders_to_create);
    }
    for folder_id in &plan.create_folder_ids {
        let folder = archive_folders
            .get(folder_id)
            .copied()
            .ok_or_else(|| AdapterError::new(format!("planned folder `{folder_id}` not found")))?;
        let payload = bitwarden_folder_payload(folder);
        let created_id = target.create_folder(&payload)?;
        summary.folders_created += 1;
        summary.created_folder_ids.push(created_id.clone());
        folder_id_map.insert(folder.id.clone(), created_id);
        progress.counted(
            "creating folders",
            summary.folders_created as u64,
            folders_to_create,
        );
    }

    let items_to_create = plan.create_item_ids.len() as u64;
    let attachments_to_upload =
        planned_attachments_to_upload(&archive_items, &target_items, plan, update_existing)?;
    if items_to_create > 0 {
        progress.counted("creating items", 0, items_to_create);
    }
    if attachments_to_upload > 0 {
        progress.counted("uploading attachments", 0, attachments_to_upload);
    }
    for item_id in &plan.create_item_ids {
        let item = archive_items
            .get(item_id)
            .copied()
            .ok_or_else(|| AdapterError::new(format!("planned item `{item_id}` not found")))?;
        let payload = bitwarden_create_payload(
            item,
            mark_restored,
            opened.vault.metadata.archive_version,
            target_folder_id(item, &folder_id_map).as_deref(),
            target_organization_id,
        )?;
        let created_id = target.create_item(&payload)?;
        summary.items_created += 1;
        summary.created_item_ids.push(created_id.clone());
        progress.counted(
            "creating items",
            summary.items_created as u64,
            items_to_create,
        );
        restore_map_entries.push((
            item.id.clone(),
            RestoreMapEntry {
                target_item_id: created_id.clone(),
                source_fingerprint: item_fingerprint(item),
            },
        ));

        for attachment in &item.attachments {
            let Some(payload) = attachments.get(&attachment.path) else {
                return Err(AdapterError::new(format!(
                    "attachment payload `{}` not found",
                    attachment.path
                )));
            };
            attachment_upload_jobs.push(AttachmentUpload {
                target_item_id: created_id.clone(),
                bytes: payload.bytes.clone(),
                file_name: attachment.file_name.clone(),
                size: attachment.size,
                sha256: attachment.sha256.clone(),
            });
        }
    }

    if update_existing {
        let items_to_update = plan.update_item_ids.len() as u64;
        if items_to_update > 0 {
            progress.counted("updating items", 0, items_to_update);
        }
        for item_id in &plan.update_item_ids {
            let item = archive_items.get(item_id).copied().ok_or_else(|| {
                AdapterError::new(format!("planned update item `{item_id}` not found"))
            })?;
            let target_id = plan.matched_target_item_ids.get(item_id).ok_or_else(|| {
                AdapterError::new(format!("planned update item `{item_id}` has no target id"))
            })?;
            let mut payload = bitwarden_create_payload(
                item,
                mark_restored,
                opened.vault.metadata.archive_version,
                target_folder_id(item, &folder_id_map).as_deref(),
                target_organization_id,
            )?;
            payload["id"] = json!(target_id);
            target.edit_item(target_id, &payload)?;
            summary.items_updated += 1;
            summary.updated_item_ids.push(target_id.clone());
            progress.counted(
                "updating items",
                summary.items_updated as u64,
                items_to_update,
            );
            restore_map_entries.push((
                item.id.clone(),
                RestoreMapEntry {
                    target_item_id: target_id.clone(),
                    source_fingerprint: item_fingerprint(item),
                },
            ));

            let target_item = target_items
                .get(target_id)
                .copied()
                .ok_or_else(|| AdapterError::new(format!("target item `{target_id}` not found")))?;
            let pairing = pair_attachments(&item.attachments, &target_item.attachments);
            for (attachment, present) in item.attachments.iter().zip(pairing.archive_present) {
                if present {
                    continue;
                }
                let Some(payload) = attachments.get(&attachment.path) else {
                    return Err(AdapterError::new(format!(
                        "attachment payload `{}` not found",
                        attachment.path
                    )));
                };
                attachment_upload_jobs.push(AttachmentUpload {
                    target_item_id: target_id.clone(),
                    bytes: payload.bytes.clone(),
                    file_name: attachment.file_name.clone(),
                    size: attachment.size,
                    sha256: attachment.sha256.clone(),
                });
            }
        }
    }

    // On a target that saves the whole apply in one commit, the old version
    // of a changed attachment is removed before its successor is uploaded,
    // so the successor keeps the file name instead of becoming "x (2).ext".
    // Both land in the same save; if anything fails before the uploads are
    // done, the whole apply is discarded (nothing is saved), so the target
    // never ends up with neither version.
    let replaced = if update_existing && target.batches_writes() {
        match replace_same_name_attachments(
            target,
            plan,
            &target_items,
            &attachment_upload_jobs,
            summary,
        ) {
            Ok(replaced) => replaced,
            Err(error) => {
                return Err(discard_replacements(
                    target,
                    summary,
                    restore_map_entries,
                    error,
                ));
            }
        }
    } else {
        Vec::new()
    };

    // The upload seam reports all-or-nothing, so a failed batch is recorded
    // as "possibly partial" rather than guessed at.
    match target.upload_attachments(&attachment_upload_jobs, progress, attachments_to_upload) {
        Ok(uploaded) => {
            summary.attachments_uploaded = uploaded.len();
            summary.uploaded_attachments = uploaded;
        }
        Err(error) if !summary.replaced_attachment_ids.is_empty() => {
            return Err(discard_replacements(
                target,
                summary,
                restore_map_entries,
                error,
            ));
        }
        Err(error) => {
            summary.attachment_upload_incomplete = true;
            return Err(error);
        }
    }

    // A delete tied to an item update (its replacement was just uploaded by
    // that update) only runs when updates are applied.
    let delete_attachments = plan
        .delete_attachments
        .iter()
        .filter(|attachment| update_existing || !attachment.requires_item_update)
        .filter(|attachment| !replaced.contains(attachment))
        .collect::<Vec<_>>();
    let attachments_to_delete = delete_attachments.len() as u64;
    if attachments_to_delete > 0 {
        progress.counted("deleting attachments", 0, attachments_to_delete);
    }
    for (index, attachment) in delete_attachments.into_iter().enumerate() {
        match target.delete_attachment(&attachment.target_item_id, &attachment.attachment_id) {
            Ok(()) => {
                summary.attachments_deleted += 1;
                summary
                    .deleted_attachment_ids
                    .push(attachment.attachment_id.clone());
            }
            // The target left everything untouched; keeping one extra
            // attachment is safe, so skip it instead of aborting the apply.
            Err(AdapterError::KeptByHistory(_)) => summary
                .attachment_deletes_kept_by_history
                .push(attachment.target_item_id.clone()),
            Err(error) => return Err(error),
        }
        progress.counted(
            "deleting attachments",
            index as u64 + 1,
            attachments_to_delete,
        );
    }

    let items_to_delete = plan.delete_item_ids.len() as u64;
    if items_to_delete > 0 {
        progress.counted("deleting items", 0, items_to_delete);
    }
    for item_id in &plan.delete_item_ids {
        target.delete_item(item_id, plan.prune_permanent)?;
        summary.items_deleted += 1;
        summary.deleted_item_ids.push(item_id.clone());
        progress.counted(
            "deleting items",
            summary.items_deleted as u64,
            items_to_delete,
        );
    }

    let folders_to_delete = plan.delete_folder_ids.len() as u64;
    if folders_to_delete > 0 {
        progress.counted("deleting folders", 0, folders_to_delete);
    }
    for folder_id in &plan.delete_folder_ids {
        target.delete_folder(folder_id)?;
        summary.folders_deleted += 1;
        summary.deleted_folder_ids.push(folder_id.clone());
        progress.counted(
            "deleting folders",
            summary.folders_deleted as u64,
            folders_to_delete,
        );
    }

    Ok(())
}

/// A step failed after old attachment versions were removed (in memory)
/// ahead of their successors' upload: drop every change of the run so the
/// commit that follows saves nothing, and report nothing as applied.
fn discard_replacements(
    target: &dyn VaultTargetOps,
    summary: &mut ApplySummary,
    restore_map_entries: &mut Vec<(String, RestoreMapEntry)>,
    error: AdapterError,
) -> AdapterError {
    if summary.replaced_attachment_ids.is_empty() {
        return error;
    }
    target.discard();
    *summary = ApplySummary::default();
    restore_map_entries.clear();
    AdapterError::new(format!(
        "{error}; attachments it replaces had already been removed in memory, so every \
         change of this run was discarded and nothing was saved"
    ))
}

/// Remove the old target version of every changed attachment that an
/// upload job is about to replace under the same file name (see
/// `run_apply`). Returns the planned deletes handled here, including any
/// the target kept because entry history references the file.
fn replace_same_name_attachments<'a>(
    target: &dyn VaultTargetOps,
    plan: &'a RestorePlan,
    target_items: &BTreeMap<String, &VaultItem>,
    upload_jobs: &[AttachmentUpload],
    summary: &mut ApplySummary,
) -> Result<Vec<&'a RestoreAttachmentDelete>, AdapterError> {
    let mut handled = Vec::new();
    for delete in plan
        .delete_attachments
        .iter()
        .filter(|delete| delete.requires_item_update)
    {
        let file_name = target_items
            .get(&delete.target_item_id)
            .and_then(|item| {
                item.attachments
                    .iter()
                    .find(|attachment| attachment.id == delete.attachment_id)
            })
            .map(|attachment| attachment.file_name.as_str());
        let replaced_by_upload = file_name.is_some_and(|file_name| {
            upload_jobs.iter().any(|job| {
                job.target_item_id == delete.target_item_id && job.file_name == file_name
            })
        });
        if !replaced_by_upload {
            continue;
        }
        match target.delete_attachment(&delete.target_item_id, &delete.attachment_id) {
            Ok(()) => {
                summary.attachments_deleted += 1;
                summary
                    .replaced_attachment_ids
                    .push(delete.attachment_id.clone());
            }
            Err(AdapterError::KeptByHistory(_)) => summary
                .attachment_deletes_kept_by_history
                .push(delete.target_item_id.clone()),
            Err(error) => return Err(error),
        }
        handled.push(delete);
    }
    Ok(handled)
}

/// Restore-map entries for archive items the plan matched to existing
/// target items (entries for created/updated items are collected during
/// apply; re-inserting a matched item's entry is idempotent).
fn matched_restore_map_entries(
    opened: &OpenedArchive,
    plan: &RestorePlan,
) -> Result<Vec<(String, RestoreMapEntry)>, AdapterError> {
    let archive_items = opened
        .vault
        .items
        .iter()
        .map(|item| (item.id.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    plan.matched_target_item_ids
        .iter()
        .map(|(source_item_id, target_item_id)| {
            let item = archive_items.get(source_item_id.as_str()).ok_or_else(|| {
                AdapterError::new(format!("matched item `{source_item_id}` not found"))
            })?;
            Ok((
                source_item_id.clone(),
                RestoreMapEntry {
                    target_item_id: target_item_id.clone(),
                    source_fingerprint: item_fingerprint(item),
                },
            ))
        })
        .collect()
}

pub fn verify_applied_restore(
    target: &dyn VaultTargetOps,
    summary: &ApplySummary,
    progress: &dyn ProgressReporter,
) -> Result<RestoreVerification, AdapterError> {
    progress.phase("verify applied restore");
    let created_items = verify_items_exist(target, &summary.created_item_ids, progress)
        .map_err(|error| AdapterError::new(format!("post-apply verification failed: {error}")))?;
    let updated_items = verify_items_exist(target, &summary.updated_item_ids, progress)
        .map_err(|error| AdapterError::new(format!("post-apply verification failed: {error}")))?;
    let attachments = verify_uploaded_attachments(target, &summary.uploaded_attachments, progress)
        .map_err(|error| {
            AdapterError::new(format!(
                "post-apply attachment verification failed: {error}"
            ))
        })?;
    let deleted_items =
        verify_deleted_items(target, &summary.deleted_item_ids, progress).map_err(|error| {
            AdapterError::new(format!(
                "post-apply deleted item verification failed: {error}"
            ))
        })?;
    let deleted_attachments =
        verify_deleted_attachments(target, &summary.deleted_attachment_ids, progress).map_err(
            |error| {
                AdapterError::new(format!(
                    "post-apply deleted attachment verification failed: {error}"
                ))
            },
        )?;
    let deleted_folders = verify_deleted_folders(target, &summary.deleted_folder_ids, progress)
        .map_err(|error| {
            AdapterError::new(format!(
                "post-apply deleted folder verification failed: {error}"
            ))
        })?;
    Ok(RestoreVerification {
        created_items,
        updated_items,
        attachments,
        deleted_items,
        deleted_attachments,
        deleted_folders,
    })
}

fn verify_items_exist(
    target: &dyn VaultTargetOps,
    item_ids: &[String],
    progress: &dyn ProgressReporter,
) -> Result<usize, AdapterError> {
    let total = item_ids.len() as u64;
    let mut completed = 0;
    if total > 0 {
        progress.counted("verifying items", 0, total);
    }
    for item_id in item_ids {
        target.get_item(item_id)?;
        completed += 1;
        progress.counted("verifying items", completed, total);
    }
    Ok(item_ids.len())
}

fn verify_uploaded_attachments(
    target: &dyn VaultTargetOps,
    uploaded_attachments: &[UploadedAttachment],
    progress: &dyn ProgressReporter,
) -> Result<usize, AdapterError> {
    if uploaded_attachments.is_empty() {
        return Ok(0);
    }

    let total = uploaded_attachments.len() as u64;
    let mut completed = 0;
    if total > 0 {
        progress.counted("verifying attachments", 0, total);
    }
    for uploaded in uploaded_attachments {
        if !verify_uploaded_attachment_with_retry(target, uploaded)? {
            return Err(AdapterError::new(format!(
                "uploaded attachment for item `{}` did not match archived bytes after apply",
                uploaded.target_item_id
            )));
        }
        completed += 1;
        progress.counted("verifying attachments", completed, total);
    }

    Ok(uploaded_attachments.len())
}

fn verify_uploaded_attachment_with_retry(
    target: &dyn VaultTargetOps,
    uploaded: &UploadedAttachment,
) -> Result<bool, AdapterError> {
    for attempt in 0..ATTACHMENT_VERIFY_ATTEMPTS {
        target.sync()?;
        let item_json = target.get_item(&uploaded.target_item_id)?;
        let item = serde_json::from_str::<Value>(&item_json)?;
        let attachment_id = item
            .get("attachments")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|attachment| {
                attachment.get("fileName").and_then(Value::as_str)
                    == Some(uploaded.file_name.as_str())
            })
            .and_then(|attachment| attachment.get("id"))
            .and_then(Value::as_str)
            .map(str::to_string);
        if let Some(attachment_id) = attachment_id {
            let bytes = target.download_attachment(&uploaded.target_item_id, &attachment_id)?;
            if stable_fingerprint(&bytes) == uploaded.sha256 {
                return Ok(true);
            }
        }
        if attempt + 1 < ATTACHMENT_VERIFY_ATTEMPTS {
            std::thread::sleep(ATTACHMENT_VERIFY_RETRY_DELAY);
        }
    }
    Ok(false)
}

fn verify_deleted_items(
    target: &dyn VaultTargetOps,
    item_ids: &[String],
    progress: &dyn ProgressReporter,
) -> Result<usize, AdapterError> {
    if item_ids.is_empty() {
        return Ok(0);
    }

    let listed_items = target.list_visible_items()?;
    let total = item_ids.len() as u64;
    let mut completed = 0;
    if total > 0 {
        progress.counted("verifying deleted items", 0, total);
    }
    for item_id in item_ids {
        let still_visible = listed_items.iter().any(|item| &item.id == item_id);
        if still_visible {
            return Err(AdapterError::new(format!(
                "deleted item `{item_id}` was still visible after apply"
            )));
        }
        completed += 1;
        progress.counted("verifying deleted items", completed, total);
    }

    Ok(item_ids.len())
}

fn verify_deleted_attachments(
    target: &dyn VaultTargetOps,
    attachment_ids: &[String],
    progress: &dyn ProgressReporter,
) -> Result<usize, AdapterError> {
    if attachment_ids.is_empty() {
        return Ok(0);
    }

    let listed_items = target.list_visible_items()?;
    let total = attachment_ids.len() as u64;
    let mut completed = 0;
    if total > 0 {
        progress.counted("verifying deleted attachments", 0, total);
    }
    for attachment_id in attachment_ids {
        let still_visible = listed_items
            .iter()
            .any(|item| item.attachment_ids.contains(attachment_id));
        if still_visible {
            return Err(AdapterError::new(format!(
                "deleted attachment `{attachment_id}` was still visible after apply"
            )));
        }
        completed += 1;
        progress.counted("verifying deleted attachments", completed, total);
    }

    Ok(attachment_ids.len())
}

fn verify_deleted_folders(
    target: &dyn VaultTargetOps,
    folder_ids: &[String],
    progress: &dyn ProgressReporter,
) -> Result<usize, AdapterError> {
    if folder_ids.is_empty() {
        return Ok(0);
    }

    let visible_folder_ids = target.list_folder_ids()?;
    let total = folder_ids.len() as u64;
    let mut completed = 0;
    if total > 0 {
        progress.counted("verifying deleted folders", 0, total);
    }
    for folder_id in folder_ids {
        let still_visible = visible_folder_ids.contains(folder_id);
        if still_visible {
            return Err(AdapterError::new(format!(
                "deleted folder `{folder_id}` was still visible after apply"
            )));
        }
        completed += 1;
        progress.counted("verifying deleted folders", completed, total);
    }

    Ok(folder_ids.len())
}

/// Merge `entries` into the target's restore map and write the chunks that
/// changed. Chunks whose stored content already equals the merged map are
/// left alone, so a no-op run edits nothing (no `bw edit`, no KeePass save).
/// Returns whether anything was written.
fn upsert_restore_map(
    target: &dyn VaultTargetOps,
    target_vault: &Vault,
    entries: Vec<(String, RestoreMapEntry)>,
    stale_source_item_ids: &[String],
    target_organization_id: Option<&str>,
) -> Result<bool, AdapterError> {
    let existing_state =
        restore_map_state(target_vault).map_err(|error| AdapterError::new(error.to_string()))?;
    let mut map = existing_state
        .as_ref()
        .map(|state| state.map.clone())
        .unwrap_or_else(RestoreMap::empty);
    for source_item_id in stale_source_item_ids {
        map.entries.remove(source_item_id);
    }
    for (source_item_id, entry) in entries {
        map.entries.insert(source_item_id, entry);
    }

    let existing_items = restore_map_items_by_chunk(target_vault);
    let chunks = split_restore_map(&map, target_organization_id)?;
    let mut written = false;
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        let existing_item = existing_items.by_chunk.get(&chunk_index).copied();
        if existing_item
            .is_some_and(|item| restore_map_chunk_is_current(item, chunk, target_organization_id))
        {
            continue;
        }
        let payload = bitwarden_restore_map_payload(
            existing_item,
            chunk,
            target_organization_id,
            &restore_map_item_name(chunk_index),
        )?;
        let encoded_len = BASE64.encode(serde_json::to_vec(&payload)?).len();
        if encoded_len > RESTORE_MAP_MAX_ENCODED_ARG_BYTES {
            return Err(AdapterError::new(format!(
                "restore map chunk {} exceeded encoded argument budget",
                chunk_index + 1
            )));
        }
        if let Some(existing_item) = existing_item {
            target.edit_item(&existing_item.id, &payload)?;
        } else {
            target.create_item(&payload)?;
        }
        written = true;
    }

    for (chunk_index, existing_item) in existing_items.by_chunk {
        if chunk_index >= chunks.len() {
            target.delete_item(&existing_item.id, false)?;
            written = true;
        }
    }
    for duplicate_item in existing_items.duplicates {
        target.delete_item(&duplicate_item.id, false)?;
        written = true;
    }

    Ok(written)
}

/// Whether a stored restore-map chunk item already holds exactly `chunk`
/// where [`bitwarden_restore_map_payload`] would put it (root folder, the
/// managed note, the right organization), so rewriting it changes nothing.
fn restore_map_chunk_is_current(
    item: &VaultItem,
    chunk: &RestoreMap,
    target_organization_id: Option<&str>,
) -> bool {
    let stored = restore_map_field(item)
        .and_then(|field| serde_json::from_str::<RestoreMap>(&field.value).ok());
    let organization_id = item
        .backend_metadata
        .iter()
        .find_map(|(key, value)| (key == "bitwarden.raw").then_some(value))
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .and_then(|raw| {
            raw.get("organizationId")
                .and_then(Value::as_str)
                .map(str::to_string)
        });
    stored.as_ref() == Some(chunk)
        && item.folder_id.is_none()
        && item.notes.as_deref() == Some(RESTORE_MAP_NOTE)
        && organization_id.as_deref() == target_organization_id
}

fn bitwarden_create_payload(
    item: &VaultItem,
    mark_restored: bool,
    archive_version: u32,
    target_folder_id: Option<&str>,
    target_organization_id: Option<&str>,
) -> Result<Value, AdapterError> {
    if let Some(raw) = item
        .backend_metadata
        .iter()
        .find_map(|(key, value)| (key == "bitwarden.raw").then_some(value))
    {
        let mut value = serde_json::from_str::<Value>(raw)?;
        if let Some(object) = value.as_object_mut() {
            object.remove("id");
            object.remove("revisionDate");
            object.remove("creationDate");
            object.remove("deletedDate");
            object.remove("attachments");
        }
        value["folderId"] = target_folder_id.map_or(Value::Null, |folder_id| json!(folder_id));
        if let Some(target_organization_id) = target_organization_id {
            value["organizationId"] = json!(target_organization_id);
            if value.get("collectionIds").is_none() {
                value["collectionIds"] = json!([]);
            }
        }
        if mark_restored {
            add_restore_markers(&mut value, item, archive_version);
        }
        return Ok(value);
    }

    let item_type = item_type_number(&item.kind);
    let mut value = json!({
        "folderId": target_folder_id,
        "type": item_type,
        "name": item.name,
        "notes": item.notes,
        "favorite": item.favorite,
        "fields": fields_payload(&item.fields),
    });
    if item_type == 2 {
        ensure_secure_note_payload(&mut value);
    }
    if let Some(target_organization_id) = target_organization_id {
        value["organizationId"] = json!(target_organization_id);
        value["collectionIds"] = json!([]);
    }

    if let ItemKind::Login {
        username,
        password,
        uris,
        totp,
    } = &item.kind
    {
        value["login"] = json!({
            "username": username,
            "password": password,
            "totp": totp,
            "uris": uris.iter().map(|uri| json!({ "uri": uri })).collect::<Vec<_>>(),
        });
    }
    if mark_restored {
        add_restore_markers(&mut value, item, archive_version);
    }

    Ok(value)
}

fn bitwarden_folder_payload(folder: &Folder) -> Value {
    json!({
        "name": folder.name,
    })
}

fn target_folder_id(item: &VaultItem, folder_id_map: &BTreeMap<String, String>) -> Option<String> {
    item.folder_id
        .as_ref()
        .map(|folder_id| folder_id_map.get(folder_id).unwrap_or(folder_id).clone())
}

fn planned_attachments_to_upload(
    archive_items: &BTreeMap<String, &VaultItem>,
    target_items: &BTreeMap<String, &VaultItem>,
    plan: &RestorePlan,
    update_existing: bool,
) -> Result<u64, AdapterError> {
    let mut total = 0;
    for item_id in &plan.create_item_ids {
        let item = archive_items
            .get(item_id)
            .ok_or_else(|| AdapterError::new(format!("planned item `{item_id}` not found")))?;
        total += item.attachments.len() as u64;
    }
    if update_existing {
        for item_id in &plan.update_item_ids {
            let item = archive_items.get(item_id).ok_or_else(|| {
                AdapterError::new(format!("planned update item `{item_id}` not found"))
            })?;
            let target_id = plan.matched_target_item_ids.get(item_id).ok_or_else(|| {
                AdapterError::new(format!("planned update item `{item_id}` has no target id"))
            })?;
            let target_item = target_items
                .get(target_id)
                .ok_or_else(|| AdapterError::new(format!("target item `{target_id}` not found")))?;
            total += pair_attachments(&item.attachments, &target_item.attachments)
                .archive_present
                .iter()
                .filter(|present| !**present)
                .count() as u64;
        }
    }
    Ok(total)
}

fn add_restore_markers(value: &mut Value, item: &VaultItem, archive_version: u32) {
    let markers = [
        (YABBT_SOURCE_ITEM_ID_FIELD, item.id.clone()),
        (YABBT_SOURCE_FINGERPRINT_FIELD, item_fingerprint(item)),
        (YABBT_ARCHIVE_VERSION_FIELD, archive_version.to_string()),
    ];
    let fields = value
        .as_object_mut()
        .map(|object| object.entry("fields").or_insert_with(|| json!([])))
        .and_then(Value::as_array_mut);
    let Some(fields) = fields else {
        return;
    };

    fields.retain(|field| {
        let name = field.get("name").and_then(Value::as_str);
        !matches!(
            name,
            Some(YABBT_SOURCE_ITEM_ID_FIELD)
                | Some(YABBT_SOURCE_FINGERPRINT_FIELD)
                | Some(YABBT_ARCHIVE_VERSION_FIELD)
        )
    });

    for (name, marker_value) in markers {
        fields.push(json!({
            "name": name,
            "value": marker_value,
            "type": 1,
        }));
    }
}

fn bitwarden_restore_map_payload(
    existing_item: Option<&VaultItem>,
    map: &RestoreMap,
    target_organization_id: Option<&str>,
    item_name: &str,
) -> Result<Value, AdapterError> {
    let mut value = json!({
        "folderId": null,
        "type": 2,
        "name": item_name,
        "notes": RESTORE_MAP_NOTE,
        "favorite": false,
        "fields": [],
    });
    if let Some(existing_item) = existing_item {
        value["id"] = json!(existing_item.id);
    }

    value["type"] = json!(2);
    value["name"] = json!(item_name);
    value["notes"] = json!(RESTORE_MAP_NOTE);
    ensure_secure_note_payload(&mut value);
    if let Some(target_organization_id) = target_organization_id {
        value["organizationId"] = json!(target_organization_id);
        value["collectionIds"] = json!([]);
    }

    let map_json = serde_json::to_string(map)?;
    let fields = value
        .as_object_mut()
        .map(|object| object.entry("fields").or_insert_with(|| json!([])))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| AdapterError::new("restore map item fields were not an array"))?;
    fields
        .retain(|field| field.get("name").and_then(Value::as_str) != Some(RESTORE_MAP_FIELD_NAME));
    fields.push(json!({
        "name": RESTORE_MAP_FIELD_NAME,
        "value": map_json,
        "type": 1,
    }));

    Ok(value)
}

struct ExistingRestoreMapItems<'a> {
    by_chunk: BTreeMap<usize, &'a VaultItem>,
    duplicates: Vec<&'a VaultItem>,
}

fn restore_map_items_by_chunk(vault: &Vault) -> ExistingRestoreMapItems<'_> {
    let mut by_chunk = BTreeMap::new();
    let mut duplicates = Vec::new();
    for item in vault.items.iter().filter(|item| is_restore_map_item(item)) {
        let Some(chunk_index) = restore_map_chunk_index(&item.name) else {
            continue;
        };
        if let std::collections::btree_map::Entry::Vacant(entry) = by_chunk.entry(chunk_index) {
            entry.insert(item);
        } else {
            duplicates.push(item);
        }
    }

    ExistingRestoreMapItems {
        by_chunk,
        duplicates,
    }
}

fn split_restore_map(
    map: &RestoreMap,
    target_organization_id: Option<&str>,
) -> Result<Vec<RestoreMap>, AdapterError> {
    let mut chunks = Vec::new();
    let mut current = RestoreMap::empty();

    for (source_item_id, entry) in &map.entries {
        let mut candidate = current.clone();
        candidate
            .entries
            .insert(source_item_id.clone(), entry.clone());
        let candidate_len =
            encoded_restore_map_payload_len(chunks.len(), &candidate, target_organization_id)?;

        if candidate_len > RESTORE_MAP_CHUNK_TARGET_ENCODED_BYTES && !current.entries.is_empty() {
            chunks.push(current);
            current = RestoreMap::empty();
            current
                .entries
                .insert(source_item_id.clone(), entry.clone());
            let single_len =
                encoded_restore_map_payload_len(chunks.len(), &current, target_organization_id)?;
            if single_len > RESTORE_MAP_MAX_ENCODED_ARG_BYTES {
                return Err(AdapterError::new(format!(
                    "restore map entry `{source_item_id}` is too large to fit in one Bitwarden item"
                )));
            }
        } else {
            if candidate_len > RESTORE_MAP_MAX_ENCODED_ARG_BYTES {
                return Err(AdapterError::new(format!(
                    "restore map entry `{source_item_id}` is too large to fit in one Bitwarden item"
                )));
            }
            current = candidate;
        }
    }

    if !current.entries.is_empty() {
        chunks.push(current);
    }

    Ok(chunks)
}

fn encoded_restore_map_payload_len(
    chunk_index: usize,
    map: &RestoreMap,
    target_organization_id: Option<&str>,
) -> Result<usize, AdapterError> {
    let payload = bitwarden_restore_map_payload(
        None,
        map,
        target_organization_id,
        &restore_map_item_name(chunk_index),
    )?;
    Ok(BASE64.encode(serde_json::to_vec(&payload)?).len())
}

fn ensure_secure_note_payload(value: &mut Value) {
    value["secureNote"] = json!({
        "type": 0,
    });
}

fn item_type_number(kind: &ItemKind) -> u8 {
    match kind {
        ItemKind::Login { .. } => 1,
        ItemKind::SecureNote => 2,
        ItemKind::Card => 3,
        ItemKind::Identity => 4,
        ItemKind::SshKey | ItemKind::Unknown { .. } => 2,
    }
}

fn fields_payload(fields: &[Field]) -> Vec<Value> {
    fields
        .iter()
        .map(|field| {
            json!({
                "name": field.name,
                "value": field.value,
                "type": if field.hidden { 1 } else { 0 },
            })
        })
        .collect()
}

use crate::adapters::bitwarden_json::ORG_ITEMS_NOT_EXPORTED;
use crate::diff::stable_fingerprint;
use crate::model::{AttachmentRef, Folder, Vault, VaultItem};
use crate::progress::{NoopProgress, ProgressReporter};
use crate::restore_map::{RestoreMap, is_restore_map_item, restore_map_state};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const YABBT_SOURCE_ITEM_ID_FIELD: &str = "yabbt.source_item_id";
pub const YABBT_SOURCE_FINGERPRINT_FIELD: &str = "yabbt.source_fingerprint";
pub const YABBT_ARCHIVE_VERSION_FIELD: &str = "yabbt.archive_version";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RestorePlanOptions<'a> {
    pub target_organization_id: Option<&'a str>,
    pub prune: bool,
    pub prune_permanent: bool,
    /// Waive the mass-delete guard (see [`MASS_DELETE_MIN_ITEMS`]).
    pub allow_mass_delete: bool,
}

/// Prune is blocked as a likely mistake (wiped or broken source, wrong
/// archive, wrong target) when the archive has no items at all, or when it
/// would delete more than half of the target's items *and* more than this
/// many items, unless `allow_mass_delete` is set.
pub const MASS_DELETE_MIN_ITEMS: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RestorePlan {
    pub target_backend: String,
    pub dry_run: bool,
    pub archive_scope: String,
    pub archive_items: usize,
    pub target_items_scanned: Option<usize>,
    pub folders_to_create: usize,
    pub folders_to_delete: usize,
    pub items_to_create: usize,
    pub items_to_update: usize,
    pub items_unchanged: usize,
    pub items_to_skip: usize,
    pub items_to_delete: usize,
    pub attachments_to_upload: usize,
    pub attachments_to_delete: usize,
    pub warning_count: usize,
    pub create_item_ids: Vec<String>,
    pub create_folder_ids: Vec<String>,
    pub delete_folder_ids: Vec<String>,
    pub update_item_ids: Vec<String>,
    pub unchanged_item_ids: Vec<String>,
    pub skip_item_ids: Vec<String>,
    pub delete_item_ids: Vec<String>,
    pub delete_attachment_ids: Vec<String>,
    #[serde(skip)]
    pub delete_attachments: Vec<RestoreAttachmentDelete>,
    pub matched_target_folder_ids: BTreeMap<String, String>,
    pub matched_target_item_ids: BTreeMap<String, String>,
    pub restore_folder_ambiguous_ids: Vec<String>,
    pub invalid_scope_item_ids: Vec<String>,
    pub unsupported_organization_item_ids: Vec<String>,
    pub unsupported_collection_item_ids: Vec<String>,
    pub restore_map_stale_item_ids: Vec<String>,
    pub restore_fingerprint_ambiguous_item_ids: Vec<String>,
    pub prune_permanent: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct RestoreAttachmentDelete {
    pub target_item_id: String,
    pub attachment_id: String,
    /// The item's archive attachments are not all on the target yet: this
    /// delete may only run together with the item update that uploads them
    /// (`--update-existing`), never on its own.
    pub requires_item_update: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestorePlanStatus {
    Ready,
    Blocked,
}

impl RestorePlan {
    pub fn status(&self) -> RestorePlanStatus {
        if self.blockers.is_empty() {
            RestorePlanStatus::Ready
        } else {
            RestorePlanStatus::Blocked
        }
    }
}

pub fn plan_restore(archive: &Vault, target: Option<&Vault>, target_backend: &str) -> RestorePlan {
    plan_restore_with_options(
        archive,
        target,
        target_backend,
        RestorePlanOptions::default(),
    )
}

pub fn plan_restore_with_options(
    archive: &Vault,
    target: Option<&Vault>,
    target_backend: &str,
    options: RestorePlanOptions<'_>,
) -> RestorePlan {
    plan_restore_with_options_and_progress(archive, target, target_backend, options, &NoopProgress)
}

pub fn plan_restore_with_options_and_progress(
    archive: &Vault,
    target: Option<&Vault>,
    target_backend: &str,
    options: RestorePlanOptions<'_>,
    progress: &dyn ProgressReporter,
) -> RestorePlan {
    // An archive taken from a vault that was itself a restore target carries
    // that vault's restore-map note(s). They are yabbt bookkeeping for the
    // *archived* vault, not user data: restoring them would create a
    // duplicate map chunk that the next apply trashes again, forever.
    let archive_without_restore_maps;
    let archive = if archive.items.iter().any(is_restore_map_item) {
        archive_without_restore_maps = Vault {
            metadata: archive.metadata.clone(),
            folders: archive.folders.clone(),
            items: archive
                .items
                .iter()
                .filter(|item| !is_restore_map_item(item))
                .cloned()
                .collect(),
            report: archive.report.clone(),
        };
        &archive_without_restore_maps
    } else {
        archive
    };

    let mut blockers = Vec::new();
    if !archive.report.complete {
        let unexported_org_items = archive
            .report
            .warnings
            .iter()
            .any(|warning| warning.code == ORG_ITEMS_NOT_EXPORTED);
        blockers.push(if unexported_org_items {
            format!(
                "archive is marked incomplete ({ORG_ITEMS_NOT_EXPORTED}: organization items were \
                 not exported; re-run the backup or sync with --personal-only to accept a \
                 personal-vault-only archive)"
            )
        } else {
            "archive is marked incomplete".to_string()
        });
    }

    let archive_items = items_by_id(archive);
    let archive_folders = folders_by_id(archive);
    let archive_scope = infer_archive_scope(archive);
    if archive_scope.mixes_personal_and_organization {
        blockers.push(
            "archive mixes personal and organization scoped items; restore one scope at a time"
                .to_string(),
        );
    }
    if archive_scope.has_multiple_organizations {
        blockers.push(
            "archive contains items from multiple source organizations; restore one organization at a time"
                .to_string(),
        );
    }
    let folder_plan = plan_folders(archive, target);
    for folder_id in &folder_plan.ambiguous_folder_ids {
        blockers.push(format!(
            "archive folder `{folder_id}` matches multiple target folders"
        ));
    }
    for item in &archive.items {
        if let Some(folder_id) = &item.folder_id
            && !archive_folders.contains_key(folder_id)
        {
            blockers.push(format!(
                "archive item `{}` references missing folder `{folder_id}`",
                item.id
            ));
        }
    }
    let unsupported_organization_item_ids = archive
        .items
        .iter()
        .filter(|item| {
            bitwarden_item_scope(item).organization_scoped
                && options.target_organization_id.is_none()
        })
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    if !unsupported_organization_item_ids.is_empty() {
        blockers.push(
            "archive contains Bitwarden organization or collection scoped items; restore target organization mapping is not implemented yet"
                .to_string(),
        );
    }
    let unsupported_collection_item_ids = archive
        .items
        .iter()
        .filter(|item| bitwarden_item_scope(item).collection_scoped)
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    if !unsupported_collection_item_ids.is_empty() {
        blockers.push(
            "archive contains Bitwarden collection scoped items; collection mapping is not implemented yet"
                .to_string(),
        );
    }
    let restore_map = match target.map(restore_map_state).transpose() {
        Ok(state) => state.flatten().map(|state| state.map),
        Err(error) => {
            blockers.push(error.to_string());
            None
        }
    };
    let target_items = target.map(restorable_items_by_id);
    let target_markers = target.map(items_by_source_marker);
    let target_fingerprints = target_items.as_ref().map(targets_by_restore_fingerprint);
    let mut create_item_ids = Vec::new();
    let mut update_item_ids = Vec::new();
    let mut unchanged_item_ids = Vec::new();
    let mut skip_item_ids = Vec::new();
    let mut matched_target_item_ids = BTreeMap::new();
    let mut restore_map_stale_item_ids = Vec::new();
    let mut restore_fingerprint_ambiguous_item_ids = Vec::new();
    let mut matched_target_ids = BTreeSet::new();

    match &target_items {
        Some(target_items) => {
            if let Some(restore_map) = &restore_map {
                for (source_item_id, entry) in &restore_map.entries {
                    if !target_items.contains_key(&entry.target_item_id) {
                        restore_map_stale_item_ids.push(source_item_id.clone());
                    }
                }
            }

            let total_archive_items = archive_items.len() as u64;
            if total_archive_items > 0 {
                progress.counted("planning archive items", 0, total_archive_items);
            }

            // Bind archive items to target items strongest-evidence first, one
            // tier at a time (restore map, then per-item marker, then original
            // id), so a weaker match can never claim a target that a stronger
            // match owns. Within a tier archive items are visited in id order
            // and a target already claimed is skipped, so each target item is
            // bound to at most one archive item and the outcome is
            // deterministic. Unbound items then try the fingerprint fallback.
            let mut strong_matches = BTreeMap::<&String, &VaultItem>::new();
            for tier in [
                StrongMatch::RestoreMap,
                StrongMatch::Marker,
                StrongMatch::Id,
            ] {
                for id in archive_items.keys() {
                    if strong_matches.contains_key(id) {
                        continue;
                    }
                    let candidate = match tier {
                        StrongMatch::RestoreMap => map_target_item(id, &restore_map, target_items),
                        StrongMatch::Marker => target_markers
                            .as_ref()
                            .and_then(|markers| markers.get(id))
                            .copied(),
                        StrongMatch::Id => target_items.get(id).copied(),
                    };
                    if let Some(target_item) = candidate
                        && matched_target_ids.insert(target_item.id.clone())
                    {
                        strong_matches.insert(id, target_item);
                    }
                }
            }

            let mut planned_archive_items = 0;
            for (id, archive_item) in &archive_items {
                if let Some(target_item) = strong_matches.get(id).copied() {
                    matched_target_item_ids.insert(id.clone(), target_item.id.clone());
                    if items_match(archive_item, target_item, &folder_plan) {
                        unchanged_item_ids.push(id.clone());
                    } else {
                        update_item_ids.push(id.clone());
                    }
                } else {
                    match fingerprint_target_item(
                        archive_item,
                        target_fingerprints.as_ref(),
                        &matched_target_ids,
                    ) {
                        FingerprintMatch::Unique(target_item) => {
                            matched_target_ids.insert(target_item.id.clone());
                            matched_target_item_ids.insert(id.clone(), target_item.id.clone());
                            unchanged_item_ids.push(id.clone());
                        }
                        FingerprintMatch::Ambiguous => {
                            restore_fingerprint_ambiguous_item_ids.push(id.clone());
                            create_item_ids.push(id.clone());
                        }
                        FingerprintMatch::None => create_item_ids.push(id.clone()),
                    }
                }
                planned_archive_items += 1;
                progress.counted(
                    "planning archive items",
                    planned_archive_items,
                    total_archive_items,
                );
            }

            let total_target_items = target_items.len() as u64;
            if total_target_items > 0 {
                progress.counted("planning target items", 0, total_target_items);
            }
            let mut planned_target_items = 0;
            for id in target_items.keys() {
                if !archive_items.contains_key(id) && !matched_target_ids.contains(id) {
                    skip_item_ids.push(id.clone());
                }
                planned_target_items += 1;
                progress.counted(
                    "planning target items",
                    planned_target_items,
                    total_target_items,
                );
            }
        }
        None => {
            let total_archive_items = archive_items.len() as u64;
            if total_archive_items > 0 {
                progress.counted("planning archive items", 0, total_archive_items);
            }
            for (index, id) in archive_items.keys().enumerate() {
                create_item_ids.push(id.clone());
                progress.counted(
                    "planning archive items",
                    index as u64 + 1,
                    total_archive_items,
                );
            }
        }
    }

    if options.prune && !restore_fingerprint_ambiguous_item_ids.is_empty() {
        blockers.push("prune blocked by ambiguous fingerprint matches".to_string());
    }
    if options.prune && !folder_plan.ambiguous_folder_ids.is_empty() {
        blockers.push("prune blocked by ambiguous folder matches".to_string());
    }

    let attachments_to_upload = archive
        .items
        .iter()
        .filter(|item| create_item_ids.contains(&item.id) || update_item_ids.contains(&item.id))
        .map(|item| item.attachments.len())
        .sum();
    let prune_plan = if options.prune
        && restore_fingerprint_ambiguous_item_ids.is_empty()
        && folder_plan.ambiguous_folder_ids.is_empty()
    {
        plan_prune(
            archive,
            target,
            &matched_target_item_ids,
            &skip_item_ids,
            &folder_plan,
        )
    } else {
        PrunePlan::default()
    };
    if !options.allow_mass_delete {
        blockers.extend(mass_delete_blocker(archive, target, &prune_plan));
    }

    RestorePlan {
        target_backend: target_backend.to_string(),
        dry_run: true,
        archive_scope: archive_scope.label.to_string(),
        archive_items: archive.items.len(),
        target_items_scanned: target.map(|target| {
            target
                .items
                .iter()
                .filter(|item| !is_restore_map_item(item))
                .count()
        }),
        folders_to_create: folder_plan.create_folder_ids.len(),
        folders_to_delete: prune_plan.delete_folder_ids.len(),
        items_to_create: create_item_ids.len(),
        items_to_update: update_item_ids.len(),
        items_unchanged: unchanged_item_ids.len(),
        items_to_skip: skip_item_ids.len(),
        items_to_delete: prune_plan.delete_item_ids.len(),
        attachments_to_upload,
        attachments_to_delete: prune_plan.delete_attachment_ids.len(),
        warning_count: archive.report.warnings.len()
            + restore_map_stale_item_ids.len()
            + restore_fingerprint_ambiguous_item_ids.len(),
        create_item_ids,
        create_folder_ids: folder_plan.create_folder_ids,
        delete_folder_ids: prune_plan.delete_folder_ids,
        update_item_ids,
        unchanged_item_ids,
        skip_item_ids,
        delete_item_ids: prune_plan.delete_item_ids,
        delete_attachment_ids: prune_plan.delete_attachment_ids,
        delete_attachments: prune_plan.delete_attachments,
        matched_target_folder_ids: folder_plan.matched_target_folder_ids,
        matched_target_item_ids,
        restore_folder_ambiguous_ids: folder_plan.ambiguous_folder_ids,
        invalid_scope_item_ids: archive_scope.invalid_scope_item_ids,
        unsupported_organization_item_ids,
        unsupported_collection_item_ids,
        restore_map_stale_item_ids,
        restore_fingerprint_ambiguous_item_ids,
        prune_permanent: options.prune_permanent,
        blockers,
    }
}

/// Guard against a prune that would wipe most of the target: almost always
/// a wiped or broken source, the wrong archive, or the wrong target.
fn mass_delete_blocker(
    archive: &Vault,
    target: Option<&Vault>,
    prune_plan: &PrunePlan,
) -> Option<String> {
    let deletes_anything = !prune_plan.delete_item_ids.is_empty()
        || !prune_plan.delete_attachment_ids.is_empty()
        || !prune_plan.delete_folder_ids.is_empty();
    if !deletes_anything {
        return None;
    }
    if archive.items.is_empty() {
        return Some(
            "prune blocked: the archive contains no items, so every target item would be deleted; pass --allow-mass-delete if this is intended"
                .to_string(),
        );
    }
    let target_items = target.map_or(0, |target| {
        target
            .items
            .iter()
            .filter(|item| !is_restore_map_item(item))
            .count()
    });
    let item_deletes = prune_plan.delete_item_ids.len();
    if item_deletes > MASS_DELETE_MIN_ITEMS && item_deletes * 2 > target_items {
        return Some(format!(
            "prune blocked: it would delete {item_deletes} of {target_items} target items (more than half); pass --allow-mass-delete if this is intended"
        ));
    }
    None
}

fn items_by_id(vault: &Vault) -> BTreeMap<String, &VaultItem> {
    vault
        .items
        .iter()
        .map(|item| (item.id.clone(), item))
        .collect()
}

fn folders_by_id(vault: &Vault) -> BTreeMap<String, &Folder> {
    vault
        .folders
        .iter()
        .map(|folder| (folder.id.clone(), folder))
        .collect()
}

struct ArchiveScope {
    label: &'static str,
    invalid_scope_item_ids: Vec<String>,
    mixes_personal_and_organization: bool,
    has_multiple_organizations: bool,
}

fn infer_archive_scope(vault: &Vault) -> ArchiveScope {
    let mut personal_item_ids = Vec::new();
    let mut organization_item_ids = Vec::new();
    let mut source_organizations = BTreeSet::<String>::new();

    for item in &vault.items {
        match bitwarden_item_scope(item).organization_id {
            Some(None) => personal_item_ids.push(item.id.clone()),
            Some(Some(organization_id)) => {
                organization_item_ids.push(item.id.clone());
                source_organizations.insert(organization_id);
            }
            None => {}
        }
    }

    let mixes_personal_and_organization =
        !personal_item_ids.is_empty() && !organization_item_ids.is_empty();
    let has_multiple_organizations = source_organizations.len() > 1;
    let mut invalid_scope_item_ids = Vec::new();
    if mixes_personal_and_organization {
        invalid_scope_item_ids.extend(organization_item_ids.iter().cloned());
        invalid_scope_item_ids.extend(personal_item_ids.iter().cloned());
    } else if has_multiple_organizations {
        invalid_scope_item_ids.extend(organization_item_ids.iter().cloned());
    }
    invalid_scope_item_ids.sort();
    invalid_scope_item_ids.dedup();

    let label = if mixes_personal_and_organization || has_multiple_organizations {
        "mixed"
    } else if !organization_item_ids.is_empty() {
        "organization"
    } else if !personal_item_ids.is_empty() {
        "personal"
    } else {
        "unknown"
    };

    ArchiveScope {
        label,
        invalid_scope_item_ids,
        mixes_personal_and_organization,
        has_multiple_organizations,
    }
}

struct FolderPlan {
    create_folder_ids: Vec<String>,
    matched_target_folder_ids: BTreeMap<String, String>,
    ambiguous_folder_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct PrunePlan {
    delete_item_ids: Vec<String>,
    delete_attachment_ids: Vec<String>,
    delete_attachments: Vec<RestoreAttachmentDelete>,
    delete_folder_ids: Vec<String>,
}

fn plan_folders(archive: &Vault, target: Option<&Vault>) -> FolderPlan {
    let Some(target) = target else {
        return FolderPlan {
            create_folder_ids: archive
                .folders
                .iter()
                .map(|folder| folder.id.clone())
                .collect(),
            matched_target_folder_ids: BTreeMap::new(),
            ambiguous_folder_ids: Vec::new(),
        };
    };

    let mut target_folders_by_name = BTreeMap::<String, Vec<&Folder>>::new();
    for folder in &target.folders {
        target_folders_by_name
            .entry(folder.name.clone())
            .or_default()
            .push(folder);
    }

    let mut create_folder_ids = Vec::new();
    let mut matched_target_folder_ids = BTreeMap::new();
    let mut ambiguous_folder_ids = Vec::new();
    for archive_folder in &archive.folders {
        match target_folders_by_name
            .get(&archive_folder.name)
            .map(Vec::as_slice)
        {
            Some([target_folder]) => {
                matched_target_folder_ids
                    .insert(archive_folder.id.clone(), target_folder.id.clone());
            }
            Some(_) => ambiguous_folder_ids.push(archive_folder.id.clone()),
            None => create_folder_ids.push(archive_folder.id.clone()),
        }
    }

    FolderPlan {
        create_folder_ids,
        matched_target_folder_ids,
        ambiguous_folder_ids,
    }
}

fn restorable_items_by_id(vault: &Vault) -> BTreeMap<String, &VaultItem> {
    vault
        .items
        .iter()
        .filter(|item| !is_restore_map_item(item))
        .map(|item| (item.id.clone(), item))
        .collect()
}

fn plan_prune(
    archive: &Vault,
    target: Option<&Vault>,
    matched_target_item_ids: &BTreeMap<String, String>,
    skip_item_ids: &[String],
    folder_plan: &FolderPlan,
) -> PrunePlan {
    let Some(target) = target else {
        return PrunePlan::default();
    };

    let archive_items = items_by_id(archive);
    let target_items = restorable_items_by_id(target);
    let delete_item_ids = skip_item_ids.to_vec();
    let delete_item_id_set = delete_item_ids.iter().cloned().collect::<BTreeSet<_>>();
    let mut delete_attachments = Vec::new();

    for (source_item_id, target_item_id) in matched_target_item_ids {
        if delete_item_id_set.contains(target_item_id) {
            continue;
        }
        let Some(archive_item) = archive_items.get(source_item_id).copied() else {
            continue;
        };
        let Some(target_item) = target_items.get(target_item_id).copied() else {
            continue;
        };
        let pairing = pair_attachments(&archive_item.attachments, &target_item.attachments);
        // Never remove a target attachment ahead of its replacement: when
        // some archive attachment still has to be uploaded (changed content,
        // a rename on a hash-less target), the delete is tied to the item
        // update that uploads it.
        let requires_item_update = pairing.archive_present.contains(&false);
        for (target_attachment, kept) in target_item.attachments.iter().zip(&pairing.target_kept) {
            if !kept {
                delete_attachments.push(RestoreAttachmentDelete {
                    target_item_id: target_item_id.clone(),
                    attachment_id: target_attachment.id.clone(),
                    requires_item_update,
                });
            }
        }
    }

    let mut target_folders_to_keep = folder_plan
        .matched_target_folder_ids
        .values()
        .cloned()
        .collect::<BTreeSet<_>>();
    for item in target
        .items
        .iter()
        .filter(|item| !is_restore_map_item(item))
    {
        if delete_item_id_set.contains(&item.id) {
            continue;
        }
        if let Some(folder_id) = &item.folder_id {
            target_folders_to_keep.insert(folder_id.clone());
        }
    }

    // Nested folders are named "Parent/Child": never delete an ancestor of a
    // kept folder (for KeePass that would destroy the kept subtree), and
    // delete the deepest folders first so a parent is empty when its turn
    // comes.
    let kept_folder_names = target
        .folders
        .iter()
        .filter(|folder| target_folders_to_keep.contains(&folder.id))
        .map(|folder| folder.name.as_str())
        .collect::<Vec<_>>();
    let mut delete_folders = target
        .folders
        .iter()
        .filter(|folder| !target_folders_to_keep.contains(&folder.id))
        .filter(|folder| {
            let prefix = format!("{}/", folder.name);
            !kept_folder_names
                .iter()
                .any(|kept| kept.starts_with(&prefix))
        })
        .collect::<Vec<_>>();
    let depth = |folder: &Folder| folder.name.matches('/').count();
    delete_folders.sort_by(|left, right| {
        depth(right)
            .cmp(&depth(left))
            .then_with(|| left.id.cmp(&right.id))
    });
    let delete_folder_ids = delete_folders
        .into_iter()
        .map(|folder| folder.id.clone())
        .collect::<Vec<_>>();
    delete_attachments.sort();
    let mut delete_attachment_ids = delete_attachments
        .iter()
        .map(|attachment| attachment.attachment_id.clone())
        .collect::<Vec<_>>();
    delete_attachment_ids.sort();

    PrunePlan {
        delete_item_ids,
        delete_attachment_ids,
        delete_attachments,
        delete_folder_ids,
    }
}

/// How one item's archive attachments line up with its target attachments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttachmentPairing {
    /// Per archive attachment: already on the target (no upload needed).
    pub archive_present: Vec<bool>,
    /// Per target attachment: corresponds to an archive attachment (kept by
    /// prune).
    pub target_kept: Vec<bool>,
}

/// Pair an item's archive attachments with its target attachments.
///
/// Attachments hashed on both sides (archives always are; KeePass targets
/// are) pair one-to-one by content, ignoring the file name: a KeePass
/// target stores a second attachment with an already-used name as
/// "x (2).txt". Whatever is left falls back to the file name when either
/// side has no hash, which is how `bw` targets (whose listings carry none)
/// have always been compared.
pub(crate) fn pair_attachments(
    archive: &[AttachmentRef],
    target: &[AttachmentRef],
) -> AttachmentPairing {
    let mut archive_present = vec![false; archive.len()];
    let mut target_kept = vec![false; target.len()];
    for (archive_index, archive_attachment) in archive.iter().enumerate() {
        if archive_attachment.sha256.is_empty() {
            continue;
        }
        let partner = target.iter().enumerate().position(|(index, candidate)| {
            !target_kept[index] && candidate.sha256 == archive_attachment.sha256
        });
        if let Some(target_index) = partner {
            archive_present[archive_index] = true;
            target_kept[target_index] = true;
        }
    }
    let name_match = |left: &AttachmentRef, right: &AttachmentRef| {
        left.file_name == right.file_name && (left.sha256.is_empty() || right.sha256.is_empty())
    };
    for (archive_index, archive_attachment) in archive.iter().enumerate() {
        if !archive_present[archive_index] {
            archive_present[archive_index] = target
                .iter()
                .any(|target_attachment| name_match(archive_attachment, target_attachment));
        }
    }
    for (target_index, target_attachment) in target.iter().enumerate() {
        if !target_kept[target_index] {
            target_kept[target_index] = archive
                .iter()
                .any(|archive_attachment| name_match(archive_attachment, target_attachment));
        }
    }
    AttachmentPairing {
        archive_present,
        target_kept,
    }
}

/// Whether two items carry the same attachments: the same multiset of
/// contents when every attachment on both sides is hashed (so a renamed
/// duplicate or a content change is detected), else the same multiset of
/// file names (hash-less `bw` listings). Used for the fingerprint fallback,
/// where the attachments help identify the item, so it is stricter than the
/// change check in [`items_match`].
fn attachments_equivalent(archive_item: &VaultItem, target_item: &VaultItem) -> bool {
    let all = || {
        archive_item
            .attachments
            .iter()
            .chain(&target_item.attachments)
    };
    let key = |item: &VaultItem, hashed: bool| {
        let mut keys = item
            .attachments
            .iter()
            .map(|attachment| {
                if hashed {
                    attachment.sha256.clone()
                } else {
                    attachment.file_name.clone()
                }
            })
            .collect::<Vec<_>>();
        keys.sort();
        keys
    };
    let hashed = all().all(|attachment| !attachment.sha256.is_empty());
    key(archive_item, hashed) == key(target_item, hashed)
}

fn items_by_source_marker(vault: &Vault) -> BTreeMap<String, &VaultItem> {
    vault
        .items
        .iter()
        .filter_map(|item| marker_field(item, YABBT_SOURCE_ITEM_ID_FIELD).map(|id| (id, item)))
        .collect()
}

/// Whether a matched target item already holds the archive item: same
/// content, every archive attachment present on the target (see
/// [`pair_attachments`]), and the expected folder. Target-only attachments
/// do not make an item changed: an update could not remove them anyway
/// (prune does), and treating them as a change would plan the same update
/// on every run, e.g. after `--update-existing` without `--prune` kept the
/// old version of a changed attachment next to the new one.
fn items_match(
    archive_item: &VaultItem,
    target_item: &VaultItem,
    folder_plan: &FolderPlan,
) -> bool {
    let content_matches = restore_item_fingerprint(archive_item)
        == restore_item_fingerprint(target_item)
        && pair_attachments(&archive_item.attachments, &target_item.attachments)
            .archive_present
            .iter()
            .all(|present| *present);
    content_matches && folder_ids_match(archive_item, target_item, folder_plan)
}

fn folder_ids_match(
    archive_item: &VaultItem,
    target_item: &VaultItem,
    folder_plan: &FolderPlan,
) -> bool {
    let Some(source_folder_id) = &archive_item.folder_id else {
        return target_item.folder_id.is_none();
    };
    if folder_plan
        .create_folder_ids
        .iter()
        .any(|folder_id| folder_id == source_folder_id)
    {
        return false;
    }

    let expected_target_folder_id = folder_plan
        .matched_target_folder_ids
        .get(source_folder_id)
        .map(String::as_str)
        .unwrap_or(source_folder_id);
    target_item.folder_id.as_deref() == Some(expected_target_folder_id)
}

fn targets_by_restore_fingerprint<'a>(
    target_items: &'a BTreeMap<String, &'a VaultItem>,
) -> BTreeMap<String, Vec<&'a VaultItem>> {
    let mut targets = BTreeMap::<String, Vec<&VaultItem>>::new();
    for item in target_items.values() {
        targets
            .entry(restore_item_fingerprint(item))
            .or_default()
            .push(*item);
    }
    targets
}

/// Strong (identity-based) match sources, strongest first.
#[derive(Clone, Copy)]
enum StrongMatch {
    RestoreMap,
    Marker,
    Id,
}

enum FingerprintMatch<'a> {
    Unique(&'a VaultItem),
    Ambiguous,
    None,
}

fn fingerprint_target_item<'a>(
    archive_item: &VaultItem,
    target_fingerprints: Option<&'a BTreeMap<String, Vec<&'a VaultItem>>>,
    matched_target_ids: &BTreeSet<String>,
) -> FingerprintMatch<'a> {
    let Some(targets) = target_fingerprints
        .and_then(|targets| targets.get(&restore_item_fingerprint(archive_item)))
    else {
        return FingerprintMatch::None;
    };
    let available_targets = targets
        .iter()
        .copied()
        .filter(|target| !matched_target_ids.contains(&target.id))
        .filter(|target| attachments_equivalent(archive_item, target))
        .collect::<Vec<_>>();
    match available_targets.as_slice() {
        [target] => FingerprintMatch::Unique(target),
        [] => FingerprintMatch::None,
        _ => FingerprintMatch::Ambiguous,
    }
}

/// Content fingerprint for restore change detection and fingerprint
/// matching: the normalized thin model plus the normalized raw payload
/// residual, so data that only lives in the raw payload (card numbers,
/// identity fields, SSH keys, passkeys, URI match types) is compared too.
/// Attachments are left out; they are compared separately (see
/// [`items_match`] and [`attachments_equivalent`]), by rules that depend on
/// both sides.
fn restore_item_fingerprint(item: &VaultItem) -> String {
    let mut canonical = item.clone();
    canonical.id.clear();
    canonical.folder_id = None;
    canonical.backend_metadata.clear();
    canonical.fields.retain(|field| {
        !matches!(
            field.name.as_str(),
            YABBT_SOURCE_ITEM_ID_FIELD
                | YABBT_SOURCE_FINGERPRINT_FIELD
                | YABBT_ARCHIVE_VERSION_FIELD
        )
    });
    canonical.fields.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.value.cmp(&right.value))
            .then_with(|| left.hidden.cmp(&right.hidden))
    });
    canonical.attachments.clear();

    let raw = restore_raw_residual(item);
    let json =
        serde_json::to_vec(&(&canonical, &raw)).expect("vault item serialization is infallible");
    stable_fingerprint(&json)
}

/// Top-level raw keys that are target-assigned, Bitwarden-maintained, or
/// handled elsewhere in the plan, and so must not influence change
/// detection.
///
/// `passwordHistory` is deliberately excluded: Bitwarden appends to it
/// whenever an item's password is edited (including by yabbt's own
/// `--update-existing` edits), so a target's history legitimately diverges
/// from the archive and including it would mark items as changed on every
/// run. The current password itself is still compared via the thin model.
const RESTORE_RAW_IGNORED_KEYS: &[&str] = &[
    // Target-assigned identity, timestamps, and placement.
    "id",
    "revisionDate",
    "creationDate",
    "deletedDate",
    "folderId",
    "organizationId",
    "collectionIds",
    // Attachments are compared via the thin model (ids/urls are per-target).
    "attachments",
    // Bitwarden-maintained history (see above).
    "passwordHistory",
    // `bw list`/`bw get` view-state and per-cipher key material.
    "object",
    "edit",
    "viewPassword",
    "organizationUseTotp",
    "permissions",
    "key",
    // Covered by the thin model, which normalizes them (field order, marker
    // fields, KeePass field types) consistently across backends.
    "type",
    "name",
    "notes",
    "favorite",
    "fields",
    // Carries only `type: 0` (generic note); the item type is in the model.
    "secureNote",
];

/// Login keys covered by the thin model or maintained by Bitwarden.
const RESTORE_RAW_IGNORED_LOGIN_KEYS: &[&str] =
    &["username", "password", "totp", "passwordRevisionDate"];

/// The part of an item's raw backend payload (`bitwarden.raw`) that the thin
/// [`VaultItem`] model does not represent: card and identity data, SSH keys,
/// passkeys, URI match types, reprompt, and any future Bitwarden fields.
/// Volatile/target-assigned keys are stripped and "empty" values (null, "",
/// [], {}) are dropped so backends that spell absence differently compare
/// equal. Items without a raw payload compare as an empty residual.
fn restore_raw_residual(item: &VaultItem) -> Value {
    let raw = item
        .backend_metadata
        .iter()
        .find_map(|(key, value)| (key == "bitwarden.raw").then_some(value))
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok());
    let Some(Value::Object(mut object)) = raw else {
        return Value::Object(Map::new());
    };
    for key in RESTORE_RAW_IGNORED_KEYS {
        object.remove(*key);
    }
    if object.get("reprompt").and_then(Value::as_u64) == Some(0) {
        object.remove("reprompt");
    }
    if let Some(Value::Object(login)) = object.get_mut("login") {
        for key in RESTORE_RAW_IGNORED_LOGIN_KEYS {
            login.remove(*key);
        }
        if let Some(Value::Array(uris)) = login.get_mut("uris") {
            for uri in uris.iter_mut() {
                if let Value::Object(uri) = uri {
                    // The URI string is in the thin model; keep `match`.
                    uri.remove("uri");
                    uri.remove("uriChecksum");
                }
            }
        }
    }
    let mut residual = Value::Object(object);
    prune_empty_json(&mut residual);
    residual
}

/// Recursively drop object members whose value is null, "", or an object or
/// array that is empty (or contains only empty values) after pruning.
fn prune_empty_json(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for child in object.values_mut() {
                prune_empty_json(child);
            }
            object.retain(|_, child| !is_empty_json(child));
        }
        Value::Array(array) => {
            for child in array.iter_mut() {
                prune_empty_json(child);
            }
            if array.iter().all(is_empty_json) {
                array.clear();
            }
        }
        _ => {}
    }
}

fn is_empty_json(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(text) => text.is_empty(),
        Value::Array(array) => array.is_empty(),
        Value::Object(object) => object.is_empty(),
        Value::Bool(_) | Value::Number(_) => false,
    }
}

fn map_target_item<'a>(
    source_item_id: &str,
    restore_map: &Option<RestoreMap>,
    target_items: &'a BTreeMap<String, &'a VaultItem>,
) -> Option<&'a VaultItem> {
    let entry = restore_map.as_ref()?.entries.get(source_item_id)?;
    target_items.get(&entry.target_item_id).copied()
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct BitwardenItemScope {
    organization_scoped: bool,
    collection_scoped: bool,
    organization_id: Option<Option<String>>,
}

fn bitwarden_item_scope(item: &VaultItem) -> BitwardenItemScope {
    let Some(raw) = item
        .backend_metadata
        .iter()
        .find_map(|(key, value)| (key == "bitwarden.raw").then_some(value))
    else {
        return BitwardenItemScope::default();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return BitwardenItemScope::default();
    };

    let organization_scoped = value
        .get("organizationId")
        .is_some_and(|organization_id| !organization_id.is_null());
    let organization_id = value.get("organizationId").map(|organization_id| {
        organization_id
            .as_str()
            .map(str::to_string)
            .filter(|organization_id| !organization_id.is_empty())
    });
    let collection_scoped =
        value
            .get("collectionIds")
            .is_some_and(|collection_ids| match collection_ids.as_array() {
                Some(collection_ids) => !collection_ids.is_empty(),
                None => !collection_ids.is_null(),
            });

    BitwardenItemScope {
        organization_scoped,
        collection_scoped,
        organization_id,
    }
}

fn marker_field(item: &VaultItem, name: &str) -> Option<String> {
    item.fields
        .iter()
        .find(|field| field.hidden && field.name == name)
        .map(|field| field.value.clone())
}

//! KeePass (.kdbx) backend. The adapter holds a KDBX4 database in memory
//! and renders it to Bitwarden-wire JSON parsed through `normalize_export`,
//! so planning, fingerprints, and the restore map work identically to the
//! `bw` backend. Writes always persist the full item payload in a protected
//! `yabbt.bitwarden_raw` custom field, which makes write -> render a
//! faithful round trip.
//!
//! Target mutations only change the in-memory database; [`VaultTargetOps::commit`]
//! writes the file once (save to a temp file, re-read and verify, atomic
//! rename). A failed commit leaves the file untouched and discards the
//! unsaved changes.

use super::bitwarden_json::normalize_export;
use super::{AdapterError, BackendCapabilities, VaultExport, VaultSource};
use crate::archive::ArchiveAttachment;
use crate::diff::stable_fingerprint;
use crate::model::Vault;
use crate::progress::{NoopProgress, ProgressReporter};
use crate::restore_apply::{AttachmentUpload, UploadedAttachment, VaultTargetOps, VisibleItem};
use keepass::DatabaseKey;
use keepass::config::{DatabaseConfig, KdfConfig};
use keepass::db::{
    AttachmentId, AttachmentRef, Database, Entry, EntryId, EntryMut, EntryRef, GroupId, History,
    Value as KdbxValue,
};
use secrecy::zeroize::Zeroizing;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use uuid::Uuid;

/// Custom field holding the full Bitwarden-wire payload of an entry.
pub const KEEPASS_RAW_FIELD: &str = "yabbt.bitwarden_raw";
/// Entry tag marking a favorite item.
pub const KEEPASS_FAVORITE_TAG: &str = "favorite";
const RECYCLE_BIN_GROUP_NAME: &str = "Recycle Bin";
/// Standard kdbx field names owned by the entry itself, not custom fields.
const RESERVED_FIELDS: &[&str] = &["Title", "UserName", "Password", "URL", "Notes", "otp"];
/// Folder names use "/" to nest; a "/" inside a KeePass group name is shown
/// as this look-alike (U+2215 DIVISION SLASH) so a group named "a/b" stays
/// distinct from a group "b" nested in "a". Creating a folder maps it back.
const GROUP_NAME_SLASH: char = '\u{2215}';

#[derive(Debug, Clone)]
pub struct KeepassVaultOptions {
    pub path: PathBuf,
    pub passphrase: String,
    /// Target usage only: when the file is missing, start from an empty
    /// KDBX4 database in memory and materialize it on the first save, so a
    /// dry run never touches disk.
    pub create_if_missing: bool,
}

pub struct KeepassVault {
    path: PathBuf,
    /// Held for the whole run; zeroized on drop so the master passphrase does
    /// not linger in freed heap (e.g. after a core dump or swap-out).
    passphrase: Zeroizing<String>,
    state: Mutex<KeepassState>,
}

impl std::fmt::Debug for KeepassVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeepassVault")
            .field("path", &self.path)
            .field("passphrase", &"<redacted>")
            .finish_non_exhaustive()
    }
}

struct KeepassState {
    db: Database,
    /// False until the auto-created database is first saved.
    file_exists: bool,
    /// One `.bak` copy per process run, before the first write.
    bak_written: bool,
    saves_written: usize,
    /// The in-memory database has changes not yet written to the file.
    dirty: bool,
    /// SHA-256 of the file as last read or written; `sync` skips reloading
    /// a file that has not changed since.
    file_digest: Option<String>,
    /// Set when the in-memory database can no longer be trusted (a mutation
    /// failed half-way and the file could not be re-read): every further
    /// mutation and save is refused.
    poisoned: Option<String>,
}

// The decrypted `Database` holds every secret in the vault; never include it
// in debug output.
impl std::fmt::Debug for KeepassState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeepassState")
            .field("db", &"<redacted>")
            .field("file_exists", &self.file_exists)
            .field("bak_written", &self.bak_written)
            .field("saves_written", &self.saves_written)
            .field("dirty", &self.dirty)
            .field("poisoned", &self.poisoned.is_some())
            .finish_non_exhaustive()
    }
}

impl KeepassVault {
    pub fn open(options: KeepassVaultOptions) -> Result<Self, AdapterError> {
        let KeepassVaultOptions {
            path,
            passphrase,
            create_if_missing,
        } = options;
        let (db, file_exists, file_digest) = if path.exists() {
            let bytes = std::fs::read(&path)?;
            let db = open_database(&bytes, &passphrase, "failed to open keepass database")?;
            (db, true, Some(stable_fingerprint(&bytes)))
        } else if create_if_missing {
            (Database::with_config(new_database_config()), false, None)
        } else {
            return Err(AdapterError::new(format!(
                "keepass database `{}` does not exist",
                path.display()
            )));
        };
        Ok(Self {
            path,
            passphrase: Zeroizing::new(passphrase),
            state: Mutex::new(KeepassState {
                db,
                file_exists,
                bak_written: false,
                saves_written: 0,
                dirty: false,
                file_digest,
                poisoned: None,
            }),
        })
    }

    /// How many times this adapter has written the database file.
    pub fn saves_written(&self) -> usize {
        self.lock().saves_written
    }

    fn lock(&self) -> MutexGuard<'_, KeepassState> {
        self.state.lock().expect("keepass state lock")
    }

    /// The state, for a mutation; refused once the database is poisoned.
    fn lock_for_mutation(&self) -> Result<MutexGuard<'_, KeepassState>, AdapterError> {
        let state = self.lock();
        if let Some(reason) = &state.poisoned {
            return Err(AdapterError::new(format!(
                "refusing to modify keepass database: {reason}"
            )));
        }
        Ok(state)
    }

    /// Persist the in-memory database: copy the pre-run file to a new
    /// `<file>.<UTC timestamp>.bak` once per run (never overwriting an
    /// earlier copy), then write to a sibling temp file, re-read and verify
    /// it, and atomically rename it over the database.
    fn save_locked(&self, state: &mut KeepassState) -> Result<(), AdapterError> {
        let existing = self.unchanged_on_disk(state)?;
        if state.file_exists && !state.bak_written {
            // Copy via an owner-only, create-new destination: the `.bak` holds
            // the full encrypted database, and a predictable sibling name in a
            // shared directory must not follow a pre-planted symlink.
            let existing = existing.unwrap_or_default();
            let (bak, mut file) = create_backup_file(&self.path)?;
            std::io::Write::write_all(&mut file, &existing)?;
            file.sync_all()?;
            eprintln!(
                "notice: copied {} to {} before first write",
                self.path.display(),
                bak.display()
            );
            state.bak_written = true;
        }

        let mut temp = self.path.clone().into_os_string();
        temp.push(".tmp-yabbt");
        let temp = PathBuf::from(temp);
        let written = (|| {
            // create_new defeats symlink redirection on the predictable temp
            // name; mode 0600 stops the atomic rename from downgrading a
            // hardened database to world-readable.
            let mut file = open_new_private(&temp)?;
            state
                .db
                .save(&mut file, database_key(&self.passphrase))
                .map_err(|error| {
                    AdapterError::new(format!("failed to save keepass database: {error}"))
                })?;
            file.sync_all()?;
            drop(file);
            let bytes = std::fs::read(&temp)?;
            self.verify_written_attachments(&bytes, &state.db)?;
            std::fs::rename(&temp, &self.path)?;
            Ok::<_, AdapterError>(stable_fingerprint(&bytes))
        })();
        let digest = match written {
            Ok(digest) => digest,
            Err(error) => {
                // Never rename a file that failed to write or verify; the
                // original database stays untouched.
                let _ = std::fs::remove_file(&temp);
                return Err(error);
            }
        };
        state.saves_written += 1;
        state.file_digest = Some(digest);

        if !state.file_exists {
            eprintln!(
                "notice: created new keepass database {}",
                self.path.display()
            );
            state.file_exists = true;
            // The file now contains only yabbt's own writes; nothing older
            // is left to back up this run.
            state.bak_written = true;
        }
        Ok(())
    }

    /// Refuse to save over a file another program changed since this adapter
    /// last read or wrote it (e.g. a KeePassXC save during the run): the
    /// write would silently drop that program's changes. Returns the current
    /// file bytes (`None` when yabbt is about to create the file).
    ///
    /// The check runs right before the write; a save racing the few
    /// milliseconds between it and the rename is not detected.
    fn unchanged_on_disk(&self, state: &KeepassState) -> Result<Option<Vec<u8>>, AdapterError> {
        let modified = || {
            AdapterError::new(format!(
                "refusing to save keepass database `{}`: it was modified by another program \
                 since yabbt read it; re-run to apply the changes on top of the current file",
                self.path.display()
            ))
        };
        if !state.file_exists {
            return match std::fs::symlink_metadata(&self.path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error.into()),
                Ok(_) => Err(modified()),
            };
        }
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(modified()),
            Err(error) => return Err(error.into()),
        };
        if state.file_digest.as_deref() != Some(stable_fingerprint(&bytes).as_str()) {
            return Err(modified());
        }
        Ok(Some(bytes))
    }

    /// Drop every unsaved change: re-read the file (or start empty again if
    /// it was never written). If the file cannot be re-read the in-memory
    /// database is poisoned.
    fn discard_pending(&self, state: &mut KeepassState) {
        state.dirty = false;
        if !state.file_exists {
            state.db = Database::with_config(new_database_config());
            state.poisoned = None;
            return;
        }
        let reloaded = std::fs::read(&self.path)
            .map_err(AdapterError::from)
            .and_then(|bytes| {
                let db = open_database(&bytes, &self.passphrase, "failed to re-read")?;
                Ok((db, stable_fingerprint(&bytes)))
            });
        match reloaded {
            Ok((db, digest)) => {
                state.db = db;
                state.file_digest = Some(digest);
                state.poisoned = None;
            }
            Err(error) => {
                state.poisoned = Some(format!("unsaved changes could not be discarded ({error})"));
            }
        }
    }

    /// Safety net against writer bugs: re-open the freshly written temp file
    /// and require every entry's attachments (current and history versions,
    /// as name + SHA-256) to match the in-memory database.
    fn verify_written_attachments(&self, bytes: &[u8], db: &Database) -> Result<(), AdapterError> {
        let written = open_database(
            bytes,
            &self.passphrase,
            "failed to re-read written keepass database",
        )?;
        let expected = attachment_digest(db);
        let actual = attachment_digest(&written);
        if expected == actual {
            return Ok(());
        }
        let entry = expected
            .iter()
            .find(|(key, value)| actual.get(*key) != Some(*value))
            .map(|(key, _)| key)
            .or_else(|| actual.keys().find(|key| !expected.contains_key(*key)))
            .map(|(uuid, _)| uuid.to_string())
            .unwrap_or_default();
        Err(AdapterError::new(format!(
            "refusing to save keepass database: attachments read back from the written file \
             do not match the in-memory state (entry `{entry}`); `{}` was left untouched",
            self.path.display()
        )))
    }

    /// Render the current database state as a canonical [`Vault`], parsed
    /// through the same `normalize_export` path as real `bw` output.
    pub fn scan_vault(&self) -> Result<Vault, AdapterError> {
        render_vault(&self.lock().db)
    }

    pub fn export_with_progress(
        &self,
        progress: &dyn ProgressReporter,
    ) -> Result<VaultExport, AdapterError> {
        progress.step_start("read keepass database");
        let state = self.lock();
        let vault = render_vault(&state.db)?;
        let mut attachments = Vec::new();
        for item in &vault.items {
            let Some(entry) = entry_by_id(&state.db, &item.id) else {
                continue;
            };
            for attachment_ref in &item.attachments {
                let Some((_, attachment)) = attachment_by_id(&entry, &attachment_ref.id) else {
                    continue;
                };
                attachments.push(ArchiveAttachment {
                    path: attachment_ref.path.clone(),
                    bytes: attachment.data.get().clone(),
                });
            }
        }
        progress.step_finish("read keepass database");
        Ok(VaultExport { vault, attachments })
    }
}

fn open_database(bytes: &[u8], passphrase: &str, context: &str) -> Result<Database, AdapterError> {
    let mut reader = bytes;
    Database::open(&mut reader, database_key(passphrase))
        .map_err(|error| AdapterError::new(format!("{context}: {error}")))
}

impl VaultSource for KeepassVault {
    fn name(&self) -> &str {
        "keepass"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            read_items: true,
            write_items: true,
            read_attachments: true,
            write_attachments: true,
            organizations: false,
            sends: false,
            passkeys: false,
            ssh_keys: true,
            strict_restore: true,
        }
    }

    fn export(&self) -> Result<VaultExport, AdapterError> {
        self.export_with_progress(&NoopProgress)
    }
}

impl super::BackupSource for KeepassVault {
    fn backend_name(&self) -> &'static str {
        "keepass"
    }

    fn export_with_progress(
        &self,
        progress: &dyn ProgressReporter,
    ) -> Result<VaultExport, AdapterError> {
        KeepassVault::export_with_progress(self, progress)
    }
}

impl crate::restore_apply::RestoreTarget for KeepassVault {
    fn backend_name(&self) -> &'static str {
        "keepass"
    }

    fn scan(&self, progress: &dyn ProgressReporter) -> Result<Vault, AdapterError> {
        progress.step_start("read keepass database");
        let vault = self.scan_vault()?;
        progress.step_finish("read keepass database");
        Ok(vault)
    }
}

impl VaultTargetOps for KeepassVault {
    fn create_folder(&self, payload: &Value) -> Result<String, AdapterError> {
        let name = payload
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| AdapterError::new("folder payload missing name"))?
            .to_string();
        let mut state = self.lock_for_mutation()?;
        // Bitwarden names nested folders "Parent/Child"; materialize them as
        // nested groups, reusing groups already on the path (e.g. a parent
        // created implicitly for an earlier child in this run).
        let trashed = recycle_bin_group_ids(&state.db);
        let mut group_id = state.db.root().id();
        for segment in name.split('/') {
            let group_name = segment.replace(GROUP_NAME_SLASH, "/");
            let existing = state.db.group(group_id).and_then(|group| {
                group
                    .groups()
                    .find(|child| child.name == group_name && !trashed.contains(&child.id()))
                    .map(|child| child.id())
            });
            group_id = match existing {
                Some(child_id) => child_id,
                None => {
                    state.dirty = true;
                    let mut parent = state
                        .db
                        .group_mut(group_id)
                        .ok_or_else(|| AdapterError::new("parent group not found"))?;
                    let mut child = parent.add_group();
                    child.name = group_name;
                    child.as_ref().id()
                }
            };
        }
        Ok(group_id.uuid().to_string())
    }

    fn create_item(&self, payload: &Value) -> Result<String, AdapterError> {
        let mut state = self.lock_for_mutation()?;
        let group_id = target_group_id(&state.db, payload)?;
        state.dirty = true;
        let mut group = state
            .db
            .group_mut(group_id)
            .ok_or_else(|| AdapterError::new("target folder not found"))?;
        let mut entry = group.add_entry();
        apply_payload(&mut entry, payload);
        Ok(entry.as_ref().id().uuid().to_string())
    }

    fn edit_item(&self, item_id: &str, payload: &Value) -> Result<(), AdapterError> {
        let mut state = self.lock_for_mutation()?;
        let entry_id = parse_entry_id(item_id)?;
        let group_id = target_group_id(&state.db, payload)?;
        let (before, parent_id) = {
            let entry = state
                .db
                .entry(entry_id)
                .ok_or_else(|| AdapterError::new(format!("entry `{item_id}` not found")))?;
            ((*entry).clone(), entry.parent().id())
        };
        let mut entry = state
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| AdapterError::new(format!("entry `{item_id}` not found")))?;
        apply_payload(&mut entry, payload);
        // An edit to what the entry already holds is not a change: the
        // database stays clean, so a no-op run never rewrites the file.
        let changed = *entry != before;
        // Only move when the group differs; `move_to` would otherwise still
        // reorder the group and record a "previous group".
        let moved = if parent_id == group_id {
            Ok(false)
        } else {
            entry
                .move_to(group_id)
                .map(|()| true)
                .map_err(|error| AdapterError::new(error.to_string()))
        };
        if changed || moved.as_ref().is_ok_and(|moved| *moved) {
            state.dirty = true;
        }
        moved.map(|_| ())
    }

    fn upload_attachments(
        &self,
        jobs: &[AttachmentUpload],
        progress: &dyn ProgressReporter,
        total: u64,
    ) -> Result<Vec<UploadedAttachment>, AdapterError> {
        if jobs.is_empty() {
            return Ok(Vec::new());
        }
        let mut state = self.lock_for_mutation()?;
        let mut uploaded = Vec::with_capacity(jobs.len());
        for (index, job) in jobs.iter().enumerate() {
            let entry_id = parse_entry_id(&job.target_item_id)?;
            let mut entry = state.db.entry_mut(entry_id).ok_or_else(|| {
                AdapterError::new(format!(
                    "attachment target entry `{}` not found",
                    job.target_item_id
                ))
            })?;
            // kdbx keys attachments by name and the crate replaces on a
            // collision; never overwrite an existing attachment (a duplicate
            // name in the archive or a user's file), store it as "x (2).ext".
            let file_name = unused_attachment_name(&entry.as_ref(), &job.file_name);
            entry.add_attachment(&file_name, KdbxValue::protected(job.bytes.clone()));
            state.dirty = true;
            uploaded.push(UploadedAttachment {
                target_item_id: job.target_item_id.clone(),
                file_name,
                size: job.size,
                sha256: job.sha256.clone(),
            });
            progress.counted("uploading attachments", (index + 1) as u64, total);
        }
        Ok(uploaded)
    }

    fn delete_attachment(&self, item_id: &str, attachment_id: &str) -> Result<(), AdapterError> {
        let mut state = self.lock_for_mutation()?;
        let entry_id = parse_entry_id(item_id)?;
        let entry = state
            .db
            .entry(entry_id)
            .ok_or_else(|| AdapterError::new(format!("entry `{item_id}` not found")))?;
        let name = attachment_by_id(&entry, attachment_id)
            .map(|(name, _)| name.to_string())
            .ok_or_else(|| {
                AdapterError::new(format!(
                    "attachment `{attachment_id}` not found on entry `{item_id}`"
                ))
            })?;
        remove_from_pool(
            &mut state,
            PoolRemoval::Attachment {
                entry: entry_id,
                name,
            },
        )
    }

    fn delete_item(&self, item_id: &str, permanent: bool) -> Result<(), AdapterError> {
        let mut state = self.lock_for_mutation()?;
        let entry_id = parse_entry_id(item_id)?;
        if state.db.entry(entry_id).is_none() {
            return Err(AdapterError::new(format!("entry `{item_id}` not found")));
        }
        if permanent {
            return remove_from_pool(&mut state, PoolRemoval::Entry(entry_id));
        }
        state.dirty = true;
        let bin_id = ensure_recycle_bin(&mut state.db);
        let mut entry = state
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| AdapterError::new(format!("entry `{item_id}` not found")))?;
        entry
            .move_to(bin_id)
            .map_err(|error| AdapterError::new(error.to_string()))
    }

    fn delete_folder(&self, folder_id: &str) -> Result<(), AdapterError> {
        let mut state = self.lock_for_mutation()?;
        let group_id = parse_group_id(folder_id)?;
        if group_id == state.db.root().id() || recycle_bin_group_ids(&state.db).contains(&group_id)
        {
            return Err(AdapterError::new(format!(
                "refusing to delete keepass group `{folder_id}`: it is the root or recycle bin"
            )));
        }
        let group = state
            .db
            .group(group_id)
            .ok_or_else(|| AdapterError::new(format!("folder `{folder_id}` not found")))?;
        // The crate's group removal is recursive and bypasses the recycle
        // bin, so only ever remove a group that is already empty.
        if group.entry_ids().next().is_some() || group.group_ids().next().is_some() {
            return Err(AdapterError::new(format!(
                "refusing to delete keepass group `{}` ({folder_id}): it still contains entries \
                 or subgroups",
                group.name
            )));
        }
        state.dirty = true;
        state
            .db
            .group_mut(group_id)
            .ok_or_else(|| AdapterError::new(format!("folder `{folder_id}` not found")))?
            .remove();
        Ok(())
    }

    fn sync(&self) -> Result<(), AdapterError> {
        let mut state = self.lock();
        if state.dirty {
            return Err(AdapterError::new(
                "keepass database has unsaved changes; commit them before reloading",
            ));
        }
        if !state.file_exists {
            return Ok(());
        }
        let bytes = std::fs::read(&self.path)?;
        let digest = stable_fingerprint(&bytes);
        // The file is exactly what this adapter last read or wrote (and
        // verified): nothing to reload, and no key derivation to pay for.
        if state.file_digest.as_deref() == Some(digest.as_str()) {
            return Ok(());
        }
        state.db = open_database(
            &bytes,
            &self.passphrase,
            "failed to reload keepass database",
        )?;
        state.file_digest = Some(digest);
        state.poisoned = None;
        Ok(())
    }

    fn get_item(&self, item_id: &str) -> Result<String, AdapterError> {
        let state = self.lock();
        let entry = entry_by_id(&state.db, item_id)
            .ok_or_else(|| AdapterError::new(format!("entry `{item_id}` not found")))?;
        let parent_id = entry.parent().id();
        if recycle_bin_group_ids(&state.db).contains(&parent_id) {
            return Err(AdapterError::new(format!("entry `{item_id}` not found")));
        }
        let mut rendered = render_entry(&entry, parent_id, state.db.root().id());
        rendered["attachments"] = rendered_attachments(&entry);
        Ok(rendered.to_string())
    }

    fn download_attachment(
        &self,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<Vec<u8>, AdapterError> {
        let state = self.lock();
        let entry = entry_by_id(&state.db, item_id)
            .ok_or_else(|| AdapterError::new(format!("entry `{item_id}` not found")))?;
        attachment_by_id(&entry, attachment_id)
            .map(|(_, attachment)| attachment.data.get().clone())
            .ok_or_else(|| {
                AdapterError::new(format!(
                    "attachment `{attachment_id}` not found on entry `{item_id}`"
                ))
            })
    }

    fn list_visible_items(&self) -> Result<Vec<VisibleItem>, AdapterError> {
        let state = self.lock();
        let recycle_bins = recycle_bin_group_ids(&state.db);
        Ok(state
            .db
            .iter_all_entries()
            .filter(|entry| !recycle_bins.contains(&entry.parent().id()))
            .map(|entry| {
                let uuid = entry.id().uuid();
                VisibleItem {
                    id: uuid.to_string(),
                    attachment_ids: entry
                        .attachments_named()
                        .map(|(name, _)| keepass_attachment_id(uuid, name))
                        .collect(),
                }
            })
            .collect())
    }

    fn list_folder_ids(&self) -> Result<Vec<String>, AdapterError> {
        let state = self.lock();
        Ok(folder_paths(&state.db)
            .into_iter()
            .map(|(group_id, _)| group_id.uuid().to_string())
            .collect())
    }

    fn batches_writes(&self) -> bool {
        true
    }

    fn discard(&self) {
        let mut state = self.lock();
        self.discard_pending(&mut state);
    }

    /// Write every pending mutation in one save. On failure the file is left
    /// untouched and the unsaved changes are discarded from memory, so a
    /// later commit cannot persist them by accident.
    fn commit(&self) -> Result<(), AdapterError> {
        let mut state = self.lock();
        if let Some(reason) = state.poisoned.clone() {
            self.discard_pending(&mut state);
            return Err(AdapterError::new(format!(
                "refusing to save keepass database: {reason}; nothing was written to `{}`",
                self.path.display()
            )));
        }
        if !state.dirty {
            return Ok(());
        }
        match self.save_locked(&mut state) {
            Ok(()) => {
                state.dirty = false;
                Ok(())
            }
            Err(error) => {
                self.discard_pending(&mut state);
                Err(AdapterError::new(format!(
                    "{error}; nothing was written to `{}`, and the unsaved changes were discarded",
                    self.path.display()
                )))
            }
        }
    }
}

/// Stable id of an entry's attachment, independent of the binary-pool slot
/// it occupies (pool slots are renumbered by every removal). Attachment
/// names are unique per entry, so (entry uuid, name) identifies it.
pub fn keepass_attachment_id(entry: Uuid, name: &str) -> String {
    let digest = stable_fingerprint(format!("{entry}\0{name}").as_bytes());
    format!("kdbx-{}", &digest[..32])
}

/// The attachment of `entry` whose stable id is `attachment_id`.
fn attachment_by_id<'a>(
    entry: &'a EntryRef<'_>,
    attachment_id: &str,
) -> Option<(&'a str, AttachmentRef<'a>)> {
    let uuid = entry.id().uuid();
    entry
        .attachments_named()
        .find(|(name, _)| keepass_attachment_id(uuid, name) == attachment_id)
}

fn parse_entry_id(item_id: &str) -> Result<EntryId, AdapterError> {
    Uuid::parse_str(item_id)
        .map(EntryId::from_uuid)
        .map_err(|_| AdapterError::new(format!("`{item_id}` is not a valid keepass entry id")))
}

fn parse_group_id(folder_id: &str) -> Result<GroupId, AdapterError> {
    Uuid::parse_str(folder_id)
        .map(GroupId::from_uuid)
        .map_err(|_| AdapterError::new(format!("`{folder_id}` is not a valid keepass group id")))
}

/// Resolve the group an item payload belongs in: its `folderId` group, or
/// the root group when null/absent.
fn target_group_id(db: &Database, payload: &Value) -> Result<GroupId, AdapterError> {
    match payload.get("folderId").and_then(Value::as_str) {
        Some(folder_id) => {
            let group_id = parse_group_id(folder_id)?;
            db.group(group_id)
                .map(|group| group.id())
                .ok_or_else(|| AdapterError::new(format!("target folder `{folder_id}` not found")))
        }
        None => Ok(db.root().id()),
    }
}

/// Write a Bitwarden-wire item payload onto a kdbx entry. The verbatim
/// payload lands in the protected `yabbt.bitwarden_raw` field, standard
/// values map to kdbx fields, and uniquely-named custom fields become kdbx
/// custom fields (duplicates stay raw-only).
fn apply_payload(entry: &mut EntryMut<'_>, payload: &Value) {
    entry.fields.clear();
    entry.tags.retain(|tag| tag != KEEPASS_FAVORITE_TAG);

    entry.set_protected(KEEPASS_RAW_FIELD, payload.to_string());
    if let Some(name) = payload.get("name").and_then(Value::as_str) {
        entry.set_unprotected("Title", name);
    }
    if let Some(notes) = payload.get("notes").and_then(Value::as_str)
        && !notes.is_empty()
    {
        entry.set_unprotected("Notes", notes);
    }
    if payload.get("favorite").and_then(Value::as_bool) == Some(true) {
        entry.tags.push(KEEPASS_FAVORITE_TAG.to_string());
    }

    if payload.get("type").and_then(Value::as_u64) == Some(1)
        && let Some(login) = payload.get("login")
    {
        if let Some(username) = login.get("username").and_then(Value::as_str) {
            entry.set_unprotected("UserName", username);
        }
        if let Some(password) = login.get("password").and_then(Value::as_str) {
            entry.set_protected("Password", password);
        }
        if let Some(totp) = login.get("totp").and_then(Value::as_str) {
            entry.set_protected("otp", totp);
        }
        if let Some(url) = login
            .get("uris")
            .and_then(Value::as_array)
            .and_then(|uris| uris.first())
            .and_then(|uri| uri.get("uri"))
            .and_then(Value::as_str)
        {
            entry.set_unprotected("URL", url);
        }
    }

    let fields = payload
        .get("fields")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut name_counts = std::collections::BTreeMap::new();
    for field in &fields {
        if let Some(name) = field.get("name").and_then(Value::as_str) {
            *name_counts.entry(name.to_string()).or_insert(0usize) += 1;
        }
    }
    let mut written = BTreeSet::new();
    for field in &fields {
        let Some(name) = field.get("name").and_then(Value::as_str) else {
            continue;
        };
        let is_reserved = RESERVED_FIELDS.contains(&name) || name == KEEPASS_RAW_FIELD;
        if is_reserved || name_counts[name] > 1 || !written.insert(name.to_string()) {
            continue;
        }
        let value = field
            .get("value")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if field.get("type").and_then(Value::as_u64) == Some(1) {
            entry.set_protected(name, value);
        } else {
            entry.set_unprotected(name, value);
        }
    }
}

/// `file_name` if the entry has no attachment by that name, else the first
/// free "stem (n).ext" for n >= 2.
fn unused_attachment_name(entry: &EntryRef<'_>, file_name: &str) -> String {
    let taken = entry
        .attachments_named()
        .map(|(name, _)| name.to_string())
        .collect::<BTreeSet<_>>();
    if !taken.contains(file_name) {
        return file_name.to_string();
    }
    let (stem, extension) = match file_name.rfind('.') {
        Some(dot) if dot > 0 => file_name.split_at(dot),
        _ => (file_name, ""),
    };
    (2u64..)
        .map(|counter| format!("{stem} ({counter}){extension}"))
        .find(|candidate| !taken.contains(candidate))
        .expect("an unused attachment name exists")
}

/// A mutation that drops binaries from the kdbx attachment pool.
enum PoolRemoval {
    /// Remove one named attachment from an entry's current version.
    Attachment { entry: EntryId, name: String },
    /// Permanently remove an entry (with its history).
    Entry(EntryId),
}

/// Apply `removal` to the in-memory database, keeping the kdbx binary pool
/// dense and every surviving reference on its original bytes. Refusals
/// leave the database untouched; a failure half-way poisons it.
fn remove_from_pool(state: &mut KeepassState, removal: PoolRemoval) -> Result<(), AdapterError> {
    let layout = plan_pool_removal(&state.db, &removal)?;
    state.dirty = true;
    if let Err(error) = execute_pool_removal(&mut state.db, removal, layout) {
        state.poisoned = Some(format!("an attachment removal failed half-way ({error})"));
        return Err(error);
    }
    Ok(())
}

/// One current-version attachment reference.
#[derive(Debug, Clone)]
struct CurrentRef {
    entry: EntryId,
    name: String,
    slot: usize,
}

/// How a removal re-lays out the binary pool.
#[derive(Debug)]
struct PoolLayout {
    /// Nothing but the removal itself is needed: it only drops the highest
    /// slots, and nothing else references them.
    trivial: bool,
    /// Slots referenced from entry history; they keep their ids and bytes.
    pinned: BTreeSet<usize>,
    /// Pinned slots the removal drops, re-created at the same id through a
    /// current reference to the same binary.
    recreate: BTreeMap<usize, CurrentRef>,
    /// Current references re-added, in this order, into the free ids.
    movable: Vec<CurrentRef>,
    /// Final pool size.
    total: usize,
    /// History versions (entry, index) rebuilt from their entry's current
    /// version, because their attachments equal it and keeping their old
    /// slot ids would make the pool impossible to keep dense.
    rebuild: BTreeMap<Uuid, BTreeSet<usize>>,
}

/// One entry history version's attachment references.
struct HistoryVersion {
    entry: EntryId,
    index: usize,
    slots: Vec<usize>,
    /// Same attachments (names and bytes), icon and previous group as its
    /// entry's current version, so it can be rebuilt from it.
    rebuildable: bool,
}

/// Decide, without touching `db`, how to apply `removal` so the pool stays
/// dense.
///
/// Up to keepass 0.15.4 the KDBX4 writer emitted the binary pool sorted and
/// compacted but wrote each reference's original pool id, so any gap
/// shifted every later reference onto the wrong binary (0.15.5 renumbers
/// on save; keeping the pool dense here stays harmless). Its removal helpers
/// also drop a binary as soon as one reference goes, even when other
/// entries or history versions share it (back-references are not rebuilt
/// on load). The crate can only re-add a binary through a current
/// reference, and history references cannot be rewritten in place. So:
/// current references are detached and re-added into the free ids, binaries
/// referenced from history keep their ids, and a history version whose
/// attachments equal its entry's current ones may be rebuilt from the
/// current version when its old ids would leave an unfillable gap. A
/// removal that would still lose a history-only binary or leave a gap is
/// refused.
fn plan_pool_removal(db: &Database, removal: &PoolRemoval) -> Result<PoolLayout, AdapterError> {
    let (removed_entry, removed_name) = match removal {
        PoolRemoval::Attachment { entry, name } => (*entry, Some(name.as_str())),
        PoolRemoval::Entry(entry) => (*entry, None),
    };
    let entry = db
        .entry(removed_entry)
        .ok_or_else(|| AdapterError::new("entry not found"))?;
    let removed_slots = match removed_name {
        Some(name) => BTreeSet::from([entry
            .attachment_by_name(name)
            .ok_or_else(|| AdapterError::new(format!("attachment `{name}` not found")))?
            .id()
            .id()]),
        None => entry
            .attachments()
            .map(|attachment| attachment.id().id())
            .collect(),
    };
    let pool = pool_slots(db);

    let mut current = Vec::new();
    let mut versions = Vec::new();
    for entry in db.iter_all_entries() {
        let entry_id = entry.id();
        if removed_name.is_none() && entry_id == removed_entry {
            continue;
        }
        let mut entry_refs = entry
            .attachments_named()
            .filter(|(name, _)| entry_id != removed_entry || Some(*name) != removed_name)
            .map(|(name, attachment)| (name.to_string(), attachment.id()))
            .collect::<Vec<_>>();
        entry_refs.sort_by(|(left, _), (right, _)| left.cmp(right));
        let distinct_slots = entry_refs
            .iter()
            .map(|(_, id)| id.id())
            .collect::<BTreeSet<_>>()
            .len()
            == entry_refs.len();
        current.extend(entry_refs.iter().map(|(name, id)| CurrentRef {
            entry: entry_id,
            name: name.clone(),
            slot: id.id(),
        }));
        let count = entry
            .history
            .as_ref()
            .map_or(0, |history| history.get_entries().len());
        for index in 0..count {
            let Some(version) = entry.historical(index) else {
                continue;
            };
            let mut version_refs = version
                .attachments_named()
                .map(|(name, attachment)| (name.to_string(), attachment.id()))
                .collect::<Vec<_>>();
            if version_refs.is_empty() {
                continue;
            }
            version_refs.sort_by(|(left, _), (right, _)| left.cmp(right));
            let rebuildable = distinct_slots
                && attachments_subset(db, &version_refs, &entry_refs)
                && version.icon() == entry.icon()
                && version.previous_parent().map(|group| group.id())
                    == entry.previous_parent().map(|group| group.id());
            versions.push(HistoryVersion {
                entry: entry_id,
                index,
                slots: version_refs.iter().map(|(_, id)| id.id()).collect(),
                rebuildable,
            });
        }
    }
    let referenced = current
        .iter()
        .map(|reference| reference.slot)
        .chain(versions.iter().flat_map(|version| version.slots.clone()))
        .collect::<BTreeSet<_>>();
    if let Some(missing) = referenced.iter().find(|slot| !pool.contains(slot)) {
        return Err(AdapterError::new(format!(
            "keepass database has a dangling attachment reference (binary {missing}); \
             refusing to change its attachments"
        )));
    }

    // Common case: the removal only drops the highest slots and nothing else
    // uses them, so the pool stays dense on its own.
    let survivors = pool.difference(&removed_slots).copied().collect::<Vec<_>>();
    if referenced.is_disjoint(&removed_slots) && survivors.iter().copied().eq(0..survivors.len()) {
        return Ok(PoolLayout {
            trivial: true,
            pinned: BTreeSet::new(),
            recreate: BTreeMap::new(),
            movable: Vec::new(),
            total: survivors.len(),
            rebuild: BTreeMap::new(),
        });
    }

    let attempt = |rebuild_eligible: bool| -> Result<PoolLayout, AdapterError> {
        let rebuilt = |version: &HistoryVersion| rebuild_eligible && version.rebuildable;
        let mut pinned_by = BTreeMap::new();
        for version in versions.iter().filter(|version| !rebuilt(version)) {
            for slot in &version.slots {
                pinned_by.entry(*slot).or_insert(version.entry);
            }
        }
        let pinned = pinned_by.keys().copied().collect::<BTreeSet<_>>();
        let mut recreate = BTreeMap::new();
        for slot in pinned.intersection(&removed_slots) {
            let Some(reference) = current.iter().find(|reference| reference.slot == *slot) else {
                return Err(history_only_error(pinned_by[slot]));
            };
            recreate.insert(*slot, reference.clone());
        }
        let mut movable = current
            .iter()
            .filter(|reference| !pinned.contains(&reference.slot))
            .cloned()
            .collect::<Vec<_>>();
        movable.sort_by(|left, right| {
            (left.slot, left.entry.uuid(), &left.name).cmp(&(
                right.slot,
                right.entry.uuid(),
                &right.name,
            ))
        });
        let total = pinned.len() + movable.len();
        if let Some(highest) = pinned.iter().next_back()
            && *highest >= total
        {
            return Err(history_gap_error(pinned_by[highest]));
        }
        let mut rebuild = BTreeMap::<Uuid, BTreeSet<usize>>::new();
        for version in versions.iter().filter(|version| rebuilt(version)) {
            rebuild
                .entry(version.entry.uuid())
                .or_default()
                .insert(version.index);
        }
        Ok(PoolLayout {
            trivial: false,
            pinned,
            recreate,
            movable,
            total,
            rebuild,
        })
    };
    match attempt(false) {
        Ok(layout) => Ok(layout),
        Err(error) if versions.iter().any(|version| version.rebuildable) => {
            attempt(true).map_err(|_| error)
        }
        Err(error) => Err(error),
    }
}

/// Every attachment of `version` is also in `current`, under the same name
/// with the same bytes.
fn attachments_subset(
    db: &Database,
    version: &[(String, AttachmentId)],
    current: &[(String, AttachmentId)],
) -> bool {
    let same_bytes = |left: AttachmentId, right: AttachmentId| {
        left == right
            || match (db.attachment(left), db.attachment(right)) {
                (Some(left), Some(right)) => left.data.get() == right.data.get(),
                _ => false,
            }
    };
    version.iter().all(|(name, id)| {
        current
            .iter()
            .any(|(current_name, current_id)| current_name == name && same_bytes(*id, *current_id))
    })
}

/// Carry out a [`PoolLayout`] computed by [`plan_pool_removal`].
fn execute_pool_removal(
    db: &mut Database,
    removal: PoolRemoval,
    layout: PoolLayout,
) -> Result<(), AdapterError> {
    let PoolLayout {
        trivial,
        pinned,
        mut recreate,
        movable,
        total,
        rebuild,
    } = layout;

    // Move (not copy) the bytes every re-added reference needs out of the
    // pool before any binary is dropped; a binary shared by several
    // re-added references is cloned for all but the last.
    let mut uses = BTreeMap::<usize, usize>::new();
    for reference in movable.iter().chain(recreate.values()) {
        *uses.entry(reference.slot).or_default() += 1;
    }
    let mut bytes = BTreeMap::new();
    db.foreach_attachment_mut(|mut attachment| {
        let slot = attachment.id().id();
        if uses.contains_key(&slot) {
            bytes.insert(
                slot,
                std::mem::replace(&mut attachment.data, KdbxValue::unprotected(Vec::new())),
            );
        }
    });
    let mut take_bytes = |slot: usize| -> Result<KdbxValue<Vec<u8>>, AdapterError> {
        let remaining = uses
            .get_mut(&slot)
            .ok_or_else(|| AdapterError::new("attachment bytes not reserved"))?;
        *remaining -= 1;
        if *remaining == 0 {
            bytes.remove(&slot)
        } else {
            bytes.get(&slot).cloned()
        }
        .ok_or_else(|| AdapterError::new("attachment bytes missing"))
    };

    match &removal {
        PoolRemoval::Attachment { entry, name } => db
            .entry_mut(*entry)
            .ok_or_else(|| AdapterError::new("entry not found"))?
            .remove_attachment_by_name(name),
        PoolRemoval::Entry(entry) => db
            .entry_mut(*entry)
            .ok_or_else(|| AdapterError::new("entry not found"))?
            .remove(),
    }
    if trivial {
        return check_pool_consistent(db);
    }

    // Detach every reference that is re-added below; this drops their
    // binaries (the crate drops a binary with its last known reference).
    for reference in movable.iter().chain(recreate.values()) {
        db.entry_mut(reference.entry)
            .ok_or_else(|| AdapterError::new("entry not found"))?
            .remove_attachment_by_name(&reference.name);
    }
    // Drop every binary nothing pins (unreferenced leftovers included).
    db.foreach_attachment_mut(|attachment| {
        if !pinned.contains(&attachment.id().id()) {
            attachment.remove();
        }
    });

    // Fill the pool from id 0 upwards: pinned ids stay (or are re-created),
    // every other id takes the next movable reference. The crate always
    // assigns the lowest free id, which the check below confirms.
    let mut movable = movable.into_iter();
    for id in 0..total {
        let reference = if pinned.contains(&id) {
            match recreate.remove(&id) {
                Some(reference) => reference,
                None => continue,
            }
        } else {
            movable
                .next()
                .ok_or_else(|| AdapterError::new("attachment pool layout ran out of binaries"))?
        };
        let data = take_bytes(reference.slot)?;
        let assigned = db
            .entry_mut(reference.entry)
            .ok_or_else(|| AdapterError::new("entry not found"))?
            .add_attachment(reference.name, data)
            .id()
            .id();
        if assigned != id {
            return Err(AdapterError::new(format!(
                "attachment pool layout expected binary {id}, the keepass library assigned \
                 {assigned}"
            )));
        }
    }
    if movable.next().is_some() || !recreate.is_empty() {
        return Err(AdapterError::new(
            "attachment pool layout left binaries unplaced",
        ));
    }

    for (entry_uuid, indices) in rebuild {
        rebuild_history_versions(db, EntryId::from_uuid(entry_uuid), &indices)?;
    }
    check_pool_consistent(db)
}

/// Replace history versions `indices` of `entry_id` (each holding a subset
/// of the current version's attachments) with copies of the current version
/// that carry the old version's own data (fields, tags, times, auto-type,
/// colours, custom data) and only its attachments, so they reference the
/// current version's (re-laid-out) binaries.
///
/// A copy is taken while the current attachments the version lacks are
/// detached; they are then re-added with the same bytes, and since their
/// ids are the only free ones the crate hands the same ids back.
fn rebuild_history_versions(
    db: &mut Database,
    entry_id: EntryId,
    indices: &BTreeSet<usize>,
) -> Result<(), AdapterError> {
    let missing = || AdapterError::new("entry not found");
    let entry = db.entry(entry_id).ok_or_else(missing)?;
    let mut current = entry
        .attachments_named()
        .map(|(name, attachment)| (name.to_string(), attachment.id().id()))
        .collect::<Vec<_>>();
    current.sort_by_key(|(_, slot)| *slot);
    let mut version_names = BTreeMap::new();
    for index in indices {
        let version = entry.historical(*index).ok_or_else(missing)?;
        version_names.insert(
            *index,
            version
                .attachments_named()
                .map(|(name, _)| name.to_string())
                .collect::<BTreeSet<_>>(),
        );
    }
    let Some(history) = db.entry_mut(entry_id).ok_or_else(missing)?.history.take() else {
        return Ok(());
    };

    let mut rebuilt = BTreeMap::new();
    for (index, names) in version_names {
        let extras = current
            .iter()
            .filter(|(name, _)| !names.contains(name))
            .collect::<Vec<_>>();
        let mut held = Vec::with_capacity(extras.len());
        for (name, slot) in &extras {
            let mut entry = db.entry_mut(entry_id).ok_or_else(missing)?;
            let data = {
                let mut attachment = entry
                    .attachment_by_name_mut(name)
                    .ok_or_else(|| AdapterError::new("attachment not found"))?;
                std::mem::replace(&mut attachment.data, KdbxValue::unprotected(Vec::new()))
            };
            entry.remove_attachment_by_name(name);
            held.push((name.clone(), *slot, data));
        }
        let template: Entry = (*db.entry(entry_id).ok_or_else(missing)?).clone();
        for (name, slot, data) in held {
            let assigned = db
                .entry_mut(entry_id)
                .ok_or_else(missing)?
                .add_attachment(name, data)
                .id()
                .id();
            if assigned != slot {
                return Err(AdapterError::new(format!(
                    "history rebuild expected binary {slot}, the keepass library assigned \
                     {assigned}"
                )));
            }
        }
        let version = &history.get_entries()[index];
        let mut copy = template;
        copy.fields = version.fields.clone();
        copy.autotype = version.autotype.clone();
        copy.tags = version.tags.clone();
        copy.times = version.times.clone();
        copy.custom_data = version.custom_data.clone();
        copy.foreground_color = version.foreground_color.clone();
        copy.background_color = version.background_color.clone();
        copy.override_url = version.override_url.clone();
        copy.quality_check = version.quality_check;
        copy.history = None;
        rebuilt.insert(index, copy);
    }

    let versions = history
        .get_entries()
        .iter()
        .enumerate()
        .map(|(index, version)| rebuilt.remove(&index).unwrap_or_else(|| version.clone()))
        .collect::<Vec<_>>();
    let mut rebuilt_history = History::default();
    // `add_entry` prepends, so add oldest first to keep the order.
    for version in versions.into_iter().rev() {
        rebuilt_history.add_entry(version);
    }
    db.entry_mut(entry_id).ok_or_else(missing)?.history = Some(rebuilt_history);
    Ok(())
}

/// The pool is exactly ids 0..n and every current and history reference
/// resolves.
fn check_pool_consistent(db: &Database) -> Result<(), AdapterError> {
    let pool = pool_slots(db);
    let dense = pool.iter().copied().eq(0..pool.len());
    let resolves = db.iter_all_entries().all(|entry| {
        let count = entry
            .history
            .as_ref()
            .map_or(0, |history| history.get_entries().len());
        let current_ok = entry
            .attachments()
            .all(|attachment| pool.contains(&attachment.id().id()));
        current_ok
            && (0..count).all(|index| {
                entry.historical(index).is_none_or(|version| {
                    version
                        .attachments()
                        .all(|attachment| pool.contains(&attachment.id().id()))
                })
            })
    });
    if dense && resolves {
        Ok(())
    } else {
        Err(AdapterError::new(
            "attachment pool is inconsistent after the removal",
        ))
    }
}

fn history_only_error(entry: EntryId) -> AdapterError {
    AdapterError::KeptByHistory(format!(
        "cannot remove this keepass attachment: the same file is kept in the history of entry \
         `{}`, and the keepass library cannot keep a file that only entry history references; \
         delete that entry's history in KeePassXC (or keep the attachment) and retry",
        entry.uuid()
    ))
}

fn history_gap_error(entry: EntryId) -> AdapterError {
    AdapterError::KeptByHistory(format!(
        "cannot remove this keepass attachment: the history of entry `{}` references a file \
         stored after it in the database's attachment pool, which the keepass library cannot \
         renumber; delete that entry's history in KeePassXC (or keep the attachment) and retry",
        entry.uuid()
    ))
}

fn pool_slots(db: &Database) -> BTreeSet<usize> {
    db.iter_all_attachments()
        .map(|attachment| attachment.id().id())
        .collect()
}

/// Per entry version (`None` = current, `Some(i)` = history index), the
/// sorted `(name, sha256)` list of its attachments.
type AttachmentDigest = BTreeMap<(Uuid, Option<usize>), Vec<(String, String)>>;

fn attachment_digest(db: &Database) -> AttachmentDigest {
    fn version_digest(version: &EntryRef<'_>) -> Vec<(String, String)> {
        let mut list = version
            .attachments_named()
            .map(|(name, attachment)| (name.to_string(), stable_fingerprint(attachment.data.get())))
            .collect::<Vec<_>>();
        list.sort();
        list
    }

    let mut digest = AttachmentDigest::new();
    for entry in db.iter_all_entries() {
        let uuid = entry.id().uuid();
        let versions = entry
            .history
            .as_ref()
            .map_or(0, |history| history.get_entries().len());
        let current = version_digest(&entry);
        if !current.is_empty() {
            digest.insert((uuid, None), current);
        }
        for index in 0..versions {
            if let Some(version) = entry.historical(index) {
                let list = version_digest(&version);
                if !list.is_empty() {
                    digest.insert((uuid, Some(index)), list);
                }
            }
        }
    }
    digest
}

/// Get the recycle-bin group id, creating the group and registering it in
/// the database metadata when absent.
fn ensure_recycle_bin(db: &mut Database) -> GroupId {
    if let Some(uuid) = db.meta.recyclebin_uuid {
        let group_id = GroupId::from_uuid(uuid);
        if db.group(group_id).is_some() {
            return group_id;
        }
    }
    let group_id = {
        let mut root = db.root_mut();
        let mut bin = root.add_group();
        bin.name = RECYCLE_BIN_GROUP_NAME.to_string();
        bin.as_ref().id()
    };
    db.meta.recyclebin_uuid = Some(group_id.uuid());
    group_id
}

fn database_key(passphrase: &str) -> DatabaseKey {
    DatabaseKey::new().with_password(passphrase)
}

/// Argon2id parameters for newly created databases (KeePassXC-style 64 MiB;
/// paid twice per save because of the read-back verification, and saves
/// happen once per apply). The crate's default is Argon2d with 1 MiB; KDBX
/// stores Argon2 memory in bytes.
const NEW_DB_ARGON2_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
const NEW_DB_ARGON2_ITERATIONS: u64 = 10;
const NEW_DB_ARGON2_PARALLELISM: u32 = 2;

fn new_database_config() -> DatabaseConfig {
    let mut config = DatabaseConfig::default();
    // Reuse the crate default's Argon2 version (1.3) instead of depending on
    // the argon2 crate directly for its `Version` type.
    if let KdfConfig::Argon2 { version, .. } = config.kdf_config {
        config.kdf_config = KdfConfig::Argon2id {
            iterations: NEW_DB_ARGON2_ITERATIONS,
            memory: NEW_DB_ARGON2_MEMORY_BYTES,
            parallelism: NEW_DB_ARGON2_PARALLELISM,
            version,
        };
    }
    // The insecure-fast KDF makes new databases trivially crackable and exists
    // only to keep the test suite fast. Compile it out of release builds so a
    // stray environment variable can never weaken real data, and warn loudly
    // when it does apply.
    #[cfg(any(test, debug_assertions))]
    if std::env::var("YABBT_KEEPASS_KDF").as_deref() == Ok("insecure-fast") {
        eprintln!(
            "warning: YABBT_KEEPASS_KDF=insecure-fast is set; the new database uses a \
             deliberately weak KDF and must never hold real secrets"
        );
        config.kdf_config = KdfConfig::Aes { rounds: 10 };
    }
    config
}

/// Open a fresh owner-only (0600) file at a predictable sibling path. Any
/// stale leftover is removed first, then `create_new` ensures we never follow
/// or write through a symlink an attacker pre-planted in a shared directory
/// (it fails closed if the path reappears as a symlink between calls).
fn open_new_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    create_new_private(path)
}

/// Create an owner-only (0600) file that must not exist yet.
fn create_new_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Create a fresh `<file>.<UTC timestamp>.bak` (with a `-n` suffix when a
/// copy from the same second exists). Earlier copies are never overwritten,
/// so the pre-yabbt original survives every later run.
fn create_backup_file(path: &std::path::Path) -> Result<(PathBuf, std::fs::File), AdapterError> {
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    for attempt in 1..=1000u32 {
        let mut name = path.as_os_str().to_owned();
        if attempt == 1 {
            name.push(format!(".{stamp}.bak"));
        } else {
            name.push(format!(".{stamp}-{attempt}.bak"));
        }
        let candidate = PathBuf::from(name);
        match create_new_private(&candidate) {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(AdapterError::new(format!(
        "could not find a free backup file name next to `{}`",
        path.display()
    )))
}

fn entry_by_id<'a>(db: &'a Database, item_id: &str) -> Option<EntryRef<'a>> {
    let uuid = Uuid::parse_str(item_id).ok()?;
    db.entry(EntryId::from_uuid(uuid))
}

/// The recycle-bin group and every group nested inside it: everything in
/// this subtree is trashed.
fn recycle_bin_group_ids(db: &Database) -> Vec<GroupId> {
    let mut trashed = Vec::new();
    let mut pending = db
        .meta
        .recyclebin_uuid
        .map(GroupId::from_uuid)
        .filter(|bin_id| db.group(*bin_id).is_some())
        .into_iter()
        .collect::<Vec<_>>();
    while let Some(group_id) = pending.pop() {
        if trashed.contains(&group_id) {
            continue;
        }
        trashed.push(group_id);
        if let Some(group) = db.group(group_id) {
            pending.extend(group.group_ids());
        }
    }
    trashed
}

/// A group name as one folder-path segment: a literal "/" would read as
/// nesting, so it is shown as [`GROUP_NAME_SLASH`].
fn folder_segment(group_name: &str) -> String {
    group_name.replace('/', &GROUP_NAME_SLASH.to_string())
}

/// Every non-trashed group below the root, as `(id, "Parent/Child")` in
/// depth-first order. Nested groups use Bitwarden's nested-folder naming so
/// entries in subgroups always belong to a known folder.
fn folder_paths(db: &Database) -> Vec<(GroupId, String)> {
    let trashed = recycle_bin_group_ids(db);
    let mut folders = Vec::new();
    let mut pending = db
        .root()
        .groups()
        .map(|group| (group.id(), folder_segment(&group.name)))
        .collect::<Vec<_>>();
    pending.reverse();
    while let Some((group_id, path)) = pending.pop() {
        if trashed.contains(&group_id) {
            continue;
        }
        if let Some(group) = db.group(group_id) {
            let children = group
                .groups()
                .map(|child| {
                    (
                        child.id(),
                        format!("{path}/{}", folder_segment(&child.name)),
                    )
                })
                .collect::<Vec<_>>();
            pending.extend(children.into_iter().rev());
        }
        folders.push((group_id, path));
    }
    folders
}

/// Render the database as Bitwarden-wire export + listed-items JSON and
/// parse it through `normalize_export`. The recycle bin is excluded.
fn render_vault(db: &Database) -> Result<Vault, AdapterError> {
    let recycle_bins = recycle_bin_group_ids(db);
    let root_id = db.root().id();

    let folders = folder_paths(db)
        .into_iter()
        .map(|(group_id, name)| {
            json!({
                "id": group_id.uuid().to_string(),
                "name": name,
            })
        })
        .collect::<Vec<_>>();

    let mut export_items = Vec::new();
    let mut listed_items = Vec::new();
    for entry in db.iter_all_entries() {
        let parent_id = entry.parent().id();
        if recycle_bins.contains(&parent_id) {
            continue;
        }
        let rendered = render_entry(&entry, parent_id, root_id);
        listed_items.push(json!({
            "id": rendered["id"],
            "attachments": rendered_attachments(&entry),
        }));
        export_items.push(rendered);
    }

    let export_json = json!({ "folders": folders, "items": export_items }).to_string();
    let listed_json = json!(listed_items).to_string();
    let mut vault =
        normalize_export(&export_json, &listed_json, "keepass", None).map_err(|error| {
            AdapterError::new(format!("failed to render keepass database: {error}"))
        })?;
    // Attachment sizes and hashes come from the actual bytes (like the bw
    // export path after downloading), so restore planning matches kdbx
    // attachments by content, not just by file name.
    for item in &mut vault.items {
        let Some(entry) = entry_by_id(db, &item.id) else {
            continue;
        };
        for attachment_ref in &mut item.attachments {
            if let Some((_, attachment)) = attachment_by_id(&entry, &attachment_ref.id) {
                let bytes = attachment.data.get();
                attachment_ref.size = bytes.len() as u64;
                attachment_ref.sha256 = stable_fingerprint(bytes);
            }
        }
    }
    Ok(vault)
}

/// The entry's attachments as Bitwarden-wire attachment JSON, sorted by
/// file name (the crate keeps them in a hash map, whose iteration order
/// changes from run to run).
fn rendered_attachments(entry: &EntryRef<'_>) -> Value {
    let uuid = entry.id().uuid();
    let mut attachments = entry.attachments_named().collect::<Vec<_>>();
    attachments.sort_by_key(|(name, _)| *name);
    json!(
        attachments
            .into_iter()
            .map(|(name, attachment)| {
                json!({
                    "id": keepass_attachment_id(uuid, name),
                    "fileName": name,
                    "size": attachment.data.get().len(),
                })
            })
            .collect::<Vec<_>>()
    )
}

/// Render one entry to Bitwarden-wire item JSON. The stored
/// `yabbt.bitwarden_raw` payload is the base when present (guaranteeing
/// fidelity for everything yabbt wrote); entries authored in other KeePass
/// tools are synthesized. Live kdbx values overlay the base so user edits
/// made in KeePass are visible.
fn render_entry(entry: &EntryRef<'_>, parent_id: GroupId, root_id: GroupId) -> Value {
    let mut base = entry
        .get(KEEPASS_RAW_FIELD)
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| synthesized_base(entry));

    base["id"] = json!(entry.id().uuid().to_string());
    base["folderId"] = if parent_id == root_id {
        Value::Null
    } else {
        json!(parent_id.uuid().to_string())
    };
    if let Some(title) = entry.get_title() {
        base["name"] = json!(title);
    }
    match entry.get("Notes") {
        Some(notes) if !notes.is_empty() => base["notes"] = json!(notes),
        _ => {}
    }
    base["favorite"] = json!(entry.tags.iter().any(|tag| tag == KEEPASS_FAVORITE_TAG));

    if base.get("type").and_then(Value::as_u64) == Some(1) {
        let login = base
            .as_object_mut()
            .expect("base is object")
            .entry("login")
            .or_insert_with(|| json!({}));
        // The base came from the attacker-controllable `yabbt.bitwarden_raw`
        // field, so `login` (and `uris`/`uris[0]` below) may be any JSON type.
        // serde_json's index-assignment panics on a non-object/non-array, so
        // coerce each container before writing into it.
        if !login.is_object() {
            *login = json!({});
        }
        if let Some(username) = entry.get_username() {
            login["username"] = json!(username);
        }
        if let Some(password) = entry.get_password() {
            login["password"] = json!(password);
        }
        if let Some(totp) = entry.get_raw_otp_value() {
            login["totp"] = json!(totp);
        }
        if let Some(url) = entry.get_url()
            && !url.is_empty()
        {
            let uris = login
                .as_object_mut()
                .expect("login coerced to object")
                .entry("uris")
                .or_insert_with(|| json!([]));
            match uris.as_array_mut().and_then(|uris| uris.first_mut()) {
                Some(first) if first.is_object() => first["uri"] = json!(url),
                _ => *uris = json!([{ "uri": url }]),
            }
        }
    }

    overlay_custom_fields(entry, &mut base);
    base
}

/// Base payload for entries not written by yabbt (no raw field).
fn synthesized_base(entry: &EntryRef<'_>) -> Value {
    let is_login = entry.get_username().is_some()
        || entry.get_password().is_some()
        || entry.get_url().is_some()
        || entry.get_raw_otp_value().is_some();
    json!({
        "type": if is_login { 1 } else { 2 },
        "name": entry.get_title().unwrap_or_default(),
        "notes": Value::Null,
        "favorite": false,
        "fields": [],
    })
}

/// Overlay kdbx custom fields onto base.fields: values of uniquely-named
/// base fields are updated in place; kdbx-only custom fields are appended.
fn overlay_custom_fields(entry: &EntryRef<'_>, base: &mut Value) {
    let fields = base
        .as_object_mut()
        .expect("base is object")
        .entry("fields")
        .or_insert_with(|| json!([]));
    let Some(fields) = fields.as_array_mut() else {
        return;
    };

    for (name, value) in custom_fields(entry) {
        let mut matches = fields
            .iter_mut()
            .filter(|field| field.get("name").and_then(Value::as_str) == Some(name.as_str()))
            .collect::<Vec<_>>();
        match matches.len() {
            1 => {
                matches[0]["value"] = json!(value.get());
                matches[0]["type"] = json!(if value.is_protected() { 1 } else { 0 });
            }
            0 => fields.push(json!({
                "name": name,
                "value": value.get(),
                "type": if value.is_protected() { 1 } else { 0 },
            })),
            // Duplicate-named fields stay raw-authoritative.
            _ => {}
        }
    }
}

/// The entry's custom (non-standard, non-yabbt) fields sorted by name: the
/// crate keeps fields in a hash map, whose iteration order changes from run
/// to run, and appended fields must render identically every time.
fn custom_fields<'a>(entry: &'a EntryRef<'_>) -> Vec<(String, &'a KdbxValue<String>)> {
    let mut fields = entry
        .fields
        .iter()
        .filter(|(name, _)| {
            !RESERVED_FIELDS.contains(&name.as_str()) && name.as_str() != KEEPASS_RAW_FIELD
        })
        .map(|(name, value)| (name.clone(), value))
        .collect::<Vec<_>>();
    fields.sort_by(|(left, _), (right, _)| left.cmp(right));
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "unit-test-password";

    fn cheap_config() -> DatabaseConfig {
        let mut config = DatabaseConfig::default();
        config.kdf_config = KdfConfig::Aes { rounds: 10 };
        config
    }

    #[test]
    fn new_databases_use_argon2id_with_64_mib() {
        // The crate default is Argon2d with 1 MiB (its memory unit is bytes).
        match new_database_config().kdf_config {
            KdfConfig::Argon2id {
                memory,
                iterations,
                parallelism,
                ..
            } => {
                assert_eq!(memory, 64 * 1024 * 1024, "memory is in bytes");
                assert!(iterations >= 3, "iterations: {iterations}");
                assert!(parallelism >= 1, "parallelism: {parallelism}");
            }
            other => panic!("expected Argon2id, got {other:?}"),
        }
    }

    #[test]
    fn save_after_crate_attachment_removal_keeps_other_attachments() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("vault.kdbx");
        let mut db = Database::with_config(cheap_config());
        let mut ids = Vec::new();
        for title in ["A", "B", "C"] {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected("Title", title);
            entry.add_attachment(
                format!("{title}.bin"),
                KdbxValue::protected(title.as_bytes().to_vec()),
            );
            ids.push(entry.as_ref().id());
        }
        let mut file = std::fs::File::create(&path).expect("create kdbx");
        db.save(&mut file, database_key(PASSWORD))
            .expect("save kdbx");
        drop(file);
        let original = std::fs::read(&path).expect("read kdbx");

        let vault = KeepassVault::open(KeepassVaultOptions {
            path: path.clone(),
            passphrase: PASSWORD.to_string(),
            create_if_missing: false,
        })
        .expect("open vault");
        {
            let mut state = vault.state.lock().expect("lock");
            // Bypass the adapter's pool-preserving removal. keepass <= 0.15.4
            // mis-numbered the gap this leaves (B then read C's bytes);
            // 0.15.5 renumbers on save, so the verified save must succeed
            // and every remaining entry keep its own bytes.
            state
                .db
                .entry_mut(ids[0])
                .expect("entry A")
                .remove_attachment_by_name("A.bin");
            state.dirty = true;
        }
        vault.commit().expect("save with a gap in the binary pool");
        assert_ne!(std::fs::read(&path).expect("read kdbx"), original);

        let db = open_database(
            &std::fs::read(&path).expect("read kdbx"),
            PASSWORD,
            "reopen",
        )
        .expect("reopen kdbx");
        assert!(
            db.entry(ids[0])
                .expect("entry A")
                .attachment_by_name("A.bin")
                .is_none()
        );
        for (index, title) in [(1, "B"), (2, "C")] {
            let entry = db.entry(ids[index]).expect("entry");
            let attachment = entry
                .attachment_by_name(&format!("{title}.bin"))
                .expect("attachment kept");
            assert_eq!(attachment.data.get().as_slice(), title.as_bytes());
        }
    }
}

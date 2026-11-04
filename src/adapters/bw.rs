use super::bitwarden_json::{accept_personal_only_scope, normalize_export};
use super::command::{CommandOutput, CommandRequest, CommandRunner};
use super::{AdapterError, BackendCapabilities, VaultExport, VaultSource};
use crate::archive::ArchiveAttachment;
use crate::bw_env::{BwEnvScope, bw_child_env};
use crate::model::Vault;
use crate::progress::{NoopProgress, ProgressReporter};
use crate::restore_apply::{AttachmentUpload, UploadedAttachment, VaultTargetOps, VisibleItem};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BwSourceOptions {
    pub server_url: Option<String>,
    pub organization_id: Option<String>,
    pub strict: bool,
    pub attachment_jobs: usize,
    pub attachment_mode: BwAttachmentMode,
    pub profile: Option<BwProfileEnv>,
    /// The user acknowledged that a personal-scope export covers the
    /// personal vault only: organization items it cannot include are still
    /// counted and reported, but no longer mark the report incomplete.
    pub personal_only: bool,
}

/// Per-profile environment for `bw` invocations: an isolated appdata dir and
/// an optional session key held in memory for the duration of the run.
#[derive(Clone, PartialEq, Eq)]
pub struct BwProfileEnv {
    pub appdata_dir: PathBuf,
    pub session: Option<String>,
}

// The session is a secret; show only whether one is present.
impl std::fmt::Debug for BwProfileEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BwProfileEnv")
            .field("appdata_dir", &self.appdata_dir)
            .field("session", &self.session.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BwAttachmentMode {
    Download,
    MetadataOnly,
}

impl Default for BwSourceOptions {
    fn default() -> Self {
        Self {
            server_url: None,
            organization_id: None,
            strict: true,
            attachment_jobs: 4,
            attachment_mode: BwAttachmentMode::Download,
            profile: None,
            personal_only: false,
        }
    }
}

#[derive(Debug)]
pub struct BwSourceAdapter<R> {
    runner: R,
    options: BwSourceOptions,
}

#[derive(Debug, Clone)]
struct AttachmentDownloadJob {
    item_index: usize,
    attachment_index: usize,
    item_id: String,
    attachment_id: String,
    path: String,
}

enum AttachmentDownloadResult {
    Downloaded {
        item_index: usize,
        attachment_index: usize,
        path: String,
        bytes: Vec<u8>,
        size: u64,
        sha256: String,
    },
    Missing {
        item_id: String,
        attachment_id: String,
        reason: String,
    },
}

// `bytes` is plaintext attachment content; show only its length.
impl std::fmt::Debug for AttachmentDownloadResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttachmentDownloadResult::Downloaded {
                item_index,
                attachment_index,
                path,
                bytes,
                size,
                sha256,
            } => f
                .debug_struct("Downloaded")
                .field("item_index", item_index)
                .field("attachment_index", attachment_index)
                .field("path", path)
                .field("bytes", &format_args!("<{} bytes>", bytes.len()))
                .field("size", size)
                .field("sha256", sha256)
                .finish(),
            AttachmentDownloadResult::Missing {
                item_id,
                attachment_id,
                reason,
            } => f
                .debug_struct("Missing")
                .field("item_id", item_id)
                .field("attachment_id", attachment_id)
                .field("reason", reason)
                .finish(),
        }
    }
}

impl<R> BwSourceAdapter<R> {
    pub fn new(runner: R, options: BwSourceOptions) -> Self {
        Self { runner, options }
    }

    pub fn runner(&self) -> &R {
        &self.runner
    }
}

impl<R: CommandRunner + Sync> BwSourceAdapter<R> {
    pub fn export_with_progress(
        &self,
        progress: &dyn ProgressReporter,
    ) -> Result<VaultExport, AdapterError> {
        if let Some(server_url) = &self.options.server_url {
            progress.step_start("bw config server");
            self.configure_server(server_url)?;
            progress.step_finish("bw config server");
        }

        progress.step_start("bw status");
        self.ensure_unlocked()?;
        progress.step_finish("bw status");

        progress.step_start("bw sync");
        self.run_bw(vec!["sync".to_string()])?;
        progress.step_finish("bw sync");

        progress.step_start("bw export");
        let export_json = self
            .run_bw(export_args(&self.options.organization_id))?
            .stdout_string()?;
        progress.step_finish("bw export");
        progress.step_start("bw list items");
        let listed_items_json = self
            .run_bw(list_items_args(&self.options.organization_id))?
            .stdout_string()?;
        progress.step_finish("bw list items");
        progress.step_start("normalize vault export");
        let mut vault = normalize_export(
            &export_json,
            &listed_items_json,
            "bw",
            self.options.server_url.as_deref(),
        )?;
        if self.options.personal_only {
            accept_personal_only_scope(&mut vault.report);
        }
        progress.step_finish("normalize vault export");

        if self.options.attachment_mode == BwAttachmentMode::MetadataOnly {
            return Ok(VaultExport {
                vault,
                attachments: Vec::new(),
            });
        }

        let temp_dir = private_tempdir()?;
        let download_jobs = attachment_download_jobs(&vault);
        let total_attachments = download_jobs.len() as u64;
        if total_attachments > 0 {
            progress.counted("downloading attachments", 0, total_attachments);
        }

        let mut archive_attachments = Vec::new();
        for result in self.download_export_attachments(temp_dir.path(), &download_jobs, progress)? {
            match result {
                AttachmentDownloadResult::Downloaded {
                    item_index,
                    attachment_index,
                    path,
                    bytes,
                    size,
                    sha256,
                } => {
                    let attachment = &mut vault.items[item_index].attachments[attachment_index];
                    attachment.size = size;
                    attachment.sha256 = sha256;
                    archive_attachments.push(ArchiveAttachment { path, bytes });
                }
                AttachmentDownloadResult::Missing {
                    item_id,
                    attachment_id,
                    reason,
                } => {
                    vault.report.complete = false;
                    vault.report.warnings.push(crate::model::Warning {
                        code: "attachment-download-failed".to_string(),
                        message: format!(
                            "attachment `{attachment_id}` for item `{item_id}` was not downloaded: {reason}"
                        ),
                    });
                }
            }
        }

        Ok(VaultExport {
            vault,
            attachments: archive_attachments,
        })
    }

    /// Every `bw` call starts from a cleared environment plus an allowlist
    /// (see `bw_env`), so inherited variables such as `BW_CLEANEXIT` or
    /// `NODE_TLS_REJECT_UNAUTHORIZED` cannot change bw's exit status, output,
    /// or TLS verification.
    fn bw_request(&self, args: Vec<String>) -> CommandRequest {
        let mut request = CommandRequest::new("bw", args);
        let scope = match &self.options.profile {
            Some(profile) => BwEnvScope::Profile {
                appdata_dir: &profile.appdata_dir,
                session: profile.session.as_deref(),
            },
            None => BwEnvScope::Ambient,
        };
        request.env_clear = true;
        request.env = bw_child_env(std::env::vars_os(), scope, true);
        request
    }

    fn run_bw(&self, args: Vec<String>) -> Result<CommandOutput, AdapterError> {
        let output = self.runner.run(self.bw_request(args))?;
        Self::check_output(output)
    }

    /// Like `run_bw`, but pipes `stdin` to the `bw` child instead of placing
    /// it in argv. Used for the base64 item/folder payloads so vault secrets
    /// never appear on the command line.
    fn run_bw_stdin(
        &self,
        args: Vec<String>,
        stdin: Vec<u8>,
    ) -> Result<CommandOutput, AdapterError> {
        let mut request = self.bw_request(args);
        request.stdin = Some(stdin);
        let output = self.runner.run(request)?;
        Self::check_output(output)
    }

    fn check_output(output: CommandOutput) -> Result<CommandOutput, AdapterError> {
        if output.success() {
            Ok(output)
        } else {
            Err(AdapterError::CommandFailed {
                program: "bw".to_string(),
                status: output.status,
                stderr: redact(&output.stderr_lossy()),
            })
        }
    }

    fn ensure_unlocked(&self) -> Result<(), AdapterError> {
        let status_json = self.run_bw(vec!["status".to_string()])?.stdout_string()?;
        let status = serde_json::from_str::<Value>(&status_json)?;
        let status = status.get("status").and_then(Value::as_str);
        // In profile mode yabbt manages the session itself, so pointing the
        // user at `export BW_SESSION` would be wrong (and ignored).
        if let Some(profile) = &self.options.profile {
            // The profile directory is `<base>/<profile name>`.
            let name = profile
                .appdata_dir
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "<name>".to_string());
            match status {
                Some("locked") => {
                    return Err(AdapterError::new(format!(
                        "bw profile `{name}` is locked; re-run yabbt to unlock it interactively, \
                         or run `yabbt bw-login --profile {name}`"
                    )));
                }
                Some("unauthenticated") => {
                    return Err(AdapterError::new(format!(
                        "bw profile `{name}` is not logged in; run `yabbt bw-login --profile {name}` first"
                    )));
                }
                _ => {}
            }
        }
        match status {
            Some("unlocked") => Ok(()),
            Some("locked") => Err(AdapterError::new(
                "bw vault is locked; run `export BW_SESSION=\"$(bw unlock --raw)\"` before running yabbt",
            )),
            Some("unauthenticated") => Err(AdapterError::new(
                "bw is not logged in; run `bw login`, then `export BW_SESSION=\"$(bw unlock --raw)\"` before running yabbt",
            )),
            Some(other) => Err(AdapterError::new(format!(
                "unexpected bw status `{other}`; expected unlocked"
            ))),
            None => Err(AdapterError::new(
                "bw status did not include a `status` field; expected unlocked",
            )),
        }
    }

    fn download_export_attachments(
        &self,
        temp_dir: &Path,
        jobs: &[AttachmentDownloadJob],
        progress: &dyn ProgressReporter,
    ) -> Result<Vec<AttachmentDownloadResult>, AdapterError> {
        if jobs.is_empty() {
            return Ok(Vec::new());
        }

        let worker_count = self.options.attachment_jobs.max(1).min(jobs.len());
        let next_job = AtomicUsize::new(0);
        let (sender, receiver) =
            mpsc::channel::<(usize, Result<AttachmentDownloadResult, AdapterError>)>();
        let mut received = Vec::with_capacity(jobs.len());
        let total = jobs.len() as u64;
        let mut completed = 0;

        std::thread::scope(|scope| {
            for _ in 0..worker_count {
                let sender = sender.clone();
                let next_job = &next_job;
                scope.spawn(move || {
                    loop {
                        let job_index = next_job.fetch_add(1, Ordering::SeqCst);
                        let Some(job) = jobs.get(job_index) else {
                            break;
                        };
                        let result = self.download_export_attachment(temp_dir, job);
                        if sender.send((job_index, result)).is_err() {
                            break;
                        }
                    }
                });
            }
            drop(sender);

            for result in receiver {
                completed += 1;
                progress.counted("downloading attachments", completed, total);
                received.push(result);
            }
        });

        received.sort_by_key(|(job_index, _)| *job_index);
        let mut downloads = Vec::with_capacity(jobs.len());
        for (_job_index, result) in received {
            downloads.push(result?);
        }
        Ok(downloads)
    }

    fn download_export_attachment(
        &self,
        temp_dir: &Path,
        job: &AttachmentDownloadJob,
    ) -> Result<AttachmentDownloadResult, AdapterError> {
        validate_object_id("attachment", &job.attachment_id)?;
        validate_object_id("item", &job.item_id)?;
        // Temp names come from local indices only, never from backend ids.
        let output_path = temp_dir.join(format!(
            "attachment-{}-{}",
            job.item_index, job.attachment_index
        ));
        let missing = |reason: String| AttachmentDownloadResult::Missing {
            item_id: job.item_id.clone(),
            attachment_id: job.attachment_id.clone(),
            reason,
        };
        match self.run_bw(vec![
            "get".to_string(),
            "attachment".to_string(),
            job.attachment_id.clone(),
            "--itemid".to_string(),
            job.item_id.clone(),
            "--output".to_string(),
            output_path.to_string_lossy().into_owned(),
        ]) {
            Ok(_) => {}
            // `--permissive`: a failed download (deleted attachment, server
            // error) becomes a warning and an incomplete report, exactly
            // like a download that produced no file. The stderr in the
            // error is already redacted.
            Err(error @ AdapterError::CommandFailed { .. }) if !self.options.strict => {
                return Ok(missing(error.to_string()));
            }
            Err(error) => return Err(error),
        }

        let bytes = match std::fs::read(&output_path) {
            Ok(bytes) => bytes,
            Err(error) if self.options.strict => {
                return Err(AdapterError::new(format!(
                    "attachment `{}` for item `{}` was not downloaded: {error}",
                    job.attachment_id, job.item_id
                )));
            }
            Err(error) => return Ok(missing(error.to_string())),
        };
        let size = bytes.len() as u64;
        let sha256 = sha256_hex(&bytes);

        Ok(AttachmentDownloadResult::Downloaded {
            item_index: job.item_index,
            attachment_index: job.attachment_index,
            path: job.path.clone(),
            bytes,
            size,
            sha256,
        })
    }

    fn upload_attachment(
        &self,
        temp_dir: &Path,
        job_index: usize,
        job: &AttachmentUpload,
    ) -> Result<UploadedAttachment, AdapterError> {
        // The target item id comes from the backend (a `bw create item`
        // response or a target scan). Validate it before it reaches argv, and
        // never use it in a filesystem path: the per-job directory is named
        // from the local job index only, so a hostile id such as
        // `/home/u/.config/x` cannot redirect where plaintext is written.
        validate_object_id("item", &job.target_item_id)?;
        let file_name = Path::new(&job.file_name)
            .file_name()
            .and_then(|file_name| file_name.to_str())
            .filter(|file_name| !file_name.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("attachment-{job_index}"));
        let attachment_dir = temp_dir.join(format!("job-{job_index}"));
        std::fs::create_dir_all(&attachment_dir)?;
        let output_path = attachment_dir.join(file_name);
        write_private(&output_path, &job.bytes)?;
        self.run_bw(vec![
            "create".to_string(),
            "attachment".to_string(),
            "--file".to_string(),
            output_path.to_string_lossy().into_owned(),
            "--itemid".to_string(),
            job.target_item_id.clone(),
        ])?;

        Ok(UploadedAttachment {
            target_item_id: job.target_item_id.clone(),
            file_name: job.file_name.clone(),
            size: job.size,
            sha256: job.sha256.clone(),
        })
    }

    fn configure_server(&self, server_url: &str) -> Result<(), AdapterError> {
        let output = self.runner.run(self.bw_request(vec![
            "config".to_string(),
            "server".to_string(),
            server_url.to_string(),
        ]))?;
        if output.success() {
            return Ok(());
        }

        let stderr = output.stderr_lossy();
        if stderr.contains("Logout required before server config update") {
            let configured_server = self
                .run_bw(vec!["config".to_string(), "server".to_string()])?
                .stdout_string()?;
            if same_server_url(&configured_server, server_url) {
                return Ok(());
            }
        }

        Err(AdapterError::CommandFailed {
            program: "bw".to_string(),
            status: output.status,
            stderr: redact(&stderr),
        })
    }

    fn listed_items_json(&self) -> Result<Value, AdapterError> {
        let listed_items_json = self
            .run_bw(list_items_args(&self.options.organization_id))?
            .stdout_string()?;
        serde_json::from_str::<Value>(&listed_items_json).map_err(AdapterError::Json)
    }
}

impl<R: CommandRunner + Sync> super::BackupSource for BwSourceAdapter<R> {
    fn backend_name(&self) -> &'static str {
        "bw"
    }

    fn export_with_progress(
        &self,
        progress: &dyn ProgressReporter,
    ) -> Result<VaultExport, AdapterError> {
        BwSourceAdapter::export_with_progress(self, progress)
    }
}

impl<R: CommandRunner + Sync> crate::restore_apply::RestoreTarget for BwSourceAdapter<R> {
    fn backend_name(&self) -> &'static str {
        "bw"
    }

    fn scan(&self, progress: &dyn ProgressReporter) -> Result<Vault, AdapterError> {
        Ok(self.export_with_progress(progress)?.vault)
    }
}

impl<R: CommandRunner + Sync> VaultTargetOps for BwSourceAdapter<R> {
    fn create_folder(&self, payload: &Value) -> Result<String, AdapterError> {
        let encoded = BASE64.encode(serde_json::to_vec(payload)?);
        let created = self
            .run_bw_stdin(
                vec!["create".to_string(), "folder".to_string()],
                encoded.into_bytes(),
            )?
            .stdout_string()?;
        created_folder_id(&created)
    }

    fn create_item(&self, payload: &Value) -> Result<String, AdapterError> {
        let encoded = BASE64.encode(serde_json::to_vec(payload)?);
        let created = self
            .run_bw_stdin(
                vec!["create".to_string(), "item".to_string()],
                encoded.into_bytes(),
            )?
            .stdout_string()?;
        created_item_id(&created)
    }

    fn edit_item(&self, item_id: &str, payload: &Value) -> Result<(), AdapterError> {
        validate_object_id("item", item_id)?;
        let encoded = BASE64.encode(serde_json::to_vec(payload)?);
        self.run_bw_stdin(
            vec!["edit".to_string(), "item".to_string(), item_id.to_string()],
            encoded.into_bytes(),
        )?;
        Ok(())
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

        let temp_dir = private_tempdir()?;
        let worker_count = self.options.attachment_jobs.max(1).min(jobs.len());
        let next_job = AtomicUsize::new(0);
        let cancelled = AtomicBool::new(false);
        let (sender, receiver) =
            mpsc::channel::<(usize, Result<UploadedAttachment, AdapterError>)>();
        let mut received = Vec::with_capacity(jobs.len());
        let mut completed = 0;

        std::thread::scope(|scope| {
            for _ in 0..worker_count {
                let sender = sender.clone();
                let next_job = &next_job;
                let cancelled = &cancelled;
                let temp_dir = temp_dir.path();
                scope.spawn(move || {
                    loop {
                        if cancelled.load(Ordering::SeqCst) {
                            break;
                        }
                        let job_index = next_job.fetch_add(1, Ordering::SeqCst);
                        let Some(job) = jobs.get(job_index) else {
                            break;
                        };
                        let result = self.upload_attachment(temp_dir, job_index, job);
                        let failed = result.is_err();
                        if failed {
                            cancelled.store(true, Ordering::SeqCst);
                        }
                        if sender.send((job_index, result)).is_err() {
                            break;
                        }
                        if failed {
                            break;
                        }
                    }
                });
            }
            drop(sender);

            for result in receiver {
                completed += 1;
                progress.counted("uploading attachments", completed, total);
                received.push(result);
            }
        });

        received.sort_by_key(|(job_index, _)| *job_index);
        let mut uploaded = Vec::with_capacity(jobs.len());
        for (_job_index, result) in received {
            uploaded.push(result?);
        }
        Ok(uploaded)
    }

    fn delete_attachment(&self, item_id: &str, attachment_id: &str) -> Result<(), AdapterError> {
        validate_object_id("attachment", attachment_id)?;
        validate_object_id("item", item_id)?;
        self.run_bw(vec![
            "delete".to_string(),
            "attachment".to_string(),
            attachment_id.to_string(),
            "--itemid".to_string(),
            item_id.to_string(),
        ])?;
        Ok(())
    }

    fn delete_item(&self, item_id: &str, permanent: bool) -> Result<(), AdapterError> {
        validate_object_id("item", item_id)?;
        let mut args = vec![
            "delete".to_string(),
            "item".to_string(),
            item_id.to_string(),
        ];
        if permanent {
            args.push("--permanent".to_string());
        }
        self.run_bw(args)?;
        Ok(())
    }

    fn delete_folder(&self, folder_id: &str) -> Result<(), AdapterError> {
        validate_object_id("folder", folder_id)?;
        self.run_bw(vec![
            "delete".to_string(),
            "folder".to_string(),
            folder_id.to_string(),
        ])?;
        Ok(())
    }

    fn sync(&self) -> Result<(), AdapterError> {
        self.run_bw(vec!["sync".to_string()])?;
        Ok(())
    }

    fn get_item(&self, item_id: &str) -> Result<String, AdapterError> {
        validate_object_id("item", item_id)?;
        self.run_bw(vec![
            "get".to_string(),
            "item".to_string(),
            item_id.to_string(),
        ])?
        .stdout_string()
    }

    fn download_attachment(
        &self,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<Vec<u8>, AdapterError> {
        validate_object_id("attachment", attachment_id)?;
        validate_object_id("item", item_id)?;
        let temp_dir = private_tempdir()?;
        let output_path = temp_dir.path().join("attachment");
        self.run_bw(vec![
            "get".to_string(),
            "attachment".to_string(),
            attachment_id.to_string(),
            "--itemid".to_string(),
            item_id.to_string(),
            "--output".to_string(),
            output_path.to_string_lossy().into_owned(),
        ])?;
        Ok(std::fs::read(&output_path)?)
    }

    fn list_visible_items(&self) -> Result<Vec<VisibleItem>, AdapterError> {
        let listed_items = self.listed_items_json()?;
        Ok(listed_items
            .as_array()
            .into_iter()
            .flatten()
            .map(|item| VisibleItem {
                id: item
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                attachment_ids: item
                    .get("attachments")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|attachment| attachment.get("id").and_then(Value::as_str))
                    .map(str::to_string)
                    .collect(),
            })
            .collect())
    }

    fn list_folder_ids(&self) -> Result<Vec<String>, AdapterError> {
        let export_json = self
            .run_bw(export_args(&self.options.organization_id))?
            .stdout_string()?;
        let export = serde_json::from_str::<Value>(&export_json)?;
        Ok(export
            .get("folders")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|folder| folder.get("id").and_then(Value::as_str))
            .map(str::to_string)
            .collect())
    }
}

fn attachment_download_jobs(vault: &Vault) -> Vec<AttachmentDownloadJob> {
    vault
        .items
        .iter()
        .enumerate()
        .flat_map(|(item_index, item)| {
            item.attachments
                .iter()
                .enumerate()
                .map(
                    move |(attachment_index, attachment)| AttachmentDownloadJob {
                        item_index,
                        attachment_index,
                        item_id: item.id.clone(),
                        attachment_id: attachment.id.clone(),
                        path: attachment.path.clone(),
                    },
                )
        })
        .collect()
}

fn created_item_id(output: &str) -> Result<String, AdapterError> {
    created_object_id("item", output)
}

fn created_folder_id(output: &str) -> Result<String, AdapterError> {
    created_object_id("folder", output)
}

/// Extract and validate the id `bw create` returned. The id is
/// backend-controlled and later reaches argv, temp-file handling, and the
/// restore map, so it is held to the same character set as every other id.
fn created_object_id(kind: &str, output: &str) -> Result<String, AdapterError> {
    let value = serde_json::from_str::<Value>(output)?;
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| AdapterError::new(format!("created {kind} response did not include id")))?;
    validate_object_id(kind, id)?;
    Ok(id.to_string())
}

fn same_server_url(left: &str, right: &str) -> bool {
    left.trim().trim_end_matches('/') == right.trim().trim_end_matches('/')
}

impl<R: CommandRunner + Sync> VaultSource for BwSourceAdapter<R> {
    fn name(&self) -> &str {
        "bw"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            read_items: true,
            write_items: false,
            read_attachments: true,
            write_attachments: false,
            organizations: true,
            sends: false,
            passkeys: true,
            ssh_keys: true,
            strict_restore: false,
        }
    }

    fn export(&self) -> Result<VaultExport, AdapterError> {
        self.export_with_progress(&NoopProgress)
    }
}

fn export_args(organization_id: &Option<String>) -> Vec<String> {
    let mut args = vec![
        "--raw".to_string(),
        "export".to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    if let Some(organization_id) = organization_id {
        args.push("--organizationid".to_string());
        args.push(organization_id.clone());
    }
    args
}

fn list_items_args(organization_id: &Option<String>) -> Vec<String> {
    let mut args = vec!["list".to_string(), "items".to_string()];
    if let Some(organization_id) = organization_id {
        args.push("--organizationid".to_string());
        args.push(organization_id.clone());
    }
    args
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Create an owner-only (0700) temporary directory. `tempfile::tempdir()`
/// creates directories with the process umask (typically world-readable
/// 0755); attachment plaintext is written here during backup/restore, so the
/// directory must not be readable by other local users.
fn private_tempdir() -> std::io::Result<tempfile::TempDir> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
    }
    #[cfg(not(unix))]
    {
        tempfile::tempdir()
    }
}

/// Write decrypted attachment bytes to an owner-only (0600) file. Plain
/// `std::fs::write` honours the umask and typically yields 0644.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

/// Sanitize captured `bw` stderr before it is surfaced in an error message.
///
/// `bw` invocations can carry secrets (item payloads on stdin, session keys in
/// the environment), and a Node/commander error path may echo argv-like blobs.
/// Collapse whitespace, drop any long opaque token that could be a base64
/// payload or session key, and bound the overall length so a hostile or
/// verbose backend cannot dump large/secret-bearing output to the terminal.
pub(crate) fn redact(value: &str) -> String {
    const MAX_LEN: usize = 512;
    const MAX_TOKEN_LEN: usize = 40;

    let scrubbed = value
        .split_whitespace()
        .map(|token| {
            // Long tokens with no separators are the shape of base64 payloads,
            // session keys, and other opaque secrets; replace them wholesale.
            if token.len() > MAX_TOKEN_LEN
                && token
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'))
            {
                "<redacted>"
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    if scrubbed.len() > MAX_LEN {
        // Truncate on a char boundary so the lossy-UTF-8 stderr never panics.
        let end = (0..=MAX_LEN)
            .rev()
            .find(|&i| scrubbed.is_char_boundary(i))
            .unwrap_or(0);
        let mut truncated = scrubbed[..end].to_string();
        truncated.push_str(" …<truncated>");
        truncated
    } else {
        scrubbed
    }
}

/// Reject object identifiers that could be reinterpreted by `bw` as options.
///
/// Item/folder/organization IDs are UUIDs and attachment IDs are alphanumeric;
/// both fit `[A-Za-z0-9-]` and never begin with `-`. Anything else (empty, a
/// leading dash, or stray characters) is refused before it reaches argv so a
/// hostile server or poisoned restore map cannot smuggle a flag.
fn validate_object_id(kind: &str, id: &str) -> Result<(), AdapterError> {
    let valid = !id.is_empty()
        && !id.starts_with('-')
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if valid {
        Ok(())
    } else {
        Err(AdapterError::new(format!(
            "refusing to use malformed {kind} id in bw command"
        )))
    }
}

#[allow(dead_code)]
fn _assert_path_is_used_for_docs(_: &Path) {}

#[cfg(test)]
mod tests {
    use super::{redact, validate_object_id};

    #[test]
    fn validate_object_id_accepts_uuid_and_attachment_ids() {
        assert!(validate_object_id("item", "9f8b7c6d-1234-4abc-9def-0123456789ab").is_ok());
        // Bitwarden attachment ids are alphanumeric, not UUIDs.
        assert!(validate_object_id("attachment", "o4lrz3ic6mvf3xls4umvbnnsme34tah0").is_ok());
    }

    #[test]
    fn validate_object_id_rejects_flag_like_and_malformed_ids() {
        assert!(validate_object_id("item", "--permanent").is_err());
        assert!(validate_object_id("item", "-x").is_err());
        assert!(validate_object_id("item", "").is_err());
        assert!(validate_object_id("item", "id with space").is_err());
        assert!(validate_object_id("item", "id;rm").is_err());
    }

    #[test]
    fn redact_strips_long_opaque_tokens_and_bounds_length() {
        let session = "a".repeat(88);
        let scrubbed = redact(&format!("error near {session} done"));
        assert!(!scrubbed.contains(&session));
        assert!(scrubbed.contains("<redacted>"));
        assert!(scrubbed.contains("error near"));

        let long = "word ".repeat(400);
        assert!(redact(&long).len() <= 512 + " …<truncated>".len());
    }

    #[test]
    fn redact_keeps_short_human_readable_messages() {
        assert_eq!(redact("You are not logged in.\n"), "You are not logged in.");
    }
}

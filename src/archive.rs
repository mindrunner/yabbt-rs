use crate::model::{AttachmentRef, Vault};
use crate::progress::{NoopProgress, ProgressReporter};
use age::secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveBuilder {
    vault: Vault,
    attachments: Vec<ArchiveAttachment>,
    allow_weak_passphrase: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveAttachment {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedArchive {
    pub vault: Vault,
    pub attachments: Vec<ArchiveAttachment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveManifest {
    pub format_version: u32,
    pub payload_checksum: String,
    pub attachment_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveSummary {
    pub format_version: u32,
    pub source_backend: String,
    pub source_server: Option<String>,
    pub created_at: String,
    pub folder_count: usize,
    pub item_count: usize,
    pub attachment_count: usize,
    pub warning_count: usize,
    pub complete: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("passphrase must not be empty")]
    EmptyPassphrase,
    #[error("weak passphrase refused: {0}; use --yolo to override")]
    WeakPassphrase(String),
    #[error("archive encryption failed: {0}")]
    Encrypt(String),
    #[error("invalid passphrase or archive integrity check failed: {0}")]
    Decrypt(String),
    #[error("archive integrity check failed: {0}")]
    Integrity(String),
    #[error("archive format error: {0}")]
    Format(String),
    #[error("archive validation failed: {0}")]
    Validation(String),
    #[error("archive I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("archive JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("archive model failed: {0}")]
    Model(#[from] crate::model::ModelError),
}

impl ArchiveBuilder {
    pub fn new(vault: Vault) -> Self {
        Self {
            vault,
            attachments: Vec::new(),
            allow_weak_passphrase: false,
        }
    }

    pub fn attachment(mut self, attachment: ArchiveAttachment) -> Self {
        self.attachments.push(attachment);
        self
    }

    pub fn allow_weak_passphrase(mut self) -> Self {
        self.allow_weak_passphrase = true;
        self
    }

    /// Encode, encrypt, and publish the archive at `path` according to
    /// `mode` (see [`WriteMode`]).
    pub fn write(
        self,
        path: impl AsRef<Path>,
        passphrase: &str,
        mode: WriteMode,
    ) -> Result<(), ArchiveError> {
        self.write_with_progress(path, passphrase, mode, &NoopProgress)
    }

    pub fn write_with_progress(
        self,
        path: impl AsRef<Path>,
        passphrase: &str,
        mode: WriteMode,
        progress: &dyn ProgressReporter,
    ) -> Result<(), ArchiveError> {
        let staged = self.stage_with_progress(path, passphrase, progress)?;
        progress.step_start("publish archive file");
        staged.publish(mode)?;
        progress.step_finish("publish archive file");
        Ok(())
    }

    /// Encode and encrypt the archive into a uniquely named, owner-only temp
    /// file next to `path` (fsynced), without touching `path` itself. The
    /// caller can verify the staged file and then [`StagedArchive::publish`]
    /// it, or drop it to discard it.
    pub fn stage_with_progress(
        self,
        path: impl AsRef<Path>,
        passphrase: &str,
        progress: &dyn ProgressReporter,
    ) -> Result<StagedArchive, ArchiveError> {
        if passphrase.is_empty() {
            return Err(ArchiveError::EmptyPassphrase);
        }
        if !self.allow_weak_passphrase {
            validate_passphrase_strength(passphrase)?;
        }

        progress.phase("write archive");
        progress.step_start("encode archive payload");
        let payload = encode_tar_payload(&self.vault, &self.attachments, progress)?;
        progress.step_finish("encode archive payload");
        progress.step_start("compress archive");
        let compressed = zstd::stream::encode_all(Cursor::new(payload), 0)?;
        progress.step_finish("compress archive");
        progress.step_start("encrypt archive");
        let encrypted = encrypt_payload(&compressed, passphrase)?;
        progress.step_finish("encrypt archive");

        progress.step_start("write archive file");
        let staged = StagedArchive::write(path.as_ref(), &encrypted)?;
        progress.step_finish("write archive file");
        Ok(staged)
    }
}

/// How a finished archive is published at its destination path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// Publish only if nothing exists at the destination. The check is part
    /// of the atomic publish itself, so a file that appeared after an earlier
    /// existence check is never replaced: the write fails with an
    /// [`std::io::ErrorKind::AlreadyExists`] I/O error instead.
    CreateNew,
    /// Atomically replace whatever exists at the destination.
    Overwrite,
}

/// An encrypted archive fully written and fsynced to a temp file in its
/// destination's directory, not yet visible at the destination. Dropping it
/// removes the temp file, so a failed or abandoned write never leaves a
/// partial (or unwanted) archive behind.
#[derive(Debug)]
pub struct StagedArchive {
    temp: tempfile::NamedTempFile,
    destination: PathBuf,
}

impl StagedArchive {
    fn write(destination: &Path, bytes: &[u8]) -> std::io::Result<Self> {
        let name = destination
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        // A random name per run: a stale temp file from a crashed run never
        // blocks the next write, and nothing can pre-plant a symlink at a
        // predictable name. tempfile creates it with O_EXCL and mode 0600,
        // so the (encrypted) archive is owner-only.
        let mut temp = tempfile::Builder::new()
            .prefix(&format!(".{name}."))
            .suffix(".tmp-yabbt")
            .tempfile_in(parent_dir(destination))?;
        temp.write_all(bytes)?;
        temp.as_file().sync_all()?;
        Ok(Self {
            temp,
            destination: destination.to_path_buf(),
        })
    }

    /// The staged temp file, for reading the archive back before publishing.
    pub fn path(&self) -> &Path {
        self.temp.path()
    }

    /// The path the archive is published at.
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    /// Atomically move the staged file to its destination, then fsync the
    /// directory so the new name survives a crash. On failure the temp file
    /// is removed and the destination is untouched.
    ///
    /// A file system that does not support fsync on directories (some FUSE
    /// and network mounts answer EINVAL/ENOTSUP) only gets a warning: the
    /// archive is already published at that point.
    pub fn publish(self, mode: WriteMode) -> Result<(), ArchiveError> {
        self.publish_with(mode, sync_dir)
    }

    fn publish_with(
        self,
        mode: WriteMode,
        sync_dir: impl FnOnce(&Path) -> std::io::Result<()>,
    ) -> Result<(), ArchiveError> {
        let Self { temp, destination } = self;
        let persisted = match mode {
            // Linux: renameat2(RENAME_NOREPLACE); elsewhere (or on file
            // systems without it) hard link + unlink, which also fails if
            // the destination exists.
            WriteMode::CreateNew => temp.persist_noclobber(&destination),
            WriteMode::Overwrite => temp.persist(&destination),
        };
        // On error the temp file handed back in the error is dropped here,
        // which removes it.
        persisted.map_err(|error| publish_error(error.error, mode))?;
        match sync_dir(parent_dir(&destination)) {
            Ok(()) => Ok(()),
            Err(error) if directory_sync_unsupported(&error) => {
                eprintln!(
                    "warning: published {}, but its directory cannot be fsynced on this \
                     filesystem ({error}); the new file name may not survive a crash or power loss",
                    destination.display()
                );
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }
}

/// Errno values the publish step classifies. Only what `std` cannot express
/// portably through [`std::io::ErrorKind`].
#[cfg(any(target_os = "linux", target_os = "android"))]
mod errno {
    pub const EPERM: i32 = 1;
    #[cfg(test)]
    pub const EIO: i32 = 5;
    pub const EINVAL: i32 = 22;
    pub const ENOSYS: i32 = 38;
    pub const EOPNOTSUPP: i32 = 95;
    pub const ENOTSUP: i32 = EOPNOTSUPP;
}

#[cfg(target_vendor = "apple")]
mod errno {
    pub const EPERM: i32 = 1;
    #[cfg(test)]
    pub const EIO: i32 = 5;
    pub const EINVAL: i32 = 22;
    pub const ENOSYS: i32 = 78;
    pub const EOPNOTSUPP: i32 = 102;
    pub const ENOTSUP: i32 = 45;
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
mod errno {
    pub const EPERM: i32 = 1;
    #[cfg(test)]
    pub const EIO: i32 = 5;
    pub const EINVAL: i32 = 22;
    pub const ENOSYS: i32 = -1;
    pub const EOPNOTSUPP: i32 = -1;
    pub const ENOTSUP: i32 = -1;
}

/// Whether a directory fsync failed only because the file system does not
/// support it (nothing was lost).
fn directory_sync_unsupported(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::Unsupported
        || matches!(
            error.raw_os_error(),
            Some(code) if code == errno::EINVAL || code == errno::ENOTSUP || code == errno::EOPNOTSUPP
        )
}

/// The error for a failed publish rename. A no-clobber publish on a file
/// system without `renameat2(RENAME_NOREPLACE)` and hard links (common on
/// FUSE mounts) fails with ENOSYS/EPERM/ENOTSUP; say so and how to proceed.
/// The publish still fails closed.
fn publish_error(error: std::io::Error, mode: WriteMode) -> ArchiveError {
    let unsupported = error.kind() == std::io::ErrorKind::Unsupported
        || matches!(
            error.raw_os_error(),
            Some(code) if [errno::ENOSYS, errno::EPERM, errno::ENOTSUP, errno::EOPNOTSUPP, errno::EINVAL]
                .contains(&code)
        );
    if mode == WriteMode::CreateNew && unsupported {
        return ArchiveError::Io(std::io::Error::new(
            error.kind(),
            format!(
                "{error} (the filesystem does not support no-clobber rename; pass --overwrite \
                 or write to a local filesystem)"
            ),
        ));
    }
    ArchiveError::Io(error)
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Hard ceiling on the decompressed archive payload. An attacker who supplies
/// an archive plus its passphrase ("verify this backup") could otherwise feed
/// a zstd bomb that expands to many GiB and OOM-kills `inspect`/`verify`.
const MAX_DECOMPRESSED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Decompress a zstd stream, refusing payloads larger than `limit` instead of
/// buffering the whole (potentially hostile) expansion in memory.
fn decompress_bounded(compressed: Vec<u8>, limit: u64) -> Result<Vec<u8>, ArchiveError> {
    let decoder = zstd::stream::read::Decoder::new(Cursor::new(compressed))
        .map_err(|error| ArchiveError::Decrypt(error.to_string()))?;
    let mut payload = Vec::new();
    decoder
        .take(limit + 1)
        .read_to_end(&mut payload)
        .map_err(|error| ArchiveError::Decrypt(error.to_string()))?;
    if payload.len() as u64 > limit {
        return Err(ArchiveError::Format(
            "decompressed archive exceeds the maximum allowed size".to_string(),
        ));
    }
    Ok(payload)
}

/// Read, decrypt, decompress, and decode an archive in a single pass. All
/// public entry points share this so the file is only read and decrypted once.
fn decode_archive(
    path: impl AsRef<Path>,
    passphrase: &str,
) -> Result<(OpenedArchive, ArchiveManifest), ArchiveError> {
    let bytes = std::fs::read(path).map_err(ArchiveError::Io)?;
    let compressed = decrypt_payload(&bytes, passphrase)?;
    let payload = decompress_bounded(compressed, MAX_DECOMPRESSED_BYTES)?;
    decode_tar_payload(&payload)
}

pub fn open_archive(
    path: impl AsRef<Path>,
    passphrase: &str,
) -> Result<OpenedArchive, ArchiveError> {
    decode_archive(path, passphrase).map(|(opened, _manifest)| opened)
}

/// Open an archive and run semantic verification from the SAME decode, so
/// `restore` no longer reads and decrypts the file twice (a TOCTOU window
/// where the file could be swapped between the open and the verify). The inner
/// `Result` carries the semantic-validation outcome so callers can keep the
/// dry-run-warns / apply-fails distinction.
pub fn open_and_verify_archive(
    path: impl AsRef<Path>,
    passphrase: &str,
) -> Result<(OpenedArchive, Result<(), ArchiveError>), ArchiveError> {
    let (opened, _manifest) = decode_archive(path, passphrase)?;
    let verification = validate_archive_semantics(&opened);
    Ok((opened, verification))
}

pub fn verify_archive(
    path: impl AsRef<Path>,
    passphrase: &str,
) -> Result<ArchiveManifest, ArchiveError> {
    let (opened, manifest) = decode_archive(path, passphrase)?;
    validate_archive_semantics(&opened)?;
    Ok(manifest)
}

pub fn summarize_archive(
    path: impl AsRef<Path>,
    passphrase: &str,
) -> Result<ArchiveSummary, ArchiveError> {
    let (opened, manifest) = decode_archive(path, passphrase)?;
    let counts = opened.vault.object_counts();

    Ok(ArchiveSummary {
        format_version: manifest.format_version,
        source_backend: opened.vault.metadata.source_backend,
        source_server: opened.vault.metadata.source_server,
        created_at: opened.vault.metadata.created_at,
        folder_count: counts.folders,
        item_count: counts.items,
        attachment_count: counts.attachments,
        warning_count: counts.warnings,
        complete: opened.vault.report.complete,
    })
}

fn encode_tar_payload(
    vault: &Vault,
    attachments: &[ArchiveAttachment],
    progress: &dyn ProgressReporter,
) -> Result<Vec<u8>, ArchiveError> {
    let vault_json = serde_json::to_vec_pretty(vault)?;
    let manifest = ArchiveManifest {
        format_version: 1,
        payload_checksum: payload_checksum(&vault_json, attachments),
        attachment_count: attachments.len(),
    };
    let manifest_json = serde_json::to_vec_pretty(&manifest)?;

    let mut payload = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut payload);
        append_bytes(&mut builder, "manifest.json", &manifest_json)?;
        append_bytes(&mut builder, "vault.json", &vault_json)?;
        let total_attachments = attachments.len() as u64;
        if total_attachments > 0 {
            progress.counted("encoding attachments", 0, total_attachments);
        }
        let mut encoded_attachments = 0;
        for attachment in attachments {
            append_bytes(&mut builder, &attachment.path, &attachment.bytes)?;
            encoded_attachments += 1;
            progress.counted(
                "encoding attachments",
                encoded_attachments,
                total_attachments,
            );
        }
        builder.finish()?;
    }
    Ok(payload)
}

fn decode_tar_payload(payload: &[u8]) -> Result<(OpenedArchive, ArchiveManifest), ArchiveError> {
    // Bound the entry count so a hostile payload cannot force unbounded work
    // through a flood of tiny tar headers. The decompressed payload is already
    // size-capped, so cumulative entry bytes are bounded too.
    const MAX_TAR_ENTRIES: usize = 10_000_000;

    let mut manifest_bytes = None;
    let mut vault_bytes = None;
    let mut attachments = Vec::new();
    let mut attachment_paths = BTreeSet::<String>::new();
    let mut entry_count = 0usize;
    let mut archive = tar::Archive::new(Cursor::new(payload));
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type().is_dir() {
            continue;
        }
        entry_count += 1;
        if entry_count > MAX_TAR_ENTRIES {
            return Err(ArchiveError::Format(
                "archive contains too many entries".to_string(),
            ));
        }
        let path = entry
            .path()
            .map_err(|error| ArchiveError::Format(error.to_string()))?
            .to_string_lossy()
            .into_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        match path.as_str() {
            "manifest.json" => {
                if manifest_bytes.is_some() {
                    return Err(ArchiveError::Format("duplicate manifest.json".to_string()));
                }
                manifest_bytes = Some(bytes);
            }
            "vault.json" => {
                if vault_bytes.is_some() {
                    return Err(ArchiveError::Format("duplicate vault.json".to_string()));
                }
                vault_bytes = Some(bytes);
            }
            _ => {
                if !attachment_paths.insert(path.clone()) {
                    return Err(ArchiveError::Format(format!(
                        "duplicate attachment payload `{path}`"
                    )));
                }
                attachments.push(ArchiveAttachment { path, bytes });
            }
        }
    }

    let manifest_bytes =
        manifest_bytes.ok_or_else(|| ArchiveError::Format("missing manifest.json".to_string()))?;
    let vault_bytes =
        vault_bytes.ok_or_else(|| ArchiveError::Format("missing vault.json".to_string()))?;
    let manifest: ArchiveManifest = serde_json::from_slice(&manifest_bytes)?;
    let vault_json = String::from_utf8(vault_bytes.clone())
        .map_err(|_| ArchiveError::Format("invalid vault.json utf-8".to_string()))?;
    let vault = Vault::from_json(&vault_json)?;

    if manifest.attachment_count != attachments.len() {
        return Err(ArchiveError::Integrity(format!(
            "manifest attachment count {} but decoded {} attachment payloads",
            manifest.attachment_count,
            attachments.len()
        )));
    }

    let actual_checksum = payload_checksum(&vault_bytes, &attachments);
    if actual_checksum != manifest.payload_checksum {
        return Err(ArchiveError::Integrity(format!(
            "manifest payload checksum {} but decoded payload checksum {}",
            manifest.payload_checksum, actual_checksum
        )));
    }

    Ok((OpenedArchive { vault, attachments }, manifest))
}

fn append_bytes(
    builder: &mut tar::Builder<&mut Vec<u8>>,
    path: &str,
    bytes: &[u8],
) -> Result<(), ArchiveError> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o600);
    header.set_cksum();
    builder.append_data(&mut header, path, Cursor::new(bytes))?;
    Ok(())
}

fn encrypt_payload(payload: &[u8], passphrase: &str) -> Result<Vec<u8>, ArchiveError> {
    let passphrase = SecretString::from(passphrase.to_owned());
    let encryptor = age::Encryptor::with_user_passphrase(passphrase);
    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|error| ArchiveError::Encrypt(error.to_string()))?;
    writer
        .write_all(payload)
        .map_err(|error| ArchiveError::Encrypt(error.to_string()))?;
    writer
        .finish()
        .map_err(|error| ArchiveError::Encrypt(error.to_string()))?;
    Ok(encrypted)
}

fn decrypt_payload(payload: &[u8], passphrase: &str) -> Result<Vec<u8>, ArchiveError> {
    let passphrase = SecretString::from(passphrase.to_owned());
    let identity = age::scrypt::Identity::new(passphrase);
    let decryptor =
        age::Decryptor::new(payload).map_err(|error| ArchiveError::Decrypt(error.to_string()))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|error| ArchiveError::Decrypt(error.to_string()))?;
    let mut decrypted = Vec::new();
    reader
        .read_to_end(&mut decrypted)
        .map_err(|error| ArchiveError::Decrypt(error.to_string()))?;
    Ok(decrypted)
}

fn payload_checksum(vault_json: &[u8], attachments: &[ArchiveAttachment]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(vault_json);
    for attachment in attachments {
        hasher.update(attachment.path.as_bytes());
        hasher.update((attachment.bytes.len() as u64).to_le_bytes());
        hasher.update(&attachment.bytes);
    }
    hex::encode(hasher.finalize())
}

fn validate_archive_semantics(opened: &OpenedArchive) -> Result<(), ArchiveError> {
    if !opened.vault.report.complete {
        return Err(ArchiveError::Validation(
            "backup is marked incomplete".to_string(),
        ));
    }

    let mut expected = BTreeMap::<String, &AttachmentRef>::new();
    for item in &opened.vault.items {
        for attachment in &item.attachments {
            expected.insert(attachment.path.clone(), attachment);
        }
    }

    let actual = opened
        .attachments
        .iter()
        .map(|attachment| (attachment.path.clone(), attachment))
        .collect::<BTreeMap<_, _>>();

    for (path, attachment_ref) in &expected {
        let Some(attachment) = actual.get(path) else {
            return Err(ArchiveError::Validation(format!(
                "missing attachment payload `{path}`"
            )));
        };
        if attachment_ref.size != attachment.bytes.len() as u64 {
            return Err(ArchiveError::Validation(format!(
                "attachment size mismatch for `{path}`"
            )));
        }
        if !attachment_ref.sha256.is_empty() {
            let actual_sha = hex::encode(Sha256::digest(&attachment.bytes));
            if attachment_ref.sha256 != actual_sha {
                return Err(ArchiveError::Validation(format!(
                    "attachment sha256 mismatch for `{path}`"
                )));
            }
        }
    }

    for path in actual.keys() {
        if !expected.contains_key(path) {
            return Err(ArchiveError::Validation(format!(
                "orphan attachment payload `{path}`"
            )));
        }
    }

    Ok(())
}

pub fn validate_passphrase_strength(passphrase: &str) -> Result<(), ArchiveError> {
    let passphrase = passphrase.trim();
    let lower = passphrase.to_lowercase();
    let common = [
        "password",
        "passphrase",
        "bitwarden",
        "vaultwarden",
        "backup",
        "test passphrase",
    ];

    if common.contains(&lower.as_str()) {
        return Err(ArchiveError::WeakPassphrase(
            "it is a common or predictable passphrase".to_string(),
        ));
    }
    if passphrase.chars().count() < 20 {
        return Err(ArchiveError::WeakPassphrase(
            "it must be at least 20 characters".to_string(),
        ));
    }
    if all_same_character(passphrase) {
        return Err(ArchiveError::WeakPassphrase(
            "it repeats one character".to_string(),
        ));
    }

    // Passphrase-of-words path: require enough *distinct* words and length so
    // degenerate inputs like "aaaa aaaa aaaa aaaaaaaaaa" don't slip through.
    let words = passphrase.split_whitespace().collect::<Vec<_>>();
    let distinct_words = words
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    if words.len() >= 4 && distinct_words >= 3 && passphrase.chars().count() >= 24 {
        return Ok(());
    }

    let categories = [
        passphrase
            .chars()
            .any(|character| character.is_ascii_lowercase()),
        passphrase
            .chars()
            .any(|character| character.is_ascii_uppercase()),
        passphrase
            .chars()
            .any(|character| character.is_ascii_digit()),
        passphrase
            .chars()
            .any(|character| !character.is_ascii_alphanumeric()),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();

    if categories < 3 {
        return Err(ArchiveError::WeakPassphrase(
            "use 4+ random words or 20+ characters with mixed character types".to_string(),
        ));
    }

    Ok(())
}

fn all_same_character(passphrase: &str) -> bool {
    let mut chars = passphrase.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    chars.all(|character| character == first)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zstd_compress(bytes: &[u8]) -> Vec<u8> {
        zstd::stream::encode_all(Cursor::new(bytes.to_vec()), 0).expect("compress")
    }

    #[test]
    fn decompress_bounded_accepts_payload_within_limit() {
        let compressed = zstd_compress(&vec![0u8; 1024]);
        let payload = decompress_bounded(compressed, 4096).expect("within limit");
        assert_eq!(payload.len(), 1024);
    }

    #[test]
    fn decompress_bounded_rejects_payload_over_limit() {
        // A highly compressible buffer that expands well past a small limit:
        // the bound must reject it rather than buffering the whole expansion.
        let compressed = zstd_compress(&vec![0u8; 1_000_000]);
        let error = decompress_bounded(compressed, 1024).expect_err("over limit");
        assert!(matches!(error, ArchiveError::Format(_)));
    }

    fn staged(dir: &Path) -> StagedArchive {
        StagedArchive::write(&dir.join("backup.yabbt"), b"archive-bytes").expect("stage")
    }

    /// Some file systems (FUSE, network mounts) reject fsync on a directory
    /// with EINVAL/ENOTSUP. The rename already published the archive, so
    /// that must not be reported as a failed write.
    #[test]
    fn publish_succeeds_when_directory_fsync_is_unsupported() {
        for errno in [errno::EINVAL, errno::ENOTSUP, errno::EOPNOTSUPP] {
            let temp = tempfile::tempdir().expect("tempdir");
            let destination = temp.path().join("backup.yabbt");
            staged(temp.path())
                .publish_with(WriteMode::CreateNew, |_| {
                    Err(std::io::Error::from_raw_os_error(errno))
                })
                .expect("published despite unsupported directory fsync");
            assert_eq!(std::fs::read(&destination).expect("read"), b"archive-bytes");
        }
    }

    #[test]
    fn publish_reports_other_directory_fsync_errors() {
        let temp = tempfile::tempdir().expect("tempdir");
        let error = staged(temp.path())
            .publish_with(WriteMode::CreateNew, |_| {
                Err(std::io::Error::from_raw_os_error(errno::EIO))
            })
            .expect_err("a real fsync failure is reported");
        assert!(matches!(error, ArchiveError::Io(_)), "{error}");
    }

    /// FUSE mounts without renameat2 or hard links make the no-clobber
    /// publish fail with a bare "Function not implemented" or "Operation
    /// not permitted": the error must say why and what to do instead.
    #[test]
    fn no_clobber_publish_errors_explain_unsupported_file_systems() {
        for errno in [errno::ENOSYS, errno::EPERM, errno::EOPNOTSUPP] {
            let error = publish_error(
                std::io::Error::from_raw_os_error(errno),
                WriteMode::CreateNew,
            )
            .to_string();
            assert!(
                error.contains("does not support no-clobber rename"),
                "{error}"
            );
            assert!(error.contains("--overwrite"), "{error}");
        }
        let exists = publish_error(
            std::io::Error::from(std::io::ErrorKind::AlreadyExists),
            WriteMode::CreateNew,
        );
        assert!(!exists.to_string().contains("--overwrite"), "{exists}");
        match exists {
            ArchiveError::Io(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists)
            }
            other => panic!("unexpected {other:?}"),
        }
        let overwrite = publish_error(
            std::io::Error::from_raw_os_error(errno::EPERM),
            WriteMode::Overwrite,
        );
        assert!(
            !overwrite.to_string().contains("--overwrite"),
            "{overwrite}"
        );
    }
}

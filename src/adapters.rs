pub mod bitwarden_json;
pub mod bw;
pub mod command;
pub mod keepass;

use crate::archive::ArchiveAttachment;
use crate::model::Vault;
use crate::progress::ProgressReporter;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultExport {
    pub vault: Vault,
    pub attachments: Vec<ArchiveAttachment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendCapabilities {
    pub read_items: bool,
    pub write_items: bool,
    pub read_attachments: bool,
    pub write_attachments: bool,
    pub organizations: bool,
    pub sends: bool,
    pub passkeys: bool,
    pub ssh_keys: bool,
    pub strict_restore: bool,
}

pub trait VaultSource {
    fn name(&self) -> &str;
    fn capabilities(&self) -> BackendCapabilities;
    fn export(&self) -> Result<VaultExport, AdapterError>;
}

/// A backup source a backend exposes to the CLI: a progress-aware full
/// export of the vault including attachment bytes.
pub trait BackupSource {
    fn backend_name(&self) -> &'static str;
    fn export_with_progress(
        &self,
        progress: &dyn ProgressReporter,
    ) -> Result<VaultExport, AdapterError>;
}

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("{0}")]
    Message(String),
    /// A KeePass attachment removal the keepass library cannot carry out
    /// without losing a file that entry history still references. Nothing
    /// was changed; restore apply skips such a delete and reports it.
    #[error("{0}")]
    KeptByHistory(String),
    #[error("command `{program}` failed with status {status}: {stderr}")]
    CommandFailed {
        program: String,
        status: i32,
        stderr: String,
    },
    #[error("adapter I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("adapter JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

impl BackendCapabilities {
    pub fn to_wire(&self) -> String {
        format!(
            "read_items={};write_items={};read_attachments={};write_attachments={};organizations={};sends={};passkeys={};ssh_keys={};strict_restore={}",
            self.read_items,
            self.write_items,
            self.read_attachments,
            self.write_attachments,
            self.organizations,
            self.sends,
            self.passkeys,
            self.ssh_keys,
            self.strict_restore
        )
    }
}

impl AdapterError {
    pub fn new(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }
}

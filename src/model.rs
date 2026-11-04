use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    pub metadata: VaultMetadata,
    pub folders: Vec<Folder>,
    pub items: Vec<VaultItem>,
    pub report: CompletenessReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMetadata {
    pub archive_version: u32,
    pub source_backend: String,
    pub source_server: Option<String>,
    pub created_at: String,
    pub tool_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Folder {
    pub id: String,
    pub name: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultItem {
    pub id: String,
    pub kind: ItemKind,
    pub name: String,
    pub notes: Option<String>,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub fields: Vec<Field>,
    pub attachments: Vec<AttachmentRef>,
    pub backend_metadata: Vec<(String, String)>,
}

// Redact secret-bearing fields (notes, and the verbatim backend payload which
// includes the raw item JSON) while keeping structural fields useful for
// debugging. Prevents an accidental `{:?}` from dumping vault secrets.
impl std::fmt::Debug for VaultItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultItem")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("name", &self.name)
            .field("notes", &self.notes.as_ref().map(|_| "<redacted>"))
            .field("folder_id", &self.folder_id)
            .field("favorite", &self.favorite)
            .field("fields", &self.fields)
            .field("attachments", &self.attachments)
            .field(
                "backend_metadata",
                &format_args!("<{} entries redacted>", self.backend_metadata.len()),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ItemKind {
    Login {
        username: String,
        password: String,
        uris: Vec<String>,
        totp: Option<String>,
    },
    SecureNote,
    Card,
    Identity,
    SshKey,
    /// An item type yabbt does not model (a future Bitwarden type, or a
    /// missing/invalid type). A struct variant because serde's internally
    /// tagged representation cannot serialize a newtype variant around a
    /// string; archives never contained the old shape since it could not be
    /// written.
    Unknown {
        kind: String,
    },
}

// Redact username/password/totp; keep the variant and URI count for debugging.
impl std::fmt::Debug for ItemKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ItemKind::Login { uris, totp, .. } => f
                .debug_struct("Login")
                .field("username", &"<redacted>")
                .field("password", &"<redacted>")
                .field("uri_count", &uris.len())
                .field("totp", &totp.as_ref().map(|_| "<redacted>"))
                .finish(),
            ItemKind::SecureNote => f.write_str("SecureNote"),
            ItemKind::Card => f.write_str("Card"),
            ItemKind::Identity => f.write_str("Identity"),
            ItemKind::SshKey => f.write_str("SshKey"),
            ItemKind::Unknown { kind } => f.debug_struct("Unknown").field("kind", kind).finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub value: String,
    pub hidden: bool,
}

// Field values include hidden custom-field secrets; show name/hidden only.
impl std::fmt::Debug for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Field")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .field("hidden", &self.hidden)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentRef {
    pub id: String,
    pub file_name: String,
    pub size: u64,
    pub sha256: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletenessReport {
    pub complete: bool,
    pub warnings: Vec<Warning>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Warning {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectCounts {
    pub folders: usize,
    pub items: usize,
    pub attachments: usize,
    pub warnings: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("failed to serialize vault model: {0}")]
    Serialize(#[from] serde_json::Error),
}

impl Vault {
    pub fn object_counts(&self) -> ObjectCounts {
        ObjectCounts {
            folders: self.folders.len(),
            items: self.items.len(),
            attachments: self.items.iter().map(|item| item.attachments.len()).sum(),
            warnings: self.report.warnings.len(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("vault model serialization is infallible")
    }

    pub fn from_json(input: &str) -> Result<Self, ModelError> {
        serde_json::from_str(input).map_err(ModelError::Serialize)
    }
}

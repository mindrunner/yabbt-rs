use super::AdapterError;
use crate::model::{
    AttachmentRef, CompletenessReport, Field, Folder, ItemKind, Vault, VaultItem, VaultMetadata,
    Warning,
};
use chrono::Utc;
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Deserialize)]
struct ExportFile {
    #[serde(default)]
    folders: Vec<BwFolder>,
    #[serde(default)]
    items: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct BwFolder {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BwItem {
    id: String,
    folder_id: Option<String>,
    #[serde(default)]
    r#type: u8,
    name: String,
    notes: Option<String>,
    #[serde(default)]
    favorite: bool,
    login: Option<BwLogin>,
    #[serde(default)]
    fields: Vec<BwField>,
}

#[derive(Debug, Deserialize)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    #[serde(default)]
    uris: Vec<BwUri>,
}

#[derive(Debug, Deserialize)]
struct BwUri {
    uri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BwField {
    name: Option<String>,
    value: Option<String>,
    #[serde(default)]
    r#type: u8,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListedItem {
    id: String,
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default)]
    attachments: Vec<ListedAttachment>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListedAttachment {
    id: String,
    file_name: String,
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    size: Option<u64>,
}

/// Warning code: organization items are visible to the account but not in
/// this personal-scope export. Marks the report incomplete.
pub const ORG_ITEMS_NOT_EXPORTED: &str = "org-items-not-exported";
/// Warning code: the same situation, explicitly accepted with
/// `--personal-only`. Informational; the report stays complete.
pub const ORG_ITEMS_EXCLUDED_BY_SCOPE: &str = "org-items-excluded-by-scope";

/// Accept a personal-vault-only scope for a report produced by
/// [`normalize_export`]: every `org-items-not-exported` warning becomes an
/// informational `org-items-excluded-by-scope` warning carrying the same
/// count, and the report is complete again unless another warning still
/// marks it incomplete. Apply this right after `normalize_export`, before
/// any other step can add warnings.
pub fn accept_personal_only_scope(report: &mut CompletenessReport) {
    let mut accepted = false;
    for warning in &mut report.warnings {
        if warning.code != ORG_ITEMS_NOT_EXPORTED {
            continue;
        }
        // The count is the leading number of the message built above.
        let count = warning
            .message
            .split_whitespace()
            .next()
            .and_then(|count| count.parse::<usize>().ok());
        let items = match count {
            Some(count) => format!("{count} organization item(s)"),
            None => "organization items".to_string(),
        };
        warning.code = ORG_ITEMS_EXCLUDED_BY_SCOPE.to_string();
        warning.message = format!(
            "{items} visible to this account are excluded by --personal-only: this archive \
             covers the personal vault only; back up each organization separately with \
             --organization-id <org-id>"
        );
        accepted = true;
    }
    // normalize_export marks a report incomplete only for unexported org
    // items, so once those are accepted the report is complete again.
    if accepted
        && report
            .warnings
            .iter()
            .all(|warning| warning.code == ORG_ITEMS_EXCLUDED_BY_SCOPE)
    {
        report.complete = true;
    }
}

pub fn normalize_export(
    export_json: &str,
    listed_items_json: &str,
    source_backend: &str,
    source_server: Option<&str>,
) -> Result<Vault, AdapterError> {
    let export: ExportFile = serde_json::from_str(export_json)?;
    let listed_items: Vec<ListedItem> = serde_json::from_str(listed_items_json)?;
    let mut report = CompletenessReport {
        complete: true,
        warnings: Vec::new(),
    };
    // `bw export` without `--organizationid` covers only the personal vault,
    // but `bw list items` also returns every organization item the account
    // can see. Flag those instead of reporting a silently partial backup as
    // complete. Only a count is reported: no names, item IDs, or org IDs.
    let exported_ids = export
        .items
        .iter()
        .filter_map(|item| item.get("id").and_then(Value::as_str))
        .collect::<HashSet<_>>();
    let unexported_org_items = listed_items
        .iter()
        .filter(|item| {
            item.organization_id
                .as_deref()
                .is_some_and(|organization_id| !organization_id.is_empty())
                && !exported_ids.contains(item.id.as_str())
        })
        .count();
    if unexported_org_items > 0 {
        report.complete = false;
        report.warnings.push(Warning {
            code: ORG_ITEMS_NOT_EXPORTED.to_string(),
            message: format!(
                "{unexported_org_items} organization item(s) visible to this account are not in \
                 this export: a personal-vault backup does not include organization items; pass \
                 --personal-only to accept a personal-vault-only archive, or back up each \
                 organization separately with --organization-id <org-id>"
            ),
        });
    }
    let attachments_by_item = listed_items
        .into_iter()
        .map(|item| (item.id, item.attachments))
        .collect::<HashMap<_, _>>();

    let folders = export
        .folders
        .into_iter()
        .map(|folder| Folder {
            id: folder.id,
            name: folder.name,
        })
        .collect();

    let mut items = Vec::with_capacity(export.items.len());
    for raw_item in export.items {
        let item: BwItem = serde_json::from_value(raw_item.clone())?;
        let attachments = attachments_by_item
            .get(&item.id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|attachment| AttachmentRef {
                path: format!("attachments/{}/{}.bin", item.id, attachment.id),
                id: attachment.id,
                file_name: attachment.file_name,
                size: attachment.size.unwrap_or_default(),
                sha256: String::new(),
            })
            .collect();
        let kind = item_kind(&item);

        items.push(VaultItem {
            id: item.id,
            kind,
            name: item.name,
            notes: item.notes,
            folder_id: item.folder_id,
            favorite: item.favorite,
            fields: item
                .fields
                .into_iter()
                .filter_map(|field| {
                    Some(Field {
                        name: field.name?,
                        value: field.value.unwrap_or_default(),
                        hidden: field.r#type == 1,
                    })
                })
                .collect(),
            attachments,
            backend_metadata: vec![(
                "bitwarden.raw".to_string(),
                serde_json::to_string(&raw_item).expect("raw item serializes"),
            )],
        });
    }

    Ok(Vault {
        metadata: VaultMetadata {
            archive_version: 1,
            source_backend: source_backend.to_string(),
            source_server: source_server.map(str::to_string),
            created_at: Utc::now().to_rfc3339(),
            tool_version: crate::VERSION.to_string(),
        },
        folders,
        items,
        report,
    })
}

fn item_kind(item: &BwItem) -> ItemKind {
    match item.r#type {
        1 => {
            let login = item.login.as_ref();
            ItemKind::Login {
                username: login
                    .and_then(|login| login.username.clone())
                    .unwrap_or_default(),
                password: login
                    .and_then(|login| login.password.clone())
                    .unwrap_or_default(),
                uris: login
                    .map(|login| {
                        login
                            .uris
                            .iter()
                            .filter_map(|uri| uri.uri.clone())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
                totp: login.and_then(|login| login.totp.clone()),
            }
        }
        2 => ItemKind::SecureNote,
        3 => ItemKind::Card,
        4 => ItemKind::Identity,
        5 => ItemKind::SshKey,
        other => ItemKind::Unknown {
            kind: format!("bitwarden-type-{other}"),
        },
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

fn deserialize_optional_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => number
            .as_u64()
            .map(Some)
            .ok_or_else(|| serde::de::Error::custom("attachment size must be an unsigned integer")),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        // Parse the numeric string live `bw` sometimes returns, but on failure
        // report only that parsing failed — never echo the raw value, which is
        // attacker/backend-controlled input.
        Some(Value::String(value)) => value.parse::<u64>().map(Some).map_err(|_| {
            serde::de::Error::custom("attachment size string is not an unsigned integer")
        }),
        Some(other) => Err(serde::de::Error::custom(format!(
            "attachment size must be an unsigned integer or string, got {}",
            json_type_name(&other)
        ))),
    }
}

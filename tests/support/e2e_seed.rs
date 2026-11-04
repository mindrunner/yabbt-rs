use crate::support::E2eResult;
use crate::support::bw_live::{BwAccount, write_attachment_file};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;
use yabbt::diff::stable_fingerprint;
use yabbt::model::{ItemKind, Vault, VaultItem};
use yabbt::restore_map::is_restore_map_item;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultShape {
    pub folders: usize,
    pub items: usize,
    pub attachments: usize,
    pub login_items: usize,
    pub secure_notes: usize,
    pub cards: usize,
    pub identities: usize,
    pub favorite_items: usize,
    pub custom_fields: usize,
    pub hidden_fields: usize,
    pub item_signatures: Vec<String>,
}

pub fn seed_source_account(account: &BwAccount, temp_dir: &Path) -> E2eResult<VaultShape> {
    let infra_folder = account.create_folder("YABBT E2E Infrastructure")?;
    let duplicates_folder = account.create_folder("YABBT E2E Duplicate Names")?;

    let primary_login = account.create_item(json!({
        "type": 1,
        "name": "YABBT E2E Login Primary",
        "notes": "synthetic note: primary login",
        "favorite": true,
        "folderId": infra_folder,
        "login": {
            "username": "source-user@example.test",
            "password": "synthetic-password-primary",
            "totp": "otpauth://totp/yabbt-e2e?secret=JBSWY3DPEHPK3PXP&issuer=yabbt",
            "uris": [
                { "match": 0, "uri": "https://service-a.example.test/login" },
                { "match": 1, "uri": "https://service-a-alt.example.test/login" }
            ]
        },
        "fields": [
            { "name": "environment", "value": "e2e", "type": 0 },
            { "name": "recovery-code", "value": "synthetic-recovery-code", "type": 1 }
        ]
    }))?;
    let attachment_path = write_attachment_file(
        temp_dir,
        "yabbt-e2e-recovery.txt",
        b"synthetic yabbt e2e attachment\n",
    )?;
    account.create_attachment(&primary_login, &attachment_path)?;

    account.create_item(json!({
        "type": 1,
        "name": "YABBT E2E Duplicate Login",
        "notes": "synthetic duplicate in infra folder",
        "folderId": infra_folder,
        "login": {
            "username": "duplicate-one@example.test",
            "password": "synthetic-password-duplicate-one",
            "uris": [{ "match": 0, "uri": "https://duplicate.example.test/one" }]
        }
    }))?;

    account.create_item(json!({
        "type": 1,
        "name": "YABBT E2E Duplicate Login",
        "notes": "synthetic duplicate in named folder",
        "folderId": duplicates_folder,
        "login": {
            "username": "duplicate-two@example.test",
            "password": "synthetic-password-duplicate-two",
            "uris": [{ "match": 0, "uri": "https://duplicate.example.test/two" }]
        }
    }))?;

    for index in 0..10 {
        account.create_item(json!({
            "type": 1,
            "name": format!("YABBT E2E Service Login {index:02}"),
            "notes": format!("synthetic service login {index:02}"),
            "folderId": infra_folder,
            "login": {
                "username": format!("service-{index:02}@example.test"),
                "password": format!("synthetic-service-password-{index:02}"),
                "uris": [{ "match": 0, "uri": format!("https://service-{index:02}.example.test/login") }]
            },
            "fields": [{ "name": "service-index", "value": index.to_string(), "type": 0 }]
        }))?;
    }

    account.create_item(json!({
        "type": 2,
        "name": "YABBT E2E Secure Note",
        "notes": "synthetic secure note body",
        "folderId": infra_folder,
        "secureNote": { "type": 0 },
        "fields": [{ "name": "note-field", "value": "synthetic-note-field", "type": 0 }]
    }))?;

    account.create_item(json!({
        "type": 3,
        "name": "YABBT E2E Card",
        "notes": "synthetic card item",
        "card": {
            "cardholderName": "Yabbt Test",
            "brand": "Visa",
            "number": "4111111111111111",
            "expMonth": "01",
            "expYear": "2030",
            "code": "123"
        }
    }))?;

    account.create_item(json!({
        "type": 4,
        "name": "YABBT E2E Identity",
        "notes": "synthetic identity item",
        "identity": {
            "title": "Mx",
            "firstName": "Yabbt",
            "lastName": "Tester",
            "email": "identity@example.test"
        }
    }))?;

    account.sync()?;
    semantic_shape(&account.export_vault()?)
}

pub fn semantic_shape(vault: &Vault) -> E2eResult<VaultShape> {
    let folder_names = vault
        .folders
        .iter()
        .map(|folder| (folder.id.as_str(), secret_hash(&folder.name)))
        .collect::<BTreeMap<_, _>>();
    let restorable_items = vault
        .items
        .iter()
        .filter(|item| !is_restore_map_item(item))
        .collect::<Vec<_>>();

    let mut shape = VaultShape {
        folders: vault.folders.len(),
        items: restorable_items.len(),
        attachments: restorable_items
            .iter()
            .map(|item| item.attachments.len())
            .sum(),
        login_items: 0,
        secure_notes: 0,
        cards: 0,
        identities: 0,
        favorite_items: restorable_items.iter().filter(|item| item.favorite).count(),
        custom_fields: restorable_items.iter().map(|item| item.fields.len()).sum(),
        hidden_fields: restorable_items
            .iter()
            .flat_map(|item| &item.fields)
            .filter(|field| field.hidden)
            .count(),
        item_signatures: Vec::with_capacity(restorable_items.len()),
    };

    for item in restorable_items {
        match item.kind {
            ItemKind::Login { .. } => shape.login_items += 1,
            ItemKind::SecureNote => shape.secure_notes += 1,
            ItemKind::Card => shape.cards += 1,
            ItemKind::Identity => shape.identities += 1,
            ItemKind::SshKey | ItemKind::Unknown { .. } => {}
        }
        shape
            .item_signatures
            .push(item_signature(item, &folder_names)?);
    }
    shape.item_signatures.sort();
    Ok(shape)
}

fn item_signature(item: &VaultItem, folder_names: &BTreeMap<&str, String>) -> E2eResult<String> {
    let fields = item
        .fields
        .iter()
        .map(|field| {
            json!({
                "name_hash": secret_hash(&field.name),
                "value_hash": secret_hash(&field.value),
                "hidden": field.hidden,
            })
        })
        .collect::<Vec<_>>();
    let attachments = item
        .attachments
        .iter()
        .map(|attachment| {
            json!({
                "file_name_hash": secret_hash(&attachment.file_name),
                "size": attachment.size,
            })
        })
        .collect::<Vec<_>>();
    let kind = match &item.kind {
        ItemKind::Login {
            username,
            password,
            uris,
            totp,
        } => json!({
            "type": "login",
            "username_hash": secret_hash(username),
            "password_hash": secret_hash(password),
            "uri_hashes": uris.iter().map(|uri| secret_hash(uri)).collect::<Vec<_>>(),
            "totp_hash": totp.as_ref().map(|value| secret_hash(value)),
        }),
        ItemKind::SecureNote => json!({ "type": "secure_note" }),
        ItemKind::Card => json!({ "type": "card" }),
        ItemKind::Identity => json!({ "type": "identity" }),
        ItemKind::SshKey => json!({ "type": "ssh_key" }),
        ItemKind::Unknown { kind } => json!({ "type": "unknown", "kind_hash": secret_hash(kind) }),
    };
    let signature = json!({
        "name_hash": secret_hash(&item.name),
        "notes_hash": item.notes.as_ref().map(|value| secret_hash(value)),
        "folder_name_hash": item.folder_id.as_deref().and_then(|id| folder_names.get(id)),
        "favorite": item.favorite,
        "fields": fields,
        "attachments": attachments,
        "kind": kind,
        "raw_detail_hash": raw_detail_hash(item)?,
    });
    Ok(stable_fingerprint(&serde_json::to_vec(&signature)?))
}

fn secret_hash(value: &str) -> String {
    stable_fingerprint(value.as_bytes())
}

fn raw_detail_hash(item: &VaultItem) -> E2eResult<Option<String>> {
    let Some((_, raw)) = item
        .backend_metadata
        .iter()
        .find(|(key, _)| key == "bitwarden.raw")
    else {
        return Ok(None);
    };
    let raw: serde_json::Value = serde_json::from_str(raw)?;
    let detail = match item.kind {
        ItemKind::Card => raw.get("card"),
        ItemKind::Identity => raw.get("identity"),
        ItemKind::SshKey => raw.get("sshKey"),
        ItemKind::Unknown { .. } => Some(&raw),
        ItemKind::Login { .. } | ItemKind::SecureNote => None,
    };
    match detail {
        Some(value) => Ok(Some(secret_hash(&serde_json::to_string(value)?))),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::semantic_shape;
    use yabbt::model::{
        CompletenessReport, Field, Folder, ItemKind, Vault, VaultItem, VaultMetadata,
    };

    #[test]
    fn semantic_shape_excludes_restore_map_items() {
        let vault = Vault {
            metadata: VaultMetadata {
                archive_version: 1,
                source_backend: "test".to_string(),
                source_server: None,
                created_at: "now".to_string(),
                tool_version: "test".to_string(),
            },
            folders: vec![Folder {
                id: "folder-1".to_string(),
                name: "Folder".to_string(),
            }],
            items: vec![
                VaultItem {
                    id: "item-1".to_string(),
                    kind: ItemKind::Login {
                        username: "user".to_string(),
                        password: "pass".to_string(),
                        uris: vec!["https://example.test".to_string()],
                        totp: None,
                    },
                    name: "Login".to_string(),
                    notes: None,
                    folder_id: Some("folder-1".to_string()),
                    favorite: true,
                    fields: Vec::new(),
                    attachments: Vec::new(),
                    backend_metadata: Vec::new(),
                },
                VaultItem {
                    id: "map".to_string(),
                    kind: ItemKind::SecureNote,
                    name: "yabbt restore map - do not edit".to_string(),
                    notes: Some("Managed by yabbt. Do not edit.".to_string()),
                    folder_id: None,
                    favorite: false,
                    fields: vec![Field {
                        name: "yabbt.restore_map".to_string(),
                        value: r#"{"version":1,"entries":{}}"#.to_string(),
                        hidden: true,
                    }],
                    attachments: Vec::new(),
                    backend_metadata: Vec::new(),
                },
            ],
            report: CompletenessReport {
                complete: true,
                warnings: Vec::new(),
            },
        };

        let shape = semantic_shape(&vault).expect("shape");

        assert_eq!(shape.items, 1);
        assert_eq!(shape.login_items, 1);
        assert_eq!(shape.favorite_items, 1);
    }
}

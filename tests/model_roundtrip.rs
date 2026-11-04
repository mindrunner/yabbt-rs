use yabbt::adapters::BackendCapabilities;
use yabbt::diff::item_fingerprint;
use yabbt::model::{
    AttachmentRef, CompletenessReport, Field, Folder, ItemKind, Vault, VaultItem, VaultMetadata,
};

fn sample_vault() -> Vault {
    Vault {
        metadata: VaultMetadata {
            archive_version: 1,
            source_backend: "fixture".to_string(),
            source_server: Some("https://vault.example.test".to_string()),
            created_at: "2026-05-03T11:30:00Z".to_string(),
            tool_version: "0.1.0".to_string(),
        },
        folders: vec![Folder {
            id: "folder-1".to_string(),
            name: "Infrastructure".to_string(),
        }],
        items: vec![VaultItem {
            id: "item-1".to_string(),
            kind: ItemKind::Login {
                username: "alice".to_string(),
                password: "correct horse battery staple".to_string(),
                uris: vec!["https://example.test".to_string()],
                totp: Some("otpauth://totp/example".to_string()),
            },
            name: "Example".to_string(),
            notes: Some("important note".to_string()),
            folder_id: Some("folder-1".to_string()),
            favorite: true,
            fields: vec![Field {
                name: "env".to_string(),
                value: "prod".to_string(),
                hidden: false,
            }],
            attachments: vec![AttachmentRef {
                id: "attachment-1".to_string(),
                file_name: "recovery.txt".to_string(),
                size: 12,
                sha256: "pending".to_string(),
                path: "attachments/item-1/attachment-1.bin".to_string(),
            }],
            backend_metadata: vec![("bw_id".to_string(), "source-id".to_string())],
        }],
        report: CompletenessReport {
            complete: true,
            warnings: Vec::new(),
        },
    }
}

#[test]
fn vault_model_round_trips_through_json() {
    let vault = sample_vault();

    let json = vault.to_json();
    let restored = Vault::from_json(&json).expect("valid vault json");

    assert_eq!(restored, vault);
    assert_eq!(restored.object_counts().items, 1);
    assert_eq!(restored.object_counts().attachments, 1);
}

#[test]
fn adapter_capabilities_have_stable_wire_format() {
    let capabilities = BackendCapabilities {
        read_items: true,
        write_items: false,
        read_attachments: true,
        write_attachments: false,
        organizations: true,
        sends: false,
        passkeys: false,
        ssh_keys: true,
        strict_restore: false,
    };

    assert_eq!(
        capabilities.to_wire(),
        "read_items=true;write_items=false;read_attachments=true;write_attachments=false;organizations=true;sends=false;passkeys=false;ssh_keys=true;strict_restore=false"
    );
}

#[test]
fn every_item_kind_round_trips_and_fingerprints() {
    for kind in [
        ItemKind::SecureNote,
        ItemKind::Card,
        ItemKind::Identity,
        ItemKind::SshKey,
        ItemKind::Unknown {
            kind: "bitwarden-type-7".to_string(),
        },
    ] {
        let mut vault = sample_vault();
        vault.items[0].kind = kind.clone();

        // Neither serialization nor fingerprinting may panic on any variant.
        let fingerprint = item_fingerprint(&vault.items[0]);
        let restored = Vault::from_json(&vault.to_json()).expect("valid vault json");

        assert_eq!(restored.items[0].kind, kind);
        assert_eq!(item_fingerprint(&restored.items[0]), fingerprint);
    }
}

#[test]
fn unknown_item_kind_has_stable_wire_format() {
    let json = serde_json::to_value(ItemKind::Unknown {
        kind: "bitwarden-type-7".to_string(),
    })
    .expect("unknown kind serializes");

    assert_eq!(
        json,
        serde_json::json!({ "type": "unknown", "kind": "bitwarden-type-7" })
    );
}

#[test]
fn item_fingerprint_is_stable_across_model_round_trip() {
    let vault = sample_vault();
    let before = item_fingerprint(&vault.items[0]);
    let restored = Vault::from_json(&vault.to_json()).expect("valid vault json");
    let after = item_fingerprint(&restored.items[0]);

    assert_eq!(before, after);
}

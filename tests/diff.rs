use yabbt::diff::{DiffStatus, diff_vaults};
use yabbt::model::{CompletenessReport, ItemKind, Vault, VaultItem, VaultMetadata};

#[test]
fn diff_vaults_reports_added_removed_changed_and_unchanged_items() {
    let baseline = vault(vec![
        item("changed", "Old Note"),
        item("removed", "Removed Note"),
        item("same", "Same Note"),
    ]);
    let current = vault(vec![
        item("added", "Added Note"),
        item("changed", "New Note"),
        item("same", "Same Note"),
    ]);

    let report = diff_vaults(&baseline, &current);

    assert_eq!(report.added, vec!["added"]);
    assert_eq!(report.removed, vec!["removed"]);
    assert_eq!(report.changed, vec!["changed"]);
    assert_eq!(report.unchanged_count, 1);
    assert_eq!(report.status(), DiffStatus::Changed);
}

#[test]
fn diff_vaults_reports_unchanged_status_when_items_match() {
    let baseline = vault(vec![item("same", "Same Note")]);
    let current = vault(vec![item("same", "Same Note")]);

    let report = diff_vaults(&baseline, &current);

    assert_eq!(report.status(), DiffStatus::Unchanged);
}

fn vault(items: Vec<VaultItem>) -> Vault {
    Vault {
        metadata: VaultMetadata {
            archive_version: 1,
            source_backend: "fixture".to_string(),
            source_server: None,
            created_at: "2026-05-03T12:00:00Z".to_string(),
            tool_version: "0.1.0".to_string(),
        },
        folders: Vec::new(),
        items,
        report: CompletenessReport {
            complete: true,
            warnings: Vec::new(),
        },
    }
}

fn item(id: &str, note: &str) -> VaultItem {
    VaultItem {
        id: id.to_string(),
        kind: ItemKind::SecureNote,
        name: format!("{id} display name"),
        notes: Some(note.to_string()),
        folder_id: None,
        favorite: false,
        fields: Vec::new(),
        attachments: Vec::new(),
        backend_metadata: Vec::new(),
    }
}

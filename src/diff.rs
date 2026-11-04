use crate::model::{Vault, VaultItem};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffReport {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
    pub unchanged_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffStatus {
    Changed,
    Unchanged,
}

impl DiffReport {
    pub fn status(&self) -> DiffStatus {
        if self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty() {
            DiffStatus::Unchanged
        } else {
            DiffStatus::Changed
        }
    }
}

pub fn diff_vaults(baseline: &Vault, current: &Vault) -> DiffReport {
    let baseline_items = items_by_id(baseline);
    let current_items = items_by_id(current);
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let mut unchanged_count = 0;

    for (id, current_item) in &current_items {
        let Some(baseline_item) = baseline_items.get(id) else {
            added.push(id.clone());
            continue;
        };

        if item_fingerprint(baseline_item) == item_fingerprint(current_item) {
            unchanged_count += 1;
        } else {
            changed.push(id.clone());
        }
    }

    for id in baseline_items.keys() {
        if !current_items.contains_key(id) {
            removed.push(id.clone());
        }
    }

    DiffReport {
        added,
        removed,
        changed,
        unchanged_count,
    }
}

pub fn item_fingerprint(item: &VaultItem) -> String {
    let mut canonical = item.clone();
    canonical.backend_metadata.sort();
    canonical.fields.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.value.cmp(&right.value))
            .then_with(|| left.hidden.cmp(&right.hidden))
    });
    canonical.attachments.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.file_name.cmp(&right.file_name))
            .then_with(|| left.sha256.cmp(&right.sha256))
    });

    let json = serde_json::to_vec(&canonical).expect("vault item serialization is infallible");
    stable_fingerprint(&json)
}

pub fn stable_fingerprint(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn items_by_id(vault: &Vault) -> BTreeMap<String, &VaultItem> {
    vault
        .items
        .iter()
        .map(|item| (item.id.clone(), item))
        .collect()
}

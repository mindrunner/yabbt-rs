use crate::model::{Field, ItemKind, Vault, VaultItem};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const RESTORE_MAP_VERSION: u32 = 1;
pub const RESTORE_MAP_ITEM_NAME: &str = "yabbt restore map - do not edit";
pub const RESTORE_MAP_FIELD_NAME: &str = "yabbt.restore_map";
pub const RESTORE_MAP_NOTE: &str = "Managed by yabbt. Do not edit.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreMap {
    pub version: u32,
    pub entries: BTreeMap<String, RestoreMapEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreMapEntry {
    pub target_item_id: String,
    pub source_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreMapState {
    pub item_id: String,
    pub item_ids: Vec<String>,
    pub map: RestoreMap,
}

#[derive(Debug, thiserror::Error)]
pub enum RestoreMapError {
    #[error("restore map item `{item_id}` has invalid JSON: {source}")]
    InvalidJson {
        item_id: String,
        source: serde_json::Error,
    },
    #[error("restore map item `{item_id}` has unsupported version {version}")]
    UnsupportedVersion { item_id: String, version: u32 },
}

impl RestoreMap {
    pub fn empty() -> Self {
        Self {
            version: RESTORE_MAP_VERSION,
            entries: BTreeMap::new(),
        }
    }
}

pub fn restore_map_state(vault: &Vault) -> Result<Option<RestoreMapState>, RestoreMapError> {
    let mut items = vault
        .items
        .iter()
        .filter(|item| is_restore_map_item(item))
        .collect::<Vec<_>>();
    if items.is_empty() {
        return Ok(None);
    }

    items.sort_by_key(|item| restore_map_chunk_index(&item.name).unwrap_or(usize::MAX));
    let mut item_ids = Vec::new();
    let mut seen_chunk_indexes = BTreeSet::new();
    let mut merged = RestoreMap::empty();
    for item in items {
        let chunk_index = restore_map_chunk_index(&item.name).unwrap_or(usize::MAX);
        if !seen_chunk_indexes.insert(chunk_index) {
            continue;
        }
        item_ids.push(item.id.clone());
        let value = restore_map_field(item)
            .map(|field| field.value.as_str())
            .unwrap_or("{}");
        let map = serde_json::from_str::<RestoreMap>(value).map_err(|source| {
            RestoreMapError::InvalidJson {
                item_id: item.id.clone(),
                source,
            }
        });
        let map = map?;
        if map.version != RESTORE_MAP_VERSION {
            return Err(RestoreMapError::UnsupportedVersion {
                item_id: item.id.clone(),
                version: map.version,
            });
        }

        merged.entries.extend(map.entries);
    }

    Ok(Some(RestoreMapState {
        item_id: item_ids[0].clone(),
        item_ids,
        map: merged,
    }))
}

pub fn is_restore_map_item(item: &VaultItem) -> bool {
    restore_map_chunk_index(&item.name).is_some()
        && matches!(item.kind, ItemKind::SecureNote)
        && restore_map_field(item).is_some()
}

pub fn restore_map_item_name(chunk_index: usize) -> String {
    if chunk_index == 0 {
        RESTORE_MAP_ITEM_NAME.to_string()
    } else {
        format!("{RESTORE_MAP_ITEM_NAME} {}", chunk_index + 1)
    }
}

pub fn restore_map_chunk_index(name: &str) -> Option<usize> {
    if name == RESTORE_MAP_ITEM_NAME {
        return Some(0);
    }
    let suffix = name.strip_prefix(&format!("{RESTORE_MAP_ITEM_NAME} "))?;
    let chunk_number = suffix.parse::<usize>().ok()?;
    (chunk_number >= 2).then_some(chunk_number - 1)
}

pub fn restore_map_field(item: &VaultItem) -> Option<&Field> {
    item.fields
        .iter()
        .find(|field| field.hidden && field.name == RESTORE_MAP_FIELD_NAME)
}

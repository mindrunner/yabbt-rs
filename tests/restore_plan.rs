use std::collections::BTreeMap;
use yabbt::diff::item_fingerprint;
use yabbt::model::{
    AttachmentRef, CompletenessReport, Field, Folder, ItemKind, Vault, VaultItem, VaultMetadata,
};
use yabbt::restore_plan::{
    RestorePlan, RestorePlanOptions, RestorePlanStatus, plan_restore, plan_restore_with_options,
};

#[test]
fn restore_plan_compares_archive_against_target_without_secret_fields() {
    let archive = vault(vec![
        item("create-item", "new archive note"),
        item("same-item", "same note"),
        item("update-item", "archive changed note"),
    ]);
    let target = vault(vec![
        item("same-item", "same note"),
        item("skip-item", "target only note"),
        item("update-item", "older target note"),
    ]);

    let plan = plan_restore(&archive, Some(&target), "bw");

    assert_eq!(plan.status(), RestorePlanStatus::Ready);
    assert_eq!(plan.target_backend, "bw");
    assert!(plan.dry_run);
    assert_eq!(plan.archive_items, 3);
    assert_eq!(plan.target_items_scanned, Some(3));
    assert_eq!(plan.items_to_create, 1);
    assert_eq!(plan.items_to_update, 1);
    assert_eq!(plan.items_unchanged, 1);
    assert_eq!(plan.items_to_skip, 1);
    assert_eq!(plan.attachments_to_upload, 1);
    assert_eq!(plan.create_item_ids, vec!["create-item"]);
    assert_eq!(plan.update_item_ids, vec!["update-item"]);
    assert_eq!(plan.unchanged_item_ids, vec!["same-item"]);
    assert_eq!(plan.skip_item_ids, vec!["skip-item"]);
    assert_eq!(
        plan.matched_target_item_ids,
        BTreeMap::from([
            ("same-item".to_string(), "same-item".to_string()),
            ("update-item".to_string(), "update-item".to_string()),
        ])
    );
    assert!(plan.blockers.is_empty());
}

#[test]
fn restore_plan_with_prune_reports_target_only_items_attachments_and_empty_folders() {
    let mut archive_item = item("archive-item", "same note");
    archive_item.folder_id = Some("archive-folder".to_string());
    archive_item.attachments = vec![AttachmentRef {
        id: "archive-attachment".to_string(),
        file_name: "shared.txt".to_string(),
        size: 13,
        sha256: "shared-sha".to_string(),
        path: "attachments/archive-item/archive-attachment.bin".to_string(),
    }];
    let mut archive = vault(vec![archive_item]);
    archive.folders = vec![Folder {
        id: "archive-folder".to_string(),
        name: "Shared Folder".to_string(),
    }];

    let mut matched_target_item = item("archive-item", "same note");
    matched_target_item.folder_id = Some("target-folder".to_string());
    matched_target_item.attachments = vec![
        AttachmentRef {
            id: "target-shared-attachment".to_string(),
            file_name: "shared.txt".to_string(),
            size: 13,
            sha256: "shared-sha".to_string(),
            path: "attachments/archive-item/target-shared-attachment.bin".to_string(),
        },
        AttachmentRef {
            id: "target-extra-attachment".to_string(),
            file_name: "extra-secret.txt".to_string(),
            size: 9,
            sha256: "extra-sha".to_string(),
            path: "attachments/archive-item/target-extra-attachment.bin".to_string(),
        },
    ];
    let mut target_only_item = item("target-only-item", "target only note");
    target_only_item.folder_id = Some("target-only-folder".to_string());
    let mut target = vault(vec![matched_target_item, target_only_item]);
    target.folders = vec![
        Folder {
            id: "target-folder".to_string(),
            name: "Shared Folder".to_string(),
        },
        Folder {
            id: "target-only-folder".to_string(),
            name: "Target Only Folder".to_string(),
        },
    ];

    let plan = plan_restore_with_options(
        &archive,
        Some(&target),
        "bw",
        RestorePlanOptions {
            target_organization_id: None,
            prune: true,
            prune_permanent: false,
            ..RestorePlanOptions::default()
        },
    );

    assert_eq!(plan.status(), RestorePlanStatus::Ready);
    assert_eq!(plan.items_to_skip, 1);
    assert_eq!(plan.items_to_delete, 1);
    assert_eq!(plan.delete_item_ids, vec!["target-only-item"]);
    assert_eq!(plan.attachments_to_delete, 1);
    assert_eq!(plan.delete_attachment_ids, vec!["target-extra-attachment"]);
    assert_eq!(plan.delete_attachments.len(), 1);
    assert_eq!(plan.delete_attachments[0].target_item_id, "archive-item");
    assert_eq!(
        plan.delete_attachments[0].attachment_id,
        "target-extra-attachment"
    );
    assert_eq!(plan.folders_to_delete, 1);
    assert_eq!(plan.delete_folder_ids, vec!["target-only-folder"]);
    assert!(!plan.prune_permanent);
}

#[test]
fn restore_plan_with_prune_blocks_ambiguous_fingerprint_matches() {
    let mut archive_item = item("archive-item", "same note");
    archive_item.name = "Shared secret title".to_string();
    let mut target_item_one = archive_item.clone();
    target_item_one.id = "target-one".to_string();
    let mut target_item_two = archive_item.clone();
    target_item_two.id = "target-two".to_string();

    let archive = vault(vec![archive_item]);
    let target = vault(vec![target_item_one, target_item_two]);

    let plan = plan_restore_with_options(
        &archive,
        Some(&target),
        "bw",
        RestorePlanOptions {
            prune: true,
            ..RestorePlanOptions::default()
        },
    );

    assert_eq!(plan.status(), RestorePlanStatus::Blocked);
    assert_eq!(
        plan.restore_fingerprint_ambiguous_item_ids,
        vec!["archive-item"]
    );
    assert!(
        plan.blockers
            .iter()
            .any(|blocker| blocker.contains("ambiguous fingerprint matches"))
    );
    assert!(plan.delete_item_ids.is_empty());
}

#[test]
fn restore_plan_with_prune_blocks_ambiguous_folder_matches() {
    let mut archive = vault(Vec::new());
    archive.folders = vec![Folder {
        id: "archive-folder".to_string(),
        name: "Shared Folder".to_string(),
    }];
    let mut target = vault(Vec::new());
    target.folders = vec![
        Folder {
            id: "target-folder-one".to_string(),
            name: "Shared Folder".to_string(),
        },
        Folder {
            id: "target-folder-two".to_string(),
            name: "Shared Folder".to_string(),
        },
    ];

    let plan = plan_restore_with_options(
        &archive,
        Some(&target),
        "bw",
        RestorePlanOptions {
            prune: true,
            ..RestorePlanOptions::default()
        },
    );

    assert_eq!(plan.status(), RestorePlanStatus::Blocked);
    assert_eq!(plan.restore_folder_ambiguous_ids, vec!["archive-folder"]);
    assert!(
        plan.blockers
            .iter()
            .any(|blocker| blocker.contains("ambiguous folder matches"))
    );
    assert!(plan.delete_folder_ids.is_empty());
}

#[test]
fn restore_plan_with_prune_never_deletes_restore_map_item() {
    let archive = vault(Vec::new());
    let target = vault(vec![restore_map_item(
        r#"{"version":1,"entries":{}}"#.to_string(),
    )]);

    let plan = plan_restore_with_options(
        &archive,
        Some(&target),
        "bw",
        RestorePlanOptions {
            prune: true,
            ..RestorePlanOptions::default()
        },
    );

    assert_eq!(plan.target_items_scanned, Some(0));
    assert_eq!(plan.items_to_delete, 0);
    assert!(plan.delete_item_ids.is_empty());
}

#[test]
fn restore_plan_blocks_incomplete_archives() {
    let mut vault = sample_vault();
    vault.report.complete = false;

    let plan = plan_restore(&vault, None, "bw");

    assert_eq!(plan.status(), RestorePlanStatus::Blocked);
    assert_eq!(plan.blockers, vec!["archive is marked incomplete"]);
}

#[test]
fn restore_plan_incomplete_personal_scope_blocker_points_at_personal_only() {
    let mut vault = sample_vault();
    vault.report.complete = false;
    vault.report.warnings.push(yabbt::model::Warning {
        code: "org-items-not-exported".to_string(),
        message: "2 organization item(s) ...".to_string(),
    });

    let plan = plan_restore(&vault, None, "bw");

    assert_eq!(plan.status(), RestorePlanStatus::Blocked);
    assert_eq!(plan.blockers.len(), 1);
    assert!(plan.blockers[0].starts_with("archive is marked incomplete"));
    assert!(plan.blockers[0].contains("org-items-not-exported"));
    assert!(plan.blockers[0].contains("--personal-only"));
}

#[test]
fn restore_plan_without_target_scan_reports_archive_only_counts() {
    let plan = plan_restore(&sample_vault(), None, "bw");

    assert_eq!(plan.archive_items, 1);
    assert_eq!(plan.target_items_scanned, None);
    assert_eq!(plan.folders_to_create, 0);
    assert_eq!(plan.items_to_create, 1);
    assert_eq!(plan.items_to_update, 0);
    assert_eq!(plan.items_unchanged, 0);
    assert_eq!(plan.items_to_skip, 0);
    assert_eq!(plan.create_item_ids, vec!["item-1"]);
}

#[test]
fn restore_plan_maps_folders_by_name_and_reports_missing_folders() {
    let mut archive = vault(Vec::new());
    archive.folders = vec![
        Folder {
            id: "archive-existing-folder".to_string(),
            name: "Shared folder".to_string(),
        },
        Folder {
            id: "archive-missing-folder".to_string(),
            name: "Missing folder".to_string(),
        },
    ];
    let mut target = vault(Vec::new());
    target.folders = vec![Folder {
        id: "target-existing-folder".to_string(),
        name: "Shared folder".to_string(),
    }];

    let plan = plan_restore(&archive, Some(&target), "bw");

    assert_eq!(plan.folders_to_create, 1);
    assert_eq!(plan.create_folder_ids, vec!["archive-missing-folder"]);
    assert_eq!(
        plan.matched_target_folder_ids,
        BTreeMap::from([(
            "archive-existing-folder".to_string(),
            "target-existing-folder".to_string()
        )])
    );
}

#[test]
fn restore_plan_treats_equivalent_target_folder_ids_as_unchanged() {
    let mut archive_item = item("item-1", "same note");
    archive_item.folder_id = Some("archive-folder".to_string());
    let mut target_item = archive_item.clone();
    target_item.folder_id = Some("target-folder".to_string());
    let mut archive = vault(vec![archive_item]);
    archive.folders = vec![Folder {
        id: "archive-folder".to_string(),
        name: "Shared folder".to_string(),
    }];
    let mut target = vault(vec![target_item]);
    target.folders = vec![Folder {
        id: "target-folder".to_string(),
        name: "Shared folder".to_string(),
    }];

    let plan = plan_restore(&archive, Some(&target), "bw");

    assert_eq!(plan.folders_to_create, 0);
    assert_eq!(plan.items_to_update, 0);
    assert_eq!(plan.items_unchanged, 1);
    assert_eq!(plan.unchanged_item_ids, vec!["item-1"]);
}

#[test]
fn restore_plan_matches_hidden_yabbt_source_item_marker_across_target_ids() {
    let archive_item = item("archive-item", "same note");
    let fingerprint = item_fingerprint(&archive_item);
    let mut target_item = archive_item.clone();
    target_item.id = "bitwarden-assigned-id".to_string();
    target_item.fields.push(Field {
        name: "yabbt.source_item_id".to_string(),
        value: "archive-item".to_string(),
        hidden: true,
    });
    target_item.fields.push(Field {
        name: "yabbt.source_fingerprint".to_string(),
        value: fingerprint,
        hidden: true,
    });

    let archive = vault(vec![archive_item]);
    let target = vault(vec![target_item]);

    let plan = plan_restore(&archive, Some(&target), "bw");

    assert_eq!(plan.items_to_create, 0);
    assert_eq!(plan.items_to_update, 0);
    assert_eq!(plan.items_unchanged, 1);
    assert_eq!(plan.items_to_skip, 0);
    assert_eq!(plan.unchanged_item_ids, vec!["archive-item"]);
    assert_eq!(
        plan.matched_target_item_ids,
        BTreeMap::from([(
            "archive-item".to_string(),
            "bitwarden-assigned-id".to_string()
        )])
    );
}

#[test]
fn restore_plan_matches_restore_map_item_and_excludes_it_from_target_counts() {
    let archive_item = item("archive-item", "same note");
    let fingerprint = item_fingerprint(&archive_item);
    let mut target_item = archive_item.clone();
    target_item.id = "bitwarden-assigned-id".to_string();
    let map_item = restore_map_item(format!(
        r#"{{"version":1,"entries":{{"archive-item":{{"target_item_id":"bitwarden-assigned-id","source_fingerprint":"{fingerprint}"}}}}}}"#
    ));

    let archive = vault(vec![archive_item]);
    let target = vault(vec![target_item, map_item]);

    let plan = plan_restore(&archive, Some(&target), "bw");

    assert_eq!(plan.target_items_scanned, Some(1));
    assert_eq!(plan.items_to_create, 0);
    assert_eq!(plan.items_to_update, 0);
    assert_eq!(plan.items_unchanged, 1);
    assert_eq!(plan.items_to_skip, 0);
    assert_eq!(plan.unchanged_item_ids, vec!["archive-item"]);
    assert_eq!(
        plan.matched_target_item_ids,
        BTreeMap::from([(
            "archive-item".to_string(),
            "bitwarden-assigned-id".to_string()
        )])
    );
}

#[test]
fn restore_plan_restore_map_match_still_reports_changed_target_item() {
    let archive_item = item("archive-item", "current archive note");
    let fingerprint = item_fingerprint(&archive_item);
    let target_item = item("bitwarden-assigned-id", "older target note");
    let map_item = restore_map_item(format!(
        r#"{{"version":1,"entries":{{"archive-item":{{"target_item_id":"bitwarden-assigned-id","source_fingerprint":"{fingerprint}"}}}}}}"#
    ));

    let archive = vault(vec![archive_item]);
    let target = vault(vec![target_item, map_item]);

    let plan = plan_restore(&archive, Some(&target), "bw");

    assert_eq!(plan.items_to_create, 0);
    assert_eq!(plan.items_to_update, 1);
    assert_eq!(plan.items_unchanged, 0);
    assert_eq!(plan.update_item_ids, vec!["archive-item"]);
    assert_eq!(
        plan.matched_target_item_ids,
        BTreeMap::from([(
            "archive-item".to_string(),
            "bitwarden-assigned-id".to_string()
        )])
    );
}

#[test]
fn restore_plan_reports_stale_restore_map_entries() {
    let archive_item = item("archive-item", "same note");
    let map_item = restore_map_item(
        r#"{"version":1,"entries":{"archive-item":{"target_item_id":"missing-target-id","source_fingerprint":"stale-fingerprint"}}}"#
            .to_string(),
    );

    let archive = vault(vec![archive_item]);
    let target = vault(vec![map_item]);

    let plan = plan_restore(&archive, Some(&target), "bw");

    assert_eq!(plan.target_items_scanned, Some(0));
    assert_eq!(plan.items_to_create, 1);
    assert_eq!(plan.restore_map_stale_item_ids, vec!["archive-item"]);
    assert_eq!(plan.warning_count, 1);
    assert_eq!(plan.create_item_ids, vec!["archive-item"]);
}

#[test]
fn restore_plan_reads_restore_map_entries_split_across_chunks() {
    let archive_item_one = item("archive-item-one", "same note one");
    let archive_item_two = item("archive-item-two", "same note two");
    let fingerprint_one = item_fingerprint(&archive_item_one);
    let fingerprint_two = item_fingerprint(&archive_item_two);
    let target_item_one = item("target-item-one", "same note one");
    let target_item_two = item("target-item-two", "same note two");
    let map_item_one = restore_map_item_named(
        "yabbt-restore-map-id-1",
        "yabbt restore map - do not edit",
        format!(
            r#"{{"version":1,"entries":{{"archive-item-one":{{"target_item_id":"target-item-one","source_fingerprint":"{fingerprint_one}"}}}}}}"#
        ),
    );
    let map_item_two = restore_map_item_named(
        "yabbt-restore-map-id-2",
        "yabbt restore map - do not edit 2",
        format!(
            r#"{{"version":1,"entries":{{"archive-item-two":{{"target_item_id":"target-item-two","source_fingerprint":"{fingerprint_two}"}}}}}}"#
        ),
    );

    let archive = vault(vec![archive_item_one, archive_item_two]);
    let target = vault(vec![
        target_item_one,
        target_item_two,
        map_item_two,
        map_item_one,
    ]);

    let plan = plan_restore(&archive, Some(&target), "bw");

    assert_eq!(plan.target_items_scanned, Some(2));
    assert_eq!(plan.items_to_create, 0);
    assert_eq!(plan.items_to_update, 2);
    assert_eq!(plan.items_unchanged, 0);
    assert_eq!(
        plan.matched_target_item_ids,
        BTreeMap::from([
            (
                "archive-item-one".to_string(),
                "target-item-one".to_string()
            ),
            (
                "archive-item-two".to_string(),
                "target-item-two".to_string()
            ),
        ])
    );
}

#[test]
fn restore_plan_ignores_later_duplicate_restore_map_chunk_names() {
    let archive_item = item("archive-item", "same note");
    let fingerprint = item_fingerprint(&archive_item);
    let target_item = item("target-primary", "same note");
    let duplicate_target_item = item("target-duplicate", "same note");
    let primary_map_item = restore_map_item_named(
        "yabbt-restore-map-primary",
        "yabbt restore map - do not edit",
        format!(
            r#"{{"version":1,"entries":{{"archive-item":{{"target_item_id":"target-primary","source_fingerprint":"{fingerprint}"}}}}}}"#
        ),
    );
    let duplicate_map_item = restore_map_item_named(
        "yabbt-restore-map-duplicate",
        "yabbt restore map - do not edit",
        format!(
            r#"{{"version":1,"entries":{{"archive-item":{{"target_item_id":"target-duplicate","source_fingerprint":"{fingerprint}"}}}}}}"#
        ),
    );

    let archive = vault(vec![archive_item]);
    let target = vault(vec![
        target_item,
        duplicate_target_item,
        primary_map_item,
        duplicate_map_item,
    ]);

    let plan = plan_restore(&archive, Some(&target), "bw");

    assert_eq!(
        plan.matched_target_item_ids,
        BTreeMap::from([("archive-item".to_string(), "target-primary".to_string())])
    );
}

#[test]
fn restore_plan_matches_unique_normalized_fingerprint_across_target_ids() {
    let mut archive_item = item("archive-item", "same note");
    archive_item.name = "Shared secret title".to_string();
    let mut target_item = archive_item.clone();
    target_item.id = "bitwarden-assigned-id".to_string();

    let archive = vault(vec![archive_item]);
    let target = vault(vec![target_item]);

    let plan = plan_restore(&archive, Some(&target), "bw");

    assert_eq!(plan.items_to_create, 0);
    assert_eq!(plan.items_to_update, 0);
    assert_eq!(plan.items_unchanged, 1);
    assert_eq!(plan.items_to_skip, 0);
    assert_eq!(
        plan.matched_target_item_ids,
        BTreeMap::from([(
            "archive-item".to_string(),
            "bitwarden-assigned-id".to_string()
        )])
    );
}

#[test]
fn restore_plan_treats_missing_target_attachment_sha_as_metadata_match() {
    let archive = sample_vault();
    let mut target = archive.clone();
    target.items[0].attachments[0].sha256.clear();

    let plan = plan_restore(&archive, Some(&target), "bw");

    assert_eq!(plan.items_to_update, 0);
    assert_eq!(plan.items_unchanged, 1);
    assert_eq!(plan.attachments_to_upload, 0);
}

#[test]
fn restore_plan_treats_unreliable_target_attachment_size_as_metadata_match() {
    let archive = sample_vault();
    let mut target = archive.clone();
    target.items[0].attachments[0].sha256.clear();
    target.items[0].attachments[0].size += 42;

    let plan = plan_restore_with_options(
        &archive,
        Some(&target),
        "bw",
        RestorePlanOptions {
            prune: true,
            ..RestorePlanOptions::default()
        },
    );

    assert_eq!(plan.items_to_update, 0);
    assert_eq!(plan.items_unchanged, 1);
    assert_eq!(plan.attachments_to_upload, 0);
    assert_eq!(plan.attachments_to_delete, 0);
    assert!(plan.delete_attachment_ids.is_empty());
}

fn attachment(id: &str, file_name: &str, sha256: &str) -> AttachmentRef {
    AttachmentRef {
        id: id.to_string(),
        file_name: file_name.to_string(),
        size: 7,
        sha256: sha256.to_string(),
        path: format!("attachments/item/{id}.bin"),
    }
}

/// Same file name, different content, both sides hashed (a KeePass target):
/// the item is an update that re-uploads the new content, and pruning the old
/// version is only allowed together with that update.
#[test]
fn restore_plan_detects_changed_attachment_content_when_both_sides_are_hashed() {
    let mut archive_item = item("item", "same note");
    archive_item.attachments = vec![attachment("archive-att", "doc.txt", "sha-new")];
    let mut target_item = item("item", "same note");
    target_item.attachments = vec![attachment("target-att", "doc.txt", "sha-old")];

    let plan = plan_restore_with_options(
        &vault(vec![archive_item]),
        Some(&vault(vec![target_item])),
        "keepass",
        prune_options(),
    );

    assert_eq!(plan.update_item_ids, vec!["item"]);
    assert_eq!(plan.attachments_to_upload, 1);
    assert_eq!(plan.delete_attachment_ids, vec!["target-att"]);
    assert!(
        plan.delete_attachments[0].requires_item_update,
        "the old version may only go once the new one is uploaded"
    );
}

/// A pure target extra (archive attachments all present) is pruned without
/// requiring an item update, as before.
#[test]
fn restore_plan_prunes_extra_attachment_without_requiring_an_update() {
    let mut archive_item = item("item", "same note");
    archive_item.attachments = vec![attachment("archive-att", "doc.txt", "sha-doc")];
    let mut target_item = item("item", "same note");
    target_item.attachments = vec![
        attachment("target-doc", "doc.txt", "sha-doc"),
        attachment("target-extra", "extra.txt", "sha-extra"),
    ];

    let plan = plan_restore_with_options(
        &vault(vec![archive_item]),
        Some(&vault(vec![target_item])),
        "keepass",
        prune_options(),
    );

    assert_eq!(plan.delete_attachment_ids, vec!["target-extra"]);
    assert!(!plan.delete_attachments[0].requires_item_update);
}

/// KeePass stores a second attachment with an already-used name as
/// "x (2).txt"; matching by content keeps that item unchanged.
#[test]
fn restore_plan_matches_hashed_attachments_by_content_not_name() {
    let mut archive_item = item("item", "same note");
    archive_item.attachments = vec![
        attachment("archive-1", "x.txt", "sha-one"),
        attachment("archive-2", "x.txt", "sha-two"),
    ];
    let mut target_item = item("item", "same note");
    target_item.attachments = vec![
        attachment("target-1", "x.txt", "sha-one"),
        attachment("target-2", "x (2).txt", "sha-two"),
    ];

    let plan = plan_restore_with_options(
        &vault(vec![archive_item]),
        Some(&vault(vec![target_item])),
        "keepass",
        prune_options(),
    );

    assert_eq!(plan.unchanged_item_ids, vec!["item"]);
    assert_eq!(plan.attachments_to_upload, 0);
    assert_eq!(plan.attachments_to_delete, 0);
}

/// Hashed duplicates: two archive copies of the same content against one
/// target copy is a change, and the reverse prunes one copy.
#[test]
fn restore_plan_counts_duplicate_hashed_attachments() {
    let mut archive_item = item("item", "same note");
    archive_item.attachments = vec![
        attachment("archive-1", "x.txt", "sha-same"),
        attachment("archive-2", "y.txt", "sha-same"),
    ];
    let mut target_item = item("item", "same note");
    target_item.attachments = vec![attachment("target-1", "x.txt", "sha-same")];

    let plan = plan_restore_with_options(
        &vault(vec![archive_item.clone()]),
        Some(&vault(vec![target_item.clone()])),
        "keepass",
        prune_options(),
    );
    assert_eq!(plan.update_item_ids, vec!["item"]);
    assert_eq!(plan.attachments_to_delete, 0);

    // The archive's one copy is on the target: nothing to update, and prune
    // removes the extra copy.
    let plan = plan_restore_with_options(
        &vault(vec![target_item]),
        Some(&vault(vec![archive_item])),
        "keepass",
        prune_options(),
    );
    assert_eq!(plan.unchanged_item_ids, vec!["item"]);
    assert_eq!(plan.attachments_to_delete, 1);
    assert!(!plan.delete_attachments[0].requires_item_update);
}

/// After `--update-existing` without `--prune` stored a changed attachment
/// next to the old version (KeePass: "doc (2).txt"), every archive
/// attachment is on the target: the item is unchanged (no update on every
/// run), and only prune removes the old version, without an item update.
#[test]
fn restore_plan_leaves_target_extra_attachments_to_prune() {
    let mut archive_item = item("item", "same note");
    archive_item.attachments = vec![attachment("archive-att", "doc.txt", "sha-new")];
    let mut target_item = item("item", "same note");
    target_item.attachments = vec![
        attachment("target-old", "doc.txt", "sha-old"),
        attachment("target-new", "doc (2).txt", "sha-new"),
    ];

    let plan = plan_restore_with_options(
        &vault(vec![archive_item.clone()]),
        Some(&vault(vec![target_item.clone()])),
        "keepass",
        RestorePlanOptions::default(),
    );
    assert_eq!(plan.unchanged_item_ids, vec!["item"]);
    assert!(plan.update_item_ids.is_empty());
    assert_eq!(plan.attachments_to_delete, 0);

    let plan = plan_restore_with_options(
        &vault(vec![archive_item]),
        Some(&vault(vec![target_item])),
        "keepass",
        prune_options(),
    );
    assert_eq!(plan.unchanged_item_ids, vec!["item"]);
    assert_eq!(plan.delete_attachment_ids, vec!["target-old"]);
    assert!(!plan.delete_attachments[0].requires_item_update);
}

/// A `bw` target listing carries no hashes: attachments still compare by
/// file name only, so unchanged names stay unchanged and renames are updates.
#[test]
fn restore_plan_compares_unhashed_target_attachments_by_name() {
    let mut archive_item = item("item", "same note");
    archive_item.attachments = vec![attachment("archive-att", "doc.txt", "sha-new")];
    let mut same_name = item("item", "same note");
    same_name.attachments = vec![attachment("target-att", "doc.txt", "")];

    let plan = plan_restore_with_options(
        &vault(vec![archive_item.clone()]),
        Some(&vault(vec![same_name])),
        "bw",
        prune_options(),
    );
    assert_eq!(plan.unchanged_item_ids, vec!["item"]);
    assert_eq!(plan.attachments_to_delete, 0);

    let mut renamed = item("item", "same note");
    renamed.attachments = vec![attachment("target-att", "old.txt", "")];
    let plan = plan_restore_with_options(
        &vault(vec![archive_item]),
        Some(&vault(vec![renamed])),
        "bw",
        prune_options(),
    );
    assert_eq!(plan.update_item_ids, vec!["item"]);
    assert_eq!(plan.attachments_to_upload, 1);
    assert_eq!(plan.delete_attachment_ids, vec!["target-att"]);
    assert!(plan.delete_attachments[0].requires_item_update);
}

#[test]
fn restore_plan_reports_ambiguous_normalized_fingerprint_matches() {
    let mut archive_item = item("archive-item", "same note");
    archive_item.name = "Shared secret title".to_string();
    let mut target_item_one = archive_item.clone();
    target_item_one.id = "bitwarden-assigned-id-one".to_string();
    let mut target_item_two = archive_item.clone();
    target_item_two.id = "bitwarden-assigned-id-two".to_string();

    let archive = vault(vec![archive_item]);
    let target = vault(vec![target_item_one, target_item_two]);

    let plan = plan_restore(&archive, Some(&target), "bw");

    assert_eq!(plan.items_to_create, 1);
    assert_eq!(plan.items_unchanged, 0);
    assert_eq!(
        plan.restore_fingerprint_ambiguous_item_ids,
        vec!["archive-item"]
    );
    assert_eq!(plan.warning_count, 1);
    assert!(plan.matched_target_item_ids.is_empty());
}

#[test]
fn restore_plan_blocks_bitwarden_organization_scoped_items() {
    let mut archive_item = item("org-item", "same note");
    archive_item.backend_metadata.push((
        "bitwarden.raw".to_string(),
        r#"{"id":"org-item","organizationId":"source-org","collectionIds":["source-collection"]}"#
            .to_string(),
    ));
    let archive = vault(vec![archive_item]);
    let target = vault(Vec::new());

    let plan = plan_restore(&archive, Some(&target), "bw");

    assert_eq!(plan.status(), RestorePlanStatus::Blocked);
    assert_eq!(
        plan.unsupported_organization_item_ids,
        vec!["org-item".to_string()]
    );
    assert!(
        plan.blockers
            .iter()
            .any(|blocker| blocker.contains("organization or collection scoped items"))
    );
    assert!(
        plan.blockers.iter().all(
            |blocker| !blocker.contains("source-org") && !blocker.contains("source-collection")
        )
    );
}

#[test]
fn restore_plan_allows_organization_scoped_items_with_target_organization() {
    let mut archive_item = item("org-item", "same note");
    archive_item.backend_metadata.push((
        "bitwarden.raw".to_string(),
        r#"{"id":"org-item","organizationId":"source-org","collectionIds":[]}"#.to_string(),
    ));
    let archive = vault(vec![archive_item]);
    let target = vault(Vec::new());

    let plan = plan_restore_with_options(
        &archive,
        Some(&target),
        "bw",
        RestorePlanOptions {
            target_organization_id: Some("target-org"),
            ..RestorePlanOptions::default()
        },
    );

    assert_eq!(plan.status(), RestorePlanStatus::Ready);
    assert!(plan.unsupported_organization_item_ids.is_empty());
    assert!(plan.unsupported_collection_item_ids.is_empty());
    assert_eq!(plan.create_item_ids, vec!["org-item"]);
}

#[test]
fn restore_plan_blocks_collection_scoped_items_even_with_target_organization() {
    let mut archive_item = item("collection-item", "same note");
    archive_item.backend_metadata.push((
        "bitwarden.raw".to_string(),
        r#"{"id":"collection-item","organizationId":"source-org","collectionIds":["source-collection"]}"#
            .to_string(),
    ));
    let archive = vault(vec![archive_item]);
    let target = vault(Vec::new());

    let plan = plan_restore_with_options(
        &archive,
        Some(&target),
        "bw",
        RestorePlanOptions {
            target_organization_id: Some("target-org"),
            ..RestorePlanOptions::default()
        },
    );

    assert_eq!(plan.status(), RestorePlanStatus::Blocked);
    assert!(plan.unsupported_organization_item_ids.is_empty());
    assert_eq!(
        plan.unsupported_collection_item_ids,
        vec!["collection-item".to_string()]
    );
    assert!(
        plan.blockers
            .iter()
            .any(|blocker| blocker.contains("collection scoped items"))
    );
}

#[test]
fn restore_plan_blocks_mixed_personal_and_organization_archive_scope() {
    let mut personal_item = item("personal-item", "personal note");
    personal_item.backend_metadata.push((
        "bitwarden.raw".to_string(),
        r#"{"id":"personal-item","organizationId":null,"collectionIds":[]}"#.to_string(),
    ));
    let mut organization_item = item("organization-item", "org note");
    organization_item.backend_metadata.push((
        "bitwarden.raw".to_string(),
        r#"{"id":"organization-item","organizationId":"source-org","collectionIds":[]}"#
            .to_string(),
    ));
    let archive = vault(vec![personal_item, organization_item]);
    let target = vault(Vec::new());

    let plan = plan_restore_with_options(
        &archive,
        Some(&target),
        "bw",
        RestorePlanOptions {
            target_organization_id: Some("target-org"),
            ..RestorePlanOptions::default()
        },
    );

    assert_eq!(plan.status(), RestorePlanStatus::Blocked);
    assert_eq!(plan.archive_scope, "mixed");
    assert_eq!(
        plan.invalid_scope_item_ids,
        vec!["organization-item".to_string(), "personal-item".to_string()]
    );
    assert!(
        plan.blockers
            .iter()
            .any(|blocker| blocker.contains("mixes personal and organization scoped items"))
    );
    assert!(
        plan.blockers
            .iter()
            .all(|blocker| !blocker.contains("source-org"))
    );
}

#[test]
fn restore_plan_blocks_multi_organization_archive_scope() {
    let mut first_org_item = item("first-org-item", "first org note");
    first_org_item.backend_metadata.push((
        "bitwarden.raw".to_string(),
        r#"{"id":"first-org-item","organizationId":"source-org-one","collectionIds":[]}"#
            .to_string(),
    ));
    let mut second_org_item = item("second-org-item", "second org note");
    second_org_item.backend_metadata.push((
        "bitwarden.raw".to_string(),
        r#"{"id":"second-org-item","organizationId":"source-org-two","collectionIds":[]}"#
            .to_string(),
    ));
    let archive = vault(vec![first_org_item, second_org_item]);
    let target = vault(Vec::new());

    let plan = plan_restore_with_options(
        &archive,
        Some(&target),
        "bw",
        RestorePlanOptions {
            target_organization_id: Some("target-org"),
            ..RestorePlanOptions::default()
        },
    );

    assert_eq!(plan.status(), RestorePlanStatus::Blocked);
    assert_eq!(plan.archive_scope, "mixed");
    assert_eq!(
        plan.invalid_scope_item_ids,
        vec!["first-org-item".to_string(), "second-org-item".to_string()]
    );
    assert!(
        plan.blockers
            .iter()
            .any(|blocker| blocker.contains("multiple source organizations"))
    );
    assert!(plan.blockers.iter().all(|blocker| {
        !blocker.contains("source-org-one") && !blocker.contains("source-org-two")
    }));
}

fn prune_options() -> RestorePlanOptions<'static> {
    RestorePlanOptions {
        target_organization_id: None,
        prune: true,
        prune_permanent: false,
        ..RestorePlanOptions::default()
    }
}

fn folder(id: &str, name: &str) -> Folder {
    Folder {
        id: id.to_string(),
        name: name.to_string(),
    }
}

#[test]
fn restore_plan_with_prune_keeps_ancestor_folders_of_surviving_items() {
    let archive = vault(vec![item("same-item", "same note")]);
    let mut nested_item = item("same-item", "same note");
    nested_item.folder_id = Some("child-folder".to_string());
    let mut target = vault(vec![nested_item]);
    target.folders = vec![
        folder("parent-folder", "Work"),
        folder("child-folder", "Work/Sub"),
        folder("other-folder", "Old"),
    ];

    let plan = plan_restore_with_options(&archive, Some(&target), "keepass", prune_options());

    assert_eq!(plan.status(), RestorePlanStatus::Ready);
    assert_eq!(plan.delete_folder_ids, vec!["other-folder"]);
}

#[test]
fn restore_plan_with_prune_deletes_nested_folders_deepest_first() {
    let archive = vault(Vec::new());
    let mut target = vault(Vec::new());
    target.folders = vec![
        folder("a-parent", "Old"),
        folder("m-grandchild", "Old/Sub/Deep"),
        folder("z-child", "Old/Sub"),
    ];

    let plan = plan_restore_with_options(&archive, Some(&target), "keepass", prune_options());

    assert_eq!(
        plan.delete_folder_ids,
        vec!["m-grandchild", "z-child", "a-parent"]
    );
}

fn sample_vault() -> Vault {
    vault(vec![VaultItem {
        id: "item-1".to_string(),
        kind: ItemKind::Login {
            username: "alice".to_string(),
            password: "hunter2".to_string(),
            uris: vec!["https://example.test".to_string()],
            totp: Some("otpauth://totp/example".to_string()),
        },
        name: "Secret Login".to_string(),
        notes: Some("secret note".to_string()),
        folder_id: None,
        favorite: false,
        fields: vec![Field {
            name: "pin".to_string(),
            value: "1234".to_string(),
            hidden: true,
        }],
        attachments: vec![AttachmentRef {
            id: "attachment-1".to_string(),
            file_name: "recovery.txt".to_string(),
            size: 13,
            sha256: "7b3ab6aba8e82522c98468aa813ae3d894b485b9fe936d275e8ff169159d13a0".to_string(),
            path: "attachments/item-1/attachment-1.bin".to_string(),
        }],
        backend_metadata: Vec::new(),
    }])
}

fn restore_map_item(value: String) -> VaultItem {
    restore_map_item_named(
        "yabbt-restore-map-id",
        "yabbt restore map - do not edit",
        value,
    )
}

fn restore_map_item_named(id: &str, name: &str, value: String) -> VaultItem {
    VaultItem {
        id: id.to_string(),
        kind: ItemKind::SecureNote,
        name: name.to_string(),
        notes: Some("Managed by yabbt. Do not edit.".to_string()),
        folder_id: None,
        favorite: false,
        fields: vec![Field {
            name: "yabbt.restore_map".to_string(),
            value,
            hidden: true,
        }],
        attachments: Vec::new(),
        backend_metadata: Vec::new(),
    }
}

fn vault(items: Vec<VaultItem>) -> Vault {
    Vault {
        metadata: VaultMetadata {
            archive_version: 1,
            source_backend: "fixture".to_string(),
            source_server: Some("https://vault.example.test".to_string()),
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
        name: format!("{id} secret title"),
        notes: Some(note.to_string()),
        folder_id: None,
        favorite: false,
        fields: Vec::new(),
        attachments: if id == "create-item" {
            vec![AttachmentRef {
                id: "attachment-create".to_string(),
                file_name: "create-secret.txt".to_string(),
                size: 13,
                sha256: "7b3ab6aba8e82522c98468aa813ae3d894b485b9fe936d275e8ff169159d13a0"
                    .to_string(),
                path: "attachments/create-item/attachment-create.bin".to_string(),
            }]
        } else {
            Vec::new()
        },
        backend_metadata: Vec::new(),
    }
}

fn raw_card(id: &str, number: &str) -> VaultItem {
    let mut card = item(id, "card note");
    card.kind = ItemKind::Card;
    card.name = "Visa".to_string();
    card.backend_metadata.push((
        "bitwarden.raw".to_string(),
        serde_json::json!({
            "id": id,
            "type": 3,
            "name": "Visa",
            "notes": "card note",
            "card": { "number": number, "code": "123" },
        })
        .to_string(),
    ));
    card
}

#[test]
fn restore_plan_detects_change_only_present_in_raw_payload() {
    let archive = vault(vec![raw_card("card", "4111111111111111")]);
    let target = vault(vec![raw_card("card", "5500000000000004")]);

    let plan = plan_restore(&archive, Some(&target), "bw");

    assert_eq!(plan.update_item_ids, vec!["card"]);
    assert!(plan.unchanged_item_ids.is_empty());
}

#[test]
fn restore_plan_fingerprint_fallback_does_not_match_different_raw_payload() {
    let archive = vault(vec![raw_card("source-card", "4111111111111111")]);
    let target = vault(vec![raw_card("target-card", "5500000000000004")]);

    let plan = plan_restore(&archive, Some(&target), "bw");

    assert!(plan.unchanged_item_ids.is_empty());
    assert_eq!(plan.create_item_ids, vec!["source-card"]);
    assert!(plan.matched_target_item_ids.is_empty());
}

#[test]
fn restore_plan_fingerprint_fallback_ignores_target_assigned_raw_keys() {
    let archive = vault(vec![raw_card("source-card", "4111111111111111")]);
    let mut target_card = raw_card("target-card", "4111111111111111");
    target_card.backend_metadata = vec![(
        "bitwarden.raw".to_string(),
        serde_json::json!({
            "id": "target-card",
            "type": 3,
            "name": "Visa",
            "notes": "card note",
            "folderId": null,
            "revisionDate": "2026-09-09T09:09:09Z",
            "reprompt": 0,
            "passwordHistory": [],
            "card": { "number": "4111111111111111", "code": "123", "brand": null },
        })
        .to_string(),
    )];
    let target = vault(vec![target_card]);

    let plan = plan_restore(&archive, Some(&target), "bw");

    assert_eq!(plan.unchanged_item_ids, vec!["source-card"]);
    assert!(plan.create_item_ids.is_empty());
}

fn map_entries_json(entries: &[(&str, &str)]) -> String {
    let entries = entries
        .iter()
        .map(|(source, target)| {
            (
                source.to_string(),
                serde_json::json!({ "target_item_id": target, "source_fingerprint": "" }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    serde_json::json!({ "version": 1, "entries": entries }).to_string()
}

fn assert_targets_bound_once(plan: &RestorePlan) {
    let mut targets = plan.matched_target_item_ids.values().collect::<Vec<_>>();
    let total = targets.len();
    targets.sort();
    targets.dedup();
    assert_eq!(
        targets.len(),
        total,
        "a target item is bound to several archive items: {:?}",
        plan.matched_target_item_ids
    );
}

/// A source clone (identical content, id sorting before the original) must
/// not steal the original's mapped target via the fingerprint fallback.
#[test]
fn restore_plan_fingerprint_fallback_does_not_steal_strongly_matched_target() {
    let original = item("source-item", "same note");
    let mut clone = original.clone();
    clone.id = "aaa-clone".to_string();
    let mut target_item = original.clone();
    target_item.id = "target-item".to_string();
    let map_item = restore_map_item(map_entries_json(&[("source-item", "target-item")]));

    let archive = vault(vec![original, clone]);
    let target = vault(vec![target_item, map_item]);

    let plan = plan_restore(&archive, Some(&target), "bw");

    assert_targets_bound_once(&plan);
    assert_eq!(
        plan.matched_target_item_ids,
        BTreeMap::from([("source-item".to_string(), "target-item".to_string())])
    );
    assert_eq!(plan.create_item_ids, vec!["aaa-clone"]);
    assert_eq!(plan.unchanged_item_ids, vec!["source-item"]);
}

/// Two restore-map entries (or a map entry and a marker) pointing at the
/// same target item must not both bind it; the first claim wins
/// deterministically and the other archive item falls through.
#[test]
fn restore_plan_strong_matches_never_bind_a_target_twice() {
    let first = item("item-a", "note a");
    let second = item("item-b", "note b");
    let mut target_item = first.clone();
    target_item.id = "target-item".to_string();
    target_item.fields.push(Field {
        name: "yabbt.source_item_id".to_string(),
        value: "item-b".to_string(),
        hidden: true,
    });
    let map_item = restore_map_item(map_entries_json(&[
        ("item-a", "target-item"),
        ("item-b", "target-item"),
    ]));

    let archive = vault(vec![second.clone(), first.clone()]);
    let target = vault(vec![target_item, map_item]);

    let plan = plan_restore(&archive, Some(&target), "bw");

    assert_targets_bound_once(&plan);
    assert_eq!(
        plan.matched_target_item_ids,
        BTreeMap::from([("item-a".to_string(), "target-item".to_string())])
    );
    assert_eq!(plan.create_item_ids, vec!["item-b"]);
}

/// A map match outranks a marker match on the same target, regardless of
/// archive item order.
#[test]
fn restore_plan_map_match_outranks_marker_match() {
    let mapped = item("zzz-mapped", "note");
    let marked = item("aaa-marked", "note");
    let mut target_item = mapped.clone();
    target_item.id = "target-item".to_string();
    target_item.fields.push(Field {
        name: "yabbt.source_item_id".to_string(),
        value: "aaa-marked".to_string(),
        hidden: true,
    });
    let map_item = restore_map_item(map_entries_json(&[("zzz-mapped", "target-item")]));

    let archive = vault(vec![marked, mapped]);
    let target = vault(vec![target_item, map_item]);

    let plan = plan_restore(&archive, Some(&target), "bw");

    assert_targets_bound_once(&plan);
    assert_eq!(
        plan.matched_target_item_ids,
        BTreeMap::from([("zzz-mapped".to_string(), "target-item".to_string())])
    );
    assert_eq!(plan.create_item_ids, vec!["aaa-marked"]);
}

fn numbered_items(prefix: &str, count: usize) -> Vec<VaultItem> {
    (0..count)
        .map(|index| {
            item(
                &format!("{prefix}-{index:02}"),
                &format!("{prefix} {index}"),
            )
        })
        .collect()
}

fn prune_plan(archive: &Vault, target: &Vault, allow_mass_delete: bool) -> RestorePlan {
    plan_restore_with_options(
        archive,
        Some(target),
        "bw",
        RestorePlanOptions {
            prune: true,
            allow_mass_delete,
            ..RestorePlanOptions::default()
        },
    )
}

fn has_mass_delete_blocker(plan: &RestorePlan) -> bool {
    plan.blockers
        .iter()
        .any(|blocker| blocker.contains("--allow-mass-delete"))
}

#[test]
fn restore_plan_prune_blocks_when_archive_is_empty() {
    let archive = vault(Vec::new());
    let target = vault(numbered_items("target", 2));

    let plan = prune_plan(&archive, &target, false);

    assert_eq!(plan.status(), RestorePlanStatus::Blocked);
    assert!(has_mass_delete_blocker(&plan), "{:?}", plan.blockers);
    // The would-be deletions are still reported for the dry run.
    assert_eq!(plan.delete_item_ids.len(), 2);

    let plan = prune_plan(&archive, &target, true);
    assert_eq!(
        plan.status(),
        RestorePlanStatus::Ready,
        "{:?}",
        plan.blockers
    );
}

#[test]
fn restore_plan_prune_blocks_deleting_most_of_the_target() {
    let mut target_items = numbered_items("keep", 8);
    target_items.extend(numbered_items("gone", 12));
    let archive = vault(numbered_items("keep", 8));
    let target = vault(target_items);

    let plan = prune_plan(&archive, &target, false);

    assert_eq!(plan.items_to_delete, 12);
    assert_eq!(plan.status(), RestorePlanStatus::Blocked);
    assert!(has_mass_delete_blocker(&plan), "{:?}", plan.blockers);

    let plan = prune_plan(&archive, &target, true);
    assert_eq!(
        plan.status(),
        RestorePlanStatus::Ready,
        "{:?}",
        plan.blockers
    );
}

#[test]
fn restore_plan_prune_allows_ordinary_deletions() {
    // More than 10 deletes, but well under half the target.
    let mut target_items = numbered_items("keep", 20);
    target_items.extend(numbered_items("gone", 11));
    let plan = prune_plan(
        &vault(numbered_items("keep", 20)),
        &vault(target_items),
        false,
    );
    assert_eq!(plan.items_to_delete, 11);
    assert_eq!(
        plan.status(),
        RestorePlanStatus::Ready,
        "{:?}",
        plan.blockers
    );

    // Most of a small target, but only a handful of items.
    let mut target_items = numbered_items("keep", 2);
    target_items.extend(numbered_items("gone", 6));
    let plan = prune_plan(
        &vault(numbered_items("keep", 2)),
        &vault(target_items),
        false,
    );
    assert_eq!(plan.items_to_delete, 6);
    assert_eq!(
        plan.status(),
        RestorePlanStatus::Ready,
        "{:?}",
        plan.blockers
    );
}

#[test]
fn restore_plan_without_prune_never_reports_mass_delete() {
    let plan = plan_restore(
        &vault(Vec::new()),
        Some(&vault(numbered_items("t", 30))),
        "bw",
    );
    assert_eq!(
        plan.status(),
        RestorePlanStatus::Ready,
        "{:?}",
        plan.blockers
    );
}

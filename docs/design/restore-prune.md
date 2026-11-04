# Restore Prune Design

> Design record. The README and `docs/threat-model.md` describe current
> behavior; where they differ from this document, they take precedence.

## Goal

Add an explicit destructive mirror mode to archive restore so a target Bitwarden/Vaultwarden vault can be reconciled to an archive. This should happen before deeper organization and collection restore work because delete/prune semantics affect the safety model for later complete restore and sync features.

The default restore behavior remains conservative: create missing folders/items, optionally update matched changed items, upload missing attachments, and never delete target-only data. Pruning is only enabled when the user passes `--prune`.

## Command Surface

Initial CLI shape:

```bash
yabbt restore --target bw bitwarden.yabbt --passphrase-env YABBT_PASSPHRASE --dry-run --prune
yabbt restore --target bw bitwarden.yabbt --passphrase-env YABBT_PASSPHRASE --apply --prune
yabbt restore --target bw bitwarden.yabbt --passphrase-env YABBT_PASSPHRASE --apply --prune --prune-permanent
```

`--prune` means delete target-only data after planning against the archive. It does not imply `--update-existing`; changed matched items still require `--update-existing`.

`--prune-permanent` enables irreversible item deletion. Without it, target-only items are sent to Bitwarden Trash using the default `bw delete item <id>` behavior. Permanent deletion uses `bw delete item <id> --permanent`.

`--prune-permanent` is invalid unless `--prune` and `--apply` are both present.

## Scope

The first prune implementation covers a personal-vault archive restore into a personal target vault:

- Delete target-only items.
- Delete target-only attachments on matched items.
- Delete target-only folders after item and attachment pruning.
- Keep output secret-safe: counts and IDs only.

Organization and collection-scoped archives keep the current blockers until collection mapping is implemented. Pruning must not delete organization collections or collection-scoped items until that scope mapping exists.

## Planning Semantics

Restore planning should extend `RestorePlan` with prune fields:

- `items_to_delete`
- `delete_item_ids`
- `attachments_to_delete`
- `delete_attachment_ids`
- `folders_to_delete`
- `delete_folder_ids`
- `prune_permanent`

Planning remains read-only. It scans the target vault, excludes the yabbt restore-map item from normal target comparisons, and computes target-only data relative to the archive and matched target items.

Target-only items are target items that are not matched to any archive item by restore map, per-item marker, original ID, or unique normalized fingerprint. The yabbt restore-map item must never be pruned as a target-only item.

Target-only attachments are attachments present on a matched target item but absent from the corresponding archive item. Matching uses SHA-256 when available, falling back to filename plus size only when checksum data is unavailable. Attachment deletion is skipped if the matched item itself is scheduled for item deletion.

Target-only folders are target folders with no corresponding archive folder by exact folder-name mapping. Folder deletion is allowed only after item pruning has been planned, because Bitwarden folder deletion does not delete item contents. Empty-folder detection should be based on the post-prune item set, not the pre-prune target scan.

Ambiguity blocks pruning. If item, folder, or attachment matching is ambiguous, the plan should report IDs and stop before mutation.

## Apply Semantics

`restore --apply --prune` recomputes the plan immediately before mutation and stops if blockers exist. It must also keep strict archive verification before mutation.

Mutation order:

1. Create missing folders and items using existing restore semantics.
2. Optionally update matched changed items only when `--update-existing` is set.
3. Upload missing archive attachments using existing restore semantics.
4. Delete target-only attachments on matched items.
5. Delete target-only items.
6. Delete target-only folders that are empty after item pruning.
7. Update or repair the yabbt restore map.
8. Run `--verify-after` checks when requested.

The apply summary should include prune counts:

- `items_deleted`
- `attachments_deleted`
- `folders_deleted`
- `prune_permanent`

The summary should print IDs only for deleted objects and must not print item names, folder names, attachment names, notes, usernames, passwords, TOTP values, custom fields, or attachment bytes.

## Backend Commands

For the `bw` target adapter:

- Delete items with `bw delete item <target-id>`.
- Delete permanent items with `bw delete item <target-id> --permanent`.
- Delete attachments with `bw delete attachment <attachment-id>`.
- Delete folders with `bw delete folder <folder-id>`.

Command failures must be redacted using the same stderr handling as other `bw` adapter failures.

## Safety Requirements

Pruning is destructive and must never be enabled by default.

Dry-run must show the exact deletion counts and target object IDs before apply. Apply must recompute the same categories from fresh target state rather than trusting a previous dry-run.

If `--prune` is used with `--no-restore-map`, pruning can still proceed, but only for unambiguous matches. Ambiguous fingerprint matches block rather than risking deletion of the wrong target object.

If the archive is incomplete, mixed personal-plus-organization scope, multi-organization scope, or collection-scoped without collection mapping, pruning is blocked before any mutation.

## Testing

Tests should be added before implementation for:

- `restore --dry-run --prune` reports target-only item, attachment, and folder IDs without names or secrets.
- `restore --apply --prune` sends item deletes to Trash by default and does not pass `--permanent`.
- `restore --apply --prune --prune-permanent` passes `--permanent` for item deletes.
- `--prune` does not imply `--update-existing`.
- The yabbt restore-map item is never deleted as a target-only item.
- Ambiguous fingerprint and folder matches block pruning.
- Organization and collection-scoped archives keep current blockers.
- Stateful repeated prune runs are idempotent: the second run reports zero delete/create/upload mutations.


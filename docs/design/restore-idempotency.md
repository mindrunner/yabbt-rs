# Restore Idempotency Strategy

> Design record. The README and `docs/threat-model.md` describe current
> behavior; where they differ from this document, they take precedence.

**Goal:** Make `restore --apply` idempotent so repeated restore runs do not create duplicate items.

**Current limitation:** Bitwarden assigns a new item ID when `bw create item` succeeds. The archive retains the original source item ID, so a later target scan cannot match unmarked restored target items by ID. The planner may treat those archive items as missing again and `restore --apply` may create duplicates.

**Current safe behavior:** Restore apply is create-only. It creates missing folders by exact name, rewrites restored item folder IDs to target-vault folder IDs, has guardrails for Bitwarden organization-scoped items, blocks collection-scoped archive items until collection mapping exists, skips item updates by default, never deletes target-only folders or items, and verifies the archive before mutation. By default, apply writes one yabbt-managed map item to the target vault, backfills it for already matched items, repairs stale entries that point to missing target items, and restore planning uses it to avoid duplicate creates without per-item metadata. `--no-restore-map` opts out. `--mark-restored` remains available as a per-item marker fallback.

Update note: `--update-existing` is now available as an explicit opt-in. It edits only changed items that were matched by restore map, per-item marker, original ID, or unique normalized fingerprint. It also uploads archive attachments missing from matched existing items. Deletes, overwrites, and target-only attachment cleanup remain out of scope.

---

## Options To Revisit

### Option 1: Hidden Bitwarden Metadata Fields

Write yabbt metadata into each restored Bitwarden item as hidden custom fields:

```json
{
  "name": "yabbt.source_item_id",
  "value": "<archive item id>",
  "type": 1
}
```

Potential fields:

- `yabbt.source_item_id`: original archive item ID.
- `yabbt.source_fingerprint`: stable yabbt fingerprint at restore time.
- `yabbt.archive_version`: yabbt archive/model version that produced the restore.

Pros:

- Reliable idempotency even though Bitwarden assigns a new item ID.
- Portable across machines because the marker travels with the target vault.
- Supports future update/conflict logic.

Cons:

- Pollutes the target vault with tool metadata.
- Hidden fields are concealed in the UI but are still visible to vault owners, exports, CLI access, and anyone with decrypted vault access.
- Some users may not want any tool-managed fields in their password manager.

Status: Implemented as explicit `--mark-restored` support. The remaining decision is whether hidden markers should stay opt-in or become default later.

### Option 2: Target Vault Restore Map Item

Write one yabbt-managed secure note into the target vault:

```text
name: yabbt restore map - do not edit
hidden field: yabbt.restore_map
```

The hidden field value stores JSON mapping archive item IDs to target item IDs and source fingerprints.

Pros:

- Avoids adding metadata to every restored item.
- Travels with the target vault, so it works across machines.
- Supports deterministic planning after Bitwarden assigns new target IDs.

Cons:

- Adds one visible tool-managed item to the target vault.
- If a user deletes or edits the map item, yabbt may lose deterministic matching.
- The map content is hidden in the UI but still visible in exports, CLI output, and to anyone with decrypted vault access.

Status: Implemented as the default restore apply idempotency mechanism. `--no-restore-map` opts out. Restore planning reads the map item automatically when present, excludes it from normal target counts, and reports stale source item IDs for map entries whose target item no longer exists. Apply updates the map for newly created items, backfills mappings for already matched target items, and removes stale entries while rewriting the map.

### Option 3: Exact Normalized Fingerprint Matching

Match archive items to target items by stable content fingerprint after normalizing volatile fields and excluding target-assigned IDs.

Pros:

- No target vault metadata.
- Prevents duplicates when the restored item is unchanged.

Cons:

- If the restored item is edited later, the fingerprint changes and idempotency may fail.
- Cannot distinguish two intentionally identical items.

Status: Implemented as a marker-free fallback after restore-map, per-item marker, and ID matching. It matches only when the normalized fingerprint is unique in the target. Ambiguous matches are reported by archive item ID and are not guessed silently.

### Option 4: Natural-Key Matching

Match by item-type-specific natural keys:

- Login: name + username + URI set.
- Secure note: name plus stable non-secret metadata where available.
- Card/identity: selected stable fields.

Pros:

- No target vault metadata.
- More resilient than full fingerprint when non-key fields change.

Cons:

- Collisions are possible.
- Renames or URI edits can break matching.
- Needs careful per-item-kind rules.

### Option 5: External Restore Map

Store `archive_item_id -> target_item_id` outside the vault, for example in a local encrypted sidecar file.

Pros:

- Reliable when the map is present.
- Does not modify vault items.

Cons:

- Easy to lose.
- Awkward across machines.
- Undermines archive portability unless map lifecycle is very clear.

### Option 6: Keep ID-Only Matching

Keep current behavior.

Pros:

- Simple.
- No metadata or heuristics.

Cons:

- Repeated restore creates duplicates after Bitwarden assigns new IDs.
- Not acceptable as the long-term default for `--apply`.

---

## Recommended Direction

Implement a conservative matching strategy ladder:

1. Match by yabbt target-vault restore map if present. (Implemented.)
2. Else match by yabbt hidden per-item metadata marker if present. (Implemented.)
3. Else match by exact normalized fingerprint if unique. (Implemented.)
4. Else match by natural key if unique. (Future.)
5. Else treat the item as create-needed and emit an ambiguity warning. (Partially implemented for fingerprint ambiguity.)

This keeps deterministic metadata-based idempotency available while still avoiding duplicates in common no-metadata cases. Ambiguous matches must not be guessed silently.

## Implementation Notes For Later

- Add integration-style tests proving repeated `restore --apply` does not create duplicates once the fake `bw` can persist target state across calls.
- Add secret-safe warnings for ambiguous natural-key matches.
- Decide whether metadata fields stay opt-in or become default.
- Add a later security-hardening pass for temporary plaintext attachment files used during backup and restore. The current `bw` CLI requires file paths for attachment download/upload; future work should reduce exposure with memory-backed temp directories where available, tighter permissions, better cleanup reporting, or streaming APIs if supported.

## Backlog: Organization And Collection Restore

Full Bitwarden organization/collection handling is deferred. The current code should keep safe guardrails, but deeper behavior belongs in a later dedicated design and implementation pass.

Open topics:

- Add first-class archive scope metadata: personal vault vs one source organization. Archives should not mix personal and organization items, and should not contain multiple organizations.
- Define source organization metadata in the canonical model without making source organization IDs part of restore semantics.
- Model collections explicitly, including enough source metadata to map collections by name or another stable key.
- Decide collection restore policy: block missing target collections by default, with a possible later `--create-collections` opt-in.
- Implement target collection discovery and ambiguity handling for `bw`/Vaultwarden.
- Rewrite `organizationId` and `collectionIds` only through explicit target-scope mapping. Never replay source organization or collection IDs blindly.
- Decide restore-map placement for organization restores: personal vault map, target organization map, or separate maps per restore scope.

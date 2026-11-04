# yabbt

A command-line tool that backs up Bitwarden and Vaultwarden vaults, attachments
included, into encrypted archives through the official Bitwarden CLI (`bw`).
It can verify and inspect those archives offline, diff them against a live
vault, restore them into another account, and sync one-way between two
accounts or between a vault and a KeePass (.kdbx) database.

> [!WARNING]
> **Status: experimental (0.x).** This tool reads and writes password vaults.
> Behavior, flags, and the archive format may still change between 0.x
> releases. Before trusting it with data you care about:
>
> - Keep an independent backup of your vault (for example Bitwarden's own
>   encrypted export) that does not depend on this tool.
> - Run every `restore` and `sync` as a dry run first (the default) and read
>   the plan before adding `--apply`.
> - Be careful with `--prune` and especially `--prune-permanent`.
> - KeePass writes go through an experimental KDBX4 writer that can drop
>   data it does not model (plugin data, KeeShare settings, custom icons); see
>   [KeePass](#keepass).
> - Read the [threat model](docs/threat-model.md) for known gaps.

## Features

- **Encrypted archives.** A backup is a single file: a versioned tar layout,
  compressed with zstd and encrypted with a passphrase via
  [age](https://age-encryption.org/). It contains the normalized vault,
  attachment bytes, integrity metadata, and a completeness report.
- **Complete or loudly incomplete.** If a backup cannot capture everything
  (for example organization items in a personal export, or an attachment
  that fails to download with `--permissive`), the archive is marked
  incomplete and `verify` fails instead of reporting success.
- **Offline verification.** `verify` checks the manifest, payload digests,
  and every attachment's size and SHA-256. `inspect` prints a safe summary.
- **Secret-safe output.** `inspect`, `verify`, `diff`, and restore plans print
  counts and IDs only, never names, notes, passwords, or attachment content.
- **Diff** a live vault against an archive.
- **Conservative restore** with dry-run planning, idempotent re-runs (via a
  restore map stored in the target vault), opt-in updates, opt-in pruning
  that uses the trash by default, and a mass-delete guard.
- **One-way sync** between two Bitwarden accounts (named persistent `bw`
  profiles, so both stay logged in) or from Bitwarden to KeePass, writing an
  archive on every run.
- **KeePass (.kdbx, KDBX4)** as a restore/sync target and as a
  backup/diff source, including attachments, custom fields, TOTP, and
  nested groups.
- Works with any server `bw` can talk to: Bitwarden cloud, self-hosted
  Bitwarden, and Vaultwarden (the live end-to-end test runs against
  Vaultwarden).

## Prerequisites

- **Bitwarden CLI (`bw`)**, the official client, on your `PATH`. Use a
  recent release; see Bitwarden's documentation for installation. Every
  interaction with your Bitwarden or Vaultwarden server goes through `bw`.
  Not needed for KeePass-only use (`backup`/`diff --source keepass`,
  `restore --target keepass`, `verify`, `inspect`).
- **Rust toolchain** 1.89 or newer to build from source.
- **Linux or macOS.** Windows is untested.
- Optional: `age`, `zstd`, and `tar` only if you want to unpack an archive
  without this tool, using [`contrib/extract-yabbt.sh`](#extracting-an-archive-without-yabbt).

## Install

From the Git repository:

```bash
cargo install --locked --git https://github.com/mindrunner/yabbt-rs
```

From a local checkout:

```bash
git clone https://github.com/mindrunner/yabbt-rs
cd yabbt-rs
cargo install --locked --path .
```

There are no prebuilt binaries or crates.io releases yet.

## Quick start

The archive passphrase is always read from an environment variable whose name
you pass with `--passphrase-env`, so it never appears on the command line.
Read it without echoing it:

```bash
printf 'Archive passphrase: '; read -rs YABBT_PASSPHRASE; echo
export YABBT_PASSPHRASE
```

Backup refuses weak archive passphrases by default. Use a long random
passphrase, such as 4+ random words from a password generator. `--yolo`
explicitly overrides this check for testing or knowingly weak archives.

Back up, verify, and inspect:

```bash
bw login
export BW_SESSION="$(bw unlock --raw)"

archive="bitwarden-$(date +%F).yabbt"
yabbt backup --source bw --out "$archive" --passphrase-env YABBT_PASSPHRASE
yabbt verify "$archive" --passphrase-env YABBT_PASSPHRASE
yabbt inspect "$archive" --passphrase-env YABBT_PASSPHRASE
```

Plan a restore into the currently logged-in account without changing it:

```bash
yabbt restore --target bw "$archive" --passphrase-env YABBT_PASSPHRASE --dry-run
```

Clear the variables when you are done (`unset YABBT_PASSPHRASE BW_SESSION`),
especially in shared shells.

## Commands

```text
yabbt doctor
yabbt backup --source bw --out <archive> --passphrase-env <ENV> [--overwrite] [--yolo]
yabbt inspect <archive> --passphrase-env <ENV>
yabbt verify <archive> --passphrase-env <ENV>
yabbt diff --source bw --archive <archive> --passphrase-env <ENV>
yabbt restore --target bw <archive> --passphrase-env <ENV> --dry-run [--format human|json]
yabbt restore --target bw <archive> --passphrase-env <ENV> --apply
yabbt restore --target bw <archive> --passphrase-env <ENV> --apply --verify-after
yabbt restore --target bw <archive> --passphrase-env <ENV> --apply --update-existing
yabbt restore --target bw <archive> --passphrase-env <ENV> --apply --no-restore-map
yabbt restore --target bw <archive> --passphrase-env <ENV> --apply --mark-restored
yabbt restore --target bw <archive> --passphrase-env <ENV> --dry-run --prune
yabbt restore --target bw <archive> --passphrase-env <ENV> --apply --prune
yabbt restore --target bw <archive> --passphrase-env <ENV> --apply --prune --prune-permanent
yabbt restore --target bw <archive> --passphrase-env <ENV> --apply --prune --allow-mass-delete
yabbt bw-login --profile <name> [--server-url <URL>]
yabbt sync --source bw --target bw --source-profile <name> --target-profile <name> --out <archive> --passphrase-env <ENV> [--apply ...]
yabbt backup --source keepass --keepass-file <path.kdbx> --keepass-passphrase-env <ENV> --out <archive> --passphrase-env <ENV>
yabbt diff --source keepass --keepass-file <path.kdbx> --keepass-passphrase-env <ENV> --archive <archive> --passphrase-env <ENV>
yabbt restore --target keepass --keepass-file <path.kdbx> --keepass-passphrase-env <ENV> <archive> --passphrase-env <ENV> --apply
yabbt sync --source bw --target keepass --source-profile <name> --keepass-file <path.kdbx> --keepass-passphrase-env <ENV> --out <archive> --passphrase-env <ENV> [--apply ...]
```

`yabbt <command> --help` lists every flag. `backup`, `restore`, and `sync`
also accept `--progress auto|always|never|plain|json`, and `backup`, `diff`,
`restore`, and `sync` accept `--attachment-jobs <N>` (parallel attachment
transfers, default 4).

## Backup

`backup --source bw` runs `bw sync`, `bw export --format json`, `bw list items`, and `bw get attachment ... --output ...` for each attachment.

By default a failed attachment download aborts the backup. With
`--permissive`, it becomes a warning and the archive is marked incomplete.

For Vaultwarden or self-hosted Bitwarden:

```bash
yabbt backup --source bw --server-url https://vault.example.test --out vault.yabbt --passphrase-env YABBT_PASSPHRASE
```

### Backup scope: personal vault vs. organizations

Without `--organization-id`, `backup --source bw` exports the **personal vault
only** — that is what `bw export` covers. Organization items the account can
see are *not* included. yabbt detects them (they show up in `bw list items`
but not in the export) and marks the archive incomplete with an
`org-items-not-exported` warning that carries only a count, so `verify` fails
and `restore`/`sync` refuse to treat the archive as a full copy instead of
silently reporting `complete: true`.

If a personal-vault-only backup is what you want, pass `--personal-only`
(`backup --source bw` and `sync --source bw`; on `backup` it cannot be combined
with `--organization-id`). The organization items are still counted and
recorded as an informational `org-items-excluded-by-scope` warning, but the
archive stays `complete: true`, so `verify`, `restore`, and `sync` accept it.
`backup` and sync's backup step print a short stderr notice whenever the
archive carries warnings: whether it is complete, plus warning codes and
counts.

To back up an organization, run one backup per organization (`bw list
organizations` shows the IDs):

```bash
yabbt backup --source bw --organization-id <org-id> --out org.yabbt --passphrase-env YABBT_PASSPHRASE
```

An organization backup contains that organization's items only. Exporting
several organizations into one archive is not supported yet.

### Verify, inspect, diff

Verify an archive:

```bash
yabbt verify bitwarden.yabbt --passphrase-env YABBT_PASSPHRASE
```

`verify` is strict. It exits non-zero if the archive is corrupt, marked incomplete, has missing attachment payloads, has orphan attachment payloads, or attachment size/SHA-256 metadata does not match the stored payload bytes.

Inspect a safe, non-secret summary:

```bash
yabbt inspect bitwarden.yabbt --passphrase-env YABBT_PASSPHRASE
```

`inspect` is informational. It exits successfully for a structurally readable archive and prints `complete: false` if the backup report says the export was incomplete.

`inspect` and `verify` print counts and metadata only. They do not print item names, folder names, notes, usernames, passwords, TOTP values, custom field values, attachment names, or attachment bytes.

Diff the current Bitwarden/Vaultwarden account against an archive:

```bash
yabbt diff --source bw --archive bitwarden.yabbt --passphrase-env YABBT_PASSPHRASE
```

`diff` currently compares item IDs and stable item fingerprints. It prints counts plus added, removed, and changed item IDs. It does not print item names, notes, usernames, passwords, TOTP values, custom field values, attachment names, or attachment bytes.

## Bitwarden profiles

The stock `bw` CLI holds one global session, so working with two accounts
normally means logging in and out. yabbt avoids that with named persistent
profiles: each profile is a directory under
`$XDG_DATA_HOME/yabbt/bw-profiles/<name>` (default
`~/.local/share/yabbt/bw-profiles/<name>`) used as `BITWARDENCLI_APPDATA_DIR`,
so every profile keeps its own `bw` login.

```bash
# one-time setup per account; bw prompts for credentials on the tty
yabbt bw-login --profile prod --server-url https://vault.example.com
yabbt bw-login --profile lab  --server-url https://vw.lab.example.com
```

`backup`, `diff`, and `restore` accept `--bw-profile <name>`. When a profile's
vault is locked, yabbt runs `bw unlock --raw` interactively (bw prompts for the
master password; yabbt never sees it) and keeps the session key in memory for
the rest of the run.

```bash
yabbt backup --source bw --bw-profile prod --out backup.yabbt --passphrase-env YABBT_PASSPHRASE
yabbt restore --target bw --bw-profile lab backup.yabbt --passphrase-env YABBT_PASSPHRASE --dry-run
```

## Sync

`yabbt sync` runs the whole pipeline in one go: export the source profile's
vault, write the encrypted archive to a temp file next to `--out`, verify it,
publish it at `--out` (the run doubles as a backup), scan the target profile
read-only, and plan the restore. It is a dry run by default; `--apply`
mutates the target. The source account is only ever exported from — sync
cannot mutate it. Source and target profiles must differ.

Sync only publishes an archive that passes strict verification, which
includes being complete. If the export is incomplete (for example
organization items without `--personal-only`, or failed attachment downloads
under `--permissive`) or the new archive fails verification, the temp file is
deleted, `--out` is left exactly as it was — with `--overwrite`, the previous
archive survives — and the plan is blocked with the verification error
(exit code 3, for dry runs and `--apply` alike). Use `backup` if you want to
keep an incomplete archive. A verified archive is published before the plan
is computed, so it is kept even if the plan then blocks.

```bash
# dry-run: plan only, nothing is written to the target
yabbt sync --source bw --target bw \
  --source-profile prod --target-profile lab \
  --out ~/backups/prod-backup.yabbt --passphrase-env YABBT_PASSPHRASE

# apply with idempotency map and post-apply verification
yabbt sync --source bw --target bw \
  --source-profile prod --target-profile lab \
  --out ~/backups/prod-backup.yabbt --passphrase-env YABBT_PASSPHRASE \
  --apply --update-existing --verify-after
```

`backup` and `sync` refuse to replace an existing file at `--out` (exit code
2, checked before anything is exported) unless `--overwrite` is passed. A
verified archive is published before the restore is planned, so without this
check a run against a wiped or broken (but complete-looking) source would
silently replace the last good backup with an empty one — even on a dry run.
The check is repeated atomically when
the finished archive is moved into place, so a file that appears at `--out`
while the export runs is not replaced either. That atomic check needs a
filesystem with `renameat2(RENAME_NOREPLACE)` or hard links; on one with
neither (some FUSE mounts) the write fails closed with an error saying so —
pass `--overwrite` or write to a local filesystem. Archives are written to a
randomly named owner-only temp file next to `--out` and moved into place
only when complete. For scheduled runs, prefer a dated
file name (`--out ~/backups/prod-$(date +%F).yabbt`) over `--overwrite`, so
older backups survive a bad run.

Sync supports the restore flags (`--update-existing`, `--prune`,
`--prune-permanent`, `--allow-mass-delete`, `--verify-after`,
`--mark-restored`, `--no-restore-map`, `--format`, `--progress`,
`--attachment-jobs`) plus the backup-side `--overwrite`, `--server-url`,
`--permissive`, `--personal-only`, and `--yolo`. Before anything is exported, sync checks the
KeePass side (flags, passphrase, and that an existing database opens) and
refuses an `--out` that is the `--keepass-file` itself, one of its
timestamped `<kdbx>.<UTC timestamp>.bak` copies, or its `.tmp-yabbt` temp
file. `--organization-id` selects the
target organization, matching its meaning on `restore`; the source export is
personal-vault scope for now. If the source account can see organization
items, that export is marked incomplete (see "Backup scope" above) and the
sync plan is blocked rather than mirroring a partial vault, unless
`--personal-only` acknowledges that only the personal vault is synced.

## KeePass

KeePass (.kdbx, KDBX4) works as both a target and a source. The database
passphrase is read from `--keepass-passphrase-env <ENV>`; keyfile support is a
follow-up.

As a **target** (`restore --target keepass`, `sync --target keepass`):
entries, groups, attachments, hidden/custom fields, TOTP, and the restore map
all land in the database, so repeated syncs update entries instead of
duplicating them. A missing `.kdbx` is created automatically on `--apply`
(never on dry-run). Non-permanent `--prune` moves entries to the
KeePassXC-recognized Recycle Bin; `--prune-permanent` removes them.
Nested groups map to Bitwarden's nested-folder names (`Parent/Child`) in both
directions; a `/` inside a group name is shown as `∕` (U+2215 DIVISION SLASH)
so a group literally named `a/b` stays distinct from a group `b` inside `a`,
and creating a folder maps it back. Prune only removes groups that are already
empty and never removes a parent of a group it keeps. Entries anywhere inside
the Recycle Bin, including its subgroups, count as deleted.

Attachments are compared by content (SHA-256), not by file name: an
attachment whose bytes changed in the source is an item update, uploaded with
`--update-existing`. With `--prune` as well, the old version is removed right
before the new one is added under the same file name; both happen in the same
save, so the database never ends up with neither version (if the upload
fails, the whole run is discarded and nothing is written). Without `--prune`
the new version is stored next to the old one as `name (2).ext`, and the
entry then counts as unchanged; a later `--prune` removes the old version. A
second attachment with an already-used name is likewise stored as
`name (2).ext` and does not show up as a change on every run. All changes of
one `--apply` are written in a single save at the end; if that save fails,
the database file is left untouched and nothing is reported as applied. A run
that changes nothing does not write the file at all (and makes no `.bak`
copy).

yabbt refuses to save over a database that another program (for example
KeePassXC) saved after yabbt read it: right before writing it re-hashes the
file, and if it changed, nothing is written, the run's changes are dropped,
and the error asks you to re-run, which then applies the changes on top of
the other program's version. (A save racing the last few milliseconds before
the rename is not detected; close the database in other programs during a
sync.)

An attachment that is also kept in the same entry's history (KeePassXC keeps
the previous version of an edited entry, attachments included) cannot be
removed through the `keepass` crate without corrupting that history. Prune
skips such an attachment instead of failing: the rest of the run is applied,
the summary counts it under `attachments_delete_skipped`, stderr warns with
the target item ID (never the file name), and the run exits 0. Delete the
entry's history in KeePassXC to let a later `--prune` remove it.

As a **source** (`backup --source keepass`, `diff --source keepass`,
`sync --source keepass`): the database is read into the canonical vault model,
including databases authored entirely in KeePassXC. A missing source file is
an error.

```bash
printf 'KeePass passphrase: '; read -rs KDBX_PASS; echo
export KDBX_PASS
# bw -> keepass, one go (dry-run by default, --apply to write)
yabbt sync --source bw --target keepass --source-profile prod \
  --keepass-file ~/vaults/mirror.kdbx --keepass-passphrase-env KDBX_PASS \
  --out ~/backups/prod-backup.yabbt --passphrase-env YABBT_PASSPHRASE --apply

# keepass -> archive, and verify nothing drifted
yabbt backup --source keepass --keepass-file ~/vaults/mirror.kdbx \
  --keepass-passphrase-env KDBX_PASS --out kdbx-backup.yabbt --passphrase-env YABBT_PASSPHRASE
yabbt diff --source keepass --keepass-file ~/vaults/mirror.kdbx \
  --keepass-passphrase-env KDBX_PASS --archive kdbx-backup.yabbt --passphrase-env YABBT_PASSPHRASE
```

**Safety caveat:** writes go through the `keepass` Rust crate's experimental
KDBX4 writer, which re-serializes the whole file from what it parses — KDBX
extras it does not model (plugin data, KeeShare settings, custom icons) can be
dropped on rewrite. Entries, groups, fields, and attachments are core format
data and round-trip fine. Before the first write of each run, yabbt copies the
existing file to a new `<file>.kdbx.<UTC timestamp>.bak` (for example
`vault.kdbx.20261011T120000Z.bak`) and prints a notice; earlier copies are
never overwritten, so the pre-yabbt original stays available, and old copies
are yours to clean up. Writes are atomic (temp file + rename), and the save
re-reads the written file and refuses to replace the database if any entry's
attachments do not read back identically, or if another program changed the
file since yabbt read it. Prefer pointing yabbt at a dedicated
sync-target database and opening it read-only in KeePassXC; if you point it at
a database KeePassXC actively maintains, the `.bak` copies are your recovery
path for those extras. `sync --source keepass --target keepass` is not supported; use
`backup` + `restore` for kdbx-to-kdbx copies.

## Restore

Plan a restore without mutating the target vault:

```bash
yabbt restore --target bw bitwarden.yabbt --passphrase-env YABBT_PASSPHRASE --dry-run
yabbt restore --target bw bitwarden.yabbt --passphrase-env YABBT_PASSPHRASE --dry-run --format json
yabbt restore --target bw org.yabbt --organization-id <target-org-id> --passphrase-env YABBT_PASSPHRASE --apply
```

`restore --dry-run` decrypts the archive, scans the current `bw` target account read-only, builds a target-aware mutation plan, and emits counts, blockers, and item/folder IDs only. It does not mutate the target vault.

`restore --apply` recomputes the target-aware plan immediately before mutation, verifies the archive strictly (an archive that fails verification blocks the plan, exit code 3, exactly as on `--dry-run`), creates missing folders by matching folders by exact name, creates only items missing from the target, rewrites item folder IDs to the target vault's folder IDs, and uploads attachments for newly created items. Existing changed items are skipped by default; target-only folders and items are never deleted.

Bitwarden organization and collection completeness is deferred to a later dedicated pass. Current restore behavior keeps guardrails so source organization and collection IDs are not replayed blindly. Collection-scoped items still block until collection mapping is implemented.

### Updating and pruning

`restore --apply --update-existing` also updates changed target items that were matched by restore map, per-item marker, original ID, or unique normalized fingerprint. It uses `bw edit item <id> <encodedJson>`, prints counts and IDs only, updates the restore map after successful edits, and still never deletes target-only items. For existing matched items, yabbt uploads archive attachments that are missing on the target item. When both sides carry a SHA-256 checksum (archives always do, and so do KeePass targets), attachments are paired one-to-one by content regardless of file name. `bw` item listings carry no checksum, so on a `bw` target an attachment with the same file name counts as present; size and content are not compared there. An item counts as changed because of its attachments only when an archive attachment is missing on the target; target-only attachments are left to `--prune`. Without `--prune` it does not delete target-only attachments or overwrite existing attachments.

`restore --dry-run --prune` reports target-only items, attachments, and folders that would be deleted. It prints counts and IDs only.

`restore --apply --prune` deletes target-only data after recomputing the plan and verifying the archive. Item deletion uses Bitwarden Trash by default. `--prune-permanent` passes `--permanent` for item deletes and is irreversible. `--prune` does not imply `--update-existing`; changed matched items are still skipped unless `--update-existing` is also passed.

Prune has a mass-delete guard: the plan is blocked (exit code 3, for `--dry-run` and `--apply` alike) when the archive contains no items at all, or when prune would delete more than half of the target's items and more than 10 of them. Those are the signatures of a wiped or broken source, the wrong archive, or the wrong target. The dry run still lists what would be deleted; pass `--allow-mass-delete` (together with `--prune`) when the deletion is intended.

`restore --apply --verify-after` additionally checks that every item ID returned by `bw create item` and every target ID edited by `bw edit item` can be fetched with `bw get item <id>`. For every uploaded attachment it looks the attachment up by file name on the fetched item, downloads it, and compares the SHA-256 of the downloaded bytes with the archived checksum (retrying a few times to allow for server-side lag). With `--prune`, it verifies deleted item, attachment, and folder IDs are absent from fresh target metadata. It prints verification counts only and does not print attachment names.

### Idempotency: restore map and markers

`restore --apply` writes one yabbt-managed secure note named `yabbt restore map - do not edit` into the target vault by default. The note contains a hidden `yabbt.restore_map` custom field mapping archive item IDs to Bitwarden-assigned target item IDs. The map is updated for newly created items and for archive items that already matched an existing target item; when its content would not change, the map item is not rewritten at all (`restore_map_updated: false`), so a no-op run makes no `bw edit` call and no KeePass save. Later dry-run/apply planning reads that single map item, excludes it from normal restore counts, and avoids duplicate creates without adding metadata to every restored item. If a map entry points to a missing target item, planning reports the stale source item ID and apply removes that stale map entry when rewriting the map. Restore-map notes inside an archive (taken from a vault that was itself a restore target) are yabbt bookkeeping for that vault: restore ignores them and does not count them in `archive_items`.

If an apply step fails part-way (for example an attachment upload or a delete), yabbt prints `restore partially applied` with the counts and the created, updated, and deleted IDs so far, still writes the restore map for the items it already created or matched (unless `--no-restore-map`), and exits 1. A plain re-run then does not duplicate those items; attachments whose upload failed show up as changed items and are uploaded by `--update-existing`.

`restore --apply --no-restore-map` opts out of creating or updating that map item. This is mainly useful when you want a completely yabbt-metadata-free target vault and accept weaker idempotency.

`restore --apply --mark-restored` writes hidden Bitwarden custom fields to newly created items: `yabbt.source_item_id`, `yabbt.source_fingerprint`, and `yabbt.archive_version`. Later dry-run/apply planning uses these markers to match restored items back to archive items even though Bitwarden assigned new item IDs.

If no restore-map, per-item marker, or ID match exists, restore planning falls back to an exact normalized item fingerprint. It only uses this fallback when exactly one target item matches; ambiguous fingerprint matches are reported by archive item ID and are not guessed silently.

Change detection (unchanged vs. update) and the fingerprint fallback compare the whole item, including data that only exists in Bitwarden's raw item payload: card and identity fields, SSH keys, passkeys, URI match types, and reprompt. Target-assigned or Bitwarden-maintained keys are ignored: item/folder/organization/collection IDs, timestamps, attachment IDs, yabbt marker fields, and password history (Bitwarden appends to it on every password edit, so it legitimately diverges between source and target).

Known limitation: repeated restore apply runs are strongest for items tracked by the restore map, items previously created with `--mark-restored`, or items that still match by original ID. If `--no-restore-map` is used, exact fingerprint fallback can still prevent duplicates for unchanged unique items, but edited or duplicate-looking items may still require explicit metadata or future natural-key matching.

The restore map and markers live in the target vault, so anyone who can edit that vault can influence which item an update or prune acts on. Only point restore and sync at target vaults whose other writers you trust; see the [threat model](docs/threat-model.md).

### Plan counts

Restore plan counts are target-aware:

- `archive_items`: items found in the archive.
- `target_items_scanned`: items found in the live target account, excluding yabbt-managed restore map items.
- `items_to_create`: archive items missing from the target.
- `items_to_update`: archive items whose target item has the same ID but different content fingerprint.
- `items_unchanged`: archive items already matching the target.
- `items_to_skip`: target-only items that would be left untouched.
- `items_to_delete`: target-only items that would be deleted only when `--prune` is passed.
- `attachments_to_delete`: target-only attachments on matched items that would be deleted only when `--prune` is passed.
- `folders_to_delete`: target-only folders that would be deleted only when `--prune` is passed.
- `warnings`: archive warnings plus stale restore-map entries and ambiguous fingerprint matches.

## Exit codes

- `0`: success (for `--dry-run`, the plan is ready to apply).
- `1`: runtime failure (backend error, unreadable or undecryptable archive, a failed `verify` command, a failed `--verify-after` check, failed or partial apply).
- `2`: usage error (invalid or conflicting flags, missing passphrase variable, refused weak passphrase, refused output path — including an `--out` that appeared while the export ran).
- `3`: `restore`/`sync` plan is blocked; the blockers are printed and nothing was applied. This includes an archive that decrypts but fails strict verification (for example, one marked incomplete). A blocked `--dry-run` exits `3` exactly like the same blocked `--apply`, so scripts can gate `--apply` on a clean dry run.

## Security

Archive payloads are serialized as a versioned tar layout, compressed with `zstd`, and encrypted with passphrase-based `age` encryption. Verification decrypts, decompresses, validates the archive manifest, and checks payload digests.

The passphrase is read from an environment variable so it does not appear in shell history as a command argument. Backup refuses short, common, or low-diversity passphrases unless `--yolo` is passed. Clear the variable after use in shared shells.

yabbt runs `bw` with a cleared environment plus an allowlist (`PATH`, `HOME`,
locale, `XDG_*`, proxy variables, `NODE_EXTRA_CA_CERTS` for a private CA, and
`BW_SESSION`/`BITWARDENCLI_APPDATA_DIR` when no `--bw-profile` is used).
Variables that change `bw`'s exit status or output (`BW_CLEANEXIT`,
`BW_RESPONSE`, `BW_QUIET`, `BW_RAW`, `BW_PRETTY`, `BW_NOINTERACTION`) or weaken
TLS (`NODE_TLS_REJECT_UNAUTHORIZED`, `NODE_OPTIONS`) never reach it. If your
setup needs another variable, list it in `YABBT_BW_ENV_PASSTHROUGH`
(comma-separated; `NAME_*` matches a prefix).

Attachments pass through a private temporary directory (mode 0700, files
0600) because `bw` only reads and writes attachments as files; the directory
is removed when the run ends.

[`docs/threat-model.md`](docs/threat-model.md) describes the assets, the
mitigations, and the known gaps in detail. To report a vulnerability, see
[SECURITY.md](SECURITY.md).

## Extracting an archive without yabbt

An archive is a standard age-encrypted, zstd-compressed tar file, so you can
always get your data back with standard tools:

```bash
contrib/extract-yabbt.sh backup.yabbt ./extracted
# equivalent to: age --decrypt backup.yabbt | zstd -d | tar -x -C ./extracted
```

This writes the **decrypted vault and attachments to disk in plain text**.
Extract only to a location you trust and delete it afterwards.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for building, testing, and the
test-data policy. Notable changes are listed in [CHANGELOG.md](CHANGELOG.md).
Design notes live in [`docs/design/`](docs/design/).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

## Disclaimer

This is an independent project. It is not affiliated with, endorsed by, or
sponsored by Bitwarden Inc., the KeePass project, the KeePassXC project, or
the Vaultwarden project. It talks to Bitwarden-compatible servers only through
the official Bitwarden CLI (`bw`) and reads and writes KeePass databases in
the KDBX 4 file format. Bitwarden, KeePass, KeePassXC, Vaultwarden, and other names are
trademarks of their respective owners and are used here only to describe
compatibility.

The software is provided "as is", without warranty of any kind; see the
license files. You are responsible for keeping independent backups of your
data.

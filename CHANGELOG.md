# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the version is 0.x, minor releases may contain breaking changes to
flags, output, and the archive format.

## [Unreleased]

First public release candidate.

### Added

- `backup --source bw`: back up a Bitwarden or Vaultwarden vault, including
  attachments, through the official `bw` CLI into a single archive (tar,
  zstd-compressed, age passphrase encryption). Weak archive passphrases are
  refused (exit code 2) unless `--yolo` is passed. `--organization-id` backs up one
  organization; `--permissive` turns failed attachment downloads into
  warnings and an incomplete archive.
- `verify` (strict integrity and completeness check) and `inspect`
  (secret-safe summary) for archives; `contrib/extract-yabbt.sh` to unpack an
  archive with `age`, `zstd`, and `tar` alone.
- `diff --source bw|keepass`: compare a live vault with an archive by item ID
  and content fingerprint, printing counts and IDs only.
- `restore --target bw|keepass` with dry-run planning (human or JSON output),
  conservative `--apply`, opt-in `--update-existing`, opt-in `--prune` (trash
  by default, `--prune-permanent` for irreversible deletes),
  `--verify-after`, and idempotent re-runs through a restore map stored in
  the target (`--no-restore-map` to opt out, `--mark-restored` for per-item
  markers).
- Named persistent `bw` profiles (`bw-login --profile`, `--bw-profile`) so
  several accounts stay logged in side by side, with interactive unlock.
- `sync`: one-way export, archive, verify, and restore in one run, from one
  `bw` profile to another or between `bw` and KeePass; dry run by default.
- KeePass (.kdbx, KDBX4) as restore/sync target and backup/diff/sync source,
  including attachments, custom fields, TOTP, nested groups, Recycle Bin
  prune, and a timestamped `.bak` copy before the first write of each run.
- Progress reporting (`--progress`) and parallel attachment transfers
  (`--attachment-jobs`).
- Documented exit codes, including exit code 3 for blocked restore/sync plans
  (also when the archive fails strict verification, for `--dry-run` and
  `--apply` alike).

### Security and data-safety hardening

- `bw` children run with a cleared, allowlisted environment; variables that
  change `bw`'s exit status or output or weaken TLS never reach it.
  `YABBT_BW_ENV_PASSTHROUGH` admits extra variables explicitly.
- Vault payloads are passed to `bw` on stdin, never on argv; backend-returned
  IDs are validated and never used to build temporary paths.
- Personal-vault backups that cannot include visible organization items are
  marked incomplete instead of reporting success; `--personal-only` on
  `backup`/`sync` acknowledges personal-vault scope explicitly. `backup`
  prints a short notice when the archive carries warnings.
- Archive decoding is bounded (decompression size, entry count, duplicate
  entries rejected) and restore opens and verifies an archive in a single
  pass. Archive writes are atomic: the archive is written to a randomly
  named owner-only temp file (a stale temp file from a crashed run never
  blocks a write), fsynced, moved into place, and the directory fsynced.
- `backup` and `sync` refuse to replace an existing archive without
  `--overwrite`, including an `--out` that appears while the export runs
  (the final move into place never replaces a file); `sync` refuses an
  `--out` that aliases the KeePass database, its timestamped `.bak` copies,
  or its temp file.
- `sync` publishes its archive only after reading it back and verifying it
  as complete: an incomplete or unverifiable export is discarded, the
  previous archive at `--out` survives even with `--overwrite`, and the plan
  is blocked.
- Prune is blocked by a mass-delete guard (empty archive, or more than half
  of the target and more than 10 items) unless `--allow-mass-delete` is
  passed.
- Restore change detection compares the raw item payload (cards,
  identities, SSH keys, passkeys, URI match types, reprompt); each target
  item binds to at most one archive item; a partially failed apply still
  records the restore map for what it created and reports what it did.
- KeePass: upgraded to `keepass` 0.15; attachments stay on the right entries
  after removals, including in databases whose entry history shares
  attachments; attachments are identified by entry and name instead of their
  position in the database's attachment pool, so a prune can no longer delete
  a neighbouring attachment or make `--verify-after` fail spuriously; nested
  groups are never destroyed by prune; existing attachments and earlier
  `.bak` copies are never overwritten; new databases use Argon2id (64 MiB)
  and enforce the passphrase-strength policy; a malformed
  `yabbt.bitwarden_raw` field in a database no longer crashes the reader.
- KeePass writes are batched: an apply saves (and re-reads to verify) the
  database once instead of after every change, which makes large restores
  into a new database much faster. A failed save leaves the file untouched,
  discards the unsaved changes, and reports nothing of them as applied.
- Restore compares attachments by content when both sides carry SHA-256
  hashes (archives, KeePass targets): an attachment whose bytes changed is an
  item update that re-uploads it with `--update-existing`, and KeePass's
  `name (2).ext` copies of duplicate file names no longer show up as changes
  on every run. Prune never deletes a target attachment of a matched item
  before its replacement is uploaded (this applies to `bw` targets too).
- KeePass rendering is deterministic (custom fields and attachments are
  sorted), so unchanged databases no longer produce spurious diffs; a group
  name containing `/` renders with `∕` (U+2215) instead of colliding with a
  nested group of the same path.
- No-op runs write nothing: when the restore map's content would not change
  it is not rewritten (`restore_map_updated: false`, no `bw edit`), and a
  KeePass edit that would leave an entry identical is not a change, so a
  `sync`/`restore --apply` that changes nothing no longer rewrites the kdbx
  or adds a full `.bak` copy every run.
- KeePass: yabbt refuses to save over a database that another program (e.g.
  KeePassXC) saved, or created, after yabbt read it; nothing is written, the
  run's changes are discarded, and the error asks for a re-run.
- Restore: an item whose archive attachments are all on the target is no
  longer an update because of target-only attachments (those are left to
  `--prune`), so `--update-existing` without `--prune` stops re-planning and
  re-saving the same KeePass entry on every run. On KeePass, a changed
  attachment replaced with `--update-existing --prune` keeps its file name
  (the old version is removed right before the upload, in the same save; a
  failed upload discards the whole run) instead of becoming `name (2).ext`.
- KeePass: a prune of an attachment that entry history still references
  (common in KeePassXC-edited databases) is skipped with a warning naming the
  target item ID and counted as `attachments_delete_skipped`, instead of
  aborting the whole apply.
- Archive publish: a directory fsync the filesystem does not support
  (EINVAL/ENOTSUP) after the archive was published is a warning, not a failed
  write; a no-clobber publish failing on filesystems without
  `renameat2`/hard links (some FUSE mounts) explains why and suggests
  `--overwrite` or a local filesystem.
- Secret-bearing types have redacting `Debug` implementations, and `bw`
  error output is sanitized before it is shown.
- Dependencies updated: keepass 0.17, zstd 0.14, base64 0.23, and all
  semver-compatible updates (clears 11 RustSec advisories, among them zstd and
  ctutils on the runtime path). Archives and kdbx files stay readable in both
  directions between the old and new builds. age stays on 0.11: age 0.12
  pulls in `p256` and `crypto-bigint` 0.5 (RUSTSEC-2026-0387, no fix in that
  line).

### Known limitations

- The source side of `sync` exports the personal vault only; exporting
  several organizations into one archive is not supported.
- Collection-scoped items block restore until collection mapping exists.
- KeePass keyfiles are not supported; KeePass writes use an experimental
  KDBX4 writer that can drop data it does not model.
- KeePass: an attachment that is also kept in the same entry's history cannot
  be removed through the `keepass` crate; prune keeps it and warns (delete
  the entry's history in KeePassXC to let prune remove it). A permanent
  entry delete the crate has to refuse for the same reason still stops the
  apply with an error.
- KeePass: an attachment that already ended up as `name (2).ext` keeps that
  name; only replacements made from now on keep the original name.
- Restore-map entries and markers in the target vault are trusted as-is; see
  `docs/threat-model.md`.

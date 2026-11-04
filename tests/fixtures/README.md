# Fixture Policy

Fixtures must be synthetic. Do not commit real vault exports, real passwords, real TOTP seeds, real notes, or real attachments.

Stage 0/1 tests construct some fixtures in Rust code. Bitwarden adapter tests use synthetic JSON fixture files under `tests/fixtures/bitwarden/`.

- Folders and collection-like relationships.
- Login, secure note, card, identity, SSH key, and unknown item kinds.
- Custom fields.
- Unicode names.
- Duplicate item names.
- Attachment metadata and attachment bytes.
- Completeness warnings.

Live Bitwarden or Vaultwarden integration data must be generated in disposable test accounts only.

## Live Vaultwarden E2E

`tests/vaultwarden_e2e.rs` is ignored by default and must be enabled explicitly:

```bash
YABBT_E2E_VAULTWARDEN=1 \
YABBT_E2E_VAULTWARDEN_URL=http://127.0.0.1:8080 \
YABBT_E2E_SOURCE_EMAIL=yabbt-source@example.test \
YABBT_E2E_SOURCE_PASSWORD='...' \
YABBT_E2E_TARGET_EMAIL=yabbt-target@example.test \
YABBT_E2E_TARGET_PASSWORD='...' \
cargo test --test vaultwarden_e2e -- --ignored --nocapture
```

Optional variables:

- `YABBT_E2E_VAULTWARDEN_ADMIN_TOKEN` enables admin API readiness checks and account reset helpers.
- `YABBT_E2E_RESET_ACCOUNTS=1` asks the admin helper to prepare missing accounts. Current Vaultwarden admin APIs can invite users but cannot set their master passwords, so the harness refuses to delete registered accounts automatically. If the accounts are missing, it sends invites and stops; complete registration with the configured passwords, then rerun without this flag.
- `YABBT_E2E_RUN_ID=<id>` controls generated default `yabbt-source-<id>@example.test` and `yabbt-target-<id>@example.test` account names.
- `YABBT_E2E_ALLOW_UNSAFE_ACCOUNTS=1` disables the guard that rejects non-test-looking email addresses.

The live test uses isolated Bitwarden CLI appdata directories per account, clears ambient Bitwarden CLI environment variables before each `bw` or `yabbt` invocation, removes leftover generated `YABBT E2E*` items/folders and the yabbt restore-map item from previous interrupted runs, seeds the source through `bw`, runs `yabbt backup`, verifies and inspects the archive, restores into the target account, then runs a second restore to check idempotency. It requires both source and target accounts to have no other data at the start so repeated runs do not mix old data with the deterministic seed.

Logs and assertions must remain secret-safe: print counts, IDs, and hashes rather than passwords, notes, TOTP seeds, custom field values, or attachment bytes.

Future `sync` E2E coverage should reuse this harness: source/target account setup, isolated `bw` sessions, deterministic seed data, and secret-safe shape comparison. The first sync scenario should stay one-way and conservative: dry-run first, explicit apply for mutation, and no destructive target cleanup unless a future mirror/prune flag asks for it.

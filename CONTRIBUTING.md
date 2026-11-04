# Contributing

Thanks for your interest in improving this project. Bug reports, reviews, and
pull requests are welcome. For security problems, follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.

## Never use real vault data

This applies to issues, pull requests, test fixtures, logs, and screenshots:

- Do not commit or attach real vault exports, archives, `.kdbx` files,
  passwords, TOTP seeds, notes, session keys, or attachments.
- Fixtures must be synthetic. See [`tests/fixtures/README.md`](tests/fixtures/README.md)
  for the fixture policy and what the synthetic fixtures cover.
- Live Bitwarden or Vaultwarden testing happens only in disposable test
  accounts.
- Test output and assertions must stay secret-safe: print counts, IDs, and
  hashes, never passwords, notes, TOTP seeds, custom field values, or
  attachment bytes.

## Building

You need Rust 1.89 or newer (the `rust-version` in `Cargo.toml`).

```bash
cargo build
cargo run -- doctor
```

## Checks

Run these before opening a pull request; CI runs the same:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

CI also runs `cargo audit` against the RustSec advisory database
(`cargo install cargo-audit --locked` to run it locally).

The regular test suite needs no network and no real `bw`: CLI tests drive
small fake `bw` scripts (they need `bash`), and KeePass tests create
throwaway databases. CLI tests that create KeePass databases set
`YABBT_KEEPASS_KDF=insecure-fast` to skip the expensive key derivation; that
hook exists only in debug/test builds.

## Live Vaultwarden end-to-end test

`tests/vaultwarden_e2e.rs` exercises backup, verify, inspect, restore, and a
second idempotent restore against a real Vaultwarden server through the real
`bw` CLI. It is `#[ignore]`d and additionally gated on an environment
variable, so it never runs by accident. It needs:

- a disposable Vaultwarden instance,
- two registered, **empty** test accounts (source and target),
- the official `bw` CLI on `PATH`.

```bash
YABBT_E2E_VAULTWARDEN=1 \
YABBT_E2E_VAULTWARDEN_URL=http://127.0.0.1:8080 \
YABBT_E2E_SOURCE_EMAIL=yabbt-source@example.test \
YABBT_E2E_SOURCE_PASSWORD='...' \
YABBT_E2E_TARGET_EMAIL=yabbt-target@example.test \
YABBT_E2E_TARGET_PASSWORD='...' \
cargo test --test vaultwarden_e2e -- --ignored --nocapture
```

Optional variables (admin token, account reset, run ID, and the guard against
non-test-looking email addresses) are described in
[`tests/fixtures/README.md`](tests/fixtures/README.md#live-vaultwarden-e2e).
Never point it at accounts that hold real data.

## Pull requests

- Keep changes focused; one logical change per commit where practical.
- Add or update tests for behavior changes. Restore, prune, and sync changes
  should include a test that shows nothing unexpected is mutated.
- Keep all user-facing output secret-safe (counts and IDs only, as described
  in [`docs/threat-model.md`](docs/threat-model.md)).
- If a change affects what data is read, written, deleted, or exposed, update
  `docs/threat-model.md` and the README in the same pull request.
- Add a line to the `Unreleased` section of [CHANGELOG.md](CHANGELOG.md) for
  user-visible changes.

## Commit messages

Short, lowercase, imperative subject lines with a type or area prefix,
matching the existing history, for example:

```text
fix: never overwrite an earlier keepass .bak copy
restore: block prune that would delete most of the target
docs: threat model for restore/sync safety fixes
```

Common prefixes are `feat`, `fix`, `docs`, `chore`, `ci`, `style`, and area
names such as `restore`, `sync`, `bw`, `cli`, `keepass`, and `archive`.

## License

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed under MIT OR Apache-2.0, without any
additional terms or conditions.

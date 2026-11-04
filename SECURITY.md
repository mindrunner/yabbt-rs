# Security Policy

This tool handles password-vault contents, so security reports are very
welcome and are treated as a priority.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through GitHub's private vulnerability reporting: open the
repository's **Security** tab and click **Report a vulnerability**. Include:

- the version or commit you tested,
- the command and flags involved,
- what an attacker needs (local access, control of a server, write access to
  a target vault or KeePass database, a crafted archive, ...),
- the impact, and steps to reproduce with synthetic data.

This is a volunteer-maintained project; the maintainer aims to acknowledge
reports within a week. Please allow reasonable time for a fix before
disclosing publicly. Reporters are credited in the advisory unless they
prefer otherwise.

**Never include real vault data** in a report or an issue: no exports,
archives, `.kdbx` files, passwords, session keys, TOTP seeds, or attachment
contents from a real vault. Reproduce with a disposable test account or a
synthetic database instead. If a report needs a sample file, generate one
with throwaway data.

## Scope

In scope, for example:

- disclosure of secrets (vault contents, archive or KeePass passphrases,
  `bw` session keys) through output, logs, files, process arguments, or the
  child-process environment;
- weaknesses in archive encryption, integrity checks, or verification
  (an archive that passes `verify` but is tampered with or incomplete);
- restore, prune, or sync acting on the wrong items, deleting data
  unexpectedly, or bypassing the dry-run, blocker, or mass-delete guards;
- unsafe handling of hostile input: crafted archives, malicious `bw` or
  server responses, or hostile KeePass databases;
- unsafe temporary files or file permissions.

Out of scope:

- vulnerabilities in the Bitwarden CLI, Bitwarden or Vaultwarden servers,
  KeePass/KeePassXC, or `age` themselves (report those upstream);
- attacks that require an already compromised user account or a replaced
  `bw` binary on `PATH`;
- known gaps documented in [`docs/threat-model.md`](docs/threat-model.md),
  unless you found a way to make them worse than described.

## Supported versions

The project is pre-1.0. Only the latest release (and the `main` branch) gets
security fixes.

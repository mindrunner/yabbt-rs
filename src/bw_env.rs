//! The environment every `bw` child process runs with.
//!
//! `bw` is a Node program whose contract with yabbt (exit status, stdout
//! shape, TLS verification) can be changed by environment variables:
//! `BW_CLEANEXIT` makes *failed* commands exit 0, `BW_RESPONSE`/`BW_QUIET`/
//! `BW_RAW`/`BW_PRETTY` change what is printed, and
//! `NODE_TLS_REJECT_UNAUTHORIZED=0` / `NODE_OPTIONS` disable certificate
//! verification or inject code. A stray variable in the user's shell must not
//! be able to make a failed restore look successful, so every `bw` child
//! starts from an empty environment plus an explicit allowlist instead of
//! inheriting yabbt's environment.

use std::ffi::{OsStr, OsString};
use std::path::Path;

/// Comma-separated list of extra variable names to pass through to `bw`
/// (an entry ending in `*` is a prefix). Escape hatch for setups that need a
/// variable the allowlist does not cover. Names in [`DENIED_ENV_VARS`] and,
/// in profile mode, the profile-managed variables are refused regardless.
pub const PASSTHROUGH_ENV: &str = "YABBT_BW_ENV_PASSTHROUGH";

/// Inherited from the parent when present.
const ALLOWED_ENV_VARS: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LANGUAGE",
    "TZ",
    "TMPDIR",
    "TERM",
    // Network access in proxied environments.
    "http_proxy",
    "https_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "no_proxy",
    "NO_PROXY",
    "all_proxy",
    "ALL_PROXY",
    // Self-hosted servers behind a private CA. This only *adds* trust
    // anchors; it cannot disable verification.
    "NODE_EXTRA_CA_CERTS",
    // Minimum for Node to run on Windows.
    "SYSTEMROOT",
    "WINDIR",
    "APPDATA",
    "LOCALAPPDATA",
    "USERPROFILE",
    "PATHEXT",
    "COMSPEC",
    "TEMP",
    "TMP",
];

/// Inherited from the parent when present, by name prefix. `XDG_CONFIG_HOME`
/// locates bw's default data directory on Linux.
const ALLOWED_ENV_PREFIXES: &[&str] = &["LC_", "XDG_"];

/// Never inherited, not even through [`PASSTHROUGH_ENV`]: they alter bw's
/// exit-status/output contract, disable TLS verification, or inject code.
/// yabbt sets the ones it needs itself.
pub const DENIED_ENV_VARS: &[&str] = &[
    "BW_CLEANEXIT",
    "BW_RESPONSE",
    "BW_QUIET",
    "BW_PRETTY",
    "BW_RAW",
    "BW_NOINTERACTION",
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "NODE_OPTIONS",
];

/// Variables that select the bw account. Inherited in ambient mode (the
/// documented `export BW_SESSION=...` workflow); in profile mode they are set
/// by yabbt and never inherited, so another account cannot cross-contaminate
/// the profile.
const ACCOUNT_ENV_VARS: &[&str] = &["BW_SESSION", "BITWARDENCLI_APPDATA_DIR"];

/// Which bw account state a child process should use.
#[derive(Clone, Copy)]
pub enum BwEnvScope<'a> {
    /// The user's own bw state: their `BW_SESSION` and
    /// `BITWARDENCLI_APPDATA_DIR` pass through.
    Ambient,
    /// A yabbt profile: the appdata dir and (optional) session come from
    /// yabbt, never from the parent environment.
    Profile {
        appdata_dir: &'a Path,
        session: Option<&'a str>,
    },
}

// The session is a secret; show only whether one is present.
impl std::fmt::Debug for BwEnvScope<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BwEnvScope::Ambient => f.write_str("Ambient"),
            BwEnvScope::Profile {
                appdata_dir,
                session,
            } => f
                .debug_struct("Profile")
                .field("appdata_dir", appdata_dir)
                .field("session", &session.map(|_| "<redacted>"))
                .finish(),
        }
    }
}

/// Build the complete environment for a `bw` child from `parent` (normally
/// `std::env::vars_os()`). The caller must clear the child's environment
/// before applying the result. `non_interactive` sets `BW_NOINTERACTION` so a
/// prompt fails fast instead of waiting on a closed stdin; interactive
/// `bw login`/`bw unlock` leave it unset.
pub fn bw_child_env<I>(
    parent: I,
    scope: BwEnvScope<'_>,
    non_interactive: bool,
) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let parent = parent.into_iter().collect::<Vec<_>>();
    let passthrough = parent
        .iter()
        .find(|(name, _)| name_eq(name, PASSTHROUGH_ENV))
        .and_then(|(_, value)| value.to_str())
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let profile_mode = matches!(scope, BwEnvScope::Profile { .. });

    let mut env = parent
        .into_iter()
        .filter(|(name, _)| {
            if DENIED_ENV_VARS.iter().any(|denied| name_eq(name, denied)) {
                return false;
            }
            let is_account_var = ACCOUNT_ENV_VARS.iter().any(|var| name_eq(name, var));
            if is_account_var {
                return !profile_mode;
            }
            ALLOWED_ENV_VARS
                .iter()
                .any(|allowed| name_eq(name, allowed))
                || ALLOWED_ENV_PREFIXES
                    .iter()
                    .any(|prefix| name_has_prefix(name, prefix))
                || passthrough
                    .iter()
                    .any(|entry| match entry.strip_suffix('*') {
                        Some(prefix) => name_has_prefix(name, prefix),
                        None => name_eq(name, entry),
                    })
        })
        .collect::<Vec<_>>();

    if let BwEnvScope::Profile {
        appdata_dir,
        session,
    } = scope
    {
        env.push((
            "BITWARDENCLI_APPDATA_DIR".into(),
            appdata_dir.as_os_str().to_owned(),
        ));
        if let Some(session) = session {
            env.push(("BW_SESSION".into(), session.into()));
        }
    }
    if non_interactive {
        env.push(("BW_NOINTERACTION".into(), "true".into()));
    }
    env
}

/// Environment variable names are case-insensitive on Windows only.
fn name_eq(name: &OsStr, expected: &str) -> bool {
    match name.to_str() {
        Some(name) if cfg!(windows) => name.eq_ignore_ascii_case(expected),
        Some(name) => name == expected,
        None => false,
    }
}

fn name_has_prefix(name: &OsStr, prefix: &str) -> bool {
    match name.to_str() {
        Some(name) if cfg!(windows) => name
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix)),
        Some(name) => name.starts_with(prefix),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent(vars: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        vars.iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value)))
            .collect()
    }

    fn get<'a>(env: &'a [(OsString, OsString)], name: &str) -> Option<&'a str> {
        env.iter()
            .rev()
            .find(|(key, _)| key == name)
            .and_then(|(_, value)| value.to_str())
    }

    const HOSTILE: &[(&str, &str)] = &[
        ("BW_CLEANEXIT", "1"),
        ("BW_RESPONSE", "true"),
        ("BW_QUIET", "true"),
        ("BW_PRETTY", "true"),
        ("BW_RAW", "true"),
        ("BW_NOINTERACTION", "false"),
        ("NODE_TLS_REJECT_UNAUTHORIZED", "0"),
        ("NODE_OPTIONS", "--require /tmp/evil.js"),
    ];

    #[test]
    fn hostile_vars_never_reach_bw_in_any_scope_even_via_passthrough() {
        let mut vars = HOSTILE.to_vec();
        vars.push((
            PASSTHROUGH_ENV,
            "BW_CLEANEXIT,NODE_TLS_REJECT_UNAUTHORIZED,NODE_*,BW_*",
        ));
        let appdata = Path::new("/profiles/prod");
        for scope in [
            BwEnvScope::Ambient,
            BwEnvScope::Profile {
                appdata_dir: appdata,
                session: None,
            },
        ] {
            for non_interactive in [false, true] {
                let env = bw_child_env(parent(&vars), scope, non_interactive);
                for (name, _) in HOSTILE {
                    if *name == "BW_NOINTERACTION" && non_interactive {
                        assert_eq!(get(&env, name), Some("true"));
                    } else {
                        assert_eq!(get(&env, name), None, "{name} leaked ({scope:?})");
                    }
                }
            }
        }
    }

    #[test]
    fn allowlisted_vars_pass_and_everything_else_is_dropped() {
        let env = bw_child_env(
            parent(&[
                ("PATH", "/usr/bin"),
                ("HOME", "/home/u"),
                ("LC_ALL", "C.UTF-8"),
                ("XDG_CONFIG_HOME", "/home/u/.config"),
                ("https_proxy", "http://proxy:3128"),
                ("NO_PROXY", "localhost"),
                ("NODE_EXTRA_CA_CERTS", "/etc/ssl/ca.pem"),
                ("AWS_SECRET_ACCESS_KEY", "nope"),
                ("YABBT_PASSPHRASE", "archive passphrase"),
                ("BW_CLIENTSECRET", "api secret"),
                ("BW_PASSWORD", "master password"),
            ]),
            BwEnvScope::Ambient,
            false,
        );

        assert_eq!(get(&env, "PATH"), Some("/usr/bin"));
        assert_eq!(get(&env, "HOME"), Some("/home/u"));
        assert_eq!(get(&env, "LC_ALL"), Some("C.UTF-8"));
        assert_eq!(get(&env, "XDG_CONFIG_HOME"), Some("/home/u/.config"));
        assert_eq!(get(&env, "https_proxy"), Some("http://proxy:3128"));
        assert_eq!(get(&env, "NO_PROXY"), Some("localhost"));
        assert_eq!(get(&env, "NODE_EXTRA_CA_CERTS"), Some("/etc/ssl/ca.pem"));
        assert_eq!(get(&env, "AWS_SECRET_ACCESS_KEY"), None);
        assert_eq!(get(&env, "YABBT_PASSPHRASE"), None);
        assert_eq!(get(&env, "BW_CLIENTSECRET"), None);
        assert_eq!(get(&env, "BW_PASSWORD"), None);
        assert_eq!(get(&env, "BW_NOINTERACTION"), None);
    }

    #[test]
    fn ambient_scope_keeps_the_users_bw_account() {
        let env = bw_child_env(
            parent(&[
                ("BW_SESSION", "user-session"),
                ("BITWARDENCLI_APPDATA_DIR", "/home/u/bw"),
            ]),
            BwEnvScope::Ambient,
            true,
        );

        assert_eq!(get(&env, "BW_SESSION"), Some("user-session"));
        assert_eq!(get(&env, "BITWARDENCLI_APPDATA_DIR"), Some("/home/u/bw"));
        assert_eq!(get(&env, "BW_NOINTERACTION"), Some("true"));
    }

    #[test]
    fn profile_scope_replaces_the_account_vars_and_ignores_passthrough_for_them() {
        let vars = parent(&[
            ("BW_SESSION", "other-session"),
            ("BITWARDENCLI_APPDATA_DIR", "/other"),
            (PASSTHROUGH_ENV, "BW_SESSION,BITWARDENCLI_APPDATA_DIR"),
        ]);
        let appdata = Path::new("/profiles/prod");

        let env = bw_child_env(
            vars.clone(),
            BwEnvScope::Profile {
                appdata_dir: appdata,
                session: Some("profile-session"),
            },
            true,
        );
        let sessions = env.iter().filter(|(name, _)| name == "BW_SESSION").count();
        assert_eq!(sessions, 1);
        assert_eq!(get(&env, "BW_SESSION"), Some("profile-session"));
        assert_eq!(
            get(&env, "BITWARDENCLI_APPDATA_DIR"),
            Some("/profiles/prod")
        );

        let env = bw_child_env(
            vars,
            BwEnvScope::Profile {
                appdata_dir: appdata,
                session: None,
            },
            false,
        );
        assert_eq!(get(&env, "BW_SESSION"), None);
    }

    #[test]
    fn passthrough_admits_listed_names_and_prefixes() {
        let env = bw_child_env(
            parent(&[
                (PASSTHROUGH_ENV, " BITWARDENCLI_DEBUG , CORP_PROXY_* ,"),
                ("BITWARDENCLI_DEBUG", "true"),
                ("CORP_PROXY_AUTH", "x"),
                ("CORP_OTHER", "y"),
            ]),
            BwEnvScope::Ambient,
            true,
        );

        assert_eq!(get(&env, "BITWARDENCLI_DEBUG"), Some("true"));
        assert_eq!(get(&env, "CORP_PROXY_AUTH"), Some("x"));
        assert_eq!(get(&env, "CORP_OTHER"), None);
        assert_eq!(get(&env, PASSTHROUGH_ENV), None);
    }
}

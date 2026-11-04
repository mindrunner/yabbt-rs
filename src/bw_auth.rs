//! Interactive authentication for named bw profiles. Runs in the CLI layer
//! with raw std::process so `bw` itself can prompt on the tty: yabbt never
//! sees the master password, and captured session keys stay in memory.

use crate::adapters::bw::redact;
use crate::bw_env::{BwEnvScope, bw_child_env};
use crate::bw_profile::BwProfile;
use std::process::{Command, Stdio};

#[derive(Debug, thiserror::Error)]
pub enum BwAuthError {
    #[error("bw status failed for profile `{profile}`: {message}")]
    Status { profile: String, message: String },
    #[error(
        "bw profile `{profile}` is not logged in; run `yabbt bw-login --profile {profile}` first"
    )]
    NotLoggedIn { profile: String },
    #[error("bw unlock failed for profile `{profile}`")]
    UnlockFailed { profile: String },
    #[error("bw login failed for profile `{profile}`")]
    LoginFailed { profile: String },
    #[error("bw config server failed for profile `{profile}`: {message}")]
    ConfigFailed { profile: String, message: String },
    #[error("running bw for profile auth failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BwProfileStatus {
    Unlocked,
    Locked,
    Unauthenticated,
}

/// Ensure the profile has a usable vault session. Returns the session key to
/// pass as `BW_SESSION` (`None` when the ambient state is already unlocked).
/// Locked profiles are unlocked interactively: `bw unlock --raw` inherits
/// stdin/stderr so bw prompts for the master password on the tty, while the
/// session key is captured from stdout and held in memory only.
pub fn ensure_session(profile: &BwProfile) -> Result<Option<String>, BwAuthError> {
    match profile_status(profile)? {
        BwProfileStatus::Unlocked => Ok(None),
        BwProfileStatus::Unauthenticated => Err(BwAuthError::NotLoggedIn {
            profile: profile.name.clone(),
        }),
        BwProfileStatus::Locked => {
            eprintln!(
                "unlocking bw profile `{}` (bw will prompt for the master password)",
                profile.name
            );
            let output = profile_command(profile)
                .args(["unlock", "--raw"])
                .stdin(Stdio::inherit())
                .stderr(Stdio::inherit())
                .stdout(Stdio::piped())
                .spawn()?
                .wait_with_output()?;
            if !output.status.success() {
                return Err(BwAuthError::UnlockFailed {
                    profile: profile.name.clone(),
                });
            }
            let session = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if session.is_empty() {
                return Err(BwAuthError::UnlockFailed {
                    profile: profile.name.clone(),
                });
            }
            Ok(Some(session))
        }
    }
}

/// True when the profile is logged in (locked or unlocked).
pub fn is_authenticated(profile: &BwProfile) -> Result<bool, BwAuthError> {
    Ok(profile_status(profile)? != BwProfileStatus::Unauthenticated)
}

/// Configure the server URL (when given) and run a fully interactive
/// `bw login` inside the profile directory.
pub fn interactive_login(profile: &BwProfile, server_url: Option<&str>) -> Result<(), BwAuthError> {
    if let Some(server_url) = server_url {
        let output = profile_command(profile)
            .args(["config", "server", server_url])
            .output()?;
        if !output.status.success() {
            return Err(BwAuthError::ConfigFailed {
                profile: profile.name.clone(),
                message: redact(&String::from_utf8_lossy(&output.stderr)),
            });
        }
    }

    eprintln!(
        "logging into bw profile `{}` (bw will prompt for credentials)",
        profile.name
    );
    let status = profile_command(profile)
        .arg("login")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    if !status.success() {
        return Err(BwAuthError::LoginFailed {
            profile: profile.name.clone(),
        });
    }
    // `bw login` prints `export BW_SESSION=...` to stdout on success. yabbt
    // does not use that value (it re-derives a session via unlock), so warn the
    // operator that the echoed key landed in their terminal scrollback.
    eprintln!(
        "notice: `bw` may have printed a BW_SESSION key above; yabbt does not need it — \
         clear your scrollback if this is a shared terminal"
    );
    Ok(())
}

fn profile_status(profile: &BwProfile) -> Result<BwProfileStatus, BwAuthError> {
    let output = profile_command(profile).arg("status").output()?;
    if !output.status.success() {
        return Err(BwAuthError::Status {
            profile: profile.name.clone(),
            message: redact(&String::from_utf8_lossy(&output.stderr)),
        });
    }
    let status = serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .ok()
        .and_then(|value| {
            value
                .get("status")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .ok_or_else(|| BwAuthError::Status {
            profile: profile.name.clone(),
            message: "bw status did not include a `status` field".to_string(),
        })?;
    match status.as_str() {
        "unlocked" => Ok(BwProfileStatus::Unlocked),
        "locked" => Ok(BwProfileStatus::Locked),
        "unauthenticated" => Ok(BwProfileStatus::Unauthenticated),
        other => Err(BwAuthError::Status {
            profile: profile.name.clone(),
            message: format!("unexpected bw status `{other}`"),
        }),
    }
}

/// `bw` inside the profile directory, started from a cleared environment
/// plus the `bw_env` allowlist. Interactive (`bw login`/`bw unlock` prompt on
/// the tty), so `BW_NOINTERACTION` is left unset.
fn profile_command(profile: &BwProfile) -> Command {
    let mut command = Command::new("bw");
    command.env_clear();
    command.envs(bw_child_env(
        std::env::vars_os(),
        BwEnvScope::Profile {
            appdata_dir: &profile.dir,
            session: None,
        },
        false,
    ));
    command
}

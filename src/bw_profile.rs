//! Named, persistent Bitwarden CLI profiles. Each profile is a directory
//! used as `BITWARDENCLI_APPDATA_DIR`, so several `bw` accounts stay logged
//! in side by side without the usual login/logout dance.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BwProfile {
    pub name: String,
    pub dir: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error(
        "invalid profile name `{0}`: use letters, digits, `.`, `_`, or `-`, starting with a letter or digit"
    )]
    InvalidName(String),
    #[error("cannot resolve the profile directory: neither XDG_DATA_HOME nor HOME is set")]
    NoBaseDir,
    #[error("profile directory I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// `$XDG_DATA_HOME/yabbt/bw-profiles`, falling back to
/// `$HOME/.local/share/yabbt/bw-profiles`.
pub fn profiles_base_dir() -> Result<PathBuf, ProfileError> {
    let data_home = std::env::var_os("XDG_DATA_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".local").join("share"))
        })
        .ok_or(ProfileError::NoBaseDir)?;
    Ok(data_home.join("yabbt").join("bw-profiles"))
}

/// Resolve a named profile under the default base dir, creating the profile
/// directory (mode 0o700) if it does not exist yet.
pub fn resolve_profile(name: &str) -> Result<BwProfile, ProfileError> {
    resolve_profile_in(&profiles_base_dir()?, name)
}

pub fn resolve_profile_in(base: &Path, name: &str) -> Result<BwProfile, ProfileError> {
    if !is_valid_profile_name(name) {
        return Err(ProfileError::InvalidName(name.to_string()));
    }
    let dir = base.join(name);
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let owner_only = std::fs::Permissions::from_mode(0o700);
        // Restrict the leaf and the enclosing profiles directory so profile
        // names are not world-listable. `create_dir_all` would otherwise leave
        // the parent at the process umask (typically 0755).
        std::fs::set_permissions(&dir, owner_only.clone())?;
        let _ = std::fs::set_permissions(base, owner_only);
    }
    Ok(BwProfile {
        name: name.to_string(),
        dir,
    })
}

fn is_valid_profile_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_simple_profile_names() {
        for name in ["prod", "lab2", "a.b_c-1", "0start"] {
            assert!(is_valid_profile_name(name), "expected `{name}` to be valid");
        }
    }

    #[test]
    fn rejects_dangerous_profile_names() {
        for name in [
            "", ".", "..", ".hidden", "-flag", "a/b", "a\\b", "a b", "a:b",
        ] {
            assert!(
                !is_valid_profile_name(name),
                "expected `{name}` to be rejected"
            );
        }
    }

    #[test]
    fn resolve_creates_profile_dir_with_restricted_permissions() {
        let base = tempfile::tempdir().expect("tempdir");
        let profile = resolve_profile_in(base.path(), "prod").expect("resolve profile");

        assert_eq!(profile.name, "prod");
        assert_eq!(profile.dir, base.path().join("prod"));
        assert!(profile.dir.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&profile.dir)
                .expect("profile dir metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }

    #[test]
    fn resolve_rejects_path_traversal_names() {
        let base = tempfile::tempdir().expect("tempdir");
        assert!(matches!(
            resolve_profile_in(base.path(), "../escape"),
            Err(ProfileError::InvalidName(_))
        ));
    }
}

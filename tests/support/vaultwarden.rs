use crate::support::E2eResult;
use reqwest::StatusCode;
use reqwest::blocking::Client;
use serde_json::Value;
use std::env;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct VaultwardenConfig {
    pub base_url: String,
    pub admin_token: Option<String>,
    pub source: TestAccount,
    pub target: TestAccount,
    pub reset_accounts: bool,
}

#[derive(Debug, Clone)]
pub struct TestAccount {
    pub email: String,
    pub password: String,
}

impl VaultwardenConfig {
    pub fn from_env() -> E2eResult<Self> {
        let base_url = required_env("YABBT_E2E_VAULTWARDEN_URL")?
            .trim_end_matches('/')
            .to_string();
        let run_id =
            env::var("YABBT_E2E_RUN_ID").unwrap_or_else(|_| Uuid::new_v4().simple().to_string());
        let default_password = format!("yabbt e2e passphrase {run_id} with enough entropy");
        let source = TestAccount {
            email: env::var("YABBT_E2E_SOURCE_EMAIL")
                .unwrap_or_else(|_| format!("yabbt-source-{run_id}@example.test")),
            password: env::var("YABBT_E2E_SOURCE_PASSWORD")
                .unwrap_or_else(|_| default_password.clone()),
        };
        let target = TestAccount {
            email: env::var("YABBT_E2E_TARGET_EMAIL")
                .unwrap_or_else(|_| format!("yabbt-target-{run_id}@example.test")),
            password: env::var("YABBT_E2E_TARGET_PASSWORD").unwrap_or(default_password),
        };
        let allow_unsafe_accounts = truthy_env("YABBT_E2E_ALLOW_UNSAFE_ACCOUNTS");
        let reset_accounts = truthy_env("YABBT_E2E_RESET_ACCOUNTS");

        validate_test_account(&source.email, allow_unsafe_accounts)?;
        validate_test_account(&target.email, allow_unsafe_accounts)?;
        if source.email == target.email {
            return Err("source and target Vaultwarden test accounts must differ".into());
        }

        Ok(Self {
            base_url,
            admin_token: env::var("YABBT_E2E_VAULTWARDEN_ADMIN_TOKEN")
                .ok()
                .filter(|value| !value.is_empty()),
            source,
            target,
            reset_accounts,
        })
    }

    pub fn admin_client(&self) -> E2eResult<Option<VaultwardenAdmin>> {
        let Some(token) = &self.admin_token else {
            return Ok(None);
        };
        VaultwardenAdmin::login(&self.base_url, token).map(Some)
    }
}

#[derive(Debug)]
pub struct VaultwardenAdmin {
    base_url: String,
    client: Client,
}

impl VaultwardenAdmin {
    pub fn login(base_url: &str, token: &str) -> E2eResult<Self> {
        let client = Client::builder()
            .cookie_store(true)
            .timeout(Duration::from_secs(15))
            .build()?;
        let response = client
            .post(format!("{}/admin", base_url.trim_end_matches('/')))
            .form(&[("token", token)])
            .send()?;
        if !response.status().is_success() && response.status() != StatusCode::FOUND {
            return Err(format!(
                "Vaultwarden admin login failed with HTTP status {}",
                response.status()
            )
            .into());
        }
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        })
    }

    pub fn ensure_ready(&self) -> E2eResult<()> {
        let response = self
            .client
            .get(format!("{}/admin/users", self.base_url))
            .send()?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!(
                "Vaultwarden admin API readiness check failed with HTTP status {}",
                response.status()
            )
            .into())
        }
    }

    pub fn reset_accounts_if_requested(&self, config: &VaultwardenConfig) -> E2eResult<()> {
        if !config.reset_accounts {
            return Ok(());
        }
        let source_exists = self.user_id_by_mail(&config.source.email)?.is_some();
        let target_exists = self.user_id_by_mail(&config.target.email)?.is_some();
        if source_exists || target_exists {
            return Err(
                "YABBT_E2E_RESET_ACCOUNTS=1 requested, but Vaultwarden admin APIs cannot set master passwords after deleting users; refusing to delete registered test accounts automatically. Use clean pre-registered accounts, or delete/re-register them manually before rerunning."
                    .into(),
            );
        }
        self.invite_user(&config.source.email)?;
        self.invite_user(&config.target.email)?;
        Err(
            "Vaultwarden admin invited the missing test accounts. Complete registration for both accounts with the configured passwords, then rerun without YABBT_E2E_RESET_ACCOUNTS=1."
                .into(),
        )
    }

    pub fn invite_user(&self, email: &str) -> E2eResult<()> {
        let response = self
            .client
            .post(format!("{}/admin/invite", self.base_url))
            .json(&serde_json::json!({ "email": email }))
            .send()?;
        if response.status().is_success() || response.status() == StatusCode::CONFLICT {
            Ok(())
        } else {
            Err(format!(
                "Vaultwarden admin invite for test account failed with HTTP status {}",
                response.status()
            )
            .into())
        }
    }

    fn user_id_by_mail(&self, email: &str) -> E2eResult<Option<String>> {
        let encoded_email = percent_encode_path_segment(email);
        let response = self
            .client
            .get(format!(
                "{}/admin/users/by-mail/{encoded_email}",
                self.base_url
            ))
            .send()?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(format!(
                "Vaultwarden admin user lookup failed with HTTP status {}",
                response.status()
            )
            .into());
        }
        let user: Value = response.json()?;
        Ok(user
            .get("id")
            .or_else(|| user.get("uuid"))
            .and_then(Value::as_str)
            .map(str::to_string))
    }
}

fn required_env(name: &str) -> E2eResult<String> {
    env::var(name)
        .map_err(|error| format!("{name} is required for Vaultwarden E2E: {error}").into())
}

fn truthy_env(name: &str) -> bool {
    matches!(env::var(name).as_deref(), Ok("1") | Ok("true") | Ok("yes"))
}

fn validate_test_account(email: &str, allow_unsafe_accounts: bool) -> E2eResult<()> {
    if allow_unsafe_accounts || looks_like_test_account(email) {
        Ok(())
    } else {
        Err(format!(
            "refusing to use non-test-looking Vaultwarden account `{email}`; use yabbt-* or +yabbt-* test accounts, or set YABBT_E2E_ALLOW_UNSAFE_ACCOUNTS=1"
        )
        .into())
    }
}

fn looks_like_test_account(email: &str) -> bool {
    email.starts_with("yabbt-") || email.contains("+yabbt-") || email.ends_with("@example.test")
}

fn percent_encode_path_segment(input: &str) -> String {
    input
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![byte as char]
            }
            other => format!("%{other:02X}").chars().collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{looks_like_test_account, percent_encode_path_segment};

    #[test]
    fn recognizes_dedicated_test_accounts() {
        assert!(looks_like_test_account("yabbt-source-run@example.test"));
        assert!(looks_like_test_account("person+yabbt-target@example.com"));
        assert!(!looks_like_test_account("person@example.com"));
    }

    #[test]
    fn encodes_email_for_admin_lookup_path() {
        assert_eq!(
            percent_encode_path_segment("person+yabbt@example.test"),
            "person%2Byabbt%40example.test"
        );
    }
}

use crate::support::E2eResult;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::Value;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use yabbt::adapters::bitwarden_json::normalize_export;
use yabbt::model::Vault;
use yabbt::restore_map::RESTORE_MAP_ITEM_NAME;

#[derive(Debug)]
pub struct BwAccount {
    server_url: String,
    email: String,
    password: String,
    appdata_dir: TempDir,
    session: Option<String>,
}

impl BwAccount {
    pub fn new(server_url: &str, email: &str, password: &str) -> E2eResult<Self> {
        let account = Self {
            server_url: server_url.to_string(),
            email: email.to_string(),
            password: password.to_string(),
            appdata_dir: tempfile::tempdir()?,
            session: None,
        };
        account.run_bw("config server", ["config", "server", server_url], false)?;
        Ok(account)
    }

    pub fn login(&mut self) -> E2eResult<()> {
        let output = self.run_bw(
            "login",
            [
                "--raw",
                "login",
                &self.email,
                "--passwordenv",
                "YABBT_E2E_BW_PASSWORD",
            ],
            false,
        )?;
        let session = String::from_utf8(output)?.trim().to_string();
        if session.is_empty() {
            return Err("bw login succeeded but did not return a session key".into());
        }
        self.session = Some(session);
        self.sync()
    }

    pub fn sync(&self) -> E2eResult<()> {
        self.run_bw("sync", ["sync"], true).map(|_| ())
    }

    pub fn cleanup_yabbt_e2e_data(&self) -> E2eResult<()> {
        self.sync()?;
        for item in self.list_objects("items")? {
            let name = item.get("name").and_then(Value::as_str).unwrap_or_default();
            if (is_yabbt_e2e_name(name) || name == RESTORE_MAP_ITEM_NAME)
                && let Some(id) = item.get("id").and_then(Value::as_str)
            {
                self.delete_object("item", id)?;
            }
        }
        self.sync()?;
        for folder in self.list_objects("folders")? {
            let name = folder
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if is_yabbt_e2e_name(name)
                && let Some(id) = folder.get("id").and_then(Value::as_str)
            {
                self.delete_object("folder", id)?;
            }
        }
        self.sync()
    }

    pub fn create_folder(&self, name: &str) -> E2eResult<String> {
        self.create_object("folder", serde_json::json!({ "name": name }))
    }

    pub fn create_item(&self, payload: Value) -> E2eResult<String> {
        self.create_object("item", payload)
    }

    pub fn create_attachment(&self, item_id: &str, path: &Path) -> E2eResult<String> {
        let path = path
            .to_str()
            .ok_or("attachment path must be valid UTF-8 for bw CLI")?;
        let output = self.run_bw(
            "create attachment",
            ["create", "attachment", "--file", path, "--itemid", item_id],
            true,
        )?;
        parse_id(&String::from_utf8(output)?)
    }

    pub fn export_vault(&self) -> E2eResult<Vault> {
        self.sync()?;
        let export_json = String::from_utf8(self.run_bw(
            "export",
            ["--raw", "export", "--format", "json"],
            true,
        )?)?;
        let listed_items_json =
            String::from_utf8(self.run_bw("list items", ["list", "items"], true)?)?;
        Ok(normalize_export(
            &export_json,
            &listed_items_json,
            "bw",
            Some(&self.server_url),
        )?)
    }

    pub fn appdata_dir(&self) -> &Path {
        self.appdata_dir.path()
    }

    pub fn session(&self) -> Option<&str> {
        self.session.as_deref()
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    fn create_object(&self, object: &str, payload: Value) -> E2eResult<String> {
        let encoded = encode_json(&payload)?;
        let output = self.run_bw(
            &format!("create {object}"),
            ["--raw", "create", object, encoded.as_str()],
            true,
        )?;
        parse_id(&String::from_utf8(output)?)
    }

    fn list_objects(&self, object: &str) -> E2eResult<Vec<Value>> {
        let output =
            String::from_utf8(self.run_bw(&format!("list {object}"), ["list", object], true)?)?;
        Ok(serde_json::from_str(&output)?)
    }

    fn delete_object(&self, object: &str, id: &str) -> E2eResult<()> {
        self.run_bw(&format!("delete {object}"), ["delete", object, id], true)
            .map(|_| ())
    }

    fn run_bw<I, S>(&self, operation: &str, args: I, include_session: bool) -> E2eResult<Vec<u8>>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = Command::new("bw");
        clear_bitwarden_env(&mut command);
        command
            .args(args)
            .env("BITWARDENCLI_APPDATA_DIR", self.appdata_dir.path())
            .env("HOME", self.appdata_dir.path())
            .env("YABBT_E2E_BW_PASSWORD", &self.password);
        if include_session {
            let session = self
                .session
                .as_deref()
                .ok_or("bw operation requires an authenticated session")?;
            command.env("BW_SESSION", session);
        }
        let output = command.output()?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!(
                "bw {operation} failed with status {}: {stderr}",
                output.status.code().unwrap_or(-1)
            )
            .into())
        }
    }
}

pub fn apply_yabbt_bw_env(account: &BwAccount, command: &mut assert_cmd::Command) {
    clear_assert_bitwarden_env(command);
    command
        .env("BITWARDENCLI_APPDATA_DIR", account.appdata_dir())
        .env("HOME", account.appdata_dir());
    if let Some(session) = account.session() {
        command.env("BW_SESSION", session);
    }
}

fn clear_bitwarden_env(command: &mut Command) {
    for name in BITWARDEN_ENV_VARS {
        command.env_remove(name);
    }
}

fn clear_assert_bitwarden_env(command: &mut assert_cmd::Command) {
    for name in BITWARDEN_ENV_VARS {
        command.env_remove(name);
    }
}

const BITWARDEN_ENV_VARS: &[&str] = &[
    "BITWARDENCLI_APPDATA_DIR",
    "BW_CLIENTID",
    "BW_CLIENTSECRET",
    "BW_PASSWORD",
    "BW_SESSION",
];

pub fn encode_json(value: &Value) -> E2eResult<String> {
    Ok(BASE64.encode(serde_json::to_vec(value)?))
}

fn parse_id(output: &str) -> E2eResult<String> {
    let value: Value = serde_json::from_str(output)?;
    value
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "bw create response did not include an id".into())
}

pub fn write_attachment_file(dir: &Path, name: &str, bytes: &[u8]) -> E2eResult<PathBuf> {
    let path = dir.join(name);
    std::fs::write(&path, bytes)?;
    Ok(path)
}

fn is_yabbt_e2e_name(name: &str) -> bool {
    name.starts_with("YABBT E2E")
}

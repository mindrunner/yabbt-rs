use clap::{Parser, Subcommand, ValueEnum};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::adapters::BackupSource;
use crate::adapters::bitwarden_json::{ORG_ITEMS_EXCLUDED_BY_SCOPE, ORG_ITEMS_NOT_EXPORTED};
use crate::adapters::bw::BwProfileEnv;
use crate::adapters::bw::{BwAttachmentMode, BwSourceAdapter, BwSourceOptions};
use crate::adapters::command::StdCommandRunner;
use crate::adapters::keepass::{KeepassVault, KeepassVaultOptions};
use crate::archive::{
    ArchiveBuilder, ArchiveError, ArchiveSummary, OpenedArchive, StagedArchive, WriteMode,
    open_and_verify_archive, open_archive, summarize_archive, validate_passphrase_strength,
    verify_archive,
};
use crate::bw_auth::{ensure_session, interactive_login, is_authenticated};
use crate::bw_profile::resolve_profile;
use crate::diff::{DiffReport, diff_vaults};
use crate::model::CompletenessReport;
use crate::progress::{NoopProgress, ProgressMode, ProgressReporter, reporter_for_mode};
use crate::restore_apply::{
    ApplyOptions, ApplySummary, RestoreError, RestoreTarget, apply_restore_plan,
};
use crate::restore_plan::{
    RestorePlan, RestorePlanOptions, RestorePlanStatus, plan_restore_with_options_and_progress,
};

const DEFAULT_ATTACHMENT_JOBS: usize = 4;
/// Exit code for a restore/sync whose plan has blockers: nothing was applied
/// to the target. Distinct from 1 (runtime failure) and 2 (usage error) so
/// scripts can tell "refused to act" from "crashed".
pub const EXIT_PLAN_BLOCKED: i32 = 3;

#[derive(Debug, Parser)]
#[command(name = "yabbt", about = "password vault backup toolkit")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum Command {
    Doctor,
    Backup {
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
        /// Replace an existing archive at --out.
        #[arg(long)]
        overwrite: bool,
        #[arg(long)]
        passphrase_env: Option<String>,
        #[arg(long)]
        server_url: Option<String>,
        #[arg(long)]
        organization_id: Option<String>,
        /// Accept that a bw export without --organization-id covers the
        /// personal vault only: organization items are counted and reported
        /// but do not mark the archive incomplete.
        #[arg(long, conflicts_with = "organization_id")]
        personal_only: bool,
        #[arg(long)]
        permissive: bool,
        #[arg(long)]
        yolo: bool,
        #[arg(long)]
        bw_profile: Option<String>,
        #[arg(long)]
        keepass_file: Option<PathBuf>,
        #[arg(long)]
        keepass_passphrase_env: Option<String>,
        #[arg(long, value_enum, default_value_t = ProgressMode::Auto)]
        progress: ProgressMode,
        #[arg(long, default_value_t = DEFAULT_ATTACHMENT_JOBS)]
        attachment_jobs: usize,
    },
    Inspect {
        archive: Option<PathBuf>,
        #[arg(long)]
        passphrase_env: Option<String>,
    },
    Verify {
        archive: Option<PathBuf>,
        #[arg(long)]
        passphrase_env: Option<String>,
    },
    Diff {
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        archive: Option<PathBuf>,
        #[arg(long)]
        passphrase_env: Option<String>,
        #[arg(long)]
        server_url: Option<String>,
        #[arg(long)]
        organization_id: Option<String>,
        #[arg(long)]
        permissive: bool,
        #[arg(long)]
        bw_profile: Option<String>,
        #[arg(long)]
        keepass_file: Option<PathBuf>,
        #[arg(long)]
        keepass_passphrase_env: Option<String>,
        #[arg(long, default_value_t = DEFAULT_ATTACHMENT_JOBS)]
        attachment_jobs: usize,
    },
    Restore {
        #[arg(long)]
        target: Option<String>,
        archive: Option<PathBuf>,
        #[arg(long)]
        passphrase_env: Option<String>,
        #[arg(long)]
        organization_id: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        verify_after: bool,
        #[arg(long)]
        mark_restored: bool,
        #[arg(long)]
        no_restore_map: bool,
        #[arg(long)]
        update_existing: bool,
        #[arg(long)]
        prune: bool,
        #[arg(long)]
        prune_permanent: bool,
        /// Allow --prune to delete most of the target (or everything, for an
        /// empty archive).
        #[arg(long)]
        allow_mass_delete: bool,
        #[arg(long)]
        yolo: bool,
        #[arg(long)]
        bw_profile: Option<String>,
        #[arg(long)]
        keepass_file: Option<PathBuf>,
        #[arg(long)]
        keepass_passphrase_env: Option<String>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
        #[arg(long, value_enum, default_value_t = ProgressMode::Auto)]
        progress: ProgressMode,
        #[arg(long, default_value_t = DEFAULT_ATTACHMENT_JOBS)]
        attachment_jobs: usize,
    },
    BwLogin {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        server_url: Option<String>,
    },
    Sync {
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        source_profile: Option<String>,
        #[arg(long)]
        target_profile: Option<String>,
        #[arg(long)]
        keepass_file: Option<PathBuf>,
        #[arg(long)]
        keepass_passphrase_env: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
        /// Replace an existing archive at --out.
        #[arg(long)]
        overwrite: bool,
        #[arg(long)]
        passphrase_env: Option<String>,
        #[arg(long)]
        server_url: Option<String>,
        #[arg(long)]
        organization_id: Option<String>,
        /// Accept that the bw source export covers the personal vault only:
        /// organization items are counted and reported but do not mark the
        /// archive incomplete or block the sync.
        #[arg(long)]
        personal_only: bool,
        #[arg(long)]
        permissive: bool,
        #[arg(long)]
        yolo: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        verify_after: bool,
        #[arg(long)]
        mark_restored: bool,
        #[arg(long)]
        no_restore_map: bool,
        #[arg(long)]
        update_existing: bool,
        #[arg(long)]
        prune: bool,
        #[arg(long)]
        prune_permanent: bool,
        /// Allow --prune to delete most of the target (or everything, for an
        /// empty archive).
        #[arg(long)]
        allow_mass_delete: bool,
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
        #[arg(long, value_enum, default_value_t = ProgressMode::Auto)]
        progress: ProgressMode,
        #[arg(long, default_value_t = DEFAULT_ATTACHMENT_JOBS)]
        attachment_jobs: usize,
    },
}

pub fn run<I, S>(args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<OsString> + Clone,
{
    match Cli::try_parse_from(args) {
        Ok(cli) => run_cli(cli),
        Err(error) => error.exit(),
    }
}

pub fn run_cli(cli: Cli) -> i32 {
    match cli.command.unwrap_or(Command::Doctor) {
        Command::Doctor => {
            println!("yabbt doctor");
            println!("status: archive core foundation available");
            println!(
                "live backends: bw backup, diff, restore dry-run, and restore apply available"
            );
            0
        }
        Command::Backup {
            source,
            out,
            overwrite,
            passphrase_env,
            server_url,
            organization_id,
            personal_only,
            permissive,
            yolo,
            bw_profile,
            keepass_file,
            keepass_passphrase_env,
            progress,
            attachment_jobs,
        } => run_backup(BackupOptions {
            source,
            out,
            overwrite,
            passphrase_env,
            server_url,
            organization_id,
            personal_only,
            permissive,
            yolo,
            bw_profile,
            keepass_file,
            keepass_passphrase_env,
            progress,
            attachment_jobs,
        }),
        Command::Inspect {
            archive,
            passphrase_env,
        } => run_archive_summary("inspect", archive, passphrase_env),
        Command::Verify {
            archive,
            passphrase_env,
        } => run_archive_summary("verify", archive, passphrase_env),
        Command::Diff {
            source,
            archive,
            passphrase_env,
            server_url,
            organization_id,
            permissive,
            bw_profile,
            keepass_file,
            keepass_passphrase_env,
            attachment_jobs,
        } => run_diff(DiffOptions {
            source,
            archive,
            passphrase_env,
            server_url,
            organization_id,
            permissive,
            bw_profile,
            keepass_file,
            keepass_passphrase_env,
            attachment_jobs,
        }),
        Command::Restore {
            target,
            archive,
            passphrase_env,
            organization_id,
            dry_run,
            apply,
            verify_after,
            mark_restored,
            no_restore_map,
            update_existing,
            prune,
            prune_permanent,
            allow_mass_delete,
            yolo,
            bw_profile,
            keepass_file,
            keepass_passphrase_env,
            format,
            progress,
            attachment_jobs,
        } => run_restore(RestoreOptions {
            target,
            archive,
            passphrase_env,
            organization_id,
            dry_run,
            apply,
            verify_after,
            mark_restored,
            no_restore_map,
            update_existing,
            prune,
            prune_permanent,
            allow_mass_delete,
            yolo,
            bw_profile,
            keepass_file,
            keepass_passphrase_env,
            format,
            progress,
            attachment_jobs,
        }),
        Command::BwLogin {
            profile,
            server_url,
        } => run_bw_login(profile, server_url),
        Command::Sync {
            source,
            target,
            source_profile,
            target_profile,
            keepass_file,
            keepass_passphrase_env,
            out,
            overwrite,
            passphrase_env,
            server_url,
            organization_id,
            personal_only,
            permissive,
            yolo,
            dry_run,
            apply,
            verify_after,
            mark_restored,
            no_restore_map,
            update_existing,
            prune,
            prune_permanent,
            allow_mass_delete,
            format,
            progress,
            attachment_jobs,
        } => run_sync(SyncOptions {
            source,
            target,
            source_profile,
            target_profile,
            keepass_file,
            keepass_passphrase_env,
            out,
            overwrite,
            passphrase_env,
            server_url,
            organization_id,
            personal_only,
            permissive,
            yolo,
            dry_run,
            apply,
            verify_after,
            mark_restored,
            no_restore_map,
            update_existing,
            prune,
            prune_permanent,
            allow_mass_delete,
            format,
            progress,
            attachment_jobs,
        }),
    }
}

struct SyncOptions {
    source: Option<String>,
    target: Option<String>,
    source_profile: Option<String>,
    target_profile: Option<String>,
    keepass_file: Option<PathBuf>,
    keepass_passphrase_env: Option<String>,
    out: Option<PathBuf>,
    overwrite: bool,
    passphrase_env: Option<String>,
    server_url: Option<String>,
    organization_id: Option<String>,
    personal_only: bool,
    permissive: bool,
    yolo: bool,
    dry_run: bool,
    apply: bool,
    verify_after: bool,
    mark_restored: bool,
    no_restore_map: bool,
    update_existing: bool,
    prune: bool,
    prune_permanent: bool,
    allow_mass_delete: bool,
    format: OutputFormat,
    progress: ProgressMode,
    attachment_jobs: usize,
}

/// One-way sync: export the source vault, stage and verify the encrypted
/// archive, publish it at `--out` only if it verified (this run doubles as a
/// backup), then plan a restore into the target. Dry-run by default;
/// `--apply` mutates the target. The source is only ever exported from —
/// sync cannot mutate it.
fn run_sync(options: SyncOptions) -> i32 {
    let SyncOptions {
        source,
        target,
        source_profile,
        target_profile,
        keepass_file,
        keepass_passphrase_env,
        out,
        overwrite,
        passphrase_env,
        server_url,
        organization_id,
        personal_only,
        permissive,
        yolo,
        dry_run,
        apply,
        verify_after,
        mark_restored,
        no_restore_map,
        update_existing,
        prune,
        prune_permanent,
        allow_mass_delete,
        format,
        progress,
        attachment_jobs,
    } = options;

    if let Err(code) = validate_attachment_jobs(attachment_jobs) {
        return code;
    }
    let source_backend = source.as_deref().unwrap_or_default().to_string();
    if !matches!(source_backend.as_str(), "bw" | "keepass") {
        eprintln!("unsupported sync source: {source_backend}");
        return 2;
    }
    let target_backend = target.as_deref().unwrap_or_default().to_string();
    if !matches!(target_backend.as_str(), "bw" | "keepass") {
        eprintln!("unsupported sync target: {target_backend}");
        return 2;
    }
    if source_backend == "keepass" && target_backend == "keepass" {
        eprintln!(
            "sync from keepass to keepass is not supported yet; use backup --source keepass and restore --target keepass"
        );
        return 2;
    }
    if dry_run && apply {
        eprintln!("sync cannot combine --dry-run with --apply (dry-run is the default)");
        return 2;
    }
    if verify_after && !apply {
        eprintln!("sync --verify-after requires --apply");
        return 2;
    }
    if mark_restored && !apply {
        eprintln!("sync --mark-restored requires --apply");
        return 2;
    }
    if no_restore_map && !apply {
        eprintln!("sync --no-restore-map requires --apply");
        return 2;
    }
    if update_existing && !apply {
        eprintln!("sync --update-existing requires --apply");
        return 2;
    }
    if prune_permanent && (!apply || !prune) {
        eprintln!("sync --prune-permanent requires --apply --prune");
        return 2;
    }
    if allow_mass_delete && !prune {
        eprintln!("sync --allow-mass-delete requires --prune");
        return 2;
    }
    let restore_map = apply && !no_restore_map;

    // Per-side flag validation.
    if source_backend == "bw" && source_profile.is_none() {
        eprintln!("sync requires --source-profile <name>");
        return 2;
    }
    if target_backend == "bw" && target_profile.is_none() {
        eprintln!("sync requires --target-profile <name>");
        return 2;
    }
    if source_backend != "bw" && source_profile.is_some() {
        eprintln!("sync --source-profile is only valid with --source bw");
        return 2;
    }
    if target_backend != "bw" && target_profile.is_some() {
        eprintln!("sync --target-profile is only valid with --target bw");
        return 2;
    }
    if source_backend != "bw" && (server_url.is_some() || permissive) {
        eprintln!("sync --server-url and --permissive are only valid with --source bw");
        return 2;
    }
    if source_backend != "bw" && personal_only {
        eprintln!("sync --personal-only is only valid with --source bw");
        return 2;
    }
    if target_backend != "bw" && organization_id.is_some() {
        eprintln!("sync --organization-id is only valid with --target bw");
        return 2;
    }
    if source_backend == "bw"
        && target_backend == "bw"
        && (keepass_file.is_some() || keepass_passphrase_env.is_some())
    {
        eprintln!("sync --keepass-file requires a keepass source or target");
        return 2;
    }
    let Some(out) = out else {
        eprintln!("sync requires --out <archive>");
        return 2;
    };
    if let Err(code) = prepare_archive_out("sync", &out, overwrite) {
        return code;
    }
    if let Err(code) = reject_out_aliasing_keepass("sync", &out, keepass_file.as_deref()) {
        return code;
    }
    let passphrase = match read_passphrase_env("sync", passphrase_env) {
        Ok(passphrase) => passphrase,
        Err(code) => return code,
    };
    if target_backend == "keepass" {
        // Validate the target's flags, passphrase, and that the database
        // opens BEFORE the (possibly long, possibly interactive) source
        // export. It is reopened after the export so the restore plans
        // against the file's state at that point.
        if let Err(code) = open_keepass_vault(
            "sync",
            keepass_file.clone(),
            keepass_passphrase_env.clone(),
            true,
            yolo,
        ) {
            return code;
        }
    }

    // Resolve bw profiles (no auth yet) and reject same-profile syncs.
    let mut resolved = Vec::new();
    for name in [source_profile, target_profile] {
        let Some(name) = name else {
            resolved.push(None);
            continue;
        };
        match resolve_profile(&name) {
            Ok(profile) => resolved.push(Some(profile)),
            Err(error) => {
                eprintln!("sync failed: {error}");
                return 2;
            }
        }
    }
    let mut resolved = resolved.into_iter();
    let source_bw_profile = resolved.next().flatten();
    let target_bw_profile = resolved.next().flatten();
    if let (Some(source), Some(target)) = (&source_bw_profile, &target_bw_profile) {
        let same_profile = match (
            std::fs::canonicalize(&source.dir),
            std::fs::canonicalize(&target.dir),
        ) {
            (Ok(source_dir), Ok(target_dir)) => source_dir == target_dir,
            _ => source.dir == target.dir,
        };
        if same_profile {
            eprintln!("sync source and target profiles must differ");
            return 2;
        }
    }

    // Fail fast on auth before any export happens.
    let mut profile_envs = Vec::new();
    for profile in [source_bw_profile, target_bw_profile] {
        let Some(profile) = profile else {
            profile_envs.push(None);
            continue;
        };
        let session = match ensure_session(&profile) {
            Ok(session) => session,
            Err(error) => {
                eprintln!("sync failed: {error}");
                return 2;
            }
        };
        profile_envs.push(Some(BwProfileEnv {
            appdata_dir: profile.dir,
            session,
        }));
    }
    let mut profile_envs = profile_envs.into_iter();
    let source_profile_env = profile_envs.next().flatten();
    let target_profile_env = profile_envs.next().flatten();

    println!("sync source {source_backend} -> target {target_backend}");
    let progress = reporter_for_mode(progress);

    let staged = if source_backend == "keepass" {
        let keepass = match open_keepass_vault(
            "sync",
            keepass_file.clone(),
            keepass_passphrase_env.clone(),
            false,
            yolo,
        ) {
            Ok(keepass) => keepass,
            Err(code) => return code,
        };
        stage_backup(&keepass, &out, &passphrase, yolo, progress.as_ref())
    } else {
        let source_adapter = BwSourceAdapter::new(
            StdCommandRunner,
            BwSourceOptions {
                server_url,
                organization_id: None,
                strict: !permissive,
                attachment_jobs,
                attachment_mode: BwAttachmentMode::Download,
                profile: source_profile_env,
                personal_only,
            },
        );
        stage_backup(&source_adapter, &out, &passphrase, yolo, progress.as_ref())
    };
    let (staged, report) = match staged {
        Ok(staged) => staged,
        Err(code) => return code,
    };
    print_backup_report_notice(&report);

    // Read the staged archive back and verify it strictly BEFORE it replaces
    // anything at --out. Only a verified (and therefore complete) archive is
    // published; it then doubles as a backup even if the plan blocks below.
    // An incomplete or unverifiable export is discarded so it can never
    // replace the last good backup (with --overwrite) or pose as one, and the
    // verification error blocks the plan (exit code 3).
    progress.phase("verify archive");
    progress.step_start("verify archive");
    let (opened, verify_result) = match open_and_verify_archive(staged.path(), &passphrase) {
        Ok(result) => {
            progress.step_finish("verify archive");
            result
        }
        Err(error) => {
            eprintln!(
                "sync failed: the new archive could not be read back: {error}; {}",
                out_left_unchanged(&out)
            );
            return 1;
        }
    };
    let verify_error = match verify_result {
        Ok(()) => {
            debug_assert!(opened.vault.report.complete);
            if let Err(code) = publish_archive("sync", staged, overwrite) {
                return code;
            }
            println!("wrote backup archive {}", out.display());
            None
        }
        Err(error) => {
            drop(staged);
            eprintln!(
                "sync did not publish the new archive: it failed verification ({error}); {}",
                out_left_unchanged(&out)
            );
            Some(error)
        }
    };

    let flow = RestoreFlow {
        archive: RestoreArchive::Opened {
            opened,
            verify_error,
        },
        organization_id: organization_id.clone(),
        apply,
        verify_after,
        mark_restored,
        restore_map,
        update_existing,
        prune,
        prune_permanent,
        allow_mass_delete,
        format,
    };
    if target_backend == "keepass" {
        let keepass =
            match open_keepass_vault("sync", keepass_file, keepass_passphrase_env, true, yolo) {
                Ok(keepass) => keepass,
                Err(code) => return code,
            };
        run_restore_flow(&keepass, flow, progress.as_ref())
    } else {
        let target_adapter = BwSourceAdapter::new(
            StdCommandRunner,
            BwSourceOptions {
                server_url: None,
                organization_id,
                strict: true,
                attachment_jobs,
                attachment_mode: BwAttachmentMode::MetadataOnly,
                profile: target_profile_env,
                personal_only: false,
            },
        );
        run_restore_flow(&target_adapter, flow, progress.as_ref())
    }
}

fn out_left_unchanged(out: &Path) -> String {
    if out.symlink_metadata().is_ok() {
        format!("the existing --out {} was left unchanged", out.display())
    } else {
        format!("nothing was written to --out {}", out.display())
    }
}

fn run_bw_login(profile: Option<String>, server_url: Option<String>) -> i32 {
    let Some(profile_name) = profile else {
        eprintln!("bw-login requires --profile <name>");
        return 2;
    };
    let profile = match resolve_profile(&profile_name) {
        Ok(profile) => profile,
        Err(error) => {
            eprintln!("bw-login failed: {error}");
            return 2;
        }
    };
    match is_authenticated(&profile) {
        Ok(true) => {
            println!("bw profile `{}` is already logged in", profile.name);
            return 0;
        }
        Ok(false) => {}
        Err(error) => {
            eprintln!("bw-login failed: {error}");
            return 1;
        }
    }
    match interactive_login(&profile, server_url.as_deref()) {
        Ok(()) => {
            println!("bw profile `{}` logged in", profile.name);
            0
        }
        Err(error) => {
            eprintln!("bw-login failed: {error}");
            1
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
}

struct RestoreOptions {
    target: Option<String>,
    archive: Option<PathBuf>,
    passphrase_env: Option<String>,
    organization_id: Option<String>,
    dry_run: bool,
    apply: bool,
    verify_after: bool,
    mark_restored: bool,
    no_restore_map: bool,
    update_existing: bool,
    prune: bool,
    prune_permanent: bool,
    allow_mass_delete: bool,
    yolo: bool,
    bw_profile: Option<String>,
    keepass_file: Option<PathBuf>,
    keepass_passphrase_env: Option<String>,
    format: OutputFormat,
    progress: ProgressMode,
    attachment_jobs: usize,
}

struct BackupOptions {
    source: Option<String>,
    out: Option<PathBuf>,
    overwrite: bool,
    passphrase_env: Option<String>,
    server_url: Option<String>,
    organization_id: Option<String>,
    personal_only: bool,
    permissive: bool,
    yolo: bool,
    bw_profile: Option<String>,
    keepass_file: Option<PathBuf>,
    keepass_passphrase_env: Option<String>,
    progress: ProgressMode,
    attachment_jobs: usize,
}

/// Resolve a named bw profile and make sure it has a usable session,
/// unlocking interactively when needed. `None` keeps the ambient bw
/// environment exactly as before.
fn resolve_profile_env(
    bw_profile: Option<&str>,
    command_name: &str,
) -> Result<Option<BwProfileEnv>, i32> {
    let Some(name) = bw_profile else {
        return Ok(None);
    };
    let profile = match resolve_profile(name) {
        Ok(profile) => profile,
        Err(error) => {
            eprintln!("{command_name} failed: {error}");
            return Err(2);
        }
    };
    let session = match ensure_session(&profile) {
        Ok(session) => session,
        Err(error) => {
            eprintln!("{command_name} failed: {error}");
            return Err(2);
        }
    };
    Ok(Some(BwProfileEnv {
        appdata_dir: profile.dir,
        session,
    }))
}

/// Make sure the archive output path is writable BEFORE any export work
/// starts: create missing parent directories, reject a path that is an
/// existing directory, and refuse to replace an existing archive unless
/// `--overwrite` was passed (an existing archive may be the last good
/// backup; a run against a wiped or broken source must not silently replace
/// it). Failing here costs milliseconds; failing at write time costs the
/// whole export.
fn prepare_archive_out(command_name: &str, out: &Path, overwrite: bool) -> Result<(), i32> {
    if out.is_dir() {
        eprintln!(
            "{command_name} --out {} is a directory; pass a file path",
            out.display()
        );
        return Err(2);
    }
    // symlink_metadata: a dangling symlink at --out still counts as existing.
    if !overwrite && out.symlink_metadata().is_ok() {
        eprintln!(
            "{command_name} --out {} already exists; pass --overwrite to replace it, or choose a new file name",
            out.display()
        );
        return Err(2);
    }
    if let Some(parent) = out.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        if let Err(error) = std::fs::create_dir_all(parent) {
            eprintln!(
                "{command_name} failed to create output directory {}: {error}",
                parent.display()
            );
            return Err(2);
        }
        eprintln!("notice: created output directory {}", parent.display());
    }
    Ok(())
}

/// Refuse an archive `--out` that is the keepass database, one of its
/// `<kdbx>.<UTC timestamp>[-n].bak` copies, or its temp file: writing the
/// archive would destroy the database (or a backup of it) before it is even
/// opened. The archive's own temp file has a random name, so it cannot
/// collide.
fn reject_out_aliasing_keepass(
    command_name: &str,
    out: &Path,
    keepass_file: Option<&Path>,
) -> Result<(), i32> {
    let Some(keepass_file) = keepass_file else {
        return Ok(());
    };
    let keepass_paths = [
        keepass_file.to_path_buf(),
        with_suffix(keepass_file, ".tmp-yabbt"),
    ];
    let collides = keepass_paths
        .iter()
        .any(|keepass_path| same_file_path(out, keepass_path))
        || is_keepass_backup_of(out, keepass_file);
    if collides {
        eprintln!(
            "{command_name} --out {} collides with --keepass-file {} (or its timestamped .bak copies / .tmp-yabbt file); choose a different archive path",
            out.display(),
            keepass_file.display()
        );
        return Err(2);
    }
    Ok(())
}

/// Whether `candidate` names a keepass backup copy of `keepass_file`, i.e.
/// `<kdbx>.<YYYYMMDDTHHMMSSZ>.bak` or `<kdbx>.<YYYYMMDDTHHMMSSZ>-<n>.bak` in
/// the database's directory. Both paths are compared as spelled (with the
/// parent directory canonicalized, which is how the keepass adapter names its
/// copies) and fully canonicalized (catching a symlinked `--out` or kdbx).
fn is_keepass_backup_of(candidate: &Path, keepass_file: &Path) -> bool {
    let candidates = [
        lexically_normalized_path(candidate),
        normalized_path(candidate),
    ];
    let databases = [
        lexically_normalized_path(keepass_file),
        normalized_path(keepass_file),
    ];
    candidates.iter().any(|candidate| {
        databases.iter().any(|database| {
            candidate.parent() == database.parent()
                && match (candidate.file_name(), database.file_name()) {
                    (Some(name), Some(database_name)) => {
                        is_backup_name(&name.to_string_lossy(), &database_name.to_string_lossy())
                    }
                    _ => false,
                }
        })
    })
}

fn is_backup_name(name: &str, database_name: &str) -> bool {
    let Some(stamp) = name
        .strip_prefix(database_name)
        .and_then(|rest| rest.strip_prefix('.'))
        .and_then(|rest| rest.strip_suffix(".bak"))
    else {
        return false;
    };
    let (stamp, counter) = match stamp.split_once('-') {
        Some((stamp, counter)) => (stamp, Some(counter)),
        None => (stamp, None),
    };
    let bytes = stamp.as_bytes();
    let is_timestamp = bytes.len() == 16
        && bytes[..8].iter().all(u8::is_ascii_digit)
        && bytes[8] == b'T'
        && bytes[9..15].iter().all(u8::is_ascii_digit)
        && bytes[15] == b'Z';
    let counter_ok = counter
        .is_none_or(|counter| !counter.is_empty() && counter.bytes().all(|b| b.is_ascii_digit()));
    is_timestamp && counter_ok
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Whether two paths name the same file, for paths that may not exist yet:
/// existing files compare by identity (catching symlinks and hard links),
/// otherwise by canonicalized parent directory plus file name.
fn same_file_path(left: &Path, right: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(left), Ok(right)) = (std::fs::metadata(left), std::fs::metadata(right)) {
            return left.dev() == right.dev() && left.ino() == right.ino();
        }
    }
    normalized_path(left) == normalized_path(right)
}

fn normalized_path(path: &Path) -> PathBuf {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return canonical;
    }
    lexically_normalized_path(path)
}

/// Canonicalized parent directory plus the file name as spelled, without
/// resolving the file itself (a symlink keeps its own name).
fn lexically_normalized_path(path: &Path) -> PathBuf {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    match (std::fs::canonicalize(parent), path.file_name()) {
        (Ok(parent), Some(name)) => parent.join(name),
        _ => std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf()),
    }
}

fn validate_attachment_jobs(attachment_jobs: usize) -> Result<(), i32> {
    if attachment_jobs == 0 {
        eprintln!("attachment jobs must be at least 1");
        Err(2)
    } else {
        Ok(())
    }
}

struct DiffOptions {
    source: Option<String>,
    archive: Option<PathBuf>,
    passphrase_env: Option<String>,
    server_url: Option<String>,
    organization_id: Option<String>,
    permissive: bool,
    bw_profile: Option<String>,
    keepass_file: Option<PathBuf>,
    keepass_passphrase_env: Option<String>,
    attachment_jobs: usize,
}

fn run_diff(options: DiffOptions) -> i32 {
    let DiffOptions {
        source,
        archive,
        passphrase_env,
        server_url,
        organization_id,
        permissive,
        bw_profile,
        keepass_file,
        keepass_passphrase_env,
        attachment_jobs,
    } = options;

    if let Err(code) = validate_attachment_jobs(attachment_jobs) {
        return code;
    }
    let source_backend = source.as_deref().unwrap_or_default().to_string();
    if !matches!(source_backend.as_str(), "bw" | "keepass") {
        eprintln!("unsupported diff source: {source_backend}");
        return 2;
    }
    let Some(archive_path) = archive else {
        eprintln!("diff requires --archive <archive>");
        return 2;
    };
    let passphrase = match read_passphrase_env("diff", passphrase_env) {
        Ok(passphrase) => passphrase,
        Err(code) => return code,
    };
    let baseline = match open_archive(&archive_path, &passphrase) {
        Ok(opened) => opened.vault,
        Err(error) => {
            eprintln!("diff failed: {error}");
            return 1;
        }
    };

    let current = if source_backend == "keepass" {
        if let Err(code) = reject_bw_only_flags(
            "diff",
            &bw_profile,
            &server_url,
            &organization_id,
            permissive,
            false,
        ) {
            return code;
        }
        let keepass =
            match open_keepass_vault("diff", keepass_file, keepass_passphrase_env, false, false) {
                Ok(keepass) => keepass,
                Err(code) => return code,
            };
        match keepass.export_with_progress(&NoopProgress) {
            Ok(export) => export.vault,
            Err(error) => {
                eprintln!("diff failed: {error}");
                return 1;
            }
        }
    } else {
        if keepass_file.is_some() || keepass_passphrase_env.is_some() {
            eprintln!("diff --keepass-file is only valid with --source keepass");
            return 2;
        }
        let profile = match resolve_profile_env(bw_profile.as_deref(), "diff") {
            Ok(profile) => profile,
            Err(code) => return code,
        };
        let adapter = BwSourceAdapter::new(
            StdCommandRunner,
            BwSourceOptions {
                server_url,
                organization_id,
                strict: !permissive,
                attachment_jobs,
                attachment_mode: BwAttachmentMode::Download,
                profile,
                personal_only: false,
            },
        );
        match adapter.export_with_progress(&NoopProgress) {
            Ok(export) => export.vault,
            Err(error) => {
                eprintln!("diff failed: {error}");
                return 1;
            }
        }
    };

    let report = diff_vaults(&baseline, &current);
    println!(
        "diff archive {} against source {source_backend}",
        archive_path.display()
    );
    println!("archive_complete: {}", baseline.report.complete);
    println!("source_complete: {}", current.report.complete);
    print_diff_report(&report);
    0
}

/// Reject bw-specific flags for non-bw backends with a uniform message.
fn reject_bw_only_flags(
    command_name: &str,
    bw_profile: &Option<String>,
    server_url: &Option<String>,
    organization_id: &Option<String>,
    permissive: bool,
    personal_only: bool,
) -> Result<(), i32> {
    let offending = if bw_profile.is_some() {
        Some("--bw-profile")
    } else if server_url.is_some() {
        Some("--server-url")
    } else if organization_id.is_some() {
        Some("--organization-id")
    } else if permissive {
        Some("--permissive")
    } else if personal_only {
        Some("--personal-only")
    } else {
        None
    };
    if let Some(flag) = offending {
        eprintln!("{command_name} {flag} is only valid with a bw backend");
        return Err(2);
    }
    Ok(())
}

fn run_backup(options: BackupOptions) -> i32 {
    let BackupOptions {
        source,
        out,
        overwrite,
        passphrase_env,
        server_url,
        organization_id,
        personal_only,
        permissive,
        yolo,
        bw_profile,
        keepass_file,
        keepass_passphrase_env,
        progress,
        attachment_jobs,
    } = options;

    if let Err(code) = validate_attachment_jobs(attachment_jobs) {
        return code;
    }
    let source_backend = source.as_deref().unwrap_or_default().to_string();
    if !matches!(source_backend.as_str(), "bw" | "keepass") {
        eprintln!("unsupported backup source: {source_backend}");
        return 2;
    }
    let Some(out) = out else {
        eprintln!("backup requires --out <archive>");
        return 2;
    };
    if let Err(code) = prepare_archive_out("backup", &out, overwrite) {
        return code;
    }
    if source_backend == "keepass"
        && let Err(code) = reject_out_aliasing_keepass("backup", &out, keepass_file.as_deref())
    {
        return code;
    }
    let Some(passphrase_env) = passphrase_env else {
        eprintln!("backup requires --passphrase-env <ENV>");
        return 2;
    };
    let passphrase = match std::env::var(&passphrase_env) {
        Ok(value) if !value.is_empty() => value,
        Ok(_) => {
            eprintln!("passphrase env `{passphrase_env}` is empty");
            return 2;
        }
        Err(error) => {
            eprintln!(
                "failed to read passphrase env `{passphrase_env}`: {}",
                describe_var_error(&error)
            );
            return 2;
        }
    };

    if source_backend == "keepass" {
        if let Err(code) = reject_bw_only_flags(
            "backup",
            &bw_profile,
            &server_url,
            &organization_id,
            permissive,
            personal_only,
        ) {
            return code;
        }
        let keepass =
            match open_keepass_vault("backup", keepass_file, keepass_passphrase_env, false, yolo) {
                Ok(keepass) => keepass,
                Err(code) => return code,
            };
        let progress = reporter_for_mode(progress);
        return run_backup_flow(
            &keepass,
            &out,
            &passphrase,
            yolo,
            overwrite,
            progress.as_ref(),
        );
    }

    if keepass_file.is_some() || keepass_passphrase_env.is_some() {
        eprintln!("backup --keepass-file is only valid with --source keepass");
        return 2;
    }
    let profile = match resolve_profile_env(bw_profile.as_deref(), "backup") {
        Ok(profile) => profile,
        Err(code) => return code,
    };
    let progress = reporter_for_mode(progress);
    let adapter = BwSourceAdapter::new(
        StdCommandRunner,
        BwSourceOptions {
            server_url,
            organization_id,
            strict: !permissive,
            attachment_jobs,
            attachment_mode: BwAttachmentMode::Download,
            profile,
            personal_only,
        },
    );
    run_backup_flow(
        &adapter,
        &out,
        &passphrase,
        yolo,
        overwrite,
        progress.as_ref(),
    )
}

/// Export the source vault and write the encrypted archive. The source is
/// pre-built so callers can scope it to a bw profile or a keepass file.
fn run_backup_flow(
    source: &dyn BackupSource,
    out: &Path,
    passphrase: &str,
    yolo: bool,
    overwrite: bool,
    progress: &dyn ProgressReporter,
) -> i32 {
    let (staged, report) = match stage_backup(source, out, passphrase, yolo, progress) {
        Ok(staged) => staged,
        Err(code) => return code,
    };
    if let Err(code) = publish_archive("backup", staged, overwrite) {
        return code;
    }
    println!("wrote backup archive {}", out.display());
    print_backup_report_notice(&report);
    0
}

/// Publish a staged archive at its `--out`. Without `--overwrite` the
/// publish itself refuses to replace a file, so one that appeared after
/// `prepare_archive_out` checked the path (while the export ran) survives.
fn publish_archive(command_name: &str, staged: StagedArchive, overwrite: bool) -> Result<(), i32> {
    let out = staged.destination().to_path_buf();
    let mode = if overwrite {
        WriteMode::Overwrite
    } else {
        WriteMode::CreateNew
    };
    match staged.publish(mode) {
        Ok(()) => Ok(()),
        Err(ArchiveError::Io(error))
            if !overwrite && error.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            eprintln!(
                "{command_name} --out {} already exists (it appeared while the export ran) and was left unchanged; the new archive was discarded; pass --overwrite to replace it, or choose a new file name",
                out.display()
            );
            Err(2)
        }
        Err(error) => {
            eprintln!("failed to write backup archive: {error}");
            Err(1)
        }
    }
}

/// Export the source vault and stage the encrypted archive in a temp file
/// next to `out`; nothing is visible at `out` until the caller publishes it.
fn stage_backup(
    source: &dyn BackupSource,
    out: &Path,
    passphrase: &str,
    yolo: bool,
    progress: &dyn ProgressReporter,
) -> Result<(StagedArchive, CompletenessReport), i32> {
    // The archive writer enforces this too, but checking before the export
    // fails in milliseconds instead of after the whole vault is downloaded.
    if yolo {
        if let Err(error) = validate_passphrase_strength(passphrase) {
            eprintln!("warning: --yolo set; writing archive with a weak passphrase ({error})");
        }
    } else if let Err(error) = validate_passphrase_strength(passphrase) {
        // A refused passphrase is a usage error, like a refused keepass
        // passphrase for a new database: nothing was exported or written.
        eprintln!("failed to write backup archive: {error}");
        return Err(2);
    }
    progress.phase("backup source");
    let export = match source.export_with_progress(progress) {
        Ok(export) => export,
        Err(error) => {
            eprintln!("backup failed: {error}");
            return Err(1);
        }
    };
    let report = export.vault.report.clone();
    let mut archive = ArchiveBuilder::new(export.vault);
    for attachment in export.attachments {
        archive = archive.attachment(attachment);
    }
    if yolo {
        archive = archive.allow_weak_passphrase();
    }
    match archive.stage_with_progress(out, passphrase, progress) {
        Ok(staged) => Ok((staged, report)),
        Err(error) => {
            eprintln!("failed to write backup archive: {error}");
            Err(1)
        }
    }
}

/// Tell the user on stderr whether the archive just written is complete and
/// which warnings its report carries: codes and counts only. Only the
/// organization-scope warnings, which are count-only by construction, are
/// printed in full. A complete report without warnings prints nothing.
fn print_backup_report_notice(report: &CompletenessReport) {
    if report.complete && report.warnings.is_empty() {
        return;
    }
    let mut counts = BTreeMap::<&str, usize>::new();
    for warning in &report.warnings {
        *counts.entry(warning.code.as_str()).or_default() += 1;
    }
    let summary = if counts.is_empty() {
        "none".to_string()
    } else {
        counts
            .iter()
            .map(|(code, count)| format!("{code} x{count}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    eprintln!(
        "notice: archive complete: {}; warnings: {summary}",
        report.complete
    );
    for warning in &report.warnings {
        if matches!(
            warning.code.as_str(),
            ORG_ITEMS_NOT_EXPORTED | ORG_ITEMS_EXCLUDED_BY_SCOPE
        ) {
            eprintln!("notice: {}: {}", warning.code, warning.message);
        }
    }
}

fn run_restore(options: RestoreOptions) -> i32 {
    let RestoreOptions {
        target,
        archive,
        passphrase_env,
        organization_id,
        dry_run,
        apply,
        verify_after,
        mark_restored,
        no_restore_map,
        update_existing,
        prune,
        prune_permanent,
        allow_mass_delete,
        yolo,
        bw_profile,
        keepass_file,
        keepass_passphrase_env,
        format,
        progress,
        attachment_jobs,
    } = options;

    if let Err(code) = validate_attachment_jobs(attachment_jobs) {
        return code;
    }
    let target_backend = target.as_deref().unwrap_or_default().to_string();
    if !matches!(target_backend.as_str(), "bw" | "keepass") {
        eprintln!("unsupported restore target: {target_backend}");
        return 2;
    }
    if dry_run == apply {
        eprintln!("restore requires either --dry-run or --apply");
        return 2;
    }
    if verify_after && !apply {
        eprintln!("restore --verify-after requires --apply");
        return 2;
    }
    if mark_restored && !apply {
        eprintln!("restore --mark-restored requires --apply");
        return 2;
    }
    if no_restore_map && !apply {
        eprintln!("restore --no-restore-map requires --apply");
        return 2;
    }
    if update_existing && !apply {
        eprintln!("restore --update-existing requires --apply");
        return 2;
    }
    if prune_permanent && (!apply || !prune) {
        eprintln!("restore --prune-permanent requires --apply --prune");
        return 2;
    }
    if allow_mass_delete && !prune {
        eprintln!("restore --allow-mass-delete requires --prune");
        return 2;
    }
    let restore_map = apply && !no_restore_map;
    let Some(archive_path) = archive else {
        eprintln!("restore requires <archive>");
        return 2;
    };
    let passphrase = match read_passphrase_env("restore", passphrase_env) {
        Ok(passphrase) => passphrase,
        Err(code) => return code,
    };
    let flow = RestoreFlow {
        archive: RestoreArchive::File {
            path: archive_path,
            passphrase,
        },
        organization_id: organization_id.clone(),
        apply,
        verify_after,
        mark_restored,
        restore_map,
        update_existing,
        prune,
        prune_permanent,
        allow_mass_delete,
        format,
    };

    if target_backend == "keepass" {
        if bw_profile.is_some() {
            eprintln!("restore --bw-profile is only valid with --target bw");
            return 2;
        }
        if organization_id.is_some() {
            eprintln!("restore --organization-id is only valid with --target bw");
            return 2;
        }
        let keepass =
            match open_keepass_vault("restore", keepass_file, keepass_passphrase_env, true, yolo) {
                Ok(keepass) => keepass,
                Err(code) => return code,
            };
        let progress = reporter_for_mode(progress);
        return run_restore_flow(&keepass, flow, progress.as_ref());
    }

    if keepass_file.is_some() || keepass_passphrase_env.is_some() {
        eprintln!("restore --keepass-file is only valid with --target keepass");
        return 2;
    }
    let profile = match resolve_profile_env(bw_profile.as_deref(), "restore") {
        Ok(profile) => profile,
        Err(code) => return code,
    };
    let progress = reporter_for_mode(progress);
    let adapter = BwSourceAdapter::new(
        StdCommandRunner,
        BwSourceOptions {
            server_url: None,
            organization_id,
            strict: true,
            attachment_jobs,
            attachment_mode: BwAttachmentMode::MetadataOnly,
            profile,
            personal_only: false,
        },
    );
    run_restore_flow(&adapter, flow, progress.as_ref())
}

/// Open (or, for targets, lazily create) the keepass database named by the
/// CLI flags, reading its passphrase from the given environment variable.
fn open_keepass_vault(
    command_name: &str,
    keepass_file: Option<PathBuf>,
    keepass_passphrase_env: Option<String>,
    create_if_missing: bool,
    yolo: bool,
) -> Result<KeepassVault, i32> {
    let Some(path) = keepass_file else {
        eprintln!("{command_name} requires --keepass-file <path>");
        return Err(2);
    };
    let passphrase = read_passphrase_env_flag(
        command_name,
        "--keepass-passphrase-env",
        keepass_passphrase_env,
    )?;
    // Enforce passphrase strength when this run would create a brand-new
    // encrypted database; an existing database keeps whatever passphrase it
    // already has. `--yolo` is the explicit override, matching backup.
    if create_if_missing && !path.exists() {
        if yolo {
            eprintln!(
                "warning: --yolo set; skipping passphrase strength check for new keepass database"
            );
        } else if let Err(error) = validate_passphrase_strength(&passphrase) {
            eprintln!("{command_name} refuses to create keepass database: {error}");
            eprintln!("choose a stronger passphrase or pass --yolo to override");
            return Err(2);
        }
    }
    KeepassVault::open(KeepassVaultOptions {
        path,
        passphrase,
        create_if_missing,
    })
    .map_err(|error| {
        eprintln!("{command_name} failed: {error}");
        1
    })
}

/// Everything restore does once flags are validated and the target adapter
/// is built: open the archive, scan the target read-only, verify the
/// archive, plan, then print the dry-run plan or apply it.
struct RestoreFlow {
    archive: RestoreArchive,
    organization_id: Option<String>,
    apply: bool,
    verify_after: bool,
    mark_restored: bool,
    restore_map: bool,
    update_existing: bool,
    prune: bool,
    prune_permanent: bool,
    allow_mass_delete: bool,
    format: OutputFormat,
}

/// The archive a restore flow plans from.
enum RestoreArchive {
    /// Open and verify this archive file (`restore`).
    File { path: PathBuf, passphrase: String },
    /// Already decoded and verified by the caller (`sync`'s freshly written
    /// archive), so it is not decrypted a second time.
    Opened {
        opened: OpenedArchive,
        verify_error: Option<ArchiveError>,
    },
}

fn run_restore_flow(
    target: &dyn RestoreTarget,
    flow: RestoreFlow,
    progress: &dyn ProgressReporter,
) -> i32 {
    let RestoreFlow {
        archive,
        organization_id,
        apply,
        verify_after,
        mark_restored,
        restore_map,
        update_existing,
        prune,
        prune_permanent,
        allow_mass_delete,
        format,
    } = flow;

    let (opened, verify_error) = match archive {
        RestoreArchive::File { path, passphrase } => {
            progress.phase("restore archive");
            progress.step_start("open archive");
            // Open and verify from a single decode so the archive is never
            // read twice (no TOCTOU window where the file could be swapped
            // between open and verify).
            match open_and_verify_archive(&path, &passphrase) {
                Ok((opened, verify_result)) => {
                    progress.step_finish("open archive");
                    (opened, verify_result.err())
                }
                Err(error) => {
                    eprintln!("restore failed: {error}");
                    return 1;
                }
            }
        }
        RestoreArchive::Opened {
            opened,
            verify_error,
        } => (opened, verify_error),
    };

    progress.phase("scan target vault");
    let target_vault = match target.scan(progress) {
        Ok(vault) => vault,
        Err(error) => {
            eprintln!("restore failed: {error}");
            return 1;
        }
    };

    progress.phase("plan restore");
    // A failed archive verification is a plan blocker in both modes, so a
    // dry-run and an --apply of the same archive exit the same way
    // (EXIT_PLAN_BLOCKED), with the reason listed among the blockers.
    let mut plan = plan_restore_with_options_and_progress(
        &opened.vault,
        Some(&target_vault),
        target.backend_name(),
        RestorePlanOptions {
            target_organization_id: organization_id.as_deref(),
            prune,
            prune_permanent,
            allow_mass_delete,
        },
        progress,
    );
    if let Some(error) = verify_error {
        let blocker = error.to_string();
        if !plan.blockers.iter().any(|existing| existing == &blocker) {
            plan.blockers.push(blocker);
        }
    }

    if apply {
        if plan.status() == RestorePlanStatus::Blocked {
            eprintln!("restore failed: plan has blockers");
            print_restore_blocker_details(&plan);
            return EXIT_PLAN_BLOCKED;
        }
        let outcome = match apply_restore_plan(
            target,
            &opened,
            &plan,
            &target_vault,
            organization_id.as_deref(),
            ApplyOptions {
                mark_restored,
                restore_map,
                update_existing,
                verify_after,
            },
            progress,
        ) {
            Ok(outcome) => outcome,
            Err(RestoreError::Apply { summary, error }) => {
                if summary.has_mutations() {
                    // Tell the user exactly what this run already changed.
                    print_restore_apply_summary(
                        &summary,
                        &plan,
                        mark_restored,
                        update_existing,
                        true,
                    );
                }
                eprintln!("restore failed: {error}");
                if summary.has_mutations() {
                    eprintln!(
                        "the target was partially modified; see the counts and ids printed above"
                    );
                    if restore_map && summary.items_created > 0 && !summary.restore_map_updated {
                        eprintln!(
                            "warning: the restore map was not updated, so a re-run may duplicate the created items"
                        );
                    }
                    if summary.attachment_upload_incomplete {
                        eprintln!(
                            "attachment uploads did not complete; re-run with --update-existing to upload the missing attachments"
                        );
                    }
                }
                return 1;
            }
            Err(RestoreError::Verify { summary, error }) => {
                print_restore_apply_summary(&summary, &plan, mark_restored, update_existing, false);
                eprintln!("{error}");
                return 1;
            }
        };
        print_restore_apply_summary(
            &outcome.summary,
            &plan,
            mark_restored,
            update_existing,
            false,
        );
        if let Some(verification) = outcome.verification {
            println!("post_apply_verified: true");
            println!("created_items_verified: {}", verification.created_items);
            println!("updated_items_verified: {}", verification.updated_items);
            println!("attachments_verified: {}", verification.attachments);
            println!("deleted_items_verified: {}", verification.deleted_items);
            println!(
                "deleted_attachments_verified: {}",
                verification.deleted_attachments
            );
            println!("deleted_folders_verified: {}", verification.deleted_folders);
        }
    } else {
        match format {
            OutputFormat::Human => print_restore_plan(&plan),
            OutputFormat::Json => match serde_json::to_string_pretty(&plan) {
                Ok(json) => println!("{json}"),
                Err(error) => {
                    eprintln!("restore failed: {error}");
                    return 1;
                }
            },
        }
        if plan.status() == RestorePlanStatus::Blocked {
            return EXIT_PLAN_BLOCKED;
        }
    }
    0
}

fn run_archive_summary(
    command_name: &str,
    archive: Option<PathBuf>,
    passphrase_env: Option<String>,
) -> i32 {
    let Some(archive) = archive else {
        eprintln!("{command_name} requires <archive>");
        return 2;
    };
    let passphrase = match read_passphrase_env(command_name, passphrase_env) {
        Ok(passphrase) => passphrase,
        Err(code) => return code,
    };

    let summary = match summarize_archive(&archive, &passphrase) {
        Ok(summary) => summary,
        Err(error) => {
            eprintln!("{command_name} failed: {error}");
            return 1;
        }
    };

    if command_name == "verify" {
        if let Err(error) = verify_archive(&archive, &passphrase) {
            eprintln!("verify failed: {error}");
            return 1;
        }
        println!("archive verified {}", archive.display());
    } else {
        println!("archive {}", archive.display());
    }
    print_safe_summary(&summary);
    0
}

fn print_safe_summary(summary: &ArchiveSummary) {
    println!("format: {}", summary.format_version);
    println!("source: {}", summary.source_backend);
    if let Some(source_server) = &summary.source_server {
        println!("server: {source_server}");
    }
    println!("created: {}", summary.created_at);
    println!("folders: {}", summary.folder_count);
    println!("items: {}", summary.item_count);
    println!("attachments: {}", summary.attachment_count);
    println!("warnings: {}", summary.warning_count);
    println!("complete: {}", summary.complete);
}

fn print_diff_report(report: &DiffReport) {
    println!("added: {}", report.added.len());
    println!("removed: {}", report.removed.len());
    println!("changed: {}", report.changed.len());
    println!("unchanged: {}", report.unchanged_count);
    print_item_ids("added item ids", &report.added);
    print_item_ids("removed item ids", &report.removed);
    print_item_ids("changed item ids", &report.changed);
}

fn print_restore_plan(plan: &RestorePlan) {
    println!("restore plan");
    println!("target: {}", plan.target_backend);
    println!("dry_run: {}", plan.dry_run);
    println!(
        "status: {}",
        match plan.status() {
            RestorePlanStatus::Ready => "ready",
            RestorePlanStatus::Blocked => "blocked",
        }
    );
    println!("archive_items: {}", plan.archive_items);
    match plan.target_items_scanned {
        Some(count) => println!("target_items_scanned: {count}"),
        None => println!("target_items_scanned: not_scanned"),
    }
    println!("folders_to_create: {}", plan.folders_to_create);
    println!("folders_to_delete: {}", plan.folders_to_delete);
    println!("items_to_create: {}", plan.items_to_create);
    println!("items_to_update: {}", plan.items_to_update);
    println!("items_unchanged: {}", plan.items_unchanged);
    println!("items_to_skip: {}", plan.items_to_skip);
    println!("items_to_delete: {}", plan.items_to_delete);
    println!("attachments_to_upload: {}", plan.attachments_to_upload);
    println!("attachments_to_delete: {}", plan.attachments_to_delete);
    println!("prune_permanent: {}", plan.prune_permanent);
    println!("warnings: {}", plan.warning_count);
    print_item_ids("create folder ids", &plan.create_folder_ids);
    print_item_ids("delete folder ids", &plan.delete_folder_ids);
    print_item_ids("create item ids", &plan.create_item_ids);
    print_item_ids("update item ids", &plan.update_item_ids);
    print_item_ids("unchanged item ids", &plan.unchanged_item_ids);
    print_item_ids("skip item ids", &plan.skip_item_ids);
    print_item_ids("delete item ids", &plan.delete_item_ids);
    print_item_ids("delete attachment ids", &plan.delete_attachment_ids);
    print_item_ids(
        "unsupported organization item ids",
        &plan.unsupported_organization_item_ids,
    );
    print_item_ids(
        "unsupported collection item ids",
        &plan.unsupported_collection_item_ids,
    );
    print_item_ids(
        "stale restore map item ids",
        &plan.restore_map_stale_item_ids,
    );
    print_item_ids("ambiguous folder ids", &plan.restore_folder_ambiguous_ids);
    print_item_ids(
        "ambiguous fingerprint item ids",
        &plan.restore_fingerprint_ambiguous_item_ids,
    );
    if !plan.blockers.is_empty() {
        println!("blockers:");
        for blocker in &plan.blockers {
            println!("  {blocker}");
        }
    }
}

fn print_restore_blocker_details(plan: &RestorePlan) {
    if !plan.blockers.is_empty() {
        eprintln!("blockers:");
        for blocker in &plan.blockers {
            eprintln!("  {blocker}");
        }
    }
    eprint_item_ids(
        "unsupported organization item ids",
        &plan.unsupported_organization_item_ids,
    );
    eprint_item_ids("invalid scope item ids", &plan.invalid_scope_item_ids);
    eprint_item_ids(
        "unsupported collection item ids",
        &plan.unsupported_collection_item_ids,
    );
    eprint_item_ids("ambiguous folder ids", &plan.restore_folder_ambiguous_ids);
    eprint_item_ids(
        "ambiguous fingerprint item ids",
        &plan.restore_fingerprint_ambiguous_item_ids,
    );
    eprint_item_ids("delete folder ids", &plan.delete_folder_ids);
    eprint_item_ids("delete item ids", &plan.delete_item_ids);
    eprint_item_ids("delete attachment ids", &plan.delete_attachment_ids);
}

fn print_restore_apply_summary(
    summary: &ApplySummary,
    plan: &RestorePlan,
    mark_restored: bool,
    update_existing: bool,
    partial: bool,
) {
    println!(
        "{}",
        if partial {
            "restore partially applied"
        } else {
            "restore applied"
        }
    );
    println!("target: {}", plan.target_backend);
    println!(
        "mode: {}",
        if update_existing {
            "create-and-update"
        } else {
            "create-only"
        }
    );
    println!("folders_created: {}", summary.folders_created);
    println!("items_created: {}", summary.items_created);
    println!("items_updated: {}", summary.items_updated);
    println!("attachments_uploaded: {}", summary.attachments_uploaded);
    println!("folders_deleted: {}", summary.folders_deleted);
    println!("items_deleted: {}", summary.items_deleted);
    println!("attachments_deleted: {}", summary.attachments_deleted);
    println!(
        "attachments_delete_skipped: {}",
        summary.attachment_deletes_kept_by_history.len()
    );
    println!("prune_permanent: {}", plan.prune_permanent);
    println!(
        "items_update_skipped: {}",
        if update_existing {
            plan.items_to_update.saturating_sub(summary.items_updated)
        } else {
            plan.items_to_update
        }
    );
    println!("items_unchanged: {}", plan.items_unchanged);
    println!(
        "items_delete_skipped: {}",
        plan.items_to_skip.saturating_sub(summary.items_deleted)
    );
    println!("marked_restored: {mark_restored}");
    println!("restore_map_updated: {}", summary.restore_map_updated);
    if partial {
        println!(
            "attachment_upload_incomplete: {}",
            summary.attachment_upload_incomplete
        );
        print_item_ids("created folder ids", &summary.created_folder_ids);
        print_item_ids("created item ids", &summary.created_item_ids);
        print_item_ids("updated item ids", &summary.updated_item_ids);
    }
    print_item_ids("deleted folder ids", &summary.deleted_folder_ids);
    print_item_ids("deleted item ids", &summary.deleted_item_ids);
    print_item_ids("deleted attachment ids", &summary.deleted_attachment_ids);
    print_item_ids("replaced attachment ids", &summary.replaced_attachment_ids);
    warn_attachment_deletes_kept_by_history(&summary.attachment_deletes_kept_by_history);
}

/// One stderr warning per target item whose planned attachment deletes were
/// skipped because entry history still references the files (ids and
/// counts only, never attachment names).
fn warn_attachment_deletes_kept_by_history(item_ids: &[String]) {
    let mut counts = std::collections::BTreeMap::<&str, usize>::new();
    for item_id in item_ids {
        *counts.entry(item_id.as_str()).or_default() += 1;
    }
    for (item_id, count) in counts {
        eprintln!(
            "warning: kept {count} attachment(s) of target item `{item_id}` that prune would \
             delete: the same file is still referenced from that entry's history, which the \
             keepass library cannot preserve without it; delete the entry's history in \
             KeePassXC to let a later --prune remove it"
        );
    }
}

fn print_item_ids(label: &str, ids: &[String]) {
    if ids.is_empty() {
        return;
    }

    println!("{label}:");
    for id in ids {
        println!("  {id}");
    }
}

fn eprint_item_ids(label: &str, ids: &[String]) {
    if ids.is_empty() {
        return;
    }

    eprintln!("{label}:");
    for id in ids {
        eprintln!("  {id}");
    }
}

fn read_passphrase_env(command_name: &str, passphrase_env: Option<String>) -> Result<String, i32> {
    read_passphrase_env_flag(command_name, "--passphrase-env", passphrase_env)
}

fn read_passphrase_env_flag(
    command_name: &str,
    flag: &str,
    passphrase_env: Option<String>,
) -> Result<String, i32> {
    let Some(passphrase_env) = passphrase_env else {
        eprintln!("{command_name} requires {flag} <ENV>");
        return Err(2);
    };
    match std::env::var(&passphrase_env) {
        Ok(value) if !value.is_empty() => Ok(value),
        Ok(_) => {
            eprintln!("passphrase env `{passphrase_env}` is empty");
            Err(2)
        }
        Err(error) => {
            eprintln!(
                "failed to read passphrase env `{passphrase_env}`: {}",
                describe_var_error(&error)
            );
            Err(2)
        }
    }
}

/// Describe an env-var read failure without echoing the value. `VarError`'s
/// own `Display` embeds the raw bytes for the not-unicode case, which would
/// print a passphrase set to a non-UTF-8 value.
fn describe_var_error(error: &std::env::VarError) -> &'static str {
    match error {
        std::env::VarError::NotPresent => "it is not set",
        std::env::VarError::NotUnicode(_) => "it is not valid unicode",
    }
}

impl Command {
    pub fn name(&self) -> &'static str {
        match self {
            Command::Doctor => "doctor",
            Command::Backup { .. } => "backup",
            Command::Inspect { .. } => "inspect",
            Command::Verify { .. } => "verify",
            Command::Diff { .. } => "diff",
            Command::Restore { .. } => "restore",
            Command::BwLogin { .. } => "bw-login",
            Command::Sync { .. } => "sync",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepass_backup_names_match_only_the_timestamped_pattern() {
        for name in [
            "vault.kdbx.20261011T120000Z.bak",
            "vault.kdbx.20261011T120000Z-2.bak",
            "vault.kdbx.20261011T120000Z-117.bak",
        ] {
            assert!(is_backup_name(name, "vault.kdbx"), "{name}");
        }
        for name in [
            "vault.kdbx.bak",
            "vault.kdbx..bak",
            "vault.kdbx.20261011T120000Z.bak.yabbt",
            "vault.kdbx.20261011T120000Z-.bak",
            "vault.kdbx.20261011T120000Z-x.bak",
            "vault.kdbx.2026101T120000Z.bak",
            "vault.kdbx.archive.bak",
            "other.kdbx.20261011T120000Z.bak",
            "vault.kdbx20261011T120000Z.bak",
        ] {
            assert!(!is_backup_name(name, "vault.kdbx"), "{name}");
        }
    }
}

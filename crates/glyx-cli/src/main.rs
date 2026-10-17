mod auth;
mod daemon;
mod exports;
mod extension;
mod gitcred;
mod items;
mod select;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "glyx", version, about = "Local-first password manager")]
struct Cli {
    #[arg(long, global = true, help = "Output machine-readable JSON")]
    json: bool,
    #[arg(long, global = true, help = "Vault directory (or GLYX_VAULT)")]
    vault: Option<PathBuf>,
    #[arg(long, global = true, help = "Keyfile path")]
    keyfile: Option<PathBuf>,
    #[arg(long, global = true, help = "Read password from this env var")]
    password_env: Option<String>,
    #[arg(long, global = true, help = "Ignore sessions, always prompt")]
    no_session: bool,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    #[command(about = "Vault lifecycle")]
    Vault {
        #[command(subcommand)]
        cmd: VaultCmd,
    },
    #[command(about = "Unlock and remember for a while")]
    Unlock {
        #[arg(long, help = "Session length in minutes")]
        ttl: Option<u64>,
        #[arg(long, help = "Also set a short convenience passphrase")]
        with_pin: bool,
    },
    #[command(about = "Forget sessions")]
    Lock,
    #[command(about = "List items")]
    Ls {
        #[arg(long, help = "Filter by folder")]
        folder: Option<String>,
        #[arg(long, help = "Filter by tag")]
        tag: Option<String>,
        #[arg(long, help = "Filter by type")]
        item_type: Option<String>,
        #[arg(long, help = "Include tombstones")]
        all: bool,
    },
    #[command(about = "Show one item")]
    Show {
        #[arg(help = "Id, id prefix, or exact name")]
        query: String,
        #[arg(long, help = "Reveal secret fields")]
        reveal: bool,
        #[arg(long, help = "Render note refs to values")]
        render: bool,
    },
    #[command(about = "Add an item")]
    Add {
        #[arg(help = "Item type: login, totp, identity, card, note, file, ssh_key, ...")]
        item_type: String,
        #[arg(long, help = "Display name")]
        name: String,
        #[arg(long, help = "Folder path")]
        folder: Option<String>,
        #[arg(long, help = "Tag (repeatable)")]
        tag: Vec<String>,
        #[arg(long, help = "Field as key=value (repeatable)")]
        field: Vec<String>,
        #[arg(long, help = "Generate into field, optionally name:length")]
        generate: Vec<String>,
        #[arg(long, help = "Read the note body from a file")]
        body_file: Option<PathBuf>,
        #[arg(long, help = "Prompt for missing fields")]
        interactive: bool,
    },
    #[command(about = "Edit an item")]
    Edit {
        #[arg(help = "Id, id prefix, or exact name")]
        query: String,
        #[arg(long, help = "New display name")]
        rename: Option<String>,
        #[arg(long, help = "Set field as key=value (repeatable)")]
        field: Vec<String>,
        #[arg(long, help = "Delete field (repeatable)")]
        delete_field: Vec<String>,
        #[arg(long, help = "Read the note body from a file")]
        body_file: Option<PathBuf>,
        #[arg(long, help = "Prompt for fields")]
        interactive: bool,
    },
    #[command(about = "Delete an item (tombstone, sync-safe)")]
    Rm {
        #[arg(help = "Id, id prefix, or exact name")]
        query: String,
    },
    #[command(about = "Print a TOTP code")]
    Totp {
        #[arg(help = "Id, id prefix, or exact name")]
        query: String,
    },
    #[command(about = "Copy a field to the clipboard")]
    Fill {
        #[arg(help = "Id, id prefix, or exact name")]
        query: String,
        #[arg(long, default_value = "password", help = "Field to copy")]
        field: String,
        #[arg(long, default_value = "15", help = "Clear after N seconds, 0 keeps")]
        timeout: u64,
        #[arg(long, help = "Resolve only, touch nothing")]
        dry_run: bool,
    },
    #[command(about = "SSH key operations")]
    Ssh {
        #[command(subcommand)]
        cmd: SshCmd,
    },
    #[command(about = "File and secret exports")]
    Export {
        #[command(subcommand)]
        cmd: ExportCmd,
    },
    #[command(about = "Secret injection into files")]
    Inject {
        #[command(subcommand)]
        cmd: InjectCmd,
    },
    #[command(about = "Vault sync state")]
    SyncStatus,
    #[command(about = "Merge sync-conflict copies, optionally with another vault")]
    Sync {
        #[arg(help = "Other vault directory for pairwise merge")]
        path: Option<PathBuf>,
        #[arg(long, help = "Other vault keyfile")]
        other_keyfile: Option<PathBuf>,
        #[arg(long, help = "Other vault password env var")]
        other_password_env: Option<String>,
    },
    #[command(about = "List merge conflicts")]
    Conflicts {
        #[command(subcommand)]
        cmd: Option<ConflictsCmd>,
    },
    #[command(about = "Purge old tombstones")]
    Gc {
        #[arg(long, default_value = "30d", help = "Purge tombstones older than this")]
        older_than: String,
        #[arg(long, help = "List only, change nothing")]
        dry_run: bool,
    },
    #[command(about = "Check vault health")]
    Doctor {
        #[arg(long, help = "Rebuild the SQLite index from envelope headers")]
        rebuild_index: bool,
        #[arg(long, help = "Also unlock and decrypt every item and blob")]
        with_unlock: bool,
    },
    #[command(about = "Manage the localhost daemon")]
    Daemon {
        #[command(subcommand)]
        cmd: DaemonCmd,
    },
    #[command(about = "Browser extension native host")]
    Extension {
        #[command(subcommand)]
        cmd: ExtensionCmd,
    },
    #[command(about = "Git credential helper setup")]
    Git {
        #[command(subcommand)]
        cmd: GitCmd,
    },
}

#[derive(Debug, Subcommand)]
enum VaultCmd {
    #[command(about = "Choose the active vault (interactive)")]
    Select,
    #[command(about = "Create a fresh vault directory")]
    Init {
        #[arg(help = "New vault directory (must not exist)")]
        path: PathBuf,
        #[arg(long, value_enum, default_value = "balanced", help = "Cost preset")]
        preset: Preset,
        #[arg(long, value_enum, default_value = "xchacha", help = "Payload cipher")]
        cipher: CipherOpt,
        #[arg(
            long,
            help = "Keyfile path, generated when missing; omit for password-only"
        )]
        keyfile: Option<PathBuf>,
    },
    #[command(about = "Rotate password, keyfile, KDF params, or cipher")]
    Rekey {
        #[arg(long, help = "New keyfile path; generated when missing")]
        new_keyfile: Option<PathBuf>,
        #[arg(long, help = "Drop the keyfile, keep password only")]
        no_keyfile: bool,
        #[arg(long, help = "Read new password from this env var")]
        new_password_env: Option<String>,
        #[arg(long, value_enum, help = "New payload cipher")]
        cipher: Option<CipherOpt>,
        #[arg(long, value_enum, help = "New KDF cost preset")]
        preset: Option<Preset>,
        #[arg(long, help = "Keep old keyslots")]
        keep_old_slots: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ConflictsCmd {
    #[command(about = "Show one conflict")]
    Show {
        #[arg(help = "Id, id prefix, or exact name")]
        query: String,
        #[arg(long, help = "Reveal secret values")]
        reveal: bool,
    },
    #[command(about = "Resolve one conflict")]
    Resolve {
        #[arg(help = "Id, id prefix, or exact name")]
        query: String,
        #[arg(long, help = "Keep the local version")]
        mine: bool,
        #[arg(long, help = "Keep the remote version")]
        theirs: bool,
        #[arg(long, help = "Set field as key=value (repeatable)")]
        field: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, Subcommand)]
enum DaemonCmd {
    #[command(about = "Start the localhost daemon")]
    Start {
        #[arg(long, help = "Idle auto-lock minutes")]
        idle_lock_min: Option<u64>,
    },
    #[command(about = "Stop the localhost daemon")]
    Stop,
    #[command(about = "Daemon status")]
    Status,
}

#[derive(Debug, Subcommand)]
enum ExtensionCmd {
    #[command(about = "Install native host manifests")]
    Install {
        #[arg(long, help = "Install Chrome manifest")]
        chrome: bool,
        #[arg(long, help = "Install Firefox manifest")]
        firefox: bool,
    },
    #[command(about = "Allow a Chrome extension id")]
    Allow {
        #[arg(help = "Extension id from chrome://extensions")]
        id: String,
    },
    #[command(about = "Extension wiring status")]
    Status,
}

#[derive(Debug, Clone, Copy, Subcommand)]
enum GitCmd {
    #[command(about = "Configure git to use glyx")]
    Setup,
    #[command(about = "Git helper diagnostics")]
    Status,
}

#[derive(Debug, Subcommand)]
enum SshCmd {
    #[command(about = "Generate a key pair into a new item")]
    Gen {
        #[arg(long, help = "Display name")]
        name: String,
        #[arg(long, value_enum, default_value = "ed25519", help = "Key kind")]
        kind: SshKind,
        #[arg(long, help = "Public key comment")]
        comment: Option<String>,
        #[arg(long, help = "Folder path")]
        folder: Option<String>,
    },
    #[command(about = "Print SSH_AUTH_SOCK for the daemon agent")]
    AgentEnv,
    #[command(about = "Export a key to a file")]
    Export {
        #[arg(help = "Id, id prefix, or exact name")]
        query: String,
        #[arg(long, help = "Target path")]
        to: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum ExportCmd {
    #[command(about = "Register a file export")]
    Add {
        #[arg(help = "Target path")]
        target: PathBuf,
        #[arg(long, help = "Source item")]
        item: Option<String>,
        #[arg(long, help = "Source field")]
        field: Option<String>,
        #[arg(long, help = "Source blob address")]
        blob: Option<String>,
        #[arg(long, help = "Source ssh key item")]
        ssh: Option<String>,
        #[arg(long, help = "Keep the file on lock")]
        keep: bool,
        #[arg(long, help = "File mode bits, e.g. 384 for 0600")]
        perm: Option<u32>,
    },
    #[command(about = "List registered exports and injections")]
    Ls,
    #[command(about = "Wipe a tracked file and forget it")]
    Recall {
        #[arg(help = "Target path")]
        target: PathBuf,
    },
    #[command(about = "Materialize all registered exports")]
    Enforce {
        #[arg(long, help = "Overwrite drifted files")]
        force: bool,
    },
    #[command(about = "Show tamper findings")]
    Tamper,
    #[command(about = "Three-way merge a drifted file")]
    Merge {
        #[arg(help = "Target path")]
        target: PathBuf,
        #[arg(long, help = "Take on-disk side for all conflicts")]
        theirs: bool,
        #[arg(long, help = "Take vault side for all conflicts")]
        ours: bool,
        #[arg(long, help = "Pick per hunk as N:theirs|ours|custom (repeatable)")]
        pick: Vec<String>,
        #[arg(long, help = "Walk conflicts interactively")]
        interactive: bool,
    },
}

#[derive(Debug, Subcommand)]
enum InjectCmd {
    #[command(about = "Track a file or a folder for secret injection")]
    Add {
        #[arg(help = "File, or folder of matching files")]
        file: PathBuf,
        #[arg(long, default_value = "encrypted-pointer", help = "Locked form")]
        form: String,
        #[arg(long, help = "Glob for folders, for example '*.md'")]
        glob: Option<String>,
    },
    #[command(about = "Rescan tracked folders for matching files")]
    Scan,
    #[command(about = "Stop tracking a file or folder")]
    Rm {
        #[arg(help = "File or folder")]
        target: PathBuf,
    },
    #[command(about = "List tracked injections")]
    Ls,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Preset {
    #[value(help = "Balanced desktop defaults")]
    Balanced,
    #[value(help = "Hardened defaults")]
    Hardened,
    #[value(help = "Low-RAM mobile defaults")]
    Mobile,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CipherOpt {
    #[value(help = "XChaCha20-Poly1305")]
    Xchacha,
    #[value(help = "AES-256-GCM")]
    Aesgcm,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SshKind {
    #[value(help = "Ed25519")]
    Ed25519,
    #[value(help = "RSA-4096")]
    Rsa4096,
}

struct Ctx {
    json: bool,
    vault: Option<PathBuf>,
    keyfile: Option<PathBuf>,
    password_env: Option<String>,
    no_session: bool,
}

impl Ctx {
    fn unlocked(&self) -> Result<glyx_store::UnlockedVault> {
        auth::resolve_unlocked(&auth::AuthFlags {
            vault: auth::resolve_vault_path(self.vault.as_ref())?,
            keyfile: self.keyfile.clone(),
            password_env: self.password_env.clone(),
            no_session: self.no_session,
        })
    }
    fn vault_path(&self) -> Result<PathBuf> {
        auth::resolve_vault_path(self.vault.as_ref())
    }
}

fn preset_params(preset: Preset) -> glyx_core::KdfParams {
    match preset {
        Preset::Balanced => glyx_core::KdfParams::balanced(),
        Preset::Hardened => glyx_core::KdfParams::hardened(),
        Preset::Mobile => glyx_core::KdfParams::mobile(),
    }
}

fn cipher_of(cipher: CipherOpt) -> glyx_core::Cipher {
    match cipher {
        CipherOpt::Xchacha => glyx_core::Cipher::Xchacha20poly1305,
        CipherOpt::Aesgcm => glyx_core::Cipher::Aes256gcm,
    }
}

fn main() -> Result<()> {
    if let Some(name) = std::env::args().next() {
        if name.ends_with("git-credential-glyx") {
            return git_credential_main();
        }
    }
    let cli = Cli::parse();
    let Cli {
        json,
        vault,
        keyfile,
        password_env,
        no_session,
        cmd,
    } = cli;
    let ctx = Ctx {
        json,
        vault,
        keyfile,
        password_env,
        no_session,
    };
    match cmd {
        Some(cmd) => dispatch(&ctx, cmd),
        None => select::cmd_select(ctx.json),
    }
}

fn git_credential_main() -> Result<()> {
    let action = std::env::args().nth(1).unwrap_or_default();
    let input = gitcred::read_credential_input()?;
    let vault_path = auth::resolve_vault_path(None)?;
    let mut uv = auth::resolve_unlocked(&auth::AuthFlags {
        vault: vault_path,
        keyfile: std::env::var("GLYX_KEYFILE").ok().map(PathBuf::from),
        password_env: std::env::var("GLYX_PASSWORD")
            .ok()
            .map(|_| "GLYX_PASSWORD".to_owned()),
        no_session: false,
    })?;
    match action.as_str() {
        "get" => gitcred::cmd_get(&mut uv, &input),
        "store" => gitcred::cmd_store(&mut uv, &input),
        "erase" => gitcred::cmd_erase(&mut uv, &input),
        _ => Ok(()),
    }
}

fn dispatch(ctx: &Ctx, cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Ls {
            folder,
            tag,
            item_type,
            all,
        } => cmd_ls(
            ctx,
            folder.as_deref(),
            tag.as_deref(),
            item_type.as_deref(),
            all,
        ),
        Cmd::Show {
            query,
            reveal,
            render,
        } => cmd_show(ctx, &query, reveal, render),
        Cmd::Add {
            item_type,
            name,
            folder,
            tag,
            field,
            generate,
            body_file,
            interactive,
        } => cmd_add(
            ctx,
            AddInput {
                item_type,
                name,
                folder,
                tag,
                field,
                generate,
                body_file,
                interactive,
            },
        ),
        Cmd::Edit {
            query,
            rename,
            field,
            delete_field,
            body_file,
            interactive,
        } => cmd_edit(
            ctx,
            &query,
            rename,
            &field,
            &delete_field,
            body_file.as_ref(),
            interactive,
        ),
        Cmd::Rm { query } => cmd_rm(ctx, &query),
        Cmd::Totp { query } => cmd_totp(ctx, &query),
        Cmd::Fill {
            query,
            field,
            timeout,
            dry_run,
        } => cmd_fill(ctx, &query, &field, timeout, dry_run),
        other => dispatch_grouped(ctx, other),
    }
}

fn dispatch_grouped(ctx: &Ctx, cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Vault { cmd } => dispatch_vault(ctx, cmd),
        Cmd::Unlock { ttl, with_pin } => cmd_unlock(ctx, ttl, with_pin),
        Cmd::Lock => cmd_lock(ctx),
        Cmd::Ssh { cmd } => dispatch_ssh(ctx, cmd),
        Cmd::Export { cmd } => dispatch_export(ctx, cmd),
        Cmd::Inject { cmd } => dispatch_inject(ctx, cmd),
        Cmd::SyncStatus => cmd_sync_status(ctx),
        Cmd::Sync {
            path,
            other_keyfile,
            other_password_env,
        } => cmd_sync(
            ctx,
            path.as_ref(),
            other_keyfile.as_ref(),
            other_password_env.as_deref(),
        ),
        Cmd::Conflicts { cmd } => match cmd {
            None => cmd_conflicts(ctx),
            Some(ConflictsCmd::Show { query, reveal }) => cmd_conflict_show(ctx, &query, reveal),
            Some(ConflictsCmd::Resolve {
                query,
                mine,
                theirs,
                field,
            }) => cmd_conflict_resolve(ctx, &query, mine, theirs, &field),
        },
        Cmd::Gc {
            older_than,
            dry_run,
        } => cmd_gc(ctx, &older_than, dry_run),
        Cmd::Doctor {
            rebuild_index,
            with_unlock,
        } => doctor(
            &ctx.vault_path()?,
            ctx.keyfile.as_deref(),
            rebuild_index,
            with_unlock,
            ctx.password_env.as_deref(),
            ctx.json,
        ),
        Cmd::Daemon { cmd } => dispatch_daemon(ctx, cmd),
        Cmd::Extension { cmd } => dispatch_extension(ctx, cmd),
        Cmd::Git { cmd } => dispatch_git(ctx, cmd),
        Cmd::Ls { .. }
        | Cmd::Show { .. }
        | Cmd::Add { .. }
        | Cmd::Edit { .. }
        | Cmd::Rm { .. }
        | Cmd::Totp { .. }
        | Cmd::Fill { .. } => unreachable!("item commands handled in dispatch"),
    }
}

fn dispatch_ssh(ctx: &Ctx, cmd: SshCmd) -> Result<()> {
    match cmd {
        SshCmd::Gen {
            name,
            kind,
            comment,
            folder,
        } => cmd_ssh_gen(ctx, name, kind, comment, folder),
        SshCmd::AgentEnv => exports::cmd_agent_env(ctx.json),
        SshCmd::Export { query, to } => {
            let mut uv = ctx.unlocked()?;
            exports::cmd_ssh_export(&mut uv, &query, to, ctx.json)
        }
    }
}

fn dispatch_export(ctx: &Ctx, cmd: ExportCmd) -> Result<()> {
    match cmd {
        ExportCmd::Add {
            target,
            item,
            field,
            blob,
            ssh,
            keep,
            perm,
        } => {
            let uv = ctx.unlocked()?;
            exports::cmd_add(
                exports::ExportAdd {
                    target,
                    item,
                    field,
                    blob,
                    ssh,
                    keep,
                    perm,
                },
                &uv,
                ctx.json,
            )
        }
        ExportCmd::Ls => exports::cmd_ls(ctx.json),
        ExportCmd::Recall { target } => exports::cmd_recall(&target, ctx.json),
        ExportCmd::Enforce { force } => {
            let mut uv = ctx.unlocked()?;
            exports::cmd_enforce(&mut uv, force, ctx.json)
        }
        ExportCmd::Tamper => exports::cmd_tamper(ctx.vault.as_ref(), ctx.json),
        ExportCmd::Merge {
            target,
            theirs,
            ours,
            pick,
            interactive,
        } => {
            let uv = ctx.unlocked()?;
            exports::cmd_merge(
                &uv,
                &target,
                exports::MergeOpts {
                    theirs,
                    ours,
                    interactive,
                },
                &pick,
                ctx.json,
            )
        }
    }
}

fn dispatch_inject(ctx: &Ctx, cmd: InjectCmd) -> Result<()> {
    match cmd {
        InjectCmd::Add { file, form, glob } => {
            exports::cmd_inject_add(&file, &form, glob.as_deref(), ctx.json)
        }
        InjectCmd::Scan => exports::cmd_inject_scan(ctx.json),
        InjectCmd::Rm { target } => exports::cmd_inject_rm(&target, ctx.json),
        InjectCmd::Ls => exports::cmd_ls(ctx.json),
    }
}

fn dispatch_daemon(ctx: &Ctx, cmd: DaemonCmd) -> Result<()> {
    match cmd {
        DaemonCmd::Start { idle_lock_min } => {
            daemon::cmd_start(ctx.vault.as_deref(), idle_lock_min, ctx.json)
        }
        DaemonCmd::Stop => daemon::cmd_stop(ctx.json),
        DaemonCmd::Status => {
            daemon::cmd_status(ctx.json);
            Ok(())
        }
    }
}

fn dispatch_extension(ctx: &Ctx, cmd: ExtensionCmd) -> Result<()> {
    match cmd {
        ExtensionCmd::Install { chrome, firefox } => {
            extension::cmd_install(&ctx.vault_path()?, chrome, firefox, ctx.json)
        }
        ExtensionCmd::Allow { id } => extension::cmd_allow(&id, ctx.json),
        ExtensionCmd::Status => {
            extension::cmd_status(&ctx.vault_path()?, ctx.json);
            Ok(())
        }
    }
}

fn dispatch_git(ctx: &Ctx, cmd: GitCmd) -> Result<()> {
    match cmd {
        GitCmd::Setup => cmd_git_setup(ctx.json),
        GitCmd::Status => cmd_git_status(ctx.json),
    }
}

fn dispatch_vault(ctx: &Ctx, cmd: VaultCmd) -> Result<()> {
    match cmd {
        VaultCmd::Select => select::cmd_select(ctx.json),
        VaultCmd::Init {
            path,
            preset,
            cipher,
            keyfile,
        } => vault_init(ctx, &path, preset, cipher, keyfile.as_deref()),
        VaultCmd::Rekey {
            new_keyfile,
            no_keyfile,
            new_password_env,
            cipher,
            preset,
            keep_old_slots,
        } => vault_rekey(
            ctx,
            new_keyfile.as_ref(),
            no_keyfile,
            new_password_env.as_deref(),
            cipher,
            preset,
            keep_old_slots,
        ),
    }
}

fn vault_init(
    ctx: &Ctx,
    path: &Path,
    preset: Preset,
    cipher: CipherOpt,
    keyfile: Option<&Path>,
) -> Result<()> {
    let password = auth::read_password(ctx.password_env.as_deref())?;
    let kf = keyfile.map(auth::load_or_create_keyfile).transpose()?;
    let suite = glyx_core::CipherSuiteConfig {
        kdf: glyx_core::KdfId::Argon2id,
        cipher: cipher_of(cipher),
        params: preset_params(preset),
    };
    let vault = glyx_store::Vault::init(path, suite, &password, kf.as_ref())?;
    let mut cfg = auth::load_config();
    cfg.register(glyx_store::config::VaultEntry {
        path: path.to_path_buf(),
        name: None,
        vault_id: Some(vault.config().vault_id),
        keyfile: keyfile.map(Path::to_path_buf),
        last_used_ms: 0,
    });
    cfg.select(path);
    auth::save_config(&cfg)?;
    if ctx.json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "vault_id": vault.config().vault_id,
                "path": path,
                "keyfile_required": vault.keyfile_required(),
            })
        );
    } else {
        println!("vault created: {}", path.display());
        println!("vault id: {}", vault.config().vault_id);
        println!(
            "protection: {}",
            if vault.keyfile_required() {
                "password + keyfile"
            } else {
                "password only"
            }
        );
    }
    Ok(())
}

fn vault_rekey(
    ctx: &Ctx,
    new_keyfile: Option<&PathBuf>,
    no_keyfile: bool,
    new_password_env: Option<&str>,
    cipher: Option<CipherOpt>,
    preset: Option<Preset>,
    keep_old_slots: bool,
) -> Result<()> {
    if new_keyfile.is_some() && no_keyfile {
        bail!("pass only one of --new-keyfile or --no-keyfile");
    }
    let vault_path = ctx.vault_path()?;
    let vault = glyx_store::Vault::open(&vault_path)?;
    let mut uv = auth::full_unlock(&vault, ctx.keyfile.as_deref(), ctx.password_env.as_deref())?;
    let old_slots: Vec<Uuid> = uv.list_slots()?.into_iter().map(|(id, _)| id).collect();
    if new_keyfile.is_none()
        && !no_keyfile
        && new_password_env.is_none()
        && cipher.is_none()
        && preset.is_none()
    {
        bail!("nothing to rotate: pass --new-keyfile, --no-keyfile, --new-password-env, --cipher, or --preset");
    }
    let rotate_keyfile = new_keyfile.is_some() || no_keyfile;
    let rotated = rotate_keyfile || new_password_env.is_some();
    if rotated {
        let (new_kf, required) = if no_keyfile {
            (glyx_crypto::ZERO_KEYFILE, false)
        } else {
            let p = new_keyfile.context("--new-keyfile is required to rotate credentials")?;
            (auth::load_or_create_keyfile(p)?, true)
        };
        let new_pw = auth::read_password(new_password_env)?;
        let params = preset.map_or(vault.config().cipher_suite.params, preset_params);
        let id = uv.add_slot_with_params(&new_pw, &new_kf, params)?;
        if !vault.verify_slot(&id, &new_pw, &new_kf)? {
            bail!("new keyslot failed verification");
        }
        if rotate_keyfile {
            uv.set_keyfile_required(required)?;
        }
        if !ctx.json {
            println!("new keyslot verified: {id}");
        }
    }
    if let Some(cipher) = cipher {
        let n = uv.reencrypt(cipher_of(cipher))?;
        if !ctx.json {
            println!("re-encrypted {n} items");
        }
    }
    if !keep_old_slots && rotated {
        for id in &old_slots {
            if uv.list_slots()?.iter().any(|(s, _)| s == id) {
                uv.retire_slot(id)?;
            }
        }
        if !ctx.json {
            println!("retired {} old keyslot(s)", old_slots.len());
        }
    }
    if ctx.json {
        println!("{}", serde_json::json!({"ok": true}));
    }
    Ok(())
}

fn cmd_unlock(ctx: &Ctx, ttl: Option<u64>, with_pin: bool) -> Result<()> {
    let vault_path = ctx.vault_path()?;
    let vault = glyx_store::Vault::open(&vault_path)?;
    let mut uv = auth::full_unlock(&vault, ctx.keyfile.as_deref(), ctx.password_env.as_deref())?;
    let rep = glyx_agent::enforce_all(&mut uv, false).map_err(|e| anyhow::anyhow!(e))?;
    let ttl = ttl.unwrap_or(auth::load_config().session_ttl_min);
    if with_pin {
        let pin = rpassword::prompt_password("new PIN: ").context("cannot read PIN")?;
        if pin.len() < 4 {
            bail!("PIN must be at least 4 characters");
        }
        uv.seal_pin_session(pin.as_bytes(), ttl)?;
    } else {
        uv.write_plain_session(ttl)?;
    }
    if ctx.json {
        println!("{}", serde_json::json!({"ok": true, "ttl_min": ttl}));
    } else {
        println!("unlocked for {ttl} minutes");
        println!(
            "exports: {} file(s), {} injection(s)",
            rep.files, rep.injected
        );
        for s in &rep.skipped {
            println!("skipped: {s} (run export enforce --force)");
        }
    }
    Ok(())
}

fn cmd_lock(ctx: &Ctx) -> Result<()> {
    let vault_path = auth::resolve_vault_path(ctx.vault.as_ref()).ok();
    if let Some(path) = vault_path.as_ref() {
        if let Ok(vault) = glyx_store::Vault::open(path) {
            let session_path = glyx_store::session::session_path(&vault.config().vault_id);
            if session_path.exists() {
                let uv = if let Some(uv) = vault.open_session(None)? {
                    Some(uv)
                } else {
                    let pin =
                        rpassword::prompt_password("vault PIN for file cleanup (empty to skip): ")
                            .unwrap_or_default();
                    if pin.is_empty() {
                        eprintln!("skipping file cleanup");
                        None
                    } else {
                        vault.open_session(Some(pin.as_bytes()))?
                    }
                };
                if let Some(uv) = uv {
                    let rep = glyx_agent::teardown_all(&uv).map_err(|e| anyhow::anyhow!(e))?;
                    if !ctx.json && (rep.wiped > 0 || rep.restored > 0 || !rep.drifted.is_empty()) {
                        println!("agent: wiped {}, restored {}", rep.wiped, rep.restored);
                        for d in &rep.drifted {
                            println!("drifted: {d}");
                        }
                    }
                }
            }
        }
    }
    let n = match vault_path.as_ref() {
        Some(path) => {
            let vault = glyx_store::Vault::open(path)?;
            let before = glyx_store::session::session_path(&vault.config().vault_id).exists();
            glyx_store::session::wipe_ticket(&vault.config().vault_id);
            usize::from(before)
        }
        None => glyx_store::session::wipe_all(),
    };
    if ctx.json {
        println!("{}", serde_json::json!({"ok": true, "wiped": n}));
    } else {
        println!("locked, wiped {n} session(s)");
    }
    Ok(())
}

fn cmd_ls(
    ctx: &Ctx,
    folder: Option<&str>,
    tag: Option<&str>,
    item_type: Option<&str>,
    all: bool,
) -> Result<()> {
    let uv = ctx.unlocked()?;
    let rows = uv.list(all)?;
    let want_type = item_type
        .map(|t| glyx_core::template::parse_type(t).map_err(|e| anyhow::anyhow!(e)))
        .transpose()?;
    let mut detailed = Vec::new();
    for row in &rows {
        if let Some(want) = want_type {
            if type_label(want) != row.item_type {
                continue;
            }
        }
        let item = uv.get_item(&row.id)?;
        let keep = folder
            .is_none_or(|f| item.as_ref().is_some_and(|item| item.folder.as_str() == f))
            && tag.is_none_or(|t| {
                item.as_ref()
                    .is_some_and(|item| item.tags.iter().any(|x| x.as_str() == t))
            });
        if keep {
            detailed.push(row.clone());
        }
    }
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&rows_json(&detailed))?);
    } else {
        for row in &detailed {
            let del = if row.deleted { " [deleted]" } else { "" };
            println!(
                "{} {} {}{del}",
                &row.id.as_simple().to_string()[..8],
                row.item_type,
                row.name
            );
        }
    }
    Ok(())
}

fn cmd_show(ctx: &Ctx, query: &str, reveal: bool, render: bool) -> Result<()> {
    let uv = ctx.unlocked()?;
    let item = items::resolve_query(&uv, query)?;
    if render {
        let body = glyx_store::present::note_rendered(&uv, &item, reveal)?;
        if ctx.json {
            println!(
                "{}",
                serde_json::json!({
                    "id": item.id,
                    "name": item.name,
                    "type": item.item_type,
                    "body": body,
                })
            );
        } else {
            println!("{body}");
        }
        return Ok(());
    }
    if ctx.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&items::item_json(&item, true))?
        );
    } else {
        println!("{} [{}]", item.name, type_label(item.item_type));
        println!("id: {}", item.id);
        if !item.folder.is_empty() {
            println!("folder: {}", item.folder);
        }
        for (k, f) in &item.fields {
            let show = items::display_value(item.item_type, k, reveal);
            println!(
                "{k}: {}",
                if show {
                    f.value.expose().to_owned()
                } else {
                    "••••".to_owned()
                }
            );
        }
    }
    Ok(())
}
struct AddInput {
    item_type: String,
    name: String,
    folder: Option<String>,
    tag: Vec<String>,
    field: Vec<String>,
    generate: Vec<String>,
    body_file: Option<PathBuf>,
    interactive: bool,
}

fn cmd_add(ctx: &Ctx, input: AddInput) -> Result<()> {
    let mut uv = ctx.unlocked()?;
    let parsed =
        glyx_core::template::parse_type(&input.item_type).map_err(|e| anyhow::anyhow!(e))?;
    let mut field_pairs = input.field;
    if let Some(path) = input.body_file.as_ref() {
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        field_pairs.push(format!("body={body}"));
    }
    let values = items::collect_fields(
        &field_pairs,
        &input.generate,
        parsed,
        input.interactive,
        None,
    )?;
    let item = items::build_new(
        &mut uv,
        parsed,
        input.name,
        input.folder.unwrap_or_default(),
        input.tag,
        values,
    )?;
    let id = item.id;
    uv.put_item(&item)?;
    if ctx.json {
        println!("{}", serde_json::json!({"ok": true, "id": id}));
    } else {
        println!("added {id}");
    }
    Ok(())
}

fn cmd_edit(
    ctx: &Ctx,
    query: &str,
    rename: Option<String>,
    field: &[String],
    delete_field: &[String],
    body_file: Option<&PathBuf>,
    interactive: bool,
) -> Result<()> {
    let mut uv = ctx.unlocked()?;
    let mut item = items::resolve_query(&uv, query)?;
    let renamed = rename.is_some();
    if let Some(name) = rename {
        item.name = name;
    }
    let mut values = BTreeMap::new();
    for pair in field {
        let (k, v) = items::split_field(pair)?;
        values.insert(k, v);
    }
    if let Some(path) = body_file {
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        values.insert("body".to_owned(), body);
    }
    if interactive {
        items::wizard_fill(item.item_type, &mut values, Some(&item))?;
    }
    for k in delete_field {
        item.fields.remove(k);
    }
    items::apply_fields(&mut uv, &mut item, values)?;
    if !field.is_empty() || !delete_field.is_empty() || renamed || interactive {
        uv.put_item(&item)?;
    }
    if ctx.json {
        println!(
            "{}",
            serde_json::json!({"ok": true, "id": item.id, "rev": item.rev})
        );
    } else {
        println!("updated {} (rev {})", item.id, item.rev);
    }
    Ok(())
}

fn cmd_rm(ctx: &Ctx, query: &str) -> Result<()> {
    let mut uv = ctx.unlocked()?;
    let item = items::resolve_query(&uv, query)?;
    let id = item.id;
    uv.delete_item(&id)?;
    if ctx.json {
        println!("{}", serde_json::json!({"ok": true, "id": id}));
    } else {
        println!("deleted {id} (tombstone kept for sync)");
    }
    Ok(())
}

fn cmd_fill(ctx: &Ctx, query: &str, field: &str, timeout: u64, dry_run: bool) -> Result<()> {
    let uv = ctx.unlocked()?;
    let item = items::resolve_query(&uv, query)?;
    let value = item
        .fields
        .get(field)
        .context("no such field")?
        .value
        .expose()
        .to_owned();
    if dry_run {
        if ctx.json {
            println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "id": item.id,
                    "field": field,
                    "backend": glyx_autofill::clipboard::backend_name(),
                })
            );
        } else {
            println!("would copy {} from {}", field, item.id);
        }
        return Ok(());
    }
    glyx_autofill::clipboard::copy(&value).map_err(|e| anyhow::anyhow!(e))?;
    if timeout == 0 {
        if ctx.json {
            println!("{}", serde_json::json!({"ok": true, "cleared": false}));
        } else {
            println!("copied {field} (stays until replaced)");
        }
        return Ok(());
    }
    if ctx.json {
        println!("{}", serde_json::json!({"ok": true, "timeout_s": timeout}));
    } else {
        println!("copied {field}, clearing in {timeout}s");
    }
    std::thread::sleep(std::time::Duration::from_secs(timeout));
    let cleared =
        glyx_autofill::clipboard::clear_if_ours(&value).map_err(|e| anyhow::anyhow!(e))?;
    if !ctx.json {
        if cleared {
            println!("cleared");
        } else {
            println!("clipboard changed, left alone");
        }
    }
    Ok(())
}

fn cmd_totp(ctx: &Ctx, query: &str) -> Result<()> {
    let uv = ctx.unlocked()?;
    let item = items::resolve_query(&uv, query)?;
    let params = items::totp_params(&item)?;
    let code = glyx_crypto::totp::generate_code(&params)?;
    if ctx.json {
        println!(
            "{}",
            serde_json::json!({"code": code, "period": params.step})
        );
    } else {
        println!("{code}");
    }
    Ok(())
}

fn cmd_ssh_gen(
    ctx: &Ctx,
    name: String,
    kind: SshKind,
    comment: Option<String>,
    folder: Option<String>,
) -> Result<()> {
    let mut uv = ctx.unlocked()?;
    let kind_str = match kind {
        SshKind::Ed25519 => "ed25519",
        SshKind::Rsa4096 => "rsa4096",
    };
    let pair = glyx_crypto::ssh::generate(kind_str, comment.as_deref().unwrap_or(""))?;
    let mut values = BTreeMap::new();
    values.insert("private".to_owned(), pair.openssh_private);
    values.insert("public".to_owned(), pair.openssh_public.clone());
    values.insert("comment".to_owned(), comment.unwrap_or_default());
    values.insert("kind".to_owned(), kind_str.to_owned());
    let item = items::build_new(
        &mut uv,
        glyx_core::ItemType::SshKey,
        name,
        folder.unwrap_or_default(),
        Vec::new(),
        values,
    )?;
    let id = item.id;
    uv.put_item(&item)?;
    if ctx.json {
        println!(
            "{}",
            serde_json::json!({"ok": true, "id": id, "public": pair.openssh_public})
        );
    } else {
        println!("added {id}");
        println!("{}", pair.openssh_public);
    }
    Ok(())
}

fn cmd_sync_status(ctx: &Ctx) -> Result<()> {
    let vault_path = ctx.vault_path()?;
    let vault = glyx_store::Vault::open(&vault_path)?;
    let headers = vault.scan_headers()?;
    let live = headers.iter().filter(|h| !h.deleted).count();
    let max_rev = headers.iter().map(|h| h.rev).max().unwrap_or(0);
    let uv = ctx.unlocked()?;
    let conflicts = uv.list_conflicts()?.len();
    let last_merge = uv.last_merge_ms()?;
    if ctx.json {
        println!(
            "{}",
            serde_json::json!({
                "envelopes": headers.len(),
                "live": live,
                "tombstones": headers.len() - live,
                "max_rev": max_rev,
                "conflicts": conflicts,
                "last_merge_ms": last_merge,
            })
        );
    } else {
        println!("envelopes: {}", headers.len());
        println!("live: {live}, tombstones: {}", headers.len() - live);
        println!("max rev: {max_rev}");
        println!("conflicts: {conflicts}");
        match last_merge {
            Some(ms) => println!("last merge: {ms}"),
            None => println!("last merge: never"),
        }
    }
    Ok(())
}

fn cmd_sync(
    ctx: &Ctx,
    other: Option<&PathBuf>,
    other_keyfile: Option<&PathBuf>,
    other_password_env: Option<&str>,
) -> Result<()> {
    let mut uv = ctx.unlocked()?;
    let heal = uv.heal_conflict_files()?;
    let mut adopted = 0usize;
    let mut merged = heal.merged;
    let mut conflicts = heal.conflicts;
    let mut blobs = 0usize;
    if let Some(other_path) = other {
        let other_vault = glyx_store::Vault::open(other_path)?;
        let kf_bytes = auth::resolve_keyfile(
            &other_vault,
            other_keyfile.or(ctx.keyfile.as_ref()).map(PathBuf::as_path),
        )?;
        let pw_env = other_password_env.or(ctx.password_env.as_deref());
        let pw = auth::read_password(pw_env)?;
        let other_uv = other_vault.unlock(&pw, &kf_bytes)?;
        let rep = uv.sync_from(&other_uv)?;
        adopted = rep.adopted;
        merged += rep.merged;
        conflicts += rep.conflicts;
        blobs = rep.blobs;
    }
    if heal.healed + adopted + merged > 0 {
        uv.stamp_merge()?;
    }
    if ctx.json {
        println!(
            "{}",
            serde_json::json!({
                "healed": heal.healed,
                "adopted": adopted,
                "merged": merged,
                "conflicts": conflicts,
                "blobs": blobs,
            })
        );
    } else {
        println!(
            "healed: {}, adopted: {adopted}, merged: {merged}, conflicts: {conflicts}, blobs: {blobs}",
            heal.healed
        );
    }
    Ok(())
}

fn find_conflict(uv: &glyx_store::UnlockedVault, query: &str) -> Result<glyx_store::ConflictMeta> {
    let metas = uv.list_conflicts()?;
    if let Ok(id) = query.parse::<Uuid>() {
        if let Some(m) = metas.into_iter().rfind(|m| m.item_id == id) {
            return Ok(m);
        }
        bail!("no conflict for {id}");
    }
    let mut hits: Vec<_> = metas
        .into_iter()
        .filter(|m| m.item_id.as_simple().to_string().starts_with(query))
        .collect();
    if hits.len() == 1 {
        return Ok(hits.remove(0));
    }
    if hits.len() > 1 {
        bail!("ambiguous id prefix, matches {} conflicts", hits.len());
    }
    let item = items::resolve_query(uv, query)?;
    uv.list_conflicts()?
        .into_iter()
        .rfind(|m| m.item_id == item.id)
        .context("no conflict for item")
}

fn cmd_conflicts(ctx: &Ctx) -> Result<()> {
    let uv = ctx.unlocked()?;
    let metas = uv.list_conflicts()?;
    if ctx.json {
        println!(
            "{}",
            serde_json::Value::Array(
                metas
                    .iter()
                    .map(|m| serde_json::json!({
                        "item": m.item_id,
                        "created_ms": m.created_ms,
                        "targets": m.race_targets,
                    }))
                    .collect()
            )
        );
    } else {
        for m in &metas {
            println!("{} races: {}", m.item_id, m.race_targets.join(","));
        }
        if metas.is_empty() {
            println!("no conflicts");
        }
    }
    Ok(())
}

fn cmd_conflict_show(ctx: &Ctx, query: &str, reveal: bool) -> Result<()> {
    let uv = ctx.unlocked()?;
    let meta = find_conflict(&uv, query)?;
    let Some((winner, local, remote, targets)) = uv.read_conflict(&meta.item_id)? else {
        bail!("conflict vanished");
    };
    let show_val = |v: &str| {
        if reveal {
            v.to_owned()
        } else {
            "••••".to_owned()
        }
    };
    if ctx.json {
        println!(
            "{}",
            serde_json::json!({
                "item": meta.item_id,
                "targets": targets,
                "winner_rev": winner.rev,
                "local_rev": local.rev,
                "remote_rev": remote.rev,
            })
        );
    } else {
        println!("conflict {} targets: {}", meta.item_id, targets.join(","));
        for t in &targets {
            let (mine, theirs) = race_values(&local, &remote, t);
            println!("{t}: mine={} theirs={}", show_val(&mine), show_val(&theirs));
        }
    }
    Ok(())
}

fn race_values(
    local: &glyx_core::Item,
    remote: &glyx_core::Item,
    target: &str,
) -> (String, String) {
    if let Some(field) = target.strip_prefix("field:") {
        let mine = local.fields.get(field).map_or("", |f| f.value.expose());
        let theirs = remote.fields.get(field).map_or("", |f| f.value.expose());
        return (mine.to_owned(), theirs.to_owned());
    }
    match target {
        "name" => (local.name.clone(), remote.name.clone()),
        "folder" => (local.folder.clone(), remote.folder.clone()),
        _ => (String::new(), String::new()),
    }
}

fn cmd_conflict_resolve(
    ctx: &Ctx,
    query: &str,
    mine: bool,
    theirs: bool,
    field: &[String],
) -> Result<()> {
    if mine && theirs {
        bail!("pass only one of --mine or --theirs");
    }
    if (mine || theirs) && !field.is_empty() {
        bail!("--field cannot combine with --mine or --theirs");
    }
    let mut uv = ctx.unlocked()?;
    let meta = find_conflict(&uv, query)?;
    let resolution = if mine {
        glyx_store::Resolution::Mine
    } else if theirs {
        glyx_store::Resolution::Theirs
    } else {
        let mut map = BTreeMap::new();
        for pair in field {
            let (k, v) = items::split_field(pair)?;
            map.insert(k, v);
        }
        if map.is_empty() {
            bail!("nothing to resolve: pass --mine, --theirs, or --field");
        }
        glyx_store::Resolution::Fields(map)
    };
    if !uv.resolve_conflict(&meta.item_id, resolution)? {
        bail!("conflict vanished");
    }
    if ctx.json {
        println!("{}", serde_json::json!({"ok": true, "id": meta.item_id}));
    } else {
        println!("resolved {}", meta.item_id);
    }
    Ok(())
}

fn parse_duration_ms(text: &str) -> Result<u64> {
    let (num, mult) = if let Some(n) = text.strip_suffix('d') {
        (n, 86_400_000u64)
    } else if let Some(n) = text.strip_suffix('h') {
        (n, 3_600_000u64)
    } else if let Some(n) = text.strip_suffix('m') {
        (n, 60_000u64)
    } else {
        (text, 86_400_000u64)
    };
    Ok(num
        .parse::<u64>()
        .context("bad duration")?
        .saturating_mul(mult))
}

fn cmd_gc(ctx: &Ctx, older_than: &str, dry_run: bool) -> Result<()> {
    let window = parse_duration_ms(older_than)?;
    if dry_run {
        let uv = ctx.unlocked()?;
        let now = glyx_core::ids::wall_ms_now();
        let cutoff = now.saturating_sub(window);
        let mut ids = Vec::new();
        for row in uv.list(true)? {
            if !row.deleted {
                continue;
            }
            if let Some(item) = uv.get_item(&row.id)? {
                if item.hlc.wall_ms < cutoff {
                    ids.push(row.id);
                }
            }
        }
        output_ids(ctx.json, &ids, "would purge");
        return Ok(());
    }
    let mut uv = ctx.unlocked()?;
    let ids = uv.gc_tombstones(window)?;
    output_ids(ctx.json, &ids, "purged");
    Ok(())
}

fn output_ids(as_json: bool, ids: &[Uuid], verb: &str) {
    if as_json {
        println!("{}", serde_json::json!({ "ids": ids }));
    } else {
        for id in ids {
            println!("{verb} {id}");
        }
        if ids.is_empty() {
            println!("nothing to purge");
        }
    }
}

fn cmd_git_setup(as_json: bool) -> Result<()> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let dir = PathBuf::from(home).join(".local").join("bin");
    std::fs::create_dir_all(&dir)?;
    let link = dir.join("git-credential-glyx");
    let exe = std::env::current_exe()?;
    #[cfg(unix)]
    {
        if std::fs::read_link(&link).is_err() {
            std::os::unix::fs::symlink(&exe, &link)?;
        }
    }
    let status = std::process::Command::new("git")
        .args(["config", "--global", "credential.helper", "glyx"])
        .status()?;
    if !status.success() {
        anyhow::bail!("git config failed");
    }
    if as_json {
        println!("{}", serde_json::json!({"ok": true, "link": link}));
    } else {
        println!("git credential helper installed: {}", link.display());
        println!("set GLYX_VAULT (and GLYX_KEYFILE) or unlock once for silent fills");
    }
    Ok(())
}

fn cmd_git_status(as_json: bool) -> Result<()> {
    let out = std::process::Command::new("git")
        .args(["config", "--get", "credential.helper"])
        .output()?;
    let helper = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if as_json {
        println!("{}", serde_json::json!({"helper": helper}));
    } else {
        println!("credential.helper: {helper}");
    }
    Ok(())
}

fn type_label(item_type: glyx_core::ItemType) -> &'static str {
    match item_type {
        glyx_core::ItemType::Login => "login",
        glyx_core::ItemType::Passkey => "passkey",
        glyx_core::ItemType::Totp => "totp",
        glyx_core::ItemType::Identity => "identity",
        glyx_core::ItemType::Card => "card",
        glyx_core::ItemType::Note => "note",
        glyx_core::ItemType::File => "file",
        glyx_core::ItemType::SshKey => "ssh_key",
        glyx_core::ItemType::GenericKey => "generic_key",
    }
}

fn rows_json(rows: &[glyx_store::IndexRow]) -> serde_json::Value {
    serde_json::Value::Array(
        rows.iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "type": r.item_type,
                    "name": r.name,
                    "rev": r.rev,
                    "deleted": r.deleted,
                })
            })
            .collect(),
    )
}

fn doctor(
    path: &PathBuf,
    keyfile: Option<&std::path::Path>,
    rebuild_index: bool,
    with_unlock: bool,
    password_env: Option<&str>,
    as_json: bool,
) -> Result<()> {
    let mut report = serde_json::json!({"path": path});
    let vault = glyx_store::Vault::open(path)?;
    report["format_version"] = serde_json::json!(vault.config().format_version);
    report["keyslots"] = serde_json::json!(vault.keyslot_count()?);
    let headers = vault.scan_headers()?;
    report["envelopes"] = serde_json::json!(headers.len());
    report["live"] = serde_json::json!(headers.iter().filter(|h| !h.deleted).count());
    if rebuild_index {
        let n = vault.rebuild_index()?;
        report["rebuilt_index"] = serde_json::json!(n);
    }
    if with_unlock {
        let kf = auth::resolve_keyfile(&vault, keyfile)?;
        let password = auth::read_password(password_env)?;
        let unlocked = vault.unlock(&password, &kf)?;
        let mut items_ok = 0;
        for h in &headers {
            if unlocked.get_item(&h.id)?.is_some() {
                items_ok += 1;
            }
        }
        report["decrypted_items"] = serde_json::json!(items_ok);
    }
    report["ok"] = serde_json::json!(true);
    report["clipboard"] = serde_json::json!({
        "backend": glyx_autofill::clipboard::backend_name(),
        "available": glyx_autofill::clipboard::available(),
    });
    if as_json {
        println!("{report}");
    } else {
        println!("vault ok: {}", path.display());
        println!("format: v{}", vault.config().format_version);
        println!(
            "clipboard: {} ({})",
            glyx_autofill::clipboard::backend_name(),
            if glyx_autofill::clipboard::available() {
                "available"
            } else {
                "unavailable"
            }
        );
        println!("keyslots: {}", report["keyslots"]);
        println!("envelopes: {} (live {})", headers.len(), report["live"]);
        if let Some(n) = report.get("rebuilt_index") {
            println!("index rebuilt: {n}");
        }
        if let Some(n) = report.get("decrypted_items") {
            println!("decrypted: {n}");
        }
    }
    Ok(())
}

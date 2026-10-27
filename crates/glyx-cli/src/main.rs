mod auth;
mod daemon;
mod exports;
mod extension;
mod gitcred;
mod items;
mod select;
mod tui;

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
        #[arg(long, help = "Do not materialize exports or injections")]
        no_materialize: bool,
    },
    #[command(about = "Forget sessions")]
    Lock,
    #[command(about = "Interactive full-screen browser and editor")]
    Tui,
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
        #[arg(long, short, help = "Case-insensitive search")]
        query: Option<String>,
        #[arg(long, help = "Only favorites")]
        favorite: bool,
        #[arg(long, value_enum, default_value = "updated", help = "Sort order")]
        sort: SortKey,
        #[arg(long, help = "Reverse the sort")]
        reverse: bool,
        #[arg(long, help = "Return at most this many items")]
        limit: Option<usize>,
        #[arg(long, default_value_t = 0, help = "Skip this many items")]
        offset: usize,
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
    #[command(about = "Manage stored passkeys")]
    Passkey {
        #[command(subcommand)]
        cmd: PasskeyCmd,
    },
    #[command(about = "Generate a password")]
    Gen {
        #[arg(long, default_value_t = 24, help = "Length")]
        length: usize,
        #[arg(long, help = "Exclude lowercase letters")]
        no_lower: bool,
        #[arg(long, help = "Exclude uppercase letters")]
        no_upper: bool,
        #[arg(long, help = "Exclude digits")]
        no_digits: bool,
        #[arg(long, help = "Exclude symbols")]
        no_symbols: bool,
        #[arg(long, help = "Allow visually ambiguous characters")]
        allow_ambiguous: bool,
    },
    #[command(about = "Encrypted vault attachments")]
    Blob {
        #[command(subcommand)]
        cmd: BlobCmd,
    },
    #[command(about = "Mark an item as favorite")]
    Favorite {
        #[arg(help = "Id, id prefix, or exact name")]
        query: String,
        #[arg(long, help = "Remove the favorite mark")]
        off: bool,
    },
    #[command(about = "Recently opened items")]
    Recents,
    #[command(about = "Tags and folders with item counts")]
    Library,
    #[command(about = "Manage tags")]
    Tag {
        #[command(subcommand)]
        cmd: TagCmd,
    },
    #[command(about = "Manage folders")]
    Folder {
        #[command(subcommand)]
        cmd: FolderCmd,
    },
    #[command(about = "Find possible duplicate items")]
    Duplicates,
    #[command(about = "Apply an action to several items")]
    Bulk {
        #[command(subcommand)]
        cmd: BulkCmd,
    },
    #[command(about = "Known devices, labels, and last activity")]
    Devices {
        #[command(subcommand)]
        cmd: Option<DeviceCmd>,
    },
    #[command(about = "Password health report")]
    Health {
        #[arg(long, default_value_t = 12, help = "Minimum password length")]
        min_length: usize,
        #[arg(long, default_value_t = 365, help = "Maximum password age in days")]
        max_age_days: u64,
    },
    #[command(about = "Local audit log")]
    Audit {
        #[arg(long, default_value_t = 50, help = "Number of events")]
        limit: usize,
        #[arg(long, default_value_t = 0, help = "Skip events")]
        offset: usize,
        #[arg(long, help = "Filter by event name")]
        event: Option<String>,
    },
    #[command(about = "Show item history")]
    History {
        #[arg(help = "Id, id prefix, or exact name")]
        query: String,
        #[arg(long, help = "Show a history file")]
        show: Option<String>,
        #[arg(long, help = "Reveal secrets in --show output")]
        reveal: bool,
        #[arg(long, help = "Compare a history file with the current item")]
        compare: Option<String>,
    },
    #[command(about = "Restore a historical revision")]
    Restore {
        #[arg(help = "Id, id prefix, or exact name")]
        query: String,
        #[arg(long, help = "Revision to restore")]
        rev: Option<u64>,
        #[arg(long, help = "History file name")]
        file: Option<String>,
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
        #[arg(long, help = "Attach an encrypted file (25 MiB max)")]
        attach: Option<PathBuf>,
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
        #[arg(long, help = "Replace the encrypted attachment (25 MiB max)")]
        attach: Option<PathBuf>,
        #[arg(long, help = "Move to a folder (empty string clears)")]
        folder: Option<String>,
        #[arg(long, help = "Add a tag (repeatable)")]
        tag: Vec<String>,
        #[arg(long, help = "Remove a tag (repeatable)")]
        remove_tag: Vec<String>,
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
    #[command(about = "Show or change app settings")]
    Config {
        #[command(subcommand)]
        cmd: Option<ConfigCmd>,
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
    #[command(about = "Write an encrypted-artifact backup archive")]
    Backup {
        #[arg(help = "Archive path (must not exist)")]
        out: PathBuf,
    },
    #[command(about = "Restore a backup into a new vault directory")]
    Restore {
        #[arg(help = "Archive path")]
        archive: PathBuf,
        #[arg(help = "New vault directory (must not exist)")]
        dest: PathBuf,
    },
    #[command(about = "Remove a vault from the registry (files untouched)")]
    Forget {
        #[arg(help = "Vault directory (defaults to the selected vault)")]
        path: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCmd {
    #[command(about = "Print current settings")]
    Show,
    #[command(about = "Change one setting")]
    Set {
        #[arg(
            help = "Key: mode, session_ttl_min, auto_materialize, daemon_on_exit, idle_lock_min"
        )]
        key: String,
        #[arg(help = "New value")]
        value: String,
    },
}

#[derive(Debug, Subcommand)]
enum PasskeyCmd {
    #[command(about = "List stored passkeys")]
    Ls,
    #[command(about = "Show passkey metadata")]
    Show {
        #[arg(help = "Id, id prefix, or exact name")]
        query: String,
    },
    #[command(about = "Delete a passkey")]
    Rm {
        #[arg(help = "Id, id prefix, or exact name")]
        query: String,
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
enum BlobCmd {
    #[command(about = "Encrypt and store a file")]
    Put {
        #[arg(help = "File to attach")]
        file: PathBuf,
    },
    #[command(about = "Decrypt an attachment to a file")]
    Get {
        #[arg(help = "Blob address")]
        addr: String,
        #[arg(long, help = "Output path")]
        out: PathBuf,
    },
    #[command(about = "List stored attachments")]
    Ls,
    #[command(about = "Find and optionally purge unreferenced attachments")]
    Gc {
        #[arg(long, help = "Delete orphans instead of listing them")]
        purge: bool,
    },
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
    #[command(about = "Unlock (materialize) one tracked target")]
    Unlock {
        #[arg(help = "Tracked file or folder")]
        target: PathBuf,
        #[arg(long, help = "Overwrite drifted files")]
        force: bool,
    },
    #[command(about = "Lock (restore locked form) one tracked target")]
    Lock {
        #[arg(help = "Tracked file or folder")]
        target: PathBuf,
    },
    #[command(about = "Point a tracked target at its new path")]
    Move {
        #[arg(help = "Old path")]
        old: PathBuf,
        #[arg(help = "New path")]
        new: PathBuf,
    },
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

#[derive(Debug, Subcommand)]
enum DeviceCmd {
    #[command(about = "Set a local device label")]
    Label {
        #[arg(help = "Device id, id prefix, or 'this'")]
        device: String,
        #[arg(help = "New label")]
        label: String,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SortKey {
    #[value(help = "Last updated")]
    Updated,
    #[value(help = "Name")]
    Name,
    #[value(help = "Item type")]
    Type,
    #[value(help = "Favorites first")]
    Favorite,
}

#[derive(Debug, Subcommand)]
enum TagCmd {
    #[command(about = "Rename a tag everywhere")]
    Rename {
        #[arg(help = "Current tag")]
        from: String,
        #[arg(help = "New tag")]
        to: String,
    },
    #[command(about = "Remove a tag everywhere")]
    Rm {
        #[arg(help = "Tag to remove")]
        tag: String,
    },
}

#[derive(Debug, Subcommand)]
enum FolderCmd {
    #[command(about = "Rename a folder everywhere")]
    Rename {
        #[arg(help = "Current folder")]
        from: String,
        #[arg(help = "New folder")]
        to: String,
    },
    #[command(about = "Move all items in a folder to the root")]
    Rm {
        #[arg(help = "Folder to remove")]
        folder: String,
    },
}

#[derive(Debug, Subcommand)]
enum BulkCmd {
    #[command(about = "Mark selected items as favorite")]
    Favorite {
        #[arg(long = "id", help = "Item id, prefix, or name (repeatable)")]
        ids: Vec<String>,
        #[arg(long, help = "Also select this folder")]
        folder: Option<String>,
    },
    #[command(about = "Remove the favorite mark")]
    Unfavorite {
        #[arg(long = "id", help = "Item id, prefix, or name (repeatable)")]
        ids: Vec<String>,
        #[arg(long, help = "Also select this folder")]
        folder: Option<String>,
    },
    #[command(about = "Add a tag")]
    AddTag {
        #[arg(help = "Tag to add")]
        tag: String,
        #[arg(long = "id", help = "Item id, prefix, or name (repeatable)")]
        ids: Vec<String>,
        #[arg(long, help = "Also select this folder")]
        folder: Option<String>,
    },
    #[command(about = "Remove a tag")]
    RemoveTag {
        #[arg(help = "Tag to remove")]
        tag: String,
        #[arg(long = "id", help = "Item id, prefix, or name (repeatable)")]
        ids: Vec<String>,
        #[arg(long, help = "Also select this folder")]
        folder: Option<String>,
    },
    #[command(about = "Move selected items to a folder")]
    MoveFolder {
        #[arg(help = "Destination folder")]
        to: String,
        #[arg(long = "id", help = "Item id, prefix, or name (repeatable)")]
        ids: Vec<String>,
        #[arg(long, help = "Also select items in this folder")]
        folder: Option<String>,
    },
    #[command(about = "Tombstone selected items")]
    Delete {
        #[arg(long = "id", help = "Item id, prefix, or name (repeatable)")]
        ids: Vec<String>,
        #[arg(long, help = "Also select this folder")]
        folder: Option<String>,
        #[arg(long, help = "Confirm deletion")]
        yes: bool,
    },
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

#[allow(clippy::too_many_lines)]
fn dispatch(ctx: &Ctx, cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Ls {
            folder,
            tag,
            item_type,
            all,
            query,
            favorite,
            sort,
            reverse,
            limit,
            offset,
        } => cmd_ls(
            ctx,
            LsArgs {
                folder: folder.as_deref(),
                tag: tag.as_deref(),
                item_type: item_type.as_deref(),
                all,
                query: query.as_deref(),
                favorite,
                sort,
                reverse,
                limit,
                offset,
            },
        ),
        Cmd::Show {
            query,
            reveal,
            render,
        } => cmd_show(ctx, &query, reveal, render),
        Cmd::Passkey { cmd } => dispatch_passkey(ctx, cmd),
        Cmd::Gen {
            length,
            no_lower,
            no_upper,
            no_digits,
            no_symbols,
            allow_ambiguous,
        } => cmd_gen(
            ctx,
            length,
            no_lower,
            no_upper,
            no_digits,
            no_symbols,
            allow_ambiguous,
        ),
        Cmd::Blob { cmd } => cmd_blob(ctx, cmd),
        cmd @ (Cmd::Favorite { .. }
        | Cmd::Recents
        | Cmd::Library
        | Cmd::Tag { .. }
        | Cmd::Folder { .. }
        | Cmd::Duplicates
        | Cmd::Bulk { .. }
        | Cmd::Devices { .. }
        | Cmd::Health { .. }
        | Cmd::Audit { .. }) => dispatch_library(ctx, cmd),
        Cmd::History {
            query,
            show,
            reveal,
            compare,
        } => cmd_history(ctx, &query, show.as_deref(), reveal, compare.as_deref()),
        Cmd::Restore { query, rev, file } => cmd_restore(ctx, &query, rev, file.as_deref()),
        Cmd::Add {
            item_type,
            name,
            folder,
            tag,
            field,
            generate,
            body_file,
            attach,
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
                attach,
                interactive,
            },
        ),
        Cmd::Edit {
            query,
            rename,
            field,
            delete_field,
            body_file,
            attach,
            folder,
            tag,
            remove_tag,
            interactive,
        } => cmd_edit(
            ctx,
            EditInput {
                query,
                rename,
                field,
                delete_field,
                body_file,
                attach,
                folder,
                tag,
                remove_tag,
                interactive,
            },
        ),
        Cmd::Rm { query } => cmd_rm(ctx, &query),
        Cmd::Totp { query } => cmd_totp(ctx, &query),
        Cmd::Fill {
            query,
            field,
            timeout,
            dry_run,
        } => cmd_fill(ctx, &query, &field, timeout, dry_run),
        Cmd::Tui => tui::cmd_tui(ctx),
        other => dispatch_grouped(ctx, other),
    }
}

fn dispatch_grouped(ctx: &Ctx, cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Vault { cmd } => dispatch_vault(ctx, cmd),
        Cmd::Unlock {
            ttl,
            with_pin,
            no_materialize,
        } => cmd_unlock(ctx, ttl, with_pin, no_materialize),
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
        Cmd::Config { cmd } => cmd_config(ctx, cmd),
        Cmd::Ls { .. }
        | Cmd::Show { .. }
        | Cmd::Gen { .. }
        | Cmd::Blob { .. }
        | Cmd::Favorite { .. }
        | Cmd::Recents
        | Cmd::Library
        | Cmd::Tag { .. }
        | Cmd::Folder { .. }
        | Cmd::Duplicates
        | Cmd::Bulk { .. }
        | Cmd::Devices { .. }
        | Cmd::Health { .. }
        | Cmd::Audit { .. }
        | Cmd::History { .. }
        | Cmd::Restore { .. }
        | Cmd::Add { .. }
        | Cmd::Edit { .. }
        | Cmd::Rm { .. }
        | Cmd::Totp { .. }
        | Cmd::Fill { .. }
        | Cmd::Passkey { .. }
        | Cmd::Tui => unreachable!("interactive commands handled in dispatch"),
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
        InjectCmd::Unlock { target, force } => {
            let mut uv = ctx.unlocked()?;
            exports::cmd_target_unlock(&mut uv, &target, force, ctx.json)
        }
        InjectCmd::Lock { target } => {
            let uv = ctx.unlocked()?;
            exports::cmd_target_lock(&uv, &target, ctx.json)
        }
        InjectCmd::Move { old, new } => {
            let uv = ctx.unlocked()?;
            exports::cmd_target_move(&uv, &old, &new, ctx.json)
        }
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
        VaultCmd::Backup { out } => cmd_vault_backup(ctx, &out),
        VaultCmd::Restore { archive, dest } => cmd_vault_restore(ctx, &archive, &dest),
        VaultCmd::Forget { path } => vault_forget(ctx, path.as_deref()),
    }
}

fn cmd_vault_backup(ctx: &Ctx, out: &Path) -> Result<()> {
    let path = ctx.vault_path()?;
    let vault = glyx_store::Vault::open(&path)?;
    let cfg = auth::load_config();
    let keyfile = cfg
        .find(&path)
        .and_then(|entry| entry.keyfile.as_deref())
        .map(Path::to_path_buf);
    let report = glyx_store::backup::create(&vault, out, keyfile.as_deref())?;
    if ctx.json {
        println!(
            "{}",
            serde_json::json!({"ok": true, "path": out, "bytes": report.bytes})
        );
    } else {
        println!("wrote {} bytes to {}", report.bytes, out.display());
    }
    Ok(())
}

fn cmd_vault_restore(ctx: &Ctx, archive: &Path, dest: &Path) -> Result<()> {
    glyx_store::backup::restore(archive, dest)?;
    let vault = glyx_store::Vault::open(dest)?;
    let mut cfg = auth::load_config();
    let label = dest.file_name().map_or_else(
        || dest.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    cfg.register(glyx_store::config::VaultEntry {
        path: dest.to_path_buf(),
        name: Some(label),
        vault_id: Some(vault.config().vault_id),
        keyfile: None,
        last_used_ms: glyx_core::ids::wall_ms_now(),
    });
    cfg.select(dest);
    auth::save_config(&cfg)?;
    if ctx.json {
        println!(
            "{}",
            serde_json::json!({"ok": true, "path": dest, "vault_id": vault.config().vault_id})
        );
    } else {
        println!("restored {}", dest.display());
    }
    Ok(())
}

fn vault_forget(ctx: &Ctx, path: Option<&Path>) -> Result<()> {
    let target = match path {
        Some(p) => glyx_store::config::normalize(p),
        None => ctx.vault_path()?,
    };
    let mut cfg = auth::load_config();
    let Some(entry) = cfg.find(&target).cloned() else {
        bail!("not registered: {}", target.display());
    };
    cfg.remove(&target);
    auth::save_config(&cfg)?;
    if let Some(id) = entry.vault_id {
        glyx_store::session::wipe_ticket(&id);
    }
    if ctx.json {
        println!("{}", serde_json::json!({"ok": true, "forgotten": target}));
    } else {
        println!("forgot {} (vault files untouched)", target.display());
    }
    Ok(())
}

fn cmd_config(ctx: &Ctx, cmd: Option<ConfigCmd>) -> Result<()> {
    use glyx_store::config::{DaemonExit, SessionMode};
    let mut cfg = auth::load_config();
    match cmd {
        None | Some(ConfigCmd::Show) => {
            if ctx.json {
                println!("{}", serde_json::to_string(&cfg)?);
            } else {
                let mode = match cfg.mode {
                    SessionMode::Oneshot => "oneshot",
                    SessionMode::Session => "session",
                };
                let exit = match cfg.daemon_on_exit {
                    DaemonExit::Stop => "stop",
                    DaemonExit::Keep => "keep",
                };
                println!("mode = {mode}");
                println!("session_ttl_min = {}", cfg.session_ttl_min);
                println!("auto_materialize = {}", cfg.auto_materialize);
                println!("daemon_on_exit = {exit}");
                println!(
                    "idle_lock_min = {}",
                    cfg.idle_lock_min
                        .map_or_else(|| "-".to_owned(), |v| v.to_string())
                );
                println!(
                    "current_vault = {}",
                    cfg.current_vault
                        .as_ref()
                        .map_or_else(|| "-".to_owned(), |p| p.display().to_string())
                );
            }
        }
        Some(ConfigCmd::Set { key, value }) => {
            match key.as_str() {
                "mode" => {
                    cfg.mode = match value.as_str() {
                        "session" => SessionMode::Session,
                        "oneshot" => SessionMode::Oneshot,
                        other => bail!("mode must be oneshot or session, got {other}"),
                    };
                }
                "session_ttl_min" => {
                    let parsed: u64 = value.parse().context("session_ttl_min must be a number")?;
                    cfg.session_ttl_min = parsed.clamp(1, glyx_store::session::SESSION_TTL_MAX_MIN);
                }
                "auto_materialize" => {
                    cfg.auto_materialize = match value.as_str() {
                        "true" | "1" | "yes" | "on" => true,
                        "false" | "0" | "no" | "off" => false,
                        other => bail!("auto_materialize must be true or false, got {other}"),
                    };
                }
                "daemon_on_exit" => {
                    cfg.daemon_on_exit = match value.as_str() {
                        "keep" => DaemonExit::Keep,
                        "stop" => DaemonExit::Stop,
                        other => bail!("daemon_on_exit must be stop or keep, got {other}"),
                    };
                }
                "idle_lock_min" => {
                    cfg.idle_lock_min =
                        Some(value.parse().context("idle_lock_min must be a number")?);
                }
                other => bail!("unknown setting {other}"),
            }
            auth::save_config(&cfg)?;
            if ctx.json {
                println!("{}", serde_json::json!({"ok": true, "key": key}));
            } else {
                println!("set {key} = {value}");
            }
        }
    }
    Ok(())
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

fn cmd_unlock(ctx: &Ctx, ttl: Option<u64>, with_pin: bool, no_materialize: bool) -> Result<()> {
    let vault_path = ctx.vault_path()?;
    let vault = glyx_store::Vault::open(&vault_path)?;
    let mut uv = auth::full_unlock(&vault, ctx.keyfile.as_deref(), ctx.password_env.as_deref())?;
    let auto = !no_materialize && auth::load_config().auto_materialize;
    let rep = if auto {
        glyx_agent::enforce_all(&mut uv, false).map_err(|e| anyhow::anyhow!(e))?
    } else {
        glyx_agent::MaterializeReport::default()
    };
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
        println!(
            "{}",
            serde_json::json!({"ok": true, "ttl_min": ttl, "materialized": auto})
        );
    } else {
        println!("unlocked for {ttl} minutes");
        if auto {
            println!(
                "exports: {} file(s), {} injection(s)",
                rep.files, rep.injected
            );
            for s in &rep.skipped {
                println!("skipped: {s} (run export enforce --force)");
            }
        } else {
            println!(
                "auto-materialize off: unlock tracked targets with `glyx inject unlock <target>`"
            );
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

fn item_matches(item: &glyx_core::Item, query: &str) -> bool {
    let needle = query.to_lowercase();
    item.name.to_lowercase().contains(&needle)
        || item.folder.to_lowercase().contains(&needle)
        || item.tags.iter().any(|t| t.to_lowercase().contains(&needle))
        || item.fields.iter().any(|(key, field)| {
            glyx_store::present::display_value(item.item_type, key, false)
                && field.value.expose().to_lowercase().contains(&needle)
        })
}

#[derive(Clone, Copy)]
struct LsArgs<'a> {
    folder: Option<&'a str>,
    tag: Option<&'a str>,
    item_type: Option<&'a str>,
    all: bool,
    query: Option<&'a str>,
    favorite: bool,
    sort: SortKey,
    reverse: bool,
    limit: Option<usize>,
    offset: usize,
}

fn cmd_ls(ctx: &Ctx, args: LsArgs<'_>) -> Result<()> {
    let LsArgs {
        folder,
        tag,
        item_type,
        all,
        query,
        favorite: favorite_only,
        sort,
        reverse,
        limit,
        offset,
    } = args;
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
        if favorite_only && !row.favorite {
            continue;
        }
        let item = uv.get_item(&row.id)?;
        let keep = folder
            .is_none_or(|f| item.as_ref().is_some_and(|item| item.folder.as_str() == f))
            && tag.is_none_or(|t| {
                item.as_ref()
                    .is_some_and(|item| item.tags.iter().any(|x| x.as_str() == t))
            })
            && query.is_none_or(|q| item.as_ref().is_some_and(|item| item_matches(item, q)));
        if keep {
            detailed.push(row.clone());
        }
    }
    detailed.sort_by(|a, b| {
        let ordering = match sort {
            SortKey::Updated => a.updated_ms.cmp(&b.updated_ms),
            SortKey::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            SortKey::Type => a.item_type.cmp(&b.item_type),
            SortKey::Favorite => a
                .favorite
                .cmp(&b.favorite)
                .then_with(|| b.updated_ms.cmp(&a.updated_ms)),
        };
        let ordering = if matches!(sort, SortKey::Updated | SortKey::Favorite) == reverse {
            ordering
        } else {
            ordering.reverse()
        };
        ordering.then_with(|| a.id.cmp(&b.id))
    });
    let detailed: Vec<_> = detailed
        .into_iter()
        .skip(offset)
        .take(limit.unwrap_or(usize::MAX))
        .collect();
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&rows_json(&detailed))?);
    } else {
        for row in &detailed {
            let del = if row.deleted { " [deleted]" } else { "" };
            println!(
                "{} {} {}{del}",
                &row.id.as_simple().to_string()[..8],
                row.item_type,
                if row.favorite {
                    format!("★ {}", row.name)
                } else {
                    row.name.clone()
                }
            );
        }
    }
    Ok(())
}

fn dispatch_library(ctx: &Ctx, cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Favorite { query, off } => cmd_favorite(ctx, &query, off),
        Cmd::Recents => cmd_recents(ctx),
        Cmd::Library => cmd_library(ctx),
        Cmd::Tag { cmd } => cmd_tag(ctx, cmd),
        Cmd::Folder { cmd } => cmd_folder(ctx, cmd),
        Cmd::Duplicates => cmd_duplicates(ctx),
        Cmd::Bulk { cmd } => cmd_bulk(ctx, cmd),
        Cmd::Devices { cmd } => cmd_devices(ctx, cmd),
        Cmd::Health {
            min_length,
            max_age_days,
        } => cmd_health(ctx, min_length, max_age_days),
        Cmd::Audit {
            limit,
            offset,
            event,
        } => cmd_audit(ctx, limit, offset, event.as_deref()),
        _ => unreachable!("not a library command"),
    }
}

fn cmd_devices(ctx: &Ctx, cmd: Option<DeviceCmd>) -> Result<()> {
    let uv = ctx.unlocked()?;
    if let Some(DeviceCmd::Label { device, label }) = cmd {
        let devices = uv.devices()?;
        let target = if device == "this" {
            devices.iter().find(|d| d.current)
        } else {
            devices
                .iter()
                .find(|d| d.id == device || d.id.starts_with(&device))
        };
        let Some(target) = target else {
            bail!("device not found");
        };
        let mut cfg = glyx_store::config::load();
        cfg.set_device_label(uv.config().vault_id, target.id.clone(), label.clone());
        glyx_store::config::save(&cfg)?;
        let _ = glyx_store::audit::append(
            uv.config().vault_id,
            &uv.device_node().to_hex(),
            "device_label",
            None,
            None,
            Some("success"),
            Some(&format!("{} -> {label}", target.id)),
        );
        println!("labeled {} as {label}", &target.id[..8]);
        return Ok(());
    }
    let devices = uv.devices()?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&devices)?);
    } else {
        for device in devices {
            println!(
                "{} {}{} {}",
                &device.id[..8],
                if device.current { "* " } else { "" },
                device.label,
                if device.last_seen_ms > 0 {
                    format!("last seen {}", device.last_seen_ms)
                } else {
                    String::new()
                }
            );
        }
    }
    Ok(())
}

fn cmd_health(ctx: &Ctx, min_length: usize, max_age_days: u64) -> Result<()> {
    let uv = ctx.unlocked()?;
    let report = uv.health(min_length, max_age_days)?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "items {} | weak {} | reused {} | old {} | no TOTP {}",
            report.summary.items,
            report.summary.weak,
            report.summary.reused,
            report.summary.old,
            report.summary.no_totp
        );
        for issue in &report.issues {
            println!(
                "{} {} [{}]",
                &issue.id.as_simple().to_string()[..8],
                issue.name,
                issue.issues.join(", ")
            );
        }
    }
    Ok(())
}

fn cmd_audit(ctx: &Ctx, limit: usize, offset: usize, event: Option<&str>) -> Result<()> {
    let uv = ctx.unlocked()?;
    let events = glyx_store::audit::list(&uv.config().vault_id, limit, offset, event)?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&events)?);
    } else if events.is_empty() {
        println!("no audit events");
    } else {
        for event in events {
            println!(
                "{} {} {}{}{}",
                event.ts_ms,
                event.event,
                event.outcome.unwrap_or_default(),
                event
                    .item_id
                    .map(|id| format!(" {}", &id.as_simple().to_string()[..8]))
                    .unwrap_or_default(),
                event
                    .field
                    .map(|field| format!(" {field}"))
                    .unwrap_or_default()
            );
        }
    }
    Ok(())
}

fn cli_audit(
    uv: &glyx_store::UnlockedVault,
    event: &str,
    item: Option<uuid::Uuid>,
    field: Option<&str>,
) {
    let _ = glyx_store::audit::append(
        uv.config().vault_id,
        &uv.device_node().to_hex(),
        event,
        item,
        field,
        Some("success"),
        None,
    );
}

fn cmd_favorite(ctx: &Ctx, query: &str, off: bool) -> Result<()> {
    let mut uv = ctx.unlocked()?;
    let item = items::resolve_query(&uv, query)?;
    uv.set_favorite(&item.id, !off)?;
    if ctx.json {
        println!(
            "{}",
            serde_json::json!({"id": item.id, "name": item.name, "favorite": !off})
        );
    } else {
        println!(
            "{} {}",
            if off { "unfavorited" } else { "favorited" },
            item.name
        );
    }
    Ok(())
}

fn cmd_recents(ctx: &Ctx) -> Result<()> {
    let uv = ctx.unlocked()?;
    let config = glyx_store::config::load();
    let mut out = Vec::new();
    for recent in config.recents(&uv.config().vault_id) {
        let Ok(Some(item)) = uv.get_item(&recent.item_id) else {
            continue;
        };
        if item.deleted {
            continue;
        }
        out.push(serde_json::json!({
            "id": item.id,
            "name": item.name,
            "type": type_label(item.item_type),
            "favorite": item.favorite,
            "folder": item.folder,
            "at_ms": recent.at_ms,
        }));
    }
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else if out.is_empty() {
        println!("no recents");
    } else {
        for row in out {
            println!(
                "{} {} {}",
                row["id"].as_str().map_or("", |id| &id[..8.min(id.len())]),
                row["type"].as_str().unwrap_or(""),
                row["name"].as_str().unwrap_or("")
            );
        }
    }
    Ok(())
}

fn cmd_library(ctx: &Ctx) -> Result<()> {
    let uv = ctx.unlocked()?;
    let library = uv.library()?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&library)?);
    } else {
        println!("tags:");
        for (tag, count) in &library.tags {
            println!("  {tag} ({count})");
        }
        println!("folders:");
        for (folder, count) in &library.folders {
            println!("  {folder} ({count})");
        }
    }
    Ok(())
}

fn cmd_tag(ctx: &Ctx, cmd: TagCmd) -> Result<()> {
    let mut uv = ctx.unlocked()?;
    let affected = match cmd {
        TagCmd::Rename { from, to } => {
            if to.trim().is_empty() {
                bail!("tag name must not be empty");
            }
            uv.rename_tag(&from, &to)?
        }
        TagCmd::Rm { tag } => uv.delete_tag(&tag)?,
    };
    if ctx.json {
        println!("{}", serde_json::json!({"ok": true, "affected": affected}));
    } else {
        println!("updated {affected} item(s)");
    }
    Ok(())
}

fn cmd_folder(ctx: &Ctx, cmd: FolderCmd) -> Result<()> {
    let mut uv = ctx.unlocked()?;
    let affected = match cmd {
        FolderCmd::Rename { from, to } => {
            if to.trim().is_empty() {
                bail!("folder name must not be empty");
            }
            uv.rename_folder(&from, &to)?
        }
        FolderCmd::Rm { folder } => uv.delete_folder(&folder)?,
    };
    if ctx.json {
        println!("{}", serde_json::json!({"ok": true, "affected": affected}));
    } else {
        println!("updated {affected} item(s)");
    }
    Ok(())
}

fn cmd_duplicates(ctx: &Ctx) -> Result<()> {
    let uv = ctx.unlocked()?;
    let groups = uv.duplicates()?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&groups)?);
    } else if groups.is_empty() {
        println!("no duplicates found");
    } else {
        for (index, group) in groups.iter().enumerate() {
            println!(
                "group {}: {}{}",
                index + 1,
                group.reason.join("+"),
                if group.same_password {
                    " (same password)"
                } else {
                    ""
                }
            );
            for item in &group.items {
                println!(
                    "  {} {} {}",
                    &item.id.as_simple().to_string()[..8],
                    item.item_type,
                    item.name
                );
            }
        }
    }
    Ok(())
}

fn bulk_targets(
    uv: &glyx_store::UnlockedVault,
    ids: &[String],
    folder: Option<&str>,
) -> Result<Vec<uuid::Uuid>> {
    let mut out = Vec::new();
    for query in ids {
        out.push(items::resolve_query(uv, query)?.id);
    }
    if let Some(folder) = folder {
        for row in uv.list(false)? {
            if row.folder == folder {
                out.push(row.id);
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    if out.is_empty() {
        bail!("no items selected; pass --id and/or --folder");
    }
    Ok(out)
}

fn cmd_bulk(ctx: &Ctx, cmd: BulkCmd) -> Result<()> {
    let mut uv = ctx.unlocked()?;
    let affected = match cmd {
        BulkCmd::Favorite { ids, folder } => {
            let targets = bulk_targets(&uv, &ids, folder.as_deref())?;
            uv.set_favorite_many(&targets, true)?
        }
        BulkCmd::Unfavorite { ids, folder } => {
            let targets = bulk_targets(&uv, &ids, folder.as_deref())?;
            uv.set_favorite_many(&targets, false)?
        }
        BulkCmd::AddTag { tag, ids, folder } => {
            if tag.trim().is_empty() {
                bail!("tag must not be empty");
            }
            let targets = bulk_targets(&uv, &ids, folder.as_deref())?;
            uv.add_tags_many(&targets, &[tag])?
        }
        BulkCmd::RemoveTag { tag, ids, folder } => {
            let targets = bulk_targets(&uv, &ids, folder.as_deref())?;
            uv.remove_tags_many(&targets, &[tag])?
        }
        BulkCmd::MoveFolder { to, ids, folder } => {
            let targets = bulk_targets(&uv, &ids, folder.as_deref())?;
            uv.set_folder_many(&targets, &to)?
        }
        BulkCmd::Delete { ids, folder, yes } => {
            if !yes {
                bail!("refusing to delete without --yes");
            }
            let targets = bulk_targets(&uv, &ids, folder.as_deref())?;
            uv.delete_many(&targets)?
        }
    };
    if ctx.json {
        println!("{}", serde_json::json!({"ok": true, "affected": affected}));
    } else {
        println!("updated {affected} item(s)");
    }
    Ok(())
}

#[allow(clippy::fn_params_excessive_bools)]
fn cmd_gen(
    ctx: &Ctx,
    length: usize,
    no_lower: bool,
    no_upper: bool,
    no_digits: bool,
    no_symbols: bool,
    allow_ambiguous: bool,
) -> Result<()> {
    let options = glyx_crypto::pass::PasswordOptions {
        length,
        lowercase: !no_lower,
        uppercase: !no_upper,
        digits: !no_digits,
        symbols: !no_symbols,
        exclude_ambiguous: !allow_ambiguous,
    };
    let password = glyx_crypto::pass::generate_with_options(options)?;
    if ctx.json {
        println!(
            "{}",
            serde_json::json!({
                "password": password,
                "length": length,
                "entropy_bits": glyx_crypto::pass::password_entropy_bits(&options)
            })
        );
    } else {
        println!("{password}");
    }
    Ok(())
}

fn read_attachment(path: &Path) -> Result<Vec<u8>> {
    let meta =
        std::fs::metadata(path).with_context(|| format!("cannot inspect {}", path.display()))?;
    if meta.len() > glyx_store::MAX_BLOB_BYTES as u64 {
        bail!("attachment exceeds the 25 MiB limit");
    }
    let data = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    if data.len() > glyx_store::MAX_BLOB_BYTES {
        bail!("attachment exceeds the 25 MiB limit");
    }
    Ok(data)
}

fn cmd_blob(ctx: &Ctx, cmd: BlobCmd) -> Result<()> {
    let uv = ctx.unlocked()?;
    match cmd {
        BlobCmd::Put { file } => {
            let data = read_attachment(&file)?;
            let addr = uv.put_blob(&data)?;
            if ctx.json {
                println!(
                    "{}",
                    serde_json::json!({"ok": true, "addr": addr, "size": data.len()})
                );
            } else {
                println!("{addr}");
            }
        }
        BlobCmd::Get { addr, out } => {
            let data = uv.get_blob(&addr)?;
            glyx_store::vault::atomic_write(&out, &data)?;
            if ctx.json {
                println!(
                    "{}",
                    serde_json::json!({"ok": true, "addr": addr, "out": out, "size": data.len()})
                );
            } else {
                println!("wrote {} bytes to {}", data.len(), out.display());
            }
        }
        BlobCmd::Ls => {
            let blobs = uv.blob_addresses()?;
            if ctx.json {
                let rows: Vec<_> = blobs
                    .iter()
                    .map(|(addr, size)| serde_json::json!({"addr": addr, "size": size}))
                    .collect();
                println!("{}", serde_json::json!({"blobs": rows}));
            } else {
                for (addr, size) in blobs {
                    println!("{addr}  {size}");
                }
            }
        }
        BlobCmd::Gc { purge } => {
            let conn = glyx_agent::ledger::open_db()?;
            let exports = glyx_agent::ledger::list_exports(&conn)?;
            let refs: std::collections::HashSet<String> =
                exports.into_iter().filter_map(|e| e.blob_addr).collect();
            let report = uv.gc_blobs(&refs, !purge)?;
            if ctx.json {
                println!("{}", serde_json::to_string(&report)?);
            } else {
                println!(
                    "existing {} orphans {} ({} bytes) purged {} ({} bytes)",
                    report.existing,
                    report.orphans,
                    report.orphan_bytes,
                    report.purged,
                    report.purged_bytes
                );
            }
        }
    }
    Ok(())
}

fn history_time(hlc: glyx_core::Hlc) -> String {
    let ms = i64::try_from(hlc.wall_ms).unwrap_or(i64::MAX);
    chrono::DateTime::from_timestamp_millis(ms).map_or_else(
        || hlc.wall_ms.to_string(),
        |d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    )
}

fn cmd_history(
    ctx: &Ctx,
    query: &str,
    show: Option<&str>,
    reveal: bool,
    compare: Option<&str>,
) -> Result<()> {
    let uv = ctx.unlocked()?;
    let item = items::resolve_query(&uv, query)?;
    if let Some(file) = show {
        let history = uv.history_item(&item.id, file)?;
        if reveal {
            cli_audit(&uv, "item_reveal", Some(item.id), Some("history"));
        }
        if ctx.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "item": glyx_store::present::item_json(&history, reveal)
                }))?
            );
        } else {
            println!("{} [rev {}]", history.name, history.rev);
            for (k, f) in &history.fields {
                let value = if items::display_value(history.item_type, k, reveal) {
                    f.value.expose().to_owned()
                } else {
                    "••••".to_owned()
                };
                println!("{k}: {value}");
            }
        }
        return Ok(());
    }
    if let Some(file) = compare {
        let history = uv.history_item(&item.id, file)?;
        let current = uv
            .get_item(&item.id)?
            .ok_or_else(|| anyhow::anyhow!("no such item"))?;
        let mut changed = Vec::new();
        if current.name != history.name {
            changed.push("name".to_owned());
        }
        if current.folder != history.folder {
            changed.push("folder".to_owned());
        }
        if current.tags != history.tags {
            changed.push("tags".to_owned());
        }
        if current.favorite != history.favorite {
            changed.push("favorite".to_owned());
        }
        let keys: std::collections::BTreeSet<_> =
            current.fields.keys().chain(history.fields.keys()).collect();
        for key in keys {
            if current.fields.get(key).map(|f| f.value.expose())
                != history.fields.get(key).map(|f| f.value.expose())
            {
                changed.push(key.clone());
            }
        }
        if ctx.json {
            println!(
                "{}",
                serde_json::json!({
                    "current_rev": current.rev,
                    "history_rev": history.rev,
                    "changed": changed
                })
            );
        } else if changed.is_empty() {
            println!("no differences");
        } else {
            println!("{}", changed.join(", "));
        }
        return Ok(());
    }
    let entries = uv.history(&item.id)?;
    if ctx.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({"id": item.id, "items": entries}))?
        );
    } else if entries.is_empty() {
        println!("no history for {}", item.name);
    } else {
        for entry in entries {
            let deleted = if entry.deleted { " [deleted]" } else { "" };
            println!(
                "rev {}  {}  {}{deleted}",
                entry.rev,
                history_time(entry.hlc),
                entry.file
            );
        }
    }
    Ok(())
}

fn cmd_restore(ctx: &Ctx, query: &str, rev: Option<u64>, file: Option<&str>) -> Result<()> {
    let mut uv = ctx.unlocked()?;
    let item = items::resolve_query(&uv, query)?;
    let file = if let Some(file) = file {
        file.to_owned()
    } else {
        let rev = rev.context("pass --rev or --file")?;
        uv.history(&item.id)?
            .into_iter()
            .find(|entry| entry.rev == rev)
            .map(|entry| entry.file)
            .with_context(|| format!("no history revision {rev}"))?
    };
    let restored = uv.restore_history(&item.id, &file)?;
    cli_audit(&uv, "item_restore", Some(restored.id), None);
    if ctx.json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "id": restored.id,
                "name": restored.name,
                "rev": restored.rev,
            })
        );
    } else {
        println!("restored {} at revision {}", restored.name, restored.rev);
    }
    Ok(())
}

fn cmd_show(ctx: &Ctx, query: &str, reveal: bool, render: bool) -> Result<()> {
    let uv = ctx.unlocked()?;
    let item = items::resolve_query(&uv, query)?;
    let _ = glyx_store::config::note_recent(uv.config().vault_id, item.id);
    if reveal {
        cli_audit(&uv, "item_reveal", Some(item.id), None);
    }
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
    attach: Option<PathBuf>,
    interactive: bool,
}

struct EditInput {
    query: String,
    rename: Option<String>,
    field: Vec<String>,
    delete_field: Vec<String>,
    body_file: Option<PathBuf>,
    attach: Option<PathBuf>,
    folder: Option<String>,
    tag: Vec<String>,
    remove_tag: Vec<String>,
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
    let mut values = items::collect_fields(
        &field_pairs,
        &input.generate,
        parsed,
        input.interactive,
        None,
    )?;
    if let Some(path) = input.attach.as_ref() {
        let data = read_attachment(path)?;
        let addr = uv.put_blob(&data)?;
        values.insert("blob".to_owned(), addr);
    }
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
    cli_audit(&uv, "item_create", Some(id), None);
    if ctx.json {
        println!("{}", serde_json::json!({"ok": true, "id": id}));
    } else {
        println!("added {id}");
    }
    Ok(())
}

fn cmd_edit(ctx: &Ctx, input: EditInput) -> Result<()> {
    let EditInput {
        query,
        rename,
        field,
        delete_field,
        body_file,
        attach,
        folder,
        tag,
        remove_tag,
        interactive,
    } = input;
    let mut uv = ctx.unlocked()?;
    let mut item = items::resolve_query(&uv, &query)?;
    let renamed = rename.is_some();
    if let Some(name) = rename {
        item.name = name;
    }
    let folder_set = folder.is_some();
    if let Some(folder) = folder {
        item.folder = folder;
    }
    for t in &tag {
        if !item.tags.contains(t) {
            item.tags.push(t.clone());
        }
    }
    for t in &remove_tag {
        item.tags.retain(|x| x != t);
    }
    let mut values = BTreeMap::new();
    for pair in &field {
        let (k, v) = items::split_field(pair)?;
        values.insert(k, v);
    }
    if let Some(path) = &body_file {
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        values.insert("body".to_owned(), body);
    }
    if let Some(path) = &attach {
        let data = read_attachment(path)?;
        let addr = uv.put_blob(&data)?;
        values.insert("blob".to_owned(), addr);
    }
    if interactive {
        items::wizard_fill(item.item_type, &mut values, Some(&item))?;
    }
    for k in &delete_field {
        item.fields.remove(k);
    }
    items::apply_fields(&mut uv, &mut item, values)?;
    let changed = !field.is_empty()
        || !delete_field.is_empty()
        || renamed
        || body_file.is_some()
        || attach.is_some()
        || interactive
        || folder_set
        || !tag.is_empty()
        || !remove_tag.is_empty();
    if changed {
        uv.put_item(&item)?;
        cli_audit(&uv, "item_edit", Some(item.id), None);
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

fn dispatch_passkey(ctx: &Ctx, cmd: PasskeyCmd) -> Result<()> {
    match cmd {
        PasskeyCmd::Ls => cmd_passkey_ls(ctx),
        PasskeyCmd::Show { query } => cmd_passkey_show(ctx, &query),
        PasskeyCmd::Rm { query } => cmd_passkey_rm(ctx, &query),
    }
}

fn resolve_passkey(uv: &glyx_store::UnlockedVault, query: &str) -> Result<glyx_core::Item> {
    if let Ok(item) = uv.resolve(query) {
        if glyx_daemon::passkey::metadata(&item).is_some() {
            return Ok(item);
        }
    }
    let mut hits = Vec::new();
    for row in uv.list(false)? {
        if let Some(item) = uv.get_item(&row.id)? {
            if let Some(meta) = glyx_daemon::passkey::metadata(&item) {
                if meta.rp_id == query || meta.user_name == query || meta.name == query {
                    hits.push(item);
                }
            }
        }
    }
    match hits.len() {
        0 => bail!("no passkey matching {query:?}"),
        1 => Ok(hits.remove(0)),
        count => bail!("{count} passkeys match {query:?}; use the item id"),
    }
}

fn cmd_passkey_ls(ctx: &Ctx) -> Result<()> {
    let uv = ctx.unlocked()?;
    let mut out = Vec::new();
    for row in uv.list(false)? {
        if let Some(item) = uv.get_item(&row.id)? {
            if let Some(meta) = glyx_daemon::passkey::metadata(&item) {
                out.push(meta);
            }
        }
    }
    out.sort_by(|a, b| a.rp_name.cmp(&b.rp_name).then_with(|| a.name.cmp(&b.name)));
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else if out.is_empty() {
        println!("no passkeys stored");
    } else {
        for item in out {
            println!(
                "{}  {}  {}  {}{}",
                item.item_id,
                item.rp_id,
                item.user_name,
                item.name,
                if item.usable { "" } else { "  [missing key]" }
            );
        }
    }
    Ok(())
}

fn cmd_passkey_show(ctx: &Ctx, query: &str) -> Result<()> {
    let uv = ctx.unlocked()?;
    let item = resolve_passkey(&uv, query)?;
    let meta = glyx_daemon::passkey::metadata(&item).context("item is not a passkey")?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&meta)?);
    } else {
        println!("{} [passkey]", meta.name);
        println!("id: {}", meta.item_id);
        println!("relying_party: {}", meta.rp_id);
        println!("rp_name: {}", meta.rp_name);
        println!("user_name: {}", meta.user_name);
        println!("display_name: {}", meta.display_name);
        println!("credential_id: {}", meta.credential_id);
        println!("algorithm: {}", meta.algorithm);
        println!("sign_count: {}", meta.sign_count);
        println!("aaguid: {}", meta.aaguid);
        println!("transports: {}", meta.transports);
        println!("discoverable: {}", meta.discoverable);
        println!("backup_eligible: {}", meta.backup_eligible);
        println!("backup_state: {}", meta.backup_state);
        println!("created_ms: {}", meta.created_ms);
        println!("last_used_ms: {}", meta.last_used_ms);
        println!("usable: {}", meta.usable);
    }
    Ok(())
}

fn cmd_passkey_rm(ctx: &Ctx, query: &str) -> Result<()> {
    let mut uv = ctx.unlocked()?;
    let item = resolve_passkey(&uv, query)?;
    let id = item.id;
    uv.delete_item(&id)?;
    cli_audit(&uv, "item_delete", Some(id), None);
    if ctx.json {
        println!("{}", serde_json::json!({"ok": true, "id": id}));
    } else {
        println!("deleted {id} (tombstone kept for sync)");
    }
    Ok(())
}

fn cmd_rm(ctx: &Ctx, query: &str) -> Result<()> {
    let mut uv = ctx.unlocked()?;
    let item = items::resolve_query(&uv, query)?;
    let id = item.id;
    uv.delete_item(&id)?;
    cli_audit(&uv, "item_delete", Some(id), None);
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
    cli_audit(&uv, "totp", Some(item.id), None);
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
                    "favorite": r.favorite,
                    "folder": r.folder,
                    "tags": r.tags,
                    "updated_ms": r.updated_ms,
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

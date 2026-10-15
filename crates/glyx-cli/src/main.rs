mod auth;
mod items;

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
    cmd: Cmd,
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
    #[command(about = "SSH key operations")]
    Ssh {
        #[command(subcommand)]
        cmd: SshCmd,
    },
    #[command(about = "Vault sync state")]
    SyncStatus,
    #[command(about = "Check vault health")]
    Doctor {
        #[arg(long, help = "Rebuild the SQLite index from envelope headers")]
        rebuild_index: bool,
        #[arg(long, help = "Also unlock and decrypt every item and blob")]
        with_unlock: bool,
    },
}

#[derive(Debug, Subcommand)]
enum VaultCmd {
    #[command(about = "Create a fresh vault directory")]
    Init {
        #[arg(help = "New vault directory (must not exist)")]
        path: PathBuf,
        #[arg(long, value_enum, default_value = "balanced", help = "Cost preset")]
        preset: Preset,
        #[arg(long, value_enum, default_value = "xchacha", help = "Payload cipher")]
        cipher: CipherOpt,
        #[arg(long, help = "Keyfile path; generated when missing")]
        keyfile: PathBuf,
    },
    #[command(about = "Rotate password, keyfile, KDF params, or cipher")]
    Rekey {
        #[arg(long, help = "New keyfile path; generated when missing")]
        new_keyfile: Option<PathBuf>,
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
    dispatch(&ctx, cmd)
}

fn dispatch(ctx: &Ctx, cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Vault { cmd } => match cmd {
            VaultCmd::Init {
                path,
                preset,
                cipher,
                keyfile,
            } => vault_init(ctx, &path, preset, cipher, &keyfile),
            VaultCmd::Rekey {
                new_keyfile,
                new_password_env,
                cipher,
                preset,
                keep_old_slots,
            } => vault_rekey(
                ctx,
                new_keyfile.as_ref(),
                new_password_env.as_deref(),
                cipher,
                preset,
                keep_old_slots,
            ),
        },
        Cmd::Unlock { ttl, with_pin } => cmd_unlock(ctx, ttl, with_pin),
        Cmd::Lock => cmd_lock(ctx),
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
        Cmd::Show { query, reveal } => cmd_show(ctx, &query, reveal),
        Cmd::Add {
            item_type,
            name,
            folder,
            tag,
            field,
            generate,
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
                interactive,
            },
        ),
        Cmd::Edit {
            query,
            rename,
            field,
            delete_field,
            interactive,
        } => cmd_edit(ctx, &query, rename, &field, &delete_field, interactive),
        Cmd::Rm { query } => cmd_rm(ctx, &query),
        Cmd::Totp { query } => cmd_totp(ctx, &query),
        Cmd::Ssh { cmd } => match cmd {
            SshCmd::Gen {
                name,
                kind,
                comment,
                folder,
            } => cmd_ssh_gen(ctx, name, kind, comment, folder),
        },
        Cmd::SyncStatus => cmd_sync_status(ctx),
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
    }
}

fn vault_init(
    ctx: &Ctx,
    path: &Path,
    preset: Preset,
    cipher: CipherOpt,
    keyfile: &Path,
) -> Result<()> {
    let password = auth::read_password(ctx.password_env.as_deref())?;
    let kf = auth::load_or_create_keyfile(keyfile)?;
    let suite = glyx_core::CipherSuiteConfig {
        kdf: glyx_core::KdfId::Argon2id,
        cipher: cipher_of(cipher),
        params: preset_params(preset),
    };
    let vault = glyx_store::Vault::init(path, suite, &password, &kf)?;
    if ctx.json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "vault_id": vault.config().vault_id,
                "path": path,
            })
        );
    } else {
        println!("vault created: {}", path.display());
        println!("vault id: {}", vault.config().vault_id);
    }
    Ok(())
}

fn vault_rekey(
    ctx: &Ctx,
    new_keyfile: Option<&PathBuf>,
    new_password_env: Option<&str>,
    cipher: Option<CipherOpt>,
    preset: Option<Preset>,
    keep_old_slots: bool,
) -> Result<()> {
    let vault_path = ctx.vault_path()?;
    let vault = glyx_store::Vault::open(&vault_path)?;
    let mut uv = auth::full_unlock(&vault, ctx.keyfile.as_deref(), ctx.password_env.as_deref())?;
    let old_slots: Vec<Uuid> = uv.list_slots()?.into_iter().map(|(id, _)| id).collect();
    if new_keyfile.is_none() && new_password_env.is_none() && cipher.is_none() && preset.is_none() {
        bail!("nothing to rotate: pass --new-keyfile, --new-password-env, --cipher, or --preset");
    }
    let rotated = new_keyfile.is_some() || new_password_env.is_some();
    if rotated {
        let kf_path = new_keyfile.context("--new-keyfile is required to rotate credentials")?;
        let new_kf = auth::load_or_create_keyfile(kf_path)?;
        let new_pw = auth::read_password(new_password_env)?;
        let params = preset.map_or(vault.config().cipher_suite.params, preset_params);
        let id = uv.add_slot_with_params(&new_pw, &new_kf, params)?;
        if !vault.verify_slot(&id, &new_pw, &new_kf)? {
            bail!("new keyslot failed verification");
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
    let uv = auth::full_unlock(&vault, ctx.keyfile.as_deref(), ctx.password_env.as_deref())?;
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
    }
    Ok(())
}

fn cmd_lock(ctx: &Ctx) -> Result<()> {
    let n = match ctx.vault.as_ref() {
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

fn cmd_show(ctx: &Ctx, query: &str, reveal: bool) -> Result<()> {
    let uv = ctx.unlocked()?;
    let item = items::resolve_query(&uv, query)?;
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
    interactive: bool,
}

fn cmd_add(ctx: &Ctx, input: AddInput) -> Result<()> {
    let mut uv = ctx.unlocked()?;
    let parsed =
        glyx_core::template::parse_type(&input.item_type).map_err(|e| anyhow::anyhow!(e))?;
    let values = items::collect_fields(
        &input.field,
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
    if ctx.json {
        println!(
            "{}",
            serde_json::json!({
                "envelopes": headers.len(),
                "live": live,
                "tombstones": headers.len() - live,
                "max_rev": max_rev,
            })
        );
    } else {
        println!("envelopes: {}", headers.len());
        println!("live: {live}, tombstones: {}", headers.len() - live);
        println!("max rev: {max_rev}");
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
        let kf_path = keyfile.context("--keyfile is required with --with-unlock")?;
        let kf = auth::read_keyfile(kf_path)?;
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
    if as_json {
        println!("{report}");
    } else {
        println!("vault ok: {}", path.display());
        println!("format: v{}", vault.config().format_version);
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

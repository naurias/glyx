use std::path::PathBuf;

use anyhow::{Context, Result};

pub struct ExportAdd {
    pub target: PathBuf,
    pub item: Option<String>,
    pub field: Option<String>,
    pub blob: Option<String>,
    pub ssh: Option<String>,
    pub keep: bool,
    pub perm: Option<u32>,
}

pub fn cmd_add(input: ExportAdd, uv: &glyx_store::UnlockedVault, as_json: bool) -> Result<()> {
    let conn = glyx_agent::ledger::open_db()?;
    let (kind, item_id, field_out, blob_out) = if let Some(query) = input.ssh {
        let found = uv.resolve(&query).map_err(|e| anyhow::anyhow!(e))?;
        ("ssh", Some(found.id), None, None)
    } else if let Some(addr) = input.blob {
        ("blob", None, None, Some(addr))
    } else if let Some(query) = input.item {
        let found = uv.resolve(&query).map_err(|e| anyhow::anyhow!(e))?;
        (
            "field",
            Some(found.id),
            Some(input.field.unwrap_or_else(|| "password".to_owned())),
            None,
        )
    } else {
        anyhow::bail!("pass --item, --blob, or --ssh");
    };
    let id = glyx_agent::ledger::register_export(
        &conn,
        &glyx_agent::ledger::ExportSpec {
            target: &input.target,
            kind,
            item_id,
            field: field_out.as_deref(),
            blob_addr: blob_out.as_deref(),
            keep_on_lock: input.keep,
            perm: input.perm.unwrap_or(0o600),
        },
    )?;
    if as_json {
        println!("{}", serde_json::json!({"ok": true, "id": id}));
    } else {
        println!(
            "export registered: {} (keep on lock: {})",
            input.target.display(),
            input.keep
        );
    }
    Ok(())
}

pub fn cmd_ls(as_json: bool) -> Result<()> {
    let conn = glyx_agent::ledger::open_db()?;
    let exports = glyx_agent::ledger::list_exports(&conn)?;
    let injects = glyx_agent::ledger::list_injects(&conn)?;
    if as_json {
        println!(
            "{}",
            serde_json::json!({
                "exports": exports.iter().map(|e| serde_json::json!({
                    "target": e.target, "kind": e.kind, "keep": e.keep_on_lock,
                })).collect::<Vec<_>>(),
                "injects": injects.iter().map(|i| serde_json::json!({
                    "target": i.target, "form": i.form,
                })).collect::<Vec<_>>(),
            })
        );
    } else {
        for e in &exports {
            let keep = if e.keep_on_lock { "keep" } else { "wipe" };
            println!("{} [{}] {} ({keep})", e.target.display(), e.kind, e.id);
        }
        for i in &injects {
            println!("{} [inject:{}]", i.target.display(), i.form);
        }
        if exports.is_empty() && injects.is_empty() {
            println!("no exports registered");
        }
    }
    Ok(())
}

pub fn cmd_recall(target: &std::path::Path, as_json: bool) -> Result<()> {
    let removed = glyx_agent::recall_target(target)?;
    if as_json {
        println!("{}", serde_json::json!({"ok": true, "removed": removed}));
    } else if removed {
        println!("recalled {}", target.display());
    } else {
        println!("nothing tracked at {}", target.display());
    }
    Ok(())
}

pub fn cmd_enforce(uv: &mut glyx_store::UnlockedVault, force: bool, as_json: bool) -> Result<()> {
    let rep = glyx_agent::enforce_all(uv, force).map_err(|e| anyhow::anyhow!(e))?;
    if as_json {
        println!(
            "{}",
            serde_json::json!({"files": rep.files, "injected": rep.injected, "skipped": rep.skipped})
        );
    } else {
        println!(
            "materialized {} file(s), {} injection(s)",
            rep.files, rep.injected
        );
        for s in &rep.skipped {
            println!("skipped: {s} (use --force)");
        }
    }
    Ok(())
}

pub fn cmd_tamper(vault: Option<&PathBuf>, as_json: bool) -> Result<()> {
    let locked = match vault {
        Some(path) => match glyx_store::Vault::open(path) {
            Ok(v) => v.open_session(None)?.is_none(),
            Err(_) => true,
        },
        None => true,
    };
    let conn = glyx_agent::ledger::open_db()?;
    let found = glyx_agent::engine::check_all(&conn, locked).map_err(|e| anyhow::anyhow!(e))?;
    if as_json {
        println!(
            "{}",
            serde_json::Value::Array(
                found
                    .iter()
                    .map(|t| serde_json::json!({
                        "target": t.target,
                        "kind": format!("{:?}", t.kind),
                        "detail": t.detail,
                    }))
                    .collect()
            )
        );
    } else {
        for t in &found {
            println!("{:?}: {} ({})", t.kind, t.target, t.detail);
        }
        if found.is_empty() {
            println!("no tamper detected");
        }
    }
    Ok(())
}

pub fn cmd_inject_add(target: &std::path::Path, form: &str, as_json: bool) -> Result<()> {
    let conn = glyx_agent::ledger::open_db()?;
    glyx_agent::ledger::register_inject(&conn, target, form)?;
    if as_json {
        println!("{}", serde_json::json!({"ok": true}));
    } else {
        println!("tracking {} (locked form: {form})", target.display());
    }
    Ok(())
}

pub fn cmd_ssh_export(
    uv: &mut glyx_store::UnlockedVault,
    query: &str,
    to: Option<PathBuf>,
    as_json: bool,
) -> Result<()> {
    let item = uv.resolve(query).map_err(|e| anyhow::anyhow!(e))?;
    let target = to.unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());
        PathBuf::from(home)
            .join(".ssh")
            .join(format!("glyx_{}", item.name))
    });
    let conn = glyx_agent::ledger::open_db()?;
    glyx_agent::ledger::register_export(
        &conn,
        &glyx_agent::ledger::ExportSpec {
            target: &target,
            kind: "ssh",
            item_id: Some(item.id),
            field: None,
            blob_addr: None,
            keep_on_lock: false,
            perm: 0o600,
        },
    )?;
    glyx_agent::engine::materialize_all(uv, false).map_err(|e| anyhow::anyhow!(e))?;
    if as_json {
        println!("{}", serde_json::json!({"ok": true, "target": target}));
    } else {
        println!("ssh key at {}", target.display());
    }
    Ok(())
}

pub fn cmd_agent_env(as_json: bool) -> Result<()> {
    let sock =
        glyx_agent::ssh_agent::live_socket().context("no agent socket: unlock the daemon first")?;
    if as_json {
        println!("{}", serde_json::json!({"SSH_AUTH_SOCK": sock}));
    } else {
        println!("export SSH_AUTH_SOCK={}", sock.display());
    }
    Ok(())
}

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};

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
    let roots = glyx_agent::ledger::list_inject_roots(&conn)?;
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
                "roots": roots.iter().map(|r| serde_json::json!({
                    "root": r.root, "glob": r.glob, "form": r.form,
                })).collect::<Vec<_>>(),
            })
        );
    } else {
        for r in &roots {
            println!("{} [folder:{}] {}", r.root.display(), r.glob, r.form);
        }
        for e in &exports {
            let keep = if e.keep_on_lock { "keep" } else { "wipe" };
            println!("{} [{}] {} ({keep})", e.target.display(), e.kind, e.id);
        }
        for i in &injects {
            println!("{} [inject:{}]", i.target.display(), i.form);
        }
        if exports.is_empty() && injects.is_empty() && roots.is_empty() {
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
            serde_json::json!({
                "files": rep.files, "injected": rep.injected,
                "scanned": rep.scanned, "skipped": rep.skipped,
            })
        );
    } else {
        println!(
            "materialized {} file(s), {} injection(s) from {} scanned file(s)",
            rep.files, rep.injected, rep.scanned
        );
        for s in &rep.skipped {
            println!("skipped: {s} (use --force)");
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub struct MergeOpts {
    pub theirs: bool,
    pub ours: bool,
    pub interactive: bool,
}

pub fn cmd_merge(
    uv: &glyx_store::UnlockedVault,
    target: &std::path::Path,
    opts: MergeOpts,
    pick: &[String],
    as_json: bool,
) -> Result<()> {
    use std::collections::BTreeMap;
    let preview = glyx_agent::engine::preview_merge(uv, target).map_err(|e| anyhow::anyhow!(e))?;
    let conflicts = glyx_agent::merge::conflict_indexes(&preview.hunks);
    if conflicts.is_empty() {
        let merged = glyx_agent::engine::apply_merge(uv, target, &BTreeMap::new())
            .map_err(|e| anyhow::anyhow!(e))?;
        if as_json {
            println!("{}", serde_json::json!({"ok": true, "conflicts": 0}));
        } else {
            println!(
                "merged {} ({} bytes, no conflicts)",
                target.display(),
                merged.len()
            );
        }
        return Ok(());
    }
    let mut picks = BTreeMap::new();
    if opts.theirs {
        for idx in &conflicts {
            picks.insert(*idx, glyx_agent::merge::Pick::Theirs);
        }
    } else if opts.ours {
        for idx in &conflicts {
            picks.insert(*idx, glyx_agent::merge::Pick::Ours);
        }
    }
    for spec in pick {
        let (idx, choice) = spec
            .split_once(':')
            .context("pick looks like N:theirs|ours")?;
        let idx: usize = idx.parse().context("pick index must be a number")?;
        if !conflicts.contains(&idx) {
            bail!("hunk {idx} is not a conflict");
        }
        picks.insert(
            idx,
            match choice {
                "theirs" => glyx_agent::merge::Pick::Theirs,
                "ours" => glyx_agent::merge::Pick::Ours,
                custom => glyx_agent::merge::Pick::Custom(custom.to_owned()),
            },
        );
    }
    if picks.len() < conflicts.len() {
        if !opts.interactive {
            bail!(
                "{} conflict(s) need picks ({}); pass --theirs, --ours, --pick, or --interactive",
                conflicts.len(),
                conflicts
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
        walkthrough(&preview, &conflicts, &mut picks)?;
    }
    let merged =
        glyx_agent::engine::apply_merge(uv, target, &picks).map_err(|e| anyhow::anyhow!(e))?;
    if as_json {
        println!(
            "{}",
            serde_json::json!({"ok": true, "conflicts": conflicts.len(), "bytes": merged.len()})
        );
    } else {
        println!(
            "merged {} ({} conflict(s) resolved)",
            target.display(),
            conflicts.len()
        );
    }
    Ok(())
}

fn walkthrough(
    preview: &glyx_agent::engine::MergePreview,
    conflicts: &[usize],
    picks: &mut BTreeMap<usize, glyx_agent::merge::Pick>,
) -> Result<()> {
    use std::io::IsTerminal as _;
    if !std::io::stdin().is_terminal() {
        bail!("no TTY: pass --theirs, --ours, or --pick");
    }
    println!(
        "{} conflict(s) in {}",
        conflicts.len(),
        preview.target.display()
    );
    for idx in conflicts {
        if picks.contains_key(idx) {
            continue;
        }
        let hunk = &preview.hunks[*idx];
        println!(
            "--- hunk {idx}{} ---",
            if hunk.secret { " [secret]" } else { "" }
        );
        for line in &hunk.base {
            println!("  base   | {line}");
        }
        for line in &hunk.theirs {
            println!("  theirs | {line}");
        }
        for line in &hunk.ours {
            println!("  ours   | {line}");
        }
        let choice = inquire::Select::new("resolve", vec!["theirs", "ours", "custom", "quit"])
            .prompt()
            .map_err(|e| anyhow::anyhow!(e))?;
        match choice {
            "theirs" => {
                picks.insert(*idx, glyx_agent::merge::Pick::Theirs);
            }
            "ours" => {
                picks.insert(*idx, glyx_agent::merge::Pick::Ours);
            }
            "custom" => {
                let text = inquire::Text::new("replacement lines (\\n separated)")
                    .prompt()
                    .map_err(|e| anyhow::anyhow!(e))?;
                picks.insert(
                    *idx,
                    glyx_agent::merge::Pick::Custom(text.replace("\\n", "\n")),
                );
            }
            _ => bail!("aborted, file untouched"),
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

pub fn cmd_inject_add(
    target: &std::path::Path,
    form: &str,
    glob: Option<&str>,
    as_json: bool,
) -> Result<()> {
    let conn = glyx_agent::ledger::open_db()?;
    if target.is_dir() {
        let glob = glob.unwrap_or("*.md");
        let form = if form == "encrypted-pointer" {
            "ref"
        } else {
            form
        };
        glyx_agent::ledger::register_inject_root(&conn, target, glob, form)?;
        let rep = glyx_agent::ledger::expand_inject_roots(&conn)?;
        if as_json {
            println!(
                "{}",
                serde_json::json!({
                    "ok": true, "root": target, "glob": glob, "files": rep.files,
                })
            );
        } else {
            println!(
                "tracking folder {} ({glob}, {} file(s), locked form: {form})",
                target.display(),
                rep.files
            );
        }
        return Ok(());
    }
    glyx_agent::ledger::register_inject(&conn, target, form, None)?;
    if as_json {
        println!("{}", serde_json::json!({"ok": true}));
    } else {
        println!("tracking {} (locked form: {form})", target.display());
    }
    Ok(())
}

pub fn cmd_inject_scan(as_json: bool) -> Result<()> {
    let rep = glyx_agent::scan_inject_roots().map_err(|e| anyhow::anyhow!(e))?;
    if as_json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true, "roots": rep.roots, "files": rep.files,
                "removed": rep.removed, "skipped": rep.skipped,
            })
        );
    } else {
        println!(
            "scanned {} root(s): {} file(s), {} removed, {} skipped",
            rep.roots, rep.files, rep.removed, rep.skipped
        );
    }
    Ok(())
}

pub fn cmd_inject_rm(target: &std::path::Path, as_json: bool) -> Result<()> {
    let conn = glyx_agent::ledger::open_db()?;
    let removed = if target.is_dir() {
        glyx_agent::ledger::forget_inject_root(&conn, target)?
    } else {
        glyx_agent::forget_target(target)?
    };
    if as_json {
        println!("{}", serde_json::json!({"ok": true, "removed": removed}));
    } else if removed {
        println!("forgot {}", target.display());
    } else {
        println!("nothing tracked at {}", target.display());
    }
    Ok(())
}

pub fn cmd_target_unlock(
    uv: &mut glyx_store::UnlockedVault,
    target: &std::path::Path,
    force: bool,
    as_json: bool,
) -> Result<()> {
    let rep = glyx_agent::materialize_target(uv, target, force).map_err(|e| anyhow::anyhow!(e))?;
    if as_json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true, "files": rep.files, "injected": rep.injected,
                "scanned": rep.scanned, "skipped": rep.skipped,
            })
        );
    } else {
        println!(
            "unlocked {} ({} file(s), {} injection(s))",
            target.display(),
            rep.files,
            rep.injected
        );
        for s in &rep.skipped {
            println!("skipped: {s} (use --force)");
        }
    }
    Ok(())
}

pub fn cmd_target_lock(
    uv: &glyx_store::UnlockedVault,
    target: &std::path::Path,
    as_json: bool,
) -> Result<()> {
    let rep = glyx_agent::teardown_targets(uv, Some(target)).map_err(|e| anyhow::anyhow!(e))?;
    if as_json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true, "wiped": rep.wiped, "restored": rep.restored, "drifted": rep.drifted,
            })
        );
    } else {
        println!(
            "locked {} (wiped {}, restored {})",
            target.display(),
            rep.wiped,
            rep.restored
        );
        for d in &rep.drifted {
            println!("drifted: {d}");
        }
    }
    Ok(())
}

pub fn cmd_target_move(
    uv: &glyx_store::UnlockedVault,
    old: &std::path::Path,
    new: &std::path::Path,
    as_json: bool,
) -> Result<()> {
    let rep = glyx_agent::relocate_target(uv, old, new).map_err(|e| anyhow::anyhow!(e))?;
    if as_json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true, "exports": rep.exports, "roots": rep.roots, "injects": rep.injects,
            })
        );
    } else {
        println!(
            "moved {} -> {} ({} export(s), {} root(s), {} inject(s))",
            old.display(),
            new.display(),
            rep.exports,
            rep.roots,
            rep.injects
        );
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

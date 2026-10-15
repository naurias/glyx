use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use uuid::Uuid;

pub fn resolve_query(uv: &glyx_store::UnlockedVault, query: &str) -> Result<glyx_core::Item> {
    if let Ok(id) = query.parse::<Uuid>() {
        if let Some(item) = uv.get_item(&id)? {
            return Ok(item);
        }
        bail!("no item with id {id}");
    }
    let rows = uv.list(true)?;
    let mut live_rows = Vec::new();
    let mut dead = 0;
    for row in &rows {
        if row.deleted {
            dead += 1;
        } else {
            live_rows.push(row);
        }
    }
    let mut hits = Vec::new();
    for row in &live_rows {
        if row.id.as_simple().to_string().starts_with(query) {
            hits.push(row.id);
        }
    }
    if hits.len() == 1 {
        return uv.get_item(&hits[0])?.context("item vanished");
    }
    if hits.len() > 1 {
        bail!("ambiguous id prefix, matches {} items", hits.len());
    }
    let mut named = Vec::new();
    for row in &live_rows {
        if row.name == query {
            named.push(row.id);
        }
    }
    if named.len() == 1 {
        return uv.get_item(&named[0])?.context("item vanished");
    }
    if named.is_empty() {
        if dead > 0 {
            bail!("no live item matching {query:?} ({dead} deleted)");
        }
        bail!("no item matching {query:?}");
    }
    bail!("ambiguous name, matches {} items; use an id", named.len());
}

pub fn display_value(item_type: glyx_core::ItemType, key: &str, reveal: bool) -> bool {
    if reveal {
        return true;
    }
    !glyx_core::template::spec(item_type)
        .iter()
        .any(|s| s.name == key && s.secret)
}

pub fn item_json(item: &glyx_core::Item, reveal: bool) -> serde_json::Value {
    let mut fields = serde_json::Map::new();
    for (k, f) in &item.fields {
        let show = display_value(item.item_type, k, reveal);
        fields.insert(
            k.clone(),
            serde_json::Value::String(if show {
                f.value.expose().to_owned()
            } else {
                "••••".to_owned()
            }),
        );
    }
    serde_json::json!({
        "id": item.id,
        "type": item.item_type,
        "name": item.name,
        "folder": item.folder,
        "tags": item.tags,
        "fields": fields,
        "rev": item.rev,
        "deleted": item.deleted,
    })
}

pub fn split_field(pair: &str) -> Result<(String, String)> {
    let (k, v) = pair
        .split_once('=')
        .context("--field must look like key=value")?;
    if k.trim().is_empty() {
        bail!("--field key must not be empty");
    }
    Ok((k.trim().to_owned(), v.to_owned()))
}

pub fn split_generate(spec: &str) -> Result<(String, usize)> {
    match spec.split_once(':') {
        Some((name, len)) => Ok((
            name.trim().to_owned(),
            len.parse().context("--generate length must be a number")?,
        )),
        None => Ok((spec.trim().to_owned(), 24)),
    }
}

pub fn collect_fields(
    pairs: &[String],
    generates: &[String],
    item_type: glyx_core::ItemType,
    interactive: bool,
    existing: Option<&glyx_core::Item>,
) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for pair in pairs {
        let (k, v) = split_field(pair)?;
        out.insert(k, v);
    }
    for spec in generates {
        let (name, len) = split_generate(spec)?;
        out.insert(
            name,
            glyx_crypto::pass::generate_password(len).map_err(|e| anyhow::anyhow!(e))?,
        );
    }
    if interactive {
        wizard_fill(item_type, &mut out, existing)?;
    }
    for field in glyx_core::template::spec(item_type) {
        if field.required && !out.contains_key(field.name) {
            if let Some(item) = existing {
                if item.fields.contains_key(field.name) {
                    continue;
                }
            }
            bail!("missing required field {}", field.name);
        }
    }
    Ok(out)
}

pub fn wizard_fill(
    item_type: glyx_core::ItemType,
    out: &mut BTreeMap<String, String>,
    existing: Option<&glyx_core::Item>,
) -> Result<()> {
    for field in glyx_core::template::spec(item_type) {
        if out.contains_key(field.name) {
            continue;
        }
        let current = existing.and_then(|item| item.fields.get(field.name));
        if current.is_some()
            && !inquire::Confirm::new(&format!("change {}?", field.name))
                .with_default(false)
                .prompt()
                .map_err(|e| anyhow::anyhow!(e))?
        {
            continue;
        }
        if field.secret {
            let make = inquire::Confirm::new(&format!("generate {}?", field.name))
                .with_default(true)
                .prompt()
                .map_err(|e| anyhow::anyhow!(e))?;
            if make {
                out.insert(
                    field.name.to_owned(),
                    glyx_crypto::pass::generate_password(24)?,
                );
                continue;
            }
            let value = inquire::Password::new(field.name)
                .without_confirmation()
                .with_display_mode(inquire::PasswordDisplayMode::Masked)
                .prompt()
                .map_err(|e| anyhow::anyhow!(e))?;
            out.insert(field.name.to_owned(), value);
        } else {
            let default = current
                .map(|f| f.value.expose().to_owned())
                .unwrap_or_default();
            let mut prompt = inquire::Text::new(field.name);
            if !default.is_empty() {
                prompt = prompt.with_default(&default);
            }
            let value = prompt.prompt().map_err(|e| anyhow::anyhow!(e))?;
            if !value.is_empty() || field.required {
                out.insert(field.name.to_owned(), value);
            }
        }
    }
    Ok(())
}

pub fn build_new(
    uv: &mut glyx_store::UnlockedVault,
    item_type: glyx_core::ItemType,
    name: String,
    folder: String,
    tags: Vec<String>,
    values: BTreeMap<String, String>,
) -> Result<glyx_core::Item> {
    let hlc = uv.next_hlc()?;
    let node = uv.device_node();
    let mut fields = BTreeMap::new();
    for (k, v) in values {
        fields.insert(
            k,
            glyx_core::Field {
                value: glyx_core::SecretString::new(v),
                field_hlc: hlc,
            },
        );
    }
    let item = glyx_core::Item {
        id: uuid::Uuid::now_v7(),
        item_type,
        name,
        folder,
        tags,
        fields,
        hlc,
        rev: 1,
        deleted: false,
        updated_by: node,
    };
    item.validate().map_err(|e| anyhow::anyhow!(e))?;
    Ok(item)
}

pub fn apply_fields(
    uv: &mut glyx_store::UnlockedVault,
    item: &mut glyx_core::Item,
    values: BTreeMap<String, String>,
) -> Result<()> {
    let hlc = uv.next_hlc()?;
    for (k, v) in values {
        item.fields.insert(
            k,
            glyx_core::Field {
                value: glyx_core::SecretString::new(v),
                field_hlc: hlc,
            },
        );
    }
    item.hlc = hlc;
    item.rev = item.rev.saturating_add(1);
    item.updated_by = uv.device_node();
    Ok(())
}

pub fn totp_params(item: &glyx_core::Item) -> Result<glyx_crypto::TotpParams> {
    let to_anyhow = |e: glyx_crypto::CryptoError| anyhow::anyhow!(e);
    let seed_field = item
        .fields
        .get("seed")
        .context("totp item has no seed field")?;
    let raw = seed_field.value.expose().trim();
    if let Some(uri) = raw.strip_prefix("otpauth://") {
        let full = format!("otpauth://{uri}");
        return glyx_crypto::totp::params_from_uri(&full).map_err(to_anyhow);
    }
    if raw.contains('?') || raw.contains("secret=") {
        return glyx_crypto::totp::params_from_uri(raw).map_err(to_anyhow);
    }
    let step = item
        .fields
        .get("period")
        .map_or(30, |f| f.value.expose().trim().parse().unwrap_or(30));
    let digits = item
        .fields
        .get("digits")
        .map_or(6, |f| f.value.expose().trim().parse().unwrap_or(6));
    Ok(glyx_crypto::TotpParams {
        seed: glyx_crypto::totp::seed_from_b32(raw).map_err(to_anyhow)?,
        step,
        digits,
    })
}

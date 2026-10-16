use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};

pub fn resolve_query(uv: &glyx_store::UnlockedVault, query: &str) -> Result<glyx_core::Item> {
    uv.resolve(query).map_err(|e| anyhow::anyhow!(e))
}

pub fn display_value(item_type: glyx_core::ItemType, key: &str, reveal: bool) -> bool {
    glyx_store::present::display_value(item_type, key, reveal)
}

pub fn item_json(item: &glyx_core::Item, reveal: bool) -> serde_json::Value {
    glyx_store::present::item_json(item, reveal)
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
                    glyx_crypto::pass::generate_password(24).map_err(|e| anyhow::anyhow!(e))?,
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
    glyx_store::present::build_new(uv, item_type, name, folder, tags, values)
        .map_err(|e| anyhow::anyhow!(e))
}

pub fn apply_fields(
    uv: &mut glyx_store::UnlockedVault,
    item: &mut glyx_core::Item,
    values: BTreeMap<String, String>,
) -> Result<()> {
    glyx_store::present::apply_fields(uv, item, values).map_err(|e| anyhow::anyhow!(e))
}

pub fn totp_params(item: &glyx_core::Item) -> Result<glyx_crypto::TotpParams> {
    glyx_store::present::totp_params(item).map_err(|e| anyhow::anyhow!(e))
}

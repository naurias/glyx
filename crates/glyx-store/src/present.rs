use std::collections::BTreeMap;
use std::fmt::Write as _;

use uuid::Uuid;

use crate::{StoreError, UnlockedVault};

#[must_use]
pub fn display_value(item_type: glyx_core::ItemType, key: &str, reveal: bool) -> bool {
    if reveal {
        return true;
    }
    !glyx_core::template::spec(item_type)
        .iter()
        .any(|s| s.name == key && s.secret)
}

#[must_use]
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
        "favorite": item.favorite,
        "fields": fields,
        "rev": item.rev,
        "deleted": item.deleted,
    })
}

pub fn build_new(
    uv: &mut UnlockedVault,
    item_type: glyx_core::ItemType,
    name: String,
    folder: String,
    tags: Vec<String>,
    values: BTreeMap<String, String>,
) -> Result<glyx_core::Item, StoreError> {
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
        favorite: false,
        fields,
        hlc,
        rev: 1,
        deleted: false,
        updated_by: node,
    };
    item.validate()?;
    Ok(item)
}

pub fn totp_params(item: &glyx_core::Item) -> Result<glyx_crypto::TotpParams, StoreError> {
    let bad = |why: &str| StoreError::Corrupt(format!("totp item: {why}"));
    let seed_field = item
        .fields
        .get("seed")
        .ok_or_else(|| bad("no seed field"))?;
    let raw = seed_field.value.expose().trim();
    if let Some(uri) = raw.strip_prefix("otpauth://") {
        let full = format!("otpauth://{uri}");
        return glyx_crypto::totp::params_from_uri(&full).map_err(|e| bad(&e.to_string()));
    }
    if raw.contains('?') || raw.contains("secret=") {
        return glyx_crypto::totp::params_from_uri(raw).map_err(|e| bad(&e.to_string()));
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
        seed: glyx_crypto::totp::seed_from_b32(raw).map_err(|e| bad(&e.to_string()))?,
        step,
        digits,
    })
}

pub fn apply_fields(
    uv: &mut UnlockedVault,
    item: &mut glyx_core::Item,
    values: BTreeMap<String, String>,
) -> Result<(), StoreError> {
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

pub fn note_rendered(
    uv: &UnlockedVault,
    item: &glyx_core::Item,
    reveal: bool,
) -> Result<String, StoreError> {
    let body = item.fields.get("body").map_or("", |f| f.value.expose());
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(start) = rest.find("{{glyx:") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 7..];
        let Some(end) = after.find("}}") else {
            out.push_str(&rest[start..]);
            return Ok(out);
        };
        let inner = &after[..end];
        let token_end = start + 7 + end + 2;
        match inner.split_once('/') {
            Some((id, field)) if !field.is_empty() && !field.contains(['}', '{', ' ', '\n']) => {
                match id.parse::<Uuid>() {
                    Ok(uuid) => match uv.get_item(&uuid)? {
                        Some(target) => match target.fields.get(field) {
                            Some(f) if display_value(target.item_type, field, reveal) => {
                                out.push_str(f.value.expose());
                            }
                            Some(_) => out.push_str("\u{2022}\u{2022}\u{2022}\u{2022}"),
                            None => {
                                let _ = write!(out, "[missing {id}/{field}]");
                            }
                        },
                        None => {
                            let _ = write!(out, "[missing {id}/{field}]");
                        }
                    },
                    Err(_) => out.push_str(&rest[start..token_end]),
                }
            }
            _ => out.push_str(&rest[start..token_end]),
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

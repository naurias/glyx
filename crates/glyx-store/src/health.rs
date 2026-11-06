use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{StoreError, UnlockedVault};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthSummary {
    pub items: usize,
    pub weak: usize,
    pub reused: usize,
    pub old: usize,
    pub no_totp: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthIssue {
    pub id: Uuid,
    pub name: String,
    pub item_type: String,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthReport {
    pub generated_ms: u64,
    pub summary: HealthSummary,
    pub issues: Vec<HealthIssue>,
}

fn entropy_bits(password: &str) -> f64 {
    let mut lower = false;
    let mut upper = false;
    let mut digit = false;
    let mut symbol = false;
    let mut other = false;
    for ch in password.chars() {
        if ch.is_ascii_lowercase() {
            lower = true;
        } else if ch.is_ascii_uppercase() {
            upper = true;
        } else if ch.is_ascii_digit() {
            digit = true;
        } else if ch.is_ascii() {
            symbol = true;
        } else {
            other = true;
        }
    }
    let mut charset = 0;
    if lower {
        charset += 26;
    }
    if upper {
        charset += 26;
    }
    if digit {
        charset += 10;
    }
    if symbol {
        charset += 32;
    }
    if other {
        charset += 128;
    }
    if charset == 0 {
        return 0.0;
    }
    let length = f64::from(u32::try_from(password.chars().count()).unwrap_or(u32::MAX));
    length * f64::from(charset).log2()
}

impl UnlockedVault {
    pub fn health(&self, min_length: usize, max_age_days: u64) -> Result<HealthReport, StoreError> {
        let now = glyx_core::ids::wall_ms_now();
        let max_age_ms = max_age_days.saturating_mul(86_400_000);
        let mut report = HealthReport {
            generated_ms: now,
            ..HealthReport::default()
        };
        let mut issues: BTreeMap<Uuid, (glyx_core::Item, Vec<String>)> = BTreeMap::new();
        let mut reuse: BTreeMap<String, Vec<Uuid>> = BTreeMap::new();
        let mut linked_totp = BTreeSet::new();
        for row in self.list(false)? {
            let Some(item) = self.get_item(&row.id)? else {
                continue;
            };
            if item.item_type != glyx_core::ItemType::Totp {
                continue;
            }
            if let Some(login) = item
                .fields
                .get("login_id")
                .map(|f| f.value.expose().trim().to_owned())
                .filter(|value| !value.is_empty())
            {
                linked_totp.insert(login);
            }
        }
        for row in self.list(false)? {
            let Some(item) = self.get_item(&row.id)? else {
                continue;
            };
            report.summary.items += 1;
            if item.item_type != glyx_core::ItemType::Login {
                continue;
            }
            let Some(password_field) = item.fields.get("password") else {
                continue;
            };
            let password = password_field.value.expose();
            let mut found = Vec::new();
            if password.chars().count() < min_length || entropy_bits(password) < 60.0 {
                found.push("weak".to_owned());
                report.summary.weak += 1;
            }
            if max_age_ms > 0 && now.saturating_sub(password_field.field_hlc.wall_ms) > max_age_ms {
                found.push("old".to_owned());
                report.summary.old += 1;
            }
            if !item.fields.contains_key("seed") && !linked_totp.contains(&item.id.to_string()) {
                found.push("no_totp".to_owned());
                report.summary.no_totp += 1;
            }
            reuse
                .entry(glyx_crypto::blake3_hex(password.as_bytes()))
                .or_default()
                .push(item.id);
            if !found.is_empty() {
                issues.insert(item.id, (item, found));
            }
        }
        for ids in reuse.values().filter(|ids| ids.len() > 1) {
            report.summary.reused += ids.len();
            for id in ids {
                if let Some((_item, found)) = issues.get_mut(id) {
                    found.push("reused".to_owned());
                } else if let Some(item) = self.get_item(id)? {
                    issues.insert(*id, (item, vec!["reused".to_owned()]));
                }
            }
        }
        report.issues = issues
            .into_values()
            .map(|(item, mut issues)| {
                issues.sort();
                issues.dedup();
                HealthIssue {
                    id: item.id,
                    name: item.name,
                    item_type: crate::vault::type_label(item.item_type).to_owned(),
                    issues,
                }
            })
            .collect();
        report.issues.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(report)
    }
}

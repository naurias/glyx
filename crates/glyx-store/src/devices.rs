use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{config, conflicts, StoreError, UnlockedVault};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub label: String,
    pub last_seen_ms: u64,
    pub current: bool,
}

impl UnlockedVault {
    pub fn devices(&self) -> Result<Vec<DeviceInfo>, StoreError> {
        let mut seen: BTreeMap<glyx_core::DeviceId, u64> = BTreeMap::new();
        let mut bump = |node: glyx_core::DeviceId, wall_ms: u64| {
            let value = seen.entry(node).or_default();
            *value = (*value).max(wall_ms);
        };
        bump(self.device_node(), glyx_core::ids::wall_ms_now());
        for row in self.list(true)? {
            bump(row.hlc.node, row.hlc.wall_ms);
            if let Some(item) = self.get_item(&row.id)? {
                for field in item.fields.values() {
                    bump(field.field_hlc.node, field.field_hlc.wall_ms);
                }
            }
            for entry in self.history(&row.id)? {
                bump(entry.hlc.node, entry.hlc.wall_ms);
            }
        }
        for meta in self.list_conflicts()? {
            let conflict = conflicts::read_conflict(&meta.path)?;
            for envelope in [&conflict.winner, &conflict.local, &conflict.remote] {
                bump(envelope.hlc.node, envelope.hlc.wall_ms);
            }
        }
        let cfg = config::load();
        let current = self.device_node();
        let vault_id = self.config().vault_id;
        let mut out: Vec<_> = seen
            .into_iter()
            .map(|(node, last_seen_ms)| {
                let id = node.to_hex();
                let label = cfg.device_label(&vault_id, &id).map_or_else(
                    || {
                        if node == current {
                            "This device".to_owned()
                        } else {
                            format!("Device {}", &id[..8])
                        }
                    },
                    str::to_owned,
                );
                DeviceInfo {
                    id,
                    label,
                    last_seen_ms,
                    current: node == current,
                }
            })
            .collect();
        out.sort_by(|a, b| {
            b.current
                .cmp(&a.current)
                .then_with(|| b.last_seen_ms.cmp(&a.last_seen_ms))
        });
        Ok(out)
    }
}

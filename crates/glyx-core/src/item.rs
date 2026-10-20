use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{CoreError, DeviceId, Hlc, SecretString};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemType {
    Login,
    Passkey,
    Totp,
    Identity,
    Card,
    Note,
    File,
    SshKey,
    GenericKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub value: SecretString,
    pub field_hlc: Hlc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub id: Uuid,
    #[serde(rename = "type")]
    pub item_type: ItemType,
    pub name: String,
    pub folder: String,
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub favorite: bool,
    pub fields: BTreeMap<String, Field>,
    pub hlc: Hlc,
    pub rev: u64,
    pub deleted: bool,
    pub updated_by: DeviceId,
}

impl Item {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.name.trim().is_empty() {
            return Err(CoreError::Validation {
                field: "name",
                reason: "must not be empty".to_owned(),
            });
        }
        for key in self.fields.keys() {
            let ok = !key.is_empty()
                && key
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
            if !ok {
                return Err(CoreError::Validation {
                    field: "fields",
                    reason: format!("bad field key {key:?}, use [a-z0-9_]+"),
                });
            }
        }
        Ok(())
    }
    #[must_use = "canonical JSON is computed, not stored"]
    pub fn canonical_json(&self) -> Result<String, CoreError> {
        serde_json::to_string(self).map_err(|e| CoreError::Validation {
            field: "item",
            reason: e.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn sample(node: DeviceId) -> Item {
        let mut fields = BTreeMap::new();
        fields.insert(
            "password".to_owned(),
            Field {
                value: SecretString::new("s3cret".to_owned()),
                field_hlc: Hlc {
                    wall_ms: 2,
                    seq: 0,
                    node,
                },
            },
        );
        Item {
            id: Uuid::now_v7(),
            item_type: ItemType::Login,
            name: "example".to_owned(),
            folder: "web".to_owned(),
            tags: vec!["a".to_owned()],
            favorite: false,
            fields,
            hlc: Hlc {
                wall_ms: 1,
                seq: 0,
                node,
            },
            rev: 1,
            deleted: false,
            updated_by: node,
        }
    }

    #[test]
    fn canonical_json_stable() {
        let item = sample(DeviceId::zero());
        let a = item.canonical_json().expect("serializes");
        let back: Item = serde_json::from_str(&a).expect("deserializes");
        assert_eq!(back.canonical_json().expect("reserializes"), a);
        assert!(a.contains("\"password\""));
    }

    #[test]
    fn validation_rules() {
        let mut item = sample(DeviceId::zero());
        item.name = "  ".to_owned();
        assert!(item.validate().is_err());
        item.name = "ok".to_owned();
        item.fields.insert(
            "Bad Key".to_owned(),
            Field {
                value: SecretString::new("x".to_owned()),
                field_hlc: Hlc {
                    wall_ms: 1,
                    seq: 0,
                    node: DeviceId::zero(),
                },
            },
        );
        assert!(item.validate().is_err());
    }

    #[test]
    fn secret_redacted_in_debug() {
        let s = SecretString::new("hunter2".to_owned());
        assert!(!format!("{s:?}").contains("hunter2"));
    }

    #[test]
    fn hlc_monotonic() {
        let a = DeviceId::zero();
        let t1 = Hlc::now(a);
        let remote = Hlc {
            wall_ms: t1.wall_ms + 1_000,
            seq: 0,
            node: DeviceId([9; 16]),
        };
        let t2 = t1.update(remote, a);
        assert!(t2 > t1);
        assert!(t2 > remote);
    }
}

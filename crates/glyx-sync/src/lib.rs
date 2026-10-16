use std::cmp::Ordering;
use std::collections::BTreeMap;

use glyx_core::{DeviceId, Field, Hlc, Item, SecretString};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderOrder {
    Older,
    Newer,
    Concurrent,
}

#[must_use]
pub fn cmp_header(a: Hlc, a_rev: u64, b: Hlc, b_rev: u64) -> HeaderOrder {
    match (a.wall_ms, a.seq).cmp(&(b.wall_ms, b.seq)) {
        Ordering::Less => HeaderOrder::Older,
        Ordering::Greater => HeaderOrder::Newer,
        Ordering::Equal if a.node != b.node => HeaderOrder::Concurrent,
        Ordering::Equal if a_rev < b_rev => HeaderOrder::Older,
        Ordering::Equal if a_rev > b_rev => HeaderOrder::Newer,
        Ordering::Equal => HeaderOrder::Concurrent,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictKind {
    FastForward,
    Stale,
    Concurrent,
    Tombstone,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum RaceTarget {
    Field(String),
    Name,
    Folder,
    Tags,
    ItemType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldRace {
    pub item_id: uuid::Uuid,
    pub target: RaceTarget,
    pub mine: String,
    pub theirs: String,
    pub winner_is_mine: bool,
}

fn clock_ord(a: Hlc, b: Hlc) -> Ordering {
    (a.wall_ms, a.seq).cmp(&(b.wall_ms, b.seq))
}

struct Contest<'a> {
    local_hlc: Hlc,
    local_val: &'a str,
    remote_hlc: Hlc,
    remote_val: &'a str,
    local_node: DeviceId,
    remote_node: DeviceId,
}

fn pick_str(
    races: &mut Vec<FieldRace>,
    item_id: uuid::Uuid,
    target: RaceTarget,
    contest: &Contest,
    out_hlc: &mut Hlc,
    out_val: &mut String,
) {
    if contest.local_val == contest.remote_val {
        return;
    }
    match clock_ord(contest.local_hlc, contest.remote_hlc) {
        Ordering::Greater => {
            *out_hlc = contest.local_hlc;
            contest.local_val.clone_into(out_val);
        }
        Ordering::Less => {
            *out_hlc = contest.remote_hlc;
            contest.remote_val.clone_into(out_val);
        }
        Ordering::Equal if contest.local_node == contest.remote_node => {
            *out_hlc = contest.local_hlc;
            contest.local_val.clone_into(out_val);
        }
        Ordering::Equal => {
            let mine_wins = contest.local_node > contest.remote_node;
            *out_hlc = if mine_wins {
                contest.local_hlc
            } else {
                contest.remote_hlc
            };
            if mine_wins {
                contest.local_val.clone_into(out_val);
            } else {
                contest.remote_val.clone_into(out_val);
            }
            races.push(FieldRace {
                item_id,
                target,
                mine: contest.local_val.to_owned(),
                theirs: contest.remote_val.to_owned(),
                winner_is_mine: mine_wins,
            });
        }
    }
}

fn contest_for<'a>(
    local_hlc: Hlc,
    local_val: &'a str,
    remote_hlc: Hlc,
    remote_val: &'a str,
    local_node: DeviceId,
    remote_node: DeviceId,
) -> Contest<'a> {
    Contest {
        local_hlc,
        local_val,
        remote_hlc,
        remote_val,
        local_node,
        remote_node,
    }
}

#[must_use]
pub fn merge_items(
    local: &Item,
    remote: &Item,
    tick: Hlc,
    node: DeviceId,
    local_node: DeviceId,
    remote_node: DeviceId,
) -> (Item, Vec<FieldRace>) {
    debug_assert_eq!(local.id, remote.id);
    let mut races = Vec::new();
    let mut out = local.clone();
    if local.deleted || remote.deleted {
        let newer = match clock_ord(local.hlc, remote.hlc) {
            Ordering::Less => remote,
            _ => local,
        };
        out.fields = newer.fields.clone();
        out.deleted = true;
        out.hlc = tick;
        out.rev = local.rev.max(remote.rev).saturating_add(1);
        out.updated_by = node;
        return (out, races);
    }
    out.fields = merge_fields(local, remote, &mut races, local_node, remote_node);
    merge_attrs(&mut out, local, remote, &mut races, local_node, remote_node);
    out.hlc = tick;
    out.rev = local.rev.max(remote.rev).saturating_add(1);
    out.deleted = false;
    out.updated_by = node;
    (out, races)
}

fn merge_fields(
    local: &Item,
    remote: &Item,
    races: &mut Vec<FieldRace>,
    local_node: DeviceId,
    remote_node: DeviceId,
) -> BTreeMap<String, Field> {
    let mut fields = BTreeMap::new();
    let mut keys: Vec<&String> = local.fields.keys().chain(remote.fields.keys()).collect();
    keys.sort();
    keys.dedup();
    for key in keys {
        match (local.fields.get(key), remote.fields.get(key)) {
            (Some(l), Some(r)) => {
                let mut hlc = l.field_hlc;
                let mut val = l.value.expose().to_owned();
                let contest = contest_for(
                    l.field_hlc,
                    l.value.expose(),
                    r.field_hlc,
                    r.value.expose(),
                    local_node,
                    remote_node,
                );
                pick_str(
                    races,
                    local.id,
                    RaceTarget::Field(key.clone()),
                    &contest,
                    &mut hlc,
                    &mut val,
                );
                fields.insert(
                    key.clone(),
                    Field {
                        value: SecretString::new(val),
                        field_hlc: hlc,
                    },
                );
            }
            (Some(l), None) => {
                fields.insert(key.clone(), l.clone());
            }
            (None, Some(r)) => {
                fields.insert(key.clone(), r.clone());
            }
            (None, None) => {}
        }
    }
    fields
}

fn merge_attrs(
    out: &mut Item,
    local: &Item,
    remote: &Item,
    races: &mut Vec<FieldRace>,
    local_node: DeviceId,
    remote_node: DeviceId,
) {
    let mut name = local.name.clone();
    let mut name_hlc = local.hlc;
    pick_str(
        races,
        local.id,
        RaceTarget::Name,
        &contest_for(
            local.hlc,
            &local.name,
            remote.hlc,
            &remote.name,
            local_node,
            remote_node,
        ),
        &mut name_hlc,
        &mut name,
    );
    out.name = name;
    let mut folder = local.folder.clone();
    let mut folder_hlc = local.hlc;
    pick_str(
        races,
        local.id,
        RaceTarget::Folder,
        &contest_for(
            local.hlc,
            &local.folder,
            remote.hlc,
            &remote.folder,
            local_node,
            remote_node,
        ),
        &mut folder_hlc,
        &mut folder,
    );
    out.folder = folder;
    let local_tags = serde_json::to_string(&local.tags).unwrap_or_default();
    let remote_tags = serde_json::to_string(&remote.tags).unwrap_or_default();
    let mut tags_json = local_tags.clone();
    let mut tags_hlc = local.hlc;
    pick_str(
        races,
        local.id,
        RaceTarget::Tags,
        &contest_for(
            local.hlc,
            &local_tags,
            remote.hlc,
            &remote_tags,
            local_node,
            remote_node,
        ),
        &mut tags_hlc,
        &mut tags_json,
    );
    out.tags = serde_json::from_str(&tags_json).unwrap_or_default();
    if local.item_type != remote.item_type {
        let local_wins = match clock_ord(local.hlc, remote.hlc) {
            Ordering::Greater => true,
            Ordering::Less => false,
            Ordering::Equal => local_node >= remote_node,
        };
        if clock_ord(local.hlc, remote.hlc) == Ordering::Equal {
            races.push(FieldRace {
                item_id: local.id,
                target: RaceTarget::ItemType,
                mine: format!("{:?}", local.item_type),
                theirs: format!("{:?}", remote.item_type),
                winner_is_mine: local_wins,
            });
        }
        out.item_type = if local_wins {
            local.item_type
        } else {
            remote.item_type
        };
    }
}

#[must_use]
pub fn remote_dominates(local: &Item, remote: &Item) -> bool {
    if local.deleted != remote.deleted {
        return false;
    }
    for (key, local_field) in &local.fields {
        match remote.fields.get(key) {
            Some(remote_field) => match clock_ord(remote_field.field_hlc, local_field.field_hlc) {
                Ordering::Less => return false,
                Ordering::Equal => {
                    if remote_field.value != local_field.value {
                        return false;
                    }
                }
                Ordering::Greater => {}
            },
            None => return false,
        }
    }
    if local.name != remote.name
        || local.folder != remote.folder
        || local.tags != remote.tags
        || local.item_type != remote.item_type
    {
        return clock_ord(remote.hlc, local.hlc) == Ordering::Greater;
    }
    true
}

#[must_use]
pub fn classify(
    local: Hlc,
    local_rev: u64,
    local_deleted: bool,
    remote: Hlc,
    remote_rev: u64,
    remote_deleted: bool,
) -> ConflictKind {
    if local_deleted || remote_deleted {
        return ConflictKind::Tombstone;
    }
    match cmp_header(local, local_rev, remote, remote_rev) {
        HeaderOrder::Older => ConflictKind::FastForward,
        HeaderOrder::Newer => ConflictKind::Stale,
        HeaderOrder::Concurrent => ConflictKind::Concurrent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use glyx_core::DeviceId;

    fn hlc(ms: u64, node_byte: u8) -> Hlc {
        Hlc {
            wall_ms: ms,
            seq: 0,
            node: DeviceId([node_byte; 16]),
        }
    }

    #[test]
    fn orders_headers() {
        assert_eq!(cmp_header(hlc(1, 0), 1, hlc(2, 0), 1), HeaderOrder::Older);
        assert_eq!(cmp_header(hlc(3, 0), 1, hlc(2, 0), 1), HeaderOrder::Newer);
        assert_eq!(
            cmp_header(hlc(2, 0), 1, hlc(2, 1), 1),
            HeaderOrder::Concurrent
        );
    }

    #[test]
    fn concurrency_smoke_two_writers() {
        let a = hlc(100, 1);
        let b = Hlc {
            wall_ms: 100,
            seq: 0,
            node: DeviceId([2; 16]),
        };
        assert_eq!(classify(a, 2, false, b, 2, false), ConflictKind::Concurrent);
        assert_eq!(
            classify(a, 1, false, hlc(200, 2), 1, false),
            ConflictKind::FastForward
        );
        assert_eq!(
            classify(hlc(300, 1), 1, false, hlc(200, 2), 1, false),
            ConflictKind::Stale
        );
        assert_eq!(classify(a, 2, true, b, 2, false), ConflictKind::Tombstone);
    }
}

#[cfg(test)]
mod merge_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn node(b: u8) -> DeviceId {
        DeviceId([b; 16])
    }

    fn hlc(ms: u64, n: u8) -> Hlc {
        Hlc {
            wall_ms: ms,
            seq: 0,
            node: node(n),
        }
    }

    fn item(node_byte: u8, ms: u64, fields: &[(&str, &str)]) -> Item {
        let mut map = BTreeMap::new();
        for (k, v) in fields {
            map.insert(
                (*k).to_owned(),
                glyx_core::Field {
                    value: glyx_core::SecretString::new((*v).to_owned()),
                    field_hlc: hlc(ms, node_byte),
                },
            );
        }
        Item {
            id: uuid::Uuid::now_v7(),
            item_type: glyx_core::ItemType::Login,
            name: "n".to_owned(),
            folder: String::new(),
            tags: Vec::new(),
            fields: map,
            hlc: hlc(ms, node_byte),
            rev: 1,
            deleted: false,
            updated_by: node(node_byte),
        }
    }

    fn merge(a: &Item, b: &Item) -> (Item, Vec<FieldRace>) {
        let tick = Hlc {
            wall_ms: 999,
            seq: 0,
            node: node(0),
        };
        merge_items(a, b, tick, node(0), a.hlc.node, b.hlc.node)
    }

    #[test]
    fn disjoint_fields_union() {
        let id = uuid::Uuid::now_v7();
        let mut a = item(1, 10, &[("username", "u")]);
        let mut b = item(2, 10, &[("password", "p")]);
        a.id = id;
        b.id = id;
        let (out, races) = merge(&a, &b);
        assert!(races.is_empty());
        assert_eq!(out.fields["username"].value.expose(), "u");
        assert_eq!(out.fields["password"].value.expose(), "p");
    }

    #[test]
    fn newer_field_wins_no_race() {
        let id = uuid::Uuid::now_v7();
        let mut a = item(1, 10, &[("password", "old")]);
        let mut b = item(2, 20, &[("password", "new")]);
        a.id = id;
        b.id = id;
        let (out, races) = merge(&a, &b);
        assert!(races.is_empty());
        assert_eq!(out.fields["password"].value.expose(), "new");
    }

    #[test]
    fn same_clock_race_deterministic() {
        let id = uuid::Uuid::now_v7();
        let mut a = item(1, 10, &[("password", "aaa")]);
        let mut b = item(2, 10, &[("password", "bbb")]);
        a.id = id;
        b.id = id;
        let (ab, races_ab) = merge(&a, &b);
        let (ba, races_ba) = merge(&b, &a);
        assert_eq!(races_ab.len(), 1);
        assert_eq!(ab.fields["password"].value, ba.fields["password"].value);
        assert_eq!(ab.name, ba.name);
        assert_ne!(races_ab[0].winner_is_mine, races_ba[0].winner_is_mine);
    }

    #[test]
    fn tombstone_wins() {
        let id = uuid::Uuid::now_v7();
        let mut a = item(1, 10, &[("password", "x")]);
        let mut b = item(2, 20, &[("password", "y")]);
        a.id = id;
        b.id = id;
        b.deleted = true;
        let (out, _) = merge(&a, &b);
        assert!(out.deleted);
        assert_eq!(out.fields["password"].value.expose(), "y");
    }

    #[test]
    fn merge_idempotent() {
        let id = uuid::Uuid::now_v7();
        let mut a = item(1, 10, &[("password", "aaa"), ("url", "u")]);
        let mut b = item(2, 10, &[("password", "bbb")]);
        a.id = id;
        b.id = id;
        let (once_out, _) = merge(&a, &b);
        let (twice_out, twice_races) = merge(&once_out, &b);
        assert_eq!(once_out.fields, twice_out.fields);
        assert!(twice_races.is_empty());
    }
}

#[cfg(test)]
mod fuzz {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    pub fn arb_item() -> impl Strategy<Value = Item> {
        (
            prop::collection::btree_map("[a-z]{1,3}", "[a-z0-9]{0,5}", 0..4),
            0..2000u64,
            1..3u8,
        )
            .prop_map(|(fields, ms, n)| {
                let mut map = BTreeMap::new();
                for (k, v) in fields {
                    map.insert(
                        k,
                        glyx_core::Field {
                            value: glyx_core::SecretString::new(v),
                            field_hlc: Hlc {
                                wall_ms: ms,
                                seq: 0,
                                node: DeviceId([n; 16]),
                            },
                        },
                    );
                }
                Item {
                    id: uuid::Uuid::from_bytes([42; 16]),
                    item_type: glyx_core::ItemType::Login,
                    name: "n".to_owned(),
                    folder: String::new(),
                    tags: Vec::new(),
                    fields: map,
                    hlc: Hlc {
                        wall_ms: ms,
                        seq: 0,
                        node: DeviceId([n; 16]),
                    },
                    rev: 1,
                    deleted: false,
                    updated_by: DeviceId([n; 16]),
                }
            })
    }

    proptest! {
        #[test]
        fn commutative_and_lossless(a in arb_item(), b_ms in 0..2000u64, b_n in 3..5u8) {
            let mut b = a.clone();
            b.hlc = Hlc { wall_ms: b_ms, seq: 0, node: DeviceId([b_n; 16]) };
            b.updated_by = DeviceId([b_n; 16]);
            for f in b.fields.values_mut() {
                f.field_hlc = b.hlc;
            }
            let tick = Hlc { wall_ms: 9999, seq: 0, node: DeviceId([0; 16]) };
            let (ab, _) = merge_items(&a, &b, tick, DeviceId([0; 16]), a.hlc.node, b.hlc.node);
            let (ba, _) = merge_items(&b, &a, tick, DeviceId([0; 16]), b.hlc.node, a.hlc.node);
            prop_assert_eq!(field_vals(&ab), field_vals(&ba));
            for (k, v) in field_vals(&ab) {
                let av = a.fields.get(&k).map(|f| f.value.expose());
                let bv = b.fields.get(&k).map(|f| f.value.expose());
                prop_assert!(Some(v.as_str()) == av || Some(v.as_str()) == bv);
            }
            for k in a.fields.keys().chain(b.fields.keys()) {
                prop_assert!(ab.fields.contains_key(k));
            }
        }
    }

    fn field_vals(item: &Item) -> BTreeMap<String, String> {
        item.fields
            .iter()
            .map(|(k, f)| (k.clone(), f.value.expose().to_owned()))
            .collect()
    }
}

use rusqlite::{Connection, OptionalExtension as _};
use uuid::Uuid;

use crate::{layout, StoreError};

#[derive(Debug, Clone)]
pub struct IndexRow {
    pub id: Uuid,
    pub hlc: glyx_core::Hlc,
    pub rev: u64,
    pub deleted: bool,
    pub item_type: String,
    pub name: String,
}

pub fn init_schema(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS items(
           id TEXT PRIMARY KEY,
           hlc_ms INTEGER NOT NULL, hlc_seq INTEGER NOT NULL, node BLOB NOT NULL,
           rev INTEGER NOT NULL, deleted INTEGER NOT NULL,
           item_type TEXT NOT NULL, name TEXT NOT NULL, updated_ms INTEGER NOT NULL);
         CREATE INDEX IF NOT EXISTS idx_items_updated ON items(updated_ms);",
    )?;
    conn.execute(
        "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        [layout::INDEX_SCHEMA_VERSION.to_string()],
    )?;
    Ok(())
}

pub fn upsert(conn: &Connection, item: &glyx_core::Item) -> Result<(), StoreError> {
    let type_str = serde_json::to_value(item.item_type)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into());
    conn.execute(
        "INSERT INTO items(id, hlc_ms, hlc_seq, node, rev, deleted, item_type, name, updated_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(id) DO UPDATE SET hlc_ms=excluded.hlc_ms, hlc_seq=excluded.hlc_seq,
           node=excluded.node, rev=excluded.rev, deleted=excluded.deleted,
           item_type=excluded.item_type, name=excluded.name, updated_ms=excluded.updated_ms",
        rusqlite::params![
            item.id.as_simple().to_string(),
            item.hlc.wall_ms.cast_signed(),
            i64::from(item.hlc.seq),
            item.hlc.node.0.to_vec(),
            item.rev.cast_signed(),
            i64::from(item.deleted),
            type_str,
            item.name,
            glyx_core::ids::wall_ms_now().cast_signed(),
        ],
    )?;
    Ok(())
}

fn decode_hlc(ms: i64, seq: i64, node: Vec<u8>) -> rusqlite::Result<glyx_core::Hlc> {
    let cvt = |field: &'static str| {
        move |e: std::num::TryFromIntError| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Integer,
                format!("{field}: {e}").into(),
            )
        }
    };
    let node: [u8; 16] = node.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, "bad node".into())
    })?;
    Ok(glyx_core::Hlc {
        wall_ms: u64::try_from(ms).map_err(cvt("hlc_ms"))?,
        seq: u16::try_from(seq).map_err(cvt("hlc_seq"))?,
        node: glyx_core::DeviceId(node),
    })
}

pub fn list(conn: &Connection, include_deleted: bool) -> Result<Vec<IndexRow>, StoreError> {
    let sql = if include_deleted {
        "SELECT id, hlc_ms, hlc_seq, node, rev, deleted, item_type, name
         FROM items ORDER BY updated_ms DESC"
    } else {
        "SELECT id, hlc_ms, hlc_seq, node, rev, deleted, item_type, name
         FROM items WHERE deleted = 0 ORDER BY updated_ms DESC"
    };
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([], |r| {
        let id_hex: String = r.get(0)?;
        Ok(IndexRow {
            id: Uuid::parse_str(&id_hex).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?,
            hlc: decode_hlc(r.get(1)?, r.get(2)?, r.get(3)?)?,
            rev: u64::try_from(r.get::<_, i64>(4)?).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    4,
                    rusqlite::types::Type::Integer,
                    format!("rev: {e}").into(),
                )
            })?,
            deleted: r.get::<_, i64>(5)? != 0,
            item_type: r.get(6)?,
            name: r.get(7)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

pub fn count(conn: &Connection) -> Result<i64, StoreError> {
    Ok(conn.query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0))?)
}

pub fn get(conn: &Connection, id: &Uuid) -> Result<Option<IndexRow>, StoreError> {
    let id_hex = id.as_simple().to_string();
    conn.query_row(
        "SELECT id, hlc_ms, hlc_seq, node, rev, deleted, item_type, name FROM items WHERE id=?1",
        [&id_hex],
        |r| {
            Ok(IndexRow {
                id: *id,
                hlc: decode_hlc(r.get(1)?, r.get(2)?, r.get(3)?)?,
                rev: u64::try_from(r.get::<_, i64>(4)?).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        4,
                        rusqlite::types::Type::Integer,
                        format!("rev: {e}").into(),
                    )
                })?,
                deleted: r.get::<_, i64>(5)? != 0,
                item_type: r.get(6)?,
                name: r.get(7)?,
            })
        },
    )
    .optional()
    .map_err(StoreError::from)
}

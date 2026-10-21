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
    pub updated_ms: u64,
    pub favorite: bool,
    pub folder: String,
    pub tags: Vec<String>,
}

pub fn init_schema(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS items(
           id TEXT PRIMARY KEY,
           hlc_ms INTEGER NOT NULL, hlc_seq INTEGER NOT NULL, node BLOB NOT NULL,
           rev INTEGER NOT NULL, deleted INTEGER NOT NULL,
           item_type TEXT NOT NULL, name TEXT NOT NULL, updated_ms INTEGER NOT NULL,
           favorite INTEGER NOT NULL DEFAULT 0,
           folder TEXT NOT NULL DEFAULT '',
           tags_json TEXT NOT NULL DEFAULT '[]');
         CREATE INDEX IF NOT EXISTS idx_items_updated ON items(updated_ms);",
    )?;
    let old_version: Option<i64> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |r| {
                let value: String = r.get(0)?;
                Ok(value.parse::<i64>().unwrap_or(0))
            },
        )
        .optional()?;
    let mut migrated = old_version.is_some_and(|v| v < layout::INDEX_SCHEMA_VERSION);
    for (column, ddl) in [
        (
            "favorite",
            "ALTER TABLE items ADD COLUMN favorite INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "folder",
            "ALTER TABLE items ADD COLUMN folder TEXT NOT NULL DEFAULT ''",
        ),
        (
            "tags_json",
            "ALTER TABLE items ADD COLUMN tags_json TEXT NOT NULL DEFAULT '[]'",
        ),
    ] {
        if !has_column(conn, column)? {
            conn.execute(ddl, [])?;
            migrated = true;
        }
    }
    if migrated {
        conn.execute(
            "INSERT INTO meta(key, value) VALUES ('needs_backfill', '1')
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [],
        )?;
        conn.execute("UPDATE items SET updated_ms = hlc_ms", [])?;
    }
    conn.execute(
        "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        [layout::INDEX_SCHEMA_VERSION.to_string()],
    )?;
    Ok(())
}

fn has_column(conn: &Connection, name: &str) -> Result<bool, StoreError> {
    let mut stmt = conn.prepare("PRAGMA table_info(items)")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(1))?;
    for row in rows {
        if row? == name {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn needs_backfill(conn: &Connection) -> Result<bool, StoreError> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'needs_backfill'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    Ok(value.is_some_and(|v| v == "1"))
}

pub fn clear_backfill(conn: &Connection) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO meta(key, value) VALUES ('needs_backfill', '0')
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [],
    )?;
    Ok(())
}

pub fn upsert(conn: &Connection, item: &glyx_core::Item) -> Result<(), StoreError> {
    let type_str = serde_json::to_value(item.item_type)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into());
    let tags_json = serde_json::to_string(&item.tags).unwrap_or_else(|_| "[]".into());
    conn.execute(
        "INSERT INTO items(id, hlc_ms, hlc_seq, node, rev, deleted, item_type, name, updated_ms,
                           favorite, folder, tags_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(id) DO UPDATE SET hlc_ms=excluded.hlc_ms, hlc_seq=excluded.hlc_seq,
           node=excluded.node, rev=excluded.rev, deleted=excluded.deleted,
           item_type=excluded.item_type, name=excluded.name, updated_ms=excluded.updated_ms,
           favorite=excluded.favorite, folder=excluded.folder, tags_json=excluded.tags_json",
        rusqlite::params![
            item.id.as_simple().to_string(),
            item.hlc.wall_ms.cast_signed(),
            i64::from(item.hlc.seq),
            item.hlc.node.0.to_vec(),
            item.rev.cast_signed(),
            i64::from(item.deleted),
            type_str,
            item.name,
            item.hlc.wall_ms.cast_signed(),
            i64::from(item.favorite),
            item.folder,
            tags_json,
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

const SELECT: &str = "SELECT id, hlc_ms, hlc_seq, node, rev, deleted, item_type, name,
                             updated_ms, favorite, folder, tags_json FROM items";

fn row_from(r: &rusqlite::Row<'_>) -> rusqlite::Result<IndexRow> {
    let id_hex: String = r.get(0)?;
    let updated_ms = u64::try_from(r.get::<_, i64>(8)?).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            8,
            rusqlite::types::Type::Integer,
            format!("updated_ms: {e}").into(),
        )
    })?;
    let tags_json: String = r.get(11)?;
    Ok(IndexRow {
        id: Uuid::parse_str(&id_hex).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
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
        updated_ms,
        favorite: r.get::<_, i64>(9)? != 0,
        folder: r.get(10)?,
        tags: serde_json::from_str(&tags_json).unwrap_or_default(),
    })
}

pub fn list(conn: &Connection, include_deleted: bool) -> Result<Vec<IndexRow>, StoreError> {
    let sql = if include_deleted {
        format!("{SELECT} ORDER BY updated_ms DESC, name COLLATE NOCASE ASC, id ASC")
    } else {
        format!(
            "{SELECT} WHERE deleted = 0 ORDER BY updated_ms DESC, name COLLATE NOCASE ASC, id ASC"
        )
    };
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], row_from)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

pub fn remove(conn: &Connection, id: &Uuid) -> Result<(), StoreError> {
    conn.execute(
        "DELETE FROM items WHERE id = ?1",
        [&id.as_simple().to_string()],
    )?;
    Ok(())
}

pub fn count(conn: &Connection) -> Result<i64, StoreError> {
    Ok(conn.query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0))?)
}

pub fn get(conn: &Connection, id: &Uuid) -> Result<Option<IndexRow>, StoreError> {
    let id_hex = id.as_simple().to_string();
    conn.query_row(&format!("{SELECT} WHERE id = ?1"), [&id_hex], row_from)
        .optional()
        .map_err(StoreError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_v1_index_and_backfills() {
        let conn = Connection::open_in_memory().expect("db");
        conn.execute_batch(
            "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO meta(key, value) VALUES ('schema_version', '1');
             CREATE TABLE items(
               id TEXT PRIMARY KEY,
               hlc_ms INTEGER NOT NULL, hlc_seq INTEGER NOT NULL, node BLOB NOT NULL,
               rev INTEGER NOT NULL, deleted INTEGER NOT NULL,
               item_type TEXT NOT NULL, name TEXT NOT NULL, updated_ms INTEGER NOT NULL);",
        )
        .expect("schema");
        init_schema(&conn).expect("migrate");
        assert!(needs_backfill(&conn).expect("flag"));
        let value: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .expect("version");
        assert_eq!(value, layout::INDEX_SCHEMA_VERSION.to_string());
        let mut stmt = conn.prepare("PRAGMA table_info(items)").expect("pragma");
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get(1))
            .expect("rows")
            .map(|row| row.expect("column"))
            .collect();
        assert!(columns.contains(&"favorite".to_owned()));
        assert!(columns.contains(&"folder".to_owned()));
        assert!(columns.contains(&"tags_json".to_owned()));
        clear_backfill(&conn).expect("clear");
        assert!(!needs_backfill(&conn).expect("flag"));
    }
}

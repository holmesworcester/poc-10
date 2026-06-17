//! SQL storage for protocol-neutral fact bytes.
//!
//! Facts are immutable, content-addressed rows. This module owns inserting,
//! purging, and reading those rows; runtime workers decide when those
//! operations should happen. It knows the protocol-neutral `Fact` shape, local
//! admission columns, incoming rows, and projection queue links, but it does not
//! decode fact bytes or branch on protocol-specific fact families.

use crate::core::db::{quoted_identifier, quoted_table_name, Db, TableName};
use crate::core::facts::{fact_id, Fact, FactId, FactScope, ScopeKind};
use crate::core::project_fact::ProjectionMode;
use crate::core::schema::{
    CONTEXT_EDGES, FACTS, INCOMING_FACTS, LOCAL_FACT_ADMISSIONS, PENDING_PROJECTION,
    PENDING_PROJECTION_MATCHES, PENDING_TIME_RANGES, TIME_WAKES,
};
use crate::core::wire::Writer;
use rusqlite::{params, OptionalExtension};

const OWNER_KEYED_FACT_CLEANUP_TABLES: &[TableName] = &[
    CONTEXT_EDGES,
    TIME_WAKES,
    PENDING_TIME_RANGES,
    PENDING_PROJECTION_MATCHES,
    PENDING_PROJECTION,
];

/// The all-zero [`FactId`] stored in the scope columns of non-scoped facts.
const EMPTY_FACT_ID: FactId = [0u8; 32];

#[derive(Debug, Clone, Copy)]
enum FactReadSource {
    Retained,
    Incoming,
}

impl FactReadSource {
    fn select_by_id_sql(self) -> &'static str {
        match self {
            Self::Retained => {
                "SELECT f.id, m.scope, m.scope_kind, m.scope_id, m.received_at, f.bytes
                 FROM facts f
                 JOIN local_fact_admissions m ON m.fact_id = f.id
                 WHERE f.id = ?1
                 LIMIT 1"
            }
            Self::Incoming => {
                "SELECT id, scope, scope_kind, scope_id, received_at, bytes
                 FROM incoming_facts
                 WHERE id = ?1
                 LIMIT 1"
            }
        }
    }
}

fn fact_db_error(message: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(message.into())
}

fn verify_idempotent_insert<T>(
    changed: usize,
    existing: impl FnOnce() -> rusqlite::Result<Option<T>>,
    matches_existing: impl FnOnce(&T) -> bool,
    conflict_message: impl Into<String>,
) -> rusqlite::Result<bool> {
    if changed == 0 {
        let matches = existing()?.as_ref().map(matches_existing).unwrap_or(false);
        if !matches {
            return Err(fact_db_error(conflict_message));
        }
    }
    Ok(changed > 0)
}

/// Count retained fact byte rows.
pub(crate) fn fact_count(db: &Db) -> rusqlite::Result<usize> {
    db.table_row_count(FACTS)
}

/// Return whether a retained fact row exists.
pub(crate) fn fact_exists(db: &Db, id: &FactId) -> rusqlite::Result<bool> {
    db.conn()
        .query_row(
            "SELECT 1 FROM facts WHERE id = ?1 LIMIT 1",
            params![id.as_slice()],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
}

/// Load a retained fact by id.
pub(crate) fn persisted_fact(db: &Db, id: &FactId) -> Result<Option<Fact>, String> {
    fact_by_id_in_tx(db, id).map_err(|err| format!("load fact row: {err}"))
}

/// Insert a fact and mark it pending for projection.
pub(crate) fn insert_fact_and_pending_in_tx(db: &Db, fact: &Fact) -> rusqlite::Result<bool> {
    insert_fact_and_pending_with_mode_in_tx(db, fact, ProjectionMode::Normal)
}

/// Insert a fact and mark it pending with an explicit projection mode.
pub(crate) fn insert_fact_and_pending_with_mode_in_tx(
    db: &Db,
    fact: &Fact,
    mode: ProjectionMode,
) -> rusqlite::Result<bool> {
    let db_changed = insert_retained_fact_in_tx(db, fact)?;
    if db_changed {
        insert_pending_owner_with_mode_in_tx(db, fact.id, mode)?;
    }
    Ok(db_changed)
}

/// Mark `owner` pending in a specific projection mode.
pub(crate) fn insert_pending_owner_with_mode_in_tx(
    db: &Db,
    owner: FactId,
    mode: ProjectionMode,
) -> rusqlite::Result<usize> {
    db.conn().execute(
        "INSERT INTO pending_projection (owner, mode) VALUES (?1, ?2)
         ON CONFLICT(owner) DO UPDATE SET mode =
             CASE
                 WHEN excluded.mode = 'replay' OR pending_projection.mode = 'replay' THEN 'replay'
                 ELSE 'normal'
             END",
        params![owner.as_slice(), mode.as_str()],
    )
}

/// Insert a projectable incoming input.
pub(crate) fn insert_incoming_fact_in_tx(db: &Db, fact: &Fact) -> rusqlite::Result<bool> {
    if let Some(bytes) = fact_bytes_by_id_in_tx(db, &fact.id)? {
        if bytes == fact.bytes {
            return Ok(false);
        }
        return Err(fact_db_error("conflicting retained row for incoming fact"));
    }

    let (scope, scope_kind, scope_id) = fact_scope_columns(&fact.scope);
    let changed = db.conn().execute(
        "INSERT OR IGNORE INTO incoming_facts
            (id, scope, scope_kind, scope_id, received_at, bytes)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            fact.id.as_slice(),
            scope,
            scope_kind,
            scope_id.as_slice(),
            sqlite_u64(fact.timestamp, "incoming fact received_at")?,
            fact.bytes.as_slice()
        ],
    )?;
    verify_idempotent_insert(
        changed,
        || incoming_fact_by_id_in_tx(db, &fact.id),
        |existing| existing.bytes == fact.bytes,
        "conflicting row for incoming fact",
    )
}

pub(crate) fn delete_incoming_fact_in_tx(db: &Db, owner: FactId) -> rusqlite::Result<bool> {
    let changed = delete_rows_by_blob_column_in_tx(db, INCOMING_FACTS, "id", owner.as_slice())? > 0;
    if changed {
        delete_owner_rows_from_tables(db, OWNER_KEYED_FACT_CLEANUP_TABLES, owner)?;
    }
    Ok(changed)
}

/// Move an incoming fact into the retained fact table without requeueing it.
pub(crate) fn move_incoming_to_retained_in_tx(db: &Db, fact: &Fact) -> rusqlite::Result<bool> {
    let retained = insert_retained_fact_in_tx(db, fact)?;
    delete_incoming_fact_in_tx(db, fact.id)?;
    Ok(retained)
}

/// Remove a fact and every durable row keyed to it.
pub(crate) fn purge_fact_in_tx(db: &Db, owner: FactId) -> rusqlite::Result<bool> {
    let mut changed = delete_rows_by_blob_column_in_tx(db, FACTS, "id", owner.as_slice())? > 0;
    changed |=
        delete_rows_by_blob_column_in_tx(db, LOCAL_FACT_ADMISSIONS, "fact_id", owner.as_slice())?
            > 0;
    changed |= delete_owner_rows_from_tables(db, OWNER_KEYED_FACT_CLEANUP_TABLES, owner)? > 0;
    changed |= delete_rows_by_blob_column_in_tx(
        db,
        PENDING_PROJECTION_MATCHES,
        "offer_owner",
        owner.as_slice(),
    )? > 0;
    Ok(changed)
}

pub(crate) fn insert_retained_fact_in_tx(db: &Db, fact: &Fact) -> rusqlite::Result<bool> {
    let fact_bytes_inserted = insert_fact_bytes_in_tx(db, fact)?;
    let admission_inserted = insert_local_fact_admission_in_tx(db, fact)? > 0;
    Ok(fact_bytes_inserted || admission_inserted)
}

pub(crate) fn incoming_pending_fact_ids(db: &Db, limit: usize) -> Result<Vec<FactId>, String> {
    let limit = i64::try_from(limit).map_err(|_| "incoming fact limit exceeds i64".to_string())?;
    let sql = incoming_ready_sql("e.id", "ORDER BY e.received_at, e.id LIMIT ?1")?;
    let mut stmt = db
        .conn()
        .prepare(&sql)
        .map_err(|err| format!("load incoming facts: {err}"))?;
    let rows = stmt
        .query_map(params![limit], |row| {
            fact_id_column(row.get::<_, Vec<u8>>(0)?, "incoming id")
        })
        .map_err(|err| format!("load incoming facts: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("load incoming facts: {err}"))
}

pub(crate) fn incoming_fact_by_id(db: &Db, id: &FactId) -> Result<Option<Fact>, String> {
    incoming_fact_by_id_in_tx(db, id).map_err(|err| format!("load incoming fact: {err}"))
}

pub(crate) fn sqlite_u64(value: u64, name: &str) -> rusqlite::Result<i64> {
    i64::try_from(value)
        .map_err(|_| fact_db_error(format!("{name}: SQL value exceeds SQLite integer range")))
}

fn insert_fact_bytes_in_tx(db: &Db, fact: &Fact) -> rusqlite::Result<bool> {
    let changed = db.conn().execute(
        "INSERT OR IGNORE INTO facts (id, bytes) VALUES (?1, ?2)",
        params![fact.id.as_slice(), fact.bytes.as_slice()],
    )?;
    verify_idempotent_insert(
        changed,
        || fact_bytes_by_id_in_tx(db, &fact.id),
        |existing| existing.as_slice() == fact.bytes.as_slice(),
        "conflicting row for facts",
    )
}

fn insert_local_fact_admission_in_tx(db: &Db, fact: &Fact) -> rusqlite::Result<usize> {
    let (scope, scope_kind, scope_id) = fact_scope_columns(&fact.scope);
    let received_at = sqlite_u64(fact.timestamp, "fact received_at")?;
    let bytes = local_fact_admission_bytes(fact)?;
    let id = fact_id(&bytes);
    db.conn().execute(
        "INSERT OR IGNORE INTO local_fact_admissions
            (id, fact_id, scope, scope_kind, scope_id, received_at, bytes)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            id.as_slice(),
            fact.id.as_slice(),
            scope,
            scope_kind,
            scope_id.as_slice(),
            received_at,
            bytes.as_slice()
        ],
    )
}

fn local_fact_admission_bytes(fact: &Fact) -> rusqlite::Result<Vec<u8>> {
    let (scope, scope_kind, scope_id) = fact_scope_columns(&fact.scope);
    let mut out = Writer::new();
    out.bytes(b"topo:local_fact_admission:v1");
    out.fixed(&fact.id);
    out.string_u32be(scope)
        .map_err(|err| local_fact_admission_wire_error("scope", err))?;
    out.string_u32be(scope_kind)
        .map_err(|err| local_fact_admission_wire_error("scope_kind", err))?;
    out.fixed(scope_id);
    out.u64be(fact.timestamp);
    Ok(out.finish())
}

fn local_fact_admission_wire_error(
    field: &str,
    err: crate::core::wire::WireError,
) -> rusqlite::Error {
    fact_db_error(format!("local fact admission {field}: {err}"))
}

fn fact_scope_columns(scope: &FactScope) -> (&'static str, &str, &FactId) {
    match scope {
        FactScope::Global => ("global", "", &EMPTY_FACT_ID),
        FactScope::Local => ("local", "", &EMPTY_FACT_ID),
        FactScope::Scoped { kind, id } => ("scoped", kind.as_str(), id),
    }
}

fn incoming_ready_sql(select: &str, suffix: &str) -> Result<String, String> {
    let incoming_facts = quoted_table_name(INCOMING_FACTS).map_err(|err| err.to_string())?;
    let context_edges = quoted_table_name(CONTEXT_EDGES).map_err(|err| err.to_string())?;
    let pending_matches =
        quoted_table_name(PENDING_PROJECTION_MATCHES).map_err(|err| err.to_string())?;
    Ok(format!(
        r#"
        SELECT {select}
        FROM {incoming_facts} e
        WHERE NOT EXISTS (
                SELECT 1
                FROM {context_edges} n
                WHERE n.owner = e.id
                  AND n.direction = 'need'
            )
           OR EXISTS (
                SELECT 1
                FROM {pending_matches} m
                WHERE m.owner = e.id
            )
        {suffix}
        "#
    ))
}

fn fact_by_id_in_tx(db: &Db, id: &FactId) -> rusqlite::Result<Option<Fact>> {
    fact_by_id_from(db, FactReadSource::Retained, id)
}

fn incoming_fact_by_id_in_tx(db: &Db, id: &FactId) -> rusqlite::Result<Option<Fact>> {
    fact_by_id_from(db, FactReadSource::Incoming, id)
}

fn fact_by_id_from(db: &Db, source: FactReadSource, id: &FactId) -> rusqlite::Result<Option<Fact>> {
    db.conn()
        .query_row(
            source.select_by_id_sql(),
            params![id.as_slice()],
            fact_from_sql_row,
        )
        .optional()
}

fn fact_bytes_by_id_in_tx(db: &Db, id: &FactId) -> rusqlite::Result<Option<Vec<u8>>> {
    db.conn()
        .query_row(
            "SELECT bytes FROM facts WHERE id = ?1 LIMIT 1",
            params![id.as_slice()],
            |row| row.get(0),
        )
        .optional()
}

fn fact_from_sql_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Fact> {
    let id = fact_id_column(row.get::<_, Vec<u8>>(0)?, "id")?;
    let scope_tag = row.get::<_, String>(1)?;
    let scope_kind = row.get::<_, String>(2)?;
    let scope_id = fact_id_column(row.get::<_, Vec<u8>>(3)?, "scope_id")?;
    let timestamp = u64_column(row.get::<_, i64>(4)?, "received_at")?;
    let bytes = row.get::<_, Vec<u8>>(5)?;
    let scope = decode_fact_scope_columns(&scope_tag, &scope_kind, &scope_id)?;
    if fact_id(&bytes) != id {
        return Err(fact_db_error("fact row key does not match fact bytes"));
    }
    Ok(Fact {
        id,
        scope,
        timestamp,
        bytes,
    })
}

fn decode_fact_scope_columns(
    scope: &str,
    scope_kind: &str,
    scope_id: &FactId,
) -> rusqlite::Result<FactScope> {
    match scope {
        "global" | "local" => {
            if !scope_kind.is_empty() || scope_id != &EMPTY_FACT_ID {
                return Err(fact_db_error(format!(
                    "{scope} fact scope has scoped columns set"
                )));
            }
            Ok(if scope == "global" {
                FactScope::Global
            } else {
                FactScope::Local
            })
        }
        "scoped" => Ok(FactScope::Scoped {
            kind: ScopeKind::new(scope_kind.to_string()).map_err(fact_db_error)?,
            id: *scope_id,
        }),
        other => Err(fact_db_error(format!("invalid fact scope {other:?}"))),
    }
}

fn fact_id_column(bytes: Vec<u8>, name: &str) -> rusqlite::Result<FactId> {
    bytes
        .try_into()
        .map_err(|_| fact_db_error(format!("fact SQL column {name} is not a fact id")))
}

fn u64_column(value: i64, name: &str) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| fact_db_error(format!("fact SQL column {name} is negative")))
}

fn delete_rows_by_owner_in_tx(db: &Db, table: TableName, owner: FactId) -> rusqlite::Result<usize> {
    delete_rows_by_blob_column_in_tx(db, table, "owner", owner.as_slice())
}

fn delete_rows_by_blob_column_in_tx(
    db: &Db,
    table: TableName,
    column: &str,
    value: &[u8],
) -> rusqlite::Result<usize> {
    let table = quoted_table_name(table)?;
    let column = quoted_identifier(column)?;
    db.conn().execute(
        &format!("DELETE FROM {table} WHERE {column} = ?1"),
        params![value],
    )
}

fn delete_owner_rows_from_tables(
    db: &Db,
    tables: &[TableName],
    owner: FactId,
) -> rusqlite::Result<usize> {
    let mut deleted = 0usize;
    for table in tables {
        deleted += delete_rows_by_owner_in_tx(db, *table, owner)?;
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::schema::CORE_SCHEMA_SOURCE;

    #[test]
    fn duplicate_fact_bytes_are_idempotent_even_with_different_local_admissions() {
        let db = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let first = Fact::new(FactScope::Global, 1, b"same fact bytes".to_vec());
        let duplicate = Fact::new(FactScope::Local, 2, first.bytes.clone());
        assert_eq!(first.id, duplicate.id);

        db.write_transaction(|tx| {
            assert!(insert_fact_and_pending_in_tx(tx, &first)?);
            assert!(!insert_fact_and_pending_in_tx(tx, &duplicate)?);
            Ok(())
        })
        .expect("insert duplicate fact bytes");

        assert_eq!(
            persisted_fact(&db, &first.id).expect("load fact"),
            Some(first)
        );
    }

    #[test]
    fn incoming_pending_ids_treat_pending_matches_as_ready() {
        let db = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let ready = Fact::new(FactScope::Local, 1, b"ready incoming".to_vec());
        let blocked = Fact::new(FactScope::Local, 2, b"blocked incoming".to_vec());

        db.write_transaction(|tx| {
            insert_incoming_fact_in_tx(tx, &ready)?;
            insert_incoming_fact_in_tx(tx, &blocked)?;
            tx.conn().execute(
                "INSERT INTO context_edges
                    (owner, direction, role, scope_key, start_key, end_key)
                 VALUES (?1, 'need', 'incoming_context', ?2, ?3, ?4)",
                params![
                    blocked.id.as_slice(),
                    b"scope".as_slice(),
                    b"a".as_slice(),
                    b"z".as_slice()
                ],
            )?;
            Ok(())
        })
        .expect("seed incoming facts");

        assert_eq!(
            incoming_pending_fact_ids(&db, 10).expect("pending incoming ids"),
            vec![ready.id]
        );

        db.conn()
            .execute(
                "INSERT INTO pending_projection_matches
                    (owner, need_role, need_scope_key, need_start_key, need_end_key,
                     offer_owner, offer_start_key, offer_end_key)
                 VALUES (?1, 'incoming_context', ?2, ?3, ?4, ?5, ?3, ?4)",
                params![
                    blocked.id.as_slice(),
                    b"scope".as_slice(),
                    b"a".as_slice(),
                    b"z".as_slice(),
                    ready.id.as_slice()
                ],
            )
            .expect("record pending match");

        assert_eq!(
            incoming_pending_fact_ids(&db, 10).expect("matched incoming ids"),
            vec![ready.id, blocked.id]
        );
    }

    #[test]
    fn delete_incoming_fact_clears_owner_keyed_runtime_rows() {
        let db = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let fact = Fact::new(FactScope::Local, 1, b"incoming cleanup".to_vec());
        let offer = Fact::new(FactScope::Local, 2, b"incoming offer".to_vec());

        db.write_transaction(|tx| {
            insert_incoming_fact_in_tx(tx, &fact)?;
            seed_owner_keyed_fact_rows(tx, fact.id, offer.id)
        })
        .expect("seed incoming owner rows");
        assert_owner_keyed_fact_rows(&db, fact.id, 1);

        assert!(db
            .write_transaction(|tx| delete_incoming_fact_in_tx(tx, fact.id))
            .expect("delete incoming fact"));

        assert!(incoming_fact_by_id_in_tx(&db, &fact.id)
            .expect("load incoming fact")
            .is_none());
        assert_owner_keyed_fact_rows(&db, fact.id, 0);
    }

    #[test]
    fn purge_fact_clears_owner_keyed_and_offer_keyed_runtime_rows() {
        let db = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let fact = Fact::new(FactScope::Local, 1, b"retained cleanup".to_vec());
        let other = Fact::new(FactScope::Local, 2, b"other retained".to_vec());

        db.write_transaction(|tx| {
            insert_retained_fact_in_tx(tx, &fact)?;
            seed_owner_keyed_fact_rows(tx, fact.id, other.id)?;
            seed_pending_match(tx, other.id, fact.id)
        })
        .expect("seed retained owner rows");
        assert_owner_keyed_fact_rows(&db, fact.id, 1);
        assert_eq!(pending_match_offer_count(&db, fact.id), 1);

        assert!(db
            .write_transaction(|tx| purge_fact_in_tx(tx, fact.id))
            .expect("purge fact"));

        assert!(fact_bytes_by_id_in_tx(&db, &fact.id)
            .expect("load retained fact")
            .is_none());
        assert_owner_keyed_fact_rows(&db, fact.id, 0);
        assert_eq!(pending_match_offer_count(&db, fact.id), 0);
    }

    fn seed_owner_keyed_fact_rows(
        db: &Db,
        owner: FactId,
        offer_owner: FactId,
    ) -> rusqlite::Result<()> {
        db.conn().execute(
            "INSERT INTO context_edges
                (owner, direction, role, scope_key, start_key, end_key)
             VALUES (?1, 'need', 'cleanup_role', ?2, ?3, ?4)",
            params![
                owner.as_slice(),
                b"scope".as_slice(),
                b"a".as_slice(),
                b"z".as_slice()
            ],
        )?;
        db.conn().execute(
            "INSERT INTO time_wakes (timeline, at, owner)
             VALUES ('cleanup_timeline', 1, ?1)",
            params![owner.as_slice()],
        )?;
        db.conn().execute(
            "INSERT INTO pending_time_ranges
                (owner, timeline, has_start, start_exclusive, end_inclusive)
             VALUES (?1, 'cleanup_timeline', 0, 0, 1)",
            params![owner.as_slice()],
        )?;
        db.conn().execute(
            "INSERT INTO pending_projection (owner, mode)
             VALUES (?1, 'normal')",
            params![owner.as_slice()],
        )?;
        seed_pending_match(db, owner, offer_owner)
    }

    fn seed_pending_match(db: &Db, owner: FactId, offer_owner: FactId) -> rusqlite::Result<()> {
        db.conn().execute(
            "INSERT INTO pending_projection_matches
                (owner, need_role, need_scope_key, need_start_key, need_end_key,
                 offer_owner, offer_start_key, offer_end_key)
             VALUES (?1, 'cleanup_role', ?2, ?3, ?4, ?5, ?3, ?4)",
            params![
                owner.as_slice(),
                b"scope".as_slice(),
                b"a".as_slice(),
                b"z".as_slice(),
                offer_owner.as_slice()
            ],
        )?;
        Ok(())
    }

    fn assert_owner_keyed_fact_rows(db: &Db, owner: FactId, expected: i64) {
        for table in OWNER_KEYED_FACT_CLEANUP_TABLES {
            assert_eq!(
                owner_row_count(db, *table, owner),
                expected,
                "owner rows in {}",
                table.as_str()
            );
        }
    }

    fn owner_row_count(db: &Db, table: TableName, owner: FactId) -> i64 {
        let table = quoted_table_name(table).expect("quote table");
        db.conn()
            .query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE owner = ?1"),
                params![owner.as_slice()],
                |row| row.get(0),
            )
            .expect("count owner rows")
    }

    fn pending_match_offer_count(db: &Db, offer_owner: FactId) -> i64 {
        db.conn()
            .query_row(
                "SELECT COUNT(*) FROM pending_projection_matches WHERE offer_owner = ?1",
                params![offer_owner.as_slice()],
                |row| row.get(0),
            )
            .expect("count offer rows")
    }
}

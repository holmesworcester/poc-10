//! Fact storage for the runtime.
//!
//! Facts are immutable, content-addressed rows. This module owns inserting,
//! purging, and reading those rows; pipeline workers decide when those
//! operations should happen.
//!
//! This is the storage companion to `facts.rs` and the entry point used by the
//! projection pipeline. Inserting a new fact writes both the durable byte row
//! and the local admission row, then marks the fact pending so projection can
//! derive runtime state from it. Reading a fact reconstructs the protocol bytes
//! together with the local scope and timestamp that this store recorded at
//! admission time.
//!
//! The important split is `facts` versus `local_fact_admissions`. `facts`
//! stores bytes by content id. `local_fact_admissions` records how this store
//! first admitted those bytes: scope, admission timestamp, and the derived
//! local admission id used for ordering. That admission record is local
//! runtime metadata, not a protocol fact to sync.
//!
//! Purge is the reverse boundary. It removes the byte row and every core-owned
//! row keyed by the fact id: local admission, standing context, time wakes,
//! pending time ranges, and pending projection. Protocol-owned rows that refer
//! to the fact are removed by emitted row mutations or protocol handlers, not
//! by this generic storage module.
//!
//! If the content-addressing rule, admission ordering, or purge fanout changes,
//! change it here. If a protocol wants to interpret the fact bytes, that logic
//! belongs in the protocol fact module and its projector.

use crate::core::facts::{fact_id, Fact, FactId, FactScope, ScopeKind};
use crate::core::schema::EPHEMERAL_PROJECTION_INPUTS;
use crate::core::store::Store;
use crate::core::wire::Writer;
use rusqlite::{params, OptionalExtension};

// === Durable mutations ===

/// Insert a fact and mark it pending for projection.
///
/// Facts are immutable and content-addressed. The fact bytes live in `facts`;
/// the local admission record is a separate local-only fact about those bytes.
/// Returns whether either row was newly inserted.
pub(crate) fn insert_fact_and_pending_in_tx(store: &Store, fact: &Fact) -> rusqlite::Result<bool> {
    let inserted = insert_fact_in_tx(store, fact)?;
    if inserted {
        insert_pending_owner_in_tx(store, fact.id)?;
    }
    Ok(inserted)
}

/// Mark `owner` pending so the next projection pass (re)projects it.
pub(crate) fn insert_pending_owner_in_tx(store: &Store, owner: FactId) -> rusqlite::Result<usize> {
    store.conn().execute(
        "INSERT OR IGNORE INTO pending_projection (owner) VALUES (?1)",
        params![owner.as_slice()],
    )
}

/// Insert a runtime-local projectable input.
///
/// Ephemeral inputs use the `Fact` container for id, scope, timestamp, and
/// bytes, but they are not inserted into durable `facts` or
/// `local_fact_admissions`. Projection may read durable context and emit durable
/// facts, then the input row is removed according to the projection decision.
pub(crate) fn insert_ephemeral_fact_in_tx(store: &Store, fact: &Fact) -> rusqlite::Result<bool> {
    let (scope, scope_kind, scope_id) = fact_scope_columns(&fact.scope);
    let changed = store.conn().execute(
        "INSERT OR IGNORE INTO ephemeral_projection_inputs
            (id, scope, scope_kind, scope_id, received_at, bytes)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            fact.id.as_slice(),
            scope,
            scope_kind,
            scope_id.as_slice(),
            sqlite_u64(fact.timestamp, "ephemeral fact received_at")?,
            fact.bytes.as_slice()
        ],
    )?;
    if changed == 0 {
        let existing = ephemeral_fact_by_id_in_tx(store, &fact.id)?;
        if existing.as_ref() != Some(fact) {
            return Err(rusqlite::Error::InvalidParameterName(
                "conflicting row for ephemeral projection input".to_string(),
            ));
        }
    }
    Ok(changed > 0)
}

pub(crate) fn delete_ephemeral_fact_in_tx(store: &Store, owner: FactId) -> rusqlite::Result<bool> {
    Ok(store.conn().execute(
        "DELETE FROM ephemeral_projection_inputs WHERE id = ?1",
        params![owner.as_slice()],
    )? > 0)
}

/// Remove a fact and every durable row keyed to it.
///
/// Deletes the fact bytes, its local admission fact, its context edges, its time
/// wakes, any pending time-range rows it owns, and its pending-projection
/// marker. Returns whether anything was actually removed.
pub(crate) fn purge_fact_in_tx(store: &Store, owner: FactId) -> rusqlite::Result<bool> {
    let mut changed = store
        .conn()
        .execute("DELETE FROM facts WHERE id = ?1", params![owner.as_slice()])?
        > 0;
    for sql in [
        "DELETE FROM local_fact_admissions WHERE fact_id = ?1",
        "DELETE FROM context_edges WHERE owner = ?1",
        "DELETE FROM time_wakes WHERE owner = ?1",
        "DELETE FROM pending_time_ranges WHERE owner = ?1",
    ] {
        changed |= store.conn().execute(sql, params![owner.as_slice()])? > 0;
    }
    changed |= store.conn().execute(
        "DELETE FROM pending_projection WHERE owner = ?1",
        params![owner.as_slice()],
    )? > 0;
    Ok(changed)
}

fn insert_fact_in_tx(store: &Store, fact: &Fact) -> rusqlite::Result<bool> {
    let changed = store.conn().execute(
        "INSERT OR IGNORE INTO facts (id, bytes) VALUES (?1, ?2)",
        params![fact.id.as_slice(), fact.bytes.as_slice()],
    )?;
    if changed == 0 {
        let existing = fact_bytes_by_id_in_tx(store, &fact.id)?;
        if existing.as_deref() != Some(fact.bytes.as_slice()) {
            return Err(rusqlite::Error::InvalidParameterName(
                "conflicting row for facts".to_string(),
            ));
        }
    }
    let admitted = insert_local_fact_admission_in_tx(store, fact)? > 0;
    Ok(changed > 0 || admitted)
}

fn insert_local_fact_admission_in_tx(store: &Store, fact: &Fact) -> rusqlite::Result<usize> {
    let (scope, scope_kind, scope_id) = fact_scope_columns(&fact.scope);
    let received_at = sqlite_u64(fact.timestamp, "fact received_at")?;
    let bytes = local_fact_admission_bytes(fact)?;
    let id = fact_id(&bytes);
    store.conn().execute(
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
    rusqlite::Error::InvalidParameterName(format!("local fact admission {field}: {err}"))
}

fn fact_scope_columns(scope: &FactScope) -> (&'static str, &str, &FactId) {
    match scope {
        FactScope::Global => ("global", "", &EMPTY_FACT_ID),
        FactScope::Local => ("local", "", &EMPTY_FACT_ID),
        FactScope::Scoped { kind, id } => ("scoped", kind.as_str(), id),
    }
}

// === Reading and decoding rows ===

/// Load a fact by id, returning `None` when no such fact is stored.
pub fn persisted_fact(store: &Store, id: &FactId) -> Result<Option<Fact>, String> {
    fact_by_id_in_tx(store, id).map_err(|err| format!("load fact row: {err}"))
}

/// Load every stored fact.
pub fn persisted_facts(store: &Store) -> Result<Vec<Fact>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT f.id, m.scope, m.scope_kind, m.scope_id, m.received_at, f.bytes
             FROM facts f
             JOIN local_fact_admissions m ON m.fact_id = f.id
             ORDER BY f.id",
        )
        .map_err(|err| format!("load fact rows: {err}"))?;
    let rows = stmt
        .query_map([], fact_from_sql_row)
        .map_err(|err| format!("load fact rows: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("load fact rows: {err}"))
}

pub(crate) fn ephemeral_pending_fact_ids(
    store: &Store,
    limit: usize,
) -> Result<Vec<FactId>, String> {
    let limit =
        i64::try_from(limit).map_err(|_| "ephemeral projection limit exceeds i64".to_string())?;
    let mut stmt = store
        .conn()
        .prepare(&format!(
            "SELECT id FROM {} ORDER BY received_at, id LIMIT ?1",
            EPHEMERAL_PROJECTION_INPUTS.as_str()
        ))
        .map_err(|err| format!("load ephemeral projection inputs: {err}"))?;
    let rows = stmt
        .query_map(params![limit], |row| {
            fact_id_column(row.get::<_, Vec<u8>>(0)?, "ephemeral id")
        })
        .map_err(|err| format!("load ephemeral projection inputs: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("load ephemeral projection inputs: {err}"))
}

pub(crate) fn ephemeral_fact_by_id(store: &Store, id: &FactId) -> Result<Option<Fact>, String> {
    ephemeral_fact_by_id_in_tx(store, id)
        .map_err(|err| format!("load ephemeral projection input: {err}"))
}

fn fact_by_id_in_tx(store: &Store, id: &FactId) -> rusqlite::Result<Option<Fact>> {
    store
        .conn()
        .query_row(
            "SELECT f.id, m.scope, m.scope_kind, m.scope_id, m.received_at, f.bytes
             FROM facts f
             JOIN local_fact_admissions m ON m.fact_id = f.id
             WHERE f.id = ?1
             LIMIT 1",
            params![id.as_slice()],
            fact_from_sql_row,
        )
        .optional()
}

fn ephemeral_fact_by_id_in_tx(store: &Store, id: &FactId) -> rusqlite::Result<Option<Fact>> {
    store
        .conn()
        .query_row(
            "SELECT id, scope, scope_kind, scope_id, received_at, bytes
             FROM ephemeral_projection_inputs
             WHERE id = ?1
             LIMIT 1",
            params![id.as_slice()],
            fact_from_sql_row,
        )
        .optional()
}

fn fact_bytes_by_id_in_tx(store: &Store, id: &FactId) -> rusqlite::Result<Option<Vec<u8>>> {
    store
        .conn()
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
        return Err(rusqlite::Error::InvalidParameterName(
            "fact row key does not match fact bytes".to_string(),
        ));
    }
    Ok(Fact {
        id,
        scope,
        timestamp,
        bytes,
    })
}

/// Rebuild a [`FactScope`] from the admission fact's three scope columns.
fn decode_fact_scope_columns(
    scope: &str,
    scope_kind: &str,
    scope_id: &FactId,
) -> rusqlite::Result<FactScope> {
    match scope {
        "global" | "local" => {
            if !scope_kind.is_empty() || scope_id != &EMPTY_FACT_ID {
                return Err(rusqlite::Error::InvalidParameterName(format!(
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
            kind: ScopeKind::new(scope_kind.to_string())
                .map_err(rusqlite::Error::InvalidParameterName)?,
            id: *scope_id,
        }),
        other => Err(rusqlite::Error::InvalidParameterName(format!(
            "invalid fact scope {other:?}"
        ))),
    }
}

fn fact_id_column(bytes: Vec<u8>, name: &str) -> rusqlite::Result<FactId> {
    bytes.try_into().map_err(|_| {
        rusqlite::Error::InvalidParameterName(format!("fact SQL column {name} is not a fact id"))
    })
}

fn u64_column(value: i64, name: &str) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| {
        rusqlite::Error::InvalidParameterName(format!("fact SQL column {name} is negative"))
    })
}

fn sqlite_u64(value: u64, name: &str) -> rusqlite::Result<i64> {
    i64::try_from(value).map_err(|_| {
        rusqlite::Error::InvalidParameterName(format!("{name} exceeds SQLite integer range"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::schema::CORE_SCHEMA_SOURCE;

    #[test]
    fn duplicate_fact_bytes_are_idempotent_even_with_different_local_admissions() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open store");
        let first = Fact::new(FactScope::Global, 1, b"same fact bytes".to_vec());
        let duplicate = Fact::new(FactScope::Local, 2, first.bytes.clone());
        assert_eq!(first.id, duplicate.id);

        store
            .write_transaction(|tx| {
                assert!(insert_fact_and_pending_in_tx(tx, &first)?);
                assert!(!insert_fact_and_pending_in_tx(tx, &duplicate)?);
                Ok(())
            })
            .expect("insert duplicate fact bytes");

        assert_eq!(
            persisted_fact(&store, &first.id).expect("load fact"),
            Some(first)
        );
    }
}

/// The all-zero [`FactId`] stored in the scope columns of non-scoped facts.
const EMPTY_FACT_ID: FactId = [0u8; 32];

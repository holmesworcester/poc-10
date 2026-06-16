//! A small SQLite-backed row store.
//!
//! Store is the lowest runtime layer above SQLite. It knows how to apply SQL
//! schema batches, run transactions, read or write keyed byte rows, and persist
//! protocol-neutral fact bytes plus local admission metadata. It does not know
//! protocol-specific meanings: fact families, payload tags, validation rules,
//! network targets, and sync work are all layered on top of these primitives.
//!
//! There are two row shapes in the project. Typed tables declare their own SQL
//! columns and are usually queried by the module that owns them, with store
//! supplying small table/column helpers for mechanical reads and deletes.
//! Opaque row tables use the generic `(row_key, row_value)` shape and flow
//! through the helpers in this file. `SchemaSource::row_tables` is the allowlist
//! that tells store which opaque tables are safe for those helpers; it is not a
//! semantic registry.
//!
//! The critical path is short:
//! 1. Open a store with the SQL schema batches declared by core IO and the
//!    selected protocol's module scopes.
//! 2. Use `write_transaction` to group rows that must become visible together.
//! 3. Use row helpers for opaque row tables, typed-table helpers for simple
//!    table/column operations, and fact helpers for content-addressed bytes.
//!
//! All atomicity comes from callers choosing the transaction closure. Store
//! supplies `BEGIN IMMEDIATE`, rollback, quoting, allowlist checks, and
//! idempotent opaque-row inserts. It should stay below fact-type decoding,
//! context matching, intent dispatch, and protocol validation.
//!
//! The dynamic SQL in this file is table-name interpolation for row operations,
//! replay reset, intent work selection, fact queue scans, and state-summary
//! hashing. Values are always bound parameters, and table names are accepted
//! only from `TableName` after a conservative identifier check.

use crate::core::facts::{fact_id, Fact, FactId, FactScope, ScopeKind};
use crate::core::project_fact::ProjectionMode;
use crate::core::row_schema::RowTableSchema;
use crate::core::schema::{
    CONTEXT_EDGES, FACTS, INCOMING_FACTS, INTENTS, LOCAL_FACT_ADMISSIONS, LOCAL_INTENTS,
    PENDING_PROJECTION, PENDING_PROJECTION_MATCHES, PENDING_TIME_RANGES, TIME_WAKES,
};
use crate::core::wire::Writer;
use rusqlite::{
    params, params_from_iter, types::ValueRef, Connection as SqliteConnection, OptionalExtension,
};
use std::path::Path;
use std::time::Duration;

/// A static, trusted row-table name.
///
/// Protocol and core IO modules declare these names next to the row encoders
/// that understand their values. Store validates the identifier before using
/// it in SQL, then treats rows as opaque bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TableName(&'static str);

impl TableName {
    /// Build a trusted static table name.
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    /// Return the raw table name.
    pub fn as_str(self) -> &'static str {
        self.0
    }
}

/// Replay lifecycle declarations for tables created by one schema source.
///
/// `protected` tables are retained fact-store tables and are never cleared by
/// replay. `reset` tables are derived, queued, or local runtime state that
/// replay can clear before rebuilding. `summary` tables are hashed by
/// replay-check.
#[derive(Debug, Clone, Copy)]
pub struct ReplayTables {
    /// Retained fact-store tables that replay reset must not clear.
    pub protected: &'static [TableName],
    /// Tables cleared by replay reset.
    pub reset: &'static [TableName],
    /// Tables included in replay-check state summaries.
    pub summary: &'static [TableName],
}

impl ReplayTables {
    /// Empty replay lifecycle declarations for tests and non-replay schemas.
    pub const EMPTY: Self = Self {
        protected: &[],
        reset: &[],
        summary: &[],
    };
}

/// One executable schema batch plus the opaque row tables it declares.
///
/// Typed tables live entirely in `ddl`. The `row_tables` list is only the
/// allowlist for the remaining `TableRow` helpers; it does not validate table
/// shape on open.
#[derive(Debug, Clone, Copy)]
pub struct SchemaSource {
    /// SQL batch applied when the store opens.
    pub ddl: &'static str,
    /// Opaque row tables this source makes available to row helpers.
    pub row_tables: &'static [TableName],
    /// Schema-backed opaque row tables this source makes available to row
    /// helpers. These are the migration target for handwritten `rows.rs`
    /// modules; store still persists them through the same key/value boundary.
    pub row_schemas: &'static [RowTableSchema],
    /// Replay reset and summary lifecycle declarations for this source's
    /// tables.
    pub replay: ReplayTables,
}

/// Quote a declared table name after rejecting unsafe identifier bytes.
pub(crate) fn quoted_table_name(table: TableName) -> rusqlite::Result<String> {
    quoted_table_name_str(table.as_str())
}

/// Quote a table name string after rejecting unsafe identifier bytes.
pub(crate) fn quoted_table_name_str(name: &str) -> rusqlite::Result<String> {
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
    {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "invalid table name {name}"
        )));
    }
    Ok(format!("\"{name}\""))
}

/// Quote one SQL identifier after rejecting unsafe identifier bytes.
pub(crate) fn quoted_identifier(name: &str) -> rusqlite::Result<String> {
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "invalid identifier {name}"
        )));
    }
    Ok(format!("\"{name}\""))
}

/// Quote and comma-join SQL identifiers.
pub(crate) fn quoted_identifier_list<I, S>(columns: I) -> rusqlite::Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    columns
        .into_iter()
        .map(|column| quoted_identifier(column.as_ref()))
        .collect::<rusqlite::Result<Vec<_>>>()
        .map(|columns| columns.join(", "))
}

/// One opaque key/value row in one declared table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableRow {
    /// Declared opaque row table.
    pub table: TableName,
    /// Opaque row key.
    pub key: Vec<u8>,
    /// Opaque row value.
    pub value: Vec<u8>,
}

/// One raw row in the durable or local intent work table.
///
/// Store owns the idempotent SQL shape for these rows. `core::intents` owns
/// converting between this mechanical form and an `Intent`, and
/// `handle_intent` owns queue precedence, retry, and handler semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IntentWorkRow {
    pub(crate) kind: String,
    pub(crate) idempotence_key: Vec<u8>,
    pub(crate) payload: Vec<u8>,
}

impl IntentWorkRow {
    pub(crate) fn new(
        kind: impl Into<String>,
        idempotence_key: impl Into<Vec<u8>>,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            kind: kind.into(),
            idempotence_key: idempotence_key.into(),
            payload: payload.into(),
        }
    }
}

/// Ordering policy for selecting the next raw intent work row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IntentWorkRowOrder {
    /// Stable identity order for durable, replayable work.
    StableIdentity,
    /// SQLite insertion order for process-local ephemeral work.
    Insertion,
}

fn store_error(message: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(message.into())
}

fn prefix_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut upper = prefix.to_vec();
    let idx = upper.iter().rposition(|byte| *byte != u8::MAX)?;
    upper[idx] += 1;
    upper.truncate(idx + 1);
    Some(upper)
}

fn sqlite_limit(limit: usize) -> i64 {
    // Callers use usize::MAX for unbounded scans; SQLite treats LIMIT -1 as no limit.
    i64::try_from(limit).unwrap_or(-1)
}

fn unique_table_names(tables: impl IntoIterator<Item = TableName>) -> Vec<TableName> {
    let mut unique = Vec::new();
    for table in tables {
        if !unique.contains(&table) {
            unique.push(table);
        }
    }
    unique
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
            return Err(store_error(conflict_message));
        }
    }
    Ok(changed > 0)
}

fn quoted_intent_work_table_name(table: TableName) -> rusqlite::Result<String> {
    if table == INTENTS || table == LOCAL_INTENTS {
        quoted_table_name(table)
    } else {
        Err(store_error(format!(
            "table {} is not an intent work table",
            table.as_str()
        )))
    }
}

fn validate_replay_lifecycle(protected: &[TableName], reset: &[TableName]) -> rusqlite::Result<()> {
    for table in reset {
        if protected.contains(table) {
            return Err(store_error(format!(
                "table {} cannot be both replay-protected and replay-resettable",
                table.as_str()
            )));
        }
    }
    Ok(())
}

fn hash_cell(hasher: &mut blake3::Hasher, value: ValueRef<'_>) {
    match value {
        ValueRef::Null => hasher.update(&[0u8]),
        ValueRef::Integer(int) => {
            hasher.update(&[1u8]);
            hasher.update(&int.to_le_bytes())
        }
        ValueRef::Real(real) => {
            hasher.update(&[2u8]);
            hasher.update(&real.to_bits().to_le_bytes())
        }
        ValueRef::Text(text) => {
            hasher.update(&[3u8]);
            hasher.update(&(text.len() as u64).to_le_bytes());
            hasher.update(text)
        }
        ValueRef::Blob(blob) => {
            hasher.update(&[4u8]);
            hasher.update(&(blob.len() as u64).to_le_bytes());
            hasher.update(blob)
        }
    };
}

/// The only durable substrate core offers protocol code.
///
/// Durable and memory tables are both ordinary SQLite tables on this one
/// connection; memory tables are `TEMP` tables. Every row helper is therefore a
/// single SQL path, and `write_transaction` rollback covers both classes.
pub struct Store {
    conn: SqliteConnection,
    row_tables: Vec<TableName>,
    row_schemas: Vec<RowTableSchema>,
    replay_protected_tables: Vec<TableName>,
    replay_reset_tables: Vec<TableName>,
    replay_summary_tables: Vec<TableName>,
}

/// Canonical digest of one declared table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableSummary {
    /// Table name owning this area.
    pub table: String,
    /// Canonical hash of the table's rows.
    pub hash: [u8; 32],
    /// Row count in the table.
    pub count: usize,
}

impl Store {
    /// Expose the underlying SQLite connection to core modules that own their
    /// table SQL directly.
    pub(crate) fn conn(&self) -> &SqliteConnection {
        &self.conn
    }

    /// Open a disk store and apply SQL schema sources.
    pub fn open_disk_with_schema_sources(
        path: impl AsRef<Path>,
        sources: &[SchemaSource],
    ) -> rusqlite::Result<Self> {
        let conn = SqliteConnection::open(path)?;
        Self::from_connection_with_schema_sources(conn, sources)
    }

    /// Open an in-memory store without creating any protocol tables.
    pub fn open_memory() -> rusqlite::Result<Self> {
        Self::open_memory_with_schema_sources(&[])
    }

    /// Open an in-memory store and apply SQL schema sources.
    pub fn open_memory_with_schema_sources(sources: &[SchemaSource]) -> rusqlite::Result<Self> {
        let conn = SqliteConnection::open_in_memory()?;
        Self::from_connection_with_schema_sources(conn, sources)
    }

    fn from_connection_with_schema_sources(
        conn: SqliteConnection,
        sources: &[SchemaSource],
    ) -> rusqlite::Result<Self> {
        let row_tables = unique_table_names(sources.iter().flat_map(|source| {
            source
                .row_tables
                .iter()
                .copied()
                .chain(source.row_schemas.iter().map(|schema| schema.table))
        }));
        let row_schemas = sources
            .iter()
            .flat_map(|source| source.row_schemas.iter().copied())
            .collect();
        let replay_protected_tables = unique_table_names(
            sources
                .iter()
                .flat_map(|source| source.replay.protected.iter().copied()),
        );
        let replay_reset_tables = unique_table_names(
            sources
                .iter()
                .flat_map(|source| source.replay.reset.iter().copied()),
        );
        let replay_summary_tables = unique_table_names(
            sources
                .iter()
                .flat_map(|source| source.replay.summary.iter().copied()),
        );
        validate_replay_lifecycle(&replay_protected_tables, &replay_reset_tables)?;
        let store = Self::from_connection_parts(
            conn,
            row_tables,
            row_schemas,
            replay_protected_tables,
            replay_reset_tables,
            replay_summary_tables,
        )?;
        for source in sources {
            store.conn.execute_batch(source.ddl)?;
        }
        Ok(store)
    }

    fn from_connection_parts(
        conn: SqliteConnection,
        row_tables: Vec<TableName>,
        row_schemas: Vec<RowTableSchema>,
        replay_protected_tables: Vec<TableName>,
        replay_reset_tables: Vec<TableName>,
        replay_summary_tables: Vec<TableName>,
    ) -> rusqlite::Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )?;
        Ok(Self {
            conn,
            row_tables,
            row_schemas,
            replay_protected_tables,
            replay_reset_tables,
            replay_summary_tables,
        })
    }

    /// Schema-backed opaque row declarations registered for this store.
    pub fn row_schemas(&self) -> &[RowTableSchema] {
        &self.row_schemas
    }

    /// Tables protected from replay reset.
    pub fn replay_protected_tables(&self) -> &[TableName] {
        &self.replay_protected_tables
    }

    /// Tables replay reset is allowed to clear.
    pub fn replay_reset_tables(&self) -> &[TableName] {
        &self.replay_reset_tables
    }

    /// Tables replay-check hashes as protocol/runtime state.
    pub fn replay_summary_tables(&self) -> &[TableName] {
        &self.replay_summary_tables
    }

    /// Clear every schema-declared replay-resettable table.
    ///
    /// Replay callers do not provide a keep-list. Protected tables are excluded
    /// by construction when the store opens, so retained fact storage cannot be
    /// cleared by a replay bug in a caller.
    pub fn clear_replay_reset_tables(&self) -> Result<usize, String> {
        self.write_transaction(|tx| {
            let mut cleared = 0usize;
            for table in &self.replay_reset_tables {
                let quoted = quoted_table_name(*table)?;
                tx.conn.execute(&format!("DELETE FROM {quoted}"), [])?;
                cleared += 1;
            }
            Ok(cleared)
        })
        .map_err(|err| format!("clear replay reset tables: {err}"))
    }

    /// Hash every schema-declared replay-summary table.
    pub fn replay_summary_table_hashes(&self) -> Result<Vec<TableSummary>, String> {
        let mut summaries = Vec::with_capacity(self.replay_summary_tables.len());
        for table in &self.replay_summary_tables {
            summaries.push(self.hash_table(*table)?);
        }
        Ok(summaries)
    }

    /// Write a standalone, consistent copy of this store to `path`.
    ///
    /// `VACUUM INTO` produces a single self-contained database file with no WAL
    /// or SHM sidecar, so callers can copy or open the snapshot independently.
    /// Used by replay diagnostics to run replay on scratch databases without
    /// mutating the live store. The path is interpolated as a SQL string literal
    /// because `VACUUM INTO` does not accept bound parameters; embedded quotes are
    /// escaped.
    pub fn backup_into(&self, path: &Path) -> Result<(), String> {
        let target = path
            .to_str()
            .ok_or_else(|| "snapshot path is not valid UTF-8".to_string())?
            .replace('\'', "''");
        self.conn
            .execute_batch(&format!("VACUUM INTO '{target}'"))
            .map_err(|err| format!("snapshot store: {err}"))
    }

    fn quoted_row_table_name(&self, table: TableName) -> rusqlite::Result<String> {
        if !self.row_tables.contains(&table) {
            return Err(store_error(format!(
                "table {} is not an opaque row table",
                table.as_str()
            )));
        }
        quoted_table_name(table)
    }

    // Critical path: callers put every atomic row mutation
    // through this closure, then use the transaction-local row helpers below.
    /// Run a write transaction.
    ///
    /// The closure sees its own writes through the same SQLite handle. Keep
    /// closures narrow: they are where callers express the atomic unit, while
    /// this store only supplies `BEGIN IMMEDIATE` / `COMMIT` / `ROLLBACK`.
    pub fn write_transaction<T>(
        &self,
        apply: impl FnOnce(&Store) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = apply(self);
        match result {
            Ok(value) => match self.conn.execute_batch("COMMIT") {
                Ok(()) => Ok(value),
                Err(err) => {
                    let _ = self.conn.execute_batch("ROLLBACK");
                    Err(err)
                }
            },
            Err(err) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(err)
            }
        }
    }

    // Row writes: these are intentionally table/key/value operations. Any
    // richer meaning belongs to the module that constructed the `TableRow`.
    /// Insert rows idempotently in their declared tables.
    pub fn insert_table_rows(&self, rows: Vec<TableRow>) -> rusqlite::Result<usize> {
        self.write_transaction(|store| store.insert_table_rows_in_tx(rows))
    }

    /// Transaction-local form of `insert_table_rows`.
    pub fn insert_table_rows_in_tx(&self, rows: Vec<TableRow>) -> rusqlite::Result<usize> {
        let mut inserted = 0;
        for row in rows {
            let table_name = self.quoted_row_table_name(row.table)?;
            let changed = self.conn.execute(
                &format!(
                    "INSERT OR IGNORE INTO {table_name}
                        (row_key, row_value)
                     VALUES (?1, ?2)"
                ),
                params![row.key.as_slice(), row.value.as_slice()],
            )?;
            inserted += usize::from(verify_idempotent_insert(
                changed,
                || {
                    self.conn
                        .query_row(
                            &format!("SELECT row_value FROM {table_name} WHERE row_key = ?1"),
                            params![row.key.as_slice()],
                            |row| row.get::<_, Vec<u8>>(0),
                        )
                        .optional()
                },
                |existing| existing.as_slice() == row.value.as_slice(),
                format!("conflicting row for {}", row.table.as_str()),
            )?);
        }
        Ok(inserted)
    }

    /// Delete rows by key from one declared table.
    pub fn delete_table_rows(
        &self,
        table: TableName,
        keys: Vec<Vec<u8>>,
    ) -> rusqlite::Result<usize> {
        self.write_transaction(|store| store.delete_table_rows_in_tx(table, keys))
    }

    /// Transaction-local form of `delete_table_rows`.
    pub fn delete_table_rows_in_tx(
        &self,
        table: TableName,
        keys: Vec<Vec<u8>>,
    ) -> rusqlite::Result<usize> {
        let mut deleted = 0;
        let table_name = self.quoted_row_table_name(table)?;
        for key in keys {
            deleted += self.conn.execute(
                &format!("DELETE FROM {table_name} WHERE row_key = ?1"),
                params![key],
            )?;
        }
        Ok(deleted)
    }

    // Row reads: exact lookup, count, full scan, bounded prefix scan, and
    // bounded key-range scan are the complete read surface core exposes.
    /// Fetch one row value by exact key.
    pub fn table_row(&self, table: TableName, key: &[u8]) -> rusqlite::Result<Option<Vec<u8>>> {
        let table_name = self.quoted_row_table_name(table)?;
        self.conn
            .query_row(
                &format!("SELECT row_value FROM {table_name} WHERE row_key = ?1"),
                params![key],
                |row| row.get(0),
            )
            .optional()
    }

    /// Count rows in one declared typed or opaque table.
    pub fn table_row_count(&self, table: TableName) -> rusqlite::Result<usize> {
        let table_name = quoted_table_name(table)?;
        self.conn
            .query_row(&format!("SELECT COUNT(*) FROM {table_name}"), [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|count| count as usize)
    }

    /// Delete rows from a declared typed table by its `owner` blob column.
    pub(crate) fn delete_rows_by_owner_in_tx(
        &self,
        table: TableName,
        owner: FactId,
    ) -> rusqlite::Result<usize> {
        self.delete_rows_by_blob_column_in_tx(table, "owner", owner.as_slice())
    }

    /// Delete rows from a declared typed table by one blob column.
    pub(crate) fn delete_rows_by_blob_column_in_tx(
        &self,
        table: TableName,
        column: &str,
        value: &[u8],
    ) -> rusqlite::Result<usize> {
        let table = quoted_table_name(table)?;
        let column = quoted_identifier(column)?;
        self.conn.execute(
            &format!("DELETE FROM {table} WHERE {column} = ?1"),
            params![value],
        )
    }

    /// Select rows from a declared typed table by one blob column.
    pub(crate) fn rows_by_blob_column<T>(
        &self,
        table: TableName,
        select_columns: &[&str],
        blob_column: &str,
        blob_value: &[u8],
        order_columns: &[&str],
        decode: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<Vec<T>> {
        if select_columns.is_empty() {
            return Err(rusqlite::Error::InvalidParameterName(
                "typed row select requires at least one column".to_string(),
            ));
        }
        let table = quoted_table_name(table)?;
        let select_columns = quoted_identifier_list(select_columns)?;
        let blob_column = quoted_identifier(blob_column)?;
        let order_clause = if order_columns.is_empty() {
            String::new()
        } else {
            format!(" ORDER BY {}", quoted_identifier_list(order_columns)?)
        };
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {select_columns} FROM {table} WHERE {blob_column} = ?1{order_clause}"
        ))?;
        let rows = stmt.query_map(params![blob_value], decode)?;
        rows.collect()
    }

    /// Insert one raw intent work row idempotently inside the caller's transaction.
    pub(crate) fn insert_intent_work_row_in_tx(
        &self,
        table: TableName,
        row: &IntentWorkRow,
    ) -> rusqlite::Result<bool> {
        let table_name = quoted_intent_work_table_name(table)?;
        let changed = self.conn.execute(
            &format!(
                "INSERT OR IGNORE INTO {table_name} (kind, idempotence_key, payload)
                 VALUES (?1, ?2, ?3)"
            ),
            params![
                row.kind.as_str(),
                row.idempotence_key.as_slice(),
                row.payload.as_slice()
            ],
        )?;
        verify_idempotent_insert(
            changed,
            || {
                self.conn
                    .query_row(
                        &format!(
                            "SELECT payload
                         FROM {table_name}
                         WHERE kind = ?1 AND idempotence_key = ?2"
                        ),
                        params![row.kind.as_str(), row.idempotence_key.as_slice()],
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .optional()
            },
            |existing| existing.as_slice() == row.payload.as_slice(),
            format!("conflicting intent row for {}", row.kind),
        )
    }

    /// Delete one raw intent work row by its idempotent queue identity.
    pub(crate) fn delete_intent_work_row_in_tx(
        &self,
        table: TableName,
        kind: &str,
        idempotence_key: &[u8],
    ) -> rusqlite::Result<usize> {
        let table_name = quoted_intent_work_table_name(table)?;
        self.conn.execute(
            &format!("DELETE FROM {table_name} WHERE kind = ?1 AND idempotence_key = ?2"),
            params![kind, idempotence_key],
        )
    }

    /// Move a local raw intent row to the end of insertion order.
    pub(crate) fn rotate_intent_work_row_to_tail_in_tx(
        &self,
        table: TableName,
        row: &IntentWorkRow,
    ) -> rusqlite::Result<bool> {
        if self.delete_intent_work_row_in_tx(table, &row.kind, &row.idempotence_key)? == 0 {
            return Ok(false);
        }
        self.insert_intent_work_row_in_tx(table, row)?;
        Ok(true)
    }

    /// Select the next raw intent work row for any allowed handler kind.
    pub(crate) fn next_intent_work_row(
        &self,
        table: TableName,
        allowed_kinds: &[&str],
        order: IntentWorkRowOrder,
    ) -> rusqlite::Result<Option<IntentWorkRow>> {
        if allowed_kinds.is_empty() {
            return Ok(None);
        }
        let table_name = quoted_intent_work_table_name(table)?;
        let order = match order {
            IntentWorkRowOrder::StableIdentity => "kind, idempotence_key",
            IntentWorkRowOrder::Insertion => "rowid",
        };
        let placeholders = (1..=allowed_kinds.len())
            .map(|idx| format!("?{idx}"))
            .collect::<Vec<_>>()
            .join(", ");
        self.conn
            .query_row(
                &format!(
                    "SELECT kind, idempotence_key, payload
                     FROM {table_name}
                     WHERE kind IN ({placeholders})
                     ORDER BY {order}
                     LIMIT 1"
                ),
                params_from_iter(allowed_kinds.iter().copied()),
                |row| {
                    Ok(IntentWorkRow {
                        kind: row.get(0)?,
                        idempotence_key: row.get(1)?,
                        payload: row.get(2)?,
                    })
                },
            )
            .optional()
    }

    /// Hash one table's rows canonically, independent of insertion order.
    ///
    /// Rows are ordered by every column so the digest depends only on content,
    /// and each cell is serialized with a type tag so distinct SQLite types
    /// never alias.
    fn hash_table(&self, table: TableName) -> Result<TableSummary, String> {
        let quoted = quoted_table_name(table).map_err(|err| err.to_string())?;
        let columns = self.table_columns(&quoted)?;
        if columns.is_empty() {
            return Err(format!("table {} has no columns to hash", table.as_str()));
        }
        let column_list = quoted_identifier_list(&columns).map_err(|err| err.to_string())?;

        let mut stmt = self
            .conn
            .prepare(&format!(
                "SELECT {column_list} FROM {quoted} ORDER BY {column_list}"
            ))
            .map_err(|err| format!("prepare hash scan for {}: {err}", table.as_str()))?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"topo:store-table-summary:v1");
        hasher.update(&(table.as_str().len() as u64).to_le_bytes());
        hasher.update(table.as_str().as_bytes());
        for column in &columns {
            hasher.update(&(column.len() as u64).to_le_bytes());
            hasher.update(column.as_bytes());
        }

        let column_count = columns.len();
        let mut count = 0usize;
        let mut rows = stmt
            .query([])
            .map_err(|err| format!("scan {}: {err}", table.as_str()))?;
        while let Some(row) = rows
            .next()
            .map_err(|err| format!("scan {}: {err}", table.as_str()))?
        {
            for index in 0..column_count {
                let value = row
                    .get_ref(index)
                    .map_err(|err| format!("read {} cell: {err}", table.as_str()))?;
                hash_cell(&mut hasher, value);
            }
            count += 1;
        }
        Ok(TableSummary {
            table: table.as_str().to_string(),
            hash: *hasher.finalize().as_bytes(),
            count,
        })
    }

    fn table_columns(&self, quoted_table: &str) -> Result<Vec<String>, String> {
        let mut stmt = self
            .conn
            .prepare(&format!("PRAGMA table_info({quoted_table})"))
            .map_err(|err| format!("read columns: {err}"))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|err| format!("read columns: {err}"))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|err| format!("read columns: {err}"))
    }

    /// Scan one declared table in key order.
    pub fn table_rows(&self, table: TableName) -> rusqlite::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let table_name = self.quoted_row_table_name(table)?;
        self.query_key_value_rows(
            &format!(
                "SELECT row_key, row_value FROM {table_name}
                    ORDER BY row_key"
            ),
            [],
        )
    }

    /// Scan one declared table by lexicographic key prefix.
    pub fn table_rows_with_key_prefix(
        &self,
        table: TableName,
        prefix: &[u8],
        limit: usize,
    ) -> rusqlite::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let table_name = self.quoted_row_table_name(table)?;
        let limit = sqlite_limit(limit);
        let Some(upper) = prefix_upper_bound(prefix) else {
            return self.query_key_value_rows(
                &format!(
                    "SELECT row_key, row_value FROM {table_name}
                         WHERE row_key >= ?1
                         ORDER BY row_key
                         LIMIT ?2"
                ),
                params![prefix, limit],
            );
        };
        self.query_key_value_rows(
            &format!(
                "SELECT row_key, row_value FROM {table_name}
                     WHERE row_key >= ?1 AND row_key < ?2
                     ORDER BY row_key
                     LIMIT ?3"
            ),
            params![prefix, upper, limit],
        )
    }

    fn query_key_value_rows<P>(
        &self,
        sql: &str,
        params: P,
    ) -> rusqlite::Result<Vec<(Vec<u8>, Vec<u8>)>>
    where
        P: rusqlite::Params,
    {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params, |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        rows.collect()
    }
}

// === Fact storage primitives ===

// Fact storage for the runtime.
//
// Facts are immutable, content-addressed rows. This module owns inserting,
// purging, and reading those rows; runtime workers decide when those
// operations should happen.
//
// Store is allowed to know the protocol-neutral `Fact` shape, local admission
// columns, incoming rows, and projection queue links. It must not decode fact
// bytes or branch on protocol-specific fact types, fact families, or payload
// tags.
//
// This is the storage companion to `facts.rs` and the entry point used by the
// projection worker. Inserting a new fact writes both the retained byte row and
// the local admission metadata row, then marks the fact pending so projection
// can derive runtime state from it. Reading a fact reconstructs the protocol
// bytes together with the local scope and timestamp that this store recorded at
// admission time.
//
// The important split is `facts` versus `local_fact_admissions`. `facts`
// stores bytes by content id. `local_fact_admissions` records how this store
// first admitted those bytes: scope, admission timestamp, and the derived
// local admission id used for ordering. That admission record is local
// runtime metadata, not separate protocol truth and not a protocol fact to
// sync.
//
// Purge is the reverse boundary. It removes the byte row and every core-owned
// row keyed by the fact id: local admission, standing context, time wakes,
// pending time ranges, pending projection, and queued projection matches.
// Protocol-owned rows that refer to the fact are removed by emitted row
// mutations or protocol handlers, not by this generic storage module.
//
// If the content-addressing rule, admission ordering, or purge fanout changes,
// change it here. If a protocol wants to interpret the fact bytes, that logic
// belongs in the protocol fact module and its projector.

const OWNER_KEYED_FACT_CLEANUP_TABLES: &[TableName] = &[
    CONTEXT_EDGES,
    TIME_WAKES,
    PENDING_TIME_RANGES,
    PENDING_PROJECTION_MATCHES,
    PENDING_PROJECTION,
];

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

    fn scan_sql(self) -> &'static str {
        match self {
            Self::Retained => {
                "SELECT f.id, m.scope, m.scope_kind, m.scope_id, m.received_at, f.bytes
                 FROM facts f
                 JOIN local_fact_admissions m ON m.fact_id = f.id
                 ORDER BY f.id"
            }
            Self::Incoming => {
                "SELECT id, scope, scope_kind, scope_id, received_at, bytes
                 FROM incoming_facts
                 ORDER BY received_at, id"
            }
        }
    }

    fn scan_error(self) -> &'static str {
        match self {
            Self::Retained => "load fact rows",
            Self::Incoming => "load incoming facts",
        }
    }
}

fn delete_owner_rows_from_tables(
    store: &Store,
    tables: &[TableName],
    owner: FactId,
) -> rusqlite::Result<usize> {
    let mut deleted = 0usize;
    for table in tables {
        deleted += store.delete_rows_by_owner_in_tx(*table, owner)?;
    }
    Ok(deleted)
}

// === Durable mutations ===

/// Insert a fact and mark it pending for projection.
///
/// Facts are immutable and content-addressed. The fact bytes live in `facts`;
/// the local admission record is local metadata about those bytes.
/// Returns whether either row was newly inserted.
pub(crate) fn insert_fact_and_pending_in_tx(store: &Store, fact: &Fact) -> rusqlite::Result<bool> {
    insert_fact_and_pending_with_mode_in_tx(store, fact, ProjectionMode::Normal)
}

/// Insert a fact and mark it pending with an explicit projection mode.
pub(crate) fn insert_fact_and_pending_with_mode_in_tx(
    store: &Store,
    fact: &Fact,
    mode: ProjectionMode,
) -> rusqlite::Result<bool> {
    let store_changed = insert_retained_fact_in_tx(store, fact)?;
    if store_changed {
        insert_pending_owner_with_mode_in_tx(store, fact.id, mode)?;
    }
    Ok(store_changed)
}

/// Mark `owner` pending in a specific projection mode.
pub(crate) fn insert_pending_owner_with_mode_in_tx(
    store: &Store,
    owner: FactId,
    mode: ProjectionMode,
) -> rusqlite::Result<usize> {
    store.conn().execute(
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
///
/// Incoming facts use the `Fact` container for id, scope, timestamp, and
/// bytes, but they are not inserted into durable `facts` or
/// `local_fact_admissions`. Projection decides whether to retain, park, or drop
/// the input, then removes the incoming row when that decision commits.
pub(crate) fn insert_incoming_fact_in_tx(store: &Store, fact: &Fact) -> rusqlite::Result<bool> {
    if let Some(bytes) = fact_bytes_by_id_in_tx(store, &fact.id)? {
        if bytes == fact.bytes {
            return Ok(false);
        }
        return Err(rusqlite::Error::InvalidParameterName(
            "conflicting retained row for incoming fact".to_string(),
        ));
    }

    let (scope, scope_kind, scope_id) = fact_scope_columns(&fact.scope);
    let changed = store.conn().execute(
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
        || incoming_fact_by_id_in_tx(store, &fact.id),
        |existing| existing.bytes == fact.bytes,
        "conflicting row for incoming fact",
    )
}

pub(crate) fn delete_incoming_fact_in_tx(store: &Store, owner: FactId) -> rusqlite::Result<bool> {
    let changed =
        store.delete_rows_by_blob_column_in_tx(INCOMING_FACTS, "id", owner.as_slice())? > 0;
    if changed {
        delete_owner_rows_from_tables(store, OWNER_KEYED_FACT_CLEANUP_TABLES, owner)?;
    }
    Ok(changed)
}

/// Move an incoming fact into the retained fact table without requeueing it.
///
/// Projection has already consumed this incoming item; retaining it should make
/// its bytes and local admission visible, but must not create a second initial
/// pending-projection row for the same fact.
pub(crate) fn move_incoming_to_retained_in_tx(
    store: &Store,
    fact: &Fact,
) -> rusqlite::Result<bool> {
    let retained = insert_retained_fact_in_tx(store, fact)?;
    delete_incoming_fact_in_tx(store, fact.id)?;
    Ok(retained)
}

/// Remove a fact and every durable row keyed to it.
///
/// Deletes the fact bytes, its local admission fact, its context edges, its time
/// wakes, any pending time-range rows it owns, and its pending-projection
/// marker. Returns whether anything was actually removed.
pub(crate) fn purge_fact_in_tx(store: &Store, owner: FactId) -> rusqlite::Result<bool> {
    let mut changed = store.delete_rows_by_blob_column_in_tx(FACTS, "id", owner.as_slice())? > 0;
    changed |= store.delete_rows_by_blob_column_in_tx(
        LOCAL_FACT_ADMISSIONS,
        "fact_id",
        owner.as_slice(),
    )? > 0;
    changed |= delete_owner_rows_from_tables(store, OWNER_KEYED_FACT_CLEANUP_TABLES, owner)? > 0;
    changed |= store.delete_rows_by_blob_column_in_tx(
        PENDING_PROJECTION_MATCHES,
        "offer_owner",
        owner.as_slice(),
    )? > 0;
    Ok(changed)
}

pub(crate) fn insert_retained_fact_in_tx(store: &Store, fact: &Fact) -> rusqlite::Result<bool> {
    let fact_bytes_inserted = insert_fact_bytes_in_tx(store, fact)?;
    let admission_inserted = insert_local_fact_admission_in_tx(store, fact)? > 0;
    Ok(fact_bytes_inserted || admission_inserted)
}

fn insert_fact_bytes_in_tx(store: &Store, fact: &Fact) -> rusqlite::Result<bool> {
    let changed = store.conn().execute(
        "INSERT OR IGNORE INTO facts (id, bytes) VALUES (?1, ?2)",
        params![fact.id.as_slice(), fact.bytes.as_slice()],
    )?;
    verify_idempotent_insert(
        changed,
        || fact_bytes_by_id_in_tx(store, &fact.id),
        |existing| existing.as_slice() == fact.bytes.as_slice(),
        "conflicting row for facts",
    )
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
    facts_from(store, FactReadSource::Retained)
}

pub(crate) fn incoming_pending_fact_ids(
    store: &Store,
    limit: usize,
) -> Result<Vec<FactId>, String> {
    let limit = i64::try_from(limit).map_err(|_| "incoming fact limit exceeds i64".to_string())?;
    let sql = incoming_ready_sql("e.id", "ORDER BY e.received_at, e.id LIMIT ?1")?;
    let mut stmt = store
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

pub(crate) fn incoming_fact_by_id(store: &Store, id: &FactId) -> Result<Option<Fact>, String> {
    incoming_fact_by_id_in_tx(store, id).map_err(|err| format!("load incoming fact: {err}"))
}

fn facts_from(store: &Store, source: FactReadSource) -> Result<Vec<Fact>, String> {
    let label = source.scan_error();
    let mut stmt = store
        .conn()
        .prepare(source.scan_sql())
        .map_err(|err| format!("{label}: {err}"))?;
    let rows = stmt
        .query_map([], fact_from_sql_row)
        .map_err(|err| format!("{label}: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("{label}: {err}"))
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

fn fact_by_id_in_tx(store: &Store, id: &FactId) -> rusqlite::Result<Option<Fact>> {
    fact_by_id_from(store, FactReadSource::Retained, id)
}

fn incoming_fact_by_id_in_tx(store: &Store, id: &FactId) -> rusqlite::Result<Option<Fact>> {
    fact_by_id_from(store, FactReadSource::Incoming, id)
}

fn fact_by_id_from(
    store: &Store,
    source: FactReadSource,
    id: &FactId,
) -> rusqlite::Result<Option<Fact>> {
    store
        .conn()
        .query_row(
            source.select_by_id_sql(),
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

pub(crate) fn sqlite_u64(value: u64, name: &str) -> rusqlite::Result<i64> {
    i64::try_from(value).map_err(|_| {
        rusqlite::Error::InvalidParameterName(format!(
            "{name}: SQL value exceeds SQLite integer range"
        ))
    })
}

/// The all-zero [`FactId`] stored in the scope columns of non-scoped facts.
const EMPTY_FACT_ID: FactId = [0u8; 32];

#[cfg(test)]
mod fact_tests {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::schema::{CORE_SCHEMA_SOURCE, INTENTS, LOCAL_INTENTS};

    const TEST_ROWS: TableName = TableName::new("test.rows");
    const MEMORY_ROWS: TableName = TableName::new("test.memory_rows");
    const TYPED_EVENTS: TableName = TableName::new("test.typed_events");

    const TEST_ROWS_SCHEMA: SchemaSource = SchemaSource {
        ddl: r#"
CREATE TABLE IF NOT EXISTS "test.rows" (
    row_key BLOB PRIMARY KEY NOT NULL,
    row_value BLOB NOT NULL
);
"#,
        row_tables: &[TEST_ROWS],
        row_schemas: &[],
        replay: ReplayTables::EMPTY,
    };

    const MEMORY_ROWS_SCHEMA: SchemaSource = SchemaSource {
        ddl: r#"
CREATE TEMP TABLE IF NOT EXISTS "test.memory_rows" (
    row_key BLOB PRIMARY KEY NOT NULL,
    row_value BLOB NOT NULL
);
"#,
        row_tables: &[MEMORY_ROWS],
        row_schemas: &[],
        replay: ReplayTables::EMPTY,
    };

    const TYPED_EVENTS_SCHEMA: SchemaSource = SchemaSource {
        ddl: r#"
CREATE TABLE IF NOT EXISTS "test.typed_events" (
    owner BLOB NOT NULL,
    seq INTEGER NOT NULL,
    label TEXT NOT NULL,
    PRIMARY KEY (owner, seq)
);
"#,
        row_tables: &[],
        row_schemas: &[],
        replay: ReplayTables::EMPTY,
    };

    #[test]
    fn duplicate_row_insert_is_idempotent_but_conflicting_value_rejects() {
        let store =
            Store::open_memory_with_schema_sources(&[TEST_ROWS_SCHEMA]).expect("open store");
        let row = TableRow {
            table: TEST_ROWS,
            key: b"k".to_vec(),
            value: b"one".to_vec(),
        };

        assert_eq!(
            store.insert_table_rows(vec![row.clone()]).expect("insert"),
            1
        );
        assert_eq!(
            store
                .insert_table_rows(vec![row.clone()])
                .expect("idempotent insert"),
            0
        );

        let err = store
            .insert_table_rows(vec![TableRow {
                value: b"two".to_vec(),
                ..row
            }])
            .expect_err("conflicting insert must reject");

        assert!(err.to_string().contains("conflicting row for test.rows"));
    }

    #[test]
    fn memory_rows_are_connection_local_temp_tables() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("memory-rows.db");
        let sources = [MEMORY_ROWS_SCHEMA];

        let store_a = Store::open_disk_with_schema_sources(&path, &sources).expect("open store a");
        store_a
            .insert_table_rows(vec![TableRow {
                table: MEMORY_ROWS,
                key: b"k".to_vec(),
                value: b"v".to_vec(),
            }])
            .expect("insert memory row");
        assert_eq!(store_a.table_row_count(MEMORY_ROWS).expect("count a"), 1);

        let store_b = Store::open_disk_with_schema_sources(&path, &sources).expect("open store b");
        assert_eq!(
            store_b.table_row_count(MEMORY_ROWS).expect("count b"),
            0,
            "memory rows should be local to one Store handle"
        );

        assert!(
            store_a
                .conn
                .query_row(
                    "SELECT name FROM sqlite_temp_master WHERE type = 'table' AND name = ?1",
                    [MEMORY_ROWS.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .expect("query temp schema")
                .is_some(),
            "memory row tables are SQLite TEMP tables"
        );
    }

    #[test]
    fn memory_rows_roll_back_with_write_transaction() {
        let store =
            Store::open_memory_with_schema_sources(&[MEMORY_ROWS_SCHEMA]).expect("open store");

        let err = store
            .write_transaction(|store| {
                store.insert_table_rows_in_tx(vec![TableRow {
                    table: MEMORY_ROWS,
                    key: b"k".to_vec(),
                    value: b"v".to_vec(),
                }])?;
                Err::<(), _>(rusqlite::Error::InvalidParameterName(
                    "force rollback".to_string(),
                ))
            })
            .expect_err("transaction should roll back");

        assert!(err.to_string().contains("force rollback"));
        assert_eq!(
            store
                .table_row_count(MEMORY_ROWS)
                .expect("count after rollback"),
            0
        );
    }

    #[test]
    fn memory_prefix_scan_is_key_ordered_and_limited() {
        let store =
            Store::open_memory_with_schema_sources(&[MEMORY_ROWS_SCHEMA]).expect("open store");
        store
            .insert_table_rows(vec![
                TableRow {
                    table: MEMORY_ROWS,
                    key: b"b/2".to_vec(),
                    value: b"two".to_vec(),
                },
                TableRow {
                    table: MEMORY_ROWS,
                    key: b"b/1".to_vec(),
                    value: b"one".to_vec(),
                },
                TableRow {
                    table: MEMORY_ROWS,
                    key: b"c/1".to_vec(),
                    value: b"skip".to_vec(),
                },
            ])
            .expect("insert rows");

        let rows = store
            .table_rows_with_key_prefix(MEMORY_ROWS, b"b/", 1)
            .expect("scan prefix");
        assert_eq!(rows, vec![(b"b/1".to_vec(), b"one".to_vec())]);
    }

    #[test]
    fn memory_prefix_scan_without_upper_bound_is_limited_by_sql() {
        let store =
            Store::open_memory_with_schema_sources(&[MEMORY_ROWS_SCHEMA]).expect("open store");
        store
            .insert_table_rows(vec![
                TableRow {
                    table: MEMORY_ROWS,
                    key: vec![0xfe],
                    value: b"before".to_vec(),
                },
                TableRow {
                    table: MEMORY_ROWS,
                    key: vec![0xff],
                    value: b"root".to_vec(),
                },
                TableRow {
                    table: MEMORY_ROWS,
                    key: vec![0xff, 0x00],
                    value: b"child-0".to_vec(),
                },
                TableRow {
                    table: MEMORY_ROWS,
                    key: vec![0xff, 0x01],
                    value: b"child-1".to_vec(),
                },
            ])
            .expect("insert rows");

        let rows = store
            .table_rows_with_key_prefix(MEMORY_ROWS, &[0xff], 2)
            .expect("scan all-ff prefix");
        assert_eq!(
            rows,
            vec![
                (vec![0xff], b"root".to_vec()),
                (vec![0xff, 0x00], b"child-0".to_vec()),
            ]
        );

        let rows = store
            .table_rows_with_key_prefix(MEMORY_ROWS, &[], 2)
            .expect("scan empty prefix");
        assert_eq!(
            rows,
            vec![
                (vec![0xfe], b"before".to_vec()),
                (vec![0xff], b"root".to_vec()),
            ]
        );

        let rows = store
            .table_rows_with_key_prefix(MEMORY_ROWS, &[0xff], usize::MAX)
            .expect("scan unbounded all-ff prefix");
        assert_eq!(
            rows,
            vec![
                (vec![0xff], b"root".to_vec()),
                (vec![0xff, 0x00], b"child-0".to_vec()),
                (vec![0xff, 0x01], b"child-1".to_vec()),
            ]
        );
    }

    #[test]
    fn typed_rows_by_blob_column_are_filtered_and_ordered() {
        let store =
            Store::open_memory_with_schema_sources(&[TYPED_EVENTS_SCHEMA]).expect("open store");
        for (owner, seq, label) in [
            (b"a".as_slice(), 2_i64, "second"),
            (b"b".as_slice(), 1_i64, "other"),
            (b"a".as_slice(), 1_i64, "first"),
        ] {
            store
                .conn()
                .execute(
                    r#"INSERT INTO "test.typed_events" (owner, seq, label)
                       VALUES (?1, ?2, ?3)"#,
                    params![owner, seq, label],
                )
                .expect("insert typed event");
        }
        assert_eq!(
            store
                .table_row_count(TYPED_EVENTS)
                .expect("count typed rows"),
            3
        );

        let rows = store
            .rows_by_blob_column(
                TYPED_EVENTS,
                &["label", "seq"],
                "owner",
                b"a",
                &["seq"],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .expect("select typed rows");

        assert_eq!(
            rows,
            vec![("first".to_string(), 1), ("second".to_string(), 2)]
        );

        let err = store
            .rows_by_blob_column(TYPED_EVENTS, &[], "owner", b"a", &["seq"], |_| Ok(()))
            .expect_err("empty select should fail before preparing invalid SQL");
        assert!(err
            .to_string()
            .contains("typed row select requires at least one column"));
    }

    #[test]
    fn intent_work_rows_are_idempotent_but_conflicts_reject() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open store");
        let row = IntentWorkRow::new("send", b"key".to_vec(), b"one".to_vec());

        assert!(store
            .write_transaction(|tx| tx.insert_intent_work_row_in_tx(INTENTS, &row))
            .expect("insert intent row"));
        assert!(!store
            .write_transaction(|tx| tx.insert_intent_work_row_in_tx(INTENTS, &row))
            .expect("idempotent insert"));

        let err = store
            .write_transaction(|tx| {
                tx.insert_intent_work_row_in_tx(
                    INTENTS,
                    &IntentWorkRow::new("send", b"key".to_vec(), b"two".to_vec()),
                )
            })
            .expect_err("conflicting insert must reject");

        assert!(err.to_string().contains("conflicting intent row for send"));
    }

    #[test]
    fn incoming_pending_ids_treat_pending_matches_as_ready() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open store");
        let ready = Fact::new(FactScope::Local, 1, b"ready incoming".to_vec());
        let blocked = Fact::new(FactScope::Local, 2, b"blocked incoming".to_vec());

        store
            .write_transaction(|tx| {
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
            incoming_pending_fact_ids(&store, 10).expect("pending incoming ids"),
            vec![ready.id]
        );

        store
            .conn()
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
            incoming_pending_fact_ids(&store, 10).expect("matched incoming ids"),
            vec![ready.id, blocked.id]
        );
    }

    #[test]
    fn delete_incoming_fact_clears_owner_keyed_runtime_rows() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open store");
        let fact = Fact::new(FactScope::Local, 1, b"incoming cleanup".to_vec());
        let offer = Fact::new(FactScope::Local, 2, b"incoming offer".to_vec());

        store
            .write_transaction(|tx| {
                insert_incoming_fact_in_tx(tx, &fact)?;
                seed_owner_keyed_fact_rows(tx, fact.id, offer.id)
            })
            .expect("seed incoming owner rows");
        assert_owner_keyed_fact_rows(&store, fact.id, 1);

        assert!(store
            .write_transaction(|tx| delete_incoming_fact_in_tx(tx, fact.id))
            .expect("delete incoming fact"));

        assert!(incoming_fact_by_id_in_tx(&store, &fact.id)
            .expect("load incoming fact")
            .is_none());
        assert_owner_keyed_fact_rows(&store, fact.id, 0);
    }

    #[test]
    fn purge_fact_clears_owner_keyed_and_offer_keyed_runtime_rows() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open store");
        let fact = Fact::new(FactScope::Local, 1, b"retained cleanup".to_vec());
        let other = Fact::new(FactScope::Local, 2, b"other retained".to_vec());

        store
            .write_transaction(|tx| {
                insert_retained_fact_in_tx(tx, &fact)?;
                seed_owner_keyed_fact_rows(tx, fact.id, other.id)?;
                seed_pending_match(tx, other.id, fact.id)
            })
            .expect("seed retained owner rows");
        assert_owner_keyed_fact_rows(&store, fact.id, 1);
        assert_eq!(pending_match_offer_count(&store, fact.id), 1);

        assert!(store
            .write_transaction(|tx| purge_fact_in_tx(tx, fact.id))
            .expect("purge fact"));

        assert!(fact_bytes_by_id_in_tx(&store, &fact.id)
            .expect("load retained fact")
            .is_none());
        assert_owner_keyed_fact_rows(&store, fact.id, 0);
        assert_eq!(pending_match_offer_count(&store, fact.id), 0);
    }

    fn seed_owner_keyed_fact_rows(
        store: &Store,
        owner: FactId,
        offer_owner: FactId,
    ) -> rusqlite::Result<()> {
        store.conn().execute(
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
        store.conn().execute(
            "INSERT INTO time_wakes (timeline, at, owner)
             VALUES ('cleanup_timeline', 1, ?1)",
            params![owner.as_slice()],
        )?;
        store.conn().execute(
            "INSERT INTO pending_time_ranges
                (owner, timeline, has_start, start_exclusive, end_inclusive)
             VALUES (?1, 'cleanup_timeline', 0, 0, 1)",
            params![owner.as_slice()],
        )?;
        store.conn().execute(
            "INSERT INTO pending_projection (owner, mode)
             VALUES (?1, 'normal')",
            params![owner.as_slice()],
        )?;
        seed_pending_match(store, owner, offer_owner)
    }

    fn seed_pending_match(
        store: &Store,
        owner: FactId,
        offer_owner: FactId,
    ) -> rusqlite::Result<()> {
        store.conn().execute(
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

    fn assert_owner_keyed_fact_rows(store: &Store, owner: FactId, expected: i64) {
        for table in OWNER_KEYED_FACT_CLEANUP_TABLES {
            assert_eq!(
                owner_row_count(store, *table, owner),
                expected,
                "owner rows in {}",
                table.as_str()
            );
        }
    }

    fn owner_row_count(store: &Store, table: TableName, owner: FactId) -> i64 {
        let table = quoted_table_name(table).expect("quote table");
        store
            .conn()
            .query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE owner = ?1"),
                params![owner.as_slice()],
                |row| row.get(0),
            )
            .expect("count owner rows")
    }

    fn pending_match_offer_count(store: &Store, offer_owner: FactId) -> i64 {
        store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pending_projection_matches WHERE offer_owner = ?1",
                params![offer_owner.as_slice()],
                |row| row.get(0),
            )
            .expect("count offer rows")
    }

    #[test]
    fn intent_work_rows_select_durable_by_identity_order() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open store");
        for row in [
            IntentWorkRow::new("z_kind", b"2".to_vec(), b"z".to_vec()),
            IntentWorkRow::new("a_kind", b"2".to_vec(), b"a2".to_vec()),
            IntentWorkRow::new("a_kind", b"1".to_vec(), b"a1".to_vec()),
        ] {
            store
                .write_transaction(|tx| tx.insert_intent_work_row_in_tx(INTENTS, &row))
                .expect("insert durable row");
        }

        let selected = store
            .next_intent_work_row(
                INTENTS,
                &["z_kind", "a_kind"],
                IntentWorkRowOrder::StableIdentity,
            )
            .expect("select durable row")
            .expect("durable row");

        assert_eq!(selected.kind, "a_kind");
        assert_eq!(selected.idempotence_key, b"1");
        assert_eq!(selected.payload, b"a1");
    }

    #[test]
    fn local_intent_work_rows_select_by_insertion_and_rotate_to_tail() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open store");
        let first = IntentWorkRow::new("work", b"first".to_vec(), b"1".to_vec());
        let second = IntentWorkRow::new("work", b"second".to_vec(), b"2".to_vec());
        for row in [&first, &second] {
            store
                .write_transaction(|tx| tx.insert_intent_work_row_in_tx(LOCAL_INTENTS, row))
                .expect("insert local row");
        }

        assert_eq!(
            store
                .next_intent_work_row(LOCAL_INTENTS, &["work"], IntentWorkRowOrder::Insertion)
                .expect("select first local")
                .expect("first local")
                .idempotence_key,
            b"first"
        );

        store
            .write_transaction(|tx| tx.rotate_intent_work_row_to_tail_in_tx(LOCAL_INTENTS, &first))
            .expect("rotate first row");

        assert_eq!(
            store
                .next_intent_work_row(LOCAL_INTENTS, &["work"], IntentWorkRowOrder::Insertion)
                .expect("select second local")
                .expect("second local")
                .idempotence_key,
            b"second"
        );
    }
}

//! A small SQLite-backed row store.
//!
//! Store is the lowest runtime layer above SQLite. It knows how to apply SQL
//! schema batches, run transactions, and read or write keyed byte rows. It does
//! not know what any row means. Fact admission, projection context, dependency
//! edges, network targets, and sync work are all core runtime, protocol, or IO
//! concepts layered on top of these primitives.
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
//! 3. Use row helpers for opaque row tables, and typed-table helpers for simple
//!    table/column operations.
//!
//! All atomicity comes from callers choosing the transaction closure. Store
//! supplies `BEGIN IMMEDIATE`, rollback, quoting, allowlist checks, and
//! idempotent opaque-row inserts. It should stay below projection, context
//! matching, intent dispatch, and protocol validation.
//!
//! The only dynamic SQL in this file is table-name interpolation for row
//! operations, replay reset, and state-summary hashing. Values are always bound
//! parameters, and table names are accepted only from `TableName` after a
//! conservative identifier check.

use crate::core::row_schema::RowTableSchema;
use rusqlite::{params, types::ValueRef, Connection as SqliteConnection, OptionalExtension};
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

fn unique_table_names<'a>(tables: impl IntoIterator<Item = &'a TableName>) -> Vec<TableName> {
    let mut unique = Vec::new();
    for table in tables {
        if !unique.contains(table) {
            unique.push(*table);
        }
    }
    unique
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
        let row_tables = sources
            .iter()
            .flat_map(|source| {
                source
                    .row_tables
                    .iter()
                    .copied()
                    .chain(source.row_schemas.iter().map(|schema| schema.table))
            })
            .collect();
        let row_schemas = sources
            .iter()
            .flat_map(|source| source.row_schemas.iter().copied())
            .collect();
        let replay_protected_tables =
            unique_table_names(sources.iter().flat_map(|source| source.replay.protected));
        let replay_reset_tables =
            unique_table_names(sources.iter().flat_map(|source| source.replay.reset));
        let replay_summary_tables =
            unique_table_names(sources.iter().flat_map(|source| source.replay.summary));
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

    fn row_table_name(&self, table: TableName) -> rusqlite::Result<String> {
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
            let table_name = self.row_table_name(row.table)?;
            let changed = self.conn.execute(
                &format!(
                    "INSERT OR IGNORE INTO {table_name}
                        (row_key, row_value)
                     VALUES (?1, ?2)"
                ),
                params![row.key.as_slice(), row.value.as_slice()],
            )?;
            if changed == 0 {
                let existing = self
                    .conn
                    .query_row(
                        &format!("SELECT row_value FROM {table_name} WHERE row_key = ?1"),
                        params![row.key.as_slice()],
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .optional()?;
                if existing.as_deref() != Some(row.value.as_slice()) {
                    return Err(store_error(format!(
                        "conflicting row for {}",
                        row.table.as_str()
                    )));
                }
            }
            inserted += changed;
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
        let table_name = self.row_table_name(table)?;
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
        let table_name = self.row_table_name(table)?;
        self.conn
            .query_row(
                &format!("SELECT row_value FROM {table_name} WHERE row_key = ?1"),
                params![key],
                |row| row.get(0),
            )
            .optional()
    }

    /// Count rows in one declared table.
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
        let table_name = self.row_table_name(table)?;
        let mut stmt = self.conn.prepare(&format!(
            "SELECT row_key, row_value FROM {table_name}
                ORDER BY row_key"
        ))?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect()
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
        let table_name = self.row_table_name(table)?;
        let Some(upper) = prefix_upper_bound(prefix) else {
            let mut stmt = self.conn.prepare(&format!(
                "SELECT row_key, row_value FROM {table_name}
                     WHERE row_key >= ?1
                     ORDER BY row_key"
            ))?;
            let rows = stmt.query_map(params![prefix], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let row = row?;
                if !row.0.starts_with(prefix) || out.len() == limit {
                    break;
                }
                out.push(row);
            }
            return Ok(out);
        };

        let mut stmt = self.conn.prepare(&format!(
            "SELECT row_key, row_value FROM {table_name}
                 WHERE row_key >= ?1 AND row_key < ?2
                 ORDER BY row_key
                 LIMIT ?3"
        ))?;
        let rows = stmt.query_map(params![prefix, upper, limit as i64], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        rows.collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

// === Fact storage primitives ===

// Fact storage for the runtime.
//
// Facts are immutable, content-addressed rows. This module owns inserting,
// purging, and reading those rows; runtime workers decide when those
// operations should happen.
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

use crate::core::facts::{fact_id, Fact, FactId, FactScope, ScopeKind};
use crate::core::project_fact::ProjectionMode;
use crate::core::schema::{
    CANDIDATE_FACTS, CONTEXT_EDGES, FACTS, LOCAL_FACT_ADMISSIONS, PENDING_PROJECTION,
    PENDING_PROJECTION_MATCHES, PENDING_TIME_RANGES, TIME_WAKES,
};
use crate::core::wire::Writer;

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
    let inserted = insert_retained_fact_in_tx(store, fact)?;
    if inserted {
        insert_pending_owner_with_mode_in_tx(store, fact.id, mode)?;
    }
    Ok(inserted)
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

/// Insert a runtime-local projectable input.
///
/// Candidate facts use the `Fact` container for id, scope, timestamp, and
/// bytes, but they are not inserted into durable `facts` or
/// `local_fact_admissions`. Projection may read durable context and emit durable
/// facts, then the input row is removed when projection commits.
pub(crate) fn insert_candidate_fact_in_tx(store: &Store, fact: &Fact) -> rusqlite::Result<bool> {
    let (scope, scope_kind, scope_id) = fact_scope_columns(&fact.scope);
    let changed = store.conn().execute(
        "INSERT OR IGNORE INTO candidate_facts
            (id, scope, scope_kind, scope_id, received_at, bytes)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            fact.id.as_slice(),
            scope,
            scope_kind,
            scope_id.as_slice(),
            sqlite_u64(fact.timestamp, "candidate fact received_at")?,
            fact.bytes.as_slice()
        ],
    )?;
    if changed == 0 {
        let existing = candidate_fact_by_id_in_tx(store, &fact.id)?;
        if existing.as_ref() != Some(fact) {
            return Err(rusqlite::Error::InvalidParameterName(
                "conflicting row for candidate fact".to_string(),
            ));
        }
    }
    Ok(changed > 0)
}

pub(crate) fn delete_candidate_fact_in_tx(store: &Store, owner: FactId) -> rusqlite::Result<bool> {
    let mut changed =
        store.delete_rows_by_blob_column_in_tx(CANDIDATE_FACTS, "id", owner.as_slice())? > 0;
    changed |= store.delete_rows_by_owner_in_tx(PENDING_PROJECTION_MATCHES, owner)? > 0;
    Ok(changed)
}

/// Move a volatile candidate into the retained fact table without requeueing it.
///
/// Projection has already consumed this candidate item; retaining it should make
/// its bytes and local admission visible, but must not create a second initial
/// pending-projection row for the same fact.
pub(crate) fn move_candidate_to_retained_in_tx(
    store: &Store,
    fact: &Fact,
) -> rusqlite::Result<bool> {
    let retained = insert_retained_fact_in_tx(store, fact)?;
    delete_candidate_fact_in_tx(store, fact.id)?;
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
    for table in [
        CONTEXT_EDGES,
        TIME_WAKES,
        PENDING_TIME_RANGES,
        PENDING_PROJECTION_MATCHES,
        PENDING_PROJECTION,
    ] {
        changed |= store.delete_rows_by_owner_in_tx(table, owner)? > 0;
    }
    changed |= store.delete_rows_by_blob_column_in_tx(
        PENDING_PROJECTION_MATCHES,
        "offer_owner",
        owner.as_slice(),
    )? > 0;
    Ok(changed)
}

pub(crate) fn insert_retained_fact_in_tx(store: &Store, fact: &Fact) -> rusqlite::Result<bool> {
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

pub(crate) fn candidate_pending_fact_ids(
    store: &Store,
    limit: usize,
) -> Result<Vec<FactId>, String> {
    let limit = i64::try_from(limit).map_err(|_| "candidate fact limit exceeds i64".to_string())?;
    let mut stmt = store
        .conn()
        .prepare(&format!(
            r#"
            SELECT e.id
            FROM {ephemeral} e
            WHERE NOT EXISTS (
                    SELECT 1
                    FROM {context} n
                    WHERE n.owner = e.id
                      AND n.direction = 'need'
                )
               OR EXISTS (
                    SELECT 1
                    FROM {context} n
                    JOIN {context} o
                      ON o.direction = 'offer'
                     AND o.role = n.role
                     AND o.scope_key = n.scope_key
                     AND o.start_key <= n.end_key
                     AND o.end_key >= n.start_key
                    WHERE n.owner = e.id
                      AND n.direction = 'need'
                )
            ORDER BY e.received_at, e.id
            LIMIT ?1
            "#,
            ephemeral = CANDIDATE_FACTS.as_str(),
            context = CONTEXT_EDGES.as_str(),
        ))
        .map_err(|err| format!("load candidate facts: {err}"))?;
    let rows = stmt
        .query_map(params![limit], |row| {
            fact_id_column(row.get::<_, Vec<u8>>(0)?, "candidate id")
        })
        .map_err(|err| format!("load candidate facts: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("load candidate facts: {err}"))
}

pub(crate) fn candidate_fact_by_id(store: &Store, id: &FactId) -> Result<Option<Fact>, String> {
    candidate_fact_by_id_in_tx(store, id).map_err(|err| format!("load candidate fact: {err}"))
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

fn candidate_fact_by_id_in_tx(store: &Store, id: &FactId) -> rusqlite::Result<Option<Fact>> {
    store
        .conn()
        .query_row(
            "SELECT id, scope, scope_kind, scope_id, received_at, bytes
             FROM candidate_facts
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

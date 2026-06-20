//! SQLite connection, transaction boundaries, and typed row mutation helpers.
//!
//! `Db` is the lowest runtime layer above SQLite. It opens the connection,
//! applies schema batches, runs explicit transactions, quotes trusted table and
//! column identifiers for syntax safety, and applies typed row mutations. It
//! does not own fact persistence, projection queues, intent queues,
//! state-summary diagnostics, network queues, or protocol query SQL; those
//! modules use `Db::conn()` and `write_transaction()` to own their table
//! behavior directly.
//!
//! All atomicity comes from callers choosing the transaction closure. `Db`
//! supplies `BEGIN IMMEDIATE`, rollback, and `COMMIT`; owning modules decide
//! which facts, rows, queue entries, or diagnostics belong in that boundary.
//!
//! The first exported path below is the one fact families use most often:
//! declare a `TypedTableSchema`, build `TableInsert` or `TableDeleteWhere`
//! values from decoded facts, emit `RowMutation`s, and keep direct read SQL in
//! the owning query module.
//!
//! The storage-version marker is protocol-owned state. A `SchemaSource` may
//! declare a `StorageVersionSource`: the marker table, the version column, and
//! the columns that sort newest marker rows first. `Db` records only that read
//! recipe when it opens schema sources. `current_storage_version()` then asks
//! "what storage version does this database currently project?" by reading the
//! latest declared marker row, for example
//! `protocol_version_rows.protocol_version ORDER BY applied_at_ms DESC,
//! update_fact_id DESC LIMIT 1`. Fresh or stale databases are repaired by the
//! protocol's versioning update path; core only reads the marker to enforce
//! declared commit preconditions. Query helpers that opt into current-storage
//! checks use the same marker to return a mismatch error before reading
//! incompatible materialized rows.
//!
//! The exported surface is split by responsibility:
//!
//! - `Db` is the reusable SQLite handle and transaction boundary.
//! - `TableName`, `TypedTableSchema`, `TableInsert`, `TableDeleteWhere`,
//!   `RowMutation`, and `Value` are the typed-row mutation vocabulary.
//! - `SchemaSource`, `StorageVersionSource`, and `ReplayTables` let runtime
//!   owners declare schema, upgrade-marker, and rebuild lifecycle metadata.
//! - The crate-visible quoting helpers are for modules that own direct SQL but
//!   still need the same trusted-identifier validation as the row helpers.

use rusqlite::{
    params_from_iter, types::Value as SqliteValue, Connection as SqliteConnection,
    OptionalExtension,
};
use std::path::Path;
use std::time::Duration;

// =============================================================================
// Query Defaults
// =============================================================================

/// Temporary upper bound for read helpers that still return Vec-backed pages.
///
/// Query modules should shrink this surface into caller-supplied paging or
/// narrower SQL predicates as their fact families migrate fully to SQL.
pub const DEFAULT_QUERY_LIMIT: usize = 10_000;

// =============================================================================
// Typed Row Vocabulary
// =============================================================================

/// A static, trusted row-table name.
///
/// Protocol and core IO modules declare these names next to the row encoders
/// that understand their values. Db validates the identifier before using
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

/// SQLite value carried by typed-table row mutations and internal SQL helpers.
///
/// Protocol row builders choose these values from their fact layout and table
/// schema. Conversion into SQLite bind parameters is mechanical; `Db` does
/// not interpret what a column or parameter means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Bytes(Vec<u8>),
    U64(u64),
    Bool(bool),
}

impl Value {
    pub(crate) fn as_sqlite_value(&self) -> rusqlite::Result<SqliteValue> {
        match self {
            Self::Bytes(value) => Ok(SqliteValue::Blob(value.clone())),
            Self::U64(value) => i64::try_from(*value)
                .map(SqliteValue::Integer)
                .map_err(|_| {
                    rusqlite::Error::InvalidParameterName(
                        "SQL value exceeds SQLite integer range".to_string(),
                    )
                }),
            Self::Bool(value) => Ok(SqliteValue::Integer(i64::from(*value))),
        }
    }
}

/// Insert a typed-table row by column values.
///
/// The insert is idempotent only when an existing row has exactly the same
/// column values. To change projected state, emit a matching `DeleteWhere`
/// before the replacement insert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableInsert {
    /// Typed table to insert into.
    pub table: TableName,
    /// Columns supplied by this insert.
    pub columns: &'static [&'static str],
    /// Values corresponding to `columns`.
    pub values: Vec<Value>,
}

/// Delete typed-table rows matching all supplied columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableDeleteWhere {
    /// Typed table to delete from.
    pub table: TableName,
    /// Predicate columns.
    pub columns: &'static [&'static str],
    /// Predicate values corresponding to `columns`.
    pub values: Vec<Value>,
}

/// Protocol-owned typed table declaration.
///
/// This is the narrow schema surface shared by projection code and the runtime
/// commit path. Protocol registry code owns the SQL DDL; row builders use this
/// value to avoid re-declaring table names and column order beside every
/// materialized read model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypedTableSchema {
    /// Typed table name.
    pub table: TableName,
    /// Full insert column order for this table's materialized row.
    pub columns: &'static [&'static str],
    /// Logical key columns used for delete/replacement mutations.
    pub key_columns: &'static [&'static str],
}

impl TypedTableSchema {
    /// Build an insert mutation using this schema's declared column order.
    pub fn insert(self, values: Vec<Value>) -> TableInsert {
        TableInsert {
            table: self.table,
            columns: self.columns,
            values,
        }
    }

    /// Build a delete mutation against this schema's logical key columns.
    pub fn delete_by_key(self, values: Vec<Value>) -> TableDeleteWhere {
        TableDeleteWhere {
            table: self.table,
            columns: self.key_columns,
            values,
        }
    }
}

/// Row-level mutations a command, projector, or handler can request.
///
/// Core validates the target table against the runtime description before any
/// mutation commits. The module that constructs the mutation owns the row
/// layout and semantic meaning.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowMutation {
    InsertValues(TableInsert),
    DeleteWhere(TableDeleteWhere),
}

// =============================================================================
// Exported Database Handle
// =============================================================================

/// The only durable substrate core offers protocol code.
///
/// Durable and memory tables are both ordinary SQLite tables on this one
/// connection; memory tables are `TEMP` tables. Every row helper is therefore a
/// single SQL path, and `write_transaction` rollback covers both classes.
pub struct Db {
    conn: SqliteConnection,
    schema: SchemaCatalog,
}

impl Db {
    // =========================================================================
    // Central Entry Points
    // =========================================================================

    /// Expose the underlying SQLite connection to core modules that own their
    /// table SQL directly.
    pub(crate) fn conn(&self) -> &SqliteConnection {
        &self.conn
    }

    /// Open a disk database and apply SQL schema sources.
    pub fn open_disk_with_schema_sources(
        path: impl AsRef<Path>,
        sources: &[SchemaSource],
    ) -> rusqlite::Result<Self> {
        let conn = SqliteConnection::open(path)?;
        Self::from_connection_with_schema_sources(conn, sources)
    }

    /// Open an in-memory db without creating any protocol tables.
    pub fn open_memory() -> rusqlite::Result<Self> {
        Self::open_memory_with_schema_sources(&[])
    }

    /// Open an in-memory db and apply SQL schema sources.
    pub fn open_memory_with_schema_sources(sources: &[SchemaSource]) -> rusqlite::Result<Self> {
        let conn = SqliteConnection::open_in_memory()?;
        Self::from_connection_with_schema_sources(conn, sources)
    }

    // Critical path: callers put every atomic row mutation
    // through this closure, then use the transaction-local row helpers below.
    /// Run a write transaction.
    ///
    /// The closure sees its own writes through the same SQLite handle. Keep
    /// closures narrow: they are where callers express the atomic unit, while
    /// this database only supplies `BEGIN IMMEDIATE` / `COMMIT` / `ROLLBACK`.
    pub fn write_transaction<T>(
        &self,
        apply: impl FnOnce(&Db) -> rusqlite::Result<T>,
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

    // =========================================================================
    // Typed Row Mutation Operations
    // =========================================================================

    /// Insert typed table rows idempotently in their declared tables.
    pub fn insert_table_values(&self, rows: Vec<TableInsert>) -> rusqlite::Result<usize> {
        self.write_transaction(|db| {
            let mut inserted = 0;
            for row in rows {
                inserted += db.insert_values_in_tx(&row)?;
            }
            Ok(inserted)
        })
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

    /// Apply validated row mutations inside the caller's transaction.
    ///
    /// Projection and dispatch own the larger commit order. Db owns the SQL
    /// mechanics for typed table inserts/deletes.
    pub(crate) fn apply_row_mutations_in_tx(
        &self,
        mutations: &[RowMutation],
    ) -> rusqlite::Result<()> {
        for mutation in mutations {
            match mutation {
                RowMutation::InsertValues(insert) => {
                    self.insert_values_in_tx(insert)?;
                }
                RowMutation::DeleteWhere(delete) => {
                    self.delete_where_in_tx(delete)?;
                }
            }
        }
        Ok(())
    }

    /// Insert a typed-table row idempotently in the caller's transaction.
    pub(crate) fn insert_values_in_tx(&self, insert: &TableInsert) -> rusqlite::Result<usize> {
        validate_columns_and_values(insert.columns, &insert.values, "insert")?;
        let table = quoted_table_name(insert.table)?;
        let columns = quoted_identifier_list(insert.columns)?;
        let placeholders = placeholders(insert.values.len());
        let values = sqlite_values(&insert.values)?;
        let changed = self.conn.execute(
            &format!("INSERT OR IGNORE INTO {table} ({columns}) VALUES ({placeholders})"),
            params_from_iter(values.iter()),
        )?;
        if changed == 0 && !self.insert_values_match(insert, &values)? {
            return Err(db_error(format!(
                "conflicting row for {}",
                insert.table.as_str()
            )));
        }
        Ok(changed)
    }

    /// Delete typed-table rows by an exact column predicate in the caller's transaction.
    pub(crate) fn delete_where_in_tx(&self, delete: &TableDeleteWhere) -> rusqlite::Result<usize> {
        validate_columns_and_values(delete.columns, &delete.values, "delete")?;
        let table = quoted_table_name(delete.table)?;
        let predicate = where_clause(delete.columns)?;
        let values = sqlite_values(&delete.values)?;
        self.conn.execute(
            &format!("DELETE FROM {table} WHERE {predicate}"),
            params_from_iter(values.iter()),
        )
    }

    fn insert_values_match(
        &self,
        insert: &TableInsert,
        values: &[SqliteValue],
    ) -> rusqlite::Result<bool> {
        let table = quoted_table_name(insert.table)?;
        let predicate = where_clause(insert.columns)?;
        self.conn
            .query_row(
                &format!("SELECT 1 FROM {table} WHERE {predicate} LIMIT 1"),
                params_from_iter(values.iter()),
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
    }
}

// =============================================================================
// Schema Source Vocabulary
// =============================================================================

/// One executable schema batch plus rebuild lifecycle declarations.
#[derive(Debug, Clone, Copy)]
pub struct SchemaSource {
    /// SQL batch applied when the database opens.
    pub ddl: &'static str,
    /// Protocol-owned storage-version marker declaration, when this source owns one.
    pub storage_version: Option<StorageVersionSource>,
    /// Rebuild reset and summary lifecycle declarations for this source's
    /// tables.
    pub replay: ReplayTables,
}

/// Rebuild lifecycle declarations for tables created by one schema source.
///
/// `protected` tables are retained fact-storage tables and are never cleared by
/// rebuild. `reset` tables are derived, queued, or local runtime state that a
/// rebuild can clear before replay-mode projection. `summary` tables are
/// hashed by `state-summary`.
#[derive(Debug, Clone, Copy)]
pub struct ReplayTables {
    /// Retained fact-storage tables that rebuild reset must not clear.
    pub protected: &'static [TableName],
    /// Tables cleared by rebuild reset.
    pub reset: &'static [TableName],
    /// Tables included in state summaries.
    pub summary: &'static [TableName],
}

impl ReplayTables {
    /// Empty rebuild lifecycle declarations for tests and non-rebuild schemas.
    pub const EMPTY: Self = Self {
        protected: &[],
        reset: &[],
        summary: &[],
    };
}

/// Trusted declaration for the protocol-owned storage-version marker.
///
/// Core uses this only to compare a commit's required version with the latest
/// marker row. The table and columns are still protocol-owned projected state.
#[derive(Debug, Clone, Copy)]
pub struct StorageVersionSource {
    /// Table that stores projected version marker rows.
    pub table: TableName,
    /// Column containing the storage version.
    pub version_column: &'static str,
    /// Columns ordered descending to select the latest marker row.
    pub order_by_columns: &'static [&'static str],
}

impl Db {
    // =========================================================================
    // Schema Opening Stages
    // =========================================================================

    fn from_connection_with_schema_sources(
        conn: SqliteConnection,
        sources: &[SchemaSource],
    ) -> rusqlite::Result<Self> {
        let schema = SchemaCatalog::from_sources(sources)?;
        let db = Self::from_connection_parts(conn, schema)?;
        for source in sources {
            db.conn.execute_batch(source.ddl)?;
        }
        Ok(db)
    }

    fn from_connection_parts(
        conn: SqliteConnection,
        schema: SchemaCatalog,
    ) -> rusqlite::Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA temp_store = MEMORY;",
        )?;
        Ok(Self { conn, schema })
    }

    // =========================================================================
    // Replay Lifecycle Views
    // =========================================================================

    /// Tables protected from rebuild reset.
    pub fn replay_protected_tables(&self) -> &[TableName] {
        &self.schema.replay.protected
    }

    /// Tables rebuild reset is allowed to clear.
    pub fn replay_reset_tables(&self) -> &[TableName] {
        &self.schema.replay.reset
    }

    /// Tables state-summary hashes as protocol/runtime state.
    pub fn replay_summary_tables(&self) -> &[TableName] {
        &self.schema.replay.summary
    }

    // =========================================================================
    // Storage-Version Marker Reads
    // =========================================================================

    /// Return the current core storage-version marker, if the database has one.
    pub fn current_storage_version(&self) -> rusqlite::Result<Option<u32>> {
        let Some(source) = self.schema.storage_version else {
            return Ok(None);
        };
        let table = quoted_table_name(source.table)?;
        let version_column = quoted_identifier(source.version_column)?;
        let order_by = storage_version_order_by(source.order_by_columns)?;
        self.conn
            .query_row(
                &format!("SELECT {version_column} FROM {table}{order_by} LIMIT 1"),
                [],
                |row| {
                    let version = row.get::<_, i64>(0)?;
                    u32::try_from(version)
                        .map_err(|_| db_error("stored storage version is outside u32 range"))
                },
            )
            .optional()
    }

    /// Return true when the stored marker matches the expected table version.
    pub fn storage_version_is(&self, expected: u32) -> rusqlite::Result<bool> {
        self.current_storage_version()
            .map(|stored| stored == Some(expected))
    }

    /// Enforce the storage-version precondition for a commit boundary.
    pub(crate) fn require_storage_version(&self, expected: u32) -> Result<(), String> {
        match self.current_storage_version() {
            Ok(Some(stored)) if stored == expected => Ok(()),
            Ok(Some(stored)) => Err(format!(
                "storage version mismatch: required_version={expected} stored_version={stored}"
            )),
            Ok(None) => Err(format!(
                "storage version mismatch: required_version={expected} stored_version=missing"
            )),
            Err(err) => Err(format!("read storage version marker: {err}")),
        }
    }
}

// =============================================================================
// Compiled Schema Metadata
// =============================================================================

struct SchemaCatalog {
    storage_version: Option<StorageVersionSource>,
    replay: ReplayCatalog,
}

impl SchemaCatalog {
    fn from_sources(sources: &[SchemaSource]) -> rusqlite::Result<Self> {
        Ok(Self {
            storage_version: declared_storage_version_source(sources)?,
            replay: ReplayCatalog::from_sources(sources)?,
        })
    }
}

struct ReplayCatalog {
    protected: Vec<TableName>,
    reset: Vec<TableName>,
    summary: Vec<TableName>,
}

impl ReplayCatalog {
    fn from_sources(sources: &[SchemaSource]) -> rusqlite::Result<Self> {
        let protected = unique_table_names(
            sources
                .iter()
                .flat_map(|source| source.replay.protected.iter().copied()),
        );
        let reset = unique_table_names(
            sources
                .iter()
                .flat_map(|source| source.replay.reset.iter().copied()),
        );
        let summary = unique_table_names(
            sources
                .iter()
                .flat_map(|source| source.replay.summary.iter().copied()),
        );
        validate_replay_lifecycle(&protected, &reset)?;
        Ok(Self {
            protected,
            reset,
            summary,
        })
    }
}

// =============================================================================
// Shared Error Helper
// =============================================================================

fn db_error(message: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(message.into())
}

// =============================================================================
// Schema Opening Helpers
// =============================================================================

fn unique_table_names(tables: impl IntoIterator<Item = TableName>) -> Vec<TableName> {
    let mut unique = Vec::new();
    for table in tables {
        if !unique.contains(&table) {
            unique.push(table);
        }
    }
    unique
}

fn validate_replay_lifecycle(protected: &[TableName], reset: &[TableName]) -> rusqlite::Result<()> {
    for table in reset {
        if protected.contains(table) {
            return Err(db_error(format!(
                "table {} cannot be both replay-protected and replay-resettable",
                table.as_str()
            )));
        }
    }
    Ok(())
}

fn declared_storage_version_source(
    sources: &[SchemaSource],
) -> rusqlite::Result<Option<StorageVersionSource>> {
    let mut declared = None;
    for source in sources {
        let Some(version_source) = source.storage_version else {
            continue;
        };
        match declared {
            Some(existing) if !same_storage_version_source(existing, version_source) => {
                return Err(db_error(format!(
                    "conflicting storage version sources declared: {} and {}",
                    existing.table.as_str(),
                    version_source.table.as_str()
                )));
            }
            Some(_) => {}
            None => declared = Some(version_source),
        }
    }
    Ok(declared)
}

fn same_storage_version_source(left: StorageVersionSource, right: StorageVersionSource) -> bool {
    left.table == right.table
        && left.version_column == right.version_column
        && left.order_by_columns == right.order_by_columns
}

// =============================================================================
// SQL Identifier Helpers
// =============================================================================

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

// =============================================================================
// Row Mutation SQL Helpers
// =============================================================================

fn validate_columns_and_values(
    columns: &[&str],
    values: &[Value],
    label: &str,
) -> rusqlite::Result<()> {
    if columns.is_empty() {
        return Err(db_error(format!(
            "{label} mutation requires at least one column"
        )));
    }
    if columns.len() != values.len() {
        return Err(db_error(format!(
            "{label} mutation column/value count mismatch"
        )));
    }
    Ok(())
}

fn sqlite_values(values: &[Value]) -> rusqlite::Result<Vec<SqliteValue>> {
    values.iter().map(Value::as_sqlite_value).collect()
}

fn where_clause(columns: &[&str]) -> rusqlite::Result<String> {
    columns
        .iter()
        .enumerate()
        .map(|(index, column)| Ok(format!("{} = ?{}", quoted_identifier(column)?, index + 1)))
        .collect::<rusqlite::Result<Vec<_>>>()
        .map(|columns| columns.join(" AND "))
}

fn storage_version_order_by(columns: &[&str]) -> rusqlite::Result<String> {
    if columns.is_empty() {
        return Ok(String::new());
    }
    let columns = columns
        .iter()
        .map(|column| Ok(format!("{} DESC", quoted_identifier(column)?)))
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(format!(" ORDER BY {}", columns.join(", ")))
}

fn placeholders(count: usize) -> String {
    (1..=count)
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(", ")
}

// =============================================================================
// Tests
// =============================================================================
//
// Ordered most-central-first: the full insert/delete/replace plus rollback proof
// of the typed row-mutation path leads; narrow guards and config checks follow.

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ROWS: TableName = TableName::new("test_rows");
    const TEST_COLUMNS: &[&str] = &["id", "payload"];
    const TEST_KEY_COLUMNS: &[&str] = &["id"];
    const TEST_SCHEMA: SchemaSource = SchemaSource {
        ddl: r#"
CREATE TABLE IF NOT EXISTS test_rows (
    id BLOB PRIMARY KEY NOT NULL,
    payload BLOB NOT NULL
);
"#,
        storage_version: None,
        replay: ReplayTables::EMPTY,
    };

    #[test]
    fn row_mutations_insert_delete_and_roll_back_as_one_transaction() {
        let store = Db::open_memory_with_schema_sources(&[TEST_SCHEMA]).expect("open memory db");
        let first = test_insert(b"one", b"first");
        let replacement = test_insert(b"one", b"replacement");

        store
            .write_transaction(|tx| {
                tx.apply_row_mutations_in_tx(&[RowMutation::InsertValues(first)])
            })
            .expect("insert first row");
        assert_eq!(store.table_row_count(TEST_ROWS).expect("count rows"), 1);

        store
            .write_transaction(|tx| {
                tx.apply_row_mutations_in_tx(&[
                    RowMutation::DeleteWhere(test_delete(b"one")),
                    RowMutation::InsertValues(replacement.clone()),
                ])
            })
            .expect("replace row");
        assert_eq!(test_payload(&store, b"one"), b"replacement".to_vec());

        let rollback: rusqlite::Result<()> = store.write_transaction(|tx| {
            tx.apply_row_mutations_in_tx(&[
                RowMutation::DeleteWhere(test_delete(b"one")),
                RowMutation::InsertValues(test_insert(b"two", b"second")),
            ])?;
            Err(db_error("force rollback after row mutations"))
        });
        assert!(rollback.is_err(), "forced error should roll back");

        assert_eq!(store.table_row_count(TEST_ROWS).expect("count rows"), 1);
        assert_eq!(test_payload(&store, b"one"), b"replacement".to_vec());
        assert!(
            !row_exists(&store, b"two").expect("query second row"),
            "rolled-back insert should not remain"
        );
    }

    #[test]
    fn row_mutations_reject_mismatched_columns_without_partial_commit() {
        let store = Db::open_memory_with_schema_sources(&[TEST_SCHEMA]).expect("open memory db");
        let err = store
            .write_transaction(|tx| {
                tx.apply_row_mutations_in_tx(&[
                    RowMutation::InsertValues(test_insert(b"one", b"first")),
                    RowMutation::InsertValues(TableInsert {
                        table: TEST_ROWS,
                        columns: TEST_COLUMNS,
                        values: vec![Value::Bytes(b"missing-payload".to_vec())],
                    }),
                ])
            })
            .expect_err("mismatched row should reject");

        assert!(
            err.to_string().contains("column/value count mismatch"),
            "{err}"
        );
        assert_eq!(
            store.table_row_count(TEST_ROWS).expect("count rows"),
            0,
            "failed mutation batch should roll back earlier row writes"
        );
    }

    #[test]
    fn db_connections_keep_temp_storage_in_memory() {
        let store = Db::open_memory().expect("open memory db");

        let temp_store = store
            .conn()
            .query_row("PRAGMA temp_store", [], |row| row.get::<_, i64>(0))
            .expect("query temp_store pragma");

        assert_eq!(
            temp_store, 2,
            "SQLite temp_store MEMORY has numeric value 2"
        );
    }

    fn test_insert(id: &[u8], payload: &[u8]) -> TableInsert {
        TableInsert {
            table: TEST_ROWS,
            columns: TEST_COLUMNS,
            values: vec![Value::Bytes(id.to_vec()), Value::Bytes(payload.to_vec())],
        }
    }

    fn test_delete(id: &[u8]) -> TableDeleteWhere {
        TableDeleteWhere {
            table: TEST_ROWS,
            columns: TEST_KEY_COLUMNS,
            values: vec![Value::Bytes(id.to_vec())],
        }
    }

    fn test_payload(store: &Db, id: &[u8]) -> Vec<u8> {
        store
            .conn()
            .query_row("SELECT payload FROM test_rows WHERE id = ?1", [id], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .expect("query test payload")
    }

    fn row_exists(store: &Db, id: &[u8]) -> rusqlite::Result<bool> {
        store
            .conn()
            .query_row("SELECT 1 FROM test_rows WHERE id = ?1", [id], |_| Ok(()))
            .optional()
            .map(|row| row.is_some())
    }
}

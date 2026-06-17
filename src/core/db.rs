//! SQLite connection and generic row-mutation plumbing.
//!
//! `Db` is the lowest runtime layer above SQLite. It opens the connection,
//! applies schema batches, runs explicit transactions, quotes trusted table and
//! column identifiers, and applies typed row mutations. It does not own fact
//! persistence, projection queues, intent queues, replay diagnostics, network
//! queues, or protocol query SQL; those modules use `Db::conn()` and
//! `write_transaction()` to own their table behavior directly.
//!
//! All atomicity comes from callers choosing the transaction closure. `Db`
//! supplies `BEGIN IMMEDIATE`, rollback, and `COMMIT`; owning modules decide
//! which facts, rows, queue entries, or diagnostics belong in that boundary.

use crate::core::facts::{Fact, FactId};
use rusqlite::{
    params, params_from_iter, types::Value as SqliteValue, Connection as SqliteConnection,
    OptionalExtension,
};
use std::path::Path;
use std::time::Duration;

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

/// Replay lifecycle declarations for tables created by one schema source.
///
/// `protected` tables are retained fact-storage tables and are never cleared by
/// replay. `reset` tables are derived, queued, or local runtime state that
/// replay can clear before rebuilding. `summary` tables are hashed by
/// replay-check.
#[derive(Debug, Clone, Copy)]
pub struct ReplayTables {
    /// Retained fact-storage tables that replay reset must not clear.
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

/// One executable schema batch plus replay lifecycle declarations.
#[derive(Debug, Clone, Copy)]
pub struct SchemaSource {
    /// SQL batch applied when the database opens.
    pub ddl: &'static str,
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

fn db_error(message: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(message.into())
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

/// The only durable substrate core offers protocol code.
///
/// Durable and memory tables are both ordinary SQLite tables on this one
/// connection; memory tables are `TEMP` tables. Every row helper is therefore a
/// single SQL path, and `write_transaction` rollback covers both classes.
pub struct Db {
    conn: SqliteConnection,
    replay_protected_tables: Vec<TableName>,
    replay_reset_tables: Vec<TableName>,
    replay_summary_tables: Vec<TableName>,
}

/// Temporary upper bound for read helpers that still return Vec-backed pages.
///
/// Query modules should shrink this surface into caller-supplied paging or
/// narrower SQL predicates as their fact families migrate fully to SQL.
pub const DEFAULT_QUERY_LIMIT: usize = 10_000;

impl Db {
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

    fn from_connection_with_schema_sources(
        conn: SqliteConnection,
        sources: &[SchemaSource],
    ) -> rusqlite::Result<Self> {
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
        let db = Self::from_connection_parts(
            conn,
            replay_protected_tables,
            replay_reset_tables,
            replay_summary_tables,
        )?;
        for source in sources {
            db.conn.execute_batch(source.ddl)?;
        }
        Ok(db)
    }

    fn from_connection_parts(
        conn: SqliteConnection,
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
            replay_protected_tables,
            replay_reset_tables,
            replay_summary_tables,
        })
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

    /// Write a standalone, consistent copy of this database to `path`.
    ///
    /// `VACUUM INTO` produces a single self-contained database file with no WAL
    /// or SHM sidecar, so callers can copy or open the snapshot independently.
    /// Used by replay diagnostics to run replay on scratch databases without
    /// mutating the live database. The path is interpolated as a SQL string literal
    /// because `VACUUM INTO` does not accept bound parameters; embedded quotes are
    /// escaped.
    pub fn backup_into(&self, path: &Path) -> Result<(), String> {
        let target = path
            .to_str()
            .ok_or_else(|| "snapshot path is not valid UTF-8".to_string())?
            .replace('\'', "''");
        self.conn
            .execute_batch(&format!("VACUUM INTO '{target}'"))
            .map_err(|err| format!("snapshot database: {err}"))
    }

    /// Count retained fact byte rows.
    pub fn fact_count(&self) -> rusqlite::Result<usize> {
        self.table_row_count(crate::core::schema::FACTS)
    }

    /// Load one retained fact by id.
    pub fn fact(&self, id: &FactId) -> Result<Option<Fact>, String> {
        self.conn
            .query_row(
                "SELECT f.id, m.scope, m.scope_kind, m.scope_id, m.received_at, f.bytes
                 FROM facts f
                 JOIN local_fact_admissions m ON m.fact_id = f.id
                 WHERE f.id = ?1
                 LIMIT 1",
                params![id.as_slice()],
                retained_fact_from_row,
            )
            .optional()
            .map_err(|err| format!("load fact row: {err}"))
    }

    /// Return whether a retained fact row exists.
    pub fn fact_exists(&self, id: &FactId) -> rusqlite::Result<bool> {
        self.conn
            .query_row(
                "SELECT 1 FROM facts WHERE id = ?1 LIMIT 1",
                params![id.as_slice()],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
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

fn retained_fact_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Fact> {
    let id = fact_id_column(row.get::<_, Vec<u8>>(0)?, "id")?;
    let scope_tag = row.get::<_, String>(1)?;
    let scope_kind = row.get::<_, String>(2)?;
    let scope_id = fact_id_column(row.get::<_, Vec<u8>>(3)?, "scope_id")?;
    let timestamp = u64_column(row.get::<_, i64>(4)?, "received_at")?;
    let bytes = row.get::<_, Vec<u8>>(5)?;
    Fact::from_storage_columns(id, &scope_tag, &scope_kind, scope_id, timestamp, bytes)
        .map_err(db_error)
}

fn fact_id_column(bytes: Vec<u8>, name: &str) -> rusqlite::Result<FactId> {
    bytes
        .try_into()
        .map_err(|_| db_error(format!("fact SQL column {name} is not a fact id")))
}

fn u64_column(value: i64, name: &str) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| db_error(format!("fact SQL column {name} is negative")))
}

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

fn placeholders(count: usize) -> String {
    (1..=count)
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(", ")
}

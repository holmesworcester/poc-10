//! A small SQLite-backed row store.
//!
//! This file is intentionally below the protocol. It knows how to apply declared
//! schemas, run transactions, and read or write keyed byte rows. It does not
//! know what any row means. Event admission, projection context, dependency
//! edges, network targets, and sync work are all protocol or IO concepts layered
//! on top of these primitives.
//!
//! The critical path is short:
//! 1. Open a store with the schemas declared by core IO and the selected
//!    protocol's module scopes.
//! 2. Use `write_transaction` to group rows that must become visible together.
//! 3. Use row helpers for opaque row tables. Query typed tables directly by
//!    their declared SQLite columns.
//!
//! The only dynamic SQL in this file is generic row-table creation and
//! table-name interpolation for row operations. Values are always bound
//! parameters, and table names are accepted only from `TableName` after a
//! conservative identifier check.

use crate::core::schema_dsl::{self, ColumnType, TableDeclaration, TableKind, TableStorage};
use rusqlite::{params, Connection as SqliteConnection, OptionalExtension};
use std::collections::{BTreeSet, HashSet};
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct SqliteTableColumn {
    name: String,
    declared_type: String,
    not_null: bool,
    primary_key_position: i64,
}

fn store_error(message: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(message.into())
}

fn table_declarations_from_schema_sources(
    sources: &[&str],
) -> rusqlite::Result<Vec<TableDeclaration>> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for (source_index, source) in sources.iter().enumerate() {
        let document = schema_dsl::parse_schema(source)
            .map_err(|err| store_error(format!("schema source {}: {err}", source_index + 1)))?;
        for table in document {
            if !seen.insert(table.name.clone()) {
                return Err(store_error(format!(
                    "duplicate schema table {}",
                    table.name
                )));
            }
            out.push(table);
        }
    }
    Ok(out)
}

fn sqlite_table_columns(
    conn: &SqliteConnection,
    quoted_table_name: &str,
) -> rusqlite::Result<Vec<SqliteTableColumn>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({quoted_table_name})"))?;
    let rows = stmt.query_map([], |row| {
        Ok(SqliteTableColumn {
            name: row.get(1)?,
            declared_type: row.get(2)?,
            not_null: row.get::<_, i64>(3)? != 0,
            primary_key_position: row.get(5)?,
        })
    })?;
    rows.collect()
}

fn sqlite_table_indexes(
    conn: &SqliteConnection,
    quoted_table_name: &str,
) -> rusqlite::Result<Vec<(String, bool, Vec<String>)>> {
    let mut stmt = conn.prepare(&format!("PRAGMA index_list({quoted_table_name})"))?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)? != 0,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut indexes = Vec::new();
    for row in rows {
        let (name, unique, origin) = row?;
        if origin == "pk" {
            continue;
        }
        let quoted_index_name = quoted_table_name_str(&name)?;
        let mut info = conn.prepare(&format!("PRAGMA index_info({quoted_index_name})"))?;
        let columns = info
            .query_map([], |row| row.get::<_, String>(2))?
            .collect::<Result<Vec<_>, _>>()?;
        indexes.push((name, unique, columns));
    }
    Ok(indexes)
}

fn sqlite_type(ty: &ColumnType) -> &'static str {
    match ty {
        ColumnType::Bytes { .. } => "BLOB",
        ColumnType::U64 => "INTEGER",
        ColumnType::Text => "TEXT",
        ColumnType::Bool => "INTEGER",
    }
}

fn storage_prefix(storage: TableStorage) -> &'static str {
    match storage {
        TableStorage::Durable => "",
        TableStorage::Memory => "TEMP ",
    }
}

fn prefix_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut upper = prefix.to_vec();
    let idx = upper.iter().rposition(|byte| *byte != u8::MAX)?;
    upper[idx] += 1;
    upper.truncate(idx + 1);
    Some(upper)
}

/// The only durable substrate core offers protocol code.
///
/// Durable and memory tables are both ordinary SQLite tables on this one
/// connection; memory tables are `TEMP` tables. Every row helper is therefore a
/// single SQL path, and `write_transaction` rollback covers both classes.
pub struct Store {
    conn: SqliteConnection,
    declared_tables: HashSet<String>,
    row_tables: HashSet<String>,
}

impl Store {
    /// Expose the underlying SQLite connection to core modules that own their
    /// table SQL directly.
    pub(crate) fn conn(&self) -> &SqliteConnection {
        &self.conn
    }

    /// Open a disk store and apply row-table declarations parsed from p8sql sources.
    pub fn open_disk_with_schema_sources(
        path: impl AsRef<Path>,
        sources: &[&str],
    ) -> rusqlite::Result<Self> {
        let conn = SqliteConnection::open(path)?;
        Self::from_connection_with_schema_sources(conn, sources)
    }

    /// Open an in-memory store without creating any protocol tables.
    pub fn open_memory() -> rusqlite::Result<Self> {
        Self::open_memory_with_schema_sources(&[])
    }

    /// Open an in-memory store and apply row-table declarations parsed from p8sql sources.
    pub fn open_memory_with_schema_sources(sources: &[&str]) -> rusqlite::Result<Self> {
        let conn = SqliteConnection::open_in_memory()?;
        Self::from_connection_with_schema_sources(conn, sources)
    }

    fn from_connection_with_schema_sources(
        conn: SqliteConnection,
        sources: &[&str],
    ) -> rusqlite::Result<Self> {
        let tables = table_declarations_from_schema_sources(sources)?;
        let declared_tables = tables.iter().map(|table| table.name.clone()).collect();
        let row_tables = tables
            .iter()
            .filter(|table| table.kind == TableKind::Row)
            .map(|table| table.name.clone())
            .collect();
        let store = Self::from_connection_parts(conn, declared_tables, row_tables)?;
        store.apply_schema_source_tables(&tables)?;
        Ok(store)
    }

    fn from_connection_parts(
        conn: SqliteConnection,
        declared_tables: HashSet<String>,
        row_tables: HashSet<String>,
    ) -> rusqlite::Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )?;
        Ok(Self {
            conn,
            declared_tables,
            row_tables,
        })
    }

    fn row_table_name(&self, table: TableName) -> rusqlite::Result<String> {
        if !self.row_tables.contains(table.as_str()) {
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
        if !self.declared_tables.contains(table.as_str()) {
            return Err(store_error(format!(
                "table {} is not declared",
                table.as_str()
            )));
        }
        let table_name = quoted_table_name(table)?;
        self.conn
            .query_row(&format!("SELECT COUNT(*) FROM {table_name}"), [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|count| count as usize)
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

    // Schema helpers: core applies declarations from module scopes. It does not
    // build protocol tables from central knowledge.
    fn apply_schema_source_tables(&self, tables: &[TableDeclaration]) -> rusqlite::Result<()> {
        for table in tables {
            self.apply_schema_source_table(table)?;
        }
        Ok(())
    }

    fn apply_schema_source_table(&self, table: &TableDeclaration) -> rusqlite::Result<()> {
        if table.kind == TableKind::Row {
            return self.apply_schema_source_row_table(table.storage, &table.name);
        }
        self.apply_schema_source_typed_table(table)
    }

    fn apply_schema_source_row_table(
        &self,
        storage: TableStorage,
        table_name: &str,
    ) -> rusqlite::Result<()> {
        let quoted = quoted_table_name_str(table_name)?;
        let existing = sqlite_table_columns(&self.conn, &quoted)?;
        if existing.is_empty() {
            return self.conn.execute_batch(&format!(
                "CREATE {}TABLE {quoted} (
                    row_key BLOB PRIMARY KEY NOT NULL,
                    row_value BLOB NOT NULL
                );",
                storage_prefix(storage)
            ));
        }
        let valid = existing.len() == 2
            && existing[0].name == "row_key"
            && existing[0].declared_type.eq_ignore_ascii_case("BLOB")
            && existing[0].not_null
            && existing[0].primary_key_position == 1
            && existing[1].name == "row_value"
            && existing[1].declared_type.eq_ignore_ascii_case("BLOB")
            && existing[1].not_null
            && existing[1].primary_key_position == 0;
        if valid {
            Ok(())
        } else {
            Err(store_error(format!(
                "existing table {table_name} does not match store row-table shape"
            )))
        }
    }

    fn apply_schema_source_typed_table(&self, table: &TableDeclaration) -> rusqlite::Result<()> {
        let quoted = quoted_table_name_str(&table.name)?;
        let existing = sqlite_table_columns(&self.conn, &quoted)?;
        if !existing.is_empty() {
            return self.validate_existing_typed_table(table, &existing);
        }
        self.create_typed_table(table, &quoted)
    }

    fn create_typed_table(&self, table: &TableDeclaration, quoted: &str) -> rusqlite::Result<()> {
        let mut declarations = table
            .columns
            .iter()
            .map(|column| {
                Ok(format!(
                    "{} {} NOT NULL",
                    quoted_identifier(&column.name)?,
                    sqlite_type(&column.ty)
                ))
            })
            .collect::<rusqlite::Result<Vec<_>>>()?;
        declarations.push(format!(
            "PRIMARY KEY ({})",
            quoted_identifier_list(table.row_key.columns.iter().map(String::as_str))?
        ));
        self.conn.execute_batch(&format!(
            "CREATE {}TABLE {quoted} (
                {}
            );",
            storage_prefix(table.storage),
            declarations.join(",\n                ")
        ))?;

        for index in &table.indexes {
            let index_name = quoted_table_name_str(&format!("{}_{}", table.name, index.name))?;
            let unique = if index.unique { "UNIQUE " } else { "" };
            self.conn.execute_batch(&format!(
                "CREATE {unique}INDEX IF NOT EXISTS {index_name}
                 ON {quoted} ({});",
                quoted_identifier_list(index.columns.iter().map(String::as_str))?
            ))?;
        }
        Ok(())
    }

    fn validate_existing_typed_table(
        &self,
        table: &TableDeclaration,
        columns: &[SqliteTableColumn],
    ) -> rusqlite::Result<()> {
        if columns.len() != table.columns.len() {
            return Err(store_error(format!(
                "existing table {} column count does not match declared shape",
                table.name
            )));
        }
        for (idx, declared) in table.columns.iter().enumerate() {
            let existing = &columns[idx];
            let expected_pk = table
                .row_key
                .columns
                .iter()
                .position(|column| column == &declared.name)
                .map(|position| (position + 1) as i64)
                .unwrap_or(0);
            let shape_matches = existing.name == declared.name
                && existing
                    .declared_type
                    .eq_ignore_ascii_case(sqlite_type(&declared.ty))
                && existing.not_null
                && existing.primary_key_position == expected_pk;
            if !shape_matches {
                return Err(store_error(format!(
                    "existing table {} column {} does not match declared shape",
                    table.name, declared.name
                )));
            }
        }

        let quoted = quoted_table_name_str(&table.name)?;
        let existing_indexes = sqlite_table_indexes(&self.conn, &quoted)?;
        for declared in &table.indexes {
            let name = format!("{}_{}", table.name, declared.name);
            match existing_indexes
                .iter()
                .find(|(existing_name, _, _)| existing_name == &name)
            {
                Some((_, unique, columns))
                    if *unique == declared.unique && columns == &declared.columns => {}
                Some(_) => {
                    return Err(store_error(format!(
                        "existing table {} index {} does not match declared shape",
                        table.name, name
                    )));
                }
                None => {
                    return Err(store_error(format!(
                        "existing table {} is missing index {}",
                        table.name, name
                    )));
                }
            }
        }
        for (existing_name, _, _) in &existing_indexes {
            if !table
                .indexes
                .iter()
                .any(|declared| existing_name == &format!("{}_{}", table.name, declared.name))
            {
                return Err(store_error(format!(
                    "existing table {} has undeclared index {}",
                    table.name, existing_name
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ROWS: TableName = TableName::new("test.rows");
    const MEMORY_ROWS: TableName = TableName::new("test.memory_rows");

    #[test]
    fn duplicate_row_insert_is_idempotent_but_conflicting_value_rejects() {
        let store =
            Store::open_memory_with_schema_sources(&["row_table test.rows;"]).expect("open store");
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
        let sources = ["memory row_table test.memory_rows;"];

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
        let store = Store::open_memory_with_schema_sources(&["memory row_table test.memory_rows;"])
            .expect("open store");

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
        let store = Store::open_memory_with_schema_sources(&["memory row_table test.memory_rows;"])
            .expect("open store");
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
}

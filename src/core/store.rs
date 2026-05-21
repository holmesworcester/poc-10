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
//! 3. Use the row helpers to insert, replace, delete, and scan by key prefix or
//!    by an explicit key range.
//!
//! The only dynamic SQL in this file is generic row-table creation and
//! table-name interpolation for row operations. Values are always bound
//! parameters, and table names are accepted only from `TableName` after a
//! conservative identifier check.

use crate::core::schema_dsl::{TableDeclaration, TableStorage};
use rusqlite::{params, params_from_iter, Connection as SqliteConnection, OptionalExtension};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

mod sql;
use self::sql::*;

/// A static, trusted row-table name.
///
/// Protocol and core IO modules declare these names next to the row encoders
/// that understand their values. Store validates the identifier before using
/// it in SQL, then treats rows as opaque bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TableName(&'static str);

impl TableName {
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    pub fn as_str(self) -> &'static str {
        self.0
    }
}

/// One opaque key/value row in one declared table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableRow {
    pub table: TableName,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// The only durable substrate core offers protocol code.
///
/// Durable and memory tables are both ordinary SQLite tables on this one
/// connection; memory tables are `TEMP` tables. Every row helper is therefore a
/// single SQL path, and `write_transaction` rollback covers both classes.
pub struct Store {
    conn: SqliteConnection,
    typed_tables: HashMap<String, TableDeclaration>,
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
        let typed_tables = typed_table_map(&tables)?;
        let store = Self::from_connection_parts(conn, typed_tables)?;
        store.apply_schema_source_tables(&tables)?;
        Ok(store)
    }

    fn from_connection_parts(
        conn: SqliteConnection,
        typed_tables: HashMap<String, TableDeclaration>,
    ) -> rusqlite::Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )?;
        Ok(Self { conn, typed_tables })
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
            if let Some(table) = self.typed_table(row.table) {
                inserted += self.insert_typed_row(table, row, false)?;
                continue;
            }
            let table_name = quoted_table_name(row.table)?;
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
                    return Err(rusqlite::Error::InvalidParameterName(format!(
                        "conflicting row for {}",
                        row.table.as_str()
                    )));
                }
            }
            inserted += changed;
        }
        Ok(inserted)
    }

    /// Replace rows in their declared tables.
    pub fn replace_table_rows_in_tx(&self, rows: Vec<TableRow>) -> rusqlite::Result<usize> {
        let mut replaced = 0;
        for row in rows {
            if let Some(table) = self.typed_table(row.table) {
                replaced += self.insert_typed_row(table, row, true)?;
                continue;
            }
            let table_name = quoted_table_name(row.table)?;
            replaced += self.conn.execute(
                &format!(
                    "INSERT OR REPLACE INTO {table_name}
                        (row_key, row_value)
                     VALUES (?1, ?2)"
                ),
                params![row.key, row.value],
            )?;
        }
        Ok(replaced)
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
        if let Some(declared) = self.typed_table(table) {
            for key in keys {
                deleted += self.delete_typed_row(declared, &key)?;
            }
            return Ok(deleted);
        }
        let table_name = quoted_table_name(table)?;
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
        if let Some(declared) = self.typed_table(table) {
            return self
                .typed_row_by_key(declared, key)
                .map(|row| row.map(|(_, value)| value));
        }
        let table_name = quoted_table_name(table)?;
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
        if let Some(declared) = self.typed_table(table) {
            return self.typed_row_count(declared);
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
        if let Some(declared) = self.typed_table(table) {
            return self.typed_rows(declared);
        }
        let table_name = quoted_table_name(table)?;
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
        if let Some(declared) = self.typed_table(table) {
            let mut out = Vec::new();
            for row in self.typed_rows(declared)? {
                if !row.0.starts_with(prefix) {
                    continue;
                }
                out.push(row);
                if out.len() == limit {
                    break;
                }
            }
            return Ok(out);
        }
        let table_name = quoted_table_name(table)?;
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
        if is_row_table_declaration(table) {
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
            let temp = match storage {
                TableStorage::Durable => "",
                TableStorage::Memory => "TEMP ",
            };
            return self.conn.execute_batch(&format!(
                "CREATE {temp}TABLE {quoted} (
                    row_key BLOB PRIMARY KEY NOT NULL,
                    row_value BLOB NOT NULL
                );"
            ));
        }
        validate_sqlite_row_table(table_name, &existing)
    }

    fn apply_schema_source_typed_table(&self, table: &TableDeclaration) -> rusqlite::Result<()> {
        let quoted = quoted_table_name_str(&table.name)?;
        let existing = sqlite_table_columns(&self.conn, &quoted)?;
        if !existing.is_empty() {
            return validate_sqlite_typed_table(&self.conn, table, &existing);
        }
        let temp = match table.storage {
            TableStorage::Durable => "",
            TableStorage::Memory => "TEMP ",
        };

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
            quoted_identifier_list(&table.row_key.columns)?
        ));
        self.conn.execute_batch(&format!(
            "CREATE {temp}TABLE {quoted} (
                {}
            );",
            declarations.join(",\n                ")
        ))?;

        for index in &table.indexes {
            let index_name = quoted_table_name_str(&format!("{}_{}", table.name, index.name))?;
            let unique = if index.unique { "UNIQUE " } else { "" };
            self.conn.execute_batch(&format!(
                "CREATE {unique}INDEX IF NOT EXISTS {index_name}
                 ON {quoted} ({});",
                quoted_identifier_list(&index.columns)?
            ))?;
        }
        Ok(())
    }

    fn typed_table(&self, table: TableName) -> Option<&TableDeclaration> {
        self.typed_tables.get(table.as_str())
    }

    fn insert_typed_row(
        &self,
        table: &TableDeclaration,
        row: TableRow,
        replace: bool,
    ) -> rusqlite::Result<usize> {
        let values = decode_typed_row_values(table, &row)?;
        let quoted = quoted_table_name_str(&table.name)?;
        let columns = table_column_list(table)?;
        let placeholders = placeholders(table.columns.len());
        let insert = if replace {
            "INSERT OR REPLACE"
        } else {
            "INSERT OR IGNORE"
        };
        let changed = self.conn.execute(
            &format!("{insert} INTO {quoted} ({columns}) VALUES ({placeholders})"),
            params_from_iter(values.iter()),
        )?;

        if !replace && changed == 0 {
            match self.typed_row_by_key(table, &row.key)? {
                Some((_, existing)) if existing == row.value => {}
                _ => {
                    return Err(rusqlite::Error::InvalidParameterName(format!(
                        "conflicting row for {}",
                        row.table.as_str()
                    )));
                }
            }
        }
        Ok(changed)
    }

    fn delete_typed_row(&self, table: &TableDeclaration, key: &[u8]) -> rusqlite::Result<usize> {
        let key_values = decode_typed_key_values(table, key)?;
        let quoted = quoted_table_name_str(&table.name)?;
        self.conn.execute(
            &format!(
                "DELETE FROM {quoted} WHERE {}",
                row_key_where_clause(table)?
            ),
            params_from_iter(key_values.iter()),
        )
    }

    fn typed_row_by_key(
        &self,
        table: &TableDeclaration,
        key: &[u8],
    ) -> rusqlite::Result<Option<(Vec<u8>, Vec<u8>)>> {
        let key_values = decode_typed_key_values(table, key)?;
        self.typed_row_by_decoded_key(table, &key_values)
    }

    fn typed_row_by_decoded_key(
        &self,
        table: &TableDeclaration,
        key_values: &[rusqlite::types::Value],
    ) -> rusqlite::Result<Option<(Vec<u8>, Vec<u8>)>> {
        let quoted = quoted_table_name_str(&table.name)?;
        self.conn
            .query_row(
                &format!(
                    "SELECT {} FROM {quoted} WHERE {}",
                    table_column_list(table)?,
                    row_key_where_clause(table)?
                ),
                params_from_iter(key_values.iter()),
                |row| sqlite_row_to_table_row(table, row),
            )
            .optional()
    }

    fn typed_row_count(&self, table: &TableDeclaration) -> rusqlite::Result<usize> {
        let quoted = quoted_table_name_str(&table.name)?;
        self.conn
            .query_row(&format!("SELECT COUNT(*) FROM {quoted}"), [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|count| count as usize)
    }

    fn typed_rows(&self, table: &TableDeclaration) -> rusqlite::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let quoted = quoted_table_name_str(&table.name)?;
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {} FROM {quoted} ORDER BY {}",
            table_column_list(table)?,
            quoted_identifier_list(&table.row_key.columns)?
        ))?;
        let rows = stmt.query_map([], |row| sqlite_row_to_table_row(table, row))?;
        rows.collect()
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

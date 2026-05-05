//! A small SQLite-backed row store.
//!
//! This file is intentionally below the protocol. It knows how to apply declared
//! schemas, run transactions, and read or write keyed byte rows. It does not
//! know what any row means. Event admission, labels, missing-dep edges, network
//! targets, and sync queues are all protocol or IO concepts layered on top of
//! these primitives.
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

use rusqlite::{params, Connection as SqliteConnection, OptionalExtension};
use std::{path::Path, time::Duration};

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

/// Where a declared schema is expected to live.
///
/// The SQL still says `CREATE TABLE` or `CREATE TEMP TABLE`; this value makes a
/// module's persistence choice visible to the registry before SQLite sees the
/// statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageClass {
    Durable,
    Temp,
}

/// One schema fragment owned by a core IO module or protocol module scope.
///
/// Most modules should use `Schema::durable_row_table`: the module owns the
/// table name and persistence decision, while store supplies the uniform
/// `(row_key BLOB PRIMARY KEY, row_value BLOB)` shape. Raw SQL exists for
/// future specialized indexes, but it should be uncommon and reviewed harder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schema {
    pub id: &'static str,
    pub storage: StorageClass,
    pub definition: SchemaDefinition,
}

/// The concrete schema operation requested by a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaDefinition {
    RowTable(TableName),
    Sql(&'static str),
}

impl Schema {
    pub const fn row_table(id: &'static str, storage: StorageClass, table: TableName) -> Self {
        Self {
            id,
            storage,
            definition: SchemaDefinition::RowTable(table),
        }
    }

    pub const fn durable_row_table(id: &'static str, table: TableName) -> Self {
        Self::row_table(id, StorageClass::Durable, table)
    }

    pub const fn temp_row_table(id: &'static str, table: TableName) -> Self {
        Self::row_table(id, StorageClass::Temp, table)
    }

    pub const fn durable(id: &'static str, sql: &'static str) -> Self {
        Self {
            id,
            storage: StorageClass::Durable,
            definition: SchemaDefinition::Sql(sql),
        }
    }

    pub const fn temp(id: &'static str, sql: &'static str) -> Self {
        Self {
            id,
            storage: StorageClass::Temp,
            definition: SchemaDefinition::Sql(sql),
        }
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
pub struct Store {
    conn: SqliteConnection,
}

impl Store {
    /// Open a disk store without creating any protocol tables.
    ///
    /// Production callers should prefer `open_disk_with_schemas`; this form is
    /// kept for tests that exercise the bare row substrate.
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        Self::open_disk_with_schemas(path, &[])
    }

    /// Alias for `open`, kept so tests can name the backing medium explicitly.
    pub fn open_disk(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        Self::open_disk_with_schemas(path, &[])
    }

    /// Open a disk store and apply the caller-declared schemas.
    pub fn open_disk_with_schemas(
        path: impl AsRef<Path>,
        schemas: &[Schema],
    ) -> rusqlite::Result<Self> {
        let conn = SqliteConnection::open(path)?;
        Self::from_connection(conn, schemas)
    }

    /// Open an in-memory store without creating any protocol tables.
    pub fn open_memory() -> rusqlite::Result<Self> {
        Self::open_memory_with_schemas(&[])
    }

    /// Open an in-memory store and apply the caller-declared schemas.
    pub fn open_memory_with_schemas(schemas: &[Schema]) -> rusqlite::Result<Self> {
        let conn = SqliteConnection::open_in_memory()?;
        Self::from_connection(conn, schemas)
    }

    fn from_connection(conn: SqliteConnection, schemas: &[Schema]) -> rusqlite::Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))?;
        let store = Self { conn };
        store.apply_schemas(schemas)?;
        Ok(store)
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
            Ok(value) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(value)
            }
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
            let table_name = quoted_table_name(row.table)?;
            inserted += self.conn.execute(
                &format!(
                    "INSERT OR IGNORE INTO {table_name}
                        (row_key, row_value)
                     VALUES (?1, ?2)"
                ),
                params![row.key, row.value],
            )?;
        }
        Ok(inserted)
    }

    /// Replace rows in their declared tables.
    pub fn replace_table_rows_in_tx(&self, rows: Vec<TableRow>) -> rusqlite::Result<usize> {
        let mut replaced = 0;
        for row in rows {
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
        let table_name = quoted_table_name(table)?;
        self.conn
            .query_row(&format!("SELECT COUNT(*) FROM {table_name}"), [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|count| count as usize)
    }

    /// Scan one declared table in key order.
    pub fn table_rows(&self, table: TableName) -> rusqlite::Result<Vec<(Vec<u8>, Vec<u8>)>> {
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

    /// Scan one declared table by lexicographic key range.
    ///
    /// This is still a row-store primitive, not a protocol index. Protocol
    /// modules choose key encodings such as `(timestamp, event_id)` and store
    /// only asks SQLite for rows whose opaque keys fall in the requested span.
    pub fn table_rows_in_key_range(
        &self,
        table: TableName,
        lower_inclusive: &[u8],
        upper_exclusive: Option<&[u8]>,
        limit: usize,
    ) -> rusqlite::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let table_name = quoted_table_name(table)?;
        match upper_exclusive {
            Some(upper) => {
                let mut stmt = self.conn.prepare(&format!(
                    "SELECT row_key, row_value FROM {table_name}
                         WHERE row_key >= ?1 AND row_key < ?2
                         ORDER BY row_key
                         LIMIT ?3"
                ))?;
                let rows = stmt
                    .query_map(params![lower_inclusive, upper, limit as i64], |row| {
                        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
                    })?;
                rows.collect()
            }
            None => {
                let mut stmt = self.conn.prepare(&format!(
                    "SELECT row_key, row_value FROM {table_name}
                         WHERE row_key >= ?1
                         ORDER BY row_key
                         LIMIT ?2"
                ))?;
                let rows = stmt.query_map(params![lower_inclusive, limit as i64], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
                })?;
                rows.collect()
            }
        }
    }

    // Schema helpers: core applies declarations from module scopes. It does not
    // build protocol tables from central knowledge.
    fn apply_schemas(&self, schemas: &[Schema]) -> rusqlite::Result<()> {
        validate_schema_ids(schemas)?;
        for schema in schemas {
            self.apply_schema(schema)?;
        }
        Ok(())
    }

    fn apply_schema(&self, schema: &Schema) -> rusqlite::Result<()> {
        match schema.definition {
            SchemaDefinition::RowTable(table) => self.apply_row_table_schema(schema.storage, table),
            SchemaDefinition::Sql(sql) => self.conn.execute_batch(sql),
        }
    }

    fn apply_row_table_schema(
        &self,
        storage: StorageClass,
        table: TableName,
    ) -> rusqlite::Result<()> {
        let table_name = quoted_table_name(table)?;
        let create = match storage {
            StorageClass::Durable => "CREATE TABLE IF NOT EXISTS",
            StorageClass::Temp => "CREATE TEMP TABLE IF NOT EXISTS",
        };
        self.conn.execute_batch(&format!(
            "{create} {table_name} (
                row_key BLOB PRIMARY KEY NOT NULL,
                row_value BLOB NOT NULL
            );"
        ))
    }
}

fn validate_schema_ids(schemas: &[Schema]) -> rusqlite::Result<()> {
    for (left_index, left) in schemas.iter().enumerate() {
        validate_schema_id(left.id)?;
        for right in &schemas[left_index + 1..] {
            if left.id == right.id {
                return Err(rusqlite::Error::InvalidParameterName(format!(
                    "duplicate schema id {}",
                    left.id
                )));
            }
        }
    }
    Ok(())
}

fn validate_schema_id(id: &str) -> rusqlite::Result<()> {
    if id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return Ok(());
    }
    Err(rusqlite::Error::InvalidParameterName(format!(
        "invalid schema id {id}"
    )))
}

/// Compute the exclusive upper bound for a byte-prefix range.
fn prefix_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut upper = prefix.to_vec();
    for byte in upper.iter_mut().rev() {
        if *byte != u8::MAX {
            *byte += 1;
            upper.truncate(
                prefix
                    .iter()
                    .rposition(|candidate| *candidate != u8::MAX)
                    .expect("position found")
                    + 1,
            );
            return Some(upper);
        }
    }
    None
}

/// Quote a trusted static table name after rejecting unsafe identifier bytes.
fn quoted_table_name(table: TableName) -> rusqlite::Result<String> {
    let name = table.as_str();
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

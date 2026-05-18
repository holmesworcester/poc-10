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

use crate::core::schema_dsl::{self, ColumnType, TableDeclaration, TableKind};
use rusqlite::{
    params, params_from_iter, types::Value, Connection as SqliteConnection, OptionalExtension,
};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
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
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    pub fn as_str(self) -> &'static str {
        self.0
    }
}

/// Where a declared row table is expected to live.
///
/// Durable rows are normal SQLite tables. Memory rows are process-local maps
/// held by `Store`; they are not SQLite TEMP tables and are never visible to a
/// second store handle or another process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageClass {
    Durable,
    Memory,
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

    pub const fn memory_row_table(id: &'static str, table: TableName) -> Self {
        Self::row_table(id, StorageClass::Memory, table)
    }

    pub const fn durable(id: &'static str, sql: &'static str) -> Self {
        Self {
            id,
            storage: StorageClass::Durable,
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

type MemoryRows = BTreeMap<Vec<u8>, Vec<u8>>;
type MemoryTables = HashMap<TableName, MemoryRows>;

/// The only durable substrate core offers protocol code.
pub struct Store {
    conn: SqliteConnection,
    table_storage: HashMap<TableName, StorageClass>,
    typed_tables: HashMap<String, TableDeclaration>,
    memory_tables: RefCell<MemoryTables>,
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

    /// Open a disk store and apply row-table declarations parsed from p8sql sources.
    pub fn open_disk_with_schema_sources(
        path: impl AsRef<Path>,
        sources: &[&str],
    ) -> rusqlite::Result<Self> {
        Self::open_disk_with_schema_sources_and_schemas(path, sources, &[])
    }

    /// Open a disk store and apply p8sql declarations plus explicit core schemas.
    pub fn open_disk_with_schema_sources_and_schemas(
        path: impl AsRef<Path>,
        sources: &[&str],
        schemas: &[Schema],
    ) -> rusqlite::Result<Self> {
        let conn = SqliteConnection::open(path)?;
        Self::from_connection_with_schema_sources_and_schemas(conn, sources, schemas)
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

    /// Open an in-memory store and apply row-table declarations parsed from p8sql sources.
    pub fn open_memory_with_schema_sources(sources: &[&str]) -> rusqlite::Result<Self> {
        Self::open_memory_with_schema_sources_and_schemas(sources, &[])
    }

    /// Open an in-memory store and apply p8sql declarations plus explicit core schemas.
    pub fn open_memory_with_schema_sources_and_schemas(
        sources: &[&str],
        schemas: &[Schema],
    ) -> rusqlite::Result<Self> {
        let conn = SqliteConnection::open_in_memory()?;
        Self::from_connection_with_schema_sources_and_schemas(conn, sources, schemas)
    }

    fn from_connection(conn: SqliteConnection, schemas: &[Schema]) -> rusqlite::Result<Self> {
        let store = Self::from_connection_parts(conn, table_storage_map(schemas)?, HashMap::new())?;
        store.apply_schemas(schemas)?;
        Ok(store)
    }

    fn from_connection_with_schema_sources_and_schemas(
        conn: SqliteConnection,
        sources: &[&str],
        schemas: &[Schema],
    ) -> rusqlite::Result<Self> {
        let tables = table_declarations_from_schema_sources(sources)?;
        let typed_tables = typed_table_map(&tables)?;
        let store = Self::from_connection_parts(conn, table_storage_map(schemas)?, typed_tables)?;
        store.apply_schemas(schemas)?;
        store.apply_schema_source_tables(&tables)?;
        Ok(store)
    }

    fn from_connection_parts(
        conn: SqliteConnection,
        table_storage: HashMap<TableName, StorageClass>,
        typed_tables: HashMap<String, TableDeclaration>,
    ) -> rusqlite::Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA journal_mode = WAL;")?;
        let memory_tables = table_storage
            .iter()
            .filter_map(|(table, storage)| {
                (*storage == StorageClass::Memory).then_some((*table, BTreeMap::new()))
            })
            .collect();
        let store = Self {
            conn,
            table_storage,
            typed_tables,
            memory_tables: RefCell::new(memory_tables),
        };
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
        let memory_before = self.memory_tables.borrow().clone();
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = apply(self);
        match result {
            Ok(value) => match self.conn.execute_batch("COMMIT") {
                Ok(()) => Ok(value),
                Err(err) => {
                    *self.memory_tables.borrow_mut() = memory_before;
                    let _ = self.conn.execute_batch("ROLLBACK");
                    Err(err)
                }
            },
            Err(err) => {
                *self.memory_tables.borrow_mut() = memory_before;
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
            if self.storage_for(row.table) == StorageClass::Memory {
                inserted += self.insert_memory_row(row)?;
                continue;
            }
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
            if self.storage_for(row.table) == StorageClass::Memory {
                self.memory_table_mut(row.table).insert(row.key, row.value);
                replaced += 1;
                continue;
            }
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
        if self.storage_for(table) == StorageClass::Memory {
            let mut tables = self.memory_tables.borrow_mut();
            let rows = tables.entry(table).or_default();
            for key in keys {
                if rows.remove(&key).is_some() {
                    deleted += 1;
                }
            }
            return Ok(deleted);
        }
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
        if self.storage_for(table) == StorageClass::Memory {
            return Ok(self
                .memory_tables
                .borrow()
                .get(&table)
                .and_then(|rows| rows.get(key).cloned()));
        }
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
        if self.storage_for(table) == StorageClass::Memory {
            return Ok(self
                .memory_tables
                .borrow()
                .get(&table)
                .map(BTreeMap::len)
                .unwrap_or_default());
        }
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

    /// SQLite connection-local external write marker.
    ///
    /// `PRAGMA data_version` changes when another connection commits to the
    /// same database, but not for writes made by this `Store`'s own connection.
    /// Runtime code can use it to avoid broad reloads while still noticing
    /// sibling CLI processes that appended facts or intents.
    pub fn data_version(&self) -> rusqlite::Result<i64> {
        self.conn
            .query_row("PRAGMA data_version", [], |row| row.get(0))
    }

    /// Scan one declared table in key order.
    pub fn table_rows(&self, table: TableName) -> rusqlite::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if self.storage_for(table) == StorageClass::Memory {
            return Ok(self
                .memory_tables
                .borrow()
                .get(&table)
                .map(|rows| {
                    rows.iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect()
                })
                .unwrap_or_default());
        }
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
        if self.storage_for(table) == StorageClass::Memory {
            return Ok(self.memory_rows_with_key_prefix(table, prefix, limit));
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

    /// Scan one declared table by lexicographic key range.
    ///
    /// This is still a row-store primitive, not a protocol index. Protocol
    /// modules choose key encodings such as `(timestamp, fact_id)` and store
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
        if self.storage_for(table) == StorageClass::Memory {
            return Ok(self.memory_rows_in_key_range(
                table,
                lower_inclusive,
                upper_exclusive,
                limit,
            ));
        }
        if let Some(declared) = self.typed_table(table) {
            let mut out = Vec::new();
            for row in self.typed_rows(declared)? {
                if row.0.as_slice() < lower_inclusive {
                    continue;
                }
                if upper_exclusive.is_some_and(|upper| row.0.as_slice() >= upper) {
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

    fn apply_schema_source_tables(&self, tables: &[TableDeclaration]) -> rusqlite::Result<()> {
        for table in tables {
            self.apply_schema_source_table(table)?;
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
        if storage == StorageClass::Memory {
            self.memory_tables.borrow_mut().entry(table).or_default();
            return Ok(());
        }
        let table_name = quoted_table_name(table)?;
        self.conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {table_name} (
                row_key BLOB PRIMARY KEY NOT NULL,
                row_value BLOB NOT NULL
            );"
        ))
    }

    fn apply_schema_source_table(&self, table: &TableDeclaration) -> rusqlite::Result<()> {
        if is_row_table_declaration(table) {
            return self.apply_schema_source_row_table(&table.name);
        }
        self.apply_schema_source_typed_table(table)
    }

    fn apply_schema_source_row_table(&self, table_name: &str) -> rusqlite::Result<()> {
        let quoted = quoted_table_name_str(table_name)?;
        let existing = sqlite_table_columns(&self.conn, &quoted)?;
        if existing.is_empty() {
            return self.conn.execute_batch(&format!(
                "CREATE TABLE {quoted} (
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
            "CREATE TABLE {quoted} (
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

    fn storage_for(&self, table: TableName) -> StorageClass {
        self.table_storage
            .get(&table)
            .copied()
            .unwrap_or(StorageClass::Durable)
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

    fn memory_table_mut(
        &self,
        table: TableName,
    ) -> std::cell::RefMut<'_, BTreeMap<Vec<u8>, Vec<u8>>> {
        std::cell::RefMut::map(self.memory_tables.borrow_mut(), |tables| {
            tables.entry(table).or_default()
        })
    }

    fn insert_memory_row(&self, row: TableRow) -> rusqlite::Result<usize> {
        use std::collections::btree_map::Entry;

        let mut rows = self.memory_table_mut(row.table);
        match rows.entry(row.key) {
            Entry::Vacant(entry) => {
                entry.insert(row.value);
                Ok(1)
            }
            Entry::Occupied(entry) if entry.get() == &row.value => Ok(0),
            Entry::Occupied(_) => Err(rusqlite::Error::InvalidParameterName(format!(
                "conflicting row for {}",
                row.table.as_str()
            ))),
        }
    }

    fn memory_rows_with_key_prefix(
        &self,
        table: TableName,
        prefix: &[u8],
        limit: usize,
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let tables = self.memory_tables.borrow();
        let Some(rows) = tables.get(&table) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        if let Some(upper) = prefix_upper_bound(prefix) {
            for (key, value) in rows.range(prefix.to_vec()..upper) {
                if out.len() == limit {
                    break;
                }
                out.push((key.clone(), value.clone()));
            }
        } else {
            for (key, value) in rows.range(prefix.to_vec()..) {
                if !key.starts_with(prefix) || out.len() == limit {
                    break;
                }
                out.push((key.clone(), value.clone()));
            }
        }
        out
    }

    fn memory_rows_in_key_range(
        &self,
        table: TableName,
        lower_inclusive: &[u8],
        upper_exclusive: Option<&[u8]>,
        limit: usize,
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let tables = self.memory_tables.borrow();
        let Some(rows) = tables.get(&table) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        match upper_exclusive {
            Some(upper) => {
                for (key, value) in rows.range(lower_inclusive.to_vec()..upper.to_vec()) {
                    if out.len() == limit {
                        break;
                    }
                    out.push((key.clone(), value.clone()));
                }
            }
            None => {
                for (key, value) in rows.range(lower_inclusive.to_vec()..) {
                    if out.len() == limit {
                        break;
                    }
                    out.push((key.clone(), value.clone()));
                }
            }
        }
        out
    }
}

fn table_declarations_from_schema_sources(
    sources: &[&str],
) -> rusqlite::Result<Vec<TableDeclaration>> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for (source_index, source) in sources.iter().enumerate() {
        let document = schema_dsl::parse_schema(source).map_err(|err| {
            rusqlite::Error::InvalidParameterName(format!(
                "schema source {}: {err}",
                source_index + 1
            ))
        })?;
        for table in document.tables {
            if !seen.insert(table.name.clone()) {
                return Err(rusqlite::Error::InvalidParameterName(format!(
                    "duplicate schema table {}",
                    table.name
                )));
            }
            out.push(table);
        }
    }
    Ok(out)
}

fn typed_table_map(
    tables: &[TableDeclaration],
) -> rusqlite::Result<HashMap<String, TableDeclaration>> {
    let mut out = HashMap::new();
    for table in tables {
        if table.kind == TableKind::Typed {
            if out.insert(table.name.clone(), table.clone()).is_some() {
                return Err(rusqlite::Error::InvalidParameterName(format!(
                    "duplicate typed schema table {}",
                    table.name
                )));
            }
        }
    }
    Ok(out)
}

fn is_row_table_declaration(table: &TableDeclaration) -> bool {
    table.kind == TableKind::Row
}

fn decode_typed_row_values(
    table: &TableDeclaration,
    row: &TableRow,
) -> rusqlite::Result<Vec<Value>> {
    let key_values = decode_typed_key_values_named(table, &row.key)?;
    let mut value_offset = 0;
    let mut values = Vec::with_capacity(table.columns.len());

    for column in &table.columns {
        if let Some((_, value)) = key_values
            .iter()
            .find(|(name, _)| name.as_str() == column.name)
        {
            values.push(value.clone());
        } else {
            values.push(decode_column_value(
                &column.ty,
                &row.value,
                &mut value_offset,
                &format!("{}.{}", table.name, column.name),
            )?);
        }
    }

    if value_offset != row.value.len() {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "typed row for {} has trailing value bytes",
            table.name
        )));
    }
    Ok(values)
}

fn decode_typed_key_values(table: &TableDeclaration, key: &[u8]) -> rusqlite::Result<Vec<Value>> {
    decode_typed_key_values_named(table, key).map(|values| {
        values
            .into_iter()
            .map(|(_, value)| value)
            .collect::<Vec<_>>()
    })
}

fn decode_typed_key_values_named(
    table: &TableDeclaration,
    key: &[u8],
) -> rusqlite::Result<Vec<(String, Value)>> {
    let mut offset = 0;
    let mut values = Vec::with_capacity(table.row_key.columns.len());
    for column_name in &table.row_key.columns {
        let column = table.column(column_name).ok_or_else(|| {
            rusqlite::Error::InvalidParameterName(format!(
                "typed table {} row key references unknown column {}",
                table.name, column_name
            ))
        })?;
        values.push((
            column.name.clone(),
            decode_column_value(
                &column.ty,
                key,
                &mut offset,
                &format!("{}.{}", table.name, column.name),
            )?,
        ));
    }
    if offset != key.len() {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "typed row for {} has trailing key bytes",
            table.name
        )));
    }
    Ok(values)
}

fn sqlite_row_to_table_row(
    table: &TableDeclaration,
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<(Vec<u8>, Vec<u8>)> {
    let mut key = Vec::new();
    let mut value = Vec::new();
    for (index, column) in table.columns.iter().enumerate() {
        let column_value = sqlite_column_value(row, index, &column.ty)?;
        if table
            .row_key
            .columns
            .iter()
            .any(|name| name == &column.name)
        {
            encode_column_value(&column.ty, &column_value, &mut key, &column.name)?;
        } else {
            encode_column_value(&column.ty, &column_value, &mut value, &column.name)?;
        }
    }
    Ok((key, value))
}

fn decode_column_value(
    ty: &ColumnType,
    bytes: &[u8],
    offset: &mut usize,
    label: &str,
) -> rusqlite::Result<Value> {
    match ty {
        ColumnType::Bytes { len: Some(len) } => {
            let out = take_exact(bytes, offset, *len, label)?;
            Ok(Value::Blob(out.to_vec()))
        }
        ColumnType::Bytes { len: None } => {
            let len = take_u32(bytes, offset, label)? as usize;
            let out = take_exact(bytes, offset, len, label)?;
            Ok(Value::Blob(out.to_vec()))
        }
        ColumnType::U64 => {
            let raw = take_exact(bytes, offset, 8, label)?;
            let value = u64::from_be_bytes(raw.try_into().unwrap());
            let value = i64::try_from(value).map_err(|_| {
                rusqlite::Error::InvalidParameterName(format!(
                    "typed column {label} exceeds SQLite integer range"
                ))
            })?;
            Ok(Value::Integer(value))
        }
        ColumnType::I64 => {
            let raw = take_exact(bytes, offset, 8, label)?;
            Ok(Value::Integer(i64::from_be_bytes(raw.try_into().unwrap())))
        }
        ColumnType::Text => {
            let len = take_u32(bytes, offset, label)? as usize;
            let raw = take_exact(bytes, offset, len, label)?;
            let text = String::from_utf8(raw.to_vec()).map_err(|err| {
                rusqlite::Error::InvalidParameterName(format!(
                    "typed column {label} is not utf8: {err}"
                ))
            })?;
            Ok(Value::Text(text))
        }
        ColumnType::Bool => {
            let raw = take_exact(bytes, offset, 1, label)?[0];
            match raw {
                0 => Ok(Value::Integer(0)),
                1 => Ok(Value::Integer(1)),
                _ => Err(rusqlite::Error::InvalidParameterName(format!(
                    "typed column {label} has invalid bool byte {raw}"
                ))),
            }
        }
    }
}

fn encode_column_value(
    ty: &ColumnType,
    value: &Value,
    out: &mut Vec<u8>,
    label: &str,
) -> rusqlite::Result<()> {
    match (ty, value) {
        (ColumnType::Bytes { len: Some(len) }, Value::Blob(bytes)) => {
            if bytes.len() != *len {
                return Err(rusqlite::Error::InvalidParameterName(format!(
                    "typed column {label} has {} bytes, expected {len}",
                    bytes.len()
                )));
            }
            out.extend_from_slice(bytes);
        }
        (ColumnType::Bytes { len: None }, Value::Blob(bytes)) => {
            put_sized_u32(out, bytes, label)?;
        }
        (ColumnType::U64, Value::Integer(value)) => {
            let value = u64::try_from(*value).map_err(|_| {
                rusqlite::Error::InvalidParameterName(format!(
                    "typed column {label} has negative u64 value"
                ))
            })?;
            out.extend_from_slice(&value.to_be_bytes());
        }
        (ColumnType::I64, Value::Integer(value)) => {
            out.extend_from_slice(&value.to_be_bytes());
        }
        (ColumnType::Text, Value::Text(text)) => {
            put_sized_u32(out, text.as_bytes(), label)?;
        }
        (ColumnType::Bool, Value::Integer(0)) => out.push(0),
        (ColumnType::Bool, Value::Integer(1)) => out.push(1),
        (ColumnType::Bool, Value::Integer(value)) => {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "typed column {label} has invalid bool integer {value}"
            )));
        }
        _ => {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "typed column {label} value does not match declared type"
            )));
        }
    }
    Ok(())
}

fn sqlite_column_value(
    row: &rusqlite::Row<'_>,
    index: usize,
    ty: &ColumnType,
) -> rusqlite::Result<Value> {
    match ty {
        ColumnType::Bytes { .. } => row.get::<_, Vec<u8>>(index).map(Value::Blob),
        ColumnType::U64 | ColumnType::I64 | ColumnType::Bool => {
            row.get::<_, i64>(index).map(Value::Integer)
        }
        ColumnType::Text => row.get::<_, String>(index).map(Value::Text),
    }
}

fn take_exact<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    len: usize,
    label: &str,
) -> rusqlite::Result<&'a [u8]> {
    let end = offset.checked_add(len).ok_or_else(|| {
        rusqlite::Error::InvalidParameterName(format!("typed column {label} length overflows"))
    })?;
    if end > bytes.len() {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "typed column {label} is truncated"
        )));
    }
    let out = &bytes[*offset..end];
    *offset = end;
    Ok(out)
}

fn take_u32(bytes: &[u8], offset: &mut usize, label: &str) -> rusqlite::Result<u32> {
    let raw = take_exact(bytes, offset, 4, label)?;
    Ok(u32::from_be_bytes(raw.try_into().unwrap()))
}

fn put_sized_u32(out: &mut Vec<u8>, bytes: &[u8], label: &str) -> rusqlite::Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| {
        rusqlite::Error::InvalidParameterName(format!("typed column {label} exceeds u32 length"))
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn table_column_list(table: &TableDeclaration) -> rusqlite::Result<String> {
    let columns = table
        .columns
        .iter()
        .map(|column| column.name.clone())
        .collect::<Vec<_>>();
    quoted_identifier_list(&columns)
}

fn row_key_where_clause(table: &TableDeclaration) -> rusqlite::Result<String> {
    table
        .row_key
        .columns
        .iter()
        .enumerate()
        .map(|(index, column)| Ok(format!("{} = ?{}", quoted_identifier(column)?, index + 1)))
        .collect::<rusqlite::Result<Vec<_>>>()
        .map(|clauses| clauses.join(" AND "))
}

fn placeholders(count: usize) -> String {
    (1..=count)
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// One column returned by SQLite's `PRAGMA table_info`.
///
/// This is storage metadata, not protocol schema. Store uses it only when a
/// table already exists, to prove that the physical table still has the core
/// row-store shape before writing opaque bytes into it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SqliteTableColumn {
    name: String,
    declared_type: String,
    not_null: bool,
    primary_key_position: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SqliteIndex {
    name: String,
    unique: bool,
    columns: Vec<String>,
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
) -> rusqlite::Result<Vec<SqliteIndex>> {
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
        indexes.push(SqliteIndex {
            name,
            unique,
            columns,
        });
    }
    Ok(indexes)
}

fn validate_sqlite_row_table(
    table_name: &str,
    columns: &[SqliteTableColumn],
) -> rusqlite::Result<()> {
    let valid = columns.len() == 2
        && columns[0].name == "row_key"
        && columns[0].declared_type.eq_ignore_ascii_case("BLOB")
        && columns[0].not_null
        && columns[0].primary_key_position == 1
        && columns[1].name == "row_value"
        && columns[1].declared_type.eq_ignore_ascii_case("BLOB")
        && columns[1].not_null
        && columns[1].primary_key_position == 0;
    if valid {
        return Ok(());
    }
    Err(rusqlite::Error::InvalidParameterName(format!(
        "existing table {table_name} does not match store row-table shape"
    )))
}

fn validate_sqlite_typed_table(
    conn: &SqliteConnection,
    table: &TableDeclaration,
    columns: &[SqliteTableColumn],
) -> rusqlite::Result<()> {
    if columns.len() != table.columns.len() {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "existing table {} column count does not match declared shape",
            table.name
        )));
    }
    for (idx, declared) in table.columns.iter().enumerate() {
        let existing = &columns[idx];
        if existing.name != declared.name {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "existing table {} column {} is {}, expected {}",
                table.name, idx, existing.name, declared.name
            )));
        }
        if !existing
            .declared_type
            .eq_ignore_ascii_case(sqlite_type(&declared.ty))
        {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "existing table {} column {} has type {}, expected {}",
                table.name,
                declared.name,
                existing.declared_type,
                sqlite_type(&declared.ty)
            )));
        }
        if !existing.not_null {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "existing table {} column {} is nullable",
                table.name, declared.name
            )));
        }
        let expected_pk = table
            .row_key
            .columns
            .iter()
            .position(|column| column == &declared.name)
            .map(|position| (position + 1) as i64)
            .unwrap_or(0);
        if existing.primary_key_position != expected_pk {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "existing table {} column {} has primary-key position {}, expected {}",
                table.name, declared.name, existing.primary_key_position, expected_pk
            )));
        }
    }

    let quoted = quoted_table_name_str(&table.name)?;
    let existing_indexes = sqlite_table_indexes(conn, &quoted)?;
    for declared in &table.indexes {
        let name = format!("{}_{}", table.name, declared.name);
        let Some(existing) = existing_indexes.iter().find(|index| index.name == name) else {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "existing table {} is missing index {}",
                table.name, name
            )));
        };
        if existing.unique != declared.unique {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "existing table {} index {} uniqueness does not match",
                table.name, name
            )));
        }
        if existing.columns != declared.columns {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "existing table {} index {} columns {:?}, expected {:?}",
                table.name, name, existing.columns, declared.columns
            )));
        }
    }
    for existing in &existing_indexes {
        if !table
            .indexes
            .iter()
            .any(|declared| existing.name == format!("{}_{}", table.name, declared.name))
        {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "existing table {} has undeclared index {}",
                table.name, existing.name
            )));
        }
    }
    Ok(())
}

fn sqlite_type(ty: &ColumnType) -> &'static str {
    match ty {
        ColumnType::Bytes { .. } => "BLOB",
        ColumnType::U64 | ColumnType::I64 => "INTEGER",
        ColumnType::Text => "TEXT",
        ColumnType::Bool => "INTEGER",
    }
}

fn table_storage_map(schemas: &[Schema]) -> rusqlite::Result<HashMap<TableName, StorageClass>> {
    let mut out = HashMap::new();
    for schema in schemas {
        if let SchemaDefinition::RowTable(table) = schema.definition {
            match out.insert(table, schema.storage) {
                Some(existing) if existing != schema.storage => {
                    return Err(rusqlite::Error::InvalidParameterName(format!(
                        "table {} declared with multiple storage classes",
                        table.as_str()
                    )));
                }
                _ => {}
            }
        }
    }
    Ok(out)
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

/// Quote a declared table name after rejecting unsafe identifier bytes.
fn quoted_table_name(table: TableName) -> rusqlite::Result<String> {
    quoted_table_name_str(table.as_str())
}

fn quoted_table_name_str(name: &str) -> rusqlite::Result<String> {
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

fn quoted_identifier(name: &str) -> rusqlite::Result<String> {
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

fn quoted_identifier_list(columns: &[String]) -> rusqlite::Result<String> {
    columns
        .iter()
        .map(|column| quoted_identifier(column))
        .collect::<rusqlite::Result<Vec<_>>>()
        .map(|columns| columns.join(", "))
}

/// Wrap a row-codec error in the `rusqlite::Error` variant the rest of the
/// store API uses. Row helpers across the workers and protocol schema files
/// share this shape: a `String` describing why decoding a row's bytes
/// failed is lifted to `rusqlite::Error::InvalidParameterName` so it can
/// flow through `?` alongside genuine SQL errors. Centralizing the
/// constructor here keeps the variant choice in one place.
pub fn table_error(err: String) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ROWS: TableName = TableName::new("test.rows");
    const MEMORY_ROWS: TableName = TableName::new("test.memory_rows");

    #[test]
    fn duplicate_row_insert_is_idempotent_but_conflicting_value_rejects() {
        let store = Store::open_memory_with_schemas(&[Schema::durable_row_table(
            "test.rows.v1",
            TEST_ROWS,
        )])
        .expect("open store");
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
    fn memory_rows_are_store_local_and_not_sqlite_temp_tables() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("memory-rows.db");
        let schemas = [Schema::memory_row_table("test.memory_rows.v1", MEMORY_ROWS)];

        let store_a = Store::open_disk_with_schemas(&path, &schemas).expect("open store a");
        store_a
            .insert_table_rows(vec![TableRow {
                table: MEMORY_ROWS,
                key: b"k".to_vec(),
                value: b"v".to_vec(),
            }])
            .expect("insert memory row");
        assert_eq!(store_a.table_row_count(MEMORY_ROWS).expect("count a"), 1);

        let store_b = Store::open_disk_with_schemas(&path, &schemas).expect("open store b");
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
                .is_none(),
            "memory row tables should not be SQLite TEMP tables"
        );
    }

    #[test]
    fn memory_rows_roll_back_with_write_transaction() {
        let store = Store::open_memory_with_schemas(&[Schema::memory_row_table(
            "test.memory_rows.v1",
            MEMORY_ROWS,
        )])
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
        let store = Store::open_memory_with_schemas(&[Schema::memory_row_table(
            "test.memory_rows.v1",
            MEMORY_ROWS,
        )])
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

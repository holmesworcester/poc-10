//! Checked SQL insert-selects for pipeline queue fanout.
//!
//! A checked insert-select is a narrow adapter from static read-only SQL into a
//! queue table. Pipeline workers choose the destination table and columns; this
//! helper only describes the bounded source rows, declared source tables, and
//! bound parameters.
//!
//! The mechanism is intentionally smaller than "run arbitrary SQL". The query
//! text must be a single comment-free `SELECT`, every `FROM` and `JOIN` table
//! must appear in `allowed_tables`, and every supplied value is bound as a
//! parameter. This gives context matching and time-wake admission one shared
//! `INSERT OR IGNORE ... SELECT` path without making core accept free-form SQL
//! from protocol modules.
//!
//! Add capability here only when several pipeline workers need the same checked
//! SQL shape. The caller still owns the meaning of the query, the destination
//! queue, and any richer validation for its scheduling rule.

use crate::core::intents::Value;
use crate::core::store::{quoted_identifier_list, quoted_table_name};
use crate::core::store::{Store, TableName};
use rusqlite::types::Value as SqliteValue;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Select {
    /// Static `SELECT` text that yields the columns expected by the caller.
    sql: &'static str,
    /// Tables this select is allowed to read.
    allowed_tables: &'static [TableName],
    /// Bound parameters used by `sql`.
    params: Vec<Param>,
}

impl Select {
    pub(super) fn new(
        sql: &'static str,
        allowed_tables: &'static [TableName],
        params: Vec<Param>,
    ) -> Self {
        Self {
            sql,
            allowed_tables,
            params,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Param {
    /// SQLite parameter name, including its marker such as `:owner`.
    name: &'static str,
    value: Value,
}

impl Param {
    pub(super) fn bytes(name: &'static str, value: impl Into<Vec<u8>>) -> Self {
        Self {
            name,
            value: Value::Bytes(value.into()),
        }
    }

    pub(super) fn text(name: &'static str, value: impl Into<String>) -> Self {
        Self {
            name,
            value: Value::Text(value.into()),
        }
    }

    pub(super) fn u64(name: &'static str, value: u64) -> Self {
        Self {
            name,
            value: Value::U64(value),
        }
    }

    pub(super) fn bool(name: &'static str, value: bool) -> Self {
        Self {
            name,
            value: Value::Bool(value),
        }
    }

    fn as_sqlite_value(&self) -> rusqlite::Result<SqliteValue> {
        self.value.as_sqlite_value()
    }
}

pub(super) fn insert_select_in_tx(
    store: &Store,
    target_table: TableName,
    target_columns: &[&str],
    select: &Select,
) -> rusqlite::Result<usize> {
    if target_columns.is_empty() {
        return Err(rusqlite::Error::InvalidParameterName(
            "insert-select requires at least one target column".to_string(),
        ));
    }
    validate_select_sql(select.sql, select.allowed_tables)?;
    let table_name = quoted_table_name(target_table)?;
    let columns = quoted_identifier_list(target_columns.iter().copied())?;
    let sql = format!(
        "INSERT OR IGNORE INTO {table_name} ({columns}) {}",
        select.sql
    );
    let mut stmt = store.conn().prepare(&sql)?;
    for param in &select.params {
        let index = stmt.parameter_index(param.name)?.ok_or_else(|| {
            rusqlite::Error::InvalidParameterName(format!(
                "insert-select SQL does not bind parameter {}",
                param.name
            ))
        })?;
        stmt.raw_bind_parameter(index, param.as_sqlite_value()?)?;
    }
    stmt.raw_execute()
}

/// Check the deliberately small SQL surface accepted by `insert_select_in_tx`.
fn validate_select_sql(sql: &str, allowed_tables: &[TableName]) -> rusqlite::Result<()> {
    let trimmed = sql.trim_start();
    if !trimmed
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("select"))
    {
        return Err(rusqlite::Error::InvalidParameterName(
            "select SQL must be SELECT-only".to_string(),
        ));
    }
    if sql.contains(';') || sql.contains("--") || sql.contains("/*") {
        return Err(rusqlite::Error::InvalidParameterName(
            "select SQL must be one comment-free SELECT statement".to_string(),
        ));
    }
    let allowed = allowed_tables
        .iter()
        .map(|table| table.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    for window in sql_identifier_tokens(sql).windows(2) {
        let keyword = window[0].to_ascii_lowercase();
        if matches!(keyword.as_str(), "from" | "join") && !allowed.contains(window[1].as_str()) {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "select SQL reads undeclared table {}",
                window[1]
            )));
        }
    }
    Ok(())
}

/// Tokenize enough SQL to find `FROM` and `JOIN` table identifiers.
///
/// This is not a SQL parser. It is paired with the single-statement,
/// comment-free validation above and exists only to enforce the table allowlist
/// for the static selects core accepts.
fn sql_identifier_tokens(sql: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in sql.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' {
            current.push(ch);
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::store::SchemaSource;

    const SOURCE_TABLE: TableName = TableName::new("source_rows");
    const TARGET_TABLE: TableName = TableName::new("target_queue");
    const VALUE_TABLE: TableName = TableName::new("target_values");

    const TEST_SCHEMA: SchemaSource = SchemaSource {
        ddl: r#"
CREATE TABLE IF NOT EXISTS source_rows (
    owner BLOB PRIMARY KEY NOT NULL,
    role TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS target_queue (
    owner BLOB PRIMARY KEY NOT NULL
);

CREATE TABLE IF NOT EXISTS target_values (
    value INTEGER PRIMARY KEY NOT NULL
);
"#,
        row_tables: &[],
    };

    fn open_store() -> Store {
        Store::open_memory_with_schema_sources(&[TEST_SCHEMA]).expect("open test store")
    }

    #[test]
    fn insert_select_fans_out_bound_rows_from_declared_tables() {
        let store = open_store();
        store
            .conn()
            .execute(
                "INSERT INTO source_rows (owner, role) VALUES (?1, ?2), (?3, ?4), (?5, ?6)",
                (
                    b"owner-a".as_slice(),
                    "ready",
                    b"owner-b".as_slice(),
                    "waiting",
                    b"owner-c".as_slice(),
                    "ready",
                ),
            )
            .expect("seed source rows");

        let inserted = insert_select_in_tx(
            &store,
            TARGET_TABLE,
            &["owner"],
            &Select::new(
                r#"
                SELECT owner
                FROM source_rows
                WHERE role = :role
                ORDER BY owner
                "#,
                &[SOURCE_TABLE],
                vec![Param::text(":role", "ready")],
            ),
        )
        .expect("insert selected rows");

        assert_eq!(inserted, 2);
        let owners = selected_target_owners(&store);
        assert_eq!(owners, vec![b"owner-a".to_vec(), b"owner-c".to_vec()]);
    }

    #[test]
    fn insert_select_rejects_reads_from_undeclared_tables() {
        let store = open_store();

        let err = insert_select_in_tx(
            &store,
            TARGET_TABLE,
            &["owner"],
            &Select::new("SELECT owner FROM source_rows", &[], Vec::new()),
        )
        .expect_err("undeclared table should fail");

        assert!(
            err.to_string()
                .contains("reads undeclared table source_rows"),
            "{err}"
        );
    }

    #[test]
    fn insert_select_rejects_comment_or_multi_statement_sql() {
        let err = validate_select_sql(
            "SELECT owner FROM source_rows; SELECT owner FROM source_rows",
            &[SOURCE_TABLE],
        )
        .expect_err("multi statement should fail");

        assert!(
            err.to_string()
                .contains("one comment-free SELECT statement"),
            "{err}"
        );
    }

    #[test]
    fn insert_select_rejects_parameters_not_bound_by_sql() {
        let store = open_store();

        let err = insert_select_in_tx(
            &store,
            TARGET_TABLE,
            &["owner"],
            &Select::new(
                "SELECT owner FROM source_rows WHERE role = :role",
                &[SOURCE_TABLE],
                vec![Param::text(":unused", "ready")],
            ),
        )
        .expect_err("unused parameter should fail");

        assert!(
            err.to_string().contains("does not bind parameter :unused"),
            "{err}"
        );
    }

    #[test]
    fn insert_select_rejects_u64_values_outside_sqlite_integer_range() {
        let store = open_store();

        let err = insert_select_in_tx(
            &store,
            VALUE_TABLE,
            &["value"],
            &Select::new(
                "SELECT :value AS value",
                &[],
                vec![Param::u64(":value", i64::MAX as u64 + 1)],
            ),
        )
        .expect_err("oversized integer should fail");

        assert!(
            err.to_string()
                .contains("SQL value exceeds SQLite integer range"),
            "{err}"
        );
    }

    fn selected_target_owners(store: &Store) -> Vec<Vec<u8>> {
        let mut stmt = store
            .conn()
            .prepare("SELECT owner FROM target_queue ORDER BY owner")
            .expect("prepare target query");
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .expect("query target rows");
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect target rows")
    }
}

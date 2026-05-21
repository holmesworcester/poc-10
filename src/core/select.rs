//! Checked SQL SELECTs for queue fanout.
//!
//! A select is a read-only query over declared tables. Pipeline workers choose
//! the destination queue table and columns; the select only describes the
//! bounded source rows and bound parameters.

use crate::core::store::{Store, TableName};
use rusqlite::types::Value as SqliteValue;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Select {
    pub sql: &'static str,
    pub allowed_tables: &'static [TableName],
    pub params: Vec<Param>,
}

impl Select {
    pub fn empty() -> Self {
        Self::new("SELECT NULL AS owner WHERE 0", &[], Vec::new())
    }

    pub fn new(
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
pub struct Param {
    pub name: &'static str,
    pub value: Value,
}

impl Param {
    pub fn bytes(name: &'static str, value: impl Into<Vec<u8>>) -> Self {
        Self {
            name,
            value: Value::Bytes(value.into()),
        }
    }

    pub fn text(name: &'static str, value: impl Into<String>) -> Self {
        Self {
            name,
            value: Value::Text(value.into()),
        }
    }

    pub fn u64(name: &'static str, value: u64) -> Self {
        Self {
            name,
            value: Value::U64(value),
        }
    }

    pub fn i64(name: &'static str, value: i64) -> Self {
        Self {
            name,
            value: Value::I64(value),
        }
    }

    pub fn bool(name: &'static str, value: bool) -> Self {
        Self {
            name,
            value: Value::Bool(value),
        }
    }

    pub(crate) fn as_sqlite_value(&self) -> rusqlite::Result<SqliteValue> {
        self.value.as_sqlite_value()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Bytes(Vec<u8>),
    Text(String),
    U64(u64),
    I64(i64),
    Bool(bool),
}

impl Value {
    fn as_sqlite_value(&self) -> rusqlite::Result<SqliteValue> {
        match self {
            Self::Bytes(value) => Ok(SqliteValue::Blob(value.clone())),
            Self::Text(value) => Ok(SqliteValue::Text(value.clone())),
            Self::U64(value) => i64::try_from(*value)
                .map(SqliteValue::Integer)
                .map_err(|_| {
                    rusqlite::Error::InvalidParameterName(
                        "select parameter exceeds SQLite integer range".to_string(),
                    )
                }),
            Self::I64(value) => Ok(SqliteValue::Integer(*value)),
            Self::Bool(value) => Ok(SqliteValue::Integer(i64::from(*value))),
        }
    }
}

pub(crate) fn insert_select_in_tx(
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
    let columns = target_columns
        .iter()
        .map(|column| quoted_identifier(column))
        .collect::<rusqlite::Result<Vec<_>>>()?
        .join(", ");
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

fn quoted_table_name(table: TableName) -> rusqlite::Result<String> {
    let name = table.as_str();
    if name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
    {
        Ok(format!("\"{name}\""))
    } else {
        Err(rusqlite::Error::InvalidParameterName(format!(
            "invalid table name {name}"
        )))
    }
}

fn quoted_identifier(name: &str) -> rusqlite::Result<String> {
    if name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        Ok(format!("\"{name}\""))
    } else {
        Err(rusqlite::Error::InvalidParameterName(format!(
            "invalid identifier {name}"
        )))
    }
}

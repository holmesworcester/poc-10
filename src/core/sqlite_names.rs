//! Shared SQLite identifier quoting for core-owned SQL.

use crate::core::store::TableName;

/// Quote a declared table name after rejecting unsafe identifier bytes.
pub(crate) fn quoted_table_name(table: TableName) -> rusqlite::Result<String> {
    quoted_table_name_str(table.as_str())
}

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

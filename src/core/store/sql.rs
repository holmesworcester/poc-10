use super::*;
use crate::core::schema_dsl::{self, ColumnType, TableDeclaration, TableKind};
use crate::core::wire::{Reader, WireError, Writer};
use rusqlite::{types::Value, Connection as SqliteConnection};
use std::collections::{BTreeSet, HashMap};

pub(super) fn table_declarations_from_schema_sources(
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

pub(super) fn typed_table_map(
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

pub(super) fn is_row_table_declaration(table: &TableDeclaration) -> bool {
    table.kind == TableKind::Row
}

pub(super) fn decode_typed_row_values(
    table: &TableDeclaration,
    row: &TableRow,
) -> rusqlite::Result<Vec<Value>> {
    let key_values = decode_typed_key_values_named(table, &row.key)?;
    let mut value_reader = Reader::new(&row.value);
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
                &mut value_reader,
                &format!("{}.{}", table.name, column.name),
            )?);
        }
    }

    value_reader
        .finish()
        .map_err(|err| typed_wire_error(&format!("{}.value", table.name), err))?;
    Ok(values)
}

pub(super) fn decode_typed_key_values(
    table: &TableDeclaration,
    key: &[u8],
) -> rusqlite::Result<Vec<Value>> {
    decode_typed_key_values_named(table, key).map(|values| {
        values
            .into_iter()
            .map(|(_, value)| value)
            .collect::<Vec<_>>()
    })
}

pub(super) fn decode_typed_key_values_named(
    table: &TableDeclaration,
    key: &[u8],
) -> rusqlite::Result<Vec<(String, Value)>> {
    let mut key_reader = Reader::new(key);
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
                &mut key_reader,
                &format!("{}.{}", table.name, column.name),
            )?,
        ));
    }
    key_reader
        .finish()
        .map_err(|err| typed_wire_error(&format!("{}.key", table.name), err))?;
    Ok(values)
}

pub(super) fn sqlite_row_to_table_row(
    table: &TableDeclaration,
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<(Vec<u8>, Vec<u8>)> {
    let mut key = Writer::new();
    let mut value = Writer::new();
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
    Ok((key.finish(), value.finish()))
}

pub(super) fn decode_column_value(
    ty: &ColumnType,
    reader: &mut Reader<'_>,
    label: &str,
) -> rusqlite::Result<Value> {
    match ty {
        ColumnType::Bytes { len: Some(len) } => {
            let out = reader
                .bytes(*len)
                .map_err(|err| typed_wire_error(label, err))?;
            Ok(Value::Blob(out.to_vec()))
        }
        ColumnType::Bytes { len: None } => {
            let out = reader
                .bytes_u32be()
                .map_err(|err| typed_wire_error(label, err))?;
            Ok(Value::Blob(out.to_vec()))
        }
        ColumnType::U64 => {
            let value = reader.u64be().map_err(|err| typed_wire_error(label, err))?;
            let value = i64::try_from(value).map_err(|_| {
                rusqlite::Error::InvalidParameterName(format!(
                    "typed column {label} exceeds SQLite integer range"
                ))
            })?;
            Ok(Value::Integer(value))
        }
        ColumnType::I64 => {
            let raw = reader
                .array::<8>()
                .map_err(|err| typed_wire_error(label, err))?;
            Ok(Value::Integer(i64::from_be_bytes(raw)))
        }
        ColumnType::Text => {
            let text = reader
                .string_u32be()
                .map_err(|err| typed_wire_error(label, err))?;
            Ok(Value::Text(text))
        }
        ColumnType::Bool => {
            let value = reader.bool8().map_err(|err| typed_wire_error(label, err))?;
            Ok(Value::Integer(i64::from(value)))
        }
    }
}

pub(super) fn encode_column_value(
    ty: &ColumnType,
    value: &Value,
    out: &mut Writer,
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
            out.bytes(bytes);
        }
        (ColumnType::Bytes { len: None }, Value::Blob(bytes)) => {
            out.bytes_u32be(bytes)
                .map_err(|err| typed_wire_error(label, err))?;
        }
        (ColumnType::U64, Value::Integer(value)) => {
            let value = u64::try_from(*value).map_err(|_| {
                rusqlite::Error::InvalidParameterName(format!(
                    "typed column {label} has negative u64 value"
                ))
            })?;
            out.u64be(value);
        }
        (ColumnType::I64, Value::Integer(value)) => {
            out.bytes(&value.to_be_bytes());
        }
        (ColumnType::Text, Value::Text(text)) => {
            out.string_u32be(text)
                .map_err(|err| typed_wire_error(label, err))?;
        }
        (ColumnType::Bool, Value::Integer(0)) => out.bool8(false),
        (ColumnType::Bool, Value::Integer(1)) => out.bool8(true),
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

pub(super) fn sqlite_column_value(
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

pub(super) fn typed_wire_error(label: &str, err: WireError) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(format!("typed column {label}: {err}"))
}

pub(super) fn table_column_list(table: &TableDeclaration) -> rusqlite::Result<String> {
    let columns = table
        .columns
        .iter()
        .map(|column| column.name.clone())
        .collect::<Vec<_>>();
    quoted_identifier_list(&columns)
}

pub(super) fn row_key_where_clause(table: &TableDeclaration) -> rusqlite::Result<String> {
    table
        .row_key
        .columns
        .iter()
        .enumerate()
        .map(|(index, column)| Ok(format!("{} = ?{}", quoted_identifier(column)?, index + 1)))
        .collect::<rusqlite::Result<Vec<_>>>()
        .map(|clauses| clauses.join(" AND "))
}

pub(super) fn placeholders(count: usize) -> String {
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
pub(super) struct SqliteTableColumn {
    name: String,
    declared_type: String,
    not_null: bool,
    primary_key_position: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SqliteIndex {
    name: String,
    unique: bool,
    columns: Vec<String>,
}

pub(super) fn sqlite_table_columns(
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

pub(super) fn sqlite_table_indexes(
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

pub(super) fn validate_sqlite_row_table(
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

pub(super) fn validate_sqlite_typed_table(
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

pub(super) fn sqlite_type(ty: &ColumnType) -> &'static str {
    match ty {
        ColumnType::Bytes { .. } => "BLOB",
        ColumnType::U64 | ColumnType::I64 => "INTEGER",
        ColumnType::Text => "TEXT",
        ColumnType::Bool => "INTEGER",
    }
}

/// Compute the exclusive upper bound for a byte-prefix range.
pub(super) fn prefix_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
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
pub(super) fn quoted_table_name(table: TableName) -> rusqlite::Result<String> {
    quoted_table_name_str(table.as_str())
}

pub(super) fn quoted_table_name_str(name: &str) -> rusqlite::Result<String> {
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

pub(super) fn quoted_identifier(name: &str) -> rusqlite::Result<String> {
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

pub(super) fn quoted_identifier_list(columns: &[String]) -> rusqlite::Result<String> {
    columns
        .iter()
        .map(|column| quoted_identifier(column))
        .collect::<rusqlite::Result<Vec<_>>>()
        .map(|columns| columns.join(", "))
}

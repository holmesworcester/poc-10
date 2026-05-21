use crate::core::schema_dsl::{self, ColumnType, TableDeclaration, TableKind};
use crate::core::sqlite_names::quoted_table_name_str;
use rusqlite::Connection as SqliteConnection;
use std::collections::BTreeSet;

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
        for table in document {
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

pub(super) fn is_row_table_declaration(table: &TableDeclaration) -> bool {
    table.kind == TableKind::Row
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
        ColumnType::U64 => "INTEGER",
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

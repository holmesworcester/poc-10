//! Parser for the small schema declaration files used by the store.
//!
//! The grammar is intentionally line-oriented:
//!
//! ```text
//! [memory] row_table name;
//! [memory] table name {
//!   column name bytes[(N)]|u64|text|bool;
//!   row_key (column, ...);
//!   [unique] index name (column, ...);
//! }
//! ```
//!
//! The DSL is a boundary tool, not a migration language. It declares the table
//! shapes a fresh store must have and the shapes an existing store must already
//! match. Core applies those declarations in `store.rs`; protocol modules keep
//! their own declarations beside the row encoders and query helpers that
//! understand them.
//!
//! Extend this file when core needs another storage primitive every module can
//! share. Do not add expressions, callbacks, or protocol validation here; those
//! belong in the module that owns the data.

use std::collections::BTreeSet;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableDeclaration {
    /// SQLite table name, optionally qualified with module-style dots.
    pub name: String,
    /// Opaque row table or typed declared-column table.
    pub kind: TableKind,
    /// Whether this table is durable or `TEMP`/connection-local.
    pub storage: TableStorage,
    /// Declared columns in SQLite order.
    pub columns: Vec<ColumnDeclaration>,
    /// Primary row key columns.
    pub row_key: RowKeyDeclaration,
    /// Secondary indexes that must exist with the declared shape.
    pub indexes: Vec<IndexDeclaration>,
}

impl TableDeclaration {
    /// Return one declared column by name.
    pub fn column(&self, name: &str) -> Option<&ColumnDeclaration> {
        self.columns.iter().find(|column| column.name == name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableKind {
    /// Opaque `row_key`/`row_value` table.
    Row,
    /// Declared-column table with a row key and optional indexes.
    Typed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableStorage {
    /// Stored in the database file.
    Durable,
    /// SQLite `TEMP` table scoped to the current connection.
    Memory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnDeclaration {
    /// Column name as declared in p8sql.
    pub name: String,
    /// Core-supported SQLite column type.
    pub ty: ColumnType,
}

/// Column types the store knows how to create and validate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnType {
    /// Blob column, optionally documented with an expected byte length.
    ///
    /// SQLite does not enforce the length; code that writes the column must.
    Bytes { len: Option<usize> },
    /// Unsigned 64-bit integer stored in SQLite's signed integer range.
    U64,
    /// UTF-8 text.
    Text,
    /// Boolean stored as SQLite integer `0` or `1`.
    Bool,
}

/// Declared primary row key for a typed table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowKeyDeclaration {
    pub columns: Vec<String>,
}

/// Declared secondary index for a typed table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexDeclaration {
    /// Suffix used to build the SQLite index name.
    pub name: String,
    /// Whether the index enforces uniqueness.
    pub unique: bool,
    /// Indexed columns in order.
    pub columns: Vec<String>,
}

/// Parse error with source position in a p8sql document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// One-based line number.
    pub line: usize,
    /// One-based column number. The current parser reports whole-line errors.
    pub column: usize,
    /// Human-readable parse failure.
    pub detail: String,
}

impl ParseError {
    fn new(line: usize, detail: impl Into<String>) -> Self {
        Self {
            line,
            column: 1,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.column, self.detail)
    }
}

impl std::error::Error for ParseError {}

/// Parse a p8sql schema document into table declarations.
///
/// The parser validates declaration shape, duplicate names, and column
/// references. Store validation and protocol row semantics happen elsewhere.
pub fn parse_schema(source: &str) -> Result<Vec<TableDeclaration>, ParseError> {
    let mut tables = Vec::new();
    let mut seen_tables = BTreeSet::new();
    let mut current: Option<TableBuilder> = None;

    for (index, raw) in source.lines().enumerate() {
        let line_no = index + 1;
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }

        if current.is_some() {
            if line == "}" {
                let table = current.take().expect("current table").finish()?;
                if !seen_tables.insert(table.name.clone()) {
                    return Err(ParseError::new(
                        line_no,
                        format!("duplicate table declaration `{}`", table.name),
                    ));
                }
                tables.push(table);
                current = None;
                continue;
            }
            current
                .as_mut()
                .expect("current table")
                .parse_statement(line_no, line)?;
            continue;
        }

        let (storage, rest) = strip_memory(line);
        if let Some(name) = rest
            .strip_prefix("row_table ")
            .and_then(|value| value.strip_suffix(';'))
        {
            let name = parse_name(line_no, name.trim())?;
            if !seen_tables.insert(name.clone()) {
                return Err(ParseError::new(
                    line_no,
                    format!("duplicate table declaration `{name}`"),
                ));
            }
            tables.push(row_table(name, storage));
            continue;
        }
        if let Some(header) = rest
            .strip_prefix("table ")
            .and_then(|value| value.strip_suffix('{'))
        {
            current = Some(TableBuilder::new(
                parse_name(line_no, header.trim())?,
                storage,
                line_no,
            ));
            continue;
        }
        return Err(ParseError::new(line_no, "expected `table` or `row_table`"));
    }

    if let Some(builder) = current {
        return Err(ParseError::new(
            builder.line,
            format!("unterminated table declaration `{}`", builder.name),
        ));
    }

    Ok(tables)
}

/// Builder for one typed-table block.
///
/// It keeps duplicate tracking local to the table while the outer parser owns
/// duplicate table names across the whole source.
struct TableBuilder {
    name: String,
    storage: TableStorage,
    line: usize,
    columns: Vec<ColumnDeclaration>,
    column_names: BTreeSet<String>,
    row_key: Option<RowKeyDeclaration>,
    indexes: Vec<IndexDeclaration>,
    index_names: BTreeSet<String>,
}

impl TableBuilder {
    fn new(name: String, storage: TableStorage, line: usize) -> Self {
        Self {
            name,
            storage,
            line,
            columns: Vec::new(),
            column_names: BTreeSet::new(),
            row_key: None,
            indexes: Vec::new(),
            index_names: BTreeSet::new(),
        }
    }

    fn parse_statement(&mut self, line_no: usize, line: &str) -> Result<(), ParseError> {
        if let Some(rest) = line.strip_prefix("column ") {
            let rest = rest
                .strip_suffix(';')
                .ok_or_else(|| ParseError::new(line_no, "column statement must end with `;`"))?;
            let mut parts = rest.split_whitespace();
            let name = parts
                .next()
                .ok_or_else(|| ParseError::new(line_no, "column statement missing name"))?;
            let ty = parts
                .next()
                .ok_or_else(|| ParseError::new(line_no, "column statement missing type"))?;
            if parts.next().is_some() {
                return Err(ParseError::new(
                    line_no,
                    "column statement has extra tokens",
                ));
            }
            let name = parse_identifier(line_no, name)?;
            if !self.column_names.insert(name.clone()) {
                return Err(ParseError::new(
                    line_no,
                    format!("duplicate column declaration `{name}`"),
                ));
            }
            self.columns.push(ColumnDeclaration {
                name,
                ty: parse_type(line_no, ty)?,
            });
            return Ok(());
        }

        if let Some(rest) = line.strip_prefix("row_key ") {
            if self.row_key.is_some() {
                return Err(ParseError::new(
                    line_no,
                    format!("duplicate row key declaration for table `{}`", self.name),
                ));
            }
            let columns = parse_list_statement(line_no, rest, "row_key")?;
            self.row_key = Some(RowKeyDeclaration { columns });
            return Ok(());
        }

        let (unique, rest) = if let Some(rest) = line.strip_prefix("unique ") {
            (true, rest)
        } else {
            (false, line)
        };
        if let Some(rest) = rest.strip_prefix("index ") {
            let (name, columns) = parse_named_list_statement(line_no, rest, "index")?;
            if !self.index_names.insert(name.clone()) {
                return Err(ParseError::new(
                    line_no,
                    format!("duplicate index declaration `{name}`"),
                ));
            }
            self.indexes.push(IndexDeclaration {
                name,
                unique,
                columns,
            });
            return Ok(());
        }

        Err(ParseError::new(
            line_no,
            "unknown table statement; expected `column`, `row_key`, `index`, or `unique`",
        ))
    }

    fn finish(self) -> Result<TableDeclaration, ParseError> {
        let row_key = self.row_key.ok_or_else(|| {
            ParseError::new(
                self.line,
                format!("table `{}` must declare a row key", self.name),
            )
        })?;
        validate_columns_exist(
            &self.name,
            "row key",
            &row_key.columns,
            &self.column_names,
            self.line,
        )?;
        for index in &self.indexes {
            validate_columns_exist(
                &self.name,
                &format!("index `{}`", index.name),
                &index.columns,
                &self.column_names,
                self.line,
            )?;
        }
        Ok(TableDeclaration {
            name: self.name,
            kind: TableKind::Typed,
            storage: self.storage,
            columns: self.columns,
            row_key,
            indexes: self.indexes,
        })
    }
}

fn row_table(name: String, storage: TableStorage) -> TableDeclaration {
    TableDeclaration {
        name,
        kind: TableKind::Row,
        storage,
        columns: vec![
            ColumnDeclaration {
                name: "key".to_string(),
                ty: ColumnType::Bytes { len: None },
            },
            ColumnDeclaration {
                name: "value".to_string(),
                ty: ColumnType::Bytes { len: None },
            },
        ],
        row_key: RowKeyDeclaration {
            columns: vec!["key".to_string()],
        },
        indexes: Vec::new(),
    }
}

/// Strip the optional storage qualifier from a top-level declaration.
fn strip_memory(line: &str) -> (TableStorage, &str) {
    line.strip_prefix("memory ")
        .map(|rest| (TableStorage::Memory, rest))
        .unwrap_or((TableStorage::Durable, line))
}

/// Remove p8sql comments.
///
/// Both `#` and `//` are accepted because schema snippets are often embedded
/// near Rust code and markdown notes.
fn strip_comment(line: &str) -> &str {
    let hash = line.find('#');
    let slash = line.find("//");
    let end = match (hash, slash) {
        (Some(left), Some(right)) => left.min(right),
        (Some(index), None) | (None, Some(index)) => index,
        (None, None) => line.len(),
    };
    &line[..end]
}

fn parse_type(line: usize, ty: &str) -> Result<ColumnType, ParseError> {
    if ty == "bytes" {
        return Ok(ColumnType::Bytes { len: None });
    }
    if let Some(len) = ty
        .strip_prefix("bytes(")
        .and_then(|value| value.strip_suffix(')'))
    {
        let len = len
            .parse::<usize>()
            .map_err(|_| ParseError::new(line, "invalid byte length"))?;
        if len == 0 {
            return Err(ParseError::new(
                line,
                "byte length must be greater than zero",
            ));
        }
        return Ok(ColumnType::Bytes { len: Some(len) });
    }
    match ty {
        "u64" => Ok(ColumnType::U64),
        "text" => Ok(ColumnType::Text),
        "bool" => Ok(ColumnType::Bool),
        _ => Err(ParseError::new(line, format!("unknown column type `{ty}`"))),
    }
}

fn parse_named_list_statement(
    line: usize,
    rest: &str,
    label: &str,
) -> Result<(String, Vec<String>), ParseError> {
    let (name, list) = rest
        .split_once(' ')
        .ok_or_else(|| ParseError::new(line, format!("{label} statement missing columns")))?;
    Ok((
        parse_identifier(line, name)?,
        parse_list_statement(line, list, label)?,
    ))
}

fn parse_list_statement(line: usize, rest: &str, label: &str) -> Result<Vec<String>, ParseError> {
    let rest = rest
        .strip_suffix(';')
        .ok_or_else(|| ParseError::new(line, format!("{label} statement must end with `;`")))?
        .trim();
    let inner = rest
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
        .ok_or_else(|| ParseError::new(line, format!("{label} statement must use `(columns)`")))?;
    let columns = inner
        .split(',')
        .map(str::trim)
        .map(|name| parse_identifier(line, name))
        .collect::<Result<Vec<_>, _>>()?;
    if columns.is_empty() {
        return Err(ParseError::new(line, "identifier list cannot be empty"));
    }
    Ok(columns)
}

fn parse_name(line: usize, name: &str) -> Result<String, ParseError> {
    if !name.is_empty()
        && name
            .split('.')
            .all(|part| parse_identifier(line, part).is_ok())
    {
        return Ok(name.to_string());
    }
    Err(ParseError::new(
        line,
        format!("invalid table name `{name}`"),
    ))
}

fn parse_identifier(line: usize, name: &str) -> Result<String, ParseError> {
    let mut bytes = name.bytes();
    let valid_start = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_');
    if valid_start && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
        Ok(name.to_string())
    } else {
        Err(ParseError::new(
            line,
            format!("invalid identifier `{name}`"),
        ))
    }
}

fn validate_columns_exist(
    table: &str,
    owner: &str,
    refs: &[String],
    columns: &BTreeSet<String>,
    line: usize,
) -> Result<(), ParseError> {
    for column in refs {
        if !columns.contains(column) {
            return Err(ParseError::new(
                line,
                format!("table `{table}` {owner} references unknown column `{column}`"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::schema::CORE_SCHEMA_SOURCE;

    #[test]
    fn parses_tables_row_keys_indexes_and_byte_lengths() {
        let schema = parse_schema(
            r#"
            row_table facts;

            table facts_typed {
              column id bytes(32);
              column scope text;
              column timestamp u64;
              column payload bytes;
              row_key (id);
              index by_scope_time (scope, timestamp);
              unique index by_scope_id (scope, id);
            }
            "#,
        )
        .expect("schema parses");

        let opaque_facts = table(&schema, "facts").expect("row table");
        assert_eq!(opaque_facts.kind, TableKind::Row);
        assert_eq!(opaque_facts.row_key.columns, vec!["key"]);
        assert_eq!(
            opaque_facts.column("key").map(|column| &column.ty),
            Some(&ColumnType::Bytes { len: None })
        );

        let typed_facts = table(&schema, "facts_typed").expect("typed facts table");
        assert_eq!(typed_facts.kind, TableKind::Typed);
        assert_eq!(typed_facts.row_key.columns, vec!["id"]);
        assert_eq!(
            typed_facts.column("id").map(|column| &column.ty),
            Some(&ColumnType::Bytes { len: Some(32) })
        );
        assert_eq!(
            index(typed_facts, "by_scope_time"),
            Some(&IndexDeclaration {
                name: "by_scope_time".to_string(),
                unique: false,
                columns: vec!["scope".to_string(), "timestamp".to_string()],
            })
        );
        assert_eq!(
            index(typed_facts, "by_scope_id").map(|index| index.unique),
            Some(true)
        );
    }

    #[test]
    fn parses_initial_poc10_schema_files() {
        let core = parse_schema(CORE_SCHEMA_SOURCE).expect("core schema parses");

        assert_eq!(
            table_names(&core),
            vec![
                "facts",
                "local_fact_admissions",
                "context_edges",
                "time_wakes",
                "pending_projection",
                "pending_time_ranges",
                "intents",
                "local_intents",
                "clock",
            ]
        );
        assert_eq!(
            table(&core, "local_intents").map(|table| table.storage),
            Some(TableStorage::Memory)
        );
    }

    #[test]
    fn rejects_missing_row_key_and_unknown_references() {
        assert!(parse_schema("table facts {\n  column key bytes;\n}").is_err());
        assert!(
            parse_schema("table facts {\n  column key bytes;\n  row_key (missing);\n}").is_err()
        );
    }

    #[test]
    fn rejects_tokens_outside_the_schema_grammar() {
        let err = parse_schema(
            r#"
            table facts {
              column key bytes;
              row_key (key);
              let callback = rust();
            }
            "#,
        )
        .expect_err("embedded expressions are outside the DSL");

        assert!(err.detail.contains("unknown table statement"));
    }

    fn table<'a>(tables: &'a [TableDeclaration], name: &str) -> Option<&'a TableDeclaration> {
        tables.iter().find(|table| table.name == name)
    }

    fn index<'a>(table: &'a TableDeclaration, name: &str) -> Option<&'a IndexDeclaration> {
        table.indexes.iter().find(|index| index.name == name)
    }

    fn table_names(tables: &[TableDeclaration]) -> Vec<&str> {
        tables.iter().map(|table| table.name.as_str()).collect()
    }
}

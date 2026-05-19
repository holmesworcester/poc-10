//! Parser and byte-codec helpers for the poc-10 schema declaration files.
//!
//! The DSL owns table declarations and fixed record layouts. Core uses those
//! declarations for storage shape and byte packing mechanics; protocol modules
//! still own semantic invariants, projection policy, crypto, and command
//! behavior.

use crate::core::store::{TableName, TableRow};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::OnceLock;

pub const CORE_SCHEMA_SOURCE: &str = include_str!("schema.p8sql");
pub const FACTS_SCHEMA_SOURCE: &str = include_str!("../protocol/facts/schema.p8sql");
pub const INTENTS_SCHEMA_SOURCE: &str = include_str!("../protocol/intents/schema.p8sql");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaDocument {
    pub tables: Vec<TableDeclaration>,
    pub layouts: Vec<LayoutDeclaration>,
}

impl SchemaDocument {
    pub fn table(&self, name: &str) -> Option<&TableDeclaration> {
        self.tables.iter().find(|table| table.name == name)
    }

    pub fn layout(&self, name: &str) -> Option<&LayoutDeclaration> {
        self.layouts.iter().find(|layout| layout.name == name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableDeclaration {
    pub name: String,
    pub kind: TableKind,
    pub columns: Vec<ColumnDeclaration>,
    pub row_key: RowKeyDeclaration,
    pub indexes: Vec<IndexDeclaration>,
}

impl TableDeclaration {
    pub fn column(&self, name: &str) -> Option<&ColumnDeclaration> {
        self.columns.iter().find(|column| column.name == name)
    }

    pub fn index(&self, name: &str) -> Option<&IndexDeclaration> {
        self.indexes.iter().find(|index| index.name == name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableKind {
    Row,
    Typed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnDeclaration {
    pub name: String,
    pub ty: ColumnType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColumnType {
    U8,
    U16,
    U32,
    Bytes { len: Option<usize> },
    U64,
    I64,
    Text,
    Bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowKeyDeclaration {
    pub columns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexDeclaration {
    pub name: String,
    pub unique: bool,
    pub columns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutDeclaration {
    pub name: String,
    pub fields: Vec<FieldDeclaration>,
}

impl LayoutDeclaration {
    pub fn field(&self, name: &str) -> Option<&FieldDeclaration> {
        self.fields.iter().find(|field| field.name == name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDeclaration {
    pub name: String,
    pub ty: ColumnType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I64(i64),
    Bytes(Vec<u8>),
    Text(String),
    Bool(bool),
}

impl FieldValue {
    pub fn bytes_array<const N: usize>(&self, label: &str) -> Result<[u8; N], String> {
        match self {
            FieldValue::Bytes(bytes) => bytes
                .as_slice()
                .try_into()
                .map_err(|_| format!("field `{label}` is not {N} bytes")),
            _ => Err(format!("field `{label}` is not bytes")),
        }
    }

    pub fn u8(&self, label: &str) -> Result<u8, String> {
        match self {
            FieldValue::U8(value) => Ok(*value),
            _ => Err(format!("field `{label}` is not u8")),
        }
    }

    pub fn u16(&self, label: &str) -> Result<u16, String> {
        match self {
            FieldValue::U16(value) => Ok(*value),
            _ => Err(format!("field `{label}` is not u16")),
        }
    }

    pub fn u32(&self, label: &str) -> Result<u32, String> {
        match self {
            FieldValue::U32(value) => Ok(*value),
            _ => Err(format!("field `{label}` is not u32")),
        }
    }

    pub fn u64(&self, label: &str) -> Result<u64, String> {
        match self {
            FieldValue::U64(value) => Ok(*value),
            _ => Err(format!("field `{label}` is not u64")),
        }
    }

    pub fn bool(&self, label: &str) -> Result<bool, String> {
        match self {
            FieldValue::Bool(value) => Ok(*value),
            _ => Err(format!("field `{label}` is not bool")),
        }
    }

    pub fn bytes(&self, label: &str) -> Result<&[u8], String> {
        match self {
            FieldValue::Bytes(value) => Ok(value),
            _ => Err(format!("field `{label}` is not bytes")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRecord {
    values: BTreeMap<String, FieldValue>,
}

impl DecodedRecord {
    pub fn new(values: BTreeMap<String, FieldValue>) -> Self {
        Self { values }
    }

    pub fn get(&self, name: &str) -> Result<&FieldValue, String> {
        self.values
            .get(name)
            .ok_or_else(|| format!("decoded record is missing field `{name}`"))
    }

    pub fn u8(&self, name: &str) -> Result<u8, String> {
        self.get(name)?.u8(name)
    }

    pub fn u16(&self, name: &str) -> Result<u16, String> {
        self.get(name)?.u16(name)
    }

    pub fn u32(&self, name: &str) -> Result<u32, String> {
        self.get(name)?.u32(name)
    }

    pub fn u64(&self, name: &str) -> Result<u64, String> {
        self.get(name)?.u64(name)
    }

    pub fn bool(&self, name: &str) -> Result<bool, String> {
        self.get(name)?.bool(name)
    }

    pub fn bytes(&self, name: &str) -> Result<&[u8], String> {
        self.get(name)?.bytes(name)
    }

    pub fn bytes_vec(&self, name: &str) -> Result<Vec<u8>, String> {
        Ok(self.bytes(name)?.to_vec())
    }

    pub fn bytes_array<const N: usize>(&self, name: &str) -> Result<[u8; N], String> {
        self.get(name)?.bytes_array(name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub column: usize,
    pub detail: String,
}

impl ParseError {
    fn new(line: usize, column: usize, detail: impl Into<String>) -> Self {
        Self {
            line,
            column,
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

pub fn parse_schema(source: &str) -> Result<SchemaDocument, ParseError> {
    Parser::new(source)?.parse_document()
}

pub fn core_schema_document() -> &'static SchemaDocument {
    static DOCUMENT: OnceLock<SchemaDocument> = OnceLock::new();
    DOCUMENT.get_or_init(|| parse_schema(CORE_SCHEMA_SOURCE).expect("core schema parses"))
}

pub fn facts_schema_document() -> &'static SchemaDocument {
    static DOCUMENT: OnceLock<SchemaDocument> = OnceLock::new();
    DOCUMENT.get_or_init(|| parse_schema(FACTS_SCHEMA_SOURCE).expect("facts schema parses"))
}

pub fn intents_schema_document() -> &'static SchemaDocument {
    static DOCUMENT: OnceLock<SchemaDocument> = OnceLock::new();
    DOCUMENT.get_or_init(|| parse_schema(INTENTS_SCHEMA_SOURCE).expect("intents schema parses"))
}

pub fn facts_layout(name: &str) -> &'static LayoutDeclaration {
    facts_schema_document()
        .layout(name)
        .unwrap_or_else(|| panic!("missing facts layout `{name}`"))
}

pub fn intents_layout(name: &str) -> &'static LayoutDeclaration {
    intents_schema_document()
        .layout(name)
        .unwrap_or_else(|| panic!("missing intents layout `{name}`"))
}

pub fn facts_table(name: &str) -> &'static TableDeclaration {
    facts_schema_document()
        .table(name)
        .unwrap_or_else(|| panic!("missing facts table `{name}`"))
}

pub fn encode_layout_record(
    layout: &LayoutDeclaration,
    values: &[(&str, FieldValue)],
) -> Result<Vec<u8>, String> {
    let values = value_map(values)?;
    let mut out = Vec::new();
    for field in &layout.fields {
        let value = values
            .get(field.name.as_str())
            .ok_or_else(|| format!("layout `{}` missing field `{}`", layout.name, field.name))?;
        encode_value(&field.ty, value, &mut out, &field.name)?;
    }
    reject_extra_values(
        values.keys().copied(),
        layout.fields.iter().map(|field| field.name.as_str()),
        &format!("layout `{}`", layout.name),
    )?;
    Ok(out)
}

pub fn decode_layout_record(
    layout: &LayoutDeclaration,
    bytes: &[u8],
) -> Result<DecodedRecord, String> {
    let mut offset = 0;
    let mut values = BTreeMap::new();
    for field in &layout.fields {
        let value = decode_value(&field.ty, bytes, &mut offset, &field.name)?;
        values.insert(field.name.clone(), value);
    }
    if offset != bytes.len() {
        return Err(format!("layout `{}` has trailing bytes", layout.name));
    }
    Ok(DecodedRecord::new(values))
}

pub fn encode_table_row(
    table_name: TableName,
    table: &TableDeclaration,
    values: &[(&str, FieldValue)],
) -> Result<TableRow, String> {
    if table.kind != TableKind::Typed {
        return Err(format!("table `{}` is not typed", table.name));
    }
    let values = value_map(values)?;
    let mut key = Vec::new();
    let mut value = Vec::new();
    for column in &table.columns {
        let field = values
            .get(column.name.as_str())
            .ok_or_else(|| format!("table `{}` missing column `{}`", table.name, column.name))?;
        if table
            .row_key
            .columns
            .iter()
            .any(|name| name == &column.name)
        {
            encode_value(&column.ty, field, &mut key, &column.name)?;
        } else {
            encode_value(&column.ty, field, &mut value, &column.name)?;
        }
    }
    reject_extra_values(
        values.keys().copied(),
        table.columns.iter().map(|column| column.name.as_str()),
        &format!("table `{}`", table.name),
    )?;
    Ok(TableRow {
        table: table_name,
        key,
        value,
    })
}

pub fn decode_table_row(
    table: &TableDeclaration,
    key: &[u8],
    value: &[u8],
) -> Result<DecodedRecord, String> {
    if table.kind != TableKind::Typed {
        return Err(format!("table `{}` is not typed", table.name));
    }
    let mut key_offset = 0;
    let mut value_offset = 0;
    let mut values = BTreeMap::new();
    for column in &table.columns {
        let from_key = table
            .row_key
            .columns
            .iter()
            .any(|name| name == &column.name);
        let decoded = if from_key {
            decode_value(&column.ty, key, &mut key_offset, &column.name)?
        } else {
            decode_value(&column.ty, value, &mut value_offset, &column.name)?
        };
        values.insert(column.name.clone(), decoded);
    }
    if key_offset != key.len() {
        return Err(format!("table `{}` key has trailing bytes", table.name));
    }
    if value_offset != value.len() {
        return Err(format!("table `{}` value has trailing bytes", table.name));
    }
    Ok(DecodedRecord::new(values))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenKind {
    Ident(String),
    Number(u64),
    Symbol(char),
    Eof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Token {
    kind: TokenKind,
    line: usize,
    column: usize,
}

struct Parser<'a> {
    lexer: Lexer<'a>,
    lookahead: Token,
}

impl<'a> Parser<'a> {
    fn new(source: &'a str) -> Result<Self, ParseError> {
        let mut lexer = Lexer::new(source);
        let lookahead = lexer.next_token()?;
        Ok(Self { lexer, lookahead })
    }

    fn parse_document(mut self) -> Result<SchemaDocument, ParseError> {
        let mut tables = Vec::new();
        let mut table_names = BTreeSet::new();
        let mut layouts = Vec::new();
        let mut layout_names = BTreeSet::new();

        while !matches!(self.lookahead.kind, TokenKind::Eof) {
            match &self.lookahead.kind {
                TokenKind::Ident(keyword) if keyword == "row_table" => {
                    let table = self.parse_row_table()?;
                    if !table_names.insert(table.name.clone()) {
                        return Err(
                            self.error(format!("duplicate table declaration `{}`", table.name))
                        );
                    }
                    tables.push(table);
                }
                TokenKind::Ident(keyword) if keyword == "table" => {
                    let table = self.parse_table()?;
                    if !table_names.insert(table.name.clone()) {
                        return Err(
                            self.error(format!("duplicate table declaration `{}`", table.name))
                        );
                    }
                    tables.push(table);
                }
                TokenKind::Ident(keyword) if keyword == "layout" => {
                    let layout = self.parse_layout()?;
                    if !layout_names.insert(layout.name.clone()) {
                        return Err(
                            self.error(format!("duplicate layout declaration `{}`", layout.name))
                        );
                    }
                    layouts.push(layout);
                }
                _ => return Err(self.error("expected `row_table`, `table`, or `layout`")),
            };
        }

        Ok(SchemaDocument { tables, layouts })
    }

    fn parse_table(&mut self) -> Result<TableDeclaration, ParseError> {
        let table_token = self.expect_keyword("table")?;
        let name = self.parse_name()?;
        self.expect_symbol('{')?;

        let mut columns = Vec::new();
        let mut column_names = BTreeSet::new();
        let mut row_key = None;
        let mut indexes = Vec::new();
        let mut index_names = BTreeSet::new();

        loop {
            if self.consume_symbol('}')? {
                break;
            }
            if matches!(self.lookahead.kind, TokenKind::Eof) {
                return Err(ParseError::new(
                    table_token.line,
                    table_token.column,
                    format!("unterminated table declaration `{name}`"),
                ));
            }

            let keyword = match &self.lookahead.kind {
                TokenKind::Ident(keyword) => keyword.as_str(),
                _ => {
                    return Err(self.error(
                        "expected table statement: `column`, `row_key`, `index`, or `unique`",
                    ))
                }
            };

            match keyword {
                "column" => self.parse_column_statement(&mut columns, &mut column_names)?,
                "row_key" => {
                    let token = self.expect_keyword("row_key")?;
                    if row_key.is_some() {
                        return Err(ParseError::new(
                            token.line,
                            token.column,
                            format!("duplicate row key declaration for table `{name}`"),
                        ));
                    }
                    let columns = self.parse_ident_list()?;
                    self.expect_symbol(';')?;
                    row_key = Some(RowKeyDeclaration { columns });
                }
                "index" => {
                    self.parse_index_statement(false, &mut indexes, &mut index_names)?;
                }
                "unique" => {
                    self.expect_keyword("unique")?;
                    self.parse_index_statement(true, &mut indexes, &mut index_names)?;
                }
                _ => {
                    return Err(self.error(format!(
                        "unknown table statement `{keyword}`; expected `column`, `row_key`, `index`, or `unique`"
                    )));
                }
            }
        }

        let row_key = row_key.ok_or_else(|| {
            ParseError::new(
                table_token.line,
                table_token.column,
                format!("table `{name}` must declare a row key"),
            )
        })?;

        validate_columns_exist(
            &name,
            "row key",
            &row_key.columns,
            &column_names,
            table_token.line,
        )?;
        for index in &indexes {
            validate_columns_exist(
                &name,
                &format!("index `{}`", index.name),
                &index.columns,
                &column_names,
                table_token.line,
            )?;
        }

        Ok(TableDeclaration {
            name,
            kind: TableKind::Typed,
            columns,
            row_key,
            indexes,
        })
    }

    fn parse_row_table(&mut self) -> Result<TableDeclaration, ParseError> {
        self.expect_keyword("row_table")?;
        let name = self.parse_name()?;
        self.expect_symbol(';')?;

        Ok(TableDeclaration {
            name,
            kind: TableKind::Row,
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
        })
    }

    fn parse_column_statement(
        &mut self,
        columns: &mut Vec<ColumnDeclaration>,
        column_names: &mut BTreeSet<String>,
    ) -> Result<(), ParseError> {
        self.expect_keyword("column")?;
        let name_token = self.expect_identifier()?;
        let name = identifier_text(&name_token);
        if !column_names.insert(name.clone()) {
            return Err(ParseError::new(
                name_token.line,
                name_token.column,
                format!("duplicate column declaration `{name}`"),
            ));
        }
        let ty = self.parse_column_type()?;
        self.expect_symbol(';')?;
        columns.push(ColumnDeclaration { name, ty });
        Ok(())
    }

    fn parse_column_type(&mut self) -> Result<ColumnType, ParseError> {
        let ty_token = self.expect_identifier()?;
        let ty = identifier_text(&ty_token);
        match ty.as_str() {
            "bytes" => {
                let len = if self.consume_symbol('(')? {
                    let len_token = self.expect_number()?;
                    let len = match len_token.kind {
                        TokenKind::Number(value) => usize::try_from(value).map_err(|_| {
                            ParseError::new(
                                len_token.line,
                                len_token.column,
                                "byte length is too large",
                            )
                        })?,
                        _ => unreachable!("expect_number returned a non-number token"),
                    };
                    if len == 0 {
                        return Err(ParseError::new(
                            len_token.line,
                            len_token.column,
                            "byte length must be greater than zero",
                        ));
                    }
                    self.expect_symbol(')')?;
                    Some(len)
                } else {
                    None
                };
                Ok(ColumnType::Bytes { len })
            }
            "u8" => Ok(ColumnType::U8),
            "u16" => Ok(ColumnType::U16),
            "u32" => Ok(ColumnType::U32),
            "u64" => Ok(ColumnType::U64),
            "i64" => Ok(ColumnType::I64),
            "text" => Ok(ColumnType::Text),
            "bool" => Ok(ColumnType::Bool),
            _ => Err(ParseError::new(
                ty_token.line,
                ty_token.column,
                format!("unknown column type `{ty}`"),
            )),
        }
    }

    fn parse_layout(&mut self) -> Result<LayoutDeclaration, ParseError> {
        let layout_token = self.expect_keyword("layout")?;
        let name = self.parse_name()?;
        self.expect_symbol('{')?;

        let mut fields = Vec::new();
        let mut field_names = BTreeSet::new();
        loop {
            if self.consume_symbol('}')? {
                break;
            }
            if matches!(self.lookahead.kind, TokenKind::Eof) {
                return Err(ParseError::new(
                    layout_token.line,
                    layout_token.column,
                    format!("unterminated layout declaration `{name}`"),
                ));
            }
            let keyword = match &self.lookahead.kind {
                TokenKind::Ident(keyword) => keyword.as_str(),
                _ => return Err(self.error("expected layout statement: `field`")),
            };
            if keyword != "field" {
                return Err(self.error(format!(
                    "unknown layout statement `{keyword}`; expected `field`"
                )));
            }
            self.expect_keyword("field")?;
            let field_token = self.expect_identifier()?;
            let field_name = identifier_text(&field_token);
            if !field_names.insert(field_name.clone()) {
                return Err(ParseError::new(
                    field_token.line,
                    field_token.column,
                    format!("duplicate field declaration `{field_name}`"),
                ));
            }
            let ty = self.parse_column_type()?;
            self.expect_symbol(';')?;
            fields.push(FieldDeclaration {
                name: field_name,
                ty,
            });
        }
        if fields.is_empty() {
            return Err(ParseError::new(
                layout_token.line,
                layout_token.column,
                format!("layout `{name}` must declare at least one field"),
            ));
        }
        Ok(LayoutDeclaration { name, fields })
    }

    fn parse_index_statement(
        &mut self,
        unique: bool,
        indexes: &mut Vec<IndexDeclaration>,
        index_names: &mut BTreeSet<String>,
    ) -> Result<(), ParseError> {
        self.expect_keyword("index")?;
        let name_token = self.expect_identifier()?;
        let name = identifier_text(&name_token);
        if !index_names.insert(name.clone()) {
            return Err(ParseError::new(
                name_token.line,
                name_token.column,
                format!("duplicate index declaration `{name}`"),
            ));
        }
        let columns = self.parse_ident_list()?;
        self.expect_symbol(';')?;
        indexes.push(IndexDeclaration {
            name,
            unique,
            columns,
        });
        Ok(())
    }

    fn parse_ident_list(&mut self) -> Result<Vec<String>, ParseError> {
        self.expect_symbol('(')?;
        let mut items = Vec::new();

        loop {
            if self.consume_symbol(')')? {
                if items.is_empty() {
                    return Err(self.error("identifier list cannot be empty"));
                }
                return Ok(items);
            }

            let item_token = self.expect_identifier()?;
            items.push(identifier_text(&item_token));

            if self.consume_symbol(',')? {
                continue;
            }
            self.expect_symbol(')')?;
            return Ok(items);
        }
    }

    fn parse_name(&mut self) -> Result<String, ParseError> {
        let mut parts = vec![identifier_text(&self.expect_identifier()?)];
        while self.consume_symbol('.')? {
            parts.push(identifier_text(&self.expect_identifier()?));
        }
        Ok(parts.join("."))
    }

    fn expect_keyword(&mut self, expected: &str) -> Result<Token, ParseError> {
        match &self.lookahead.kind {
            TokenKind::Ident(actual) if actual == expected => {
                let token = self.lookahead.clone();
                self.advance()?;
                Ok(token)
            }
            _ => Err(self.error(format!("expected `{expected}`"))),
        }
    }

    fn expect_identifier(&mut self) -> Result<Token, ParseError> {
        match self.lookahead.kind {
            TokenKind::Ident(_) => {
                let token = self.lookahead.clone();
                self.advance()?;
                Ok(token)
            }
            _ => Err(self.error("expected identifier")),
        }
    }

    fn expect_number(&mut self) -> Result<Token, ParseError> {
        match self.lookahead.kind {
            TokenKind::Number(_) => {
                let token = self.lookahead.clone();
                self.advance()?;
                Ok(token)
            }
            _ => Err(self.error("expected number")),
        }
    }

    fn expect_symbol(&mut self, expected: char) -> Result<Token, ParseError> {
        match self.lookahead.kind {
            TokenKind::Symbol(actual) if actual == expected => {
                let token = self.lookahead.clone();
                self.advance()?;
                Ok(token)
            }
            _ => Err(self.error(format!("expected `{expected}`"))),
        }
    }

    fn consume_symbol(&mut self, expected: char) -> Result<bool, ParseError> {
        match self.lookahead.kind {
            TokenKind::Symbol(actual) if actual == expected => {
                self.advance()?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn advance(&mut self) -> Result<(), ParseError> {
        self.lookahead = self.lexer.next_token()?;
        Ok(())
    }

    fn error(&self, detail: impl Into<String>) -> ParseError {
        ParseError::new(self.lookahead.line, self.lookahead.column, detail)
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
                1,
                format!("table `{table}` {owner} references unknown column `{column}`"),
            ));
        }
    }
    Ok(())
}

fn identifier_text(token: &Token) -> String {
    match &token.kind {
        TokenKind::Ident(value) => value.clone(),
        _ => unreachable!("identifier_text called with non-identifier token"),
    }
}

struct Lexer<'a> {
    input: &'a [u8],
    offset: usize,
    line: usize,
    column: usize,
}

impl<'a> Lexer<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            input: source.as_bytes(),
            offset: 0,
            line: 1,
            column: 1,
        }
    }

    fn next_token(&mut self) -> Result<Token, ParseError> {
        self.skip_whitespace_and_comments();
        let line = self.line;
        let column = self.column;

        let Some(byte) = self.peek() else {
            return Ok(Token {
                kind: TokenKind::Eof,
                line,
                column,
            });
        };

        if is_ident_start(byte) {
            return Ok(Token {
                kind: TokenKind::Ident(self.read_identifier()),
                line,
                column,
            });
        }

        if byte.is_ascii_digit() {
            return Ok(Token {
                kind: TokenKind::Number(self.read_number(line, column)?),
                line,
                column,
            });
        }

        if matches!(byte, b'{' | b'}' | b'(' | b')' | b',' | b';' | b'.') {
            self.bump();
            return Ok(Token {
                kind: TokenKind::Symbol(byte as char),
                line,
                column,
            });
        }

        Err(ParseError::new(
            line,
            column,
            format!("unexpected character `{}`", byte as char),
        ))
    }

    fn skip_whitespace_and_comments(&mut self) {
        loop {
            while self.peek().is_some_and(|byte| byte.is_ascii_whitespace()) {
                self.bump();
            }

            if self.peek() == Some(b'#')
                || (self.peek() == Some(b'/') && self.peek_next() == Some(b'/'))
            {
                while let Some(byte) = self.bump() {
                    if byte == b'\n' {
                        break;
                    }
                }
                continue;
            }

            break;
        }
    }

    fn read_identifier(&mut self) -> String {
        let start = self.offset;
        while self.peek().is_some_and(is_ident_continue) {
            self.bump();
        }
        std::str::from_utf8(&self.input[start..self.offset])
            .expect("identifier contains only ASCII")
            .to_string()
    }

    fn read_number(&mut self, line: usize, column: usize) -> Result<u64, ParseError> {
        let mut value = 0u64;
        while let Some(byte) = self.peek() {
            if !byte.is_ascii_digit() {
                break;
            }
            let digit = (byte - b'0') as u64;
            value = value
                .checked_mul(10)
                .and_then(|value| value.checked_add(digit))
                .ok_or_else(|| ParseError::new(line, column, "number literal is too large"))?;
            self.bump();
        }
        Ok(value)
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.offset).copied()
    }

    fn peek_next(&self) -> Option<u8> {
        self.input.get(self.offset + 1).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.offset += 1;
        if byte == b'\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Some(byte)
    }
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn value_map<'a>(
    values: &'a [(&'a str, FieldValue)],
) -> Result<BTreeMap<&'a str, &'a FieldValue>, String> {
    let mut out = BTreeMap::new();
    for (name, value) in values {
        if out.insert(*name, value).is_some() {
            return Err(format!("duplicate field value `{name}`"));
        }
    }
    Ok(out)
}

fn reject_extra_values<'a>(
    actual: impl Iterator<Item = &'a str>,
    declared: impl Iterator<Item = &'a str>,
    owner: &str,
) -> Result<(), String> {
    let declared = declared.collect::<BTreeSet<_>>();
    let extras = actual
        .filter(|name| !declared.contains(name))
        .collect::<Vec<_>>();
    if extras.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{owner} has undeclared field values: {}",
            extras.join(", ")
        ))
    }
}

fn encode_value(
    ty: &ColumnType,
    value: &FieldValue,
    out: &mut Vec<u8>,
    label: &str,
) -> Result<(), String> {
    match (ty, value) {
        (ColumnType::U8, FieldValue::U8(value)) => out.push(*value),
        (ColumnType::U16, FieldValue::U16(value)) => out.extend_from_slice(&value.to_be_bytes()),
        (ColumnType::U32, FieldValue::U32(value)) => out.extend_from_slice(&value.to_be_bytes()),
        (ColumnType::U64, FieldValue::U64(value)) => out.extend_from_slice(&value.to_be_bytes()),
        (ColumnType::I64, FieldValue::I64(value)) => out.extend_from_slice(&value.to_be_bytes()),
        (ColumnType::Bytes { len: Some(len) }, FieldValue::Bytes(bytes)) => {
            if bytes.len() != *len {
                return Err(format!(
                    "field `{label}` has {} bytes, expected {len}",
                    bytes.len()
                ));
            }
            out.extend_from_slice(bytes);
        }
        (ColumnType::Bytes { len: None }, FieldValue::Bytes(bytes)) => {
            let len = u32::try_from(bytes.len())
                .map_err(|_| format!("field `{label}` exceeds u32 length"))?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(bytes);
        }
        (ColumnType::Text, FieldValue::Text(text)) => {
            let len = u32::try_from(text.len())
                .map_err(|_| format!("field `{label}` exceeds u32 length"))?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(text.as_bytes());
        }
        (ColumnType::Bool, FieldValue::Bool(false)) => out.push(0),
        (ColumnType::Bool, FieldValue::Bool(true)) => out.push(1),
        _ => {
            return Err(format!(
                "field `{label}` value does not match declared type"
            ))
        }
    }
    Ok(())
}

fn decode_value(
    ty: &ColumnType,
    bytes: &[u8],
    offset: &mut usize,
    label: &str,
) -> Result<FieldValue, String> {
    match ty {
        ColumnType::U8 => Ok(FieldValue::U8(take_exact(bytes, offset, 1, label)?[0])),
        ColumnType::U16 => {
            let raw = take_exact(bytes, offset, 2, label)?;
            Ok(FieldValue::U16(u16::from_be_bytes(raw.try_into().unwrap())))
        }
        ColumnType::U32 => {
            let raw = take_exact(bytes, offset, 4, label)?;
            Ok(FieldValue::U32(u32::from_be_bytes(raw.try_into().unwrap())))
        }
        ColumnType::U64 => {
            let raw = take_exact(bytes, offset, 8, label)?;
            Ok(FieldValue::U64(u64::from_be_bytes(raw.try_into().unwrap())))
        }
        ColumnType::I64 => {
            let raw = take_exact(bytes, offset, 8, label)?;
            Ok(FieldValue::I64(i64::from_be_bytes(raw.try_into().unwrap())))
        }
        ColumnType::Bytes { len: Some(len) } => Ok(FieldValue::Bytes(
            take_exact(bytes, offset, *len, label)?.to_vec(),
        )),
        ColumnType::Bytes { len: None } => {
            let raw_len = take_exact(bytes, offset, 4, label)?;
            let len = u32::from_be_bytes(raw_len.try_into().unwrap()) as usize;
            Ok(FieldValue::Bytes(
                take_exact(bytes, offset, len, label)?.to_vec(),
            ))
        }
        ColumnType::Text => {
            let raw_len = take_exact(bytes, offset, 4, label)?;
            let len = u32::from_be_bytes(raw_len.try_into().unwrap()) as usize;
            let raw = take_exact(bytes, offset, len, label)?;
            let text = String::from_utf8(raw.to_vec())
                .map_err(|err| format!("field `{label}` is not utf8: {err}"))?;
            Ok(FieldValue::Text(text))
        }
        ColumnType::Bool => match take_exact(bytes, offset, 1, label)?[0] {
            0 => Ok(FieldValue::Bool(false)),
            1 => Ok(FieldValue::Bool(true)),
            value => Err(format!("field `{label}` has invalid bool byte {value}")),
        },
    }
}

fn take_exact<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    len: usize,
    label: &str,
) -> Result<&'a [u8], String> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| format!("field `{label}` length overflows"))?;
    if end > bytes.len() {
        return Err(format!("field `{label}` is truncated"));
    }
    let out = &bytes[*offset..end];
    *offset = end;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

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

            layout facts_wire {
              field version u8;
              field id bytes(32);
              field timestamp u64;
              field body bytes;
            }
            "#,
        )
        .expect("schema parses");

        let opaque_facts = schema.table("facts").expect("row table");
        assert_eq!(opaque_facts.kind, TableKind::Row);
        assert_eq!(opaque_facts.row_key.columns, vec!["key"]);
        assert_eq!(
            opaque_facts.column("key").map(|column| &column.ty),
            Some(&ColumnType::Bytes { len: None })
        );

        let typed_facts = schema.table("facts_typed").expect("typed facts table");
        assert_eq!(typed_facts.kind, TableKind::Typed);
        assert_eq!(typed_facts.row_key.columns, vec!["id"]);
        assert_eq!(
            typed_facts.column("id").map(|column| &column.ty),
            Some(&ColumnType::Bytes { len: Some(32) })
        );
        assert_eq!(
            typed_facts.index("by_scope_time"),
            Some(&IndexDeclaration {
                name: "by_scope_time".to_string(),
                unique: false,
                columns: vec!["scope".to_string(), "timestamp".to_string()],
            })
        );
        assert_eq!(
            typed_facts.index("by_scope_id").map(|index| index.unique),
            Some(true)
        );

        let layout = schema.layout("facts_wire").expect("layout");
        assert_eq!(
            layout.field("version").map(|field| &field.ty),
            Some(&ColumnType::U8)
        );
        assert_eq!(
            layout.field("body").map(|field| &field.ty),
            Some(&ColumnType::Bytes { len: None })
        );
    }

    #[test]
    fn parses_initial_poc10_schema_files() {
        let core = parse_schema(CORE_SCHEMA_SOURCE).expect("core schema parses");
        let facts = parse_schema(FACTS_SCHEMA_SOURCE).expect("fact module schema parses");
        let handlers = parse_schema(INTENTS_SCHEMA_SOURCE).expect("handler schema parses");

        assert_eq!(
            table_names(&core),
            vec![
                "facts",
                "inbox",
                "needs",
                "offers",
                "time_wakes",
                "pending_projection",
                "intents",
                "clock",
            ]
        );
        assert_eq!(
            table_names(&facts),
            vec![
                "message_rows",
                "opened_message_rows",
                "sealed_message_rows",
                "message_tombstone_rows",
                "file_slice_rows",
                "workspace_rows",
                "recipient_key_rows",
                "key_wrap_rows",
                "user_rows",
                "local_endpoint_rows",
                "local_endpoint_secret_rows",
                "local_endpoint_signing_public_key_rows",
                "local_endpoint_signing_secret_rows",
                "identity_endpoint_shared_rows",
                "content_event_rows",
                "cascade_staged_fact_rows",
                "admin_rows",
                "content_messages",
                "content_reactions",
                "content_files",
                "connection_ephemeral_secret_rows",
                "connection_request_rows",
                "connection_response_rows",
                "invite_accepted_rows",
                "invite_server_rows",
                "user_invite_rows",
                "device_invite_rows",
                "invite_secret_rows",
                "sync_compare_rows",
                "sync_have_id_rows",
                "sync_need_id_rows",
                "sync_shareable_fact_rows",
                "message_deletion_rows",
                "file_deletion_rows",
                "removal_frontier_rows",
                "local_history_node_secret_rows",
                "disappearing_messages_setting_rows",
            ]
        );
        assert_eq!(
            table_names(&handlers),
            vec![
                "purge_retire_coords",
                "sync_index_snapshots",
                "connection_attempt_checkpoints",
                "send_network_frame_cursors",
            ]
        );

        for document in [&core, &facts, &handlers] {
            for table in &document.tables {
                match table.kind {
                    TableKind::Row => {
                        assert_eq!(table.row_key.columns, vec!["key"]);
                        assert_eq!(
                            table.column("key").map(|column| &column.ty),
                            Some(&ColumnType::Bytes { len: None })
                        );
                        assert_eq!(
                            table.column("value").map(|column| &column.ty),
                            Some(&ColumnType::Bytes { len: None })
                        );
                        assert!(table.indexes.is_empty());
                    }
                    TableKind::Typed => {
                        assert!(
                            matches!(
                                table.name.as_str(),
                                "content_messages" | "content_reactions" | "content_files"
                            ),
                            "unexpected typed table {}",
                            table.name
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn rejects_missing_row_key_and_unknown_references() {
        let missing_key = parse_schema(
            r#"
            table facts {
              column key bytes;
            }
            "#,
        );
        assert!(missing_key.is_err());

        let unknown_column = parse_schema(
            r#"
            table facts {
              column key bytes;
              row_key (missing);
            }
            "#,
        );
        assert!(unknown_column.is_err());
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

    fn table_names(document: &SchemaDocument) -> Vec<&str> {
        document
            .tables
            .iter()
            .map(|table| table.name.as_str())
            .collect()
    }
}

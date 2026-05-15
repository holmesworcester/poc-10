//! Parser skeleton for the poc-10 schema declaration files.
//!
//! This module intentionally stops at a small AST. It does not create store
//! schemas or row codecs yet; the first step is making durable table ownership
//! explicit and parseable without embedding SQL or Rust behavior.

use std::collections::BTreeSet;
use std::fmt;

pub const CORE_SCHEMA_SOURCE: &str = include_str!("schema.p8sql");
pub const EVENT_MODULES_SCHEMA_SOURCE: &str = include_str!("../event_modules/schema.p8sql");
pub const HANDLERS_SCHEMA_SOURCE: &str = include_str!("../handlers/schema.p8sql");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaDocument {
    pub tables: Vec<TableDeclaration>,
}

impl SchemaDocument {
    pub fn table(&self, name: &str) -> Option<&TableDeclaration> {
        self.tables.iter().find(|table| table.name == name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableDeclaration {
    pub name: String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnDeclaration {
    pub name: String,
    pub ty: ColumnType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColumnType {
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

        while !matches!(self.lookahead.kind, TokenKind::Eof) {
            let table = self.parse_table()?;
            if !table_names.insert(table.name.clone()) {
                return Err(self.error(format!("duplicate table declaration `{}`", table.name)));
            }
            tables.push(table);
        }

        Ok(SchemaDocument { tables })
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
            columns,
            row_key,
            indexes,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tables_row_keys_indexes_and_byte_lengths() {
        let schema = parse_schema(
            r#"
            table facts {
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

        let facts = schema.table("facts").expect("facts table");
        assert_eq!(facts.row_key.columns, vec!["id"]);
        assert_eq!(
            facts.column("id").map(|column| &column.ty),
            Some(&ColumnType::Bytes { len: Some(32) })
        );
        assert_eq!(
            facts.index("by_scope_time"),
            Some(&IndexDeclaration {
                name: "by_scope_time".to_string(),
                unique: false,
                columns: vec!["scope".to_string(), "timestamp".to_string()],
            })
        );
        assert_eq!(
            facts.index("by_scope_id").map(|index| index.unique),
            Some(true)
        );
    }

    #[test]
    fn parses_initial_poc10_schema_files() {
        let core = parse_schema(CORE_SCHEMA_SOURCE).expect("core schema parses");
        let event_modules =
            parse_schema(EVENT_MODULES_SCHEMA_SOURCE).expect("event module schema parses");
        let handlers = parse_schema(HANDLERS_SCHEMA_SOURCE).expect("handler schema parses");

        assert_eq!(
            table_names(&core),
            vec![
                "facts",
                "inbox",
                "needs",
                "offers",
                "pending_projection",
                "intents",
                "clock",
                "network_in",
                "network_out",
            ]
        );
        assert_eq!(
            table_names(&event_modules),
            vec![
                "message_rows",
                "sealed_message_rows",
                "message_tombstone_rows",
                "file_rows",
                "workspace_rows",
                "recipient_key_rows",
                "key_wrap_rows",
                "user_rows",
                "local_endpoint_rows",
                "local_endpoint_secret_rows",
                "local_endpoint_signing_public_key_rows",
                "local_endpoint_signing_secret_rows",
                "content_event_rows",
                "sync_compare_rows",
                "sync_have_id_rows",
                "sync_need_id_rows",
            ]
        );
        assert_eq!(
            table_names(&handlers),
            vec![
                "purge_retire_coords",
                "sync_index_snapshots",
                "connection_attempt_checkpoints",
                "network_send_cursors",
            ]
        );

        for document in [&core, &event_modules, &handlers] {
            for table in &document.tables {
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

//! Parser for the poc-10 schema declaration files.
//!
//! A `.p8sql` source is a list of `table NAME { column NAME bytes; ...;
//! row_key (COL, ...); }` blocks; `#` and `//` start line comments. Core only
//! needs each table's name and a way to confirm the declaration is the uniform
//! row-store shape, so this parser stops at a small AST: it builds no SQL and
//! owns no row codecs. Every column type is `bytes`; any other column type,
//! index declaration, or statement outside this grammar is rejected.

use std::collections::BTreeSet;

pub const CORE_SCHEMA_SOURCE: &str = include_str!("schema.p8sql");
pub const EVENT_MODULES_SCHEMA_SOURCE: &str = include_str!("../event_modules/schema.p8sql");
pub const HANDLERS_SCHEMA_SOURCE: &str = include_str!("../handlers/schema.p8sql");

/// One parsed `.p8sql` document: table declarations in source order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaDocument {
    pub tables: Vec<TableDeclaration>,
}

/// One `table NAME { ... }` block. `columns` lists column names in declared
/// order (every column is a `bytes` column); `row_key` lists the row-key
/// column names. The store decides whether this shape is one it accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableDeclaration {
    pub name: String,
    pub columns: Vec<String>,
    pub row_key: Vec<String>,
}

/// Parse a schema source into its table declarations.
pub fn parse_schema(source: &str) -> Result<SchemaDocument, String> {
    let tokens = tokenize(source);
    let mut parser = Parser {
        tokens: &tokens,
        pos: 0,
    };
    let mut tables = Vec::new();
    let mut names = BTreeSet::new();
    while !parser.at_end() {
        let table = parser.parse_table()?;
        if !names.insert(table.name.clone()) {
            return Err(format!("duplicate table declaration `{}`", table.name));
        }
        tables.push(table);
    }
    Ok(SchemaDocument { tables })
}

/// Split a source into identifier and punctuation tokens, dropping `#` and
/// `//` line comments and all whitespace.
fn tokenize(source: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    for line in source.lines() {
        let mut spaced = String::new();
        for ch in strip_comment(line).chars() {
            if "{}(),;".contains(ch) {
                spaced.push(' ');
                spaced.push(ch);
                spaced.push(' ');
            } else {
                spaced.push(ch);
            }
        }
        tokens.extend(spaced.split_whitespace().map(str::to_string));
    }
    tokens
}

fn strip_comment(line: &str) -> &str {
    match [line.find('#'), line.find("//")]
        .into_iter()
        .flatten()
        .min()
    {
        Some(at) => &line[..at],
        None => line,
    }
}

struct Parser<'a> {
    tokens: &'a [String],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn at_end(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    fn peek(&self) -> Option<&'a str> {
        self.tokens.get(self.pos).map(String::as_str)
    }

    fn next(&mut self) -> Result<&'a str, String> {
        let token = self
            .tokens
            .get(self.pos)
            .ok_or("unexpected end of schema source")?;
        self.pos += 1;
        Ok(token.as_str())
    }

    fn expect(&mut self, expected: &str) -> Result<(), String> {
        match self.next()? {
            found if found == expected => Ok(()),
            found => Err(format!("expected `{expected}`, found `{found}`")),
        }
    }

    fn parse_ident(&mut self) -> Result<String, String> {
        let token = self.next()?;
        if !token.is_empty()
            && token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            Ok(token.to_string())
        } else {
            Err(format!("expected identifier, found `{token}`"))
        }
    }

    fn parse_table(&mut self) -> Result<TableDeclaration, String> {
        self.expect("table")?;
        let name = self.parse_ident()?;
        self.expect("{")?;

        let mut columns: Vec<String> = Vec::new();
        let mut row_key = None;
        loop {
            match self.peek() {
                Some("}") => {
                    self.pos += 1;
                    break;
                }
                Some("column") => {
                    self.pos += 1;
                    let column = self.parse_ident()?;
                    let ty = self.next()?;
                    if ty != "bytes" {
                        return Err(format!(
                            "table `{name}` column `{column}` must be `bytes`, found `{ty}`"
                        ));
                    }
                    self.expect(";")?;
                    if columns.contains(&column) {
                        return Err(format!("duplicate column `{column}` in table `{name}`"));
                    }
                    columns.push(column);
                }
                Some("row_key") => {
                    self.pos += 1;
                    if row_key.is_some() {
                        return Err(format!("duplicate row key in table `{name}`"));
                    }
                    row_key = Some(self.parse_ident_list()?);
                    self.expect(";")?;
                }
                Some(other) => {
                    return Err(format!(
                        "unknown table statement `{other}` in table `{name}`; \
                         expected `column`, `row_key`, or `}}`"
                    ));
                }
                None => return Err(format!("unterminated table declaration `{name}`")),
            }
        }

        let row_key = row_key.ok_or_else(|| format!("table `{name}` must declare a row key"))?;
        for column in &row_key {
            if !columns.contains(column) {
                return Err(format!(
                    "table `{name}` row key references unknown column `{column}`"
                ));
            }
        }
        Ok(TableDeclaration {
            name,
            columns,
            row_key,
        })
    }

    fn parse_ident_list(&mut self) -> Result<Vec<String>, String> {
        self.expect("(")?;
        let mut items = Vec::new();
        loop {
            if self.peek() == Some(")") {
                self.pos += 1;
                if items.is_empty() {
                    return Err("identifier list cannot be empty".to_string());
                }
                return Ok(items);
            }
            if !items.is_empty() {
                self.expect(",")?;
            }
            items.push(self.parse_ident()?);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_uniform_row_tables_and_ignores_comments() {
        let document = parse_schema(
            "# leading comment\n\
             table facts {\n\
               column key bytes;  // inline comment\n\
               column value bytes;\n\
               row_key (key);\n\
             }\n",
        )
        .expect("schema parses");

        assert_eq!(document.tables.len(), 1);
        let facts = &document.tables[0];
        assert_eq!(facts.name, "facts");
        assert_eq!(facts.columns, ["key", "value"]);
        assert_eq!(facts.row_key, ["key"]);
    }

    #[test]
    fn parses_initial_poc10_schema_files() {
        for source in [
            CORE_SCHEMA_SOURCE,
            EVENT_MODULES_SCHEMA_SOURCE,
            HANDLERS_SCHEMA_SOURCE,
        ] {
            let document = parse_schema(source).expect("schema parses");
            assert!(!document.tables.is_empty());
            for table in &document.tables {
                assert_eq!(table.columns, ["key", "value"], "table `{}`", table.name);
                assert_eq!(table.row_key, ["key"], "table `{}`", table.name);
            }
        }
    }

    #[test]
    fn rejects_declarations_outside_the_grammar() {
        // missing row key
        assert!(parse_schema("table facts { column key bytes; }").is_err());
        // row key references an undeclared column
        assert!(parse_schema("table facts { column key bytes; row_key (missing); }").is_err());
        // duplicate table
        assert!(parse_schema(
            "table facts { column key bytes; row_key (key); }\n\
             table facts { column key bytes; row_key (key); }"
        )
        .is_err());

        let embedded = parse_schema("table facts { let cb = rust(); }")
            .expect_err("embedded expressions are outside the DSL");
        assert!(embedded.contains("unknown table statement"), "{embedded}");

        let typed = parse_schema("table facts { column key u64; row_key (key); }")
            .expect_err("only bytes columns are supported");
        assert!(typed.contains("must be `bytes`"), "{typed}");
    }
}

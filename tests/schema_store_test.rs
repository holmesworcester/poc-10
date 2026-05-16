use std::collections::BTreeSet;

use rusqlite::Connection;
use topo::core::schema_dsl::{
    parse_schema, CORE_SCHEMA_SOURCE, FACT_MODULES_SCHEMA_SOURCE, INTENT_HANDLERS_SCHEMA_SOURCE,
};
use topo::core::store::{Store, TableName, TableRow};

fn checked_schema_sources() -> [&'static str; 3] {
    [
        CORE_SCHEMA_SOURCE,
        FACT_MODULES_SCHEMA_SOURCE,
        INTENT_HANDLERS_SCHEMA_SOURCE,
    ]
}

fn declared_table_names(sources: &[&str]) -> BTreeSet<String> {
    sources
        .iter()
        .flat_map(|source| parse_schema(source).expect("schema parses").tables)
        .map(|table| table.name)
        .collect()
}

fn sqlite_table_names(path: &std::path::Path) -> BTreeSet<String> {
    let conn = Connection::open(path).expect("open sqlite");
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .expect("prepare table name query");
    stmt.query_map([], |row| row.get::<_, String>(0))
        .expect("query table names")
        .collect::<Result<BTreeSet<_>, _>>()
        .expect("collect table names")
}

#[test]
fn schema_sources_create_declared_row_tables() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("schema-store.db");
    let sources = checked_schema_sources();

    let store = Store::open_disk_with_schema_sources(&path, &sources).expect("open store");
    let declared = declared_table_names(&sources);
    let actual = sqlite_table_names(&path);
    assert!(
        declared.is_subset(&actual),
        "missing schema tables: {:?}",
        declared.difference(&actual).collect::<Vec<_>>()
    );

    store
        .insert_table_rows(vec![
            TableRow {
                table: TableName::new("facts"),
                key: b"fact/1".to_vec(),
                value: b"fact bytes".to_vec(),
            },
            TableRow {
                table: TableName::new("message_rows"),
                key: b"message/1".to_vec(),
                value: b"message bytes".to_vec(),
            },
            TableRow {
                table: TableName::new("network_send_cursors"),
                key: b"cursor/1".to_vec(),
                value: b"cursor bytes".to_vec(),
            },
        ])
        .expect("insert rows into p8sql-created tables");

    assert_eq!(
        store
            .table_row(TableName::new("facts"), b"fact/1")
            .expect("read fact row"),
        Some(b"fact bytes".to_vec())
    );

    Store::open_disk_with_schema_sources(&path, &sources)
        .expect("reopen validates existing tables");
}

#[test]
fn schema_sources_reject_existing_table_with_wrong_shape() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("schema-store.db");
    let conn = Connection::open(&path).expect("open sqlite");
    conn.execute_batch(
        "CREATE TABLE facts (
            key BLOB PRIMARY KEY NOT NULL,
            value BLOB NOT NULL
        );",
    )
    .expect("create incompatible table");
    drop(conn);

    let err = match Store::open_disk_with_schema_sources(&path, &[CORE_SCHEMA_SOURCE]) {
        Ok(_) => panic!("incompatible table should reject"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("existing table facts"),
        "unexpected error: {err}"
    );
}

#[test]
fn schema_sources_reject_non_row_store_declarations() {
    let source = r#"
        table not_rows {
          column id bytes;
          column value bytes;
          row_key (id);
        }
    "#;

    let err = match Store::open_memory_with_schema_sources(&[source]) {
        Ok(_) => panic!("non-row-store declaration should reject"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("must use row-store shape"),
        "unexpected error: {err}"
    );
}

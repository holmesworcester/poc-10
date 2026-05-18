use std::collections::BTreeSet;

use rusqlite::Connection;
use topo::core::schema_dsl::{
    parse_schema, CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE, INTENTS_SCHEMA_SOURCE,
};
use topo::core::store::{Store, TableName, TableRow};

fn checked_schema_sources() -> [&'static str; 3] {
    [
        CORE_SCHEMA_SOURCE,
        FACTS_SCHEMA_SOURCE,
        INTENTS_SCHEMA_SOURCE,
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
                table: TableName::new("send_network_frame_cursors"),
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
fn schema_sources_create_typed_table_declarations() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("typed-schema-store.db");
    let source = r#"
        table typed_messages {
          column workspace_id bytes(32);
          column message_id bytes(32);
          column created_at_ms u64;
          column deleted bool;
          row_key (workspace_id, message_id);
          index by_workspace_created (workspace_id, created_at_ms);
        }
    "#;

    Store::open_disk_with_schema_sources(&path, &[source]).expect("create typed table");
    let conn = Connection::open(&path).expect("open sqlite");
    let columns = conn
        .prepare("PRAGMA table_info(typed_messages)")
        .expect("prepare table info")
        .query_map([], |row| row.get::<_, String>(1))
        .expect("query table info")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect columns");
    assert_eq!(
        columns,
        vec![
            "workspace_id".to_string(),
            "message_id".to_string(),
            "created_at_ms".to_string(),
            "deleted".to_string()
        ]
    );

    let index_count: usize = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'typed_messages_by_workspace_created'",
            [],
            |row| row.get(0),
        )
        .expect("query typed index");
    assert_eq!(index_count, 1);

    Store::open_disk_with_schema_sources(&path, &[source]).expect("reopen validates typed table");
}

#[test]
fn schema_sources_reject_existing_typed_table_with_wrong_shape() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("typed-schema-store.db");
    let conn = Connection::open(&path).expect("open sqlite");
    conn.execute_batch(
        "CREATE TABLE typed_messages (
            workspace_id BLOB NOT NULL,
            message_id BLOB NOT NULL,
            created_at_ms TEXT NOT NULL,
            deleted INTEGER NOT NULL,
            PRIMARY KEY (workspace_id, message_id)
        );",
    )
    .expect("create incompatible typed table");
    drop(conn);
    let source = r#"
        table typed_messages {
          column workspace_id bytes(32);
          column message_id bytes(32);
          column created_at_ms u64;
          column deleted bool;
          row_key (workspace_id, message_id);
        }
    "#;

    let err = match Store::open_disk_with_schema_sources(&path, &[source]) {
        Ok(_) => panic!("incompatible typed table should reject"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("existing table typed_messages"),
        "unexpected error: {err}"
    );
}

#[test]
fn schema_sources_reject_existing_typed_table_missing_declared_index() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("typed-schema-store.db");
    let conn = Connection::open(&path).expect("open sqlite");
    conn.execute_batch(
        "CREATE TABLE typed_messages (
            workspace_id BLOB NOT NULL,
            message_id BLOB NOT NULL,
            created_at_ms INTEGER NOT NULL,
            deleted INTEGER NOT NULL,
            PRIMARY KEY (workspace_id, message_id)
        );",
    )
    .expect("create typed table without declared index");
    drop(conn);
    let source = r#"
        table typed_messages {
          column workspace_id bytes(32);
          column message_id bytes(32);
          column created_at_ms u64;
          column deleted bool;
          row_key (workspace_id, message_id);
          index by_workspace_created (workspace_id, created_at_ms);
        }
    "#;

    let err = match Store::open_disk_with_schema_sources(&path, &[source]) {
        Ok(_) => panic!("typed table with missing index should reject"),
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("is missing index typed_messages_by_workspace_created"),
        "unexpected error: {err}"
    );
}

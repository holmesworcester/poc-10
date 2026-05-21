use std::collections::BTreeSet;

use rusqlite::{params, Connection};
use topo::core::schema::CORE_SCHEMA_SOURCE;
use topo::core::schema_dsl::{parse_schema, TableStorage};
use topo::core::store::{Store, TableName, TableRow};
use topo::protocol::facts::content::{file, reaction};
use topo::protocol::registry::{FACTS_SCHEMA_SOURCE, INTENTS_SCHEMA_SOURCE};

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
        .flat_map(|source| parse_schema(source).expect("schema parses"))
        .filter(|table| table.storage == TableStorage::Durable)
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
        .insert_table_rows(vec![TableRow {
            table: TableName::new("workspace_rows"),
            key: b"clock".to_vec(),
            value: 1u64.to_be_bytes().to_vec(),
        }])
        .expect("insert row into p8sql-created row table");

    assert_eq!(
        store
            .table_row(TableName::new("workspace_rows"), b"clock")
            .expect("read p8sql row"),
        Some(1u64.to_be_bytes().to_vec())
    );

    Store::open_disk_with_schema_sources(&path, &sources)
        .expect("reopen validates existing tables");
}

#[test]
fn schema_source_memory_row_tables_are_temp() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("schema-memory-store.db");
    let local_intents = TableName::new("local_intents");

    let store = Store::open_disk_with_schema_sources(&path, &[CORE_SCHEMA_SOURCE])
        .expect("open store with core schema");
    assert_eq!(
        store
            .table_row_count(local_intents)
            .expect("count temp rows"),
        0
    );
    assert!(
        !sqlite_table_names(&path).contains("local_intents"),
        "memory schema table should not be durable"
    );

    let reopened = Store::open_disk_with_schema_sources(&path, &[CORE_SCHEMA_SOURCE])
        .expect("reopen store with core schema");
    assert_eq!(
        reopened
            .table_row_count(local_intents)
            .expect("count temp rows after reopen"),
        0
    );
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
fn content_read_model_rows_materialize_into_typed_tables() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("content-read-models.db");
    Store::open_disk_with_schema_sources(&path, &[FACTS_SCHEMA_SOURCE])
        .expect("open content schema store");
    let conn = Connection::open(&path).expect("open sqlite");

    conn.execute(
        "INSERT INTO content_messages
         (workspace_id, message_id, author_user_id, created_at_ms, signer_id, frontier_id,
          minute, leaf_id, deleted)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)",
        params![
            &[1u8; 32][..],
            &[9u8; 32][..],
            &[2u8; 32][..],
            60_000_i64,
            &[6u8; 32][..],
            &[3u8; 32][..],
            1_i64,
            &[4u8; 32][..],
        ],
    )
    .expect("insert content message row");

    let reaction_row = reaction::rows::ReactionRow {
        workspace_id: [1; 32],
        reaction_id: [10; 32],
        created_at_ms: 60_001,
        target_message_id: [9; 32],
        author_user_id: [2; 32],
        nonce: [6; reaction::fact::REACTION_NONCE_BYTES],
        ciphertext: b"+1".to_vec(),
    };
    conn.execute(
        "INSERT INTO content_reactions
         (workspace_id, reaction_id, message_id, author_user_id, created_at_ms, nonce,
          ciphertext, deleted)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
        params![
            reaction_row.workspace_id.as_slice(),
            reaction_row.reaction_id.as_slice(),
            reaction_row.target_message_id.as_slice(),
            reaction_row.author_user_id.as_slice(),
            reaction_row.created_at_ms as i64,
            reaction_row.nonce.as_slice(),
            reaction_row.ciphertext.as_slice(),
        ],
    )
    .expect("insert reaction row");

    let file_fact = file::fact::ContentFileFact {
        workspace_id: [1; 32],
        created_at_ms: 60_002,
        message_id: [9; 32],
        author_user_id: [2; 32],
        file_id: [11; 32],
        blob_bytes: 4096,
        total_slices: 2,
        slice_bytes: 2048,
        root_hash: [7; file::fact::FILE_ROOT_HASH_BYTES],
        sealed_metadata: b"meta".to_vec(),
    };
    conn.execute(
        "INSERT INTO content_files
         (workspace_id, file_fact_id, message_id, file_id, author_user_id, created_at_ms,
          root_hash, byte_len, total_slices, slice_bytes, sealed_metadata, deleted)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0)",
        params![
            file_fact.workspace_id.as_slice(),
            &[12u8; 32][..],
            file_fact.message_id.as_slice(),
            file_fact.file_id.as_slice(),
            file_fact.author_user_id.as_slice(),
            file_fact.created_at_ms as i64,
            file_fact.root_hash.as_slice(),
            file_fact.blob_bytes as i64,
            i64::from(file_fact.total_slices),
            i64::from(file_fact.slice_bytes),
            file_fact.sealed_metadata.as_slice(),
        ],
    )
    .expect("insert file row");
    let message_columns = conn
        .query_row(
            "SELECT author_user_id, created_at_ms, signer_id, deleted
             FROM content_messages
             WHERE workspace_id = ?1 AND message_id = ?2",
            params![&[1u8; 32][..], &[9u8; 32][..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .expect("query content_messages");
    assert_eq!(message_columns, (vec![2; 32], 60_000, vec![6; 32], 0));

    let reaction_columns = conn
        .query_row(
            "SELECT message_id, author_user_id, created_at_ms, nonce, ciphertext, deleted
             FROM content_reactions
             WHERE workspace_id = ?1 AND reaction_id = ?2",
            params![&[1u8; 32][..], &[10u8; 32][..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .expect("query content_reactions");
    assert_eq!(
        reaction_columns,
        (
            vec![9; 32],
            vec![2; 32],
            60_001,
            vec![6; 24],
            b"+1".to_vec(),
            0
        )
    );

    let file_columns = conn
        .query_row(
            "SELECT file_fact_id, message_id, file_id, root_hash, byte_len, total_slices,
                    slice_bytes, sealed_metadata, deleted
             FROM content_files
             WHERE workspace_id = ?1 AND file_fact_id = ?2",
            params![&[1u8; 32][..], &[12u8; 32][..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            },
        )
        .expect("query content_files");
    assert_eq!(
        file_columns,
        (
            vec![12; 32],
            vec![9; 32],
            vec![11; 32],
            vec![7; 32],
            4096,
            2,
            2048,
            b"meta".to_vec(),
            0
        )
    );

    let opaque_table_count: i64 = conn
        .query_row(
            "SELECT COUNT(*)
             FROM sqlite_master
             WHERE type = 'table'
               AND name IN ('content_message_rows', 'reaction_rows', 'file_rows')",
            [],
            |row| row.get(0),
        )
        .expect("query old opaque tables");
    assert_eq!(opaque_table_count, 0);
}

#[test]
fn schema_source_typed_tables_reject_opaque_row_helpers() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("typed-row-store.db");
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
    let store = Store::open_disk_with_schema_sources(&path, &[source]).expect("open store");
    let err = store
        .insert_table_rows(vec![TableRow {
            table: TableName::new("typed_messages"),
            key: vec![0; 64],
            value: vec![0; 9],
        }])
        .expect_err("typed tables must not accept opaque row writes");
    assert!(
        err.to_string().contains("not an opaque row table"),
        "unexpected error: {err}"
    );
}

#[test]
fn schema_sources_require_explicit_row_table_declarations() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("typed-key-value-store.db");
    let source = r#"
        table legacy_key_value_shape {
          column key bytes;
          column value bytes;
          row_key (key);
        }
    "#;

    Store::open_disk_with_schema_sources(&path, &[source])
        .expect("key/value table block creates a typed table");
    let conn = Connection::open(&path).expect("open sqlite");
    let columns = conn
        .prepare("PRAGMA table_info(legacy_key_value_shape)")
        .expect("prepare table info")
        .query_map([], |row| row.get::<_, String>(1))
        .expect("query table info")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect columns");
    assert_eq!(columns, vec!["key".to_string(), "value".to_string()]);
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

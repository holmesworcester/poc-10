use std::collections::BTreeSet;

use rusqlite::{params, Connection};
use topo::core::row_schema::{RowField, RowTableSchema, RowValue};
use topo::core::schema::CORE_SCHEMA_SOURCE;
use topo::core::store::{ReplayTables, SchemaSource, Store, TableName, TableRow};
use topo::protocol::content::{file, reaction};
use topo::protocol::registry::FACTS_SCHEMA_SOURCE;

const TYPED_MESSAGES: TableName = TableName::new("typed_messages");
const TEST_ROWS: TableName = TableName::new("test_rows");
const SCHEMA_BACKED_ROWS: TableName = TableName::new("schema_backed_rows");
const REPLAY_PROTECTED_ROWS: TableName = TableName::new("replay_protected_rows");
const REPLAY_RESET_ROWS: TableName = TableName::new("replay_reset_rows");

const SCHEMA_BACKED_KEY: &[RowField] = &[RowField::bytes32("owner")];
const SCHEMA_BACKED_VALUE: &[RowField] = &[
    RowField::u64be("created_at_ms"),
    RowField::bytes("payload", 2),
];
const SCHEMA_BACKED_ROW_SCHEMA: RowTableSchema =
    RowTableSchema::new(SCHEMA_BACKED_ROWS, SCHEMA_BACKED_KEY, SCHEMA_BACKED_VALUE);

const TYPED_MESSAGES_SCHEMA: SchemaSource = SchemaSource {
    ddl: r#"
CREATE TABLE IF NOT EXISTS typed_messages (
    workspace_id BLOB NOT NULL,
    message_id BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    deleted INTEGER NOT NULL,
    PRIMARY KEY (workspace_id, message_id)
);
CREATE INDEX IF NOT EXISTS typed_messages_by_workspace_created
    ON typed_messages (workspace_id, created_at_ms);
"#,
    row_tables: &[],
    row_schemas: &[],
    replay: ReplayTables::EMPTY,
};

const TEST_ROWS_SCHEMA: SchemaSource = SchemaSource {
    ddl: r#"
CREATE TABLE IF NOT EXISTS test_rows (
    row_key BLOB PRIMARY KEY NOT NULL,
    row_value BLOB NOT NULL
);
"#,
    row_tables: &[TEST_ROWS],
    row_schemas: &[],
    replay: ReplayTables::EMPTY,
};

const SCHEMA_BACKED_ROWS_SCHEMA: SchemaSource = SchemaSource {
    ddl: r#"
CREATE TABLE IF NOT EXISTS schema_backed_rows (
    row_key BLOB PRIMARY KEY NOT NULL,
    row_value BLOB NOT NULL
);
"#,
    row_tables: &[],
    row_schemas: &[SCHEMA_BACKED_ROW_SCHEMA],
    replay: ReplayTables::EMPTY,
};

const REPLAY_LIFECYCLE_SCHEMA: SchemaSource = SchemaSource {
    ddl: r#"
CREATE TABLE IF NOT EXISTS replay_protected_rows (
    row_key BLOB PRIMARY KEY NOT NULL,
    row_value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS replay_reset_rows (
    row_key BLOB PRIMARY KEY NOT NULL,
    row_value BLOB NOT NULL
);
"#,
    row_tables: &[REPLAY_PROTECTED_ROWS, REPLAY_RESET_ROWS],
    row_schemas: &[],
    replay: ReplayTables {
        protected: &[REPLAY_PROTECTED_ROWS],
        reset: &[REPLAY_RESET_ROWS],
        summary: &[REPLAY_PROTECTED_ROWS, REPLAY_RESET_ROWS],
    },
};

fn checked_schema_sources() -> [SchemaSource; 2] {
    [CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE]
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
fn schema_sources_execute_declared_ddl_and_allowlisted_row_tables() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("schema-store.db");
    let sources = checked_schema_sources();

    let store = Store::open_disk_with_schema_sources(&path, &sources).expect("open store");
    let actual = sqlite_table_names(&path);
    for expected in [
        "facts",
        "local_fact_admissions",
        "context_edges",
        "content_messages",
        "content_reactions",
        "content_files",
        "workspace_rows",
    ] {
        assert!(actual.contains(expected), "missing schema table {expected}");
    }

    store
        .insert_table_rows(vec![TableRow {
            table: TableName::new("workspace_rows"),
            key: b"clock".to_vec(),
            value: 1u64.to_be_bytes().to_vec(),
        }])
        .expect("insert row into allowlisted row table");

    assert_eq!(
        store
            .table_row(TableName::new("workspace_rows"), b"clock")
            .expect("read row"),
        Some(1u64.to_be_bytes().to_vec())
    );

    Store::open_disk_with_schema_sources(&path, &sources).expect("reopen executes idempotent DDL");
}

#[test]
fn core_local_intents_table_is_temp() {
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
        "local_intents should not be durable"
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
fn core_candidate_facts_table_survives_reopen() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("candidate-facts-store.db");

    Store::open_disk_with_schema_sources(&path, &[CORE_SCHEMA_SOURCE])
        .expect("open store with core schema");
    let conn = Connection::open(&path).expect("open sqlite");
    conn.execute(
        "INSERT INTO candidate_facts
            (id, scope, scope_kind, scope_id, received_at, bytes)
         VALUES (?1, 'global', '', ?2, 123, ?3)",
        params![[7u8; 32], [0u8; 32], b"candidate".as_slice()],
    )
    .expect("insert candidate fact");
    drop(conn);

    Store::open_disk_with_schema_sources(&path, &[CORE_SCHEMA_SOURCE])
        .expect("reopen store with core schema");
    let conn = Connection::open(&path).expect("open sqlite after reopen");
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM candidate_facts", [], |row| row.get(0))
        .expect("count candidate facts");
    assert_eq!(count, 1);
}

#[test]
fn schema_sources_create_typed_tables_and_indexes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("typed-schema-store.db");

    Store::open_disk_with_schema_sources(&path, &[TYPED_MESSAGES_SCHEMA])
        .expect("create typed table");
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

    Store::open_disk_with_schema_sources(&path, &[TYPED_MESSAGES_SCHEMA])
        .expect("reopen keeps explicit DDL idempotent");
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
          minute, deleted)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
        params![
            &[1u8; 32][..],
            &[9u8; 32][..],
            &[2u8; 32][..],
            60_000_i64,
            &[6u8; 32][..],
            &[3u8; 32][..],
            1_i64,
        ],
    )
    .expect("insert content message row");

    let reaction_row = reaction::queries::ReactionRow {
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
        signer_id: [3; 32],
        signer_public_key: [4; 32],
        file_id: [11; 32],
        blob_bytes: 4096,
        total_slices: 2,
        slice_bytes: 2048,
        root_hash: [7; file::fact::FILE_ROOT_HASH_BYTES],
        sealed_metadata: file::fact::SealedMetadata::new(b"meta").expect("metadata"),
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
}

#[test]
fn replay_lifecycle_reset_preserves_protected_tables() {
    let store = Store::open_memory_with_schema_sources(&[REPLAY_LIFECYCLE_SCHEMA])
        .expect("open lifecycle store");
    store
        .insert_table_rows(vec![
            TableRow {
                table: REPLAY_PROTECTED_ROWS,
                key: b"protected".to_vec(),
                value: b"kept".to_vec(),
            },
            TableRow {
                table: REPLAY_RESET_ROWS,
                key: b"derived".to_vec(),
                value: b"cleared".to_vec(),
            },
        ])
        .expect("seed lifecycle rows");

    assert_eq!(
        store
            .clear_replay_reset_tables()
            .expect("clear replay reset"),
        1
    );
    assert_eq!(
        store
            .table_row(REPLAY_PROTECTED_ROWS, b"protected")
            .expect("read protected row"),
        Some(b"kept".to_vec())
    );
    assert_eq!(
        store
            .table_row(REPLAY_RESET_ROWS, b"derived")
            .expect("read reset row"),
        None
    );

    let summaries = store
        .replay_summary_table_hashes()
        .expect("hash replay summary tables");
    assert_eq!(summaries.len(), 2);
    assert_eq!(
        summaries
            .iter()
            .find(|summary| summary.table == REPLAY_PROTECTED_ROWS.as_str())
            .expect("protected summary")
            .count,
        1
    );
    assert_eq!(
        summaries
            .iter()
            .find(|summary| summary.table == REPLAY_RESET_ROWS.as_str())
            .expect("reset summary")
            .count,
        0
    );
}

#[test]
fn core_replay_preserves_only_retained_fact_store_and_resets_clock() {
    let store =
        Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open core store");
    let protected = store
        .replay_protected_tables()
        .iter()
        .map(|table| table.as_str())
        .collect::<Vec<_>>();
    assert_eq!(protected, vec!["facts", "local_fact_admissions"]);

    let reset = store
        .replay_reset_tables()
        .iter()
        .map(|table| table.as_str())
        .collect::<Vec<_>>();
    assert!(
        reset.contains(&"clock"),
        "store-local clock is local runtime metadata, not replay-preserved fact truth: {reset:?}"
    );
}

#[test]
fn replay_lifecycle_rejects_protected_reset_overlap() {
    const BAD_SCHEMA: SchemaSource = SchemaSource {
        ddl: r#"
CREATE TABLE IF NOT EXISTS replay_protected_rows (
    row_key BLOB PRIMARY KEY NOT NULL,
    row_value BLOB NOT NULL
);
"#,
        row_tables: &[REPLAY_PROTECTED_ROWS],
        row_schemas: &[],
        replay: ReplayTables {
            protected: &[REPLAY_PROTECTED_ROWS],
            reset: &[REPLAY_PROTECTED_ROWS],
            summary: &[],
        },
    };

    let err = match Store::open_memory_with_schema_sources(&[BAD_SCHEMA]) {
        Ok(_) => panic!("overlapping replay lifecycle declarations must reject"),
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("cannot be both replay-protected and replay-resettable"),
        "{err}"
    );
}

#[test]
fn typed_tables_reject_opaque_row_helpers() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("typed-row-store.db");
    let store =
        Store::open_disk_with_schema_sources(&path, &[TYPED_MESSAGES_SCHEMA]).expect("open store");
    let err = store
        .insert_table_rows(vec![TableRow {
            table: TYPED_MESSAGES,
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
fn row_helpers_require_row_table_allowlist() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("typed-key-value-store.db");
    let key_value_shape = SchemaSource {
        ddl: r#"
CREATE TABLE IF NOT EXISTS legacy_key_value_shape (
    row_key BLOB PRIMARY KEY NOT NULL,
    row_value BLOB NOT NULL
);
        "#,
        row_tables: &[],
        row_schemas: &[],
        replay: ReplayTables::EMPTY,
    };

    let store = Store::open_disk_with_schema_sources(&path, &[key_value_shape])
        .expect("key/value table block creates a typed table unless allowlisted");
    let err = store
        .insert_table_rows(vec![TableRow {
            table: TableName::new("legacy_key_value_shape"),
            key: b"k".to_vec(),
            value: b"v".to_vec(),
        }])
        .expect_err("non-allowlisted key/value table should reject row helper");

    assert!(err.to_string().contains("not an opaque row table"));
}

#[test]
fn schema_backed_row_tables_are_allowlisted_and_keep_declared_shape() {
    let store = Store::open_memory_with_schema_sources(&[SCHEMA_BACKED_ROWS_SCHEMA])
        .expect("open schema-backed row store");
    let row = SCHEMA_BACKED_ROW_SCHEMA
        .row(
            &[RowValue::Bytes(vec![1; 32])],
            &[RowValue::U64(9), RowValue::Bytes(vec![7, 8])],
        )
        .expect("schema row");

    assert_eq!(store.row_schemas(), &[SCHEMA_BACKED_ROW_SCHEMA]);
    assert_eq!(
        store.insert_table_rows(vec![row.clone()]).expect("insert"),
        1
    );

    let stored = store
        .table_row(SCHEMA_BACKED_ROWS, &row.key)
        .expect("read")
        .expect("stored row");
    assert_eq!(
        SCHEMA_BACKED_ROW_SCHEMA
            .decode_value(&stored)
            .expect("decode value"),
        vec![RowValue::U64(9), RowValue::Bytes(vec![7, 8])]
    );
}

#[test]
fn allowlisted_row_tables_keep_idempotent_conflict_checks() {
    let store =
        Store::open_memory_with_schema_sources(&[TEST_ROWS_SCHEMA]).expect("open memory store");
    let row = TableRow {
        table: TEST_ROWS,
        key: b"k".to_vec(),
        value: b"one".to_vec(),
    };

    assert_eq!(
        store.insert_table_rows(vec![row.clone()]).expect("insert"),
        1
    );
    assert_eq!(
        store
            .insert_table_rows(vec![row.clone()])
            .expect("idempotent insert"),
        0
    );

    let err = store
        .insert_table_rows(vec![TableRow {
            value: b"two".to_vec(),
            ..row
        }])
        .expect_err("conflicting insert must reject");

    assert!(err.to_string().contains("conflicting row for test_rows"));
}

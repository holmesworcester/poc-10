use std::collections::BTreeSet;

use rusqlite::{params, Connection};
use topo::core::db::{Db, ReplayTables, SchemaSource, TableInsert, TableName, Value};
use topo::core::schema::CORE_SCHEMA_SOURCE;
use topo::protocol::content::{file, reaction};
use topo::protocol::registry::FACTS_SCHEMA_SOURCE;
use topo::protocol::versioning::local_update::queries::state_summary_table_hashes;

const TYPED_MESSAGES: TableName = TableName::new("typed_messages");
const REPLAY_PROTECTED_ROWS: TableName = TableName::new("replay_protected_rows");
const REPLAY_RESET_ROWS: TableName = TableName::new("replay_reset_rows");
const LIFECYCLE_COLUMNS: &[&str] = &["id", "payload"];

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
    storage_version: None,
    replay: ReplayTables::EMPTY,
};

const REPLAY_LIFECYCLE_SCHEMA: SchemaSource = SchemaSource {
    ddl: r#"
CREATE TABLE IF NOT EXISTS replay_protected_rows (
    id BLOB PRIMARY KEY NOT NULL,
    payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS replay_reset_rows (
    id BLOB PRIMARY KEY NOT NULL,
    payload BLOB NOT NULL
);
"#,
    storage_version: None,
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

fn sqlite_index_names(path: &std::path::Path) -> BTreeSet<String> {
    let conn = Connection::open(path).expect("open sqlite");
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'index'")
        .expect("prepare index name query");
    stmt.query_map([], |row| row.get::<_, String>(0))
        .expect("query index names")
        .collect::<Result<BTreeSet<_>, _>>()
        .expect("collect index names")
}

#[test]
fn schema_sources_execute_declared_ddl() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("schema-db.db");
    let sources = checked_schema_sources();

    Db::open_disk_with_schema_sources(&path, &sources).expect("open db");
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

    Db::open_disk_with_schema_sources(&path, &sources).expect("reopen executes idempotent DDL");
}

#[test]
fn protocol_schema_indexes_sync_hot_paths() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("sync-index-schema.db");

    Db::open_disk_with_schema_sources(&path, &[FACTS_SCHEMA_SOURCE]).expect("open protocol schema");
    let actual = sqlite_index_names(&path);

    for expected in [
        "sync_shareable_fact_rows_by_fact",
        "sync_shareable_fact_rows_by_workspace_timestamp",
        "sync_negentropy_leaf_rows_by_workspace_timestamp",
    ] {
        assert!(actual.contains(expected), "missing sync index {expected}");
    }

    let conn = Connection::open(&path).expect("open sqlite");
    let shareable_by_fact_plan = query_plan_details(
        &conn,
        "EXPLAIN QUERY PLAN
         SELECT workspace_id, fact_id, timestamp_ms
         FROM sync_shareable_fact_rows
         WHERE fact_id = ?1
         ORDER BY workspace_id, fact_id
         LIMIT ?2",
        params![&[1u8; 32][..], 16_i64],
    );
    assert!(
        shareable_by_fact_plan.contains("sync_shareable_fact_rows_by_fact"),
        "fact-id shareable lookup should use sync index: {shareable_by_fact_plan}"
    );

    let leaf_range_plan = query_plan_details(
        &conn,
        "EXPLAIN QUERY PLAN
         SELECT workspace_id, owner_fact_id, timestamp_ms, contribution_fingerprint
         FROM sync_negentropy_leaf_rows
         WHERE workspace_id = ?1 AND timestamp_ms >= ?2 AND timestamp_ms <= ?3
         ORDER BY timestamp_ms, owner_fact_id
         LIMIT ?4",
        params![&[2u8; 32][..], 10_i64, 20_i64, 16_i64],
    );
    assert!(
        leaf_range_plan.contains("sync_negentropy_leaf_rows_by_workspace_timestamp"),
        "workspace timestamp leaf lookup should use sync index: {leaf_range_plan}"
    );
}

fn query_plan_details<P: rusqlite::Params>(conn: &Connection, sql: &str, params: P) -> String {
    let mut stmt = conn.prepare(sql).expect("prepare query plan");
    stmt.query_map(params, |row| row.get::<_, String>(3))
        .expect("query plan")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect query plan")
        .join("\n")
}

#[test]
fn core_local_intents_table_is_temp() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("schema-memory-store.db");
    let local_intents = TableName::new("local_intents");
    let local_intent_context = TableName::new("local_intent_context");

    let store = Db::open_disk_with_schema_sources(&path, &[CORE_SCHEMA_SOURCE])
        .expect("open db with core schema");
    assert_eq!(
        store
            .table_row_count(local_intents)
            .expect("count temp rows"),
        0
    );
    assert_eq!(
        store
            .table_row_count(local_intent_context)
            .expect("count local context rows"),
        0
    );
    assert!(
        !sqlite_table_names(&path).contains("local_intents"),
        "local_intents should not be durable"
    );
    assert!(
        !sqlite_table_names(&path).contains("local_intent_context"),
        "local_intent_context should not be durable"
    );

    let reopened = Db::open_disk_with_schema_sources(&path, &[CORE_SCHEMA_SOURCE])
        .expect("reopen db with core schema");
    assert_eq!(
        reopened
            .table_row_count(local_intents)
            .expect("count temp rows after reopen"),
        0
    );
    assert_eq!(
        reopened
            .table_row_count(local_intent_context)
            .expect("count local context rows after reopen"),
        0
    );
}

#[test]
fn core_incoming_tables_are_temp() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("incoming-facts-store.db");
    let incoming_facts = TableName::new("incoming_facts");
    let pending_incoming_projection = TableName::new("pending_incoming_projection");

    let store = Db::open_disk_with_schema_sources(&path, &[CORE_SCHEMA_SOURCE])
        .expect("open db with core schema");
    for table in [incoming_facts, pending_incoming_projection] {
        assert_eq!(
            store.table_row_count(table).expect("count temp rows"),
            0,
            "{} should be queryable on the live connection",
            table.as_str()
        );
        assert!(
            !sqlite_table_names(&path).contains(table.as_str()),
            "{} should not be durable",
            table.as_str()
        );
    }

    let reopened = Db::open_disk_with_schema_sources(&path, &[CORE_SCHEMA_SOURCE])
        .expect("reopen db with core schema");
    for table in [incoming_facts, pending_incoming_projection] {
        assert_eq!(
            reopened
                .table_row_count(table)
                .expect("count temp rows after reopen"),
            0,
            "{} should reopen empty",
            table.as_str()
        );
    }
}

#[test]
fn schema_sources_create_typed_tables_and_indexes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("typed-schema-db.db");

    Db::open_disk_with_schema_sources(&path, &[TYPED_MESSAGES_SCHEMA]).expect("create typed table");
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

    Db::open_disk_with_schema_sources(&path, &[TYPED_MESSAGES_SCHEMA])
        .expect("reopen keeps explicit DDL idempotent");
}

#[test]
fn content_read_model_rows_materialize_into_typed_tables() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("content-read-models.db");
    Db::open_disk_with_schema_sources(&path, &[FACTS_SCHEMA_SOURCE])
        .expect("open content schema db");
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
fn rebuild_lifecycle_declares_protected_reset_and_summary_tables() {
    let store =
        Db::open_memory_with_schema_sources(&[REPLAY_LIFECYCLE_SCHEMA]).expect("open lifecycle db");
    store
        .insert_table_values(vec![
            TableInsert {
                table: REPLAY_PROTECTED_ROWS,
                columns: LIFECYCLE_COLUMNS,
                values: vec![
                    Value::Bytes(b"protected".to_vec()),
                    Value::Bytes(b"kept".to_vec()),
                ],
            },
            TableInsert {
                table: REPLAY_RESET_ROWS,
                columns: LIFECYCLE_COLUMNS,
                values: vec![
                    Value::Bytes(b"derived".to_vec()),
                    Value::Bytes(b"cleared".to_vec()),
                ],
            },
        ])
        .expect("seed lifecycle rows");

    let protected = store
        .replay_protected_tables()
        .iter()
        .map(|table| table.as_str())
        .collect::<Vec<_>>();
    assert_eq!(protected, vec![REPLAY_PROTECTED_ROWS.as_str()]);
    let reset = store
        .replay_reset_tables()
        .iter()
        .map(|table| table.as_str())
        .collect::<Vec<_>>();
    assert_eq!(reset, vec![REPLAY_RESET_ROWS.as_str()]);

    assert_eq!(
        store
            .table_row_count(REPLAY_PROTECTED_ROWS)
            .expect("count protected rows"),
        1
    );

    let summaries = state_summary_table_hashes(&store).expect("hash state summary tables");
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
        1
    );
}

#[test]
fn core_replay_preserves_only_retained_facts_and_resets_runtime_tables() {
    let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open core db");
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
        !reset.contains(&"clock"),
        "removed local time table must stay absent: {reset:?}"
    );
}

#[test]
fn replay_lifecycle_rejects_protected_reset_overlap() {
    const BAD_SCHEMA: SchemaSource = SchemaSource {
        ddl: r#"
CREATE TABLE IF NOT EXISTS replay_protected_rows (
    id BLOB PRIMARY KEY NOT NULL,
    payload BLOB NOT NULL
);
"#,
        storage_version: None,
        replay: ReplayTables {
            protected: &[REPLAY_PROTECTED_ROWS],
            reset: &[REPLAY_PROTECTED_ROWS],
            summary: &[],
        },
    };

    let err = match Db::open_memory_with_schema_sources(&[BAD_SCHEMA]) {
        Ok(_) => panic!("overlapping rebuild lifecycle declarations must reject"),
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("cannot be both replay-protected and replay-resettable"),
        "{err}"
    );
}

#[test]
fn typed_table_values_keep_idempotent_conflict_checks() {
    const COLUMNS: &[&str] = &["workspace_id", "message_id", "created_at_ms", "deleted"];
    let store =
        Db::open_memory_with_schema_sources(&[TYPED_MESSAGES_SCHEMA]).expect("open memory db");
    let row = TableInsert {
        table: TYPED_MESSAGES,
        columns: COLUMNS,
        values: vec![
            Value::Bytes(vec![1; 32]),
            Value::Bytes(vec![2; 32]),
            Value::U64(9),
            Value::Bool(false),
        ],
    };

    assert_eq!(
        store
            .insert_table_values(vec![row.clone()])
            .expect("insert"),
        1
    );
    assert_eq!(
        store
            .insert_table_values(vec![row.clone()])
            .expect("idempotent insert"),
        0
    );

    let err = store
        .insert_table_values(vec![TableInsert {
            values: vec![
                Value::Bytes(vec![1; 32]),
                Value::Bytes(vec![2; 32]),
                Value::U64(10),
                Value::Bool(false),
            ],
            ..row
        }])
        .expect_err("conflicting insert must reject");

    assert!(err
        .to_string()
        .contains("conflicting row for typed_messages"));
}

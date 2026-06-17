# DB, Schema, And SQL Ownership

This note records the simplified runtime storage split. The runtime should not
hide SQLite behind a broad store abstraction. SQLite is the query engine, and
the module that owns a table should own the SQL for that table's behavior.

The target is a smaller codebase:

- `core/schema.rs` owns schema declarations and validation metadata.
- `core/db.rs` owns the live SQLite connection and transaction mechanics.
- `core/project_fact.rs` owns projection commit SQL.
- `core/handle_intent.rs` owns intent queue SQL.
- `core/network.rs` owns network queue SQL.
- `core/replay.rs` owns replay wipe, enqueue, and summary SQL.
- Protocol fact-family roots own projected table declarations and row builders.
- Protocol `queries.rs` modules own bounded SQL reads over projected rows.

Projectors remain pure. They do not execute SQL. They emit row mutations, facts,
intents, context, and time wakes; `project_fact` commits that output atomically.

## Remove The Persistent Clock

Command time is frontend/operator input, not protocol truth. Runtime authoring
uses system time by default, and deterministic CLI tests pass time explicitly,
for example:

```text
con --at 5000 message send WORKSPACE_ID "first"
con --at 5100 message send WORKSPACE_ID "second"
```

Status/report paths that need "now" receive it from the CLI/app boundary or
omit it when no explicit value is supplied.

## `schema.rs`

`schema.rs` is declarative. It describes tables, schema sources, replay
classifications, and row validation metadata. It should not own live database
execution.

It owns:

- core table names
- core `CREATE TABLE` and index SQL
- `SchemaSource`
- `SchemaRegistry`
- replay-retained and replay-reset table sets
- table-name validation and quoting
- table and column metadata used to validate protocol row mutations

Representative shape:

```rust
pub struct SchemaSource {
    pub owner: &'static str,
    pub sql: &'static str,
    pub projected_tables: &'static [ProjectedTableSchema],
    pub replay_tables: ReplayTables,
}

pub struct SchemaRegistry {
    sources: Vec<SchemaSource>,
    projected_tables: BTreeMap<TableName, ProjectedTableSchema>,
    replay_retained: BTreeSet<TableName>,
    replay_reset: BTreeSet<TableName>,
}

impl SchemaRegistry {
    pub fn validate_table(&self, table: TableName) -> Result<(), SchemaError>;
    pub fn validate_mutation(&self, mutation: &RowMutation) -> Result<(), SchemaError>;
    pub fn quoted_table(&self, table: TableName) -> Result<String, SchemaError>;
    pub fn quoted_column(&self, table: TableName, column: &str) -> Result<String, SchemaError>;
    pub fn replay_reset_tables(&self) -> impl Iterator<Item = TableName>;
}
```

Core schema stays here:

```sql
CREATE TABLE IF NOT EXISTS facts (
    id BLOB PRIMARY KEY NOT NULL,
    bytes BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS local_fact_admissions (
    fact_id BLOB PRIMARY KEY NOT NULL,
    scope TEXT NOT NULL,
    scope_kind TEXT NOT NULL,
    scope_id BLOB NOT NULL,
    received_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS context_edges (
    owner BLOB NOT NULL,
    direction TEXT NOT NULL,
    role TEXT NOT NULL,
    scope_key BLOB NOT NULL,
    start_key BLOB NOT NULL,
    end_key BLOB NOT NULL,
    PRIMARY KEY (owner, direction, role, scope_key, start_key, end_key)
);

CREATE TABLE IF NOT EXISTS pending_projection (
    owner BLOB PRIMARY KEY NOT NULL,
    mode TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS intents (
    kind TEXT NOT NULL,
    idempotence_key BLOB NOT NULL,
    payload BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    claimed_at INTEGER,
    PRIMARY KEY (kind, idempotence_key)
);
```

Protocol fact-family schema stays with the family. Prefer explicit SQL columns
over opaque `row_key`/`row_value` packing:

```rust
// protocol/auth/recipient_key.rs
pub const RECIPIENT_KEY_ROWS: TableName = TableName::new("recipient_key_rows");

pub const RECIPIENT_KEY_SCHEMA: ProjectedTableSchema = ProjectedTableSchema {
    table: RECIPIENT_KEY_ROWS,
    columns: &[
        Column::blob("workspace_id"),
        Column::blob("recipient_key_id"),
        Column::blob("endpoint_id"),
        Column::blob("recipient_key"),
        Column::blob("previous_recipient_key_id"),
        Column::integer("created_at_ms"),
        Column::blob("signer_public_key"),
    ],
    primary_key: &["workspace_id", "recipient_key_id"],
    indexes: &[
        Index::new(
            "recipient_key_by_workspace_created",
            &["workspace_id", "created_at_ms", "recipient_key_id"],
        ),
    ],
};
```

## `context.rs`

`context.rs` should stay. It is not a store abstraction; it is the pure
dependency vocabulary that projectors use to describe what they need and what
they offer.

It owns:

- `Role`
- `ContextKey`
- `ContextNeed`
- `ContextOffer`
- `ContextSet`
- pure key construction helpers
- pure context-set diff helpers, if keeping them here remains clearer

It should not own SQL. The SQL tables, overlap queries, wake rows, and pending
match commits belong in `project_fact.rs`.

Projectors should still emit context like this:

```rust
ProjectionOutput::new()
    .need(ContextNeed::for_key_parts(
        fact.id,
        "recipient_key",
        FactScope::Scoped {
            kind: "workspace".into(),
            id: workspace_id,
        },
        [&recipient_key_id],
    )?)
```

`project_fact` then stores that pure context edge:

```sql
INSERT OR IGNORE INTO context_edges
    (owner, direction, role, scope_key, start_key, end_key)
VALUES
    (?1, 'need', ?2, ?3, ?4, ?5);
```

The simplification is not to delete context. The simplification is to keep
context as plain typed data and keep all matching SQL in `project_fact`.

## `row_schema.rs`

The simplest target is to eliminate `row_schema.rs`.

`row_schema.rs` currently exists to encode and decode opaque protocol row
tables shaped like:

```sql
CREATE TABLE some_family_rows (
    row_key BLOB PRIMARY KEY NOT NULL,
    row_value BLOB NOT NULL
);
```

Keeping that shape forces every useful query to decode blobs or to duplicate
index tables. Since protocol `queries.rs` should use full SQL, projected tables
should instead use explicit SQL columns. Then SQLite can filter, order, join,
count, and page directly on the stored columns.

The preferred migration is:

1. Give every projected fact-family table explicit SQL columns.
2. Replace `RowTableSchema` constants with lightweight `ProjectedTableSchema`
   declarations in the fact-family root.
3. Replace `TableRow { key, value }` mutations with typed insert/delete
   mutations that name columns.
4. Move any remaining validation metadata into `schema.rs`.
5. Delete `row_schema.rs`.

The old opaque mutation shape should disappear:

```rust
RowMutation::Put(TableRow {
    table: RECIPIENT_KEY_ROWS,
    key: recipient_key_key(workspace_id, recipient_key_id)?,
    value: recipient_key_value(&recipient)?,
})
```

Use typed table mutations instead:

```rust
RowMutation::Insert {
    table: RECIPIENT_KEY_ROWS,
    columns: &[
        "workspace_id",
        "recipient_key_id",
        "endpoint_id",
        "recipient_key",
        "previous_recipient_key_id",
        "created_at_ms",
        "signer_public_key",
    ],
    values: vec![
        SqlValue::Blob(workspace_id.to_vec()),
        SqlValue::Blob(recipient_key_id.to_vec()),
        SqlValue::Blob(recipient.endpoint_id.to_vec()),
        SqlValue::Blob(recipient.recipient_key.to_vec()),
        SqlValue::Blob(recipient.previous_recipient_key_id.to_vec()),
        SqlValue::U64(recipient.created_at_ms),
        SqlValue::Blob(recipient.signer_public_key.to_vec()),
    ],
}
```

`project_fact` commits typed mutations directly:

```sql
INSERT OR REPLACE INTO recipient_key_rows
    (workspace_id, recipient_key_id, endpoint_id, recipient_key,
     previous_recipient_key_id, created_at_ms, signer_public_key)
VALUES
    (?1, ?2, ?3, ?4, ?5, ?6, ?7);
```

Typed tables are probably simpler if queries use full SQL, because query SQL can
filter, order, join, and count on named columns without decoding row blobs.
That makes `row_schema.rs` a migration aid to remove, not a permanent
architecture component.

## `db.rs`

`db.rs` is the small runtime database type. It replaces the broad `store.rs`
API with connection ownership and guardrails.

It owns:

- opening disk and memory databases
- applying schema sources
- exposing `conn()` for read SQL
- running write transactions
- validating typed row mutations through `SchemaRegistry`
- exact fact reads
- bounded fact batch reads

It should not own protocol queries, protocol row construction, intent queue
policy, network queue policy, projection commit ordering, or replay behavior.

Representative shape:

```rust
pub struct Db {
    conn: rusqlite::Connection,
    schema: SchemaRegistry,
}

impl Db {
    pub fn open(path: &Path, sources: &[SchemaSource]) -> Result<Self, DbError>;
    pub fn open_memory(sources: &[SchemaSource]) -> Result<Self, DbError>;

    pub fn conn(&self) -> &rusqlite::Connection {
        &self.conn
    }

    pub fn tx<T>(
        &self,
        f: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T, DbError>,
    ) -> Result<T, DbError>;

    pub fn validate_mutation(&self, mutation: &RowMutation) -> Result<(), DbError> {
        self.schema.validate_mutation(mutation).map_err(DbError::Schema)
    }

    pub fn quoted_table(&self, table: TableName) -> Result<String, DbError> {
        self.schema.quoted_table(table).map_err(DbError::Schema)
    }

    pub fn quoted_column(&self, table: TableName, column: &str) -> Result<String, DbError> {
        self.schema.quoted_column(table, column).map_err(DbError::Schema)
    }

    pub fn fact_by_id(&self, id: FactId) -> Result<Option<Fact>, DbError>;

    pub fn facts_by_ids(
        &self,
        ids: &[FactId],
        limit: NonZeroUsize,
    ) -> Result<Vec<Fact>, DbError>;
}
```

Bounded fact batch reads are the only shared helper that should load fact
bytes. Sync and network send paths should select fact ids first, then call this
helper with an explicit limit.

```sql
SELECT f.id, m.scope, m.scope_kind, m.scope_id, m.received_at, f.bytes
FROM facts f
JOIN local_fact_admissions m ON m.fact_id = f.id
WHERE f.id IN (?1, ?2, ?3)
ORDER BY m.received_at, f.id
LIMIT ?4;
```

## `project_fact.rs`

`project_fact` owns the projection write transaction. It is acceptable for this
module to use direct SQL because it owns the commit order and the core tables it
updates.

Representative commit:

```rust
fn commit_projection(
    db: &Db,
    item: PendingFact,
    output: ProjectedOutput,
    allowed_tables: &[TableName],
) -> Result<(), Error> {
    db.tx(|tx| {
        retain_or_drop_fact(tx, &item, &output)?;
        replace_context(tx, item.fact_id, &output.context)?;
        replace_time_wakes(tx, item.fact_id, &output.time_wakes)?;
        apply_row_mutations(db, tx, output.row_mutations, allowed_tables)?;
        enqueue_emitted_facts(tx, output.effects.facts)?;
        enqueue_incoming_facts(tx, output.effects.incoming_facts)?;
        enqueue_intents(tx, output.effects.intents)?;
        enqueue_local_intents(tx, output.effects.local_intents)?;
        complete_projection(tx, item.source, item.fact_id)?;
        Ok(())
    })
}
```

Fact retention:

```sql
INSERT OR IGNORE INTO facts (id, bytes)
VALUES (?1, ?2);

INSERT OR IGNORE INTO local_fact_admissions
    (fact_id, scope, scope_kind, scope_id, received_at)
VALUES
    (?1, ?2, ?3, ?4, ?5);
```

Context replacement:

```sql
DELETE FROM context_edges
WHERE owner = ?1;

INSERT OR IGNORE INTO context_edges
    (owner, direction, role, scope_key, start_key, end_key)
VALUES
    (?1, ?2, ?3, ?4, ?5, ?6);
```

Time-wake replacement:

```sql
DELETE FROM time_wakes
WHERE owner = ?1;

INSERT OR IGNORE INTO time_wakes (timeline, at, owner)
VALUES (?1, ?2, ?3);
```

Protocol row mutation commit:

```rust
fn apply_row_mutations(
    db: &Db,
    tx: &rusqlite::Transaction<'_>,
    mutations: impl IntoIterator<Item = RowMutation>,
    allowed_tables: &[TableName],
) -> Result<(), Error> {
    for mutation in mutations {
        db.validate_mutation(&mutation)?;
        match mutation {
            RowMutation::Insert(insert) => {
                require_allowed(insert.table, allowed_tables)?;
                let table = db.quoted_table(insert.table)?;
                let columns = insert
                    .columns
                    .iter()
                    .map(|column| db.quoted_column(insert.table, column))
                    .collect::<Result<Vec<_>, _>>()?;
                let placeholders = placeholders(insert.values.len());
                tx.execute(
                    &format!(
                        "INSERT OR REPLACE INTO {table} ({})
                         VALUES ({placeholders})",
                        columns.join(", ")
                    ),
                    params_from_values(&insert.values),
                )?;
            }
            RowMutation::DeleteWhere(delete) => {
                require_allowed(delete.table, allowed_tables)?;
                let table = db.quoted_table(delete.table)?;
                let predicate = checked_predicate(db, delete.table, &delete.predicate)?;
                tx.execute(
                    &format!("DELETE FROM {table} WHERE {predicate}"),
                    params_from_values(&delete.values),
                )?;
            }
        }
    }
    Ok(())
}
```

For a recipient key row, the committed SQL is ordinary table SQL:

```sql
INSERT OR REPLACE INTO recipient_key_rows
    (workspace_id, recipient_key_id, endpoint_id, recipient_key,
     previous_recipient_key_id, created_at_ms, signer_public_key)
VALUES
    (?1, ?2, ?3, ?4, ?5, ?6, ?7);

DELETE FROM recipient_key_rows
WHERE workspace_id = ?1
  AND recipient_key_id = ?2;
```

Projection completion:

```sql
DELETE FROM incoming_facts
WHERE id = ?1;

DELETE FROM pending_projection
WHERE owner = ?1;

DELETE FROM pending_projection_matches
WHERE owner = ?1 OR offer_owner = ?1;

DELETE FROM pending_time_ranges
WHERE owner = ?1;
```

## `handle_intent.rs`

`handle_intent` owns intent queue lifecycle. Direct SQL here is clearer than a
generic queue abstraction because the module owns claim, completion, rotation,
and dispatch ordering.

Claim one intent:

```sql
SELECT kind, idempotence_key, payload
FROM intents
ORDER BY
    claimed_at IS NOT NULL,
    created_at,
    kind,
    idempotence_key
LIMIT 1;
```

Mark it claimed:

```sql
UPDATE intents
SET claimed_at = ?3
WHERE kind = ?1
  AND idempotence_key = ?2;
```

Complete it after handler output commits:

```sql
DELETE FROM intents
WHERE kind = ?1
  AND idempotence_key = ?2;
```

Insert follow-up work:

```sql
INSERT OR IGNORE INTO intents
    (kind, idempotence_key, payload, created_at, claimed_at)
VALUES
    (?1, ?2, ?3, ?4, NULL);
```

Local intents use the same SQL shape against `local_intents`. They remain
connection-local or process-local operational work, not durable protocol truth.

## `network.rs`

`network.rs` owns network queue SQL. These tables are core-owned operational
queues, so direct SQL belongs with the queue policy.

Enqueue frame and target index:

```sql
INSERT OR IGNORE INTO network_outgoing (row_key, row_value)
VALUES (?1, ?2);

INSERT OR IGNORE INTO network_outgoing_targets (row_key, row_value)
VALUES (?1, ?2);
```

Claim a bounded batch for one target:

```sql
SELECT row_key, row_value
FROM network_outgoing
WHERE row_key >= ?1
  AND row_key < ?2
ORDER BY row_key
LIMIT ?3;
```

Delete sent rows:

```sql
DELETE FROM network_outgoing
WHERE row_key = ?1;
```

Prune a target when no queued rows remain:

```sql
SELECT 1
FROM network_outgoing
WHERE row_key >= ?1
  AND row_key < ?2
LIMIT 1;

DELETE FROM network_outgoing_targets
WHERE row_key = ?3;
```

## `replay.rs`

Replay owns derived-state reset, replay enqueue, and projection/intent driving.
It should call `project_fact` and `handle_intent` for normal work, and use
direct SQL only for replay-specific setup. Replay does not need to own state
summary hashing as part of its primary operation.

Wipe replay-reset tables from the schema registry:

```rust
fn wipe_replay_state(db: &Db) -> Result<usize, Error> {
    db.tx(|tx| {
        let mut cleared = 0;
        for table in db.schema().replay_reset_tables() {
            let table = db.quoted_table(table)?;
            cleared += tx.execute(&format!("DELETE FROM {table}"), [])?;
        }
        Ok(cleared)
    })
}
```

Canonical replay enqueue:

```sql
INSERT OR IGNORE INTO pending_projection (owner, mode)
SELECT id, 'replay'
FROM facts;
```

Replay should return basic counters and assert that replay did not produce
forbidden live output, such as network rows. Full-state hashing belongs in a
separate diagnostic/test module.

## `replay_check.rs`

`replay_check.rs` owns replay diagnostics. It may run replay in multiple orders
and hash selected tables after each run to prove replay determinism. This keeps
whole-table summary scans out of replay's primary rebuild path.

Ordered replay diagnostics:

```sql
SELECT f.id
FROM facts f
JOIN local_fact_admissions a ON a.fact_id = f.id
ORDER BY a.received_at, f.id;
```

`replay_check.rs` can maintain its own diagnostic table list or accept one from
the CLI/test harness. That list does not need to be first-class core schema
metadata unless production code needs it, which it should not.

Diagnostic summary scans are allowed here because they are explicitly
debug/test behavior and do not become general query APIs. Keep these scans out
of `db.rs`; if a small shared row-hashing helper is useful, put it in a narrow
module such as `db_helpers.rs`, or in `db_test_helpers.rs` when only tests use
it.

```sql
SELECT col_a, col_b, col_c
FROM some_diagnostic_table
ORDER BY col_a, col_b, col_c;
```

The diagnostic should stream rows through a hasher, not materialize the table:

```rust
let mut rows = stmt.query([])?;
while let Some(row) = rows.next()? {
    hash_row(&mut hasher, row)?;
}
```

## Protocol Queries

Protocol `queries.rs` modules may use full SQL. They are not pure functions.
They must be bounded, indexed, and semantic.

Good query:

```rust
pub fn latest_local_key_secret(
    db: &Db,
    workspace_id: FactId,
) -> Result<Option<LocalKeySecretRow>, Error> {
    let mut stmt = db.conn().prepare(
        "SELECT workspace_id, frontier_id, secret_fact_id, owner_endpoint_id,
                created_at_ms, key_secret
         FROM local_key_secret_rows
         WHERE workspace_id = ?1
         ORDER BY created_at_ms DESC, frontier_id DESC
         LIMIT 1",
    )?;
    stmt.query_row(params![workspace_id], decode_local_key_secret_row)
        .optional()
}
```

Good page:

```sql
SELECT message_id, created_at_ms, author_user_id, signer_id, text
FROM opened_message_rows
WHERE workspace_id = ?1
  AND (created_at_ms, message_id) > (?2, ?3)
ORDER BY created_at_ms, message_id
LIMIT ?4;
```

Good count:

```sql
SELECT COUNT(*)
FROM content_messages
WHERE workspace_id = ?1
  AND deleted = 0;
```

Bad query shapes:

- `SELECT ... FROM facts` followed by Rust decoding to find semantic data
- `SELECT row_key, row_value FROM some_table ORDER BY row_key` in production
  query code
- loading rows and taking `.len()` instead of `COUNT(*)`
- loading a whole workspace when a page is needed
- using `usize::MAX` to mean "unbounded"

## Net Effect

This split removes the broad `store.rs` surface. It keeps SQLite visible where
it matters, keeps projectors pure, keeps table semantics near their owners, and
reduces LOC by deleting generic wrappers that only forward to one SQL statement.

The only general read helpers left in `db.rs` should be exact or explicitly
bounded fact reads. Everything else is owner-module SQL.

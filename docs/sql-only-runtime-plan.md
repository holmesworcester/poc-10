# SQL-Only Runtime Plan

This plan moves the runtime toward a simple SQLite-centered model: protocol
facts remain durable opaque bytes, protocol projectors materialize queryable
meaning into declared SQLite rows, and runtime code only keeps bounded
operation-local state in Rust. SQLite is the query engine. Rust authors facts,
projects rows, coordinates atomic commits, and renders bounded CLI results.

The target model deliberately avoids an ORM. The runtime stores binary fact
ids, binary row keys, deterministic row values, context edges, time wakes, and
work queues. Explicit SQL and schema-aware store primitives keep ordering,
limits, transaction boundaries, and byte layouts visible.

## Target Invariants

1. Production code does not load all facts into Rust memory.
2. Production code does not load all rows from a projected table into Rust
   memory.
3. Every queryable fact family owns a projected table, a row schema, pure row
   construction helpers, and typed query helpers.
4. Projectors stay pure. They decode and validate one fact plus supplied
   context, then return `ProjectionOutput`.
5. `core::project_fact` is the projection transaction coordinator. It commits
   projector output through store primitives.
6. `core::store` owns SQLite mechanics, schema registration, table validation,
   bounded reads, exact reads, counts, and transaction helpers.
7. Protocol query modules own semantic predicates and typed decoding over their
   projected tables.
8. Runtime handlers use DB-backed state for durable protocol indexes, including
   sync and negentropy. Handler-local Rust state is bounded to one operation.
9. CLI commands page user-facing lists and may hold only the visible page or
   selected object.
10. Tests do not rely on broad fact or table scans. Most tests are pure
    author/projector tests or black-box CLI tests.

## Layer Boundaries

### Store

`src/core/store.rs` owns generic storage mechanics only:

- opening SQLite with a protocol-provided schema registry
- creating declared row tables and indexes
- validating row mutations against registered schemas
- exact fact reads and bounded fact batch reads
- exact row reads
- bounded prefix/range/page row reads
- SQL counts and existence checks
- write transactions and transaction-local write primitives

`store.rs` must not own protocol meaning. It should not know what a local key
secret, content message, recipient key, workspace, or sync fact means.

### Project Fact

`src/core/project_fact.rs` owns projection lifecycle and commit ordering:

- load one pending fact or bounded pending batch
- assemble the `ProjectionContext`
- call the protocol projector
- commit fact retention, incoming deletion, context replacement, time wakes,
  row mutations, emitted facts, emitted incoming facts, intents, local intents,
  and queue deletion in one transaction

`project_fact.rs` should call high-level store primitives instead of embedding
raw SQL for common writes.

### Protocol Fact Families

Each fact family owns:

- `fact.rs` for the typed fact
- `encode.rs` for canonical bytes
- `project.rs` for projector-local decode/authenticate/adapt and pure
  projection
- `queries.rs` for typed SQL reads over projected rows
- local row helpers and table schema declarations

The family declares queryable rows beside the family that owns the meaning.
Core consumes those declarations through runtime schema registration.

### Handlers

Handlers own bounded stateful work. They may query store-backed state, but they
must not materialize unbounded fact sets or table sets. Durable sync state,
including negentropy nodes and leaves, belongs in projected SQLite rows rather
than handler memory.

## Store API Shape

The final store API should make the wrong operation unavailable to production
code. Representative primitives:

```rust
impl Store {
    pub fn open_disk_with_schema_sources(
        path: impl AsRef<Path>,
        sources: &[SchemaSource],
    ) -> Result<Self, StoreError>;

    pub fn read_transaction<T>(
        &self,
        f: impl FnOnce(&ReadStore<'_>) -> Result<T, StoreError>,
    ) -> Result<T, StoreError>;

    pub fn write_transaction<T>(
        &self,
        f: impl FnOnce(&mut WriteStore<'_>) -> Result<T, StoreError>,
    ) -> Result<T, StoreError>;

    pub fn fact_count(&self) -> Result<usize, StoreError>;
    pub fn fact_by_id(&self, id: &FactId) -> Result<Option<Fact>, StoreError>;
    pub fn facts_by_ids(
        &self,
        ids: &[FactId],
        limit: usize,
    ) -> Result<Vec<Fact>, StoreError>;

    pub fn row(
        &self,
        table: TableName,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, StoreError>;

    pub fn row_count(&self, table: TableName) -> Result<usize, StoreError>;

    pub fn rows_by_prefix(
        &self,
        table: TableName,
        prefix: &[u8],
        after_key: Option<&[u8]>,
        limit: NonZeroUsize,
    ) -> Result<Vec<KeyValueRow>, StoreError>;

    pub fn query_one<T>(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
        decode: impl FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    ) -> Result<Option<T>, StoreError>;

    pub fn query_page<T>(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
        limit: NonZeroUsize,
        decode: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    ) -> Result<Vec<T>, StoreError>;
}

impl WriteStore<'_> {
    pub fn insert_retained_fact(&mut self, fact: &Fact) -> Result<bool, StoreError>;
    pub fn insert_incoming_fact(&mut self, fact: &Fact) -> Result<bool, StoreError>;
    pub fn delete_incoming_fact(&mut self, id: &FactId) -> Result<(), StoreError>;
    pub fn purge_fact(&mut self, id: &FactId) -> Result<(), StoreError>;

    pub fn put_row(&mut self, row: TableRow) -> Result<(), StoreError>;
    pub fn delete_row(&mut self, table: TableName, key: &[u8]) -> Result<(), StoreError>;
    pub fn apply_row_mutations(
        &mut self,
        mutations: impl IntoIterator<Item = RowMutation>,
        allowed_tables: &[TableName],
    ) -> Result<(), StoreError>;

    pub fn replace_context(
        &mut self,
        owner: FactId,
        context: &ContextSet,
    ) -> Result<(), StoreError>;

    pub fn replace_time_wakes(
        &mut self,
        owner: FactId,
        wakes: &[TimeWake],
    ) -> Result<(), StoreError>;

    pub fn queue_projection(
        &mut self,
        fact_id: FactId,
        mode: ProjectionMode,
    ) -> Result<(), StoreError>;

    pub fn complete_projection(
        &mut self,
        fact_id: FactId,
        source: ProjectionSource,
    ) -> Result<(), StoreError>;

    pub fn insert_intent(&mut self, intent: &Intent) -> Result<(), StoreError>;
    pub fn insert_local_intent(&mut self, intent: &Intent) -> Result<(), StoreError>;
}
```

The API should not include a production `table_rows(table)` method. Bounded
prefix/page helpers are acceptable because the caller must state a key range and
limit. Tests should use the same constrained API surface.

## Schema Registration

Protocol modules describe tables declaratively. Core validates and creates
those tables without importing protocol meaning.

```rust
pub struct TableSchema {
    pub name: TableName,
    pub key: RowTableKeySchema,
    pub value: RowTableValueSchema,
    pub indexes: &'static [IndexSchema],
}

pub struct SchemaSource {
    pub owner: &'static str,
    pub tables: &'static [TableSchema],
}

pub struct RuntimeDescription {
    pub schema_sources: &'static [SchemaSource],
    pub projector: fn() -> Box<dyn Projector>,
    pub handlers: &'static [HandlerDescription],
}
```

A fact family schema stays local to the owning family:

```rust
pub const LOCAL_KEY_SECRET_ROWS: TableName = TableName::new("local_key_secret_rows");

pub const LOCAL_KEY_SECRET_SCHEMA: TableSchema = TableSchema {
    name: LOCAL_KEY_SECRET_ROWS,
    key: row_key_schema![
        bytes32("workspace_id"),
        bytes32("frontier_id"),
    ],
    value: row_value_schema![
        bytes32("secret_fact_id"),
        bytes32("owner_endpoint_id"),
        u64("created_at_ms"),
        bytes32("key_secret"),
    ],
    indexes: &[
        index_schema!(
            "local_key_secret_by_workspace_created",
            ["workspace_id", "created_at_ms", "frontier_id"]
        ),
    ],
};
```

The owning projector emits rows through local helpers:

```rust
pub fn local_key_secret_row(fact_id: FactId, fact: &LocalKeySecretFact) -> TableRow {
    TableRow {
        table: LOCAL_KEY_SECRET_ROWS,
        key: LOCAL_KEY_SECRET_SCHEMA.encode_key(&[
            RowValue::Bytes32(fact.workspace_id),
            RowValue::Bytes32(fact.frontier_id),
        ]),
        value: LOCAL_KEY_SECRET_SCHEMA.encode_value(&[
            RowValue::Bytes32(fact_id),
            RowValue::Bytes32(fact.owner_endpoint_id),
            RowValue::U64(fact.created_at_ms),
            RowValue::Bytes32(fact.key_secret),
        ]),
    }
}
```

The owning query module decodes the same row shape:

```rust
pub fn latest_for_workspace(
    store: &Store,
    workspace_id: FactId,
) -> Result<Option<LocalKeySecretRow>, String> {
    store.query_one(
        "SELECT row_key, row_value
         FROM local_key_secret_rows
         WHERE workspace_id = ?1
         ORDER BY created_at_ms DESC, frontier_id DESC
         LIMIT 1",
        params![workspace_id],
        decode_local_key_secret_row,
    )
}
```

## Projection Commit Flow

`project_fact` should become a readable orchestration layer:

```rust
fn commit_projected_output(
    store: &Store,
    item: PendingFact,
    output: ProjectedOutput,
    allowed_tables: &[TableName],
) -> Result<(), String> {
    store.write_transaction(|tx| {
        match item.source {
            ProjectionSource::Durable => {
                if output.retain_self {
                    tx.insert_retained_fact(&item.fact)?;
                } else {
                    tx.purge_fact(&item.fact_id)?;
                }
            }
            ProjectionSource::Incoming => {
                if output.retain_self {
                    tx.insert_retained_fact(&item.fact)?;
                }
                tx.delete_incoming_fact(&item.fact_id)?;
            }
        }

        tx.replace_context(item.fact_id, &output.context)?;
        tx.replace_time_wakes(item.fact_id, &output.time_wakes)?;
        tx.apply_row_mutations(output.runtime_effects.row_mutations, allowed_tables)?;

        for fact in output.runtime_effects.facts {
            if tx.insert_retained_fact(&fact)? {
                tx.queue_projection(fact.id, ProjectionMode::Normal)?;
            }
        }

        for fact in output.runtime_effects.incoming_facts {
            tx.insert_incoming_fact(&fact)?;
        }

        for id in output.runtime_effects.purged_facts {
            tx.purge_fact(&id)?;
        }

        for intent in output.runtime_effects.intents {
            tx.insert_intent(&intent)?;
        }

        for intent in output.runtime_effects.local_intents {
            tx.insert_local_intent(&intent)?;
        }

        tx.complete_projection(item.fact_id, item.source)?;
        Ok(())
    })
}
```

The exact method names can differ. The important boundary is that projection
commit SQL lives behind store primitives, while projection ordering remains in
`project_fact`.

## Query Model

Each query should be one of these shapes:

- exact by key
- bounded page by key prefix and cursor
- bounded time range
- `COUNT(*)`
- `EXISTS`
- bounded fact-id batch followed by exact fact byte load

The following shapes are not allowed in production code or tests:

- load every retained fact and decode until one matches
- load every row from a projected table and filter in Rust
- use `usize::MAX` to mean "no limit"
- count by loading rows and taking `.len()`
- build a long-lived in-memory read model that duplicates SQLite state

## Sync And Negentropy

Sync should use DB-backed negentropy state. Shareable facts, leaves, context
dependencies, and node summaries are projected rows. Handlers query these rows
with connection, workspace, time, and range predicates.

The handler path should look like:

1. Decode the compare/range request.
2. Query authorized workspaces for the connection.
3. Query the negentropy summary for the requested range.
4. If summaries match, emit no work.
5. If facts must be sent, query bounded fact ids for the connection and range.
6. Expand context dependencies using indexed context-have rows and bounded
   queues.
7. Load final fact bytes by bounded id batch.
8. Emit a send intent or network output for that bounded batch.

Sync should not build a Rust vector of all shareable facts for a connection.
Range filtering and authorization filtering belong in SQL before fact bytes are
loaded.

## CLI Model

CLI commands are the only place that may hold frontend-oriented state, and only
within a visible page or selected object. CLI list commands should accept an
explicit limit and cursor or use a small default limit. Examples:

- messages in a workspace: page by `(created_at_ms, message_id)`
- files in a workspace: page by `(created_at_ms, file_fact_id)`
- users in a workspace: page by `(username, user_id)`
- peers in a workspace: page by `(device_name, endpoint_id)`
- file slices: page by `(slice_index)`

Single-object commands can use exact keyed reads. Status commands should use SQL
counts and reductions rather than materialized lists.

## Tests

Unit tests should concentrate on pure author and projector behavior:

- author tests assert emitted fact bytes and receipts
- projector tests provide explicit facts/context and assert `ProjectionOutput`
- row helper tests assert key/value round trips
- query tests seed targeted projected rows and assert bounded query results

Black-box CLI tests should exercise user-visible behavior without inspecting
storage through broad scans.

Architecture tests should reject broad read patterns in both `src` and `tests`:

- `Runtime::facts`
- `runtime.facts()`
- `persisted_facts(`
- production `table_rows(`
- `table_rows_with_key_prefix(..., usize::MAX)`
- counting by loading rows and taking `.len()`

Replay/debug tools that genuinely require global scans must be isolated behind
explicit module allowlists and must not leak helper APIs back into runtime or
protocol code.

## LOC Reduction Strategy

This migration should reduce code volume rather than add a parallel abstraction
stack. Use these rules while changing code:

1. Delete broad helper APIs after their last caller is migrated. Do not keep
   compatibility wrappers.
2. Prefer one generic store primitive over many near-duplicate protocol helper
   loops.
3. Keep row encoding and decoding in one local helper per table. Query modules
   should reuse it instead of open-coding field extraction.
4. Replace Rust filters over loaded rows with SQL predicates. This removes both
   loops and intermediate vectors.
5. Replace Rust `.len()` counts with SQL `COUNT(*)`.
6. Replace manual "latest row" scans with `ORDER BY ... LIMIT 1`.
7. Replace in-memory set construction with indexed `EXISTS`, `JOIN`, or bounded
   key-prefix queries where practical.
8. Use the existing `RowTableSchema`/`RowValue` machinery instead of adding an
   ORM or a second row-mapping framework.
9. Keep protocol row structs small and local. Do not create repository-wide
   generic typed-record traits unless repetition remains after several families
   are migrated.
10. Consolidate tests by moving repeated runtime setup into CLI fixtures and
    moving projector setup into small fact-family fixtures.
11. Remove tests that only prove broad scan helpers work. Replace them with
    author/projector tests or black-box CLI behavior tests.
12. Do not preserve old and new sync selection paths. Move one path at a time
    and delete the replaced path in the same change.

The desired result is less code because each query becomes either a direct SQL
predicate or a small row helper call, and the runtime loses broad compatibility
surfaces.

## Migration Order

1. Add architecture tests that ban new broad reads in `src` and `tests`, with
   temporary allowlists for existing sites being migrated.
2. Add store primitives for fact counts, exact fact reads, bounded fact batches,
   exact row reads, bounded pages, SQL counts, and transaction-local row writes.
3. Move common projection commit writes behind `WriteStore` primitives while
   keeping `project_fact` responsible for commit ordering.
4. Replace trivial count callers with SQL counts.
5. Add projected tables for local endpoint, local signer secret, local key
   secret, local recipient key, recipient key, removal frontier, and local
   history node secret.
6. Rewrite auth and key-wrap queries to use those projected tables.
7. Add or tighten content query pages for messages, files, reactions, file
   slices, and retention status.
8. Rewrite connection membership and request queries to use keyed or bounded
   SQL rather than global membership/request scans.
9. Rewrite sync selection around DB-backed negentropy and bounded fact-id
   batches.
10. Convert tests away from broad reads. Keep most coverage in author/projector
    unit tests and black-box CLI tests.
11. Remove `Runtime::facts`, `persisted_facts`, production `Store::table_rows`,
    and unbounded prefix-scan call sites.
12. Tighten architecture tests by removing temporary allowlists.
13. Commit the completed work on the same worktree branch before handoff or
    review.

## Done Criteria

- No production runtime path can ask for all facts or all rows.
- Every semantic query reads a projected table owned by the fact family that
  defines the meaning.
- Projectors remain pure and do not query the store.
- `project_fact` commits projector output atomically through store primitives.
- Sync negentropy state is DB-backed and queried by bounded predicates.
- CLI list commands are paged.
- Tests avoid broad scans and use author/projector or black-box CLI coverage.
- Architecture tests enforce the boundaries.

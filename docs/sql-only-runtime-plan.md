# SQL Runtime Storage Model

The runtime uses SQLite as the storage and query engine. Core persists facts as
opaque content-addressed bytes, projectors emit typed mutations for projected
tables, and protocol query modules run bounded SQL over those projected tables.

## Boundaries

- `core/store.rs` owns the SQLite connection, schema execution, transactions,
  typed row mutation mechanics, fact storage, intent work rows, replay table
  reset, and replay summaries.
- `core/project_fact.rs` owns projection commit ordering: source retention,
  context replacement, due time wakes, row mutations, emitted facts, intents,
  and queue deletion.
- `core/handle_intent.rs` owns intent queue selection, handler dispatch, retry
  behavior, and atomic commit of handler output.
- `core/network.rs` owns TCP and memory-local network queue SQL.
- Protocol fact-family roots own projected table names, column order, key
  columns, and typed row builders.
- Protocol `queries.rs` modules own SQL reads over projected rows. They may use
  joins, ordering, counts, and pagination, but must stay bounded and indexed.

Projectors stay pure: they decode and validate one fact plus supplied context,
then return `ProjectionOutput`. They do not query SQLite.

## Store Surface

Store intentionally has a small public surface:

- open disk or memory stores from schema sources
- expose `conn()` inside the crate for owned SQL modules
- run `write_transaction`
- insert typed table values for tests and seeds
- count declared tables
- exact fact reads and fact existence
- replay reset and replay summary hashes

There is no generic `(row_key, row_value)` table API. Table owners write the
SQL shape they need directly, and projectors use typed `InsertValues` and
`DeleteWhere` mutations.

## Query Rules

Queries may use full SQL against projected tables. The guardrails are:

- no semantic scans of `facts`
- no unbounded result sets
- no loading broad rows and filtering in Rust
- use indexed predicates, `COUNT`, `EXISTS`, `ORDER BY ... LIMIT`, joins, and
  pages
- load fact bytes only by exact selected ids and bounded batches

SQLite is the abstraction for reads. The codebase should not grow generic read
helpers that merely wrap one SQL shape per caller.

## Replay

Replay clears schema-declared derived state, queues retained facts for
projection, and rebuilds projected state by running the normal projection commit
path in replay mode. Replay summaries hash declared summary tables after rebuild
so diagnostics can compare deterministic projected state.

Replay does not own protocol-specific rebuilding logic. Projectors decide what
their fact materializes in replay mode.

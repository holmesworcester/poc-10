# SQL Runtime Storage Model

The runtime uses SQLite as the storage and query engine. Core persists facts as
opaque content-addressed bytes, projectors emit typed mutations for projected
tables, and protocol query modules run bounded SQL over projected tables.

## Boundaries

- `core/db.rs` owns the SQLite connection, schema execution, transactions,
  trusted identifier quoting, and generic typed row mutation mechanics.
- `core/schema.rs` declares retained fact tables, local fact admission tables,
  incoming fact tables, queue tables, and rebuild lifecycle groups.
- `core/project_fact.rs` owns fact lifecycle SQL and projection commit ordering:
  retained and incoming admission, pending queue selection, context
  replacement, due time wakes, exact fact purges, row mutations, emitted facts,
  intents, rebuild effect commit, and queue deletion.
- `core/handle_intent.rs` owns intent queue SQL, handler input fact loading,
  handler dispatch, retry behavior, and atomic commit of handler output.
- `core/network.rs` owns TCP and memory-local network queue SQL.
- `protocol/versioning/queries.rs` owns state-summary diagnostics.
- Protocol fact-family roots own projected table names, column order, key
  columns, and typed row builders.
- Protocol `queries.rs` modules own bounded SQL reads over projected rows.

Projectors stay pure: they decode and validate one fact plus supplied context,
then return `ProjectionOutput`. They do not query SQLite.

## Db Surface

`Db` is connection plumbing, not a broad store abstraction:

- open disk or memory databases from schema sources
- expose `conn()` inside the crate for modules that own SQL
- run `write_transaction`
- apply typed table inserts/deletes for projected rows and seed data
- count declared tables

There is no generic `(row_key, row_value)` API and no generic read helper layer.
Table owners write the SQL shape they need directly.

## Query Rules

Queries may use full SQL against projected tables. The guardrails are:

- no semantic scans of `facts`
- no unbounded result sets
- no loading broad rows and filtering in Rust
- use indexed predicates, `COUNT`, `EXISTS`, `ORDER BY ... LIMIT`, joins, and
  pages
- load fact bytes only by exact selected ids and bounded batches

SQLite is the abstraction for reads.

## Rebuild

Rebuild clears schema-declared derived state, queues retained facts for
projection, and rebuilds projected state by running the normal projection and
intent commit paths in replay mode. Rebuild does not own protocol-specific
logic; projectors decide what their facts materialize in replay mode.

State-summary is separate protocol diagnostic work. It hashes declared summary
tables after ordinary runtime work has drained.

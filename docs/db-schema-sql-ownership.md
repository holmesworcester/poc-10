# DB, Schema, And SQL Ownership

The runtime should not hide SQLite behind a broad store abstraction. SQLite is
the query engine, and the module that owns a table owns the SQL for that
table's behavior.

## Current Split

- `core/schema.rs` owns core table names, schema batches, and replay lifecycle
  declarations.
- `core/db.rs` owns the SQLite connection, schema execution, transactions,
  trusted identifier quoting, and generic typed row mutation mechanics.
- `core/fact_db.rs` owns retained facts, local fact admissions, incoming facts,
  fact purge cleanup, and pending-projection admission rows.
- `core/project_fact.rs` owns projection queue selection, projection commit
  ordering, standing context SQL, due time wake SQL, and row mutation commit.
- `core/handle_intent.rs` owns durable and local intent queue SQL.
- `core/network.rs` owns network queue SQL.
- `core/replay.rs` owns replay reset and replay-mode work driving.
- `core/replay_check.rs` owns diagnostic replay summaries and pass comparison.
- Protocol fact-family roots own projected table declarations and row builders.
- Protocol `queries.rs` modules own bounded SQL reads over projected rows.

Projectors remain pure. They do not execute SQL. They emit row mutations,
facts, intents, context, and time wakes; core commits that output atomically.

## Schema

Schema sources are declarative. They provide executable DDL plus replay
lifecycle declarations:

- `protected` tables are retained fact-storage tables that replay must not
  clear.
- `reset` tables are derived, queued, or local runtime state that replay clears
  before rebuilding.
- `summary` tables are included in replay-check state digests.

Schema declarations do not own live database execution. Runtime modules that
own behavior call `Db::conn()` and `Db::write_transaction()`.

## Db

`Db` is deliberately small:

- open disk or memory databases from schema sources
- expose the SQLite connection inside the crate
- run explicit write transactions
- quote trusted table/column identifiers
- apply typed row mutations
- count declared tables
- snapshot the database for diagnostics

`Db` must not grow generic read helpers or queue-specific APIs. If a module
owns a table, that module writes the SQL shape it needs.

## Facts

`fact_db.rs` is the protocol-neutral fact table owner. It stores immutable fact
bytes by content id, records the first local admission metadata, handles
incoming fact rows, queues retained facts for projection, and purges
core-owned rows keyed by a fact id.

Fact SQL does not decode protocol payloads. Protocol meaning belongs to
fact-family projectors and query modules.

## Projection

`project_fact.rs` owns the commit boundary from fact bytes to derived state. A
projection commit may:

- clear consumed pending work
- retain or drop an incoming fact
- replace standing needs
- append offers
- queue dependents whose needs now match
- replace time wakes
- apply typed row mutations
- admit emitted facts
- record emitted intents

Projectors supply data. `project_fact.rs` supplies SQL and ordering.

## Intents

`handle_intent.rs` owns queue selection, retry rotation, handler context
loading, and the transaction that deletes handled work while committing handler
output. Durable intent rows are replayable; local intent rows are connection
local and disappear on restart.

## Queries

Protocol `queries.rs` modules may use full SQL against projected tables. The
rules are:

- no semantic scans of `facts`
- no unbounded result sets
- no loading broad rows and filtering in Rust
- use indexed predicates, joins, counts, `EXISTS`, `ORDER BY ... LIMIT`, and
  pages
- load fact bytes only by exact selected ids and bounded batches

SQLite is the read abstraction.

## Replay

Replay rebuilds derived state. It clears schema-declared reset tables, marks
retained facts pending in replay mode, and drives the normal bounded projection
and intent workers until the replay barrier is idle.

Replay must not perform network IO, fire recurring live schedules, or make
wall-clock decisions. Projectors decide how their fact materializes under
`ProjectionContext::is_replay()`.

`replay_check.rs` is diagnostic. It may run replay in multiple orders and hash
summary tables to prove deterministic rebuilds. Whole-table summary scans stay
there, not in `db.rs`.

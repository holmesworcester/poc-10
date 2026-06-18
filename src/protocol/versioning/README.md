# Versioning

`versioning` is a protocol scope. It is not itself a fact family.

This scope owns the release constant `CURRENT_PROTOCOL_VERSION`, the recurring
check that compares the schema-declared protocol marker with that constant, and
the local update fact that repairs stale derived state. Core owns the generic
commit-side `StorageRequirement` guard; see `src/core/README.md` for that
runtime contract.

## Rules

1. A release must not author a new durable fact type until every non-deprecated
   release can decode, authenticate, validate, and project that type.
2. Projectors for current code must support every old durable fact type that can
   remain in `facts`.
3. New projectors and queries must not write old materialized table shapes.
4. Commands, projectors, handlers, and queries declare the storage version they
   expect before they touch materialized state.
5. If code advances past the stored database marker, normal queries fail and
   normal effect commits roll back instead of consuming queued work.
6. The recurring version check emits a local update fact. Projecting that fact
   wipes resettable derived state, queues retained facts in replay mode, records
   protocol-visible update history, and advances the schema-declared protocol
   marker.

## Layout

- `src/protocol/versioning.rs` owns `CURRENT_PROTOCOL_VERSION` and the scope
  map.
- `src/protocol/versioning/check_version.rs` owns the recurring
  `check_version` intent that authors update facts when the schema-declared
  protocol marker is stale.
- `src/protocol/versioning/local_update.rs` owns the `local_update` fact
  family, its projected protocol-visible update row, and the `state-summary`
  diagnostic.
- `src/protocol/versioning/local_update/queries.rs` owns state-summary
  diagnostics.

The actual fact family is `versioning/local_update/`. Its role files
(`fact.rs`, `encode.rs`, `author.rs`, `project.rs`, `api.rs`, `cli.rs`) stay
under that directory. `state-summary` is a diagnostic command owned by the
local-update family. It hashes schema-declared summary tables so rebuild output
can be compared without adding protocol meaning to core.

## Update Loop

The update loop is protocol responsibility. It answers one question: has this
database already projected retained facts into the materialized shape expected
by this checkout?

The recurring `check_version` intent compares the schema-declared protocol
marker with `CURRENT_PROTOCOL_VERSION`. If they match, it emits no work. If
they do not match, it emits a priority local update fact. The update fact is
retained as history, but its projector does rebuild work only during live
projection; replay projection of an old update fact is a no-op so previous
updates do not rerun.

The update fact projection requests the rebuild effect, writes
protocol-visible update history, and advances the schema-declared protocol
marker in the same projection commit. The rebuild effect clears
schema-declared resettable state and marks retained facts pending in replay
mode.

## Storage Requirements

A storage requirement is a local safety contract for one read or write path. It
is separate from the recurring update loop.

Protocol projectors and handlers register `StorageRequirement::Current` for
ordinary work. Core enforces that requirement inside the same SQL transaction
that would otherwise remove the source queue row and commit the effects. On
mismatch, SQLite rolls the whole transaction back. The versioning update
projector and handler use `StorageRequirement::MaintenanceBypass` so repair can
run while storage is stale.

Queries are direct SQL readers, so core does not gate them automatically the way
it gates projection and intent commits. Before touching materialized tables, a
query must choose one explicit behavior: require the current storage version
and return a mismatch error, intentionally support an old not-yet-replayed
table shape with compatibility SQL, or act as a maintenance/diagnostic query
that is allowed to inspect stale state. The normal user-facing path should
require current storage unless the query documents a specific stale-storage
compatibility path.

## Boundaries

Core does not know release policy, fact-family compatibility, or table meaning.
It reads the schema-declared protocol marker, enforces the storage requirement
it is handed, and executes rebuild/update effects mechanically.

Protocol modules own the marker table, version number, recurring check, update
fact, query policy, and per-family compatibility rules. Compatibility with
older retained facts or older materialized storage belongs in the owning
projector/query code. During an update, that code may read old storage shapes
only to derive the current release's state; it must write only the current
release's declared tables and effects, never old database tables.

Core also does not store future-version incoming facts as protocol truth.
Incoming is volatile intake. Fact storage happens only after admission and
projection.

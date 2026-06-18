# Protocol Versioning

This is the current poc-10 model. Versioning is protocol-owned release
discipline plus a local storage repair loop. Core stays mechanical: it stores
facts, drains queues, commits effects atomically, and runs rebuild/replay when a
projector asks for it.

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
   wipes resettable derived state, queues retained facts in replay mode, and
   records the current release marker.

## What Exists

- `src/protocol/versioning.rs` documents the split between the stored release
  marker and per-projector/query storage requirements.
- `src/protocol/versioning.rs` owns `CURRENT_PROTOCOL_VERSION` and the
  versioning scope map.
- `src/protocol/versioning/update.rs` owns the local update fact family and the
  projected protocol version row.
- `src/protocol/versioning/check_version.rs` owns the recurring `check_version` intent
  that authors update facts when the stored release marker is stale.
- `src/protocol/versioning/queries.rs` owns storage guards and state-summary
  diagnostics.
- Protocol projectors and handlers register `StorageRequirement::Current` for
  ordinary work. The versioning update projector and handler use
  `StorageRequirement::MaintenanceBypass` so repair can run while storage is
  stale.
- `RuntimeEffects::rebuild_derived_state` is the only generic rebuild effect.
  Projection commit is the only path that may request it.

## Release Marker

The release marker is stored protocol state. It answers one question: has this
database already projected retained facts into the materialized shape expected by
this checkout?

The recurring `check_version` intent compares the latest projected marker row
with `CURRENT_PROTOCOL_VERSION`. If they match, it emits no work. If they do not
match, it emits a priority local update fact. The update fact is retained as
history, but its projector does rebuild work only during live projection; replay
projection of an old update fact is a no-op so previous updates do not rerun.

## Storage Requirements

A storage requirement is a local safety contract for one read or write path. It
is separate from the release marker.

Projector and handler effects carry a required storage version. Core enforces
that requirement inside the same SQL transaction that would otherwise remove the
source queue row and commit the effects. On mismatch, SQLite rolls the whole
transaction back. Queries call the protocol-owned guard before reading
materialized rows and return an error on mismatch.

This means old materialized state is not trusted by new code. It also means
stale queued work remains available after the update fact repairs storage.

## Rebuild

The update fact projection requests the rebuild effect and writes the new marker
row in the same projection commit. The rebuild effect clears schema-declared
resettable state and marks retained facts pending in replay mode.

Replay mode is carried by work rows. Projectors and handlers can inspect that
mode through their context and suppress live-only effects such as network work
or recurring operational decisions. Retained facts are the source of truth; all
materialized rows, queues, time wakes, and local intents are rebuilt or
recreated only if current projectors produce them.

## What Core Does Not Do

Core does not know release policy, fact-family compatibility, version numbers,
or table meaning. It only enforces the storage requirement it is handed and
executes the rebuild effect mechanically.

Core also does not store future-version incoming facts as protocol truth.
Incoming is volatile intake. Fact storage happens only after admission and
projection.

## What Remains To Prove

The important checks are practical:

- registry tests ensure ordinary routes and handlers declare the current storage
  requirement, while update routes use the maintenance bypass;
- black-box CLI tests simulate a stale stored marker and prove queries fail
  until update/rebuild drains;
- replay tests prove update facts do not rerun rebuild during replay and do not
  produce network output;
- release review must enforce the read-before-write rule for any new durable
  fact type.

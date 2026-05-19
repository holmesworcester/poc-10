# Core Cleanup Plan

This plan targets duplicated mechanics and superfluous surface area in `src/core`.
The goal is to make core smaller, more protocol-neutral, and easier to change
without weakening the current architecture guardrails.

## Goals

- Keep core responsible for generic runtime mechanics only: storage, fact
  projection, context matching, intent dispatch, transport byte movement, CLI
  dispatch, and process lifecycle.
- Move protocol-specific types, schema constants, and policy decisions out of
  core.
- Collapse duplicated byte encoding and decoding into one shared codec surface.
- Split large modules by responsibility before changing behavior.
- Remove public APIs and schema rows that are not wired into real workflows.

## Non-Goals

- Do not redesign fact semantics, protocol registrations, or CLI behavior.
- Do not replace the row-store model with an ORM or broad typed persistence
  layer.
- Do not combine protocol fact modules while cleaning core.
- Do not remove architecture boundary tests unless the boundary itself is
  intentionally moved and documented.

## Phase 1: Inventory And Safety Net

1. Record the current public core API.
   - Generate a list of `pub` items under `src/core`.
   - Mark each item as runtime-used, protocol-used, test-only, or unused.
   - Pay special attention to `network::OutboundFrame`, `network_queues`,
     `tcp`, `wake_loop` helpers, and store constructors.

2. Add narrow regression tests before moving code.
   - Persist/load one fact, one need, one offer, one time wake, and one intent.
   - Exercise exact context matching through the wake loop.
   - Exercise deferred handler dispatch with fact context.
   - Exercise atomic row intent save behavior.
   - Exercise memory-backed network queues.

3. Keep branch hygiene strict.
   - Make each phase a separate commit.
   - Avoid formatting churn outside files being moved.
   - Use mechanical moves first, behavior changes second.

## Phase 2: Consolidate Byte Codecs

Problem: core has several local byte readers and writers with the same
big-endian and length-prefixed operations.

Current duplicated locations:

- `wire.rs`: shared `Reader`, `Writer`, fixed integer layouts.
- `wake_loop.rs`: local `Reader`, `put_u8`, `put_u16`, `put_u32`, `put_u64`,
  `put_string_u16`, `put_bytes_u32`.
- `intents.rs`: local `IntentReader`, `put_sized_u16`, `put_sized_u32`.
- `store.rs`: typed-column `take_exact`, `take_u32`, `put_sized_u32`.
- `network_queues.rs`: local `read_u32` and route key encoding.
- `logical_clock.rs` and `tcp.rs`: simple hand-rolled integer codecs.

Plan:

1. Extend `wire::Writer`.
   - Add `u16be`.
   - Add fallible `bytes_u16`, `bytes_u32`, and `string_u16`.
   - Keep error type generic enough to adapt to `String` and `rusqlite::Error`.

2. Extend `wire::Reader`.
   - Add `u16be`.
   - Add `bytes_u16`, `bytes_u32`, `string_u16`, and `finish`.
   - Keep exact-length behavior strict.

3. Migrate callers incrementally.
   - Start with `intents.rs`; it is small and self-contained.
   - Then migrate `wake_loop` row codecs.
   - Then migrate store typed-column codec helpers with a local error adapter.
   - Finally migrate small helpers in `network_queues`, `logical_clock`, and
     `tcp` where it improves clarity.

4. Remove local readers after each migration.
   - No module should retain a private sequential reader unless it has a
     genuinely different error model or parsing strategy.

Verification:

- Existing wire tests still pass.
- Intent round-trip tests still pass.
- Wake-loop persistence tests still pass.
- Store schema tests still pass.

## Phase 3: Split Wake Loop Responsibilities

Problem: `wake_loop.rs` owns state mutation, persistence, dirty tracking,
context indexes, matching acceleration, time wakes, handler dispatch, atomic
row application, and row codecs.

Target shape:

- `wake_loop.rs`
  - Public `WakeLoop`, `DrainReport`, `DispatchReport`.
  - High-level orchestration only.

- `wake_state.rs`
  - Internal fact/context/time/intent state containers.
  - Pending projection queue.
  - Dirty tracking.

- `wake_persistence.rs`
  - Table constants for facts, needs, offers, time wakes, pending projection,
    and intents.
  - Row encoders/decoders.
  - `load` and `save` helpers.

- `context_index.rs`
  - Exact context key indexes.
  - Insert/remove/rebuild operations.
  - Lookup operations for exact roles.

- `intent_queue.rs`
  - Intent idempotence key generation.
  - Validate, record, pop, restore, and rebuild key index.

- `atomic_rows.rs`
  - Atomic row intent validation and conversion into `TableRow` or
    `TableDelete`.

Migration order:

1. Move row encoders/decoders into `wake_persistence.rs` without changing
   behavior.
2. Move context index fields and helpers into `ContextIndex`.
3. Move intent queue fields and helpers into `IntentQueue`.
4. Move atomic row helpers into `atomic_rows.rs`.
5. Leave `WakeLoop` as the orchestration facade.

Verification:

- `WakeLoop::load` and `WakeLoop::save` remain behaviorally identical.
- Exact context matches wake the same owners in the same order.
- Intent idempotence conflicts produce the same errors.
- Architecture tests still see protocol-neutral wake-loop vocabulary.

## Phase 4: Centralize Context Matching

Problem: exact selector matching is implemented in both `matchers.rs` and
`wake_loop.rs`. `ExactSelectorMatcher` builds temporary indexes, while
`WakeLoop` keeps persistent exact indexes and performs exact matching inline.

Plan:

1. Keep the `ContextMatcher` trait as the protocol extension point.
2. Introduce a core `ContextIndex` API.
   - `matches_for_delta(delta, matchers) -> Vec<ContextMatch>`.
   - `matched_context_for_owner(owner, matchers, facts) -> ProjectionContext`.
3. Move exact role discovery and exact matching into `ContextIndex`.
4. Keep custom matcher execution delegated through `ContextMatcher`.
5. Reduce `ExactSelectorMatcher` to a simple matcher implementation or a marker
   wrapper, depending on whether the indexed path fully covers it.

Verification:

- Existing custom matcher tests still pass.
- Exact matcher tests still pass.
- Wake-loop matching tests still pass.
- No protocol module learns about the index internals.

## Phase 5: Split Store Internals

Problem: `store.rs` is the row-store API, SQLite adapter, schema applier, typed
table codec, memory backend, and SQLite schema validator.

Target shape:

- `store.rs`
  - Public `Store`, `TableName`, `TableRow`, `Schema`, `StorageClass`.
  - Public row read/write methods.

- `store_sqlite.rs`
  - SQLite table creation and row operations.
  - Quoting and identifier validation.

- `store_memory.rs`
  - Memory table backend and range scans.

- `schema_apply.rs`
  - Apply parsed schema declarations.
  - Validate existing SQLite tables and indexes.

- `typed_rows.rs`
  - Typed table row/key encoding and decoding.
  - Column value codec adapters.

Migration order:

1. Move private helper functions without API changes.
2. Introduce small internal structs where needed, such as `TypedTableStore`.
3. Keep `Store` as the only public durable substrate.
4. Defer any API renames until after the split.

Verification:

- Schema store tests still pass.
- Memory table behavior remains process-local.
- Typed row conflict behavior remains idempotent.
- SQLite table validation still rejects incompatible existing tables.

## Phase 6: Restore Core/Protocol Boundaries

Problem: core imports concrete protocol types and protocol schema files.

Boundary leaks:

- `command_context.rs` imports protocol signing and encryption fact types.
- `schema_dsl.rs` exposes protocol schema constants.

Plan:

1. Make command capabilities generic or trait-based.
   - Core should define `CommandContext`, `CommandClock`, and capability access
     traits.
   - Protocol should define concrete signing/encryption capability payloads.
   - If associated types are needed, put them on a protocol-facing trait rather
     than importing protocol facts into core.

2. Move protocol schema constants out of `core::schema_dsl`.
   - Keep `CORE_SCHEMA_SOURCE` in core.
   - Move `FACTS_SCHEMA_SOURCE` and `INTENTS_SCHEMA_SOURCE` to protocol-owned
     modules.
   - Update `protocol.rs` and `protocol/runtime.rs` to import schema sources
     from protocol-owned locations.

3. Preserve tests that require exactly three schema DSL files.
   - The file layout can stay the same.
   - The constants should live with the owner of each schema.

Verification:

- Core compiles without importing `crate::protocol`.
- Protocol command code still gets the same concrete local capabilities.
- Runtime still opens the same schema source set.

## Phase 7: Remove Superfluous Surface

Candidates:

- `row_table inbox` in `src/core/schema.p8sql`.
  - It appears unused by core and protocol code.
  - Remove it if no migration or compatibility test needs it.

- `network::OutboundFrame.deadline`.
  - Currently accepted but ignored.
  - Either wire it into TCP write budgeting or remove it.

- `network::OutboundFrame.retry_key`.
  - Currently accepted but ignored.
  - Either use it for queue/idempotence behavior or remove it.

- `daemon::StartOptions.tick_ms`.
  - Parsed and stored but not used for scheduling.
  - Either make active ticks sleep according to `tick_ms` or remove the field
    and CLI flag.

- `network_queues::outbound_rows`.
  - Definition-only in the current code search.
  - Remove unless an external crate uses it.

- `tcp::serve_inbound`.
  - Superseded by reusable `Listener::accept_available` in daemon paths.
  - Remove if only tests or old callers reference it.

- Bare store constructors such as `Store::open` and `Store::open_disk`.
  - Keep only if tests or external users need a schema-less store.
  - Otherwise prefer explicit schema-source constructors.

Verification:

- Run repo-wide `rg` before each removal.
- Remove one candidate per commit.
- If a candidate is public API but unused internally, document whether external
  API stability matters before deleting it.

## Phase 8: Tighten Runtime And Dispatch

Problem: runtime and wake loop both expose multiple dispatch paths, and handler
output application is repeated.

Plan:

1. Extract shared handler-output application.
   - Purge facts.
   - Submit emitted facts.
   - Record emitted intents.
   - Update `DispatchReport`.

2. Collapse dispatch variants.
   - Keep one internal `dispatch_matching` path.
   - Expose only the variants actually used by runtime and tests.

3. Make handler context construction explicit.
   - A handler that needs facts should get fact context.
   - A handler that needs store access should get store context.
   - Avoid hidden string checks such as matching `"handler context missing fact "`
     as control flow when a typed retry/missing-input signal would be clearer.

Verification:

- Deferred handlers still retry without losing intents.
- Atomic handlers still run only through the intended path.
- Fact-context handlers still skip missing facts without corrupting queue state.

## Phase 9: Documentation And Ownership Map

After the code moves, add a short ownership map near `src/core.rs` or in
architecture docs:

- `facts.rs`: fact identity and scope.
- `context.rs`: durable needs/offers and context-set diffs.
- `matchers.rs` plus `context_index.rs`: matching contracts and indexes.
- `projection.rs`: projector contracts and projection outputs.
- `intents.rs` plus `intent_queue.rs`: intent data and idempotence queues.
- `wake_loop.rs`: orchestration facade.
- `store.rs`: public row-store facade.
- `wire.rs`: byte codec primitives.
- `tcp.rs` and `network_queues.rs`: transport byte movement.
- `daemon.rs` and `cli.rs`: process and command runner mechanics.

## Suggested Commit Sequence

1. Add codec helpers to `wire`.
2. Migrate `intents` to `wire`.
3. Migrate wake-loop persistence codecs to `wire`.
4. Move wake-loop persistence helpers.
5. Extract `ContextIndex`.
6. Extract `IntentQueue`.
7. Extract atomic row helpers.
8. Split store typed-row and schema-application internals.
9. Remove protocol imports from core.
10. Remove unused schema/API surface one candidate at a time.

## Done Criteria

- `src/core` has no imports from `crate::protocol`.
- Only `wire.rs` owns generic sequential byte reading/writing.
- `wake_loop.rs` is an orchestration facade, not a persistence and indexing
  implementation.
- `store.rs` exposes the row-store API while implementation details live in
  focused internal modules.
- Unused core schema rows and ignored API fields are removed or wired.
- Architecture tests and core/protocol tests pass.

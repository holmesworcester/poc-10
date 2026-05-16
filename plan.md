# Current Plan

This is the short handoff plan for the poc-10 rewrite. The destination design
is `new_architecture.md`; durable encryption rules are in `encryption.md`;
dep-aware sync notes are in `negentropy_recs.md`.

## Current State

- Branch: `new-architecture`.
- Product-facing binary: `match`.
- Target code lives in `src/core`, `src/event_modules`, `src/handlers`,
  `src/commands`, `src/match_app.rs`, and `src/demo.rs`.
- Legacy production code is contained in `src/legacy/` so it can be deleted as
  one island after cutover.
- Full `cargo test` passed after the `match` binary rename, command-module
  move, flat handler layout, `WakeLoop` rename, and legacy island move.
- Two target architecture guardrails remain intentionally ignored until old
  worker queues and projector row/label output are fully replaced.

## Recent Structural Decisions

- Use "facts" as the conceptual model.
- Wake scheduling now lives in `WakeLoop`.
- The executable is `match` because context matching is central and topo-sort is
  no longer the mental model.
- Concrete command constructors moved into event modules:
  `identity_workspace::create::create_workspace` and
  `sealed_message::create::send_message`.
- `src/commands` now only exposes `CommandContext` and `CommandOutput`.
- Handlers are flat files under `src/handlers/<handler>.rs`; handler
  subdirectories are forbidden.
- `src/legacy/` contains old app/daemon/protocol/worker code. New target work
  should not add behavior there.
- `src/legacy/round_robin.rs` is only the old daemon scheduler loop. It cannot
  be removed until `match start/stop/reset` no longer depend on legacy daemon
  scheduling.

## Target Runtime Cutover

The next production-path work is a target runtime facade that owns:

- store opening from the three schema files.
- `WakeLoop` load/save.
- projector registry.
- context matcher registry.
- handler registry.
- `submit_fact` and `submit_intent`.
- bounded projection drain.
- bounded deferred intent dispatch.
- command output submission and draining.

`match_app` should then call that facade instead of
`legacy::app::run::<legacy::protocol::Protocol>`.

## Hard Behavior Still Needed

- Full receive path for signed key-wrap facts:
  transit frame open -> signed envelope validation -> key-wrap projector ->
  unwrap/materialize intents -> key coverage offers.
- Real target transit packaging and network send:
  connection send intent -> transit frame creation -> network send intent ->
  send acknowledgement.
- Durable sync index/checkpoint facts or handler state, replacing the legacy
  in-memory `SyncIndex`.
- Dep-aware sync range closure that includes out-of-range dependencies and key
  offers for in-range facts.
- Purge split:
  exact content purge, cascade discovery, secret retirement, sync-index purge,
  and expiry/floor handling as bounded intents/handlers.
- Projection/open path for encrypted content using supplied key context without
  introducing an open-message worker.

## Cleanup Rules

- Do not add new target behavior under `src/legacy/`.
- Do not add broad files named `runtime`, `state`, `schema.rs`, `codec.rs`, or
  `cli.rs`.
- Do not add handler subdirectories.
- Do not let intents become logic sinks. Intents name work; handlers perform one
  bounded effect; event modules own protocol fact construction and validation.
- Keep docs short and current. Delete historical plans instead of preserving
  stale architecture guidance.

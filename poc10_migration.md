# Poc-10 Migration Status

This file tracks remaining cleanup after the old source island was removed.
The executable TODO list lives in `tests/poc10_cutover_todo_test.rs`.

## Current State

- Production entry is `match`, implemented by `src/main.rs` and a thin root
  app boundary.
- Product commands route through the core runtime/app facade configured by
  `src/protocol.rs`.
- Commands return receipts: ids, scope ids, and deterministic timestamps only.
  CLI/API code queries projected rows after runtime drain when it needs display
  data.
- Automatic behavior is projector/intent/handler driven. Handlers may call
  deterministic `create.rs` constructors; projectors and handlers must not call
  user-facing `commands.rs` or `cli.rs`.
- `CommandContext` and `CommandOutput` live in `core::command_context`; there
  is no root `src/commands` module.
- Module manifests live under `src/protocol/facts.rs` and
  `src/protocol/intents.rs`, with the concrete registry in `src/protocol.rs`.
- Smoke coverage belongs in black-box CLI tests against the real `match`
  binary; there is no product `demo` or `smoke` command.
- The old source island and its boundary test were deleted.

## Success Criteria

- Poc-8 behavior is covered by target black-box tests or target harness tests.
- Target code uses facts, context needs/offers, matchers, core projection
  pipelines,
  projectors, intents, flat handlers, module commands, module queries, and
  module CLI adapters.
- Runtime is generic core runtime/app plus protocol registry, not
  product-specific runtime logic.
- No old labels, blocker tables, ready queues, canonical ingress queues,
  recently-valid queues, pending reprojection queues, or worker catalogs remain.
  These names are legacy/removal vocabulary only. They must not reappear in
  target code paths except in tests or documentation. No removed-source imports
  remain.
- Reactive work creates new facts through intents and handlers, not through
  commands.

## Replacement Map

| Old responsibility | Target owner |
| --- | --- |
| event admission | core runtime fact submission plus fact layout validation |
| dependency unblock | context needs/offers plus matchers |
| ready/blocked/reprojection queues | SQLite pending fact table plus direct context wake fanout |
| labels | update/about context offers |
| canonical ingress + receive metadata | receive facts plus context offers |
| projection row writes | row mutations from projectors |
| content purge | purge intents and purge handlers |
| key unwrap/materialization | encryption projectors plus key handlers |
| transit in/out | receive/transit/network handlers |
| sync worker/index | sync facts plus durable sync handlers |
| command admission helper | `core::command_context` + generic core runtime |

## Remaining Work

1. Port the remaining product commands and daemon lifecycle to generic core
   runtime/app methods plus module-local `cli.rs`/`commands.rs`/`queries.rs`.
2. Replace transit send packaging and `network_send` stubs with real fixed-frame
   handler behavior.
3. Complete durable sync state and dep-aware range closure for out-of-range
   dependencies and keys.
4. Finish purge cascade, secret retirement, expiry, and floor behavior as
   bounded handlers.
5. Cover the remaining poc-8 behavior with target tests, then remove obsolete
   migration guardrails.

## Proofs

- Target architecture and intent cleanliness guardrails cover the new shape.
- Target runtime tests cover command submission, projection, handler dispatch
  registry parity, and signed content-message routing.
- Target projector/handler tests cover the translated fact families and bounded
  effects currently ported.

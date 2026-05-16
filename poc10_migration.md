# Poc-10 Migration Status

This file tracks what must happen before `src/legacy/` can be deleted.

## Success Criteria

- Every non-ignored poc-8 behavior test passes through the `match` binary or an
  equivalent target harness.
- Target code uses facts, context needs/offers, matchers, `WakeLoop`,
  projectors, intents, and flat handlers.
- No old labels, blocker tables, ready queues, canonical ingress queues,
  recently-valid queues, pending reprojection queues, or worker catalogs remain
  outside `src/legacy/`.
- Production `match` commands and daemon behavior no longer call
  `legacy::app`, `legacy::protocol`, or `legacy::workers`.
- `src/legacy/` can be removed as one directory.

## Current Replacement Map

| Legacy responsibility | Target owner |
| --- | --- |
| event admission | `WakeLoop::submit_fact` plus fact layout validation |
| dependency unblock | context needs/offers plus matchers |
| ready/blocked/reprojection queues | pending projection in `WakeLoop` |
| labels | update/about context offers |
| canonical ingress + receive metadata | receive facts plus context offers |
| projection row writes | atomic row intents from projectors |
| content purge | purge intents and purge handlers |
| key unwrap/materialization | encryption projectors plus key handlers |
| transit in/out workers | receive/transit/network handlers |
| sync worker/index | sync facts plus durable sync handlers |
| command admission helper | target command context + runtime facade |

## Cutover Order

1. Build the target runtime facade and route `match demo` through it.
2. Route one real production admission path through target `WakeLoop`; signed
   key-wrap receive is the preferred first path.
3. Replace target transit send packaging and network send stubs.
4. Replace sync index and range response with durable target facts/handlers.
5. Replace content purge, expiry, floor, and secret retirement workers with
   bounded handlers.
6. Port remaining CLI commands from `legacy::protocol::commands` to pure target
   command constructors plus runtime submission.
7. Enable the ignored poc-10 guardrails.
8. Delete `src/legacy/`.

## Current Proofs

- Full `cargo test` is green in the current migration state.
- Target projector tests cover the ported fact families under
  `src/event_modules`.
- Target handler tests cover materialize/unwrap key wrap, purge, receive
  transit, handle sync, network send envelope validation, and send-on-connection
  retry behavior.
- `poc10_encryption_key_healing_test` covers deterministic wraps, key requests,
  retained-node post-deletion healing, recipient-key supersession, and local
  private-key purge.
- `poc10_sync_context_test` covers out-of-range dependency/key context at the
  target context layer.
- Legacy black-box CLI tests still pass through the contained `src/legacy/`
  production path.

## Open Risks

- Stubs must stay visibly retrying. `NOT_YET_WIRED` handlers are not real
  behavior and must not be counted as cutover.
- The target runtime facade must not become a new worker catalog.
- Sync closure must remain bounded when matching selector-based needs/offers.
- Purge handlers must be exact and crash-safe; broad scans need explicit bounded
  intent decomposition.

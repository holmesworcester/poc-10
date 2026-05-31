# TODO: Flatten Intent Chains

This document records the intent-shape rule needed to keep replay admission
flat and easy to reason about.

## Rule

Non-recurring intent handlers should not enqueue follow-up intents. If a
projected fact needs multiple independent effects, the projector should emit
those intents separately.

Recurring intent handlers are the exception. A recurring handler is live-only
scheduler work installed by the daemon after replay, so it may enqueue the
operational intents needed for that tick.

The replay rule stays simple:

```text
if route.runs_during_replay { admit intent } else { suppress intent }
```

Replay should not need to understand handler internals, network IO, command
eligibility, or a transitive graph of follow-up work.

## Why

Handler chains make replay harder to audit. A replayable handler can enqueue a
live-only child intent unless every edge is checked. Keeping independent effects
at the projector boundary means the existing route-level `runs_during_replay`
boolean is enough to decide what enters the replay workset.

This also keeps protocol ownership clearer:

- Projectors decide what durable facts imply.
- Intent handlers perform one registered unit of work.
- Recurring handlers own live maintenance loops.
- Replay suppresses live-only work by route metadata, not by special cases.

## Current Chain Inventory

Allowed recurring chain:

- `maintain_connections -> send_bootstrap_connection_request`

Cleanup candidates:

- `create_connection_response -> send_bootstrap_connection_response`
- `seed_connection_sync -> send_facts_on_connection`
- `share_fact_with_sync -> send_facts_on_connection`
- `send_sync_compare_response -> send_facts_on_connection`
- `send_needed_fact_id -> send_facts_on_connection`
- `send_requested_fact -> send_facts_on_connection`
- `send_facts_on_connection -> send_network_frame`

The connection-event cleanup is being explored separately. This TODO only
records the target rule and the current worklist.

## Implementation Plan

1. Add a guardrail test that finds handler-to-handler intent enqueues outside
   recurring handlers, with a temporary allowlist for the cleanup candidates.
2. Move live-tail and response sends to projector-emitted intents where the
   originating fact directly implies both operations.
3. Keep `share_fact_with_sync` replayable for sync-index rebuilds, but make any
   live send a separately emitted live-only intent.
4. Decide whether `send_facts_on_connection -> send_network_frame` should remain
   a terminal transport-packaging step or become a direct network row write.
5. Remove each cleanup candidate from the allowlist as the corresponding
   handler chain is flattened.
6. Commit the completed work on that same worktree branch before handoff or
   review.

## Tests

Implementation should include realistic tests for:

- Replay admits only routes with `runs_during_replay=true`.
- A replayable handler cannot enqueue a live-only child through an untracked
  chain.
- `share_fact_with_sync` rebuilds the sync index during replay without creating
  live network send work.
- Recurring `maintain_connections` can enqueue bootstrap attempts only after the
  replay barrier.
- The guardrail test fails on any new non-recurring handler chain unless it is
  explicitly allowlisted while being retired.

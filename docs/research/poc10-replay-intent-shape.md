# poc-10 Replay And Intent Shape

This note describes the runtime shape needed before protocol versioning work.
It does not define release ceilings, old-client compatibility, or fact-version
migration. The goal is narrower: make poc-10 safe to wipe derived state, replay
retained facts, and resume operational work without preserving queued intents.

## Target Invariants

- Retained facts, including retained local facts, are the durable source of
  truth. Core schema marks fact storage and local admission metadata as
  rebuild-protected, so rebuild reset cannot delete them. Queued intents are not
  protocol truth.
- Every poc-10 queued intent is droppable on upgrade. After replay, required
  work is recreated from retained facts, replay-mode projection, context, or
  normal live runtime scheduling.
- Projectors are deterministic over fact bytes plus projection context,
  including replay mode. Durable truth projectors rebuild rows and context in
  replay; live session/negotiation projectors validate retained evidence and
  intentionally emit no live state when `ProjectionContext::is_replay()` is
  true.
- Core owns replay scheduling. During replay, core queues retained facts in
  replay mode and passes replay mode to handlers; projectors and handlers make
  live-only no-op decisions at their own effect edges.
- Db and schema declarations own table lifecycle. Core and protocol schema
  sources declare retained fact-store tables, resettable runtime tables, and
  state-summary tables; replay does not discover a keep-list from SQLite.
- All durable wall-clock `TimeWake` behavior must be replayable. If a
  wall-clock action is operational and not replayable, it must be a recurring
  intent instead.
- Local secrets are local facts until ordinary purge or retirement facts remove
  them. Upgrade replay uses the same purge and retirement rules as an endpoint
  that was offline and later catches up.
- Recurring operational work is not durable state. The daemon installs it from
  the existing intent registry while the process is online.

## Runtime Changes

Add an explicit replay entry point to core runtime:

1. Stop handler dispatch and network activity.
2. Drop durable and local queued intents.
3. Clear schema-declared replay-resettable state: read-model rows, sync
   indexes, context edges, `time_wakes`, pending projection rows, pending time
   ranges, ephemeral projection inputs, intent queues, temp network queues, and
   local clock observations. The retained fact store (`facts` plus local
   admission metadata) is outside the resettable table set.
4. Mark all retained facts pending for projection in replay mode.
5. Drain fact projection; projectors decide from replay context whether to
   rebuild durable state or no-op live session/negotiation state.
6. Admit replayable semantic time wakes to fixpoint.
7. Drain replay work to fixpoint: pending fact projection, context match
   wakeups, replayable semantic time wakes, and queued intents running with
   replay-mode handler context.
   Each pass may create facts, rows, context, semantic time wakes, or more
   queued intents.
8. Finish all replay work before network activity resumes.
9. Start the daemon, install recurring intents from the handler registry, and
   resume normal dispatch.

Replay is allowed to use wall-clock context only through replayable semantic
time-wake timelines. It must not run connection maintenance, bootstrap retry,
presence refresh, sync polling, or network sends.

## Handler Registry And Replay Context

Keep the existing `HandlerRoute` registry as the dispatch table and recurring
schedule source:

```rust
pub struct HandlerRoute {
    pub name: &'static str,
    pub intent_kind: &'static str,
    pub factory: HandlerFactory,
    pub recurrence: Option<RecurringIntentSpec>,
}
```

Replay mode is not a route-table flag. Core dispatches queued intents with
`HandlerContext::is_replay()` set, and each handler chooses whether to rebuild
deterministic state or return empty effects.

Handlers that do work during replay must be deterministic rebuild work. They
may create facts or local rows from retained facts. Handlers must not use
network IO, fresh randomness, process-global mutable state, or operational
wall-clock decisions while `HandlerContext::is_replay()` is true.

Initial poc-10 policy:

| Work surface | Replay behavior |
| --- | --- |
| `share_fact_with_sync` | Rebuilds sync-derived state during replay, but skips live tail advertisements. |
| `key_wrap_creation` facts | Project deterministically from retained recipient/request facts plus retained local source and signer facts to recreate `key_wrap` facts. |
| `key_wrap_recovery` facts | Project deterministically from retained wrap, recipient, frontier, and local recipient-key facts to recreate local secret facts. Ordinary purge/retirement rules decide whether those local secret facts survive. |
| `create_connection` | Returns no effects during replay. Network-visible response work must be rebuilt from committed request/response facts after replay. |
| accepted bootstrap peer projection | Rebuilt during replay from retained local `invite_accepted` facts; live maintenance consumes those rows after the replay barrier. |
| sync compare/have/need/send intents | Do not run during replay. They are live session prompts or send packaging. |
| bootstrap, connection-frame, network-send, receive-network intents | Do not run during replay. They are operational IO attempts. |

Replay mode stays out of the route table. A test should fail if routing tries to
encode replay policy instead of letting the handler or projector own its own
effect edge.

## Recurring Intents

Operational repetition belongs in the intent registry, not in durable time
wakes and not in projectors.

```rust
pub struct RecurringIntentSpec {
    pub interval_ms: u64,
    pub initial_delay_ms: u64,
    pub build_intent: fn(&Db) -> Result<Option<Intent>, String>,
}
```

Daemon startup installs in-memory schedules for handler routes with recurrence.
The schedules are not persisted. There is nothing to wipe on upgrade and
nothing to replay. Recurring intents do not fire until replay has completed and
the daemon is running normally.

Use recurring intents for live operational loops:

- `maintain_connections`
- presence refresh
- sync polling, if a poller is added
- bootstrap retry planning

Use durable `TimeWake` only when the wake changes replayable protocol state:

- disappearing-message expiry
- retention and purge eligibility
- durable retirement deadlines, if modeled by time

`content_message_expiry` stays a durable semantic timeline. The current
`connection_peer_retry` timeline should be removed from daemon time wakes and
replaced by recurring connection maintenance.

## Connection Maintenance

Connection retry should not be owned by historical `request` facts.
The operational goal is to keep the local endpoint connected to enough peers in
a potentially large endpoint set.

Retained local `invite_accepted` facts are the replay source for accepted
bootstrap peers. Their projection writes `invite_accepted_rows`, including the
bootstrap endpoint/address/secret from the accepted link, and offers
`connection_invite_secret` under the derived invite-secret id. A live recurring
`maintain_connections` intent consumes those rows plus connection-owned request
and attempt rows.

`maintain_connections` must not invent peers by broad-querying endpoint-owned
membership tables. It reads accepted bootstrap peer rows, unanswered request
rows, answered connection rows, and request-owned
`bootstrap_connection_attempt_rows`. It creates connection attempts and request
facts only as live work after rebuild/readiness has completed, and records one
attempt row per accepted invite to avoid forking duplicate requests.

Replay rebuilds accepted bootstrap peer rows by replaying retained
`invite_accepted` facts. The recurring `maintain_connections` intent is
live-only and starts after storage is ready, once those rows have been rebuilt.

Bootstrap connection attempts are covered by this maintenance loop. A replayed
`invite_accepted` row makes the accepted invite eligible. A later live
`maintain_connections` tick creates local ephemeral handshake material plus the
sealed request fact, and normal request projection materializes the retryable
request row. If that send is dropped or fails, the next live maintenance tick
re-queries unanswered request rows and retries. There is no separate durable
`connection_peer_retry` loop.

Connection request projection should validate and materialize request history.
It should not own an operational retry loop and should not emit
`connection_peer_retry` wakes. Bootstrap sends become local attempts created by
connection-maintenance decisions.

`create_connection` is flat fact creation. It must not send network bytes before
the responder ephemeral and `connection` facts commit.
The safe shape is:

- create or reuse the durable local connection fact;
- commit them first;
- queue a local send derived from the committed response;
- if the send is lost, later live request retry or connection maintenance can
  re-emit the send from committed facts.

## Key Material

`key_wrap_creation` local facts replay because they are deterministic projection
work. If the recipient/key-request facts and required local source and signer
facts remain, projection emits the same `key_wrap` fact. If the local source was
purged or retired, ordinary context rules park or suppress the work.

`key_wrap_recovery` local facts replay under the same rule: deterministic local
fact creation only. They carry ids, not plaintext key material. Opened local
secrets are represented by local facts and are retained or removed by the normal
purge/retirement facts.

## CLI Test Surface

Add CLI commands that exercise protocol update and rebuild diagnostics without
making replay a separate public upgrade command:

- `update`: author a local protocol update fact. Its live projection records the
  current protocol version, requests the generic rebuild effect, and leaves the
  retained update fact as audit history. Replay-mode projection of update facts
  is a no-op, so old update facts remain records without re-triggering rebuild.
- `state-summary`: print a stable hashable summary of rebuild-relevant state:
  retained facts, materialized rows, context edges, semantic time wakes, sync
  indexes, local key-material rows, and connection-maintenance rows. The output
  should include one overall `state_hash` plus per-area hashes and counts for
  schema-declared summary tables, computed from canonical row serialization
  with deterministic ordering. Volatile scheduler state, socket state, temp
  network queues, and wall-clock timestamps that are not protocol state stay
  out of the summary because their schema sources do not mark them
  summary-visible.
- `intent-registry`: list every handler route with recurrence metadata and
  command exclusion. Replay behavior is visible in handler code through
  `HandlerContext::is_replay()`, not in route metadata.
- `recurring-intents`: list recurring intent specs from the handler registry.
  The output should come from static registry metadata, not persisted job rows.
- `recurring-run KIND --now MS`: test one recurring intent kind without
  starting the daemon. It builds the registered recurring intent for the given
  time and runs the normal handler path once, with network send handlers still
  excluded unless the test explicitly opts in.
- `connection-maintenance-status`: print the connection maintenance view:
  accepted bootstrap peer rows, active attempts, active connections, target
  count, and pending local bootstrap sends.

These commands should make side effects visible. `state-summary` should remain
a read-only digest over schema-declared summary tables; update/rebuild behavior
is exercised through ordinary daemon/runtime projection.

## Test Plan

- Registry test: `HandlerRoute` has no replay policy flag, and live/session
  handlers explicitly branch on `HandlerContext::is_replay()`.
- Registry test: recurring operational intents are declared in handler-route
  metadata, not in projectors or durable time-wake declarations.
- Time-wake test: every daemon `TimeWake` timeline is replayable; connection
  retry is not listed as a daemon time wake.
- Replay test: old queued intents are dropped, retained facts replay, and
  required sync/key-wrap work is recreated.
- Replay test: network and connection-send handlers receive replay context and
  return empty effects before the replay barrier completes.
- Sync test: shareable-fact rows and negentropy summaries are wiped and rebuilt
  from retained facts.
- Key-wrap test: replay projection of `key_wrap_creation` recreates the same
  deterministic `key_wrap` fact without duplicate meaning.
- Recovery test: replay projection of `key_wrap_recovery` creates deterministic
  local secret facts and respects existing purge/retirement facts.
- Connection test: daemon startup installs the recurring
  `maintain_connections` schedule in memory, and no persisted job row exists.
- Connection test: replay no longer recreates bootstrap retries from old
  `request` history alone.
- Bootstrap test: replay rebuilds accepted bootstrap peer rows from
  `invite_accepted` but creates no bootstrap send before recurring maintenance
  runs.
- Bootstrap test: `recurring-run maintain_connections --now MS` creates or
  retries bootstrap attempts from accepted bootstrap peer rows and
  request-owned attempt rows, not by scanning endpoint membership tables.
- Recurring-intent test: `recurring-intents` and `intent-registry` show
  `maintain_connections` as live-only recurring work and show no persisted
  recurring job rows.
- Update CLI test: `update` plus the ordinary daemon loop rebuilds projected
  rows from retained facts and unblocks guarded queries.
- State-summary CLI test: `state-summary` reports a stable digest and per-area
  hashes without mutating live database state.

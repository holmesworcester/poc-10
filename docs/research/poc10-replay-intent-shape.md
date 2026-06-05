# poc-10 Replay And Intent Shape

This note describes the runtime shape needed before protocol versioning work.
It does not define release ceilings, old-client compatibility, or fact-version
migration. The goal is narrower: make poc-10 safe to wipe derived state, replay
retained facts, and resume operational work without preserving queued intents.

## Target Invariants

- Retained facts, including retained local facts, are the durable source of
  truth. Core schema marks fact storage and local admission metadata as
  replay-protected, so replay reset cannot delete them. Queued intents are not
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
  replay mode and may suppress or defer emitted intents according to
  intent-registry metadata.
- Store and schema declarations own table lifecycle. Core and protocol schema
  sources declare protected input tables, resettable derived/queue tables, and
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
   ranges, ephemeral projection inputs, intent queues, and temp network queues.
   Protected inputs such as retained facts, local fact admissions,
   clock/trusted-time observations, and local facts not covered by retained
   purge or retirement facts are outside the resettable table set.
4. Mark all retained facts pending for projection in replay mode.
5. Drain fact projection; projectors decide from replay context whether to
   rebuild durable state or no-op live session/negotiation state.
6. Admit replayable semantic time wakes to fixpoint.
7. Drain replay-allowed work to fixpoint: pending fact projection, context
   match wakeups, replayable semantic time wakes, and replay-allowed intents.
   Each pass may create facts, rows, context, semantic time wakes, or more
   replay-allowed intents.
8. Finish all replay-required work before network activity resumes.
9. Start the daemon, install recurring intents from the handler registry, and
   resume normal dispatch.

Replay is allowed to use wall-clock context only through replayable semantic
time-wake timelines. It must not run connection maintenance, bootstrap retry,
presence refresh, sync polling, or network sends.

## Intent Registry

Extend the existing `HandlerRoute` metadata rather than creating a second
registry:

```rust
pub struct HandlerRoute {
    pub name: &'static str,
    pub intent_kind: &'static str,
    pub factory: HandlerFactory,
    pub runs_during_replay: bool,
    pub recurrence: Option<RecurringIntentSpec>,
}
```

`runs_during_replay` answers one question: if this intent is emitted while
replay is rebuilding facts and rows, may core dispatch it before the replay
barrier finishes?

Replay-enabled handlers must be deterministic rebuild work. They may create
facts or local rows from retained facts. They must not use network IO, fresh
randomness, process-global mutable state, or operational wall-clock decisions.

Initial poc-10 policy:

| Intent kind | Replay behavior |
| --- | --- |
| `share_fact_with_sync` | Runs during replay if kept as an intent; it rebuilds sync-derived state. |
| `create_key_wrap` | Runs during replay; it deterministically creates idempotent `key_wrap` facts from retained recipient/request facts plus retained local source and signer facts. |
| `unwrap_key_wrap` | Runs during replay if its handler only creates deterministic local secret facts from retained wrap, recipient, frontier, and local recipient-key facts. Ordinary purge/retirement rules decide whether those local secret facts survive. |
| `create_connection` | Does not run during replay. Network-visible response work must be rebuilt from committed request/response facts after replay. |
| connection candidate registration intents | Run during replay; they rebuild connection-maintenance-owned candidate rows from endpoint/auth facts. |
| sync compare/have/need/send intents | Do not run during replay. They are live session prompts or send packaging. |
| bootstrap, connection-frame, network-send, receive-network intents | Do not run during replay. They are operational IO attempts. |

Every handler route should declare this flag. A test should fail if a new
handler route omits the handler replay decision.

## Recurring Intents

Operational repetition belongs in the intent registry, not in durable time
wakes and not in projectors.

```rust
pub struct RecurringIntentSpec {
    pub interval_ms: u64,
    pub initial_delay_ms: u64,
    pub build_intent: fn(&Store) -> Result<Option<Intent>, String>,
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

Add replay-allowed candidate-registration intents plus a live recurring
`maintain_connections` intent.

Endpoint/auth projectors decide which endpoints are valid connection
candidates. They should not run the maintenance loop directly. Instead they
emit replay-allowed registration work such as
`register_connection_candidate` and, when needed,
`unregister_connection_candidate`. Those handlers own the
connection-maintenance candidate index.

`maintain_connections` must not discover peers by broad-querying auth or
endpoint-owned tables. It reads only connection-maintenance-owned state:
candidate rows, active connection rows, active attempt rows or facts, recent
failure/backoff rows, and target connection policy. It then chooses peers
needed to maintain the target connection count, creates connection attempts and
request facts, closes excess or stale attempts through protocol-owned
close/abandon facts or rows, and records backoff or failure state in
connection-maintenance-owned storage.

Replay rebuilds the candidate table by replaying endpoint/auth facts and
dispatching replay-allowed candidate-registration intents. The recurring
`maintain_connections` intent is live-only and starts after replay, once the
candidate index has been rebuilt.

Bootstrap connection attempts are covered by this maintenance loop. A
successful candidate registration makes an endpoint eligible. A later live
`maintain_connections` tick chooses that endpoint, creates the local attempt
and request facts, and queues the local bootstrap send attempt. If that send is
dropped or fails, the next live maintenance tick re-evaluates the
connection-maintenance index and retries according to connection-owned target
count and backoff state. There is no separate durable
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

`create_key_wrap` can run during replay because it is deterministic fact
creation. If the recipient/key-request facts and required local source and
signer facts remain, it emits the same `key_wrap` fact. If the local source was
purged or retired, ordinary context rules suppress the work.

`unwrap_key_wrap` can run during replay under the same rule: deterministic
local fact creation only. It must carry ids, not plaintext key material, in the
intent payload. Opened local secrets are represented by local facts and are
retained or removed by the normal purge/retirement facts.

## CLI Test Surface

Add CLI commands that exercise replay and recurring intents without requiring
an actual upgrade:

- `replay [--reverse | --scramble --seed N]`: run the replay entry point with
  network and recurring schedules disabled. The default pass uses canonical
  fact order, `--reverse` admits retained facts newest-first, and `--scramble`
  admits retained facts plus replay-allowed work in a deterministic shuffled
  order. Each pass drops queued intents, wipes derived state, projects retained
  facts, admits replayable semantic time wakes, drains replay-allowed work to
  fixpoint, and prints counters for dropped intents, projected facts, context
  match wakeups, semantic time wakes, replay-allowed intents, emitted facts,
  purged facts, row mutations, and blocked network/live-only work.
- `state-summary`: print a stable hashable summary of replay-relevant state:
  retained facts, materialized rows, context edges, semantic time wakes, sync
  indexes, local key-material rows, and connection-maintenance rows. The output
  should include one overall `state_hash` plus per-area hashes and counts for
  schema-declared summary tables, computed from canonical row serialization
  with deterministic ordering. Volatile scheduler state, socket state, temp
  network queues, and wall-clock timestamps that are not protocol state stay
  out of the summary because their schema sources do not mark them
  summary-visible.
- `replay-check`: copy the database to scratch snapshots, run canonical replay,
  an idempotent replay, `replay --reverse`, and several
  `replay --scramble --seed N` passes, then compare the same state summary
  `state_hash` for every pass. It should prove replay idempotence, projection
  order independence, replay-allowed work interleaving independence, and report
  the per-area hash/count differences for any table or owned-state area whose
  replay-derived rows diverge.
- `intent-registry`: list every handler route with `runs_during_replay`,
  recurrence metadata, command exclusion, and whether the route can perform
  network IO.
- `recurring-intents`: list recurring intent specs from the handler registry.
  The output should come from static registry metadata, not persisted job rows.
- `recurring-run KIND --now MS`: test one recurring intent kind without
  starting the daemon. It builds the registered recurring intent for the given
  time and runs the normal handler path once, with network send handlers still
  excluded unless the test explicitly opts in.
- `connection-maintenance-status`: print connection-maintenance-owned state:
  candidate rows, active attempts, active connections, backoff rows, target
  count, and pending local bootstrap sends. It must not read auth-owned tables
  directly.

These commands should make side effects visible. A replay command that causes
network rows, live-only local intents, recurring scheduler fires, or
maintenance attempts before the replay barrier should report an error.

## Test Plan

- Registry test: every `HandlerRoute` has `runs_during_replay` set explicitly.
- Registry test: recurring operational intents are declared in handler-route
  metadata, not in projectors or durable time-wake declarations.
- Time-wake test: every daemon `TimeWake` timeline is replayable; connection
  retry is not listed as a daemon time wake.
- Replay test: old queued intents are dropped, retained facts replay, and
  required sync/key-wrap work is recreated.
- Replay test: network and connection-send handlers are not dispatched before
  the replay barrier completes.
- Sync test: shareable-fact rows and negentropy summaries are wiped and rebuilt
  from retained facts.
- Key-wrap test: replay dispatch of `create_key_wrap` is idempotent and creates
  no duplicate meaning when the same wrap already exists.
- Unwrap test: replay dispatch of `unwrap_key_wrap` is idempotent, creates
  deterministic local secret facts, and respects existing purge/retirement
  facts.
- Connection test: daemon startup installs the recurring
  `maintain_connections` schedule in memory, and no persisted job row exists.
- Connection test: replay no longer recreates bootstrap retries from old
  `request` history alone.
- Bootstrap test: replay rebuilds the connection candidate index but creates no
  bootstrap send before recurring maintenance runs.
- Bootstrap test: `recurring-run maintain_connections --now MS` creates or
  retries bootstrap attempts from connection-maintenance-owned candidate rows,
  not by scanning auth-owned endpoint tables.
- Recurring-intent test: `recurring-intents` and `intent-registry` show
  `maintain_connections` as live-only recurring work and show no persisted
  recurring job rows.
- Replay CLI test: `replay-check` reports the same state summary digest for
  canonical replay, idempotent replay, reverse projection order, and scrambled
  replay order, with zero network/live-only side effects during every pass.
- Replay order test: `replay --reverse` and `replay --scramble --seed N`
  produce the same state summary as canonical replay while exercising different
  projection order and replay-allowed work interleavings.

# poc-10 Replay And Intent Shape

This note describes the runtime shape needed before protocol versioning work.
It does not define release ceilings, old-client compatibility, or fact-version
migration. The goal is narrower: make poc-10 safe to wipe derived state, replay
retained facts, and resume operational work without preserving queued intents.

## Target Invariants

- Retained facts, including retained local facts, are the durable source of
  truth. Queued intents are not protocol truth.
- Every poc-10 queued intent is droppable on upgrade. After replay, required
  work is recreated from retained facts, replayed rows, context, or normal live
  runtime scheduling.
- Projectors are deterministic and replay-blind. Given the same facts and
  context, they emit the same rows, needs, offers, semantic time wakes, and
  intent requests.
- Core owns replay mode. During replay, core may suppress or defer emitted
  intents according to intent-registry metadata; projectors do not branch on
  replay.
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
3. Wipe derived state: read-model rows, sync indexes, context edges,
   `time_wakes`, pending projection rows, pending time ranges, ephemeral
   projection inputs, and temp network queues. Keep retained facts, local fact
   admissions, clock/trusted-time observations, and local facts not covered by
   retained purge or retirement facts.
4. Mark all retained facts pending for projection.
5. Drain fact projection.
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
| `unwrap_key_wrap` | Recreated from facts but dispatched after the replay barrier; ordinary purge/retirement rules decide whether local secret facts survive. |
| `create_connection_response` | Does not run during replay. Network-visible response work must be rebuilt from committed request/response facts after replay. |
| sync compare/have/need/send intents | Do not run during replay. They are live session prompts or send packaging. |
| bootstrap, connection-frame, network-send, receive-network intents | Do not run during replay. They are operational IO attempts. |

Every handler route should declare this flag. A test should fail if a new
handler route omits the replay decision.

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

Connection retry should not be owned by historical `connection_request` facts.
The operational goal is to keep the local endpoint connected to enough peers in
a potentially large endpoint set.

Add a recurring `maintain_connections` intent:

1. The handler reads local endpoint state, known endpoint/shared-auth rows,
   current connection rows, active attempt rows or facts, recent failures, and
   target connection policy.
2. It chooses peers needed to maintain the target connection count.
3. It creates connection attempts and request facts for selected peers.
4. It closes excess or stale attempts through protocol-owned close/abandon
   facts or rows.
5. It records backoff or failure state as local derived state or local facts,
   depending on whether the information must survive restart.

Connection request projection should validate and materialize request history.
It should not own an operational retry loop and should not emit
`connection_peer_retry` wakes. Bootstrap sends become local attempts created by
connection-maintenance decisions.

`create_connection_response` needs an atomicity fix. It must not send network
bytes before the responder ephemeral fact and `connection_response` fact commit.
The safe shape is:

- create or reuse the durable local response facts;
- commit them first;
- queue a local send derived from the committed response;
- if the send is lost, later live request retry or connection maintenance can
  re-emit the send from committed facts.

## Key Material

`create_key_wrap` can run during replay because it is deterministic fact
creation. If the recipient/key-request facts and required local source and
signer facts remain, it emits the same `key_wrap` fact. If the local source was
purged or retired, ordinary context rules suppress the work.

`unwrap_key_wrap` should be rebuilt from facts but run after the replay barrier.
It must carry ids, not plaintext key material, in the intent payload. Opened
local secrets are represented by local facts and are retained or removed by the
normal purge/retirement facts.

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
- Unwrap test: replay recreates `unwrap_key_wrap` work from facts but does not
  dispatch it until after the replay barrier.
- Connection test: daemon startup installs the recurring
  `maintain_connections` schedule in memory, and no persisted job row exists.
- Connection test: replay no longer recreates bootstrap retries from old
  `connection_request` history alone.

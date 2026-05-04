# Negentropy Recommendations

## Scope

This note records the current design decisions for real dep-aware negentropy in
`poc-8`. It is planning guidance, not an implementation status report.

The goal is to sync outer-valid shared events, including blocked events, using
incremental negentropy state. The system should not rebuild the index on demand,
and it should not keep the sync index fully current unless there is sync work
that needs it.

## Shareable Events

Blocked shared events are shareable. A blocked event has already passed the
outer event boundary: canonical bytes parse, the event id matches the bytes, the
event has a shared scope, outer validation has succeeded, and any missing
dependencies are represented as blocker rows. Some events may contain ciphertext
whose inner validity is unknowable locally, so sync should advertise the
outer-valid dependency graph rather than wait for full projection.

Rejected events are not shareable. Transient connection-scoped sync control
events are not part of the durable shareable event set.

Use a durable event-pipeline log:

```text
shareable_events:
  share_seq integer primary key
  event_id unique not null
  scope_key not null
  sync_key not null
  status_at_share not null  # blocked | ready | applied
  shared_at_ms not null
```

`shareable_events` is owned by `protocol/event_modules/worker.rs`, or whatever
event-scoped pipeline worker owns canonical admission. It is not owned by the
sync module. The event worker writes this row in the same transaction that
records the event and its status/blockers, so consumers never see a shareable
event without the matching event row.

The ownership split is:

```text
event_modules/worker.rs
  owns event admission, dependency blocking, event status, and shareable_events

sync/worker.rs
  consumes shareable_events and owns the negentropy index/cursors
```

## Lazy Indexing

The sync worker should not consume `shareable_events` simply because new rows
exist. Indexing is lazy and request-driven.

The sync module owns a cursor over the event-pipeline log:

```text
sync_index_cursor:
  scope_key primary key
  last_share_seq not null
```

Accepted negentropy compare/control events project to sync-owned request rows:

```text
sync_negentropy_requests:
  request_seq integer primary key
  connection_id not null
  scope_key not null
  required_share_seq not null
  kind not null              # root_compare | exact_root_compare | start_root_compare
  payload not null
  status not null
```

Transit unwrap does not call sync directly. It writes raw canonical ingress.
Canonical admission accepts or rejects the negentropy compare/control event.
When an accepted negentropy compare/control event is projected, that projector
records `required_share_seq` as the current `shareable_events` frontier for the
event's `scope_key`. A user-triggered local sync should also enter through this
shape when possible, by admitting a local start-compare event whose projector
writes `kind = start_root_compare`. A thin CLI adapter may write the same request
row directly only when there is no useful local event to project.

`sync::worker.run` should do no work if there are no pending
`sync_negentropy_requests`.

When requests exist, the worker:

1. Groups pending requests by `scope_key`.
2. For each scope, reads the maximum pending `required_share_seq`.
3. Consumes `shareable_events` after `sync_index_cursor.last_share_seq` up to
   that required frontier.
4. Incrementally updates dep-aware negentropy state.
5. Advances `sync_index_cursor` in the same transaction as the index updates.
6. Processes only requests whose `required_share_seq <= last_share_seq`.

The core invariant is:

```text
Never answer a negentropy request against an index older than that request's
required_share_seq.
```

The worker does not need to include events that became shareable after the
request was recorded. Those events can wait for the next inbound request or the
next local sync-start request.

`sync_key` should be `timestamp_be || event_id`. Range sync can then ask for a
recent suffix, such as "last day", and reconcile only recent roots at the
range-tree leaves. Dependency repair is handled by dep-aware closure sends, not
by widening the root range to old history.

## Dep-Aware Index State

poc-7's dep-aware sync has the right correctness shape. It does not recursively
search dependency graphs while answering every compare. It builds a
range-bounded root storage whose fingerprint combines:

```text
root ids in the slice
+ present transitive dependency ids required by those roots
  excluding ids that are themselves roots in the same slice
```

Use that combined fingerprint in `poc-8`, but do not add a separate dependency
reconciliation round. The simpler recommended flow is:

```text
Root reconciliation:
  compare root ranges using combined fingerprint
  record:
    have_root_ids
    need_root_ids
    dep_probe_root_ids  # exact slices whose combined dependency fingerprint
                        # differs

Send:
  full present closure for have_root_ids + dep_probe_root_ids
  then have_root_ids
```

The receiver dedupes by event id, so already-present dependency bytes are
ordinary duplicate ingress. Missing deps arrive before roots if send ordering
puts closure ids first.

This is correct as long as both sides may respond to root-reconciliation
dep-probe slices by sending their own present closure. If a combined fingerprint
mismatch is caused by a dependency only the remote side has, the remote side's
symmetric root-reconciliation handling sends that dependency. If the mismatch
is caused by a dependency only we have, our handling sends it.

Keep a known-closure cache separately from the present-closure cache:

```text
known closure:
  all transitive dependency ids learned from outer dependency edges, whether or
  not the event bytes are locally present

present closure:
  transitive dependency ids that are locally present/shareable
```

Root-range fingerprints and sends use present closure. Known closure is still
useful for incremental propagation, estimating closure size, debug/audit views,
and proving that blocked outer-valid events advertise dependency edges even when
some dependency bytes are not locally present.

The sync worker maintains this state progressively. The exact schema can evolve,
but the first version should separate presence, root membership, direct
dependencies, known closure, present closure, node summaries, and cursor
state.

Index tables:

```text
sync_present:
  scope_key
  event_id
  sync_key
  status_at_share
  primary key(scope_key, event_id)

sync_roots:
  scope_key
  event_id
  sync_key
  primary key(scope_key, event_id)

sync_direct_deps:
  scope_key
  event_id
  dep_id
  primary key(scope_key, event_id, dep_id)

sync_dep_closure_known:
  scope_key
  root_event_id
  dep_id
  primary key(scope_key, root_event_id, dep_id)

sync_dep_closure_present:
  scope_key
  root_event_id
  dep_id
  primary key(scope_key, root_event_id, dep_id)

sync_dep_waiters:
  scope_key
  dep_id
  root_event_id
  primary key(scope_key, dep_id, root_event_id)

sync_node_summary:
  scope_key
  node
  root_count
  root_hash
  dep_count
  dep_hash
  primary key(scope_key, node)

sync_node_known_dep:
  scope_key
  node
  dep_id
  refcount
  primary key(scope_key, node, dep_id)

sync_node_present_dep:
  scope_key
  node
  dep_id
  refcount
  primary key(scope_key, node, dep_id)
```

For each newly consumed shareable event `r`:

1. Insert `r` into `sync_present`.
2. Decode and store its direct dependency ids in `sync_direct_deps`.
3. Build or update `sync_dep_closure_known(r)` by combining direct deps plus
   cached known closures for any deps already known.
4. Build or update `sync_dep_closure_present(r)` by combining only deps that are
   already in `sync_present`, plus their cached present closures.
5. Register waiters so that when a missing dependency later becomes shareable,
   newly learned closure rows propagate to roots that depend on it.
6. If `r` is a root for a sync scope/range, add it to `sync_roots` and update
   node summaries along its path.

When a dependency `d` later becomes shareable, the worker:

1. Inserts `d` into `sync_present`.
2. Builds or extends `d`'s known/present closures.
3. Finds roots waiting on `d`.
4. Copies only new known and present closure deltas into those roots.
5. Propagates the delta onward through `sync_dep_waiters`.
6. Updates affected node summaries.

Request-time compare must not recurse through dependency graphs. It reads
precomputed node summaries and exact root/present-closure rows only.

Do not stop building a root's global transitive closure just because a dep is
also a root somewhere else. The closure cache should remain complete. Dedupe
happens when building a node or slice summary: if dependency `d` is also a root
inside that same node/slice, exclude `d` from that node's external dep set
because `d` is already represented by the node's root contribution. `d`'s own
closure still contributes through `d` as a root.

Use separate hash domains for roots and dependencies. Use refcounts so repeated
dependency edges do not double-count or cancel out. Cycles should not recurse
forever; treat already-visiting ids as a no-op for the current propagation path.

## Request Handling

After the index is caught up to each request's required frontier, request
handling follows the poc-7 dep-aware root reconciliation shape, but sends
present closures directly.

Root reconciliation compares range roots with combined fingerprints:

```text
RootCompare(node, remote_count, remote_combined_fingerprint)
  if local summary matches:
    emit nothing
  else if node is splittable:
    emit child RootCompare events
  else:
    exchange exact root ids and combined fingerprint
    record:
      have_root_ids
      need_root_ids
      dep_probe_root_ids if combined fingerprint still differs
```

Sending uses present closure directly:

```text
closure_ids = present_closure(have_root_ids + dep_probe_root_ids)
send_ids = order_deps_before_roots(closure_ids, have_root_ids)
for id in send_ids:
  if id is in sync_present:
    emit SendEvent(connection_id, id) or equivalent durable send intent
```

Dependency-order each send batch so selected deps arrive before roots that
require them. The receiver still dedupes by event id, so sending a present
closure that partly overlaps the peer's state is acceptable.

The worker emits deterministic connection-scoped events or send intents through
normal command output. Those events are admitted by the event-module worker.
Local sync event projection writes connection outbox rows. The connection worker
wraps bytes and writes transport send rows.

Sync does not write sockets, does not create transit blobs, and does not own the
fact that a durable event is shareable.

## End-To-End Flow

```text
local or inbound canonical event
  -> event_modules/worker.rs
  -> parse + outer validation
  -> insert event as blocked/ready/applied
  -> insert shareable_events row if shared and outer-valid

inbound dep-sync control bytes
  -> transit unwrap
  -> RawEventIngress row
  -> canonical admission accepts negentropy compare/control event
  -> negentropy compare/control projector
  -> insert sync_negentropy_requests row with required_share_seq

local sync start
  -> local start-compare event, or thin CLI adapter when no event is useful
  -> negentropy compare/control projector or adapter
  -> insert sync_negentropy_requests row with required_share_seq

sync::worker.run
  -> if no pending requests, return
  -> catch index up to required_share_seq for pending scopes
  -> advance sync_index_cursor
  -> run root reconciliation requests
  -> compute present closure for have_root + dep_probe roots
  -> order closure sends before root sends
  -> emit deterministic send intents

connection::worker.run
  -> drain outbox
  -> wrap bytes
  -> write TCP send queue
```

## Transit Facts And Ingress Projection

Transit envelopes are not shared canonical event truth, but they can still be
modeled as facts about local system behavior. This is useful for deterministic
simulation and audit traces: a whole multi-client run can be described as facts
such as bytes received, transit unwrapped, transit dropped, raw inner events
queued, send attempted, and send failed.

Classify facts by how production sync treats them:

```text
Shared domain facts
  durable app/protocol facts intended to replicate across peers

Local operational facts
  local observations such as received bytes, unwrap success, unwrap drop,
  learned route, send attempt, send failure

Transient protocol facts
  connection-scoped compare/have/need/send intents that describe real protocol
  behavior but are not durable shared truth
```

For production negentropy, `shareable_events` includes only shared outer-valid
canonical events. Local operational transit facts do not enter
`shareable_events` unless the protocol intentionally syncs operational logs.
For simulation, local operational facts from all nodes may be collected into a
single trace so tests can assert complete causality.

Transit ingress can use projection naturally if the receipt itself is modeled as
a local/transient fact:

```text
TransitReceived(wire_id, origin, envelope_bytes)
```

The `TransitReceived` projector may use a scoped context fetcher for local
endpoint keys, bootstrap authorization, connection lookup, and connection
workspace scope. Local secret context is still context; it must be explicit and
owned by the transit/connection module.

Projection output remains rows only:

```text
TransitReceived + scoped context
  -> RawEventIngress(wire_id, index, auth_context, canonical_bytes)
  -> TransitUnwrapped(wire_id, connection_id?, auth_context, inner_count)

TransitReceived + scoped context
  -> TransitDropped(wire_id, reason, envelope_metadata)
```

There is no transit blocking/unblocking. If the local node lacks the bootstrap
key, connection key, connection row, or authorization context required to unwrap
the envelope, the projector returns a drop fact in debug/audit mode or no rows
plus metrics in normal mode. A later key should not resurrect old ingress unless
the protocol has an explicit replay/repair rule for local operational logs.

Candidate debug/audit row:

```text
transit_drop_facts:
  wire_id primary key
  origin
  envelope_kind              # malformed | bootstrap | connection
  connection_id null
  sender_endpoint null
  recipient_endpoint null
  reason                     # no_local_key | wrong_recipient | unknown_connection
                             # decrypt_failed | unauthorized_inner_scope | malformed
  seen_at_ms
```

Successful unwrap writes raw ingress rows. The normal event pipeline still
owns canonical admission:

```text
TCP receive
  -> TransitReceived

TransitReceived projector
  -> RawEventIngress rows
  or TransitDropped row

RawEventIngress worker/pipeline
  -> record_from_bytes(canonical_bytes)
  -> ingress authorization checks from auth_context
  -> event admission
  -> blocked/ready/applied
  -> shareable_events if shared and outer-valid
```

Outbound can be factored the same way for simulation without moving wrapping
into the network layer:

```text
NeedId / SendEvent / outbox
  -> TransitSendAttempted
  -> TransitWrapped
  -> TcpSendQueued
  -> TransitSent or TransitSendFailed
```

Core provides opaque network queues for protocol workers. There should be one
core outgoing network queue for all protocol network activity. Its destination
metadata is transport-shaped, such as IP/port or socket id, not semantic
connection ids.

Candidate core row:

```text
outgoing_network:
  network_seq integer primary key
  target_kind                  # ip_port | socket_id
  ip null
  port null
  socket_id null
  bytes not null               # opaque protocol-produced bytes
  status                       # pending | sent | failed
  not_before_ms
  attempts
  last_error null
  created_at_ms
```

Protocol workers may write this row, but core does not inspect the bytes. Core
owns queue mechanics, TCP framing, socket write attempts, retry/backpressure
metadata, and send completion state. The connection/transit worker owns the
semantic conversion from `connection_id` to a concrete transport target and the
creation of transit bytes.

Outbound production flow:

```text
sync::worker.run
  -> NeedId response creates deterministic SendEvent or send intent
  -> event admission/projection writes connection outbox row

connection/transit worker
  -> claims outbox(connection_id, event_id)
  -> loads canonical bytes for event_id
  -> checks connection/workspace authorization
  -> wraps bytes into transit envelope
  -> resolves connection_id to ip/port or socket id
  -> writes outgoing_network(target = ip/port, bytes = transit_blob)
  -> marks outbox sent only after core reports network send completion

core network worker
  -> claims outgoing_network
  -> writes TCP frame to target
  -> records sent/failed
```

For simulation and debug/audit, outbound operational facts can mirror the queue
state without changing the production boundary:

```text
TransitSendAttempted(connection_id, event_id, target)
TransitWrapped(connection_id, event_id, wire_id, byte_len)
NetworkSendQueued(network_seq, wire_id, target)
NetworkSendCompleted(network_seq)
NetworkSendFailed(network_seq, reason)
```

Those facts are useful trace material, but they are not shared domain events and
do not enter `shareable_events` unless the protocol explicitly syncs
operational logs.

The connection/transit module remains responsible for wrap/unwrap semantics.
The network layer still only moves bytes. The event pipeline remains
responsible for deciding whether unwrapped canonical bytes become accepted,
blocked, rejected, and shareable.

## North-Star Tests

The first dep-aware sync tests should be black-box CLI tests scoped to the
protocol event modules, not root-level protocol soup. They should prove that a
recent range can sync a recent leaf event without syncing unrelated old history,
while still sending the old dependencies required to project that recent event.

The sync id for these tests is `timestamp_be || event_id`. That is what makes
"latest leaves" meaningful: a recent suffix range contains the new message root
but excludes its old signer dependency roots.

### One Old Dependency

This is the smallest correctness proof:

```text
old signer dependency S:
  timestamp = now - 3 years

new message M:
  timestamp = now
  deps = [S]
```

Run a recent-range sync that includes `M` and excludes `S`.

Expected outcome:

1. The sender's recent root range contains `M`, not `S`.
2. The dep-aware fingerprint for that range includes present external dep `S`.
3. A mismatch causes the sender to send `S` before `M`.
4. The receiver projects `S`, then projects `M`.
5. The newest message is visible/projected on the receiver.
6. Old unrelated events outside the recent range are not sent.

This test should fail under plain timestamp range sync because `M` would arrive
blocked on missing `S`.

### Transitive Old Dependency Chain

The stress version keeps the same shape but makes the old dependency transitive:

```text
old signer chain:
  S0 timestamp = now - 3 years
  S1 timestamp = now - 3 years + 1, deps = [S0]
  ...
  S1000 timestamp = now - 3 years + 1000, deps = [S999]

new message M:
  timestamp = now
  deps = [S1000]
```

Run the same recent-range sync.

Expected outcome:

1. The sender's recent root range still contains only `M`.
2. The dep-aware present closure for `M` contains the full old chain
   `S0..S1000`.
3. The sender orders the chain before `M`.
4. The receiver projects the whole chain and then `M`.
5. The receiver does not pull unrelated old history.

This test proves the worker builds and stores transitive closure progressively.
It should not recursively walk the chain during request handling.

## Rollout Notes

1. Add the event-pipeline-owned `shareable_events` log.
2. Teach canonical admission to write `shareable_events` for shared outer-valid
   events, including blocked events.
3. Add sync-owned request rows and cursor/index tables.
4. Change negentropy compare/control event projectors to write request rows
   instead of answering inline.
5. Implement `sync::worker.run` as request-driven catch-up plus request
   handling.
6. Model transit receipt as local/transient facts whose projector writes
   `RawEventIngress`, `TransitUnwrapped`, or `TransitDropped` rows.
7. Route outbound wrapped bytes through the core outgoing network queue with
   IP/port or socket-id target metadata, not through protocol-specific socket
   writes.
8. Add tests that prove blocked outer-valid events enter `shareable_events`,
   lazy indexing does no work without pending requests, request handling catches
   the index up to `required_share_seq`, transitive known/present closures
   update incrementally, root fingerprints detect missing present deps, present
   closure sends include deps outside the root range, the one-old-dep recent
   message test projects the newest message without syncing unrelated old
   history, the transitive old-dep-chain variant projects the newest message,
   and duplicate inbound deps are ignored by normal event admission.
9. Add transit projector tests for unwrap success, drop facts, and raw ingress
   rows, plus pipeline tests proving raw ingress still goes through normal
   canonical admission before becoming shareable.
10. Add outbound tests proving connection/transit workers write opaque bytes to
    the core outgoing network queue and core never inspects transit or sync
    semantics.
11. Commit the completed work on the same worktree branch before handoff or
   review.

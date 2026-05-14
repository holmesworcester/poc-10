# New Architecture

This document describes the target architecture for the event pipeline,
context system, intents, handlers, transit, sync, encryption, and purge. It is
written as the destination design, not as a compatibility layer over the
current worker/label/blocking system.

The goal is to remove overlapping mechanisms and replace them with one small
set of primitives:

```text
facts
context needs
context offers
context matchers
pending projection
projectors
intents
intent handlers
```

There should be no permanent holdovers such as labels, blocked-event tables,
pending reprojection queues, worker-specific drain queues, or receive metadata
side channels. Existing code can migrate incrementally, but the end state
should not keep duplicate vocabulary.

## Design Principles

Core owns mechanics, not protocol meaning.

Projectors own protocol validation and decide what missing or present context
means.

Intent handlers own bounded stateful work and feed results back through facts
and intents.

Context is explicit. There are no hidden side channels for dependencies,
labels, receive metadata, key availability, or transport provenance.

Every destructive step is atomic when it runs. Large workflows are sequences of
bounded atomic steps driven by deferred intents.

Projectors may use `core::crypto` for encryption and decryption when the
operation is pure over the fact and provided context. Projectors still may not
do IO, broad scans, clock reads, process-local mutation, or nested event
admission.

## Facts

A fact is the generic unit of durable or local event state.

```rust
struct Fact {
    id: FactId,
    scope: FactScope,
    timestamp: u64,
    bytes: Vec<u8>,
}
```

Scope is generic. Core can index by scope, but projectors decide what a scope
means.

```rust
enum FactScope {
    Global,
    Local,
    Scoped { kind: ScopeKind, id: FactId },
}
```

Examples:

```text
Global
  root/bootstrap facts that are not scoped to an existing fact

Local
  local receive observations, local endpoint secrets, local operational facts

Scoped { kind: "workspace", id: workspace_fact_id }
  ordinary shared workspace facts

Scoped { kind: "connection", id: connection_id }
  connection-scoped sync facts

Scoped { kind: "invite", id: invite_fact_id }
  bootstrap facts before a workspace has projected
```

The current `workspace_id: Option<EventId>` should become this generic scope
field. Workspace remains a protocol concept, not a special core concept.

## Context

Projectors do not issue arbitrary broad queries. They receive context by
declaring needs and consuming matching offers.

```rust
struct ContextNeed {
    owner: FactId,
    role: Role,
    scope: FactScope,
    selector: Selector,
}

struct ContextOffer {
    owner: FactId,
    role: Role,
    scope: FactScope,
    selector: Selector,
    payload_ref: FactId,
}
```

Core does not know whether a need is required or optional. The projector
decides that by what it emits.

Required context example:

```text
message has no signer context
  -> emits Need(role="event", selector=signer_id)
  -> emits no message row
```

Optional future context example:

```text
message has no deletion context
  -> emits Need(role="message_deletion", selector=message_id)
  -> emits sealed_message row
```

Later, a deletion projects:

```text
message_deletion
  -> emits Offer(role="message_deletion", selector=target_message_id)
```

Core matches that offer to the message's standing need and wakes the message.
The message reprojects with deletion context and emits tombstone rows, deletes,
and purge intents.

### Replace Semantics

Each projection pass owns the current context surface for its fact.

Core diffs the new needs/offers against the old needs/offers for the same
owner:

```text
unchanged need/offer
  keep it and do not wake

new need
  insert it, match existing offers, wake owner if matches exist

new offer
  insert it, match existing needs, wake need owners

removed need/offer
  delete it
```

This avoids reproject loops from standing needs. A stable watch for future
deletions remains present, but it does not trigger a new wake every time the
projector re-emits it.

## Context Matchers

A `ContextMatcher` matches needs and offers for one role. Core owns lifecycle;
matchers own efficient role-specific lookup.

```rust
trait ContextMatcher {
    fn role(&self) -> Role;

    fn match_need_to_offers(
        &self,
        need: &ContextNeed,
        store: &Store,
    ) -> Result<Vec<ContextOfferRef>, String>;

    fn match_offer_to_needs(
        &self,
        offer: &ContextOffer,
        store: &Store,
    ) -> Result<Vec<FactId>, String>;
}
```

Core uses matchers in three places:

```text
new need
  -> find matching offers
  -> wake need owner

new offer
  -> find matching needs
  -> wake need owners

load context for projection
  -> resolve current needs to matching offers
  -> load offer payload refs
```

Match scopes are part of the key. Most roles are workspace-scoped, but not all.
Bootstrap roles may match by invite id, endpoint id, candidate workspace id, or
other exact authority-bearing selectors before a workspace has projected.

Core should reduce accidental cross-talk through scope and role. Projectors
still validate semantic correctness, including workspace membership, event
type, signer authority, endpoint role, and local/private state.

### Standard Matchers

Exact event matcher:

```text
Need(role="event", selector=event_id)
Offer(role="event", selector=event_id)
```

Secret coverage matcher:

```text
Need:
  role = "secret_coverage"
  selector = (workspace, frontier, minute, event_id_in_minute)

Offer:
  role = "secret_coverage"
  selector = (workspace, frontier, range_start, range_width, bit_depth, prefix)

match:
  same workspace
  same frontier
  offer time range covers need minute
  offer trie prefix covers need event_id_in_minute
```

Receive matcher:

```text
Need(role="receive.endpoint", selector=received_event_id)
Offer(role="receive.endpoint", selector=received_event_id)
```

Deletion matcher:

```text
Need(role="message_deletion", selector=message_id)
Offer(role="message_deletion", selector=message_id)
```

Recipient-key supersession matcher:

```text
Need(role="recipient_key_superseded", selector=recipient_key_id)
Offer(role="recipient_key_superseded", selector=recipient_key_id)
```

## Projectors

Projectors consume facts and matched context. They emit intents, needs, and
offers.

```rust
fn project(fact: Fact, context: Context) -> ProjectionOutput;

struct ProjectionOutput {
    intents: Vec<Intent>,
    needs: Vec<ContextNeed>,
    offers: Vec<ContextOffer>,
}
```

Projector rules:

```text
- Pure over fact plus provided context.
- May use core::crypto for deterministic encryption/decryption over context.
- Does not do IO.
- Does not read broad state.
- Does not mutate process-local state.
- Does not read the clock directly.
- Does not admit nested facts.
- Decides whether missing context prevents output or just creates a standing need.
- Emits the full current need/offer surface on every pass.
```

Projectors validate protocol semantics. Core may provide candidate context, but
the projector must still verify type, scope, workspace, signer, author,
endpoint, role, and authorization.

## Intents

Everything a projector or handler wants done is an intent.

```rust
struct Intent {
    kind: IntentKind,
    key: IntentKey,
    payload: Vec<u8>,
}
```

`IntentKind` declares its execution class:

```rust
enum IntentExecution {
    Atomic,
    Deferred,
}
```

A given intent kind is always atomic or always deferred. If an operation
sometimes needs deferred behavior, split it into two intent kinds.

Atomic intents are exact, bounded, deterministic, and safe to apply in the
projection transaction:

```text
PutRow
DeleteRow
PutFactState
DeleteFactState
PurgeExactStorage
```

Deferred intents are stateful, retryable, asynchronous, or split across
transactions:

```text
PurgeEvent
DiscoverCascade
RetireSecret
MaterializeKeyWraps
UnwrapKey
DeriveLeaf
SendOnConnection
SendBootstrapRequest
SendHandshakeResponse
ReceiveTransit
NetworkSend
HandleSync
StartSync
SyncIndexUpdate
ExpireMinute
ChopFloor
ConnectionAttempt
ConnectionResponse
```

Core applies atomic intents immediately. Deferred intents go into
`core.intents` and are claimed by registered handlers.

## Intent Handlers

Handlers consume deferred intents.

```rust
fn handle(intent: Intent, ctx: HandlerContext) -> HandlerOutput;

struct HandlerOutput {
    intents: Vec<Intent>,
    facts: Vec<ProposedFact>,
}
```

Handler rules:

```text
- One handler owns each deferred intent kind.
- Handlers do bounded work per call.
- Handlers are idempotent by intent key.
- Handlers may use local/private/process/external state explicitly allowed for that kind.
- Handlers feed semantic results back as facts or intents.
- Handlers do not directly call other handlers.
- Handlers clear or replace the claimed intent only after durable progress is committed.
```

Handlers are allowed to use sockets, clocks, private keys, broad scans,
process-local sync indexes, post-commit sequencing, and local retention
mutation. Those capabilities are precisely why the work is not projector work.

## Core Loop

The runtime loop is:

```text
drain inbox
admit facts
enqueue pending projection

project pending facts
  load matched context from current needs/offers
  run projector
  apply atomic intents
  replace owner needs/offers by diff
  match new needs/offers and enqueue wakes
  persist deferred intents

claim deferred intents
dispatch to registered handlers
  handlers emit facts and intents

repeat until bounded work budget is exhausted
```

This replaces:

```text
Ready/Blocked/Applied scheduling logic
dependency unblock worker
labels
pending reprojection queue
recently valid queue
domain-specific pending worker queues
receive metadata side channels
```

## Core Schemas

The target core schema set is small:

```text
core.facts
core.inbox
core.needs
core.offers
core.pending_projection
core.intents
core.clock
core.network_in
core.network_out
```

`core.facts`

Stores fact bytes and generic metadata: id, scope, timestamp, status, and
retention/projection bookkeeping.

`core.inbox`

Staged local or remote canonical bytes plus optional receive/provenance
context. Receive/provenance should usually be converted into local receive
facts instead of carried as projection side-channel metadata.

`core.needs`

Current context needs emitted by each fact's latest projection.

`core.offers`

Current context offers emitted by each fact's latest projection.

`core.pending_projection`

Facts that should project or reproject.

`core.intents`

Deferred stateful work keyed by deterministic intent kind and key, with
claim/retry metadata.

`core.clock`

Store-backed logical clock state, if retained.

`core.network_in` and `core.network_out`

Optional transport-edge queues if network IO remains core-owned. If transport
becomes a pure handler-owned edge, these move under that handler.

## Event Module Projection Schemas

These are materialized fact state, read models, or protocol indexes. They are
not worker queues.

Identity:

```text
identity.workspaces
identity.users
identity.admins
identity.endpoint_shared
identity.endpoint_memberships
identity.local_endpoint
identity.local_endpoint_secret
identity.local_endpoint_signing_public_key
identity.local_endpoint_signing_secret
identity.invite_secrets
identity.invites_accepted
identity.invite_servers
identity.device_invites
identity.user_invites
```

Content:

```text
content.events
content.messages
content.sealed_messages
content.message_tombstones
content.reactions
content.sealed_reactions
content.files
content.files_by_message
content.files_by_file_id
content.file_slices
```

Encryption:

```text
encryption.removal_frontiers
encryption.disappearing_messages_settings
encryption.workspace_chop_floor
encryption.recipient_keys
encryption.local_recipient_keys
encryption.local_key_secrets
encryption.local_history_node_secrets
encryption.local_history_node_tombstones
encryption.key_wraps
encryption.key_secret_commitments
```

Connection:

```text
connection.connection_events
connection.request_connections
connection.connections
connection.invite_workspaces
connection.connection_scoped_events
connection.transport_targets
```

Sync:

```text
none required for durable semantic projection
```

Sync compare/have/need are connection-scoped facts. Their durable bytes can be
cached in `connection.connection_scoped_events` until sent or compacted.

Test-only:

```text
test_events.staged_event_with_deps
```

## Handler-Owned Checkpoint Schemas

Handlers should own private durable schemas only when needed for resumable
local state or checkpoints. They should not own hidden scheduling queues.
Scheduling lives in `core.intents`.

Current/future checkpoint schemas:

```text
content.purge_retire_coords
future content.purge_cascade_cursors
future sync.snapshots
future sync.cursors
```

`encryption.workspace_chop_floor` may remain an encryption projection table or
move to the expiry/chop handler as a checkpoint. The important point is that it
is persistent progress state, not a drain queue.

## Removed Or Collapsed Tables

These current tables disappear in the target architecture:

```text
event_modules.ready_events
event_modules.blocked_events_by_missing_dep
event_modules.missing_deps_by_blocked_event
event_modules.dependents_by_dep
event_modules.deps_by_dependent
event_modules.labels
event_modules.recently_valid_events
event_modules.pending_reprojections
event_modules.applied_shared_events
event_modules.event_receive_context
canonical.in
content.purge_instructions
encryption.pending_key_requests
encryption.pending_key_unwraps
encryption.pending_wrap_reconcile
connection.pending_connection_attempts
connection.pending_connection_responses
sync.in
transit.out
encryption.negentropy_pending_purges
```

They are replaced by:

```text
core.needs
core.offers
core.pending_projection
core.intents
core.inbox
local receive facts
```

## Receive Facts

Receive metadata should be represented as local facts about received facts.

```text
ReceiveFact {
    received_event_id,
    origin,
    local_endpoint,
    remote_endpoint,
    authorization,
    transit_kind,
    connection_id,
    request_id,
    received_at,
}
```

The receive fact offers context:

```text
Offer(
    owner = receive_fact_id,
    role = "receive.bootstrap_invite" | "receive.endpoint",
    selector = received_event_id,
    payload_ref = receive_fact_id,
)
```

This replaces `ReceiveMetadata` queue metadata and `event_receive_context`.

Advantages:

```text
receive context survives restart
duplicate receives are visible for debugging
multiple observations of one shared fact can coexist
projection consumes receive context through ordinary needs/offers
shared fact identity stays independent of local receive state
```

Receive facts are local operational facts. They should not sync as shared
history, and they can be compacted by local retention policy.

## Transit, Connection, And Sync

Transit, connection, and sync communicate through facts and intents, not direct
handler calls.

### Connection State

Connection projectors/handlers produce relationship state:

```text
connection.connection_events
connection.request_connections
connection.connections
connection.invite_workspaces
connection.transport_targets
```

Conceptually:

```text
ConnectionEstablished {
    connection_id,
    local_endpoint,
    remote_endpoint,
    connection_secret,
    authorized_scope,
}

TransportRoute {
    connection_id,
    addr,
}
```

### Transit Intents

Outbound after connection:

```text
SendOnConnection(connection_id, event_id)
```

Outbound before connection:

```text
SendBootstrapRequest(request_id, addr)
SendHandshakeResponse(response_id, request_id, addr)
```

Inbound:

```text
ReceiveTransit(frame)
```

Network edge:

```text
NetworkSend(addr, frame)
```

### Transit Send

`SendOnConnection` handler:

```text
load connection route
load connection secret
load remote endpoint
load event bytes
batch pending sends for same connection
wrap bytes into connection transit envelope
emit NetworkSend
clear SendOnConnection after durable handoff/send boundary
```

This is the replacement for `transit.out`.

### Transit Receive

`ReceiveTransit` handler:

```text
unwrap inbound frame
authenticate sender/recipient/connection
recover inner canonical bytes
classify each inner payload
emit inner facts
emit local ReceiveFact for each inner fact
```

Connection transit may carry:

```text
connection response facts
connection-scoped sync facts
shared workspace facts
```

It must reject facts outside the connection's authorized scopes.

### Bootstrap Cycle

Peer A has an invite/address and wants to connect to peer B.

```text
A creates connection_request fact
A projects request
  -> PutRow(connection_event)
  -> Intent(SendBootstrapRequest)

SendBootstrapRequest handler
  -> wrap request bytes to B endpoint key
  -> NetworkSend

B ReceiveTransit handler
  -> unwrap bootstrap frame with B local endpoint secret
  -> emit connection_request fact
  -> emit ReceiveFact about request

B connection_request projector
  -> consumes receive.bootstrap_invite context
  -> validates request, sender, invite secret
  -> PutRow(connection_event)
  -> Intent(ConnectionResponse)

ConnectionResponse handler
  -> create connection_response fact
  -> emit/propose response fact
  -> Intent(SendHandshakeResponse)

SendHandshakeResponse handler
  -> wrap response bytes using handshake material
  -> NetworkSend

A ReceiveTransit handler
  -> unwrap handshake response
  -> emit connection_response fact
  -> emit ReceiveFact about response

A connection_response projector
  -> consumes receive.endpoint context
  -> validates request, invite, ephemeral, handshake
  -> PutRow(connection)
  -> PutRow(request_connection)
  -> PutRow(transport_target)
```

After this, both peers have a connection id, route, remote endpoint, and
connection secret.

### Sync Cycle

Sync decides what event ids should move. Transit decides how bytes move.

Start:

```text
StartSync handler
  -> read scoped SyncIndex summary
  -> create compare fact
  -> compare projector caches connection-scoped fact
  -> Intent(SendOnConnection(compare_id))
```

Receive compare:

```text
ReceiveTransit
  -> emits compare fact scoped to connection

compare projector
  -> Intent(HandleSync(compare_id))

HandleSync handler
  -> compare remote summary to local summary
  -> if equal: no-op
  -> if small differing range: emit have_id facts
  -> if large differing range: emit child compare facts
```

Have/need:

```text
have_id received
  -> if local lacks id, emit need_id fact
  -> SendOnConnection(need_id)

need_id received
  -> if id can be sent on this connection
  -> SendOnConnection(connection_id, durable_event_id)
```

Shared fact delivery:

```text
ReceiveTransit
  -> unwrap shared event bytes
  -> verify connection authorizes event scope
  -> admit shared fact
  -> project fact
  -> update needs/offers/intents
  -> SyncIndexUpdate intent
```

The exchange repeats until range summaries match.

## Encryption And Key Healing

Keys use context needs/offers rather than hard dependencies.

Content facts that need a secret emit:

```text
Need(
    role = "secret_coverage",
    selector = (workspace, frontier, minute, event_id_in_minute),
)
```

Local key roots, retained history nodes, and accepted key wraps emit:

```text
Offer(
    role = "secret_coverage",
    selector = (workspace, frontier, range_start, range_width, bit_depth, prefix),
)
```

The `SecretCoverageMatcher` wakes content facts when coverage appears.

Projectors may decrypt/open content if the required key material is present in
context. This keeps plaintext read-model writes with the owning content
projector. If a crypto operation needs broad search, private state not present
as context, or follow-up admission, it should be a deferred intent instead.

Key requests are ordinary shared facts:

```text
key_request projector
  -> validates requester/responder/frontier/recipient key
  -> Intent(MaterializeKeyWraps)
```

Key wraps are ordinary shared facts:

```text
key_wrap projector
  -> validates signer/frontier/recipient
  -> PutRow(key_wrap)
  -> Offer(secret_coverage) if the wrap can serve as coverage context
  -> Intent(UnwrapKey) if local recipient material may open it
```

Deterministic/idempotent wrap keys prevent amplification:

```text
key_wrap edge = (workspace, frontier, recipient_key, target_coverage)
```

Proactive sharing becomes:

```text
recipient key offer appears
local secret coverage offer exists
  -> MaterializeKeyWraps intent creates missing deterministic wraps
```

Explicit requests use the same `MaterializeKeyWraps` handler. If the frontier
root is gone after deletion, the handler wraps retained history nodes instead
of resurrecting the root.

Recipient-key supersession is an update/offer, not a hard dependency on bytes
that might later be purged:

```text
recipient_key successor projector
  -> validates self-contained supersession authority
  -> DeleteRow(old recipient_key row)
  -> Offer(role="recipient_key_superseded", selector=old_recipient_key_id)
  -> Intent(PurgeRetiredRecipientMaterial)
```

## Purge And Retention

Semantic deletion projection and physical retention purge are separate.

Projector work:

```text
validate deletion/update fact
write tombstone/read-model deletes
emit deletion offer
emit PurgeEvent intent
```

Purge handler work:

```text
claim PurgeEvent
load target bytes if retained
compute exact purge consequences
commit bounded atomic purge step
emit RetireSecret intent
emit DiscoverCascade intent
emit SyncIndexPurge/SyncIndexUpdate intent
clear or replace PurgeEvent
```

Current `content_purge` is a bundle of:

```text
semantic deletion materialization
retention byte purge
cascade discovery
secret retirement
sync index repair
```

The target architecture splits those into separate intent handlers. Destructive
steps remain atomic, but the full workflow is intentionally multi-step.

## Codebase Migration Plan

The migration should temporarily bridge old code only inside short-lived
compatibility modules. The final state must remove every old queue, label, and
blocked-event table listed above.

### Phase 1: Introduce Core Types

Add the target types:

```text
Fact
FactScope
ContextNeed
ContextOffer
ContextMatcher
Intent
IntentKind
IntentExecution
ProjectionOutput { intents, needs, offers }
HandlerOutput { intents, facts }
```

Implement `PutRow` and `DeleteRow` as atomic intents. Existing projector row
outputs should be converted mechanically into these intent kinds.

### Phase 2: Add Core Tables

Add:

```text
core.facts
core.inbox
core.needs
core.offers
core.pending_projection
core.intents
```

Keep current tables only long enough to migrate tests and modules. Do not add
new behavior to old tables.

### Phase 3: Replace Projection Scheduling

Replace:

```text
Ready
Blocked
recently_valid_events
pending_reprojections
dependency_unblock worker
```

with:

```text
core.pending_projection
needs/offers
ExactEventMatcher
```

Exact dependency needs replace missing-dependency blocker edges. A fact whose
required context is absent simply emits needs and no validity/self offer.

### Phase 4: Replace Labels

Convert label uses to needs/offers:

```text
message deletion
file deletion
recipient key supersession
future about/update facts
```

Remove `event_modules.labels` and all label wake logic.

### Phase 5: Replace Receive Metadata

Introduce local receive facts and receive matchers.

Remove:

```text
ReceiveMetadata side-channel projection
event_receive_context
canonical.in receive metadata coupling
```

Transit receive should emit inner facts plus receive facts.

### Phase 6: Replace Worker Queues With Intents

Move these queues into `core.intents`:

```text
content.purge_instructions
encryption.pending_key_requests
encryption.pending_key_unwraps
encryption.pending_wrap_reconcile
connection.pending_connection_attempts
connection.pending_connection_responses
sync.in
transit.out
encryption.negentropy_pending_purges
event_modules.applied_shared_events
```

Each current worker becomes a registered intent handler.

### Phase 7: Transit And Connection Rewrite

Implement:

```text
SendBootstrapRequest
SendHandshakeResponse
SendOnConnection
ReceiveTransit
NetworkSend
```

Connection projectors produce connection state and connection intents. Transit
handlers consume connection state and produce facts/receive facts. No direct
handler calls.

### Phase 8: Sync Rewrite

Sync compare/have/need remain connection-scoped facts.

Replace `sync.in` and `transit.out` with:

```text
HandleSync
StartSync
SendOnConnection
SyncIndexUpdate
SyncIndexPurge
```

Sync decides ids and sync facts. Transit moves bytes.

### Phase 9: Secret Coverage Rewrite

Add `SecretCoverageMatcher`.

Move content key dependencies to:

```text
Need(secret_coverage coord)
Offer(secret_coverage range)
```

Projectors may decrypt/open content when matching key context is present.

Key request, key wrap, local key secret, and local history node projectors emit
coverage offers and deferred intents rather than worker queues.

### Phase 10: Purge Split

Split current `content_purge` into:

```text
PurgeEvent handler
DiscoverCascade handler
RetireSecret handler
SyncIndexPurge/SyncIndexUpdate handler
```

Keep `content.purge_retire_coords` or equivalent checkpoint state only if still
needed for crash recovery. Do not keep `content.purge_instructions`.

### Phase 11: Remove Compatibility

Delete all old schemas and compatibility code:

```text
blocked-event tables
dependency edge tables
labels
ready queue
recently-valid queue
pending-reprojection queue
domain worker queues
receive side-channel storage
```

Update tests so they assert target vocabulary:

```text
needs/offers replace blocking
offers replace labels
intents replace worker queues
receive facts replace receive metadata
SendOnConnection replaces transit.out
HandleSync replaces sync.in
```

### Phase 12: Audit Boundaries

Add boundary tests:

```text
projectors only emit intents/needs/offers
projectors may use core::crypto only with provided context
projectors do not call handlers
handlers do not call handlers
handlers emit facts/intents back through core
all deferred intents are deterministic by key
unchanged standing needs/offers do not wake
new offers wake matching needs exactly once
receive facts are local-only
sync/transit/connection communicate only through facts and intents
```

## End State

The final model is:

```text
facts produce needs, offers, and intents
needs and offers wake projection
projectors validate protocol meaning
atomic intents commit exact state
deferred intents drive bounded handlers
handlers produce more facts and intents
transit moves bytes
sync decides ids
connection proves peer relationships
receive facts record local observations
```

There is one context mechanism, one projection scheduler, and one deferred
intent queue. Everything else is either module projection state or handler
checkpoint state.

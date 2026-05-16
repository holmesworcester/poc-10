# New Architecture

This document describes the poc-10 target architecture and the current
migration checkpoint. The target vocabulary is deliberately small:

```text
facts
context needs
context offers
context matchers
pending projection
projectors
intents
intent handlers
WakeLoop
```

The design is not a wrapper around the old worker/blocking model. The end state
has one fact store, one context matching surface, one projection scheduler, and
one deferred intent queue.

## Poc-10 Success Criteria

`poc-10` starts from the merged `poc-8` behavior, but the implementation target
is this architecture.

The migration succeeds when:

- Every non-ignored `poc-8` test passes in `poc-10`, with the same user-facing
  behavior.
- The old mechanisms are gone, not wrapped: legacy labels, blocked tables,
  ready queues, pending reprojection queues, worker-specific domain queues, and
  receive metadata side channels.
- Core owns facts, context, context matchers, pending projection, `WakeLoop`,
  intents, handler dispatch, storage mechanics, wire field primitives, and
  crypto helpers.
- Event modules own fact semantics: layouts, projectors, context roles,
  command constructors, read-model rows, and protocol validation rules.
- Intent handlers own bounded stateful work and handler checkpoint state.
- Projectors return only needs, offers, and intents.
- Intent handlers return only facts and intents. The current `purged_facts`
  output is a migration checkpoint for exact retained fact purge, not a broad
  storage escape hatch.
- No event module, handler, command, schema, or wire layout reaches around core
  to call another stage directly.
- There is no event-bus layer. `WakeLoop` is the target projection and intent
  coordinator.
- The product-facing binary is `match`; the package may still be named `topo`.
- `src/match_app.rs` is the bridge from `src/main.rs` to either target
  walkthrough code or the contained legacy compatibility path.
- Every handler is a flat `src/handlers/<name>.rs` file declared from
  `src/handlers.rs`; handler-owned subdirectories are not part of the target.
- There is no `mod.rs` anywhere in the repository.
- End-state guardrail: There is no per-module `rows.rs`, `layout.rs`, or `cli.rs`
  where logic can hide. During the current checkpoint, existing
  `rows.rs` and `layout.rs` files are narrow/declarative migration files; they
  must not become protocol logic sinks.
- Schema declarations exist in exactly three visible places:
  `src/core/schema.p8sql`, `src/event_modules/schema.p8sql`, and
  `src/handlers/schema.p8sql`.
- Wire layouts are declarative and fixed length unless a fact explicitly stores
  opaque chunk bytes with a fixed outer slot.
- Transit frames use the same fixed-layout wire machinery and support only the
  two configured frame sizes.
- Boundary tests fail if new dumping-ground files, ad hoc SQL, ad hoc codecs,
  broad projector reads, direct handler calls, or direct network/store side
  effects appear.

The first milestone is not feature expansion. It is a structural switch-over
with the `poc-8` behavior still green.

## Current Migration Checkpoint

As of the 2026-05-15 checkpoint on branch `new-architecture`, the repo is in a
mixed state by design:

- `src/main.rs` delegates to `topo::match_app::run`.
- `src/match_app.rs` is the product-facing bridge. `match demo` runs the
  target-tree walkthrough in `src/demo.rs`; other commands still dispatch
  through `crate::legacy::app::run::<crate::legacy::protocol::Protocol>`.
- `examples/match_demo.rs` is a thin wrapper around the same target walkthrough.
- `src/legacy.rs` and `src/legacy/` are the contained compatibility island for
  old production CLI and daemon behavior. New architecture work should not add
  behavior there.
- `src/core/wake_loop.rs` persists and reloads facts, needs, offers,
  pending projection, and intents. It also feeds exact declared fact inputs into
  handlers instead of exposing all facts.
- Target event modules under `src/event_modules/` are exercised by poc-10 tests
  and are not yet the whole production path.
- Target handlers under `src/handlers/` are flat files and are registered from
  `src/handlers.rs`.
- The old handler subdirectory shape has been removed.
- Target receive transit can open fixed transit frames that carry signed
  key-wrap facts, admit the opened fact, and record local receive provenance.
  Send-side packaging and TCP send remain bounded handler cuts/stubs until the
  event-module constructors own the remaining frame and crypto helpers.
- Target purge can remove exact retained target facts through handler output;
  cascade discovery, secret retirement, and sync-index repair still need their
  bounded handler cuts before legacy purge code can disappear.

Implemented target slices:

- Core fact/context/intent/projector contracts.
- Context needs/offers/matchers for exact facts, secret coverage, receive
  provenance, deletion/update wakeups, and recipient-key supersession.
- Atomic row intents as the projector-owned path for bounded read-model writes
  and deletes.
- `WakeLoop` projection drains that replace owner needs/offers, match context
  deltas, wake matching owners, apply atomic intents, and persist deferred
  intents.
- Handler dispatch that accepts only declared fact inputs and returns facts,
  purges, and follow-up intents.
- Target tests for signed facts, sealed messages, key wraps, key request
  healing, recipient-key supersession cleanup, signed key-wrap transit receive,
  transit frame layout, sync context, receive provenance, and flat handler
  contracts.
- `CommandContext` for pure target command constructors that do not call legacy
  workers or handler dispatch directly.

Current hard gaps:

- The production CLI still needs to run through target `WakeLoop`, target
  projectors, and target handlers. Signed key-wrap receive is the first
  implemented target admission cut because it exercises signed facts, context,
  key offers, unwrap intents, receive provenance, and anti-amplification.
  General shared fact admission still needs the same treatment.
- Transit wrap/unwrap is not fully target-owned. The remaining work is to move
  frame packaging, nonce derivation, associated data, payload packing, and size
  choice into event-module constructors so handlers can emit follow-up intents
  without owning wire or crypto semantics.
- Sync still needs the target context transfer for key dependencies. In-range
  encrypted content must bring relevant out-of-range key wraps or retained key
  nodes, and perf tests should prove that display remains fast.
- Purge still needs bounded cuts for cascade discovery, secret retirement, and
  sync-index purge/update.
- Broad encryption code still needs more narrow files around recipient keys,
  key requests, key wraps, local secrets, wrap-source/frontier validation, and
  secret coverage matching.
- The legacy compatibility island should be deleted only after unchanged or
  harness-only-adjusted `poc-8` tests cover the target behavior.

## File Organization

The target source tree makes ownership visible at the top level:

```text
src/
  lib.rs
  main.rs
  match_app.rs
  demo.rs
  core.rs
  event_modules.rs
  handlers.rs
  commands.rs
  legacy.rs

  core/
    schema.p8sql
    facts.rs
    context.rs
    matchers.rs
    projection.rs
    intents.rs
    handler_dispatch.rs
    wake_loop.rs
    store.rs
    wire.rs
    crypto.rs
    schema_dsl.rs

  event_modules/
    schema.p8sql
    <module>.rs
    <module>/
      fact.rs
      layout.rs
      create.rs
      project.rs
      rows.rs
      context.rs

  handlers/
    schema.p8sql
    connection.rs
    connection_response.rs
    handle_sync.rs
    materialize_key_wraps.rs
    network_send.rs
    purge_event.rs
    purge_retired_recipient_material.rs
    receive_transit.rs
    sync_index_update.rs
    transit.rs
    unwrap_key_wrap.rs

  commands/
    context.rs

  legacy/
    app.rs
    daemon.rs
    protocol.rs
    round_robin.rs
    workers.rs
```

The exact event module names can change. The ownership pattern should not.

`src/lib.rs`, `src/core.rs`, `src/event_modules.rs`, `src/handlers.rs`,
`src/commands.rs`, and `src/legacy.rs` are manifests. They declare modules and
may re-export narrow APIs; they should not accumulate behavior.

`src/legacy/` is a migration boundary. It keeps old production behavior
reachable while `match` is cut over. It is not a compatibility layer to keep
forever.

### No `mod.rs`

Rust module declarations live in manifest files:

```text
src/core.rs
src/event_modules.rs
src/handlers.rs
src/commands.rs
src/legacy.rs
```

Those files should contain declarations and narrow re-exports only.

### File Role Rules

Use role names that predict allowed behavior:

```text
fact.rs
  protocol data types and semantic field names

layout.rs
  declarative fixed-length wire layout for that fact type

create.rs
  local constructors that produce proposed facts or intent payloads

project.rs
  one projector entry point plus local validation glue

rows.rs
  current migration checkpoint for read-model row shapes

context.rs
  context roles, selectors, offers, needs, and matcher helpers

frame.rs / receive.rs
  transit-specific fixed-frame helpers and receive classification
```

Avoid broad names such as `utils`, `helpers`, `common`, `misc`, `manager`, and
`service`. If a helper is real, its file should name the invariant it enforces
or the object it builds.

### Schema Ownership

There are exactly three durable schema DSL files:

```text
src/core/schema.p8sql
src/event_modules/schema.p8sql
src/handlers/schema.p8sql
```

`src/core/schema.p8sql` contains core mechanics:

```text
facts
inbox
needs
offers
pending_projection
intents
clock
network_in
network_out
```

`src/event_modules/schema.p8sql` contains projection/read-model state.

`src/handlers/schema.p8sql` contains handler checkpoint or operational state.

The schema DSL may declare tables, indexes, uniqueness, byte lengths, and row
keys. It should not contain Rust expressions, projection callbacks, or protocol
validation logic.

## Facts

A fact is the generic unit of durable or local event state:

```rust
struct Fact {
    id: FactId,
    scope: FactScope,
    timestamp: u64,
    bytes: Vec<u8>,
}
```

Core can index by scope, but event modules decide what a scope means:

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
```

Workspace remains a protocol concept, not a special core concept.

## Context

Projectors do not issue arbitrary broad queries. They receive context by
declaring needs and consuming matching offers:

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

Core does not decide whether a need is required or optional. The projector
decides that by whether it emits rows, offers, or intents when the context is
missing.

Each projection pass owns the current context surface for its fact. `WakeLoop`
diffs the new needs/offers against the old needs/offers for the same owner:

```text
unchanged need/offer
  keep it and do not wake

new need
  insert it, match existing offers, wake owner if matches exist

new offer
  insert it, match existing needs, wake matched owners

removed need/offer
  delete it
```

This makes standing watches stable. Re-emitting a watch does not wake the owner
again unless a matching offer changes.

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

Standard matchers:

```text
Exact fact matcher
  Need(role="fact", selector=fact_id)
  Offer(role="fact", selector=fact_id)

Secret coverage matcher
  Need(role="secret_coverage", selector=(workspace, frontier, minute, leaf))
  Offer(role="secret_coverage", selector=(workspace, frontier, range, prefix))

Receive provenance matcher
  Need(role="transit_received", selector=received_fact_id)
  Offer(role="transit_received", selector=received_fact_id)

Deletion/update matcher
  Need(role="message_deletion", selector=message_id)
  Offer(role="message_deletion", selector=message_id)

Recipient-key supersession matcher
  Need(role="recipient_key_superseded", selector=recipient_key_id)
  Offer(role="recipient_key_superseded", selector=recipient_key_id)
```

Scope is part of the match key. Projectors still validate semantic correctness,
including workspace membership, fact type, signer authority, endpoint role, and
local/private state.

## Projectors

Projectors consume a fact plus matched context and emit only intents, needs,
and offers:

```rust
fn project(fact: Fact, context: ProjectionContext) -> ProjectionOutput;

struct ProjectionOutput {
    intents: Vec<Intent>,
    needs: Vec<ContextNeed>,
    offers: Vec<ContextOffer>,
}
```

### Projector Style

A projector should read like validation followed by output:

```rust
pub fn project(fact: &Fact, ctx: &ProjectionContext) -> ProjectionOutput {
    let message = decode_message(fact)?;
    let workspace = ctx.require_fact(message.workspace_id)?;
    let signer = ctx.require_fact(message.signer_key_id)?;
    ctx.watch("message_deletion", fact.id);

    require_signature(&message, &signer)?;
    require_workspace_membership(&signer, &workspace)?;

    output()
        .offer_fact(fact.id)
        .intent(put_row(message_row(&message)))
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
- Emits the full current need/offer surface on every pass.
- Uses atomic intents for bounded row writes and deletes.
```

Projectors validate protocol meaning. Core may supply candidate context; the
projector must still verify type, scope, workspace, signer, author, endpoint,
role, and authorization.

## Intents

Everything a projector or handler wants done is an intent:

```rust
struct Intent {
    kind: IntentKind,
    execution: IntentExecution,
    key: Vec<u8>,
    payload: Vec<u8>,
}

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
UnwrapKeyWrap
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

Core applies atomic intents during projection. Deferred intents go into
`core.intents` and are claimed by registered handlers.

## Intent Handlers

Handlers consume deferred intents:

```rust
fn handle(intent: &Intent, ctx: &HandlerContext) -> Result<HandlerOutput, String>;

struct HandlerOutput {
    facts: Vec<Fact>,
    intents: Vec<Intent>,
}
```

### Intent Handler Style

An intent handler should read like a bounded state-machine step:

```rust
pub fn handle(intent: &Intent, ctx: &HandlerContext) -> HandlerOutput {
    let purge = decode_purge_event(intent)?;
    let target = ctx.require_fact(purge.target_id)?;
    let plan = retention_plan_for_exact_target(&target)?;

    output()
        .purge_fact(plan.target_id())
        .intent(retire_secret(plan.retire_coord()))
        .intent(discover_cascade(plan.target_id()))
}
```

Handler rules:

```text
- One handler owns each deferred intent kind.
- Handlers are flat files under src/handlers/.
- Handlers declare exact fact inputs when they need fact context.
- Handlers do bounded work per call.
- Handlers are idempotent by intent key.
- Handlers may use local/private/process/external state explicitly allowed for that kind.
- Handlers feed semantic results back as facts or intents.
- Handlers do not directly call other handlers.
- Handlers clear or replace the claimed intent only after durable progress is committed.
```

Handlers may use sockets, clocks, private keys, broad scans, process-local sync
indexes, post-commit sequencing, and local retention mutation. Those
capabilities are precisely why the work is not projector work.

## WakeLoop

`WakeLoop` is the target runtime cycle:

```text
submit fact
  persist fact if new
  enqueue pending projection

project pending facts
  load matched context from current needs/offers
  run projector
  apply atomic intents
  replace owner needs/offers by diff
  match new needs/offers and enqueue wakes
  persist deferred intents

dispatch deferred intents
  claim intent
  build handler context from declared fact ids
  run flat handler
  submit returned facts
  persist returned intents

repeat until the work budget is exhausted
```

`WakeLoop` owns the mechanics. Event modules and handlers own protocol meaning.

## Wire And Codecs

### Wire And Codec Style

Target wire code uses one shared fixed-layout system in `core/wire.rs` with
field primitives:

```text
U8
U16be
U32be
U64be
Bool8
Tag<N>
FixedBytes<N>
Id32
Hash32
PublicKey32
Signature64
Nonce24
Ciphertext<N>
Padding<N>
```

Event modules declare layouts and should not hand-roll byte parsing loops. The
current checkpoint still has per-module layout files; those files should remain
declarative and converge on generated fixed-layout readers/writers.

The layout system should generate:

```text
encoded length constant
encode
decode
field slicing
wrong-length rejection
trailing-byte rejection
golden vector tests
```

Fixed length remains the default. If a logical value is variable length, use a
fixed encrypted slot, a fixed chunk fact, a hash pointer to separately chunked
bytes, or a fixed enum variant with its own total length.

## Transit

### Transit Frame Style

Transit uses the same fixed-layout system as facts. The outer frame layouts are:

```text
TransitSmallV1
TransitLargeV1
```

Each frame has a fixed public header and a fixed encrypted payload slot:

```text
tag
version
frame_size_class
sender_endpoint_id
receiver_endpoint_id
connection_id
nonce
ciphertext_and_tag
```

The encrypted payload contains packed canonical fact bytes, actual used length,
and padding. The outer frame reveals only small or large.

Outbound after connection:

```text
SendOnConnection(connection_id, fact_id)
  -> load route, connection state, and fact bytes
  -> package one small or large transit frame
  -> emit NetworkSend(addr, frame)
```

Inbound:

```text
ReceiveTransit(frame)
  -> authenticate sender, recipient, connection, and scope
  -> recover inner bytes
  -> classify explicit fact types
  -> emit inner shared facts
  -> emit local TransitReceived facts
```

Connection transit may carry connection responses, connection-scoped sync
facts, or shared workspace facts. It must reject facts outside the connection's
authorized scopes.

## Receive Facts

Receive metadata is represented as local facts about received facts:

```text
TransitReceivedFact {
    received_fact_id,
    origin_addr,
    local_endpoint_id,
    sender_endpoint_id,
    transit_kind,
    connection_id,
    request_id,
    frame_hash,
    received_at_local_ms,
}
```

The receive fact offers context:

```text
Offer(
    owner = transit_received_fact_id,
    role = "transit_received",
    selector = received_fact_id,
    payload_ref = transit_received_fact_id,
)
```

The receive intent carries opaque frame bytes, observed origin address, and
local receive time. The handler uses those only to open the frame and build
local provenance facts. Shared fact identity is derived from canonical inner
bytes.

Transport-bound facts may explicitly need receive provenance. Ordinary shared
facts should validate through signatures, dependencies, context, and
projectors.

The first concrete shared-fact admission point should be signed key-wrap
receive. Transit unwrap recovers signed key-wrap bytes; admission parses only
enough to assign fact scope and timestamp. Authority remains projector work.

## Connection And Sync

Connection projectors and handlers produce relationship state:

```text
connection.connection_events
connection.request_connections
connection.connections
connection.invite_workspaces
connection.transport_targets
```

Connection flow:

```text
connection request fact
  -> SendBootstrapRequest
  -> ReceiveTransit on peer
  -> request projector validates invite/endpoint context
  -> ConnectionResponse
  -> SendHandshakeResponse
  -> ReceiveTransit on initiator
  -> response projector materializes connection state
```

Sync decides which ids should move. Transit decides how bytes move.

```text
StartSync
  -> create compare fact
  -> SendOnConnection(compare_id)

compare fact received
  -> HandleSync(compare_id)
  -> emit have_id, need_id, or child compare facts

need_id received
  -> if authorized and locally present, SendOnConnection(connection_id, fact_id)
```

Sync facts are connection-scoped facts. Durable sync bytes can be cached in
connection-scoped projection state until sent or compacted. Dep-aware sync must
include key context needed to display in-range encrypted content.

## Encryption And Key Healing

Keys use context needs/offers rather than hard event dependencies.

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
context. If a crypto operation needs broad search, private state not present as
context, or follow-up admission, it should be a deferred intent instead.

Key requests are shared facts:

```text
key_request projector
  -> validates requester/responder/frontier/recipient key
  -> Intent(MaterializeKeyWraps)
```

Key wraps are shared facts:

```text
key_wrap projector
  -> validates signer/frontier/recipient
  -> PutRow(key_wrap)
  -> Offer(secret_coverage) when usable as coverage context
  -> Intent(UnwrapKeyWrap) when local recipient material may open it
```

Deterministic wrap keys prevent amplification:

```text
key_wrap edge = (workspace, frontier, recipient_key, target_coverage)
```

Recipient-key supersession is an update/offer:

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
load exact target bytes if retained
compute bounded purge consequences
emit exact purge output
emit RetireSecret intent
emit DiscoverCascade intent
emit SyncIndexUpdate intent
clear or replace PurgeEvent
```

The target split is:

```text
PurgeEvent
DiscoverCascade
RetireSecret
SyncIndexUpdate
PurgeRetiredRecipientMaterial
```

Destructive steps are atomic when they run. The full workflow is intentionally
multi-step and retryable through intents.

## Legacy Mechanisms Removed Or Collapsing

These names are legacy/removal vocabulary only. They must not reappear in
target code paths except in tests or documentation that explicitly describes
the old mechanism being deleted:

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
core.facts
core.needs
core.offers
core.pending_projection
core.intents
core.inbox
local receive facts
context matchers
flat intent handlers
```

## Remaining Migration Cuts

The next cuts should move live behavior onto the target architecture without
adding new compatibility layers:

```text
1. Extend the signed-key-wrap ReceiveTransit path into a general target
   admission path for the remaining shared fact types.
2. Finish event-module-owned transit frame packaging and send-side
   classification.
3. Wire SendOnConnection -> transit packaging -> NetworkSend through facts and
   intents.
4. Move sync compare/have/need handling to target facts, context, and handlers.
5. Finish dep-aware sync for key coverage needed by encrypted content.
6. Split purge into exact purge, cascade discovery, secret retirement, and
   sync-index update handlers.
7. Delete the legacy compatibility island once the unchanged or harness-only
   adjusted poc-8 tests pass through the target path.
```

## Guardrails

### Simplicity Guardrails

- Add boundary tests before broad rewrites.
- Keep root manifests declaration-only.
- Keep every handler as one flat file under `src/handlers/`.
- Register fact types, context roles, intent kinds, handlers, and wire layouts
  in visible manifests.
- Generate row and wire boilerplate from declarative schema/layouts wherever
  possible.
- Prefer one exact helper per invariant over one flexible helper with flags.
- Give every deferred intent kind an idempotence key.
- Give every context matcher deterministic tests for new-need-to-old-offer and
  new-offer-to-old-need matching.
- Keep CLI parsing thin: parse arguments, call one command constructor or read
  model, print output.
- Keep read models separate from projection scheduling and handler checkpoint
  state.

## End State

The final model is:

```text
facts produce needs, offers, and intents
needs and offers wake projection
context matchers find candidates
projectors validate protocol meaning
atomic intents commit exact state
deferred intents drive bounded handlers
handlers produce more facts and intents
transit moves bytes
sync decides ids
connection proves peer relationships
receive facts record local observations
WakeLoop coordinates mechanics
```

There is one context mechanism, one projection scheduler, and one deferred
intent queue. Everything else is either event-module projection state, command
construction, transport IO, or handler checkpoint state.

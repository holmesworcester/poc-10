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

## Poc-10 Success Criteria

`poc-10` is the new-architecture repository. It should start from the merged
`poc-8` behavior, but the implementation target is this architecture, not a
compatibility layer around the old one.

The migration succeeds when:

- Every non-ignored `poc-8` test passes in `poc-10`, with the same user-facing
  behavior.
- The old mechanisms are gone, not wrapped: labels, blocked tables, ready
  queues, pending reprojection queues, worker-specific domain queues, and
  receive metadata side channels.
- Core owns facts, context, projection scheduling, intents, handler dispatch,
  storage mechanics, wire field primitives, and crypto helpers.
- Protocol code owns projectors, context matchers, wire layouts, user-facing
  commands, and protocol validation rules.
- Intent handlers own bounded stateful work and handler checkpoint state.
- Projectors return only needs, offers, and intents.
- Intent handlers return only facts and intents.
- No event module, handler, command, schema, or wire layout reaches around core
  to call another stage directly.
- There is no `mod.rs` anywhere in the repository.
- There is no per-module `rows.rs`, `layout.rs`, or `cli.rs` where logic can
  hide.
- Schema declarations exist in exactly three visible places:
  `core/schema.p8sql`, `event_modules/schema.p8sql`, and
  `handlers/schema.p8sql`.
- Wire layouts are declarative and fixed length unless the fact explicitly
  stores opaque chunk bytes with a fixed outer slot.
- Transit frames use the same fixed-layout wire machinery and support only the
  two configured frame sizes.
- Boundary tests fail if new dumping-ground files, ad hoc SQL, ad hoc codecs,
  broad projector reads, direct handler calls, or direct network/store side
  effects appear.

The first `poc-10` milestone is not feature expansion. It is a clean structural
switch-over with the `poc-8` test suite still green.

## Current Migration Checkpoint

As of 2026-05-15 on branch `new-architecture`, `cargo test` is green with the
target architecture slices that have landed so far. This is still a migration
state, not the final "zero cruft" state: legacy `protocol/` modules and
workers still coexist with the target `core/`, `event_modules/`, and
`handlers/` shape, and two poc-10 architecture guardrail tests remain ignored
until projector rows/labels and old worker queues are fully replaced.

Implemented target slices:

- Core fact/context/intent/projector primitives exist and are covered by
  boundary tests.
- Atomic row intents are the projector-owned path for bounded read-model row
  writes and deletes.
- Context needs/offers replace the key blocking paths for target encrypted
  messages, recipient keys, key wraps, and update/deletion wakeups.
- Secret coverage matching wakes sealed content without modeling implicit keys
  as hard event dependencies.
- Signed key-wrap creation, key request healing, proactive recipient-key
  wrapping, and post-deletion retained-node wrapping have target tests.
- Local capability facts are scoped `Local` and transit refuses to send local
  facts or private fact tags.
- Transit/connection target intent tests cover the split between connection
  send, transit wrapping, and opaque network send.
- Sealed messages carry purge coordinates, deletion offers emit deterministic
  `purge_event` intents, and `PurgeEventHandler` now purges retained target
  facts through `HandlerOutput` rather than mutating storage behind core.
- Deferred handlers declare exact fact inputs through the handler contract, and
  EventBus builds handler context from those ids instead of exposing all facts.
- The target projection drain can apply atomic row intents immediately through
  core store primitives while leaving only deferred intents in the queue.
- Target `SendOnConnection` is retry-safe while packaging remains incomplete: it
  validates sendability but returns an error rather than consuming work.
- Generated deterministic key wraps use source fact time for retained
  history-node wraps instead of a zero placeholder.
- Key request projection validates requester/recipient and responder/frontier
  authority before materializing wraps, and ignores sources not owned by the
  named responder.
- Recipient supersession now wakes local recipient-key material cleanup:
  superseded public recipient facts keep their validation/supersession context
  but stop requesting proactive wrap sources, while exact deferred cleanup
  purges obsolete local recipient private material after revalidating it.

Current hard gaps:

- The target modules are not yet the live production path. `src/event_modules/*`
  and `src/handlers/*` are exercised by target tests, while production CLI and
  daemon behavior still mostly dispatch through legacy `src/protocol` modules
  and `src/workers`.
- Target transit wrap/unwrap is not real yet. Current target tests enforce
  capability/sendability boundaries and opaque intent naming, but real frame
  encryption, network IO, inbound unwrap, and receive-fact admission still live
  in legacy workers.
- The current target `SendOnConnection` handler must not be considered live
  behavior. It validates sendability and keeps the intent retryable, but does
  not yet produce a transit-wrap or network-send handoff.
- Some target tests and compatibility bridges still apply atomic rows with the
  old RowIntentHandler path. New target paths should use projection drain with
  atomic row application.
- Finish the full target receive path for signed key-wrap facts. Incoming signed
  envelopes containing key-wrap payloads must validate signature, signer
  authority, recipient key, and frontier context before producing key-wrap rows,
  offers, and unwrap intents.
- Decide whether explicit key-request time needs separate provenance on
  generated wraps. The implementation now uses source fact time without adding
  request entropy to the deterministic anti-amplification key.
- Complete the purge split. `PurgeEventHandler` currently handles exact retained
  fact purge; cascade discovery, secret retirement, and sync-index purge/update
  still need bounded handlers before legacy `content_purge` can disappear. The
  current `purged_facts` output is acceptable only as a migration checkpoint; the
  final shape should prefer retention-specific bounded outputs/intents over a
  generic fact-delete escape hatch.
- Split broad target encryption code before adding more behavior. Recipient key,
  key request, key wrap, local secret, wrap-source/frontier, and secret coverage
  matching should be separate narrow files or modules.
- Move reusable payload reader/writer primitives into `core/wire.rs`. Intent and
  layout files should declare fixed or bounded fields instead of accumulating
  hand-rolled offsets.
- Move dep-aware sync to context needs/offers. Sync must include relevant
  out-of-range key wraps or retained key nodes for in-range encrypted content,
  and perf tests should prove one-day-out-of-range dependencies display fast.
- Convert connection, transit, and sync workers into intent handlers without
  turning intents into logic sinks. `SendOnConnection`, transit wrap/unwrap, sync
  compare handling, and network send should communicate only through facts and
  intents.
- Define the command contract. Commands should be pure constructors over a
  standard command context with narrow lookups, especially for local signing and
  local capability material.
- Delete legacy queues/tables/files only after their target behavior is covered
  by unchanged or harness-only-adjusted `poc-8` tests.

The next implementation priority is the hard middle, not cosmetic cleanup:
target receive/projection for signed key wraps, deterministic wrap timestamps,
dep-aware sync context transfer for keys, and the remaining purge handlers.
The first production-path cut should route one real admission path through
target `EventBus` and target projectors, with key-wrap receive as the preferred
candidate because it exercises signed facts, context, key offers, unwrap
intents, and anti-amplification.

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

File names are part of the architecture. A file with a broad name tends to
become a broad responsibility. `poc-10` should use narrow role names and
boundary tests so logic has nowhere ambiguous to accumulate.

## Project Layout

The target source tree should make ownership visible from the top level:

```text
src/
  lib.rs
  core.rs
  event_modules.rs
  handlers.rs
  commands.rs

  core/
    schema.p8sql
    crypto.rs
    facts.rs
    context.rs
    matchers.rs
    projection.rs
    intents.rs
    handler_dispatch.rs
    store.rs
    wire.rs

  event_modules/
    schema.p8sql
    message/
      fact.rs
      layout.rs
      create.rs
      project.rs
      rules.rs
      read.rs
    signed_fact/
      fact.rs
      context.rs
      layout.rs
      create.rs
      project.rs
    key_wrap/
      fact.rs
      layout.rs
      create.rs
      project.rs
      rules.rs
      read.rs

  handlers/
    schema.p8sql
    purge_event.rs
    discover_cascade.rs
    retire_secret.rs
    materialize_key_wraps.rs
    receive_transit.rs
    send_on_connection.rs
    network_send.rs

  commands/
    send_message.rs
    delete_message.rs
    accept_invite.rs
    view.rs
```

The exact event module names can change, but the ownership pattern should not.

### No `mod.rs`

`mod.rs` should disappear entirely.

Rust still needs module declarations, but they should live in a small number of
manifest files:

```text
src/core.rs
src/event_modules.rs
src/handlers.rs
src/commands.rs
```

Those files are declarations only:

```rust
pub mod facts;
pub mod context;
pub mod projection;
```

They should contain no functions, no tests, no constants other than module
exports, no `use` trees other than re-exports, and no conditional behavior.
A boundary test should reject `mod.rs` and should line-count the manifest files
so they cannot become the new dumping grounds.

### File Role Rules

Use narrow role names:

```text
fact.rs
  protocol data types and semantic field names

layout.rs
  declarative fixed-length wire layout for that fact type

create.rs
  user/local command constructors that produce proposed facts

project.rs
  one projector entrypoint plus tiny local glue

rules.rs
  named, reusable validation predicates for that module

read.rs
  read models and presentation-facing queries
```

Avoid broad names:

```text
mod.rs
rows.rs
layout.rs
cli.rs
utils.rs
helpers.rs
common.rs
misc.rs
manager.rs
service.rs
```

If a helper is real, its file should say what invariant it checks or what
object it builds. For example, prefer `workspace_auth.rs` or
`retention_cover.rs` over `helpers.rs`.

### Schema Ownership

Schema should be declarative and globally visible by ownership class.

There should be exactly three schema files:

```text
src/core/schema.p8sql
src/event_modules/schema.p8sql
src/handlers/schema.p8sql
```

`core/schema.p8sql` contains only core tables:

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

`event_modules/schema.p8sql` contains only projection state:

```text
message_rows
sealed_message_rows
file_rows
workspace_rows
recipient_key_rows
key_wrap_rows
```

`handlers/schema.p8sql` contains only handler checkpoint or operational state:

```text
purge_retire_coords
sync_index_snapshots
connection_attempt_checkpoints
network_send_cursors
```

The schema DSL should allow tables, indexes, uniqueness, byte lengths, and row
key declarations. It should not allow Rust expressions, projection callbacks,
or validation logic. Generated Rust table constants and row codecs are fine,
but handwritten SQL should not appear outside the schema compiler and tests.

The point is searchability: every durable table is visible in one of three
files, so no event module or handler can hide a private schema.

### Projector Style

A projector should read like a validation test followed by a small output
statement. It should be mostly one-liners composed from common helpers:

```rust
pub fn project(fact: &Fact, ctx: &ProjectionContext) -> ProjectionOutput {
    let msg = fact.decode::<Message>()?;
    let workspace = ctx.require(event::<Workspace>(msg.workspace_id))?;
    let signer = ctx.require(event::<SignerPubkey>(msg.signer_key_id))?;
    let deletion = ctx.optional(update::<MessageDeletion>(fact.id));

    require(signature_valid(&msg, &signer))?;
    require(signer_is_member_of_workspace(&signer, &workspace))?;
    require(message_names_workspace(&msg, &workspace))?;

    output()
        .need(update::<MessageDeletion>(fact.id))
        .offer(event::<Message>(fact.id))
        .intent(put_row(message_row(&msg, deletion)))
}
```

Common helpers should be small and named by invariant:

```text
signature_valid
signer_is_member_of_workspace
message_names_workspace
recipient_key_supersedes_previous
wrap_matches_recipient_and_frontier
secret_covers_leaf_coord
```

Helpers may compose other helpers, but they must not query storage, emit
intents, mutate rows, call handlers, or inspect process state. A projector can
then stay declarative without hiding protocol meaning in generic utility code.

For missing context, the helper should make the need obvious:

```rust
let signer = ctx.require(event::<SignerPubkey>(msg.signer_key_id))?;
let key = ctx.require(secret_covering(msg.leaf_coord))?;
ctx.watch(update::<MessageDeletion>(fact.id));
```

`require` means "without this, do not apply rows." `watch` means "apply now,
but wake me if this arrives later." Core stores both as context needs; the
projector gives them meaning.

### Intent Handler Style

An intent handler should read like a bounded state-machine step:

```rust
pub fn handle(intent: &Intent, ctx: &HandlerContext) -> HandlerOutput {
    let purge = intent.decode::<PurgeEvent>()?;
    let target = ctx.load_fact(purge.target_id)?;
    let plan = retention_plan_for_exact_target(&target, ctx.retention())?;

    ctx.atomic(plan.storage_deletes())?;

    output()
        .intent(retire_secret(plan.retire_coord()))
        .intent(discover_cascade(plan.target_id()))
        .intent(sync_index_purge(plan.shared_event_id()))
}
```

Handlers may read local state, use clocks, use network IO, and commit bounded
atomic steps. They should still be boring: decode intent, load exact inputs,
compute plan, commit one bounded step, emit follow-on facts or intents.

No handler should call another handler. Chaining happens through the intent
queue so crash recovery and idempotence stay visible.

### Wire And Codec Style

`poc-10` should avoid per-module handwritten `layout.rs` files.

Use one shared fixed-layout wire system in `core/wire.rs` with field
primitives:

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

Event modules declare layouts, not readers and writers:

```rust
wire_layout! {
    MessageV1: fixed {
        tag: Tag<4> = b"MSG1",
        workspace_id: Id32,
        author_id: Id32,
        signer_key_id: Id32,
        leaf_coord: U64be,
        nonce: Nonce24,
        ciphertext: Ciphertext<1024>,
    }
}
```

The macro or DSL should generate:

```text
encoded length constant
encode
decode
field slicing
wrong-length rejection
trailing-byte rejection
golden vector tests
```

Fixed length remains the default. If a logical value is variable length, use
one of these patterns:

```text
fixed encrypted slot with encrypted inner length
fixed chunk fact
hash pointer to separately chunked bytes
fixed enum variant with its own total length
```

Do not reintroduce ad hoc varints, maps, arbitrary `Vec<u8>` fields, or
per-event parsing loops.

### Transit Frame Style

Transit should use the same fixed-layout system as facts.

Flatten transit wrapping into two outer frame layouts:

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
ciphertext_and_tag<SMALL_PAYLOAD>
```

and:

```text
tag
version
frame_size_class
sender_endpoint_id
receiver_endpoint_id
connection_id
nonce
ciphertext_and_tag<LARGE_PAYLOAD>
```

The encrypted payload can contain the packed canonical fact bytes, their
actual used length, and padding. The outer frame length should reveal only
"small" or "large", not a bespoke per-message size.

This removes nested transit wrappers and keeps transit compatible with the
fixed-field discipline. The batcher chooses small or large; the wire layer
only encodes one fixed layout or the other.

### Simplicity Guardrails

The repo should make the easy path the correct path:

- Add boundary tests before the large rewrite, not after.
- Reject broad filenames and `mod.rs` in source inventory tests.
- Keep manifests, projectors, handlers, and rule files under explicit line
  limits unless a local exception is justified in the test.
- Register fact types, context roles, intent kinds, handlers, and wire layouts
  in visible manifests.
- Generate row and wire boilerplate from declarative schema/layouts.
- Keep every compatibility bridge in a directory named `migration/`, and delete
  that directory before declaring `poc-10` complete.
- Prefer one exact helper per invariant over one flexible helper with flags.
- Give every intent kind an idempotence key in its type definition.
- Give every context matcher deterministic tests for `new need -> old offers`
  and `new offer -> old needs`.
- Keep CLI parsing thin: parse arguments, call one command constructor or read
  model, print output.
- Keep read models separate from projection and handler checkpoint state.
- Keep fixture/golden tests close to layout declarations so wire changes are
  obvious and reviewable.

Pleasant code here means boring code: the file name predicts the allowed side
effects, the function name states the invariant, and the test name states the
behavior.

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

Opening a message means deriving or loading the local history leaf secret,
checking that it is the leaf named by the sealed message row, and AEAD-opening
the sealed payload with the message associated data. In poc-8 this is read-side
work over `content.sealed_messages`; poc-10 may keep that read helper or
materialize `content.messages` during projection when the required secret is
already projection context. In either case, opening is not a deferred handler.

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

### Phase 0: Start `poc-10`

Create `poc-10` from the pushed `poc-8` `master` that includes recipient key
rotation and this document.

The first `poc-10` commits should:

```text
copy the full poc-8 test suite
add source inventory boundary tests for forbidden files
add schema-location boundary tests
add projector and handler boundary tests
add fixed-wire-layout golden test harness
keep cargo test green
```

Do not begin by rewriting behavior. Begin by installing the guardrails that
will keep the rewrite from recreating the old dumping grounds.

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

Projectors may decrypt/open content when matching key context is present, or
leave opening as a read-side helper over sealed rows. Do not route that through
a handler unless it becomes a genuinely stateful, bounded effect.

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

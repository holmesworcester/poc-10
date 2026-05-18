# New Architecture

This document describes the poc-10 target architecture and the current
migration checkpoint. The target vocabulary is deliberately small:

```text
facts
context needs
context offers
context matchers
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
- Core owns facts, context, command context, context matchers, `WakeLoop`,
  generic runtime/app mechanics, intents, handler dispatch, storage mechanics,
  wire field primitives, and crypto helpers.
- Fact modules own fact semantics: layouts, projectors, context roles,
  command constructors, read-model rows, module-local CLI adapters, module
  queries, and protocol validation rules.
- Intent handlers own bounded stateful work and handler checkpoint state.
- Projectors return only needs, offers, and intents.
- Intent handlers return only facts and intents. The current `purged_facts`
  output is a migration checkpoint for exact retained fact purge, not a broad
  storage escape hatch.
- No fact module, intent handler, command, schema, or wire layout reaches around core
  to call another stage directly.
- There is no event-bus layer. `WakeLoop` is the target projection and intent
  coordinator.
- The product-facing binary is `match`; the package may still be named `topo`.
- Product entry is a thin root function that supplies the CLI name and protocol
  registry to generic core runtime/app code. It must not contain
  `MatchRuntime`-specific product logic.
- There is no product `demo` or `smoke` command. Smoke coverage belongs in
  black-box CLI tests against the real `match` binary.
- Intent handlers are themed files under `src/protocol/intents/<theme>/...`
  and declared from `src/protocol/intents.rs`; broad driver or catch-all
  intent submodules are not part of the target.
- Fact and intent manifests live under `src/protocol/` as `facts.rs` and
  `intents.rs`.
- There is no root `src/commands` module. The command context lives in
  `src/core/command_context.rs` as `core::command_context`.
- There is no `mod.rs` anywhere in the repository.
- End-state guardrail: `rows.rs`, `layout.rs`, and module-local `cli.rs` stay
  narrow and declarative. They must not become protocol logic sinks.
- Schema declarations exist in exactly three visible places:
  `src/core/schema.p8sql`, `src/protocol/facts/schema.p8sql`, and
  `src/protocol/intents/schema.p8sql`.
- The schema declaration surface is the source of truth for storage tables,
  read-model row codecs, and canonical fact wire codecs.
- Wire layouts are declarative and fixed length. There are no variable payload
  slots.
- Transit frames use the same fixed-layout wire machinery and support only the
  two configured frame sizes.
- Boundary tests fail if new dumping-ground files, ad hoc SQL, ad hoc codecs,
  broad projector reads, direct handler calls, or direct network/store side
  effects appear.

The first milestone is not feature expansion. It is a structural switch-over
with the `poc-8` behavior still green.

## Current Migration Checkpoint

As of the 2026-05-15 checkpoint on branch `main`, the repo is in a cutover
state with target code active and remaining gaps called out by ignored guardrail
or black-box tests:

- `src/main.rs` delegates to the product-facing `match` entrypoint.
- Product commands are being cut over to a generic core runtime/app facade
  configured by `src/protocol.rs`. Any product-specific runtime facade is
  temporary cutover debt, not the target architecture.
- Smoke behavior is tested through black-box CLI tests on the real `match`
  binary, not through a demo command or demo source file.
- The legacy module island has been removed; new behavior belongs in target
  modules only.
- `src/core/wake_loop.rs` persists and reloads facts, needs, offers, internal
  projection wakes, and intents. It also feeds exact declared fact inputs into
  handlers instead of exposing all facts.
- Target fact modules under `src/protocol/facts/` are exercised by poc-10 tests
  and are not yet the whole production path.
- Target intent handlers under `src/protocol/intents/` are themed files and
  are registered from `src/protocol/intents.rs`.
- Broad handler driver submodules have been removed.
- Target receive transit can open fixed transit frames that carry signed
  key-wrap facts, admit the opened fact, and record local receive provenance.
  Send-side flow now emits send-on-connection and network-send intents and can
  write a bounded TCP frame when route context is present. Remaining send-side
  debt is fixed-layout intent generation from schema, durable acknowledgements,
  cursors, and richer route retry policy.
- Target purge can remove exact retained target facts through handler output;
  cascade discovery, secret retirement, and sync-index repair still need their
  bounded handler cuts before target purge behavior is complete.

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
  transit frame layout, sync context, receive provenance, flat handler
  contracts, black-box invite/accept/link flows, basic content send/messages,
  encryption CLI flows, and daemon lifecycle.
- `CommandContext` for user-facing target commands that may read projected state
  through module `queries.rs`, but do not call legacy workers or handler
  dispatch directly. The type lives in `core::command_context`.

Current hard gaps:

- The production CLI still needs to finish moving through a generic core
  runtime/app facade configured by the protocol registry. Several user-facing
  commands are target-owned and black-box tested, but `match_app.rs` still has
  hand routing and explicit "not ported" paths.
- Transit wrap/unwrap is not fully target-owned. The remaining work is to make
  intent/frame layouts schema-generated and fixed length, finish durable
  network acknowledgements/cursors, and keep crypto semantics in fact-module
  constructors instead of handlers.
- Sync still needs the target context transfer for key dependencies. In-range
  encrypted content must bring relevant out-of-range key wraps or retained key
  nodes, and perf tests should prove that display remains fast.
- Purge still needs bounded cuts for cascade discovery, secret retirement, and
  sync-index purge/update.
- Remaining poc-8 behavior needs unchanged or harness-only-adjusted target
  coverage before the migration can be called complete.

## File Organization

The target source tree makes ownership visible at the top level:

```text
src/
  lib.rs
  main.rs
  match_app.rs
  core.rs
  protocol.rs
  protocol/
    matchers.rs
    matchers/
      exact.rs
      range.rs
      coverage.rs
      wrap_source.rs

  core/
    schema.p8sql
    command_context.rs
    cli.rs
    runtime.rs
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

  protocol/
    facts.rs
    facts/
      schema.p8sql
      <module>.rs
      <module>/
        fact.rs
        layout.rs
        create.rs
        commands.rs
        cli.rs
        project.rs
        queries.rs
        rows.rs
    intents.rs
    intents/
      schema.p8sql
      connection.rs
      connection/
        create_response.rs
        send_bootstrap_request.rs
      content.rs
      content/
        purge_below_retention_floor.rs
        purge_deleted_message.rs
        purge_expired_message.rs
        purge_message_child.rs
      encryption.rs
      encryption/
        create_key_wrap.rs
        purge_retired_recipient_material.rs
        unwrap_key_wrap.rs
      sync.rs
      sync/
        record_indexed_fact.rs
        send_compare_response.rs
        send_needed_fact_id.rs
        send_requested_fact.rs
      transport.rs
      transport/
        receive_transit_frame.rs
        send_facts_on_connection.rs
        send_network_frame.rs

```

The exact fact module names can change. The ownership pattern should not.
Only `src/core/context.rs` owns context primitives. Protocol context roles,
selectors, need constructors, offer constructors, and matcher implementations
belong under `src/protocol/matchers/`, organized by generic matching relation
such as exact, range, coverage, or wrap-source. Fact modules must not define
their own `matchers.rs`, `context.rs`, or `selectors.rs` files. Projectors own
which protocol-defined needs and offers they emit, while matcher modules own
only candidate-pairing algorithms. Need/offer shapes should be as generic as
the matching relation allows, using event type plus typed selector parameters
instead of fact-module-specific matcher vocabulary.

A fact module is one fact family. A directory that defines several durable
fact types is a bundle and should be split before review, even when the facts
are conceptually related. This rule applies to encryption and sync equally:
`recipient_key`, `local_recipient_key`, `key_wrap`, `sync_compare`,
`sync_have_id`, `sync_need_id`, `sync_range_request`, `sync_encrypted_root`,
`sync_shared_event`, and `sync_key_wrap_available` are separate fact-family
modules. Shared helper code is allowed only when its file name states the
specific invariant it owns, such as signer validation or range matching.

`project.rs` is not a folder for sub-events. A `project/` subtree is acceptable
only for fact-family-local helper slices named after validation steps or output
families. If a `project/` child corresponds to a different fact tag, the module
is bundled incorrectly and must be split.

`src/lib.rs`, `src/core.rs`, `src/protocol.rs`, `src/protocol/facts.rs`, and
`src/protocol/intents.rs` are
manifests. They declare modules and may re-export narrow APIs; they should not
accumulate behavior. Public concrete protocol namespaces live under
`topo::protocol::facts` and `topo::protocol::intents` without top-level
dumping-ground files.

`src/protocol.rs` is the target protocol registry. It is a declarative table of
contents across schema sources, fact registrations, context matcher roles,
intent kinds, and handlers. It does not replace the fact-module or
intent-handler manifests: those files define Rust namespaces, while
`protocol.rs` declares which namespaces make up the concrete `match` protocol.

The old legacy source island has been removed. Do not recreate compatibility
bridges; port behavior into the target runtime, fact modules, intent handlers,
and queries instead.

### No `mod.rs`

Rust module declarations live in manifest files:

```text
src/core.rs
src/protocol/facts.rs
src/protocol/intents.rs
```

Those files should contain declarations and narrow re-exports only.

### File Role Rules

Use role names that predict allowed behavior:

```text
fact.rs
  protocol data types and semantic field names

layout.rs
  current migration checkpoint for fixed-length fact wire layout

create.rs
  deterministic constructors from explicit parameters to proposed facts or
  intent payloads. Projectors, handlers, and user-facing commands may share
  this layer.

commands.rs
  user-facing or API-facing workflows over `CommandContext`. Commands can
  call `queries.rs` for read-before-create decisions, compose multiple
  constructors, and return facts/intents plus a typed receipt. They do not run
  projection, dispatch handlers, or mutate the store.

cli.rs
  frontend adapter: argv parsing and text formatting only. It calls
  `commands.rs` and leaves runtime draining and persistence to the root
  app/runtime boundary.

project.rs
  one projector entry point plus local validation glue

  It must dispatch one fact family only. Do not hide multiple event types in a
  projector folder; split them into modules and register each projector in
  `protocol.rs`.

queries.rs
  read-only projected-state lookups used by CLI/reporting and by explicitly
  user-facing commands. Query helpers may inspect rows but never write,
  project, dispatch handlers, or replace context.

rows.rs
  current migration checkpoint for read-model row shapes

protocol/matchers/*.rs
  one generic matching relation per file; each matcher module owns the
  relation's role constants, selector constructors, need/offer constructors,
  matcher implementation, and relation-specific tests

frame.rs / receive.rs
  transit-specific fixed-frame helpers and receive classification
```

### Command Chaining

Commands are not the automatic/reactive mechanism. If behavior is triggered by
new facts, missing context, transit receive, sync, or purge, it belongs in
projectors plus intent handlers and receives inputs through
`ProjectionContext`/`HandlerContext`.

User-facing operations may chain command work:

```text
parse CLI/API request
call module command
submit facts/intents to core runtime
drain projection and relevant handlers
call module query for the displayed result
```

That post-command query is valid only because the runtime step establishes the
previous state in the local store. If a later step cannot know that prior state
has projected, it must not query optimistically; it should emit or retain a
context need and let the wake loop re-run the owning projector when the matching
offer exists.

Avoid broad names such as `utils`, `helpers`, `common`, `misc`, `manager`, and
`service`. If a helper is real, its file should name the invariant it enforces
or the object it builds.

### Schema Ownership

There are exactly three durable schema DSL files:

```text
src/core/schema.p8sql
src/protocol/facts/schema.p8sql
src/protocol/intents/schema.p8sql
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
```

`src/protocol/facts/schema.p8sql` contains projection/read-model state.
In the end state it also declares fact wire layouts and read-model row
key/value layouts. Generated codecs use those declarations to produce
fixed-length fact encoders/decoders and row key/value constructors.

`src/protocol/intents/schema.p8sql` contains handler checkpoint or operational state.

The schema DSL may declare opaque row tables, typed tables, indexes,
uniqueness, byte lengths, and row keys. It should not contain Rust expressions,
projection callbacks, or protocol validation logic.

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

Core can index by scope, but fact modules decide what a scope means:

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

Projectors do not issue arbitrary broad queries. Core supplies
`ProjectionContext` from offers matched by registered `ContextMatcher`s:

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

The source of truth is the `ContextNeed` / `ContextOffer` / `ContextMatcher`
model, not protocol helper files. A projector first inspects the supplied
`ProjectionContext`. If required matched context is absent, it emits a stable
`ContextNeed` and no materialized rows or intents for that branch. A fact emits
`ContextOffer`s only after the projector has validated that the fact is valid
context for that role.

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

This keeps needs stable. Re-emitting the same need does not wake the owner
again unless matching offers change.

## Context Matchers

A `ContextMatcher` matches needs and offers for one protocol role. Core owns
lifecycle; matcher modules under `src/protocol/matchers/` own efficient
relation-specific lookup plus the generic need/offer constructors projectors
emit.

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

The matcher owns both directions of candidate matching: new need against
existing offers, and new offer against existing needs. A match only supplies
candidate context. The target projector must still decode and validate matched
facts semantically before emitting rows, offers, or intents.

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

## Protocol Registry

The concrete protocol has one registry file:

```text
src/protocol.rs
```

It may declare:

```text
schema sources
fact names and tags
projector names
context matcher roles
intent kinds and execution class
handler names and accepted intent kinds
```

It must not run projection, construct handlers, open stores, branch on fact
bytes, parse CLI input, or call transport IO. Registry entries should reference
module constants where possible so renames fail at compile time.

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
pub fn project(fact: &Fact, ctx: &ProjectionContext) -> Result<ProjectionOutput, String> {
    let message = decode_message(fact)?;
    let workspace_need = workspace_need(fact.id, message.workspace_id);
    let signer_need = signer_need(fact.id, message.signer_key_id);

    let waiting = output()
        .need(workspace_need.clone())
        .need(signer_need.clone());

    let Some(workspace) = ctx.payload_for(&workspace_need) else {
        return Ok(waiting);
    };
    let Some(signer) = ctx.payload_for(&signer_need) else {
        return Ok(waiting);
    };

    require_signature(&message, &signer)?;
    require_workspace_membership(&signer, &workspace)?;

    Ok(output()
        .need(workspace_need)
        .need(signer_need)
        .offer_fact(fact.id)
        .intent(put_row(message_row(&message))))
}
```

`payload_for` finds the `MatchedContext` for the exact need the projector
emitted and returns `matched.payload`. It does not query the store, run matcher
logic, or decide authorization; core already built the context from matched
needs/offers before invoking the projector.

The `waiting` output is not a blocked state. It is the fact's current standing
context surface. If either matching offer already exists from an earlier pass,
the matcher will wake this fact and core will supply that matched context on
the next projection. If the output can be affected by future update/about facts
such as deletions or key coverage, the projector keeps those stable needs in
the successful output too.

Projector rules:

```text
- Pure over fact plus provided context.
- Inspects supplied ProjectionContext before emitting required ContextNeeds.
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

### Projector Translation Checklist

When translating a legacy projector into the target tree:

```text
1. Read the legacy projector and record every require_dependency, update label,
   receive/provenance check, queued side effect, and row write.
2. For each requirement, inspect supplied ProjectionContext first. If matched
   context is absent, emit a stable target ContextNeed unless the fact is
   local-only or truly dependency-free.
3. Decode matched context inside the target projector and re-check type, scope,
   workspace, signer/author authority, and endpoint role before writing rows.
4. Emit ContextOffers only after the fact is valid context for that role.
5. If required context is missing, return stable needs and no materialized rows
   or intents for that branch.
6. Convert bounded row writes/deletes to atomic intents.
7. Convert async, retryable, IO, purge, transit, sync, and key-healing work to
   explicit typed deferred intents owned by handlers.
8. Keep helper functions small, local to the fact family, and named after the
   invariant they validate.
9. Add any new context role, need constructor, offer constructor, and matching
   behavior to the relation-specific module under src/protocol/matchers/, then
   register that matcher in src/protocol.rs.
10. If a port is temporarily a row shell because sibling context is not ready,
    document the exact legacy parity gap in the module docs and remove that gap
    when the sibling context lands.
11. Do not add protocol-specific context.rs, selectors.rs, or fact-module
    matchers.rs helper/source-of-truth files. Keep projection logic in
    project.rs and relation-specific matching in src/protocol/matchers/.
```

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
- Handlers are themed, self-contained files under src/protocol/intents/.
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
  enqueue an internal projection wake

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

`WakeLoop` owns the mechanics. Fact modules and intent handlers own protocol
meaning.

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

Fact modules declare fixed fact layouts in `src/protocol/facts/schema.p8sql`
and should not hand-roll byte parsing loops. The current checkpoint still has
per-module layout files; those files should remain declarative and converge on
generated fixed-layout readers/writers.

The declaration system should generate:

```text
encoded length constant
encode
decode
field slicing
wrong-length rejection
trailing-byte rejection
golden vector tests
```

All protocol facts are fixed length. If content is larger than one fact, split
it into fixed-size chunk facts. Do not add variable payload slots, hash-pointer
payload indirection, or handwritten per-module byte slicing.

Read-model row codecs come from the same declaration surface:

```text
table declaration
  durable table shape
  row key fields
  row value fields
  fixed byte widths
  generated key/value constructors
  generated key/value decoders
```

This removes handwritten per-module `rows.rs` files in the end state. Projectors
still make the semantic decision to write a row; generated codecs only build the
bounded bytes for `PutRow` and `DeleteRow` intents.

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
core.pending_projection as an internal WakeLoop checkpoint
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
2. Finish fact-module-owned transit frame packaging and send-side
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
- Keep every handler as a themed, self-contained file under
  `src/protocol/intents/`.
- Register fact types, context roles, intent kinds, handlers, and wire layouts
  in visible manifests.
- Generate row and wire boilerplate from the three schema declaration files.
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
intent queue. Everything else is either fact-module projection state, command
construction, transport IO, or handler checkpoint state.

# Poc-10 Migration Map

This file captures the Phase 0 reconnaissance for moving from the merged
`poc-8` implementation to the architecture in `new_architecture.md`.

The immediate goal is not feature expansion. The first milestone is a structural
switch-over where every non-ignored `poc-8` test still passes and the old
mechanisms are deleted rather than wrapped.

## Baseline

Repository:

```text
/home/holmes/poc-10
branch: new-architecture
base: 7278943 Clarify poc-10 architecture success criteria
```

Current source inventory:

```text
45 mod.rs files
29 schema.rs files
34 codec.rs files
18 cli.rs files
0 schema.p8sql files
```

The target guardrail tests in `tests/poc10_architecture_boundary_test.rs` are
split intentionally:

```text
active:
  poc10_success_criteria_are_recorded_in_architecture_doc

ignored until migration reaches the target:
  no mod.rs files
  no per-module schema.rs/codec.rs/cli.rs files
  exactly three schema.p8sql files
  no dumping-ground filenames
  root manifests are declarations only
```

## Current Obsolete Mechanisms

Delete these as the replacement primitives land:

```text
EventStatus::{Ready, Blocked, Applied}
event_modules.ready_events
event_modules.blocked_events_by_missing_dep
event_modules.missing_deps_by_blocked_event
event_modules.dependents_by_dep
event_modules.deps_by_dependent
event_modules.labels
event_modules.pending_reprojections
event_modules.recently_valid_events
event_modules.event_receive_context
event_modules.applied_shared_events
workers canonical.in
workers sync.in
workers transit.out
content.purge_instructions
encryption.pending_key_requests
encryption.pending_key_unwraps
encryption.pending_wrap_reconcile
connection.pending_connection_attempts
connection.pending_connection_responses
```

The replacement vocabulary is:

```text
facts
context needs
context offers
context matchers
pending projection
projectors
intents
intent handlers
receive facts
```

## Behavior That Must Survive

Event pipeline:

```text
deterministic fact ids from canonical bytes
idempotent duplicate admission
bad input rows are consumed and cannot poison queues
command admission returns ids immediately
projectors never see unapplied, failed, or missing context as valid context
missing required context wakes naturally when an offer appears
future update context, such as deletion, can wake an already-applied fact
deletion can purge before ordinary dependencies are present
message deletion suppresses files, slices, and reactions
recipient-key supersession prevents re-delivery resurrection
sync index catch-up still happens for newly applied shared facts
```

Encryption and key healing:

```text
targeted duplicate key requests produce one deterministic wrap edge
frontier root wrap is used when the root still exists
post-deletion requests wrap retained path nodes without resurrecting the root
key wraps stay deterministic for the same wrap edge
root secret commitments remain one-root-per-frontier
secret coverage preserves the time tree and in-minute trie
recipient-key supersession purges old private material and wraps
content heals when matching key coverage arrives
purge remains crash-safe across target-before-delete and delete-before-target
```

Transit, connection, and sync:

```text
TCP remains opaque frame transport
transit authenticates sender, recipient, connection, and scope
bootstrap transit carries only connection requests
handshake transit carries only connection responses
connection transit carries authorized connection responses, sync facts, or shared facts
request validation differs for local and received requests
response id remains the connection id
sync facts stay connection-scoped and direction-free in canonical bytes
need-id cannot authorize arbitrary sends
```

Wire and schema:

```text
typed table names and declared schemas only
idempotent inserts with conflict rejection
memory tables disappear on reopen
wrong-length and trailing-byte rejection
fixed-width ids, hashes, keys, signatures, and nonces
fixed encrypted slots for bounded variable plaintext
file slice proof slot budget and zero padding behavior
```

## Target Ownership

Core:

```text
src/core/schema.p8sql
src/core/facts.rs
src/core/context.rs
src/core/matchers.rs
src/core/projection.rs
src/core/intents.rs
src/core/handler_dispatch.rs
src/core/store.rs
src/core/wire.rs
src/core/crypto.rs
```

Event modules:

```text
src/event_modules/schema.p8sql
src/event_modules/<module>/fact.rs
src/event_modules/<module>/layout.rs
src/event_modules/<module>/create.rs
src/event_modules/<module>/project.rs
src/event_modules/<module>/rules.rs
src/event_modules/<module>/read.rs
```

Handlers:

```text
src/handlers/schema.p8sql
src/handlers/purge_event.rs
src/handlers/discover_cascade.rs
src/handlers/retire_secret.rs
src/handlers/materialize_key_wraps.rs
src/handlers/unwrap_key.rs
src/handlers/receive_transit.rs
src/handlers/send_on_connection.rs
src/handlers/network_send.rs
src/handlers/handle_sync.rs
src/handlers/sync_index_update.rs
```

Commands:

```text
src/commands/<user_command>.rs
```

Commands parse local input and construct facts or read models. They do not
drive workers, mutate storage directly, or perform transport IO.

## Parallel Work Waves

### Wave 1: Core Contracts

Keep this mostly local or assign to one worker. All later slices depend on the
same contracts.

```text
Fact
FactScope
ContextNeed
ContextOffer
ContextMatcher
ProjectionContext
ProjectionOutput { needs, offers, intents }
Intent
IntentKind
IntentExecution
HandlerOutput { facts, intents }
```

Deliverable:

```text
compileable core contracts
active boundary tests for projector/handler output vocabulary
no behavioral rewrite yet
```

### Wave 2: Schema And Wire

Disjoint owner from core behavior.

```text
introduce schema.p8sql parser/generator stub
create the three schema.p8sql files
introduce core/wire.rs fixed-layout primitives
add golden layout tests
```

Do not migrate every fact immediately. First make the target path attractive
and testable.

### Wave 3: Event Pipeline Slice

Replace the scheduler vocabulary.

```text
facts table replaces event status lifecycle
needs/offers replace blockers and labels
pending_projection replaces ready/reprojection/recently-valid queues
exact-event matcher replaces dependency unblock worker
update/about offers replace deletion and supersession labels
```

Port `worker_contract_test.rs` behavior while removing old queue names from the
assertions.

### Wave 4: Encryption Slice

Split current encryption worker queues into projectors plus handlers.

```text
key_request -> MaterializeKeyWraps intent
key_wrap -> rows, coverage offers, UnwrapKey intent
recipient_key -> current key row, supersession offer, purge retired material intent
local_key_secret -> secret coverage offer, proactive MaterializeKeyWraps intent
local_history_node_secret -> range coverage offer
content -> Need(secret_coverage)
```

Handlers:

```text
MaterializeKeyWraps
UnwrapKey
RetireSecret
ChopFloor
PurgeRetiredRecipientMaterial
```

Critical tests to preserve:

```text
partitioned joiner duplicate key request behavior
post-deletion requests wrap retained nodes without restoring root
cover summary convergence
chop after prior retire does not resurrect frontier root
concurrent peer sends survive sibling delete
message resyncs after proactive key arrival
recipient rotation purges old private key and wraps
```

### Wave 5: Transit, Connection, Sync Slice

Collapse worker queues and side channels into facts and intents.

```text
transit.out -> SendOnConnection intent
sync.in -> HandleSync intent
pending_connection_attempts -> SendBootstrapRequest or ConnectionAttempt intent
pending_connection_responses -> ConnectionResponse and SendHandshakeResponse intents
canonical.in receive metadata -> ReceiveFact plus context offers
applied_shared_events -> SyncIndexUpdate intent
negentropy pending purges -> SyncIndexPurge intent
```

Handlers:

```text
receive_transit
send_on_connection
network_send
connection_response
handle_sync
sync_index_update
```

Transit wire target:

```text
TransitSmallV1
TransitLargeV1
fixed public header
fixed encrypted payload slot
outer length reveals only small or large
```

### Wave 6: Deletion Pass

Only after behavior is green on the new path:

```text
remove compatibility migration modules
unignore poc-10 target guardrail tests one at a time
delete old schema.rs/codec.rs/cli.rs/mod.rs files
delete old worker queues
delete old labels and blocker tables
delete old receive side channels
```

Completion means:

```text
cargo test passes
cargo test -- --ignored passes for target guardrails
all target guardrails are unignored or converted into active tests
```


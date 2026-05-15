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
3 schema.p8sql files
```

The target guardrail tests in `tests/poc10_architecture_boundary_test.rs` are
split intentionally:

```text
active:
  poc10_success_criteria_are_recorded_in_architecture_doc
  poc10_core_contract_files_are_present
  poc10_projector_output_contract_emits_only_needs_offers_and_intents
  poc10_handler_output_contract_emits_only_facts_and_intents
  poc10_core_event_bus_exposes_protocol_neutral_vocabulary
  poc10_target_has_exactly_three_schema_dsl_files

ignored until migration reaches the target:
  no mod.rs files
  no per-module schema.rs/codec.rs/cli.rs files
  no old event status/blocker/label/receive queue names
  no old worker queue names
  projectors emit only needs/offers/intents
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

### Wave 2 And 3 Parallelization Matrix

Coordination rule: core contract changes must be serialized through the main
integrator. This includes `Fact`, `ContextNeed`, `ContextOffer`,
`ContextMatcher`, `ProjectionOutput`, `Intent`, `HandlerOutput`, generated
schema shape, and fixed wire layout primitives. Slice owners can propose
contract changes, but they do not merge them directly. After the main integrator
marks those contracts stable for a wave, module and handler slices can run in
parallel as long as their write sets remain disjoint from the rows below and
from each other.

Wave 2 matrix:

| Lane | Disjoint write set | Allowed tests | Blocking dependencies | Handoff point |
| --- | --- | --- | --- | --- |
| Schema declarations and generator | `src/core/schema.p8sql`, `src/event_modules/schema.p8sql`, `src/handlers/schema.p8sql`, `src/core/schema_dsl.rs` | `cargo test --lib core::schema_dsl`; `cargo test --test poc10_architecture_boundary_test poc10_success_criteria_are_recorded_in_architecture_doc` | Wave 1 contract names and field vocabulary are frozen by the main integrator | Three schema files parse, generated table names are stable, and the integrator publishes the schema shape for downstream slices |
| Fixed wire primitives | `src/core/wire.rs`, new `tests/wire_layout_test.rs` | `cargo test --test wire_layout_test`; `cargo test --test sync_storage_boundary_test`; active poc-10 boundary test | Schema lane has fixed ids, field widths, and slot budgets for facts and transit records | Wrong-length, trailing-byte, fixed-width id, hash, key, signature, nonce, and encrypted-slot behavior is covered by golden tests |
| Store/schema loading | `src/core/store.rs`, new `tests/schema_store_test.rs` | `cargo test --test schema_store_test`; `cargo test --test sync_storage_boundary_test`; active poc-10 boundary test | Schema declarations parse and the main integrator has accepted the generated storage API | Store can create declared tables from `schema.p8sql` without relying on old per-module `schema.rs` declarations |

Wave 3 matrix:

| Lane | Disjoint write set | Allowed tests | Blocking dependencies | Handoff point |
| --- | --- | --- | --- | --- |
| Event pipeline core integration | `src/core/facts.rs`, `src/core/context.rs`, `src/core/matchers.rs`, `src/core/projection.rs`, `src/core/handler_dispatch.rs`, `src/core/store.rs`, `src/workers/event_admission.rs`, `src/workers/event_projection.rs`, `src/workers/dependency_unblock.rs`, `src/workers/pipeline_helpers/event_lifecycle.rs`, `src/workers/pipeline_helpers/event_pipeline.rs` | `cargo test --test worker_contract_test`; `cargo test --test rules_boundary_test`; active poc-10 boundary test | Wave 1 contracts and Wave 2 schema/store handoffs are complete | Facts, needs, offers, pending projections, and exact-event matchers replace old ready/blocked/reprojection vocabulary for the test-event path |
| Test-event module proof | `src/event_modules/test_events/**`, or temporary bridge files under `src/protocol/event_modules/test_events/**` until the target tree is wired | `cargo test --test worker_contract_test`; `cargo test --test rules_boundary_test` | Event pipeline core exposes stable projector inputs and `ProjectionOutput` | A minimal module proves duplicate admission, missing context, natural wakeup, and reprojection without touching old queue names |
| Content module slice | `src/event_modules/content/{message,message_deletion,file,file_slice,file_deletion,reaction,content_event}/**` | `cargo test --test content_cli_test`; `cargo test --test disappearing_messages_cli_test`; `cargo test --test cascade_cli_test`; `cargo test --test worker_contract_test` for shared pipeline regressions | Test-event proof is green and the main integrator has frozen matcher/offer semantics | Content projectors emit only facts, needs, offers, and intents; deletion/supersession labels are represented as update/about offers |
| Identity module slice | `src/event_modules/identity/{user,admin,workspace,endpoint,endpoint_shared,invite,invite_server,invite_accepted,user_invite,device_invite,signed}/**` | `cargo test --test invite_accept_cli_test`; `cargo test --test generate_cli_test`; `cargo test --test leaf_coord_cli_test`; `cargo test --test worker_contract_test` for shared pipeline regressions | Test-event proof is green and fact scope/canonical id behavior is frozen | Identity projectors use the shared fact/context path and do not write blocker, label, or ready-event tables |
| Connection and sync fact slice | `src/event_modules/connection/{connection_request,connection_response,connection_ephemeral_secret,transit}/**`, `src/event_modules/sync/{need_id,have_id,compare}/**` | `cargo test --test network_queue_contract_test`; `cargo test --test black_box_sync_test`; `cargo test --test sync_storage_boundary_test`; `cargo test --test worker_contract_test` for shared pipeline regressions | Event pipeline core is stable; Wave 5 still owns transport handlers and network side effects | Projectors can produce receive/send/sync intents without invoking old transit, connection, or sync worker queues |
| Handler skeleton slice | `src/handlers/schema.p8sql`, `src/handlers/purge_event.rs`, `src/handlers/discover_cascade.rs`, new `tests/handler_dispatch_boundary_test.rs` | `cargo test --test worker_contract_test`; `cargo test --test handler_dispatch_boundary_test` | `Intent`, `IntentKind`, `IntentExecution`, and `HandlerOutput` are frozen by the main integrator | Pipeline can record and dispatch intents through handler outputs; Wave 4 and Wave 5 fill in encryption, transit, and sync side effects |

### Wave 2: Schema And Wire

Status: complete. The target schema and wire foundation is in place for the
next event-bus integration slice:

```text
the schema.p8sql parser/generator stub exists
the three target schema.p8sql files exist
core/wire.rs fixed-layout primitives exist
golden layout tests cover fixed-width and trailing-byte behavior
store/schema loading can create declared target tables
```

Completed scope, disjoint from core behavior:

```text
introduced schema.p8sql parser/generator stub
created the three schema.p8sql files
introduced core/wire.rs fixed-layout primitives
added golden layout tests
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
assertions. The first bridge should prove the event-bus path with the smallest
fact/projector/handler surface that can exercise the new contracts end to end.

Bridge success criteria:

```text
submit fact:
  admitting a command or received event writes one fact row with a deterministic
  id from canonical bytes and returns that id before projection side effects run

project once:
  each newly admitted fact creates at most one pending projection for the same
  fact/projector pair, and duplicate admission does not create another pending
  projection

replace standing context:
  when a projector emits a new offer for the same subject and offer kind, the
  bridge makes the new offer the standing context observed by later projections
  without requiring old blocker, label, or recently-valid tables

match need/offer:
  a pending projection with an unmet need stays pending until a compatible
  offer exists, then resumes with a ProjectionContext containing exactly the
  matched offer data needed by that projector

wake owner:
  inserting a compatible offer wakes only pending projections that own a
  matching need, and does not scan or enqueue unrelated facts

emit intent:
  a successful projection records ProjectionOutput intents as pending handler
  work without executing handler side effects during projection

no stable-need self-loop:
  if a projector re-emits the same unmet stable need for the same fact, the
  bridge records the need once and does not repeatedly wake or re-project that
  fact without a new matching offer

no duplicate wake amplification:
  duplicate facts, duplicate offers, and repeated compatible wake checks do not
  multiply pending projections or handler intents for work that has already been
  queued
```

The bridge is complete when these criteria are asserted without referencing old
ready, blocked, dependency, label, reprojection, or recently-valid queue names.

Current proof status:

```text
done: core EventBus persists facts, needs, offers, pending_projection, intents
done: stable needs do not self-wake
done: added offers wake matching owners once
done: duplicate offers and duplicate facts do not amplify pending projection
done: failed dependency projection never becomes dependency context
done: update/about offers can reproject applied dependents
done: update/about offers can retire waiting facts before primary context exists
done: deterministic intents dedupe by kind/key and conflict on changed payload
done: bounded handler dispatch feeds returned facts/intents back through EventBus
done: registered row handler applies atomic put_row/delete_row intents
done: event_with_deps bridge proves out-of-order exact dependency healing
done: event_with_deps owns a poc-10 projector surface beside its legacy row projector
done: secret_coverage matcher proves range offers can wake point needs
done: target-tree identity_workspace projector materializes a workspace row through AtomicIntent::PutRow
done: target-tree sealed_message projector keeps signer and secret needs standing until both context offers are present
done: signer context materializes sealed_message_rows before secret coverage is available
done: overlapping secret coverage offers emit one deterministic message_rows atomic intent without key amplification
done: target-tree deletion update context purges messages before keys arrive
done: opened messages retain only deletion update context so later deletes wake row cleanup and retention purge intent
done: intent handlers declare accepted intent kinds so mixed queues do not route follow-up intents to the wrong handler
done: projection-owned message row put/delete stays inside sealed_message projection rather than handler code
done: unchanged poc-8 e2e suites pass without scenario edits: black_box_sync, cascade, cli_surface, content, daemon_lifecycle, disappearing_messages, encryption, generate, invite_accept, leaf_coord, negentropy_purge_sync, sync_storage_boundary, view
done: ignored poc-8 e2e case cli_three_long_running_daemons_converge_messages_among_late_joiner passes when run explicitly
done: ignored poc-8 e2e case cascade_cli_replays_event_with_deps_out_of_order_and_unblocks_50k passes when run explicitly
done: target encryption key-healing slice models recipient-key-triggered proactive wrap needs as context matches
done: duplicate target key requests converge on one deterministic materialize_key_wraps intent without request entropy
done: post-deletion target key request wraps retained history-node sources without requiring or recreating the frontier root
done: rotated target recipient keys only match frontier sources at or after the new key timestamp
done: recipient supersession wakes the predecessor and emits purge_retired_recipient_material instead of future wrap intents
done: target encryption history-node offers reuse secret_coverage to wake/open sealed messages
done: sync compare unit coverage pins out-of-range dependency closure before in-range roots
done: active target guardrails prevent legacy file names, legacy protocol/worker imports, intent dumping, and handler logic in projectors
done: projection context exposes exact matched need/offer/payload facts, not broad sibling offers with the same payload owner
done: core dispatch can drain atomic and deferred intents separately
done: target projectors revalidate secret and wrap context before opening messages or emitting wraps
done: identity_workspace row layout moved out of project.rs into rows.rs so projectors do not define row tables or row shapes
done: active target guardrails now cover manifests, schema DSL files, layout files, project row definitions, handler context ownership, and CLI-equivalent parsing/printing
done: poc10 sync context proof shows a timestamp range request can pull out-of-range event deps and out-of-range key offers before sending encrypted roots
done: poc10 transit/connection interface proof keeps connection drain, transit wrapping, connection send, and send acknowledgement as distinct intent steps
```

The next event-pipeline step is to replace the simplified message row proof
with the real poc-8 row values: sealed message rows are durable projection
output, and opening is deterministic read/projection work using local history
node secrets. `purge_event` remains a deferred retention intent, but its handler
should not exist until it preserves the existing broad purge/retire/cascade
behavior.

The next encryption handler step needs one missing core contract before it can
be real: a deferred handler must be able to read the matched local source
secret and recipient key payloads, or receive those exact payload facts through
an explicit handler context. A handler that emits placeholder key-wrap facts
without source secret material is intentionally rejected as cruft.

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

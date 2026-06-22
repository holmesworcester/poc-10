# Command Runtime Simplification

This note describes the target command/runtime shape for poc-10 and the
migration needed across protocol fact families.

## Target Model

Core has three separate surfaces:

- Fact-family APIs read projected state or author facts.
- The command host commits authored facts atomically.
- Runtime and daemon drain queues.

A CLI command is any user-invoked verb, including read-only verbs such as
`messages`, `view`, `workspaces`, and `count`. A fact-family API operation is a
typed protocol operation. Some API operations are read-only and return a view
model. Authoring API operations return `AuthoredFacts<T>`, meaning a receipt plus
facts ready for admission.

Command execution does not run projection for private freshness. It reads the
current projected state once, authors all facts from that initial state, commits
the authored facts, and returns. A command must not query after it has started
authoring facts. If chained authoring needs an id from an earlier authored fact,
it uses the in-memory fact or receipt it just constructed, not a projected row.

The daemon is the live queue driver. One daemon tick gives recurring builders a
chance to queue work, drains local and projection batches, accepts inbound
network input, admits due time wakes, dispatches durable intents, and pumps
outgoing network rows. Version repair is just recurring protocol work guarded by
normal storage-version checks; the daemon loop does not own a separate storage
readiness gate.

Production version replay rebuild is protocol policy: a protocol-owned update
fact requests the effect that wipes resettable state and marks retained facts
pending in replay mode. Replay order variation remains a diagnostic surface for
proving idempotence and order independence, not the public upgrade command.

## File Roles

Each fact family converges on this split:

- `cli.rs`: argv parsing and `CliOutput` formatting.
- `api.rs`: typed read and authoring operations for the fact family.
- `author.rs`: pure fact construction, signing, encryption, and assembly.
- `queries.rs`: low-level read-model and table helpers.
- `project.rs`: projection and materialization.
- `encode.rs` and `fact.rs`: canonical bytes and fact shape.

`commands.rs` is not a standard role file. Authoring functions live in
`api.rs`. User-facing read workflows that currently live in `cli.rs` or
`queries.rs` move behind `api.rs` when they are protocol operations rather than
row helpers. `queries.rs` remains available for projectors, handlers, and API
functions that need direct row access.

## Core Migration

1. Rename the shared authoring bundle to `AuthoredFacts<T>`.
   Remove previous command-bundle vocabulary.
2. Rename command commit paths to authored-fact language.
   Runtime and store commit helpers use `submit_authored_facts` vocabulary.
3. Remove hidden command/query projection freshness.
   The command host reads the store as-is. Tests that need eventual visibility
   drive daemon work or use `assert eventually`.
4. Narrow `Runtime`.
   Runtime remains the owner of bounded projection, intent dispatch, time-wake
   admission, replay, and state-summary mechanics. It should not be the concept
   every CLI command depends on for query freshness.
5. Flatten replay language.
   Replay may drive queues to its barrier, but the public model should not teach
   a general runtime fixpoint.
6. Minimize core rebuild/versioning surface.
   Version checks, update facts, and rebuild policy should stay in protocol
   modules. Core should keep only protocol-neutral mechanics: queue mode,
   priority work admission, resettable table declarations, and diagnostic
   replay checks. Revisit `runtime`, `daemon`, and `replay` after the update
   path settles to remove any version-specific vocabulary or unnecessary
   orchestration helpers.

## Fact Family Migration Inventory

Authoring families migrated to `api.rs`:

- `auth/admin`
- `auth/endpoint`
- `auth/invite_accepted`
- `auth/invite_secret`
- `auth/key_wrap`
- `auth/user`
- `auth/user_invite`
- `auth/workspace`
- `connection/close`
- `connection/request`
- `content/file_deletion`
- `content/message`
- `content/message_deletion`
- `content/retention_policy`

Authoring code outside a standard fact-family `api.rs`:

- `sync/local_setting.rs`
- `content/message/cli.rs` for reaction and file-send workflows that assemble
  multiple fact families.

Read/query families that should keep row helpers but expose user-facing
operations through an API when they are part of the CLI or protocol surface:

- `auth/device_invite`
- `auth/endpoint_shared`
- `auth/invite_server`
- `connection/connection`
- `connection/fact_receipt`
- `content/file`
- `content/file_slice`
- `content/reaction`
- `sync/compare`
- `sync/have_id`
- `sync/need_id`
- `sync/shared_fact`

Families with no command or query surface can stay focused on fact shape,
encoding, authoring, projection, and handler use until they need an API:

- `auth/key_request`
- `auth/local_history_node_secret`
- `auth/local_key_secret`
- `auth/local_recipient_key`
- `auth/local_secret_retirement`
- `auth/local_signer_secret`
- `auth/recipient_key`
- `auth/removal_frontier`
- `auth/signature`
- `connection/ephemeral_secret`
- `connection/frame_bundle`
- `connection/frame_file_slice`
- `connection/frame_observation`
- `connection/frame_small`
- `sync/range_request`

## Test Migration

Black-box protocol tests should use existing command surfaces: CLI commands,
daemon ticks, `assert eventually`, and `state-summary`. Direct tests remain for
core primitives such as atomic effect commit, bounded queue limits, context
matching, schema lifecycle, fact encoders/decoders, and projector-local
authentication boundaries.

Tests that only preserve old command/runtime orchestration should be deleted or
rewritten. A command-visible result must become visible through normal daemon
work, not through hidden command projection.

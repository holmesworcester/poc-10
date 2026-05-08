# Disappearing Messages Plan

This document extends `encryption_plan.md` with a first-class design for
disappearing messages: messages that expire automatically after a configurable
TTL, without anyone running `delete-message`. It is meant to be read alongside
`plan.md`, the current `encryption_plan.md`, and the older
`event-centered-encryption-auth-plan/encryption_plan.md` from which the
phase-two history-tree shape is borrowed.

The minimum viable shape is:

```text
admin-signed workspace TTL setting
  -> message authoring snaps an expiry minute into the message event
  -> per-minute history tree node covers all messages in that minute
  -> daemon worker punctures fully expired minute nodes on tick
  -> deterministic deletion summary commits to the expired minute set
```

This doc reuses the existing deletion + purge story rather than inventing a
parallel one. Disappearing messages are deletion facts whose source is "the
clock advanced past a minute boundary", not "an author chose to delete one
message". The same retained-cover/purge-cover machinery covers both.

## How This Doc Relates To The Plans It Extends

The current `encryption_plan.md` describes phase one (ordinary recipient-key
wraps for an entire `removal_frontier_id`) and a narrow phase-two slice that
adds local history range-node secrets:

> Real HKDF-SHA256 derivation in `core::crypto` for local range-node secrets.
> ... `local_history_node_secret` local events name canonical range nodes and
> can tombstone an older local path node by exact row delete.
> (`encryption_plan.md`, lines 277-285)

The original `event-centered-encryption-auth-plan/encryption_plan.md` Phase
Two section (lines 271-359) is more specific about *what* a leaf names and
*how* the cover summary is computed. The relevant lines are:

> ```
> history_coord = (unix_minute, event_id)
> leaf_secret   = KDF(epoch_root, "leaf", unix_minute, event_id)
> node_secret   = KDF(parent_secret, "left" | "right", node_prefix)
> ```
>
> Use BLAKE3-256 for event ids, tree commitments, and set hashes, with
> domain-separated inputs for each use.
> (original plan, lines 277-287)

> ```
> deleted_set'       = deleted_set union incoming_delete_cover
> retained_cover'    = canonical_minimal_cover(all_history - deleted_set')
> purge_cover'       = canonical_minimal_cover(deleted_set')
> history_summary_id = Hset("history-delete-summary", deleted_set', retained_cover')
> ```
> (original plan, lines 314-320)

Disappearing messages depend on both of those primitives: leaf coords keyed
by `(unix_minute, event_id)`, and a deletion summary that commutes under set
union. **The current implementation diverges from that spec**: see the
"Acknowledged divergence from the plan" section below. This design assumes
the corrected primitives and surfaces the gap explicitly.

## Implementation Note (Supersedes Sections 1–5)

The slices that shipped on the `task-disappearing-messages` branch do **not**
introduce an `expired_minute` event, do **not** tombstone whole minutes, and
do **not** sync any expiry-related fact between peers. The earlier sections
(1–5) describe an `expired_minute`-event-based design that was abandoned;
this note records what actually got built and why.

### What ships

  * **Per-message stamping (slices 1 + 3).** Each `MessageEvent` commits in
    canonical bytes to its own `expires_at_minute: u64` and a
    `disappearing_setting_id: EventId` — the policy under which it was
    authored, either a signed `disappearing_messages_setting` or the
    workspace event id (slice-1 fallback). The projector validates the
    stamped expiry against the referenced policy.
  * **Per-peer clock-driven retirement (slice 1).** The
    `disappearing_minute_expiry` daemon-step worker scans `sealed_messages`
    every tick. For each row whose `expires_at_minute < now_unix_minute`,
    it deletes the read-model + sealed rows, writes a
    `MESSAGE_TOMBSTONES` row (which triggers the existing `content_purge`
    cascade for reactions/files), purges the message's canonical bytes,
    and calls `RetireDeletedEventLeaf` for the message's per-event leaf.
  * **Re-arrival rejection.** The message projector reads
    `now_unix_minute` from `EventContext` and tombstones expired-at-receive
    messages with a deletion label so re-arrivals can't resurrect them.
  * **Cascade through `content_purge` (slice 4).** Reactions, files, and
    file_slices are reclaimed in the same daemon tick via `content_purge`
    by gating on the parent message's tombstone. Reaction leaves are
    additionally retired by the disappearing-minute worker
    (parent-driven).

### What does *not* ship (deliberate simplifications)

  * **No `expired_minute` event.** Convergence is provided by canonical-bytes
    equality of the original messages: every peer admits the same bytes,
    derives the same `expires_at_minute`, and reaches the same retirement
    decision when its own clock crosses the boundary. There is no shared
    "expiry fact" event to converge on.
  * **No whole-minute tombstone.** The encryption-worker TODO at
    `src/workers/encryption.rs:1147` describes a `RetireExpiredMinute`
    primitive that consolidates retirement to one tombstone per minute
    instead of one per leaf. With **mutable per-message TTLs** (slice 2),
    different messages in the same minute can have *different* stamped
    expiries, so the optimization only pays off for a fixed workspace
    TTL across all messages. Until then we accept per-leaf tombstones
    and rely on key rotation (a new `removal_frontier`) for coarse
    cleanup of accumulated tombstones.
  * **No deletion-summary commitment** (the abandoned slice-3
    `Hset(deleted_set, retained_cover, expired_minute_set)`). Convergence
    on the cover summary already implies agreement on retained state, and
    the deletion *path* is implied by canonical-bytes equality of the
    original messages.

### Mutable-TTL ⇒ dirty-tree consequence

Per-message stamping monotonically fixes each message's expiry at
authoring; the admin can still flip-flop the policy ("strict" 1 minute
→ "less strict" 5 minutes → strict again) without retroactively
changing already-authored messages' stamps. That gives us monotonicity
*per message*, but loses the property that "all leaves in minute M
retire together at minute M+TTL" — different leaves in a minute can
retire at different boundaries. The FS tree therefore accumulates
per-leaf tombstones over time; pruning that debris requires either:

  1. A future fixed-TTL workspace mode (immutable disappearing setting
     baked into workspace creation), enabling whole-minute retirement.
  2. A periodic key rotation (new `removal_frontier`) that starts a
     fresh subtree, leaving the old debris tombstoned in a frontier
     nobody authors under anymore.

### Why keep the time axis at all (under mutable TTL)

The 2-axis tree (time tree + within-minute trie) is preserved despite
not exploiting whole-minute retirement under mutable TTLs. The
arithmetic shows the time axis is **structural overhead** in the
current mode:

  * Per-retirement walk depth = log₂(active_minutes) +
    log₂(messages_per_minute) = log₂(total_active_events). The 2-axis
    split *redistributes* depth between the time and trie axes; it
    does **not** reduce total depth versus a single trie of the same
    N.
  * Cost per retirement scales the same: ~log₂(N) materialized
    sibling rows + tombstones. Concrete bytes are ~0.5 KB × log₂(N)
    per retirement.

The reason to keep it is **option preservation**:

  * A fixed-TTL workspace mode (no admin-mutable setting; the TTL is
    set once at workspace creation and immutable) makes
    whole-minute retirement viable: one tombstone per minute_node
    collapses every descendant leaf in that minute, regardless of how
    many messages were in it. The reduction is from O(messages) to
    O(1) per retired minute.
  * Without a time axis baked into the tree, switching to a
    fixed-TTL mode later would require migrating every existing
    workspace's tree shape. Keeping the time axis preserves the
    option without a migration.

So the design choice for this branch is "carry slightly more code now
for the option to claw back per-retirement cost in a future fixed-TTL
mode." If poc-8 commits to mutable TTLs forever, the time axis is
dead weight and a follow-up could simplify to a single trie keyed on
event_id alone — but that's a one-way door and not worth taking
without a confirmed product decision against fixed TTLs.

### Latest-setting trust gap (recap)

Authors pick which admitted setting to reference. A malicious peer can
reference an *older more-permissive* setting to extend their messages'
effective TTL. Honest authors always reference the latest. Closing the
gap requires committing to a specific epoch (time-based, logical
order, or counter-based — see §6). Out of scope.

## Acknowledged Divergence From The Plan

The phase-two slice landed in
`src/protocol/event_modules/encryption/local_history_node_secret/` does not
match the original spec. Specifically:

1. **KDF.** The plan calls for BLAKE3-256-keyed-hash with domain separation.
   The implementation uses HKDF-SHA256 (see
   `local_history_node_secret/commands.rs:48` calling `crypto::hkdf_sha256_key`
   with purpose `b"topo local history node secret v1"`).
2. **Leaf granularity.** The plan's leaf coordinate is
   `(unix_minute, event_id)`. The current code uses a power-of-two `range_start
   / range_width` keyed off `u64` slots interpreted as `created_at_ms` (see
   `commands.rs` and `codec::validate_range`); leaves are message-grained, not
   minute-grained.
3. **No `event_id` in leaf coord.** Two messages with the same `created_at_ms`
   would derive the same leaf secret. The current `next_timestamp` helper in
   `core/logical_clock.rs` keeps locally authored timestamps strictly
   increasing, but it cannot prevent cross-peer collision: peer A and peer B
   may independently author messages at the same ms while offline.

Disappearing messages cannot be built honestly on top of (1) and (2) without
adding cross-peer collision risk and a node-per-event tree. Therefore this doc
assumes the corrected leaf shape:

```text
history_coord = (unix_minute, event_id)
leaf_secret   = KDF(removal_frontier_secret, "leaf", unix_minute, event_id)
minute_secret = KDF(removal_frontier_secret, "minute", unix_minute)
node_secret   = KDF(parent_secret, "left" | "right", node_prefix)
```

The KDF must be a real reviewed primitive. `core/crypto.rs` already exposes
`hash` (BLAKE3) and `hkdf_sha256_key`. Adding a `blake3_keyed_hash` helper with
domain-separation tags `"topo disappearing minute v1"`,
`"topo disappearing leaf v1"`, etc., is needed; it is not invented crypto, just
a domain-separated wrapper around BLAKE3's keyed mode. Until that helper
exists, disappearing-messages code should not claim to implement the spec.

A separate slice — outside the scope of this plan — must rewrite
`local_history_node_secret` to take `unix_minute` as a leaf coordinate and use
BLAKE3-keyed-hash. That slice unblocks (a) cross-peer collision safety and (b)
the per-minute coarse-grained puncture that disappearing messages depend on.
This document specifies disappearing messages on top of the corrected shape;
the two slices land separately.

## 1. Vocabulary And Event Types

### Scope choice: workspace-wide TTL with no per-message override

poc-7 (Quiet) historically modeled disappearing messages at workspace
granularity. The simplest workable choice for poc-8 is:

- **Workspace-wide TTL.** A single admin-signed shared event sets the TTL for
  every shared content event in the workspace.
- **No per-message override** in the first slice. Per-message TTL means every
  message must commit to its own expiry, which then has to round-trip through
  the encryption/key-wrap obligations as if every TTL were a private epoch.
  That cost is real and is rejected in the first slice.
- **Per-thread TTL** is rejected. poc-8 has no first-class thread event; adding
  one is a separate problem and is explicitly out of scope.
- **Per-author TTL** is rejected. Authors do not own the workspace's
  forward-secrecy boundary; admins do.
- **Per-recipient TTL** is rejected. poc-8 is p2p; recipients are equal peers,
  not server-managed accounts.

### New event types

```text
src/protocol/event_modules/encryption/disappearing_messages_setting/
  types.rs        // DisappearingMessagesSettingEvent
  codec.rs        // signed envelope; admin-authority dependency
  commands.rs     // set_workspace_ttl(ttl_minutes, signer_admin_id, ...)
  projector.rs    // writes (workspace_id, setting_event_id, ttl_minutes,
                  //   effective_at_ms) row; supersedes prior setting row
  schema.rs       // DISAPPEARING_MESSAGES_SETTINGS table
  cli.rs          // optional: admin command to set/inspect TTL
  mod.rs

src/protocol/event_modules/encryption/expired_minute/
  types.rs        // local-only ExpiredMinuteEvent
  codec.rs
  commands.rs     // expire_minute(workspace_id, removal_frontier_id, minute)
  projector.rs    // writes EXPIRED_MINUTES row + tombstone summary
  schema.rs
  mod.rs
```

`disappearing_messages_setting` is a **shared admin-signed event**. Its
canonical bytes carry:

```text
TYPE_DISAPPEARING_MESSAGES_SETTING (u8)
workspace_id           : EventId
created_at_ms          : u64
ttl_minutes            : u32   // 0 = disabled
effective_at_minute    : u64   // floor(created_at_ms / 60_000); included for
                               //   deterministic comparison without
                               //   re-deriving from created_at_ms
signer_admin_event_id  : EventId  // admin authority dependency
```

Wrapped in the existing `signed::codec` envelope used by `admin`, `user`, and
`endpoint_shared`. Dependencies: `workspace_id`, `signer_admin_event_id`,
`signer_endpoint_shared_id`. The signer's endpoint must be authorized by the
named admin user (same model used by `admin` projection today).

`expired_minute` is a **local-only** event. Its canonical bytes carry:

```text
TYPE_EXPIRED_MINUTE (u8)
workspace_id           : EventId
removal_frontier_id    : EventId
unix_minute            : u64
expired_at_ms          : u64    // logical time when expiry was projected;
                                //   diagnostic only, not in the summary
source_setting_id      : EventId  // disappearing_messages_setting that
                                  //   authorized expiry; dependency
```

Dependencies: `removal_frontier_id`, `source_setting_id`. The event id is
deterministic from canonical bytes per the existing rule that proposed event
ids come from canonical bytes (RULES.md, "Proposed Events Have Deterministic
IDs"). Two peers receiving the same setting and reaching the same
`unix_minute` independently produce the same `expired_minute` event id.

### What is shared vs local

| Event                              | Scope  | Sync? | Notes |
|------------------------------------|--------|-------|-------|
| `disappearing_messages_setting`    | Shared | Yes   | Admin authority. |
| `expired_minute`                   | Local  | No    | Each peer derives its own; convergence comes from determinism. |
| Existing `message`                 | Shared | Yes   | Plus a derived `expires_at_minute` projection row (see §3). |
| Existing `local_history_node_secret` | Local | No  | Already local. |

`expired_minute` deliberately does not become a shared event. The shared
ingredient is the setting; the time advance is local clock work. Two peers
that both reach minute `M` and both have the same setting derive the same
expired-minute fact independently. Making it shared would force every peer to
acknowledge every other peer's clock advance, which is the wrong shape.

This mirrors the encryption plan's local-secret-events principle:

> The most important correction from the older plan is that local secrets are
> events. They should participate in the common event pipeline like any other
> dependency. (`encryption_plan.md`, lines 17-19)

## 2. Setting And Changing Disappearing-Message Settings

### Authority

Any workspace admin can issue a `disappearing_messages_setting` event. This
matches the existing admin model in
`src/protocol/event_modules/identity/admin/`: admins sign workspace-scoped
authority events, and the projector validates the signer's endpoint against
its admin's `signing_public_key`. No quorum, no founder-only restriction. The
cost of being wrong is bounded — a later setting can always change the TTL,
and existing messages already carry their authored-time expiry (see below) —
so a single-admin authority threshold matches the rest of the workspace
admin model.

This matches poc-7 (Quiet) precedent: an admin/owner-equivalent role sets
disappearing-message policy.

### Propagation

A setting change is a shared event. Sync delivers it like any other shared
fact. Convergence rules:

- **Order-independent projection.** Two settings `S1, S2` with
  `S1.created_at_ms < S2.created_at_ms` produce the same active setting row
  regardless of arrival order, because the projector keys the
  active-setting row by `workspace_id` and replaces it iff the incoming
  setting has a later `(created_at_ms, event_id)` than the current row.
- **Late arrivals do not retroactively change message expiry.** A setting
  applies only to messages authored after its `effective_at_minute`; messages
  authored before that minute were already stamped with their authored-time
  expiry and remain expired or live according to the setting that was active
  at authoring time.

### Authored-time expiry stamping

Every shared content event must carry the expiry it was given when authored,
not look up the current setting at projection time. Looking up at projection
time would mean a setting change retroactively rewrites every message's
expiry, which is exactly what "late-arriving setting events should not change
already-authored messages" forbids.

The authoring path is therefore:

```text
message::commands::send(input, ctx)
  context.active_setting -> (ttl_minutes, setting_event_id)
  expires_at_minute = floor(input.created_at_ms / 60_000) + ttl_minutes
  // expires_at_minute = u64::MAX when ttl_minutes == 0 (TTL disabled)
  ...stamps expires_at_minute into the canonical bytes
```

The active setting is read through a narrow command-context query (per
RULES.md "commands receive explicit input values plus narrow read context
values"). It is not a worker drain.

### Conflicting concurrent setting changes

Two admins concurrently emitting `S1` and `S2` is the same problem as two
admins concurrently emitting other workspace settings. Resolution is the
existing pattern: order by `(created_at_ms, event_id)` deterministically. Both
peers converge on the same active setting once both events have synced. There
is no "winner takes all" race because the projector keys the active row by
workspace and replaces strictly under `(created_at_ms, event_id)` ordering.

If a message was authored under `S1` while `S2` was concurrently in flight,
the message is still stamped with `S1`'s TTL. This is correct: at the time of
authoring, `S1` was the message's view of policy. Subsequent peers will agree
on the per-message expiry because the message canonical bytes carry it.

## 3. Per-Message Expiry Vs Workspace Setting

### Recommendation: stamp `expires_at_minute` into `MessageEvent` canonical bytes

The two options are:

1. **In-event `expires_at_minute`.** Add a fixed-width `u64` to
   `MessageEvent` canonical bytes after the existing per-message FS field
   set. Disappearing messages then have a self-describing expiry that is
   deterministic from the canonical bytes — no projector lookup, no race
   between message and setting arrival.
2. **External projection table.** Keep `MessageEvent` unchanged and write
   `(message_id -> expires_at_minute)` rows derived from the active setting
   at projection time. This sounds cheaper but is wrong: it makes message
   expiry depend on which setting events have arrived, which violates "same
   shared event set converges to the same projected state regardless of
   order".

Option 1 wins. The trade-off is that every message event grows by 8 bytes,
but message canonical bytes are already fixed-width per RULES.md, so adding a
fixed field is exactly what the codec allows.

The new `MessageEvent` shape (and the parallel `ReactionEvent`,
`FileEvent`, `FileSliceEvent` shapes) becomes:

```text
TYPE_MESSAGE (u8)
workspace_id           : EventId
created_at_ms          : u64
author_user_id         : EventId
removal_frontier_id    : EventId
local_key_secret_id    : EventId
expires_at_minute      : u64    // NEW; u64::MAX = no expiry
nonce                  : XChaCha20Poly1305Nonce
ciphertext             : MessageCiphertext
```

The projector validates `expires_at_minute >= floor(created_at_ms / 60_000)`
and rejects messages whose stamped expiry is in the past at authoring time.
This is a sanity guard against forged events; it is not a forward-secrecy
boundary, since the projector cannot prove what the active setting *was* at
the message's `created_at_ms`. The forward-secrecy boundary lives in §4 (the
history tree puncture).

### File and reaction expiry

Files and reactions inherit the parent message's TTL. Their canonical bytes
also carry `expires_at_minute`, set to the parent message's value at
authoring time, not recomputed from the active setting. This keeps the
"authored-time expiry stamping" rule uniform across content event types and
avoids a parent-lookup race.

## 4. Integration With The Per-Message FS History Tree

### Leaf coord and minute granularity

Per the original plan (lines 277-281), the leaf coord is
`(unix_minute, event_id)`:

```text
unix_minute  = floor(created_at_ms / 60_000)
leaf_secret  = KDF(epoch_root, "leaf", unix_minute, event_id)
```

Minute granularity is **load-bearing** for disappearing messages. The
per-minute epoch node is the smallest unit at which expiry can advance. Sub-
minute granularity (per-second or per-millisecond) would create one node per
event in practice and force every expiry to puncture every leaf
individually, which defeats the cover-summary scheme. Coarser-than-minute
granularity (per-hour, per-day) makes expiry chunkier than users want.

Therefore the minute is the unit of:

- KDF derivation (one node per `unix_minute`),
- expiry advancement (one `expired_minute` event per minute),
- cover-summary commitment (the deletion summary commits to the set of
  expired minutes).

### Per-minute node key derivation

```text
minute_node_secret(workspace_id, removal_frontier_id, unix_minute)
  = blake3_keyed_hash(
      key   = removal_frontier_secret(workspace_id, removal_frontier_id),
      data  = "topo disappearing minute v1" || workspace_id || removal_frontier_id || unix_minute,
    )
```

`blake3_keyed_hash` lives in `core::crypto` and is a thin domain-separated
wrapper around BLAKE3's keyed-hash mode. The `removal_frontier_secret` is
already the source secret for `local_history_node_secret`; the new helper
just adds a minute-granularity derivation alongside the existing
range-node derivation.

### The "minute fully expired" condition

A minute is *fully expired* when, for every message authored in that minute
under the corresponding `removal_frontier_id`, the message's
`expires_at_minute < current_minute`. Because messages stamp their expiry at
authoring time, a minute's expiry is determined by the largest stamped
`expires_at_minute` among messages with `unix_minute(created_at_ms) == M`.

Equivalently, with workspace-wide TTL and no per-message override, every
message in minute `M` shares the same TTL `T`, so the minute fully expires
at `M + T + 1`. The general formulation supports a future per-message
override slice without changing the cover algorithm.

### Per-minute puncture and the "purge cover"

When a minute is fully expired, the receiver punctures the entire
`unix_minute` epoch node (not its leaves). After puncture:

- The minute node's secret is irretrievably gone (its row is deleted via
  exact-row-delete).
- Every per-message leaf under that minute loses its derivation source.
- All ciphertext bound to those leaf secrets is unrecoverable.

The deterministic-cover gain over phase one is that one tombstone retires
many leaves. Without this gain, every disappearing message would need its own
tombstone event, which scales badly.

The "purge cover" at minute granularity is a set of cover entries:

```text
purge_cover_entry = (removal_frontier_id, unix_minute)
```

distinct from the user-delete "leaf retain set" used by individual
`message_deletion` events:

```text
leaf_retain_entry = (removal_frontier_id, unix_minute, event_id)
```

Both feed into the same deletion summary in §6.

## 5. Ongoing Purge Of Cover, Keys, Events

The current `content_purge` worker drains *on demand*: deletion projection
writes a `content.purge_pending` row, the post-admission hook runs the worker
once, and the daemon's tick still belt-and-suspenders runs a full scan
periodically. See `src/workers/content_purge.rs` and
`src/protocol/event_modules/content/message_deletion/schema.rs`.

Disappearing messages need a **time-driven** drain. There is no admission
event to react to: the only signal is that the logical clock has advanced
past a minute boundary.

### New worker: `disappearing_minute_expiry`

```text
src/workers/disappearing_minute_expiry.rs

inputs:
  - logical_clock::logical_time(store)
  - active disappearing_messages_setting per workspace
  - existing per-minute message index (to enumerate non-expired minutes)
  - already-projected expired_minute rows (idempotent skip)

step:
  for each (workspace_id, removal_frontier_id) in active workspaces:
    let now_minute = floor(logical_time / 60_000)
    let setting    = active_disappearing_messages_setting(workspace_id)
    if setting.ttl_minutes == 0: continue
    for unix_minute in candidate_expired_minutes(workspace_id, now_minute):
      if expired_minute_exists(workspace_id, removal_frontier_id, unix_minute): continue
      // Build a deterministic expired_minute event and admit through the
      // common pipeline. The event's projector then:
      //   1. Walks every message + reaction + file + slice authored in
      //      this (workspace, frontier, unix_minute), writes tombstone
      //      summary rows preserving "this minute existed and held N
      //      events, now expired", and exact-row-deletes the read-model
      //      rows.
      //   2. Calls retention::purge_event_storage_in_tx for each event,
      //      removing canonical bytes (the same primitive used by
      //      content_purge today).
      //   3. Tombstones the minute's epoch node by exact-row-deleting the
      //      LOCAL_HISTORY_NODE_SECRETS row keyed by
      //      (workspace, frontier, range_start=unix_minute, range_width=1)
      //      after writing a LOCAL_HISTORY_NODE_TOMBSTONES row.
```

The worker calls `expired_minute::commands::expire_minute(...)` and admits
the proposed event through the common worker. It does not mutate storage
directly — that follows the encryption plan's rule:

> Derivation workers may create events, but only by calling commands and
> sending proposed events back through common admission.
> (`encryption_plan.md`, lines 36-38)

### Tick budget

The daemon already has `--tick-ms`; `disappearing_minute_expiry` registers as
a `daemon_step` worker on the same tick (see `content_purge::daemon_worker`
for the pattern). One scan per tick, bounded by the standard `work_limit`,
catches up the expired-minute set deterministically. Tick budget is
unchanged because the per-tick work is `O(minutes since last tick)`, which
is `O(1)` under any reasonable tick cadence.

### Logical clock interaction

The expiry worker reads from `crate::core::logical_clock::logical_time`,
which is the same source used by every CLI test today. Tests that need to
"advance time past TTL" call `clock advance` and then drain the daemon. This
keeps disappearing-messages tests deterministic: no real wall clock, no
flaky sleeps. Production binaries can either expose a `clock now` command
that snapshots system time into the logical clock, or set the logical clock
from system time on every tick — that policy choice belongs to the daemon
loop, not to the worker, and is the same choice already made for any other
time-sensitive worker.

### Writing tombstones, then purging

Order of operations within the transaction:

1. Write durable tombstone summary rows (one per expired event, plus one
   per expired minute).
2. Exact-row-delete the read-model rows (messages, reactions, file
   descriptors, file slices).
3. `retention::purge_event_storage_in_tx` to remove canonical bytes.
4. Exact-row-delete the corresponding `LOCAL_HISTORY_NODE_SECRETS` row,
   after writing a `LOCAL_HISTORY_NODE_TOMBSTONES` row pointing the
   retired minute node at the expiry event id.

Step 4 is what keeps a future replay from re-deriving the minute secret.
The tombstone row is the surviving public commitment that the minute
existed and is now gone, per RULES.md "purging may remove physical
evidence, but it must not be the only representation of a semantic
change".

## 6. Convergence, Per-Message Setting Reference, And The Trust Model

### Convergence comes from per-message stamping, not from a global
deletion summary

Each message commits to its own `expires_at_minute` in canonical bytes.
Two peers admitting the same byte sequence reach the same retirement
decision once their local clocks cross the stamped boundary. There is
no need for a shared "history of deletions" hash: every peer derives
identical retirement behavior from the byte-equal admitted set.

This is the load-bearing convergence claim. An earlier draft of this
section described an `Hset` deletion-summary commitment over
`(deleted_set, retained_cover, expired_minute_set)`. That commitment is
not necessary for convergence — it summarizes a state that is already
implied by canonical-bytes equality. It is preserved at the bottom of
this section as a future-work option for cross-peer audit / reporting,
but it is not part of the slice that ships.

### Per-message setting reference

`MessageEvent` carries `disappearing_setting_id: EventId` in canonical
bytes. The reference is one of:

  * The event id of a signed `disappearing_messages_setting` event for
    the workspace, when one has been admitted at authoring time. The
    author records *which setting they honored*.
  * The workspace event id, as the slice-1 fallback when no setting has
    been authored yet. The workspace event itself carries
    `disappearing_ttl_minutes` for this purpose.

The reference is added to the message's dependencies, so the projector
loads it through normal context. The projector enforces:

  * The reference is either the workspace event for that workspace, or
    a signed `disappearing_messages_setting` for that workspace; any
    other dep type is rejected.
  * `expires_at_minute` matches what the referenced setting permits:
    - If `permitted_ttl == 0` → `expires_at_minute == EXPIRES_NEVER`
    - Else → `expires_at_minute == authored_minute + permitted_ttl`
      where `authored_minute = floor(created_at_ms / 60_000)`
  * Mismatches are rejected at projection.

This eliminates the trust gap of the prior draft, where authors could
stamp arbitrary expiry. An author can now only stamp an expiry that
*some* admin-authored setting (or the workspace creation TTL) explicitly
permits.

### Trust model and known gap: latest-setting enforcement

A peer can still pick any setting it wants as the reference, including
an *older* setting whose `ttl_minutes` is larger than the latest. The
projector accepts any reference that is *some* admitted setting, not
specifically the *latest*. This is intentional for the slice that
ships: closing the gap requires an answer to the epoch question.

Concretely, a malicious peer can extend the effective TTL of its own
messages by referencing a stale setting. They cannot stamp arbitrary
expiry, but they can pick the maximum TTL ever set for the workspace.
Honest peers honor the stamped expiry as canonical fact, and
disappearance still happens; it just happens at the older setting's
boundary instead of the latest.

### Future work: closing the latest-setting gap with epochs

Three options for upgrading from "best effort" to "strict enforcement"
of the latest setting:

  * **Time-based** (simplest): the projector enumerates admitted
    settings for the workspace and rejects a message whose referenced
    setting was already superseded by a strictly newer setting at
    `message.created_at_ms`. Trusts admin clocks within a clock-skew
    bound.
  * **Logical order**: each setting carries a sequence number signed by
    the admin, or chains a dep on the prior setting. Eliminates clock
    trust but requires admins to coordinate.
  * **Counter-based**: a per-workspace monotonic counter, e.g. derived
    from a hash chain over admitted settings. Self-converging without
    clock trust.

All three are out of scope for this slice. The per-message reference
field gives us the hook for any of them later.

### Future work: optional `Hset` deletion summary commitment

The earlier draft of this section proposed:

```text
history_summary_id = Hset(
    "history-delete-summary v1",
    deleted_set,           // sorted by (unix_minute, event_id)
    retained_cover,        // sorted by canonical node prefix
    expired_minute_set,    // sorted by unix_minute
)
```

with a domain-separated BLAKE3 over the canonical sorted concatenation.
Useful as an audit primitive — it lets an external observer see two
peers agree on the entire deletion-and-expiry path that produced the
current cover, not just on the cover itself. Not required for
convergence (convergence is implied by canonical-bytes equality of
admitted messages), so deferred.

## 7. Edge Cases The Design Must Handle

### Cross-peer same-`created_at_ms` collision

Two peers offline-author messages with `created_at_ms = 1_700_000_000_000`.
Under the current `next_timestamp` scheme each peer's local clock is
strictly increasing, but cross-peer there is no coordination. With the
plan's `(unix_minute, event_id)` leaf coord:

- Both leaves land in the same `unix_minute` node.
- Each leaf is keyed additionally by its `event_id`, which is BLAKE3 over
  canonical bytes. Even if `created_at_ms` collides, the two messages have
  different ciphertext / nonce / signer and therefore different event ids.
- The two leaves are distinct under the leaf KDF; no key collision.

If the leaf coord were just `unix_minute` without `event_id`, both peers
would derive the same leaf secret and collide. Including `event_id` is what
makes the cross-peer collision case safe.

### Authored-but-not-synced expiry

Peer A authors a message with `expires_at_minute = M`. Peer A goes offline
for longer than the TTL. Peer B's clock is now past `M`. When peer A
reconnects, the message tries to sync to peer B.

Two policies are possible:

1. **Admit-and-immediately-purge.** Peer B admits the message through the
   common pipeline. Projection succeeds (the message is well-formed),
   writes the read-model row, then the disappearing-minute-expiry worker
   on the next tick observes that this minute has been expired-set since
   long before and purges. The read-model row blinks into existence and
   then disappears.
2. **Refuse at admission.** Peer B's `event_admission` checks the
   message's `expires_at_minute < current_minute` and rejects without
   projection.

Choice (2). Reasoning:

- The message's canonical bytes survive on disk as `Rejected`; that wastes
  no key material, since the rejection is deterministic from the message
  and the local clock.
- Choice (1) requires plaintext to materialize on disk briefly, which
  contradicts the "ciphertext-only durable shared event" rule.
- A future receiver coming online after their own clock has advanced past
  the expiry will reach the same rejection deterministically, so no peer
  needs to keep the bytes around as projection bait.

This matches RULES.md's general rejection model: the receiver decides
under the same projector rules every other peer would.

### Conflicting TTL settings

Two admins concurrently emit `S1` and `S2` with different TTLs. The
projector keys the active setting row by `workspace_id` and replaces it
strictly under `(created_at_ms, event_id)` ordering — last-event-wins by
deterministic compare. Both peers converge on the same active setting once
both events have synced. Messages authored under `S1` keep `S1`'s TTL;
messages authored under `S2` keep `S2`'s; messages authored after both have
synced use whichever event is "active" by the deterministic compare.

### Manual delete plus disappearing TTL

A user runs `delete-message` on a message whose disappearing TTL has not
yet fired. The existing `message_deletion` event projects, the
content_purge worker runs, the message's leaf is retired ahead of schedule.
Later, the disappearing-minute-expiry worker reaches that minute and tries
to puncture the minute node. The retired leaf is no longer present; the
minute-node retire still proceeds. The semantics are:

- Manual delete is monotonic with TTL expiry. Both end up with the
  message's canonical bytes purged.
- The expired-minute tombstone is the durable summary; the manual-delete
  tombstone is a sub-summary. Both survive; both contribute to the
  deletion summary id.
- Re-running expiry against an already-deleted minute is a no-op.

### Manually-deleted leaf inside a not-yet-expired minute

Mirror image: a single message in minute `M` is manually deleted via
`message_deletion`. Its leaf secret row is retired immediately by the
existing per-message FS retire path (`local_history_node_secret`
projection). Later, when minute `M` expires globally, the
disappearing-minute-expiry worker enumerates messages in `M` and finds the
already-deleted message with no read-model row. The worker:

- Skips the per-event tombstone for this message (already written).
- Continues with siblings.
- Retires the minute node when reached.

The no-op is clean: every step that "would have" purged the message
canonical bytes finds them already missing and proceeds without error.

## 8. Out Of Scope

Explicitly not in this design:

- **Per-thread TTL.** poc-8 has no thread event.
- **TTL on file events independent of the parent message.** Files inherit
  the parent message's TTL via the same authored-time stamp.
- **Admin-override TTLs that bypass the workspace setting.** No "admin can
  exempt this message" path. If admins need different policy for different
  messages, they change the setting and re-author.
- **Per-recipient TTL.** Every workspace member sees the same TTL. There
  is no "Bob's view expires faster than Alice's" mode.
- **Read receipts or per-reader expiry.** poc-8 does not model read state.
- **Server-side enforcement.** poc-8 is p2p; there is no server.
- **Fractional or sub-minute TTL.** TTL is a `u32` count of minutes.
- **Time-zoned or wall-clock-aligned TTL.** Expiry is in unix minutes; UI
  may render in local time, but the protocol counts minutes from epoch.
- **Resurrection of expired messages.** Once a minute is in the expired
  set, no event can un-expire it. A future "extend TTL" feature would need
  to be a different design with very different forward-secrecy
  consequences.
- **Sub-minute jitter / random expiry windows.** Expiry is deterministic
  from `(created_at_ms, ttl_minutes)`.
- **Disappearing CLI sessions, notifications, or sync state.** Only
  durable shared content events expire.

## 9. Implementation Order

Each slice must include realistic tests and must be committed on this
worktree branch before handoff (the encryption plan's worktree rule
applies).

### Slice 1: minimum viable disappearing messages

Smallest viable proof. No CLI for changing the TTL setting; the TTL is
baked into workspace creation as a fixed argument.

1. Add `core::crypto::blake3_keyed_hash` with domain-separated tags. (Or
   document the helper as the explicit prerequisite for slice 2 if slice
   1 can use HKDF-SHA256 honestly; pick one and surface it in code.)
2. Rewrite `local_history_node_secret` to take `(unix_minute, event_id)`
   leaf coords using BLAKE3-keyed-hash. This is the cross-peer collision
   fix and the per-minute node prerequisite.
3. Add `expires_at_minute: u64` to `MessageEvent` canonical bytes; codec
   length and tests update; projector validates non-negative future-or-
   past authored-time semantics.
4. Add a `workspace.disappearing_ttl_minutes` initialization argument to
   `workspace::commands::create`. Slice 1 hardcodes this at creation; no
   changeability yet.
5. Add `expired_minute` event module: types/codec/commands/projector/
   schema/mod. Local-only, depends on a synthetic
   "workspace_initial_setting" until slice 2 introduces the shared event.
6. Add the `disappearing_minute_expiry` worker. Register it on the
   daemon tick alongside `content_purge`.
7. Black-box CLI test: two endpoints, authored TTL = 1 minute, send a
   message, advance the logical clock past the minute, run sync + drain,
   assert the message is gone from both peers' read models and the
   canonical bytes are purged.

### Slice 2: setting events

8. Add `disappearing_messages_setting` shared event module. Admin-signed.
   Replace slice 1's hardcoded creation argument with the shared event.
9. Add admin CLI for setting the TTL.
10. Project setting changes; validate that messages authored under the
    pre-change TTL keep their stamped expiry.

### Slice 3: deletion summary monotonicity

11. Implement `Hset` deletion summary covering deleted_set,
    retained_cover, expired_minute_set.
12. Property tests for set-equality ⇒ id-equality, expiry idempotence,
    delete-then-expire / expire-then-delete commutativity.
13. Cross-peer summary-equality CLI test: peers reach the same summary
    after independent expiry advancement and a single manual delete.

### Slice 4: reactions and files

14. Stamp `expires_at_minute` into reaction, file, and file_slice
    canonical bytes. Inherit parent message's expiry at authoring time.
15. Extend the expiry worker to enumerate non-message content; verify
    purge of file-slice ciphertext when the parent message minute
    expires.

### Slice 5: rotation interplay

16. Test interaction with `recipient_key_tombstone` and
    `removal_frontier`: a frontier change mid-TTL leaves old-frontier
    minutes punctured under the old frontier's history tree; expiry
    worker enumerates per-frontier.
17. Test invite-time history grant: a newly invited endpoint receives
    only retained-cover nodes for not-yet-expired minutes, never an
    expired minute's secret.

After slice 5, disappearing messages compose with the rest of the
encryption plan: rotation, deletion, history-tree puncture, and ciphertext
purge all share the same deletion-summary commitment, and the daemon's
tick-driven worker keeps the on-disk state aligned with the current
logical time.

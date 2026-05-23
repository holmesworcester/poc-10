# Projector-Owned Dep-Aware Negentropy

This note describes the target dep-aware negentropy model for poc-10. The
negentropy tree is durable sync state, but dependency knowledge does not belong
to sync handlers. Each fact projector decides the sync leaf view for the fact it
is projecting and emits `add_to_negentropy` work with the shareable context it
already has.

## Goal

When a peer compares or requests a time range, it should receive the facts in
that range plus enough out-of-range context to project them quickly. For
encrypted content, that includes recipient keys, key wraps, retained key-node
wraps, and ordinary authority or deletion context.

The server remains untrusted. It can relay range summaries and bytes, but it
does not grant key authority. Missing-key and missing-context recovery is still
represented by facts, context needs/offers, and bounded intent handlers.

## Ownership Model

Projectors own negentropy membership. A projector that can decode a fact and
determine the workspace or handler namespace should emit an
`add_to_negentropy` intent for that namespace on the same projection pass that
emits its ordinary rows, offers, needs, wakes, or self-purge intent.

This applies even when the fact is parked for missing context. Parking means
"do not materialize the read model yet"; it does not mean "hide the fact from
sync". A parked projector can still say:

- this fact belongs in this sync leaf range.
- these matched context facts are already available.

The `add_to_negentropy` handler owns only durable index mechanics. It persists
the projector-supplied leaf contribution, updates ancestor summaries, and
advertises changed ranges to live connections. It must not infer dependencies by
scanning protocol rows, `context_edges`, or fact bytes.

Unresolved needs are deliberately not part of durable negentropy state. A need
is emitted before its payload fact has been loaded and, for many signed facts,
before the target projector can complete signature or authority checks. Hashing
or relaying raw need selectors through negentropy would let pre-auth input shape
the sync commitment surface. Needs remain ordinary projector output used by the
local context matcher and by explicit request flows; only validated offers and
their shareable owner facts become negentropy context.

## Leaf Contribution

An `add_to_negentropy` payload is a complete projector view for one owner fact
in one handler namespace:

```text
handler_namespace
workspace_id or other sync scope
owner_fact_id
owner_timestamp_ms
leaf_range
state: admitted | materialized | retracted
context_have[]
context_offer[]
```

`context_have` contains sync-eligible context facts that the projector has
validated or consumed in this pass. It should include exact input parents,
matched update/about facts, matched authority facts, key wraps, retained key
nodes, and other out-of-range witnesses that would help a receiver project the
owner fact. Local-only secrets must not be listed as sendable facts; projectors
should represent their shared coverage through the public facts or selectors
that peers are allowed to learn.

`context_offer` contains the public offer metadata associated with the included
context facts. It is useful when the receiver can match the transferred facts
without re-running unrelated range discovery. Offer metadata may be indexed
only after the projector that emitted it has decoded and validated enough input
to publish that offer. Missing selectors are not encoded here; a receiver that
still lacks context discovers that by projecting the received facts and emitting
its own local needs or signed request facts.

The leaf range is the owner's sync range, not the context fact's timestamp
range. This is what makes a message inside day N carry key and authority
context from day N-1 without requiring the receiver to guess another range.
Each context fact will also contribute to its own normal leaf when its projector
runs.

## Incremental Handler

`add_to_negentropy` is an upsert into protocol-owned negentropy tables keyed by:

```text
(handler_namespace, sync_scope, owner_fact_id, leaf_range)
```

The handler stores the canonical contribution and updates the persisted range
tree in the same transaction. The range hash should be a deterministic digest of
the owner fact identity plus sorted `context_have` and `context_offer` entries,
with counts stored beside fingerprints. When a contribution changes, the
handler subtracts the old contribution hash from affected ancestors and adds the
new one. The handler must be idempotent: replaying the same contribution is a
no-op, and replaying a richer later contribution cannot lose context learned by
an earlier pass.

Incrementality is load-bearing. Updating one leaf must touch only the stored
leaf contribution and the ancestor path from that leaf to the root. It must not
rebuild a namespace tree by scanning all leaves. Batches may coalesce shared
ancestors across several changed leaves, but the work should still be
proportional to the changed leaves and their unique ancestor set.

Intent identity must allow reprojection to enqueue changed views without
conflicting with an already queued older view. The safest shape is a
content-addressed intent key:

```text
hash("add_to_negentropy", handler_namespace, sync_scope, owner_fact_id,
     leaf_range, contribution_hash)
```

The durable row key remains owner-based, so many queued snapshots converge to
one stored contribution. To avoid depending on queue order, handler state should
be a monotonic join:

- owner membership moves from `admitted` to `materialized` to `retracted`, and
  never moves backward.
- `context_have` rows are inserted idempotently and kept as a union.
- `context_offer` rows are inserted idempotently and kept as a union, but only
  when they are backed by a shareable owner fact or authenticated protocol state
  the receiver is allowed to learn.

This keeps older queued snapshots from overwriting richer later context. If a
module has optional branches where an old context fact would become harmful
rather than merely extra, that same projector must emit the explicit prune for
its own owner id.

## Reprojection Flow

Projection still follows the normal poc-10 replacement model. A fact emits its
standing context needs and offers, core matches already stored offers, and core
may rerun the projector before committing the settled output. The settled
output may include `add_to_negentropy` with:

- no context, for a dependency-free fact.
- some `context_have` and `context_offer`, for a parked fact whose already
  validated context should travel with the owner fact.
- all required `context_have` and associated offers, for a fully materialized
  fact.

When new context later wakes the owner fact, the projector emits a new
contribution. The negentropy leaf hash changes because the context view changed,
even if the owner fact id and timestamp did not. Peers that already share the
owner fact but differ on context closure will still compare unequal and can
exchange the missing context facts or request facts.

The projector may still emit ordinary `ContextNeed` rows while parked. Those
rows wake local projection when matching offers arrive, but they are not hashed
into negentropy and are not advertised as leaf closure.

## Sync Response Behavior

Compare and response handlers should read only the durable negentropy index for
their handler namespace and connection-authorized scope. For a mismatched small
range, the response can include:

- owner fact ids in the leaf range.
- `context_have` fact ids attached to those owners, subject to the same
  connection authorization as ordinary shared facts.
- associated context offer metadata needed to match those context facts locally,
  also subject to authorization.

This keeps dep-aware sync bounded. The expensive semantic choice of what counts
as context was already made by projectors during projection. Sync handlers only
walk indexed range rows and exact leaf-context rows.

## Range Sync CLI

Implementation needs a black-box CLI surface for bounded range sync. The
command should drive the real runtime and connection/sync facts, not test-only
row seeding, and it should make dependency behavior observable:

```text
sync-range <peer-or-connection> --workspace <id> --start-ms <ms> --end-ms <ms>
  --with-deps
sync-range <peer-or-connection> --workspace <id> --start-ms <ms> --end-ms <ms>
  --without-deps
```

Exact spelling can follow the CLI's local conventions, but the behavior must be
available. `--with-deps` sends the owner leaves plus projector-supplied
`context_have` facts and associated offer context for those leaves.
`--without-deps` sends only the owner leaves in the requested range. That second
mode exists to prove the test is not accidentally passing because a full-range
sync happened.

`sync-range` is still ordinary established-connection transit. The CLI should
resolve the peer or connection, enqueue the same `send_facts_on_connection`
range intent used by background sync, and let the daemon-owned connection and
network handlers perform framing and socket egress. It should not build frames
or write to the network directly from the command path.

The current poc-10 implementation stores owner leaves and `context_have` rows
as projector-supplied `add_to_negentropy` contributions. Range sends walk those
rows for dependency closure and never rediscover dependencies by parsing fact
bytes in the sync handler. Raw needs remain excluded from the persisted rows.
That exclusion is a security boundary, not just a space optimization: a
projector may emit needs before the related signature or authority context has
validated, so only validated offers/context may become advertised negentropy
state.

## Purge And Retraction

Removal must use the same ownership boundary. When a target projector observes
deletion, expiry, supersession, or retirement context for its own fact, it emits
the ordinary row deletions/self-purge and a retracted negentropy contribution
or `remove_from_negentropy` intent for its own owner id. The handler removes
the stored contribution and updates ancestor hashes transactionally before or
with physical fact-byte purge.

Owner purge is the same minimal update as insertion: subtract the stored
contribution from that owner's leaf path and delete the leaf rows. The harder
case where purging one dependency invalidates other already-indexed leaves is
not required for the first implementation. If that path is added, it should be
driven by projector-owned reverse references from `context_have` facts or
bounded selector rows back to the affected owner leaves, then apply ordinary
leaf deltas for only those owners. It should not become a full tree rebuild or
a sync-handler dependency scan.

Sync must not rediscover purged ids from a stale shareable scan. A missing fact
row is not enough as the primary mechanism; the negentropy contribution for the
purged owner must also disappear or become a tombstone according to the module's
retention policy.

## Invariants

- Projectors decide which facts enter negentropy and which offer-backed context
  facts are attached to each leaf.
- Parked facts waiting on missing context can enter negentropy on first pass.
- `add_to_negentropy` handlers persist and hash supplied contributions; they do
  not infer dependency closure.
- Raw `ContextNeed` selectors are never persisted in negentropy state, hashed
  into range summaries, or sent as leaf closure; they are pre-auth projector
  hints until satisfied by validated offers.
- Leaf and owner-purge updates are incremental; no required update path rebuilds
  the full negentropy tree.
- Range summaries include context closure, not only owner fact ids.
- Local-only secret material is never exposed as sendable `context_have`.
- Purge/retraction removes the owner's negentropy contribution through the
  owner projector or its validated purge path.

## Implementation Tests

Add focused tests with the implementation:

- projector tests proving a parked encrypted/message fact emits
  `add_to_negentropy` with its current validated `context_have` and without raw
  `ContextNeed` selectors.
- guardrail tests proving unresolved needs do not affect negentropy hashes,
  persisted contribution rows, or range response payloads.
- handler tests proving idempotent upsert, ancestor hash delta updates, and
  richer snapshots do not regress when older queued intents run later.
- index tests proving one-leaf add/update/remove touches only that leaf's path
  to the root, with batched updates coalescing shared ancestors.
- purge tests proving a self-purged owner is removed from the persisted
  negentropy root and is not reintroduced by a follow-up sync round.
- two-peer sync tests where an in-range message depends on out-of-range
  authority/key context and the receiver projects or opens it without a second
  manual range request.
- black-box CLI range-sync tests where the message timestamp is inside the
  requested range, the signer/authority fact required to validate that message
  is outside the range, and `sync-range --with-deps` makes the message arrive
  and appear in `messages` without syncing the full range. The paired
  `--without-deps` case must not make the message viewable, proving the signer
  context came from dep-aware leaf closure rather than an accidental full sync.
- guardrail tests proving sync compare/response code reads the durable
  negentropy tables instead of scanning all facts or context rows for closure.
- final worktree step: commit the completed work on that same worktree branch
  before handoff or review.

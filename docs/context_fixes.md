# Context Fixes

This note records the planned context model fix for `main`. The current runtime
loads retained fact bytes as matched context payloads. That makes one fact
version's raw bytes part of another projector's dependency contract. It is the
wrong long-term boundary: fact versions can remain readable forever, but every
dependent projector cannot be updated forever for every dependency fact layout.

The replacement model is a provenance-backed semantic key/value context index.
Projectors publish offers as typed projection effects. Core stamps ownership and
producer identity. Later projectors consume matched offers, not arbitrary fact
bytes.

## Problem

Today a pending context match records the matching need/offer edge and, when the
pending owner is projected, core loads the offer owner's retained `Fact` as the
payload in `ProjectionContext`.

That couples consumers to producer fact bytes:

- a producer projector may correctly accept an old fact version and derive the
  current semantic meaning;
- a dependent projector may still expect the newer fact layout when core hands
  it the producer fact bytes;
- fixing that by teaching every dependent projector every historical dependency
  layout does not scale.

The semantic output of the producer projector should be the dependency surface.
The retained fact bytes are audit input for that producer, not a general context
payload API for other projectors.

## Context Shape

Needs are exact key requests.

```rust
NeedEffect {
    key: ContextKey,
}
```

Offers are key/value facts. Exact offers and range offers are distinct effects.

```rust
ExactOfferEffect {
    key: ContextKey,
    value: ContextValue,
}

RangeOfferEffect {
    start_key: ContextKey,
    end_key: ContextKey,
    value: ContextValue,
}
```

Core stamps all provenance:

```rust
StampedExactOffer {
    id: ContextOfferId,
    offering_fact: FactId,
    offering_fact_type: FactTypeId,
    key: ContextKey,
    value: ContextValue,
}

StampedRangeOffer {
    id: ContextOfferId,
    offering_fact: FactId,
    offering_fact_type: FactTypeId,
    start_key: ContextKey,
    end_key: ContextKey,
    value: ContextValue,
}
```

Projectors do not supply `offering_fact`, `offering_fact_type`, `needing_fact`,
or `needing_fact_type`. They only emit typed claims through a builder tied to the
registered projector that is currently running.

## Keys And Values

The context key contains the semantic kind plus its lookup parameters. The value
is one scalar byte value. Core treats both as opaque bytes.

Examples:

```text
key   = encode("message.author", message_fact_id)
value = author_user_id

key   = encode("message.created_at", message_fact_id)
value = created_at_ms

key   = encode("recipient_key.public_key", recipient_key_fact_id)
value = public_key_bytes

key   = encode("message.purged", message_fact_id)
value = deletion_fact_id
```

If a projector offers many fields, it emits one offer per field. Do not add a
generic structured offer value to carry several fields at once. A role-specific
helper may encode a scalar in a tiny canonical format, but generic nested
records should not be part of core context.

Exact offers are the common path. Range offers are explicit coverage claims:

```text
start = encode("retention.covers_message_at", workspace_id, start_ms)
end   = encode("retention.covers_message_at", workspace_id, end_ms)
value = policy_id
```

Then a message needing coverage asks for the exact key:

```text
key = encode("retention.covers_message_at", workspace_id, message_created_at)
```

Matching is:

```text
exact_offer.key == need.key
range_offer.start_key <= need.key <= range_offer.end_key
```

Needs do not need ranges in the new model unless a concrete future case proves
otherwise.

## Projection Effects

Offers are projection effects. They should not be exceptional state outside the
effect model, but they do need the projection-owned capability boundary.

Use two effect buckets:

```rust
RuntimeEffects       // generic committed work: facts, handler intents, etc.
ProjectionEffects    // fact-owned, producer-stamped effects
```

`ProjectionEffects` should include:

- needs;
- exact offers;
- range offers;
- projected row mutations;
- child facts;
- self purge;
- intents emitted by this projection.

Projected rows and offers both need owner/producer provenance. Row mutations are
also purged or reset as derived projection state, so they should go through the
same provenance-stamping builder rather than a separate ad hoc path.

## Builder Boundary

Incorrect producer labels should be unrepresentable.

```rust
struct ProjectionBuilder<P: RegisteredProjector> {
    owner: FactId,
    _producer: PhantomData<P>,
}

impl<P: RegisteredProjector> ProjectionBuilder<P> {
    fn need<K>(&mut self, selector: K::Selector)
    where
        K: NeedKind;

    fn offer_exact<K>(&mut self, selector: K::Selector, value: K::Value)
    where
        K: OfferKind<Producer = P>;

    fn offer_range<K>(&mut self, range: K::Range, value: K::Value)
    where
        K: RangeOfferKind<Producer = P>;

    fn insert_row<R>(&mut self, row: R)
    where
        R: ProjectedRow<Producer = P>;
}
```

The builder stamps:

- current projected fact id;
- registered projector/route/fact type;
- offer id;
- row provenance where applicable.

Verus should prove the builder once: every emitted offer/row carries the current
owner and registered producer. Per-projector proofs should then focus on
semantic truth, for example:

- `SignatureProjector` emits `signature.proof` only when the signature predicate
  holds;
- `WorkspaceProjector` emits workspace offers only when the accepted workspace
  proof exists.

Meta tests still matter for coverage:

- every registered projector has a proof module;
- every emitted offer kind has a producer theorem;
- every consumed offer kind has a consumer contract;
- negative or revocation offer kinds have completeness coverage;
- proof-bearing paths do not use raw payload context.

## Pending Projection

Pending projection should store references to matched offers, not duplicated
offer data and not payload fact assumptions.

Target shape:

```rust
PendingMatchedOffer {
    need: StampedNeed,
    offer_id: ContextOfferId,
}

MatchedOffer {
    need: StampedNeed,
    offer: StampedExactOfferOrRangeOffer,
}
```

`pending_projection_matches` should carry the pending owner, the need selector,
and the matched `offer_id`. When core loads `ProjectionContext`, it hydrates the
full offer from SQLite and gives projector code matched offers:

```rust
context.offer_for::<MessageAuthor>(message_id)
context.offers_for::<RetentionCoverage>(message_created_at)
```

It should not load the offering fact bytes as ordinary semantic context.

## Storage

Storage should mirror the exact/range split.

```text
context_needs
  owner
  role
  scope_key
  key

context_exact_offers
  offer_id
  owner
  owner_scope_key
  owner_received_at
  role
  scope_key
  key
  value

context_range_offers
  offer_id
  owner
  owner_scope_key
  owner_received_at
  role
  scope_key
  start_key
  end_key
  value

pending_projection_matches
  owner
  need_role
  need_scope_key
  need_start_key
  need_end_key
  offer_id
```

Indexes should preserve the current fast path:

- exact need -> exact offer: `key = ?`;
- exact need -> range offer: `start_key <= ? AND end_key >= ?`;
- purge by owner fact id;
- clear pending matches by `offer_id` or offer owner when an offering fact is
  purged.

`ContextOfferId` should be content-derived from the stamped offer fields with a
domain prefix, so duplicate semantic offers are idempotent and provenance is
included in the identity.

## Lifecycle

Context offers are derived projection state.

- Replay reset wipes needs, offers, pending projection matches, time wakes, and
  projected rows, then replays retained facts.
- Fact purge deletes offers owned by that fact and removes pending matches
  referencing those offers.
- Incoming facts that are dropped cannot leave durable offers behind.
- Retained facts may be old versions forever, but replay rebuilds current
  semantic offers from the projector that owns each retained fact.

## Regression Test

Add the failing test before the migration.

The test should construct:

1. A producer fact with an old/breaking byte layout.
2. A producer projector that can decode that old version and emits the current
   semantic offer, such as `message.author -> user_id`.
3. A consumer projector that needs `message.author(message_id)` and succeeds
   from the matched offer value.
4. An assertion that the same consumer would fail if it tried to decode the
   producer's old fact bytes as the dependency payload.

This proves the desired boundary: dependency projectors consume semantic offers,
not raw dependency fact layouts.

## Rollout

1. Add the regression test that demonstrates why raw fact payload context is
   brittle.
2. Add typed context keys, scalar values, exact offer effects, range offer
   effects, and offer ids.
3. Add the projection builder and route-bound producer stamping.
4. Change context storage and pending matches to reference offer ids.
5. Add `ProjectionContext` matched-offer APIs.
6. Migrate projectors from `payload_for` / `matched_payloads_for` to typed
   matched-offer helpers.
7. Retire or quarantine raw payload context behind explicit compatibility tests.
8. Add guardrail tests for builder provenance, exact/range matching, purge
   cleanup, replay reset, and proof coverage.
9. Run focused tests, then full `cargo test -- --test-threads=1`.
10. Commit the completed work on the same worktree branch before handoff or
    review.

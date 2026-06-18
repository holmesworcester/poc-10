# Inbound Origin Metadata Handoff

This is an implementation brief for the next agent. The goal is to make inbound
network durability projector-owned while preserving origin IP metadata through
fact replay.

## Target Model

Inbound transport has two phases:

1. Core intake stages opaque network bytes and volatile receive metadata.
2. Connection and wire projectors decide what ordinary facts should become
   durable.

Core may carry origin address and receive time only as process-local metadata on
incoming projection inputs. Any origin metadata that must survive replay must be
encoded in normal retained fact bytes, emitted by a projector. Replay must work
because the receipt or observation fact reprojects, not because core saved
metadata in a side table.

The main runtime shape is:

```text
other peer -> network -> incoming -> projection
pending ------------------------^
projection -> pending
projection -> durable facts, rows, offers, intents
```

`incoming` and `pending` are distinct queues. `incoming` is volatile intake for
outside-origin facts. `pending` is durable retained fact work.

## Required Ownership Boundaries

Core owns:

- Raw network byte staging.
- Process-local `incoming_facts` projection input.
- Optional volatile incoming metadata attached to an `incoming_facts` row.
- Pending projection, context matching, replay mechanics, and generic effect
  commit.

Core must not own:

- Durable origin metadata for retained facts.
- A retained-origin side table.
- Protocol decisions about which received bytes deserve durable metadata.
- Connection-specific receipt or observation construction.

Connection and wire projectors own:

- Classifying accepted connection wire facts.
- Reading volatile incoming metadata while projecting an incoming wire fact.
- Emitting contained semantic facts directly.
- Emitting durable local receipt or observation facts that contain origin
  address and receive time.
- Deciding whether a volatile wire wrapper is retained, dropped, or purged.

## Fact Flow Rules

Network receive must stage bytes before semantic durability:

1. TCP receive writes raw bytes into a core-owned incoming network queue.
2. Protocol intake classifies recognized connection wire frames into volatile
   incoming facts.
3. The incoming fact's projector receives origin metadata through projection
   context only while the row is in `incoming_facts`.
4. The projector emits durable metadata facts with `ProjectionOutput::fact(...)`
   when metadata should survive.
5. The projector emits contained semantic facts with
   `ProjectionOutput::incoming_fact(...)`, so those facts still go through their
   owning projectors before retention.

Do not make bootstrap connection request or response frames special. They enter
incoming projection like every other received connection fact. Their projectors
decide whether to retain themselves and whether to emit durable receipt facts.

For established connection frames:

- `connection_frame_small`, `connection_frame_file_slice`, and
  `connection_frame_bundle` are volatile wire wrappers.
- Their projectors consume incoming metadata and connection context.
- On successful open, they emit each contained semantic fact directly with
  `incoming_fact(...)`.
- For each received semantic fact that needs origin evidence, they emit a
  durable `connection_fact_receipt` with `fact(...)`.
- If an about-frame observation fact remains required, it must also be a normal
  projector-emitted durable fact, not core-retained metadata.
- Invalid frames drop from incoming without durable metadata.

## Replay Requirement

Fact replay means derived state is cleared while retained fact bytes remain.
After replay:

- Origin IP and receive time for retained received facts are still available.
- `connection_fact_receipt` facts reproject and recreate their offers and
  receipt-origin rows.
- Any retained `connection_frame_observation` facts reproject and recreate their
  offers.
- No projector obtains origin metadata from core for a durable retained fact.

The only acceptable reason origin metadata survives replay is that it is inside
ordinary retained fact bytes.

## Forbidden Implementations

Do not implement any of these:

- A durable core table such as `retained_fact_origins`.
- Durable origin columns on `facts`, `local_fact_admissions`, or
  `pending_projection`.
- A replay-protected core metadata table for incoming origins.
- A handler or daemon path that writes receipt rows directly from raw inbound
  bytes.
- A projector that depends on `incoming_metadata()` while projecting a durable
  retained fact.
- A connection-frame projector that stores opened child facts directly as
  durable facts before their owning projectors run.
- A special durable fast path for bootstrap `connection_request` or
  `connection_response`.

## Suggested Implementation Order

1. Start from current `main` in a fresh worktree and branch.
2. Add or adjust core incoming staging so raw inbound bytes go to an incoming
   network queue, then classified facts go to `incoming_facts`.
3. Keep incoming origin metadata volatile: it may be stored on temp
   `incoming_facts`, but nowhere durable in core.
4. Ensure durable projection inputs never receive ambient incoming metadata from
   core.
5. Update connection request and connection response projection so received
   bootstrap facts emit durable `connection_fact_receipt` facts when they accept
   the inbound path.
6. Update established connection-frame projectors so opened child facts use
   `incoming_fact(...)`, while receipt or observation metadata facts use
   `fact(...)`.
7. Update architecture docs and diagrams to show `network -> incoming ->
   projection` and the separate `pending -> projection` input.
8. Add realistic tests that prove the runtime, projector, and replay behavior.
9. Commit the completed work on that same worktree branch before handoff or
   review.

## Success Criteria Checklist

The implementation is not complete until every item below is true.

- [ ] `git grep -n "retained_fact_origins"` returns no target-code hits.
- [ ] Core schema has no durable origin metadata table and no durable origin
      columns.
- [ ] Origin address and receive time are present only in volatile incoming
      staging or in protocol-owned fact bytes.
- [ ] Durable projection context does not expose incoming origin metadata.
- [ ] Incoming projection context exposes origin metadata only for rows staged
      from network intake.
- [ ] Runtime diagrams show `other peer -> network -> incoming -> projection`
      and a separate `pending -> projection` input with pending loopback.
- [ ] Bootstrap `connection_request` and connection response facts enter
      `incoming_facts`; there is no special durable-before-projector path.
- [ ] Bootstrap receive projectors emit durable `connection_fact_receipt` facts
      through projector output when the inbound path is accepted.
- [ ] Established connection-frame projectors emit contained semantic facts with
      `incoming_fact(...)`, not `fact(...)`.
- [ ] Established connection-frame projectors emit durable local receipt or
      observation facts with `fact(...)`.
- [ ] Invalid or unauthenticated incoming wire facts can be dropped without
      durable receipt or observation facts.
- [ ] No handler writes connection receipt rows directly from inbound network
      bytes.
- [ ] No daemon path constructs durable receipt, observation, or origin facts
      from inbound network bytes.
- [ ] A replay test clears derived state while retaining facts, reprojects, and
      proves origin IP metadata is restored from retained receipt or observation
      facts.
- [ ] A test proves a durable retained fact projection has no ambient incoming
      metadata available from core.
- [ ] A test proves a connection-frame projector emits opened children as
      incoming facts and receipt or observation metadata as durable facts.
- [ ] A test proves bootstrap receive facts are staged through incoming
      projection and emit receipt facts from their projectors.
- [ ] Documentation states that replay-preserved origin metadata is ordinary
      protocol fact data, not core metadata.
- [ ] `cargo fmt` passes.
- [ ] The focused tests added for this change pass.
- [ ] Full `cargo test` passes, or any failure is shown to be unrelated and
      documented with concrete evidence.
- [ ] The final commit contains the implementation, docs, and tests on the same
      worktree branch.

# Dep-Aware Sync

This note describes the target dep-aware sync model for poc-10. It replaces the
old worker-queue design with facts, context needs/offers, and bounded sync
handlers.

## Goal

When a peer asks for a time range, it should receive enough facts to project the
facts in that range quickly, even if necessary context lies outside the range.
For encrypted content that means keys as well as ordinary dependencies.

The server is untrusted. It may relay range summaries and bytes, but it cannot
grant key authority. Missing-key requests and responses are facts.

## Relationships To Track

Sync should reason over context relationships, not hidden queues:

- exact input: a fact requires another fact id before it can apply.
- update/about: a later fact changes context for an earlier fact, such as
  deletion, supersession, receive provenance, or purge relevance.
- selector need/offer: a fact needs or offers context described by a selector,
  such as key coverage for a frontier/minute/leaf range.

The same `context_edges` relation that wakes projection should be usable to
discover what out-of-range facts matter for a range.

## Range Closure

For every candidate fact in the requested range, sync should include:

- exact input parents that are not already known by the receiver.
- relevant update/about facts for the target fact, even when those updates are
  later than the requested range.
- matched offers for standing needs that are required for projection.
- key-wrap and retained-key offers needed to open encrypted content.

This closure should be bounded. If a selector can match too broadly, the matcher
or event module must impose a stable limit and fall back to explicit request
facts.

## Encrypted Content

For encrypted content in a range, sync must make the key path fast:

- include recipient key facts needed to validate wraps.
- include key wraps addressed to the receiving endpoint when known.
- include retained history-node wraps when the frontier root is gone.
- include key-request facts if the receiver still lacks coverage.

The receiver should usually display content without a second round trip because
proactive deterministic wraps exist. Concurrent or partitioned joiners recover
through deterministic key requests.

## Handler Shape

Sync handlers are bounded intent handlers:

- `handle_sync`: interpret one inbound sync fact or compare result and emit
  precise follow-up facts/intents.
- `sync_index_update`: update durable sync summary/checkpoint state, or keep the
  intent queued until the target durable index exists.
- transit send handlers package sync facts as ordinary facts; sync does not own
  sockets.

There is no sync worker. Sync behavior is modeled as facts, context, and
bounded intent handlers.

## Performance Proof

The required performance test is a one-day-out-of-range dependency case:

1. message fact is inside the requested range.
2. dependency/key facts are outside the range.
3. sync closure includes the required context.
4. projection/opening completes without waiting for a second manual sync.

The encrypted version must prove that key wraps or retained key-node wraps are
included because the context relationship is known, not because the receiver
guessed a separate key request first.

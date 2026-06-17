# TODO: Fast Batch Generation

This document records the current ideas for making `generate` fast without
breaking the poc-10 pipeline model.

## Current Observation

The current poc-10 generate path is model-correct but expensive:

1. The CLI builds `AuthoredFacts` containing many message facts.
2. Runtime commits those facts and marks each one pending for projection.
3. The daemon drains pending projection work.
4. Projectors emit `share_fact_with_sync` intents.
5. The share handler records sync contributions and updates negentropy state.
6. CLI-visible state appears through normal daemon work, so black-box tests wait
   for projected rows instead of relying on command-local settlement.

With durable projection transaction batching added, release CLI measurements on
this worktree were:

| Case | Local main | Batched durable projection |
| --- | ---: | ---: |
| `generate 1000 128` average | about 1750 ms | about 1195 ms |
| `generate 3000 128` | 5757 ms | 3749 ms |

That is a useful 30-35% improvement, but not an order-of-magnitude change.

A profiled 1000-message run after durable projection batching still spent most
time in:

- Projection and context matching.
- `share_fact_with_sync` handler dispatch.
- Per-fact negentropy path updates.
- Per-fact share contribution recording.

## Why poc-7 Is Faster

poc-7 generation is faster because it is bulk-shaped across more of the stack:

- It loads local authoring context once.
- It explicitly opens one SQLite transaction per generated batch.
- Each inner create still calls the normal create/project path, but nested
  transaction guards no-op when an outer transaction is already active.
- Sync range negentropy is mostly built lazily from `shared_event_index` and
  cached, rather than maintaining a richer projector-supplied tree contribution
  for every generated event during daemon-driven projection and handler work.
- Many perf helpers call the Rust generation path directly, avoiding extra
  black-box CLI process overhead.

poc-10 should not blindly copy the test-only shortcuts. The useful lesson is to
batch at the same semantic boundaries the normal pipeline already owns.

## Constraints

Keep these constraints unless we intentionally create a test-only command:

- Generated facts must use the same fact shape, signing, encryption, projection,
  sharing, and sync visibility rules as normal message creation.
- Projectors remain the source of share/context/negentropy contributions.
- The queued handler model stays intact: commands may enqueue effects, but
  daemon/network egress remains daemon-owned.
- Batched projection work must preserve context visibility for facts processed
  earlier in the same batch.
- Batched work must be atomic at its chosen chunk boundary.
- A later failure in a chunk must not leave earlier same-chunk projection or
  handler state half-committed.
- The black-box CLI behavior should stay representative of real command usage.

## Model-Preserving Work

### 1. Batch Durable Projection Transactions

Status: implemented on this worktree.

Durable pending facts are processed in bounded chunks. Each fact still runs:

```text
load pending fact -> prepare projection effects -> commit projection effects
```

The difference is that a chunk shares one SQLite write transaction. That removes
per-fact transaction overhead while keeping projection order and same-batch
context visibility. Ephemeral projection stays on the old per-input path.

Tests should cover:

- A later pending fact can read context written by an earlier pending fact in the
  same chunk.
- If a later fact fails, earlier same-chunk projection state rolls back.

### 2. Batch Handler Dispatch for Homogeneous Intents

The next likely win is batching `share_fact_with_sync` handling.

Today, generate emits many homogeneous share intents. Each intent validates,
records a contribution, updates negentropy, and commits through normal handler
dispatch. A model-preserving batch path would let the dispatcher group adjacent
or same-kind intents and call an optional handler batch API:

```text
load inputs for N intents -> handler prepares N effects -> commit all effects
```

For `share_fact_with_sync`, the handler can still be mechanical:

- Decode each intent.
- Require the owner fact for upserts.
- Validate only associated offered context, never untrusted needs.
- Record the projector-supplied sync contribution.
- Update the persisted negentropy contribution/tree state.
- Emit any allowed local follow-up effects.

The important change is that many share contributions and negentropy updates
commit under one transaction or one chunked set of transactions.

Tests should cover:

- Mixed valid and invalid share intents roll back at the batch boundary.
- Duplicate/idempotent share intents remain idempotent.
- Commands still do not dispatch handlers while committing authored facts.
- Live-tail network egress is not sent directly by the command path.

### 3. Batch Negentropy Path Updates

The current per-fact share handler updates the path from leaf to root. That is
incremental and model-correct, but generate touches many leaves in the same
range. A batched updater can compute the union of dirty leaves and rebuild the
minimal affected internal nodes once per chunk.

This should keep the same persisted tree shape and the same projector-supplied
leaf contributions, but change the update algorithm from:

```text
for each leaf: update leaf path to root
```

to:

```text
collect dirty leaves -> update dirty leaves -> rebuild unique dirty ancestors
```

Tests should cover:

- Batched output hashes equal repeated single-update output hashes.
- Updating many leaves in one range rebuilds shared ancestors once.
- Purge/retract updates only the theoretically necessary paths where practical.

### 4. Statement Reuse Inside Hot Loops

Projection and share handling repeatedly run the same SQL statements. Once the
transaction boundaries are chunked, prepared statement reuse may be a smaller but
clean win.

Candidates:

- Pending fact loads.
- Previous context loads.
- Exact/range context matching.
- Context replacement inserts/deletes.
- Share contribution upserts.
- Negentropy leaf and node updates.

This should be hidden behind small store helpers or transaction-scoped helper
objects, not spread as ad hoc SQL caches through protocol code.

### 5. Command-Level Chunking

For very large generate counts, the command should probably chunk work at a
higher level too:

```text
build facts for chunk -> commit facts -> settle chunk -> repeat
```

This bounds memory and keeps long-running commands from holding too much state.
It also makes progress reporting natural. The chunk size should be large enough
to amortize pipeline overhead but small enough to avoid long write locks.

This is different from a special test-only bypass: each chunk still uses normal
fact admission, projection, handler dispatch, and sync contribution logic.

## Test-Only Option

If we need a pure data-generation tool for stress tests, it should be explicitly
named and documented as not representative of normal creation. For example:

```text
generate-fixture
```

That command could write precomputed facts/projections/sync rows directly, but
it should not be used as evidence that the normal command/projection path is
fast. It is useful for network, download, storage, or sync-setting scale tests
where authoring cost is not the subject.

## Preferred Order

1. Keep durable projection transaction batching.
2. Add homogeneous handler batch dispatch, starting with `share_fact_with_sync`.
3. Batch negentropy dirty-leaf/path updates inside share handling.
4. Reuse prepared statements inside the hot transaction-scoped loops.
5. Add command-level chunking for very large generate counts.
6. Only add a test-only fixture generator if perf tests need datasets larger
   than the normal creation path can reasonably produce.

## Success Criteria

The goal is not just "generate is fast" but "normal fact creation is fast":

- `generate 1000 128` should move toward sub-second release CLI wall time.
- `generate 10000 128` should be practical as a black-box test setup.
- Normal single-message send should not get more complex or slower.
- The code should still explain itself in pipeline terms: facts, projection,
  queued handler effects, and persisted sync contributions.
- New batch APIs must have realistic tests for atomicity, idempotency, and
  same-batch context visibility.

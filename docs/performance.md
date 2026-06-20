# Performance

poc-10 optimizes for a uniform fact projection model. Facts are admitted,
projected, parked on explicit context needs when blocked, woken by matching
offers, and replayed through the same runtime machinery. This keeps the model
small and rebuildable, but it makes high-volume message flows more expensive
than poc-7's more specialized event pipeline.

The current performance conclusion is that the largest gap is structural, not a
single SQLite setting. The model pays for more facts, more dependency edges, and
more blocking/unblocking work. Small storage tuning helps only at the margin.

Detailed benchmark runs and unmerged optimization experiments live on the
`projection-drain-batch` branch. Main carries the replay perf fixture and this
write-up, but not the projection batching or storage-tuning commits from that
branch.

## Current Conclusion

poc-10 is slower than poc-7 for generated messages primarily because the current
fact graph does more work per user-visible message:

- A connection frame is itself a fact.
- Connection frames are often one-to-one with payload facts instead of carrying
  many facts per frame.
- Blocking and unblocking are queue-driven projection work. A dependency-hostile
  order parks facts and wakes them later instead of doing a single topological
  pass.
- Signatures are separate facts, and message facts depend on signature facts.
- Durable projection batching matters, but it is not the main gap.
- poc-7-style SQLite page-cache and row-storage tweaks are not a major lever in
  the replay fixture.
- The normal message replay fixture does not show strong O(N^2) scaling through
  20k messages.
- True range matches still represent real mathematical risk. Time wakes and
  broad key-tree/key-availability ranges can match many facts as state grows, so
  they need more care than exact fact-id dependencies.

The practical direction is to keep the model and improve the implementation:
batch where the current runtime already owns a batch boundary, cache hot fact
loads and decoded fact material, pipeline independent work, and add concurrency
where ownership boundaries are clear.

## Projection Cost Shape

For exact dependencies, each fact only needs a bounded number of other facts.
That dependency shape is not inherently quadratic. The cost comes from the
runtime path used to discover readiness:

```text
project fact
  -> emit standing needs if context is missing
  -> store needs
  -> later store matching offers
  -> wake owners
  -> requeue projection
  -> reload fact and matched context
```

A topological replay such as Kahn's algorithm can maintain an in-memory
ready-set and process each edge once. poc-10's durable context model instead
persists needs and offers, records pending matches, and revisits facts through
ordinary queue workers. That buys crash-safe, uniform replay semantics, but it
can add a constant multiplier for each dependency edge and extra work when facts
arrive in a bad order.

This multiplier is different from an algorithmic range explosion. Exact
fact-id dependencies should remain roughly linear in the number of facts and
edges. Broad range matches can grow with the number of matching facts in the
range and therefore need separate indexing, aggregation, or scheduling rules.

## Measured Runtime Batching

The replay fixture was run with 5000 generated messages in runtime order. The
baseline was the same code with `TOPO_PROJECTION_BATCH_SIZE=1`; the batched case
used batch size 25.

| Case | Median drain time | Interpretation |
| --- | ---: | --- |
| Batch size 1 | 7711 ms | Baseline |
| Batch size 25 | 6282 ms | 18.5% faster than size 1 |

Equivalently, turning batching off is about 23% slower than batch size 25 in
this fixture. This is a real win, but it is not large enough to explain the
poc-7 gap by itself.

## Measured Storage Tweaks

The same 5000-message runtime-order fixture was used to isolate storage tweaks
on top of batch size 25.

| Tweak | Median drain time | Delta versus batch-only |
| --- | ---: | ---: |
| Batch only | 6282 ms | baseline |
| Larger SQLite page cache | 6228 ms | 0.9% faster |
| Cached prepared statements | 6212 ms | 1.1% faster |
| `WITHOUT ROWID` hot tables | 6220 ms | 1.0% faster |
| Page cache + cached statements | 6222 ms | 1.0% faster |
| All storage tweaks | 6223 ms | 0.9% faster |

These changes are directionally reasonable, but the measured effect is inside
normal benchmark noise for this fixture. They should not drive architectural
decisions.

`WITHOUT ROWID` is still the right shape for set-like tables keyed by the
declared primary key. SQLite rowid tables with BLOB or composite primary keys
store both a hidden rowid table and a separate primary-key index. `WITHOUT
ROWID` makes the declared primary key the table btree. That helps set-like
queues such as pending projection, but it should not be applied to queues that
depend on insertion order unless they first gain an explicit sequence column.

## Message Replay Scaling

Random-order replay stresses parking and waking because dependent facts are
queued in an intentionally poor order. The current 5k, 10k, and 20k random runs
used batch size 25 and a longer idle timeout for the perf harness.

| Messages | Drain samples | Median drain | Median throughput |
| ---: | --- | ---: | ---: |
| 5000 | 10784 / 9589 / 8604 ms | 9589 ms | 521 msg/s |
| 10000 | 22417 / 22459 / 23374 ms | 22459 ms | 445 msg/s |
| 20000 | 39408 / 40942 / 40322 ms | 40322 ms | 496 msg/s |

The scaling ratios were:

- 5000 to 10000: 2.34x time for 2x messages.
- 10000 to 20000: 1.80x time for 2x messages.
- 5000 to 20000: 4.20x time for 4x messages.

That shows order sensitivity and benchmark variance, but not strong quadratic
growth through 20k messages. The message projection test does not prove a major
algorithmic nonlinearity in exact-dependency projection.

## Real Nonlinear Risks

The real nonlinear risks are broad range relationships:

- Time wakes can wake every owner whose wake time falls in a queried range.
- Key-tree or key-availability ranges can cover many facts if represented as
  broad ranges rather than exact key facts or aggregated checkpoints.
- Any context range whose width grows with history can make one new offer or one
  new need match many standing rows.

These are mathematically different from exact message dependencies. If a range
can match `M` owners, then a single projection commit can enqueue `O(M)` work.
If many facts repeatedly publish overlapping broad ranges, the total can become
superlinear even when each individual fact has a small number of logical
dependencies.

## Future Work

The model does not need to change just to close the current measured gap. The
next performance work should keep the projection and context semantics intact:

- Bundle multiple facts per connection frame where transport semantics allow it.
- Add connection send modes for immediate sends versus bundled sends.
- Batch homogeneous intent handling, especially sync-sharing work.
- Cache hot fact bytes and decoded typed facts during a projection drain.
- Add explicit in-memory ready queues or dependency indexes for replay without
  changing durable context semantics.
- Use concurrency for independent projection or intent work once table ownership
  and commit boundaries are clear.
- Treat broad range needs and offers as a separate optimization problem: avoid
  needless ranges, aggregate large ranges, and make range wakeups proportional
  to useful work.

The current evidence supports treating the storage tweaks as investigation
results rather than merging them for their own sake.

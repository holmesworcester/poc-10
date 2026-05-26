# TODO: Efficient Dep Search

This document records the work needed to make exact dependency expansion tight
to the selected facts instead of the timestamp span that contains them.

## Current Observation

`expand_fact_ids_with_context_for_connection` is finite and connection-bounded,
but it is not selective enough for sparse exact sends.

The current path:

1. Loads all facts shareable on the connection.
2. Finds the minimum and maximum timestamp among the selected ids.
3. Calls `shareable_facts_for_connection_range(..., include_deps=true)`.
4. Seeds dependency expansion with every authorized fact in that timestamp span.

That means two selected ids far apart in time can pull unrelated authorized
facts between them before dependency closure runs. The walk still stops at
missing, purged, unauthorized, and local-only facts because those facts are not
present in the connection-authorized shareable set, but the initial candidate
set can be much larger than the selected ids plus their reachable dependencies.

## Target Behavior

Exact selected-id sends should expand only through stored `context_have` edges
reachable from the requested roots.

The bounded shape should be:

```text
requested roots + reachable authorized context_have edges
```

not:

```text
all authorized facts between min(selected.timestamp)..max(selected.timestamp)
```

The output should still preserve the sync security boundary:

- Only facts shareable with the connection may be emitted.
- Dependency expansion uses stored `context_have` rows, not decoded payload
  scans.
- Missing, purged, unauthorized, and local-only facts stop the walk.
- Cycles and repeated dependencies terminate through visited-set dedupe.
- Dependencies should be ordered before roots when both are selected for send.

## Minimal Work

Replace `expand_fact_ids_with_context_for_connection` with an exact graph walk:

1. Build the connection-authorized shareable map once, keyed by fact id.
2. Track the authorized workspace ids that expose each shareable fact.
3. Start traversal from the requested fact ids only.
4. For each selected fact id, load `negentropy_context_have_for_leaf` only for
   the authorized workspace leaves that expose that fact.
5. Recursively visit context facts that are also present in the authorized map.
6. Emit facts after their dependencies so explicit sends can project in one
   receive pass.

Keep `shareable_facts_for_connection_range(..., include_deps=true)` available
for bucket/range callers until range sync has its own dep-aware index. Do not
make selected exact-id expansion call the range helper.

## Larger Follow-Up

The range path should eventually use a sync-owned dependency index rather than
request-time recursion. The useful split is:

- direct dependency rows: `(workspace_id, owner_fact_id) -> dep_fact_id`
- present closure rows: `(workspace_id, root_fact_id) -> dep_fact_id`
- optional waiter rows for dependencies that become shareable later
- range/node summaries that include present external dependency contribution

Request-time compare and exact send planning should then read precomputed root
and present-closure rows. They should not recursively decode payloads or expand
through timestamp spans while answering a request.

## Reference Patterns

Use the selected-send shape from `poc-7`: exact requested ids are filtered for
sendability, then recursively visited through direct dependency rows, with deps
emitted before roots.

Use the `poc-8` sync-worker direction for the durable index shape: keep direct
deps, known closure, present closure, and request-time reads separate.

## Tests

Add realistic tests with the implementation:

- Sparse selected roots do not include unrelated authorized facts between their
  timestamps.
- A recent selected root includes an old transitive dependency chain outside the
  root timestamp range.
- Dependencies are emitted before roots.
- Unauthorized, missing, purged, and local-only dependencies stop expansion.
- Cycles and repeated dependencies terminate and dedupe.
- Existing range-with-deps behavior remains covered until it is intentionally
  replaced by the durable closure index.

## Worktree Task Checklist

1. Implement exact selected-id dependency expansion in
   `src/protocol/sync/shared_fact/rows.rs`.
2. Keep the public behavior connection-authorized and based only on stored
   `context_have` rows.
3. Add or update tests for the cases above.
4. Run the narrow relevant tests, then broaden to the sync/protocol test set if
   the implementation touches shared helpers.
5. Commit the completed work on that same worktree branch before handoff or
   review.

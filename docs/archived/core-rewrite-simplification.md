# Core Rewrite Simplification

This note evaluates whether `src/core` can be rewritten much smaller in lines
and simpler in logic, and concludes where the real leverage is. It judges every
candidate against the constraints that define the runtime: atomic crash-safe
commit, deterministic replay, peer-to-peer out-of-order convergence, fast mobile
start, and core protocol-neutrality. A change that violates one of those is a
non-starter regardless of its line count.

The figures below are net, post-replacement estimates: a deletion that forces
new code to recover a property SQLite gave for free is counted at its true net,
not its gross deletion.

## Conclusion

There is no "much simpler" wholesale rewrite of core that preserves the
constraints. Core is already near its essential floor.

Two facts reframe the question:

- The 17,307-LOC core headline overstates the logic surface. The two largest
  files are roughly half tests — `project_fact.rs` (5,125) and
  `handle_intent.rs` (1,760) — so the genuine logic surface is closer to
  11,000–12,000 LOC, and almost every remaining structure is essential.
- The leverage is in the protocol, not core. The 44 fact-family `project.rs`
  files total ~27,500 LOC (about half of the protocol tree) and are copied from
  one skeleton. Replacing that skeleton with generated code is by far the largest
  whole-repo reduction, but it *grows* core, because the shared logic moves into
  core, the protocol-neutral substrate.

So the realistic outcome is asymmetric: the **repo** can lose ~9,000–14,000 LOC,
but **core** cannot get dramatically smaller without getting slightly larger. The
safe reduction inside core itself is ~900–1,200 net non-test LOC (~5–7%), from a
janitorial pass plus two targeted structural merges — not a redesign.

## What Is Essential (Do Not Rewrite)

These structures look like simplification candidates but each one earns its keep.
A "simpler" rewrite here regresses a capability.

- **Commit-statement ordering.** In `commit_runtime_effects_in_tx`
  (`project_fact.rs`) and the accepted-outcome substages, the statement order
  *is* the contract: purge → rebuild-wipe → facts → rows → intents, and
  needs-replace → offer-append → context-wake. Two-phase validation (stateless
  before SQL, content-id/idempotency against the live transaction) is not
  expressible as an ORM relation. This is the load-bearing wall of the file.
- **Durable/local intent split.** `local_intents`/`local_intent_context` are
  `CREATE TEMP TABLE` (`schema.rs`), so restart drops them with zero wipe code.
  Merging the two queues behind a `durable` flag replaces a SQLite-guaranteed
  invariant with a hand-written startup purge that must provably run before any
  drain. The `IntentQueue{Durable,Local}` enum already makes the two-ness cost
  only ~20 LOC.
- **Outgoing network queue on SQLite.** `queue_outgoing_in_tx` runs inside the
  handler `write_transaction` (`connection/queue_outgoing_frame`,
  `connection/send_facts_on_connection`, `connection/maintain_connections`), so
  "frame enqueued iff producing fact committed" is a free property of the shared
  transaction. A `VecDeque` re-creates it as post-commit flush plus rollback-drop
  machinery the codebase deliberately lacks.
- **`incoming_facts` on SQLite.** Drained inside the projection transaction
  (atomic stage → admit). Same atomicity loss as outgoing if relocated.
- **`wire.rs` fixed-layout codec.** The bytes are cryptographic canonicalization
  inputs: signing zeroes specific fields and the fact id is BLAKE3 of the
  canonical bytes. A `serde`/`bincode` layout is an implementation detail, unusable
  as a signing spec, and would *add* code to re-implement padding, NUL, and UTF-8
  validation. It is imported by ~109 files.
- **The needs/offers parking model.** Order-independent, value-carrying,
  role-based dependency resolution with no background scans and no
  projector-to-projector calls — exactly what out-of-order peer receipt requires.
  The fat is the exact/range table duplication, not the model.
- **Persisting derived state to amortize replay.** Only `facts` and
  `local_fact_admissions` are replay-protected; everything else is rebuildable
  (`schema.rs`). Normal startup does zero projection. Any in-memory-and-replay
  model reintroduces exactly the cost this design already avoids, on the hot
  startup and crash-recovery paths.
- **`RuntimeTurnLock`.** ~30 LOC of `flock` that makes a whole turn the unit of
  mutual exclusion across the daemon and CLI processes. SQLite's per-transaction
  serialization cannot replace cross-process turn exclusion.

## Directions Evaluated

Seven directions were considered. Verdicts use net core LOC unless noted.

### 1. Lean into a Rust ORM or framework — not worth it

Only ~80–110 LOC in `db.rs` is genuinely ORM-shaped (the typed-row INSERT/DELETE
string glue and quoting helpers). Against that: the effect IR
(`Value`/`TableInsert`/`RowMutation`/`TypedTableSchema`) crosses the core→protocol
boundary in ~55 files and must survive any backend; `sqlx`'s compile-checked
queries cannot validate SQL built dynamically from a `TableName` enum plus a
runtime column list; and an async ORM forces a `tokio` runtime into a
single-writer, single-connection, single-threaded process that has no concurrency
to manage. The bulk of the complexity (`project_fact.rs`, `context_db.rs`,
`network.rs`) sees zero reduction. **Salvage:** the dependency-free `db.rs`
thinning the idea points at — collapse the multi-source storage-version conflict
machinery, flatten the schema/replay catalogs, unify the two identifier-quoting
validators (~−120 to −160), keeping `storage_version_is` (a live caller exists in
`versioning/check_version`).

### 2. Simplify the projection/intent contract — partial, biggest total lever

See "The Largest Lever" below. The contract is uniform enough to generate, but
the win is overwhelmingly protocol-side and grows core. Two sub-moves are
rejected: making scope a property of `Role` is unsound (scope is a per-call-site
runtime parameter for at least `connection/close`, `auth/signature`,
`connection/frame_file_slice`, `connection/connection`, `auth/key_wrap`,
`auth/local_history_node_secret`), and merging durable/local intents is harmful
(see Essential, above).

### 3. Collapse queues to the essential set — partial, ~−100 to −140

Most "queues" are essential or are denormalizations, not collapsible truth. The
sound wins: replace the `network_outgoing_targets` index table with
`SELECT DISTINCT target_addr FROM network_outgoing` (~−45, the `target_addr`
column already exists), and fold `pending_projection_matches` into a
recompute-at-drain from the standing context needs/offers it was derived from
(~−40 to −55), reusing the existing overlap helpers. Two folds are unsound or
harmful: `pending_time_ranges` records a fire-time snapshot of the timeline
high-water that the owner's next projection destroys, so it cannot be recomputed
from current state; and merging `intents` with `local_intents` forfeits the free
TEMP crash-purge. The matches fold trades a cached read for a per-drain overlap
recompute, so measure replay-to-fixpoint cost on a mobile-sized corpus before
taking it.

### 4. Move volatile queues to in-memory structures — not worth it

The premise is already satisfied: the TEMP tables run under
`PRAGMA temp_store = MEMORY` (`db.rs`), so they never touch disk — there is no
memory or startup win available. And four of the five
(`network_outgoing`, `incoming_facts`, `local_intents`, plus the targets index)
co-commit atomically inside the projection/handler `write_transaction`; moving
them to Rust memory re-implements that free atomicity as new post-commit
plumbing and splits two uniform dispatch paths into SQL-plus-Rust. **Salvage:**
only `network_incoming` is a clean carve-out — the inbound drain is already three
separate transactions (claim → submit → delete) with no transaction spanning
accept and admission, and admission is idempotent, so a runtime-owned
`VecDeque` plus a dedup `HashSet` removes ~−85 to −95 of marshalling code. Frame
it as a marshalling cleanup, not a memory win.

### 5. Full in-memory with a fact mirror and replay-on-startup — harmful

Net positive code: ~+450 to +1,450 core LOC. Deleting the durable derived tables
removes ~−1,600 of SQL, but recovering what SQLite gave for free adds more: an
in-memory range-overlap matching engine (~+800 to +1,200), a persisted fact
dependency graph and loader (~+400 to +600), a demand-driven lazy scheduler with
eager invalidation when peer offers arrive (~+600 to +1,000), and a memory
eviction policy (~+300). Full replay is also too slow on mobile for a real
multi-month corpus (tens to hundreds of thousands of facts, each costing a BLAKE3
verify plus an Ed25519 verify plus a decrypt plus a context match, more than once
because parking re-projects). The kernel the idea reaches for already exists:
`facts` and `local_fact_admissions` are the only protected store, all derived
state is already declared rebuildable, and the needs/offers tables
(`context_needs`, `context_*_offers`, plus `pending_projection_matches`) *are*
the resolved dependency graph — with replay-to-fixpoint handling ordering
without a precomputed graph. Peer sync also defeats laziness: an arriving fact's
offer side can satisfy parked needs of not-yet-materialized facts, so offers
must be processed eagerly regardless of materialization.

### 6. Vanilla cruft and dead-code removal — the most actionable

Survives review. ~−500 to −650 net non-test core, zero added logic. The largest
items: excise the env-gated `projection_timings` diagnostics
(`record_projection_timing_in_tx` and the timing fields threaded through
`PreparedProjection`, the table DDL, and its tests; default-off, nothing reads it
for correctness); the network-local cruft (drop `network_outgoing_targets`, the
address-prefix-in-key decode chain, and the cryptographically-impossible
`*_row_matches` collision verifiers); collapse the `project_fact` insert-wrapper
ladder and the SELECT/DELETE owner-cleanup duplication; delete the zero-caller
`RuntimeEffects::purge_fact` builder (`effects.rs:129`) and the dead
`matched_values_for` accessor. The `run_turn` "stage-table" idea is *not* a win —
the 11 stages have heterogeneous closure captures and load-bearing duplication
(durable projection runs pre and post; local intents drain twice), so a static
table forces adapter wrappers and obscures the ordering. The order-sensitive
helper folds (`_if_retained`, idempotent-insert) are lower priority because they
concentrate the commit-ordering invariant; take them only behind the existing
`contract_tests`.

### 7. Novel: unify the context offer relation — partial, ~−120 to −180, one real core win

The current context substrate has one exact-need table plus two offer tables:
`context_needs`, `context_exact_offers`, and `context_range_offers`. That matches
the public model — needs are exact keys, while offers may be exact or range
claims — but the two offer tables duplicate exact-vs-range SQL and loaders. The
stored overlap rule already treats an exact offer as the equal-endpoint case of
a range offer:

```text
need.role == offer.role
need.scope == offer.scope
offer.start_key <= need.key <= offer.end_key
```

So collapse to **one always-`(start,end)` offers table** while keeping
`context_needs` exact. Always match by the coverage query, and delete the
exact-offer/range-offer table split plus the duplicated selector/load paths in
`context_db.rs`. This needs zero protocol change and loses no capability.

The important correction: do **not** delete range matching to coarsen everything
to exact. `auth/local_history_node_secret::secret_offer` is a genuine
two-dimensional range *offer* (a minute window crossed with a leaf-prefix bound)
where the breadth lives on the offer side; deleting range there forces
combinatorial offer fan-out. Unify *up* to always-range; do not delete down.

Two further novel ideas are independently worthwhile but lower priority and not
folded into the headline: turn-as-data for the `run_turn` pipeline in
`runtime.rs` (kept distinct from the rejected stage-table because it also folds
time-wakes into a projection source), and merging `local_fact_admissions` into
`facts` (real LOC, but it blurs the content-pure facts table with local
non-deterministic metadata and touches the replay-protected and summary sets — a
clarity cost the LOC win may not justify).

## The Largest Lever: Fact-Family Codegen

All 44 fact families repeat one projector skeleton: fixed-layout decode plus its
roundtrip/tag/length tests, fact-id authentication and the reject quartet, the
identity `adapt` seam (44 of them, every one `Ok(source)`), the need/offer
constructor pairs, the scope check, the park-until-matched ladder, and
schema-derived row builders. The only irreducible per-family code is the
`materialize(self, matched) -> Output` policy.

A `fact_family!` macro that expands to projector-local code in each family can
remove ~−8,000 to −12,000 protocol LOC by replacing 44 hand-copied copies of
those invariants with one audited expansion. The cost is real and concentrated:

- It *grows* core by ~+700 to +850 LOC, because the generated logic lives in the
  protocol-neutral substrate.
- It must **wrap** `wire.rs`, not replace it: the generated decoder has to
  reproduce the exact fixed-width, big-endian, zero-padded canonical layout, or
  fact ids change and sync convergence breaks. Byte-for-byte fact-id test vectors
  are the acceptance gate.
- It must be a typed macro, not a config/data file, to preserve compiler-checked
  routing.
- Blast radius concentrates: a bug in the generated park-ladder or scope check
  affects all families at once. This is mitigated because the contract is already
  uniform, but it argues for converting leaf families first
  (`connection/frame_observation`, `auth/user`, `connection/ephemeral_secret`)
  against their existing test vectors before the heavy ones
  (`content/message`, `connection/request`, `connection/connection`).

This is the single highest-leverage change in the repo and it *strengthens* the
invariants by making them provable once. It is also the clearest evidence that
"simpler core" and "simpler repo" point in opposite directions.

## Recommended Path

Each phase is independently shippable and test-green. Land as small revertible
changes; rely on `contract_tests`, the context/wake tests, the replay-idempotence
and state-summary checks, and the architecture-boundary tests as the safety net.

**Phase 0 — cruft floor (low risk).** Direction 6 plus deleting the 44 identity
`adapt` seams (mechanical; reintroduce per-fact when a versioned fact actually
lands). Approximately −480 to −680 core and −500 to −700 protocol. Pure deletion
and one-for-one dedup, no logic added.

**Phase 1 — structural core merges (low to medium risk).** The context-offer
relation unification (direction 7), the dependency-free `db.rs` thinning (direction 1
salvage), the `network_incoming` carve-out (direction 4 salvage), and — after
measuring replay cost — the `pending_projection_matches` fold (direction 3).
Cumulative core ≈ −900 to −1,200 (~5–7%). This is the realistic safe ceiling for
core itself. Defer the admission-fact merge unless the purity cost is judged
acceptable.

**Phase 2 — the protocol lever (medium risk, separate program).** The
`fact_family!` macro. Protocol −8,000 to −12,000; core +700 to +850. Convert leaf
families first against fact-id test vectors, then the heavy families.

Whole-program outcome: roughly −9,000 to −13,500 LOC across the tree, with core
netting flat-to-slightly-down once the macro's growth offsets Phases 0–1. If the
goal is strictly fewer core lines, stop after Phase 1 (~−1,000). If the goal is
less total code and fewer hand-copied invariants, Phase 2 is where the win is.

## Net LOC Summary

| Move | Verdict | Core Δ | Protocol Δ |
| --- | --- | --- | --- |
| Cruft pass (dir 6) | do | −500 to −650 | 0 |
| Delete 44 identity `adapt` seams | do | 0 | −500 to −700 |
| Unify context offer relation (dir 7) | do | −120 to −180 | 0 |
| `db.rs` thinning, no ORM (dir 1 salvage) | do | −120 to −160 | 0 |
| `network_incoming` → `VecDeque` (dir 4 salvage) | do | −85 to −95 | 0 |
| Fold `pending_projection_matches` (dir 3) | measure first | −40 to −55 | 0 |
| Drop `network_outgoing_targets` index (dir 3/6) | do | −45 | 0 |
| `fact_family!` codegen (dir 2) | separate program | +700 to +850 | −8,000 to −12,000 |
| ORM/framework (dir 1) | reject | ~0 | 0 |
| All volatile queues → memory (dir 4) | reject | ~0 or worse | +churn |
| In-memory + replay-on-startup (dir 5) | reject | +450 to +1,450 | 0 |
| Merge `intents` ∪ `local_intents` | reject | ~0, worse logic | 0 |

# In-Memory Projection with Bounded Replay

This note explores a variant of poc-10 where projection and read-model state live
in memory with a ceiling on memory usage. It records the reasoning that took the
idea from its first framing ("persist only facts, replay a bounded window on
startup") to the design that survives analysis: **persist facts and a syntactic
needs/offers index; project the active range in memory; resolve cross-time
matches by lookup.** No code changes follow from this note.

## 1. The idea, and where it landed

**The original proposal.** Keep projection and all derived state in memory.
Persist only the fact log plus a small sidecar. On startup, rebuild derived state
by replaying facts; cap memory by replaying only a bounded slice and rebuilding
negentropy the same way.

**The hoped-for benefits.** (1) Faster — all in memory. (2) Simpler — no SQLite
schema plumbing. (3) Easier Verus proofs — projectors don't round-trip SQLite.
(4) Easier versioning — always replay, storage stays the same. (5) More
atomicity flexibility. (6) Less duplicated, less plaintext data.

**Where it landed.** The load-bearing discovery (§3) is that the needs/offers
**match relation cannot be windowed or rebuilt from a windowed replay** — its
matches reach across the whole history, not just a recent tail. So it must be either
fully replayed every boot (unbounded) or **persisted**. The chosen design (§4)
persists it as a **syntactic** index (`f(fact content)`, validity-free), and
computes validity and read-model state **in memory** over the active range, the
poc-10 way. Cross-time matching becomes a lookup that pulls in the few old stored
facts it touches. The whole pipeline is **projector-owned** (§5): routing,
edge extraction, persistence, and effects are all projector logic, proven with
the same machinery, with the framework reduced to a matching/storage substrate.

The cost is a persisted derived structure (the index) — less clean than a
facts-only store, but correct, mostly in-memory, and cheap to cold-start.

## 2. Current poc-10 starting point

poc-10 persists two things in SQLite:

- The **fact log** — `facts` (content-addressed `id -> bytes`) and
  `local_fact_admissions`. Plaintext, immutable. See `src/core/facts.rs`,
  `src/core/schema.rs`.
- **Derived state** — `context_needs`, `context_exact_offers`,
  `context_range_offers`, `time_wakes`, plus protocol rows. Fully derived,
  persisted for lookup, rebuilt on a rebuild effect. See
  `src/core/project_fact.rs`.

Projectors are pure over `(fact, matched context)` and commit declarative output
in one transaction. Matching is **key-rendezvous**: a need `(owner, role,
scope_key, key)` meets an offer with the same address — facts do not name each
other by hash to match. Facts can **stall** in `pending_projection` until their
needs are met. Today an offer implies *validated* evidence (the producing fact
passed signature/authority/needs checks).

Sync state is also persisted: negentropy leaf/node rows and per-leaf
`context_have` closures (`src/protocol/sync/shared_fact/index.rs`). Dep-aware
sync ships each shared fact with the `context_have` closure needed to project it
(`src/protocol/sync/share_fact_with_sync.rs`); range comparison splits by
timestamp until ≤ `MAX_HAVE_IDS_PER_RANGE` (64) facts.

## 3. Why the match index cannot be windowed

This result forces the rest of the design.

The proposal is event sourcing with an in-memory read model and **no snapshots**.
The decisive question: *can we produce a correct projection from a bounded slice
of the log without a checkpoint of the state at the cut?* A checkpoint is the
durable derived state the proposal wants to delete, so it is off the table.

Bounded replay computes **wrong** state, not partial state. "Replay the most
recent N" is sound only for last-writer-wins tails. For membership, revocations,
tombstones, counters it is unsound — an old `remove-member` outside the window
vanishes and the member reappears.

Conceive of it operationally, not as a batch computation that converges. Projection
is a **queue that gets played**: seed it from the range, feed it incoming facts and
any facts a match pulls in, and draining one item can enqueue more (a wake). It is
ongoing — new input always arrives, so it need not ever terminate; there is no
"final" state, only the state at each moment of quiescence. The property that must
hold is **confluence**: the queue can be drained in any order — live arrival order,
or replay order — and reach the same quiescent state. Suppression (negation) is
what threatens confluence, since "project X unless removed" lets order matter; it
is safe exactly when no two facts can suppress each other in a cycle (the
operational form of *stratified negation*), which is also the precondition that
makes **replay reach the same state as the live run**. §5 realizes this queue in
memory as recursion — the call stack is the queue.

- **Fact 1 — the working set is not time-bounded.** A fact pulled into the queue
  can, through its matches, pull in facts arbitrarily far back, and a wake can
  cascade across the whole history. So restricting the queue — or the index it
  matches against — to a time window drops items the in-window work genuinely
  needs: the state cannot be rebuilt from a windowed replay, only by playing
  everything or by persisting the relation.
- **Fact 2 — two-directional maintenance.** A new fact `δ` updates the match relation via
  `need-key → offers` (resolve δ's needs) **and** `offer-key → needs` (find
  existing facts δ's offers now satisfy, re-derive them). This is semi-naive
  Datalog / incremental view maintenance. Drop the backward direction and the
  only correct fallback is re-projecting all facts per delta. Both directions
  need random-access lookups; you cannot stream the relation.

**Cascade** (why "keep recent, recompute the rest" fails): `g` out of window
withheld offer `o_g` because its need `n_g` was unmet; resident `h` needs `o_g`'s
value by key. Offer `o'` arrives satisfying `n_g`. Correct: `o' → wake g → o_g →
wake h`. If `n_g` is not findable, `g` never wakes, `o_g` never appears, and `h`
is permanently wrong with no read-path able to notice. So the relation must be
**complete and randomly queryable** before the first admit: persist it.

## 4. The chosen model: persist the index, project the range in memory

Persisting the match index turns the backward join into a **lookup**, so the
irreducibility of §3 stops being a problem.

- **Durable (required):** the fact log, and the needs/offers index — a **key-value
  lookup** keyed by match address, reverse-keyed (by target/predicate) for
  late-binding entries so a deletion/rekey can reach a target authored before it.
  Resolved on every admit and load: out-of-order delivery means a deletion keyed
  to `F` can arrive before `F`, so admission queries the index by the arriving
  item's own address, and loads query it too.
- **In memory:** read-model / validated state for the **active range** (what the
  UI shows plus what is arriving), rebuilt on demand; projector proofs stay over
  in-memory `(fact, context)`.
- **Demand-driven matching, in both directions.** The active range is a *seed*;
  items outside it are pulled in by the index's two-directional join (§3, Fact 2).
  A **need → offer** lookup pulls the old items an in-range item *depends on* (its
  offerers). An **offer → need** lookup pulls the old items a newly-arrived item
  *satisfies* (its dependents) and re-projects them — the §3 cascade. So **needs
  pull old offerers; offers pull old needers.** A pulled item brings its *edge*
  always (it's in the index); its *body* loads only if the projector consumes the
  body (§6). Both directions cross the range boundary, so out-of-order arrival is
  handled symmetrically — whichever side lands second does the lookup that finds
  the side that landed first.

This is the **two axes**: bodies and read-model **window** (lazy,
display-budgeted) — that is what bounds memory; the index **does not** (persisted,
queried) — that is what keeps matching correct.

Cost vs a facts-only store: a persisted derived structure (weakens benefits 2 and
6 — the index is dependency/social-graph metadata at rest); versioning becomes
index migration (benefit 4); an index entry must land with its fact (benefit 5).
Kept: in-memory speed (1), in-memory projector proofs (3), and a **cheap cold
start** — load/query the index, project only the active range, no full replay.

### A relocatable seam: local store or web frontend

The split — durable side (facts + index + lookup) vs in-memory read model — is a
**relocatable seam**. In one process it's a local app with the index in SQLite;
across a network it's a web backend holding facts + index and a browser holding
the read model. Across a network it *is* lazy-loading:

- the frontend working set **is** the bounded read model — no separate client
  cache to invalidate;
- the **fetch protocol is the sync protocol** (§7) — "give me this range plus its
  closure" is what dep-aware sync already does, so a frontend is just a peer
  syncing a bounded range; closures batch dependencies (per-range, not per-fact);
- **cache invalidation falls out of matching** — a new offer/suppression is a
  match: pushed to resident targets, looked up on next load otherwise;
- the frontend is **disposable** — a reload re-pulls; nothing client-side needs to
  persist.

The full index is `O(fact-count)`, too large for the browser, so it stays
backend-side and answers lookups; the frontend holds only the read model, and
validates the closure of anything it displays (§5).

## 5. The projector model: items, two passes, a routing tree

Everything in the pipeline is an **item**; a **fact** is a durable,
content-addressed item. A connection frame is an item too — ciphertext addressed
to you, not a fact — so don't force it to be one. The pipeline operates on items
that carry edges and project; "fact" is the item that gets a content-id and
flushes.

### Two halves, two readings of "offer"

poc-10's offer means *validated evidence* — it exists only once its fact is
validated (signature, authority, needs met by other valid offers), so it is
`f(fact, context)`. That stays, **in memory**. The new, persisted thing is a
**syntactic edge**: `f(fact content)` alone — "this item, if valid, offers X" —
with no validity. The system cleaves into two layers, and each projector into two
halves:

```rust
fn extract(item: &Item) -> Vec<Edge>                         // syntactic, context-free
fn project(item: &Item, ctx: Context<Validated>) -> (State, Effects)  // semantic
```

- **`extract` is context-free by signature.** It produces the syntactic edges
  (the `Asserted` needs/offers) from content alone — no matching, no signatures,
  no context. A projector that *can't* extract without context won't compile;
  that's the gating assumption ("needs/offers are a pure function of content")
  enforced structurally rather than audited. The same emission feeds both layers,
  so equivalence between syntactic and validated needs/offers is definitional.
- **The closure rule: addresses must be self-contained.** Because `extract` sees
  only the item's own bytes, *every context address a fact will ever need must be
  carried in — or derivable from — that fact's own fields.* A forward need (a
  message addressing its channel and author) already satisfies this. The trap is
  **suppression/deletion needs**: a fact must carry the address of whatever can
  remove it, because `extract` cannot discover that from context. Two current
  poc-10 facts break this — **reaction** and **slice** — whose deletion needs
  resolve through projection-time context not present in their fields; the fix is to
  copy those suppressing addresses into the fact (an easy field addition), after
  which `extract` is self-contained. Those copied addresses are asserted routing
  hints, not authority: `project` must compare them with validated parent/context
  facts before materializing state or effects. A forged child can dirty the
  syntactic index with useless edges, but it cannot create validated state.
- **`project` produces validated state.** Validity is its own non-monotone
  relation — revocation can retract it — computed in memory, cached, never
  persisted. Validating an item pulls its authority closure (bounded, recursive),
  verifies any denormalized dependency addresses against that closure, and only
  then emits state, durable offers, or effects.

**Typestate makes validate-before-use structural.** One type, parameterized by
validity:

```rust
struct Offer<V> { /* role, scope, key, value */ }
fn validate(o: Offer<Asserted>, /* proof */) -> Option<Offer<Validated>>;
fn use_in_state(o: Offer<Validated>);   // Asserted won't compile here
```

The index is the `Asserted` (dirty) layer — it holds edges from facts that may be
forged or invalid; correctness depends on `validate` gating every use, and the
type enforces it. "Out of display window" ≠ "out of validation scope": a new
offer can force validating an out-of-display fact because it changes a resident
fact's state — finding it is a cheap syntactic lookup, validating it is the
recursive cost.

### Properties live on edges, not in registration

The framework needs no static classification of fact types, because the whole
index is persisted (so there is nothing to pre-classify for selective replay).
Instead the projector **emits each edge with whatever properties matter** —
suppressing vs additive, forward (closure-carried) vs late-binding (reverse-keyed),
1-to-1 vs predicate — content-pure, in `extract`. This is more granular and more
provable than registration flags: you prove the projector emits the marker
correctly, rather than trusting a declaration matches behavior. Because we keep
the whole index, there is no GC of matched offers and no cardinality tiering to
reason about.

The same mechanism decides **what stays resident**. A projector can mark a fact
**mandatory** — always projected into validated state, *first*, for any range, in
or out of the display window. **Channels** are mandatory (the structural substrate
the range sits in — the sidebar, rendered whole). **Removals** are the suppression
substrate: every projected fact is checked against them (the security-critical
completeness — never show a removed message), so the suppression index must be
**complete and consulted on every admit**. This is the projector-owned form of the
old "must-keep / replay-always class": a projector-emitted marker queried from the
index, not a registry flag.

Mandatory means **always in memory** — every range, every cold start, never
windowed away — so it is the one part of the read-model with no ceiling from the
display window, and the explicit goal is to **keep the mandatory set as small as
possible.** Channels are naturally small. Removals are the growth risk (the
tombstone layer accumulates with deletion history), bounded two ways: only the
suppression *index tuples* need stay resident and consulted — a tombstone's state
is *applied* only when its target is itself resident, not eagerly projected for all
of history — and the retention **horizon** (§7) caps how far back tombstones stay
hot, since tombstones travel with bodies and are GC'd once their target falls below
it. The resident suppression set is therefore bounded by the horizon, not all-time
history.

### Persistence is a projector decision

`durable` vs `volatile` is a content-pure choice the projector makes per item:
durable items flush (fact bytes + edges) to disk; volatile items keep their edges
in the in-memory index only. The discipline: **persistence is content-pure, never
validity-gated** — the index must hold unvalidated facts' edges or cross-time
matching breaks, so a projector may not say "persist only if valid." What a
projector *can* do is gate whether an item **exists**: emission, not persistence,
is where semantics enters.

This unifies poc-10's volatile vs persistent queues into one mechanism. A
connection frame: `extract` emits the edge *need = transit key K*, volatile (no
flush); `project` matches K — decryption **is** the frame's validation — and
emits the inner facts as effects; those facts hit their own `extract` and flush.
The frame never touches disk (a privacy win: only decrypted, admitted facts
persist, never ciphertext). Restart semantics fall out: unflushed edges vanish
(the peer resends), flushed ones survive. The transit-key handshake is just
ordinary need/offer matching, including its out-of-order duals. The same flush
decision covers operational obligations (§9): must-survive intents flush,
transient socket observations don't.

### Routing is a projector tree

Routing is projector logic, not framework dispatch. A **root** projector routes
by family/scope (auth, connection, sync, content); each **family** projector
routes by type to **leaf** projectors. Every node is a projector (extract +
project), so routing coverage and disjointness are proven with the same
machinery, and the context-free `extract` composes (a tree of context-free
dispatchers is context-free). Registration shrinks to naming the root.

Family projectors are the natural place to **enforce scope-wide output rules**:
the connection family marks **unopened inbound frames** volatile so ciphertext
never reaches disk, while the request/connection facts they open into stay
**retained evidence** (what replay drops is their *live* effects — send state,
session rows — not the facts themselves); the auth family can require every edge
carry a signer; a family can set a default persistence class or edge invariant —
enforced and proven once at the boundary rather than per leaf.

### The two-pass pipeline

- **Pass 1 — admit / extract / persist.** Run `extract`, add edges to the
  in-memory index, and flush durable items' edges + bytes to disk. Runs for
  **every** item (the index must be complete, §3). Content-pure, cheap, durable —
  this is admission. A crash here is atomic per item.
- **Pass 2 — validate / project.** Run `project` with validated context to build
  read-model state and effects. Runs over the **mandatory substrate first**
  (channels, and the removal suppression index — always resident, regardless of
  range), then the **active range + the resident facts a new item affects +
  in-flight downloads**. In-memory,
  rebuildable — a crash just re-validates from the index.

So Pass 1 is total, Pass 2 is scoped — that asymmetry is the memory story.
`project` never re-persists edges; Pass 1 already did. The passes map onto
poc-10's existing admission/projection split (extraction moves into admission),
and onto the **two replay modes**: a projection/validity-logic change re-runs
Pass 2 only (index intact); a *syntactic-extraction* change re-runs Pass 1 (a
parallel `O(facts)` map, no matching cascade) then Pass 2. All churn happens in memory.

### Evaluation: recursion is the queue

The §3 "queue that gets played" has a concrete in-memory form: Pass 2 drains it by
**demand-driven recursion**, where the call stack *is* the queue. Because validated
state is in memory (§4), `project` can suspend mid-item, recurse into the context it
depends on, and resume — something poc-10's transactional queue cannot do. To
project an item, ensure everything it depends on is projected first; memoize so each
item projects once:

```text
memo     = {}                              # item -> result, this pass
on_stack = {}                              # cycle detection

play(f):                                   # "play" one §3 queue item
    if f in memo:     return memo[f]               # already done
    if f in on_stack: raise SuppressionCycle(f)    # stratification violation, located
    on_stack.add(f)
    for addr in extract(f):                # context-free needs (the closure rule)
        for g in resolve(addr):            # providers via the index, pulling old facts (§4)
            play(g)                        # context first
    out = project(f, collect(extract(f), memo))  # the pure §5 projector, context now ready
    for e in out.emitted:                  # emitted facts (incl. transient "intents")...
        play(e)                            # ...are played too
    apply(out.state)
    on_stack.discard(f); memo[f] = out; return out

for f in range ∪ incoming: play(f)         # outer order irrelevant — confluence
```

Three things fall out, mechanizing what §3 had to assert:

- **Termination = the stratification condition.** Needs resolve by hash
  (content-addressed → backward in time) or by predicate through the index (the
  partner is pulled in if old); a finite fact history plus `memo` visits each item
  once and terminates — *unless* an item's projection transitively requires itself,
  which `on_stack` catches as a `SuppressionCycle` **at the exact offending item**.
  The §3 "no two facts suppress each other in a cycle" precondition stops being a
  proof obligation and becomes a located runtime error.
- **Confluence falls out of evaluation order.** The outer loop's order does not
  matter: recursion forces every item's context before the item, so any order — live
  arrival or replay — reaches the same quiescent state (§3, §9), realized rather than
  assumed.
- **Intents are emitted, not persisted.** Rich in-memory projector state means an
  operational "intent" ("add to sync state") is just a fact `project` emits for
  another projector to consume — never flushed, because it is **recomputable from the
  persisted facts** and re-derives on the next pass. This is `project`'s share of the
  persistence rule (§5): emit transient, flush only must-survive. There is no durable *obligation* record to
  keep either: operational work (sends, connection, sync) is **desired state** a
  projector derives and a recurring **worker** reconciles each turn (see *Workers*
  below) — recurrence, not a retry record, not a persisted queued intent.

**Suppression rides the same index — no reverse-reachability.** A tombstone does not
trigger a walk down a dependency graph. By the closure rule a suppressible fact
**posts its own need keyed on the tombstoneable parent id** it carries; a tombstone
is an offer on that key; suppression is then ordinary `offer → need` matching (§3
Fact 2 — the reverse-keyed direction of the *same* need/offer index, not a second
structure). Transitivity composes one hop per level:

- **In replay it is automatic.** `play(child)` reads the parent's *result* from
  `memo` — the recursion forced the parent first — so a suppressed/absent parent makes
  the child suppress with no propagation step; it falls out of evaluation order.
- **Live, it is a re-demand wavefront over the index.** A tombstone for `X` arriving
  means: look up the needs keyed on `X` (the `offer → need` direction) and re-play
  them; those whose projected presence changed are themselves parents others posted
  needs on, so look up *their* keys — next hop. One forward lookup per level (a
  grandchild watches its immediate parent's id, not `X`, so it is reached on the
  second wave). The transitive-downstream set is reached by composing forward lookups,
  never a reverse traversal.

What recursion does **not** absorb is small and exogenous: it reaches *backward*
through needs, so it cannot reach forward to **a frame that will arrive** or
**`now ≥ T`**. Network ingress and the clock stay outside *seed* sources — a new
frame is a fresh root to `play`, the clock re-demands due time-edges — not work
queues. And a need-chain as deep as the history makes recursion depth = chain length,
so a pathological depth swaps the call stack for an explicit LIFO stack (a queue by
another name) purely to avoid native-stack overflow.

### The type model

Confinement is the parameter list — a projector acts only on what it is handed, so its
signature is its sandbox. One projector is one private state plus two halves (refining
the `(State, Effects)` sketch above: state becomes a `&mut` parameter, and the effect
channel collapses to emitted facts, since I/O moves to workers).

```rust
trait Projector {
    type Item;
    type State: Default;                    // PRIVATE — only this projector writes it

    // Pass 1: no &self, no state, no ctx in scope — cannot read anything but the
    // item's own bytes. Purity is the absence of parameters, not an audit.
    fn extract(item: &Self::Item) -> Vec<Edge>;

    // Pass 2: &mut to its OWN state; reads others only through validated offers.
    // Output is facts + own-state writes — no I/O, no clock, no foreign state.
    fn project(item: &Admitted<Self::Item>, ctx: Context<Validated>, st: &mut Self::State)
        -> Vec<EmittedFact>;
}
```

- **Private state, offers-only bus.** "Only its owner writes" is `&mut Self::State`;
  dispatch is generated code that hands the channel projector `&mut all.channels` and
  never `&mut all.auth`, so no projector can *name* another's state (static, no `Any`).
  The consequence: projectors never read each other's state — only the **offers a
  projector publishes**. The validated-offer index is the entire inter-projector channel.
- **`Asserted` vs `Validated` (your "adds to valid needs/offers", made precise).**
  `extract`'s edges land **`Asserted`** — that is what persist writes to the index
  (§4). They promote to **`Validated`** only when `project` validates the item in Pass
  2, becoming context for others. `Context<Validated>` exposes only the clean layer;
  state-building won't accept `Asserted` (typestate).
- **`Admitted` makes extract-before-project a compile error.** Its only constructor
  persists:

```rust
struct Admitted<I>(I);                       // private field — unforgeable outside the engine
fn admit<I>(item: I) -> Admitted<I> {        // the ONLY constructor
    let edges = extract(&item);              //   Pass 1: extract...
    index.insert_asserted(edges);            //   ...persist edges (Asserted)...
    flush_if_durable(&item, &edges);         //   ...flush bytes if durable.
    Admitted(item)
}
```

  `project`/`play` require `Admitted<Item>`, `resolve` returns it, emitted facts go
  `play(admit(e))` — so Pass 2 is unreachable without Pass 1. This is the order:
  extract→persist→project, where "Pass 1 total" means *no item escapes extract* (not
  re-extract all history — the index accumulates; cold start loads it), and admitting a
  whole batch before projecting is *efficiency*, not correctness: project an item before
  its later partner is admitted and the `offer → need` dual wakes it when the partner
  lands — confluence makes the final state order-independent.
- **Emission can't forge authority.** An emitted fact is not privileged — it re-enters
  `admit` → `validate` like any inbound fact, so emitting outside one's authority
  yields a fact that fails validation and never becomes a `Validated` offer. Unsigned
  local signals are gated by origin instead: `enum Origin { Network(FrameId),
  Local(LocalToken) }`, where a local-signal family's `validate` demands the
  runtime-minted `Origin::Local`, so a network frame can never inject one.

Every consequence of a projector is therefore a write to its own state or an emitted
fact — no I/O, no clock, no reach into foreign state or the raw `Asserted` index beyond
its own extract. That small surface is the safety target the Verus proofs aim at.

### Workers: the reconciliation layer

Projectors cannot touch the world. That capability lives in a small fixed set of
**recurring intents (workers)** — the reconciliation loops that run every turn, read
desired state, act, and admit what they observe as facts.

```text
for worker in manifest.recurring:        // connection, sync, transport, ingress, time
    worker.run(now_ms, host_io, index)   // read desired state, reconcile world, admit facts
```

- **Recurrence replaces retries.** Connection and sync are not one-shot obligations to
  retry on failure — they are loops that each turn re-derive the gap between desired and
  observed state and act to close it. A failed send is just seen again next turn: no
  retry queue, no backoff record, no receipt-as-suppression. Recurrence *is* the
  liveness mechanism (operational, not a proven property).
- **Workers add facts and do I/O — nothing else.** A worker reads derived state and the
  index (read-only) and performs host I/O, and commits results only by **admitting
  facts** that re-enter the projector pipeline. It cannot write read-model state, so
  every state change still flows through a projector validating a fact; the safety
  boundary is unbroken.
- **Durable state is facts only; worker live-state is what replay drops.** A worker
  holds volatile in-memory state — the live socket, session keys, a backoff timer — but
  no durable private state; anything that must survive restart is a fact. That volatile
  state is exactly the "live effects (send state, session rows) replay drops" from the
  connection-volatility rule above; replay drops it, the loop re-establishes it.
- **Workers are the exogenous-seed residue.** They are precisely what recursion cannot
  reach (the network, the clock) from *Evaluation* above — the seeds, not what is
  reachable from a seed. Everything else (local signals, derived obligations) is a
  projector.

So the system is two non-overlapping capabilities: **projectors** own state-writes and
fact emission (pure, confined, the safety target); **workers** own I/O and the clock
(volatile, operational, the liveness layer). The only durable thing either produces is
facts + the index.

## 6. Keeping it small and fast

The index is `O(fact-count × small tuple)`, horizon-bounded. Edges can be
**valueless** (pure connectivity, keyed by `(role, scope, key)` or range) —
matching is on the key, and values are read from fact bodies at `project` time,
so the index is leaner than poc-10's value-bearing offers.

Further cost reducers, all optional:

- **Load relationships, not state.** A body splits into small relationship fields
  (refs, keys, the edges) and a heavy terminal payload (message text, **file
  bytes**). Pass 1 needs only the relationship fields; payloads load on display,
  never on the index path. This argues for an encoding with a cheap-to-scan header
  and a separate payload.
- **Range offers resolve by iteration.** Revoke-before-T and validity intervals
  are few; projecting a window just plays through the handful that cover it. An
  interval index is a *perf* fallback if a deployment ever accumulates many, never
  a correctness need.
- **Defer signature re-verification** when loading an already-admitted local store
  (the facts passed validation once; on-disk integrity is the only fresh
  question). Anything displayed/served/acted-on still verifies its closure.
- **Checkpoints that are themselves facts** for unbounded aggregates ("channel C
  has N messages as of F_k"): replay from the latest checkpoint plus deltas. A
  version bump invalidates them (recompute — they are an optimization, never
  truth); superseded ones GC; out-of-order suppression of a pre-checkpoint target
  makes a monotone count wrong, so suppression-sensitive aggregates recompute.

### Worked example: file slices (heavy payloads)

A file is the sharpest test of "relationships light, payload heavy," and it falls
out of the §4 pull mechanism with no special-casing.

**Items and edges.** A file is identified by a root hash `R`. A small **file fact**
commits `R` and carries the sharing authority. Each **slice** is heavy bytes (on
disk) plus a light **outboard proof** verifying it against `R`. A **file-aggregate**
projection tracks progress and validity. The edges, all keyed by `R`: every slice
carries a *need* keyed by `R` ("I belong to file `R`") and an *offer* "slice `i`
of `R`" (carrying its leaf-hash + proof); the file fact carries an *offer* keyed
by `R`; the aggregate has a predicate *need* "slices of `R`".

**Both pull directions, concretely:**

- **need → offer** (the aggregate pulls its dependencies). Opening the file — or a
  message that references `R` — brings the aggregate into range. Its need
  "authority `R`" pulls the file fact (`O(1)` semantic validate); its predicate
  need "slices of `R`" does an index reverse-lookup pulling **every slice's edge**,
  including old ones far outside the display range. It verifies each proof against
  `R` and counts presence — all over the pulled *metadata* (leaf-hash + proof). No
  payload is touched.
- **offer → need** (a new item wakes old dependents — the wake-up). The file fact's
  offer is keyed by `R`, and *every slice needs `R`*, so when the file fact arrives
  its `offer → need` lookup wakes **all slices that reference `R`** — including the
  ones that beat it to disk — and they re-project (validate against `R`).
  Symmetrically, a new slice's offer wakes the resident aggregate. The out-of-order
  duals (slices-before-file-fact, file-fact-before-slices) are just the two joins
  keyed by `R`.

**Eager vs lazy.** If `R` is resident or an in-flight download, these wakes
re-project immediately (so completion is noticed). If `R` is idle, a late file
fact or slice just persists; the aggregate recomputes from the index on next open.
This is why the resident set is "display range ∪ in-flight downloads."

**Bytes stay on disk** until *assembly* — a separate, explicit body-load when the
user opens the file, then released. Validation and progress never load payloads,
because the projector consumes only the proof/hash metadata in the edges.

**Representation: outboard proofs vs a manifest — they converge.** Either each
slice carries its own proof and needs the root `R` directly (one-level wake: the
file fact wakes all slices at once), or the slices depend on a **manifest** fact
that holds the commitments (the manifest wakes them). A manifest is `O(N)`, which
collides with fixed-size facts, so for large files it becomes a **tree of
fixed-size manifest facts** — a merkle tree whose nodes are facts, where a slice's
"proof" is the chain of manifests up to `R`, and the wake cascades down the tree
level by level. That tree *is* the deduped form of the outboard proofs, so the two
designs are one merkle structure with a storage choice: proofs-on-slices
(one-level wake, redundant siblings) vs manifests-as-facts (multi-level wake, no
redundancy, fixed-size). Small files fit a single manifest fact; large files use a
few fixed sizes / a fixed-fan-out tree.

The merkle / content-addressed structure is load-bearing: it makes per-slice
validation a hash-walk against `R` rather than a re-hash of bytes, so the metadata
pull never secretly drags in payloads. A whole-file-only hash would force assembly
to validate — the signal to make it merkle.

## 7. Sync under bounded retention

Bounded retention and set-reconciliation sync look like they are in tension:
negentropy fingerprints cannot tell "never had it" from "evicted it," so a naive
peer would re-flood the facts you dropped. The resolution is to make the sync range
a **local, per-message** decision, not a negotiated session floor.

- **No negotiated floor — bound your own compare items.** To sync only a limited
  range, a peer bounds the **compare items it sends** to that range, and **rejects
  incoming compare items whose range is too large** when it is in limited mode. Each
  side drives reconciliation from **its own** requests; an oversized request from
  the other side is simply rejected, not serviced. The willingness-to-sync range
  lives in the compare items (and in what you reject), per message — no handshake,
  no advertised horizon. This also dissolves the never-had/evicted ambiguity: you
  never engage a compare item outside your range, so there is nothing to re-flood.
- **Boundary divergence is transient, not churn.** Below the range a peer syncs, its
  set and a longer-retaining peer's legitimately differ, but under a shared
  retention policy the ranges track wall-clock and converge, and propagating
  tombstones catch up, so the two re-converge on their own. Eventual consistency
  absorbs it; there is no "forever" mismatch to prevent.
- **The horizon is the GC boundary** — a late-binding edge (tombstone) is GC-able
  once its target is also outside the horizon, when the body is gone and the edge
  is moot.
- **Tombstones travel with bodies** — serving an evicted body to a peer must carry
  any suppressing edge over it; suppression is part of what negentropy reconciles.

## 8. Alternative considered: recompute the index instead of persisting it

The facts-only path (persist only facts, recompute the index by replay) keeps the
original elegance and free replay-versioning, but pays the §3 cost: a *full*
replay (windowed is unsound). Making it tolerable was a whole apparatus —
background periodic replay (only eventually consistent, unsafe for suppression);
always replaying a structurally-required minority immediately; progressive replay;
partial replay only on the windowable bulk; a three-pass relationship/verify/
materialize split. Persisting the index turns all of that into a lookup, so it was
not chosen. The pieces still useful (relationships-not-state, deferred local
signatures, checkpoint-facts) were kept in §6.

## 9. Other drawbacks, independent of the index

- **Non-idempotent effects.** Replay is safe only for idempotent effects, and there
  are no persisted *obligation* intents to replay: operational work (sends, connection,
  sync) is **desired state** projectors derive and recurring **workers** reconcile each
  turn (§5, *Workers*) — recurrence, not a retry record, so a re-run just re-observes the
  gap. A truly external one-shot still needs an idempotent endpoint or a confirming fact
  (exactly-once is impossible in any model), but that is the endpoint's concern, not a
  queued intent.
- **Features needing a large complete index.** Full-text search over all history is
  a second derived store, windowed (misses old) or persisted (like the match
  index). Check any design against `message-search-index-plan.md`.
- **Plaintext metadata.** The persisted index is dependency/social-graph metadata
  at rest; even with encrypted bodies it could leak the graph. **Not a threat-model
  violation for now:** the threat model assumes storage is secure, so at-rest index
  metadata matters only if that assumption is later relaxed (a compromised or
  honest-but-curious host) — which would then call for index encryption-at-rest or
  structural blinding.
- **Determinism.** Requires no suppression cycles (§3) so queue draining is
  **confluent** (order-independent); otherwise replay can reach a different state
  than the live run.

## 10. Assessment of the stated benefits

1. **Faster.** Largely holds — projection and read model in memory; index lookups
   replace heavier derived-table traffic.
2. **Simpler / no schema.** Partly. The derived read-model tables go; the match
   index stays a persisted structure. Net simpler than today's full set.
3. **Easier Verus proofs.** Holds, and improves: projectors are pure over in-memory
   `(fact, context)`; `extract`'s signature enforces syntactic purity; routing,
   edge properties, and persistence are projector proofs rather than trusted
   framework code; the typestate makes validate-before-use a compile error.
4. **Easier versioning.** Two replay modes (§5): projection-logic change → Pass 2
   only; extraction-schema change → re-extract (parallel map) then Pass 2. Free
   replay-versioning for the read model; the index is re-extracted, not re-derived
   for free.
5. **Atomicity.** Largely holds — append-only log, append-mostly index (an entry
   lands with its fact); validated state is in-memory and rebuildable.
6. **Less plaintext / duplication.** Partly. Read-model duplication goes; the index
   is added dependency metadata at rest (see §9). And volatile transport never
   persists, a privacy gain.

## 11. The shape, in one place

- **Durable (required):** fact log + syntactic needs/offers index (KV, reverse-keyed
  for late-binding, valueless).
- **In memory:** validated read-model state for the active range, plus a
  projector-marked **mandatory** substrate kept minimal (channels; the removal
  suppression index, horizon-bounded) always resident; cross-time matches resolved
  by lookup that pulls in old stored facts.
- **Everything is an item; facts are durable items.** Projectors own routing (a
  proven tree), edge extraction (context-free), persistence (content-pure), and
  effects. The framework owns matching/storage and naming the root.
- **Two layers:** syntactic edges persisted (`Asserted`); validity + state in memory
  (`Validated`), typestate-gated.
- **Two passes:** extract/persist (all items, admission) → validate/project (active
  range, in memory).
- **Windows by display budget:** bodies, read-model, terminal payloads (file bytes
  laziest).
- **Bounded by the horizon:** index size, tombstone lifetime, sync reconciliation.

## 12. Open questions

- Do poc-10's real projectors fit the **context-free `extract`** signature — i.e.
  are needs/offers genuinely a pure function of content? The signature enforces it,
  so any that don't will fail to compile. Mostly yes; the known gaps are
  **suppression/deletion needs** that resolve through projection-time context —
  **reaction** and **slice** today — fixed by carrying the suppressing address in
  the fact (the closure rule, §5). The remaining open part is whether any projector
  needs a referenced fact's *content* (a map-with-lookups rather than a pure map).
- How large is the index over a multi-year workspace? `O(fact-count)`,
  horizon-bounded — the real memory/disk ceiling. Measure before assuming bounded.
- How large is the closure-carried portion of `context_have` — how much body-axis
  memory closures pin when projecting a range.
- Is the matching system free of **suppression cycles** (no fact pair suppressing
  each other), so queue draining is confluent — replay reaches the same state as the
  live run regardless of order?
- On the negentropy range protocol (§7), does the compare-item shape already
  support **bounding sent ranges and rejecting oversized received ranges** (so
  limited-range sync needs no negotiated floor), and what should the oversized-range
  rejection threshold be?

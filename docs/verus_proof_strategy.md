# Verus Proof Strategy

This is the single Verus proof plan for poc-10. It replaces the former
separate TODO document so proof order, assumptions, and threat-model coverage do
not drift.

The eventual goal is a whole-codebase Verus proof of every invariant in
`THREAT_MODEL.md` over the actual Rust code we run. A proof over a parallel
model is not coverage. A Rust test can guard behavior, but it cannot check off a
proof item.

## Execution Plan

This plan starts from the current core projection path:

```text
src/core/project_fact.rs::project_one
  -> load_one_projection_input
  -> evaluate_loaded_projection_input
  -> prepare_projection
       -> dispatcher.dispatch_projection(&fact, &pending_inputs)
       -> enforce_owner_is_self(&fact, &output)
       -> ProjectionOutput::context_set(fact.id)
       -> validate_runtime_effects_for_admission(...)
  -> commit_projection_effects
       -> settle_projected_input_lifecycle_in_tx
       -> publish_retained_projection_state_in_tx
       -> wake_projection_work_from_new_context_in_tx
       -> commit_projector_emitted_runtime_effects_in_tx
```

### Stage 1: Theorem Surface And Debt Ledger

Concrete work: keep `src/core/proofs.rs` as the only place where core theorem
interfaces live. For every temporary `#[verifier::external_body]` theorem,
write the exact Rust path it stands for, the property it claims, and the later
proof or refactor that should remove the external body. The theorem list is
ordered from high-value composition theorems down to local helper theorems and
foundational crypto/substrate assumptions.

Win: every trusted core statement becomes named proof debt instead of ambient
confidence. Projector proofs can import a precise theorem name, and the
threat-model walkthrough can say exactly which core gap is still open.

What it means: this stage proves no security invariant by itself. It gives us a
stable vocabulary for the rest of the work: route dispatch, offer finalization,
offer provenance versus semantic offer proof, revocation-complete context,
table-write ownership, owner-scoped replacement, transition effects, and atomic
commit.

Success criteria: Verus accepts `src/core/proofs.rs`; normal Rust builds do not
depend on proof modules; no theorem in core mentions protocol authority roles;
each external-body theorem has a specific Rust-code target; and tests fail if
the plan splits back into multiple docs or model-only projector proofs return.

### Stage 2: Local Core Facts Already Exposed By The Code

Concrete work: prove the small core helpers over the production Rust code whose
runtime shape is already visible. `ProjectionOutput::context_set(fact.id)` must
copy each `ContextOfferClaim` into a `ContextOffer` with the same role, scope,
key range, and offer value and with `owner = fact.id`.
`ContextOfferClaim::into_offer` must be part of that proof, not merely mirrored by a separate model function.
`enforce_owner_is_self` must reject any need, time wake, or purge owned by a
different fact. Dropped incoming facts must not leave durable context or time
wakes behind.

Win: core, not projectors, owns the transition from ownerless claims to owned
offers. A projector can propose an offer claim, but only the projection worker
attaches the projected fact id, and owner-bearing effects cannot point at some
other fact.

What it means: this closes the first link in the provenance chain. If a stored
offer is produced by this path, its owner is the fact currently being projected,
not a projector-selected value. This still does not prove the projector's
semantic claim; it proves the core ownership mechanics around that claim.
Self-only purge is compatible with target-owned deletion: a deletion projector
publishes a self-owned `fact_purged` offer, and the target projector consumes
that offer and purges its own rows and fact bytes. A cross-fact purge remains a
core proof failure.

Success criteria: `offer_claim_finalizes_to_projected_owner`,
`projection_output_owner_bearing_effects_are_self`,
`purges_are_self_only`, and the missing-context/drop helpers lose
`external_body` only when Cargo-verus verifies the production Rust helper or
function body that normal builds execute. Focused Rust tests cover rejection of
foreign owners and dropped incoming durable-output attempts; and no
threat-model checklist item is claimed from this stage alone.

Current production-code foothold: `projected_owner_matches`,
`projected_purge_owners_are_self`, `projected_need_owners_are_self`,
`projected_time_wake_owners_are_self`, `projected_output_owners_are_self`,
`projected_owner_status`, `owner_status_allows_projection`,
`ContextOfferClaim::into_offer`,
`owned_offers_from_claims`, and `context_set_from_projection_parts` are real
production helpers inside Verus verification. Cargo-verus proves that
`projected_owner_matches(owner, fact_id)`
accepts if and only if `owner == fact_id`. It also proves that the purge, need,
and time-wake scan helpers accept if and only if every owner in the scanned
slice is the projected fact id. `projected_output_owners_are_self` composes
those scans and accepts if and only if every purge id, need owner, and wake
owner in the projection output parts equals the projected fact id.
`projected_owner_status` returns the exact production status class: accepted,
foreign purge, foreign need, or foreign time wake, with each status tied to the
same owner predicates; `enforce_owner_is_self` branches on that verified status
before producing `Ok(())` or a diagnostic error.
`owner_status_allows_projection` accepts if and only if the status is exactly
the accepted status, so the production success branch has a verified decision
predicate rather than an informal interpretation of the status byte.
`projection_output_owner_status(output, fact_id)` applies that same verified
status classification to the actual `ProjectionOutput` object consumed by
`enforce_owner_is_self`.
Cargo-verus also proves that the returned `ContextOffer.owner` equals the
owner argument for one claim and that role, scope, start key, end key, and
offer value are copied unchanged. For a slice of claims, Cargo-verus proves
the same length, owner, role, scope, start key, end key, and value preservation
for every returned offer. For the pre-normalization context-set construction,
Cargo-verus proves the input needs are carried unchanged and the constructed
offers preserve the same owner and claim fields. Cargo-verus also proves that
the version replay rebuild shape decision accepts exactly ordinary projections
or version replay rebuild projections with empty standing output: no standing needs, offers, or time wakes.
It also proves that the production status helper returns accepted or
standing-output exactly from that predicate, and that the allow helper accepts
only the accepted status.
`version_replay_rebuild_projection_status(context, wakes, effects)` applies
that same verified status classification to the actual prepared projection
shape consumed by `validate_version_replay_rebuild_projection_shape`. That is
not the full offer-finalization or version
replay rebuild admission theorem yet: the
`ProjectionOutput::context_set` normalization step and the `prepare_projection`
call order remain open core proof work, as does the
`validate_version_replay_rebuild_projection_shape` `Result` wrapper. It is also
not the full owner-bearing output theorem yet: the exported theorem still needs a
correspondence proof tying the `enforce_owner_is_self` `Result` wrapper,
diagnostic rejection branches, and `prepare_projection` call order to the
verified status and allow helpers.

### Stage 3: Routed Projection Evidence

Concrete work: keep leaf projectors on the simple `Projector::project` API and
put route evidence at the dispatcher boundary. `ProjectionDispatcher` selects
the effective tag and registered `FactRoute`, calls that route projector, and
returns a `RoutedProjection`. A `RoutedProjection` is the plain
`ProjectionOutput` plus router-stamped `ProjectionRouteEvidence`: projected
fact id, effective tag, registered route tag, stable projector info name, and
storage requirement. Carry that route evidence through `PreparedProjection` so
the commit path can say which route produced the output. The proof identity is
the stable route tag/projector-info pair, not runtime function-pointer
equality.

Terminology in this stage:

- `ProjectionDispatcher`: the production entry point used by `project_fact`.
  It chooses the route before the leaf projector runs.
- `FactRoute`: one registry row from a fact tag to the projector function,
  storage requirement, and stable projector metadata for that tag.
- effective tag: the semantic fact tag after envelope decoding. For ordinary
  facts it is the first byte; for envelope facts it is the inner protocol tag.
- route tag: the registered `FactRoute.tag` selected for the effective tag.
- `RoutedProjection`: the `ProjectionOutput` returned by the leaf projector
  plus route evidence stamped by the dispatcher that selected and called that
  projector. Leaf projectors do not construct this value.
- `ProjectionRouteEvidence`: the route evidence carried with a
  `RoutedProjection`: owner fact id, effective tag, route tag, projector info,
  and storage requirement.
- `projector_info`: stable human-readable projector identity from the route
  table. It is proof/debug metadata, not a runtime authority check by itself.
- `storage_requirement`: the storage-version guard the selected route requires
  before its effects may commit.

Win: a visible output can be tied to the route that actually projected the
owner fact. This is the core-side answer to "which projector did this come
from?"

What it means: when later projector proofs say "the auth signature projector
proved this kind of offer," core can prove the projected fact was dispatched to
that exact route before the output was committed. Without this stage, a
proof-facing `ProvenOffer` view could identify an offer but not the producer
theorem that justifies it.

Success criteria: `project_fact_dispatches_owner_route` loses `external_body`;
tests show an unknown tag is rejected, an envelope effective tag routes to the
semantic route, and the route evidence carried into `PreparedProjection`
matches the stable route tag that ran; the route-tag to producer-theorem table
is named explicitly as a proof obligation; and the runtime code still reads as
load, prepare, commit.

Current production-code foothold: `ProjectionDispatcher::dispatch_projection`
returns `RoutedProjection`. `RouterProjector` implements that dispatcher by
selecting one route, calling that selected route's projector, applying the
route's storage requirement to the output, and attaching
`ProjectionRouteEvidence { fact_id, effective_tag, route_tag, projector_info,
storage_requirement }`. Leaf projectors still return plain `ProjectionOutput`
and cannot self-report a producer route. `prepare_projection` stores the route
evidence in `PreparedProjection`. Cargo-verus proves the production helper
`projection_route_evidence(fact_id, effective_tag, route_tag, projector_info,
storage_requirement)` returns route evidence with exactly those same field
values. Cargo-verus also proves that
`selected_route_evidence(fact_id, effective_tag, stamp)` builds evidence from
the selected route's proof-relevant `FactRouteStamp`: if the stamp tag is the
effective tag, the evidence route tag is that same effective tag and the
projector info/storage requirement come from the stamp. This is selected-route
metadata proof, not the full route theorem: Cargo-verus still needs to prove
the route-table search, the selected projector function call, and the
correspondence from `PreparedProjection.route_evidence` to the committed output
path.

Route-search discovery: do not try to prove route-table search directly over
`FactRoute` while it contains the projector function pointer. Cargo-verus does
not support function pointer types as a proof target. The proof-relevant route
identity is `FactRouteStamp` (`tag`, `projector_info`, `storage_requirement`);
the next route-search proof must make the production search loop operate over
that metadata, or an equivalent production structure, and keep the projector
function pointer as executable code outside the proof relation.

### Stage 4: Projection DB Write Boundary

Concrete work: limit database write access before relying on offers as proof
records.
`ProjectionWriteTx` is constructible only inside
`project_fact.rs::commit_projection_effects`; `IntentWriteTx` is constructible
only inside intent handling; protocol projectors and query modules do not
receive a raw `Db`, raw `rusqlite::Connection`, or generic write transaction
for projected state. Projectors emit values (`ContextOfferClaim`,
`ContextNeed`, `ProjectedRowMutation`, facts, intents); core decides which
write authority can commit each value. Intent handlers are not yet fully sealed:
`HandlerContext::db()` still exposes transaction-local SQL for handler-owned
reads and writes, so the proof plan must replace that with read/intent-authority
accessors before treating handler table confinement as proved.

Win: the code shape makes direct projected-state writes unrepresentable outside
the projection worker. This is the main security boundary we settled on.

What it means: if a standing context edge, projected row, or offer exists, the
proof can start from "this was written through `project_fact`" rather than
checking every SQLite call site after the fact. The validity proof record for
context is the offer itself, viewed through the core write-boundary and route
theorems, not a separate proof row.

Success criteria: projected context tables and projected protocol tables are
writable only through `ProjectionWriteTx`; intent-owned tables are writable
only through `IntentWriteTx`; query modules have read access only; tests and
protocol modules cannot bypass the typed write boundary; and
`projected_table_writes_are_project_fact_only` has a realistic Rust-code proof
target.

Current production-code foothold: `commit_projection_effects` now constructs a
`ProjectionWriteTx` inside the SQL transaction and passes it through the
projection-owned commit stages that settle the selected input, publish retained
context/time-wake state, wake newly unblocked projection work, and commit
projector-emitted effects. Intent dispatch now constructs an `IntentWriteTx`
inside the SQL transaction and passes it through the commit stages that consume
the selected queue row, load handler context, run the handler savepoint, check
storage compatibility, and commit validated handler effects. This is not the
full DB confinement proof yet: the lower SQL helpers still unwrap to `&Db`,
`HandlerContext::db()` still exposes raw handler SQL, and the split row
wrappers still rely on a shared table allowlist until table ownership is
classified.

### Stage 5: Projected Versus Intent Row Authority

Concrete work: keep the shared SQL vocabulary (`TableInsert`,
`TableDeleteWhere`, and the raw test-only `RowMutation`) but split production
authority into `ProjectedRowMutation` and `IntentRowMutation`.
`ProjectionOutput` carries `Vec<ProjectedRowMutation>` beside its needs,
offers, and time wakes; `RuntimeEffects.row_mutations` carries
`Vec<IntentRowMutation>` for intent handlers and live runtime boundaries; and
`Db` exposes separate crate-private apply helpers for projection rows and
intent rows. Internally both wrappers reuse the same typed insert/delete
mechanics.

Win: the Rust API makes it impossible for an intent handler to write a
projected table or for a projector to write an intent-owned table by accident.
This is the row-table analogue of core attaching offer ownership.

What it means: table privacy becomes a code-shape property instead of an
allowlist convention. Projectors own projected state; intent handlers own
intent state; network and local operational tables stay outside protocol
authority.

Success criteria: `projected_table_writes_are_project_fact_only` loses
`external_body`; projected-table constants are declared in one projector-owned
table family; handlers cannot construct projected row mutations; projectors
cannot construct intent row mutations; current row-mutation tests are migrated
to the split API; and code review can still follow the commit path without a
generic capability framework.

Current production-code foothold: `ProjectionOutput::row_mutation` now accepts
`ProjectedRowMutation` and stores those rows outside `RuntimeEffects`;
`RuntimeEffects::row_mutation` now accepts `IntentRowMutation`; projection
validation rejects non-empty intent row mutations inside projector effects; and
projection commit calls `apply_projected_row_mutations_in_tx` at the same
commit position where generic row mutations used to run. `RuntimeDescription`
now carries separate `projected_row_mutation_tables` and
`intent_row_mutation_tables` lists. The protocol registry classifies current
projector read-model tables as projected tables and classifies
`bootstrap_connection_attempt_rows` as intent-owned connection-maintenance
bookkeeping, not projected state. The remaining proof gap is no longer one
shared allowlist; it is proving that the production validation and commit call
path always uses the correct list, and closing lower raw-SQL escape hatches
before claiming table-write confinement as a theorem.

### Stage 6: Proven Context Loading

Concrete work: extend `pending_projection_input_context_for_owner` and
`ProjectionContext` so authority-bearing context is a `ProvenOffer` or
`ProvenContext` record, not a payload fact. Split the proof-facing state into
core provenance and semantic provenness. Core provenance says the matched offer
was finalized from an owner fact through attested route evidence. Semantic
provenness additionally requires the producer route theorem for that offer kind.
That record carries the matched offer fields, offer owner fact id, producer
route identity, output kind or index when needed to disambiguate route output,
and stable offer-carried values where selector/range fields are not expressive
enough. Consumers must depend on the standard offer boundary plus provenance
and then cite the producer theorem for semantic authority. Core exposes
`ProjectionContext::attested_offer_for` and
`ProjectionContext::matched_attested_offers_for` for local route provenance:
the stored offer owner, loaded payload fact id, and producer route fact id all
agree. That is still not a protocol proof. `ProvenOffer` is the later
composition of one attested offer with the route-local producer theorem for an
accepted offer contract. Do not expose a raw `Fact` as a projector authority
surface. This stage deliberately precedes query rewiring: projection context
loading is core input plumbing, while user-facing queries are later consumers
of projected/proven state.

The authority-facing `ProjectionContext` should expose matched attested routed
offers grouped or filtered by accepted offer contracts, then compose those into
`ProvenOffer` records by producer theorem application, not just by the needs
that happened to wake the projector. A projector should name two related but
distinct surfaces:

```text
needs emitted for scheduling/liveness
accepted proven offer contracts used for authority/proofs
emitted proven offer contracts produced for other projectors
```

An accepted offer contract names the offer kind it admits into authority
context: role, scope, key/range layout, mandatory producer route or route
family, producer theorem, whether the offer is a positive grant or a
negative/revocation condition, and the semantic relation the projector knows how
to consume. Needs may be broader or differently shaped for wakeup efficiency,
but authority proofs must use only offers admitted by one of the projector's
accepted offer contracts. The projector should not inspect unrelated offers,
silently upgrade a wakeup match into authority, trust role/scope/key without
producer-route pinning, or decode producer-owned historical fact formats.

An emitted offer contract names the offer kind the projector can produce for
other projectors: role, scope, key/range layout, producer route, output
constructor, and theorem that proves the offer from the projector's current
fact plus any accepted proven offers it consumed. It also names a stable
predicate version, and every producer version that emits the offer must
re-prove that it preserves the same predicate. Producer proofs establish
emitted offer contracts; consumer proofs cite accepted offer contracts.

Negative-authority contracts need a stronger context theorem than positive
grant contracts. For a positive grant, missing context usually means no grant,
which is safe. For revocation, deletion, key retirement, removal, and
non-resurrection invariants, a missed matching revocation offer can make stale
state look authorized. Those contracts therefore require a
revocation-context-completeness theorem: before emitting a gated sharing,
decryption, materialization, or sync offer, projection loaded all in-scope
proven revocation offers for the accepted contract.

Win: projector proofs can distinguish "there is matching context" from "there
is a proven, version-stable offer boundary from producer route P available for
me to check." This is the core tool needed for induction through multiple
projector generations without forcing every consumer to understand every
historical producer fact version.

What it means: projector matching is a liveness guarantee, not an invariant
guarantee. A match may wake a projector, but authority comes from a proven
offer emitted by a known producer route whose projector decoded/adapted its own
fact bytes and proved that offer. Consumer projectors check the proven offer's
standard role, scope, key/range, producer route/proof identity, predicate
version, and semantic relation to the current fact. If a consumer needs more
information than the
offer boundary exposes, extend the producer's stable offer/context shape or add
a producer-owned adapter theorem; do not make every consumer decode raw
producer fact versions.

Historical compatibility stays producer-owned. If an old semantic statement is
substantially different, or if several old facts together correspond to one
current semantic statement, the producer projector/family owns that join: it
emits needs, consumes proven stable offers from any required old companion
facts, performs its decode/authenticate/adapt logic, and emits the current
stable offer only when the current predicate is proved. Other projectors see
only that current proven offer, not the producer's historical fact graph.

Success criteria: `projection_context_records_offer_provenance` and
`matched_offer_loads_owner_fact` lose `external_body`; candidate
accessors are not used in authority-bearing projector proofs; tests cover a
matched unattested offer being visible for wakeup but rejected by attested
accessors, and later a matched attested-but-unproved offer rejected by
`ProvenOffer` construction when no producer theorem applies; producer proof walkthroughs show
faithful decode/adapt from every supported fact version to the stable offer
predicate, including any required multi-fact compatibility joins; consumer proof
walkthroughs identify the emitted offer contracts proved by the producer and the
accepted offer contract used by the consumer, then check the proven offer
boundary, producer route, predicate version, and provenance against the current
fact;
tests cover a candidate offer whose owner route has no applicable producer
theorem, whose role/key matches a wakeup need but no accepted offer contract,
whose offer kind is not admitted by that projector, or whose producer route is
wrong, being rejected by authority accessors; and no proof may rely on a
role/scope/selector match as authority without a producer theorem and accepted
offer contract for that proven offer kind. Negative-authority offer kinds also
have tests and theorem statements for complete revocation/deletion/retirement
context over the accepted offer contract.

### Stage 7: Core Proof Feasibility Pass

Concrete work: after the minimum refactor in stages 3-6, immediately try to
remove `#[verifier::external_body]` from the core runtime theorems. Prove the
small helpers first, then the cross-helper facts:
`project_fact_dispatches_owner_route`, `offer_claim_finalizes_to_projected_owner`,
`projected_table_writes_are_project_fact_only`,
`projection_context_records_offer_provenance`,
`matched_offer_loads_owner_fact`,
`context_replacement_preserves_owner_boundaries`, and
`atomic_projection_commit_sound`. `wake_context_matches_in_tx` must record
matches whose offer owner is the fact named by the matched offer and whose
match is sufficient for wakeup, but matcher role/scope/selector semantics are
liveness plumbing, not authority. `replace_context_for_owner_in_tx` deletes and
replaces only the current owner's needs while appending that owner's finalized
offers; and `commit_projection_effects` commits lifecycle, context, wake, row,
fact, purge, intent, and projected-output writes as one transaction.
This pass verifies the actual call graph: every `*_in_tx` helper shares the
same SQLite transaction, no effect commits on a separate connection or
autocommit path, and external wake/channel notifications cannot become
authority-visible before commit. The atomic theorem surface must include the
input fact lifecycle and emitted facts/intents/purges, not only before/output/
after snapshots.

Win: we learn early how hard the Verus proof is over the real core code. If a
proof fails because the code shape is hostile to verification, we can make the
smallest readability-preserving refactor while the surface is still narrow.

What it means: before query lockdown or projector theorem work, core should be
able to prove: the route was selected, the output was owner-bound, the offer was
written by projection, matching context was loaded with provenance records,
projected tables are confined to projection writes, owner replacement is scoped,
and the visible state after commit preserves the core induction invariant.
This stage does not prove protocol authority or semantic offer validity; that
requires the route-local producer theorem. A wrong match can at worst wake a
projector that later rejects after checking proven context; it cannot become
positive authority merely because the selector matched. Revocation-sensitive
outputs remain blocked until their accepted offer contracts have completeness
theorems.

Success criteria: no core theorem about route dispatch, offer finalization,
context provenance, table-write confinement, owner-scoped replacement, or atomic
commit still uses `external_body`; threat-model authority proofs cite proven
offer origin, producer projector theorems, and consumer offer-boundary checks
rather than matcher selector semantics; Rust tests exercise owner-scoped
replacement, overlap wakeup, rollback on later commit failure, and no orphan
offer/output rows; Verus runs in the doc tests; and the proof-debt section lists
only foundational assumptions plus explicit projector obligations.

### Stage 8: Query-Visible Source Lockdown

Concrete work: inventory every user-facing query module and CLI-visible read,
then turn the authority-bearing part of that inventory into a typed read
boundary. Each read must be classified as projected table, standing context,
proven offer, local operational status, or raw diagnostic. A query that
influences user authority decisions may read projected tables, standing context,
and proven offers only through authority accessors that preserve provenance.
Raw `ReadDb` access may expose diagnostics, but it must not produce an
authority-bearing value. Authority queries may not read raw facts, incoming
intake, pending queues, intent queues, or network staging tables as authority.

Win: the proof covers what users can see, not only what projectors can write.
Threat-model invariants are stated in terms of user-visible capabilities and
data, so query surfaces must be part of the proof boundary.

What it means: raw facts may remain auditable storage, queues may remain runtime
mechanics, and network rows may remain IO staging, but none of those can become
authority just because a query helper exposes them. Any query-visible projected
table must have a projected-table owner and, when used as authority, a proven
offer path back through projection.

Success criteria: each query-visible projected table has one declared owner
family and proven-offer path; authority reads go through typed accessors that
raw diagnostic reads cannot construct; query tests assert the intended source
class for high-risk reads; documentation names any diagnostic/raw query as
non-authority; and no threat-model invariant is checked until its user-visible
reads are tied to projected rows, context, or proven offers.

### Stage 9: Route-Local Projector Contracts

Concrete work: introduce route-local projector theorem stubs only after the
core spine is precise enough to compose them. Each stub names one route, one
owner fact shape, one emitted offer claim or projected row, required proven
context inputs, crypto/parser assumptions, predicate version, whether the
contract is positive or revocation-sensitive, and the exact semantic predicate
proved for that output.

Win: stubbing becomes controlled and useful. A stub can stand in for one
projector theorem while we build high-level proofs, without pretending every
projector output is valid.

What it means: a high-level proof may temporarily assume, for example, the
signature route proves a `signature_proof` offer from decoded bytes and an
Ed25519 verification. It may not assume all offers are proven, all rows are
authorized, all context is trustworthy, or all revocation context was complete.

Success criteria: every route-local stub is in that route's `proofs.rs`, not
core; each stub has a concrete "remove this by proving `Projector::project`
path" note; revocation-sensitive stubs name the completeness theorem they still
owe; every stable offer predicate has a version-stability obligation; no
blanket projector-validity axiom exists; and high-level walkthroughs list any
route-local stub as an open gap.

### Stage 10: First Real Projector Foothold

Concrete work: prove `auth::signature` first. The theorem must connect the
actual `SignatureProjector` path to decoded signature fact bytes, `Fact.id ==
hash(Fact.bytes)`, workspace scope, Ed25519 verification of
`signature_message(workspace_id, target_fact_id)`, and the emitted
`signature_proof` claim's role/scope/selector.

Win: we get one reusable protocol proof artifact with minimal upstream authority
dependencies. Many later auth, content, and connection proofs can consume
signature evidence through proven context.

What it means: a stored proven `signature_proof` offer says the owner fact was
routed through `auth::signature`, the projector verified the signed target
statement from the actual bytes, and core finalized that claim into the stored
offer. It still does not prove membership, admin rights, endpoint authority, or
content authorization by itself.

Success criteria: the `auth::signature` proof no longer claims model-only
coverage; Cargo-verus verifies the theorem over the
`SignatureProjector::project` production body; its proof walkthrough explains
every branch including decode failure and invalid signature; and downstream
proofs consume it through proven offer accessors rather than candidate context.

### Stage 11: Compose Threat-Model Invariants

Concrete work: work through the threat-model checklist in proof dependency
order: workspace root and auth DAG, member/admin authority, endpoint and
connection admission, sync shareability, content authorship, deletion, key
retirement, and post-delete non-resurrection. For each invariant, identify the
visible rows/offers/queries, the projector routes that can produce them, and
the proven context each route requires. State one top-level theorem that maps
the core induction invariant plus route-local projector theorems to every
checked `TM-*` item, and keep each item as a subtheorem with explicit
dependencies.

Win: the proof effort turns from local projector proofs into user-facing security
claims.

What it means: each checked threat-model item has the theorem shape it actually
needs. Authority and visibility items use only-if theorems: dangerous or
user-visible output exists only if the required facts, signatures, membership,
removal state, key state, and scope relationships were present and proven
through the projection chain. Deletion, retirement, and local materialization
items also need transition-effect theorems: once the revocation/deletion/
retirement fact is admitted, routed, and projected with complete context, the
next committed projection removes or suppresses the target-owned rows, offers,
keys, or sync-share outputs it is responsible for. Eventual user-visible cleanup
additionally depends on the runtime scheduling/fairness assumption named in
that item.

Success criteria: a checklist item is marked complete only when its query
surface, projected rows, offers, context dependencies, route dispatch, and
projector semantic theorems are all proved without non-foundational stubs; any
negative-authority item has a context-completeness proof; any must-purge or
must-retire item has a transition-effect proof; its walkthrough states the
exact theorem shape and remaining foundations; and any iff theorem is used only
where the projector relation is actually deterministic and fully characterized.

## Proof Simplifications

These reductions keep the proof focused on security invariants instead of
incidental mechanics:

- Projector matching is a liveness guarantee, not an invariant guarantee. A
  match can wake work, but no authority proof may rely on the match coordinate
  alone. Positive authority may treat missing context as no grant; revocation,
  deletion, retirement, and non-resurrection proofs need explicit context
  completeness for the accepted negative-authority offer kinds.
- Authority-bearing context means proven stable offers, backed by producer
  projector theorems over owner facts. Producers decode/authenticate/adapt their
  own fact versions and prove the emitted offer predicate. Consumers check the
  proven offer's standard role, scope, key/range, mandatory producer route,
  predicate version, and relation to the current fact; they should not decode
  every raw producer fact version.
- Needs are liveness subscriptions. Accepted proven offer contracts are the
  authority interface. A projector may emit broad or convenient needs, but its
  proof may consume only the proven offer kinds it explicitly admits.
- Emitted offer contracts are the producer side of the same boundary. A
  projector proof must name every authority-bearing offer kind it can emit and
  prove that each emitted offer follows from its current fact plus accepted
  proven offers.
- Offers are the cross-projector authority surface. If compatibility with old
  facts requires joining several old facts, the producer route/family performs
  that join internally through normal projection needs and proven stable offers,
  then emits the current offer it wants other projectors to see.
- Core proves provenance and write authority: the owner fact was routed through
  the recorded route, the output was owner-bound, projected state was written
  only by `project_fact`, and provenance-recorded context links the stable
  offer to its owner fact and route. Core does not prove protocol authority such as
  admin, signer, membership, or deletion rights.
- Avoid hash injectivity and authoring iff theorems unless a later invariant
  truly needs them. Prefer producer-side theorems from the actual stored bytes
  for projector-local output: `Fact.id` binds those bytes, and the producer
  projector decodes/adapts those bytes into stable offers. When an invariant
  depends on target id uniqueness, replay exclusion, or non-resurrection,
  BLAKE3 collision resistance is a named foundational assumption.
- Prefer only-if safety theorems for authority and visibility. Do not require
  an iff theorem unless the projector relation is deterministic and fully
  characterized. Must-purge, must-retire, and must-suppress items need separate
  transition-effect theorems rather than an only-if theorem alone.
- Query lockdown is downstream of proven context loading. Queries matter for
  user-visible invariants, but they are not required to prove that
  `project_fact` supplies proven context to projectors.
- SQLite transaction semantics, BLAKE3 content addressing/collision resistance,
  Ed25519, AEAD, key-wrap/key-derivation behavior, and byte-parser correctness
  may be named foundational assumptions while core and projector proofs are
  built. Crypto foundations may state primitive key-possession and decryption
  facts; protocol proofs still decide which projected keys are authorized,
  retired, or visible.

## File Layout

Protocol-neutral theorem surfaces and route-local theorem stubs live in
`proofs.rs` files:

```text
src/core/proofs.rs
src/protocol/<scope>/<fact_family>/proofs.rs
```

Production implementation files may carry small Verus contracts on the actual
helpers they define. Those contracts count only when Cargo-verus verifies the
production crate path. Normal Rust builds may depend on `vstd` for erased
contracts, but they must not depend on standalone proof modules. Standalone
proof modules are kept out of Cargo-verus production verification and are
verified directly by the proof-module test. Production implementation files
should stay readable as protocol code: decode, authenticate, adapt, project,
and effects.

## Core Theorem Surface

`src/core/proofs.rs` owns protocol-neutral theorem interfaces. These are the
only core assumptions projector proofs may import.

Core predicates and theorem names:

```text
projection_context_sound(ctx, graph)
projection_context_records_offer_provenance(ctx, graph)
matched_offer_loads_owner_fact(matched)
matcher_preserves_role_scope_selector(need, matched)
project_fact_dispatches_owner_route(fact, route)
projected_table_writes_are_project_fact_only(before, after)
context_replacement_preserves_owner_boundaries(before, after, owner)
atomic_projection_commit_sound(before, commit, after)
projection_output_owner_bearing_effects_are_self(output, current_fact_id)
purges_are_self_only(output, current_fact_id)
offer_claim_finalizes_to_projected_owner(claim, offer, current_fact_id)
projection_context_lacks_payload_for_need(ctx, need)
parked_output_for_missing_need(output, need)
theorem_ed25519_verify_binds(evidence)
```

Production helper contracts currently proved:

```text
projected_owner_matches(owner, fact_id) bytewise accepts if and only if owner == fact_id
projected_purge_owners_are_self(purged, fact_id) accepts if and only if every purged id is fact_id
projected_need_owners_are_self(needs, fact_id) accepts if and only if every need owner is fact_id
projected_time_wake_owners_are_self(wakes, fact_id) accepts if and only if every wake owner is fact_id
projected_output_owners_are_self(purged, needs, wakes, fact_id) accepts if and only if all three owner groups are fact_id
projected_owner_status(purged, needs, wakes, fact_id) returns accepted/foreign-purge/foreign-need/foreign-wake exactly from those predicates
owner_status_allows_projection(status) accepts if and only if status is OWNER_CHECK_ACCEPTED
projection_output_owner_status(output, fact_id) returns accepted/foreign-purge/foreign-need/foreign-wake exactly from the output's purges, needs, and time wakes
ContextOfferClaim::into_offer(claim, owner).owner == owner
ContextOfferClaim::into_offer(claim, owner) preserves role/scope/start/end/value
owned_offers_from_claims(claims, owner).len == claims.len
forall returned offer: offer.owner == owner
forall returned offer: offer.role/scope/start/end/value match the same-index claim
context_set_from_projection_parts(needs, claims, owner) preserves needs
context_set_from_projection_parts(needs, claims, owner) builds same-index owned offers
projection_route_evidence(fact_id, effective_tag, route_tag, projector_info, storage_requirement) preserves every route evidence field
selected_route_evidence(fact_id, effective_tag, stamp) preserves selected route stamp metadata and gives route_tag == effective_tag when stamp.tag == effective_tag
version_replay_rebuild_shape_allowed(version_replay_rebuild, needs, offers, wakes) accepts if and only if ordinary projection or empty version replay rebuild output
version_replay_rebuild_shape_status(version_replay_rebuild, needs, offers, wakes) returns accepted or standing-output exactly from that predicate
version_replay_rebuild_shape_status_allows_projection(status) accepts if and only if status is VERSION_REPLAY_REBUILD_SHAPE_ACCEPTED
version_replay_rebuild_projection_status(context, wakes, effects) returns accepted or standing-output exactly from the prepared context, time wakes, and rebuild effect
matched_context_owner_matches_payload(matched) accepts if and only if matched.routed_offer.offer.owner == matched.payload.id
routed_offer_owner_matches_producer(routed_offer) accepts if and only if routed_offer.offer.owner == routed_offer.producer_route.fact_id
matched_context_has_routed_provenance(matched) accepts if and only if matched.routed_offer.offer.owner == matched.payload.id and matched.routed_offer.offer.owner == matched.routed_offer.producer_route.fact_id
RoutedOffer::owner_matches_producer accepts if and only if routed_offer.offer.owner == routed_offer.producer_route.fact_id
MatchedContext::has_routed_provenance accepts if and only if matched.routed_offer.offer.owner == matched.payload.id and matched.routed_offer.offer.owner == matched.routed_offer.producer_route.fact_id
```

These contracts are proofs over helper Rust code that normal builds execute.
They are core proof footholds, not threat-model coverage and not completion of
`offer_claim_finalizes_to_projected_owner` or
`project_fact_dispatches_owner_route`.

The `owned_offers_from_claims` and `context_set_from_projection_parts` proofs use a narrow Verus
`assume_specification` for the derived `ContextOfferClaim::clone` call so Verus
can call that production clone and reason that clone preserves the whole claim.
The remaining offer-finalization gap is no longer claim-to-offer field copying
or pre-normalization context-set assembly; it is proving the
`ProjectionOutput::context_set` normalization step and `prepare_projection`
call order over executable helper code. The remaining owner-checking gap is no
longer the equality decision, per-slice scans, aggregate owner predicate,
status classification, accept-status decision, or full-output status bridge; it
is proving the `enforce_owner_is_self` `Result` wrapper diagnostic rejection
branches and `prepare_projection` call order over executable helper code.
The remaining version replay rebuild admission gap is no longer the
standing-output decision, status classification, accept-status decision, or
full prepared-shape status bridge; it is proving the
`validate_version_replay_rebuild_projection_shape` `Result` wrapper and
`prepare_projection` call order around the verified status helper.

The remaining matched-context provenance gap is no longer the local
owner/payload equality decision for one `MatchedContext` or the local
offer-owner/producer-route equality decision for one `RoutedOffer`:
`MatchedContext::with_route` rejects mismatched owner/payload/route fixtures at
runtime, the SQL pending-context loader asks the active `ProjectionDispatcher`
for producer route evidence while loading matched offer owners, and Cargo-verus
proves both production decision helpers plus their combined routed-provenance
predicate. The production `attested_offer_for` and
`matched_attested_offers_for` accessors filter on that same local predicate.
The open core work is proving that
`pending_projection_input_context_for_owner` and the SQL loader construct every
projector-visible matched context through that checked path and proving route
selection through the whole production dispatcher call graph. Semantic
provenness remains a route-local projector theorem, not a core theorem.

The remaining route-dispatch gap is no longer route-evidence field stamping or
selected-stamp evidence construction; it is proving that `RouterProjector`
found the registered route stamp for the effective tag, called that selected
projector function pointer, and carried the resulting evidence through
`prepare_projection` and commit.

Core proves plumbing only. It must not prove that an admin is valid, an endpoint
may sign content, a deletion is authorized, a receipt grants authority, or a
fact is sendable. Those are protocol proof obligations.

Foundational assumptions may cover SQLite transaction semantics, BLAKE3
content addressing and collision resistance, Ed25519 binding, AEAD behavior,
key-wrap/key-derivation primitive behavior, byte parsers, and other substrate
tools. They must be named where used. They may say what the primitive gives a
holder of the relevant key; they must not decide protocol authority such as who
is a member, admin, signer, or deletion author.

## Table Ownership

The hard core proof boundary is table ownership. The Rust API should make
unauthorized writes unrepresentable while keeping core readable.

Planned implementation shape:

```rust
pub struct ProjectedTableSchema;
pub struct IntentTableSchema;
pub struct NetworkTableSchema;

pub enum ProjectedRowMutation { /* projected inserts/deletes */ }
pub enum IntentRowMutation { /* intent-owned inserts/deletes */ }

pub struct ReadDb<'a>;
pub struct AuthorityReadDb<'a>;
pub(crate) struct ProjectionWriteTx<'a>;
pub(crate) struct IntentWriteTx<'a>;
```

Rules:

```text
Projector row builders return ProjectedRowMutation.
ProjectionOutput carries projected row mutations only.
Intent effects carry IntentRowMutation or handler-owned effects.
ProjectionWriteTx is constructible only by project_fact.
IntentWriteTx is constructible only by intent handling.
Query modules get read access, not write authority.
Authority-influencing reads use AuthorityReadDb/proven accessors, not raw ReadDb.
```

Keep `project_fact.rs` readable as load, prepare, commit: load context, run the
selected projector, validate owner and proof boundaries, publish projected
state, wake dependents, and commit follow-up work. Avoid macro-heavy ownership
DSLs, deeply generic transaction traits, and broad SQL rewrites while changing
write authority. Migrate one table owner at a time with realistic tests.

## Proven Offers

Projectors emit ownerless `ContextOfferClaim`s. Core finalizes them into stored
`ContextOffer`s with `owner = projected_fact_id`, copying role, scope, key
range, and offer value exactly.

A proven offer is not a free-standing boolean. For authority-bearing use, proof
status means the whole provenance chain exists:

```text
stored offer O
  -> O.owner = F.id
  -> F was projected by project_fact
  -> project_fact dispatched F through registered route P
  -> P emitted ownerless claim C
  -> core finalized C into O without changing role/scope/range/value
  -> P's theorem proves C from F's decoded bytes and proven context
```

At runtime, the validity proof record is the stored offer. Core's proof-facing
value is an attested routed offer: a view of that `ContextOffer` plus
provenance derived from core invariants, especially owner fact id, producer
route identity, and output kind/index when one route can emit several
authority-bearing outputs. It is not a separate persisted proof row. A later
`ProvenOffer` is constructible only from that core-attested route provenance
plus the producer theorem for the accepted offer contract. Checking role,
scope, and selector without checking producer route and predicate version is
never authority.

`ProjectionContext` should expose candidate context for wakeup, attested
routed-offer accessors for core provenance, and later proven-offer constructors
for authority:

```rust
offer_for(...)
matched_offers_for(...)
attested_offer_for(...)
matched_attested_offers_for(...)
ProvenOffer::from_attested(...)
```

Projector proofs must use proven offers, not merely attested offers, for
authority-bearing dependencies. Producer projector theorems connect those
offers to decoded/adapted owner fact bytes. Consumer projectors check the stable
offer boundary and should not know every producer fact version. Candidate
payload access is migration debt and must be removed from projector authority
paths.

Each projector should name accepted proven offer contracts separately from the
needs it emits. Needs describe what can wake the projector; accepted offer
contracts describe what offer kinds the projector admits and is allowed to treat
as authority, including the required producer route and predicate version. The
same projector should also name its emitted offer contracts: what offer kinds it
can publish for other projectors, and which theorem proves each kind.

If old fact compatibility requires multiple old facts, that multi-fact
conversion is still producer-owned. The producer route/family may wait on other
proven stable offers, but once it emits a current offer, that offer is the only
authority surface visible to downstream projectors.

The dependency graph for proven offers is well-founded over committed projection
steps. A producer theorem may consume only proven offers that were committed
before the current projection input was prepared. A batch is proved as an
ordered sequence of individual commits, or it must forbid intra-batch authority
dependencies. Cyclic authority dependencies across generations are rejected
unless a route proves a separate base case and decreasing measure.

## Proof Discoveries

Discovery: avoiding cascades forces direct support for replaceable or
query-visible authority. A materialized row whose authority can be invalidated
must either be regenerated from current proven offers, carry direct references
to every revocation-sensitive offer needed to justify it, or be queried only
through an accessor that rechecks those current proven offers. Hidden transitive
support through an old projected row is not enough: if row A depends on row B
and B's authority depended on offer C, then A is sound without a cascade only
when B's current proven offer is the stable authority boundary and its producer
theorem includes C, or A names C directly in its support set.

Stricter discovery: every dependent of replaceable authority should need the
same purge trigger id that invalidates that authority. Without cascades, the
purge trigger is the common wakeup frontier. If a dependent row can remain
visible after its authority disappears, that dependent must have emitted a need
for the same purge trigger id so core reprojects it when the purge offer is
committed. A family may choose query-time proven-offer rechecking instead, but
then the query must not treat the stale projected row as authority on its own.

## Core Induction

The runtime proof target is an induction over projection and handler commits:

```text
standing_context_sound(before)
projected_table_sound(before)
authority_read_boundary_sound(before)
well_founded_projection_step(current_fact, before)
core context construction theorem
core route dispatch theorem
core projected-table ownership theorem
projector theorem or explicit route-local projector stub for current fact
revocation-complete context theorem when the output is negative-authority gated
core context replacement theorem
core atomic commit theorem
  -> standing_context_sound(after)
  -> projected_table_sound(after)
  -> authority_read_boundary_sound(after)
  -> every committed row, finalized authority offer, sync-share contribution,
     deferred intent, and purge has a valid derivation
```

High-level threat-model coverage requires the composed only-if direction:
dangerous output implies required authority evidence and exact allowed effects.
Deletion, retirement, and non-resurrection additionally require transition
effects that remove or suppress target-owned visible state after the relevant
commit. Iff theorems are useful only when the Rust projector relation can be
exactly characterized; the safety direction is mandatory.

## First Projector Foothold

After the core proof spine is complete, start projector coverage with
`auth::signature`. It is one projector, has no upstream protocol-authority
dependency, and produces a reusable proof artifact.

Target theorem:

```text
stored proven signature_proof offer O
  -> O.owner = signature fact F.id
  -> F was routed through auth::signature::SignatureProjector
  -> SignatureProjector emitted the claim finalized into O
  -> F.bytes decode to SignatureFact {
       workspace_id,
       target_fact_id,
       signer_public_key,
       signature
     }
  -> F.id == hash(F.bytes)
  -> F.scope == workspace scope(workspace_id)
  -> Ed25519 verifies signature_message(workspace_id, target_fact_id)
     under signer_public_key
  -> BLAKE3 collision resistance is the named foundation when a downstream
     proof needs target_fact_id to uniquely identify one target byte string
  -> O.role == signature_proof
  -> O.scope == workspace scope(workspace_id)
  -> O.selector == (target_fact_id, signer_public_key)
```

This proves no carrier fact, forged context row, unrelated table write, query
helper, intent handler, or wrong projector can create a query-visible proven
`signature_proof` offer for a different target, signer key, or workspace
than the bytes actually verified. It does not prove membership, admin,
endpoint, content-author, deletion, or key-wrap authority.

## Proof Order

1. Complete the core proof spine.
2. Prove `auth::signature` as the first projector proof foothold.
3. Prove workspace bootstrap and local accepted-invite slices.
4. Prove auth authority DAG: user, admin, invites, endpoints, content signers,
   recipient keys, removal, and frontiers.
5. Prove connection request and connection admission.
6. Prove sync shareability and dependency closure.
7. Prove content admission, authorship, file slices, deletion, retention, and
   post-delete key retirement.

## Threat-Model Checklist

- [ ] TM-M1 root workspace and auth DAG.
- [ ] TM-M2 carriers do not grant authority.
- [ ] TM-M3 workspace scoping.
- [ ] TM-M4 members cannot escalate without authority.
- [ ] TM-M5 removal and retirement stop future sharing.
- [ ] TM-C1 carriers cannot read plaintext.
- [ ] TM-C2 local private material is not syncable.
- [ ] TM-C3 dependency closure stays authorized.
- [ ] TM-C4 key requests are protocol facts, not server privileges.
- [ ] TM-C5 content opening requires authority and key coverage.
- [ ] TM-I1 content authorship is signer-bound.
- [ ] TM-I2 admin authority is not content-signing authority.
- [ ] TM-I3 replay cannot change accepted statements.
- [ ] TM-I4 receipts and frames are evidence, not authority.
- [ ] TM-D1 deletion is target-owned.
- [ ] TM-D2 deleted content is not locally materialized or shareable.
- [ ] TM-D3 key retirement removes derivation paths.
- [ ] TM-D4 server replay cannot resurrect deletion.
- [ ] TM-D5 server plus post-delete compromise cannot decrypt deleted content.
- [ ] TM-D6 key healing cannot resurrect removed roots.

No checklist item may be checked while it depends on an unproved core theorem
stub or a route-local projector stub.

## Review Rules

1. Proof progress means Cargo-verus proof over production Rust code that normal
   builds execute.
2. Model/view proofs are not proof progress, even with a correspondence story.
   A `Spec*` helper may define vocabulary for a production-code contract, but
   proving a theorem only over `Spec*` values does not retire a stub, does not
   advance a stage, and does not support a threat-model checklist item.
3. Core theorem stubs live only in `src/core/proofs.rs`.
4. Protocol authority stays in protocol projector proofs.
5. Missing-context and mismatched-context branches must be explicit.
6. Runtime changes need realistic Rust tests; proof changes need Verus runs.
7. Every proof change must include a walkthrough naming theorem shape,
   assumptions, proof steps, what is really proved, and remaining gaps.
8. Commit completed work on the same worktree branch before handoff or review.

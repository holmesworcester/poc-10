use std::fs;
use std::path::Path;
use std::process::Command;

const VERUS_PLAN_PATH: &str = "docs/verus_proof_strategy.md";
const DEFAULT_VERUS_PATH: &str = "/home/holmes/verus-install/verus-x86-linux/verus";
const DEFAULT_CARGO_VERUS_PATH: &str = "/home/holmes/verus-install/verus-x86-linux/cargo-verus";

fn verus_plan() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(root.join(VERUS_PLAN_PATH)).expect("read Verus plan doc")
}

fn repo_file(path: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(root.join(path)).unwrap_or_else(|err| panic!("read {path}: {err}"))
}

fn core_proofs() -> String {
    repo_file("src/core/proofs.rs")
}

#[test]
fn verus_projector_proof_modules_verify() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let verus = std::env::var("VERUS").unwrap_or_else(|_| DEFAULT_VERUS_PATH.to_string());
    assert!(
        Path::new(&verus).exists(),
        "Verus binary not found at {verus}; set VERUS to the verifier path"
    );

    for proof_file in [
        "src/core/proofs.rs",
        "src/protocol/auth/signature/proofs.rs",
        "src/protocol/auth/invite_accepted/proofs.rs",
        "src/protocol/auth/workspace/proofs.rs",
    ] {
        let output = Command::new(&verus)
            .current_dir(root)
            .args(["--crate-type=lib", "--cfg", "verus_keep_ghost", proof_file])
            .output()
            .unwrap_or_else(|err| panic!("run Verus for {proof_file}: {err}"));
        assert!(
            output.status.success(),
            "Verus failed for {proof_file}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn cargo_verus_verifies_production_core_projection_contracts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cargo_verus =
        std::env::var("CARGO_VERUS").unwrap_or_else(|_| DEFAULT_CARGO_VERUS_PATH.to_string());
    assert!(
        Path::new(&cargo_verus).exists(),
        "cargo-verus binary not found at {cargo_verus}; set CARGO_VERUS to the verifier path"
    );

    let output = Command::new(&cargo_verus)
        .current_dir(root)
        .args([
            "focus",
            "-p",
            "topo",
            "--target-dir",
            "/mnt/storage/holmes-cargo-target/verus-production-proof-test",
            "--lib",
            "--",
            "--no-lifetime",
        ])
        .output()
        .unwrap_or_else(|err| panic!("run cargo-verus production proof: {err}"));
    assert!(
        output.status.success(),
        "cargo-verus production proof failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("verification results:: 32 verified, 0 errors"),
        "production proof should verify the real core projection contracts:\n{combined}"
    );
}

#[test]
fn protocol_proof_modules_do_not_claim_model_only_theorems() {
    let proof_files = [
        "src/protocol/auth/signature/proofs.rs",
        "src/protocol/auth/invite_accepted/proofs.rs",
        "src/protocol/auth/workspace/proofs.rs",
    ];
    let required = [
        "No theorem in this file currently claims threat-model coverage.",
        "Rust `Fact`",
        "`ProjectionContext`",
        "`ProjectionOutput` values it executes",
    ];
    let forbidden = [
        "SpecSignatureFact",
        "SpecSignatureProofOffer",
        "SpecInviteAcceptedFact",
        "SpecWorkspaceAcceptedOffer",
        "SpecWorkspaceFact",
        "SpecWorkspaceMaterializedOutput",
        "verified view extracted",
        "theorem_signature_projector_offer_is_valid",
        "theorem_workspace_accepted_projector_offer_is_valid",
        "theorem_workspace_materialization_only_if",
        "theorem_workspace_projector_materializes_iff_safety_shape",
        "theorem_workspace_materialized_output",
        "workspace_projector_materializes(",
        "valid_signature_proof_offer(",
        "valid_workspace_accepted_offer(",
    ];

    for proof_file in proof_files {
        let text = repo_file(proof_file);
        let missing = required
            .iter()
            .copied()
            .filter(|needle| !text.contains(needle))
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "{proof_file} must state Rust-backed proof obligations and no current coverage:\n{}",
            missing.join("\n")
        );

        let present = forbidden
            .iter()
            .copied()
            .filter(|needle| text.contains(needle))
            .collect::<Vec<_>>();
        assert!(
            present.is_empty(),
            "{proof_file} still contains model-only proof artifacts:\n{}",
            present.join("\n")
        );
    }
}

#[test]
fn core_proofs_make_trust_boundary_explicit() {
    let text = core_proofs();
    let required = [
        "Read the declarations from most significant to most helper-like:",
        "Every exported `theorem_*` below currently uses",
        "`#[verifier::external_body]`",
        "It is an explicit proof debt",
        "Proven in production Rust today:",
        "`projected_owner_matches(owner, fact_id)` bytewise accepts if and only if",
        "`owner == fact_id`",
        "the verified scan helpers use this production",
        "`projected_purge_owners_are_self`, `projected_need_owners_are_self`, and",
        "`projected_time_wake_owners_are_self` accept if and only if every scanned",
        "`enforce_owner_is_self` branches on these verified production scans",
        "`projected_output_owners_are_self` composes the three owner scans",
        "accepts if and only if every scanned purge id, need owner, and time-wake",
        "this aggregate helper before returning success",
        "`projected_owner_status` returns accepted, foreign purge, foreign need, or",
        "foreign time-wake exactly according to those owner predicates",
        "`enforce_owner_is_self` branches on this verified production status",
        "`owner_status_allows_projection(status)` accepts if and only if `status`",
        "is exactly `OWNER_CHECK_ACCEPTED`",
        "success branch is not an",
        "unproved interpretation of the status byte",
        "`ContextOfferClaim::into_offer(claim, owner).owner == owner`",
        "ContextOfferClaim::into_offer(claim, owner) preserves role/scope/start/end/value",
        "`owned_offers_from_claims(claims, owner)` returns one offer per claim",
        "every returned offer has `owner`",
        "same role, scope, start key, end key, and offer value",
        "`context_set_from_projection_parts(needs, claims, owner)` carries needs",
        "builds same-index owned offers from the claims",
        "`projection_route_evidence(fact_id, effective_tag, route_tag,",
        "returns `ProjectionRouteEvidence`",
        "with exactly those same field values",
        "not route selection",
        "`selected_route_evidence(fact_id, effective_tag, stamp)`",
        "selected route's proof-relevant `FactRouteStamp`",
        "evidence route tag is that same",
        "projector info/storage requirement come from the",
        "does not prove route-table search",
        "`version_replay_rebuild_shape_allowed(version_replay_rebuild, needs, offers,",
        "accepts if and only if the projection is ordinary",
        "no standing needs, offers, or time wakes",
        "`version_replay_rebuild_shape_status(version_replay_rebuild, needs, offers,",
        "returns accepted or standing-output exactly from that predicate",
        "`version_replay_rebuild_shape_status_allows_projection(status)` accepts",
        "`VERSION_REPLAY_REBUILD_SHAPE_ACCEPTED`",
        "Refactored but not yet proved",
        "`ProjectionDispatcher::dispatch_projection`",
        "`RoutedProjection`",
        "`ProjectionRouteEvidence`",
        "same route selection",
        "calls the projector",
        "field-stamping and selected-stamp helpers are verified",
        "route-table search/function-call and",
        "`PreparedProjection` correspondence",
        "Not proven yet for offer finalization",
        "Not proven yet for owner enforcement",
        "Not proven yet for version replay rebuild admission",
        "`validate_version_replay_rebuild_projection_shape`",
        "exported theorem tying",
        "`enforce_owner_is_self` `Result` wrapper diagnostic rejection",
        "Not proven here today: every exported `theorem_*` runtime/core property.",
        "First stubs to replace: the near-term core glue stubs",
        "First core proof milestone: remove `external_body` from the core theorem",
        "Punted composition theorem stubs.",
        "Near-term core theorem stubs.",
        "Foundational trusted stubs.",
        "Spec helpers and witness structs are vocabulary.",
        "do not retire a theorem",
        "correspondence theorem ties them to production",
        "SpecContextOfferClaim",
        "SpecFact",
        "SpecFactRoute",
        "SpecProjectionCommit",
        "offer_claim_finalizes_to_projected_owner",
        "projection_context_records_offer_provenance",
        "project_fact_dispatches_owner_route",
        "projected_table_writes_are_project_fact_only",
        "theorem_projection_context_sound",
        "theorem_projection_context_records_offer_provenance",
        "theorem_matched_offer_loads_owner_fact",
        "theorem_matcher_preserves_role_scope_selector",
        "theorem_project_fact_dispatches_owner_route",
        "theorem_projected_table_writes_are_project_fact_only",
        "theorem_context_replacement_preserves_owner_boundaries",
        "theorem_atomic_projection_commit_sound",
        "theorem_projection_output_owner_bearing_effects_are_self",
        "theorem_purges_are_self_only",
        "theorem_offer_claim_finalizes_to_projected_owner",
        "theorem_projection_context_lacks_payload_for_need",
        "theorem_parked_output_for_missing_need",
        "theorem_ed25519_verify_binds",
    ];
    let missing = required
        .into_iter()
        .filter(|needle| !text.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "src/core/proofs.rs is missing explicit proof-boundary structure:\n{}",
        missing.join("\n")
    );
}

#[test]
fn proof_rules_reject_model_view_only_progress() {
    let plan = verus_plan();
    let required = [
        "Proof progress means Cargo-verus proof over production Rust code that normal",
        "builds execute.",
        "Model/view proofs are not proof progress, even with a correspondence story.",
        "proving a theorem only over `Spec*` values does not retire",
        "advance a stage",
        "does not support a threat-model",
        "lose\n`external_body` only when Cargo-verus verifies the production Rust helper",
    ];
    let missing = required
        .into_iter()
        .filter(|needle| !plan.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "{VERUS_PLAN_PATH} is missing production-code proof rules:\n{}",
        missing.join("\n")
    );

    let text = core_proofs();
    assert!(
        text.contains("correspondence theorem ties them to production"),
        "src/core/proofs.rs must reject standalone model/view proof credit"
    );
}

#[test]
fn verus_plan_is_single_core_first_source() {
    let plan = verus_plan();
    let required = [
        "single Verus proof plan",
        "## Execution Plan",
        "src/core/project_fact.rs::project_one",
        "load_one_projection_input",
        "evaluate_loaded_projection_input",
        "prepare_projection",
        "dispatcher.dispatch_projection(&fact, &pending_inputs)",
        "enforce_owner_is_self(&fact, &output)",
        "ProjectionOutput::context_set(fact.id)",
        "commit_projection_effects",
        "publish_retained_projection_state_in_tx",
        "wake_projection_work_from_new_context_in_tx",
        "### Stage 1: Theorem Surface And Debt Ledger",
        "### Stage 2: Local Core Facts Already Exposed By The Code",
        "### Stage 3: Routed Projection Evidence",
        "### Stage 4: Projection DB Write Boundary",
        "### Stage 5: Projected Versus Intent Row Authority",
        "### Stage 6: Proven Context Loading",
        "### Stage 7: Core Proof Feasibility Pass",
        "### Stage 8: Query-Visible Source Lockdown",
        "### Stage 9: Route-Local Projector Contracts",
        "### Stage 10: First Real Projector Foothold",
        "### Stage 11: Compose Threat-Model Invariants",
        "Concrete work:",
        "Win:",
        "What it means:",
        "Success criteria:",
        "keep `src/core/proofs.rs` as the only place where core theorem",
        "prove the small core helpers over the production Rust code",
        "`ContextOfferClaim::into_offer` must",
        "not merely mirrored by a separate model function",
        "Model/view proofs are not proof progress, even with a correspondence story.",
        "Current production-code foothold:",
        "returned `ContextOffer.owner` equals the",
        "owner argument for one claim",
        "offer value are copied unchanged",
        "For a slice of claims, Cargo-verus proves",
        "the same length",
        "owner, role, scope",
        "start key, end key, and value preservation",
        "every returned offer",
        "version replay rebuild shape decision accepts exactly ordinary projections",
        "version replay rebuild projections",
        "no standing needs, offers, or time wakes",
        "production status helper returns accepted or",
        "standing-output exactly from that predicate",
        "allow helper accepts",
        "only the accepted status",
        "`projection_output_owner_status(output, fact_id)` applies that same verified",
        "`validate_version_replay_rebuild_projection_shape` `Result` wrapper",
        "`ProjectionOutput::context_set` normalization step",
        "keep leaf projectors on the simple `Projector::project` API",
        "`ProjectionDispatcher` selects",
        "returns a `RoutedProjection`",
        "plain\n`ProjectionOutput` plus router-stamped `ProjectionRouteEvidence`",
        "Terminology in this stage:",
        "`ProjectionDispatcher`: the production entry point used by `project_fact`",
        "`FactRoute`: one registry row from a fact tag to the projector function",
        "effective tag: the semantic fact tag after envelope decoding",
        "route tag: the registered `FactRoute.tag` selected for the effective tag",
        "`RoutedProjection`: the `ProjectionOutput` returned by the leaf projector",
        "Leaf projectors do not construct this value.",
        "`ProjectionRouteEvidence`: the route evidence carried with a",
        "`projector_info`: stable human-readable projector identity",
        "`storage_requirement`: the storage-version guard the selected route requires",
        "Carry that route evidence through",
        "The proof identity is",
        "the stable route tag/projector-info pair",
        "`ProjectionDispatcher::dispatch_projection`",
        "`RouterProjector` implements that dispatcher",
        "`ProjectionRouteEvidence { fact_id, effective_tag, route_tag,",
        "`projection_route_evidence(fact_id, effective_tag, route_tag, projector_info,",
        "returns route evidence with exactly those same field",
        "`selected_route_evidence(fact_id, effective_tag, stamp)`",
        "selected route's proof-relevant `FactRouteStamp`",
        "This is selected-route\nmetadata proof, not the full route theorem",
        "Leaf projectors still return plain `ProjectionOutput`",
        "Cargo-verus",
        "still needs to prove\nthe route-table search",
        "selected projector function call",
        "Route-search discovery",
        "`FactRoute` while it contains the projector function pointer",
        "Cargo-verus does\nnot support function pointer types as a proof target",
        "The proof-relevant route\nidentity is `FactRouteStamp`",
        "limit database write access before relying on offers as proof",
        "`ProjectionWriteTx` is constructible only inside",
        "`project_fact.rs::commit_projection_effects`; `IntentWriteTx`",
        "`ProjectionOutput` carries `Vec<ProjectedRowMutation>`",
        "`RuntimeEffects.row_mutations` carries\n`Vec<IntentRowMutation>`",
        "projection\nvalidation rejects non-empty intent row mutations",
        "`RuntimeDescription`\nnow carries separate `projected_row_mutation_tables` and",
        "`intent_row_mutation_tables` lists",
        "`bootstrap_connection_attempt_rows` as intent-owned",
        "inventory every user-facing query module",
        "may read projected tables",
        "intake, pending queues",
        "`ProjectionContext::attested_offer_for`",
        "`ProjectionContext::matched_attested_offers_for`",
        "validity proof record is the stored offer",
        "not a separate proof row",
        "Do not expose a raw `Fact` as a",
        "projector authority surface",
        "matched attested routed\noffers grouped or filtered by accepted offer contracts",
        "`ProvenOffer` records by producer theorem application",
        "needs emitted for scheduling/liveness",
        "accepted proven offer contracts used for authority/proofs",
        "emitted proven offer contracts produced for other projectors",
        "An accepted offer contract names the offer kind",
        "mandatory producer route",
        "negative/revocation condition",
        "An emitted offer contract names the offer kind",
        "predicate version",
        "Producer proofs establish",
        "emitted offer contracts; consumer proofs cite accepted offer contracts",
        "should not inspect unrelated offers",
        "silently upgrade a",
        "wakeup match into authority",
        "or decode producer-owned historical fact formats.",
        "deliberately precedes query rewiring:",
        "loading is core input plumbing",
        "not a payload fact",
        "Do not expose a raw `Fact` as a projector authority",
        "projector matching is a liveness guarantee, not an invariant",
        "authority comes from a proven",
        "offer emitted by a known producer route",
        "whose projector decoded/adapted",
        "do not make every consumer decode raw",
        "producer fact versions",
        "Historical compatibility stays producer-owned.",
        "several old facts together correspond to one",
        "producer projector/family owns that join",
        "Other projectors see",
        "only that current proven offer",
        "producer proof walkthroughs show",
        "multi-fact compatibility joins",
        "walkthroughs identify the emitted offer contracts",
        "accepted offer contract used by the consumer",
        "then check the proven offer",
        "matched unattested offer being visible for wakeup but rejected by attested\naccessors",
        "matched attested-but-unproved offer rejected by\n`ProvenOffer` construction",
        "revocation-context-completeness theorem",
        "projection_context_records_offer_provenance",
        "`wake_context_matches_in_tx` must record",
        "matches whose offer owner is the fact named by the matched offer",
        "match is sufficient for wakeup",
        "matcher role/scope/selector semantics are\nliveness",
        "actual call graph",
        "every `*_in_tx` helper shares",
        "after the minimum refactor in stages 3-6",
        "immediately try to",
        "remove `#[verifier::external_body]` from the core runtime theorems",
        "we learn early how hard the Verus proof is over the real core code",
        "before query lockdown or projector theorem work",
        "no core theorem about route dispatch, offer finalization",
        "threat-model authority proofs cite proven",
        "producer projector theorems",
        "consumer offer-boundary checks",
        "`replace_context_for_owner_in_tx` deletes and",
        "inventory every user-facing query module",
        "typed read",
        "Raw `ReadDb` access may expose diagnostics",
        "may read projected tables",
        "intake, pending queues",
        "route-local projector theorem stubs only after",
        "Each stub names one route, one",
        "revocation-sensitive stubs name the completeness theorem",
        "prove `auth::signature` first",
        "work through the threat-model checklist in proof dependency",
        "one top-level theorem",
        "transition-effect theorems",
        "## Proof Simplifications",
        "Projector matching is a liveness guarantee, not an invariant guarantee.",
        "Authority-bearing context means proven stable offers",
        "offer_for(...)",
        "matched_offers_for(...)",
        "Producers decode/authenticate/adapt their",
        "Consumers check the",
        "Offers are the cross-projector authority surface.",
        "requires joining several old facts",
        "emits the current offer it wants other projectors to see",
        "## Proof Discoveries",
        "avoiding cascades forces direct support",
        "query-visible authority",
        "carry direct references",
        "every revocation-sensitive offer",
        "Hidden transitive",
        "old projected row is not enough",
        "same purge trigger id",
        "common wakeup frontier",
        "query-time proven-offer rechecking",
        "Emitted offer contracts are the producer side",
        "name every authority-bearing offer kind it can emit",
        "same projector should also name its emitted offer contracts",
        "Core proves provenance and write authority:",
        "Avoid hash injectivity and authoring iff theorems",
        "BLAKE3 collision resistance is a named foundational assumption",
        "Prefer only-if safety theorems",
        "Must-purge, must-retire, and must-suppress",
        "Query lockdown is downstream of proven context loading.",
        "src/core/proofs.rs",
        "src/protocol/<scope>/<fact_family>/proofs.rs",
        "Production implementation files may carry small Verus contracts",
        "Cargo-verus verifies the\nproduction crate path",
        "standalone proof modules",
        "projected_owner_matches(owner, fact_id) bytewise accepts if and only if owner == fact_id",
        "projected_purge_owners_are_self(purged, fact_id) accepts if and only if every purged id is fact_id",
        "projected_need_owners_are_self(needs, fact_id) accepts if and only if every need owner is fact_id",
        "projected_time_wake_owners_are_self(wakes, fact_id) accepts if and only if every wake owner is fact_id",
        "projected_output_owners_are_self(purged, needs, wakes, fact_id) accepts if and only if all three owner groups are fact_id",
        "projected_owner_status(purged, needs, wakes, fact_id) returns accepted/foreign-purge/foreign-need/foreign-wake exactly from those predicates",
        "owner_status_allows_projection(status) accepts if and only if status is OWNER_CHECK_ACCEPTED",
        "projection_output_owner_status(output, fact_id) returns accepted/foreign-purge/foreign-need/foreign-wake exactly from the output's purges, needs, and time wakes",
        "ContextOfferClaim::into_offer(claim, owner).owner == owner",
        "ContextOfferClaim::into_offer(claim, owner) preserves role/scope/start/end/value",
        "owned_offers_from_claims(claims, owner).len == claims.len",
        "forall returned offer: offer.owner == owner",
        "forall returned offer: offer.role/scope/start/end/value match the same-index claim",
        "context_set_from_projection_parts(needs, claims, owner) preserves needs",
        "context_set_from_projection_parts(needs, claims, owner) builds same-index owned offers",
        "projection_route_evidence(fact_id, effective_tag, route_tag, projector_info, storage_requirement) preserves every route evidence field",
        "selected_route_evidence(fact_id, effective_tag, stamp) preserves selected route stamp metadata and gives route_tag == effective_tag when stamp.tag == effective_tag",
        "version_replay_rebuild_shape_allowed(version_replay_rebuild, needs, offers, wakes) accepts if and only if ordinary projection or empty version replay rebuild output",
        "version_replay_rebuild_shape_status(version_replay_rebuild, needs, offers, wakes) returns accepted or standing-output exactly from that predicate",
        "version_replay_rebuild_shape_status_allows_projection(status) accepts if and only if status is VERSION_REPLAY_REBUILD_SHAPE_ACCEPTED",
        "matched_context_owner_matches_payload(matched) accepts if and only if matched.routed_offer.offer.owner == matched.payload.id",
        "routed_offer_owner_matches_producer(routed_offer) accepts if and only if routed_offer.offer.owner == routed_offer.producer_route.fact_id",
        "matched_context_has_routed_provenance(matched) accepts if and only if matched.routed_offer.offer.owner == matched.payload.id and matched.routed_offer.offer.owner == matched.routed_offer.producer_route.fact_id",
        "RoutedOffer::owner_matches_producer accepts if and only if routed_offer.offer.owner == routed_offer.producer_route.fact_id",
        "MatchedContext::has_routed_provenance accepts if and only if matched.routed_offer.offer.owner == matched.payload.id and matched.routed_offer.offer.owner == matched.routed_offer.producer_route.fact_id",
        "`MatchedContext::with_route` rejects mismatched owner/payload/route fixtures at\nruntime",
        "the SQL pending-context loader asks the active `ProjectionDispatcher`\nfor producer route evidence",
        "The production `attested_offer_for` and\n`matched_attested_offers_for` accessors filter on that same local predicate.",
        "`pending_projection_input_context_for_owner` and the SQL loader construct every",
        "assume_specification` for the derived `ContextOfferClaim::clone`",
        "clone preserves the whole claim",
        "remaining owner-checking gap",
        "full-output status bridge",
        "remaining version replay rebuild admission gap",
        "standing-output decision",
        "status classification",
        "accept-status decision",
        "`validate_version_replay_rebuild_projection_shape` `Result` wrapper",
        "remaining route-dispatch gap",
        "route-evidence field stamping",
        "selected-stamp evidence construction",
        "route stamp for the effective tag",
        "called that selected\nprojector function pointer",
        "`enforce_owner_is_self` `Result` wrapper diagnostic rejection",
        "projection_context_records_offer_provenance(ctx, graph)",
        "matched_offer_loads_owner_fact(matched)",
        "matcher_preserves_role_scope_selector(need, matched)",
        "project_fact_dispatches_owner_route(fact, route)",
        "projected_table_writes_are_project_fact_only(before, after)",
        "offer_claim_finalizes_to_projected_owner(claim, offer, current_fact_id)",
        "theorem_ed25519_verify_binds(evidence)",
        "Projector row builders return ProjectedRowMutation.",
        "ProjectionWriteTx is constructible only by project_fact.",
        "IntentWriteTx is constructible only by intent handling.",
        "Authority-influencing reads use AuthorityReadDb/proven accessors",
        "Keep `project_fact.rs` readable as load, prepare, commit",
        "blanket projector-validity axiom",
        "No checklist item may be checked while it depends on an unproved core theorem",
    ];
    let missing = required
        .into_iter()
        .filter(|needle| !plan.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "{VERUS_PLAN_PATH} is missing single-source core-first terms:\n{}",
        missing.join("\n")
    );
}

#[test]
fn verus_plan_names_first_projector_foothold_and_threat_checklist() {
    let plan = verus_plan();
    let required = [
        "## First Projector Foothold",
        "After the core proof spine is complete, start projector coverage with",
        "stored proven signature_proof offer O",
        "F was routed through auth::signature::SignatureProjector",
        "O.selector == (target_fact_id, signer_public_key)",
        "It does not prove membership, admin,",
        "## Proof Order",
        "Complete the core proof spine.",
        "Prove `auth::signature` as the first projector proof foothold.",
        "## Threat-Model Checklist",
        "TM-M1 root workspace and auth DAG.",
        "TM-C2 local private material is not syncable.",
        "TM-I1 content authorship is signer-bound.",
        "TM-D6 key healing cannot resurrect removed roots.",
        "Every proof change must include a walkthrough",
        "Commit completed work on the same worktree branch before handoff or review.",
    ];
    let missing = required
        .into_iter()
        .filter(|needle| !plan.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "{VERUS_PLAN_PATH} is missing proof-order or checklist terms:\n{}",
        missing.join("\n")
    );
}

#[test]
fn verus_plan_rejects_retired_or_split_plan_terms() {
    let plan = verus_plan();
    let forbidden = [
        "docs/todo-add-verus-proofs.md",
        "## Assumed Core Theorems",
        "Core proof bodies are out of scope for this phase.",
        "projectors may call assume(...) directly",
        "model-level Verus theorem",
        "model-level workspace proof",
        "standalone Verus views",
        "verified-view lemmas",
        "finalized_offer_from_claim_view",
        "owner_checked_projection_output_view",
        "purge_checked_projection_output_view",
        "parked_output_for_missing_need_view",
        "theorem_no_materialized_output(output)",
        "all offers must be proven before they can be emitted",
        "context offers are authoritative",
        "generic row mutations are sufficient proof",
        "- [x] TM-M1",
        "- [x] TM-C2",
        "src/core/proof.rs",
        "src/protocol/<scope>/<fact_family>/proof.rs",
        "pub mod proof;",
        "feature = \"verus-proof\"",
    ];
    let present = forbidden
        .into_iter()
        .filter(|needle| plan.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        present.is_empty(),
        "{VERUS_PLAN_PATH} contains retired or split-plan terms:\n{}",
        present.join("\n")
    );
}

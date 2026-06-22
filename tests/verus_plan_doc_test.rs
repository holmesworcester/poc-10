use std::fs;
use std::path::Path;
use std::process::Command;

const VERUS_PLAN_PATH: &str = "docs/verus_proof_strategy.md";
const DEFAULT_VERUS_PATH: &str = "/home/holmes/verus-install/verus-x86-linux/verus";

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
fn protocol_proof_modules_do_not_claim_model_only_theorems() {
    let proof_files = [
        "src/protocol/auth/signature/proofs.rs",
        "src/protocol/auth/invite_accepted/proofs.rs",
        "src/protocol/auth/workspace/proofs.rs",
    ];
    let required = [
        "No theorem in this file currently claims threat-model coverage.",
        "actual Rust inputs and output",
    ];
    let forbidden = [
        "SpecSignatureFact",
        "SpecSignatureProofOffer",
        "SpecInviteAcceptedFact",
        "SpecWorkspaceAcceptedOffer",
        "SpecWorkspaceFact",
        "SpecWorkspaceMaterializedOutput",
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
        "theorem_matched_payloads_are_offer_owner_facts",
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
        "Proof progress means proof over production Rust code.",
        "verified Rust-code view is acceptable only with an explicit correspondence",
        "Standalone model/view proofs do not count.",
        "proving a theorem only over `Spec*` values does not retire",
        "does not advance a stage",
        "does not support a threat-model",
        "lose\n`external_body` only when the theorem body proves the production Rust helper",
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
        "projector.project(&fact, &pending_inputs)",
        "enforce_owner_is_self(&fact, &output)",
        "ProjectionOutput::context_set(fact.id)",
        "commit_projection_effects",
        "publish_retained_projection_state_in_tx",
        "wake_projection_work_from_new_context_in_tx",
        "### Stage 1: Theorem Surface And Debt Ledger",
        "### Stage 2: Local Core Facts Already Exposed By The Code",
        "### Stage 3: Routed Projection Witness",
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
        "extract the routing decision inside `RouterProjector::project`",
        "Carry that route witness through",
        "proof identity is the stable route tag",
        "limit database write access before relying on offers as proof",
        "`ProjectionWriteTx` is constructible only inside",
        "`project_fact.rs::commit_projection_effects`; `IntentWriteTx`",
        "`ProjectionOutput::row_mutation` should accept a",
        "`ProjectedRowMutation`; intent handlers should emit `IntentRowMutation`",
        "inventory every user-facing query module",
        "may read projected tables",
        "intake, pending queues",
        "`ProjectionContext::proven_offers_for`",
        "`ProjectionContext::matched_proven_offers_for`",
        "validity proof record is the stored offer",
        "not a separate proof row",
        "do not expose a raw `Fact` as a",
        "wrapped in a `ProvenContext` record",
        "collection of matched",
        "`ProvenOffer` records, grouped or filtered by accepted offer contracts",
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
        "projection context loading is core input",
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
        "revocation-context-completeness theorem",
        "projection_context_records_offer_provenance",
        "`wake_context_matches_in_tx` must record",
        "matcher role/scope/selector semantics are liveness",
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
        "Producers decode/authenticate/adapt their",
        "Consumers check the",
        "Offers are the cross-projector authority surface.",
        "requires joining several old facts",
        "emits the current offer it wants other projectors to see",
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
        "projection_context_records_offer_provenance(ctx, graph)",
        "matched_payloads_are_offer_owner_facts(matched)",
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

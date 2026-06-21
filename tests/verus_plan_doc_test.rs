use std::fs;
use std::path::Path;
use std::process::Command;

const VERUS_TODO_PATH: &str = "docs/todo-add-verus-proofs.md";
const VERUS_STRATEGY_PATH: &str = "docs/verus_proof_strategy.md";
const DEFAULT_VERUS_PATH: &str = "/home/holmes/verus-install/verus-x86-linux/verus";

fn verus_plan() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(root.join(VERUS_TODO_PATH)).expect("read Verus TODO doc")
}

fn verus_strategy() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(root.join(VERUS_STRATEGY_PATH)).expect("read Verus strategy doc")
}

fn repo_file(path: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(root.join(path)).unwrap_or_else(|err| panic!("read {path}: {err}"))
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
fn verus_plan_uses_current_fact_layout_and_context_terms() {
    let plan = verus_plan();
    let required = [
        "src/protocol/<scope>/<fact_family>/proof.rs",
        "Proof layout follows the target staged",
        "fact-family roles: decode, authenticate, adapt, project, and effects",
        "src/protocol/<scope>/<verb_object>_proof.rs",
        "src/protocol/connection/request/proof.rs",
        "src/protocol/connection/response/proof.rs",
        "src/protocol/auth/admin/proof.rs",
        "src/protocol/auth/key_wrap_creation/proof.rs",
        "src/protocol/auth/key_wrap_recovery/proof.rs",
        "src/protocol/content/file_slice/proof.rs",
        "`create.rs`, `layout.rs`, and `rows.rs` are transitional implementation or",
        "not target proof homes for new work.",
        "matched payloads are loaded from the offer owner's fact id",
        "offer-owner payload",
        "connection_invite_secret",
        "Core predicates:",
        "Projector proof obligations:",
        "Intent handler proof obligations:",
    ];
    let missing = required
        .into_iter()
        .filter(|needle| !plan.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "{VERUS_TODO_PATH} is missing current-layout proof terms:\n{}",
        missing.join("\n")
    );

    let forbidden = [
        "src/protocol/facts/",
        "src/protocol/intents/",
        "src/core/projectors_proof.rs",
        "src/core/matchers/proof.rs",
        "src/core/projection/proof.rs",
        "src/core/wake_loop/proof.rs",
        "payload_ref",
        "payload refs",
        "row intent",
        "Event Module",
        "event module",
        "event/fact",
        "after signed-fact validation lands",
        "invite-secret role mismatch",
    ];
    let present = forbidden
        .into_iter()
        .filter(|needle| plan.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        present.is_empty(),
        "{VERUS_TODO_PATH} still contains retired proof-plan terms:\n{}",
        present.join("\n")
    );

    let old_terms = plan
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .filter(|term| term.eq_ignore_ascii_case("event") || term.eq_ignore_ascii_case("events"))
        .collect::<Vec<_>>();
    assert!(
        old_terms.is_empty(),
        "{VERUS_TODO_PATH} should use fact terminology, not retired event terms"
    );
}

#[test]
fn verus_plan_names_meaningful_security_proof_targets() {
    let plan = verus_plan();
    let required = [
        "## Proof Target Selection",
        "### Auth Authority DAG",
        "valid_admin_offer(admin_offer, admin_fact, graph)",
        "Cycles of admin facts do not bootstrap authority",
        "### Auth Key Material And Forward Secrecy",
        "Deterministic key-wrap identity excludes request entropy",
        "secret_coverage",
        "Local private material and local secret facts are never sync-shareable",
        "### Connection Handshake",
        "receipt alone grants no request, response, or child-fact authority",
        "public handshake hash matches transcript",
        "### Content Admission, Deletion, And Retention",
        "Deletion is target-owned",
        "content_retention_floor",
        "### Encrypted File Slice",
        "BAO slice proof verifies against the parent file descriptor root hash",
        "Connection `frame_file_slice` remains a carrier proof",
        "### Sync Shareability And Dependency Closure",
        "Sync facts describe convergence, not domain validity",
        "`share_fact_with_sync` is emitted only after the owner projector's authority",
        "validated non-local dependencies",
        "Commit the completed work on that same worktree branch before handoff or",
    ];
    let missing = required
        .into_iter()
        .filter(|needle| !plan.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "{VERUS_TODO_PATH} is missing meaningful security proof targets:\n{}",
        missing.join("\n")
    );
}

#[test]
fn verus_strategy_centralizes_assumed_core_theorems() {
    let strategy = verus_strategy();
    let required = [
        "Core proof bodies are out of scope for this phase.",
        "src/core/proofs.rs",
        "proof code lives only in `proofs.rs` files",
        "Do not add normal Rust `theorem_*` shims or",
        "certificate structs in `proofs.rs`",
        "whole-codebase proof of every threat-model invariant",
        "parallel Verus model",
        "actual core Rust behavior",
        "Verus-only proof code is gated with `cfg(verus_keep_ghost)`",
        "protocol-neutral plumbing properties",
        "Projector proof modules may import theorem functions from this module.",
        "must not call `assume(...)` directly",
        "projection_context_sound(ctx, graph)",
        "matched_payloads_are_offer_owner_facts(matched)",
        "matcher_preserves_role_scope_selector(need, matched)",
        "projection_context_lacks_payload_for_need(ctx, need)",
        "parked_output_for_missing_need(output, need)",
        "context_replacement_preserves_owner_boundaries(before, after, owner)",
        "purges_are_self_only(output, current_fact_id)",
        "projection_output_owners_are_self(output, current_fact_id)",
        "atomic_projection_commit_sound(before, output, after)",
        "#[verifier::external_body]",
        "Every trusted theorem stub must have a name beginning with `theorem_`",
        "Do not add a theorem that asserts",
        "for an arbitrary output",
        "ProjectionContext::payload_for(&need)",
        "ProjectionOutput::new().need(need)",
        "core theorems establish plumbing soundness, and projector theorems",
        "establish protocol meaning",
        "theorem_ed25519_verify_binds(evidence)",
        "must not state protocol",
        "Proof modules must verify with Verus before a checklist item can move out of",
        "The security bar for threat-model coverage is the only-if direction over the",
        "Full iff theorems are useful when the spec can characterize the exact Rust",
        "Model-only projector relations are not proof work for this repo.",
        "Proofs must target actual Rust code.",
        "The top-level projector theorem must",
        "quantify over real Rust inputs and outputs",
        "Standalone `Spec*` duplicates are forbidden as proof targets.",
        "Disconnected model-level slices are not accepted",
        "materialized protected",
        "output implies required authority evidence",
        "Use iff only for exact projector characterization.",
        "Constructor lemmas are not checklist coverage by themselves.",
        "Every proof change must include a walkthrough before handoff.",
        "what the theorem really proves, and the remaining gaps against",
        "receipt remains only a receipt",
        "Replacing a trusted core",
        "Do not rely on static source analysis as proof.",
        "Do not cheat by placing protocol conclusions in core.",
        "Foundational axioms may assume SQLite transactions",
        "## Threat Model Checklist",
        "TM-M1 root workspace slice",
        "TM-D6",
    ];
    let missing = required
        .into_iter()
        .filter(|needle| !strategy.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "{VERUS_STRATEGY_PATH} is missing assumed-core theorem strategy terms:\n{}",
        missing.join("\n")
    );

    let forbidden = [
        "Core assumptions prove admin validity",
        "Core assumptions prove deletion authority",
        "projectors may call assume(...) directly",
        "They may remain as regression checks over",
        "Model-only projector relations are staging artifacts.",
        "model-level Verus theorem",
        "model-level workspace proof",
        "model-level workspace sync-share",
        "Model-level Verus slices are noted",
        "theorem_no_materialized_output(output)",
        "- [x] TM-M1 root workspace slice",
        "- [x] TM-C2 workspace local-bootstrap slice",
    ];
    let present = forbidden
        .into_iter()
        .filter(|needle| strategy.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        present.is_empty(),
        "{VERUS_STRATEGY_PATH} contains forbidden proof-strategy claims:\n{}",
        present.join("\n")
    );
}

use std::fs;
use std::path::Path;

const VERUS_TODO_PATH: &str = "docs/todo-add-verus-proofs.md";
const VERUS_STRATEGY_PATH: &str = "docs/verus_proof_strategy.md";

fn verus_plan() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(root.join(VERUS_TODO_PATH)).expect("read Verus TODO doc")
}

fn verus_strategy() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(root.join(VERUS_STRATEGY_PATH)).expect("read Verus strategy doc")
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
        "src/core/assumed_proof.rs",
        "protocol-neutral plumbing properties",
        "Projector proof modules may import theorem functions from this module.",
        "must not call `assume(...)` directly",
        "projection_context_sound(ctx, graph)",
        "matched_payloads_are_offer_owner_facts(ctx, graph)",
        "matcher_preserves_role_scope_selector(need, matched)",
        "context_replacement_preserves_owner_boundaries(before, after, owner)",
        "purges_are_self_only(output, current_fact_id)",
        "atomic_projection_commit_sound(before, output, after)",
        "#[verifier::external_body]",
        "Every trusted theorem stub must have a name beginning with `theorem_`",
        "core theorems establish plumbing soundness, and projector theorems",
        "establish protocol meaning",
        "receipt remains only a receipt",
        "Replacing a trusted core",
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

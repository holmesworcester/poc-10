use std::fs;
use std::path::Path;

const THREAT_MODEL_PATH: &str = "THREAT_MODEL.md";

fn threat_model() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(root.join(THREAT_MODEL_PATH)).expect("read threat model")
}

#[test]
fn threat_model_keeps_invariant_centric_shape_and_sources() {
    let model = threat_model();
    let required = [
        "# Threat Model",
        "invariant-centric threat model",
        "## Usage Scenario",
        "## Definitions",
        "## Adversaries",
        "## Security Invariants",
        "## Known Weaknesses",
        "## Review Questions",
        "https://github.com/defuse/ictm",
        "https://github.com/TryQuiet/quiet/wiki/Threat-Model",
        "docs/todo-add-verus-proofs.md",
    ];

    let missing = required
        .into_iter()
        .filter(|needle| !model.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "{THREAT_MODEL_PATH} is missing invariant-centric threat model structure:\n{}",
        missing.join("\n")
    );
}

#[test]
fn threat_model_names_required_actor_classes_and_core_objectives() {
    let model = threat_model();
    let required = [
        "OWNER",
        "MEMBER",
        "NON-MEMBER",
        "DRAGNET",
        "NETWORK ACTIVE ATTACKER",
        "SERVER",
        "MALWARE",
        "POST-DELETE DEVICE",
        "UPDATE PROVIDER",
        "ACTIVE CARRIER",
        "DELETION COLLUSION",
        "### Membership And Authority",
        "### Confidentiality",
        "### Impersonation And Integrity",
        "### Deletion And Post-Deletion Forward Secrecy",
    ];

    let missing = required
        .into_iter()
        .filter(|needle| !model.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "{THREAT_MODEL_PATH} is missing required actors or objectives:\n{}",
        missing.join("\n")
    );
}

#[test]
fn threat_model_maps_invariants_to_verus_proof_surfaces() {
    let model = threat_model();
    let required = [
        "TM-M1: Non-members cannot mint membership",
        "TM-C2: Local private material is not syncable",
        "TM-I1: Content authorship is signer-bound",
        "TM-D1: Deletion is target-owned",
        "TM-D5: Server plus post-delete device compromise cannot decrypt deleted",
        "## Proof Mapping",
        "Auth authority DAG predicates",
        "Connection handshake and receipt predicates",
        "Auth key-material predicates and handlers",
        "Content admission predicates",
        "Sync shareability and connection sendability",
        "content deletion, auth root retirement, retained-node coverage",
        "Every materialized row, emitted authority offer, emitted sync-share contribution",
    ];

    let missing = required
        .into_iter()
        .filter(|needle| !model.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "{THREAT_MODEL_PATH} is missing proof-facing invariant mapping:\n{}",
        missing.join("\n")
    );
}

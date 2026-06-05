use std::fs;
use std::path::Path;

fn source_text(path: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|err| panic!("read {path}: {err}"))
}

#[test]
fn connection_verus_proof_documents_bracket_and_counterexamples() {
    let note = source_text("docs/research/verus-connection-proof.md");
    let proof = source_text("src/protocol/connection/proof.rs");
    let runner = source_text("scripts/run_verus.sh");

    for required in [
        "never invited for that workspace",
        "endpoint membership",
        "scoped bootstrap invite",
        "Bootstrap without membership",
        "Server-forged range or need-id traffic",
        "Unchecked explicit send intents",
        "sync-selected sends",
        "scripts/run_verus.sh",
    ] {
        assert!(
            note.contains(required),
            "Verus connection proof note is missing bracket detail {required:?}"
        );
    }

    for required in [
        "never_invited_remote_cannot_receive_workspace_message_from_sync",
        "scoped_bootstrap_invite_is_intentional_memberless_visibility",
        "connection_not_involving_local_endpoint_authorizes_no_workspace",
        "sync_visibility_selects_workspace_message",
        "scoped_bootstrap_invites: Set<(Id, Id, Id)>",
    ] {
        assert!(
            proof.contains(required),
            "connection Verus proof is missing theorem/model term {required:?}"
        );
    }

    assert!(
        runner.contains("src/protocol/connection/proof.rs"),
        "Verus runner should verify the connection proof"
    );
}

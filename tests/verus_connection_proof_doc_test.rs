use std::fs;
use std::path::Path;

fn source_text(path: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|err| panic!("read {path}: {err}"))
}

#[test]
fn connection_verus_proof_documents_bracket_and_counterexamples() {
    let note = source_text("docs/research/verus-connection-proof.md");
    let root_proof = source_text("src/protocol/proof.rs");
    let request_proof = source_text("src/protocol/connection/request/proof.rs");
    let connection_proof = source_text("src/protocol/connection/connection/proof.rs");
    let sync_proof = source_text("src/protocol/sync/shared_fact/proof.rs");
    let runner = source_text("scripts/run_verus.sh");

    for required in [
        "never invited for that workspace",
        "endpoint membership",
        "scoped bootstrap invite",
        "connection/request/proof.rs",
        "connection/connection/proof.rs",
        "sync/shared_fact/proof.rs",
        "protocol/proof.rs",
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
        "scoped_bootstrap_invite_is_intentional_memberless_sync_visibility",
        "malformed_local_orientation_cannot_receive_workspace_message_from_sync",
        "mod connection_request_proof",
        "connection_connection_proof::",
        "sync_shared_fact_proof::",
    ] {
        assert!(
            root_proof.contains(required),
            "protocol root Verus proof is missing composition term {required:?}"
        );
    }

    for required in [
        "valid_connection_request_authority_for_workspace",
        "never_invited_has_no_connection_request_authority",
        "scoped_bootstrap_invite_grants_request_workspace_authority",
    ] {
        assert!(
            request_proof.contains(required),
            "request Verus proof is missing local authority term {required:?}"
        );
    }

    for required in [
        "ConnectionRow",
        "remote_endpoint",
        "connection_authorizes_workspace",
        "never_invited_connection_authorizes_no_workspace",
    ] {
        assert!(
            connection_proof.contains(required),
            "connection Verus proof is missing row certificate term {required:?}"
        );
    }

    for required in [
        "WorkspaceMessage",
        "workspace_message_is_shareable",
        "sync_visibility_selects_workspace_message",
        "not_authorized_connection_cannot_select_workspace_message",
    ] {
        assert!(
            sync_proof.contains(required),
            "sync Verus proof is missing visibility term {required:?}"
        );
    }

    assert!(
        runner.contains("src/protocol/proof.rs"),
        "Verus runner should verify the protocol composition proof"
    );
}

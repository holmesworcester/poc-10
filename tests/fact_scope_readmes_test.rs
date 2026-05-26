use std::fs;
use std::path::Path;

#[test]
fn fact_scope_readmes_document_registered_fact_modules_and_intents() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let scopes = [
        ScopeDocs {
            scope: "auth",
            fact_modules: &[
                "admin",
                "device_invite",
                "endpoint",
                "endpoint_shared",
                "invite",
                "invite_accepted",
                "invite_server",
                "key_request",
                "key_wrap",
                "local_history_node_secret",
                "local_key_secret",
                "local_recipient_key",
                "local_secret_retirement",
                "local_signer_secret",
                "recipient_key",
                "removal_frontier",
                "user",
                "user_invite",
                "workspace",
            ],
            handlers: &["create_key_wrap", "unwrap_key_wrap"],
        },
        ScopeDocs {
            scope: "content",
            fact_modules: &[
                "file",
                "file_deletion",
                "file_slice",
                "message",
                "message_deletion",
                "reaction",
                "retention_policy",
            ],
            handlers: &["no runtime intent handlers"],
        },
        ScopeDocs {
            scope: "connection",
            fact_modules: &[
                "bootstrap_request",
                "bootstrap_response",
                "close",
                "ephemeral_secret",
                "fact_receipt",
                "frame_bundle",
                "frame_file_slice",
                "frame_small",
                "request",
                "response",
            ],
            handlers: &[
                "create_connection_response",
                "receive_network_frame",
                "send_bootstrap_connection_request",
                "send_facts_on_connection",
                "send_network_frame",
            ],
        },
        ScopeDocs {
            scope: "sync",
            fact_modules: &[
                "cascade_test_fact",
                "compare",
                "encrypted_root",
                "have_id",
                "key_wrap_available",
                "need_id",
                "range_request",
                "shared_fact",
            ],
            handlers: &[
                "seed_connection_sync",
                "send_needed_fact_id",
                "send_requested_fact",
                "send_sync_compare_response",
                "share_fact_with_sync",
            ],
        },
    ];

    for scope in scopes {
        let readme_path = root
            .join("src")
            .join("protocol")
            .join(scope.scope)
            .join("README.md");
        let readme = fs::read_to_string(&readme_path)
            .unwrap_or_else(|err| panic!("read {}: {err}", readme_path.display()));
        assert!(
            readme.contains("Interface To Core"),
            "{} README should document core interface",
            scope.scope
        );
        assert!(
            readme.contains("Invariants And Responsibility"),
            "{} README should document invariants",
            scope.scope
        );
        assert!(
            readme.contains("Example Fact Graph"),
            "{} README should include an example graph",
            scope.scope
        );
        assert!(
            readme.contains("```text"),
            "{} README should include plaintext fact examples",
            scope.scope
        );
        for module in scope.fact_modules {
            assert!(
                readme.contains(module),
                "{} README should document fact module `{module}`",
                scope.scope
            );
        }
        for handler in scope.handlers {
            assert!(
                readme.contains(handler),
                "{} README should document handler `{handler}`",
                scope.scope
            );
        }
    }
}

struct ScopeDocs {
    scope: &'static str,
    fact_modules: &'static [&'static str],
    handlers: &'static [&'static str],
}

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
                "have_id",
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
            readme.contains("Managed Row State"),
            "{} README should document owned row state separately",
            scope.scope
        );
        assert!(
            readme.contains("Cross-Scope Row Reads"),
            "{} README should document direct row reads separately",
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

#[test]
fn connection_readme_separates_sealed_transport_from_fact_dependencies() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme_path = root.join("src/protocol/connection/README.md");
    let readme = fs::read_to_string(&readme_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", readme_path.display()));

    for required in [
        "sealed bootstrap request bytes (not a fact)",
        "sealed bootstrap response bytes (not a fact)",
        "inbound responder transport observation",
        "inbound responder dependency graph",
        "needs connection_fact_receipt(request)",
        "create_connection_response(request, invite_secret, receipt)",
        "The sealed bootstrap request/response bytes are transport observations",
    ] {
        assert!(
            readme.contains(required),
            "connection README should distinguish transport wrappers from dependency graph: missing {required:?}"
        );
    }
}

#[test]
fn readme_core_interface_sections_do_not_name_scope_owned_intent_routes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for scope in ["auth", "content", "sync"] {
        let readme_path = root
            .join("src")
            .join("protocol")
            .join(scope)
            .join("README.md");
        let readme = fs::read_to_string(&readme_path)
            .unwrap_or_else(|err| panic!("read {}: {err}", readme_path.display()));
        let core_interface = section(&readme, "## Interface To Core");
        for intent in ["share_fact_with_sync", "create_key_wrap", "unwrap_key_wrap"] {
            assert!(
                !core_interface.contains(intent),
                "{scope} README should describe {intent} outside Interface To Core"
            );
        }
    }
}

#[test]
fn readme_core_interface_sections_do_not_treat_owned_rows_as_egress() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for scope in ["auth", "content", "connection", "sync"] {
        let readme_path = root
            .join("src")
            .join("protocol")
            .join(scope)
            .join("README.md");
        let readme = fs::read_to_string(&readme_path)
            .unwrap_or_else(|err| panic!("read {}: {err}", readme_path.display()));
        let core_interface = section(&readme, "## Interface To Core");
        for row_phrase in ["row mutations", "typed-table rows", "read models"] {
            assert!(
                !core_interface.contains(row_phrase),
                "{scope} README should describe owned row state outside Interface To Core"
            );
        }
    }
}

#[test]
fn readme_other_scope_interfaces_separate_context_from_other_mechanisms() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for scope in ["auth", "content", "connection", "sync"] {
        let readme_path = root
            .join("src")
            .join("protocol")
            .join(scope)
            .join("README.md");
        let readme = fs::read_to_string(&readme_path)
            .unwrap_or_else(|err| panic!("read {}: {err}", readme_path.display()));
        let other_scopes = section(&readme, "## Interfaces To Other Scopes");
        for heading in ["### Context Interface", "### Other Interfaces"] {
            assert!(
                other_scopes.contains(heading),
                "{scope} README should separate context from other cross-scope mechanisms"
            );
        }
    }
}

#[test]
fn scope_readmes_open_with_what_the_scope_is_used_for() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for scope in ["auth", "content", "connection", "sync"] {
        let readme_path = root
            .join("src")
            .join("protocol")
            .join(scope)
            .join("README.md");
        let readme = fs::read_to_string(&readme_path)
            .unwrap_or_else(|err| panic!("read {}: {err}", readme_path.display()));
        let intro = first_paragraph(&readme);
        assert!(
            intro.contains("We use it to"),
            "{scope} README should open with what the scope is used for"
        );
    }
}

#[test]
fn auth_readme_contains_integrated_key_material_model() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme_path = root.join("src/protocol/auth/README.md");
    let readme = fs::read_to_string(&readme_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", readme_path.display()));
    let normalized = normalize_whitespace(&readme);

    for required in [
        "## Authority And Key Material Model",
        "### Content Key Tree",
        "### Key Wraps",
        "### Proactive Sharing",
        "### Key Requests",
        "### Forward Secrecy And Recipient Rotation",
        "### Disappearing Messages And Purge",
        "### Open Content",
        "Late arrivals do not retroactively change message expiry",
    ] {
        assert!(
            normalized.contains(required),
            "auth README should contain integrated auth/key-material guidance: missing {required:?}"
        );
    }
}

#[test]
fn sync_readme_contains_integrated_projector_owned_negentropy_model() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme_path = root.join("src/protocol/sync/README.md");
    let readme = fs::read_to_string(&readme_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", readme_path.display()));
    let normalized = normalize_whitespace(&readme);

    for required in [
        "## Visibility And Dependency Closure",
        "make shared facts converge between endpoints",
        "other scopes can rely on eventual consistency for admitted shared facts",
        "Sync starts once per established connection with an initial seed compare",
        "continues with live-tail sends for newly indexed facts",
        "where catch-up work remains",
        "uses periodic daemon tick catch-up (`--sync-ms`/`--tick-ms`)",
        "drain queued compare/have/need/fact-send work and due time wakes",
        "fast wall-clock display of fact state in a requested range",
        "requires syncing the range's dependency closure",
        "make a bounded user-visible slice useful without downloading every shared fact in the workspace",
        "latest messages starts from a requested time range",
        "If sync sent only the owner facts in the requested range",
        "projectors would park, leaving the user-visible data incomplete",
        "bounded by the requested view and its validated dependency graph",
        "## Connection Boundary",
        "Sync is scoped by established connections",
        "connection id as the security and transport domain",
        "Sync chooses ids; connection carries bytes",
        "connection request/response rows",
        "auth endpoint membership rows",
        "Dependency closure uses the same connection filter",
        "skip the origin connection that supplied a fact",
        "## Live Tail",
        "Live tail is the latency path after initial connection seeding",
        "records a changed upsert",
        "which established connections may see that owner fact",
        "removes any origin connection recorded by `connection_fact_receipt`",
        "recursively expands the owner through stored `context_have` edges",
        "does not create authority and does not bypass projection",
        "without waiting for another compare round",
        "periodic daemon tick catch-up still repair peers",
        "## Convergence Process",
        "turning projector output into a durable range index",
        "exchanging summaries, exact ids, and the requested fact bytes over established connections",
        "The owner projector admits or partially understands a shared fact",
        "same handler starts the live-tail path",
        "sync sends a `compare` fact that summarizes the visible range",
        "asks connection to send selected fact bytes",
        "Before selected bytes are handed to connection",
        "recursively expands the selected owner ids through stored `context_have` edges",
        "dependencies of dependencies",
        "A peer that receives `have_id` checks whether it already has the named fact",
        "Received bytes enter core as ordinary facts",
        "## Share Contributions",
        "not a command to send bytes immediately",
        "workspace_id owner_fact_id owner_timestamp_ms state: upsert | retract context_have",
        "`owner_timestamp_ms` is copied from the owner fact",
        "places that owner in the range-summary tree",
        "Projectors own this step because only the owning fact family knows",
        "state: upsert | retract",
        "`context_have` is the direct dependency list",
        "Raw `ContextNeed` selectors are not stored in negentropy state",
        "The recursive walk includes each in-range owner",
        "Removal uses the same ownership boundary",
        "Sync facts are the durable messages in the convergence loop",
        "each one moves the loop one step closer to equal range summaries",
        "Process step for comparing one range on one connection",
        "Process step for exact-id advertisement",
        "Process step for exact-id request",
    ] {
        assert!(
            normalized.contains(required),
            "sync README should contain integrated dep-aware negentropy guidance: missing {required:?}"
        );
    }
}

#[test]
fn auth_readme_distinguishes_sync_exact_fact_from_auth_key_wrap_context() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme_path = root.join("src/protocol/auth/README.md");
    let readme = fs::read_to_string(&readme_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", readme_path.display()));
    let normalized = normalize_whitespace(&readme);

    for required in [
        "Auth can consume sync-owned `sync_exact_fact` context",
        "Auth publishes `sync_key_wrap` from accepted concrete `key_wrap` facts",
        "key-wrap availability for auth wraps is an auth offer, not a sync-owned offer",
    ] {
        assert!(
            normalized.contains(required),
            "auth README should distinguish sync-owned exact facts from auth-owned key-wrap context: missing {required:?}"
        );
    }
    assert!(
        !normalized.contains("sync-owned exact-fact or key-wrap availability context"),
        "auth README should not describe key-wrap availability as sync-owned context"
    );
}

fn normalize_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn section<'a>(readme: &'a str, heading: &str) -> &'a str {
    let start = readme
        .find(heading)
        .unwrap_or_else(|| panic!("README is missing heading {heading:?}"));
    let after_heading = &readme[start + heading.len()..];
    if let Some(end) = after_heading.find("\n## ") {
        &after_heading[..end]
    } else {
        after_heading
    }
}

fn first_paragraph(readme: &str) -> &str {
    let after_title = readme
        .split_once("\n\n")
        .map(|(_, rest)| rest)
        .expect("README should have a title and intro paragraph");
    after_title
        .split_once("\n\n")
        .map(|(paragraph, _)| paragraph)
        .unwrap_or(after_title)
}

struct ScopeDocs {
    scope: &'static str,
    fact_modules: &'static [&'static str],
    handlers: &'static [&'static str],
}

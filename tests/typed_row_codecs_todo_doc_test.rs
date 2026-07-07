use std::fs;
use std::path::Path;

fn source_text(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn normalize_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn typed_row_codecs_todo_records_row_layout_cleanup_plan() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let note = source_text(&root.join("docs/todo-typed-row-codecs.md"));
    let normalized = normalize_whitespace(&note);

    for required in [
        "# TODO: Schema-Backed Row Helpers",
        "remove handwritten per-family `rows.rs` byte packing",
        "This TODO is about rows only",
        "READ: fact bytes -> decode -> authenticate -> adapt -> project -> effects",
        "WRITE: command -> author -> encode -> authenticate(self-check) -> admit -> READ",
        "Core may learn row fields from schema declarations",
        "core must not contain hand-written protocol-specific branches",
        "Protocol owns row declarations",
        "Core owns generic row machinery",
        "Projectors own materialization policy",
        "This is correct but too low-level",
        "Replace handwritten `rows.rs` modules with schema-backed generated helpers",
        "`encoded_len`",
        "`encode_key`, `encode_value`, `decode_key`, `decode_value`",
        "Declarative Row Schema",
        "Transitional Row Cursor",
        "Reuse Existing Fact Codecs Where Exact",
        "Convert one representative fixed-width row family first: `connection/bootstrap_request`",
        "Remove the representative handwritten `rows.rs`",
        "Add a guardrail test that flags new per-family `rows.rs` files",
        "Commit the completed work on that same worktree branch before handoff or review",
        "Existing row bytes remain stable for golden fixtures",
        "Decode rejects wrong-length row keys and values",
        "Guardrails prevent new handwritten row packing",
    ] {
        assert!(
            normalized.contains(required),
            "typed row codecs TODO is missing {required:?}"
        );
    }
}

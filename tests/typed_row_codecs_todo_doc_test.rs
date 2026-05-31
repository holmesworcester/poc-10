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
        "# TODO: Typed Row Codecs",
        "Core row mutations store protocol-owned rows as opaque `(table, key, value)` bytes",
        "This is correct but too low-level",
        "Keep core's opaque `TableRow` boundary",
        "`encoded_len`",
        "`encode_value`",
        "`decode_value`",
        "Cursor Helper",
        "Declarative Row Layout Macro",
        "Reuse Existing Fact Codecs Where Exact",
        "Convert one representative fixed-width row family first: `connection/bootstrap_request/rows.rs`",
        "Add a guardrail test that flags direct `value[N..M].copy_from_slice(...)`",
        "Commit the completed work on that same worktree branch before handoff or review",
        "Existing row bytes remain stable for a golden fixture",
        "Decode rejects wrong-length row values",
    ] {
        assert!(
            normalized.contains(required),
            "typed row codecs TODO is missing {required:?}"
        );
    }
}

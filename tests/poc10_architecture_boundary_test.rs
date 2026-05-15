use std::path::{Path, PathBuf};

fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    files
}

fn source_text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn meaningful_manifest_lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with("//")
                && !line.starts_with("//!")
                && !line.starts_with("///")
        })
        .collect()
}

#[test]
fn poc10_success_criteria_are_recorded_in_architecture_doc() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let doc = source_text(&root.join("new_architecture.md"));
    let required = [
        "## Poc-10 Success Criteria",
        "Every non-ignored `poc-8` test passes in `poc-10`",
        "There is no `mod.rs` anywhere in the repository.",
        "There is no per-module `schema.rs`, `codec.rs`, or `cli.rs`",
        "src/core/schema.p8sql",
        "src/event_modules/schema.p8sql",
        "src/handlers/schema.p8sql",
        "### Projector Style",
        "### Intent Handler Style",
        "### Wire And Codec Style",
        "### Transit Frame Style",
        "### Simplicity Guardrails",
    ];

    let missing = required
        .into_iter()
        .filter(|needle| !doc.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "new_architecture.md is missing poc-10 success criteria:\n{}",
        missing.join("\n")
    );
}

#[test]
#[ignore = "poc-10 target guardrail: enable after the module tree is converted to root manifests"]
fn poc10_target_has_no_mod_rs_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let offenders = rust_files(&root.join("src"))
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "mod.rs"))
        .map(|path| path.strip_prefix(root).unwrap().display().to_string())
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "poc-10 target has no mod.rs files; use root manifest files instead:\n{}",
        offenders.join("\n")
    );
}

#[test]
#[ignore = "poc-10 target guardrail: enable after schemas and wire layouts move to target files"]
fn poc10_target_has_no_per_module_schema_codec_or_cli_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let forbidden = ["schema.rs", "codec.rs", "cli.rs"];
    let offenders = rust_files(&root.join("src"))
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| forbidden.contains(&name))
        })
        .map(|path| path.strip_prefix(root).unwrap().display().to_string())
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "poc-10 target forbids per-module schema.rs, codec.rs, and cli.rs files:\n{}",
        offenders.join("\n")
    );
}

#[test]
#[ignore = "poc-10 target guardrail: enable after the three schema files exist"]
fn poc10_target_has_exactly_three_schema_dsl_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected = [
        "src/core/schema.p8sql",
        "src/event_modules/schema.p8sql",
        "src/handlers/schema.p8sql",
    ];

    for path in expected {
        assert!(root.join(path).exists(), "missing required schema file {path}");
    }

    let mut pending = vec![root.join("src")];
    let mut found = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "p8sql") {
                found.push(path.strip_prefix(root).unwrap().display().to_string());
            }
        }
    }
    found.sort();

    assert_eq!(
        found,
        expected,
        "poc-10 target keeps every durable table visible in exactly three schema files"
    );
}

#[test]
#[ignore = "poc-10 target guardrail: enable after broad source files are removed"]
fn poc10_target_has_no_dumping_ground_filenames() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let forbidden = [
        "utils.rs",
        "helpers.rs",
        "common.rs",
        "misc.rs",
        "manager.rs",
        "service.rs",
    ];
    let offenders = rust_files(&root.join("src"))
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| forbidden.contains(&name))
        })
        .map(|path| path.strip_prefix(root).unwrap().display().to_string())
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "poc-10 target uses invariant-specific filenames instead of dumping grounds:\n{}",
        offenders.join("\n")
    );
}

#[test]
#[ignore = "poc-10 target guardrail: enable after root manifests replace mod.rs"]
fn poc10_target_root_manifests_are_declarations_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifests = [
        "src/core.rs",
        "src/event_modules.rs",
        "src/handlers.rs",
        "src/commands.rs",
    ];

    for manifest in manifests {
        let path = root.join(manifest);
        assert!(path.exists(), "missing root manifest {manifest}");
        let text = source_text(&path);
        let offenders = meaningful_manifest_lines(&text)
            .into_iter()
            .filter(|line| {
                !(line.starts_with("pub mod ")
                    || line.starts_with("mod ")
                    || line.starts_with("pub use "))
            })
            .collect::<Vec<_>>();
        assert!(
            offenders.is_empty(),
            "{manifest} must only declare or re-export modules:\n{}",
            offenders.join("\n")
        );
    }
}


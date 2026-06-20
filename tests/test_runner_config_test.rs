use std::path::Path;

#[test]
fn normal_cargo_test_runs_the_rust_harness_serially() {
    assert_eq!(
        std::env::var("RUST_TEST_THREADS").as_deref(),
        Ok("1"),
        "poc-10 daemon/network integration tests are timing-sensitive under \
         parallel harness execution; keep normal cargo test runs serial"
    );
}

#[test]
fn manual_perf_fixtures_require_release_mode() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixtures = [
        (
            "tests/black_box_sync_perf_test.rs",
            "black_box_generated_content_sync_perf_uses_daemon_restart_boundary",
        ),
        (
            "tests/black_box_sync_perf_test.rs",
            "black_box_generated_content_live_tail_perf_skips_message_catchup",
        ),
        (
            "tests/black_box_sync_test.rs",
            "cli_cable_bound_download_perf_isolates_authoring_sync_and_save",
        ),
        (
            "tests/generate_cli_test.rs",
            "generate_cli_bulk_perf_isolates_authoring_and_admission_from_projection",
        ),
        (
            "tests/poc10_replay_cli_test.rs",
            "replay_cli_generated_messages_perf_rebuilds_normal_message_facts",
        ),
    ];

    let mut offenders = Vec::new();
    for (relative_path, fn_name) in fixtures {
        let source = std::fs::read_to_string(root.join(relative_path))
            .unwrap_or_else(|err| panic!("read {relative_path}: {err}"));
        let function = function_source(&source, fn_name);
        if !function.contains("assert_release_perf_fixture();") {
            offenders.push(format!("{relative_path}::{fn_name} missing release guard"));
        }

        let fn_offset = source
            .find(&format!("fn {fn_name}"))
            .unwrap_or_else(|| panic!("{relative_path} missing {fn_name}"));
        let ignore_context = &source[fn_offset.saturating_sub(250)..fn_offset];
        if !ignore_context.contains("cargo test --release") {
            offenders.push(format!(
                "{relative_path}::{fn_name} ignore hint omits --release"
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "manual perf fixtures must fail fast outside release mode:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn perf_documentation_names_release_mode() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let docs = std::fs::read_to_string(root.join("docs/performance.md"))
        .expect("read docs/performance.md");
    let script = std::fs::read_to_string(root.join("scripts/perf_compare.py"))
        .expect("read scripts/perf_compare.py");

    assert!(docs.contains("Performance fixtures must be run in release mode"));
    assert!(docs.contains("cargo test --release"));
    assert!(script.contains("use release mode"));
}

fn function_source<'a>(source: &'a str, fn_name: &str) -> &'a str {
    let marker = format!("fn {fn_name}");
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("missing function {fn_name}"));
    let rest = &source[start..];
    let end = rest[1..]
        .find("\n#[test]")
        .map(|offset| offset + 1)
        .unwrap_or(rest.len());
    &rest[..end]
}

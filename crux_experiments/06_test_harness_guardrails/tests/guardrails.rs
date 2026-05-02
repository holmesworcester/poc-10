use crux_core::App;
use crux_test_harness_guardrails::{
    Event, GuardedPath, GuardrailApp, GuardrailEffect, LlmStep, Model, ShellOp, ShellOutput,
    ViolationReason, ALLOWED_ROOT, MAX_TRANSCRIPT_BYTES,
};

fn edit_step(id: &str, depends_on: Vec<&str>) -> LlmStep {
    LlmStep::Edit {
        id: id.to_owned(),
        path: format!("{ALLOWED_ROOT}/src/lib.rs"),
        contents: "pub fn llm_edit() -> &'static str { \"guarded\" }\n".to_owned(),
        depends_on: depends_on.into_iter().map(str::to_owned).collect(),
    }
}

fn test_step(id: &str, depends_on: Vec<&str>) -> LlmStep {
    LlmStep::RunTests {
        id: id.to_owned(),
        manifest_dir: ALLOWED_ROOT.to_owned(),
        depends_on: depends_on.into_iter().map(str::to_owned).collect(),
    }
}

#[test]
fn boundary_checks_reject_paths_before_shell_effects() {
    assert!(GuardedPath::parse(format!("{ALLOWED_ROOT}/src/lib.rs")).is_ok());
    assert!(matches!(
        GuardedPath::parse("Cargo.toml"),
        Err(ViolationReason::PathOutsideAllowedRoot { .. })
    ));
    assert!(matches!(
        GuardedPath::parse(format!("{ALLOWED_ROOT}/../Cargo.toml")),
        Err(ViolationReason::PathTraversal { .. })
    ));
    assert!(matches!(
        GuardedPath::parse("/home/holmes/poc-8/Cargo.toml"),
        Err(ViolationReason::AbsolutePath { .. })
    ));

    let app = GuardrailApp;
    let mut model = Model::default();
    let mut command = app.update(
        Event::ProposeLlmStep(LlmStep::Edit {
            id: "edit-parent".to_owned(),
            path: "Cargo.toml".to_owned(),
            contents: "workspace edit".to_owned(),
            depends_on: Vec::new(),
        }),
        &mut model,
    );

    command.expect_no_effect_or_events();
    assert!(model.drain.pending_ids().is_empty());
    assert!(matches!(
        model.violations.as_slice(),
        [violation]
            if violation.work_id.as_deref() == Some("edit-parent")
                && matches!(
                    violation.reason,
                    ViolationReason::PathOutsideAllowedRoot { .. }
                )
    ));
}

#[test]
fn fake_shell_transcript_records_typed_effect_result() {
    let app = GuardrailApp;
    let mut model = Model::default();

    let mut command = app.update(
        Event::ProposeLlmStep(edit_step("edit-lib", vec![])),
        &mut model,
    );
    let GuardrailEffect::Shell(mut request) = command.expect_one_effect();

    assert!(matches!(
        &request.operation,
        ShellOp::WriteFile { path, contents }
            if path.as_str() == format!("{ALLOWED_ROOT}/src/lib.rs")
                && contents.contains("guarded")
    ));

    let long_stdout = "patched\n".repeat(80);
    request
        .resolve(ShellOutput::success(long_stdout))
        .expect("fake shell output should resolve typed request");

    let event = command.expect_one_event();
    let mut follow_up = app.update(event, &mut model);
    follow_up.expect_no_effect_or_events();

    assert_eq!(model.drain.completed_ids(), vec!["edit-lib"]);
    assert_eq!(model.transcript.len(), 1);
    let transcript = &model.transcript[0];
    assert_eq!(transcript.work_id.as_str(), "edit-lib");
    assert_eq!(transcript.status, 0);
    assert_eq!(
        transcript.operation,
        format!("write {ALLOWED_ROOT}/src/lib.rs")
    );
    assert!(transcript.stdout.len() > MAX_TRANSCRIPT_BYTES);
    assert!(transcript.stdout.ends_with("...[truncated]"));
}

#[test]
fn dependency_drain_defers_tests_until_edit_effect_succeeds() {
    let app = GuardrailApp;
    let mut model = Model::default();

    let mut edit_command = app.update(
        Event::ProposeLlmStep(edit_step("edit-lib", vec![])),
        &mut model,
    );
    let GuardrailEffect::Shell(mut edit_request) = edit_command.expect_one_effect();
    assert!(matches!(edit_request.operation, ShellOp::WriteFile { .. }));

    let mut blocked_command = app.update(
        Event::ProposeLlmStep(test_step("cargo-test", vec!["edit-lib"])),
        &mut model,
    );
    blocked_command.expect_no_effect_or_events();
    assert_eq!(model.drain.running_ids(), vec!["edit-lib"]);
    assert_eq!(model.drain.pending_ids(), vec!["cargo-test"]);
    assert!(model.drain.invariant_errors().is_empty());

    edit_request
        .resolve(ShellOutput::success("edit applied"))
        .expect("edit request should resolve");
    let edit_done = edit_command.expect_one_event();

    let mut test_command = app.update(edit_done, &mut model);
    let GuardrailEffect::Shell(mut test_request) = test_command.expect_one_effect();
    assert_eq!(
        test_request.operation,
        ShellOp::RunCargoTest {
            manifest_dir: GuardedPath::parse(ALLOWED_ROOT).unwrap(),
        }
    );
    assert_eq!(model.drain.completed_ids(), vec!["edit-lib"]);
    assert_eq!(model.drain.running_ids(), vec!["cargo-test"]);
    assert!(model.drain.invariant_errors().is_empty());

    test_request
        .resolve(ShellOutput::success("cargo test passed"))
        .expect("test request should resolve");
    let test_done = test_command.expect_one_event();
    let mut final_command = app.update(test_done, &mut model);

    final_command.expect_no_effect_or_events();
    assert_eq!(model.drain.completed_ids(), vec!["cargo-test", "edit-lib"]);
    assert!(model.drain.pending_ids().is_empty());
    assert!(model.drain.running_ids().is_empty());
    assert!(model.violations.is_empty());
}

#[test]
fn failed_dependency_blocks_dependent_shell_effect() {
    let app = GuardrailApp;
    let mut model = Model::default();

    let mut edit_command = app.update(
        Event::ProposeLlmStep(edit_step("edit-lib", vec![])),
        &mut model,
    );
    let GuardrailEffect::Shell(mut edit_request) = edit_command.expect_one_effect();

    let mut blocked_command = app.update(
        Event::ProposeLlmStep(test_step("cargo-test", vec!["edit-lib"])),
        &mut model,
    );
    blocked_command.expect_no_effect_or_events();

    edit_request
        .resolve(ShellOutput::failure("patch rejected"))
        .expect("edit request should resolve as a failed shell result");
    let edit_done = edit_command.expect_one_event();
    let mut after_failure = app.update(edit_done, &mut model);

    after_failure.expect_no_effect_or_events();
    assert_eq!(model.drain.failed_ids(), vec!["edit-lib"]);
    assert_eq!(model.drain.pending_ids(), vec!["cargo-test"]);
    assert!(model.drain.running_ids().is_empty());
    assert!(model.drain.invariant_errors().is_empty());
    assert_eq!(model.transcript[0].stderr, "patch rejected");
}

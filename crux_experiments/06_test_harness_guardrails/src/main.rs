use crux_core::App;
use crux_test_harness_guardrails::{
    Event, GuardrailApp, GuardrailEffect, LlmStep, Model, ShellOutput, ALLOWED_ROOT,
};

fn main() {
    let app = GuardrailApp;
    let mut model = Model::default();

    let mut command = app.update(
        Event::ProposeLlmStep(LlmStep::RunTests {
            id: "cargo-test".to_owned(),
            manifest_dir: ALLOWED_ROOT.to_owned(),
            depends_on: Vec::new(),
        }),
        &mut model,
    );

    let Some(GuardrailEffect::Shell(mut request)) = command.effects().next() else {
        eprintln!("no shell effect emitted");
        return;
    };

    println!("fake shell sees typed op: {}", request.operation.summary());
    request
        .resolve(ShellOutput::success("all tests passed"))
        .expect("fake shell response should resolve");

    if let Some(event) = command.events().next() {
        let mut follow_up = app.update(event, &mut model);
        follow_up.expect_no_effect_or_events();
    }

    let view = app.view(&model);
    println!(
        "completed={:?} failed={:?} violations={} transcript_entries={}",
        view.completed, view.failed, view.violations, view.transcript_entries
    );
}

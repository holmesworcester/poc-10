use std::path::Path;
use topo::core::cli::{self, CliOutput};
use topo::core::facts::{Fact, FactScope};
use topo::core::intents::{Intent, IntentKind};
use topo::core::projectors::{ProjectionContext, ProjectionOutput, Projector};
use topo::core::runtime::{Runtime, RuntimeDescription};
use topo::core::wire::FixedBytes;
use topo::protocol::connection::frame::create::{
    received_network_frame_effect, ReceivedNetworkFrame,
};
use topo::protocol::connection::frame::decode_fact_payload;
use topo::protocol::connection::frame::layout::{
    encode_frame_bytes, CONNECTION_FRAME_SIZE_CLASS_SMALL,
};
use topo::protocol::registry::{MatchCliContext, MATCH_COMMANDS};

#[test]
fn cli_sequence_fuzz_surface_reopens_runtime_and_observes_command_projection() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("cli-sequence.db");

    let created = run_match_cli(
        &db,
        &[
            "create-workspace",
            "fuzz-workspace",
            "--username",
            "fuzz-user",
            "--devicename",
            "fuzz-device",
        ],
    );
    let workspace_id = cli_line_value(&created, "workspace_id");

    run_match_cli(&db, &["key-frontier", &workspace_id]);
    run_match_cli(&db, &["send", &workspace_id, "hello-fuzz"]);

    let messages = run_match_cli(&db, &["messages", &workspace_id]);
    assert!(
        messages
            .lines
            .iter()
            .any(|line| line.contains("hello-fuzz")),
        "messages output should include the just-sent text:\n{}",
        messages.lines.join("\n")
    );

    let count = run_match_cli(&db, &["content-count", &workspace_id]);
    assert_eq!(cli_line_value(&count, "content_messages"), "1");
}

#[test]
fn receive_network_frame_fuzz_surface_discards_and_classifies_cleanly() {
    let discarded = received_network_frame_effect(ReceivedNetworkFrame {
        frame: b"not a frame",
        origin_addr: b"127.0.0.1:40000",
        received_at_local_ms: 1,
    })
    .expect("malformed bytes should discard cleanly");
    assert!(discarded.facts.is_empty());
    assert!(discarded.ephemeral_facts.is_empty());

    let frame = encode_frame_bytes(
        CONNECTION_FRAME_SIZE_CLASS_SMALL,
        FixedBytes([1; 32]),
        FixedBytes([2; 24]),
        &[],
    )
    .expect("encode classified frame");
    let classified = received_network_frame_effect(ReceivedNetworkFrame {
        frame: &frame,
        origin_addr: b"127.0.0.1:40000",
        received_at_local_ms: 2,
    })
    .expect("valid frame shape should classify");

    assert!(classified.facts.is_empty());
    assert_eq!(classified.ephemeral_facts.len(), 1);
    assert_eq!(classified.ephemeral_facts[0].scope, FactScope::Local);
    decode_fact_payload(classified.ephemeral_facts[0].body()).expect("classified fact decodes");
}

fn run_match_cli(db: &Path, args: &[&str]) -> CliOutput {
    let runtime = Runtime::open_disk(&topo::protocol::app::MATCH_RUNTIME, db).expect("runtime");
    let mut context = MatchCliContext::new(runtime, Some(db.to_path_buf()));
    let args = args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>();
    cli::run("con", MATCH_COMMANDS, &mut context, &args).expect("command")
}

fn cli_line_value(output: &CliOutput, key: &str) -> String {
    let prefix = format!("{key}: ");
    output
        .lines
        .iter()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing `{key}:` in output:\n{}", output.lines.join("\n")))
        .to_string()
}

#[test]
fn projection_fuzz_surface_exercises_ephemeral_transient_need_guard() {
    let mut runtime = Runtime::open_memory(&FUZZ_RUNTIME).expect("runtime");
    runtime.submit_fact(Fact::new(FactScope::Global, 1, vec![4]));

    let err = runtime
        .process_projection_until_idle(4, 16)
        .expect_err("ephemeral input with unresolved needs and effects must fail");

    assert!(
        err.contains("ephemeral projection input cannot emit effects while transient needs remain"),
        "{err}"
    );
}

const FUZZ_RUNTIME: RuntimeDescription = RuntimeDescription {
    schema_sources: &[],
    row_mutation_tables: &[],
    projector: fuzz_projector,
    handlers: &[],
    command_excluded_handlers: &[],
};

fn fuzz_projector() -> Box<dyn Projector> {
    Box::new(FuzzProjector)
}

#[derive(Debug, Clone, Copy)]
struct FuzzProjector;

impl Projector for FuzzProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        match fact.bytes.first().copied() {
            Some(4) => {
                let mut output = ProjectionOutput::new();
                output.effects.ephemeral_facts.push(Fact::new(
                    FactScope::Local,
                    fact.timestamp,
                    vec![5],
                ));
                Ok(output)
            }
            Some(5) => Ok(ProjectionOutput::new()
                .need(topo::core::context::ContextNeed::range(
                    fact.id,
                    "fuzz_match",
                    FactScope::Global,
                    [1; 32],
                    [1; 32],
                ))
                .local_intent(Intent::new(
                    IntentKind::new("fuzz_followup").expect("intent kind"),
                    b"same",
                    b"payload",
                ))),
            _ => Ok(ProjectionOutput::new()),
        }
    }
}

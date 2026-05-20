use topo::core::facts::{Fact, FactScope};
use topo::core::intent_pipeline::{HandlerContext, HandlerOutput, IntentHandler};
use topo::core::intents::{Intent, IntentExecution, IntentKind};

struct EmitsFactAndFollowup;

impl IntentHandler for EmitsFactAndFollowup {
    fn handle(&self, intent: &Intent, _context: &HandlerContext) -> Result<HandlerOutput, String> {
        let fact = Fact::new(FactScope::Local, 42, b"handler-produced-fact".to_vec());
        let followup = Intent::new(
            IntentKind::new("followup_work").unwrap(),
            IntentExecution::Deferred,
            intent.key.clone(),
            b"followup-payload".to_vec(),
        );

        Ok(HandlerOutput::new().fact(fact).intent(followup))
    }
}

#[test]
fn intent_pipeline_output_boundary_is_facts_and_followup_intents_only() {
    let input = Intent::new(
        IntentKind::new("incoming_work").unwrap(),
        IntentExecution::Atomic,
        b"idempotence-key",
        b"opaque-intent-payload",
    );

    let output = EmitsFactAndFollowup
        .handle(&input, &HandlerContext::new())
        .expect("handler output");

    let HandlerOutput {
        facts,
        purged_facts,
        intents,
    } = output;

    assert_eq!(facts.len(), 1);
    assert!(purged_facts.is_empty());
    assert_eq!(facts[0].scope, FactScope::Local);
    assert_eq!(facts[0].timestamp, 42);
    assert_eq!(facts[0].bytes, b"handler-produced-fact");

    assert_eq!(intents.len(), 1);
    let Intent {
        kind,
        execution,
        key,
        payload,
    } = &intents[0];

    assert_eq!(kind.as_str(), "followup_work");
    assert_eq!(*execution, IntentExecution::Deferred);
    assert_eq!(key, b"idempotence-key");
    assert_eq!(payload, b"followup-payload");
}

#[test]
fn intent_execution_metadata_is_protocol_neutral() {
    let atomic = Intent::new(
        IntentKind::new("materialize_row").unwrap(),
        IntentExecution::Atomic,
        b"same-work",
        b"protocol bytes stay opaque",
    );
    let deferred = Intent::new(
        IntentKind::new("send_network_bytes").unwrap(),
        IntentExecution::Deferred,
        b"same-work",
        b"route=tcp://127.0.0.1:9999",
    );
    let ephemeral = Intent::new(
        IntentKind::new("socket_write").unwrap(),
        IntentExecution::Ephemeral,
        b"same-work",
        b"route=tcp://127.0.0.1:9999",
    );

    for intent in [atomic, deferred, ephemeral] {
        let Intent {
            kind,
            execution,
            key,
            payload,
        } = intent;

        assert!(!kind.as_str().is_empty());
        assert_eq!(key, b"same-work");
        assert!(!payload.is_empty());

        match execution {
            IntentExecution::Atomic => {}
            IntentExecution::Deferred => {}
            IntentExecution::Ephemeral => {}
        }
    }
}

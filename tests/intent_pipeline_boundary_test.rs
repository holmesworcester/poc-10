use topo::core::effects::PipelineEffects;
use topo::core::facts::{Fact, FactScope};
use topo::core::intents::{HandlerContext, HandlerResult, IntentHandler};
use topo::core::intents::{Intent, IntentKind};

struct EmitsFactAndFollowup;

impl IntentHandler for EmitsFactAndFollowup {
    fn handle(&self, intent: &Intent, _context: &HandlerContext) -> HandlerResult {
        let fact = Fact::new(FactScope::Local, 42, b"handler-produced-fact".to_vec());
        let followup = Intent::new(
            IntentKind::new("followup_work").unwrap(),
            intent.key.clone(),
            b"followup-payload".to_vec(),
        );

        Ok(PipelineEffects::new().fact(fact).intent(followup))
    }
}

#[test]
fn intent_pipeline_output_boundary_is_facts_and_followup_intents_only() {
    let input = Intent::new(
        IntentKind::new("incoming_work").unwrap(),
        b"idempotence-key",
        b"opaque-intent-payload",
    );

    let output = EmitsFactAndFollowup
        .handle(&input, &HandlerContext::new())
        .expect("handler output");

    let PipelineEffects {
        facts,
        candidate_facts,
        purged_facts,
        row_mutations,
        intents,
        local_intents,
    } = output;

    assert_eq!(facts.len(), 1);
    assert!(candidate_facts.is_empty());
    assert!(purged_facts.is_empty());
    assert!(row_mutations.is_empty());
    assert!(local_intents.is_empty());
    assert_eq!(facts[0].scope, FactScope::Local);
    assert_eq!(facts[0].timestamp, 42);
    assert_eq!(facts[0].bytes, b"handler-produced-fact");

    assert_eq!(intents.len(), 1);
    let Intent { kind, key, payload } = &intents[0];

    assert_eq!(kind.as_str(), "followup_work");
    assert_eq!(key, b"idempotence-key");
    assert_eq!(payload, b"followup-payload");
}

#[test]
fn intent_metadata_is_protocol_neutral() {
    let first = Intent::new(
        IntentKind::new("send_network_bytes").unwrap(),
        b"same-work",
        b"route=tcp://127.0.0.1:9999",
    );
    let second = Intent::new(
        IntentKind::new("socket_write").unwrap(),
        b"same-work",
        b"route=tcp://127.0.0.1:9999",
    );

    for intent in [first, second] {
        let Intent { kind, key, payload } = intent;

        assert!(!kind.as_str().is_empty());
        assert_eq!(key, b"same-work");
        assert!(!payload.is_empty());
    }
}

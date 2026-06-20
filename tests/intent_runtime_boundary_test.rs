use topo::core::db::Db;
use topo::core::effects::RuntimeEffects;
use topo::core::facts::{Fact, FactScope};
use topo::core::intents::{HandlerContext, HandlerResult, IntentHandler};
use topo::core::intents::{Intent, IntentKind};

struct EmitsFactAndFollowup;

impl IntentHandler for EmitsFactAndFollowup {
    fn handle(&self, intent: &Intent, _context: &HandlerContext) -> HandlerResult {
        let fact = Fact::new(FactScope::Local, 42, b"handler-produced-fact".to_vec());
        let followup = Intent::new(
            IntentKind::new("followup_work").unwrap(),
            intent.handler_key.clone(),
            b"followup-payload".to_vec(),
        );

        Ok(RuntimeEffects::new().fact(fact).intent(followup))
    }
}

#[test]
fn intent_runtime_output_boundary_is_facts_and_followup_intents_only() {
    let store = Db::open_memory().expect("open db");
    let input = Intent::new(
        IntentKind::new("incoming_work").unwrap(),
        b"handler-key",
        b"opaque-intent-payload",
    );

    let output = EmitsFactAndFollowup
        .handle(&input, &HandlerContext::new(&store))
        .expect("handler output");

    let RuntimeEffects {
        storage_requirement,
        facts,
        priority_facts,
        incoming_facts,
        incoming_fact_metadata,
        purged_facts,
        row_mutations,
        intents,
        local_intents,
        rebuild_derived_state,
    } = output;

    assert_eq!(
        storage_requirement,
        topo::core::effects::StorageRequirement::MaintenanceBypass
    );
    assert_eq!(facts.len(), 1);
    assert!(priority_facts.is_empty());
    assert!(incoming_facts.is_empty());
    assert!(incoming_fact_metadata.is_empty());
    assert!(purged_facts.is_empty());
    assert!(row_mutations.is_empty());
    assert!(local_intents.is_empty());
    assert!(!rebuild_derived_state);
    assert_eq!(facts[0].scope, FactScope::Local);
    assert_eq!(facts[0].timestamp, 42);
    assert_eq!(facts[0].bytes, b"handler-produced-fact");

    assert_eq!(intents.len(), 1);
    let Intent {
        kind,
        handler_key,
        payload,
        context_fact_ids,
    } = &intents[0];

    assert_eq!(kind.as_str(), "followup_work");
    assert_eq!(handler_key, b"handler-key");
    assert_eq!(payload, b"followup-payload");
    assert!(context_fact_ids.is_empty());
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
        let Intent {
            kind,
            handler_key,
            payload,
            context_fact_ids,
        } = intent;

        assert!(!kind.as_str().is_empty());
        assert_eq!(handler_key, b"same-work");
        assert!(!payload.is_empty());
        assert!(context_fact_ids.is_empty());
    }
}

use topo::protocol::{IntentExecutionKind, PROTOCOL};

#[test]
fn protocol_registry_names_the_target_surfaces() {
    assert_eq!(PROTOCOL.name, "match");
    assert_eq!(PROTOCOL.schemas.len(), 3);

    assert!(PROTOCOL
        .facts
        .iter()
        .any(|fact| fact.module == "encryption" && fact.name == "key_wrap"));
    assert!(PROTOCOL
        .facts
        .iter()
        .any(|fact| fact.module == "sealed_message" && fact.name == "sealed_message"));
    assert!(PROTOCOL
        .context_matchers
        .iter()
        .any(|matcher| matcher.role == "secret_coverage"));
    assert!(PROTOCOL
        .handlers
        .iter()
        .any(|handler| handler.module == "receive_transit"));
}

#[test]
fn handler_intents_are_declared_intents() {
    for handler in PROTOCOL.handlers {
        for handled_kind in handler.intents {
            assert!(
                PROTOCOL
                    .intents
                    .iter()
                    .any(|intent| intent.kind == *handled_kind),
                "{} handles undeclared intent {}",
                handler.handler,
                handled_kind
            );
        }
    }
}

#[test]
fn row_intents_are_registered_as_atomic_and_effects_as_deferred() {
    let put_row = PROTOCOL
        .intents
        .iter()
        .find(|intent| intent.kind == "put_row")
        .expect("put_row intent");
    assert_eq!(put_row.execution, IntentExecutionKind::Atomic);

    let receive_transit = PROTOCOL
        .intents
        .iter()
        .find(|intent| intent.kind == "receive_transit_frame")
        .expect("receive transit intent");
    assert_eq!(receive_transit.execution, IntentExecutionKind::Deferred);
}

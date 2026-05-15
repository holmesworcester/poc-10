use topo::handlers::deferred_effects as effects;

#[test]
fn received_fact_intent_names_exact_payload_without_queue_rows() {
    let input = effects::AdmitReceivedFact {
        source_id: [1; 32],
        canonical_bytes: b"canonical event bytes".to_vec(),
    };
    let intent = effects::admit_received_fact_intent(input.clone());

    assert_eq!(intent.kind.as_str(), effects::ADMIT_RECEIVED_FACT);
    assert_eq!(effects::decode_admit_received_fact(&intent).unwrap(), input);
    assert_ne!(
        intent.key,
        effects::admit_received_fact_intent(effects::AdmitReceivedFact {
            source_id: [1; 32],
            canonical_bytes: b"other bytes".to_vec(),
        })
        .key
    );
}

#[test]
fn deferred_effect_intents_round_trip_with_deterministic_keys() {
    let scoped = effects::ScopedEventIntent {
        workspace_id: [1; 32],
        event_id: [2; 32],
    };
    let connection = effects::ConnectionEventIntent {
        connection_id: [3; 32],
        event_id: [4; 32],
    };
    let single = effects::SingleEventIntent { event_id: [5; 32] };

    assert_eq!(
        effects::decode_handle_sync_event(&effects::handle_sync_event_intent(connection.clone()))
            .unwrap(),
        connection
    );
    assert_eq!(
        effects::decode_sync_index_remove(&effects::sync_index_remove_intent(scoped.clone()))
            .unwrap(),
        scoped
    );
    assert_eq!(
        effects::decode_purge_event(&effects::purge_event_intent(scoped.clone())).unwrap(),
        scoped
    );
    assert_eq!(
        effects::decode_materialize_key_request(&effects::materialize_key_request_intent(
            single.clone()
        ))
        .unwrap(),
        single
    );
    assert_eq!(
        effects::decode_unwrap_key_wrap(&effects::unwrap_key_wrap_intent(single.clone())).unwrap(),
        single
    );
}

#[test]
fn key_wrap_reconcile_intent_is_trigger_specific() {
    let input = effects::ReconcileKeyWraps {
        workspace_id: [1; 32],
        trigger: effects::ReconcileTrigger::RecipientKey,
        trigger_id: [2; 32],
    };
    let intent = effects::reconcile_key_wraps_intent(input.clone());

    assert_eq!(intent.kind.as_str(), effects::RECONCILE_KEY_WRAPS);
    assert_eq!(effects::decode_reconcile_key_wraps(&intent).unwrap(), input);
    assert_ne!(
        intent.key,
        effects::reconcile_key_wraps_intent(effects::ReconcileKeyWraps {
            trigger: effects::ReconcileTrigger::Frontier,
            ..input
        })
        .key
    );
}

use crux_core::ResolveError;
use pure_planner_effects::{
    plan_frame, DrainOperation, Effect, Event, Frame, NetworkOperation, PipelineCore, PlanStep,
    StoreOperation,
};

#[test]
fn pure_planner_returns_store_network_and_drain_steps() {
    let frame = Frame::new("peer-a", 7, b"hello".to_vec());

    let plan = plan_frame(&frame);

    assert_eq!(
        plan.steps(),
        &[
            PlanStep::Store(StoreOperation::AppendFrame {
                stream_id: "peer-a".to_owned(),
                sequence: 7,
                payload: b"hello".to_vec(),
            }),
            PlanStep::Network(NetworkOperation::SendAck {
                stream_id: "peer-a".to_owned(),
                sequence: 7,
            }),
            PlanStep::Drain(DrainOperation::DrainReady {
                stream_id: "peer-a".to_owned(),
                after_sequence: 7,
            }),
        ]
    );
}

#[test]
fn frame_received_emits_typed_crux_effects_without_shell_io() {
    let core = PipelineCore::new();

    let mut effects = core
        .process_event(Event::FrameReceived(Frame::new(
            "peer-a",
            7,
            b"hello".to_vec(),
        )))
        .into_iter();

    let Some(Effect::Store(mut request)) = effects.next() else {
        panic!("expected first effect to be a store append request");
    };
    assert_eq!(
        request.operation,
        StoreOperation::AppendFrame {
            stream_id: "peer-a".to_owned(),
            sequence: 7,
            payload: b"hello".to_vec(),
        }
    );
    assert!(matches!(request.resolve(()), Err(ResolveError::Never)));

    let Some(Effect::Network(mut request)) = effects.next() else {
        panic!("expected second effect to be a network ack request");
    };
    assert_eq!(
        request.operation,
        NetworkOperation::SendAck {
            stream_id: "peer-a".to_owned(),
            sequence: 7,
        }
    );
    assert!(matches!(request.resolve(()), Err(ResolveError::Never)));

    let Some(Effect::Drain(mut request)) = effects.next() else {
        panic!("expected third effect to be a drain request");
    };
    assert_eq!(
        request.operation,
        DrainOperation::DrainReady {
            stream_id: "peer-a".to_owned(),
            after_sequence: 7,
        }
    );
    assert!(matches!(request.resolve(()), Err(ResolveError::Never)));

    assert!(effects.next().is_none());

    assert_eq!(core.view().frames_seen, 1);
    assert_eq!(core.view().last_plan_step_count, 3);
}

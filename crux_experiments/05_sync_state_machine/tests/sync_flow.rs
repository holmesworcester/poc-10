use crux_core::Core;
use sync_state_machine_crux_poc::{
    network_operations, ConnectionState, Event, MachineInput, NetworkAction, NetworkEvent,
    NetworkOperation, SyncApp, SyncStateMachine, WireMessage,
};

fn peer() -> String {
    "peer-a".to_string()
}

#[test]
fn pure_machine_handshakes_then_reaches_synced_connection() {
    let mut machine = SyncStateMachine::new("node-local", 2);

    let transition = machine.apply(MachineInput::Connect { peer: peer() });
    assert_eq!(
        transition.state,
        ConnectionState::Connecting { peer: peer() }
    );
    assert_eq!(
        transition.actions,
        vec![NetworkAction::OpenConnection { peer: peer() }]
    );

    let transition = machine.apply(MachineInput::ConnectionOpened { peer: peer() });
    assert_eq!(
        transition.state,
        ConnectionState::Handshaking { peer: peer() }
    );
    assert_eq!(
        transition.actions,
        vec![NetworkAction::Send {
            peer: peer(),
            message: WireMessage::Hello {
                node_id: "node-local".to_string(),
                last_seen: 2,
            },
        }]
    );

    let transition = machine.apply(MachineInput::MessageReceived {
        peer: peer(),
        message: WireMessage::Welcome { remote_version: 9 },
    });
    assert_eq!(
        transition.state,
        ConnectionState::Syncing {
            peer: peer(),
            requested_since: 2,
            remote_version: 9,
        }
    );
    assert_eq!(
        transition.actions,
        vec![NetworkAction::Send {
            peer: peer(),
            message: WireMessage::SyncRequest { since: 2 },
        }]
    );

    let transition = machine.apply(MachineInput::MessageReceived {
        peer: peer(),
        message: WireMessage::SyncBatch {
            changes: vec!["doc:alpha".to_string()],
            complete: true,
            remote_version: 9,
        },
    });
    assert_eq!(
        transition.state,
        ConnectionState::Connected {
            peer: peer(),
            version: 9,
        }
    );
    assert_eq!(machine.local_version(), 9);
    assert_eq!(
        transition.actions,
        vec![NetworkAction::Send {
            peer: peer(),
            message: WireMessage::Ack { version: 9 },
        }]
    );
}

#[test]
fn crux_core_emits_network_effects_for_handshake_and_sync() {
    let core: Core<SyncApp> = Core::new();

    let operations = network_operations(core.process_event(Event::Connect { peer: peer() }));
    assert_eq!(
        operations,
        vec![NetworkOperation::OpenConnection { peer: peer() }]
    );
    assert_eq!(
        core.view().state,
        ConnectionState::Connecting { peer: peer() }
    );

    let operations = network_operations(core.process_event(Event::Network(
        NetworkEvent::ConnectionOpened { peer: peer() },
    )));
    assert_eq!(
        operations,
        vec![NetworkOperation::Send {
            peer: peer(),
            message: WireMessage::Hello {
                node_id: "local-node".to_string(),
                last_seen: 0,
            },
        }]
    );
    assert_eq!(
        core.view().state,
        ConnectionState::Handshaking { peer: peer() }
    );

    let operations =
        network_operations(core.process_event(Event::Network(NetworkEvent::Received {
            peer: peer(),
            message: WireMessage::Welcome { remote_version: 5 },
        })));
    assert_eq!(
        operations,
        vec![NetworkOperation::Send {
            peer: peer(),
            message: WireMessage::SyncRequest { since: 0 },
        }]
    );
    assert_eq!(
        core.view().state,
        ConnectionState::Syncing {
            peer: peer(),
            requested_since: 0,
            remote_version: 5,
        }
    );

    let operations =
        network_operations(core.process_event(Event::Network(NetworkEvent::Received {
            peer: peer(),
            message: WireMessage::SyncBatch {
                changes: vec!["doc:alpha".to_string()],
                complete: true,
                remote_version: 5,
            },
        })));
    assert_eq!(
        operations,
        vec![NetworkOperation::Send {
            peer: peer(),
            message: WireMessage::Ack { version: 5 },
        }]
    );
    assert_eq!(
        core.view().state,
        ConnectionState::Connected {
            peer: peer(),
            version: 5,
        }
    );
    assert_eq!(core.view().local_version, 5);
}

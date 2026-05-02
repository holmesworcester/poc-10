use crux_core::Core;
use sync_state_machine_crux_poc::{network_operations, Event, NetworkEvent, SyncApp, WireMessage};

fn main() {
    let core: Core<SyncApp> = Core::new();
    let peer = "peer-a".to_string();

    print_step(
        "connect",
        &core,
        core.process_event(Event::Connect { peer: peer.clone() }),
    );
    print_step(
        "socket-opened",
        &core,
        core.process_event(Event::Network(NetworkEvent::ConnectionOpened {
            peer: peer.clone(),
        })),
    );
    print_step(
        "welcome",
        &core,
        core.process_event(Event::Network(NetworkEvent::Received {
            peer: peer.clone(),
            message: WireMessage::Welcome { remote_version: 7 },
        })),
    );
    print_step(
        "sync-batch",
        &core,
        core.process_event(Event::Network(NetworkEvent::Received {
            peer,
            message: WireMessage::SyncBatch {
                changes: vec!["doc:alpha".to_string()],
                complete: true,
                remote_version: 7,
            },
        })),
    );
}

fn print_step(
    label: &str,
    core: &Core<SyncApp>,
    effects: Vec<sync_state_machine_crux_poc::Effect>,
) {
    println!(
        "{label}: view={:?} network_effects={:?}",
        core.view(),
        network_operations(effects)
    );
}

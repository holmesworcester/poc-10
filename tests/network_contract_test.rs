use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::thread;

use topo::core::network::{self, NetworkTarget, OutboundNetworkRow};
use topo::core::store::Store;

#[test]
fn outbound_network_rows_are_opaque_and_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("network-queues.db");
    let store = Store::open_disk_with_schema_sources(&path, &[network::SCHEMA_SOURCE]).unwrap();
    let addr: SocketAddr = "127.0.0.1:41000".parse().unwrap();
    let other_addr: SocketAddr = "127.0.0.1:41001".parse().unwrap();
    let target = NetworkTarget::new(addr);
    let other_target = NetworkTarget::new(other_addr);

    let outbound = OutboundNetworkRow::new(target, b"opaque bytes".to_vec());
    let duplicate_outbound = OutboundNetworkRow::new(target, b"opaque bytes".to_vec());
    let other_outbound = OutboundNetworkRow::new(other_target, b"other target bytes".to_vec());
    assert_eq!(outbound.key, duplicate_outbound.key);
    assert_ne!(outbound.key, other_outbound.key);

    assert_eq!(
        network::enqueue_outbound(
            &store,
            &[
                outbound.clone(),
                duplicate_outbound.clone(),
                other_outbound.clone()
            ]
        )
        .unwrap(),
        2
    );
    assert_eq!(
        network::queued_outbound_targets(&store, 16).unwrap(),
        vec![target, other_target],
        "the target scheduler index deduplicates active addresses"
    );
    assert_eq!(
        store
            .table_row_count(network::OUTBOUND_TARGETS_TABLE)
            .unwrap(),
        2
    );
    assert_eq!(
        network::claim_outbound_for_target(&store, target, 16).unwrap(),
        vec![outbound.clone()]
    );
    let later_outbound = OutboundNetworkRow::new(target, b"later target bytes".to_vec());
    network::enqueue_outbound(&store, std::slice::from_ref(&later_outbound)).unwrap();
    assert_eq!(
        store
            .table_row_count(network::OUTBOUND_TARGETS_TABLE)
            .unwrap(),
        2,
        "multiple frames for one address keep one active target row"
    );
    assert_eq!(
        network::claim_outbound_for_target(&store, target, 1).unwrap(),
        vec![outbound.clone()]
    );
    assert_eq!(
        network::claim_exact_outbound(&store, std::slice::from_ref(&later_outbound)).unwrap(),
        vec![later_outbound.clone()]
    );
    assert_eq!(
        network::claim_outbound_for_target(&store, other_target, 16).unwrap(),
        vec![other_outbound]
    );
    network::delete_outbound(&store, &[outbound, later_outbound])
        .expect("delete queued outbound bytes");
    assert!(network::claim_outbound_for_target(&store, target, 16)
        .unwrap()
        .is_empty());
    assert_eq!(
        network::queued_outbound_targets(&store, 16).unwrap(),
        vec![other_target],
        "deleting the final frame for an address prunes its active target row"
    );

    let reopened = Store::open_disk_with_schema_sources(&path, &[network::SCHEMA_SOURCE]).unwrap();
    assert!(
        network::claim_outbound_for_target(&reopened, target, 16)
            .unwrap()
            .is_empty(),
        "network rows are process-local IO staging, not restart-durable protocol truth"
    );
    assert!(
        network::queued_outbound_targets(&reopened, 16)
            .unwrap()
            .is_empty(),
        "network target rows are process-local scheduling state"
    );
}

#[test]
fn outbound_pump_writes_queued_rows_and_deletes_sent_frames() {
    let store = Store::open_memory_with_schema_sources(&[network::SCHEMA_SOURCE]).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    let target = NetworkTarget::new(addr);
    let first = OutboundNetworkRow::new(target, b"first frame".to_vec());
    let second = OutboundNetworkRow::new(target, b"second frame".to_vec());
    let mut expected_rows = vec![first.clone(), second.clone()];
    expected_rows.sort_by(|left, right| left.key.cmp(&right.key));

    network::enqueue_outbound(&store, &[second, first]).expect("enqueue outbound rows");

    let reader = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept pump stream");
        vec![
            read_length_prefixed_frame(&mut stream),
            read_length_prefixed_frame(&mut stream),
        ]
    });
    let report = network::pump_outbound(&store, 16, 16).expect("pump outbound rows");

    assert_eq!(
        report,
        network::OutboundPumpReport {
            target_count: 1,
            sent_frames: 2,
            deferred_targets: 0,
        }
    );
    assert_eq!(
        reader.join().expect("reader thread"),
        expected_rows
            .iter()
            .map(|row| row.bytes.clone())
            .collect::<Vec<_>>()
    );
    assert!(network::claim_outbound_for_target(&store, target, 16)
        .expect("claim after pump")
        .is_empty());
    assert!(network::queued_outbound_targets(&store, 16)
        .expect("targets after pump")
        .is_empty());
}

#[test]
fn outbound_pump_leaves_rows_queued_when_target_is_unavailable() {
    let store = Store::open_memory_with_schema_sources(&[network::SCHEMA_SOURCE]).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind closed listener");
    let addr = listener.local_addr().expect("listener addr");
    drop(listener);
    let target = NetworkTarget::new(addr);
    let outbound = OutboundNetworkRow::new(target, b"queued until reachable".to_vec());

    network::enqueue_outbound(&store, std::slice::from_ref(&outbound))
        .expect("enqueue outbound row");
    let report = network::pump_outbound(&store, 16, 16).expect("pump unavailable target");

    assert_eq!(
        report,
        network::OutboundPumpReport {
            target_count: 1,
            sent_frames: 0,
            deferred_targets: 1,
        }
    );
    assert_eq!(
        network::claim_outbound_for_target(&store, target, 16).expect("claim queued row"),
        vec![outbound]
    );
    assert_eq!(
        network::queued_outbound_targets(&store, 16).expect("targets after deferred pump"),
        vec![target]
    );
}

fn read_length_prefixed_frame(stream: &mut std::net::TcpStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).expect("read frame length");
    let mut body = vec![0; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut body).expect("read frame body");
    body
}

use std::net::SocketAddr;

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
        network::claim_outbound_for_target(&store, target, 16).unwrap(),
        vec![outbound.clone()]
    );
    let later_outbound = OutboundNetworkRow::new(target, b"later target bytes".to_vec());
    network::enqueue_outbound(&store, std::slice::from_ref(&later_outbound)).unwrap();
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

    let reopened = Store::open_disk_with_schema_sources(&path, &[network::SCHEMA_SOURCE]).unwrap();
    assert!(
        network::claim_outbound_for_target(&reopened, target, 16)
            .unwrap()
            .is_empty(),
        "network rows are process-local IO staging, not restart-durable protocol truth"
    );
}

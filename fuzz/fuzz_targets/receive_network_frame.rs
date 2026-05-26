#![no_main]

use libfuzzer_sys::fuzz_target;
use topo::core::facts::FactScope;
use topo::protocol::connection::frame::create::{
    received_network_frame_effect, ReceivedNetworkFrame,
};
use topo::protocol::connection::{frame, receive_network_frame};

const ORIGIN_ADDR: &[u8] = b"127.0.0.1:40000";

fuzz_target!(|data: &[u8]| {
    let input = receive_network_frame::ReceiveNetworkFrame {
        frame: data.to_vec(),
        origin_addr: ORIGIN_ADDR.to_vec(),
        received_at_local_ms: timestamp(data),
    };
    if let Ok(intent) = receive_network_frame::receive_network_frame_intent(input) {
        let decoded = receive_network_frame::decode_receive_network_frame(&intent)
            .expect("encoded receive_network_frame intent should decode");
        assert_eq!(decoded.frame, data);
        assert_eq!(decoded.origin_addr, ORIGIN_ADDR);
    }

    let effects = received_network_frame_effect(ReceivedNetworkFrame {
        frame: data,
        origin_addr: ORIGIN_ADDR,
        received_at_local_ms: timestamp(data),
    })
    .expect("established-frame receive classifier should cleanly discard malformed bytes");

    assert!(effects.facts.is_empty());
    assert!(effects.purged_facts.is_empty());
    assert!(effects.row_mutations.is_empty());
    assert!(effects.intents.is_empty());
    assert!(effects.local_intents.is_empty());

    for fact in effects.ephemeral_facts {
        assert_eq!(fact.scope, FactScope::Local);
        frame::decode_fact_payload(fact.body()).expect("classified frame fact should decode");
    }
});

fn timestamp(data: &[u8]) -> u64 {
    let mut bytes = [0; 8];
    let len = data.len().min(bytes.len());
    bytes[..len].copy_from_slice(&data[..len]);
    u64::from_be_bytes(bytes)
}

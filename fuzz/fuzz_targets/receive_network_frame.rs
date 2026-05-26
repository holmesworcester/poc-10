#![no_main]

use libfuzzer_sys::fuzz_target;
use topo::core::facts::FactScope;
use topo::core::wire::FixedBytes;
use topo::protocol::connection::frame::create::{
    received_network_frame_effect, ReceivedNetworkFrame,
};
use topo::protocol::connection::frame::layout::{
    encode_frame_bytes, CONNECTION_FRAME_SIZE_CLASS_SMALL,
    CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES,
};
use topo::protocol::connection::{frame, receive_network_frame};

const ORIGIN_ADDR: &[u8] = b"127.0.0.1:40000";

fuzz_target!(|data: &[u8]| {
    exercise_network_frame(data, data);
    let synthesized = synthesized_small_frame(data);
    exercise_network_frame(&synthesized, data);
});

fn exercise_network_frame(frame_bytes: &[u8], entropy: &[u8]) {
    let input = receive_network_frame::ReceiveNetworkFrame {
        frame: frame_bytes.to_vec(),
        origin_addr: ORIGIN_ADDR.to_vec(),
        received_at_local_ms: timestamp(entropy),
    };
    if let Ok(intent) = receive_network_frame::receive_network_frame_intent(input) {
        let decoded = receive_network_frame::decode_receive_network_frame(&intent)
            .expect("encoded receive_network_frame intent should decode");
        assert_eq!(decoded.frame, frame_bytes);
        assert_eq!(decoded.origin_addr, ORIGIN_ADDR);
    }

    let effects = received_network_frame_effect(ReceivedNetworkFrame {
        frame: frame_bytes,
        origin_addr: ORIGIN_ADDR,
        received_at_local_ms: timestamp(entropy),
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
}

fn synthesized_small_frame(data: &[u8]) -> Vec<u8> {
    let connection_id = FixedBytes(array32(data, 0, 1));
    let nonce = FixedBytes(array24(data, 32, 2));
    let ciphertext_len =
        usize::from(data.first().copied().unwrap_or_default()) % (CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES + 1);
    let ciphertext = repeated_bytes(data, 56, ciphertext_len);
    encode_frame_bytes(
        CONNECTION_FRAME_SIZE_CLASS_SMALL,
        connection_id,
        nonce,
        &ciphertext,
    )
    .expect("synthetic small frame should encode")
}

fn array32(data: &[u8], offset: usize, salt: u8) -> [u8; 32] {
    let mut out = [salt; 32];
    fill_from(data, offset, &mut out);
    out
}

fn array24(data: &[u8], offset: usize, salt: u8) -> [u8; 24] {
    let mut out = [salt; 24];
    fill_from(data, offset, &mut out);
    out
}

fn repeated_bytes(data: &[u8], offset: usize, len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    fill_from(data, offset, &mut out);
    out
}

fn fill_from(data: &[u8], offset: usize, out: &mut [u8]) {
    if data.is_empty() {
        return;
    }
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = data[(offset + index) % data.len()];
    }
}

fn timestamp(data: &[u8]) -> u64 {
    let mut bytes = [0; 8];
    let len = data.len().min(bytes.len());
    bytes[..len].copy_from_slice(&data[..len]);
    u64::from_be_bytes(bytes)
}

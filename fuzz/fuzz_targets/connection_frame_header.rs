#![no_main]

use libfuzzer_sys::fuzz_target;
use topo::core::wire::FixedBytes;
use topo::core::wire::FixedLayout;
use topo::protocol::connection::frame::layout::{
    self, ConnectionFrameBundleV1, ConnectionFrameFileSliceV1, ConnectionFrameSmallV1,
    CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES, CONNECTION_FRAME_FILE_SLICE_CIPHERTEXT_BYTES,
    CONNECTION_FRAME_SIZE_CLASS_BUNDLE, CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE,
    CONNECTION_FRAME_SIZE_CLASS_SMALL, CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES,
};

fuzz_target!(|data: &[u8]| {
    exercise_frame_bytes(data);
    let synthesized = synthesized_small_frame(data);
    exercise_frame_bytes(&synthesized);
});

fn exercise_frame_bytes(bytes: &[u8]) {
    let _ = layout::peek_frame_header(bytes);
    let parts = layout::decode_frame_parts(bytes);
    let _ = ConnectionFrameSmallV1::decode(bytes);
    let _ = ConnectionFrameFileSliceV1::decode(bytes);
    let _ = ConnectionFrameBundleV1::decode(bytes);
    if let Ok(parts) = parts {
        let capacity = ciphertext_capacity(parts.header.size_class)
            .expect("decode_frame_parts only accepts registered size classes");
        assert!(parts.ciphertext.len() <= capacity);
    }
}

fn synthesized_small_frame(data: &[u8]) -> Vec<u8> {
    let connection_id = FixedBytes(array32(data, 0, 1));
    let nonce = FixedBytes(array24(data, 32, 2));
    let ciphertext_len =
        usize::from(data.first().copied().unwrap_or_default()) % (CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES + 1);
    let ciphertext = repeated_bytes(data, 56, ciphertext_len);
    let mut frame = layout::encode_frame_bytes(
        CONNECTION_FRAME_SIZE_CLASS_SMALL,
        connection_id,
        nonce,
        &ciphertext,
    )
    .expect("synthetic small frame should encode");
    if data.get(1).copied().unwrap_or_default() & 1 == 1 && frame.len() > 1 {
        let last = frame.len() - 1;
        frame[last] = frame[last].wrapping_add(1).max(1);
    }
    frame
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

fn ciphertext_capacity(size_class: u8) -> Option<usize> {
    match size_class {
        CONNECTION_FRAME_SIZE_CLASS_SMALL => Some(CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES),
        CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE => {
            Some(CONNECTION_FRAME_FILE_SLICE_CIPHERTEXT_BYTES)
        }
        CONNECTION_FRAME_SIZE_CLASS_BUNDLE => Some(CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES),
        _ => None,
    }
}

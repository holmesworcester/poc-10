#![no_main]

use libfuzzer_sys::fuzz_target;
use topo::core::wire::FixedLayout;
use topo::protocol::connection::frame::layout::{
    self, ConnectionFrameBundleV1, ConnectionFrameFileSliceV1, ConnectionFrameSmallV1,
    CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES, CONNECTION_FRAME_FILE_SLICE_CIPHERTEXT_BYTES,
    CONNECTION_FRAME_SIZE_CLASS_BUNDLE, CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE,
    CONNECTION_FRAME_SIZE_CLASS_SMALL, CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES,
};

fuzz_target!(|data: &[u8]| {
    let _ = layout::peek_frame_header(data);
    let parts = layout::decode_frame_parts(data);
    let _ = ConnectionFrameSmallV1::decode(data);
    let _ = ConnectionFrameFileSliceV1::decode(data);
    let _ = ConnectionFrameBundleV1::decode(data);

    if let Ok(parts) = parts {
        let capacity = ciphertext_capacity(parts.header.size_class)
            .expect("decode_frame_parts only accepts registered size classes");
        assert!(parts.ciphertext.len() <= capacity);
    }
});

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

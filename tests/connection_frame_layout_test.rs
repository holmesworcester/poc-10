//! Golden-bytes tests for the fixed connection::frame frame layouts.
//!
//! These tests lock the public header byte layout, the size-class discriminator,
//! and the rejection behaviour for wrong-length, trailing-byte, and mismatched
//! size-class inputs.

use topo::core::crypto::{XCHACHA20_POLY1305_NONCE_BYTES, XCHACHA20_POLY1305_TAG_BYTES};
use topo::core::wire::{Ciphertext, FixedBytes, FixedLayout, WireError};
use topo::protocol::connection::frame::frame::{
    self as connection_frame, ConnectionFrameFactBundle, SealConnectionFrame,
};
use topo::protocol::connection::frame::layout::{
    decode_frame_parts, peek_frame_header, ConnectionFrameBundleV1, ConnectionFrameFileSliceV1,
    ConnectionFrameHeader, ConnectionFrameSmallV1, CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES,
    CONNECTION_FRAME_BUNDLE_FACT_SLOTS, CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES,
    CONNECTION_FRAME_BUNDLE_PLAINTEXT_BYTES, CONNECTION_FRAME_BUNDLE_WIRE_BYTES,
    CONNECTION_FRAME_FILE_SLICE_CIPHERTEXT_BYTES, CONNECTION_FRAME_FILE_SLICE_PLAINTEXT_BYTES,
    CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES, CONNECTION_FRAME_HEADER_BYTES,
    CONNECTION_FRAME_SIZE_CLASS_BUNDLE, CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE,
    CONNECTION_FRAME_SIZE_CLASS_SMALL, CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES,
    CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES, CONNECTION_FRAME_SMALL_WIRE_BYTES,
    CONNECTION_FRAME_TAG, CONNECTION_FRAME_VERSION,
};
use topo::protocol::content::file::layout::CONTENT_FILE_BYTES;
use topo::protocol::content::file_slice::layout::CONTENT_FILE_SLICE_BYTES;

const SENDER: [u8; 32] = [0x11; 32];
const RECEIVER: [u8; 32] = [0x22; 32];
const CONNECTION: [u8; 32] = [0x33; 32];
const NONCE: [u8; XCHACHA20_POLY1305_NONCE_BYTES] = [0x44; XCHACHA20_POLY1305_NONCE_BYTES];
const SECRET: [u8; 32] = [0x66; 32];

fn small_sample() -> ConnectionFrameSmallV1 {
    ConnectionFrameSmallV1 {
        sender_endpoint_id: FixedBytes(SENDER),
        receiver_endpoint_id: FixedBytes(RECEIVER),
        connection_id: FixedBytes(CONNECTION),
        nonce: FixedBytes(NONCE),
        ciphertext: Ciphertext::<CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES>::new(b"hello small")
            .unwrap(),
    }
}

/// Runs a closure on a fresh thread with a larger stack so file-slice frame
/// values can be materialized without overflowing the default test stack.
fn on_big_stack<F>(f: F)
where
    F: FnOnce() + Send + 'static,
{
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

fn file_slice_sample() -> Box<ConnectionFrameFileSliceV1> {
    Box::new(ConnectionFrameFileSliceV1 {
        sender_endpoint_id: FixedBytes(SENDER),
        receiver_endpoint_id: FixedBytes(RECEIVER),
        connection_id: FixedBytes(CONNECTION),
        nonce: FixedBytes(NONCE),
        ciphertext: Ciphertext::<CONNECTION_FRAME_FILE_SLICE_CIPHERTEXT_BYTES>::new(
            b"hello file slice",
        )
        .unwrap(),
    })
}

fn bundle_sample() -> ConnectionFrameBundleV1 {
    ConnectionFrameBundleV1 {
        sender_endpoint_id: FixedBytes(SENDER),
        receiver_endpoint_id: FixedBytes(RECEIVER),
        connection_id: FixedBytes(CONNECTION),
        nonce: FixedBytes(NONCE),
        ciphertext: Ciphertext::<CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES>::new(b"hello bundle")
            .unwrap(),
    }
}

#[test]
fn connection_frame_constants_match_architecture_shape() {
    assert_eq!(CONNECTION_FRAME_HEADER_BYTES, 4 + 1 + 1 + 32 + 32 + 32 + 24);
    assert_eq!(CONNECTION_FRAME_VERSION, 1);
    assert_eq!(CONNECTION_FRAME_SIZE_CLASS_SMALL, 0);
    assert_eq!(CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE, 1);
    assert_eq!(CONNECTION_FRAME_SIZE_CLASS_BUNDLE, 2);

    assert_eq!(CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES, 4 * 1024);
    assert_eq!(
        CONNECTION_FRAME_FILE_SLICE_PLAINTEXT_BYTES,
        4 + 1 + 4 + 4 + CONTENT_FILE_SLICE_BYTES
    );
    assert_eq!(CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES, CONTENT_FILE_BYTES);
    assert!(CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES >= CONTENT_FILE_BYTES);
    assert_eq!(
        CONNECTION_FRAME_BUNDLE_FACT_SLOTS,
        (64 * 1024 - (4 + 1 + 4)) / (4 + CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES)
    );
    assert_eq!(
        CONNECTION_FRAME_BUNDLE_PLAINTEXT_BYTES,
        4 + 1
            + 4
            + CONNECTION_FRAME_BUNDLE_FACT_SLOTS * (4 + CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES)
    );
    assert!(CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES < CONNECTION_FRAME_BUNDLE_PLAINTEXT_BYTES);
    assert!(CONNECTION_FRAME_BUNDLE_PLAINTEXT_BYTES < 64 * 1024);
    assert!(CONNECTION_FRAME_BUNDLE_PLAINTEXT_BYTES < CONNECTION_FRAME_FILE_SLICE_PLAINTEXT_BYTES);

    assert_eq!(
        CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES,
        CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES
    );
    assert_eq!(
        CONNECTION_FRAME_FILE_SLICE_CIPHERTEXT_BYTES,
        CONNECTION_FRAME_FILE_SLICE_PLAINTEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES
    );
    assert_eq!(
        CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES,
        CONNECTION_FRAME_BUNDLE_PLAINTEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES
    );

    assert_eq!(
        CONNECTION_FRAME_SMALL_WIRE_BYTES,
        CONNECTION_FRAME_HEADER_BYTES + 4 + CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES
    );
    assert_eq!(
        CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES,
        CONNECTION_FRAME_HEADER_BYTES + 4 + CONNECTION_FRAME_FILE_SLICE_CIPHERTEXT_BYTES
    );
    assert_eq!(
        CONNECTION_FRAME_BUNDLE_WIRE_BYTES,
        CONNECTION_FRAME_HEADER_BYTES + 4 + CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES
    );

    assert_eq!(
        ConnectionFrameSmallV1::LEN,
        CONNECTION_FRAME_SMALL_WIRE_BYTES
    );
    assert_eq!(
        ConnectionFrameFileSliceV1::LEN,
        CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES
    );
    assert_eq!(
        ConnectionFrameBundleV1::LEN,
        CONNECTION_FRAME_BUNDLE_WIRE_BYTES
    );

    // Outer length reveals only the size class.
    assert_ne!(
        CONNECTION_FRAME_SMALL_WIRE_BYTES,
        CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES
    );
}

#[test]
fn small_frame_header_has_golden_byte_layout() {
    let frame = small_sample();
    let mut out = vec![0u8; ConnectionFrameSmallV1::LEN];
    frame.encode(&mut out).unwrap();

    // Tag.
    assert_eq!(&out[..4], CONNECTION_FRAME_TAG.0.as_slice());
    assert_eq!(&out[..4], b"TRNS");
    // Version + size class.
    assert_eq!(out[4], CONNECTION_FRAME_VERSION);
    assert_eq!(out[5], CONNECTION_FRAME_SIZE_CLASS_SMALL);
    // Addressing fields.
    assert_eq!(&out[6..38], &SENDER);
    assert_eq!(&out[38..70], &RECEIVER);
    assert_eq!(&out[70..102], &CONNECTION);
    // Nonce.
    assert_eq!(&out[102..126], &NONCE);
    // Inner ciphertext length prefix (FixedSlot writes u32be length first).
    let inner_len = u32::from_be_bytes(out[126..130].try_into().unwrap()) as usize;
    assert_eq!(inner_len, "hello small".len());
    assert_eq!(&out[130..130 + inner_len], b"hello small");
}

#[test]
fn file_slice_frame_header_uses_file_slice_size_class_byte() {
    on_big_stack(|| {
        let frame = file_slice_sample();
        let mut out = vec![0u8; ConnectionFrameFileSliceV1::LEN];
        frame.encode(&mut out).unwrap();

        assert_eq!(&out[..4], b"TRNS");
        assert_eq!(out[4], CONNECTION_FRAME_VERSION);
        assert_eq!(out[5], CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE);
        assert_eq!(&out[6..38], &SENDER);
        assert_eq!(&out[38..70], &RECEIVER);
        assert_eq!(&out[70..102], &CONNECTION);
        assert_eq!(&out[102..126], &NONCE);
    });
}

#[test]
fn bundle_frame_header_uses_bundle_size_class_byte() {
    let frame = bundle_sample();
    let mut out = vec![0u8; ConnectionFrameBundleV1::LEN];
    frame.encode(&mut out).unwrap();

    assert_eq!(&out[..4], b"TRNS");
    assert_eq!(out[4], CONNECTION_FRAME_VERSION);
    assert_eq!(out[5], CONNECTION_FRAME_SIZE_CLASS_BUNDLE);
    assert_eq!(&out[6..38], &SENDER);
    assert_eq!(&out[38..70], &RECEIVER);
    assert_eq!(&out[70..102], &CONNECTION);
    assert_eq!(&out[102..126], &NONCE);
}

#[test]
fn connection_frames_round_trip() {
    let small = small_sample();
    let mut small_bytes = vec![0u8; ConnectionFrameSmallV1::LEN];
    small.encode(&mut small_bytes).unwrap();
    assert_eq!(ConnectionFrameSmallV1::decode(&small_bytes).unwrap(), small);

    on_big_stack(|| {
        let file_slice = file_slice_sample();
        let mut file_slice_bytes = vec![0u8; ConnectionFrameFileSliceV1::LEN];
        file_slice.encode(&mut file_slice_bytes).unwrap();
        let decoded = ConnectionFrameFileSliceV1::decode(&file_slice_bytes).unwrap();
        assert_eq!(&decoded, file_slice.as_ref());
    });

    let bundle = bundle_sample();
    let mut bundle_bytes = vec![0u8; ConnectionFrameBundleV1::LEN];
    bundle.encode(&mut bundle_bytes).unwrap();
    assert_eq!(
        ConnectionFrameBundleV1::decode(&bundle_bytes).unwrap(),
        bundle
    );
}

#[test]
fn wrong_outer_length_is_rejected() {
    // Trailing byte.
    let small = small_sample();
    let mut buf = vec![0u8; ConnectionFrameSmallV1::LEN];
    small.encode(&mut buf).unwrap();
    buf.push(0);
    assert_eq!(
        ConnectionFrameSmallV1::decode(&buf).unwrap_err(),
        WireError::WrongLength {
            expected: ConnectionFrameSmallV1::LEN,
            actual: ConnectionFrameSmallV1::LEN + 1,
        }
    );

    // Missing byte.
    let mut buf = vec![0u8; ConnectionFrameSmallV1::LEN];
    small.encode(&mut buf).unwrap();
    buf.pop();
    assert_eq!(
        ConnectionFrameSmallV1::decode(&buf).unwrap_err(),
        WireError::WrongLength {
            expected: ConnectionFrameSmallV1::LEN,
            actual: ConnectionFrameSmallV1::LEN - 1,
        }
    );

    // Encode with wrong-sized buffer.
    let mut short = vec![0u8; ConnectionFrameSmallV1::LEN - 1];
    assert_eq!(
        small.encode(&mut short).unwrap_err(),
        WireError::WrongLength {
            expected: ConnectionFrameSmallV1::LEN,
            actual: ConnectionFrameSmallV1::LEN - 1,
        }
    );
}

#[test]
fn small_bytes_decode_fails_against_bundle_frame() {
    let small = small_sample();
    let mut buf = vec![0u8; ConnectionFrameSmallV1::LEN];
    small.encode(&mut buf).unwrap();
    assert_eq!(
        ConnectionFrameBundleV1::decode(&buf).unwrap_err(),
        WireError::WrongLength {
            expected: ConnectionFrameBundleV1::LEN,
            actual: ConnectionFrameSmallV1::LEN,
        }
    );
}

#[test]
fn mismatched_size_class_byte_is_rejected() {
    // Build a small-sized buffer but stamp the bundle size-class byte into it.
    let small = small_sample();
    let mut buf = vec![0u8; ConnectionFrameSmallV1::LEN];
    small.encode(&mut buf).unwrap();
    buf[5] = CONNECTION_FRAME_SIZE_CLASS_BUNDLE;
    assert_eq!(
        ConnectionFrameSmallV1::decode(&buf).unwrap_err(),
        WireError::InvalidBool {
            actual: CONNECTION_FRAME_SIZE_CLASS_BUNDLE
        }
    );

    // And the reverse: stamp the small size-class byte into a bundle buffer.
    let bundle = bundle_sample();
    let mut buf = vec![0u8; ConnectionFrameBundleV1::LEN];
    bundle.encode(&mut buf).unwrap();
    buf[5] = CONNECTION_FRAME_SIZE_CLASS_SMALL;
    assert_eq!(
        ConnectionFrameBundleV1::decode(&buf).unwrap_err(),
        WireError::InvalidBool {
            actual: CONNECTION_FRAME_SIZE_CLASS_SMALL
        }
    );

    // File-slice frames have their own size-class byte too.
    on_big_stack(|| {
        let file_slice = file_slice_sample();
        let mut buf = vec![0u8; ConnectionFrameFileSliceV1::LEN];
        file_slice.encode(&mut buf).unwrap();
        buf[5] = CONNECTION_FRAME_SIZE_CLASS_BUNDLE;
        assert_eq!(
            ConnectionFrameFileSliceV1::decode(&buf).unwrap_err(),
            WireError::InvalidBool {
                actual: CONNECTION_FRAME_SIZE_CLASS_BUNDLE
            }
        );
    });
}

#[test]
fn wrong_frame_tag_is_rejected() {
    let small = small_sample();
    let mut buf = vec![0u8; ConnectionFrameSmallV1::LEN];
    small.encode(&mut buf).unwrap();
    buf[0] = b'X';
    assert!(matches!(
        ConnectionFrameSmallV1::decode(&buf).unwrap_err(),
        WireError::NonZeroPadding { index: 0 }
    ));
}

#[test]
fn wrong_version_byte_is_rejected() {
    let small = small_sample();
    let mut buf = vec![0u8; ConnectionFrameSmallV1::LEN];
    small.encode(&mut buf).unwrap();
    buf[4] = CONNECTION_FRAME_VERSION + 1;
    assert!(matches!(
        ConnectionFrameSmallV1::decode(&buf).unwrap_err(),
        WireError::InvalidBool { .. }
    ));
}

#[test]
fn peek_header_recovers_addressing_without_decrypting() {
    let small = small_sample();
    let mut buf = vec![0u8; ConnectionFrameSmallV1::LEN];
    small.encode(&mut buf).unwrap();

    let header = peek_frame_header(&buf).unwrap();
    assert_eq!(
        header,
        ConnectionFrameHeader {
            size_class: CONNECTION_FRAME_SIZE_CLASS_SMALL,
            sender_endpoint_id: FixedBytes(SENDER),
            receiver_endpoint_id: FixedBytes(RECEIVER),
            connection_id: FixedBytes(CONNECTION),
            nonce: FixedBytes(NONCE),
        }
    );

    // Peeking only needs the header bytes.
    let header_only = peek_frame_header(&buf[..CONNECTION_FRAME_HEADER_BYTES]).unwrap();
    assert_eq!(header_only.size_class, CONNECTION_FRAME_SIZE_CLASS_SMALL);

    // Short buffers are rejected.
    assert!(matches!(
        peek_frame_header(&buf[..CONNECTION_FRAME_HEADER_BYTES - 1]).unwrap_err(),
        WireError::WrongLength { .. }
    ));
}

#[test]
fn ciphertext_slot_capacity_accepts_full_plaintext_plus_aead_tag() {
    let payload = vec![0xaa; CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES];
    let frame = ConnectionFrameSmallV1 {
        sender_endpoint_id: FixedBytes(SENDER),
        receiver_endpoint_id: FixedBytes(RECEIVER),
        connection_id: FixedBytes(CONNECTION),
        nonce: FixedBytes(NONCE),
        ciphertext: Ciphertext::<CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES>::new(&payload).unwrap(),
    };
    let mut buf = vec![0u8; ConnectionFrameSmallV1::LEN];
    frame.encode(&mut buf).unwrap();
    let decoded = ConnectionFrameSmallV1::decode(&buf).unwrap();
    assert_eq!(decoded.ciphertext.bytes(), payload.as_slice());

    // Overflow is rejected at construction.
    let oversize = vec![0; CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES + 1];
    assert!(matches!(
        Ciphertext::<CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES>::new(&oversize).unwrap_err(),
        WireError::ValueTooLarge { .. }
    ));
}

#[test]
fn sealed_small_connection_frame_fills_fixed_ciphertext_slot() {
    let frame = connection_frame::seal_connection_frame(SealConnectionFrame {
        connection_id: CONNECTION,
        sender_endpoint_id: SENDER,
        receiver_endpoint_id: RECEIVER,
        connection_secret: SECRET,
        nonce: NONCE,
        facts: ConnectionFrameFactBundle::from_bytes([b"alpha".to_vec(), b"beta".to_vec()]),
    })
    .expect("seal small frame");

    assert_eq!(frame.len(), CONNECTION_FRAME_SMALL_WIRE_BYTES);
    let parts = decode_frame_parts(&frame).expect("decode frame parts");
    assert_eq!(parts.header.size_class, CONNECTION_FRAME_SIZE_CLASS_SMALL);
    assert_eq!(
        parts.ciphertext.len(),
        CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES
    );

    let opened = connection_frame::open_connection_frame(&frame, &SECRET)
        .expect("open small connection::frame frame");
    assert_eq!(
        opened.facts.into_iter().collect::<Vec<_>>(),
        vec![b"alpha".to_vec(), b"beta".to_vec()]
    );
}

#[test]
fn sealed_bundle_connection_frame_fills_fixed_ciphertext_slot() {
    let facts = (0..7)
        .map(|index| vec![index; CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES])
        .collect::<Vec<_>>();
    let frame = connection_frame::seal_connection_frame(SealConnectionFrame {
        connection_id: CONNECTION,
        sender_endpoint_id: SENDER,
        receiver_endpoint_id: RECEIVER,
        connection_secret: SECRET,
        nonce: NONCE,
        facts: ConnectionFrameFactBundle::from_bytes(facts.clone()),
    })
    .expect("seal bundle frame");

    assert_eq!(frame.len(), CONNECTION_FRAME_BUNDLE_WIRE_BYTES);
    let parts = decode_frame_parts(&frame).expect("decode frame parts");
    assert_eq!(parts.header.size_class, CONNECTION_FRAME_SIZE_CLASS_BUNDLE);
    assert_eq!(
        parts.ciphertext.len(),
        CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES
    );

    let opened = connection_frame::open_connection_frame(&frame, &SECRET)
        .expect("open bundle connection::frame frame");
    assert_eq!(opened.facts.into_iter().collect::<Vec<_>>(), facts);
}

#[test]
fn sealed_file_slice_connection_frame_fills_fixed_ciphertext_slot() {
    on_big_stack(|| {
        let file_slice_fact = vec![0x77; CONTENT_FILE_SLICE_BYTES];
        let frame = connection_frame::seal_connection_frame(SealConnectionFrame {
            connection_id: CONNECTION,
            sender_endpoint_id: SENDER,
            receiver_endpoint_id: RECEIVER,
            connection_secret: SECRET,
            nonce: NONCE,
            facts: ConnectionFrameFactBundle::from_bytes([file_slice_fact.clone()]),
        })
        .expect("seal file-slice frame");

        assert_eq!(frame.len(), CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES);
        let parts = decode_frame_parts(&frame).expect("decode frame parts");
        assert_eq!(
            parts.header.size_class,
            CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE
        );
        assert_eq!(
            parts.ciphertext.len(),
            CONNECTION_FRAME_FILE_SLICE_CIPHERTEXT_BYTES
        );

        let opened = connection_frame::open_connection_frame(&frame, &SECRET)
            .expect("open file-slice connection::frame frame");
        assert_eq!(
            opened.facts.into_iter().collect::<Vec<_>>(),
            vec![file_slice_fact]
        );
    });
}

#[test]
fn opening_rejects_variable_length_ciphertext_slot() {
    let frame = topo::protocol::connection::frame::layout::encode_frame_bytes(
        CONNECTION_FRAME_SIZE_CLASS_SMALL,
        FixedBytes(SENDER),
        FixedBytes(RECEIVER),
        FixedBytes(CONNECTION),
        FixedBytes(NONCE),
        b"short ciphertext",
    )
    .expect("variable slot frame");

    let err = connection_frame::open_connection_frame(&frame, &SECRET)
        .expect_err("open rejects unfilled fixed ciphertext slot");
    assert!(err.contains("fixed slot"), "{err}");
}

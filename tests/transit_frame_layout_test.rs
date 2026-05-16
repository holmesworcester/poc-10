//! Golden-bytes tests for the fixed transit frame layouts.
//!
//! These tests lock the public header byte layout, the size-class discriminator,
//! and the rejection behaviour for wrong-length, trailing-byte, and mismatched
//! size-class inputs.

use topo::core::crypto::{XCHACHA20_POLY1305_NONCE_BYTES, XCHACHA20_POLY1305_TAG_BYTES};
use topo::core::wire::{Ciphertext, FixedBytes, FixedLayout, WireError};
use topo::event_modules::transit::frame::{
    self as transit_frame, SealConnectionFrame, TransitFactBundle,
};
use topo::event_modules::transit::layout::{
    decode_frame_parts, peek_frame_header, TransitFrameHeader, TransitLargeV1, TransitSmallV1,
    TRANSIT_FRAME_SIZE_CLASS_LARGE, TRANSIT_FRAME_SIZE_CLASS_SMALL, TRANSIT_FRAME_TAG,
    TRANSIT_FRAME_VERSION, TRANSIT_HEADER_BYTES, TRANSIT_LARGE_CIPHERTEXT_BYTES,
    TRANSIT_LARGE_PLAINTEXT_BYTES, TRANSIT_LARGE_WIRE_BYTES, TRANSIT_SMALL_CIPHERTEXT_BYTES,
    TRANSIT_SMALL_PLAINTEXT_BYTES, TRANSIT_SMALL_WIRE_BYTES,
};

const SENDER: [u8; 32] = [0x11; 32];
const RECEIVER: [u8; 32] = [0x22; 32];
const CONNECTION: [u8; 32] = [0x33; 32];
const NONCE: [u8; XCHACHA20_POLY1305_NONCE_BYTES] = [0x44; XCHACHA20_POLY1305_NONCE_BYTES];
const SECRET: [u8; 32] = [0x66; 32];

fn small_sample() -> TransitSmallV1 {
    TransitSmallV1 {
        sender_endpoint_id: FixedBytes(SENDER),
        receiver_endpoint_id: FixedBytes(RECEIVER),
        connection_id: FixedBytes(CONNECTION),
        nonce: FixedBytes(NONCE),
        ciphertext: Ciphertext::<TRANSIT_SMALL_CIPHERTEXT_BYTES>::new(b"hello small").unwrap(),
    }
}

/// Runs a closure on a fresh thread with an 8 MiB stack so that large frame
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

fn large_sample() -> Box<TransitLargeV1> {
    Box::new(TransitLargeV1 {
        sender_endpoint_id: FixedBytes(SENDER),
        receiver_endpoint_id: FixedBytes(RECEIVER),
        connection_id: FixedBytes(CONNECTION),
        nonce: FixedBytes(NONCE),
        ciphertext: Ciphertext::<TRANSIT_LARGE_CIPHERTEXT_BYTES>::new(b"hello large").unwrap(),
    })
}

#[test]
fn transit_frame_constants_match_architecture_shape() {
    assert_eq!(TRANSIT_HEADER_BYTES, 4 + 1 + 1 + 32 + 32 + 32 + 24);
    assert_eq!(TRANSIT_FRAME_VERSION, 1);
    assert_eq!(TRANSIT_FRAME_SIZE_CLASS_SMALL, 0);
    assert_eq!(TRANSIT_FRAME_SIZE_CLASS_LARGE, 1);

    assert_eq!(TRANSIT_SMALL_PLAINTEXT_BYTES, 4 * 1024);
    assert_eq!(TRANSIT_LARGE_PLAINTEXT_BYTES, 1024 * 1024);

    assert_eq!(
        TRANSIT_SMALL_CIPHERTEXT_BYTES,
        TRANSIT_SMALL_PLAINTEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES
    );
    assert_eq!(
        TRANSIT_LARGE_CIPHERTEXT_BYTES,
        TRANSIT_LARGE_PLAINTEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES
    );

    assert_eq!(
        TRANSIT_SMALL_WIRE_BYTES,
        TRANSIT_HEADER_BYTES + 4 + TRANSIT_SMALL_CIPHERTEXT_BYTES
    );
    assert_eq!(
        TRANSIT_LARGE_WIRE_BYTES,
        TRANSIT_HEADER_BYTES + 4 + TRANSIT_LARGE_CIPHERTEXT_BYTES
    );

    assert_eq!(TransitSmallV1::LEN, TRANSIT_SMALL_WIRE_BYTES);
    assert_eq!(TransitLargeV1::LEN, TRANSIT_LARGE_WIRE_BYTES);

    // Outer length reveals only the size class.
    assert_ne!(TRANSIT_SMALL_WIRE_BYTES, TRANSIT_LARGE_WIRE_BYTES);
}

#[test]
fn small_frame_header_has_golden_byte_layout() {
    let frame = small_sample();
    let mut out = vec![0u8; TransitSmallV1::LEN];
    frame.encode(&mut out).unwrap();

    // Tag.
    assert_eq!(&out[..4], TRANSIT_FRAME_TAG.0.as_slice());
    assert_eq!(&out[..4], b"TRNS");
    // Version + size class.
    assert_eq!(out[4], TRANSIT_FRAME_VERSION);
    assert_eq!(out[5], TRANSIT_FRAME_SIZE_CLASS_SMALL);
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
fn large_frame_header_uses_large_size_class_byte() {
    on_big_stack(|| {
        let frame = large_sample();
        let mut out = vec![0u8; TransitLargeV1::LEN];
        frame.encode(&mut out).unwrap();

        assert_eq!(&out[..4], b"TRNS");
        assert_eq!(out[4], TRANSIT_FRAME_VERSION);
        assert_eq!(out[5], TRANSIT_FRAME_SIZE_CLASS_LARGE);
        assert_eq!(&out[6..38], &SENDER);
        assert_eq!(&out[38..70], &RECEIVER);
        assert_eq!(&out[70..102], &CONNECTION);
        assert_eq!(&out[102..126], &NONCE);
    });
}

#[test]
fn transit_frames_round_trip() {
    let small = small_sample();
    let mut small_bytes = vec![0u8; TransitSmallV1::LEN];
    small.encode(&mut small_bytes).unwrap();
    assert_eq!(TransitSmallV1::decode(&small_bytes).unwrap(), small);

    on_big_stack(|| {
        let large = large_sample();
        let mut large_bytes = vec![0u8; TransitLargeV1::LEN];
        large.encode(&mut large_bytes).unwrap();
        let decoded = TransitLargeV1::decode(&large_bytes).unwrap();
        assert_eq!(&decoded, large.as_ref());
    });
}

#[test]
fn wrong_outer_length_is_rejected() {
    // Trailing byte.
    let small = small_sample();
    let mut buf = vec![0u8; TransitSmallV1::LEN];
    small.encode(&mut buf).unwrap();
    buf.push(0);
    assert_eq!(
        TransitSmallV1::decode(&buf).unwrap_err(),
        WireError::WrongLength {
            expected: TransitSmallV1::LEN,
            actual: TransitSmallV1::LEN + 1,
        }
    );

    // Missing byte.
    let mut buf = vec![0u8; TransitSmallV1::LEN];
    small.encode(&mut buf).unwrap();
    buf.pop();
    assert_eq!(
        TransitSmallV1::decode(&buf).unwrap_err(),
        WireError::WrongLength {
            expected: TransitSmallV1::LEN,
            actual: TransitSmallV1::LEN - 1,
        }
    );

    // Encode with wrong-sized buffer.
    let mut short = vec![0u8; TransitSmallV1::LEN - 1];
    assert_eq!(
        small.encode(&mut short).unwrap_err(),
        WireError::WrongLength {
            expected: TransitSmallV1::LEN,
            actual: TransitSmallV1::LEN - 1,
        }
    );
}

#[test]
fn small_bytes_decode_fails_against_large_frame() {
    let small = small_sample();
    let mut buf = vec![0u8; TransitSmallV1::LEN];
    small.encode(&mut buf).unwrap();
    // Feeding small bytes to the large decoder must fail on length. The large
    // decoder materializes a TransitLargeV1 on the success path, so run on a
    // larger stack to avoid blowing the default test thread stack.
    on_big_stack(move || {
        assert_eq!(
            TransitLargeV1::decode(&buf).unwrap_err(),
            WireError::WrongLength {
                expected: TransitLargeV1::LEN,
                actual: TransitSmallV1::LEN,
            }
        );
    });
}

#[test]
fn mismatched_size_class_byte_is_rejected() {
    // Build a small-sized buffer but stamp the large size-class byte into it.
    let small = small_sample();
    let mut buf = vec![0u8; TransitSmallV1::LEN];
    small.encode(&mut buf).unwrap();
    buf[5] = TRANSIT_FRAME_SIZE_CLASS_LARGE;
    assert_eq!(
        TransitSmallV1::decode(&buf).unwrap_err(),
        WireError::InvalidBool {
            actual: TRANSIT_FRAME_SIZE_CLASS_LARGE
        }
    );

    // And the reverse: stamp the small size-class byte into a large buffer.
    on_big_stack(|| {
        let large = large_sample();
        let mut buf = vec![0u8; TransitLargeV1::LEN];
        large.encode(&mut buf).unwrap();
        buf[5] = TRANSIT_FRAME_SIZE_CLASS_SMALL;
        assert_eq!(
            TransitLargeV1::decode(&buf).unwrap_err(),
            WireError::InvalidBool {
                actual: TRANSIT_FRAME_SIZE_CLASS_SMALL
            }
        );
    });
}

#[test]
fn wrong_frame_tag_is_rejected() {
    let small = small_sample();
    let mut buf = vec![0u8; TransitSmallV1::LEN];
    small.encode(&mut buf).unwrap();
    buf[0] = b'X';
    assert!(matches!(
        TransitSmallV1::decode(&buf).unwrap_err(),
        WireError::NonZeroPadding { index: 0 }
    ));
}

#[test]
fn wrong_version_byte_is_rejected() {
    let small = small_sample();
    let mut buf = vec![0u8; TransitSmallV1::LEN];
    small.encode(&mut buf).unwrap();
    buf[4] = TRANSIT_FRAME_VERSION + 1;
    assert!(matches!(
        TransitSmallV1::decode(&buf).unwrap_err(),
        WireError::InvalidBool { .. }
    ));
}

#[test]
fn peek_header_recovers_addressing_without_decrypting() {
    let small = small_sample();
    let mut buf = vec![0u8; TransitSmallV1::LEN];
    small.encode(&mut buf).unwrap();

    let header = peek_frame_header(&buf).unwrap();
    assert_eq!(
        header,
        TransitFrameHeader {
            size_class: TRANSIT_FRAME_SIZE_CLASS_SMALL,
            sender_endpoint_id: FixedBytes(SENDER),
            receiver_endpoint_id: FixedBytes(RECEIVER),
            connection_id: FixedBytes(CONNECTION),
            nonce: FixedBytes(NONCE),
        }
    );

    // Peeking only needs the header bytes.
    let header_only = peek_frame_header(&buf[..TRANSIT_HEADER_BYTES]).unwrap();
    assert_eq!(header_only.size_class, TRANSIT_FRAME_SIZE_CLASS_SMALL);

    // Short buffers are rejected.
    assert!(matches!(
        peek_frame_header(&buf[..TRANSIT_HEADER_BYTES - 1]).unwrap_err(),
        WireError::WrongLength { .. }
    ));
}

#[test]
fn ciphertext_slot_capacity_accepts_full_plaintext_plus_aead_tag() {
    let payload = vec![0xaa; TRANSIT_SMALL_CIPHERTEXT_BYTES];
    let frame = TransitSmallV1 {
        sender_endpoint_id: FixedBytes(SENDER),
        receiver_endpoint_id: FixedBytes(RECEIVER),
        connection_id: FixedBytes(CONNECTION),
        nonce: FixedBytes(NONCE),
        ciphertext: Ciphertext::<TRANSIT_SMALL_CIPHERTEXT_BYTES>::new(&payload).unwrap(),
    };
    let mut buf = vec![0u8; TransitSmallV1::LEN];
    frame.encode(&mut buf).unwrap();
    let decoded = TransitSmallV1::decode(&buf).unwrap();
    assert_eq!(decoded.ciphertext.bytes(), payload.as_slice());

    // Overflow is rejected at construction.
    let oversize = vec![0; TRANSIT_SMALL_CIPHERTEXT_BYTES + 1];
    assert!(matches!(
        Ciphertext::<TRANSIT_SMALL_CIPHERTEXT_BYTES>::new(&oversize).unwrap_err(),
        WireError::ValueTooLarge { .. }
    ));
}

#[test]
fn sealed_small_connection_frame_fills_fixed_ciphertext_slot() {
    let frame = transit_frame::seal_connection_frame(SealConnectionFrame {
        connection_id: CONNECTION,
        sender_endpoint_id: SENDER,
        receiver_endpoint_id: RECEIVER,
        connection_secret: SECRET,
        nonce: NONCE,
        facts: TransitFactBundle::from_bytes([b"alpha".to_vec(), b"beta".to_vec()]),
    })
    .expect("seal small frame");

    assert_eq!(frame.len(), TRANSIT_SMALL_WIRE_BYTES);
    let parts = decode_frame_parts(&frame).expect("decode frame parts");
    assert_eq!(parts.header.size_class, TRANSIT_FRAME_SIZE_CLASS_SMALL);
    assert_eq!(parts.ciphertext.len(), TRANSIT_SMALL_CIPHERTEXT_BYTES);

    let opened =
        transit_frame::open_connection_frame(&frame, &SECRET).expect("open small transit frame");
    assert_eq!(
        opened.facts.into_iter().collect::<Vec<_>>(),
        vec![b"alpha".to_vec(), b"beta".to_vec()]
    );
}

#[test]
fn sealed_large_connection_frame_fills_fixed_ciphertext_slot() {
    on_big_stack(|| {
        let large_fact = vec![0x55; TRANSIT_SMALL_PLAINTEXT_BYTES];
        let frame = transit_frame::seal_connection_frame(SealConnectionFrame {
            connection_id: CONNECTION,
            sender_endpoint_id: SENDER,
            receiver_endpoint_id: RECEIVER,
            connection_secret: SECRET,
            nonce: NONCE,
            facts: TransitFactBundle::from_bytes([large_fact.clone()]),
        })
        .expect("seal large frame");

        assert_eq!(frame.len(), TRANSIT_LARGE_WIRE_BYTES);
        let parts = decode_frame_parts(&frame).expect("decode frame parts");
        assert_eq!(parts.header.size_class, TRANSIT_FRAME_SIZE_CLASS_LARGE);
        assert_eq!(parts.ciphertext.len(), TRANSIT_LARGE_CIPHERTEXT_BYTES);

        let opened = transit_frame::open_connection_frame(&frame, &SECRET)
            .expect("open large transit frame");
        assert_eq!(
            opened.facts.into_iter().collect::<Vec<_>>(),
            vec![large_fact]
        );
    });
}

#[test]
fn opening_rejects_variable_length_ciphertext_slot() {
    let frame = topo::event_modules::transit::layout::encode_frame_bytes(
        TRANSIT_FRAME_SIZE_CLASS_SMALL,
        FixedBytes(SENDER),
        FixedBytes(RECEIVER),
        FixedBytes(CONNECTION),
        FixedBytes(NONCE),
        b"short ciphertext",
    )
    .expect("variable slot frame");

    let err = transit_frame::open_connection_frame(&frame, &SECRET)
        .expect_err("open rejects unfilled fixed ciphertext slot");
    assert!(err.contains("fixed slot"), "{err}");
}

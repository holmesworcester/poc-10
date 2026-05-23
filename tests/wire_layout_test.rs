use topo::core::crypto::{
    HASH_BYTES, XCHACHA20_POLY1305_NONCE_BYTES, XCHACHA20_POLY1305_TAG_BYTES,
};
use topo::core::wire::{
    fixed_tag, put_bool8, put_u16be, put_u32be, put_u64be, put_u8, take_bool8, take_u16be,
    take_u32be, take_u64be, take_u8, Ciphertext, FixedBytes, FixedLayout, FixedSlot, Id32, Nonce24,
    Tag, WireError, U16_BYTES, U32_BYTES, U64_BYTES, U8_BYTES,
};
use topo::protocol::transport::connection_frame::layout::{
    CONNECTION_FRAME_LARGE_CIPHERTEXT_BYTES, CONNECTION_FRAME_LARGE_PLAINTEXT_BYTES,
    CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES, CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES,
};

#[test]
fn scalar_layouts_have_fixed_big_endian_golden_bytes() {
    assert_eq!(U8_BYTES, 1);
    assert_eq!(U16_BYTES, 2);
    assert_eq!(U32_BYTES, 4);
    assert_eq!(U64_BYTES, 8);

    let mut out = [0; U64_BYTES];

    put_u8(0xab, &mut out[..U8_BYTES]).unwrap();
    assert_eq!(&out[..U8_BYTES], &[0xab]);
    assert_eq!(take_u8(&out[..U8_BYTES]).unwrap(), 0xab);

    put_u16be(0x1234, &mut out[..U16_BYTES]).unwrap();
    assert_eq!(&out[..U16_BYTES], &[0x12, 0x34]);
    assert_eq!(take_u16be(&out[..U16_BYTES]).unwrap(), 0x1234);

    put_u32be(0x1234_5678, &mut out[..U32_BYTES]).unwrap();
    assert_eq!(&out[..U32_BYTES], &[0x12, 0x34, 0x56, 0x78]);
    assert_eq!(take_u32be(&out[..U32_BYTES]).unwrap(), 0x1234_5678);

    put_u64be(0x1234_5678_9abc_def0, &mut out).unwrap();
    assert_eq!(&out, &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
    assert_eq!(take_u64be(&out).unwrap(), 0x1234_5678_9abc_def0);

    put_bool8(true, &mut out[..U8_BYTES]).unwrap();
    assert_eq!(&out[..U8_BYTES], &[1]);
    assert!(take_bool8(&out[..U8_BYTES]).unwrap());

    put_bool8(false, &mut out[..U8_BYTES]).unwrap();
    assert_eq!(&out[..U8_BYTES], &[0]);
    assert!(!take_bool8(&out[..U8_BYTES]).unwrap());
}

#[test]
fn fixed_bytes_lock_id_hash_key_signature_and_nonce_sizes() {
    assert_eq!(Id32::LEN, 32);
    assert_eq!(Nonce24::LEN, XCHACHA20_POLY1305_NONCE_BYTES);

    assert_fixed_bytes_golden::<32>(&[0x11; 32]);
    assert_fixed_bytes_golden::<{ HASH_BYTES }>(&[0x22; HASH_BYTES]);
    assert_fixed_bytes_golden::<{ XCHACHA20_POLY1305_NONCE_BYTES }>(
        &[0x66; XCHACHA20_POLY1305_NONCE_BYTES],
    );
}

#[test]
fn wrong_lengths_are_rejected_for_fixed_layout_decode_and_encode() {
    assert_eq!(
        Id32::decode(&[0; 31]).unwrap_err(),
        WireError::WrongLength {
            expected: 32,
            actual: 31
        }
    );
    assert_eq!(
        Id32::decode(&[0; 33]).unwrap_err(),
        WireError::WrongLength {
            expected: 32,
            actual: 33
        }
    );
    assert_eq!(
        take_u64be(&[0; 7]).unwrap_err(),
        WireError::WrongLength {
            expected: 8,
            actual: 7
        }
    );

    let value = FixedBytes([0xaa; HASH_BYTES]);
    let mut short = [0; HASH_BYTES - 1];
    assert_eq!(
        value.encode(&mut short).unwrap_err(),
        WireError::WrongLength {
            expected: HASH_BYTES,
            actual: HASH_BYTES - 1
        }
    );

    assert_eq!(
        take_bool8(&[2]).unwrap_err(),
        WireError::InvalidBool { actual: 2 }
    );
}

#[test]
fn tags_are_fixed_bytes_with_golden_layout() {
    const EVENT_TAG: Tag<4> = fixed_tag(b"EVT1");

    assert_eq!(Tag::<4>::LEN, 4);

    let mut out = [0; Tag::<4>::LEN];
    EVENT_TAG.encode(&mut out).unwrap();
    assert_eq!(&out, b"EVT1");
    assert_eq!(Tag::<4>::decode(&out).unwrap(), EVENT_TAG);

    assert_eq!(
        Tag::<4>::decode(b"EVT").unwrap_err(),
        WireError::WrongLength {
            expected: 4,
            actual: 3
        }
    );
}

#[test]
fn fixed_slots_lock_length_prefix_padding_and_rejection() {
    assert_eq!(FixedSlot::<5>::DATA_LEN, 5);
    assert_eq!(FixedSlot::<5>::LEN, 9);

    let slot = FixedSlot::<5>::new(b"abc").unwrap();
    let mut out = [0xff; FixedSlot::<5>::LEN];
    slot.encode(&mut out).unwrap();

    assert_eq!(&out, &[0, 0, 0, 3, b'a', b'b', b'c', 0, 0]);

    let decoded = FixedSlot::<5>::decode(&out).unwrap();
    assert_eq!(decoded.len(), 3);
    assert_eq!(decoded.bytes(), b"abc");
    assert_eq!(decoded.padded_bytes(), &[b'a', b'b', b'c', 0, 0]);

    assert_eq!(
        FixedSlot::<5>::decode(&out[..FixedSlot::<5>::LEN - 1]).unwrap_err(),
        WireError::WrongLength {
            expected: FixedSlot::<5>::LEN,
            actual: FixedSlot::<5>::LEN - 1
        }
    );
    assert_eq!(
        FixedSlot::<5>::new(b"abcdef").unwrap_err(),
        WireError::ValueTooLarge { max: 5, actual: 6 }
    );

    let mut invalid_padding = [0; FixedSlot::<5>::LEN];
    put_u32be(3, &mut invalid_padding[..U32_BYTES]).unwrap();
    invalid_padding[U32_BYTES..].copy_from_slice(&[b'a', b'b', b'c', 0, 1]);
    assert_eq!(
        FixedSlot::<5>::decode(&invalid_padding).unwrap_err(),
        WireError::NonZeroPadding { index: 4 }
    );
}

#[test]
fn connection_frame_ciphertext_slot_layout_includes_aead_tag_capacity() {
    assert_eq!(CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES, 4 * 1024);
    assert_eq!(
        CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES,
        CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES
    );
    assert_eq!(
        Ciphertext::<CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES>::DATA_LEN,
        CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES
    );
    assert_eq!(
        Ciphertext::<CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES>::LEN,
        U32_BYTES + CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES
    );

    assert_eq!(CONNECTION_FRAME_LARGE_PLAINTEXT_BYTES, 1024 * 1024);
    assert_eq!(
        CONNECTION_FRAME_LARGE_CIPHERTEXT_BYTES,
        CONNECTION_FRAME_LARGE_PLAINTEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES
    );
    assert_eq!(
        Ciphertext::<CONNECTION_FRAME_LARGE_CIPHERTEXT_BYTES>::DATA_LEN,
        CONNECTION_FRAME_LARGE_CIPHERTEXT_BYTES
    );
    assert_eq!(
        Ciphertext::<CONNECTION_FRAME_LARGE_CIPHERTEXT_BYTES>::LEN,
        U32_BYTES + CONNECTION_FRAME_LARGE_CIPHERTEXT_BYTES
    );
    assert!(CONNECTION_FRAME_LARGE_CIPHERTEXT_BYTES <= u32::MAX as usize);
}

fn assert_fixed_bytes_golden<const N: usize>(bytes: &[u8; N]) {
    let value = FixedBytes(*bytes);
    let mut out = [0; N];

    value.encode(&mut out).unwrap();
    assert_eq!(&out, bytes);
    assert_eq!(FixedBytes::<N>::decode(bytes).unwrap(), value);
}

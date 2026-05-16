use topo::core::crypto::{
    ED25519_PUBLIC_KEY_BYTES, ED25519_SIGNATURE_BYTES, HASH_BYTES, XCHACHA20_POLY1305_KEY_BYTES,
    XCHACHA20_POLY1305_NONCE_BYTES, XCHACHA20_POLY1305_TAG_BYTES,
};
use topo::core::wire::{
    fixed_tag, Bool8, Ciphertext, FixedBytes, FixedLayout, FixedSlot, Hash32, Id32, Nonce24,
    PublicKey32, Signature64, SymmetricKey32, Tag, U16be, U32be, U64be, WireError, U8,
};
use topo::event_modules::transit::layout::{
    TRANSIT_LARGE_CIPHERTEXT_BYTES, TRANSIT_LARGE_PLAINTEXT_BYTES, TRANSIT_SMALL_CIPHERTEXT_BYTES,
    TRANSIT_SMALL_PLAINTEXT_BYTES,
};

#[test]
fn scalar_layouts_have_fixed_big_endian_golden_bytes() {
    assert_eq!(U8::LEN, 1);
    assert_eq!(U16be::LEN, 2);
    assert_eq!(U32be::LEN, 4);
    assert_eq!(U64be::LEN, 8);
    assert_eq!(Bool8::LEN, 1);

    let mut out = [0; U64be::LEN];

    U8(0xab).encode(&mut out[..U8::LEN]).unwrap();
    assert_eq!(&out[..U8::LEN], &[0xab]);
    assert_eq!(U8::decode(&out[..U8::LEN]).unwrap(), U8(0xab));

    U16be(0x1234).encode(&mut out[..U16be::LEN]).unwrap();
    assert_eq!(&out[..U16be::LEN], &[0x12, 0x34]);
    assert_eq!(U16be::decode(&out[..U16be::LEN]).unwrap(), U16be(0x1234));

    U32be(0x1234_5678).encode(&mut out[..U32be::LEN]).unwrap();
    assert_eq!(&out[..U32be::LEN], &[0x12, 0x34, 0x56, 0x78]);
    assert_eq!(
        U32be::decode(&out[..U32be::LEN]).unwrap(),
        U32be(0x1234_5678)
    );

    U64be(0x1234_5678_9abc_def0).encode(&mut out).unwrap();
    assert_eq!(&out, &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
    assert_eq!(U64be::decode(&out).unwrap(), U64be(0x1234_5678_9abc_def0));

    Bool8(true).encode(&mut out[..Bool8::LEN]).unwrap();
    assert_eq!(&out[..Bool8::LEN], &[1]);
    assert_eq!(Bool8::decode(&out[..Bool8::LEN]).unwrap(), Bool8(true));

    Bool8(false).encode(&mut out[..Bool8::LEN]).unwrap();
    assert_eq!(&out[..Bool8::LEN], &[0]);
    assert_eq!(Bool8::decode(&out[..Bool8::LEN]).unwrap(), Bool8(false));
}

#[test]
fn fixed_bytes_lock_id_hash_key_signature_and_nonce_sizes() {
    assert_eq!(Id32::LEN, 32);
    assert_eq!(Hash32::LEN, HASH_BYTES);
    assert_eq!(PublicKey32::LEN, ED25519_PUBLIC_KEY_BYTES);
    assert_eq!(SymmetricKey32::LEN, XCHACHA20_POLY1305_KEY_BYTES);
    assert_eq!(Signature64::LEN, ED25519_SIGNATURE_BYTES);
    assert_eq!(Nonce24::LEN, XCHACHA20_POLY1305_NONCE_BYTES);

    assert_fixed_bytes_golden::<32>(&[0x11; 32]);
    assert_fixed_bytes_golden::<{ HASH_BYTES }>(&[0x22; HASH_BYTES]);
    assert_fixed_bytes_golden::<{ ED25519_PUBLIC_KEY_BYTES }>(&[0x33; ED25519_PUBLIC_KEY_BYTES]);
    assert_fixed_bytes_golden::<{ XCHACHA20_POLY1305_KEY_BYTES }>(
        &[0x44; XCHACHA20_POLY1305_KEY_BYTES],
    );
    assert_fixed_bytes_golden::<{ ED25519_SIGNATURE_BYTES }>(&[0x55; ED25519_SIGNATURE_BYTES]);
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
        U64be::decode(&[0; 7]).unwrap_err(),
        WireError::WrongLength {
            expected: 8,
            actual: 7
        }
    );

    let value: Hash32 = FixedBytes([0xaa; HASH_BYTES]);
    let mut short = [0; HASH_BYTES - 1];
    assert_eq!(
        value.encode(&mut short).unwrap_err(),
        WireError::WrongLength {
            expected: HASH_BYTES,
            actual: HASH_BYTES - 1
        }
    );

    assert_eq!(
        Bool8::decode(&[2]).unwrap_err(),
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
    U32be(3).encode(&mut invalid_padding[..U32be::LEN]).unwrap();
    invalid_padding[U32be::LEN..].copy_from_slice(&[b'a', b'b', b'c', 0, 1]);
    assert_eq!(
        FixedSlot::<5>::decode(&invalid_padding).unwrap_err(),
        WireError::NonZeroPadding { index: 4 }
    );
}

#[test]
fn transit_ciphertext_slot_layout_includes_aead_tag_capacity() {
    assert_eq!(TRANSIT_SMALL_PLAINTEXT_BYTES, 4 * 1024);
    assert_eq!(
        TRANSIT_SMALL_CIPHERTEXT_BYTES,
        TRANSIT_SMALL_PLAINTEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES
    );
    assert_eq!(
        Ciphertext::<TRANSIT_SMALL_CIPHERTEXT_BYTES>::DATA_LEN,
        TRANSIT_SMALL_CIPHERTEXT_BYTES
    );
    assert_eq!(
        Ciphertext::<TRANSIT_SMALL_CIPHERTEXT_BYTES>::LEN,
        U32be::LEN + TRANSIT_SMALL_CIPHERTEXT_BYTES
    );

    assert_eq!(TRANSIT_LARGE_PLAINTEXT_BYTES, 1024 * 1024);
    assert_eq!(
        TRANSIT_LARGE_CIPHERTEXT_BYTES,
        TRANSIT_LARGE_PLAINTEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES
    );
    assert_eq!(
        Ciphertext::<TRANSIT_LARGE_CIPHERTEXT_BYTES>::DATA_LEN,
        TRANSIT_LARGE_CIPHERTEXT_BYTES
    );
    assert_eq!(
        Ciphertext::<TRANSIT_LARGE_CIPHERTEXT_BYTES>::LEN,
        U32be::LEN + TRANSIT_LARGE_CIPHERTEXT_BYTES
    );
    assert!(TRANSIT_LARGE_CIPHERTEXT_BYTES <= u32::MAX as usize);
}

fn assert_fixed_bytes_golden<const N: usize>(bytes: &[u8; N]) {
    let value = FixedBytes(*bytes);
    let mut out = [0; N];

    value.encode(&mut out).unwrap();
    assert_eq!(&out, bytes);
    assert_eq!(FixedBytes::<N>::decode(bytes).unwrap(), value);
}

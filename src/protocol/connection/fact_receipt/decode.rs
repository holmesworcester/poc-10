//! Byte decoding for connection fact receipts.
//!
//! Decoding proves only the fixed layout: tag, length, field order, canonical
//! origin-address form, and a known receive path. It adds no semantic
//! validation; received-payload admission belongs to the owning fact projector.

use crate::core::wire;
use crate::core::wire::{FixedLayout, FixedSlot};

use super::encode::{
    CONNECTION_FACT_RECEIPT_BYTES, CONNECTION_ID_OFFSET, FRAME_HASH_OFFSET, HAS_CONNECTION_OFFSET,
    HAS_REQUEST_OFFSET, LOCAL_ENDPOINT_OFFSET, ORIGIN_OFFSET, RECEIVED_AT_OFFSET,
    RECEIVED_FACT_OFFSET, RECEIVE_PATH_OFFSET, REQUEST_ID_OFFSET, SENDER_ENDPOINT_OFFSET,
    TYPE_CONNECTION_FACT_RECEIPT,
};
use super::fact::{
    normalize_origin_addr_bytes, ConnectionFactReceipt, OriginAddr, ORIGIN_ADDR_BYTES,
    RECEIVE_PATH_CONNECTION, RECEIVE_PATH_CONNECTION_FRAME, RECEIVE_PATH_CONNECTION_REQUEST,
};

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = ConnectionFactReceipt;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact(fact.body())
    }
}

pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionFactReceipt, String> {
    wire::expect_len(bytes, CONNECTION_FACT_RECEIPT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_CONNECTION_FACT_RECEIPT {
        return Err("expected connection fact receipt".to_string());
    }
    let origin_addr =
        FixedSlot::<ORIGIN_ADDR_BYTES>::decode(&bytes[ORIGIN_OFFSET..LOCAL_ENDPOINT_OFFSET])
            .map_err(wire_err)?
            .bytes()
            .to_vec();
    let canonical_origin_addr = normalize_origin_addr_bytes(&origin_addr)?;
    if canonical_origin_addr != origin_addr {
        return Err("connection fact receipt origin addr is not canonical".to_string());
    }
    let receive_path =
        wire::take_u8(&bytes[RECEIVE_PATH_OFFSET..HAS_CONNECTION_OFFSET]).map_err(wire_err)?;
    validate_receive_path(receive_path)?;
    let has_connection =
        wire::take_bool8(&bytes[HAS_CONNECTION_OFFSET..CONNECTION_ID_OFFSET]).map_err(wire_err)?;
    let connection_id = has_connection.then(|| {
        bytes[CONNECTION_ID_OFFSET..HAS_REQUEST_OFFSET]
            .try_into()
            .unwrap()
    });
    let has_request =
        wire::take_bool8(&bytes[HAS_REQUEST_OFFSET..REQUEST_ID_OFFSET]).map_err(wire_err)?;
    let request_id = has_request.then(|| {
        bytes[REQUEST_ID_OFFSET..FRAME_HASH_OFFSET]
            .try_into()
            .unwrap()
    });
    Ok(ConnectionFactReceipt {
        received_fact_id: bytes[RECEIVED_FACT_OFFSET..ORIGIN_OFFSET]
            .try_into()
            .unwrap(),
        origin_addr: OriginAddr::new(&origin_addr).map_err(wire_err)?,
        local_endpoint_id: bytes[LOCAL_ENDPOINT_OFFSET..SENDER_ENDPOINT_OFFSET]
            .try_into()
            .unwrap(),
        sender_endpoint_id: bytes[SENDER_ENDPOINT_OFFSET..RECEIVE_PATH_OFFSET]
            .try_into()
            .unwrap(),
        receive_path,
        connection_id,
        request_id,
        frame_hash: bytes[FRAME_HASH_OFFSET..RECEIVED_AT_OFFSET]
            .try_into()
            .unwrap(),
        received_at_local_ms: wire::take_u64be(
            &bytes[RECEIVED_AT_OFFSET..CONNECTION_FACT_RECEIPT_BYTES],
        )
        .map_err(wire_err)?,
    })
}

pub(crate) fn validate_receive_path(path: u8) -> Result<(), String> {
    match path {
        RECEIVE_PATH_CONNECTION_REQUEST
        | RECEIVE_PATH_CONNECTION_FRAME
        | RECEIVE_PATH_CONNECTION => Ok(()),
        other => Err(format!("unknown connection receive path {other}")),
    }
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::connection::fact_receipt::encode::{
        encode_fact, CONNECTION_FACT_RECEIPT_BYTES, ORIGIN_OFFSET, TYPE_CONNECTION_FACT_RECEIPT,
    };

    fn fact() -> ConnectionFactReceipt {
        ConnectionFactReceipt {
            received_fact_id: [1; 32],
            origin_addr: OriginAddr::new(b"127.0.0.1:41001").expect("origin"),
            local_endpoint_id: [2; 32],
            sender_endpoint_id: [3; 32],
            receive_path: RECEIVE_PATH_CONNECTION,
            connection_id: Some([4; 32]),
            request_id: Some([6; 32]),
            frame_hash: [5; 32],
            received_at_local_ms: 1_700_000_001,
        }
    }

    #[test]
    fn fact_receipt_roundtrips_fixed_width() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), CONNECTION_FACT_RECEIPT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn fact_receipt_encode_normalizes_friendly_origin_addr() {
        let mut fact = fact();
        fact.origin_addr = OriginAddr::new(b"127.0.0.1_41001").expect("origin");
        let encoded = encode_fact(&fact).expect("encode");
        let decoded = decode_fact(&encoded).expect("decode");

        assert_eq!(decoded.origin_addr.bytes(), b"127.0.0.1:41001");
    }

    #[test]
    fn fact_receipt_decode_rejects_noncanonical_origin_addr() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        let friendly = b"127.0.0.1_41001";
        encoded[ORIGIN_OFFSET..ORIGIN_OFFSET + 4]
            .copy_from_slice(&(friendly.len() as u32).to_be_bytes());
        encoded[ORIGIN_OFFSET + 4..ORIGIN_OFFSET + 4 + friendly.len()].copy_from_slice(friendly);

        let err = decode_fact(&encoded).expect_err("noncanonical origin should fail");
        assert!(err.contains("not canonical"), "{err}");
    }

    #[test]
    fn fact_receipt_roundtrips_without_connection() {
        let fact = ConnectionFactReceipt {
            receive_path: RECEIVE_PATH_CONNECTION_REQUEST,
            connection_id: None,
            request_id: None,
            ..fact()
        };
        let encoded = encode_fact(&fact).expect("encode");
        assert_eq!(decode_fact(&encoded).expect("decode"), fact);
    }

    #[test]
    fn rejects_wrong_tag_or_length() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded[0] = TYPE_CONNECTION_FACT_RECEIPT.wrapping_add(1);
        assert!(decode_fact(&encoded).is_err());

        let mut short = encode_fact(&fact()).expect("encode");
        short.pop();
        assert!(decode_fact(&short).is_err());
    }

    #[test]
    fn rejects_unknown_receive_path() {
        let fact = ConnectionFactReceipt {
            receive_path: 99,
            ..fact()
        };
        assert!(encode_fact(&fact).is_err());
    }

    #[test]
    fn rejects_invalid_origin_addr() {
        let fact = ConnectionFactReceipt {
            origin_addr: OriginAddr::new(b"not-a-socket-addr").expect("origin"),
            ..fact()
        };
        assert!(encode_fact(&fact).is_err());
    }
}

//! Fixed-width layout for local transit receive provenance facts.
//!
//! Received-transit facts are local audit records: they say which fact or frame
//! arrived, from which origin address, under which connection or request, and
//! when the local node observed it. The layout canonicalizes origin addresses
//! so repeated receives compare by stable bytes. It should not validate the
//! received payload itself.

use crate::core::wire;
use crate::core::wire::{FixedLayout, FixedSlot};

use super::addr::normalize_origin_addr_bytes;
use super::fact::{
    TransitReceivedFact, ORIGIN_ADDR_BYTES, TRANSIT_KIND_BOOTSTRAP, TRANSIT_KIND_CONNECTION,
    TRANSIT_KIND_CONNECTION_HANDSHAKE,
};

pub const TYPE_TRANSIT_RECEIVED: u8 = 164;

pub const TRANSIT_RECEIVED_BYTES: usize =
    1 + 32 + 4 + ORIGIN_ADDR_BYTES + 32 + 32 + 1 + 1 + 32 + 1 + 32 + 32 + 8;

const RECEIVED_FACT_OFFSET: usize = 1;
const ORIGIN_OFFSET: usize = RECEIVED_FACT_OFFSET + 32;
const LOCAL_ENDPOINT_OFFSET: usize = ORIGIN_OFFSET + FixedSlot::<ORIGIN_ADDR_BYTES>::LEN;
const SENDER_ENDPOINT_OFFSET: usize = LOCAL_ENDPOINT_OFFSET + 32;
const TRANSIT_KIND_OFFSET: usize = SENDER_ENDPOINT_OFFSET + 32;
const HAS_CONNECTION_OFFSET: usize = TRANSIT_KIND_OFFSET + 1;
const CONNECTION_ID_OFFSET: usize = HAS_CONNECTION_OFFSET + 1;
const HAS_REQUEST_OFFSET: usize = CONNECTION_ID_OFFSET + 32;
const REQUEST_ID_OFFSET: usize = HAS_REQUEST_OFFSET + 1;
const FRAME_HASH_OFFSET: usize = REQUEST_ID_OFFSET + 32;
const RECEIVED_AT_OFFSET: usize = FRAME_HASH_OFFSET + 32;

pub fn encode_fact(fact: &TransitReceivedFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; TRANSIT_RECEIVED_BYTES];
    wire::put_u8(TYPE_TRANSIT_RECEIVED, &mut out[0..1]).map_err(wire_err)?;
    out[RECEIVED_FACT_OFFSET..ORIGIN_OFFSET].copy_from_slice(&fact.received_fact_id);
    let origin_addr = normalize_origin_addr_bytes(&fact.origin_addr)?;
    FixedSlot::<ORIGIN_ADDR_BYTES>::new(&origin_addr)
        .map_err(wire_err)?
        .encode(&mut out[ORIGIN_OFFSET..LOCAL_ENDPOINT_OFFSET])
        .map_err(wire_err)?;
    out[LOCAL_ENDPOINT_OFFSET..SENDER_ENDPOINT_OFFSET].copy_from_slice(&fact.local_endpoint_id);
    out[SENDER_ENDPOINT_OFFSET..TRANSIT_KIND_OFFSET].copy_from_slice(&fact.sender_endpoint_id);
    validate_transit_kind(fact.transit_kind)?;
    wire::put_u8(
        fact.transit_kind,
        &mut out[TRANSIT_KIND_OFFSET..HAS_CONNECTION_OFFSET],
    )
    .map_err(wire_err)?;
    wire::put_bool8(
        fact.connection_id.is_some(),
        &mut out[HAS_CONNECTION_OFFSET..CONNECTION_ID_OFFSET],
    )
    .map_err(wire_err)?;
    if let Some(connection_id) = fact.connection_id {
        out[CONNECTION_ID_OFFSET..HAS_REQUEST_OFFSET].copy_from_slice(&connection_id);
    }
    wire::put_bool8(
        fact.request_id.is_some(),
        &mut out[HAS_REQUEST_OFFSET..REQUEST_ID_OFFSET],
    )
    .map_err(wire_err)?;
    if let Some(request_id) = fact.request_id {
        out[REQUEST_ID_OFFSET..FRAME_HASH_OFFSET].copy_from_slice(&request_id);
    }
    out[FRAME_HASH_OFFSET..RECEIVED_AT_OFFSET].copy_from_slice(&fact.frame_hash);
    wire::put_u64be(
        fact.received_at_local_ms,
        &mut out[RECEIVED_AT_OFFSET..TRANSIT_RECEIVED_BYTES],
    )
    .map_err(wire_err)?;
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<TransitReceivedFact, String> {
    wire::expect_len(bytes, TRANSIT_RECEIVED_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_TRANSIT_RECEIVED {
        return Err("expected transport::transit received fact".to_string());
    }
    let origin_addr =
        FixedSlot::<ORIGIN_ADDR_BYTES>::decode(&bytes[ORIGIN_OFFSET..LOCAL_ENDPOINT_OFFSET])
            .map_err(wire_err)?
            .bytes()
            .to_vec();
    let canonical_origin_addr = normalize_origin_addr_bytes(&origin_addr)?;
    if canonical_origin_addr != origin_addr {
        return Err("transport::transit received origin addr is not canonical".to_string());
    }
    let transit_kind =
        wire::take_u8(&bytes[TRANSIT_KIND_OFFSET..HAS_CONNECTION_OFFSET]).map_err(wire_err)?;
    validate_transit_kind(transit_kind)?;
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
    Ok(TransitReceivedFact {
        received_fact_id: bytes[RECEIVED_FACT_OFFSET..ORIGIN_OFFSET]
            .try_into()
            .unwrap(),
        origin_addr,
        local_endpoint_id: bytes[LOCAL_ENDPOINT_OFFSET..SENDER_ENDPOINT_OFFSET]
            .try_into()
            .unwrap(),
        sender_endpoint_id: bytes[SENDER_ENDPOINT_OFFSET..TRANSIT_KIND_OFFSET]
            .try_into()
            .unwrap(),
        transit_kind,
        connection_id,
        request_id,
        frame_hash: bytes[FRAME_HASH_OFFSET..RECEIVED_AT_OFFSET]
            .try_into()
            .unwrap(),
        received_at_local_ms: wire::take_u64be(&bytes[RECEIVED_AT_OFFSET..TRANSIT_RECEIVED_BYTES])
            .map_err(wire_err)?,
    })
}

fn validate_transit_kind(kind: u8) -> Result<(), String> {
    match kind {
        TRANSIT_KIND_BOOTSTRAP | TRANSIT_KIND_CONNECTION | TRANSIT_KIND_CONNECTION_HANDSHAKE => {
            Ok(())
        }
        other => Err(format!("unknown transport::transit receive kind {other}")),
    }
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> TransitReceivedFact {
        TransitReceivedFact {
            received_fact_id: [1; 32],
            origin_addr: b"127.0.0.1:41001".to_vec(),
            local_endpoint_id: [2; 32],
            sender_endpoint_id: [3; 32],
            transit_kind: TRANSIT_KIND_CONNECTION_HANDSHAKE,
            connection_id: Some([4; 32]),
            request_id: Some([6; 32]),
            frame_hash: [5; 32],
            received_at_local_ms: 1_700_000_001,
        }
    }

    #[test]
    fn transit_received_roundtrips_fixed_width() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), TRANSIT_RECEIVED_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn transit_received_encode_normalizes_friendly_origin_addr() {
        let mut fact = fact();
        fact.origin_addr = b"127.0.0.1_41001".to_vec();
        let encoded = encode_fact(&fact).expect("encode");
        let decoded = decode_fact(&encoded).expect("decode");

        assert_eq!(decoded.origin_addr, b"127.0.0.1:41001");
    }

    #[test]
    fn transit_received_decode_rejects_noncanonical_origin_addr() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        let friendly = b"127.0.0.1_41001";
        encoded[ORIGIN_OFFSET..ORIGIN_OFFSET + 4]
            .copy_from_slice(&(friendly.len() as u32).to_be_bytes());
        encoded[ORIGIN_OFFSET + 4..ORIGIN_OFFSET + 4 + friendly.len()].copy_from_slice(friendly);

        let err = decode_fact(&encoded).expect_err("noncanonical origin should fail");
        assert!(err.contains("not canonical"), "{err}");
    }

    #[test]
    fn transit_received_roundtrips_without_connection() {
        let fact = TransitReceivedFact {
            transit_kind: TRANSIT_KIND_BOOTSTRAP,
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
        encoded[0] = TYPE_TRANSIT_RECEIVED.wrapping_add(1);
        assert!(decode_fact(&encoded).is_err());

        let mut short = encode_fact(&fact()).expect("encode");
        short.pop();
        assert!(decode_fact(&short).is_err());
    }

    #[test]
    fn rejects_unknown_transit_kind() {
        let fact = TransitReceivedFact {
            transit_kind: 99,
            ..fact()
        };
        assert!(encode_fact(&fact).is_err());
    }

    #[test]
    fn rejects_invalid_origin_addr() {
        let fact = TransitReceivedFact {
            origin_addr: b"not-a-socket-addr".to_vec(),
            ..fact()
        };
        assert!(encode_fact(&fact).is_err());
    }
}

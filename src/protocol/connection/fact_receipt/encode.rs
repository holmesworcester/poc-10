//! Canonical byte encoding for connection fact receipts.
//!
//! This file owns byte construction only: the fact tag, the fixed-width field
//! layout, and origin-address normalization at encode time. It does not add
//! semantic validation; received-payload admission belongs to the owning fact
//! projector.
//!
//! Fact receipts are fixed-width local audit records. The layout encodes the
//! received fact id, canonical origin address slot, endpoint pair, receive
//! path, optional connection and request ids, frame hash, and local receive
//! time. Origin addresses are normalized during encoding so equal observations
//! have equal bytes.

use crate::core::wire;
use crate::core::wire::{FixedLayout, FixedSlot};

use super::fact::{normalize_origin_addr_bytes, ConnectionFactReceipt, ORIGIN_ADDR_BYTES};
use super::project::decode::validate_receive_path;

pub const TYPE_CONNECTION_FACT_RECEIPT: u8 = 164;

pub const CONNECTION_FACT_RECEIPT_BYTES: usize =
    1 + 32 + 4 + ORIGIN_ADDR_BYTES + 32 + 32 + 1 + 1 + 32 + 1 + 32 + 32 + 8;

pub(crate) const RECEIVED_FACT_OFFSET: usize = 1;
pub(crate) const ORIGIN_OFFSET: usize = RECEIVED_FACT_OFFSET + 32;
pub(crate) const LOCAL_ENDPOINT_OFFSET: usize = ORIGIN_OFFSET + FixedSlot::<ORIGIN_ADDR_BYTES>::LEN;
pub(crate) const SENDER_ENDPOINT_OFFSET: usize = LOCAL_ENDPOINT_OFFSET + 32;
pub(crate) const RECEIVE_PATH_OFFSET: usize = SENDER_ENDPOINT_OFFSET + 32;
pub(crate) const HAS_CONNECTION_OFFSET: usize = RECEIVE_PATH_OFFSET + 1;
pub(crate) const CONNECTION_ID_OFFSET: usize = HAS_CONNECTION_OFFSET + 1;
pub(crate) const HAS_REQUEST_OFFSET: usize = CONNECTION_ID_OFFSET + 32;
pub(crate) const REQUEST_ID_OFFSET: usize = HAS_REQUEST_OFFSET + 1;
pub(crate) const FRAME_HASH_OFFSET: usize = REQUEST_ID_OFFSET + 32;
pub(crate) const RECEIVED_AT_OFFSET: usize = FRAME_HASH_OFFSET + 32;

pub fn encode_fact(fact: &ConnectionFactReceipt) -> Result<Vec<u8>, String> {
    let mut out = vec![0; CONNECTION_FACT_RECEIPT_BYTES];
    wire::put_u8(TYPE_CONNECTION_FACT_RECEIPT, &mut out[0..1]).map_err(wire_err)?;
    out[RECEIVED_FACT_OFFSET..ORIGIN_OFFSET].copy_from_slice(&fact.received_fact_id);
    let origin_addr = normalize_origin_addr_bytes(fact.origin_addr.bytes())?;
    FixedSlot::<ORIGIN_ADDR_BYTES>::new(&origin_addr)
        .map_err(wire_err)?
        .encode(&mut out[ORIGIN_OFFSET..LOCAL_ENDPOINT_OFFSET])
        .map_err(wire_err)?;
    out[LOCAL_ENDPOINT_OFFSET..SENDER_ENDPOINT_OFFSET].copy_from_slice(&fact.local_endpoint_id);
    out[SENDER_ENDPOINT_OFFSET..RECEIVE_PATH_OFFSET].copy_from_slice(&fact.sender_endpoint_id);
    validate_receive_path(fact.receive_path)?;
    wire::put_u8(
        fact.receive_path,
        &mut out[RECEIVE_PATH_OFFSET..HAS_CONNECTION_OFFSET],
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
        &mut out[RECEIVED_AT_OFFSET..CONNECTION_FACT_RECEIPT_BYTES],
    )
    .map_err(wire_err)?;
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

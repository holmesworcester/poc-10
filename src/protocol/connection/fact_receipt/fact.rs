//! Connection fact-receipt payload.
//!
//! A receipt is a local about-fact for one received semantic fact. It names the
//! received fact, observed origin, local endpoint, sender endpoint, receive
//! path, optional connection/request witnesses, frame hash, and receive time.
//!
//! The payload is observational evidence only. It does not validate or
//! authorize the received fact; the projector for that fact matches the receipt
//! context and decides whether it proves the required path.

use crate::core::facts::FactId;

pub const ORIGIN_ADDR_BYTES: usize = 256;
pub const RECEIVE_PATH_CONNECTION_REQUEST: u8 = 0;
pub const RECEIVE_PATH_CONNECTION_FRAME: u8 = 1;
pub const RECEIVE_PATH_CONNECTION_RESPONSE: u8 = 2;

pub type EndpointId = FactId;
pub type ConnectionId = FactId;
pub type RequestId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFactReceipt {
    pub received_fact_id: FactId,
    pub origin_addr: Vec<u8>,
    pub local_endpoint_id: EndpointId,
    pub sender_endpoint_id: EndpointId,
    pub receive_path: u8,
    pub connection_id: Option<ConnectionId>,
    pub request_id: Option<RequestId>,
    pub frame_hash: [u8; 32],
    pub received_at_local_ms: u64,
}

impl ConnectionFactReceipt {
    pub fn origin_addr_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.origin_addr)
    }
}

//! Connection fact-receipt payload.
//!
//! A receipt is a local about-fact for one received semantic fact. It names the
//! received fact, observed origin, local endpoint, sender endpoint, receive
//! path, optional connection/request witnesses, frame hash, and receive time.
//!
//! The payload is observational evidence only. It does not validate or
//! authorize the received fact; the projector for that fact matches the receipt
//! context and decides whether it proves the required path.

use std::net::SocketAddr;
use std::str;
use std::str::FromStr;

use crate::core::facts::FactId;
use crate::core::wire::FixedSlot;

pub const ORIGIN_ADDR_BYTES: usize = 256;
pub const RECEIVE_PATH_CONNECTION_REQUEST: u8 = 0;
pub const RECEIVE_PATH_CONNECTION_FRAME: u8 = 1;
pub const RECEIVE_PATH_CONNECTION: u8 = 2;

pub type EndpointId = FactId;
pub type ConnectionId = FactId;
pub type RequestId = FactId;
pub type OriginAddr = FixedSlot<ORIGIN_ADDR_BYTES>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFactReceipt {
    pub received_fact_id: FactId,
    pub origin_addr: OriginAddr,
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
        std::str::from_utf8(self.origin_addr.bytes())
    }
}

pub struct ReceiptPathInput<'a> {
    pub received_fact_id: FactId,
    pub origin_addr: &'a [u8],
    pub local_endpoint_id: FactId,
    pub sender_endpoint_id: FactId,
    pub receive_path: u8,
    pub connection_id: Option<FactId>,
    pub request_id: Option<FactId>,
    pub frame_hash: [u8; 32],
    pub received_at_local_ms: u64,
}

/// Encode an observed socket address in the one representation admitted by the
/// fact-receipt layout.
pub fn canonical_origin_addr_bytes(addr: SocketAddr) -> Vec<u8> {
    addr.to_string().into_bytes()
}

/// Normalize boundary input to canonical socket-address bytes.
pub fn normalize_origin_addr_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = str::from_utf8(bytes)
        .map_err(|_| "connection receive origin addr must be utf-8".to_string())?
        .trim();
    if value.is_empty() {
        return Err("connection receive origin addr cannot be empty".to_string());
    }
    Ok(canonical_origin_addr_bytes(parse_origin_addr(value)?))
}

fn parse_origin_addr(value: &str) -> Result<SocketAddr, String> {
    if let Ok(addr) = SocketAddr::from_str(value) {
        return Ok(addr);
    }

    let (host, port) = value
        .rsplit_once('_')
        .ok_or_else(|| "connection receive origin addr must include a port".to_string())?;
    let port = u16::from_str(port)
        .map_err(|_| "connection receive origin addr port is invalid".to_string())?;
    let candidate = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    candidate
        .parse()
        .map_err(|_| "connection receive origin addr is invalid".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_socket_addr_strings() {
        assert_eq!(
            normalize_origin_addr_bytes(b"127.0.0.1:41001").expect("ipv4"),
            b"127.0.0.1:41001"
        );
        assert_eq!(
            normalize_origin_addr_bytes(b"[::1]:41001").expect("ipv6"),
            b"[::1]:41001"
        );
    }

    #[test]
    fn accepts_invite_link_friendly_addr_strings() {
        assert_eq!(
            normalize_origin_addr_bytes(b"127.0.0.1_41001").expect("ipv4"),
            b"127.0.0.1:41001"
        );
        assert_eq!(
            normalize_origin_addr_bytes(b"::1_41001").expect("ipv6"),
            b"[::1]:41001"
        );
    }

    #[test]
    fn rejects_non_socket_origin_strings() {
        assert!(normalize_origin_addr_bytes(b"127.0.0.1").is_err());
        assert!(normalize_origin_addr_bytes(b"localhost_41001").is_err());
        assert!(normalize_origin_addr_bytes(b"127.0.0.1_bad").is_err());
    }
}

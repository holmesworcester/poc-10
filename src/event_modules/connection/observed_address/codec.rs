//! Hand-rolled wire codec for `ObservedAddressEvent`.
//!
//! Layout (fixed, big-endian for multi-byte ints):
//! ```text
//! [0]          type_code (= 37)
//! [1..33]      observer_endpoint_id (32)
//! [33..65]     subject_endpoint_id (32)
//! [65..81]     ip (16)
//! [81..83]     port (u16 BE)
//! [83..91]     observed_at_ms (u64 BE)
//! [91..99]     ttl_ms (u64 BE)
//! [99..131]    signed_by (32)
//! [131..195]   signature (64)
//! ```

use super::event::{ObservedAddressEvent, OBSERVED_ADDRESS_TYPE_CODE};

pub const OBSERVED_ADDRESS_WIRE_SIZE: usize = 1 + 32 + 32 + 16 + 2 + 8 + 8 + 32 + 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservedAddressWireError {
    Truncated,
    WrongType(u8),
    BadShape(&'static str),
}

impl std::fmt::Display for ObservedAddressWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "observed_address truncated"),
            Self::WrongType(t) => write!(f, "wrong type code: {}", t),
            Self::BadShape(s) => write!(f, "bad shape: {}", s),
        }
    }
}

impl std::error::Error for ObservedAddressWireError {}

pub fn encode(e: &ObservedAddressEvent) -> Vec<u8> {
    let mut out = Vec::with_capacity(OBSERVED_ADDRESS_WIRE_SIZE);
    out.push(OBSERVED_ADDRESS_TYPE_CODE);
    out.extend_from_slice(&e.observer_endpoint_id);
    out.extend_from_slice(&e.subject_endpoint_id);
    out.extend_from_slice(&e.ip);
    out.extend_from_slice(&e.port.to_be_bytes());
    out.extend_from_slice(&e.observed_at_ms.to_be_bytes());
    out.extend_from_slice(&e.ttl_ms.to_be_bytes());
    out.extend_from_slice(&e.signed_by);
    out.extend_from_slice(&e.signature);
    debug_assert_eq!(out.len(), OBSERVED_ADDRESS_WIRE_SIZE);
    out
}

pub fn parse(blob: &[u8]) -> Result<ObservedAddressEvent, ObservedAddressWireError> {
    if blob.len() != OBSERVED_ADDRESS_WIRE_SIZE {
        return Err(ObservedAddressWireError::Truncated);
    }
    if blob[0] != OBSERVED_ADDRESS_TYPE_CODE {
        return Err(ObservedAddressWireError::WrongType(blob[0]));
    }

    let mut pos = 1;
    let mut observer_endpoint_id = [0u8; 32];
    observer_endpoint_id.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    let mut subject_endpoint_id = [0u8; 32];
    subject_endpoint_id.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    let mut ip = [0u8; 16];
    ip.copy_from_slice(&blob[pos..pos + 16]);
    pos += 16;
    let port = u16::from_be_bytes(blob[pos..pos + 2].try_into().unwrap());
    pos += 2;
    let observed_at_ms = u64::from_be_bytes(blob[pos..pos + 8].try_into().unwrap());
    pos += 8;
    let ttl_ms = u64::from_be_bytes(blob[pos..pos + 8].try_into().unwrap());
    pos += 8;
    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[pos..pos + 64]);

    Ok(ObservedAddressEvent {
        observer_endpoint_id,
        subject_endpoint_id,
        ip,
        port,
        observed_at_ms,
        ttl_ms,
        signed_by,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let e = ObservedAddressEvent {
            observer_endpoint_id: [1u8; 32],
            subject_endpoint_id: [2u8; 32],
            ip: [10u8; 16],
            port: 4433,
            observed_at_ms: 100,
            ttl_ms: 60_000,
            signed_by: [1u8; 32],
            signature: [9u8; 64],
        };
        let blob = encode(&e);
        let parsed = parse(&blob).unwrap();
        assert_eq!(parsed, e);
    }
}

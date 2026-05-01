//! Hand-rolled wire codec for `SelfAddressEvent`.
//!
//! Layout (fixed, big-endian for multi-byte ints):
//! ```text
//! [0]          type_code (= 38)
//! [1..33]      endpoint_id (32)
//! [33..49]     ip (16)
//! [49..51]     port (u16 BE)
//! [51..59]     created_at_ms (u64 BE)
//! [59..67]     ttl_ms (u64 BE)
//! [67..99]     signed_by (32)
//! [99..163]    signature (64)
//! ```

use super::event::{SelfAddressEvent, SELF_ADDRESS_TYPE_CODE};

pub const SELF_ADDRESS_WIRE_SIZE: usize = 1 + 32 + 16 + 2 + 8 + 8 + 32 + 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfAddressWireError {
    Truncated,
    WrongType(u8),
    BadShape(&'static str),
}

impl std::fmt::Display for SelfAddressWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "self_address truncated"),
            Self::WrongType(t) => write!(f, "wrong type code: {}", t),
            Self::BadShape(s) => write!(f, "bad shape: {}", s),
        }
    }
}

impl std::error::Error for SelfAddressWireError {}

pub fn encode(e: &SelfAddressEvent) -> Vec<u8> {
    let mut out = Vec::with_capacity(SELF_ADDRESS_WIRE_SIZE);
    out.push(SELF_ADDRESS_TYPE_CODE);
    out.extend_from_slice(&e.endpoint_id);
    out.extend_from_slice(&e.ip);
    out.extend_from_slice(&e.port.to_be_bytes());
    out.extend_from_slice(&e.created_at_ms.to_be_bytes());
    out.extend_from_slice(&e.ttl_ms.to_be_bytes());
    out.extend_from_slice(&e.signed_by);
    out.extend_from_slice(&e.signature);
    debug_assert_eq!(out.len(), SELF_ADDRESS_WIRE_SIZE);
    out
}

pub fn parse(blob: &[u8]) -> Result<SelfAddressEvent, SelfAddressWireError> {
    if blob.len() != SELF_ADDRESS_WIRE_SIZE {
        return Err(SelfAddressWireError::Truncated);
    }
    if blob[0] != SELF_ADDRESS_TYPE_CODE {
        return Err(SelfAddressWireError::WrongType(blob[0]));
    }

    let mut pos = 1;
    let mut endpoint_id = [0u8; 32];
    endpoint_id.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    let mut ip = [0u8; 16];
    ip.copy_from_slice(&blob[pos..pos + 16]);
    pos += 16;
    let port = u16::from_be_bytes(blob[pos..pos + 2].try_into().unwrap());
    pos += 2;
    let created_at_ms = u64::from_be_bytes(blob[pos..pos + 8].try_into().unwrap());
    pos += 8;
    let ttl_ms = u64::from_be_bytes(blob[pos..pos + 8].try_into().unwrap());
    pos += 8;
    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[pos..pos + 64]);

    Ok(SelfAddressEvent {
        endpoint_id,
        ip,
        port,
        created_at_ms,
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
        let e = SelfAddressEvent {
            endpoint_id: [1u8; 32],
            ip: [10u8; 16],
            port: 4433,
            created_at_ms: 100,
            ttl_ms: 60_000,
            signed_by: [1u8; 32],
            signature: [9u8; 64],
        };
        let blob = encode(&e);
        let parsed = parse(&blob).unwrap();
        assert_eq!(parsed, e);
    }
}

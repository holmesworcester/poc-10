//! Hand-rolled wire codec for `ConnectionPrekeyEvent`.
//!
//! Layout (fixed size, big-endian for multi-byte integers, matching the
//! Phase 1 `connection/codec.rs` style):
//! ```text
//! [0]          type_code (= 34)
//! [1..33]      prekey_id (32)
//! [33..65]     endpoint_id (32)
//! [65..97]     private_key (32)
//! [97..129]    public_key (32)
//! [129..137]   created_at_ms (u64 BE)
//! [137..145]   ttl_ms (u64 BE)
//! [145..209]   signature (64)
//! ```

use super::event::{ConnectionPrekeyEvent, CONNECTION_PREKEY_TYPE_CODE};

pub const CONNECTION_PREKEY_WIRE_SIZE: usize = 1 + 32 + 32 + 32 + 32 + 8 + 8 + 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionPrekeyWireError {
    Truncated,
    WrongType(u8),
    BadShape(&'static str),
}

impl std::fmt::Display for ConnectionPrekeyWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "connection_prekey event truncated"),
            Self::WrongType(t) => write!(f, "wrong type code: {}", t),
            Self::BadShape(s) => write!(f, "bad shape: {}", s),
        }
    }
}

impl std::error::Error for ConnectionPrekeyWireError {}

pub fn encode(e: &ConnectionPrekeyEvent) -> Vec<u8> {
    let mut out = Vec::with_capacity(CONNECTION_PREKEY_WIRE_SIZE);
    out.push(CONNECTION_PREKEY_TYPE_CODE);
    out.extend_from_slice(&e.prekey_id);
    out.extend_from_slice(&e.endpoint_id);
    out.extend_from_slice(&e.private_key);
    out.extend_from_slice(&e.public_key);
    out.extend_from_slice(&e.created_at_ms.to_be_bytes());
    out.extend_from_slice(&e.ttl_ms.to_be_bytes());
    out.extend_from_slice(&e.signature);
    debug_assert_eq!(out.len(), CONNECTION_PREKEY_WIRE_SIZE);
    out
}

pub fn parse(blob: &[u8]) -> Result<ConnectionPrekeyEvent, ConnectionPrekeyWireError> {
    if blob.len() != CONNECTION_PREKEY_WIRE_SIZE {
        return Err(ConnectionPrekeyWireError::Truncated);
    }
    if blob[0] != CONNECTION_PREKEY_TYPE_CODE {
        return Err(ConnectionPrekeyWireError::WrongType(blob[0]));
    }

    let mut pos = 1;
    let mut prekey_id = [0u8; 32];
    prekey_id.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    let mut endpoint_id = [0u8; 32];
    endpoint_id.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    let created_at_ms = u64::from_be_bytes(blob[pos..pos + 8].try_into().unwrap());
    pos += 8;
    let ttl_ms = u64::from_be_bytes(blob[pos..pos + 8].try_into().unwrap());
    pos += 8;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[pos..pos + 64]);

    Ok(ConnectionPrekeyEvent {
        prekey_id,
        endpoint_id,
        private_key,
        public_key,
        created_at_ms,
        ttl_ms,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let e = ConnectionPrekeyEvent {
            prekey_id: [7u8; 32],
            endpoint_id: [1u8; 32],
            private_key: [2u8; 32],
            public_key: [3u8; 32],
            created_at_ms: 12345,
            ttl_ms: 60_000,
            signature: [9u8; 64],
        };
        let blob = encode(&e);
        assert_eq!(blob.len(), CONNECTION_PREKEY_WIRE_SIZE);
        let parsed = parse(&blob).unwrap();
        assert_eq!(parsed, e);
    }

    #[test]
    fn rejects_wrong_type() {
        let mut blob = vec![0xFFu8; CONNECTION_PREKEY_WIRE_SIZE];
        blob[0] = 99;
        assert!(matches!(
            parse(&blob),
            Err(ConnectionPrekeyWireError::WrongType(99))
        ));
    }

    #[test]
    fn rejects_truncated() {
        let blob = vec![CONNECTION_PREKEY_TYPE_CODE; 10];
        assert!(matches!(
            parse(&blob),
            Err(ConnectionPrekeyWireError::Truncated)
        ));
    }
}

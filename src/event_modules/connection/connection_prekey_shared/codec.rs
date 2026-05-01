//! Hand-rolled wire codec for `ConnectionPrekeySharedEvent`.
//!
//! Layout (fixed size, big-endian for multi-byte ints):
//! ```text
//! [0]          type_code (= 35)
//! [1..33]      prekey_id (32)
//! [33..65]     endpoint_id (32)
//! [65..97]     public_key (32)
//! [97..105]    created_at_ms (u64 BE)
//! [105..113]   ttl_ms (u64 BE)
//! [113..177]   signature (64)
//! ```

use super::event::{ConnectionPrekeySharedEvent, CONNECTION_PREKEY_SHARED_TYPE_CODE};

pub const CONNECTION_PREKEY_SHARED_WIRE_SIZE: usize = 1 + 32 + 32 + 32 + 8 + 8 + 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionPrekeySharedWireError {
    Truncated,
    WrongType(u8),
    BadShape(&'static str),
}

impl std::fmt::Display for ConnectionPrekeySharedWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "connection_prekey_shared event truncated"),
            Self::WrongType(t) => write!(f, "wrong type code: {}", t),
            Self::BadShape(s) => write!(f, "bad shape: {}", s),
        }
    }
}

impl std::error::Error for ConnectionPrekeySharedWireError {}

pub fn encode(e: &ConnectionPrekeySharedEvent) -> Vec<u8> {
    let mut out = Vec::with_capacity(CONNECTION_PREKEY_SHARED_WIRE_SIZE);
    out.push(CONNECTION_PREKEY_SHARED_TYPE_CODE);
    out.extend_from_slice(&e.prekey_id);
    out.extend_from_slice(&e.endpoint_id);
    out.extend_from_slice(&e.public_key);
    out.extend_from_slice(&e.created_at_ms.to_be_bytes());
    out.extend_from_slice(&e.ttl_ms.to_be_bytes());
    out.extend_from_slice(&e.signature);
    debug_assert_eq!(out.len(), CONNECTION_PREKEY_SHARED_WIRE_SIZE);
    out
}

pub fn parse(blob: &[u8]) -> Result<ConnectionPrekeySharedEvent, ConnectionPrekeySharedWireError> {
    if blob.len() != CONNECTION_PREKEY_SHARED_WIRE_SIZE {
        return Err(ConnectionPrekeySharedWireError::Truncated);
    }
    if blob[0] != CONNECTION_PREKEY_SHARED_TYPE_CODE {
        return Err(ConnectionPrekeySharedWireError::WrongType(blob[0]));
    }

    let mut pos = 1;
    let mut prekey_id = [0u8; 32];
    prekey_id.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    let mut endpoint_id = [0u8; 32];
    endpoint_id.copy_from_slice(&blob[pos..pos + 32]);
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

    Ok(ConnectionPrekeySharedEvent {
        prekey_id,
        endpoint_id,
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
        let e = ConnectionPrekeySharedEvent {
            prekey_id: [4u8; 32],
            endpoint_id: [1u8; 32],
            public_key: [3u8; 32],
            created_at_ms: 9999,
            ttl_ms: 60_000,
            signature: [9u8; 64],
        };
        let blob = encode(&e);
        assert_eq!(blob.len(), CONNECTION_PREKEY_SHARED_WIRE_SIZE);
        let parsed = parse(&blob).unwrap();
        assert_eq!(parsed, e);
    }
}

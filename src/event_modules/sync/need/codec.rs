//! Hand-rolled wire codec for `NeedEvent` (fixed size).
//!
//! Layout:
//! ```text
//! [0]          type_code (= 43)
//! [1..33]      connection_id (32)
//! [33..65]     workspace_id (32)
//! [65..97]     event_id (32)
//! [97..105]    created_at_ms (u64 BE)
//! ```

use super::event::{NeedEvent, NEED_TYPE_CODE};

pub const NEED_WIRE_SIZE: usize = 1 + 32 + 32 + 32 + 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NeedWireError {
    Truncated,
    WrongType(u8),
    BadShape(&'static str),
}

impl std::fmt::Display for NeedWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "need event truncated"),
            Self::WrongType(t) => write!(f, "wrong type code: {}", t),
            Self::BadShape(s) => write!(f, "bad shape: {}", s),
        }
    }
}

impl std::error::Error for NeedWireError {}

pub fn encode(e: &NeedEvent) -> Vec<u8> {
    let mut out = Vec::with_capacity(NEED_WIRE_SIZE);
    out.push(NEED_TYPE_CODE);
    out.extend_from_slice(&e.connection_id);
    out.extend_from_slice(&e.workspace_id);
    out.extend_from_slice(&e.event_id);
    out.extend_from_slice(&e.created_at_ms.to_be_bytes());
    debug_assert_eq!(out.len(), NEED_WIRE_SIZE);
    out
}

pub fn parse(blob: &[u8]) -> Result<NeedEvent, NeedWireError> {
    if blob.len() != NEED_WIRE_SIZE {
        return Err(NeedWireError::Truncated);
    }
    if blob[0] != NEED_TYPE_CODE {
        return Err(NeedWireError::WrongType(blob[0]));
    }
    let mut pos = 1;
    let mut connection_id = [0u8; 32];
    connection_id.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    let mut workspace_id = [0u8; 32];
    workspace_id.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    let mut event_id = [0u8; 32];
    event_id.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    let created_at_ms = u64::from_be_bytes(blob[pos..pos + 8].try_into().unwrap());
    Ok(NeedEvent {
        connection_id,
        workspace_id,
        event_id,
        created_at_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let e = NeedEvent {
            connection_id: [1u8; 32],
            workspace_id: [2u8; 32],
            event_id: [0xCDu8; 32],
            created_at_ms: 100,
        };
        let blob = encode(&e);
        assert_eq!(blob.len(), NEED_WIRE_SIZE);
        let parsed = parse(&blob).unwrap();
        assert_eq!(parsed, e);
    }

    #[test]
    fn rejects_wrong_type() {
        let mut blob = vec![0xFFu8; NEED_WIRE_SIZE];
        blob[0] = 99;
        assert!(matches!(parse(&blob), Err(NeedWireError::WrongType(99))));
    }
}

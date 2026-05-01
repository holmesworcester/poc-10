//! Hand-rolled wire codec for `HaveEvent` (fixed size).
//!
//! Layout:
//! ```text
//! [0]          type_code (= 42)
//! [1..33]      connection_id (32)
//! [33..65]     workspace_id (32)
//! [65..97]     event_id (32)
//! [97..105]    created_at_ms (u64 BE)
//! ```

use super::event::{HaveEvent, HAVE_TYPE_CODE};

pub const HAVE_WIRE_SIZE: usize = 1 + 32 + 32 + 32 + 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HaveWireError {
    Truncated,
    WrongType(u8),
    BadShape(&'static str),
}

impl std::fmt::Display for HaveWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "have event truncated"),
            Self::WrongType(t) => write!(f, "wrong type code: {}", t),
            Self::BadShape(s) => write!(f, "bad shape: {}", s),
        }
    }
}

impl std::error::Error for HaveWireError {}

pub fn encode(e: &HaveEvent) -> Vec<u8> {
    let mut out = Vec::with_capacity(HAVE_WIRE_SIZE);
    out.push(HAVE_TYPE_CODE);
    out.extend_from_slice(&e.connection_id);
    out.extend_from_slice(&e.workspace_id);
    out.extend_from_slice(&e.event_id);
    out.extend_from_slice(&e.created_at_ms.to_be_bytes());
    debug_assert_eq!(out.len(), HAVE_WIRE_SIZE);
    out
}

pub fn parse(blob: &[u8]) -> Result<HaveEvent, HaveWireError> {
    if blob.len() != HAVE_WIRE_SIZE {
        return Err(HaveWireError::Truncated);
    }
    if blob[0] != HAVE_TYPE_CODE {
        return Err(HaveWireError::WrongType(blob[0]));
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
    Ok(HaveEvent {
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
        let e = HaveEvent {
            connection_id: [1u8; 32],
            workspace_id: [2u8; 32],
            event_id: [0xCDu8; 32],
            created_at_ms: 100,
        };
        let blob = encode(&e);
        assert_eq!(blob.len(), HAVE_WIRE_SIZE);
        let parsed = parse(&blob).unwrap();
        assert_eq!(parsed, e);
    }

    #[test]
    fn rejects_wrong_type() {
        let mut blob = vec![0xFFu8; HAVE_WIRE_SIZE];
        blob[0] = 99;
        assert!(matches!(parse(&blob), Err(HaveWireError::WrongType(99))));
    }
}

//! Hand-rolled wire codec for `SyncWindowEvent` (fixed size).
//!
//! Layout:
//! ```text
//! [0]          type_code (= 40)
//! [1..33]      connection_id (32)
//! [33..65]     workspace_id (32)
//! [65]         kind (u8)
//! [66..74]     begin_ms (u64 BE)
//! [74..82]     end_ms (u64 BE)
//! [82..90]     created_at_ms (u64 BE)
//! ```

use super::event::{SyncWindowEvent, SyncWindowKind, SYNC_WINDOW_TYPE_CODE};

pub const SYNC_WINDOW_WIRE_SIZE: usize = 1 + 32 + 32 + 1 + 8 + 8 + 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncWindowWireError {
    Truncated,
    WrongType(u8),
    BadKind(u8),
    BadShape(&'static str),
}

impl std::fmt::Display for SyncWindowWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "sync_window truncated"),
            Self::WrongType(t) => write!(f, "wrong type code: {}", t),
            Self::BadKind(k) => write!(f, "unknown sync_window kind: {}", k),
            Self::BadShape(s) => write!(f, "bad shape: {}", s),
        }
    }
}

impl std::error::Error for SyncWindowWireError {}

pub fn encode(e: &SyncWindowEvent) -> Vec<u8> {
    let mut out = Vec::with_capacity(SYNC_WINDOW_WIRE_SIZE);
    out.push(SYNC_WINDOW_TYPE_CODE);
    out.extend_from_slice(&e.connection_id);
    out.extend_from_slice(&e.workspace_id);
    out.push(e.kind.as_u8());
    out.extend_from_slice(&e.begin_ms.to_be_bytes());
    out.extend_from_slice(&e.end_ms.to_be_bytes());
    out.extend_from_slice(&e.created_at_ms.to_be_bytes());
    debug_assert_eq!(out.len(), SYNC_WINDOW_WIRE_SIZE);
    out
}

pub fn parse(blob: &[u8]) -> Result<SyncWindowEvent, SyncWindowWireError> {
    if blob.len() != SYNC_WINDOW_WIRE_SIZE {
        return Err(SyncWindowWireError::Truncated);
    }
    if blob[0] != SYNC_WINDOW_TYPE_CODE {
        return Err(SyncWindowWireError::WrongType(blob[0]));
    }

    let mut pos = 1;
    let mut connection_id = [0u8; 32];
    connection_id.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    let mut workspace_id = [0u8; 32];
    workspace_id.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    let kind_byte = blob[pos];
    pos += 1;
    let kind = SyncWindowKind::from_u8(kind_byte).ok_or(SyncWindowWireError::BadKind(kind_byte))?;
    let begin_ms = u64::from_be_bytes(blob[pos..pos + 8].try_into().unwrap());
    pos += 8;
    let end_ms = u64::from_be_bytes(blob[pos..pos + 8].try_into().unwrap());
    pos += 8;
    let created_at_ms = u64::from_be_bytes(blob[pos..pos + 8].try_into().unwrap());

    Ok(SyncWindowEvent {
        connection_id,
        workspace_id,
        kind,
        begin_ms,
        end_ms,
        created_at_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_each_kind() {
        for kind in [
            SyncWindowKind::LastDay,
            SyncWindowKind::LastWeek,
            SyncWindowKind::Recent,
            SyncWindowKind::Full,
        ] {
            let e = SyncWindowEvent {
                connection_id: [1u8; 32],
                workspace_id: [2u8; 32],
                kind,
                begin_ms: 100,
                end_ms: 200,
                created_at_ms: 300,
            };
            let blob = encode(&e);
            assert_eq!(blob.len(), SYNC_WINDOW_WIRE_SIZE);
            let parsed = parse(&blob).unwrap();
            assert_eq!(parsed, e);
        }
    }

    #[test]
    fn rejects_unknown_kind() {
        let mut blob = vec![0u8; SYNC_WINDOW_WIRE_SIZE];
        blob[0] = SYNC_WINDOW_TYPE_CODE;
        blob[65] = 99;
        assert!(matches!(parse(&blob), Err(SyncWindowWireError::BadKind(99))));
    }
}

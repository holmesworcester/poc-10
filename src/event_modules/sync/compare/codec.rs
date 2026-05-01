//! Hand-rolled wire codec for `CompareEvent` (variable size: `node_id` is
//! variable length).
//!
//! Layout:
//! ```text
//! [0]            type_code (= 41)
//! [1..33]        connection_id (32)
//! [33..65]       workspace_id (32)
//! [65..67]       node_id_len (u16 BE)
//! [67..67+L]     node_id (L bytes)
//! [..]           fingerprint (32)
//! [..]           created_at_ms (u64 BE)
//! ```
//! No signature: per plan.md line 365 these are endpoint-local hints
//! authenticated by the surrounding connection, not durable shared events.

use super::event::{CompareEvent, COMPARE_TYPE_CODE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompareWireError {
    Truncated,
    WrongType(u8),
    BadShape(&'static str),
}

impl std::fmt::Display for CompareWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "compare event truncated"),
            Self::WrongType(t) => write!(f, "wrong type code: {}", t),
            Self::BadShape(s) => write!(f, "bad shape: {}", s),
        }
    }
}

impl std::error::Error for CompareWireError {}

pub fn encode(e: &CompareEvent) -> Vec<u8> {
    let cap = 1 + 32 + 32 + 2 + e.node_id.len() + 32 + 8;
    let mut out = Vec::with_capacity(cap);
    out.push(COMPARE_TYPE_CODE);
    out.extend_from_slice(&e.connection_id);
    out.extend_from_slice(&e.workspace_id);
    out.extend_from_slice(&(e.node_id.len() as u16).to_be_bytes());
    out.extend_from_slice(&e.node_id);
    out.extend_from_slice(&e.fingerprint);
    out.extend_from_slice(&e.created_at_ms.to_be_bytes());
    out
}

pub fn parse(blob: &[u8]) -> Result<CompareEvent, CompareWireError> {
    if blob.is_empty() {
        return Err(CompareWireError::Truncated);
    }
    if blob[0] != COMPARE_TYPE_CODE {
        return Err(CompareWireError::WrongType(blob[0]));
    }

    let mut pos = 1;
    let need = |p: usize, n: usize| {
        if blob.len() < p + n {
            Err(CompareWireError::Truncated)
        } else {
            Ok(())
        }
    };

    need(pos, 32)?;
    let mut connection_id = [0u8; 32];
    connection_id.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    need(pos, 32)?;
    let mut workspace_id = [0u8; 32];
    workspace_id.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    need(pos, 2)?;
    let nlen = u16::from_be_bytes(blob[pos..pos + 2].try_into().unwrap()) as usize;
    pos += 2;
    need(pos, nlen)?;
    let node_id = blob[pos..pos + nlen].to_vec();
    pos += nlen;
    need(pos, 32)?;
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    need(pos, 8)?;
    let created_at_ms = u64::from_be_bytes(blob[pos..pos + 8].try_into().unwrap());
    pos += 8;
    if blob.len() != pos {
        return Err(CompareWireError::BadShape("trailing bytes"));
    }

    Ok(CompareEvent {
        connection_id,
        workspace_id,
        node_id,
        fingerprint,
        created_at_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let e = CompareEvent {
            connection_id: [1u8; 32],
            workspace_id: [2u8; 32],
            node_id: vec![0x10, 0x20, 0x30],
            fingerprint: [0xABu8; 32],
            created_at_ms: 12345,
        };
        let blob = encode(&e);
        let parsed = parse(&blob).unwrap();
        assert_eq!(parsed, e);
    }

    #[test]
    fn empty_node_id_round_trip() {
        let e = CompareEvent {
            connection_id: [1u8; 32],
            workspace_id: [2u8; 32],
            node_id: vec![],
            fingerprint: [0u8; 32],
            created_at_ms: 100,
        };
        let blob = encode(&e);
        let parsed = parse(&blob).unwrap();
        assert_eq!(parsed, e);
    }

    #[test]
    fn rejects_wrong_type() {
        let mut blob = encode(&CompareEvent {
            connection_id: [0u8; 32],
            workspace_id: [0u8; 32],
            node_id: vec![],
            fingerprint: [0u8; 32],
            created_at_ms: 0,
        });
        blob[0] = 0xFE;
        assert!(matches!(parse(&blob), Err(CompareWireError::WrongType(0xFE))));
    }
}

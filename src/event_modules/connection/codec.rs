//! Encode/parse for the `Connection` event.
//!
//! Field-spec wire layout:
//! ```text
//! type_code(1)
//! created_at_ms(8)
//! endpoint_a(32)
//! endpoint_b(32)
//! signed_at_ms(8)
//! shared_workspaces_count(2 BE)
//! shared_workspaces([32; N], deterministic sorted)
//! signer(32)
//! signature(64)
//! ```
//!
//! TODO(plan.md): once the layout/field_spec system is extended for
//! variable-length lists, port this to use the same `FieldSpec` machinery
//! the other event modules use. Phase 1 hand-rolls a small encoder/decoder
//! to keep the connection module compilable without growing the
//! `field_spec` system.

use std::collections::BTreeSet;

use crate::runtime::control_loop::work_item::{EndpointId, WorkspaceId};

use super::event::{Connection, CONNECTION_TYPE_CODE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionWireError {
    Truncated,
    WrongType(u8),
    BadShape(&'static str),
}

impl std::fmt::Display for ConnectionWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionWireError::Truncated => write!(f, "connection event truncated"),
            ConnectionWireError::WrongType(t) => write!(f, "wrong type code: {}", t),
            ConnectionWireError::BadShape(s) => write!(f, "bad shape: {}", s),
        }
    }
}

impl std::error::Error for ConnectionWireError {}

pub fn encode_connection(c: &Connection) -> Vec<u8> {
    let n = c.shared_workspaces.len();
    let cap = 1 + 8 + 32 + 32 + 8 + 2 + n * 32 + 32 + 64;
    let mut out = Vec::with_capacity(cap);
    out.push(CONNECTION_TYPE_CODE);
    out.extend_from_slice(&c.created_at_ms.to_be_bytes());
    out.extend_from_slice(&c.endpoint_a);
    out.extend_from_slice(&c.endpoint_b);
    out.extend_from_slice(&c.signed_at_ms.to_be_bytes());
    out.extend_from_slice(&(n as u16).to_be_bytes());
    for ws in &c.shared_workspaces {
        out.extend_from_slice(ws);
    }
    out.extend_from_slice(&c.signer);
    out.extend_from_slice(&c.signature);
    out
}

pub fn parse_connection(blob: &[u8]) -> Result<Connection, ConnectionWireError> {
    if blob.is_empty() {
        return Err(ConnectionWireError::Truncated);
    }
    if blob[0] != CONNECTION_TYPE_CODE {
        return Err(ConnectionWireError::WrongType(blob[0]));
    }
    let mut pos = 1;
    let need = |p: usize, n: usize| {
        if blob.len() < p + n {
            Err(ConnectionWireError::Truncated)
        } else {
            Ok(())
        }
    };
    need(pos, 8)?;
    let created_at_ms = u64::from_be_bytes(blob[pos..pos + 8].try_into().unwrap());
    pos += 8;
    need(pos, 32)?;
    let mut endpoint_a: EndpointId = [0u8; 32];
    endpoint_a.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    need(pos, 32)?;
    let mut endpoint_b: EndpointId = [0u8; 32];
    endpoint_b.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    need(pos, 8)?;
    let signed_at_ms = u64::from_be_bytes(blob[pos..pos + 8].try_into().unwrap());
    pos += 8;
    need(pos, 2)?;
    let n = u16::from_be_bytes(blob[pos..pos + 2].try_into().unwrap()) as usize;
    pos += 2;
    let mut shared = BTreeSet::new();
    for _ in 0..n {
        need(pos, 32)?;
        let mut ws: WorkspaceId = [0u8; 32];
        ws.copy_from_slice(&blob[pos..pos + 32]);
        pos += 32;
        if !shared.insert(ws) {
            return Err(ConnectionWireError::BadShape(
                "duplicate workspace id in shared_workspaces",
            ));
        }
    }
    need(pos, 32)?;
    let mut signer = [0u8; 32];
    signer.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    need(pos, 64)?;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[pos..pos + 64]);
    pos += 64;
    if blob.len() != pos {
        return Err(ConnectionWireError::BadShape("trailing bytes"));
    }
    Ok(Connection {
        created_at_ms,
        endpoint_a,
        endpoint_b,
        shared_workspaces: shared,
        signed_at_ms,
        signer,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut shared = BTreeSet::new();
        shared.insert([1u8; 32]);
        shared.insert([2u8; 32]);
        let c = Connection {
            created_at_ms: 100,
            endpoint_a: [10u8; 32],
            endpoint_b: [20u8; 32],
            shared_workspaces: shared.clone(),
            signed_at_ms: 100,
            signer: [10u8; 32],
            signature: [9u8; 64],
        };
        let blob = encode_connection(&c);
        let parsed = parse_connection(&blob).unwrap();
        assert_eq!(parsed, c);
    }
}

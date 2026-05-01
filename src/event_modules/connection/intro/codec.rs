//! Hand-rolled wire codec for `IntroEvent` (variable size).
//!
//! Layout:
//! ```text
//! [0]            type_code (= 36)
//! [1..33]        subject_a_endpoint_id (32)
//! [33..65]       subject_b_endpoint_id (32)
//! [65..67]       addresses_a_count (u16 BE)
//! [..]           addresses_a: N * (ip[16] || port[u16 BE]) = N * 18
//! [..]           addresses_b_count (u16 BE)
//! [..]           addresses_b: M * (ip[16] || port[u16 BE]) = M * 18
//! [..]           created_at_ms (u64 BE)
//! [..]           signed_by (32)
//! [..]           signature (64)
//! ```

use super::event::{IntroAddress, IntroEvent, INTRO_TYPE_CODE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntroWireError {
    Truncated,
    WrongType(u8),
    BadShape(&'static str),
}

impl std::fmt::Display for IntroWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "intro event truncated"),
            Self::WrongType(t) => write!(f, "wrong type code: {}", t),
            Self::BadShape(s) => write!(f, "bad shape: {}", s),
        }
    }
}

impl std::error::Error for IntroWireError {}

pub fn encode(e: &IntroEvent) -> Vec<u8> {
    let n = e.addresses_a.len();
    let m = e.addresses_b.len();
    let cap = 1 + 32 + 32 + 2 + n * 18 + 2 + m * 18 + 8 + 32 + 64;
    let mut out = Vec::with_capacity(cap);
    out.push(INTRO_TYPE_CODE);
    out.extend_from_slice(&e.subject_a_endpoint_id);
    out.extend_from_slice(&e.subject_b_endpoint_id);
    out.extend_from_slice(&(n as u16).to_be_bytes());
    for a in &e.addresses_a {
        out.extend_from_slice(&a.ip);
        out.extend_from_slice(&a.port.to_be_bytes());
    }
    out.extend_from_slice(&(m as u16).to_be_bytes());
    for a in &e.addresses_b {
        out.extend_from_slice(&a.ip);
        out.extend_from_slice(&a.port.to_be_bytes());
    }
    out.extend_from_slice(&e.created_at_ms.to_be_bytes());
    out.extend_from_slice(&e.signed_by);
    out.extend_from_slice(&e.signature);
    out
}

pub fn parse(blob: &[u8]) -> Result<IntroEvent, IntroWireError> {
    if blob.is_empty() {
        return Err(IntroWireError::Truncated);
    }
    if blob[0] != INTRO_TYPE_CODE {
        return Err(IntroWireError::WrongType(blob[0]));
    }

    let mut pos = 1;
    let need = |p: usize, n: usize| {
        if blob.len() < p + n {
            Err(IntroWireError::Truncated)
        } else {
            Ok(())
        }
    };

    need(pos, 32)?;
    let mut subject_a_endpoint_id = [0u8; 32];
    subject_a_endpoint_id.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    need(pos, 32)?;
    let mut subject_b_endpoint_id = [0u8; 32];
    subject_b_endpoint_id.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;

    need(pos, 2)?;
    let na = u16::from_be_bytes(blob[pos..pos + 2].try_into().unwrap()) as usize;
    pos += 2;
    let mut addresses_a = Vec::with_capacity(na);
    for _ in 0..na {
        need(pos, 18)?;
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&blob[pos..pos + 16]);
        pos += 16;
        let port = u16::from_be_bytes(blob[pos..pos + 2].try_into().unwrap());
        pos += 2;
        addresses_a.push(IntroAddress { ip, port });
    }

    need(pos, 2)?;
    let nb = u16::from_be_bytes(blob[pos..pos + 2].try_into().unwrap()) as usize;
    pos += 2;
    let mut addresses_b = Vec::with_capacity(nb);
    for _ in 0..nb {
        need(pos, 18)?;
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&blob[pos..pos + 16]);
        pos += 16;
        let port = u16::from_be_bytes(blob[pos..pos + 2].try_into().unwrap());
        pos += 2;
        addresses_b.push(IntroAddress { ip, port });
    }

    need(pos, 8)?;
    let created_at_ms = u64::from_be_bytes(blob[pos..pos + 8].try_into().unwrap());
    pos += 8;
    need(pos, 32)?;
    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;
    need(pos, 64)?;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[pos..pos + 64]);
    pos += 64;
    if blob.len() != pos {
        return Err(IntroWireError::BadShape("trailing bytes"));
    }

    Ok(IntroEvent {
        subject_a_endpoint_id,
        subject_b_endpoint_id,
        addresses_a,
        addresses_b,
        created_at_ms,
        signed_by,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let e = IntroEvent {
            subject_a_endpoint_id: [11u8; 32],
            subject_b_endpoint_id: [22u8; 32],
            addresses_a: vec![
                IntroAddress {
                    ip: [1u8; 16],
                    port: 4433,
                },
                IntroAddress {
                    ip: [2u8; 16],
                    port: 9999,
                },
            ],
            addresses_b: vec![IntroAddress {
                ip: [3u8; 16],
                port: 7777,
            }],
            created_at_ms: 12345,
            signed_by: [33u8; 32],
            signature: [9u8; 64],
        };
        let blob = encode(&e);
        let parsed = parse(&blob).unwrap();
        assert_eq!(parsed, e);
    }

    #[test]
    fn empty_address_lists() {
        let e = IntroEvent {
            subject_a_endpoint_id: [1u8; 32],
            subject_b_endpoint_id: [2u8; 32],
            addresses_a: vec![],
            addresses_b: vec![],
            created_at_ms: 100,
            signed_by: [3u8; 32],
            signature: [9u8; 64],
        };
        let blob = encode(&e);
        let parsed = parse(&blob).unwrap();
        assert_eq!(parsed, e);
    }
}

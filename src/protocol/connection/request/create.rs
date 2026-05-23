//! Connection-request construction helpers.
//!
//! Commands use this module to sign canonical request transcripts and encode
//! optional listen-address blocks. Projectors and receive paths use the same
//! helpers to verify invite signatures and decode fixed address blocks without
//! calling user-facing command code.
//!
//! Keep request-specific crypto transcripts and address-block conversion here.
//! `layout.rs` owns stable fact byte order, `commands.rs` owns CLI-facing
//! construction, and `project.rs` owns admission and context proofs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::core::crypto;
use crate::core::wire;
use crate::protocol::auth::invite::fact::InviteSecretFact;

use super::fact::ConnectionRequestFact;

// Optional listen-address conversion is request construction logic because it
// interprets `std::net::SocketAddr`; `layout.rs` only consumes fixed bytes.

pub const ADDR_BLOCK_BYTES: usize = 19;
pub const ADDR_FAMILY_NONE: u8 = 0;
pub const ADDR_FAMILY_V4: u8 = 1;
pub const ADDR_FAMILY_V6: u8 = 2;

pub fn encode_optional_addr(addr: Option<SocketAddr>) -> Result<[u8; ADDR_BLOCK_BYTES], String> {
    let mut out = [0u8; ADDR_BLOCK_BYTES];
    match addr {
        None => {
            out[0] = ADDR_FAMILY_NONE;
        }
        Some(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                out[0] = ADDR_FAMILY_V4;
                out[1..5].copy_from_slice(&ip.octets());
                wire::put_u16be(addr.port(), &mut out[17..19]).map_err(addr_wire_err)?;
            }
            IpAddr::V6(ip) => {
                out[0] = ADDR_FAMILY_V6;
                out[1..17].copy_from_slice(&ip.octets());
                wire::put_u16be(addr.port(), &mut out[17..19]).map_err(addr_wire_err)?;
            }
        },
    }
    Ok(out)
}

pub fn decode_optional_addr(bytes: &[u8; ADDR_BLOCK_BYTES]) -> Result<Option<SocketAddr>, String> {
    let family = bytes[0];
    let raw = &bytes[1..17];
    let port = wire::take_u16be(&bytes[17..19]).map_err(addr_wire_err)?;
    match family {
        ADDR_FAMILY_NONE => {
            if raw.iter().any(|byte| *byte != 0) || port != 0 {
                return Err("absent listen addr must zero its address bytes".to_string());
            }
            Ok(None)
        }
        ADDR_FAMILY_V4 => {
            if raw[4..].iter().any(|byte| *byte != 0) {
                return Err("ipv4 listen addr must zero its trailing bytes".to_string());
            }
            let octets = [raw[0], raw[1], raw[2], raw[3]];
            Ok(Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(octets)),
                port,
            )))
        }
        ADDR_FAMILY_V6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(raw);
            Ok(Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                port,
            )))
        }
        other => Err(format!("unknown listen addr family {other}")),
    }
}

fn addr_wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

pub fn invite_signing_transcript(request: &ConnectionRequestFact) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.extend_from_slice(b"topo-connection-request-invite-signing-transcript-v1");
    out.extend_from_slice(&request.from_endpoint);
    out.extend_from_slice(&request.to_endpoint);
    out.extend_from_slice(&request.nonce);
    out.extend_from_slice(&request.invite_fact_id);
    out.extend_from_slice(&request.bootstrap_hash);
    out.extend_from_slice(&request.invite_secret_fact_id);
    out.extend_from_slice(&request.initiator_ephemeral_secret_fact_id);
    out.extend_from_slice(&request.initiator_ephemeral_public_key);
    out.extend_from_slice(&encode_optional_addr(request.from_listen_addr)?);
    out.extend_from_slice(&encode_optional_addr(request.to_listen_addr)?);
    Ok(out)
}

pub fn validate_invite_signature(
    request: &ConnectionRequestFact,
    invite_secret: &InviteSecretFact,
) -> Result<(), String> {
    if invite_secret.bootstrap_hash != request.bootstrap_hash {
        return Err("connection request bootstrap hash is not authorized".to_string());
    }
    if let Some(invite_fact_id) = invite_secret.invite_fact_id {
        if invite_fact_id != request.invite_fact_id {
            return Err("connection request invite id is not authorized".to_string());
        }
    }
    let public_key = crypto::ed25519_public_key(&invite_secret.bootstrap_secret);
    if !crypto::ed25519_verify(
        &public_key,
        &invite_signing_transcript(request)?,
        &request.invite_signature,
    ) {
        return Err("connection request invite signature is not authorized".to_string());
    }
    Ok(())
}

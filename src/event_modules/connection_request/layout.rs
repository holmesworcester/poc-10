//! Connection-request fact layout.
//!
//! Fixed-width header: tag, two endpoint ids, nonce, invite event id, bootstrap
//! hash, 64-byte invite signature, invite-secret event id, initiator ephemeral
//! secret event id, initiator ephemeral public key, then an address block of
//! `1 + 16 + 2` bytes carrying an optional IPv4/IPv6 listen socket. The address
//! family byte selects how the 16-byte slot is interpreted; both an absent and
//! a present address consume the same number of bytes so the fact stays
//! self-describing without a length prefix.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::core::crypto::ED25519_SIGNATURE_BYTES;
use crate::core::wire;

use super::fact::ConnectionRequestFact;

pub const TYPE_CONNECTION_REQUEST: u8 = 42;

const ADDR_FAMILY_NONE: u8 = 0;
const ADDR_FAMILY_V4: u8 = 4;
const ADDR_FAMILY_V6: u8 = 6;
const ADDR_BLOCK_BYTES: usize = 1 + 16 + 2;

pub const FACT_BYTES: usize =
    1 + 32 + 32 + 32 + 32 + 32 + ED25519_SIGNATURE_BYTES + 32 + 32 + 32 + ADDR_BLOCK_BYTES;

pub fn encode_fact(fact: &ConnectionRequestFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_CONNECTION_REQUEST, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.from_endpoint);
    out[33..65].copy_from_slice(&fact.to_endpoint);
    out[65..97].copy_from_slice(&fact.nonce);
    out[97..129].copy_from_slice(&fact.invite_event_id);
    out[129..161].copy_from_slice(&fact.bootstrap_hash);
    out[161..161 + ED25519_SIGNATURE_BYTES].copy_from_slice(&fact.invite_signature);
    let mut cursor = 161 + ED25519_SIGNATURE_BYTES;
    out[cursor..cursor + 32].copy_from_slice(&fact.invite_secret_event_id);
    cursor += 32;
    out[cursor..cursor + 32].copy_from_slice(&fact.initiator_ephemeral_secret_event_id);
    cursor += 32;
    out[cursor..cursor + 32].copy_from_slice(&fact.initiator_ephemeral_public_key);
    cursor += 32;
    encode_optional_addr(fact.from_listen_addr, &mut out[cursor..cursor + ADDR_BLOCK_BYTES])?;
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionRequestFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_CONNECTION_REQUEST {
        return Err("expected connection request fact".to_string());
    }
    let mut from_endpoint = [0; 32];
    from_endpoint.copy_from_slice(&bytes[1..33]);
    let mut to_endpoint = [0; 32];
    to_endpoint.copy_from_slice(&bytes[33..65]);
    let mut nonce = [0; 32];
    nonce.copy_from_slice(&bytes[65..97]);
    let mut invite_event_id = [0; 32];
    invite_event_id.copy_from_slice(&bytes[97..129]);
    let mut bootstrap_hash = [0; 32];
    bootstrap_hash.copy_from_slice(&bytes[129..161]);
    let mut invite_signature = [0; ED25519_SIGNATURE_BYTES];
    invite_signature.copy_from_slice(&bytes[161..161 + ED25519_SIGNATURE_BYTES]);
    let mut cursor = 161 + ED25519_SIGNATURE_BYTES;
    let mut invite_secret_event_id = [0; 32];
    invite_secret_event_id.copy_from_slice(&bytes[cursor..cursor + 32]);
    cursor += 32;
    let mut initiator_ephemeral_secret_event_id = [0; 32];
    initiator_ephemeral_secret_event_id.copy_from_slice(&bytes[cursor..cursor + 32]);
    cursor += 32;
    let mut initiator_ephemeral_public_key = [0; 32];
    initiator_ephemeral_public_key.copy_from_slice(&bytes[cursor..cursor + 32]);
    cursor += 32;
    let from_listen_addr = decode_optional_addr(&bytes[cursor..cursor + ADDR_BLOCK_BYTES])?;
    Ok(ConnectionRequestFact {
        from_endpoint,
        to_endpoint,
        nonce,
        invite_event_id,
        bootstrap_hash,
        invite_signature,
        invite_secret_event_id,
        initiator_ephemeral_secret_event_id,
        initiator_ephemeral_public_key,
        from_listen_addr,
    })
}

fn encode_optional_addr(addr: Option<SocketAddr>, out: &mut [u8]) -> Result<(), String> {
    wire::expect_len(out, ADDR_BLOCK_BYTES).map_err(wire_err)?;
    match addr {
        None => {
            wire::put_u8(ADDR_FAMILY_NONE, &mut out[0..1]).map_err(wire_err)?;
            // address bytes and port already zero from initial fill
        }
        Some(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                wire::put_u8(ADDR_FAMILY_V4, &mut out[0..1]).map_err(wire_err)?;
                out[1..5].copy_from_slice(&ip.octets());
                wire::put_u16be(addr.port(), &mut out[17..19]).map_err(wire_err)?;
            }
            IpAddr::V6(ip) => {
                wire::put_u8(ADDR_FAMILY_V6, &mut out[0..1]).map_err(wire_err)?;
                out[1..17].copy_from_slice(&ip.octets());
                wire::put_u16be(addr.port(), &mut out[17..19]).map_err(wire_err)?;
            }
        },
    }
    Ok(())
}

fn decode_optional_addr(bytes: &[u8]) -> Result<Option<SocketAddr>, String> {
    wire::expect_len(bytes, ADDR_BLOCK_BYTES).map_err(wire_err)?;
    let family = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    let raw = &bytes[1..17];
    let port = wire::take_u16be(&bytes[17..19]).map_err(wire_err)?;
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

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> ConnectionRequestFact {
        ConnectionRequestFact {
            from_endpoint: [1; 32],
            to_endpoint: [2; 32],
            nonce: [3; 32],
            invite_event_id: [4; 32],
            bootstrap_hash: [5; 32],
            invite_signature: [6; ED25519_SIGNATURE_BYTES],
            invite_secret_event_id: [7; 32],
            initiator_ephemeral_secret_event_id: [8; 32],
            initiator_ephemeral_public_key: [9; 32],
            from_listen_addr: None,
        }
    }

    #[test]
    fn connection_request_roundtrips_without_listen_addr() {
        let bytes = encode_fact(&fact()).expect("encode");
        assert_eq!(bytes.len(), FACT_BYTES);
        assert_eq!(decode_fact(&bytes).expect("decode"), fact());
    }

    #[test]
    fn connection_request_roundtrips_with_v4_and_v6_listen_addrs() {
        let mut request = fact();
        request.from_listen_addr = Some("127.0.0.1:55555".parse().expect("ipv4 socket addr"));
        let v4 = encode_fact(&request).expect("encode v4");
        assert_eq!(v4.len(), FACT_BYTES);
        assert_eq!(decode_fact(&v4).expect("decode v4"), request);

        request.from_listen_addr = Some("[::1]:8080".parse().expect("ipv6 socket addr"));
        let v6 = encode_fact(&request).expect("encode v6");
        assert_eq!(v6.len(), FACT_BYTES);
        assert_eq!(decode_fact(&v6).expect("decode v6"), request);
    }

    #[test]
    fn rejects_wrong_tag_or_length() {
        let mut bytes = encode_fact(&fact()).expect("encode");
        bytes[0] = TYPE_CONNECTION_REQUEST.wrapping_add(1);
        assert!(decode_fact(&bytes).is_err());

        let mut short = encode_fact(&fact()).expect("encode");
        short.pop();
        assert!(decode_fact(&short).is_err());
    }

    #[test]
    fn rejects_unknown_address_family() {
        let mut bytes = encode_fact(&fact()).expect("encode");
        let family_offset = FACT_BYTES - ADDR_BLOCK_BYTES;
        bytes[family_offset] = 9;
        assert!(decode_fact(&bytes).is_err());
    }
}

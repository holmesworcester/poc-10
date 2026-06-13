//! Canonical byte encoding for unified connection-request facts.
//!
//! This file owns byte construction only: the fact tag, fixed plaintext field
//! order and widths, address encoding, and sealed network-envelope encoding. It
//! does not open, authenticate, sign, or inspect context.
//!
//! The semantic request plaintext is fixed width for both bootstrap and
//! membership modes. The network fact body is the sealed request:
//! `tag || seal_version || initiator_ephemeral_public_key || to_endpoint || nonce ||
//! ciphertext`. The sealed bytes are the fact bytes and therefore the request id.

use crate::core::crypto::{
    self, X25519PrivateKey, XChaCha20Poly1305Nonce, ED25519_SIGNATURE_BYTES,
    XCHACHA20_POLY1305_NONCE_BYTES, XCHACHA20_POLY1305_TAG_BYTES,
};
use crate::core::wire;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::fact::{ConnectionRequestFact, REQUEST_MODE_BOOTSTRAP, REQUEST_MODE_MEMBERSHIP};

pub const TYPE_CONNECTION_REQUEST: u8 = 48;
pub(crate) const SEAL_VERSION: u8 = 1;
pub(crate) const REQUEST_PURPOSE: &[u8] = b"topo-sealed-connection-request-v2";
pub(crate) const SEALED_HEADER_BYTES: usize = 1 + 1 + 32 + 32 + XCHACHA20_POLY1305_NONCE_BYTES;
pub const ADDR_BLOCK_BYTES: usize = 19;
pub const ADDR_FAMILY_NONE: u8 = 0;
pub const ADDR_FAMILY_V4: u8 = 1;
pub const ADDR_FAMILY_V6: u8 = 2;

pub const PLAINTEXT_FACT_BYTES: usize = 1 // tag
    + 1 // mode
    + 32 // from_endpoint
    + 32 // to_endpoint
    + 32 // nonce
    + ADDR_BLOCK_BYTES // dialed_addr
    + ADDR_BLOCK_BYTES // initiator_addr
    + 32 // invite_fact_id
    + 32 // bootstrap_hash
    + 32 // invite_secret_fact_id
    + ED25519_SIGNATURE_BYTES // invite_signature
    + 32 // initiator_endpoint_shared_id
    + ED25519_SIGNATURE_BYTES // endpoint_signature
    + 32 // initiator_ephemeral_secret_fact_id
    + 32; // initiator_ephemeral_public_key
pub const FACT_BYTES: usize = PLAINTEXT_FACT_BYTES;
pub const SEALED_FACT_BYTES: usize =
    SEALED_HEADER_BYTES + PLAINTEXT_FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;
pub(crate) const INVITE_SIGNATURE_OFFSET: usize =
    1 + 1 + 32 + 32 + 32 + ADDR_BLOCK_BYTES + ADDR_BLOCK_BYTES + 32 + 32 + 32;
pub(crate) const INVITE_SIGNATURE_END: usize = INVITE_SIGNATURE_OFFSET + ED25519_SIGNATURE_BYTES;
pub(crate) const ENDPOINT_SIGNATURE_OFFSET: usize = INVITE_SIGNATURE_END + 32;
pub(crate) const ENDPOINT_SIGNATURE_END: usize =
    ENDPOINT_SIGNATURE_OFFSET + ED25519_SIGNATURE_BYTES;

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
                return Err("absent connection addr must zero its address bytes".to_string());
            }
            Ok(None)
        }
        ADDR_FAMILY_V4 => {
            if raw[4..].iter().any(|byte| *byte != 0) {
                return Err("ipv4 connection addr must zero its trailing bytes".to_string());
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
        other => Err(format!("unknown connection addr family {other}")),
    }
}

pub fn encode_fact(fact: &ConnectionRequestFact) -> Result<Vec<u8>, String> {
    encode_plaintext(fact)
}

pub fn encode_plaintext(fact: &ConnectionRequestFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; PLAINTEXT_FACT_BYTES];
    out[0] = TYPE_CONNECTION_REQUEST;
    out[1] = fact.mode;
    out[2..34].copy_from_slice(&fact.from_endpoint);
    out[34..66].copy_from_slice(&fact.to_endpoint);
    out[66..98].copy_from_slice(&fact.nonce);
    let mut cursor = 98;
    out[cursor..cursor + ADDR_BLOCK_BYTES]
        .copy_from_slice(&encode_optional_addr(fact.dialed_addr)?);
    cursor += ADDR_BLOCK_BYTES;
    out[cursor..cursor + ADDR_BLOCK_BYTES]
        .copy_from_slice(&encode_optional_addr(fact.initiator_addr)?);
    cursor += ADDR_BLOCK_BYTES;
    out[cursor..cursor + 32].copy_from_slice(&fact.invite_fact_id);
    cursor += 32;
    out[cursor..cursor + 32].copy_from_slice(&fact.bootstrap_hash);
    cursor += 32;
    out[cursor..cursor + 32].copy_from_slice(&fact.invite_secret_fact_id);
    cursor += 32;
    out[cursor..cursor + ED25519_SIGNATURE_BYTES].copy_from_slice(&fact.invite_signature);
    cursor += ED25519_SIGNATURE_BYTES;
    out[cursor..cursor + 32].copy_from_slice(&fact.initiator_endpoint_shared_id);
    cursor += 32;
    out[cursor..cursor + ED25519_SIGNATURE_BYTES].copy_from_slice(&fact.endpoint_signature);
    cursor += ED25519_SIGNATURE_BYTES;
    out[cursor..cursor + 32].copy_from_slice(&fact.initiator_ephemeral_secret_fact_id);
    cursor += 32;
    out[cursor..cursor + 32].copy_from_slice(&fact.initiator_ephemeral_public_key);
    Ok(out)
}

pub fn seal_fact(
    request: &ConnectionRequestFact,
    initiator_ephemeral_private_key: &X25519PrivateKey,
) -> Result<Vec<u8>, String> {
    if crypto::x25519_public_key(initiator_ephemeral_private_key)
        != request.initiator_ephemeral_public_key
    {
        return Err("sealed connection request ephemeral key does not match request".to_string());
    }
    let plaintext = encode_plaintext(request)?;
    let nonce = crypto::random_xchacha20poly1305_nonce();
    let header = sealed_header(
        request.initiator_ephemeral_public_key,
        request.to_endpoint,
        nonce,
    );
    let ciphertext = crypto::x25519_xchacha20poly1305_encrypt(
        initiator_ephemeral_private_key,
        &request.to_endpoint,
        REQUEST_PURPOSE,
        &header,
        &nonce,
        &plaintext,
    )?;
    if ciphertext.len() != PLAINTEXT_FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES {
        return Err("sealed connection request ciphertext length mismatch".to_string());
    }
    let mut out = Vec::with_capacity(SEALED_FACT_BYTES);
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Canonical request bytes used by bootstrap invite signatures.
pub fn bootstrap_signature_bytes(request: &ConnectionRequestFact) -> Result<Vec<u8>, String> {
    if request.mode != REQUEST_MODE_BOOTSTRAP {
        return Err("bootstrap request signature requires bootstrap mode".to_string());
    }
    wire::encode_with_zeroed_fields(
        request,
        encode_fact,
        [INVITE_SIGNATURE_OFFSET..INVITE_SIGNATURE_END],
    )
}

/// Canonical request bytes used by membership endpoint signatures.
pub fn endpoint_signature_bytes(request: &ConnectionRequestFact) -> Result<Vec<u8>, String> {
    if request.mode != REQUEST_MODE_MEMBERSHIP {
        return Err("membership request signature requires membership mode".to_string());
    }
    wire::encode_with_zeroed_fields(
        request,
        encode_fact,
        [ENDPOINT_SIGNATURE_OFFSET..ENDPOINT_SIGNATURE_END],
    )
}

fn sealed_header(
    initiator_ephemeral_public_key: [u8; 32],
    to_endpoint: [u8; 32],
    nonce: XChaCha20Poly1305Nonce,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(SEALED_HEADER_BYTES);
    out.push(TYPE_CONNECTION_REQUEST);
    out.push(SEAL_VERSION);
    out.extend_from_slice(&initiator_ephemeral_public_key);
    out.extend_from_slice(&to_endpoint);
    out.extend_from_slice(&nonce);
    out
}

fn addr_wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

//! Bootstrap-request fact and sealed network-frame layout.
//!
//! The durable `connection::request` fact remains the canonical handshake
//! state. This family owns the flat local receive fact for the sealed request
//! frame that arrives before an established connection secret exists.

use crate::core::crypto::{
    self, X25519PrivateKey, XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_NONCE_BYTES,
    XCHACHA20_POLY1305_TAG_BYTES,
};
use crate::core::wire::{self, FixedLayout, FixedSlot, Reader, Writer};
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::connection::fact_receipt::create::normalize_origin_addr_bytes;
use crate::protocol::connection::fact_receipt::fact::{OriginAddr, ORIGIN_ADDR_BYTES};
use crate::protocol::connection::request;

use super::fact::{ConnectionBootstrapRequestFact, SealedConnectionRequestFrame};

pub const TYPE_CONNECTION_BOOTSTRAP_REQUEST: u8 = 171;
pub const TYPE_SEALED_CONNECTION_REQUEST: u8 = 46;

const VERSION: u8 = 1;
const REQUEST_PURPOSE: &[u8] = b"topo-sealed-connection-request-v1";

const REQUEST_HEADER_BYTES: usize = 1 + 1 + 32 + XCHACHA20_POLY1305_NONCE_BYTES;

pub const SEALED_CONNECTION_REQUEST_BYTES: usize =
    REQUEST_HEADER_BYTES + request::layout::FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;

pub const CONNECTION_BOOTSTRAP_REQUEST_FACT_BYTES: usize =
    1 + 8 + FixedSlot::<ORIGIN_ADDR_BYTES>::LEN + SEALED_CONNECTION_REQUEST_BYTES;

pub fn encode_fact(fact: &ConnectionBootstrapRequestFact) -> Result<Vec<u8>, String> {
    validate_sealed_connection_request_frame(&fact.sealed_request_frame)?;
    let origin_addr = normalize_origin_addr_bytes(fact.origin_addr.bytes())?;

    let mut writer = Writer::with_capacity(CONNECTION_BOOTSTRAP_REQUEST_FACT_BYTES);
    writer.u8(TYPE_CONNECTION_BOOTSTRAP_REQUEST);
    writer.u64be(fact.received_at_local_ms);
    writer
        .fixed_slot::<ORIGIN_ADDR_BYTES>(&origin_addr)
        .map_err(wire_err)?;
    writer.fixed(&fact.sealed_request_frame);
    writer
        .finish_exact(CONNECTION_BOOTSTRAP_REQUEST_FACT_BYTES)
        .map_err(wire_err)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionBootstrapRequestFact, String> {
    let mut reader = Reader::new(bytes);
    reader
        .expect_len(CONNECTION_BOOTSTRAP_REQUEST_FACT_BYTES)
        .map_err(wire_err)?;
    reader
        .expect_u8(TYPE_CONNECTION_BOOTSTRAP_REQUEST)
        .map_err(wire_err)?;
    let received_at_local_ms = reader.u64be().map_err(wire_err)?;
    let origin_addr_bytes = reader.fixed_slot::<ORIGIN_ADDR_BYTES>().map_err(wire_err)?;
    let canonical_origin_addr = normalize_origin_addr_bytes(&origin_addr_bytes)?;
    if canonical_origin_addr != origin_addr_bytes {
        return Err("connection bootstrap request origin addr is not canonical".to_string());
    }
    let sealed_request_frame = reader
        .array::<SEALED_CONNECTION_REQUEST_BYTES>()
        .map_err(wire_err)?;
    reader.finish().map_err(wire_err)?;
    validate_sealed_connection_request_frame(&sealed_request_frame)?;
    Ok(ConnectionBootstrapRequestFact {
        origin_addr: OriginAddr::new(&origin_addr_bytes).map_err(wire_err)?,
        received_at_local_ms,
        sealed_request_frame,
    })
}

pub fn copy_sealed_connection_request_frame(
    frame: &[u8],
) -> Result<SealedConnectionRequestFrame, String> {
    validate_sealed_connection_request_frame(frame)?;
    let mut out = [0; SEALED_CONNECTION_REQUEST_BYTES];
    out.copy_from_slice(frame);
    Ok(out)
}

pub fn validate_sealed_connection_request_frame(frame: &[u8]) -> Result<(), String> {
    if frame.len() != SEALED_CONNECTION_REQUEST_BYTES {
        return Err("sealed connection request has wrong length".to_string());
    }
    if frame[0] != TYPE_SEALED_CONNECTION_REQUEST || frame[1] != VERSION {
        return Err("sealed connection request has unsupported header".to_string());
    }
    Ok(())
}

pub fn seal_connection_request(
    request_bytes: &[u8],
    initiator_ephemeral_private_key: &X25519PrivateKey,
) -> Result<Vec<u8>, String> {
    let request = request::layout::decode_fact(request_bytes)?;
    if crypto::x25519_public_key(initiator_ephemeral_private_key)
        != request.initiator_ephemeral_public_key
    {
        return Err("sealed connection request ephemeral key does not match request".to_string());
    }

    let nonce = crypto::random_xchacha20poly1305_nonce();
    let header = request_header(request.initiator_ephemeral_public_key, nonce);
    let ciphertext = crypto::x25519_xchacha20poly1305_encrypt(
        initiator_ephemeral_private_key,
        &request.to_endpoint,
        REQUEST_PURPOSE,
        &header,
        &nonce,
        request_bytes,
    )?;
    if ciphertext.len() != request::layout::FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES {
        return Err("sealed connection request ciphertext length mismatch".to_string());
    }

    let mut out = Vec::with_capacity(SEALED_CONNECTION_REQUEST_BYTES);
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open_connection_request(
    frame: &[u8],
    local_endpoint: &EndpointFact,
) -> Result<Vec<u8>, String> {
    validate_sealed_connection_request_frame(frame)?;
    let mut initiator_ephemeral_public_key = [0; 32];
    initiator_ephemeral_public_key.copy_from_slice(&frame[2..34]);
    let nonce = nonce_from(&frame[34..58]);
    let header = &frame[..REQUEST_HEADER_BYTES];
    let ciphertext = &frame[REQUEST_HEADER_BYTES..];

    let plaintext = crypto::x25519_xchacha20poly1305_decrypt(
        &local_endpoint.secret,
        &initiator_ephemeral_public_key,
        REQUEST_PURPOSE,
        header,
        &nonce,
        ciphertext,
    )?;
    let request = request::layout::decode_fact(&plaintext)?;
    if request.to_endpoint != local_endpoint.endpoint {
        return Err("sealed connection request is addressed to another endpoint".to_string());
    }
    if request.initiator_ephemeral_public_key != initiator_ephemeral_public_key {
        return Err(
            "sealed connection request inner ephemeral key does not match header".to_string(),
        );
    }
    Ok(plaintext)
}

fn request_header(
    initiator_ephemeral_public_key: [u8; 32],
    nonce: XChaCha20Poly1305Nonce,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(REQUEST_HEADER_BYTES);
    out.push(TYPE_SEALED_CONNECTION_REQUEST);
    out.push(VERSION);
    out.extend_from_slice(&initiator_ephemeral_public_key);
    out.extend_from_slice(&nonce);
    out
}

fn nonce_from(bytes: &[u8]) -> XChaCha20Poly1305Nonce {
    let mut nonce = [0; XCHACHA20_POLY1305_NONCE_BYTES];
    nonce.copy_from_slice(bytes);
    nonce
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::auth::endpoint::fact::EndpointFact;
    use crate::protocol::connection::fact_receipt::fact::OriginAddr;
    use crate::protocol::connection::request::fact::ConnectionRequestFact;

    fn endpoint(secret: [u8; 32]) -> EndpointFact {
        EndpointFact {
            endpoint: crypto::x25519_public_key(&secret),
            secret,
            signing_public_key: crypto::ed25519_public_key(&[91; 32]),
            signing_secret: [91; 32],
        }
    }

    fn contains_id(bytes: &[u8], id: &[u8; 32]) -> bool {
        bytes.windows(id.len()).any(|window| window == id)
    }

    #[test]
    fn connection_bootstrap_request_fact_roundtrips_fixed_width() {
        let mut sealed_request_frame = [0; SEALED_CONNECTION_REQUEST_BYTES];
        sealed_request_frame[0] = TYPE_SEALED_CONNECTION_REQUEST;
        sealed_request_frame[1] = VERSION;
        let fact = ConnectionBootstrapRequestFact {
            origin_addr: OriginAddr::new(b"127.0.0.1:41001").expect("origin"),
            received_at_local_ms: 123,
            sealed_request_frame,
        };

        let encoded = encode_fact(&fact).expect("encode");

        assert_eq!(encoded.len(), CONNECTION_BOOTSTRAP_REQUEST_FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact);
    }

    #[test]
    fn sealed_request_opens_only_for_addressed_endpoint() {
        let responder = endpoint([2; 32]);
        let initiator_ephemeral_private = [3; 32];
        let request = ConnectionRequestFact {
            from_endpoint: crypto::x25519_public_key(&[1; 32]),
            to_endpoint: responder.endpoint,
            nonce: [4; 32],
            invite_fact_id: [5; 32],
            bootstrap_hash: [6; 32],
            invite_signature: [7; crypto::ED25519_SIGNATURE_BYTES],
            invite_secret_fact_id: [8; 32],
            initiator_ephemeral_secret_fact_id: [9; 32],
            initiator_ephemeral_public_key: crypto::x25519_public_key(&initiator_ephemeral_private),
            from_listen_addr: Some("127.0.0.1:41001".parse().expect("addr")),
            to_listen_addr: None,
        };
        let bytes = request::layout::encode_fact(&request).expect("request");

        let sealed =
            seal_connection_request(&bytes, &initiator_ephemeral_private).expect("seal request");

        assert_eq!(sealed[0], TYPE_SEALED_CONNECTION_REQUEST);
        assert_eq!(sealed.len(), SEALED_CONNECTION_REQUEST_BYTES);
        assert_ne!(sealed, bytes);
        assert_eq!(
            REQUEST_HEADER_BYTES,
            1 + 1 + 32 + XCHACHA20_POLY1305_NONCE_BYTES
        );
        let public_header = &sealed[..REQUEST_HEADER_BYTES];
        assert_eq!(
            &public_header[2..34],
            &request.initiator_ephemeral_public_key
        );
        assert!(!contains_id(public_header, &request.from_endpoint));
        assert!(!contains_id(public_header, &request.to_endpoint));
        assert_eq!(
            open_connection_request(&sealed, &responder).expect("open request"),
            bytes
        );
        assert!(open_connection_request(&sealed, &endpoint([99; 32])).is_err());
    }
}
